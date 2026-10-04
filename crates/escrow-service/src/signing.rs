//! The service's half of the escrow key: assembling it, and using it.
//!
//! # Two halves, by two routes, and neither party may hold both
//!
//! The service's share is dealt to it in pieces. The cosigner deals one, over the connection the
//! runtime holds; Alice's wallet deals the other, straight from her device. Neither of them ever
//! sees the sum — a party holding both halves would hold this service's signing share and could
//! sign as it.
//!
//! So the sum is computed here and **checked here**, against the verifying share the pairing
//! published. That check is the whole of the service's trust in either delivery: a half from the
//! wrong attempt, a tampered one, or a cosigner that dealt something else all fail it identically,
//! which is fine, because the answer to all three is the same.
//!
//! # Signing a release, and why the service commits first
//!
//! FROST needs both parties' commitments before either can compute its share. The cosigner has no
//! execution context between messages, so it cannot hold a nonce across a round trip — see
//! `cosigner/src/sign.rs`. The service can, because it is an ordinary long-running
//! process. So the service commits first, the cosigner does both of its rounds inside one
//! invocation, and no single-use nonce is ever written down by either side.
//!
//! # Submitting exactly what was approved
//!
//! The cosigner returns the transactions it built. This service does **not** simply sign them: it
//! rebuilds the same transaction from the same proposal and checks the bytes match. `build` is
//! deterministic, so an honest pair agree exactly; a mismatch means the thing approved and the
//! thing about to be submitted are not the same object, and there is nothing safe to do with that
//! but stop.

use std::collections::BTreeMap;

use ark::client::send::{SendSession, SendVtxoInput};
use ark::client::types::ArkInfo;
use cosigner::escrow::{SignedHalf, WireCommitment};
use rand::rngs::OsRng;
use serde::{Deserialize, Serialize};
use threshold::commitment::SigningPackage;
use threshold::identifier::Identifier;
use threshold::keys::{KeyPackage, PublicKeyPackage};
use threshold::nonce::{self, SigningCommitments, SigningNonce};
use threshold::{point, scalar, signing};

/// This service's share of one escrow key, once both halves have arrived and checked out.
///
/// **Secret.** Half of a 2-of-2: it signs nothing alone, and it is not something to print.
#[derive(Clone, Serialize, Deserialize)]
pub struct PairedShare {
    pub escrow_key: String,
    pub attempt_id: String,
    /// The connection this pairing arrived on, as the wire names it: `<tenant>-<stream>`.
    ///
    /// Remembered because it is the only thing that says which customer this escrow belongs to.
    /// The local half of the name is the same for every wallet this service serves, so "whichever
    /// connection is open" is not an answer — it is how one customer's release request ends up on
    /// another's socket.
    #[serde(default)]
    pub stream_id: String,
    /// The assembled share, hex. The secret.
    secret_share_hex: String,
    /// The pairing's public package — its verifying key is the escrow key, unchanged by pairing.
    pub public_key_package_json: String,
    pub service_identifier_hex: String,
}

/// Redacted. A share in a log is a share given away.
impl std::fmt::Debug for PairedShare {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("PairedShare")
            .field("escrow_key", &self.escrow_key)
            .field("attempt_id", &self.attempt_id)
            .field("stream_id", &self.stream_id)
            .field("secret_share_hex", &"<redacted>")
            .finish_non_exhaustive()
    }
}

/// Why a pairing could not be assembled.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum NotPaired {
    /// One half is still missing. Not an error — the other route has not arrived yet.
    Waiting,
    /// The two halves do not sum to the share the pairing published.
    DoesNotCheckOut(String),
    /// Something on the wire was not what it claimed to be.
    Malformed(String),
    /// The halves checked out, but the share could not be written down — so it is not held, and
    /// saying otherwise would be a pairing that a restart quietly loses.
    NotStored(String),
    /// This service already holds a share of that escrow, and will not swap it for another.
    AlreadyHeld(String),
}

impl NotPaired {
    pub fn message(&self) -> String {
        match self {
            NotPaired::Waiting => "one half of the share has not arrived yet".into(),
            NotPaired::DoesNotCheckOut(why) => why.clone(),
            NotPaired::Malformed(why) => why.clone(),
            NotPaired::NotStored(why) => why.clone(),
            NotPaired::AlreadyHeld(why) => why.clone(),
        }
    }
}

impl PairedShare {
    /// Assemble the share from the two halves, and refuse it unless it checks out.
    ///
    /// `from_cosigner` arrived on the held connection; `from_wallet` arrived from Alice's device.
    /// Both are 32-byte scalars, hex.
    pub fn assemble(
        escrow_key: String,
        attempt_id: String,
        stream_id: String,
        service_identifier_hex: String,
        from_cosigner: &str,
        from_wallet: &str,
        public_key_package_json: String,
        service_verifying_share_hex: &str,
    ) -> Result<Self, NotPaired> {
        let a = scalar_from_hex(from_wallet).map_err(NotPaired::Malformed)?;
        let b = scalar_from_hex(from_cosigner).map_err(NotPaired::Malformed)?;
        let share = a + b;

        let expected = service_verifying_share_hex.to_ascii_lowercase();
        let actual = hex::encode(point::serialize_compressed(&point::base_mul(&share)));
        if actual != expected {
            // Deliberately one answer for three causes. Which of them it was is not knowable from
            // here, and guessing would be worse than saying what is true.
            return Err(NotPaired::DoesNotCheckOut(
                "the two halves do not sum to the share this pairing published".into(),
            ));
        }

        // And it must be a share of a 2-of-2, not of the group key itself: a service whose share
        // IS the group secret needs nobody, which is not a pairing.
        let pkp = PublicKeyPackage::from_json(&public_key_package_json)
            .map_err(|e| NotPaired::Malformed(format!("the pairing's package is unreadable: {e}")))?;
        if point::points_equal(&point::base_mul(&share), &pkp.verifying_key.point) {
            return Err(NotPaired::DoesNotCheckOut(
                "that share is the group key itself, which is not half of anything".into(),
            ));
        }

        Ok(Self {
            escrow_key,
            attempt_id,
            stream_id,
            secret_share_hex: hex::encode(scalar::scalar_to_bytes(&share)),
            public_key_package_json,
            service_identifier_hex,
        })
    }

    /// The share as FROST wants it. Built on demand rather than held, so there is one place it
    /// exists and it is a local.
    pub fn key_package(&self) -> Result<KeyPackage, String> {
        let share = scalar_from_hex(&self.secret_share_hex)?;
        let pkp = self.public_key_package()?;
        Ok(KeyPackage {
            identifier: self.identifier()?,
            secret_share: share,
            verifying_share: point::base_mul(&share),
            verifying_key: pkp.verifying_key.clone(),
            min_signers: 2,
        })
    }

    pub fn public_key_package(&self) -> Result<PublicKeyPackage, String> {
        PublicKeyPackage::from_json(&self.public_key_package_json)
            .map_err(|e| format!("the pairing's package is unreadable: {e}"))
    }

    pub fn identifier(&self) -> Result<Identifier, String> {
        self.service_identifier_hex.parse().map_err(|e| format!("bad identifier: {e}"))
    }

    /// The cosigner's identifier in this pairing — the other of the two.
    pub fn cosigner_identifier(&self) -> Result<Identifier, String> {
        let mine = self.identifier()?;
        self.public_key_package()?
            .verifying_shares
            .keys()
            .find(|id| **id != mine)
            .cloned()
            .ok_or_else(|| "this pairing names only one party".to_string())
    }
}

/// The nonces for one release, held in memory for one exchange and then dropped.
///
/// Not `Clone`, and never serialized. Two signatures under one nonce give up the share by simple
/// algebra, so a copy is a second use waiting to happen — the same rule the cosigner's
/// `SigningSession` follows, for the same reason.
pub struct Round {
    nonces: Vec<SigningNonce>,
}

impl Round {
    /// Round one: a fresh nonce per message, and the commitments to send with the ask.
    ///
    /// `messages` is how many sighashes the release will have — two per input, one on the ark
    /// transaction and one on its checkpoint. A count that does not match what the cosigner builds
    /// is refused by it before any nonce of its own is made, so a wrong guess costs only these.
    pub fn begin(share: &KeyPackage, messages: usize) -> (Self, Vec<WireCommitment>) {
        let mut rng = OsRng;
        let mut nonces = Vec::with_capacity(messages);
        let mut wire = Vec::with_capacity(messages);
        for _ in 0..messages {
            let nonce = nonce::new_nonce(&mut rng, &share.secret_share);
            wire.push(WireCommitment {
                hiding: hex::encode(point::serialize_compressed(&nonce.commitments.hiding)),
                binding: hex::encode(point::serialize_compressed(&nonce.commitments.binding)),
            });
            nonces.push(nonce);
        }
        (Self { nonces }, wire)
    }

    pub fn len(&self) -> usize {
        self.nonces.len()
    }

    pub fn is_empty(&self) -> bool {
        self.nonces.is_empty()
    }

    /// Round two: this service's share over both commitments, combined with the cosigner's into a
    /// finished signature for each message.
    ///
    /// Consumes the round — every nonce is spent exactly once, and there is nothing left to spend
    /// again.
    pub fn finish(
        self,
        share: &PairedShare,
        messages: &[Vec<u8>],
        theirs: &[SignedHalf],
    ) -> Result<Vec<[u8; 64]>, String> {
        if messages.len() != self.nonces.len() || theirs.len() != self.nonces.len() {
            return Err(format!(
                "{} messages and {} answers against {} nonces: index i must be a statement about \
                 message i",
                messages.len(),
                theirs.len(),
                self.nonces.len()
            ));
        }
        let key_package = share.key_package()?;
        let public_key_package = share.public_key_package()?;
        let mine = share.identifier()?;
        let cosigner = share.cosigner_identifier()?;

        messages
            .iter()
            .zip(self.nonces)
            .zip(theirs)
            .enumerate()
            .map(|(i, ((message, nonce), half))| {
                let at = |e: String| format!("message {i}: {e}");
                let their_commitment = SigningCommitments::from_hex(&half.hiding, &half.binding)
                    .map_err(|e| at(e.to_string()))?;

                let mut commitments = BTreeMap::new();
                commitments.insert(mine.clone(), nonce.commitments.clone());
                commitments.insert(cosigner.clone(), their_commitment);
                let package = SigningPackage::new(commitments, message.clone());

                let my_share = signing::sign(&package, &nonce, &key_package)
                    .map_err(|e| at(format!("frost sign: {e}")))?;
                let their_share = signing::SignatureShare {
                    s: scalar_from_hex(&half.share).map_err(at)?,
                };

                let mut shares = BTreeMap::new();
                shares.insert(mine.clone(), my_share);
                shares.insert(cosigner.clone(), their_share);
                // `aggregate` checks each share against its verifying share before summing, so a
                // cosigner that answered with something that is not a share of this key stops here
                // rather than at the ASP.
                let signature = signing::aggregate(&package, &shares, &public_key_package)
                    .map_err(|e| at(format!("frost aggregate: {e}")))?;
                Ok(signature.serialize())
            })
            .collect()
    }
}

/// What the service proposes, and what it rebuilds to check the answer against.
#[derive(Debug, Clone)]
pub struct Proposal {
    pub escrow_key: String,
    pub to_ark_address: String,
    pub amount_sats: u64,
    pub inputs: Vec<SendVtxoInput>,
}

impl Proposal {
    /// How many things a release over this proposal has to sign: one per input on the ark
    /// transaction, and one per checkpoint.
    pub fn messages(&self) -> usize {
        self.inputs.len() * 2
    }

    /// Rebuild the transaction the cosigner said it built, and refuse anything that is not it.
    ///
    /// This is what "submit exactly the approved transaction" means in practice. `build` is
    /// deterministic, so a cosigner that judged this proposal produces these bytes; anything else
    /// means the thing approved and the thing about to be broadcast are different objects.
    ///
    /// Rebuilding rather than trusting what was handed over is also the stronger check: it does not
    /// depend on the reply being honest, only on the maths being the same.
    pub fn rebuild(
        &self,
        info: &ArkInfo,
        approved_ark_tx: &str,
        approved_checkpoints: &[String],
    ) -> Result<(SendSession, Vec<Vec<u8>>), String> {
        let (session, sighashes) = self.build(info)?;
        let (ark_tx, checkpoints) = session.unsigned();
        if ark_tx != approved_ark_tx {
            return Err(
                "the transaction the cosigner approved is not the one this proposal builds; \
                 nothing may be submitted against a signature for something else"
                    .into(),
            );
        }
        if checkpoints != approved_checkpoints {
            return Err(
                "the checkpoints the cosigner approved are not the ones this proposal builds"
                    .into(),
            );
        }
        Ok((session, sighashes))
    }

    /// Build the transaction this proposal describes.
    ///
    /// Deterministic, so this is the same object every time — which is what lets a release be
    /// finished after a restart without asking anybody for anything. See
    /// [`Self::rebuild`] for the version that also checks it against what was approved.
    pub fn build(&self, info: &ArkInfo) -> Result<(SendSession, Vec<Vec<u8>>), String> {
        let owner = x_only(&self.escrow_key);
        let (session, sighashes) = SendSession::build(
            &owner,
            &self.inputs,
            &self.to_ark_address,
            self.amount_sats,
            None,
            info,
        )?;
        Ok((session, sighashes.iter().map(|s| s.to_vec()).collect()))
    }
}

fn scalar_from_hex(s: &str) -> Result<k256::Scalar, String> {
    let bytes: [u8; 32] = hex::decode(s)
        .map_err(|e| format!("not hex: {e}"))?
        .try_into()
        .map_err(|_| "a scalar is 32 bytes".to_string())?;
    scalar::scalar_from_bytes(&bytes).map_err(|e| format!("not a usable scalar: {e}"))
}

/// A compressed key without its parity byte, lowercased.
pub fn x_only(key_hex: &str) -> String {
    let k = key_hex.trim().to_ascii_lowercase();
    if k.len() == 66 {
        k[2..].to_string()
    } else {
        k
    }
}
