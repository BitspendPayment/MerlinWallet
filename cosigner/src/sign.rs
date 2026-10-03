//! FROST signing inside the stream that needs it: the cosigner's half of one round, for every
//! message in a batch.
//!
//! A send and a renewal both stop for the wallet to sign sighashes the cosigner built. They used to
//! do it by opening a *second* stream — a nested `Sign` per sighash, while the outer stream sat
//! parked waiting for the result. That worked against a native server running many streams at
//! once, and cannot work inside enclave-runtime, which runs **one request per tenant for the whole
//! life of a stream**: the outer stream holds the tenant, the nested one waits for it, and nothing
//! moves until the interaction deadline kills both. That was measured, not inferred — a second call
//! blocks on a separate TCP connection just the same, so a second channel does not help either.
//!
//! So the round rides the stream it belongs to, and it gets cheaper for it. The nested form cost
//! two round trips per signature; this is one round trip for the whole batch, because the order
//! FROST needs is "both commitments before either share", not "the wallet commits first":
//!
//! ```text
//!   cosigner → sighashes + its commitment for each
//!   wallet   → its commitment + its share for each      (it has both commitments by now)
//!   cosigner → computes its shares, aggregates, carries on
//! ```
//!
//! What the wallet gives up is seeing the finished signature, which it used to verify. That was
//! never the protection it looked like: a share is bound to one message and one pair of
//! commitments, so the cosigner cannot aggregate it over anything else — it would simply not
//! verify. And `aggregate` checks every share against its verifying share before summing, so a bad
//! wallet share is refused here rather than by the ASP.
//!
//! **Script-path only, by construction.** The taproot key-path tweak is compensated entirely on
//! the wallet's share, and the cosigner signs untweaked; a tweaked share would fail the share check
//! in `aggregate`. The cosigner only ever offers script-path sighashes on these streams, so that is
//! the right trade — but it is a property, not an accident.
//!
//! # With a service, the cosigner commits second
//!
//! FROST needs both parties' commitments before either can compute its share, and a signing nonce
//! is single-use: two signatures under one nonce give up the share by simple algebra. With the
//! wallet, the cosigner holds a stream open and keeps its nonce on the stack for the one round
//! trip. With a service it cannot — each message is one invocation, with a fresh instance and
//! nothing carried over — so a two-round exchange would mean writing a single-use nonce to disk.
//!
//! So the service commits first: its commitments ride the request. The cosigner then has both sides
//! the moment it is invoked, and produces its commitment and its share in one go. The nonce is born
//! and dies inside a single call and never reaches storage. The service aggregates, because it is
//! the party that has yet to make its own share.
//!
//! Committing second is safe for the same reason FROST is safe concurrently: the binding factor
//! covers the whole commitment set, so a share is a statement about one message and one set of
//! commitments and cannot be replayed into another. An adversary going second is the case the proof
//! already assumes; here the honest party goes second, which is strictly the better end of it.
//!

use std::collections::BTreeMap;

use rand::rngs::OsRng;
use threshold::commitment::SigningPackage;
use threshold::identifier::Identifier;
use threshold::keys::{KeyPackage, PublicKeyPackage};
use threshold::nonce::{self, SigningCommitments, SigningNonce};
use threshold::point;
use threshold::scalar::{scalar_from_bytes, scalar_to_bytes};
use threshold::signing::{self, SignatureShare};

use crate::escrow::{SignedHalf, WireCommitment};
use crate::types::Commitment;

/// What a session signs with: this cosigner's share of the key, the key's public package, and the
/// other signer's identifier.
///
/// The wallet's own key — see `Cosigner::signing_key` — or an escrow's: the ceremony does not
/// differ between them, only the share does.
pub struct SigningKey {
    pub key_package: KeyPackage,
    pub public_key_package: PublicKeyPackage,
    pub counterparty: Identifier,
}

/// One message's FROST ceremony, in flight: its commitments and shares as they arrive, and the
/// cosigner's single-use nonce.
#[derive(Default)]
struct Ceremony {
    message: Vec<u8>,
    commitments: BTreeMap<Identifier, SigningCommitments>,
    shares: BTreeMap<Identifier, SignatureShare>,
    /// Set at [`SigningSession::begin`], consumed at [`SigningSession::finish`].
    nonce: Option<SigningNonce>,
}

/// A FROST round the cosigner is halfway through, for every message in one batch.
///
/// Held by the `Sign`, `Send` or `Renew` handler across a single round trip — never by the
/// cosigner, so the nonces live on that stream's stack and a dropped stream takes them with it.
/// Deliberately opaque and not `Clone`: each ceremony owns a single-use nonce, and a copy is a
/// second use waiting to happen.
pub struct SigningSession {
    key: SigningKey,
    ceremonies: Vec<Ceremony>,
}

/// The wallet's half of one message's round: its commitment, and its share over both commitments.
pub struct WalletHalf {
    pub hiding: Vec<u8>,
    pub binding: Vec<u8>,
    pub share: Vec<u8>,
}

impl SigningSession {
    /// Round one, the cosigner's half: a fresh nonce for each message, and the commitment to it.
    ///
    /// The nonces are never persisted and never leave the session, so an interrupted round leaves
    /// nothing reusable behind.
    pub fn begin(key: SigningKey, messages: &[Vec<u8>]) -> (Self, Vec<Commitment>) {
        let ours = key.key_package.identifier.clone();
        let identifier_hex = hex::encode(ours.serialize());
        let mut rng = OsRng;
        let mut ceremonies = Vec::with_capacity(messages.len());
        let mut commitments = Vec::with_capacity(messages.len());
        for message in messages {
            let nonce = nonce::new_nonce(&mut rng, &key.key_package.secret_share);
            commitments.push(Commitment {
                identifier_hex: identifier_hex.clone(),
                hiding: point::serialize_compressed(&nonce.commitments.hiding).to_vec(),
                binding: point::serialize_compressed(&nonce.commitments.binding).to_vec(),
            });
            let mut ceremony = Ceremony {
                message: message.clone(),
                ..Default::default()
            };
            ceremony.commitments.insert(ours.clone(), nonce.commitments.clone());
            ceremony.nonce = Some(nonce);
            ceremonies.push(ceremony);
        }
        (Self { key, ceremonies }, commitments)
    }

    /// Round two: the counterparty's commitment and share for each message in, BIP-340 signatures
    /// out.
    ///
    /// [`WalletHalf`]s must be in the order the messages were — index `i` is a statement about
    /// message `i`, and nothing else ties them together. A count mismatch is refused outright,
    /// because a batch that is one short would otherwise sign every message against its
    /// neighbour's commitment and fail with an error that names the wrong one.
    ///
    /// Takes the session by value: every ceremony owns a single-use nonce.
    pub fn finish(self, halves: Vec<WalletHalf>) -> Result<Vec<Vec<u8>>, String> {
        let Self { key, ceremonies } = self;
        if halves.len() != ceremonies.len() {
            return Err(format!(
                "the wallet answered {} of {} messages",
                halves.len(),
                ceremonies.len()
            ));
        }
        ceremonies
            .into_iter()
            .zip(halves)
            .enumerate()
            .map(|(i, (mut ceremony, half))| {
                let at = |e: String| format!("message {i}: {e}");

                ceremony.commitments.insert(
                    key.counterparty.clone(),
                    SigningCommitments::from_bytes(&half.hiding, &half.binding)
                        .map_err(|e| at(e.to_string()))?,
                );
                let share_bytes: [u8; 32] = half
                    .share
                    .as_slice()
                    .try_into()
                    .map_err(|_| at("the wallet's share must be 32 bytes".into()))?;
                let theirs = scalar_from_bytes(&share_bytes)
                    .map_err(|e| at(format!("bad share scalar: {e}")))?;
                ceremony
                    .shares
                    .insert(key.counterparty.clone(), SignatureShare { s: theirs });

                // Both commitments are in, so the binding factors are final and the cosigner's
                // share can be computed. Doing this any earlier would sign under a package missing
                // the wallet's commitment — valid-looking, and wrong.
                let package =
                    SigningPackage::new(ceremony.commitments.clone(), ceremony.message.clone());
                let nonce = ceremony
                    .nonce
                    .take()
                    .ok_or_else(|| at("the nonce was already spent".into()))?;
                let ours = signing::sign(&package, &nonce, &key.key_package)
                    .map_err(|e| at(format!("frost sign: {e}")))?;
                ceremony.shares.insert(key.key_package.identifier.clone(), ours);

                // `aggregate` verifies each share against its verifying share before summing, so a
                // wallet share that does not belong to this message and these commitments stops
                // here, with the index attached, instead of at the ASP with nothing to say.
                let signature =
                    signing::aggregate(&package, &ceremony.shares, &key.public_key_package)
                        .map_err(|e| at(format!("frost aggregate: {e}")))?;
                Ok(signature.serialize().to_vec())
            })
            .collect()
    }
}

impl SigningKey {
    /// Round one and round two in one go, for the party that commits SECOND.
    ///
    /// The counterparty's commitments are already in hand, so the signing package is complete the
    /// moment this nonce exists and the share can be computed before the function returns. That is
    /// what keeps a single-use nonce off disk in a guest with no state between messages — see the
    /// module note.
    ///
    /// Each message gets its own nonce. Nothing is returned that could be used again: a share is a
    /// statement about one message and one set of commitments, and the counterparty still has to
    /// make its own before there is a signature at all.
    pub fn sign_second(
        &self,
        messages: &[Vec<u8>],
        theirs: &[WireCommitment],
    ) -> Result<Vec<SignedHalf>, String> {
        if messages.len() != theirs.len() {
            return Err(format!(
                "{} messages and {} commitments: index i must be a statement about message i",
                messages.len(),
                theirs.len()
            ));
        }
        if !self.public_key_package.verifying_shares.contains_key(&self.counterparty) {
            return Err("that counterparty is not in this pairing".into());
        }
        let ours = self.key_package.identifier.clone();
        if ours == self.counterparty {
            return Err("a party cannot be its own counterparty".into());
        }

        let mut rng = OsRng;
        let mut out = Vec::with_capacity(messages.len());
        for (i, message) in messages.iter().enumerate() {
            let at = |e: String| format!("message {i}: {e}");
            let theirs = SigningCommitments::from_hex(&theirs[i].hiding, &theirs[i].binding)
                .map_err(|e| at(e.to_string()))?;

            let nonce = nonce::new_nonce(&mut rng, &self.key_package.secret_share);
            let mut commitments = BTreeMap::new();
            commitments.insert(ours.clone(), nonce.commitments.clone());
            commitments.insert(self.counterparty.clone(), theirs);

            // Both commitments are in, so the binding factors are final. This is the whole reason
            // the exchange is shaped this way: nothing has to be held between two calls.
            let package = SigningPackage::new(commitments, message.clone());
            let share = signing::sign(&package, &nonce, &self.key_package)
                .map_err(|e| at(format!("frost sign: {e}")))?;

            out.push(SignedHalf {
                hiding: hex::encode(point::serialize_compressed(&nonce.commitments.hiding)),
                binding: hex::encode(point::serialize_compressed(&nonce.commitments.binding)),
                share: hex::encode(scalar_to_bytes(&share.s)),
            });
            // `nonce` is dropped here, having been used exactly once, and was never anywhere else.
        }
        Ok(out)
    }
}
