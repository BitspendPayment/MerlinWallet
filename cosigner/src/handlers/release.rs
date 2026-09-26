//! A service asking to be paid out of an escrow, and what has to be true before it is.
//!
//! # What a service sends, and why it is not a transaction
//!
//! An Ark send is not one transaction. It is an ark tx plus one checkpoint tx per input, and the
//! sighashes span both — so a serialized blob would have to be parsed, checked, and then have its
//! sighashes recomputed from the cosigner's own reading of it anyway. What a service sends is
//! therefore the *proposal*: where the money goes, how much, which of the escrow's VTXOs to spend,
//! and the external payment it is claiming against. The cosigner builds the transaction itself,
//! judges what it built, and signs what it judged. There is nothing to bind, because the thing
//! approved and the thing signed are one object.
//!
//! The built transactions go back in the reply, so the service submits exactly what was approved
//! rather than a rebuild of it.
//!
//! # The one number that comes from the service
//!
//! A proposed input carries an amount, and the cosigner has no independent reading of it — it does
//! not index the escrow's VTXOs. That is safe, and the reason is worth stating rather than
//! assuming: **a taproot sighash commits to every prevout amount and script**. A service that
//! understates its inputs to make a fee look small gets a signature that verifies against nothing,
//! and the ASP refuses the transaction. The only input claim that yields a usable signature is the
//! true one, so the fee checked below is the true fee or the signature is worthless. What a lie
//! costs the service is its own allowance: the release is recorded and no money moves.
//!
//! # Everything that must hold
//!
//! Six things, each checked here and none of them taken from the request:
//!
//! ```text
//!   1  the service that spoke is the one paired into this escrow   the connection, not the message
//!   2  the escrow permits a release now                            sealed session + the clock
//!   3  the transaction satisfies the policy                        outputs the cosigner built
//!   4  it fits what is left of the allowance                       sealed running total
//!   5  the external payment evidence satisfies the policy          fetched by the cosigner itself
//!   6  that evidence has not justified a release already           sealed reference index
//! ```
//!
//! Only then is anything signed, and what is signed is the sighashes of the transaction those six
//! checks were made about.
//!
//! # Signing, and why the cosigner commits second
//!
//! FROST needs both parties' commitments before either can compute its share, and a signing nonce
//! is single-use: two signatures under one nonce give up the share by simple algebra. With the
//! wallet, the cosigner holds a stream open and keeps its nonce on the stack for the one round
//! trip. Here it cannot — each message is one invocation, with a fresh instance and nothing
//! carried over — so a two-round exchange would mean writing a single-use nonce to disk.
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
//! # Concurrency, duplicates and retries
//!
//! The runtime holds this tenant's lock for the whole of an invocation, so two messages on one
//! connection cannot interleave and two releases of one escrow cannot race. What survives past that
//! is handled on sealed state: a repeat of an answered request is signed again and counted once, a
//! request id reused for a different proposal is refused, and a payment reference that has already
//! justified a release is refused whatever id it arrives under. See
//! [`EscrowSession::admit_release`].

use std::collections::{BTreeMap, BTreeSet};

use rand::rngs::OsRng;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use threshold::commitment::SigningPackage;
use threshold::identifier::Identifier;
use threshold::keys::{KeyPackage, PublicKeyPackage};
use threshold::nonce::{self, SigningCommitments};
use threshold::{point, scalar, signing};

use crate::cosigner::x_only;
use crate::asp::AspApi;
use crate::cosigner::Cosigner;
use crate::types::{Admission, ReleaseRecord};
use crate::evidence::{FetchEvidence, ReleaseFacts};
use crate::service_stream::{StreamRefusal, ToService};

/// The pay-to-anchor script every Ark transaction carries: `OP_1 <0x4e73>`.
///
/// Zero-value by construction, spendable by anyone, and there so a transaction can be fee-bumped.
/// It is not a party to the payment and must not be judged as one.
pub const ANCHOR_SCRIPT_HEX: &str = "51024e73";

/// How many VTXOs one release may spend. Each costs a checkpoint transaction and two sighashes, and
/// a proposal is a message on a connection with a ceiling of its own.
pub const MAX_RELEASE_INPUTS: usize = 64;

/// One of the escrow's VTXOs, as the service resolved it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProposedInput {
    pub txid: String,
    pub vout: u32,
    /// What the VTXO is worth. See the module note on why taking this from the service is safe.
    pub amount_sats: u64,
    /// The VTXO's own unilateral exit delay, which is part of its taproot tree — a mixed set
    /// genuinely differs, and one input's script cannot stand for another's.
    pub exit_delay: u32,
}

/// One party's FROST commitments for one message.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct WireCommitment {
    /// Compressed point, hex.
    pub hiding: String,
    /// Compressed point, hex.
    pub binding: String,
}

/// The cosigner's half of one message's signature: its commitment, and its share over both.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SignedHalf {
    pub hiding: String,
    pub binding: String,
    /// The signature share, 32 bytes, hex.
    pub share: String,
}

/// What a service asks for.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ReleaseRequest {
    /// The service's idempotency key. A repeat of it must be a repeat of the same proposal.
    pub request_id: String,
    /// Which escrow. Compared x-only, so either parity resolves.
    pub escrow_key: String,
    /// Where the money goes. An Ark address, and the policy decides whether it is an allowed one.
    pub to_ark_address: String,
    pub amount_sats: u64,
    /// The escrow's VTXOs to spend, in the order their sighashes will be in.
    pub inputs: Vec<ProposedInput>,
    /// The external payment being claimed. The service chooses it; it reaches a provider only as a
    /// path segment of a URL the sealed policy wrote.
    pub payment_reference: String,
    /// The service's commitments, one per sighash, in order.
    ///
    /// A release over `n` inputs has `2n` sighashes — one per input on the ark tx, and one per
    /// checkpoint. A count that does not match what the cosigner built is refused before any nonce
    /// is made, so the service's unused nonces are simply discarded.
    pub commitments: Vec<WireCommitment>,
}

impl ReleaseRequest {
    /// What was approved, reduced to a value a repeat can be compared against.
    ///
    /// Everything that changes what is signed, and nothing that does not: the commitments are a
    /// party's own single-use material and a retry is expected to bring fresh ones.
    pub fn proposal_hash(&self) -> String {
        // Length-prefixed, so no two different proposals can feed the hash the same bytes by
        // running one field into the next.
        fn feed(hasher: &mut Sha256, s: &str) {
            hasher.update((s.len() as u64).to_be_bytes());
            hasher.update(s.as_bytes());
        }
        let mut hasher = Sha256::new();
        feed(&mut hasher, &self.escrow_key.to_ascii_lowercase());
        feed(&mut hasher, &self.to_ark_address);
        feed(&mut hasher, &self.payment_reference);
        hasher.update(self.amount_sats.to_be_bytes());
        hasher.update((self.inputs.len() as u64).to_be_bytes());
        for input in &self.inputs {
            feed(&mut hasher, &input.txid.to_ascii_lowercase());
            hasher.update(input.vout.to_be_bytes());
            hasher.update(input.amount_sats.to_be_bytes());
            hasher.update(input.exit_delay.to_be_bytes());
        }
        hex::encode(hasher.finalize())
    }
}

/// What a service gets back when a release is approved.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ReleaseApproval {
    pub request_id: String,
    /// The ark transaction as built, base64 PSBT. Submit this, not a rebuild of it.
    pub ark_tx: String,
    /// One checkpoint transaction per input, base64 PSBTs, in input order.
    pub checkpoint_txs: Vec<String>,
    /// The cosigner's half of each sighash's signature, in sighash order.
    pub halves: Vec<SignedHalf>,
    /// Whether this was a fresh release or a repeat of one already counted. A service that lost a
    /// reply learns that its allowance was not charged twice.
    pub already_counted: bool,
}

impl Cosigner {
    /// Judge a release and, if it holds up, sign it.
    ///
    /// `Err` means something a retry might genuinely fix — the ASP was unreachable, the seal could
    /// not be written — and sends the service nothing, so it asks again. Everything the cosigner
    /// has *decided* comes back as `Ok`, because a refusal the service never receives is a refusal
    /// it will keep asking about.
    ///
    /// **The time this has.** One invocation, bounded by the runtime's request timeout — thirty
    /// seconds by default — and two outbound calls inside it: `get_info` from the ASP and the
    /// evidence GET. Both are given timeouts that fit, so a slow provider fails the release with
    /// something to say rather than having the whole call killed.
    pub async fn release<A: AspApi, F: FetchEvidence>(
        &mut self,
        stream_id: &str,
        request: &ReleaseRequest,
        asp: Option<A>,
        fetcher: &F,
    ) -> Result<ToService, String> {
        let refused = |reason: String| {
            Ok(ToService::ReleaseRefused {
                request_id: request.request_id.clone(),
                reason,
            })
        };
        match self.judge_release(stream_id, request, asp, fetcher).await {
            Ok(approval) => Ok(ToService::ReleaseSigned(Box::new(approval))),
            Err(Denial::Refused(reason)) => refused(reason),
            Err(Denial::Faulted(e)) => Err(e),
        }
    }

    async fn judge_release<A: AspApi, F: FetchEvidence>(
        &mut self,
        stream_id: &str,
        request: &ReleaseRequest,
        asp: Option<A>,
        fetcher: &F,
    ) -> Result<ReleaseApproval, Denial> {
        // --- 1. the service that spoke is the one paired into this escrow --------------------
        //
        // Not a check of anything in the request: the message arrived on a connection the runtime
        // holds to an origin this image resolved from the paired service's identifier, and nothing
        // a service sends can move it onto another service's connection.
        self.speaks_for(stream_id, &request.escrow_key, "")
            .map_err(|r| Denial::Refused(r.message()))?;

        let escrow = self
            .escrow(&request.escrow_key)
            .ok_or_else(|| Denial::Refused(StreamRefusal::UnknownEscrow.message()))?;
        let pairing = escrow
            .pairing
            .clone()
            .ok_or_else(|| Denial::Refused(StreamRefusal::UnknownEscrow.message()))?;
        if pairing.state() != crate::types::PairingState::Ready {
            return Err(Denial::Refused(format!(
                "this escrow's service pairing is not finished: {}",
                pairing.awaiting()
            )));
        }
        let session = escrow.session.clone().ok_or_else(|| {
            Denial::Refused(
                "this escrow is not committed to a deal, so there is nothing to release".into(),
            )
        })?;
        let escrow_key = escrow.escrow_key.clone();

        // --- 2. the escrow permits a release now ---------------------------------------------
        //
        // Asked here to refuse early — a closed escrow needs no transaction built and no provider
        // told about a release that is not going to happen. It is asked AGAIN before signing, and
        // that is the one that decides; see below.
        session
            .may_release(crate::handlers::helpers::now_secs())
            .map_err(|r| Denial::Refused(r.message().to_string()))?;

        // --- the transaction, built here from the proposal ------------------------------------
        if request.inputs.is_empty() {
            return Err(Denial::Refused(
                "a release that spends nothing pays nobody".into(),
            ));
        }
        if request.inputs.len() > MAX_RELEASE_INPUTS {
            return Err(Denial::Refused(format!(
                "a release may spend at most {MAX_RELEASE_INPUTS} VTXOs"
            )));
        }
        let mut seen = BTreeSet::new();
        for input in &request.inputs {
            if !seen.insert((input.txid.to_ascii_lowercase(), input.vout)) {
                return Err(Denial::Refused(
                    "the same VTXO is named twice, which is not a transaction this chain accepts"
                        .into(),
                ));
            }
        }

        let mut asp = asp.ok_or_else(|| {
            Denial::Refused(
                "this deployment names no ASP, so there is nothing to build a release against"
                    .into(),
            )
        })?;
        let info = asp
            .get_info()
            .await
            .map_err(|e| Denial::Faulted(format!("asking the ASP what it is: {e}")))?;

        let owner_pk_hex = x_only(&escrow_key);
        let vtxos: Vec<crate::types::VtxoInput> = request
            .inputs
            .iter()
            .map(|i| crate::types::VtxoInput {
                txid: i.txid.clone(),
                vout: i.vout,
                amount_sats: i.amount_sats,
                exit_delay: i.exit_delay,
                expires_at: 0,
            })
            .collect();
        let (send, _change_delay, sighashes) = crate::cosigner::build_send(
            &owner_pk_hex,
            &vtxos,
            &crate::types::SendVtxoStep1 {
                recipient_ark_address: request.to_ark_address.clone(),
                amount: request.amount_sats,
                vtxos: vtxos.clone(),
            },
            &info,
        )
        .map_err(|e| Denial::Refused(format!("that release does not build: {e}")))?;

        if request.commitments.len() != sighashes.len() {
            // Before any nonce is made, so nothing of this cosigner's is spent on a mismatch. The
            // service discards its own unused nonces and asks again with the right count.
            return Err(Denial::Refused(format!(
                "this release has {} things to sign and {} commitments arrived; send one \
                 commitment per signature, in order",
                sighashes.len(),
                request.commitments.len()
            )));
        }

        // What leaves the escrow, and what it costs. Change back to the escrow's own scripts is not
        // a payment to anybody, so it is not egress — the policy is told which scripts are ours.
        let mut owned = owned_scripts(&owner_pk_hex, &info, &request.inputs)
            .map_err(|e| Denial::Faulted(format!("working out this escrow's own scripts: {e}")))?;
        let outputs = crate::policy::outputs_of_txouts(send.outputs());

        // The anchor is not a destination. Every Ark transaction carries a zero-value pay-to-anchor
        // output so the transaction can be fee-bumped; it pays nobody, and a policy that counted it
        // as egress would refuse every release ever made.
        //
        // Only at zero, and that matters: anyone can spend a P2A output, so one carrying value
        // would be money leaving the escrow to whoever claimed it first. If one ever does, that is
        // not an anchor and it is not waved through.
        if outputs.iter().any(|o| o.script_pubkey_hex == ANCHOR_SCRIPT_HEX) {
            if let Some(bearing) = outputs
                .iter()
                .find(|o| o.script_pubkey_hex == ANCHOR_SCRIPT_HEX && o.sats > 0)
            {
                return Err(Denial::Refused(format!(
                    "this release puts {} sats in a pay-to-anchor output, which anybody may spend",
                    bearing.sats
                )));
            }
            owned.insert(ANCHOR_SCRIPT_HEX.to_string());
        }
        let paid_in: u64 = request.inputs.iter().map(|i| i.amount_sats).sum();
        let paid_out: u64 = outputs.iter().map(|o| o.sats).sum();
        let fee_sats = paid_in.checked_sub(paid_out).ok_or_else(|| {
            Denial::Refused("this release pays out more than it spends".into())
        })?;
        let egress_sats: u64 = outputs
            .iter()
            .filter(|o| !owned.contains(&o.script_pubkey_hex))
            .map(|o| o.sats)
            .sum();

        // --- 6. has this payment justified a release already? --------------------------------
        //
        // Before the evidence is fetched, not after: a reference that has already been spent needs
        // no provider to tell us it succeeded, and asking would only tell the provider about a
        // release that is not going to happen.
        let proposal_hash = request.proposal_hash();
        let admission = self
            .admit_release(
                &escrow_key,
                &request.request_id,
                &request.payment_reference,
                &proposal_hash,
            )
            .map_err(Denial::Refused)?;

        // --- 3, 4 and 5. the policy, over what was built and what was fetched ------------------
        //
        // A repeat of a release that was already counted must not be counted again while it is
        // being judged. Its sats are in `released_sats` already, so adding them a second time
        // would refuse a repeat of a release that fitted perfectly well when it was made — and a
        // service whose reply was lost would be locked out of the answer it was owed.
        let already_released_sats = match &admission {
            Admission::AlreadyAnswered(record) => {
                // Answered under THIS deal, or it is not an answer this deal owes. A release signed
                // under the last deal and never broadcast would otherwise be re-signed here, judged
                // as a repeat, and never counted against this deal's allowance.
                if record.at < session.opened_at {
                    return Err(Denial::Refused(format!(
                        "request {} was answered under a previous deal; a release from this one \
                         needs a new request id and a new payment",
                        request.request_id
                    )));
                }
                session.released_sats.saturating_sub(record.sats)
            }
            Admission::New => session.released_sats,
        };
        let facts = ReleaseFacts {
            reference: request.payment_reference.clone(),
            sats: egress_sats,
            fee_sats,
            already_released_sats,
        };
        let evidence =
            crate::evidence::gather(fetcher, &session.policy.evidence_needed(&facts)).await;
        crate::policy::enforce_release(
            &session.policy,
            Some(&outputs),
            &owned,
            &facts,
            &evidence,
        )
        .map_err(Denial::Refused)?;

        // --- 2, again, and this is the check that counts --------------------------------------
        //
        // The clock moved while this was asking other people questions. Between the first check
        // and here there were two calls out — the ASP's `get_info` and the evidence GET — each
        // with seconds of budget, and a provider that takes its time is the normal case rather
        // than a strange one.
        //
        // It has to be asked again because this refusal is the ONLY thing holding the escrow's
        // boundary. Nothing in Bitcoin stops a signature made after the deadline: both pairs sign
        // the same key, so what stops a service taking money the owner is entitled to reclaim is
        // this cosigner declining to co-sign, and a decision made on a clock reading from before
        // the wait is not a decision about now.
        let signing_at = crate::handlers::helpers::now_secs();
        session
            .may_release(signing_at)
            .map_err(|r| Denial::Refused(r.message().to_string()))?;

        // --- and only now, a signature --------------------------------------------------------
        let key_package = KeyPackage::from_json(&pairing.key_package_json)
            .map_err(|e| Denial::Faulted(format!("this pairing's sealed share is unreadable: {e}")))?;
        let public_key_package = PublicKeyPackage::from_json(&pairing.public_key_package_json)
            .map_err(|e| {
                Denial::Faulted(format!("this pairing's sealed package is unreadable: {e}"))
            })?;
        let service_id = identifier_from_hex(&pairing.service_identifier_hex)
            .map_err(|e| Denial::Faulted(format!("this pairing's sealed identifier: {e}")))?;
        // --- written down and sealed, and only then signed ------------------------------------
        //
        // In that order, because the ledger is the only thing that stops a payment paying twice,
        // and every request reopens from the seal: a release signed before its record was durable
        // is one the next instance has never heard of. If the seal cannot be written the release
        // is refused, and the in-memory record is rolled back so this instance does not go on
        // believing something the seal does not. The service retries; a retry of a release that
        // WAS recorded is answered again from the record, so nothing is lost by refusing here.
        let already_counted = matches!(admission, Admission::AlreadyAnswered(_));
        if !already_counted {
            let before = self.to_snapshot().map_err(Denial::Faulted)?;
            self.record_escrow_release(
                &escrow_key,
                request.payment_reference.clone(),
                ReleaseRecord {
                    // The same reduction the ledger compares by: a key named with either parity
                    // is one escrow. `trim_start_matches` would be wrong here — it strips repeats,
                    // and an x-only key may itself begin "02".
                    escrow_key: x_only(&escrow_key),
                    request_id: request.request_id.clone(),
                    sats: egress_sats,
                    at: signing_at,
                    proposal_hash,
                },
            )
            .map_err(Denial::Faulted)?;
            if let Err(e) = self.try_seal() {
                if let Err(undo) = self.restore_snapshot(&before) {
                    tracing::error!("rolling back an unsealed release failed too: {undo}");
                }
                return Err(Denial::Faulted(format!(
                    "this release could not be written down, so it was not signed: {e}"
                )));
            }
        }

        let halves = sign_second(
            &key_package,
            &public_key_package,
            &service_id,
            &sighashes,
            &request.commitments,
        )
        .map_err(Denial::Refused)?;

        let (ark_tx, checkpoint_txs) = send.unsigned();
        Ok(ReleaseApproval {
            request_id: request.request_id.clone(),
            ark_tx,
            checkpoint_txs,
            halves,
            already_counted,
        })
    }
}

/// A conclusion the service is told, or a fault a retry might fix.
enum Denial {
    Refused(String),
    Faulted(String),
}

/// Round one and round two in one go, for the party that commits SECOND.
///
/// The counterparty's commitments are already in hand, so the signing package is complete the
/// moment this nonce exists and the share can be computed before the function returns. That is what
/// keeps a single-use nonce off disk in a guest with no state between messages — see the module
/// note.
///
/// Each message gets its own nonce. Nothing is returned that could be used again: a share is a
/// statement about one message and one set of commitments, and the counterparty still has to make
/// its own before there is a signature at all.
pub fn sign_second(
    key_package: &KeyPackage,
    public_key_package: &PublicKeyPackage,
    counterparty: &Identifier,
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
    if !public_key_package
        .verifying_shares
        .contains_key(counterparty)
    {
        return Err("that counterparty is not in this pairing".into());
    }
    let ours = key_package.identifier.clone();
    if &ours == counterparty {
        return Err("a party cannot be its own counterparty".into());
    }

    let mut rng = OsRng;
    let mut out = Vec::with_capacity(messages.len());
    for (i, message) in messages.iter().enumerate() {
        let at = |e: String| format!("message {i}: {e}");
        let theirs = commitments_from_hex(&theirs[i].hiding, &theirs[i].binding).map_err(at)?;

        let nonce = nonce::new_nonce(&mut rng, &key_package.secret_share);
        let mut commitments = BTreeMap::new();
        commitments.insert(ours.clone(), nonce.commitments.clone());
        commitments.insert(counterparty.clone(), theirs);

        // Both commitments are in, so the binding factors are final. This is the whole reason the
        // exchange is shaped this way: nothing has to be held between two calls.
        let package = SigningPackage::new(commitments, message.clone());
        let share = signing::sign(&package, &nonce, key_package)
            .map_err(|e| at(format!("frost sign: {e}")))?;

        out.push(SignedHalf {
            hiding: hex::encode(point::serialize_compressed(&nonce.commitments.hiding)),
            binding: hex::encode(point::serialize_compressed(&nonce.commitments.binding)),
            share: hex::encode(scalar::scalar_to_bytes(&share.s)),
        });
        // `nonce` is dropped here, having been used exactly once, and was never anywhere else.
    }
    Ok(out)
}

fn commitments_from_hex(hiding: &str, binding: &str) -> Result<SigningCommitments, String> {
    let point = |what: &str, s: &str| -> Result<_, String> {
        let bytes: [u8; 33] = hex::decode(s)
            .map_err(|e| format!("{what} is not hex: {e}"))?
            .try_into()
            .map_err(|_| format!("{what} must be a 33-byte compressed point"))?;
        point::deserialize_compressed(&bytes).map_err(|e| format!("bad {what}: {e}"))
    };
    Ok(SigningCommitments {
        hiding: point("hiding commitment", hiding)?,
        binding: point("binding commitment", binding)?,
    })
}

fn identifier_from_hex(s: &str) -> Result<Identifier, String> {
    let bytes: [u8; 32] = hex::decode(s)
        .map_err(|e| format!("not hex: {e}"))?
        .try_into()
        .map_err(|_| "an identifier is 32 bytes".to_string())?;
    Identifier::deserialize(&bytes).map_err(|e| format!("{e}"))
}

/// The scriptPubKeys that belong to this escrow: one per exit delay among the inputs, plus the one
/// change is paid to. An output to any of these is not a payment to anybody — it is the escrow's
/// own money staying where it was.
fn owned_scripts(
    owner_pk_hex: &str,
    info: &ark::client::types::ArkInfo,
    inputs: &[ProposedInput],
) -> Result<BTreeSet<String>, String> {
    let network = ark::client::parse_network(&info.network)?;
    let mut delays: BTreeSet<u32> = inputs.iter().map(|i| i.exit_delay).collect();
    // `build_send` derives change at the ASP's unilateral exit delay, whatever the inputs' were.
    delays.insert(info.unilateral_exit_delay as u32);
    delays
        .into_iter()
        .map(|delay| {
            ark::client::vtxo_script_pubkey_hex(owner_pk_hex, &info.signer_pubkey, delay, network)
                .map(|s| s.to_ascii_lowercase())
        })
        .collect()
}
