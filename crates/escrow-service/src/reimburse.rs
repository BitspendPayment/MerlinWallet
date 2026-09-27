//! Asking to be reimbursed, and turning the answer into money.
//!
//! # The shape of the ask
//!
//! The service does not send a transaction. An Ark send is an ark transaction plus one checkpoint
//! per input, and a blob handed over would have to be re-derived before it could be signed — so
//! what goes is the **proposal**: which of the escrow's VTXOs to spend, where, how much, and the
//! payment it is claiming against. The cosigner builds the transaction itself, judges what it
//! built, and signs what it judged.
//!
//! Commitments ride the ask, because the cosigner cannot hold a nonce between messages. See
//! [`crate::signing`].
//!
//! # And then it is checked, not trusted
//!
//! The reply carries the transactions the cosigner built. This service rebuilds them from the same
//! proposal and compares the bytes before it signs anything. A mismatch means the thing approved
//! and the thing about to be broadcast are different objects, and the only safe move is to stop.
//!
//! # Signing is not being paid
//!
//! A valid signature is arithmetic. Money moves when the ASP accepts the transaction, which is a
//! separate step that can fail on its own — so [`Stage::ReleaseSigned`] and
//! [`Stage::ReleaseConfirmed`] are different states and the second is never assumed from the first.

use std::sync::Arc;
use std::time::Duration;

use ark::client::send::SendVtxoInput;
use ark::client::AspClient;
use super::{PersistedInput, PersistedProposal};
use cosigner::handlers::release::{ProposedInput, ReleaseRequest};
use cosigner::service_stream::{FromService, ToService};

use super::signing::{x_only, Proposal, Round};
use super::wire::{say, Wire};
use super::Stage;

/// How long to wait for the cosigner to answer one ask.
///
/// Generous, because the answer is not instant by design: the cosigner fetches the payment evidence
/// for itself, from a provider that may be a continent away, inside the one invocation the runtime
/// gives it.
const ANSWER_TIMEOUT: Duration = Duration::from_secs(45);

/// How long to wait for the runtime to re-dial before giving up on one attempt.
///
/// A drop is transient by design — the runtime is already dialling again, with a backoff of one
/// second growing to five minutes. Waiting out the early steps turns the common case from "failed"
/// into "slightly late". Past that it is not a blip and the retry loop has it.
const CONNECT_WAIT: Duration = Duration::from_secs(20);

/// How often to pick up work that has not finished.
///
/// **Not the scheduler that was removed from the enclave.** That was a timer inside a guest with no
/// execution context, armed for an escrow's deadline. This is an ordinary long-running process
/// retrying its own outstanding work, which is what such a process is for — and the enclave still
/// has no timer of any kind.
pub const RETRY_EVERY: Duration = Duration::from_secs(15);

/// What happened when this service asked.
#[derive(Debug)]
pub enum Asked {
    /// Signed, submitted, and the ASP took it.
    Confirmed { ark_txid: String, sats: u64 },
    /// The cosigner would not sign, and said why. Not an error — it is an answer, and usually the
    /// right one.
    ///
    /// `deal` is the deal the escrow is committed to, as the cosigner itself reported it — its
    /// deadline and which policy was sealed. What a service that asks before paying reads, rather
    /// than anything the owner's app told it. `None` when there is no deal, or the answer came
    /// from something other than the escrow's own cosigner.
    Refused {
        reason: String,
        deal: Option<cosigner::escrow_session::DealTerms>,
    },
    /// Something went wrong on this side. Worth retrying.
    Failed { reason: String },
    /// The outcome cannot be determined from here — see the note on
    /// [`Reimbursement::needs_reconciliation`](crate::Reimbursement::needs_reconciliation).
    NeedsReconciliation,
}

/// Ask to be reimbursed for one payment, and see it through to the chain.
pub async fn ask(wire: &Arc<Wire>, request_id: &str) -> Asked {
    ask_against(wire, request_id, None).await
}

/// Ask, naming a payment reference other than the settlement.
///
/// A settlement service asks about the **settlement**, because that is what money is owed on, and
/// this service's own `ready_to_ask` says so. Asking about anything else is refused by the cosigner,
/// and that refusal is what this is for:
///
/// - a demonstration asks about a card authorization on purpose, so the refusal can be seen rather
///   than taken on trust;
/// - a payout service asks about its payout *before funding it*. The one refusal it expects, "not
///   completed", shows every other term of the sealed policy already holds — so it knows it will
///   be paid before it pays. The proposal written down by that ask is the one the real ask reuses.
///
/// The cosigner does not care that the ask is early. It fetches whatever reference it is given and
/// checks what the sealed policy says to check.
pub async fn ask_against(
    wire: &Arc<Wire>,
    request_id: &str,
    reference: Option<&str>,
) -> Asked {
    // One at a time per ESCROW, not per reimbursement. Two payments on one escrow asked for at
    // once would each read the same VTXOs, each propose spending them, and each be signed — which
    // spends the allowance twice for money only one of them can move, and leaves the loser tied to
    // inputs that no longer exist.
    let escrow_key = {
        let store = wire.service.store.lock().await;
        match store.reimbursements.get(request_id) {
            // Returned before anything is written, so the reason it was given up on survives.
            Some(r) if r.given_up => {
                return Asked::Failed {
                    reason: format!(
                        "{request_id} was given up on ({}), so nothing is asked about it",
                        r.last_refusal.as_deref().unwrap_or("no reason recorded")
                    ),
                }
            }
            Some(r) => r.escrow_key.to_ascii_lowercase(),
            None => {
                return Asked::Failed {
                    reason: format!("nothing is tracked under {request_id}"),
                }
            }
        }
    };
    let Some(_claim) = wire.service.claim(&escrow_key).await else {
        return Asked::Failed {
            reason: "something else is already spending from this escrow".into(),
        };
    };
    match attempt(wire, request_id, reference).await {
        Ok(outcome) => outcome,
        Err(reason) => {
            let mut store = wire.service.store.lock().await;
            if let Some(r) = store.reimbursements.get_mut(request_id) {
                r.last_refusal = Some(reason.clone());
            }
            Asked::Failed { reason }
        }
    }
}

/// Tell the cosigner this service is done with a deal — a payout that failed, say — so the escrow
/// is free at once rather than at a deadline that may be hours away.
///
/// `policy_sha256` names the deal (see [`cosigner::escrow_session::DealTerms`]), so an end that
/// arrives late cannot close the next deal struck over the same escrow. The deal protects this
/// service, so this gives up nothing but its own claim: only give up on a payment first, and never
/// one that has been signed for. `Ok` once the cosigner acknowledged it.
pub async fn end_deal(wire: &Arc<Wire>, escrow_key: &str, policy_sha256: &str) -> Result<(), String> {
    let stream_id = wire
        .service
        .store
        .lock()
        .await
        .shares
        .get(&escrow_key.to_ascii_lowercase())
        .map(|share| share.stream_id.clone())
        .ok_or_else(|| format!("this service holds no share of {escrow_key}"))?;
    wait_for_connection(wire, &stream_id).await?;

    let answer = wire.connections.expect(&stream_id, policy_sha256);
    say(
        wire,
        &stream_id,
        FromService::EndDeal {
            escrow_key: escrow_key.to_string(),
            policy_sha256: policy_sha256.to_string(),
        },
    );
    match tokio::time::timeout(ANSWER_TIMEOUT, answer).await {
        Ok(Ok(ToService::Ack { .. })) => Ok(()),
        Ok(Ok(ToService::Refused { reason, .. })) => Err(reason),
        Ok(Ok(other)) => Err(format!("the cosigner said something unexpected: {other:?}")),
        Ok(Err(_)) | Err(_) => {
            wire.connections.stop_expecting(&stream_id, policy_sha256);
            Err("the cosigner did not answer".into())
        }
    }
}

async fn attempt(
    wire: &Arc<Wire>,
    request_id: &str,
    reference_override: Option<&str>,
) -> Result<Asked, String> {
    let reimbursement = {
        let store = wire.service.store.lock().await;
        store
            .reimbursements
            .get(request_id)
            .cloned()
            .ok_or_else(|| format!("nothing is tracked under {request_id}"))?
    };

    // Is another payment part-way through spending this escrow?
    //
    // Asked before anything is dialled, and only when this reimbursement has not already picked out
    // its own inputs — a retry of a spend that is already reserved is the holder itself coming back.
    //
    // The in-memory claim is not enough on its own. It is released when an attempt returns, and an
    // attempt returns on a failed submission too — at which point the transaction may still be on
    // its way to the chain, the inputs are still unspent, and a second payment would happily
    // select them. It also dies with the process.
    if reimbursement.proposal.is_none() {
        if let Some(holder) = wire
            .service
            .reserved_by(&reimbursement.escrow_key, request_id)
            .await
        {
            return Err(format!(
                "{holder} has a spend of this escrow part-finished, and the inputs it picked out \
                 may yet be spent; this waits until that one is settled or given up on"
            ));
        }
    }

    // Only now what this service can do about it. The question above is about the escrow; this one
    // is about whether we can sign at all, and it is the more fundamental failure — so it is asked
    // second, where its answer is not competing with a reason to wait.
    let share = {
        let store = wire.service.store.lock().await;
        store
            .shares
            .get(&reimbursement.escrow_key.to_ascii_lowercase())
            .cloned()
            .ok_or_else(|| {
                format!("this service holds no share of {}", reimbursement.escrow_key)
            })?
    };

    let reference = match reference_override {
        Some(forced) => forced.to_string(),
        None => reimbursement
            .reference()
            .ok_or("that payment has not settled, so there is nothing to be reimbursed for")?
            .to_string(),
    };

    // What the escrow actually holds, read from the indexer rather than remembered.
    let mut asp = AspClient::connect(&wire.service.asp_url)
        .await
        .map_err(|e| format!("connecting to the ASP: {e}"))?;
    let info = asp
        .get_info()
        .await
        .map_err(|e| format!("asking the ASP what it is: {e}"))?;
    // The proposal. Either the one this was first asked under, or — the first time — a new one
    // built from what the escrow holds and written down before anything is asked.
    //
    // A retry MUST propose the same release. The request id is what makes a repeat safe, and the
    // cosigner holds it to the proposal it answered: rebuild from current inputs and a release that
    // left change behind would propose spending the change, which is a different release under an
    // answered id, refused for ever.
    let proposal = match &reimbursement.proposal {
        Some(kept) => Proposal {
            escrow_key: reimbursement.escrow_key.clone(),
            to_ark_address: kept.to_ark_address.clone(),
            amount_sats: kept.amount_sats,
            inputs: kept
                .inputs
                .iter()
                .map(|i| SendVtxoInput {
                    txid: i.txid.clone(),
                    vout: i.vout,
                    amount_sats: i.amount_sats,
                    exit_delay: i.exit_delay,
                })
                .collect(),
        },
        None => {
            let inputs = escrow_inputs(&mut asp, &reimbursement.escrow_key, &info).await?;
            if inputs.is_empty() {
                return Err("this escrow holds nothing to be reimbursed from".into());
            }
            let proposal = Proposal {
                escrow_key: reimbursement.escrow_key.clone(),
                to_ark_address: wire.service.payout_ark_address.clone(),
                amount_sats: reimbursement.sats,
                inputs,
            };
            remember_proposal(wire, request_id, &proposal).await?;
            proposal
        }
    };

    // Are the inputs it names still there to spend? If not, something has spent them — and the only
    // thing that could is this release, landing on an attempt whose answer was lost. Ask the chain
    // rather than guess.
    if !still_spendable(&mut asp, &proposal).await? {
        return reconcile(wire, request_id, &mut asp).await;
    }

    // Already signed, and never submitted. Finish it without asking anybody.
    //
    // This is the path that matters after a crash between signing and submitting. The release was
    // approved and the signatures are on hand, so no second approval is needed — which is just as
    // well, because a deadline that has passed since means the cosigner would rightly refuse to
    // give one, and the service has already paid out.
    if !reimbursement.signatures.is_empty() {
        let signatures = signatures_from_hex(&reimbursement.signatures)?;
        let (mut session, _) = proposal.build(&info)?;
        session.sign_with_frost(signatures)?;
        return submit_and_record(wire, request_id, session, &mut asp, reimbursement.sats).await;
    }

    // Round one: commit first, so the cosigner can do both of its rounds in one invocation and
    // never write a nonce down. These nonces live here, in this frame, and nowhere else.
    let key_package = share.key_package()?;
    let (round, commitments) = Round::begin(&key_package, proposal.messages());

    // The connection THIS escrow's pairing arrived on. Not "whichever is open": the local half of
    // a stream name is the same for every wallet this service serves, so picking the first would
    // send one customer's request down another's socket.
    let stream_id = share.stream_id.clone();
    wait_for_connection(wire, &stream_id).await?;

    let request = ReleaseRequest {
        request_id: request_id.to_string(),
        escrow_key: reimbursement.escrow_key.clone(),
        to_ark_address: proposal.to_ark_address.clone(),
        amount_sats: proposal.amount_sats,
        inputs: proposal
            .inputs
            .iter()
            .map(|i| ProposedInput {
                txid: i.txid.clone(),
                vout: i.vout,
                amount_sats: i.amount_sats,
                exit_delay: i.exit_delay,
            })
            .collect(),
        payment_reference: reference,
        commitments,
    };

    // Registered before the question goes out: an answer faster than this service can start
    // listening still has somewhere to land.
    let answer = wire.connections.expect(&stream_id, request_id);
    say(wire, &stream_id, FromService::ReleaseRequest(Box::new(request)));

    let reply = match tokio::time::timeout(ANSWER_TIMEOUT, answer).await {
        Ok(Ok(reply)) => reply,
        Ok(Err(_)) | Err(_) => {
            wire.connections.stop_expecting(&stream_id, request_id);
            return Err("the cosigner did not answer".into());
        }
    };

    let approval = match reply {
        ToService::ReleaseSigned(approval) => approval,
        ToService::ReleaseRefused { reason, deal, .. } => {
            return refused(wire, request_id, reason, deal).await
        }
        ToService::Refused { reason, .. } => return refused(wire, request_id, reason, None).await,
        other => return Err(format!("the cosigner said something unexpected: {other:?}")),
    };

    // The cosigner fetched the evidence and it satisfied the policy — which is its judgement, not
    // this service's, and this is the first moment this service may record it.
    wire.service.advance(request_id, Stage::EvidenceVerified).await;

    // Rebuild what was approved, and refuse anything that is not it.
    let (mut session, sighashes) = proposal.rebuild(
        &info,
        &approval.ark_tx,
        &approval.checkpoint_txs,
    )?;

    let signatures = round.finish(&share, &sighashes, &approval.halves)?;
    session.sign_with_frost(signatures.clone())?;

    // Everything needed to finish this, written down before anything is attempted: the signatures,
    // which are public, and the txid, which a taproot witness does not change so it is already
    // fixed. With these a restart can submit without asking for a second approval — and can ask the
    // chain whether the first attempt landed rather than guessing.
    {
        let mut store = wire.service.store.lock().await;
        if let Some(r) = store.reimbursements.get_mut(request_id) {
            r.stage = Stage::ReleaseSigned.max(r.stage);
            r.signatures = signatures.iter().map(hex::encode).collect();
            r.expected_txid = Some(session.ark_txid());
        }
    }
    wire.service
        .persist()
        .await
        .map_err(|e| format!("what is about to be submitted could not be written down: {e}"))?;

    submit_and_record(wire, request_id, session, &mut asp, reimbursement.sats).await
}

/// The cosigner refused: write down why, and say so. An answer, not a failure — see [`Asked`].
async fn refused(
    wire: &Arc<Wire>,
    request_id: &str,
    reason: String,
    deal: Option<cosigner::escrow_session::DealTerms>,
) -> Result<Asked, String> {
    let mut store = wire.service.store.lock().await;
    if let Some(r) = store.reimbursements.get_mut(request_id) {
        r.last_refusal = Some(reason.clone());
    }
    drop(store);
    let _ = wire.service.persist().await;
    Ok(Asked::Refused { reason, deal })
}

/// Submit what has been signed, and write down what the chain did with it.
///
/// A signature is arithmetic. This is the payment, and it is recorded separately for that reason.
async fn submit_and_record(
    wire: &Arc<Wire>,
    request_id: &str,
    mut session: ark::client::send::SendSession,
    asp: &mut AspClient,
    sats: u64,
) -> Result<Asked, String> {
    let ark_txid = session
        .submit(asp)
        .await
        .map_err(|e| format!("the ASP would not take it: {e}"))?;

    {
        let mut store = wire.service.store.lock().await;
        if let Some(r) = store.reimbursements.get_mut(request_id) {
            r.stage = Stage::ReleaseConfirmed;
            r.ark_txid = Some(ark_txid.clone());
            r.last_refusal = None;
        }
    }
    wire.service
        .persist()
        .await
        .map_err(|e| format!("the outcome could not be written down: {e}"))?;

    Ok(Asked::Confirmed { ark_txid, sats })
}

fn signatures_from_hex(kept: &[String]) -> Result<Vec<[u8; 64]>, String> {
    kept.iter()
        .enumerate()
        .map(|(i, s)| {
            hex::decode(s)
                .map_err(|e| format!("signature {i} is not hex: {e}"))?
                .try_into()
                .map_err(|_| format!("signature {i} is not 64 bytes"))
        })
        .collect()
}

/// Write down what is being proposed, before anything is asked about it.
async fn remember_proposal(
    wire: &Arc<Wire>,
    request_id: &str,
    proposal: &Proposal,
) -> Result<(), String> {
    {
        let mut store = wire.service.store.lock().await;
        let Some(r) = store.reimbursements.get_mut(request_id) else {
            return Err(format!("nothing is tracked under {request_id}"));
        };
        r.proposal = Some(PersistedProposal {
            to_ark_address: proposal.to_ark_address.clone(),
            amount_sats: proposal.amount_sats,
            inputs: proposal
                .inputs
                .iter()
                .map(|i| PersistedInput {
                    txid: i.txid.clone(),
                    vout: i.vout,
                    amount_sats: i.amount_sats,
                    exit_delay: i.exit_delay,
                })
                .collect(),
        });
    }
    wire.service
        .persist()
        .await
        .map_err(|e| format!("the proposal could not be written down: {e}"))
}

/// Are the inputs this proposal names still there to spend?
async fn still_spendable(asp: &mut AspClient, proposal: &Proposal) -> Result<bool, String> {
    let outpoints: Vec<String> = proposal
        .inputs
        .iter()
        .map(|i| format!("{}:{}", i.txid, i.vout))
        .collect();
    let found = asp
        .get_vtxos_by_outpoints(&outpoints)
        .await
        .map_err(|e| format!("asking the indexer about this release's inputs: {e}"))?;
    // Spent ones come back marked rather than missing, so both are checked.
    Ok(found.len() == outpoints.len() && !found.iter().any(|v| v.is_spent))
}

/// The inputs are gone. Did this release spend them, or did something else?
///
/// Answered by asking the chain about the transaction that was written down before submission —
/// not by assuming. If its output is there, the release landed and the lost reply is all that was
/// missing. If it is not, something else spent the escrow and a person has to look.
async fn reconcile(
    wire: &Arc<Wire>,
    request_id: &str,
    asp: &mut AspClient,
) -> Result<Asked, String> {
    let expected = {
        let store = wire.service.store.lock().await;
        store
            .reimbursements
            .get(request_id)
            .and_then(|r| r.expected_txid.clone())
    };

    if let Some(txid) = expected {
        let landed = asp
            .get_vtxos_by_outpoints(&[format!("{txid}:0")])
            .await
            .map_err(|e| format!("asking the indexer whether {txid} landed: {e}"))?;
        if !landed.is_empty() {
            // It landed. The only thing that went missing was the answer.
            {
                let mut store = wire.service.store.lock().await;
                if let Some(r) = store.reimbursements.get_mut(request_id) {
                    r.stage = Stage::ReleaseConfirmed;
                    r.ark_txid = Some(txid.clone());
                    r.last_refusal = None;
                }
            }
            wire.service
                .persist()
                .await
                .map_err(|e| format!("the outcome could not be written down: {e}"))?;
            let sats = wire
                .service
                .tracked()
                .await
                .into_iter()
                .find(|r| r.request_id == request_id)
                .map_or(0, |r| r.sats);
            return Ok(Asked::Confirmed {
                ark_txid: txid,
                sats,
            });
        }
    }

    // Either nothing was ever signed, or what was signed is not what spent the escrow. Retrying
    // would propose a release against inputs that no longer exist, for ever.
    {
        let mut store = wire.service.store.lock().await;
        if let Some(r) = store.reimbursements.get_mut(request_id) {
            r.needs_reconciliation = true;
            r.last_refusal = Some(format!(
                "the inputs this release names have been spent, and {} — so this service cannot \
                 tell whether it was paid. Reconcile it against the chain.",
                match &r.expected_txid {
                    Some(txid) => format!("the transaction it signed ({txid}) is not on the chain"),
                    None => "nothing was ever signed for it".into(),
                }
            ));
        }
    }
    wire.service
        .persist()
        .await
        .map_err(|e| format!("the outcome could not be written down: {e}"))?;
    Ok(Asked::NeedsReconciliation)
}

/// Wait for the runtime to have a connection to this service again.
///
/// It is not this service's job to make one — it cannot; it has no way to reach the enclave. The
/// runtime dials, and after a drop it keeps dialling. So the only useful thing to do about a
/// connection that is momentarily down is to wait a little for it to come back.
async fn wait_for_connection(wire: &Arc<Wire>, stream_id: &str) -> Result<(), String> {
    let deadline = tokio::time::Instant::now() + CONNECT_WAIT;
    loop {
        if wire.connections.held_ids().iter().any(|id| id == stream_id) {
            return Ok(());
        }
        if tokio::time::Instant::now() >= deadline {
            return Err(format!(
                "the enclave has not been connected on {stream_id} for {}s; the runtime re-dials \
                 with a backoff, so this is asked again by the retry loop rather than dropped",
                CONNECT_WAIT.as_secs()
            ));
        }
        tokio::time::sleep(Duration::from_millis(250)).await;
    }
}

/// What the escrow's address holds, from the indexer.
async fn escrow_inputs(
    asp: &mut AspClient,
    escrow_key: &str,
    info: &ark::client::types::ArkInfo,
) -> Result<Vec<SendVtxoInput>, String> {
    let network = ark::client::parse_network(&info.network)?;
    let exit_delay = info.unilateral_exit_delay as u32;
    let script = ark::client::vtxo_script_pubkey_hex(
        &x_only(escrow_key),
        &info.signer_pubkey,
        exit_delay,
        network,
    )?;
    let vtxos = asp
        .get_vtxos_by_scripts(&[script])
        .await
        .map_err(|e| format!("asking the indexer what the escrow holds: {e}"))?;
    Ok(vtxos
        .into_iter()
        .filter_map(|v| {
            let outpoint = v.outpoint?;
            Some(SendVtxoInput {
                txid: outpoint.txid,
                vout: outpoint.vout,
                amount_sats: v.amount,
                exit_delay,
            })
        })
        .collect())
}

/// Keep asking about anything that has not finished, for as long as the process lives.
///
/// **This is what makes a dropped connection survivable.** The runtime re-dials on its own, but
/// re-dialling does not by itself finish a reimbursement whose request went out and whose answer
/// never came back. Something has to ask again, and the only party that can is this one.
///
/// Safe to run for ever because a retry is not a second claim: the request id is stable, so the
/// cosigner answers a repeat with `already_counted` — signed again, charged once. Nonces are fresh
/// every time because none were ever written down.
pub async fn keep_trying(wire: Arc<Wire>) {
    loop {
        tokio::time::sleep(RETRY_EVERY).await;
        for (request_id, outcome) in resume(&wire).await {
            match outcome {
                Asked::Confirmed { ark_txid, sats } => {
                    tracing::info!(%request_id, %ark_txid, sats, "reimbursed on a retry")
                }
                Asked::NeedsReconciliation => {
                    tracing::warn!(%request_id, "needs reconciling; not asking again")
                }
                // Refusals and failures are the ordinary state of a payment that is not payable
                // yet. Logged at debug so a quiet service stays quiet.
                other => tracing::debug!(%request_id, ?other, "still outstanding"),
            }
        }
    }
}

/// Ask once about everything outstanding.
///
/// A pending request is retried with **fresh** nonces, because the old ones were never written
/// down. The cosigner answers a repeat of a request it has already answered by signing again and
/// counting nothing — which is exactly what a service whose reply was lost needs, and is why no
/// single-use nonce has to survive anything.
pub async fn resume(wire: &Arc<Wire>) -> Vec<(String, Asked)> {
    let pending: Vec<String> = wire
        .service
        .tracked()
        .await
        .into_iter()
        .filter(|r| r.ready_to_ask())
        .map(|r| r.request_id)
        .collect();

    let mut outcomes = Vec::new();
    for request_id in pending {
        let outcome = ask(wire, &request_id).await;
        outcomes.push((request_id, outcome));
    }
    outcomes
}
