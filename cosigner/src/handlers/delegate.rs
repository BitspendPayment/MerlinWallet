//! The delegate: funds renewed on a schedule, by the cosigner, with nobody connected.
//!
//! **Sealing** happens while the owner is here. At the end of a send or a settle — on the same
//! stream, under the same approval — the wallet tells the cosigner what it now holds, the cosigner
//! builds an intent to refresh all of it (valid from the earliest expiry less the safety margin) and
//! the forfeits it will need (`ALL|ANYONECANPAY`, so the round's connector can be added later), and
//! the wallet FROST-signs them. That signed delegate is sealed, and the settle watch is armed for
//! the moment it becomes valid. `SettleOpen.seal_only` does the same on its own, for funds that
//! arrived by a receive.
//!
//! **Executing** happens in the watch's background task, when the deadline comes: the cosigner
//! registers the sealed intent with its ASP itself, follows the round on the event stream, and
//! answers it with the only key the round still needs, its own delegate cosigner key. No wallet
//! signature, no phone, no passkey. The refreshed funds are covered by nothing until the owner is
//! next here and seals a delegate for them — the next send or settle does it on its way out.

use crate::asp::{AspApi, EventSource};
use crate::cosigner::Cosigner;
use crate::handlers::settle::{AspCall, InFlight, Phase, SettleStep};
use crate::types::{VtxoEntry, VtxoInput};
use ark::client::types::ArkInfo;

/// What a sealed delegate covers, as reported back to the wallet.
pub struct Sealed {
    /// When its intent becomes valid, and the watch runs it. Unix seconds.
    pub valid_at: u64,
    pub margin: u64,
    /// `txid:vout` of each VTXO it refreshes.
    pub covered: Vec<String>,
}

impl Cosigner {
    /// Build a delegate over `vtxos` — the wallet's whole current set — and return the sighashes the
    /// wallet must FROST-sign. Refused when no expiry is known: a delegate valid "now" would be a
    /// refresh the owner did not ask for, and one valid never would renew nothing.
    pub fn seal_delegate_open(
        &mut self,
        vtxos: Vec<VtxoInput>,
        info: &ArkInfo,
    ) -> Result<Vec<Vec<u8>>, String> {
        self.accept_vtxos(vtxos, info)?;
        if self.owned_vtxos.is_empty() {
            return Err("nothing is held, so there is nothing to delegate".into());
        }
        if self.settle_deadline().is_none() {
            return Err(
                "no held VTXO has a known expiry yet, so there is nothing to schedule a renewal for"
                    .into(),
            );
        }
        self.delegate_intent_id = None;
        self.generate_delegate_for(info, true)
    }

    /// Take the wallet's signatures, seal the delegate, and arm the watch for when it becomes valid.
    /// The caller seals the snapshot.
    pub fn seal_delegate_finish(&mut self, signatures: Vec<Vec<u8>>) -> Result<Sealed, String> {
        self.apply_delegate_sigs(crate::types::ApplyDelegateSigs {
            signed_messages: signatures,
        })?;
        let valid_at = self
            .settle_deadline()
            .ok_or("the delegate lost its deadline between building and signing")?;
        self.arm_settle_watch(valid_at)?;
        Ok(Sealed {
            valid_at,
            margin: self.store.auto_settle_safety_margin_secs.max(0) as u64,
            covered: self
                .owned_vtxos
                .iter()
                .map(|v| format!("{}:{}", v.txid, v.vout))
                .collect(),
        })
    }

    /// Run the sealed delegate's round against the ASP. Returns the commitment txid.
    ///
    /// Safe to call again after a failure: the registered intent's id is sealed as soon as the ASP
    /// assigns it, so a retry follows the same registration rather than making a second one, and a
    /// failed batch clears it so the next attempt registers afresh.
    pub async fn execute_delegate<A: AspApi>(&mut self, asp: &mut A) -> Result<String, String> {
        let (proof, message, topics) = self
            .delegate_session
            .as_ref()
            .ok_or("no sealed delegate")?
            .register_payload()?;
        let info = asp.get_info().await?;

        let intent_id = match self.delegate_intent_id.clone() {
            Some(id) => id,
            None => {
                let id = asp.register_intent(&proof, &message).await?;
                self.delegate_intent_id = Some(id.clone());
                self.seal();
                id
            }
        };

        let mut events = asp.events(&topics).await?;
        let held: u64 = self.owned_vtxos.iter().map(|v| v.amount).sum();
        self.settle_inflight = Some(InFlight {
            phase: Phase::Intent,
            intent_id: intent_id.clone(),
            boarding: false,
            info,
        });

        let outcome: Result<crate::types::BoardingSettleSubmitted, String> = async {
            loop {
                let event = events
                    .next()
                    .await?
                    .ok_or("the ASP's event stream ended before the batch finalized")?;
                match self.settle_on_event(event)? {
                    SettleStep::Idle => {}
                    SettleStep::Submit(call) => submit(asp, call).await?,
                    SettleStep::Complete(sub) => return Ok(sub),
                    SettleStep::Sighashes(_) | SettleStep::Register { .. } => {
                        return Err("a delegate round asked for a signature it should not need".into())
                    }
                }
            }
        }
        .await;

        self.settle_inflight = None;
        match outcome {
            Ok(sub) => {
                // Everything the delegate covered was spent into the one VTXO it produced.
                self.delegate_intent_id = None;
                self.owned_vtxos = vec![VtxoEntry {
                    txid: sub.vtxo_txid,
                    vout: sub.vtxo_vout,
                    amount: held,
                    exit_delay: sub.exit_delay,
                    created_at: crate::store::now_secs(),
                    expires_at: 0,
                }];
                self.seal();
                Ok(sub.commitment_txid)
            }
            Err(e) => {
                if e.contains("batch failed") {
                    // The ASP dropped the registration with the batch; register again next time.
                    self.delegate_intent_id = None;
                    self.seal();
                }
                Err(e)
            }
        }
    }
}

async fn submit<A: AspApi>(asp: &mut A, call: AspCall) -> Result<(), String> {
    match call {
        AspCall::ConfirmRegistration { intent_id } => asp.confirm_registration(&intent_id).await,
        AspCall::TreeNonces { batch_id, pubkey, nonces } => {
            asp.submit_tree_nonces(&batch_id, &pubkey, &nonces).await
        }
        AspCall::TreeSignatures { batch_id, pubkey, signatures } => {
            asp.submit_tree_signatures(&batch_id, &pubkey, &signatures).await
        }
        AspCall::ForfeitTxs { signed_txs, signed_commitment_b64 } => {
            asp.submit_forfeits(&signed_txs, &signed_commitment_b64).await
        }
    }
}
