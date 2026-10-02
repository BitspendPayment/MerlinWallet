//! The delegate: funds renewed on a schedule, by the cosigner, with nobody connected.
//!
//! **Renewing** happens while the owner is here. At the end of a send or a renewal — on the same
//! stream, under the same approval — the wallet tells the cosigner what it now holds, the cosigner
//! builds an intent to refresh all of it (valid from the earliest expiry less the safety margin) and
//! the forfeits it will need (`ALL|ANYONECANPAY`, so the round's connector can be added later), and
//! the wallet FROST-signs them. That signed delegate is sealed, and the settle watch is armed for
//! the moment it becomes valid. `RenewOpen.delegate_only` does the same on its own, for funds that
//! arrived by a receive.
//!
//! **Executing** happens in the watch's background task, when the deadline comes: the cosigner
//! registers the sealed intent with its ASP itself, follows the round on the event stream, and
//! answers it with the only key the round still needs, its own delegate cosigner key. No wallet
//! signature, no phone, no passkey. The refreshed funds are covered by nothing until the owner is
//! next here and renews the delegate for them — the next send or renewal does it on its way out.

use crate::asp::{AspApi, EventSource};
use crate::cosigner::{Cosigner, DelegateSession};
use crate::handlers::renew::{AspCall, RenewStep};
use crate::types::{VtxoEntry, VtxoInput};
use ark::client::types::ArkInfo;
use ark::exit::{self, ExitInput, ExitSpend};

/// What a renewed delegate covers, as reported back to the wallet.
pub struct Renewed {
    /// When its intent becomes valid, and the watch runs it. Unix seconds.
    pub valid_at: u64,
    pub margin: u64,
    /// `txid:vout` of each VTXO it refreshes.
    pub covered: Vec<String>,
    /// One signed unilateral exit per VTXO, when the renewal carried an exit script.
    pub exits: Vec<SignedExit>,
}

/// A unilateral exit the wallet keeps: a spend of one VTXO through its own exit leaf, paying an
/// address the wallet named. It needs this cosigner's signature, which is why it is made while the
/// cosigner is here, and nothing afterwards — not the ASP, not us.
pub struct SignedExit {
    pub outpoint: String,
    pub raw_tx: Vec<u8>,
    pub sequence: u32,
    pub amount_sats: u64,
}

/// The exits a renewal is signing, waiting for the wallet's half of the round.
pub struct PendingExits {
    spends: Vec<(String, ExitSpend)>,
}

impl PendingExits {
    pub fn is_empty(&self) -> bool {
        self.spends.is_empty()
    }

    pub fn len(&self) -> usize {
        self.spends.len()
    }

    /// The sighashes, in the order the signatures must come back in.
    pub fn sighashes(&self) -> Vec<Vec<u8>> {
        self.spends.iter().map(|(_, s)| s.sighash.to_vec()).collect()
    }
}

impl Cosigner {
    /// Build a delegate over `vtxos` — the wallet's whole current set — and return the sighashes the
    /// wallet must FROST-sign. Refused when no expiry is known: a delegate valid "now" would be a
    /// refresh the owner did not ask for, and one valid never would renew nothing.
    pub fn renew_delegate_open(
        &mut self,
        vtxos: Vec<VtxoInput>,
        info: &ArkInfo,
        exit_script_pubkey: &[u8],
    ) -> Result<(Vec<Vec<u8>>, PendingExits), String> {
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
        let delegate = self.generate_delegate_for(info, true)?;
        let exits = self.build_exits(info, exit_script_pubkey)?;
        Ok((delegate, exits))
    }

    /// One exit transaction per held VTXO, paying `exit_script_pubkey`.
    ///
    /// Built here rather than by the wallet because signing something this cosigner did not build
    /// would make it a signing oracle. The wallet builds the same transactions from the same
    /// inputs and refuses the round unless the sighashes match, so neither side has to trust the
    /// other's arithmetic.
    ///
    /// A VTXO too small to leave a non-dust output gets no exit rather than failing the renewal:
    /// the delegate still protects it, and the wallet shows it as uncovered.
    fn build_exits(
        &self,
        info: &ArkInfo,
        exit_script_pubkey: &[u8],
    ) -> Result<PendingExits, String> {
        if exit_script_pubkey.is_empty() {
            return Ok(PendingExits { spends: Vec::new() });
        }
        let owner = ark::keys::parse_xonly(&self.owner_pk_hex()?)?;
        let asp = ark::keys::parse_xonly(&info.signer_pubkey)?;
        let network = ark::client::parse_network(&info.network)?;
        let destination = bitcoin::ScriptBuf::from_bytes(exit_script_pubkey.to_vec());

        let mut spends = Vec::new();
        for v in &self.owned_vtxos {
            let input = ExitInput {
                txid: v
                    .txid
                    .parse()
                    .map_err(|e| format!("a held VTXO has an unparseable txid {}: {e}", v.txid))?,
                vout: v.vout,
                amount_sats: v.amount,
                exit_delay: v.exit_delay,
            };
            match exit::build_exit_tx(asp, owner, network, &input, &destination) {
                Ok(spend) => spends.push((format!("{}:{}", v.txid, v.vout), spend)),
                Err(e) => {
                    tracing::debug!(outpoint = %format!("{}:{}", v.txid, v.vout), "no exit: {e}")
                }
            }
        }
        Ok(PendingExits { spends })
    }

    /// Take the wallet's signatures, keep the delegate, and arm the watch for when it is valid.
    /// The caller seals the snapshot.
    pub fn renew_delegate_finish(
        &mut self,
        signatures: Vec<Vec<u8>>,
        exits: PendingExits,
    ) -> Result<Renewed, String> {
        // The round signed the delegate's messages and then the exits', in that order.
        if signatures.len() < exits.len() {
            return Err(format!(
                "the round returned {} signatures, fewer than the {} exits it was given",
                signatures.len(),
                exits.len()
            ));
        }
        let split = signatures.len() - exits.len();
        let (delegate_sigs, exit_sigs) = signatures.split_at(split);
        let exits = finalize_exits(exits, exit_sigs)?;

        self.apply_delegate_sigs(crate::types::ApplyDelegateSigs {
            signed_messages: delegate_sigs.to_vec(),
        })?;
        let valid_at = self
            .settle_deadline()
            .ok_or("the delegate lost its deadline between building and signing")?;
        self.arm_settle_watch(valid_at)?;
        Ok(Renewed {
            valid_at,
            margin: self.store.auto_settle_safety_margin_secs.max(0) as u64,
            covered: self
                .owned_vtxos
                .iter()
                .map(|v| format!("{}:{}", v.txid, v.vout))
                .collect(),
            exits,
        })
    }

    /// Run the sealed delegate's round against the ASP. Returns the commitment txid.
    ///
    /// Safe to call again after a failure: the registered intent's id is sealed as soon as the ASP
    /// assigns it, so a retry follows the same registration rather than making a second one, and a
    /// failed batch clears it so the next attempt registers afresh.
    pub async fn execute_delegate<A: AspApi>(&mut self, asp: &mut A) -> Result<String, String> {
        let delegate = self.delegate_session.as_ref().ok_or("no sealed delegate")?.session();
        let (proof, message, topics) = delegate.register_payload()?;
        let registered = delegate.intent_id.is_some();
        let info = asp.get_info().await?;

        if !registered {
            let id = asp.register_intent(&proof, &message).await?;
            if let Some(delegate) = self.delegate_session.as_mut() {
                delegate.session_mut().intent_id = Some(id);
            }
            self.seal();
        }

        let mut events = asp.events(&topics).await?;
        let held: u64 = self.owned_vtxos.iter().map(|v| v.amount).sum();
        let exit_delay = info.unilateral_exit_delay as u32;
        self.delegate_session = self.delegate_session.take().map(|d| d.in_flight(exit_delay));

        let outcome: Result<crate::types::BoardingSettleSubmitted, String> = async {
            loop {
                let event = events
                    .next()
                    .await?
                    .ok_or("the ASP's event stream ended before the batch finalized")?;
                match self.renew_on_event(event)? {
                    RenewStep::Idle => {}
                    RenewStep::Submit(call) => submit(asp, call).await?,
                    RenewStep::Complete(sub) => return Ok(sub),
                    RenewStep::Sighashes(_) | RenewStep::Register { .. } => {
                        return Err("a delegate round asked for a signature it should not need".into())
                    }
                }
            }
        }
        .await;

        // A round that stopped short leaves the delegate waiting again; a finished one took it.
        self.delegate_session = self.delegate_session.take().map(DelegateSession::awaiting);
        match outcome {
            Ok(sub) => {
                // Everything the delegate covered was spent into the one VTXO it produced, and the
                // delegate went with its round.
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
                    if let Some(delegate) = self.delegate_session.as_mut() {
                        delegate.session_mut().intent_id = None;
                    }
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

/// Put each signature into its exit's witness. The transactions are complete after this — no ASP
/// leg, no second round, nothing left to add.
fn finalize_exits(exits: PendingExits, signatures: &[Vec<u8>]) -> Result<Vec<SignedExit>, String> {
    exits
        .spends
        .into_iter()
        .zip(signatures)
        .map(|((outpoint, spend), sig)| {
            let raw_tx = exit::finalize_exit_tx(&spend, sig)
                .map_err(|e| format!("finalizing the exit of {outpoint}: {e}"))?;
            Ok(SignedExit {
                outpoint,
                raw_tx,
                sequence: spend.sequence,
                amount_sats: spend.tx.output[0].value.to_sat(),
            })
        })
        .collect()
}

