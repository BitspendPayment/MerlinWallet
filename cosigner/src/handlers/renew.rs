//! Renewing a boarding output into Ark, or the VTXOs held, with the caller driving the ASP round.
//!
//! The cosigner used to hold the ASP connection for this: it registered the intent, opened the
//! event stream, and reacted to each event itself — which made it the Ark client as well as the
//! signer, and gave a thing that is meant to be called a socket of its own.
//!
//! What it actually contributes is signatures: the intent proof, the MuSig2 tree nonces and
//! signatures, the forfeit transactions. Every step that produces those is already synchronous and
//! transport-free (`on_batch_started`, `on_tree_signing_started`, `on_tree_nonces`,
//! `on_batch_finalization`, `on_batch_finalized`). So the loop inverts: the caller relays each
//! event and the cosigner answers with what to send the ASP next.
//!
//! Both renewal shapes run through here. A boarding output settles when `boarding_utxo` is set, a
//! self-refresh of the held VTXOs when it is not; they differ only in which session drives and
//! whether a second FROST round is needed at finalization.

use ark::client::batch::SettleAction;
use ark::client::proto::get_event_stream_response::Event;
use ark::client::types::ArkInfo;

use crate::cosigner::{Cosigner, DelegateSession};
use crate::types::BoardingSettleSubmitted;

/// One ASP call the caller must make on the cosigner's behalf.
pub enum AspCall {
    ConfirmRegistration {
        intent_id: String,
    },
    TreeNonces {
        batch_id: String,
        pubkey: String,
        nonces: Vec<(String, String)>,
    },
    TreeSignatures {
        batch_id: String,
        pubkey: String,
        signatures: Vec<(String, String)>,
    },
    ForfeitTxs {
        signed_txs: Vec<String>,
        signed_commitment_b64: String,
    },
}

/// What the caller must do next.
pub enum RenewStep {
    /// FROST-sign these, then send them back.
    Sighashes(Vec<Vec<u8>>),
    /// Register this intent with the ASP, then open its event stream on `topics`.
    Register {
        proof: String,
        message: String,
        topics: Vec<String>,
    },
    /// Make this call to the ASP, then relay the next event.
    Submit(AspCall),
    /// The event was consumed and produced nothing. Relay the next one.
    Idle,
    /// Settled.
    Complete(BoardingSettleSubmitted),
}

/// Which FROST round a boarding's returning signatures belong to. A refresh has only the first.
#[derive(Clone, Copy, PartialEq, Eq)]
pub enum Phase {
    /// Signing the intent proof, before anything is registered.
    Intent,
    /// Signing the commitment transaction, at batch finalization.
    Commitment,
}

impl Cosigner {
    /// Open a renewal and hand back the sighashes the caller must FROST-sign.
    ///
    /// `info` comes from the caller because the caller is the one talking to the ASP. It cannot
    /// redirect funds with it: every output is still derived from the cosigner's own key, so a
    /// wrong `signer_pubkey` yields a transaction the ASP rejects rather than one that pays
    /// somebody else.
    pub fn renew_open(
        &mut self,
        boarding_utxo: Option<(String, u32, u64)>,
        vtxos: Vec<crate::types::VtxoInput>,
        info: ArkInfo,
    ) -> Result<Vec<Vec<u8>>, String> {
        let boarding = boarding_utxo.is_some();
        // A boarding settle spends the named on-chain output; a self-refresh spends the set the
        // caller supplies, validated against what this wallet could own.
        if !boarding {
            self.accept_vtxos(vtxos, &info)?;
        }
        if boarding {
            return self.boarding_settle_start(boarding_utxo, &info);
        }
        // Now, not deferred: the owner is here asking for a refresh.
        let sighashes = self.generate_delegate_for(&info, false)?;
        let exit_delay = info.unilateral_exit_delay as u32;
        self.delegate_session = self.delegate_session.take().map(|d| d.in_flight(exit_delay));
        Ok(sighashes)
    }

    /// Take the caller's signatures for whichever round is open.
    ///
    /// After the intent round this yields the registration payload; after the commitment round
    /// (boarding only) the signed commitment the ASP still needs.
    pub fn renew_signed(&mut self, signed: Vec<Vec<u8>>) -> Result<RenewStep, String> {
        if let Some(inflight) = self.boarding_session.as_mut() {
            let sigs = crate::cosigner::sigs_from_wire(&signed)?;
            return match inflight.phase {
                Phase::Intent => {
                    inflight.session.insert_intent_signatures(sigs)?;
                    let (proof, message, topics) = inflight.session.register_payload()?;
                    Ok(RenewStep::Register {
                        proof,
                        message,
                        topics,
                    })
                }
                Phase::Commitment => {
                    let signed_commitment_b64 =
                        inflight.session.insert_commitment_signatures(sigs)?;
                    Ok(RenewStep::Submit(AspCall::ForfeitTxs {
                        signed_txs: Vec::new(),
                        signed_commitment_b64,
                    }))
                }
            };
        }
        if !matches!(self.delegate_session, Some(DelegateSession::InFlight { .. })) {
            return Err("no renewal in flight".into());
        }
        self.apply_delegate_sigs(crate::types::ApplyDelegateSigs {
            signed_messages: signed,
        })?;
        let (proof, message, topics) = self
            .delegate_session
            .as_ref()
            .ok_or_else(|| "no delegate session".to_string())?
            .session()
            .register_payload()?;
        Ok(RenewStep::Register {
            proof,
            message,
            topics,
        })
    }

    /// Record the id the ASP gave the registration. Needed to tell our batch from the ones a public
    /// ASP broadcasts for everybody else.
    pub fn renew_registered(&mut self, intent_id: String) -> Result<(), String> {
        match (self.boarding_session.as_mut(), self.delegate_session.as_mut()) {
            (Some(inflight), _) => inflight.intent_id = intent_id,
            (None, Some(DelegateSession::InFlight { session, .. })) => {
                session.intent_id = Some(intent_id)
            }
            _ => return Err("no renewal in flight".into()),
        }
        Ok(())
    }

    /// Consume one relayed ASP event.
    pub fn renew_on_event(&mut self, event: Event) -> Result<RenewStep, String> {
        // A foreign batch's Finalized/Failed/Tree* events must not drive this session: Finalized
        // would be recorded as our settlement and Failed would abort a renewal still waiting for
        // its own batch.
        let joined = match (&self.boarding_session, &self.delegate_session) {
            (Some(inflight), _) => inflight.session.batch_id(),
            (None, Some(DelegateSession::InFlight { session, .. })) => {
                session.joined_batch_id().unwrap_or_default().to_string()
            }
            _ => return Err("no renewal in flight".into()),
        };
        if let Some(other) =
            ark::client::batch::foreign_batch_id(&event, |id| !joined.is_empty() && joined == id)
        {
            tracing::debug!("ignoring event for foreign batch {other}");
            return Ok(RenewStep::Idle);
        }

        if self.boarding_session.is_some() {
            self.boarding_on_event(event)
        } else {
            self.delegate_on_event(event)
        }
    }

    fn boarding_on_event(&mut self, event: Event) -> Result<RenewStep, String> {
        let inflight = self
            .boarding_session
            .as_mut()
            .ok_or_else(|| "no boarding settle in flight".to_string())?;
        let intent_id = inflight.intent_id.clone();
        match event {
            // Only join a batch that lists our intent, or the ASP aborts it for its real
            // participants and boarding never settles.
            Event::BatchStarted(e) => {
                if !ark::client::batch::batch_includes_intent(&e, &intent_id) {
                    return Ok(RenewStep::Idle);
                }
                inflight.session.on_batch_started(e)?;
                Ok(RenewStep::Submit(AspCall::ConfirmRegistration { intent_id }))
            }
            Event::TreeTx(e) => {
                inflight.session.handle_tree_tx(e)?;
                Ok(RenewStep::Idle)
            }
            Event::TreeSigningStarted(e) => match inflight.session.on_tree_signing_started(e)? {
                SettleAction::NeedTreeNonces {
                    tree_tx_chunks,
                    commitment_psbt_b64,
                } => {
                    let (pubkey, nonce_map) = inflight
                        .signer
                        .gen_nonces(&tree_tx_chunks, &commitment_psbt_b64)?;
                    Ok(RenewStep::Submit(AspCall::TreeNonces {
                        batch_id: inflight.session.batch_id(),
                        pubkey,
                        nonces: nonce_map.into_iter().collect(),
                    }))
                }
                _ => Ok(RenewStep::Idle),
            },
            Event::TreeNonces(e) => match inflight.session.on_tree_nonces(e)? {
                Some(SettleAction::NeedTreeSign {
                    pending_nonces,
                    batch_expiry,
                    forfeit_pk_hex,
                }) => {
                    let (pubkey, sig_map) =
                        inflight
                            .signer
                            .sign(&pending_nonces, batch_expiry, &forfeit_pk_hex)?;
                    Ok(RenewStep::Submit(AspCall::TreeSignatures {
                        batch_id: inflight.session.batch_id(),
                        pubkey,
                        signatures: sig_map.into_iter().collect(),
                    }))
                }
                _ => Ok(RenewStep::Idle),
            },
            // The pause: the commitment transaction needs FROST signatures before the batch can
            // finalize.
            Event::BatchFinalization(e) => {
                let sighashes = inflight.session.handle_batch_finalization(e)?;
                inflight.phase = Phase::Commitment;
                Ok(RenewStep::Sighashes(
                    sighashes.iter().map(|s| s.to_vec()).collect(),
                ))
            }
            Event::BatchFinalized(_) => {
                let inflight = self.boarding_session.take().expect("checked above");
                let (commitment_txid, vtxo) = inflight.session.finalize_optimistic()?;
                let (vtxo_txid, vtxo_vout) = vtxo.unwrap_or_else(|| (commitment_txid.clone(), 0));
                Ok(RenewStep::Complete(BoardingSettleSubmitted {
                    commitment_txid,
                    vtxo_txid,
                    vtxo_vout,
                    amount_sats: inflight.amount_sats,
                    exit_delay: inflight.exit_delay,
                }))
            }
            Event::BatchFailed(e) => Err(format!("batch failed: {}", e.reason)),
            _ => Ok(RenewStep::Idle),
        }
    }

    fn delegate_on_event(&mut self, event: Event) -> Result<RenewStep, String> {
        let Some(DelegateSession::InFlight { session, exit_delay }) = self.delegate_session.as_mut()
        else {
            return Err("no renewal in flight".into());
        };
        let exit_delay = *exit_delay;
        let intent_id = session.intent_id.clone().unwrap_or_default();
        match event {
            Event::BatchStarted(e) => {
                if !ark::client::batch::batch_includes_intent(&e, &intent_id) {
                    return Ok(RenewStep::Idle);
                }
                session.on_batch_started(e)?;
                Ok(RenewStep::Submit(AspCall::ConfirmRegistration { intent_id }))
            }
            Event::TreeTx(e) => {
                session.on_tree_tx(e)?;
                Ok(RenewStep::Idle)
            }
            Event::TreeSigningStarted(e) => {
                let (batch_id, pubkey, tree_nonces) = session.on_tree_signing_started(e)?;
                Ok(RenewStep::Submit(AspCall::TreeNonces {
                    batch_id,
                    pubkey,
                    nonces: tree_nonces.into_iter().collect(),
                }))
            }
            Event::TreeNonces(e) => match session.on_tree_nonces(e)? {
                Some((batch_id, pubkey, tree_signatures)) => {
                    Ok(RenewStep::Submit(AspCall::TreeSignatures {
                        batch_id,
                        pubkey,
                        signatures: tree_signatures.into_iter().collect(),
                    }))
                }
                None => Ok(RenewStep::Idle),
            },
            Event::BatchFinalization(e) => match session.on_batch_finalization(e)? {
                Some(signed_forfeit_txs) => Ok(RenewStep::Submit(AspCall::ForfeitTxs {
                    signed_txs: signed_forfeit_txs,
                    signed_commitment_b64: String::new(),
                })),
                None => Ok(RenewStep::Idle),
            },
            Event::BatchFinalized(e) => {
                let (commitment_txid, vtxo_outpoint) = session.on_batch_finalized(e);
                self.delegate_session = None;
                let (vtxo_txid, vtxo_vout) =
                    vtxo_outpoint.unwrap_or_else(|| (commitment_txid.clone(), 0));
                Ok(RenewStep::Complete(BoardingSettleSubmitted {
                    commitment_txid,
                    vtxo_txid,
                    vtxo_vout,
                    amount_sats: 0,
                    exit_delay,
                }))
            }
            Event::BatchFailed(e) => Err(format!("batch failed: {}", e.reason)),
            _ => Ok(RenewStep::Idle),
        }
    }
}
