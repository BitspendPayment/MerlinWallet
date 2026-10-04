//! Bringing an on-chain output into Ark: the boarding round, driven by the caller one relayed ASP
//! event at a time on its own `Board` stream, through the round `crate::renew` describes.
//!
//! Unlike a refresh it signs twice: the intent proof before anything is registered, and the
//! commitment transaction at batch finalization. So it remembers which round the caller's next
//! signatures answer.

use ark::client::batch::{BoardingTreeSigner, SettleAction, SettleSession};
use ark::client::proto::get_event_stream_response::Event;
use ark::client::types::ArkInfo;

use crate::renew::{AspCall, RenewStep};
use crate::types::BoardingSettleSubmitted;

/// In-flight boarding settle, held across the commitment-FROST pause — the caller FROST-signs the
/// commitment sighashes between one relayed ASP event and the next, and this is what waits.
pub struct BoardingSettleSession {
    pub session: ark::client::batch::SettleSession,
    pub signer: ark::client::batch::BoardingTreeSigner,
    pub amount_sats: u64,
    /// Boarding exit delay, carried through to the finalized VTXO entry.
    pub exit_delay: u32,
    /// Which FROST round the caller's next signatures answer.
    pub phase: Phase,
    /// The ASP's id for this round's registration, once the caller reports it. Empty until then.
    pub intent_id: String,
}

/// Which FROST round a boarding's returning signatures belong to. A refresh has only the first.
#[derive(Clone, Copy, PartialEq, Eq)]
pub enum Phase {
    /// Signing the intent proof, before anything is registered.
    Intent,
    /// Signing the commitment transaction, at batch finalization.
    Commitment,
}

impl BoardingSettleSession {
    /// Build the session that settles `boarding_utxo` — `(txid, vout, amount_sats)`, as the wallet
    /// scanned it — into Ark, and the intent-proof sighashes to FROST-sign. The boarding address
    /// it spends from is derived here, from `owner_pk_hex` and the ASP's parameters, not taken
    /// from the caller.
    pub(crate) fn begin(
        owner_pk_hex: &str,
        info: &ArkInfo,
        (txid, vout, amount_sats): (String, u32, u64),
    ) -> Result<(Self, Vec<Vec<u8>>), String> {
        let network = ark::client::parse_network(&info.network)?;
        let exit_delay = info.boarding_exit_delay as u32;
        let boarding_address =
            ark::client::boarding_address(owner_pk_hex, &info.signer_pubkey, exit_delay, network)
                .map_err(|e| format!("boarding_address: {e}"))?;
        let signer = BoardingTreeSigner::generate();
        let (session, sighashes) = SettleSession::new_boarding(
            owner_pk_hex,
            &info.signer_pubkey,
            &info.forfeit_pubkey,
            &boarding_address,
            &txid,
            vout,
            amount_sats,
            exit_delay,
            &info.network,
            &signer.cosigner_pubkey_hex(),
        )
        .map_err(|e| format!("new_boarding: {e}"))?;
        let boarding = Self {
            session,
            signer,
            amount_sats,
            exit_delay,
            phase: Phase::Intent,
            intent_id: String::new(),
        };
        Ok((boarding, sighashes.iter().map(|s| s.to_vec()).collect()))
    }

    /// Take the caller's signatures for whichever round is open: after the intent round, the
    /// registration payload; after the commitment round, the signed commitment the ASP still needs.
    pub(crate) fn signed(&mut self, signed: &[Vec<u8>]) -> Result<RenewStep, String> {
        let sigs = crate::util::sigs_from_wire(signed)?;
        match self.phase {
            Phase::Intent => {
                self.session.insert_intent_signatures(sigs)?;
                let (proof, message, topics) = self.session.register_payload()?;
                Ok(RenewStep::Register { proof, message, topics })
            }
            Phase::Commitment => {
                let signed_commitment_b64 = self.session.insert_commitment_signatures(sigs)?;
                Ok(RenewStep::Submit(AspCall::ForfeitTxs {
                    signed_txs: Vec::new(),
                    signed_commitment_b64,
                }))
            }
        }
    }

    /// Consume one relayed ASP event of this boarding's round. The round ends at `BatchFinalized`,
    /// whatever that yields, and the caller drops the session there.
    pub(crate) fn on_event(&mut self, event: Event) -> Result<RenewStep, String> {
        let intent_id = self.intent_id.clone();
        match event {
            // Only join a batch that lists our intent, or the ASP aborts it for its real
            // participants and boarding never settles.
            Event::BatchStarted(e) => {
                if !ark::client::batch::batch_includes_intent(&e, &intent_id) {
                    return Ok(RenewStep::Idle);
                }
                self.session.on_batch_started(e)?;
                Ok(RenewStep::Submit(AspCall::ConfirmRegistration { intent_id }))
            }
            Event::TreeTx(e) => {
                self.session.handle_tree_tx(e)?;
                Ok(RenewStep::Idle)
            }
            Event::TreeSigningStarted(e) => match self.session.on_tree_signing_started(e)? {
                SettleAction::NeedTreeNonces {
                    tree_tx_chunks,
                    commitment_psbt_b64,
                } => {
                    let (pubkey, nonce_map) =
                        self.signer.gen_nonces(&tree_tx_chunks, &commitment_psbt_b64)?;
                    Ok(RenewStep::Submit(AspCall::TreeNonces {
                        batch_id: self.session.batch_id(),
                        pubkey,
                        nonces: nonce_map.into_iter().collect(),
                    }))
                }
                _ => Ok(RenewStep::Idle),
            },
            Event::TreeNonces(e) => match self.session.on_tree_nonces(e)? {
                Some(SettleAction::NeedTreeSign {
                    pending_nonces,
                    batch_expiry,
                    forfeit_pk_hex,
                }) => {
                    let (pubkey, sig_map) =
                        self.signer.sign(&pending_nonces, batch_expiry, &forfeit_pk_hex)?;
                    Ok(RenewStep::Submit(AspCall::TreeSignatures {
                        batch_id: self.session.batch_id(),
                        pubkey,
                        signatures: sig_map.into_iter().collect(),
                    }))
                }
                _ => Ok(RenewStep::Idle),
            },
            // The pause: the commitment transaction needs FROST signatures before the batch can
            // finalize.
            Event::BatchFinalization(e) => {
                let sighashes = self.session.handle_batch_finalization(e)?;
                self.phase = Phase::Commitment;
                Ok(RenewStep::Sighashes(
                    sighashes.iter().map(|s| s.to_vec()).collect(),
                ))
            }
            Event::BatchFinalized(_) => {
                let (commitment_txid, vtxo) = self.session.finalize_optimistic()?;
                let (vtxo_txid, vtxo_vout) = vtxo.unwrap_or_else(|| (commitment_txid.clone(), 0));
                Ok(RenewStep::Complete(BoardingSettleSubmitted {
                    commitment_txid,
                    vtxo_txid,
                    vtxo_vout,
                    amount_sats: self.amount_sats,
                    exit_delay: self.exit_delay,
                }))
            }
            Event::BatchFailed(e) => Err(format!("batch failed: {}", e.reason)),
            _ => Ok(RenewStep::Idle),
        }
    }
}
