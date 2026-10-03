//! Renewing what the wallet holds: now, with the owner here, or later through a delegate — a
//! renewal signed in advance. Boarding runs the same round on a stream of its own; see
//! `crate::boarding`.
//!
//! **Signing a delegate.** At the end of a send or a renewal — on the same stream, under the same
//! approval — the wallet tells the cosigner what it now holds, the cosigner builds an intent to
//! refresh all of it (valid from the earliest expiry less the safety margin) and the forfeits it
//! will need (`ALL|ANYONECANPAY`, so the round's connector can be added later), and the wallet
//! FROST-signs them. That signed delegate is sealed, and the settle watch is armed for the moment
//! it becomes valid — see `Cosigner::run_task_with` for what runs it. `RenewOpen.delegate_only`
//! does the same on its own, for funds that arrived by a receive.
//!
//! **Running a round.** What the cosigner contributes to an ASP round is signatures: the intent
//! proof, the MuSig2 tree nonces and signatures, the forfeit transactions. Every step that produces
//! those is synchronous and transport-free, so the loop inverts: the caller relays each event and
//! the cosigner answers with what to send the ASP next. The watch drives a due delegate the same
//! way, with its own ASP connection standing in for the caller.

use std::sync::{Arc, Mutex};

use ark::client::batch::{DelegateOutput, DelegateSettleSession, DelegateVtxoInput};
use ark::client::proto::get_event_stream_response::Event;
use ark::client::types::ArkInfo;
use ark::exit::{self, ExitInput, ExitSpend};

use crate::boarding::BoardingSettleSession;
use crate::cosigner::{
    Cosigner, Task, CATEGORY_SETTLE_DUE, WATCH_INTERVAL_MS, WATCH_TASK_ID,
};
use crate::grpc::{Duplex, HasBody, Status};
use crate::host::valid_label;
use crate::session::{enrol_device, lock, proto};
use crate::types::{BoardingSettleSubmitted, VtxoInput};

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

impl Cosigner {
    /// Open a renewal and hand back the sighashes the caller must FROST-sign.
    ///
    /// `info` comes from the caller because the caller is the one talking to the ASP. It cannot
    /// redirect funds with it: every output is still derived from the cosigner's own key, so a
    /// wrong `signer_pubkey` yields a transaction the ASP rejects rather than one that pays
    /// somebody else.
    pub fn renew_begin(
        &mut self,
        vtxos: Vec<VtxoInput>,
        info: ArkInfo,
    ) -> Result<Vec<Vec<u8>>, String> {
        // The set the caller supplies, validated against what this wallet could own.
        self.accept_vtxos(vtxos, &info)?;
        // Now, not deferred: the owner is here asking for a refresh.
        let sighashes = self.generate_delegate(&info, false)?;
        let exit_delay = info.unilateral_exit_delay as u32;
        self.renew_session = self.renew_session.take().map(|d| d.in_flight(exit_delay));
        Ok(sighashes)
    }

    /// Open a boarding round over `utxo` — `(txid, vout, amount_sats)` — and hand back the
    /// intent-proof sighashes the caller must FROST-sign. `info` is the caller's, as for
    /// [`Self::renew_begin`].
    pub fn board_begin(
        &mut self,
        utxo: (String, u32, u64),
        info: &ArkInfo,
    ) -> Result<Vec<Vec<u8>>, String> {
        let (boarding, sighashes) =
            BoardingSettleSession::begin(&self.owner_pk_hex()?, info, utxo)?;
        self.boarding_session = Some(boarding);
        Ok(sighashes)
    }

    /// Take the caller's signatures for whichever round is open.
    ///
    /// After the intent round this yields the registration payload; after the commitment round
    /// (boarding only) the signed commitment the ASP still needs.
    pub fn renew_signed(&mut self, signed: Vec<Vec<u8>>) -> Result<RenewStep, String> {
        if let Some(boarding) = self.boarding_session.as_mut() {
            return boarding.signed(&signed);
        }
        if !matches!(self.renew_session, Some(RenewSession::InFlight { .. })) {
            return Err("no renewal in flight".into());
        }
        let session = self.renew_session.as_mut().ok_or("no delegate session")?;
        session.sign(&signed)?;
        let (proof, message, topics) = session.session().register_payload()?;
        Ok(RenewStep::Register {
            proof,
            message,
            topics,
        })
    }

    /// Record the id the ASP gave the registration. Needed to tell our batch from the ones a public
    /// ASP broadcasts for everybody else.
    pub fn renew_registered(&mut self, intent_id: String) -> Result<(), String> {
        match (self.boarding_session.as_mut(), self.renew_session.as_mut()) {
            (Some(inflight), _) => inflight.intent_id = intent_id,
            (None, Some(RenewSession::InFlight { session, .. })) => {
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
        let joined = match (&self.boarding_session, &self.renew_session) {
            (Some(inflight), _) => inflight.session.batch_id(),
            (None, Some(RenewSession::InFlight { session, .. })) => {
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

        if let Some(boarding) = self.boarding_session.as_mut() {
            let finalized = matches!(event, Event::BatchFinalized(_));
            let step = boarding.on_event(event);
            if finalized {
                self.boarding_session = None;
            }
            return step;
        }
        let step = self.renew_session.as_mut().ok_or("no renewal in flight")?.on_event(event)?;
        // A finished round took the delegate with it.
        if matches!(step, RenewStep::Complete(_)) {
            self.renew_session = None;
        }
        Ok(step)
    }
}

/// The wallet's delegate, and whether a round is running for it.
pub(crate) enum RenewSession {
    /// Waiting: for the wallet's signatures, or, signed and sealed, for its deadline.
    Awaiting(DelegateSettleSession),
    /// Its round is running: a refresh the owner asked for, or the watch running it.
    InFlight {
        session: DelegateSettleSession,
        /// The ASP's exit delay, which the VTXO the round produces is held under.
        exit_delay: u32,
    },
}

impl RenewSession {
    pub(crate) fn session(&self) -> &DelegateSettleSession {
        match self {
            Self::Awaiting(session) | Self::InFlight { session, .. } => session,
        }
    }

    pub(crate) fn session_mut(&mut self) -> &mut DelegateSettleSession {
        match self {
            Self::Awaiting(session) | Self::InFlight { session, .. } => session,
        }
    }

    /// Its round starts, under the ASP's current `exit_delay`.
    pub(crate) fn in_flight(self, exit_delay: u32) -> Self {
        Self::InFlight { session: self.into_session(), exit_delay }
    }

    /// Its round stopped short of finishing, so it waits again.
    pub(crate) fn awaiting(self) -> Self {
        Self::Awaiting(self.into_session())
    }

    fn into_session(self) -> DelegateSettleSession {
        match self {
            Self::Awaiting(session) | Self::InFlight { session, .. } => session,
        }
    }

    /// Build a delegate over `vtxos` — all of them, refreshed into one VTXO paying the owner's own
    /// Ark address — and the sighashes the wallet must FROST-sign for its intent and forfeits.
    /// `intent_valid_at` of `None` makes it valid now.
    pub(crate) fn generate(
        owner_pk_hex: &str,
        vtxos: &[VtxoInput],
        info: &ArkInfo,
        intent_valid_at: Option<u64>,
    ) -> Result<(Self, Vec<Vec<u8>>), String> {
        if vtxos.is_empty() {
            return Err("no VTXOs to settle".into());
        }
        let vtxo_inputs: Vec<DelegateVtxoInput> = vtxos
            .iter()
            .map(|v| DelegateVtxoInput {
                txid: v.txid.clone(),
                vout: v.vout,
                amount_sats: v.amount_sats,
                is_swept: false,
                exit_delay: v.exit_delay,
            })
            .collect();
        let network = ark::client::parse_network(&info.network)?;
        let owner_ark_address = ark::client::ark_address(
            owner_pk_hex,
            &info.signer_pubkey,
            info.unilateral_exit_delay as u32,
            network,
        )
        .map_err(|e| format!("ark_address: {e}"))?;
        let outputs = vec![DelegateOutput {
            address: owner_ark_address,
            amount_sats: vtxos.iter().map(|v| v.amount_sats).sum(),
        }];
        let (session, sighashes) = DelegateSettleSession::generate_delegate(
            owner_pk_hex,
            &info.signer_pubkey,
            &info.forfeit_pubkey,
            &vtxo_inputs,
            &outputs,
            &info.forfeit_address,
            info.dust as u64,
            &info.network,
            intent_valid_at,
        )
        .map_err(|e| format!("generate_delegate: {e}"))?;
        Ok((Self::Awaiting(session), sighashes.iter().map(|s| s.to_vec()).collect()))
    }

    /// Put the wallet's FROST signatures into the delegate's messages. Arming the watch is
    /// renewing's business (`DelegateRenew::finalise`), not signing's: a delegate signed for a
    /// refresh the owner asked for now is spent in the same round.
    pub(crate) fn sign(&mut self, signed: &[Vec<u8>]) -> Result<(), String> {
        self.session_mut().sign_with_frost(crate::util::sigs_from_wire(signed)?)?;
        Ok(())
    }

    /// Consume one relayed ASP event of this delegate's running round. `Complete` means the round
    /// took the delegate; the caller drops it.
    pub(crate) fn on_event(&mut self, event: Event) -> Result<RenewStep, String> {
        let Self::InFlight { session, exit_delay } = self else {
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

/// A stream that carries the delegate exchange: how its own messages hold each step.
pub(crate) trait DelegateStream: Sized {
    /// What the wallet sends on this stream.
    type In: HasBody;

    /// What the delegate's round signs, with the wallet's dealt share when this is the stream's
    /// first round — empty otherwise.
    fn sighashes(session_id: &str, seq: u64, to_sign: ToSign, wallet_dealt_share: Vec<u8>) -> Self;

    /// The wallet's half of the round, if [body] is that.
    fn signed(body: <Self::In as HasBody>::Body) -> Option<Vec<proto::WalletRound>>;

    fn renewed(session_id: &str, seq: u64, renewed: proto::DelegateRenewed) -> Self;
}

/// What the delegate's round signs: the delegate's messages, then the exits', and this cosigner's
/// commitments for all of them.
pub struct ToSign {
    pub delegate: Vec<Vec<u8>>,
    pub exits: Vec<Vec<u8>>,
    pub commitments: Vec<crate::types::Commitment>,
}

/// A delegate being renewed: the round that signs it, open, and the exits it signs alongside —
/// each exit's outpoint and spend, in the order their sighashes were offered.
pub struct DelegateRenew {
    signing: crate::sign::SigningSession,
    exits: Vec<(String, ExitSpend)>,
}

impl DelegateRenew {
    /// Renew the delegate [request] asks for, on [duplex]: the round's sighashes at [seq], the
    /// wallet's signatures in, and the renewed delegate at `seq + 1`.
    pub(crate) async fn run<S: DelegateStream>(
        cosigner: &Arc<Mutex<Cosigner>>,
        duplex: &Duplex<S::In, S>,
        mut request: proto::RenewDelegate,
        session_id: &str,
        seq: u64,
        wallet_dealt_share: Vec<u8>,
    ) -> Result<(), Status> {
        let device_token = std::mem::take(&mut request.device_token);
        let (renew, to_sign) = Self::build(cosigner, request)?;
        duplex.send(S::sighashes(session_id, seq, to_sign, wallet_dealt_share));
        let rounds = S::signed(duplex.next_body("the delegate's signatures").await?)
            .ok_or_else(|| Status::invalid_argument("expected the delegate's signatures"))?;
        let renewed = renew.finalise(cosigner, rounds, &device_token)?;
        duplex.send(S::renewed(session_id, seq + 1, renewed));
        Ok(())
    }

    /// Build a delegate over the set [request] reports — the wallet's whole current set — and open
    /// the round that signs it. Refused when no expiry is known: a delegate valid "now" would be a
    /// refresh the owner did not ask for, and one valid never would renew nothing.
    pub fn build(
        cosigner: &Arc<Mutex<Cosigner>>,
        request: proto::RenewDelegate,
    ) -> Result<(Self, ToSign), Status> {
        let info = request
            .ark_info
            .map(ArkInfo::from)
            .ok_or_else(|| Status::invalid_argument("RenewDelegate carried no ark_info"))?;
        let mut c = lock(cosigner);
        c.accept_vtxos(request.vtxos.into_iter().map(Into::into).collect(), &info)
            .map_err(Status::failed_precondition)?;
        if c.vtxos.is_empty() {
            return Err(Status::failed_precondition(
                "nothing is held, so there is nothing to delegate",
            ));
        }
        if c.settle_deadline().is_none() {
            return Err(Status::failed_precondition(
                "no held VTXO has a known expiry yet, so there is nothing to schedule a renewal \
                 for",
            ));
        }
        let delegate = c.generate_delegate(&info, true).map_err(Status::failed_precondition)?;

        // One exit transaction per held VTXO, paying `exit_script_pubkey`.
        //
        // Built here rather than by the wallet because signing something this cosigner did not
        // build would make it a signing oracle. The wallet builds the same transactions from the
        // same inputs and refuses the round unless the sighashes match, so neither side has to
        // trust the other's arithmetic.
        //
        // A VTXO too small to leave a non-dust output gets no exit rather than failing the renewal:
        // the delegate still protects it, and the wallet shows it as uncovered.
        let mut exits = Vec::new();
        if !request.exit_script_pubkey.is_empty() {
            let owner_pk_hex = c.owner_pk_hex().map_err(Status::failed_precondition)?;
            let owner = ark::keys::parse_xonly(&owner_pk_hex).map_err(Status::failed_precondition)?;
            let asp =
                ark::keys::parse_xonly(&info.signer_pubkey).map_err(Status::failed_precondition)?;
            let network =
                ark::client::parse_network(&info.network).map_err(Status::failed_precondition)?;
            let destination = bitcoin::ScriptBuf::from_bytes(request.exit_script_pubkey);
            for v in &c.vtxos {
                let input = ExitInput {
                    txid: v.txid.parse().map_err(|e| {
                        Status::failed_precondition(format!(
                            "a held VTXO has an unparseable txid {}: {e}",
                            v.txid
                        ))
                    })?,
                    vout: v.vout,
                    amount_sats: v.amount,
                    exit_delay: v.exit_delay,
                };
                let outpoint = format!("{}:{}", v.txid, v.vout);
                match exit::build_exit_tx(asp, owner, network, &input, &destination) {
                    Ok(spend) => exits.push((outpoint, spend)),
                    Err(e) => tracing::debug!(%outpoint, "no exit: {e}"),
                }
            }
        }

        // One round over both halves, in that order: the wallet answers them as one list, and the
        // signatures come back the same way.
        let exit_sighashes: Vec<Vec<u8>> = exits.iter().map(|(_, s)| s.sighash.to_vec()).collect();
        let all: Vec<Vec<u8>> = delegate.iter().chain(exit_sighashes.iter()).cloned().collect();
        let key = c.signing_key().map_err(Status::internal)?;
        let (signing, commitments) = crate::sign::SigningSession::begin(key, &all);
        Ok((Self { signing, exits }, ToSign { delegate, exits: exit_sighashes, commitments }))
    }

    /// Finish the round, keep the delegate, and arm the watch — and enrol [device_token] for the
    /// wakes that watch sends, when the request carried one.
    pub fn finalise(
        self,
        cosigner: &Arc<Mutex<Cosigner>>,
        rounds: Vec<proto::WalletRound>,
        device_token: &str,
    ) -> Result<proto::DelegateRenewed, Status> {
        let device_enrolled = enrol_device(cosigner, device_token);
        let mut c = lock(cosigner);
        // A bad share is the caller's fault, and is reported as such.
        let signatures = self
            .signing
            .finish(rounds.into_iter().map(Into::into).collect())
            .map_err(Status::invalid_argument)?;

        // The round signed the delegate's messages and then the exits', in that order.
        if signatures.len() < self.exits.len() {
            return Err(Status::internal(format!(
                "the round returned {} signatures, fewer than the {} exits it was given",
                signatures.len(),
                self.exits.len()
            )));
        }
        let (delegate_sigs, exit_sigs) = signatures.split_at(signatures.len() - self.exits.len());
        // Put each signature into its exit's witness. The transactions are complete after this — no
        // ASP leg, no second round, nothing left to add.
        let exit_txs = self
            .exits
            .into_iter()
            .zip(exit_sigs)
            .map(|((outpoint, spend), sig)| {
                let raw_tx = exit::finalize_exit_tx(&spend, sig).map_err(|e| {
                    Status::internal(format!("finalizing the exit of {outpoint}: {e}"))
                })?;
                Ok(proto::ExitTx {
                    outpoint,
                    raw_tx,
                    sequence: spend.sequence,
                    amount_sats: spend.tx.output[0].value.to_sat(),
                })
            })
            .collect::<Result<Vec<_>, Status>>()?;

        c.renew_session
            .as_mut()
            .ok_or_else(|| Status::internal("no delegate session"))?
            .sign(delegate_sigs)
            .map_err(Status::internal)?;
        let valid_at = c.settle_deadline().ok_or_else(|| {
            Status::internal("the delegate lost its deadline between building and signing")
        })?;

        // Arm the watch for that deadline. Here, because `enqueue` is interactive only: background
        // work cannot grant itself standing work, so arming rides the call that signed the
        // delegate. It is the only thing this queue is used for — `crate::escrow` says why
        // an escrow's deadline needs no task.
        debug_assert!(valid_label(CATEGORY_SETTLE_DUE));
        let payload = serde_json::to_vec(&Task::SettleDue { deadline_secs: valid_at })
            .map_err(|e| Status::internal(format!("encode task: {e}")))?;
        // First run at the deadline itself — a delegate is not valid before it, so running earlier
        // would only report NotDue and put the real run a whole interval late. One already past
        // runs at once; one missed while the enclave was down runs when it recovers the queue.
        let host = c.host.clone();
        let enqueue =
            || host.enqueue(WATCH_TASK_ID, &payload, valid_at * 1000, Some(WATCH_INTERVAL_MS));
        match enqueue() {
            Ok(()) => {}
            // A task id is an idempotency key: arming again with the same deadline is a no-op, and
            // with a different one — a new delegate over VTXOs that expire at another time — the
            // runtime refuses until the old record is gone. Cancelled is terminal, so it can then
            // be forgotten, and the id is free. The watch cannot be running meanwhile: renewing
            // happens in a request, which holds the tenant the background task would need.
            Err(e) if e.contains("different input") => {
                let rearm = |e: String| Status::internal(format!("re-arming the watch: {e}"));
                host.cancel(WATCH_TASK_ID).map_err(rearm)?;
                host.forget(WATCH_TASK_ID).map_err(rearm)?;
                enqueue().map_err(Status::internal)?;
            }
            Err(e) => return Err(Status::internal(e)),
        }
        c.seal();
        Ok(proto::DelegateRenewed {
            valid_at_secs: valid_at,
            margin_secs: c.store.auto_settle_safety_margin_secs.max(0) as u64,
            covered: c.vtxos.iter().map(|v| format!("{}:{}", v.txid, v.vout)).collect(),
            device_enrolled,
            exit_txs,
        })
    }
}

impl DelegateStream for proto::SendServerMsg {
    type In = proto::SendClientMsg;

    fn sighashes(session_id: &str, seq: u64, to_sign: ToSign, wallet_dealt_share: Vec<u8>) -> Self {
        Self {
            session_id: session_id.to_string(),
            seq,
            body: Some(proto::send_server_msg::Body::Sighashes(proto::SendSighashes {
                exit_messages: to_sign.exits,
                wallet_dealt_share,
                ..proto::SendSighashes::round(to_sign.delegate, to_sign.commitments)
            })),
        }
    }

    fn signed(body: proto::send_client_msg::Body) -> Option<Vec<proto::WalletRound>> {
        match body {
            proto::send_client_msg::Body::Signed(s) => Some(s.rounds),
            _ => None,
        }
    }

    fn renewed(session_id: &str, seq: u64, renewed: proto::DelegateRenewed) -> Self {
        Self {
            session_id: session_id.to_string(),
            seq,
            body: Some(proto::send_server_msg::Body::DelegateRenewed(renewed)),
        }
    }
}

impl DelegateStream for proto::RenewServerMsg {
    type In = proto::RenewClientMsg;

    fn sighashes(session_id: &str, seq: u64, to_sign: ToSign, wallet_dealt_share: Vec<u8>) -> Self {
        Self {
            session_id: session_id.to_string(),
            seq,
            body: Some(proto::renew_server_msg::Body::Sighashes(proto::RenewSighashes {
                exit_messages: to_sign.exits,
                wallet_dealt_share,
                ..proto::RenewSighashes::round(to_sign.delegate, to_sign.commitments)
            })),
        }
    }

    fn signed(body: proto::renew_client_msg::Body) -> Option<Vec<proto::WalletRound>> {
        match body {
            proto::renew_client_msg::Body::Signed(s) => Some(s.rounds),
            _ => None,
        }
    }

    fn renewed(session_id: &str, seq: u64, renewed: proto::DelegateRenewed) -> Self {
        Self {
            session_id: session_id.to_string(),
            seq,
            body: Some(proto::renew_server_msg::Body::DelegateRenewed(renewed)),
        }
    }
}
