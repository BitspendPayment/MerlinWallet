//! Ceremonies as bidirectional gRPC sessions.
//!
//! The unary API makes a ceremony a sequence of requests, so the server has to park state between
//! them: a FROST nonce for signing, round-1 and round-2 secrets for DKG. Under a per-request
//! runtime there is no "between" — that state would have to be persisted, and a reused nonce leaks
//! a secret share.
//!
//! One stream removes the problem rather than managing it. The ceremony is one session, its secrets
//! live on this handler's stack, and a stream that dies takes them with it. A reconnect is a new
//! session with new secrets, so there is nothing to replay and no ledger to keep.
//!
//! Authentication is once, at open, for the session — matching the runtime this is heading for,
//! where one passkey assertion authorizes one interaction and the messages inside it are not
//! individually approved. See `cosign_session.proto` for why there is no per-message approval field.

use std::pin::Pin;
use std::sync::Arc;

use tokio::sync::Mutex;

use tokio_stream::{Stream, StreamExt};
use tonic::{Request, Response, Status, Streaming};

use crate::cosigner::Cosigner;
use crate::types::{SignStep1, SignStep2};

pub mod proto {
    #![allow(clippy::all)]
    tonic::include_proto!("mpc_wallet.session.v1");
}

use proto::signing_session_server::SigningSession;
use proto::{
    sign_client_msg, sign_server_msg, Commitment, SignClientMsg, SignComplete, SignCommitments,
    SignServerMsg,
};

pub struct SessionService {
    cosigner: Arc<Mutex<Cosigner>>,
}

impl SessionService {
    pub fn new(cosigner: Arc<Mutex<Cosigner>>) -> Self {
        Self { cosigner }
    }
}

type SignStream = Pin<Box<dyn Stream<Item = Result<SignServerMsg, Status>> + Send + 'static>>;
type DkgStream = Pin<Box<dyn Stream<Item = Result<proto::DkgServerMsg, Status>> + Send + 'static>>;
type SendStream = Pin<Box<dyn Stream<Item = Result<proto::SendServerMsg, Status>> + Send + 'static>>;
type SettleStream =
    Pin<Box<dyn Stream<Item = Result<proto::SettleServerMsg, Status>> + Send + 'static>>;

#[tonic::async_trait]
impl SigningSession for SessionService {
    type SignStream = SignStream;
    type DkgStream = DkgStream;
    type SendStream = SendStream;
    type SettleStream = SettleStream;

    async fn sign(
        &self,
        request: Request<Streaming<SignClientMsg>>,
    ) -> Result<Response<SignStream>, Status> {
        let cosigner = self.cosigner.clone();
        let mut inbound = request.into_inner();

        let out = async_stream::try_stream! {
            // --- Round 1: open ------------------------------------------------------------
            let first = inbound
                .next()
                .await
                .ok_or_else(|| Status::invalid_argument("stream closed before it opened"))??;
            let session_id = first.session_id.clone();
            let open = match first.body {
                Some(sign_client_msg::Body::Open(o)) => o,
                _ => Err(Status::invalid_argument("a session must open with SignOpen"))?,
            };

            let step1 = SignStep1 {
                user_id: open.user_id.clone(),
                hiding_commitment: open.hiding_commitment,
                binding_commitment: open.binding_commitment,
                message_to_sign: open.message_to_sign,
                signature: open.signature,
                full_transaction: open.full_transaction,
                timestamp_ms: open.timestamp_ms,
                script_path_spend: open.script_path_spend,
                ark_tx: Vec::new(),
            };

            // The ceremony is OURS, as an ordinary local. The actor never held it, and the lock is
            // released before we wait on the client — a slow client blocks nobody.
            let (ceremony, opened) = {
                let mut actor = cosigner.lock().await;
                actor.sign_open(step1).map_err(Status::internal)?
            };

            yield SignServerMsg {
                session_id: session_id.clone(),
                seq: 1,
                body: Some(sign_server_msg::Body::Commitments(SignCommitments {
                    commitments: opened
                        .commitments
                        .into_iter()
                        .map(|c| (c.identifier_hex, Commitment { hiding: c.hiding, binding: c.binding }))
                        .collect(),
                    message_to_sign: opened.message_to_sign,
                })),
            };

            // --- Round 2: the client's share ----------------------------------------------
            //
            // If the client never sends it, or the stream dies here, `ceremony` drops with this
            // task and the nonce is gone. That is the safe failure: an abandoned round leaves
            // nothing reusable behind.
            let second = inbound
                .next()
                .await
                .ok_or_else(|| Status::cancelled("stream closed before the share arrived"))??;
            let share = match second.body {
                Some(sign_client_msg::Body::Share(s)) => s,
                _ => Err(Status::invalid_argument("expected SignShare"))?,
            };

            let step2 = SignStep2 {
                user_id: open.user_id,
                signature_share: share.signature_share,
                signature: Vec::new(),
                timestamp_ms: open.timestamp_ms,
            };

            let done = {
                let mut actor = cosigner.lock().await;
                actor.sign_finish(ceremony, step2).map_err(Status::internal)?
            };

            yield SignServerMsg {
                session_id,
                seq: 2,
                body: Some(sign_server_msg::Body::Complete(SignComplete {
                    r_point: done.r_point,
                    z_scalar: done.z_scalar,
                })),
            };
        };

        Ok(Response::new(Box::pin(out) as SignStream))
    }

    /// DKG as one session.
    ///
    /// The unary form needed a `sessions` map keyed by user, with a TTL and an eviction loop,
    /// purely to hold round-1 and round-2 material between three requests — and that material is
    /// how the key is born. Here the session is a LOCAL: created at open, dropped when the stream
    /// ends. There is no map to evict from, no TTL to tune, and an abandoned ceremony leaves
    /// nothing behind rather than key material sitting in a map until a sweep notices.
    async fn dkg(
        &self,
        request: Request<Streaming<proto::DkgClientMsg>>,
    ) -> Result<Response<DkgStream>, Status> {
        let upstreams = { self.cosigner.lock().await.upstreams().clone() };
        let cosigner = self.cosigner.clone();
        let mut inbound = request.into_inner();

        let out = async_stream::try_stream! {
            use crate::handlers::onboarding as ob;
            use crate::handlers::onboarding::OnboardingSession;

            let first = inbound
                .next()
                .await
                .ok_or_else(|| Status::invalid_argument("stream closed before it opened"))??;
            let session_id = first.session_id.clone();
            let open = match first.body {
                Some(proto::dkg_client_msg::Body::Open(o)) => o,
                _ => Err(Status::invalid_argument("a session must open with DkgOpen"))?,
            };

            // The ceremony, owned here. Round-1 and round-2 secrets live on this stack and die
            // with the stream.
            let mut sess = OnboardingSession::new(hex::encode(&open.user_id));

            let r1 = ob::dkg_open(
                &mut sess,
                wp::DkgStep1Request {
                    user_id: open.user_id.clone(),
                    identifier: open.identifier.clone(),
                    round1_package: open.round1_package,
                },
            )?;
            yield proto::DkgServerMsg {
                session_id: session_id.clone(),
                seq: 1,
                body: Some(proto::dkg_server_msg::Body::Round1(proto::DkgRound1Out {
                    round1_packages: r1.round1_packages,
                })),
            };

            // --- The wallet's round 2, and the key ------------------------------------------
            let msg = inbound
                .next()
                .await
                .ok_or_else(|| Status::cancelled("stream closed before round 2"))??;
            let round2 = match msg.body {
                Some(proto::dkg_client_msg::Body::Round2(r)) => r,
                _ => Err(Status::invalid_argument("expected DkgRound2"))?,
            };
            let r3 = ob::dkg_finish(
                &mut sess,
                &upstreams,
                wp::DkgStep3Request {
                    user_id: open.user_id.clone(),
                    identifier: round2.identifier,
                    round2_packages_for_others: round2.round2_packages_for_others,
                },
            )?;
            let mat = sess
                .seed_material
                .take()
                .ok_or_else(|| Status::internal("DKG finished without key material"))?;
            let group_key = mat.group_key.clone();

            // Install the key and seal it. No plaintext fallback: if this fails the ceremony
            // fails, rather than leaving a wallet whose key exists only in a reply.
            {
                let mut c = cosigner.lock().await;
                c.install_policy(
                    mat.group_key,
                    &mat.key_package_json,
                    &mat.public_key_package_json,
                    mat.user_signing_identifier_hex.as_deref(),
                    mat.server_dkg_secret_hex,
                    )
                .map_err(Status::internal)?;
                c.seal().await;
            }

            yield proto::DkgServerMsg {
                session_id,
                seq: 2,
                body: Some(proto::dkg_server_msg::Body::Complete(proto::DkgComplete {
                    round2_packages_for_me: r3.round2_packages_for_me,
                    group_key,
                })),
            };
        };

        Ok(Response::new(Box::pin(out) as DkgStream))
    }


    /// A send as one session, with the caller submitting.
    ///
    /// The unary form parked the half-built transactions on the actor between "build it" and
    /// "submit it", and called the ASP itself for both `SubmitTx` and `FinalizeTx`. Here the
    /// session is a local on this handler and the caller makes those two calls: the cosigner hands
    /// over what to send and seals only once the ASP has accepted it, so an interrupted send leaves
    /// neither a half-signed transaction addressable by the next request nor a recorded spend that
    /// never happened.
    async fn send(
        &self,
        request: Request<Streaming<proto::SendClientMsg>>,
    ) -> Result<Response<SendStream>, Status> {
        let cosigner = self.cosigner.clone();
        let mut inbound = request.into_inner();

        let out = async_stream::try_stream! {
            let first = inbound
                .next()
                .await
                .ok_or_else(|| Status::invalid_argument("stream closed before it opened"))??;
            let session_id = first.session_id.clone();
            let open = match first.body {
                Some(proto::send_client_msg::Body::Open(o)) => o,
                _ => Err(Status::invalid_argument("a session must open with SendOpen"))?,
            };
            let info = open
                .ark_info
                .map(ark_info_from_proto)
                .ok_or_else(|| Status::invalid_argument("SendOpen carried no ark_info"))?;

            // The inputs come from the set the cosigner already holds, not from the request: a
            // caller cannot nominate VTXOs it does not own.
            let (mut session, change_exit_delay, sighashes) = {
                let mut c = cosigner.lock().await;
                let step1 = crate::types::SendVtxoStep1 {
                    user_id: open.user_id.clone(),
                    signature: open.signature.clone(),
                    timestamp_ms: open.timestamp_ms,
                    recipient_ark_address: open.recipient_ark_address.clone(),
                    amount: open.amount,
                    vtxos: c.vtxos().to_vec(),
                };
                c.send_open(step1, &info).map_err(Status::internal)?
            };

            yield proto::SendServerMsg {
                session_id: session_id.clone(),
                seq: 1,
                body: Some(proto::send_server_msg::Body::Sighashes(proto::SendSighashes {
                    messages_to_sign: sighashes,
                    script_path_spend: true,
                })),
            };

            // --- The caller's signatures, then what it must submit --------------------------
            let signed = match next_send(&mut inbound).await? {
                proto::send_client_msg::Body::Signed(s) => s,
                _ => Err(Status::invalid_argument("expected SendSigned"))?,
            };
            let (ark_tx_b64, checkpoint_txs) = {
                let mut c = cosigner.lock().await;
                c.send_prepare(
                    &mut session,
                    crate::types::SendVtxoStep2 {
                        user_id: open.user_id.clone(),
                        signature: open.signature.clone(),
                        timestamp_ms: open.timestamp_ms,
                        signed_messages: signed.signed_messages,
                    },
                )
                .map_err(Status::internal)?
            };

            yield proto::SendServerMsg {
                session_id: session_id.clone(),
                seq: 2,
                body: Some(proto::send_server_msg::Body::Submit(proto::SendSubmit {
                    ark_tx_b64,
                    checkpoint_txs,
                })),
            };

            // --- What the ASP returned, turned into the finalize call -----------------------
            let submitted = match next_send(&mut inbound).await? {
                proto::send_client_msg::Body::Submitted(s) => s,
                _ => Err(Status::invalid_argument("expected SendSubmitted"))?,
            };
            let final_checkpoint_txs = {
                let mut c = cosigner.lock().await;
                c.send_finalize(&mut session, &submitted.signed_checkpoint_txs)
                    .map_err(Status::internal)?
            };

            yield proto::SendServerMsg {
                session_id: session_id.clone(),
                seq: 3,
                body: Some(proto::send_server_msg::Body::Finalize(proto::SendFinalize {
                    ark_txid: submitted.ark_txid.clone(),
                    final_checkpoint_txs,
                })),
            };

            // --- Accepted. Only now is it ours to record -----------------------------------
            match next_send(&mut inbound).await? {
                proto::send_client_msg::Body::Finalized(_) => {}
                _ => Err(Status::invalid_argument("expected SendFinalized"))?,
            }
            let req = wp::SendVtxoRequest {
                user_id: open.user_id.clone(),
                signature: open.signature.clone(),
                timestamp_ms: open.timestamp_ms,
                recipient_ark_address: open.recipient_ark_address.clone(),
                amount: open.amount,
                signed_messages: Vec::new(),
            };
            let resp = {
                let mut c = cosigner.lock().await;
                let submitted =
                    c.send_complete((session, change_exit_delay), submitted.ark_txid);
                let resp = c.apply_send(&req, submitted);
                c.seal().await;
                resp
            };

            yield proto::SendServerMsg {
                session_id,
                seq: 4,
                body: Some(proto::send_server_msg::Body::Complete(proto::SendComplete {
                    ark_txid: resp.ark_txid,
                    change: None,
                })),
            };
        };

        Ok(Response::new(Box::pin(out) as SendStream))
    }




    /// Settling, with the caller driving the ASP round.
    ///
    /// The cosigner answers each relayed event with what to send the ASP next and never opens a
    /// socket of its own. `ark_info` arrives from the caller for the same reason: it is the one
    /// talking to the ASP. See `settle.rs` for why that cannot redirect funds.
    async fn settle(
        &self,
        request: Request<Streaming<proto::SettleClientMsg>>,
    ) -> Result<Response<SettleStream>, Status> {
        use crate::handlers::settle::SettleStep;

        let cosigner = self.cosigner.clone();
        let mut inbound = request.into_inner();

        let out = async_stream::try_stream! {
            let first = inbound
                .next()
                .await
                .ok_or_else(|| Status::invalid_argument("stream closed before it opened"))??;
            let session_id = first.session_id.clone();
            let open = match first.body {
                Some(proto::settle_client_msg::Body::Open(o)) => o,
                _ => Err(Status::invalid_argument("a session must open with SettleOpen"))?,
            };
            let info = open
                .ark_info
                .map(ark_info_from_proto)
                .ok_or_else(|| Status::invalid_argument("SettleOpen carried no ark_info"))?;
            let boarding_utxo = open.boarding_utxo.map(|u| (u.txid, u.vout, u.amount_sats));
            let user_id_hex = crate::handlers::parsers::user_id_hex(&open.user_id);

            let sighashes = {
                let mut c = cosigner.lock().await;
                c.settle_open(boarding_utxo, info).await.map_err(Status::internal)?
            };

            let mut seq = 1u64;
            let mut step = SettleStep::Sighashes(sighashes);

            loop {
                // Say what we need, then read what the caller did about it.
                let body = match step {
                    SettleStep::Sighashes(messages_to_sign) => Some(
                        proto::settle_server_msg::Body::Sighashes(proto::SettleSighashes {
                            messages_to_sign,
                            script_path_spend: true,
                        }),
                    ),
                    SettleStep::Register { proof, message, topics } => Some(
                        proto::settle_server_msg::Body::Register(proto::RegisterIntent {
                            proof,
                            message,
                            topics,
                        }),
                    ),
                    SettleStep::Submit(call) => {
                        Some(proto::settle_server_msg::Body::Submit(asp_submit(call)))
                    }
                    SettleStep::Idle => {
                        Some(proto::settle_server_msg::Body::Idle(proto::SettleIdle {}))
                    }
                    SettleStep::Complete(sub) => {
                        let complete = proto::SettleComplete {
                            commitment_txid: sub.commitment_txid.clone(),
                            vtxo_txid: sub.vtxo_txid.clone(),
                            vtxo_vout: sub.vtxo_vout,
                            amount_sats: sub.amount_sats,
                            exit_delay: sub.exit_delay,
                        };
                        {
                            let mut c = cosigner.lock().await;
                            c.apply_boarding_settle(&user_id_hex, sub);
                            c.seal().await;
                        }
                        yield proto::SettleServerMsg {
                            session_id,
                            seq,
                            body: Some(proto::settle_server_msg::Body::Complete(complete)),
                        };
                        break;
                    }
                };

                yield proto::SettleServerMsg {
                    session_id: session_id.clone(),
                    seq,
                    body,
                };
                seq += 1;

                let msg = inbound
                    .next()
                    .await
                    .ok_or_else(|| Status::cancelled("stream closed mid-settle"))??;
                let body = msg
                    .body
                    .ok_or_else(|| Status::invalid_argument("empty SettleClientMsg"))?;

                let mut c = cosigner.lock().await;
                step = match body {
                    proto::settle_client_msg::Body::Signed(s) => {
                        c.settle_signed(s.signed_messages).map_err(Status::internal)?
                    }
                    proto::settle_client_msg::Body::Registered(r) => {
                        c.settle_registered(r.intent_id).map_err(Status::internal)?;
                        SettleStep::Idle
                    }
                    proto::settle_client_msg::Body::Event(e) => match decode_event(&e.encoded)? {
                        Some(ev) => c.settle_on_event(ev).map_err(Status::internal)?,
                        None => SettleStep::Idle,
                    },
                    proto::settle_client_msg::Body::Open(_) => {
                        Err(Status::invalid_argument("the session is already open"))?
                    }
                };
            }
        };

        Ok(Response::new(Box::pin(out) as SettleStream))
    }
}

async fn next_send(
    inbound: &mut Streaming<proto::SendClientMsg>,
) -> Result<proto::send_client_msg::Body, Status> {
    let msg = inbound
        .next()
        .await
        .ok_or_else(|| Status::cancelled("stream closed mid-send"))??;
    msg.body
        .ok_or_else(|| Status::invalid_argument("empty SendClientMsg"))
}

/// One `GetEventStreamResponse` as it came off the ASP. `None` when the response carried no event,
/// which the ASP does send — a keepalive is not an error.
fn decode_event(
    encoded: &[u8],
) -> Result<Option<ark::client::proto::get_event_stream_response::Event>, Status> {
    use prost::Message as _;
    let resp = ark::client::proto::GetEventStreamResponse::decode(encoded)
        .map_err(|e| Status::invalid_argument(format!("undecodable ASP event: {e}")))?;
    Ok(resp.event)
}

fn ark_info_from_proto(i: proto::ArkInfo) -> ark::client::types::ArkInfo {
    ark::client::types::ArkInfo {
        signer_pubkey: i.signer_pubkey,
        forfeit_pubkey: i.forfeit_pubkey,
        forfeit_address: i.forfeit_address,
        checkpoint_tapscript: i.checkpoint_tapscript,
        network: i.network,
        session_duration: i.session_duration,
        unilateral_exit_delay: i.unilateral_exit_delay,
        boarding_exit_delay: i.boarding_exit_delay,
        vtxo_min_amount: i.vtxo_min_amount,
        dust: i.dust,
    }
}

fn asp_submit(call: crate::handlers::settle::AspCall) -> proto::AspSubmit {
    use crate::handlers::settle::AspCall;
    use proto::asp_submit::Call;
    let call = match call {
        AspCall::ConfirmRegistration { intent_id } => {
            Call::ConfirmRegistration(proto::ConfirmRegistration { intent_id })
        }
        AspCall::TreeNonces { batch_id, pubkey, nonces } => Call::TreeNonces(proto::TreeNonces {
            batch_id,
            pubkey,
            nonces: nonces.into_iter().collect(),
        }),
        AspCall::TreeSignatures { batch_id, pubkey, signatures } => {
            Call::TreeSignatures(proto::TreeSignatures {
                batch_id,
                pubkey,
                signatures: signatures.into_iter().collect(),
            })
        }
        // The signed commitment rides the same call as the forfeits; the ASP takes both.
        AspCall::ForfeitTxs { signed_txs, signed_commitment_b64 } => {
            let mut signed = signed_txs;
            if !signed_commitment_b64.is_empty() {
                signed.push(signed_commitment_b64);
            }
            Call::ForfeitTxs(proto::ForfeitTxs { signed_txs: signed })
        }
    };
    proto::AspSubmit { call: Some(call) }
}

// ===========================================================================
// The wallet API, over gRPC.
//
// `mpc_wallet.proto` has declared these RPCs all along; the server only ever served them as REST,
// so the proto was a message-definition file with an unimplemented service attached. This is that
// service, which is what lets `rest_api.rs` go: one transport, and the ceremonies that need a
// channel open in both directions get one.
//
// Auth is still `verify_auth` per call, as the REST layer did. That is transitional — the runtime
// this is heading for verifies a passkey assertion per interaction and hands the guest an already
// authenticated cosigner, at which point this disappears rather than being ported.
// ===========================================================================

use crate::wallet_proto::mpc_wallet_server::MpcWallet;
use crate::wallet_proto as wp;

pub struct WalletService {
    cosigner: Arc<Mutex<Cosigner>>,
    server_info: wp::GetServerInfoResponse,
}

impl WalletService {
    pub fn new(
        cosigner: Arc<Mutex<Cosigner>>,
        server_info: wp::GetServerInfoResponse,
    ) -> Self {
        Self { cosigner, server_info }
    }
}

/// Ceremonies that are sessions, not calls. Kept as explicit refusals rather than partial unary
/// implementations: a half-ported ceremony that appears to work is worse than one that says it is
/// not here. `Sign` already lives on `SigningSession`; the rest follow.
fn use_a_session(name: &str) -> Status {
    Status::unimplemented(format!(
        "{name} is a multi-round ceremony and is moving to a bidirectional session (see \
         cosign_session.proto); the unary form is being removed, not reimplemented"
    ))
}

/// Check the caller's auth signature, exactly as `dispatch_json!` did before it.
fn check(user_id: &[u8], signature: &[u8], timestamp_ms: i64, op: &str) -> Result<(), Status> {
    crate::handlers::helpers::verify_auth(user_id, signature, timestamp_ms, op)
}

#[tonic::async_trait]
impl MpcWallet for WalletService {



    async fn contact_list(
        &self,
        request: Request<wp::ContactListRequest>,
    ) -> Result<Response<wp::ContactListResponse>, Status> {
        let req = request.into_inner();
        check(&req.user_id, &req.signature, req.timestamp_ms, crate::auth::message::OP_CONTACT_LIST)?;
        let out = self.cosigner.lock().await.contact_list(req).await?;
        Ok(Response::new(out))
    }

    async fn payment_request_list(
        &self,
        request: Request<wp::PaymentRequestListRequest>,
    ) -> Result<Response<wp::PaymentRequestListResponse>, Status> {
        let req = request.into_inner();
        check(&req.user_id, &req.signature, req.timestamp_ms, crate::auth::message::OP_PAYREQ_LIST)?;
        let out = self.cosigner.lock().await.payment_request_list(req).await?;
        Ok(Response::new(out))
    }




    async fn get_server_info(
        &self,
        _request: Request<wp::GetServerInfoRequest>,
    ) -> Result<Response<wp::GetServerInfoResponse>, Status> {
        Ok(Response::new(self.server_info.clone()))
    }

    async fn send_vtxo(&self, _r: Request<wp::SendVtxoRequest>) -> Result<Response<wp::SendVtxoResponse>, Status> {
        Err(use_a_session("SendVtxo"))
    }
    async fn settle(&self, _r: Request<wp::SettleRequest>) -> Result<Response<wp::SettleResponse>, Status> {
        Err(use_a_session("Settle"))
    }
    async fn settle_delegate(&self, _r: Request<wp::SettleDelegateRequest>) -> Result<Response<wp::SettleDelegateResponse>, Status> {
        Err(use_a_session("SettleDelegate"))
    }


    // --- Gone with the contract layer ----------------------------------------------------------
    async fn contract_create(&self, _r: Request<wp::ContractCreateRequest>) -> Result<Response<wp::ContractCreateResponse>, Status> {
        Err(Status::unimplemented("the eVTXO/contract layer is not part of this API"))
    }
    async fn evtxo_pending_shares(&self, _r: Request<wp::EvtxoPendingSharesRequest>) -> Result<Response<wp::EvtxoPendingSharesResponse>, Status> {
        Err(Status::unimplemented("the eVTXO/contract layer is not part of this API"))
    }
    async fn evtxo_ack_share(&self, _r: Request<wp::EvtxoAckShareRequest>) -> Result<Response<wp::EvtxoAckShareResponse>, Status> {
        Err(Status::unimplemented("the eVTXO/contract layer is not part of this API"))
    }
    async fn redeem_vtxo(&self, _r: Request<wp::RedeemVtxoRequest>) -> Result<Response<wp::RedeemVtxoResponse>, Status> {
        Err(Status::unimplemented("RedeemVtxo is not implemented"))
    }

    // --- Owner-only mutations -------------------------------------------------------------------
    //
    // `require_owner`, not the wider signing test: adding yourself to a wallet's contact allowlist
    // is enough to bill it, since the allowlist is the only gate on `payment_request_create`.

    async fn contact_add(
        &self,
        request: Request<wp::ContactAddRequest>,
    ) -> Result<Response<wp::ContactAddResponse>, Status> {
        let req = request.into_inner();
        check(&req.user_id, &req.signature, req.timestamp_ms, crate::auth::message::OP_CONTACT_ADD)?;
        let out = self.cosigner.lock().await.contact_add(req).await?;
        Ok(Response::new(out))
    }

    async fn contact_remove(
        &self,
        request: Request<wp::ContactRemoveRequest>,
    ) -> Result<Response<wp::ContactRemoveResponse>, Status> {
        let req = request.into_inner();
        check(&req.user_id, &req.signature, req.timestamp_ms, crate::auth::message::OP_CONTACT_REMOVE)?;
        let out = self.cosigner.lock().await.contact_remove(req).await?;
        Ok(Response::new(out))
    }

    async fn payment_request_decline(
        &self,
        request: Request<wp::PaymentRequestDeclineRequest>,
    ) -> Result<Response<wp::PaymentRequestDeclineResponse>, Status> {
        let req = request.into_inner();
        check(&req.user_id, &req.signature, req.timestamp_ms, crate::auth::message::OP_PAYREQ_DECLINE)?;
        let mut actor = self.cosigner.lock().await;
        actor.require_owner(&req.user_id)?;
        actor.decline_intent(&req.id).map_err(Status::invalid_argument)?;
        actor.seal().await;
        Ok(Response::new(wp::PaymentRequestDeclineResponse { ok: true }))
    }

    /// The deliberate exception: signed by the REQUESTER, not this wallet's owner. The payer's
    /// contact allowlist is what authorizes it, which is why there is no `require_owner` here — and
    /// why one cosigner per process suits it: the requester addresses the payer's endpoint.
    async fn payment_request_create(
        &self,
        request: Request<wp::PaymentRequestCreateRequest>,
    ) -> Result<Response<wp::PaymentRequestCreateResponse>, Status> {
        let req = request.into_inner();
        check(&req.user_id, &req.signature, req.timestamp_ms, crate::auth::message::OP_PAYREQ_CREATE)?;
        let out = self.cosigner.lock().await.payment_request_create(req).await?;
        Ok(Response::new(out))
    }
}
