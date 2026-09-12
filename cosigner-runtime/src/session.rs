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

use tokio_stream::{Stream, StreamExt};
use tonic::{Request, Response, Status, Streaming};

use crate::cosigner::instance::Cosigner;
use crate::cosigner::types::{SignStep1, SignStep2};

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
    cosigner: Arc<Cosigner>,
}

impl SessionService {
    pub fn new(cosigner: Arc<Cosigner>) -> Self {
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
                let mut actor = cosigner.actor().await;
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
                let mut actor = cosigner.actor().await;
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
    /// The unary form needed a `sessions` map keyed by user, with a TTL and an eviction loop, purely
    /// to hold round-1 and round-2 material between three requests — and that material is how the
    /// key is born. Here the session is a LOCAL: created at open, dropped when the stream ends.
    /// There is no map to evict from, no TTL to tune, and an abandoned ceremony leaves nothing
    /// behind rather than leaving key material sitting in a map until a sweep notices.
    async fn dkg(
        &self,
        request: Request<Streaming<proto::DkgClientMsg>>,
    ) -> Result<Response<DkgStream>, Status> {
        let shared = self.cosigner.shared().clone();
        let cosigner = self.cosigner.clone();
        let mut inbound = request.into_inner();

        let out = async_stream::try_stream! {
            use crate::onboarding::{handlers as ob, session::OnboardingSession};

            let first = inbound
                .next()
                .await
                .ok_or_else(|| Status::invalid_argument("stream closed before it opened"))??;
            let session_id = first.session_id.clone();
            let open = match first.body {
                Some(proto::dkg_client_msg::Body::Open(o)) => o,
                _ => Err(Status::invalid_argument("a session must open with DkgOpen"))?,
            };
            let user_id_hex = hex::encode(&open.user_id);

            // The ceremony, owned here.
            let mut sess = OnboardingSession::new(user_id_hex.clone());

            // --- round 1 ---
            let r1 = {
                let (tx, rx) = tokio::sync::oneshot::channel();
                ob::onboarding_step1(
                    &mut sess,
                    &shared,
                    wp::DkgStep1Request {
                        user_id: open.user_id.clone(),
                        identifier: open.identifier.clone(),
                        round1_package: open.round1_package,
                    },
                    tx,
                );
                rx.await.map_err(|_| Status::internal("dkg round 1 dropped its reply"))??
            };
            yield proto::DkgServerMsg {
                session_id: session_id.clone(),
                seq: 1,
                body: Some(proto::dkg_server_msg::Body::Round1(proto::DkgRound1Out {
                    round1_packages: r1.round1_packages,
                })),
            };

            // --- round 2 ---
            let msg = inbound
                .next()
                .await
                .ok_or_else(|| Status::cancelled("stream closed before round 2"))??;
            let round1 = match msg.body {
                Some(proto::dkg_client_msg::Body::Round1(r)) => r,
                _ => Err(Status::invalid_argument("expected DkgRound1"))?,
            };
            let r2 = {
                let (tx, rx) = tokio::sync::oneshot::channel();
                ob::onboarding_step2(
                    &mut sess,
                    &shared,
                    wp::DkgStep2Request {
                        user_id: open.user_id.clone(),
                        identifier: round1.identifier,
                        round1_package: round1.round1_package,
                    },
                    tx,
                );
                rx.await.map_err(|_| Status::internal("dkg round 2 dropped its reply"))??
            };
            yield proto::DkgServerMsg {
                session_id: session_id.clone(),
                seq: 2,
                body: Some(proto::dkg_server_msg::Body::Round2(proto::DkgRound2Out {
                    all_round1_packages: r2.all_round1_packages,
                })),
            };

            // --- round 3, and the key ---
            let msg = inbound
                .next()
                .await
                .ok_or_else(|| Status::cancelled("stream closed before round 3"))??;
            let round2 = match msg.body {
                Some(proto::dkg_client_msg::Body::Round2(r)) => r,
                _ => Err(Status::invalid_argument("expected DkgRound2"))?,
            };
            let (r3, seed) = {
                let (tx, rx) = tokio::sync::oneshot::channel();
                let finalized = ob::onboarding_step3(
                    &mut sess,
                    &shared,
                    wp::DkgStep3Request {
                        user_id: open.user_id.clone(),
                        identifier: round2.identifier,
                        round2_packages_for_others: round2.round2_packages_for_others,
                    },
                    tx,
                );
                let out = rx.await.map_err(|_| Status::internal("dkg round 3 dropped its reply"))??;
                (out, if finalized { sess.seed_material.take() } else { None })
            };

            // Seed the key into the actor and seal it. No plaintext fallback: if this fails,
            // onboarding fails rather than leaving a wallet whose key exists only in a reply.
            let mut group_key = String::new();
            if let Some(mat) = seed {
                group_key = mat.group_key.clone();
                let mut actor = cosigner.actor().await;
                actor
                    .install_policy(
                        mat.group_key.clone(),
                        &mat.key_package_json,
                        &mat.public_key_package_json,
                        mat.user_signing_identifier_hex.as_deref(),
                        mat.server_dkg_secret_hex.clone(),
                        // A normal wallet actor has no pairing conditioning and no contracts.
                        None,
                        String::new(),
                    )
                    .map_err(Status::internal)?;
                cosigner.persist(&mut actor).await;
            }

            yield proto::DkgServerMsg {
                session_id,
                seq: 3,
                body: Some(proto::dkg_server_msg::Body::Complete(proto::DkgComplete {
                    round2_packages_for_me: r3.round2_packages_for_me,
                    group_key,
                })),
            };
        };

        Ok(Response::new(Box::pin(out) as DkgStream))
    }

    /// A send as one session.
    ///
    /// The unary form parked the half-built transactions on the actor between "build it" and
    /// "submit it", discriminated by whether `signed_messages` was empty. Here the session is a
    /// local: an abandoned send drops its half-signed transactions instead of leaving them
    /// addressable by whoever sends the next request.
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

            // --- Build ---------------------------------------------------------------------
            //
            // The inputs come from the set the cosigner already holds, not from the request: a
            // caller cannot nominate VTXOs it does not own.
            let (session, sighashes) = {
                let mut actor = cosigner.actor().await;
                let step1 = crate::cosigner::types::SendVtxoStep1 {
                    user_id: open.user_id.clone(),
                    signature: open.signature.clone(),
                    timestamp_ms: open.timestamp_ms,
                    recipient_ark_address: open.recipient_ark_address.clone(),
                    amount: open.amount,
                    vtxos: actor.vtxos().to_vec(),
                };
                let (s, delay, sighashes) = actor.send_open(step1).await.map_err(Status::internal)?;
                ((s, delay), sighashes)
            };

            yield proto::SendServerMsg {
                session_id: session_id.clone(),
                seq: 1,
                body: Some(proto::send_server_msg::Body::Sighashes(proto::SendSighashes {
                    messages_to_sign: sighashes,
                    script_path_spend: true,
                })),
            };

            // --- Submit --------------------------------------------------------------------
            let second = inbound
                .next()
                .await
                .ok_or_else(|| Status::cancelled("stream closed before the signatures arrived"))??;
            let signed = match second.body {
                Some(proto::send_client_msg::Body::Signed(s)) => s,
                _ => Err(Status::invalid_argument("expected SendSigned"))?,
            };

            let req = wp::SendVtxoRequest {
                user_id: open.user_id.clone(),
                signature: open.signature.clone(),
                timestamp_ms: open.timestamp_ms,
                recipient_ark_address: open.recipient_ark_address.clone(),
                amount: open.amount,
                signed_messages: signed.signed_messages.clone(),
            };

            let resp = {
                let mut actor = cosigner.actor().await;
                let submitted = actor
                    .send_finish(
                        session,
                        crate::cosigner::types::SendVtxoStep2 {
                            user_id: open.user_id,
                            signature: open.signature,
                            timestamp_ms: open.timestamp_ms,
                            signed_messages: signed.signed_messages,
                        },
                    )
                    .await
                    .map_err(Status::internal)?;
                let resp = actor.apply_send(&req, submitted);
                cosigner.persist(&mut actor).await;
                resp
            };

            yield proto::SendServerMsg {
                session_id,
                seq: 2,
                body: Some(proto::send_server_msg::Body::Complete(proto::SendComplete {
                    ark_txid: resp.ark_txid,
                    change: None,
                })),
            };
        };

        Ok(Response::new(Box::pin(out) as SendStream))
    }

    /// Settling a boarding output, as one session.
    ///
    /// The rounds are driven by the actor's in-flight session rather than counted here: it yields
    /// sighashes while it still needs signatures and a result when it does not, so the loop ends
    /// when the ceremony does.
    ///
    /// The in-flight state still lives on the actor (`boarding_settle`), unlike `Sign` and `Send`
    /// whose sessions are values now. That is the remaining instance of the same problem and it
    /// wants the same fix; the transport moving first is what makes the fix expressible.
    async fn settle(
        &self,
        request: Request<Streaming<proto::SettleClientMsg>>,
    ) -> Result<Response<SettleStream>, Status> {
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
            let boarding_utxo = open
                .boarding_utxo
                .map(|u| (u.txid, u.vout, u.amount_sats));

            let user_id_hex = crate::cosigner::handlers::parsers::user_id_hex(&open.user_id);
            let mut signed_messages: Vec<Vec<u8>> = Vec::new();
            let mut seq = 0u64;

            loop {
                let outcome = {
                    let mut actor = cosigner.actor().await;
                    let utxo = if signed_messages.is_empty() { boarding_utxo.clone() } else { None };
                    actor
                        .boarding_settle(utxo, std::mem::take(&mut signed_messages))
                        .await
                        .map_err(|m| Status::internal(format!("BoardingSettle: {m}")))?
                };
                seq += 1;

                match outcome {
                    crate::cosigner::types::BoardingSettleOutcome::Sighashes(messages_to_sign) => {
                        yield proto::SettleServerMsg {
                            session_id: session_id.clone(),
                            seq,
                            body: Some(proto::settle_server_msg::Body::Sighashes(
                                proto::SettleSighashes { messages_to_sign, script_path_spend: true },
                            )),
                        };
                        let next = inbound
                            .next()
                            .await
                            .ok_or_else(|| Status::cancelled("stream closed mid-settle"))??;
                        signed_messages = match next.body {
                            Some(proto::settle_client_msg::Body::Signed(s)) => s.signed_messages,
                            _ => Err(Status::invalid_argument("expected SettleSigned"))?,
                        };
                        if signed_messages.is_empty() {
                            Err(Status::invalid_argument("SettleSigned carried no signatures"))?;
                        }
                    }
                    crate::cosigner::types::BoardingSettleOutcome::Submitted(sub) => {
                        let commitment_txid = {
                            let mut actor = cosigner.actor().await;
                            let txid = actor.apply_boarding_settle(&user_id_hex, sub);
                            cosigner.persist(&mut actor).await;
                            txid
                        };
                        yield proto::SettleServerMsg {
                            session_id,
                            seq,
                            body: Some(proto::settle_server_msg::Body::Complete(
                                proto::SettleComplete { commitment_txid },
                            )),
                        };
                        break;
                    }
                }
            }
        };

        Ok(Response::new(Box::pin(out) as SettleStream))
    }
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
    cosigner: Arc<Cosigner>,
    server_info: wp::GetServerInfoResponse,
}

impl WalletService {
    pub fn new(
        cosigner: Arc<Cosigner>,
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
    crate::cosigner::handlers::helpers::verify_auth(user_id, signature, timestamp_ms, op, None)
}

#[tonic::async_trait]
impl MpcWallet for WalletService {
    async fn get_ark_info(
        &self,
        request: Request<wp::GetArkInfoRequest>,
    ) -> Result<Response<wp::GetArkInfoResponse>, Status> {
        let req = request.into_inner();
        check(&req.user_id, &req.signature, req.timestamp_ms, crate::auth::message::OP_GET_ARK_INFO)?;
        let out = self.cosigner.actor().await.get_ark_info(req).await?;
        Ok(Response::new(out))
    }

    async fn list_vtxos(
        &self,
        request: Request<wp::ListVtxosRequest>,
    ) -> Result<Response<wp::ListVtxosResponse>, Status> {
        let req = request.into_inner();
        check(&req.user_id, &req.signature, req.timestamp_ms, crate::auth::message::OP_LIST_VTXOS)?;
        let out = self.cosigner.actor().await.list_vtxos(req).await?;
        Ok(Response::new(out))
    }

    async fn list_ark_transactions(
        &self,
        request: Request<wp::ListArkTransactionsRequest>,
    ) -> Result<Response<wp::ListArkTransactionsResponse>, Status> {
        let req = request.into_inner();
        check(&req.user_id, &req.signature, req.timestamp_ms, crate::auth::message::OP_LIST_ARK_TXS)?;
        let out = self.cosigner.actor().await.list_ark_transactions(req).await?;
        Ok(Response::new(out))
    }

    async fn contact_list(
        &self,
        request: Request<wp::ContactListRequest>,
    ) -> Result<Response<wp::ContactListResponse>, Status> {
        let req = request.into_inner();
        check(&req.user_id, &req.signature, req.timestamp_ms, crate::auth::message::OP_CONTACT_LIST)?;
        let out = self.cosigner.actor().await.contact_list(req).await?;
        Ok(Response::new(out))
    }

    async fn payment_request_list(
        &self,
        request: Request<wp::PaymentRequestListRequest>,
    ) -> Result<Response<wp::PaymentRequestListResponse>, Status> {
        let req = request.into_inner();
        check(&req.user_id, &req.signature, req.timestamp_ms, crate::auth::message::OP_PAYREQ_LIST)?;
        let out = self.cosigner.actor().await.payment_request_list(req).await?;
        Ok(Response::new(out))
    }

    async fn register_device_token(
        &self,
        request: Request<wp::RegisterDeviceTokenRequest>,
    ) -> Result<Response<wp::RegisterDeviceTokenResponse>, Status> {
        let req = request.into_inner();
        check(&req.user_id, &req.signature, req.timestamp_ms, crate::auth::message::OP_REGISTER_DEVICE_TOKEN)?;
        let out = self.cosigner.actor().await.register_device_token(req).await?;
        Ok(Response::new(out))
    }

    async fn get_ark_address(
        &self,
        request: Request<wp::GetArkAddressRequest>,
    ) -> Result<Response<wp::GetArkAddressResponse>, Status> {
        let req = request.into_inner();
        check(&req.user_id, &req.signature, req.timestamp_ms, crate::auth::message::OP_GET_ARK_ADDRESS)?;
        let out = self
            .cosigner
            .actor()
            .await
            .get_ark_address(req)
            .await?;
        Ok(Response::new(out))
    }

    async fn get_boarding_address(
        &self,
        request: Request<wp::GetBoardingAddressRequest>,
    ) -> Result<Response<wp::GetBoardingAddressResponse>, Status> {
        let req = request.into_inner();
        check(&req.user_id, &req.signature, req.timestamp_ms, crate::auth::message::OP_GET_BOARDING_ADDRESS)?;
        let out = self
            .cosigner
            .actor()
            .await
            .get_boarding_address(req)
            .await?;
        Ok(Response::new(out))
    }

    async fn get_server_info(
        &self,
        _request: Request<wp::GetServerInfoRequest>,
    ) -> Result<Response<wp::GetServerInfoResponse>, Status> {
        Ok(Response::new(self.server_info.clone()))
    }

    // --- Ceremonies: sessions, not calls ------------------------------------------------------
    async fn dkg_step1(&self, _r: Request<wp::DkgStep1Request>) -> Result<Response<wp::DkgStep1Response>, Status> {
        Err(use_a_session("DKG"))
    }
    async fn dkg_step2(&self, _r: Request<wp::DkgStep2Request>) -> Result<Response<wp::DkgStep2Response>, Status> {
        Err(use_a_session("DKG"))
    }
    async fn dkg_step3(&self, _r: Request<wp::DkgStep3Request>) -> Result<Response<wp::DkgStep3Response>, Status> {
        Err(use_a_session("DKG"))
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
    async fn submit_ark_send(&self, _r: Request<wp::SubmitArkSendRequest>) -> Result<Response<wp::SubmitArkSendResponse>, Status> {
        Err(use_a_session("SubmitArkSend"))
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
        let out = self.cosigner.actor().await.contact_add(req).await?;
        Ok(Response::new(out))
    }

    async fn contact_remove(
        &self,
        request: Request<wp::ContactRemoveRequest>,
    ) -> Result<Response<wp::ContactRemoveResponse>, Status> {
        let req = request.into_inner();
        check(&req.user_id, &req.signature, req.timestamp_ms, crate::auth::message::OP_CONTACT_REMOVE)?;
        let out = self.cosigner.actor().await.contact_remove(req).await?;
        Ok(Response::new(out))
    }

    async fn payment_request_decline(
        &self,
        request: Request<wp::PaymentRequestDeclineRequest>,
    ) -> Result<Response<wp::PaymentRequestDeclineResponse>, Status> {
        let req = request.into_inner();
        check(&req.user_id, &req.signature, req.timestamp_ms, crate::auth::message::OP_PAYREQ_DECLINE)?;
        let mut actor = self.cosigner.actor().await;
        actor.require_owner(&req.user_id)?;
        actor.decline_intent(&req.id).map_err(Status::invalid_argument)?;
        self.cosigner.persist(&mut actor).await;
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
        let out = self.cosigner.actor().await.payment_request_create(req).await?;
        Ok(Response::new(out))
    }
}
