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
//!
//! # Why these are plain `async fn`s
//!
//! They were `async_stream::try_stream!` blocks behind a tonic service trait. tonic does not build
//! for `wasm32-wasip2` at all, so the guest port replaced it with [`crate::grpc`] — 250 lines that
//! do the framing, the trailers and the duplex. What did *not* change is these bodies: `yield x`
//! became `duplex.send(x)`, `inbound.next().await` became `duplex.recv().await`, and the ceremonies
//! are otherwise the same code. That was the test of whether the transport had been kept at arm's
//! length, and it passed.

use std::sync::{Arc, Mutex, MutexGuard};

use wstd::http::{Body, Request, Response};

use crate::cosigner::Cosigner;
use crate::grpc::{self, Duplex, SessionBody, Status};
use crate::types::{SignStep1, SignStep2};
use crate::wallet_proto as wp;

pub mod proto {
    #![allow(clippy::all)]
    include!(concat!(env!("OUT_DIR"), "/cosigner.v1.rs"));
}

use proto::{
    sign_client_msg, sign_server_msg, Commitment, SignClientMsg, SignCommitments, SignComplete,
    SignServerMsg,
};

/// Every RPC this service answers, under the package and service names in `cosign_session.proto`.
const PREFIX: &str = "/cosigner.v1.Cosigner/";

pub struct CosignerService {
    cosigner: Arc<Mutex<Cosigner>>,
    server_info: wp::GetServerInfoResponse,
}

impl CosignerService {
    pub fn new(cosigner: Arc<Mutex<Cosigner>>, server_info: wp::GetServerInfoResponse) -> Self {
        Self {
            cosigner,
            server_info,
        }
    }

    /// One request, routed.
    ///
    /// This is what the generated service trait was for. Matching `:path` by hand is a table of
    /// fourteen names — clearer than a code generator, and the only part of tonic still in use once
    /// the framing and the status had their own modules.
    pub async fn route(&self, req: Request<Body>) -> Response<Body> {
        let path = req.uri().path().to_string();
        let Some(method) = path.strip_prefix(PREFIX) else {
            return grpc::failed(Status::unimplemented(format!("no such service: {path}")));
        };

        // --- The ceremonies ---------------------------------------------------------------------
        //
        // Each holds the request body for the life of the response, so the head goes out before the
        // first round does.
        macro_rules! ceremony {
            ($handler:path) => {{
                let cosigner = Arc::clone(&self.cosigner);
                let inbound = req.into_body().into_boxed_body();
                return grpc::streaming(SessionBody::new(inbound, move |duplex| {
                    $handler(cosigner, duplex)
                }));
            }};
        }
        match method {
            "Sign" => ceremony!(sign),
            "Dkg" => ceremony!(dkg),
            "Send" => ceremony!(send),
            "Settle" => ceremony!(settle),
            _ => {}
        }

        // --- The single-round calls ---------------------------------------------------------------
        //
        // Nothing is held between messages, so a stream would buy nothing.
        macro_rules! unary {
            ($body:expr) => {
                match $body.await {
                    Ok(resp) => grpc::unary(resp),
                    Err(status) => grpc::failed(status),
                }
            };
        }
        let body = req.into_body();
        match method {
            "ContactAdd" => unary!(self.contact_add(body)),
            "ContactRemove" => unary!(self.contact_remove(body)),
            "ContactList" => unary!(self.contact_list(body)),
            "PaymentRequestCreate" => unary!(self.payment_request_create(body)),
            "PaymentRequestList" => unary!(self.payment_request_list(body)),
            "PaymentRequestDecline" => unary!(self.payment_request_decline(body)),
            "GetServerInfo" => unary!(self.get_server_info(body)),
            "RegisterDevice" => unary!(self.register_device(body)),
            "ForgetDevice" => unary!(self.forget_device(body)),
            "DeviceCount" => unary!(self.device_count(body)),
            other => grpc::failed(Status::unimplemented(format!("no such method: {other}"))),
        }
    }

    // -------------------------------------------------------------------------------------------
    // The single-round calls.
    // -------------------------------------------------------------------------------------------

    async fn contact_list(&self, body: Body) -> Result<wp::ContactListResponse, Status> {
        let req: wp::ContactListRequest = grpc::one_message(body).await?;
        check(&req.user_id, &req.signature, req.timestamp_ms, crate::auth::message::OP_CONTACT_LIST)?;
        lock(&self.cosigner).contact_list(req)
    }

    async fn payment_request_list(
        &self,
        body: Body,
    ) -> Result<wp::PaymentRequestListResponse, Status> {
        let req: wp::PaymentRequestListRequest = grpc::one_message(body).await?;
        check(&req.user_id, &req.signature, req.timestamp_ms, crate::auth::message::OP_PAYREQ_LIST)?;
        lock(&self.cosigner).payment_request_list(req)
    }

    async fn get_server_info(&self, body: Body) -> Result<wp::GetServerInfoResponse, Status> {
        let _: wp::GetServerInfoRequest = grpc::one_message(body).await?;
        Ok(self.server_info.clone())
    }

    async fn contact_add(&self, body: Body) -> Result<wp::ContactAddResponse, Status> {
        let req: wp::ContactAddRequest = grpc::one_message(body).await?;
        check(&req.user_id, &req.signature, req.timestamp_ms, crate::auth::message::OP_CONTACT_ADD)?;
        lock(&self.cosigner).contact_add(req)
    }

    async fn contact_remove(&self, body: Body) -> Result<wp::ContactRemoveResponse, Status> {
        let req: wp::ContactRemoveRequest = grpc::one_message(body).await?;
        check(&req.user_id, &req.signature, req.timestamp_ms, crate::auth::message::OP_CONTACT_REMOVE)?;
        lock(&self.cosigner).contact_remove(req)
    }

    async fn payment_request_decline(
        &self,
        body: Body,
    ) -> Result<wp::PaymentRequestDeclineResponse, Status> {
        let req: wp::PaymentRequestDeclineRequest = grpc::one_message(body).await?;
        check(&req.user_id, &req.signature, req.timestamp_ms, crate::auth::message::OP_PAYREQ_DECLINE)?;
        let mut actor = lock(&self.cosigner);
        actor.require_owner(&req.user_id)?;
        actor.decline_intent(&req.id).map_err(Status::invalid_argument)?;
        actor.seal();
        Ok(wp::PaymentRequestDeclineResponse { ok: true })
    }

    /// The deliberate exception: signed by the REQUESTER, not this wallet's owner. The payer's
    /// contact allowlist is what authorizes it, which is why there is no `require_owner` here — and
    /// why one cosigner per process suits it: the requester addresses the payer's endpoint.
    async fn payment_request_create(
        &self,
        body: Body,
    ) -> Result<wp::PaymentRequestCreateResponse, Status> {
        let req: wp::PaymentRequestCreateRequest = grpc::one_message(body).await?;
        check(&req.user_id, &req.signature, req.timestamp_ms, crate::auth::message::OP_PAYREQ_CREATE)?;
        lock(&self.cosigner).payment_request_create(req)
    }

    // --- Devices -------------------------------------------------------------------------------
    //
    // Forwarded to the runtime and not stored here. The cosigner has no push channel of its own and
    // never sees a token twice; `device_count` returns a number because it is not meant to be able
    // to enumerate a tenant's devices.

    async fn register_device(&self, body: Body) -> Result<proto::RegisterDeviceResponse, Status> {
        let req: proto::RegisterDeviceRequest = grpc::one_message(body).await?;
        check(&req.user_id, &req.signature, req.timestamp_ms, crate::auth::message::OP_REGISTER_DEVICE_TOKEN)?;
        lock(&self.cosigner)
            .host
            .register_device(&req.token)
            .map_err(Status::unavailable)?;
        Ok(proto::RegisterDeviceResponse {})
    }

    async fn forget_device(&self, body: Body) -> Result<proto::ForgetDeviceResponse, Status> {
        let req: proto::ForgetDeviceRequest = grpc::one_message(body).await?;
        check(&req.user_id, &req.signature, req.timestamp_ms, crate::auth::message::OP_REGISTER_DEVICE_TOKEN)?;
        lock(&self.cosigner)
            .host
            .forget_device(&req.token)
            .map_err(Status::unavailable)?;
        Ok(proto::ForgetDeviceResponse {})
    }

    async fn device_count(&self, body: Body) -> Result<proto::DeviceCountResponse, Status> {
        let req: proto::DeviceCountRequest = grpc::one_message(body).await?;
        check(&req.user_id, &req.signature, req.timestamp_ms, crate::auth::message::OP_REGISTER_DEVICE_TOKEN)?;
        let devices = lock(&self.cosigner).host.devices().map_err(Status::unavailable)?;
        Ok(proto::DeviceCountResponse { devices })
    }
}

/// Check the caller's auth signature.
fn check(user_id: &[u8], signature: &[u8], timestamp_ms: i64, op: &str) -> Result<(), Status> {
    crate::handlers::helpers::verify_auth(user_id, signature, timestamp_ms, op)
}

/// The cosigner, with a poisoned lock recovered rather than propagated.
///
/// A panic mid-ceremony leaves the wallet's in-memory state as it was — its authority comes from
/// the seal, not from this guard — and taking down every later call because one caller panicked
/// would turn a single failed request into a dead instance.
fn lock(cosigner: &Arc<Mutex<Cosigner>>) -> MutexGuard<'_, Cosigner> {
    cosigner.lock().unwrap_or_else(|e| e.into_inner())
}

// ===============================================================================================
// The ceremonies
// ===============================================================================================

async fn sign(
    cosigner: Arc<Mutex<Cosigner>>,
    duplex: Duplex<SignClientMsg, SignServerMsg>,
) -> Result<(), Status> {
    // --- Round 1: open --------------------------------------------------------------------
    let first = duplex.expect("it opened").await?;
    let session_id = first.session_id.clone();
    let open = match first.body {
        Some(sign_client_msg::Body::Open(o)) => o,
        _ => return Err(Status::invalid_argument("a session must open with SignOpen")),
    };
    // The session is authenticated ONCE, here. Every message after this one rides that assertion —
    // see cosign_session.proto for why there is no per-message approval. This was missing: the
    // check ran at the REST boundary, and deleting that boundary left the four streams open to
    // anyone who could reach the port.
    check(
        &open.user_id,
        &open.signature,
        open.timestamp_ms,
        crate::auth::message::OP_SIGN_STEP1,
    )?;

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

    // The ceremony is OURS, as an ordinary local. The actor never held it, and the lock is released
    // before we wait on the client — a slow client blocks nobody.
    let (ceremony, opened) = lock(&cosigner).sign_open(step1).map_err(Status::internal)?;

    duplex.send(SignServerMsg {
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
    });

    // --- Round 2: the client's share ------------------------------------------------------
    //
    // If the client never sends it, or the stream dies here, `ceremony` drops with this task and
    // the nonce is gone. That is the safe failure: an abandoned round leaves nothing reusable.
    let second = duplex.expect("the share arrived").await?;
    let share = match second.body {
        Some(sign_client_msg::Body::Share(s)) => s,
        _ => return Err(Status::invalid_argument("expected SignShare")),
    };

    let step2 = SignStep2 {
        user_id: open.user_id,
        signature_share: share.signature_share,
        signature: Vec::new(),
        timestamp_ms: open.timestamp_ms,
    };

    let done = lock(&cosigner)
        .sign_finish(ceremony, step2)
        .map_err(Status::internal)?;

    duplex.send(SignServerMsg {
        session_id,
        seq: 2,
        body: Some(sign_server_msg::Body::Complete(SignComplete {
            r_point: done.r_point,
            z_scalar: done.z_scalar,
        })),
    });
    Ok(())
}

/// DKG as one session.
///
/// The unary form needed a `sessions` map keyed by user, with a TTL and an eviction loop, purely to
/// hold round-1 and round-2 material between three requests — and that material is how the key is
/// born. Here the session is a LOCAL: created at open, dropped when the stream ends. There is no
/// map to evict from, no TTL to tune, and an abandoned ceremony leaves nothing behind rather than
/// key material sitting in a map until a sweep notices.
async fn dkg(
    cosigner: Arc<Mutex<Cosigner>>,
    duplex: Duplex<proto::DkgClientMsg, proto::DkgServerMsg>,
) -> Result<(), Status> {
    use crate::handlers::onboarding as ob;
    use crate::handlers::onboarding::OnboardingSession;

    let store = lock(&cosigner).store().clone();

    let first = duplex.expect("it opened").await?;
    let session_id = first.session_id.clone();
    let open = match first.body {
        Some(proto::dkg_client_msg::Body::Open(o)) => o,
        _ => return Err(Status::invalid_argument("a session must open with DkgOpen")),
    };

    // No `check()` here, and it is the one stream that cannot have one: the owner key it would
    // verify against is what this ceremony mints. `DkgOpen` carries `signature` and `timestamp_ms`
    // for shape only. Integrity comes from FROST itself and from the ceremony living on one stream
    // — see `handlers::onboarding`.

    // The ceremony, owned here. Round-1 and round-2 secrets live on this stack and die with the
    // stream.
    let mut sess = OnboardingSession::new(hex::encode(&open.user_id));

    let r1 = ob::dkg_open(
        &mut sess,
        wp::DkgStep1Request {
            user_id: open.user_id.clone(),
            identifier: open.identifier.clone(),
            round1_package: open.round1_package,
        },
    )?;
    duplex.send(proto::DkgServerMsg {
        session_id: session_id.clone(),
        seq: 1,
        body: Some(proto::dkg_server_msg::Body::Round1(proto::DkgRound1Out {
            round1_packages: r1.round1_packages,
        })),
    });

    // --- The wallet's round 2, and the key ------------------------------------------------
    let msg = duplex.expect("round 2").await?;
    let round2 = match msg.body {
        Some(proto::dkg_client_msg::Body::Round2(r)) => r,
        _ => return Err(Status::invalid_argument("expected DkgRound2")),
    };
    let r3 = ob::dkg_finish(
        &mut sess,
        &store,
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

    // Install the key and seal it. No plaintext fallback: if this fails the ceremony fails, rather
    // than leaving a wallet whose key exists only in a reply.
    {
        let mut c = lock(&cosigner);
        c.install_policy(
            mat.group_key,
            &mat.key_package_json,
            &mat.public_key_package_json,
            mat.user_signing_identifier_hex.as_deref(),
            mat.server_dkg_secret_hex,
        )
        .map_err(Status::internal)?;
        c.seal();
    }

    duplex.send(proto::DkgServerMsg {
        session_id,
        seq: 2,
        body: Some(proto::dkg_server_msg::Body::Complete(proto::DkgComplete {
            round2_packages_for_me: r3.round2_packages_for_me,
            group_key,
        })),
    });
    Ok(())
}

/// A send as one session, with the caller submitting.
///
/// The unary form parked the half-built transactions on the actor between "build it" and "submit
/// it", and called the ASP itself for both `SubmitTx` and `FinalizeTx`. Here the session is a local
/// on this handler and the caller makes those two calls: the cosigner hands over what to send and
/// seals only once the ASP has accepted it, so an interrupted send leaves neither a half-signed
/// transaction addressable by the next request nor a recorded spend that never happened.
async fn send(
    cosigner: Arc<Mutex<Cosigner>>,
    duplex: Duplex<proto::SendClientMsg, proto::SendServerMsg>,
) -> Result<(), Status> {
    let first = duplex.expect("it opened").await?;
    let session_id = first.session_id.clone();
    let open = match first.body {
        Some(proto::send_client_msg::Body::Open(o)) => o,
        _ => return Err(Status::invalid_argument("a session must open with SendOpen")),
    };
    // Authenticated ONCE, here — see `sign` above.
    check(
        &open.user_id,
        &open.signature,
        open.timestamp_ms,
        crate::auth::message::OP_SEND_VTXO,
    )?;

    let info = open
        .ark_info
        .map(ark_info_from_proto)
        .ok_or_else(|| Status::invalid_argument("SendOpen carried no ark_info"))?;

    // The caller names its inputs, and the cosigner validates every one against the scriptPubKey it
    // derives from its own owner key before selecting — so naming a VTXO here cannot widen what the
    // wallet owns.
    let (mut session, change_exit_delay, sighashes) = {
        let step1 = crate::types::SendVtxoStep1 {
            user_id: open.user_id.clone(),
            signature: open.signature.clone(),
            timestamp_ms: open.timestamp_ms,
            recipient_ark_address: open.recipient_ark_address.clone(),
            amount: open.amount,
            vtxos: vtxos_from_proto(open.vtxos.clone()),
        };
        lock(&cosigner).send_open(step1, &info).map_err(Status::internal)?
    };

    duplex.send(proto::SendServerMsg {
        session_id: session_id.clone(),
        seq: 1,
        body: Some(proto::send_server_msg::Body::Sighashes(proto::SendSighashes {
            messages_to_sign: sighashes,
            script_path_spend: true,
        })),
    });

    // --- The caller's signatures, then what it must submit --------------------------------
    let signed = match next_body(&duplex, "mid-send").await? {
        proto::send_client_msg::Body::Signed(s) => s,
        _ => return Err(Status::invalid_argument("expected SendSigned")),
    };
    let (ark_tx_b64, checkpoint_txs) = lock(&cosigner)
        .send_prepare(
            &mut session,
            crate::types::SendVtxoStep2 {
                user_id: open.user_id.clone(),
                signature: open.signature.clone(),
                timestamp_ms: open.timestamp_ms,
                signed_messages: signed.signed_messages,
            },
        )
        .map_err(Status::internal)?;

    duplex.send(proto::SendServerMsg {
        session_id: session_id.clone(),
        seq: 2,
        body: Some(proto::send_server_msg::Body::Submit(proto::SendSubmit {
            ark_tx_b64,
            checkpoint_txs,
        })),
    });

    // --- What the ASP returned, turned into the finalize call ------------------------------
    let submitted = match next_body(&duplex, "mid-send").await? {
        proto::send_client_msg::Body::Submitted(s) => s,
        _ => return Err(Status::invalid_argument("expected SendSubmitted")),
    };
    let final_checkpoint_txs = lock(&cosigner)
        .send_finalize(&mut session, &submitted.signed_checkpoint_txs)
        .map_err(Status::internal)?;

    duplex.send(proto::SendServerMsg {
        session_id: session_id.clone(),
        seq: 3,
        body: Some(proto::send_server_msg::Body::Finalize(proto::SendFinalize {
            ark_txid: submitted.ark_txid.clone(),
            final_checkpoint_txs,
        })),
    });

    // --- Accepted. Only now is it ours to record -------------------------------------------
    match next_body(&duplex, "mid-send").await? {
        proto::send_client_msg::Body::Finalized(_) => {}
        _ => return Err(Status::invalid_argument("expected SendFinalized")),
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
        let mut c = lock(&cosigner);
        let submitted = c.send_complete((session, change_exit_delay), submitted.ark_txid);
        let resp = c.apply_send(&req, submitted);
        c.seal();
        resp
    };

    duplex.send(proto::SendServerMsg {
        session_id,
        seq: 4,
        body: Some(proto::send_server_msg::Body::Complete(proto::SendComplete {
            ark_txid: resp.ark_txid,
            change: None,
        })),
    });
    Ok(())
}

/// Settling, with the caller driving the ASP round.
///
/// The cosigner answers each relayed event with what to send the ASP next and never opens a socket
/// of its own. `ark_info` arrives from the caller for the same reason: it is the one talking to the
/// ASP. See `settle.rs` for why that cannot redirect funds.
async fn settle(
    cosigner: Arc<Mutex<Cosigner>>,
    duplex: Duplex<proto::SettleClientMsg, proto::SettleServerMsg>,
) -> Result<(), Status> {
    use crate::handlers::settle::SettleStep;

    let first = duplex.expect("it opened").await?;
    let session_id = first.session_id.clone();
    let open = match first.body {
        Some(proto::settle_client_msg::Body::Open(o)) => o,
        _ => return Err(Status::invalid_argument("a session must open with SettleOpen")),
    };
    // Authenticated ONCE, here — see `sign` above.
    check(
        &open.user_id,
        &open.signature,
        open.timestamp_ms,
        crate::auth::message::OP_SETTLE,
    )?;

    let info = open
        .ark_info
        .map(ark_info_from_proto)
        .ok_or_else(|| Status::invalid_argument("SettleOpen carried no ark_info"))?;
    let boarding_utxo = open.boarding_utxo.map(|u| (u.txid, u.vout, u.amount_sats));
    let vtxos = vtxos_from_proto(open.vtxos);

    let sighashes = lock(&cosigner)
        .settle_open(boarding_utxo, vtxos, info)
        .map_err(Status::internal)?;

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
            SettleStep::Idle => Some(proto::settle_server_msg::Body::Idle(proto::SettleIdle {})),
            SettleStep::Complete(sub) => {
                let complete = proto::SettleComplete {
                    commitment_txid: sub.commitment_txid.clone(),
                    vtxo_txid: sub.vtxo_txid.clone(),
                    vtxo_vout: sub.vtxo_vout,
                    amount_sats: sub.amount_sats,
                    exit_delay: sub.exit_delay,
                };
                {
                    let mut c = lock(&cosigner);
                    c.apply_boarding_settle(sub);
                    c.seal();
                }
                duplex.send(proto::SettleServerMsg {
                    session_id,
                    seq,
                    body: Some(proto::settle_server_msg::Body::Complete(complete)),
                });
                return Ok(());
            }
        };

        duplex.send(proto::SettleServerMsg {
            session_id: session_id.clone(),
            seq,
            body,
        });
        seq += 1;

        let msg = duplex.expect("the next settle step").await?;
        let body = msg
            .body
            .ok_or_else(|| Status::invalid_argument("empty SettleClientMsg"))?;

        // Scoped tightly: the guard must not still be held when the loop comes back around to
        // `recv().await`, or a nested `Sign` session — which the caller opens on its own connection
        // while this one is parked — would find the cosigner locked by a stream that is waiting on
        // that very sign to finish.
        let mut c = lock(&cosigner);
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
                return Err(Status::invalid_argument("the session is already open"))
            }
        };
        drop(c);
    }
}

async fn next_body(
    duplex: &Duplex<proto::SendClientMsg, proto::SendServerMsg>,
    what: &str,
) -> Result<proto::send_client_msg::Body, Status> {
    duplex
        .expect(what)
        .await?
        .body
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

fn vtxos_from_proto(v: Vec<proto::VtxoInput>) -> Vec<crate::types::VtxoInput> {
    v.into_iter()
        .map(|i| crate::types::VtxoInput {
            txid: i.txid,
            vout: i.vout,
            amount_sats: i.amount_sats,
            exit_delay: i.exit_delay,
        })
        .collect()
}

fn ark_info_from_proto(i: wp::ArkInfo) -> ark::client::types::ArkInfo {
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
        AspCall::ForfeitTxs { signed_txs, signed_commitment_b64 } => {
            Call::ForfeitTxs(proto::ForfeitTxs {
                signed_forfeit_txs: signed_txs,
                signed_commitment_tx: signed_commitment_b64,
            })
        }
    };
    proto::AspSubmit { call: Some(call) }
}
