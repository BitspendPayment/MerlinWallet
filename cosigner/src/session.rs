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
        // Nothing is served without the runtime's word that a passkey approved this request.
        //
        // That is the whole of authentication now. Every request used to carry a Schnorr signature
        // by the wallet's share key, checked here in the guest; enclave-runtime gates every request
        // on a WebAuthn assertion bound to its exact method and path before it reaches us, and stamps
        // the tenant it resolved onto this header — having stripped any copy a client sent, so it
        // cannot be supplied from outside. A passkey-gated wallet could not have produced the old
        // signature anyway: it holds no plaintext share to sign with.
        //
        // It is checked first, before the path, so an unauthenticated caller learns nothing about the
        // method surface. And it fails CLOSED: behind a runtime with no gate configured the header is
        // never set, so this cosigner refuses everything rather than serving keys to whoever connects.
        if let Err(status) = tenant_of(&req) {
            return grpc::failed(status);
        }

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
        lock(&self.cosigner).contact_list(req)
    }

    async fn payment_request_list(
        &self,
        body: Body,
    ) -> Result<wp::PaymentRequestListResponse, Status> {
        let req: wp::PaymentRequestListRequest = grpc::one_message(body).await?;
        lock(&self.cosigner).payment_request_list(req)
    }

    async fn get_server_info(&self, body: Body) -> Result<wp::GetServerInfoResponse, Status> {
        let _: wp::GetServerInfoRequest = grpc::one_message(body).await?;
        Ok(self.server_info.clone())
    }

    async fn contact_add(&self, body: Body) -> Result<wp::ContactAddResponse, Status> {
        let req: wp::ContactAddRequest = grpc::one_message(body).await?;
        lock(&self.cosigner).contact_add(req)
    }

    async fn contact_remove(&self, body: Body) -> Result<wp::ContactRemoveResponse, Status> {
        let req: wp::ContactRemoveRequest = grpc::one_message(body).await?;
        lock(&self.cosigner).contact_remove(req)
    }

    async fn payment_request_decline(
        &self,
        body: Body,
    ) -> Result<wp::PaymentRequestDeclineResponse, Status> {
        let req: wp::PaymentRequestDeclineRequest = grpc::one_message(body).await?;
        let mut actor = lock(&self.cosigner);
        actor.decline_intent(&req.id).map_err(Status::invalid_argument)?;
        actor.seal();
        Ok(wp::PaymentRequestDeclineResponse { ok: true })
    }

    /// A request to be paid, delivered by this wallet's owner but written by somebody else.
    ///
    /// The runtime authenticated the caller, who is the PAYER — the request travelled out of band
    /// and the payer's app brought it here. So what is checked is not who is calling but who wrote
    /// it: `authorship` carries a group-key signature, and the payer's allowlist decides whether that
    /// author may bill this wallet. See `Cosigner::payment_request_create`.
    async fn payment_request_create(
        &self,
        body: Body,
    ) -> Result<wp::PaymentRequestCreateResponse, Status> {
        let req: wp::PaymentRequestCreateRequest = grpc::one_message(body).await?;
        lock(&self.cosigner).payment_request_create(req)
    }

    // --- Devices -------------------------------------------------------------------------------
    //
    // Forwarded to the runtime and not stored here. The cosigner has no push channel of its own and
    // never sees a token twice; `device_count` returns a number because it is not meant to be able
    // to enumerate a tenant's devices.

    async fn register_device(&self, body: Body) -> Result<proto::RegisterDeviceResponse, Status> {
        let req: proto::RegisterDeviceRequest = grpc::one_message(body).await?;
        lock(&self.cosigner)
            .host
            .register_device(&req.token)
            .map_err(Status::unavailable)?;
        Ok(proto::RegisterDeviceResponse {})
    }

    async fn forget_device(&self, body: Body) -> Result<proto::ForgetDeviceResponse, Status> {
        let req: proto::ForgetDeviceRequest = grpc::one_message(body).await?;
        lock(&self.cosigner)
            .host
            .forget_device(&req.token)
            .map_err(Status::unavailable)?;
        Ok(proto::ForgetDeviceResponse {})
    }

    async fn device_count(&self, body: Body) -> Result<proto::DeviceCountResponse, Status> {
        let _: proto::DeviceCountRequest = grpc::one_message(body).await?;
        let devices = lock(&self.cosigner).host.devices().map_err(Status::unavailable)?;
        Ok(proto::DeviceCountResponse { devices })
    }
}

/// The header the runtime puts the resolved tenant on.
pub const TENANT_HEADER: &str = "x-enclave-tenant";

/// The tenant the runtime authenticated this request as, or why there is none.
///
/// Sixteen bytes as lowercase hex, exactly as `apply_tenant` writes it. A malformed value is refused
/// like a missing one: the runtime never produces it, so it did not come from the runtime.
fn tenant_of(req: &Request<Body>) -> Result<String, Status> {
    let value = req
        .headers()
        .get(TENANT_HEADER)
        .ok_or_else(|| Status::unauthenticated("no tenant: this request was not approved by the runtime"))?
        .to_str()
        .map_err(|_| Status::unauthenticated("the tenant header is not text"))?;
    let well_formed = value.len() == 32 && value.bytes().all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f'));
    if !well_formed {
        return Err(Status::unauthenticated("the tenant header is malformed"));
    }
    Ok(value.to_string())
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
    // Authenticated before it got here: the runtime approved this stream with a passkey assertion,
    // once, at open, and `route` refuses anything that arrives without the tenant it resolved.

    let step1 = SignStep1 {
        hiding_commitment: open.hiding_commitment,
        binding_commitment: open.binding_commitment,
        message_to_sign: open.message_to_sign,
        full_transaction: open.full_transaction,
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
        signature_share: share.signature_share,
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

    let first = duplex.expect("it opened").await?;
    let session_id = first.session_id.clone();
    let open = match first.body {
        Some(proto::dkg_client_msg::Body::Open(o)) => o,
        _ => return Err(Status::invalid_argument("a session must open with DkgOpen")),
    };

    // Authenticated for the first time. There never was a check here and there could not be one:
    // the owner key a body signature would verify against is what this ceremony mints. The runtime's
    // passkey is not that key, so it can approve the ceremony that creates it.

    // One wallet per tenant, and never silently a second. Checked before any round-1 material
    // exists, so a refused ceremony leaves nothing behind.
    lock(&cosigner).refuse_if_onboarded()?;

    // The ceremony, owned here. Round-1 and round-2 secrets live on this stack and die with the
    // stream.
    let mut sess = OnboardingSession::new();

    let r1 = ob::dkg_open(
        &mut sess,
        wp::DkgStep1Request {
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
        wp::DkgStep3Request {
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

    // After the key, so a refused enrolment cannot cost the wallet its ceremony.
    let device_enrolled = enrol_device(&cosigner, &open.device_token);

    duplex.send(proto::DkgServerMsg {
        session_id,
        seq: 2,
        body: Some(proto::dkg_server_msg::Body::Complete(proto::DkgComplete {
            round2_packages_for_me: r3.round2_packages_for_me,
            group_key,
            device_enrolled,
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
    // Authenticated by the runtime at open — see `sign` above.

    let info = open
        .ark_info
        .map(ark_info_from_proto)
        .ok_or_else(|| Status::invalid_argument("SendOpen carried no ark_info"))?;

    // The caller names its inputs, and the cosigner validates every one against the scriptPubKey it
    // derives from its own owner key before selecting — so naming a VTXO here cannot widen what the
    // wallet owns.
    let (mut session, change_exit_delay, sighashes) = {
        let step1 = crate::types::SendVtxoStep1 {
            recipient_ark_address: open.recipient_ark_address.clone(),
            amount: open.amount,
            vtxos: vtxos_from_proto(open.vtxos.clone()),
        };
        lock(&cosigner).send_open(step1, &info).map_err(Status::internal)?
    };

    // Round one of the FROST signature, on this stream. It used to be a nested `Sign` stream per
    // sighash, which deadlocks inside enclave-runtime — see `Cosigner::sign_in_band_begin`.
    let (round, commitments) = lock(&cosigner)
        .sign_in_band_begin(&sighashes)
        .map_err(Status::internal)?;

    duplex.send(proto::SendServerMsg {
        session_id: session_id.clone(),
        seq: 1,
        body: Some(proto::send_server_msg::Body::Sighashes(sighashes_msg(
            sighashes,
            commitments,
        ))),
    });

    // --- The wallet's half of the round, then what it must submit --------------------------
    let signed = match next_body(&duplex, "mid-send").await? {
        proto::send_client_msg::Body::Signed(s) => s,
        _ => return Err(Status::invalid_argument("expected SendSigned")),
    };
    // A bad share is the caller's fault, and is reported as such rather than as ours.
    let signatures = lock(&cosigner)
        .sign_in_band_finish(round, wallet_halves(signed.rounds))
        .map_err(Status::invalid_argument)?;
    let (ark_tx_b64, checkpoint_txs) = lock(&cosigner)
        .send_prepare(
            &mut session,
            crate::types::SendVtxoStep2 {
                signed_messages: signatures,
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
        session_id: session_id.clone(),
        seq: 4,
        body: Some(proto::send_server_msg::Body::Complete(proto::SendComplete {
            ark_txid: resp.ark_txid,
            change: None,
        })),
    });

    // --- Optionally, seal a delegate over what the wallet holds now -------------------------
    //
    // On this stream so it rides the approval — and the passkey seed — the send already had. A
    // caller that closes instead has simply not asked for it.
    if let Some(msg) = duplex.recv().await {
        let mut seal = match msg.body {
            Some(proto::send_client_msg::Body::Seal(seal)) => seal,
            _ => return Err(Status::invalid_argument("after SendComplete only a seal may follow")),
        };
        let device_token = std::mem::take(&mut seal.device_token);
        let seal_round = seal_open(&cosigner, seal)?;
        let mut sighashes =
            sighashes_msg(seal_round.delegate_sighashes, seal_round.commitments);
        sighashes.exit_messages = seal_round.exit_sighashes;
        duplex.send(proto::SendServerMsg {
            session_id: session_id.clone(),
            seq: 5,
            body: Some(proto::send_server_msg::Body::Sighashes(sighashes)),
        });
        let signed = match next_body(&duplex, "the delegate's signatures").await? {
            proto::send_client_msg::Body::Signed(s) => s,
            _ => return Err(Status::invalid_argument("expected the delegate's signatures")),
        };
        let sealed = seal_finish(
            &cosigner,
            seal_round.round,
            seal_round.exits,
            signed.rounds,
            &device_token,
        )?;
        duplex.send(proto::SendServerMsg {
            session_id,
            seq: 6,
            body: Some(proto::send_server_msg::Body::Sealed(sealed)),
        });
    }
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
    // Authenticated by the runtime at open — see `sign` above.

    let info = open
        .ark_info
        .map(ark_info_from_proto)
        .ok_or_else(|| Status::invalid_argument("SettleOpen carried no ark_info"))?;
    if open.seal_only {
        // Nothing to refresh now; seal a delegate over the set and close.
        let seal = proto::SealDelegate {
            vtxos: open.vtxos,
            ark_info: Some(info_to_proto(&info)),
            device_token: open.device_token,
            exit_script_pubkey: open.exit_script_pubkey,
        };
        return settle_seal(&cosigner, &duplex, seal, &session_id, 1).await;
    }
    let boarding_utxo = open.boarding_utxo.map(|u| (u.txid, u.vout, u.amount_sats));
    let vtxos = vtxos_from_proto(open.vtxos);

    let sighashes = lock(&cosigner)
        .settle_open(boarding_utxo, vtxos, info)
        .map_err(Status::internal)?;

    let mut seq = 1u64;
    let mut step = SettleStep::Sighashes(sighashes);

    // The FROST round that is waiting for the wallet's half. A settle signs twice — the intent
    // proof, and for a boarding settle the commitment transaction later — so this is set each time
    // sighashes go out and taken when the matching `Signed` comes back. Holding it here rather than
    // on the cosigner is what keeps the nonces on this stream's stack, where a dropped stream takes
    // them with it.
    let mut pending_round: Option<crate::cosigner::InBandRound> = None;

    loop {
        // Say what we need, then read what the caller did about it.
        let body = match step {
            SettleStep::Sighashes(messages_to_sign) => {
                // Round one, on this stream — see `Cosigner::sign_in_band_begin` for why it cannot
                // be a nested `Sign` any more.
                let (round, commitments) = lock(&cosigner)
                    .sign_in_band_begin(&messages_to_sign)
                    .map_err(Status::internal)?;
                pending_round = Some(round);
                Some(proto::settle_server_msg::Body::Sighashes(settle_sighashes_msg(
                    messages_to_sign,
                    commitments,
                )))
            }
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
                    session_id: session_id.clone(),
                    seq,
                    body: Some(proto::settle_server_msg::Body::Complete(complete)),
                });
                // Optionally, seal a delegate over what the wallet holds now — on this stream, so it
                // rides the approval and the passkey seed the settle already had.
                if let Some(msg) = duplex.recv().await {
                    let seal = match msg.body {
                        Some(proto::settle_client_msg::Body::Seal(seal)) => seal,
                        _ => {
                            return Err(Status::invalid_argument(
                                "after SettleComplete only a seal may follow",
                            ))
                        }
                    };
                    settle_seal(&cosigner, &duplex, seal, &session_id, seq + 1).await?;
                }
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

        // Scoped to this iteration, and released before the loop comes back around to
        // `recv().await`. That used to matter because the caller opened a nested `Sign` on its own
        // connection while this stream was parked; signing is in-band now, so nothing else takes
        // this lock mid-settle — but holding a guard across an await is still the wrong habit.
        let mut c = lock(&cosigner);
        step = match body {
            proto::settle_client_msg::Body::Signed(s) => {
                let round = pending_round.take().ok_or_else(|| {
                    Status::invalid_argument("signatures arrived with no round waiting for them")
                })?;
                let signatures = c
                    .sign_in_band_finish(round, wallet_halves(s.rounds))
                    .map_err(Status::invalid_argument)?;
                c.settle_signed(signatures).map_err(Status::internal)?
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
            proto::settle_client_msg::Body::Seal(_) => {
                return Err(Status::invalid_argument("a seal follows SettleComplete, not the round"))
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

/// The wallet's half of an in-band round, off the wire.
fn wallet_halves(rounds: Vec<proto::WalletRound>) -> Vec<crate::cosigner::WalletHalf> {
    rounds
        .into_iter()
        .map(|r| crate::cosigner::WalletHalf {
            hiding: r.hiding,
            binding: r.binding,
            share: r.share,
        })
        .collect()
}

/// The identifier every commitment in a batch shares — they are all the cosigner's.
fn cosigner_identifier(commitments: &[crate::types::Commitment]) -> String {
    commitments
        .first()
        .map(|c| c.identifier_hex.clone())
        .unwrap_or_default()
}

fn wire_commitments(commitments: Vec<crate::types::Commitment>) -> Vec<proto::Commitment> {
    commitments
        .into_iter()
        .map(|c| proto::Commitment {
            hiding: c.hiding,
            binding: c.binding,
        })
        .collect()
}

/// A send's sighashes with the cosigner's half of round one. Always script-path: the cosigner signs
/// untweaked, and in-band signing cannot compensate a tweak — see `Cosigner::sign_in_band_begin`.
fn sighashes_msg(
    messages_to_sign: Vec<Vec<u8>>,
    commitments: Vec<crate::types::Commitment>,
) -> proto::SendSighashes {
    proto::SendSighashes {
        messages_to_sign,
        script_path_spend: true,
        cosigner_identifier: cosigner_identifier(&commitments),
        cosigner_commitments: wire_commitments(commitments),
        exit_messages: Vec::new(),
    }
}

fn settle_sighashes_msg(
    messages_to_sign: Vec<Vec<u8>>,
    commitments: Vec<crate::types::Commitment>,
) -> proto::SettleSighashes {
    proto::SettleSighashes {
        messages_to_sign,
        script_path_spend: true,
        cosigner_identifier: cosigner_identifier(&commitments),
        cosigner_commitments: wire_commitments(commitments),
        exit_messages: Vec::new(),
    }
}

fn vtxos_from_proto(v: Vec<proto::VtxoInput>) -> Vec<crate::types::VtxoInput> {
    v.into_iter()
        .map(|i| crate::types::VtxoInput {
            txid: i.txid,
            vout: i.vout,
            amount_sats: i.amount_sats,
            exit_delay: i.exit_delay,
            expires_at: i.expires_at,
        })
        .collect()
}

/// Build the delegate over the set the caller reports, and open the FROST round that signs it.
/// What a seal's round is signing: the delegate's messages, then the exits'.
struct SealRound {
    round: crate::cosigner::InBandRound,
    delegate_sighashes: Vec<Vec<u8>>,
    exit_sighashes: Vec<Vec<u8>>,
    exits: crate::handlers::delegate::PendingExits,
    commitments: Vec<crate::types::Commitment>,
}

fn seal_open(
    cosigner: &Arc<Mutex<Cosigner>>,
    seal: proto::SealDelegate,
) -> Result<SealRound, Status> {
    let info = seal
        .ark_info
        .map(ark_info_from_proto)
        .ok_or_else(|| Status::invalid_argument("SealDelegate carried no ark_info"))?;
    let mut c = lock(cosigner);
    let (delegate_sighashes, exits) = c
        .seal_delegate_open(vtxos_from_proto(seal.vtxos), &info, &seal.exit_script_pubkey)
        .map_err(Status::failed_precondition)?;
    // One round over both halves, in that order: the wallet answers them as one list, and the
    // signatures come back the same way.
    let exit_sighashes = exits.sighashes();
    let all: Vec<Vec<u8>> = delegate_sighashes
        .iter()
        .chain(exit_sighashes.iter())
        .cloned()
        .collect();
    let (round, commitments) = c.sign_in_band_begin(&all).map_err(Status::internal)?;
    Ok(SealRound { round, delegate_sighashes, exit_sighashes, exits, commitments })
}

/// Finish the round, seal the delegate, and arm the watch — and enrol [device_token] for the wakes
/// that watch sends, when the seal carried one.
fn seal_finish(
    cosigner: &Arc<Mutex<Cosigner>>,
    round: crate::cosigner::InBandRound,
    exits: crate::handlers::delegate::PendingExits,
    rounds: Vec<proto::WalletRound>,
    device_token: &str,
) -> Result<proto::DelegateSealed, Status> {
    let device_enrolled = enrol_device(cosigner, device_token);
    let mut c = lock(cosigner);
    // A bad share is the caller's fault, and is reported as such.
    let signatures = c
        .sign_in_band_finish(round, wallet_halves(rounds))
        .map_err(Status::invalid_argument)?;
    let sealed = c
        .seal_delegate_finish(signatures, exits)
        .map_err(Status::internal)?;
    c.seal();
    Ok(proto::DelegateSealed {
        valid_at_secs: sealed.valid_at,
        margin_secs: sealed.margin,
        covered: sealed.covered,
        device_enrolled,
        exit_txs: sealed
            .exits
            .into_iter()
            .map(|e| proto::ExitTx {
                outpoint: e.outpoint,
                raw_tx: e.raw_tx,
                sequence: e.sequence,
                amount_sats: e.amount_sats,
            })
            .collect(),
    })
}

/// Enrol a device token carried in-band, if there is one. Whether it was, rather than an error: the
/// operation it rode on is what the caller asked for, and must not fail because a wake could not be
/// arranged — the wallet sends the token again next time.
fn enrol_device(cosigner: &Arc<Mutex<Cosigner>>, token: &str) -> bool {
    if token.is_empty() {
        return false;
    }
    lock(cosigner).host.register_device(token).is_ok()
}

/// The seal exchange on a `Settle` stream: sighashes out, signatures in, sealed out.
async fn settle_seal(
    cosigner: &Arc<Mutex<Cosigner>>,
    duplex: &Duplex<proto::SettleClientMsg, proto::SettleServerMsg>,
    mut seal: proto::SealDelegate,
    session_id: &str,
    seq: u64,
) -> Result<(), Status> {
    let device_token = std::mem::take(&mut seal.device_token);
    let seal_round = seal_open(cosigner, seal)?;
    let mut sighashes = settle_sighashes_msg(seal_round.delegate_sighashes, seal_round.commitments);
    sighashes.exit_messages = seal_round.exit_sighashes;
    duplex.send(proto::SettleServerMsg {
        session_id: session_id.to_string(),
        seq,
        body: Some(proto::settle_server_msg::Body::Sighashes(sighashes)),
    });
    let signed = match duplex.expect("the delegate's signatures").await?.body {
        Some(proto::settle_client_msg::Body::Signed(s)) => s,
        _ => return Err(Status::invalid_argument("expected the delegate's signatures")),
    };
    let sealed = seal_finish(
        cosigner,
        seal_round.round,
        seal_round.exits,
        signed.rounds,
        &device_token,
    )?;
    duplex.send(proto::SettleServerMsg {
        session_id: session_id.to_string(),
        seq: seq + 1,
        body: Some(proto::settle_server_msg::Body::Sealed(sealed)),
    });
    Ok(())
}

fn info_to_proto(i: &ark::client::types::ArkInfo) -> wp::ArkInfo {
    wp::ArkInfo {
        signer_pubkey: i.signer_pubkey.clone(),
        forfeit_pubkey: i.forfeit_pubkey.clone(),
        forfeit_address: i.forfeit_address.clone(),
        checkpoint_tapscript: i.checkpoint_tapscript.clone(),
        network: i.network.clone(),
        session_duration: i.session_duration,
        unilateral_exit_delay: i.unilateral_exit_delay,
        boarding_exit_delay: i.boarding_exit_delay,
        vtxo_min_amount: i.vtxo_min_amount,
        dust: i.dust,
    }
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
