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
use crate::handlers::recover::dealt_share_for;
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
    /// fifteen names — clearer than a code generator, and the only part of tonic still in use once
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
            "Escrow" => ceremony!(escrow),
            "PairService" => ceremony!(pair_service),
            "EscrowReclaim" => ceremony!(escrow_reclaim),
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
            "GetServerInfo" => unary!(self.get_server_info(body)),
            "RegisterDevice" => unary!(self.register_device(body)),
            "ForgetDevice" => unary!(self.forget_device(body)),
            "DeviceCount" => unary!(self.device_count(body)),
            "Recover" => unary!(self.recover(body)),
            "EscrowList" => unary!(self.escrow_list(body)),
            "EscrowOpenSession" => unary!(self.escrow_open_session(body)),
            "PairServiceConfirm" => unary!(self.pair_service_confirm(body)),
            other => grpc::failed(Status::unimplemented(format!("no such method: {other}"))),
        }
    }

    // -------------------------------------------------------------------------------------------
    // The single-round calls.
    // -------------------------------------------------------------------------------------------

    async fn get_server_info(&self, body: Body) -> Result<wp::GetServerInfoResponse, Status> {
        let _: wp::GetServerInfoRequest = grpc::one_message(body).await?;
        Ok(self.server_info.clone())
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

    /// See [`crate::handlers::recover`]. Reads the seal; installs nothing.
    async fn recover(&self, body: Body) -> Result<proto::RecoverResponse, Status> {
        let req: proto::RecoverRequest = grpc::one_message(body).await?;
        crate::handlers::recover::recover(&lock(&self.cosigner), req)
    }

    /// Mark a pairing usable: the service has both halves and its share checks out.
    ///
    /// The cosigner cannot establish this for itself — it never sees the wallet's half, and asking
    /// the service would mean trusting an answer it has no way to check. What it can do is refuse
    /// to treat a pairing as usable until the party that *would* know says so, and refuse a
    /// confirmation that names a different attempt than the one it sealed.
    async fn pair_service_confirm(
        &self,
        body: Body,
    ) -> Result<proto::PairServiceConfirmResponse, Status> {
        let req: proto::PairServiceConfirmRequest = grpc::one_message(body).await?;
        let mut c = lock(&self.cosigner);
        c.confirm_escrow_pairing(&req.escrow_key, &hex::encode(&req.attempt_id))
            .map_err(Status::failed_precondition)?;
        c.seal();
        Ok(proto::PairServiceConfirmResponse {})
    }

    /// Commit an escrow to a deal: what the paired service may take, and until when.
    async fn escrow_open_session(
        &self,
        body: Body,
    ) -> Result<proto::EscrowOpenSessionResponse, Status> {
        let req: proto::EscrowOpenSessionRequest = grpc::one_message(body).await?;
        let now = crate::handlers::helpers::now_secs();
        let session = deal_of(&req, now)?;
        let description = session.policy.describe();
        let deadline = session.deadline;

        let mut c = lock(&self.cosigner);
        c.open_escrow_session(&req.escrow_key, session, now)
            .map_err(Status::failed_precondition)?;
        c.seal();
        // Nothing is scheduled for the deadline, and nothing needs to be. A deadline is a fact
        // about the clock that every decision reads out of the seal — `may_release` and
        // `may_reclaim` reach the same answer whether or not anything ran when it passed. What
        // used to be here was a task that woke the owner, and it bought a notification at the cost
        // of a scheduler; the owner learns the same thing from `EscrowList` the next time they
        // look. See `crate::escrow_session`.
        Ok(proto::EscrowOpenSessionResponse {
            policy_description: description,
            deadline_secs: deadline,
        })
    }

    /// The escrow keys this wallet holds — public projection only, so a device that keeps nothing
    /// can ask what exists instead of remembering.
    async fn escrow_list(&self, body: Body) -> Result<proto::EscrowListResponse, Status> {
        let _: proto::EscrowListRequest = grpc::one_message(body).await?;
        // One reading of the clock for the whole listing, so two escrows are never described as of
        // two different moments.
        let now = crate::handlers::helpers::now_secs();
        let c = lock(&self.cosigner);
        Ok(proto::EscrowListResponse {
            escrows: c.escrows().iter().map(|e| escrow_summary(e, now)).collect(),
        })
    }
}

/// One escrow as a caller may see it: the public projection, as of [now]. What `EscrowList`
/// returns, and what `Recover` hands a new device so it can rebuild its escrows the way it
/// rebuilt the wallet.
pub(crate) fn escrow_summary(e: &crate::types::EscrowRecord, now: i64) -> proto::EscrowSummary {
    proto::EscrowSummary {

        escrow_key: e.escrow_key.clone(),
        wallet_identifier: hex::decode(&e.wallet_identifier_hex).unwrap_or_default(),
        public_key_package_json: e.public_key_package_json.clone(),
        created_at: e.created_at,
        service_identifier: e
            .pairing
            .as_ref()
            .map(|p| p.service_identifier_hex.clone())
            .unwrap_or_default(),
        service_ready: e
            .pairing
            .as_ref()
            .is_some_and(|p| p.state() == crate::types::PairingState::Ready),
        // Reported apart as well as together: they arrive by different routes, at
        // different moments, and a caller waiting on one wants to know which.
        service_confirmed: e
            .pairing
            .as_ref()
            .is_some_and(|p| p.service_confirmed),
        wallet_confirmed: e
            .pairing
            .as_ref()
            .is_some_and(|p| p.wallet_confirmed),
        session: e.session.as_ref().map(|s| proto::EscrowSessionSummary {
            // Whether it still holds the escrow: a spent deal lets the next one be struck.
            open: s.holds_the_escrow(now),
            deadline_secs: s.deadline,
            opened_at: s.opened_at,
            released_sats: s.released_sats,
            policy_description: s.policy.describe(),
        }),
        context: hex::decode(&e.context_hex).unwrap_or_default(),
        reclaim_opened: e.reclaim_opened_at.is_some(),
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

/// One signature, as one in-band round.
///
/// The wallet used to commit first, in `SignOpen`. It cannot: its nonce is hedged with its share,
/// and it holds no share until this stream's first answer brings the half the cosigner dealt it.
/// So this is the round `Send` and `Settle` already run — the cosigner commits first, the wallet
/// answers with its commitments and its share together — over a single message.
///
/// Script-path only, like every in-band round: the cosigner signs untweaked and `aggregate` checks
/// each share, so a key-path share could never have aggregated here. It is refused by name rather
/// than left to fail as a bad share.
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

    if !open.script_path_spend {
        return Err(Status::invalid_argument(
            "Sign is script-path only: the cosigner signs untweaked, so a key-path share cannot \
             aggregate",
        ));
    }

    // NOTHING ABOUT THE MESSAGE IS CHECKED HERE. The contract gate that once stood between an
    // authorized caller and a signature over arbitrary bytes went with the contract layer; the
    // policy IR is what has to take its place before this is exposed for real signing.
    // `full_transaction` is what that policy will read, and is why it still travels.

    // The wallet's half of its own share, before any nonce exists: a caller that is not this
    // wallet is refused with nothing to abandon.
    let dealt = dealt_share_for(&lock(&cosigner), &open.identifier)?;

    // The round is OURS, as an ordinary local. The lock is released before we wait on the client —
    // a slow client blocks nobody.
    let messages = vec![open.message_to_sign.clone()];
    let (round, commitments) = lock(&cosigner)
        .sign_in_band_begin(&messages)
        .map_err(Status::internal)?;

    tracing::info!("Sign: returned the dealt share to the wallet's own identifier");
    duplex.send(SignServerMsg {
        session_id: session_id.clone(),
        seq: 1,
        body: Some(sign_server_msg::Body::Commitments(SignCommitments {
            commitments: commitments
                .into_iter()
                .map(|c| (c.identifier_hex, Commitment { hiding: c.hiding, binding: c.binding }))
                .collect(),
            message_to_sign: open.message_to_sign,
            wallet_dealt_share: dealt,
        })),
    });

    // --- Round 2: the wallet's commitments and share ----------------------------------------
    //
    // If the client never sends it, or the stream dies here, `round` drops with this task and the
    // nonce is gone. That is the safe failure: an abandoned round leaves nothing reusable.
    let second = duplex.expect("the share arrived").await?;
    let share = match second.body {
        Some(sign_client_msg::Body::Share(s)) => s,
        _ => return Err(Status::invalid_argument("expected SignShare")),
    };

    // A bad share is the caller's fault, and is reported as such rather than as ours.
    let signature = lock(&cosigner)
        .sign_in_band_finish(
            round,
            vec![crate::cosigner::WalletHalf {
                hiding: share.hiding_commitment,
                binding: share.binding_commitment,
                share: share.signature_share,
            }],
        )
        .map_err(Status::invalid_argument)?
        .pop()
        .ok_or_else(|| Status::internal("the round produced no signature"))?;
    if signature.len() != 64 {
        return Err(Status::internal("the round produced a signature that is not 64 bytes"));
    }

    // BIP-340: `R.x ‖ z`, and `aggregate` normalizes R to even Y — so the compressed point the
    // wallet verifies against is that x under an even prefix.
    let mut r_point = vec![0x02];
    r_point.extend_from_slice(&signature[..32]);
    duplex.send(SignServerMsg {
        session_id,
        seq: 2,
        body: Some(sign_server_msg::Body::Complete(SignComplete {
            r_point,
            z_scalar: signature[32..].to_vec(),
        })),
    });
    Ok(())
}

/// The deal an [`EscrowOpenSessionRequest`](proto::EscrowOpenSessionRequest) asks for, as of `now`
/// — asked on its own or riding a send that tops the escrow up.
fn deal_of(
    req: &proto::EscrowOpenSessionRequest,
    now: i64,
) -> Result<crate::escrow_session::EscrowSession, Status> {
    // An unparseable policy is `never`, not `always`: a deal nobody can take from is a bad day,
    // and one anybody can take from is a lost escrow.
    let policy: crate::policy::Policy = serde_json::from_str(&req.policy_json)
        .map_err(|e| Status::invalid_argument(format!("that is not a policy: {e}")))?;
    crate::escrow_session::EscrowSession::open(policy, now, req.deadline_secs)
        .map_err(Status::invalid_argument)
}

/// DKG as one session.
///
/// The unary form needed a `sessions` map keyed by user, with a TTL and an eviction loop, purely to
/// hold round-1 and round-2 material between three requests — and that material is how the key is
/// born. Here the session is a LOCAL: created at open, dropped when the stream ends. There is no
/// map to evict from, no TTL to tune, and an abandoned ceremony leaves nothing behind rather than
/// key material sitting in a map until a sweep notices.
/// Minting an escrow key: one reshare, two exchanges, nothing parked.
///
/// The same shape as [`dkg`] and for the same reason — the round-1 and round-2 secrets are what the
/// key is born from, so they live on this frame and die with it. What differs is that both parties
/// already have keys: the reshare is dealt under the identifiers they hold in the wallet key, and
/// neither side's wallet share changes. See [`crate::handlers::escrow`].
///
/// When the open names a service, the stream goes on to pair it into the new escrow — the
/// [`pair_service`] ceremony without its first round, and with the wallet's confirmation on this
/// stream — so an escrow is set up for a service on one approval.
async fn escrow(
    cosigner: Arc<Mutex<Cosigner>>,
    duplex: Duplex<proto::EscrowClientMsg, proto::EscrowServerMsg>,
) -> Result<(), Status> {
    use crate::handlers::escrow as esc;

    let first = duplex.expect("it opened").await?;
    let session_id = first.session_id.clone();
    let open = match first.body {
        Some(proto::escrow_client_msg::Body::Open(o)) => o,
        _ => return Err(Status::invalid_argument("a session must open with EscrowOpen")),
    };

    // A service to pair into the escrow once it exists, on this same approval. Checked as
    // `pair_service` checks it and before anything is dealt, so naming one this image does not know
    // mints nothing.
    let pairing = if open.service_identifier.is_empty() && open.attempt_id.is_empty() {
        None
    } else {
        Some(pairing_target(&open.service_identifier, &open.attempt_id)?)
    };

    // There is nothing to reshare before there is a wallet. Taken once, up front, so the ceremony
    // runs against one consistent view of the key it is derived from.
    //
    // A wallet whose ceremony kept no dealt share is refused here rather than at release: its owner
    // cannot rebuild the wallet share an escrow share is built on top of, so the escrow would be
    // spendable by this cosigner's half and nobody else's.
    let (old_kp, old_pkp) = {
        let c = lock(&cosigner);
        if c.wallet_dealt_share_hex().is_none() {
            return Err(Status::failed_precondition(
                "this wallet was made before recovery existed: its owner could not rebuild a share \
                 for an escrow, so there is no safe escrow to mint",
            ));
        }
        c.wallet_key_material().ok_or_else(|| {
            Status::failed_precondition("this wallet has no key yet; there is nothing to escrow from")
        })?
    };

    // The wallet's half of its own share, before anything is dealt — see `dealt_share_for`. A
    // reshare builds on the wallet share, so the wallet needs this to finalize its own side.
    let dealt = dealt_share_for(&lock(&cosigner), &open.identifier)?;

    let mut sess = esc::EscrowSession::new();
    let our_round1 = esc::escrow_open(
        &mut sess,
        &old_kp,
        &open.identifier,
        &open.round1_package,
        &open.context,
    )?;
    duplex.send(proto::EscrowServerMsg {
        session_id: session_id.clone(),
        seq: 1,
        body: Some(proto::escrow_server_msg::Body::Round1(
            proto::EscrowRound1Out {
                round1_package: our_round1,
                wallet_dealt_share: dealt,
            },
        )),
    });

    let msg = duplex.expect("round 2").await?;
    let round2 = match msg.body {
        Some(proto::escrow_client_msg::Body::Round2(r)) => r,
        _ => return Err(Status::invalid_argument("expected EscrowRound2")),
    };
    let for_wallet = esc::escrow_finish(&mut sess, &old_kp, &old_pkp, &round2.round2_package)?;
    let material = sess
        .material
        .take()
        .ok_or_else(|| Status::internal("the reshare finished without key material"))?;
    let escrow_key = material.escrow_key.clone();

    // Sealed before it is announced. A wallet told about an escrow this cosigner cannot co-sign for
    // would be a wallet that funds a key only half of which exists.
    {
        let mut c = lock(&cosigner);
        c.install_escrow(crate::types::EscrowRecord {
            escrow_key: material.escrow_key,
            key_package_json: material.key_package_json,
            public_key_package_json: material.public_key_package_json,
            wallet_identifier_hex: material.wallet_identifier_hex,
            context_hex: material.context_hex,
            wallet_delta_share_hex: material.wallet_delta_share_hex,
            created_at: crate::handlers::helpers::now_secs(),
            pairing: None,
            session: None,
            reclaim_opened_at: None,
        })
        .map_err(Status::failed_precondition)?;
        c.seal();
    }

    duplex.send(proto::EscrowServerMsg {
        session_id: session_id.clone(),
        seq: 2,
        body: Some(proto::escrow_server_msg::Body::Complete(
            proto::EscrowComplete {
                round2_package: for_wallet,
                escrow_key: escrow_key.clone(),
            },
        )),
    });
    let Some(target) = pairing else { return Ok(()) };

    // --- Pairing the service in, as `pair_service` does ------------------------------------------
    //
    // Without its first round: the wallet holds the share it just minted, so there is nothing to
    // rebuild it from.
    let msg = duplex.expect("the wallet's dealing").await?;
    let deal = match msg.body {
        Some(proto::escrow_client_msg::Body::Deal(d)) => d,
        _ => return Err(Status::invalid_argument("expected PairServiceDeal")),
    };
    let material = lock(&cosigner)
        .escrow_key_material(&escrow_key)
        .ok_or_else(|| Status::internal("this escrow's sealed key material is unreadable"))?;
    let paired = deal_and_deliver(&cosigner, &escrow_key, material, &target, deal).await?;
    duplex.send(proto::EscrowServerMsg {
        session_id: session_id.clone(),
        seq: 3,
        body: Some(proto::escrow_server_msg::Body::Paired(paired)),
    });

    // The wallet's word that its own half was delivered and taken — what `PairServiceConfirm`
    // says, on this stream because a second call could not run while it is open. The service's
    // word arrives after the stream ends: it needs the tenant this stream holds.
    let msg = duplex.expect("word that the wallet delivered its half").await?;
    if !matches!(msg.body, Some(proto::escrow_client_msg::Body::Delivered(_))) {
        return Err(Status::invalid_argument("expected PairServiceConfirmRequest"));
    }
    {
        let mut c = lock(&cosigner);
        c.confirm_escrow_pairing(&escrow_key, &hex::encode(&target.attempt_id))
            .map_err(Status::failed_precondition)?;
        c.seal();
    }
    duplex.send(proto::EscrowServerMsg {
        session_id,
        seq: 4,
        body: Some(proto::escrow_server_msg::Body::Confirmed(
            proto::PairServiceConfirmResponse {},
        )),
    });
    Ok(())
}

/// Pairing a service into an escrow, and handing it its half — deliver, then seal.
///
/// A stream because the wallet cannot deal until it has rebuilt its escrow share, and it keeps no
/// share: the two halves it needs ride the first server message, as they do on every other stream.
///
/// The order at the end is deliberate and documented in [`crate::handlers::delivery`]: this
/// cosigner never keeps the service's half, so a pairing sealed before a failed delivery could
/// never be completed. Delivering first makes a failure harmless — nothing is sealed, and the
/// wallet simply pairs again with a fresh half.
async fn pair_service(
    cosigner: Arc<Mutex<Cosigner>>,
    duplex: Duplex<proto::PairServiceClientMsg, proto::PairServiceServerMsg>,
) -> Result<(), Status> {
    let first = duplex.expect("it opened").await?;
    let session_id = first.session_id.clone();
    let open = match first.body {
        Some(proto::pair_service_client_msg::Body::Open(o)) => o,
        _ => return Err(Status::invalid_argument("a session must open with PairServiceOpen")),
    };
    let target = pairing_target(&open.service_identifier, &open.attempt_id)?;

    let (material, dealt, delta) = {
        let c = lock(&cosigner);
        let escrow = c
            .escrow(&open.escrow_key)
            .ok_or_else(|| Status::not_found("this wallet holds no such escrow"))?;
        // A FINISHED pairing is not replaceable: a second service in one escrow is a second way to
        // be paid out of money committed to a single deal. A *pending* one is a different matter —
        // it is an attempt that did not complete, and pairing again is how a wallet retries. The
        // cosigner deals a fresh half each time, because it keeps none.
        if escrow
            .pairing
            .as_ref()
            .is_some_and(|p| p.state() == crate::types::PairingState::Ready)
        {
            return Err(Status::failed_precondition(
                "this escrow already has a service paired into it",
            ));
        }
        let delta = hex::decode(&escrow.wallet_delta_share_hex)
            .map_err(|e| Status::internal(format!("sealed escrow delta is not hex: {e}")))?;
        let wallet_id_bytes = hex::decode(&escrow.wallet_identifier_hex)
            .map_err(|e| Status::internal(format!("sealed wallet identifier is not hex: {e}")))?;
        // Answered only to the identifier the ceremony recorded — the same rule every other stream
        // applies, reached through the same function.
        let dealt = dealt_share_for(&c, &wallet_id_bytes)?;
        let material = c
            .escrow_key_material(&open.escrow_key)
            .ok_or_else(|| Status::internal("this escrow's sealed key material is unreadable"))?;
        (material, dealt, delta)
    };

    duplex.send(proto::PairServiceServerMsg {
        session_id: session_id.clone(),
        seq: 1,
        body: Some(proto::pair_service_server_msg::Body::Ready(
            proto::PairServiceReady {
                wallet_dealt_share: dealt,
                escrow_delta_share: delta,
            },
        )),
    });

    let msg = duplex.expect("the wallet's dealing").await?;
    let deal = match msg.body {
        Some(proto::pair_service_client_msg::Body::Deal(d)) => d,
        _ => return Err(Status::invalid_argument("expected PairServiceDeal")),
    };
    let done = deal_and_deliver(&cosigner, &open.escrow_key, material, &target, deal).await?;

    duplex.send(proto::PairServiceServerMsg {
        session_id,
        seq: 2,
        body: Some(proto::pair_service_server_msg::Body::Done(done)),
    });
    Ok(())
}

/// A service to pair into an escrow, and the attempt that ties its two halves together.
struct PairingTarget {
    service_id: threshold::identifier::Identifier,
    /// Where the service is, according to the image.
    origin: String,
    attempt_id: Vec<u8>,
}

/// Check what a pairing names, before anything is dealt — on `PairService`, and on an `Escrow`
/// stream that pairs the escrow it mints.
fn pairing_target(service_identifier: &[u8], attempt_id: &[u8]) -> Result<PairingTarget, Status> {
    use crate::handlers::delivery::ServiceRegistry;

    // Enough to be unrepeatable by accident. It is a label, not a secret: it ties two deliveries
    // together and nothing rests on it being unguessable.
    if attempt_id.len() != 16 {
        return Err(Status::invalid_argument("a pairing attempt id is 16 bytes"));
    }

    // Where this service is, according to the IMAGE. Resolved before anything is dealt, so naming
    // a service this enclave does not know costs nothing and reveals nothing.
    let origin = ServiceRegistry::from_env()
        .origin_of(&hex::encode(service_identifier))?
        .to_string();

    let b: [u8; 32] = service_identifier
        .try_into()
        .map_err(|_| Status::invalid_argument("a service identifier is 32 bytes"))?;
    let service_id = threshold::identifier::Identifier::deserialize(&b)
        .map_err(|e| Status::invalid_argument(format!("bad service identifier: {e}")))?;
    Ok(PairingTarget { service_id, origin, attempt_id: attempt_id.to_vec() })
}

/// Deal this cosigner's half of a pairing from the wallet's dealing, hand it to the service, and
/// seal the pairing pending — deliver, then seal, as [`pair_service`] explains. What comes back
/// tells the wallet where to send its own half.
async fn deal_and_deliver(
    cosigner: &Arc<Mutex<Cosigner>>,
    escrow_key: &str,
    (escrow_kp, escrow_pkp, wallet_id): (
        threshold::keys::KeyPackage,
        threshold::keys::PublicKeyPackage,
        threshold::identifier::Identifier,
    ),
    target: &PairingTarget,
    deal: proto::PairServiceDeal,
) -> Result<proto::PairServiceDone, Status> {
    let material = crate::handlers::pairing::pair_service(
        &escrow_kp,
        &escrow_pkp,
        &wallet_id,
        &target.service_id,
        &deal.contribution_to_cosigner,
        &deal.contribution_to_service,
    )?;
    let attempt_id_hex = hex::encode(&target.attempt_id);

    // Over the connection the runtime will go on holding after this call ends — that is what lets
    // the service speak first later, when it asks for a release. See `handlers::delivery`.
    let host = lock(cosigner).host();
    crate::handlers::delivery::deliver_pairing_half(
        host.as_ref(),
        &material.service_identifier_hex,
        &target.origin,
        &crate::service_stream::ToService::PairingHalf {
            escrow_key: escrow_key.to_string(),
            attempt_id: attempt_id_hex.clone(),
            service_identifier: material.service_identifier_hex.clone(),
            half: hex::encode(&material.service_half),
            public_key_package_json: material.public_key_package_json.clone(),
            service_verifying_share: material.service_verifying_share_hex.clone(),
        },
    )
    .await
    .map_err(|e| {
        Status::unavailable(format!(
            "the service did not take its half, so nothing was paired: {e}"
        ))
    })?;

    let done = proto::PairServiceDone {
        public_key_package_json: material.public_key_package_json.clone(),
        service_verifying_share: material.service_verifying_share_hex.clone(),
        // So the wallet delivers its own half to the same place. It does not choose an origin, and
        // could not: the list lives in the image.
        service_origin: target.origin.clone(),
        attempt_id: target.attempt_id.clone(),
    };
    let mut c = lock(cosigner);
    c.pair_escrow_service(
        escrow_key,
        crate::types::ServicePairing {
            service_identifier_hex: material.service_identifier_hex,
            key_package_json: material.key_package_json,
            public_key_package_json: material.public_key_package_json,
            service_verifying_share_hex: material.service_verifying_share_hex,
            paired_at: crate::handlers::helpers::now_secs(),
            attempt_id_hex,
            // Delivered, not yet shown to work: the service has one half of two, and neither
            // party has vouched for it. See `handlers::delivery`.
            service_confirmed: false,
            wallet_confirmed: false,
        },
    )
    .map_err(Status::failed_precondition)?;
    c.seal();
    Ok(done)
}

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
            mat.wallet_dealt_share_hex,
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
/// Taking back what is left of an escrow, once its deal is over.
///
/// The same four steps a send takes, because it is one — of the escrow's key rather than the
/// wallet's. See [`crate::handlers::reclaim`] for what is checked and what is derived rather than
/// accepted.
async fn escrow_reclaim(
    cosigner: Arc<Mutex<Cosigner>>,
    duplex: Duplex<proto::EscrowReclaimClientMsg, proto::EscrowReclaimServerMsg>,
) -> Result<(), Status> {
    let first = duplex.expect("it opened").await?;
    let session_id = first.session_id.clone();
    let open = match first.body {
        Some(proto::escrow_reclaim_client_msg::Body::Open(o)) => o,
        _ => {
            return Err(Status::invalid_argument(
                "a session must open with EscrowReclaimOpen",
            ))
        }
    };
    let info = open
        .ark_info
        .map(ark_info_from_proto)
        .ok_or_else(|| Status::invalid_argument("EscrowReclaimOpen carried no ark_info"))?;

    let now = crate::handlers::helpers::now_secs();
    let mut reclaim = lock(&cosigner).reclaim_open(
        &open.escrow_key,
        vtxos_from_proto(open.vtxos.clone()),
        &info,
        now,
    )?;

    // From here on the owner may come to hold signatures that empty this escrow, and nothing
    // that happens later on this stream — or fails to — tells the cosigner whether they did. So
    // the escrow is retired from deals now, and durably, before a single nonce exists: a seal
    // that cannot be written means no round at all. See `Cosigner::open_escrow_session`.
    {
        let mut c = lock(&cosigner);
        c.mark_escrow_reclaim_opened(&open.escrow_key, now)
            .map_err(Status::failed_precondition)?;
        c.try_seal().map_err(|e| {
            Status::unavailable(format!("could not record the reclaim, so it does not begin: {e}"))
        })?;
    }

    // Round one, on this stream, as a send does it: the cosigner commits first so the whole batch
    // costs one round trip — but with the ESCROW's share, not the wallet's.
    let (round, commitments) = lock(&cosigner)
        .sign_in_band_begin_as(&reclaim.key_package, &reclaim.sighashes);

    duplex.send(proto::EscrowReclaimServerMsg {
        session_id: session_id.clone(),
        seq: 1,
        body: Some(proto::escrow_reclaim_server_msg::Body::Sighashes(
            proto::EscrowReclaimSighashes {
                messages_to_sign: reclaim.sighashes.clone(),
                cosigner_identifier: cosigner_identifier(&commitments),
                cosigner_commitments: wire_commitments(commitments),
                wallet_dealt_share: reclaim.wallet_dealt_share.clone(),
                escrow_delta_share: reclaim.escrow_delta_share.clone(),
                to_ark_address: reclaim.to_ark_address.clone(),
                amount_sats: reclaim.amount_sats,
            },
        )),
    });

    // --- The wallet's half of the round, then what it must submit --------------------------
    let signed = match reclaim_body(&duplex, "mid-reclaim").await? {
        proto::escrow_reclaim_client_msg::Body::Signed(s) => s,
        _ => return Err(Status::invalid_argument("expected EscrowReclaimSigned")),
    };
    let signatures = lock(&cosigner)
        .sign_in_band_finish_as(
            &reclaim.key_package,
            &reclaim.public_key_package,
            &reclaim.wallet_identifier,
            round,
            wallet_halves(signed.rounds),
        )
        .map_err(Status::invalid_argument)?;
    let (ark_tx_b64, checkpoint_txs) = {
        let sigs = crate::cosigner::sigs_from_wire(&signatures).map_err(Status::internal)?;
        reclaim.session.sign_with_frost(sigs).map_err(Status::internal)?;
        reclaim
            .session
            .prepare_submit()
            .map_err(|e| Status::internal(format!("prepare submit: {e}")))?
    };

    duplex.send(proto::EscrowReclaimServerMsg {
        session_id: session_id.clone(),
        seq: 2,
        body: Some(proto::escrow_reclaim_server_msg::Body::Submit(
            proto::SendSubmit {
                ark_tx_b64,
                checkpoint_txs,
            },
        )),
    });

    // --- What the ASP returned, turned into the finalize call ------------------------------
    let submitted = match reclaim_body(&duplex, "mid-reclaim").await? {
        proto::escrow_reclaim_client_msg::Body::Submitted(s) => s,
        _ => return Err(Status::invalid_argument("expected SendSubmitted")),
    };
    let final_checkpoint_txs = reclaim
        .session
        .finalize_checkpoints(&submitted.signed_checkpoint_txs)
        .map_err(|e| Status::internal(format!("finalize checkpoints: {e}")))?;

    duplex.send(proto::EscrowReclaimServerMsg {
        session_id: session_id.clone(),
        seq: 3,
        body: Some(proto::escrow_reclaim_server_msg::Body::Finalize(
            proto::SendFinalize {
                ark_txid: submitted.ark_txid.clone(),
                final_checkpoint_txs,
            },
        )),
    });

    // --- Accepted. Only now is the escrow closed for good ----------------------------------
    match reclaim_body(&duplex, "mid-reclaim").await? {
        proto::escrow_reclaim_client_msg::Body::Finalized(_) => {}
        _ => return Err(Status::invalid_argument("expected SendFinalized")),
    }
    reclaim.session.mark_done();
    // Nothing to close. A reclaim is only permitted once the deadline has passed, so by the time
    // this runs the deal is already over — by the clock, which is the only way a deal ends.
    lock(&cosigner).seal();

    duplex.send(proto::EscrowReclaimServerMsg {
        session_id,
        seq: 4,
        body: Some(proto::escrow_reclaim_server_msg::Body::Complete(
            proto::EscrowReclaimComplete {
                ark_txid: submitted.ark_txid,
            },
        )),
    });
    Ok(())
}

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

    // The wallet's half of its own share, before anything is built — see `dealt_share_for`. It
    // rides the first sighashes and nothing after: the trailing seal reuses what the wallet rebuilt.
    let dealt = dealt_share_for(&lock(&cosigner), &open.identifier)?;

    let info = open
        .ark_info
        .map(ark_info_from_proto)
        .ok_or_else(|| Status::invalid_argument("SendOpen carried no ark_info"))?;

    // A top-up that also commits its escrow to a deal. Asked now, before anything is built: a deal
    // that could not be struck is refused while no money has moved. Nothing else can write until
    // this stream ends — it holds the tenant — so the same answer holds once the send is final.
    // Where the money goes is the caller's to say, as for any send: an owner could always fund an
    // escrow one way and commit it another, and a service pays against what the escrow holds.
    let commit = match open.escrow_commit.as_ref() {
        None => None,
        Some(req) => {
            let now = crate::handlers::helpers::now_secs();
            let deal = deal_of(req, now)?;
            lock(&cosigner)
                .may_commit_escrow(&req.escrow_key, now)
                .map_err(Status::failed_precondition)?;
            Some((req.escrow_key.clone(), deal, now))
        }
    };

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
        body: Some(proto::send_server_msg::Body::Sighashes(proto::SendSighashes {
            wallet_dealt_share: dealt,
            ..sighashes_msg(sighashes, commitments)
        })),
    });
    tracing::info!("Send: returned the dealt share to the wallet's own identifier");

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
    let (resp, committed) = {
        let mut c = lock(&cosigner);
        let submitted = c.send_complete((session, change_exit_delay), submitted.ark_txid);
        let resp = c.apply_send(submitted);
        match commit {
            None => {
                c.seal();
                (resp, None)
            }
            // The money is in the escrow now, so no failure below may read like the refusal at
            // open: an app retries that one, and a retry here would send the money twice.
            Some((escrow_key, deal, now)) => {
                let committed = proto::EscrowOpenSessionResponse {
                    policy_description: deal.policy.describe(),
                    deadline_secs: deal.deadline,
                };
                // Checked at open with this same `now`, and nothing wrote since, so this does not
                // fail. If it ever did, its reason stays in the log: said here, it could read
                // like the refusal an app retries.
                c.open_escrow_session(&escrow_key, deal, now).map_err(|e| {
                    tracing::error!("a deal checked at open was refused after the send: {e}");
                    Status::internal(
                        "the send went through but the deal was not committed; commit it on its \
                         own",
                    )
                })?;
                // Sealed before it is announced: the app goes on to ask the service to pay
                // against this deal.
                c.try_seal().map_err(|e| {
                    Status::unavailable(format!(
                        "the send went through but the deal could not be saved ({e}); commit it \
                         on its own"
                    ))
                })?;
                (resp, Some(committed))
            }
        }
    };

    duplex.send(proto::SendServerMsg {
        session_id: session_id.clone(),
        seq: 4,
        body: Some(proto::send_server_msg::Body::Complete(proto::SendComplete {
            ark_txid: resp.ark_txid,
            change: None,
            committed,
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

    // The wallet's half of its own share — see `dealt_share_for`. Taken by the FIRST sighashes this
    // stream sends, whichever path sends them, and gone after: a settle signs two or three rounds
    // and the wallet rebuilds its share once.
    let mut dealt = Some(dealt_share_for(&lock(&cosigner), &open.identifier)?);
    tracing::info!("Settle: returning the dealt share to the wallet's own identifier");

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
        return settle_seal(&cosigner, &duplex, seal, &session_id, 1, dealt.take()).await;
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
                Some(proto::settle_server_msg::Body::Sighashes(proto::SettleSighashes {
                    wallet_dealt_share: dealt.take().unwrap_or_default(),
                    ..settle_sighashes_msg(messages_to_sign, commitments)
                }))
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
                    // No share with it: the settle's first round already carried one.
                    settle_seal(&cosigner, &duplex, seal, &session_id, seq + 1, None).await?;
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

async fn reclaim_body(
    duplex: &Duplex<proto::EscrowReclaimClientMsg, proto::EscrowReclaimServerMsg>,
    what: &str,
) -> Result<proto::escrow_reclaim_client_msg::Body, Status> {
    duplex
        .expect(what)
        .await?
        .body
        .ok_or_else(|| Status::invalid_argument("empty EscrowReclaimClientMsg"))
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
        wallet_dealt_share: Vec::new(),
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
        wallet_dealt_share: Vec::new(),
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
///
/// [dealt_share] is the wallet's half of its share when this seal is the stream's first round — a
/// `seal_only` open — and `None` when a settle ran before it and already handed it over.
async fn settle_seal(
    cosigner: &Arc<Mutex<Cosigner>>,
    duplex: &Duplex<proto::SettleClientMsg, proto::SettleServerMsg>,
    mut seal: proto::SealDelegate,
    session_id: &str,
    seq: u64,
    dealt_share: Option<Vec<u8>>,
) -> Result<(), Status> {
    let device_token = std::mem::take(&mut seal.device_token);
    let seal_round = seal_open(cosigner, seal)?;
    let mut sighashes = settle_sighashes_msg(seal_round.delegate_sighashes, seal_round.commitments);
    sighashes.exit_messages = seal_round.exit_sighashes;
    sighashes.wallet_dealt_share = dealt_share.unwrap_or_default();
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
