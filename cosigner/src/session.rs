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
use crate::delegate::DelegateRenew;
use crate::escrow_session::Escrow;
use crate::grpc::{self, Duplex, SessionBody, Status};
use crate::handlers::recover::dealt_share_for;
use crate::wallet_proto as wp;

pub mod proto {
    #![allow(clippy::all)]
    include!(concat!(env!("OUT_DIR"), "/cosigner.v1.rs"));
}

use proto::{
    sign_client_msg, sign_server_msg, SignClientMsg, SignCommitments, SignComplete, SignServerMsg,
};

/// Every RPC this service answers, under the package and service names in `cosign_session.proto`.
const PREFIX: &str = "/cosigner.v1.Cosigner/";

pub struct Session {
    cosigner: Arc<Mutex<Cosigner>>,
    server_info: wp::GetServerInfoResponse,
}

impl Session {
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
        // Authentication is the runtime's: it lets a request through only once a passkey approved
        // it. Run it without a gate and anyone can call this.
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
            "Renew" => ceremony!(renew),
            "Escrow" => ceremony!(escrow),
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

    /// Commit an escrow to a deal: what the paired service may take, and until when.
    async fn escrow_open_session(
        &self,
        body: Body,
    ) -> Result<proto::EscrowOpenSessionResponse, Status> {
        let req: proto::EscrowOpenSessionRequest = grpc::one_message(body).await?;
        let now = crate::handlers::helpers::now_secs();
        let escrow = Escrow::from_request(&req, now)?;
        let description = escrow.policy.describe();
        let deadline = escrow.deadline;

        let mut c = lock(&self.cosigner);
        c.open_escrow_session(escrow, now).map_err(Status::failed_precondition)?;
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
            escrows: c.escrows().iter().map(|e| e.summary(now)).collect(),
        })
    }
}

/// The cosigner, with a poisoned lock recovered rather than propagated.
///
/// A panic mid-ceremony leaves the wallet's in-memory state as it was — its authority comes from
/// the seal, not from this guard — and taking down every later call because one caller panicked
/// would turn a single failed request into a dead instance.
pub(crate) fn lock(cosigner: &Arc<Mutex<Cosigner>>) -> MutexGuard<'_, Cosigner> {
    cosigner.lock().unwrap_or_else(|e| e.into_inner())
}

// ===============================================================================================
// The ceremonies
// ===============================================================================================

/// One signature, as one in-band round.
///
/// The wallet used to commit first, in `SignOpen`. It cannot: its nonce is hedged with its share,
/// and it holds no share until this stream's first answer brings the half the cosigner dealt it.
/// So this is the round `Send` and `Renew` already run — the cosigner commits first, the wallet
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
                .map(|c| (c.identifier_hex.clone(), c.into()))
                .collect(),
            message_to_sign: open.message_to_sign,
            wallet_dealt_share: dealt,
        })),
    });

    // --- Round 2: the wallet's commitments and share ----------------------------------------
    //
    // If the client never sends it, or the stream dies here, `round` drops with this task and the
    // nonce is gone. That is the safe failure: an abandoned round leaves nothing reusable.
    let share = match duplex.next_body("the share arrived").await? {
        sign_client_msg::Body::Share(s) => s,
        _ => return Err(Status::invalid_argument("expected SignShare")),
    };

    // A bad share is the caller's fault, and is reported as such rather than as ours.
    let signature = lock(&cosigner)
        .sign_in_band_finish(round, vec![share.into()])
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
/// When the open names a service, the stream goes on to pair it into the new escrow, and the
/// wallet confirms on this stream — so an escrow is set up for a service on one approval. The
/// pairing is usable once the service confirms too, which can only arrive after this stream ends.
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

    // A service to pair into the escrow once it exists, on this same approval. Checked before
    // anything is dealt, so naming one this image does not know mints nothing.
    let service = if open.service_identifier.is_empty() && open.attempt_id.is_empty() {
        None
    } else {
        // Enough to be unrepeatable by accident. It is a label, not a secret: it ties two
        // deliveries together and nothing rests on it being unguessable.
        if open.attempt_id.len() != 16 {
            return Err(Status::invalid_argument("a pairing attempt id is 16 bytes"));
        }
        Some(crate::escrow::Service::named(&open.service_identifier)?)
    };
    let attempt_id_hex = hex::encode(&open.attempt_id);

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

    let round2 = match duplex.next_body("round 2").await? {
        proto::escrow_client_msg::Body::Round2(r) => r,
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
    let Some(service) = service else { return Ok(()) };

    // --- Pairing the service in ----------------------------------------------------------------
    let deal = match duplex.next_body("the wallet's dealing").await? {
        proto::escrow_client_msg::Body::Deal(d) => d,
        _ => return Err(Status::invalid_argument("expected PairServiceDeal")),
    };
    let escrow = lock(&cosigner)
        .escrow_details(&escrow_key)
        .ok_or_else(|| Status::internal("this escrow's sealed key material is unreadable"))?;
    let paired = escrow.deal_and_deliver(&cosigner, &service, &attempt_id_hex, deal).await?;
    duplex.send(proto::EscrowServerMsg {
        session_id: session_id.clone(),
        seq: 3,
        body: Some(proto::escrow_server_msg::Body::Paired(paired)),
    });

    // The wallet's word that its own half was delivered and taken — on this stream, because a
    // second call could not run while it is open. The service's word arrives after the stream
    // ends: it needs the tenant this stream holds.
    let delivered = duplex.next_body("word that the wallet delivered its half").await?;
    if !matches!(delivered, proto::escrow_client_msg::Body::Delivered(_)) {
        return Err(Status::invalid_argument("expected PairServiceConfirmRequest"));
    }
    {
        let mut c = lock(&cosigner);
        c.confirm_escrow_pairing(&escrow_key, &attempt_id_hex)
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
    let round2 = match duplex.next_body("round 2").await? {
        proto::dkg_client_msg::Body::Round2(r) => r,
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

/// Taking back what is left of an escrow, once its deal is over: a [`send`] whose open names
/// `reclaim_escrow`.
///
/// The same four steps a send takes, because it is one — of the escrow's key rather than the
/// wallet's. See [`crate::handlers::reclaim`] for what is checked and what is derived rather than
/// accepted.
async fn reclaim(
    cosigner: Arc<Mutex<Cosigner>>,
    duplex: Duplex<proto::SendClientMsg, proto::SendServerMsg>,
    session_id: String,
    open: proto::SendOpen,
) -> Result<(), Status> {
    // Where it goes is derived, never named, and it takes everything the escrow holds.
    if !open.recipient_ark_address.is_empty() || open.amount != 0 || open.escrow_commit.is_some() {
        return Err(Status::invalid_argument(
            "a reclaim names no recipient, amount or deal: it returns what the escrow holds to \
             this wallet",
        ));
    }
    let info = open
        .ark_info
        .map(ark::client::types::ArkInfo::from)
        .ok_or_else(|| Status::invalid_argument("SendOpen carried no ark_info"))?;

    let now = crate::handlers::helpers::now_secs();
    let mut reclaim = lock(&cosigner).reclaim_open(
        &open.reclaim_escrow,
        open.vtxos.into_iter().map(Into::into).collect(),
        &info,
        now,
    )?;

    // From here on the owner may come to hold signatures that empty this escrow, and nothing
    // that happens later on this stream — or fails to — tells the cosigner whether they did. So
    // the escrow is retired from deals now, and durably, before a single nonce exists: a seal
    // that cannot be written means no round at all. See `Cosigner::open_escrow_session`.
    {
        let mut c = lock(&cosigner);
        c.mark_escrow_reclaim_opened(&open.reclaim_escrow, now)
            .map_err(Status::failed_precondition)?;
        c.try_seal().map_err(|e| {
            Status::unavailable(format!("could not record the reclaim, so it does not begin: {e}"))
        })?;
    }

    // Round one, on this stream, as a send does it: the cosigner commits first so the whole batch
    // costs one round trip — but with the ESCROW's share, not the wallet's.
    let (round, commitments) = lock(&cosigner)
        .sign_in_band_begin_as(&reclaim.key_package, &reclaim.sighashes);

    duplex.send(proto::SendServerMsg {
        session_id: session_id.clone(),
        seq: 1,
        body: Some(proto::send_server_msg::Body::Sighashes(proto::SendSighashes {
            wallet_dealt_share: reclaim.wallet_dealt_share.clone(),
            escrow_delta_share: reclaim.escrow_delta_share.clone(),
            to_ark_address: reclaim.to_ark_address.clone(),
            amount_sats: reclaim.amount_sats,
            ..proto::SendSighashes::round(reclaim.sighashes.clone(), commitments)
        })),
    });

    // --- The wallet's half of the round, then what it must submit --------------------------
    let signed = match duplex.next_body("mid-reclaim").await? {
        proto::send_client_msg::Body::Signed(s) => s,
        _ => return Err(Status::invalid_argument("expected SendSigned")),
    };
    let signatures = lock(&cosigner)
        .sign_in_band_finish_as(
            &reclaim.key_package,
            &reclaim.public_key_package,
            &reclaim.wallet_identifier,
            round,
            signed.rounds.into_iter().map(Into::into).collect(),
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

    duplex.send(proto::SendServerMsg {
        session_id: session_id.clone(),
        seq: 2,
        body: Some(proto::send_server_msg::Body::Submit(
            proto::SendSubmit {
                ark_tx_b64,
                checkpoint_txs,
            },
        )),
    });

    // --- What the ASP returned, turned into the finalize call ------------------------------
    let submitted = match duplex.next_body("mid-reclaim").await? {
        proto::send_client_msg::Body::Submitted(s) => s,
        _ => return Err(Status::invalid_argument("expected SendSubmitted")),
    };
    let final_checkpoint_txs = reclaim
        .session
        .finalize_checkpoints(&submitted.signed_checkpoint_txs)
        .map_err(|e| Status::internal(format!("finalize checkpoints: {e}")))?;

    duplex.send(proto::SendServerMsg {
        session_id: session_id.clone(),
        seq: 3,
        body: Some(proto::send_server_msg::Body::Finalize(
            proto::SendFinalize {
                ark_txid: submitted.ark_txid.clone(),
                final_checkpoint_txs,
            },
        )),
    });

    // --- Accepted. Only now is the escrow closed for good ----------------------------------
    match duplex.next_body("mid-reclaim").await? {
        proto::send_client_msg::Body::Finalized(_) => {}
        _ => return Err(Status::invalid_argument("expected SendFinalized")),
    }
    reclaim.session.mark_done();
    // Nothing to close. A reclaim is only permitted once the deadline has passed, so by the time
    // this runs the deal is already over — by the clock, which is the only way a deal ends.
    lock(&cosigner).seal();

    duplex.send(proto::SendServerMsg {
        session_id,
        seq: 4,
        body: Some(proto::send_server_msg::Body::Complete(proto::SendComplete {
            ark_txid: submitted.ark_txid,
            change: None,
            committed: None,
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

    // The wallet's half of its own share, before anything is built — see `dealt_share_for`. It
    // rides the first sighashes and nothing after: a trailing delegate renewal reuses what the
    // wallet rebuilt.
    let dealt = dealt_share_for(&lock(&cosigner), &open.identifier)?;

    // Taking back what is left of an escrow is a send too, on this same stream — see [`reclaim`].
    if !open.reclaim_escrow.is_empty() {
        return reclaim(cosigner, duplex, session_id, open).await;
    }

    let info = open
        .ark_info
        .map(ark::client::types::ArkInfo::from)
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
            let deal = Escrow::from_request(req, now)?;
            lock(&cosigner)
                .may_commit_escrow(&deal.escrow_key, now)
                .map_err(Status::failed_precondition)?;
            Some((deal, now))
        }
    };

    // The caller names its inputs, and the cosigner validates every one against the scriptPubKey it
    // derives from its own owner key before selecting — so naming a VTXO here cannot widen what the
    // wallet owns.
    let (mut session, change_exit_delay, sighashes) = {
        let step1 = crate::types::SendVtxoStep1 {
            recipient_ark_address: open.recipient_ark_address.clone(),
            amount: open.amount,
            vtxos: open.vtxos.iter().cloned().map(Into::into).collect(),
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
            ..proto::SendSighashes::round(sighashes, commitments)
        })),
    });
    tracing::info!("Send: returned the dealt share to the wallet's own identifier");

    // --- The wallet's half of the round, then what it must submit --------------------------
    let signed = match duplex.next_body("mid-send").await? {
        proto::send_client_msg::Body::Signed(s) => s,
        _ => return Err(Status::invalid_argument("expected SendSigned")),
    };
    // A bad share is the caller's fault, and is reported as such rather than as ours.
    let signatures = lock(&cosigner)
        .sign_in_band_finish(round, signed.rounds.into_iter().map(Into::into).collect())
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
    let submitted = match duplex.next_body("mid-send").await? {
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
    match duplex.next_body("mid-send").await? {
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
            Some((deal, now)) => {
                let committed = proto::EscrowOpenSessionResponse {
                    policy_description: deal.policy.describe(),
                    deadline_secs: deal.deadline,
                };
                // Checked at open with this same `now`, and nothing wrote since, so this does not
                // fail. If it ever did, its reason stays in the log: said here, it could read
                // like the refusal an app retries.
                c.open_escrow_session(deal, now).map_err(|e| {
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

    // --- Optionally, renew the delegate over what the wallet holds now ---------------------
    //
    // On this stream so it rides the approval — and the passkey seed — the send already had. A
    // caller that closes instead has simply not asked for it.
    if let Some(msg) = duplex.recv().await {
        let request = match msg.body {
            Some(proto::send_client_msg::Body::RenewDelegate(r)) => r,
            _ => {
                return Err(Status::invalid_argument(
                    "after SendComplete only the delegate's renewal may follow",
                ))
            }
        };
        DelegateRenew::run(&cosigner, &duplex, request, &session_id, 5, vec![]).await?;
    }
    Ok(())
}

/// Renewing a boarding output into Ark, or the VTXOs held, with the caller driving the ASP round.
///
/// The cosigner answers each relayed event with what to send the ASP next and never opens a socket
/// of its own. `ark_info` arrives from the caller for the same reason: it is the one talking to the
/// ASP. See `handlers/renew.rs` for why that cannot redirect funds.
async fn renew(
    cosigner: Arc<Mutex<Cosigner>>,
    duplex: Duplex<proto::RenewClientMsg, proto::RenewServerMsg>,
) -> Result<(), Status> {
    use crate::handlers::renew::RenewStep;

    let first = duplex.expect("it opened").await?;
    let session_id = first.session_id.clone();
    let open = match first.body {
        Some(proto::renew_client_msg::Body::Open(o)) => o,
        _ => return Err(Status::invalid_argument("a session must open with RenewOpen")),
    };
    // Authenticated by the runtime at open — see `sign` above.

    // The wallet's half of its own share — see `dealt_share_for`. Taken by the FIRST sighashes this
    // stream sends, whichever path sends them, and gone after: a renewal signs two or three rounds
    // and the wallet rebuilds its share once.
    let mut dealt = Some(dealt_share_for(&lock(&cosigner), &open.identifier)?);
    tracing::info!("Renew: returning the dealt share to the wallet's own identifier");

    let info = open
        .ark_info
        .map(ark::client::types::ArkInfo::from)
        .ok_or_else(|| Status::invalid_argument("RenewOpen carried no ark_info"))?;
    if open.delegate_only {
        // Nothing to refresh now; renew the delegate over the set and close.
        let request = proto::RenewDelegate {
            vtxos: open.vtxos,
            ark_info: Some(wp::ArkInfo::from(&info)),
            device_token: open.device_token,
            exit_script_pubkey: open.exit_script_pubkey,
        };
        let dealt = dealt.take().unwrap_or_default();
        return DelegateRenew::run(&cosigner, &duplex, request, &session_id, 1, dealt).await;
    }
    let boarding_utxo = open.boarding_utxo.map(|u| (u.txid, u.vout, u.amount_sats));
    let vtxos: Vec<crate::types::VtxoInput> = open.vtxos.into_iter().map(Into::into).collect();

    let sighashes = lock(&cosigner)
        .renew_open(boarding_utxo, vtxos, info)
        .map_err(Status::internal)?;

    let mut seq = 1u64;
    let mut step = RenewStep::Sighashes(sighashes);

    // The FROST round that is waiting for the wallet's half. A renewal signs twice — the intent
    // proof, and for a boarding settle the commitment transaction later — so this is set each time
    // sighashes go out and taken when the matching `Signed` comes back. Holding it here rather than
    // on the cosigner is what keeps the nonces on this stream's stack, where a dropped stream takes
    // them with it.
    let mut pending_round: Option<crate::cosigner::InBandRound> = None;

    loop {
        // Say what we need, then read what the caller did about it.
        let body = match step {
            RenewStep::Sighashes(messages_to_sign) => {
                // Round one, on this stream — see `Cosigner::sign_in_band_begin` for why it cannot
                // be a nested `Sign` any more.
                let (round, commitments) = lock(&cosigner)
                    .sign_in_band_begin(&messages_to_sign)
                    .map_err(Status::internal)?;
                pending_round = Some(round);
                Some(proto::renew_server_msg::Body::Sighashes(proto::RenewSighashes {
                    wallet_dealt_share: dealt.take().unwrap_or_default(),
                    ..proto::RenewSighashes::round(messages_to_sign, commitments)
                }))
            }
            RenewStep::Register { proof, message, topics } => Some(
                proto::renew_server_msg::Body::Register(proto::RegisterIntent {
                    proof,
                    message,
                    topics,
                }),
            ),
            RenewStep::Submit(call) => {
                Some(proto::renew_server_msg::Body::Submit(call.into()))
            }
            RenewStep::Idle => Some(proto::renew_server_msg::Body::Idle(proto::RenewIdle {})),
            RenewStep::Complete(sub) => {
                let complete = proto::RenewComplete {
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
                duplex.send(proto::RenewServerMsg {
                    session_id: session_id.clone(),
                    seq,
                    body: Some(proto::renew_server_msg::Body::Complete(complete)),
                });
                // Optionally, renew the delegate over what the wallet holds now — on this stream,
                // so it rides the approval and the passkey seed the renewal already had.
                if let Some(msg) = duplex.recv().await {
                    let request = match msg.body {
                        Some(proto::renew_client_msg::Body::RenewDelegate(r)) => r,
                        _ => {
                            return Err(Status::invalid_argument(
                                "after RenewComplete only the delegate's renewal may follow",
                            ))
                        }
                    };
                    // No share with it: the renewal's first round already carried one.
                    let next = seq + 1;
                    DelegateRenew::run(&cosigner, &duplex, request, &session_id, next, vec![])
                        .await?;
                }
                return Ok(());
            }
        };

        duplex.send(proto::RenewServerMsg {
            session_id: session_id.clone(),
            seq,
            body,
        });
        seq += 1;

        let body = duplex.next_body("the next renewal step").await?;

        // Scoped to this iteration, and released before the loop comes back around to
        // `recv().await`. That used to matter because the caller opened a nested `Sign` on its own
        // connection while this stream was parked; signing is in-band now, so nothing else takes
        // this lock mid-renewal — but holding a guard across an await is still the wrong habit.
        let mut c = lock(&cosigner);
        step = match body {
            proto::renew_client_msg::Body::Signed(s) => {
                let round = pending_round.take().ok_or_else(|| {
                    Status::invalid_argument("signatures arrived with no round waiting for them")
                })?;
                let signatures = c
                    .sign_in_band_finish(round, s.rounds.into_iter().map(Into::into).collect())
                    .map_err(Status::invalid_argument)?;
                c.renew_signed(signatures).map_err(Status::internal)?
            }
            proto::renew_client_msg::Body::Registered(r) => {
                c.renew_registered(r.intent_id).map_err(Status::internal)?;
                RenewStep::Idle
            }
            proto::renew_client_msg::Body::Event(e) => match Option::try_from(e)? {
                Some(ev) => c.renew_on_event(ev).map_err(Status::internal)?,
                None => RenewStep::Idle,
            },
            proto::renew_client_msg::Body::Open(_) => {
                return Err(Status::invalid_argument("the session is already open"))
            }
            proto::renew_client_msg::Body::RenewDelegate(_) => {
                return Err(Status::invalid_argument(
                    "the delegate's renewal follows RenewComplete, not the round",
                ))
            }
        };
        drop(c);
    }
}

/// Enrol a device token carried in-band, if there is one. Whether it was, rather than an error: the
/// operation it rode on is what the caller asked for, and must not fail because a wake could not be
/// arranged — the wallet sends the token again next time.
pub(crate) fn enrol_device(cosigner: &Arc<Mutex<Cosigner>>, token: &str) -> bool {
    if token.is_empty() {
        return false;
    }
    lock(cosigner).host.register_device(token).is_ok()
}

