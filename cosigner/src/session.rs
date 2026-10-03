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
use crate::escrow::EscrowSession;
use crate::renew::{DelegateRenew, DelegateStream};
use crate::sign::SigningSession;
use crate::grpc::{self, Duplex, HasBody, SessionBody, Status};
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
            "Board" => ceremony!(board),
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

    /// See [`Cosigner::recover`]. Reads the seal; installs nothing.
    async fn recover(&self, body: Body) -> Result<proto::RecoverResponse, Status> {
        let req: proto::RecoverRequest = grpc::one_message(body).await?;
        lock(&self.cosigner).recover(req)
    }

    /// The escrows this wallet holds — public projection only, so a device that keeps nothing
    /// can ask what exists instead of remembering.
    async fn escrow_list(&self, body: Body) -> Result<proto::EscrowListResponse, Status> {
        let _: proto::EscrowListRequest = grpc::one_message(body).await?;
        // One reading of the clock for the whole listing, so two escrows are never described as of
        // two different moments.
        let now = crate::handlers::helpers::now_secs();
        let c = lock(&self.cosigner);
        Ok(proto::EscrowListResponse {
            escrows: c.list_escrow_sessions().iter().map(|e| e.summary(now)).collect(),
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

/// One signature, as one signing session.
///
/// The wallet used to commit first, in `SignOpen`. It cannot: its nonce is hedged with its share,
/// and it holds no share until this stream's first answer brings the half the cosigner dealt it.
/// So this is the round `Send` and `Renew` already run — the cosigner commits first, the wallet
/// answers with its commitments and its share together — over a single message.
///
/// Script-path only, like every signing session: the cosigner signs untweaked and `aggregate`
/// checks each share, so a key-path share could never have aggregated here. It is refused by name
/// rather than left to fail as a bad share.
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
    let dealt = lock(&cosigner).dealt_share_for(&open.identifier)?;

    // The round is OURS, as an ordinary local. The lock is released before we wait on the client —
    // a slow client blocks nobody.
    let messages = vec![open.message_to_sign.clone()];
    let key = lock(&cosigner).signing_key().map_err(Status::internal)?;
    let (signing, commitments) = SigningSession::begin(key, &messages);

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
    // If the client never sends it, or the stream dies here, `signing` drops with this task and the
    // nonce is gone. That is the safe failure: an abandoned round leaves nothing reusable.
    let share = match duplex.next_body("the share arrived").await? {
        sign_client_msg::Body::Share(s) => s,
        _ => return Err(Status::invalid_argument("expected SignShare")),
    };

    // A bad share is the caller's fault, and is reported as such rather than as ours.
    let signature = signing
        .finish(vec![share.into()])
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

/// Minting an escrow: one reshare, two exchanges, nothing parked — then pairing a service into it
/// and striking its deal.
///
/// The same shape as [`dkg`] and for the same reason — the round-1 and round-2 secrets are what the
/// key is born from, so they live on this frame and die with it. What differs is that both parties
/// already have keys: the reshare is dealt under the identifiers they hold in the wallet key, and
/// neither side's wallet share changes. See [`EscrowSession::begin_mint`].
///
/// When the open names a service, the stream goes on to pair it into the new escrow, the wallet
/// confirms on this stream, and the deal the open names is struck — so an escrow is set up for a
/// payment on one approval. One escrow, one deal: nothing commits an escrow but this stream, so
/// the next payment mints the next escrow. The pairing is usable once the service confirms too,
/// which can only arrive after this stream ends.
async fn escrow(
    cosigner: Arc<Mutex<Cosigner>>,
    duplex: Duplex<proto::EscrowClientMsg, proto::EscrowServerMsg>,
) -> Result<(), Status> {
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
        Some(crate::escrow::Service::resolve(&open.service_identifier)?)
    };
    let attempt_id_hex = hex::encode(&open.attempt_id);
    // And its deal, with it and only with it — checked here too, so terms that could never be
    // struck mint nothing. A deal nobody can release under would lock the money away until the
    // deadline for no one's benefit; a service with no deal is a pairing nothing could ever use.
    let terms = match &service {
        Some(_) => Some(crate::escrow::DealTerms::from_request(
            &open,
            crate::handlers::helpers::now_secs(),
        )?),
        None if open.policy_json.is_empty() && open.deadline_secs == 0 => None,
        None => {
            return Err(Status::invalid_argument(
                "a deal needs a service paired into its escrow to release under",
            ))
        }
    };

    // There is nothing to reshare before there is a wallet. Taken once, up front, so the ceremony
    // runs against one consistent view of the key it is derived from.
    let wallet = lock(&cosigner).signing_key().map_err(Status::failed_precondition)?;

    // The wallet's half of its own share, before anything is dealt — see `dealt_share_for`. A
    // reshare builds on the wallet share, so the wallet needs this to finalize its own side; and a
    // wallet whose ceremony kept no dealt share is refused here rather than at release: its owner
    // could not rebuild the share an escrow share is built on top of, so the escrow would be
    // spendable by this cosigner's half and nobody else's.
    let dealt = lock(&cosigner).dealt_share_for(&open.identifier)?;

    let (mint, our_round1) = EscrowSession::begin_mint(
        &wallet.key_package,
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
    let now = crate::handlers::helpers::now_secs();
    let (for_wallet, escrow) = EscrowSession::finalise_mint(
        mint,
        &wallet.key_package,
        &wallet.public_key_package,
        &round2.round2_package,
        now,
    )?;
    let escrow_key = escrow.escrow_key.clone();

    // Sealed before it is announced. A wallet told about an escrow this cosigner cannot co-sign for
    // would be a wallet that funds a key only half of which exists.
    {
        let mut c = lock(&cosigner);
        c.add_escrow(escrow).map_err(Status::failed_precondition)?;
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
    let (Some(service), Some(terms)) = (service, terms) else { return Ok(()) };

    // --- Pairing the service in ----------------------------------------------------------------
    let deal = match duplex.next_body("the wallet's dealing").await? {
        proto::escrow_client_msg::Body::Deal(d) => d,
        _ => return Err(Status::invalid_argument("expected PairServiceDeal")),
    };
    // This cosigner's half, dealt from the wallet's dealing, handed to the service, and only then
    // sealed pending — see "Deliver, then seal" in `crate::escrow`: this cosigner never keeps the
    // service's half, so a pairing sealed before a failed delivery could never be completed.
    let material = lock(&cosigner)
        .get_escrow_session(&escrow_key)
        .ok_or_else(|| Status::internal("the escrow this stream minted is gone"))?
        .prepare_pairing(
            &service.id,
            &deal.contribution_to_cosigner,
            &deal.contribution_to_service,
        )?;
    let host = lock(&cosigner).host();
    material
        .deliver(host.as_ref(), &service.origin, &escrow_key, &attempt_id_hex)
        .await
        .map_err(|e| {
            Status::unavailable(format!(
                "the service did not take its half, so nothing was paired: {e}"
            ))
        })?;
    let paired = proto::PairServiceDone {
        public_key_package_json: material.public_key_package_json.clone(),
        service_verifying_share: material.service_verifying_share_hex.clone(),
        // So the wallet delivers its own half to the same place. It does not choose an origin, and
        // could not: the list lives in the image.
        service_origin: service.origin.clone(),
    };
    let pairing =
        material.into_pairing(attempt_id_hex.clone(), crate::handlers::helpers::now_secs());
    {
        let mut c = lock(&cosigner);
        c.escrow_mut(&escrow_key)
            .and_then(|e| e.record_pairing(pairing))
            .map_err(Status::failed_precondition)?;
        c.seal();
    }
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
    // And the deal, with it: both halves are with the service now. Sealed before it is announced,
    // because the app goes on to fund the escrow and ask the service to pay against it.
    let confirmed = proto::PairServiceConfirmResponse {
        policy_description: terms.policy.describe(),
        deadline_secs: terms.deadline,
    };
    {
        let mut c = lock(&cosigner);
        c.escrow_mut(&escrow_key)
            .and_then(|e| {
                e.confirm_pairing(&attempt_id_hex, |p| p.wallet_confirmed = true)?;
                e.strike_deal(terms)
            })
            .map_err(Status::failed_precondition)?;
        c.try_seal().map_err(|e| {
            Status::unavailable(format!("the deal could not be saved ({e}); nothing was struck"))
        })?;
    }
    // Nothing is scheduled for the deadline, and nothing needs to be. A deadline is a fact about
    // the clock that every decision reads out of the seal — see `crate::escrow`.
    duplex.send(proto::EscrowServerMsg {
        session_id: session_id.clone(),
        seq: 4,
        body: Some(proto::escrow_server_msg::Body::Confirmed(confirmed)),
    });

    // --- Funding it, on this same approval ------------------------------------------------------
    //
    // Optional: a wallet that closes now funds the escrow with a send of its own. One that goes on
    // sends the price here, and the stream does what a `Send` would — except choose where the money
    // goes. That is not the wallet's to say: it is the escrow this stream minted, at the address
    // derived from the key this cosigner holds.
    let Some(next) = duplex.recv().await else { return Ok(()) };
    let open = match next.into_body().and_then(proto::EscrowServerMsg::uncarry) {
        Some(proto::send_client_msg::Body::Open(open)) => open,
        _ => {
            return Err(Status::invalid_argument(
                "after the deal only the send that funds the escrow may follow",
            ))
        }
    };
    if !open.recipient_ark_address.is_empty() || !open.reclaim_escrow.is_empty() {
        return Err(Status::invalid_argument(
            "a funding send names no recipient: it pays the escrow this stream minted",
        ));
    }
    let info = open
        .ark_info
        .map(ark::client::types::ArkInfo::from)
        .ok_or_else(|| Status::invalid_argument("the funding send carried no ark_info"))?;
    let (session, change_exit_delay, sighashes) = {
        let mut c = lock(&cosigner);
        let escrow_address = c
            .get_escrow_session(&escrow_key)
            .ok_or_else(|| Status::internal("the escrow this stream minted is gone"))?
            .funding_address(&info)?;
        let step1 = crate::types::SendVtxoStep1 {
            recipient_ark_address: escrow_address,
            amount: open.amount,
            vtxos: open.vtxos.into_iter().map(Into::into).collect(),
        };
        c.create_send_session(step1, &info).map_err(Status::internal)?
    };
    // No dealt share: the wallet rebuilt its own on this stream's first round, and one stream is
    // one reconstruction.
    drive_send(&cosigner, &duplex, &session_id, session, change_exit_delay, sighashes, vec![])
        .await
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
    use crate::onboarding::OnboardingSession;

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

    let r1 = sess.begin(
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
    let r3 = sess.finalise(
        wp::DkgStep3Request {
            identifier: round2.identifier,
            round2_packages_for_others: round2.round2_packages_for_others,
        },
    )?;
    let (Some(group_key), Some(key_package_json), Some(public_key_package_json)) =
        (sess.group_key.take(), sess.key_package_json.take(), sess.public_key_package_json.take())
    else {
        return Err(Status::internal("DKG finished without key material"));
    };

    // Install the key and seal it. No plaintext fallback: if this fails the ceremony fails, rather
    // than leaving a wallet whose key exists only in a reply.
    {
        let mut c = lock(&cosigner);
        c.install_key(
            group_key.clone(),
            &key_package_json,
            &public_key_package_json,
            sess.user_signing_identifier_hex.as_deref(),
            sess.wallet_dealt_share_hex.take(),
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
/// wallet's. See [`EscrowSession::prepare_reclaim`] for what is checked and what is derived rather
/// than accepted.
async fn reclaim(
    cosigner: Arc<Mutex<Cosigner>>,
    duplex: Duplex<proto::SendClientMsg, proto::SendServerMsg>,
    session_id: String,
    open: proto::SendOpen,
) -> Result<(), Status> {
    // Where it goes is derived, never named, and it takes everything the escrow holds.
    if !open.recipient_ark_address.is_empty() || open.amount != 0 {
        return Err(Status::invalid_argument(
            "a reclaim names no recipient or amount: it returns what the escrow holds to this \
             wallet",
        ));
    }
    let info = open
        .ark_info
        .map(ark::client::types::ArkInfo::from)
        .ok_or_else(|| Status::invalid_argument("SendOpen carried no ark_info"))?;

    let now = crate::handlers::helpers::now_secs();
    let mut reclaim = lock(&cosigner).prepare_reclaim(
        &open.reclaim_escrow,
        open.vtxos.into_iter().map(Into::into).collect(),
        &info,
        now,
    )?;

    // Nothing to retire before the round. Signatures it hands out can only empty this escrow, and
    // it is never committed to a deal again — the session that minted it struck its one deal.

    // Round one, on this stream, as a send does it: the cosigner commits first so the whole batch
    // costs one round trip — but with the ESCROW's share, not the wallet's.
    let (signing, commitments) = SigningSession::begin(reclaim.key, &reclaim.sighashes);

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
    let signatures = signing
        .finish(signed.rounds.into_iter().map(Into::into).collect())
        .map_err(Status::invalid_argument)?;
    let (ark_tx_b64, checkpoint_txs) =
        crate::cosigner::sign_and_prepare(&mut reclaim.session, &signatures)
            .map_err(Status::internal)?;

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
    let dealt = lock(&cosigner).dealt_share_for(&open.identifier)?;

    // Taking back what is left of an escrow is a send too, on this same stream — see [`reclaim`].
    if !open.reclaim_escrow.is_empty() {
        return reclaim(cosigner, duplex, session_id, open).await;
    }

    let info = open
        .ark_info
        .map(ark::client::types::ArkInfo::from)
        .ok_or_else(|| Status::invalid_argument("SendOpen carried no ark_info"))?;

    // The caller names its inputs, and the cosigner validates every one against the scriptPubKey it
    // derives from its own owner key before selecting — so naming a VTXO here cannot widen what the
    // wallet owns.
    let (session, change_exit_delay, sighashes) = {
        let step1 = crate::types::SendVtxoStep1 {
            recipient_ark_address: open.recipient_ark_address.clone(),
            amount: open.amount,
            vtxos: open.vtxos.iter().cloned().map(Into::into).collect(),
        };
        lock(&cosigner).create_send_session(step1, &info).map_err(Status::internal)?
    };

    drive_send(&cosigner, &duplex, &session_id, session, change_exit_delay, sighashes, dealt).await
}

/// A send's rounds, from its sighashes to its change recorded and an optional delegate renewal —
/// on whichever stream carries them ([`SendStream`]): `Send` itself, or `Escrow` funding the escrow
/// it has just minted. [dealt] rides the first sighashes: the wallet's dealt share when this is the
/// stream's first reconstruction of it, empty when the wallet has already rebuilt its share.
async fn drive_send<S: SendStream>(
    cosigner: &Arc<Mutex<Cosigner>>,
    duplex: &Duplex<S::In, S>,
    session_id: &str,
    mut session: ark::client::send::SendSession,
    change_exit_delay: u32,
    sighashes: Vec<Vec<u8>>,
    dealt: Vec<u8>,
) -> Result<(), Status> {
    let say = |seq, body| {
        duplex.send(S::carry(proto::SendServerMsg {
            session_id: session_id.to_string(),
            seq,
            body: Some(body),
        }))
    };

    // Round one of the FROST signature, on this stream. It used to be a nested `Sign` stream per
    // sighash, which deadlocks inside enclave-runtime — see `crate::sign`.
    let key = lock(cosigner).signing_key().map_err(Status::internal)?;
    let (signing, commitments) = SigningSession::begin(key, &sighashes);

    say(1, proto::send_server_msg::Body::Sighashes(proto::SendSighashes {
        wallet_dealt_share: dealt,
        ..proto::SendSighashes::round(sighashes, commitments)
    }));

    // --- The wallet's half of the round, then what it must submit --------------------------
    let signed = match next_send(duplex).await? {
        proto::send_client_msg::Body::Signed(s) => s,
        _ => return Err(Status::invalid_argument("expected SendSigned")),
    };
    // A bad share is the caller's fault, and is reported as such rather than as ours.
    let signatures = signing
        .finish(signed.rounds.into_iter().map(Into::into).collect())
        .map_err(Status::invalid_argument)?;
    let (ark_tx_b64, checkpoint_txs) =
        crate::cosigner::sign_and_prepare(&mut session, &signatures).map_err(Status::internal)?;

    say(2, proto::send_server_msg::Body::Submit(proto::SendSubmit {
        ark_tx_b64,
        checkpoint_txs,
    }));

    // --- What the ASP returned, turned into the finalize call ------------------------------
    let submitted = match next_send(duplex).await? {
        proto::send_client_msg::Body::Submitted(s) => s,
        _ => return Err(Status::invalid_argument("expected SendSubmitted")),
    };
    let final_checkpoint_txs = session
        .finalize_checkpoints(&submitted.signed_checkpoint_txs)
        .map_err(|e| Status::internal(format!("finalize checkpoints: {e}")))?;

    say(3, proto::send_server_msg::Body::Finalize(proto::SendFinalize {
        ark_txid: submitted.ark_txid.clone(),
        final_checkpoint_txs,
    }));

    // --- Accepted. Only now is it ours to record -------------------------------------------
    match next_send(duplex).await? {
        proto::send_client_msg::Body::Finalized(_) => {}
        _ => return Err(Status::invalid_argument("expected SendFinalized")),
    }
    {
        let mut c = lock(cosigner);
        c.finalise_send_session(session, change_exit_delay);
        c.seal();
    }

    say(4, proto::send_server_msg::Body::Complete(proto::SendComplete {
        ark_txid: submitted.ark_txid,
        change: None,
    }));

    // --- Optionally, renew the delegate over what the wallet holds now ---------------------
    //
    // On this stream so it rides the approval — and the passkey seed — the send already had. A
    // caller that closes instead has simply not asked for it.
    if let Some(msg) = duplex.recv().await {
        let request = match msg.into_body().and_then(S::uncarry) {
            Some(proto::send_client_msg::Body::RenewDelegate(r)) => r,
            _ => {
                return Err(Status::invalid_argument(
                    "after SendComplete only the delegate's renewal may follow",
                ))
            }
        };
        DelegateRenew::run(cosigner, duplex, request, session_id, 5, vec![]).await?;
    }
    Ok(())
}

/// The next step of a send, out of whatever its stream carries.
async fn next_send<S: SendStream>(
    duplex: &Duplex<S::In, S>,
) -> Result<proto::send_client_msg::Body, Status> {
    S::uncarry(duplex.next_body("mid-send").await?)
        .ok_or_else(|| Status::invalid_argument("expected the send's next step"))
}

/// A stream a send's rounds can ride, and how it carries a `Send` stream's messages: as they are,
/// or inside its own. Every one that does also carries the delegate renewal that may follow.
pub(crate) trait SendStream: DelegateStream {
    fn carry(msg: proto::SendServerMsg) -> Self;

    /// The `Send` stream's message in [body], or None if [body] is something else.
    fn uncarry(body: <Self::In as HasBody>::Body) -> Option<proto::send_client_msg::Body>;
}

impl SendStream for proto::SendServerMsg {
    fn carry(msg: proto::SendServerMsg) -> Self {
        msg
    }

    fn uncarry(body: proto::send_client_msg::Body) -> Option<proto::send_client_msg::Body> {
        Some(body)
    }
}

/// `Escrow`, funding the escrow it minted: a `Send` stream's messages, inside its own.
impl SendStream for proto::EscrowServerMsg {
    fn carry(msg: proto::SendServerMsg) -> Self {
        Self {
            session_id: msg.session_id.clone(),
            seq: msg.seq,
            body: Some(proto::escrow_server_msg::Body::Funding(msg)),
        }
    }

    fn uncarry(body: proto::escrow_client_msg::Body) -> Option<proto::send_client_msg::Body> {
        match body {
            proto::escrow_client_msg::Body::Fund(msg) => msg.body,
            _ => None,
        }
    }
}

impl DelegateStream for proto::EscrowServerMsg {
    type In = proto::EscrowClientMsg;

    fn sighashes(
        session_id: &str,
        seq: u64,
        to_sign: crate::renew::ToSign,
        wallet_dealt_share: Vec<u8>,
    ) -> Self {
        Self::carry(proto::SendServerMsg::sighashes(session_id, seq, to_sign, wallet_dealt_share))
    }

    fn signed(body: proto::escrow_client_msg::Body) -> Option<Vec<proto::WalletRound>> {
        Self::uncarry(body).and_then(proto::SendServerMsg::signed)
    }

    fn renewed(session_id: &str, seq: u64, renewed: proto::DelegateRenewed) -> Self {
        Self::carry(proto::SendServerMsg::renewed(session_id, seq, renewed))
    }
}

/// Renewing the VTXOs held, with the caller driving the ASP round.
///
/// The cosigner answers each relayed event with what to send the ASP next and never opens a socket
/// of its own. `ark_info` arrives from the caller for the same reason: it is the one talking to the
/// ASP. See `Cosigner::renew_begin` for why that cannot redirect funds.
async fn renew(
    cosigner: Arc<Mutex<Cosigner>>,
    duplex: Duplex<proto::RenewClientMsg, proto::RenewServerMsg>,
) -> Result<(), Status> {
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
    let mut dealt = Some(lock(&cosigner).dealt_share_for(&open.identifier)?);
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
    let vtxos = open.vtxos.into_iter().map(Into::into).collect();
    let sighashes = lock(&cosigner).renew_begin(vtxos, info).map_err(Status::internal)?;
    drive_round(&cosigner, &duplex, &session_id, dealt, sighashes).await
}

/// Boarding one on-chain output into Ark: the round `renew` drives, opened with `BoardOpen` on a
/// stream of its own.
async fn board(
    cosigner: Arc<Mutex<Cosigner>>,
    duplex: Duplex<proto::RenewClientMsg, proto::RenewServerMsg>,
) -> Result<(), Status> {
    let first = duplex.expect("it opened").await?;
    let session_id = first.session_id.clone();
    let open = match first.body {
        Some(proto::renew_client_msg::Body::Board(o)) => o,
        _ => return Err(Status::invalid_argument("a session must open with BoardOpen")),
    };
    // Authenticated by the runtime at open — see `sign` above.

    // The wallet's half of its own share, as `renew` hands it out: with the first sighashes.
    let dealt = lock(&cosigner).dealt_share_for(&open.identifier)?;
    tracing::info!("Board: returning the dealt share to the wallet's own identifier");

    let info = open
        .ark_info
        .map(ark::client::types::ArkInfo::from)
        .ok_or_else(|| Status::invalid_argument("BoardOpen carried no ark_info"))?;
    let utxo = open
        .utxo
        .map(|u| (u.txid, u.vout, u.amount_sats))
        .ok_or_else(|| Status::invalid_argument("BoardOpen carried no utxo"))?;
    let sighashes = lock(&cosigner).board_begin(utxo, &info).map_err(Status::internal)?;
    drive_round(&cosigner, &duplex, &session_id, Some(dealt), sighashes).await
}

/// The round `renew` and `board` share: from the first sighashes to `RenewComplete`, and the
/// delegate's renewal the caller may ask for after it. [dealt] goes out with the first sighashes,
/// unless the stream already spent it.
async fn drive_round(
    cosigner: &Arc<Mutex<Cosigner>>,
    duplex: &Duplex<proto::RenewClientMsg, proto::RenewServerMsg>,
    session_id: &str,
    mut dealt: Option<Vec<u8>>,
    sighashes: Vec<Vec<u8>>,
) -> Result<(), Status> {
    use crate::renew::RenewStep;

    let mut seq = 1u64;
    let mut step = RenewStep::Sighashes(sighashes);

    // The FROST round that is waiting for the wallet's half. A renewal signs twice — the intent
    // proof, and for a boarding settle the commitment transaction later — so this is set each time
    // sighashes go out and taken when the matching `Signed` comes back. Holding it here rather than
    // on the cosigner is what keeps the nonces on this stream's stack, where a dropped stream takes
    // them with it.
    let mut pending_round: Option<SigningSession> = None;

    loop {
        // Say what we need, then read what the caller did about it.
        let body = match step {
            RenewStep::Sighashes(messages_to_sign) => {
                // Round one, on this stream — see `crate::sign` for why it cannot be a nested
                // `Sign` any more.
                let key = lock(cosigner).signing_key().map_err(Status::internal)?;
                let (signing, commitments) = SigningSession::begin(key, &messages_to_sign);
                pending_round = Some(signing);
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
                    let mut c = lock(cosigner);
                    c.apply_boarding_settle(sub);
                    c.seal();
                }
                duplex.send(proto::RenewServerMsg {
                    session_id: session_id.to_string(),
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
                    DelegateRenew::run(cosigner, duplex, request, session_id, next, vec![])
                        .await?;
                }
                return Ok(());
            }
        };

        duplex.send(proto::RenewServerMsg {
            session_id: session_id.to_string(),
            seq,
            body,
        });
        seq += 1;

        let body = duplex.next_body("the next renewal step").await?;

        // Scoped to this iteration, and released before the loop comes back around to
        // `recv().await`. That used to matter because the caller opened a nested `Sign` on its own
        // connection while this stream was parked; signing rides this stream now, so nothing else
        // takes this lock mid-renewal — but holding a guard across an await is still the wrong
        // habit.
        let mut c = lock(cosigner);
        step = match body {
            proto::renew_client_msg::Body::Signed(s) => {
                let round = pending_round.take().ok_or_else(|| {
                    Status::invalid_argument("signatures arrived with no round waiting for them")
                })?;
                let signatures = round
                    .finish(s.rounds.into_iter().map(Into::into).collect())
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
            proto::renew_client_msg::Body::Open(_) | proto::renew_client_msg::Body::Board(_) => {
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

