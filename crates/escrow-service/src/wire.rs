//! The connection the enclave's runtime holds to this service, and what travels on it.
//!
//! # This service is a server for a connection it did not dial
//!
//! It has no passkey for Alice's tenant, so it can never call the cosigner. And the cosigner cannot
//! hold a socket, having no execution context between invocations. So the **runtime** holds one,
//! opened when the pairing happened, and re-dialled by the runtime whenever it drops.
//!
//! ```text
//!   GET  /escrow/stream?id=<tenant>-<stream>   held open, text/event-stream
//!   POST /escrow/send?id=<tenant>-<stream>     one message from the enclave, and its reply
//!   POST /pair/wallet                          Alice's device, delivering her half directly
//! ```
//!
//! # The id names the tenant, and that is load-bearing
//!
//! A stream id is tenant-local to the guest: the cosigner derives it from *this service's*
//! identifier, so every wallet it serves opens a connection under the same local name. The runtime
//! puts the tenant on the front, and this service keys its connections by the whole of it.
//!
//! Without that, two customers would collapse into one connection — each new one closing the last —
//! and a message sent here, which arrives as a POST with no connection identity of its own, could
//! not be answered down the right socket. That is not hypothetical; it is what happened, and it is
//! why `StreamRecord::wire_id` exists.
//!
//! # Nothing said here is believed by the cosigner
//!
//! This service claims a payment reference and proposes a transaction. The cosigner fetches the
//! evidence itself, with its own read-only credential, builds the transaction itself, and checks it
//! against a policy this service cannot see and did not write.

use std::collections::BTreeMap;
use std::sync::Arc;

use axum::extract::{Query, State};
use axum::http::StatusCode;
use axum::response::{IntoResponse, Sse};
use axum::routing::{get, post};
use axum::{Json, Router};
use cosigner::escrow::{FromService, ToService};
use serde::Deserialize;
use tokio::sync::mpsc;
use tokio_stream::StreamExt;

use super::Service;
use crate::signing::{NotPaired, PairedShare};
use crate::trust::EnclaveTrust;
use enclave_client::{KIND_OPEN, KIND_SEND};

/// One connection the runtime is holding, by the id it announced.
struct Held {
    /// What to write down it. `FromService` — the direction this service speaks.
    out: mpsc::UnboundedSender<FromService>,
    /// When the enclave signed the request that opened it, in milliseconds. A later open under the
    /// same id replaces this one only if it was signed later: an old document replayed must not be
    /// able to take a connection over.
    attested_ms: u64,
}

/// Every connection, and everything waiting to be said on one.
pub struct Connections {
    /// Which enclaves are believed. Every stream open and every message is checked against it
    /// before anything else happens — see [`crate::trust`].
    trust: EnclaveTrust,
    held: std::sync::Mutex<BTreeMap<String, Held>>,
    /// What could not be said because nothing was holding a connection. Sent on the next dial: the
    /// runtime re-establishes these, so a moment without one is a wait rather than a loss.
    waiting: std::sync::Mutex<BTreeMap<String, Vec<FromService>>>,
    /// Halves from Alice's device, by `escrow:attempt`, waiting for the cosigner's.
    from_wallet: std::sync::Mutex<BTreeMap<String, String>>,
    /// Halves from the cosigner, by the same key, waiting for Alice's.
    from_cosigner: std::sync::Mutex<BTreeMap<String, PendingHalf>>,
    /// Who is waiting for an answer, by the connection it was asked on and what it asked about.
    ///
    /// Registered before the question goes out, so an answer that comes back faster than this
    /// service can start listening still has somewhere to land. Keyed by the connection too: an
    /// answer is believed only from the connection the question went down, so an answer about
    /// one customer's request cannot be delivered on another's.
    waiters: std::sync::Mutex<BTreeMap<(String, String), tokio::sync::oneshot::Sender<ToService>>>,
    /// Answers nobody was waiting for. Kept so a walkthrough can show what was said.
    pub unclaimed: std::sync::Mutex<Vec<ToService>>,
}

impl Connections {
    pub fn new(trust: EnclaveTrust) -> Self {
        Self {
            trust,
            held: Default::default(),
            waiting: Default::default(),
            from_wallet: Default::default(),
            from_cosigner: Default::default(),
            waiters: Default::default(),
            unclaimed: Default::default(),
        }
    }
}

#[derive(Clone)]
struct PendingHalf {
    stream_id: String,
    half: String,
    service_identifier: String,
    public_key_package_json: String,
    service_verifying_share: String,
}

/// What the wallet delivers, straight from Alice's device.
#[derive(Debug, Deserialize)]
struct WalletHalf {
    escrow_key: String,
    attempt_id: String,
    contribution: String,
}

#[derive(Debug, Deserialize)]
struct StreamId {
    id: String,
}

pub struct Wire {
    pub service: Arc<Service>,
    pub connections: Arc<Connections>,
}

pub fn router(service: Arc<Service>, connections: Arc<Connections>) -> Router {
    let wire = Arc::new(Wire {
        service,
        connections,
    });
    Router::new()
        .route("/escrow/stream", get(hold))
        .route("/escrow/send", post(from_enclave))
        .route("/pair/wallet", post(from_wallet))
        .route("/status", get(status))
        .with_state(wire)
}

/// Hold a connection open, and say nothing until there is something to say.
///
/// Ending this response is not a failure — it is a reconnect, and the next dial arrives with the
/// same id. The runtime waits out a backoff and comes back.
async fn hold(
    State(wire): State<Arc<Wire>>,
    Query(StreamId { id }): Query<StreamId>,
    headers: axum::http::HeaderMap,
) -> axum::response::Response {
    let attested_ms = match admit(&wire, &headers, KIND_OPEN, &id, b"") {
        Ok(at) => at,
        Err(refused) => return refused,
    };
    let (tx, rx) = mpsc::unbounded_channel::<FromService>();
    {
        let mut held = wire.connections.held.lock().unwrap();
        // A second dial under the same id replaces the first: it IS the same connection,
        // re-dialled — provided it was signed after the one it replaces.
        if held.get(&id).is_some_and(|h| !h.out.is_closed() && h.attested_ms > attested_ms) {
            return (
                StatusCode::CONFLICT,
                Json(serde_json::json!({ "error": "a newer connection holds that id" })),
            )
                .into_response();
        }
        held.insert(
            id.clone(),
            Held {
                out: tx.clone(),
                attested_ms,
            },
        );
    }
    // Anything that had nowhere to go now does.
    let backlog = wire
        .connections
        .waiting
        .lock()
        .unwrap()
        .remove(&id)
        .unwrap_or_default();
    for message in backlog {
        let _ = tx.send(message);
    }

    // Server-sent events, with the payload base64'd: the runtime reads `id:` and `data:` and
    // expects the data to decode to the message bytes.
    let mut seq = 0u64;
    let events = tokio_stream::wrappers::UnboundedReceiverStream::new(rx).map(move |message| {
        seq += 1;
        let payload = serde_json::to_vec(&message).unwrap_or_default();
        use base64::Engine;
        Ok::<_, std::convert::Infallible>(
            axum::response::sse::Event::default()
                .id(format!("{}-{seq}", message.kind()))
                .data(base64::engine::general_purpose::STANDARD.encode(payload)),
        )
    });
    Sse::new(events)
        .keep_alive(axum::response::sse::KeepAlive::default())
        .into_response()
}

/// One message from the enclave, on the connection its runtime holds.
async fn from_enclave(
    State(wire): State<Arc<Wire>>,
    Query(StreamId { id }): Query<StreamId>,
    headers: axum::http::HeaderMap,
    body: axum::body::Bytes,
) -> axum::response::Response {
    if let Err(refused) = admit(&wire, &headers, KIND_SEND, &id, &body) {
        return refused;
    }
    let message: ToService = match serde_json::from_slice(&body) {
        Ok(m) => m,
        Err(e) => {
            return (
                StatusCode::BAD_REQUEST,
                Json(serde_json::json!({ "error": format!("undecodable: {e}") })),
            )
                .into_response()
        }
    };
    match message {
        ToService::PairingHalf {
            escrow_key,
            attempt_id,
            service_identifier,
            half,
            public_key_package_json,
            service_verifying_share,
        } => {
            // A half dealt for another service is not this one's to assemble, and filing it would
            // let whoever sent it choose the identifier a share is kept under.
            let ours = hex::encode(wire.service.identifier.serialize());
            if !service_identifier.eq_ignore_ascii_case(&ours) {
                return (
                    StatusCode::BAD_REQUEST,
                    Json(serde_json::json!({ "error": "that half was dealt for another service" })),
                )
                    .into_response();
            }
            let key = pair_key(&escrow_key, &attempt_id);
            wire.connections.from_cosigner.lock().unwrap().insert(
                key.clone(),
                PendingHalf {
                    stream_id: id,
                    half,
                    service_identifier,
                    public_key_package_json,
                    service_verifying_share,
                },
            );
            // Waiting is the ordinary outcome: Alice's half may not have arrived yet, and the
            // refusal cases have already been reported on the connection by `settle`.
            let _ = settle(&wire, &escrow_key, &attempt_id).await;
        }
        // An answer to something this service asked. Recorded for whoever is waiting on it.
        other => {
            let about = match &other {
                ToService::Ack { about } | ToService::Refused { about, .. } => about.clone(),
                ToService::ReleaseSigned(a) => a.request_id.clone(),
                ToService::ReleaseRefused { request_id, .. } => request_id.clone(),
                ToService::PairingHalf { attempt_id, .. } => attempt_id.clone(),
            };
            let waiter = wire.connections.waiters.lock().unwrap().remove(&(id.clone(), about));
            match waiter {
                Some(tx) => {
                    let _ = tx.send(other);
                }
                None => wire.connections.unclaimed.lock().unwrap().push(other),
            }
        }
    }
    (StatusCode::OK, Json(serde_json::json!({ "ok": true }))).into_response()
}

/// Alice's half, from her device. Nothing public comes with it — it is one scalar, checked against
/// the package the cosigner sent.
async fn from_wallet(
    State(wire): State<Arc<Wire>>,
    Json(half): Json<WalletHalf>,
) -> axum::response::Response {
    let key = pair_key(&half.escrow_key, &half.attempt_id);
    wire.connections
        .from_wallet
        .lock()
        .unwrap()
        .insert(key, half.contribution);
    let outcome = settle(&wire, &half.escrow_key, &half.attempt_id).await;
    match outcome {
        Ok(()) => (StatusCode::OK, Json(serde_json::json!({ "state": "ready" }))).into_response(),
        Err(NotPaired::Waiting) => (
            StatusCode::ACCEPTED,
            Json(serde_json::json!({ "state": "waiting" })),
        )
            .into_response(),
        Err(why) => (
            StatusCode::BAD_REQUEST,
            Json(serde_json::json!({ "error": why.message() })),
        )
            .into_response(),
    }
}

/// Both halves present? Then assemble and check, and tell the cosigner either way.
///
/// The check is the whole of this service's trust in either delivery. Until it passes there is no
/// share, and this service says nothing about being paired.
async fn settle(wire: &Arc<Wire>, escrow_key: &str, attempt_id: &str) -> Result<(), NotPaired> {
    let key = pair_key(escrow_key, attempt_id);
    let from_wallet = wire.connections.from_wallet.lock().unwrap().get(&key).cloned();
    let from_cosigner = wire.connections.from_cosigner.lock().unwrap().get(&key).cloned();
    let (Some(wallet_half), Some(pending)) = (from_wallet, from_cosigner) else {
        return Err(NotPaired::Waiting);
    };

    let assembled = PairedShare::assemble(
        escrow_key.to_string(),
        attempt_id.to_string(),
        pending.stream_id.clone(),
        pending.service_identifier.clone(),
        &pending.half,
        &wallet_half,
        pending.public_key_package_json.clone(),
        &pending.service_verifying_share,
    );

    match assembled {
        Ok(share) => {
            // Never over a share this service already holds and is using, or one that arrived on
            // another customer's connection. Two halves chosen together check out against a
            // verifying share chosen with them, so the check above says nothing about whether a
            // replacement is the real pairing — and a share swapped under a live payout is one the
            // cosigner's half no longer matches, so the payout is never repaid.
            let refused = {
                let mut store = wire.service.store.lock().await;
                let held = store.shares.get(&escrow_key.to_ascii_lowercase());
                let in_use = store.reimbursements.values().any(|r| {
                    r.escrow_key.eq_ignore_ascii_case(escrow_key)
                        && !r.given_up
                        && r.stage < crate::Stage::ReleaseConfirmed
                });
                match held {
                    Some(held) if held.stream_id != share.stream_id => Some(
                        "this escrow is already paired, on another connection".to_string(),
                    ),
                    Some(_) if in_use => Some(
                        "this escrow is already paired and has a payment in progress".to_string(),
                    ),
                    _ => {
                        store.shares.insert(escrow_key.to_ascii_lowercase(), share);
                        None
                    }
                }
            };
            if let Some(why) = refused {
                say(
                    wire,
                    &pending.stream_id,
                    FromService::PairingRefused {
                        escrow_key: escrow_key.to_string(),
                        attempt_id: attempt_id.to_string(),
                        reason: why.clone(),
                    },
                );
                forget(wire, &key);
                return Err(NotPaired::AlreadyHeld(why));
            }
            // Written down BEFORE it is called ready, and a failure to write is a failure to pair.
            //
            // Saying ready is what lets the owner commit money to this escrow. A share that only
            // exists in memory is one a restart loses — and then the cosigner holds a pairing it
            // believes is finished, against a service that can no longer sign. The money would sit
            // there until the deadline with nobody able to release it.
            if let Err(e) = wire.service.persist().await {
                tracing::warn!(error = %e, "the pairing could not be written down; refusing it");
                // Out of memory too, so what this service holds matches what it just told the
                // cosigner. The contributions are kept: the wallet retries its half, and the same
                // attempt reassembles.
                wire.service
                    .store
                    .lock()
                    .await
                    .shares
                    .remove(&escrow_key.to_ascii_lowercase());
                let why = format!("this service could not store the share: {e}");
                say(
                    wire,
                    &pending.stream_id,
                    FromService::PairingRefused {
                        escrow_key: escrow_key.to_string(),
                        attempt_id: attempt_id.to_string(),
                        reason: why.clone(),
                    },
                );
                return Err(NotPaired::NotStored(why));
            }
            // The service's half of "this pairing works", and the only party that can say it: it is
            // the only one that ever holds both halves.
            say(
                wire,
                &pending.stream_id,
                FromService::PairingReady {
                    escrow_key: escrow_key.to_string(),
                    attempt_id: attempt_id.to_string(),
                },
            );
            forget(wire, &key);
            Ok(())
        }
        Err(NotPaired::Waiting) => Err(NotPaired::Waiting),
        Err(why) => {
            say(
                wire,
                &pending.stream_id,
                FromService::PairingRefused {
                    escrow_key: escrow_key.to_string(),
                    attempt_id: attempt_id.to_string(),
                    reason: why.message(),
                },
            );
            forget(wire, &key);
            Err(why)
        }
    }
}

/// Is this request the enclave's, on a connection meant for this service? The first thing either
/// enclave route asks; nothing it says is looked at until the answer is yes.
///
/// The id must name this service's stream — the runtime puts `<tenant>-svc-<this service>` on
/// every request it makes here — and the attestation must bind exactly this id and these bytes.
#[allow(clippy::result_large_err)]
fn admit(
    wire: &Arc<Wire>,
    headers: &axum::http::HeaderMap,
    kind: &str,
    id: &str,
    body: &[u8],
) -> Result<u64, axum::response::Response> {
    let ours = cosigner::escrow::service_stream_id(&hex::encode(
        wire.service.identifier.serialize(),
    ));
    if !id.ends_with(&format!("-{ours}")) {
        return Err((
            StatusCode::BAD_REQUEST,
            Json(serde_json::json!({ "error": "that connection is not for this service" })),
        )
            .into_response());
    }
    wire.connections
        .trust
        .verify(headers, kind, id, body)
        .map_err(|why| {
            tracing::warn!(%id, %kind, %why, "refused a request that is not the enclave's");
            (
                StatusCode::UNAUTHORIZED,
                Json(serde_json::json!({ "error": why })),
            )
                .into_response()
        })
}

fn forget(wire: &Arc<Wire>, key: &str) {
    wire.connections.from_wallet.lock().unwrap().remove(key);
    wire.connections.from_cosigner.lock().unwrap().remove(key);
}

/// Say something on the connection the runtime is holding, or keep it for the next one.
///
/// A send that fails means the far side went away: the receiver is gone with the response that was
/// holding it. The entry is dropped rather than left to be picked as though it were live — a dead
/// connection that still answers `held_ids` is how a message goes nowhere and a caller waits for an
/// answer that was never sent.
pub fn say(wire: &Arc<Wire>, stream_id: &str, message: FromService) {
    let sent = {
        let mut held = wire.connections.held.lock().unwrap();
        match held.get(stream_id) {
            Some(connection) if connection.out.send(message.clone()).is_ok() => true,
            Some(_) => {
                held.remove(stream_id);
                false
            }
            None => false,
        }
    };
    if !sent {
        wire.connections
            .waiting
            .lock()
            .unwrap()
            .entry(stream_id.to_string())
            .or_default()
            .push(message);
    }
}

/// What this service has been told and what it is tracking, for a walkthrough.
async fn status(State(wire): State<Arc<Wire>>) -> axum::response::Response {
    let tracked = wire.service.tracked().await;
    let paired: Vec<String> = wire
        .service
        .store
        .lock()
        .await
        .shares
        .keys()
        .cloned()
        .collect();
    Json(serde_json::json!({
        "paired_escrows": paired,
        "reimbursements": tracked.iter().map(|r| serde_json::json!({
            "request_id": r.request_id,
            "stage": r.stage.label(),
            "started": r.started_ref,
            "settled": r.settled_ref,
            "given_up": r.given_up,
            "sats": r.sats,
            "ark_txid": r.ark_txid,
            "last_refusal": r.last_refusal,
        })).collect::<Vec<_>>(),
    }))
    .into_response()
}

fn pair_key(escrow_key: &str, attempt_id: &str) -> String {
    format!(
        "{}:{}",
        escrow_key.to_ascii_lowercase(),
        attempt_id.to_ascii_lowercase()
    )
}

impl Connections {
    /// Say that an answer to `about` is expected on `stream_id`, and hand back where it will
    /// arrive. An answer to the same question on any other connection is not this one.
    ///
    /// Called before the question is asked. An answer that comes back before this service is
    /// listening would otherwise be recorded as unclaimed and waited for for ever.
    pub fn expect(&self, stream_id: &str, about: &str) -> tokio::sync::oneshot::Receiver<ToService> {
        let (tx, rx) = tokio::sync::oneshot::channel();
        self.waiters
            .lock()
            .unwrap()
            .insert((stream_id.to_string(), about.to_string()), tx);
        rx
    }

    /// Stop waiting — the ask failed before it was sent, or timed out.
    pub fn stop_expecting(&self, stream_id: &str, about: &str) {
        self.waiters
            .lock()
            .unwrap()
            .remove(&(stream_id.to_string(), about.to_string()));
    }

    /// Whether the runtime is holding a connection under this id.
    pub fn is_holding(&self, stream_id: &str) -> bool {
        self.held.lock().unwrap().contains_key(stream_id)
    }

    /// How many connections are held whose id ends in `local` — one per wallet the enclave serves,
    /// all announcing the same local name. See the module note.
    pub fn held_under(&self, local: &str) -> usize {
        self.held
            .lock()
            .unwrap()
            .keys()
            .filter(|id| id.ends_with(&format!("-{local}")))
            .count()
    }

    /// The id of the connection this escrow's pairing arrived on.
    pub fn stream_for(&self, escrow_key: &str, attempt_id: &str) -> Option<String> {
        self.from_cosigner
            .lock()
            .unwrap()
            .get(&pair_key(escrow_key, attempt_id))
            .map(|p| p.stream_id.clone())
    }

    /// How many messages are waiting for a connection under this id.
    pub fn waiting_for(&self, stream_id: &str) -> usize {
        self.waiting
            .lock()
            .unwrap()
            .get(stream_id)
            .map_or(0, |queued| queued.len())
    }

    /// Drop every held connection, as a network that went away would.
    ///
    /// For demonstrating recovery, which is the only way to show it is real. The runtime notices
    /// the stream end, waits out its backoff and dials again; anything that could not be said
    /// meanwhile is kept and goes out on the next one.
    pub fn drop_all(&self) -> usize {
        let mut held = self.held.lock().unwrap();
        let dropped = held.len();
        // Dropping the sender closes the channel, which ends the response holding the stream open.
        held.clear();
        dropped
    }

    /// Every connection currently held, by id — pruning any whose far side has gone.
    ///
    /// `UnboundedSender::is_closed` is the only signal there is: the receiver lives inside the
    /// response that is holding the stream open, so it is dropped exactly when that response ends.
    pub fn held_ids(&self) -> Vec<String> {
        let mut held = self.held.lock().unwrap();
        held.retain(|_, connection| !connection.out.is_closed());
        held.keys().cloned().collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{Reimbursement, Stage};
    use k256::elliptic_curve::Field;

    const ESCROW: &str = "02aa";

    fn wire() -> Arc<Wire> {
        Arc::new(Wire {
            service: Service::new(
                threshold::identifier::Identifier::derive(b"test-service").unwrap(),
                "ark1example".into(),
                "http://127.0.0.1:7070".into(),
                None,
            ),
            connections: Arc::new(Connections::new(EnclaveTrust::accept_all())),
        })
    }

    /// The wire id the runtime uses for `tenant`'s connection to this service.
    fn stream(wire: &Arc<Wire>, tenant: &str) -> String {
        let ours = hex::encode(wire.service.identifier.serialize());
        format!("{tenant}-{}", cosigner::escrow::service_stream_id(&ours))
    }

    async fn post(wire: &Arc<Wire>, stream: &str, message: &ToService) -> StatusCode {
        from_enclave(
            State(wire.clone()),
            Query(StreamId { id: stream.into() }),
            axum::http::HeaderMap::new(),
            serde_json::to_vec(message).unwrap().into(),
        )
        .await
        .status()
    }

    /// Two halves that genuinely sum to the verifying share they come with — the cosigner's, for
    /// the wire, and the wallet's, for `/pair/wallet`.
    fn halves(wire: &Arc<Wire>, attempt: &str, for_service: Option<&str>) -> (ToService, WalletHalf) {
        let (a, b) = (k256::Scalar::random(&mut rand::rngs::OsRng), k256::Scalar::random(&mut rand::rngs::OsRng));
        let group = threshold::point::base_mul(&k256::Scalar::random(&mut rand::rngs::OsRng));
        let package = threshold::keys::PublicKeyPackage {
            verifying_shares: BTreeMap::new(),
            verifying_key: threshold::keys::VerifyingKey::new(group),
        };
        let ours = hex::encode(wire.service.identifier.serialize());
        let hex32 = |s: &k256::Scalar| hex::encode(threshold::scalar::scalar_to_bytes(s));
        (
            ToService::PairingHalf {
                escrow_key: ESCROW.into(),
                attempt_id: attempt.into(),
                service_identifier: for_service.map_or(ours, str::to_string),
                half: hex32(&b),
                public_key_package_json: package.to_json(),
                service_verifying_share: hex::encode(threshold::point::serialize_compressed(
                    &threshold::point::base_mul(&(a + b)),
                )),
            },
            WalletHalf {
                escrow_key: ESCROW.into(),
                attempt_id: attempt.into(),
                contribution: hex32(&a),
            },
        )
    }

    async fn pair(wire: &Arc<Wire>, stream: &str, attempt: &str) -> StatusCode {
        let (from_cosigner, from_device) = halves(wire, attempt, None);
        assert_eq!(post(wire, stream, &from_cosigner).await, StatusCode::OK);
        from_wallet(State(wire.clone()), Json(from_device)).await.status()
    }

    async fn held_attempt(wire: &Arc<Wire>) -> Option<String> {
        let store = wire.service.store.lock().await;
        store.shares.get(ESCROW).map(|s| s.attempt_id.clone())
    }

    /// C-1's lever: an answer is believed only from the connection the question went down. The
    /// same words posted under another customer's id reach nobody.
    #[tokio::test]
    async fn an_answer_on_another_connection_does_not_reach_whoever_asked() {
        let wire = wire();
        let mut answer = wire.connections.expect(&stream(&wire, "a"), "reimb-0001");
        let refusal = ToService::ReleaseRefused {
            request_id: "reimb-0001".into(),
            reason: r#"status is "PENDING", not "COMPLETED""#.into(),
            deal: None,
        };

        post(&wire, &stream(&wire, "b"), &refusal).await;
        assert!(answer.try_recv().is_err(), "an answer from another connection was believed");
        assert_eq!(wire.connections.unclaimed.lock().unwrap().len(), 1);

        post(&wire, &stream(&wire, "a"), &refusal).await;
        assert!(answer.try_recv().is_ok(), "and the real one still lands");
    }

    /// C-1 itself: without the runtime's attestation, nothing posted here is heard — not even the
    /// exact words a waiting caller is listening for, on the right connection.
    #[tokio::test]
    async fn nothing_unattested_is_heard() {
        let wire = Arc::new(Wire {
            service: wire().service.clone(),
            connections: Arc::new(Connections::new(EnclaveTrust::from_files(vec![
                "/nonexistent/enclave-pins.json".into(),
            ]))),
        });
        let on = stream(&wire, "a");
        let mut answer = wire.connections.expect(&on, "reimb-0001");
        let forged = ToService::ReleaseRefused {
            request_id: "reimb-0001".into(),
            reason: r#"status is "PENDING", not "COMPLETED""#.into(),
            deal: None,
        };
        assert_eq!(post(&wire, &on, &forged).await, StatusCode::UNAUTHORIZED);
        assert!(answer.try_recv().is_err(), "a forged answer reached the caller");
        assert!(wire.connections.unclaimed.lock().unwrap().is_empty());

        let dialled = hold(
            State(wire.clone()),
            Query(StreamId { id: on.clone() }),
            axum::http::HeaderMap::new(),
        )
        .await;
        assert_eq!(dialled.status(), StatusCode::UNAUTHORIZED);
        assert!(!wire.connections.is_holding(&on), "an unattested dial took a connection");
    }

    #[tokio::test]
    async fn a_connection_named_for_another_service_is_refused() {
        let wire = wire();
        let theirs = format!("a-{}", cosigner::escrow::service_stream_id(&"77".repeat(32)));
        let (half, _) = halves(&wire, "a1", None);
        assert_eq!(post(&wire, &theirs, &half).await, StatusCode::BAD_REQUEST);
    }

    #[tokio::test]
    async fn a_half_dealt_for_another_service_is_not_filed() {
        let wire = wire();
        let (half, _) = halves(&wire, "a1", Some(&"77".repeat(32)));
        assert_eq!(post(&wire, &stream(&wire, "a"), &half).await, StatusCode::BAD_REQUEST);
        assert!(wire.connections.from_cosigner.lock().unwrap().is_empty());
    }

    /// H-2: a pairing that checks out is still not allowed to replace a share this service holds
    /// and is using, nor one that arrived on another customer's connection.
    #[tokio::test]
    async fn a_share_in_use_or_from_elsewhere_is_never_replaced() {
        let wire = wire();
        assert_eq!(pair(&wire, &stream(&wire, "a"), "a1").await, StatusCode::OK);
        assert_eq!(held_attempt(&wire).await.as_deref(), Some("a1"));

        // Another customer's connection, halves that check out: refused.
        assert_eq!(pair(&wire, &stream(&wire, "b"), "a2").await, StatusCode::BAD_REQUEST);
        assert_eq!(held_attempt(&wire).await.as_deref(), Some("a1"));

        // The same connection re-pairing an idle escrow is a pairing done again: allowed.
        assert_eq!(pair(&wire, &stream(&wire, "a"), "a3").await, StatusCode::OK);
        assert_eq!(held_attempt(&wire).await.as_deref(), Some("a3"));

        // With a payout in progress, not even from the same connection.
        wire.service.store.lock().await.reimbursements.insert(
            "reimb-0001".into(),
            Reimbursement {
                request_id: "reimb-0001".into(),
                escrow_key: ESCROW.into(),
                started_ref: "Transaction:1".into(),
                settled_ref: None,
                amount_minor: 3_000_000,
                currency: "NGN".into(),
                sats: 23_010,
                stage: Stage::Started,
                last_refusal: None,
                needs_reconciliation: false,
                proposal: None,
                signatures: Vec::new(),
                expected_txid: None,
                ark_txid: None,
                given_up: false,
            },
        );
        assert_eq!(pair(&wire, &stream(&wire, "a"), "a4").await, StatusCode::BAD_REQUEST);
        assert_eq!(held_attempt(&wire).await.as_deref(), Some("a3"));
    }
}
