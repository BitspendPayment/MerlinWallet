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
use cosigner::service_stream::{FromService, ToService};
use serde::Deserialize;
use tokio::sync::mpsc;
use tokio_stream::StreamExt;

use super::Service;
use crate::service::signing::{NotPaired, PairedShare};

/// One connection the runtime is holding, by the id it announced.
struct Held {
    /// What to write down it. `FromService` — the direction this service speaks.
    out: mpsc::UnboundedSender<FromService>,
}

/// Every connection, and everything waiting to be said on one.
#[derive(Default)]
pub struct Connections {
    held: std::sync::Mutex<BTreeMap<String, Held>>,
    /// What could not be said because nothing was holding a connection. Sent on the next dial: the
    /// runtime re-establishes these, so a moment without one is a wait rather than a loss.
    waiting: std::sync::Mutex<BTreeMap<String, Vec<FromService>>>,
    /// Halves from Alice's device, by `escrow:attempt`, waiting for the cosigner's.
    from_wallet: std::sync::Mutex<BTreeMap<String, String>>,
    /// Halves from the cosigner, by the same key, waiting for Alice's.
    from_cosigner: std::sync::Mutex<BTreeMap<String, PendingHalf>>,
    /// Who is waiting for an answer, by what they asked about.
    ///
    /// Registered before the question goes out, so an answer that comes back faster than this
    /// service can start listening still has somewhere to land.
    waiters: std::sync::Mutex<BTreeMap<String, tokio::sync::oneshot::Sender<ToService>>>,
    /// Answers nobody was waiting for. Kept so a walkthrough can show what was said.
    pub unclaimed: std::sync::Mutex<Vec<ToService>>,
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
) -> axum::response::Response {
    let (tx, rx) = mpsc::unbounded_channel::<FromService>();
    {
        let mut held = wire.connections.held.lock().unwrap();
        // A second dial under the same id replaces the first: it IS the same connection, re-dialled.
        held.insert(id.clone(), Held { out: tx.clone() });
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
    body: axum::body::Bytes,
) -> axum::response::Response {
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
            let waiter = wire.connections.waiters.lock().unwrap().remove(&about);
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
            {
                let mut store = wire.service.store.lock().await;
                store.shares.insert(escrow_key.to_ascii_lowercase(), share);
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
            "authorization": r.authorization_token,
            "clearing": r.clearing_token,
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
    /// Say that an answer to `about` is expected, and hand back where it will arrive.
    ///
    /// Called before the question is asked. An answer that comes back before this service is
    /// listening would otherwise be recorded as unclaimed and waited for for ever.
    pub fn expect(&self, about: &str) -> tokio::sync::oneshot::Receiver<ToService> {
        let (tx, rx) = tokio::sync::oneshot::channel();
        self.waiters.lock().unwrap().insert(about.to_string(), tx);
        rx
    }

    /// Stop waiting — the ask failed before it was sent, or timed out.
    pub fn stop_expecting(&self, about: &str) {
        self.waiters.lock().unwrap().remove(about);
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
