//! Two customers on one service, over real connections.
//!
//! # Why this exists
//!
//! The enclave derives its stream id from the **service**, so every wallet it serves opens a
//! connection under the same local name. Only the tenant the runtime puts in front tells them
//! apart. A service that keyed its connections by the local half would have each new customer
//! close the last one's, and — because a message sent to a service arrives as a POST of its own,
//! carrying no connection identity beyond that id — would answer down whichever socket it happened
//! to have.
//!
//! That is not hypothetical. It happened, in the Dart fixture, and it is why `StreamRecord::wire_id`
//! names the tenant. This service is a **second, independent implementation** of the same routing,
//! and until now nothing exercised it with two connections actually present.
//!
//! # What is being tested, and what is not
//!
//! The service's own routing, over real HTTP against the real router. Not the cosigner, which is
//! not involved — and which fails closed anyway if a message ever does reach the wrong wallet: the
//! guest is handed its own local id, looks up an escrow it does not hold, and refuses.
//!
//! So a crossed wire costs a stuck request, not a stolen one. This pins that it does not happen at
//! all.

use std::sync::Arc;
use std::time::Duration;

use card_escrow::policy::Terms;
use card_escrow::service::wire::{router, say, Connections, Wire};
use card_escrow::service::Service;
use cosigner::service_stream::FromService;
use futures_util::StreamExt;

/// The id the enclave opens under — the same for every wallet this service serves.
const LOCAL: &str = "svc-4444444444444444444444444444444444444444";

fn wire_id(tenant: &str) -> String {
    format!("{tenant}-{LOCAL}")
}

/// One customer's held connection, and what has arrived on it.
struct Held {
    events: tokio::sync::mpsc::UnboundedReceiver<serde_json::Value>,
    /// The task reading the stream. It owns the response, so aborting it is what closes the
    /// socket — dropping a `JoinHandle` does not stop a task, and a reader that keeps reading is a
    /// client that has not gone away.
    reader: tokio::task::JoinHandle<()>,
}

impl Drop for Held {
    fn drop(&mut self) {
        self.reader.abort();
    }
}

impl Held {
    /// The next message, or `None` if nothing arrives in time.
    async fn next(&mut self) -> Option<serde_json::Value> {
        tokio::time::timeout(Duration::from_secs(3), self.events.recv())
            .await
            .ok()
            .flatten()
    }

    /// Assert nothing arrives. A shorter wait, because proving a negative is a matter of patience
    /// and this one only has to outlast the delivery it is checking did not happen.
    async fn nothing(&mut self) -> bool {
        tokio::time::timeout(Duration::from_millis(600), self.events.recv())
            .await
            .is_err()
    }
}

/// Open a connection the way the runtime does, and decode what comes down it.
async fn hold(base: &str, id: &str) -> Held {
    let (tx, events) = tokio::sync::mpsc::unbounded_channel();
    let url = format!("{base}/escrow/stream?id={id}");
    let response = reqwest::Client::new()
        .get(&url)
        .header("accept", "text/event-stream")
        .send()
        .await
        .expect("the service holds a connection");
    assert!(response.status().is_success());

    let task = tokio::spawn(async move {
        let mut stream = response.bytes_stream();
        let mut buffer = String::new();
        while let Some(Ok(chunk)) = stream.next().await {
            buffer.push_str(&String::from_utf8_lossy(&chunk));
            // An event ends at a blank line; a frame boundary is not an event boundary.
            while let Some(end) = buffer.find("\n\n") {
                let block: String = buffer.drain(..end + 2).collect();
                let Some(data) = block
                    .lines()
                    .find_map(|line| line.strip_prefix("data:"))
                    .map(str::trim)
                else {
                    continue; // the comment the service opens with, or a keepalive
                };
                use base64::Engine;
                let bytes = base64::engine::general_purpose::STANDARD
                    .decode(data)
                    .expect("the service base64s its payloads");
                let _ = tx.send(serde_json::from_slice(&bytes).expect("JSON"));
            }
        }
    });

    Held {
        events,
        reader: task,
    }
}

/// The service, its router, and the address it is listening on.
async fn service() -> (Arc<Wire>, String) {
    let service = Service::new(
        threshold::identifier::Identifier::derive(b"merlin-e2e-escrow-service").unwrap(),
        "ark1service".into(),
        "http://127.0.0.1:7070".into(),
        "http://127.0.0.1:7100".into(),
        Terms::example("ark1service".into(), "http://127.0.0.1:7100".into()),
        None,
    );
    let connections = Arc::new(Connections::default());
    let wire = Arc::new(Wire {
        service: Arc::clone(&service),
        connections: Arc::clone(&connections),
    });

    let listener = tokio::net::TcpListener::bind(("127.0.0.1", 0)).await.unwrap();
    let base = format!("http://{}", listener.local_addr().unwrap());
    let app = router(service, connections);
    tokio::spawn(async move {
        let _ = axum::serve(listener, app).await;
    });
    (wire, base)
}

fn ready(escrow: &str) -> FromService {
    FromService::PairingReady {
        escrow_key: escrow.into(),
        attempt_id: "aa".repeat(16),
    }
}

/// Wait for the service to notice a connection has come or gone.
async fn until(wire: &Arc<Wire>, id: &str, held: bool) {
    for _ in 0..60 {
        if wire.connections.held_ids().iter().any(|h| h == id) == held {
            return;
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    panic!("the connection {id} never became {}", if held { "held" } else { "gone" });
}

// ===============================================================================================

/// Each customer gets their own messages, and only their own.
#[tokio::test]
async fn two_customers_receive_only_their_own_events() {
    let (wire, base) = service().await;
    let (alice, bob) = (wire_id("aaaa"), wire_id("bbbb"));

    let mut alices = hold(&base, &alice).await;
    let mut bobs = hold(&base, &bob).await;
    until(&wire, &alice, true).await;
    until(&wire, &bob, true).await;
    assert_eq!(
        wire.connections.held_under(LOCAL),
        2,
        "two customers, one local name, two connections"
    );

    say(&wire, &alice, ready("02aaaa"));
    say(&wire, &bob, ready("02bbbb"));

    let to_alice = alices.next().await.expect("Alice's message");
    let to_bob = bobs.next().await.expect("Bob's message");
    assert_eq!(to_alice["escrow_key"], "02aaaa");
    assert_eq!(to_bob["escrow_key"], "02bbbb");

    // And neither got a second one — which is what "did not also receive the other's" means.
    assert!(alices.nothing().await, "Alice received something of Bob's");
    assert!(bobs.nothing().await, "Bob received something of Alice's");
}

/// One customer's connection going away leaves the other's alone.
///
/// This is the regression. The first implementation replaced a connection whenever another arrived
/// under the same local name, so a second customer silently disconnected the first.
#[tokio::test]
async fn one_customer_disconnecting_does_not_disturb_the_other() {
    let (wire, base) = service().await;
    let (alice, bob) = (wire_id("aaaa"), wire_id("bbbb"));

    let alices = hold(&base, &alice).await;
    let mut bobs = hold(&base, &bob).await;
    until(&wire, &alice, true).await;
    until(&wire, &bob, true).await;

    // Alice goes away, as a network partition would take her.
    drop(alices);
    say(&wire, &alice, ready("02aaaa"));
    until(&wire, &alice, false).await;

    // Bob is untouched, and still hears what is said to him.
    assert!(
        wire.connections.held_ids().iter().any(|h| *h == bob),
        "Bob's connection went with Alice's"
    );
    say(&wire, &bob, ready("02bbbb"));
    let to_bob = bobs.next().await.expect("Bob is still connected");
    assert_eq!(to_bob["escrow_key"], "02bbbb");
}

/// What could not be said is kept for the customer it was for, and nobody else.
#[tokio::test]
async fn a_backlog_belongs_to_the_customer_it_was_for() {
    let (wire, base) = service().await;
    let (alice, bob) = (wire_id("aaaa"), wire_id("bbbb"));

    let mut bobs = hold(&base, &bob).await;
    until(&wire, &bob, true).await;

    // Nothing is holding Alice's connection, so this has nowhere to go — and is kept rather than
    // lost, and kept under HER id.
    say(&wire, &alice, ready("02aaaa"));
    assert_eq!(wire.connections.waiting_for(&alice), 1);
    assert_eq!(
        wire.connections.waiting_for(&bob),
        0,
        "Alice's message must not be queued against Bob"
    );
    assert!(bobs.nothing().await, "and must not be delivered to him");

    // When Alice's connection comes back — as the runtime's re-dial brings it — it is hers.
    let mut alices = hold(&base, &alice).await;
    let to_alice = alices.next().await.expect("the backlog is delivered on the next dial");
    assert_eq!(to_alice["escrow_key"], "02aaaa");
    assert_eq!(wire.connections.waiting_for(&alice), 0, "and is not delivered twice");
    assert!(bobs.nothing().await, "Bob still hears nothing of it");
}

/// A re-dial under the same id is the SAME connection, and replaces it rather than accumulating.
///
/// The runtime re-establishes a dropped connection under the id it was opened with, so two live
/// connections under one wire id would mean the service had lost track of one.
#[tokio::test]
async fn a_redial_replaces_the_connection_it_is_replacing() {
    let (wire, base) = service().await;
    let alice = wire_id("aaaa");

    let first = hold(&base, &alice).await;
    until(&wire, &alice, true).await;
    assert_eq!(wire.connections.held_under(LOCAL), 1);

    // The runtime dials again under the same id, without the old one having been noticed as gone.
    let mut second = hold(&base, &alice).await;
    tokio::time::sleep(Duration::from_millis(200)).await;
    assert_eq!(
        wire.connections.held_under(LOCAL),
        1,
        "one id is one connection, however many times it is dialled"
    );

    // And what is said goes to the live one.
    say(&wire, &alice, ready("02aaaa"));
    let to_alice = second.next().await.expect("the connection that is up");
    assert_eq!(to_alice["escrow_key"], "02aaaa");
    drop(first);
}
