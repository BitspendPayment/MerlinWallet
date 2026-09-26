//! A pairing is not finished until it is written down.
//!
//! # Why this matters
//!
//! Saying `pairing-ready` is what lets the owner commit money to an escrow. If the share behind
//! that only exists in memory, a restart loses it — and then the cosigner holds a pairing it
//! believes is complete, against a service that can no longer sign its half. The money sits there
//! until the deadline with nobody able to release it.
//!
//! So a failure to store is a failure to pair, and the service says so rather than logging it and
//! carrying on.

mod common;

use std::sync::Arc;

use card_escrow::service::wire::{router, Connections, Wire};
use card_escrow::service::Service;
use rand::rngs::OsRng;
use threshold::identifier::Identifier;
use threshold::{point, scalar};

/// A real pairing's two halves, as the two routes deliver them.
struct Halves {
    escrow_key: String,
    attempt_id: String,
    service_identifier: String,
    /// What the cosigner deals, over the held connection.
    from_cosigner: String,
    /// What the wallet deals, straight from the device.
    from_wallet: String,
    public_key_package_json: String,
    service_verifying_share: String,
}

/// Mint one, by the same route `handlers::pairing` takes.
fn halves() -> Halves {
    let (kps, pkp) = common::dkg_2of2();
    let (wallet_kp, cosigner_kp) = (kps[0].clone(), kps[1].clone());
    let service_id = Identifier::derive(b"merlin-e2e-escrow-service").unwrap();
    let dealt = threshold::dkg::refresh_to_ids(
        &wallet_kp,
        &[wallet_kp.identifier.clone(), cosigner_kp.identifier.clone()],
        &[service_id.clone(), cosigner_kp.identifier.clone()],
        2,
        &mut OsRng,
    );
    let a_at_service = dealt[&service_id];
    let material = cosigner::handlers::pairing::pair_service(
        &cosigner_kp,
        &pkp,
        &wallet_kp.identifier,
        &service_id,
        &scalar::scalar_to_bytes(&dealt[&cosigner_kp.identifier]),
        &point::serialize_compressed(&point::base_mul(&a_at_service)),
    )
    .expect("an honest pairing");

    Halves {
        escrow_key: hex::encode(pkp.verifying_key.serialize()),
        attempt_id: "aa".repeat(16),
        service_identifier: material.service_identifier_hex.clone(),
        from_cosigner: hex::encode(&material.service_half),
        from_wallet: hex::encode(scalar::scalar_to_bytes(&a_at_service)),
        public_key_package_json: material.public_key_package_json.clone(),
        service_verifying_share: material.service_verifying_share_hex.clone(),
    }
}

/// A service whose store is somewhere it cannot write.
async fn service_storing_at(path: Option<std::path::PathBuf>) -> (Arc<Wire>, String) {
    let service = Service::new(
        Identifier::derive(b"merlin-e2e-escrow-service").unwrap(),
        "ark1service".into(),
        "http://127.0.0.1:7070".into(),
        path,
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

/// Deliver both halves, and report what the wallet's delivery was told.
async fn deliver(base: &str, h: &Halves) -> reqwest::StatusCode {
    let client = reqwest::Client::new();
    // The cosigner's half, as it arrives on the held connection.
    client
        .post(format!("{base}/escrow/send?id=tenant-svc-x"))
        .json(&serde_json::json!({
            "kind": "pairing-half",
            "escrow_key": h.escrow_key,
            "attempt_id": h.attempt_id,
            "service_identifier": h.service_identifier,
            "half": h.from_cosigner,
            "public_key_package_json": h.public_key_package_json,
            "service_verifying_share": h.service_verifying_share,
        }))
        .send()
        .await
        .expect("the service takes the half");

    // The wallet's, straight from the device.
    client
        .post(format!("{base}/pair/wallet"))
        .json(&serde_json::json!({
            "escrow_key": h.escrow_key,
            "attempt_id": h.attempt_id,
            "contribution": h.from_wallet,
        }))
        .send()
        .await
        .expect("the service takes the half")
        .status()
}

/// The ordinary case, so the failing one below is about storage and nothing else.
#[tokio::test]
async fn a_pairing_that_can_be_stored_is_ready() {
    let dir = std::env::temp_dir().join(format!("card-escrow-pair-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let path = dir.join("ok.json");
    let _ = std::fs::remove_file(&path);

    let (wire, base) = service_storing_at(Some(path.clone())).await;
    let h = halves();
    assert_eq!(deliver(&base, &h).await, reqwest::StatusCode::OK);

    let held = wire.service.store.lock().await;
    assert!(
        held.shares.contains_key(&h.escrow_key.to_ascii_lowercase()),
        "the share is held"
    );
    assert!(path.exists(), "and written down");
    drop(held);
    std::fs::remove_file(&path).ok();
}

/// And one that cannot be stored is refused, not logged and waved through.
///
/// A share that only lives in memory is one a restart loses — and the cosigner would by then have
/// been told the pairing was complete, so the owner could commit money to an escrow nobody can
/// release from.
#[tokio::test]
async fn a_pairing_that_cannot_be_stored_is_refused() {
    // A directory that does not exist, so every write fails.
    let path = std::env::temp_dir()
        .join(format!("card-escrow-nowhere-{}", std::process::id()))
        .join("missing")
        .join("store.json");

    let (wire, base) = service_storing_at(Some(path)).await;
    let h = halves();
    let status = deliver(&base, &h).await;

    assert_eq!(
        status,
        reqwest::StatusCode::BAD_REQUEST,
        "a pairing that could not be stored must not report success"
    );
    assert!(
        wire.service
            .store
            .lock()
            .await
            .shares
            .is_empty(),
        "and must not be held in memory either — what this service holds has to match what it \
         just told the cosigner"
    );
}
