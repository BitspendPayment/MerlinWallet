//! The connection to an escrow service: who may speak on it, and what a pairing needs before it
//! counts as done.
//!
//! The service is the one party in this design that can never call in — it has no passkey for its
//! user's tenant, and `tenant_of` is checked before the path and fails closed. So everything it
//! says arrives on a connection the RUNTIME holds, opened by this cosigner to an origin the image
//! named. These tests stand in for the runtime with a fake and check the decisions, which is where
//! the interesting part is.

mod common;

use std::sync::{Arc, Mutex};

use common::Recorder;
use cosigner::handlers::helpers::block_on_ready;
use cosigner::service_stream::{service_stream_id, FromService, ToService};
use cosigner::types::{EscrowRecord, PairingState, ServicePairing};

const NOW: i64 = 1_700_000_000;
const SERVICE: &str = "44";
const ORIGIN: &str = "https://service.example";

fn wallet(store: &Arc<cosigner::store::Store>, host: Arc<Recorder>) -> cosigner::Cosigner {
    let (kps, pkp) = common::dkg_2of2();
    let group_key = hex::encode(pkp.verifying_key.serialize());
    let c = Mutex::new(
        cosigner::Cosigner::open_with_host(store.clone(), group_key.clone(), host).expect("open"),
    );
    common::seed_policy_with_dealt_share(
        &c,
        &group_key,
        &kps[1],
        &kps[0],
        &pkp,
        Some(hex::encode([9u8; 32])),
        Some(hex::encode([7u8; 32])),
    );
    c.into_inner().unwrap()
}

fn service_id() -> String {
    SERVICE.repeat(32)
}

/// An escrow with a service paired into it, delivered but not yet vouched for by anybody.
fn seed(c: &mut cosigner::Cosigner, escrow_key: &str, attempt: &str) {
    c.install_escrow(EscrowRecord {
        escrow_key: escrow_key.to_string(),
        key_package_json: "{}".into(),
        public_key_package_json: "{}".into(),
        wallet_identifier_hex: "11".repeat(32),
        context_hex: "22".repeat(16),
        wallet_delta_share_hex: "33".repeat(32),
        created_at: NOW,
        pairing: Some(ServicePairing {
            service_identifier_hex: service_id(),
            key_package_json: "{}".into(),
            public_key_package_json: "{}".into(),
            service_verifying_share_hex: "55".repeat(33),
            paired_at: NOW,
            attempt_id_hex: attempt.to_string(),
            service_confirmed: false,
            wallet_confirmed: false,
        }),
        session: None,
        reclaim_opened_at: None,
    })
    .expect("install escrow");
}

fn say(c: &mut cosigner::Cosigner, stream: &str, message: &FromService) -> ToService {
    let payload = serde_json::to_vec(message).unwrap();
    let reply = c
        .on_service_message(stream, "msg-1", &payload)
        .expect("a refusal is a reply, not an error");
    serde_json::from_slice(&reply).expect("the reply decodes")
}

fn is_ack(reply: &ToService) -> bool {
    matches!(reply, ToService::Ack { .. })
}

fn refusal(reply: &ToService) -> String {
    match reply {
        ToService::Refused { reason, .. } => reason.clone(),
        other => panic!("expected a refusal, got {other:?}"),
    }
}

/// A half goes out on the connection the runtime holds, not as a request of its own — and the
/// connection is opened to the origin the IMAGE resolved, never one on the wire.
#[test]
fn a_pairing_half_travels_on_the_connection_the_runtime_holds() {
    let host = Arc::new(Recorder::default());
    let half = ToService::PairingHalf {
        escrow_key: "02".to_string() + &"ab".repeat(32),
        attempt_id: "aa".repeat(16),
        service_identifier: service_id(),
        half: "77".repeat(32),
        public_key_package_json: "{}".into(),
        service_verifying_share: "55".repeat(33),
    };
    let id = block_on_ready(cosigner::handlers::delivery::deliver_pairing_half(
        host.as_ref(),
        &service_id(),
        ORIGIN,
        &half,
    ))
    .expect("the service took it");

    assert_eq!(id, service_stream_id(&service_id()));
    assert_eq!(host.opened(), vec![(id.clone(), ORIGIN.to_string())]);
    let sent = host.sent();
    assert_eq!(sent.len(), 1);
    assert_eq!(sent[0].0, id);
    let decoded: serde_json::Value = serde_json::from_slice(&sent[0].1).unwrap();
    assert_eq!(decoded["kind"], "pairing-half");
    assert_eq!(decoded["half"], "77".repeat(32));
}

/// A second escrow with the same service reuses the connection rather than making a second: a
/// tenant may hold eight, and a wallet may hold sixty-four escrows.
#[test]
fn two_escrows_with_one_service_share_one_connection() {
    let host = Arc::new(Recorder::default());
    let half = |escrow: &str| ToService::PairingHalf {
        escrow_key: escrow.to_string(),
        attempt_id: "aa".repeat(16),
        service_identifier: service_id(),
        half: "77".repeat(32),
        public_key_package_json: "{}".into(),
        service_verifying_share: "55".repeat(33),
    };
    for escrow in ["02aa", "02bb"] {
        block_on_ready(cosigner::handlers::delivery::deliver_pairing_half(
            host.as_ref(),
            &service_id(),
            ORIGIN,
            &half(escrow),
        ))
        .expect("delivered");
    }
    assert_eq!(host.opened().len(), 1, "one service, one connection");
    assert_eq!(host.sent().len(), 2, "two halves on it");
}

/// Nothing is sealed when the far side cannot be reached. The cosigner keeps no copy of the half it
/// deals, so a pairing sealed against a delivery that did not land could never be completed.
#[test]
fn a_service_that_cannot_be_reached_fails_the_delivery() {
    let host = Arc::new(Recorder::default());
    host.disconnect_on_open();
    let half = ToService::PairingHalf {
        escrow_key: "02aa".into(),
        attempt_id: "aa".repeat(16),
        service_identifier: service_id(),
        half: "77".repeat(32),
        public_key_package_json: "{}".into(),
        service_verifying_share: "55".repeat(33),
    };
    let err = block_on_ready(cosigner::handlers::delivery::deliver_pairing_half(
        host.as_ref(),
        &service_id(),
        ORIGIN,
        &half,
    ))
    .expect_err("a connection that never comes up is a delivery that did not happen");
    assert!(err.contains("could not be reached"), "unexpected: {err}");
    assert!(host.sent().is_empty());
}

/// The service's word finishes its half of the pairing, and only its half.
#[test]
fn the_service_confirming_is_not_the_whole_pairing() {
    let Some(store) = common::try_store() else { return };
    let host = Arc::new(Recorder::default());
    let mut c = wallet(&store, host);
    let key = "02".to_string() + &"ab".repeat(32);
    let attempt = "aa".repeat(16);
    seed(&mut c, &key, &attempt);
    let stream = service_stream_id(&service_id());

    let reply = say(
        &mut c,
        &stream,
        &FromService::PairingReady {
            escrow_key: key.clone(),
            attempt_id: attempt.clone(),
        },
    );
    assert!(is_ack(&reply), "{reply:?}");

    let pairing = c.escrow(&key).unwrap().pairing.clone().unwrap();
    assert!(pairing.service_confirmed);
    assert!(!pairing.wallet_confirmed);
    assert_eq!(pairing.state(), PairingState::Pending);
    assert!(pairing.awaiting().contains("wallet"));

    // And it survives the seal, because a restart must reach the same answer.
    c.seal();
    let reopened = cosigner::Cosigner::open_with_host(
        store.clone(),
        c.group_key().to_string(),
        Arc::new(Recorder::default()),
    )
    .expect("reopen");
    assert!(
        reopened.escrow(&key).unwrap().pairing.as_ref().unwrap().service_confirmed,
        "what the service said is in the seal"
    );
}

/// A message on one service's connection cannot speak for an escrow paired to another. The
/// connection is the authentication: the runtime opened it to an origin the image resolved from
/// this service's identifier, and nothing in the message can move it.
#[test]
fn a_service_cannot_speak_for_an_escrow_it_was_not_paired_into() {
    let Some(store) = common::try_store() else { return };
    let host = Arc::new(Recorder::default());
    let mut c = wallet(&store, host);
    let key = "02".to_string() + &"ab".repeat(32);
    let attempt = "aa".repeat(16);
    seed(&mut c, &key, &attempt);

    let other = service_stream_id(&"99".repeat(32));
    let reply = say(
        &mut c,
        &other,
        &FromService::PairingReady {
            escrow_key: key.clone(),
            attempt_id: attempt.clone(),
        },
    );
    assert!(
        refusal(&reply).contains("different service"),
        "{reply:?}"
    );
    assert!(
        !c.escrow(&key).unwrap().pairing.as_ref().unwrap().service_confirmed,
        "nothing was confirmed"
    );
}

/// Confirming an attempt that was never dealt would mark a pairing usable on the strength of halves
/// that do not belong together.
#[test]
fn a_confirmation_for_another_attempt_is_refused() {
    let Some(store) = common::try_store() else { return };
    let host = Arc::new(Recorder::default());
    let mut c = wallet(&store, host);
    let key = "02".to_string() + &"ab".repeat(32);
    seed(&mut c, &key, &"aa".repeat(16));

    let reply = say(
        &mut c,
        &service_stream_id(&service_id()),
        &FromService::PairingReady {
            escrow_key: key.clone(),
            attempt_id: "bb".repeat(16),
        },
    );
    assert!(refusal(&reply).contains("not the one this cosigner dealt"), "{reply:?}");
}

/// An escrow this wallet does not hold is a refusal, not a panic and not an error — an error would
/// have the runtime deliver the message again for ever.
#[test]
fn an_unknown_escrow_is_refused_rather_than_retried() {
    let Some(store) = common::try_store() else { return };
    let host = Arc::new(Recorder::default());
    let mut c = wallet(&store, host);
    let reply = say(
        &mut c,
        &service_stream_id(&service_id()),
        &FromService::PairingReady {
            escrow_key: "02".to_string() + &"ff".repeat(32),
            attempt_id: "aa".repeat(16),
        },
    );
    assert!(refusal(&reply).contains("no such escrow"), "{reply:?}");
}

/// Bytes that are not a message at all still answer. The runtime redelivers on an error, so a
/// payload that will never decode must not be one.
#[test]
fn an_undecodable_message_answers_instead_of_being_redelivered_for_ever() {
    let Some(store) = common::try_store() else { return };
    let host = Arc::new(Recorder::default());
    let mut c = wallet(&store, host);
    let reply = c
        .on_service_message(&service_stream_id(&service_id()), "msg-1", b"not json")
        .expect("a reply, not an error");
    let reply: ToService = serde_json::from_slice(&reply).unwrap();
    assert!(refusal(&reply).contains("did not decode"), "{reply:?}");
}

/// A redelivered message — what a reconnect looks like — reaches the same answer.
#[test]
fn a_message_delivered_twice_reaches_the_same_answer() {
    let Some(store) = common::try_store() else { return };
    let host = Arc::new(Recorder::default());
    let mut c = wallet(&store, host);
    let key = "02".to_string() + &"ab".repeat(32);
    let attempt = "aa".repeat(16);
    seed(&mut c, &key, &attempt);
    let stream = service_stream_id(&service_id());
    let message = FromService::PairingReady {
        escrow_key: key.clone(),
        attempt_id: attempt.clone(),
    };

    assert!(is_ack(&say(&mut c, &stream, &message)));
    assert!(is_ack(&say(&mut c, &stream, &message)));
    assert!(c.escrow(&key).unwrap().pairing.as_ref().unwrap().service_confirmed);
}

/// A service that could not use its half says so. Nothing is undone — the pairing was never usable
/// — but the wallet is free to pair again, and this cosigner deals a fresh half because it kept
/// none of the last one.
#[test]
fn a_refused_half_leaves_the_pairing_exactly_as_unusable_as_it_was() {
    let Some(store) = common::try_store() else { return };
    let host = Arc::new(Recorder::default());
    let mut c = wallet(&store, host);
    let key = "02".to_string() + &"ab".repeat(32);
    let attempt = "aa".repeat(16);
    seed(&mut c, &key, &attempt);

    let reply = say(
        &mut c,
        &service_stream_id(&service_id()),
        &FromService::PairingRefused {
            escrow_key: key.clone(),
            attempt_id: attempt.clone(),
            reason: "the halves did not sum to the published verifying share".into(),
        },
    );
    assert!(is_ack(&reply), "{reply:?}");
    let pairing = c.escrow(&key).unwrap().pairing.clone().unwrap();
    assert!(!pairing.service_confirmed);
    assert_eq!(pairing.state(), PairingState::Pending);
}

/// Both halves of the confirmation, from the two parties that can each see only their own side.
#[test]
fn a_pairing_is_usable_once_both_parties_have_said_so() {
    let Some(store) = common::try_store() else { return };
    let host = Arc::new(Recorder::default());
    let c = Arc::new(Mutex::new(wallet(&store, host)));
    let key = "02".to_string() + &"ab".repeat(32);
    let attempt = "aa".repeat(16);
    seed(&mut c.lock().unwrap(), &key, &attempt);

    say(
        &mut c.lock().unwrap(),
        &service_stream_id(&service_id()),
        &FromService::PairingReady {
            escrow_key: key.clone(),
            attempt_id: attempt.clone(),
        },
    );
    c.lock().unwrap().confirm_escrow_pairing(&key, &attempt).unwrap();

    let guard = c.lock().unwrap();
    let pairing = guard.escrow(&key).unwrap().pairing.as_ref().unwrap();
    assert_eq!(pairing.state(), PairingState::Ready);
    assert_eq!(pairing.awaiting(), "nothing");
}
