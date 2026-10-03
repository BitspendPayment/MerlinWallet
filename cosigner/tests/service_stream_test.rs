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
use cosigner::asp::NoAsp;
use cosigner::escrow::{
    handle_service_message, service_stream_id, EscrowStage, FromService, PairingMaterial,
    PairingState, ServicePairing, ToService,
};
use cosigner::evidence::NoEvidence;

const NOW: i64 = 1_700_000_000;
const SERVICE: &str = "44";
const ORIGIN: &str = "https://service.example";

fn wallet(store: &Arc<cosigner::store::Store>, host: Arc<Recorder>) -> cosigner::Cosigner {
    let (kps, pkp) = common::dkg_2of2();
    let group_key = hex::encode(pkp.verifying_key.serialize());
    let c = Mutex::new(
        cosigner::Cosigner::open(store.clone(), group_key.clone(), host).expect("open"),
    );
    common::seed_policy_with_dealt_share(
        &c,
        &group_key,
        &kps[1],
        &kps[0],
        &pkp,
        Some(hex::encode([7u8; 32])),
    );
    c.into_inner().unwrap()
}

fn service_id() -> String {
    SERVICE.repeat(32)
}

/// An escrow with a service paired into it, delivered but not yet vouched for by anybody.
fn seed(c: &mut cosigner::Cosigner, escrow_key: &str, attempt: &str) {
    c.add_escrow(cosigner::escrow::EscrowSession {
        escrow_key: escrow_key.to_string(),
        key_package_json: "{}".into(),
        public_key_package_json: "{}".into(),
        wallet_identifier_hex: "11".repeat(32),
        context_hex: "22".repeat(16),
        wallet_delta_share_hex: "33".repeat(32),
        created_at: NOW,
        stage: EscrowStage::Paired(ServicePairing {
            service_identifier_hex: service_id(),
            key_package_json: "{}".into(),
            public_key_package_json: "{}".into(),
            service_verifying_share_hex: "55".repeat(33),
            paired_at: NOW,
            attempt_id_hex: attempt.to_string(),
            service_confirmed: false,
            wallet_confirmed: false,
        }),
    })
    .expect("install escrow");
}

/// [payload] arriving on [stream], as one `on-message` invocation would deliver it.
fn deliver(c: &mut cosigner::Cosigner, stream: &str, payload: &[u8]) -> Result<Vec<u8>, String> {
    block_on_ready(handle_service_message(c, stream, payload, None::<NoAsp>, &NoEvidence))
}

fn say(c: &mut cosigner::Cosigner, stream: &str, message: &FromService) -> ToService {
    let payload = serde_json::to_vec(message).unwrap();
    let reply = deliver(c, stream, &payload).expect("a refusal is a reply, not an error");
    serde_json::from_slice(&reply).expect("the reply decodes")
}

/// What a pairing deals this service, as `prepare_pairing` hands it back.
fn material() -> PairingMaterial {
    PairingMaterial {
        service_identifier_hex: service_id(),
        key_package_json: "{}".into(),
        public_key_package_json: "{}".into(),
        service_half: vec![0x77; 32],
        service_verifying_share_hex: "55".repeat(33),
    }
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
    let escrow_key = "02".to_string() + &"ab".repeat(32);
    block_on_ready(material().deliver(host.as_ref(), ORIGIN, &escrow_key, &"aa".repeat(16)))
        .expect("the service took it");

    let id = service_stream_id(&service_id());
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
    for escrow in ["02aa", "02bb"] {
        block_on_ready(material().deliver(host.as_ref(), ORIGIN, escrow, &"aa".repeat(16)))
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
    let err = block_on_ready(material().deliver(host.as_ref(), ORIGIN, "02aa", &"aa".repeat(16)))
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

    let pairing = c.get_escrow_session(&key).unwrap().pairing().cloned().unwrap();
    assert!(pairing.service_confirmed);
    assert!(!pairing.wallet_confirmed);
    assert_eq!(pairing.state(), PairingState::Pending);
    assert!(pairing.awaiting().contains("wallet"));

    // And it survives the seal, because a restart must reach the same answer.
    c.seal();
    let reopened = cosigner::Cosigner::open(
        store.clone(),
        c.group_key().to_string(),
        Arc::new(Recorder::default()),
    )
    .expect("reopen");
    assert!(
        reopened.get_escrow_session(&key).unwrap().pairing().unwrap().service_confirmed,
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
        !c.get_escrow_session(&key).unwrap().pairing().unwrap().service_confirmed,
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
    let reply = deliver(&mut c, &service_stream_id(&service_id()), b"not json")
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
    assert!(c.get_escrow_session(&key).unwrap().pairing().unwrap().service_confirmed);
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
    let pairing = c.get_escrow_session(&key).unwrap().pairing().cloned().unwrap();
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
    c.lock()
        .unwrap()
        .escrow_mut(&key)
        .and_then(|e| e.confirm_pairing(&attempt, |p| p.wallet_confirmed = true))
        .unwrap();

    let guard = c.lock().unwrap();
    let pairing = guard.get_escrow_session(&key).unwrap().pairing().unwrap();
    assert_eq!(pairing.state(), PairingState::Ready);
    assert_eq!(pairing.awaiting(), "nothing");
}
