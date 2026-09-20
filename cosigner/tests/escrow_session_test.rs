//! Committing an escrow to a deal, through the cosigner that seals it.
//!
//! The state machine's own rules are unit-tested in `src/escrow_session.rs`. What is checked here
//! is what the cosigner does with them: that a session cannot be opened over an escrow nobody could
//! release from, that a live deal cannot be replaced under the owner's feet, and — the one that
//! matters for a machine that is evicted and reseated constantly — that a session survives the seal
//! and a restored instance reaches the same answers from the clock alone.

mod common;

use cosigner::escrow_session::{EscrowSession, EscrowState, Refusal};
use cosigner::policy::Policy;
use cosigner::types::{EscrowRecord, ServicePairing};

const NOW: i64 = 1_700_000_000;
const HOUR: i64 = 3_600;

/// An escrow on a wallet, optionally with a service paired into it.
fn seed_escrow(
    cosigner: &std::sync::Mutex<cosigner::Cosigner>,
    escrow_key: &str,
    paired: bool,
) {
    let mut c = cosigner.lock().unwrap();
    c.install_escrow(EscrowRecord {
        escrow_key: escrow_key.to_string(),
        key_package_json: "{}".into(),
        public_key_package_json: "{}".into(),
        wallet_identifier_hex: "11".repeat(32),
        context_hex: "22".repeat(16),
        wallet_delta_share_hex: "33".repeat(32),
        created_at: NOW,
        pairing: paired.then(|| ServicePairing {
            service_identifier_hex: "44".repeat(32),
            key_package_json: "{}".into(),
            public_key_package_json: "{}".into(),
            service_verifying_share_hex: "55".repeat(33),
            paired_at: NOW,
            attempt_id_hex: "aa".repeat(16),
            // Seeded finished: these tests are about the DEAL, and a pending pairing is refused a
            // deal for reasons of its own — proved separately below.
            service_confirmed: true,
            wallet_confirmed: true,
        }),
        session: None,
    })
    .expect("install escrow");
}

/// A wallet whose runtime is a fake, so a test can see what was asked of it — and what was not.
fn open(
    store: &std::sync::Arc<cosigner::store::Store>,
    host: std::sync::Arc<common::Recorder>,
) -> cosigner::Cosigner {
    let (kps, pkp) = common::dkg_2of2();
    let group_key = hex::encode(pkp.verifying_key.serialize());
    let c = std::sync::Mutex::new(
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

fn wallet(store: &std::sync::Arc<cosigner::store::Store>) -> (std::sync::Mutex<cosigner::Cosigner>, String) {
    let (kps, pkp) = common::dkg_2of2();
    let group_key = hex::encode(pkp.verifying_key.serialize());
    let c = common::open_cosigner(store, &group_key);
    common::seed_policy_with_dealt_share(
        &c,
        &group_key,
        &kps[1],
        &kps[0],
        &pkp,
        Some(hex::encode([9u8; 32])),
        Some(hex::encode([7u8; 32])),
    );
    (c, group_key)
}

/// An escrow nobody can release from must not be committed: the owner would be locked out of their
/// own money until the deadline, for no one's benefit.
#[test]
fn an_escrow_with_no_service_cannot_be_committed() {
    let Some(store) = common::try_store() else { return };
    let (c, _) = wallet(&store);
    let key = "02".to_string() + &"ab".repeat(32);
    seed_escrow(&c, &key, false);

    let session = EscrowSession::open(Policy::Always, NOW, NOW + HOUR).unwrap();
    let err = c
        .lock()
        .unwrap()
        .open_escrow_session(&key, session, NOW)
        .expect_err("an escrow with no service must not be committed");
    assert!(err.contains("no service paired"), "unexpected: {err}");
}

#[test]
fn a_live_deal_cannot_be_replaced_under_the_owners_feet() {
    let Some(store) = common::try_store() else { return };
    let (c, _) = wallet(&store);
    let key = "02".to_string() + &"ab".repeat(32);
    seed_escrow(&c, &key, true);

    let first = EscrowSession::open(Policy::Always, NOW, NOW + HOUR).unwrap();
    c.lock().unwrap().open_escrow_session(&key, first, NOW).expect("the first deal");

    let second = EscrowSession::open(Policy::Always, NOW, NOW + 2 * HOUR).unwrap();
    let err = c
        .lock()
        .unwrap()
        .open_escrow_session(&key, second, NOW)
        .expect_err("a second deal over a live one must be refused");
    assert!(err.contains("already committed"), "unexpected: {err}");
}

/// Once it is over, the escrow can be committed again — the key is still there, and a second deal
/// is a second deal rather than a mistake.
#[test]
fn an_escrow_can_be_committed_again_once_its_deal_is_over() {
    let Some(store) = common::try_store() else { return };
    let (c, _) = wallet(&store);
    let key = "02".to_string() + &"ab".repeat(32);
    seed_escrow(&c, &key, true);

    let first = EscrowSession::open(Policy::Always, NOW, NOW + HOUR).unwrap();
    c.lock().unwrap().open_escrow_session(&key, first, NOW).expect("the first deal");

    let second = EscrowSession::open(Policy::Always, NOW + 2 * HOUR, NOW + 3 * HOUR).unwrap();
    c.lock()
        .unwrap()
        .open_escrow_session(&key, second, NOW + 2 * HOUR)
        .expect("a deal after the last one ended");
}

/// The one that matters for a machine that is evicted and reseated between requests.
#[test]
fn a_deal_survives_the_seal_and_a_restored_instance_agrees_with_the_clock() {
    let Some(store) = common::try_store() else { return };
    let key = "02".to_string() + &"ab".repeat(32);
    let group_key;
    {
        let (c, gk) = wallet(&store);
        group_key = gk;
        seed_escrow(&c, &key, true);
        let session = EscrowSession::open(
            Policy::TotalOutMax { sats: 50_000 },
            NOW,
            NOW + HOUR,
        )
        .unwrap();
        let mut guard = c.lock().unwrap();
        guard.open_escrow_session(&key, session, NOW).expect("commit");
        guard.seal();
    }

    // A second instance over the same store: what the runtime does on every reseat.
    let reopened = common::open_cosigner(&store, &group_key);
    let guard = reopened.lock().unwrap();
    let escrow = guard.escrow(&key).expect("the escrow came back");
    let session = escrow.session.as_ref().expect("and so did its deal");

    assert_eq!(session.state, EscrowState::Open);
    assert_eq!(session.deadline, NOW + HOUR);
    assert_eq!(session.policy, Policy::TotalOutMax { sats: 50_000 });

    // And it reaches the same answers as the instance that armed it, from the clock alone — with
    // nothing written down at the deadline.
    assert!(session.may_release(NOW + 60).is_ok());
    assert_eq!(session.may_reclaim(NOW + 60), Err(Refusal::StillOpen));
    assert_eq!(session.may_release(NOW + HOUR), Err(Refusal::EscrowClosed));
    assert!(session.may_reclaim(NOW + HOUR).is_ok());
}

#[test]
fn closing_a_deal_that_was_never_opened_says_so() {
    let Some(store) = common::try_store() else { return };
    let (c, _) = wallet(&store);
    let key = "02".to_string() + &"ab".repeat(32);
    seed_escrow(&c, &key, true);

    let err = c
        .lock()
        .unwrap()
        .close_escrow_session(&key, NOW)
        .expect_err("there is nothing to close");
    assert!(err.contains("not committed"), "unexpected: {err}");
}

#[test]
fn a_deal_on_an_escrow_this_wallet_does_not_hold_is_refused() {
    let Some(store) = common::try_store() else { return };
    let (c, _) = wallet(&store);
    let session = EscrowSession::open(Policy::Always, NOW, NOW + HOUR).unwrap();
    let err = c
        .lock()
        .unwrap()
        .open_escrow_session(&("02".to_string() + &"ff".repeat(32)), session, NOW)
        .expect_err("a stranger's escrow is not this wallet's to commit");
    assert!(err.contains("no such escrow"), "unexpected: {err}");
}

/// An escrow is named by the address it pays, which commits to the x-only key — so either parity
/// must resolve to the same escrow.
#[test]
fn an_escrow_resolves_by_either_parity() {
    let Some(store) = common::try_store() else { return };
    let (c, _) = wallet(&store);
    let even = "02".to_string() + &"ab".repeat(32);
    let odd = "03".to_string() + &"ab".repeat(32);
    seed_escrow(&c, &even, true);

    let session = EscrowSession::open(Policy::Always, NOW, NOW + HOUR).unwrap();
    c.lock()
        .unwrap()
        .open_escrow_session(&odd, session, NOW)
        .expect("the same key, named with the other parity");
}

// ---------------------------------------------------------------------------
// Nothing runs at the deadline.
// ---------------------------------------------------------------------------

/// A deadline is a fact about the clock, not an event.
///
/// There was a task once that woke the owner when a deal ended. It is gone, and what replaced it is
/// nothing at all: every decision reads the deadline out of the seal and compares it to the clock,
/// so an instance that was never running when the deadline passed reaches exactly the same answer
/// as one that was. Nothing is enqueued, and nothing has to be recovered.
#[test]
fn committing_an_escrow_to_a_deal_schedules_nothing() {
    let Some(store) = common::try_store() else { return };
    let host = std::sync::Arc::new(common::Recorder::default());
    let c = std::sync::Mutex::new(open(&store, host.clone()));
    let key = "02".to_string() + &"ab".repeat(32);
    seed_escrow(&c, &key, true);

    let session = EscrowSession::open(Policy::Always, NOW, NOW + HOUR).unwrap();
    c.lock().unwrap().open_escrow_session(&key, session, NOW).expect("commit it");

    assert!(
        host.enqueued().is_empty(),
        "an escrow deadline is not work; it is a number the seal already carries"
    );
    assert!(host.woken().is_empty());
}

/// And the answer it reaches without anything having run is the right one, before and after.
#[test]
fn the_deadline_decides_with_nothing_having_run_at_it() {
    let session = EscrowSession::open(Policy::Always, NOW, NOW + HOUR).unwrap();
    assert!(session.may_release(NOW + HOUR - 1).is_ok());
    assert!(session.may_reclaim(NOW + HOUR - 1).is_err());

    // Nobody wrote anything down in between.
    assert!(session.may_release(NOW + HOUR).is_err());
    assert!(session.may_reclaim(NOW + HOUR).is_ok());
    assert_eq!(session.state, cosigner::escrow_session::EscrowState::Open);
}

/// A pairing the service has not finished is not a pairing you can deal against.
///
/// The service's share arrives as two halves by two routes, and one of them is delivered by the
/// device rather than the enclave. Until the service confirms it holds both and has checked what
/// they sum to, it can sign nothing — so an escrow committed to such a "service" would be money
/// locked away with nobody able to take its side.
#[test]
fn a_deal_cannot_be_committed_to_a_pairing_the_service_has_not_finished() {
    let Some(store) = common::try_store() else { return };
    let (c, _) = wallet(&store);
    let key = "02".to_string() + &"ab".repeat(32);

    {
        let mut guard = c.lock().unwrap();
        guard
            .install_escrow(EscrowRecord {
                escrow_key: key.clone(),
                key_package_json: "{}".into(),
                public_key_package_json: "{}".into(),
                wallet_identifier_hex: "11".repeat(32),
                context_hex: "22".repeat(16),
                wallet_delta_share_hex: "33".repeat(32),
                created_at: NOW,
                pairing: Some(ServicePairing {
                    service_identifier_hex: "44".repeat(32),
                    key_package_json: "{}".into(),
                    public_key_package_json: "{}".into(),
                    service_verifying_share_hex: "55".repeat(33),
                    paired_at: NOW,
                    attempt_id_hex: "aa".repeat(16),
                    service_confirmed: false,
                    wallet_confirmed: false,
                }),
                session: None,
            })
            .expect("install escrow");
    }

    let session = EscrowSession::open(Policy::Always, NOW, NOW + HOUR).unwrap();
    let err = c
        .lock()
        .unwrap()
        .open_escrow_session(&key, session, NOW)
        .expect_err("a pending pairing is not a service that can be paid");
    assert!(err.contains("not finished"), "unexpected: {err}");

    // The wallet alone is not enough. It delivered its half, but it cannot see the half this
    // cosigner dealt and so cannot vouch for the share the two sum to.
    c.lock()
        .unwrap()
        .confirm_escrow_pairing(&key, &"aa".repeat(16))
        .expect("confirming the attempt that was sealed");
    let session = EscrowSession::open(Policy::Always, NOW, NOW + HOUR).unwrap();
    let err = c
        .lock()
        .unwrap()
        .open_escrow_session(&key, session, NOW)
        .expect_err("one party's word is not both parties agreeing");
    assert!(err.contains("service has not confirmed"), "unexpected: {err}");

    // And the service alone would not have been either — it arrives over the connection the
    // runtime holds, and only with the wallet's does the pairing become usable.
    c.lock()
        .unwrap()
        .confirm_pairing_by_service(&key, &"aa".repeat(16))
        .expect("the service confirming the attempt that was dealt");
    let session = EscrowSession::open(Policy::Always, NOW, NOW + HOUR).unwrap();
    c.lock()
        .unwrap()
        .open_escrow_session(&key, session, NOW)
        .expect("a finished pairing can be dealt against");
}

/// Neither party can finish a pairing on its own, whichever of them speaks first.
#[test]
fn a_pairing_needs_both_parties_whichever_order_they_speak_in() {
    let Some(store) = common::try_store() else { return };
    let (c, _) = wallet(&store);
    let key = "02".to_string() + &"cd".repeat(32);
    let attempt = "aa".repeat(16);
    c.lock()
        .unwrap()
        .install_escrow(EscrowRecord {
            escrow_key: key.clone(),
            key_package_json: "{}".into(),
            public_key_package_json: "{}".into(),
            wallet_identifier_hex: "11".repeat(32),
            context_hex: "66".repeat(16),
            wallet_delta_share_hex: "33".repeat(32),
            created_at: NOW,
            pairing: Some(ServicePairing {
                service_identifier_hex: "44".repeat(32),
                key_package_json: "{}".into(),
                public_key_package_json: "{}".into(),
                service_verifying_share_hex: "55".repeat(33),
                paired_at: NOW,
                attempt_id_hex: attempt.clone(),
                service_confirmed: false,
                wallet_confirmed: false,
            }),
            session: None,
        })
        .expect("install escrow");

    let ready = |c: &std::sync::Mutex<cosigner::Cosigner>| {
        c.lock()
            .unwrap()
            .escrow(&key)
            .and_then(|e| e.pairing.as_ref().map(|p| p.state()))
            .unwrap()
            == cosigner::types::PairingState::Ready
    };

    c.lock().unwrap().confirm_pairing_by_service(&key, &attempt).unwrap();
    assert!(!ready(&c), "the service alone cannot finish a pairing");
    c.lock().unwrap().confirm_escrow_pairing(&key, &attempt).unwrap();
    assert!(ready(&c), "with both, it is finished");

    // Idempotent in both directions: a redelivered message and a retried confirmation are what
    // both routes look like under a reconnect.
    c.lock().unwrap().confirm_pairing_by_service(&key, &attempt).unwrap();
    c.lock().unwrap().confirm_escrow_pairing(&key, &attempt).unwrap();
    assert!(ready(&c));
}

/// A confirmation is for one attempt. Accepting another's would mark a pairing usable on the
/// strength of a delivery that was for a different pair of halves entirely.
#[test]
fn a_confirmation_for_another_attempt_is_refused() {
    let Some(store) = common::try_store() else { return };
    let (c, _) = wallet(&store);
    let key = "02".to_string() + &"ab".repeat(32);
    seed_escrow(&c, &key, true);

    let err = c
        .lock()
        .unwrap()
        .confirm_escrow_pairing(&key, &"bb".repeat(16))
        .expect_err("a confirmation naming another attempt must be refused");
    assert!(err.contains("different pairing attempt"), "unexpected: {err}");

    // The one it actually sealed is accepted, and twice is fine — a retried confirmation is still
    // a confirmation.
    for _ in 0..2 {
        c.lock()
            .unwrap()
            .confirm_escrow_pairing(&key, &"aa".repeat(16))
            .expect("the attempt this escrow holds");
    }
}

/// A retry must be able to pair again. A pairing that did not finish is an attempt, not a service,
/// and refusing to replace it would make the first failed delivery permanent.
#[test]
fn an_unfinished_pairing_may_be_replaced_but_a_finished_one_may_not() {
    let Some(store) = common::try_store() else { return };
    let (c, _) = wallet(&store);
    let key = "02".to_string() + &"ab".repeat(32);
    seed_escrow(&c, &key, true); // seeded Ready

    let second = |attempt: &str| ServicePairing {
        service_identifier_hex: "44".repeat(32),
        key_package_json: "{}".into(),
        public_key_package_json: "{}".into(),
        service_verifying_share_hex: "55".repeat(33),
        paired_at: NOW,
        attempt_id_hex: attempt.repeat(16),
        service_confirmed: false,
        wallet_confirmed: false,
    };

    let err = c
        .lock()
        .unwrap()
        .pair_escrow_service(&key, second("bb"))
        .expect_err("a finished pairing must not be replaced");
    assert!(err.contains("already has a service"), "unexpected: {err}");

    // Now an escrow whose pairing never finished: replacing it is exactly what a retry does.
    let unfinished = "02".to_string() + &"cd".repeat(32);
    {
        let mut guard = c.lock().unwrap();
        guard
            .install_escrow(EscrowRecord {
                escrow_key: unfinished.clone(),
                key_package_json: "{}".into(),
                public_key_package_json: "{}".into(),
                wallet_identifier_hex: "11".repeat(32),
                context_hex: "23".repeat(16),
                wallet_delta_share_hex: "33".repeat(32),
                created_at: NOW,
                pairing: Some(second("dd")), // Pending
                session: None,
            })
            .expect("install escrow");
        guard
            .pair_escrow_service(&unfinished, second("ee"))
            .expect("an attempt that did not finish may be paired again");
        assert_eq!(
            guard.escrow(&unfinished).unwrap().pairing.as_ref().unwrap().attempt_id_hex,
            "ee".repeat(16),
            "and the record that survives is the retry's, not the abandoned attempt's"
        );
    }
}
