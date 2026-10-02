//! Committing an escrow to its deal, through the cosigner that seals it.
//!
//! The state machine's own rules are unit-tested in `src/escrow_session.rs`. What is checked here
//! is what the cosigner does with them: that a deal cannot be struck over an escrow nobody could
//! release from, that an escrow is committed to one deal and never again, and — the one that
//! matters for a machine that is evicted and reseated constantly — that a deal survives the seal
//! and a restored instance reaches the same answers from the clock alone.

mod common;

use cosigner::escrow::{DealTerms, EscrowSession, Refusal};
use cosigner::policy::Policy;
use cosigner::types::ServicePairing;

use common::seed_escrow;

const NOW: i64 = 1_700_000_000;
const HOUR: i64 = 3_600;

/// A deal on [Policy::Always] that runs for an hour from `from`.
fn an_hour_from(from: i64) -> DealTerms {
    DealTerms::validate(Policy::Always, from, from + HOUR).unwrap()
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

    let err = c
        .lock()
        .unwrap()
        .escrow_mut(&key)
        .and_then(|e| e.strike_deal(an_hour_from(NOW)))
        .expect_err("an escrow with no service must not be committed");
    assert!(err.contains("no service paired"), "unexpected: {err}");
}

/// An escrow is committed to one deal, ever: not over a live one, and not once it is over either.
///
/// Once its deal is over the owner may open a reclaim, and the signatures that hands out can empty
/// the escrow whenever they are submitted — this cosigner cannot see whether they left the device.
/// A deal struck again over them would be one the owner could empty at will, so the next deal gets
/// the next escrow.
#[test]
fn an_escrow_is_committed_to_one_deal_ever() {
    let Some(store) = common::try_store() else { return };
    let (c, _) = wallet(&store);
    let key = "02".to_string() + &"ab".repeat(32);
    seed_escrow(&c, &key, true);

    c
        .lock()
        .unwrap()
        .escrow_mut(&key)
        .and_then(|e| e.strike_deal(an_hour_from(NOW)))
        .expect("its deal");
    // Even long after that deal is over.
    let err = c
        .lock()
        .unwrap()
        .escrow_mut(&key)
        .and_then(|e| e.strike_deal(an_hour_from(NOW + 2 * HOUR)))
        .expect_err("a second deal on one escrow");
    assert!(err.contains("already committed"), "unexpected: {err}");
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
        let terms =
            DealTerms::validate(Policy::TotalOutMax { sats: 50_000 }, NOW, NOW + HOUR).unwrap();
        let mut guard = c.lock().unwrap();
        guard.escrow_mut(&key).and_then(|e| e.strike_deal(terms)).expect("commit");
        guard.seal();
    }

    // A second instance over the same store: what the runtime does on every reseat.
    let reopened = common::open_cosigner(&store, &group_key);
    let guard = reopened.lock().unwrap();
    let escrow = guard.escrow(&key).expect("the escrow came back");
    let terms = escrow.terms.as_ref().expect("and so did its deal");

    assert_eq!(terms.deadline, NOW + HOUR);
    assert_eq!(terms.policy, Policy::TotalOutMax { sats: 50_000 });

    // And it reaches the same answers as the instance that armed it, from the clock alone — with
    // nothing written down at the deadline.
    assert!(escrow.may_release(NOW + 60).is_ok());
    assert_eq!(escrow.may_reclaim(NOW + 60), Err(Refusal::StillOpen));
    assert_eq!(escrow.may_release(NOW + HOUR), Err(Refusal::DealEnded));
    assert!(escrow.may_reclaim(NOW + HOUR).is_ok());
}

#[test]
fn a_deal_on_an_escrow_this_wallet_does_not_hold_is_refused() {
    let Some(store) = common::try_store() else { return };
    let (c, _) = wallet(&store);
    let stranger = "02".to_string() + &"ff".repeat(32);
    let err = c
        .lock()
        .unwrap()
        .escrow_mut(&stranger)
        .and_then(|e| e.strike_deal(an_hour_from(NOW)))
        .expect_err("a stranger's escrow is not this wallet's to commit");
    assert!(err.contains("no such escrow"), "unexpected: {err}");
}

/// A seal written before every escrow carried its own deal still opens — the wallet's key is in
/// it. Its escrows come back without their deals: what they hold is their owner's to take back, and
/// none is committed again. Its wallet-wide release ledger is not read.
#[test]
fn an_older_seals_escrows_load_without_their_deals() {
    let Some(store) = common::try_store() else { return };
    let (c, _) = wallet(&store);
    let key = "02".to_string() + &"ab".repeat(32);
    seed_escrow(&c, &key, true);
    let mut guard = c.lock().unwrap();

    // The shape an older seal kept: the deal on the record, the ledger beside the escrows.
    let mut snap: serde_json::Value =
        serde_json::from_slice(&guard.to_snapshot().unwrap()).unwrap();
    let escrow = snap["escrows"][0].as_object_mut().unwrap();
    escrow.remove("terms");
    escrow.remove("releases");
    escrow.insert(
        "session".into(),
        serde_json::json!({
            "escrow_key": key, "policy": {"op": "always"}, "opened_at": NOW,
            "deadline": NOW + HOUR, "released_sats": 0,
        }),
    );
    escrow.insert("reclaim_opened_at".into(), serde_json::Value::Null);
    snap["released_references"] = serde_json::json!({
        "tx-1": {
            "escrow_key": "ab".repeat(32), "request_id": "r", "sats": 1, "at": NOW,
            "proposal_hash": "p", "deadline": NOW + HOUR,
        },
    });
    guard
        .restore_snapshot(&serde_json::to_vec(&snap).unwrap())
        .expect("an older seal still opens");

    let escrow = guard.escrow(&key).expect("its escrow came back");
    assert!(escrow.terms.is_none(), "without its deal");
    assert!(escrow.may_reclaim(NOW).is_ok(), "so its owner may take it back");
    assert_eq!(guard.release_count(), 0, "the old ledger is not read");
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

    c.lock()
        .unwrap()
        .escrow_mut(&odd)
        .and_then(|e| e.strike_deal(an_hour_from(NOW)))
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

    c
        .lock()
        .unwrap()
        .escrow_mut(&key)
        .and_then(|e| e.strike_deal(an_hour_from(NOW)))
        .expect("commit it");

    assert!(
        host.enqueued().is_empty(),
        "an escrow deadline is not work; it is a number the seal already carries"
    );
    assert!(host.woken().is_empty());
}

/// And the answer it reaches without anything having run is the right one, before and after.
#[test]
fn the_deadline_decides_with_nothing_having_run_at_it() {
    let Some(store) = common::try_store() else { return };
    let (c, _) = wallet(&store);
    let key = "02".to_string() + &"ab".repeat(32);
    seed_escrow(&c, &key, true);
    c
        .lock()
        .unwrap()
        .escrow_mut(&key)
        .and_then(|e| e.strike_deal(an_hour_from(NOW)))
        .expect("commit it");

    let guard = c.lock().unwrap();
    let escrow = guard.escrow(&key).unwrap();
    assert!(escrow.may_release(NOW + HOUR - 1).is_ok());
    assert!(escrow.may_reclaim(NOW + HOUR - 1).is_err());

    // Nobody wrote anything down in between, and there is nothing that could have been: a deal is
    // a policy and a date, and the date is the whole of the decision.
    assert!(escrow.may_release(NOW + HOUR).is_err());
    assert!(escrow.may_reclaim(NOW + HOUR).is_ok());
}

/// A deal is struck before its service has finished pairing — the service can only say so once the
/// stream that strikes the deal has ended — and what holds the money meanwhile is that nothing is
/// released through a pairing it has not finished. See `release_test.rs`.
#[test]
fn a_deal_is_struck_before_its_service_has_finished_pairing() {
    let Some(store) = common::try_store() else { return };
    let (c, _) = wallet(&store);
    let key = "02".to_string() + &"ab".repeat(32);
    seed_escrow(&c, &key, false);
    c.lock()
        .unwrap()
        .escrow_mut(&key)
        .and_then(|e| e.record_pairing(pending("aa")))
        .expect("delivered, not yet vouched for");
    c.lock()
        .unwrap()
        .escrow_mut(&key)
        .and_then(|e| e.confirm_by_wallet(&"aa".repeat(16)))
        .expect("the wallet's word, as the stream gives it");

    c.lock()
        .unwrap()
        .escrow_mut(&key)
        .and_then(|e| e.strike_deal(an_hour_from(NOW)))
        .expect("the service's word arrives after the stream; the deal cannot wait for it");
}

/// A pairing delivered under attempt [attempt], vouched for by nobody yet.
fn pending(attempt: &str) -> ServicePairing {
    ServicePairing {
        service_identifier_hex: "44".repeat(32),
        key_package_json: "{}".into(),
        public_key_package_json: "{}".into(),
        service_verifying_share_hex: "55".repeat(33),
        paired_at: NOW,
        attempt_id_hex: attempt.repeat(16),
        service_confirmed: false,
        wallet_confirmed: false,
    }
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
        .install_escrow(EscrowSession {
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
            terms: None,
            releases: Default::default(),
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

    c.lock().unwrap().escrow_mut(&key).and_then(|e| e.confirm_by_service(&attempt)).unwrap();
    assert!(!ready(&c), "the service alone cannot finish a pairing");
    c.lock().unwrap().escrow_mut(&key).and_then(|e| e.confirm_by_wallet(&attempt)).unwrap();
    assert!(ready(&c), "with both, it is finished");

    // Idempotent in both directions: a redelivered message and a retried confirmation are what
    // both routes look like under a reconnect.
    c.lock().unwrap().escrow_mut(&key).and_then(|e| e.confirm_by_service(&attempt)).unwrap();
    c.lock().unwrap().escrow_mut(&key).and_then(|e| e.confirm_by_wallet(&attempt)).unwrap();
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
        .escrow_mut(&key)
        .and_then(|e| e.confirm_by_wallet(&"bb".repeat(16)))
        .expect_err("a confirmation naming another attempt must be refused");
    assert!(err.contains("different pairing attempt"), "unexpected: {err}");

    // The one it actually sealed is accepted, and twice is fine — a retried confirmation is still
    // a confirmation.
    for _ in 0..2 {
        c.lock()
            .unwrap()
            .escrow_mut(&key)
            .and_then(|e| e.confirm_by_wallet(&"aa".repeat(16)))
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
        .escrow_mut(&key)
        .and_then(|e| e.record_pairing(second("bb")))
        .expect_err("a finished pairing must not be replaced");
    assert!(err.contains("already has a service"), "unexpected: {err}");

    // Now an escrow whose pairing never finished: replacing it is exactly what a retry does.
    let unfinished = "02".to_string() + &"cd".repeat(32);
    {
        let mut guard = c.lock().unwrap();
        guard
            .install_escrow(EscrowSession {
                escrow_key: unfinished.clone(),
                key_package_json: "{}".into(),
                public_key_package_json: "{}".into(),
                wallet_identifier_hex: "11".repeat(32),
                context_hex: "23".repeat(16),
                wallet_delta_share_hex: "33".repeat(32),
                created_at: NOW,
                pairing: Some(second("dd")), // Pending
                terms: None,
                releases: Default::default(),
            })
            .expect("install escrow");
        guard
            .escrow_mut(&unfinished)
            .and_then(|e| e.record_pairing(second("ee")))
            .expect("an attempt that did not finish may be paired again");
        assert_eq!(
            guard.escrow(&unfinished).unwrap().pairing.as_ref().unwrap().attempt_id_hex,
            "ee".repeat(16),
            "and the record that survives is the retry's, not the abandoned attempt's"
        );
    }
}

// ---------------------------------------------------------------------------
// Reclaim
// ---------------------------------------------------------------------------

/// A reclaim derives its inputs' exit delay rather than accepting one.
///
/// The delay is part of a VTXO's taproot tree, so it decides the scriptPubKey the sighash commits
/// to. An indexer does not report it at all — so a caller reading what an escrow holds has nothing
/// to put there, and a zero produces `OP_0 OP_CSV`, a script the ASP refuses outright with
/// "CSV block type not allowed". Found by running the walkthrough, which is the only place a real
/// ASP sees the script.
#[test]
fn a_reclaim_ignores_the_exit_delay_it_is_given() {
    let Some(store) = common::try_store() else { return };
    // Built here rather than through `seed_escrow`, because a reclaim answers only to the
    // identifier the ceremony recorded — so the escrow's must be this wallet's real one.
    let (kps, pkp) = common::dkg_2of2();
    let group_key = hex::encode(pkp.verifying_key.serialize());
    let c = std::sync::Mutex::new(
        cosigner::Cosigner::open_with_host(
            store.clone(),
            group_key.clone(),
            std::sync::Arc::new(common::Recorder::default()),
        )
        .expect("open"),
    );
    common::seed_policy_with_dealt_share(
        &c,
        &group_key,
        &kps[1],
        &kps[0],
        &pkp,
        Some(hex::encode([7u8; 32])),
    );
    let key = group_key.clone();
    c.lock()
        .unwrap()
        .install_escrow(EscrowSession {
            escrow_key: key.clone(),
            key_package_json: kps[1].to_json(),
            public_key_package_json: pkp.to_json(),
            wallet_identifier_hex: hex::encode(kps[0].identifier.serialize()),
            context_hex: "44".repeat(16),
            wallet_delta_share_hex: "33".repeat(32),
            created_at: NOW,
            pairing: None,
            terms: None,
            releases: Default::default(),
        })
        .expect("install escrow");

    let info = ark::client::types::ArkInfo {
        signer_pubkey: "79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798".into(),
        forfeit_pubkey: "0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798".into(),
        forfeit_address: "bcrt1qq5rjlmqartxjyh6vnmjrhrqnc58q2hqr5asln0".into(),
        checkpoint_tapscript: String::new(),
        network: "regtest".into(),
        session_duration: 0,
        unilateral_exit_delay: 512,
        boarding_exit_delay: 144,
        vtxo_min_amount: 0,
        dust: 330,
    };
    // What an indexer gives a caller: no delay at all.
    let vtxos = vec![cosigner::types::VtxoInput {
        txid: "11".repeat(32),
        vout: 0,
        amount_sats: 80_000,
        exit_delay: 0,
        expires_at: 0,
    }];

    let guard = c.lock().unwrap();
    // The escrow has no session here, so nothing is holding it and a reclaim is permitted; what is
    // being checked is that it BUILDS, which it cannot at a zero delay.
    let reclaim = guard
        .reclaim_open(&key, vtxos, &info, NOW)
        .expect("a reclaim must build from what an indexer actually reports");
    assert_eq!(reclaim.amount_sats, 80_000);
    drop(guard);

    // The delay it actually used, read off the sighashes: they commit to the prevout's script, so
    // a build at one delay cannot produce a build at another's. Compare against both candidates.
    let sighashes_at = |delay: u32| {
        let owner = &key[2..];
        ark::client::send::SendSession::build(
            owner,
            &[ark::client::send::SendVtxoInput {
                txid: "11".repeat(32),
                vout: 0,
                amount_sats: 80_000,
                exit_delay: delay,
            }],
            &reclaim.to_ark_address,
            80_000,
            None,
            &info,
        )
        .expect("it builds")
        .1
        .iter()
        .map(|s| s.to_vec())
        .collect::<Vec<_>>()
    };

    assert_eq!(
        reclaim.sighashes,
        sighashes_at(512),
        "a reclaim must build at the ASP's unilateral exit delay"
    );
    assert_ne!(
        reclaim.sighashes,
        sighashes_at(0),
        "and NOT at the zero an indexer's silence leaves behind — that is `OP_0 OP_CSV`, which no \
         ASP will take"
    );

    // And where it goes was derived, not asked for.
    assert!(reclaim.to_ark_address.starts_with("tark1"), "{}", reclaim.to_ark_address);
}
