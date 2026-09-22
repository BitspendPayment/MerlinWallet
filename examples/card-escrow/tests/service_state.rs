//! What the service must not lose, and what it must keep apart.
//!
//! Two of the demonstrations are about the service rather than the escrow: that a restart does not
//! strand work, and that two customers on one service do not tread on each other.

use std::sync::Arc;

use card_escrow::policy::Terms;
use card_escrow::service::wire::Connections;
use card_escrow::service::{PersistedInput, PersistedProposal, Reimbursement, Service, Stage};

fn terms() -> Terms {
    Terms::example("ark1service".into(), "http://127.0.0.1:7100".into())
}

fn service(path: Option<std::path::PathBuf>) -> Arc<Service> {
    Service::new(
        threshold::identifier::Identifier::derive(b"merlin-e2e-escrow-service").unwrap(),
        "ark1service".into(),
        "http://127.0.0.1:7070".into(),
        "http://127.0.0.1:7100".into(),
        terms(),
        path,
    )
}

fn cleared(request_id: &str) -> Reimbursement {
    Reimbursement {
        request_id: request_id.into(),
        escrow_key: "02".to_string() + &"ab".repeat(32),
        authorization_token: "txn_auth_0001".into(),
        clearing_token: Some("txn_clr_0002".into()),
        amount_minor: 2_000,
        currency: "USD".into(),
        sats: 20_000,
        stage: Stage::CardCleared,
        last_refusal: None,
        needs_reconciliation: false,
        proposal: None,
        signatures: Vec::new(),
        expected_txid: None,
        ark_txid: None,
    }
}

/// A purchase that had cleared but not been reimbursed when the process died is still owed, and the
/// service must come back knowing it.
#[tokio::test]
async fn a_restart_keeps_work_that_was_not_finished() {
    let dir = std::env::temp_dir().join(format!("card-escrow-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let path = dir.join("restart.json");
    let _ = std::fs::remove_file(&path);

    {
        let before = service(Some(path.clone()));
        before
            .store
            .lock()
            .await
            .reimbursements
            .insert("reimb-0001".into(), cleared("reimb-0001"));
        before.persist().await.unwrap();
    }

    // A different process, with nothing in memory.
    let after = service(Some(path.clone()));
    after.restore().await.unwrap();
    let tracked = after.tracked().await;
    assert_eq!(tracked.len(), 1);
    assert_eq!(tracked[0].stage, Stage::CardCleared);
    assert!(
        tracked[0].ready_to_ask(),
        "a cleared purchase that was never paid is still owed after a restart"
    );

    std::fs::remove_file(&path).ok();
}

/// And what it comes back with carries no nonce, because none was ever written.
///
/// A retry after a restart uses fresh nonces, which the cosigner answers as a repeat — signed
/// again, counted once. That is what makes persisting one unnecessary, and persisting a single-use
/// nonce is how a share is given away.
#[tokio::test]
async fn nothing_that_survives_a_restart_is_a_nonce() {
    let s = service(None);
    s.store
        .lock()
        .await
        .reimbursements
        .insert("reimb-0001".into(), cleared("reimb-0001"));
    let written = serde_json::to_string(&*s.store.lock().await).unwrap();
    for forbidden in ["nonce", "hiding", "binding"] {
        assert!(
            !written.contains(forbidden),
            "the store carries {forbidden:?}: {written}"
        );
    }
}

/// A confirmed payment stays confirmed, whatever arrives afterwards.
#[tokio::test]
async fn a_late_message_cannot_unconfirm_a_payment() {
    let s = service(None);
    let mut paid = cleared("reimb-0001");
    paid.stage = Stage::ReleaseConfirmed;
    paid.ark_txid = Some("abcd".into());
    s.store
        .lock()
        .await
        .reimbursements
        .insert("reimb-0001".into(), paid);

    s.advance("reimb-0001", Stage::CardCleared).await;
    let tracked = s.tracked().await;
    assert_eq!(tracked[0].stage, Stage::ReleaseConfirmed);
    assert!(!tracked[0].ready_to_ask(), "and it is not asked for again");
}

/// Two wallets, one service, and the same local stream name.
///
/// The cosigner derives its stream id from the SERVICE, so every wallet it serves opens under the
/// same local name. Only the tenant the runtime puts in front tells them apart — and without that
/// each new customer would close the last one's connection and answers would go to the wrong one.
#[test]
fn two_customers_are_held_as_two_connections_under_one_name() {
    let local = cosigner::service_stream::service_stream_id(&"44".repeat(32));
    let alice = format!("{}-{local}", "11".repeat(16));
    let bob = format!("{}-{local}", "22".repeat(16));

    assert_ne!(alice, bob, "two tenants must not share a connection name");
    assert!(alice.ends_with(&format!("-{local}")));
    assert!(bob.ends_with(&format!("-{local}")));

    // And a service keying by the whole id holds both at once.
    let connections = Connections::default();
    assert_eq!(connections.held_under(&local), 0);
    assert!(!connections.is_holding(&alice));
}


// ===============================================================================================
// Recovery
//
// The runtime re-dials a dropped connection on its own. What it cannot do is finish a
// reimbursement whose request went out and whose answer never came back — something has to ask
// again, and the only party that can is this one.
// ===============================================================================================

/// A connection that goes away takes nothing with it.
///
/// Dropping every held connection is what a network partition looks like from in here. The work is
/// still owed afterwards, and still asked for.
#[tokio::test]
async fn work_outlives_the_connection_it_was_waiting_on() {
    let s = service(None);
    s.store
        .lock()
        .await
        .reimbursements
        .insert("reimb-0001".into(), cleared("reimb-0001"));

    let connections = Connections::default();
    assert_eq!(connections.drop_all(), 0, "nothing held yet");

    // The reimbursement is untouched by the connection going, and is still owed.
    let tracked = s.tracked().await;
    assert_eq!(tracked[0].stage, Stage::CardCleared);
    assert!(
        tracked[0].ready_to_ask(),
        "a drop is a reason to ask again, not a reason to stop"
    );
}

/// What could not be said while the connection was down is said on the next one.
///
/// Not dropped: the runtime re-establishes these, so a moment without a connection is a wait.
#[tokio::test]
async fn what_could_not_be_said_waits_for_the_next_connection() {
    let connections = std::sync::Arc::new(Connections::default());
    let service = service(None);
    let wire = std::sync::Arc::new(card_escrow::service::wire::Wire {
        service,
        connections: std::sync::Arc::clone(&connections),
    });

    // Nothing is holding a connection, so this has nowhere to go — and is kept rather than lost.
    card_escrow::service::wire::say(
        &wire,
        "tenant-svc-abc",
        cosigner::service_stream::FromService::PairingReady {
            escrow_key: "02aa".into(),
            attempt_id: "0011".into(),
        },
    );
    assert!(
        !connections.is_holding("tenant-svc-abc"),
        "nothing was holding it"
    );
    assert_eq!(
        connections.waiting_for("tenant-svc-abc"),
        1,
        "and the message is waiting for the next dial rather than gone"
    );
}

/// A retry is not a second claim.
///
/// The request id is stable across every attempt, which is the whole reason retrying is safe: the
/// cosigner answers a repeat by signing again and counting nothing.
#[tokio::test]
async fn a_retry_carries_the_same_request_id() {
    let s = service(None);
    let first = cleared("reimb-0001");
    s.store
        .lock()
        .await
        .reimbursements
        .insert(first.request_id.clone(), first.clone());

    // Whatever else changes between attempts, this does not.
    let again = s.tracked().await.into_iter().next().unwrap();
    assert_eq!(again.request_id, first.request_id);
    assert_eq!(again.clearing_token, first.clearing_token);
}

/// A reimbursement whose outcome this service cannot determine stops being asked about.
///
/// Retrying something that may already have landed, for ever, is how a loop runs for ever.
#[tokio::test]
async fn one_that_cannot_be_determined_stops_the_retrying() {
    let s = service(None);
    let mut stuck = cleared("reimb-0001");
    stuck.stage = Stage::ReleaseSigned;
    stuck.needs_reconciliation = true;
    s.store
        .lock()
        .await
        .reimbursements
        .insert("reimb-0001".into(), stuck);

    assert!(
        !s.tracked().await[0].ready_to_ask(),
        "it waits for a person, not for another attempt"
    );
}

// ===============================================================================================
// A retry is the SAME release
// ===============================================================================================

/// A retry must propose what was proposed the first time, not what the escrow holds now.
///
/// This is the one that bites after a successful release whose reply was lost. Spending a
/// 100,000-sat VTXO to pay 20,000 leaves 80,000 of change behind — so an attempt that rebuilt from
/// current inputs would propose spending the *change*, which is a different release under an
/// already-answered request id. The cosigner refuses it, correctly, and the retry loop would ask
/// again for ever.
#[tokio::test]
async fn a_retry_proposes_what_was_proposed_the_first_time() {
    let s = service(None);
    let mut first = cleared("reimb-0001");
    first.proposal = Some(PersistedProposal {
        to_ark_address: "ark1service".into(),
        amount_sats: 20_000,
        inputs: vec![PersistedInput {
            txid: "11".repeat(32),
            vout: 0,
            amount_sats: 100_000,
            exit_delay: 512,
        }],
    });
    s.store
        .lock()
        .await
        .reimbursements
        .insert("reimb-0001".into(), first.clone());

    // Whatever the escrow holds later, this is what a retry has to say.
    let kept = s.tracked().await.into_iter().next().unwrap().proposal.unwrap();
    assert_eq!(kept.inputs.len(), 1);
    assert_eq!(kept.inputs[0].amount_sats, 100_000, "the ORIGINAL input, not the change");
    assert_eq!(kept.amount_sats, 20_000);
    assert_eq!(kept, first.proposal.unwrap());
}

/// And it survives a restart, because that is when a retry is most likely to be the first thing
/// that happens.
#[tokio::test]
async fn the_proposal_survives_a_restart() {
    let dir = std::env::temp_dir().join(format!("card-escrow-proposal-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let path = dir.join("proposal.json");
    let _ = std::fs::remove_file(&path);

    {
        let before = service(Some(path.clone()));
        let mut r = cleared("reimb-0001");
        r.stage = Stage::ReleaseSigned;
        r.expected_txid = Some("ab".repeat(32));
        r.proposal = Some(PersistedProposal {
            to_ark_address: "ark1service".into(),
            amount_sats: 20_000,
            inputs: vec![PersistedInput {
                txid: "11".repeat(32),
                vout: 0,
                amount_sats: 100_000,
                exit_delay: 512,
            }],
        });
        before.store.lock().await.reimbursements.insert("reimb-0001".into(), r);
        before.persist().await.unwrap();
    }

    let after = service(Some(path.clone()));
    after.restore().await.unwrap();
    let back = after.tracked().await.into_iter().next().unwrap();
    assert_eq!(back.proposal.unwrap().inputs[0].amount_sats, 100_000);
    assert_eq!(
        back.expected_txid,
        Some("ab".repeat(32)),
        "what was about to be submitted is what a retry asks the chain about"
    );

    std::fs::remove_file(&path).ok();
}

// ===============================================================================================
// Saving
// ===============================================================================================

/// Several things save at once — an operator's request, the retry loop, a pairing completing — and
/// they share a temporary file and a destination.
///
/// Without one writer at a time, two savers write the same `.tmp` and rename in whichever order
/// they finish: one overwrites the other's bytes, or renames a file the other already moved.
#[tokio::test]
async fn concurrent_saves_do_not_tread_on_each_other() {
    let dir = std::env::temp_dir().join(format!("card-escrow-saves-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let path = dir.join("concurrent.json");
    let _ = std::fs::remove_file(&path);

    let s = service(Some(path.clone()));
    for i in 0..8 {
        s.store
            .lock()
            .await
            .reimbursements
            .insert(format!("reimb-{i:04}"), cleared(&format!("reimb-{i:04}")));
    }

    let mut savers = Vec::new();
    for _ in 0..32 {
        let s = std::sync::Arc::clone(&s);
        savers.push(tokio::spawn(async move { s.persist().await }));
    }
    for saver in savers {
        saver.await.unwrap().expect("every save lands, or none can be trusted");
    }

    // And what is on disk is a whole, readable snapshot rather than a half-written one.
    let restored = service(Some(path.clone()));
    restored.restore().await.expect("the file is intact");
    assert_eq!(restored.tracked().await.len(), 8);

    std::fs::remove_file(&path).ok();
}

// ===============================================================================================
// Finishing an already-approved payment
// ===============================================================================================

/// A release that was signed and never submitted can be finished without asking anybody.
///
/// This is the window that matters: the process dies between signing and submitting, and by the
/// time it comes back the deadline has passed. The cosigner is right to refuse a second approval —
/// the deal is over — but the payment was already agreed and the merchant has already been paid.
/// The signatures are what close that gap, and they are public: BIP-340 signatures that go on the
/// chain, nothing like the single-use nonces that are never written down.
#[tokio::test]
async fn a_signed_release_keeps_everything_it_needs_to_be_submitted() {
    let dir = std::env::temp_dir().join(format!("card-escrow-signed-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let path = dir.join("signed.json");
    let _ = std::fs::remove_file(&path);

    {
        let before = service(Some(path.clone()));
        let mut r = cleared("reimb-0001");
        r.stage = Stage::ReleaseSigned;
        r.proposal = Some(PersistedProposal {
            to_ark_address: "ark1service".into(),
            amount_sats: 20_000,
            inputs: vec![PersistedInput {
                txid: "11".repeat(32),
                vout: 0,
                amount_sats: 100_000,
                exit_delay: 512,
            }],
        });
        // Two sighashes, one per input across the ark tx and its checkpoint.
        r.signatures = vec!["ab".repeat(64), "cd".repeat(64)];
        r.expected_txid = Some("ef".repeat(32));
        before.store.lock().await.reimbursements.insert("reimb-0001".into(), r);
        before.persist().await.unwrap();
    }

    // A different process, with nothing in memory and no way to ask for a new approval.
    let after = service(Some(path.clone()));
    after.restore().await.unwrap();
    let back = after.tracked().await.into_iter().next().unwrap();

    assert_eq!(back.signatures.len(), 2, "the signatures came back");
    assert!(back.proposal.is_some(), "and what they sign");
    assert_eq!(back.expected_txid, Some("ef".repeat(32)));
    assert_eq!(
        back.signatures[0].len(),
        128,
        "64 bytes of hex — a finished BIP-340 signature, not anything secret"
    );

    std::fs::remove_file(&path).ok();
}

/// And what is kept is never a nonce.
///
/// Two signatures under one nonce give up the share by simple algebra, so no nonce is ever written
/// down — not to survive a restart, not for anything. What IS written is the finished signature,
/// which is public the moment it exists.
#[tokio::test]
async fn what_is_kept_to_finish_a_payment_is_never_secret() {
    let s = service(None);
    let mut r = cleared("reimb-0001");
    r.signatures = vec!["ab".repeat(64)];
    r.expected_txid = Some("ef".repeat(32));
    s.store.lock().await.reimbursements.insert("reimb-0001".into(), r);

    let written = serde_json::to_string(&*s.store.lock().await).unwrap();
    for forbidden in ["nonce", "hiding", "binding", "secret_share"] {
        assert!(
            !written.contains(forbidden),
            "the store carries {forbidden:?}: {written}"
        );
    }
}

/// Two purchases on one escrow do not both go looking for inputs.
///
/// The guard has to be keyed by the ESCROW, not the reimbursement — that is the resource. Keyed by
/// request id, both purchases would claim successfully, each read the same VTXOs, and each be
/// signed for them: the allowance spent twice for money only one of them can move, and the loser
/// left tied to inputs that no longer exist.
///
/// Driven through `ask`, because the binding being tested is at the call site rather than in the
/// lock. Nothing reaches an ASP: the claim is taken first, and that is the point.
#[tokio::test]
async fn a_second_purchase_on_one_escrow_waits_for_the_first() {
    let s = service(None);
    let escrow = "02aa";
    for id in ["reimb-0001", "reimb-0002"] {
        let mut r = cleared(id);
        r.escrow_key = escrow.into();
        s.store.lock().await.reimbursements.insert(id.into(), r);
    }
    let wire = std::sync::Arc::new(card_escrow::service::wire::Wire {
        service: std::sync::Arc::clone(&s),
        connections: std::sync::Arc::new(card_escrow::service::wire::Connections::default()),
    });

    // Something is already spending from this escrow.
    let held = s.claim(escrow).await.expect("the first purchase has it");

    // The second must be turned away here, before it looks at a single VTXO.
    match card_escrow::service::reimburse::ask(&wire, "reimb-0002").await {
        card_escrow::service::reimburse::Asked::Failed { reason } => assert!(
            reason.contains("already spending from this escrow"),
            "turned away for the wrong reason: {reason}"
        ),
        other => panic!("a second purchase must not proceed: {other:?}"),
    }

    drop(held);
}

// ===============================================================================================
// A part-finished spend keeps its escrow
// ===============================================================================================

/// A purchase that was signed and whose submission failed still owns the inputs it picked out.
///
/// This is the window an in-memory lock cannot cover. The lock is released when the attempt
/// returns — and a failed submission is an attempt returning — but the transaction may still be on
/// its way to the chain and the inputs are still unspent. A second purchase selecting them would
/// get its own signatures, and the cosigner would rightly approve: different request, different
/// payment, different proposal. Both would spend the allowance; only one could settle.
#[tokio::test]
async fn a_failed_submission_still_holds_the_escrow() {
    let s = service(None);
    let escrow = "02aa";

    // Purchase A: signed, and its submission failed. The lock it held is long gone.
    let mut a = cleared("reimb-0001");
    a.escrow_key = escrow.into();
    a.stage = Stage::ReleaseSigned;
    a.proposal = Some(PersistedProposal {
        to_ark_address: "ark1service".into(),
        amount_sats: 20_000,
        inputs: vec![PersistedInput {
            txid: "11".repeat(32),
            vout: 0,
            amount_sats: 100_000,
            exit_delay: 512,
        }],
    });
    a.signatures = vec!["ab".repeat(64), "cd".repeat(64)];
    a.expected_txid = Some("ef".repeat(32));
    a.last_refusal = Some("the ASP would not take it".into());

    // Purchase B: cleared, and about to go looking for inputs.
    let mut b = cleared("reimb-0002");
    b.escrow_key = escrow.into();

    {
        let mut store = s.store.lock().await;
        store.reimbursements.insert("reimb-0001".into(), a);
        store.reimbursements.insert("reimb-0002".into(), b);
    }

    assert_eq!(
        s.reserved_by(escrow, "reimb-0002").await.as_deref(),
        Some("reimb-0001"),
        "A's inputs are still live, so the escrow is still A's"
    );
    // And A is not blocked by itself: a retry is the holder coming back.
    assert_eq!(s.reserved_by(escrow, "reimb-0001").await, None);

    let wire = std::sync::Arc::new(card_escrow::service::wire::Wire {
        service: std::sync::Arc::clone(&s),
        connections: std::sync::Arc::new(card_escrow::service::wire::Connections::default()),
    });
    match card_escrow::service::reimburse::ask(&wire, "reimb-0002").await {
        card_escrow::service::reimburse::Asked::Failed { reason } => assert!(
            reason.contains("part-finished"),
            "B was turned away for the wrong reason: {reason}"
        ),
        other => panic!("B must not select A's inputs: {other:?}"),
    }
}

/// And the reservation survives a restart, because it is a property of what was written down
/// rather than of a lock held by a process that is no longer running.
#[tokio::test]
async fn a_part_finished_spend_still_holds_the_escrow_after_a_restart() {
    let dir = std::env::temp_dir().join(format!("card-escrow-reserve-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let path = dir.join("reserve.json");
    let _ = std::fs::remove_file(&path);

    {
        let before = service(Some(path.clone()));
        let mut a = cleared("reimb-0001");
        a.escrow_key = "02aa".into();
        a.stage = Stage::ReleaseSigned;
        a.proposal = Some(PersistedProposal {
            to_ark_address: "ark1service".into(),
            amount_sats: 20_000,
            inputs: vec![PersistedInput {
                txid: "11".repeat(32),
                vout: 0,
                amount_sats: 100_000,
                exit_delay: 512,
            }],
        });
        a.signatures = vec!["ab".repeat(64)];
        let mut b = cleared("reimb-0002");
        b.escrow_key = "02aa".into();
        let mut store = before.store.lock().await;
        store.reimbursements.insert("reimb-0001".into(), a);
        store.reimbursements.insert("reimb-0002".into(), b);
        drop(store);
        before.persist().await.unwrap();
    }

    // A different process. Nothing holds a lock, and nothing needs to.
    let after = service(Some(path.clone()));
    after.restore().await.unwrap();
    assert_eq!(
        after.reserved_by("02aa", "reimb-0002").await.as_deref(),
        Some("reimb-0001"),
        "a spend that outlived the process that started it still owns its inputs"
    );

    std::fs::remove_file(&path).ok();
}

/// Once the holder is settled — or given up on — the escrow is free again.
///
/// Otherwise a single unresolvable purchase would block the escrow for ever, which is a different
/// way of losing the money.
#[tokio::test]
async fn a_settled_or_abandoned_spend_frees_the_escrow() {
    let s = service(None);
    let escrow = "02aa";

    let held = |stage: Stage, reconciling: bool| {
        let mut r = cleared("reimb-0001");
        r.escrow_key = escrow.into();
        r.stage = stage;
        r.needs_reconciliation = reconciling;
        r.proposal = Some(PersistedProposal {
            to_ark_address: "ark1service".into(),
            amount_sats: 20_000,
            inputs: vec![PersistedInput {
                txid: "11".repeat(32),
                vout: 0,
                amount_sats: 100_000,
                exit_delay: 512,
            }],
        });
        r
    };

    for (stage, reconciling, still_held) in [
        (Stage::ReleaseSigned, false, true),
        (Stage::EvidenceVerified, false, true),
        // Paid: the inputs are spent, and there is nothing left to reserve.
        (Stage::ReleaseConfirmed, false, false),
        // Given up on: a person has it now, and the escrow must not be blocked for ever.
        (Stage::ReleaseSigned, true, false),
    ] {
        s.store
            .lock()
            .await
            .reimbursements
            .insert("reimb-0001".into(), held(stage, reconciling));
        assert_eq!(
            s.reserved_by(escrow, "reimb-0002").await.is_some(),
            still_held,
            "stage {stage:?}, reconciling {reconciling}"
        );
    }
}
