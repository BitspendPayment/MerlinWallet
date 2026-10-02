//! The settle watch: what the cosigner does in the background, with an ASP and without one.
//!
//! A guest reaches only the origins its image allowlists. Where that includes the ASP, a due
//! delegate is executed in the task itself. Where it does not — as here, since these tests pass no
//! ASP — the task does what it can always do without a connection: read its own sealed delegate,
//! compare the deadline to the clock, and wake its owner's devices.

mod common;

use std::sync::Arc;

use ark::client::types::ArkInfo;
use cosigner::handlers::watch::{Outcome, Task, CATEGORY_SETTLE_DUE, WATCH_TASK_ID};
use common::Recorder;
use cosigner::host::valid_label;
use cosigner::types::VtxoInput;

fn payload(deadline_secs: u64) -> Vec<u8> {
    serde_json::to_vec(&Task::SettleDue { deadline_secs }).unwrap()
}

fn open_with(
    store: &Arc<cosigner::store::Store>,
    host: Arc<Recorder>,
    group_key: &str,
) -> cosigner::Cosigner {
    cosigner::Cosigner::open_with_host(store.clone(), group_key.to_string(), host)
        .expect("open")
}

/// A wallet holding nothing has nothing to wake anyone about, and the watch retires itself rather
/// than asking every half hour about work that no longer exists.
#[test]
fn a_watch_with_nothing_to_settle_cancels_itself() {
    let Some(store) = common::try_store() else {
        return;
    };
    let host = Arc::new(Recorder::default());
    let mut c = open_with(&store, host.clone(), "nothing");

    let out = c.run_task(WATCH_TASK_ID, &payload(1)).expect("run");
    assert_eq!(
        serde_json::from_slice::<Outcome>(&out).unwrap(),
        Outcome::NothingToSettle
    );
    assert_eq!(*host.cancelled.lock().unwrap(), vec![WATCH_TASK_ID]);
    assert!(
        host.woken.lock().unwrap().is_empty(),
        "nobody should be woken when there is nothing to settle"
    );
}

/// A malformed payload is an error, not a silent success — the runtime retries errors and
/// persists successes, so concluding "fine" on bytes we could not read would lose the work.
#[test]
fn an_undecodable_payload_is_an_error() {
    let Some(store) = common::try_store() else {
        return;
    };
    let mut c = open_with(&store, Arc::new(Recorder::default()), "bad");

    let err = c
        .run_task(WATCH_TASK_ID, b"not json")
        .expect_err("an undecodable payload must not report success");
    assert!(err.contains("undecodable"), "unhelpful error: {err}");

    let err = c
        .run_task("not a valid id!", &payload(1))
        .expect_err("a task id outside the runtime's alphabet must be refused");
    assert!(err.contains("tenant-local"), "unhelpful error: {err}");
}

/// Arming needs a real deadline. Expiry is the ASP's to know and is 0 until it has indexed the
/// VTXOs; arming against that would wake the owner about a deadline nobody computed.
#[test]
fn an_unknown_deadline_is_not_armed() {
    let Some(store) = common::try_store() else {
        return;
    };
    let host = Arc::new(Recorder::default());
    let c = open_with(&store, host.clone(), "unknown");

    let err = c.arm_settle_watch(0).expect_err("0 is not a deadline");
    assert!(err.contains("not known yet"), "unhelpful error: {err}");
    assert!(host.enqueued.lock().unwrap().is_empty());
}

/// Arming asks for the shape `enclave:tasks` specifies: a tenant-local idempotency key, a repeating
/// interval at or above the runtime's floor, and a payload the task can decode back.
#[test]
fn arming_enqueues_a_repeating_watch() {
    let Some(store) = common::try_store() else {
        return;
    };
    let host = Arc::new(Recorder::default());
    let c = open_with(&store, host.clone(), "arm");

    c.arm_settle_watch(2_000_000_000).expect("arm");

    let enqueued = host.enqueued.lock().unwrap();
    assert_eq!(enqueued.len(), 1, "one watch, however often it is armed");
    let (id, payload, _run_at, interval) = &enqueued[0];
    assert_eq!(id, WATCH_TASK_ID);
    assert!(
        interval.is_some_and(|ms| ms >= 1000),
        "enclave:tasks requires an interval of at least 1000ms, got {interval:?}"
    );
    assert_eq!(
        serde_json::from_slice::<Task>(payload).unwrap(),
        Task::SettleDue {
            deadline_secs: 2_000_000_000
        },
        "the task must be able to decode what arming encoded"
    );
}

/// The category the app matches on is an opaque label, not prose: the payload crosses the parent
/// instance and Google, so `notify.wit` allows 1-64 of [A-Za-z0-9_-] and nothing readable.
#[test]
fn the_wake_category_is_an_opaque_label() {
    assert!(valid_label(CATEGORY_SETTLE_DUE));
    assert!(!valid_label("Your VTXOs are expiring!"));
    assert!(!valid_label(""));
    assert!(!valid_label(&"x".repeat(65)));
}

/// Regtest-shaped ASP parameters. Only the keys and delays matter here.
fn ark_info() -> ArkInfo {
    ArkInfo {
        // Real keys and a real regtest address: `generate_delegate` parses all three, and with
        // placeholders every test that needs a delegate quietly skipped.
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
    }
}

/// Build a cosigner holding a real, signed delegate — the state the watch exists to watch.
fn with_delegate(
    store: &Arc<cosigner::store::Store>,
    host: Arc<Recorder>,
) -> Option<(cosigner::Cosigner, String)> {
    let (kps, pkp) = common::dkg_2of2();
    let group_key = hex::encode(pkp.verifying_key.serialize());
    let mut c = cosigner::Cosigner::open_with_host(store.clone(), group_key.clone(), host)
        .expect("open");
    c.install_policy(
        group_key.clone(),
        &kps[1].to_json(),
        &pkp.to_json(),
        Some(&hex::encode(kps[0].identifier.serialize())),
        None,
    )
    .expect("install policy");
    c.accept_vtxos(
        vec![VtxoInput {
            txid: "a".repeat(64),
            vout: 0,
            amount_sats: 100_000,
            exit_delay: 512,
            expires_at: 0,
        }],
        &ark_info(),
    )
    .expect("accept vtxos");
    // Transport-free: the delegate is built from the cosigner's own key and the caller's ArkInfo.
    match c.generate_delegate_for(&ark_info(), false) {
        Ok(_) => Some((c, group_key)),
        Err(e) => {
            eprintln!("skip: could not build a delegate offline: {e}");
            None
        }
    }
}

/// Before the deadline the watch concludes, and concluding is not failing: the runtime retries
/// errors and persists successes, so "not due" has to be an Ok.
#[test]
fn a_watch_before_the_deadline_does_not_wake() {
    let Some(store) = common::try_store() else {
        return;
    };
    let host = Arc::new(Recorder::default());
    let Some((mut c, _)) = with_delegate(&store, host.clone()) else {
        return;
    };

    let far_future = 4_000_000_000u64;
    let out = c
        .run_task(WATCH_TASK_ID, &payload(far_future))
        .expect("a watch that is not due is a conclusion, not a failure");
    assert!(matches!(
        serde_json::from_slice::<Outcome>(&out).unwrap(),
        Outcome::NotDue { .. }
    ));
    assert!(host.woken.lock().unwrap().is_empty());
    assert!(host.cancelled.lock().unwrap().is_empty(), "still worth watching");
}

/// Past the deadline it wakes — the one call a background task may make, spending an enrolment an
/// interactive call already earned. It carries an opaque category and nothing readable.
#[test]
fn a_due_watch_wakes_the_owner() {
    let Some(store) = common::try_store() else {
        return;
    };
    let host = Arc::new(Recorder::default());
    let Some((mut c, _)) = with_delegate(&store, host.clone()) else {
        return;
    };

    let out = c
        .run_task(WATCH_TASK_ID, &payload(1))
        .expect("run");
    assert_eq!(
        serde_json::from_slice::<Outcome>(&out).unwrap(),
        Outcome::Woke { deadline_secs: 1 }
    );

    let woken = host.woken.lock().unwrap();
    assert_eq!(woken.len(), 1, "one wake per due occurrence");
    assert_eq!(woken[0].0, CATEGORY_SETTLE_DUE);
    assert!(
        host.cancelled.lock().unwrap().is_empty(),
        "the delegate is still unsettled, so the watch stays armed"
    );
}

/// An ASP that answers as scripted, and counts registrations.
#[derive(Default)]
struct ScriptedAsp {
    registrations: usize,
    refuse_registration: bool,
}

struct EndedStream;

impl cosigner::asp::EventSource for EndedStream {
    async fn next(
        &mut self,
    ) -> Result<Option<ark::client::proto::get_event_stream_response::Event>, String> {
        Ok(None)
    }
}

impl cosigner::asp::AspApi for ScriptedAsp {
    type Events = EndedStream;
    async fn get_info(&mut self) -> Result<ArkInfo, String> {
        Ok(ark_info())
    }
    async fn register_intent(&mut self, _: &str, _: &str) -> Result<String, String> {
        if self.refuse_registration {
            return Err("registerIntent: 400: refused".into());
        }
        self.registrations += 1;
        Ok(format!("intent-{}", self.registrations))
    }
    async fn events(&mut self, _: &[String]) -> Result<EndedStream, String> {
        Ok(EndedStream)
    }
    async fn confirm_registration(&mut self, _: &str) -> Result<(), String> {
        Ok(())
    }
    async fn submit_tree_nonces(&mut self, _: &str, _: &str, _: &[(String, String)]) -> Result<(), String> {
        Ok(())
    }
    async fn submit_tree_signatures(&mut self, _: &str, _: &str, _: &[(String, String)]) -> Result<(), String> {
        Ok(())
    }
    async fn submit_forfeits(&mut self, _: &[String], _: &str) -> Result<(), String> {
        Ok(())
    }
}

fn block_on<F: std::future::Future>(fut: F) -> F::Output {
    futures_executor_lite(fut)
}

/// A single-threaded executor for futures whose I/O is all scripted and never parks.
fn futures_executor_lite<F: std::future::Future>(fut: F) -> F::Output {
    use std::task::{Context, Poll, RawWaker, RawWakerVTable, Waker};
    fn noop(_: *const ()) {}
    fn clone(_: *const ()) -> RawWaker {
        RawWaker::new(std::ptr::null(), &VTABLE)
    }
    static VTABLE: RawWakerVTable = RawWakerVTable::new(clone, noop, noop, noop);
    let waker = unsafe { Waker::from_raw(RawWaker::new(std::ptr::null(), &VTABLE)) };
    let mut cx = Context::from_waker(&waker);
    let mut fut = std::pin::pin!(fut);
    loop {
        if let Poll::Ready(out) = fut.as_mut().poll(&mut cx) {
            return out;
        }
    }
}

/// A due delegate the ASP will not take is a conclusion of this run, not an error: an error is
/// retried five times and then the task is dead, and a dead watch renews nothing again. So it wakes
/// the owner, reports, and the next interval tries again.
#[test]
fn a_delegate_the_asp_refuses_wakes_the_owner_and_keeps_the_watch() {
    let Some(store) = common::try_store() else {
        return;
    };
    let host = Arc::new(Recorder::default());
    let Some((mut c, _)) = with_delegate(&store, host.clone()) else {
        return;
    };
    let mut asp = ScriptedAsp { refuse_registration: true, ..Default::default() };

    let out = block_on(c.run_task_with(WATCH_TASK_ID, &payload(1), Some(&mut asp)))
        .expect("a failed round is reported, not raised");
    assert_eq!(
        serde_json::from_slice::<Outcome>(&out).unwrap(),
        Outcome::Woke { deadline_secs: 1 }
    );
    assert_eq!(host.woken.lock().unwrap()[0].0, CATEGORY_SETTLE_DUE);
    assert!(host.cancelled.lock().unwrap().is_empty(), "the delegate is still owed");
}

/// A delegate waiting for its deadline is not a round. What a renewal reports is refused rather than
/// pinned on it — only a round in flight takes a registration or signatures.
#[test]
fn a_waiting_delegate_takes_nothing_meant_for_a_round() {
    let Some(store) = common::try_store() else {
        return;
    };
    let Some((mut c, _)) = with_delegate(&store, Arc::new(Recorder::default())) else {
        return;
    };
    assert!(c.renew_registered("intent-1".into()).is_err());
    assert!(c.renew_signed(Vec::new()).is_err());
}

/// The registration is sealed as soon as the ASP assigns it, so a run that dies mid-round and is
/// retried follows the same registration instead of making a second one.
#[test]
fn a_retried_run_follows_the_registration_it_already_made() {
    let Some(store) = common::try_store() else {
        return;
    };
    let host = Arc::new(Recorder::default());
    let Some((mut c, _)) = with_delegate(&store, host.clone()) else {
        return;
    };
    let mut asp = ScriptedAsp::default();

    for _ in 0..2 {
        // The stream ends before any batch: the round fails and the owner is woken.
        let out = block_on(c.run_task_with(WATCH_TASK_ID, &payload(1), Some(&mut asp))).unwrap();
        assert!(matches!(serde_json::from_slice::<Outcome>(&out).unwrap(), Outcome::Woke { .. }));
    }
    assert_eq!(asp.registrations, 1, "one registration, however often the run is retried");
}

/// The runtime calls `run-task` with its run id — `<id>:<generation>:<occurrence>` — not the bare
/// id it was enqueued under. Refusing that refused every run a real runtime made: the watch was
/// retried to failure on every wallet, and nobody was ever woken.
#[test]
fn a_run_id_from_the_runtime_is_accepted() {
    let Some(store) = common::try_store() else {
        return;
    };
    let host = Arc::new(Recorder::default());
    let Some((mut c, _)) = with_delegate(&store, host) else {
        return;
    };

    let run_id = format!("{WATCH_TASK_ID}:9773b23946c8f53906cda66263d0580b:0");
    let out = c
        .run_task(&run_id, &payload(4_000_000_000))
        .expect("the runtime's run id must be accepted");
    assert!(matches!(
        serde_json::from_slice::<Outcome>(&out).unwrap(),
        Outcome::NotDue { .. }
    ));

    let err = c
        .run_task("bad id!:00:0", &payload(1))
        .expect_err("the id part is still checked");
    assert!(err.contains("tenant-local"), "unhelpful error: {err}");
}

/// A renewal needs a deadline: with no expiry known there is nothing to schedule it for, and a
/// delegate valid "now" would be a refresh nobody asked for.
#[test]
fn renewing_without_a_known_expiry_is_refused() {
    let Some(store) = common::try_store() else {
        return;
    };
    let mut c = open_with(&store, Arc::new(Recorder::default()), "unindexed");
    let err = c
        .renew_delegate_open(
            vec![VtxoInput {
                txid: "a".repeat(64),
                vout: 0,
                amount_sats: 50_000,
                exit_delay: 512,
                expires_at: 0,
            }],
            &ark_info(),
            &[],
        )
        .map(|_| ())
        .expect_err("nothing to schedule against");
    assert!(err.contains("known expiry"), "unhelpful error: {err}");
}

/// Renewing the delegate re-arms the watch for its own deadline. The runtime refuses an id reused
/// with different input, so the old watch is cancelled and forgotten first — without that, the
/// second renewal a wallet ever made failed, and the first time the cosigner refreshed funds
/// itself, the wallet could never protect them again.
#[test]
fn arming_again_for_a_new_deadline_replaces_the_watch() {
    let Some(store) = common::try_store() else {
        return;
    };
    let host = Arc::new(Recorder::default());
    let c = open_with(&store, host.clone(), "rearm");

    c.arm_settle_watch(2_000_000_000).expect("first");
    c.arm_settle_watch(2_000_000_000).expect("the same deadline again is a no-op");
    c.arm_settle_watch(2_100_000_000).expect("a new deadline replaces the watch");

    let enqueued = host.enqueued.lock().unwrap();
    assert_eq!(enqueued.len(), 2);
    assert_eq!(
        serde_json::from_slice::<Task>(&enqueued[1].1).unwrap(),
        Task::SettleDue { deadline_secs: 2_100_000_000 }
    );
    assert_eq!(*host.cancelled.lock().unwrap(), vec![WATCH_TASK_ID]);
}
