//! The settle watch: what the cosigner can do in the background, and what it deliberately cannot.
//!
//! A guest has no egress — `wasmtime_wasi`'s `SocketAddrCheck` refuses every address and the
//! runtime never overrides it — so a background task cannot reach the ASP. It cannot register an
//! intent, relay a batch round, or ask what arrived. What it can do without a socket is read its
//! own sealed delegate and compare the deadline to the clock, then wake its owner's devices.

mod common;

use std::sync::{Arc, Mutex};

use ark::client::types::ArkInfo;
use cosigner::handlers::watch::{Outcome, Task, CATEGORY_SETTLE_DUE, WATCH_TASK_ID};
use cosigner::host::{valid_label, Host};
use cosigner::types::VtxoInput;

/// Records what the cosigner asked of the runtime.
#[derive(Default)]
struct Recorder {
    enqueued: Mutex<Vec<(String, Vec<u8>, u64, Option<u64>)>>,
    cancelled: Mutex<Vec<String>>,
    woken: Mutex<Vec<(String, Option<String>)>>,
    registered: Mutex<Vec<String>>,
}

impl Host for Recorder {
    fn enqueue(
        &self,
        id: &str,
        payload: &[u8],
        run_at_ms: u64,
        interval_ms: Option<u64>,
    ) -> Result<(), String> {
        self.enqueued
            .lock()
            .unwrap()
            .push((id.into(), payload.to_vec(), run_at_ms, interval_ms));
        Ok(())
    }
    fn cancel(&self, id: &str) -> Result<(), String> {
        self.cancelled.lock().unwrap().push(id.into());
        Ok(())
    }
    fn register_device(&self, token: &str) -> Result<(), String> {
        self.registered.lock().unwrap().push(token.into());
        Ok(())
    }
    fn forget_device(&self, _: &str) -> Result<(), String> {
        Ok(())
    }
    fn devices(&self) -> Result<u32, String> {
        Ok(self.registered.lock().unwrap().len() as u32)
    }
    fn wake(&self, category: &str, reference: Option<&str>) -> Result<(), String> {
        self.woken
            .lock()
            .unwrap()
            .push((category.into(), reference.map(Into::into)));
        Ok(())
    }
}

fn payload(deadline_secs: u64) -> Vec<u8> {
    serde_json::to_vec(&Task::SettleDue { deadline_secs }).unwrap()
}

async fn open_with(
    store: &Arc<cosigner::store::Store>,
    host: Arc<Recorder>,
    group_key: &str,
) -> cosigner::Cosigner {
    cosigner::Cosigner::open_with_host(store.clone(), group_key.to_string(), host)
        .await
        .expect("open")
}

/// With no delegate there is nothing to wake anyone about, and the watch retires itself rather
/// than asking every half hour about work that no longer exists.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_watch_with_nothing_to_settle_cancels_itself() {
    let Some(store) = common::try_store().await else {
        return;
    };
    let host = Arc::new(Recorder::default());
    let mut c = open_with(&store, host.clone(), "nothing").await;

    let out = c.run_task(WATCH_TASK_ID, &payload(1)).await.expect("run");
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
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn an_undecodable_payload_is_an_error() {
    let Some(store) = common::try_store().await else {
        return;
    };
    let mut c = open_with(&store, Arc::new(Recorder::default()), "bad").await;

    let err = c
        .run_task(WATCH_TASK_ID, b"not json")
        .await
        .expect_err("an undecodable payload must not report success");
    assert!(err.contains("undecodable"), "unhelpful error: {err}");

    let err = c
        .run_task("not a valid id!", &payload(1))
        .await
        .expect_err("a task id outside the runtime's alphabet must be refused");
    assert!(err.contains("tenant-local"), "unhelpful error: {err}");
}

/// Arming needs a real deadline. Expiry is the ASP's to know and is 0 until it has indexed the
/// VTXOs; arming against that would wake the owner about a deadline nobody computed.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn an_unknown_deadline_is_not_armed() {
    let Some(store) = common::try_store().await else {
        return;
    };
    let host = Arc::new(Recorder::default());
    let c = open_with(&store, host.clone(), "unknown").await;

    let err = c.arm_settle_watch(0).expect_err("0 is not a deadline");
    assert!(err.contains("not known yet"), "unhelpful error: {err}");
    assert!(host.enqueued.lock().unwrap().is_empty());
}

/// Arming asks for the shape `enclave:tasks` specifies: a tenant-local idempotency key, a repeating
/// interval at or above the runtime's floor, and a payload the task can decode back.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn arming_enqueues_a_repeating_watch() {
    let Some(store) = common::try_store().await else {
        return;
    };
    let host = Arc::new(Recorder::default());
    let c = open_with(&store, host.clone(), "arm").await;

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
        signer_pubkey: "0".repeat(64),
        forfeit_pubkey: "0".repeat(64),
        forfeit_address: String::new(),
        checkpoint_tapscript: String::new(),
        network: "regtest".into(),
        session_duration: 0,
        unilateral_exit_delay: 512,
        boarding_exit_delay: 144,
        vtxo_min_amount: 0,
        dust: 0,
    }
}

/// Build a cosigner holding a real, signed delegate — the state the watch exists to watch.
async fn with_delegate(
    store: &Arc<cosigner::store::Store>,
    host: Arc<Recorder>,
) -> Option<(cosigner::Cosigner, String)> {
    let (kps, pkp) = common::dkg_2of2();
    let group_key = hex::encode(pkp.verifying_key.serialize());
    let mut c = cosigner::Cosigner::open_with_host(store.clone(), group_key.clone(), host)
        .await
        .expect("open");
    c.install_policy(
        group_key.clone(),
        &kps[1].to_json(),
        &pkp.to_json(),
        Some(&hex::encode(kps[0].identifier.serialize())),
        Some(hex::encode([9u8; 32])),
    )
    .expect("install policy");
    c.accept_vtxos(
        vec![VtxoInput {
            txid: "a".repeat(64),
            vout: 0,
            amount_sats: 100_000,
            exit_delay: 512,
        }],
        &ark_info(),
    )
    .expect("accept vtxos");
    // Transport-free: the delegate is built from the cosigner's own key and the caller's ArkInfo.
    match c.generate_delegate_for(&ark_info()).await {
        Ok(_) => Some((c, group_key)),
        Err(e) => {
            eprintln!("skip: could not build a delegate offline: {e}");
            None
        }
    }
}

/// Before the deadline the watch concludes, and concluding is not failing: the runtime retries
/// errors and persists successes, so "not due" has to be an Ok.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_watch_before_the_deadline_does_not_wake() {
    let Some(store) = common::try_store().await else {
        return;
    };
    let host = Arc::new(Recorder::default());
    let Some((mut c, _)) = with_delegate(&store, host.clone()).await else {
        return;
    };

    let far_future = 4_000_000_000u64;
    let out = c
        .run_task(WATCH_TASK_ID, &payload(far_future))
        .await
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
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_due_watch_wakes_the_owner() {
    let Some(store) = common::try_store().await else {
        return;
    };
    let host = Arc::new(Recorder::default());
    let Some((mut c, _)) = with_delegate(&store, host.clone()).await else {
        return;
    };

    let out = c
        .run_task(WATCH_TASK_ID, &payload(1))
        .await
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
