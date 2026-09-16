//! The settle watch: when a sealed delegate comes due, the cosigner runs it.
//!
//! A VTXO expires. The wallet signs a delegate to refresh it while it is here — see
//! `handlers/delegate.rs` — and the cosigner seals it and enqueues this watch for the moment it
//! becomes valid. Then, with no request in flight and nobody connected, the task opens the wallet,
//! registers the sealed intent with the ASP over the enclave's one allowed origin, follows the round,
//! and signs the tree with the cosigner's own key.
//!
//! Waking the owner is the fallback, for when it cannot: the image names no ASP, or the round failed.
//! A failure is a conclusion of this run, not an error — an error is retried five times and then the
//! task is dead, and a watch that died would renew nothing ever again. So it reports, wakes, and the
//! next interval tries again.

use serde::{Deserialize, Serialize};

use crate::asp::AspApi;
use crate::cosigner::Cosigner;
use crate::host::{valid_label, valid_task_id};

/// The id the watch is enqueued under. Tenant-local, and an idempotency key: re-arming replaces
/// rather than accumulating, so a wallet has one watch however many times it prepares a delegate.
pub const WATCH_TASK_ID: &str = "settle-watch";

/// How often the watch runs again after its first run at the deadline — the retry cadence for a
/// round that did not complete. `enclave:tasks` requires at least 1000ms.
pub const WATCH_INTERVAL_MS: u64 = 30 * 60 * 1000;

/// The wake category the app matches on. Opaque by contract — see `notify.wit`. Raised when a due
/// delegate could not be run here, so the owner can refresh in person.
pub const CATEGORY_SETTLE_DUE: &str = "settle-due";

/// Raised after the cosigner refreshed the funds itself: the refreshed VTXO has no delegate yet, and
/// the next time the owner is here the wallet seals one.
pub const CATEGORY_DELEGATE_SETTLED: &str = "delegate-settled";

/// What the watch carries. Small and self-describing so the runtime's stored payload stays
/// readable, and so a future second task kind does not need a new queue id.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(tag = "kind", rename_all = "kebab-case")]
pub enum Task {
    /// Wake the owner once the sealed delegate's intent becomes valid.
    SettleDue {
        /// Unix seconds: earliest covered VTXO expiry minus the safety margin.
        deadline_secs: u64,
    },
}

/// What a run of the watch concluded. Returned to the caller so a test can assert on it, and
/// encoded as the task's result so the runtime persists something meaningful.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(tag = "outcome", rename_all = "kebab-case")]
pub enum Outcome {
    /// Nothing is owed yet.
    NotDue { deadline_secs: u64, now_secs: u64 },
    /// The cosigner ran the delegate: the funds are refreshed.
    Settled { commitment_txid: String },
    /// Due, and not run here — no ASP, or the round failed. The devices were woken.
    Woke { deadline_secs: u64 },
    /// There is no delegate to settle any more — the watch cancels itself.
    NothingToSettle,
}

impl Cosigner {
    /// The body of the guest's exported `run-task`, with no ASP to run a delegate against — so a
    /// due delegate wakes the owner instead.
    pub fn run_task(&mut self, task_id: &str, payload: &[u8]) -> Result<Vec<u8>, String> {
        futures_lite_block_on(self.run_task_with::<NoAsp>(task_id, payload, None))
    }

    /// The body of the guest's exported `run-task`.
    ///
    /// `task_id` is the runtime's *run* id, `<id>:<generation>:<occurrence>` — stable across retries
    /// of one occurrence, distinct across occurrences — not the id it was enqueued under. Only the
    /// id is ours to check; the rest identifies the run.
    ///
    /// Errors are retried by the runtime and successes are persisted, so anything recoverable must
    /// return `Err` and anything concluded must return `Ok` — including "not due" and "could not
    /// run it", which are conclusions and not failures.
    pub async fn run_task_with<A: AspApi>(
        &mut self,
        task_id: &str,
        payload: &[u8],
        asp: Option<&mut A>,
    ) -> Result<Vec<u8>, String> {
        let id = task_id.split(':').next().unwrap_or_default();
        if !valid_task_id(id) {
            return Err(format!("task id {task_id:?} is not a tenant-local key"));
        }
        let task: Task = serde_json::from_slice(payload)
            .map_err(|e| format!("undecodable task payload: {e}"))?;
        let outcome = match task {
            Task::SettleDue { deadline_secs } => self.settle_due(deadline_secs, asp).await?,
        };
        serde_json::to_vec(&outcome).map_err(|e| format!("encode outcome: {e}"))
    }

    async fn settle_due<A: AspApi>(
        &mut self,
        deadline_secs: u64,
        asp: Option<&mut A>,
    ) -> Result<Outcome, String> {
        // No sealed delegate: it was run, or spent by a send, or replaced — nothing is owed. The
        // cancel is best-effort (a background run may not mutate the queue); the next seal re-arms.
        if self.delegate_session.is_none() {
            self.host.cancel(WATCH_TASK_ID).ok();
            return Ok(Outcome::NothingToSettle);
        }

        let now = crate::store::now_secs().max(0) as u64;
        if now < deadline_secs {
            return Ok(Outcome::NotDue {
                deadline_secs,
                now_secs: now,
            });
        }

        if let Some(asp) = asp {
            match self.execute_delegate(asp).await {
                Ok(commitment_txid) => {
                    // Best-effort: the refresh happened either way.
                    self.host.wake(CATEGORY_DELEGATE_SETTLED, None).ok();
                    return Ok(Outcome::Settled { commitment_txid });
                }
                Err(e) => eprintln!("the sealed delegate could not be run: {e}"),
            }
        }

        // The one call a task may make that an interactive call had to earn first. It spends the
        // enrolment; it authorizes nothing.
        self.host
            .wake(CATEGORY_SETTLE_DUE, None)
            .map_err(|e| format!("wake: {e}"))?;
        Ok(Outcome::Woke { deadline_secs })
    }

    /// Arm the watch. Interactive only, because `enqueue` is: background work cannot grant itself
    /// standing work, so this rides the call that prepared the delegate.
    ///
    /// `deadline_secs` of 0 means the expiry was unknown — the ASP had not indexed the VTXOs yet —
    /// and arming against a made-up deadline would wake the owner for nothing. Refused rather than
    /// guessed.
    pub fn arm_settle_watch(&self, deadline_secs: u64) -> Result<(), String> {
        if deadline_secs == 0 {
            return Err("no deadline to watch: the VTXO expiries are not known yet".into());
        }
        debug_assert!(valid_label(CATEGORY_SETTLE_DUE));
        let payload = serde_json::to_vec(&Task::SettleDue { deadline_secs })
            .map_err(|e| format!("encode task: {e}"))?;
        // First run at the deadline itself — a delegate is not valid before it, so running earlier
        // would only report NotDue and put the real run a whole interval late. One already past
        // runs at once; one missed while the enclave was down runs when it recovers the queue.
        let run_at_ms = deadline_secs * 1000;
        let enqueue = || self.host.enqueue(WATCH_TASK_ID, &payload, run_at_ms, Some(WATCH_INTERVAL_MS));
        match enqueue() {
            Ok(()) => Ok(()),
            // A task id is an idempotency key: arming again with the same deadline is a no-op, and
            // with a different one — a new delegate over VTXOs that expire at another time — the
            // runtime refuses until the old record is gone. Cancelled is terminal, so it can then be
            // forgotten, and the id is free. The watch cannot be running meanwhile: sealing happens
            // in a request, which holds the tenant the background task would need.
            Err(e) if e.contains("different input") => {
                self.host.cancel(WATCH_TASK_ID).map_err(|e| format!("re-arming the watch: {e}"))?;
                self.host.forget(WATCH_TASK_ID).map_err(|e| format!("re-arming the watch: {e}"))?;
                enqueue()
            }
            Err(e) => Err(e),
        }
    }
}

/// The watch without an ASP.
struct NoAsp;

impl AspApi for NoAsp {
    type Events = NoEvents;
    async fn get_info(&mut self) -> Result<ark::client::types::ArkInfo, String> {
        Err("no ASP".into())
    }
    async fn register_intent(&mut self, _: &str, _: &str) -> Result<String, String> {
        Err("no ASP".into())
    }
    async fn events(&mut self, _: &[String]) -> Result<NoEvents, String> {
        Err("no ASP".into())
    }
    async fn confirm_registration(&mut self, _: &str) -> Result<(), String> {
        Err("no ASP".into())
    }
    async fn submit_tree_nonces(&mut self, _: &str, _: &str, _: &[(String, String)]) -> Result<(), String> {
        Err("no ASP".into())
    }
    async fn submit_tree_signatures(&mut self, _: &str, _: &str, _: &[(String, String)]) -> Result<(), String> {
        Err("no ASP".into())
    }
    async fn submit_forfeits(&mut self, _: &[String], _: &str) -> Result<(), String> {
        Err("no ASP".into())
    }
}

struct NoEvents;

impl crate::asp::EventSource for NoEvents {
    async fn next(
        &mut self,
    ) -> Result<Option<ark::client::proto::get_event_stream_response::Event>, String> {
        Ok(None)
    }
}

/// Drive a future that never actually waits — `run_task` with no ASP makes no I/O.
fn futures_lite_block_on<F: std::future::Future>(fut: F) -> F::Output {
    use std::task::{Context, Poll, RawWaker, RawWakerVTable, Waker};
    fn noop(_: *const ()) {}
    fn clone(_: *const ()) -> RawWaker {
        RawWaker::new(std::ptr::null(), &VTABLE)
    }
    static VTABLE: RawWakerVTable = RawWakerVTable::new(clone, noop, noop, noop);
    let waker = unsafe { Waker::from_raw(RawWaker::new(std::ptr::null(), &VTABLE)) };
    let mut cx = Context::from_waker(&waker);
    let mut fut = std::pin::pin!(fut);
    match fut.as_mut().poll(&mut cx) {
        Poll::Ready(out) => out,
        Poll::Pending => panic!("run_task without an ASP never waits"),
    }
}
