//! The settle watch: the cosigner's half of unattended settling.
//!
//! A VTXO expires. Before the rewrite a 60-second tick inside an always-on process noticed and
//! settled it; that process is gone, and the thing replacing it cannot reach the ASP from a
//! background task — `wasmtime_wasi` refuses every address to a guest. So a task cannot settle.
//!
//! What it can do is know the deadline. The delegate is prepared while the caller is here: the app
//! relays one ASP round, the cosigner produces a signed `ReadyToSettle` delegate and seals it, and
//! the same interactive call enqueues a repeating check. Later, with no network and no caller, the
//! task compares the sealed deadline to the clock and wakes the owner's devices. The app comes
//! back, finds the delegate already signed, and drives the round.
//!
//! That is strictly more durable than the tick it replaces, which only ran while the process
//! happened to be up. A queued task survives a restart by construction.

use serde::{Deserialize, Serialize};

use crate::cosigner::Cosigner;
use crate::host::{valid_label, valid_task_id};

/// The id the watch is enqueued under. Tenant-local, and an idempotency key: re-arming replaces
/// rather than accumulating, so a wallet has one watch however many times it prepares a delegate.
pub const WATCH_TASK_ID: &str = "settle-watch";

/// How often the watch runs. `enclave:tasks` requires at least 1000ms; half an hour is the
/// coarsest interval that still leaves room to act inside a safety margin measured in hours.
pub const WATCH_INTERVAL_MS: u64 = 30 * 60 * 1000;

/// The wake category the app matches on. Opaque by contract — see `notify.wit`.
pub const CATEGORY_SETTLE_DUE: &str = "settle-due";

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
    /// The devices were woken.
    Woke { deadline_secs: u64 },
    /// There is no delegate to settle any more — the watch cancels itself.
    NothingToSettle,
}

impl Cosigner {
    /// The body of the guest's exported `run-task`.
    ///
    /// Errors are retried by the runtime and successes are persisted, so anything recoverable must
    /// return `Err` and anything concluded must return `Ok` — including "not due", which is a
    /// conclusion and not a failure.
    pub fn run_task(&mut self, task_id: &str, payload: &[u8]) -> Result<Vec<u8>, String> {
        if !valid_task_id(task_id) {
            return Err(format!("task id {task_id:?} is not a tenant-local key"));
        }
        let task: Task = serde_json::from_slice(payload)
            .map_err(|e| format!("undecodable task payload: {e}"))?;
        let outcome = match task {
            Task::SettleDue { deadline_secs } => self.settle_due(deadline_secs)?,
        };
        serde_json::to_vec(&outcome).map_err(|e| format!("encode outcome: {e}"))
    }

    fn settle_due(&mut self, deadline_secs: u64) -> Result<Outcome, String> {
        // A delegate that is gone was settled, spent or invalidated while we were not looking.
        // Cancelling is the honest end: leaving the watch queued would wake the owner every half
        // hour about work that no longer exists.
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
        // First run now rather than at the deadline: the interval is what carries it forward, and
        // a check that runs early simply reports NotDue. Arming for the deadline itself would mean
        // a missed occurrence lands a whole interval late.
        let run_at_ms = (crate::store::now_secs().max(0) as u64) * 1000;
        self.host
            .enqueue(WATCH_TASK_ID, &payload, run_at_ms, Some(WATCH_INTERVAL_MS))
    }
}
