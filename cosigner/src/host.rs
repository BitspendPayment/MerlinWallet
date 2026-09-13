//! What the cosigner asks of the runtime it runs inside.
//!
//! Two capabilities, mirroring `enclave:tasks/queue` and `enclave:notify/notify` in
//! `~/enclave-runtime/wit/` method for method, so the guest port is an adapter rather than a
//! translation. The runtime binds every call to the current tenant; nothing here takes a tenant id.
//!
//! ## Why this is a trait and not the WIT import
//!
//! The cosigner is still a native process. Naming the capability now means the code that needs it
//! can be written and tested against a fake, and the WIT binding becomes one `impl` when the guest
//! port happens.
//!
//! ## What a background task can and cannot do
//!
//! It cannot reach the network. `wasmtime_wasi`'s `SocketAddrCheck` defaults to refusing every
//! address and the runtime never overrides it, so a guest has no egress at all — not in a request,
//! not in a task. That rules out the obvious shape for unattended settling: a task cannot register
//! an intent, relay a batch round, or ask the ASP what arrived.
//!
//! What it can do without a socket is read its own sealed state and compare a deadline to the
//! clock. So the cosigner does not settle in the background — it *wakes its owner* when a settle
//! comes due, with the delegate already signed and waiting, and the app drives the round over the
//! attested channel. `notify.wit` names this as the primary use: "a finished task telling its owner
//! to come and look".

use std::fmt;

/// `enclave:tasks/queue` + `enclave:notify/notify`.
///
/// Mutating calls — `enqueue`, `register_device`, `forget_device` — are interactive-only in the
/// runtime: background work cannot grant itself standing work or a standing way to reach a device.
/// `wake` is the deliberate exception, because spending an enrolment an interactive call already
/// made is the whole point of a task.
pub trait Host: Send + Sync {
    /// `id` is a tenant-local idempotency key: ASCII letters, digits, `-` or `_`.
    /// `run_at_ms` is Unix milliseconds. `interval_ms`, when present, is at least 1000.
    fn enqueue(
        &self,
        id: &str,
        payload: &[u8],
        run_at_ms: u64,
        interval_ms: Option<u64>,
    ) -> Result<(), String>;

    /// A JSON task record: state, attempt count and result bytes. The cosigner does not read it
    /// today; it is here because the runtime offers it and a mirror with holes is not a mirror.
    fn status(&self, id: &str) -> Result<String, String>;

    fn cancel(&self, id: &str) -> Result<(), String>;

    /// Drop a terminal record to release quota. Never removes running work.
    fn forget(&self, id: &str) -> Result<(), String>;

    /// Enrol an FCM token. The cosigner never sees it again — the runtime owns the registry, which
    /// is why there is no `devices() -> [token]`, only a count.
    fn register_device(&self, token: &str) -> Result<(), String>;

    fn forget_device(&self, token: &str) -> Result<(), String>;

    fn devices(&self) -> Result<u32, String>;

    /// Wake every device this tenant enrolled.
    ///
    /// `category` and `reference` are opaque labels, 1–64 of `[A-Za-z0-9_-]`. NOT prose: the
    /// payload crosses the parent instance and Google, the two parties the design excludes from a
    /// tenant's data, so it carries nothing a person reads. The app wakes and fetches the detail
    /// over the attested channel.
    fn wake(&self, category: &str, reference: Option<&str>) -> Result<(), String>;
}

/// The runtime is not there.
///
/// Every call fails rather than succeeding quietly. A cosigner running as a plain process has no
/// task queue and no push channel, and a silent no-op would let a settle deadline pass with
/// everything looking healthy — which is the failure this whole path exists to prevent.
pub struct Detached;

impl Host for Detached {
    fn enqueue(&self, id: &str, _: &[u8], _: u64, _: Option<u64>) -> Result<(), String> {
        Err(format!("no runtime to enqueue {id}: not running as a guest"))
    }
    fn status(&self, id: &str) -> Result<String, String> {
        Err(format!("no runtime to ask about {id}: not running as a guest"))
    }
    fn cancel(&self, id: &str) -> Result<(), String> {
        Err(format!("no runtime to cancel {id}: not running as a guest"))
    }
    fn forget(&self, id: &str) -> Result<(), String> {
        Err(format!("no runtime to forget {id}: not running as a guest"))
    }
    fn register_device(&self, _: &str) -> Result<(), String> {
        Err("no runtime to enrol a device with: not running as a guest".into())
    }
    fn forget_device(&self, _: &str) -> Result<(), String> {
        Err("no runtime to forget a device with: not running as a guest".into())
    }
    fn devices(&self) -> Result<u32, String> {
        Ok(0)
    }
    fn wake(&self, category: &str, _: Option<&str>) -> Result<(), String> {
        Err(format!(
            "no runtime to wake devices for {category}: not running as a guest"
        ))
    }
}

/// Validate an opaque label the way `notify.wit` specifies, so a bad one is refused here rather
/// than at the host boundary where the error has less to say.
pub fn valid_label(s: &str) -> bool {
    (1..=64).contains(&s.chars().count())
        && s.chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '_' || c == '-')
}

/// Validate a task id: the same alphabet, and the runtime treats it as an idempotency key.
pub fn valid_task_id(s: &str) -> bool {
    valid_label(s)
}

impl fmt::Debug for dyn Host {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("Host")
    }
}
