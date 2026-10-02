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
//! It reaches exactly what its image allows, and nothing else. `wasmtime_wasi`'s `SocketAddrCheck`
//! refuses every address by default; a deployment overrides it with an origin allowlist that is
//! image configuration, measured into PCR0 — so a client learns where this guest may send traffic
//! from the same attestation that tells it what the guest is. This deployment allows the ASP.
//!
//! So a settle that has come due is executed in the task itself rather than handed back to a phone;
//! see `crate::asp`. Where the image names no ASP, the task falls back on the thing it can always
//! do without a connection: read its own sealed state, compare a deadline to the clock, and *wake
//! its owner*, with the delegate already signed and waiting for the app to drive over the attested
//! channel. `notify.wit` names that as the primary use: "a finished task telling its owner to come
//! and look".

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

    // --- Connections to services, held by the runtime -----------------------------------------
    //
    // Outbound: each message from a service is one invocation.

    /// Hold a connection to `origin`, which the image must allow. Survives a restart.
    fn stream_open(&self, id: &str, origin: &str) -> Result<(), String>;

    /// Stop maintaining it. Idempotent.
    fn stream_close(&self, id: &str) -> Result<(), String>;

    /// One message to the far side.
    ///
    /// Fails when the connection is down rather than queueing: only the caller knows whether a
    /// message is still worth sending after the far side has been absent.
    fn stream_send(&self, id: &str, payload: &[u8]) -> Result<(), String>;

    /// A JSON record: whether it is connected, and enough history to tell "never worked" from
    /// "flapping".
    fn stream_status(&self, id: &str) -> Result<String, String>;
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

    fn stream_open(&self, id: &str, _: &str) -> Result<(), String> {
        Err(format!("no runtime to hold a connection {id}: not running as a guest"))
    }

    fn stream_close(&self, _: &str) -> Result<(), String> {
        // Closing what was never opened is what a caller wants either way.
        Ok(())
    }

    fn stream_send(&self, id: &str, _: &[u8]) -> Result<(), String> {
        Err(format!("no connection {id} to send on: not running as a guest"))
    }

    fn stream_status(&self, id: &str) -> Result<String, String> {
        Err(format!("no connection {id}: not running as a guest"))
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
