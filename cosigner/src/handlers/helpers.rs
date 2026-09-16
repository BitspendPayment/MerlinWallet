//! Small helpers shared by the handlers.
//!
//! This was the multi-tenant toolkit: `verify_auth` checked a Schnorr signature on every request,
//! and a set of `*_user_*` helpers keyed per-user rows in a shared store by group key, resolved
//! through `policy_owner_idx`. None of it has a job now. Authentication is the runtime's — a request
//! reaches this instance only with the tenant a passkey resolved to — and one instance is one wallet
//! over its own filesystem, so there are no per-user rows to key. Most of those helpers had no
//! callers left well before this; the two that did deleted store trees nothing wrote.

/// Seconds since the Unix epoch.
pub fn now_secs() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs() as i64
}
