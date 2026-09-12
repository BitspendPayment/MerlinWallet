//! What this cosigner reaches out to: its store, and nothing else.
//!
//! It held an `AspClient` until the caller took over driving the Ark protocol, and an `FcmClient`
//! until waking a device became the host's job. Both gave a thing that is meant to be *called* a
//! socket of its own — and the push in particular needed a detached task that outlived the call,
//! which a per-request runtime does not have.
//!
//! It was `SharedServices` — shared meaning shared between tenants, one ASP connection and one
//! store serving every tenant in the process. There is one cosigner now, so there is nobody to share
//! with, and the name described an arrangement rather than a thing.

use std::sync::Arc;

use crate::kv_store::KvStore;

pub struct Upstreams {
    pub persistence: Arc<dyn KvStore>,
    /// Auto-settle threshold: submit a stored intent when
    /// `now > earliest_expires_at - auto_settle_safety_margin_secs`.
    pub auto_settle_safety_margin_secs: i64,
}

impl Upstreams {
    pub fn new(
        persistence: Arc<dyn KvStore>,
        auto_settle_safety_margin_secs: i64,
    ) -> Self {
        Self {
            persistence,
            auto_settle_safety_margin_secs,
        }
    }
}
