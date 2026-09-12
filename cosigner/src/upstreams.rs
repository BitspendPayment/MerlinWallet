//! What this cosigner reaches out to: its store, and the push channel it nudges a device through.
//!
//! Not the ASP. It held an `AspClient` until the caller took over driving the Ark protocol — which
//! made a thing that is meant to be called keep a socket of its own, and made it the caller's Ark
//! client as well as its signer.
//!
//! It was `SharedServices` — shared meaning shared between tenants, one ASP connection and one
//! store serving every tenant in the process. There is one cosigner now, so there is nobody to share
//! with, and the name described an arrangement rather than a thing.

use std::sync::Arc;

use crate::fcm_client::FcmClient;
use crate::kv_store::KvStore;

pub struct Upstreams {
    pub persistence: Arc<dyn KvStore>,
    /// Push notifications. None when `FCM_SERVICE_ACCOUNT_CIPHERTEXT` is unset
    /// (auto-settle still works for users who open the app — pushes are the
    /// wake mechanism, not the only delegation path).
    pub fcm: Option<Arc<FcmClient>>,
    /// Auto-settle threshold: submit a stored intent when
    /// `now > earliest_expires_at - auto_settle_safety_margin_secs`.
    pub auto_settle_safety_margin_secs: i64,
}

impl Upstreams {
    pub fn new(
        persistence: Arc<dyn KvStore>,
        fcm: Option<Arc<FcmClient>>,
        auto_settle_safety_margin_secs: i64,
    ) -> Self {
        Self {
            persistence,
            fcm,
            auto_settle_safety_margin_secs,
        }
    }
}
