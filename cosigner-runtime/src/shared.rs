//! The upstreams this cosigner talks to, held behind one `Arc`: its store, the ASP, and the push
//! channel it nudges a device through.

use std::sync::Arc;

use crate::fcm_client::FcmClient;
use crate::kv_store::KvStore;

pub struct SharedServices {
    pub persistence: Arc<dyn KvStore>,
    /// ASP gRPC client. REQUIRED — the cosigner cannot serve Ark without it (enforced at startup).
    pub asp_client: Arc<tokio::sync::Mutex<ark::client::AspClient>>,
    /// Push notifications. None when `FCM_SERVICE_ACCOUNT_CIPHERTEXT` is unset
    /// (auto-settle still works for users who open the app — pushes are the
    /// wake mechanism, not the only delegation path).
    pub fcm: Option<Arc<FcmClient>>,
    /// Auto-settle threshold: submit a stored intent when
    /// `now > earliest_expires_at - auto_settle_safety_margin_secs`.
    pub auto_settle_safety_margin_secs: i64,
}

impl SharedServices {
    pub fn new(
        persistence: Arc<dyn KvStore>,
        asp_client: ark::client::AspClient,
        fcm: Option<Arc<FcmClient>>,
        auto_settle_safety_margin_secs: i64,
    ) -> Self {
        Self {
            persistence,
            asp_client: Arc::new(tokio::sync::Mutex::new(asp_client)),
            fcm,
            auto_settle_safety_margin_secs,
        }
    }
}
