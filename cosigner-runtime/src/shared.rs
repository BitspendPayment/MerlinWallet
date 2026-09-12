//! Shared services held behind `Arc` and passed to every user actor.
//! These are upstreams that fundamentally serve all users from one connection
//! (ASP gRPC, persistence backend).

use std::sync::Arc;

use crate::auth::session::SessionAuthority;
use crate::events::EventBus;
use crate::fcm_client::FcmClient;
use crate::kv_store::KvStore;

pub struct SharedServices {
    pub persistence: Arc<dyn KvStore>,
    /// Mints + verifies the Bearer session tokens the cosigner issues after a WebAuthn assertion,
    /// using its own Ed25519 keypair (`WEBAUTH_TOKEN_SECRET`). When disabled (no secret) auth falls
    /// back to Schnorr only.
    pub session_authority: Arc<SessionAuthority>,
    /// Per-user event bus (Phase 3): publish-side for `contract_share` etc., subscribed by the SSE
    /// event stream (`/u/{vk}/events`) so a backend user can react in real time.
    pub events: EventBus,
    /// ASP gRPC client. REQUIRED — the cosigner cannot serve Ark without it (enforced at startup).
    pub asp_client: Arc<tokio::sync::Mutex<ark::client::AspClient>>,
    /// Push notifications. None when `FCM_SERVICE_ACCOUNT_CIPHERTEXT` is unset
    /// (auto-settle still works for users who open the app — pushes are the
    /// wake mechanism, not the only delegation path).
    pub fcm: Option<Arc<FcmClient>>,
    /// Auto-settle threshold: submit a stored intent when
    /// `now > earliest_expires_at - auto_settle_safety_margin_secs`.
    pub auto_settle_safety_margin_secs: i64,
    /// Per-user actor idle threshold (seconds). Read by the eviction sweep
    /// in the auto-settle tick task.
    pub actor_idle_threshold_secs: i64,
}

impl SharedServices {
    pub fn new(
        persistence: Arc<dyn KvStore>,
        asp_client: ark::client::AspClient,
        fcm: Option<Arc<FcmClient>>,
        auto_settle_safety_margin_secs: i64,
        actor_idle_threshold_secs: i64,
        session_authority: Arc<SessionAuthority>,
    ) -> Self {
        Self {
            persistence,
            session_authority,
            events: EventBus::new(),
            asp_client: Arc::new(tokio::sync::Mutex::new(asp_client)),
            fcm,
            auto_settle_safety_margin_secs,
            actor_idle_threshold_secs,
        }
    }
}
