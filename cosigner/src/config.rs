use std::env;

/// Server configuration loaded from environment variables.
/// Mirrors the Dart `ServerConfig` from `server/lib/config.dart`.
#[derive(Debug, Clone)]
pub struct ServerConfig {
    /// Filesystem path to the SQLite database backing the single KV store, e.g.
    /// `/var/lib/cosigner/state.db`. Parent directories are created at open. `:memory:` gives an
    /// ephemeral store (tests). Env `SQLITE_PATH`.
    pub sqlite_path: String,
    /// ASP (Ark Service Provider) gRPC URL, e.g. "http://localhost:7070".
    /// When empty, Ark RPCs return UNAVAILABLE.
    pub asp_url: String,
    /// Bitcoin network name (e.g. "regtest", "signet", "testnet", "mainnet").
    /// Used for logging; the authoritative network comes from the ASP's GetArkInfo.
    pub bitcoin_network: String,
    /// Auto-settle threshold: submit a stored delegate intent when
    /// `now > earliest_expires_at - this`. Default 30 minutes.
    pub auto_settle_safety_margin_secs: i64,
}

impl ServerConfig {
    /// Load configuration from environment variables.
    /// Supports Docker secrets via `_FILE` suffix pattern.
    pub fn from_environment() -> Self {
        Self {
            sqlite_path: env::var("SQLITE_PATH")
                .ok()
                .filter(|s| !s.is_empty())
                .unwrap_or_else(|| DEFAULT_SQLITE_PATH.to_string()),
            asp_url: env::var("ASP_URL").unwrap_or_default(),
            bitcoin_network: env::var("BITCOIN_NETWORK").unwrap_or_else(|_| "regtest".to_string()),
            auto_settle_safety_margin_secs: env::var("AUTO_SETTLE_SAFETY_MARGIN_SECS")
                .ok()
                .and_then(|s| s.parse().ok())
                .unwrap_or(1800),
        }
    }
}

/// Where the KV database lives when `SQLITE_PATH` is unset. A relative path so a bare `cargo run`
/// works without root; deployments point this at the mounted data volume.
const DEFAULT_SQLITE_PATH: &str = "data/cosigner.db";
