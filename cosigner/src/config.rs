use std::env;

/// What the runtime passes the guest, as environment variables.
///
/// Three values, and none of them is an endpoint — though not for want of anywhere to go. A guest
/// reaches exactly the origins its image allowlists, and `ASP_URL` is one of them; it is read where
/// it is used (`asp::rest::AspRest::from_env`) rather than here, so a deployment naming no ASP has
/// no connection at all rather than a half-configured one. `COSIGNER_GROUP_KEY` — which wallet this
/// instance serves — is read in `main` rather than here, because a missing one is a refusal to
/// serve rather than a default.
#[derive(Debug, Clone)]
pub struct Config {
    /// Directory the KV store lives in, e.g. `/var/lib/cosigner`. Created at open, so a fresh
    /// deployment needs no setup. `:memory:` gives an ephemeral store (tests). Env `STORE_DIR`.
    pub store_dir: String,
    /// Bitcoin network name (e.g. "regtest", "signet", "testnet", "mainnet").
    /// Used for logging; the authoritative network comes from the ASP's GetArkInfo.
    pub bitcoin_network: String,
    /// Auto-settle threshold: submit a stored delegate intent when
    /// `now > earliest_expires_at - this`. Default 30 minutes.
    pub auto_settle_safety_margin_secs: i64,
}

impl Config {
    /// Load configuration from environment variables.
    pub fn from_environment() -> Self {
        Self {
            store_dir: env::var("STORE_DIR")
                .ok()
                .filter(|s| !s.is_empty())
                .unwrap_or_else(|| DEFAULT_STORE_DIR.to_string()),
            bitcoin_network: env::var("BITCOIN_NETWORK").unwrap_or_else(|_| "regtest".to_string()),
            auto_settle_safety_margin_secs: env::var("AUTO_SETTLE_SAFETY_MARGIN_SECS")
                .ok()
                .and_then(|s| s.parse().ok())
                .unwrap_or(1800),
        }
    }
}

/// Where the store lives when `STORE_DIR` is unset. A relative path so a bare test run works
/// without root; deployments point this at the filesystem the runtime scoped to this client.
const DEFAULT_STORE_DIR: &str = "data/cosigner";
