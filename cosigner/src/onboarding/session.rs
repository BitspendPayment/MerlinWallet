//! Per-user Onboarding ceremony state. Native Rust — no WASM. Owned by the
//! `OnboardingManager`, accessed under a `parking_lot::Mutex`, evicted on TTL
//! or after step3 finalizes. The FROST round state lives in the shared
//! [`CeremonyRounds`] core; this adds only the Onboarding-specific bits.

use std::time::Instant;

use threshold::identifier::Identifier;

use super::ceremony::{CeremonyRounds, Reply};
use crate::wallet_proto::{DkgStep1Response, DkgStep3Response};

/// Freshly-minted DKG key material captured at step3 finalize, so the manager can seed it
/// straight into the guest IN-MEMORY (Plan A — the host persists only the public projection, so
/// there's no plaintext to read back from `policies`).
pub struct SeedMaterial {
    pub group_key: String,
    pub key_package_json: String,
    pub public_key_package_json: String,
    pub user_signing_identifier_hex: Option<String>,
    pub server_dkg_secret_hex: Option<String>,
}

pub struct OnboardingSession {
    pub user_id_hex: String,
    pub rounds: CeremonyRounds,
    /// Server's Onboarding secret (hex 32-byte scalar), persisted to the policy at finalize.
    pub server_internal_secret_hex: String,
    /// Set at step3 finalize: the in-memory key material the manager seeds into the guest.
    pub seed_material: Option<SeedMaterial>,
    // Rendezvous pools: replies parked until a 2-party round completes.
    pub pending_step1: Vec<Reply<DkgStep1Response>>,
    pub pending_step3: Vec<(Identifier, Reply<DkgStep3Response>)>,
    pub last_touch: Instant,
}

impl OnboardingSession {
    pub fn new(user_id_hex: String) -> Self {
        Self {
            user_id_hex,
            rounds: CeremonyRounds::default(),
            server_internal_secret_hex: String::new(),
            seed_material: None,
            pending_step1: Vec::new(),
            pending_step3: Vec::new(),
            last_touch: Instant::now(),
        }
    }
}
