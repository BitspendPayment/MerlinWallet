//! One DKG ceremony's state, owned by the stream driving it.
//!
//! It used to live in an `OnboardingManager`'s map behind a mutex, with a TTL and an eviction
//! sweep, because the ceremony spanned three separate requests and the key material had to survive
//! between them. On one stream it is a local: created at open, dropped when the stream ends. An
//! abandoned ceremony leaves nothing for a sweep to find.
//!
//! The FROST round state lives in [`CeremonyRounds`]; this adds only the DKG-specific bits.

use super::ceremony::CeremonyRounds;

/// Freshly-minted DKG key material, captured when round 3 finalizes so the caller can install it
/// straight from memory. The host persists only the public projection, so there is no plaintext to
/// read back from `policies`.
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
    /// Set when round 3 finalizes: the key material to install.
    pub seed_material: Option<SeedMaterial>,
}

impl OnboardingSession {
    pub fn new(user_id_hex: String) -> Self {
        Self {
            user_id_hex,
            rounds: CeremonyRounds::default(),
            server_internal_secret_hex: String::new(),
            seed_material: None,
        }
    }
}
