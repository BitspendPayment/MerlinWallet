//! Native-Rust onboarding. The `OnboardingManager` owns short-lived
//! `OnboardingSession`s keyed by `user_id_hex`, evicts stale ones, and persists
//! `policy_state` to sled on step3 success. The long-lived per-user actor in
//! `CosignerRegistry` is spawned lazily on the first post-onboarding request.

mod ceremony;
pub mod handlers;
pub mod session;

