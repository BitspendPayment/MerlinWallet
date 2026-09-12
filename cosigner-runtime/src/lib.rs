//! Library target. Exposes module internals so integration tests and future
//! tooling can reuse them without going through the `main.rs` binary.

pub mod auth;
pub mod bitcoin;
pub mod config;
pub mod cosigner;
pub mod events;
pub mod fcm_client;
pub mod onboarding;
pub mod kv_store;
pub mod session;
pub mod shared;
pub mod telemetry;

pub mod wallet_proto {
    tonic::include_proto!("mpc_wallet");
}
