//! One cosigner, serving one wallet.
//!
//! [`Cosigner`] holds the keys, the FROST ceremonies and the Ark sessions; [`instance::Cosigner`]
//! is the wallet this process serves, loaded from its seal. Tenancy is deliberately absent: the
//! runtime this is built for hands an instance a filesystem already scoped to one client, so there
//! is nothing here to route between.

pub mod cosigner;
pub mod auth;
pub mod config;
pub mod handlers;
pub mod kv_store;
pub mod session;
pub mod upstreams;
pub mod store;
pub mod types;

pub use cosigner::Cosigner;
pub use types::ArkTxEntry;

pub mod wallet_proto {
    tonic::include_proto!("mpc_wallet");
}
