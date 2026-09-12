//! One cosigner, serving one wallet.
//!
//! [`Cosigner`] is that wallet: its keys, its FROST ceremonies, its Ark sessions, loaded from its
//! seal when the process opens. Tenancy is deliberately absent — the runtime this is built for
//! hands an instance a filesystem already scoped to one client, so there is nothing here to route
//! between — and so are outbound sockets: the ASP is driven by whoever calls, and waking a device
//! is the host's. What is left talks to its [`store`] and to its caller.

pub mod auth;
pub mod config;
pub mod cosigner;
pub mod handlers;
pub mod session;
pub mod store;
pub mod types;

pub use cosigner::Cosigner;
pub use types::ArkTxEntry;

pub mod wallet_proto {
    tonic::include_proto!("mpc_wallet");
}
