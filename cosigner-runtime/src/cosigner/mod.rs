//! The cosigner. One `CosignerActor` holds the keys, the FROST ceremonies and the Ark sessions;
//! `instance::Cosigner` is the single wallet this process serves, loaded from its seal.

pub mod actor;
pub mod handlers;
pub mod store;
pub mod instance;
pub mod state;
pub mod types;

pub use actor::CosignerActor;
pub use state::CosignerState;
pub use types::ArkTxEntry;
