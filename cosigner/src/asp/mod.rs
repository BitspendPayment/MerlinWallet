//! The cosigner's own connection to its ASP — for renewing funds with nobody connected.
//!
//! Everything interactive still goes through the caller: a send or a settle is driven by the app,
//! which relays each ASP event on the stream and makes each ASP call the cosigner asks for. That
//! works because the app is there. A **sealed delegate** exists for when it is not: the wallet has
//! already signed the intent and the forfeits, so executing it needs only the cosigner's own key —
//! and a connection to the ASP, which is what this module is.
//!
//! The enclave admits exactly the ASP's origin (`guestEgressOrigins` in the runtime's deployment),
//! and the guest learns the address from `ASP_URL` in its environment. Both are image configuration,
//! measured into PCR0.
//!
//! It speaks arkd's REST gateway over HTTP/1.1 — the only version a guest's `wasi:http` offers —
//! with the event stream as server-sent events. [`AspApi`] is the seam: the executor is written
//! against it, [`rest::AspRest`] implements it in the guest, and tests implement it with a script.

pub mod json;
pub mod sse;

#[cfg(target_arch = "wasm32")]
pub mod rest;

use ark::client::proto::get_event_stream_response::Event;
use ark::client::types::ArkInfo;

/// What one delegate round needs from the ASP.
#[allow(async_fn_in_trait)]
pub trait AspApi {
    type Events: EventSource;

    async fn get_info(&mut self) -> Result<ArkInfo, String>;
    async fn register_intent(&mut self, proof: &str, message: &str) -> Result<String, String>;
    async fn events(&mut self, topics: &[String]) -> Result<Self::Events, String>;
    async fn confirm_registration(&mut self, intent_id: &str) -> Result<(), String>;
    async fn submit_tree_nonces(
        &mut self,
        batch_id: &str,
        pubkey: &str,
        nonces: &[(String, String)],
    ) -> Result<(), String>;
    async fn submit_tree_signatures(
        &mut self,
        batch_id: &str,
        pubkey: &str,
        signatures: &[(String, String)],
    ) -> Result<(), String>;
    async fn submit_forfeits(
        &mut self,
        signed_forfeit_txs: &[String],
        signed_commitment_tx: &str,
    ) -> Result<(), String>;
}

/// The ASP's event stream. `Ok(None)` when it ended.
#[allow(async_fn_in_trait)]
pub trait EventSource {
    async fn next(&mut self) -> Result<Option<Event>, String>;
}
