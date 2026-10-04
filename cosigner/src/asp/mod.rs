//! The cosigner's own connection to its ASP — for renewing funds with nobody connected.
//!
//! Everything interactive still goes through the caller: a send or a settle is driven by the app,
//! which relays each ASP event on the stream and makes each ASP call the cosigner asks for. That
//! works because the app is there. A **sealed delegate** exists for when it is not: the wallet has
//! already signed the intent and the forfeits, so executing it needs only the cosigner's own key —
//! and a connection to the ASP, which is what this module is.
//!
//! The guest learns the address from `ASP_URL` in its environment, a setting written into the guest
//! file at deployment and measured into PCR16 with the code. The runtime lets a guest reach the
//! public internet and, in the emulator, its host — an ASP on either.
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

/// An ASP that is not there.
///
/// Not a fallback so much as the truth for a build or a deployment that names no ASP:
/// every call fails, so a path that needed one says so instead of quietly doing less. The task
/// watch and the escrow release both take `Option<impl AspApi>` and this is what stands in when
/// there is none.
pub struct NoAsp;

impl AspApi for NoAsp {
    type Events = NoEvents;
    async fn get_info(&mut self) -> Result<ark::client::types::ArkInfo, String> {
        Err("this deployment names no ASP".into())
    }
    async fn register_intent(&mut self, _: &str, _: &str) -> Result<String, String> {
        Err("this deployment names no ASP".into())
    }
    async fn events(&mut self, _: &[String]) -> Result<NoEvents, String> {
        Err("this deployment names no ASP".into())
    }
    async fn confirm_registration(&mut self, _: &str) -> Result<(), String> {
        Err("this deployment names no ASP".into())
    }
    async fn submit_tree_nonces(&mut self, _: &str, _: &str, _: &[(String, String)]) -> Result<(), String> {
        Err("this deployment names no ASP".into())
    }
    async fn submit_tree_signatures(&mut self, _: &str, _: &str, _: &[(String, String)]) -> Result<(), String> {
        Err("this deployment names no ASP".into())
    }
    async fn submit_forfeits(&mut self, _: &[String], _: &str) -> Result<(), String> {
        Err("this deployment names no ASP".into())
    }
}

pub struct NoEvents;

impl EventSource for NoEvents {
    async fn next(&mut self) -> Result<Option<Event>, String> {
        Ok(None)
    }
}
