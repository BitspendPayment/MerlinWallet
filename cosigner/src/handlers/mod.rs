//! Per-RPC handler functions invoked by the user actor.
//!
//! Each handler takes `&mut CosignerInstance + &mut CosignerState + &Store +
//! &CosignerRegistry + request`, runs synchronously inside `spawn_blocking`, and
//! returns `Result<Response, Status>`. Async I/O (ASP gRPC, persistence in
//! some backends) goes via `tokio::runtime::Handle::block_on` from inside the
//! blocking task, which is the safe pattern for tokio's blocking pool.

pub mod ark_send;
pub mod helpers;
pub mod onboarding;
pub mod settle;
pub mod parsers;
pub mod payment_request;
