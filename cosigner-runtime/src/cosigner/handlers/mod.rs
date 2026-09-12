//! Per-RPC handler functions invoked by the user actor.
//!
//! Each handler takes `&mut CosignerInstance + &mut CosignerState + &SharedServices +
//! &CosignerRegistry + request`, runs synchronously inside `spawn_blocking`, and
//! returns `Result<Response, Status>`. Async I/O (ASP gRPC, persistence in
//! some backends) goes via `tokio::runtime::Handle::block_on` from inside the
//! blocking task, which is the safe pattern for tokio's blocking pool.

pub mod ark;
pub mod ark_send;
pub mod auto_settle;
pub mod device_token;
pub mod helpers;
pub mod parsers;
pub mod payment_request;
pub mod vtxo_stream;
