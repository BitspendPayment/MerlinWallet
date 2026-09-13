//! The cosigner, as a Wasm component.
//!
//! One instance serves one wallet: which wallet is configuration, not something a caller names per
//! request — that is what removes the whole class of confusion the old `/u/{group_key}/...` routing
//! had, where a caller could name one wallet while addressing another. There is no other wallet to
//! address.
//!
//! There is no listener here and no runtime to start. The component exports
//! `wasi:http/incoming-handler`; the runtime owns the socket, the TLS and the HTTP/2 negotiation,
//! and calls [`main`] once per request. What used to be `tonic::transport::Server::builder()` is
//! gone with the rest of tonic, which does not build for `wasm32-wasip2` at all.
//!
//! Nor is there a shutdown signal. The old server caught SIGTERM so in-flight sessions could
//! finish; a guest has no signals, and the runtime stopping an instance between requests is what
//! the equivalent looks like here.

use std::sync::{Arc, Mutex};

use cosigner::grpc::Status;
use cosigner::{config, grpc, session, store};
use wstd::http::{Body, Request, Response};

#[wstd::http_server]
async fn main(req: Request<Body>) -> Result<Response<Body>, wstd::http::Error> {
    Ok(match serve(req).await {
        Ok(response) => response,
        // A failure to open the wallet at all is still a gRPC call that has to answer. Reporting it
        // in the trailers rather than as an HTTP error is what lets a client tell "this wallet is
        // misconfigured" from "the runtime could not reach the guest".
        Err(status) => grpc::failed(status),
    })
}

async fn serve(req: Request<Body>) -> Result<Response<Body>, Status> {
    let cfg = config::ServerConfig::from_environment();

    // Refuse to serve with an empty `bitcoin_network`. The client uses this string verbatim as the
    // HRP source for rendering wallet addresses; an empty value would silently fall through to a
    // wrong-network default on the client side. `from_environment` already defaults to "regtest" on
    // a missing var, so this only fires when the operator explicitly set BITCOIN_NETWORK="".
    const VALID_NETWORKS: [&str; 5] = ["mainnet", "testnet", "signet", "mutinynet", "regtest"];
    if !VALID_NETWORKS.contains(&cfg.bitcoin_network.as_str()) {
        return Err(Status::failed_precondition(format!(
            "invalid BITCOIN_NETWORK={:?}; expected one of {VALID_NETWORKS:?}",
            cfg.bitcoin_network
        )));
    }

    // The only thing this instance opens: its own store, a directory on the filesystem the runtime
    // scoped to this client. No ASP connection, no push channel — the caller drives the Ark
    // protocol and the host wakes devices.
    let store = Arc::new(
        store::Store::open(&cfg.store_dir, cfg.auto_settle_safety_margin_secs)
            .map_err(|e| Status::internal(format!("opening the store: {e}")))?,
    );

    let group_key = std::env::var("COSIGNER_GROUP_KEY").map_err(|_| {
        Status::failed_precondition("COSIGNER_GROUP_KEY is required: a cosigner serves one wallet")
    })?;

    let cosigner = Arc::new(Mutex::new(cosigner::Cosigner::open(
        store,
        group_key.clone(),
    )?));
    let server_info = cosigner::wallet_proto::GetServerInfoResponse {
        bitcoin_network: cfg.bitcoin_network.clone(),
    };

    Ok(session::CosignerService::new(cosigner, server_info)
        .route(req)
        .await)
}
