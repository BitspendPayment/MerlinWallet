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
use cosigner::{config, grpc, session, store, Cosigner};
use wstd::http::{Body, Request, Response};

/// What the seal is filed under when `COSIGNER_GROUP_KEY` says nothing — see [`serve`].
const DEFAULT_GROUP_KEY: &str = "wallet";

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

    let cosigner = Arc::new(Mutex::new(open_cosigner(&cfg)?));
    let server_info = cosigner::wallet_proto::GetServerInfoResponse {
        bitcoin_network: cfg.bitcoin_network.clone(),
    };

    Ok(session::CosignerService::new(cosigner, server_info)
        .route(req)
        .await)
}

/// This instance's wallet, loaded from its seal.
///
/// Shared by the request path and the background task, which both need the whole wallet and get it
/// the same way: there is no instance kept between them to inherit.
fn open_cosigner(cfg: &config::ServerConfig) -> Result<Cosigner, Status> {
    // The only thing this instance opens: its own store, a directory on the filesystem the runtime
    // scoped to this client. No ASP connection, no push channel — the caller drives the Ark
    // protocol and the host wakes devices.
    let store = Arc::new(
        store::Store::open(&cfg.store_dir, cfg.auto_settle_safety_margin_secs)
            .map_err(|e| Status::internal(format!("opening the store: {e}")))?,
    );

    // Which wallet this instance serves. Configuration, not something a caller names per request —
    // but it no longer has to be *supplied*, and under a real runtime it cannot be.
    //
    // enclave-runtime scopes each tenant's filesystem before the guest sees it, so the store this
    // instance opened already belongs to exactly one wallet; there is nothing here to route
    // between and this string is only the key the seal is filed under. Requiring it also could not
    // work: the image's environment is all `S3FS_*`, which the runtime strips, so nothing reaches
    // the guest to set it and the instance refused to start at all.
    //
    // Safe to default because it is *not* the wallet's identity. DKG installs the real group key
    // into the policy inside the seal (`install_policy` writes `policy.group_key`, not this), so
    // the identity survives and a restart still finds its snapshot under the same bootstrap name.
    // The env var stays for a deployment that runs several wallets over one filesystem.
    let group_key =
        std::env::var("COSIGNER_GROUP_KEY").unwrap_or_else(|_| DEFAULT_GROUP_KEY.to_string());

    Cosigner::open_with_host(store, group_key, host())
}

/// The runtime, if we are running inside one.
///
/// `Detached` off the target is not a fallback so much as the truth: a host build has no task queue
/// and no push channel, and every call failing is what stops a missed deadline looking healthy.
#[cfg(target_arch = "wasm32")]
fn host() -> Arc<dyn cosigner::host::Host> {
    Arc::new(runtime::Runtime)
}

#[cfg(not(target_arch = "wasm32"))]
fn host() -> Arc<dyn cosigner::host::Host> {
    Arc::new(cosigner::host::Detached)
}

/// The runtime's two capabilities, and the task it calls back into.
///
/// Only on the component target: `wit_bindgen::generate!` emits component-model imports that a
/// native build has nothing to link against. `host.rs` describes the same two interfaces as a
/// trait so everything above this can be written and tested on the host; this is the one `impl`
/// that was always going to be the point of that.
#[cfg(target_arch = "wasm32")]
mod runtime {
    use std::sync::Arc;

    use cosigner::host::Host;

    mod bindings {
        wit_bindgen::generate!({ path: "wit", world: "cosigner", generate_all });
    }

    use bindings::enclave::notify::notify;
    use bindings::enclave::tasks::queue;

    /// Each method is the WIT function with the same name. Nothing is adapted, which is what the
    /// trait was shaped for.
    pub struct Runtime;

    impl Host for Runtime {
        fn enqueue(
            &self,
            id: &str,
            payload: &[u8],
            run_at_ms: u64,
            interval_ms: Option<u64>,
        ) -> Result<(), String> {
            queue::enqueue(id, payload, run_at_ms, interval_ms)
        }
        fn status(&self, id: &str) -> Result<String, String> {
            queue::status(id)
        }
        fn cancel(&self, id: &str) -> Result<(), String> {
            queue::cancel(id)
        }
        fn forget(&self, id: &str) -> Result<(), String> {
            queue::forget(id)
        }
        fn register_device(&self, token: &str) -> Result<(), String> {
            notify::register_device(token)
        }
        fn forget_device(&self, token: &str) -> Result<(), String> {
            notify::forget_device(token)
        }
        fn devices(&self) -> Result<u32, String> {
            notify::devices()
        }
        fn wake(&self, category: &str, reference: Option<&str>) -> Result<(), String> {
            notify::wake(category, reference)
        }
    }

    /// `run-task`, the other half of `enclave:tasks/background`.
    ///
    /// The runtime calls this on its own schedule with no request in flight, so it opens the wallet
    /// itself rather than sharing one — there is no instance kept between a request and a task to
    /// share. When the sealed delegate has come due it runs it against the ASP the image names —
    /// see `handlers/watch.rs` — and wakes the owner only when it cannot.
    struct Background;

    impl bindings::Guest for Background {
        fn run_task(task_id: String, payload: Vec<u8>) -> Result<Vec<u8>, String> {
            // The runtime records a failed run's error inside the sealed task record, where nobody
            // reads it; stderr reaches the console. Said here too, so a watch that keeps failing
            // says why.
            let run = || {
                let cfg = cosigner::config::ServerConfig::from_environment();
                let mut wallet = super::open_cosigner(&cfg).map_err(|e| e.to_string())?;
                // The ASP, when the image names one — a due delegate is then run here, not handed
                // back to a phone.
                let mut asp = cosigner::asp::rest::AspRest::from_env();
                wstd::runtime::block_on(wallet.run_task_with(&task_id, &payload, asp.as_mut()))
            };
            run().inspect_err(|e| eprintln!("background task {task_id} failed: {e}"))
        }
    }

    bindings::export!(Background with_types_in bindings);

    /// Silences the unused warning for a type whose only purpose is to be exported.
    #[allow(dead_code)]
    fn _keep(_: Arc<dyn Host>) {}
}
