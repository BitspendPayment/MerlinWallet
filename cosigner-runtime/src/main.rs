use std::sync::Arc;

use clap::Parser;

use cosigner_runtime::{config, fcm_client, kv_store, shared, telemetry};

#[derive(Parser)]
#[command(
    name = "server",
    about = "MPC Wallet Server with per-user WASM crypto isolation"
)]
struct Args {
    /// REST/JSON listen port (HTTP/1.1). Defaults to PORT env var or 7074.
    #[arg(long)]
    port: Option<u16>,
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let mut telemetry_guard = telemetry::init();

    let args = Args::parse();

    let cfg = config::ServerConfig::from_environment();
    tracing::info!("Config: network={}", cfg.bitcoin_network);

    // Refuse to boot with an empty `bitcoin_network`. The client uses this
    // string verbatim as the HRP source for rendering wallet addresses; an
    // empty value would silently fall through to a wrong-network default
    // on the client side. ServerConfig::from_environment already defaults
    // to "regtest" on a missing var, so this check only fires when the
    // operator explicitly set BITCOIN_NETWORK="" (a configuration mistake).
    const VALID_NETWORKS: [&str; 5] = ["mainnet", "testnet", "signet", "mutinynet", "regtest"];
    if !VALID_NETWORKS.contains(&cfg.bitcoin_network.as_str()) {
        return Err(format!(
            "Invalid BITCOIN_NETWORK={:?}; expected one of {:?}",
            cfg.bitcoin_network, VALID_NETWORKS
        )
        .into());
    }

    // Persistence: the single embedded SQLite KV backend, a file on the local data volume.
    tracing::info!("Persistence: SQLite KV backend at {}", cfg.sqlite_path);
    let persistence: Arc<dyn kv_store::KvStore> =
        Arc::new(kv_store::SqliteStore::open(&cfg.sqlite_path)?);

    // ASP connection — REQUIRED. The cosigner is an Ark wallet co-signer; it cannot serve without
    // an ASP, so a missing URL or a failed connect is a hard startup error, not a soft fallback.
    if cfg.asp_url.is_empty() {
        return Err("ASP_URL is required".into());
    }
    tracing::info!("Connecting to ASP at {}", cfg.asp_url);
    let asp_client = ark::client::AspClient::connect(&cfg.asp_url)
        .await
        .map_err(|e| format!("Failed to connect to ASP at {}: {e}", cfg.asp_url))?;
    tracing::info!("Connected to ASP");

    // FCM push client (optional; auto-settle still works without it).
    let fcm = if cfg.fcm_service_account_json.trim().is_empty() {
        tracing::warn!(
            "FCM_SERVICE_ACCOUNT_JSON not set; push notifications disabled — \
             auto-settle will only fire for users who open the app"
        );
        None
    } else {
        let base_url_override = if cfg.fcm_base_url.is_empty() {
            None
        } else {
            Some(cfg.fcm_base_url.clone())
        };
        match fcm_client::FcmClient::from_service_account_json(
            &cfg.fcm_service_account_json,
            base_url_override,
        ) {
            Ok(client) => {
                if !cfg.fcm_base_url.is_empty() {
                    tracing::warn!(
                        "FCM_BASE_URL override active: {} — push traffic NOT going to real Firebase",
                        cfg.fcm_base_url
                    );
                }
                tracing::info!("FCM client initialized");
                Some(Arc::new(client))
            }
            Err(e) => {
                tracing::error!("FCM init failed: {e}; push notifications disabled");
                None
            }
        }
    };

    let shared = Arc::new(shared::SharedServices::new(
        persistence,
        asp_client,
        fcm,
        cfg.auto_settle_safety_margin_secs,
    ));

    // One cosigner per process, named by COSIGNER_GROUP_KEY. Not optional: a cosigner serves one
    // wallet, and which wallet is configuration rather than something a caller names per request.
    // That is what removes a whole class of confusion the old `/u/{group_key}/...` routing had —
    // a caller naming one wallet while addressing another. There is no other wallet to address.
    let group_key = std::env::var("COSIGNER_GROUP_KEY")
        .map_err(|_| "COSIGNER_GROUP_KEY is required: a cosigner serves exactly one wallet")?;
    let grpc_port: u16 = args
        .port
        .or_else(|| std::env::var("GRPC_PORT").ok().and_then(|s| s.parse().ok()))
        .unwrap_or(7075);

    let wallet_state = std::sync::Arc::new(parking_lot::Mutex::new(
        cosigner_runtime::cosigner::state::CosignerState::new(group_key.clone()),
    ));
    let cosigner = std::sync::Arc::new(
        cosigner_runtime::cosigner::instance::Cosigner::open(shared.clone(), wallet_state).await?,
    );
    let server_info = cosigner_runtime::wallet_proto::GetServerInfoResponse {
        bitcoin_network: cfg.bitcoin_network.clone(),
    };

    let grpc_addr: std::net::SocketAddr = format!("0.0.0.0:{grpc_port}").parse()?;
    tracing::info!(%group_key, "cosigner listening on {grpc_addr} (gRPC over HTTP/2)");

    let sessions =
        cosigner_runtime::session::proto::signing_session_server::SigningSessionServer::new(
            cosigner_runtime::session::SessionService::new(cosigner.clone()),
        );
    let wallet = cosigner_runtime::wallet_proto::mpc_wallet_server::MpcWalletServer::new(
        cosigner_runtime::session::WalletService::new(cosigner, server_info),
    );
    let serve_result = tonic::transport::Server::builder()
        .add_service(sessions)
        .add_service(wallet)
        .serve_with_shutdown(grpc_addr, shutdown_signal())
        .await;

    telemetry_guard.shutdown();
    serve_result?;
    Ok(())
}

/// Stop serving on SIGTERM or Ctrl-C, so in-flight sessions finish rather than being cut.
async fn shutdown_signal() {
    let ctrl_c = async { tokio::signal::ctrl_c().await.ok(); };
    #[cfg(unix)]
    let term = async {
        if let Ok(mut s) = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())
        {
            s.recv().await;
        }
    };
    #[cfg(not(unix))]
    let term = std::future::pending::<()>();
    tokio::select! {
        _ = ctrl_c => {}
        _ = term => {}
    }
}
