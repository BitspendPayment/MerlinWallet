//! The deterministic mock payment provider, as a server.
//!
//! ```text
//!   cargo run --bin mock-provider -- --port 7100
//! ```
//!
//! **Nothing here moves money.** Every record it serves carries `"simulated": true` and every reply
//! carries an `x-simulated-payments: true` header. See `card_escrow::provider`.

use std::sync::Arc;

use card_escrow::provider::{router, MockProvider};
use clap::Parser;

#[derive(Parser)]
#[command(about = "A deterministic mock of a card processor's read API. Simulated payments only.")]
struct Args {
    #[arg(long, default_value_t = 7100)]
    port: u16,
    /// Bind address. All interfaces by default: the enclave reaches this from its own network.
    #[arg(long, default_value = "0.0.0.0")]
    bind: String,
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "info".into()),
        )
        .init();

    let args = Args::parse();
    let provider = MockProvider::new();
    let listener = tokio::net::TcpListener::bind((args.bind.as_str(), args.port)).await?;
    tracing::info!(
        addr = %listener.local_addr()?,
        "mock provider up — SIMULATED PAYMENTS ONLY, nothing here moves money"
    );
    axum::serve(listener, router(Arc::clone(&provider))).await?;
    Ok(())
}
