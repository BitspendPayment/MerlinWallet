//! The card programme's settlement service.
//!
//! ```text
//!   cargo run --bin card-service -- \
//!       --port 7099 --asp http://127.0.0.1:7070 \
//!       --provider http://127.0.0.1:7100 \
//!       --payout-xonly <32-byte hex> \
//!       --store ./service-state.json
//! ```
//!
//! Two faces, and the split is the whole design:
//!
//! - **Enclave-facing** — `/escrow/stream` and `/escrow/send`, the connection the runtime holds.
//!   This is where the cosigner's half of the escrow share arrives, and where reimbursement is
//!   asked for. See `card_escrow::service::wire`.
//! - **Operator-facing** — `/card/...` and `/reimburse`, which the walkthrough drives. This is
//!   where the card lifecycle is simulated, using credentials the cosigner never has.
//!
//! A cosigner that could reach the second face could manufacture the evidence it then verifies.
//! It cannot: it has one read-only credential, bound to the provider's origin.

use std::sync::Arc;

use axum::extract::{Path, State};
use axum::http::StatusCode;
use axum::response::IntoResponse;
use axum::routing::{get, post};
use axum::{Json, Router};
use card_escrow::policy::Terms;
use card_escrow::service::reimburse::{self, Asked};
use card_escrow::service::wire::{router as wire_router, Connections, Wire};
use card_escrow::service::{Reimbursement, Service, Stage};
use clap::Parser;
use serde::Deserialize;

#[derive(Parser)]
#[command(about = "A card programme's settlement service, reimbursed from a Bitcoin escrow.")]
struct Args {
    #[arg(long, default_value_t = 7099)]
    port: u16,
    #[arg(long, default_value = "0.0.0.0")]
    bind: String,
    /// The ASP, for reading what an escrow holds and submitting what was approved.
    #[arg(long, env = "ASP_URL", default_value = "http://127.0.0.1:7070")]
    asp: String,
    /// The payment provider, from THIS service's side — what this process dials to simulate
    /// payments.
    #[arg(long, env = "PROVIDER_URL", default_value = "http://127.0.0.1:7100")]
    provider: String,
    /// The same provider, as the ENCLAVE reaches it.
    ///
    /// Usually identical, and in the dev stack it is not: `192.168.127.254` is this host as the
    /// guest sees it, and nothing on the host routes there. The sealed policy must carry the name
    /// the cosigner will dial, because the credential is bound to that origin and a credential is
    /// not sent anywhere but to the provider it is for. Getting this wrong is refused rather than
    /// quietly sent to the wrong place — which is how it was found.
    #[arg(long, env = "PROVIDER_URL_FROM_ENCLAVE")]
    provider_from_enclave: Option<String>,
    /// This service's own key, x-only hex — where it is paid.
    #[arg(long, env = "SERVICE_PAYOUT_XONLY")]
    payout_xonly: String,
    /// The label the enclave's image knows this service by.
    #[arg(long, env = "SERVICE_LABEL", default_value = "merlin-e2e-escrow-service")]
    label: String,
    /// Where to keep what must survive a restart. Its signing share lives here.
    #[arg(long, env = "SERVICE_STORE")]
    store: Option<std::path::PathBuf>,
}

struct App {
    wire: Arc<Wire>,
    provider: String,
    http: reqwest::Client,
    terms: Terms,
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env().unwrap_or_else(|_| "info".into()),
        )
        .init();
    let args = Args::parse();

    // Where this service is paid. Derived from its own key, and told to the cosigner only as a
    // proposal — the policy decides whether it is an allowed destination.
    let mut asp = ark::client::AspClient::connect(&args.asp)
        .await
        .map_err(|e| anyhow::anyhow!("connecting to the ASP at {}: {e}", args.asp))?;
    let info = asp
        .get_info()
        .await
        .map_err(|e| anyhow::anyhow!("asking the ASP what it is: {e}"))?;
    let network =
        ark::client::parse_network(&info.network).map_err(|e| anyhow::anyhow!("{e}"))?;
    let payout = ark::client::ark_address(
        &args.payout_xonly,
        &info.signer_pubkey,
        info.unilateral_exit_delay as u32,
        network,
    )
    .map_err(|e| anyhow::anyhow!("deriving where this service is paid: {e}"))?;

    let provider_from_enclave = args
        .provider_from_enclave
        .clone()
        .unwrap_or_else(|| args.provider.clone());
    let terms = Terms::example(payout.clone(), provider_from_enclave.clone());
    let identifier = threshold::identifier::Identifier::derive(args.label.as_bytes())
        .map_err(|e| anyhow::anyhow!("{e}"))?;
    let service = Service::new(
        identifier.clone(),
        payout.clone(),
        args.asp.clone(),
        args.store.clone(),
    );
    service.restore().await?;

    let wire = Arc::new(Wire {
        service: Arc::clone(&service),
        connections: Arc::new(Connections::default()),
    });
    let app = Arc::new(App {
        wire: Arc::clone(&wire),
        provider: args.provider.clone(),
        http: reqwest::Client::new(),
        terms,
    });

    // Anything a previous run left unfinished, retried with fresh nonces. See `reimburse::resume`.
    for (request_id, outcome) in reimburse::resume(&wire).await {
        tracing::info!(%request_id, ?outcome, "picked up where a previous run left off");
    }
    // And then keep picking it up. A connection that drops is re-dialled by the runtime, but a
    // reimbursement whose answer was lost in the drop needs somebody to ask again — and this is the
    // only party that can. See `reimburse::keep_trying`.
    tokio::spawn(reimburse::keep_trying(Arc::clone(&wire)));

    let router = wire_router(Arc::clone(&service), Arc::clone(&wire.connections))
        .merge(control(Arc::clone(&app)));
    let listener = tokio::net::TcpListener::bind((args.bind.as_str(), args.port)).await?;
    tracing::info!(
        addr = %listener.local_addr()?,
        identifier = %hex::encode(identifier.serialize()),
        payout = %payout,
        provider = %args.provider,
        provider_from_enclave = %provider_from_enclave,
        "settlement service up — SIMULATED card payments, real Bitcoin escrow"
    );
    axum::serve(listener, router).await?;
    Ok(())
}

/// The operator-facing half: driving the card lifecycle, and asking to be paid.
fn control(app: Arc<App>) -> Router {
    Router::new()
        .route("/escrow/active/{escrow_key}", post(escrow_active))
        .route("/card/authorize", post(authorize))
        .route("/card/clear/{request_id}", post(clear))
        .route("/card/reverse/{request_id}", post(reverse))
        .route("/reimburse/{request_id}", post(reimburse_one))
        .route("/connections", get(connections))
        .route("/connections/drop", post(drop_connections))
        .route("/policy", get(policy))
        .with_state(app)
}

/// The owner committed the escrow to a deal, so there is an allowance to draw on.
async fn escrow_active(
    State(app): State<Arc<App>>,
    Path(escrow_key): Path<String>,
) -> axum::response::Response {
    let held = app
        .wire
        .service
        .store
        .lock()
        .await
        .shares
        .contains_key(&escrow_key.to_ascii_lowercase());
    if !held {
        return bad("this service holds no share of that escrow, so it is not paired into it");
    }
    Json(serde_json::json!({ "escrow": escrow_key, "stage": Stage::EscrowActive.label() }))
        .into_response()
}

/// Which record to name as the payment. Absent means the clearing, which is the only sensible one.
#[derive(Deserialize)]
struct AskAgainst {
    against: Option<String>,
}

#[derive(Deserialize)]
struct Authorize {
    escrow_key: String,
    /// Minor units — cents. Integers, so nothing is lost on the way in.
    amount_minor: u64,
    #[serde(default = "usd")]
    currency: String,
}

fn usd() -> String {
    "USD".into()
}

/// Simulate a card being presented. A hold, not a payment — and nothing is asked for on it.
async fn authorize(
    State(app): State<Arc<App>>,
    Json(request): Json<Authorize>,
) -> axum::response::Response {
    let Some(sats) = app.terms.sats_for(request.amount_minor) else {
        return bad("that amount does not convert to a whole number of sats at the agreed rate");
    };
    let simulated: serde_json::Value = match app
        .http
        .post(format!("{}/simulate/authorization", app.provider))
        .json(&serde_json::json!({
            "amount": request.amount_minor as f64 / 100.0,
            "currency_code": request.currency,
            "card_token": app.terms.card_token,
            "user_token": "user_alice",
        }))
        .send()
        .await
    {
        Ok(r) => match r.json().await {
            Ok(v) => v,
            Err(e) => return bad(&format!("the provider's answer was not JSON: {e}")),
        },
        Err(e) => return bad(&format!("the provider would not simulate: {e}")),
    };
    let Some(token) = simulated["token"].as_str() else {
        return bad("the provider returned no token");
    };

    let request_id = app.wire.service.next_request_id().await;
    {
        let mut store = app.wire.service.store.lock().await;
        store.reimbursements.insert(
            request_id.clone(),
            Reimbursement {
                request_id: request_id.clone(),
                escrow_key: request.escrow_key,
                started_ref: token.to_string(),
                settled_ref: None,
                amount_minor: request.amount_minor,
                currency: request.currency,
                sats,
                stage: Stage::Started,
                last_refusal: None,
                needs_reconciliation: false,
                proposal: None,
                signatures: Vec::new(),
                expected_txid: None,
                ark_txid: None,
                given_up: false,
            },
        );
    }
    let _ = app.wire.service.persist().await;
    Json(serde_json::json!({
        "request_id": request_id,
        "authorization": token,
        "sats_when_cleared": sats,
        "stage": Stage::Started.label(),
        "simulated": true,
    }))
    .into_response()
}

/// Simulate the merchant submitting. A **new** record, linked to the authorization.
async fn clear(
    State(app): State<Arc<App>>,
    Path(request_id): Path<String>,
) -> axum::response::Response {
    let authorization = {
        let store = app.wire.service.store.lock().await;
        match store.reimbursements.get(&request_id) {
            Some(r) => r.started_ref.clone(),
            None => return bad("nothing is tracked under that id"),
        }
    };
    let simulated: serde_json::Value = match app
        .http
        .post(format!("{}/simulate/clearing", app.provider))
        .json(&serde_json::json!({ "authorization_token": authorization }))
        .send()
        .await
    {
        Ok(r) => match r.json().await {
            Ok(v) => v,
            Err(e) => return bad(&format!("the provider's answer was not JSON: {e}")),
        },
        Err(e) => return bad(&format!("the provider would not simulate: {e}")),
    };
    let Some(token) = simulated["token"].as_str() else {
        return bad(&format!("the provider refused to clear it: {simulated}"));
    };
    {
        let mut store = app.wire.service.store.lock().await;
        if let Some(r) = store.reimbursements.get_mut(&request_id) {
            r.settled_ref = Some(token.to_string());
            if r.stage < Stage::Settled {
                r.stage = Stage::Settled;
            }
        }
    }
    let _ = app.wire.service.persist().await;
    Json(serde_json::json!({
        "request_id": request_id,
        "authorization": authorization,
        "clearing": token,
        "stage": Stage::Settled.label(),
        "simulated": true,
    }))
    .into_response()
}

/// Simulate the hold being given back. Nothing is owed on a reversal.
async fn reverse(
    State(app): State<Arc<App>>,
    Path(request_id): Path<String>,
) -> axum::response::Response {
    let authorization = {
        let store = app.wire.service.store.lock().await;
        match store.reimbursements.get(&request_id) {
            Some(r) => r.started_ref.clone(),
            None => return bad("nothing is tracked under that id"),
        }
    };
    match app
        .http
        .post(format!("{}/simulate/reversal/{authorization}", app.provider))
        .send()
        .await
    {
        Ok(_) => Json(serde_json::json!({ "reversed": authorization, "simulated": true }))
            .into_response(),
        Err(e) => bad(&format!("the provider would not simulate: {e}")),
    }
}

/// Ask the cosigner to reimburse one purchase.
///
/// `?against=authorization` asks about the HOLD instead of the clearing — which a settlement
/// service would never do, and which the walkthrough does on purpose so the cosigner's refusal can
/// be seen rather than taken on trust.
async fn reimburse_one(
    State(app): State<Arc<App>>,
    Path(request_id): Path<String>,
    axum::extract::Query(query): axum::extract::Query<AskAgainst>,
) -> axum::response::Response {
    let forced = match query.against.as_deref() {
        Some("authorization") => {
            let store = app.wire.service.store.lock().await;
            match store.reimbursements.get(&request_id) {
                Some(r) => Some(r.started_ref.clone()),
                None => return bad("nothing is tracked under that id"),
            }
        }
        Some(other) => return bad(&format!("there is nothing called {other:?} to ask against")),
        None => None,
    };
    match reimburse::ask_against(&app.wire, &request_id, forced.as_deref()).await {
        Asked::Confirmed { ark_txid, sats } => Json(serde_json::json!({
            "outcome": "confirmed",
            "ark_txid": ark_txid,
            "sats": sats,
            "stage": Stage::ReleaseConfirmed.label(),
        }))
        .into_response(),
        Asked::Refused { reason } => Json(serde_json::json!({
            "outcome": "refused",
            "reason": reason,
        }))
        .into_response(),
        Asked::Failed { reason } => (
            StatusCode::SERVICE_UNAVAILABLE,
            Json(serde_json::json!({ "outcome": "failed", "reason": reason })),
        )
            .into_response(),
        Asked::NeedsReconciliation => Json(serde_json::json!({
            "outcome": "needs-reconciliation",
            "reason": "the release probably landed and its reply was lost; reconcile against the \
                       chain",
        }))
        .into_response(),
    }
}

/// The policy this service expects to be judged against.
///
/// Served rather than restated in the walkthrough, so the demo and the code cannot drift: Alice
/// seals exactly this, and the cosigner enforces exactly this. The service does not get to change
/// it afterwards — once sealed it is the owner's, not the service's.
async fn policy(State(app): State<Arc<App>>) -> axum::response::Response {
    let script = match ark::client::ark_address_script_pubkey_hex(&app.terms.service_ark_address) {
        Ok(s) => s,
        Err(e) => return bad(&format!("this service's own address is unusable: {e}")),
    };
    let one_purchase = app.terms.sats_for(2_000).unwrap_or(0);
    Json(card_escrow::policy::policy(&app.terms, &script, one_purchase)).into_response()
}

/// Which connections the enclave's runtime is holding — one per wallet, all under the same local
/// name. See `card_escrow::service::wire`.
async fn connections(State(app): State<Arc<App>>) -> axum::response::Response {
    Json(serde_json::json!({ "held": app.wire.connections.held_ids() })).into_response()
}

/// Drop every held connection, so recovery can be shown rather than asserted.
///
/// The runtime re-dials on its own. What this demonstrates is that a reimbursement caught by the
/// drop is not lost with it: the retry loop asks again once the connection is back.
async fn drop_connections(State(app): State<Arc<App>>) -> axum::response::Response {
    let dropped = app.wire.connections.drop_all();
    tracing::info!(dropped, "dropped every held connection; the runtime will re-dial");
    Json(serde_json::json!({ "dropped": dropped })).into_response()
}

fn bad(why: &str) -> axum::response::Response {
    (
        StatusCode::BAD_REQUEST,
        Json(serde_json::json!({ "error": why })),
    )
        .into_response()
}
