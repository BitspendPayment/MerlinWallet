//! The payment provider the cosigner asks — a deterministic mock, and a real adapter beside it.
//!
//! # These are NOT Marqeta's fields
//!
//! Everything the mock serves is invented for this example and named to be obviously so. It is
//! shaped *like* a card processor's transaction record — a token, a type, a state, an amount, a
//! card — because that is the shape a policy has to be able to reason about, but no field here
//! should be read as a claim about Marqeta's API. The real adapter ([`marqeta`]) is where actual
//! field names belong, and it is written against the published documentation with its unknowns
//! marked as unknowns.
//!
//! Every mock response carries `"simulated": true` and every mock reply carries an
//! `x-simulated-payments: true` header. Nothing here ever moved money.
//!
//! # An authorization and a clearing are two records, not one
//!
//! A card payment is not one object whose flag flips. The card is presented and an *authorization*
//! is created — a hold, which may expire, be reversed, or clear for a different amount. Later, the
//! merchant submits and a *clearing* is created, a separate record that points back at the
//! authorization it settles.
//!
//! That distinction is the whole reason this example exists, because it is what a settlement
//! service must not paper over: money owed is owed on the clearing, and an escrow released against
//! an authorization is an escrow released against something that may never complete.
//!
//! ```text
//!   POST /simulate/authorization     ──▶  txn_auth_0001   type=authorization        state=PENDING
//!   POST /simulate/clearing          ──▶  txn_clr_0001    type=authorization.clearing
//!                                          │                                        state=COMPLETION
//!                                          └── preceding_transaction_token = txn_auth_0001
//!   GET  /transactions/{token}       ──▶  whichever record that is, or 404
//! ```
//!
//! # The mock's schema, in full
//!
//! ```json
//! {
//!   "token": "txn_clr_0001",                    // this record's identity
//!   "type": "authorization" | "authorization.clearing" | "authorization.reversal",
//!   "state": "PENDING" | "COMPLETION" | "DECLINED" | "REVERSED",
//!   "amount": 20.00,                            // a decimal, in `currency_code`
//!   "currency_code": "USD",
//!   "card_token": "card_alice_0001",            // which card was presented
//!   "user_token": "user_alice",                 // whose card it is
//!   "merchant_name": "Example Coffee",
//!   "preceding_transaction_token": "txn_auth_0001",  // clearings and reversals only
//!   "created_time": "2026-09-20T12:00:00Z",
//!   "simulated": true                           // ALWAYS true here
//! }
//! ```
//!
//! # What a policy asks of it
//!
//! Six things, and the policy in [`crate::policy`] requires all of them together:
//!
//! | asked | field | why |
//! |---|---|---|
//! | payment identity | `token` | that this evidence is about *this* release |
//! | card / account | `card_token` | that it was the escrow owner's card |
//! | purchase type | `type` | a clearing, not an authorization that may vanish |
//! | clearing state | `state` | that it completed rather than declined |
//! | currency | `currency_code` | that "20" is dollars |
//! | amount | `amount` | converted at the sealed rate, exactly what is being released |

use std::collections::BTreeMap;
use std::sync::{Arc, Mutex};

use axum::extract::{Path, State};
use axum::http::StatusCode;
use axum::response::IntoResponse;
use axum::routing::{get, post};
use axum::{Json, Router};
use serde::{Deserialize, Serialize};

pub mod marqeta;

/// What kind of record this is.
///
/// Spelled as the mock serves them. A real processor's vocabulary is larger and is the adapter's
/// business, not this module's.
pub mod kind {
    /// The hold taken when the card was presented. Not a payment yet.
    pub const AUTHORIZATION: &str = "authorization";
    /// The settlement of an authorization. This is what money is owed on.
    pub const CLEARING: &str = "authorization.clearing";
    /// An authorization given back. Nothing is owed.
    pub const REVERSAL: &str = "authorization.reversal";
}

/// Where a record has got to.
pub mod state {
    /// Authorized and waiting. May still clear, expire or be reversed.
    pub const PENDING: &str = "PENDING";
    /// Cleared. The one state money may be released against.
    pub const COMPLETION: &str = "COMPLETION";
    pub const DECLINED: &str = "DECLINED";
    pub const REVERSED: &str = "REVERSED";
}

/// One record as the mock serves it. See the module note: these are not Marqeta's field names.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MockTransaction {
    pub token: String,
    #[serde(rename = "type")]
    pub kind: String,
    pub state: String,
    /// A decimal amount, serialized as a JSON number the way a processor would.
    pub amount: f64,
    pub currency_code: String,
    pub card_token: String,
    pub user_token: String,
    pub merchant_name: String,
    /// The authorization a clearing or reversal settles. Absent on an authorization itself.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub preceding_transaction_token: Option<String>,
    pub created_time: String,
    /// Always true. Nothing here moved money.
    pub simulated: bool,
}

/// What a caller asks the mock to pretend happened.
#[derive(Debug, Clone, Deserialize)]
pub struct SimulateAuthorization {
    pub amount: f64,
    #[serde(default = "usd")]
    pub currency_code: String,
    pub card_token: String,
    pub user_token: String,
    #[serde(default = "merchant")]
    pub merchant_name: String,
    /// Authorize and immediately decline, for showing what a refusal looks like.
    #[serde(default)]
    pub decline: bool,
}

#[derive(Debug, Clone, Deserialize)]
pub struct SimulateClearing {
    /// The authorization being settled.
    pub authorization_token: String,
    /// What actually cleared, if it differs from what was authorized — which is the normal case for
    /// a tip, a fuel pump, or a hotel. `None` clears the authorized amount.
    #[serde(default)]
    pub amount: Option<f64>,
}

fn usd() -> String {
    "USD".into()
}
fn merchant() -> String {
    "Example Coffee".into()
}

/// The mock's world: every record it has been told to pretend happened.
///
/// Deterministic by construction — tokens are issued in order from a counter, and the clock is a
/// counter too, so two runs of the same script produce the same records byte for byte. A demo that
/// cannot be diffed against itself is a demo that cannot be trusted to show a regression.
#[derive(Default)]
pub struct MockProvider {
    inner: Mutex<Inner>,
}

#[derive(Default)]
struct Inner {
    transactions: BTreeMap<String, MockTransaction>,
    issued: u32,
    /// Seconds since a fixed epoch, so `created_time` is reproducible.
    clock: u64,
    /// Tokens the provider will pretend not to know about yet, however many times it is asked.
    withheld: Vec<String>,
}

/// A fixed starting point, so the demo's timestamps are the same on every run.
const EPOCH: &str = "2026-01-01T00:00:00Z";

impl MockProvider {
    pub fn new() -> Arc<Self> {
        Arc::new(Self::default())
    }

    /// Pretend a card was presented. Returns the authorization record.
    pub fn authorize(&self, request: SimulateAuthorization) -> MockTransaction {
        let mut inner = self.inner.lock().unwrap();
        inner.issued += 1;
        inner.clock += 60;
        let token = format!("txn_auth_{:04}", inner.issued);
        let record = MockTransaction {
            token: token.clone(),
            kind: kind::AUTHORIZATION.into(),
            state: if request.decline {
                state::DECLINED.into()
            } else {
                state::PENDING.into()
            },
            amount: request.amount,
            currency_code: request.currency_code,
            card_token: request.card_token,
            user_token: request.user_token,
            merchant_name: request.merchant_name,
            preceding_transaction_token: None,
            created_time: at(inner.clock),
            simulated: true,
        };
        inner.transactions.insert(token, record.clone());
        record
    }

    /// Pretend the merchant submitted, and the authorization settled.
    ///
    /// A **new record**, linked to the authorization rather than replacing it. Both remain
    /// readable afterwards, which is what lets the example show that asking about the
    /// authorization still says "authorization, pending" once the clearing exists.
    pub fn clear(&self, request: SimulateClearing) -> Result<MockTransaction, String> {
        let mut inner = self.inner.lock().unwrap();
        let authorization = inner
            .transactions
            .get(&request.authorization_token)
            .cloned()
            .ok_or_else(|| format!("no authorization {}", request.authorization_token))?;
        if authorization.kind != kind::AUTHORIZATION {
            return Err(format!(
                "{} is a {}, and only an authorization clears",
                authorization.token, authorization.kind
            ));
        }
        if authorization.state == state::DECLINED {
            return Err(format!("{} was declined and cannot clear", authorization.token));
        }
        if inner.transactions.values().any(|t| {
            t.kind == kind::CLEARING
                && t.preceding_transaction_token.as_deref() == Some(&authorization.token)
        }) {
            return Err(format!("{} has already cleared", authorization.token));
        }
        inner.issued += 1;
        inner.clock += 3_600;
        let token = format!("txn_clr_{:04}", inner.issued);
        let record = MockTransaction {
            token: token.clone(),
            kind: kind::CLEARING.into(),
            state: state::COMPLETION.into(),
            amount: request.amount.unwrap_or(authorization.amount),
            preceding_transaction_token: Some(authorization.token.clone()),
            created_time: at(inner.clock),
            ..authorization
        };
        inner.transactions.insert(token, record.clone());
        Ok(record)
    }

    /// Pretend the hold was given back. Nothing is owed on a reversal.
    pub fn reverse(&self, authorization_token: &str) -> Result<MockTransaction, String> {
        let mut inner = self.inner.lock().unwrap();
        let authorization = inner
            .transactions
            .get(authorization_token)
            .cloned()
            .ok_or_else(|| format!("no authorization {authorization_token}"))?;
        inner.issued += 1;
        inner.clock += 120;
        let token = format!("txn_rev_{:04}", inner.issued);
        let record = MockTransaction {
            token: token.clone(),
            kind: kind::REVERSAL.into(),
            state: state::REVERSED.into(),
            preceding_transaction_token: Some(authorization.token.clone()),
            created_time: at(inner.clock),
            ..authorization
        };
        inner.transactions.insert(token, record.clone());
        Ok(record)
    }

    /// What the cosigner's GET sees. `None` is a 404 — which is what "not available yet" looks
    /// like from outside, and is exactly the case a policy's `on_unavailable` has to answer.
    pub fn transaction(&self, token: &str) -> Option<MockTransaction> {
        let inner = self.inner.lock().unwrap();
        if inner.withheld.iter().any(|t| t == token) {
            return None;
        }
        inner.transactions.get(token).cloned()
    }

    /// Pretend a record has not reached the read API yet, although it exists.
    ///
    /// Real processors have this gap: a transaction is authoritative before it is queryable. A
    /// verifier that treated "not found" as "did not happen" would refuse valid releases, and one
    /// that treated it as "happened" would release against nothing.
    pub fn withhold(&self, token: &str) {
        self.inner.lock().unwrap().withheld.push(token.to_string());
    }

    pub fn publish(&self, token: &str) {
        self.inner.lock().unwrap().withheld.retain(|t| t != token);
    }

    /// Everything, oldest token first — for a walkthrough that wants to show the ledger.
    pub fn all(&self) -> Vec<MockTransaction> {
        self.inner.lock().unwrap().transactions.values().cloned().collect()
    }
}

/// A reproducible timestamp: the fixed epoch plus `seconds`.
fn at(seconds: u64) -> String {
    // Deliberately arithmetic on a fixed string rather than a real clock — the demo must produce
    // the same bytes twice.
    let days = seconds / 86_400;
    let rest = seconds % 86_400;
    format!(
        "2026-01-{:02}T{:02}:{:02}:{:02}Z",
        1 + days,
        rest / 3_600,
        (rest % 3_600) / 60,
        rest % 60
    )
    .replace("2026-01-00", EPOCH)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn provider() -> Arc<MockProvider> {
        MockProvider::new()
    }

    fn twenty_dollars() -> SimulateAuthorization {
        SimulateAuthorization {
            amount: 20.00,
            currency_code: "USD".into(),
            card_token: "card_alice_0001".into(),
            user_token: "user_alice".into(),
            merchant_name: "Example Coffee".into(),
            decline: false,
        }
    }

    /// The distinction the whole example rests on: two records, linked, both readable.
    #[test]
    fn an_authorization_and_its_clearing_are_separate_linked_records() {
        let p = provider();
        let auth = p.authorize(twenty_dollars());
        assert_eq!(auth.kind, kind::AUTHORIZATION);
        assert_eq!(auth.state, state::PENDING);
        assert!(auth.preceding_transaction_token.is_none());

        let cleared = p
            .clear(SimulateClearing {
                authorization_token: auth.token.clone(),
                amount: None,
            })
            .expect("it clears");
        assert_ne!(cleared.token, auth.token, "a clearing is its own record");
        assert_eq!(cleared.kind, kind::CLEARING);
        assert_eq!(cleared.state, state::COMPLETION);
        assert_eq!(
            cleared.preceding_transaction_token.as_deref(),
            Some(auth.token.as_str()),
            "and it points back at what it settles"
        );

        // The authorization is untouched. Nothing flipped a flag.
        let still = p.transaction(&auth.token).expect("still there");
        assert_eq!(still.kind, kind::AUTHORIZATION);
        assert_eq!(still.state, state::PENDING);
    }

    /// A clearing may settle for more or less than was held — a tip, a fuel pump, a hotel.
    #[test]
    fn a_clearing_may_differ_from_what_was_authorized() {
        let p = provider();
        let auth = p.authorize(twenty_dollars());
        let cleared = p
            .clear(SimulateClearing {
                authorization_token: auth.token,
                amount: Some(23.50),
            })
            .unwrap();
        assert_eq!(cleared.amount, 23.50);
    }

    #[test]
    fn an_authorization_clears_once_and_a_declined_one_never_does() {
        let p = provider();
        let auth = p.authorize(twenty_dollars());
        let once = SimulateClearing {
            authorization_token: auth.token.clone(),
            amount: None,
        };
        p.clear(once.clone()).unwrap();
        assert!(p.clear(once).unwrap_err().contains("already cleared"));

        let declined = p.authorize(SimulateAuthorization {
            decline: true,
            ..twenty_dollars()
        });
        let err = p
            .clear(SimulateClearing {
                authorization_token: declined.token,
                amount: None,
            })
            .unwrap_err();
        assert!(err.contains("declined"), "{err}");
    }

    /// A record that exists but has not reached the read API is a 404, and must stay one.
    #[test]
    fn a_withheld_record_reads_as_not_there_until_it_is_published() {
        let p = provider();
        let auth = p.authorize(twenty_dollars());
        let cleared = p
            .clear(SimulateClearing {
                authorization_token: auth.token,
                amount: None,
            })
            .unwrap();

        p.withhold(&cleared.token);
        assert!(p.transaction(&cleared.token).is_none());
        p.publish(&cleared.token);
        assert!(p.transaction(&cleared.token).is_some());
    }

    /// Two runs of the same script produce the same records, or the demo cannot be diffed.
    #[test]
    fn the_mock_is_deterministic() {
        let script = || {
            let p = provider();
            let auth = p.authorize(twenty_dollars());
            p.clear(SimulateClearing {
                authorization_token: auth.token,
                amount: None,
            })
            .unwrap();
            serde_json::to_string(&p.all()).unwrap()
        };
        assert_eq!(script(), script());
    }

    /// Everything it serves says so.
    #[test]
    fn every_record_is_labelled_simulated() {
        let p = provider();
        let auth = p.authorize(twenty_dollars());
        p.clear(SimulateClearing {
            authorization_token: auth.token,
            amount: None,
        })
        .unwrap();
        assert!(p.all().iter().all(|t| t.simulated));
        let json = serde_json::to_value(&p.all()[0]).unwrap();
        assert_eq!(json["simulated"], true);
    }
}


// ===============================================================================================
// Serving it
//
// Two halves, and the split is the point. `/transactions/{token}` is what the COSIGNER reads, with
// a read-only credential. `/simulate/...` is what the test driver writes, and the cosigner has no
// credential for it and no reason to call it. A verifier that could manufacture its own evidence
// would not be verifying anything.
// ===============================================================================================

/// The header every mock reply carries, so nobody has to read the body to know what this is.
pub const SIMULATED_HEADER: &str = "x-simulated-payments";

pub fn router(provider: Arc<MockProvider>) -> Router {
    Router::new()
        .route("/transactions/{token}", get(read_transaction))
        .route("/simulate/authorization", post(simulate_authorization))
        .route("/simulate/clearing", post(simulate_clearing))
        .route("/simulate/reversal/{token}", post(simulate_reversal))
        .route("/simulate/withhold/{token}", post(withhold))
        .route("/simulate/publish/{token}", post(publish))
        .route("/simulate/ledger", get(ledger))
        .with_state(provider)
}

/// Everything served says it is simulated, in the body and in a header.
fn labelled<T: Serialize>(status: StatusCode, body: T) -> axum::response::Response {
    let mut response = (status, Json(body)).into_response();
    response
        .headers_mut()
        .insert(SIMULATED_HEADER, axum::http::HeaderValue::from_static("true"));
    response
}

/// What the cosigner GETs. The only route it is given a credential for.
async fn read_transaction(
    State(provider): State<Arc<MockProvider>>,
    Path(token): Path<String>,
) -> axum::response::Response {
    match provider.transaction(&token) {
        Some(record) => labelled(StatusCode::OK, record),
        // Not found, which is what delayed availability looks like from outside — and is exactly
        // the case a policy's `on_unavailable` has to answer for.
        None => labelled(
            StatusCode::NOT_FOUND,
            serde_json::json!({ "error": "no such transaction", "simulated": true }),
        ),
    }
}

async fn simulate_authorization(
    State(provider): State<Arc<MockProvider>>,
    Json(request): Json<SimulateAuthorization>,
) -> axum::response::Response {
    labelled(StatusCode::CREATED, provider.authorize(request))
}

async fn simulate_clearing(
    State(provider): State<Arc<MockProvider>>,
    Json(request): Json<SimulateClearing>,
) -> axum::response::Response {
    match provider.clear(request) {
        Ok(record) => labelled(StatusCode::CREATED, record),
        Err(why) => labelled(
            StatusCode::CONFLICT,
            serde_json::json!({ "error": why, "simulated": true }),
        ),
    }
}

async fn simulate_reversal(
    State(provider): State<Arc<MockProvider>>,
    Path(token): Path<String>,
) -> axum::response::Response {
    match provider.reverse(&token) {
        Ok(record) => labelled(StatusCode::CREATED, record),
        Err(why) => labelled(
            StatusCode::CONFLICT,
            serde_json::json!({ "error": why, "simulated": true }),
        ),
    }
}

/// Pretend a record has not reached the read API yet, although it exists.
async fn withhold(
    State(provider): State<Arc<MockProvider>>,
    Path(token): Path<String>,
) -> axum::response::Response {
    provider.withhold(&token);
    labelled(StatusCode::OK, serde_json::json!({ "withheld": token, "simulated": true }))
}

async fn publish(
    State(provider): State<Arc<MockProvider>>,
    Path(token): Path<String>,
) -> axum::response::Response {
    provider.publish(&token);
    labelled(StatusCode::OK, serde_json::json!({ "published": token, "simulated": true }))
}

/// Everything it has been told to pretend, for a walkthrough that wants to show its working.
async fn ledger(State(provider): State<Arc<MockProvider>>) -> axum::response::Response {
    labelled(StatusCode::OK, provider.all())
}
