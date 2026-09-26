//! [`AspApi`] over arkd's REST gateway, through the guest's `wasi:http`.

use std::time::Duration;

use http_body_util::BodyExt;
use serde_json::{json, Value};
use wstd::http::{Body, Client, Method, Request};

use super::{json, sse::SseFramer, AspApi, EventSource};
use ark::client::proto::get_event_stream_response::Event;
use ark::client::types::ArkInfo;

pub struct AspRest {
    base: String,
}

impl AspRest {
    /// From `ASP_URL`, e.g. `http://192.168.127.254:7070`. `None` when unset: the image does not let
    /// this guest reach an ASP, and a delegate falls back to waking the owner.
    pub fn from_env() -> Option<Self> {
        let base = std::env::var("ASP_URL").ok()?;
        let base = base.trim().trim_end_matches('/').to_string();
        (!base.is_empty()).then_some(AspRest { base })
    }

    fn client(streaming: bool) -> Client {
        let mut c = Client::new();
        c.set_connect_timeout(Duration::from_secs(10));
        c.set_first_byte_timeout(Duration::from_secs(30));
        // The event stream is quiet between rounds apart from heartbeats; a request is not.
        c.set_between_bytes_timeout(Duration::from_secs(if streaming { 120 } else { 30 }));
        c
    }

    async fn call(&self, method: Method, path: &str, body: Option<Value>) -> Result<String, String> {
        let request = Request::builder()
            .method(method)
            .uri(format!("{}{path}", self.base))
            .header("accept", "application/json");
        let request = match body {
            Some(b) => request
                .header("content-type", "application/json")
                .body(Body::from(b.to_string())),
            None => request.body(Body::empty()),
        }
        .map_err(|e| format!("building {path}: {e}"))?;
        let mut response = Self::client(false)
            .send(request)
            .await
            .map_err(|e| format!("{path}: {e}"))?;
        let status = response.status();
        let text = response
            .body_mut()
            .str_contents()
            .await
            .map_err(|e| format!("{path}: reading the answer: {e}"))?
            .to_string();
        if !status.is_success() {
            return Err(format!("{path}: {status}: {text}"));
        }
        Ok(text)
    }
}

impl AspApi for AspRest {
    type Events = RestEvents;

    async fn get_info(&mut self) -> Result<ArkInfo, String> {
        json::ark_info(&self.call(Method::GET, "/v1/info", None).await?)
    }

    async fn register_intent(&mut self, proof: &str, message: &str) -> Result<String, String> {
        let text = self
            .call(
                Method::POST,
                "/v1/batch/registerIntent",
                Some(json!({ "intent": { "proof": proof, "message": message } })),
            )
            .await?;
        let v: Value = serde_json::from_str(&text).map_err(|e| format!("registerIntent: {e}"))?;
        v.get("intentId")
            .and_then(Value::as_str)
            .map(str::to_string)
            .ok_or_else(|| format!("registerIntent answered without an intentId: {text}"))
    }

    async fn events(&mut self, topics: &[String]) -> Result<RestEvents, String> {
        let query: Vec<String> = topics
            .iter()
            .map(|t| format!("topics={}", percent(t)))
            .collect();
        let uri = format!("{}/v1/batch/events?{}", self.base, query.join("&"));
        let request = Request::builder()
            .method(Method::GET)
            .uri(uri)
            .header("accept", "text/event-stream")
            .body(Body::empty())
            .map_err(|e| format!("building the event stream request: {e}"))?;
        let response = Self::client(true)
            .send(request)
            .await
            .map_err(|e| format!("opening the event stream: {e}"))?;
        if !response.status().is_success() {
            return Err(format!("the event stream answered {}", response.status()));
        }
        Ok(RestEvents {
            body: response.into_body().into_boxed_body(),
            framer: SseFramer::default(),
        })
    }

    async fn confirm_registration(&mut self, intent_id: &str) -> Result<(), String> {
        self.call(Method::POST, "/v1/batch/ack", Some(json!({ "intentId": intent_id })))
            .await
            .map(drop)
    }

    async fn submit_tree_nonces(
        &mut self,
        batch_id: &str,
        pubkey: &str,
        nonces: &[(String, String)],
    ) -> Result<(), String> {
        let nonces: serde_json::Map<String, Value> =
            nonces.iter().map(|(k, v)| (k.clone(), Value::String(v.clone()))).collect();
        self.call(
            Method::POST,
            "/v1/batch/tree/submitNonces",
            Some(json!({ "batchId": batch_id, "pubkey": pubkey, "treeNonces": nonces })),
        )
        .await
        .map(drop)
    }

    async fn submit_tree_signatures(
        &mut self,
        batch_id: &str,
        pubkey: &str,
        signatures: &[(String, String)],
    ) -> Result<(), String> {
        let signatures: serde_json::Map<String, Value> =
            signatures.iter().map(|(k, v)| (k.clone(), Value::String(v.clone()))).collect();
        self.call(
            Method::POST,
            "/v1/batch/tree/submitSignatures",
            Some(json!({ "batchId": batch_id, "pubkey": pubkey, "treeSignatures": signatures })),
        )
        .await
        .map(drop)
    }

    async fn submit_forfeits(
        &mut self,
        signed_forfeit_txs: &[String],
        signed_commitment_tx: &str,
    ) -> Result<(), String> {
        self.call(
            Method::POST,
            "/v1/batch/submitForfeitTxs",
            Some(json!({
                "signedForfeitTxs": signed_forfeit_txs,
                "signedCommitmentTx": signed_commitment_tx,
            })),
        )
        .await
        .map(drop)
    }
}

pub struct RestEvents {
    body: http_body_util::combinators::UnsyncBoxBody<bytes::Bytes, wstd::http::Error>,
    framer: SseFramer,
}

impl EventSource for RestEvents {
    async fn next(&mut self) -> Result<Option<Event>, String> {
        loop {
            while let Some(payload) = self.framer.next() {
                if let Some(event) = json::event(&payload)? {
                    return Ok(Some(event));
                }
            }
            match self.body.frame().await {
                None => return Ok(None),
                Some(Err(e)) => return Err(format!("the event stream broke: {e}")),
                Some(Ok(frame)) => {
                    if let Ok(data) = frame.into_data() {
                        self.framer.push(&data);
                    }
                }
            }
        }
    }
}

/// Percent-encode a query value. Topics are hex outpoints and pubkeys, but encoding costs nothing.
fn percent(s: &str) -> String {
    s.bytes()
        .map(|b| match b {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => (b as char).to_string(),
            _ => format!("%{b:02X}"),
        })
        .collect()
}
