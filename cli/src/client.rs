//! Thin REST client for the cosigner, mirroring what the Flutter app does.
//!
//! Every authenticated call carries `user_id` / `signature` / `timestamp_ms`, where the signature
//! is BIP-340 over `sha256("MPC_WALLET_AUTH_V1:<op>:<ts>:<user_id_hex>")` — the same canonical
//! message `auth::message::build_auth_message` builds server-side.
//!
//! Note the routing rule: the `{group_key}` in the URL selects WHICH ACTOR handles the call, while
//! `user_id` in the body is WHO SIGNED. They're the same for your own wallet's calls, but differ
//! for `payment-request/create`, where you sign as yourself and address the payer's actor.

use std::time::{SystemTime, UNIX_EPOCH};

use anyhow::{anyhow, Result};
use serde_json::{json, Value};

use threshold::auth::AuthSigner;

pub struct Client {
    http: reqwest::Client,
    base: String,
}

pub fn now_ms() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_millis() as i64
}

/// The canonical auth message (SHA-256 of the pinned format string).
pub fn build_auth_message(operation: &str, timestamp_ms: i64, user_id_hex: &str) -> Vec<u8> {
    use sha2::{Digest, Sha256};
    let msg = format!("MPC_WALLET_AUTH_V1:{operation}:{timestamp_ms}:{user_id_hex}");
    Sha256::digest(msg.as_bytes()).to_vec()
}

impl Client {
    pub fn new(base: String) -> Self {
        Self {
            http: reqwest::Client::new(),
            base: base.trim_end_matches('/').to_string(),
        }
    }

    /// Unauthenticated POST (DKG, which runs before a key exists). Takes the FULL path — the
    /// runtime nests its router under `/api`; `post_signed` adds `/api/u/{group_key}` itself.
    pub async fn post(&self, path: &str, body: Value) -> Result<Value> {
        let url = format!("{}{}", self.base, path);
        let resp = self.http.post(&url).json(&body).send().await?;
        Self::read(resp, &url).await
    }

    /// MEMBER-signed POST (`sign/step1-2`, `contacts/*`, `payment-request/*`): a Schnorr signature
    /// and NO token — `verify_auth` short-circuits on a token, and a group-scoped one is rejected
    /// here as "session token does not match request user".
    pub async fn post_signed(
        &self,
        group_key: &str,
        path: &str,
        op: &str,
        signer: &AuthSigner,
        body: Value,
    ) -> Result<Value> {
        let ts = now_ms();
        let user_id_hex = hex::encode(signer.public_key_compressed());
        let sig = signer.sign(&build_auth_message(op, ts, &user_id_hex));

        let mut body = body;
        let obj = body
            .as_object_mut()
            .ok_or_else(|| anyhow!("request body must be a JSON object"))?;
        obj.insert("user_id".into(), json!(user_id_hex));
        obj.insert("signature".into(), json!(hex::encode(sig)));
        obj.insert("timestamp_ms".into(), json!(ts));

        let url = format!("{}/api/u/{}{}", self.base, group_key, path);
        let resp = self.http.post(&url).json(&body).send().await?;
        Self::read(resp, &url).await
    }

    /// Cross-wallet POST: address `target_group`'s actor while authenticating as `my_group`.
    ///
    /// Used by `payment-request/create`, the one call whose URL wallet differs from the caller. We
    /// identify by GROUP key because the payee address derives from it — a share key would yield an
    /// address we cannot spend. Group keys can't be Schnorr-signed, hence the token.
    pub async fn post_as_group(
        &self,
        target_group: &str,
        path: &str,
        my_group: &str,
        body: Value,
    ) -> Result<Value> {
        let mut body = body;
        body.as_object_mut()
            .ok_or_else(|| anyhow!("request body must be a JSON object"))?
            .insert("user_id".into(), json!(my_group));
        let url = format!("{}/api/u/{}{}", self.base, target_group, path);
        let token = crate::session::mint(my_group, 3600)?;
        let resp = self
            .http
            .post(&url)
            .bearer_auth(token)
            .json(&body)
            .send()
            .await?;
        Self::read(resp, &url).await
    }

    /// GROUP-key POST (all `ark/*`, device-token registration): these authenticate against the
    /// GROUP key, so a session token is the only credential that works.
    pub async fn post_session(&self, group_key: &str, path: &str, body: Value) -> Result<Value> {
        let url = format!("{}/api/u/{}{}", self.base, group_key, path);
        let token = crate::session::mint(group_key, 3600)?;
        let resp = self
            .http
            .post(&url)
            .bearer_auth(token)
            .json(&body)
            .send()
            .await?;
        Self::read(resp, &url).await
    }

    async fn read(resp: reqwest::Response, url: &str) -> Result<Value> {
        let status = resp.status();
        let text = resp.text().await.unwrap_or_default();
        if !status.is_success() {
            // The runtime returns {"error": "...", "code": n} — surface the message, not the JSON.
            let msg = serde_json::from_str::<Value>(&text)
                .ok()
                .and_then(|v| v.get("error").and_then(|e| e.as_str()).map(String::from))
                .unwrap_or(text);
            return Err(anyhow!("{status} from {url}: {msg}"));
        }
        if text.trim().is_empty() {
            return Ok(json!({}));
        }
        Ok(serde_json::from_str(&text)?)
    }
}

/// Build an `AuthSigner` from a FROST key package's secret share — this is the wallet's auth
/// identity (the same key the cosigner checks `user_id` signatures against).
pub fn signer_from_key_package(key_package_json: &str) -> Result<AuthSigner> {
    use threshold::keys::KeyPackage;
    use threshold::scalar::scalar_to_bytes;
    let kp = KeyPackage::from_json(key_package_json)
        .map_err(|e| anyhow!("bad key package: {e:?}"))?;
    AuthSigner::from_secret_bytes(&scalar_to_bytes(&kp.secret_share))
        .map_err(|e| anyhow!("auth signer: {e:?}"))
}
