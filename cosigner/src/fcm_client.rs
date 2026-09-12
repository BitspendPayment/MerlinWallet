//! Firebase Cloud Messaging HTTP v1 client.
//!
//! Sends data-only push notifications to wake the recipient device after a
//! VTXO arrives, so the app can re-delegate while still in the background.
//!
//! Auth: Google service account JWT-bearer flow. Access tokens are minted on
//! demand and cached for 1 hour minus 5-minute slack.

use std::collections::HashMap;
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

use jsonwebtoken::{encode, Algorithm, EncodingKey, Header};
use serde::{Deserialize, Serialize};
use tokio::sync::Mutex;

const FCM_SCOPE: &str = "https://www.googleapis.com/auth/firebase.messaging";
const TOKEN_URL: &str = "https://oauth2.googleapis.com/token";
const FCM_BASE_URL: &str = "https://fcm.googleapis.com";
const SAFETY_SLACK_SECS: i64 = 5 * 60;

#[derive(Debug, Clone, Deserialize)]
pub struct ServiceAccount {
    pub project_id: String,
    pub client_email: String,
    pub private_key: String,
    pub token_uri: Option<String>,
}

struct CachedToken {
    access_token: String,
    expires_at: i64,
}

pub struct FcmClient {
    sa: ServiceAccount,
    http: reqwest::Client,
    encoding_key: EncodingKey,
    /// FCM messages:send base URL. Defaults to `FCM_BASE_URL`; overridable
    /// for e2e mock-server tests via `FCM_BASE_URL` env var.
    base_url: String,
    cache: Arc<Mutex<Option<CachedToken>>>,
}

impl FcmClient {
    /// Parse a service-account JSON string and build a client. `base_url`
    /// is `None` for real Firebase or `Some(mock_url)` for tests.
    pub fn from_service_account_json(
        json: &str,
        base_url_override: Option<String>,
    ) -> Result<Self, String> {
        let sa: ServiceAccount =
            serde_json::from_str(json).map_err(|e| format!("parse service account: {e}"))?;
        let encoding_key = EncodingKey::from_rsa_pem(sa.private_key.as_bytes())
            .map_err(|e| format!("parse RSA private key: {e}"))?;
        let http = reqwest::Client::builder()
            .timeout(std::time::Duration::from_secs(15))
            .build()
            .map_err(|e| format!("build reqwest client: {e}"))?;
        let base_url = base_url_override.unwrap_or_else(|| FCM_BASE_URL.to_string());
        Ok(Self {
            sa,
            http,
            encoding_key,
            base_url,
            cache: Arc::new(Mutex::new(None)),
        })
    }

    /// Send a data-only push to one FCM token. Errors are surfaced so the
    /// caller can log them; failures don't propagate further.
    pub async fn send_data(
        &self,
        target_token: &str,
        data: &HashMap<String, String>,
    ) -> Result<(), String> {
        let access = self.access_token().await?;
        let url = format!(
            "{}/v1/projects/{}/messages:send",
            self.base_url, self.sa.project_id
        );
        let body = serde_json::json!({
            "message": {
                "token": target_token,
                "data": data,
                // Android: high priority + content-available so the device wakes
                // for background processing.
                "android": {
                    "priority": "HIGH",
                },
                // iOS: silent push (content-available=1) + apns-priority=5
                // (Apple requires <=5 for content-available). Without this APNS
                // drops the message rather than waking the app.
                "apns": {
                    "headers": {
                        "apns-priority": "5",
                        "apns-push-type": "background",
                    },
                    "payload": {
                        "aps": {
                            "content-available": 1,
                        }
                    }
                }
            }
        });
        let resp = self
            .http
            .post(&url)
            .bearer_auth(&access)
            .json(&body)
            .send()
            .await
            .map_err(|e| format!("FCM POST: {e}"))?;
        let status = resp.status();
        if !status.is_success() {
            let body = resp.text().await.unwrap_or_default();
            return Err(format!("FCM send returned {status}: {body}"));
        }
        Ok(())
    }

    /// Send a USER-VISIBLE notification (title/body) plus a data payload. Used
    /// for boarding deposits: the user taps the notification to board (no
    /// background processing, so a normal-priority visible push, not silent).
    pub async fn send_notification(
        &self,
        target_token: &str,
        title: &str,
        body: &str,
        data: &HashMap<String, String>,
    ) -> Result<(), String> {
        let access = self.access_token().await?;
        let url = format!(
            "{}/v1/projects/{}/messages:send",
            self.base_url, self.sa.project_id
        );
        let body = serde_json::json!({
            "message": {
                "token": target_token,
                "notification": { "title": title, "body": body },
                "data": data,
                "android": { "priority": "HIGH" },
                "apns": {
                    "headers": { "apns-priority": "10" },
                    "payload": { "aps": { "alert": { "title": title, "body": body } } }
                }
            }
        });
        let resp = self
            .http
            .post(&url)
            .bearer_auth(&access)
            .json(&body)
            .send()
            .await
            .map_err(|e| format!("FCM POST: {e}"))?;
        let status = resp.status();
        if !status.is_success() {
            let body = resp.text().await.unwrap_or_default();
            return Err(format!("FCM send returned {status}: {body}"));
        }
        Ok(())
    }

    async fn access_token(&self) -> Result<String, String> {
        let now = unix_secs();
        {
            let cache = self.cache.lock().await;
            if let Some(t) = cache.as_ref() {
                if t.expires_at - SAFETY_SLACK_SECS > now {
                    return Ok(t.access_token.clone());
                }
            }
        }
        let new = self.mint_token().await?;
        let mut cache = self.cache.lock().await;
        *cache = Some(CachedToken {
            access_token: new.access_token.clone(),
            expires_at: now + new.expires_in,
        });
        Ok(new.access_token)
    }

    async fn mint_token(&self) -> Result<TokenResponse, String> {
        let now = unix_secs();
        let token_uri = self
            .sa
            .token_uri
            .clone()
            .unwrap_or_else(|| TOKEN_URL.to_string());
        let claims = JwtClaims {
            iss: self.sa.client_email.clone(),
            scope: FCM_SCOPE.to_string(),
            // OAuth audience must match the endpoint the assertion is POSTed
            // to; real Google verifies this. We use the same `token_uri` for
            // both so dev (real Firebase) and test (mock server) stay in sync.
            aud: token_uri.clone(),
            iat: now,
            exp: now + 3600,
        };
        let header = Header::new(Algorithm::RS256);
        let jwt =
            encode(&header, &claims, &self.encoding_key).map_err(|e| format!("sign JWT: {e}"))?;
        let resp = self
            .http
            .post(&token_uri)
            .form(&[
                ("grant_type", "urn:ietf:params:oauth:grant-type:jwt-bearer"),
                ("assertion", &jwt),
            ])
            .send()
            .await
            .map_err(|e| format!("OAuth POST: {e}"))?;
        if !resp.status().is_success() {
            let status = resp.status();
            let body = resp.text().await.unwrap_or_default();
            return Err(format!("OAuth token mint {status}: {body}"));
        }
        resp.json::<TokenResponse>()
            .await
            .map_err(|e| format!("parse OAuth response: {e}"))
    }
}

#[derive(Debug, Serialize)]
struct JwtClaims {
    iss: String,
    scope: String,
    aud: String,
    iat: i64,
    exp: i64,
}

#[derive(Debug, Deserialize)]
struct TokenResponse {
    access_token: String,
    expires_in: i64,
}

fn unix_secs() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0)
}
