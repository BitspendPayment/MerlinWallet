//! `register_device_token` handler. Stores an FCM token on the user's actor
//! state so the cosigner can wake the device when a new VTXO arrives via
//! `vtxo_stream`.

use tonic::Status;

use crate::cosigner::Cosigner;
use crate::handlers::parsers;
use crate::store::run_blocking;
use crate::state::DeviceToken;
use crate::wallet_proto::*;

use super::helpers::{now_secs, save_user_device_tokens};

const MAX_TOKEN_AGE_SECS: i64 = 60 * 24 * 60 * 60; // 60 days

impl Cosigner {
    pub async fn register_device_token(
        &mut self,
        req: RegisterDeviceTokenRequest,
    ) -> Result<RegisterDeviceTokenResponse, Status> {
        let upstreams = self.upstreams.clone();
        let span = tracing::info_span!("actor::register_device_token", user_id = %parsers::user_id_hex(&req.user_id));
        run_blocking(self.state.clone(), move |state| {
            let _enter = span.enter();
            let upstreams = upstreams.as_ref();
            let user_id_hex = parsers::user_id_hex(&req.user_id);
            // Auth (OP_REGISTER_DEVICE_TOKEN) ran at the REST boundary.

            if req.fcm_token.trim().is_empty() {
                return Err(Status::invalid_argument("fcm_token must not be empty"));
            }
            if req.platform != "android" && req.platform != "ios" {
                return Err(Status::invalid_argument(
                    "platform must be one of: android, ios",
                ));
            }

            let now = now_secs();
            state.device_tokens.retain(|t| {
                t.fcm_token != req.fcm_token && now - t.registered_at < MAX_TOKEN_AGE_SECS
            });
            state.device_tokens.push(DeviceToken {
                fcm_token: req.fcm_token.clone(),
                platform: req.platform.clone(),
                registered_at: now,
                app_version: req.app_version.clone(),
            });

            save_user_device_tokens(
                upstreams.persistence.as_ref(),
                &user_id_hex,
                &state.device_tokens,
            );
            tracing::info!(
                "[{user_id_hex}] register_device_token: platform={} version={} token_count={}",
                req.platform,
                req.app_version,
                state.device_tokens.len()
            );
            Ok(RegisterDeviceTokenResponse { ok: true })
        })
        .await
    }
}
