//! Storage and notification helpers for the cosigner.
//!
//! What is left of `registry.rs`. The registry held a `DashMap` of actors, a command channel per
//! actor and a `route_*` function per operation; with one cosigner per process, called directly,
//! none of that has anything to route. These are the parts that were never about routing: sealing
//! and restoring the snapshot, running blocking state work off the async threads, and pushing.

use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

use futures::FutureExt;
use parking_lot::Mutex;
use tonic::Status;

use crate::shared::SharedServices;

use super::actor::CosignerActor;
use super::state::{CosignerState, DeviceToken};

pub(crate) fn now_secs() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0)
}

/// Per-actor mailbox depth. Sized for normal request bursts plus a margin for
/// stream fan-in (VTXO updates, indexer events).



// ===========================================================================
// The tokio actor that owns the per-cosigner `CosignerState` and drives it.
// All signing keys + ceremony live in the per-actor `cosigner-actor`.
// ===========================================================================

/// Lock `state` inside `spawn_blocking`, run `f`, return the typed
/// result. `(user, state)` ownership stays with the actor task across this
/// call; the mutex guards only protect against panic-recovery reseating the
/// instance.
///
/// On a handler panic, `spawn_blocking` returns `Err(JoinError::is_panic)`.
/// We surface that as `Err(Status::internal("handler panicked"))` so the
/// caller's oneshot reply fires with an error instead of hanging. The actor
/// task itself stays alive — its outer `catch_unwind` in `run_cosigner` reseats
/// the wedged WASM instance and drains in-flight rendezvous replies.
pub(crate) async fn run_blocking<F, T>(state: Arc<Mutex<CosignerState>>, f: F) -> Result<T, Status>
where
    F: FnOnce(&mut CosignerState) -> Result<T, Status> + Send + 'static,
    T: Send + 'static,
{
    let outcome = tokio::task::spawn_blocking(move || {
        let mut state = state.lock();
        f(&mut state)
    })
    .await;
    match outcome {
        Ok(res) => res,
        Err(join_err) if join_err.is_panic() => {
            tracing::error!("actor handler panicked: {join_err:?}");
            Err(Status::internal("handler panicked"))
        }
        Err(join_err) => Err(Status::internal(format!(
            "actor handler task error: {join_err:?}"
        ))),
    }
}




/// Phase 4: opaque sealed-state tree (one blob per group key). The host stores it but
/// cannot read it (identity-sealed JSON today; enclave AEAD later). Keyed by group key.
const SEALED_STATE_TREE: &str = "sealed_state";

/// Persist the actor's snapshot blob after a state mutation (best-effort).
/// Re-seal an actor whose state changed outside a `route_*` fn.
pub(crate) async fn persist_actor_snapshot_for(
    actor: &mut CosignerActor,
    group_key: &str,
) {
    // The actor holds its own `shared`, so callers don't have to thread it through.
    let shared = actor.shared.clone();
    persist_actor_snapshot(actor, &shared, group_key).await;
}

pub(crate) async fn persist_actor_snapshot(
    actor: &mut CosignerActor,
    shared: &SharedServices,
    group_key: &str,
) {
    match actor.to_snapshot() {
        Ok(blob) => {
            if let Err(e) = shared
                .persistence
                .put(SEALED_STATE_TREE, group_key, &hex::encode(blob))
            {
                tracing::warn!("persist sealed_state/{group_key} failed: {e}");
            }
        }
        Err(e) => tracing::warn!("snapshot failed: {e}"),
    }
}

/// Restore the actor's state from a persisted snapshot, if one exists (on spawn/reseat).
/// Returns `true` when a snapshot was restored — meaning the actor now holds its policy +
/// keys from the sealed blob, so the caller can SKIP `InstallPolicy` (no plaintext key read).
/// `false` when there's no stored blob (first run) or restore failed.
pub(crate) async fn restore_actor_snapshot(
    actor: &mut CosignerActor,
    shared: &SharedServices,
    group_key: &str,
) -> bool {
    let stored = shared.persistence.get(SEALED_STATE_TREE, group_key);
    let Ok(Some(hex_blob)) = stored else {
        return false;
    };
    let Ok(blob) = hex::decode(&hex_blob) else {
        tracing::warn!("sealed_state/{group_key}: corrupt hex; ignoring");
        return false;
    };
    match actor.restore_snapshot(&blob) {
        Ok(()) => {
            tracing::info!("restored actor snapshot for {group_key}");
            true
        }
        Err(e) => {
            tracing::warn!("restore failed: {e}");
            false
        }
    }
}




// ---------------------------------------------------------------------------
// Request-to-pay. Each mutates the actor's SEALED state, so each re-persists the snapshot.
// ---------------------------------------------------------------------------






/// Populate the host `policy_state` projection from the native actor (Plan A: the actor's seal is
/// the single source of truth — there is no `policies` sled tree). The host keeps no secret key
/// (`key_package_json` blank, `server_dkg_secret_hex` None); `contract_pairing` stays in the actor.
pub(crate) async fn load_policy_state_from_actor(
    state: &Arc<Mutex<CosignerState>>,
    actor: &mut CosignerActor,
) -> Result<(), Status> {
    match actor.public_policy() {
        Ok(pp) => {
            let contracts = if pp.contracts_json.is_empty() {
                Default::default()
            } else {
                serde_json::from_str(&pp.contracts_json)
                    .map_err(|e| Status::internal(format!("bad contracts json: {e}")))?
            };
            let mut st = state.lock();
            st.policy_state = Some(crate::cosigner::state::PolicyState {
                cosigner_id: pp.group_key,
                user_signing_identifier_hex: pp.user_signing_identifier_hex,
                server_dkg_secret_hex: None,
                normal_policy: crate::cosigner::state::NormalPolicy {
                    id: "normal".to_string(),
                    key_package_json: String::new(),
                    public_key_package_json: pp.public_key_package_json,
                },
                contracts,
                contract_pairing: None,
            });
            Ok(())
        }
        Err(e) => Err(Status::internal(format!("GetPublicPolicy: {e}"))),
    }
}





/// Send a "vtxo_received" VISIBLE notification to every registered device for
/// this user. The wallet share is passkey-gated, so the device can't silently
/// sign a fresh delegate from a background push — the notification asks the
/// user to open the app, where the Ark tab offers a delegate button (one
/// passkey gesture). Best-effort: failures are logged and ignored — the
/// stream handler has already persisted state, the open-app fallback closes
/// any gap.
pub(crate) async fn push_vtxo_received(
    shared: &SharedServices,
    user_id_hex: &str,
    tokens: &[DeviceToken],
) {
    let Some(fcm) = shared.fcm.as_ref() else {
        return;
    };
    if tokens.is_empty() {
        return;
    }
    let mut data = std::collections::HashMap::new();
    data.insert("type".to_string(), "vtxo_received".to_string());
    data.insert("user_id".to_string(), user_id_hex.to_string());
    for token in tokens {
        if let Err(e) = fcm
            .send_notification(
                &token.fcm_token,
                "Funds received",
                "Tap to activate auto-settle protection",
                &data,
            )
            .await
        {
            tracing::warn!("[{user_id_hex}] FCM push to {} failed: {e}", token.platform);
        }
    }
}

/// Notify the payer that an allowlisted contact has asked them to pay. Best-effort — the intent is
/// already sealed, and the app also polls on resume.
pub async fn push_payment_request(
    fcm: &std::sync::Arc<crate::fcm_client::FcmClient>,
    payer_vk_hex: &str,
    tokens: &[DeviceToken],
    intent_id: &str,
    amount_sats: u64,
) {
    if tokens.is_empty() {
        return;
    }
    let mut data = std::collections::HashMap::new();
    data.insert("type".to_string(), "payment_request".to_string());
    data.insert("user_id".to_string(), payer_vk_hex.to_string());
    data.insert("id".to_string(), intent_id.to_string());
    data.insert("amount_sats".to_string(), amount_sats.to_string());
    let body = format!("{amount_sats} sats — tap to review");
    for token in tokens {
        if let Err(e) = fcm
            .send_notification(&token.fcm_token, "Payment requested", &body, &data)
            .await
        {
            tracing::warn!(
                "[{payer_vk_hex}] payment-request push to {} failed: {e}",
                token.platform
            );
        }
    }
}


