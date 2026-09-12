//! Shared helpers for actor command handlers. Each function takes plain references to
//! `CosignerState` and shared services so handlers can compose without locking.

use std::time::{SystemTime, UNIX_EPOCH};

use tonic::Status;

use crate::auth::message::{build_auth_message, MAX_TIMESTAMP_DRIFT_MS};
use crate::cosigner::state::CosignerState;
use crate::kv_store::KvStore;

/// Per-user auth check. A valid upstream session token bound to this user (`session`, already
/// signature+exp-verified at the REST boundary) authenticates the request; otherwise we fall back
/// to the single-key BIP-340 Schnorr signature verified against the `user_id` (owner pubkey)
/// host-side via the `threshold` crate. A token for a DIFFERENT user is rejected (no fallback).
pub fn auth_check(
    state: &mut CosignerState,
    user_id_bytes: &[u8],
    signature: &[u8],
    timestamp_ms: i64,
    operation: &str,
) -> Result<(), Status> {
    // A gated wallet sends an EMPTY signature and authenticates via the session
    // token alone — reaching here means that token was missing or invalid. Say
    // so, instead of the misleading generic 64-byte complaint below.
    if signature.is_empty() {
        return Err(Status::unauthenticated(
            "missing or invalid session token (no Schnorr signature supplied)",
        ));
    }

    let user_id_hex = hex::encode(user_id_bytes);
    timestamp_check(state, timestamp_ms, &user_id_hex, operation)?;

    let auth_message = build_auth_message(operation, timestamp_ms, &user_id_hex);

    // BIP-340 Schnorr verification of the auth message (pure public crypto; the user_id IS the
    // 33-byte pubkey). Host-side via the `threshold` crate — no legacy WASM component involved.
    let pk: &[u8; 33] = user_id_bytes
        .try_into()
        .map_err(|_| Status::unauthenticated("user_id must be a 33-byte public key"))?;
    let sig: &[u8; 64] = signature
        .try_into()
        .map_err(|_| Status::unauthenticated("signature must be 64 bytes"))?;
    let is_valid = threshold::auth::verify_schnorr_signature(pk, &auth_message, sig);

    if !is_valid {
        tracing::warn!("[{user_id_hex}] Signature verification failed for {operation}");
        return Err(Status::unauthenticated("Invalid authentication signature"));
    }

    Ok(())
}

/// Stateless variant of [`auth_check`]: verifies the BIP-340 signature + the timestamp drift
/// without a `CosignerState`.
/// (The replay window is the same; auth carries no replay cache — see `timestamp_check`.)
pub fn verify_auth(
    user_id_bytes: &[u8],
    signature: &[u8],
    timestamp_ms: i64,
    operation: &str,
) -> Result<(), Status> {
    // See auth_check: an empty signature means "session token expected".
    if signature.is_empty() {
        return Err(Status::unauthenticated(
            "missing or invalid session token (no Schnorr signature supplied)",
        ));
    }

    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_millis() as i64;
    if (now - timestamp_ms).abs() > MAX_TIMESTAMP_DRIFT_MS {
        return Err(Status::unauthenticated(
            "Request timestamp is outside acceptable range",
        ));
    }
    let user_id_hex = hex::encode(user_id_bytes);
    let auth_message = build_auth_message(operation, timestamp_ms, &user_id_hex);
    let pk: &[u8; 33] = user_id_bytes
        .try_into()
        .map_err(|_| Status::unauthenticated("user_id must be a 33-byte public key"))?;
    let sig: &[u8; 64] = signature
        .try_into()
        .map_err(|_| Status::unauthenticated("signature must be 64 bytes"))?;
    if !threshold::auth::verify_schnorr_signature(pk, &auth_message, sig) {
        return Err(Status::unauthenticated("Invalid authentication signature"));
    }
    Ok(())
}

/// Timestamp drift check (no signature, no replay cache). The signing nonce is
/// generated randomly per request, so replay of a captured (timestamp, sig) is
/// not a concern; we only reject requests outside the acceptable clock window.
pub fn timestamp_check(
    _state: &mut CosignerState,
    timestamp_ms: i64,
    user_id_hex: &str,
    operation: &str,
) -> Result<(), Status> {
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_millis() as i64;
    let diff = (now - timestamp_ms).abs();
    if diff > MAX_TIMESTAMP_DRIFT_MS {
        tracing::warn!(
            "[{user_id_hex}] Timestamp validation failed for {operation}: diff={diff}ms"
        );
        return Err(Status::unauthenticated(
            "Request timestamp is outside acceptable range",
        ));
    }
    Ok(())
}

/// Whether `claimed_share_hex` is one of the group's authorized verifying shares.
pub fn is_authorized_share(authorized_shares: &[String], claimed_share_hex: &str) -> bool {
    authorized_shares.iter().any(|s| s == claimed_share_hex)
}

/// Group auth: the request is signed by ONE of the group's authorized verifying
/// shares (any participant of a contract cosigner). Verifies the BIP-340
/// signature against `claimed_share` AND asserts it is in `authorized_shares`.
/// Each signer signs as herself — the auth message binds her own share, which is
/// both the pubkey the signature is checked against and the identity in the
/// canonical message, so this reduces to the per-key `auth_check`.
pub fn auth_check_group(
    state: &mut CosignerState,
    claimed_share_bytes: &[u8],
    authorized_shares: &[String],
    signature: &[u8],
    timestamp_ms: i64,
    operation: &str,
) -> Result<(), Status> {
    let claimed_hex = hex::encode(claimed_share_bytes);
    if !is_authorized_share(authorized_shares, &claimed_hex) {
        tracing::warn!("[{claimed_hex}] not an authorized signer for {operation}");
        return Err(Status::unauthenticated(
            "signer not authorized for this group",
        ));
    }
    auth_check(state, claimed_share_bytes, signature, timestamp_ms, operation)
}

/// Ensure the host `policy_state` projection is present. Plan A: the native `CosignerActor`'s seal
/// is the single source — `policy_state` is populated from the actor by `ensure_actor` (called per
/// command before dispatch); there is no `policies` sled tree. So this is now just a presence check.
/// (`persistence`/`secret_store` kept for call-site signature symmetry.)
pub fn ensure_policy_loaded(
    state: &mut CosignerState,
    _persistence: &dyn KvStore,
    user_id_hex: &str,
) -> Result<(), Status> {
    if state.policy_state.is_some() {
        return Ok(());
    }
    Err(Status::not_found(format!(
        "No policy state for {user_id_hex} (actor not loaded — onboarding incomplete?)"
    )))
}

/// Fetch the user's group x-only pubkey (64 hex chars) for Ark address derivation.
/// The compressed key from the policy is 33 bytes (66 hex); strip the parity byte.
pub fn get_user_xonly_pubkey(
    state: &mut CosignerState,
    persistence: &dyn KvStore,
    user_id_hex: &str,
) -> Result<String, Status> {
    ensure_policy_loaded(state, persistence, user_id_hex)?;
    let ps = state
        .policy_state
        .as_ref()
        .ok_or_else(|| Status::not_found("no policy state"))?;
    let vk_hex = crate::cosigner::handlers::parsers::extract_verifying_key(
        &ps.normal_policy.public_key_package_json,
    )?;
    if vk_hex.len() == 66 {
        Ok(vk_hex[2..].to_string())
    } else if vk_hex.len() == 64 {
        Ok(vk_hex)
    } else {
        Err(Status::internal(format!(
            "unexpected verifying key length: {}",
            vk_hex.len()
        )))
    }
}

/// Resolve an addressing id (a member's verifying share) to its GROUP KEY
/// (`cosigner_id`) via `policy_owner_idx`, so all of a group's per-user data is keyed
/// by the one group key. Identity for a group key, or any id with no index entry.
pub fn group_key_of(persistence: &dyn KvStore, id: &str) -> String {
    persistence
        .get("policy_owner_idx", id)
        .ok()
        .flatten()
        .unwrap_or_else(|| id.to_string())
}

/// Persist a user's VTXO list (best-effort; logs and ignores errors).
pub fn save_user_vtxos(
    persistence: &dyn KvStore,
    user_id_hex: &str,
    vtxos: &[crate::cosigner::state::VtxoEntry],
) {
    let user_id_hex = &group_key_of(persistence, user_id_hex);
    if let Ok(json) = serde_json::to_string(vtxos) {
        if let Err(e) = persistence.put("vtxo_store", user_id_hex, &json) {
            tracing::warn!("persist vtxo_store/{user_id_hex} failed: {e}");
        }
    }
}

/// Persist a user's registered device tokens.
pub fn save_user_device_tokens(
    persistence: &dyn KvStore,
    user_id_hex: &str,
    tokens: &[crate::cosigner::state::DeviceToken],
) {
    let user_id_hex = &group_key_of(persistence, user_id_hex);
    if let Ok(json) = serde_json::to_string(tokens) {
        if let Err(e) = persistence.put("device_tokens", user_id_hex, &json) {
            tracing::warn!("persist device_tokens/{user_id_hex} failed: {e}");
        }
    }
}

/// Persist a user's Ark transaction history.
pub fn save_user_ark_history(
    persistence: &dyn KvStore,
    user_id_hex: &str,
    entries: &[crate::cosigner::types::ArkTxEntry],
) {
    let user_id_hex = &group_key_of(persistence, user_id_hex);
    if let Ok(json) = serde_json::to_string(entries) {
        if let Err(e) = persistence.put("ark_tx_history", user_id_hex, &json) {
            tracing::warn!("persist ark_tx_history/{user_id_hex} failed: {e}");
        }
    }
}

/// Read back a user's Ark transaction history from persistence. Returns an
/// empty vec on miss or parse failure (best-effort — history isn't safety-
/// critical, just user-facing).
pub fn load_user_ark_history(
    persistence: &dyn KvStore,
    user_id_hex: &str,
) -> Vec<crate::cosigner::types::ArkTxEntry> {
    let user_id_hex = &group_key_of(persistence, user_id_hex);
    match persistence.get("ark_tx_history", user_id_hex) {
        Ok(Some(json)) => match serde_json::from_str(&json) {
            Ok(entries) => entries,
            Err(e) => {
                tracing::warn!("parse ark_tx_history/{user_id_hex} failed: {e}");
                Vec::new()
            }
        },
        _ => Vec::new(),
    }
}

/// Read back a user's stored VTXOs from persistence. Returns an empty vec on
/// miss or parse failure. The vtxo_stream subscription will reconcile via its
/// own dedup as ASP events arrive, so a stale read here is self-healing.
pub fn load_user_vtxos(
    persistence: &dyn KvStore,
    user_id_hex: &str,
) -> Vec<crate::cosigner::state::VtxoEntry> {
    let user_id_hex = &group_key_of(persistence, user_id_hex);
    match persistence.get("vtxo_store", user_id_hex) {
        Ok(Some(json)) => match serde_json::from_str(&json) {
            Ok(vtxos) => vtxos,
            Err(e) => {
                tracing::warn!("parse vtxo_store/{user_id_hex} failed: {e}");
                Vec::new()
            }
        },
        _ => Vec::new(),
    }
}

/// Read back a user's registered FCM device tokens from persistence. Closes
/// the gap from TODO #4 — without this, pushes silently no-op after a
/// cosigner restart for any user who hasn't reopened the app since.
pub fn load_user_device_tokens(
    persistence: &dyn KvStore,
    user_id_hex: &str,
) -> Vec<crate::cosigner::state::DeviceToken> {
    let user_id_hex = &group_key_of(persistence, user_id_hex);
    match persistence.get("device_tokens", user_id_hex) {
        Ok(Some(json)) => match serde_json::from_str(&json) {
            Ok(tokens) => tokens,
            Err(e) => {
                tracing::warn!("parse device_tokens/{user_id_hex} failed: {e}");
                Vec::new()
            }
        },
        _ => Vec::new(),
    }
}

/// Record a user's boarding address so the boarding watcher can poll it. Keyed
/// by the canonical group key (one entry per group).
pub fn save_user_boarding_address(
    persistence: &dyn KvStore,
    user_id_hex: &str,
    boarding_address: &str,
) {
    let user_id_hex = &group_key_of(persistence, user_id_hex);
    if let Err(e) = persistence.put("boarding_watches", user_id_hex, boarding_address) {
        tracing::warn!("persist boarding_watches/{user_id_hex} failed: {e}");
    }
}

/// The set of boarding outpoints (`txid:vout`) already pushed for, so the
/// watcher notifies once per deposit and survives a restart.
pub fn save_user_boarding_seen(persistence: &dyn KvStore, user_id_hex: &str, seen: &[String]) {
    let user_id_hex = &group_key_of(persistence, user_id_hex);
    if let Ok(json) = serde_json::to_string(seen) {
        if let Err(e) = persistence.put("boarding_seen_outpoints", user_id_hex, &json) {
            tracing::warn!("persist boarding_seen_outpoints/{user_id_hex} failed: {e}");
        }
    }
}

pub fn load_user_boarding_seen(persistence: &dyn KvStore, user_id_hex: &str) -> Vec<String> {
    let user_id_hex = &group_key_of(persistence, user_id_hex);
    match persistence.get("boarding_seen_outpoints", user_id_hex) {
        Ok(Some(json)) => serde_json::from_str(&json).unwrap_or_default(),
        _ => Vec::new(),
    }
}

/// Persist a stored signed delegate intent. The on-disk record carries no
/// secret material — the cosigner secret stays in `SecretStore` and is
/// reattached only at rehydration time (issue #31).
pub fn save_user_delegate(
    persistence: &dyn KvStore,
    user_id_hex: &str,
    record: &crate::cosigner::state::PersistedDelegateRecord,
) {
    let user_id_hex = &group_key_of(persistence, user_id_hex);
    match serde_json::to_string(record) {
        Ok(json) => {
            if let Err(e) = persistence.put("delegate_sessions", user_id_hex, &json) {
                tracing::warn!("persist delegate_sessions/{user_id_hex} failed: {e}");
            }
        }
        Err(e) => {
            tracing::warn!("serialize delegate_sessions/{user_id_hex} failed: {e}");
        }
    }
}

/// Read back a stored delegate. Returns `None` on miss, parse failure, or
/// any other error — caller treats absence as "no delegate, client should
/// re-delegate on next refresh."
pub fn load_user_delegate(
    persistence: &dyn KvStore,
    user_id_hex: &str,
) -> Option<crate::cosigner::state::PersistedDelegateRecord> {
    let user_id_hex = &group_key_of(persistence, user_id_hex);
    match persistence.get("delegate_sessions", user_id_hex) {
        Ok(Some(json)) => match serde_json::from_str(&json) {
            Ok(record) => Some(record),
            Err(e) => {
                tracing::warn!("parse delegate_sessions/{user_id_hex} failed: {e}");
                None
            }
        },
        _ => None,
    }
}

/// Drop the stored delegate. Called from every invalidation site — once
/// the in-memory `DelegateRecord` is cleared, the sled row must go too,
/// otherwise the next actor spawn would rehydrate a stale intent that no
/// longer matches `state.vtxos`.
pub fn delete_user_delegate(persistence: &dyn KvStore, user_id_hex: &str) {
    let user_id_hex = &group_key_of(persistence, user_id_hex);
    if let Err(e) = persistence.delete("delegate_sessions", user_id_hex) {
        tracing::warn!("delete delegate_sessions/{user_id_hex} failed: {e}");
    }
}

/// Plan A Phase 2: persist the guest-delegate auto-settle threshold (Unix secs) — a SECRET-FREE
/// marker so a stored delegate survives a runtime restart. The delegate itself lives in the guest's
/// sealed snapshot; this is only the host's "fire at / has a pending delegate" record (replacing the
/// legacy `delegate_sessions` row, which carried no secret either but needed the dkg-secret to rehydrate).
pub fn save_guest_delegate_threshold(persistence: &dyn KvStore, user_id_hex: &str, threshold: i64) {
    let user_id_hex = &group_key_of(persistence, user_id_hex);
    if let Err(e) = persistence.put(
        "guest_delegate_thresholds",
        user_id_hex,
        &threshold.to_string(),
    ) {
        tracing::warn!("persist guest_delegate_thresholds/{user_id_hex} failed: {e}");
    }
}

/// Read back the guest-delegate threshold marker. `None` on miss / parse error.
pub fn load_guest_delegate_threshold(persistence: &dyn KvStore, user_id_hex: &str) -> Option<i64> {
    let user_id_hex = &group_key_of(persistence, user_id_hex);
    match persistence.get("guest_delegate_thresholds", user_id_hex) {
        Ok(Some(s)) => s.parse().ok(),
        _ => None,
    }
}

/// Drop the guest-delegate threshold marker (after the delegate auto-settles or is invalidated).
pub fn delete_guest_delegate_threshold(persistence: &dyn KvStore, user_id_hex: &str) {
    let user_id_hex = &group_key_of(persistence, user_id_hex);
    if let Err(e) = persistence.delete("guest_delegate_thresholds", user_id_hex) {
        tracing::warn!("delete guest_delegate_thresholds/{user_id_hex} failed: {e}");
    }
}

/// Seconds since the Unix epoch.
pub fn now_secs() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs() as i64
}

/// Calculate spent amount from a transaction (PSBT or raw tx) for policy eval.
pub fn calculate_spent_amount(
    state: &mut CosignerState,
    full_tx: &[u8],
    pkp_json: &str,
) -> Result<i64, Status> {
    if full_tx.is_empty() {
        return Ok(0);
    }
    if full_tx.len() > 5 && full_tx[..5] == [0x70, 0x73, 0x62, 0x74, 0xff] {
        if let Ok(psbt) = bitcoin::Psbt::deserialize(full_tx) {
            let input_total: u64 = psbt
                .inputs
                .iter()
                .filter_map(|i| i.witness_utxo.as_ref())
                .map(|utxo| utxo.value.to_sat())
                .sum();
            // The user's change script is whatever script their spent inputs
            // reside under — for Ark redeems all of the user's VTXOs share a
            // single script tied to their group key. Reading it from the
            // PSBT's witness_utxo is safe: any tampering also tampers the
            // sighash the FROST signature commits to, so a compromised
            // client can't silently mislabel inputs without producing a
            // signature that won't verify or won't broadcast.
            //
            // Outputs whose script matches the user's input script are
            // change; the spent (recipient) amount is everything else.
            let user_input_scripts: std::collections::HashSet<_> = psbt
                .inputs
                .iter()
                .filter_map(|i| i.witness_utxo.as_ref())
                .map(|utxo| utxo.script_pubkey.clone())
                .collect();
            let change_amount: u64 = psbt
                .unsigned_tx
                .output
                .iter()
                .filter(|out| user_input_scripts.contains(&out.script_pubkey))
                .map(|out| out.value.to_sat())
                .sum();
            let net_spend = input_total.saturating_sub(change_amount);
            tracing::info!(
                "PSBT policy eval: inputs={input_total}, change={change_amount}, net_spend={net_spend}"
            );
            return Ok(net_spend as i64);
        }
    }
    if full_tx.starts_with(b"ARK_AMOUNT:") {
        let amount_str = std::str::from_utf8(&full_tx[11..])
            .map_err(|e| Status::internal(format!("invalid ARK_AMOUNT: {e}")))?;
        let amount: i64 = amount_str
            .parse()
            .map_err(|e| Status::internal(format!("invalid ARK_AMOUNT value: {e}")))?;
        return Ok(amount);
    }
    let tweaked_pkp_json =
        crate::cosigner::handlers::parsers::pub_key_package_tweak_json(pkp_json, None)?;
    let vk_hex = crate::cosigner::handlers::parsers::extract_verifying_key(&tweaked_pkp_json)?;
    let script_hex = crate::bitcoin::tx_parser::derive_p2tr_script_hex(&vk_hex)
        .map_err(|e| Status::internal(format!("P2TR derivation: {e}")))?;
    let spent = crate::bitcoin::tx_parser::calculate_spent_amount(
        full_tx,
        &script_hex,
        state
            .utxo_state
            .as_ref()
            .map(|u| &u.utxos[..])
            .unwrap_or(&[]),
    )
    .map_err(|e| Status::internal(format!("tx parse: {e}")))?;
    Ok(spent)
}

#[cfg(test)]
mod tests {
    use super::is_authorized_share;

    #[test]
    fn authorized_share_membership() {
        let roster = vec!["aa".to_string(), "bb".to_string()];
        assert!(is_authorized_share(&roster, "aa"));
        assert!(is_authorized_share(&roster, "bb"));
        assert!(!is_authorized_share(&roster, "cc"));
        // Empty roster authorizes nobody.
        assert!(!is_authorized_share(&[], "aa"));
    }
}
