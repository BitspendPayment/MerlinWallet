//! Shared helpers for actor command handlers. Each function takes plain references to
//! `CosignerState` and upstreams services so handlers can compose without locking.

use std::time::{SystemTime, UNIX_EPOCH};

use tonic::Status;

use crate::auth::message::{build_auth_message, MAX_TIMESTAMP_DRIFT_MS};
use crate::kv_store::KvStore;



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



/// Whether `claimed_share_hex` is one of the group's authorized verifying shares.
pub fn is_authorized_share(authorized_shares: &[String], claimed_share_hex: &str) -> bool {
    authorized_shares.iter().any(|s| s == claimed_share_hex)
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
    vtxos: &[crate::types::VtxoEntry],
) {
    let user_id_hex = &group_key_of(persistence, user_id_hex);
    if let Ok(json) = serde_json::to_string(vtxos) {
        if let Err(e) = persistence.put("vtxo_store", user_id_hex, &json) {
            tracing::warn!("persist vtxo_store/{user_id_hex} failed: {e}");
        }
    }
}





/// Read back a user's stored VTXOs from persistence. Returns an empty vec on
/// miss or parse failure. The vtxo_stream subscription will reconcile via its
/// own dedup as ASP events arrive, so a stale read here is self-healing.
pub fn load_user_vtxos(
    persistence: &dyn KvStore,
    user_id_hex: &str,
) -> Vec<crate::types::VtxoEntry> {
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
