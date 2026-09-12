//! Storage and notification helpers for the cosigner.
//!
//! What is left of `registry.rs`. The registry held a `DashMap` of actors, a command channel per
//! actor and a `route_*` function per operation; with one cosigner per process, called directly,
//! none of that has anything to route. These are the parts that were never about routing: sealing
//! and restoring the snapshot, running blocking state work off the async threads, and pushing.

use std::time::{SystemTime, UNIX_EPOCH};


use crate::upstreams::Upstreams;

use super::cosigner::Cosigner;

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






/// Phase 4: opaque sealed-state tree (one blob per group key). The host stores it but
/// cannot read it (identity-sealed JSON today; enclave AEAD later). Keyed by group key.
const SEALED_STATE_TREE: &str = "sealed_state";

/// Persist the actor's snapshot blob after a state mutation (best-effort).
/// Re-seal an actor whose state changed outside a `route_*` fn.
pub(crate) async fn seal_snapshot_for(
    actor: &mut Cosigner,
    group_key: &str,
) {
    // The cosigner holds its own `upstreams`, so callers don't have to thread it through.
    let upstreams = actor.upstreams.clone();
    seal_snapshot(actor, &upstreams, group_key).await;
}

pub(crate) async fn seal_snapshot(
    actor: &mut Cosigner,
    upstreams: &Upstreams,
    group_key: &str,
) {
    match actor.to_snapshot() {
        Ok(blob) => {
            if let Err(e) = upstreams
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
pub(crate) async fn restore_snapshot(
    actor: &mut Cosigner,
    upstreams: &Upstreams,
    group_key: &str,
) -> bool {
    let stored = upstreams.persistence.get(SEALED_STATE_TREE, group_key);
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
















