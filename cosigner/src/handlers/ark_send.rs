//! Heavy Ark RPCs (send/redeem/settle/settle_delegate/submit_ark_send).
//! Each handler runs synchronously in `spawn_blocking`; ASP gRPC calls are
//! awaited via `Handle::current().block_on(...)` against the store client.

use crate::grpc::Status;

use crate::cosigner::Cosigner;
use crate::handlers::parsers;
use crate::types::VtxoEntry;
use crate::types::VtxoInput;
use crate::store::Store;
use crate::wallet_proto::*;

use super::helpers::{
    delete_user_delegate, now_secs,
};



// =============================================================================
// send_vtxo — guest-routed helpers (the session + signing live in the WASM guest;
// these only translate the host's VTXO projection in/out of the guest wires).
// =============================================================================

/// The VTXOs a delegate settles and the deadline its intent becomes valid at (earliest VTXO expiry
/// − the safety margin). The self-refresh output is computed from the cosigner's own key.
pub fn build_delegate_step1(
    owned: &[VtxoEntry],
    store: &Store,
) -> Result<(Vec<VtxoInput>, Option<u64>), Status> {
    if owned.is_empty() {
        return Err(Status::failed_precondition("no VTXOs to settle"));
    }
    let vtxos = owned
        .iter()
        .map(|e| VtxoInput {
            txid: e.txid.clone(),
            vout: e.vout,
            amount_sats: e.amount,
            exit_delay: e.exit_delay,
        })
        .collect();
    let earliest = owned
        .iter()
        .filter_map(|e| (e.expires_at > 0).then_some(e.expires_at))
        .min()
        .unwrap_or(0);
    let margin = store.auto_settle_safety_margin_secs;
    let intent_valid_at = if earliest > margin {
        Some((earliest - margin) as u64)
    } else {
        None
    };
    Ok((vtxos, intent_valid_at))
}

/// Apply a completed send to the owned VTXO set: the send spent everything, so clear it and add
/// back whatever change it produced.
pub fn apply_send_result(
    owned: &mut Vec<VtxoEntry>,
    store: &Store,
    req: &SendVtxoRequest,
    ark_txid: String,
    change: Option<(String, u32, u64, u32)>,
) -> SendVtxoResponse {
    let user_id_hex = parsers::user_id_hex(&req.user_id);
    owned.clear();
    // The send consumed the VTXOs a stored delegate may cover, so it can no longer be settled.
    delete_user_delegate(store, &user_id_hex);
    super::helpers::delete_guest_delegate_threshold(store, &user_id_hex);
    if let Some((txid, vout, amount, exit_delay)) = change {
        tracing::info!(
            "[{user_id_hex}] SendVtxo: change VTXO txid={txid}, vout={vout}, amount={amount}, exit_delay={exit_delay}"
        );
        owned.push(VtxoEntry {
            txid,
            vout,
            amount,
            exit_delay,
            created_at: now_secs(),
            expires_at: 0,
        });
    }
    SendVtxoResponse {
        status: send_vtxo_response::Status::Settled as i32,
        messages_to_sign: vec![],
        script_path_spend: false,
        ark_txid,
        error_message: String::new(),
    }
}

// =============================================================================
// submit_ark_send
// =============================================================================

impl Cosigner {

}
