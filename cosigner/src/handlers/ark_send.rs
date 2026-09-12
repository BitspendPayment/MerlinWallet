//! Heavy Ark RPCs (send/redeem/settle/settle_delegate/submit_ark_send).
//! Each handler runs synchronously in `spawn_blocking`; ASP gRPC calls are
//! awaited via `Handle::current().block_on(...)` against the upstreams client.

use tonic::Status;

use crate::cosigner::Cosigner;
use crate::handlers::parsers;
use crate::state::{CosignerState, VtxoEntry};
use crate::types::VtxoInput;
use crate::upstreams::Upstreams;
use crate::wallet_proto::*;

use super::helpers::{
    delete_user_delegate, now_secs, save_user_vtxos,
};



// =============================================================================
// send_vtxo — guest-routed helpers (the session + signing live in the WASM guest;
// these only translate the host's VTXO projection in/out of the guest wires).
// =============================================================================

/// Guest-routed delegate-settle Phase 1 prep: the VTXOs to push into the guest + the
/// host-computed intent renewal deadline (earliest VTXO expiry − safety margin). The guest
/// computes the self-refresh output itself; the host only supplies what it alone knows.
pub fn build_delegate_step1(
    state: &CosignerState,
    upstreams: &Upstreams,
) -> Result<(Vec<VtxoInput>, Option<u64>), Status> {
    if state.vtxos.is_empty() {
        return Err(Status::failed_precondition("no VTXOs to settle"));
    }
    let vtxos = state
        .vtxos
        .iter()
        .map(|e| VtxoInput {
            txid: e.txid.clone(),
            vout: e.vout,
            amount_sats: e.amount,
            exit_delay: e.exit_delay,
        })
        .collect();
    let earliest = state
        .vtxos
        .iter()
        .filter_map(|e| (e.expires_at > 0).then_some(e.expires_at))
        .min()
        .unwrap_or(0);
    let margin = upstreams.auto_settle_safety_margin_secs;
    let intent_valid_at = if earliest > margin {
        Some((earliest - margin) as u64)
    } else {
        None
    };
    Ok((vtxos, intent_valid_at))
}

/// Phase 2: apply the guest's `SendVtxoStep2` result to the host VTXO/history projection
/// (drop spent VTXOs, add the guest-reported change, invalidate delegate, record history)
/// and produce the `Settled` gRPC response.
pub fn apply_send_result(
    state: &mut CosignerState,
    upstreams: &Upstreams,
    req: &SendVtxoRequest,
    ark_txid: String,
    change: Option<(String, u32, u64, u32)>,
) -> SendVtxoResponse {
    let user_id_hex = parsers::user_id_hex(&req.user_id);
    state.vtxos.clear();
    state.delegate_session = None;
    delete_user_delegate(upstreams.persistence.as_ref(), &user_id_hex);
    // The off-chain send consumed VTXOs the stored guest delegate may reference; its host-side marker
    // carries no coverage info, so clear it (else `has_active_delegate` stays true + the auto-settle
    // tick could submit signatures over now-spent VTXOs).
    if state.guest_delegate_threshold.take().is_some() {
        super::helpers::delete_guest_delegate_threshold(upstreams.persistence.as_ref(), &user_id_hex);
        tracing::info!("[{user_id_hex}] guest delegate marker invalidated by off-chain send");
    }
    if let Some((txid, vout, amount, exit_delay)) = change {
        tracing::info!(
            "[{user_id_hex}] SendVtxo: change VTXO txid={txid}, vout={vout}, amount={amount}, exit_delay={exit_delay}"
        );
        state.vtxos.push(VtxoEntry {
            txid,
            vout,
            amount,
            exit_delay,
            created_at: now_secs(),
            expires_at: 0,
        });
    }
    save_user_vtxos(upstreams.persistence.as_ref(), &user_id_hex, &state.vtxos);
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
