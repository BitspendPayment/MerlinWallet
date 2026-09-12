//! Heavy Ark RPCs (send/redeem/settle/settle_delegate/submit_ark_send).
//! Each handler runs synchronously in `spawn_blocking`; ASP gRPC calls are
//! awaited via `Handle::current().block_on(...)` against the shared client.

use tokio::runtime::Handle;
use tonic::Status;

use crate::cosigner::actor::CosignerActor;
use crate::cosigner::handlers::parsers;
use crate::cosigner::store::run_blocking;
use crate::cosigner::state::{CosignerState, VtxoEntry};
use crate::cosigner::types::{ArkTxEntry, VtxoInput};
use crate::shared::SharedServices;
use crate::wallet_proto::*;

use super::helpers::{
    delete_user_delegate, now_secs, save_user_ark_history, save_user_vtxos,
};

fn fetch_asp_info(
    asp: &std::sync::Arc<tokio::sync::Mutex<ark::client::AspClient>>,
) -> Result<ark::client::types::ArkInfo, Status> {
    let asp = asp.clone();
    Handle::current().block_on(async move {
        let mut guard = asp.lock().await;
        match &guard.info {
            Some(i) => Ok(i.clone()),
            None => guard
                .get_info()
                .await
                .map_err(|e| Status::internal(format!("ASP get_info: {e}"))),
        }
    })
}

// =============================================================================
// send_vtxo — guest-routed helpers (the session + signing live in the WASM guest;
// these only translate the host's VTXO projection in/out of the guest wires).
// =============================================================================

/// Guest-routed delegate-settle Phase 1 prep: the VTXOs to push into the guest + the
/// host-computed intent renewal deadline (earliest VTXO expiry − safety margin). The guest
/// computes the self-refresh output itself; the host only supplies what it alone knows.
pub fn build_delegate_step1(
    state: &CosignerState,
    shared: &SharedServices,
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
    let margin = shared.auto_settle_safety_margin_secs;
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
    shared: &SharedServices,
    req: &SendVtxoRequest,
    ark_txid: String,
    change: Option<(String, u32, u64, u32)>,
) -> SendVtxoResponse {
    let user_id_hex = parsers::user_id_hex(&req.user_id);
    state.vtxos.clear();
    state.delegate_session = None;
    delete_user_delegate(shared.persistence.as_ref(), &user_id_hex);
    // The off-chain send consumed VTXOs the stored guest delegate may reference; its host-side marker
    // carries no coverage info, so clear it (else `has_active_delegate` stays true + the auto-settle
    // tick could submit signatures over now-spent VTXOs).
    if state.guest_delegate_threshold.take().is_some() {
        super::helpers::delete_guest_delegate_threshold(shared.persistence.as_ref(), &user_id_hex);
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
    save_user_vtxos(shared.persistence.as_ref(), &user_id_hex, &state.vtxos);
    state.ark_tx_history.push(ArkTxEntry {
        tx_type: "send".into(),
        amount_sats: -(req.amount as i64),
        txid: ark_txid.clone(),
        timestamp: now_secs(),
    });
    save_user_ark_history(
        shared.persistence.as_ref(),
        &user_id_hex,
        &state.ark_tx_history,
    );
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

impl CosignerActor {
    pub async fn submit_ark_send(
        &mut self,
        req: SubmitArkSendRequest,
    ) -> Result<(SubmitArkSendResponse, Vec<(String, u64)>), Status> {
        let shared = self.shared.clone();
        let span = tracing::info_span!("actor::submit_ark_send", user_id = %parsers::user_id_hex(&req.user_id));
        run_blocking(self.state.clone(), move |state| {
    let _enter = span.enter();
    let shared = shared.as_ref();
    use bitcoin::base64::{self, Engine as _};

    let user_id_hex = parsers::user_id_hex(&req.user_id);
    tracing::info!("[{user_id_hex}] SubmitArkSend");
    // Auth (OP_SEND_VTXO) ran at the REST boundary.

    let asp = shared.asp_client.clone();

    // Decode client's signed ark tx (base64 PSBT).
    let signed_ark_bytes = base64::engine::general_purpose::STANDARD
        .decode(&req.signed_ark_tx_b64)
        .map_err(|e| Status::invalid_argument(format!("invalid ark tx base64: {e}")))?;
    let signed_ark_psbt = bitcoin::Psbt::deserialize(&signed_ark_bytes)
        .map_err(|e| Status::invalid_argument(format!("invalid ark tx PSBT: {e}")))?;

    for (i, input) in signed_ark_psbt.unsigned_tx.input.iter().enumerate() {
        tracing::info!(
            "[{user_id_hex}] SubmitArkSend: PSBT input[{i}] = {}:{}",
            input.previous_output.txid,
            input.previous_output.vout
        );
    }

    let mut client_signed_checkpoints = Vec::new();
    let mut signed_checkpoint_b64s = Vec::new();
    for cp_b64 in &req.signed_checkpoint_txs_b64 {
        let cp_bytes = base64::engine::general_purpose::STANDARD
            .decode(cp_b64)
            .map_err(|e| Status::invalid_argument(format!("invalid checkpoint base64: {e}")))?;
        let cp = bitcoin::Psbt::deserialize(&cp_bytes)
            .map_err(|e| Status::invalid_argument(format!("invalid checkpoint PSBT: {e}")))?;
        client_signed_checkpoints.push(cp);
        signed_checkpoint_b64s.push(cp_b64.clone());
    }

    let signed_ark_b64 =
        base64::engine::general_purpose::STANDARD.encode(&signed_ark_psbt.serialize());

    // Submit + finalize against the ASP, then return the response data we need
    // back to the sync side.
    let asp_for_call = asp.clone();
    let log_user = user_id_hex.clone();
    let (ark_txid, response_signed_checkpoint_txs, info) =
        Handle::current().block_on(async move {
            let mut guard = asp_for_call.lock().await;
            tracing::info!("[{log_user}] SubmitArkSend: calling asp.submit_tx");
            let response = guard
                .submit_tx(signed_ark_b64, signed_checkpoint_b64s)
                .await
                .map_err(|e| {
                    tracing::error!("[{log_user}] SubmitArkSend: asp.submit_tx failed: {e}");
                    Status::internal(format!("submit_tx: {e}"))
                })?;
            let ark_txid = response.ark_txid.clone();
            // Hold off on info fetch until after counter-signing is decided.
            Ok::<_, Status>((ark_txid, response.signed_checkpoint_txs, guard.info.clone()))
        })?;

    // Counter-sign: merge client FROST sigs onto ASP-returned checkpoints.
    let mut final_checkpoints = Vec::new();
    for asp_cp_b64 in &response_signed_checkpoint_txs {
        let asp_cp_bytes = base64::engine::general_purpose::STANDARD
            .decode(asp_cp_b64)
            .map_err(|e| Status::internal(format!("invalid ASP checkpoint: {e}")))?;
        let mut asp_cp = bitcoin::Psbt::deserialize(&asp_cp_bytes)
            .map_err(|e| Status::internal(format!("invalid ASP checkpoint PSBT: {e}")))?;

        let cp_txid = asp_cp.unsigned_tx.compute_txid();
        if let Some(client_cp) = client_signed_checkpoints
            .iter()
            .find(|cp| cp.unsigned_tx.compute_txid() == cp_txid)
        {
            if let Some(ws) = &client_cp.inputs[0].witness_script {
                asp_cp.inputs[0].witness_script = Some(ws.clone());
            }
            if asp_cp.inputs[0].tap_scripts.is_empty() {
                asp_cp.inputs[0].tap_scripts = client_cp.inputs[0].tap_scripts.clone();
            }
            // arkd drops the client's `condition` witness field when it re-serializes
            // the checkpoint, yet re-evaluates the condition at FinalizeTx — carry it back.
            for (k, v) in &client_cp.inputs[0].unknown {
                asp_cp.inputs[0]
                    .unknown
                    .entry(k.clone())
                    .or_insert_with(|| v.clone());
            }
            for ((pk, lh), sig) in &client_cp.inputs[0].tap_script_sigs {
                asp_cp.inputs[0]
                    .tap_script_sigs
                    .insert((*pk, *lh), sig.clone());
            }
        }

        let final_bytes = asp_cp.serialize();
        final_checkpoints.push(base64::engine::general_purpose::STANDARD.encode(&final_bytes));
    }

    // Finalize.
    let asp_for_finalize = asp.clone();
    let ark_txid_for_finalize = ark_txid.clone();
    Handle::current().block_on(async move {
        let mut guard = asp_for_finalize.lock().await;
        guard
            .finalize_tx(ark_txid_for_finalize, final_checkpoints)
            .await
            .map_err(|e| Status::internal(format!("finalize_tx: {e}")))
    })?;

    // Compute change VTXO.
    let outputs = &signed_ark_psbt.unsigned_tx.output;
    let (change_txid, change_vout, change_amount) = if outputs.len() >= 3 {
        let txid = signed_ark_psbt.unsigned_tx.compute_txid().to_string();
        let idx = (outputs.len() - 2) as u32;
        let amt = outputs[idx as usize].value.to_sat();
        (txid, idx, amt)
    } else {
        (String::new(), 0, 0)
    };

    // Update local VTXO state. The off-chain send consumed VTXOs, so any
    // stored delegate intent is now stale — invalidate it.
    let spent_total: u64 = state
        .vtxos
        .iter()
        .filter(|e| {
            req.spent_outpoints
                .contains(&format!("{}:{}", e.txid, e.vout))
        })
        .map(|e| e.amount)
        .sum();
    state.vtxos.retain(|e| {
        !req.spent_outpoints
            .contains(&format!("{}:{}", e.txid, e.vout))
    });
    if let Some(record) = &state.delegate_session {
        let any_covered_spent = record
            .covered_outpoints
            .iter()
            .any(|(t, v)| req.spent_outpoints.contains(&format!("{t}:{v}")));
        if any_covered_spent {
            state.delegate_session = None;
            delete_user_delegate(shared.persistence.as_ref(), &user_id_hex);
            tracing::info!(
                "[{user_id_hex}] delegate invalidated: covered VTXO consumed by off-chain send"
            );
        }
    }
    // The guest-delegate marker carries no coverage info (the real delegate lives in the guest seal),
    // and an off-chain send always consumes VTXOs the stored delegate may reference — so the host
    // can't auto-settle it safely. Clear the marker so `has_active_delegate` reflects reality and the
    // tick task won't submit signatures over now-spent VTXOs.
    if state.guest_delegate_threshold.take().is_some() {
        super::helpers::delete_guest_delegate_threshold(shared.persistence.as_ref(), &user_id_hex);
        tracing::info!("[{user_id_hex}] guest delegate marker invalidated by off-chain send");
    }
    if change_amount > 0 {
        let exit_delay = match info {
            Some(i) => i.unilateral_exit_delay as u32,
            None => fetch_asp_info(&asp)?.unilateral_exit_delay as u32,
        };
        state.vtxos.push(VtxoEntry {
            txid: change_txid.clone(),
            vout: change_vout,
            amount: change_amount,
            exit_delay,
            created_at: now_secs(),
            expires_at: 0,
        });
    }

    tracing::info!(
        "[{user_id_hex}] SubmitArkSend: ark_txid={ark_txid}, change=({change_txid}, {change_vout}, {change_amount})"
    );
    save_user_vtxos(shared.persistence.as_ref(), &user_id_hex, &state.vtxos);

    let sent_amount = spent_total.saturating_sub(change_amount);
    state.ark_tx_history.push(ArkTxEntry {
        tx_type: "send".into(),
        amount_sats: -(sent_amount as i64),
        txid: ark_txid.clone(),
        timestamp: now_secs(),
    });
    save_user_ark_history(
        shared.persistence.as_ref(),
        &user_id_hex,
        &state.ark_tx_history,
    );

    // Hand back every output as (scriptPubKey hex, sats) so the caller can recognise a payment
    // that settles an outstanding request — this path never says which request it pays.
    let paid_outputs: Vec<(String, u64)> = signed_ark_psbt
        .unsigned_tx
        .output
        .iter()
        .map(|o| (hex::encode(o.script_pubkey.as_bytes()), o.value.to_sat()))
        .collect();

    Ok((
        SubmitArkSendResponse {
            ark_txid,
            change_txid,
            change_vout,
            change_amount,
        },
        paid_outputs,
    ))
        })
        .await
    }
}
