//! Auto-settle tick handler. Driven from a global 60-second task in main.rs
//! that fans out `CosignerCommand::TickAutoSettle` to every spawned actor.
//!
//! The actor wakes here, checks its stored `DelegateRecord`, and submits the
//! signed intent into the next ASP batch when the earliest covered VTXO's
//! `expires_at` falls within `auto_settle_safety_margin_secs` of now.

use tokio::runtime::Handle;
use tonic::Status;

use crate::cosigner::actor::CosignerActor;
use crate::cosigner::store::run_blocking;
use crate::cosigner::state::VtxoEntry;
use crate::cosigner::types::ArkTxEntry;

use super::helpers::{now_secs, save_user_ark_history, save_user_vtxos};

/// Per-actor tick. No-ops when there is nothing to do.
impl CosignerActor {
    pub async fn tick_auto_settle(&mut self) -> Result<(), Status> {
        let shared = self.shared.clone();
        run_blocking(self.state.clone(), move |state| {
    let shared = shared.as_ref();
    let Some(record) = state.delegate_session.as_ref() else {
        return Ok(());
    };
    // Resolve `earliest_expires_at` against current state: the value stored
    // on the record at Phase 1 time may be 0 if the vtxo_stream backfill
    // hadn't landed yet. If state.vtxos now has a non-zero timestamp for
    // any covered outpoint, use that. Outpoints missing from state.vtxos
    // mean the VTXO has been spent — the invalidation hooks should have
    // cleared the delegate, but if we see it here we skip to be safe.
    let effective_expiry = if record.earliest_expires_at > 0 {
        record.earliest_expires_at
    } else {
        record
            .covered_outpoints
            .iter()
            .filter_map(|(t, v)| {
                state
                    .vtxos
                    .iter()
                    .find(|e| &e.txid == t && e.vout == *v)
                    .and_then(|e| {
                        if e.expires_at > 0 {
                            Some(e.expires_at)
                        } else {
                            None
                        }
                    })
            })
            .min()
            .unwrap_or(0)
    };
    if effective_expiry == 0 {
        return Ok(());
    }
    let now = now_secs();
    let threshold = effective_expiry.saturating_sub(shared.auto_settle_safety_margin_secs);
    if now < threshold {
        return Ok(());
    }

    let asp = shared.asp_client.clone();

    let record = state.delegate_session.take().expect("checked above");
    tracing::info!(
        "auto-settle: driving stored intent for {} VTXO(s), effective_expiry={} now={}",
        record.covered_outpoints.len(),
        effective_expiry,
        now
    );
    // The in-memory record is gone; the sled row must follow whether the
    // drive succeeds or fails (failure → client re-delegates next refresh).
    let user_id_hex = state.cosigner_id.clone();
    super::helpers::delete_user_delegate(shared.persistence.as_ref(), &user_id_hex);

    let mut session = record.session;
    let outcome = Handle::current().block_on(async move {
        let mut guard = asp.lock().await;
        let (commitment_txid, vtxo_outpoint) = session
            .settle(&mut *guard)
            .await
            .map_err(|e| Status::internal(format!("auto-settle: {e}")))?;
        let info = match &guard.info {
            Some(i) => i.clone(),
            None => guard
                .get_info()
                .await
                .map_err(|e| Status::internal(format!("get_info: {e}")))?,
        };
        Ok::<_, Status>((commitment_txid, vtxo_outpoint, info))
    });

    let (commitment_txid, vtxo_outpoint, info) = match outcome {
        Ok(v) => v,
        Err(e) => {
            tracing::warn!(
                "auto-settle drive failed: {e}; clearing stored intent so client can re-delegate"
            );
            return Ok(());
        }
    };

    let (vtxo_txid, vtxo_vout) = vtxo_outpoint.unwrap_or_else(|| (commitment_txid.clone(), 0));
    let total_amount: u64 = state.vtxos.iter().map(|e| e.amount).sum();
    state.vtxos.clear();
    let new_exit_delay = info.unilateral_exit_delay as u32;
    state.vtxos.push(VtxoEntry {
        txid: vtxo_txid.clone(),
        vout: vtxo_vout,
        amount: total_amount,
        exit_delay: new_exit_delay,
        created_at: now_secs(),
        expires_at: 0,
    });
    state.ark_tx_history.push(ArkTxEntry {
        tx_type: "settle".into(),
        amount_sats: total_amount as i64,
        txid: vtxo_txid.clone(),
        timestamp: now_secs(),
    });
    save_user_vtxos(shared.persistence.as_ref(), &user_id_hex, &state.vtxos);
    save_user_ark_history(
        shared.persistence.as_ref(),
        &user_id_hex,
        &state.ark_tx_history,
    );
    tracing::info!(
        "[{user_id_hex}] auto-settle: settled, new VTXO {vtxo_txid}:{vtxo_vout} amount={total_amount} commitment={commitment_txid}"
    );
    Ok(())
        })
        .await
    }
}
