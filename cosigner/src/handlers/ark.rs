//! Simple Ark RPCs (info, address derivation, balance/list).
//! Heavier ones (settle/send/redeem) live in their own module.


use tokio::runtime::Handle;
use tonic::Status;

use crate::cosigner::Cosigner;
use crate::handlers::parsers;
use crate::store::run_blocking;
use crate::state::CosignerState;
use crate::shared::SharedServices;
use crate::wallet_proto::*;

use super::helpers::{get_user_xonly_pubkey, save_user_vtxos};

/// Fetch ASP info (sync wrapper). Caches on the ASP client itself.
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

impl Cosigner {
    pub async fn get_ark_info(
        &mut self,
        req: GetArkInfoRequest,
    ) -> Result<GetArkInfoResponse, Status> {
        let shared = self.shared.clone();
        let span = tracing::info_span!("actor::get_ark_info", user_id = %parsers::user_id_hex(&req.user_id));
        run_blocking(self.state.clone(), move |_state| {
            let _enter = span.enter();
            let shared = shared.as_ref();
            let user_id_hex = parsers::user_id_hex(&req.user_id);
            tracing::info!("[{user_id_hex}] GetArkInfo");
            // Auth (OP_GET_ARK_INFO) ran at the REST boundary.
            let asp = shared.asp_client.clone();
            let info = fetch_asp_info(&asp)?;
            Ok(GetArkInfoResponse {
                signer_pubkey: info.signer_pubkey,
                forfeit_pubkey: info.forfeit_pubkey,
                network: info.network,
                session_duration: info.session_duration,
                unilateral_exit_delay: info.unilateral_exit_delay,
                boarding_exit_delay: info.boarding_exit_delay,
                vtxo_min_amount: info.vtxo_min_amount,
                dust: info.dust,
                checkpoint_tapscript: info.checkpoint_tapscript,
                forfeit_address: info.forfeit_address,
                auto_settle_safety_margin_secs: shared.auto_settle_safety_margin_secs,
            })
        })
        .await
    }
}

/// Drop cached VTXOs the ASP says are already spent.
///
/// The cache is otherwise only maintained by the `IndexerUpdate` push subscription; if that misses
/// an event it keeps listing spent VTXOs, they get picked as send inputs, and every send dies with
/// `VTXO_ALREADY_SPENT` forever.
///
/// Deliberately narrow, because two wider versions broke the Ark e2e:
///   * rebuilding the list from the ASP RESURRECTED just-spent VTXOs (the indexer lags a fresh
///     send, so it still lists them as spendable) — undoing the local post-send update;
///   * pruning against a SCRIPT query wiped the whole wallet when the derived scripts didn't match
///     the ones the VTXOs actually sit under.
/// So: query by the outpoints we already hold (no derivation to get wrong), and remove only on an
/// explicit `is_spent`/`is_swept`/`is_unrolled`. Silence is never treated as evidence, and nothing
/// is ever added.
fn drop_spent_vtxos(state: &mut CosignerState, shared: &SharedServices, user_id_hex: &str) {
    if state.vtxos.is_empty() {
        return;
    }
    let outpoints: Vec<String> = state
        .vtxos
        .iter()
        .map(|e| format!("{}:{}", e.txid, e.vout))
        .collect();

    let asp = shared.asp_client.clone();
    let queried = Handle::current().block_on(async move {
        let mut guard = asp.lock().await;
        guard.get_vtxos_by_outpoints(&outpoints).await
    });
    let reported = match queried {
        Ok(v) => v,
        Err(e) => {
            tracing::warn!("[{user_id_hex}] spent-VTXO check: indexer query failed: {e}");
            return;
        }
    };

    let spent: std::collections::HashSet<(String, u32)> = reported
        .into_iter()
        .filter(|v| v.is_spent || v.is_swept || v.is_unrolled)
        .filter_map(|v| v.outpoint.map(|o| (o.txid, o.vout)))
        .collect();
    if spent.is_empty() {
        return;
    }

    let before = state.vtxos.len();
    state
        .vtxos
        .retain(|e| !spent.contains(&(e.txid.clone(), e.vout)));
    if state.vtxos.len() != before {
        tracing::info!(
            "[{user_id_hex}] dropped {} spent VTXO(s) the stream had missed",
            before - state.vtxos.len()
        );
        save_user_vtxos(shared.persistence.as_ref(), user_id_hex, &state.vtxos);
    }
}

impl Cosigner {
    pub async fn get_ark_address(
        &mut self,
        req: GetArkAddressRequest,
    ) -> Result<GetArkAddressResponse, Status> {
        let shared = self.shared.clone();
        let span = tracing::info_span!("actor::get_ark_address", user_id = %parsers::user_id_hex(&req.user_id));
        run_blocking(self.state.clone(), move |state| {
            let _enter = span.enter();
            let shared = shared.as_ref();
            let user_id_hex = parsers::user_id_hex(&req.user_id);
            tracing::info!("[{user_id_hex}] GetArkAddress");
            // Auth (OP_GET_ARK_ADDRESS) ran at the REST boundary.
            let asp = shared.asp_client.clone();
            let info = fetch_asp_info(&asp)?;

            let owner_pk_hex =
                get_user_xonly_pubkey(state, shared.persistence.as_ref(), &user_id_hex)?;

            let network = ark::client::parse_network(&info.network).map_err(Status::internal)?;
            let exit_delay = info.unilateral_exit_delay as u32;
            let ark_addr =
                ark::client::ark_address(&owner_pk_hex, &info.signer_pubkey, exit_delay, network)
                    .map_err(|e| Status::internal(format!("ark_address: {e}")))?;


            Ok(GetArkAddressResponse {
                ark_address: ark_addr,
            })
        })
        .await
    }
}

impl Cosigner {
    pub async fn get_boarding_address(
        &mut self,
        req: GetBoardingAddressRequest,
    ) -> Result<GetBoardingAddressResponse, Status> {
        let shared = self.shared.clone();
        let span = tracing::info_span!("actor::get_boarding_address", user_id = %parsers::user_id_hex(&req.user_id));
        run_blocking(self.state.clone(), move |state| {
            let _enter = span.enter();
            let shared = shared.as_ref();
            let user_id_hex = parsers::user_id_hex(&req.user_id);
            tracing::info!("[{user_id_hex}] GetBoardingAddress");
            // Auth (OP_GET_BOARDING_ADDRESS) ran at the REST boundary.
            let asp = shared.asp_client.clone();
            let info = fetch_asp_info(&asp)?;
            let owner_pk_hex =
                get_user_xonly_pubkey(state, shared.persistence.as_ref(), &user_id_hex)?;
            let network = ark::client::parse_network(&info.network).map_err(Status::internal)?;
            let exit_delay = info.boarding_exit_delay as u32;
            let boarding_addr = ark::client::boarding_address(
                &owner_pk_hex,
                &info.signer_pubkey,
                exit_delay,
                network,
            )
            .map_err(|e| Status::internal(format!("boarding_address: {e}")))?;
            super::helpers::save_user_boarding_address(
                shared.persistence.as_ref(),
                &user_id_hex,
                &boarding_addr,
            );
            Ok(GetBoardingAddressResponse {
                boarding_address: boarding_addr,
            })
        })
        .await
    }
}

impl Cosigner {
    pub async fn list_vtxos(
        &mut self,
        req: ListVtxosRequest,
    ) -> Result<ListVtxosResponse, Status> {
        let shared = self.shared.clone();
        let span =
            tracing::info_span!("actor::list_vtxos", user_id = %parsers::user_id_hex(&req.user_id));
        run_blocking(self.state.clone(), move |state| {
            let _enter = span.enter();
            let shared = shared.as_ref();
            let user_id_hex = parsers::user_id_hex(&req.user_id);
            // Auth (OP_LIST_VTXOS) ran at the REST boundary.
            let asp = shared.asp_client.clone();
            let info = fetch_asp_info(&asp)?;
            let network = ark::client::parse_network(&info.network).map_err(Status::internal)?;

            let owner_pk_hex =
                get_user_xonly_pubkey(state, shared.persistence.as_ref(), &user_id_hex)?;

            // Clients pick send inputs from this list, so spent entries must not survive it.
            drop_spent_vtxos(state, shared, &user_id_hex);

            let mut vtxos = Vec::new();
            let mut total_balance: u64 = 0;
            for entry in state.vtxos.iter() {
                let script = ark::client::vtxo_script_pubkey_hex(
                    &owner_pk_hex,
                    &info.signer_pubkey,
                    entry.exit_delay,
                    network,
                )
                .unwrap_or_default();
                total_balance += entry.amount;
                vtxos.push(VtxoInfo {
                    txid: entry.txid.clone(),
                    vout: entry.vout,
                    amount: entry.amount,
                    created_at: entry.created_at,
                    expires_at: entry.expires_at,
                    status: "confirmed".to_string(),
                    is_preconfirmed: false,
                    exit_delay: entry.exit_delay,
                    script,
                });
            }
            // Plan A Phase 2: a delegate is "active" if the guest holds a pending one (its `fire at`
            // threshold is set — restored from the secret-free marker on spawn) OR the legacy host session
            // is loaded. The guest path is the live one; the host `delegate_session` is the dead legacy.
            let has_active_delegate =
                state.guest_delegate_threshold.is_some() || state.delegate_session.is_some();
            tracing::info!(
                "[{user_id_hex}] ListVtxos: returning {} vtxos, balance={total_balance}, has_active_delegate={has_active_delegate}",
                vtxos.len()
            );
            Ok(ListVtxosResponse {
                vtxos,
                total_balance,
                has_active_delegate,
            })
        })
        .await
    }
}

impl Cosigner {
    pub async fn list_ark_transactions(
        &mut self,
        req: ListArkTransactionsRequest,
    ) -> Result<ListArkTransactionsResponse, Status> {
        let span = tracing::info_span!("actor::list_ark_transactions", user_id = %parsers::user_id_hex(&req.user_id));
        run_blocking(self.state.clone(), move |state| {
            let _enter = span.enter();
            let _user_id_hex = parsers::user_id_hex(&req.user_id);
            // Auth (OP_LIST_ARK_TXS) ran at the REST boundary.
            let transactions = state
                .ark_tx_history
                .iter()
                .map(|e| ArkTransactionSummary {
                    tx_type: e.tx_type.clone(),
                    amount_sats: e.amount_sats,
                    txid: e.txid.clone(),
                    timestamp: e.timestamp,
                })
                .collect();
            Ok(ListArkTransactionsResponse { transactions })
        })
        .await
    }
}
