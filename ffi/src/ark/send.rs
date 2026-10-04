//! FFI functions for client-side Ark off-chain send building.
//!
//! Replicates the logic from `ark/src/client/send.rs` (SendSession) but
//! without async dependencies, suitable for FFI from Dart.

use std::collections::HashMap;
use std::str::FromStr;
use std::sync::Mutex;

use ark_core::send::{self, OffchainTransactions, VtxoInput};
use ark_core::server;

use bitcoin::base64::{self, Engine};
use bitcoin::hashes::Hash;
use bitcoin::key::Secp256k1;
use bitcoin::sighash::{Prevouts, SighashCache};
use bitcoin::taproot::{self};
use bitcoin::{
    Amount, Network, OutPoint, Psbt, ScriptBuf, TapLeafHash, TapSighashType, TxOut,
    XOnlyPublicKey,
};

use serde::{Deserialize, Serialize};

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

#[derive(Deserialize)]
pub struct BuildSendParams {
    pub owner_pk: String,
    pub vtxo_inputs: Vec<VtxoInputParam>,
    pub recipient_ark_address: String,
    pub amount: u64,
    pub change_ark_address: Option<String>,
    pub exit_delay: u32,
    pub ark_info: ArkInfoParam,
}

#[derive(Deserialize)]
pub struct VtxoInputParam {
    pub txid: String,
    pub vout: u32,
    pub amount: u64,
    /// This VTXO's own exit delay. Per-input because a wallet holds a mix
    /// (a boarded VTXO keeps the boarding delay; received/refreshed ones use
    /// the unilateral delay). Absent => the top-level `exit_delay`.
    #[serde(default)]
    pub exit_delay: Option<u32>,
    /// Present => this input is a contract eVTXO spent via its cooperative
    /// (`ConditionMultisigClosure`) leaf, signed by V′ and gated by the cosigner.
    #[serde(default)]
    pub evtxo: Option<EvtxoSpendInfoParam>,
}

#[derive(Deserialize)]
pub struct EvtxoSpendInfoParam {
    pub contract_id: String, // 32-byte hex; commit = sha256(contract_id)
    pub server_pk: String,   // x-only hex (ASP signer)
    pub evtxo_pk: String,    // x-only hex (V′, the 2-of-2 {wallet,cosigner} key)
    pub owner_pk: String,    // x-only hex (V, keys the exit leaf)
    pub exit_delay: u32,
    /// Hex of the opaque contract args for the gate (PSBT `EVTXO/0x01` proprietary).
    #[serde(default)]
    pub contract_args: Option<String>,
}

#[derive(Deserialize)]
pub struct ArkInfoParam {
    pub signer_pubkey: String,
    pub forfeit_pubkey: String,
    pub forfeit_address: String,
    pub checkpoint_tapscript: String,
    pub network: String,
    pub session_duration: i64,
    pub unilateral_exit_delay: i64,
    pub boarding_exit_delay: i64,
    pub vtxo_min_amount: i64,
    pub dust: i64,
}

#[derive(Serialize)]
pub struct BuildSendResult {
    pub handle: u64,
    pub sighashes: Vec<String>,
    pub ark_tx_bytes: String,
    /// PSBT (hex) to pass as `fullTransaction` to the cosigner's sign so the
    /// contract gate fires and V′ is selected. When the spend has an eVTXO input
    /// this is the checkpoint PSBT (whose input 0 `witness_utxo` is the eVTXO
    /// spk); otherwise it equals `ark_tx_bytes` (normal sends are unaffected).
    pub gate_tx_bytes: String,
}

#[derive(Serialize)]
pub struct InsertSigsResult {
    pub signed_ark_tx_b64: String,
    pub signed_checkpoint_txs_b64: Vec<String>,
}

#[derive(Serialize)]
pub struct ChangeVtxoResult {
    pub txid: String,
    pub vout: u32,
    pub amount: u64,
}

enum SighashTarget {
    ArkTx(usize),
    Checkpoint(usize),
}

struct SighashEntry {
    target: SighashTarget,
    leaf_hash: TapLeafHash,
    /// The x-only key whose `tap_script_sigs` slot this signature fills — the
    /// VTXO owner key V for normal inputs, or V′ for an eVTXO input.
    signer_pk: XOnlyPublicKey,
}

pub struct SendState {
    ark_tx: Psbt,
    checkpoint_txs: Vec<Psbt>,
    sighash_entries: Vec<SighashEntry>,
}

// ---------------------------------------------------------------------------
// Global session store
// ---------------------------------------------------------------------------

static SESSIONS: Mutex<Option<HashMap<u64, SendState>>> = Mutex::new(None);
static NEXT_HANDLE: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(1);

fn get_sessions() -> std::sync::MutexGuard<'static, Option<HashMap<u64, SendState>>> {
    let mut guard = SESSIONS.lock().unwrap();
    if guard.is_none() {
        *guard = Some(HashMap::new());
    }
    guard
}

// ---------------------------------------------------------------------------
// Build
// ---------------------------------------------------------------------------

pub fn build_send_tx(params_json: &str) -> Result<String, String> {
    let params: BuildSendParams =
        serde_json::from_str(params_json).map_err(|e| format!("JSON parse: {e}"))?;

    let secp = Secp256k1::new();
    let network = parse_network(&params.ark_info.network)?;
    let owner_pk = parse_xonly(&params.owner_pk)?;
    let asp_pk = parse_xonly(&params.ark_info.signer_pubkey)?;

    let exit_seq = server::parse_sequence_number(params.exit_delay as i64)
        .map_err(|e| format!("invalid exit_delay: {e}"))?;

    // Fallback reconstruction (top-level delay) — kept for the change-address
    // default; inputs each rebuild with their OWN delay below.
    let vtxo = ark_core::Vtxo::new_default(&secp, asp_pk, owner_pk, exit_seq, network)
        .map_err(|e| format!("Vtxo::new_default: {e}"))?;

    // Reconstruct spend info per DISTINCT input delay — each VTXO's script
    // embeds its own delay, so one template can't serve a mixed set.
    let mut vtxo_by_delay: HashMap<u32, ark_core::Vtxo> = HashMap::new();
    for vi in &params.vtxo_inputs {
        if vi.evtxo.is_some() {
            continue;
        }
        let delay = vi.exit_delay.unwrap_or(params.exit_delay);
        if let std::collections::hash_map::Entry::Vacant(slot) = vtxo_by_delay.entry(delay) {
            let seq = server::parse_sequence_number(delay as i64)
                .map_err(|e| format!("invalid exit_delay: {e}"))?;
            let v = ark_core::Vtxo::new_default(&secp, asp_pk, owner_pk, seq, network)
                .map_err(|e| format!("Vtxo::new_default: {e}"))?;
            slot.insert(v);
        }
    }

    // Build VtxoInputs. Each input is either a normal VTXO (default forfeit leaf,
    // signed by the owner key V) or a contract eVTXO spent via its cooperative
    // `ConditionMultisigClosure` leaf (signed by V′, gated by the cosigner).
    let mut send_inputs: Vec<VtxoInput> = Vec::with_capacity(params.vtxo_inputs.len());
    let mut signer_pks: Vec<XOnlyPublicKey> = Vec::with_capacity(params.vtxo_inputs.len());
    // (input index, contract_id, optional gate args) — attached to PSBTs post-build.
    let mut evtxo_inputs: Vec<(usize, [u8; 32], Option<Vec<u8>>)> = Vec::new();

    for (i, vi) in params.vtxo_inputs.iter().enumerate() {
        let outpoint = OutPoint {
            txid: vi.txid.parse().map_err(|e| format!("invalid txid: {e}"))?,
            vout: vi.vout,
        };
        match vi.evtxo.as_ref() {
            Some(e) => {
                let contract_id = crate::from_hex::<[u8; 32]>(&e.contract_id)?;
                let server = crate::from_hex::<[u8; 32]>(&e.server_pk)?;
                let evtxo_pk = crate::from_hex::<[u8; 32]>(&e.evtxo_pk)?;
                let owner = crate::from_hex::<[u8; 32]>(&e.owner_pk)?;
                let commit: [u8; 32] =
                    bitcoin::hashes::sha256::Hash::hash(&contract_id).to_byte_array();
                let (coop_script, th_cb) = ark::evtxo_cooperative_spend_info(
                    &commit, &server, &evtxo_pk, &owner, e.exit_delay,
                )
                .ok_or("evtxo_cooperative_spend_info failed")?;
                let spk =
                    ark::evtxo_script_pubkey(&commit, &server, &evtxo_pk, &owner, e.exit_delay)
                        .map_err(|err| format!("evtxo_script_pubkey: {err:?}"))?;
                // ark's ControlBlock -> bitcoin's via its serialized form.
                let cb = taproot::ControlBlock::decode(&th_cb.serialize())
                    .map_err(|err| format!("control block decode: {err}"))?;
                let tapscripts = vec![
                    ScriptBuf::from_bytes(coop_script.clone()),
                    ScriptBuf::from_bytes(ark::evtxo_exit_script(e.exit_delay, &owner)),
                ];
                send_inputs.push(VtxoInput::new(
                    ScriptBuf::from_bytes(coop_script),
                    None,
                    cb,
                    tapscripts,
                    ScriptBuf::from_bytes(spk.to_vec()),
                    Amount::from_sat(vi.amount),
                    outpoint,
                    Vec::new(),
                ));
                signer_pks.push(
                    XOnlyPublicKey::from_slice(&evtxo_pk)
                        .map_err(|err| format!("invalid evtxo_pk: {err}"))?,
                );
                let args = match e.contract_args.as_deref() {
                    Some(a) if !a.is_empty() => Some(crate::from_hex::<Vec<u8>>(a)?),
                    _ => None,
                };
                evtxo_inputs.push((i, contract_id, args));
            }
            None => {
                let delay = vi.exit_delay.unwrap_or(params.exit_delay);
                let input_vtxo = &vtxo_by_delay[&delay];
                let (spend_script, control_block) = input_vtxo
                    .forfeit_spend_info()
                    .map_err(|e| format!("forfeit_spend_info: {e}"))?;
                send_inputs.push(VtxoInput::new(
                    spend_script,
                    None,
                    control_block,
                    input_vtxo.tapscripts(),
                    input_vtxo.script_pubkey(),
                    Amount::from_sat(vi.amount),
                    outpoint,
                    Vec::new(), // assets — none (ark-core 0.9)
                ));
                signer_pks.push(owner_pk);
            }
        }
    }

    // Parse addresses
    let recipient: ark_core::ArkAddress = params
        .recipient_ark_address
        .parse()
        .map_err(|e| format!("invalid recipient: {e}"))?;
    // ark-core 0.9: SendReceiver instead of (&addr, amount) tuples.
    let receivers = vec![send::SendReceiver::bitcoin(
        recipient,
        Amount::from_sat(params.amount),
    )];

    // 0.9 requires a change address (only emits change when there's leftover).
    // Default to the sender's own ark address when none is provided.
    let change_addr: ark_core::ArkAddress = match params.change_ark_address.as_deref() {
        Some(a) => a.parse().map_err(|e| format!("invalid change addr: {e}"))?,
        None => vtxo.to_ark_address(),
    };

    // Build server::Info
    let server_info = build_server_info(&params.ark_info, network)?;

    // Build transactions
    let OffchainTransactions {
        mut ark_tx,
        mut checkpoint_txs,
    } = send::build_offchain_transactions(&receivers, &change_addr, &send_inputs, &server_info)
        .map_err(|e| format!("build_offchain_transactions: {e}"))?;

    // Attach the condition preimage (contract_id) on both the checkpoint input and
    // the ark_tx input (each reveals the cooperative leaf), plus the gate's args.
    for (i, contract_id, args) in &evtxo_inputs {
        let cond = encode_condition(&[contract_id.to_vec()]);
        let cond_key = bitcoin::psbt::raw::Key {
            type_value: 222,
            key: ark_core::VTXO_CONDITION_KEY.to_vec(),
        };
        checkpoint_txs[*i].inputs[0]
            .unknown
            .insert(cond_key.clone(), cond.clone());
        ark_tx.inputs[*i].unknown.insert(cond_key, cond);
        if let Some(args) = args {
            checkpoint_txs[*i].inputs[0].proprietary.insert(
                bitcoin::psbt::raw::ProprietaryKey {
                    prefix: b"EVTXO".to_vec(),
                    subtype: 0x01,
                    key: Vec::new(),
                },
                args.clone(),
            );
        }
    }

    // Compute sighashes (per-input signer key threaded for tap_script_sigs).
    let mut sighashes = Vec::new();
    let mut sighash_entries = Vec::new();

    collect_ark_tx_sighashes(&ark_tx, &signer_pks, &mut sighashes, &mut sighash_entries)?;
    for (ci, cp_psbt) in checkpoint_txs.iter().enumerate() {
        collect_checkpoint_sighash(cp_psbt, ci, &signer_pks, &mut sighashes, &mut sighash_entries)?;
    }

    // Serialize ark_tx (after attaching condition fields) for fullTransaction passthrough.
    let ark_tx_bytes_hex = hex::encode(ark_tx.serialize());
    // The gate fires on the PSBT whose input carries the eVTXO witness_utxo — the
    // checkpoint. Fall back to the ark tx for normal (non-eVTXO) sends.
    let gate_tx_bytes_hex = match evtxo_inputs.first() {
        Some((i, _, _)) => hex::encode(checkpoint_txs[*i].serialize()),
        None => ark_tx_bytes_hex.clone(),
    };

    // Store session
    let handle = NEXT_HANDLE.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    let state = SendState {
        ark_tx,
        checkpoint_txs,
        sighash_entries,
    };
    get_sessions().as_mut().unwrap().insert(handle, state);

    let result = BuildSendResult {
        handle,
        sighashes: sighashes.iter().map(|s| hex::encode(s)).collect(),
        ark_tx_bytes: ark_tx_bytes_hex,
        gate_tx_bytes: gate_tx_bytes_hex,
    };
    serde_json::to_string(&result).map_err(|e| format!("JSON serialize: {e}"))
}

/// Encode condition-witness elements in ark-core's PSBT `condition` field format
/// (compact-size count, then each element length-prefixed). For our cooperative
/// leaf the single element is the 32-byte `contract_id` preimage.
fn encode_condition(elements: &[Vec<u8>]) -> Vec<u8> {
    fn write_compact(out: &mut Vec<u8>, n: u64) {
        if n < 0xfd {
            out.push(n as u8);
        } else if n <= 0xffff {
            out.push(0xfd);
            out.extend_from_slice(&(n as u16).to_le_bytes());
        } else if n <= 0xffff_ffff {
            out.push(0xfe);
            out.extend_from_slice(&(n as u32).to_le_bytes());
        } else {
            out.push(0xff);
            out.extend_from_slice(&n.to_le_bytes());
        }
    }
    let mut out = Vec::new();
    write_compact(&mut out, elements.len() as u64);
    for e in elements {
        write_compact(&mut out, e.len() as u64);
        out.extend_from_slice(e);
    }
    out
}

// ---------------------------------------------------------------------------
// Insert signatures
// ---------------------------------------------------------------------------

pub fn insert_send_signatures(handle: u64, signatures_json: &str) -> Result<String, String> {
    let sig_hexes: Vec<String> =
        serde_json::from_str(signatures_json).map_err(|e| format!("JSON parse: {e}"))?;

    let mut sessions = get_sessions();
    let state = sessions
        .as_mut()
        .unwrap()
        .get_mut(&handle)
        .ok_or("invalid session handle")?;

    if sig_hexes.len() != state.sighash_entries.len() {
        return Err(format!(
            "expected {} sigs, got {}",
            state.sighash_entries.len(),
            sig_hexes.len()
        ));
    }

    // Parse and insert signatures
    for (hex_sig, entry) in sig_hexes.iter().zip(state.sighash_entries.iter()) {
        let sig_bytes = crate::from_hex::<Vec<u8>>(hex_sig)?;
        if sig_bytes.len() != 64 {
            return Err(format!("expected 64-byte sig, got {}", sig_bytes.len()));
        }
        let schnorr_sig = bitcoin::secp256k1::schnorr::Signature::from_slice(&sig_bytes)
            .map_err(|e| format!("invalid schnorr sig: {e}"))?;

        let sig = taproot::Signature {
            signature: schnorr_sig,
            sighash_type: TapSighashType::Default,
        };

        match &entry.target {
            SighashTarget::ArkTx(input_idx) => {
                if *input_idx >= state.ark_tx.inputs.len() {
                    return Err(format!("ark tx input index {} out of bounds (len={})", input_idx, state.ark_tx.inputs.len()));
                }
                state.ark_tx.inputs[*input_idx].tap_script_sigs
                    .insert((entry.signer_pk, entry.leaf_hash), sig);
            }
            SighashTarget::Checkpoint(cp_idx) => {
                if *cp_idx >= state.checkpoint_txs.len() {
                    return Err(format!("checkpoint index {} out of bounds (len={})", cp_idx, state.checkpoint_txs.len()));
                }
                if state.checkpoint_txs[*cp_idx].inputs.is_empty() {
                    return Err(format!("checkpoint {} has no inputs", cp_idx));
                }
                state.checkpoint_txs[*cp_idx].inputs[0].tap_script_sigs
                    .insert((entry.signer_pk, entry.leaf_hash), sig);
            }
        }
    }

    // Encode results as base64
    let b64 = base64::engine::general_purpose::STANDARD;
    let signed_ark_tx_b64 = b64.encode(state.ark_tx.serialize());
    let signed_checkpoint_txs_b64: Vec<String> = state
        .checkpoint_txs
        .iter()
        .map(|cp| b64.encode(cp.serialize()))
        .collect();

    let result = InsertSigsResult {
        signed_ark_tx_b64,
        signed_checkpoint_txs_b64,
    };
    serde_json::to_string(&result).map_err(|e| format!("JSON serialize: {e}"))
}

// ---------------------------------------------------------------------------
// Change VTXO
// ---------------------------------------------------------------------------

pub fn get_change_vtxo(handle: u64) -> Result<String, String> {
    let sessions = get_sessions();
    let state = sessions
        .as_ref()
        .unwrap()
        .get(&handle)
        .ok_or("invalid session handle")?;

    let outputs = &state.ark_tx.unsigned_tx.output;
    if outputs.len() < 3 {
        return Ok("null".to_string());
    }
    let txid = state.ark_tx.unsigned_tx.compute_txid().to_string();
    let change_idx = outputs.len() - 2;
    let amount = outputs[change_idx].value.to_sat();
    if amount == 0 {
        return Ok("null".to_string());
    }

    let result = ChangeVtxoResult {
        txid,
        vout: change_idx as u32,
        amount,
    };
    serde_json::to_string(&result).map_err(|e| format!("JSON serialize: {e}"))
}

// ---------------------------------------------------------------------------
// Free session
// ---------------------------------------------------------------------------

pub fn free_send_session(handle: u64) {
    if let Ok(mut sessions) = SESSIONS.lock() {
        if let Some(map) = sessions.as_mut() {
            map.remove(&handle);
        }
    }
}

// ---------------------------------------------------------------------------
// Helpers (replicated from ark/src/client/send.rs)
// ---------------------------------------------------------------------------

fn collect_ark_tx_sighashes(
    psbt: &Psbt,
    signer_pks: &[XOnlyPublicKey],
    sighashes: &mut Vec<[u8; 32]>,
    entries: &mut Vec<SighashEntry>,
) -> Result<(), String> {
    let prevouts: Vec<TxOut> = psbt
        .inputs
        .iter()
        .map(|i| {
            i.witness_utxo
                .clone()
                .ok_or("missing witness_utxo in ark tx input".to_string())
        })
        .collect::<Result<Vec<_>, _>>()?;

    let mut cache = SighashCache::new(&psbt.unsigned_tx);

    for (idx, input) in psbt.inputs.iter().enumerate() {
        let leaf_hash = input
            .tap_script_sigs
            .keys()
            .next()
            .map(|(_, lh)| *lh)
            .or_else(|| {
                input
                    .tap_scripts
                    .values()
                    .next()
                    .map(|(script, ver)| TapLeafHash::from_script(script, *ver))
            })
            .ok_or_else(|| format!("no leaf hash for ark tx input {idx}"))?;

        let hash = cache
            .taproot_script_spend_signature_hash(
                idx,
                &Prevouts::All(&prevouts),
                leaf_hash,
                TapSighashType::Default,
            )
            .map_err(|e| format!("sighash for ark tx input {idx}: {e}"))?;

        sighashes.push(hash.to_byte_array());
        entries.push(SighashEntry {
            target: SighashTarget::ArkTx(idx),
            leaf_hash,
            signer_pk: *signer_pks
                .get(idx)
                .ok_or_else(|| format!("no signer_pk for ark tx input {idx}"))?,
        });
    }
    Ok(())
}

fn collect_checkpoint_sighash(
    psbt: &Psbt,
    checkpoint_idx: usize,
    signer_pks: &[XOnlyPublicKey],
    sighashes: &mut Vec<[u8; 32]>,
    entries: &mut Vec<SighashEntry>,
) -> Result<(), String> {
    let prevout = psbt.inputs[0]
        .witness_utxo
        .clone()
        .ok_or("missing witness_utxo in checkpoint input")?;

    let leaf_hash = psbt.inputs[0]
        .tap_script_sigs
        .keys()
        .next()
        .map(|(_, lh)| *lh)
        .or_else(|| {
            psbt.inputs[0]
                .tap_scripts
                .values()
                .next()
                .map(|(script, ver)| TapLeafHash::from_script(script, *ver))
        })
        .ok_or_else(|| format!("no leaf hash for checkpoint {checkpoint_idx}"))?;

    let mut cache = SighashCache::new(&psbt.unsigned_tx);
    let hash = cache
        .taproot_script_spend_signature_hash(
            0,
            &Prevouts::All(&[prevout]),
            leaf_hash,
            TapSighashType::Default,
        )
        .map_err(|e| format!("sighash for checkpoint {checkpoint_idx}: {e}"))?;

    sighashes.push(hash.to_byte_array());
    entries.push(SighashEntry {
        target: SighashTarget::Checkpoint(checkpoint_idx),
        leaf_hash,
        signer_pk: *signer_pks
            .get(checkpoint_idx)
            .ok_or_else(|| format!("no signer_pk for checkpoint {checkpoint_idx}"))?,
    });
    Ok(())
}

fn build_server_info(info: &ArkInfoParam, network: Network) -> Result<server::Info, String> {
    let signer_pk_hex = if info.signer_pubkey.len() == 64 {
        format!("02{}", info.signer_pubkey)
    } else {
        info.signer_pubkey.clone()
    };
    let signer_pk = bitcoin::secp256k1::PublicKey::from_slice(&crate::from_hex::<Vec<u8>>(&signer_pk_hex)?)
        .map_err(|e| format!("invalid signer_pubkey: {e}"))?;

    let forfeit_pk_hex = if info.forfeit_pubkey.len() == 64 {
        format!("02{}", info.forfeit_pubkey)
    } else {
        info.forfeit_pubkey.clone()
    };
    let forfeit_pk = bitcoin::secp256k1::PublicKey::from_slice(&crate::from_hex::<Vec<u8>>(&forfeit_pk_hex)?)
        .map_err(|e| format!("invalid forfeit_pubkey: {e}"))?;

    let forfeit_address: bitcoin::Address<bitcoin::address::NetworkUnchecked> = info
        .forfeit_address
        .parse()
        .map_err(|e| format!("invalid forfeit_address: {e}"))?;
    let forfeit_address = forfeit_address
        .require_network(network)
        .map_err(|e| format!("forfeit_address network mismatch: {e}"))?;

    let checkpoint_tapscript = ScriptBuf::from_bytes(crate::from_hex::<Vec<u8>>(&info.checkpoint_tapscript)?);

    let exit_delay = server::parse_sequence_number(info.unilateral_exit_delay)
        .map_err(|e| format!("invalid unilateral_exit_delay: {e}"))?;
    let boarding_delay = server::parse_sequence_number(info.boarding_exit_delay)
        .map_err(|e| format!("invalid boarding_exit_delay: {e}"))?;

    Ok(server::Info {
        version: String::new(),
        signer_pk,
        forfeit_pk,
        forfeit_address,
        checkpoint_tapscript,
        network,
        session_duration: info.session_duration as u64,
        unilateral_exit_delay: exit_delay,
        boarding_exit_delay: boarding_delay,
        utxo_min_amount: None,
        utxo_max_amount: None,
        vtxo_min_amount: if info.vtxo_min_amount > 0 {
            Some(Amount::from_sat(info.vtxo_min_amount as u64))
        } else {
            None
        },
        vtxo_max_amount: None,
        dust: Amount::from_sat(info.dust as u64),
        fees: None,
        scheduled_session: None,
        deprecated_signers: vec![],
        service_status: HashMap::new(),
        digest: String::new(),
        // Not enforced by the off-chain send build path; 0 = unset.
        max_tx_weight: 0,
        max_op_return_outputs: 0,
    })
}

fn parse_xonly(hex: &str) -> Result<XOnlyPublicKey, String> {
    let hex = if hex.len() == 66 && (hex.starts_with("02") || hex.starts_with("03")) {
        &hex[2..]
    } else {
        hex
    };
    XOnlyPublicKey::from_str(hex).map_err(|e| format!("invalid x-only pubkey: {e}"))
}

fn parse_network(network: &str) -> Result<Network, String> {
    match network {
        "bitcoin" | "mainnet" => Ok(Network::Bitcoin),
        "testnet" | "testnet3" => Ok(Network::Testnet),
        "signet" | "mutinynet" => Ok(Network::Signet),
        "regtest" => Ok(Network::Regtest),
        _ => Err(format!("unknown network: {network}")),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn encode_condition_single_preimage_matches_ark_format() {
        // For `Condition = OP_SHA256 <commit> OP_EQUAL`, the condition witness is a
        // single 32-byte preimage. ark-core encodes it as: count varint (0x01),
        // element-len varint (0x20), then the 32 bytes. arkd reads exactly this.
        let cid = [0xcd_u8; 32];
        let enc = encode_condition(&[cid.to_vec()]);
        assert_eq!(enc.len(), 1 + 1 + 32);
        assert_eq!(enc[0], 0x01); // one element
        assert_eq!(enc[1], 0x20); // 32-byte length
        assert_eq!(&enc[2..], &cid[..]);
    }

    #[test]
    fn encode_condition_compact_size_boundaries() {
        // 253-byte element crosses the 0xfd compact-size boundary.
        let big = vec![0xaa_u8; 253];
        let enc = encode_condition(&[big.clone()]);
        assert_eq!(enc[0], 0x01); // count
        assert_eq!(enc[1], 0xfd); // len marker for 253
        assert_eq!(&enc[2..4], &[0xfd, 0x00]); // 253 LE u16
        assert_eq!(&enc[4..], &big[..]);
    }
}
