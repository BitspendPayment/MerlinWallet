//! Off-chain VTXO send — build, sign, and submit Ark transactions.
//!
//! This module implements the off-chain send flow for MPC wallets:
//!
//! 1. **Build** (`SendSession::build`) — construct ark tx + checkpoint txs
//!    using `ark_core::send`, compute all sighashes for FROST signing.
//! 2. **Sign** (`sign_with_frost`) — insert FROST signatures.
//! 3. **Submit** (`submit`) — submit to ASP, counter-sign checkpoints, finalize.

use std::collections::HashMap;
use std::str::FromStr;

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

#[cfg(feature = "client")]
use crate::client::asp_client::AspClient;
use crate::client::types::ArkInfo;

// ---------------------------------------------------------------------------
// Public types
// ---------------------------------------------------------------------------

/// VTXO input descriptor for off-chain send.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SendVtxoInput {
    pub txid: String,
    pub vout: u32,
    pub amount_sats: u64,
    /// This VTXO's OWN unilateral-exit delay, which is part of its taproot tree
    /// and therefore of its scriptPubKey. A wallet legitimately holds a mix: a
    /// boarding-settled VTXO carries `boarding_exit_delay` while a received one
    /// carries `unilateral_exit_delay`, so one delay cannot stand in for all.
    pub exit_delay: u32,
}

/// Tracks which transaction and input index a sighash belongs to.
enum SighashTarget {
    /// Ark transaction input at the given index.
    ArkTx(usize),
    /// Checkpoint transaction at the given index (input is always 0).
    Checkpoint(usize),
}

struct SighashEntry {
    target: SighashTarget,
    leaf_hash: TapLeafHash,
}

enum SendPhase {
    AwaitingSignatures,
    ReadyToSubmit,
    Done,
}

/// A session for sending VTXOs off-chain to an Ark address.
///
/// The flow splits into phases so FROST signing can happen externally:
/// 1. `build()` → compute sighashes
/// 2. `sign_with_frost()` → insert signatures
/// 3. `submit()` → drive ASP submit + finalize
pub struct SendSession {
    phase: SendPhase,

    owner_pk: XOnlyPublicKey,

    // Transactions built by ark_core::send
    ark_tx: Psbt,
    checkpoint_txs: Vec<Psbt>,

    // Sighash metadata for inserting signatures
    sighash_entries: Vec<SighashEntry>,

    // FROST signatures (stored after sign_with_frost, applied during submit)
    frost_signatures: Option<Vec<[u8; 64]>>,
}

// ---------------------------------------------------------------------------
// Construction
// ---------------------------------------------------------------------------

impl SendSession {
    /// Build off-chain transactions and compute all sighashes.
    ///
    /// Returns `(session, sighashes)` where sighashes need FROST signing.
    /// Sighash order: all ark tx inputs first, then all checkpoint inputs.
    pub fn build(
        owner_pk_hex: &str,
        vtxo_inputs: &[SendVtxoInput],
        recipient_ark_address: &str,
        amount_sats: u64,
        change_ark_address: Option<&str>,
        ark_info: &ArkInfo,
    ) -> Result<(Self, Vec<[u8; 32]>), String> {
        let secp = Secp256k1::new();
        let network = parse_network(&ark_info.network)?;

        let owner_pk = parse_xonly(owner_pk_hex)?;
        let asp_pk = parse_xonly(&ark_info.signer_pubkey)?;

        // Derive the spend info from EACH input's own exit delay, not from one
        // shared value. The delay is part of the VTXO's taproot tree, so reusing
        // one input's script/control block for the rest yields a wrong
        // scriptPubKey and a sighash computed over the wrong prevout — the ASP
        // rejects such a send. `generate_delegate` already builds one Vtxo per
        // distinct delay; this is the same treatment for the send path.
        //
        // Cached by delay: a mixed set is usually just two distinct values
        // (boarding vs unilateral), and Vtxo::new_default does real taproot work.
        let mut spend_info_by_delay: HashMap<u32, _> = HashMap::new();
        for vi in vtxo_inputs {
            if spend_info_by_delay.contains_key(&vi.exit_delay) {
                continue;
            }
            let exit_seq = server::parse_sequence_number(vi.exit_delay as i64)
                .map_err(|e| format!("invalid exit_delay {}: {e}", vi.exit_delay))?;
            let vtxo = ark_core::Vtxo::new_default(&secp, asp_pk, owner_pk, exit_seq, network)
                .map_err(|e| format!("Vtxo::new_default: {e}"))?;
            let (spend_script, control_block) = vtxo
                .forfeit_spend_info()
                .map_err(|e| format!("forfeit_spend_info: {e}"))?;
            spend_info_by_delay.insert(
                vi.exit_delay,
                (
                    spend_script,
                    control_block,
                    vtxo.tapscripts(),
                    vtxo.script_pubkey(),
                ),
            );
        }

        // Build VtxoInput for each input VTXO.
        let send_inputs: Vec<VtxoInput> = vtxo_inputs
            .iter()
            .map(|vi| {
                let outpoint = OutPoint {
                    txid: vi.txid.parse().map_err(|e| format!("invalid txid: {e}"))?,
                    vout: vi.vout,
                };
                let (spend_script, control_block, tapscripts, vtxo_script_pubkey) =
                    spend_info_by_delay
                        .get(&vi.exit_delay)
                        .ok_or("missing spend info for exit delay")?;
                Ok(VtxoInput::new(
                    spend_script.clone(),
                    None, // no locktime for default VTXOs
                    control_block.clone(),
                    tapscripts.clone(),
                    vtxo_script_pubkey.clone(),
                    Amount::from_sat(vi.amount_sats),
                    outpoint,
                    Vec::new(), // assets — none (ark-core 0.9)
                ))
            })
            .collect::<Result<Vec<_>, String>>()?;

        // Parse recipient address.
        let recipient: ark_core::ArkAddress = recipient_ark_address
            .parse()
            .map_err(|e| format!("invalid recipient ark address: {e}"))?;

        // ark-core 0.9 takes `SendReceiver`s instead of (&addr, amount) tuples.
        let receivers = vec![send::SendReceiver::bitcoin(
            recipient,
            Amount::from_sat(amount_sats),
        )];

        // 0.9 requires a change address (it only emits a change output when
        // there is leftover value). Default to the sender's own ark address
        // when the caller didn't pass one.
        let change_addr: ark_core::ArkAddress = match change_ark_address {
            Some(a) => a
                .parse()
                .map_err(|e| format!("invalid change ark address: {e}"))?,
            None => crate::client::ark_address(
                owner_pk_hex,
                &ark_info.signer_pubkey,
                ark_info.unilateral_exit_delay as u32,
                network,
            )?
            .parse()
            .map_err(|e| format!("invalid derived change ark address: {e}"))?,
        };

        // Build server::Info from ArkInfo (only checkpoint_tapscript, dust,
        // vtxo_min_amount are used by build_offchain_transactions).
        let server_info = build_server_info(ark_info, network)?;

        // Build the off-chain transactions.
        let OffchainTransactions {
            ark_tx,
            checkpoint_txs,
        } = send::build_offchain_transactions(&receivers, &change_addr, &send_inputs, &server_info)
            .map_err(|e| format!("build_offchain_transactions: {e}"))?;

        // Compute all sighashes.
        let mut sighashes = Vec::new();
        let mut sighash_entries = Vec::new();

        // Ark tx input sighashes (one per checkpoint).
        collect_ark_tx_sighashes(&ark_tx, &mut sighashes, &mut sighash_entries)?;

        // Checkpoint tx sighashes (one per checkpoint, input 0).
        for (ci, cp_psbt) in checkpoint_txs.iter().enumerate() {
            collect_checkpoint_sighash(cp_psbt, ci, &mut sighashes, &mut sighash_entries)?;
        }

        let session = SendSession {
            phase: SendPhase::AwaitingSignatures,
            owner_pk,
            ark_tx,
            checkpoint_txs,
            sighash_entries,
            frost_signatures: None,
        };

        Ok((session, sighashes))
    }
}

// ---------------------------------------------------------------------------
// FROST signature insertion
// ---------------------------------------------------------------------------

impl SendSession {
    /// Store FROST signatures for later insertion during submit.
    pub fn sign_with_frost(&mut self, signatures: Vec<[u8; 64]>) -> Result<(), String> {
        if !matches!(self.phase, SendPhase::AwaitingSignatures) {
            return Err("sign_with_frost called in wrong phase".into());
        }
        if signatures.len() != self.sighash_entries.len() {
            return Err(format!(
                "expected {} signatures, got {}",
                self.sighash_entries.len(),
                signatures.len()
            ));
        }
        self.frost_signatures = Some(signatures);
        self.phase = SendPhase::ReadyToSubmit;
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// ASP submission
// ---------------------------------------------------------------------------

impl SendSession {
    /// Insert the stored FROST signatures into the PSBTs and produce the base64 payloads
    /// to submit: `(signed_ark_tx, unsigned_checkpoint_txs)`. Pure signing-side prep — no
    /// ASP. Callable from the wasm guest (the guest drives submission via host imports).
    pub fn prepare_submit(&mut self) -> Result<(String, Vec<String>), String> {
        if !matches!(self.phase, SendPhase::ReadyToSubmit) {
            return Err("submit called in wrong phase".into());
        }

        let signatures = self
            .frost_signatures
            .take()
            .ok_or("missing FROST signatures")?;

        // Insert FROST signatures into the ark tx + checkpoint inputs.
        for (sig_bytes, entry) in signatures.iter().zip(self.sighash_entries.iter()) {
            let schnorr_sig = bitcoin::secp256k1::schnorr::Signature::from_slice(sig_bytes)
                .map_err(|e| format!("invalid schnorr sig: {e}"))?;

            let sig = taproot::Signature {
                signature: schnorr_sig,
                sighash_type: TapSighashType::Default,
            };

            match &entry.target {
                SighashTarget::ArkTx(input_idx) => {
                    self.ark_tx.inputs[*input_idx]
                        .tap_script_sigs
                        .insert((self.owner_pk, entry.leaf_hash), sig);
                }
                SighashTarget::Checkpoint(cp_idx) => {
                    self.checkpoint_txs[*cp_idx].inputs[0]
                        .tap_script_sigs
                        .insert((self.owner_pk, entry.leaf_hash), sig);
                }
            }
        }

        // Signed ark tx + checkpoints WITHOUT our sigs (the ASP adds its own first).
        let signed_ark_b64 = encode_psbt_b64(&self.ark_tx);
        let unsigned_checkpoint_b64s: Vec<String> = self
            .checkpoint_txs
            .iter()
            .map(|cp| {
                let mut unsigned = cp.clone();
                for input in &mut unsigned.inputs {
                    input.tap_script_sigs.clear();
                }
                encode_psbt_b64(&unsigned)
            })
            .collect();

        Ok((signed_ark_b64, unsigned_checkpoint_b64s))
    }

    /// Counter-sign the ASP-returned checkpoints with our FROST signatures, returning the
    /// fully-signed checkpoint PSBTs (base64) to finalize. Pure PSBT math — guest-callable.
    pub fn finalize_checkpoints(
        &self,
        signed_checkpoint_txs_b64: &[String],
    ) -> Result<Vec<String>, String> {
        let mut final_checkpoints = Vec::new();
        for asp_cp_b64 in signed_checkpoint_txs_b64 {
            let mut asp_cp = decode_psbt_b64(asp_cp_b64)?;

            // Find matching original checkpoint by unsigned_tx txid.
            let cp_txid = asp_cp.unsigned_tx.compute_txid();
            let original = self
                .checkpoint_txs
                .iter()
                .find(|cp| cp.unsigned_tx.compute_txid() == cp_txid)
                .ok_or_else(|| format!("ASP returned unknown checkpoint txid: {cp_txid}"))?;

            // Restore witness_script / tap_scripts (may be stripped by ASP).
            if let Some(ws) = &original.inputs[0].witness_script {
                asp_cp.inputs[0].witness_script = Some(ws.clone());
            }
            if asp_cp.inputs[0].tap_scripts.is_empty() {
                asp_cp.inputs[0].tap_scripts = original.inputs[0].tap_scripts.clone();
            }

            // Copy our FROST signatures into the ASP-signed checkpoint.
            for ((pk, lh), sig) in &original.inputs[0].tap_script_sigs {
                asp_cp.inputs[0]
                    .tap_script_sigs
                    .insert((*pk, *lh), sig.clone());
            }

            final_checkpoints.push(encode_psbt_b64(&asp_cp));
        }
        Ok(final_checkpoints)
    }

    /// The transactions as built, before anybody has signed: the ark tx and one checkpoint per
    /// input, base64 PSBTs.
    ///
    /// For a counterparty that has to submit *exactly* what was approved rather than rebuild it.
    /// `build` is deterministic, so a party running it over the same inputs gets the same bytes —
    /// but "the same, we checked" is a weaker thing to rest a release on than "these, verbatim",
    /// and a signature is only valid over the transaction whose sighashes it covers anyway.
    pub fn unsigned(&self) -> (String, Vec<String>) {
        (
            encode_psbt_b64(&self.ark_tx),
            self.checkpoint_txs.iter().map(encode_psbt_b64).collect(),
        )
    }

    /// The ark transaction's id, known as soon as it is built.
    ///
    /// Fixed before anything is signed: these are taproot script-path spends, so the signatures go
    /// in the witness and the txid does not move. That is what lets a caller write down what it is
    /// about to submit, and afterwards ask the chain whether it landed.
    pub fn ark_txid(&self) -> String {
        self.ark_tx.unsigned_tx.compute_txid().to_string()
    }

    /// The ark transaction's outputs — where the money actually goes — for a policy to judge.
    pub fn outputs(&self) -> &[bitcoin::TxOut] {
        &self.ark_tx.unsigned_tx.output
    }

    /// Mark the session complete after finalization succeeds.
    pub fn mark_done(&mut self) {
        self.phase = SendPhase::Done;
    }

    /// Submit the signed transaction to the ASP and finalize. ASP transport — host only.
    /// Thin wrapper over `prepare_submit` + `finalize_checkpoints` (which the guest calls
    /// directly, driving the two ASP round-trips via host imports).
    ///
    /// Returns the Ark transaction ID.
    #[cfg(feature = "client")]
    pub async fn submit(&mut self, asp: &mut AspClient) -> Result<String, String> {
        let (signed_ark_b64, unsigned_checkpoint_b64s) = self.prepare_submit()?;
        let response = asp
            .submit_tx(signed_ark_b64, unsigned_checkpoint_b64s)
            .await
            .map_err(|e| format!("submit_tx: {e}"))?;
        let final_checkpoints = self.finalize_checkpoints(&response.signed_checkpoint_txs)?;
        asp.finalize_tx(response.ark_txid.clone(), final_checkpoints)
            .await
            .map_err(|e| format!("finalize_tx: {e}"))?;
        self.mark_done();
        Ok(response.ark_txid)
    }

    /// Returns the change VTXO outpoint `(txid, vout, amount_sats)` if the
    /// ark tx has a change output.
    /// Output order: [recipient(s)..., change, anchor]. The anchor output
    /// (0-value) is always last, so change is second-to-last when present.
    /// Call after `submit()`.
    pub fn change_vtxo(&self) -> Option<(String, u32, u64)> {
        let outputs = &self.ark_tx.unsigned_tx.output;
        // At minimum: 1 recipient + 1 anchor = 2 outputs (no change).
        // With change: 1 recipient + 1 change + 1 anchor = 3+ outputs.
        if outputs.len() < 3 {
            return None;
        }
        let txid = self.ark_tx.unsigned_tx.compute_txid().to_string();
        // Change is second-to-last (before anchor)
        let change_idx = outputs.len() - 2;
        let amount = outputs[change_idx].value.to_sat();
        if amount == 0 {
            return None;
        }
        Some((txid, change_idx as u32, amount))
    }
}

// ---------------------------------------------------------------------------
// Sighash computation helpers
// ---------------------------------------------------------------------------

/// Compute taproot script-spend sighashes for all ark tx inputs.
fn collect_ark_tx_sighashes(
    psbt: &Psbt,
    sighashes: &mut Vec<[u8; 32]>,
    entries: &mut Vec<SighashEntry>,
) -> Result<(), String> {
    let prevouts: Vec<TxOut> = psbt
        .inputs
        .iter()
        .map(|i| {
            i.witness_utxo
                .clone()
                .ok_or("ark tx input missing witness_utxo")
        })
        .collect::<Result<Vec<_>, _>>()?;

    for (i, psbt_input) in psbt.inputs.iter().enumerate() {
        let (_, (script, leaf_version)) = psbt_input
            .tap_scripts
            .first_key_value()
            .ok_or_else(|| format!("ark tx input {i} missing tap_scripts"))?;

        let leaf_hash = TapLeafHash::from_script(script, *leaf_version);
        let prevs = Prevouts::All(&prevouts);

        let tap_sighash = SighashCache::new(&psbt.unsigned_tx)
            .taproot_script_spend_signature_hash(
                i,
                &prevs,
                leaf_hash,
                TapSighashType::Default,
            )
            .map_err(|e| format!("ark tx sighash input {i}: {e}"))?;

        sighashes.push(tap_sighash.to_raw_hash().to_byte_array());
        entries.push(SighashEntry {
            target: SighashTarget::ArkTx(i),
            leaf_hash,
        });
    }
    Ok(())
}

/// Compute taproot script-spend sighash for a checkpoint tx (input 0).
fn collect_checkpoint_sighash(
    psbt: &Psbt,
    checkpoint_index: usize,
    sighashes: &mut Vec<[u8; 32]>,
    entries: &mut Vec<SighashEntry>,
) -> Result<(), String> {
    let witness_utxo = psbt.inputs[0]
        .witness_utxo
        .clone()
        .ok_or("checkpoint missing witness_utxo")?;
    let prevouts = Prevouts::All(&[witness_utxo]);

    let psbt_input = &psbt.inputs[0];
    let (_, (script, leaf_version)) = psbt_input
        .tap_scripts
        .first_key_value()
        .ok_or("checkpoint missing tap_scripts")?;

    let leaf_hash = TapLeafHash::from_script(script, *leaf_version);

    let tap_sighash = SighashCache::new(&psbt.unsigned_tx)
        .taproot_script_spend_signature_hash(0, &prevouts, leaf_hash, TapSighashType::Default)
        .map_err(|e| format!("checkpoint sighash: {e}"))?;

    sighashes.push(tap_sighash.to_raw_hash().to_byte_array());
    entries.push(SighashEntry {
        target: SighashTarget::Checkpoint(checkpoint_index),
        leaf_hash,
    });
    Ok(())
}

// ---------------------------------------------------------------------------
// server::Info construction
// ---------------------------------------------------------------------------

/// Build a `server::Info` from our `ArkInfo`, populating only the fields
/// needed by `build_offchain_transactions`.
fn build_server_info(ark_info: &ArkInfo, network: Network) -> Result<server::Info, String> {
    // server::Info uses bitcoin::secp256k1::PublicKey (33-byte compressed).
    // Our signer/forfeit pubkeys may be x-only (32-byte) — prefix with 02.
    let signer_pk_hex = if ark_info.signer_pubkey.len() == 64 {
        format!("02{}", ark_info.signer_pubkey)
    } else {
        ark_info.signer_pubkey.clone()
    };
    let signer_pk_bytes = hex_decode(&signer_pk_hex)?;
    let signer_pk = bitcoin::secp256k1::PublicKey::from_slice(&signer_pk_bytes)
        .map_err(|e| format!("invalid signer_pubkey: {e}"))?;

    let forfeit_pk_hex = if ark_info.forfeit_pubkey.len() == 64 {
        format!("02{}", ark_info.forfeit_pubkey)
    } else {
        ark_info.forfeit_pubkey.clone()
    };
    let forfeit_pk_bytes = hex_decode(&forfeit_pk_hex)?;
    let forfeit_pk = bitcoin::secp256k1::PublicKey::from_slice(&forfeit_pk_bytes)
        .map_err(|e| format!("invalid forfeit_pubkey: {e}"))?;

    let forfeit_address: bitcoin::Address<bitcoin::address::NetworkUnchecked> = ark_info
        .forfeit_address
        .parse()
        .map_err(|e| format!("invalid forfeit_address: {e}"))?;
    let forfeit_address = forfeit_address
        .require_network(network)
        .map_err(|e| format!("forfeit_address network mismatch: {e}"))?;

    let checkpoint_bytes = hex_decode(&ark_info.checkpoint_tapscript)?;
    let checkpoint_tapscript = ScriptBuf::from_bytes(checkpoint_bytes);

    let exit_delay = server::parse_sequence_number(ark_info.unilateral_exit_delay)
        .map_err(|e| format!("invalid unilateral_exit_delay: {e}"))?;
    let boarding_delay = server::parse_sequence_number(ark_info.boarding_exit_delay)
        .map_err(|e| format!("invalid boarding_exit_delay: {e}"))?;

    Ok(server::Info {
        version: String::new(),
        signer_pk,
        forfeit_pk,
        forfeit_address,
        checkpoint_tapscript,
        network,
        session_duration: ark_info.session_duration as u64,
        unilateral_exit_delay: exit_delay,
        boarding_exit_delay: boarding_delay,
        utxo_min_amount: None,
        utxo_max_amount: None,
        vtxo_min_amount: if ark_info.vtxo_min_amount > 0 {
            Some(Amount::from_sat(ark_info.vtxo_min_amount as u64))
        } else {
            None
        },
        vtxo_max_amount: None,
        dust: Amount::from_sat(ark_info.dust as u64),
        fees: None,
        scheduled_session: None,
        deprecated_signers: vec![],
        service_status: HashMap::new(),
        digest: String::new(),
        // Not enforced by the off-chain send build path; arkd's real limits
        // come from GetArkInfo. 0 = unset here.
        max_tx_weight: 0,
        max_op_return_outputs: 0,
    })
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

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

fn hex_decode(hex: &str) -> Result<Vec<u8>, String> {
    (0..hex.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&hex[i..i + 2], 16).map_err(|e| format!("hex decode: {e}")))
        .collect()
}

fn decode_psbt_b64(b64: &str) -> Result<Psbt, String> {
    let engine = base64::engine::GeneralPurpose::new(
        &base64::alphabet::STANDARD,
        base64::engine::GeneralPurposeConfig::new(),
    );
    let bytes = engine
        .decode(b64)
        .map_err(|e| format!("base64 decode: {e}"))?;
    Psbt::deserialize(&bytes).map_err(|e| format!("PSBT deserialize: {e}"))
}

fn encode_psbt_b64(psbt: &Psbt) -> String {
    let engine = base64::engine::GeneralPurpose::new(
        &base64::alphabet::STANDARD,
        base64::engine::GeneralPurposeConfig::new(),
    );
    engine.encode(psbt.serialize())
}
