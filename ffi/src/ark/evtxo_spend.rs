//! FFI for spending an eVTXO's cooperative (contract-gated) leaf on-chain.
//!
//! The cooperative leaf is an Ark `ConditionMultisigClosure`:
//!   `OP_SHA256 <commit> OP_EQUAL OP_VERIFY <server_pk> OP_CHECKSIGVERIFY <V′> OP_CHECKSIG`
//! where `commit = sha256(contract_id)` and `contract_id = sha256(component_wasm)`.
//! Spending it requires, in witness-stack order (bottom→top):
//!   `[v_prime_sig(64), server_sig(64), contract_id(32)]`, then the leaf script
//! and its control block. `v_prime_sig` is the 2-of-2 {wallet, cosigner} FROST
//! signature (the cosigner only releases its share if the committed contract
//! returns `allow`); `server_sig` is the ASP signer key's BIP-340 signature over
//! the same script-path sighash.
//!
//! Build returns the sighash both legs sign plus the PSBT to hand the cosigner
//! (carrying `witness_utxo` = the eVTXO spk + the contract args in the
//! proprietary map). Finalize signs the server leg with the ASP key and
//! assembles the witness into a broadcastable transaction.

use std::collections::HashMap;
use std::sync::Mutex;

use bitcoin::consensus::serialize;
use bitcoin::hashes::{sha256, Hash};
use bitcoin::secp256k1::{Keypair, Message, Secp256k1, SecretKey, XOnlyPublicKey};
use bitcoin::sighash::{Prevouts, SighashCache};
use bitcoin::taproot::LeafVersion;
use bitcoin::{
    Amount, OutPoint, Psbt, ScriptBuf, Sequence, TapLeafHash, TapSighashType, Transaction, TxIn,
    TxOut, Txid, Witness,
};

use serde::{Deserialize, Serialize};

use super::{hex_decode, hex_encode, hex_to_32};

/// PSBT proprietary key carrying off-chain contract args, mirrored from
/// `cosigner`'s `tx_parser::{CONTRACT_ARGS_PREFIX, CONTRACT_ARGS_SUBTYPE}`.
/// Keep these byte-identical or the cosigner won't read the args.
const CONTRACT_ARGS_PREFIX: &[u8] = b"EVTXO";
const CONTRACT_ARGS_SUBTYPE: u8 = 0x01;

// ---------------------------------------------------------------------------
// Params / results
// ---------------------------------------------------------------------------

#[derive(Deserialize)]
pub struct BuildEvtxoSpendParams {
    /// 32-byte hex; `contract_id = sha256(component_wasm)`. `commit = sha256(contract_id)`.
    pub contract_id: String,
    /// x-only hex of the ASP signer key (`GetArkInfo.signer_pubkey`).
    pub server_pk: String,
    /// x-only hex of V′ (the 2-of-2 {wallet, cosigner} contract key).
    pub evtxo_pk: String,
    /// x-only hex of the main key V (keys the exit leaf; part of the address).
    pub owner_pk: String,
    pub exit_delay: u32,
    pub input: EvtxoInputParam,
    pub output: SpendOutputParam,
    /// Hex of the opaque contract args handed to the gate via the PSBT proprietary
    /// map. Omit (or empty) for a contract that takes no args.
    #[serde(default)]
    pub contract_args: Option<String>,
}

#[derive(Deserialize)]
pub struct EvtxoInputParam {
    /// Funding txid in display (big-endian) order.
    pub txid: String,
    pub vout: u32,
    /// Sats locked in the eVTXO (the prevout value).
    pub amount: u64,
}

#[derive(Deserialize)]
pub struct SpendOutputParam {
    /// Destination scriptPubKey hex. Fee = `input.amount - output.amount`.
    pub script_pubkey: String,
    pub amount: u64,
}

#[derive(Serialize)]
pub struct BuildEvtxoSpendResult {
    pub handle: u64,
    /// The taproot script-path sighash both the V′ and server legs sign (hex).
    pub sighash: String,
    /// PSBT (hex) to pass as `fullTransaction` to the cosigner's `sign`.
    pub psbt: String,
    /// 34-byte eVTXO scriptPubKey (`OP_1 <32>`), for deriving the funding address.
    pub evtxo_spk: String,
}

struct EvtxoSpendState {
    unsigned_tx: Transaction,
    coop_script: ScriptBuf,
    control_block: Vec<u8>,
    sighash: [u8; 32],
    contract_id: [u8; 32],
    server_pk: XOnlyPublicKey,
}

// ---------------------------------------------------------------------------
// Session store
// ---------------------------------------------------------------------------

static SESSIONS: Mutex<Option<HashMap<u64, EvtxoSpendState>>> = Mutex::new(None);
static NEXT_HANDLE: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(1);

fn get_sessions() -> std::sync::MutexGuard<'static, Option<HashMap<u64, EvtxoSpendState>>> {
    let mut guard = SESSIONS.lock().unwrap();
    if guard.is_none() {
        *guard = Some(HashMap::new());
    }
    guard
}

// ---------------------------------------------------------------------------
// Build
// ---------------------------------------------------------------------------

pub fn build_evtxo_spend(params_json: &str) -> Result<String, String> {
    let params: BuildEvtxoSpendParams =
        serde_json::from_str(params_json).map_err(|e| format!("JSON parse: {e}"))?;

    let contract_id = hex_to_32(&params.contract_id)?;
    let server_pk = hex_to_32(&params.server_pk)?;
    let evtxo_pk = hex_to_32(&params.evtxo_pk)?;
    let owner_pk = hex_to_32(&params.owner_pk)?;
    let server_pk_xonly = XOnlyPublicKey::from_slice(&server_pk)
        .map_err(|e| format!("invalid server_pk x-only: {e}"))?;

    // On-chain commitment: commit = sha256(contract_id).
    let commit: [u8; 32] = sha256::Hash::hash(&contract_id).to_byte_array();

    // eVTXO scriptPubKey (split-key tree: cooperative = server/V′, exit = V).
    let evtxo_spk = ark::evtxo_script_pubkey(&commit, &server_pk, &evtxo_pk, &owner_pk, params.exit_delay)
        .map_err(|e| format!("evtxo_script_pubkey: {e:?}"))?;
    let evtxo_spk_buf = ScriptBuf::from_bytes(evtxo_spk.to_vec());

    // Cooperative-leaf script + control block (the contract-gated spend path).
    let (coop_script, control_block) =
        ark::evtxo_cooperative_spend_info(&commit, &server_pk, &evtxo_pk, &owner_pk, params.exit_delay)
            .ok_or("evtxo_cooperative_spend_info failed")?;
    let coop_script_buf = ScriptBuf::from_bytes(coop_script.clone());

    // Unsigned spend: the eVTXO outpoint in, one destination output.
    let txid: Txid = params
        .input
        .txid
        .parse()
        .map_err(|e| format!("invalid input txid: {e}"))?;
    let out_spk = ScriptBuf::from_bytes(hex_decode(&params.output.script_pubkey)?);
    if params.output.amount > params.input.amount {
        return Err(format!(
            "output {} exceeds input {}",
            params.output.amount, params.input.amount
        ));
    }
    let unsigned_tx = Transaction {
        version: bitcoin::transaction::Version::TWO,
        lock_time: bitcoin::absolute::LockTime::ZERO,
        input: vec![TxIn {
            previous_output: OutPoint { txid, vout: params.input.vout },
            script_sig: ScriptBuf::new(),
            // Cooperative leaf has no CSV, so the input can be final.
            sequence: Sequence::ENABLE_RBF_NO_LOCKTIME,
            witness: Witness::new(),
        }],
        output: vec![TxOut {
            value: Amount::from_sat(params.output.amount),
            script_pubkey: out_spk,
        }],
    };

    let prevout = TxOut {
        value: Amount::from_sat(params.input.amount),
        script_pubkey: evtxo_spk_buf,
    };

    // Script-path sighash over the cooperative leaf — both legs sign this.
    let leaf_hash = TapLeafHash::from_script(&coop_script_buf, LeafVersion::TapScript);
    let sighash = SighashCache::new(&unsigned_tx)
        .taproot_script_spend_signature_hash(
            0,
            &Prevouts::All(std::slice::from_ref(&prevout)),
            leaf_hash,
            TapSighashType::Default,
        )
        .map_err(|e| format!("sighash: {e}"))?
        .to_byte_array();

    // PSBT for the cosigner: witness_utxo lets it detect the eVTXO + introspect;
    // the proprietary key carries the contract args.
    let mut psbt =
        Psbt::from_unsigned_tx(unsigned_tx.clone()).map_err(|e| format!("psbt: {e}"))?;
    psbt.inputs[0].witness_utxo = Some(prevout);
    if let Some(args_hex) = params.contract_args.as_deref() {
        if !args_hex.is_empty() {
            let args = hex_decode(args_hex)?;
            psbt.inputs[0].proprietary.insert(
                bitcoin::psbt::raw::ProprietaryKey {
                    prefix: CONTRACT_ARGS_PREFIX.to_vec(),
                    subtype: CONTRACT_ARGS_SUBTYPE,
                    key: vec![],
                },
                args,
            );
        }
    }
    let psbt_hex = hex_encode(&psbt.serialize());

    let handle = NEXT_HANDLE.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    get_sessions().as_mut().unwrap().insert(
        handle,
        EvtxoSpendState {
            unsigned_tx,
            coop_script: coop_script_buf,
            control_block: control_block.serialize(),
            sighash,
            contract_id,
            server_pk: server_pk_xonly,
        },
    );

    let result = BuildEvtxoSpendResult {
        handle,
        sighash: hex_encode(&sighash),
        psbt: psbt_hex,
        evtxo_spk: hex_encode(&evtxo_spk),
    };
    serde_json::to_string(&result).map_err(|e| format!("JSON serialize: {e}"))
}

// ---------------------------------------------------------------------------
// Finalize
// ---------------------------------------------------------------------------

/// Assemble the cooperative-leaf witness from the V′ FROST signature plus a
/// freshly produced server-leg signature, and return the raw signed tx hex.
/// `signer_sk_hex` is the ASP signer secret key; its x-only pubkey MUST equal the
/// `server_pk` the spend was built against.
pub fn finalize_evtxo_spend(
    handle: u64,
    v_prime_sig_hex: &str,
    signer_sk_hex: &str,
) -> Result<String, String> {
    let mut sessions = get_sessions();
    let state = sessions
        .as_mut()
        .unwrap()
        .get_mut(&handle)
        .ok_or("invalid session handle")?;

    let v_prime_sig = hex_decode(v_prime_sig_hex)?;
    if v_prime_sig.len() != 64 {
        return Err(format!("expected 64-byte V′ sig, got {}", v_prime_sig.len()));
    }

    // Server leg: sign the same script-path sighash with the ASP signer key.
    let secp = Secp256k1::new();
    let sk_bytes = hex_to_32(signer_sk_hex)?;
    let sk = SecretKey::from_slice(&sk_bytes).map_err(|e| format!("invalid signer_sk: {e}"))?;
    let keypair = Keypair::from_secret_key(&secp, &sk);
    let (signer_xonly, _parity) = XOnlyPublicKey::from_keypair(&keypair);
    if signer_xonly != state.server_pk {
        return Err(format!(
            "signer key x-only {} != server_pk {}",
            signer_xonly, state.server_pk
        ));
    }
    let msg = Message::from_digest(state.sighash);
    let server_sig = secp.sign_schnorr_no_aux_rand(&msg, &keypair);

    // Witness stack (bottom→top): v_prime_sig, server_sig, contract_id, then the
    // leaf script and control block.
    let mut witness = Witness::new();
    witness.push(&v_prime_sig);
    witness.push(server_sig.as_ref());
    witness.push(state.contract_id);
    witness.push(state.coop_script.as_bytes());
    witness.push(&state.control_block);

    let mut tx = state.unsigned_tx.clone();
    tx.input[0].witness = witness;
    Ok(hex_encode(&serialize(&tx)))
}

pub fn free_evtxo_spend(handle: u64) {
    if let Ok(mut sessions) = SESSIONS.lock() {
        if let Some(map) = sessions.as_mut() {
            map.remove(&handle);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // arkd's regtest signer key (docker-compose.ark.yml ARKD_WALLET_SIGNER_KEY).
    const SIGNER_SK: &str = "afcd3fa10f82a05fddc9574fdb13b3991b568e89cc39a72ba4401df8abef35f0";

    fn server_pk_hex() -> String {
        let secp = Secp256k1::new();
        let sk = SecretKey::from_slice(&hex_to_32(SIGNER_SK).unwrap()).unwrap();
        let kp = Keypair::from_secret_key(&secp, &sk);
        hex_encode(&XOnlyPublicKey::from_keypair(&kp).0.serialize())
    }

    fn build_params() -> String {
        // A valid p2tr output spk (OP_1 <32>) as the destination.
        let out_spk = format!("5120{}", "ab".repeat(32));
        format!(
            r#"{{
                "contract_id": "{cid}",
                "server_pk": "{spk}",
                "evtxo_pk": "{vp}",
                "owner_pk": "{ow}",
                "exit_delay": 144,
                "input": {{ "txid": "{txid}", "vout": 0, "amount": 1000000 }},
                "output": {{ "script_pubkey": "{out}", "amount": 50000 }},
                "contract_args": "{args}"
            }}"#,
            cid = "cd".repeat(32),
            spk = server_pk_hex(),
            vp = "02".repeat(32),
            ow = "03".repeat(32),
            txid = "11".repeat(32),
            out = out_spk,
            args = hex_encode(b"ORACLE-OK"),
        )
    }

    #[test]
    fn build_returns_consistent_sighash_and_carries_args() {
        let out = build_evtxo_spend(&build_params()).unwrap();
        let res: serde_json::Value = serde_json::from_str(&out).unwrap();
        let psbt_hex = res["psbt"].as_str().unwrap();
        let sighash_hex = res["sighash"].as_str().unwrap();
        let evtxo_spk = res["evtxo_spk"].as_str().unwrap();

        // eVTXO spk is a 34-byte v1 taproot program.
        assert_eq!(evtxo_spk.len(), 68);
        assert!(evtxo_spk.starts_with("5120"));

        // Independently recompute the cooperative-leaf sighash from the PSBT and
        // assert it matches what build returned (both legs will sign this).
        let psbt = Psbt::deserialize(&hex_decode(psbt_hex).unwrap()).unwrap();
        let prevout = psbt.inputs[0].witness_utxo.clone().unwrap();

        let commit: [u8; 32] =
            sha256::Hash::hash(&hex_to_32(&"cd".repeat(32)).unwrap()).to_byte_array();
        let coop = ark::contract_cooperative_script(
            &commit,
            &hex_to_32(&server_pk_hex()).unwrap(),
            &hex_to_32(&"02".repeat(32)).unwrap(),
        );
        let leaf_hash =
            TapLeafHash::from_script(&ScriptBuf::from_bytes(coop), LeafVersion::TapScript);
        let recomputed = SighashCache::new(&psbt.unsigned_tx)
            .taproot_script_spend_signature_hash(
                0,
                &Prevouts::All(std::slice::from_ref(&prevout)),
                leaf_hash,
                TapSighashType::Default,
            )
            .unwrap()
            .to_byte_array();
        assert_eq!(hex_encode(&recomputed), sighash_hex);

        // The contract args ride the PSBT proprietary map under EVTXO/0x01.
        let args = psbt.inputs[0]
            .proprietary
            .iter()
            .find(|(k, _)| {
                k.prefix.as_slice() == CONTRACT_ARGS_PREFIX
                    && k.subtype == CONTRACT_ARGS_SUBTYPE
                    && k.key.is_empty()
            })
            .map(|(_, v)| v.clone())
            .unwrap();
        assert_eq!(args, b"ORACLE-OK");
    }

    #[test]
    fn finalize_assembles_five_item_witness_with_correct_sizes() {
        let out = build_evtxo_spend(&build_params()).unwrap();
        let handle = serde_json::from_str::<serde_json::Value>(&out).unwrap()["handle"]
            .as_u64()
            .unwrap();

        // A dummy V′ sig is fine: witness assembly doesn't verify it (consensus
        // does, at broadcast). We only check the witness shape here.
        let dummy_v_prime = hex_encode(&[0x11u8; 64]);
        let raw_hex = finalize_evtxo_spend(handle, &dummy_v_prime, SIGNER_SK).unwrap();
        let tx: Transaction =
            bitcoin::consensus::deserialize(&hex_decode(&raw_hex).unwrap()).unwrap();

        let w: Vec<&[u8]> = tx.input[0].witness.iter().collect();
        assert_eq!(w.len(), 5, "witness items");
        assert_eq!(w[0].len(), 64, "v_prime_sig");
        assert_eq!(w[1].len(), 64, "server_sig");
        assert_eq!(w[2].len(), 32, "contract_id");
        assert_eq!(w[2], &[0xcd_u8; 32][..], "contract_id bytes"); // sha256-preimage = 0xcd*32
        // w[3] = coop script, w[4] = control block (0xc0|parity + 32 + path).
        assert!(w[3].len() > 32, "coop script");
        assert_eq!((w[4].len() - 1) % 32, 0, "control block is 33 + 32*k");
        free_evtxo_spend(handle);
    }

    #[test]
    fn finalize_rejects_wrong_signer_key() {
        let out = build_evtxo_spend(&build_params()).unwrap();
        let handle = serde_json::from_str::<serde_json::Value>(&out).unwrap()["handle"]
            .as_u64()
            .unwrap();
        let wrong_sk = "11".repeat(32);
        let err = finalize_evtxo_spend(handle, &hex_encode(&[0x11u8; 64]), &wrong_sk).unwrap_err();
        assert!(err.contains("server_pk"), "got: {err}");
        free_evtxo_spend(handle);
    }
}
