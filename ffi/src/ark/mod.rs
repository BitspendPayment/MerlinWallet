//! C-ABI FFI bindings for the Ark protocol library.
//!
//! All functions return a heap-allocated [`FfiResult`] that must be freed
//! with [`ark_free_result`].

use std::ffi::{CStr, CString};
use std::os::raw::c_char;
use std::ptr;

use ark::taptree::TapLeaf;

mod address;
mod evtxo_address;
mod evtxo_spend;
mod exit;
mod send;

// ---------------------------------------------------------------------------
// FfiResult
// ---------------------------------------------------------------------------

/// Result struct returned by every ark FFI function.
///
/// - `success`: true if the operation succeeded.
/// - `data`: JSON or hex string on success (null on failure).
/// - `error`: error message on failure (null on success).
#[repr(C)]
pub struct FfiResult {
    pub success: bool,
    pub data: *mut c_char,
    pub error: *mut c_char,
}

impl FfiResult {
    fn ok(data: &str) -> *mut Self {
        let c_data = CString::new(data).unwrap_or_default();
        Box::into_raw(Box::new(FfiResult {
            success: true,
            data: c_data.into_raw(),
            error: ptr::null_mut(),
        }))
    }

    fn err(msg: &str) -> *mut Self {
        let c_error = CString::new(msg).unwrap_or_default();
        Box::into_raw(Box::new(FfiResult {
            success: false,
            data: ptr::null_mut(),
            error: c_error.into_raw(),
        }))
    }
}

// ---------------------------------------------------------------------------
// Memory management
// ---------------------------------------------------------------------------

/// Free an FfiResult returned by any ark_* function.
#[no_mangle]
pub extern "C" fn ark_free_result(ptr: *mut FfiResult) {
    if ptr.is_null() {
        return;
    }
    unsafe {
        let result = Box::from_raw(ptr);
        if !result.data.is_null() {
            drop(CString::from_raw(result.data));
        }
        if !result.error.is_null() {
            drop(CString::from_raw(result.error));
        }
    }
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/// Read a C string pointer as a &str. Returns None if null or invalid UTF-8.
fn read_cstr(ptr: *const c_char) -> Option<String> {
    if ptr.is_null() {
        return None;
    }
    unsafe { CStr::from_ptr(ptr).to_str().ok().map(|s| s.to_string()) }
}

/// Helper: decode hex string to bytes.
fn hex_decode(s: &str) -> Result<Vec<u8>, String> {
    // `hex::decode` rejects odd length + invalid chars and never panics (the old
    // `&s[i..i+2]` slicing could panic on a non-char-boundary multi-byte UTF-8 input).
    hex::decode(s).map_err(|e| format!("invalid hex: {e}"))
}

/// Helper: decode hex to 32-byte array.
fn hex_to_32(s: &str) -> Result<[u8; 32], String> {
    let bytes = hex_decode(s)?;
    if bytes.len() != 32 {
        return Err(format!("expected 32 bytes, got {}", bytes.len()));
    }
    let mut out = [0u8; 32];
    out.copy_from_slice(&bytes);
    Ok(out)
}

/// Helper: encode bytes as hex string.
fn hex_encode(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{:02x}", b)).collect()
}

// ---------------------------------------------------------------------------
// Ark protocol FFI functions
// ---------------------------------------------------------------------------

/// Compute the default VTXO script pubkey for the given keys and exit delay.
///
/// Returns hex-encoded 34-byte script pubkey (OP_1 <x-only tweaked key>).
#[no_mangle]
pub extern "C" fn ark_default_vtxo_script_pubkey(
    server_pk_hex: *const c_char,
    owner_pk_hex: *const c_char,
    exit_delay: u32,
) -> *mut FfiResult {
    let result = (|| -> Result<String, String> {
        let server_hex = read_cstr(server_pk_hex).ok_or("null server_pk_hex")?;
        let owner_hex = read_cstr(owner_pk_hex).ok_or("null owner_pk_hex")?;
        let server_pk = hex_to_32(&server_hex)?;
        let owner_pk = hex_to_32(&owner_hex)?;

        let tree = ark::default_vtxo_tree(&server_pk, &owner_pk, exit_delay);
        let spk = ark::vtxo_script_pubkey(&tree)
            .map_err(|e| format!("vtxo_script_pubkey: {e}"))?;
        Ok(hex_encode(&spk))
    })();

    match result {
        Ok(data) => FfiResult::ok(&data),
        Err(e) => FfiResult::err(&e),
    }
}

/// Get forfeit (cooperative) spend info for a default Ark VTXO.
///
/// Returns JSON: `{"script_hex": "...", "control_block_hex": "..."}`
#[no_mangle]
pub extern "C" fn ark_forfeit_spend_info(
    server_pk_hex: *const c_char,
    owner_pk_hex: *const c_char,
    exit_delay: u32,
) -> *mut FfiResult {
    let result = (|| -> Result<String, String> {
        let server_hex = read_cstr(server_pk_hex).ok_or("null server_pk_hex")?;
        let owner_hex = read_cstr(owner_pk_hex).ok_or("null owner_pk_hex")?;
        let server_pk = hex_to_32(&server_hex)?;
        let owner_pk = hex_to_32(&owner_hex)?;

        let (script, cb) = ark::forfeit_spend_info(&server_pk, &owner_pk, exit_delay)
            .ok_or("forfeit_spend_info failed")?;
        let json = format!(
            r#"{{"script_hex":"{}","control_block_hex":"{}"}}"#,
            hex_encode(&script),
            hex_encode(&cb.serialize()),
        );
        Ok(json)
    })();

    match result {
        Ok(data) => FfiResult::ok(&data),
        Err(e) => FfiResult::err(&e),
    }
}

/// Get exit (unilateral) spend info for a default Ark VTXO.
///
/// Returns JSON: `{"script_hex": "...", "control_block_hex": "..."}`
#[no_mangle]
pub extern "C" fn ark_exit_spend_info(
    server_pk_hex: *const c_char,
    owner_pk_hex: *const c_char,
    exit_delay: u32,
) -> *mut FfiResult {
    let result = (|| -> Result<String, String> {
        let server_hex = read_cstr(server_pk_hex).ok_or("null server_pk_hex")?;
        let owner_hex = read_cstr(owner_pk_hex).ok_or("null owner_pk_hex")?;
        let server_pk = hex_to_32(&server_hex)?;
        let owner_pk = hex_to_32(&owner_hex)?;

        let (script, cb) = ark::exit_spend_info(&server_pk, &owner_pk, exit_delay)
            .ok_or("exit_spend_info failed")?;
        let json = format!(
            r#"{{"script_hex":"{}","control_block_hex":"{}"}}"#,
            hex_encode(&script),
            hex_encode(&cb.serialize()),
        );
        Ok(json)
    })();

    match result {
        Ok(data) => FfiResult::ok(&data),
        Err(e) => FfiResult::err(&e),
    }
}

/// Build a forfeit/cooperative multisig script.
///
/// Returns hex-encoded script bytes.
#[no_mangle]
pub extern "C" fn ark_multisig_script(
    server_pk_hex: *const c_char,
    owner_pk_hex: *const c_char,
) -> *mut FfiResult {
    let result = (|| -> Result<String, String> {
        let server_hex = read_cstr(server_pk_hex).ok_or("null server_pk_hex")?;
        let owner_hex = read_cstr(owner_pk_hex).ok_or("null owner_pk_hex")?;
        let server_pk = hex_to_32(&server_hex)?;
        let owner_pk = hex_to_32(&owner_hex)?;

        let script = ark::multisig_script(&server_pk, &owner_pk);
        Ok(hex_encode(&script))
    })();

    match result {
        Ok(data) => FfiResult::ok(&data),
        Err(e) => FfiResult::err(&e),
    }
}

/// Build a CSV + signature exit script.
///
/// Returns hex-encoded script bytes.
#[no_mangle]
pub extern "C" fn ark_csv_sig_script(
    exit_delay: u32,
    owner_pk_hex: *const c_char,
) -> *mut FfiResult {
    let result = (|| -> Result<String, String> {
        let owner_hex = read_cstr(owner_pk_hex).ok_or("null owner_pk_hex")?;
        let owner_pk = hex_to_32(&owner_hex)?;

        let script = ark::csv_sig_script(exit_delay, &owner_pk);
        Ok(hex_encode(&script))
    })();

    match result {
        Ok(data) => FfiResult::ok(&data),
        Err(e) => FfiResult::err(&e),
    }
}

/// Compute the TapLeaf hash of a script (using default tapscript leaf version 0xc0).
///
/// Returns hex-encoded 32-byte leaf hash.
#[no_mangle]
pub extern "C" fn ark_tapleaf_hash(
    script_hex: *const c_char,
) -> *mut FfiResult {
    let result = (|| -> Result<String, String> {
        let hex_str = read_cstr(script_hex).ok_or("null script_hex")?;
        let script_bytes = hex_decode(&hex_str)?;

        let leaf = TapLeaf::new(script_bytes);
        Ok(hex_encode(&leaf.hash()))
    })();

    match result {
        Ok(data) => FfiResult::ok(&data),
        Err(e) => FfiResult::err(&e),
    }
}

// ---------------------------------------------------------------------------
// Ark Send FFI functions
// ---------------------------------------------------------------------------

/// Build an off-chain Ark send transaction.
///
/// Input: JSON string with BuildSendParams.
/// Returns JSON: `{"handle": <u64>, "sighashes": ["hex"...], "ark_tx_bytes": "hex"}`
#[no_mangle]
pub extern "C" fn ark_build_send_tx(params_json: *const c_char) -> *mut FfiResult {
    let result = (|| -> Result<String, String> {
        let json = read_cstr(params_json).ok_or("null params_json")?;
        send::build_send_tx(&json)
    })();
    match result {
        Ok(data) => FfiResult::ok(&data),
        Err(e) => FfiResult::err(&e),
    }
}

/// Insert FROST signatures into a send session's PSBTs.
///
/// Input: handle (u64), signatures as JSON array of hex strings.
/// Returns JSON: `{"signed_ark_tx_b64": "...", "signed_checkpoint_txs_b64": [...]}`
#[no_mangle]
pub extern "C" fn ark_insert_send_signatures(
    handle: u64,
    signatures_json: *const c_char,
) -> *mut FfiResult {
    let result = (|| -> Result<String, String> {
        let json = read_cstr(signatures_json).ok_or("null signatures_json")?;
        send::insert_send_signatures(handle, &json)
    })();
    match result {
        Ok(data) => FfiResult::ok(&data),
        Err(e) => FfiResult::err(&e),
    }
}

/// Get change VTXO info from a send session.
///
/// Returns JSON: `{"txid": "...", "vout": <u32>, "amount": <u64>}` or `"null"`.
#[no_mangle]
pub extern "C" fn ark_get_change_vtxo(handle: u64) -> *mut FfiResult {
    match send::get_change_vtxo(handle) {
        Ok(data) => FfiResult::ok(&data),
        Err(e) => FfiResult::err(&e),
    }
}

/// Free a send session.
#[no_mangle]
pub extern "C" fn ark_free_send_session(handle: u64) {
    send::free_send_session(handle);
}

// ---------------------------------------------------------------------------
// eVTXO cooperative-spend FFI functions
// ---------------------------------------------------------------------------

/// Build an on-chain spend of an eVTXO's cooperative (contract-gated) leaf.
///
/// Input: JSON string with `BuildEvtxoSpendParams`.
/// Returns JSON: `{"handle": <u64>, "sighash": "hex", "psbt": "hex", "evtxo_spk": "hex"}`.
/// Pass `psbt` to the cosigner's `sign` as `fullTransaction` (it carries the
/// eVTXO `witness_utxo` + the contract args); `sign` the `sighash` with
/// `applyTweak:false` to get the V′ leg.
#[no_mangle]
pub extern "C" fn ark_build_evtxo_spend(params_json: *const c_char) -> *mut FfiResult {
    let result = (|| -> Result<String, String> {
        let json = read_cstr(params_json).ok_or("null params_json")?;
        evtxo_spend::build_evtxo_spend(&json)
    })();
    match result {
        Ok(data) => FfiResult::ok(&data),
        Err(e) => FfiResult::err(&e),
    }
}

/// Finalize an eVTXO cooperative spend: assemble the witness from the V′ FROST
/// signature plus a server-leg signature produced from the ASP signer key.
///
/// Input: handle (u64), `v_prime_sig_hex` (64-byte hex), `signer_sk_hex` (the ASP
/// signer secret key; its x-only pubkey must equal the built `server_pk`).
/// Returns the raw signed transaction hex, ready for `sendrawtransaction`.
#[no_mangle]
pub extern "C" fn ark_finalize_evtxo_spend(
    handle: u64,
    v_prime_sig_hex: *const c_char,
    signer_sk_hex: *const c_char,
) -> *mut FfiResult {
    let result = (|| -> Result<String, String> {
        let v_prime = read_cstr(v_prime_sig_hex).ok_or("null v_prime_sig_hex")?;
        let signer_sk = read_cstr(signer_sk_hex).ok_or("null signer_sk_hex")?;
        evtxo_spend::finalize_evtxo_spend(handle, &v_prime, &signer_sk)
    })();
    match result {
        Ok(data) => FfiResult::ok(&data),
        Err(e) => FfiResult::err(&e),
    }
}

/// Free an eVTXO spend session.
#[no_mangle]
pub extern "C" fn ark_free_evtxo_spend(handle: u64) {
    evtxo_spend::free_evtxo_spend(handle);
}

/// Derive the Ark address for an eVTXO output key, so a normal off-chain send can
/// mint a VTXO at it through arkd.
///
/// Input: JSON `{ "server_pk": hex, "q_evtxo": hex, "network": "regtest" }`.
/// Returns the bech32m Ark address string.
#[no_mangle]
pub extern "C" fn ark_evtxo_ark_address(params_json: *const c_char) -> *mut FfiResult {
    let result = (|| -> Result<String, String> {
        let json = read_cstr(params_json).ok_or("null params_json")?;
        evtxo_address::evtxo_ark_address(&json)
    })();
    match result {
        Ok(data) => FfiResult::ok(&data),
        Err(e) => FfiResult::err(&e),
    }
}

#[cfg(test)]
mod tests {
    #[test]
    fn test_parse_sequence() {
        let seq = ark_core::server::parse_sequence_number(86016).unwrap();
        println!("Sequence for 86016: {} = 0x{:08x}", seq.0, seq.0);
        let rl = seq.to_relative_lock_time();
        println!("Relative lock time: {:?}", rl);
        assert!(matches!(rl, Some(bitcoin::relative::LockTime::Time(_))));
    }
}
