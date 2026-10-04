//! Authentication FFI functions.

use super::handles::box_handle;
use super::{read_bytes, read_cstr, FfiResult};
use std::os::raw::{c_char, c_void};

use threshold::auth;

// ---------------------------------------------------------------------------
// AuthSigner Create
// ---------------------------------------------------------------------------

/// Create an AuthSigner from a secret key.
///
/// - `secret_hex`: 64-char hex scalar (32 bytes).
///
/// Returns FfiResult with:
/// - `handle`: opaque AuthSigner pointer.
/// - `data`: compressed public key hex (66 chars).
#[no_mangle]
pub extern "C" fn threshold_auth_signer_create(
    secret_hex: *const c_char,
) -> *mut FfiResult {
    let result = (|| -> Result<(String, *mut c_void), String> {
        let secret_str = read_cstr(secret_hex).ok_or("null secret_hex")?;
        let bytes = crate::from_hex::<[u8; 32]>(&secret_str)?;

        let signer = auth::AuthSigner::from_secret_bytes(&bytes)
            .map_err(|e| format!("AuthSigner creation failed: {e}"))?;

        let pk_hex = hex::encode(signer.public_key_compressed());
        let handle = box_handle(signer);
        Ok((pk_hex, handle))
    })();

    match result {
        Ok((data, handle)) => FfiResult::ok_with_handle(&data, handle),
        Err(e) => FfiResult::err(&e),
    }
}

// ---------------------------------------------------------------------------
// AuthSigner Sign
// ---------------------------------------------------------------------------

/// Sign a message with an AuthSigner.
///
/// - `signer_handle`: opaque AuthSigner pointer (borrowed).
/// - `msg_ptr`/`msg_len`: message bytes.
///
/// Returns FfiResult with:
/// - `data`: signature hex (128 chars = 64 bytes).
#[no_mangle]
pub extern "C" fn threshold_auth_signer_sign(
    signer_handle: *mut c_void,
    msg_ptr: *const u8,
    msg_len: u32,
) -> *mut FfiResult {
    let result = (|| -> Result<String, String> {
        let signer = unsafe {
            super::handles::borrow_handle::<auth::AuthSigner>(signer_handle)
        }
        .ok_or("null signer_handle")?;

        let message = read_bytes(msg_ptr, msg_len).ok_or("null or empty message")?;
        let sig = signer.sign(&message);
        Ok(hex::encode(sig))
    })();

    match result {
        Ok(data) => FfiResult::ok(&data),
        Err(e) => FfiResult::err(&e),
    }
}

// ---------------------------------------------------------------------------
// AuthSigner Public Key
// ---------------------------------------------------------------------------

/// Get the compressed public key from an AuthSigner.
///
/// Returns FfiResult with:
/// - `data`: compressed public key hex (66 chars).
#[no_mangle]
pub extern "C" fn threshold_auth_signer_public_key(
    signer_handle: *mut c_void,
) -> *mut FfiResult {
    let result = (|| -> Result<String, String> {
        let signer = unsafe {
            super::handles::borrow_handle::<auth::AuthSigner>(signer_handle)
        }
        .ok_or("null signer_handle")?;

        Ok(hex::encode(signer.public_key_compressed()))
    })();

    match result {
        Ok(data) => FfiResult::ok(&data),
        Err(e) => FfiResult::err(&e),
    }
}

// ---------------------------------------------------------------------------
// Verify Schnorr Signature
// ---------------------------------------------------------------------------

/// Verify a BIP-340 Schnorr signature.
///
/// - `pk_hex`: compressed public key hex (66 chars).
/// - `msg_ptr`/`msg_len`: message bytes.
/// - `sig_hex`: signature hex (128 chars = 64 bytes).
///
/// Returns FfiResult with:
/// - `data`: "true" or "false".
#[no_mangle]
pub extern "C" fn threshold_verify_schnorr_signature(
    pk_hex: *const c_char,
    msg_ptr: *const u8,
    msg_len: u32,
    sig_hex: *const c_char,
) -> *mut FfiResult {
    let result = (|| -> Result<String, String> {
        let pk_str = read_cstr(pk_hex).ok_or("null pk_hex")?;
        let sig_str = read_cstr(sig_hex).ok_or("null sig_hex")?;

        let pk_bytes = crate::from_hex::<[u8; 33]>(&pk_str)?;
        let sig_bytes = crate::from_hex::<[u8; 64]>(&sig_str)?;
        let message = read_bytes(msg_ptr, msg_len).ok_or("null or empty message")?;

        let valid = auth::verify_schnorr_signature(&pk_bytes, &message, &sig_bytes);
        Ok(valid.to_string())
    })();

    match result {
        Ok(data) => FfiResult::ok(&data),
        Err(e) => FfiResult::err(&e),
    }
}
