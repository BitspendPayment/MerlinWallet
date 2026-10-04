//! Utility FFI functions: identifiers, scalars, points, polynomials.

use super::{read_bytes, read_cstr, FfiResult};
use std::os::raw::c_char;

use rand::rngs::OsRng;
use threshold::identifier::Identifier;
use threshold::point;
use threshold::polynomial;
use threshold::random;
use threshold::scalar::{scalar_from_bytes, scalar_from_bytes_allow_zero, scalar_to_bytes};

// ---------------------------------------------------------------------------
// Identifier
// ---------------------------------------------------------------------------

/// Derive an identifier from arbitrary bytes (SHA-256 based).
///
/// - `msg_ptr`/`msg_len`: seed bytes.
///
/// Returns FfiResult with `data` = identifier hex (64 chars).
#[no_mangle]
pub extern "C" fn threshold_identifier_derive(
    msg_ptr: *const u8,
    msg_len: u32,
) -> *mut FfiResult {
    let result = (|| -> Result<String, String> {
        let msg = read_bytes(msg_ptr, msg_len).ok_or("null or empty msg")?;
        let id = Identifier::derive(&msg).map_err(|e| format!("derive failed: {e}"))?;
        Ok(hex::encode(id.serialize()))
    })();

    match result {
        Ok(data) => FfiResult::ok(&data),
        Err(e) => FfiResult::err(&e),
    }
}

/// Create an identifier from a BigInt hex scalar.
///
/// Returns FfiResult with `data` = identifier hex (64 chars).
#[no_mangle]
pub extern "C" fn threshold_identifier_from_bigint(
    hex_str: *const c_char,
) -> *mut FfiResult {
    let result = (|| -> Result<String, String> {
        let s = read_cstr(hex_str).ok_or("null hex_str")?;
        let bytes = crate::from_hex::<[u8; 32]>(&s)?;
        let id = Identifier::deserialize(&bytes).map_err(|e| format!("bad identifier: {e}"))?;
        Ok(hex::encode(id.serialize()))
    })();

    match result {
        Ok(data) => FfiResult::ok(&data),
        Err(e) => FfiResult::err(&e),
    }
}

// ---------------------------------------------------------------------------
// Scalar / Coefficient generation
// ---------------------------------------------------------------------------

/// Generate `count` random coefficients.
///
/// - `seed_ptr`/`seed_len`: optional seed for deterministic generation (null for random).
///
/// Returns FfiResult with `data` = JSON array of hex scalars.
#[no_mangle]
pub extern "C" fn threshold_generate_coefficients(
    count: u32,
    seed_ptr: *const u8,
    seed_len: u32,
) -> *mut FfiResult {
    let result = (|| -> Result<String, String> {
        let coeffs = if !seed_ptr.is_null() && seed_len > 0 {
            let seed = read_bytes(seed_ptr, seed_len).ok_or("bad seed")?;
            random::generate_coefficients_seeded(count as usize, &seed)
        } else {
            let mut rng = OsRng;
            random::generate_coefficients(count as usize, &mut rng)
        };

        let arr: Vec<serde_json::Value> = coeffs
            .iter()
            .map(|c| serde_json::Value::String(hex::encode(scalar_to_bytes(c))))
            .collect();
        Ok(serde_json::Value::Array(arr).to_string())
    })();

    match result {
        Ok(data) => FfiResult::ok(&data),
        Err(e) => FfiResult::err(&e),
    }
}

/// Evaluate a polynomial at a given identifier.
///
/// - `id_hex`: identifier hex (64 chars).
/// - `coeffs_json`: JSON array of hex scalars.
///
/// Returns FfiResult with `data` = result scalar hex (64 chars).
#[no_mangle]
pub extern "C" fn threshold_evaluate_polynomial(
    id_hex: *const c_char,
    coeffs_json: *const c_char,
) -> *mut FfiResult {
    let result = (|| -> Result<String, String> {
        let id_str = read_cstr(id_hex).ok_or("null id_hex")?;
        let coeffs_str = read_cstr(coeffs_json).ok_or("null coeffs_json")?;

        let id_bytes = crate::from_hex::<[u8; 32]>(&id_str)?;
        let id = Identifier::deserialize(&id_bytes).map_err(|e| format!("bad identifier: {e}"))?;

        let v: serde_json::Value =
            serde_json::from_str(&coeffs_str).map_err(|e| format!("bad JSON: {e}"))?;
        let arr = v.as_array().ok_or("expected JSON array")?;
        let mut coeffs = Vec::new();
        for item in arr {
            let hex = item.as_str().ok_or("coefficient must be hex string")?;
            let bytes = crate::from_hex::<[u8; 32]>(hex)?;
            coeffs.push(scalar_from_bytes_allow_zero(&bytes).map_err(|e| format!("bad scalar: {e}"))?);
        }

        let result = polynomial::evaluate_polynomial(&id, &coeffs);
        Ok(hex::encode(scalar_to_bytes(&result)))
    })();

    match result {
        Ok(data) => FfiResult::ok(&data),
        Err(e) => FfiResult::err(&e),
    }
}

/// Generate a random non-zero scalar.
///
/// Returns FfiResult with `data` = hex scalar (64 chars).
#[no_mangle]
pub extern "C" fn threshold_mod_n_random() -> *mut FfiResult {
    let mut rng = OsRng;
    let s = random::mod_n_random(&mut rng);
    FfiResult::ok(&hex::encode(scalar_to_bytes(&s)))
}

// ---------------------------------------------------------------------------
// Point operations
// ---------------------------------------------------------------------------

/// Compute scalar * G (base point multiplication).
///
/// - `scalar_hex`: 64-char hex scalar.
///
/// Returns FfiResult with `data` = compressed point hex (66 chars).
#[no_mangle]
pub extern "C" fn threshold_elem_base_mul(scalar_hex: *const c_char) -> *mut FfiResult {
    let result = (|| -> Result<String, String> {
        let s_str = read_cstr(scalar_hex).ok_or("null scalar_hex")?;
        let bytes = crate::from_hex::<[u8; 32]>(&s_str)?;
        let scalar = scalar_from_bytes(&bytes).map_err(|e| format!("bad scalar: {e}"))?;
        let p = point::base_mul(&scalar);
        Ok(hex::encode(point::serialize_compressed(&p)))
    })();

    match result {
        Ok(data) => FfiResult::ok(&data),
        Err(e) => FfiResult::err(&e),
    }
}

/// Serialize a point to compressed form (33 bytes).
///
/// Input is a compressed point hex (66 chars). This is effectively a no-op
/// validation — deserialize then re-serialize.
///
/// Returns FfiResult with `data` = compressed point hex (66 chars).
#[no_mangle]
pub extern "C" fn threshold_elem_serialize_compressed(
    point_hex: *const c_char,
) -> *mut FfiResult {
    let result = (|| -> Result<String, String> {
        let s = read_cstr(point_hex).ok_or("null point_hex")?;
        let bytes = crate::from_hex::<[u8; 33]>(&s)?;
        let p = point::deserialize_compressed(&bytes).map_err(|e| format!("bad point: {e}"))?;
        Ok(hex::encode(point::serialize_compressed(&p)))
    })();

    match result {
        Ok(data) => FfiResult::ok(&data),
        Err(e) => FfiResult::err(&e),
    }
}

/// Deserialize a compressed point (33 bytes).
///
/// - `hex_str`: compressed point hex (66 chars).
///
/// Returns FfiResult with `data` = compressed point hex (66 chars, validated).
#[no_mangle]
pub extern "C" fn threshold_elem_deserialize_compressed(
    hex_str: *const c_char,
) -> *mut FfiResult {
    let result = (|| -> Result<String, String> {
        let s = read_cstr(hex_str).ok_or("null hex_str")?;
        let bytes = crate::from_hex::<[u8; 33]>(&s)?;
        let p = point::deserialize_compressed(&bytes).map_err(|e| format!("bad point: {e}"))?;
        Ok(hex::encode(point::serialize_compressed(&p)))
    })();

    match result {
        Ok(data) => FfiResult::ok(&data),
        Err(e) => FfiResult::err(&e),
    }
}
