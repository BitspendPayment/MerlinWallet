//! FROST signing FFI functions.

use super::handles::box_handle;
use super::{read_cstr, FfiResult};
use std::collections::BTreeMap;
use std::os::raw::{c_char, c_void};

use rand::rngs::OsRng;
use threshold::commitment::SigningPackage;
use threshold::identifier::Identifier;
use threshold::keys::{KeyPackage, PublicKeyPackage};
use std::sync::atomic::{AtomicBool, Ordering};
use threshold::nonce::{self, SigningCommitments};
use threshold::point;
use threshold::scalar::{scalar_from_bytes, scalar_to_bytes};
use threshold::signing;

fn parse_identifier_hex(hex: &str) -> Result<Identifier, String> {
    let bytes = crate::from_hex::<[u8; 32]>(hex)?;
    Identifier::deserialize(&bytes).map_err(|e| format!("bad identifier: {e}"))
}

/// Parse a signing package from JSON.
///
/// Format: { "commitments": { "id_hex": { "hiding": "hex33", "binding": "hex33" }, ... }, "message": "hex" }
fn parse_signing_package_json(json_str: &str) -> Result<SigningPackage, String> {
    let v: serde_json::Value =
        serde_json::from_str(json_str).map_err(|e| format!("bad JSON: {e}"))?;

    let comms_obj = v["commitments"]
        .as_object()
        .ok_or("expected commitments object")?;
    let mut commitments = BTreeMap::new();
    for (id_hex, comm_val) in comms_obj {
        let id = parse_identifier_hex(id_hex)?;
        let hiding_hex = comm_val["hiding"]
            .as_str()
            .ok_or("expected hiding hex")?;
        let binding_hex = comm_val["binding"]
            .as_str()
            .ok_or("expected binding hex")?;

        let hiding_bytes = crate::from_hex::<[u8; 33]>(hiding_hex)?;
        let binding_bytes = crate::from_hex::<[u8; 33]>(binding_hex)?;

        let hiding = point::deserialize_compressed(&hiding_bytes)
            .map_err(|e| format!("bad hiding point: {e}"))?;
        let binding = point::deserialize_compressed(&binding_bytes)
            .map_err(|e| format!("bad binding point: {e}"))?;

        commitments.insert(id, SigningCommitments { binding, hiding });
    }

    let message_hex = v["message"].as_str().ok_or("expected message hex")?;
    let message = crate::from_hex::<Vec<u8>>(message_hex)?;

    Ok(SigningPackage::new(commitments, message))
}

// ---------------------------------------------------------------------------
// New Nonce
// ---------------------------------------------------------------------------

/// Generate a signing nonce pair.
///
/// - `secret_hex`: 64-char hex of the signer's secret share scalar.
///
/// Returns FfiResult with:
/// - `data`: JSON { "hiding": "hex33", "binding": "hex33" } (public commitments).
/// - `handle`: opaque SigningNonce pointer.
#[no_mangle]
pub extern "C" fn threshold_new_nonce(secret_hex: *const c_char) -> *mut FfiResult {
    let result = (|| -> Result<(String, *mut c_void), String> {
        let secret_str = read_cstr(secret_hex).ok_or("null secret_hex")?;
        let secret = parse_scalar_hex(&secret_str)?;

        let mut rng = OsRng;
        let nonce = nonce::new_nonce(&mut rng, &secret);

        let hiding = hex::encode(point::serialize_compressed(&nonce.commitments.hiding));
        let binding = hex::encode(point::serialize_compressed(&nonce.commitments.binding));

        let data = serde_json::json!({
            "hiding": hiding,
            "binding": binding,
        })
        .to_string();

        // Box with a one-shot "spent" flag so `threshold_frost_sign` can enforce
        // FROST's single-use-nonce requirement.
        let handle = box_handle(super::FfiSigningNonce {
            nonce,
            spent: AtomicBool::new(false),
        });
        Ok((data, handle))
    })();

    match result {
        Ok((data, handle)) => FfiResult::ok_with_handle(&data, handle),
        Err(e) => FfiResult::err(&e),
    }
}

fn parse_scalar_hex(hex: &str) -> Result<k256::Scalar, String> {
    let bytes = crate::from_hex::<[u8; 32]>(hex)?;
    scalar_from_bytes(&bytes).map_err(|e| format!("bad scalar: {e}"))
}

// ---------------------------------------------------------------------------
// FROST Sign
// ---------------------------------------------------------------------------

/// Compute a FROST signature share.
///
/// - `signing_pkg_json`: JSON signing package.
/// - `nonce_handle`: opaque SigningNonce pointer (borrowed).
/// - `key_pkg_json`: JSON key package.
///
/// Returns FfiResult with:
/// - `data`: hex string of the signature share scalar (64 chars).
#[no_mangle]
pub extern "C" fn threshold_frost_sign(
    signing_pkg_json: *const c_char,
    nonce_handle: *mut c_void,
    key_pkg_json: *const c_char,
) -> *mut FfiResult {
    let result = (|| -> Result<String, String> {
        let pkg_str = read_cstr(signing_pkg_json).ok_or("null signing_pkg_json")?;
        let kp_str = read_cstr(key_pkg_json).ok_or("null key_pkg_json")?;

        let signing_pkg = parse_signing_package_json(&pkg_str)?;

        let nonce = unsafe { super::handles::borrow_handle::<super::FfiSigningNonce>(nonce_handle) }
            .ok_or("null nonce_handle")?;

        // SECURITY (single-use nonce): FROST nonce reuse across two signatures over
        // different challenges leaks the secret share. Atomically claim the nonce;
        // a second sign on the same handle fails closed. Each `signWithContext` on the
        // client mints a fresh nonce per message, so this never trips legitimate signing.
        if nonce.spent.swap(true, Ordering::SeqCst) {
            return Err("signing nonce already used (single-use only)".into());
        }

        let kp = KeyPackage::from_json(&kp_str).map_err(|e| format!("bad key package: {e}"))?;

        let share = signing::sign(&signing_pkg, &nonce.nonce, &kp)
            .map_err(|e| format!("sign failed: {e}"))?;

        Ok(hex::encode(scalar_to_bytes(&share.s)))
    })();

    match result {
        Ok(data) => FfiResult::ok(&data),
        Err(e) => FfiResult::err(&e),
    }
}

// ---------------------------------------------------------------------------
// FROST Aggregate
// ---------------------------------------------------------------------------

/// Aggregate signature shares into a final signature.
///
/// - `signing_pkg_json`: JSON signing package.
/// - `shares_json`: JSON object { "id_hex": "share_hex", ... }.
/// - `pub_key_pkg_json`: JSON public key package.
///
/// Returns FfiResult with:
/// - `data`: JSON { "R": "hex33", "Z": "hex64" } (signature components).
#[no_mangle]
pub extern "C" fn threshold_frost_aggregate(
    signing_pkg_json: *const c_char,
    shares_json: *const c_char,
    pub_key_pkg_json: *const c_char,
) -> *mut FfiResult {
    let result = (|| -> Result<String, String> {
        let pkg_str = read_cstr(signing_pkg_json).ok_or("null signing_pkg_json")?;
        let shares_str = read_cstr(shares_json).ok_or("null shares_json")?;
        let pkp_str = read_cstr(pub_key_pkg_json).ok_or("null pub_key_pkg_json")?;

        let signing_pkg = parse_signing_package_json(&pkg_str)?;

        let shares_val: serde_json::Value =
            serde_json::from_str(&shares_str).map_err(|e| format!("bad shares JSON: {e}"))?;
        let shares_obj = shares_val.as_object().ok_or("expected shares object")?;
        let mut shares = BTreeMap::new();
        for (id_hex, share_val) in shares_obj {
            let id = parse_identifier_hex(id_hex)?;
            let share_hex = share_val.as_str().ok_or("share must be hex string")?;
            let s = parse_scalar_hex(share_hex)?;
            shares.insert(id, signing::SignatureShare { s });
        }

        let pkp = PublicKeyPackage::from_json(&pkp_str)
            .map_err(|e| format!("bad public key package: {e}"))?;

        let signature = signing::aggregate(&signing_pkg, &shares, &pkp)
            .map_err(|e| format!("aggregate failed: {e}"))?;

        let r_hex = hex::encode(point::serialize_compressed(&signature.r));
        let z_hex = hex::encode(scalar_to_bytes(&signature.z));

        let data = serde_json::json!({
            "R": r_hex,
            "Z": z_hex,
        })
        .to_string();
        Ok(data)
    })();

    match result {
        Ok(data) => FfiResult::ok(&data),
        Err(e) => FfiResult::err(&e),
    }
}
