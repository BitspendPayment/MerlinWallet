//! Pure JSON / hex parsing helpers used across handlers. All static — no
//! `&self`, no shared services.

use std::collections::HashMap;
use std::time::{SystemTime, UNIX_EPOCH};

use threshold::keys::PublicKeyPackage;
use tonic::Status;

/// Tweak a public key package (BIP-341 key-path; pure public math, no secret) and return its
/// JSON. Host-side replacement for the legacy in-WASM `pub_key_package_tweak` call — used only
/// for address/script derivation and verification, never signing.
pub fn pub_key_package_tweak_json(
    pkp_json: &str,
    merkle_root: Option<&[u8]>,
) -> Result<String, Status> {
    let pkp = PublicKeyPackage::from_json(pkp_json)
        .map_err(|e| Status::internal(format!("bad public key package JSON: {e}")))?;
    Ok(pkp.tweak(merkle_root).to_json())
}

pub fn user_id_hex(user_id: &[u8]) -> String {
    hex::encode(user_id)
}

pub fn now_ms() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_millis() as i64
}

pub fn parse_round2_result(json_str: &str) -> Result<HashMap<String, String>, Status> {
    let v: serde_json::Value = serde_json::from_str(json_str)
        .map_err(|e| Status::internal(format!("bad round2 result: {e}")))?;
    let obj = v
        .as_object()
        .ok_or_else(|| Status::internal("expected round2 packages object"))?;
    let mut result = HashMap::new();
    for (k, v) in obj {
        result.insert(k.clone(), v.to_string());
    }
    Ok(result)
}

pub fn extract_secret_share(kp_json: &str) -> Result<String, Status> {
    let v: serde_json::Value = serde_json::from_str(kp_json)
        .map_err(|e| Status::internal(format!("bad key package JSON: {e}")))?;
    v["secretShare"]
        .as_str()
        .map(|s| s.to_string())
        .ok_or_else(|| Status::internal("missing secretShare in key package"))
}

pub fn extract_identifier(kp_json: &str) -> Result<String, Status> {
    let v: serde_json::Value = serde_json::from_str(kp_json)
        .map_err(|e| Status::internal(format!("bad key package JSON: {e}")))?;
    v["identifier"]
        .as_str()
        .map(|s| s.to_string())
        .ok_or_else(|| Status::internal("missing identifier in key package"))
}

/// The recipient's signing identifier `id_i` = the entry of a 2-entry `V′` PKP whose
/// id is NOT the cosigner's. Used by a contract actor to insert the recipient's FROST
/// commitment/share at its real `V′` identifier (the author's existing V identifier,
/// or a refreshed participant's derived id) — which is generally NOT `derive(user_id)`.
pub fn extract_recipient_identifier(
    pkp_json: &str,
    cosigner_id_hex: &str,
) -> Result<String, Status> {
    let v: serde_json::Value = serde_json::from_str(pkp_json)
        .map_err(|e| Status::internal(format!("bad public key package JSON: {e}")))?;
    let shares = v["verifyingShares"]
        .as_object()
        .ok_or_else(|| Status::internal("missing verifyingShares in PKP"))?;
    shares
        .keys()
        .find(|k| k.as_str() != cosigner_id_hex)
        .cloned()
        .ok_or_else(|| Status::internal("no recipient identifier in V′ PKP"))
}

pub fn extract_verifying_key(pkp_json: &str) -> Result<String, Status> {
    let v: serde_json::Value = serde_json::from_str(pkp_json)
        .map_err(|e| Status::internal(format!("bad public key package JSON: {e}")))?;
    v["verifyingKey"]
        .as_str()
        .map(|s| s.to_string())
        .ok_or_else(|| Status::internal("missing verifyingKey in public key package"))
}

pub fn extract_verifying_share(pkp_json: &str, id_hex: &str) -> Result<String, Status> {
    let v: serde_json::Value = serde_json::from_str(pkp_json)
        .map_err(|e| Status::internal(format!("bad public key package JSON: {e}")))?;
    v["verifyingShares"][id_hex]
        .as_str()
        .map(|s| s.to_string())
        .ok_or_else(|| Status::internal(format!("missing verifying share for {id_hex}")))
}

/// Build the signing package JSON consumed by `frost_sign` / `frost_aggregate`.
/// `commitments_json` is `{"id": "comms_json_str", ...}` (string-wrapped values).
pub fn build_signing_package_json(
    commitments_json: &str,
    message_hex: &str,
) -> Result<String, Status> {
    let comms_val: serde_json::Value = serde_json::from_str(commitments_json)
        .map_err(|e| Status::internal(format!("bad commitments JSON: {e}")))?;
    let comms_obj = comms_val
        .as_object()
        .ok_or_else(|| Status::internal("commitments not an object"))?;

    let mut parsed_comms = serde_json::Map::new();
    for (id, val) in comms_obj {
        let inner_json = val
            .as_str()
            .ok_or_else(|| Status::internal("commitment value not a string"))?;
        let parsed: serde_json::Value = serde_json::from_str(inner_json)
            .map_err(|e| Status::internal(format!("bad inner commitment JSON: {e}")))?;
        parsed_comms.insert(id.clone(), parsed);
    }
    let pkg = serde_json::json!({
        "commitments": serde_json::Value::Object(parsed_comms),
        "message": message_hex,
    });
    Ok(pkg.to_string())
}

/// Parse a JSON object of string-wrapped values into a HashMap.
pub fn parse_json_string_map(json: &str) -> Result<HashMap<String, String>, Status> {
    let v: serde_json::Value =
        serde_json::from_str(json).map_err(|e| Status::internal(format!("bad JSON: {e}")))?;
    let obj = v
        .as_object()
        .ok_or_else(|| Status::internal("expected JSON object"))?;
    let mut result = HashMap::new();
    for (k, v) in obj {
        let s = v
            .as_str()
            .map(|s| s.to_string())
            .unwrap_or_else(|| v.to_string());
        result.insert(k.clone(), s);
    }
    Ok(result)
}
