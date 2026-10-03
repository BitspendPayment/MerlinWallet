//! Reading values out of the JSON forms the threshold crate serializes its packages to.

use crate::grpc::Status;

/// The group key of a public key package, as the hex its JSON form carries.
pub(crate) fn extract_verifying_key(pkp_json: &str) -> Result<String, Status> {
    let v: serde_json::Value = serde_json::from_str(pkp_json)
        .map_err(|e| Status::internal(format!("bad public key package JSON: {e}")))?;
    v["verifyingKey"]
        .as_str()
        .map(|s| s.to_string())
        .ok_or_else(|| Status::internal("missing verifyingKey in public key package"))
}
