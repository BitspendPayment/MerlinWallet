//! FFI for the `enclave-client` verifier.
//!
//! One stateless call: is this document, arriving on a connection that served this certificate
//! over this nonce, from the enclave these pins describe? The caller owns the network — it sends
//! the nonce, reads `x-enclave-attestation` and the peer certificate off its own socket, and
//! passes the bytes in.

use std::ffi::{CStr, CString};
use std::os::raw::c_char;
use std::slice;
use std::time::{Duration, UNIX_EPOCH};

use enclave_client::{verify_connection, Pins};
use serde::Serialize;

#[derive(Serialize)]
struct ConnectionVerifyResult {
    ok: bool,
    /// Hex SHA-256 of the certificate the document binds — the one to pin later connections to.
    #[serde(skip_serializing_if = "String::is_empty")]
    certificate_sha256: String,
    /// Hex SHA-256 of the guest component the enclave serves.
    #[serde(skip_serializing_if = "String::is_empty")]
    guest_sha256: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    timestamp_ms: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    error: Option<String>,
}

fn to_c_string(s: &str) -> *mut c_char {
    CString::new(s).unwrap_or_default().into_raw()
}

fn from_c_str(ptr: *const c_char) -> String {
    if ptr.is_null() {
        return String::new();
    }
    unsafe { CStr::from_ptr(ptr) }.to_string_lossy().into_owned()
}

fn from_bytes<'a>(ptr: *const u8, len: usize) -> &'a [u8] {
    if ptr.is_null() || len == 0 {
        &[]
    } else {
        unsafe { slice::from_raw_parts(ptr, len) }
    }
}

fn refuse(error: String) -> *mut c_char {
    to_c_string(
        &serde_json::to_string(&ConnectionVerifyResult {
            ok: false,
            certificate_sha256: String::new(),
            guest_sha256: String::new(),
            timestamp_ms: None,
            error: Some(error),
        })
        .unwrap_or_default(),
    )
}

/// Verify an enclave-runtime attestation document against pins and the connection it arrived on.
///
/// - `doc` — the COSE_Sign1 bytes, base64-decoded from `x-enclave-attestation`.
/// - `trust_root` — DER or PEM of the pinned root (the AWS Nitro root in production).
/// - `pcr0_hex`, `pcr16_hex` — the pinned image and guest measurements, 96 hex characters each.
/// - `served_certificate` — DER of the leaf certificate the TLS connection presented.
/// - `nonce` — the bytes sent in `x-enclave-nonce`, decoded.
/// - `now_unix_ms`, `max_age_secs` — the clock, and how old a document may be.
///
/// Returns JSON, freed with `enclave_string_free`:
///   `{"ok":true,"certificate_sha256":"…","guest_sha256":"…","timestamp_ms":…}`
///   `{"ok":false,"error":"…"}`
#[no_mangle]
pub extern "C" fn enclave_verify_connection(
    doc_ptr: *const u8,
    doc_len: usize,
    trust_root_ptr: *const u8,
    trust_root_len: usize,
    pcr0_hex: *const c_char,
    pcr16_hex: *const c_char,
    served_ptr: *const u8,
    served_len: usize,
    nonce_ptr: *const u8,
    nonce_len: usize,
    now_unix_ms: u64,
    max_age_secs: u64,
) -> *mut c_char {
    let pcr = |name: &str, ptr| {
        hex::decode(from_c_str(ptr)).map_err(|e| format!("{name} is not hex: {e}"))
    };
    let (pcr0, pcr16) = match (pcr("pcr0", pcr0_hex), pcr("pcr16", pcr16_hex)) {
        (Ok(a), Ok(b)) => (a, b),
        (Err(e), _) | (_, Err(e)) => return refuse(e),
    };
    let pins = Pins {
        trust_root: from_bytes(trust_root_ptr, trust_root_len).to_vec(),
        pcr0,
        pcr16,
        max_age: Duration::from_secs(max_age_secs),
    };

    match verify_connection(
        from_bytes(doc_ptr, doc_len),
        &pins,
        from_bytes(served_ptr, served_len),
        from_bytes(nonce_ptr, nonce_len),
        UNIX_EPOCH + Duration::from_millis(now_unix_ms),
    ) {
        Ok(attested) => to_c_string(
            &serde_json::to_string(&ConnectionVerifyResult {
                ok: true,
                certificate_sha256: hex::encode(attested.certificate_sha256),
                guest_sha256: hex::encode(attested.guest_sha256),
                timestamp_ms: Some(attested.document.timestamp_ms),
                error: None,
            })
            .unwrap_or_default(),
        ),
        Err(e) => refuse(e.to_string()),
    }
}

/// Free a string returned by `enclave_verify_connection`.
#[no_mangle]
pub extern "C" fn enclave_string_free(s: *mut c_char) {
    if !s.is_null() {
        unsafe {
            drop(CString::from_raw(s));
        }
    }
}
