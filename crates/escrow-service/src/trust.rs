//! Which enclaves this service believes, and how it knows one spoke.
//!
//! Everything the enclave says here arrives as plain HTTP — the held `GET /escrow/stream` and one
//! `POST /escrow/send` per message — and a URL can be reached by anybody. Believing it on sight is
//! how a forged "not completed yet" once made a payout platform fund a payment nobody had sealed,
//! and how a customer running a cosigner of their own could have been paired as though it were
//! Merlin's. So the runtime attaches an attestation document to each request, binding the wire id
//! and the exact bytes to the measured image (see [`enclave_client::verify_stream`]), and nothing
//! here is taken without one that checks out against a pinned enclave.
//!
//! # Pins
//!
//! A pins file is the shape a deployment publishes as `deployment.json`: `pcr0` and `pcr16` in hex,
//! and `trust_root` — base64 DER — for an emulated enclave. Without one the root is AWS's. Several
//! may be given, for an upgrade that runs two images at once.
//!
//! A file is read again whenever it changes, and one that is missing pins nothing. A dev enclave
//! mints its root at every boot, so the platform starts before the enclave does and learns it when
//! the boot writes the file.

use std::path::PathBuf;
use std::sync::Mutex;
use std::time::{Duration, SystemTime};

use axum::http::HeaderMap;
use enclave_client::{verify_stream, Pins, AWS_NITRO_ROOT_G1_PEM, STREAM_ATTESTATION_HEADER};
use serde::Deserialize;

/// How old a document may be. The runtime signs one per request, so a real one is seconds old;
/// this allows for the two hosts' clocks and for nothing else.
const MAX_AGE: Duration = Duration::from_secs(300);

pub struct EnclaveTrust {
    sources: Vec<Source>,
    #[cfg(any(test, feature = "test-trust"))]
    accept_all: bool,
}

struct Source {
    path: PathBuf,
    /// What was read, as of the modification time it was read at.
    loaded: Mutex<(Option<SystemTime>, Option<Pins>)>,
}

#[derive(Deserialize)]
struct PinsFile {
    pcr0: String,
    pcr16: String,
    #[serde(default)]
    trust_root: Option<String>,
}

impl EnclaveTrust {
    /// Believe the enclaves these pins files name.
    pub fn from_files(paths: Vec<PathBuf>) -> Self {
        Self {
            sources: paths
                .into_iter()
                .map(|path| Source {
                    path,
                    loaded: Mutex::new((None, None)),
                })
                .collect(),
            #[cfg(any(test, feature = "test-trust"))]
            accept_all: false,
        }
    }

    /// Believe anybody. Tests only — see the `test-trust` feature.
    #[cfg(any(test, feature = "test-trust"))]
    pub fn accept_all() -> Self {
        Self {
            sources: Vec::new(),
            accept_all: true,
        }
    }

    /// Was this request sent by an enclave this service pins — exactly this body, as `kind`, on the
    /// connection `wire_id` names? `Ok` carries the document's time, in milliseconds, so a newer
    /// `open` can replace an older one and never the reverse.
    pub fn verify(
        &self,
        headers: &HeaderMap,
        kind: &str,
        wire_id: &str,
        body: &[u8],
    ) -> Result<u64, String> {
        #[cfg(any(test, feature = "test-trust"))]
        if self.accept_all {
            return Ok(SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map_or(0, |d| d.as_millis() as u64));
        }
        let encoded = headers
            .get(STREAM_ATTESTATION_HEADER)
            .ok_or("no attestation: this did not come through an enclave's runtime")?;
        use base64::Engine;
        let cose = base64::engine::general_purpose::STANDARD
            .decode(encoded.as_bytes())
            .map_err(|e| format!("the attestation is not base64: {e}"))?;

        let pins = self.pinned();
        if pins.is_empty() {
            return Err("this service pins no enclave yet".into());
        }
        let now = SystemTime::now();
        let mut why = String::new();
        for p in &pins {
            match verify_stream(&cose, p, kind, wire_id, body, now) {
                Ok(document) => return Ok(document.timestamp_ms),
                Err(e) => why = e.to_string(),
            }
        }
        Err(format!("the attestation does not check out: {why}"))
    }

    /// Every enclave pinned right now, reading a file again if it changed since it was last read.
    fn pinned(&self) -> Vec<Pins> {
        self.sources
            .iter()
            .filter_map(|source| {
                let modified = std::fs::metadata(&source.path)
                    .and_then(|m| m.modified())
                    .ok();
                let mut loaded = source.loaded.lock().unwrap();
                if modified.is_none() {
                    *loaded = (None, None);
                } else if loaded.0 != modified {
                    let pins = read_pins(&source.path).map_err(|e| {
                        tracing::warn!(path = %source.path.display(), error = %e, "pins unreadable; trusting nothing from them");
                    });
                    *loaded = (modified, pins.ok());
                }
                loaded.1.clone()
            })
            .collect()
    }
}

fn read_pins(path: &std::path::Path) -> Result<Pins, String> {
    let text = std::fs::read_to_string(path).map_err(|e| e.to_string())?;
    let file: PinsFile = serde_json::from_str(&text).map_err(|e| e.to_string())?;
    let pcr = |hex_value: &str, name: &str| -> Result<Vec<u8>, String> {
        let bytes = hex::decode(hex_value.trim()).map_err(|e| format!("{name}: {e}"))?;
        if bytes.len() != 48 {
            return Err(format!("{name} is {} bytes, not 48", bytes.len()));
        }
        Ok(bytes)
    };
    let trust_root = match file.trust_root.as_deref().filter(|r| !r.is_empty()) {
        Some(b64) => {
            use base64::Engine;
            // Loudly: a root that is not AWS's is an emulated enclave, whose documents prove only
            // that some copy of the pinned image produced them.
            tracing::warn!(path = %path.display(), "pinning an emulated enclave's attestation root, not AWS's");
            base64::engine::general_purpose::STANDARD
                .decode(b64.trim())
                .map_err(|e| format!("trust_root: {e}"))?
        }
        None => AWS_NITRO_ROOT_G1_PEM.as_bytes().to_vec(),
    };
    Ok(Pins {
        trust_root,
        pcr0: pcr(&file.pcr0, "pcr0")?,
        pcr16: pcr(&file.pcr16, "pcr16")?,
        max_age: MAX_AGE,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn trust(dir: &std::path::Path) -> (EnclaveTrust, PathBuf) {
        let path = dir.join("enclave-pins.json");
        (EnclaveTrust::from_files(vec![path.clone()]), path)
    }

    #[test]
    fn nothing_is_believed_without_a_document_or_without_pins() {
        let dir = std::env::temp_dir().join(format!("trust-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let (trust, path) = trust(&dir);

        let mut headers = HeaderMap::new();
        let refusal = trust.verify(&headers, "send", "t-svc", b"{}").unwrap_err();
        assert!(refusal.contains("no attestation"), "{refusal}");

        headers.insert(STREAM_ATTESTATION_HEADER, "AAAA".parse().unwrap());
        let refusal = trust.verify(&headers, "send", "t-svc", b"{}").unwrap_err();
        assert!(refusal.contains("pins no enclave"), "a missing file pins nothing: {refusal}");

        // A file that appears later is read then — the dev platform starts before the enclave.
        std::fs::write(
            &path,
            format!(r#"{{"pcr0":"{}","pcr16":"{}"}}"#, "00".repeat(48), "11".repeat(48)),
        )
        .unwrap();
        assert_eq!(trust.pinned().len(), 1);
        let refusal = trust.verify(&headers, "send", "t-svc", b"{}").unwrap_err();
        assert!(refusal.contains("does not check out"), "garbage is not a document: {refusal}");
        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn a_pins_file_with_the_wrong_length_pins_nothing() {
        let dir = std::env::temp_dir().join(format!("trust-bad-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let (trust, path) = trust(&dir);
        std::fs::write(&path, r#"{"pcr0":"00","pcr16":"11"}"#).unwrap();
        assert!(trust.pinned().is_empty());
        std::fs::remove_dir_all(&dir).unwrap();
    }
}
