//! The document itself: COSE_Sign1 over a CBOR payload, signed by a leaf that chains to a root.
//!
//! Follows `nitro-attestation::verify` in enclave-runtime check for check, so a document the
//! runtime's own reference client accepts is accepted here and nothing else is. It is a separate
//! implementation only because that crate verifies with `aws-lc-rs`, which needs CMake and a C
//! toolchain for every mobile target; this one is pure Rust.

use std::collections::BTreeMap;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use der::{Decode, Header, Reader, SliceReader};
use p384::ecdsa::signature::hazmat::PrehashVerifier;
use p384::ecdsa::{Signature, VerifyingKey};
use sha2::{Digest, Sha384};
use x509_cert::ext::pkix::BasicConstraints;
use x509_cert::Certificate;

use crate::error::{Error, Result};

/// The AWS Nitro Enclaves root, G1 — the production trust anchor.
/// <https://aws-nitro-enclaves.amazonaws.com/AWS_NitroEnclaves_Root-G1.zip>
pub const AWS_NITRO_ROOT_G1_PEM: &str = "-----BEGIN CERTIFICATE-----
MIICETCCAZagAwIBAgIRAPkxdWgbkK/hHUbMtOTn+FYwCgYIKoZIzj0EAwMwSTEL
MAkGA1UEBhMCVVMxDzANBgNVBAoMBkFtYXpvbjEMMAoGA1UECwwDQVdTMRswGQYD
VQQDDBJhd3Mubml0cm8tZW5jbGF2ZXMwHhcNMTkxMDI4MTMyODA1WhcNNDkxMDI4
MTQyODA1WjBJMQswCQYDVQQGEwJVUzEPMA0GA1UECgwGQW1hem9uMQwwCgYDVQQL
DANBV1MxGzAZBgNVBAMMEmF3cy5uaXRyby1lbmNsYXZlczB2MBAGByqGSM49AgEG
BSuBBAAiA2IABPwCVOumCMHzaHDimtqQvkY4MpJzbolL//Zy2YlES1BR5TSksfbb
48C8WBoyt7F2Bw7eEtaaP+ohG2bnUs990d0JX28TcPQXCEPZ3BABIeTPYwEoCWZE
h8l5YoQwTcU/9KNCMEAwDwYDVR0TAQH/BAUwAwEB/zAdBgNVHQ4EFgQUkCW1DdkF
R+eWw5b6cp3PmanfS5YwDgYDVR0PAQH/BAQDAgGGMAoGCCqGSM49BAMDA2kAMGYC
MQCjfy+Rocm9Xue4YnwWmNJVA44fA0P5W2OpYow9OYCVRaEevL8uO1XYru5xtMPW
rfMCMQCi85sWBbJwKKXdS6BptQFuZbT73o/gBh1qUxl/nNr12UO8Yfwr6wPLb+6N
IwLz3/Y=
-----END CERTIFICATE-----";

/// COSE `alg` for ES384. QEMU's emulated NSM writes -1 to say it did not sign; that is refused.
const COSE_ALG_ES384: i128 = -35;

/// ecdsa-with-SHA384, the only certificate signature algorithm a Nitro chain uses.
const ECDSA_WITH_SHA384: &str = "1.2.840.10045.4.3.3";

/// id-ce-basicConstraints.
const BASIC_CONSTRAINTS: &str = "2.5.29.19";

/// The payload, once its signature and chain have been checked.
#[derive(Debug, Clone)]
pub struct AttestationDocument {
    pub module_id: String,
    pub timestamp_ms: u64,
    pub digest: String,
    pub pcrs: BTreeMap<u32, Vec<u8>>,
    pub certificate: Vec<u8>,
    pub cabundle: Vec<Vec<u8>>,
    pub public_key: Option<Vec<u8>>,
    pub user_data: Option<Vec<u8>>,
    pub nonce: Option<Vec<u8>>,
}

impl AttestationDocument {
    pub fn pcr(&self, index: u32) -> Option<&[u8]> {
        self.pcrs.get(&index).map(Vec::as_slice)
    }

    pub fn timestamp(&self) -> SystemTime {
        UNIX_EPOCH + Duration::from_millis(self.timestamp_ms)
    }
}

/// Verify a COSE_Sign1 attestation document's signature and its chain to `trust_root`.
///
/// `trust_root` is the DER or PEM of the pinned root: [`AWS_NITRO_ROOT_G1_PEM`] in production, the
/// per-boot `trust-root.der` against a dev enclave. `now` judges certificate validity windows.
///
/// This establishes that the enclave the root vouches for signed the payload, and nothing about
/// *which* enclave or *which* connection — see [`crate::verify_connection`] for that.
pub fn verify(cose: &[u8], trust_root: &[u8], now: SystemTime) -> Result<AttestationDocument> {
    let sign1 = CoseSign1::parse(cose)?;
    sign1.require_es384()?;
    let document = decode_payload(&sign1.payload)?;

    // Order matters: establish that the leaf is trusted *before* trusting the key it carries to
    // check the document's own signature. The other way round, a forged document could nominate
    // its own signing certificate.
    verify_chain(&document, trust_root, now)?;

    let leaf = parse_certificate(&document.certificate, "the leaf")?;
    let key = p384_key(&leaf, "the leaf")?;
    // COSE signatures are fixed-width r‖s, not the ASN.1 SEQUENCE X.509 uses.
    let signature = Signature::from_slice(&sign1.signature).map_err(|_| Error::Signature)?;
    let digest = Sha384::digest(sign1.to_be_signed()?);
    key.verify_prehash(&digest, &signature)
        .map_err(|_| Error::Signature)?;

    Ok(document)
}

struct CoseSign1 {
    protected: Vec<u8>,
    payload: Vec<u8>,
    signature: Vec<u8>,
}

impl CoseSign1 {
    fn parse(cose: &[u8]) -> Result<Self> {
        let value: ciborium::Value = ciborium::from_reader(cose)
            .map_err(|e| Error::Malformed(format!("not CBOR: {e}")))?;
        // Tagged (18) or bare, depending on the producer.
        let value = match value {
            ciborium::Value::Tag(_, inner) => *inner,
            other => other,
        };
        let array = value
            .into_array()
            .map_err(|_| Error::Malformed("COSE_Sign1 is not an array".into()))?;
        let [protected, _unprotected, payload, signature]: [ciborium::Value; 4] = array
            .try_into()
            .map_err(|a: Vec<_>| Error::Malformed(format!("COSE_Sign1 has {} elements, not 4", a.len())))?;
        let bytes = |v: ciborium::Value, name: &str| {
            v.into_bytes()
                .map_err(|_| Error::Malformed(format!("COSE_Sign1 {name} is not a byte string")))
        };
        Ok(CoseSign1 {
            protected: bytes(protected, "protected header")?,
            payload: bytes(payload, "payload")?,
            signature: bytes(signature, "signature")?,
        })
    }

    fn require_es384(&self) -> Result<()> {
        let header: ciborium::Value = ciborium::from_reader(self.protected.as_slice())
            .map_err(|e| Error::Malformed(format!("protected header is not CBOR: {e}")))?;
        let alg = header
            .as_map()
            .and_then(|m| {
                m.iter().find(|(k, _)| k.as_integer().map(i128::from) == Some(1))
            })
            .and_then(|(_, v)| v.as_integer())
            .map(i128::from);
        match alg {
            Some(COSE_ALG_ES384) => Ok(()),
            Some(other) => Err(Error::Malformed(format!(
                "COSE algorithm {other}, not ES384 (-35); -1 is an unsigned emulator document"
            ))),
            None => Err(Error::Malformed("protected header names no algorithm".into())),
        }
    }

    /// `Sig_structure = ["Signature1", protected, external_aad = b"", payload]`, RFC 9052 §4.4.
    fn to_be_signed(&self) -> Result<Vec<u8>> {
        let structure = ciborium::Value::Array(vec![
            ciborium::Value::Text("Signature1".into()),
            ciborium::Value::Bytes(self.protected.clone()),
            ciborium::Value::Bytes(Vec::new()),
            ciborium::Value::Bytes(self.payload.clone()),
        ]);
        let mut out = Vec::new();
        ciborium::into_writer(&structure, &mut out)
            .map_err(|e| Error::Malformed(format!("encoding Sig_structure: {e}")))?;
        Ok(out)
    }
}

fn decode_payload(payload: &[u8]) -> Result<AttestationDocument> {
    let value: ciborium::Value = ciborium::from_reader(payload)
        .map_err(|e| Error::Malformed(format!("payload is not CBOR: {e}")))?;
    let map = value
        .as_map()
        .ok_or_else(|| Error::Malformed("payload is not a map".into()))?;
    let get = |name: &str| map.iter().find(|(k, _)| k.as_text() == Some(name)).map(|(_, v)| v);
    let missing = |name: &str, kind: &str| Error::Malformed(format!("{name:?} is missing or not {kind}"));

    let text = |name: &str| {
        get(name)
            .and_then(|v| v.as_text())
            .map(str::to_string)
            .ok_or_else(|| missing(name, "text"))
    };
    let bytes = |name: &str| {
        get(name)
            .and_then(|v| v.as_bytes())
            .cloned()
            .ok_or_else(|| missing(name, "bytes"))
    };
    // Absent and null are the same thing: the runtime omits a field it did not ask the NSM for.
    let optional_bytes = |name: &str| get(name).and_then(|v| v.as_bytes()).cloned();

    let timestamp_ms = get("timestamp")
        .and_then(|v| v.as_integer())
        .and_then(|i| u64::try_from(i).ok())
        .ok_or_else(|| missing("timestamp", "an unsigned integer"))?;

    let mut pcrs = BTreeMap::new();
    for (k, v) in get("pcrs")
        .and_then(|v| v.as_map())
        .ok_or_else(|| missing("pcrs", "a map"))?
    {
        let index = k
            .as_integer()
            .and_then(|i| u32::try_from(i).ok())
            .ok_or_else(|| Error::Malformed("a PCR index is not an integer".into()))?;
        let value = v
            .as_bytes()
            .cloned()
            .ok_or_else(|| Error::Malformed(format!("PCR{index} is not bytes")))?;
        pcrs.insert(index, value);
    }

    let cabundle = get("cabundle")
        .and_then(|v| v.as_array())
        .ok_or_else(|| missing("cabundle", "an array"))?
        .iter()
        .map(|v| {
            v.as_bytes()
                .cloned()
                .ok_or_else(|| Error::Malformed("a cabundle entry is not bytes".into()))
        })
        .collect::<Result<Vec<_>>>()?;

    let digest = text("digest")?;
    if digest != "SHA384" {
        return Err(Error::Malformed(format!("digest is {digest:?}, not SHA384")));
    }

    Ok(AttestationDocument {
        module_id: text("module_id")?,
        timestamp_ms,
        digest,
        pcrs,
        certificate: bytes("certificate")?,
        cabundle,
        public_key: optional_bytes("public_key"),
        user_data: optional_bytes("user_data"),
        nonce: optional_bytes("nonce"),
    })
}

/// `cabundle` is ordered root first, so the chain is `cabundle` in order, then the leaf. Every
/// certificate must be inside its validity window, every one above the leaf must be a CA, and each
/// must be issued — by name and by signature — by the one before it. The root's authority comes
/// from being byte-equal to the pinned one, not from its self-signature.
fn verify_chain(document: &AttestationDocument, trust_root: &[u8], now: SystemTime) -> Result<()> {
    let pinned = decode_certificate(trust_root)?;
    let presented = document
        .cabundle
        .first()
        .ok_or_else(|| Error::Chain("the cabundle is empty, so nothing chains to a root".into()))?;
    if presented != &pinned {
        return Err(Error::Chain(format!(
            "the document chains to root {}, not the pinned root {}",
            hex::encode(sha2::Sha256::digest(presented)),
            hex::encode(sha2::Sha256::digest(&pinned)),
        )));
    }

    let now = now
        .duration_since(UNIX_EPOCH)
        .map_err(|_| Error::Chain("verification time is before the Unix epoch".into()))?;

    let chain: Vec<&[u8]> = document
        .cabundle
        .iter()
        .map(Vec::as_slice)
        .chain(std::iter::once(document.certificate.as_slice()))
        .collect();

    let mut issuer: Option<Certificate> = None;
    for (depth, der) in chain.iter().enumerate() {
        let what = format!("the certificate at depth {depth}");
        let cert = parse_certificate(der, &what)?;
        let tbs = &cert.tbs_certificate;

        let not_before = tbs.validity.not_before.to_unix_duration();
        let not_after = tbs.validity.not_after.to_unix_duration();
        if now < not_before || now > not_after {
            return Err(Error::Chain(format!(
                "{what} ({}) is valid from {}s to {}s, not at {}s",
                tbs.subject,
                not_before.as_secs(),
                not_after.as_secs(),
                now.as_secs()
            )));
        }

        // Without this a leaf could be presented as an intermediate and sign others.
        let is_leaf = depth == chain.len() - 1;
        if !is_leaf && !is_ca(&cert)? {
            return Err(Error::Chain(format!(
                "{what} ({}) is not a CA but has a certificate below it",
                tbs.subject
            )));
        }

        if let Some(parent) = &issuer {
            if tbs.issuer != parent.tbs_certificate.subject {
                return Err(Error::Chain(format!(
                    "{what} names issuer {} but follows {}",
                    tbs.issuer, parent.tbs_certificate.subject
                )));
            }
            verify_issued_by(der, &cert, parent, &what)?;
        }
        issuer = Some(cert);
    }
    Ok(())
}

fn verify_issued_by(der: &[u8], cert: &Certificate, issuer: &Certificate, what: &str) -> Result<()> {
    let algorithm = cert.signature_algorithm.oid.to_string();
    if algorithm != ECDSA_WITH_SHA384 {
        return Err(Error::Chain(format!(
            "{what} is signed with {algorithm}, not ecdsa-with-SHA384"
        )));
    }
    let key = p384_key(issuer, &format!("the issuer of {what}"))?;
    let signature = cert
        .signature
        .as_bytes()
        .and_then(|b| Signature::from_der(b).ok())
        .ok_or_else(|| Error::Chain(format!("{what} has a malformed signature")))?;
    // Over the TBS bytes as they arrived, not a re-encoding of the parsed structure: a
    // re-encoding is only the same bytes if the issuer's encoder was canonical.
    let digest = Sha384::digest(raw_tbs(der)?);
    key.verify_prehash(&digest, &signature)
        .map_err(|_| Error::Chain(format!("{what}'s signature does not verify under its issuer's key")))
}

/// The first element of the outer `Certificate` SEQUENCE, header and all.
fn raw_tbs(der: &[u8]) -> Result<&[u8]> {
    let malformed = |e: der::Error| Error::Chain(format!("reading the TBS certificate: {e}"));
    let mut reader = SliceReader::new(der).map_err(malformed)?;
    Header::decode(&mut reader).map_err(malformed)?;
    reader.tlv_bytes().map_err(malformed)
}

fn is_ca(cert: &Certificate) -> Result<bool> {
    let Some(extensions) = &cert.tbs_certificate.extensions else {
        return Ok(false);
    };
    let Some(ext) = extensions
        .iter()
        .find(|e| e.extn_id.to_string() == BASIC_CONSTRAINTS)
    else {
        return Ok(false);
    };
    let bc = BasicConstraints::from_der(ext.extn_value.as_bytes())
        .map_err(|e| Error::Chain(format!("malformed basicConstraints: {e}")))?;
    Ok(bc.ca)
}

fn parse_certificate(der: &[u8], what: &str) -> Result<Certificate> {
    Certificate::from_der(der).map_err(|e| Error::Chain(format!("parsing {what}: {e}")))
}

fn p384_key(cert: &Certificate, what: &str) -> Result<VerifyingKey> {
    cert.tbs_certificate
        .subject_public_key_info
        .subject_public_key
        .as_bytes()
        .and_then(|b| VerifyingKey::from_sec1_bytes(b).ok())
        .ok_or_else(|| Error::Chain(format!("{what} does not carry a P-384 key")))
}

/// Accept a certificate as PEM or DER, returning DER.
pub(crate) fn decode_certificate(bytes: &[u8]) -> Result<Vec<u8>> {
    if !bytes.starts_with(b"-----BEGIN") {
        return Ok(bytes.to_vec());
    }
    let text = std::str::from_utf8(bytes)
        .map_err(|_| Error::Chain("the PEM trust root is not UTF-8".into()))?;
    let body: String = text
        .lines()
        .skip_while(|l| !l.starts_with("-----BEGIN"))
        .skip(1)
        .take_while(|l| !l.starts_with("-----END"))
        .collect();
    use base64::Engine;
    base64::engine::general_purpose::STANDARD
        .decode(body.trim())
        .map_err(|e| Error::Chain(format!("decoding the PEM trust root: {e}")))
}
