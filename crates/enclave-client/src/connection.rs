//! What turns "some enclave signed this" into "the enclave I pinned is on the other end of this
//! connection, now".

use std::time::{Duration, SystemTime};

use sha2::{Digest, Sha256, Sha384};

use crate::document::{verify, AttestationDocument};
use crate::error::{Error, Result};

/// The register the runtime measures its guest component into.
pub const PCR_GUEST: u32 = 16;

/// What a client pins. The same three values `passkey-client` and `nitro-attest` take.
#[derive(Debug, Clone)]
pub struct Pins {
    /// DER or PEM of the root the chain must reach. [`crate::AWS_NITRO_ROOT_G1_PEM`] in
    /// production; a dev enclave mints a fresh one each boot.
    pub trust_root: Vec<u8>,
    /// The runtime image, 48 bytes.
    pub pcr0: Vec<u8>,
    /// The guest component, 48 bytes — see [`guest_pcr`]. An identity only together with PCR0:
    /// the runtime is what writes this register, so PCR0 is what says it was this runtime.
    pub pcr16: Vec<u8>,
    /// How old a document may be. It is fetched live, on the response it attests.
    pub max_age: Duration,
}

/// A connection, verified.
#[derive(Debug, Clone)]
pub struct Attested {
    pub document: AttestationDocument,
    /// SHA-256 of the leaf certificate the document is bound to — equal, by the time this exists,
    /// to the one the connection served. Later connections compare against it rather than being
    /// attested again: the runtime only attaches documents to `/auth/*` responses.
    pub certificate_sha256: [u8; 32],
    /// SHA-256 of the guest component the enclave is serving.
    pub guest_sha256: [u8; 32],
}

/// Verify an attestation document against [`Pins`] and the connection it arrived on.
///
/// `served_certificate` is the DER of the leaf certificate **this TLS connection presented** —
/// read from the socket, not from anything the server said. `nonce` is what the client sent in
/// `x-enclave-nonce`, decoded.
///
/// Checks, in order: the signature and chain to the pinned root; PCR0 and PCR16; the nonce; the
/// age; that `user_data` is the runtime's 68-byte layout; that its certificate hash is the served
/// certificate's; and that its guest hash measures to the PCR16 the document carries.
pub fn verify_connection(
    cose: &[u8],
    pins: &Pins,
    served_certificate: &[u8],
    nonce: &[u8],
    now: SystemTime,
) -> Result<Attested> {
    let document = verify(cose, &pins.trust_root, now)?;
    check_pcrs(&document, pins)?;

    match &document.nonce {
        None => return Err(Error::NonceMissing),
        Some(got) if got != nonce => {
            return Err(Error::NonceMismatch { got: hex::encode(got), sent: hex::encode(nonce) })
        }
        Some(_) => {}
    }

    check_age(&document, pins, now)?;

    let hashes = AttestationHashes::parse(
        document
            .user_data
            .as_deref()
            .ok_or_else(|| Error::UserData("the document carries none".into()))?,
    )?;

    let served: [u8; 32] = Sha256::digest(served_certificate).into();
    if hashes.tls_certificate != served {
        return Err(Error::CertificateMismatch {
            bound: hex::encode(hashes.tls_certificate),
            served: hex::encode(served),
        });
    }

    // The runtime puts sha256(component) in user_data and extends PCR16 with the same value, so the
    // two must agree. PCR16 already matched the pin; this says the user_data describes that guest.
    let pcr16 = document.pcr(PCR_GUEST).ok_or(Error::PcrMissing(PCR_GUEST))?;
    if pcr_after_one_extend(&hashes.guest).as_slice() != pcr16 {
        return Err(Error::GuestMismatch { guest: hex::encode(hashes.guest) });
    }

    Ok(Attested {
        document,
        certificate_sha256: hashes.tls_certificate,
        guest_sha256: hashes.guest,
    })
}

/// PCR0 and PCR16 are the pinned ones: this runtime, serving this guest.
pub(crate) fn check_pcrs(document: &AttestationDocument, pins: &Pins) -> Result<()> {
    for (index, expected) in [(0, &pins.pcr0), (PCR_GUEST, &pins.pcr16)] {
        let got = document.pcr(index).ok_or(Error::PcrMissing(index))?;
        if got != expected.as_slice() {
            return Err(Error::PcrMismatch {
                index,
                got: hex::encode(got),
                expected: hex::encode(expected),
            });
        }
    }
    Ok(())
}

/// No older than the pins allow. A document stamped in the future counts its distance as age.
pub(crate) fn check_age(document: &AttestationDocument, pins: &Pins, now: SystemTime) -> Result<()> {
    let age = now
        .duration_since(document.timestamp())
        .unwrap_or_else(|e| e.duration());
    if age > pins.max_age {
        return Err(Error::Stale { age_secs: age.as_secs(), max_age_secs: pins.max_age.as_secs() });
    }
    Ok(())
}

/// The runtime's `user_data`:
///
/// ```text
///   0x12 0x20 ‖ sha256(tls leaf DER) ‖ 0x12 0x20 ‖ sha256(guest component)
///     │    └── length, 32 bytes
///     └── multihash code for sha2-256
/// ```
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AttestationHashes {
    pub tls_certificate: [u8; 32],
    pub guest: [u8; 32],
}

const MULTIHASH_SHA256: [u8; 2] = [0x12, 0x20];
pub const ATTESTATION_HASHES_LEN: usize = 2 * (2 + 32);

impl AttestationHashes {
    pub fn parse(bytes: &[u8]) -> Result<Self> {
        if bytes.len() != ATTESTATION_HASHES_LEN {
            return Err(Error::UserData(format!(
                "{} bytes, not the {ATTESTATION_HASHES_LEN} of two multihash SHA-256 digests",
                bytes.len()
            )));
        }
        if bytes[0..2] != MULTIHASH_SHA256 || bytes[34..36] != MULTIHASH_SHA256 {
            return Err(Error::UserData("a digest is not multihash sha2-256".into()));
        }
        let mut hashes = AttestationHashes { tls_certificate: [0; 32], guest: [0; 32] };
        hashes.tls_certificate.copy_from_slice(&bytes[2..34]);
        hashes.guest.copy_from_slice(&bytes[36..68]);
        Ok(hashes)
    }
}

/// What a register holds after exactly one extension with `data` from zero: `SHA384(0⁴⁸ ‖ data)`.
pub fn pcr_after_one_extend(data: &[u8]) -> [u8; 48] {
    Sha384::new().chain_update([0u8; 48]).chain_update(data).finalize().into()
}

/// The PCR16 an enclave serving `component` attests — what `nitro-attest --measure` prints.
pub fn guest_pcr(component: &[u8]) -> [u8; 48] {
    pcr_after_one_extend(&Sha256::digest(component))
}
