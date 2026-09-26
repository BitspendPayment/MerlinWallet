//! Against a real document, captured from a dev enclave (`dev-enclave.sh --name merlin`) serving
//! the cosigner component:
//!
//! ```text
//! curl --resolve enclave.test:8443:127.0.0.1 --cacert pebble-root.pem \
//!      -H "x-enclave-nonce: <b64url of dev-nonce.hex>" -D - https://enclave.test:8443/auth/
//! ```
//!
//! with the leaf that connection served (`openssl s_client`), and that boot's `trust-root.der`.
//! Not a document this crate built for itself, which would only show the verifier agrees with its
//! own test helper.
//!
//! The dev chain is minted per boot and valid for 30 days, so every test verifies at the moment the
//! document was produced rather than at the wall clock.

use std::time::{Duration, SystemTime, UNIX_EPOCH};

use enclave_client::{
    guest_pcr, pcr_after_one_extend, verify, verify_connection, Error, Pins, AWS_NITRO_ROOT_G1_PEM,
};

const DOCUMENT: &[u8] = include_bytes!("fixtures/dev-document.cose");
const SERVED_LEAF: &[u8] = include_bytes!("fixtures/dev-served-leaf.der");
const TRUST_ROOT: &[u8] = include_bytes!("fixtures/dev-trust-root.der");
const NONCE_HEX: &str = include_str!("fixtures/dev-nonce.hex");

/// As printed by `dev-enclave.sh` for that boot.
const PCR0: &str = "8f2026d5a6c50479e27152c06ca86852ce0ec9528efd5f13d8bee969f128076adf1c720ead49d5629724fe2562a1cd99";
const PCR16: &str = "e5d19028de3519c28511df1942d0bac7ba3e633707adbd3c4017d4ba8ca8e515a1b79e5b91081ec19267cf35f732f9b3";
/// `sha256sum cosigner.wasm` for the component it served.
const GUEST_SHA256: &str = "8c8e83402faafdaf775f7b421ede83bc1d8325eba84f97395c91783271f9d51f";
/// `sha256sum dev-served-leaf.der`.
const LEAF_SHA256: &str = "a9f24f8f55d4541b3dddccc4a73ee585e03e1722da0bdd00855472111114188c";

fn pins() -> Pins {
    Pins {
        trust_root: TRUST_ROOT.to_vec(),
        pcr0: hex::decode(PCR0).unwrap(),
        pcr16: hex::decode(PCR16).unwrap(),
        max_age: Duration::from_secs(300),
    }
}

fn nonce() -> Vec<u8> {
    hex::decode(NONCE_HEX.trim()).unwrap()
}

/// The moment the document was stamped, read straight from the payload — only to aim the clock.
fn produced_at() -> SystemTime {
    let (_, payload, _) = split(DOCUMENT);
    let value: ciborium::Value = ciborium::from_reader(payload.as_slice()).unwrap();
    let ms = value
        .as_map()
        .unwrap()
        .iter()
        .find(|(k, _)| k.as_text() == Some("timestamp"))
        .and_then(|(_, v)| v.as_integer())
        .map(|i| u64::try_from(i).unwrap())
        .unwrap();
    UNIX_EPOCH + Duration::from_millis(ms)
}

#[test]
fn a_real_dev_document_verifies_against_its_pins() {
    let attested = verify_connection(DOCUMENT, &pins(), SERVED_LEAF, &nonce(), produced_at())
        .expect("the captured document must verify");
    assert_eq!(hex::encode(attested.certificate_sha256), LEAF_SHA256);
    assert_eq!(hex::encode(attested.guest_sha256), GUEST_SHA256);
    assert_eq!(attested.document.digest, "SHA384");
}

#[test]
fn the_production_root_is_refused_for_a_dev_document() {
    let pins = Pins { trust_root: AWS_NITRO_ROOT_G1_PEM.as_bytes().to_vec(), ..pins() };
    let err = verify_connection(DOCUMENT, &pins, SERVED_LEAF, &nonce(), produced_at()).unwrap_err();
    assert!(matches!(err, Error::Chain(_)), "{err}");
}

#[test]
fn another_image_is_refused() {
    let mut pins = pins();
    pins.pcr0[0] ^= 1;
    let err = verify_connection(DOCUMENT, &pins, SERVED_LEAF, &nonce(), produced_at()).unwrap_err();
    assert!(matches!(err, Error::PcrMismatch { index: 0, .. }), "{err}");
}

/// The case PCR0 alone cannot catch: the right runtime serving a different component.
#[test]
fn another_guest_is_refused() {
    let pins = Pins { pcr16: guest_pcr(b"some other component").to_vec(), ..pins() };
    let err = verify_connection(DOCUMENT, &pins, SERVED_LEAF, &nonce(), produced_at()).unwrap_err();
    assert!(matches!(err, Error::PcrMismatch { index: 16, .. }), "{err}");
}

/// A document replayed onto a connection it was not made for — here, a certificate that is not
/// the one bound in `user_data`.
#[test]
fn a_connection_serving_another_certificate_is_refused() {
    let other = [SERVED_LEAF, b"x"].concat();
    let err = verify_connection(DOCUMENT, &pins(), &other, &nonce(), produced_at()).unwrap_err();
    assert!(matches!(err, Error::CertificateMismatch { .. }), "{err}");
}

#[test]
fn a_document_over_another_nonce_is_refused() {
    let mut sent = nonce();
    sent[0] ^= 1;
    let err = verify_connection(DOCUMENT, &pins(), SERVED_LEAF, &sent, produced_at()).unwrap_err();
    assert!(matches!(err, Error::NonceMismatch { .. }), "{err}");
}

#[test]
fn an_old_document_is_refused() {
    let later = produced_at() + Duration::from_secs(301);
    let err = verify_connection(DOCUMENT, &pins(), SERVED_LEAF, &nonce(), later).unwrap_err();
    assert!(matches!(err, Error::Stale { .. }), "{err}");
}

#[test]
fn a_chain_outside_its_validity_is_refused() {
    let err = verify(DOCUMENT, TRUST_ROOT, produced_at() + Duration::from_secs(40 * 86400)).unwrap_err();
    assert!(matches!(err, Error::Chain(_)), "{err}");
}

/// Flip one byte anywhere in the payload and the signature no longer covers it.
#[test]
fn a_tampered_payload_is_refused() {
    let (protected, payload, signature) = split(DOCUMENT);
    let mut changed = payload.clone();
    let at = changed.len() / 2;
    changed[at] ^= 1;
    let tampered = join(&protected, &changed, &signature);
    assert!(verify(&tampered, TRUST_ROOT, produced_at()).is_err());
}

/// QEMU's emulated NSM writes alg -1 and does not sign. Refused before anything else is read.
#[test]
fn an_unsigned_emulator_document_is_refused() {
    let (_, payload, _) = split(DOCUMENT);
    let mut protected = Vec::new();
    ciborium::into_writer(
        &ciborium::Value::Map(vec![(1.into(), (-1).into())]),
        &mut protected,
    )
    .unwrap();
    let unsigned = join(&protected, &payload, &[]);
    let err = verify(&unsigned, TRUST_ROOT, produced_at()).unwrap_err();
    assert!(matches!(err, Error::Malformed(_)), "{err}");
}

/// Against a value computed outside this crate — `{ head -c 48 /dev/zero; printf abc; } | sha384sum`
/// — the same vector enclave-runtime pins.
#[test]
fn one_extension_is_sha384_over_zeros_then_the_data() {
    assert_eq!(
        hex::encode(pcr_after_one_extend(b"abc")),
        "b1c16eb7634112b7c9d5ebd27e62a2d4528bbfcfd68b62d3afd9ecf98e0f413a84314acce78317fb69fd895155343e09"
    );
    assert_eq!(
        hex::encode(pcr_after_one_extend(&hex::decode(GUEST_SHA256).unwrap())),
        PCR16,
        "the served component's hash measures to the PCR16 the enclave printed"
    );
}

fn split(cose: &[u8]) -> (Vec<u8>, Vec<u8>, Vec<u8>) {
    let value: ciborium::Value = ciborium::from_reader(cose).unwrap();
    let value = match value {
        ciborium::Value::Tag(_, inner) => *inner,
        v => v,
    };
    let a = value.into_array().unwrap();
    let b = |v: &ciborium::Value| v.as_bytes().unwrap().clone();
    (b(&a[0]), b(&a[2]), b(&a[3]))
}

fn join(protected: &[u8], payload: &[u8], signature: &[u8]) -> Vec<u8> {
    let mut out = Vec::new();
    ciborium::into_writer(
        &ciborium::Value::Array(vec![
            ciborium::Value::Bytes(protected.to_vec()),
            ciborium::Value::Map(vec![]),
            ciborium::Value::Bytes(payload.to_vec()),
            ciborium::Value::Bytes(signature.to_vec()),
        ]),
        &mut out,
    )
    .unwrap();
    out
}
