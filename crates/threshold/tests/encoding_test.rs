//! Reading identifiers and commitments back from the forms they travel in.

use std::str::FromStr;

use threshold::identifier::Identifier;
use threshold::keys::KeyPackage;
use threshold::nonce::SigningCommitments;
use threshold::point;

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

#[test]
fn an_identifier_reads_back_from_its_bytes_and_from_its_hex() {
    let id = Identifier::derive(b"a participant").unwrap();
    let bytes = id.serialize();
    assert_eq!(Identifier::try_from(&bytes[..]).unwrap(), id);
    assert_eq!(Identifier::from_str(&hex(&bytes)).unwrap(), id);
    assert!(Identifier::try_from(&bytes[..31]).is_err(), "31 bytes is not an identifier");
    assert!(Identifier::from_str("not hex").is_err());
}

#[test]
fn commitments_read_back_from_their_compressed_points() {
    let p = point::base_mul(&k256::Scalar::from(7u64));
    let bytes = point::serialize_compressed(&p);
    let c = SigningCommitments::from_bytes(&bytes, &bytes).unwrap();
    assert_eq!(c.hiding, p);
    assert!(SigningCommitments::from_bytes(&bytes[..32], &bytes).is_err());
}

/// Key packages are read off the wire, and their hex is not trusted to be ASCII. A three-byte
/// character followed by ASCII has an even length, so a decoder that sliced the string two bytes at
/// a time cut the character in half — a panic, which across the FFI is an abort.
#[test]
fn hex_with_a_multibyte_character_is_refused_not_a_panic() {
    let identifier = format!("€{}", "a".repeat(61));
    assert_eq!(identifier.len(), 64);
    let json = format!(
        r#"{{"identifier":"{identifier}","secretShare":"{s}","verifyingShare":"{p}","verifyingKey":"{p}","minSigners":2}}"#,
        s = "11".repeat(32),
        p = "02".repeat(33),
    );
    assert!(KeyPackage::from_json(&json).is_err());
}
