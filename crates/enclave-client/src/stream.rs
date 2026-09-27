//! What proves a message on a service stream came from the enclave.
//!
//! The runtime holds a connection to a service on its guest's behalf — `GET /escrow/stream` held
//! open, and one `POST /escrow/send` per message the guest sends — and those arrive at the service
//! as ordinary HTTP that anybody could send. So the runtime attaches an attestation document to
//! each, in `x-enclave-attestation`, whose `user_data` binds what was sent:
//!
//! ```text
//!   SHA-256( "enclave-runtime/stream/v1\0" ‖ kind ‖ "\0" ‖ wire id ‖ "\0" ‖ SHA-256(body) )
//!   kind: "open" (the GET, empty body) or "send" (the POST, its exact bytes)
//! ```
//!
//! [`verify_stream`] checks it: the chain to the pinned root, PCR0 and PCR16 pinned, the age, and
//! that `user_data` is exactly that digest. The wire id names the tenant as well as the stream, and
//! PCR16 names the guest, so a verified document says *this* guest spoke for *that* tenant — not a
//! customer running a guest of their own, and not one tenant's enclave speaking for another's.

use std::time::SystemTime;

use sha2::{Digest, Sha256};

use crate::connection::{check_age, check_pcrs, Pins};
use crate::document::{verify, AttestationDocument};
use crate::error::{Error, Result};

/// The header the runtime puts the document in: the same one inbound responses use.
pub const STREAM_ATTESTATION_HEADER: &str = "x-enclave-attestation";

/// Domain separation, so a stream document can never be mistaken for any other the runtime signs.
pub const STREAM_DOMAIN: &[u8] = b"enclave-runtime/stream/v1\0";

/// A held connection being opened: the `GET /escrow/stream`, whose body is empty.
pub const KIND_OPEN: &str = "open";
/// One message: the `POST /escrow/send`, whose body is the message.
pub const KIND_SEND: &str = "send";

/// What the runtime puts in `user_data` for one stream request. See the module note.
pub fn stream_user_data(kind: &str, wire_id: &str, body: &[u8]) -> [u8; 32] {
    Sha256::new()
        .chain_update(STREAM_DOMAIN)
        .chain_update(kind.as_bytes())
        .chain_update([0u8])
        .chain_update(wire_id.as_bytes())
        .chain_update([0u8])
        .chain_update(Sha256::digest(body))
        .finalize()
        .into()
}

/// Verify the document on one stream request: that the pinned enclave sent exactly `body`, as
/// `kind`, on the connection `wire_id` names, recently.
///
/// Returns the document, whose [`timestamp`](AttestationDocument::timestamp) a service uses to let
/// a newer `open` replace an older one and never the other way round.
pub fn verify_stream(
    cose: &[u8],
    pins: &Pins,
    kind: &str,
    wire_id: &str,
    body: &[u8],
    now: SystemTime,
) -> Result<AttestationDocument> {
    let document = verify(cose, &pins.trust_root, now)?;
    check_pcrs(&document, pins)?;
    check_age(&document, pins, now)?;
    let expected = stream_user_data(kind, wire_id, body);
    match document.user_data.as_deref() {
        Some(got) if got == expected.as_slice() => Ok(document),
        Some(_) => Err(Error::UserData(format!(
            "it does not bind this {kind} on {wire_id}: the bytes, the connection or the kind differ"
        ))),
        None => Err(Error::UserData("the document carries none".into())),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Pinned so the runtime, which computes the same digest, can be held to it byte for byte.
    #[test]
    fn the_digest_is_pinned() {
        let got = stream_user_data(KIND_SEND, "00112233445566778899aabbccddeeff-svc-abc", b"{\"kind\":\"ack\"}");
        assert_eq!(hex::encode(got), PINNED_VECTOR);
    }

    /// The runtime's own pinned vectors (`runtime/src/stream.rs`, `what_a_request_binds_is_pinned`):
    /// the enclave that signs and the service that checks must agree byte for byte.
    #[test]
    fn the_runtime_and_this_crate_bind_the_same_bytes() {
        let wire_id = "01010101010101010101010101010101-esc";
        assert_eq!(
            hex::encode(stream_user_data(KIND_OPEN, wire_id, b"")),
            "f9a46679b41ae322117cb08515fefa42b1c53a7d24aa472eedde9650a6d7fb82"
        );
        assert_eq!(
            hex::encode(stream_user_data(KIND_SEND, wire_id, b"hello")),
            "c828be10c689f688431ce5ecb5ca9870a03f8ac375956733fa755150bdd6fa7c"
        );
    }

    #[test]
    fn every_input_moves_the_digest() {
        let base = stream_user_data(KIND_SEND, "t-svc", b"body");
        assert_ne!(base, stream_user_data(KIND_OPEN, "t-svc", b"body"));
        assert_ne!(base, stream_user_data(KIND_SEND, "u-svc", b"body"));
        assert_ne!(base, stream_user_data(KIND_SEND, "t-svc", b"bodY"));
        // The separators keep a field from running into the next.
        assert_ne!(
            stream_user_data(KIND_SEND, "a", b""),
            stream_user_data("sen", "da", b""),
        );
    }

    const PINNED_VECTOR: &str = "52d59ee5a125b692e6868c8aba6d729cfafe821885e72f726469444ded70c981";
}
