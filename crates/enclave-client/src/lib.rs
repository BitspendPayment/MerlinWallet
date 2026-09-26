//! Verifying that a connection reaches the enclave a client pinned.
//!
//! enclave-runtime attaches an attestation document to every `/auth/*` response, in
//! `x-enclave-attestation`, over the nonce the client sent in `x-enclave-nonce`. The document is
//! an AWS Nitro COSE_Sign1 whose `user_data` binds the TLS certificate the connection served and
//! the guest component behind it. [`verify_connection`] checks all of it; the client then holds
//! [`Attested::certificate_sha256`] and refuses any later connection that serves a different
//! certificate, since guest responses carry no document of their own.
//!
//! No HTTP, no async: callers fetch the document and read the served certificate off their own
//! socket, and pass bytes in.

mod connection;
mod document;
mod error;

pub use connection::{
    guest_pcr, pcr_after_one_extend, verify_connection, Attested, AttestationHashes, Pins,
    ATTESTATION_HASHES_LEN, PCR_GUEST,
};
pub use document::{verify, AttestationDocument, AWS_NITRO_ROOT_G1_PEM};
pub use error::{Error, Result};
