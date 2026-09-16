use thiserror::Error;

/// Why a document was refused. Every variant is a refusal: there is no "verified, but" here.
#[derive(Error, Debug)]
pub enum Error {
    #[error("malformed attestation document: {0}")]
    Malformed(String),

    #[error("certificate chain: {0}")]
    Chain(String),

    #[error("the document's signature does not verify under its leaf certificate")]
    Signature,

    #[error("PCR{index} mismatch: the document says {got}, expected {expected}")]
    PcrMismatch { index: u32, got: String, expected: String },

    #[error("the document carries no PCR{0}")]
    PcrMissing(u32),

    #[error("the document carries no nonce, so it cannot be shown to be fresh")]
    NonceMissing,

    #[error("nonce mismatch: the document echoes {got}, sent {sent}")]
    NonceMismatch { got: String, sent: String },

    #[error("user_data: {0}")]
    UserData(String),

    #[error("the document is bound to certificate {bound}, but this connection was served {served}")]
    CertificateMismatch { bound: String, served: String },

    #[error("the document's guest hash {guest} does not measure to its PCR16")]
    GuestMismatch { guest: String },

    #[error("the document is {age_secs}s old, over the {max_age_secs}s limit")]
    Stale { age_secs: u64, max_age_secs: u64 },
}

pub type Result<T> = std::result::Result<T, Error>;
