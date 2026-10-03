use core::fmt;

#[derive(Debug, Clone)]
pub enum Error {
    InvalidZeroScalar,
    InvalidScalar,
    InvalidPoint,
    InvalidSignature,
    IdentityCommitment,
    UnknownIdentifier,
    IncorrectNumberOfCommitments,
    IncorrectBindingFactorPreimages,
    MismatchedCommitment,
    SerializationError,
    // DKG errors
    InvalidProofOfKnowledge,
    InvalidSecretShare,
    InvalidCoefficients,
    InvalidMinSigners,
    InvalidMaxSigners,
    IncorrectNumberOfPackages,
    IncorrectPackageMapping,
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Error::InvalidZeroScalar => write!(f, "invalid zero scalar"),
            Error::InvalidScalar => write!(f, "invalid scalar"),
            Error::InvalidPoint => write!(f, "invalid point"),
            Error::InvalidSignature => write!(f, "invalid signature"),
            Error::IdentityCommitment => write!(f, "identity commitment"),
            Error::UnknownIdentifier => write!(f, "unknown identifier"),
            Error::IncorrectNumberOfCommitments => {
                write!(f, "incorrect number of commitments")
            }
            Error::IncorrectBindingFactorPreimages => {
                write!(f, "incorrect binding factor preimages")
            }
            Error::MismatchedCommitment => write!(f, "mismatched commitment"),
            Error::SerializationError => write!(f, "serialization error"),
            Error::InvalidProofOfKnowledge => {
                write!(f, "invalid proof of knowledge")
            }
            Error::InvalidSecretShare => write!(f, "invalid secret share"),
            Error::InvalidCoefficients => write!(f, "invalid coefficients"),
            Error::InvalidMinSigners => write!(f, "invalid min_signers"),
            Error::InvalidMaxSigners => write!(f, "invalid max_signers"),
            Error::IncorrectNumberOfPackages => {
                write!(f, "incorrect number of packages")
            }
            Error::IncorrectPackageMapping => {
                write!(f, "incorrect package mapping")
            }
        }
    }
}

/// Hex that does not decode is malformed serialized data.
impl From<hex_conservative::HexToBytesError> for Error {
    fn from(_: hex_conservative::HexToBytesError) -> Self {
        Error::SerializationError
    }
}

impl From<hex_conservative::HexToArrayError> for Error {
    fn from(_: hex_conservative::HexToArrayError) -> Self {
        Error::SerializationError
    }
}
