use crate::error::Error;
use crate::scalar::{scalar_from_bytes, scalar_to_bytes};
use alloc::vec::Vec;
use core::cmp::Ordering;
use k256::elliptic_curve::ops::Reduce;
use k256::elliptic_curve::subtle::ConstantTimeEq;
use k256::{Scalar, U256};
use sha2::{Digest, Sha256};

/// A non-zero scalar identifying a FROST participant.
#[derive(Clone, Debug)]
pub struct Identifier {
    s: Scalar,
}

impl Identifier {
    /// Create an identifier from a non-zero scalar.
    pub fn new(s: Scalar) -> Result<Self, Error> {
        if s.is_zero().into() {
            return Err(Error::InvalidZeroScalar);
        }
        Ok(Self { s })
    }

    /// Derive an identifier from a message: SHA256(msg) mod n.
    pub fn derive(msg: &[u8]) -> Result<Self, Error> {
        let hash = Sha256::digest(msg);
        let wide = U256::from_be_slice(&hash);
        let s = <Scalar as Reduce<U256>>::reduce(wide);
        Self::new(s)
    }

    /// Create an identifier from a small integer (1-based index).
    pub fn from_u16(n: u16) -> Result<Self, Error> {
        if n == 0 {
            return Err(Error::InvalidZeroScalar);
        }
        Self::new(Scalar::from(n as u64))
    }

    /// Get the underlying scalar.
    pub fn to_scalar(&self) -> &Scalar {
        &self.s
    }

    /// Serialize to 32-byte big-endian.
    pub fn serialize(&self) -> [u8; 32] {
        scalar_to_bytes(&self.s)
    }

    /// Deserialize from 32-byte big-endian.
    pub fn deserialize(b: &[u8; 32]) -> Result<Self, Error> {
        let s = scalar_from_bytes(b)?;
        Ok(Self { s })
    }
}

/// 32 bytes, big-endian — what [`Identifier::serialize`] produces.
impl TryFrom<&[u8]> for Identifier {
    type Error = Error;

    fn try_from(bytes: &[u8]) -> Result<Self, Error> {
        let bytes: &[u8; 32] = bytes.try_into().map_err(|_| Error::SerializationError)?;
        Self::deserialize(bytes)
    }
}

/// 64 hex characters: [`Identifier::serialize`], in hex.
impl core::str::FromStr for Identifier {
    type Err = Error;

    fn from_str(s: &str) -> Result<Self, Error> {
        Self::deserialize(&<[u8; 32] as hex_conservative::FromHex>::from_hex(s)?)
    }
}

impl PartialEq for Identifier {
    fn eq(&self, other: &Self) -> bool {
        self.s.ct_eq(&other.s).into()
    }
}

impl Eq for Identifier {}

impl PartialOrd for Identifier {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for Identifier {
    fn cmp(&self, other: &Self) -> Ordering {
        let a = scalar_to_bytes(&self.s);
        let b = scalar_to_bytes(&other.s);
        a.cmp(&b)
    }
}

/// Sort a list of identifiers by their scalar value (big-endian byte comparison).
pub fn sorted_identifiers(ids: &[Identifier]) -> Vec<Identifier> {
    let mut sorted = ids.to_vec();
    sorted.sort();
    sorted
}
