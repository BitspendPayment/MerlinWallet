use crate::error::Error;
use hex_conservative::{DisplayHex, FromHex};
use crate::identifier::Identifier;
use crate::keys::VerifyingKey;
use crate::point;
use alloc::vec::Vec;
use k256::{ProjectivePoint, Scalar};

/// Verifiable Secret Sharing commitment: a list of coefficient commitments g^a_i.
#[derive(Clone, Debug)]
pub struct VssCommitment {
    pub coeffs: Vec<ProjectivePoint>,
}

impl VssCommitment {
    /// Evaluate the commitment polynomial at identifier `id` to get the verifying share.
    ///
    /// Uses the approach: sum += coeffs[k] * x^k for k in 0..len.
    pub fn get_verifying_share(&self, id: &Identifier) -> ProjectivePoint {
        let x = *id.to_scalar();
        let mut itok = Scalar::ONE;
        let mut sum = ProjectivePoint::IDENTITY;

        for k in 0..self.coeffs.len() {
            let term = point::point_mul(&self.coeffs[k], &itok);
            sum = point::point_add(&sum, &term);
            itok = itok * x;
        }
        sum
    }

    /// Extract the group verifying key (constant term commitment).
    pub fn to_verifying_key(&self) -> VerifyingKey {
        VerifyingKey::new(self.coeffs[0])
    }

    /// Deserialize from JSON: a list of hex-encoded 33-byte compressed points.
    pub fn from_json_value(v: &serde_json::Value) -> Result<Self, Error> {
        let arr = v.as_array().ok_or(Error::SerializationError)?;
        let mut coeffs = Vec::with_capacity(arr.len());
        for item in arr {
            let hex_str = item.as_str().ok_or(Error::SerializationError)?;
            let bytes = <[u8; 33]>::from_hex(hex_str)?;
            let p = point::deserialize_compressed(&bytes)?;
            coeffs.push(p);
        }
        Ok(Self { coeffs })
    }

    /// Serialize to JSON: a list of hex-encoded 33-byte compressed points.
    pub fn to_json_value(&self) -> serde_json::Value {
        let arr: Vec<serde_json::Value> = self
            .coeffs
            .iter()
            .map(|c| {
                let bytes = point::serialize_compressed(c);
                serde_json::Value::String(bytes.to_lower_hex_string())
            })
            .collect();
        serde_json::Value::Array(arr)
    }
}

/// Element-wise sum of multiple VSS commitments.
pub fn sum_commitments(commitments: &[VssCommitment]) -> Result<VssCommitment, Error> {
    if commitments.is_empty() {
        return Err(Error::IncorrectNumberOfCommitments);
    }
    let l = commitments[0].coeffs.len();
    if l == 0 {
        return Ok(VssCommitment {
            coeffs: Vec::new(),
        });
    }

    let mut group = alloc::vec![ProjectivePoint::IDENTITY; l];

    for c in commitments {
        if c.coeffs.len() != l {
            return Err(Error::IncorrectNumberOfCommitments);
        }
        for i in 0..l {
            group[i] = point::point_add(&group[i], &c.coeffs[i]);
        }
    }

    Ok(VssCommitment { coeffs: group })
}
