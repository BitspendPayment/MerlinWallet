use crate::error::Error;
use hex_conservative::{DisplayHex, FromHex};
use crate::identifier::Identifier;
use crate::point;
use crate::scalar::{scalar_from_bytes, scalar_to_bytes};
use crate::tweak::compute_tweak;
use alloc::collections::BTreeMap;
use k256::{ProjectivePoint, Scalar};

/// Group public key.
#[derive(Clone, Debug)]
pub struct VerifyingKey {
    pub point: ProjectivePoint,
}

impl VerifyingKey {
    pub fn new(point: ProjectivePoint) -> Self {
        Self { point }
    }

    pub fn has_even_y(&self) -> bool {
        point::has_even_y(&self.point)
    }

    /// Return a copy with even Y. If already even, returns self unchanged.
    pub fn into_even_y(&self) -> Self {
        if !self.has_even_y() {
            Self {
                point: point::point_negate(&self.point),
            }
        } else {
            self.clone()
        }
    }

    /// Serialize the public key as 33-byte compressed point.
    pub fn serialize(&self) -> [u8; 33] {
        point::serialize_compressed(&self.point)
    }

    /// Deserialize from 33-byte compressed point.
    pub fn deserialize(b: &[u8; 33]) -> Result<Self, Error> {
        let p = point::deserialize_compressed(b)?;
        Ok(Self::new(p))
    }
}

/// Per-participant key package containing the secret share.
#[derive(Clone)]
pub struct KeyPackage {
    pub identifier: Identifier,
    pub secret_share: Scalar,
    pub verifying_share: ProjectivePoint,
    pub verifying_key: VerifyingKey,
    pub min_signers: usize,
}

// Redacting Debug: `secret_share` must never reach logs / panic output.
impl core::fmt::Debug for KeyPackage {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("KeyPackage { secret_share: <redacted>, .. }")
    }
}

impl KeyPackage {
    pub fn has_even_y(&self) -> bool {
        self.verifying_key.has_even_y()
    }

    /// Normalize to even Y parity for BIP-340 compatibility.
    pub fn into_even_y(&self) -> Self {
        if !self.has_even_y() {
            Self {
                identifier: self.identifier.clone(),
                secret_share: -self.secret_share,
                verifying_share: point::point_negate(&self.verifying_share),
                verifying_key: self.verifying_key.into_even_y(),
                min_signers: self.min_signers,
            }
        } else {
            self.clone()
        }
    }

    /// Apply taproot tweak (BIP-341).
    pub fn tweak(&self, merkle_root: Option<&[u8]>) -> Self {
        let kp = self.into_even_y();
        let t = compute_tweak(&kp.verifying_key.point, merkle_root);
        let t_g = point::base_mul(&t);

        Self {
            identifier: kp.identifier,
            secret_share: kp.secret_share + t,
            verifying_share: point::point_add(&kp.verifying_share, &t_g),
            verifying_key: VerifyingKey::new(point::point_add(
                &kp.verifying_key.point,
                &t_g,
            )),
            min_signers: kp.min_signers,
        }
    }

    /// Deserialize from JSON (matching Dart format).
    pub fn from_json(json: &str) -> Result<Self, Error> {
        let v: serde_json::Value =
            serde_json::from_str(json).map_err(|_| Error::SerializationError)?;
        Self::from_json_value(&v)
    }

    pub fn from_json_value(v: &serde_json::Value) -> Result<Self, Error> {
        let id_hex = v["identifier"]
            .as_str()
            .ok_or(Error::SerializationError)?;
        let secret_hex = v["secretShare"]
            .as_str()
            .ok_or(Error::SerializationError)?;
        let vs_hex = v["verifyingShare"]
            .as_str()
            .ok_or(Error::SerializationError)?;
        let vk_hex = v["verifyingKey"]
            .as_str()
            .ok_or(Error::SerializationError)?;
        let min_signers = v["minSigners"]
            .as_u64()
            .ok_or(Error::SerializationError)? as usize;

        let id_bytes = <[u8; 32]>::from_hex(id_hex)?;
        let secret_bytes = <[u8; 32]>::from_hex(secret_hex)?;
        let vs_bytes = <[u8; 33]>::from_hex(vs_hex)?;
        let vk_bytes = <[u8; 33]>::from_hex(vk_hex)?;

        Ok(Self {
            identifier: Identifier::deserialize(&id_bytes)?,
            secret_share: scalar_from_bytes(&secret_bytes)?,
            verifying_share: point::deserialize_compressed(&vs_bytes)?,
            verifying_key: VerifyingKey::deserialize(&vk_bytes)?,
            min_signers,
        })
    }

    /// Serialize to JSON (matching Dart format).
    pub fn to_json(&self) -> alloc::string::String {
        use alloc::format;
        let id = self.identifier.serialize().to_lower_hex_string();
        let ss = scalar_to_bytes(&self.secret_share).to_lower_hex_string();
        let vs = point::serialize_compressed(&self.verifying_share).to_lower_hex_string();
        let vk = self.verifying_key.serialize().to_lower_hex_string();
        format!(
            r#"{{"identifier":"{}","secretShare":"{}","verifyingShare":"{}","verifyingKey":"{}","minSigners":{}}}"#,
            id, ss, vs, vk, self.min_signers
        )
    }
}

/// Group public key package (no secrets).
#[derive(Clone, Debug)]
pub struct PublicKeyPackage {
    pub verifying_shares: BTreeMap<Identifier, ProjectivePoint>,
    pub verifying_key: VerifyingKey,
}

impl PublicKeyPackage {
    pub fn has_even_y(&self) -> bool {
        self.verifying_key.has_even_y()
    }

    /// Normalize to even Y parity.
    pub fn into_even_y(&self) -> Self {
        if !self.has_even_y() {
            let new_shares = self
                .verifying_shares
                .iter()
                .map(|(id, share)| {
                    (id.clone(), point::point_negate(share))
                })
                .collect();
            Self {
                verifying_shares: new_shares,
                verifying_key: self.verifying_key.into_even_y(),
            }
        } else {
            self.clone()
        }
    }

    /// Apply taproot tweak.
    pub fn tweak(&self, merkle_root: Option<&[u8]>) -> Self {
        let pkg = self.into_even_y();
        let t = compute_tweak(&pkg.verifying_key.point, merkle_root);
        let t_g = point::base_mul(&t);

        let new_shares = pkg
            .verifying_shares
            .iter()
            .map(|(id, share)| {
                (id.clone(), point::point_add(share, &t_g))
            })
            .collect();

        Self {
            verifying_shares: new_shares,
            verifying_key: VerifyingKey::new(point::point_add(
                &pkg.verifying_key.point,
                &t_g,
            )),
        }
    }

    /// Serialize to JSON (matching Dart format).
    pub fn to_json(&self) -> alloc::string::String {
        use alloc::format;
        use alloc::string::String;
        use alloc::vec::Vec;

        let vk = self.verifying_key.serialize().to_lower_hex_string();

        let shares: Vec<String> = self
            .verifying_shares
            .iter()
            .map(|(id, share)| {
                let id_hex = id.serialize().to_lower_hex_string();
                let share_hex = point::serialize_compressed(share).to_lower_hex_string();
                format!(r#""{}":"{}""#, id_hex, share_hex)
            })
            .collect();

        let shares_str = shares.join(",");
        format!(
            r#"{{"verifyingKey":"{}","verifyingShares":{{{}}}}}"#,
            vk, shares_str
        )
    }

    /// Deserialize from JSON (matching Dart format).
    pub fn from_json(json: &str) -> Result<Self, Error> {
        let v: serde_json::Value =
            serde_json::from_str(json).map_err(|_| Error::SerializationError)?;
        Self::from_json_value(&v)
    }

    pub fn from_json_value(v: &serde_json::Value) -> Result<Self, Error> {
        let vk_hex = v["verifyingKey"]
            .as_str()
            .ok_or(Error::SerializationError)?;
        let vk_bytes = <[u8; 33]>::from_hex(vk_hex)?;
        let verifying_key = VerifyingKey::deserialize(&vk_bytes)?;

        let shares_obj = v["verifyingShares"]
            .as_object()
            .ok_or(Error::SerializationError)?;
        let mut verifying_shares = BTreeMap::new();
        for (key, value) in shares_obj {
            let id_bytes = <[u8; 32]>::from_hex(key)?;
            let id = Identifier::deserialize(&id_bytes)?;
            let share_hex =
                value.as_str().ok_or(Error::SerializationError)?;
            let share_bytes = <[u8; 33]>::from_hex(share_hex)?;
            let share = point::deserialize_compressed(&share_bytes)?;
            verifying_shares.insert(id, share);
        }

        Ok(Self {
            verifying_shares,
            verifying_key,
        })
    }
}
