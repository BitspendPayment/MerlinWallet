//! Pairing a service into an escrow: a second way to sign `V'`, and no new key.
//!
//! # What a pairing is
//!
//! An escrow key `V'` is held 2-of-2 by the wallet and this cosigner. A deal also needs a way for
//! the *service* to be paid without the payer present at settlement — so the service is given a
//! share of `V'` too, by a **key-preserving refresh**:
//!
//! ```text
//!   wallet   deals  a@service , a@cosigner
//!   cosigner deals  b@service , b@cosigner        (its own, freshly random)
//!   service        s = a@service + b@service
//! ```
//!
//! `V'` does not move. What comes out is a *second* 2-of-2 over the same key — `{service,
//! cosigner}` — so the escrow ends with two pairings and this cosigner in both:
//!
//! | pair | signs `V'` | when |
//! |---|---|---|
//! | wallet + cosigner | yes | reclaim, once the escrow closes |
//! | service + cosigner | yes | release, when the policy permits |
//! | wallet + service | **no** | they share no pairing |
//! | anyone alone | **no** | |
//!
//! That the cosigner is in both is the whole design: nothing moves without it, so its policy is
//! what the escrow actually rests on.
//!
//! # The two things that must be checked here
//!
//! **The half this cosigner cannot see.** The wallet's contribution to the service arrives as a
//! *point*, never a scalar — a cosigner holding both `a@service` and its own counter-share would
//! have two points on one line and could reconstruct the pairing outright. So it must be taken on
//! faith, except that it need not be: [`verify_user_contribution`] pins it down from public data,
//! and a wallet that lies about it is refused rather than allowed to steer the package everything
//! downstream trusts.
//!
//! **A slope of zero.** The pairing polynomial is `f_S(t) = v + m_S·t` with `m_S = r_wallet +
//! r_cosigner`. If `m_S` is zero the polynomial is *constant*: the service's share is the group
//! secret and it signs alone, with nobody's help. Neither half being random prevents that — a
//! wallet that learned this cosigner's half could choose its own to cancel it — so
//! [`service_poly_commitment`] refuses it on the finished package.

use std::collections::BTreeMap;

use rand::rngs::OsRng;

use crate::grpc::Status;

use threshold::dkg::{self, Receiver};
use threshold::identifier::Identifier;
use threshold::keys::{KeyPackage, PublicKeyPackage};
use threshold::point;
use threshold::scalar::{scalar_from_bytes, scalar_to_bytes};
use threshold::service_poly::{service_poly_commitment, verify_user_contribution};

/// Every pairing is a 2-of-2, and the maths here assumes it: `service_poly_commitment` recovers a
/// degree-1 slope from one verifying share, which no higher threshold determines.
const MIN_SIGNERS: usize = 2;

/// What a completed pairing yields.
pub struct PairingMaterial {
    pub service_identifier_hex: String,
    /// This cosigner's share of the `{service, cosigner}` pairing.
    pub key_package_json: String,
    /// The pairing's public package. Its verifying key is `V'` — unchanged, and checked.
    pub public_key_package_json: String,
    /// `b@service`: this cosigner's half of the service's share. **For the service and nobody
    /// else** — handed out once and never kept, because a party holding both halves holds the
    /// service's share.
    pub service_half: Vec<u8>,
    /// The verifying share the service's assembled share must match, hex. Public, and what lets
    /// the service check it was dealt honestly before it relies on being able to sign.
    pub service_verifying_share_hex: String,
}

// Redacting `Debug`: `service_half` is half of the service's share, and `key_package_json` holds
// this cosigner's own. Neither belongs in a log or a panic message.
impl core::fmt::Debug for PairingMaterial {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("PairingMaterial")
            .field("service_identifier_hex", &self.service_identifier_hex)
            .field("service_verifying_share_hex", &self.service_verifying_share_hex)
            .field("key_package_json", &"<redacted>")
            .field("service_half", &"<redacted>")
            .finish()
    }
}

/// Deal this cosigner's half of a service pairing, and refuse anything that would not be a pairing.
///
/// `escrow_kp` / `escrow_pkp` are this cosigner's share of `V'` and the escrow's public package.
/// `a_at_cosigner` is the wallet's contribution to *this cosigner*, a 32-byte scalar;
/// `a_at_service_point` is its contribution to the service, a 33-byte compressed point.
#[allow(clippy::too_many_arguments)]
pub fn pair_service(
    escrow_kp: &KeyPackage,
    escrow_pkp: &PublicKeyPackage,
    wallet_id: &Identifier,
    service_id: &Identifier,
    a_at_cosigner: &[u8],
    a_at_service_point: &[u8],
) -> Result<PairingMaterial, Status> {
    let cosigner_id = escrow_kp.identifier.clone();
    if service_id == &cosigner_id || service_id == wallet_id {
        return Err(Status::invalid_argument(
            "a service must have an identifier of its own, not one already in the escrow",
        ));
    }

    let a_c: [u8; 32] = a_at_cosigner
        .try_into()
        .map_err(|_| Status::invalid_argument("the wallet's scalar contribution must be 32 bytes"))?;
    let a_c = scalar_from_bytes(&a_c)
        .map_err(|e| Status::invalid_argument(format!("bad scalar contribution: {e}")))?;
    let a_s: [u8; 33] = a_at_service_point
        .try_into()
        .map_err(|_| Status::invalid_argument("the wallet's point contribution must be 33 bytes"))?;
    let a_s_point = point::deserialize_compressed(&a_s)
        .map_err(|e| Status::invalid_argument(format!("bad point contribution: {e}")))?;

    // The half this cosigner cannot see, pinned down from public data. A wallet that lies here
    // steers the package everything downstream trusts.
    verify_user_contribution(
        escrow_pkp,
        wallet_id,
        &cosigner_id,
        service_id,
        &a_c,
        &a_s_point,
    )
    .map_err(|e| {
        Status::invalid_argument(format!(
            "the wallet's contribution to this service does not check out: {e}"
        ))
    })?;

    // This cosigner's own half is drawn from the enclave's RNG, never derived and never influenced
    // by a caller: it is the half that makes each pairing's slope distinct, and two pairings on one
    // slope are two points on one line.
    let mut id_partial = BTreeMap::new();
    id_partial.insert(wallet_id.clone(), scalar_to_bytes(&a_c));
    let pairing = dkg::refresh_to_receiver(
        escrow_kp,
        &Receiver {
            id: service_id.clone(),
            partial_verifying_share: a_s,
        },
        &id_partial,
        MIN_SIGNERS,
        &mut OsRng,
    )
    .map_err(|e| Status::internal(format!("refresh_to_receiver: {e}")))?;

    // A refresh preserves the key. If this one did not, the pairing signs for something that is not
    // the escrow — and money sent to the escrow would be unreachable through it.
    if !point::points_equal(
        &pairing.pairing_pkp.verifying_key.point,
        &escrow_pkp.verifying_key.point,
    ) {
        return Err(Status::internal(
            "the pairing moved the escrow key; a refresh must preserve it",
        ));
    }

    // A zero slope would make the pairing polynomial constant and hand the service the group
    // secret. See the module note: nothing upstream prevents it.
    service_poly_commitment(&pairing.pairing_pkp, service_id, MIN_SIGNERS).map_err(|e| {
        Status::invalid_argument(format!(
            "this pairing would let the service sign alone, and is refused: {e}"
        ))
    })?;

    let pkp_json = pairing.pairing_pkp.to_json();
    let verifying_share = pairing
        .pairing_pkp
        .verifying_shares
        .get(service_id)
        .ok_or_else(|| Status::internal("the pairing does not name the service it is for"))?;

    Ok(PairingMaterial {
        service_identifier_hex: hex::encode(service_id.serialize()),
        key_package_json: pairing.my_kp.to_json(),
        public_key_package_json: pkp_json,
        service_half: pairing.receiver_half.to_vec(),
        service_verifying_share_hex: hex::encode(point::serialize_compressed(verifying_share)),
    })
}
