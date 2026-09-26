//! Verifying that a service-share refresh was dealt honestly.
//!
//! A service share is minted by a key-preserving refresh ([`crate::dkg::refresh_to_ids`] /
//! [`crate::dkg::refresh_to_receiver`]): the user and the cosigner each deal a contribution, and
//! the service sums the two halves. Because the refresh preserves the key, EVERY service
//! polynomial has the same constant term `v` (the group secret), and at `min_signers = 2` it is
//! degree 1:
//!
//! ```text
//! f_S(t) = v + m_S·t        where  m_S = r_user,S + r_cosigner,S
//! ```
//!
//! Two services minted on ONE polynomial hold two points on one line and **interpolate `v`
//! outright** — neither the cosigner nor the user involved. So distinctness matters. `m_S` is a
//! sum, and the cosigner's half is drawn fresh from the OS CSPRNG on every pairing, so a collision
//! requires that CSPRNG to repeat — at which point FROST nonce reuse has already broken the wallet,
//! on exactly the same assumption. The wallet's half is derived rather than drawn, so the cosigner
//! also refuses a repeated derivation context; see `handlers::escrow`.
//!
//! The degenerate case is a slope of ZERO, which makes the polynomial constant and hands the
//! service the group secret. That is not prevented by either half being random — a user that knew
//! the cosigner's half could cancel it — so [`service_poly_commitment`] refuses it on the finished
//! package.
//!
//! What DOES need checking is the half the cosigner cannot see. The user supplies its
//! contribution to the service as a POINT, so a lying client could steer the resulting pairing
//! package. [`verify_user_contribution`] pins that down from public data alone.

use crate::error::Error;
use crate::identifier::Identifier;
use crate::keys::PublicKeyPackage;
use crate::lagrange::lagrange_coeff_at_zero;
use crate::point;
use alloc::vec;
use k256::{ProjectivePoint, Scalar};


/// Invert a scalar, mapping the zero scalar to an error rather than panicking.
fn invert(s: &Scalar) -> Result<Scalar, Error> {
    Option::<Scalar>::from(s.invert()).ok_or(Error::InvalidZeroScalar)
}

/// Recover the slope commitment `m·G` of a `{service, cosigner}` pairing polynomial
/// from public data alone.
///
/// For a degree-1 key-preserving refresh, the service's verifying share is
/// `VS_s = V + id_s·(m·G)`, so `m·G = id_s⁻¹ · (VS_s − V)`. Every party holding the
/// pairing [`PublicKeyPackage`] — user, cosigner, and service — derives the same point.
///
/// `min_signers` must be 2. The recovery above assumes degree 1; a higher threshold
/// makes the polynomial's identity depend on coefficients that no single verifying
/// share determines, so this returns [`Error::InvalidMinSigners`] rather than silently
/// computing a wrong id.
pub fn service_poly_commitment(
    pairing_pkp: &PublicKeyPackage,
    service_id: &Identifier,
    min_signers: usize,
) -> Result<ProjectivePoint, Error> {
    if min_signers != 2 {
        return Err(Error::InvalidMinSigners);
    }
    let vs_s = pairing_pkp
        .verifying_shares
        .get(service_id)
        .ok_or(Error::UnknownIdentifier)?;
    let numerator = point::point_add(vs_s, &point::point_negate(&pairing_pkp.verifying_key.point));
    let m_g = point::point_mul(&numerator, &invert(service_id.to_scalar())?);

    // A zero slope is a CONSTANT polynomial: `f_S(t) = v` for every `t`, so the service's share
    // would be the group secret itself and it could sign alone. Nothing upstream prevents this —
    // the slope is a sum, and a user that knew the cosigner's half could choose its own to cancel
    // it — so it is refused here, which is the one place that sees the finished package.
    if point::is_identity(&m_g) {
        return Err(Error::InvalidSecretShare);
    }
    Ok(m_g)
}

/// Verify that the user dealt its refresh contribution honestly, and return its slope
/// commitment `r_u·G`.
///
/// The user hands the cosigner a scalar `a@cosigner = g_u(id_c)` and a *point* `a@service·G`.
/// The cosigner cannot see `a@service`, so without this check it must take the point on faith —
/// and a user that lies about it steers the resulting pairing package. The package is what
/// everything downstream trusts: the verifying share the service is filed under, the share the
/// service assembles, and the key the cosigner will later aggregate against. This is the only
/// thing standing between a lying client and all three.
///
/// The user's contribution is `g_u(t) = λ_u·u + r_u·t`, so with `λ_u·u·G` recoverable
/// from the wallet's public key package:
///
/// ```text
/// r_u·G  = id_c⁻¹ · (a@cosigner·G − λ_u·u·G)
/// check    a@service·G == λ_u·u·G + id_s·(r_u·G)
/// ```
///
/// `r_u = 0` is permitted: the pairing slope is `r_u + r_c`, and the cosigner's own
/// contribution is freshly random, so a constant user contribution is not by itself a
/// break. A zero *pairing* slope is caught by [`service_poly_commitment`].
pub fn verify_user_contribution(
    wallet_pkp: &PublicKeyPackage,
    wallet_id: &Identifier,
    cosigner_id: &Identifier,
    service_id: &Identifier,
    a_at_cosigner: &Scalar,
    a_at_service_point: &ProjectivePoint,
) -> Result<ProjectivePoint, Error> {
    if wallet_id == cosigner_id || service_id == wallet_id || service_id == cosigner_id {
        return Err(Error::IncorrectPackageMapping);
    }
    let u_g = wallet_pkp
        .verifying_shares
        .get(wallet_id)
        .ok_or(Error::UnknownIdentifier)?;

    // The additive piece of the user's share over the current holder set {wallet, cosigner}.
    let id_set = vec![wallet_id.clone(), cosigner_id.clone()];
    let lambda_u = lagrange_coeff_at_zero(wallet_id, &id_set);
    let lam_u_g = point::point_mul(u_g, &lambda_u);

    // r_u·G = id_c⁻¹ · (a@cosigner·G − λ_u·u·G)
    let a_c_g = point::base_mul(a_at_cosigner);
    let numerator = point::point_add(&a_c_g, &point::point_negate(&lam_u_g));
    let r_u_g = point::point_mul(&numerator, &invert(cosigner_id.to_scalar())?);

    // g_u(id_s)·G must equal λ_u·u·G + id_s·(r_u·G).
    let expected = point::point_add(
        &lam_u_g,
        &point::point_mul(&r_u_g, service_id.to_scalar()),
    );
    if !point::points_equal(&expected, a_at_service_point) {
        return Err(Error::InvalidSecretShare);
    }
    Ok(r_u_g)
}
