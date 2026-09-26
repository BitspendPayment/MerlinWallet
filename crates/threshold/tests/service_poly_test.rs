//! The service-polynomial invariant: no two service shares may live on the same
//! refreshed polynomial.
//!
//! `test_duplicate_slope_recovers_group_secret` is the reason the rest of this file
//! exists — it demonstrates the actual break. Keep it as a permanent regression guard:
//! if it ever stops recovering the secret, the threat model here has changed and the
//! enforcement elsewhere should be re-derived rather than trusted.

extern crate alloc;

use alloc::collections::BTreeMap;
use alloc::vec::Vec;
use k256::Scalar;
use rand::rngs::OsRng;
use threshold::dkg::{self, Receiver};
use threshold::error::Error;
use threshold::identifier::Identifier;
use threshold::keys::{KeyPackage, PublicKeyPackage, VerifyingKey};
use threshold::lagrange::lagrange_coeff_at_zero;
use threshold::nonce::new_nonce;
use threshold::point;
use threshold::service_poly::verify_user_contribution;

const MIN_SIGNERS: usize = 2;

fn random_scalar(rng: &mut impl rand::RngCore) -> Scalar {
    loop {
        let s = new_nonce(rng, &Scalar::ONE).hiding;
        if !bool::from(s.is_zero()) {
            return s;
        }
    }
}

/// A 2-of-2 wallet, dealer-style, keeping the group secret so tests can assert
/// recovery against ground truth.
struct Wallet {
    secret: Scalar,
    wallet_id: Identifier,
    cosigner_id: Identifier,
    wallet_kp: KeyPackage,
    cosigner_kp: KeyPackage,
    pkp: PublicKeyPackage,
}

fn deal_2of2(rng: &mut impl rand::RngCore) -> Wallet {
    let secret = random_scalar(rng);
    let slope = random_scalar(rng);
    let coeffs = [secret, slope];

    let wallet_id = Identifier::from_u16(1).unwrap();
    let cosigner_id = Identifier::from_u16(2).unwrap();

    let eval = |id: &Identifier| {
        let x = *id.to_scalar();
        coeffs[0] + coeffs[1] * x
    };
    let w_share = eval(&wallet_id);
    let c_share = eval(&cosigner_id);
    let vk = VerifyingKey::new(point::base_mul(&secret));

    let mut verifying_shares = BTreeMap::new();
    verifying_shares.insert(wallet_id.clone(), point::base_mul(&w_share));
    verifying_shares.insert(cosigner_id.clone(), point::base_mul(&c_share));
    let pkp = PublicKeyPackage {
        verifying_shares,
        verifying_key: vk.clone(),
    };

    let mk = |id: &Identifier, share: Scalar| KeyPackage {
        identifier: id.clone(),
        secret_share: share,
        verifying_share: point::base_mul(&share),
        verifying_key: vk.clone(),
        min_signers: MIN_SIGNERS,
    };

    Wallet {
        secret,
        wallet_id: wallet_id.clone(),
        cosigner_id: cosigner_id.clone(),
        wallet_kp: mk(&wallet_id, w_share),
        cosigner_kp: mk(&cosigner_id, c_share),
        pkp,
    }
}

/// Interpolate a set of (identifier, share) points back to the constant term.
fn interpolate(points: &[(Identifier, Scalar)]) -> Scalar {
    let ids: Vec<Identifier> = points.iter().map(|(id, _)| id.clone()).collect();
    points.iter().fold(Scalar::ZERO, |acc, (id, share)| {
        acc + lagrange_coeff_at_zero(id, &ids) * *share
    })
}

/// Run the real enrollment: the user deals its contribution, the cosigner deals its own
/// and returns the pairing, and the service sums the two halves into its share.
struct Enrollment {
    service_id: Identifier,
    service_share: Scalar,
    pairing: dkg::RefreshedPairing,
    a_at_cosigner: Scalar,
    a_at_service_point: k256::ProjectivePoint,
}

fn enroll(w: &Wallet, service_label: &[u8], rng: &mut (impl rand::RngCore + rand_core::RngCore)) -> Enrollment {
    let service_id = Identifier::derive(service_label).unwrap();

    // User side: deal onto {service, cosigner}.
    let dealt = dkg::refresh_to_ids(
        &w.wallet_kp,
        &[w.wallet_id.clone(), w.cosigner_id.clone()],
        &[service_id.clone(), w.cosigner_id.clone()],
        MIN_SIGNERS,
        rng,
    );
    let a_at_service = dealt[&service_id];
    let a_at_cosigner = dealt[&w.cosigner_id];
    let a_at_service_point = point::base_mul(&a_at_service);

    // Cosigner side: deal its own contribution, fold in the user's, build the pairing.
    let mut id_partial = BTreeMap::new();
    id_partial.insert(
        w.wallet_id.clone(),
        threshold::scalar::scalar_to_bytes(&a_at_cosigner),
    );
    let pairing = dkg::refresh_to_receiver(
        &w.cosigner_kp,
        &Receiver {
            id: service_id.clone(),
            partial_verifying_share: point::serialize_compressed(&a_at_service_point),
        },
        &id_partial,
        MIN_SIGNERS,
        rng,
    )
    .expect("refresh_to_receiver");

    // Service side: s = a@service + b@service.
    let b_at_service =
        threshold::scalar::scalar_from_bytes(&pairing.receiver_half).unwrap();
    let service_share = a_at_service + b_at_service;

    Enrollment {
        service_id,
        service_share,
        pairing,
        a_at_cosigner,
        a_at_service_point,
    }
}

// ---------------------------------------------------------------------------



/// THE ATTACK. Two services issued shares under one slope interpolate the group secret
/// outright — no cosigner, no user. This is why the cosigner's half of every slope must come from
/// a CSPRNG and never from anything a caller can influence or repeat.
#[test]
fn duplicate_slope_recovers_group_secret() {
    let mut rng = OsRng;
    let secret = random_scalar(&mut rng);
    let slope = random_scalar(&mut rng);

    let id_a = Identifier::derive(b"service-a").unwrap();
    let id_b = Identifier::derive(b"service-b").unwrap();

    // Same polynomial f(t) = secret + slope·t, two different service identifiers.
    let f = |id: &Identifier| secret + slope * *id.to_scalar();
    let share_a = f(&id_a);
    let share_b = f(&id_b);

    let stolen = interpolate(&[(id_a, share_a), (id_b, share_b)]);
    assert_eq!(
        stolen, secret,
        "two shares on one line reconstruct the group secret — the invariant is load-bearing"
    );
}


#[test]
fn user_contribution_verifies_when_dealt_honestly() {
    let mut rng = OsRng;
    let w = deal_2of2(&mut rng);
    let e = enroll(&w, b"service-a", &mut rng);

    verify_user_contribution(
        &w.pkp,
        &w.wallet_id,
        &w.cosigner_id,
        &e.service_id,
        &e.a_at_cosigner,
        &e.a_at_service_point,
    )
    .expect("an honestly dealt contribution must verify");
}

#[test]
fn user_contribution_rejects_a_tampered_service_point() {
    let mut rng = OsRng;
    let w = deal_2of2(&mut rng);
    let e = enroll(&w, b"service-a", &mut rng);

    // Nudge the point the cosigner cannot otherwise check.
    let tampered = point::point_add(&e.a_at_service_point, &point::base_mul(&Scalar::ONE));
    let err = verify_user_contribution(
        &w.pkp,
        &w.wallet_id,
        &w.cosigner_id,
        &e.service_id,
        &e.a_at_cosigner,
        &tampered,
    )
    .unwrap_err();
    assert!(matches!(err, Error::InvalidSecretShare), "got {err:?}");
}

#[test]
fn user_contribution_rejects_a_tampered_cosigner_scalar() {
    let mut rng = OsRng;
    let w = deal_2of2(&mut rng);
    let e = enroll(&w, b"service-a", &mut rng);

    let err = verify_user_contribution(
        &w.pkp,
        &w.wallet_id,
        &w.cosigner_id,
        &e.service_id,
        &(e.a_at_cosigner + Scalar::ONE),
        &e.a_at_service_point,
    )
    .unwrap_err();
    assert!(matches!(err, Error::InvalidSecretShare), "got {err:?}");
}




#[test]
fn user_contribution_rejects_colliding_identifiers() {
    let mut rng = OsRng;
    let w = deal_2of2(&mut rng);
    let e = enroll(&w, b"service-a", &mut rng);

    // A service that claims the cosigner's identifier would sit on top of the
    // cosigner's own counter-share.
    let err = verify_user_contribution(
        &w.pkp,
        &w.wallet_id,
        &w.cosigner_id,
        &w.cosigner_id,
        &e.a_at_cosigner,
        &e.a_at_service_point,
    )
    .unwrap_err();
    assert!(matches!(err, Error::IncorrectPackageMapping), "got {err:?}");
}


// ---------------------------------------------------------------------------
// `service_poly_commitment` — the check the branch's doc promised and never had.
// ---------------------------------------------------------------------------

/// The slope every party can recover, and the property that makes it worth recovering: it is the
/// same point whoever computes it, from the pairing package alone.
#[test]
fn the_pairing_slope_is_recoverable_from_public_data() {
    let mut rng = OsRng;
    let w = deal_2of2(&mut rng);
    let e = enroll(&w, b"service-a", &mut rng);

    let m_g = threshold::service_poly::service_poly_commitment(
        &e.pairing.pairing_pkp,
        &e.service_id,
        MIN_SIGNERS,
    )
    .expect("an honest pairing has a recoverable slope");

    // It is the slope the enrolment actually used: `VS_s = V + id_s·(m·G)` rearranged the other
    // way round must land back on the service's verifying share.
    let vs = e
        .pairing
        .pairing_pkp
        .verifying_shares
        .get(&e.service_id)
        .unwrap();
    let rebuilt = point::point_add(
        &e.pairing.pairing_pkp.verifying_key.point,
        &point::point_mul(&m_g, e.service_id.to_scalar()),
    );
    assert!(point::points_equal(&rebuilt, vs));

    // And the share the service assembled is not the group secret.
    assert!(
        !point::points_equal(
            &point::base_mul(&e.service_share),
            &e.pairing.pairing_pkp.verifying_key.point
        ),
        "a service whose share is the group key could sign alone"
    );
}

/// THE DEGENERATE CASE. A zero slope makes the polynomial constant — `f_S(t) = v` for every `t` —
/// so the service's share IS the group secret and it signs alone, with nobody's help.
///
/// Neither half being random prevents it: the slope is a sum, so a user that learned the
/// cosigner's half could choose its own to cancel it exactly. This is the only place that sees the
/// finished package, and so the only place that can refuse.
#[test]
fn a_zero_slope_is_refused_rather_than_handing_the_service_the_group_key() {
    let mut rng = OsRng;
    let w = deal_2of2(&mut rng);
    let e = enroll(&w, b"service-a", &mut rng);
    let service_id = e.service_id.clone();

    // A pairing package whose service verifying share IS the group key — exactly what a cancelled
    // slope produces.
    let mut shares = e.pairing.pairing_pkp.verifying_shares.clone();
    let vk = e.pairing.pairing_pkp.verifying_key.point;
    shares.insert(service_id.clone(), vk);
    let degenerate = PublicKeyPackage {
        verifying_shares: shares,
        verifying_key: VerifyingKey::new(vk),
    };

    assert!(
        matches!(
            threshold::service_poly::service_poly_commitment(&degenerate, &service_id, MIN_SIGNERS),
            Err(Error::InvalidSecretShare)
        ),
        "a constant pairing polynomial must be refused"
    );
}

/// The recovery assumes degree 1. At any other threshold the slope is not determined by one
/// verifying share, so it refuses rather than computing something that looks like an answer.
#[test]
fn a_threshold_other_than_two_is_refused_rather_than_guessed() {
    let mut rng = OsRng;
    let w = deal_2of2(&mut rng);
    let e = enroll(&w, b"service-a", &mut rng);

    for min_signers in [1usize, 3, 5] {
        assert!(matches!(
            threshold::service_poly::service_poly_commitment(
                &e.pairing.pairing_pkp,
                &e.service_id,
                min_signers,
            ),
            Err(Error::InvalidMinSigners)
        ));
    }
}

#[test]
fn a_service_the_pairing_does_not_name_is_refused() {
    let mut rng = OsRng;
    let w = deal_2of2(&mut rng);
    let e = enroll(&w, b"service-a", &mut rng);
    let stranger = Identifier::derive(b"service-b").unwrap();

    assert!(matches!(
        threshold::service_poly::service_poly_commitment(
            &e.pairing.pairing_pkp,
            &stranger,
            MIN_SIGNERS,
        ),
        Err(Error::UnknownIdentifier)
    ));
}
