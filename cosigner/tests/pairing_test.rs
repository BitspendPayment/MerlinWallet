//! Pairing a service into an escrow: a second way to sign one key, and the ways it is refused.
//!
//! The escrow key `V'` is held by the wallet and the cosigner. Pairing gives the *service* a share
//! of the same key, by a key-preserving refresh — so afterwards two different pairs can sign `V'`
//! and the cosigner is in both. That last part is the design: nothing moves without it.
//!
//! What is proved here is that a pairing really is one — the key does not move, the service's
//! assembled share signs, and the wallet's own share does not fit the pairing — and that the two
//! ways to make a non-pairing are refused.

mod common;

use rand::rngs::OsRng;

use cosigner::handlers::pairing;

use threshold::dkg;
use threshold::identifier::Identifier;
use threshold::keys::{KeyPackage, PublicKeyPackage};
use threshold::point;
use threshold::scalar::scalar_from_bytes;

const MIN_SIGNERS: usize = 2;

/// An escrow-shaped 2-of-2 to pair into. `dkg_2of2` gives index 0 = wallet, 1 = cosigner, which is
/// the same shape a reshare leaves behind — see `escrow_test.rs` for the reshare itself.
struct Escrow {
    wallet: KeyPackage,
    cosigner: KeyPackage,
    pkp: PublicKeyPackage,
}

fn escrow() -> Escrow {
    let (kps, pkp) = common::dkg_2of2();
    Escrow {
        wallet: kps[0].clone(),
        cosigner: kps[1].clone(),
        pkp,
    }
}

/// The wallet's side: deal onto `{service, cosigner}` and hand over a scalar and a point.
fn wallet_deals(e: &Escrow, service_id: &Identifier) -> (Vec<u8>, Vec<u8>, k256::Scalar) {
    let dealt = dkg::refresh_to_ids(
        &e.wallet,
        &[e.wallet.identifier.clone(), e.cosigner.identifier.clone()],
        &[service_id.clone(), e.cosigner.identifier.clone()],
        MIN_SIGNERS,
        &mut OsRng,
    );
    let a_at_service = dealt[service_id];
    let a_at_cosigner = dealt[&e.cosigner.identifier];
    (
        threshold::scalar::scalar_to_bytes(&a_at_cosigner).to_vec(),
        point::serialize_compressed(&point::base_mul(&a_at_service)).to_vec(),
        a_at_service,
    )
}

fn pair(e: &Escrow, label: &[u8]) -> (Identifier, pairing::PairingMaterial, k256::Scalar) {
    let service_id = Identifier::derive(label).unwrap();
    let (to_cosigner, to_service, a_at_service) = wallet_deals(e, &service_id);
    let material = pairing::pair_service(
        &e.cosigner,
        &e.pkp,
        &e.wallet.identifier,
        &service_id,
        &to_cosigner,
        &to_service,
    )
    .expect("an honest pairing");
    (service_id, material, a_at_service)
}

#[test]
fn a_pairing_does_not_move_the_escrow_key() {
    let e = escrow();
    let (_, material, _) = pair(&e, b"service-a");
    let pkp = PublicKeyPackage::from_json(&material.public_key_package_json).unwrap();

    assert!(
        point::points_equal(&pkp.verifying_key.point, &e.pkp.verifying_key.point),
        "a refresh preserves the key; money already in the escrow must stay reachable"
    );
    assert_eq!(pkp.verifying_shares.len(), 2, "the pairing holds exactly two");
}

/// The point of the whole exercise: the service and the cosigner can sign the escrow.
#[test]
fn the_service_and_the_cosigner_can_sign_the_escrow_key() {
    let e = escrow();
    let (service_id, material, a_at_service) = pair(&e, b"service-a");

    // The service assembles its share from the two halves.
    let b_at_service = scalar_from_bytes(&material.service_half.clone().try_into().unwrap()).unwrap();
    let share = a_at_service + b_at_service;
    let pkp = PublicKeyPackage::from_json(&material.public_key_package_json).unwrap();

    // It checks out against what the pairing published, before relying on it.
    assert!(
        point::points_equal(
            &point::base_mul(&share),
            pkp.verifying_shares.get(&service_id).unwrap()
        ),
        "the assembled share must match the verifying share the pairing published"
    );

    let service_kp = KeyPackage {
        identifier: service_id,
        secret_share: share,
        verifying_share: point::base_mul(&share),
        verifying_key: pkp.verifying_key.clone(),
        min_signers: MIN_SIGNERS,
    };
    let cosigner_kp = KeyPackage::from_json(&material.key_package_json).unwrap();

    let message: [u8; 32] = [3u8; 32];
    let sig = common::group_sign(&[service_kp, cosigner_kp], &pkp, &message);

    use bitcoin::secp256k1::{schnorr, Message, Secp256k1, XOnlyPublicKey};
    let vk = pkp.verifying_key.into_even_y().serialize();
    Secp256k1::verification_only()
        .verify_schnorr(
            &schnorr::Signature::from_slice(&sig).unwrap(),
            &Message::from_digest(message),
            &XOnlyPublicKey::from_slice(&vk[1..]).unwrap(),
        )
        .expect("service + cosigner must sign the escrow key as BIP-340");
}

/// The service's share is not the group key, so it cannot sign alone.
#[test]
fn the_service_cannot_sign_alone() {
    let e = escrow();
    let (_, material, a_at_service) = pair(&e, b"service-a");
    let b_at_service = scalar_from_bytes(&material.service_half.clone().try_into().unwrap()).unwrap();
    let share = a_at_service + b_at_service;
    let pkp = PublicKeyPackage::from_json(&material.public_key_package_json).unwrap();

    assert!(
        !point::points_equal(&point::base_mul(&share), &pkp.verifying_key.point),
        "a share equal to the group key is a service that needs nobody"
    );
}

/// A wallet that lies about the half the cosigner cannot see is refused.
#[test]
fn a_tampered_contribution_to_the_service_is_refused() {
    let e = escrow();
    let service_id = Identifier::derive(b"service-a").unwrap();
    let (to_cosigner, _, _) = wallet_deals(&e, &service_id);

    // Some other point entirely — which is exactly what a client steering the package would send.
    let lie = point::serialize_compressed(&point::base_mul(&threshold::random::mod_n_random(
        &mut OsRng,
    )))
    .to_vec();

    let err = pairing::pair_service(
        &e.cosigner,
        &e.pkp,
        &e.wallet.identifier,
        &service_id,
        &to_cosigner,
        &lie,
    )
    .expect_err("a contribution that does not check out must be refused");
    assert!(
        format!("{err:?}").contains("does not check out"),
        "unexpected: {err:?}"
    );
}

#[test]
fn a_service_claiming_an_identifier_already_in_the_escrow_is_refused() {
    let e = escrow();
    for (who, id) in [
        ("the cosigner's", e.cosigner.identifier.clone()),
        ("the wallet's", e.wallet.identifier.clone()),
    ] {
        let (to_cosigner, to_service, _) = wallet_deals(&e, &id);
        let err = pairing::pair_service(
            &e.cosigner,
            &e.pkp,
            &e.wallet.identifier,
            &id,
            &to_cosigner,
            &to_service,
        )
        .expect_err("a service may not claim an identifier the escrow already has");
        assert!(
            format!("{err:?}").contains("identifier of its own"),
            "{who}: unexpected {err:?}"
        );
    }
}

/// Two services paired into one escrow must not share a slope — two points on one line determine
/// it, and the line's constant term is the escrow key itself.
#[test]
fn two_pairings_have_different_slopes() {
    let e = escrow();
    let (id_a, mat_a, _) = pair(&e, b"service-a");
    let (id_b, mat_b, _) = pair(&e, b"service-b");

    let slope = |mat: &pairing::PairingMaterial, id: &Identifier| {
        let pkp = PublicKeyPackage::from_json(&mat.public_key_package_json).unwrap();
        threshold::service_poly::service_poly_commitment(&pkp, id, MIN_SIGNERS).unwrap()
    };
    assert!(
        !point::points_equal(&slope(&mat_a, &id_a), &slope(&mat_b, &id_b)),
        "two pairings on one slope would let their services interpolate the escrow key"
    );
}

/// The cosigner keeps its own half and hands over the service's, once. A record that kept both
/// would be a record that holds the service's share.
#[test]
fn the_sealed_pairing_holds_the_cosigners_half_and_not_the_services() {
    let e = escrow();
    let (service_id, material, a_at_service) = pair(&e, b"service-a");

    let sealed = cosigner::types::ServicePairing {
        service_identifier_hex: material.service_identifier_hex.clone(),
        key_package_json: material.key_package_json.clone(),
        public_key_package_json: material.public_key_package_json.clone(),
        service_verifying_share_hex: material.service_verifying_share_hex.clone(),
        paired_at: 0,
        attempt_id_hex: "aa".repeat(16),
        service_confirmed: false,
        wallet_confirmed: false,
    };
    let json = serde_json::to_string(&sealed).unwrap();

    let b_at_service =
        scalar_from_bytes(&material.service_half.clone().try_into().unwrap()).unwrap();
    let share = a_at_service + b_at_service;
    for secret in [
        hex::encode(threshold::scalar::scalar_to_bytes(&b_at_service)),
        hex::encode(threshold::scalar::scalar_to_bytes(&share)),
    ] {
        assert!(
            !json.contains(&secret),
            "the sealed pairing must not contain the service's half or its share"
        );
    }

    // What it does hold is this cosigner's own share, which is half of a 2-of-2 and signs nothing
    // by itself.
    let mine = KeyPackage::from_json(&sealed.key_package_json).unwrap();
    assert_eq!(mine.identifier, e.cosigner.identifier);
    assert_ne!(mine.secret_share, share);
    assert_ne!(service_id, e.cosigner.identifier);
}

/// A pairing needs the escrow it is for; a stranger's package cannot stand in.
#[test]
fn a_pairing_against_the_wrong_escrow_is_refused() {
    let mine = escrow();
    let theirs = escrow();
    let service_id = Identifier::derive(b"service-a").unwrap();
    let (to_cosigner, to_service, _) = wallet_deals(&mine, &service_id);

    let err = pairing::pair_service(
        &mine.cosigner,
        &theirs.pkp,
        &mine.wallet.identifier,
        &service_id,
        &to_cosigner,
        &to_service,
    )
    .expect_err("a contribution dealt against one escrow must not pair into another");
    // It fails for the right reason: the contribution is checked against the escrow's own verifying
    // shares, so one dealt elsewhere cannot satisfy them.
    assert!(
        format!("{err:?}").contains("does not check out"),
        "unexpected: {err:?}"
    );
}
