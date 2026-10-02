//! The escrow key: a second key for the same pair, and a share that is still not kept anywhere.
//!
//! Two properties matter, and one of them is easy to get wrong quietly.
//!
//! The obvious one is that both sides end the reshare on the same `V'`, that it is genuinely a new
//! key rather than the wallet's own, and that the pair can sign under it.
//!
//! The one that would rot silently is the arithmetic: escrowed money must be as recoverable as
//! ordinary money. A wallet keeps no share — it rebuilds one per operation from its passkey plus a
//! scalar this cosigner sealed — and an escrow share that could not be rebuilt the same way would
//! be the single thing a lost phone could not get back. So the whole chain is checked here, from a
//! real ceremony to a real reshare:
//!
//! ```text
//!   s'_wallet  ==  f_wallet(id) + Δ_wallet(id) + contribution
//! ```
//!
//! where `contribution` is the one scalar the cosigner seals and the other two come from the
//! passkey.

mod common;

use std::collections::BTreeMap;

use rand::rngs::OsRng;

use cosigner::handlers::escrow::{self, EscrowSession};
use cosigner::handlers::onboarding::{self as ob, OnboardingSession};
use cosigner::wallet_proto::{DkgStep1Request, DkgStep3Request};

use threshold::dkg::{self, Round1Package, Round2Package};
use threshold::identifier::Identifier;
use threshold::keys::{KeyPackage, PublicKeyPackage};
use threshold::point;
use threshold::random;
use threshold::scalar::{scalar_from_bytes, scalar_to_bytes};

/// The client's parity rule: a rebuilt share is right up to a sign, and the verifying share — which
/// is public and already on the device — says which. `None` when neither matches, which is how a
/// missing or wrong term announces itself instead of producing a share that cannot sign.
///
/// A macro rather than a function: the scalar type is not re-exported, so it cannot be named in a
/// signature, only inferred.
macro_rules! pick_sign {
    ($cand:expr, $vs:expr $(,)?) => {{
        let c = $cand;
        if point::points_equal(&point::base_mul(&c), $vs) {
            Some(c)
        } else if point::points_equal(&point::base_mul(&-c), $vs) {
            Some(-c)
        } else {
            None
        }
    }};
}

/// One wallet, made the way a real one is: the cosigner runs the ceremony, and the wallet's side is
/// played here so the test keeps the polynomial a passkey would have derived.
struct Wallet {
    kp: KeyPackage,
    pkp: PublicKeyPackage,
    /// `f_wallet`, the polynomial this wallet dealt — a passkey derives this on a real device.
    /// Kept as bytes: the scalar type is not re-exported, and bytes are what a device would hold.
    coefficients: Vec<[u8; 32]>,
    /// What the cosigner sealed: `f_cosigner(id_wallet)`.
    dealt_share_hex: String,
    /// The cosigner's own key material for this wallet.
    cosigner_kp: KeyPackage,
}

fn onboard() -> Wallet {
    let mut rng = OsRng;
    let secret = random::mod_n_random(&mut rng);
    let coefficients = vec![random::mod_n_random(&mut rng)];
    let (w_r1_secret, w_r1_pub) = dkg::dkg_part1(2, 2, &secret, &coefficients, &mut rng).unwrap();
    let wallet_id = w_r1_secret.identifier.clone();

    let mut sess = OnboardingSession::new();
    let r1 = ob::dkg_open(
        &mut sess,
        DkgStep1Request {
            identifier: wallet_id.serialize().to_vec(),
            round1_package: w_r1_pub.to_json(),
        },
    )
    .expect("open");

    let others_r1: BTreeMap<Identifier, Round1Package> = r1
        .round1_packages
        .iter()
        .map(|(id_hex, json)| {
            let b: [u8; 32] = hex::decode(id_hex).unwrap().try_into().unwrap();
            (
                Identifier::deserialize(&b).unwrap(),
                Round1Package::from_json(json).unwrap(),
            )
        })
        .filter(|(id, _)| *id != wallet_id)
        .collect();

    let (w_r2_secret, w_r2_out) = dkg::dkg_part2(&w_r1_secret, &others_r1, &[]).unwrap();
    let r3 = ob::dkg_finish(
        &mut sess,
        DkgStep3Request {
            identifier: wallet_id.serialize().to_vec(),
            round2_packages_for_others: w_r2_out
                .iter()
                .map(|(id, p)| (hex::encode(id.serialize()), p.to_json()))
                .collect(),
        },
    )
    .expect("finish");
    let mat = sess.seed_material.take().expect("key material");

    let ours: BTreeMap<Identifier, Round2Package> = r3
        .round2_packages_for_me
        .iter()
        .map(|(id_hex, json)| {
            let b: [u8; 32] = hex::decode(id_hex).unwrap().try_into().unwrap();
            (
                Identifier::deserialize(&b).unwrap(),
                Round2Package::from_json(json).unwrap(),
            )
        })
        .collect();
    let (kp, pkp) = dkg::dkg_part3(&w_r1_secret, &w_r2_secret, &others_r1, &ours, &[]).unwrap();

    Wallet {
        kp,
        pkp,
        coefficients: w_r1_secret.coefficients.iter().map(scalar_to_bytes).collect(),
        dealt_share_hex: mat.wallet_dealt_share_hex.expect("a sealed dealt share"),
        cosigner_kp: KeyPackage::from_json(&mat.key_package_json).expect("cosigner kp"),
    }
}

/// Run the reshare: the cosigner through its handler, the wallet's half played here.
fn make_escrow(
    w: &Wallet,
) -> (KeyPackage, PublicKeyPackage, escrow::EscrowMaterial, Vec<[u8; 32]>) {
    let mut rng = OsRng;
    let wallet_id = w.kp.identifier.clone();
    let cosigner_id = w.cosigner_kp.identifier.clone();

    // The wallet's Δ. On a device this comes from the passkey; the point of the test is that it is
    // *some* polynomial the wallet can reproduce, so it is kept and used again below.
    let delta_secret = random::mod_n_random(&mut rng);
    let delta_coeffs = vec![random::mod_n_random(&mut rng)];
    let (w_r1s, w_r1p) =
        dkg::dkg_reshare_part1(&wallet_id, 2, 2, &delta_secret, &delta_coeffs, &mut rng).unwrap();

    let mut sess = EscrowSession::new();
    let server_r1_json = sess
        .begin(&w.cosigner_kp, &wallet_id.serialize(), &w_r1p.to_json(), &fresh_context())
        .expect("begin");
    let server_r1 = Round1Package::from_json(&server_r1_json).unwrap();

    let peers: BTreeMap<Identifier, Round1Package> =
        [(cosigner_id.clone(), server_r1)].into_iter().collect();
    let (w_r2s, w_shares) = dkg::dkg_part2(&w_r1s, &peers, &[]).unwrap();

    let server_r2_json = sess
        .finalise(&w.cosigner_kp, &w.pkp, &w_shares.get(&cosigner_id).unwrap().to_json())
        .expect("finalise");
    let material = sess.material.take().expect("escrow material");

    let peers_r2: BTreeMap<Identifier, Round2Package> = [(
        cosigner_id.clone(),
        Round2Package::from_json(&server_r2_json).unwrap(),
    )]
    .into_iter()
    .collect();
    let receivers = [wallet_id, cosigner_id];
    let (new_kp, new_pkp) =
        dkg::dkg_reshare_part3(&w_r2s, &peers, &peers_r2, &w.pkp, &w.kp, &receivers)
            .expect("wallet reshare part3");

    (
        new_kp,
        new_pkp,
        material,
        w_r1s.coefficients.iter().map(scalar_to_bytes).collect(),
    )
}

#[test]
fn both_sides_land_on_one_escrow_key_and_it_is_not_the_wallet_key() {
    let w = onboard();
    let (wallet_escrow_kp, wallet_escrow_pkp, material, _) = make_escrow(&w);

    assert_eq!(
        hex::encode(wallet_escrow_pkp.verifying_key.serialize()),
        material.escrow_key,
        "the wallet and the cosigner must derive the same escrow key"
    );
    assert_ne!(
        material.escrow_key,
        hex::encode(w.pkp.verifying_key.serialize()),
        "an escrow key that is the wallet's key would put the service in the wallet"
    );
    assert_eq!(
        wallet_escrow_kp.identifier, w.kp.identifier,
        "the reshare keeps the identifiers it was dealt under"
    );
    // Two holders, no more: a reshare that left a third party in would be a different design.
    let escrow_pkp: PublicKeyPackage =
        PublicKeyPackage::from_json(&material.public_key_package_json).unwrap();
    assert_eq!(escrow_pkp.verifying_shares.len(), 2);
}

/// The property that keeps escrowed money recoverable — run exactly as a device runs it.
///
/// Two normalisations, so two parity choices, each settled against a verifying share that is public
/// and already on the device. An earlier version of this folded the dealt share into the cosigner's
/// delta and passed about half the time: whenever `V` came out with even Y. That is why the steps
/// are kept separate and why both `±` are resolved here rather than assumed.
#[test]
fn the_escrow_share_rebuilds_from_the_passkey_and_one_sealed_scalar() {
    let w = onboard();
    let (wallet_escrow_kp, _, material, delta_coefficients) = make_escrow(&w);
    let id = w.kp.identifier.clone();

    // Back to scalars from the bytes a device would hold. Named by inference — the scalar type is
    // not re-exported, which is itself a hint that bytes are the right thing to keep.
    let wallet_poly: Vec<_> = w
        .coefficients
        .iter()
        .map(|b| scalar_from_bytes(b).unwrap())
        .collect();
    let delta_poly: Vec<_> = delta_coefficients
        .iter()
        .map(|b| scalar_from_bytes(b).unwrap())
        .collect();

    // Step 1 — the wallet share, as every operation already rebuilds it: the passkey's polynomial
    // plus the scalar sealed at DKG, with the sign the verifying share picks.
    let dealt = scalar_from_bytes(&hex32(&w.dealt_share_hex)).unwrap();
    let own = threshold::polynomial::evaluate_polynomial(&id, &wallet_poly);
    let s_wallet = pick_sign!(own + dealt, w.pkp.verifying_shares.get(&id).unwrap())
        .expect("the wallet share must rebuild from the passkey and the sealed dealt share");
    assert_eq!(
        s_wallet, w.kp.secret_share,
        "and it must be the share the ceremony produced"
    );

    // Step 2 — the escrow share on top of it: the passkey's delta plus the one scalar this escrow
    // sealed, with the sign the ESCROW's verifying share picks.
    let escrow_pkp = PublicKeyPackage::from_json(&material.public_key_package_json).unwrap();
    let own_delta = threshold::polynomial::evaluate_polynomial(&id, &delta_poly);
    let cosigner_delta = scalar_from_bytes(&hex32(&material.wallet_delta_share_hex)).unwrap();
    let rebuilt = pick_sign!(
        s_wallet + own_delta + cosigner_delta,
        escrow_pkp.verifying_shares.get(&id).unwrap(),
    )
    .expect("the escrow share must rebuild from the wallet share, the passkey and the sealed delta");

    assert_eq!(
        rebuilt, wallet_escrow_kp.secret_share,
        "the rebuilt escrow share must be the one the reshare produced"
    );

    // Each term is load-bearing: drop any one and nothing checks out.
    assert!(pick_sign!(own_delta + cosigner_delta, escrow_pkp.verifying_shares.get(&id).unwrap()).is_none());
    assert!(pick_sign!(s_wallet + cosigner_delta, escrow_pkp.verifying_shares.get(&id).unwrap()).is_none());
    assert!(pick_sign!(s_wallet + own_delta, escrow_pkp.verifying_shares.get(&id).unwrap()).is_none());
}

#[test]
fn the_pair_can_sign_under_the_escrow_key() {
    let w = onboard();
    let (wallet_escrow_kp, wallet_escrow_pkp, material, _) = make_escrow(&w);
    let cosigner_escrow_kp = KeyPackage::from_json(&material.key_package_json).unwrap();

    // Thirty-two bytes, because BIP-340 verification takes a digest.
    let message: [u8; 32] = [7u8; 32];
    let sig = common::group_sign(
        &[wallet_escrow_kp, cosigner_escrow_kp],
        &wallet_escrow_pkp,
        &message,
    );

    // Checked with `bitcoin`'s secp256k1 rather than this repo's own verifier: an independent
    // implementation agreeing is worth more than ours agreeing with itself, and it is the one the
    // network would apply.
    use bitcoin::secp256k1::{schnorr, Message, Secp256k1, XOnlyPublicKey};
    let vk = wallet_escrow_pkp.verifying_key.into_even_y().serialize();
    let xonly = XOnlyPublicKey::from_slice(&vk[1..]).expect("an x-only key");
    Secp256k1::verification_only()
        .verify_schnorr(
            &schnorr::Signature::from_slice(&sig).expect("a schnorr signature"),
            &Message::from_digest(message),
            &xonly,
        )
        .expect("the escrow pair's signature must verify under V' as BIP-340");
}

/// Two escrows from one wallet must not share a delta: two of this cosigner's dealings on one line
/// would be two points on it.
#[test]
fn two_escrows_from_one_wallet_are_different_keys() {
    let w = onboard();
    let (_, _, first, _) = make_escrow(&w);
    let (_, _, second, _) = make_escrow(&w);

    assert_ne!(
        first.escrow_key, second.escrow_key,
        "a second escrow must be a second key"
    );
    assert_ne!(
        first.wallet_delta_share_hex, second.wallet_delta_share_hex,
        "and a second delta — a reused delta is a reused line"
    );
}

#[test]
fn a_ceremony_that_has_not_opened_refuses_to_finish() {
    let w = onboard();
    let mut sess = EscrowSession::new();
    let err = sess.finalise(&w.cosigner_kp, &w.pkp, "{}")
        .expect_err("finishing what never opened must refuse");
    assert!(format!("{err:?}").contains("has not opened"), "unexpected: {err:?}");
}

#[test]
fn opening_twice_refuses_rather_than_dealing_a_second_delta() {
    let w = onboard();
    let mut rng = OsRng;
    let id = w.kp.identifier.clone();
    let (_, r1p) = dkg::dkg_reshare_part1(
        &id,
        2,
        2,
        &random::mod_n_random(&mut rng),
        &[random::mod_n_random(&mut rng)],
        &mut rng,
    )
    .unwrap();

    let mut sess = EscrowSession::new();
    let ctx = fresh_context();
    sess.begin(&w.cosigner_kp, &id.serialize(), &r1p.to_json(), &ctx).expect("first");
    let err = sess.begin(&w.cosigner_kp, &id.serialize(), &r1p.to_json(), &ctx)
        .expect_err("a second open on one session must refuse");
    assert!(format!("{err:?}").contains("already opened"), "unexpected: {err:?}");
}

/// A wallet claiming the cosigner's own identifier would collapse the reshare onto one point.
#[test]
fn a_wallet_claiming_the_cosigners_identifier_is_refused() {
    let w = onboard();
    let mut rng = OsRng;
    let cosigner_id = w.cosigner_kp.identifier.clone();
    let (_, r1p) = dkg::dkg_reshare_part1(
        &cosigner_id,
        2,
        2,
        &random::mod_n_random(&mut rng),
        &[random::mod_n_random(&mut rng)],
        &mut rng,
    )
    .unwrap();

    let mut sess = EscrowSession::new();
    let err = sess
        .begin(&w.cosigner_kp, &cosigner_id.serialize(), &r1p.to_json(), &fresh_context())
        .expect_err("the cosigner's own identifier must be refused");
    assert!(
        format!("{err:?}").contains("this cosigner's own"),
        "unexpected: {err:?}"
    );
}

/// Unused in assertions but kept honest: the escrow verifying key really is `V + Δ`.
#[test]
fn the_escrow_key_is_the_wallet_key_plus_the_deltas() {
    let w = onboard();
    let (_, escrow_pkp, _, _) = make_escrow(&w);
    assert!(
        !point::points_equal(&escrow_pkp.verifying_key.point, &w.pkp.verifying_key.point),
        "a non-zero delta must move the key"
    );
    let _ = scalar_to_bytes(&w.kp.secret_share);
}

fn hex32(s: &str) -> [u8; 32] {
    hex::decode(s).unwrap().try_into().unwrap()
}

/// A derivation context, drawn as a wallet draws one.
fn fresh_context() -> Vec<u8> {
    use rand::Rng;
    let mut ctx = vec![0u8; 16];
    OsRng.fill(&mut ctx[..]);
    ctx
}

#[test]
fn a_context_that_is_too_short_is_refused() {
    let w = onboard();
    let mut rng = OsRng;
    let id = w.kp.identifier.clone();
    let (_, r1p) = dkg::dkg_reshare_part1(
        &id,
        2,
        2,
        &random::mod_n_random(&mut rng),
        &[random::mod_n_random(&mut rng)],
        &mut rng,
    )
    .unwrap();

    let mut sess = EscrowSession::new();
    let err = sess.begin(&w.cosigner_kp, &id.serialize(), &r1p.to_json(), &[1, 2, 3])
        .expect_err("a guessable context must be refused");
    assert!(format!("{err:?}").contains("16 to 32 bytes"), "unexpected: {err:?}");
}
