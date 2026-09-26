//! The DKG ceremony, driven the way the stream drives it: one session as a local, two exchanges,
//! and the key material handed back at the end.
//!
//! There was no in-process coverage of a full ceremony before — `OnboardingManager`'s tests
//! exercised its session map, TTL and eviction sweep, all of which went with the always-on model.
//! This covers what actually matters: that the cosigner and the wallet derive the same group key,
//! and that an abandoned ceremony leaves nothing behind.

mod common;

use std::collections::BTreeMap;

use rand::rngs::OsRng;

use cosigner::handlers::onboarding as ob;
use cosigner::handlers::onboarding::OnboardingSession;
use cosigner::wallet_proto::{DkgStep1Request, DkgStep3Request};

use threshold::dkg::{self, Round1Package, Round2Package};
use threshold::identifier::Identifier;
use threshold::random;

fn parse_wire(wire: &std::collections::HashMap<String, String>) -> BTreeMap<Identifier, Round1Package> {
    wire.iter()
        .map(|(id_hex, json)| {
            let bytes: [u8; 32] = hex::decode(id_hex).unwrap().try_into().unwrap();
            (
                Identifier::deserialize(&bytes).unwrap(),
                Round1Package::from_json(json).unwrap(),
            )
        })
        .collect()
}

/// Run the full three rounds and check both sides land on the same group key.
#[test]
fn ceremony_derives_one_group_key() {
    let Some(store) = common::try_store() else {
        return;
    };

    // The wallet deals its own round 1.
    let mut rng = OsRng;
    let secret = random::mod_n_random(&mut rng);
    let coefficients = vec![random::mod_n_random(&mut rng)];
    let (w_r1_secret, w_r1_pub) = dkg::dkg_part1(2, 2, &secret, &coefficients, &mut rng).unwrap();
    let wallet_id = w_r1_secret.identifier.clone();
    let mut sess = OnboardingSession::new();

    // --- The wallet's round 1 in, everybody's out -------------------------------------------
    let r1 = ob::dkg_open(
        &mut sess,
        DkgStep1Request {
            identifier: wallet_id.serialize().to_vec(),
            round1_package: w_r1_pub.to_json(),
        },
    )
    .expect("open");
    assert_eq!(r1.round1_packages.len(), 2, "both dealers' round1 packages");

    // --- The wallet computes its round 2 from the others' round 1 ---------------------------
    let all_r1 = parse_wire(&r1.round1_packages);
    let others_r1: BTreeMap<Identifier, Round1Package> = all_r1
        .iter()
        .filter(|(id, _)| **id != wallet_id)
        .map(|(id, p)| (id.clone(), p.clone()))
        .collect();
    let (w_r2_secret, w_r2_out) = dkg::dkg_part2(&w_r1_secret, &others_r1, &[]).unwrap();

    // --- Its round 2 in, ours out with the key ----------------------------------------------
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

    let mat = sess
        .seed_material
        .take()
        .expect("the ceremony must yield key material");

    // The wallet finalizes with the cosigner's round2 package addressed to it.
    let our_r2: BTreeMap<Identifier, Round2Package> = r3
        .round2_packages_for_me
        .iter()
        .map(|(id_hex, json)| {
            let bytes: [u8; 32] = hex::decode(id_hex).unwrap().try_into().unwrap();
            (
                Identifier::deserialize(&bytes).unwrap(),
                Round2Package::from_json(json).unwrap(),
            )
        })
        .collect();
    let (_, wallet_pkp) = dkg::dkg_part3(&w_r1_secret, &w_r2_secret, &others_r1, &our_r2, &[])
        .expect("wallet part3");

    assert_eq!(
        hex::encode(wallet_pkp.into_even_y().verifying_key.serialize()),
        mat.group_key,
        "the wallet and the cosigner must derive the same group key"
    );

    let _ = store.delete("sealed_state", &mat.group_key);
}

/// An abandoned ceremony leaves no key material anywhere.
///
/// The session used to live in a map with a TTL, so round-1 and round-2 secrets — what the key is
/// born from — sat there until a sweep noticed. Here the session is a local: drop it and they are
/// gone, and a second ceremony starts from nothing.
#[test]
fn abandoned_ceremony_leaves_nothing() {
    let Some(_store) = common::try_store() else {
        return;
    };

    let mut rng = OsRng;
    let secret = random::mod_n_random(&mut rng);
    let coefficients = vec![random::mod_n_random(&mut rng)];
    let (w_r1_secret, w_r1_pub) = dkg::dkg_part1(2, 2, &secret, &coefficients, &mut rng).unwrap();
    let wallet_id = w_r1_secret.identifier.clone();

    let req = |pkg: String| DkgStep1Request {
        identifier: wallet_id.serialize().to_vec(),
        round1_package: pkg,
    };

    // Open a ceremony, take the cosigner's round1 package, then abandon it.
    let mut first = OnboardingSession::new();
    let a = ob::dkg_open(&mut first, req(w_r1_pub.to_json())).expect("first");
    drop(first);

    // A fresh ceremony deals a fresh secret: the cosigner's package must differ.
    let mut second = OnboardingSession::new();
    let b = ob::dkg_open(&mut second, req(w_r1_pub.to_json())).expect("second");

    let cosigner_pkg = |wire: &std::collections::HashMap<String, String>| {
        wire.iter()
            .find(|(id_hex, _)| **id_hex != hex::encode(wallet_id.serialize()))
            .map(|(_, json)| json.clone())
            .expect("the cosigner's own round1 package")
    };
    assert_ne!(
        cosigner_pkg(&a.round1_packages),
        cosigner_pkg(&b.round1_packages),
        "a new ceremony must not reuse the abandoned one's round1 secret"
    );
}

/// A wallet that already has a key refuses a second ceremony.
///
/// `install_policy` overwrites unconditionally, so a second DKG on the same tenant would replace the
/// key and strand everything held under the old one — 2-of-2 has no other way back. The e2e suite
/// did exactly that without noticing, re-running DKG on one wallet name across tests, and got away
/// with it only because nothing was funded in between.
#[test]
fn a_wallet_with_a_key_refuses_a_second_dkg() {
    let Some(store) = common::try_store() else {
        return;
    };
    let fresh = common::open_cosigner(&store, "wallet");
    assert!(
        fresh.lock().unwrap().refuse_if_onboarded().is_ok(),
        "a wallet with no key must be allowed its first ceremony"
    );

    let (kps, pkp) = common::dkg_2of2();
    common::seed_policy(&fresh, "wallet", &kps[1], &kps[0], &pkp, None);
    drop(fresh);

    // Reopened, so the refusal comes from the seal and not from memory.
    let reopened = common::open_cosigner(&store, "wallet");
    let err = reopened
        .lock()
        .unwrap()
        .refuse_if_onboarded()
        .expect_err("a second DKG over an existing key must be refused");
    assert_eq!(err.code(), cosigner::grpc::Code::FailedPrecondition);
}

/// Recovery's arithmetic, over a real ceremony.
///
/// A wallet's share is `f_wallet(id) + f_cosigner(id)`. A new phone can reproduce the first term
/// from the passkey's PRF; the second is the scalar the cosigner now seals. This proves the two add
/// up to the share the wallet actually ended the ceremony with — up to the even-Y normalization
/// `dkg_part3` applies to everybody, which is why the recovering wallet tries both signs and keeps
/// the one matching its sealed verifying share.
#[test]
fn the_sealed_dealt_share_rebuilds_the_wallet_share() {
    let Some(store) = common::try_store() else {
        return;
    };

    // The wallet's polynomial. Random here; derived from the passkey on a real device — what
    // matters to this test is only that the wallet still has it at the end.
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
    let all_r1 = parse_wire(&r1.round1_packages);
    let others_r1: BTreeMap<Identifier, Round1Package> = all_r1
        .iter()
        .filter(|(id, _)| **id != wallet_id)
        .map(|(id, p)| (id.clone(), p.clone()))
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

    let our_r2: BTreeMap<Identifier, Round2Package> = r3
        .round2_packages_for_me
        .iter()
        .map(|(id_hex, json)| {
            let bytes: [u8; 32] = hex::decode(id_hex).unwrap().try_into().unwrap();
            (
                Identifier::deserialize(&bytes).unwrap(),
                Round2Package::from_json(json).unwrap(),
            )
        })
        .collect();
    let (wallet_kp, _) = dkg::dkg_part3(&w_r1_secret, &w_r2_secret, &others_r1, &our_r2, &[])
        .expect("wallet part3");

    // What the cosigner sealed, and what the wallet can work out on its own.
    let dealt_hex = mat
        .wallet_dealt_share_hex
        .expect("the ceremony must seal the share dealt to the wallet");
    let dealt = threshold::scalar::scalar_from_bytes(
        &hex::decode(&dealt_hex).unwrap().try_into().unwrap(),
    )
    .expect("the sealed share is a scalar");
    let own = threshold::polynomial::evaluate_polynomial(&wallet_id, &w_r1_secret.coefficients);

    let rebuilt = own + dealt;
    let negated = -rebuilt;
    assert!(
        rebuilt == wallet_kp.secret_share || negated == wallet_kp.secret_share,
        "f_wallet(id) + the sealed dealt share must be the wallet's own share, up to parity"
    );

    // And nothing else would do: a share off by one is not a share.
    assert_ne!(
        own, wallet_kp.secret_share,
        "the wallet's own half alone is not its share — the sealed half is what makes it one"
    );

    let _ = store.delete("sealed_state", &mat.group_key);
}
