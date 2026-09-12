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
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn ceremony_derives_one_group_key() {
    let Some(upstreams) = common::try_shared().await else {
        return;
    };

    // The wallet deals its own round 1.
    let mut rng = OsRng;
    let secret = random::mod_n_random(&mut rng);
    let coefficients = vec![random::mod_n_random(&mut rng)];
    let (w_r1_secret, w_r1_pub) = dkg::dkg_part1(2, 2, &secret, &coefficients, &mut rng).unwrap();
    let wallet_id = w_r1_secret.identifier.clone();
    let user_id = wallet_id.serialize().to_vec();

    let mut sess = OnboardingSession::new(hex::encode(&user_id));

    // --- The wallet's round 1 in, everybody's out -------------------------------------------
    let r1 = ob::dkg_open(
        &mut sess,
        DkgStep1Request {
            user_id: user_id.clone(),
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
        &upstreams,
        DkgStep3Request {
            user_id: user_id.clone(),
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

    let _ = upstreams.persistence.delete("sealed_state", &mat.group_key);
    let _ = upstreams.persistence.delete("policy_owner_idx", &hex::encode(&user_id));
}

/// An abandoned ceremony leaves no key material anywhere.
///
/// The session used to live in a map with a TTL, so round-1 and round-2 secrets — what the key is
/// born from — sat there until a sweep noticed. Here the session is a local: drop it and they are
/// gone, and a second ceremony starts from nothing.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn abandoned_ceremony_leaves_nothing() {
    let Some(upstreams) = common::try_shared().await else {
        return;
    };

    let mut rng = OsRng;
    let secret = random::mod_n_random(&mut rng);
    let coefficients = vec![random::mod_n_random(&mut rng)];
    let (w_r1_secret, w_r1_pub) = dkg::dkg_part1(2, 2, &secret, &coefficients, &mut rng).unwrap();
    let wallet_id = w_r1_secret.identifier.clone();
    let user_id = wallet_id.serialize().to_vec();

    let req = |pkg: String| DkgStep1Request {
        user_id: user_id.clone(),
        identifier: wallet_id.serialize().to_vec(),
        round1_package: pkg,
    };

    // Open a ceremony, take the cosigner's round1 package, then abandon it.
    let mut first = OnboardingSession::new(hex::encode(&user_id));
    let a = ob::dkg_open(&mut first, req(w_r1_pub.to_json())).expect("first");
    drop(first);

    // A fresh ceremony deals a fresh secret: the cosigner's package must differ.
    let mut second = OnboardingSession::new(hex::encode(&user_id));
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
