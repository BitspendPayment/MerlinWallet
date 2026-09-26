//! The 2-of-2 cooperative sign, driven the way the `Sign` stream drives it: the cosigner commits
//! first, the wallet answers with its commitments and its share together, the cosigner aggregates.
//! It is the in-band round `Send` and `Settle` run, over one message — the wallet cannot commit
//! first any more, because it holds no share until the stream's first answer brings the half the
//! cosigner dealt it. The user/client half is simulated host-side.
//!
//! There is no warm path here. A cosigner is opened for a request and its state comes from the seal
//! every time, so what used to be the "cold-spawn" case is the only case: seed on one `Cosigner`,
//! drop it, open a fresh one, sign.
//!
//! Persistence is in-process SQLite. The ASP channel is lazy and never used on the signing path.

mod common;

use threshold::point;
use threshold::scalar::scalar_from_bytes;
use threshold::signature::Signature;

/// Seed, drop, reopen, and run a full ceremony against the reopened cosigner.
#[test]
fn sign_session_restores_seal_and_verifies() {
    let Some(store) = common::try_store() else {
        return;
    };

    // 2-of-2 {user, cosigner} key. Index 0 = user (client), index 1 = cosigner (server).
    let (kps, pkp) = common::dkg_2of2();
    let group_key = hex::encode(pkp.verifying_key.serialize());
    let (kp_user, kp_cosigner) = (&kps[0], &kps[1]);
    let message = vec![0x42u8; 32];

    let seeder = common::open_cosigner(&store, &group_key);
    common::seed_policy(&seeder, &group_key, kp_cosigner, kp_user, &pkp, None);
    drop(seeder);

    // A fresh instance holds nothing in memory: the seal is where its keys come from.
    let cosigner = common::open_cosigner(&store, &group_key);

    // Round 1. The round leaves the cosigner with the reply; nothing is parked behind it.
    let (round, theirs) = cosigner
        .lock()
        .unwrap()
        .sign_in_band_begin(std::slice::from_ref(&message))
        .expect("begin");
    assert_eq!(theirs.len(), 1, "one message, one commitment");

    // The client's round-trip, with no lock held on the cosigner.
    let ours = common::wallet_answers(kp_user, std::slice::from_ref(&message), &theirs);

    // Round 2. The round goes back in by value and is consumed.
    let signature = cosigner
        .lock()
        .unwrap()
        .sign_in_band_finish(round, ours)
        .expect("finish")
        .pop()
        .expect("one signature");

    // As the `Sign` stream reports it, and as the wallet's `frostFinish` reads it: R compressed
    // under an even prefix — `aggregate` normalizes it — and z.
    let mut r = [0x02u8; 33];
    r[1..].copy_from_slice(&signature[..32]);
    let z: [u8; 32] = signature[32..].try_into().expect("z is 32 bytes");
    Signature::new(
        point::deserialize_compressed(&r).unwrap(),
        scalar_from_bytes(&z).unwrap(),
    )
    .verify(&pkp.verifying_key, &message)
    .expect("aggregated 2-of-2 signature must verify under the group key");

    let _ = store.delete("sealed_state", &group_key);
}

/// The property the design rests on: an abandoned ceremony leaves nothing reusable behind.
///
/// A FROST nonce may be used once — signing twice under one nonce leaks the secret share. The round
/// is a value: drop it and the nonce is gone, and a second round on the same cosigner gets fresh
/// commitments.
#[test]
fn abandoned_ceremony_leaves_no_reusable_nonce() {
    let Some(store) = common::try_store() else {
        return;
    };

    let (kps, pkp) = common::dkg_2of2();
    let group_key = hex::encode(pkp.verifying_key.serialize());
    let message = vec![0x42u8; 32];

    let cosigner = common::open_cosigner(&store, &group_key);
    common::seed_policy(&cosigner, &group_key, &kps[1], &kps[0], &pkp, None);

    // Open a round and abandon it, as an interrupted stream does.
    let (_, first) = cosigner
        .lock()
        .unwrap()
        .sign_in_band_begin(std::slice::from_ref(&message))
        .expect("first open");
    // Same cosigner, same message: a second round must not reuse the first one's nonce.
    let (_, second) = cosigner
        .lock()
        .unwrap()
        .sign_in_band_begin(std::slice::from_ref(&message))
        .expect("second open");

    assert_ne!(first[0].hiding, second[0].hiding, "hiding commitment must not repeat");
    assert_ne!(first[0].binding, second[0].binding, "binding commitment must not repeat");

    let _ = store.delete("sealed_state", &group_key);
}
