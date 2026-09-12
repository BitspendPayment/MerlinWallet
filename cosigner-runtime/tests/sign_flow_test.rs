//! The 2-of-2 cooperative sign, driven the way a streaming session drives it: `open` returns the
//! ceremony, the client's round-trip happens, `finish` consumes it. The user/client half is
//! simulated host-side.
//!
//! There is no warm path here any more. A cosigner is opened for a request and its state comes from
//! the seal every time, so what used to be the "cold-spawn" case is the only case: seed on one
//! `Cosigner`, drop it, open a fresh one, sign.
//!
//! Persistence is in-process SQLite. The ASP channel is lazy and never used on the signing path.

mod common;

use std::collections::BTreeMap;
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

use rand::rngs::OsRng;

use cosigner_runtime::cosigner::types::{SignStep1, SignStep2};

use threshold::auth::AuthSigner;
use threshold::commitment::SigningPackage;
use threshold::identifier::Identifier;
use threshold::keys::{KeyPackage, PublicKeyPackage};
use threshold::nonce::{self, SigningCommitments};
use threshold::point;
use threshold::scalar::{scalar_from_bytes, scalar_to_bytes};
use threshold::signature::Signature;
use threshold::signing;

fn now_ms() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_millis() as i64
}

/// The client's half of round 1: a fresh nonce and the request carrying its commitments.
fn client_round1(kp_user: &KeyPackage, message: &[u8; 32]) -> (nonce::SigningNonce, SignStep1) {
    let auth = AuthSigner::from_secret_bytes(&scalar_to_bytes(&kp_user.secret_share)).unwrap();
    let mut rng = OsRng;
    let user_nonce = nonce::new_nonce(&mut rng, &kp_user.secret_share);
    let req = SignStep1 {
        user_id: auth.public_key_compressed().to_vec(),
        hiding_commitment: point::serialize_compressed(&user_nonce.commitments.hiding).to_vec(),
        binding_commitment: point::serialize_compressed(&user_nonce.commitments.binding).to_vec(),
        message_to_sign: message.to_vec(),
        signature: vec![],
        full_transaction: vec![],
        timestamp_ms: now_ms(),
        script_path_spend: true, // raw FROST (no taproot tweak)
        ark_tx: vec![],
    };
    (user_nonce, req)
}

/// Seed, drop, reopen, and run a full ceremony against the reopened cosigner.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn sign_session_restores_seal_and_verifies() {
    let Some(shared) = common::try_shared().await else {
        return;
    };

    // 2-of-2 {user, cosigner} key. Index 0 = user (client), index 1 = cosigner (server).
    let (kps, pkp) = common::dkg_2of2();
    let group_key = hex::encode(pkp.verifying_key.serialize());
    let (kp_user, kp_cosigner) = (&kps[0], &kps[1]);
    let message = [0x42u8; 32];

    let seeder = common::open_cosigner(&shared, &group_key).await;
    common::seed_policy(&seeder, &group_key, kp_cosigner, kp_user, &pkp, None).await;
    drop(seeder);

    // A fresh instance holds nothing in memory: the seal is where its keys come from.
    let cosigner = common::open_cosigner(&shared, &group_key).await;
    let (user_nonce, req1) = client_round1(kp_user, &message);
    let user_id = req1.user_id.clone();

    // Round 1. The ceremony leaves the cosigner with the reply; nothing is parked behind it.
    let (ceremony, resp1) = {
        let mut actor = cosigner.actor().await;
        actor.sign_open(req1).expect("sign_open")
    };

    // The client's round-trip, with no lock held on the cosigner.
    let mut commitments: BTreeMap<Identifier, SigningCommitments> = BTreeMap::new();
    for c in &resp1.commitments {
        let id_arr: [u8; 32] = hex::decode(&c.identifier_hex).unwrap().try_into().unwrap();
        let h: [u8; 33] = c.hiding.clone().try_into().unwrap();
        let b: [u8; 33] = c.binding.clone().try_into().unwrap();
        commitments.insert(
            Identifier::deserialize(&id_arr).unwrap(),
            SigningCommitments {
                hiding: point::deserialize_compressed(&h).unwrap(),
                binding: point::deserialize_compressed(&b).unwrap(),
            },
        );
    }
    let signing_pkg = SigningPackage::new(commitments, message.to_vec());
    let user_share = signing::sign(&signing_pkg, &user_nonce, kp_user).expect("user share");

    // Round 2. The ceremony goes back in by value and is consumed.
    let resp2 = {
        let mut actor = cosigner.actor().await;
        actor
            .sign_finish(
                ceremony,
                SignStep2 {
                    user_id,
                    signature_share: scalar_to_bytes(&user_share.s).to_vec(),
                    signature: vec![],
                    timestamp_ms: now_ms(),
                },
            )
            .expect("sign_finish")
    };

    let r_arr: [u8; 33] = resp2.r_point.try_into().expect("R is 33 bytes");
    let z_arr: [u8; 32] = resp2.z_scalar.try_into().expect("Z is 32 bytes");
    let signature = Signature::new(
        point::deserialize_compressed(&r_arr).unwrap(),
        scalar_from_bytes(&z_arr).unwrap(),
    );
    signature
        .verify(&pkp.verifying_key, &message)
        .expect("aggregated 2-of-2 signature must verify under the group key");

    let _ = shared.persistence.delete("sealed_state", &group_key);
}

/// The property the redesign rests on: an abandoned ceremony leaves nothing reusable behind.
///
/// A FROST nonce may be used once — signing twice under one nonce leaks the secret share. The old
/// model parked the ceremony on the actor between two requests, so an abandoned round 1 left a live
/// nonce sitting in memory addressable by whoever sent round 2. Here the ceremony is a value: drop
/// it and the nonce is gone, and a second ceremony on the same cosigner gets fresh commitments.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn abandoned_ceremony_leaves_no_reusable_nonce() {
    let Some(shared) = common::try_shared().await else {
        return;
    };

    let (kps, pkp) = common::dkg_2of2();
    let group_key = hex::encode(pkp.verifying_key.serialize());
    let (kp_user, kp_cosigner) = (&kps[0], &kps[1]);
    let message = [0x42u8; 32];

    let cosigner = common::open_cosigner(&shared, &group_key).await;
    common::seed_policy(&cosigner, &group_key, kp_cosigner, kp_user, &pkp, None).await;

    // Open a ceremony and abandon it, as an interrupted stream does.
    let (_, first) = {
        let mut actor = cosigner.actor().await;
        actor.sign_open(client_round1(kp_user, &message).1).expect("first open")
    };

    // Same cosigner, same message: a second ceremony must not reuse the first one's nonce.
    let (_, second) = {
        let mut actor = cosigner.actor().await;
        actor.sign_open(client_round1(kp_user, &message).1).expect("second open")
    };

    let cosigner_id = hex::encode(kp_cosigner.identifier.serialize());
    let find = |out: &cosigner_runtime::cosigner::types::SignStep1Out| {
        out.commitments
            .iter()
            .find(|c| c.identifier_hex == cosigner_id)
            .expect("cosigner's own commitments")
            .clone()
    };
    let (a, b) = (find(&first), find(&second));
    assert_ne!(a.hiding, b.hiding, "hiding commitment must not repeat across ceremonies");
    assert_ne!(a.binding, b.binding, "binding commitment must not repeat across ceremonies");

    let _ = shared.persistence.delete("sealed_state", &group_key);
}
