//! `Recover`: the half of a wallet's key the cosigner keeps, and the four ways it refuses to
//! hand it over.
//!
//! The ceremony's arithmetic — that this share plus the wallet's own rebuilds the wallet's share —
//! is proved over a real ceremony in `dkg_test.rs`. What is checked here is the gate around it: it
//! answers only after onboarding, only for the identifier the ceremony recorded, and it never
//! touches the policy while doing it.

mod common;

use cosigner::handlers::recover::recover;
use cosigner::session::proto::RecoverRequest;

use threshold::identifier::Identifier;

/// The share the cosigner dealt, standing in for a real ceremony's.
const DEALT: [u8; 32] = [7u8; 32];

fn asking_as(id: &Identifier) -> RecoverRequest {
    RecoverRequest {
        identifier: id.serialize().to_vec(),
    }
}

#[test]
fn recover_returns_the_dealt_share_to_the_wallets_own_identifier() {
    let Some(store) = common::try_store() else {
        return;
    };
    let (kps, pkp) = common::dkg_2of2();
    let group_key = hex::encode(pkp.verifying_key.serialize());
    let cosigner = common::open_cosigner(&store, &group_key);
    common::seed_policy_with_dealt_share(
        &cosigner,
        &group_key,
        &kps[1],
        &kps[0],
        &pkp,
        Some(hex::encode([9u8; 32])),
        Some(hex::encode(DEALT)),
    );

    let resp = recover(&cosigner.lock().unwrap(), asking_as(&kps[0].identifier))
        .expect("the owner's own identifier must be answered");

    assert_eq!(resp.dealt_share, DEALT.to_vec(), "the sealed share, verbatim");
    assert_eq!(resp.group_key, group_key);
    assert!(
        resp.public_key_package_json.contains(&group_key),
        "the package the caller checks its rebuilt share against must come back with it"
    );

    // Nothing was installed: the wallet that existed before the call is the one that exists after,
    // under the same key, and it answers again the same way.
    let again = recover(&cosigner.lock().unwrap(), asking_as(&kps[0].identifier))
        .expect("recovering must not consume or re-key the wallet");
    assert_eq!(again.group_key, group_key);
    assert_eq!(again.dealt_share, resp.dealt_share);
}

#[test]
fn recover_refuses_before_there_is_a_wallet() {
    let Some(store) = common::try_store() else {
        return;
    };
    let (kps, pkp) = common::dkg_2of2();
    let group_key = hex::encode(pkp.verifying_key.serialize());
    // Opened, never onboarded — the mirror of `refuse_if_onboarded`.
    let cosigner = common::open_cosigner(&store, &group_key);

    let err = recover(&cosigner.lock().unwrap(), asking_as(&kps[0].identifier))
        .expect_err("there is nothing to recover before a ceremony");
    assert!(
        format!("{err:?}").contains("no key yet"),
        "unexpected refusal: {err:?}"
    );
}

#[test]
fn recover_refuses_an_identifier_the_ceremony_never_saw() {
    let Some(store) = common::try_store() else {
        return;
    };
    let (kps, pkp) = common::dkg_2of2();
    let group_key = hex::encode(pkp.verifying_key.serialize());
    let cosigner = common::open_cosigner(&store, &group_key);
    common::seed_policy_with_dealt_share(
        &cosigner,
        &group_key,
        &kps[1],
        &kps[0],
        &pkp,
        None,
        Some(hex::encode(DEALT)),
    );

    // A passkey whose PRF answered differently derives a different identifier. It would rebuild a
    // share that cannot sign, so it is refused rather than served.
    let (other_kps, _) = common::dkg_2of2();
    let err = recover(&cosigner.lock().unwrap(), asking_as(&other_kps[0].identifier))
        .expect_err("a stranger's identifier must not be answered");
    assert!(
        format!("{err:?}").contains("does not derive this wallet"),
        "unexpected refusal: {err:?}"
    );
}

#[test]
fn recover_refuses_a_wallet_onboarded_before_the_share_was_kept() {
    let Some(store) = common::try_store() else {
        return;
    };
    let (kps, pkp) = common::dkg_2of2();
    let group_key = hex::encode(pkp.verifying_key.serialize());
    let cosigner = common::open_cosigner(&store, &group_key);
    common::seed_policy(&cosigner, &group_key, &kps[1], &kps[0], &pkp, None);

    let err = recover(&cosigner.lock().unwrap(), asking_as(&kps[0].identifier))
        .expect_err("an old wallet has no restore path, and must be told so");
    assert!(
        format!("{err:?}").contains("before recovery existed"),
        "unexpected refusal: {err:?}"
    );
}

/// The share has to survive the seal, or recovery only works until the enclave restarts.
#[test]
fn the_dealt_share_survives_seal_and_restore() {
    let Some(store) = common::try_store() else {
        return;
    };
    let (kps, pkp) = common::dkg_2of2();
    let group_key = hex::encode(pkp.verifying_key.serialize());
    {
        let cosigner = common::open_cosigner(&store, &group_key);
        common::seed_policy_with_dealt_share(
            &cosigner,
            &group_key,
            &kps[1],
            &kps[0],
            &pkp,
            Some(hex::encode([9u8; 32])),
            Some(hex::encode(DEALT)),
        );
    }

    // A second actor over the same store: what the runtime does on every reseat.
    let reopened = common::open_cosigner(&store, &group_key);
    let resp = recover(&reopened.lock().unwrap(), asking_as(&kps[0].identifier))
        .expect("a restored wallet must still be recoverable");
    assert_eq!(resp.dealt_share, DEALT.to_vec());
}
