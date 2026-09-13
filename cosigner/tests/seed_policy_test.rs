//! Installing key material seals it into the actor snapshot with NO plaintext policy in
//! persistence. Proves the actor owns the keys via the install path alone — a `sealed_state` blob
//! appears, nothing is written to a plaintext `policies` tree — which is what lets a later
//! `Cosigner::open` restore them without the host ever keeping a plaintext signing key.
//!
//! Integration test: persistence is in-process SQLite. The ASP channel is lazy and never used here.

mod common;


#[test]
fn install_policy_seals_without_plaintext() {
    let Some(store) = common::try_store() else {
        return;
    };

    let (kps, pkp) = common::dkg_2of2();
    let kp_user = &kps[0];
    let kp_cosigner = &kps[1];
    let group_key = hex::encode(pkp.verifying_key.serialize());

    // Install straight into the actor — note we never write the `policies` tree.
    let cosigner = common::open_cosigner(&store, &group_key);
    common::seed_policy(&cosigner, &group_key, kp_cosigner, kp_user, &pkp, None);

    // The actor sealed its state ⇒ a sealed_state blob exists for the group key.
    let blob = store.get("sealed_state", &group_key).unwrap();
    assert!(blob.is_some(), "expected a sealed_state blob after install");

    // …and no plaintext policy was written/needed — the actor owns the keys.
    let plaintext = store.get("policies", &group_key).unwrap();
    assert!(
        plaintext.is_none(),
        "installing a policy must not require a plaintext copy in the `policies` tree"
    );

    // Drop the key this test wrote (the in-memory store dies with the test anyway).
    let _ = store.delete("sealed_state", &group_key);
}
