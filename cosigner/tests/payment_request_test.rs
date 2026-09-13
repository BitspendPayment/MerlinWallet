//! Request-to-pay: the contact allowlist gate and its sealed persistence.
//!
//! Scope is deliberately narrow — only what can be proven WITHOUT the Ark stack. Creating an
//! intent derives the payee address from the ASP, so those paths (creation, inbox, fulfilment)
//! are exercised by the regtest CLI against a live stack, not faked here.
//!
//! What this does prove is the security-critical half: `verify_auth` deliberately does not bind a
//! signer to the actor it addresses, so the payer's allowlist is the ONLY thing standing between a
//! stranger and their inbox — and it must survive a cold spawn.
//!
//! Drives the registry directly, so it covers AUTHORIZATION (in the actor), not AUTHENTICATION
//! (the Schnorr check at the REST boundary). Persistence is in-process SQLite.
//!
//! Owner-only routes carry the payer's own id, because that is what the REST layer produces:
//! `signer_user_id` falls back to the URL group key when the body omits `user_id`, so an empty
//! one never reaches an actor in production. `require_owner` rejects it.

mod common;

use cosigner::wallet_proto::{
    ContactAddRequest, ContactListRequest, ContactRemoveRequest, PaymentRequestCreateRequest,
};

fn create_req(receiver_vk: &[u8]) -> PaymentRequestCreateRequest {
    PaymentRequestCreateRequest {
        user_id: receiver_vk.to_vec(),
        amount_sats: 1_000,
        memo: "coffee".to_string(),
        expires_in_secs: 0,
        signature: vec![],
        timestamp_ms: 0,
        ark_info: None,
    }
}

#[test]
fn allowlist_gates_requests_and_survives_cold_spawn() {
    let Some(store) = common::try_store() else {
        return;
    };

    // The payer, and the party asking to be paid (who receives the money).
    let (payer_kps, payer_pkp) = common::dkg_2of2();
    let payer_group = hex::encode(payer_pkp.verifying_key.serialize());
    let payer_id = payer_pkp.verifying_key.serialize().to_vec();
    let (_receiver_kps, receiver_pkp) = common::dkg_2of2();
    let receiver_vk = receiver_pkp.verifying_key.serialize().to_vec();

    let cosigner = common::open_cosigner(&store, &payer_group);
    common::seed_policy(
        &cosigner,
        &payer_group,
        &payer_kps[1],
        &payer_kps[0],
        &payer_pkp,
        Some(hex::encode([7u8; 32])),
    );

    // A stranger is refused — and refused BEFORE any state is touched or the ASP is consulted,
    // which is why this assertion is meaningful with or without a live stack.
    let err = cosigner
        .lock()
        .unwrap()
        .payment_request_create(create_req(&receiver_vk))
        .expect_err("a non-contact must not be able to create a request");
    assert_eq!(
        err.code(),
        cosigner::grpc::Code::PermissionDenied,
        "expected PermissionDenied, got: {err:?}"
    );

    // Authorize them.
    cosigner
        .lock()
        .unwrap()
        .contact_add(ContactAddRequest {
                user_id: payer_id.clone(),
                contact_verifying_key: receiver_vk.clone(),
                label: "Bob".to_string(),
                signature: vec![],
                timestamp_ms: 0,
        })
        .expect("add contact");

    // The allowlist is sealed: drop the cosigner so nothing survives in memory, then read it back
    // from a fresh one (restored from the snapshot).
    drop(cosigner);
    let cosigner = common::open_cosigner(&store, &payer_group);
    let list = cosigner
        .lock()
        .unwrap()
        .contact_list(ContactListRequest {
                user_id: payer_id.clone(),
                signature: vec![],
                timestamp_ms: 0,
        })
        .expect("list contacts");
    assert_eq!(list.contacts.len(), 1, "contact must survive a cold spawn");
    assert_eq!(list.contacts[0].verifying_key, receiver_vk);
    assert_eq!(list.contacts[0].label, "Bob");

    // Revoking re-closes the gate.
    cosigner
        .lock()
        .unwrap()
        .contact_remove(ContactRemoveRequest {
                user_id: payer_id.clone(),
                contact_verifying_key: receiver_vk.clone(),
                signature: vec![],
                timestamp_ms: 0,
        })
        .expect("remove contact");

    let err = cosigner
        .lock()
        .unwrap()
        .payment_request_create(create_req(&receiver_vk))
        .expect_err("a revoked contact must not be able to create a request");
    assert_eq!(err.code(), cosigner::grpc::Code::PermissionDenied);

    let _ = store.delete("sealed_state", &payer_group);
}

/// The owner-only routes must reject a caller who authenticated as a DIFFERENT wallet.
///
/// `verify_auth` only proves the caller holds the key it named in its own body, while the URL
/// picks the actor — so without `require_owner` an attacker signs as their own wallet and writes
/// to the victim's. Adding yourself to the victim's allowlist is enough to bill them, since that
/// allowlist is the only gate on PaymentRequestCreate.
#[test]
fn owner_only_routes_reject_another_wallets_key() {
    let Some(store) = common::try_store() else {
        return;
    };

    let (payer_kps, payer_pkp) = common::dkg_2of2();
    let payer_group = hex::encode(payer_pkp.verifying_key.serialize());
    // The attacker holds a perfectly valid wallet — just not this one.
    let (_att_kps, attacker_pkp) = common::dkg_2of2();
    let attacker_id = attacker_pkp.verifying_key.serialize().to_vec();

    let cosigner = common::open_cosigner(&store, &payer_group);
    common::seed_policy(
        &cosigner,
        &payer_group,
        &payer_kps[1],
        &payer_kps[0],
        &payer_pkp,
        Some(hex::encode([9u8; 32])),
    );

    let err = cosigner
        .lock()
        .unwrap()
        .contact_add(ContactAddRequest {
                user_id: attacker_id.clone(),
                contact_verifying_key: attacker_id.clone(),
                label: "self-authorized".to_string(),
                signature: vec![],
                timestamp_ms: 0,
        })
        .expect_err("another wallet's key must not write this wallet's allowlist");
    assert_eq!(err.code(), cosigner::grpc::Code::PermissionDenied, "got: {err:?}");

    // ...and must not be able to read the inbox or the allowlist either.
    let err = cosigner
        .lock()
        .unwrap()
        .contact_list(ContactListRequest {
                user_id: attacker_id.clone(),
                signature: vec![],
                timestamp_ms: 0,
        })
        .expect_err("another wallet's key must not read this wallet's contacts");
    assert_eq!(err.code(), cosigner::grpc::Code::PermissionDenied, "got: {err:?}");

    let _ = store.delete("sealed_state", &payer_group);
}
