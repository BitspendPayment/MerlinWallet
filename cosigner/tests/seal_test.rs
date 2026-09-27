//! What opening from the seal does when the seal is not what it should be.
//!
//! Since the wallet keeps no key, the cosigner's seal is the only copy of anything. So "there is
//! no seal" and "there is a seal and it cannot be read" are different situations with different
//! right answers: the first is a wallet that has not onboarded and may run a DKG; the second is a
//! read fault, and opening it as the first would let a DKG re-key the tenant over funds sealed
//! under the old key — which a 2-of-2 cannot get back.

mod common;

/// A seal that is there and cannot be read refuses to open — so nothing can be dealt over it.
#[test]
fn a_present_but_unreadable_seal_refuses_to_open_as_a_fresh_wallet() {
    let Some(store) = common::try_store() else {
        return;
    };
    let (kps, pkp) = common::dkg_2of2();
    let group_key = hex::encode(pkp.verifying_key.serialize());
    let cosigner = common::open_cosigner(&store, &group_key);
    common::seed_policy(&cosigner, &group_key, &kps[1], &kps[0], &pkp, None);
    drop(cosigner);

    // Not hex at all.
    store.put("sealed_state", &group_key, "not-hex").expect("put");
    let err = cosigner::Cosigner::open(store.clone(), group_key.clone())
        .err()
        .expect("a corrupt seal must not open as a fresh wallet");
    assert!(format!("{err:?}").contains("unreadable"), "{err:?}");

    // Hex, and JSON, and not a snapshot.
    store
        .put("sealed_state", &group_key, &hex::encode(b"{}"))
        .expect("put");
    assert!(cosigner::Cosigner::open(store.clone(), group_key.clone()).is_err());

    // No seal at all is a wallet that has not onboarded, and opens.
    store.delete("sealed_state", &group_key).expect("delete");
    let fresh = cosigner::Cosigner::open(store, group_key).expect("no seal is a fresh wallet");
    assert!(fresh.refuse_if_onboarded().is_ok(), "nothing sealed, so nothing to protect");
}

/// A seal written while the wallet still had contacts and payment requests opens, key and all.
///
/// The snapshot lost three fields with them — `contacts`, `payment_intents`, `seen_request_nonces`
/// — and a wallet sealed before that still carries them. Its seal is the only copy of its key, so
/// the old fields have to be ignored rather than refused.
#[test]
fn a_seal_that_still_holds_contacts_and_payment_requests_opens() {
    let Some(store) = common::try_store() else {
        return;
    };
    let (kps, pkp) = common::dkg_2of2();
    let group_key = hex::encode(pkp.verifying_key.serialize());
    let cosigner = common::open_cosigner(&store, &group_key);
    common::seed_policy(&cosigner, &group_key, &kps[1], &kps[0], &pkp, None);
    drop(cosigner);

    // Today's seal, plus the three fields as the old cosigner wrote them.
    let sealed = store.get("sealed_state", &group_key).expect("get").expect("a seal");
    let mut snapshot: serde_json::Value =
        serde_json::from_slice(&hex::decode(sealed).expect("hex")).expect("json");
    let contact = format!("02{}", "ab".repeat(32));
    snapshot["contacts"] = serde_json::json!([
        { "vk_hex": contact, "label": "Bob", "added_at": 1_700_000_000 }
    ]);
    snapshot["payment_intents"] = serde_json::json!([{
        "id": "00".repeat(16),
        "from_vk_hex": contact,
        "to_ark_address": "tark1qq",
        "amount_sats": 5000,
        "memo": "invoice 1",
        "created_at": 1_700_000_000,
        "expires_at": 1_700_086_400,
        "status": "Pending",
        "ark_txid": ""
    }]);
    snapshot["seen_request_nonces"][&"11".repeat(16)] = serde_json::json!(1_700_003_600);
    let old = serde_json::to_vec(&snapshot).expect("json");
    store.put("sealed_state", &group_key, &hex::encode(old)).expect("put");

    let reopened = cosigner::Cosigner::open(store, group_key.clone())
        .expect("a seal from before the removal must still open");
    assert_eq!(reopened.owner_pk_hex().expect("its key came back"), &group_key[2..]);
}
