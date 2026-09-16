//! Request-to-pay: who may bill a wallet, and how that is proven.
//!
//! The caller of `PaymentRequestCreate` is the PAYER. A request cannot be sent to somebody else's
//! cosigner — the runtime resolves the tenant from the caller's own token — so it travels out of band
//! and the payer's app submits it. The runtime authenticates the payer; these tests are about the
//! other question, whether the REQUESTER wrote it, which a group-key signature answers.
//!
//! The old version of this file tested a share key resolved to a group key through
//! `policy_owner_idx`. That lookup only worked while every wallet shared one store: per tenant, the
//! payer's store has never heard of the requester, so the id never resolved — and had the payer
//! allowlisted the share key instead, the payee address would have been derived from it, an address
//! the requester cannot spend. `a_share_key_cannot_stand_in_for_the_group_key` is that case.
//!
//! Driven through the cosigner directly. `ark_info` is supplied by the request and the payee address
//! is derived locally from it, so acceptance is testable here and not only refusal.

mod common;

use std::sync::Mutex;

use cosigner::grpc::Code;
use cosigner::handlers::payment_request::{request_digest, MAX_REQUEST_VALIDITY_SECS};
use cosigner::store::Store;
use cosigner::wallet_proto::{
    ArkInfo, ContactAddRequest, ContactListRequest, ContactRemoveRequest,
    PaymentRequestCreateRequest, RequestAuthorship,
};
use cosigner::Cosigner;

use threshold::keys::{KeyPackage, PublicKeyPackage};

/// A wallet: its two key packages (user, cosigner), its public package, and its group key.
struct Wallet {
    kps: Vec<KeyPackage>,
    pkp: PublicKeyPackage,
    key: Vec<u8>,
}

fn wallet() -> Wallet {
    let (kps, pkp) = common::dkg_2of2();
    let key = pkp.verifying_key.serialize().to_vec();
    Wallet { kps, pkp, key }
}

/// A payer's cosigner, seeded and ready, over [store].
fn payer_cosigner(store: &std::sync::Arc<Store>, payer: &Wallet) -> Mutex<Cosigner> {
    let group = hex::encode(&payer.key);
    let c = common::open_cosigner(store, &group);
    common::seed_policy(&c, &group, &payer.kps[1], &payer.kps[0], &payer.pkp, None);
    c
}

/// Real ASP parameters — the payee address is derived from these, so the signer key must be a point.
fn ark_info() -> ArkInfo {
    ArkInfo {
        signer_pubkey: "79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798".into(),
        forfeit_pubkey: "79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798".into(),
        forfeit_address: String::new(),
        checkpoint_tapscript: String::new(),
        network: "regtest".into(),
        session_duration: 0,
        unilateral_exit_delay: 512,
        boarding_exit_delay: 144,
        vtxo_min_amount: 0,
        dust: 0,
    }
}

fn now() -> i64 {
    cosigner::handlers::helpers::now_secs()
}

/// A request from [requester] to [payer], signed by whatever [signer] holds.
fn request(
    requester_key: &[u8],
    payer_key: &[u8],
    not_after: i64,
    nonce: [u8; 16],
    sign: impl Fn(&[u8; 32]) -> [u8; 64],
) -> PaymentRequestCreateRequest {
    let mut authorship = RequestAuthorship {
        requester_group_key: requester_key.to_vec(),
        payer_group_key: payer_key.to_vec(),
        not_after,
        nonce: nonce.to_vec(),
        signature: Vec::new(),
    };
    let (amount_sats, expires_in_secs, memo) = (1_000, 0, "coffee".to_string());
    let digest = request_digest(&authorship, amount_sats, expires_in_secs, &memo);
    authorship.signature = sign(&digest).to_vec();
    PaymentRequestCreateRequest {
        amount_sats,
        memo,
        expires_in_secs,
        ark_info: Some(ark_info()),
        authorship: Some(authorship),
    }
}

/// Signed by [author]'s group key, as the requester's own wallet would.
fn by(author: &Wallet) -> impl Fn(&[u8; 32]) -> [u8; 64] + '_ {
    move |digest| common::group_sign(&author.kps, &author.pkp, digest)
}

fn add_contact(c: &Mutex<Cosigner>, key: &[u8]) {
    c.lock()
        .unwrap()
        .contact_add(ContactAddRequest {
            contact_verifying_key: key.to_vec(),
            label: "Bob".into(),
        })
        .expect("add contact");
}

fn create(c: &Mutex<Cosigner>, req: PaymentRequestCreateRequest) -> Result<cosigner::wallet_proto::PaymentIntent, cosigner::grpc::Status> {
    c.lock()
        .unwrap()
        .payment_request_create(req)
        .map(|r| r.intent.expect("an intent"))
}

#[test]
fn a_signed_request_from_a_contact_pays_its_author() {
    let Some(store) = common::try_store() else { return };
    let (alice, bob) = (wallet(), wallet());
    let payer = payer_cosigner(&store, &alice);
    add_contact(&payer, &bob.key);

    let intent = create(&payer, request(&bob.key, &alice.key, now() + 600, [1; 16], by(&bob)))
        .expect("an authored request from a contact is accepted");

    assert_eq!(intent.status, "pending");
    assert_eq!(intent.from_verifying_key, bob.key);
    // The address is derived from the key that SIGNED — never supplied, so it cannot be redirected.
    let expected = ark::client::ark_address(
        &hex::encode(&bob.key[1..]),
        &ark_info().signer_pubkey,
        512,
        ark::client::parse_network("regtest").unwrap(),
    )
    .unwrap();
    assert_eq!(intent.to_ark_address, expected, "the payee must be the author's own address");
}

#[test]
fn an_unsigned_request_is_refused() {
    let Some(store) = common::try_store() else { return };
    let (alice, bob) = (wallet(), wallet());
    let payer = payer_cosigner(&store, &alice);
    add_contact(&payer, &bob.key);

    let mut req = request(&bob.key, &alice.key, now() + 600, [2; 16], by(&bob));
    req.authorship = None;
    assert_eq!(create(&payer, req).unwrap_err().code(), Code::Unauthenticated);
}

/// Somebody who is not Bob claims to be Bob. Bob is a contact, so the allowlist would wave it through
/// — the signature is what stops it.
#[test]
fn a_request_claiming_to_be_a_contact_is_refused_without_their_signature() {
    let Some(store) = common::try_store() else { return };
    let (alice, bob, mallory) = (wallet(), wallet(), wallet());
    let payer = payer_cosigner(&store, &alice);
    add_contact(&payer, &bob.key);

    let err = create(&payer, request(&bob.key, &alice.key, now() + 600, [3; 16], by(&mallory)))
        .unwrap_err();
    assert_eq!(err.code(), Code::Unauthenticated, "got: {err}");
}

/// A share key signs perfectly well on its own. It must not pass for the group key: the payee address
/// derives from whatever key is accepted here, and a share key's address is not the wallet's.
#[test]
fn a_share_key_cannot_stand_in_for_the_group_key() {
    let Some(store) = common::try_store() else { return };
    let (alice, bob) = (wallet(), wallet());
    let payer = payer_cosigner(&store, &alice);
    add_contact(&payer, &bob.key);

    // Bob's share alone, signing a single-key Schnorr and claiming the group key.
    let share_only = |digest: &[u8; 32]| {
        let signer = threshold::auth::AuthSigner::from_secret_bytes(
            &threshold::scalar::scalar_to_bytes(&bob.kps[0].secret_share),
        )
        .unwrap();
        signer.sign(digest)
    };
    let err = create(&payer, request(&bob.key, &alice.key, now() + 600, [4; 16], share_only))
        .unwrap_err();
    assert_eq!(err.code(), Code::Unauthenticated, "got: {err}");
}

#[test]
fn a_request_from_someone_not_allowlisted_is_refused() {
    let Some(store) = common::try_store() else { return };
    let (alice, bob) = (wallet(), wallet());
    let payer = payer_cosigner(&store, &alice);

    let err = create(&payer, request(&bob.key, &alice.key, now() + 600, [5; 16], by(&bob)))
        .unwrap_err();
    assert_eq!(err.code(), Code::PermissionDenied);
}

/// Bob wrote a genuine request — to Carol. It must not be accepted when delivered to Alice.
#[test]
fn a_request_written_for_another_wallet_is_refused() {
    let Some(store) = common::try_store() else { return };
    let (alice, bob, carol) = (wallet(), wallet(), wallet());
    let payer = payer_cosigner(&store, &alice);
    add_contact(&payer, &bob.key);

    let err = create(&payer, request(&bob.key, &carol.key, now() + 600, [6; 16], by(&bob)))
        .unwrap_err();
    assert_eq!(err.code(), Code::PermissionDenied, "got: {err}");
}

/// The same request twice is one request — and still one after the cosigner is reopened, since the
/// runtime rebuilds instances freely and a replay need not wait for the same one.
#[test]
fn a_replayed_request_is_refused_even_after_a_reopen() {
    let Some(store) = common::try_store() else { return };
    let (alice, bob) = (wallet(), wallet());
    let group = hex::encode(&alice.key);
    let req = request(&bob.key, &alice.key, now() + 600, [7; 16], by(&bob));

    {
        let payer = payer_cosigner(&store, &alice);
        add_contact(&payer, &bob.key);
        create(&payer, req.clone()).expect("the first delivery is accepted");
        assert_eq!(create(&payer, req.clone()).unwrap_err().code(), Code::AlreadyExists);
    }

    let reopened = common::open_cosigner(&store, &group);
    assert_eq!(
        create(&reopened, req).unwrap_err().code(),
        Code::AlreadyExists,
        "the nonce must be sealed, not held in memory"
    );
}

#[test]
fn stale_and_overlong_requests_are_refused() {
    let Some(store) = common::try_store() else { return };
    let (alice, bob) = (wallet(), wallet());
    let payer = payer_cosigner(&store, &alice);
    add_contact(&payer, &bob.key);

    let expired = request(&bob.key, &alice.key, now() - 1, [8; 16], by(&bob));
    assert_eq!(create(&payer, expired).unwrap_err().code(), Code::PermissionDenied);

    let overlong =
        request(&bob.key, &alice.key, now() + MAX_REQUEST_VALIDITY_SECS + 60, [9; 16], by(&bob));
    assert_eq!(create(&payer, overlong).unwrap_err().code(), Code::InvalidArgument);
}

/// A signature over one amount does not authorize another.
#[test]
fn a_tampered_request_is_refused() {
    let Some(store) = common::try_store() else { return };
    let (alice, bob) = (wallet(), wallet());
    let payer = payer_cosigner(&store, &alice);
    add_contact(&payer, &bob.key);

    let mut req = request(&bob.key, &alice.key, now() + 600, [10; 16], by(&bob));
    req.amount_sats = 1_000_000;
    assert_eq!(create(&payer, req).unwrap_err().code(), Code::Unauthenticated);
}

/// The allowlist is sealed with the wallet, and removing a contact closes the gate again.
#[test]
fn contacts_are_sealed_and_removal_closes_the_gate() {
    let Some(store) = common::try_store() else { return };
    let (alice, bob) = (wallet(), wallet());
    let group = hex::encode(&alice.key);
    {
        let payer = payer_cosigner(&store, &alice);
        add_contact(&payer, &bob.key);
    }

    let reopened = common::open_cosigner(&store, &group);
    let listed = reopened.lock().unwrap().contact_list(ContactListRequest {}).unwrap();
    assert_eq!(listed.contacts.len(), 1);
    assert_eq!(listed.contacts[0].verifying_key, bob.key);

    reopened
        .lock()
        .unwrap()
        .contact_remove(ContactRemoveRequest { contact_verifying_key: bob.key.clone() })
        .unwrap();
    let err = create(&reopened, request(&bob.key, &alice.key, now() + 600, [11; 16], by(&bob)))
        .unwrap_err();
    assert_eq!(err.code(), Code::PermissionDenied);
}

#[test]
fn a_contact_must_be_a_compressed_key() {
    let Some(store) = common::try_store() else { return };
    let alice = wallet();
    let payer = payer_cosigner(&store, &alice);
    let err = payer
        .lock()
        .unwrap()
        .contact_add(ContactAddRequest { contact_verifying_key: vec![0x04; 33], label: "x".into() })
        .unwrap_err();
    assert_eq!(err.code(), Code::InvalidArgument);
}

/// The digest, pinned. The Dart client computes it independently in `requests/authorship.dart`, and a
/// single differing byte refuses every request with nothing to say why — so both suites assert this
/// same vector, and a change to either side fails its own tests first.
#[test]
fn the_digest_matches_the_pinned_vector() {
    let mut payer = vec![0x02];
    payer.extend([0x11; 32]);
    let mut requester = vec![0x03];
    requester.extend([0x22; 32]);
    let authorship = RequestAuthorship {
        requester_group_key: requester,
        payer_group_key: payer,
        not_after: 1_900_000_000,
        nonce: (0u8..16).collect(),
        signature: Vec::new(),
    };
    let digest = request_digest(&authorship, 5_000, 3_600, "invoice 1");
    assert_eq!(hex::encode(digest), PINNED_DIGEST);
}

const PINNED_DIGEST: &str = "00357a6997451fd8a7de58208fb1afb10bf0ffc809c7ca4db9ab1c7a759fab74";
