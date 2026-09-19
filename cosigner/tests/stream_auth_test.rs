//! Authentication, at the one place it happens: the router.
//!
//! Every request used to carry a Schnorr signature by the wallet's share key, checked in the guest.
//! That is gone. enclave-runtime gates every request on a WebAuthn assertion bound to its exact
//! method and path, and a request reaches this component only once that verified — stamped with the
//! tenant it resolved as `x-enclave-tenant`, a header the runtime strips from anything a client sends.
//! So `CosignerService::route` requires that header, and these tests are about that requirement:
//! every method refuses without it, a malformed one is no better than a missing one, and it is
//! checked before anything else so an unauthenticated caller learns nothing about what is here.
//!
//! They drive `route` with real framed bodies rather than calling handlers directly, because the
//! defect this file first guarded against was not in a check — it was that nothing called one, and
//! only the wire shows that. So these also cover the transport: routing, the five-byte frames, and
//! the `grpc-status` trailer a client actually reads a failure from.

mod common;

use cosigner::grpc::Code;
use cosigner::session::proto;
use cosigner::wallet_proto::{GetServerInfoRequest, GetServerInfoResponse};
use cosigner::Cosigner;

use threshold::keys::KeyPackage;

use common::wire::{block_on, collect, request, service, TENANT};

/// Every RPC the service answers. Kept as a list so a new method is refused-by-default here the day
/// it is added, rather than whenever somebody remembers to write a test for it.
const METHODS: &[&str] = &[
    "Sign", "Dkg", "Send", "Settle",
    "ContactAdd", "ContactRemove", "ContactList",
    "PaymentRequestCreate", "PaymentRequestList", "PaymentRequestDecline",
    "GetServerInfo", "RegisterDevice", "ForgetDevice", "DeviceCount", "Recover",
];

/// A `SignOpen` from the wallet that owns [kp_user]. No commitments: the wallet has no share to
/// hedge a nonce with until the cosigner's first answer brings the half it dealt.
fn sign_open(kp_user: &KeyPackage) -> proto::SignClientMsg {
    proto::SignClientMsg {
        session_id: "s1".into(),
        seq: 0,
        body: Some(proto::sign_client_msg::Body::Open(proto::SignOpen {
            message_to_sign: vec![0x42; 32],
            full_transaction: Vec::new(),
            script_path_spend: true,
            identifier: kp_user.identifier.serialize().to_vec(),
        })),
    }
}

/// A seeded cosigner and the wallet key packages that own it.
fn seeded() -> Option<(Cosigner, Vec<KeyPackage>)> {
    let store = common::try_store()?;
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
        Some(hex::encode([7u8; 32])),
    );
    Some((cosigner.into_inner().unwrap(), kps))
}

/// Without the runtime's tenant, every method refuses — streams and unary calls alike, and before
/// reading a single message.
#[test]
fn every_method_refuses_without_a_tenant() {
    let Some((cosigner, _)) = seeded() else { return };
    let svc = service(cosigner);
    for method in METHODS {
        // An empty body: refusal must not depend on what, if anything, was sent.
        let answer = collect::<GetServerInfoResponse>(block_on(
            svc.route(request::<GetServerInfoRequest>(method, &[], None)),
        ));
        assert_eq!(
            answer.code,
            Code::Unauthenticated as u32,
            "{method} must refuse without a tenant, got {} ({})",
            answer.code,
            answer.message
        );
        assert!(answer.messages.is_empty(), "{method} answered before refusing");
    }
}

/// The runtime writes sixteen bytes as lowercase hex. Anything else did not come from it.
#[test]
fn a_malformed_tenant_is_no_tenant() {
    let Some((cosigner, _)) = seeded() else { return };
    let svc = service(cosigner);
    for bad in ["", "not-hex", "0123456789ABCDEF0123456789ABCDEF", "0123456789abcdef"] {
        let answer = collect::<GetServerInfoResponse>(block_on(svc.route(request(
            "GetServerInfo",
            &[GetServerInfoRequest::default()],
            Some(bad),
        ))));
        assert_eq!(answer.code, Code::Unauthenticated as u32, "tenant {bad:?} must be refused");
    }
}

/// Checked before the path, so an unauthenticated caller cannot map what is here: an unknown method
/// and a real one look the same to it.
#[test]
fn an_unauthenticated_caller_cannot_tell_what_exists() {
    let Some((cosigner, _)) = seeded() else { return };
    let svc = service(cosigner);
    let real = collect::<GetServerInfoResponse>(block_on(
        svc.route(request::<GetServerInfoRequest>("GetServerInfo", &[], None)),
    ));
    let bogus = collect::<GetServerInfoResponse>(block_on(
        svc.route(request::<GetServerInfoRequest>("NoSuchMethod", &[], None)),
    ));
    assert_eq!(real.code, bogus.code);
    assert_eq!(real.code, Code::Unauthenticated as u32);
}

/// With a tenant, the same stream opens — so the gate is not simply refusing everything.
#[test]
fn a_tenant_opens_a_signing_session() {
    let Some((cosigner, kps)) = seeded() else { return };
    let answer = collect::<proto::SignServerMsg>(block_on(
        service(cosigner).route(request("Sign", &[sign_open(&kps[0])], Some(TENANT))),
    ));
    let first = answer
        .messages
        .first()
        .unwrap_or_else(|| panic!("the cosigner must answer: {} {}", answer.code, answer.message));
    assert!(
        matches!(first.body, Some(proto::sign_server_msg::Body::Commitments(_))),
        "expected the commitments round, got {:?}",
        first.body
    );
}

/// A ceremony that is cut off mid-round ends as a cancellation, not as a success.
///
/// The client half-closes after opening, so the handler parks waiting for a share that never comes.
/// The trailers are the only place that difference can be said, and reporting OK here would tell a
/// client its round completed.
#[test]
fn a_stream_that_ends_mid_ceremony_is_a_cancellation() {
    let Some((cosigner, kps)) = seeded() else { return };
    let answer = collect::<proto::SignServerMsg>(block_on(
        service(cosigner).route(request("Sign", &[sign_open(&kps[0])], Some(TENANT))),
    ));
    assert_eq!(answer.code, Code::Cancelled as u32, "got {}", answer.message);
    assert_eq!(answer.messages.len(), 1, "the commitments round went out before the client vanished");
}

/// An unknown method, once authenticated, is a gRPC status and not an HTTP one — a client reading
/// only the head would otherwise see a perfectly successful call.
#[test]
fn an_unknown_method_is_unimplemented_in_the_trailers() {
    let Some((cosigner, _)) = seeded() else { return };
    let resp = block_on(
        service(cosigner).route(request::<GetServerInfoRequest>("Nope", &[], Some(TENANT))),
    );
    assert_eq!(resp.status(), 200, "gRPC reports failure in the trailers");
    assert_eq!(collect::<GetServerInfoResponse>(resp).code, Code::Unimplemented as u32);
}

#[test]
fn get_server_info_answers_a_single_framed_message() {
    let Some((cosigner, _)) = seeded() else { return };
    let answer = collect::<GetServerInfoResponse>(block_on(service(cosigner).route(request(
        "GetServerInfo",
        &[GetServerInfoRequest::default()],
        Some(TENANT),
    ))));
    assert_eq!(answer.code, Code::Ok as u32, "got {}", answer.message);
    assert_eq!(answer.messages.len(), 1);
    assert_eq!(answer.messages[0].bitcoin_network, "regtest");
}

/// A DKG over a wallet that already has a key is refused on the wire, before any round-one material
/// is dealt.
#[test]
fn a_second_dkg_is_refused_on_the_wire() {
    let Some((cosigner, _)) = seeded() else { return };
    let open = proto::DkgClientMsg {
        session_id: "d1".into(),
        seq: 0,
        body: Some(proto::dkg_client_msg::Body::Open(proto::DkgOpen {
            identifier: vec![1; 32],
            round1_package: "{}".into(),
            ..Default::default()
        })),
    };
    let answer = collect::<proto::DkgServerMsg>(block_on(
        service(cosigner).route(request("Dkg", &[open], Some(TENANT))),
    ));
    assert_eq!(answer.code, Code::FailedPrecondition as u32, "got {}", answer.message);
    assert!(answer.messages.is_empty(), "no round-one package may go out");
}
