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

use std::future::Future;
use std::sync::{Arc, Mutex};
use std::task::{Context, Poll, Waker};

use bytes::Bytes;
use http_body_util::BodyExt;

use cosigner::grpc::framing::{frame, Deframer};
use cosigner::grpc::Code;
use cosigner::session::proto;
use cosigner::session::{CosignerService, TENANT_HEADER};
use cosigner::wallet_proto::{GetServerInfoRequest, GetServerInfoResponse};
use cosigner::Cosigner;
use wstd::http::{Body, Request, Response};

use threshold::keys::KeyPackage;
use threshold::nonce;
use threshold::point;

/// What the runtime puts on an approved request: sixteen bytes, lowercase hex.
const TENANT: &str = "0123456789abcdef0123456789abcdef";

/// Every RPC the service answers. Kept as a list so a new method is refused-by-default here the day
/// it is added, rather than whenever somebody remembers to write a test for it.
const METHODS: &[&str] = &[
    "Sign", "Dkg", "Send", "Settle",
    "ContactAdd", "ContactRemove", "ContactList",
    "PaymentRequestCreate", "PaymentRequestList", "PaymentRequestDecline",
    "GetServerInfo", "RegisterDevice", "ForgetDevice", "DeviceCount",
];

/// Drive a future to completion on this thread.
///
/// Every body here is already in memory, so nothing genuinely parks and a busy poll is enough. The
/// cap is what turns "this future never finishes" into a failed test rather than a hung one — which
/// matters, because a duplex that stops making progress is exactly the bug this file would catch.
fn block_on<F: Future>(fut: F) -> F::Output {
    let mut fut = Box::pin(fut);
    let mut cx = Context::from_waker(Waker::noop());
    for _ in 0..100_000 {
        if let Poll::Ready(value) = fut.as_mut().poll(&mut cx) {
            return value;
        }
    }
    panic!("the future never completed");
}

/// A gRPC request carrying `messages`, addressed at `method`, as the runtime would deliver it — or,
/// with `tenant: None`, as it would never deliver it.
fn request<M: prost::Message>(method: &str, messages: &[M], tenant: Option<&str>) -> Request<Body> {
    let mut buf = Vec::new();
    for message in messages {
        buf.extend_from_slice(&frame(&message.encode_to_vec()));
    }
    let mut builder = Request::builder()
        .method("POST")
        .uri(format!("http://cosigner/cosigner.v1.Cosigner/{method}"))
        .header("content-type", "application/grpc+proto");
    if let Some(tenant) = tenant {
        builder = builder.header(TENANT_HEADER, tenant);
    }
    builder
        .body(Body::from_http_body(
            http_body_util::Full::new(Bytes::from(buf))
                .map_err(|e: std::convert::Infallible| -> wstd::http::Error { match e {} }),
        ))
        .expect("request is well formed")
}

/// What came back: the decoded messages, and the status a client reads from the trailers.
struct Answer<M> {
    messages: Vec<M>,
    code: u32,
    message: String,
}

fn collect<M: prost::Message + Default>(resp: Response<Body>) -> Answer<M> {
    let collected = block_on(resp.into_body().into_boxed_body().collect()).expect("collect body");
    let trailers = collected.trailers().cloned().unwrap_or_default();
    let code = trailers
        .get("grpc-status")
        .expect("every gRPC response carries a grpc-status trailer")
        .to_str()
        .unwrap()
        .parse()
        .unwrap();
    let message = trailers
        .get("grpc-message")
        .map(|v| v.to_str().unwrap().to_string())
        .unwrap_or_default();

    let mut deframer = Deframer::default();
    deframer.push(&collected.to_bytes());
    let mut messages = Vec::new();
    while let Some(bytes) = deframer.next().expect("well-framed response") {
        messages.push(M::decode(bytes).expect("decodable response"));
    }
    Answer { messages, code, message }
}

fn service(cosigner: Cosigner) -> CosignerService {
    CosignerService::new(
        Arc::new(Mutex::new(cosigner)),
        GetServerInfoResponse { bitcoin_network: "regtest".into() },
    )
}

/// A `SignOpen` with a real commitment from the wallet's share.
fn sign_open(kp_user: &KeyPackage) -> proto::SignClientMsg {
    let nonce = nonce::new_nonce(&mut rand::rngs::OsRng, &kp_user.secret_share);
    proto::SignClientMsg {
        session_id: "s1".into(),
        seq: 0,
        body: Some(proto::sign_client_msg::Body::Open(proto::SignOpen {
            hiding_commitment: point::serialize_compressed(&nonce.commitments.hiding).to_vec(),
            binding_commitment: point::serialize_compressed(&nonce.commitments.binding).to_vec(),
            message_to_sign: vec![0x42; 32],
            full_transaction: Vec::new(),
            script_path_spend: true,
        })),
    }
}

/// A seeded cosigner and the wallet key packages that own it.
fn seeded() -> Option<(Cosigner, Vec<KeyPackage>)> {
    let store = common::try_store()?;
    let (kps, pkp) = common::dkg_2of2();
    let group_key = hex::encode(pkp.verifying_key.serialize());
    let cosigner = common::open_cosigner(&store, &group_key);
    common::seed_policy(&cosigner, &group_key, &kps[1], &kps[0], &pkp, None);
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
        })),
    };
    let answer = collect::<proto::DkgServerMsg>(block_on(
        service(cosigner).route(request("Dkg", &[open], Some(TENANT))),
    ));
    assert_eq!(answer.code, Code::FailedPrecondition as u32, "got {}", answer.message);
    assert!(answer.messages.is_empty(), "no round-one package may go out");
}
