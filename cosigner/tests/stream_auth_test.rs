//! The four ceremony streams, over the real transport.
//!
//! `check()` ran on all seven unary RPCs and on none of the four streams: every handler carried the
//! comment "auth ran at the REST boundary", and that boundary was deleted. Anyone who could reach
//! the port could open a `Send` and have the cosigner co-sign a spend.
//!
//! These drive [`CosignerService::route`] with a real framed request body rather than calling the
//! ceremony functions directly, because the defect was not in `verify_auth` — it was that nothing
//! called it, and only the wire shows that. They used to drive tonic over a TCP socket; tonic does
//! not build for `wasm32-wasip2`, so the wire is now `src/grpc`'s own framing and trailers, and
//! these cover that too: routing, the five-byte frames, and the `grpc-status` a client actually
//! reads a failure from.

mod common;

use std::future::Future;
use std::sync::{Arc, Mutex};
use std::task::{Context, Poll, Waker};
use std::time::{SystemTime, UNIX_EPOCH};

use bytes::Bytes;
use http_body_util::BodyExt;

use cosigner::grpc::framing::{frame, Deframer};
use cosigner::grpc::Code;
use cosigner::session::proto;
use cosigner::session::CosignerService;
use cosigner::wallet_proto::GetServerInfoResponse;
use cosigner::Cosigner;
use wstd::http::{Body, Request, Response};

use threshold::auth::AuthSigner;
use threshold::keys::KeyPackage;
use threshold::scalar::scalar_to_bytes;

fn now_ms() -> i64 {
    SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_millis() as i64
}

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

/// A gRPC request carrying `messages`, addressed at `method`.
fn request<M: prost::Message>(method: &str, messages: &[M]) -> Request<Body> {
    let mut buf = Vec::new();
    for message in messages {
        buf.extend_from_slice(&frame(&message.encode_to_vec()));
    }
    Request::builder()
        .method("POST")
        .uri(format!("http://cosigner/cosigner.v1.Cosigner/{method}"))
        .header("content-type", "application/grpc+proto")
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

/// A `SignOpen` signed by the wallet's own key, or deliberately not.
fn sign_open(kp_user: &KeyPackage, authentic: bool) -> proto::SignClientMsg {
    let auth = AuthSigner::from_secret_bytes(&scalar_to_bytes(&kp_user.secret_share)).unwrap();
    let user_id = auth.public_key_compressed().to_vec();
    let ts = now_ms();
    let signature = if authentic {
        auth.sign(&cosigner::auth::message::build_auth_message(
            cosigner::auth::message::OP_SIGN_STEP1,
            ts,
            &hex::encode(&user_id),
        ))
        .to_vec()
    } else {
        vec![7u8; 64]
    };
    proto::SignClientMsg {
        session_id: "s1".into(),
        seq: 0,
        body: Some(proto::sign_client_msg::Body::Open(proto::SignOpen {
            user_id,
            signature,
            timestamp_ms: ts,
            hiding_commitment: vec![2u8; 33],
            binding_commitment: vec![2u8; 33],
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

/// An unsigned `SignOpen` is refused before any ceremony state is created.
#[test]
fn sign_rejects_an_unauthenticated_open() {
    let Some((cosigner, kps)) = seeded() else { return };

    let resp = block_on(service(cosigner).route(request("Sign", &[sign_open(&kps[0], false)])));
    let answer = collect::<proto::SignServerMsg>(resp);

    assert_eq!(
        answer.code,
        Code::Unauthenticated as u32,
        "expected Unauthenticated, got {} ({})",
        answer.code,
        answer.message
    );
    assert!(
        answer.messages.is_empty(),
        "a refused open must not have answered a round first: {:?}",
        answer.messages
    );
}

/// …and a correctly signed one is let through, so the gate is not simply refusing everything.
#[test]
fn sign_accepts_an_authenticated_open() {
    let Some((cosigner, kps)) = seeded() else { return };

    let resp = block_on(service(cosigner).route(request("Sign", &[sign_open(&kps[0], true)])));
    let answer = collect::<proto::SignServerMsg>(resp);

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
/// The client half-closes after opening, so `check()` passes and the handler parks waiting for the
/// share that never comes. Worth its own test: the trailers are the only place that difference can
/// be said, and reporting OK here would tell a client its round completed.
#[test]
fn a_stream_that_ends_mid_ceremony_is_a_cancellation() {
    let Some((cosigner, kps)) = seeded() else { return };

    let resp = block_on(service(cosigner).route(request("Sign", &[sign_open(&kps[0], true)])));
    let answer = collect::<proto::SignServerMsg>(resp);

    assert_eq!(answer.code, Code::Cancelled as u32, "got {}", answer.message);
    assert_eq!(
        answer.messages.len(),
        1,
        "the commitments round went out before the client vanished"
    );
}

/// An unknown method is a gRPC status, not an HTTP one — a client reading only the head would
/// otherwise see a perfectly successful call.
#[test]
fn an_unknown_method_is_unimplemented_in_the_trailers() {
    let Some((cosigner, _)) = seeded() else { return };

    let resp = block_on(service(cosigner).route(request::<proto::SignClientMsg>("Nope", &[])));
    assert_eq!(resp.status(), 200, "gRPC reports failure in the trailers");
    let answer = collect::<proto::SignServerMsg>(resp);
    assert_eq!(answer.code, Code::Unimplemented as u32);
}

/// A unary call is authenticated the same way, and answers with one message and an OK trailer.
#[test]
fn get_server_info_answers_a_single_framed_message() {
    let Some((cosigner, _)) = seeded() else { return };

    let resp = block_on(
        service(cosigner).route(request("GetServerInfo", &[cosigner::wallet_proto::GetServerInfoRequest::default()])),
    );
    let answer = collect::<GetServerInfoResponse>(resp);

    assert_eq!(answer.code, Code::Ok as u32, "got {}", answer.message);
    assert_eq!(answer.messages.len(), 1);
    assert_eq!(answer.messages[0].bitcoin_network, "regtest");
}
