//! The four ceremony streams, over a real gRPC connection.
//!
//! `check()` ran on all seven unary RPCs and on none of the four streams: every handler carried the
//! comment "auth ran at the REST boundary", and that boundary was deleted. Anyone who could reach
//! the port could open a `Send` and have the cosigner co-sign a spend.
//!
//! These tests drive tonic against a real server rather than calling the handlers directly, because
//! the defect was not in `verify_auth` — it was that nothing called it. Only the wire shows that.

mod common;

use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

use cosigner::session::proto;
use cosigner::session::proto::cosigner_client::CosignerClient;
use cosigner::session::CosignerService;
use cosigner::wallet_proto::GetServerInfoResponse;
use cosigner::Cosigner;

use threshold::auth::AuthSigner;
use threshold::keys::KeyPackage;
use threshold::scalar::scalar_to_bytes;

fn now_ms() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_millis() as i64
}

/// Serve one cosigner on an ephemeral port; returns its address.
async fn serve(cosigner: Cosigner) -> String {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let svc = proto::cosigner_server::CosignerServer::new(CosignerService::new(
        Arc::new(tokio::sync::Mutex::new(cosigner)),
        GetServerInfoResponse {
            bitcoin_network: "regtest".into(),
        },
    ));
    tokio::spawn(async move {
        tonic::transport::Server::builder()
            .add_service(svc)
            .serve_with_incoming(tokio_stream::wrappers::TcpListenerStream::new(listener))
            .await
            .ok();
    });
    format!("http://{addr}")
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

/// An unsigned `SignOpen` is refused before any ceremony state is created.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn sign_rejects_an_unauthenticated_open() {
    let Some(store) = common::try_store().await else {
        return;
    };
    let (kps, pkp) = common::dkg_2of2();
    let group_key = hex::encode(pkp.verifying_key.serialize());

    let cosigner = common::open_cosigner(&store, &group_key).await;
    common::seed_policy(&cosigner, &group_key, &kps[1], &kps[0], &pkp, None).await;
    let addr = serve(cosigner.into_inner()).await;

    let mut client = CosignerClient::connect(addr).await.expect("connect");
    let (tx, rx) = tokio::sync::mpsc::channel(4);
    tx.send(sign_open(&kps[0], false)).await.unwrap();
    let mut inbound = client
        .sign(tokio_stream::wrappers::ReceiverStream::new(rx))
        .await
        .expect("open stream")
        .into_inner();

    let first = tokio_stream::StreamExt::next(&mut inbound).await;
    let err = first
        .expect("the server must answer")
        .expect_err("a forged signature must not open a signing session");
    assert_eq!(
        err.code(),
        tonic::Code::Unauthenticated,
        "expected Unauthenticated, got: {err:?}"
    );
}

/// …and a correctly signed one is let through, so the gate is not simply refusing everything.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn sign_accepts_an_authenticated_open() {
    let Some(store) = common::try_store().await else {
        return;
    };
    let (kps, pkp) = common::dkg_2of2();
    let group_key = hex::encode(pkp.verifying_key.serialize());

    let cosigner = common::open_cosigner(&store, &group_key).await;
    common::seed_policy(&cosigner, &group_key, &kps[1], &kps[0], &pkp, None).await;
    let addr = serve(cosigner.into_inner()).await;

    let mut client = CosignerClient::connect(addr).await.expect("connect");
    let (tx, rx) = tokio::sync::mpsc::channel(4);
    tx.send(sign_open(&kps[0], true)).await.unwrap();
    let mut inbound = client
        .sign(tokio_stream::wrappers::ReceiverStream::new(rx))
        .await
        .expect("open stream")
        .into_inner();

    let msg = tokio_stream::StreamExt::next(&mut inbound)
        .await
        .expect("the server must answer")
        .expect("an authentic open must be accepted");
    assert!(
        matches!(msg.body, Some(proto::sign_server_msg::Body::Commitments(_))),
        "expected the commitments round, got {:?}",
        msg.body
    );
}
