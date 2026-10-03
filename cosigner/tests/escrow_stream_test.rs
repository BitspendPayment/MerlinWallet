//! The `Escrow` stream end to end, over the wire: mint, pair and deal, on one approval.
//!
//! Every other test of it stops at the open or drives the escrow's methods directly. This one plays
//! the wallet through all four exchanges against a fake runtime and checks what the cosigner sealed
//! at the end — so what is under test is the stream's own wiring: that the service's half went to
//! the service, that the deal struck is the one the wallet opened with, and that each confirmation
//! is recorded as the word of the party that gave it.
//!
//! The wallet's turns depend on the cosigner's — its round two is dealt against the cosigner's
//! round one — so the request body is fed one message at a time, as a client would send it. A file
//! of its own because it names the service in `SERVICE_ORIGINS`, which is the whole process's.

mod common;

use std::collections::{BTreeMap, VecDeque};
use std::pin::Pin;
use std::sync::{Arc, Mutex};
use std::task::{Context, Poll, Waker};

use bytes::Bytes;
use http_body::{Body as _, Frame};
use http_body_util::combinators::UnsyncBoxBody;
use prost::Message as _;
use rand::rngs::OsRng;
use wstd::http::{Body, Request};

use common::Recorder;
use cosigner::escrow::{service_stream_id, EscrowStage, PairingState, ToService};
use cosigner::grpc::framing::{frame, Deframer};
use cosigner::handlers::helpers::now_secs;
use cosigner::session::proto::{self, EscrowClientMsg, EscrowServerMsg};
use cosigner::session::proto::escrow_client_msg::Body as ToCosigner;
use cosigner::session::proto::escrow_server_msg::Body as FromCosigner;
use threshold::dkg::{self, Round1Package, Round2Package};
use threshold::identifier::Identifier;
use threshold::{point, random, scalar};

const ORIGIN: &str = "https://service.example";

/// The wallet's end of the stream: frames handed over as the test decides them. Empty is `Pending`,
/// as a connection with nothing in flight is — which is what makes this a conversation rather than
/// a batch.
#[derive(Clone, Default)]
struct Wire(Arc<Mutex<VecDeque<Bytes>>>);

impl Wire {
    fn say(&self, seq: u64, body: ToCosigner) {
        let message = EscrowClientMsg { session_id: "escrow".into(), seq, body: Some(body) };
        self.0.lock().unwrap().push_back(frame(&message.encode_to_vec()));
    }
}

impl http_body::Body for Wire {
    type Data = Bytes;
    type Error = wstd::http::Error;

    fn poll_frame(
        self: Pin<&mut Self>,
        _: &mut Context<'_>,
    ) -> Poll<Option<Result<Frame<Bytes>, Self::Error>>> {
        match self.0.lock().unwrap().pop_front() {
            Some(bytes) => Poll::Ready(Some(Ok(Frame::data(bytes)))),
            None => Poll::Pending,
        }
    }
}

/// The cosigner's end, read one message at a time.
struct Reply {
    body: UnsyncBoxBody<Bytes, wstd::http::Error>,
    deframer: Deframer,
}

impl Reply {
    /// Open the `Escrow` stream, with `wire` as its request body.
    fn open(cosigner: cosigner::Cosigner, wire: &Wire) -> Self {
        let request = Request::builder()
            .method("POST")
            .uri("http://cosigner/cosigner.v1.Cosigner/Escrow")
            .header("content-type", "application/grpc+proto")
            .body(Body::from_http_body(wire.clone()))
            .expect("request is well formed");
        let response = common::wire::block_on(common::wire::service(cosigner).route(request));
        Self { body: response.into_body().into_boxed_body(), deframer: Deframer::default() }
    }

    /// The cosigner's next message, which must be number `seq`. It has been sent everything it
    /// asked for, so it has something to say: waiting is a test that forgot to answer, and trailers
    /// are a stream that failed.
    fn next(&mut self, seq: u64) -> FromCosigner {
        let mut cx = Context::from_waker(Waker::noop());
        loop {
            if let Some(bytes) = self.deframer.next().expect("well framed") {
                let message = EscrowServerMsg::decode(bytes).expect("decodable");
                assert_eq!(message.seq, seq, "the cosigner's messages arrive in order");
                return message.body.expect("a message with a body");
            }
            match Pin::new(&mut self.body).poll_frame(&mut cx) {
                Poll::Ready(Some(Ok(frame))) => match frame.into_data() {
                    Ok(data) => self.deframer.push(&data),
                    Err(frame) => panic!("the stream ended early: {:?}", frame.trailers_ref()),
                },
                Poll::Ready(Some(Err(e))) => panic!("the stream failed: {e}"),
                Poll::Ready(None) => panic!("the stream ended before message {seq}"),
                Poll::Pending => panic!("the cosigner is waiting for a message never sent"),
            }
        }
    }

    /// How the stream ended, as a client reads it from the trailers: status code and message.
    fn finish(mut self) -> (String, String) {
        let mut cx = Context::from_waker(Waker::noop());
        let Poll::Ready(Some(Ok(frame))) = Pin::new(&mut self.body).poll_frame(&mut cx) else {
            panic!("expected the trailers after the last message");
        };
        let trailers = frame.into_trailers().expect("trailers, and nothing more said");
        let read = |name: &str| trailers.get(name).map_or("", |v| v.to_str().unwrap()).to_string();
        (read("grpc-status"), read("grpc-message"))
    }
}

/// One approval, one stream: the escrow is minted, its service paired in, and its deal struck — and
/// what is sealed at the end is exactly that, with nobody's word recorded as anybody else's.
#[test]
fn an_escrow_is_minted_paired_and_dealt_on_one_stream() {
    let Some(store) = common::try_store() else { return };

    // A wallet, its runtime, and the one service its image knows.
    let (kps, pkp) = common::dkg_2of2();
    let (wallet_kp, cosigner_kp) = (&kps[0], &kps[1]);
    let (wallet_id, cosigner_id) = (wallet_kp.identifier.clone(), cosigner_kp.identifier.clone());
    let group_key = hex::encode(pkp.verifying_key.serialize());
    let host = Arc::new(Recorder::default());
    let c = Mutex::new(
        cosigner::Cosigner::open(store.clone(), group_key.clone(), host.clone()).expect("open"),
    );
    let dealt = [7u8; 32];
    common::seed_policy_with_dealt_share(
        &c,
        &group_key,
        cosigner_kp,
        wallet_kp,
        &pkp,
        Some(hex::encode(dealt)),
    );
    let service_id = Identifier::derive(b"the platform").unwrap();
    let service_hex = hex::encode(service_id.serialize());
    std::env::set_var("SERVICE_ORIGINS", format!("{service_hex}={ORIGIN}"));

    // --- Open: the wallet's dealing of its Δ, the service, and the deal it wants struck ----------
    let mut rng = OsRng;
    let (delta, slope) = (random::mod_n_random(&mut rng), random::mod_n_random(&mut rng));
    let (w_r1s, w_r1p) = dkg::dkg_reshare_part1(&wallet_id, 2, 2, &delta, &[slope], &mut rng)
        .expect("the wallet's round one");
    let attempt = [0xaa; 16];
    let deadline = now_secs() + 3_600;
    let wire = Wire::default();
    let mut reply = Reply::open(c.into_inner().unwrap(), &wire);
    wire.say(
        1,
        ToCosigner::Open(proto::EscrowOpen {
            identifier: wallet_id.serialize().to_vec(),
            round1_package: w_r1p.to_json(),
            context: vec![3; 16],
            service_identifier: service_id.serialize().to_vec(),
            attempt_id: attempt.to_vec(),
            policy_json: r#"{"op":"always"}"#.into(),
            deadline_secs: deadline,
        }),
    );

    // --- Round one back, and the wallet's round two ----------------------------------------------
    let FromCosigner::Round1(round1) = reply.next(1) else { panic!("expected round one") };
    assert_eq!(round1.wallet_dealt_share, dealt, "the half the wallet rebuilds its share from");
    let peers: BTreeMap<Identifier, Round1Package> =
        [(cosigner_id.clone(), Round1Package::from_json(&round1.round1_package).unwrap())].into();
    let (w_r2s, w_shares) = dkg::dkg_part2(&w_r1s, &peers, &[]).expect("the wallet's round two");
    wire.say(
        2,
        ToCosigner::Round2(proto::EscrowRound2 {
            round2_package: w_shares[&cosigner_id].to_json(),
        }),
    );

    // --- The escrow key: the same on both sides --------------------------------------------------
    let FromCosigner::Complete(complete) = reply.next(2) else { panic!("expected the escrow key") };
    let peers_r2: BTreeMap<Identifier, Round2Package> =
        [(cosigner_id.clone(), Round2Package::from_json(&complete.round2_package).unwrap())].into();
    let receivers = [wallet_id.clone(), cosigner_id.clone()];
    let (escrow_kp, escrow_pkp) =
        dkg::dkg_reshare_part3(&w_r2s, &peers, &peers_r2, &pkp, wallet_kp, &receivers)
            .expect("the wallet's escrow share");
    assert_eq!(complete.escrow_key, hex::encode(escrow_pkp.verifying_key.serialize()));

    // --- The pairing: the wallet deals the service's share onto {service, cosigner} --------------
    let pairing_ids = [service_id.clone(), cosigner_id.clone()];
    let dealing = dkg::refresh_to_ids(&escrow_kp, &receivers, &pairing_ids, 2, &mut rng);
    let a_at_service = dealing[&service_id];
    wire.say(
        3,
        ToCosigner::Deal(proto::PairServiceDeal {
            contribution_to_cosigner: scalar::scalar_to_bytes(&dealing[&cosigner_id]).to_vec(),
            contribution_to_service: point::serialize_compressed(&point::base_mul(&a_at_service))
                .to_vec(),
        }),
    );

    // The cosigner's half went to the service, over the connection the runtime holds to the origin
    // the image names — once.
    let FromCosigner::Paired(paired) = reply.next(3) else { panic!("expected the pairing") };
    assert_eq!(paired.service_origin, ORIGIN);
    let stream = service_stream_id(&service_hex);
    assert_eq!(host.opened(), vec![(stream.clone(), ORIGIN.to_string())]);
    let sent = host.sent();
    assert_eq!(sent.len(), 1, "one half, sent once");
    assert_eq!(sent[0].0, stream);
    let ToService::PairingHalf { escrow_key, attempt_id, half, .. } =
        serde_json::from_slice(&sent[0].1).expect("a message the service can read")
    else {
        panic!("expected the service's half");
    };
    assert_eq!(escrow_key, complete.escrow_key);
    assert_eq!(attempt_id, hex::encode(attempt));
    // And the two halves make the share the pairing published — what the service checks before it
    // relies on being able to sign.
    let b_at_service =
        scalar::scalar_from_bytes(&hex::decode(half).unwrap().try_into().unwrap()).unwrap();
    let share = point::base_mul(&(a_at_service + b_at_service));
    assert_eq!(hex::encode(point::serialize_compressed(&share)), paired.service_verifying_share);

    // --- Delivered: the wallet's word that its own half landed, and the deal with it -------------
    wire.say(
        4,
        ToCosigner::Delivered(proto::PairServiceConfirmRequest {
            escrow_key: complete.escrow_key.clone(),
            attempt_id: attempt.to_vec(),
        }),
    );
    let FromCosigner::Confirmed(confirmed) = reply.next(4) else { panic!("expected the deal") };
    assert_eq!(confirmed.deadline_secs, deadline);
    assert_eq!(reply.finish(), ("0".to_string(), String::new()), "the stream ends cleanly");

    // What was sealed: an escrow committed to the deal it was opened with, its service paired in,
    // and the WALLET's word recorded as the wallet's. The service's arrives later, on its own
    // connection — so the pairing is not usable yet, and must not look it.
    let reopened = common::open_cosigner(&store, &group_key);
    let guard = reopened.lock().unwrap();
    let escrow = guard.get_escrow_session(&complete.escrow_key).expect("the escrow was sealed");
    let EscrowStage::Dealt { pairing, terms, releases } = &escrow.stage else {
        panic!("expected the escrow committed to its deal");
    };
    assert!(pairing.wallet_confirmed, "the wallet's word, recorded as the wallet's");
    assert!(!pairing.service_confirmed, "the service has said nothing yet");
    assert_eq!(pairing.state(), PairingState::Pending);
    assert_eq!(pairing.attempt_id_hex, hex::encode(attempt));
    assert_eq!(terms.deadline, deadline);
    assert!(releases.is_empty());

    drop(guard);
    let _ = store.delete("sealed_state", &group_key);
}
