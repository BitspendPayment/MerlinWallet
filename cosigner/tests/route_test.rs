//! The router, over real frames: routing, the five-byte frames, and the `grpc-status` trailer a
//! client actually reads a failure from.
//!
//! Driven through `route` with real framed bodies rather than handlers directly: only the wire
//! shows what a client actually reads.

mod common;

use std::collections::BTreeMap;
use std::sync::Arc;

use rand::rngs::OsRng;

use cosigner::grpc::Code;
use cosigner::session::proto;
use cosigner::wallet_proto::{GetServerInfoRequest, GetServerInfoResponse};
use cosigner::Cosigner;

use threshold::dkg::{self, Round1Package};
use threshold::identifier::Identifier;
use threshold::keys::KeyPackage;
use threshold::random;

use common::wire::{block_on, collect, request, service, Reply, Wire};

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
        Some(hex::encode([7u8; 32])),
    );
    Some((cosigner.into_inner().unwrap(), kps))
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
        service(cosigner).route(request("Sign", &[sign_open(&kps[0])])),
    ));
    assert_eq!(answer.code, Code::Cancelled as u32, "got {}", answer.message);
    assert_eq!(answer.messages.len(), 1, "the commitments round went out before the client vanished");
}

/// An unknown method is a gRPC status and not an HTTP one — a client reading
/// only the head would otherwise see a perfectly successful call.
#[test]
fn an_unknown_method_is_unimplemented_in_the_trailers() {
    let Some((cosigner, _)) = seeded() else { return };
    let resp = block_on(
        service(cosigner).route(request::<GetServerInfoRequest>("Nope", &[])),
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
        service(cosigner).route(request("Dkg", &[open])),
    ));
    assert_eq!(answer.code, Code::FailedPrecondition as u32, "got {}", answer.message);
    assert!(answer.messages.is_empty(), "no round-one package may go out");
}

/// A key that could not be saved is never announced. The wallet would go on to fund a key the
/// cosigner forgets on its next request, which reopens from the seal — so the ceremony fails.
#[test]
fn a_dkg_whose_key_cannot_be_sealed_does_not_finish() {
    let dir = tempfile::tempdir().unwrap();
    let store = cosigner::store::Store::open(dir.path().to_str().unwrap(), 1800).expect("a store");
    common::block_seal(dir.path(), "tenant");
    let cosigner =
        Cosigner::open(Arc::new(store), "tenant".into(), Arc::new(cosigner::host::Detached))
            .expect("a fresh tenant");

    // The wallet's round one, and the cosigner's back.
    let mut rng = OsRng;
    let (secret, slope) = (random::mod_n_random(&mut rng), random::mod_n_random(&mut rng));
    let (r1s, r1p) = dkg::dkg_part1(2, 2, &secret, &[slope], &mut rng).unwrap();
    let me = hex::encode(r1s.identifier.serialize());
    let say = |wire: &Wire, seq, body| {
        wire.send(&proto::DkgClientMsg { session_id: "d1".into(), seq, body: Some(body) })
    };
    let wire = Wire::default();
    let mut reply = Reply::open(cosigner, "Dkg", &wire);
    say(
        &wire,
        1,
        proto::dkg_client_msg::Body::Open(proto::DkgOpen {
            identifier: r1s.identifier.serialize().to_vec(),
            round1_package: r1p.to_json(),
            ..Default::default()
        }),
    );
    let Some(proto::dkg_server_msg::Body::Round1(round1)) = reply.next::<proto::DkgServerMsg>().body
    else {
        panic!("expected round one");
    };

    // The wallet's round two: everything the cosigner needs to finish the key.
    let peers: BTreeMap<Identifier, Round1Package> = round1
        .round1_packages
        .iter()
        .filter(|(id, _)| **id != me)
        .map(|(id, package)| (id.parse().unwrap(), Round1Package::from_json(package).unwrap()))
        .collect();
    let (_, shares) = dkg::dkg_part2(&r1s, &peers, &[]).unwrap();
    say(
        &wire,
        2,
        proto::dkg_client_msg::Body::Round2(proto::DkgRound2 {
            identifier: r1s.identifier.serialize().to_vec(),
            round2_packages_for_others: shares
                .iter()
                .map(|(id, package)| (hex::encode(id.serialize()), package.to_json()))
                .collect(),
        }),
    );

    let (code, message) = reply.finish();
    assert_eq!(code, (Code::Unavailable as u32).to_string(), "{message}");
    assert!(message.contains("the ceremony did not finish"), "unexpected: {message}");
}
