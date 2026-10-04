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

use std::collections::BTreeMap;
use std::sync::{Arc, Mutex, Once};

use rand::rngs::OsRng;

use common::wire::{Reply, Wire};
use common::Recorder;
use cosigner::escrow::{service_stream_id, EscrowStage, PairingState, ToService};
use cosigner::handlers::helpers::now_secs;
use cosigner::session::proto::{self, EscrowClientMsg, EscrowServerMsg};
use cosigner::session::proto::escrow_client_msg::Body as ToCosigner;
use cosigner::session::proto::escrow_server_msg::Body as FromCosigner;
use threshold::dkg::{self, Round1Package, Round2Package, Round2SecretPackage};
use threshold::identifier::Identifier;
use threshold::keys::{KeyPackage, PublicKeyPackage};
use threshold::{point, random, scalar};

const ORIGIN: &str = "https://service.example";

/// What the payment costs, sent into the escrow out of the wallet's one VTXO.
const PRICE: u64 = 30_000;

/// The wallet's message number `seq` on the `Escrow` stream.
fn say(wire: &Wire, seq: u64, body: ToCosigner) {
    wire.send(&EscrowClientMsg { session_id: "escrow".into(), seq, body: Some(body) });
}

/// A message of the `Send` stream that funds the escrow, as `Escrow` carries it.
fn fund(wire: &Wire, seq: u64, body: proto::send_client_msg::Body) {
    let send = proto::SendClientMsg { session_id: "escrow".into(), seq, body: Some(body) };
    say(wire, seq, ToCosigner::Fund(send));
}

/// The cosigner's next message, which must be number `seq`.
fn next(reply: &mut Reply, seq: u64) -> FromCosigner {
    let message: EscrowServerMsg = reply.next();
    assert_eq!(message.seq, seq, "the cosigner's messages arrive in order");
    message.body.expect("a message with a body")
}

/// A wallet on the `Escrow` stream with its round two sent: the cosigner's next word is the
/// escrow's key — once that key is sealed.
struct Minting {
    wire: Wire,
    reply: Reply,
    host: Arc<Recorder>,
    store: Arc<cosigner::store::Store>,
    group_key: String,
    pkp: PublicKeyPackage,
    wallet_kp: KeyPackage,
    cosigner_id: Identifier,
    service_id: Identifier,
    peers: BTreeMap<Identifier, Round1Package>,
    w_r2s: Round2SecretPackage,
    attempt: [u8; 16],
    deadline: i64,
}

/// A wallet that has run the `Escrow` stream as far as its deal — minted, paired, dealt — and is
/// still on it: the cosigner waits to hear whether the escrow is funded on the same approval.
struct Dealt {
    wire: Wire,
    reply: Reply,
    store: Arc<cosigner::store::Store>,
    group_key: String,
    wallet_kp: KeyPackage,
    escrow_key: String,
    attempt: [u8; 16],
    deadline: i64,
}

/// The one service this image knows, named once for the whole process: the environment is shared
/// by every test in it.
fn the_platform() -> Identifier {
    static NAMED: Once = Once::new();
    let service_id = Identifier::derive(b"the platform").unwrap();
    NAMED.call_once(|| {
        std::env::set_var(
            "SERVICE_ORIGINS",
            format!("{}={ORIGIN}", hex::encode(service_id.serialize())),
        );
    });
    service_id
}

/// Open the stream as a wallet would, and run it as far as the wallet's round two.
fn mint(store: Arc<cosigner::store::Store>) -> Minting {
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
    let service_id = the_platform();

    // --- Open: the wallet's dealing of its Δ, the service, and the deal it wants struck ----------
    let mut rng = OsRng;
    let (delta, slope) = (random::mod_n_random(&mut rng), random::mod_n_random(&mut rng));
    let (w_r1s, w_r1p) = dkg::dkg_reshare_part1(&wallet_id, 2, 2, &delta, &[slope], &mut rng)
        .expect("the wallet's round one");
    let attempt = [0xaa; 16];
    let deadline = now_secs() + 3_600;
    let wire = Wire::default();
    let mut reply = Reply::open(c.into_inner().unwrap(), "Escrow", &wire);
    say(
        &wire,
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
    let FromCosigner::Round1(round1) = next(&mut reply, 1) else { panic!("expected round one") };
    assert_eq!(round1.wallet_dealt_share, dealt, "the half the wallet rebuilds its share from");
    let peers: BTreeMap<Identifier, Round1Package> =
        [(cosigner_id.clone(), Round1Package::from_json(&round1.round1_package).unwrap())].into();
    let (w_r2s, w_shares) = dkg::dkg_part2(&w_r1s, &peers, &[]).expect("the wallet's round two");
    say(
        &wire,
        2,
        ToCosigner::Round2(proto::EscrowRound2 {
            round2_package: w_shares[&cosigner_id].to_json(),
        }),
    );

    Minting {
        wire,
        reply,
        host,
        store,
        group_key,
        pkp,
        wallet_kp: wallet_kp.clone(),
        cosigner_id,
        service_id,
        peers,
        w_r2s,
        attempt,
        deadline,
    }
}

/// Run the stream as a wallet would, as far as the deal, checking each of the cosigner's answers.
fn deal(store: Arc<cosigner::store::Store>) -> Dealt {
    let Minting {
        wire,
        mut reply,
        host,
        store,
        group_key,
        pkp,
        wallet_kp,
        cosigner_id,
        service_id,
        peers,
        w_r2s,
        attempt,
        deadline,
    } = mint(store);
    let wallet_id = wallet_kp.identifier.clone();
    let service_hex = hex::encode(service_id.serialize());
    let mut rng = OsRng;

    // --- The escrow key: the same on both sides --------------------------------------------------
    let FromCosigner::Complete(complete) = next(&mut reply, 2) else {
        panic!("expected the escrow key")
    };
    let peers_r2: BTreeMap<Identifier, Round2Package> =
        [(cosigner_id.clone(), Round2Package::from_json(&complete.round2_package).unwrap())].into();
    let receivers = [wallet_id.clone(), cosigner_id.clone()];
    let (escrow_kp, escrow_pkp) =
        dkg::dkg_reshare_part3(&w_r2s, &peers, &peers_r2, &pkp, &wallet_kp, &receivers)
            .expect("the wallet's escrow share");
    assert_eq!(complete.escrow_key, hex::encode(escrow_pkp.verifying_key.serialize()));

    // --- The pairing: the wallet deals the service's share onto {service, cosigner} --------------
    let pairing_ids = [service_id.clone(), cosigner_id.clone()];
    let dealing = dkg::refresh_to_ids(&escrow_kp, &receivers, &pairing_ids, 2, &mut rng);
    let a_at_service = dealing[&service_id];
    say(
        &wire,
        3,
        ToCosigner::Deal(proto::PairServiceDeal {
            contribution_to_cosigner: scalar::scalar_to_bytes(&dealing[&cosigner_id]).to_vec(),
            contribution_to_service: point::serialize_compressed(&point::base_mul(&a_at_service))
                .to_vec(),
        }),
    );

    // The cosigner's half went to the service, over the connection the runtime holds to the origin
    // the deployment names — once.
    let FromCosigner::Paired(paired) = next(&mut reply, 3) else { panic!("expected the pairing") };
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
    say(
        &wire,
        4,
        ToCosigner::Delivered(proto::PairServiceConfirmRequest {
            escrow_key: complete.escrow_key.clone(),
            attempt_id: attempt.to_vec(),
        }),
    );
    let FromCosigner::Confirmed(confirmed) = next(&mut reply, 4) else {
        panic!("expected the deal")
    };
    assert_eq!(confirmed.deadline_secs, deadline);

    Dealt {
        wire,
        reply,
        store,
        group_key,
        wallet_kp,
        escrow_key: complete.escrow_key,
        attempt,
        deadline,
    }
}

/// One approval, one stream: the escrow is minted, its service paired in, and its deal struck — and
/// what is sealed at the end is exactly that, with nobody's word recorded as anybody else's.
#[test]
fn an_escrow_is_minted_paired_and_dealt_on_one_stream() {
    let Some(store) = common::try_store() else { return };
    let Dealt { wire, reply, store, group_key, escrow_key, attempt, deadline, .. } = deal(store);

    // A wallet that funds the escrow with a send of its own ends its side here.
    wire.close();
    assert_eq!(reply.finish(), ("0".to_string(), String::new()), "the stream ends cleanly");

    // What was sealed: an escrow committed to the deal it was opened with, its service paired in,
    // and the WALLET's word recorded as the wallet's. The service's arrives later, on its own
    // connection — so the pairing is not usable yet, and must not look it.
    let reopened = common::open_cosigner(&store, &group_key);
    let guard = reopened.lock().unwrap();
    let escrow = guard.get_escrow_session(&escrow_key).expect("the escrow was sealed");
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

/// An escrow that could not be saved is never announced: the wallet would fund a key the cosigner
/// forgets on its next request, which reopens from the seal. The stream fails instead, and says so.
#[test]
fn an_escrow_that_cannot_be_sealed_is_never_announced() {
    let dir = tempfile::tempdir().unwrap();
    let store = cosigner::store::Store::open(dir.path().to_str().unwrap(), 1800).expect("a store");
    let Minting { reply, group_key, .. } = mint(Arc::new(store));

    // The wallet's round two is on the wire and not yet read; the disk fails before it is.
    common::block_seal(dir.path(), &group_key);
    let (code, message) = reply.finish();
    assert_eq!(code, (cosigner::grpc::Code::Unavailable as u32).to_string(), "{message}");
    assert!(message.contains("nothing was minted"), "unexpected: {message}");
}

/// The ASP's terms, as a wallet relays them.
fn ark_info() -> cosigner::wallet_proto::ArkInfo {
    cosigner::wallet_proto::ArkInfo {
        signer_pubkey: "79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798".into(),
        forfeit_pubkey: "0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798".into(),
        forfeit_address: "bcrt1qq5rjlmqartxjyh6vnmjrhrqnc58q2hqr5asln0".into(),
        checkpoint_tapscript: String::new(),
        network: "regtest".into(),
        session_duration: 0,
        unilateral_exit_delay: 512,
        boarding_exit_delay: 144,
        vtxo_min_amount: 0,
        dust: 330,
    }
}

/// The send that funds the escrow: the price, out of the one VTXO the wallet holds, paid to
/// [recipient] — which a funding send must leave empty.
fn funding_open(recipient: &str) -> proto::send_client_msg::Body {
    proto::send_client_msg::Body::Open(proto::SendOpen {
        recipient_ark_address: recipient.into(),
        amount: PRICE,
        ark_info: Some(ark_info()),
        vtxos: vec![proto::VtxoInput {
            txid: "11".repeat(32),
            vout: 0,
            amount_sats: 100_000,
            exit_delay: 512,
            expires_at: 0,
        }],
        ..Default::default()
    })
}

/// A payment on one approval: the escrow minted, paired and dealt, then funded on the same stream —
/// the money going where the cosigner says, to the escrow it minted, and nowhere the wallet named.
#[test]
fn an_escrow_is_funded_on_the_same_approval() {
    let Some(store) = common::try_store() else { return };
    let Dealt { wire, mut reply, wallet_kp, escrow_key, .. } = deal(store);

    fund(&wire, 5, funding_open(""));
    let FromCosigner::Funding(proto::SendServerMsg {
        body: Some(proto::send_server_msg::Body::Sighashes(sighashes)),
        ..
    }) = next(&mut reply, 1)
    else {
        panic!("expected the funding send's sighashes");
    };
    assert!(
        sighashes.wallet_dealt_share.is_empty(),
        "the wallet rebuilt its share on this stream's first round; one stream, one reconstruction"
    );

    // The wallet's half of the round, with the share it rebuilt for the reshare.
    let commitments: Vec<cosigner::types::Commitment> = sighashes
        .cosigner_commitments
        .iter()
        .map(|c| cosigner::types::Commitment {
            identifier_hex: sighashes.cosigner_identifier.clone(),
            hiding: c.hiding.clone(),
            binding: c.binding.clone(),
        })
        .collect();
    let halves = common::wallet_answers(&wallet_kp, &sighashes.messages_to_sign, &commitments);
    fund(
        &wire,
        6,
        proto::send_client_msg::Body::Signed(proto::SendSigned {
            rounds: halves
                .into_iter()
                .map(|h| proto::WalletRound {
                    hiding: h.hiding,
                    binding: h.binding,
                    share: h.share,
                })
                .collect(),
        }),
    );

    // What to submit to the ASP pays the escrow this stream minted, at the address its key gives.
    let FromCosigner::Funding(proto::SendServerMsg {
        body: Some(proto::send_server_msg::Body::Submit(submit)),
        ..
    }) = next(&mut reply, 2)
    else {
        panic!("expected the funding send's transaction");
    };
    let escrow_xonly = &escrow_key[2..];
    let address = ark::client::ark_address(
        escrow_xonly,
        &ark_info().signer_pubkey,
        512,
        ark::client::parse_network("regtest").unwrap(),
    )
    .unwrap();
    let escrow_script = ark::client::address::ark_address_script_pubkey_hex(&address).unwrap();
    let psbt: bitcoin::Psbt = submit.ark_tx_b64.parse().expect("a PSBT");
    assert!(
        psbt.unsigned_tx
            .output
            .iter()
            .any(|o| hex::encode(o.script_pubkey.as_bytes()) == escrow_script
                && o.value.to_sat() == PRICE),
        "the price goes to the escrow's own address"
    );
}

/// Where a payment's money goes is the cosigner's to derive, never the wallet's to name: a funding
/// send that names a recipient is refused before anything is built.
#[test]
fn a_funding_send_cannot_name_where_the_money_goes() {
    let Some(store) = common::try_store() else { return };
    let Dealt { wire, reply, .. } = deal(store);

    fund(&wire, 5, funding_open("tark1somewhere-else"));
    let (code, message) = reply.finish();
    assert_eq!(code, (cosigner::grpc::Code::InvalidArgument as u32).to_string(), "{message}");
    assert!(message.contains("names no recipient"), "unexpected: {message}");
}
