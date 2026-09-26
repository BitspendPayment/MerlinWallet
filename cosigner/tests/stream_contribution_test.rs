//! The half of the wallet's share the cosigner dealt, handed back on the streams that sign.
//!
//! The wallet keeps no share between operations. Each one re-derives the wallet's own half from its
//! passkey and adds the half the cosigner dealt it at DKG — which used to come back from `Recover`
//! alone, and now rides the first round of `Sign`, `Send` and `Settle`, under the approval the
//! stream already has. These tests are about what may come back, to whom, and how often:
//!
//!  * to the identifier the ceremony recorded, and to no other;
//!  * never without the runtime's tenant, which is what says whose instance this is;
//!  * once per stream, on its first round;
//!  * and never the cosigner's *own* share, which is a different scalar and leaves for nobody.
//!
//! On tenants. One tenant is one instance over one store; the runtime scopes the filesystem and
//! this component never sees another tenant's seal. There is no in-guest tenant table to test, so
//! "tenant A cannot read tenant B's half" is shown the only way it can be here: two instances over
//! two stores, each asked with the other's wallet, each refusing.
//!
//! Driven through `route`, over real frames, because the property is about the wire. A body is
//! written whole before the handler runs, so a test reads what the cosigner says first and cannot
//! answer it — the stream then ends `Cancelled`, which is what a wallet vanishing looks like.

mod common;

use cosigner::grpc::Code;
use cosigner::session::proto;
use cosigner::wallet_proto as wp;
use cosigner::Cosigner;

use threshold::keys::{KeyPackage, PublicKeyPackage};
use threshold::scalar::scalar_to_bytes;

use common::wire::{block_on, collect, request, service, Answer, TENANT};

/// What the cosigner dealt this wallet. Any 32 bytes: nothing here adds it to anything.
const DEALT: [u8; 32] = [0x5a; 32];

/// The ASP's key in `ark_info()`: the secp256k1 generator's x, a valid x-only key.
const ASP_XONLY: &str = "79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798";

struct Wallet {
    cosigner: Cosigner,
    kps: Vec<KeyPackage>,
    pkp: PublicKeyPackage,
}

impl Wallet {
    fn identifier(&self) -> Vec<u8> {
        self.kps[0].identifier.serialize().to_vec()
    }
}

/// A wallet in its own store — its own tenant — whose seal holds [dealt].
fn wallet(dealt: Option<[u8; 32]>) -> Option<Wallet> {
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
        // A seal needs the Ark cosigner key to sign the delegate with.
        Some(hex::encode([9u8; 32])),
        dealt.map(hex::encode),
    );
    Some(Wallet { cosigner: cosigner.into_inner().unwrap(), kps, pkp })
}

fn ark_info() -> wp::ArkInfo {
    wp::ArkInfo {
        signer_pubkey: ASP_XONLY.into(),
        forfeit_pubkey: format!("02{ASP_XONLY}"),
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

fn vtxo(txid: char) -> proto::VtxoInput {
    proto::VtxoInput {
        txid: txid.to_string().repeat(64),
        vout: 0,
        amount_sats: 50_000,
        exit_delay: 512,
        // A delegate needs a deadline to be scheduled against.
        expires_at: 4_102_444_800,
    }
}

fn sign_open(identifier: Vec<u8>) -> proto::SignClientMsg {
    proto::SignClientMsg {
        session_id: "s".into(),
        seq: 0,
        body: Some(proto::sign_client_msg::Body::Open(proto::SignOpen {
            message_to_sign: vec![0x42; 32],
            full_transaction: Vec::new(),
            script_path_spend: true,
            identifier,
        })),
    }
}

/// A send to the wallet's own Ark address: somewhere real to pay, with nothing else to set up.
fn send_open(w: &Wallet, identifier: Vec<u8>) -> proto::SendClientMsg {
    let owner = hex::encode(&w.pkp.verifying_key.serialize()[1..]);
    let recipient =
        ark::client::address::ark_address(&owner, ASP_XONLY, 512, bitcoin::Network::Regtest)
            .expect("an Ark address");
    proto::SendClientMsg {
        session_id: "s".into(),
        seq: 0,
        body: Some(proto::send_client_msg::Body::Open(proto::SendOpen {
            recipient_ark_address: recipient,
            amount: 10_000,
            ark_info: Some(ark_info()),
            vtxos: vec![vtxo('a')],
            identifier,
        })),
    }
}

/// A `seal_only` settle: the one settle whose first round needs no ASP to have said anything.
fn settle_open(identifier: Vec<u8>) -> proto::SettleClientMsg {
    proto::SettleClientMsg {
        session_id: "s".into(),
        seq: 0,
        body: Some(proto::settle_client_msg::Body::Open(proto::SettleOpen {
            ark_info: Some(ark_info()),
            vtxos: vec![vtxo('a')],
            seal_only: true,
            identifier,
            ..Default::default()
        })),
    }
}

/// The dealt share on a stream's first answer, whichever stream it is.
enum First {
    Sign(Answer<proto::SignServerMsg>),
    Send(Answer<proto::SendServerMsg>),
    Settle(Answer<proto::SettleServerMsg>),
}

impl First {
    fn code(&self) -> u32 {
        match self {
            First::Sign(a) => a.code,
            First::Send(a) => a.code,
            First::Settle(a) => a.code,
        }
    }

    fn message(&self) -> &str {
        match self {
            First::Sign(a) => &a.message,
            First::Send(a) => &a.message,
            First::Settle(a) => &a.message,
        }
    }

    fn answered(&self) -> usize {
        match self {
            First::Sign(a) => a.messages.len(),
            First::Send(a) => a.messages.len(),
            First::Settle(a) => a.messages.len(),
        }
    }

    /// What the first answer carried as the wallet's dealt share. Panics if there was no answer, or
    /// it was not the round that carries one.
    fn dealt(&self) -> Vec<u8> {
        match self {
            First::Sign(a) => match &a.messages.first().expect("an answer").body {
                Some(proto::sign_server_msg::Body::Commitments(c)) => c.wallet_dealt_share.clone(),
                other => panic!("expected the commitments round, got {other:?}"),
            },
            First::Send(a) => match &a.messages.first().expect("an answer").body {
                Some(proto::send_server_msg::Body::Sighashes(s)) => s.wallet_dealt_share.clone(),
                other => panic!("expected sighashes, got {other:?}"),
            },
            First::Settle(a) => match &a.messages.first().expect("an answer").body {
                Some(proto::settle_server_msg::Body::Sighashes(s)) => s.wallet_dealt_share.clone(),
                other => panic!("expected sighashes, got {other:?}"),
            },
        }
    }
}

const STREAMS: &[&str] = &["Sign", "Send", "Settle"];

/// Open [stream] on [w]'s instance as the wallet [identifier] claims to be, and read what comes back.
fn open(stream: &str, w: Wallet, identifier: Vec<u8>, tenant: Option<&str>) -> First {
    match stream {
        "Sign" => First::Sign(collect(block_on(
            service(w.cosigner).route(request("Sign", &[sign_open(identifier)], tenant)),
        ))),
        "Send" => {
            let open = send_open(&w, identifier);
            First::Send(collect(block_on(
                service(w.cosigner).route(request("Send", &[open], tenant)),
            )))
        }
        "Settle" => First::Settle(collect(block_on(
            service(w.cosigner).route(request("Settle", &[settle_open(identifier)], tenant)),
        ))),
        other => panic!("no such stream: {other}"),
    }
}

/// The wallet's own identifier gets the half it was dealt, verbatim, on the first round.
#[test]
fn every_signing_stream_returns_the_dealt_share_to_the_wallets_own_identifier() {
    for stream in STREAMS {
        let Some(w) = wallet(Some(DEALT)) else { return };
        let id = w.identifier();
        let first = open(stream, w, id, Some(TENANT));
        assert_eq!(
            first.answered(),
            1,
            "{stream}: one round went out before the client vanished ({} {})",
            first.code(),
            first.message()
        );
        assert_eq!(first.dealt(), DEALT.to_vec(), "{stream}: the sealed share, verbatim");
        // The test cannot answer the round, so the stream is cut off — not failed, and not done.
        assert_eq!(first.code(), Code::Cancelled as u32, "{stream}: {}", first.message());
    }
}

/// What comes back is what the cosigner DEALT, never what it HOLDS. They are different scalars, and
/// the second one signs.
#[test]
fn the_cosigners_own_share_never_leaves() {
    for stream in STREAMS {
        let Some(w) = wallet(Some(DEALT)) else { return };
        let own = scalar_to_bytes(&w.kps[1].secret_share).to_vec();
        let id = w.identifier();
        let dealt = open(stream, w, id, Some(TENANT)).dealt();
        assert_ne!(dealt, own, "{stream} returned the cosigner's own signing share");
    }
}

/// A wallet that is not this one — a wrong passkey, a PRF that answers differently, or somebody
/// else's wallet altogether — is refused, and before anything is said.
#[test]
fn an_identifier_the_ceremony_never_saw_is_refused_on_every_stream() {
    for stream in STREAMS {
        let Some(w) = wallet(Some(DEALT)) else { return };
        let Some(stranger) = wallet(Some([0x11; 32])) else { return };
        let first = open(stream, w, stranger.identifier(), Some(TENANT));
        assert_eq!(
            first.code(),
            Code::PermissionDenied as u32,
            "{stream}: {}",
            first.message()
        );
        assert_eq!(first.answered(), 0, "{stream} answered a wallet that is not its own");
    }
}

/// Two tenants are two instances over two stores. Each holds one wallet's half and refuses the
/// other's wallet — and neither can be made to say what the other holds.
#[test]
fn one_tenants_instance_does_not_answer_for_another_tenants_wallet() {
    for stream in STREAMS {
        let (Some(a), Some(b)) = (wallet(Some([0xaa; 32])), wallet(Some([0xbb; 32]))) else {
            return;
        };
        let (id_a, id_b) = (a.identifier(), b.identifier());

        let b_on_a = open(stream, a, id_b, Some(TENANT));
        assert_eq!(b_on_a.code(), Code::PermissionDenied as u32, "{stream}: {}", b_on_a.message());
        assert_eq!(b_on_a.answered(), 0);

        let a_on_b = open(stream, b, id_a, Some(TENANT));
        assert_eq!(a_on_b.code(), Code::PermissionDenied as u32, "{stream}: {}", a_on_b.message());
        assert_eq!(a_on_b.answered(), 0);
    }
}

/// Knowing the identifier is not enough — it is public. Without the tenant the runtime resolved,
/// nothing is answered at all.
#[test]
fn the_right_identifier_without_a_tenant_gets_nothing() {
    for stream in STREAMS {
        let Some(w) = wallet(Some(DEALT)) else { return };
        let id = w.identifier();
        let first = open(stream, w, id, None);
        assert_eq!(first.code(), Code::Unauthenticated as u32, "{stream}: {}", first.message());
        assert_eq!(first.answered(), 0, "{stream} answered an unapproved caller");
    }
}

/// An identifier that is not 32 bytes — or not sent, which is what a wallet from before this would
/// do — is a malformed request, not a wrong passkey.
#[test]
fn a_missing_identifier_is_refused() {
    for stream in STREAMS {
        let Some(w) = wallet(Some(DEALT)) else { return };
        let first = open(stream, w, Vec::new(), Some(TENANT));
        assert_eq!(first.code(), Code::InvalidArgument as u32, "{stream}: {}", first.message());
        assert_eq!(first.answered(), 0);
    }
}

/// A wallet sealed before the cosigner kept what it dealt has nothing to rebuild a share from. It
/// is refused by name — this is the message a development wallet that needs resetting sees.
#[test]
fn a_wallet_with_no_dealt_share_cannot_sign() {
    for stream in STREAMS {
        let Some(w) = wallet(None) else { return };
        let id = w.identifier();
        let first = open(stream, w, id, Some(TENANT));
        assert_eq!(first.code(), Code::FailedPrecondition as u32, "{stream}: {}", first.message());
        assert!(
            first.message().contains("created before recovery existed"),
            "{stream}: {}",
            first.message()
        );
        assert_eq!(first.answered(), 0);
    }
}

/// `Sign` is script-path only, and says so rather than failing later as a bad share.
#[test]
fn a_key_path_sign_is_refused_by_name() {
    let Some(w) = wallet(Some(DEALT)) else { return };
    let mut open = sign_open(w.identifier());
    if let Some(proto::sign_client_msg::Body::Open(o)) = &mut open.body {
        o.script_path_spend = false;
    }
    let answer = collect::<proto::SignServerMsg>(block_on(
        service(w.cosigner).route(request("Sign", &[open], Some(TENANT))),
    ));
    assert_eq!(answer.code, Code::InvalidArgument as u32, "{}", answer.message);
    assert!(answer.messages.is_empty(), "no share may go out for a round that will not run");
}
