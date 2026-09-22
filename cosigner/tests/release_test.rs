//! A service asking to be paid out of an escrow.
//!
//! Six things have to hold before anything is signed, and none of them is taken on the service's
//! word. What is proved here is each of the six refusing on its own, and — the part that makes the
//! rest worth anything — that when they all hold, the cosigner's half really does combine with the
//! service's into a BIP-340 signature over the escrow key.

mod common;

use std::collections::BTreeMap;
use std::sync::Arc;

use common::Recorder;
use cosigner::asp::AspApi;
use cosigner::escrow_session::EscrowSession;
use cosigner::evidence::{Evidence, EvidenceRequest, FetchEvidence, HttpGet, OnUnavailable, Predicate};
use cosigner::handlers::helpers::block_on_ready;
use cosigner::handlers::release::{ProposedInput, ReleaseRequest, WireCommitment};
use cosigner::policy::Policy;
use cosigner::service_stream::{service_stream_id, ToService};
use cosigner::types::{EscrowRecord, ServicePairing};

use ark::client::types::ArkInfo;
use rand::rngs::OsRng;
use threshold::commitment::SigningPackage;
use threshold::identifier::Identifier;
use threshold::keys::{KeyPackage, PublicKeyPackage};
use threshold::nonce::{self, SigningCommitments};
use threshold::scalar::scalar_from_bytes;
use threshold::{point, scalar, signing};

const MIN_SIGNERS: usize = 2;
const HOUR: i64 = 3_600;
/// One VTXO, and a payout small enough that there is change.
const VTXO_SATS: u64 = 200_000;
const PAYOUT_SATS: u64 = 50_000;
const REFERENCE: &str = "tx_abc123";
/// A valid x-only key that is not the service's — BIP-340's test vector for private key 3.
const ELSEWHERE: &str = "f9308a019258c31049344f85f89d5229b531c845836f99b08601f113bce036f9";

// ---------------------------------------------------------------------------------------------
// The world the release happens in
// ---------------------------------------------------------------------------------------------

fn ark_info() -> ArkInfo {
    ArkInfo {
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

/// An ASP that answers the one question a release asks it.
struct Asp;

impl AspApi for Asp {
    type Events = cosigner::asp::NoEvents;
    async fn get_info(&mut self) -> Result<ArkInfo, String> {
        Ok(ark_info())
    }
    async fn register_intent(&mut self, _: &str, _: &str) -> Result<String, String> {
        Err("not used".into())
    }
    async fn events(&mut self, _: &[String]) -> Result<Self::Events, String> {
        Err("not used".into())
    }
    async fn confirm_registration(&mut self, _: &str) -> Result<(), String> {
        Err("not used".into())
    }
    async fn submit_tree_nonces(&mut self, _: &str, _: &str, _: &[(String, String)]) -> Result<(), String> {
        Err("not used".into())
    }
    async fn submit_tree_signatures(&mut self, _: &str, _: &str, _: &[(String, String)]) -> Result<(), String> {
        Err("not used".into())
    }
    async fn submit_forfeits(&mut self, _: &[String], _: &str) -> Result<(), String> {
        Err("not used".into())
    }
}

/// A provider that says whatever a test tells it to, and records what it was asked.
#[derive(Default)]
struct Provider {
    answer: std::sync::Mutex<Option<Evidence>>,
    asked: std::sync::Mutex<Vec<EvidenceRequest>>,
}

impl Provider {
    fn saying(body: serde_json::Value) -> Self {
        Self {
            answer: std::sync::Mutex::new(Some(Evidence::Json(body))),
            asked: Default::default(),
        }
    }
    fn unreachable() -> Self {
        Self {
            answer: std::sync::Mutex::new(Some(Evidence::Unreachable("no route".into()))),
            asked: Default::default(),
        }
    }
}

impl FetchEvidence for Provider {
    async fn fetch(&self, request: &EvidenceRequest) -> Evidence {
        self.asked.lock().unwrap().push(request.clone());
        self.answer
            .lock()
            .unwrap()
            .clone()
            .unwrap_or(Evidence::Unreachable("nothing configured".into()))
    }
}

/// A provider that takes its time answering.
///
/// The wait is a blocking one because this future is driven by `block_on_ready`, which has no
/// reactor under it: yielding is not an option, so waiting really does have to wait. That is the
/// point — the cosigner reads the real clock, and the only honest way to test what it does when the
/// clock moves during a fetch is to let it move.
struct SlowProvider {
    answer: Evidence,
    takes: std::time::Duration,
}

impl FetchEvidence for SlowProvider {
    async fn fetch(&self, _request: &EvidenceRequest) -> Evidence {
        std::thread::sleep(self.takes);
        self.answer.clone()
    }
}

/// The escrow, its service pairing, and everything the service needs to finish a signature.
struct Paired {
    cosigner: cosigner::Cosigner,
    escrow_key: String,
    stream: String,
    service_kp: KeyPackage,
    pairing_pkp: PublicKeyPackage,
    /// Where the service is paid.
    service_address: String,
}

fn paired(store: &Arc<cosigner::store::Store>, policy: Policy) -> Paired {
    paired_with(store, policy, true, HOUR)
}

/// A deal that ends in [`lasts`] seconds rather than an hour.
fn paired_for(store: &Arc<cosigner::store::Store>, policy: Policy, lasts: i64) -> Paired {
    paired_with(store, policy, true, lasts)
}

/// `finished` is whether BOTH parties have vouched for the pairing. False is what a restart from
/// between the two confirmations leaves behind.
fn paired_with(
    store: &Arc<cosigner::store::Store>,
    policy: Policy,
    finished: bool,
    lasts: i64,
) -> Paired {
    // The escrow: a 2-of-2 the wallet and this cosigner hold, exactly as a reshare leaves it.
    let (kps, pkp) = common::dkg_2of2();
    let (wallet_kp, cosigner_kp) = (kps[0].clone(), kps[1].clone());
    let escrow_key = hex::encode(pkp.verifying_key.serialize());

    // Pair a service in, by the same route `handlers::pairing` takes.
    let service_id = Identifier::derive(b"a-card-service").unwrap();
    let dealt = threshold::dkg::refresh_to_ids(
        &wallet_kp,
        &[wallet_kp.identifier.clone(), cosigner_kp.identifier.clone()],
        &[service_id.clone(), cosigner_kp.identifier.clone()],
        MIN_SIGNERS,
        &mut OsRng,
    );
    let a_at_service = dealt[&service_id];
    let material = cosigner::handlers::pairing::pair_service(
        &cosigner_kp,
        &pkp,
        &wallet_kp.identifier,
        &service_id,
        &scalar::scalar_to_bytes(&dealt[&cosigner_kp.identifier]),
        &point::serialize_compressed(&point::base_mul(&a_at_service)),
    )
    .expect("an honest pairing");

    // The service assembles its share from the two halves it was dealt.
    let b_at_service =
        scalar_from_bytes(&material.service_half.clone().try_into().unwrap()).unwrap();
    let share = a_at_service + b_at_service;
    let pairing_pkp = PublicKeyPackage::from_json(&material.public_key_package_json).unwrap();
    let service_kp = KeyPackage {
        identifier: service_id,
        secret_share: share,
        verifying_share: point::base_mul(&share),
        verifying_key: pairing_pkp.verifying_key.clone(),
        min_signers: MIN_SIGNERS,
    };

    // A wallet to hold it all, with the escrow sealed and committed to a deal.
    let group_key = hex::encode(pkp.verifying_key.serialize());
    let c = std::sync::Mutex::new(
        cosigner::Cosigner::open_with_host(
            store.clone(),
            group_key.clone(),
            Arc::new(Recorder::default()),
        )
        .expect("open"),
    );
    common::seed_policy_with_dealt_share(
        &c,
        &group_key,
        &cosigner_kp,
        &wallet_kp,
        &pkp,
        Some(hex::encode([9u8; 32])),
        Some(hex::encode([7u8; 32])),
    );
    let mut cosigner = c.into_inner().unwrap();

    let now = now();
    cosigner
        .install_escrow(EscrowRecord {
            escrow_key: escrow_key.clone(),
            key_package_json: cosigner_kp.to_json(),
            public_key_package_json: pkp.to_json(),
            wallet_identifier_hex: hex::encode(wallet_kp.identifier.serialize()),
            context_hex: "22".repeat(16),
            wallet_delta_share_hex: "33".repeat(32),
            created_at: now,
            pairing: Some(ServicePairing {
                service_identifier_hex: material.service_identifier_hex.clone(),
                key_package_json: material.key_package_json.clone(),
                public_key_package_json: material.public_key_package_json.clone(),
                service_verifying_share_hex: material.service_verifying_share_hex.clone(),
                paired_at: now,
                attempt_id_hex: "aa".repeat(16),
                service_confirmed: finished,
                wallet_confirmed: true,
            }),
            // An unfinished pairing cannot be committed to a deal through `open_escrow_session` —
            // it is refused there, and rightly. It reaches a release only from a seal that carries
            // both, which `serde(default)` makes possible for anything written before the
            // confirmation existed. So that case is installed rather than opened.
            session: (!finished).then(|| {
                EscrowSession::open(policy.clone(), now, now + lasts).expect("a deal")
            }),
        })
        .expect("install escrow");
    if finished {
        cosigner
            .open_escrow_session(
                &escrow_key,
                EscrowSession::open(policy, now, now + lasts).expect("a deal"),
                now,
            )
            .expect("commit it");
    }

    let info = ark_info();
    let service_address = ark::client::ark_address(
        &"44".repeat(32),
        &info.signer_pubkey,
        info.unilateral_exit_delay as u32,
        ark::client::parse_network(&info.network).unwrap(),
    )
    .expect("an address for the service");

    Paired {
        stream: service_stream_id(&material.service_identifier_hex),
        cosigner,
        escrow_key,
        service_kp,
        pairing_pkp,
        service_address,
    }
}

/// A second escrow on the same wallet, paired to the same service and committed to its own deal.
///
/// Built by hand rather than through a second ceremony: what is being tested is the ledger, and a
/// pairing that signs is not needed to ask for a release that is refused before any signing.
fn second_escrow(p: &mut Paired) -> String {
    let first = p.cosigner.escrow(&p.escrow_key).expect("the first").clone();
    let key = "02".to_string() + &"be".repeat(32);
    let now = now();
    p.cosigner
        .install_escrow(EscrowRecord {
            escrow_key: key.clone(),
            context_hex: "99".repeat(16),
            // Its own deal, not a copy of the first one's.
            session: None,
            ..first
        })
        .expect("a second escrow");
    p.cosigner
        .open_escrow_session(
            &key,
            EscrowSession::open(permissive(), now, now + HOUR).expect("a deal"),
            now,
        )
        .expect("commit it");
    key
}

fn now() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs() as i64
}

// ---------------------------------------------------------------------------------------------
// The service's own side of a signature
// ---------------------------------------------------------------------------------------------

/// The service's round one. It commits FIRST, which is what lets the cosigner do both of its rounds
/// inside one invocation and never write a nonce down.
fn service_commits(n: usize) -> (Vec<nonce::SigningNonce>, Vec<WireCommitment>) {
    let mut nonces = Vec::new();
    let mut wire = Vec::new();
    for _ in 0..n {
        // A secret the nonce is drawn against; the service's own share would do, and does below.
        let nonce = nonce::new_nonce(&mut OsRng, &threshold::random::mod_n_random(&mut OsRng));
        wire.push(WireCommitment {
            hiding: hex::encode(point::serialize_compressed(&nonce.commitments.hiding)),
            binding: hex::encode(point::serialize_compressed(&nonce.commitments.binding)),
        });
        nonces.push(nonce);
    }
    (nonces, wire)
}

/// The service's round two, once the cosigner has answered: its own share, then the aggregate.
fn service_finishes(
    p: &Paired,
    messages: &[Vec<u8>],
    nonces: Vec<nonce::SigningNonce>,
    halves: &[cosigner::handlers::release::SignedHalf],
) -> Vec<Vec<u8>> {
    let cosigner_id = p
        .pairing_pkp
        .verifying_shares
        .keys()
        .find(|id| **id != p.service_kp.identifier)
        .cloned()
        .expect("the pairing holds two");

    messages
        .iter()
        .zip(nonces)
        .zip(halves)
        .map(|((message, nonce), half)| {
            let theirs = SigningCommitments {
                hiding: point::deserialize_compressed(
                    &hex::decode(&half.hiding).unwrap().try_into().unwrap(),
                )
                .unwrap(),
                binding: point::deserialize_compressed(
                    &hex::decode(&half.binding).unwrap().try_into().unwrap(),
                )
                .unwrap(),
            };
            let mut commitments = BTreeMap::new();
            commitments.insert(p.service_kp.identifier.clone(), nonce.commitments.clone());
            commitments.insert(cosigner_id.clone(), theirs);

            let package = SigningPackage::new(commitments, message.clone());
            let mine = signing::sign(&package, &nonce, &p.service_kp).expect("the service signs");
            let theirs = signing::SignatureShare {
                s: scalar_from_bytes(&hex::decode(&half.share).unwrap().try_into().unwrap())
                    .unwrap(),
            };

            let mut shares = BTreeMap::new();
            shares.insert(p.service_kp.identifier.clone(), mine);
            shares.insert(cosigner_id.clone(), theirs);
            signing::aggregate(&package, &shares, &p.pairing_pkp)
                .expect("two shares over one package make one signature")
                .serialize()
                .to_vec()
        })
        .collect()
}

// ---------------------------------------------------------------------------------------------
// Requests
// ---------------------------------------------------------------------------------------------

fn request(p: &Paired, commitments: Vec<WireCommitment>) -> ReleaseRequest {
    ReleaseRequest {
        request_id: "req-1".into(),
        escrow_key: p.escrow_key.clone(),
        to_ark_address: p.service_address.clone(),
        amount_sats: PAYOUT_SATS,
        inputs: vec![ProposedInput {
            txid: "11".repeat(32),
            vout: 0,
            amount_sats: VTXO_SATS,
            exit_delay: 512,
        }],
        payment_reference: REFERENCE.into(),
        commitments,
    }
}

fn ask(p: &mut Paired, request: &ReleaseRequest, provider: &Provider) -> ToService {
    block_on_ready(
        p.cosigner
            .release(&p.stream.clone(), request, Some(Asp), provider),
    )
    .expect("a decision, not a fault")
}

fn approval(reply: &ToService) -> &cosigner::handlers::release::ReleaseApproval {
    match reply {
        ToService::ReleaseSigned(a) => a,
        other => panic!("expected an approval, got {other:?}"),
    }
}

fn refusal(reply: &ToService) -> String {
    match reply {
        ToService::ReleaseRefused { reason, .. } => reason.clone(),
        other => panic!("expected a refusal, got {other:?}"),
    }
}

fn permissive() -> Policy {
    Policy::Always
}

// ---------------------------------------------------------------------------------------------
// The thing the rest is in aid of
// ---------------------------------------------------------------------------------------------

/// An approved release really is a signature: the cosigner's half and the service's combine into a
/// BIP-340 signature that verifies against the escrow key. A share that did not, would not.
#[test]
fn an_approved_release_signs_the_escrow_key() {
    let Some(store) = common::try_store() else { return };
    let mut p = paired(&store, permissive());

    // One input: an ark tx sighash and a checkpoint sighash, so two things to sign.
    let (nonces, commitments) = service_commits(2);
    let req = request(&p, commitments);
    let reply = ask(&mut p, &req, &Provider::default());
    let approved = approval(&reply).clone();
    assert_eq!(approved.halves.len(), 2);
    assert!(!approved.already_counted);
    assert!(!approved.ark_tx.is_empty());
    assert_eq!(approved.checkpoint_txs.len(), 1);

    let messages = sighashes(&p, &req);
    let signatures = service_finishes(&p, &messages, nonces, &approved.halves);

    use bitcoin::secp256k1::{schnorr, Message, Secp256k1, XOnlyPublicKey};
    let vk = p.pairing_pkp.verifying_key.into_even_y().serialize();
    for (i, (sig, message)) in signatures.iter().zip(&messages).enumerate() {
        Secp256k1::verification_only()
            .verify_schnorr(
                &schnorr::Signature::from_slice(sig).unwrap(),
                &Message::from_digest(message.clone().try_into().unwrap()),
                &XOnlyPublicKey::from_slice(&vk[1..]).unwrap(),
            )
            .unwrap_or_else(|e| panic!("sighash {i} did not verify: {e}"));
    }
}

/// The sighashes the cosigner will have built, recomputed here so a test can check a signature
/// against them. The service has the same code and does the same thing.
fn sighashes(p: &Paired, req: &ReleaseRequest) -> Vec<Vec<u8>> {
    let owner = p.escrow_key[2..].to_string();
    let vtxos: Vec<cosigner::types::VtxoInput> = req
        .inputs
        .iter()
        .map(|i| cosigner::types::VtxoInput {
            txid: i.txid.clone(),
            vout: i.vout,
            amount_sats: i.amount_sats,
            exit_delay: i.exit_delay,
            expires_at: 0,
        })
        .collect();
    let (_, sighashes) = ark::client::send::SendSession::build(
        &owner,
        &vtxos
            .iter()
            .map(|v| ark::client::send::SendVtxoInput {
                txid: v.txid.clone(),
                vout: v.vout,
                amount_sats: v.amount_sats,
                exit_delay: v.exit_delay,
            })
            .collect::<Vec<_>>(),
        &req.to_ark_address,
        req.amount_sats,
        None,
        &ark_info(),
    )
    .expect("the same build the cosigner did");
    sighashes.iter().map(|s| s.to_vec()).collect()
}

// ---------------------------------------------------------------------------------------------
// 1. the service that spoke is the one paired into this escrow
// ---------------------------------------------------------------------------------------------

#[test]
fn a_release_asked_for_on_another_services_connection_is_refused() {
    let Some(store) = common::try_store() else { return };
    let mut p = paired(&store, permissive());
    let (_, commitments) = service_commits(2);
    let req = request(&p, commitments);

    p.stream = service_stream_id(&"99".repeat(32));
    let reply = ask(&mut p, &req, &Provider::default());
    assert!(refusal(&reply).contains("different service"), "{reply:?}");
}

// ---------------------------------------------------------------------------------------------
// 2. the escrow permits a release now
// ---------------------------------------------------------------------------------------------

/// A deal ends one way: its deadline passes. There is no other, and there is deliberately no way
/// for the owner to cut it short — see `cosigner::escrow_session`.
///
/// The clock is let run for real rather than a flag being set, because a flag is not what happens.
/// Nothing is written when a deal lapses, so the only honest way to test it is to let it lapse.
#[test]
fn a_release_after_the_deadline_is_refused() {
    let Some(store) = common::try_store() else { return };
    // A deal with one second left.
    let mut p = paired_for(&store, permissive(), 1);
    let (_, commitments) = service_commits(2);
    let req = request(&p, commitments);
    assert!(
        matches!(ask(&mut p, &req, &Provider::default()), ToService::ReleaseSigned(_)),
        "while it is running, a release is signed"
    );

    std::thread::sleep(std::time::Duration::from_secs(2));

    let (_, commitments) = service_commits(2);
    let mut after = request(&p, commitments);
    after.request_id = "req-after".into();
    after.payment_reference = "tx_later".into();
    let reply = ask(&mut p, &after, &Provider::default());
    assert!(refusal(&reply).contains("deal is over"), "{reply:?}");
}

// ---------------------------------------------------------------------------------------------
// 3. the transaction satisfies the policy
// ---------------------------------------------------------------------------------------------

#[test]
fn a_release_paying_somewhere_the_policy_does_not_allow_is_refused() {
    let Some(store) = common::try_store() else { return };
    // Allow exactly one destination, and it is not the one the service asks for.
    let elsewhere = ark::client::ark_address_script_pubkey_hex(
        &ark::client::ark_address(
            ELSEWHERE,
            &ark_info().signer_pubkey,
            512,
            ark::client::parse_network("regtest").unwrap(),
        )
        .unwrap(),
    )
    .unwrap();
    let mut p = paired(
        &store,
        Policy::OutputsOnlyTo {
            scripts: vec![elsewhere],
        },
    );

    let (_, commitments) = service_commits(2);
    let req = request(&p, commitments);
    let reply = ask(&mut p, &req, &Provider::default());
    assert!(refusal(&reply).contains("not an allowed destination"), "{reply:?}");
}

#[test]
fn a_release_over_the_per_transaction_cap_is_refused() {
    let Some(store) = common::try_store() else { return };
    let mut p = paired(&store, Policy::TotalOutMax { sats: PAYOUT_SATS - 1 });
    let (_, commitments) = service_commits(2);
    let req = request(&p, commitments);
    let reply = ask(&mut p, &req, &Provider::default());
    assert!(refusal(&reply).contains("over the"), "{reply:?}");
}

/// An ordinary release conserves value — an off-chain Ark transaction pays no fee, and change goes
/// back to the escrow — so the strictest possible fee cap still permits one.
#[test]
fn an_ordinary_release_pays_no_fee_at_all() {
    let Some(store) = common::try_store() else { return };
    let mut p = paired(&store, Policy::FeeMax { sats: 0 });
    let (_, commitments) = service_commits(2);
    let req = request(&p, commitments);
    assert!(
        matches!(ask(&mut p, &req, &Provider::default()), ToService::ReleaseSigned(_)),
        "an Ark send conserves value; the anchor output is what pays"
    );
}

/// The structural fact the cap rests on, pinned so it is noticed if it ever stops being true:
/// whatever the payout, an Ark send's outputs add up to exactly what its inputs were worth. Even
/// change too small to pay — below the dust threshold — is not left behind.
///
/// So on this chain `FeeMax` never fires through honest construction. It is there because "the
/// escrow loses nothing" is a thing a policy should be able to *say*, and because value quietly
/// going missing is the failure a release must not sign through.
#[test]
fn an_ark_send_conserves_every_sat_whatever_it_pays_out() {
    let info = ark_info();
    let to = ark::client::ark_address(
        ELSEWHERE,
        &info.signer_pubkey,
        512,
        ark::client::parse_network(&info.network).unwrap(),
    )
    .unwrap();
    for amount in [50_000u64, VTXO_SATS - 200, VTXO_SATS - 1, VTXO_SATS] {
        let (session, _) = ark::client::send::SendSession::build(
            &"44".repeat(32),
            &[ark::client::send::SendVtxoInput {
                txid: "11".repeat(32),
                vout: 0,
                amount_sats: VTXO_SATS,
                exit_delay: 512,
            }],
            &to,
            amount,
            None,
            &info,
        )
        .expect("it builds");
        let out: u64 = session.outputs().iter().map(|o| o.value.to_sat()).sum();
        assert_eq!(
            out, VTXO_SATS,
            "paying {amount} out of {VTXO_SATS} lost {} sats",
            VTXO_SATS - out
        );
    }
}

// ---------------------------------------------------------------------------------------------
// 4. it fits what is left of the allowance
// ---------------------------------------------------------------------------------------------

/// A running cap, not a per-transaction one: an escrow is spent against over days, and what the
/// owner commits is a total.
#[test]
fn a_release_that_would_take_the_running_total_over_its_cap_is_refused() {
    let Some(store) = common::try_store() else { return };
    let mut p = paired(
        &store,
        Policy::ReleasedTotalMax {
            sats: PAYOUT_SATS + 1,
        },
    );

    // The first one fits.
    let (_, commitments) = service_commits(2);
    let first = request(&p, commitments);
    assert!(matches!(
        ask(&mut p, &first, &Provider::default()),
        ToService::ReleaseSigned(_)
    ));

    // The second is the same size and there is no room for it.
    let (_, commitments) = service_commits(2);
    let mut second = request(&p, commitments);
    second.request_id = "req-2".into();
    second.payment_reference = "tx_def456".into();
    let reply = ask(&mut p, &second, &Provider::default());
    assert!(refusal(&reply).contains("released already"), "{reply:?}");
}

// ---------------------------------------------------------------------------------------------
// 5. the external payment evidence satisfies the policy
// ---------------------------------------------------------------------------------------------

fn condition() -> Policy {
    Policy::HttpGet(Box::new(HttpGet {
        provider: "https://diva.example".into(),
        path: "/v3/transactions/{reference}".into(),
        credentials: "DIVA".into(),
        expect: vec![
            Predicate::Equals {
                at: "state".into(),
                value: "COMPLETION".into(),
            },
            Predicate::MatchesReference { at: "token".into() },
        ],
        on_unavailable: OnUnavailable::Deny,
    }))
}

#[test]
fn a_release_the_provider_does_not_confirm_is_refused() {
    let Some(store) = common::try_store() else { return };
    let mut p = paired(&store, condition());
    let (_, commitments) = service_commits(2);
    let req = request(&p, commitments);

    let provider = Provider::saying(serde_json::json!({
        "state": "DECLINED",
        "token": REFERENCE,
    }));
    let reply = ask(&mut p, &req, &provider);
    assert!(refusal(&reply).contains("state"), "{reply:?}");
}

/// A provider that cannot be reached is not a provider that said yes.
#[test]
fn a_provider_that_cannot_be_reached_denies_rather_than_defaulting_open() {
    let Some(store) = common::try_store() else { return };
    let mut p = paired(&store, condition());
    let (_, commitments) = service_commits(2);
    let req = request(&p, commitments);
    let reply = ask(&mut p, &req, &Provider::unreachable());
    assert!(matches!(reply, ToService::ReleaseRefused { .. }), "{reply:?}");
}

/// The evidence is bound to THIS release: a provider answering about some other payment satisfies
/// nothing, however healthy the answer looks.
#[test]
fn evidence_about_another_payment_does_not_justify_this_release() {
    let Some(store) = common::try_store() else { return };
    let mut p = paired(&store, condition());
    let (_, commitments) = service_commits(2);
    let req = request(&p, commitments);

    let provider = Provider::saying(serde_json::json!({
        "state": "COMPLETION",
        "token": "some-other-payment",
    }));
    let reply = ask(&mut p, &req, &provider);
    assert!(matches!(reply, ToService::ReleaseRefused { .. }), "{reply:?}");
}

#[test]
fn a_release_the_provider_confirms_goes_ahead_and_the_cosigner_fetched_it_itself() {
    let Some(store) = common::try_store() else { return };
    let mut p = paired(&store, condition());
    let (_, commitments) = service_commits(2);
    let req = request(&p, commitments);

    let provider = Provider::saying(serde_json::json!({
        "state": "COMPLETION",
        "token": REFERENCE,
    }));
    let reply = ask(&mut p, &req, &provider);
    assert!(matches!(reply, ToService::ReleaseSigned(_)), "{reply:?}");

    let asked = provider.asked.lock().unwrap().clone();
    assert_eq!(asked.len(), 1, "the cosigner fetched it once, itself");
    assert_eq!(asked[0].provider, "https://diva.example");
    assert_eq!(
        asked[0].path,
        format!("/v3/transactions/{REFERENCE}"),
        "the service supplies the reference and nothing else about the request"
    );
    assert_eq!(asked[0].credentials, "DIVA");
}

// ---------------------------------------------------------------------------------------------
// 6. that evidence has not justified a release already
// ---------------------------------------------------------------------------------------------

/// A replayed authorization verifies every time, because it really did succeed. What stops it
/// paying twice is the sealed record and nothing else.
#[test]
fn one_payment_justifies_one_release_however_it_is_asked_for() {
    let Some(store) = common::try_store() else { return };
    let mut p = paired(&store, permissive());

    let (_, commitments) = service_commits(2);
    let first = request(&p, commitments);
    assert!(matches!(ask(&mut p, &first, &Provider::default()), ToService::ReleaseSigned(_)));

    // Same payment, new request id, new commitments — everything a replay would change.
    let (_, commitments) = service_commits(2);
    let mut again = request(&p, commitments);
    again.request_id = "req-2".into();
    let reply = ask(&mut p, &again, &Provider::default());
    assert!(refusal(&reply).contains("already been released against"), "{reply:?}");
}

/// The record has to survive a restart, because the instance that made it does not.
#[test]
fn what_an_escrow_has_paid_out_against_survives_a_restart() {
    let Some(store) = common::try_store() else { return };
    let mut p = paired(&store, permissive());
    let (_, commitments) = service_commits(2);
    let first = request(&p, commitments);
    ask(&mut p, &first, &Provider::default());

    let group_key = p.cosigner.group_key().to_string();
    p.cosigner = cosigner::Cosigner::open_with_host(
        store.clone(),
        group_key,
        Arc::new(Recorder::default()),
    )
    .expect("reopen");

    let (_, commitments) = service_commits(2);
    let mut again = request(&p, commitments);
    again.request_id = "req-2".into();
    let reply = ask(&mut p, &again, &Provider::default());
    assert!(refusal(&reply).contains("already been released against"), "{reply:?}");
}

// ---------------------------------------------------------------------------------------------
// Retries, duplicates and the things a connection does
// ---------------------------------------------------------------------------------------------

/// A service whose reply was lost asks again. It gets a signature — a fresh one, over a fresh
/// nonce — and its allowance is not charged twice.
#[test]
fn a_retried_request_is_signed_again_and_counted_once() {
    let Some(store) = common::try_store() else { return };
    let mut p = paired(&store, permissive());

    let (_, commitments) = service_commits(2);
    let req = request(&p, commitments);
    let first = ask(&mut p, &req, &Provider::default());
    assert!(!approval(&first).already_counted);

    // The same request, with the fresh nonces a service that lost its own would have.
    let (nonces, commitments) = service_commits(2);
    let mut retry = req.clone();
    retry.commitments = commitments;
    let second = ask(&mut p, &retry, &Provider::default());
    let approved = approval(&second).clone();
    assert!(approved.already_counted, "the allowance was charged once");

    // And it is a real signature, not a stored one: it verifies against the NEW commitments.
    let messages = sighashes(&p, &retry);
    let signatures = service_finishes(&p, &messages, nonces, &approved.halves);
    use bitcoin::secp256k1::{schnorr, Message, Secp256k1, XOnlyPublicKey};
    let vk = p.pairing_pkp.verifying_key.into_even_y().serialize();
    for (sig, message) in signatures.iter().zip(&messages) {
        Secp256k1::verification_only()
            .verify_schnorr(
                &schnorr::Signature::from_slice(sig).unwrap(),
                &Message::from_digest(message.clone().try_into().unwrap()),
                &XOnlyPublicKey::from_slice(&vk[1..]).unwrap(),
            )
            .expect("a retry is signed afresh");
    }
}

/// A request id is an idempotency key. A different release wearing an answered one is a different
/// release, and is refused rather than signed.
#[test]
fn a_request_id_reused_for_a_different_release_is_refused() {
    let Some(store) = common::try_store() else { return };
    let mut p = paired(&store, permissive());
    let (_, commitments) = service_commits(2);
    let req = request(&p, commitments);
    ask(&mut p, &req, &Provider::default());

    let (_, commitments) = service_commits(2);
    let mut different = request(&p, commitments);
    different.amount_sats = PAYOUT_SATS + 1;
    let reply = ask(&mut p, &different, &Provider::default());
    assert!(refusal(&reply).contains("different release"), "{reply:?}");
}

/// The cosigner makes no nonce until it knows the count matches, so a service that guessed wrong
/// loses only its own unused nonces.
#[test]
fn a_commitment_count_that_does_not_match_is_refused_before_anything_is_signed() {
    let Some(store) = common::try_store() else { return };
    let mut p = paired(&store, permissive());
    let (_, commitments) = service_commits(1);
    let req = request(&p, commitments);
    let reply = ask(&mut p, &req, &Provider::default());
    assert!(refusal(&reply).contains("one commitment per signature"), "{reply:?}");

    // And nothing was recorded, so the right request still goes through.
    let (_, commitments) = service_commits(2);
    let good = request(&p, commitments);
    assert!(matches!(ask(&mut p, &good, &Provider::default()), ToService::ReleaseSigned(_)));
}

#[test]
fn a_release_that_spends_one_vtxo_twice_is_refused() {
    let Some(store) = common::try_store() else { return };
    let mut p = paired(&store, permissive());
    let (_, commitments) = service_commits(4);
    let mut req = request(&p, commitments);
    let input = req.inputs[0].clone();
    req.inputs.push(input);
    let reply = ask(&mut p, &req, &Provider::default());
    assert!(refusal(&reply).contains("named twice"), "{reply:?}");
}

/// A pairing nobody has finished cannot be paid: the service holds one half of two, so it could
/// not produce its side of the signature anyway.
#[test]
fn a_release_against_an_unfinished_pairing_is_refused() {
    let Some(store) = common::try_store() else { return };
    let mut p = paired_with(&store, permissive(), false, HOUR);
    let (_, commitments) = service_commits(2);
    let req = request(&p, commitments);
    let reply = ask(&mut p, &req, &Provider::default());
    assert!(refusal(&reply).contains("not finished"), "{reply:?}");
}


// ===============================================================================================
// What a spent payment must survive
//
// A payment that succeeded goes on being true for ever, so the record of having paid against it is
// the only thing standing between a service and being paid twice. These are the ways that record
// could be made to disappear.
// ===============================================================================================

/// Reopening a deal must not forget what the last one already paid against.
///
/// The obvious place to keep this ledger is the session, and that is exactly wrong: a session can
/// be replaced, and replacing it would hand back every payment the previous one had spent.
#[test]
fn reopening_an_escrow_does_not_hand_back_the_payments_it_already_spent() {
    let Some(store) = common::try_store() else { return };
    let mut p = paired_for(&store, permissive(), 1);

    let (_, commitments) = service_commits(2);
    let first = request(&p, commitments);
    assert!(matches!(ask(&mut p, &first, &Provider::default()), ToService::ReleaseSigned(_)));

    // The deal runs out and a new one is struck over the same escrow. Waiting it out rather than
    // ending it: a deal has no ending but its deadline.
    std::thread::sleep(std::time::Duration::from_secs(2));
    let key = p.escrow_key.clone();
    let now = now();
    p.cosigner
        .open_escrow_session(
            &key,
            EscrowSession::open(permissive(), now, now + HOUR).expect("a new deal"),
            now,
        )
        .expect("a new deal can be struck once the last one is over");
    p.cosigner.seal();

    // The same payment, under a new request id. It was spent, and it stays spent.
    let (_, commitments) = service_commits(2);
    let mut again = request(&p, commitments);
    again.request_id = "req-after-reopen".into();
    let reply = ask(&mut p, &again, &Provider::default());
    assert!(
        refusal(&reply).contains("already been released against"),
        "a new deal is a new allowance, not a fresh set of payments: {reply:?}"
    );
}

/// Nor may the next escrow along spend it.
///
/// One wallet may hold several escrows with the same service. A ledger scoped to one of them would
/// let a payment be spent once per escrow.
#[test]
fn a_second_escrow_cannot_spend_a_payment_the_first_one_did() {
    let Some(store) = common::try_store() else { return };
    let mut p = paired(&store, permissive());

    let (_, commitments) = service_commits(2);
    let first = request(&p, commitments);
    assert!(matches!(ask(&mut p, &first, &Provider::default()), ToService::ReleaseSigned(_)));

    // A second escrow on this wallet, paired to the same service and committed to its own deal.
    let second = second_escrow(&mut p);

    let (_, commitments) = service_commits(2);
    let mut elsewhere = request(&p, commitments);
    elsewhere.escrow_key = second;
    elsewhere.request_id = "req-other-escrow".into();
    let reply = ask(&mut p, &elsewhere, &Provider::default());
    assert!(
        refusal(&reply).contains("already been released against"),
        "one payment, one release — whichever escrow asks: {reply:?}"
    );
}

/// A retry must not be judged as if it were new spending.
///
/// Its sats are already in the running total, so counting them again would refuse a repeat of a
/// release that fitted when it was made — and a service whose reply was lost would never get the
/// answer it was owed.
#[test]
fn a_retry_is_not_charged_against_the_allowance_a_second_time() {
    let Some(store) = common::try_store() else { return };
    // Room for exactly this one release and no more.
    let mut p = paired(&store, Policy::ReleasedTotalMax { sats: PAYOUT_SATS });

    let (_, commitments) = service_commits(2);
    let req = request(&p, commitments);
    assert!(matches!(ask(&mut p, &req, &Provider::default()), ToService::ReleaseSigned(_)));

    let (_, commitments) = service_commits(2);
    let mut retry = req.clone();
    retry.commitments = commitments;
    let reply = ask(&mut p, &retry, &Provider::default());
    let approved = approval(&reply);
    assert!(
        approved.already_counted,
        "a retry of a release that fitted must still fit: {reply:?}"
    );
}


// ===============================================================================================
// The clock, and the request id
// ===============================================================================================

/// A deadline that passes WHILE the cosigner is asking a provider must still be a deadline.
///
/// The check before the work is not enough. Two calls out sit between it and the signature — the
/// ASP's and the provider's — and this refusal is the only thing holding the escrow's boundary at
/// all: both pairs sign the same key, so a signature made after the deadline takes money the owner
/// was entitled to reclaim, and nothing in Bitcoin would stop it being spent.
#[test]
fn a_deadline_that_passes_during_the_fetch_still_refuses() {
    let Some(store) = common::try_store() else { return };
    // Live for one more second, and a provider that takes two.
    let mut p = paired_for(&store, condition(), 1);
    let (_, commitments) = service_commits(2);
    let req = request(&p, commitments);

    let slow = SlowProvider {
        // Everything the policy wants to hear — so what refuses this is the clock, and only the
        // clock. A test where the evidence also failed would prove nothing.
        answer: Evidence::Json(serde_json::json!({
            "state": "COMPLETION",
            "token": REFERENCE,
        })),
        takes: std::time::Duration::from_secs(2),
    };
    let reply = block_on_ready(p.cosigner.release(&p.stream.clone(), &req, Some(Asp), &slow))
        .expect("a decision, not a fault");

    assert!(
        refusal(&reply).contains("deal is over"),
        "the deadline passed while the provider was answering: {reply:?}"
    );
    assert!(
        p.cosigner.released_references().is_empty(),
        "nothing was signed, so nothing may be written down"
    );
}

/// And a deal with room to spare is still signed, so the recheck is not simply refusing everything.
#[test]
fn a_deal_with_time_left_is_still_signed_after_a_slow_provider() {
    let Some(store) = common::try_store() else { return };
    let mut p = paired_for(&store, condition(), HOUR);
    let (_, commitments) = service_commits(2);
    let req = request(&p, commitments);

    let slow = SlowProvider {
        answer: Evidence::Json(serde_json::json!({
            "state": "COMPLETION",
            "token": REFERENCE,
        })),
        takes: std::time::Duration::from_millis(1_200),
    };
    let reply = block_on_ready(p.cosigner.release(&p.stream.clone(), &req, Some(Asp), &slow))
        .expect("a decision");
    assert!(matches!(reply, ToService::ReleaseSigned(_)), "{reply:?}");
}

/// A request id names one release. Changing the payment must not buy a second one under it.
///
/// The ledger is keyed by payment, because that is what must not be spent twice — but a repeat that
/// changed its reference would miss that lookup entirely. Then one request id would name two
/// approved releases, and a service correlating replies by it could not tell which it held.
#[test]
fn a_request_id_cannot_be_reused_by_changing_the_payment() {
    let Some(store) = common::try_store() else { return };
    let mut p = paired(&store, permissive());

    let (_, commitments) = service_commits(2);
    let first = request(&p, commitments);
    assert!(matches!(ask(&mut p, &first, &Provider::default()), ToService::ReleaseSigned(_)));

    // The same request id, a different payment, and a different release.
    let (_, commitments) = service_commits(2);
    let mut again = request(&p, commitments);
    again.payment_reference = "tx_a_different_payment".into();
    again.amount_sats = PAYOUT_SATS + 1;
    let reply = ask(&mut p, &again, &Provider::default());
    assert!(
        refusal(&reply).contains("was already answered"),
        "one request id, one release: {reply:?}"
    );

    // A genuinely new release, with a request id of its own, is still fine.
    let (_, commitments) = service_commits(2);
    let mut fresh = request(&p, commitments);
    fresh.request_id = "req-2".into();
    fresh.payment_reference = "tx_a_different_payment".into();
    assert!(matches!(ask(&mut p, &fresh, &Provider::default()), ToService::ReleaseSigned(_)));
}

/// Two services may both call their first request "1", so the id is the escrow's to scope.
#[test]
fn a_request_id_is_scoped_to_the_escrow_that_answered_it() {
    let Some(store) = common::try_store() else { return };
    let mut p = paired(&store, permissive());

    let (_, commitments) = service_commits(2);
    let first = request(&p, commitments);
    assert!(matches!(ask(&mut p, &first, &Provider::default()), ToService::ReleaseSigned(_)));

    let second = second_escrow(&mut p);
    let (_, commitments) = service_commits(2);
    let mut elsewhere = request(&p, commitments);
    elsewhere.escrow_key = second;
    elsewhere.payment_reference = "tx_another_payment".into();
    // Same request id as the first escrow's — and that is not a collision, because a request id
    // belongs to the conversation an escrow has with its service.
    assert!(
        matches!(ask(&mut p, &elsewhere, &Provider::default()), ToService::ReleaseSigned(_)),
        "a request id is the service's key for one escrow, not a wallet-wide name"
    );
}
