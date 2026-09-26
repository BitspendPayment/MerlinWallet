//! A whole escrow, paired and committed, standing in front of a mock provider.
//!
//! Everything here is real but the network: a real reshare-shaped 2-of-2, a real service pairing,
//! the real sealed policy from `card_escrow::policy`, and the real `Cosigner::release` path. The
//! provider is the deterministic mock, reached through a fetcher that calls it directly rather than
//! over HTTP — what is being proved is the decision, and a socket in the middle would only make the
//! test slower and flakier.

#![allow(dead_code)]

use std::sync::Arc;

use ark::client::types::ArkInfo;
use card_escrow::policy::Terms;
use card_escrow::provider::{MockProvider, MockTransaction, SimulateAuthorization, SimulateClearing};
use cosigner::asp::AspApi;
use cosigner::escrow_session::EscrowSession;
use cosigner::evidence::{Evidence, EvidenceRequest, FetchEvidence};
use cosigner::handlers::helpers::block_on_ready;
use cosigner::handlers::release::{ProposedInput, ReleaseRequest, WireCommitment};
use cosigner::service_stream::{service_stream_id, ToService};
use cosigner::types::{EscrowRecord, ServicePairing};
use rand::rngs::OsRng;
use std::collections::BTreeMap;

use threshold::dkg::{self, Round1Package, Round2Package};
use threshold::identifier::Identifier;
use threshold::keys::{KeyPackage, PublicKeyPackage};
use threshold::{point, random, scalar};

const HOUR: i64 = 3_600;
const VTXO_SATS: u64 = 100_000;

/// The mock provider, as the cosigner reaches it: a direct call, with the same request the HTTP
/// path would have made.
pub struct DirectProvider(pub Arc<MockProvider>);

impl FetchEvidence for DirectProvider {
    async fn fetch(&self, request: &EvidenceRequest) -> Evidence {
        // The path the policy built, with the reference already confined to one segment by
        // `safe_reference`. Reading the token back out of it is exactly what the server does.
        let token = request.path.rsplit('/').next().unwrap_or_default();
        match self.0.transaction(token) {
            Some(record) => match serde_json::to_value(&record) {
                Ok(body) => Evidence::Json(body),
                Err(e) => Evidence::Unusable(format!("the provider's answer was not JSON: {e}")),
            },
            // A 404 — which is what delayed availability looks like from outside.
            None => Evidence::Unusable("the provider answered 404 Not Found".into()),
        }
    }
}

/// An ASP that answers the one question a release asks it.
pub struct Asp;

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

pub fn ark_info() -> ArkInfo {
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

/// Everything standing up: a wallet, an escrow, a paired service, a committed deal and a provider.
pub struct World {
    pub cosigner: cosigner::Cosigner,
    pub provider: Arc<MockProvider>,
    pub terms: Terms,
    pub escrow_key: String,
    pub stream: String,
    /// An Ark address that is not the service's, for showing a payout being refused.
    pub somewhere_else: String,
    service_kp: KeyPackage,
    pairing_pkp: PublicKeyPackage,
    store: Arc<cosigner::store::Store>,
    asked: std::cell::Cell<u32>,
}

impl World {
    pub fn new() -> Option<Self> {
        Self::with_allowance(80_000)
    }

    /// A world whose deal runs out in one second, for the cases that need it to.
    pub fn briefly() -> Option<Self> {
        Self::build(80_000, 1)
    }

    pub fn with_allowance(allowance_sats: u64) -> Option<Self> {
        Self::build(allowance_sats, HOUR)
    }

    fn build(allowance_sats: u64, lasts: i64) -> Option<Self> {
        let store = Arc::new(cosigner::store::Store::open(":memory:", 1_800).ok()?);
        let info = ark_info();
        let network = ark::client::parse_network(&info.network).ok()?;

        // The service's own address, and somewhere that is not it.
        let service_address = ark::client::ark_address(
            &"44".repeat(32),
            &info.signer_pubkey,
            info.unilateral_exit_delay as u32,
            network,
        )
        .ok()?;
        let somewhere_else = ark::client::ark_address(
            "f9308a019258c31049344f85f89d5229b531c845836f99b08601f113bce036f9",
            &info.signer_pubkey,
            info.unilateral_exit_delay as u32,
            network,
        )
        .ok()?;
        let service_script = ark::client::ark_address_script_pubkey_hex(&service_address).ok()?;

        let terms = Terms {
            allowance_sats,
            ..Terms::example(service_address, "https://provider.example".into())
        };
        let policy = card_escrow::policy::policy(
            &terms,
            &service_script,
            terms.sats_for(2_000).expect("$20 converts"),
        );

        // A wallet, an escrow-shaped 2-of-2, and a service paired into it.
        let (kps, pkp) = dkg_2of2();
        let (wallet_kp, cosigner_kp) = (kps[0].clone(), kps[1].clone());
        let escrow_key = hex::encode(pkp.verifying_key.serialize());
        let service_id = Identifier::derive(b"merlin-e2e-escrow-service").ok()?;
        let dealt = threshold::dkg::refresh_to_ids(
            &wallet_kp,
            &[wallet_kp.identifier.clone(), cosigner_kp.identifier.clone()],
            &[service_id.clone(), cosigner_kp.identifier.clone()],
            2,
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
        .ok()?;

        let b_at_service =
            threshold::scalar::scalar_from_bytes(&material.service_half.clone().try_into().ok()?)
                .ok()?;
        let share = a_at_service + b_at_service;
        let pairing_pkp = PublicKeyPackage::from_json(&material.public_key_package_json).ok()?;
        let service_kp = KeyPackage {
            identifier: service_id,
            secret_share: share,
            verifying_share: point::base_mul(&share),
            verifying_key: pairing_pkp.verifying_key.clone(),
            min_signers: 2,
        };

        let group_key = escrow_key.clone();
        let mut cosigner =
            cosigner::Cosigner::open(store.clone(), group_key.clone()).ok()?;
        seed_policy(&mut cosigner, &group_key, &cosigner_kp, &wallet_kp, &pkp);

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
                    service_confirmed: true,
                    wallet_confirmed: true,
                }),
                session: None,
                reclaim_opened_at: None,
            })
            .ok()?;
        cosigner
            .open_escrow_session(
                &escrow_key,
                EscrowSession::open(policy, now, now + lasts).ok()?,
                now,
            )
            .ok()?;

        Some(Self {
            stream: service_stream_id(&material.service_identifier_hex),
            cosigner,
            provider: MockProvider::new(),
            terms,
            escrow_key,
            somewhere_else,
            service_kp,
            pairing_pkp,
            store,
            asked: std::cell::Cell::new(0),
        })
    }

    // --- the card ------------------------------------------------------------------------------

    pub fn authorize(&self, cents: u64) -> MockTransaction {
        self.authorize_on_card(cents, &self.terms.card_token.clone())
    }

    pub fn authorize_on_card(&self, cents: u64, card: &str) -> MockTransaction {
        self.provider.authorize(SimulateAuthorization {
            amount: cents as f64 / 100.0,
            currency_code: self.terms.currency_code.clone(),
            card_token: card.into(),
            user_token: "user_alice".into(),
            merchant_name: "Example Coffee".into(),
            decline: false,
        })
    }

    pub fn authorize_in(&self, cents: u64, currency: &str) -> MockTransaction {
        self.provider.authorize(SimulateAuthorization {
            amount: cents as f64 / 100.0,
            currency_code: currency.into(),
            card_token: self.terms.card_token.clone(),
            user_token: "user_alice".into(),
            merchant_name: "Example Coffee".into(),
            decline: false,
        })
    }

    pub fn clear(&self, authorization: &str, cents: Option<u64>) -> MockTransaction {
        self.provider
            .clear(SimulateClearing {
                authorization_token: authorization.into(),
                amount: cents.map(|c| c as f64 / 100.0),
            })
            .expect("it clears")
    }

    // --- the ask -------------------------------------------------------------------------------

    /// A well-formed reimbursement request for one payment.
    pub fn request(&self, reference: &str, sats: u64) -> ReleaseRequest {
        self.asked.set(self.asked.get() + 1);
        ReleaseRequest {
            request_id: format!("reimb-{:04}", self.asked.get()),
            escrow_key: self.escrow_key.clone(),
            to_ark_address: self.terms.service_ark_address.clone(),
            amount_sats: sats,
            inputs: vec![ProposedInput {
                txid: "11".repeat(32),
                vout: 0,
                amount_sats: VTXO_SATS,
                exit_delay: 512,
            }],
            payment_reference: reference.into(),
            commitments: commitments(2),
        }
    }

    pub fn ask_about(&mut self, reference: &str, sats: u64) -> ToService {
        let request = self.request(reference, sats);
        self.ask(request)
    }

    pub fn ask(&mut self, request: ReleaseRequest) -> ToService {
        let provider = DirectProvider(Arc::clone(&self.provider));
        self.ask_with(request, &provider)
    }

    pub fn ask_with<F: FetchEvidence>(&mut self, request: ReleaseRequest, fetcher: &F) -> ToService {
        let stream = self.stream.clone();
        block_on_ready(self.cosigner.release(&stream, &request, Some(Asp), fetcher))
            .expect("a decision, not a fault")
    }

    // --- the deal ------------------------------------------------------------------------------

    /// Let the deal run out.
    ///
    /// Waiting rather than ending it, because a deal has no ending but its deadline — there is no
    /// close, for the owner or anybody. See `cosigner::escrow_session`.
    ///
    /// A real wait, because a lapse writes nothing: the seal is identical either side of the
    /// deadline, and the only honest way to test that is to let the clock move.
    pub fn lapse(&mut self) {
        let key = self.escrow_key.clone();
        let deadline = self
            .cosigner
            .escrow(&key)
            .and_then(|e| e.session.as_ref())
            .map(|s| s.deadline)
            .expect("a deal to wait out");
        let remaining = deadline - now();
        if remaining >= 0 {
            std::thread::sleep(std::time::Duration::from_millis(
                (remaining as u64 + 1) * 1_000,
            ));
        }
    }

    /// Let the deal run out and strike a new one over the same escrow.
    pub fn reopen(&mut self) {
        self.lapse();
        let key = self.escrow_key.clone();
        let policy = self.policy();
        let now = now();
        self.cosigner
            .open_escrow_session(
                &key,
                EscrowSession::open(policy, now, now + HOUR).expect("a new deal"),
                now,
            )
            .expect("a new deal can be struck once the last is over");
    }

    /// A second escrow on this wallet, paired to the same service and committed to its own deal.
    pub fn second_escrow(&mut self) -> String {
        let first = self.cosigner.escrow(&self.escrow_key).expect("the first").clone();
        let key = "02".to_string() + &"be".repeat(32);
        let policy = self.policy();
        let now = now();
        self.cosigner
            .install_escrow(EscrowRecord {
                escrow_key: key.clone(),
                context_hex: "99".repeat(16),
                session: None,
                ..first
            })
            .expect("a second escrow");
        self.cosigner
            .open_escrow_session(
                &key,
                EscrowSession::open(policy, now, now + HOUR).expect("a deal"),
                now,
            )
            .expect("commit it");
        key
    }

    fn policy(&self) -> cosigner::policy::Policy {
        let script =
            ark::client::ark_address_script_pubkey_hex(&self.terms.service_ark_address).unwrap();
        card_escrow::policy::policy(
            &self.terms,
            &script,
            self.terms.sats_for(2_000).unwrap(),
        )
    }

    /// Whether this wallet has recorded any release at all.
    pub fn nothing_released(&self) -> bool {
        self.cosigner.released_references().is_empty()
    }
}

/// The service's commitments for one ask. Fresh every time — a nonce is used once.
pub fn commitments(n: usize) -> Vec<WireCommitment> {
    let mut out = Vec::with_capacity(n);
    for _ in 0..n {
        let nonce = threshold::nonce::new_nonce(
            &mut OsRng,
            &threshold::random::mod_n_random(&mut OsRng),
        );
        out.push(WireCommitment {
            hiding: hex::encode(point::serialize_compressed(&nonce.commitments.hiding)),
            binding: hex::encode(point::serialize_compressed(&nonce.commitments.binding)),
        });
    }
    out
}

pub fn now() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs() as i64
}

/// A host-side 2-of-2, even-Y normalized. Index 0 is the wallet, 1 the cosigner.
///
/// The same ceremony `cosigner/tests/common` runs, so an escrow here is shaped exactly as a
/// reshare leaves one.
pub fn dkg_2of2() -> (Vec<KeyPackage>, PublicKeyPackage) {
    let mut rng = OsRng;
    let (min, max) = (2usize, 2usize);

    let mut r1_secrets = Vec::new();
    let mut r1_packages: BTreeMap<Identifier, Round1Package> = BTreeMap::new();
    for _ in 0..max {
        let secret = random::mod_n_random(&mut rng);
        let coefficients: Vec<_> = (0..min - 1)
            .map(|_| random::mod_n_random(&mut rng))
            .collect();
        let (secret_pkg, pub_pkg) =
            dkg::dkg_part1(max, min, &secret, &coefficients, &mut rng).expect("dkg_part1");
        r1_packages.insert(secret_pkg.identifier.clone(), pub_pkg);
        r1_secrets.push(secret_pkg);
    }

    let mut r2_secrets = Vec::new();
    let mut all_r2: Vec<BTreeMap<Identifier, Round2Package>> = Vec::new();
    for secret_pkg in &r1_secrets {
        let others: BTreeMap<Identifier, Round1Package> = r1_packages
            .iter()
            .filter(|(id, _)| **id != secret_pkg.identifier)
            .map(|(id, p)| (id.clone(), p.clone()))
            .collect();
        let (r2_secret, r2_out) = dkg::dkg_part2(secret_pkg, &others, &[]).expect("dkg_part2");
        r2_secrets.push(r2_secret);
        all_r2.push(r2_out);
    }

    let mut key_packages = Vec::new();
    let mut pkp_out: Option<PublicKeyPackage> = None;
    for (i, r2_secret) in r2_secrets.iter().enumerate() {
        let others_r1: BTreeMap<Identifier, Round1Package> = r1_packages
            .iter()
            .filter(|(id, _)| **id != r2_secret.identifier)
            .map(|(id, p)| (id.clone(), p.clone()))
            .collect();
        let mut our_r2: BTreeMap<Identifier, Round2Package> = BTreeMap::new();
        for (j, r2_pkgs) in all_r2.iter().enumerate() {
            if j == i {
                continue;
            }
            if let Some(pkg) = r2_pkgs.get(&r2_secret.identifier) {
                our_r2.insert(r1_secrets[j].identifier.clone(), pkg.clone());
            }
        }
        let (kp, pkp) =
            dkg::dkg_part3(&r1_secrets[i], r2_secret, &others_r1, &our_r2, &[]).expect("dkg_part3");
        key_packages.push(kp.into_even_y());
        pkp_out = Some(pkp.into_even_y());
    }

    (key_packages, pkp_out.unwrap())
}

/// Open the cosigner this process serves, loading whatever its seal already holds.

fn seed_policy(
    cosigner: &mut cosigner::Cosigner,
    group_key: &str,
    kp_cosigner: &KeyPackage,
    kp_user: &KeyPackage,
    pkp: &PublicKeyPackage,
) {
    cosigner
        .install_policy(
            group_key.to_string(),
            &kp_cosigner.to_json(),
            &pkp.to_json(),
            Some(&hex::encode(kp_user.identifier.serialize())),
            Some(hex::encode([9u8; 32])),
            Some(hex::encode([7u8; 32])),
        )
        .expect("install policy");
    cosigner.seal();
}
