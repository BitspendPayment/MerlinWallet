//! Onboarding: the DKG ceremony that mints this cosigner's key.
//!
//! `threshold::dkg::*` called directly on typed round state, converting to and from JSON only at
//! the wire boundary (proto `map<string,string>` of id_hex → pkg_json).
//!
//! Two exchanges, not three. `DKGStep1/2/3` were three unary calls because each had to be a
//! request; step 2 did nothing a caller needed — it recomputed the cosigner's round 2 and returned
//! the round-1 packages step 1 had already returned. On a stream the cosigner does that itself,
//! leaving what the ceremony actually is: the wallet's round 1 in and everybody's out, then its
//! round 2 in and ours out with the key.
//!
//! The session is a local on the stream that drives it. It used to live in an `OnboardingManager`'s
//! map behind a mutex, with a TTL and an eviction sweep, because the ceremony spanned three
//! separate requests and the key material had to survive between them. Dropped with the stream now,
//! so an abandoned ceremony leaves nothing for a sweep to find.
//!
//! No `auth_check`/`timestamp_check` here, deliberately: the user's owner key only exists once
//! onboarding completes, so there is no shared secret to verify against during the ceremony.
//! Integrity comes from FROST itself, and from the ceremony living on one stream.

use std::collections::{BTreeMap, BTreeSet, HashMap};

use rand::rngs::OsRng;
use rand::Rng;
use crate::grpc::Status;

use threshold::dkg::{
    self, Round1Package, Round1SecretPackage, Round2Package, Round2SecretPackage,
};
use threshold::identifier::Identifier;
use threshold::random;
use threshold::scalar::{scalar_from_bytes, scalar_to_bytes};

use crate::handlers::parsers;
use crate::store::Store;
use crate::wallet_proto::{DkgStep1Request, DkgStep1Response, DkgStep3Request, DkgStep3Response};

/// Freshly-minted DKG key material, captured when round 3 finalizes so the caller can install it
/// straight from memory. The host persists only the public projection, so there is no plaintext to
/// read back from `policies`.
pub struct SeedMaterial {
    pub group_key: String,
    pub key_package_json: String,
    pub public_key_package_json: String,
    pub user_signing_identifier_hex: Option<String>,
    pub server_dkg_secret_hex: Option<String>,
}

pub struct OnboardingSession {
    pub user_id_hex: String,
    pub rounds: CeremonyRounds,
    /// Server's Onboarding secret (hex 32-byte scalar), persisted to the policy at finalize.
    pub server_internal_secret_hex: String,
    /// Set when round 3 finalizes: the key material to install.
    pub seed_material: Option<SeedMaterial>,
}

impl OnboardingSession {
    pub fn new(user_id_hex: String) -> Self {
        Self {
            user_id_hex,
            rounds: CeremonyRounds::default(),
            server_internal_secret_hex: String::new(),
            seed_material: None,
        }
    }
}

/// `server_id` is the cosigner's own FROST identifier — the key its round1 package lives under.
#[derive(Default)]
pub struct CeremonyRounds {
    pub round1_packages: BTreeMap<Identifier, Round1Package>,
    /// Round2 packages addressed TO the cosigner, keyed by sender id.
    pub round2_received: BTreeMap<Identifier, Round2Package>,
    /// The cosigner's own round2 packages FOR each recipient.
    pub round2_local: BTreeMap<Identifier, Round2Package>,
    /// All round2 packages for relay: sender id → { recipient id → package }.
    pub round2_relay: BTreeMap<Identifier, BTreeMap<Identifier, Round2Package>>,
    /// Passive receivers (no round1 package). Empty in 2-of-2.
    pub receiver_identifiers: BTreeSet<Identifier>,
    pub server_id: Option<Identifier>,
    pub round1_secret: Option<Round1SecretPackage>,
    pub round2_secret: Option<Round2SecretPackage>,
}

impl CeremonyRounds {
    pub fn total_participants(&self) -> usize {
        self.round1_packages.len() + self.receiver_identifiers.len()
    }

    pub fn relay_sender_count(&self) -> usize {
        self.round2_relay.len()
    }

    pub fn is_round2_local_empty(&self) -> bool {
        self.round2_local.is_empty()
    }

    pub fn receiver_ids(&self) -> Vec<Identifier> {
        self.receiver_identifiers.iter().cloned().collect()
    }

    /// All round1 packages except the one keyed by `exclude` (the cosigner's own,
    /// when feeding `dkg_part2`/`dkg_part3`).
    pub fn round1_packages_excluding(
        &self,
        exclude: &Identifier,
    ) -> BTreeMap<Identifier, Round1Package> {
        self.round1_packages
            .iter()
            .filter(|(id, _)| *id != exclude)
            .map(|(id, pkg)| (id.clone(), pkg.clone()))
            .collect()
    }

    pub fn insert_relay_packages(
        &mut self,
        sender: Identifier,
        pkgs: BTreeMap<Identifier, Round2Package>,
    ) {
        self.round2_relay.insert(sender, pkgs);
    }

    /// Fold the cosigner's own round2 packages into the relay under its id.
    pub fn insert_relay_from_local(&mut self, server: Identifier) {
        self.round2_relay.insert(server, self.round2_local.clone());
    }

    // --- wire (egress) serializers: typed → proto `map<string,string>` ---

    /// All round1 packages as `{id_hex: pkg_json}`.
    pub fn round1_packages_wire(&self) -> HashMap<String, String> {
        self.round1_packages
            .iter()
            .map(|(id, pkg)| (hex::encode(id.serialize()), pkg.to_json()))
            .collect()
    }

    /// Round2 packages destined for `recipient`, as `{sender_id_hex: pkg_json}`.
    pub fn relay_packages_for(&self, recipient: &Identifier) -> HashMap<String, String> {
        let mut out = HashMap::new();
        for (sender, by_recipient) in &self.round2_relay {
            if let Some(pkg) = by_recipient.get(recipient) {
                out.insert(hex::encode(sender.serialize()), pkg.to_json());
            }
        }
        out
    }
}

// --- wire (ingress) + hex helpers ---

fn hex_decode_32(s: &str) -> Result<[u8; 32], Status> {
    let bytes = hex::decode(s).map_err(|e| Status::internal(format!("bad hex: {e}")))?;
    let out: [u8; 32] = bytes
        .try_into()
        .map_err(|_| Status::internal("expected 32 bytes"))?;
    Ok(out)
}

pub fn parse_identifier_hex(hex: &str) -> Result<Identifier, Status> {
    let bytes = hex_decode_32(hex)?;
    Identifier::deserialize(&bytes).map_err(|e| Status::internal(format!("bad identifier: {e}")))
}

pub fn parse_scalar_hex(hex: &str) -> Result<k256::Scalar, Status> {
    let bytes = hex_decode_32(hex)?;
    scalar_from_bytes(&bytes).map_err(|e| Status::internal(format!("bad scalar: {e}")))
}

pub fn round1_pkg_from_json(json: &str) -> Result<Round1Package, Status> {
    Round1Package::from_json(json).map_err(|e| Status::internal(format!("bad R1 pkg: {e}")))
}

/// Parse a proto `map<string,string>` of `recipient_id_hex → round2 pkg_json` into a
/// typed map. Used at step3 ingress.
pub fn round2_pkgs_from_wire(
    wire: &HashMap<String, String>,
) -> Result<BTreeMap<Identifier, Round2Package>, Status> {
    let mut out = BTreeMap::new();
    for (id_hex, pkg_json) in wire {
        let id = parse_identifier_hex(id_hex)?;
        let pkg = Round2Package::from_json(pkg_json)
            .map_err(|e| Status::internal(format!("bad R2 pkg: {e}")))?;
        out.insert(id, pkg);
    }
    Ok(out)
}

// Real 2-of-2 {wallet, cosigner}: both parties deal, both hold a share, no
// recovery/hardware third party. `receiver_identifiers` stays empty.
const TOTAL_PARTICIPANTS: usize = 2;
const THRESHOLD_COUNT: usize = 2;

fn req_identifier(bytes: &[u8]) -> Result<Identifier, Status> {
    parse_identifier_hex(&hex::encode(bytes))
}

#[tracing::instrument(skip_all, name = "dkg::open", fields(user_id = %parsers::user_id_hex(&req.user_id)))]
pub fn dkg_open(
    sess: &mut OnboardingSession,
    req: DkgStep1Request,
) -> Result<DkgStep1Response, Status> {
    let user_id_hex = parsers::user_id_hex(&req.user_id);
    tracing::info!(
        "[{user_id_hex}] DKG open from {}",
        hex::encode(&req.identifier)
    );

    // Register this dealer's round1 package (or a passive receiver).
    let id = match req_identifier(&req.identifier) {
        Ok(id) => id,
        Err(e) => {
            return Err(e);
            }
    };
    if req.round1_package.is_empty() {
        tracing::info!("[{user_id_hex}] DKG: registered passive receiver");
        sess.rounds.receiver_identifiers.insert(id);
    } else {
        match round1_pkg_from_json(&req.round1_package) {
            Ok(pkg) => {
                sess.rounds.round1_packages.insert(id, pkg);
            }
            Err(e) => {
                return Err(e);
                }
        }
    }

    // Server self-init (first caller only): deal our own round1 package.
    if sess.rounds.round1_secret.is_none() {
        tracing::info!("[{user_id_hex}] Server: generating onboarding secrets");
        let secret_hex = hex::encode(scalar_to_bytes(&random::mod_n_random(&mut OsRng)));
        let mut rng = OsRng;
        let mut seed = [0u8; 32];
        rng.fill(&mut seed);
        let coefficients = random::generate_coefficients_seeded(THRESHOLD_COUNT - 1, &seed);

        let dealt = parse_scalar_hex(&secret_hex).and_then(|secret| {
            dkg::dkg_part1(
                TOTAL_PARTICIPANTS,
                THRESHOLD_COUNT,
                &secret,
                &coefficients,
                &mut rng,
            )
            .map_err(|e| Status::internal(format!("dkg_part1: {e}")))
        });
        let (r1_secret, r1_pub) = match dealt {
            Ok(v) => v,
            Err(e) => {
                return Err(e);
                }
        };
        let server_id = r1_secret.identifier.clone();
        sess.rounds.server_id = Some(server_id.clone());
        sess.server_internal_secret_hex = secret_hex;
        sess.rounds.round1_packages.insert(server_id, r1_pub);
        sess.rounds.round1_secret = Some(r1_secret);
    }

    if sess.rounds.total_participants() < TOTAL_PARTICIPANTS {
        return Err(Status::failed_precondition(
            "round 1 is short a participant: 2-of-2 completes on the first caller",
        ));
    }
    Ok(DkgStep1Response {
        round1_packages: sess.rounds.round1_packages_wire(),
    })
}

/// Compute the cosigner's own round-2 packages from everybody's round 1.
///
/// This was `DKGStep2`, a whole round of its own — and it returned the round-1 packages the
/// previous call had already returned. The round existed to give the unary API somewhere to
/// trigger this computation from; in a session the cosigner simply does it when it needs it.
fn compute_local_round2(sess: &mut OnboardingSession, user_id_hex: &str) -> Result<(), Status> {
    if sess.rounds.round1_secret.is_none() {
        return Err(Status::internal("no onboarding session"));
    }

    if sess.rounds.is_round2_local_empty() {
        tracing::info!("[{user_id_hex}] DKG: computing round 2");
        let Some(server_id) = sess.rounds.server_id.clone() else {
            return Err(Status::internal("server ID not initialized"));
            };
        let round1_pkgs = sess.rounds.round1_packages_excluding(&server_id);
        let receiver_ids = sess.rounds.receiver_ids();
        let Some(round1_secret) = sess.rounds.round1_secret.take() else {
            return Err(Status::internal("round1 secret missing"));
            };
        let (r2_secret, r2_pkgs) = match dkg::dkg_part2(&round1_secret, &round1_pkgs, &receiver_ids)
        {
            Ok(v) => v,
            Err(e) => {
                return Err(Status::internal(format!("dkg_part2: {e}")));
                }
        };
        sess.rounds.round2_secret = Some(r2_secret);
        sess.rounds.round2_local = r2_pkgs;
    }
    Ok(())
}

#[tracing::instrument(skip_all, name = "dkg::finish", fields(user_id = %parsers::user_id_hex(&req.user_id)))]
pub fn dkg_finish(
    sess: &mut OnboardingSession,
    store: &Store,
    req: DkgStep3Request,
) -> Result<DkgStep3Response, Status> {
    let user_id_hex = parsers::user_id_hex(&req.user_id);
    compute_local_round2(sess, &user_id_hex)?;
    let sender_id = match req_identifier(&req.identifier) {
        Ok(id) => id,
        Err(e) => {
            return Err(e);
            }
    };
    tracing::info!(
        "[{user_id_hex}] DKG finish from {}",
        hex::encode(&req.identifier)
    );

    // Register the sender's round2 packages: keep the one addressed to us, relay all.
    let Some(server_id) = sess.rounds.server_id.clone() else {
        return Err(Status::internal("server ID not initialized"));
        };
    let pkgs = match round2_pkgs_from_wire(&req.round2_packages_for_others) {
        Ok(p) => p,
        Err(e) => {
            return Err(e);
            }
    };
    if let Some(for_server) = pkgs.get(&server_id) {
        sess.rounds
            .round2_received
            .insert(sender_id.clone(), for_server.clone());
    }
    sess.rounds.insert_relay_packages(sender_id.clone(), pkgs);

    if sess.rounds.relay_sender_count() < TOTAL_PARTICIPANTS - 1 {
        return Err(Status::failed_precondition(
            "round 3 is short a participant: 2-of-2 completes on the first caller",
        ));
    }

    sess.rounds.insert_relay_from_local(server_id.clone());

    // Finalize: derive the group key V, persist the policy + the member→group index.
    let finalized = (|| -> Result<(), Status> {
        tracing::info!("[{user_id_hex}] DKG: computing KeyPackage");

        // 2-of-2 {wallet, cosigner}: the wallet is the only non-server dealer.
        let wallet_id = sess
            .rounds
            .round1_packages
            .keys()
            .find(|id| **id != server_id)
            .cloned()
            .ok_or_else(|| Status::internal("2-of-2 Onboarding: wallet dealer not found"))?;
        let wallet_identifier_hex = hex::encode(wallet_id.serialize());

        let round1_pkgs = sess.rounds.round1_packages_excluding(&server_id);
        let receiver_ids = sess.rounds.receiver_ids();
        let r2_secret = sess
            .rounds
            .round2_secret
            .take()
            .ok_or_else(|| Status::internal("round2 secret missing"))?;

        // dkg_part3 ignores its first arg per the threshold contract; pass a stub.
        let dummy_r1 = Round1SecretPackage {
            identifier: r2_secret.identifier.clone(),
            coefficients: Vec::new(),
            commitment: r2_secret.commitment.clone(),
            min_signers: r2_secret.min_signers,
            max_signers: r2_secret.max_signers,
        };

        let (kp, pkp) = dkg::dkg_part3(
            &dummy_r1,
            &r2_secret,
            &round1_pkgs,
            &sess.rounds.round2_received,
            &receiver_ids,
        )
        .map_err(|e| Status::internal(format!("dkg_part3: {e}")))?;

        let kp_json = kp.to_json();
        let pkp_json = pkp.to_json();

        // `policy_user_id` = the wallet's VERIFYING SHARE — the id the client uses for ALL
        // post-DKG requests (`_userId = compressed(verifyingShare)`). The DKG-time `user_id_hex`
        // is a temp id that's never used again, so the routing index keys on THIS, not that.
        let policy_user_id = parsers::extract_verifying_share(&pkp_json, &wallet_identifier_hex)?;
        let group_key = parsers::extract_verifying_key(&pkp_json)?;

        let user_signing_identifier_hex = Some(wallet_identifier_hex);
        let server_dkg_secret_hex = Some(sess.server_internal_secret_hex.clone());

        sess.seed_material = Some(SeedMaterial {
            group_key: group_key.clone(),
            key_package_json: kp_json,
            public_key_package_json: pkp_json,
            user_signing_identifier_hex,
            server_dkg_secret_hex,
        });

        store
            
            .put("policy_owner_idx", &policy_user_id, &group_key)
            .map_err(|e| {
                tracing::error!("persist policy_owner_idx/{policy_user_id} failed: {e}");
                Status::internal(format!("persist policy_owner_idx failed: {e}"))
            })?;
        tracing::info!("[{user_id_hex}] Onboarding complete; cosigner_id (group key)={group_key}");
        Ok(())
    })();
    finalized?;

    Ok(DkgStep3Response {
        round2_packages_for_me: sess.rounds.relay_packages_for(&sender_id),
    })
}
