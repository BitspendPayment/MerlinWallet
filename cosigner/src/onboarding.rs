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

use std::collections::{BTreeMap, BTreeSet};

use rand::rngs::OsRng;
use rand::Rng;
use crate::grpc::Status;

use threshold::dkg::{
    self, Round1Package, Round1SecretPackage, Round2Package, Round2SecretPackage,
};
use threshold::identifier::Identifier;
use threshold::random;
use threshold::scalar::scalar_to_bytes;

use crate::wallet_proto::{DkgStep1Request, DkgStep1Response, DkgStep3Request, DkgStep3Response};

// Real 2-of-2 {wallet, cosigner}: both parties deal, both hold a share, no
// recovery/hardware third party. `receiver_identifiers` stays empty.
const TOTAL_PARTICIPANTS: usize = 2;
const THRESHOLD_COUNT: usize = 2;

#[derive(Default)]
pub struct OnboardingSession {
    pub round1_packages: BTreeMap<Identifier, Round1Package>,
    /// Round2 packages addressed TO the cosigner, keyed by sender id.
    pub round2_received: BTreeMap<Identifier, Round2Package>,
    /// The cosigner's own round2 packages FOR each recipient.
    pub round2_local: BTreeMap<Identifier, Round2Package>,
    /// All round2 packages for relay: sender id → { recipient id → package }.
    pub round2_relay: BTreeMap<Identifier, BTreeMap<Identifier, Round2Package>>,
    /// Passive receivers (no round1 package). Empty in 2-of-2.
    pub receiver_identifiers: BTreeSet<Identifier>,
    /// The cosigner's own FROST identifier — the key its round1 package lives under.
    pub server_id: Option<Identifier>,
    pub round1_secret: Option<Round1SecretPackage>,
    pub round2_secret: Option<Round2SecretPackage>,
    // Set when round 3 finalizes: the key material, for the caller to install straight from
    // memory.
    /// The group key, hex.
    pub group_key: Option<String>,
    /// This cosigner's key package, JSON.
    pub key_package_json: Option<String>,
    /// The group's public key package, JSON.
    pub public_key_package_json: Option<String>,
    /// The wallet's FROST identifier, hex.
    pub user_signing_identifier_hex: Option<String>,
    /// `f_cosigner(wallet_identifier)`: the share this cosigner dealt to the wallet during the
    /// ceremony, kept so the wallet can be rebuilt on another device.
    ///
    /// A wallet's share is the sum of both dealers' polynomials at its identifier. The wallet
    /// re-derives its own half from its passkey, and this is the half it cannot: the polynomial it
    /// came from is destroyed when round two ends. Worth nothing alone — without the passkey's
    /// half it is one term of a sum — and it never leaves the tenant that owns it.
    pub wallet_dealt_share_hex: Option<String>,
}

impl OnboardingSession {
    pub fn new() -> Self {
        Self::default()
    }

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

    #[tracing::instrument(skip_all, name = "dkg::open")]
    pub fn begin(&mut self, req: DkgStep1Request) -> Result<DkgStep1Response, Status> {
        tracing::info!(
            "DKG open from {}",
            hex::encode(&req.identifier)
        );

        // Register this dealer's round1 package (or a passive receiver).
        let id = Identifier::try_from(req.identifier.as_slice())
            .map_err(|e| Status::internal(format!("bad identifier: {e}")))?;
        if req.round1_package.is_empty() {
            tracing::info!("DKG: registered passive receiver");
            self.receiver_identifiers.insert(id);
        } else {
            let pkg = Round1Package::from_json(&req.round1_package)
                .map_err(|e| Status::internal(format!("bad R1 pkg: {e}")))?;
            self.round1_packages.insert(id, pkg);
        }

        // Server self-init (first caller only): deal our own round1 package.
        if self.round1_secret.is_none() {
            tracing::info!("Server: generating onboarding secrets");
            let secret = random::mod_n_random(&mut OsRng);
            let mut rng = OsRng;
            let mut seed = [0u8; 32];
            rng.fill(&mut seed);
            let coefficients = random::generate_coefficients_seeded(THRESHOLD_COUNT - 1, &seed);

            let (r1_secret, r1_pub) = dkg::dkg_part1(
                TOTAL_PARTICIPANTS,
                THRESHOLD_COUNT,
                &secret,
                &coefficients,
                &mut rng,
            )
            .map_err(|e| Status::internal(format!("dkg_part1: {e}")))?;
            let server_id = r1_secret.identifier.clone();
            self.server_id = Some(server_id.clone());
            self.round1_packages.insert(server_id, r1_pub);
            self.round1_secret = Some(r1_secret);
        }

        if self.total_participants() < TOTAL_PARTICIPANTS {
            return Err(Status::failed_precondition(
                "round 1 is short a participant: 2-of-2 completes on the first caller",
            ));
        }
        // Every round1 package, as `{id_hex: pkg_json}`.
        Ok(DkgStep1Response {
            round1_packages: self
                .round1_packages
                .iter()
                .map(|(id, pkg)| (hex::encode(id.serialize()), pkg.to_json()))
                .collect(),
        })
    }

    #[tracing::instrument(skip_all, name = "dkg::finish")]
    pub fn finalise(&mut self, req: DkgStep3Request) -> Result<DkgStep3Response, Status> {
        // The cosigner's own round-2 packages, from everybody's round 1. This was `DKGStep2`, a
        // whole round of its own — and it returned the round-1 packages the previous call had
        // already returned. The round existed to give the unary API somewhere to trigger this
        // computation from; in a session the cosigner simply does it when it needs it.
        if self.round1_secret.is_none() {
            return Err(Status::internal("no onboarding session"));
        }

        if self.is_round2_local_empty() {
            tracing::info!("DKG: computing round 2");
            let Some(server_id) = self.server_id.clone() else {
                return Err(Status::internal("server ID not initialized"));
                };
            let round1_pkgs: BTreeMap<Identifier, Round1Package> = self
                .round1_packages
                .iter()
                .filter(|(id, _)| **id != server_id)
                .map(|(id, pkg)| (id.clone(), pkg.clone()))
                .collect();
            let receiver_ids = self.receiver_ids();
            let Some(round1_secret) = self.round1_secret.take() else {
                return Err(Status::internal("round1 secret missing"));
                };
            let (r2_secret, r2_pkgs) = dkg::dkg_part2(&round1_secret, &round1_pkgs, &receiver_ids)
                .map_err(|e| Status::internal(format!("dkg_part2: {e}")))?;
            self.round2_secret = Some(r2_secret);
            self.round2_local = r2_pkgs;
        }
        let sender_id = Identifier::try_from(req.identifier.as_slice())
            .map_err(|e| Status::internal(format!("bad identifier: {e}")))?;
        tracing::info!(
            "DKG finish from {}",
            hex::encode(&req.identifier)
        );

        // Register the sender's round2 packages: keep the one addressed to us, relay all.
        let Some(server_id) = self.server_id.clone() else {
            return Err(Status::internal("server ID not initialized"));
            };
        // Off the wire, `{recipient_id_hex: pkg_json}`.
        let mut pkgs = BTreeMap::new();
        for (id_hex, pkg_json) in &req.round2_packages_for_others {
            let id = id_hex
                .parse::<Identifier>()
                .map_err(|e| Status::internal(format!("bad identifier: {e}")))?;
            let pkg = Round2Package::from_json(pkg_json)
                .map_err(|e| Status::internal(format!("bad R2 pkg: {e}")))?;
            pkgs.insert(id, pkg);
        }
        if let Some(for_server) = pkgs.get(&server_id) {
            self.round2_received.insert(sender_id.clone(), for_server.clone());
        }
        self.round2_relay.insert(sender_id.clone(), pkgs);

        if self.relay_sender_count() < TOTAL_PARTICIPANTS - 1 {
            return Err(Status::failed_precondition(
                "round 3 is short a participant: 2-of-2 completes on the first caller",
            ));
        }

        // The cosigner's own round2 packages join the relay under its id.
        self.round2_relay.insert(server_id.clone(), self.round2_local.clone());

        // Finalize: derive the group key V, persist the policy + the member→group index.
        let finalized = (|| -> Result<(), Status> {
            tracing::info!("DKG: computing KeyPackage");

            // 2-of-2 {wallet, cosigner}: the wallet is the only non-server dealer.
            let wallet_id = self
                .round1_packages
                .keys()
                .find(|id| **id != server_id)
                .cloned()
                .ok_or_else(|| Status::internal("2-of-2 Onboarding: wallet dealer not found"))?;
            let wallet_identifier_hex = hex::encode(wallet_id.serialize());

            let round1_pkgs: BTreeMap<Identifier, Round1Package> = self
                .round1_packages
                .iter()
                .filter(|(id, _)| **id != server_id)
                .map(|(id, pkg)| (id.clone(), pkg.clone()))
                .collect();
            let receiver_ids = self.receiver_ids();
            let r2_secret = self
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
                &self.round2_received,
                &receiver_ids,
            )
            .map_err(|e| Status::internal(format!("dkg_part3: {e}")))?;

            let kp_json = kp.to_json();
            let pkp_json = pkp.to_json();

            let group_key = crate::serde::extract_verifying_key(&pkp_json)?;

            // The one thing from this ceremony the wallet could never reconstruct for itself.
            self.wallet_dealt_share_hex = self
                .round2_local
                .get(&wallet_id)
                .map(|pkg| hex::encode(scalar_to_bytes(&pkg.secret_share)));
            self.user_signing_identifier_hex = Some(wallet_identifier_hex);
            self.key_package_json = Some(kp_json);
            self.public_key_package_json = Some(pkp_json);
            self.group_key = Some(group_key.clone());

            tracing::info!("Onboarding complete; cosigner_id (group key)={group_key}");
            Ok(())
        })();
        finalized?;

        Ok(DkgStep3Response {
            // The round2 packages addressed to the sender, as `{dealer_id_hex: pkg_json}`.
            round2_packages_for_me: self
                .round2_relay
                .iter()
                .filter_map(|(dealer, by_recipient)| {
                    let pkg = by_recipient.get(&sender_id)?;
                    Some((hex::encode(dealer.serialize()), pkg.to_json()))
                })
                .collect(),
        })
    }
}
