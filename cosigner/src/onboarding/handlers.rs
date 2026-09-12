//! The DKG ceremony: `threshold::dkg::*` called directly on the typed round state in
//! `OnboardingSession.rounds`.
//!
//! Two exchanges, not three. `DKGStep1/2/3` were three unary calls because each had to be a
//! request; step 2 did nothing a caller needed — it recomputed the cosigner's round 2 and returned
//! the round-1 packages step 1 had already returned. On a stream the cosigner does that itself,
//! leaving what the ceremony actually is: the wallet's round 1 in and everybody's out, then its
//! round 2 in and ours out with the key.
//!
//! Each step answers its caller directly. It used to park a `oneshot` in a `pending_*` pool and
//! wait for whichever participant closed the round to fulfil it — a rendezvous for a ceremony
//! several parties joined by separate requests. The ceremony is 2-of-2 and one of the two is this
//! cosigner, so there is exactly one remote participant and it always closes the round on arrival:
//! the pools could never fill. One stream per ceremony leaves nothing for them to do either way.
//!
//! These handlers deliberately do NOT call `auth_check`/`timestamp_check`: the user's owner key
//! only exists once onboarding completes, so there is no shared secret to verify against during
//! the ceremony. Integrity comes from FROST itself, and from the ceremony living on one stream —
//! an abandoned one leaves nothing behind.

use rand::rngs::OsRng;
use rand::Rng;
use tonic::Status;

use threshold::dkg::{self, Round1SecretPackage};
use threshold::identifier::Identifier;
use threshold::random;
use threshold::scalar::scalar_to_bytes;

use super::ceremony::{self};
use crate::handlers::parsers;
use crate::upstreams::Upstreams;
use crate::wallet_proto::{
    DkgStep1Request, DkgStep1Response, DkgStep3Request,
    DkgStep3Response,
};

use super::session::OnboardingSession;

// Real 2-of-2 {wallet, cosigner}: both parties deal, both hold a share, no
// recovery/hardware third party. `receiver_identifiers` stays empty.
const TOTAL_PARTICIPANTS: usize = 2;
const THRESHOLD_COUNT: usize = 2;

fn req_identifier(bytes: &[u8]) -> Result<Identifier, Status> {
    ceremony::parse_identifier_hex(&hex::encode(bytes))
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
        match ceremony::round1_pkg_from_json(&req.round1_package) {
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

        let dealt = ceremony::parse_scalar_hex(&secret_hex).and_then(|secret| {
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
    upstreams: &Upstreams,
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
    let pkgs = match ceremony::round2_pkgs_from_wire(&req.round2_packages_for_others) {
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

        sess.seed_material = Some(crate::onboarding::session::SeedMaterial {
            group_key: group_key.clone(),
            key_package_json: kp_json,
            public_key_package_json: pkp_json,
            user_signing_identifier_hex,
            server_dkg_secret_hex,
        });

        upstreams
            .persistence
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
