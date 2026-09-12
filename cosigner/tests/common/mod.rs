// Shared test helpers: each integration binary compiles this module and uses only part of it.
#![allow(dead_code)]

//! Shared setup for the integration tests. Builds `Upstreams` against the local dev stack.
//!
//! Persistence is an in-process SQLite store, so there is no external dependency to reach and each
//! `try_shared` call gets its own isolated database. The ASP channel is created lazily, so a
//! reachable arkd is NOT needed for paths that never issue an ASP RPC (FROST signing, policy seal,
//! DKG onboarding bookkeeping) — which is every test using this helper. `try_shared` returns
//! `None` only if the ASP URL itself is malformed.

use cosigner::Cosigner;
use cosigner::state::CosignerState;
use std::collections::BTreeMap;
use std::sync::Arc;

use rand::rngs::OsRng;

use cosigner::kv_store::SqliteStore;
use cosigner::upstreams::Upstreams;

use threshold::dkg::{self, Round1Package, Round2Package};
use threshold::identifier::Identifier;
use threshold::keys::{KeyPackage, PublicKeyPackage};
use threshold::random;

pub async fn try_shared() -> Option<Arc<Upstreams>> {
    let asp_url = std::env::var("ASP_URL").unwrap_or_else(|_| "http://127.0.0.1:7070".to_string());

    // `:memory:` — a fresh, private store per caller. Tests no longer share one namespace, so a
    // leftover key from a failed run can't leak into the next one.
    let store = Arc::new(SqliteStore::open(":memory:").expect("open in-memory store"));
    Some(Arc::new(Upstreams::new(
        store,
        None, // fcm
        1800, // auto_settle_safety_margin_secs
    )))
}

/// Host-side 2-of-2 DKG; even-Y-normalized outputs. Index 0 = user/client, 1 = cosigner/server.
/// The actor no longer performs DKG, so tests mint the key material themselves.
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
pub async fn open_cosigner(upstreams: &Arc<Upstreams>, group_key: &str) -> tokio::sync::Mutex<Cosigner> {
    let state = Arc::new(parking_lot::Mutex::new(CosignerState::new(
        group_key.to_string(),
    )));
    tokio::sync::Mutex::new(
        Cosigner::open(upstreams.clone(), state)
            .await
            .expect("open cosigner"),
    )
}

/// Install a wallet's key material and seal it, as DKG's final round does: the cosigner key
/// package, the group PKP, the user's signing identifier and the Ark cosigner secret.
pub async fn seed_policy(
    cosigner: &tokio::sync::Mutex<Cosigner>,
    group_key: &str,
    kp_cosigner: &KeyPackage,
    kp_user: &KeyPackage,
    pkp: &PublicKeyPackage,
    ark_cosigner_secret_hex: Option<String>,
) {
    let mut actor = cosigner.lock().await;
    actor
        .install_policy(
            group_key.to_string(),
            &kp_cosigner.to_json(),
            &pkp.to_json(),
            Some(&hex::encode(kp_user.identifier.serialize())),
            ark_cosigner_secret_hex,
            None,
            String::new(),
        )
        .expect("install policy");
    actor.seal().await;
}
