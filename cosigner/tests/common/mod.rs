// Shared test helpers: each integration binary compiles this module and uses only part of it.
#![allow(dead_code)]

//! Shared setup for the integration tests. Builds `Store` against the local dev stack.
//!
//! Persistence is an in-process SQLite store, so there is no external dependency to reach and each
//! `try_shared` call gets its own isolated database. The ASP channel is created lazily, so a
//! reachable arkd is NOT needed for paths that never issue an ASP RPC (FROST signing, policy seal,
//! DKG onboarding bookkeeping) — which is every test using this helper. `try_shared` returns
//! `None` only if the ASP URL itself is malformed.

use cosigner::Cosigner;
use std::collections::BTreeMap;
use std::sync::Arc;

use rand::rngs::OsRng;

use cosigner::store::Store;

use threshold::dkg::{self, Round1Package, Round2Package};
use threshold::identifier::Identifier;
use threshold::keys::{KeyPackage, PublicKeyPackage};
use threshold::random;

use std::sync::Mutex;

pub fn try_store() -> Option<Arc<Store>> {
    // `:memory:` — a fresh, private store per caller. Tests no longer share one namespace, so a
    // leftover key from a failed run can't leak into the next one.
    Some(Arc::new(
        Store::open(":memory:", 1800).expect("open in-memory store"),
    ))
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
pub fn open_cosigner(store: &Arc<Store>, group_key: &str) -> Mutex<Cosigner> {
    Mutex::new(Cosigner::open(store.clone(), group_key.to_string()).expect("open cosigner"))
}

/// Install a wallet's key material and seal it, as DKG's final round does: the cosigner key
/// package, the group PKP, the user's signing identifier and the Ark cosigner secret.
pub fn seed_policy(
    cosigner: &Mutex<Cosigner>,
    group_key: &str,
    kp_cosigner: &KeyPackage,
    kp_user: &KeyPackage,
    pkp: &PublicKeyPackage,
    ark_cosigner_secret_hex: Option<String>,
) {
    seed_policy_with_dealt_share(
        cosigner,
        group_key,
        kp_cosigner,
        kp_user,
        pkp,
        ark_cosigner_secret_hex,
        None,
    );
}

/// As [`seed_policy`], plus the share the cosigner dealt the wallet at DKG — what `Recover` hands
/// back. `None` is a wallet onboarded before recovery existed.
pub fn seed_policy_with_dealt_share(
    cosigner: &Mutex<Cosigner>,
    group_key: &str,
    kp_cosigner: &KeyPackage,
    kp_user: &KeyPackage,
    pkp: &PublicKeyPackage,
    ark_cosigner_secret_hex: Option<String>,
    wallet_dealt_share_hex: Option<String>,
) {
    let mut actor = cosigner.lock().unwrap();
    actor
        .install_policy(
            group_key.to_string(),
            &kp_cosigner.to_json(),
            &pkp.to_json(),
            Some(&hex::encode(kp_user.identifier.serialize())),
            ark_cosigner_secret_hex,
            wallet_dealt_share_hex,
            )
        .expect("install policy");
    actor.seal();
}

/// A 2-of-2 BIP-340 signature over [message] by the group key, both halves played host-side.
///
/// What a wallet and its cosigner produce together — used where a test needs a group-key signature
/// without standing up a ceremony, such as authoring a payment request. `key_packages` is the pair
/// `dkg_2of2` returns.
pub fn group_sign(
    key_packages: &[KeyPackage],
    public_key_package: &PublicKeyPackage,
    message: &[u8],
) -> [u8; 64] {
    use threshold::commitment::SigningPackage;
    use threshold::nonce;
    use threshold::signing;

    let mut rng = OsRng;
    let nonces: Vec<_> = key_packages
        .iter()
        .map(|kp| nonce::new_nonce(&mut rng, &kp.secret_share))
        .collect();
    let commitments = key_packages
        .iter()
        .zip(&nonces)
        .map(|(kp, n)| (kp.identifier.clone(), n.commitments.clone()))
        .collect::<BTreeMap<_, _>>();
    let package = SigningPackage::new(commitments, message.to_vec());
    let shares = key_packages
        .iter()
        .zip(&nonces)
        .map(|(kp, n)| {
            (
                kp.identifier.clone(),
                signing::sign(&package, n, kp).expect("share"),
            )
        })
        .collect::<BTreeMap<_, _>>();
    signing::aggregate(&package, &shares, public_key_package)
        .expect("aggregate")
        .serialize()
}
