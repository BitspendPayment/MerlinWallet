use crate::error::Error;
use hex_conservative::{DisplayHex, FromHex};
use crate::identifier::Identifier;
use crate::keys::{PublicKeyPackage, VerifyingKey};
use crate::point;
use crate::polynomial;
use crate::scalar::{scalar_from_bytes, scalar_to_bytes};
use crate::vss::{self, VssCommitment};
use alloc::collections::BTreeMap;
use alloc::string::String;
use alloc::vec::Vec;
use k256::elliptic_curve::ops::Reduce;
use k256::{ProjectivePoint, Scalar, U256};
use rand_core::RngCore;
use sha2::{Digest, Sha256};

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

/// Proof-of-knowledge signature used during DKG round 1.
#[derive(Clone, Debug)]
pub struct DkgSignature {
    pub r: ProjectivePoint,
    pub z: Scalar,
}

/// Public package broadcast by each participant after DKG round 1.
#[derive(Clone, Debug)]
pub struct Round1Package {
    pub commitment: VssCommitment,
    pub proof_of_knowledge: DkgSignature,
    pub verifying_key: VerifyingKey,
}

/// Secret state kept by a participant between DKG rounds 1 and 2.
#[derive(Clone)]
pub struct Round1SecretPackage {
    pub identifier: Identifier,
    pub coefficients: Vec<Scalar>,
    pub commitment: VssCommitment,
    pub min_signers: usize,
    pub max_signers: usize,
}

// Redacting Debug: `coefficients` includes the secret polynomial constant term.
impl core::fmt::Debug for Round1SecretPackage {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("Round1SecretPackage { coefficients: <redacted>, .. }")
    }
}

/// Package sent point-to-point from one participant to another in round 2.
#[derive(Clone)]
pub struct Round2Package {
    pub secret_share: Scalar,
}

// Redacting Debug: `secret_share` is the dealt secret share.
impl core::fmt::Debug for Round2Package {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("Round2Package { secret_share: <redacted> }")
    }
}

/// Secret state kept by a participant between DKG rounds 2 and 3.
#[derive(Clone)]
pub struct Round2SecretPackage {
    pub identifier: Identifier,
    pub commitment: VssCommitment,
    pub secret_share: Scalar,
    pub min_signers: usize,
    pub max_signers: usize,
}

// Redacting Debug: `secret_share` is secret.
impl core::fmt::Debug for Round2SecretPackage {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("Round2SecretPackage { secret_share: <redacted>, .. }")
    }
}

// ---------------------------------------------------------------------------
// DKG challenge (matches Dart dkgChallenge in utils.dart:199)
// ---------------------------------------------------------------------------

/// Compute the DKG proof-of-knowledge challenge:
/// c = SHA256(id_bytes(32) || vk_compressed(33) || R_compressed(33)) mod n
fn dkg_challenge(id: &Identifier, vk: &VerifyingKey, r: &ProjectivePoint) -> Scalar {
    let mut hasher = Sha256::new();
    hasher.update(id.serialize());
    hasher.update(vk.serialize());
    hasher.update(point::serialize_compressed(r));
    let hash = hasher.finalize();
    let wide = U256::from_be_slice(&hash);
    <Scalar as Reduce<U256>>::reduce(wide)
}

// ---------------------------------------------------------------------------
// Proof of knowledge (matches Dart computeProofOfKnowledge / verifyProofOfKnowledge)
// ---------------------------------------------------------------------------

/// Generate a random non-zero scalar.
fn random_scalar(rng: &mut impl RngCore) -> Scalar {
    loop {
        let mut bytes = [0u8; 32];
        rng.fill_bytes(&mut bytes);
        let wide = U256::from_be_slice(&bytes);
        let s = <Scalar as Reduce<U256>>::reduce(wide);
        if !bool::from(s.is_zero()) {
            return s;
        }
    }
}

/// Compute a proof of knowledge of the secret polynomial constant term.
///
/// sig.z = a0 * c + k (mod n), sig.r = k * G
pub fn compute_proof_of_knowledge(
    id: &Identifier,
    coefficients: &[Scalar],
    vk: &VerifyingKey,
    rng: &mut impl RngCore,
) -> Result<DkgSignature, Error> {
    if coefficients.is_empty() {
        return Err(Error::InvalidCoefficients);
    }
    let k = random_scalar(rng);
    let r = point::base_mul(&k);

    let c = dkg_challenge(id, vk, &r);
    let a0 = coefficients[0];
    let z = a0 * c + k;

    Ok(DkgSignature { r, z })
}

/// Verify a proof of knowledge.
///
/// Check: R == z*G + (-c)*VK
pub fn verify_proof_of_knowledge(
    id: &Identifier,
    vk: &VerifyingKey,
    sig: &DkgSignature,
) -> Result<(), Error> {
    let c = dkg_challenge(id, vk, &sig.r);
    let z_g = point::base_mul(&sig.z);
    let c_neg = -c;
    let c_neg_vk = point::point_mul(&vk.point, &c_neg);
    let right = point::point_add(&z_g, &c_neg_vk);

    if point::points_equal(&sig.r, &right) {
        Ok(())
    } else {
        Err(Error::InvalidProofOfKnowledge)
    }
}

// ---------------------------------------------------------------------------
// Validation
// ---------------------------------------------------------------------------

fn validate_num_signers(min: usize, max: usize) -> Result<(), Error> {
    if min < 2 {
        return Err(Error::InvalidMinSigners);
    }
    if max < 2 {
        return Err(Error::InvalidMaxSigners);
    }
    if min > max {
        return Err(Error::InvalidMinSigners);
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// DKG Part 1 (matches Dart dkgPart1 in dkg.dart:298)
// ---------------------------------------------------------------------------

/// DKG round 1: generate secret polynomial, commitment, and proof of knowledge.
///
/// - `secret`: the participant's secret (polynomial constant term).
/// - `coefficients`: the remaining polynomial coefficients (length = min_signers - 1).
/// - Returns `(Round1SecretPackage, Round1Package)`.
pub fn dkg_part1(
    max_signers: usize,
    min_signers: usize,
    secret: &Scalar,
    coefficients: &[Scalar],
    rng: &mut impl RngCore,
) -> Result<(Round1SecretPackage, Round1Package), Error> {
    validate_num_signers(min_signers, max_signers)?;

    let (coeffs, commitment_points) =
        polynomial::generate_secret_polynomial(secret, coefficients);
    let commitment = VssCommitment {
        coeffs: commitment_points,
    };
    let vk = commitment.to_verifying_key();
    let vk_bytes = vk.serialize();
    let identifier = Identifier::derive(&vk_bytes)?;

    let sig = compute_proof_of_knowledge(&identifier, &coeffs, &vk, rng)?;

    let secret_pkg = Round1SecretPackage {
        identifier: identifier.clone(),
        coefficients: coeffs,
        commitment: commitment.clone(),
        min_signers,
        max_signers,
    };
    let pub_pkg = Round1Package {
        commitment,
        proof_of_knowledge: sig,
        verifying_key: vk,
    };
    Ok((secret_pkg, pub_pkg))
}

// ---------------------------------------------------------------------------
// DKG Part 2 (matches Dart dkgPart2 in dkg.dart:336)
// ---------------------------------------------------------------------------

/// DKG round 2: verify others' round 1 packages and compute shares for each.
///
/// - `secret_pkg`: our round 1 secret package.
/// - `round1_pkgs`: round 1 packages from all other *dealer* participants.
/// - `receiver_identifiers`: identifiers of passive receivers (no round 1 package).
/// - Returns `(Round2SecretPackage, Map<Identifier, Round2Package>)`.
pub fn dkg_part2(
    secret_pkg: &Round1SecretPackage,
    round1_pkgs: &BTreeMap<Identifier, Round1Package>,
    receiver_identifiers: &[Identifier],
) -> Result<(Round2SecretPackage, BTreeMap<Identifier, Round2Package>), Error> {
    if round1_pkgs.len() + receiver_identifiers.len() != secret_pkg.max_signers - 1 {
        return Err(Error::IncorrectNumberOfPackages);
    }
    for pkg in round1_pkgs.values() {
        if pkg.commitment.coeffs.len() != secret_pkg.min_signers {
            return Err(Error::IncorrectNumberOfCommitments);
        }
    }

    let mut out = BTreeMap::new();

    // Compute shares for other dealers (verify proofs)
    for (sender_id, pkg) in round1_pkgs {
        let vk = pkg.commitment.to_verifying_key();
        verify_proof_of_knowledge(sender_id, &vk, &pkg.proof_of_knowledge)?;

        let share = polynomial::evaluate_polynomial(sender_id, &secret_pkg.coefficients);
        out.insert(sender_id.clone(), Round2Package { secret_share: share });
    }

    // Compute shares for passive receivers (no proof to verify)
    for receiver_id in receiver_identifiers {
        let share = polynomial::evaluate_polynomial(receiver_id, &secret_pkg.coefficients);
        out.insert(receiver_id.clone(), Round2Package { secret_share: share });
    }

    let fii = polynomial::evaluate_polynomial(
        &secret_pkg.identifier,
        &secret_pkg.coefficients,
    );

    Ok((
        Round2SecretPackage {
            identifier: secret_pkg.identifier.clone(),
            commitment: secret_pkg.commitment.clone(),
            secret_share: fii,
            min_signers: secret_pkg.min_signers,
            max_signers: secret_pkg.max_signers,
        },
        out,
    ))
}

// ---------------------------------------------------------------------------
// DKG Part 3 (matches Dart dkgPart3 in dkg.dart:377)
// ---------------------------------------------------------------------------

/// DKG round 3: verify received shares and compute final key package.
///
/// - `_r1_secret`: round 1 secret package (kept for API compatibility with Dart).
/// - `r2_secret`: round 2 secret package.
/// - `round1_pkgs`: other dealers' round 1 packages.
/// - `round2_pkgs`: other dealers' round 2 packages (shares addressed to us).
/// - `receiver_identifiers`: identifiers of passive receivers (included in PKP).
/// - Returns `(KeyPackage, PublicKeyPackage)` both normalized to even Y.
pub fn dkg_part3(
    _r1_secret: &Round1SecretPackage,
    r2_secret: &Round2SecretPackage,
    round1_pkgs: &BTreeMap<Identifier, Round1Package>,
    round2_pkgs: &BTreeMap<Identifier, Round2Package>,
    receiver_identifiers: &[Identifier],
) -> Result<(crate::keys::KeyPackage, PublicKeyPackage), Error> {
    if round1_pkgs.len() + receiver_identifiers.len() != r2_secret.max_signers - 1 {
        return Err(Error::IncorrectNumberOfPackages);
    }
    if round1_pkgs.len() != round2_pkgs.len() {
        return Err(Error::IncorrectNumberOfPackages);
    }
    for id in round1_pkgs.keys() {
        if !round2_pkgs.contains_key(id) {
            return Err(Error::IncorrectPackageMapping);
        }
    }

    let mut si = Scalar::ZERO;

    for (sender_id, pkg2) in round2_pkgs {
        let r1 = round1_pkgs
            .get(sender_id)
            .ok_or(Error::UnknownIdentifier)?;

        // Verify: share * G == commitment.getVerifyingShare(our_id)
        let share_point = point::base_mul(&pkg2.secret_share);
        let expected = r1.commitment.get_verifying_share(&r2_secret.identifier);
        if !point::points_equal(&share_point, &expected) {
            return Err(Error::InvalidSecretShare);
        }

        si = si + pkg2.secret_share;
    }

    // Add our own self-share
    si = si + r2_secret.secret_share;
    let secret_share = si;
    let verifying_share = point::base_mul(&secret_share);

    // Build commitment map from dealer round 1 packages
    let mut commit_map: BTreeMap<Identifier, VssCommitment> = BTreeMap::new();
    for (id, pkg) in round1_pkgs {
        commit_map.insert(id.clone(), pkg.commitment.clone());
    }
    commit_map.insert(r2_secret.identifier.clone(), r2_secret.commitment.clone());

    // Build PublicKeyPackage with ALL participant IDs (dealers + receivers)
    let group = vss::sum_commitments(&commit_map.values().cloned().collect::<Vec<_>>())?;
    let mut all_ids: Vec<Identifier> = commit_map.keys().cloned().collect();
    for rid in receiver_identifiers {
        all_ids.push(rid.clone());
    }
    all_ids.sort();
    let public_key_package = pkp_from_commitment(&all_ids, &group);

    let key_package = crate::keys::KeyPackage {
        identifier: r2_secret.identifier.clone(),
        secret_share,
        verifying_share,
        verifying_key: public_key_package.verifying_key.clone(),
        min_signers: r2_secret.min_signers,
    };

    Ok((key_package.into_even_y(), public_key_package.into_even_y()))
}

/// DKG Part 3 for a passive receiver (no secret polynomial contribution).
///
/// The receiver verifies shares from each dealer against their commitments,
/// accumulates the shares (no self-share), and derives its KeyPackage and
/// the shared PublicKeyPackage.
pub fn dkg_part3_receive(
    my_identifier: &Identifier,
    dealer_round1_pkgs: &BTreeMap<Identifier, Round1Package>,
    shares_for_me: &BTreeMap<Identifier, Round2Package>,
    min_signers: usize,
    max_signers: usize,
    all_participant_identifiers: &[Identifier],
) -> Result<(crate::keys::KeyPackage, PublicKeyPackage), Error> {
    if dealer_round1_pkgs.len() != shares_for_me.len() {
        return Err(Error::IncorrectNumberOfPackages);
    }
    for id in dealer_round1_pkgs.keys() {
        if !shares_for_me.contains_key(id) {
            return Err(Error::IncorrectPackageMapping);
        }
    }

    // Verify each dealer's share against their commitment, then accumulate
    let mut si = Scalar::ZERO;
    for (dealer_id, pkg2) in shares_for_me {
        let r1 = dealer_round1_pkgs
            .get(dealer_id)
            .ok_or(Error::UnknownIdentifier)?;

        let share_point = point::base_mul(&pkg2.secret_share);
        let expected = r1.commitment.get_verifying_share(my_identifier);
        if !point::points_equal(&share_point, &expected) {
            return Err(Error::InvalidSecretShare);
        }

        si = si + pkg2.secret_share;
    }

    // Receiver has no self-share
    let secret_share = si;
    let verifying_share = point::base_mul(&secret_share);

    // Build PublicKeyPackage from dealer commitments with ALL participant IDs
    let dealer_commitments: Vec<VssCommitment> = dealer_round1_pkgs
        .values()
        .map(|pkg| pkg.commitment.clone())
        .collect();
    let group = vss::sum_commitments(&dealer_commitments)?;

    let mut sorted_ids = all_participant_identifiers.to_vec();
    sorted_ids.sort();
    let public_key_package = pkp_from_commitment(&sorted_ids, &group);

    let key_package = crate::keys::KeyPackage {
        identifier: my_identifier.clone(),
        secret_share,
        verifying_share,
        verifying_key: public_key_package.verifying_key.clone(),
        min_signers,
    };

    let _ = max_signers; // used for API consistency
    Ok((key_package.into_even_y(), public_key_package.into_even_y()))
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/// Build a PublicKeyPackage from a summed commitment and the set of identifiers.
pub fn pkp_from_commitment(
    ids: &[Identifier],
    commit: &VssCommitment,
) -> PublicKeyPackage {
    let mut vmap = BTreeMap::new();
    for id in ids {
        vmap.insert(id.clone(), commit.get_verifying_share(id));
    }
    let vk = commit.to_verifying_key();
    PublicKeyPackage {
        verifying_shares: vmap,
        verifying_key: vk,
    }
}

/// Build a PublicKeyPackage from a map of per-participant commitments.
///
/// Sums the commitments, then evaluates at each participant's identifier.
pub fn pkp_from_dkg_commitments(
    commits: &BTreeMap<Identifier, VssCommitment>,
) -> Result<PublicKeyPackage, Error> {
    let ids: Vec<Identifier> = commits.keys().cloned().collect();
    let list: Vec<VssCommitment> = commits.values().cloned().collect();
    let group = vss::sum_commitments(&list)?;
    let mut sorted_ids = ids;
    sorted_ids.sort();
    Ok(pkp_from_commitment(&sorted_ids, &group))
}

// ---------------------------------------------------------------------------
// Key Refresh (matches Dart dkgRefreshPart1/2/3 in dkg.dart:542-720)
// ---------------------------------------------------------------------------

/// Key refresh round 1: generate a zero-secret polynomial for share refresh.
///
/// The constant term is zero (no net change to group key). Only higher
/// coefficients are random. The identity point is stripped from the broadcast
/// commitment (receivers must prepend it before verification).
///
/// - `identifier`: this participant's identifier.
/// - `coefficients`: random coefficients (length = min_signers - 1).
/// - Returns `(Round1SecretPackage, Round1Package)`.
pub fn dkg_refresh_part1(
    identifier: &Identifier,
    max_signers: usize,
    min_signers: usize,
    coefficients: &[Scalar],
    rng: &mut impl RngCore,
) -> Result<(Round1SecretPackage, Round1Package), Error> {
    validate_num_signers(min_signers, max_signers)?;

    let refreshing_key = Scalar::ZERO;
    let (coeffs, commitment_points) =
        polynomial::generate_secret_polynomial(&refreshing_key, coefficients);

    if commitment_points.is_empty() {
        return Err(Error::InvalidCoefficients);
    }

    // Strip the identity-point first coefficient (constant term = 0 -> identity)
    let trimmed = commitment_points[1..].to_vec();
    let trim_commit = VssCommitment { coeffs: trimmed };

    let vk = trim_commit.to_verifying_key();
    let sig = compute_proof_of_knowledge(identifier, &coeffs, &vk, rng)?;

    let secret_pkg = Round1SecretPackage {
        identifier: identifier.clone(),
        coefficients: coeffs,
        commitment: trim_commit.clone(),
        min_signers,
        max_signers,
    };
    let pub_pkg = Round1Package {
        commitment: trim_commit,
        proof_of_knowledge: sig,
        verifying_key: vk,
    };
    Ok((secret_pkg, pub_pkg))
}

/// Key refresh round 2: compute shares for each peer.
///
/// Prepends the identity point to each peer's commitment for verification,
/// then evaluates our polynomial at each peer's identifier.
pub fn dkg_refresh_part2(
    secret_pkg: &Round1SecretPackage,
    round1_pkgs: &BTreeMap<Identifier, Round1Package>,
) -> Result<(Round2SecretPackage, BTreeMap<Identifier, Round2Package>), Error> {
    if round1_pkgs.len() != secret_pkg.max_signers - 1 {
        return Err(Error::IncorrectNumberOfPackages);
    }

    // Prepend identity to our own commitment
    let mut my_coeffs = alloc::vec![ProjectivePoint::IDENTITY];
    my_coeffs.extend_from_slice(&secret_pkg.commitment.coeffs);

    let my_full_commit = VssCommitment { coeffs: my_coeffs };

    let mut out = BTreeMap::new();

    for (sender_id, r1) in round1_pkgs {
        // Prepend identity to peer's commitment
        let mut peer_coeffs = alloc::vec![ProjectivePoint::IDENTITY];
        peer_coeffs.extend_from_slice(&r1.commitment.coeffs);

        if peer_coeffs.len() != secret_pkg.min_signers {
            return Err(Error::IncorrectNumberOfCommitments);
        }

        let share = polynomial::evaluate_polynomial(sender_id, &secret_pkg.coefficients);
        out.insert(sender_id.clone(), Round2Package { secret_share: share });
    }

    let fii = polynomial::evaluate_polynomial(
        &secret_pkg.identifier,
        &secret_pkg.coefficients,
    );

    Ok((
        Round2SecretPackage {
            identifier: secret_pkg.identifier.clone(),
            commitment: my_full_commit,
            secret_share: fii,
            min_signers: secret_pkg.min_signers,
            max_signers: secret_pkg.max_signers,
        },
        out,
    ))
}

/// Key refresh round 3: verify shares, combine with old key package.
///
/// Prepends identity to each peer's broadcast commitment, verifies received
/// shares, accumulates refresh delta, and adds old secret share. Produces
/// a new KeyPackage with updated shares but the same group public key.
pub fn dkg_refresh_part3(
    r2_secret: &Round2SecretPackage,
    round1_pkgs: &BTreeMap<Identifier, Round1Package>,
    round2_pkgs: &BTreeMap<Identifier, Round2Package>,
    old_pkp: &PublicKeyPackage,
    old_kp: &crate::keys::KeyPackage,
) -> Result<(crate::keys::KeyPackage, PublicKeyPackage), Error> {
    // Prepend identity to each peer's commitment
    let mut new_r1: BTreeMap<Identifier, Round1Package> = BTreeMap::new();
    for (sender_id, r1) in round1_pkgs {
        let mut coeffs = alloc::vec![ProjectivePoint::IDENTITY];
        coeffs.extend_from_slice(&r1.commitment.coeffs);
        new_r1.insert(sender_id.clone(), Round1Package {
            commitment: VssCommitment { coeffs },
            proof_of_knowledge: r1.proof_of_knowledge.clone(),
            verifying_key: old_pkp.verifying_key.clone(),
        });
    }

    if new_r1.len() != r2_secret.max_signers - 1 {
        return Err(Error::IncorrectNumberOfPackages);
    }
    if new_r1.len() != round2_pkgs.len() {
        return Err(Error::IncorrectNumberOfPackages);
    }
    for id in new_r1.keys() {
        if !round2_pkgs.contains_key(id) {
            return Err(Error::IncorrectPackageMapping);
        }
    }

    let mut si = Scalar::ZERO;

    for (sender_id, r2) in round2_pkgs {
        let r1 = new_r1.get(sender_id).ok_or(Error::UnknownIdentifier)?;

        // Verify: share * G == commitment.getVerifyingShare(our_id)
        let share_point = point::base_mul(&r2.secret_share);
        let expected = r1.commitment.get_verifying_share(&r2_secret.identifier);
        if !point::points_equal(&share_point, &expected) {
            return Err(Error::InvalidSecretShare);
        }

        si = si + r2.secret_share;
    }

    // Add our own self-share
    si = si + r2_secret.secret_share;

    // Add old secret share
    si = si + old_kp.secret_share;

    let new_secret_share = si;
    let new_verifying = point::base_mul(&new_secret_share);

    // Build commitment map from the identity-prepended R1 packages
    let mut commit_map: BTreeMap<Identifier, VssCommitment> = BTreeMap::new();
    for (id, pkg) in &new_r1 {
        commit_map.insert(id.clone(), pkg.commitment.clone());
    }
    commit_map.insert(r2_secret.identifier.clone(), r2_secret.commitment.clone());

    let zero_pkp = pkp_from_dkg_commitments(&commit_map)?;

    // Combine zero-refresh verifying shares with old verifying shares
    let mut new_vs: BTreeMap<Identifier, ProjectivePoint> = BTreeMap::new();
    for (id, vs_new) in &zero_pkp.verifying_shares {
        let vs_old = old_pkp
            .verifying_shares
            .get(id)
            .ok_or(Error::UnknownIdentifier)?;
        let sum = point::point_add(vs_new, vs_old);
        new_vs.insert(id.clone(), sum);
    }

    let pub_pkg = PublicKeyPackage {
        verifying_shares: new_vs,
        verifying_key: old_pkp.verifying_key.clone(),
    };

    let key_pkg = crate::keys::KeyPackage {
        identifier: r2_secret.identifier.clone(),
        secret_share: new_secret_share,
        verifying_share: new_verifying,
        verifying_key: pub_pkg.verifying_key.clone(),
        min_signers: r2_secret.min_signers,
    };

    Ok((key_pkg, pub_pkg))
}

// ---------------------------------------------------------------------------
// Key Resharing (eVTXO key generation)
//
// Produce a NEW key `V' = V + Δ` shared among a chosen receiver subset, by
// adding the old share to a fresh NON-zero dealing. Unlike refresh, the group
// key intentionally CHANGES and the new shareholder set EXCLUDES old holders not
// in `receiver_identifiers` (e.g. the hardware signer) — so only the receivers
// can sign `V'`. Dealing reuses `dkg_part1` (random non-zero secret) + `dkg_part2`
// with the receivers as `receiver_identifiers`.
// ---------------------------------------------------------------------------

/// Resharing round 1: deal a fresh NON-zero polynomial under an EXPLICIT
/// identifier (the dealer's existing identity, so self-shares and the receivers'
/// old shares line up). Unlike `dkg_refresh_part1` the constant term is the
/// random `secret` (so the group key shifts by Δ); unlike `dkg_part1` the
/// identifier is supplied rather than derived. Round 2 then uses the regular
/// `dkg_part2` (commitments are full-length, no identity prepend).
pub fn dkg_reshare_part1(
    identifier: &Identifier,
    max_signers: usize,
    min_signers: usize,
    secret: &Scalar,
    coefficients: &[Scalar],
    rng: &mut impl RngCore,
) -> Result<(Round1SecretPackage, Round1Package), Error> {
    validate_num_signers(min_signers, max_signers)?;

    let (coeffs, commitment_points) =
        polynomial::generate_secret_polynomial(secret, coefficients);
    let commitment = VssCommitment {
        coeffs: commitment_points,
    };
    let vk = commitment.to_verifying_key();
    let sig = compute_proof_of_knowledge(identifier, &coeffs, &vk, rng)?;

    let secret_pkg = Round1SecretPackage {
        identifier: identifier.clone(),
        coefficients: coeffs,
        commitment: commitment.clone(),
        min_signers,
        max_signers,
    };
    let pub_pkg = Round1Package {
        commitment,
        proof_of_knowledge: sig,
        verifying_key: vk,
    };
    Ok((secret_pkg, pub_pkg))
}

/// Resharing finalizer for a dealer-receiver (e.g. the cosigner): it dealt a
/// non-zero polynomial AND receives a new share. `round1_pkgs`/`round2_pkgs` are
/// the OTHER dealers' packages (shares addressed to us); `r2_secret` is our own
/// dealing. Combines: peer-dealer shares + own self-share + old share, yielding
/// `V' = V + Δ`. `receiver_identifiers` is the NEW shareholder set; the resulting
/// PKP holds only these (old holders outside the set are excluded).
pub fn dkg_reshare_part3(
    r2_secret: &Round2SecretPackage,
    round1_pkgs: &BTreeMap<Identifier, Round1Package>,
    round2_pkgs: &BTreeMap<Identifier, Round2Package>,
    old_pkp: &PublicKeyPackage,
    old_kp: &crate::keys::KeyPackage,
    receiver_identifiers: &[Identifier],
) -> Result<(crate::keys::KeyPackage, PublicKeyPackage), Error> {
    if round1_pkgs.len() != round2_pkgs.len() {
        return Err(Error::IncorrectNumberOfPackages);
    }
    for id in round1_pkgs.keys() {
        if !round2_pkgs.contains_key(id) {
            return Err(Error::IncorrectPackageMapping);
        }
    }

    let mut si = Scalar::ZERO;
    for (sender_id, pkg2) in round2_pkgs {
        let r1 = round1_pkgs.get(sender_id).ok_or(Error::UnknownIdentifier)?;
        let share_point = point::base_mul(&pkg2.secret_share);
        let expected = r1.commitment.get_verifying_share(&r2_secret.identifier);
        if !point::points_equal(&share_point, &expected) {
            return Err(Error::InvalidSecretShare);
        }
        si = si + pkg2.secret_share;
    }
    si = si + r2_secret.secret_share; // our own dealing self-share
    si = si + old_kp.secret_share; // reshare: V' = V + Δ

    // Δ commitments: the peer dealers plus this dealer.
    let mut delta_commitments: BTreeMap<Identifier, VssCommitment> = BTreeMap::new();
    for (id, pkg) in round1_pkgs {
        delta_commitments.insert(id.clone(), pkg.commitment.clone());
    }
    delta_commitments.insert(r2_secret.identifier.clone(), r2_secret.commitment.clone());

    finalize_reshare(
        si,
        old_pkp,
        &delta_commitments,
        receiver_identifiers,
        &r2_secret.identifier,
        r2_secret.min_signers,
    )
}

/// Resharing finalizer for a pure receiver (e.g. the wallet): no self-share.
/// `dealer_round1_pkgs`/`shares_for_me` cover ALL dealers. Adds the old share.
pub fn dkg_reshare_part3_receive(
    my_identifier: &Identifier,
    dealer_round1_pkgs: &BTreeMap<Identifier, Round1Package>,
    shares_for_me: &BTreeMap<Identifier, Round2Package>,
    old_pkp: &PublicKeyPackage,
    old_kp: &crate::keys::KeyPackage,
    receiver_identifiers: &[Identifier],
    min_signers: usize,
) -> Result<(crate::keys::KeyPackage, PublicKeyPackage), Error> {
    if dealer_round1_pkgs.len() != shares_for_me.len() {
        return Err(Error::IncorrectNumberOfPackages);
    }
    for id in dealer_round1_pkgs.keys() {
        if !shares_for_me.contains_key(id) {
            return Err(Error::IncorrectPackageMapping);
        }
    }

    let mut si = Scalar::ZERO;
    for (dealer_id, pkg2) in shares_for_me {
        let r1 = dealer_round1_pkgs
            .get(dealer_id)
            .ok_or(Error::UnknownIdentifier)?;
        let share_point = point::base_mul(&pkg2.secret_share);
        let expected = r1.commitment.get_verifying_share(my_identifier);
        if !point::points_equal(&share_point, &expected) {
            return Err(Error::InvalidSecretShare);
        }
        si = si + pkg2.secret_share;
    }
    si = si + old_kp.secret_share; // reshare: V' = V + Δ

    let mut delta_commitments: BTreeMap<Identifier, VssCommitment> = BTreeMap::new();
    for (id, pkg) in dealer_round1_pkgs {
        delta_commitments.insert(id.clone(), pkg.commitment.clone());
    }

    finalize_reshare(
        si,
        old_pkp,
        &delta_commitments,
        receiver_identifiers,
        my_identifier,
        min_signers,
    )
}

/// Output of [`refresh_to_receiver`]: my refreshed counter-share key package, the
/// 2-entry `PublicKeyPackage` for the new `{receiver, me}` pairing, and my own
/// half-scalar for the receiver (serialized) for delivery to it.
pub struct RefreshedPairing {
    pub receiver_half: [u8; 32],
    pub my_kp: crate::keys::KeyPackage,
    pub pairing_pkp: PublicKeyPackage,
}

/// The new receiver of a refreshed pairing: its identifier and the OTHER current
/// holders' COMBINED contribution to its verifying share, as a curve point. Passing a
/// point (never the scalar) lets me build the receiver's verifying share without ever
/// learning its secret share.
pub struct Receiver {
    pub id: Identifier,
    pub partial_verifying_share: [u8; 33],
}

/// Key-preserving REFRESH of the group key (held at `my_key_package`) onto a NEW
/// `{receiver, me}` `min_signers`-of-2 pairing (key UNCHANGED). The other holders have
/// already dealt their slices: `id_partial_share` (keyed by dealer id) holds the scalars
/// dealt to ME; `receiver.partial_verifying_share` is their COMBINED contribution to the
/// receiver, as a point (so I never learn its secret). Current holders = `me +
/// id_partial_share.keys()`. I deal my own slice, then return my counter-share key package
/// (`C = own_at_me + Σ id_partial_share`), the pairing PKP, and my half for the receiver.
pub fn refresh_to_receiver(
    my_key_package: &crate::keys::KeyPackage,
    receiver: &Receiver,
    id_partial_share: &BTreeMap<Identifier, [u8; 32]>,
    min_signers: usize,
    rng: &mut impl RngCore,
) -> Result<RefreshedPairing, Error> {
    let my_id = my_key_package.identifier.clone();
    let vprime_vk = my_key_package.verifying_key.clone();

    // The current shareholder set: me + every holder who dealt me a partial share.
    let mut id_set: Vec<Identifier> = id_partial_share.keys().cloned().collect();
    id_set.push(my_id.clone());

    // My own refresh contribution to the new {receiver, me} sharing.
    let own = refresh_to_ids(
        my_key_package,
        &id_set,
        &[receiver.id.clone(), my_id.clone()],
        min_signers,
        rng,
    );
    let own_at_receiver = own[&receiver.id];
    let own_at_me = own[&my_id];

    // C = own_at_me + Σ (the other holders' partial shares dealt to me).
    let mut c = own_at_me;
    for share_bytes in id_partial_share.values() {
        c = c + scalar_from_bytes(share_bytes)?;
    }
    let c_point = point::base_mul(&c);

    // receiver_share·G = (other holders' combined contribution)·G + own_receiver·G —
    // built WITHOUT learning the receiver's secret share (only its point).
    let partial = point::deserialize_compressed(&receiver.partial_verifying_share)?;
    let receiver_share_point = point::point_add(&partial, &point::base_mul(&own_at_receiver));

    let my_kp = crate::keys::KeyPackage {
        identifier: my_id.clone(),
        secret_share: c,
        verifying_share: c_point,
        verifying_key: vprime_vk.clone(),
        min_signers,
    };
    let mut verifying_shares: BTreeMap<Identifier, ProjectivePoint> = BTreeMap::new();
    verifying_shares.insert(receiver.id.clone(), receiver_share_point);
    verifying_shares.insert(my_id, c_point);
    let pairing_pkp = PublicKeyPackage {
        verifying_shares,
        verifying_key: vprime_vk,
    };

    Ok(RefreshedPairing {
        receiver_half: scalar_to_bytes(&own_at_receiver),
        my_kp,
        pairing_pkp,
    })
}

/// Deal THIS holder's key-preserving refresh contribution toward a new shareholder set.
///
/// Decomposes the holder's Shamir share of the group secret (held at `my_key_package`,
/// shared over `id_set`) into its additive piece `x = λ · ss`, deals a FRESH polynomial
/// `s(t) = x + r₁·t + … + r_{k-1}·t^{k-1}` of degree `min_signers - 1` (constant term is
/// the additive piece, the rest random), and returns `id → s(id)` for every
/// `recipient_id`. When every current holder does this and the per-id contributions are
/// summed, the result is a fresh `min_signers`-of-`recipient_ids.len()` Shamir sharing of
/// the SAME secret — the key is UNCHANGED (proactive refresh) and the new shares are
/// independent of the old ones.
pub fn refresh_to_ids(
    my_key_package: &crate::keys::KeyPackage,
    id_set: &[Identifier],
    recipient_ids: &[Identifier],
    min_signers: usize,
    rng: &mut impl RngCore,
) -> BTreeMap<Identifier, Scalar> {
    let lambda = crate::lagrange::lagrange_coeff_at_zero(&my_key_package.identifier, id_set);
    let mut coeffs = Vec::with_capacity(min_signers);
    coeffs.push(lambda * my_key_package.secret_share);
    for _ in 1..min_signers {
        coeffs.push(random_scalar(rng));
    }
    recipient_ids
        .iter()
        .map(|id| (id.clone(), polynomial::evaluate_polynomial(id, &coeffs)))
        .collect()
}

/// Shared resharing finalization. Given the new secret share `si` (already
/// including the old share), the dealer Δ-commitments, and the new receiver set:
/// compute `V' = V + Δ·G`, fold verifying shares (old + Δ) for the receivers
/// ONLY, and BIP-340 even-Y normalize. Both finalizers compute the SAME `V'` and
/// Δ, so they normalize identically and their shares stay consistent.
fn finalize_reshare(
    si: Scalar,
    old_pkp: &PublicKeyPackage,
    delta_commitments: &BTreeMap<Identifier, VssCommitment>,
    receiver_identifiers: &[Identifier],
    my_identifier: &Identifier,
    min_signers: usize,
) -> Result<(crate::keys::KeyPackage, PublicKeyPackage), Error> {
    let secret_share = si;
    let verifying_share = point::base_mul(&secret_share);

    // Δ polynomial commitment (NON-zero constant term => the key changes).
    let delta = vss::sum_commitments(
        &delta_commitments.values().cloned().collect::<Vec<_>>(),
    )?;
    // V' = V + Δ·G  (Δ·G is the summed dealer constant-term commitment).
    let new_vk_point = point::point_add(&old_pkp.verifying_key.point, &delta.coeffs[0]);

    // Fold verifying shares for the NEW receiver set only (excludes old holders
    // not being re-shared to — e.g. the hardware signer).
    let mut new_vs: BTreeMap<Identifier, ProjectivePoint> = BTreeMap::new();
    for id in receiver_identifiers {
        let vs_old = old_pkp
            .verifying_shares
            .get(id)
            .ok_or(Error::UnknownIdentifier)?;
        let vs_delta = delta.get_verifying_share(id);
        new_vs.insert(id.clone(), point::point_add(vs_old, &vs_delta));
    }

    let pub_pkg = PublicKeyPackage {
        verifying_shares: new_vs,
        verifying_key: VerifyingKey::new(new_vk_point),
    };
    let key_pkg = crate::keys::KeyPackage {
        identifier: my_identifier.clone(),
        secret_share,
        verifying_share,
        verifying_key: pub_pkg.verifying_key.clone(),
        min_signers,
    };

    Ok((key_pkg.into_even_y(), pub_pkg.into_even_y()))
}

// ---------------------------------------------------------------------------
// JSON serialization (wire-compatible with Dart)
// ---------------------------------------------------------------------------

impl DkgSignature {
    /// Deserialize from JSON: {"R": "hex_compressed", "Z": "hex_scalar"}
    pub fn from_json_value(v: &serde_json::Value) -> Result<Self, Error> {
        let r_hex = v["R"].as_str().ok_or(Error::SerializationError)?;
        let z_hex = v["Z"].as_str().ok_or(Error::SerializationError)?;

        let r_bytes = <[u8; 33]>::from_hex(r_hex)?;
        let z_bytes = <[u8; 32]>::from_hex(z_hex)?;

        let r = point::deserialize_compressed(&r_bytes)?;
        let z = scalar_from_bytes(&z_bytes)?;

        Ok(Self { r, z })
    }

    /// Serialize to JSON: {"R": "hex_compressed", "Z": "hex_scalar"}
    pub fn to_json_value(&self) -> serde_json::Value {
        let r_hex = point::serialize_compressed(&self.r).to_lower_hex_string();
        let z_hex = scalar_to_bytes(&self.z).to_lower_hex_string();
        serde_json::json!({
            "R": r_hex,
            "Z": z_hex
        })
    }
}

impl Round1Package {
    /// Deserialize from JSON (matching Dart Round1Package.fromJson).
    ///
    /// ```json
    /// {
    ///   "commitment": ["hex_point", ...],
    ///   "proofOfKnowledge": {"R": "hex", "Z": "hex"},
    ///   "verifyingKey": {"E": [byte, byte, ...]}
    /// }
    /// ```
    pub fn from_json(json: &str) -> Result<Self, Error> {
        let v: serde_json::Value =
            serde_json::from_str(json).map_err(|_| Error::SerializationError)?;
        Self::from_json_value(&v)
    }

    pub fn from_json_value(v: &serde_json::Value) -> Result<Self, Error> {
        let commitment = VssCommitment::from_json_value(&v["commitment"])?;
        let proof_of_knowledge = DkgSignature::from_json_value(&v["proofOfKnowledge"])?;

        // VerifyingKey: {"E": [byte, byte, ...]} — array of integers (33 compressed bytes)
        let e_arr = v["verifyingKey"]["E"]
            .as_array()
            .ok_or(Error::SerializationError)?;
        let mut e_bytes = [0u8; 33];
        if e_arr.len() != 33 {
            return Err(Error::SerializationError);
        }
        for (i, val) in e_arr.iter().enumerate() {
            e_bytes[i] = val.as_u64().ok_or(Error::SerializationError)? as u8;
        }
        let verifying_key = VerifyingKey::deserialize(&e_bytes)?;

        Ok(Self {
            commitment,
            proof_of_knowledge,
            verifying_key,
        })
    }

    /// Serialize to JSON (matching Dart Round1Package.toJson).
    pub fn to_json(&self) -> String {
        let v = self.to_json_value();
        serde_json::to_string(&v).unwrap_or_default()
    }

    pub fn to_json_value(&self) -> serde_json::Value {
        let vk_compressed = self.verifying_key.serialize();
        let e_arr: Vec<serde_json::Value> = vk_compressed
            .iter()
            .map(|&b| serde_json::Value::Number(serde_json::Number::from(b)))
            .collect();

        serde_json::json!({
            "commitment": self.commitment.to_json_value(),
            "proofOfKnowledge": self.proof_of_knowledge.to_json_value(),
            "verifyingKey": { "E": e_arr }
        })
    }
}

impl Round2Package {
    /// Deserialize from JSON: {"secretShare": "hex_scalar"}
    pub fn from_json(json: &str) -> Result<Self, Error> {
        let v: serde_json::Value =
            serde_json::from_str(json).map_err(|_| Error::SerializationError)?;
        Self::from_json_value(&v)
    }

    pub fn from_json_value(v: &serde_json::Value) -> Result<Self, Error> {
        let hex_str = v["secretShare"]
            .as_str()
            .ok_or(Error::SerializationError)?;
        let bytes = <[u8; 32]>::from_hex(hex_str)?;
        let secret_share = scalar_from_bytes(&bytes)?;
        Ok(Self { secret_share })
    }

    /// Serialize to JSON: {"secretShare": "hex_scalar"}
    pub fn to_json(&self) -> String {
        let v = self.to_json_value();
        serde_json::to_string(&v).unwrap_or_default()
    }

    pub fn to_json_value(&self) -> serde_json::Value {
        let hex_str = scalar_to_bytes(&self.secret_share).to_lower_hex_string();
        serde_json::json!({ "secretShare": hex_str })
    }
}
