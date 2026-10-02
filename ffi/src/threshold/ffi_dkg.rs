//! DKG and key refresh FFI functions.

use super::handles::box_handle;
use super::{read_cstr, FfiResult};
use std::collections::BTreeMap;
use std::os::raw::{c_char, c_void};

use rand::rngs::OsRng;
use threshold::dkg::{self, Round1Package, Round1SecretPackage, Round2Package, Round2SecretPackage};
use threshold::identifier::Identifier;
use threshold::scalar::scalar_from_bytes;
use threshold::random;

// ---------------------------------------------------------------------------
// Helpers: JSON <-> Rust types
// ---------------------------------------------------------------------------

fn parse_identifier_hex(hex: &str) -> Result<Identifier, String> {
    let bytes = crate::from_hex::<[u8; 32]>(hex).map_err(|e| format!("bad identifier hex: {e}"))?;
    Identifier::deserialize(&bytes).map_err(|e| format!("bad identifier: {e}"))
}

fn parse_scalar_hex(hex: &str) -> Result<k256::Scalar, String> {
    let bytes = crate::from_hex::<[u8; 32]>(hex).map_err(|e| format!("bad scalar hex: {e}"))?;
    scalar_from_bytes(&bytes).map_err(|e| format!("bad scalar: {e}"))
}

fn parse_round1_pkgs_json(
    json_str: &str,
) -> Result<BTreeMap<Identifier, Round1Package>, String> {
    let v: serde_json::Value =
        serde_json::from_str(json_str).map_err(|e| format!("bad JSON: {e}"))?;
    let obj = v.as_object().ok_or("expected JSON object")?;
    let mut map = BTreeMap::new();
    for (id_hex, pkg_val) in obj {
        let id = parse_identifier_hex(id_hex)?;
        let pkg =
            Round1Package::from_json_value(pkg_val).map_err(|e| format!("bad R1 pkg: {e}"))?;
        map.insert(id, pkg);
    }
    Ok(map)
}

fn parse_round2_pkgs_json(
    json_str: &str,
) -> Result<BTreeMap<Identifier, Round2Package>, String> {
    let v: serde_json::Value =
        serde_json::from_str(json_str).map_err(|e| format!("bad JSON: {e}"))?;
    let obj = v.as_object().ok_or("expected JSON object")?;
    let mut map = BTreeMap::new();
    for (id_hex, pkg_val) in obj {
        let id = parse_identifier_hex(id_hex)?;
        let pkg =
            Round2Package::from_json_value(pkg_val).map_err(|e| format!("bad R2 pkg: {e}"))?;
        map.insert(id, pkg);
    }
    Ok(map)
}

fn parse_identifier_list_json(json_str: &str) -> Result<Vec<Identifier>, String> {
    let v: serde_json::Value =
        serde_json::from_str(json_str).map_err(|e| format!("bad JSON: {e}"))?;
    let arr = v.as_array().ok_or("expected JSON array")?;
    let mut ids = Vec::new();
    for item in arr {
        let hex = item.as_str().ok_or("expected hex string in array")?;
        ids.push(parse_identifier_hex(hex)?);
    }
    Ok(ids)
}

fn serialize_round1_pkg(pkg: &Round1Package) -> String {
    serde_json::to_string(&pkg.to_json_value()).unwrap_or_default()
}

fn serialize_round2_pkgs(pkgs: &BTreeMap<Identifier, Round2Package>) -> String {
    let mut obj = serde_json::Map::new();
    for (id, pkg) in pkgs {
        let id_hex = hex::encode(id.serialize());
        obj.insert(id_hex, pkg.to_json_value());
    }
    serde_json::to_string(&serde_json::Value::Object(obj)).unwrap_or_default()
}

// ---------------------------------------------------------------------------
// DKG Part 1
// ---------------------------------------------------------------------------

/// DKG round 1: generate secret polynomial, commitment, and proof of knowledge.
///
/// - `secret_hex`: 64-char hex scalar (the participant's secret).
/// - `coefficients_json`: JSON array of hex scalars (length = min_signers - 1).
///
/// Returns FfiResult with:
/// - `data`: JSON of the Round1Package.
/// - `handle`: opaque Round1SecretPackage pointer.
#[no_mangle]
pub extern "C" fn threshold_dkg_part1(
    max_signers: u32,
    min_signers: u32,
    secret_hex: *const c_char,
    coefficients_json: *const c_char,
) -> *mut FfiResult {
    let result = (|| -> Result<(String, *mut c_void), String> {
        let secret_str = read_cstr(secret_hex).ok_or("null secret_hex")?;
        let coeffs_str = read_cstr(coefficients_json).ok_or("null coefficients_json")?;

        let secret = parse_scalar_hex(&secret_str)?;

        let coeffs_val: serde_json::Value =
            serde_json::from_str(&coeffs_str).map_err(|e| format!("bad coefficients JSON: {e}"))?;
        let coeffs_arr = coeffs_val.as_array().ok_or("coefficients must be array")?;
        let mut coefficients = Vec::new();
        for item in coeffs_arr {
            let hex = item.as_str().ok_or("coefficient must be hex string")?;
            coefficients.push(parse_scalar_hex(hex)?);
        }

        let mut rng = OsRng;
        let (secret_pkg, pub_pkg) = dkg::dkg_part1(
            max_signers as usize,
            min_signers as usize,
            &secret,
            &coefficients,
            &mut rng,
        )
        .map_err(|e| format!("dkg_part1 failed: {e}"))?;

        let data = serialize_round1_pkg(&pub_pkg);
        let handle = box_handle(secret_pkg);
        Ok((data, handle))
    })();

    match result {
        Ok((data, handle)) => FfiResult::ok_with_handle(&data, handle),
        Err(e) => FfiResult::err(&e),
    }
}

// ---------------------------------------------------------------------------
// DKG Part 2
// ---------------------------------------------------------------------------

/// DKG round 2: verify others' round 1 packages and compute shares.
///
/// - `r1_secret_handle`: opaque Round1SecretPackage pointer (borrowed, not consumed).
/// - `round1_pkgs_json`: JSON object { "id_hex": round1_package_json, ... }.
/// - `receiver_ids_json`: JSON array of hex identifiers (passive receivers).
///
/// Returns FfiResult with:
/// - `data`: JSON object of Round2Packages { "id_hex": round2_package_json, ... }.
/// - `handle`: opaque Round2SecretPackage pointer.
#[no_mangle]
pub extern "C" fn threshold_dkg_part2(
    r1_secret_handle: *mut c_void,
    round1_pkgs_json: *const c_char,
    receiver_ids_json: *const c_char,
) -> *mut FfiResult {
    let result = (|| -> Result<(String, *mut c_void), String> {
        let r1_secret = unsafe {
            super::handles::borrow_handle::<Round1SecretPackage>(r1_secret_handle)
        }
        .ok_or("null r1_secret_handle")?;

        let pkgs_str = read_cstr(round1_pkgs_json).ok_or("null round1_pkgs_json")?;
        let round1_pkgs = parse_round1_pkgs_json(&pkgs_str)?;

        let receiver_ids = if receiver_ids_json.is_null() {
            Vec::new()
        } else {
            let ids_str = read_cstr(receiver_ids_json).ok_or("bad receiver_ids_json")?;
            if ids_str.is_empty() || ids_str == "[]" {
                Vec::new()
            } else {
                parse_identifier_list_json(&ids_str)?
            }
        };

        let (r2_secret, r2_pkgs) =
            dkg::dkg_part2(r1_secret, &round1_pkgs, &receiver_ids)
                .map_err(|e| format!("dkg_part2 failed: {e}"))?;

        let data = serialize_round2_pkgs(&r2_pkgs);
        let handle = box_handle(r2_secret);
        Ok((data, handle))
    })();

    match result {
        Ok((data, handle)) => FfiResult::ok_with_handle(&data, handle),
        Err(e) => FfiResult::err(&e),
    }
}

// ---------------------------------------------------------------------------
// DKG Part 3
// ---------------------------------------------------------------------------

/// DKG round 3: verify received shares and compute final key package.
///
/// Returns FfiResult with:
/// - `data`: JSON { "key_package": kp_json, "public_key_package": pkp_json }.
#[no_mangle]
pub extern "C" fn threshold_dkg_part3(
    r1_secret_handle: *mut c_void,
    r2_secret_handle: *mut c_void,
    round1_pkgs_json: *const c_char,
    round2_pkgs_json: *const c_char,
    receiver_ids_json: *const c_char,
) -> *mut FfiResult {
    let result = (|| -> Result<String, String> {
        let r1_secret = unsafe {
            super::handles::borrow_handle::<Round1SecretPackage>(r1_secret_handle)
        }
        .ok_or("null r1_secret_handle")?;
        let r2_secret = unsafe {
            super::handles::borrow_handle::<Round2SecretPackage>(r2_secret_handle)
        }
        .ok_or("null r2_secret_handle")?;

        let r1_str = read_cstr(round1_pkgs_json).ok_or("null round1_pkgs_json")?;
        let r2_str = read_cstr(round2_pkgs_json).ok_or("null round2_pkgs_json")?;
        let round1_pkgs = parse_round1_pkgs_json(&r1_str)?;
        let round2_pkgs = parse_round2_pkgs_json(&r2_str)?;

        let receiver_ids = if receiver_ids_json.is_null() {
            Vec::new()
        } else {
            let ids_str = read_cstr(receiver_ids_json).ok_or("bad receiver_ids_json")?;
            if ids_str.is_empty() || ids_str == "[]" {
                Vec::new()
            } else {
                parse_identifier_list_json(&ids_str)?
            }
        };

        let (kp, pkp) =
            dkg::dkg_part3(r1_secret, r2_secret, &round1_pkgs, &round2_pkgs, &receiver_ids)
                .map_err(|e| format!("dkg_part3 failed: {e}"))?;

        let result = serde_json::json!({
            "key_package": serde_json::from_str::<serde_json::Value>(&kp.to_json()).unwrap_or_default(),
            "public_key_package": serde_json::from_str::<serde_json::Value>(&pkp.to_json()).unwrap_or_default(),
        });
        Ok(result.to_string())
    })();

    match result {
        Ok(data) => FfiResult::ok(&data),
        Err(e) => FfiResult::err(&e),
    }
}

// ---------------------------------------------------------------------------
// DKG Part 3 Receive (passive)
// ---------------------------------------------------------------------------

/// DKG round 3 for a passive receiver.
///
/// Returns FfiResult with:
/// - `data`: JSON { "key_package": kp_json, "public_key_package": pkp_json }.
#[no_mangle]
pub extern "C" fn threshold_dkg_part3_receive(
    my_id_hex: *const c_char,
    dealer_r1_json: *const c_char,
    shares_json: *const c_char,
    min_signers: u32,
    max_signers: u32,
    all_ids_json: *const c_char,
) -> *mut FfiResult {
    let result = (|| -> Result<String, String> {
        let id_str = read_cstr(my_id_hex).ok_or("null my_id_hex")?;
        let my_id = parse_identifier_hex(&id_str)?;

        let r1_str = read_cstr(dealer_r1_json).ok_or("null dealer_r1_json")?;
        let shares_str = read_cstr(shares_json).ok_or("null shares_json")?;
        let ids_str = read_cstr(all_ids_json).ok_or("null all_ids_json")?;

        let dealer_r1 = parse_round1_pkgs_json(&r1_str)?;
        let shares = parse_round2_pkgs_json(&shares_str)?;
        let all_ids = parse_identifier_list_json(&ids_str)?;

        let (kp, pkp) = dkg::dkg_part3_receive(
            &my_id,
            &dealer_r1,
            &shares,
            min_signers as usize,
            max_signers as usize,
            &all_ids,
        )
        .map_err(|e| format!("dkg_part3_receive failed: {e}"))?;

        let result = serde_json::json!({
            "key_package": serde_json::from_str::<serde_json::Value>(&kp.to_json()).unwrap_or_default(),
            "public_key_package": serde_json::from_str::<serde_json::Value>(&pkp.to_json()).unwrap_or_default(),
        });
        Ok(result.to_string())
    })();

    match result {
        Ok(data) => FfiResult::ok(&data),
        Err(e) => FfiResult::err(&e),
    }
}

// ---------------------------------------------------------------------------
// Key Refresh
// ---------------------------------------------------------------------------

/// Key refresh round 1.
///
/// - `id_hex`: this participant's identifier hex.
/// - `seed_ptr`/`seed_len`: optional seed for deterministic coefficients (null for random).
///
/// Returns FfiResult with:
/// - `data`: JSON of the Round1Package.
/// - `handle`: opaque Round1SecretPackage pointer.
#[no_mangle]
pub extern "C" fn threshold_dkg_refresh_part1(
    id_hex: *const c_char,
    max_signers: u32,
    min_signers: u32,
    seed_ptr: *const u8,
    seed_len: u32,
) -> *mut FfiResult {
    let result = (|| -> Result<(String, *mut c_void), String> {
        let id_str = read_cstr(id_hex).ok_or("null id_hex")?;
        let identifier = parse_identifier_hex(&id_str)?;

        let mut rng = OsRng;
        let coefficients = if !seed_ptr.is_null() && seed_len > 0 {
            let seed = super::read_bytes(seed_ptr, seed_len).ok_or("bad seed")?;
            random::generate_coefficients_seeded(min_signers as usize - 1, &seed)
        } else {
            random::generate_coefficients(min_signers as usize - 1, &mut rng)
        };

        let (secret_pkg, pub_pkg) = dkg::dkg_refresh_part1(
            &identifier,
            max_signers as usize,
            min_signers as usize,
            &coefficients,
            &mut rng,
        )
        .map_err(|e| format!("dkg_refresh_part1 failed: {e}"))?;

        // Return coefficients alongside the round1 package so the Dart side
        // can call evaluatePolynomial for protected-key derivation.
        let coeffs_hex: Vec<serde_json::Value> = secret_pkg.coefficients.iter()
            .map(|c| serde_json::Value::String(hex::encode(threshold::scalar::scalar_to_bytes(c))))
            .collect();
        let r1_pkg_val: serde_json::Value = serde_json::from_str(&serialize_round1_pkg(&pub_pkg))
            .unwrap_or_default();
        let data = serde_json::json!({
            "round1Package": r1_pkg_val,
            "coefficients": coeffs_hex,
        }).to_string();
        let handle = box_handle(secret_pkg);
        Ok((data, handle))
    })();

    match result {
        Ok((data, handle)) => FfiResult::ok_with_handle(&data, handle),
        Err(e) => FfiResult::err(&e),
    }
}

/// Key refresh round 2.
#[no_mangle]
pub extern "C" fn threshold_dkg_refresh_part2(
    r1_secret_handle: *mut c_void,
    round1_pkgs_json: *const c_char,
) -> *mut FfiResult {
    let result = (|| -> Result<(String, *mut c_void), String> {
        let r1_secret = unsafe {
            super::handles::borrow_handle::<Round1SecretPackage>(r1_secret_handle)
        }
        .ok_or("null r1_secret_handle")?;

        let pkgs_str = read_cstr(round1_pkgs_json).ok_or("null round1_pkgs_json")?;
        let round1_pkgs = parse_round1_pkgs_json(&pkgs_str)?;

        let (r2_secret, r2_pkgs) =
            dkg::dkg_refresh_part2(r1_secret, &round1_pkgs)
                .map_err(|e| format!("dkg_refresh_part2 failed: {e}"))?;

        let data = serialize_round2_pkgs(&r2_pkgs);
        let handle = box_handle(r2_secret);
        Ok((data, handle))
    })();

    match result {
        Ok((data, handle)) => FfiResult::ok_with_handle(&data, handle),
        Err(e) => FfiResult::err(&e),
    }
}

/// Key refresh round 3.
#[no_mangle]
pub extern "C" fn threshold_dkg_refresh_part3(
    r2_secret_handle: *mut c_void,
    round1_pkgs_json: *const c_char,
    round2_pkgs_json: *const c_char,
    old_pkp_json: *const c_char,
    old_kp_json: *const c_char,
) -> *mut FfiResult {
    let result = (|| -> Result<String, String> {
        let r2_secret = unsafe {
            super::handles::borrow_handle::<Round2SecretPackage>(r2_secret_handle)
        }
        .ok_or("null r2_secret_handle")?;

        let r1_str = read_cstr(round1_pkgs_json).ok_or("null round1_pkgs_json")?;
        let r2_str = read_cstr(round2_pkgs_json).ok_or("null round2_pkgs_json")?;
        let old_pkp_str = read_cstr(old_pkp_json).ok_or("null old_pkp_json")?;
        let old_kp_str = read_cstr(old_kp_json).ok_or("null old_kp_json")?;

        let round1_pkgs = parse_round1_pkgs_json(&r1_str)?;
        let round2_pkgs = parse_round2_pkgs_json(&r2_str)?;

        let old_pkp = threshold::keys::PublicKeyPackage::from_json(&old_pkp_str)
            .map_err(|e| format!("bad old PKP: {e}"))?;
        let old_kp = threshold::keys::KeyPackage::from_json(&old_kp_str)
            .map_err(|e| format!("bad old KP: {e}"))?;

        let (kp, pkp) = dkg::dkg_refresh_part3(
            r2_secret,
            &round1_pkgs,
            &round2_pkgs,
            &old_pkp,
            &old_kp,
        )
        .map_err(|e| format!("dkg_refresh_part3 failed: {e}"))?;

        let result = serde_json::json!({
            "key_package": serde_json::from_str::<serde_json::Value>(&kp.to_json()).unwrap_or_default(),
            "public_key_package": serde_json::from_str::<serde_json::Value>(&pkp.to_json()).unwrap_or_default(),
        });
        Ok(result.to_string())
    })();

    match result {
        Ok(data) => FfiResult::ok(&data),
        Err(e) => FfiResult::err(&e),
    }
}

/// Key-preserving REFRESH of a single holder's share toward two recipient ids.
///
/// Deals THIS holder's additive piece `x = λ · secret_share` (over `id_set`) as the
/// constant term of a degree-1 polynomial `s(t) = x + slope·t`, then evaluates it at
/// the participant id and the cosigner id. The caller supplies `slope` (rather than
/// the crate's internal random coefficient) so the same polynomial yields both the
/// scalar slice it keeps/sends AND the matching `·G` point — deterministic across the
/// wallet's own calls. When every current holder does this with `min_signers = 2` and
/// the per-id slices are summed, the recipients hold a fresh 2-of-n sharing of the SAME
/// key. Used by `createEvtxoKey` to refresh `V` onto the {service, cosigner} pairing.
///
/// Inputs: `kp_json` (holder KeyPackage), `id_set_json` (JSON array of current-holder
/// identifier hex), `participant_hex` / `cosigner_hex` (32-byte recipient id scalars),
/// `slope_hex` (32-byte scalar). Returns JSON `{at_participant, at_cosigner}` (hex 32B).
#[no_mangle]
pub extern "C" fn threshold_refresh_share_to_id(
    kp_json: *const c_char,
    id_set_json: *const c_char,
    participant_hex: *const c_char,
    cosigner_hex: *const c_char,
    slope_hex: *const c_char,
) -> *mut FfiResult {
    let result = (|| -> Result<String, String> {
        let kp_str = read_cstr(kp_json).ok_or("null kp_json")?;
        let id_set_str = read_cstr(id_set_json).ok_or("null id_set_json")?;
        let participant_str = read_cstr(participant_hex).ok_or("null participant_hex")?;
        let cosigner_str = read_cstr(cosigner_hex).ok_or("null cosigner_hex")?;
        let slope_str = read_cstr(slope_hex).ok_or("null slope_hex")?;

        let kp = threshold::keys::KeyPackage::from_json(&kp_str)
            .map_err(|e| format!("bad KP: {e}"))?;

        let id_list: Vec<String> = serde_json::from_str(&id_set_str)
            .map_err(|e| format!("bad id_set JSON: {e}"))?;
        let id_set: Vec<Identifier> = id_list
            .iter()
            .map(|h| parse_identifier_hex(h))
            .collect::<Result<_, _>>()?;

        let participant_id = parse_identifier_hex(&participant_str)?;
        let cosigner_id = parse_identifier_hex(&cosigner_str)?;
        let slope = parse_scalar_hex(&slope_str)?;

        // s(t) = (λ · secret_share) + slope·t, evaluated at each recipient id.
        let lambda = threshold::lagrange::lagrange_coeff_at_zero(&kp.identifier, &id_set);
        let coeffs = vec![lambda * kp.secret_share, slope];
        let at_participant =
            threshold::polynomial::evaluate_polynomial(&participant_id, &coeffs);
        let at_cosigner =
            threshold::polynomial::evaluate_polynomial(&cosigner_id, &coeffs);

        let data = serde_json::json!({
            "at_participant": hex::encode(threshold::scalar::scalar_to_bytes(&at_participant)),
            "at_cosigner": hex::encode(threshold::scalar::scalar_to_bytes(&at_cosigner)),
        })
        .to_string();
        Ok(data)
    })();

    match result {
        Ok(data) => FfiResult::ok(&data),
        Err(e) => FfiResult::err(&e),
    }
}

// ---------------------------------------------------------------------------
// eVTXO key resharing
// ---------------------------------------------------------------------------

/// Resharing round 1 from an EXPLICIT polynomial, the way `threshold_dkg_part1` takes one.
///
/// The seeded sibling below draws its constant term from the RNG and expands its coefficients from
/// a caller's seed — two different derivations, one of them the improvised expander
/// `SECURITY_FINDINGS` TH-6 flags. A wallet minting an escrow needs neither: its delta comes from
/// the passkey through the same labelled HKDF as everything else it holds, so it arrives here as
/// scalars and is used as given. That is what makes an escrow share rebuildable on another device.
///
/// - `secret_hex`: 64-char hex scalar (the delta's constant term — NON-zero, so the key moves).
/// - `coefficients_json`: JSON array of hex scalars (length = min_signers - 1).
#[no_mangle]
pub extern "C" fn threshold_dkg_reshare_part1_from(
    id_hex: *const c_char,
    max_signers: u32,
    min_signers: u32,
    secret_hex: *const c_char,
    coefficients_json: *const c_char,
) -> *mut FfiResult {
    let result = (|| -> Result<(String, *mut c_void), String> {
        let id_str = read_cstr(id_hex).ok_or("null id_hex")?;
        let identifier = parse_identifier_hex(&id_str)?;
        let secret_str = read_cstr(secret_hex).ok_or("null secret_hex")?;
        let coeffs_str = read_cstr(coefficients_json).ok_or("null coefficients_json")?;

        let secret = parse_scalar_hex(&secret_str)?;
        let coeffs_val: serde_json::Value =
            serde_json::from_str(&coeffs_str).map_err(|e| format!("bad coefficients JSON: {e}"))?;
        let coeffs_arr = coeffs_val.as_array().ok_or("coefficients must be array")?;
        let mut coefficients = Vec::new();
        for item in coeffs_arr {
            let hex = item.as_str().ok_or("coefficient must be hex string")?;
            coefficients.push(parse_scalar_hex(hex)?);
        }

        let mut rng = OsRng;
        let (secret_pkg, pub_pkg) = dkg::dkg_reshare_part1(
            &identifier,
            max_signers as usize,
            min_signers as usize,
            &secret,
            &coefficients,
            &mut rng,
        )
        .map_err(|e| format!("dkg_reshare_part1 failed: {e}"))?;

        let data = serialize_round1_pkg(&pub_pkg);
        let handle = box_handle(secret_pkg);
        Ok((data, handle))
    })();

    match result {
        Ok((data, handle)) => FfiResult::ok_with_handle(&data, handle),
        Err(e) => FfiResult::err(&e),
    }
}

/// eVTXO reshare round 1: deal a fresh NON-zero polynomial under an EXPLICIT
/// identifier (the dealer's existing identity). Used by the signer (hardware /
/// software). Round 2 then uses the regular `threshold_dkg_part2`.
#[no_mangle]
pub extern "C" fn threshold_dkg_reshare_part1(
    id_hex: *const c_char,
    max_signers: u32,
    min_signers: u32,
    seed_ptr: *const u8,
    seed_len: u32,
) -> *mut FfiResult {
    let result = (|| -> Result<(String, *mut c_void), String> {
        let id_str = read_cstr(id_hex).ok_or("null id_hex")?;
        let identifier = parse_identifier_hex(&id_str)?;

        let mut rng = OsRng;
        let secret = random::mod_n_random(&mut rng);
        let coefficients = if !seed_ptr.is_null() && seed_len > 0 {
            let seed = super::read_bytes(seed_ptr, seed_len).ok_or("bad seed")?;
            random::generate_coefficients_seeded(min_signers as usize - 1, &seed)
        } else {
            random::generate_coefficients(min_signers as usize - 1, &mut rng)
        };

        let (secret_pkg, pub_pkg) = dkg::dkg_reshare_part1(
            &identifier,
            max_signers as usize,
            min_signers as usize,
            &secret,
            &coefficients,
            &mut rng,
        )
        .map_err(|e| format!("dkg_reshare_part1 failed: {e}"))?;

        let r1_pkg_val: serde_json::Value =
            serde_json::from_str(&serialize_round1_pkg(&pub_pkg)).unwrap_or_default();
        let data = serde_json::json!({ "round1Package": r1_pkg_val }).to_string();
        let handle = box_handle(secret_pkg);
        Ok((data, handle))
    })();

    match result {
        Ok((data, handle)) => FfiResult::ok_with_handle(&data, handle),
        Err(e) => FfiResult::err(&e),
    }
}

/// eVTXO reshare finalizer for a DEALER (e.g. the author): combine this dealer's
/// own dealing (`r2_secret` handle) with the peer dealers' round1 packages and the
/// shares dealt to this dealer, plus the old share, into the new `V′` key package +
/// PKP. Mirrors `dkg_reshare_part3` in the threshold crate. `min_signers` is taken
/// from the handle, so it is not a parameter here.
#[no_mangle]
pub extern "C" fn threshold_dkg_reshare_part3(
    r2_secret_handle: *mut c_void,
    round1_pkgs_json: *const c_char,
    round2_pkgs_json: *const c_char,
    old_pkp_json: *const c_char,
    old_kp_json: *const c_char,
    receiver_ids_json: *const c_char,
) -> *mut FfiResult {
    let result = (|| -> Result<String, String> {
        let r2_secret = unsafe {
            super::handles::borrow_handle::<Round2SecretPackage>(r2_secret_handle)
        }
        .ok_or("null r2_secret_handle")?;

        let r1_str = read_cstr(round1_pkgs_json).ok_or("null round1_pkgs_json")?;
        let r2_str = read_cstr(round2_pkgs_json).ok_or("null round2_pkgs_json")?;
        let old_pkp_str = read_cstr(old_pkp_json).ok_or("null old_pkp_json")?;
        let old_kp_str = read_cstr(old_kp_json).ok_or("null old_kp_json")?;

        let round1_pkgs = parse_round1_pkgs_json(&r1_str)?;
        let round2_pkgs = parse_round2_pkgs_json(&r2_str)?;
        let old_pkp = threshold::keys::PublicKeyPackage::from_json(&old_pkp_str)
            .map_err(|e| format!("bad old PKP: {e}"))?;
        let old_kp = threshold::keys::KeyPackage::from_json(&old_kp_str)
            .map_err(|e| format!("bad old KP: {e}"))?;

        let receiver_ids = if receiver_ids_json.is_null() {
            Vec::new()
        } else {
            let ids_str = read_cstr(receiver_ids_json).ok_or("bad receiver_ids_json")?;
            if ids_str.is_empty() || ids_str == "[]" {
                Vec::new()
            } else {
                parse_identifier_list_json(&ids_str)?
            }
        };

        let (kp, pkp) = dkg::dkg_reshare_part3(
            r2_secret,
            &round1_pkgs,
            &round2_pkgs,
            &old_pkp,
            &old_kp,
            &receiver_ids,
        )
        .map_err(|e| format!("dkg_reshare_part3 failed: {e}"))?;

        let result = serde_json::json!({
            "key_package": serde_json::from_str::<serde_json::Value>(&kp.to_json()).unwrap_or_default(),
            "public_key_package": serde_json::from_str::<serde_json::Value>(&pkp.to_json()).unwrap_or_default(),
        });
        Ok(result.to_string())
    })();

    match result {
        Ok(data) => FfiResult::ok(&data),
        Err(e) => FfiResult::err(&e),
    }
}

/// eVTXO reshare finalizer for a pure receiver (the wallet): combine the dealers'
/// shares with the old share into a new 2-of-2 `V′` key package + PKP. Mirrors
/// `dkg_reshare_part3_receive` in the threshold crate.
#[no_mangle]
pub extern "C" fn threshold_dkg_reshare_part3_receive(
    my_id_hex: *const c_char,
    dealer_r1_json: *const c_char,
    shares_json: *const c_char,
    old_pkp_json: *const c_char,
    old_kp_json: *const c_char,
    receiver_ids_json: *const c_char,
    min_signers: u32,
) -> *mut FfiResult {
    let result = (|| -> Result<String, String> {
        let id_str = read_cstr(my_id_hex).ok_or("null my_id_hex")?;
        let my_id = parse_identifier_hex(&id_str)?;

        let r1_str = read_cstr(dealer_r1_json).ok_or("null dealer_r1_json")?;
        let shares_str = read_cstr(shares_json).ok_or("null shares_json")?;
        let old_pkp_str = read_cstr(old_pkp_json).ok_or("null old_pkp_json")?;
        let old_kp_str = read_cstr(old_kp_json).ok_or("null old_kp_json")?;
        let ids_str = read_cstr(receiver_ids_json).ok_or("null receiver_ids_json")?;

        let dealer_r1 = parse_round1_pkgs_json(&r1_str)?;
        let shares = parse_round2_pkgs_json(&shares_str)?;
        let receiver_ids = parse_identifier_list_json(&ids_str)?;
        let old_pkp = threshold::keys::PublicKeyPackage::from_json(&old_pkp_str)
            .map_err(|e| format!("bad old PKP: {e}"))?;
        let old_kp = threshold::keys::KeyPackage::from_json(&old_kp_str)
            .map_err(|e| format!("bad old KP: {e}"))?;

        let (kp, pkp) = dkg::dkg_reshare_part3_receive(
            &my_id,
            &dealer_r1,
            &shares,
            &old_pkp,
            &old_kp,
            &receiver_ids,
            min_signers as usize,
        )
        .map_err(|e| format!("dkg_reshare_part3_receive failed: {e}"))?;

        let result = serde_json::json!({
            "key_package": serde_json::from_str::<serde_json::Value>(&kp.to_json()).unwrap_or_default(),
            "public_key_package": serde_json::from_str::<serde_json::Value>(&pkp.to_json()).unwrap_or_default(),
        });
        Ok(result.to_string())
    })();

    match result {
        Ok(data) => FfiResult::ok(&data),
        Err(e) => FfiResult::err(&e),
    }
}
