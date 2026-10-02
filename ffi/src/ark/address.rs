//! Ark address derivation, for a wallet that has to do it itself.
//!
//! The cosigner used to derive these and hand them back over `GetArkAddress` / `GetBoardingAddress`
//! — two RPCs that did nothing but take a key the caller already held and run ark-core over it. Both
//! are gone, so the wallet needs its own copy.
//!
//! Lifted verbatim from `crates/ark/src/client/address.rs`, which is gated behind that crate's
//! `signing` feature. Raising this crate to `signing` would have been the obvious move and is the
//! wrong one: `signing` pulls `tonic-build` into `crates/ark`'s build script, so every cross-build
//! — four Android ABIs, iOS, the enclave — would need `protoc` on the build host to generate prost
//! types this library never calls. These three functions need only `ark_core` and `bitcoin`, both
//! already dependencies here.
//!
//! Reimplementing in Dart was never an option. Two divergent VTXO taptrees already exist in this
//! repository — `ark::default_vtxo_tree` writes the exit leaf as
//! `<owner> CHECKSIGVERIFY <raw delay> CSV DROP`, while `ark_core::Vtxo::new_default` writes
//! `<bip68 seq> CSV DROP <owner> CHECKSIG` — different opcode order, different sequence encoding,
//! different output key. A third guess means funds sent to an address nobody can spend. The parity
//! test at the bottom is what keeps this one honest.

use ark_core::{BoardingOutput, Vtxo};
use bitcoin::key::Secp256k1;
use bitcoin::Network;

use super::{read_cstr, FfiResult};
use std::os::raw::c_char;

/// The off-chain Ark address for this owner under this ASP.
#[no_mangle]
pub extern "C" fn ark_address(
    owner_pk_hex: *const c_char,
    asp_pk_hex: *const c_char,
    exit_delay: u32,
    network: *const c_char,
) -> *mut FfiResult {
    match derive(owner_pk_hex, asp_pk_hex, exit_delay, network, Kind::Ark) {
        Ok(s) => FfiResult::ok(&s),
        Err(e) => FfiResult::err(&e),
    }
}

/// The on-chain address funds are boarded through.
#[no_mangle]
pub extern "C" fn ark_boarding_address(
    owner_pk_hex: *const c_char,
    asp_pk_hex: *const c_char,
    exit_delay: u32,
    network: *const c_char,
) -> *mut FfiResult {
    match derive(owner_pk_hex, asp_pk_hex, exit_delay, network, Kind::Boarding) {
        Ok(s) => FfiResult::ok(&s),
        Err(e) => FfiResult::err(&e),
    }
}

/// The VTXO scriptPubKey (hex) this owner's VTXOs sit under.
///
/// What the indexer is queried with. A wallet has two — one per exit delay — because a boarded VTXO
/// keeps the boarding delay while received and refreshed ones use the unilateral delay.
#[no_mangle]
pub extern "C" fn ark_vtxo_script_pubkey_hex(
    owner_pk_hex: *const c_char,
    asp_pk_hex: *const c_char,
    exit_delay: u32,
    network: *const c_char,
) -> *mut FfiResult {
    match derive(owner_pk_hex, asp_pk_hex, exit_delay, network, Kind::Script) {
        Ok(s) => FfiResult::ok(&s),
        Err(e) => FfiResult::err(&e),
    }
}

enum Kind {
    Ark,
    Boarding,
    Script,
}

fn derive(
    owner_pk_hex: *const c_char,
    asp_pk_hex: *const c_char,
    exit_delay: u32,
    network: *const c_char,
    kind: Kind,
) -> Result<String, String> {
    let owner = read_cstr(owner_pk_hex).ok_or("owner_pk_hex is null or not UTF-8")?;
    let asp = read_cstr(asp_pk_hex).ok_or("asp_pk_hex is null or not UTF-8")?;
    let net = read_cstr(network).ok_or("network is null or not UTF-8")?;

    let secp = Secp256k1::new();
    let owner_pk = ark::keys::parse_xonly(&owner)?;
    let asp_pk = ark::keys::parse_xonly(&asp)?;
    let net = parse_network(&net)?;
    let exit_seq = ark_core::server::parse_sequence_number(exit_delay as i64)
        .map_err(|e| format!("parse_sequence_number: {e}"))?;

    match kind {
        Kind::Boarding => {
            let boarding = BoardingOutput::new(&secp, asp_pk, owner_pk, exit_seq, net)
                .map_err(|e| format!("BoardingOutput::new: {e}"))?;
            Ok(boarding.address().to_string())
        }
        Kind::Ark | Kind::Script => {
            let vtxo = Vtxo::new_default(&secp, asp_pk, owner_pk, exit_seq, net)
                .map_err(|e| format!("Vtxo::new_default: {e}"))?;
            Ok(match kind {
                Kind::Script => hex::encode(vtxo.script_pubkey().as_bytes()),
                _ => vtxo.to_ark_address().encode(),
            })
        }
    }
}

/// The ASP's network string. Kept identical to `ark::client::parse_network`, including the aliases:
/// a mutinynet deployment reports "mutinynet" and means signet.
fn parse_network(network: &str) -> Result<Network, String> {
    match network {
        "bitcoin" | "mainnet" => Ok(Network::Bitcoin),
        "testnet" | "testnet3" => Ok(Network::Testnet),
        "signet" | "mutinynet" => Ok(Network::Signet),
        "regtest" => Ok(Network::Regtest),
        _ => Err(format!("unknown network: {network}")),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// These must agree with `ark::client::address` for identical inputs, byte for byte.
    ///
    /// That parity is the whole reason this file is a lift rather than an implementation: the
    /// cosigner derives every output it signs from its own copy, and an address the wallet shows
    /// that the cosigner would not derive is an address nobody can spend from.
    #[test]
    fn parity_with_the_cosigners_derivation() {
        // A fixed keypair, so a change to either side shows up as a diff rather than as flakiness.
        let owner = "79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798";
        let asp = "c6047f9441ed7d6d3045406e95c07cd85c778e4b8cef3ca7abac09b95c709ee5";

        for network in ["bitcoin", "testnet", "signet", "regtest"] {
            let net = ark::client::parse_network(network).expect("network");
            for delay in [144u32, 512, 86016] {
                assert_eq!(
                    derive_str(owner, asp, delay, network, Kind::Ark),
                    ark::client::ark_address(owner, asp, delay, net),
                    "ark address diverged for {network}/{delay}"
                );
                assert_eq!(
                    derive_str(owner, asp, delay, network, Kind::Boarding),
                    ark::client::boarding_address(owner, asp, delay, net),
                    "boarding address diverged for {network}/{delay}"
                );
                assert_eq!(
                    derive_str(owner, asp, delay, network, Kind::Script),
                    ark::client::vtxo_script_pubkey_hex(owner, asp, delay, net),
                    "vtxo script diverged for {network}/{delay}"
                );
            }
        }
    }

    /// A compressed ASP key and its x-only form must derive the same address — the ASP publishes
    /// the former and wallets hold the latter, and they meet here.
    #[test]
    fn compressed_and_xonly_agree() {
        let owner = "79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798";
        let asp_x = "c6047f9441ed7d6d3045406e95c07cd85c778e4b8cef3ca7abac09b95c709ee5";
        let asp_c = format!("02{asp_x}");
        assert_eq!(
            derive_str(owner, asp_x, 144, "regtest", Kind::Ark),
            derive_str(owner, &asp_c, 144, "regtest", Kind::Ark),
        );
    }

    #[test]
    fn an_unknown_network_is_refused_rather_than_defaulted() {
        assert!(parse_network("mainnett").is_err());
        assert!(derive_str(
            "79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798",
            "c6047f9441ed7d6d3045406e95c07cd85c778e4b8cef3ca7abac09b95c709ee5",
            144,
            "liquid",
            Kind::Ark
        )
        .is_err());
    }

    /// Call `derive` without the C-string round trip.
    fn derive_str(
        owner: &str,
        asp: &str,
        delay: u32,
        network: &str,
        kind: Kind,
    ) -> Result<String, String> {
        let secp = Secp256k1::new();
        let owner_pk = ark::keys::parse_xonly(owner)?;
        let asp_pk = ark::keys::parse_xonly(asp)?;
        let net = parse_network(network)?;
        let exit_seq = ark_core::server::parse_sequence_number(delay as i64)
            .map_err(|e| format!("parse_sequence_number: {e}"))?;
        match kind {
            Kind::Boarding => BoardingOutput::new(&secp, asp_pk, owner_pk, exit_seq, net)
                .map(|b| b.address().to_string())
                .map_err(|e| format!("BoardingOutput::new: {e}")),
            Kind::Ark | Kind::Script => {
                let vtxo = Vtxo::new_default(&secp, asp_pk, owner_pk, exit_seq, net)
                    .map_err(|e| format!("Vtxo::new_default: {e}"))?;
                Ok(match kind {
                    Kind::Script => hex::encode(vtxo.script_pubkey().as_bytes()),
                    _ => vtxo.to_ark_address().encode(),
                })
            }
        }
    }
}
