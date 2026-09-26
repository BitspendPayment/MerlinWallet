//! The unilateral exit, for the wallet side.
//!
//! Thin JSON wrappers over `ark::exit`, which the cosigner calls directly. Same code on both
//! sides on purpose: the cosigner builds the exit it is about to sign, the wallet rebuilds it and
//! refuses to sign unless the sighashes match. Two implementations would be two chances to sign a
//! transaction nobody checked.
//!
//! Enabled through `ark`'s `exit` feature, which pulls only `ark-core` and `bitcoin` — not
//! `signing`, whose build script wants `protoc` on every Android, iOS and enclave build host.

use ark::exit::{self, ExitInput};
use bitcoin::consensus::{deserialize, encode::serialize_hex};
use bitcoin::script::ScriptBuf;
use bitcoin::taproot::ControlBlock;
use bitcoin::address::{Address, NetworkUnchecked};
use bitcoin::{Network, Transaction, XOnlyPublicKey};
use std::str::FromStr;
use serde::{Deserialize, Serialize};
use std::os::raw::c_char;

use super::{read_cstr, FfiResult};

#[derive(Deserialize)]
struct SpendInfoParams {
    owner_pk: String,
    asp_pk: String,
    exit_delay: u32,
    network: String,
}

#[derive(Serialize)]
struct SpendInfoResult {
    script: String,
    control_block: String,
    script_pubkey: String,
    sequence: u32,
}

#[derive(Deserialize)]
struct BuildParams {
    owner_pk: String,
    asp_pk: String,
    network: String,
    txid: String,
    vout: u32,
    amount_sats: u64,
    exit_delay: u32,
    /// Where the money goes: a scriptPubKey, hex. The wallet derives it from the address the user
    /// gave at onboarding.
    destination_script_pubkey: String,
}

#[derive(Serialize)]
struct BuildResult {
    /// What the 2-of-2 signs.
    sighash: String,
    unsigned_tx: String,
    script: String,
    control_block: String,
    sequence: u32,
}

#[derive(Deserialize)]
struct VerifyParams {
    /// What the wallet built and signed.
    unsigned_tx: String,
    sighash: String,
    script: String,
    control_block: String,
    /// The wallet's group key, x-only — the 2-of-2 the exit leaf names.
    owner_pk: String,
    /// What the cosigner returned.
    raw_tx: String,
}

#[derive(Deserialize)]
struct FinalizeParams {
    unsigned_tx: String,
    script: String,
    control_block: String,
    /// 64 bytes of BIP-340, from the completed FROST round.
    signature: String,
}

/// The scriptPubKey of an ordinary on-chain address, and whether it is usable at all.
///
/// This is how an exit address becomes something to pay: the user types an address, and it is
/// checked here, once, against the network the ASP says it is on — a mainnet address on a signet
/// wallet, or a typo, is an exit that would never be spendable, found at the moment it is entered
/// rather than the moment it is needed.
#[no_mangle]
pub extern "C" fn ark_onchain_script_pubkey(
    address: *const c_char,
    network: *const c_char,
) -> *mut FfiResult {
    match script_pubkey_of(address, network) {
        Ok(s) => FfiResult::ok(&s),
        Err(e) => FfiResult::err(&e),
    }
}

fn script_pubkey_of(address: *const c_char, network: *const c_char) -> Result<String, String> {
    let address = read_cstr(address).ok_or("address is null or not UTF-8")?;
    let net = parse_network(&read_cstr(network).ok_or("network is null or not UTF-8")?)?;
    let parsed = Address::<NetworkUnchecked>::from_str(address.trim())
        .map_err(|e| format!("not a Bitcoin address: {e}"))?
        .require_network(net)
        .map_err(|_| format!("that address is not a {net} address"))?;
    Ok(hex::encode(parsed.script_pubkey().as_bytes()))
}

/// The exit leaf, its control block, the scriptPubKey it sits under, and the nSequence its spend
/// must carry. `ark_exit_spend_info` is the older, unusable one — see `ark::exit`.
#[no_mangle]
pub extern "C" fn ark_vtxo_exit_spend_info(params_json: *const c_char) -> *mut FfiResult {
    match spend_info(params_json) {
        Ok(s) => FfiResult::ok(&s),
        Err(e) => FfiResult::err(&e),
    }
}

/// Build the exit spend of one VTXO. Returns the unsigned transaction and its sighash.
#[no_mangle]
pub extern "C" fn ark_build_exit_tx(params_json: *const c_char) -> *mut FfiResult {
    match build(params_json) {
        Ok(s) => FfiResult::ok(&s),
        Err(e) => FfiResult::err(&e),
    }
}

/// Check an exit the cosigner returned against the one the wallet built, and return its txid.
///
/// The wallet asked for a signature over *its own* sighash; this is where it confirms it got back
/// exactly that transaction, signed. Anything else — a different destination, a different amount,
/// a witness that does not satisfy the leaf — is a cosigner returning something other than what
/// the round was about, and is refused before it is stored.
///
/// The txid comes from here rather than over the wire because it is derivable from bytes the
/// wallet has already checked: being told an identity it could compute is a dependency worth not
/// having, and a wrong one would send its owner looking for a transaction that does not exist.
#[no_mangle]
pub extern "C" fn ark_verify_exit_tx(params_json: *const c_char) -> *mut FfiResult {
    match verify(params_json) {
        Ok(txid) => FfiResult::ok(&txid),
        Err(e) => FfiResult::err(&e),
    }
}

/// Put the signature into the witness. Returns the raw transaction, hex, ready to broadcast.
#[no_mangle]
pub extern "C" fn ark_finalize_exit_tx(params_json: *const c_char) -> *mut FfiResult {
    match finalize(params_json) {
        Ok(s) => FfiResult::ok(&s),
        Err(e) => FfiResult::err(&e),
    }
}

fn spend_info(params_json: *const c_char) -> Result<String, String> {
    let params: SpendInfoParams = parse(params_json)?;
    let (script, control_block, script_pubkey, sequence) = exit::exit_spend_info(
        xonly(&params.asp_pk)?,
        xonly(&params.owner_pk)?,
        params.exit_delay,
        parse_network(&params.network)?,
    )?;
    json(&SpendInfoResult {
        script: hex::encode(script.as_bytes()),
        control_block: hex::encode(control_block.serialize()),
        script_pubkey: hex::encode(script_pubkey.as_bytes()),
        sequence,
    })
}

fn build(params_json: *const c_char) -> Result<String, String> {
    let params: BuildParams = parse(params_json)?;
    let input = ExitInput {
        txid: params
            .txid
            .parse()
            .map_err(|e| format!("invalid vtxo txid: {e}"))?,
        vout: params.vout,
        amount_sats: params.amount_sats,
        exit_delay: params.exit_delay,
    };
    let destination = ScriptBuf::from_bytes(decode(&params.destination_script_pubkey)?);
    let spend = exit::build_exit_tx(
        xonly(&params.asp_pk)?,
        xonly(&params.owner_pk)?,
        parse_network(&params.network)?,
        &input,
        &destination,
    )?;
    json(&BuildResult {
        sighash: hex::encode(spend.sighash),
        unsigned_tx: serialize_hex(&spend.tx),
        script: hex::encode(spend.script.as_bytes()),
        control_block: hex::encode(spend.control_block.serialize()),
        sequence: spend.sequence,
    })
}

fn finalize(params_json: *const c_char) -> Result<String, String> {
    let params: FinalizeParams = parse(params_json)?;
    let tx: Transaction = deserialize(&decode(&params.unsigned_tx)?)
        .map_err(|e| format!("the unsigned exit does not parse: {e}"))?;
    let control_block = ControlBlock::decode(&decode(&params.control_block)?)
        .map_err(|e| format!("invalid control block: {e}"))?;
    let spend = exit::ExitSpend {
        sequence: tx.input.first().map(|i| i.sequence.to_consensus_u32()).unwrap_or(0),
        tx,
        // Only the witness is assembled here, and the sighash is not part of it.
        sighash: [0u8; 32],
        script: ScriptBuf::from_bytes(decode(&params.script)?),
        control_block,
    };
    let raw = exit::finalize_exit_tx(&spend, &decode(&params.signature)?)?;
    Ok(hex::encode(raw))
}

fn verify(params_json: *const c_char) -> Result<String, String> {
    let params: VerifyParams = parse(params_json)?;
    let expected: Transaction = deserialize(&decode(&params.unsigned_tx)?)
        .map_err(|e| format!("the wallet's own exit does not parse: {e}"))?;
    let signed: Transaction = deserialize(&decode(&params.raw_tx)?)
        .map_err(|e| format!("the returned exit does not parse: {e}"))?;

    // Same transaction, witness aside: same input, same outputs, same sequence, same version.
    let mut stripped = signed.clone();
    for input in stripped.input.iter_mut() {
        input.witness = bitcoin::Witness::new();
    }
    if stripped != expected {
        return Err("the returned exit is not the transaction the wallet signed".to_string());
    }

    let witness = &signed.input[0].witness;
    if witness.len() != 3 {
        return Err(format!(
            "an exit witness is a signature, a leaf and a control block, got {} items",
            witness.len()
        ));
    }
    if witness.nth(1) != Some(&decode(&params.script)?[..])
        || witness.nth(2) != Some(&decode(&params.control_block)?[..])
    {
        return Err("the returned exit names a different leaf".to_string());
    }

    // And the signature is real: the 2-of-2's, over the sighash the wallet computed.
    let signature = witness.nth(0).ok_or("no signature in the exit witness")?;
    let signature = bitcoin::secp256k1::schnorr::Signature::from_slice(signature)
        .map_err(|e| format!("the exit's signature is malformed: {e}"))?;
    let sighash: [u8; 32] = decode(&params.sighash)?
        .try_into()
        .map_err(|_| "a sighash is 32 bytes".to_string())?;
    bitcoin::secp256k1::Secp256k1::verification_only()
        .verify_schnorr(
            &signature,
            &bitcoin::secp256k1::Message::from_digest(sighash),
            &xonly(&params.owner_pk)?,
        )
        .map_err(|e| format!("the exit is not signed by this wallet's key: {e}"))?;

    // A witness cannot change a txid, so this is the same before and after signing.
    Ok(signed.compute_txid().to_string())
}

fn parse<T: serde::de::DeserializeOwned>(params_json: *const c_char) -> Result<T, String> {
    let raw = read_cstr(params_json).ok_or("params are null or not UTF-8")?;
    serde_json::from_str(&raw).map_err(|e| format!("JSON parse: {e}"))
}

fn json<T: Serialize>(value: &T) -> Result<String, String> {
    serde_json::to_string(value).map_err(|e| format!("JSON serialize: {e}"))
}

fn decode(s: &str) -> Result<Vec<u8>, String> {
    hex::decode(s).map_err(|e| format!("invalid hex: {e}"))
}

/// x-only (64 hex) or compressed (66) — the ASP publishes compressed, a wallet's own key is
/// x-only, and both reach here. Same rule as `ark::client::address`.
fn xonly(s: &str) -> Result<XOnlyPublicKey, String> {
    let s = if s.len() == 66 && (s.starts_with("02") || s.starts_with("03")) {
        &s[2..]
    } else {
        s
    };
    XOnlyPublicKey::from_slice(&decode(s)?).map_err(|e| format!("invalid x-only pubkey: {e}"))
}

fn parse_network(name: &str) -> Result<Network, String> {
    match name {
        "bitcoin" | "mainnet" => Ok(Network::Bitcoin),
        "testnet" | "testnet3" => Ok(Network::Testnet),
        "signet" | "mutinynet" => Ok(Network::Signet),
        "regtest" => Ok(Network::Regtest),
        _ => Err(format!("unknown network: {name}")),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::ffi::CString;

    const ASP: &str = "0250929b74c1a04954b78b4b6035e97a5e078a5a0f28ec96d547bfee9ace803ac0";
    const OWNER: &str = "79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798";

    fn call(
        f: extern "C" fn(*const c_char) -> *mut FfiResult,
        params: &str,
    ) -> Result<String, String> {
        let c = CString::new(params).unwrap();
        let ptr = f(c.as_ptr());
        let result = unsafe { &*ptr };
        let out = if result.success {
            Ok(unsafe { CStr::from_ptr(result.data) }.to_string_lossy().into_owned())
        } else {
            Err(unsafe { CStr::from_ptr(result.error) }.to_string_lossy().into_owned())
        };
        super::super::ark_free_result(ptr);
        out
    }
    use std::ffi::CStr;

    fn build_params(amount: u64) -> String {
        format!(
            r#"{{"owner_pk":"{OWNER}","asp_pk":"{ASP}","network":"regtest",
                 "txid":"34fcce0000000000000000000000000000000000000000000000000000000000",
                 "vout":0,"amount_sats":{amount},"exit_delay":86016,
                 "destination_script_pubkey":"5120{}"}}"#,
            "ab".repeat(32)
        )
    }

    /// What the wallet does before signing: build the same exit the cosigner did, and compare.
    #[test]
    fn building_twice_gives_the_same_sighash() {
        let first = call(ark_build_exit_tx, &build_params(130_000)).unwrap();
        let second = call(ark_build_exit_tx, &build_params(130_000)).unwrap();
        assert_eq!(first, second);
        assert!(first.contains("\"sequence\""));
    }

    /// A different amount is a different transaction — the comparison has to notice.
    #[test]
    fn a_different_amount_is_a_different_sighash() {
        let a: serde_json::Value =
            serde_json::from_str(&call(ark_build_exit_tx, &build_params(130_000)).unwrap()).unwrap();
        let b: serde_json::Value =
            serde_json::from_str(&call(ark_build_exit_tx, &build_params(120_000)).unwrap()).unwrap();
        assert_ne!(a["sighash"], b["sighash"]);
    }

    #[test]
    fn the_spend_info_matches_what_the_build_used() {
        let info: serde_json::Value = serde_json::from_str(
            &call(
                ark_vtxo_exit_spend_info,
                &format!(
                    r#"{{"owner_pk":"{OWNER}","asp_pk":"{ASP}","exit_delay":86016,"network":"regtest"}}"#
                ),
            )
            .unwrap(),
        )
        .unwrap();
        let built: serde_json::Value =
            serde_json::from_str(&call(ark_build_exit_tx, &build_params(130_000)).unwrap()).unwrap();
        assert_eq!(info["script"], built["script"]);
        assert_eq!(info["control_block"], built["control_block"]);
        assert_eq!(info["sequence"], built["sequence"]);
    }

    #[test]
    fn finalizing_produces_a_transaction_with_the_witness_in_it() {
        let built: serde_json::Value =
            serde_json::from_str(&call(ark_build_exit_tx, &build_params(130_000)).unwrap()).unwrap();
        let raw = call(
            ark_finalize_exit_tx,
            &format!(
                r#"{{"unsigned_tx":{},"script":{},"control_block":{},"signature":"{}"}}"#,
                built["unsigned_tx"], built["script"], built["control_block"], "cd".repeat(64)
            ),
        )
        .unwrap();
        let tx: Transaction = deserialize(&hex::decode(&raw).unwrap()).unwrap();
        assert_eq!(tx.input[0].witness.len(), 3);
        assert_eq!(tx.output.len(), 2);
    }

    /// The check the wallet runs on what comes back: it must be its own transaction, signed by the
    /// 2-of-2, and nothing else.
    #[test]
    fn verification_accepts_our_own_signed_exit_and_refuses_anything_else() {
        use bitcoin::secp256k1::{Keypair, Message, Secp256k1, SecretKey};

        let secp = Secp256k1::new();
        let owner_kp = Keypair::from_secret_key(&secp, &SecretKey::from_slice(&[9u8; 32]).unwrap());
        let owner_pk = hex::encode(owner_kp.x_only_public_key().0.serialize());
        let built: serde_json::Value = serde_json::from_str(
            &call(
                ark_build_exit_tx,
                &build_params(130_000).replace(OWNER, &owner_pk),
            )
            .unwrap(),
        )
        .unwrap();

        let sighash: [u8; 32] = hex::decode(built["sighash"].as_str().unwrap())
            .unwrap()
            .try_into()
            .unwrap();
        let sig = secp.sign_schnorr_no_aux_rand(&Message::from_digest(sighash), &owner_kp);
        let raw = call(
            ark_finalize_exit_tx,
            &format!(
                r#"{{"unsigned_tx":{},"script":{},"control_block":{},"signature":"{}"}}"#,
                built["unsigned_tx"], built["script"], built["control_block"], hex::encode(sig.as_ref())
            ),
        )
        .unwrap();

        let verify = |raw_tx: &str, sighash_hex: &str| {
            call(
                ark_verify_exit_tx,
                &format!(
                    r#"{{"unsigned_tx":{},"sighash":"{}","script":{},"control_block":{},
                         "owner_pk":"{owner_pk}","raw_tx":"{raw_tx}"}}"#,
                    built["unsigned_tx"], sighash_hex, built["script"], built["control_block"]
                ),
            )
        };
        assert!(verify(&raw, &hex::encode(sighash)).is_ok());

        // A signature over something else: the same transaction, but not the one we signed.
        let elsewhere = secp.sign_schnorr_no_aux_rand(&Message::from_digest([3u8; 32]), &owner_kp);
        let forged = call(
            ark_finalize_exit_tx,
            &format!(
                r#"{{"unsigned_tx":{},"script":{},"control_block":{},"signature":"{}"}}"#,
                built["unsigned_tx"], built["script"], built["control_block"],
                hex::encode(elsewhere.as_ref())
            ),
        )
        .unwrap();
        assert!(verify(&forged, &hex::encode(sighash)).is_err(), "a signature over another message");

        // A transaction paying somewhere else entirely, however well signed.
        let other: serde_json::Value = serde_json::from_str(
            &call(
                ark_build_exit_tx,
                &build_params(130_000)
                    .replace(OWNER, &owner_pk)
                    .replace(&"ab".repeat(32), &"cd".repeat(32)),
            )
            .unwrap(),
        )
        .unwrap();
        let other_sighash: [u8; 32] = hex::decode(other["sighash"].as_str().unwrap())
            .unwrap()
            .try_into()
            .unwrap();
        let other_sig = secp.sign_schnorr_no_aux_rand(&Message::from_digest(other_sighash), &owner_kp);
        let other_raw = call(
            ark_finalize_exit_tx,
            &format!(
                r#"{{"unsigned_tx":{},"script":{},"control_block":{},"signature":"{}"}}"#,
                other["unsigned_tx"], other["script"], other["control_block"],
                hex::encode(other_sig.as_ref())
            ),
        )
        .unwrap();
        assert!(
            verify(&other_raw, &hex::encode(sighash)).is_err(),
            "an exit paying a different address must be refused"
        );
    }

    /// An exit address is checked when it is typed, not when it is needed.
    #[test]
    fn an_address_becomes_a_script_and_a_wrong_network_is_caught() {
        let spk = |addr: &str, net: &str| {
            let a = CString::new(addr).unwrap();
            let n = CString::new(net).unwrap();
            let ptr = ark_onchain_script_pubkey(a.as_ptr(), n.as_ptr());
            let result = unsafe { &*ptr };
            let out = if result.success {
                Ok(unsafe { CStr::from_ptr(result.data) }.to_string_lossy().into_owned())
            } else {
                Err(unsafe { CStr::from_ptr(result.error) }.to_string_lossy().into_owned())
            };
            super::super::ark_free_result(ptr);
            out
        };
        // A regtest P2WPKH address, and the same string on the wrong network.
        let addr = "bcrt1qq5rjlmqartxjyh6vnmjrhrqnc58q2hqr5asln0";
        assert!(spk(addr, "regtest").unwrap().starts_with("0014"));
        assert!(spk(addr, "bitcoin").is_err(), "a regtest address is not a mainnet one");
        assert!(spk("not an address", "regtest").is_err());
        // Whitespace from a paste is not a reason to refuse.
        assert_eq!(spk(&format!("  {addr} "), "regtest").unwrap(), spk(addr, "regtest").unwrap());
    }

    #[test]
    fn a_bad_destination_is_refused_rather_than_signed() {
        let params = build_params(130_000).replace(&format!("5120{}", "ab".repeat(32)), "zz");
        assert!(call(ark_build_exit_tx, &params).is_err());
    }
}
