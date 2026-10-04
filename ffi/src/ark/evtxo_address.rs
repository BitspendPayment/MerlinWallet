//! Derive the Ark address for a contract eVTXO output key, so an off-chain send
//! can target it as a recipient — arkd then mints a VTXO at `OP_1 <Q_evtxo>` that
//! it tracks and can later co-sign through its cooperative (`ConditionMultisigClosure`)
//! path. An `ArkAddress` is just `(server_key, vtxo_tap_key)`; `vtxo_tap_key` is the
//! eVTXO's tweaked taproot output key (bytes [2..] of its 34-byte scriptPubKey).

use ark_core::ArkAddress;
use bitcoin::key::TweakedPublicKey;
use bitcoin::{Network, XOnlyPublicKey};

use serde::Deserialize;


#[derive(Deserialize)]
pub struct EvtxoArkAddressParams {
    pub server_pk: String, // ASP signer x-only hex
    pub q_evtxo: String,   // eVTXO output key x-only hex (evtxo_spk[2..])
    pub network: String,
}

pub fn evtxo_ark_address(params_json: &str) -> Result<String, String> {
    let p: EvtxoArkAddressParams =
        serde_json::from_str(params_json).map_err(|e| format!("JSON parse: {e}"))?;
    let server = XOnlyPublicKey::from_slice(&crate::from_hex::<[u8; 32]>(&p.server_pk)?)
        .map_err(|e| format!("invalid server_pk: {e}"))?;
    let q = XOnlyPublicKey::from_slice(&crate::from_hex::<[u8; 32]>(&p.q_evtxo)?)
        .map_err(|e| format!("invalid q_evtxo: {e}"))?;
    let network = match p.network.as_str() {
        "bitcoin" | "mainnet" => Network::Bitcoin,
        "testnet" | "testnet3" => Network::Testnet,
        "signet" | "mutinynet" => Network::Signet,
        "regtest" => Network::Regtest,
        other => return Err(format!("unknown network: {other}")),
    };
    // The output key already commits the eVTXO tapscript tree (NUMS-internal
    // tweaked by its merkle root); treat it as the final tweaked key.
    let tweaked = TweakedPublicKey::dangerous_assume_tweaked(q);
    Ok(ArkAddress::new(network, server, tweaked).encode())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn round_trips_through_decode() {
        // Valid on-curve x-only keys (the secp256k1 generator's x-coordinate).
        let server = "79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798";
        let q = server;
        let params = format!(
            r#"{{"server_pk":"{server}","q_evtxo":"{q}","network":"regtest"}}"#
        );
        let addr = evtxo_ark_address(&params).unwrap();
        assert!(addr.starts_with("tark1"), "regtest ark addr, got: {addr}");
        // The decoded address recovers the same output key we asked arkd to mint.
        let decoded = ArkAddress::decode(&addr).unwrap();
        assert_eq!(
            decoded.to_p2tr_script_pubkey().as_bytes()[2..].to_vec(),
            crate::from_hex::<[u8; 32]>(q).unwrap().to_vec()
        );
    }
}
