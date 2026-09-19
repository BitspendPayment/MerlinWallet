#![cfg_attr(not(feature = "std"), no_std)]

extern crate alloc;

#[cfg(feature = "signing")]
pub mod client;

#[cfg(feature = "exit")]
pub mod exit;

use alloc::vec::Vec;
use threshold::taptree::{ControlBlock, TapLeaf, TapNode, UNSPENDABLE_KEY_X_ONLY};

// Re-export taptree types for convenience
pub use threshold::taptree;

// Bitcoin script opcodes
const OP_CHECKSIG: u8 = 0xac;
const OP_CHECKSIGVERIFY: u8 = 0xad;
const OP_CSV: u8 = 0xb2;  // OP_CHECKSEQUENCEVERIFY
const OP_DROP: u8 = 0x75;
const OP_SHA256: u8 = 0xa8;
const OP_EQUAL: u8 = 0x87;
const OP_VERIFY: u8 = 0x69;

/// Build forfeit/cooperative script:
/// `<server_pk> OP_CHECKSIGVERIFY <owner_pk> OP_CHECKSIG`
///
/// Both keys must be 32-byte x-only pubkeys.
pub fn multisig_script(server_pk: &[u8; 32], owner_pk: &[u8; 32]) -> Vec<u8> {
    let mut script = Vec::with_capacity(68); // 1+32 + 1 + 1+32 + 1
    script.push(0x20); // OP_PUSHBYTES_32
    script.extend_from_slice(server_pk);
    script.push(OP_CHECKSIGVERIFY);
    script.push(0x20); // OP_PUSHBYTES_32
    script.extend_from_slice(owner_pk);
    script.push(OP_CHECKSIG);
    script
}

/// Build unilateral exit script:
/// `<owner_pk> OP_CHECKSIGVERIFY <sequence> OP_CHECKSEQUENCEVERIFY OP_DROP`
///
/// `owner_pk` must be a 32-byte x-only pubkey.
/// `exit_delay` is encoded as a Bitcoin script number (minimal push).
pub fn csv_sig_script(exit_delay: u32, owner_pk: &[u8; 32]) -> Vec<u8> {
    let seq_bytes = script_number_encode(exit_delay as i64);
    let mut script = Vec::with_capacity(35 + seq_bytes.len() + 2);
    script.push(0x20); // OP_PUSHBYTES_32
    script.extend_from_slice(owner_pk);
    script.push(OP_CHECKSIGVERIFY);
    push_script_number(&mut script, &seq_bytes);
    script.push(OP_CSV);
    script.push(OP_DROP);
    script
}

/// BIP-68 relative-locktime sequence, matching ark-core's `parse_sequence_number`
/// (and arkd): `< 512` → block height; `>= 512` → seconds, encoded as
/// `TYPE_FLAG | ceil(secs / 512)`. Used so an eVTXO's exit leaf is a valid Ark
/// closure the ASP accepts.
fn bip68_sequence(delay: u32) -> u32 {
    const TYPE_FLAG: u32 = 1 << 22;
    if delay < 512 {
        delay
    } else {
        TYPE_FLAG | ((delay + 511) / 512)
    }
}

/// Exit leaf in ark-lib `CSVMultisigClosure` layout: `<bip68_seq> OP_CSV OP_DROP
/// <owner_pk> OP_CHECKSIG`. Unlike [`csv_sig_script`] (the MPC-wallet default
/// VTXO layout), this is byte-identical to what ark-core/arkd produce, so an
/// eVTXO carrying it passes the ASP's `ParseVtxoScript`/`DecodeClosure`. The
/// sequence is BIP-68 encoded (see [`bip68_sequence`]).
pub fn evtxo_exit_script(exit_delay: u32, owner_pk: &[u8; 32]) -> Vec<u8> {
    let seq_bytes = script_number_encode(bip68_sequence(exit_delay) as i64);
    let mut script = Vec::with_capacity(seq_bytes.len() + 1 + 2 + 34);
    push_script_number(&mut script, &seq_bytes);
    script.push(OP_CSV);
    script.push(OP_DROP);
    script.push(0x20); // OP_PUSHBYTES_32
    script.extend_from_slice(owner_pk);
    script.push(OP_CHECKSIG);
    script
}

/// Build a default Ark VTXO taproot tree with two leaves at depth 1:
/// - Leaf 0 (forfeit): `<server_pk> OP_CHECKSIGVERIFY <owner_pk> OP_CHECKSIG`
/// - Leaf 1 (exit): `<owner_pk> OP_CHECKSIGVERIFY <sequence> OP_CSV OP_DROP`
pub fn default_vtxo_tree(
    server_pk: &[u8; 32],
    owner_pk: &[u8; 32],
    exit_delay: u32,
) -> TapNode {
    let forfeit = TapLeaf::new(multisig_script(server_pk, owner_pk));
    let exit = TapLeaf::new(csv_sig_script(exit_delay, owner_pk));
    TapNode::Branch(
        alloc::boxed::Box::new(TapNode::Leaf(forfeit)),
        alloc::boxed::Box::new(TapNode::Leaf(exit)),
    )
}

/// Derive the tweaked output key for a VTXO (using UNSPENDABLE_KEY as internal key).
/// Returns the 33-byte compressed tweaked key.
pub fn vtxo_output_key(tree: &TapNode) -> Result<[u8; 33], threshold::error::Error> {
    threshold::taptree::tweaked_output_key_from_x_only(&UNSPENDABLE_KEY_X_ONLY, tree)
}

/// Derive the script pubkey (OP_1 <x-only tweaked key>) for a VTXO.
/// Returns 34 bytes: [0x51, 0x20, ...32 bytes x-only key].
pub fn vtxo_script_pubkey(tree: &TapNode) -> Result<[u8; 34], threshold::error::Error> {
    let compressed = vtxo_output_key(tree)?;
    let mut spk = [0u8; 34];
    spk[0] = 0x51; // OP_1 (witness version 1)
    spk[1] = 0x20; // OP_PUSHBYTES_32
    spk[2..].copy_from_slice(&compressed[1..33]); // x-only
    Ok(spk)
}

/// Get forfeit spend info: (script_bytes, control_block).
pub fn forfeit_spend_info(
    server_pk: &[u8; 32],
    owner_pk: &[u8; 32],
    exit_delay: u32,
) -> Option<(Vec<u8>, ControlBlock)> {
    let tree = default_vtxo_tree(server_pk, owner_pk, exit_delay);
    let forfeit_leaf = TapLeaf::new(multisig_script(server_pk, owner_pk));
    let cb = ControlBlock::new(&UNSPENDABLE_KEY_X_ONLY, &forfeit_leaf, &tree)?;
    Some((forfeit_leaf.script, cb))
}

/// Get exit spend info: (script_bytes, control_block).
pub fn exit_spend_info(
    server_pk: &[u8; 32],
    owner_pk: &[u8; 32],
    exit_delay: u32,
) -> Option<(Vec<u8>, ControlBlock)> {
    let tree = default_vtxo_tree(server_pk, owner_pk, exit_delay);
    let exit_leaf = TapLeaf::new(csv_sig_script(exit_delay, owner_pk));
    let cb = ControlBlock::new(&UNSPENDABLE_KEY_X_ONLY, &exit_leaf, &tree)?;
    Some((exit_leaf.script, cb))
}

// ---------------------------------------------------------------------------
// eVTXO: contract-gated cooperative path
// ---------------------------------------------------------------------------

/// Build the eVTXO cooperative leaf — Ark's `ConditionMultisigClosure` shape:
/// `<condition> OP_VERIFY <multisig>`, where the condition is a hashlock on the
/// contract:
///
/// `OP_SHA256 <commit> OP_EQUAL OP_VERIFY <server_pk> OP_CHECKSIGVERIFY <evtxo_pk> OP_CHECKSIG`
///
/// `commit = sha256(contract_id)`, `contract_id = sha256(component_wasm)` — the
/// "hash of the hash of the wasm". The spend witness reveals `contract_id`; the
/// script enforces `sha256(contract_id) == commit` on-chain, and `evtxo_pk` (the
/// 2-of-2 {wallet, cosigner} key) makes the cosigner mandatory so it runs the
/// committed contract before co-signing. Byte-compatible with ark-lib's
/// `ConditionMultisigClosure` (`OP_EQUAL OP_VERIFY`, not `OP_EQUALVERIFY`).
pub fn contract_cooperative_script(
    commit: &[u8; 32],
    server_pk: &[u8; 32],
    evtxo_pk: &[u8; 32],
) -> Vec<u8> {
    let multisig = multisig_script(server_pk, evtxo_pk);
    let mut script = Vec::with_capacity(5 + 32 + multisig.len());
    script.push(OP_SHA256);
    script.push(0x20); // OP_PUSHBYTES_32 (OP_DATA_32)
    script.extend_from_slice(commit);
    script.push(OP_EQUAL);
    script.push(OP_VERIFY);
    script.extend_from_slice(&multisig);
    script
}

/// Build an eVTXO taproot tree (split-key, contract-committed):
/// - Leaf 0 (cooperative): the `ConditionMultisigClosure` above — hashlock on
///   `commit` + `server_pk`/`evtxo_pk` multisig. The cosigner is mandatory and
///   runs the committed contract before co-signing.
/// - Leaf 1 (exit): `<owner_pk> OP_CHECKSIGVERIFY <sequence> OP_CSV OP_DROP`,
///   keyed by the main `owner_pk`, so unilateral exit stays available without the
///   cosigner after the timelock (the standard Ark escape hatch).
pub fn evtxo_tree(
    commit: &[u8; 32],
    server_pk: &[u8; 32],
    evtxo_pk: &[u8; 32],
    owner_pk: &[u8; 32],
    exit_delay: u32,
) -> TapNode {
    let cooperative = TapLeaf::new(contract_cooperative_script(commit, server_pk, evtxo_pk));
    let exit = TapLeaf::new(evtxo_exit_script(exit_delay, owner_pk));
    TapNode::Branch(
        alloc::boxed::Box::new(TapNode::Leaf(cooperative)),
        alloc::boxed::Box::new(TapNode::Leaf(exit)),
    )
}

/// Derive the eVTXO script pubkey (OP_1 <x-only tweaked key>), 34 bytes.
pub fn evtxo_script_pubkey(
    commit: &[u8; 32],
    server_pk: &[u8; 32],
    evtxo_pk: &[u8; 32],
    owner_pk: &[u8; 32],
    exit_delay: u32,
) -> Result<[u8; 34], threshold::error::Error> {
    vtxo_script_pubkey(&evtxo_tree(commit, server_pk, evtxo_pk, owner_pk, exit_delay))
}

/// Cooperative-leaf spend info for an eVTXO: (script_bytes, control_block).
/// This is the contract-gated path (hashlock on `commit` + `server_pk`/`evtxo_pk`).
pub fn evtxo_cooperative_spend_info(
    commit: &[u8; 32],
    server_pk: &[u8; 32],
    evtxo_pk: &[u8; 32],
    owner_pk: &[u8; 32],
    exit_delay: u32,
) -> Option<(Vec<u8>, ControlBlock)> {
    let tree = evtxo_tree(commit, server_pk, evtxo_pk, owner_pk, exit_delay);
    let leaf = TapLeaf::new(contract_cooperative_script(commit, server_pk, evtxo_pk));
    let cb = ControlBlock::new(&UNSPENDABLE_KEY_X_ONLY, &leaf, &tree)?;
    Some((leaf.script, cb))
}

/// Exit-leaf spend info for an eVTXO: (script_bytes, control_block).
/// Unilateral exit on the main `owner_pk` after the CSV delay.
pub fn evtxo_exit_spend_info(
    commit: &[u8; 32],
    server_pk: &[u8; 32],
    evtxo_pk: &[u8; 32],
    owner_pk: &[u8; 32],
    exit_delay: u32,
) -> Option<(Vec<u8>, ControlBlock)> {
    let tree = evtxo_tree(commit, server_pk, evtxo_pk, owner_pk, exit_delay);
    let leaf = TapLeaf::new(evtxo_exit_script(exit_delay, owner_pk));
    let cb = ControlBlock::new(&UNSPENDABLE_KEY_X_ONLY, &leaf, &tree)?;
    Some((leaf.script, cb))
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/// Encode a positive integer as a minimal Bitcoin script number.
fn script_number_encode(n: i64) -> Vec<u8> {
    if n == 0 {
        return Vec::new();
    }

    let negative = n < 0;
    let mut abs = if negative { -n } else { n } as u64;
    let mut result = Vec::new();

    while abs > 0 {
        result.push((abs & 0xff) as u8);
        abs >>= 8;
    }

    // If the high bit is set, add an extra byte for the sign.
    if result.last().map_or(false, |b| b & 0x80 != 0) {
        result.push(if negative { 0x80 } else { 0x00 });
    } else if negative {
        let last = result.last_mut().unwrap();
        *last |= 0x80;
    }

    result
}

/// Push a script number onto the script with the appropriate opcode.
fn push_script_number(script: &mut Vec<u8>, data: &[u8]) {
    let len = data.len();
    if len == 0 {
        script.push(0x00); // OP_0
    } else if len == 1 && data[0] <= 16 && data[0] >= 1 {
        // OP_1 through OP_16
        script.push(0x50 + data[0]);
    } else if len < 0x4c {
        script.push(len as u8); // direct push
        script.extend_from_slice(data);
    } else if len <= 0xff {
        script.push(0x4c); // OP_PUSHDATA1
        script.push(len as u8);
        script.extend_from_slice(data);
    } else {
        script.push(0x4d); // OP_PUSHDATA2
        script.extend_from_slice(&(len as u16).to_le_bytes());
        script.extend_from_slice(data);
    }
}

#[cfg(test)]
mod evtxo_tests {
    use super::*;

    const COMMIT: [u8; 32] = [0x44; 32]; // sha256(contract_id)
    const SERVER_PK: [u8; 32] = [0x11; 32];
    const EVTXO_PK: [u8; 32] = [0x22; 32]; // V′ (2-of-2 wallet+cosigner)
    const OWNER_PK: [u8; 32] = [0x33; 32]; // V  (main key)

    #[test]
    fn cooperative_script_is_condition_multisig() {
        // Ark ConditionMultisigClosure: OP_SHA256 <commit> OP_EQUAL OP_VERIFY <multisig>.
        let s = contract_cooperative_script(&COMMIT, &SERVER_PK, &EVTXO_PK);
        assert_eq!(s[0], 0xa8); // OP_SHA256
        assert_eq!(s[1], 0x20); // OP_PUSHBYTES_32
        assert_eq!(&s[2..34], &COMMIT);
        assert_eq!(s[34], 0x87); // OP_EQUAL
        assert_eq!(s[35], 0x69); // OP_VERIFY
        assert_eq!(&s[36..], multisig_script(&SERVER_PK, &EVTXO_PK).as_slice());
    }

    #[test]
    fn evtxo_script_pubkey_is_v1_taproot() {
        let spk = evtxo_script_pubkey(&COMMIT, &SERVER_PK, &EVTXO_PK, &OWNER_PK, 144).unwrap();
        assert_eq!(spk.len(), 34);
        assert_eq!(spk[0], 0x51); // OP_1
        assert_eq!(spk[1], 0x20); // OP_PUSHBYTES_32
    }

    #[test]
    fn cooperative_leaf_is_condition_multisig_exit_leaf_is_owner_csv() {
        let (coop, cb) =
            evtxo_cooperative_spend_info(&COMMIT, &SERVER_PK, &EVTXO_PK, &OWNER_PK, 144).unwrap();
        assert_eq!(coop, contract_cooperative_script(&COMMIT, &SERVER_PK, &EVTXO_PK));
        assert_eq!(cb.internal_key, UNSPENDABLE_KEY_X_ONLY);
        assert_eq!(cb.merkle_path.len(), 1); // two-leaf tree, one sibling

        // The exit leaf is the standard CSV script keyed by the main owner key.
        let (exit, _) =
            evtxo_exit_spend_info(&COMMIT, &SERVER_PK, &EVTXO_PK, &OWNER_PK, 144).unwrap();
        assert_eq!(exit, evtxo_exit_script(144, &OWNER_PK));
    }

    #[test]
    fn distinct_commitments_yield_distinct_addresses() {
        // The contract commitment is bound into the taproot output key.
        let a = evtxo_script_pubkey(&[0xaa; 32], &SERVER_PK, &EVTXO_PK, &OWNER_PK, 144).unwrap();
        let b = evtxo_script_pubkey(&[0xbb; 32], &SERVER_PK, &EVTXO_PK, &OWNER_PK, 144).unwrap();
        assert_ne!(a, b);
    }

    #[test]
    fn evtxo_differs_from_plain_vtxo() {
        let evtxo = evtxo_script_pubkey(&COMMIT, &SERVER_PK, &EVTXO_PK, &OWNER_PK, 144).unwrap();
        let plain = vtxo_script_pubkey(&default_vtxo_tree(&SERVER_PK, &OWNER_PK, 144)).unwrap();
        assert_ne!(evtxo, plain);
    }

    #[test]
    fn evtxo_exit_leaf_matches_arklib_csv_layout() {
        // ark-lib CSVMultisigClosure: <bip68_seq> OP_CSV OP_DROP <key> OP_CHECKSIG.
        // 86016s ≥ 512 → time-based: (1<<22) | ceil(86016/512=168) = 0x4000a8.
        let s = evtxo_exit_script(86016, &OWNER_PK);
        assert_eq!(s[0], 0x03); // push 3 bytes
        assert_eq!(&s[1..4], &[0xa8, 0x00, 0x40]); // 0x4000a8, little-endian
        assert_eq!(s[4], OP_CSV);
        assert_eq!(s[5], OP_DROP);
        assert_eq!(s[6], 0x20); // OP_PUSHBYTES_32
        assert_eq!(&s[7..39], &OWNER_PK);
        assert_eq!(s[39], OP_CHECKSIG);
        // < 512 → raw block height (no type flag); 144 needs a sign byte.
        let b = evtxo_exit_script(144, &OWNER_PK);
        assert_eq!(b[0], 0x02);
        assert_eq!(&b[1..3], &[0x90, 0x00]);
    }
}
