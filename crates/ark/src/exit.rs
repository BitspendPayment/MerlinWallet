//! The unilateral exit: spending a VTXO through its own exit leaf, with nobody's help.
//!
//! A VTXO sits under a taproot output with two leaves. The forfeit leaf needs the ASP, so it is
//! worth nothing the day the ASP stops answering. The exit leaf needs only the owner, after a
//! relative timelock — and the owner here is a 2-of-2 between the wallet and the cosigner, so the
//! spend still needs both. That is the whole problem this module exists for: the signature is
//! obtainable *now*, while the cosigner is up, and the transaction is kept until it is needed.
//! See "Emergency exit" in the README.
//!
//! So the flow is build → sighash → the 2-of-2 signs → finalize, and what is stored is a complete
//! transaction that anybody can broadcast:
//!
//! ```text
//!   input   the VTXO, nSequence = its BIP-68 exit delay
//!   output  the whole amount, to an address the user gave us
//!   output  a P2A anchor, 0 sats
//! ```
//!
//! **It pays no fee.** A fee fixed at signing time is a guess about a fee market months away, and
//! a wallet that cannot re-sign cannot correct it. The anchor moves that decision to broadcast
//! time: P2A is spendable by anyone, so whoever wants the exit confirmed — the destination wallet,
//! a bump service — attaches a child that pays for both. The transaction is version 3 for the same
//! reason: TRUC is what makes a zero-fee parent relayable with its child.
//!
//! Both sides of the 2-of-2 build this: the cosigner to know what it signs, the wallet to check
//! what it is asked to sign. Same code, same bytes, or the sighashes disagree and the seal fails.

use ark_core::{anchor_output, Vtxo};
use bitcoin::hashes::Hash;
use bitcoin::key::Secp256k1;
use bitcoin::script::ScriptBuf;
use bitcoin::sighash::{Prevouts, SighashCache};
use bitcoin::taproot::{ControlBlock, LeafVersion};
use bitcoin::{
    absolute::LockTime, transaction::Version, Amount, Network, OutPoint, Sequence, TapLeafHash,
    TapSighashType, Transaction, TxIn, TxOut, Txid, Witness, XOnlyPublicKey,
};

/// Below this a P2TR output is dust, and the exit would be unrelayable. The ASP's own `dust` is
/// the same number today; this is the consensus-side floor rather than a policy we chose.
pub const DUST_SATS: u64 = 330;

/// One VTXO to be exited.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExitInput {
    pub txid: Txid,
    pub vout: u32,
    pub amount_sats: u64,
    /// The exit delay this VTXO was created under — boarded ones keep the boarding delay, received
    /// and refreshed ones use the unilateral one, and a wallet holds both at once.
    pub exit_delay: u32,
}

/// An exit transaction waiting for the 2-of-2's signature.
#[derive(Debug, Clone)]
pub struct ExitSpend {
    /// Unsigned. [`finalize_exit_tx`] returns the signed bytes; this is what the sighash covers.
    pub tx: Transaction,
    /// What the owner signs, BIP-341 script-path over the exit leaf.
    pub sighash: [u8; 32],
    /// The exit leaf, for the witness.
    pub script: ScriptBuf,
    /// Its control block, for the witness.
    pub control_block: ControlBlock,
    /// The input's nSequence: the exit delay, BIP-68 encoded.
    pub sequence: u32,
}

/// The VTXO this owner holds under this ASP, from which every script and key below is derived.
pub fn vtxo(
    asp_pk: XOnlyPublicKey,
    owner_pk: XOnlyPublicKey,
    exit_delay: u32,
    network: Network,
) -> Result<Vtxo, String> {
    let secp = Secp256k1::new();
    let exit_seq = ark_core::server::parse_sequence_number(exit_delay as i64)
        .map_err(|e| format!("exit delay {exit_delay} is not a usable sequence: {e}"))?;
    Vtxo::new_default(&secp, asp_pk, owner_pk, exit_seq, network)
        .map_err(|e| format!("Vtxo::new_default: {e}"))
}

/// The exit leaf, its control block, the scriptPubKey it sits under, and the nSequence a spend of
/// it must carry.
///
/// Not the hand-rolled tree in this crate's root — that one writes the leaf in a different opcode
/// order, with the delay unencoded, and ends on `OP_DROP` so it cannot be satisfied at all. Real
/// VTXOs live under `ark_core`'s tree, and so does this.
pub fn exit_spend_info(
    asp_pk: XOnlyPublicKey,
    owner_pk: XOnlyPublicKey,
    exit_delay: u32,
    network: Network,
) -> Result<(ScriptBuf, ControlBlock, ScriptBuf, u32), String> {
    let vtxo = vtxo(asp_pk, owner_pk, exit_delay, network)?;
    let (script, control_block) = vtxo
        .exit_spend_info()
        .map_err(|e| format!("exit_spend_info: {e}"))?;
    Ok((
        script,
        control_block,
        vtxo.script_pubkey(),
        vtxo.exit_delay().to_consensus_u32(),
    ))
}

/// Build the exit spend of [`input`], paying everything to `destination` plus an anchor.
///
/// `destination` is a scriptPubKey the user gave us — an address in a wallet this one does not
/// control, which is the point of an exit.
pub fn build_exit_tx(
    asp_pk: XOnlyPublicKey,
    owner_pk: XOnlyPublicKey,
    network: Network,
    input: &ExitInput,
    destination: &ScriptBuf,
) -> Result<ExitSpend, String> {
    if input.amount_sats < DUST_SATS {
        return Err(format!(
            "{} sats is below the {DUST_SATS}-sat dust floor, so its exit could not be relayed",
            input.amount_sats
        ));
    }
    if destination.is_empty() {
        return Err("no destination for the exit".to_string());
    }

    let (script, control_block, script_pubkey, sequence) =
        exit_spend_info(asp_pk, owner_pk, input.exit_delay, network)?;

    let tx = Transaction {
        // TRUC. A zero-fee transaction is relayed only with the child that pays for it.
        version: Version::non_standard(3),
        lock_time: LockTime::ZERO,
        input: vec![TxIn {
            previous_output: OutPoint { txid: input.txid, vout: input.vout },
            script_sig: ScriptBuf::new(),
            // The exit leaf's `OP_CHECKSEQUENCEVERIFY` is satisfied by this and nothing else.
            sequence: Sequence::from_consensus(sequence),
            witness: Witness::new(),
        }],
        output: vec![
            TxOut {
                value: Amount::from_sat(input.amount_sats),
                script_pubkey: destination.clone(),
            },
            anchor_output(),
        ],
    };

    let prevout = TxOut {
        value: Amount::from_sat(input.amount_sats),
        script_pubkey,
    };
    let leaf_hash = TapLeafHash::from_script(&script, LeafVersion::TapScript);
    let sighash = SighashCache::new(&tx)
        .taproot_script_spend_signature_hash(
            0,
            &Prevouts::All(std::slice::from_ref(&prevout)),
            leaf_hash,
            TapSighashType::Default,
        )
        .map_err(|e| format!("exit sighash: {e}"))?
        .to_byte_array();

    Ok(ExitSpend { tx, sighash, script, control_block, sequence })
}

/// The signed transaction, ready to broadcast: witness `[signature, exit leaf, control block]`.
pub fn finalize_exit_tx(spend: &ExitSpend, signature: &[u8]) -> Result<Vec<u8>, String> {
    if signature.len() != 64 {
        return Err(format!(
            "an exit signature is 64 bytes of BIP-340, got {}",
            signature.len()
        ));
    }
    let mut witness = Witness::new();
    witness.push(signature);
    witness.push(spend.script.as_bytes());
    witness.push(spend.control_block.serialize());

    let mut tx = spend.tx.clone();
    tx.input[0].witness = witness;
    Ok(bitcoin::consensus::serialize(&tx))
}

#[cfg(test)]
mod tests {
    use super::*;
    use bitcoin::secp256k1::{Keypair, Message, SecretKey};

    fn keys() -> (XOnlyPublicKey, XOnlyPublicKey) {
        let secp = Secp256k1::new();
        let asp = Keypair::from_secret_key(&secp, &SecretKey::from_slice(&[7u8; 32]).unwrap());
        let owner = Keypair::from_secret_key(&secp, &SecretKey::from_slice(&[9u8; 32]).unwrap());
        (asp.x_only_public_key().0, owner.x_only_public_key().0)
    }

    fn input() -> ExitInput {
        ExitInput {
            txid: "34fcce0000000000000000000000000000000000000000000000000000000000"
                .parse()
                .unwrap(),
            vout: 0,
            amount_sats: 130_000,
            exit_delay: 86016,
        }
    }

    fn destination() -> ScriptBuf {
        // A P2TR output, as any exit address of consequence is.
        let mut spk = vec![0x51, 0x20];
        spk.extend_from_slice(&[0xab; 32]);
        ScriptBuf::from_bytes(spk)
    }

    /// The leaf has to be the one real VTXOs carry, or the exit spends nothing.
    #[test]
    fn the_leaf_is_ark_cores_own() {
        let (asp, owner) = keys();
        let (script, control_block, spk, _) =
            exit_spend_info(asp, owner, 86016, Network::Regtest).unwrap();
        let vtxo = vtxo(asp, owner, 86016, Network::Regtest).unwrap();
        let (expected_script, expected_cb) = vtxo.exit_spend_info().unwrap();
        assert_eq!(script, expected_script);
        assert_eq!(control_block.serialize(), expected_cb.serialize());
        assert_eq!(spk, vtxo.script_pubkey());
    }

    /// 86016 is seconds, not blocks. Read as blocks it would be a timelock of a year and a half.
    #[test]
    fn a_delay_in_seconds_stays_in_seconds() {
        let (asp, owner) = keys();
        let (_, _, _, sequence) = exit_spend_info(asp, owner, 86016, Network::Regtest).unwrap();
        let seq = Sequence::from_consensus(sequence);
        assert!(seq.is_relative_lock_time());
        assert!(seq.is_time_locked(), "86016 is a number of seconds");
        assert_eq!(seq.to_relative_lock_time().unwrap().is_block_height(), false);
    }

    #[test]
    fn a_block_delay_stays_in_blocks() {
        let (asp, owner) = keys();
        let (_, _, _, sequence) = exit_spend_info(asp, owner, 144, Network::Regtest).unwrap();
        assert!(Sequence::from_consensus(sequence)
            .to_relative_lock_time()
            .unwrap()
            .is_block_height());
    }

    #[test]
    fn the_exit_pays_everything_to_the_destination_and_nothing_in_fees() {
        let (asp, owner) = keys();
        let spend =
            build_exit_tx(asp, owner, Network::Regtest, &input(), &destination()).unwrap();
        assert_eq!(spend.tx.version, Version::non_standard(3));
        assert_eq!(spend.tx.output.len(), 2);
        assert_eq!(spend.tx.output[0].value, Amount::from_sat(130_000));
        assert_eq!(spend.tx.output[0].script_pubkey, destination());
        assert_eq!(spend.tx.output[1], anchor_output());
        // Zero fee: what goes in comes out.
        let out: u64 = spend.tx.output.iter().map(|o| o.value.to_sat()).sum();
        assert_eq!(out, 130_000);
        assert_eq!(spend.tx.input[0].sequence.to_consensus_u32(), spend.sequence);
    }

    #[test]
    fn dust_cannot_be_exited() {
        let (asp, owner) = keys();
        let mut tiny = input();
        tiny.amount_sats = 329;
        let err = build_exit_tx(asp, owner, Network::Regtest, &tiny, &destination()).unwrap_err();
        assert!(err.contains("dust"), "{err}");
    }

    /// The signed transaction has to satisfy the leaf it names: a real BIP-340 signature over the
    /// sighash, then the script and its control block.
    #[test]
    fn a_finalized_exit_carries_a_signature_that_verifies() {
        let secp = Secp256k1::new();
        let owner_kp = Keypair::from_secret_key(&secp, &SecretKey::from_slice(&[9u8; 32]).unwrap());
        let (asp, owner) = keys();
        let spend =
            build_exit_tx(asp, owner, Network::Regtest, &input(), &destination()).unwrap();

        let sig = secp.sign_schnorr_no_aux_rand(&Message::from_digest(spend.sighash), &owner_kp);
        let raw = finalize_exit_tx(&spend, sig.as_ref()).unwrap();

        let tx: Transaction = bitcoin::consensus::deserialize(&raw).unwrap();
        let witness = &tx.input[0].witness;
        assert_eq!(witness.len(), 3);
        assert_eq!(witness.nth(1).unwrap(), spend.script.as_bytes());
        assert_eq!(witness.nth(2).unwrap(), spend.control_block.serialize());
        secp.verify_schnorr(&sig, &Message::from_digest(spend.sighash), &owner)
            .expect("the owner's signature must verify against the exit leaf's key");
    }

    #[test]
    fn a_signature_of_the_wrong_length_is_refused() {
        let (asp, owner) = keys();
        let spend =
            build_exit_tx(asp, owner, Network::Regtest, &input(), &destination()).unwrap();
        assert!(finalize_exit_tx(&spend, &[1u8; 65]).is_err());
    }
}
