//! The unilateral exits a seal hands back.
//!
//! What matters here is that the exit is *complete* when the wallet gets it: a real 2-of-2
//! signature over the VTXO's exit leaf, in a transaction anybody can broadcast. That is the only
//! thing the wallet cannot obtain later, because obtaining it needs this cosigner.

mod common;

use bitcoin::consensus::deserialize;
use bitcoin::Transaction;
use cosigner::cosigner::WalletHalf;
use cosigner::types::{Commitment, VtxoInput};
use std::collections::BTreeMap;

use ark::client::types::ArkInfo;
use rand::rngs::OsRng;
use threshold::identifier::Identifier;
use threshold::keys::KeyPackage;
use threshold::nonce::{self, SigningCommitments};
use threshold::point;
use threshold::scalar::scalar_to_bytes;
use threshold::commitment::SigningPackage;
use threshold::signing;

/// A host that accepts whatever the seal schedules. Sealing arms the settle watch, and that needs
/// somewhere to enqueue it; outside the enclave there is no runtime, so this stands in.
#[derive(Default)]
struct Accepting;

impl cosigner::host::Host for Accepting {
    fn enqueue(&self, _: &str, _: &[u8], _: u64, _: Option<u64>) -> Result<(), String> {
        Ok(())
    }
    fn status(&self, _: &str) -> Result<String, String> {
        Ok("{}".into())
    }
    fn cancel(&self, _: &str) -> Result<(), String> {
        Ok(())
    }
    fn forget(&self, _: &str) -> Result<(), String> {
        Ok(())
    }
    fn register_device(&self, _: &str) -> Result<(), String> {
        Ok(())
    }
    fn forget_device(&self, _: &str) -> Result<(), String> {
        Ok(())
    }
    fn devices(&self) -> Result<u32, String> {
        Ok(0)
    }
    fn wake(&self, _: &str, _: Option<&str>) -> Result<(), String> {
        Ok(())
    }
}

/// A P2TR output somewhere else entirely — an exit pays a wallet this one does not control.
fn destination() -> Vec<u8> {
    let mut spk = vec![0x51, 0x20];
    spk.extend_from_slice(&[0xab; 32]);
    spk
}

fn ark_info() -> ArkInfo {
    ArkInfo {
        signer_pubkey: "79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798".into(),
        forfeit_pubkey: "0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798".into(),
        forfeit_address: "bcrt1qq5rjlmqartxjyh6vnmjrhrqnc58q2hqr5asln0".into(),
        checkpoint_tapscript: String::new(),
        network: "regtest".into(),
        session_duration: 0,
        unilateral_exit_delay: 512,
        boarding_exit_delay: 144,
        vtxo_min_amount: 0,
        dust: 330,
    }
}

fn vtxo(txid: char, amount_sats: u64) -> VtxoInput {
    VtxoInput {
        txid: std::iter::repeat(txid).take(64).collect(),
        vout: 0,
        amount_sats,
        exit_delay: 512,
        // A delegate needs a deadline to be scheduled against.
        expires_at: 4_102_444_800,
    }
}

/// The wallet's half of the round, over every message the cosigner committed to.
fn wallet_answers(
    kp_user: &KeyPackage,
    messages: &[Vec<u8>],
    cosigner_commitments: &[Commitment],
) -> Vec<WalletHalf> {
    let mut rng = OsRng;
    messages
        .iter()
        .zip(cosigner_commitments)
        .map(|(message, theirs)| {
            let ours = nonce::new_nonce(&mut rng, &kp_user.secret_share);
            let mut commitments: BTreeMap<Identifier, SigningCommitments> = BTreeMap::new();
            let id: [u8; 32] = hex::decode(&theirs.identifier_hex).unwrap().try_into().unwrap();
            commitments.insert(
                Identifier::deserialize(&id).unwrap(),
                SigningCommitments {
                    hiding: point::deserialize_compressed(
                        &theirs.hiding.clone().try_into().unwrap(),
                    )
                    .unwrap(),
                    binding: point::deserialize_compressed(
                        &theirs.binding.clone().try_into().unwrap(),
                    )
                    .unwrap(),
                },
            );
            commitments.insert(kp_user.identifier.clone(), ours.commitments.clone());
            let package = SigningPackage::new(commitments, message.clone());
            let share = signing::sign(&package, &ours, kp_user).expect("wallet share");
            WalletHalf {
                hiding: point::serialize_compressed(&ours.commitments.hiding).to_vec(),
                binding: point::serialize_compressed(&ours.commitments.binding).to_vec(),
                share: scalar_to_bytes(&share.s).to_vec(),
            }
        })
        .collect()
}

struct Sealed {
    exits: Vec<cosigner::handlers::delegate::SignedExit>,
}

/// Run a whole seal: open it, answer its round as the wallet would, and finish.
fn seal(vtxos: Vec<VtxoInput>, exit_script: &[u8]) -> Option<Sealed> {
    let store = common::try_store()?;
    let (kps, pkp) = common::dkg_2of2();
    let group_key = hex::encode(pkp.verifying_key.serialize());
    let cosigner = std::sync::Mutex::new(
        cosigner::Cosigner::open_with_host(
            store.clone(),
            group_key.clone(),
            std::sync::Arc::new(Accepting),
        )
        .expect("open"),
    );
    // With an Ark cosigner secret, or `generate_delegate_for` has nothing to sign the delegate with
    // and the whole test skips silently.
    common::seed_policy(
        &cosigner,
        &group_key,
        &kps[1],
        &kps[0],
        &pkp,
        Some(hex::encode([9u8; 32])),
    );
    let mut c = cosigner.into_inner().unwrap();

    let (delegate_sighashes, exits) = match c.seal_delegate_open(vtxos, &ark_info(), exit_script) {
        Ok(opened) => opened,
        Err(e) => panic!("the seal must work offline: {e}"),
    };
    let all: Vec<Vec<u8>> = delegate_sighashes
        .iter()
        .cloned()
        .chain(exits.sighashes())
        .collect();
    let (round, theirs) = c.sign_in_band_begin(&all).expect("begin");
    assert_eq!(theirs.len(), all.len(), "one commitment per message");

    let ours = wallet_answers(&kps[0], &all, &theirs);
    let signatures = c.sign_in_band_finish(round, ours).expect("finish");
    let sealed = c.seal_delegate_finish(signatures, exits).expect("seal");
    Some(Sealed { exits: sealed.exits })
}

/// One exit per VTXO, each spending its own outpoint and paying the whole amount to the address
/// the wallet named. Signed: the witness is complete, so nothing else is needed to broadcast it.
#[test]
fn a_seal_returns_one_signed_exit_per_vtxo() {
    let Some(sealed) = seal(vec![vtxo('a', 100_000), vtxo('b', 50_000)], &destination()) else {
        return;
    };
    assert_eq!(sealed.exits.len(), 2);

    for (exit, amount) in sealed.exits.iter().zip([100_000u64, 50_000]) {
        assert_eq!(exit.amount_sats, amount);
        let tx: Transaction = deserialize(&exit.raw_tx).expect("an exit must be a transaction");
        assert_eq!(tx.input.len(), 1);
        assert_eq!(
            format!("{}:{}", tx.input[0].previous_output.txid, tx.input[0].previous_output.vout),
            exit.outpoint,
        );
        assert_eq!(tx.input[0].sequence.to_consensus_u32(), exit.sequence);
        assert_eq!(tx.input[0].witness.len(), 3, "signature, leaf, control block");
        // Everything to the wallet's own address, and an anchor for whoever pays the fee.
        assert_eq!(tx.output.len(), 2);
        assert_eq!(tx.output[0].value.to_sat(), amount);
        assert_eq!(tx.output[0].script_pubkey.as_bytes(), destination());
        assert_eq!(tx.output[1].value.to_sat(), 0);
    }
}

/// A wallet with no exit address yet still seals a delegate — it just gets no exits.
#[test]
fn without_an_exit_address_a_seal_still_works() {
    let Some(sealed) = seal(vec![vtxo('a', 100_000)], &[]) else { return };
    assert!(sealed.exits.is_empty());
}

/// Too small to leave a non-dust output: no exit for that VTXO, and the seal still happens. The
/// delegate protects it; an exit could not be relayed.
#[test]
fn dust_gets_no_exit_but_does_not_fail_the_seal() {
    let Some(sealed) = seal(vec![vtxo('a', 100_000), vtxo('b', 200)], &destination()) else {
        return;
    };
    assert_eq!(sealed.exits.len(), 1);
    assert_eq!(sealed.exits[0].amount_sats, 100_000);
}
