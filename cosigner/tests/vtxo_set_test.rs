//! The owned VTXO set survives boarding and reaches a send.
//!
//! There were two sets until recently: one in the seal that `send_open` selected from, and one
//! loaded from storage that boarding wrote. Nothing bridged them — `set_vtxos` had no callers — so
//! a freshly boarded VTXO was invisible to a send and the funds could not be spent. These tests
//! pin the two halves of that: what boarding writes is what a send reads, and it survives a reopen.

mod common;

use ark::client::types::ArkInfo;
use cosigner::types::{BoardingSettleSubmitted, VtxoInput};

/// The two delays a wallet's VTXOs can carry: received/refreshed, and boarded.
fn info() -> ArkInfo {
    ArkInfo {
        signer_pubkey: String::new(),
        forfeit_pubkey: String::new(),
        forfeit_address: String::new(),
        checkpoint_tapscript: String::new(),
        network: "regtest".into(),
        session_duration: 0,
        unilateral_exit_delay: 512,
        boarding_exit_delay: 144,
        vtxo_min_amount: 0,
        dust: 0,
    }
}

fn vtxo(txid: &str, amount: u64, exit_delay: u32) -> VtxoInput {
    VtxoInput {
        txid: txid.into(),
        vout: 0,
        amount_sats: amount,
        exit_delay,
    }
}

fn boarded(txid: &str, amount: u64, exit_delay: u32) -> BoardingSettleSubmitted {
    BoardingSettleSubmitted {
        commitment_txid: "commitment".into(),
        vtxo_txid: txid.into(),
        vtxo_vout: 0,
        amount_sats: amount,
        exit_delay,
    }
}

/// What boarding records is what a send selects from.
#[test]
fn a_boarded_vtxo_is_visible_to_a_send() {
    let Some(store) = common::try_store() else {
        return;
    };
    let (kps, pkp) = common::dkg_2of2();
    let group_key = hex::encode(pkp.verifying_key.serialize());

    let cosigner = common::open_cosigner(&store, &group_key);
    common::seed_policy(&cosigner, &group_key, &kps[1], &kps[0], &pkp, None);

    {
        let mut c = cosigner.lock().unwrap();
        assert!(c.vtxos().is_empty(), "a fresh wallet owns nothing");
        c.apply_boarding_settle(boarded("aa", 50_000, 144));

        // `vtxos()` is what `send_open` selects from. Before the collapse this stayed empty.
        let spendable = c.vtxos();
        assert_eq!(spendable.len(), 1, "the boarded VTXO must be spendable");
        assert_eq!(spendable[0].txid, "aa");
        assert_eq!(spendable[0].amount_sats, 50_000);
        assert_eq!(
            spendable[0].exit_delay, 144,
            "boarding keeps its own exit delay, not the unilateral one"
        );
    }
}

/// And it survives a reopen, because the seal is the only place it lives now.
#[test]
fn the_owned_set_survives_a_reopen() {
    let Some(store) = common::try_store() else {
        return;
    };
    let (kps, pkp) = common::dkg_2of2();
    let group_key = hex::encode(pkp.verifying_key.serialize());

    {
        let cosigner = common::open_cosigner(&store, &group_key);
        common::seed_policy(&cosigner, &group_key, &kps[1], &kps[0], &pkp, None);
        let mut c = cosigner.lock().unwrap();
        c.apply_boarding_settle(boarded("bb", 25_000, 144));
        c.seal();
    }

    let reopened = common::open_cosigner(&store, &group_key);
    let spendable = reopened.lock().unwrap().vtxos();
    assert_eq!(spendable.len(), 1, "the seal carries the owned set");
    assert_eq!(spendable[0].txid, "bb");
    assert_eq!(spendable[0].amount_sats, 25_000);

    let _ = store.delete("sealed_state", &group_key);
}

/// The caller supplies the set; the cosigner decides what of it this wallet could own.
///
/// Every spendable VTXO sits under a script derived from the cosigner's own owner key and one of
/// the ASP's two exit delays. A delay outside that pair names a script this wallet does not
/// control, so asserting it must not widen what the wallet will spend.
#[test]
fn a_caller_cannot_widen_what_it_owns() {
    let Some(store) = common::try_store() else {
        return;
    };
    let (kps, pkp) = common::dkg_2of2();
    let group_key = hex::encode(pkp.verifying_key.serialize());

    let cosigner = common::open_cosigner(&store, &group_key);
    common::seed_policy(&cosigner, &group_key, &kps[1], &kps[0], &pkp, None);
    let mut c = cosigner.lock().unwrap();

    // Both of the wallet's own delays are accepted — a mixed set is the normal case.
    c.accept_vtxos(
        vec![vtxo("aa", 1_000, 512), vtxo("bb", 2_000, 144)],
        &info(),
    )
    .expect("received and boarded VTXOs are both ours");
    assert_eq!(c.vtxos().len(), 2);

    // A third delay is a script this wallet cannot spend from.
    let err = c
        .accept_vtxos(vec![vtxo("cc", 9_999, 1_000)], &info())
        .expect_err("an unknown exit delay is not this wallet's to spend");
    assert!(err.contains("not ours"), "unhelpful error: {err}");

    // A rejected set must not have replaced the good one.
    assert_eq!(c.vtxos().len(), 2, "a refused set must leave the old one");

    for (bad, why) in [
        (vec![vtxo("dd", 0, 512)], "no amount"),
        (vec![vtxo("ee", 1, 512), vtxo("ee", 1, 512)], "named twice"),
    ] {
        let err = c.accept_vtxos(bad, &info()).expect_err(why);
        assert!(err.contains(why), "expected {why:?}, got: {err}");
    }

    let _ = store.delete("sealed_state", &group_key);
}
