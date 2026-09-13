//! The owned VTXO set survives boarding and reaches a send.
//!
//! There were two sets until recently: one in the seal that `send_open` selected from, and one
//! loaded from storage that boarding wrote. Nothing bridged them — `set_vtxos` had no callers — so
//! a freshly boarded VTXO was invisible to a send and the funds could not be spent. These tests
//! pin the two halves of that: what boarding writes is what a send reads, and it survives a reopen.

mod common;

use cosigner::types::BoardingSettleSubmitted;

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
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_boarded_vtxo_is_visible_to_a_send() {
    let Some(store) = common::try_store().await else {
        return;
    };
    let (kps, pkp) = common::dkg_2of2();
    let group_key = hex::encode(pkp.verifying_key.serialize());

    let cosigner = common::open_cosigner(&store, &group_key).await;
    common::seed_policy(&cosigner, &group_key, &kps[1], &kps[0], &pkp, None).await;

    {
        let mut c = cosigner.lock().await;
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
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn the_owned_set_survives_a_reopen() {
    let Some(store) = common::try_store().await else {
        return;
    };
    let (kps, pkp) = common::dkg_2of2();
    let group_key = hex::encode(pkp.verifying_key.serialize());

    {
        let cosigner = common::open_cosigner(&store, &group_key).await;
        common::seed_policy(&cosigner, &group_key, &kps[1], &kps[0], &pkp, None).await;
        let mut c = cosigner.lock().await;
        c.apply_boarding_settle(boarded("bb", 25_000, 144));
        c.seal().await;
    }

    let reopened = common::open_cosigner(&store, &group_key).await;
    let spendable = reopened.lock().await.vtxos();
    assert_eq!(spendable.len(), 1, "the seal carries the owned set");
    assert_eq!(spendable[0].txid, "bb");
    assert_eq!(spendable[0].amount_sats, 25_000);

    let _ = store.delete("sealed_state", &group_key);
}
