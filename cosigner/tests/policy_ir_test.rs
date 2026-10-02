//! The policy IR: evaluation, static analysis, rendering, and the bounds that make it safe to
//! evaluate at all.
//!
//! These are the security tests for the ceiling every signer is bound by. The pairing-routing and
//! fail-closed-migration cases live in `service_poly_invariant_test.rs`; what is pinned here is the
//! language itself.

use std::collections::{BTreeMap, BTreeSet};

use bitcoin::{absolute::LockTime, transaction::Version, Amount, ScriptBuf, Transaction, TxOut};
use cosigner::policy::{
    enforce, outputs_of, EvalContext, Policy, MAX_POLICY_DEPTH,
};

// Distinct P2WPKH-shaped scripts.
const DEST: &str = "0014000102030405060708090a0b0c0d0e0f10111213";
const OTHER: &str = "0014ffeeddccbbaa99887766554433221100ffeeddcc";
const MINE: &str = "0014aabbccddeeff00112233445566778899aabbcc";

fn tx_paying(outs: &[(&str, u64)]) -> Vec<u8> {
    let tx = Transaction {
        version: Version::TWO,
        lock_time: LockTime::ZERO,
        input: vec![],
        output: outs
            .iter()
            .map(|(spk, sats)| TxOut {
                value: Amount::from_sat(*sats),
                script_pubkey: ScriptBuf::from_hex(spk).unwrap(),
            })
            .collect(),
    };
    bitcoin::consensus::encode::serialize(&tx)
}

fn nothing_owned() -> BTreeSet<String> {
    BTreeSet::new()
}

fn owning(scripts: &[&str]) -> BTreeSet<String> {
    scripts.iter().map(|s| s.to_string()).collect()
}

/// The common two-clause grant: pay only these, and no more than this in total.
fn allowlist_with_cap(scripts: &[&str], max_sats: u64) -> Policy {
    Policy::AllOf {
        of: vec![only_to(scripts), Policy::TotalOutMax { sats: max_sats }],
    }
}

fn only_to(scripts: &[&str]) -> Policy {
    Policy::OutputsOnlyTo {
        scripts: scripts.iter().map(|s| s.to_string()).collect(),
    }
}

// ---------------------------------------------------------------------------
// Evaluation, per variant.
// ---------------------------------------------------------------------------

#[test]
fn always_permits_and_never_denies() {
    let tx = tx_paying(&[(OTHER, u64::MAX / 2)]);
    assert!(enforce(&Policy::Always, &tx, &nothing_owned()).is_ok());
    assert!(enforce(&Policy::Never, &tx, &nothing_owned()).is_err());
}

#[test]
fn all_of_needs_every_branch_and_any_of_needs_one() {
    let tx = tx_paying(&[(DEST, 10_000)]);
    let pass = only_to(&[DEST]);
    let fail = only_to(&[OTHER]);

    let all_pass = Policy::AllOf {
        of: vec![pass.clone(), Policy::TotalOutMax { sats: 10_000 }],
    };
    assert!(enforce(&all_pass, &tx, &nothing_owned()).is_ok());

    let all_mixed = Policy::AllOf {
        of: vec![pass.clone(), fail.clone()],
    };
    assert!(enforce(&all_mixed, &tx, &nothing_owned()).is_err());

    let any_mixed = Policy::AnyOf {
        of: vec![fail.clone(), pass],
    };
    assert!(enforce(&any_mixed, &tx, &nothing_owned()).is_ok());

    let any_none = Policy::AnyOf {
        of: vec![fail, Policy::Never],
    };
    assert!(enforce(&any_none, &tx, &nothing_owned()).is_err());
}

#[test]
fn the_total_cap_applies_to_the_sum_and_the_single_cap_to_each_output() {
    let two_outputs = tx_paying(&[(DEST, 60_000), (DEST, 60_000)]);

    // 120k total: over a 100k total cap...
    assert!(enforce(
        &Policy::TotalOutMax { sats: 100_000 },
        &two_outputs,
        &nothing_owned()
    )
    .is_err());
    // ...but each individual output is under a 100k per-output cap.
    assert!(enforce(
        &Policy::SingleOutMax { sats: 100_000 },
        &two_outputs,
        &nothing_owned()
    )
    .is_ok());
    assert!(enforce(
        &Policy::SingleOutMax { sats: 59_999 },
        &two_outputs,
        &nothing_owned()
    )
    .is_err());
}

#[test]
fn an_unrecognised_external_evaluator_denies() {
    // The escape hatch is a door, not a feature: shipping the variant must grant nothing until an
    // evaluator is deliberately registered.
    let p = Policy::External {
        evaluator: "simplicity".into(),
        config: vec![1, 2, 3],
    };
    let err = enforce(&p, &tx_paying(&[(DEST, 1)]), &nothing_owned()).unwrap_err();
    assert!(err.contains("not available"), "{err}");
}

// ---------------------------------------------------------------------------
// A missing transaction is not a global denial — each predicate decides.
// ---------------------------------------------------------------------------

#[test]
fn always_holds_without_a_transaction_but_output_predicates_refuse_to_guess() {
    // This is what lets the wallet's own `Always` policy sit on the signing path: a renewal's
    // sighash arrives with no transaction at all, and denying globally on that would break every
    // renewal.
    assert!(enforce(&Policy::Always, &[], &nothing_owned()).is_ok());
    assert!(enforce(&Policy::Never, &[], &nothing_owned()).is_err());

    for p in [
        only_to(&[DEST]),
        Policy::TotalOutMax { sats: 1 },
        Policy::SingleOutMax { sats: 1 },
    ] {
        let err = enforce(&p, &[], &nothing_owned()).unwrap_err();
        assert!(err.contains("needs the outputs it is authorising"), "{err}");
    }
}

#[test]
fn an_undecodable_transaction_denies_rather_than_passing() {
    let err = enforce(&only_to(&[DEST]), &[0xde, 0xad, 0xbe, 0xef], &nothing_owned()).unwrap_err();
    assert!(err.contains("undecodable"), "{err}");
}

// ---------------------------------------------------------------------------
// Change is not egress.
// ---------------------------------------------------------------------------

#[test]
fn change_back_to_our_own_scripts_is_exempt_from_both_the_allowlist_and_the_cap() {
    // The original check treated every output as a payment, so a change output had to be allowlisted
    // — which is why the takeaway path could not reuse it. A policy bounds what LEAVES the wallet.
    let tx = tx_paying(&[(DEST, 40_000), (MINE, 900_000)]);
    let mine = owning(&[MINE]);

    let p = Policy::AllOf {
        of: vec![only_to(&[DEST]), Policy::TotalOutMax { sats: 50_000 }],
    };
    assert!(
        enforce(&p, &tx, &mine).is_ok(),
        "900k of change must not count against a 50k egress cap"
    );

    // Without the ownership claim the very same transaction is refused, on both counts.
    assert!(enforce(&p, &tx, &nothing_owned()).is_err());
}

// ---------------------------------------------------------------------------
// Bounds. Non-Turing-complete is not automatically safe.
// ---------------------------------------------------------------------------

#[test]
fn an_over_deep_policy_is_refused_at_installation() {
    // Depth is bounded so recursive evaluation cannot exhaust the enclave's stack. Built just deep
    // enough to break the limit — building one deep enough to actually overflow would overflow
    // this test's own stack on drop, which is the point being defended against.
    let mut p = Policy::TotalOutMax { sats: 1 };
    for _ in 0..(MAX_POLICY_DEPTH + 5) {
        p = Policy::AllOf { of: vec![p] };
    }
    let err = p.validate().unwrap_err();
    assert!(err.contains("nests deeper"), "{err}");

    // And evaluation refuses independently, so the guarantee does not rest on validate having run.
    let err = enforce(&p, &tx_paying(&[(DEST, 1)]), &nothing_owned()).unwrap_err();
    assert!(err.contains("nests deeper"), "{err}");
}

#[test]
fn an_over_wide_policy_is_refused_at_installation() {
    let p = Policy::AllOf {
        of: (0..1_000)
            .map(|i| Policy::TotalOutMax { sats: i + 1 })
            .collect(),
    };
    let err = p.validate().unwrap_err();
    assert!(err.contains("more than"), "{err}");
}

#[test]
fn deeply_nested_json_is_rejected_by_the_parser_rather_than_overflowing() {
    // The real attack surface is an enrolment body, not a hand-built tree.
    let mut doc = String::new();
    for _ in 0..2_000 {
        doc.push_str(r#"{"op":"all_of","of":["#);
    }
    doc.push_str(r#"{"op":"always"}"#);
    for _ in 0..2_000 {
        doc.push_str("]}");
    }
    assert!(
        serde_json::from_str::<Policy>(&doc).is_err(),
        "a 2000-deep policy document must not deserialize"
    );
}

#[test]
fn self_defeating_policies_are_refused_at_installation() {
    // An empty `all_of` is a vacuous PASS — exactly the accidental widening this IR exists to make
    // impossible — so both empty combinators are rejected rather than silently interpreted.
    assert!(Policy::AllOf { of: vec![] }.validate().is_err());
    assert!(Policy::AnyOf { of: vec![] }.validate().is_err());
    // ...and evaluation refuses them too, so a hand-built one cannot slip past.
    let tx = tx_paying(&[(DEST, 1)]);
    assert!(enforce(&Policy::AllOf { of: vec![] }, &tx, &nothing_owned()).is_err());

    assert!(only_to(&[]).validate().is_err(), "say never instead");
    assert!(Policy::TotalOutMax { sats: 0 }.validate().is_err());
    assert!(
        only_to(&["not hex"]).validate().is_err(),
        "destinations are scriptPubKey hex"
    );
    assert!(
        only_to(&["0014AABB"]).validate().is_err(),
        "uppercase would never match the lowercase hex we compare against"
    );
}

#[test]
fn a_valid_policy_installs() {
    let p = Policy::AllOf {
        of: vec![
            only_to(&[DEST, OTHER]),
            Policy::TotalOutMax { sats: 100_000 },
        ],
    };
    assert!(p.validate().is_ok());
    assert!(Policy::Always.validate().is_ok());
    assert!(Policy::Never.validate().is_ok());
}

// ---------------------------------------------------------------------------
// Rendering. A policy the user must consent to has to be readable, which is the whole argument for
// a tree over a compiled program — so it is asserted, not assumed.
// ---------------------------------------------------------------------------

#[test]
fn a_policy_renders_as_the_sentence_a_user_would_consent_to() {
    assert_eq!(Policy::Always.describe(), "may spend without restriction");
    assert_eq!(Policy::Never.describe(), "may not spend at all");

    let p = allowlist_with_cap(&[DEST, OTHER], 100_000);
    assert_eq!(
        p.describe(),
        "may only pay 2 approved destinations, and may spend at most 100000 sats in one transaction"
    );

    assert_eq!(
        Policy::AnyOf {
            of: vec![
                Policy::SingleOutMax { sats: 5 },
                only_to(&[DEST]),
            ],
        }
        .describe(),
        "may send at most 5 sats to any one destination, or may only pay 1 approved destination"
    );
}

// ---------------------------------------------------------------------------
// Wire form.
// ---------------------------------------------------------------------------

#[test]
fn a_policy_document_round_trips_through_json() {
    let p = Policy::AllOf {
        of: vec![
            only_to(&[DEST]),
            Policy::TotalOutMax { sats: 100_000 },
            Policy::SingleOutMax { sats: 25_000 },
        ],
    };
    let json = serde_json::to_string(&p).unwrap();
    assert_eq!(serde_json::from_str::<Policy>(&json).unwrap(), p);
    // The tag is what makes the document readable by a client that wants to render it.
    assert!(json.contains(r#""op":"total_out_max""#), "{json}");
}

// ---------------------------------------------------------------------------
// The layering: the policy judges outputs, something else proves the transaction.
// ---------------------------------------------------------------------------

#[test]
fn the_policy_layer_deliberately_knows_nothing_about_the_message_signed() {
    // `evaluate` has nowhere to pass a message, and that is correct rather than a gap: a predicate
    // over outputs has no business recomputing sighashes. What used to be the hole is that NOTHING
    // did it — a service could present a compliant transaction and be signed over something else.
    //
    // That proof now lives one layer up, in `CosignerActor::bind_message_to_transaction`, which
    // runs BEFORE this and refuses unless the message is a sighash of the supplied transaction,
    // with prevouts and tap leaves rebuilt from the cosigner's own VTXO cache rather than taken
    // from the request. The crypto is pinned in `ark::client::bind`; what is pinned here is the
    // separation — this layer stays a pure predicate over outputs.
    let policy = allowlist_with_cap(&[DEST], 100_000);
    let compliant = tx_paying(&[(DEST, 10_000)]);

    let ctx_tx: Transaction = bitcoin::consensus::encode::deserialize(&compliant).unwrap();
    let outs = outputs_of(&ctx_tx);
    let owned = nothing_owned();

    assert!(policy
        .evaluate(&EvalContext {
            outputs: Some(&outs),
            owned_scripts: &owned,
            // Not a release: this test is about output predicates, which have nothing to bind to
            // a payment.
            release: None,
            evidence: &std::collections::BTreeMap::new(),
        })
        .is_ok());

    // The same outputs reached by any route evaluate the same way. That determinism is the point
    // of keeping the predicate free of transaction identity — it is why the binding proof has to
    // be a separate, prior step rather than something smuggled into a policy variant.
    let same = outputs_of(&ctx_tx);
    assert_eq!(outs, same);
}

// ---------------------------------------------------------------------------
// The evidence condition, inside a policy tree.
// ---------------------------------------------------------------------------

use cosigner::evidence::{Evidence, HttpGet, Predicate, ReleaseFacts};

fn diva() -> Policy {
    Policy::HttpGet(Box::new(HttpGet {
        provider: "https://diva.example".into(),
        path: "/v1/transactions/{reference}".into(),
        credentials: "DIVA".into(),
        expect: vec![
            Predicate::Equals { at: "state".into(), value: "COMPLETION".into() },
            Predicate::MatchesReference { at: "token".into() },
        ],
        on_unavailable: Default::default(),
    }))
}

fn a_release() -> ReleaseFacts {
    ReleaseFacts {
        reference: "tx_1".into(),
        sats: 10_000,
        fee_sats: 0,
        already_released_sats: 0,
    }
}

/// A release is judged on BOTH halves: what the transaction does, and what the provider says.
/// Neither alone is enough, which is the whole point of putting them in one tree.
#[test]
fn a_release_needs_the_transaction_and_the_evidence_to_agree() {
    let policy = Policy::AllOf {
        of: vec![
            Policy::OutputsOnlyTo { scripts: vec![DEST.into()] },
            Policy::TotalOutMax { sats: 10_000 },
            diva(),
        ],
    };
    policy.validate().expect("a policy that names a provider is a policy");

    let raw = tx_paying(&[(DEST, 10_000)]);
    let tx: Transaction = bitcoin::consensus::encode::deserialize(&raw).unwrap();
    let outs = outputs_of(&tx);
    let owned = nothing_owned();
    let release = a_release();

    // What has to be fetched is derived from the policy, never from the request.
    let needed = policy.evidence_needed(&release);
    assert_eq!(needed.len(), 1);
    assert_eq!(needed[0].provider, "https://diva.example");
    assert_eq!(needed[0].path, "/v1/transactions/tx_1");

    let good = std::collections::BTreeMap::from([(
        needed[0].key(),
        Evidence::Json(serde_json::json!({"state": "COMPLETION", "token": "tx_1"})),
    )]);
    assert!(cosigner::policy::enforce_release(&policy, Some(&outs), &owned, &release, &good).is_ok());

    // The same transaction, with the payment not completed: refused.
    let bad = std::collections::BTreeMap::from([(
        needed[0].key(),
        Evidence::Json(serde_json::json!({"state": "PENDING", "token": "tx_1"})),
    )]);
    assert!(cosigner::policy::enforce_release(&policy, Some(&outs), &owned, &release, &bad).is_err());

    // Perfect evidence, and a transaction that pays somebody else: also refused.
    let elsewhere = tx_paying(&[("51200000000000000000000000000000000000000000000000000000000000000000", 10_000)]);
    let other: Transaction = bitcoin::consensus::encode::deserialize(&elsewhere).unwrap();
    assert!(cosigner::policy::enforce_release(
        &policy,
        Some(&outputs_of(&other)),
        &owned,
        &release,
        &good
    )
    .is_err());
}

/// A policy carrying an evidence condition cannot be satisfied on a path that has no release —
/// the wallet's own renewal and send, which know nothing about a payment.
#[test]
fn an_evidence_condition_denies_where_there_is_no_release_to_bind_to() {
    let raw = tx_paying(&[(DEST, 10_000)]);
    let tx: Transaction = bitcoin::consensus::encode::deserialize(&raw).unwrap();
    let err = cosigner::policy::enforce_outputs(&diva(), Some(&outputs_of(&tx)), &nothing_owned())
        .unwrap_err();
    assert!(err.contains("what release it is judging"), "{err}");
}

/// Every branch's evidence is gathered, including one a short-circuit might never reach: which
/// branch answers is not known until it has been asked.
#[test]
fn evidence_is_gathered_from_branches_an_any_of_might_skip() {
    let mut second = match diva() {
        Policy::HttpGet(c) => *c,
        _ => unreachable!(),
    };
    second.path = "/v2/payments/{reference}".into();
    let policy = Policy::AnyOf {
        of: vec![diva(), Policy::HttpGet(Box::new(second))],
    };
    let needed = policy.evidence_needed(&a_release());
    assert_eq!(needed.len(), 2, "both branches, not just the first");
}

/// Two conditions asking the same provider the same question are fetched once.
#[test]
fn the_same_question_is_not_asked_twice() {
    let policy = Policy::AllOf { of: vec![diva(), diva()] };
    assert_eq!(policy.evidence_needed(&a_release()).len(), 1);
}

// ===============================================================================================
// The two terms a release added: what a transaction may lose, and what an escrow may pay out in
// total. Both read `ReleaseFacts`, so both deny outside a release rather than guessing.
// ===============================================================================================

fn facts(sats: u64, fee_sats: u64, already_released_sats: u64) -> ReleaseFacts {
    ReleaseFacts {
        reference: "tx_1".into(),
        sats,
        fee_sats,
        already_released_sats,
    }
}

fn judge(policy: &Policy, facts: &ReleaseFacts) -> Result<(), String> {
    cosigner::policy::enforce_release(
        policy,
        Some(&[]),
        &Default::default(),
        facts,
        &BTreeMap::new(),
    )
}

#[test]
fn a_fee_cap_permits_what_is_under_it_and_refuses_what_is_over() {
    let policy = Policy::FeeMax { sats: 500 };
    assert!(judge(&policy, &facts(10_000, 0, 0)).is_ok());
    assert!(judge(&policy, &facts(10_000, 500, 0)).is_ok(), "the cap itself is allowed");
    let err = judge(&policy, &facts(10_000, 501, 0)).unwrap_err();
    assert!(err.contains("501 sats in fees"), "{err}");
}

/// Zero is the normal setting on Ark, where a send conserves value exactly.
#[test]
fn a_fee_cap_of_zero_says_the_escrow_may_lose_nothing() {
    let policy = Policy::FeeMax { sats: 0 };
    assert!(policy.validate().is_ok(), "unlike an amount cap, zero is a meaningful fee cap");
    assert!(judge(&policy, &facts(10_000, 0, 0)).is_ok());
    assert!(judge(&policy, &facts(10_000, 1, 0)).is_err());
    assert_eq!(policy.describe(), "must not lose any of what it spends");
}

/// A running total, not a per-transaction one: an escrow is spent against over days.
#[test]
fn a_total_release_cap_counts_what_has_already_gone() {
    let policy = Policy::ReleasedTotalMax { sats: 10_000 };
    assert!(judge(&policy, &facts(10_000, 0, 0)).is_ok());
    assert!(judge(&policy, &facts(4_000, 0, 6_000)).is_ok(), "exactly the cap");
    let err = judge(&policy, &facts(4_001, 0, 6_000)).unwrap_err();
    assert!(err.contains("6000 sats have been released already"), "{err}");
}

#[test]
fn a_running_total_that_would_overflow_denies_rather_than_wrapping() {
    let policy = Policy::ReleasedTotalMax { sats: u64::MAX };
    let err = judge(&policy, &facts(u64::MAX, 0, 1)).unwrap_err();
    assert!(err.contains("overflows"), "{err}");
}

/// Both terms are about a release. Asked outside one — a renewal, a send the owner drove — they
/// refuse rather than reading a missing figure as zero.
#[test]
fn the_release_terms_deny_where_there_is_no_release_to_read() {
    for policy in [
        Policy::FeeMax { sats: 500 },
        Policy::ReleasedTotalMax { sats: 10_000 },
    ] {
        let err = cosigner::policy::enforce(&policy, &[], &Default::default())
            .expect_err("no release to judge");
        assert!(
            err.contains("no release") || err.contains("not a release"),
            "{err}"
        );
    }
}
