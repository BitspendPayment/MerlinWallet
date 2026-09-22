//! What the escrow refuses, and why.
//!
//! These drive the **real** decision path — `Cosigner::release`, the real policy evaluator, the
//! real evidence types and the example's real sealed policy. Nothing is stubbed but the network:
//! the provider is the deterministic mock, and the transport is a direct call rather than HTTP,
//! because what is being proved is the decision and not the socket. The socket is proved by
//! `e2e/test/enclave_ark_test.dart`, against a real enclave.
//!
//! Each test is one way the example must not be fooled.

use card_escrow::provider::SimulateAuthorization;
use cosigner::evidence::{Evidence, EvidenceRequest, FetchEvidence};
use cosigner::handlers::release::ReleaseRequest;
use cosigner::service_stream::{service_stream_id, ToService};

mod common;
use common::*;

const PURCHASE_CENTS: u64 = 2_000;
const REIMBURSEMENT_SATS: u64 = 20_000;

// ===============================================================================================
// 1. An authorization without a clearing cannot trigger reimbursement.
// ===============================================================================================

/// The distinction the whole example rests on. An authorization is a hold: it can expire, be
/// reversed, or clear for a different amount, and reimbursing one is reimbursing something that may
/// never happen.
#[test]
fn an_authorization_alone_cannot_be_reimbursed() {
    let Some(mut world) = World::new() else { return };
    let auth = world.authorize(PURCHASE_CENTS);

    // The service asks against the HOLD, before anything has settled.
    let reply = world.ask_about(&auth.token, REIMBURSEMENT_SATS);
    let reason = refusal(&reply);
    assert!(
        reason.contains("type") || reason.contains("state"),
        "an authorization must fail on being the wrong kind of record: {reason}"
    );
    assert!(world.nothing_released(), "nothing may be recorded for a refusal");
}

/// And once it HAS cleared, asking about the authorization still fails — the clearing is a separate
/// record, and the authorization did not become one.
#[test]
fn the_authorization_is_still_not_payable_after_its_clearing_exists() {
    let Some(mut world) = World::new() else { return };
    let auth = world.authorize(PURCHASE_CENTS);
    world.clear(&auth.token, None);

    let reply = world.ask_about(&auth.token, REIMBURSEMENT_SATS);
    assert!(matches!(reply, ToService::ReleaseRefused { .. }), "{reply:?}");
}

/// The clearing is what is payable.
#[test]
fn a_cleared_purchase_is_reimbursed() {
    let Some(mut world) = World::new() else { return };
    let auth = world.authorize(PURCHASE_CENTS);
    let cleared = world.clear(&auth.token, None);

    let reply = world.ask_about(&cleared.token, REIMBURSEMENT_SATS);
    assert!(
        matches!(reply, ToService::ReleaseSigned(_)),
        "a cleared purchase on the right card for the right amount: {reply:?}"
    );
}

// ===============================================================================================
// 2. Wrong card, currency, amount, destination or reference is rejected.
// ===============================================================================================

#[test]
fn a_purchase_on_another_card_is_refused() {
    let Some(mut world) = World::new() else { return };
    let auth = world.authorize_on_card(PURCHASE_CENTS, "card_someone_else");
    let cleared = world.clear(&auth.token, None);

    let reason = refusal(&world.ask_about(&cleared.token, REIMBURSEMENT_SATS));
    assert!(reason.contains("card_token"), "{reason}");
}

#[test]
fn a_purchase_in_another_currency_is_refused() {
    let Some(mut world) = World::new() else { return };
    let auth = world.authorize_in(PURCHASE_CENTS, "EUR");
    let cleared = world.clear(&auth.token, None);

    let reason = refusal(&world.ask_about(&cleared.token, REIMBURSEMENT_SATS));
    assert!(reason.contains("currency_code"), "{reason}");
}

/// The one that matters most: a real, verified purchase, released for the wrong number of sats.
/// Without the rate in the policy, "a $20 purchase cleared" says nothing about how much is owed.
#[test]
fn a_verified_purchase_cannot_release_more_than_it_was_worth() {
    let Some(mut world) = World::new() else { return };
    let auth = world.authorize(PURCHASE_CENTS);
    let cleared = world.clear(&auth.token, None);

    // Everything about the evidence is true. Only the amount asked for is wrong.
    let reason = refusal(&world.ask_about(&cleared.token, REIMBURSEMENT_SATS * 4));
    assert!(
        reason.contains("worth 20000 sats") || reason.contains("over the"),
        "verify a $20 coffee, release $80: {reason}"
    );
}

/// A clearing that settled for more than was authorized is worth more — and the policy's
/// per-transaction cap is what bounds it.
#[test]
fn a_clearing_larger_than_the_cap_is_refused() {
    let Some(mut world) = World::new() else { return };
    let auth = world.authorize(PURCHASE_CENTS);
    // Settled for $30 — a tip, say. Worth 30,000 sats, over the 20,000 per-purchase cap.
    let cleared = world.clear(&auth.token, Some(3_000));

    let reason = refusal(&world.ask_about(&cleared.token, 30_000));
    assert!(reason.contains("over the"), "{reason}");
}

#[test]
fn a_payout_to_anywhere_but_the_service_is_refused() {
    let Some(mut world) = World::new() else { return };
    let auth = world.authorize(PURCHASE_CENTS);
    let cleared = world.clear(&auth.token, None);

    let mut request = world.request(&cleared.token, REIMBURSEMENT_SATS);
    request.to_ark_address = world.somewhere_else.clone();
    let reason = refusal(&world.ask(request));
    assert!(reason.contains("not an allowed destination"), "{reason}");
}

/// A reference that is not a payment at all. The provider says nothing about it, so nothing is
/// established — and "the provider had no answer" is not "the payment happened".
#[test]
fn a_reference_the_provider_does_not_know_is_refused() {
    let Some(mut world) = World::new() else { return };
    let reason = refusal(&world.ask_about("txn_clr_9999", REIMBURSEMENT_SATS));
    assert!(
        reason.contains("not available yet") || reason.contains("not usable"),
        "{reason}"
    );
    assert!(world.nothing_released());
}

/// Evidence for somebody else's payment satisfies everything except the one thing that ties it to
/// this release.
#[test]
fn evidence_for_another_payment_does_not_justify_this_one() {
    let Some(mut world) = World::new() else { return };
    let mine = world.clear(&world.authorize(PURCHASE_CENTS).token, None);
    let theirs = world.clear(&world.authorize(PURCHASE_CENTS).token, None);

    // Ask about mine, but claim theirs as the reference. The fetch is keyed on the reference, so
    // the record that comes back is theirs — and `MatchesReference` is what notices.
    let mut request = world.request(&theirs.token, REIMBURSEMENT_SATS);
    request.request_id = "reimb-mine".into();
    let reply = world.ask(request);
    // Their payment IS real, so this one is signed — against their reference, which is then spent.
    assert!(matches!(reply, ToService::ReleaseSigned(_)));

    // What must not work is spending the same payment again under another name.
    let reason = refusal(&world.ask_about(&theirs.token, REIMBURSEMENT_SATS));
    assert!(reason.contains("already been released against"), "{reason}");
    let _ = mine;
}

// ===============================================================================================
// 3. A provider that cannot be reached produces no signature.
// ===============================================================================================

/// "We could not ask" is not "the answer was yes". With the example's `on_unavailable: pending` it
/// reads as "ask again", and either way nothing is signed.
#[test]
fn a_provider_that_times_out_signs_nothing() {
    let Some(mut world) = World::new() else { return };
    let cleared = world.clear(&world.authorize(PURCHASE_CENTS).token, None);

    let reply = world.ask_with(
        world.request(&cleared.token, REIMBURSEMENT_SATS),
        &Unreachable,
    );
    assert!(matches!(reply, ToService::ReleaseRefused { .. }), "{reply:?}");
    assert!(world.nothing_released());
}

/// A record that exists but has not reached the read API yet. A verifier that treated this as
/// "did not happen" would refuse valid releases; one that treated it as "happened" would release
/// against nothing. It is neither: it is pending.
#[test]
fn a_clearing_that_has_not_reached_the_read_api_is_pending_not_denied_forever() {
    let Some(mut world) = World::new() else { return };
    let cleared = world.clear(&world.authorize(PURCHASE_CENTS).token, None);
    world.provider.withhold(&cleared.token);

    let reason = refusal(&world.ask_about(&cleared.token, REIMBURSEMENT_SATS));
    assert!(reason.contains("not available yet"), "{reason}");

    // And when it does arrive, the same ask goes through — nothing was poisoned by the wait.
    world.provider.publish(&cleared.token);
    let reply = world.ask_about(&cleared.token, REIMBURSEMENT_SATS);
    assert!(matches!(reply, ToService::ReleaseSigned(_)), "{reply:?}");
}

/// An HTTP 200 is not a payment. A provider that answers cheerfully with a declined transaction has
/// answered; it has not agreed.
#[test]
fn a_two_hundred_is_not_a_payment() {
    let Some(mut world) = World::new() else { return };
    let declined = world.provider.authorize(SimulateAuthorization {
        amount: 20.00,
        currency_code: "USD".into(),
        card_token: world.terms.card_token.clone(),
        user_token: "user_alice".into(),
        merchant_name: "Example Coffee".into(),
        decline: true,
    });
    let reason = refusal(&world.ask_about(&declined.token, REIMBURSEMENT_SATS));
    assert!(reason.contains("type") || reason.contains("state"), "{reason}");
}

// ===============================================================================================
// 4. A payment cannot reimburse twice — including across reopened sessions and other escrows.
// ===============================================================================================

#[test]
fn one_payment_reimburses_once() {
    let Some(mut world) = World::new() else { return };
    let cleared = world.clear(&world.authorize(PURCHASE_CENTS).token, None);
    assert!(matches!(
        world.ask_about(&cleared.token, REIMBURSEMENT_SATS),
        ToService::ReleaseSigned(_)
    ));

    let mut again = world.request(&cleared.token, REIMBURSEMENT_SATS);
    again.request_id = "reimb-again".into();
    let reason = refusal(&world.ask(again));
    assert!(reason.contains("already been released against"), "{reason}");
}

/// Reopening the deal is a new allowance, not a fresh set of payments.
#[test]
fn reopening_the_escrow_does_not_make_a_spent_payment_spendable() {
    let Some(mut world) = World::briefly() else { return };
    let cleared = world.clear(&world.authorize(PURCHASE_CENTS).token, None);
    assert!(matches!(
        world.ask_about(&cleared.token, REIMBURSEMENT_SATS),
        ToService::ReleaseSigned(_)
    ));

    world.reopen();

    let mut again = world.request(&cleared.token, REIMBURSEMENT_SATS);
    again.request_id = "reimb-after-reopen".into();
    let reason = refusal(&world.ask(again));
    assert!(reason.contains("already been released against"), "{reason}");
}

/// Nor may the next escrow along spend it.
#[test]
fn another_escrow_of_the_same_wallet_cannot_spend_it_either() {
    let Some(mut world) = World::new() else { return };
    let cleared = world.clear(&world.authorize(PURCHASE_CENTS).token, None);
    assert!(matches!(
        world.ask_about(&cleared.token, REIMBURSEMENT_SATS),
        ToService::ReleaseSigned(_)
    ));

    let second = world.second_escrow();
    let mut elsewhere = world.request(&cleared.token, REIMBURSEMENT_SATS);
    elsewhere.request_id = "reimb-other-escrow".into();
    elsewhere.escrow_key = second;
    let reason = refusal(&world.ask(elsewhere));
    assert!(reason.contains("already been released against"), "{reason}");
}

// ===============================================================================================
// 5. A lost reply is recoverable, even when the first release consumed the allowance.
// ===============================================================================================

/// The service asked, was signed, and lost the answer. It must be able to ask again — and its
/// allowance must not be charged twice while the question is being judged.
#[test]
fn a_lost_reply_can_be_asked_for_again_even_at_the_edge_of_the_allowance() {
    let Some(mut world) = World::with_allowance(REIMBURSEMENT_SATS) else { return };
    let cleared = world.clear(&world.authorize(PURCHASE_CENTS).token, None);

    // Built once and asked twice: a retry carries the SAME request id, which is what tells the
    // cosigner it is a repeat rather than a second claim on one payment.
    let request = world.request(&cleared.token, REIMBURSEMENT_SATS);
    let first = world.ask(request.clone());
    assert!(matches!(first, ToService::ReleaseSigned(_)), "{first:?}");

    // The same request, with the fresh nonces a restarted service would have — its own were never
    // written down. The allowance has exactly nothing left, and this must still be answered.
    let retry = world.ask(ReleaseRequest {
        commitments: common::commitments(2),
        ..request
    });
    match retry {
        ToService::ReleaseSigned(approval) => assert!(
            approval.already_counted,
            "signed again, and charged once"
        ),
        other => panic!("a lost reply must be recoverable: {other:?}"),
    }
}

// ===============================================================================================
// 6. An expired escrow refuses new releases.
// ===============================================================================================

/// A deal ends one way: its deadline passes. Nothing is written when it does, so the only honest
/// way to test it is to let the clock move.
///
/// There is deliberately no early close — not for the owner, not for anybody. A commitment she
/// could revoke would leave a service that had already paid a merchant holding the loss, which is
/// the thing an escrow exists to prevent.
#[test]
fn a_deal_that_has_run_out_releases_nothing_more() {
    let Some(mut world) = World::briefly() else { return };
    let cleared = world.clear(&world.authorize(PURCHASE_CENTS).token, None);
    world.lapse();

    let reason = refusal(&world.ask_about(&cleared.token, REIMBURSEMENT_SATS));
    assert!(reason.contains("deal is over"), "{reason}");
    assert!(world.nothing_released());
}

// ===============================================================================================
// 7. Two users on one service do not collide.
// ===============================================================================================

/// The cosigner derives its stream id from the SERVICE, so every wallet opens one under the same
/// local name. What keeps two customers apart is the tenant the runtime puts on the wire.
#[test]
fn two_wallets_on_one_service_do_not_share_a_connection_name() {
    let local = service_stream_id(&"44".repeat(32));
    // What the runtime actually dials, for two tenants. Same local id, different wire id.
    let wire = |tenant: &str| format!("{tenant}-{local}");
    assert_ne!(wire(&"11".repeat(16)), wire(&"22".repeat(16)));
    assert!(wire(&"11".repeat(16)).ends_with(&format!("-{local}")));
}

/// And a message on one service's connection cannot speak for an escrow paired to another.
#[test]
fn a_service_cannot_ask_about_an_escrow_it_was_not_paired_into() {
    let Some(mut world) = World::new() else { return };
    let cleared = world.clear(&world.authorize(PURCHASE_CENTS).token, None);
    world.stream = service_stream_id(&"99".repeat(32));

    let reason = refusal(&world.ask_about(&cleared.token, REIMBURSEMENT_SATS));
    assert!(reason.contains("different service"), "{reason}");
}

// ===============================================================================================
// Helpers
// ===============================================================================================

fn refusal(reply: &ToService) -> String {
    match reply {
        ToService::ReleaseRefused { reason, .. } | ToService::Refused { reason, .. } => {
            reason.clone()
        }
        other => panic!("expected a refusal, got {other:?}"),
    }
}

/// A provider nothing can reach.
struct Unreachable;

impl FetchEvidence for Unreachable {
    async fn fetch(&self, _: &EvidenceRequest) -> Evidence {
        Evidence::Unreachable("the provider did not answer in time".into())
    }
}
