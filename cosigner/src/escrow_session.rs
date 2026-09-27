//! When an escrow may be released, and when it may be taken back.
//!
//! An escrow key is signed by two different pairs — `{wallet, cosigner}` and `{service, cosigner}`
//! — and this cosigner is in both. So which of them gets a signature, and when, is not a property
//! of the key at all. It is a decision, made here, on sealed state.
//!
//! ```text
//!   opened ──────────────────────────────────▶ deadline ─────────────────▶
//!     │                                           │
//!     │  service + cosigner may release           │  wallet + cosigner may reclaim
//!     │  wallet  + cosigner may NOT reclaim       │  service may no longer release
//! ```
//!
//! # The clock, and only the protected party may move it
//!
//! A session is a policy and a date, and which side of that date `now` falls on is the whole
//! decision. There is no flag that says a deal is over: every answer below is read out of the seal
//! and the clock.
//!
//! **The owner cannot end a deal.** She is the one who committed, and a commitment she can revoke
//! at will is not one: a service that has already paid a merchant against it would be left holding
//! the loss, which is exactly the thing this is supposed to prevent. Her control is in choosing the
//! deadline, not in taking it back afterwards.
//!
//! **The service may.** A deal protects the service, so the service is the one party that can give
//! that protection up: [`end_by_service`](EscrowSession::end_by_service) brings the deadline
//! forward to now, and never pushes it back. A payout that failed is the case — the service is owed
//! nothing, and an escrow held until a deadline hours away would help nobody.
//!
//! **And a spent deal holds nothing.** Once everything a deal allows has been released
//! ([`spent`](EscrowSession::spent)), the service has had all this deal could give it, so the
//! escrow is free to be committed to the next one. Its deadline still stands for what matters after
//! a release: a repeat of it is answered until then, and the owner may not take the escrow back
//! before it — see [`Cosigner::reclaim_horizon`](crate::Cosigner::reclaim_horizon).
//!
//! That is still one way for time to run out on a deal, read the same way by every instance: the
//! deadline moves only earlier, and only at the service's word.
//!
//! **Say plainly what holds this up.** Nothing in Bitcoin enforces the line above. Both pairings
//! sign the same key, so what stops an owner emptying a live escrow is this cosigner declining to
//! co-sign with them before the deadline — and what stops a service taking after it is the same
//! refusal pointed the other way. The escrow is enclave-enforced, not script-enforced. That is
//! defensible because the refusal lives in attested, measured code that a client verifies before it
//! sends anything; it is *not* the same guarantee as an output that cannot be spent, and nothing
//! here should be written as though it were.
//!
//! # Nothing runs at the deadline, and nothing needs to
//!
//! There is no task armed for when a deal ends, and no scheduler behind this module. A deadline is
//! a fact about the clock: [`may_release`](EscrowSession::may_release) and
//! [`may_reclaim`](EscrowSession::may_reclaim) read it out of the seal and compare it to `now`, so
//! an instance that did not exist when the deadline passed reaches exactly the same answer as one
//! that did. There is nothing to resume and nothing to recover.
//!
//! What this costs, said plainly: **nobody tells the owner their escrow has ended.** A task used to,
//! and buying that notification meant keeping a scheduler alive for every live deal. The owner
//! learns the same thing from `EscrowList` the next time the app looks, and the money is no less
//! theirs for not having been announced.
//!
//! # The connection is a different thing, and the runtime holds it
//!
//! The service does need a live connection — it has no passkey for this tenant, so it can never
//! call in, and a deal outlives any one socket. That connection is not this module's and not a
//! timer's: the runtime holds it, re-dials it after a drop, and starts it again from its own
//! records at boot. See [`crate::service_stream`], which says exactly what reconnects and when.
//!
//! # Many releases, one escrow
//!
//! A card escrow is not one payment. The owner commits an amount, spends against it over days, and
//! takes back what is left. So a release does **not** close the session; only its deadline does —
//! or releasing everything the deal allows, which a payout of one agreed price does in one go. [`released_sats`](EscrowSession::released_sats) accumulates, and that running total is what
//! [`Policy::ReleasedTotalMax`](crate::policy::Policy::ReleasedTotalMax) is checked against — a
//! per-transaction cap would bound each tap and not the deal.
//!
//! And because a payment that succeeded goes on being true, every payment that has justified a
//! release is written down — but **not here**. That record belongs to the wallet, not to a deal:
//! a session can be replaced, and a wallet can hold several escrows with the same service, so a
//! ledger scoped to one session would let a spent payment be spent again by reopening or by asking
//! the next escrow along. See [`Cosigner::admit_release`](crate::Cosigner::admit_release).

use serde::{Deserialize, Serialize};

use crate::policy::Policy;

/// One escrow's session: what the service may take, and until when.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EscrowSession {
    /// What a release must satisfy. [`Policy::Never`] by default, so an escrow whose policy failed
    /// to deserialize releases nothing rather than everything.
    #[serde(default)]
    pub policy: Policy,
    /// Unix seconds.
    pub opened_at: i64,
    /// Unix seconds. After this the service may no longer release and the owner may reclaim.
    pub deadline: i64,
    /// What has been released so far **in this deal**. Accumulates across releases — a cumulative
    /// cap is checked against this, not against one transaction.
    ///
    /// Per-session on purpose, unlike the record of which payments have been spent: this is the
    /// allowance of one deal, and reopening an escrow is a new deal with a new allowance. What must
    /// NOT reset is which payments have already been paid against, and that is why it does not live
    /// here — see [`Cosigner::admit_release`](crate::Cosigner::admit_release).
    #[serde(default)]
    pub released_sats: u64,
}

/// What the escrow's own service is told about the deal it is asking against.
///
/// A service fronts money before it is repaid, and it cannot see the seal. Two things it must know
/// before it does, and neither can come from the owner's app, which is the party a service is
/// guarding against: **until when** it may be repaid, and **which policy** was sealed. The second is
/// not idle — `all_of` stops at its first failing term, so a policy with a term appended after the
/// one the service expects to fail refuses in exactly the same words, and then refuses for ever.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DealTerms {
    /// Unix seconds.
    pub opened_at: i64,
    /// Unix seconds. After this nothing is released, and a service that has not been repaid by then
    /// will not be.
    pub deadline: i64,
    /// [`policy_sha256`](crate::policy::policy_sha256) of the sealed policy.
    pub policy_sha256: String,
}

/// Why a party may not sign right now. Each is a different thing to tell somebody.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Refusal {
    /// The service asked after the deadline.
    DealEnded,
    /// The owner asked while the escrow is still live and the service may still take.
    StillOpen,
}

impl Refusal {
    pub fn message(self) -> &'static str {
        match self {
            Refusal::DealEnded => {
                "this escrow's deal is over: it passed its deadline, and nothing more is released \
                 from it"
            }
            Refusal::StillOpen => {
                "this escrow's deal is still running: it can be taken back once the deadline \
                 passes, and until then the money is committed to it"
            }
        }
    }
}

impl EscrowSession {
    /// Strike a deal that runs until [`deadline`](Self::deadline).
    ///
    /// There is no matching `close` for the owner. See the module note: a commitment the owner can
    /// revoke is not one, and the deadline she chooses here is the whole of her control over it.
    pub fn open(policy: Policy, now: i64, deadline: i64) -> Result<Self, String> {
        if deadline <= now {
            return Err("a deal that is already over commits nothing to anybody".into());
        }
        policy.validate()?;
        Ok(Self {
            policy,
            opened_at: now,
            deadline,
            released_sats: 0,
        })
    }

    /// Whether the deal is still live.
    ///
    /// The clock, and nothing else. Time passes without anybody writing anything down, so a
    /// restart reaches the same conclusion as the instance that struck the deal — from the seal
    /// and the clock, which is all there is.
    pub fn is_open(&self, now: i64) -> bool {
        now < self.deadline
    }

    /// May `{service, cosigner}` sign? The *timing* question only — what a release pays and how
    /// much is the policy's business, and is checked separately against the transaction.
    pub fn may_release(&self, now: i64) -> Result<(), Refusal> {
        if self.is_open(now) {
            Ok(())
        } else {
            Err(Refusal::DealEnded)
        }
    }

    /// May `{wallet, cosigner}` sign? Only once the escrow is no longer live — otherwise an owner
    /// could empty an escrow the service is still entitled to take from.
    pub fn may_reclaim(&self, now: i64) -> Result<(), Refusal> {
        if self.is_open(now) {
            Err(Refusal::StillOpen)
        } else {
            Ok(())
        }
    }

    /// Count a release against this deal's allowance. Does not end the deal: an escrow is spent
    /// against, not spent once. Only a total that reaches the policy's cap frees the escrow for the
    /// next deal — see [`spent`](Self::spent).
    ///
    /// Only ever called for a release that was not counted before — a second signature over an
    /// already-answered request adds nothing, because it spends the inputs the first one did.
    pub fn record_release(&mut self, sats: u64) {
        self.released_sats = self.released_sats.saturating_add(sats);
    }

    /// Has everything this deal allows been released?
    ///
    /// Derived, never recorded: the cap is the policy's own `released_total_max` and the total is
    /// the one [`record_release`](Self::record_release) keeps. A policy with no such cap is never
    /// spent, and runs to its deadline as it always did.
    pub fn spent(&self) -> bool {
        self.policy
            .released_total_cap()
            .is_some_and(|cap| self.released_sats >= cap)
    }

    /// Does this deal still keep the escrow from being committed to another?
    ///
    /// A spent deal does not: the service has had everything it could have. Its deadline still
    /// bounds a reclaim, which reads the release records rather than this — a spent deal whose last
    /// release has not reached the ASP yet must not be emptied from under it.
    pub fn holds_the_escrow(&self, now: i64) -> bool {
        self.is_open(now) && !self.spent()
    }

    /// The service ends the deal: the deadline comes forward to `now`, and never goes back.
    ///
    /// Only the service may ask, because the deal protects the service — this gives up nothing but
    /// its own claim. What was already released keeps its own deadline in its record, so ending the
    /// deal early does not let the owner race a release the service has yet to submit.
    pub fn end_by_service(&mut self, now: i64) {
        self.deadline = self.deadline.min(now);
    }

    /// What the service is told about this deal. See [`DealTerms`].
    pub fn terms(&self) -> DealTerms {
        DealTerms {
            opened_at: self.opened_at,
            deadline: self.deadline,
            policy_sha256: crate::policy::policy_sha256(&self.policy),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const NOW: i64 = 1_000_000;
    const HOUR: i64 = 3_600;

    fn session() -> EscrowSession {
        EscrowSession::open(Policy::Always, NOW, NOW + HOUR).unwrap()
    }

    #[test]
    fn while_it_is_running_the_service_may_take_and_the_owner_may_not() {
        let s = session();
        assert!(s.may_release(NOW).is_ok());
        assert!(s.may_release(NOW + HOUR - 1).is_ok());
        assert_eq!(s.may_reclaim(NOW), Err(Refusal::StillOpen));
    }

    /// The moment the clock passes, both answers swap — with nothing written down in between, and
    /// nothing to write. That is the whole of the design: one way for a deal to end, and it leaves
    /// no record because there is no record to leave.
    #[test]
    fn at_the_deadline_the_answers_swap_without_anybody_writing_anything() {
        let s = session();
        assert!(s.may_release(NOW + HOUR - 1).is_ok());
        assert_eq!(s.may_reclaim(NOW + HOUR - 1), Err(Refusal::StillOpen));

        assert_eq!(s.may_release(NOW + HOUR), Err(Refusal::DealEnded));
        assert!(s.may_reclaim(NOW + HOUR).is_ok());

        // And a reseated instance reads the same seal and agrees, because the seal never changed.
        let round_tripped: EscrowSession =
            serde_json::from_str(&serde_json::to_string(&s).unwrap()).unwrap();
        assert_eq!(round_tripped.may_release(NOW + HOUR), Err(Refusal::DealEnded));
        assert!(round_tripped.may_reclaim(NOW + HOUR).is_ok());
    }

    /// The owner has no way to end a deal early, and that is the point rather than an omission.
    ///
    /// A commitment the owner can revoke is not a commitment: a service that had already paid a
    /// merchant against it would be left holding the loss. Her control is the deadline she chose.
    /// The two things that shorten a deal both belong to the service: ending it, and taking all of
    /// it.
    #[test]
    fn only_the_service_can_cut_a_deal_short() {
        let s = session();
        // The whole of a session's state. If something else that ends a deal early is ever added,
        // this stops compiling — which is the point of writing it down.
        let EscrowSession {
            policy: _,
            opened_at: _,
            deadline,
            released_sats: _,
        } = s.clone();
        assert_eq!(deadline, NOW + HOUR);
        assert!(s.may_release(NOW + HOUR - 1).is_ok(), "the owner cannot cut this short");
    }

    #[test]
    fn the_service_ending_a_deal_brings_the_deadline_forward_and_never_back() {
        let mut s = session();
        s.end_by_service(NOW + 60);
        assert_eq!(s.deadline, NOW + 60);
        assert_eq!(s.may_release(NOW + 60), Err(Refusal::DealEnded));
        assert!(s.may_reclaim(NOW + 60).is_ok());

        // Ending it again later is not a way to extend it.
        s.end_by_service(NOW + HOUR * 2);
        assert_eq!(s.deadline, NOW + 60);
    }

    fn capped(sats: u64) -> EscrowSession {
        let policy = Policy::AllOf {
            of: vec![Policy::TotalOutMax { sats }, Policy::ReleasedTotalMax { sats }],
        };
        EscrowSession::open(policy, NOW, NOW + HOUR).unwrap()
    }

    /// A payout of one agreed price releases it all at once, and then the deal has nothing left to
    /// give: the escrow is free for the next one while the deadline still stands.
    #[test]
    fn a_deal_whose_allowance_is_released_no_longer_holds_the_escrow() {
        let mut s = capped(23_010);
        assert!(s.holds_the_escrow(NOW));
        s.record_release(23_000);
        assert!(!s.spent(), "ten sats short of the cap is not spent");
        assert!(s.holds_the_escrow(NOW));
        s.record_release(10);
        assert!(s.spent());
        assert!(!s.holds_the_escrow(NOW), "spent, so the next deal may be struck");
        assert!(s.is_open(NOW), "and its deadline is untouched");
    }

    /// A cap is only a cap on the deal where it binds unconditionally. One branch of an `any_of`
    /// may be satisfied without it, so it cannot say the deal is spent.
    #[test]
    fn only_an_unconditional_cap_can_spend_a_deal() {
        let mut uncapped = session();
        uncapped.record_release(u64::MAX);
        assert!(!uncapped.spent(), "a deal with no cap runs to its deadline");

        let either = Policy::AnyOf {
            of: vec![Policy::ReleasedTotalMax { sats: 1 }, Policy::Always],
        };
        let mut s = EscrowSession::open(either, NOW, NOW + HOUR).unwrap();
        s.record_release(1_000);
        assert!(!s.spent());

        // Nested all_of chains count, and the smallest cap wins.
        let nested = Policy::AllOf {
            of: vec![
                Policy::ReleasedTotalMax { sats: 500 },
                Policy::AllOf { of: vec![Policy::ReleasedTotalMax { sats: 100 }] },
            ],
        };
        let mut s = EscrowSession::open(nested, NOW, NOW + HOUR).unwrap();
        s.record_release(100);
        assert!(s.spent());
    }

    #[test]
    fn the_terms_name_the_sealed_policy_and_its_deadline() {
        let s = capped(1_000);
        let terms = s.terms();
        assert_eq!(terms.opened_at, NOW);
        assert_eq!(terms.deadline, NOW + HOUR);
        assert_eq!(terms.policy_sha256, crate::policy::policy_sha256(&s.policy));
        assert_ne!(
            terms.policy_sha256,
            capped(1_001).terms().policy_sha256,
            "a different policy is a different deal"
        );
    }

    /// One escrow, many releases: a card is tapped more than once. This is the ALLOWANCE only —
    /// which payments have been spent is the wallet's ledger, tested in `release_test.rs`.
    #[test]
    fn releases_accumulate_and_do_not_end_the_deal() {
        let mut s = session();
        s.record_release(1_000);
        s.record_release(2_500);
        assert_eq!(s.released_sats, 3_500);
        assert!(s.may_release(NOW + 60).is_ok(), "an escrow is spent against, not spent once");
    }

    #[test]
    fn a_release_total_cannot_be_made_to_wrap() {
        let mut s = session();
        s.record_release(u64::MAX);
        s.record_release(u64::MAX);
        assert_eq!(s.released_sats, u64::MAX, "saturating, so a total never wraps to nothing");
    }

    #[test]
    fn a_deal_that_is_already_over_is_refused() {
        assert!(EscrowSession::open(Policy::Always, NOW, NOW).is_err());
        assert!(EscrowSession::open(Policy::Always, NOW, NOW - 1).is_err());
    }

    #[test]
    fn a_policy_that_is_not_one_is_refused_at_the_door() {
        let empty = Policy::AllOf { of: vec![] };
        assert!(EscrowSession::open(empty, NOW, NOW + HOUR).is_err());
    }

    /// The seal is the only thing that carries a session across a restart, so what it omits must
    /// come back as the safe answer rather than the convenient one.
    #[test]
    fn a_seal_missing_its_policy_releases_nothing() {
        let json = format!(
            r#"{{"opened_at":{NOW},"deadline":{}}}"#,
            NOW + HOUR
        );
        let restored: EscrowSession = serde_json::from_str(&json).expect("an older seal");
        assert_eq!(restored.policy, Policy::Never);
        assert_eq!(restored.released_sats, 0);
        // Still running by the clock — the refusal it gives a release comes from the policy.
        assert!(restored.may_release(NOW).is_ok());
    }

    #[test]
    fn a_session_survives_a_seal_round_trip() {
        let mut s = session();
        s.record_release(42);
        let round_tripped: EscrowSession =
            serde_json::from_str(&serde_json::to_string(&s).unwrap()).unwrap();
        assert_eq!(round_tripped.released_sats, 42);
        assert_eq!(round_tripped.deadline, NOW + HOUR);
    }
}
