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
//! **And a spent deal has nothing left to give.** Once everything a deal allows has been released
//! ([`spent`](EscrowSession::spent)), the service has had all this deal could give it. Its
//! deadline still stands for what matters after a release: a repeat of it is answered until then,
//! and the owner may not take the escrow back before it — see
//! [`horizon`](EscrowSession::horizon).
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
//! or releasing everything the deal allows, which a payout of one agreed price does in one go.
//! [`released_sats`](EscrowSession::released_sats) accumulates, and that running total is what
//! [`Policy::ReleasedTotalMax`](crate::policy::Policy::ReleasedTotalMax) is checked against — a
//! per-transaction cap would bound each tap and not the deal.
//!
//! And because a payment that succeeded goes on being true, every payment that has justified a
//! release is written down, on the escrow that released it, for as long as the wallet holds it.
//! The check is the wallet's, over every escrow — a wallet holds one escrow per payment, often
//! with the same service, so a ledger consulted one escrow at a time would let a spent payment be
//! spent again by asking the next escrow along. See
//! [`Cosigner::admit_release`](crate::Cosigner::admit_release).

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};

use threshold::identifier::Identifier;
use threshold::keys::{KeyPackage, PublicKeyPackage};

use crate::grpc::Status;
use crate::policy::Policy;
use crate::session::proto;
use crate::types::{PairingState, ReleaseRecord, ServicePairing};

/// One escrow and everything that happens to it, sealed: a key of its own, the service paired into
/// it, the one deal it is committed to, and what that deal has released.
///
/// The key is a *second* 2-of-2 — `V' = V + Δ_wallet + Δ_cosigner`, minted by a reshare so the
/// wallet's own key is untouched and a service can be paired into the escrow without being paired
/// into the wallet. See `handlers::escrow`. Minted, paired and committed in one session, and never
/// committed again: the next payment mints the next escrow.
///
/// **Active** while its deal runs, or a release it signed may still be on its way to the ASP;
/// **over** past its [horizon](Self::horizon), when the owner may take back what is left. Kept
/// after that: what is left is still the owner's to take, and the payments it released must never
/// justify a release anywhere again — see `Cosigner::admit_release`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EscrowSession {
    /// `V'`, compressed hex. The escrow's identity, and the owner key of the Ark address it holds.
    pub escrow_key: String,
    /// This cosigner's share of `V'`.
    pub key_package_json: String,
    /// `V'`'s public package: the group key and both verifying shares.
    pub public_key_package_json: String,
    /// The wallet's FROST identifier in this escrow, as the reshare recorded it.
    pub wallet_identifier_hex: String,
    /// The derivation context the wallet dealt its delta under, hex. Kept so a repeat can be
    /// refused — two escrows on one delta are two points on one line.
    pub context_hex: String,
    /// `Δ_cosigner(id_wallet)`, hex: this cosigner's delta share for the wallet.
    ///
    /// The wallet keeps nothing; it rebuilds its escrow share per operation as
    /// `±[ s_wallet + Δ_wallet(id) + this ]`, where `s_wallet` is the wallet share it already
    /// rebuilds and `Δ_wallet` comes from its passkey. Kept as its own term and never pre-summed
    /// with `wallet_dealt_share_hex`: an even-Y normalisation sits between them, so a sum would be
    /// wrong for every wallet whose key came out with odd Y. See `handlers::escrow`.
    pub wallet_delta_share_hex: String,
    /// Unix seconds, when it was minted.
    pub created_at: i64,
    /// The service paired into this escrow, once one is. `None` until then — an escrow with no
    /// service is a key the wallet and this cosigner hold and nobody else can be paid from.
    #[serde(default)]
    pub pairing: Option<ServicePairing>,
    /// Its deal: what the service may take, and until when. `None` when the session that minted it
    /// ended before striking one — and then for good, because nothing else commits an escrow.
    #[serde(default)]
    pub terms: Option<DealTerms>,
    /// Every payment this escrow has released against, by the reference its provider knows it by.
    ///
    /// A payment that succeeded goes on being true, so what stops it paying twice is this record
    /// and nothing else — and the check is the wallet's, over every escrow it holds.
    #[serde(default)]
    pub releases: BTreeMap<String, ReleaseRecord>,
}

/// What a deal is: what its service may take, and until when.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DealTerms {
    /// What a release must satisfy. [`Policy::Never`] by default, so a deal whose policy failed to
    /// deserialize releases nothing rather than everything.
    #[serde(default)]
    pub policy: Policy,
    /// Unix seconds.
    pub opened_at: i64,
    /// Unix seconds. After this the service may no longer release and the owner may reclaim.
    pub deadline: i64,
}

/// What the escrow's own service is told about the deal it is asking against.
///
/// A service fronts money before it is repaid, and it cannot see the seal. Two things it must know
/// before it does, and neither can come from the owner's app, which is the party a service is
/// guarding against: **until when** it may be repaid, and **which policy** was sealed. The second is
/// not idle — `all_of` stops at its first failing term, so a policy with a term appended after the
/// one the service expects to fail refuses in exactly the same words, and then refuses for ever.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SealedTerms {
    /// Unix seconds.
    pub opened_at: i64,
    /// Unix seconds. After this nothing is released, and a service that has not been repaid by then
    /// will not be.
    pub deadline: i64,
    /// [`policy_sha256`](crate::policy::policy_sha256) of the sealed policy.
    pub policy_sha256: String,
}

/// An escrow's key material, as this cosigner holds it — see [`EscrowSession::details`].
pub(crate) struct EscrowDetails {
    /// This cosigner's share of `V'`.
    pub(crate) key_package: KeyPackage,
    /// The escrow's public package.
    pub(crate) public_key_package: PublicKeyPackage,
    /// The wallet's identifier in it.
    pub(crate) wallet_id: Identifier,
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

impl DealTerms {
    /// A deal that runs from `now` until `deadline`.
    ///
    /// There is no `close` for the owner. See the module note: a commitment the owner can revoke is
    /// not one, and the deadline she chooses here is the whole of her control over it.
    pub fn validate(policy: Policy, now: i64, deadline: i64) -> Result<Self, String> {
        if deadline <= now {
            return Err("a deal that is already over commits nothing to anybody".into());
        }
        policy.validate()?;
        Ok(Self {
            policy,
            opened_at: now,
            deadline,
        })
    }

    /// The deal an [`EscrowOpen`](proto::EscrowOpen) asks for, as of `now`.
    pub(crate) fn from_request(open: &proto::EscrowOpen, now: i64) -> Result<Self, Status> {
        // An unparseable policy is `never`, not `always`: a deal nobody can take from is a bad day,
        // and one anybody can take from is a lost escrow.
        let policy: Policy = serde_json::from_str(&open.policy_json)
            .map_err(|e| Status::invalid_argument(format!("that is not a policy: {e}")))?;
        Self::validate(policy, now, open.deadline_secs).map_err(Status::invalid_argument)
    }
}

impl EscrowSession {
    /// Its key material, to deal a pairing or sign a reclaim against. `None` when what was sealed
    /// does not parse.
    pub(crate) fn details(&self) -> Option<EscrowDetails> {
        let id_bytes: [u8; 32] = hex::decode(&self.wallet_identifier_hex).ok()?.try_into().ok()?;
        Some(EscrowDetails {
            key_package: KeyPackage::from_json(&self.key_package_json).ok()?,
            public_key_package: PublicKeyPackage::from_json(&self.public_key_package_json).ok()?,
            wallet_id: Identifier::deserialize(&id_bytes).ok()?,
        })
    }

    /// Record the service paired into it.
    ///
    /// One service per escrow, and refused if there is already one: a second pairing would be a
    /// second way to be paid out of money committed to a single deal, and the escrow has no way to
    /// say which of them the deal was with.
    pub fn record_pairing(&mut self, pairing: ServicePairing) -> Result<(), String> {
        // Replaceable only while unfinished — see the note at the call site in `session.rs`. A
        // retry deals fresh halves, so the record it replaces is one nothing could have used.
        if self.pairing.as_ref().is_some_and(|p| p.state() == PairingState::Ready) {
            return Err("this escrow already has a service paired into it".into());
        }
        self.pairing = Some(pairing);
        Ok(())
    }

    /// The WALLET's half of the confirmation: it delivered its own half and the service took it.
    ///
    /// Not enough on its own. A pairing becomes usable when the service has *also* said the share
    /// checks out — see [`ServicePairing::state`](crate::types::ServicePairing::state) — because
    /// the wallet cannot see the half it is vouching for.
    ///
    /// Idempotent: confirming one that is already confirmed is what a retry looks like, and the
    /// answer to it is yes.
    pub fn confirm_by_wallet(&mut self, attempt_id_hex: &str) -> Result<(), String> {
        self.confirm(attempt_id_hex, |p| p.wallet_confirmed = true)
    }

    /// The SERVICE's half: it holds both halves and the share they sum to matches the published
    /// verifying share. Arrives over the connection the runtime holds — see
    /// [`crate::service_stream`].
    pub fn confirm_by_service(&mut self, attempt_id_hex: &str) -> Result<(), String> {
        self.confirm(attempt_id_hex, |p| p.service_confirmed = true)
    }

    fn confirm(
        &mut self,
        attempt_id_hex: &str,
        set: impl FnOnce(&mut ServicePairing),
    ) -> Result<(), String> {
        let pairing = self.pairing.as_mut().ok_or("this escrow has no service paired into it")?;
        if pairing.attempt_id_hex != attempt_id_hex {
            // Confirming attempt A on the strength of attempt B's delivery would mark a pairing
            // usable that nobody has shown to work.
            return Err(
                "that confirmation is for a different pairing attempt than the one this escrow \
                 holds"
                    .into(),
            );
        }
        set(pairing);
        Ok(())
    }

    /// Commit it to its deal: once, by the session that minted it and paired its service in.
    /// Refuses an escrow with no service, and refuses a second deal.
    ///
    /// No service means nobody could ever release, so a deal on such an escrow would lock the owner
    /// out of their own money until a deadline for no one's benefit. And never twice: once a
    /// reclaim may have been opened the owner may hold signatures that empty the escrow, and a deal
    /// struck over them would be one the owner could empty at will — so the next deal gets the next
    /// escrow, always.
    pub fn strike_deal(&mut self, terms: DealTerms) -> Result<(), String> {
        if self.pairing.is_none() {
            return Err(
                "this escrow has no service paired into it: committing it would lock the money \
                 away until the deadline with nobody able to take it"
                    .into(),
            );
        }
        if self.terms.is_some() {
            return Err(
                "this escrow is already committed to its deal; the next deal needs a new escrow"
                    .into(),
            );
        }
        self.terms = Some(terms);
        Ok(())
    }

    /// Whether its deal is running: struck, and before its deadline.
    ///
    /// The clock, and nothing else. Time passes without anybody writing anything down, so a restart
    /// reaches the same conclusion as the instance that struck the deal — from the seal and the
    /// clock, which is all there is.
    pub fn is_active(&self, now: i64) -> bool {
        self.terms.as_ref().is_some_and(|t| now < t.deadline)
    }

    /// May `{service, cosigner}` sign? The *timing* question only — what a release pays and how
    /// much is the policy's business, and is checked separately against the transaction.
    pub fn may_release(&self, now: i64) -> Result<(), Refusal> {
        if self.is_active(now) {
            Ok(())
        } else {
            Err(Refusal::DealEnded)
        }
    }

    /// May `{wallet, cosigner}` sign? Only once the deal is no longer running — otherwise an owner
    /// could empty an escrow the service is still entitled to take from.
    pub fn may_reclaim(&self, now: i64) -> Result<(), Refusal> {
        if self.is_active(now) {
            Err(Refusal::StillOpen)
        } else {
            Ok(())
        }
    }

    /// Write down a release this escrow made, under the payment that justified it. Does not end the
    /// deal: an escrow is spent against, not spent once — see [`spent`](Self::spent).
    ///
    /// Only ever called for a release that was not recorded before — a second signature over an
    /// already-answered request adds nothing, because it spends the inputs the first one did.
    pub fn record_release(&mut self, reference: String, record: ReleaseRecord) {
        self.releases.insert(reference, record);
    }

    /// What this escrow has released, in all: read off its releases, never kept beside them.
    pub fn released_sats(&self) -> u64 {
        self.releases.values().fold(0, |total, r| total.saturating_add(r.sats))
    }

    /// Has everything its deal allows been released?
    ///
    /// Derived, never recorded: the cap is the policy's own `released_total_max`. A policy with no
    /// such cap is never spent, and runs to its deadline.
    pub fn spent(&self) -> bool {
        self.terms
            .as_ref()
            .and_then(|t| t.policy.released_total_cap())
            .is_some_and(|cap| self.released_sats() >= cap)
    }

    /// Does its deal still hold the escrow — running, and with something left to release?
    pub fn holds_the_escrow(&self, now: i64) -> bool {
        self.is_active(now) && !self.spent()
    }

    /// The service ends the deal: the deadline comes forward to `now`, and never goes back.
    ///
    /// Only the service may ask, because the deal protects the service — this gives up nothing but
    /// its own claim. What was already released keeps its own deadline in its record, so ending the
    /// deal early does not let the owner race a release the service has yet to submit.
    ///
    /// `policy_sha256` names the deal, so an end meant for another escrow's cannot end this one.
    /// Ending a deal that is already over is not an error: the service asked for something that is
    /// already true.
    pub fn end_by_service(&mut self, policy_sha256: &str, now: i64) -> Result<(), String> {
        let terms = self.terms.as_mut().ok_or("this escrow is not committed to a deal")?;
        if crate::policy::policy_sha256(&terms.policy) != policy_sha256 {
            return Err("that is not the deal this escrow is committed to".into());
        }
        terms.deadline = terms.deadline.min(now);
        Ok(())
    }

    /// The earliest moment the owner may take this escrow back: the later of its deal's deadline
    /// and the deadline of every release it made.
    ///
    /// A deal can end early — spent, or ended by its service — and the service may still hold a
    /// release's signatures it has yet to submit; a reclaim spends the same VTXOs, so the deadline
    /// that release was promised still stands for the owner. Past it, nothing can be released.
    pub fn horizon(&self) -> i64 {
        let deadline = self.terms.as_ref().map_or(0, |t| t.deadline);
        self.releases.values().map(|r| r.deadline).fold(deadline, i64::max)
    }

    /// What its service is told about the deal. See [`SealedTerms`].
    pub fn sealed_terms(&self) -> Option<SealedTerms> {
        self.terms.as_ref().map(|t| SealedTerms {
            opened_at: t.opened_at,
            deadline: t.deadline,
            policy_sha256: crate::policy::policy_sha256(&t.policy),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const NOW: i64 = 1_000_000;
    const HOUR: i64 = 3_600;

    /// An escrow struck on [policy] for an hour. Its key is never read here.
    fn struck(policy: Policy) -> EscrowSession {
        EscrowSession {
            escrow_key: String::new(),
            key_package_json: String::new(),
            public_key_package_json: String::new(),
            wallet_identifier_hex: String::new(),
            context_hex: String::new(),
            wallet_delta_share_hex: String::new(),
            created_at: NOW,
            pairing: None,
            terms: Some(DealTerms::validate(policy, NOW, NOW + HOUR).unwrap()),
            releases: BTreeMap::new(),
        }
    }

    fn session() -> EscrowSession {
        struck(Policy::Always)
    }

    /// A release of [sats], recorded under its own reference.
    fn release(s: &mut EscrowSession, sats: u64) {
        let reference = format!("tx-{}", s.releases.len());
        s.record_release(
            reference,
            ReleaseRecord {
                request_id: "r".into(),
                sats,
                at: NOW,
                proposal_hash: "p".into(),
                deadline: NOW + HOUR,
            },
        );
    }

    fn deadline(s: &EscrowSession) -> i64 {
        s.terms.as_ref().unwrap().deadline
    }

    /// Its service ends [s]'s deal at [now], naming it as a service does.
    fn end(s: &mut EscrowSession, now: i64) {
        let deal = crate::policy::policy_sha256(&s.terms.as_ref().unwrap().policy);
        s.end_by_service(&deal, now).expect("its own deal");
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
        // The whole of a deal's terms. If something else that ends a deal early is ever added, this
        // stops compiling — which is the point of writing it down.
        let DealTerms {
            policy: _,
            opened_at: _,
            deadline,
        } = s.terms.clone().unwrap();
        assert_eq!(deadline, NOW + HOUR);
        assert!(s.may_release(NOW + HOUR - 1).is_ok(), "the owner cannot cut this short");
    }

    #[test]
    fn the_service_ending_a_deal_brings_the_deadline_forward_and_never_back() {
        let mut s = session();
        end(&mut s, NOW + 60);
        assert_eq!(deadline(&s), NOW + 60);
        assert_eq!(s.may_release(NOW + 60), Err(Refusal::DealEnded));
        assert!(s.may_reclaim(NOW + 60).is_ok());

        // Ending it again later is not a way to extend it.
        end(&mut s, NOW + HOUR * 2);
        assert_eq!(deadline(&s), NOW + 60);
    }

    /// An escrow whose session ended before its deal was struck has none, and never will:
    /// nothing is released from it, and it is its owner's to take back.
    #[test]
    fn an_escrow_with_no_deal_releases_nothing_and_is_its_owners() {
        let s = EscrowSession { terms: None, ..session() };
        assert_eq!(s.may_release(NOW), Err(Refusal::DealEnded));
        assert!(s.may_reclaim(NOW).is_ok());
        assert_eq!(s.horizon(), 0);
    }

    /// The horizon is the later of the deal's deadline and every release's: ending a deal early
    /// does not let the owner race a release its service has yet to submit.
    #[test]
    fn the_horizon_waits_for_every_release_made() {
        let mut s = session();
        release(&mut s, 1_000);
        end(&mut s, NOW + 60);
        assert_eq!(deadline(&s), NOW + 60);
        assert_eq!(s.horizon(), NOW + HOUR, "the release was promised until the old deadline");
    }

    fn capped(sats: u64) -> EscrowSession {
        let policy = Policy::AllOf {
            of: vec![Policy::TotalOutMax { sats }, Policy::ReleasedTotalMax { sats }],
        };
        struck(policy)
    }

    /// A payout of one agreed price releases it all at once, and then the deal has nothing left to
    /// give, while its deadline still stands.
    #[test]
    fn a_deal_whose_allowance_is_released_no_longer_holds_the_escrow() {
        let mut s = capped(23_010);
        assert!(s.holds_the_escrow(NOW));
        release(&mut s, 23_000);
        assert!(!s.spent(), "ten sats short of the cap is not spent");
        assert!(s.holds_the_escrow(NOW));
        release(&mut s, 10);
        assert!(s.spent());
        assert!(!s.holds_the_escrow(NOW), "spent");
        assert!(s.is_active(NOW), "and its deadline is untouched");
    }

    /// A cap is only a cap on the deal where it binds unconditionally. One branch of an `any_of`
    /// may be satisfied without it, so it cannot say the deal is spent.
    #[test]
    fn only_an_unconditional_cap_can_spend_a_deal() {
        let mut uncapped = session();
        release(&mut uncapped, u64::MAX);
        assert!(!uncapped.spent(), "a deal with no cap runs to its deadline");

        let either = Policy::AnyOf {
            of: vec![Policy::ReleasedTotalMax { sats: 1 }, Policy::Always],
        };
        let mut s = struck(either);
        release(&mut s, 1_000);
        assert!(!s.spent());

        // Nested all_of chains count, and the smallest cap wins.
        let nested = Policy::AllOf {
            of: vec![
                Policy::ReleasedTotalMax { sats: 500 },
                Policy::AllOf { of: vec![Policy::ReleasedTotalMax { sats: 100 }] },
            ],
        };
        let mut s = struck(nested);
        release(&mut s, 100);
        assert!(s.spent());
    }

    #[test]
    fn the_terms_name_the_sealed_policy_and_its_deadline() {
        let s = capped(1_000);
        let terms = s.sealed_terms().unwrap();
        assert_eq!(terms.opened_at, NOW);
        assert_eq!(terms.deadline, NOW + HOUR);
        assert_eq!(
            terms.policy_sha256,
            crate::policy::policy_sha256(&s.terms.as_ref().unwrap().policy)
        );
        assert_ne!(
            terms.policy_sha256,
            capped(1_001).sealed_terms().unwrap().policy_sha256,
            "a different policy is a different deal"
        );
    }

    /// One escrow, many releases: a card is tapped more than once. Which payments have been spent
    /// is checked across every escrow of the wallet, in `release_test.rs`.
    #[test]
    fn releases_accumulate_and_do_not_end_the_deal() {
        let mut s = session();
        release(&mut s, 1_000);
        release(&mut s, 2_500);
        assert_eq!(s.released_sats(), 3_500);
        assert!(s.may_release(NOW + 60).is_ok(), "an escrow is spent against, not spent once");
    }

    #[test]
    fn a_release_total_cannot_be_made_to_wrap() {
        let mut s = session();
        release(&mut s, u64::MAX);
        release(&mut s, u64::MAX);
        assert_eq!(s.released_sats(), u64::MAX, "saturating, so a total never wraps to nothing");
    }

    #[test]
    fn a_deal_that_is_already_over_is_refused() {
        assert!(DealTerms::validate(Policy::Always, NOW, NOW).is_err());
        assert!(DealTerms::validate(Policy::Always, NOW, NOW - 1).is_err());
    }

    #[test]
    fn a_policy_that_is_not_one_is_refused_at_the_door() {
        let empty = Policy::AllOf { of: vec![] };
        assert!(DealTerms::validate(empty, NOW, NOW + HOUR).is_err());
    }

    /// The seal is the only thing that carries a deal across a restart, so what it omits must come
    /// back as the safe answer rather than the convenient one.
    #[test]
    fn terms_missing_their_policy_release_nothing() {
        let json = format!(r#"{{"opened_at":{NOW},"deadline":{}}}"#, NOW + HOUR);
        let restored: DealTerms = serde_json::from_str(&json).expect("terms with no policy");
        assert_eq!(restored.policy, Policy::Never);
    }

    #[test]
    fn an_escrow_survives_a_seal_round_trip() {
        let mut s = session();
        release(&mut s, 42);
        let round_tripped: EscrowSession =
            serde_json::from_str(&serde_json::to_string(&s).unwrap()).unwrap();
        assert_eq!(round_tripped, s);
        assert_eq!(round_tripped.released_sats(), 42);
    }
}
