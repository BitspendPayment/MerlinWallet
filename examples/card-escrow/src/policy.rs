//! The deal, written down: what the service may take out of the escrow, and on what showing.
//!
//! This is the whole of what the owner agrees to. It is sealed inside the cosigner when the escrow
//! is committed, and from then on the service can supply exactly one thing that reaches a
//! provider — the payment reference — and nothing else. Not the provider, not the credential, not
//! the predicates, not the rate, not the destination, not the cap.
//!
//! # The example's terms
//!
//! | | |
//! |---|---|
//! | escrow funding | 100,000 sats |
//! | total release allowance | 80,000 sats |
//! | card purchase | USD 20.00 |
//! | conversion | 1,000 sats per USD |
//! | reimbursement | 20,000 sats |
//! | service fee | 0 |
//! | allowed destination | the service's Ark address |
//! | deadline | configurable |
//!
//! **The rate is a demonstration setting, not a market quote.** A fixed rate means the escrow bears
//! the whole price move between committing and clearing. That is a decision, and a real programme
//! would have to make it deliberately — by denominating in sats, by re-quoting per authorization,
//! or by reading a rate from a second attested source. Fixing it here keeps the example about the
//! escrow rather than about pricing.
//!
//! # Why each term is in the tree
//!
//! ```text
//!   all_of
//!     outputs_only_to   [service's script]   nowhere else, whatever the proposal says
//!     total_out_max     20,000               one reimbursement cannot exceed one purchase
//!     released_total_max 80,000              and all of them together cannot exceed the allowance
//!     fee_max           0                    the escrow loses nothing between input and output
//!     http_get          the provider          ... and the payment actually happened
//! ```
//!
//! Every one of them is checked against a transaction the **cosigner built**, not one the service
//! supplied — see `cosigner/src/handlers/release.rs`.

use cosigner::evidence::{HttpGet, OnUnavailable, Predicate};
use cosigner::policy::Policy;

/// Minor units in a dollar.
pub const CENTS_PER_USD: u32 = 100;

/// What the example commits to. Test-only values; see the module note.
#[derive(Debug, Clone)]
pub struct Terms {
    /// What Alice puts into the escrow.
    pub funding_sats: u64,
    /// The most that may ever come out of it, across every reimbursement.
    pub allowance_sats: u64,
    /// The agreed conversion. A demonstration setting.
    pub sats_per_usd: u64,
    /// What the service adds for itself. Zero here, and the policy has no term that would let it
    /// be anything else — a fee would have to be a term the owner agreed to.
    pub service_fee_sats: u64,
    /// The card whose purchases this escrow stands behind.
    pub card_token: String,
    pub currency_code: String,
    /// Where a reimbursement may go: the service's Ark address.
    pub service_ark_address: String,
    /// The provider the cosigner asks, and the credential it authenticates with. The credential is
    /// a NAME — the secret is image environment, and bound to this origin.
    pub provider_origin: String,
    pub credential_key: String,
    /// Where a single transaction lives at that provider, with `{reference}` for the payment.
    ///
    /// Provider-specific, and therefore here rather than hardcoded in the policy builder: changing
    /// the origin without changing the path would point a real provider's credential at a path only
    /// the mock serves, and the fetch would 404 for a payment that exists.
    pub provider_path: String,
    /// How long the deal lasts, in seconds from now.
    pub deadline_secs: i64,
}

impl Terms {
    /// The example's numbers, for a service paid at `service_ark_address`.
    pub fn example(service_ark_address: String, provider_origin: String) -> Self {
        Self {
            funding_sats: 100_000,
            allowance_sats: 80_000,
            sats_per_usd: 1_000,
            service_fee_sats: 0,
            card_token: "card_alice_0001".into(),
            currency_code: "USD".into(),
            service_ark_address,
            provider_origin,
            credential_key: "MOCKPROVIDER".into(),
            provider_path: "/transactions/{reference}".into(),
            deadline_secs: 3_600,
        }
    }

    /// What a purchase of `cents` is worth, at the agreed rate.
    ///
    /// Integers throughout, and `None` rather than a rounded answer: a conversion that does not
    /// come out whole is not one this example will guess at. The cosigner applies the same rule to
    /// the evidence it fetches — see `Predicate::AmountAtFixedRate`.
    pub fn sats_for(&self, cents: u64) -> Option<u64> {
        let total = u128::from(cents).checked_mul(u128::from(self.sats_per_usd))?;
        let per_unit = u128::from(CENTS_PER_USD);
        if total % per_unit != 0 {
            return None;
        }
        u64::try_from(total / per_unit).ok()
    }
}

/// The sealed policy for these terms.
///
/// `service_script_pubkey_hex` is the service's Ark address reduced to the script an output pays,
/// because that is what a transaction actually contains — an address is a way of writing one down.
pub fn policy(terms: &Terms, service_script_pubkey_hex: &str, one_purchase_sats: u64) -> Policy {
    Policy::AllOf {
        of: vec![
            // Nowhere but the service, whatever the proposal asks for. Change back to the escrow is
            // not egress and is not caught by this.
            Policy::OutputsOnlyTo {
                scripts: vec![service_script_pubkey_hex.to_ascii_lowercase()],
            },
            // One reimbursement is worth one purchase and no more.
            Policy::TotalOutMax {
                sats: one_purchase_sats,
            },
            // And everything together stays inside what was committed.
            Policy::ReleasedTotalMax {
                sats: terms.allowance_sats,
            },
            // The escrow loses nothing between its inputs and its outputs. On Ark this is always
            // satisfied — value is conserved — and it is here so that stops being true loudly.
            Policy::FeeMax { sats: 0 },
            // And the payment actually happened, on the right card, in the right currency, for the
            // right amount, and cleared rather than merely authorized.
            Policy::HttpGet(Box::new(evidence(terms))),
        ],
    }
}

/// What the cosigner must fetch for itself, and what it must find.
///
/// The six things the deal turns on. Each is its own predicate rather than one compound check, so
/// a refusal says which of them failed — "state is PENDING, not COMPLETION" is actionable, and
/// "evidence did not satisfy the policy" is not.
pub fn evidence(terms: &Terms) -> HttpGet {
    HttpGet {
        // From the sealed policy. The service names a payment; it does not name a provider.
        provider: terms.provider_origin.clone(),
        // `{reference}` is the one thing the service fills in, and it reaches the URL only through
        // `safe_reference`, which confines it to a single path segment.
        path: terms.provider_path.clone(),
        // A NAME, not a secret. The value is image environment, bound to `provider` — pointing this
        // at another allowed origin does not send the credential there, it refuses.
        credentials: terms.credential_key.clone(),
        expect: vec![
            // 1. payment identity — that this evidence is about this release and not another.
            Predicate::MatchesReference { at: "token".into() },
            // 2. purchase type — a clearing. An authorization may still expire or be reversed, and
            //    reimbursing one is reimbursing something that may never happen.
            Predicate::Equals {
                at: "type".into(),
                value: crate::provider::kind::CLEARING.into(),
            },
            // 3. clearing state — that it completed.
            Predicate::Equals {
                at: "state".into(),
                value: crate::provider::state::COMPLETION.into(),
            },
            // 4. card / account — that it was this escrow's card, not somebody else's.
            Predicate::Equals {
                at: "card_token".into(),
                value: terms.card_token.clone(),
            },
            // 5. currency — without which "20" is a number rather than an amount.
            Predicate::Equals {
                at: "currency_code".into(),
                value: terms.currency_code.clone(),
            },
            // 6. amount — converted at the sealed rate, exactly what is being released. This is
            //    what stops a verified $5 coffee releasing $500.
            Predicate::AmountAtFixedRate {
                at: "amount".into(),
                minor_units_per_unit: CENTS_PER_USD,
                sats_per_unit: terms.sats_per_usd,
            },
        ],
        // A provider that cannot be reached has not said yes. `Pending` rather than `Deny` so the
        // refusal reads as "ask again" — a clearing that has not reached the read API yet is the
        // normal case, not a failure. Either way nothing is signed.
        on_unavailable: OnUnavailable::Pending,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn terms() -> Terms {
        Terms::example("ark1example".into(), "https://provider.example".into())
    }

    /// The example's own arithmetic: $20.00 is 20,000 sats, exactly.
    #[test]
    fn a_twenty_dollar_purchase_is_twenty_thousand_sats() {
        assert_eq!(terms().sats_for(2_000), Some(20_000));
        assert_eq!(terms().sats_for(0), Some(0));
        assert_eq!(terms().sats_for(1), Some(10), "a cent is ten sats at this rate");
    }

    /// And a rate that does not divide is refused rather than rounded.
    #[test]
    fn an_inexact_conversion_has_no_answer() {
        let odd = Terms {
            sats_per_usd: 3,
            ..terms()
        };
        assert_eq!(odd.sats_for(1), None, "a cent is 3/100 of a sat, which is not a number of sats");
        assert_eq!(odd.sats_for(100), Some(3));
    }

    /// The policy has to be one the cosigner will accept at all.
    #[test]
    fn the_example_policy_validates() {
        let p = policy(&terms(), &"51".repeat(17), 20_000);
        p.validate().expect("a sealed policy must be a well-formed one");
    }

    /// And it has to be one a person can read before agreeing to it.
    #[test]
    fn the_example_policy_describes_itself() {
        let described = policy(&terms(), &"51".repeat(17), 20_000).describe();
        assert!(described.contains("1 approved destination"), "{described}");
        assert!(described.contains("20000 sats in one transaction"), "{described}");
        assert!(described.contains("80000 sats in total"), "{described}");
        assert!(described.contains("must not lose any"), "{described}");
        assert!(described.contains("provider.example"), "{described}");
    }

    /// Every one of the six is asked. A policy that checked five would be a policy that let the
    /// sixth through, and which five is not something to find out later.
    #[test]
    fn all_six_things_are_required() {
        let asked = evidence(&terms());
        let at: Vec<&str> = asked
            .expect
            .iter()
            .map(|p| match p {
                Predicate::MatchesReference { at }
                | Predicate::Equals { at, .. }
                | Predicate::AmountAtFixedRate { at, .. } => at.as_str(),
                other => panic!("unexpected predicate {other:?}"),
            })
            .collect();
        assert_eq!(
            at,
            vec!["token", "type", "state", "card_token", "currency_code", "amount"]
        );
    }

    /// The credential is a name. A policy that carried a secret could leak one by being read.
    #[test]
    fn the_policy_holds_no_secret() {
        let json = serde_json::to_string(&policy(&terms(), &"51".repeat(17), 20_000)).unwrap();
        assert!(json.contains("MOCKPROVIDER"), "the NAME is in it");
        assert!(!json.to_lowercase().contains("secret"));
        assert!(!json.to_lowercase().contains("password"));
    }
}
