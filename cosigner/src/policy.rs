//! The policy IR: what a signer may authorise.
//!
//! Every signer is bound by a [`Policy`]; the wallet's defaults to [`Policy::Always`] so the
//! enforcement path stays on the main flow rather than being skipped. The vocabulary is closed so
//! a policy can be rendered for consent ([`Policy::describe`]).
//!
//! Fail-closed: an absent policy is [`Policy::Never`], an unparseable transaction denies, and an
//! unrecognised [`Policy::External`] evaluator denies.

use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};

/// Bounded at every entry point and re-checked while evaluating: a deeply nested tree would
/// otherwise exhaust the evaluator's stack.
pub const MAX_POLICY_DEPTH: usize = 16;
/// Guards a wide-but-shallow tree.
pub const MAX_POLICY_NODES: usize = 256;

/// A predicate over a proposed spend.
///
/// No `Not`: negation would let a policy widen by accident (`Not(Never)` is `Always`), and nothing
/// here needs it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "op", rename_all = "snake_case")]
pub enum Policy {
    /// Permit anything. The wallet's default — the user is the authority over their own key.
    Always,
    /// Permit nothing. What anything unconfigured decays to.
    Never,
    /// Every branch must permit.
    AllOf { of: Vec<Policy> },
    /// At least one branch must permit.
    AnyOf { of: Vec<Policy> },
    /// Every *egress* output must pay one of these scriptPubKeys (lowercase hex). Change back to
    /// our own scripts is not egress and is not checked here.
    OutputsOnlyTo { scripts: Vec<String> },
    /// Cap on total egress value in one transaction.
    TotalOutMax { sats: u64 },
    /// Cap on the largest single egress output.
    SingleOutMax { sats: u64 },
    /// Cap on what a transaction may lose between its inputs and its outputs.
    ///
    /// **On Ark this is always zero today.** An off-chain send conserves value exactly — the anchor
    /// output is what pays, and even change too small to be an output is not dropped. The term is
    /// here because "this escrow loses nothing" is a thing a policy should be able to say, and
    /// because value quietly going missing is precisely the failure a release must not sign
    /// through. `sats: 0` is therefore the normal setting, and it permits every honest release.
    ///
    /// The only term that needs to know what the inputs were worth, and the reason it is safe to
    /// take that from the party proposing the spend: a taproot sighash commits to every prevout
    /// amount, so a false one produces a signature that verifies against nothing. A service that
    /// understates its inputs to make a fee look small gets a signature the network will not
    /// accept. What is checked here is therefore the true figure, or the signature is worthless —
    /// see [`crate::handlers::release`].
    FeeMax { sats: u64 },
    /// Cap on what one escrow may release IN TOTAL, across every release it has made.
    ///
    /// [`TotalOutMax`](Policy::TotalOutMax) bounds one transaction; a card escrow is spent against
    /// over days, so the thing an owner actually commits is a running total. Checked against what
    /// the session has already recorded — see
    /// [`EscrowSession::released_sats`](crate::escrow_session::EscrowSession::released_sats).
    ReleasedTotalMax { sats: u64 },
    /// Escape hatch for a named external evaluator. RESERVED: none is registered and an
    /// unrecognised one denies, so this grants nothing today — it exists so adding one later costs
    /// a registration rather than a redesign.
    External { evaluator: String, config: Vec<u8> },
    /// Evidence the cosigner fetches for itself from a provider this policy names.
    ///
    /// The one predicate that is not a function of the transaction. A service may say *which*
    /// payment it is claiming; it may not say that the payment happened, and neither its JSON nor
    /// a 200 establishes anything. See [`crate::evidence`].
    HttpGet(Box<crate::evidence::HttpGet>),
}

impl Default for Policy {
    /// Fail closed.
    fn default() -> Self {
        Policy::Never
    }
}

/// One output, reduced to what a predicate can actually see.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OutputView {
    /// The scriptPubKey, lowercase hex.
    pub script_pubkey_hex: String,
    pub sats: u64,
}

/// What a predicate sees: OUTPUTS, not a transaction. A caller-supplied transaction is parsed into
/// outputs; a settle the cosigner builds already has them. One evaluator serves both.
///
/// No prevout values, so fees and balance fractions are inexpressible — a property of the call
/// sites, not the IR.
pub struct EvalContext<'a> {
    /// The proposed outputs, or `None` — a settle sighash arrives with nothing to inspect.
    pub outputs: Option<&'a [OutputView]>,
    /// ScriptPubKeys (lowercase hex) belonging to this wallet. Outputs paying these are change,
    /// not egress.
    pub owned_scripts: &'a BTreeSet<String>,
    /// What this release claims: the payment reference and what it would pay. `None` outside a
    /// release, where an [`Policy::HttpGet`] has nothing to bind evidence to and so denies.
    pub release: Option<&'a crate::evidence::ReleaseFacts>,
    /// What was fetched, by [`EvidenceRequest::key`](crate::evidence::EvidenceRequest::key).
    /// Gathered before evaluating — see the note on [`Policy::evidence_needed`].
    pub evidence: &'a BTreeMap<String, crate::evidence::Evidence>,
}

/// Reduce a transaction to the outputs a predicate can see.
pub fn outputs_of(tx: &bitcoin::Transaction) -> Vec<OutputView> {
    tx.output
        .iter()
        .map(|o| OutputView {
            script_pubkey_hex: hex::encode(o.script_pubkey.as_bytes()),
            sats: o.value.to_sat(),
        })
        .collect()
}

/// Reduce transaction outputs the cosigner built itself to what a predicate can see.
pub fn outputs_of_txouts(outputs: &[bitcoin::TxOut]) -> Vec<OutputView> {
    outputs
        .iter()
        .map(|o| OutputView {
            script_pubkey_hex: hex::encode(o.script_pubkey.as_bytes()),
            sats: o.value.to_sat(),
        })
        .collect()
}

/// The egress side of a transaction: outputs that actually leave the wallet.
struct Egress {
    /// `(scriptPubKey hex, sats)` for each non-change output.
    outputs: Vec<(String, u64)>,
    total: u64,
}

impl Egress {
    fn of(ctx: &EvalContext<'_>) -> Result<Self, String> {
        let proposed = ctx
            .outputs
            .ok_or("this policy needs the outputs it is authorising, and none were supplied")?;
        let mut outputs = Vec::new();
        let mut total: u64 = 0;
        for out in proposed {
            if ctx.owned_scripts.contains(&out.script_pubkey_hex) {
                continue; // change back to us is not egress
            }
            total = total.checked_add(out.sats).ok_or("output total overflows")?;
            outputs.push((out.script_pubkey_hex.clone(), out.sats));
        }
        Ok(Egress { outputs, total })
    }
}

impl Policy {
    /// The wallet's default: the user is the authority over their own key.
    pub const fn allow_all() -> Self {
        Policy::Always
    }

    /// Reject a policy that is too deep, too large, or self-evidently a mistake. Run at enrolment
    /// and at seal restore.
    pub fn validate(&self) -> Result<(), String> {
        let mut nodes = 0usize;
        self.validate_at(0, &mut nodes)
    }

    fn validate_at(&self, depth: usize, nodes: &mut usize) -> Result<(), String> {
        if depth > MAX_POLICY_DEPTH {
            return Err(format!("policy nests deeper than {MAX_POLICY_DEPTH} levels"));
        }
        *nodes += 1;
        if *nodes > MAX_POLICY_NODES {
            return Err(format!("policy has more than {MAX_POLICY_NODES} terms"));
        }
        match self {
            Policy::Always | Policy::Never => Ok(()),
            // `AllOf {}` is a vacuous PASS — accidental widening.
            Policy::AllOf { of } | Policy::AnyOf { of } => {
                if of.is_empty() {
                    return Err("an empty all_of/any_of is not a policy".into());
                }
                for child in of {
                    child.validate_at(depth + 1, nodes)?;
                }
                Ok(())
            }
            Policy::OutputsOnlyTo { scripts } => {
                if scripts.is_empty() {
                    return Err(
                        "outputs_only_to with no destinations denies everything; say never instead"
                            .into(),
                    );
                }
                for s in scripts {
                    if s.is_empty()
                        || s.len() % 2 != 0
                        || !s.bytes().all(|b| b.is_ascii_hexdigit() && !b.is_ascii_uppercase())
                    {
                        return Err(format!(
                            "destination {s:?} is not a lowercase-hex scriptPubKey"
                        ));
                    }
                }
                Ok(())
            }
            Policy::TotalOutMax { sats }
            | Policy::SingleOutMax { sats }
            | Policy::ReleasedTotalMax { sats } => {
                if *sats == 0 {
                    return Err("a cap of 0 sats denies everything; say never instead".into());
                }
                Ok(())
            }
            // A fee cap of 0 is not the same mistake: it says "pay no fee", which is a thing a
            // policy can mean even though nothing satisfies it on this chain.
            Policy::FeeMax { .. } => Ok(()),
            Policy::External { evaluator, .. } => {
                if evaluator.is_empty() {
                    return Err("external policy names no evaluator".into());
                }
                Ok(())
            }
            Policy::HttpGet(condition) => condition.validate(),
        }
    }

    /// `Ok(())` permits; `Err(reason)` denies.
    pub fn evaluate(&self, ctx: &EvalContext<'_>) -> Result<(), String> {
        self.evaluate_at(ctx, 0)
    }

    fn evaluate_at(&self, ctx: &EvalContext<'_>, depth: usize) -> Result<(), String> {
        // Not reliant on `validate` having run.
        if depth > MAX_POLICY_DEPTH {
            return Err(format!("policy nests deeper than {MAX_POLICY_DEPTH} levels"));
        }
        match self {
            Policy::Always => Ok(()),
            Policy::Never => Err("this signer's policy permits no spending".into()),
            Policy::AllOf { of } => {
                if of.is_empty() {
                    return Err("an empty all_of is not a policy".into());
                }
                for child in of {
                    child.evaluate_at(ctx, depth + 1)?;
                }
                Ok(())
            }
            Policy::AnyOf { of } => {
                if of.is_empty() {
                    return Err("an empty any_of is not a policy".into());
                }
                let mut reasons = Vec::new();
                for child in of {
                    match child.evaluate_at(ctx, depth + 1) {
                        Ok(()) => return Ok(()),
                        Err(e) => reasons.push(e),
                    }
                }
                Err(format!("no branch permits this: {}", reasons.join("; ")))
            }
            Policy::OutputsOnlyTo { scripts } => {
                if scripts.is_empty() {
                    return Err("no allowed destinations are configured".into());
                }
                let egress = Egress::of(ctx)?;
                let allowed: BTreeSet<&str> = scripts.iter().map(|s| s.as_str()).collect();
                for (i, (spk, _)) in egress.outputs.iter().enumerate() {
                    if !allowed.contains(spk.as_str()) {
                        return Err(format!(
                            "output {i} pays {spk}, which is not an allowed destination"
                        ));
                    }
                }
                Ok(())
            }
            Policy::TotalOutMax { sats } => {
                let egress = Egress::of(ctx)?;
                if egress.total > *sats {
                    return Err(format!(
                        "{} sats leaves the wallet, over the {sats} sat cap",
                        egress.total
                    ));
                }
                Ok(())
            }
            Policy::SingleOutMax { sats } => {
                let egress = Egress::of(ctx)?;
                for (i, (_, amount)) in egress.outputs.iter().enumerate() {
                    if amount > sats {
                        return Err(format!(
                            "output {i} sends {amount} sats, over the {sats} sat per-output cap"
                        ));
                    }
                }
                Ok(())
            }
            Policy::FeeMax { sats } => {
                let release = ctx.release.ok_or(
                    "this policy caps the fee, and this call has no release to read one from",
                )?;
                if release.fee_sats > *sats {
                    return Err(format!(
                        "this transaction pays {} sats in fees, over the {sats} sat cap",
                        release.fee_sats
                    ));
                }
                Ok(())
            }
            Policy::ReleasedTotalMax { sats } => {
                let release = ctx.release.ok_or(
                    "this policy caps what an escrow may release in total, and this call is not a \
                     release",
                )?;
                let total = release
                    .already_released_sats
                    .checked_add(release.sats)
                    .ok_or("the running release total overflows")?;
                if total > *sats {
                    return Err(format!(
                        "{} sats have been released already and this would make {total}, over the \
                         {sats} sat total for this escrow",
                        release.already_released_sats
                    ));
                }
                Ok(())
            }
            Policy::External { evaluator, .. } => Err(format!(
                "policy defers to external evaluator {evaluator:?}, which is not available"
            )),
            Policy::HttpGet(condition) => condition.evaluate(ctx.evidence, ctx.release),
        }
    }

    /// Everything this policy must have fetched before [`Self::evaluate`] can answer.
    ///
    /// Separate from evaluation because evaluation is synchronous and pure, which is what makes it
    /// cheap to test exhaustively, and a GET is neither. So a policy declares what it needs, the
    /// caller fetches it, and the decision stays a function of its inputs.
    ///
    /// Collected from **every** branch, including ones a short-circuit would skip: an `any_of` is
    /// judged on what is available, and which branch will answer is not known until it has been.
    pub fn evidence_needed(
        &self,
        release: &crate::evidence::ReleaseFacts,
    ) -> Vec<crate::evidence::EvidenceRequest> {
        let mut out = Vec::new();
        self.collect_evidence(release, &mut out, 0);
        out.sort();
        out.dedup();
        out
    }

    fn collect_evidence(
        &self,
        release: &crate::evidence::ReleaseFacts,
        out: &mut Vec<crate::evidence::EvidenceRequest>,
        depth: usize,
    ) {
        if depth > MAX_POLICY_DEPTH {
            return;
        }
        match self {
            Policy::AllOf { of } | Policy::AnyOf { of } => {
                for child in of {
                    child.collect_evidence(release, out, depth + 1);
                }
            }
            Policy::HttpGet(condition) => {
                // `None` means the reference could not be put in a URL. Nothing is fetched, and
                // `evaluate` denies for that reason rather than for a missing answer.
                if let Some(request) = condition.request(release) {
                    out.push(request);
                }
            }
            _ => {}
        }
    }

    /// The sentence a user consents to, and how a grant is audited afterwards.
    pub fn describe(&self) -> String {
        match self {
            Policy::Always => "may spend without restriction".into(),
            Policy::Never => "may not spend at all".into(),
            Policy::AllOf { of } => of
                .iter()
                .map(|c| c.describe())
                .collect::<Vec<_>>()
                .join(", and "),
            Policy::AnyOf { of } => of
                .iter()
                .map(|c| c.describe())
                .collect::<Vec<_>>()
                .join(", or "),
            Policy::OutputsOnlyTo { scripts } => match scripts.len() {
                0 => "may not pay anyone".into(),
                1 => "may only pay 1 approved destination".into(),
                n => format!("may only pay {n} approved destinations"),
            },
            Policy::TotalOutMax { sats } => {
                format!("may spend at most {sats} sats in one transaction")
            }
            Policy::SingleOutMax { sats } => {
                format!("may send at most {sats} sats to any one destination")
            }
            Policy::FeeMax { sats: 0 } => "must not lose any of what it spends".into(),
            Policy::FeeMax { sats } => format!("may pay at most {sats} sats in fees"),
            Policy::ReleasedTotalMax { sats } => {
                format!("may release at most {sats} sats in total from this escrow")
            }
            Policy::External { evaluator, .. } => {
                format!("defers to the external evaluator {evaluator:?}, which denies")
            }
            Policy::HttpGet(condition) => condition.describe(),
        }
    }
}

/// Apply a policy to a caller-supplied transaction.
///
/// An undecodable transaction denies; an ABSENT one becomes `outputs: None` and each predicate
/// decides for itself — which is what lets `Always` hold for a settle sighash while
/// `OutputsOnlyTo` still refuses to guess.
pub fn enforce(
    policy: &Policy,
    full_transaction: &[u8],
    owned_scripts: &BTreeSet<String>,
) -> Result<(), String> {
    let outputs = if full_transaction.is_empty() {
        None
    } else {
        Some(outputs_of(
            &bitcoin::consensus::encode::deserialize::<bitcoin::Transaction>(full_transaction)
                .map_err(|e| format!("undecodable transaction: {e}"))?,
        ))
    };
    enforce_outputs(policy, outputs.as_deref(), owned_scripts)
}

/// Apply a policy to outputs the cosigner built itself — the settle and send paths, which have
/// outputs rather than a transaction to show.
pub fn enforce_outputs(
    policy: &Policy,
    outputs: Option<&[OutputView]>,
    owned_scripts: &BTreeSet<String>,
) -> Result<(), String> {
    // No release and no evidence: the paths that call this are the wallet's own, where there is no
    // payment being claimed. A policy carrying an `http_get` therefore denies here — correctly,
    // because it is asking about something this call has no knowledge of.
    policy.evaluate(&EvalContext {
        outputs,
        owned_scripts,
        release: None,
        evidence: &BTreeMap::new(),
    })
}

/// Apply a policy to a release: the transaction it proposes, and the evidence already fetched for
/// it.
///
/// The release path, and the only one where an [`Policy::HttpGet`] can be satisfied — it is the
/// only one with a payment to bind evidence to.
pub fn enforce_release(
    policy: &Policy,
    outputs: Option<&[OutputView]>,
    owned_scripts: &BTreeSet<String>,
    release: &crate::evidence::ReleaseFacts,
    evidence: &BTreeMap<String, crate::evidence::Evidence>,
) -> Result<(), String> {
    policy.evaluate(&EvalContext {
        outputs,
        owned_scripts,
        release: Some(release),
        evidence,
    })
}
