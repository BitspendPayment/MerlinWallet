//! The card programme's settlement service: what it holds, what it claims, and what it waits for.
//!
//! # What this service is
//!
//! It is the party that already paid the merchant. A card programme settles a purchase in fiat when
//! it clears, and then has to be made whole. Here, being made whole means being reimbursed out of
//! the cardholder's Bitcoin escrow — so this service holds **half of the escrow key**, and the
//! cosigner inside the enclave holds the other half.
//!
//! It cannot pay itself. `{service, cosigner}` is a 2-of-2, so every sat it takes needs the
//! cosigner to agree, and the cosigner agrees only on evidence it fetched itself.
//!
//! # The lifecycle it tracks
//!
//! ```text
//!   Paired ──▶ EscrowActive ──▶ CardAuthorized ──▶ CardCleared
//!                                     │                 │
//!                                     │                 ▼
//!                                     │          EvidenceVerified ──▶ ReleaseSigned ──▶ ReleaseConfirmed
//!                                     │
//!                                     └── reversed or expired: nothing is owed, nothing is asked
//! ```
//!
//! Two of those states are not this service's to declare. **EvidenceVerified** is the cosigner's —
//! this service never inspects the evidence and its opinion of it would be worth nothing. And
//! **ReleaseConfirmed** is the chain's: a signature is not a payment, and tracking submission apart
//! from signing is what stops a service believing it has been paid because the maths worked.
//!
//! # Asking only after clearing
//!
//! An authorization is a hold. It can expire, be reversed, or clear for a different amount, and a
//! programme that reimbursed itself on one would be reimbursing itself for something that may never
//! happen. So this service waits for the clearing record — a **separate** record, linked to the
//! authorization — and asks against that.
//!
//! The cosigner does not take its word for any of it. It fetches the same record, with its own
//! read-only credential, and checks six things about it.
//!
//! # What survives a restart, and what must not
//!
//! Its share of the escrow key, its pairings, and every release it has asked for — those are in the
//! store, because an instance that lost them could neither be paid nor tell a repeat from a new
//! request.
//!
//! **Its signing nonces are not.** They live for one exchange and are dropped. A pending request
//! found after a restart is retried with fresh ones, which the cosigner answers as a repeat: signed
//! again, counted once. Persisting a single-use nonce to survive a restart would be trading the
//! share for the convenience.

use std::collections::BTreeMap;
use std::path::PathBuf;
use std::sync::Arc;

use serde::{Deserialize, Serialize};
use tokio::sync::Mutex;

pub mod reimburse;
pub mod signing;
pub mod wire;

pub use signing::PairedShare;

/// Where a purchase has got to, from this service's point of view.
///
/// Ordered, and the order is the claim: a state cannot be reached without the one before it. What
/// each means is in the module note; the two that are not this service's to declare are marked.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum Stage {
    /// Both halves of the escrow share arrived and summed to the published verifying share.
    Paired,
    /// The owner committed the escrow to a deal, so there is an allowance to draw on.
    EscrowActive,
    /// A card was presented. A hold, not a payment.
    CardAuthorized,
    /// The purchase settled. This is what money is owed on.
    CardCleared,
    /// The COSIGNER fetched the evidence and it satisfied the sealed policy. Not this service's
    /// judgement, and not reached by this service believing anything.
    EvidenceVerified,
    /// The cosigner returned its half and the two combined into a valid signature.
    ReleaseSigned,
    /// The ASP accepted the transaction. Only now has anything actually moved.
    ReleaseConfirmed,
}

impl Stage {
    pub fn label(self) -> &'static str {
        match self {
            Stage::Paired => "Paired",
            Stage::EscrowActive => "Escrow active",
            Stage::CardAuthorized => "Card authorized",
            Stage::CardCleared => "Card cleared",
            Stage::EvidenceVerified => "Evidence verified",
            Stage::ReleaseSigned => "Release signed",
            Stage::ReleaseConfirmed => "Release confirmed",
        }
    }
}

/// One purchase this service is tracking, and the reimbursement it is owed for it.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Reimbursement {
    /// This service's idempotency key for the ask. Stable across every retry of the same request —
    /// that is what lets the cosigner answer a repeat without counting it twice.
    pub request_id: String,
    pub escrow_key: String,
    /// The authorization: the hold taken when the card was presented.
    pub authorization_token: String,
    /// The clearing that settled it. `None` until it exists — and until it does, nothing is asked.
    pub clearing_token: Option<String>,
    /// What cleared, in minor units of `currency`.
    pub amount_minor: u64,
    pub currency: String,
    /// What that is worth at the sealed rate. Computed once, by the same integer arithmetic the
    /// cosigner checks the evidence with.
    pub sats: u64,
    pub stage: Stage,
    /// Why the last ask was refused, if it was. Kept so a walkthrough can show the reason rather
    /// than only that nothing happened.
    #[serde(default)]
    pub last_refusal: Option<String>,
    /// What was proposed the first time this was asked, and must be proposed again.
    ///
    /// **A retry has to be the same release, not a fresh one.** The request id is what makes a
    /// repeat safe — the cosigner answers it by signing again and counting nothing — but only if
    /// the proposal under it is unchanged. Rebuilding from whatever the escrow holds *now* would
    /// produce a different one: a release that spent a 100,000-sat VTXO leaves 80,000 of change
    /// behind, so the next attempt would propose spending the change, and the cosigner would refuse
    /// it as a different release wearing an answered request's name. For ever.
    #[serde(default)]
    pub proposal: Option<PersistedProposal>,
    /// The finished signatures for [`proposal`](Self::proposal), written down before submission.
    ///
    /// Hex, 64 bytes each, in sighash order. **Public data**: these are the BIP-340 signatures that
    /// go on the chain, and keeping them is nothing like keeping a nonce — a nonce is single-use
    /// secret material whose reuse gives up the share, and none is ever written down.
    ///
    /// Why they have to be here: a release that was approved and signed, and whose process then
    /// died before it submitted, cannot get a second approval once the deadline has passed. The
    /// cosigner is right to refuse — the deal is over. But the payment was already agreed, and the
    /// service has already paid the merchant. With these, the transaction can be rebuilt from the
    /// proposal and submitted without asking anybody for anything.
    #[serde(default)]
    pub signatures: Vec<String>,
    /// The transaction this was signed for, written down BEFORE it was submitted.
    ///
    /// A taproot witness does not change a txid, so this is known as soon as the transaction is
    /// built. It is what lets a retry ask the chain whether the first attempt landed, instead of
    /// guessing.
    #[serde(default)]
    pub expected_txid: Option<String>,
    /// The first attempt probably landed and its reply was lost, and this service can no longer
    /// tell from here.
    ///
    /// Set when a retry finds the escrow's funds already gone while this reimbursement is only
    /// recorded as signed. Retrying for ever would be wrong and assuming it succeeded would be
    /// worse, so it stops asking and says so. Reconciling against the chain is a person's job, or
    /// a job for something that knows more than this example does.
    #[serde(default)]
    pub needs_reconciliation: bool,
    /// The Ark transaction that paid it, once one has.
    #[serde(default)]
    pub ark_txid: Option<String>,
}

impl Reimbursement {
    /// What this service asks the cosigner about — the clearing, never the authorization.
    pub fn reference(&self) -> Option<&str> {
        self.clearing_token.as_deref()
    }

    /// Whether this has picked out VTXOs that may yet be spent.
    ///
    /// True from the moment a proposal exists until the release is confirmed or given up on. While
    /// it is true, nothing else may spend from the same escrow: those inputs are still live, and a
    /// second purchase selecting them would get its own signatures for money only one of the two
    /// can actually move.
    pub fn holds_a_spend(&self) -> bool {
        self.proposal.is_some()
            && !self.needs_reconciliation
            && self.stage < Stage::ReleaseConfirmed
    }

    /// Whether it is worth asking: cleared, not already paid, and not waiting on a person.
    pub fn ready_to_ask(&self) -> bool {
        self.clearing_token.is_some()
            && !self.needs_reconciliation
            && matches!(
                self.stage,
                Stage::CardCleared | Stage::EvidenceVerified | Stage::ReleaseSigned
            )
    }
}

/// Everything the service must not lose.
#[derive(Debug, Default, Clone, Serialize, Deserialize)]
pub struct Store {
    /// The escrow shares it holds, by escrow key.
    ///
    /// **Secret.** Each is half of a 2-of-2 — useless alone, and not something to print. The file
    /// this lands in is the service's key material, exactly as the cosigner's seal is its own.
    #[serde(default)]
    pub shares: BTreeMap<String, PairedShare>,
    /// Purchases being tracked, by request id.
    #[serde(default)]
    pub reimbursements: BTreeMap<String, Reimbursement>,
    /// What the service has issued so far, so request ids are its own and monotonic.
    #[serde(default)]
    pub issued: u32,
}

/// The service, and the one lock over its state.
///
/// A single lock rather than one per map: everything here is decided together — a release changes a
/// stage and reads a share — and two locks would be two orders to take them in.
pub struct Service {
    pub store: Mutex<Store>,
    /// Held for the whole of a save: serialize, write, rename.
    ///
    /// Not the same lock as the store's. The store's is taken and let go all over the place, and
    /// holding it across file I/O would make every reader wait on a disk. This one only ever
    /// serializes savers against each other — which they need, because they share a temporary file
    /// and a destination: two at once and one overwrites the other's bytes before the rename, or
    /// renames a file the other already moved.
    saving: Mutex<()>,
    /// Escrows something is spending from right now.
    ///
    /// Keyed by escrow, because that is the resource. Two purchases on one escrow asked for at
    /// once would each read the same VTXOs and each be signed for them — spending the allowance
    /// twice for money only one of them can move. Keying by reimbursement would also miss the
    /// simpler collision it was first written for: two asks under one request id each registering
    /// to be told the answer, so the first waits for a message the second took.
    in_flight: Mutex<std::collections::BTreeSet<String>>,
    path: Option<PathBuf>,
    /// This service's FROST identifier, as the enclave's image names it.
    pub identifier: threshold::identifier::Identifier,
    /// Where this service is paid: its own Ark address.
    pub payout_ark_address: String,
    /// The ASP, for reading what an escrow holds and for submitting what was approved.
    pub asp_url: String,
    /// Where the payment provider is, from this service's side. The COSIGNER's copy of this comes
    /// from its own image and is not this value — see `crate::policy`.
    pub provider_origin: String,
    /// What the agreed conversion is, so a reimbursement is sized the same way the cosigner checks
    /// it. Never the authority: the cosigner recomputes from the evidence it fetched.
    pub terms: crate::policy::Terms,
}

impl Service {
    pub fn new(
        identifier: threshold::identifier::Identifier,
        payout_ark_address: String,
        asp_url: String,
        provider_origin: String,
        terms: crate::policy::Terms,
        path: Option<PathBuf>,
    ) -> Arc<Self> {
        Arc::new(Self {
            store: Mutex::new(Store::default()),
            saving: Mutex::new(()),
            in_flight: Mutex::new(std::collections::BTreeSet::new()),
            path,
            identifier,
            payout_ark_address,
            asp_url,
            provider_origin,
            terms,
        })
    }

    /// Read back what a previous run left, if anything.
    pub async fn restore(self: &Arc<Self>) -> anyhow::Result<()> {
        let Some(path) = self.path.as_ref() else {
            return Ok(());
        };
        if !path.exists() {
            return Ok(());
        }
        let bytes = tokio::fs::read(path).await?;
        let restored: Store = serde_json::from_slice(&bytes)?;
        *self.store.lock().await = restored;
        Ok(())
    }

    /// Write it down.
    ///
    /// Whole-file, and that is deliberate for an example: the store is small, and a rewrite that
    /// either lands or does not is easier to reason about than a journal. A real service would want
    /// a database and this is not one.
    ///
    /// One saver at a time, all the way through the rename — see [`Self::saving`]. Several callers
    /// reach this at once (an operator's request, the retry loop, a pairing completing), and they
    /// share a temporary file and a destination.
    pub async fn persist(self: &Arc<Self>) -> anyhow::Result<()> {
        let Some(path) = self.path.as_ref() else {
            return Ok(());
        };
        // Taken BEFORE the snapshot is read, and held past the rename. Serializing only the write
        // would not be enough: two savers could each serialize, then write in the order they
        // serialized and rename in the other order, and the file would end up holding the older
        // of the two.
        let _saving = self.saving.lock().await;
        let bytes = {
            let store = self.store.lock().await;
            serde_json::to_vec_pretty(&*store)?
        };
        let temp = path.with_extension("tmp");
        tokio::fs::write(&temp, &bytes).await?;
        // The secret half of a 2-of-2 lives in here.
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            tokio::fs::set_permissions(&temp, std::fs::Permissions::from_mode(0o600)).await?;
        }
        tokio::fs::rename(&temp, path).await?;
        Ok(())
    }

    /// The next request id. This service's own, and monotonic, so a retry can be told from a
    /// new ask by the cosigner as well as by this service.
    pub async fn next_request_id(self: &Arc<Self>) -> String {
        let mut store = self.store.lock().await;
        store.issued += 1;
        format!("reimb-{:04}", store.issued)
    }

    /// Claim the right to spend from one escrow, or find somebody already has.
    ///
    /// **Per escrow, not per reimbursement.** An escrow's funds are one resource: two purchases
    /// asked for at once would each read the same VTXOs, each propose spending them, and each be
    /// signed — consuming the allowance twice for money only one of them can actually move, and
    /// leaving the loser tied to inputs that no longer exist.
    ///
    /// The guard releases on drop, so a panic or an early return cannot leave a reimbursement
    /// looking permanently in flight.
    pub async fn claim(self: &Arc<Self>, escrow_key: &str) -> Option<InFlight> {
        let mut held = self.in_flight.lock().await;
        if !held.insert(escrow_key.to_string()) {
            return None;
        }
        Some(InFlight {
            service: Arc::clone(self),
            held: escrow_key.to_string(),
        })
    }

    /// Which other reimbursement, if any, holds a part-finished spend of this escrow.
    ///
    /// A reimbursement reserves its escrow from the moment it has a **proposal** — the point at
    /// which specific VTXOs have been picked out and may yet be spent — until it is confirmed or
    /// given up on. Another purchase must not select the same inputs meanwhile.
    ///
    /// **Derived from what is written down, not from a lock.** A lock lives for one attempt: it is
    /// released when that attempt returns, including when it returns because submission failed —
    /// and a submission that failed may still have put a transaction where the chain can find it.
    /// It also dies with the process. Neither is any use for a spend that outlives the attempt that
    /// started it, which is exactly what a signed-but-unsubmitted release is.
    pub async fn reserved_by(self: &Arc<Self>, escrow_key: &str, except: &str) -> Option<String> {
        let want = escrow_key.to_ascii_lowercase();
        self.store
            .lock()
            .await
            .reimbursements
            .values()
            .find(|r| {
                r.request_id != except
                    && r.escrow_key.to_ascii_lowercase() == want
                    && r.holds_a_spend()
            })
            .map(|r| r.request_id.clone())
    }

    /// Everything being tracked, oldest first — for a walkthrough that shows its working.
    pub async fn tracked(self: &Arc<Self>) -> Vec<Reimbursement> {
        self.store.lock().await.reimbursements.values().cloned().collect()
    }

    /// Move a purchase to a later stage. Never backwards: a stage is a thing that happened, and
    /// "confirmed" does not become "signed" again because a later message arrived out of order.
    pub async fn advance(self: &Arc<Self>, request_id: &str, to: Stage) {
        let mut store = self.store.lock().await;
        if let Some(r) = store.reimbursements.get_mut(request_id) {
            if to > r.stage {
                r.stage = to;
            }
        }
    }
}

/// A release exactly as it was first proposed.
///
/// Kept so a retry proposes it again rather than building a new one. See
/// [`Reimbursement::proposal`].
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PersistedProposal {
    pub to_ark_address: String,
    pub amount_sats: u64,
    pub inputs: Vec<PersistedInput>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PersistedInput {
    pub txid: String,
    pub vout: u32,
    pub amount_sats: u64,
    pub exit_delay: u32,
}

/// The right to be the one spending from an escrow. Released on drop.
pub struct InFlight {
    service: Arc<Service>,
    held: String,
}

impl Drop for InFlight {
    fn drop(&mut self) {
        // A blocking lock in a drop, which is safe here because nothing holds this lock across an
        // await: every taker is `claim`, which takes it and lets it go.
        let service = Arc::clone(&self.service);
        let key = self.held.clone();
        if let Ok(mut held) = service.in_flight.try_lock() {
            held.remove(&key);
            return;
        }
        // Contended, which a `BTreeSet` insert makes vanishingly unlikely. Finish the release on
        // the runtime rather than blocking whatever is dropping this.
        tokio::spawn(async move {
            service.in_flight.lock().await.remove(&key);
        });
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn a_reimbursement(stage: Stage, cleared: bool) -> Reimbursement {
        Reimbursement {
            request_id: "reimb-0001".into(),
            escrow_key: "02aa".into(),
            authorization_token: "txn_auth_0001".into(),
            clearing_token: cleared.then(|| "txn_clr_0002".to_string()),
            amount_minor: 2_000,
            currency: "USD".into(),
            sats: 20_000,
            stage,
            last_refusal: None,
            needs_reconciliation: false,
            proposal: None,
            signatures: Vec::new(),
            expected_txid: None,
            ark_txid: None,
        }
    }

    /// The whole point of the example in one assertion: an authorization is not something to be
    /// paid for.
    #[test]
    fn nothing_is_asked_for_until_a_purchase_has_cleared() {
        assert!(!a_reimbursement(Stage::CardAuthorized, false).ready_to_ask());
        assert!(a_reimbursement(Stage::CardCleared, true).ready_to_ask());
        // And what is asked about is the CLEARING, never the hold.
        let cleared = a_reimbursement(Stage::CardCleared, true);
        assert_eq!(cleared.reference(), Some("txn_clr_0002"));
        assert_ne!(cleared.reference(), Some(cleared.authorization_token.as_str()));
    }

    /// Once it is paid it is not asked for again.
    #[test]
    fn a_confirmed_reimbursement_is_not_asked_for_again() {
        assert!(!a_reimbursement(Stage::ReleaseConfirmed, true).ready_to_ask());
    }

    /// Nor is one that needs a person to look at it. Retrying something whose outcome this service
    /// cannot determine is how a loop runs for ever.
    #[test]
    fn one_that_needs_reconciling_stops_being_asked_for() {
        let mut stuck = a_reimbursement(Stage::ReleaseSigned, true);
        assert!(stuck.ready_to_ask());
        stuck.needs_reconciliation = true;
        assert!(!stuck.ready_to_ask());
    }

    /// One escrow is spent from by one thing at a time.
    ///
    /// Two purchases on one escrow, asked for at once, would each read the same VTXOs and each be
    /// signed for them — spending the allowance twice for money only one of them can move, and
    /// leaving the loser tied to inputs that no longer exist.
    #[tokio::test]
    async fn only_one_thing_spends_from_an_escrow_at_a_time() {
        let service = service();
        let alices = service.claim("02aa").await;
        assert!(alices.is_some());
        assert!(
            service.claim("02aa").await.is_none(),
            "a second purchase must wait, not race for the same inputs"
        );
        // Another escrow is another resource, and is free to run.
        assert!(service.claim("02bb").await.is_some());

        drop(alices);
        tokio::task::yield_now().await;
        assert!(service.claim("02aa").await.is_some());
    }

    /// A signature is not a payment, and the two are tracked apart.
    #[test]
    fn signing_and_confirming_are_different_states() {
        assert!(Stage::ReleaseSigned < Stage::ReleaseConfirmed);
        assert!(a_reimbursement(Stage::ReleaseSigned, true).ready_to_ask());
    }

    #[tokio::test]
    async fn a_stage_never_goes_backwards() {
        let service = service();
        {
            let mut store = service.store.lock().await;
            store
                .reimbursements
                .insert("reimb-0001".into(), a_reimbursement(Stage::ReleaseConfirmed, true));
        }
        service.advance("reimb-0001", Stage::CardCleared).await;
        let store = service.store.lock().await;
        assert_eq!(
            store.reimbursements["reimb-0001"].stage,
            Stage::ReleaseConfirmed,
            "a message that arrives late must not un-confirm a payment"
        );
    }

    /// What must survive a restart does, and what must not is not even in the shape.
    #[tokio::test]
    async fn the_store_round_trips_without_carrying_a_nonce() {
        let service = service();
        {
            let mut store = service.store.lock().await;
            store
                .reimbursements
                .insert("reimb-0001".into(), a_reimbursement(Stage::CardCleared, true));
            store.issued = 1;
        }
        let json = serde_json::to_string(&*service.store.lock().await).unwrap();
        let back: Store = serde_json::from_str(&json).unwrap();
        assert_eq!(back.reimbursements["reimb-0001"].stage, Stage::CardCleared);
        assert_eq!(back.issued, 1);
        assert!(
            !json.contains("nonce"),
            "a single-use nonce has no business surviving a restart: {json}"
        );
    }

    #[tokio::test]
    async fn request_ids_are_this_services_own_and_monotonic() {
        let service = service();
        assert_eq!(service.next_request_id().await, "reimb-0001");
        assert_eq!(service.next_request_id().await, "reimb-0002");
    }

    fn service() -> Arc<Service> {
        Service::new(
            threshold::identifier::Identifier::derive(b"test-service").unwrap(),
            "ark1example".into(),
            "http://127.0.0.1:7070".into(),
            "http://127.0.0.1:7100".into(),
            crate::policy::Terms::example("ark1example".into(), "http://127.0.0.1:7100".into()),
            None,
        )
    }
}
