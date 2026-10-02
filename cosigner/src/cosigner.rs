//! The cosigner: the signing keys, the FROST ceremony, the Ark sessions and the ASP connection for
//! the one wallet this process serves.

use std::collections::BTreeMap;
use std::sync::Arc;

use rand::rngs::OsRng;
use serde::{Deserialize, Serialize};
use zeroize::Zeroizing;

use crate::grpc::Status;

use crate::types::{
    BoardingSettleSubmitted, Commitment,
    SendVtxoStep1, SendVtxoSubmitted, SnapshotState, VtxoEntry, VtxoInput,
};

use ark::client::batch::{DelegateSettleSession, PersistedDelegate};
use ark::client::send::{SendSession, SendVtxoInput};
use ark::client::types::ArkInfo;

use threshold::commitment::SigningPackage;
use threshold::identifier::Identifier;
use threshold::keys::{KeyPackage, PublicKeyPackage};
use threshold::nonce::{self, SigningCommitments, SigningNonce};
use threshold::point;
use threshold::scalar::scalar_from_bytes;
use threshold::signing::{self, SignatureShare};

use crate::asp::{AspApi, EventSource};
use crate::boarding::BoardingSettleSession;
use crate::host::valid_task_id;
use crate::renew::{AspCall, RenewSession, RenewStep};
use crate::store::Store;

/// How many escrow keys one wallet may hold at once. Each is a key to co-sign for and a session to
/// time out, and the seal is rewritten in full on every change.
const MAX_ESCROWS: usize = 64;
/// How many spent payments a wallet remembers, across every escrow it holds.
///
/// Not ceremony: each record is a payment this wallet will refuse to pay against twice, and the
/// seal is re-serialized in full on every change. A wallet that reached this many releases can no
/// longer tell a replay from a new payment, and the safe end of that is to stop releasing rather
/// than to forget the oldest — forgetting is exactly what a replay is waiting for.
const MAX_RELEASED_REFERENCES: usize = 1024;

// --- The settle watch --------------------------------------------------------------------------
//
// When a sealed delegate comes due, the cosigner runs it. A VTXO expires. The wallet signs a
// delegate to refresh it while it is here — see `crate::renew` — and the cosigner seals it and
// enqueues this watch for the moment it becomes valid. Then, with no request in flight and nobody
// connected, the task opens the wallet, registers the sealed intent with the ASP over the enclave's
// one allowed origin, follows the round, and signs the tree with the cosigner's own key. See
// [`Cosigner::run_task`].
//
// Waking the owner is the fallback, for when it cannot: the image names no ASP, or the round
// failed. A failure is a conclusion of this run, not an error — an error is retried five times and
// then the task is dead, and a watch that died would renew nothing ever again. So it reports,
// wakes, and the next interval tries again.

/// The id the watch is enqueued under. Tenant-local, and an idempotency key: re-arming replaces
/// rather than accumulating, so a wallet has one watch however many times it prepares a delegate.
pub const WATCH_TASK_ID: &str = "settle-watch";

/// How often the watch runs again after its first run at the deadline — the retry cadence for a
/// round that did not complete. `enclave:tasks` requires at least 1000ms.
pub const WATCH_INTERVAL_MS: u64 = 30 * 60 * 1000;

/// The wake category the app matches on. Opaque by contract — see `notify.wit`. Raised when a due
/// delegate could not be run here, so the owner can refresh in person.
pub const CATEGORY_SETTLE_DUE: &str = "settle-due";

/// Raised after the cosigner refreshed the funds itself: the refreshed VTXO has no delegate yet, and
/// the next time the owner is here the wallet renews the delegate.
pub const CATEGORY_DELEGATE_SETTLED: &str = "delegate-settled";

/// What the watch carries. Small and self-describing so the runtime's stored payload stays
/// readable, and so a future second task kind does not need a new queue id.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(tag = "kind", rename_all = "kebab-case")]
pub enum Task {
    /// Wake the owner once the sealed delegate's intent becomes valid.
    SettleDue {
        /// Unix seconds: earliest covered VTXO expiry minus the safety margin.
        deadline_secs: u64,
    },
}

/// What a run of the watch concluded. Returned to the caller so a test can assert on it, and
/// encoded as the task's result so the runtime persists something meaningful.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(tag = "outcome", rename_all = "kebab-case")]
pub enum Outcome {
    /// Nothing is owed yet.
    NotDue { deadline_secs: u64, now_secs: u64 },
    /// The cosigner ran the delegate: the funds are refreshed.
    Settled { commitment_txid: String },
    /// Due, and not run here — no ASP, or the round failed. The devices were woken.
    Woke { deadline_secs: u64 },
    /// There is no delegate to settle any more — the watch cancels itself.
    NothingToSettle,
}

/// A compressed key without its parity byte, lowercased. Two keys differing only in parity are the
/// same x-only key, and an Ark address commits to the x-only form — so a caller naming an escrow by
/// the address it pays must resolve to the escrow that pays it.
///
/// Byte-sliced, so only a string that IS hex may be sliced: a service names an escrow by this, and
/// a multibyte character in the first two bytes would otherwise panic the guest on its say-so.
pub(crate) fn x_only(key_hex: &str) -> String {
    let k = key_hex.trim().to_ascii_lowercase();
    match (k.len(), k.is_ascii()) {
        (66, true) => k[2..].to_string(),
        _ => k,
    }
}

#[cfg(test)]
mod x_only_tests {
    use super::x_only;

    #[test]
    fn strips_the_parity_byte_of_a_compressed_key() {
        assert_eq!(x_only(&format!("02{}", "ab".repeat(32))), "ab".repeat(32));
        assert_eq!(x_only(&"ab".repeat(32)), "ab".repeat(32));
    }

    #[test]
    fn a_multibyte_key_the_length_of_a_compressed_one_does_not_panic() {
        // 1 + 3 + 62 = 66 bytes, and byte 2 is inside the euro sign.
        let k = format!("0\u{20ac}{}", "a".repeat(62));
        assert_eq!(k.len(), 66);
        assert_eq!(x_only(&k), k);
    }
}

/// The key material one group installed: the cosigner's own share + the group public key, the
/// client's FROST identifier (the other half of the 2-of-2), and the share dealt to the wallet.
/// Every field is `None` until DKG installs it or a seal restores it.
#[derive(Default)]
struct GroupKey {
    group_key: Option<String>,
    key_package: Option<KeyPackage>,
    public_key_package: Option<PublicKeyPackage>,
    user_signing_identifier: Option<Identifier>,
    /// See `SnapshotState::wallet_dealt_share_hex`. Zeroized on drop: it is half of the owner's
    /// signing key, and the other half is one passkey away.
    wallet_dealt_share_hex: Option<Zeroizing<String>>,
}

/// In-flight FROST ceremony state (cleared between rounds).
#[derive(Default)]
pub struct Ceremony {
    message: Vec<u8>,
    commitments: BTreeMap<Identifier, SigningCommitments>,
    shares: BTreeMap<Identifier, SignatureShare>,
    /// The cosigner's single-use nonce for this round (set at begin, consumed at finish).
    nonce: Option<SigningNonce>,
}

/// A FROST round the cosigner is halfway through, for every sighash in one batch.
///
/// Held by the `Send` or `Renew` handler across a single round trip, and consumed by
/// [`Cosigner::sign_in_band_finish`]. Deliberately opaque and not `Clone`: each entry owns a
/// single-use nonce, and a copy is a second use waiting to happen.
pub struct InBandRound {
    ceremonies: Vec<Ceremony>,
}

/// The wallet's half of one message's round: its commitment, and its share over both commitments.
pub struct WalletHalf {
    pub hiding: Vec<u8>,
    pub binding: Vec<u8>,
    pub share: Vec<u8>,
}

pub struct Cosigner {
    policy: GroupKey,
    /// The wallet's delegate, and whether its round is running.
    pub(crate) renew_session: Option<RenewSession>,
    /// In-flight boarding settle, held across the commitment-FROST pause. Transient — never
    /// snapshotted.
    pub(crate) boarding_session: Option<BoardingSettleSession>,
    /// The escrow keys this wallet has minted. See `SnapshotState::escrows`.
    escrows: Vec<crate::types::EscrowRecord>,
    /// Payments that have already been released against. See `SnapshotState::released_references`.
    released_references: BTreeMap<String, crate::types::ReleaseRecord>,
    /// Where the seal lives.
    pub(crate) store: Arc<Store>,
    /// The runtime this cosigner runs inside: its task queue and its push channel. `Detached` when
    /// it runs as a plain process, where every call fails rather than quietly doing nothing.
    pub(crate) host: Arc<dyn crate::host::Host>,
    /// The name the seal is filed under — configuration, and not the wallet's group key, which is
    /// `policy.group_key`. See `main.rs`.
    pub(crate) group_key: String,
    /// The owned VTXO set. `VtxoEntry` carries the expiry a delegate's renewal deadline is
    /// computed from; callers wanting the ark-facing shape go through [`Self::vtxos()`].
    pub(crate) vtxos: Vec<VtxoEntry>,
}

impl Cosigner {
    /// Load this cosigner's state, then hand back something callable.
    ///
    /// Eagerly, not on first use: per-request there is no later use to amortise a lazy restore
    /// into. Storage is the whole of the state — read on entry, sealed on mutation.
    ///
    /// No seal yet is not an error. Before onboarding there is nothing to read, and DKG is what
    /// writes the first one.
    pub fn open(store: Arc<Store>, group_key: String) -> Result<Self, Status> {
        Self::open_with_host(store, group_key, Arc::new(crate::host::Detached))
    }

    /// Open against a given runtime. The guest port and the tests are the two callers.
    pub fn open_with_host(
        store: Arc<Store>,
        group_key: String,
        host: Arc<dyn crate::host::Host>,
    ) -> Result<Self, Status> {
        let mut cosigner = Self::new(store.clone(), group_key.clone(), host);
        // A seal that is there and cannot be read is not the same as no seal. Opening as a wallet
        // with no key would let a DKG re-key the tenant over funds sealed under the old one — and
        // since the seal is the only copy of anything, a read fault must stop here.
        crate::store::restore_snapshot(&mut cosigner, &store, &group_key).map_err(|e| {
            Status::failed_precondition(format!(
                "this wallet's sealed state is present but unreadable ({e}); refusing to open it \
                 as a wallet with no key"
            ))
        })?;
        Ok(cosigner)
    }

    pub fn group_key(&self) -> &str {
        &self.group_key
    }

    pub fn store(&self) -> &Arc<Store> {
        &self.store
    }

    fn new(store: Arc<Store>, group_key: String, host: Arc<dyn crate::host::Host>) -> Self {
        Self {
            policy: GroupKey::default(),
            renew_session: None,
            boarding_session: None,
            escrows: Vec::new(),
            released_references: BTreeMap::new(),
            store,
            host,
            group_key,
            vtxos: Vec::new(),
        }
    }

    /// Serialize durable state (policy, VTXOs, delegate, escrows, release ledger) into the
    /// sealed-snapshot blob. In-flight sessions are excluded (transient; MuSig2 nonces must never
    /// persist).
    pub fn to_snapshot(&self) -> Result<Vec<u8>, String> {
        let policy = &self.policy;
        let (Some(group_key), Some(key_package), Some(public_key_package)) =
            (&policy.group_key, &policy.key_package, &policy.public_key_package)
        else {
            return Err("no policy to snapshot".into());
        };
        let snap = SnapshotState {
            group_key: group_key.clone(),
            key_package_json: key_package.to_json(),
            public_key_package_json: public_key_package.to_json(),
            user_signing_identifier_hex: policy
                .user_signing_identifier
                .as_ref()
                .map(|id| hex::encode(id.serialize())),
            ark_cosigner_secret_hex: None,
            wallet_dealt_share_hex: policy
                .wallet_dealt_share_hex
                .as_ref()
                .map(|z| z.to_string()),
            vtxos: self.vtxos.clone(),
            // Persist a ReadyToSettle delegate (to_persisted errors for other phases → None).
            delegate_json: self
                .renew_session
                .as_ref()
                .and_then(|d| d.session().to_persisted().ok())
                .and_then(|p| serde_json::to_string(&p).ok()),
            delegate_intent_id: None,
            escrows: self.escrows.clone(),
            released_references: self.released_references.clone(),
        };
        serde_json::to_vec(&snap).map_err(|e| format!("snapshot serialize: {e}"))
    }

    /// Restore durable state from a snapshot blob, on open.
    pub fn restore_snapshot(&mut self, blob: &[u8]) -> Result<(), String> {
        let snap: SnapshotState =
            serde_json::from_slice(blob).map_err(|e| format!("snapshot deserialize: {e}"))?;
        let key_package = KeyPackage::from_json(&snap.key_package_json)
            .map_err(|e| format!("bad key package: {e}"))?;
        let public_key_package = PublicKeyPackage::from_json(&snap.public_key_package_json)
            .map_err(|e| format!("bad public key package: {e}"))?;
        let user_signing_identifier = snap
            .user_signing_identifier_hex
            .map(|h| h.parse::<Identifier>())
            .transpose()
            .map_err(|e| format!("bad identifier: {e}"))?;
        self.policy = GroupKey {
            group_key: Some(snap.group_key),
            key_package: Some(key_package),
            public_key_package: Some(public_key_package),
            user_signing_identifier,
            wallet_dealt_share_hex: snap.wallet_dealt_share_hex.map(Zeroizing::new),
        };
        self.vtxos = snap.vtxos;
        self.escrows = snap.escrows;
        self.released_references = snap.released_references;
        // A delegate carries its own tree-signing key and its registration's id. Older seals kept
        // both beside it — a wallet-wide key, and `delegate_intent_id` — which are read here for
        // that and nothing else: the next seal writes them inside the delegate, and not beside it.
        self.renew_session = match snap.delegate_json {
            Some(dj) => {
                let mut persisted: PersistedDelegate = serde_json::from_str(&dj)
                    .map_err(|e| format!("parse persisted delegate: {e}"))?;
                if persisted.delegate_cosigner_secret_hex.is_empty() {
                    persisted.delegate_cosigner_secret_hex =
                        snap.ark_cosigner_secret_hex.unwrap_or_default();
                }
                if persisted.intent_id.is_none() {
                    persisted.intent_id = snap.delegate_intent_id;
                }
                Some(RenewSession::Awaiting(DelegateSettleSession::from_persisted(&persisted)?))
            }
            None => None,
        };
        Ok(())
    }

    /// The share this cosigner dealt the wallet at DKG, hex, if this wallet was onboarded after
    /// recovery existed. See `SnapshotState::wallet_dealt_share_hex`.
    pub(crate) fn wallet_dealt_share_hex(&self) -> Option<&str> {
        self.policy.wallet_dealt_share_hex.as_ref().map(|z| z.as_str())
    }

    /// Take the caller's account of what this wallet holds, which means saying exactly what is and
    /// is not trusted here.
    ///
    /// NOT trusted: ownership. Every VTXO this wallet can spend sits under a scriptPubKey derived
    /// from the cosigner's OWN owner key and one of the two exit delays the ASP published — so an
    /// `exit_delay` outside that pair names a script this wallet does not control, and is refused
    /// outright. A caller cannot widen what it owns by asserting it.
    ///
    /// Trusted: existence. Whether `(txid, vout)` is really unspent is the ASP's to know, and a
    /// caller inventing one gets a transaction the ASP rejects — it wastes a round and nothing
    /// else. Existence is not a secret, so taking it on trust costs nothing.
    pub fn accept_vtxos(&mut self, supplied: Vec<VtxoInput>, info: &ArkInfo) -> Result<(), String> {
        let (unilateral, boarding) = (
            info.unilateral_exit_delay as u32,
            info.boarding_exit_delay as u32,
        );
        let now = crate::store::now_secs();
        let mut accepted: Vec<VtxoEntry> = Vec::with_capacity(supplied.len());
        for v in supplied {
            if v.exit_delay != unilateral && v.exit_delay != boarding {
                return Err(format!(
                    "vtxo {}:{} has exit delay {} — this wallet's are {unilateral} (received) or \
                     {boarding} (boarded); it is not ours to spend",
                    v.txid, v.vout, v.exit_delay
                ));
            }
            if v.amount_sats == 0 {
                return Err(format!("vtxo {}:{} has no amount", v.txid, v.vout));
            }
            if accepted.iter().any(|e| e.txid == v.txid && e.vout == v.vout) {
                return Err(format!("vtxo {}:{} named twice", v.txid, v.vout));
            }
            // Expiry is the indexer's, relayed by the caller; 0 reads as "unknown" downstream, which
            // `settle_deadline` skips conservatively rather than scheduling against a guess.
            accepted.push(VtxoEntry {
                txid: v.txid,
                vout: v.vout,
                amount: v.amount_sats,
                exit_delay: v.exit_delay,
                created_at: now,
                expires_at: v.expires_at.max(0),
            });
        }
        self.vtxos = accepted;
        Ok(())
    }

    /// The owned set in the shape ark's session builders take.
    pub fn vtxos(&self) -> Vec<VtxoInput> {
        self.vtxos
            .iter()
            .map(|e| VtxoInput {
                txid: e.txid.clone(),
                vout: e.vout,
                amount_sats: e.amount,
                exit_delay: e.exit_delay,
                expires_at: e.expires_at,
            })
            .collect()
    }

    /// When a delegate over the held set becomes valid: the earliest known expiry minus the safety
    /// margin. `None` when nothing is held, or no held VTXO has a known expiry — the ASP had not
    /// indexed them yet.
    pub(crate) fn settle_deadline(&self) -> Option<u64> {
        if self.vtxos.is_empty() {
            return None;
        }
        let earliest = self
            .vtxos
            .iter()
            .filter_map(|e| (e.expires_at > 0).then_some(e.expires_at))
            .min()
            .unwrap_or(0);
        let margin = self.store.auto_settle_safety_margin_secs;
        (earliest > margin).then(|| (earliest - margin) as u64)
    }

    /// Build a delegate over everything held and keep it as this wallet's [`RenewSession`], handing
    /// back the sighashes the wallet must FROST-sign. `deferred`: valid from
    /// [`Self::settle_deadline`] (a sealed delegate), or from now (a refresh the owner is asking
    /// for in person — the ASP refuses an intent valid in the future until then).
    pub fn generate_delegate_for(
        &mut self,
        info: &ArkInfo,
        deferred: bool,
    ) -> Result<Vec<Vec<u8>>, String> {
        let valid_at = if deferred { self.settle_deadline() } else { None };
        let (session, sighashes) =
            RenewSession::generate(&self.owner_pk_hex()?, &self.vtxos(), info, valid_at)?;
        self.renew_session = Some(session);
        Ok(sighashes)
    }

    /// The body of the guest's exported `run-task`, with no ASP to run a delegate against — so a
    /// due delegate wakes the owner instead.
    pub fn run_task(&mut self, task_id: &str, payload: &[u8]) -> Result<Vec<u8>, String> {
        crate::handlers::helpers::block_on_ready(
            self.run_task_with::<crate::asp::NoAsp>(task_id, payload, None),
        )
    }

    /// The body of the guest's exported `run-task`.
    ///
    /// `task_id` is the runtime's *run* id, `<id>:<generation>:<occurrence>` — stable across retries
    /// of one occurrence, distinct across occurrences — not the id it was enqueued under. Only the
    /// id is ours to check; the rest identifies the run.
    ///
    /// Errors are retried by the runtime and successes are persisted, so anything recoverable must
    /// return `Err` and anything concluded must return `Ok` — including "not due" and "could not
    /// run it", which are conclusions and not failures.
    pub async fn run_task_with<A: AspApi>(
        &mut self,
        task_id: &str,
        payload: &[u8],
        asp: Option<&mut A>,
    ) -> Result<Vec<u8>, String> {
        let id = task_id.split(':').next().unwrap_or_default();
        if !valid_task_id(id) {
            return Err(format!("task id {task_id:?} is not a tenant-local key"));
        }
        let task: Task = serde_json::from_slice(payload)
            .map_err(|e| format!("undecodable task payload: {e}"))?;
        let outcome = match task {
            Task::SettleDue { deadline_secs } => self.settle_due(deadline_secs, asp).await?,
        };
        serde_json::to_vec(&outcome).map_err(|e| format!("encode outcome: {e}"))
    }

    async fn settle_due<A: AspApi>(
        &mut self,
        deadline_secs: u64,
        asp: Option<&mut A>,
    ) -> Result<Outcome, String> {
        // No sealed delegate: it was run, or spent by a send, or replaced — nothing is owed. The
        // cancel is best-effort (a background run may not mutate the queue); the next renewal
        // re-arms.
        if self.renew_session.is_none() {
            self.host.cancel(WATCH_TASK_ID).ok();
            return Ok(Outcome::NothingToSettle);
        }

        let now = crate::store::now_secs().max(0) as u64;
        if now < deadline_secs {
            return Ok(Outcome::NotDue {
                deadline_secs,
                now_secs: now,
            });
        }

        if let Some(asp) = asp {
            // Run the sealed delegate's round against the ASP, for its commitment txid. Safe to
            // run again after a failure: the registered intent's id is sealed as soon as the ASP
            // assigns it, so a retry follows the same registration rather than making a second
            // one, and a failed batch clears it so the next attempt registers afresh.
            let run: Result<String, String> = async {
                let delegate =
                    self.renew_session.as_ref().ok_or("no sealed delegate")?.session();
                let (proof, message, topics) = delegate.register_payload()?;
                let registered = delegate.intent_id.is_some();
                let info = asp.get_info().await?;

                if !registered {
                    let id = asp.register_intent(&proof, &message).await?;
                    if let Some(delegate) = self.renew_session.as_mut() {
                        delegate.session_mut().intent_id = Some(id);
                    }
                    self.seal();
                }

                let mut events = asp.events(&topics).await?;
                let held: u64 = self.vtxos.iter().map(|v| v.amount).sum();
                let exit_delay = info.unilateral_exit_delay as u32;
                self.renew_session =
                    self.renew_session.take().map(|d| d.in_flight(exit_delay));

                let outcome: Result<crate::types::BoardingSettleSubmitted, String> = async {
                    loop {
                        let event = events
                            .next()
                            .await?
                            .ok_or("the ASP's event stream ended before the batch finalized")?;
                        match self.renew_on_event(event)? {
                            RenewStep::Idle => {}
                            RenewStep::Submit(AspCall::ConfirmRegistration { intent_id }) => {
                                asp.confirm_registration(&intent_id).await?
                            }
                            RenewStep::Submit(AspCall::TreeNonces { batch_id, pubkey, nonces }) => {
                                asp.submit_tree_nonces(&batch_id, &pubkey, &nonces).await?
                            }
                            RenewStep::Submit(AspCall::TreeSignatures {
                                batch_id,
                                pubkey,
                                signatures,
                            }) => {
                                asp.submit_tree_signatures(&batch_id, &pubkey, &signatures).await?
                            }
                            RenewStep::Submit(AspCall::ForfeitTxs {
                                signed_txs,
                                signed_commitment_b64,
                            }) => asp.submit_forfeits(&signed_txs, &signed_commitment_b64).await?,
                            RenewStep::Complete(sub) => return Ok(sub),
                            RenewStep::Sighashes(_) | RenewStep::Register { .. } => {
                                return Err(
                                    "a delegate round asked for a signature it should not need"
                                        .into(),
                                )
                            }
                        }
                    }
                }
                .await;

                // A round that stopped short leaves the delegate waiting again; a finished one took
                // it.
                self.renew_session =
                    self.renew_session.take().map(RenewSession::awaiting);
                match outcome {
                    Ok(sub) => {
                        // Everything the delegate covered was spent into the one VTXO it produced,
                        // and the delegate went with its round.
                        self.vtxos = vec![VtxoEntry {
                            txid: sub.vtxo_txid,
                            vout: sub.vtxo_vout,
                            amount: held,
                            exit_delay: sub.exit_delay,
                            created_at: crate::store::now_secs(),
                            expires_at: 0,
                        }];
                        self.seal();
                        Ok(sub.commitment_txid)
                    }
                    Err(e) => {
                        if e.contains("batch failed") {
                            // The ASP dropped the registration with the batch; register again next
                            // time.
                            if let Some(delegate) = self.renew_session.as_mut() {
                                delegate.session_mut().intent_id = None;
                            }
                            self.seal();
                        }
                        Err(e)
                    }
                }
            }
            .await;
            match run {
                Ok(commitment_txid) => {
                    // Best-effort: the refresh happened either way.
                    self.host.wake(CATEGORY_DELEGATE_SETTLED, None).ok();
                    return Ok(Outcome::Settled { commitment_txid });
                }
                Err(e) => eprintln!("the sealed delegate could not be run: {e}"),
            }
        }

        // The one call a task may make that an interactive call had to earn first. It spends the
        // enrolment; it authorizes nothing.
        self.host
            .wake(CATEGORY_SETTLE_DUE, None)
            .map_err(|e| format!("wake: {e}"))?;
        Ok(Outcome::Woke { deadline_secs })
    }

    /// Seal this cosigner's state, logging a failure rather than returning it.
    pub fn seal(&mut self) {
        if let Err(e) = self.try_seal() {
            tracing::warn!("{e}");
        }
    }

    /// Seal, and say whether it took. For the one place a change must not be acted on unless it
    /// is durable: a release signed but not written down is a payment that can be asked for again.
    pub fn try_seal(&mut self) -> Result<(), String> {
        let store = self.store.clone();
        let group_key = self.group_key.clone();
        crate::store::seal_snapshot(self, &store, &group_key)
    }

    /// Record a settled boarding output: replace it in the owned set with the VTXO it became, and
    /// hand back the commitment txid.
    pub fn apply_boarding_settle(&mut self, sub: BoardingSettleSubmitted) -> String {
        let now = crate::store::now_secs();
        self.vtxos
            .retain(|e| !(e.txid == sub.vtxo_txid && e.vout == sub.vtxo_vout));
        self.vtxos.push(VtxoEntry {
            txid: sub.vtxo_txid.clone(),
            vout: sub.vtxo_vout,
            amount: sub.amount_sats,
            exit_delay: sub.exit_delay,
            created_at: now,
            expires_at: 0,
        });
        sub.commitment_txid
    }

    /// Record a completed send: drop the delegate, and answer the caller. The owned set was already
    /// replaced with the change by [`Self::send_complete`].
    pub fn apply_send(
        &mut self,
        submitted: SendVtxoSubmitted,
    ) -> crate::wallet_proto::SendVtxoResponse {
        // The send spent what the sealed delegate was signed over, so it can never settle now.
        // Dropping it makes the settle watch find nothing on its next run and cancel itself.
        self.renew_session = None;
        crate::wallet_proto::SendVtxoResponse {
            status: crate::wallet_proto::send_vtxo_response::Status::Settled as i32,
            messages_to_sign: vec![],
            script_path_spend: false,
            ark_txid: submitted.ark_txid,
            error_message: String::new(),
        }
    }

    /// The wallet's group x-only pubkey (hex) — the VTXO owner key, from the installed policy's PKP.
    pub fn owner_pk_hex(&self) -> Result<String, String> {
        let pkp = self.policy.public_key_package.as_ref().ok_or("no policy installed")?;
        let vk = pkp.verifying_key.serialize(); // [u8; 33]
        Ok(hex::encode(&vk[1..]))
    }

    #[allow(clippy::too_many_arguments)]
    pub fn install_policy(
        &mut self,
        group_key: String,
        key_package_json: &str,
        public_key_package_json: &str,
        user_signing_identifier_hex: Option<&str>,
        wallet_dealt_share_hex: Option<String>,
    ) -> Result<(), String> {
        let key_package =
            KeyPackage::from_json(key_package_json).map_err(|e| format!("bad key package: {e}"))?;
        let public_key_package = PublicKeyPackage::from_json(public_key_package_json)
            .map_err(|e| format!("bad public key package: {e}"))?;
        let user_signing_identifier = user_signing_identifier_hex
            .map(|h| h.parse::<Identifier>())
            .transpose()
            .map_err(|e| format!("bad identifier: {e}"))?;
        self.policy = GroupKey {
            group_key: Some(group_key),
            key_package: Some(key_package),
            public_key_package: Some(public_key_package),
            user_signing_identifier,
            wallet_dealt_share_hex: wallet_dealt_share_hex.map(Zeroizing::new),
        };
        Ok(())
    }



    /// This wallet's group key, hex, once it has one.
    pub(crate) fn policy_group_key(&self) -> Option<String> {
        self.policy.group_key.clone()
    }

    /// The ceremony's public key package, JSON: the group key and both verifying shares. Public by
    /// construction — it is what a recovering wallet checks its rebuilt share against.
    pub(crate) fn policy_public_key_package_json(&self) -> Option<String> {
        self.policy.public_key_package.as_ref().map(PublicKeyPackage::to_json)
    }

    /// The owner's FROST identifier, as the ceremony recorded it.
    pub(crate) fn user_signing_identifier(&self) -> Option<Identifier> {
        self.policy.user_signing_identifier.clone()
    }

    /// Rebuild a wallet on a new device, from nothing but its passkey: hand back the half of its
    /// share this cosigner dealt, with the public material to check it against.
    ///
    /// # Why half a key is sitting here
    ///
    /// A FROST share is the sum of every dealer's polynomial evaluated at the participant's
    /// identifier. For this 2-of-2 that is two terms:
    ///
    /// ```text
    ///   s_wallet = f_wallet(id_wallet) + f_cosigner(id_wallet)
    /// ```
    ///
    /// The wallet's own dealer is no longer random: it is derived from the passkey's PRF output,
    /// which the platform syncs with the passkey, so a new phone that can use the passkey can
    /// reproduce `f_wallet` exactly — and with it `id_wallet`, which is derived from `a0·G`. The
    /// second term it cannot reproduce: the cosigner's polynomial was destroyed when the ceremony
    /// ended. So the cosigner keeps the one scalar it dealt out, and hands it back here.
    ///
    /// # What this is not
    ///
    /// It is not a key escrow. The scalar returned is one term of a sum whose other term exists
    /// only behind the owner's biometric; alone it signs nothing and identifies nothing. And it is
    /// not a ceremony: nothing is installed, no policy is written, no share is re-keyed. A recovery
    /// that re-keyed would strand the VTXOs, the delegate and the escrows the seal already holds —
    /// which is exactly the accident `refuse_if_onboarded` exists to prevent, and this is its mirror
    /// image: that one refuses when a policy exists, this one refuses when none does.
    ///
    /// # Who may call it
    ///
    /// The runtime resolved the tenant from the caller's passkey before this was reached; there is
    /// no second authentication to do here and none is invented. What is checked instead is that
    /// the passkey used is the *right* one: the caller sends the identifier it derived, and a
    /// mismatch is refused rather than answered. A wallet whose PRF output changed is a wallet that
    /// can no longer sign, and it is far better to say so than to hand back a share that will not
    /// add up.
    pub fn recover(
        &self,
        req: crate::session::proto::RecoverRequest,
    ) -> Result<crate::session::proto::RecoverResponse, Status> {
        let dealt_share = self.dealt_share_for(&req.identifier)?;
        // `dealt_share_for` has already refused a wallet with no key, so these are there.
        let (group_key, public_key_package_json) =
            match (self.policy_group_key(), self.policy_public_key_package_json()) {
                (Some(g), Some(p)) => (g, p),
                _ => {
                    return Err(Status::internal("the wallet has a dealt share and no key package"))
                }
            };

        let now = crate::store::now_secs();
        tracing::info!("Recover: returning the dealt share to the wallet's own identifier");
        Ok(crate::session::proto::RecoverResponse {
            dealt_share,
            public_key_package_json,
            group_key,
            escrows: self.escrows().iter().map(|e| e.summary(now)).collect(),
        })
    }

    /// The half of the wallet's share the cosigner dealt at DKG, for the wallet that is
    /// [identifier].
    ///
    /// `Recover` hands it to a device that has nothing. `Sign`, `Send` and `Renew` hand it back on
    /// their first round, every time, because the wallet keeps no share between operations any
    /// more: it re-derives its own half from the passkey and adds this one, under the approval the
    /// stream already has. One rule for all four, so there is one place it can be wrong.
    ///
    /// What this guards, and what it does not. The caller was authenticated by the runtime as this
    /// tenant before any of this ran, and a tenant's seal is the only one this instance can read —
    /// that is what keeps one tenant's half from another, and it is not re-implemented here. The
    /// identifier is public (it is in the key package and on the wire), so matching it proves
    /// nothing about who is asking. It proves the wallet asking is *this* wallet: a wrong passkey,
    /// or a PRF that answers differently, derives another identifier and is told so instead of
    /// being handed a share that would not add up.
    ///
    /// Never the cosigner's own share — that is `key_package.secret_share`, and nothing returns it.
    pub(crate) fn dealt_share_for(&self, identifier: &[u8]) -> Result<Vec<u8>, Status> {
        // The mirror of `refuse_if_onboarded`: there is nothing to hand back before a ceremony.
        if self.policy_group_key().is_none() {
            return Err(Status::failed_precondition(
                "this wallet has no key yet: there is nothing to recover, create one instead",
            ));
        }

        let expected = self.user_signing_identifier().ok_or_else(|| {
            Status::failed_precondition("this wallet's ceremony recorded no owner identifier")
        })?;
        let asked: [u8; 32] = identifier
            .try_into()
            .map_err(|_| Status::invalid_argument("identifier must be 32 bytes"))?;
        let asked = Identifier::deserialize(&asked)
            .map_err(|e| Status::invalid_argument(format!("bad identifier: {e}")))?;
        if asked != expected {
            // Not "wrong passkey" necessarily — a PRF that answers differently on this device
            // looks exactly the same from here. Either way the share would not add up, so say so
            // now.
            return Err(Status::permission_denied(
                "that passkey does not derive this wallet's owner key: the share it rebuilt would \
                 not be able to sign",
            ));
        }

        self.wallet_dealt_share_hex()
            .ok_or_else(|| {
                Status::failed_precondition(
                    "this wallet was created before recovery existed: the cosigner did not keep \
                     the share it dealt, and it cannot be recomputed",
                )
            })
            .and_then(|h| {
                hex::decode(h)
                    .map_err(|e| Status::internal(format!("sealed share is not hex: {e}")))
            })
    }

    // --- Escrow keys -----------------------------------------------------------------------------
    //
    // A second 2-of-2 over a key of its own, minted by a reshare so a service can be paired into
    // escrowed money without being paired into the wallet. See `crate::handlers::escrow`.

    /// The wallet key material a reshare is dealt against: this cosigner's own share and the
    /// group's public package. `None` before onboarding, when there is nothing to reshare.
    pub(crate) fn wallet_key_material(&self) -> Option<(KeyPackage, PublicKeyPackage)> {
        Some((self.policy.key_package.clone()?, self.policy.public_key_package.clone()?))
    }

    /// The runtime this instance is running inside.
    ///
    /// Cloned out rather than borrowed so a caller can hold it across an await without holding the
    /// wallet's lock — which matters for the one thing it is used for here: opening a connection
    /// to a service and waiting for the runtime to dial it.
    pub fn host(&self) -> Arc<dyn crate::host::Host> {
        self.host.clone()
    }

    /// The escrows this wallet holds, oldest first.
    pub fn escrows(&self) -> &[crate::types::EscrowRecord] {
        &self.escrows
    }

    /// One escrow by its key, comparing x-only so either parity resolves — the reason a caller can
    /// name an escrow by the address it pays.
    pub fn escrow(&self, escrow_key: &str) -> Option<&crate::types::EscrowRecord> {
        let want = x_only(escrow_key);
        self.escrows.iter().find(|e| x_only(&e.escrow_key) == want)
    }

    /// One escrow's key material, to deal a pairing or sign a reclaim against. `None` when the
    /// escrow is unknown or its sealed material does not parse.
    pub(crate) fn escrow_details(&self, escrow_key: &str) -> Option<crate::escrow::EscrowDetails> {
        let record = self.escrow(escrow_key)?;
        let id_bytes: [u8; 32] = hex::decode(&record.wallet_identifier_hex).ok()?.try_into().ok()?;
        Some(crate::escrow::EscrowDetails {
            key: record.escrow_key.clone(),
            key_package: KeyPackage::from_json(&record.key_package_json).ok()?,
            public_key_package: PublicKeyPackage::from_json(&record.public_key_package_json).ok()?,
            wallet_id: Identifier::deserialize(&id_bytes).ok()?,
        })
    }

    /// Record a service pairing against one escrow.
    ///
    /// One service per escrow, and refused if there is already one: a second pairing would be a
    /// second way to be paid out of money committed to a single deal, and the escrow has no way to
    /// say which of them the deal was with.
    pub fn pair_escrow_service(
        &mut self,
        escrow_key: &str,
        pairing: crate::types::ServicePairing,
    ) -> Result<(), String> {
        let want = x_only(escrow_key);
        let record = self
            .escrows
            .iter_mut()
            .find(|e| x_only(&e.escrow_key) == want)
            .ok_or("this wallet holds no such escrow")?;
        // Replaceable only while unfinished — see the note at the call site in `session.rs`. A
        // retry deals fresh halves, so the record it replaces is one nothing could have used.
        if record
            .pairing
            .as_ref()
            .is_some_and(|p| p.state() == crate::types::PairingState::Ready)
        {
            return Err("this escrow already has a service paired into it".into());
        }
        record.pairing = Some(pairing);
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
    pub fn confirm_escrow_pairing(
        &mut self,
        escrow_key: &str,
        attempt_id_hex: &str,
    ) -> Result<(), String> {
        self.confirm_pairing(escrow_key, attempt_id_hex, |p| p.wallet_confirmed = true)
    }

    /// The SERVICE's half: it holds both halves and the share they sum to matches the published
    /// verifying share. Arrives over the connection the runtime holds — see
    /// [`crate::service_stream`].
    pub fn confirm_pairing_by_service(
        &mut self,
        escrow_key: &str,
        attempt_id_hex: &str,
    ) -> Result<(), String> {
        self.confirm_pairing(escrow_key, attempt_id_hex, |p| p.service_confirmed = true)
    }

    fn confirm_pairing(
        &mut self,
        escrow_key: &str,
        attempt_id_hex: &str,
        set: impl FnOnce(&mut crate::types::ServicePairing),
    ) -> Result<(), String> {
        let want = x_only(escrow_key);
        let record = self
            .escrows
            .iter_mut()
            .find(|e| x_only(&e.escrow_key) == want)
            .ok_or("this wallet holds no such escrow")?;
        let pairing = record
            .pairing
            .as_mut()
            .ok_or("this escrow has no service paired into it")?;
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

    /// Commit an escrow to a deal. Refuses an escrow with no service, and refuses a second
    /// session over a live one.
    ///
    /// No service means nobody could ever release, so a session over such an escrow would lock the
    /// owner out of their own money until a deadline for no one's benefit.
    pub fn open_escrow_session(
        &mut self,
        escrow: crate::escrow_session::Escrow,
        now: i64,
    ) -> Result<(), String> {
        self.may_commit_escrow(&escrow.escrow_key, now)?;
        let want = x_only(&escrow.escrow_key);
        let record = self
            .escrows
            .iter_mut()
            .find(|e| x_only(&e.escrow_key) == want)
            .ok_or("this wallet holds no such escrow")?;
        record.session = Some(escrow);
        Ok(())
    }

    /// Whether [`open_escrow_session`](Self::open_escrow_session) would commit this escrow at
    /// `now`, without committing it.
    ///
    /// A send that tops an escrow up and commits it asks this before anything is built: a deal that
    /// could not be struck is refused while no money has moved. Nothing else can write between the
    /// question and the commit — the stream holds the tenant — so with the same `now` the answer
    /// still holds when the send is final.
    pub fn may_commit_escrow(&self, escrow_key: &str, now: i64) -> Result<(), String> {
        let want = x_only(escrow_key);
        let record = self
            .escrows
            .iter()
            .find(|e| x_only(&e.escrow_key) == want)
            .ok_or("this wallet holds no such escrow")?;
        // Before anything else. Signatures a reclaim handed out are valid for as long as the
        // outpoints they spend exist, and this cosigner can see neither whether they left the
        // device nor whether those outpoints are still there. A deal struck over them would be
        // one the owner could empty at will — so an escrow a reclaim was ever opened on is done
        // with deals, and the next deal gets a new escrow.
        if let Some(at) = record.reclaim_opened_at {
            return Err(format!(
                "a reclaim was opened on this escrow at {at}, so signatures that empty it may \
                 exist; it cannot be committed to a deal again — mint a new escrow"
            ));
        }
        match record.pairing.as_ref().map(|p| p.state()) {
            None => {
                return Err(
                    "this escrow has no service paired into it: committing it would lock the money \
                     away until the deadline with nobody able to take it"
                        .into(),
                )
            }
            // Delivered but not shown to work. The service holds one half of two, so it could not
            // take its side of the deal — which is the same problem as having no service at all.
            Some(crate::types::PairingState::Pending) => {
                return Err(format!(
                    "this escrow's service pairing is not finished: {}",
                    record
                        .pairing
                        .as_ref()
                        .map(|p| p.awaiting())
                        .unwrap_or("nobody has confirmed it"),
                ))
            }
            Some(crate::types::PairingState::Ready) => {}
        }
        // A deal can be struck again once the last one no longer holds the escrow: its deadline
        // has passed (or its service brought the deadline forward), or everything it allows has
        // been released. Not before, and never at the owner's word — see `crate::escrow_session`.
        if record.session.as_ref().is_some_and(|s| s.holds_the_escrow(now)) {
            return Err(
                "this escrow is already committed to a deal, and a deal runs until its deadline, \
                 until its service ends it, or until everything it allows has been released"
                    .into(),
            );
        }
        Ok(())
    }

    /// The escrow's service ends the deal it is party to.
    ///
    /// `policy_sha256` names the deal, so an end meant for one deal — a retry arriving late, say —
    /// cannot end the next one struck over the same escrow. Ending a deal that is already over is
    /// not an error: the service asked for something that is already true.
    pub fn end_escrow_deal(
        &mut self,
        escrow_key: &str,
        policy_sha256: &str,
        now: i64,
    ) -> Result<(), String> {
        let want = x_only(escrow_key);
        let session = self
            .escrows
            .iter_mut()
            .find(|e| x_only(&e.escrow_key) == want)
            .ok_or("this wallet holds no such escrow")?
            .session
            .as_mut()
            .ok_or("this escrow is not committed to a deal")?;
        if crate::policy::policy_sha256(&session.policy) != policy_sha256 {
            return Err("that is not the deal this escrow is committed to".into());
        }
        session.end_by_service(now);
        Ok(())
    }

    /// The earliest moment the owner may take this escrow back.
    ///
    /// The later of its current deal's deadline and the deadline of every deal that released
    /// anything from it. A deal that ended early — spent, or ended by its service — may have
    /// handed a service signatures it has yet to submit, and a reclaim spends the same VTXOs; so
    /// the deadline that deal promised still stands for the owner, whatever has been struck since.
    /// Read from the release ledger, which already outlives any one session.
    pub fn reclaim_horizon(&self, escrow_key: &str) -> i64 {
        let want = x_only(escrow_key);
        let released = self
            .released_references
            .values()
            .filter(|r| r.escrow_key == want)
            .map(|r| r.deadline)
            .max()
            .unwrap_or(0);
        let current = self
            .escrow(escrow_key)
            .and_then(|e| e.session.as_ref())
            .map_or(0, |s| s.deadline);
        released.max(current)
    }

    /// A reclaim is being opened on [escrow_key]: retire it from deals, for good.
    ///
    /// Called before the reclaim's round begins, and sealed by the caller before any nonce is
    /// made, so an abandoned stream is as final as a finished one. The first time is kept; a
    /// second reclaim on the same escrow — after an ASP failure, say — changes nothing.
    pub fn mark_escrow_reclaim_opened(&mut self, escrow_key: &str, now: i64) -> Result<(), String> {
        let want = x_only(escrow_key);
        let record = self
            .escrows
            .iter_mut()
            .find(|e| x_only(&e.escrow_key) == want)
            .ok_or("this wallet holds no such escrow")?;
        record.reclaim_opened_at.get_or_insert(now);
        Ok(())
    }

    /// May this release be answered at all, and has it been answered already?
    ///
    /// Four questions, and each is a different refusal:
    ///
    /// 1. **Has this payment already justified a release?** A replayed authorization verifies every
    ///    time, because it really did succeed — so what stops it paying twice is this ledger. It is
    ///    the wallet's, not the deal's: reopening an escrow must not empty it, and a second escrow
    ///    paired to the same service must not be able to spend what the first already did.
    /// 2. **Is this a repeat of the request we answered for it?** Then the answer must be the same
    ///    answer — [`Admission::AlreadyAnswered`], sign again and count nothing. A repeat that is a
    ///    *different* release, or that comes from a different escrow, is refused.
    /// 3. **Has this request id already been answered, for some other payment?** The lookup above
    ///    is by payment, so a repeat that changed its reference would miss it and be admitted as
    ///    new — leaving one request id naming two approved releases, and a service that correlates
    ///    replies by it unable to tell which one it had. An idempotency key that identifies two
    ///    different things is not one.
    /// 4. **Is there room to remember another?** See [`MAX_RELEASED_REFERENCES`].
    pub fn admit_release(
        &self,
        escrow_key: &str,
        request_id: &str,
        reference: &str,
        proposal_hash: &str,
    ) -> Result<crate::types::Admission, String> {
        use crate::types::Admission;
        if let Some(record) = self.released_references.get(reference) {
            if record.escrow_key != x_only(escrow_key) {
                return Err(format!(
                    "that payment has already been released against, by another escrow of this \
                     wallet: evidence that a payment succeeded stays true, so it may justify one \
                     release and no more"
                ));
            }
            if record.request_id != request_id {
                return Err(format!(
                    "that payment has already been released against, as request {}: evidence that \
                     a payment succeeded stays true, so it may justify one release and no more",
                    record.request_id
                ));
            }
            if record.proposal_hash != proposal_hash {
                return Err(
                    "that request id was answered for a different release; a new release needs a \
                     new request id and a new payment"
                        .into(),
                );
            }
            return Ok(Admission::AlreadyAnswered(Box::new(record.clone())));
        }
        // Scoped to the escrow, so two services that both like the name "1" do not collide: a
        // request id is the SERVICE's key, and a service reaches one escrow through one pairing.
        //
        // A scan rather than a second map, deliberately. The ledger is capped, this runs once per
        // release, and one source of truth cannot drift out of step with itself — which is exactly
        // what an index maintained beside it could do.
        if let Some((reference, record)) = self.released_references.iter().find(|(_, r)| {
            r.escrow_key == x_only(escrow_key) && r.request_id == request_id
        }) {
            return Err(format!(
                "request {request_id} was already answered, against payment {reference}, and that \
                 answer paid {} sats; a different release needs a different request id",
                record.sats
            ));
        }
        if self.released_references.len() >= MAX_RELEASED_REFERENCES {
            return Err(format!(
                "this wallet has released against {MAX_RELEASED_REFERENCES} payments and cannot \
                 remember another; past that it could not tell a repeat from a new one, so it \
                 releases nothing more"
            ));
        }
        Ok(Admission::New)
    }

    /// Write down a release this escrow made.
    ///
    /// Sealed by the caller, because a release that was signed and not recorded is a release that
    /// can be asked for again — see [`crate::handlers::release`].
    pub fn record_escrow_release(
        &mut self,
        escrow_key: &str,
        reference: String,
        record: crate::types::ReleaseRecord,
    ) -> Result<(), String> {
        let want = x_only(escrow_key);
        let session = self
            .escrows
            .iter_mut()
            .find(|e| x_only(&e.escrow_key) == want)
            .ok_or("this wallet holds no such escrow")?
            .session
            .as_mut()
            .ok_or("this escrow is not committed to anything")?;
        // Two different lifetimes, on purpose. The allowance belongs to the deal and resets when a
        // new one is struck; the payment is spent for as long as this wallet exists.
        session.record_release(record.sats);
        self.released_references.insert(reference, record);
        Ok(())
    }

    /// What this wallet has already released against, for a caller that wants to show it.
    pub fn released_references(&self) -> &BTreeMap<String, crate::types::ReleaseRecord> {
        &self.released_references
    }

    /// Record a freshly minted escrow. Refuses a duplicate key and refuses past the cap.
    ///
    /// The cap is not ceremony: every escrow is a standing obligation — a key to co-sign for, a
    /// session to time out — and the seal is re-serialized in full on every mutation, so an
    /// unbounded run of ceremonies would cost a wallet its own storage.
    pub fn install_escrow(
        &mut self,
        record: crate::types::EscrowRecord,
    ) -> Result<(), String> {
        if self.escrow(&record.escrow_key).is_some() {
            return Err("this escrow key already exists on this wallet".into());
        }
        // A repeated derivation context means a repeated delta, and two of this wallet's dealings on
        // one line determine that line. The wallet draws it fresh; this is what makes a failure to
        // do so loud rather than silent.
        if self
            .escrows
            .iter()
            .any(|e| !e.context_hex.is_empty() && e.context_hex == record.context_hex)
        {
            return Err(
                "an escrow was already minted under this derivation context; a repeat would put \
                 two of this wallet's dealings on one line"
                    .into(),
            );
        }
        if self.escrows.len() >= MAX_ESCROWS {
            return Err(format!("a wallet may hold at most {MAX_ESCROWS} escrows at once"));
        }
        self.escrows.push(record);
        Ok(())
    }

    /// Refuse a second DKG over a wallet that already has a key.
    ///
    /// `install_policy` overwrites unconditionally, so without this a second ceremony on the same
    /// tenant silently replaces the wallet's key — and everything held under the old one becomes
    /// unspendable, because 2-of-2 has no other way back.
    ///
    /// The runtime authenticates DKG, so the risk is the owner's own app — a re-run onboarding, a
    /// wiped local store — which is exactly the case where a refusal beats a quiet success.
    pub fn refuse_if_onboarded(&self) -> Result<(), Status> {
        if self.policy.key_package.is_some() {
            return Err(Status::failed_precondition(
                "this wallet already has a key; a second DKG would replace it and strand its funds",
            ));
        }
        Ok(())
    }

    // -------------------------------------------------------------------------------------------
    // In-band signing: FROST carried inside the Send and Renew streams
    // -------------------------------------------------------------------------------------------
    //
    // A send and a renewal both stop for the wallet to sign sighashes the cosigner built. They used
    // to do it by opening a *second* stream — a nested `Sign` per sighash, while the outer stream
    // sat parked waiting for the result. That worked against a native server running many streams
    // at once, and cannot work inside enclave-runtime, which runs **one request per tenant for the
    // whole life of a stream**: the outer stream holds the tenant, the nested one waits for it, and
    // nothing moves until the interaction deadline kills both. That was measured, not inferred — a
    // second call blocks on a separate TCP connection just the same, so a second channel does not
    // help either.
    //
    // So the round rides the stream it belongs to, and it gets cheaper for it. The nested form cost
    // two round trips per signature; this is one round trip for the whole batch, because the order
    // FROST needs is "both commitments before either share", not "the wallet commits first":
    //
    //   cosigner → sighashes + its commitment for each
    //   wallet   → its commitment + its share for each      (it has both commitments by now)
    //   cosigner → computes its shares, aggregates, carries on
    //
    // What the wallet gives up is seeing the finished signature, which it used to verify. That was
    // never the protection it looked like: a share is bound to one message and one pair of
    // commitments, so the cosigner cannot aggregate it over anything else — it would simply not
    // verify. And `aggregate` checks every share against its verifying share before summing, so a
    // bad wallet share is refused here rather than by the ASP.
    //
    // **Script-path only, by construction.** The taproot key-path tweak is compensated entirely on
    // the wallet's share, and the cosigner signs untweaked; a tweaked share would fail the share
    // check in `aggregate`. The cosigner only ever offers script-path sighashes on these streams,
    // so that is the right trade — but it is a property, not an accident.

    /// Round one, the cosigner's half: a fresh nonce for each message, and the commitment to it.
    ///
    /// The nonces stay in the returned [`InBandRound`], which the handler holds across the one round
    /// trip and hands back to [`Self::sign_in_band_finish`]. They are never persisted and never
    /// leave the handler's stack, so an interrupted round leaves nothing reusable behind.
    pub fn sign_in_band_begin(
        &self,
        messages: &[Vec<u8>],
    ) -> Result<(InBandRound, Vec<Commitment>), String> {
        let key_package = self.policy.key_package.as_ref().ok_or("no policy installed")?;
        Ok(in_band_begin(key_package, messages))
    }

    /// The same round one, for a key this cosigner holds that is NOT the wallet's.
    ///
    /// An escrow is a second 2-of-2 over a key of its own, and reclaiming from it is that key's
    /// pair signing — so the ceremony is identical and only the share differs.
    pub fn sign_in_band_begin_as(
        &self,
        key_package: &KeyPackage,
        messages: &[Vec<u8>],
    ) -> (InBandRound, Vec<Commitment>) {
        in_band_begin(key_package, messages)
    }

    /// Round two: the wallet's commitment and share for each message in, BIP-340 signatures out.
    ///
    /// [`WalletHalf`]s must be in the order the messages were — index `i` is a statement about
    /// message `i`, and nothing else ties them together. A count mismatch is refused outright,
    /// because a batch that is one short would otherwise sign every message against its
    /// neighbour's commitment and fail with an error that names the wrong one.
    ///
    /// Takes the round by value: every entry owns a single-use nonce.
    pub fn sign_in_band_finish(
        &self,
        round: InBandRound,
        wallet: Vec<WalletHalf>,
    ) -> Result<Vec<Vec<u8>>, String> {
        let policy = &self.policy;
        let (Some(key_package), Some(public_key_package)) =
            (&policy.key_package, &policy.public_key_package)
        else {
            return Err("no policy installed".into());
        };
        let user_identifier = policy
            .user_signing_identifier
            .as_ref()
            .ok_or("policy has no user_signing_identifier")?;
        in_band_finish(key_package, public_key_package, user_identifier, round, wallet)
    }

    /// Round two for a key that is not the wallet's. See [`Self::sign_in_band_begin_as`].
    pub fn sign_in_band_finish_as(
        &self,
        key_package: &KeyPackage,
        public_key_package: &PublicKeyPackage,
        counterparty: &Identifier,
        round: InBandRound,
        halves: Vec<WalletHalf>,
    ) -> Result<Vec<Vec<u8>>, String> {
        in_band_finish(key_package, public_key_package, counterparty, round, halves)
    }
}

/// Round one: a fresh nonce for each message, and the commitment to it.
///
/// Free of the wallet on purpose. The cosigner signs for more than one key — its own, and every
/// escrow it co-holds — and the ceremony does not differ between them, only the share does.
fn in_band_begin(key_package: &KeyPackage, messages: &[Vec<u8>]) -> (InBandRound, Vec<Commitment>) {
    let server_identifier = key_package.identifier.clone();
    let identifier_hex = hex::encode(server_identifier.serialize());

    let mut rng = OsRng;
    let mut ceremonies = Vec::with_capacity(messages.len());
    let mut commitments = Vec::with_capacity(messages.len());
    for message in messages {
        let nonce = nonce::new_nonce(&mut rng, &key_package.secret_share);
        commitments.push(Commitment {
            identifier_hex: identifier_hex.clone(),
            hiding: point::serialize_compressed(&nonce.commitments.hiding).to_vec(),
            binding: point::serialize_compressed(&nonce.commitments.binding).to_vec(),
        });
        let mut ceremony = Ceremony {
            message: message.clone(),
            ..Default::default()
        };
        ceremony
            .commitments
            .insert(server_identifier.clone(), nonce.commitments.clone());
        ceremony.nonce = Some(nonce);
        ceremonies.push(ceremony);
    }
    (InBandRound { ceremonies }, commitments)
}

/// Round two: the counterparty's commitment and share for each message in, signatures out.
fn in_band_finish(
    key_package: &KeyPackage,
    public_key_package: &PublicKeyPackage,
    counterparty: &Identifier,
    round: InBandRound,
    wallet: Vec<WalletHalf>,
) -> Result<Vec<Vec<u8>>, String> {
    {
        if wallet.len() != round.ceremonies.len() {
            return Err(format!(
                "the wallet answered {} of {} messages",
                wallet.len(),
                round.ceremonies.len()
            ));
        }
        let user_identifier = counterparty.clone();
        let server_identifier = key_package.identifier.clone();
        let policy = Shares {
            key_package,
            public_key_package,
        };

        round
            .ceremonies
            .into_iter()
            .zip(wallet)
            .enumerate()
            .map(|(i, (mut ceremony, half))| {
                let at = |e: String| format!("message {i}: {e}");

                ceremony.commitments.insert(
                    user_identifier.clone(),
                    SigningCommitments::from_bytes(&half.hiding, &half.binding)
                        .map_err(|e| at(e.to_string()))?,
                );
                let share_bytes: [u8; 32] = half
                    .share
                    .as_slice()
                    .try_into()
                    .map_err(|_| at("the wallet's share must be 32 bytes".into()))?;
                let user_share = scalar_from_bytes(&share_bytes)
                    .map_err(|e| at(format!("bad share scalar: {e}")))?;
                ceremony
                    .shares
                    .insert(user_identifier.clone(), SignatureShare { s: user_share });

                // Both commitments are in, so the binding factors are final and the cosigner's
                // share can be computed. Doing this any earlier would sign under a package missing
                // the wallet's commitment — valid-looking, and wrong.
                let package =
                    SigningPackage::new(ceremony.commitments.clone(), ceremony.message.clone());
                let nonce = ceremony
                    .nonce
                    .take()
                    .ok_or_else(|| at("the nonce was already spent".into()))?;
                let server_share = signing::sign(&package, &nonce, policy.key_package)
                    .map_err(|e| at(format!("frost sign: {e}")))?;
                ceremony.shares.insert(server_identifier.clone(), server_share);

                // `aggregate` verifies each share against its verifying share before summing, so a
                // wallet share that does not belong to this message and these commitments stops
                // here, with the index attached, instead of at the ASP with nothing to say.
                let signature =
                    signing::aggregate(&package, &ceremony.shares, policy.public_key_package)
                        .map_err(|e| at(format!("frost aggregate: {e}")))?;
                Ok(signature.serialize().to_vec())
            })
            .collect()
    }
}

/// The two halves of a key this cosigner signs with, so the body above reads the same whether it
/// is the wallet's key or an escrow's.
struct Shares<'a> {
    key_package: &'a KeyPackage,
    public_key_package: &'a PublicKeyPackage,
}

impl Cosigner {
    /// Open a send: build the off-chain send tx (after `GetInfo`) and hand back the session
    /// alongside the sighashes the client must FROST-sign. Nothing about it is stored here.
    pub fn send_open(
        &mut self,
        req: SendVtxoStep1,
        info: &ArkInfo,
    ) -> Result<(SendSession, u32, Vec<Vec<u8>>), String> {
        // `req.vtxos` is the caller's account of the set; `accept_vtxos` decides what of it this
        // wallet could actually own before any of it is selected from.
        self.accept_vtxos(req.vtxos.clone(), info)?;
        let total: u64 = req.vtxos.iter().map(|v| v.amount_sats).sum();
        if total < req.amount {
            return Err(format!(
                "insufficient balance: have {} sats, need {} sats",
                total, req.amount
            ));
        }
        let owner_pk_hex = match self.owner_pk_hex() {
            Ok(o) => o,
            Err(e) => return Err(e),
        };
        build_send(&owner_pk_hex, &req.vtxos, &req, info).map_err(|e| format!("build send: {e}"))
    }

    /// Insert the caller's signatures and hand back the transactions it must submit. It signs; the
    /// caller submits.
    pub fn send_prepare(
        &mut self,
        session: &mut SendSession,
        req: SendVtxoStep2,
    ) -> Result<(String, Vec<String>), String> {
        let signatures = sigs_from_wire(&req.signed_messages)?;
        session.sign_with_frost(signatures)?;
        session
            .prepare_submit()
            .map_err(|e| format!("prepare submit: {e}"))
    }

    /// Turn the ASP's signed checkpoints into the final ones the caller sends back as `FinalizeTx`.
    pub fn send_finalize(
        &mut self,
        session: &mut SendSession,
        signed_checkpoint_txs: &[String],
    ) -> Result<Vec<String>, String> {
        session
            .finalize_checkpoints(signed_checkpoint_txs)
            .map_err(|e| format!("finalize checkpoints: {e}"))
    }

    /// Close the send once the ASP has accepted it.
    ///
    /// Takes the session by value: it holds the half-signed transactions, so consuming it is what
    /// stops a second submit from reaching the same session. Only called after `FinalizeTx`
    /// succeeded, so nothing is recorded for a send the ASP never took.
    pub fn send_complete(
        &mut self,
        session: (SendSession, u32),
        ark_txid: String,
    ) -> SendVtxoSubmitted {
        let (mut session, change_exit_delay) = session;
        let change = session
            .change_vtxo()
            .map(|(txid, vout, amount)| (txid, vout, amount, change_exit_delay));
        session.mark_done();
        // The send spent all current VTXOs; re-add the change VTXO to the owned set, if any.
        // Expiry is unknown until the ASP indexes it, so 0 — `settle_deadline` reads that as
        // "unknown" and skips it conservatively rather than settling against a made-up deadline.
        let now = crate::store::now_secs();
        self.vtxos.clear();
        if let Some((txid, vout, amount, exit_delay)) = change.clone() {
            self.vtxos.push(VtxoEntry {
                txid,
                vout,
                amount,
                exit_delay,
                created_at: now,
                expires_at: 0,
            });
        }
        SendVtxoSubmitted { ark_txid, change }
    }

}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/// Build the off-chain send transactions (SendVtxoStep1): derive change address, run
/// `SendSession::build`, and return `(session, change_exit_delay, sighashes)`. Pure ark signing math
/// (no I/O); `info` comes from a prior gRPC `GetInfo`.
pub(crate) fn build_send(
    owner_pk_hex: &str,
    vtxos: &[VtxoInput],
    req: &SendVtxoStep1,
    info: &ArkInfo,
) -> Result<(SendSession, u32, Vec<Vec<u8>>), String> {
    if vtxos.is_empty() {
        return Err("no VTXOs to send".into());
    }
    let vtxo_inputs: Vec<SendVtxoInput> = vtxos
        .iter()
        .map(|v| SendVtxoInput {
            txid: v.txid.clone(),
            vout: v.vout,
            amount_sats: v.amount_sats,
            // Each input keeps its OWN delay; a boarding-settled VTXO and a
            // received one genuinely differ.
            exit_delay: v.exit_delay,
        })
        .collect();

    let total: u64 = vtxos.iter().map(|v| v.amount_sats).sum();
    if total < req.amount {
        return Err(format!(
            "insufficient balance: have {total}, need {}",
            req.amount
        ));
    }

    let network = ark::client::parse_network(&info.network)?;
    let change_exit_delay = info.unilateral_exit_delay as u32;
    let change_addr = if total > req.amount {
        Some(ark::client::ark_address(
            owner_pk_hex,
            &info.signer_pubkey,
            change_exit_delay,
            network,
        )?)
    } else {
        None
    };

    let (session, sighashes) = SendSession::build(
        owner_pk_hex,
        &vtxo_inputs,
        &req.recipient_ark_address,
        req.amount,
        change_addr.as_deref(),
        info,
    )?;
    Ok((
        session,
        change_exit_delay,
        sighashes.iter().map(|s| s.to_vec()).collect(),
    ))
}

use crate::types::SendVtxoStep2;

pub(crate) fn sigs_from_wire(wire: &[Vec<u8>]) -> Result<Vec<[u8; 64]>, String> {
    wire.iter()
        .map(|v| {
            <[u8; 64]>::try_from(v.as_slice()).map_err(|_| "signature must be 64 bytes".to_string())
        })
        .collect()
}

use bitcoin::hashes::Hash;
use bitcoin::sighash::{Prevouts, SighashCache};
use bitcoin::{TapLeafHash, TapSighashType};



/// the script-path sighash of the `ark_tx` input that spends an
/// OUTPUT of the verified `checkpoint_tx`. We don't re-derive ark-core's protocol; we CHAIN leg 2
/// to leg 1 — the `ark_tx` input's prevout must be an output of the same checkpoint leg 1 verified
/// spends the eVTXO. That binds the bundle to the eVTXO. The checkpoint output is `V`+server and
/// arkd validates the ark_tx independently, so taking the leaf from the PSBT is safe.
pub fn build_arktx_sighash(checkpoint_tx: &[u8], ark_tx: &[u8]) -> Result<[u8; 32], String> {
    let cp = bitcoin::Psbt::deserialize(checkpoint_tx)
        .map_err(|e| format!("checkpoint not a PSBT: {e}"))?;
    let at = bitcoin::Psbt::deserialize(ark_tx).map_err(|e| format!("ark_tx not a PSBT: {e}"))?;
    let cp_txid = cp.unsigned_tx.compute_txid();

    let prevouts: Vec<bitcoin::TxOut> = at
        .inputs
        .iter()
        .map(|i| {
            i.witness_utxo
                .clone()
                .ok_or_else(|| "ark_tx input missing witness_utxo".to_string())
        })
        .collect::<Result<_, _>>()?;

    let idx = at
        .unsigned_tx
        .input
        .iter()
        .enumerate()
        .find_map(|(i, txin)| {
            if txin.previous_output.txid != cp_txid {
                return None;
            }
            let cp_out = cp
                .unsigned_tx
                .output
                .get(txin.previous_output.vout as usize)?;
            (prevouts.get(i)?.script_pubkey == cp_out.script_pubkey).then_some(i)
        })
        .ok_or("ark_tx does not spend the verified checkpoint's output")?;

    let input = &at.inputs[idx];
    let leaf_hash = input
        .tap_script_sigs
        .keys()
        .next()
        .map(|(_, lh)| *lh)
        .or_else(|| {
            input
                .tap_scripts
                .values()
                .next()
                .map(|(script, ver)| TapLeafHash::from_script(script, *ver))
        })
        .ok_or("ark_tx input has no tap leaf")?;

    let sighash = SighashCache::new(&at.unsigned_tx)
        .taproot_script_spend_signature_hash(
            idx,
            &Prevouts::All(&prevouts),
            leaf_hash,
            TapSighashType::Default,
        )
        .map_err(|e| format!("ark_tx sighash: {e}"))?;
    Ok(sighash.to_byte_array())
}

impl Cosigner {

}
