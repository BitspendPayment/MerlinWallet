//! The cosigner: the signing keys, the Ark sessions and the ASP connection for the one wallet this
//! process serves. Its FROST rounds are `crate::sign`'s.

use std::sync::Arc;

use serde::{Deserialize, Serialize};
use zeroize::Zeroizing;

use crate::escrow::{EscrowSession, Reclaim};
use crate::grpc::Status;
use crate::sign::SigningKey;

use crate::types::{
    Admission, BoardingSettleSubmitted, ReleaseRecord,
    SendVtxoStep1, SnapshotState, VtxoEntry, VtxoInput,
};

use ark::client::batch::{DelegateSettleSession, PersistedDelegate};
use ark::client::send::{SendSession, SendVtxoInput};
use ark::client::types::ArkInfo;

use threshold::identifier::Identifier;
use threshold::keys::{KeyPackage, PublicKeyPackage};

use crate::asp::{AspApi, EventSource};
use crate::boarding::BoardingSettleSession;
use crate::host::valid_task_id;
use crate::renew::{AspCall, RenewSession, RenewStep};
use crate::store::Store;

/// How many escrows one wallet may hold. Each is a key to co-sign for and a pairing to answer for,
/// and the seal is rewritten in full on every change.
///
/// ponytail: for the wallet's life — one escrow per payment, and none is forgotten, because the
/// cosigner cannot see one emptied and what is left in it stays its owner's to take back. Forget an
/// escrow once a reclaim of it has finalized when this bites.
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
// [`Cosigner::run_task_with`].
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
/// Byte-sliced, so only a string that IS hex may be sliced: a release request names an escrow by
/// this, and a multibyte character in the first two bytes would otherwise panic the guest on its
/// say-so.
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

pub struct Cosigner {
    key: GroupKey,
    /// The wallet's delegate, and whether its round is running.
    pub(crate) renew_session: Option<RenewSession>,
    /// In-flight boarding settle, held across the commitment-FROST pause. Transient — never
    /// snapshotted.
    pub(crate) boarding_session: Option<BoardingSettleSession>,
    /// The escrows this wallet has minted, each with its deal. See `SnapshotState::escrows`.
    escrows: Vec<EscrowSession>,
    /// Where the seal lives.
    pub(crate) store: Arc<Store>,
    /// The runtime this cosigner runs inside: its task queue and its push channel. `Detached` when
    /// it runs as a plain process, where every call fails rather than quietly doing nothing.
    pub(crate) host: Arc<dyn crate::host::Host>,
    /// The name the seal is filed under — configuration, and not the wallet's group key, which is
    /// `key.group_key`. See `main.rs`.
    pub(crate) group_key: String,
    /// The owned VTXO set. `VtxoEntry` carries the expiry a delegate's renewal deadline is
    /// computed from; callers wanting the ark-facing shape go through [`Self::vtxos()`].
    pub(crate) vtxos: Vec<VtxoEntry>,
}

impl Cosigner {
    /// Load this cosigner's state, then hand back something callable, running inside [host] —
    /// `crate::host::Detached` when there is no runtime.
    ///
    /// Eagerly, not on first use: per-request there is no later use to amortise a lazy restore
    /// into. Storage is the whole of the state — read on entry, sealed on mutation.
    ///
    /// No seal yet is not an error. Before onboarding there is nothing to read, and DKG is what
    /// writes the first one.
    pub fn open(
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

    fn new(store: Arc<Store>, group_key: String, host: Arc<dyn crate::host::Host>) -> Self {
        Self {
            key: GroupKey::default(),
            renew_session: None,
            boarding_session: None,
            escrows: Vec::new(),
            store,
            host,
            group_key,
            vtxos: Vec::new(),
        }
    }

    /// Serialize durable state (the wallet's key, VTXOs, delegate, escrows) into the
    /// sealed-snapshot blob. In-flight sessions are excluded (transient; MuSig2 nonces must never
    /// persist).
    pub fn to_snapshot(&self) -> Result<Vec<u8>, String> {
        let key = &self.key;
        let (Some(group_key), Some(key_package), Some(public_key_package)) =
            (&key.group_key, &key.key_package, &key.public_key_package)
        else {
            return Err("no key to snapshot".into());
        };
        let snap = SnapshotState {
            group_key: group_key.clone(),
            key_package_json: key_package.to_json(),
            public_key_package_json: public_key_package.to_json(),
            user_signing_identifier_hex: key
                .user_signing_identifier
                .as_ref()
                .map(|id| hex::encode(id.serialize())),
            ark_cosigner_secret_hex: None,
            wallet_dealt_share_hex: key
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
        self.key = GroupKey {
            group_key: Some(snap.group_key),
            key_package: Some(key_package),
            public_key_package: Some(public_key_package),
            user_signing_identifier,
            wallet_dealt_share_hex: snap.wallet_dealt_share_hex.map(Zeroizing::new),
        };
        self.vtxos = snap.vtxos;
        self.escrows = snap.escrows;
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
    pub fn generate_delegate(
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

    /// Seal, and say whether it took. For a change that must not be acted on unless it is durable:
    /// a release signed but not written down is a payment that can be asked for again, and a key
    /// announced but not written down is one a wallet funds and the cosigner then forgets.
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

    /// The wallet's group x-only pubkey (hex) — the VTXO owner key, from the installed key's PKP.
    pub fn owner_pk_hex(&self) -> Result<String, String> {
        let pkp = self.key.public_key_package.as_ref().ok_or("this wallet has no key yet")?;
        let vk = pkp.verifying_key.serialize(); // [u8; 33]
        Ok(hex::encode(&vk[1..]))
    }

    /// Install the wallet's key as DKG left it: this cosigner's share, the group's public package,
    /// the owner's identifier, and the half of the owner's share this cosigner dealt.
    pub fn install_key(
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
        self.key = GroupKey {
            group_key: Some(group_key),
            key_package: Some(key_package),
            public_key_package: Some(public_key_package),
            user_signing_identifier,
            wallet_dealt_share_hex: wallet_dealt_share_hex.map(Zeroizing::new),
        };
        Ok(())
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
    /// not a ceremony: nothing is installed, no key is written, no share is re-keyed. A recovery
    /// that re-keyed would strand the VTXOs, the delegate and the escrows the seal already holds —
    /// which is exactly the accident `refuse_if_onboarded` exists to prevent, and this is its mirror
    /// image: that one refuses when a key exists, this one refuses when none does.
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
        let public_key_package_json =
            self.key.public_key_package.as_ref().map(PublicKeyPackage::to_json);
        let (group_key, public_key_package_json) =
            match (self.key.group_key.clone(), public_key_package_json) {
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
            escrows: self.escrows.iter().map(|e| e.summary(now)).collect(),
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
        if self.key.group_key.is_none() {
            return Err(Status::failed_precondition(
                "this wallet has no key yet: there is nothing to recover, create one instead",
            ));
        }

        let expected = self.key.user_signing_identifier.clone().ok_or_else(|| {
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

        self.key
            .wallet_dealt_share_hex
            .as_deref()
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

    // --- Escrows ---------------------------------------------------------------------------------
    //
    // A second 2-of-2 over a key of its own, minted by a reshare — see `crate::escrow`. What is
    // done to one escrow is its `EscrowSession`'s; what is here looks across all of them: the
    // release ledger, the seal, and the cap.

    /// The runtime this instance is running inside.
    ///
    /// Cloned out rather than borrowed so a caller can hold it across an await without holding the
    /// wallet's lock — which matters for the one thing it is used for here: opening a connection
    /// and waiting for the runtime to dial it.
    pub fn host(&self) -> Arc<dyn crate::host::Host> {
        self.host.clone()
    }

    /// The escrows this wallet holds, oldest first.
    pub fn list_escrow_sessions(&self) -> &[EscrowSession] {
        &self.escrows
    }

    /// One escrow, comparing x-only so either parity resolves.
    pub fn get_escrow_session(&self, escrow_key: &str) -> Option<&EscrowSession> {
        let want = x_only(escrow_key);
        self.escrows.iter().find(|e| x_only(&e.escrow_key) == want)
    }

    /// One escrow, to act on — see [`EscrowSession`] for what it does.
    pub fn escrow_mut(&mut self, escrow_key: &str) -> Result<&mut EscrowSession, String> {
        let want = x_only(escrow_key);
        self.escrows
            .iter_mut()
            .find(|e| x_only(&e.escrow_key) == want)
            .ok_or_else(|| "this wallet holds no such escrow".into())
    }

    /// May this release be answered at all, and has it been answered already?
    ///
    /// Four questions, and each is a different refusal:
    ///
    /// 1. **Has this payment already justified a release?** A replayed authorization verifies every
    ///    time, because it really did succeed — so what stops it paying twice is this ledger. It is
    ///    the wallet's, over every escrow: a wallet holds one escrow per payment, often to the same
    ///    payee, and the next one must not be able to spend what an earlier one already did.
    /// 2. **Is this a repeat of the request we answered for it?** Then the answer must be the same
    ///    answer — [`Admission::AlreadyAnswered`], sign again and count nothing. A repeat that is a
    ///    *different* release, or that comes from a different escrow, is refused.
    /// 3. **Has this request id already been answered, for some other payment?** The lookup above
    ///    is by payment, so a repeat that changed its reference would miss it and be admitted as
    ///    new — leaving one request id naming two approved releases, and a requester correlating
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
        let released = self
            .escrows
            .iter()
            .find_map(|e| e.releases().get(reference).map(|record| (e, record)));
        if let Some((escrow, record)) = released {
            if x_only(&escrow.escrow_key) != x_only(escrow_key) {
                return Err(
                    "that payment has already been released against, by another escrow of this \
                     wallet: evidence that a payment succeeded stays true, so it may justify one \
                     release and no more"
                        .into(),
                );
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
        // Scoped to the escrow, so two requesters that both like the name "1" do not collide: a
        // request id is the REQUESTER's key, and each escrow has one requester.
        //
        // A scan rather than a second map, deliberately. The ledger is capped, this runs once per
        // release, and one source of truth cannot drift out of step with itself — which is exactly
        // what an index maintained beside it could do.
        if let Some((reference, record)) = self
            .get_escrow_session(escrow_key)
            .into_iter()
            .flat_map(|e| e.releases())
            .find(|(_, r)| r.request_id == request_id)
        {
            return Err(format!(
                "request {request_id} was already answered, against payment {reference}, and that \
                 answer paid {} sats; a different release needs a different request id",
                record.sats
            ));
        }
        if self.release_count() >= MAX_RELEASED_REFERENCES {
            return Err(format!(
                "this wallet has released against {MAX_RELEASED_REFERENCES} payments and cannot \
                 remember another; past that it could not tell a repeat from a new one, so it \
                 releases nothing more"
            ));
        }
        Ok(Admission::New)
    }

    /// How many payments this wallet has released against, across every escrow.
    pub fn release_count(&self) -> usize {
        self.escrows.iter().map(|e| e.releases().len()).sum()
    }

    /// Write a release into its escrow's record and seal it — or, if the seal cannot be written,
    /// put the wallet back as it was and say so.
    ///
    /// Before it is signed, always: the ledger is the only thing that stops a payment paying twice,
    /// and every request reopens from the seal, so a release signed before its record was durable
    /// is one the next instance has never heard of. Rolled back on failure so this instance does
    /// not go on believing something the seal does not. The release is refused and asked for
    /// again; a retry of a release that WAS recorded is answered again from the record, so nothing
    /// is lost by refusing here.
    pub fn seal_release(
        &mut self,
        escrow_key: &str,
        reference: String,
        record: ReleaseRecord,
    ) -> Result<(), String> {
        let before = self.to_snapshot()?;
        // Kept with the escrow, for as long as the wallet holds it: the payment is spent for good.
        self.escrow_mut(escrow_key)?.record_release(reference, record)?;
        if let Err(e) = self.try_seal() {
            if let Err(undo) = self.restore_snapshot(&before) {
                tracing::error!("rolling back an unsealed release failed too: {undo}");
            }
            return Err(format!(
                "this release could not be written down, so it was not signed: {e}"
            ));
        }
        Ok(())
    }

    /// Record a freshly minted escrow. Refuses a duplicate key and refuses past the cap.
    ///
    /// The cap is not ceremony: every escrow is a standing obligation — a pairing to answer for, a
    /// deal to time out — and the seal is re-serialized in full on every mutation, so an unbounded
    /// run of ceremonies would cost a wallet its own storage.
    pub fn add_escrow(&mut self, record: EscrowSession) -> Result<(), String> {
        if self.get_escrow_session(&record.escrow_key).is_some() {
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
            return Err(format!("a wallet may hold at most {MAX_ESCROWS} escrows"));
        }
        self.escrows.push(record);
        Ok(())
    }

    /// Refuse a second DKG over a wallet that already has a key.
    ///
    /// `install_key` overwrites unconditionally, so without this a second ceremony on the same
    /// tenant silently replaces the wallet's key — and everything held under the old one becomes
    /// unspendable, because 2-of-2 has no other way back.
    ///
    /// The runtime authenticates DKG, so the risk is the owner's own app — a re-run onboarding, a
    /// wiped local store — which is exactly the case where a refusal beats a quiet success.
    pub fn refuse_if_onboarded(&self) -> Result<(), Status> {
        if self.key.key_package.is_some() {
            return Err(Status::failed_precondition(
                "this wallet already has a key; a second DKG would replace it and strand its funds",
            ));
        }
        Ok(())
    }

    /// The wallet's own key, for a [`SigningSession`](crate::sign::SigningSession) to sign with.
    pub fn signing_key(&self) -> Result<SigningKey, String> {
        let key = &self.key;
        let (Some(key_package), Some(public_key_package)) =
            (&key.key_package, &key.public_key_package)
        else {
            return Err("this wallet has no key yet".into());
        };
        let counterparty = key
            .user_signing_identifier
            .clone()
            .ok_or("this wallet's key has no owner identifier")?;
        Ok(SigningKey {
            key_package: key_package.clone(),
            public_key_package: public_key_package.clone(),
            counterparty,
        })
    }
}

// --- Taking back what is left ----------------------------------------------------------------
//
// What needs the whole wallet: its own address, and the dealt share. What one escrow decides for
// itself is its `EscrowSession`'s — see `crate::escrow`.

impl Cosigner {
    /// Build the reclaim of [escrow_key]'s escrow, or say why there is not one to build — see
    /// [`EscrowSession::prepare_reclaim`]. What belongs to the wallet comes from here: where the
    /// money goes, and the half of the owner's share this cosigner dealt.
    pub fn prepare_reclaim(
        &self,
        escrow_key: &str,
        vtxos: Vec<VtxoInput>,
        info: &ArkInfo,
        now: i64,
    ) -> Result<Reclaim, Status> {
        let escrow = self
            .get_escrow_session(escrow_key)
            .ok_or_else(|| Status::not_found("this wallet holds no such escrow"))?;

        let wallet_id_bytes = hex::decode(&escrow.wallet_identifier_hex)
            .map_err(|e| Status::internal(format!("sealed wallet identifier is not hex: {e}")))?;
        // Answered only to the identifier the ceremony recorded — the same rule every other stream
        // applies, reached through the same function.
        let wallet_dealt_share = self.dealt_share_for(&wallet_id_bytes)?;

        // Where it goes: the wallet's own address, from the wallet's own key. Not on the wire.
        let owner_pk_hex = self.owner_pk_hex().map_err(Status::internal)?;
        let network = ark::client::parse_network(&info.network).map_err(|e| {
            Status::invalid_argument(format!("the ASP names a network we do not know: {e}"))
        })?;
        let to_ark_address = ark::client::ark_address(
            &owner_pk_hex,
            &info.signer_pubkey,
            info.unilateral_exit_delay as u32,
            network,
        )
        .map_err(|e| Status::internal(format!("deriving where this wallet is paid: {e}")))?;

        escrow.prepare_reclaim(vtxos, info, now, to_ark_address, wallet_dealt_share)
    }
}

impl Cosigner {
    /// Open a send: build the off-chain send tx (after `GetInfo`) and hand back the session
    /// alongside the sighashes the client must FROST-sign. Nothing about it is stored here.
    pub fn create_send_session(
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
        let owner_pk_hex = self.owner_pk_hex()?;
        build_send(&owner_pk_hex, &req.vtxos, &req, info).map_err(|e| format!("build send: {e}"))
    }

    /// Close the send once the ASP has accepted it: the owned set becomes its change, and the
    /// delegate goes.
    ///
    /// Takes the session by value: it holds the half-signed transactions, so consuming it is what
    /// stops a second submit from reaching the same session. Only called after `FinalizeTx`
    /// succeeded, so nothing is recorded for a send the ASP never took.
    pub fn finalise_send_session(&mut self, mut session: SendSession, change_exit_delay: u32) {
        let change = session
            .change_vtxo()
            .map(|(txid, vout, amount)| (txid, vout, amount, change_exit_delay));
        session.mark_done();
        // The send spent all current VTXOs; re-add the change VTXO to the owned set, if any.
        // Expiry is unknown until the ASP indexes it, so 0 — `settle_deadline` reads that as
        // "unknown" and skips it conservatively rather than settling against a made-up deadline.
        let now = crate::store::now_secs();
        self.vtxos.clear();
        if let Some((txid, vout, amount, exit_delay)) = change {
            self.vtxos.push(VtxoEntry {
                txid,
                vout,
                amount,
                exit_delay,
                created_at: now,
                expires_at: 0,
            });
        }
        // The send spent what the sealed delegate was signed over, so it can never settle now.
        // Dropping it makes the settle watch find nothing on its next run and cancel itself.
        self.renew_session = None;
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

/// Put the wallet's signatures, as the wire carried them, into [session], and hand back what the
/// caller submits: the ark tx and its checkpoints. The cosigner signs; the caller submits.
pub(crate) fn sign_and_prepare(
    session: &mut SendSession,
    signatures: &[Vec<u8>],
) -> Result<(String, Vec<String>), String> {
    session.sign_with_frost(crate::util::sigs_from_wire(signatures)?)?;
    session.prepare_submit().map_err(|e| format!("prepare submit: {e}"))
}
