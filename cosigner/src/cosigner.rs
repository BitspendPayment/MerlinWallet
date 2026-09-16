//! The cosigner: the signing keys, the FROST ceremony, the Ark sessions and the ASP connection for
//! the one wallet this process serves.
//!
//! It was an actor — a struct behind a mailbox, driven by a `run_cosigner` task that processed
//! `CosignerCommand`s serially for one of many tenants. Nothing routes to it any more, so the
//! channel, the commands and the loop are gone and callers hold it directly. What that removes is
//! not only indirection: a ceremony no longer has to be split across two messages to avoid blocking
//! the loop, so a FROST nonce can live on a stream handler's stack instead of being parked here.

use std::collections::BTreeMap;
use std::sync::Arc;

use rand::rngs::OsRng;
use zeroize::Zeroizing;

use crate::grpc::Status;

use crate::handlers;

use crate::types::{
    ApplyDelegateSigs, BoardingSettleSubmitted, Commitment,
    Contact, IntentStatus, PaymentIntent,
    SendVtxoStep1, SendVtxoSubmitted, SignStep1, SignStep1Out, SignStep2,
    SignStep2Out, SnapshotState, VtxoEntry, VtxoInput,
};

use ark::client::batch::{DelegateSettleSession, PersistedDelegate};
use ark::client::send::{SendSession, SendVtxoInput};
use ark::client::types::ArkInfo;

use threshold::commitment::SigningPackage;
use threshold::identifier::Identifier;
use threshold::keys::{KeyPackage, PublicKeyPackage};
use threshold::nonce::{self, SigningCommitments, SigningNonce};
use threshold::point;
use threshold::scalar::{scalar_from_bytes, scalar_to_bytes};
use threshold::signing::{self, SignatureShare};

use crate::store::Store;

const THRESHOLD_COUNT: usize = 2;

// Request-to-pay bounds. Contacts + intents live in the sealed snapshot, which is re-serialized
// in full on every mutation — so an allowlisted peer must not be able to grow it without limit.
const MAX_CONTACTS: usize = 256;
const MAX_LABEL_LEN: usize = 64;
const MAX_MEMO_LEN: usize = 140;
const MAX_PENDING_INTENTS: usize = 50;
const MAX_PENDING_INTENTS_PER_CONTACT: usize = 3;
const DEFAULT_INTENT_TTL_SECS: i64 = 24 * 60 * 60;
const MAX_INTENT_TTL_SECS: i64 = 7 * 24 * 60 * 60;
/// How long a declined/fulfilled/expired intent lingers so the payer can still see it.
const TERMINAL_INTENT_RETENTION_SECS: i64 = 24 * 60 * 60;

/// Clamp a peer-supplied string to `max` CHARACTERS (not bytes — never split a UTF-8 sequence).
fn truncate(s: String, max: usize) -> String {
    if s.chars().count() <= max {
        s
    } else {
        s.chars().take(max).collect()
    }
}

/// An installed signing policy. The cosigner's own key share + the group public key, plus the
/// client's FROST identifier (the other half of the 2-of-2).
struct Policy {
    group_key: String,
    key_package: KeyPackage,
    public_key_package: PublicKeyPackage,
    user_signing_identifier: Option<Identifier>,
}

/// In-flight FROST ceremony state (cleared between rounds).
#[derive(Default)]
pub struct Ceremony {
    message: Vec<u8>,
    commitments: BTreeMap<Identifier, SigningCommitments>,
    shares: BTreeMap<Identifier, SignatureShare>,
    /// The cosigner's single-use nonce for this round (set in step1, consumed in step2).
    nonce: Option<SigningNonce>,
    /// The full transaction being signed, carried from the open. NOTHING READS IT. It fed the
    /// contract gate in `sign_finish`, which went with the contract layer, and it is kept because
    /// it is exactly what a policy has to see: the bytes the signature will authorize, rather than
    /// the sighash alone. The policy IR is what makes it live again.
    #[allow(dead_code)]
    full_transaction: Vec<u8>,
}

/// A FROST round the cosigner is halfway through, for every sighash in one batch.
///
/// Held by the `Send` or `Settle` handler across a single round trip, and consumed by
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
    policy: Option<Policy>,
    /// A `ReadyToSettle` delegate session the core can drive autonomously (auto-settle).
    pub(crate) delegate_session: Option<DelegateSettleSession>,
    /// In-flight GUEST-style boarding settle, held across the commitment-FROST pause (the client
    /// must FROST-sign the commitment sighashes between step 2 and step 3). Native: no held stream
    /// (step 3 finalizes optimistically). Transient — never snapshotted.
    pub(crate) boarding_settle: Option<BoardingSettleInFlight>,
    /// The settle the caller is driving: which FROST round is open, the registered intent id, and
    /// the ASP parameters it supplied. See [`crate::settle`].
    pub(crate) settle_inflight: Option<crate::handlers::settle::InFlight>,
    /// The Ark cosigner (MuSig2) secret, hex — zeroized on drop. Used for tree signing.
    ark_cosigner_secret_hex: Option<Zeroizing<String>>,
    /// Parties authorized to bill this wallet — the only authorization for an incoming request.
    contacts: Vec<Contact>,
    /// Request-to-pay records held for the payer (bounded; see `prune_intents`).
    payment_intents: Vec<PaymentIntent>,
    /// See `SnapshotState::seen_request_nonces`.
    pub(crate) seen_request_nonces: BTreeMap<String, i64>,
    /// Global services (contract gate + ASP url). Held so `command()` is a drop-in for the old
    /// `GuestInstance::command` — no per-call-site `store` threading.
    pub(crate) store: Arc<Store>,
    /// The runtime this cosigner runs inside: its task queue and its push channel. `Detached` when
    /// it runs as a plain process, where every call fails rather than quietly doing nothing.
    pub(crate) host: Arc<dyn crate::host::Host>,
    /// This user's public projection (VTXOs / history / device tokens / policy metadata). The
    /// non-signing query + stream + inbox handlers are `impl Cosigner` methods over it.
    /// The group key this cosigner serves. Configuration, not something a caller names.
    pub(crate) group_key: String,
    /// The owned VTXO set — the ONE set.
    ///
    /// There were two until recently: a `Vec<VtxoInput>` in the seal that `send_open` selected
    /// from, and this one, loaded from storage and written by boarding and sending. They never
    /// synced, so a freshly boarded VTXO was invisible to a send. `VtxoEntry` is the superset —
    /// it carries the expiry a delegate's renewal deadline is computed from — so it is the one
    /// that survives, and callers wanting the ark-facing shape go through [`Self::vtxos`].
    pub(crate) owned_vtxos: Vec<VtxoEntry>,
}

/// In-flight boarding settle, held across the commitment-FROST pause — the caller FROST-signs the
/// commitment sighashes between one relayed ASP event and the next, and this is what waits.
///
/// It used to carry the ASP event stream too, from when the cosigner held that connection itself.
/// It cannot: a guest has no egress at all, so the caller subscribes and relays each event in, and
/// the field had one writer, no readers, and a doc comment describing a design that was already
/// gone.
pub struct BoardingSettleInFlight {
    pub session: ark::client::batch::SettleSession,
    pub signer: ark::client::batch::BoardingTreeSigner,
    pub amount_sats: u64,
    /// Boarding exit delay, carried through to the finalized VTXO entry the host persists.
    pub exit_delay: u32,
}

impl Cosigner {
    /// Load this cosigner's state, then hand back something callable.
    ///
    /// Eagerly, not on first use. A lazy restore amortises the read across a process that outlives
    /// many requests, which is the shape being removed: per-request there is no later use to
    /// amortise into. Storage is the whole of the state — read on entry, sealed on mutation.
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
        crate::store::restore_snapshot(&mut cosigner, &store, &group_key);
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
            policy: None,
            delegate_session: None,
            boarding_settle: None,
            settle_inflight: None,
            ark_cosigner_secret_hex: None,
            contacts: Vec::new(),
            payment_intents: Vec::new(),
            seen_request_nonces: BTreeMap::new(),
            store,
            host,
            group_key,
            owned_vtxos: Vec::new(),
        }
    }

    /// Serialize durable state (policy + Ark secret + VTXOs + history) into the sealed-snapshot blob.
    /// In-flight sessions are excluded (transient; MuSig2 nonces must never persist).
    pub fn to_snapshot(&self) -> Result<Vec<u8>, String> {
        let policy = self.policy.as_ref().ok_or("no policy to snapshot")?;
        let snap = SnapshotState {
            group_key: policy.group_key.clone(),
            key_package_json: policy.key_package.to_json(),
            public_key_package_json: policy.public_key_package.to_json(),
            user_signing_identifier_hex: policy
                .user_signing_identifier
                .as_ref()
                .map(|id| hex::encode(id.serialize())),
            ark_cosigner_secret_hex: self.ark_secret().map(|s| s.to_string()),
            vtxos: self.owned_vtxos.clone(),
            // Persist a ReadyToSettle delegate (to_persisted errors for other phases → None).
            delegate_json: self
                .delegate_session
                .as_ref()
                .and_then(|s| s.to_persisted().ok())
                .and_then(|p| serde_json::to_string(&p).ok()),
            contacts: self.contacts.clone(),
            payment_intents: self.payment_intents.clone(),
            seen_request_nonces: self.seen_request_nonces.clone(),
        };
        serde_json::to_vec(&snap).map_err(|e| format!("snapshot serialize: {e}"))
    }

    /// Restore durable state from a snapshot blob (on actor spawn / reseat).
    pub fn restore_snapshot(&mut self, blob: &[u8]) -> Result<(), String> {
        let snap: SnapshotState =
            serde_json::from_slice(blob).map_err(|e| format!("snapshot deserialize: {e}"))?;
        let key_package = KeyPackage::from_json(&snap.key_package_json)
            .map_err(|e| format!("bad key package: {e}"))?;
        let public_key_package = PublicKeyPackage::from_json(&snap.public_key_package_json)
            .map_err(|e| format!("bad public key package: {e}"))?;
        let user_signing_identifier = match snap.user_signing_identifier_hex {
            Some(h) => Some(parse_identifier_hex(&h)?),
            None => None,
        };
        self.policy = Some(Policy {
            group_key: snap.group_key,
            key_package,
            public_key_package,
            user_signing_identifier,
        });
        self.ark_cosigner_secret_hex = snap.ark_cosigner_secret_hex.map(Zeroizing::new);
        self.owned_vtxos = snap.vtxos;
        self.contacts = snap.contacts;
        self.payment_intents = snap.payment_intents;
        self.seen_request_nonces = snap.seen_request_nonces;
        // Restore a pending ReadyToSettle delegate (needs the cosigner secret to re-derive its kp).
        self.delegate_session = match (snap.delegate_json, self.ark_secret()) {
            (Some(dj), Some(secret)) => {
                let persisted: PersistedDelegate = serde_json::from_str(&dj)
                    .map_err(|e| format!("parse persisted delegate: {e}"))?;
                Some(DelegateSettleSession::from_persisted(&persisted, secret)?)
            }
            _ => None,
        };
        Ok(())
    }

    /// The MuSig2 secret (hex), if installed.
    pub(crate) fn ark_secret(&self) -> Option<&str> {
        self.ark_cosigner_secret_hex.as_ref().map(|z| z.as_str())
    }

    pub fn ark_cosigner_secret_hex(&self) -> Option<&str> {
        self.ark_secret()
    }

    /// Take the caller's account of what this wallet holds.
    ///
    /// The cosigner learned its VTXO set from an ASP subscription it no longer runs, so a VTXO
    /// received from another wallet had no way in and could never be spent. The caller supplies
    /// them now, which means saying exactly what is and is not trusted here.
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
            // Expiry is the ASP's and is not on the wire; 0 reads as "unknown" downstream, which
            // `build_delegate_step1` skips conservatively rather than settling against a guess.
            accepted.push(VtxoEntry {
                txid: v.txid,
                vout: v.vout,
                amount: v.amount_sats,
                exit_delay: v.exit_delay,
                created_at: now,
                expires_at: 0,
            });
        }
        self.owned_vtxos = accepted;
        Ok(())
    }

    /// The owned set in the shape ark's session builders take. Expiry is dropped here because
    /// nothing downstream of a send or a settle build uses it.
    pub fn vtxos(&self) -> Vec<VtxoInput> {
        self.owned_vtxos
            .iter()
            .map(|e| VtxoInput {
                txid: e.txid.clone(),
                vout: e.vout,
                amount_sats: e.amount,
                exit_delay: e.exit_delay,
            })
            .collect()
    }

    /// The VTXO set to refresh and the renewal deadline the delegate becomes valid at.
    pub fn prepare_delegate(
        &self,
    ) -> Result<(Vec<VtxoInput>, Option<u64>), Status> {
        handlers::ark_send::build_delegate_step1(&self.owned_vtxos, &self.store)
    }

    /// Seal this actor's state. Storage is the whole of the persistence now, so a method that
    /// mutates durable state seals here rather than trusting its caller to remember.
    pub fn seal(&mut self) {
        let store = self.store.clone();
        let group_key = self.group_key.clone();
        crate::store::seal_snapshot(self, &store, &group_key);
    }

    /// Record a settled boarding output: replace it in the owned set with the VTXO it became, and
    /// hand back the commitment txid.
    pub fn apply_boarding_settle(&mut self, sub: BoardingSettleSubmitted) -> String {
        let now = crate::store::now_secs();
        self.owned_vtxos
            .retain(|e| !(e.txid == sub.vtxo_txid && e.vout == sub.vtxo_vout));
        self.owned_vtxos.push(VtxoEntry {
            txid: sub.vtxo_txid.clone(),
            vout: sub.vtxo_vout,
            amount: sub.amount_sats,
            exit_delay: sub.exit_delay,
            created_at: now,
            expires_at: 0,
        });
        sub.commitment_txid
    }

    /// Record a completed send: mirror it into the owned history, update the host projection for
    /// live queries, and mark any outstanding request the tx satisfies as paid. Matched on the
    /// STORED intent's destination + amount, so the seal stays the authority and the client never
    /// says which request it is paying.
    pub fn apply_send(
        &mut self,
        req: &crate::wallet_proto::SendVtxoRequest,
        submitted: SendVtxoSubmitted,
    ) -> crate::wallet_proto::SendVtxoResponse {
        let SendVtxoSubmitted { ark_txid, change } = submitted;
        let resp = crate::handlers::ark_send::apply_send_result(
            &mut self.owned_vtxos,
            ark_txid.clone(),
            change,
        );
        // The send spent what the sealed delegate was signed over, so it can never settle now.
        //
        // This used to be attempted in `apply_send_result` by deleting `delegate_sessions` and
        // `guest_delegate_thresholds` rows keyed by the caller's id — two store trees nothing has
        // written since the delegate moved into the seal. The deletes did nothing, and the real
        // delegate outlived every send: still sealed, still over spent inputs, and still what the
        // settle watch would wake the owner about. Dropping it here makes the watch find nothing on
        // its next run and cancel itself, which is the path that already existed for exactly this.
        self.delegate_session = None;
        if let Some(id) =
            self.fulfil_matching_intent(&req.recipient_ark_address, req.amount, &ark_txid)
        {
            tracing::info!("payment request {id} fulfilled by {ark_txid}");
        }
        resp
    }




    // -----------------------------------------------------------------------
    // Request-to-pay: contacts (allowlist) + the payer's payment-request inbox
    // -----------------------------------------------------------------------

    /// Parties authorized to bill this wallet.
    pub(crate) fn contacts(&self) -> &[Contact] {
        &self.contacts
    }

    /// Allowlist membership — the only authorization for an incoming payment request.
    pub(crate) fn is_contact(&self, vk_hex: &str) -> bool {
        self.contacts.iter().any(|c| c.vk_hex == vk_hex)
    }

    /// Authorize `vk_hex` to send this wallet payment requests (idempotent — re-adding relabels).
    pub(crate) fn add_contact(
        &mut self,
        vk_hex: String,
        label: String,
        now: i64,
    ) -> Result<(), String> {
        if hex::decode(&vk_hex).map(|b| b.len()) != Ok(33) {
            return Err("contact verifying key must be 33 bytes (hex)".into());
        }
        if let Some(existing) = self.contacts.iter_mut().find(|c| c.vk_hex == vk_hex) {
            existing.label = truncate(label, MAX_LABEL_LEN);
            return Ok(());
        }
        if self.contacts.len() >= MAX_CONTACTS {
            return Err(format!("contact list full (max {MAX_CONTACTS})"));
        }
        self.contacts.push(Contact {
            vk_hex,
            label: truncate(label, MAX_LABEL_LEN),
            added_at: now,
        });
        Ok(())
    }

    /// Revoke authorization; their pending requests are dropped too.
    pub(crate) fn remove_contact(&mut self, vk_hex: &str) -> Result<(), String> {
        let before = self.contacts.len();
        self.contacts.retain(|c| c.vk_hex != vk_hex);
        if self.contacts.len() == before {
            return Err("not a contact".into());
        }
        self.payment_intents
            .retain(|i| !(i.from_vk_hex == vk_hex && i.status == IntentStatus::Pending));
        Ok(())
    }

    pub(crate) fn payment_intents(&self) -> &[PaymentIntent] {
        &self.payment_intents
    }

    /// Record a request-to-pay. `to_ark_address` must have been DERIVED from `from_vk_hex`, and
    /// the caller must have checked `is_contact` first.
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn create_payment_intent(
        &mut self,
        from_vk_hex: String,
        to_ark_address: String,
        amount_sats: u64,
        memo: String,
        expires_in_secs: i64,
        now: i64,
    ) -> Result<PaymentIntent, String> {
        if !self.is_contact(&from_vk_hex) {
            return Err("requester is not an authorized contact".into());
        }
        if amount_sats == 0 {
            return Err("amount must be greater than zero".into());
        }
        let _ = self.prune_intents(now);

        let pending = |i: &PaymentIntent| i.status == IntentStatus::Pending;
        if self.payment_intents.iter().filter(|i| pending(i)).count() >= MAX_PENDING_INTENTS {
            return Err("payment request inbox is full".into());
        }
        let from_count = self
            .payment_intents
            .iter()
            .filter(|i| pending(i) && i.from_vk_hex == from_vk_hex)
            .count();
        if from_count >= MAX_PENDING_INTENTS_PER_CONTACT {
            return Err(format!(
                "too many pending requests from this contact (max {MAX_PENDING_INTENTS_PER_CONTACT})"
            ));
        }

        let ttl = if expires_in_secs <= 0 {
            DEFAULT_INTENT_TTL_SECS
        } else {
            expires_in_secs.min(MAX_INTENT_TTL_SECS)
        };
        let expires_at = now + ttl;
        let id = {
            let mut b = [0u8; 16];
            rand::RngCore::fill_bytes(&mut OsRng, &mut b);
            hex::encode(b)
        };
        let intent = PaymentIntent {
            id,
            from_vk_hex,
            to_ark_address,
            amount_sats,
            memo: truncate(memo, MAX_MEMO_LEN),
            created_at: now,
            expires_at,
            status: IntentStatus::Pending,
            ark_txid: String::new(),
        };
        self.payment_intents.push(intent.clone());
        Ok(intent)
    }

    /// Payer declines. Only a pending intent can be declined.
    pub(crate) fn decline_intent(&mut self, id: &str) -> Result<(), String> {
        let intent = self
            .payment_intents
            .iter_mut()
            .find(|i| i.id == id)
            .ok_or("no such payment request")?;
        if intent.status != IntentStatus::Pending {
            return Err(format!("request already {}", intent.status.as_str()));
        }
        intent.status = IntentStatus::Declined;
        Ok(())
    }

    /// Mark an intent paid once the payer's Ark send has settled.
    pub(crate) fn fulfil_intent(&mut self, id: &str, ark_txid: &str) -> Result<(), String> {
        let intent = self
            .payment_intents
            .iter_mut()
            .find(|i| i.id == id)
            .ok_or("no such payment request")?;
        if intent.status != IntentStatus::Pending {
            return Err(format!("request already {}", intent.status.as_str()));
        }
        intent.status = IntentStatus::Fulfilled;
        intent.ark_txid = ark_txid.to_string();
        Ok(())
    }

    /// Mark a pending request paid after one of the payer's sends settles, matched against the
    /// STORED intent's destination + amount.
    pub(crate) fn fulfil_matching_intent(
        &mut self,
        to_ark_address: &str,
        amount_sats: u64,
        ark_txid: &str,
    ) -> Option<String> {
        let id = self
            .payment_intents
            .iter()
            .filter(|i| {
                i.status == IntentStatus::Pending
                    && i.to_ark_address == to_ark_address
                    && i.amount_sats == amount_sats
            })
            // Oldest first, so repeated identical requests settle in order.
            .min_by_key(|i| i.created_at)
            .map(|i| i.id.clone())?;
        self.fulfil_intent(&id, ark_txid).ok()?;
        Some(id)
    }



    /// Expire stale pending intents and drop old terminal ones; keeps the sealed list bounded.
    pub(crate) fn prune_intents(&mut self, now: i64) -> bool {
        let mut changed = false;
        for intent in self.payment_intents.iter_mut() {
            if intent.status == IntentStatus::Pending && now >= intent.expires_at {
                intent.status = IntentStatus::Expired;
                changed = true;
            }
        }
        let before = self.payment_intents.len();
        self.payment_intents.retain(|i| {
            !i.status.is_terminal() || now - i.expires_at < TERMINAL_INTENT_RETENTION_SECS
        });
        changed || self.payment_intents.len() != before
    }


    /// The wallet's group x-only pubkey (hex) — the VTXO owner key, from the installed policy's PKP.
    pub fn owner_pk_hex(&self) -> Result<String, String> {
        let policy = self.policy.as_ref().ok_or("no policy installed")?;
        let vk = policy.public_key_package.verifying_key.serialize(); // [u8; 33]
        Ok(hex::encode(&vk[1..]))
    }

    /// The in-flight delegate/auto-settle session, mutated step-by-step by the async settle flow.
    pub fn delegate_session_mut(&mut self) -> Option<&mut DelegateSettleSession> {
        self.delegate_session.as_mut()
    }

    pub(crate) fn apply_delegate_sigs(&mut self, req: ApplyDelegateSigs) -> Result<(), String> {
        // Auth (OP_SETTLE_DELEGATE) ran at the REST boundary.
        let signatures: Vec<[u8; 64]> = req
            .signed_messages
            .iter()
            .map(|m| {
                m.as_slice()
                    .try_into()
                    .map_err(|_| "signature must be 64 bytes".to_string())
            })
            .collect::<Result<_, _>>()?;
        let session = self
            .delegate_session
            .as_mut()
            .ok_or("no delegate session")?;
        session.sign_with_frost(signatures)?;

        // The delegate is signed and ReadyToSettle from here, so this is the moment to arm the
        // watch: `enqueue` is interactive-only, and this is the last interactive call the settle
        // has. Best-effort — a wallet running detached from a runtime has no queue, and refusing
        // the settle over a missing background nicety would be the wrong trade.
        match self.settle_deadline() {
            Some(deadline) => {
                if let Err(e) = self.arm_settle_watch(deadline) {
                    tracing::warn!("settle watch not armed: {e}");
                }
            }
            None => tracing::debug!("settle watch not armed: VTXO expiries unknown"),
        }
        Ok(())
    }

    /// When the delegate's intent becomes valid: earliest covered expiry minus the safety margin.
    /// `None` when no covered VTXO has a known expiry — the ASP had not indexed them yet.
    fn settle_deadline(&self) -> Option<u64> {
        self.prepare_delegate().ok().and_then(|(_, valid_at)| valid_at)
    }


    #[allow(clippy::too_many_arguments)]
    pub fn install_policy(
        &mut self,
        group_key: String,
        key_package_json: &str,
        public_key_package_json: &str,
        user_signing_identifier_hex: Option<&str>,
        server_dkg_secret_hex: Option<String>,
    ) -> Result<(), String> {
        let key_package =
            KeyPackage::from_json(key_package_json).map_err(|e| format!("bad key package: {e}"))?;
        let public_key_package = PublicKeyPackage::from_json(public_key_package_json)
            .map_err(|e| format!("bad public key package: {e}"))?;
        let user_signing_identifier = match user_signing_identifier_hex {
            Some(h) => Some(parse_identifier_hex(h)?),
            None => None,
        };
        self.policy = Some(Policy {
            group_key,
            key_package,
            public_key_package,
            user_signing_identifier,
        });
        self.ark_cosigner_secret_hex = server_dkg_secret_hex.map(Zeroizing::new);
        Ok(())
    }



    /// This wallet's group key, hex, once it has one.
    pub(crate) fn policy_group_key(&self) -> Option<String> {
        self.policy.as_ref().map(|p| p.group_key.clone())
    }

    /// Refuse a second DKG over a wallet that already has a key.
    ///
    /// `install_policy` overwrites unconditionally, so without this a second ceremony on the same
    /// tenant silently replaces the wallet's key — and everything held under the old one becomes
    /// unspendable, because 2-of-2 has no other way back. The e2e suite did exactly that, repeatedly,
    /// and only got away with it because nothing was funded in between.
    ///
    /// It used to take a stranger to trigger it, since DKG was the one stream with no check at all.
    /// Now the runtime authenticates it, so the risk is the owner's own app — a re-run onboarding, a
    /// wiped local store — which is exactly the case where a refusal beats a quiet success.
    pub fn refuse_if_onboarded(&self) -> Result<(), Status> {
        if self.policy.is_some() {
            return Err(Status::failed_precondition(
                "this wallet already has a key; a second DKG would replace it and strand its funds",
            ));
        }
        Ok(())
    }

    /// Open a ceremony and hand it back. Nothing about it is stored here.
    pub fn sign_open(&mut self, req: SignStep1) -> Result<(Ceremony, SignStep1Out), String> {
        let policy = self.policy.as_ref().ok_or("no policy installed")?;
        let user_identifier = policy
            .user_signing_identifier
            .clone()
            .ok_or("policy has no user_signing_identifier")?;
        let server_identifier = policy.key_package.identifier.clone();

        let key_package = policy.key_package.clone();

        // The requested message, as asked. A `{service, cosigner}` pairing actor used to rebuild
        // a contract eVTXO's cooperative-leaf sighash here and sign only that; there are no
        // pairing actors now, and a normal wallet always took this branch anyway.
        let message = req.message_to_sign.clone();

        let mut new_signing_ceremony = Ceremony {
            message,
            full_transaction: req.full_transaction.clone(),
            ..Default::default()
        };

        let user_comm = commitments_from_bytes(&req.hiding_commitment, &req.binding_commitment)?;
        let mut rng = OsRng;
        let server_nonce = nonce::new_nonce(&mut rng, &key_package.secret_share);
        new_signing_ceremony
            .commitments
            .insert(server_identifier.clone(), server_nonce.commitments.clone());
        new_signing_ceremony.commitments.insert(user_identifier, user_comm);
        new_signing_ceremony.nonce = Some(server_nonce);

        let commitments = new_signing_ceremony
            .commitments
            .iter()
            .map(|(id, c)| Commitment {
                identifier_hex: hex::encode(id.serialize()),
                hiding: point::serialize_compressed(&c.hiding).to_vec(),
                binding: point::serialize_compressed(&c.binding).to_vec(),
            })
            .collect();
        let message_to_sign = new_signing_ceremony.message.clone();
        Ok((
            new_signing_ceremony,
            SignStep1Out {
                commitments,
                message_to_sign,
            },
        ))
    }

    /// Finish a ceremony the caller owns. Takes it by value: the nonce is single-use, so consuming
    /// the ceremony is what makes reuse unrepresentable rather than merely discouraged.
    pub fn sign_finish(
        &mut self,
        ceremony: Ceremony,
        req: SignStep2,
    ) -> Result<SignStep2Out, String> {
        let mut ceremony = ceremony;
        // NOTHING IS CHECKED HERE. The contract gate that stood in this spot was the only thing
        // between an authorized caller and a signature over arbitrary bytes, and the WASM contract
        // layer it enforced is no longer planned. The policy IR is what has to take its place
        // before this is exposed for real signing.

        let policy = self.policy.as_ref().ok_or("no policy installed")?;
        let user_identifier = policy
            .user_signing_identifier
            .clone()
            .ok_or("policy has no user_signing_identifier")?;
        let server_identifier = policy.key_package.identifier.clone();

        let key_package = policy.key_package.clone();
        let public_key_package = policy.public_key_package.clone();

        // Insert the client's signature share.
        let user_s_bytes: [u8; 32] = req
            .signature_share
            .as_slice()
            .try_into()
            .map_err(|_| "signature_share must be 32 bytes")?;
        let user_s =
            scalar_from_bytes(&user_s_bytes).map_err(|e| format!("bad share scalar: {e}"))?;
        ceremony
            .shares
            .insert(user_identifier, SignatureShare { s: user_s });

        // Compute the cosigner's share once (consumes the single-use nonce).
        if !ceremony.shares.contains_key(&server_identifier) {
            let nonce = ceremony
                .nonce
                .take()
                .ok_or("no signing nonce; call FrostSignStep1 first")?;
            let package = SigningPackage::new(
                ceremony.commitments.clone(),
                ceremony.message.clone(),
            );
            let share = signing::sign(&package, &nonce, &key_package)
                .map_err(|e| format!("frost sign: {e}"))?;
            ceremony.shares.insert(server_identifier, share);
        }

        if ceremony.shares.len() < THRESHOLD_COUNT {
            return Err("share count below threshold".into());
        }

        // Aggregate.
        let package = SigningPackage::new(
            ceremony.commitments.clone(),
            ceremony.message.clone(),
        );
        let signature = signing::aggregate(&package, &ceremony.shares, &public_key_package)
            .map_err(|e| format!("frost aggregate: {e}"))?;
        let r_point = point::serialize_compressed(&signature.r).to_vec();
        let z_scalar = scalar_to_bytes(&signature.z).to_vec();

        // No clearing step. This was `self.ceremony = Ceremony::default()` when the actor parked
        // the ceremony — erasing a spent nonce that would otherwise sit there. Taken by value, it
        // drops here whatever happens, including on every error path above.
        Ok(SignStep2Out { r_point, z_scalar })
    }


    // -------------------------------------------------------------------------------------------
    // In-band signing: FROST carried inside the Send and Settle streams
    // -------------------------------------------------------------------------------------------
    //
    // A send and a settle both stop for the wallet to sign sighashes the cosigner built. They used
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
        let policy = self.policy.as_ref().ok_or("no policy installed")?;
        let server_identifier = policy.key_package.identifier.clone();
        let identifier_hex = hex::encode(server_identifier.serialize());

        let mut rng = OsRng;
        let mut ceremonies = Vec::with_capacity(messages.len());
        let mut commitments = Vec::with_capacity(messages.len());
        for message in messages {
            let nonce = nonce::new_nonce(&mut rng, &policy.key_package.secret_share);
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
        Ok((InBandRound { ceremonies }, commitments))
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
        if wallet.len() != round.ceremonies.len() {
            return Err(format!(
                "the wallet answered {} of {} messages",
                wallet.len(),
                round.ceremonies.len()
            ));
        }
        let policy = self.policy.as_ref().ok_or("no policy installed")?;
        let user_identifier = policy
            .user_signing_identifier
            .clone()
            .ok_or("policy has no user_signing_identifier")?;
        let server_identifier = policy.key_package.identifier.clone();

        round
            .ceremonies
            .into_iter()
            .zip(wallet)
            .enumerate()
            .map(|(i, (mut ceremony, half))| {
                let at = |e: String| format!("message {i}: {e}");

                ceremony.commitments.insert(
                    user_identifier.clone(),
                    commitments_from_bytes(&half.hiding, &half.binding).map_err(at)?,
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
                let server_share = signing::sign(&package, &nonce, &policy.key_package)
                    .map_err(|e| at(format!("frost sign: {e}")))?;
                ceremony.shares.insert(server_identifier.clone(), server_share);

                // `aggregate` verifies each share against its verifying share before summing, so a
                // wallet share that does not belong to this message and these commitments stops
                // here, with the index attached, instead of at the ASP with nothing to say.
                let signature =
                    signing::aggregate(&package, &ceremony.shares, &policy.public_key_package)
                        .map_err(|e| at(format!("frost aggregate: {e}")))?;
                Ok(signature.serialize().to_vec())
            })
            .collect()
    }

    /// Boarding settle START: derive the owner key (from the installed policy), the ASP info, and
    /// the boarding address ourselves, then build the session from the wallet-scanned `boarding_utxo`
    /// `(txid, vout, amount_sats)`. Returns the intent-proof sighashes to FROST-sign.
    pub(crate) fn boarding_settle_start(
        &mut self,
        boarding_utxo: Option<(String, u32, u64)>,
        info: &ArkInfo,
    ) -> Result<Vec<Vec<u8>>, String> {
        let owner_pk_hex = match self.owner_pk_hex() {
            Ok(o) => o,
            Err(e) => return Err(e),
        };
        let network = match ark::client::parse_network(&info.network) {
            Ok(n) => n,
            Err(e) => return Err(e),
        };
        let boarding_exit_delay = info.boarding_exit_delay as u32;
        let boarding_address = match ark::client::boarding_address(
            &owner_pk_hex,
            &info.signer_pubkey,
            boarding_exit_delay,
            network,
        ) {
            Ok(a) => a,
            Err(e) => return Err(format!("boarding_address: {e}")),
        };
        let (txid, vout, amount) = match boarding_utxo {
            Some(u) => u,
            None => return Err("no boarding UTXO supplied".into()),
        };
        self.boarding_settle_step1(
            &owner_pk_hex,
            &info.signer_pubkey,
            &info.forfeit_pubkey,
            &boarding_address,
            &txid,
            vout,
            amount,
            boarding_exit_delay,
            &info.network,
        )
    }

    /// Boarding settle step 1: build the boarding session + tree-signer from the (caller-derived)
    /// owner-pk + ASP params, hold it in flight, and return the intent-proof sighashes to sign.
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn boarding_settle_step1(
        &mut self,
        owner_pk_hex: &str,
        signer_pubkey: &str,
        forfeit_pubkey: &str,
        boarding_address: &str,
        boarding_txid: &str,
        boarding_vout: u32,
        boarding_amount_sats: u64,
        boarding_exit_delay: u32,
        network: &str,
    ) -> Result<Vec<Vec<u8>>, String> {
        let secret = self
            .ark_cosigner_secret_hex()
            .ok_or("no Ark cosigner secret installed")?
            .to_string();
        let signer = ark::client::batch::BoardingTreeSigner::new(&secret)?;
        let cosigner_pk_hex = signer.cosigner_pubkey_hex();
        let (session, sighashes) = ark::client::batch::SettleSession::new_boarding(
            owner_pk_hex,
            signer_pubkey,
            forfeit_pubkey,
            boarding_address,
            boarding_txid,
            boarding_vout,
            boarding_amount_sats,
            boarding_exit_delay,
            network,
            &cosigner_pk_hex,
        )
        .map_err(|e| format!("new_boarding: {e}"))?;
        self.boarding_settle = Some(BoardingSettleInFlight {
            session,
            signer,
            amount_sats: boarding_amount_sats,
            exit_delay: boarding_exit_delay,
        });
        Ok(sighashes.iter().map(|s| s.to_vec()).collect())
    }

    /// Delegate phase 1: build the pre-authorized intent + forfeit PSBTs (after `GetInfo`) and return
    /// the sighashes the client must FROST-sign. The Ark cosigner secret never leaves the core.
    pub fn generate_delegate_for(
        &mut self,
        info: &ArkInfo,
    ) -> Result<Vec<Vec<u8>>, String> {
        let req = GenerateDelegate {
            intent_valid_at: self.prepare_delegate().map(|(_, v)| v).unwrap_or(None),
        };
        let (owner_pk_hex, cosigner_secret_hex, vtxos) = {
            let owner = match self.owner_pk_hex() {
                Ok(o) => o,
                Err(e) => return Err(e),
            };
            let secret = match self.ark_cosigner_secret_hex() {
                Some(s) => s.to_string(),
                None => return Err("no Ark cosigner secret installed".into()),
            };
            (owner, secret, self.vtxos().to_vec())
        };

        if vtxos.is_empty() {
            return Err("no VTXOs to settle".into());
        }
        let vtxo_inputs: Vec<DelegateVtxoInput> = vtxos
            .iter()
            .map(|v| DelegateVtxoInput {
                txid: v.txid.clone(),
                vout: v.vout,
                amount_sats: v.amount_sats,
                is_swept: false,
                exit_delay: v.exit_delay,
            })
            .collect();

        let network = match ark::client::parse_network(&info.network) {
            Ok(n) => n,
            Err(e) => return Err(e),
        };
        let total: u64 = vtxos.iter().map(|v| v.amount_sats).sum();
        let owner_ark_address = match ark::client::ark_address(
            &owner_pk_hex,
            &info.signer_pubkey,
            info.unilateral_exit_delay as u32,
            network,
        ) {
            Ok(a) => a,
            Err(e) => return Err(format!("ark_address: {e}")),
        };
        let outputs = vec![DelegateOutput {
            ark_address: owner_ark_address,
            amount_sats: total,
        }];

        match DelegateSettleSession::generate_delegate(
            &owner_pk_hex,
            &info.signer_pubkey,
            &info.forfeit_pubkey,
            &cosigner_secret_hex,
            &vtxo_inputs,
            &outputs,
            &info.forfeit_address,
            info.dust as u64,
            &info.network,
            req.intent_valid_at,
        ) {
            Ok((session, sighashes)) => {
                self.delegate_session = Some(session);
                Ok(sighashes.iter().map(|s| s.to_vec()).collect())
            }
            Err(e) => Err(format!("generate_delegate: {e}")),
        }
    }







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

    /// Insert the caller's signatures and hand back the transactions it must submit.
    ///
    /// The cosigner used to call `SubmitTx` itself. It signs; the caller submits.
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
        // Expiry is unknown until the ASP indexes it, so 0 — `build_delegate_step1` reads that as
        // "unknown" and skips it conservatively rather than settling against a made-up deadline.
        let now = crate::store::now_secs();
        self.owned_vtxos.clear();
        if let Some((txid, vout, amount, exit_delay)) = change.clone() {
            self.owned_vtxos.push(VtxoEntry {
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

fn parse_identifier_hex(h: &str) -> Result<Identifier, String> {
    let bytes = hex::decode(h).map_err(|e| format!("bad identifier hex: {e}"))?;
    let arr: [u8; 32] = bytes
        .as_slice()
        .try_into()
        .map_err(|_| "identifier must be 32 bytes")?;
    Identifier::deserialize(&arr).map_err(|e| format!("bad identifier: {e}"))
}

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

fn commitments_from_bytes(hiding: &[u8], binding: &[u8]) -> Result<SigningCommitments, String> {
    let h: [u8; 33] = hiding.try_into().map_err(|_| "hiding must be 33 bytes")?;
    let b: [u8; 33] = binding.try_into().map_err(|_| "binding must be 33 bytes")?;
    Ok(SigningCommitments {
        hiding: point::deserialize_compressed(&h).map_err(|e| format!("bad hiding point: {e}"))?,
        binding: point::deserialize_compressed(&b)
            .map_err(|e| format!("bad binding point: {e}"))?,
    })
}

use ark::client::batch::{DelegateOutput, DelegateVtxoInput};

use crate::types::{GenerateDelegate, SendVtxoStep2};

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
