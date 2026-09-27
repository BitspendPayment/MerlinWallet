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

use crate::store::Store;

// Request-to-pay bounds. Contacts + intents live in the sealed snapshot, which is re-serialized
// in full on every mutation — so an allowlisted peer must not be able to grow it without limit.
const MAX_CONTACTS: usize = 256;
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
const MAX_LABEL_LEN: usize = 64;
const MAX_MEMO_LEN: usize = 140;
const MAX_PENDING_INTENTS: usize = 50;
const MAX_PENDING_INTENTS_PER_CONTACT: usize = 3;
const DEFAULT_INTENT_TTL_SECS: i64 = 24 * 60 * 60;
const MAX_INTENT_TTL_SECS: i64 = 7 * 24 * 60 * 60;
/// How long a declined/fulfilled/expired intent lingers so the payer can still see it.
const TERMINAL_INTENT_RETENTION_SECS: i64 = 24 * 60 * 60;

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

/// Clamp a peer-supplied string to `max` CHARACTERS (not bytes — never split a UTF-8 sequence).
fn truncate(s: String, max: usize) -> String {
    if s.chars().count() <= max {
        s
    } else {
        s.chars().take(max).collect()
    }
}

/// The key material one group installed: the cosigner's own share + the group public key, plus the
/// client's FROST identifier (the other half of the 2-of-2).
///
/// Named for what it holds rather than what it decides. It used to be `Policy`, which was the only
/// meaning that word had here; `crate::policy::Policy` now carries the other one — what a signature
/// is *allowed* to authorize — and a single name for both would be a running invitation to confuse
/// "which key" with "may I".
struct GroupKeys {
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
    /// The cosigner's single-use nonce for this round (set at begin, consumed at finish).
    nonce: Option<SigningNonce>,
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
    policy: Option<GroupKeys>,
    /// A `ReadyToSettle` delegate session the core can drive autonomously (auto-settle).
    pub(crate) delegate_session: Option<DelegateSettleSession>,
    /// See `SnapshotState::delegate_intent_id`.
    pub(crate) delegate_intent_id: Option<String>,
    /// In-flight GUEST-style boarding settle, held across the commitment-FROST pause (the client
    /// must FROST-sign the commitment sighashes between step 2 and step 3). Native: no held stream
    /// (step 3 finalizes optimistically). Transient — never snapshotted.
    pub(crate) boarding_settle: Option<BoardingSettleInFlight>,
    /// The settle the caller is driving: which FROST round is open, the registered intent id, and
    /// the ASP parameters it supplied. See [`crate::settle`].
    pub(crate) settle_inflight: Option<crate::handlers::settle::InFlight>,
    /// The Ark cosigner (MuSig2) secret, hex — zeroized on drop. Used for tree signing.
    ark_cosigner_secret_hex: Option<Zeroizing<String>>,
    /// See `SnapshotState::wallet_dealt_share_hex`. Zeroized on drop like the secret above: it is
    /// half of the owner's signing key, and the other half is one passkey away.
    wallet_dealt_share_hex: Option<Zeroizing<String>>,
    /// The escrow keys this wallet has minted. See `SnapshotState::escrows`.
    escrows: Vec<crate::types::EscrowRecord>,
    /// Payments that have already been released against. See `SnapshotState::released_references`.
    released_references: BTreeMap<String, crate::types::ReleaseRecord>,
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
/// It used to carry the ASP event stream too. It does not now: boarding is interactive, so the
/// caller subscribes and relays each event in, and the field had one writer, no readers and a doc
/// comment describing a design that was already gone. The cosigner does hold an ASP connection of
/// its own (`crate::asp`) — but for the unattended case, executing a sealed delegate, not for a
/// round the app is already driving.
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
            policy: None,
            delegate_session: None,
            delegate_intent_id: None,
            boarding_settle: None,
            settle_inflight: None,
            ark_cosigner_secret_hex: None,
            wallet_dealt_share_hex: None,
            escrows: Vec::new(),
            released_references: BTreeMap::new(),
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
            wallet_dealt_share_hex: self
                .wallet_dealt_share_hex
                .as_ref()
                .map(|z| z.to_string()),
            vtxos: self.owned_vtxos.clone(),
            // Persist a ReadyToSettle delegate (to_persisted errors for other phases → None).
            delegate_json: self
                .delegate_session
                .as_ref()
                .and_then(|s| s.to_persisted().ok())
                .and_then(|p| serde_json::to_string(&p).ok()),
            delegate_intent_id: self.delegate_intent_id.clone(),
            contacts: self.contacts.clone(),
            payment_intents: self.payment_intents.clone(),
            seen_request_nonces: self.seen_request_nonces.clone(),
            escrows: self.escrows.clone(),
            released_references: self.released_references.clone(),
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
        self.policy = Some(GroupKeys {
            group_key: snap.group_key,
            key_package,
            public_key_package,
            user_signing_identifier,
        });
        self.ark_cosigner_secret_hex = snap.ark_cosigner_secret_hex.map(Zeroizing::new);
        self.wallet_dealt_share_hex = snap.wallet_dealt_share_hex.map(Zeroizing::new);
        self.owned_vtxos = snap.vtxos;
        self.contacts = snap.contacts;
        self.payment_intents = snap.payment_intents;
        self.seen_request_nonces = snap.seen_request_nonces;
        self.escrows = snap.escrows;
        self.released_references = snap.released_references;
        self.delegate_intent_id = snap.delegate_intent_id;
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

    /// The share this cosigner dealt the wallet at DKG, hex, if this wallet was onboarded after
    /// recovery existed. See `SnapshotState::wallet_dealt_share_hex`.
    pub(crate) fn wallet_dealt_share_hex(&self) -> Option<&str> {
        self.wallet_dealt_share_hex.as_ref().map(|z| z.as_str())
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
            // Expiry is the indexer's, relayed by the caller; 0 reads as "unknown" downstream, which
            // `build_delegate_step1` skips conservatively rather than scheduling against a guess.
            accepted.push(VtxoEntry {
                txid: v.txid,
                vout: v.vout,
                amount: v.amount_sats,
                exit_delay: v.exit_delay,
                created_at: now,
                expires_at: v.expires_at.max(0),
            });
        }
        self.owned_vtxos = accepted;
        Ok(())
    }

    /// The owned set in the shape ark's session builders take.
    pub fn vtxos(&self) -> Vec<VtxoInput> {
        self.owned_vtxos
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

    /// The VTXO set to refresh and the renewal deadline the delegate becomes valid at.
    pub fn prepare_delegate(
        &self,
    ) -> Result<(Vec<VtxoInput>, Option<u64>), Status> {
        handlers::ark_send::build_delegate_step1(&self.owned_vtxos, &self.store)
    }

    /// Seal this actor's state. Storage is the whole of the persistence now, so a method that
    /// mutates durable state seals here rather than trusting its caller to remember.
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
        // Arming the watch is sealing's business (`seal_delegate_finish`), not signing's: a delegate
        // signed for a refresh the owner asked for now is spent in the same round.
        Ok(())
    }

    /// When the delegate's intent becomes valid: earliest covered expiry minus the safety margin.
    /// `None` when no covered VTXO has a known expiry — the ASP had not indexed them yet.
    pub(crate) fn settle_deadline(&self) -> Option<u64> {
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
        wallet_dealt_share_hex: Option<String>,
    ) -> Result<(), String> {
        let key_package =
            KeyPackage::from_json(key_package_json).map_err(|e| format!("bad key package: {e}"))?;
        let public_key_package = PublicKeyPackage::from_json(public_key_package_json)
            .map_err(|e| format!("bad public key package: {e}"))?;
        let user_signing_identifier = match user_signing_identifier_hex {
            Some(h) => Some(parse_identifier_hex(h)?),
            None => None,
        };
        self.policy = Some(GroupKeys {
            group_key,
            key_package,
            public_key_package,
            user_signing_identifier,
        });
        self.ark_cosigner_secret_hex = server_dkg_secret_hex.map(Zeroizing::new);
        self.wallet_dealt_share_hex = wallet_dealt_share_hex.map(Zeroizing::new);
        Ok(())
    }



    /// This wallet's group key, hex, once it has one.
    pub(crate) fn policy_group_key(&self) -> Option<String> {
        self.policy.as_ref().map(|p| p.group_key.clone())
    }

    /// The ceremony's public key package, JSON: the group key and both verifying shares. Public by
    /// construction — it is what a recovering wallet checks its rebuilt share against.
    pub(crate) fn policy_public_key_package_json(&self) -> Option<String> {
        self.policy.as_ref().map(|p| p.public_key_package.to_json())
    }

    /// The owner's FROST identifier, as the ceremony recorded it.
    pub(crate) fn user_signing_identifier(&self) -> Option<Identifier> {
        self.policy.as_ref().and_then(|p| p.user_signing_identifier.clone())
    }

    // --- Escrow keys -----------------------------------------------------------------------------
    //
    // A second 2-of-2 over a key of its own, minted by a reshare so a service can be paired into
    // escrowed money without being paired into the wallet. See `crate::handlers::escrow`.

    /// The wallet key material a reshare is dealt against: this cosigner's own share and the
    /// group's public package. `None` before onboarding, when there is nothing to reshare.
    pub(crate) fn wallet_key_material(&self) -> Option<(KeyPackage, PublicKeyPackage)> {
        self.policy
            .as_ref()
            .map(|p| (p.key_package.clone(), p.public_key_package.clone()))
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

    /// One escrow by its key, comparing x-only so either parity resolves — the same rule contacts
    /// already use, and the reason a caller can name an escrow by the address it pays.
    pub fn escrow(&self, escrow_key: &str) -> Option<&crate::types::EscrowRecord> {
        let want = x_only(escrow_key);
        self.escrows.iter().find(|e| x_only(&e.escrow_key) == want)
    }

    /// One escrow's key material, for a pairing to be dealt against: this cosigner's share of
    /// `V'`, the escrow's public package, and the wallet's identifier in it.
    pub(crate) fn escrow_key_material(
        &self,
        escrow_key: &str,
    ) -> Option<(KeyPackage, PublicKeyPackage, Identifier)> {
        let record = self.escrow(escrow_key)?;
        let kp = KeyPackage::from_json(&record.key_package_json).ok()?;
        let pkp = PublicKeyPackage::from_json(&record.public_key_package_json).ok()?;
        let id_bytes: [u8; 32] = hex::decode(&record.wallet_identifier_hex).ok()?.try_into().ok()?;
        let wallet_id = Identifier::deserialize(&id_bytes).ok()?;
        Some((kp, pkp, wallet_id))
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
        escrow_key: &str,
        session: crate::escrow_session::EscrowSession,
        now: i64,
    ) -> Result<(), String> {
        let want = x_only(escrow_key);
        let record = self
            .escrows
            .iter_mut()
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
        // A deal can be struck again once the last one's deadline has passed, and not before.
        // There is no other way for one to end — see `crate::escrow_session`.
        if record.session.as_ref().is_some_and(|s| s.is_open(now)) {
            return Err(
                "this escrow is already committed to a deal, and a deal runs until its deadline"
                    .into(),
            );
        }
        record.session = Some(session);
        Ok(())
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
        Ok(in_band_begin(&policy.key_package, messages))
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
        let policy = self.policy.as_ref().ok_or("no policy installed")?;
        let user_identifier = policy
            .user_signing_identifier
            .clone()
            .ok_or("policy has no user_signing_identifier")?;
        in_band_finish(
            &policy.key_package,
            &policy.public_key_package,
            &user_identifier,
            round,
            wallet,
        )
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
    /// `deferred`: valid from the renewal deadline (a sealed delegate), or from now (a refresh the
    /// owner is asking for in person — the ASP refuses an intent valid in the future until then).
    pub fn generate_delegate_for(
        &mut self,
        info: &ArkInfo,
        deferred: bool,
    ) -> Result<Vec<Vec<u8>>, String> {
        let req = GenerateDelegate {
            intent_valid_at: if deferred {
                self.prepare_delegate().map(|(_, v)| v).unwrap_or(None)
            } else {
                None
            },
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
            address: owner_ark_address,
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
