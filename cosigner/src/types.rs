//! Durable, non-secret domain types. Plain data, no crypto material — the sealed snapshot is built
//! from these.

use serde::{Deserialize, Serialize};

/// One VTXO this cosigner holds. `created_at`/`expires_at` come from the ASP and feed the
/// delegate's renewal deadline; rows lacking them deserialize to 0 — unknown expiry, treated
/// conservatively.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VtxoEntry {
    pub txid: String,
    pub vout: u32,
    pub amount: u64,
    pub exit_delay: u32,
    #[serde(default)]
    pub created_at: i64,
    #[serde(default)]
    pub expires_at: i64,
}



#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ArkTxEntry {
    /// "board", "send", "receive", "settle".
    pub tx_type: String,
    /// Positive for inflows, negative for outflows.
    pub amount_sats: i64,
    pub txid: String,
    /// Seconds since the Unix epoch.
    pub timestamp: i64,
}

/// A spendable VTXO the actor can use as a send input.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VtxoInput {
    pub txid: String,
    pub vout: u32,
    pub amount_sats: u64,
    pub exit_delay: u32,
    /// Unix seconds, as the ASP's indexer reports it; 0 when not known. Schedules a wake, nothing
    /// more.
    #[serde(default)]
    pub expires_at: i64,
}



/// A party authorized to bill this wallet. One-way — the contact gives no consent. An
/// AUTHORIZATION list, so it lives in the seal.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Contact {
    /// The contact's group verifying key, hex (33-byte compressed) — its whole identity.
    pub vk_hex: String,
    /// Local display name chosen by the owner.
    pub label: String,
    /// Unix seconds.
    pub added_at: i64,
}

/// Lifecycle of a payment request held for the payer.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum IntentStatus {
    Pending,
    Fulfilled,
    Declined,
    Expired,
}

impl IntentStatus {
    /// Wire form (also what the app renders).
    pub fn as_str(&self) -> &'static str {
        match self {
            IntentStatus::Pending => "pending",
            IntentStatus::Fulfilled => "fulfilled",
            IntentStatus::Declined => "declined",
            IntentStatus::Expired => "expired",
        }
    }

    /// Terminal states are kept only briefly (for the payer's history) then pruned.
    pub fn is_terminal(&self) -> bool {
        !matches!(self, IntentStatus::Pending)
    }
}

/// A request-to-pay held for the payer.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PaymentIntent {
    /// Random 16-byte hex id.
    pub id: String,
    /// The requester's verifying key hex — was on the payer's allowlist at create time.
    pub from_vk_hex: String,
    /// DERIVED from `from_vk_hex`; never taken from the request body.
    pub to_ark_address: String,
    pub amount_sats: u64,
    pub memo: String,
    pub created_at: i64,
    pub expires_at: i64,
    pub status: IntentStatus,
    /// Set when the payer's send settles.
    #[serde(default)]
    pub ark_txid: String,
}

/// The actor's durable state, serialized into the sealed snapshot blob. Excludes in-flight
/// sessions (MuSig2 secret nonces must never persist).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SnapshotState {
    pub group_key: String,
    pub key_package_json: String,
    pub public_key_package_json: String,
    pub user_signing_identifier_hex: Option<String>,
    pub ark_cosigner_secret_hex: Option<String>,
    /// `f_cosigner(wallet_identifier)`, hex: the share this cosigner dealt the wallet at DKG.
    ///
    /// Kept so a wallet can be rebuilt on a new device. Its owner re-derives the other half of its
    /// share from the passkey's PRF and adds this one; the sum is checked against the verifying
    /// share in `public_key_package_json` before anything is saved. `default` for seals written
    /// before this existed — those wallets have no restore path, and `Recover` says so.
    #[serde(default)]
    pub wallet_dealt_share_hex: Option<String>,
    /// The owned set, with expiry. `VtxoInput` before — a shape that dropped the expiry a
    /// delegate's renewal deadline needs, which is why a second set existed alongside it.
    pub vtxos: Vec<VtxoEntry>,
    /// A `ReadyToSettle` delegate session serialized via ark `PersistedDelegate` (JSON), if
    /// one is pending. Lets durable auto-settle survive actor eviction. Only ever
    /// `ReadyToSettle` (never a `Settling`-phase session — MuSig2 nonces must not persist).
    pub delegate_json: Option<String>,
    /// The id the ASP gave the sealed delegate's registration, once the watch registered it — so a
    /// retried run follows that registration instead of making a second. `default` for older seals.
    #[serde(default)]
    pub delegate_intent_id: Option<String>,
    /// Parties authorized to send this wallet payment requests. `default` so seals written
    /// before request-to-pay restore cleanly.
    #[serde(default)]
    pub contacts: Vec<Contact>,
    /// Request-to-pay records held for this wallet. Bounded by per-requester + global caps and
    /// pruned on every mutation (the whole snapshot is re-serialized on each change).
    #[serde(default)]
    pub payment_intents: Vec<PaymentIntent>,
    /// Payment-request nonces this wallet has accepted, hex, each with the `not_after` it arrived
    /// under. Sealed rather than held in memory because a replay does not have to wait for the same
    /// instance: the runtime rebuilds instances freely, and a set that died with one would let the
    /// next accept the same request again. Pruned once `not_after` passes — after that the request
    /// is refused for being stale anyway, so remembering it buys nothing. `default` for older seals.
    #[serde(default)]
    pub seen_request_nonces: std::collections::BTreeMap<String, i64>,
}

// ===========================================================================
// Actor method inputs. Plain-data request structs passed to the `Cosigner` signing/session
// methods the registry calls (`sign_step1`, `send_vtxo_step1`, `generate_delegate`, …).
// ===========================================================================

/// SendVtxo phase 1 — build the Ark tx and get sighashes to sign.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SendVtxoStep1 {
    pub recipient_ark_address: String,
    pub amount: u64,
    /// The current spendable VTXO set, supplied by the host from its persisted projection. The
    /// actor selects from these + checks the balance itself (no separate `SetVtxos` push).
    pub vtxos: Vec<VtxoInput>,
}

/// SendVtxo phase 2 — the client's FROST signatures over the phase-1 sighashes.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SendVtxoStep2 {
    pub signed_messages: Vec<Vec<u8>>,
}

/// Delegate phase 1 — build the pre-authorized intent + forfeit PSBTs and return sighashes.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GenerateDelegate {
    // VTXOs come from the guest's own store (SetVtxos); the settle output is a self-refresh
    // to the owner's own ark address, which the guest computes from GetInfo. Neither is on
    // the wire. Only the host-computed renewal deadline is passed in.
    /// Renewal time (Unix secs) the delegate becomes valid; `None` keeps the legacy window.
    pub intent_valid_at: Option<u64>,
}

/// Delegate phase 2 — the client's FROST signatures over the phase-1 sighashes.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ApplyDelegateSigs {
    pub signed_messages: Vec<Vec<u8>>,
}

/// One participant's signing commitments, keyed by FROST identifier (hex).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Commitment {
    pub identifier_hex: String,
    pub hiding: Vec<u8>,
    pub binding: Vec<u8>,
}

// ===========================================================================
// Actor method outputs. Typed return values for the `Cosigner` methods the registry
// calls directly. Plain in-process data — no serde needed (never crosses a boundary).
// ===========================================================================





/// Output of `settle_delegate`: the finalized commitment txid, the settled VTXO outpoint if
/// produced, and the `unilateral_exit_delay` the output was built with.
#[derive(Debug)]
pub struct SettleSubmitted {
    pub commitment_txid: String,
    pub vtxo_outpoint: Option<(String, u32)>,
    pub exit_delay: u32,
}

/// Output of a completed boarding settle: the finalized settle's new VTXO.
#[derive(Debug)]
pub struct BoardingSettleSubmitted {
    pub commitment_txid: String,
    pub vtxo_txid: String,
    pub vtxo_vout: u32,
    pub amount_sats: u64,
    pub exit_delay: u32,
}

/// Result of a `boarding_settle` step: either more sighashes to FROST-sign (mid-flight) or the
/// finalized VTXO (completion).
#[derive(Debug)]
pub enum BoardingSettleOutcome {
    Sighashes(Vec<Vec<u8>>),
    Submitted(BoardingSettleSubmitted),
}

/// Output of `send_vtxo_step2`: the submitted Ark txid and the change VTXO if the send made one.
#[derive(Debug)]
pub struct SendVtxoSubmitted {
    pub ark_txid: String,
    pub change: Option<(String, u32, u64, u32)>,
}
