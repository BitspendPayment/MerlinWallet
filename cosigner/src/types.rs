//! Durable, non-secret domain types. Plain data, no crypto material — the sealed snapshot is built
//! from these.

use serde::{Deserialize, Serialize};

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
    pub vtxos: Vec<VtxoInput>,
    /// A `ReadyToSettle` delegate session serialized via ark `PersistedDelegate` (JSON), if
    /// one is pending. Lets durable auto-settle survive actor eviction. Only ever
    /// `ReadyToSettle` (never a `Settling`-phase session — MuSig2 nonces must not persist).
    pub delegate_json: Option<String>,
    /// Parties authorized to send this wallet payment requests. `default` so seals written
    /// before request-to-pay restore cleanly.
    #[serde(default)]
    pub contacts: Vec<Contact>,
    /// Request-to-pay records held for this wallet. Bounded by per-requester + global caps and
    /// pruned on every mutation (the whole snapshot is re-serialized on each change).
    #[serde(default)]
    pub payment_intents: Vec<PaymentIntent>,
}

// ===========================================================================
// Actor method inputs. Plain-data request structs passed to the `Cosigner` signing/session
// methods the registry calls (`sign_step1`, `send_vtxo_step1`, `generate_delegate`, …).
// ===========================================================================

/// SendVtxo phase 1 — build the Ark tx and get sighashes to sign.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SendVtxoStep1 {
    pub user_id: Vec<u8>,
    pub signature: Vec<u8>,
    pub timestamp_ms: i64,
    pub recipient_ark_address: String,
    pub amount: u64,
    /// The current spendable VTXO set, supplied by the host from its persisted projection. The
    /// actor selects from these + checks the balance itself (no separate `SetVtxos` push).
    pub vtxos: Vec<VtxoInput>,
}

/// SendVtxo phase 2 — the client's FROST signatures over the phase-1 sighashes.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SendVtxoStep2 {
    pub user_id: Vec<u8>,
    pub signature: Vec<u8>,
    pub timestamp_ms: i64,
    pub signed_messages: Vec<Vec<u8>>,
}

/// Delegate phase 1 — build the pre-authorized intent + forfeit PSBTs and return sighashes.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GenerateDelegate {
    pub user_id: Vec<u8>,
    pub signature: Vec<u8>,
    pub timestamp_ms: i64,
    // VTXOs come from the guest's own store (SetVtxos); the settle output is a self-refresh
    // to the owner's own ark address, which the guest computes from GetInfo. Neither is on
    // the wire. Only the host-computed renewal deadline is passed in.
    /// Renewal time (Unix secs) the delegate becomes valid; `None` keeps the legacy window.
    pub intent_valid_at: Option<u64>,
}

/// Delegate phase 2 — the client's FROST signatures over the phase-1 sighashes.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ApplyDelegateSigs {
    pub user_id: Vec<u8>,
    pub signature: Vec<u8>,
    pub timestamp_ms: i64,
    pub signed_messages: Vec<Vec<u8>>,
}

/// FROST sign round-1 request (mirrors the gRPC `SignStep1Request` fields the guest needs).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SignStep1 {
    /// The client's auth/verifying identity (compressed pubkey bytes); also the key the
    /// auth signature is checked against.
    pub user_id: Vec<u8>,
    pub hiding_commitment: Vec<u8>,
    pub binding_commitment: Vec<u8>,
    pub message_to_sign: Vec<u8>,
    /// BIP-340 auth signature over the canonical auth message for this operation.
    pub signature: Vec<u8>,
    pub full_transaction: Vec<u8>,
    pub timestamp_ms: i64,
    /// True ⇒ raw FROST (no taproot tweak).
    pub script_path_spend: bool,
    /// Service spend THROUGH arkd — the second leg's `ark_tx` PSBT. When set (and the actor is a
    /// pairing actor), the guest accepts `message_to_sign` if it equals leg 1 OR leg 2; empty ⇒
    /// single-leg, the guest OVERRIDES `message_to_sign` with the rebuilt cooperative-leaf sighash.
    pub ark_tx: Vec<u8>,
}

/// FROST sign round-2 request (mirrors the gRPC `SignStep2Request`).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SignStep2 {
    pub user_id: Vec<u8>,
    pub signature_share: Vec<u8>,
    pub signature: Vec<u8>,
    pub timestamp_ms: i64,
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



/// Output of `public_policy`: the PUBLIC projection the host loads into its `policy_state`.
#[derive(Debug)]
pub struct PublicPolicy {
    pub group_key: String,
    pub public_key_package_json: String,
    pub user_signing_identifier_hex: Option<String>,
}

/// Output of `sign_step1`: the combined commitments to sign over.
#[derive(Debug)]
pub struct SignStep1Out {
    pub commitments: Vec<Commitment>,
    pub message_to_sign: Vec<u8>,
}

/// Output of `sign_step2`: the aggregated signature (R, Z).
#[derive(Debug)]
pub struct SignStep2Out {
    pub r_point: Vec<u8>,
    pub z_scalar: Vec<u8>,
}

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
