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



/// The actor's durable state, serialized into the sealed snapshot blob. Excludes in-flight
/// sessions (MuSig2 secret nonces must never persist).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SnapshotState {
    pub group_key: String,
    pub key_package_json: String,
    pub public_key_package_json: String,
    pub user_signing_identifier_hex: Option<String>,
    /// The wallet-wide tree-signing key older seals kept — the cosigner's own DKG secret, reused
    /// for every round. Read only to restore a delegate sealed under it, and never written: each
    /// delegate now carries a key of its own.
    #[serde(default, skip_serializing)]
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
    /// Where older seals kept the delegate's registration id, which the delegate now carries.
    /// Read only to restore a delegate sealed before it did, and never written.
    #[serde(default, skip_serializing)]
    pub delegate_intent_id: Option<String>,
    /// The escrows this wallet has minted, oldest first, each with its one deal and the payments
    /// it released. `default` for seals written before escrow existed — a wallet with none simply
    /// has none. An older seal's escrows load without their deals, and its wallet-wide release
    /// ledger is not read: they are taken back, never paid from again.
    #[serde(default)]
    pub escrows: Vec<crate::escrow::EscrowSession>,
}

/// One release an escrow made, filed under the payment that justified it — see
/// [`EscrowSession::releases`](crate::escrow::EscrowSession::releases).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ReleaseRecord {
    /// The service's idempotency key for the request that asked.
    pub request_id: String,
    /// What it paid out, in sats.
    pub sats: u64,
    /// Unix seconds.
    pub at: i64,
    /// What was approved, hashed. A repeat must be the same proposal, or it is a different release
    /// wearing an answered request's name.
    pub proposal_hash: String,
    /// The deadline of the deal that approved it, unix seconds.
    ///
    /// Until then a repeat of this request is signed again, and the owner may not take the escrow
    /// back — the service may still hold these signatures unsubmitted, even if its service has
    /// since ended the deal.
    pub deadline: i64,
}

/// What the wallet says about a release it is being asked for.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Admission {
    /// This payment has never been released against. Judge it, and record it if it passes.
    New,
    /// This exact request was answered before, and the answer is still the same one.
    ///
    /// Sign it again — with a fresh nonce, as every signing does — and do NOT count it again. A
    /// service whose reply was lost has to be able to ask a second time, and two signatures over
    /// one transaction spend the same inputs, so only one of them can ever confirm.
    AlreadyAnswered(Box<ReleaseRecord>),
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

/// Result of a `boarding_session` step: either more sighashes to FROST-sign (mid-flight) or the
/// finalized VTXO (completion).
#[derive(Debug)]
pub enum BoardingSettleOutcome {
    Sighashes(Vec<Vec<u8>>),
    Submitted(BoardingSettleSubmitted),
}

