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
    /// The escrow keys this wallet has minted, newest last. `default` for seals written before
    /// escrow existed — a wallet with none simply has none.
    #[serde(default)]
    pub escrows: Vec<EscrowRecord>,
    /// Every external payment that has already justified a release, by the reference its provider
    /// knows it by.
    ///
    /// **On the wallet, deliberately, and not on the session that spent it.** A payment that
    /// succeeded goes on being true for ever, so what stops it being paid against twice is this
    /// record and nothing else — which means it has to outlive everything a service could arrange
    /// to have replaced. A ledger kept inside an [`EscrowSession`](crate::escrow_session::EscrowSession)
    /// would be emptied by reopening the deal, and would not be consulted at all by a second escrow
    /// paired to the same service. Both are ways to spend one payment twice.
    ///
    /// `default` for seals written before releases existed.
    #[serde(default)]
    pub released_references: std::collections::BTreeMap<String, ReleaseRecord>,
}

/// One release this wallet has made, filed under the payment that justified it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ReleaseRecord {
    /// Which escrow paid it, x-only so either parity resolves.
    pub escrow_key: String,
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
    /// back — the service may still hold these signatures unsubmitted, even if a newer deal has
    /// since been struck over the same escrow. `0` on a record written before this was kept: it
    /// answers no repeat and holds up no reclaim.
    #[serde(default)]
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

/// One escrow key this cosigner co-holds, sealed.
///
/// An escrow is a *second* 2-of-2 over a key of its own — `V' = V + Δ_wallet + Δ_cosigner`, minted
/// by a reshare so the wallet's own key is untouched and a service can be paired into the escrow
/// without being paired into the wallet. See `handlers::escrow`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EscrowRecord {
    /// `V'`, compressed hex. The escrow's identity, and the owner key of the Ark address it holds.
    pub escrow_key: String,
    /// This cosigner's share of `V'`.
    pub key_package_json: String,
    /// `V'`'s public package: the group key and both verifying shares.
    pub public_key_package_json: String,
    /// The wallet's FROST identifier in this escrow, as the reshare recorded it.
    pub wallet_identifier_hex: String,
    /// The derivation context the wallet dealt its delta under, hex. Kept so a repeat can be
    /// refused — two escrows on one delta are two points on one line.
    pub context_hex: String,
    /// `Δ_cosigner(id_wallet)`, hex: this cosigner's delta share for the wallet.
    ///
    /// The wallet keeps nothing; it rebuilds its escrow share per operation as
    /// `±[ s_wallet + Δ_wallet(id) + this ]`, where `s_wallet` is the wallet share it already
    /// rebuilds and `Δ_wallet` comes from its passkey. Kept as its own term and never pre-summed
    /// with `wallet_dealt_share_hex`: an even-Y normalisation sits between them, so a sum would be
    /// wrong for every wallet whose key came out with odd Y. See `handlers::escrow`.
    pub wallet_delta_share_hex: String,
    /// Unix seconds. Escrow is a session with a deadline, and this is where it started.
    pub created_at: i64,
    /// The service paired into this escrow, once one is. `None` until then — an escrow with no
    /// service is a key the wallet and this cosigner hold and nobody else can be paid from.
    #[serde(default)]
    pub pairing: Option<ServicePairing>,
    /// The live deal: what the service may take, and until when. `None` before a session is opened
    /// — a minted escrow is a key, not yet a commitment. See `crate::escrow_session`.
    #[serde(default)]
    pub session: Option<crate::escrow_session::EscrowSession>,
    /// When a reclaim was first opened on this escrow, if one ever was. From that moment the owner
    /// may hold signatures that empty it — whether the stream finished or not, the cosigner cannot
    /// see — so it may never again be committed to a deal. See `Cosigner::open_escrow_session`.
    #[serde(default)]
    pub reclaim_opened_at: Option<i64>,
}

/// Whether a pairing is finished.
///
/// A pairing is two deliveries by two routes, and it works only once the service holds both halves
/// and has checked the share they sum to. Until then it is [`Pending`](PairingState::Pending):
/// sealed, so a restart does not lose this cosigner's own share, and not usable, because a service
/// with one half can sign nothing.
///
/// Derived from two acknowledgements rather than set by whichever arrives — see
/// [`ServicePairing::state`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PairingState {
    /// At most one of the two parties has said the pairing works.
    Pending,
    /// The service has both halves and its share checks out, and the wallet agrees it delivered.
    Ready,
}

/// A service's way into one escrow: a second 2-of-2 over the same key `V'`.
///
/// Minted by a key-preserving refresh, so `V'` does not move — see `handlers::pairing`. What is
/// kept is this cosigner's own half of the pairing and the public package the service's share is
/// checked against. **Never the service's half**: it is handed over once at pairing and not
/// retained, because a party holding both halves holds the service's share.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ServicePairing {
    /// The service's FROST identifier in this pairing, hex.
    pub service_identifier_hex: String,
    /// This cosigner's share of the `{service, cosigner}` pairing.
    pub key_package_json: String,
    /// The pairing's public package. Its verifying key is `V'`, unchanged.
    pub public_key_package_json: String,
    /// The verifying share the service's own share must match, hex. Public.
    pub service_verifying_share_hex: String,
    /// Unix seconds.
    pub paired_at: i64,
    /// Which pairing attempt this is, hex. Both halves carry it, so the service can tell which two
    /// belong together — and a confirmation for another attempt is refused.
    #[serde(default)]
    pub attempt_id_hex: String,
    /// The SERVICE said, over the connection the runtime holds to it, that it has both halves and
    /// that the share they sum to matches the published verifying share.
    ///
    /// Only the service can know this: it is the only party that ever holds both halves. See
    /// `crate::service_stream`.
    #[serde(default)]
    pub service_confirmed: bool,
    /// The WALLET said it delivered its own half and the service took it.
    ///
    /// Only the wallet can know this: its half travels device-to-service and never through here.
    #[serde(default)]
    pub wallet_confirmed: bool,
}

impl ServicePairing {
    /// Whether this pairing may be committed to a deal.
    ///
    /// **Both** parties, because neither can answer for the other. The service is the only one
    /// that holds both halves, so only it can say the share checks out; the wallet is the only one
    /// that knows whether its own delivery landed. A pairing reported usable on one voice would be
    /// a pairing reported usable by a party that could not see the half it is vouching for — and
    /// an escrow committed against it would lock the owner's money away with nobody able to take
    /// it.
    ///
    /// `default` on both flags is false, so a seal that does not say is a pairing not shown to
    /// work.
    pub fn state(&self) -> PairingState {
        if self.service_confirmed && self.wallet_confirmed {
            PairingState::Ready
        } else {
            PairingState::Pending
        }
    }

    /// What is still missing, for a message that has to say so.
    pub fn awaiting(&self) -> &'static str {
        match (self.service_confirmed, self.wallet_confirmed) {
            (true, true) => "nothing",
            (false, true) => "the service has not confirmed it holds both halves and can sign",
            (true, false) => "the wallet has not confirmed it delivered its own half",
            (false, false) => "neither the service nor the wallet has confirmed it",
        }
    }
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
