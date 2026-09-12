//! Per-user mutable state. Owned by the user's actor task; never upstreams.

use serde::{Deserialize, Serialize};

use std::collections::HashMap;

use crate::types::{arr32_hex, ContractPairing};

/// One VTXO owned by the user. Persisted in `vtxo_store`. `created_at` and
/// `expires_at` come from the ASP `Vtxo` event and feed the auto-settle
/// threshold check; older rows lacking them deserialize to 0 (treated as
/// "unknown expiry" — auto-settle skips conservatively).
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

/// A signed `DelegateSettleSession` waiting for the auto-settle tick task to
/// drive it. `covered_outpoints` is the set of VTXOs the FROST signatures
/// authorize the cosigner to spend; if any of them is consumed by another
/// path (manual settle, send) the whole delegate is invalidated and the
/// client must re-delegate after the next receive.
pub struct DelegateRecord {
    pub session: ark::client::batch::DelegateSettleSession,
    pub covered_outpoints: Vec<(String, u32)>,
    /// Earliest `expires_at` across `covered_outpoints` — what the tick
    /// task compares `now` against.
    pub earliest_expires_at: i64,
    /// True while the cosigner is still waiting on the client's FROST
    /// signature shares for this delegate's sighashes — i.e. between
    /// `SettleDelegate` Phase 1 (returns sighashes) and Phase 2 (receives
    /// signatures). The sign-step1 policy bypass only applies during this
    /// window. Once signatures are stored, the record persists for the
    /// tick task but subsequent unrelated `SignStep1` calls (e.g. an
    /// off-chain Ark send) must again be policy-gated.
    pub awaiting_signatures: bool,
}

/// Sled-persisted projection of a `DelegateRecord`. Mirrors the in-memory
/// shape but uses `PersistedDelegate` (no cosigner secret — looked up from
/// `SecretStore` at rehydration time) so the on-disk JSON contains no
/// long-lived key material. See GitHub issue #31 for the rationale.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PersistedDelegateRecord {
    pub session: ark::client::batch::PersistedDelegate,
    pub covered_outpoints: Vec<(String, u32)>,
    pub earliest_expires_at: i64,
}

/// One device the user has registered for FCM push notifications.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DeviceToken {
    pub fcm_token: String,
    pub platform: String,
    pub registered_at: i64,
    #[serde(default)]
    pub app_version: String,
}

pub struct CosignerState {
    /// This cosigner actor's id (hex), set by the registry at spawn time — the
    /// GROUP KEY it co-signs for: `V` for a normal 2-of-2 wallet, `V′` for a
    /// contract. NOT "one user": a contract actor serves many members, each
    /// authenticated by their own verifying share (see `group_auth_idx` +
    /// `EvtxoPolicy.recipient_shares`). Handlers use it to scope persistence keys
    /// and as the group id for `auth_check_group`.
    pub cosigner_id: String,

    /// Active delegate-settle session — stored signed intent + scope.
    pub delegate_session: Option<DelegateRecord>,

    pub vtxos: Vec<VtxoEntry>,
    /// VTXO scriptPubKeys this user owns. Used by the registry's reverse index.
    pub owned_scripts: Vec<String>,
    /// Registered FCM/APNS device tokens. Pushes go to all of them.
    pub device_tokens: Vec<DeviceToken>,

    /// Guest-routed delegate-settle marker: the threshold timestamp (`intent_valid_at`, i.e.
    /// earliest VTXO expiry − safety margin) at/after which `TickAutoSettle` should drive the
    /// guest's stored `ReadyToSettle` delegate. The delegate session itself lives in the
    /// guest (durable via the sealed snapshot); this is the non-secret "when to fire" gate.
    /// `Some(0)` means fire on the next tick (legacy short window). Cleared after settling.
    pub guest_delegate_threshold: Option<i64>,

    /// Non-secret policy metadata (FROST *public* key package JSON, signing identifier,
    /// cosigner_id) loaded from persistence. Used for routing + address/amount derivation;
    /// the signing keys themselves live in the guest. Formerly on `CosignerInstance`.
    pub policy_state: Option<crate::state::PolicyState>,
    /// The user's UTXOs, for tx-parse / spent-amount calculation. Formerly on `CosignerInstance`.
    pub utxo_state: Option<crate::state::UtxoState>,
}

impl CosignerState {
    pub fn new(cosigner_id: String) -> Self {
        Self {
            cosigner_id,
            delegate_session: None,
            vtxos: Vec::new(),
            owned_scripts: Vec::new(),
            device_tokens: Vec::new(),
            guest_delegate_threshold: None,
            policy_state: None,
            utxo_state: None,
        }
    }
}

impl Default for CosignerState {
    fn default() -> Self {
        Self::new(String::new())
    }
}

// ===========================================================================
// Policy projection types (folded in from the former `policy` module). The host's PUBLIC view of a
// cosigner's policy; the secret key lives only in the Cosigner seal.
// ===========================================================================

/// Per-user policy state. Mirrors `PolicyState` from `server/lib/state.dart`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PolicyState {
    /// This group's cosigner id (hex) = the GROUP KEY: `V` for a normal 2-of-2
    /// wallet, `V′` for a contract. Policies are keyed under it; clients addressing
    /// by a member's verifying share resolve here via `policy_owner_idx`.
    pub cosigner_id: String,
    /// The wallet's DKG identifier (may differ from Identifier::derive(userId)
    /// when the wallet is a passive receiver).
    pub user_signing_identifier_hex: Option<String>,
    /// Server's original DKG secret (hex-encoded 32-byte scalar).
    /// Persisted separately via SecretStore (not included in storage JSON).
    #[serde(skip)]
    pub server_dkg_secret_hex: Option<String>,
    /// The user's normal 2-of-2 {user, cosigner} spending key.
    pub normal_policy: NormalPolicy,
    /// Contracts created by this user, keyed by contract scriptPubKey (hex). Each
    /// binds a reshared 2-of-2 key V′ to a WASM contract, with the cosigner's
    /// counter-share for each signing pairing (the user and the always-online
    /// service).
    #[serde(default)]
    pub contracts: HashMap<String, ContractPolicy>,
    /// Set ONLY on a `{service, cosigner}` pairing actor (Tier 2 service co-sign).
    /// Its presence marks this actor as a service co-signer that may sign nothing
    /// EXCEPT a contract-approved spend of the one eVTXO named here: the sign path
    /// rebuilds the cooperative-leaf sighash from these params and signs only that,
    /// so a compromised service cannot co-sign a `V` spend of the wallet's normal
    /// funds. `normal_policy` holds the cosigner's pairing counter-share + the V PKP.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub contract_pairing: Option<ContractPairing>,
}

/// Normal (default) spending policy.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NormalPolicy {
    pub id: String,
    /// Key package as JSON string (from WASM).
    pub key_package_json: String,
    /// Public key package as JSON string (from WASM).
    pub public_key_package_json: String,
}

/// Hex of a compressed verifying key (a participant's verifying share / group key).
/// Kept as a `String` because it is a JSON map key (serde requires string keys) and is
/// compared directly against wire-provided verifying-key hex.
pub type VerifyingKeyHex = String;

/// A contract bound to a WASM `contract_id`. NO distinct key: the wallet's normal key `V` is
/// reused. The cosigner GATE is the sole binding — it co-signs a contract eVTXO spend only
/// when (1) the WASM `evaluate` returns Allow and (2) the requesting verifying share is on the
/// allowlist (`wallet_vk` ∪ `authorized_service_vks`).
///
/// The WALLET signs contract spends with its existing normal `V` pairing. The always-online
/// SERVICE gets a key-preserving REFRESH of `V` onto `{service, cosigner}` at create time; the
/// cosigner's counter-share lives in the SEPARATE pairing actor's guest (Plan A — never stored
/// here), so this struct holds only the gate's PUBLIC metadata + the authorized-signer allowlist.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ContractPolicy {
    /// Contract that governs cooperative spends: sha256(component_wasm).
    #[serde(with = "arr32_hex")]
    pub contract_id: [u8; 32],
    /// The WALLET's own verifying-share hex — an authorized signer that uses the normal `V`
    /// pairing. Included in the allowlist.
    pub wallet_vk: VerifyingKeyHex,
    /// Unilateral-exit CSV delay (the exit leaf).
    pub exit_delay: u32,
    /// User-supplied exit-leaf owner x-only key, for the taptree.
    #[serde(with = "arr32_hex")]
    pub owner_pk: [u8; 32],

    /// Service verifying keys authorized to co-sign this contract (the gate allowlist). Each has
    /// a `{service, cosigner}` pairing whose cosigner counter-share lives in its own guest actor.
    #[serde(default, alias = "shares")]
    pub authorized_service_vks: Vec<VerifyingKeyHex>,
}

impl ContractPolicy {
    /// The verifying shares authorized to sign this contract: the wallet (normal `V`) plus every
    /// authorized service. The gate co-signs only for these.
    pub fn authorized_verifying_keys(&self) -> Vec<VerifyingKeyHex> {
        let mut keys = vec![self.wallet_vk.clone()];
        keys.extend(self.authorized_service_vks.iter().cloned());
        keys
    }
}

/// Per-user UTXO cache.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct UtxoState {
    pub user_id: String,
    pub utxos: Vec<Utxo>,
}

/// A single unspent transaction output.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Utxo {
    pub tx_hash: String,
    pub vout: u32,
    pub amount_sats: i64,
}
