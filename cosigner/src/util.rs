//! Conversions between the wire types and the cosigner's own, and the projections of its records
//! onto the wire.

use crate::grpc::Status;
use crate::session::proto;
use crate::wallet_proto as wp;

impl crate::types::EscrowRecord {
    /// This escrow as a caller may see it: the public projection, as of [now]. What `EscrowList`
    /// returns, and what `Recover` hands a new device so it can rebuild its escrows the way it
    /// rebuilt the wallet.
    pub(crate) fn summary(&self, now: i64) -> proto::EscrowSummary {
        proto::EscrowSummary {
            escrow_key: self.escrow_key.clone(),
            wallet_identifier: hex::decode(&self.wallet_identifier_hex).unwrap_or_default(),
            public_key_package_json: self.public_key_package_json.clone(),
            created_at: self.created_at,
            service_identifier: self
                .pairing
                .as_ref()
                .map(|p| p.service_identifier_hex.clone())
                .unwrap_or_default(),
            service_ready: self
                .pairing
                .as_ref()
                .is_some_and(|p| p.state() == crate::types::PairingState::Ready),
            // Reported apart as well as together: they arrive by different routes, at
            // different moments, and a caller waiting on one wants to know which.
            service_confirmed: self
                .pairing
                .as_ref()
                .is_some_and(|p| p.service_confirmed),
            wallet_confirmed: self
                .pairing
                .as_ref()
                .is_some_and(|p| p.wallet_confirmed),
            session: self.session.as_ref().map(|s| proto::EscrowSessionSummary {
                // Whether it still holds the escrow: a spent deal lets the next one be struck.
                open: s.holds_the_escrow(now),
                deadline_secs: s.deadline,
                opened_at: s.opened_at,
                released_sats: s.released_sats,
                policy_description: s.policy.describe(),
            }),
            context: hex::decode(&self.context_hex).unwrap_or_default(),
            reclaim_opened: self.reclaim_opened_at.is_some(),
        }
    }
}

/// The wallet's half of an in-band round, off the wire.
impl From<proto::WalletRound> for crate::cosigner::WalletHalf {
    fn from(r: proto::WalletRound) -> Self {
        Self { hiding: r.hiding, binding: r.binding, share: r.share }
    }
}

/// The wallet's half of a single-message round, as `Sign` carries it.
impl From<proto::SignShare> for crate::cosigner::WalletHalf {
    fn from(s: proto::SignShare) -> Self {
        Self { hiding: s.hiding_commitment, binding: s.binding_commitment, share: s.signature_share }
    }
}

impl From<crate::types::Commitment> for proto::Commitment {
    fn from(c: crate::types::Commitment) -> Self {
        Self { hiding: c.hiding, binding: c.binding }
    }
}

/// The identifier every commitment in a batch shares — they are all the cosigner's.
fn identifier_of(commitments: &[crate::types::Commitment]) -> String {
    commitments.first().map(|c| c.identifier_hex.clone()).unwrap_or_default()
}

impl proto::SendSighashes {
    /// A send's sighashes with the cosigner's half of round one. Always script-path: the cosigner
    /// signs untweaked, and in-band signing cannot compensate a tweak — see
    /// `Cosigner::sign_in_band_begin`.
    pub(crate) fn round(messages_to_sign: Vec<Vec<u8>>, commitments: Vec<crate::types::Commitment>) -> Self {
        Self {
            messages_to_sign,
            script_path_spend: true,
            cosigner_identifier: identifier_of(&commitments),
            cosigner_commitments: commitments.into_iter().map(Into::into).collect(),
            ..Default::default()
        }
    }
}

impl proto::RenewSighashes {
    /// A renewal's sighashes with the cosigner's half of round one — see
    /// [`proto::SendSighashes::round`].
    pub(crate) fn round(messages_to_sign: Vec<Vec<u8>>, commitments: Vec<crate::types::Commitment>) -> Self {
        Self {
            messages_to_sign,
            script_path_spend: true,
            cosigner_identifier: identifier_of(&commitments),
            cosigner_commitments: commitments.into_iter().map(Into::into).collect(),
            ..Default::default()
        }
    }
}

impl From<proto::VtxoInput> for crate::types::VtxoInput {
    fn from(i: proto::VtxoInput) -> Self {
        Self {
            txid: i.txid,
            vout: i.vout,
            amount_sats: i.amount_sats,
            exit_delay: i.exit_delay,
            expires_at: i.expires_at,
        }
    }
}

impl From<&ark::client::types::ArkInfo> for wp::ArkInfo {
    fn from(i: &ark::client::types::ArkInfo) -> Self {
        Self {
            signer_pubkey: i.signer_pubkey.clone(),
            forfeit_pubkey: i.forfeit_pubkey.clone(),
            forfeit_address: i.forfeit_address.clone(),
            checkpoint_tapscript: i.checkpoint_tapscript.clone(),
            network: i.network.clone(),
            session_duration: i.session_duration,
            unilateral_exit_delay: i.unilateral_exit_delay,
            boarding_exit_delay: i.boarding_exit_delay,
            vtxo_min_amount: i.vtxo_min_amount,
            dust: i.dust,
        }
    }
}

impl From<wp::ArkInfo> for ark::client::types::ArkInfo {
    fn from(i: wp::ArkInfo) -> Self {
        Self {
            signer_pubkey: i.signer_pubkey,
            forfeit_pubkey: i.forfeit_pubkey,
            forfeit_address: i.forfeit_address,
            checkpoint_tapscript: i.checkpoint_tapscript,
            network: i.network,
            session_duration: i.session_duration,
            unilateral_exit_delay: i.unilateral_exit_delay,
            boarding_exit_delay: i.boarding_exit_delay,
            vtxo_min_amount: i.vtxo_min_amount,
            dust: i.dust,
        }
    }
}

impl From<crate::renew::AspCall> for proto::AspSubmit {
    fn from(call: crate::renew::AspCall) -> Self {
        use crate::renew::AspCall;
        use proto::asp_submit::Call;
        let call = match call {
            AspCall::ConfirmRegistration { intent_id } => {
                Call::ConfirmRegistration(proto::ConfirmRegistration { intent_id })
            }
            AspCall::TreeNonces { batch_id, pubkey, nonces } => {
                Call::TreeNonces(proto::TreeNonces {
                    batch_id,
                    pubkey,
                    nonces: nonces.into_iter().collect(),
                })
            }
            AspCall::TreeSignatures { batch_id, pubkey, signatures } => {
                Call::TreeSignatures(proto::TreeSignatures {
                    batch_id,
                    pubkey,
                    signatures: signatures.into_iter().collect(),
                })
            }
            AspCall::ForfeitTxs { signed_txs, signed_commitment_b64 } => {
                Call::ForfeitTxs(proto::ForfeitTxs {
                    signed_forfeit_txs: signed_txs,
                    signed_commitment_tx: signed_commitment_b64,
                })
            }
        };
        Self { call: Some(call) }
    }
}

/// One `GetEventStreamResponse` as it came off the ASP, relayed by the wallet. `None` when the
/// response carried no event, which the ASP does send — a keepalive is not an error.
impl TryFrom<proto::AspEvent> for Option<ark::client::proto::get_event_stream_response::Event> {
    type Error = Status;

    fn try_from(e: proto::AspEvent) -> Result<Self, Status> {
        use prost::Message as _;
        let resp = ark::client::proto::GetEventStreamResponse::decode(e.encoded.as_slice())
            .map_err(|e| Status::invalid_argument(format!("undecodable ASP event: {e}")))?;
        Ok(resp.event)
    }
}

/// Every client message carries its payload in a `oneof body`, which prost makes an `Option` field.
macro_rules! has_body {
    ($($msg:ident => $body:ident),* $(,)?) => {$(
        impl crate::grpc::HasBody for proto::$msg {
            type Body = proto::$body::Body;

            fn into_body(self) -> Option<Self::Body> {
                self.body
            }
        }
    )*};
}

has_body! {
    DkgClientMsg => dkg_client_msg,
    SignClientMsg => sign_client_msg,
    SendClientMsg => send_client_msg,
    RenewClientMsg => renew_client_msg,
    EscrowClientMsg => escrow_client_msg,
}
