//! Renewing the delegate, on whichever stream carries it — `Send` or `Renew` — as one exchange:
//! what its round signs goes out, the wallet's signatures come in, the renewed delegate goes out.

use std::sync::{Arc, Mutex};

use crate::cosigner::Cosigner;
use crate::grpc::{Duplex, HasBody, Status};
use crate::session::{enrol_device, lock, proto};

/// A stream that carries the delegate exchange: how its own messages hold each step.
pub(crate) trait DelegateStream: Sized {
    /// What the wallet sends on this stream.
    type In: HasBody;

    /// What the delegate's round signs, with the wallet's dealt share when this is the stream's
    /// first round — empty otherwise.
    fn sighashes(session_id: &str, seq: u64, to_sign: ToSign, wallet_dealt_share: Vec<u8>) -> Self;

    /// The wallet's half of the round, if [body] is that.
    fn signed(body: <Self::In as HasBody>::Body) -> Option<Vec<proto::WalletRound>>;

    fn renewed(session_id: &str, seq: u64, renewed: proto::DelegateRenewed) -> Self;
}

/// What the delegate's round signs: the delegate's messages, then the exits', and this cosigner's
/// commitments for all of them.
pub(crate) struct ToSign {
    delegate: Vec<Vec<u8>>,
    exits: Vec<Vec<u8>>,
    commitments: Vec<crate::types::Commitment>,
}

/// A delegate being renewed: the round that signs it, open, and the exits it signs alongside.
pub(crate) struct DelegateRenew {
    round: crate::cosigner::InBandRound,
    exits: crate::handlers::delegate::PendingExits,
}

impl DelegateRenew {
    /// Renew the delegate [request] asks for, on [duplex]: the round's sighashes at [seq], the
    /// wallet's signatures in, and the renewed delegate at `seq + 1`.
    pub(crate) async fn run<S: DelegateStream>(
        cosigner: &Arc<Mutex<Cosigner>>,
        duplex: &Duplex<S::In, S>,
        mut request: proto::RenewDelegate,
        session_id: &str,
        seq: u64,
        wallet_dealt_share: Vec<u8>,
    ) -> Result<(), Status> {
        let device_token = std::mem::take(&mut request.device_token);
        let (renew, to_sign) = Self::build(cosigner, request)?;
        duplex.send(S::sighashes(session_id, seq, to_sign, wallet_dealt_share));
        let rounds = S::signed(duplex.next_body("the delegate's signatures").await?)
            .ok_or_else(|| Status::invalid_argument("expected the delegate's signatures"))?;
        let renewed = renew.finalise(cosigner, rounds, &device_token)?;
        duplex.send(S::renewed(session_id, seq + 1, renewed));
        Ok(())
    }

    /// Build the delegate over the set [request] reports, and open the round that signs it.
    fn build(
        cosigner: &Arc<Mutex<Cosigner>>,
        request: proto::RenewDelegate,
    ) -> Result<(Self, ToSign), Status> {
        let info = request
            .ark_info
            .map(ark::client::types::ArkInfo::from)
            .ok_or_else(|| Status::invalid_argument("RenewDelegate carried no ark_info"))?;
        let mut c = lock(cosigner);
        let (delegate, exits) = c
            .renew_delegate_open(
                request.vtxos.into_iter().map(Into::into).collect(),
                &info,
                &request.exit_script_pubkey,
            )
            .map_err(Status::failed_precondition)?;
        // One round over both halves, in that order: the wallet answers them as one list, and the
        // signatures come back the same way.
        let exit_sighashes = exits.sighashes();
        let all: Vec<Vec<u8>> = delegate.iter().chain(exit_sighashes.iter()).cloned().collect();
        let (round, commitments) = c.sign_in_band_begin(&all).map_err(Status::internal)?;
        Ok((Self { round, exits }, ToSign { delegate, exits: exit_sighashes, commitments }))
    }

    /// Finish the round, keep the delegate, and arm the watch — and enrol [device_token] for the
    /// wakes that watch sends, when the request carried one.
    fn finalise(
        self,
        cosigner: &Arc<Mutex<Cosigner>>,
        rounds: Vec<proto::WalletRound>,
        device_token: &str,
    ) -> Result<proto::DelegateRenewed, Status> {
        let device_enrolled = enrol_device(cosigner, device_token);
        let mut c = lock(cosigner);
        // A bad share is the caller's fault, and is reported as such.
        let signatures = c
            .sign_in_band_finish(self.round, rounds.into_iter().map(Into::into).collect())
            .map_err(Status::invalid_argument)?;
        let renewed = c
            .renew_delegate_finish(signatures, self.exits)
            .map_err(Status::internal)?;
        c.seal();
        Ok(proto::DelegateRenewed {
            valid_at_secs: renewed.valid_at,
            margin_secs: renewed.margin,
            covered: renewed.covered,
            device_enrolled,
            exit_txs: renewed
                .exits
                .into_iter()
                .map(|e| proto::ExitTx {
                    outpoint: e.outpoint,
                    raw_tx: e.raw_tx,
                    sequence: e.sequence,
                    amount_sats: e.amount_sats,
                })
                .collect(),
        })
    }
}

impl DelegateStream for proto::SendServerMsg {
    type In = proto::SendClientMsg;

    fn sighashes(session_id: &str, seq: u64, to_sign: ToSign, wallet_dealt_share: Vec<u8>) -> Self {
        Self {
            session_id: session_id.to_string(),
            seq,
            body: Some(proto::send_server_msg::Body::Sighashes(proto::SendSighashes {
                exit_messages: to_sign.exits,
                wallet_dealt_share,
                ..proto::SendSighashes::round(to_sign.delegate, to_sign.commitments)
            })),
        }
    }

    fn signed(body: proto::send_client_msg::Body) -> Option<Vec<proto::WalletRound>> {
        match body {
            proto::send_client_msg::Body::Signed(s) => Some(s.rounds),
            _ => None,
        }
    }

    fn renewed(session_id: &str, seq: u64, renewed: proto::DelegateRenewed) -> Self {
        Self {
            session_id: session_id.to_string(),
            seq,
            body: Some(proto::send_server_msg::Body::DelegateRenewed(renewed)),
        }
    }
}

impl DelegateStream for proto::RenewServerMsg {
    type In = proto::RenewClientMsg;

    fn sighashes(session_id: &str, seq: u64, to_sign: ToSign, wallet_dealt_share: Vec<u8>) -> Self {
        Self {
            session_id: session_id.to_string(),
            seq,
            body: Some(proto::renew_server_msg::Body::Sighashes(proto::RenewSighashes {
                exit_messages: to_sign.exits,
                wallet_dealt_share,
                ..proto::RenewSighashes::round(to_sign.delegate, to_sign.commitments)
            })),
        }
    }

    fn signed(body: proto::renew_client_msg::Body) -> Option<Vec<proto::WalletRound>> {
        match body {
            proto::renew_client_msg::Body::Signed(s) => Some(s.rounds),
            _ => None,
        }
    }

    fn renewed(session_id: &str, seq: u64, renewed: proto::DelegateRenewed) -> Self {
        Self {
            session_id: session_id.to_string(),
            seq,
            body: Some(proto::renew_server_msg::Body::DelegateRenewed(renewed)),
        }
    }
}
