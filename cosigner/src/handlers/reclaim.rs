//! Taking back what is left of an escrow, once its deal is over.
//!
//! The other pairing over the same key. An escrow key `V'` is signed by two pairs — `{wallet,
//! cosigner}` and `{service, cosigner}` — and this is the first of them, the one the service is
//! not in. So reclaiming needs the owner present, and needs this cosigner to agree.
//!
//! ```text
//!   opened ─────────────────────────────────▶ deadline ──────────────────▶
//!     │  service + cosigner may release         │  wallet + cosigner may reclaim
//!     │  THIS is refused                        │  THIS is what runs
//!     └── or the owner closes it early ─────────┘
//! ```
//!
//! **Refused while the deal is live**, and that refusal is the whole of the owner's side of the
//! bargain. Both pairings sign the same key, so nothing but this stops an owner emptying an escrow
//! a service is still entitled to take from — which would make the commitment worth nothing.
//!
//! # Where it goes is not the caller's to say
//!
//! The destination is derived here, from the wallet key this cosigner already holds. It is not on
//! the wire and there is no field for it. A reclaim that could be pointed somewhere is a reclaim an
//! attacker who reached the device could point at themselves; deriving it means the worst a bad
//! caller can do is take their own money back.
//!
//! # Which inputs, and why the caller may name them
//!
//! This cosigner does not index an escrow's funds — it holds a key, not a view of the chain — so
//! the wallet names the VTXOs. That is safe for the same reason it is on a release: a taproot
//! sighash commits to every prevout amount and script, so an input claimed wrongly yields a
//! signature that verifies against nothing. The only claim that produces a usable signature is the
//! true one.

use ark::client::send::SendSession;
use ark::client::types::ArkInfo;

use crate::cosigner::Cosigner;
use crate::escrow_session::Refusal;
use crate::grpc::Status;
use crate::types::VtxoInput;

/// Everything the wallet needs to sign a reclaim, and to see what it is signing.
pub struct Reclaim {
    pub session: SendSession,
    pub sighashes: Vec<Vec<u8>>,
    /// The wallet's own Ark address, derived here.
    pub to_ark_address: String,
    /// What is being taken back — everything the named VTXOs hold.
    pub amount_sats: u64,
    /// The escrow's key material, for signing as `{wallet, cosigner}`.
    pub key_package: threshold::keys::KeyPackage,
    pub public_key_package: threshold::keys::PublicKeyPackage,
    pub wallet_identifier: threshold::identifier::Identifier,
    /// The two halves the wallet needs to rebuild its share of the escrow key.
    pub wallet_dealt_share: Vec<u8>,
    pub escrow_delta_share: Vec<u8>,
}

impl Cosigner {
    /// Build the reclaim, or say why there is not one to build.
    pub fn reclaim_open(
        &self,
        escrow_key: &str,
        vtxos: Vec<VtxoInput>,
        info: &ArkInfo,
        now: i64,
    ) -> Result<Reclaim, Status> {
        let escrow = self
            .escrow(escrow_key)
            .ok_or_else(|| Status::not_found("this wallet holds no such escrow"))?;

        // The deal first. An escrow with no session was never committed to anything, so there is
        // nothing holding it and the owner may take it back whenever they like.
        if let Some(session) = escrow.session.as_ref() {
            if let Err(refusal) = session.may_reclaim(now) {
                return Err(match refusal {
                    Refusal::StillOpen => Status::failed_precondition(refusal.message()),
                    // `may_reclaim` returns nothing else, and a new variant should be decided
                    // about rather than folded into the nearest existing answer.
                    other => Status::failed_precondition(other.message()),
                });
            }
        }

        if vtxos.is_empty() {
            return Err(Status::failed_precondition(
                "this escrow holds nothing to take back",
            ));
        }

        // The exit delay is DERIVED, not taken from the caller.
        //
        // It is part of a VTXO's taproot tree, so it decides the scriptPubKey the sighash commits
        // to — and an escrow's funds all arrive at one address, the one built at the ASP's
        // unilateral exit delay. A wallet legitimately holds a mix (a boarding-settled VTXO carries
        // a different delay) but an escrow cannot: nothing boards into one.
        //
        // So there is exactly one right answer, this cosigner already knows it, and asking the
        // caller could only introduce a wrong one. An indexer does not report the delay at all,
        // which is how a zero got in here and produced `OP_0 OP_CSV` — a script no ASP accepts.
        let exit_delay = info.unilateral_exit_delay as u32;
        let vtxos: Vec<VtxoInput> = vtxos
            .into_iter()
            .map(|v| VtxoInput { exit_delay, ..v })
            .collect();
        let amount_sats: u64 = vtxos
            .iter()
            .map(|v| v.amount_sats)
            .try_fold(0u64, |a, b| a.checked_add(b))
            .ok_or_else(|| Status::invalid_argument("those inputs total more sats than exist"))?;

        let delta = hex::decode(&escrow.wallet_delta_share_hex)
            .map_err(|e| Status::internal(format!("sealed escrow delta is not hex: {e}")))?;
        let wallet_id_bytes = hex::decode(&escrow.wallet_identifier_hex)
            .map_err(|e| Status::internal(format!("sealed wallet identifier is not hex: {e}")))?;
        // Answered only to the identifier the ceremony recorded — the same rule every other stream
        // applies, reached through the same function.
        let wallet_dealt_share = crate::handlers::recover::dealt_share_for(self, &wallet_id_bytes)?;

        let (key_package, public_key_package, wallet_identifier) = self
            .escrow_key_material(escrow_key)
            .ok_or_else(|| Status::internal("this escrow's sealed key material is unreadable"))?;

        // Where it goes: the wallet's own address, from the wallet's own key. Not on the wire.
        let owner_pk_hex = self.owner_pk_hex().map_err(Status::internal)?;
        let network = ark::client::parse_network(&info.network)
            .map_err(|e| Status::invalid_argument(format!("the ASP names a network we do not know: {e}")))?;
        let to_ark_address = ark::client::ark_address(
            &owner_pk_hex,
            &info.signer_pubkey,
            info.unilateral_exit_delay as u32,
            network,
        )
        .map_err(|e| Status::internal(format!("deriving where this wallet is paid: {e}")))?;

        // The escrow's key is the owner of what is being spent.
        let escrow_x_only = crate::cosigner::x_only(&escrow.escrow_key);
        let (session, _change_delay, sighashes) = crate::cosigner::build_send(
            &escrow_x_only,
            &vtxos,
            &crate::types::SendVtxoStep1 {
                recipient_ark_address: to_ark_address.clone(),
                // Everything, so there is no change and nothing is left behind in a key whose deal
                // is over.
                amount: amount_sats,
                vtxos: vtxos.clone(),
            },
            info,
        )
        .map_err(|e| Status::failed_precondition(format!("that reclaim does not build: {e}")))?;

        Ok(Reclaim {
            session,
            sighashes,
            to_ark_address,
            amount_sats,
            key_package,
            public_key_package,
            wallet_identifier,
            wallet_dealt_share,
            escrow_delta_share: delta,
        })
    }
}
