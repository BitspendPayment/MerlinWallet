//! Rebuilding a wallet on a new device, from nothing but its passkey.
//!
//! # Why half a key is sitting here
//!
//! A FROST share is the sum of every dealer's polynomial evaluated at the participant's identifier.
//! For this 2-of-2 that is two terms:
//!
//! ```text
//!   s_wallet = f_wallet(id_wallet) + f_cosigner(id_wallet)
//! ```
//!
//! The wallet's own dealer is no longer random: it is derived from the passkey's PRF output, which
//! the platform syncs with the passkey, so a new phone that can use the passkey can reproduce
//! `f_wallet` exactly — and with it `id_wallet`, which is derived from `a0·G`. The second term it
//! cannot reproduce: the cosigner's polynomial was destroyed when the ceremony ended. So the
//! cosigner keeps the one scalar it dealt out, and hands it back here.
//!
//! # What this is not
//!
//! It is not a key escrow. The scalar returned is one term of a sum whose other term exists only
//! behind the owner's biometric; alone it signs nothing and identifies nothing. And it is not a
//! ceremony: nothing is installed, no policy is written, no share is re-keyed. A recovery that
//! re-keyed would strand the VTXOs, the delegate and the escrows the seal already holds — which is
//! exactly the accident `refuse_if_onboarded` exists to prevent, and this is its mirror image: that
//! one refuses when a policy exists, this one refuses when none does.
//!
//! # Who may call it
//!
//! The runtime resolved the tenant from the caller's passkey before this was reached; there is no
//! second authentication to do here and none is invented. What is checked instead is that the
//! passkey used is the *right* one: the caller sends the identifier it derived, and a mismatch is
//! refused rather than answered. A wallet whose PRF output changed is a wallet that can no longer
//! sign, and it is far better to say so than to hand back a share that will not add up.

use crate::cosigner::Cosigner;
use crate::grpc::Status;
use crate::session::proto::{RecoverRequest, RecoverResponse};

use threshold::identifier::Identifier;

pub fn recover(c: &Cosigner, req: RecoverRequest) -> Result<RecoverResponse, Status> {
    let dealt_share = dealt_share_for(c, &req.identifier)?;
    // `dealt_share_for` has already refused a wallet with no key, so these are there.
    let (group_key, public_key_package_json) = match (
        c.policy_group_key(),
        c.policy_public_key_package_json(),
    ) {
        (Some(g), Some(p)) => (g, p),
        _ => return Err(Status::internal("the wallet has a dealt share and no key package")),
    };

    let now = crate::handlers::helpers::now_secs();
    tracing::info!("Recover: returning the dealt share to the wallet's own identifier");
    Ok(RecoverResponse {
        dealt_share,
        public_key_package_json,
        group_key,
        escrows: c.escrows().iter().map(|e| e.summary(now)).collect(),
    })
}

/// The half of the wallet's share the cosigner dealt at DKG, for the wallet that is [identifier].
///
/// `Recover` hands it to a device that has nothing. `Sign`, `Send` and `Renew` hand it back on
/// their first round, every time, because the wallet keeps no share between operations any more:
/// it re-derives its own half from the passkey and adds this one, under the approval the stream
/// already has. One rule for all four, so there is one place it can be wrong.
///
/// What this guards, and what it does not. The caller was authenticated by the runtime as this
/// tenant before any of this ran, and a tenant's seal is the only one this instance can read — that
/// is what keeps one tenant's half from another, and it is not re-implemented here. The identifier
/// is public (it is in the key package and on the wire), so matching it proves nothing about who
/// is asking. It proves the wallet asking is *this* wallet: a wrong passkey, or a PRF that answers
/// differently, derives another identifier and is told so instead of being handed a share that
/// would not add up.
///
/// Never the cosigner's own share — that is `key_package.secret_share`, and nothing returns it.
pub(crate) fn dealt_share_for(c: &Cosigner, identifier: &[u8]) -> Result<Vec<u8>, Status> {
    // The mirror of `refuse_if_onboarded`: there is nothing to hand back before a ceremony.
    if c.policy_group_key().is_none() {
        return Err(Status::failed_precondition(
            "this wallet has no key yet: there is nothing to recover, create one instead",
        ));
    }

    let expected = c.user_signing_identifier().ok_or_else(|| {
        Status::failed_precondition("this wallet's ceremony recorded no owner identifier")
    })?;
    let asked: [u8; 32] = identifier
        .try_into()
        .map_err(|_| Status::invalid_argument("identifier must be 32 bytes"))?;
    let asked = Identifier::deserialize(&asked)
        .map_err(|e| Status::invalid_argument(format!("bad identifier: {e}")))?;
    if asked != expected {
        // Not "wrong passkey" necessarily — a PRF that answers differently on this device looks
        // exactly the same from here. Either way the share would not add up, so say so now.
        return Err(Status::permission_denied(
            "that passkey does not derive this wallet's owner key: the share it rebuilt would not \
             be able to sign",
        ));
    }

    c.wallet_dealt_share_hex()
        .ok_or_else(|| {
            Status::failed_precondition(
                "this wallet was created before recovery existed: the cosigner did not keep the \
                 share it dealt, and it cannot be recomputed",
            )
        })
        .and_then(|h| {
            hex::decode(h).map_err(|e| Status::internal(format!("sealed share is not hex: {e}")))
        })
}
