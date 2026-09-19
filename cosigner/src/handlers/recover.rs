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
//! re-keyed would strand the VTXOs, the delegate and the contacts the seal already holds — which is
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
    // The mirror of `refuse_if_onboarded`: there is nothing to recover before a ceremony.
    let (group_key, public_key_package_json) = match (
        c.policy_group_key(),
        c.policy_public_key_package_json(),
    ) {
        (Some(g), Some(p)) => (g, p),
        _ => {
            return Err(Status::failed_precondition(
                "this wallet has no key yet: there is nothing to recover, create one instead",
            ))
        }
    };

    let expected = c.user_signing_identifier().ok_or_else(|| {
        Status::failed_precondition("this wallet's ceremony recorded no owner identifier")
    })?;
    let asked: [u8; 32] = req.identifier.as_slice().try_into().map_err(|_| {
        Status::invalid_argument("identifier must be 32 bytes")
    })?;
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

    let dealt_share = c
        .wallet_dealt_share_hex()
        .ok_or_else(|| {
            Status::failed_precondition(
                "this wallet was created before recovery existed: the cosigner did not keep the \
                 share it dealt, and it cannot be recomputed",
            )
        })
        .and_then(|h| {
            hex::decode(h).map_err(|e| Status::internal(format!("sealed share is not hex: {e}")))
        })?;

    tracing::info!("Recover: returning the dealt share to the wallet's own identifier");
    Ok(RecoverResponse {
        dealt_share,
        public_key_package_json,
        group_key,
    })
}
