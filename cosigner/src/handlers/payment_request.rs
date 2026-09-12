//! Request-to-pay: the contact allowlist + the payer's payment-request inbox.
//!
//! A wallet allowlists a contact (one-way); that contact may then bill it. The payer's cosigner
//! checks the allowlist, DERIVES the requester's Ark address from the allowlisted key, and records
//! the intent. The payer then signs the payment or declines.
//!
//! Not a pre-signed transaction: FROST is 2-round interactive and Ark checkpoints need an ASP
//! counter-signature, so nothing can be signed ahead of approval.
//!
//! Read paths live here; mutating paths are `route_*` fns in [`crate::registry`], since
//! every change re-seals the snapshot.

use tonic::Status;

use crate::cosigner::Cosigner;
use crate::handlers::helpers::now_secs;
use crate::types::{Contact, IntentStatus, PaymentIntent};
use crate::wallet_proto::{
    ContactListRequest, ContactListResponse, PaymentRequestListRequest, PaymentRequestListResponse,
};

/// Domain → wire.
pub fn contact_to_proto(c: &Contact) -> crate::wallet_proto::Contact {
    crate::wallet_proto::Contact {
        verifying_key: hex::decode(&c.vk_hex).unwrap_or_default(),
        label: c.label.clone(),
        added_at: c.added_at,
    }
}

/// Domain → wire. `now` lets a still-`Pending` but elapsed intent report as `expired` without
/// mutating (and therefore re-sealing) state on a read.
pub fn intent_to_proto(i: &PaymentIntent, now: i64) -> crate::wallet_proto::PaymentIntent {
    let status = if i.status == IntentStatus::Pending && now >= i.expires_at {
        IntentStatus::Expired
    } else {
        i.status
    };
    crate::wallet_proto::PaymentIntent {
        id: i.id.clone(),
        from_verifying_key: hex::decode(&i.from_vk_hex).unwrap_or_default(),
        to_ark_address: i.to_ark_address.clone(),
        amount_sats: i.amount_sats,
        memo: i.memo.clone(),
        created_at: i.created_at,
        expires_at: i.expires_at,
        status: status.as_str().to_string(),
        ark_txid: i.ark_txid.clone(),
    }
}

impl Cosigner {
    /// The parties this wallet has authorized to bill it.
    ///
    /// Auth (`OP_CONTACT_LIST`) ran at the REST boundary, which only proves the
    /// caller holds the key it named — `require_owner` is what ties that key to
    /// THIS wallet, otherwise any keypair could read anyone's allowlist.
    pub async fn contact_list(
        &mut self,
        req: ContactListRequest,
    ) -> Result<ContactListResponse, Status> {
        self.require_owner(&req.user_id)?;
        Ok(ContactListResponse {
            contacts: self.contacts().iter().map(contact_to_proto).collect(),
        })
    }

    /// The payer's request inbox, newest first.
    ///
    /// Auth (`OP_PAYREQ_LIST`) ran at the REST boundary; `require_owner` binds the
    /// authenticated key to this wallet so a stranger cannot read the inbox
    /// (amounts, memos, counterparties) of any wallet they can name.
    pub async fn payment_request_list(
        &mut self,
        req: PaymentRequestListRequest,
    ) -> Result<PaymentRequestListResponse, Status> {
        self.require_owner(&req.user_id)?;
        let now = now_secs();
        // Prune here too: otherwise it only runs when a NEW request arrives, so a payer who just
        // reads their inbox keeps seeing long-lapsed ones. Re-seal only if something changed.
        if self.prune_intents(now) {
            let group_key = self.group_key().to_string();
            crate::store::seal_snapshot_for(self, &group_key).await;
        }
        let mut intents: Vec<_> = self
            .payment_intents()
            .iter()
            .map(|i| intent_to_proto(i, now))
            .collect();
        intents.sort_by(|a, b| b.created_at.cmp(&a.created_at));
        Ok(PaymentRequestListResponse { intents })
    }
}

impl Cosigner {
    /// Authorize a party to bill this wallet. Contacts are compared by GROUP key, so whichever of
    /// a wallet's ids the caller names, the allowlist stores the canonical one.
    pub async fn contact_add(
        &mut self,
        req: crate::wallet_proto::ContactAddRequest,
    ) -> Result<crate::wallet_proto::ContactAddResponse, Status> {
        self.require_owner(&req.user_id)?;
        let vk_hex = super::helpers::group_key_of(
            self.store.as_ref(),
            &hex::encode(&req.contact_verifying_key),
        );
        self.add_contact(vk_hex, req.label, crate::store::now_secs())
            .map_err(Status::invalid_argument)?;
        self.seal().await;
        Ok(crate::wallet_proto::ContactAddResponse { ok: true })
    }

    /// Revoke a contact's authorization, re-closing the only gate on `PaymentRequestCreate`.
    pub async fn contact_remove(
        &mut self,
        req: crate::wallet_proto::ContactRemoveRequest,
    ) -> Result<crate::wallet_proto::ContactRemoveResponse, Status> {
        self.require_owner(&req.user_id)?;
        let vk_hex = super::helpers::group_key_of(
            self.store.as_ref(),
            &hex::encode(&req.contact_verifying_key),
        );
        self.remove_contact(&vk_hex).map_err(Status::not_found)?;
        self.seal().await;
        Ok(crate::wallet_proto::ContactRemoveResponse { ok: true })
    }

    /// A request to be paid, from someone this wallet has allowlisted.
    ///
    /// Signed by the REQUESTER, not the payer — the payer's contact list is the whole of the
    /// authorization, which is why the gate runs before anything else here.
    pub async fn payment_request_create(
        &mut self,
        req: crate::wallet_proto::PaymentRequestCreateRequest,
    ) -> Result<crate::wallet_proto::PaymentRequestCreateResponse, Status> {
        // Resolve whichever id the requester used to its GROUP key: the canonical allowlist
        // identity, and the key the payee address MUST derive from — a share key yields an address
        // the requester cannot spend, while the payment still appears to succeed.
        let from_vk_hex = super::helpers::group_key_of(
            self.store.as_ref(),
            &hex::encode(&req.user_id),
        );
        if !self.is_contact(&from_vk_hex) {
            return Err(Status::permission_denied(
                "not an authorized contact of this wallet",
            ));
        }

        // Derive the payee address from the allowlisted key; never trust a supplied one, or a
        // contact could redirect the payment. x-only = compressed key minus its parity byte.
        if from_vk_hex.len() != 66 {
            return Err(Status::invalid_argument(
                "requester key must be a 33-byte compressed pubkey",
            ));
        }
        let owner_xonly = from_vk_hex[2..].to_string();
        let info = req
            .ark_info
            .clone()
            .ok_or_else(|| Status::invalid_argument("request carried no ark_info"))?;
        let network = ark::client::parse_network(&info.network).map_err(Status::internal)?;
        let to_ark_address = ark::client::ark_address(
            &owner_xonly,
            &info.signer_pubkey,
            info.unilateral_exit_delay as u32,
            network,
        )
        .map_err(|e| Status::internal(format!("derive ark address: {e}")))?;

        let now = crate::store::now_secs();
        let intent = self
            .create_payment_intent(
                from_vk_hex,
                to_ark_address,
                req.amount_sats,
                req.memo,
                req.expires_in_secs,
                now,
            )
            .map_err(Status::invalid_argument)?;
        self.seal().await;

        // No nudge from here. The cosigner used to push to the payer's device, which needed an
        // FCM client, an outbound socket, and a detached task that outlived the call — in a
        // per-request runtime it would fire after the instance was gone. Waking a device is the
        // host's, through its task queue. The sealed intent is the durable record either way, and
        // the app polls on resume.
        Ok(crate::wallet_proto::PaymentRequestCreateResponse {
            intent: Some(intent_to_proto(&intent, now)),
        })
    }
}
