//! Request-to-pay: the contact allowlist + the payer's payment-request inbox.
//!
//! A wallet allowlists a contact (one-way); that contact may then bill it. The payer's cosigner
//! checks the request was written by an allowlisted key, DERIVES the payee Ark address from that
//! key, and records the intent. The payer then signs the payment or declines.
//!
//! # Who is calling, and who wrote it
//!
//! Two different questions. The runtime answers the first for every request: a passkey approved it
//! and the tenant it resolved is on the header. For a payment request that caller is the PAYER — a
//! request cannot be sent to somebody else's cosigner, because the runtime resolves the tenant from
//! the caller's own token — so the request travels out of band and the payer's app submits it here.
//! The second question, whether the requester really wrote it, is answered by
//! [`RequestAuthorship`]: a signature by the requester's group key. See `mpc_wallet.proto`.
//!
//! Not a pre-signed transaction: FROST is 2-round interactive and Ark checkpoints need an ASP
//! counter-signature, so nothing can be signed ahead of approval.
//!


use crate::grpc::Status;

use crate::cosigner::Cosigner;
use crate::handlers::helpers::now_secs;
use crate::types::{Contact, IntentStatus, PaymentIntent};
use crate::wallet_proto::{
    ContactListRequest, ContactListResponse, PaymentRequestListRequest, PaymentRequestListResponse,
    RequestAuthorship,
};

use bitcoin::hashes::{sha256, Hash};
use bitcoin::secp256k1::{schnorr, Message, Secp256k1, XOnlyPublicKey};

/// Domain separation for the authorship digest. A payment-request signature must never be usable as
/// anything else — least of all a transaction sighash, which is also a 32-byte message signed by
/// this very key.
const REQUEST_DOMAIN: &[u8] = b"merlin/payment-request/v1";

/// How far ahead a request's `not_after` may be. It bounds how long a request is replayable and so
/// how many nonces a wallet has to remember — and a day is long enough for a link to sit in a chat.
pub const MAX_REQUEST_VALIDITY_SECS: i64 = 24 * 60 * 60;

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
    /// Owner-only, and that is the runtime's to decide: a request reaches this instance only with
    /// the tenant a passkey resolved to, and one tenant is one wallet.
    pub fn contact_list(
        &mut self,
        _req: ContactListRequest,
    ) -> Result<ContactListResponse, Status> {
        Ok(ContactListResponse {
            contacts: self.contacts().iter().map(contact_to_proto).collect(),
        })
    }

    /// The payer's request inbox, newest first. Owner-only, by the runtime — see `contact_list`.
    pub fn payment_request_list(
        &mut self,
        _req: PaymentRequestListRequest,
    ) -> Result<PaymentRequestListResponse, Status> {
        let now = now_secs();
        // Prune here too: otherwise it only runs when a NEW request arrives, so a payer who just
        // reads their inbox keeps seeing long-lapsed ones. Re-seal only if something changed.
        if self.prune_intents(now) {
            let group_key = self.group_key().to_string();
            crate::store::seal_snapshot_for(self, &group_key);
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
    /// Authorize a party to bill this wallet, by its GROUP key.
    ///
    /// The key is stored as given. It used to be run through `policy_owner_idx` so a caller could
    /// name a wallet by one of its share keys instead — a lookup that only worked while every wallet
    /// shared one store, and that now always misses: this wallet's store holds its own index and
    /// nobody else's. A request is matched against the key its author signs with, which is always the
    /// group key, so that is the only key an entry here can usefully be.
    pub fn contact_add(
        &mut self,
        req: crate::wallet_proto::ContactAddRequest,
    ) -> Result<crate::wallet_proto::ContactAddResponse, Status> {
        let vk_hex = compressed_key_hex(&req.contact_verifying_key, "contact key")?;
        self.add_contact(vk_hex, req.label, crate::store::now_secs())
            .map_err(Status::invalid_argument)?;
        self.seal();
        Ok(crate::wallet_proto::ContactAddResponse { ok: true })
    }

    /// Revoke a contact's authorization, re-closing the allowlist on `PaymentRequestCreate`.
    pub fn contact_remove(
        &mut self,
        req: crate::wallet_proto::ContactRemoveRequest,
    ) -> Result<crate::wallet_proto::ContactRemoveResponse, Status> {
        let vk_hex = compressed_key_hex(&req.contact_verifying_key, "contact key")?;
        self.remove_contact(&vk_hex).map_err(Status::not_found)?;
        self.seal();
        Ok(crate::wallet_proto::ContactRemoveResponse { ok: true })
    }

    /// A request to be paid, from someone this wallet has allowlisted.
    ///
    /// A request to be paid, written by somebody else and delivered by this wallet's owner.
    ///
    /// The order of the checks is deliberate. The signature comes first, so nothing about this
    /// wallet's state — its allowlist, the nonces it has seen — answers to an unsigned request. Then
    /// that it was addressed here, then that it is fresh, and only then whether its author may bill
    /// this wallet.
    pub fn payment_request_create(
        &mut self,
        req: crate::wallet_proto::PaymentRequestCreateRequest,
    ) -> Result<crate::wallet_proto::PaymentRequestCreateResponse, Status> {
        let now = crate::store::now_secs();
        let authorship = req
            .authorship
            .as_ref()
            .ok_or_else(|| Status::unauthenticated("a payment request must say who wrote it"))?;

        // 1. The requester wrote it.
        let from_vk_hex = verify_authorship(authorship, &req)?;

        // 2. It is addressed to this wallet — or it is a request to someone else, replayed here.
        let own = self
            .policy_group_key()
            .ok_or_else(|| Status::failed_precondition("this wallet has no key yet"))?;
        // Compared x-only. The parity byte is not part of a BIP-340 identity, and the key this wallet
        // sealed and the one its owner's app shows can differ in it without naming a different key.
        if !same_x_only(&hex::encode(&authorship.payer_group_key), &own) {
            return Err(Status::permission_denied(
                "this request was written for a different wallet",
            ));
        }

        // 3. It is fresh, and it has not been accepted before.
        if authorship.not_after <= now {
            return Err(Status::permission_denied("this request has expired"));
        }
        if authorship.not_after > now + MAX_REQUEST_VALIDITY_SECS {
            return Err(Status::invalid_argument(
                "a request may be valid for at most a day",
            ));
        }
        let nonce_hex = hex::encode(&authorship.nonce);
        self.seen_request_nonces.retain(|_, not_after| *not_after > now);
        if self.seen_request_nonces.contains_key(&nonce_hex) {
            return Err(Status::already_exists("this request has already been received"));
        }

        // 4. Its author may bill this wallet.
        if !self.is_contact(&from_vk_hex) {
            return Err(Status::permission_denied(
                "not an authorized contact of this wallet",
            ));
        }

        // Derive the payee address from the key that signed; never trust a supplied one, or a
        // contact could redirect the payment. x-only = compressed key minus its parity byte.
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

        self.seen_request_nonces
            .insert(nonce_hex, authorship.not_after);
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
        self.seal();

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

/// Whether two compressed keys, as hex, share an x coordinate.
fn same_x_only(a: &str, b: &str) -> bool {
    a.len() == 66 && b.len() == 66 && a[2..].eq_ignore_ascii_case(&b[2..])
}

/// A 33-byte compressed point, as hex — refused if it is anything else.
///
/// Format only. Whether it is a group key rather than a share key cannot be told from the bytes;
/// what makes a group key the only useful kind of contact is that requests are signed by one.
fn compressed_key_hex(bytes: &[u8], what: &str) -> Result<String, Status> {
    if bytes.len() != 33 || !matches!(bytes[0], 0x02 | 0x03) {
        return Err(Status::invalid_argument(format!(
            "{what} must be a 33-byte compressed public key"
        )));
    }
    XOnlyPublicKey::from_slice(&bytes[1..])
        .map_err(|_| Status::invalid_argument(format!("{what} is not a point on the curve")))?;
    Ok(hex::encode(bytes))
}

/// What the requester signs. Mirrored byte for byte by the Dart client's `requestDigest`.
///
/// ```text
/// sha256( domain ‖ payer ‖ requester ‖ amount ‖ expires_in ‖ not_after ‖ nonce ‖ sha256(memo) )
/// ```
///
/// Integers as 8-byte big-endian. The memo goes in hashed rather than raw so the digest has a fixed
/// shape and a memo cannot be crafted to look like the fields after it.
pub fn request_digest(
    authorship: &RequestAuthorship,
    amount_sats: u64,
    expires_in_secs: i64,
    memo: &str,
) -> [u8; 32] {
    let mut buf = Vec::with_capacity(REQUEST_DOMAIN.len() + 33 + 33 + 8 + 8 + 8 + 16 + 32);
    buf.extend_from_slice(REQUEST_DOMAIN);
    buf.extend_from_slice(&authorship.payer_group_key);
    buf.extend_from_slice(&authorship.requester_group_key);
    buf.extend_from_slice(&amount_sats.to_be_bytes());
    buf.extend_from_slice(&expires_in_secs.to_be_bytes());
    buf.extend_from_slice(&authorship.not_after.to_be_bytes());
    buf.extend_from_slice(&authorship.nonce);
    buf.extend_from_slice(sha256::Hash::hash(memo.as_bytes()).as_byte_array());
    *sha256::Hash::hash(&buf).as_byte_array()
}

/// Check the requester signed this request, and return the key they signed with, as hex.
///
/// BIP-340 against the requester's **group** key. Only the requester and their cosigner together
/// can produce that — which is what makes it the right key, and why a share key cannot stand in.
fn verify_authorship(
    authorship: &RequestAuthorship,
    req: &crate::wallet_proto::PaymentRequestCreateRequest,
) -> Result<String, Status> {
    let requester = compressed_key_hex(&authorship.requester_group_key, "requester key")?;
    compressed_key_hex(&authorship.payer_group_key, "payer key")?;
    if authorship.nonce.len() != 16 {
        return Err(Status::invalid_argument("a request nonce is 16 bytes"));
    }
    let signature = schnorr::Signature::from_slice(&authorship.signature)
        .map_err(|_| Status::invalid_argument("a request signature is 64 bytes, BIP-340"))?;

    let digest = request_digest(authorship, req.amount_sats, req.expires_in_secs, &req.memo);
    let key = XOnlyPublicKey::from_slice(&authorship.requester_group_key[1..])
        .map_err(|_| Status::invalid_argument("requester key is not a point on the curve"))?;
    Secp256k1::verification_only()
        .verify_schnorr(&signature, &Message::from_digest(digest), &key)
        .map_err(|_| Status::unauthenticated("the request signature does not verify"))?;
    Ok(requester)
}
