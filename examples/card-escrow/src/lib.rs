//! A worked example: a card programme's settlement service, reimbursed out of a Bitcoin escrow.
//!
//! # What this demonstrates, and what it does not
//!
//! Alice commits Bitcoin to an escrow for card spending. She buys a $20 coffee. The card programme
//! settles that purchase with the merchant in fiat, as card programmes do, and then asks to be
//! **reimbursed** out of Alice's escrow. The cosigner inside the enclave verifies, for itself and
//! with its own read-only credential, that the purchase really cleared — and only then signs.
//!
//! ```text
//!   Alice taps ──▶ merchant ──▶ network ──▶ card programme ──▶ merchant paid, in fiat
//!                                                  │
//!                                                  │  "reimburse me for txn_clr_0001"
//!                                                  ▼
//!                                            this service
//!                                                  │  over the connection the runtime holds
//!                                                  ▼
//!                                             cosigner ──GET──▶ provider
//!                                                  │              "cleared, $20.00, that card"
//!                                                  ▼
//!                                       20,000 sats out of the escrow
//! ```
//!
//! **The Bitcoin release does not fund the card payment.** It reimburses a settlement that already
//! happened. Nothing here touches a card network, and nothing here is a card programme — the
//! payment side is simulated end to end, and every simulated record says so.
//!
//! # The pieces
//!
//! - [`provider`] — a deterministic mock of a card processor's read API, in which an authorization
//!   and its clearing are **two linked records** rather than one object with a flag. Plus
//!   [`provider::marqeta`], the real-sandbox adapter, with what is verified separated from what is
//!   not.
//! - [`policy`] — the deal, written down: destination, per-purchase cap, total allowance, the fixed
//!   conversion, and the six things the evidence must show.
//! - [`service`] — the settlement service itself: it holds half of the escrow key, watches the card
//!   lifecycle, asks for reimbursement only once a purchase has cleared, and submits exactly the
//!   transaction the cosigner approved.
//!
//! # What is real
//!
//! The escrow, the pairing, the policy evaluation, the evidence fetch, the threshold signature and
//! the Ark transaction are all the production code paths, imported rather than restated. What is
//! simulated is the card network and the payment processor behind it.

pub mod policy;
pub mod provider;
pub mod service;
