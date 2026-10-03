//! Escrows, end to end: the key minted for one payment, the service paired into it, the one deal
//! it is committed to, and the connection that service speaks on. Nothing outside this module
//! knows what a service is.
//!
//! An escrow key is signed by two different pairs — `{wallet, cosigner}` and `{service, cosigner}`
//! — and this cosigner is in both. So which of them gets a signature, and when, is not a property
//! of the key at all. It is a decision, made here, on sealed state.
//!
//! ```text
//!   opened ──────────────────────────────────▶ deadline ─────────────────▶
//!     │                                           │
//!     │  service + cosigner may release           │  wallet + cosigner may reclaim
//!     │  wallet  + cosigner may NOT reclaim       │  service may no longer release
//! ```
//!
//! # The clock, and only the protected party may move it
//!
//! A session is a policy and a date, and which side of that date `now` falls on is the whole
//! decision. There is no flag that says a deal is over: every answer below is read out of the seal
//! and the clock.
//!
//! **The owner cannot end a deal.** She is the one who committed, and a commitment she can revoke
//! at will is not one: a service that has already paid a merchant against it would be left holding
//! the loss, which is exactly the thing this is supposed to prevent. Her control is in choosing the
//! deadline, not in taking it back afterwards.
//!
//! **The service may.** A deal protects the service, so the service is the one party that can give
//! that protection up: [`end_by_service`](EscrowSession::end_by_service) brings the deadline
//! forward to now, and never pushes it back. A payout that failed is the case — the service is owed
//! nothing, and an escrow held until a deadline hours away would help nobody.
//!
//! **And a spent deal has nothing left to give.** Once everything a deal allows has been released
//! ([`is_spent`](EscrowSession::is_spent)), the service has had all this deal could give it. Its
//! deadline still stands for what matters after a release: a repeat of it is answered until then,
//! and the owner may not take the escrow back before it — see
//! [`horizon`](EscrowSession::horizon).
//!
//! That is still one way for time to run out on a deal, read the same way by every instance: the
//! deadline moves only earlier, and only at the service's word.
//!
//! **Say plainly what holds this up.** Nothing in Bitcoin enforces the line above. Both pairings
//! sign the same key, so what stops an owner emptying a live escrow is this cosigner declining to
//! co-sign with them before the deadline — and what stops a service taking after it is the same
//! refusal pointed the other way. The escrow is enclave-enforced, not script-enforced. That is
//! defensible because the refusal lives in attested, measured code that a client verifies before it
//! sends anything; it is *not* the same guarantee as an output that cannot be spent, and nothing
//! here should be written as though it were.
//!
//! # Nothing runs at the deadline, and nothing needs to
//!
//! There is no task armed for when a deal ends, and no scheduler behind this module. A deadline is
//! a fact about the clock: [`may_release`](EscrowSession::may_release) and
//! [`may_reclaim`](EscrowSession::may_reclaim) read it out of the seal and compare it to `now`, so
//! an instance that did not exist when the deadline passed reaches exactly the same answer as one
//! that did. There is nothing to resume and nothing to recover.
//!
//! What this costs, said plainly: **nobody tells the owner their escrow has ended.** A task used to,
//! and buying that notification meant keeping a scheduler alive for every live deal. The owner
//! learns the same thing from `EscrowList` the next time the app looks, and the money is no less
//! theirs for not having been announced.
//!
//! # Many releases, one escrow
//!
//! A card escrow is not one payment. The owner commits an amount, spends against it over days, and
//! takes back what is left. So a release does **not** close the session; only its deadline does —
//! or releasing everything the deal allows, which a payout of one agreed price does in one go.
//! [`released_sats`](EscrowSession::released_sats) accumulates, and that running total is what
//! [`Policy::ReleasedTotalMax`](crate::policy::Policy::ReleasedTotalMax) is checked against — a
//! per-transaction cap would bound each tap and not the deal.
//!
//! And because a payment that succeeded goes on being true, every payment that has justified a
//! release is written down, on the escrow that released it, for as long as the wallet holds it.
//! The check is the wallet's, over every escrow — a wallet holds one escrow per payment, often
//! with the same service, so a ledger consulted one escrow at a time would let a spent payment be
//! spent again by asking the next escrow along. See
//! [`Cosigner::admit_release`](crate::Cosigner::admit_release).
//!
//! # What a service sends, and why it is not a transaction
//!
//! An Ark send is not one transaction. It is an ark tx plus one checkpoint tx per input, and the
//! sighashes span both — so a serialized blob would have to be parsed, checked, and then have its
//! sighashes recomputed from the cosigner's own reading of it anyway. What a service sends is
//! therefore the *proposal*: where the money goes, how much, which of the escrow's VTXOs to spend,
//! and the external payment it is claiming against. The cosigner builds the transaction itself,
//! judges what it built, and signs what it judged. There is nothing to bind, because the thing
//! approved and the thing signed are one object.
//!
//! The built transactions go back in the reply, so the service submits exactly what was approved
//! rather than a rebuild of it.
//!
//! # The one number that comes from the service
//!
//! A proposed input carries an amount, and the cosigner has no independent reading of it — it does
//! not index the escrow's VTXOs. That is safe, and the reason is worth stating rather than
//! assuming: **a taproot sighash commits to every prevout amount and script**. A service that
//! understates its inputs to make a fee look small gets a signature that verifies against nothing,
//! and the ASP refuses the transaction. The only input claim that yields a usable signature is the
//! true one, so the fee checked below is the true fee or the signature is worthless. What a lie
//! costs the service is its own allowance: the release is recorded and no money moves.
//!
//! # Everything that must hold
//!
//! Six things, each checked here and none of them taken from the request:
//!
//! ```text
//!   1  the service that spoke is the one paired into this escrow   the connection, not the message
//!   2  the escrow permits a release now                            sealed session + the clock
//!   3  the transaction satisfies the policy                        outputs the cosigner built
//!   4  it fits what is left of the allowance                       sealed running total
//!   5  the external payment evidence satisfies the policy          fetched by the cosigner itself
//!   6  that evidence has not justified a release already           sealed reference index
//! ```
//!
//! Only then is anything signed, and what is signed is the sighashes of the transaction those six
//! checks were made about.
//!
//! # Concurrency, duplicates and retries
//!
//! The runtime holds this tenant's lock for the whole of an invocation, so two messages on one
//! connection cannot interleave and two releases of one escrow cannot race. What survives past that
//! is handled on sealed state: a repeat of an answered request is signed again and counted once, a
//! request id reused for a different proposal is refused, and a payment reference that has already
//! justified a release is refused whatever id it arrives under. See
//! [`Cosigner::admit_release`](crate::Cosigner::admit_release).
//!
//! A repeat is answered from its record, not judged again, and for as long as the deal that
//! approved it would have lasted — even once its service has ended the deal. The service paid out
//! on the strength of that approval; losing the reply must not lose it the signature.
//!
//! # Taking back what is left, once the deal is over
//!
//! The other pairing over the same key. An escrow key `V'` is signed by two pairs — `{wallet,
//! cosigner}` and `{service, cosigner}` — and this is the first of them, the one the service is
//! not in. So reclaiming needs the owner present, and needs this cosigner to agree.
//!
//! ```text
//!   opened ─────────────────────────────────▶ deadline ──────────────────▶
//!     │  service + cosigner may release         │  wallet + cosigner may reclaim
//!     │  THIS is refused                        │  THIS is what runs
//!     └── or its service ends it early ─────────┘
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
//!
//! # The connection to a service
//!
//! ## Why the runtime holds it
//!
//! A service holding half of an escrow key has no passkey for its user's tenant, so it can never
//! call in: `tenant_of` is checked before the path and fails closed. And this cosigner has no
//! execution context between invocations — an instance is built to serve one call and dropped — so
//! it cannot hold a socket open either. Neither party can reach the other by the means each
//! already has.
//!
//! So the runtime holds the connection. `enclave:streams` is the interface: the guest says *keep a
//! connection to this origin*, and every message the far side sends becomes one invocation of
//! `on-message`, exactly as a due task becomes one invocation of `run-task`.
//!
//! ## What reconnects, and what activates it
//!
//! Naming it precisely, because "it reconnects" is the sort of claim that is easy to make and easy
//! to have be untrue:
//!
//! - **The mechanism is `StreamRegistry::run`** in `~/enclave-runtime/runtime/src/stream.rs`: one
//!   supervisor task per record, living in the runtime process. It dials, hands each event to the
//!   guest, and on any end — clean close or error — waits out a backoff and dials again. The
//!   backoff is 1s, 2s, 5s, 15s, 60s, 300s, and it does not give up.
//! - **The timeouts are the runtime's, not a task's.** A dial has 60 seconds to first byte, which
//!   is generous on purpose: a service with nothing to say yet is the normal case. The held
//!   connection has no lifetime of its own. One `on-message` invocation runs under the same
//!   deadline an inbound request does, NOT `--background-timeout` — it is a call with a
//!   counterparty waiting, not work scheduled for later.
//! - **After a restart it is `StreamRegistry::open_registry`.** It reads every record off disk
//!   before anything is served, and `run` starts a supervisor for each. The guest is not consulted
//!   and no timer fires.
//!
//! Two things this is *not*, and both matter:
//!
//! - It is **not** this cosigner's sealed state. The seal says an escrow has a service paired into
//!   it; it does not make a connection exist, and nothing in the guest could dial one anyway —
//!   between invocations there is no "in the guest". The runtime's own record is what stands.
//! - It is **not** the scheduler that used to watch escrow deadlines, renamed. That was a task in
//!   the queue with a run time, and it is gone. A supervisor has no schedule: it holds a socket and
//!   comes back when it drops, whether or not anybody is using the wallet.
//!
//! ## How long a connection lives
//!
//! Longer than any one deal. It is opened at pairing and not closed when a deal ends, because a
//! service that asks for a release afterwards should be told *why* — "this escrow is closed" is
//! something it can act on, where a dead socket is indistinguishable from the network being down.
//! It would also be inconsistent to close one: a deal that lapses at its deadline keeps its
//! connection, since nothing runs at a deadline to take it away.
//!
//! What bounds this is the image, not the clock: a connection exists per *service*, and the
//! services are the ones `SERVICE_ORIGINS` names.
//!
//! The guest's part is to ask once, in an interactive call, and then stop caring — the runtime
//! refuses `stream-open` from a background or message invocation for the same reason it refuses
//! `enqueue`: work arriving on a connection must not be able to grant itself more connections.
//!
//! ```text
//!   cosigner ──stream-open(id, origin)──▶ runtime ──GET /escrow/stream?id=──▶ service
//!   cosigner ──stream-send(id, bytes)───▶ runtime ──POST /escrow/send?id=───▶ service
//!   cosigner ◀──on-message(id, msg, …)── runtime ◀──────── SSE event ─────── service
//! ```
//!
//! ## One stream per service, not per escrow
//!
//! A tenant may hold eight connections and a wallet may hold sixty-four escrows, so a stream per
//! escrow would run out. A stream per *service* does not: the image names the services it will
//! talk to, and that list is what bounds this. Every message therefore names the escrow it is
//! about, and the escrow's pairing must resolve back to the stream it arrived on.
//!
//! ## What authenticates the far side
//!
//! Nothing in the message. The connection was opened to an origin **this image names**, resolved
//! from a service identifier through [`ServiceRegistry`]
//! — image environment, measured into PCR0 — and the runtime verified that origin's certificate
//! against the public web PKI before a byte arrived. So a message on stream `svc-<id>` came from
//! the origin `<id>` resolves to, and the check this module makes is the other direction: that the
//! escrow being named is paired to *that* service. A service cannot speak for an escrow it was not
//! paired into, because it cannot put its bytes on another service's connection.
//!
//! The other direction is the runtime's to prove, not this module's. What this cosigner says to a
//! service arrives there as a plain POST, which anybody could send; so the runtime attaches an
//! attestation document to every stream open and every send, binding the wire id and the exact
//! bytes to the measured image. A service that checks it knows a pairing half, a refusal or a
//! deal's terms came from this code for this tenant — not from a customer running a cosigner of
//! their own. See `docs/STREAMING.md` in enclave-runtime.
//!
//! ## Secrets and logs
//!
//! [`ToService::PairingHalf`] carries a scalar that, added to the wallet's half, IS the service's
//! signing share. It is never logged: its `Debug` impl redacts it, and [`handle_service_message`]
//! logs message kinds rather than bodies.
//!
//! # Pairing a service in: a second way to sign `V'`, and no new key
//!
//! ## What a pairing is
//!
//! An escrow key `V'` is held 2-of-2 by the wallet and this cosigner. A deal also needs a way for
//! the *service* to be paid without the payer present at settlement — so the service is given a
//! share of `V'` too, by a **key-preserving refresh**:
//!
//! ```text
//!   wallet   deals  a@service , a@cosigner
//!   cosigner deals  b@service , b@cosigner        (its own, freshly random)
//!   service        s = a@service + b@service
//! ```
//!
//! `V'` does not move. What comes out is a *second* 2-of-2 over the same key — `{service,
//! cosigner}` — so the escrow ends with two pairings and this cosigner in both:
//!
//! | pair | signs `V'` | when |
//! |---|---|---|
//! | wallet + cosigner | yes | reclaim, once the escrow closes |
//! | service + cosigner | yes | release, when the policy permits |
//! | wallet + service | **no** | they share no pairing |
//! | anyone alone | **no** | |
//!
//! That the cosigner is in both is the whole design: nothing moves without it, so its policy is
//! what the escrow actually rests on.
//!
//! ## The two things that must be checked here
//!
//! **The half this cosigner cannot see.** The wallet's contribution to the service arrives as a
//! *point*, never a scalar — a cosigner holding both `a@service` and its own counter-share would
//! have two points on one line and could reconstruct the pairing outright. So it must be taken on
//! faith, except that it need not be:
//! [`verify_user_contribution`](threshold::service_poly::verify_user_contribution) pins it down
//! from public data, and a wallet that lies about it is refused rather than allowed to steer the
//! package everything downstream trusts.
//!
//! **A slope of zero.** The pairing polynomial is `f_S(t) = v + m_S·t` with `m_S = r_wallet +
//! r_cosigner`. If `m_S` is zero the polynomial is *constant*: the service's share is the group
//! secret and it signs alone, with nobody's help. Neither half being random prevents that — a
//! wallet that learned this cosigner's half could choose its own to cancel it — so
//! [`service_poly_commitment`](threshold::service_poly::service_poly_commitment) refuses it on the
//! finished package.
//!
//! ## Where a service is: the image says, never the caller
//!
//! A pairing produces two halves. The wallet deals one straight to the service; this cosigner deals
//! the other, and a party holding both holds the service's share — so this half must travel from
//! here to the service and nowhere else, least of all back through the wallet.
//!
//! The obvious shape, a URL on the request, is the one thing that cannot be allowed. A guest
//! reaches exactly the origins its image names, and that list is image environment **measured into
//! PCR0** — so a client verifying this enclave learns from the same attestation where its traffic
//! can go. A caller-supplied URL would trade that for an SSRF gadget speaking with an attested
//! enclave's identity, and it would make the attestation's answer to "where does this send traffic"
//! be "anywhere".
//!
//! So a wallet names a **service id**, and the image decides what that means:
//!
//! ```text
//!   SERVICE_ORIGINS="<service id hex>=https://a.example,<service id hex>=https://b.example"
//! ```
//!
//! Two spellings are accepted, and the second one is not cosmetic. `dev-enclave.sh` validates a
//! `--guest-env` value against `[A-Za-z0-9:/._-]`, which admits neither `=` nor `,` — so an image
//! built through that script cannot carry the natural form at all. Entries may therefore be
//! separated by `_` as well as `,`, and an id from its origin by `:` as well as `=`:
//!
//! ```text
//!   SERVICE_ORIGINS="<id>:https://a.example_<id>:https://b.example"
//! ```
//!
//! An origin's own `://` is not ambiguous because the split is on the FIRST separator, and a hex id
//! contains neither.
//!
//! An id with no entry is refused before anything is dealt. The cost is honest and worth stating:
//! **a new service is a new image, a new PCR0 and republished pins.** That is the same cost the ASP
//! already carries, and it is what keeps "this enclave talks to these services" a thing a client
//! can check rather than a thing it is told.
//!
//! ## Two routes, one share
//!
//! A pairing has **two** deliveries, and only one of them happens here:
//!
//! ```text
//!   cosigner ──b@service──▶ service        this module, enclave to service
//!   wallet   ──a@service──▶ service        the device, to the SAME origin
//!                            └── s = a + b, checked against the published verifying share
//! ```
//!
//! The wallet's half must not come through here. This cosigner already holds its own counter-share;
//! one that also saw `a@service` would hold both terms of the service's share and could sign as it.
//! So the wallet is told where this enclave delivered
//! ([`service_origin`](proto::PairServiceDone::service_origin)) and sends its own half to the same
//! place — the origin comes from the measured image either way, and the wallet never chooses one.
//!
//! ## Over the connection the runtime holds
//!
//! The half does not travel as a request of its own. It goes on the stream the runtime maintains
//! to this service — `stream-open` then `stream-send` — for one reason that has nothing to do with
//! pairing: the *service* has to be able to speak first later, when it asks for a release, and it
//! has no passkey for this tenant so it can never call in. A connection that only exists while the
//! wallet is here would be no use to it. So the connection is opened at pairing, outlives the call
//! that opened it, and is re-established by the runtime's supervisor whenever it drops — see
//! *The connection to a service*, above.
//!
//! ## Deliver, then seal — but seal *pending*
//!
//! The cosigner's half is never retained, so a pairing whose delivery failed can never be
//! completed: the service would have no share and the half that would have given it one is gone.
//! Delivering first makes that harmless — nothing is sealed, and the wallet sets up a new escrow.
//!
//! But a pairing that has been delivered is not yet a pairing that *works*. Three things happen and
//! each can fail on its own, so each is recorded on its own:
//!
//! ```text
//!   1  stream-send lands          the service has this cosigner's half   (else: nothing sealed)
//!   2  wallet delivers its half   the service has both                   (wallet_confirmed)
//!   3  service checks the sum     the share matches the verifying share  (service_confirmed)
//! ```
//!
//! A failure between 1 and 2 leaves a `pending` pairing sealed and the service holding one useless
//! half; that escrow stays unpaired, and the wallet sets up a new one. A failure between 2 and 3 is
//! the same picture from one step further on. What is *not* possible is a pairing reported usable
//! on one party's word: step 3 arrives over the stream from the service and step 2 from the wallet,
//! and [`ServicePairing::state`] is `Ready` only with both. A
//! restart changes none of this — the flags are in the seal.
//!
//! # Minting an escrow key: the same two parties, a second key, one reshare
//!
//! ## What an escrow key is
//!
//! A wallet's own key `V` is a 2-of-2 between the phone and this cosigner. Escrowed money needs a
//! key that a *third* interest can be paid from without the payer present at settlement — but
//! handing that interest a share of `V` would hand it the whole wallet. So escrow gets a key of its
//! own:
//!
//! ```text
//!   reshare {wallet, cosigner} over V   ──▶   V' = V + Δ_wallet + Δ_cosigner
//! ```
//!
//! Both sides deal a fresh non-zero `Δ` under the identifiers they already have, and both finalize.
//! `V'` is a new key held 2-of-2 by the same pair, and `V` is untouched — the wallet keeps spending
//! from it exactly as before. Funding an escrow is then an ordinary Ark send from `V` to `V'`'s
//! address, and everything afterwards is about who may spend `V'`.
//!
//! The service is paired into `V'` separately (see [`EscrowSession::prepare_pairing`]), never into
//! `V`. That is the whole reason this ceremony exists rather than reusing the wallet's key.
//!
//! ## Nothing secret at rest, here too
//!
//! A wallet keeps no share; it rebuilds one for each operation from its passkey plus the half this
//! cosigner sealed. An escrow share has to work the same way or escrowed money would be the one
//! thing a lost phone could not recover. It is built on top of the wallet share rather than beside
//! it:
//!
//! ```text
//!   s_wallet  = ±[ f_wallet(id) + dealt_share ]        checked against V's verifying share
//!   s'_wallet = ±[ s_wallet + Δ_wallet(id) + Δ_cosigner(id) ]   against V''s
//!                              \__________/   \______________/
//!                              from the passkey   one scalar, sealed here
//! ```
//!
//! **The two `±` are why this seals `Δ_cosigner(id)` alone and not its sum with `dealt_share`.**
//! Every finalizer normalises to an even-Y group key, so a normalisation sits *between* those two
//! terms: when `V` came out with odd Y the wallet's share is negated before the deltas are added,
//! and a pre-added sum would be wrong for half of all wallets — silently, and only for those half.
//! A test caught exactly that. Keep them separate.
//!
//! ## What minting is not
//!
//! It does not decide anything. Whether a release is permitted is the policy's business
//! ([`crate::policy`]); this only mints the key that a policy will later guard.

use std::collections::{BTreeMap, BTreeSet};

use ark::client::send::SendSession;
use rand::rngs::OsRng;
use ark::client::types::ArkInfo;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use threshold::dkg::{
    self, Receiver, Round1Package, Round1SecretPackage, Round2Package, Round2SecretPackage,
};
use threshold::identifier::Identifier;
use threshold::keys::{KeyPackage, PublicKeyPackage};
use threshold::point;
use threshold::random;
use threshold::scalar::{scalar_from_bytes, scalar_to_bytes};
use threshold::service_poly::{service_poly_commitment, verify_user_contribution};

use crate::asp::AspApi;
use crate::cosigner::{x_only, Cosigner};
use crate::evidence::{FetchEvidence, ReleaseFacts};
use crate::grpc::Status;
use crate::handlers::helpers::now_secs;
use crate::host::Host;
use crate::policy::Policy;
use crate::session::proto;
use crate::sign::SigningKey;
use crate::types::{Admission, ReleaseRecord, VtxoInput};

/// One escrow and everything that happens to it, sealed: a key of its own, the service paired into
/// it, the one deal it is committed to, and what that deal has released.
///
/// The key is a *second* 2-of-2 — `V' = V + Δ_wallet + Δ_cosigner`, minted by a reshare so the
/// wallet's own key is untouched and a service can be paired into the escrow without being paired
/// into the wallet. See [`begin_mint`](Self::begin_mint). Minted, paired and committed in one
/// session, and never committed again: the next payment mints the next escrow.
///
/// **Active** while its deal runs, or a release it signed may still be on its way to the ASP;
/// **over** past its [horizon](Self::horizon), when the owner may take back what is left. Kept
/// after that: what is left is still the owner's to take, and the payments it released must never
/// justify a release anywhere again — see `Cosigner::admit_release`.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(from = "SealedEscrow")]
pub struct EscrowSession {
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
    /// wrong for every wallet whose key came out with odd Y. See the module note on minting.
    pub wallet_delta_share_hex: String,
    /// Unix seconds, when it was minted.
    pub created_at: i64,
    /// How far it has come: minted, a service paired in, its deal struck.
    pub stage: EscrowStage,
}

/// How far an escrow has come. One way only — minted, then a service paired in, then its one deal
/// — and a stream that ended part-way leaves it where it stopped.
///
/// Whether a deal is running is not a stage. It is the clock against the deadline, read the same
/// way by every instance with nothing written when it passes — see the module note.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EscrowStage {
    /// Minted; the stream that minted it ended before a service was paired in. A key the wallet
    /// and this cosigner hold, and nobody else can be paid from.
    Minted,
    /// A service paired in; the stream ended before the deal was struck.
    Paired(ServicePairing),
    /// Committed to its one deal, for good: nothing else commits an escrow.
    Dealt {
        pairing: ServicePairing,
        /// What the service may take, and until when.
        terms: DealTerms,
        /// Every payment this escrow has released against, by the reference its provider knows it
        /// by. A payment that succeeded goes on being true, so what stops it paying twice is this
        /// record and nothing else — and the check is the wallet's, over every escrow it holds.
        #[serde(default)]
        releases: BTreeMap<String, ReleaseRecord>,
    },
}

/// An escrow as any seal so far wrote it. Before the stage had a field of its own, an escrow kept
/// its pairing — and, for a while, its deal and releases — beside the key, and those read as the
/// stage they reached. An older seal's deal, kept as `session`, is not read: such an escrow comes
/// back paired, its owner's to take back.
#[derive(Deserialize)]
struct SealedEscrow {
    escrow_key: String,
    key_package_json: String,
    public_key_package_json: String,
    wallet_identifier_hex: String,
    context_hex: String,
    wallet_delta_share_hex: String,
    created_at: i64,
    #[serde(default)]
    stage: Option<EscrowStage>,
    #[serde(default)]
    pairing: Option<ServicePairing>,
    #[serde(default)]
    terms: Option<DealTerms>,
    #[serde(default)]
    releases: BTreeMap<String, ReleaseRecord>,
}

impl From<SealedEscrow> for EscrowSession {
    fn from(sealed: SealedEscrow) -> Self {
        let stage = match sealed.stage {
            Some(stage) => stage,
            None => match (sealed.pairing, sealed.terms) {
                (None, _) => EscrowStage::Minted,
                (Some(pairing), None) => EscrowStage::Paired(pairing),
                (Some(pairing), Some(terms)) => EscrowStage::Dealt {
                    pairing,
                    terms,
                    releases: sealed.releases,
                },
            },
        };
        Self {
            escrow_key: sealed.escrow_key,
            key_package_json: sealed.key_package_json,
            public_key_package_json: sealed.public_key_package_json,
            wallet_identifier_hex: sealed.wallet_identifier_hex,
            context_hex: sealed.context_hex,
            wallet_delta_share_hex: sealed.wallet_delta_share_hex,
            created_at: sealed.created_at,
            stage,
        }
    }
}

/// What an escrow with no deal has released.
static NO_RELEASES: BTreeMap<String, ReleaseRecord> = BTreeMap::new();

// Redacting `Debug`: `key_package_json` is this cosigner's share of `V'`, `wallet_delta_share_hex`
// a term of the owner's escrow share, and the pairing holds this cosigner's share of that pairing.
// None of them belongs in a log or a panic message.
impl core::fmt::Debug for EscrowSession {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("EscrowSession")
            .field("escrow_key", &self.escrow_key)
            .field("wallet_identifier_hex", &self.wallet_identifier_hex)
            .field("context_hex", &self.context_hex)
            .field("created_at", &self.created_at)
            .field(
                "stage",
                &match self.stage {
                    EscrowStage::Minted => "minted",
                    EscrowStage::Paired(_) => "paired",
                    EscrowStage::Dealt { .. } => "dealt",
                },
            )
            .field("service", &self.pairing().map(|p| &p.service_identifier_hex))
            .field("terms", &self.terms())
            .field("releases", self.releases())
            .field("key_package_json", &"<redacted>")
            .field("wallet_delta_share_hex", &"<redacted>")
            .finish()
    }
}

/// What a deal is: what its service may take, and until when.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DealTerms {
    /// What a release must satisfy. [`Policy::Never`] by default, so a deal whose policy failed to
    /// deserialize releases nothing rather than everything.
    #[serde(default)]
    pub policy: Policy,
    /// Unix seconds.
    pub opened_at: i64,
    /// Unix seconds. After this the service may no longer release and the owner may reclaim.
    pub deadline: i64,
}

/// What the escrow's own service is told about the deal it is asking against.
///
/// A service fronts money before it is repaid, and it cannot see the seal. Two things it must know
/// before it does, and neither can come from the owner's app, which is the party a service is
/// guarding against: **until when** it may be repaid, and **which policy** was sealed. The second is
/// not idle — `all_of` stops at its first failing term, so a policy with a term appended after the
/// one the service expects to fail refuses in exactly the same words, and then refuses for ever.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SealedTerms {
    /// Unix seconds.
    pub opened_at: i64,
    /// Unix seconds. After this nothing is released, and a service that has not been repaid by then
    /// will not be.
    pub deadline: i64,
    /// [`policy_sha256`](crate::policy::policy_sha256) of the sealed policy.
    pub policy_sha256: String,
}

/// Why a party may not sign right now. Each is a different thing to tell somebody.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Refusal {
    /// The service asked after the deadline.
    DealEnded,
    /// The owner asked while the escrow is still live and the service may still take.
    StillOpen,
}

impl Refusal {
    pub fn message(self) -> &'static str {
        match self {
            Refusal::DealEnded => {
                "this escrow's deal is over: it passed its deadline, and nothing more is released \
                 from it"
            }
            Refusal::StillOpen => {
                "this escrow's deal is still running: it can be taken back once the deadline \
                 passes, and until then the money is committed to it"
            }
        }
    }
}

impl DealTerms {
    /// A deal that runs from `now` until `deadline`.
    ///
    /// There is no `close` for the owner. See the module note: a commitment the owner can revoke is
    /// not one, and the deadline she chooses here is the whole of her control over it.
    pub fn validate(policy: Policy, now: i64, deadline: i64) -> Result<Self, String> {
        if deadline <= now {
            return Err("a deal that is already over commits nothing to anybody".into());
        }
        policy.validate()?;
        Ok(Self {
            policy,
            opened_at: now,
            deadline,
        })
    }

    /// The deal an [`EscrowOpen`](proto::EscrowOpen) asks for, as of `now`.
    pub(crate) fn from_request(open: &proto::EscrowOpen, now: i64) -> Result<Self, Status> {
        // An unparseable policy is `never`, not `always`: a deal nobody can take from is a bad day,
        // and one anybody can take from is a lost escrow.
        let policy: Policy = serde_json::from_str(&open.policy_json)
            .map_err(|e| Status::invalid_argument(format!("that is not a policy: {e}")))?;
        Self::validate(policy, now, open.deadline_secs).map_err(Status::invalid_argument)
    }
}

/// An escrow's key material, as this cosigner holds it — see [`EscrowSession::key_material`].
pub(crate) struct EscrowKeyMaterial {
    /// This cosigner's share of `V'`.
    pub(crate) key_package: KeyPackage,
    /// The escrow's public package.
    pub(crate) public_key_package: PublicKeyPackage,
    /// The wallet's identifier in it.
    pub(crate) wallet_id: Identifier,
}

// --- The service paired into it ------------------------------------------------------------------

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
/// Minted by a key-preserving refresh, so `V'` does not move — see
/// [`EscrowSession::prepare_pairing`].
/// What is kept is this cosigner's own half of the pairing and the public package the service's
/// share is checked against. **Never the service's half**: it is handed over once at pairing and
/// not retained, because a party holding both halves holds the service's share.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
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
    /// [`FromService::PairingReady`].
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

/// Every pairing is a 2-of-2, and the maths here assumes it: `service_poly_commitment` recovers a
/// degree-1 slope from one verifying share, which no higher threshold determines.
const MIN_SIGNERS: usize = 2;

/// What [`EscrowSession::prepare_pairing`] hands back: the service's half to deliver, and the
/// record sealed once it is.
pub struct PairingMaterial {
    pub service_identifier_hex: String,
    /// This cosigner's share of the `{service, cosigner}` pairing.
    pub key_package_json: String,
    /// The pairing's public package. Its verifying key is `V'` — unchanged, and checked.
    pub public_key_package_json: String,
    /// `b@service`: this cosigner's half of the service's share. **For the service and nobody
    /// else** — handed out once and never kept, because a party holding both halves holds the
    /// service's share.
    pub service_half: Vec<u8>,
    /// The verifying share the service's assembled share must match, hex. Public, and what lets
    /// the service check it was dealt honestly before it relies on being able to sign.
    pub service_verifying_share_hex: String,
}

// Redacting `Debug`: `service_half` is half of the service's share, and `key_package_json` holds
// this cosigner's own. Neither belongs in a log or a panic message.
impl core::fmt::Debug for PairingMaterial {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("PairingMaterial")
            .field("service_identifier_hex", &self.service_identifier_hex)
            .field("service_verifying_share_hex", &self.service_verifying_share_hex)
            .field("key_package_json", &"<redacted>")
            .field("service_half", &"<redacted>")
            .finish()
    }
}

impl PairingMaterial {
    /// Hand the service this cosigner's half, over the connection the runtime holds to it — the
    /// one it will speak first on later, when it asks for a release.
    ///
    /// Nothing is sealed before this succeeds: the half is never kept, so a pairing sealed against
    /// a delivery that did not land could never be completed. See *Deliver, then seal* in the
    /// module note.
    pub async fn deliver(
        &self,
        host: &dyn Host,
        origin: &str,
        escrow_key: &str,
        attempt_id: &str,
    ) -> Result<(), String> {
        let half = ToService::PairingHalf {
            escrow_key: escrow_key.to_string(),
            attempt_id: attempt_id.to_string(),
            service_identifier: self.service_identifier_hex.clone(),
            half: hex::encode(&self.service_half),
            public_key_package_json: self.public_key_package_json.clone(),
            service_verifying_share: self.service_verifying_share_hex.clone(),
        };
        send_to_service(host, &self.service_identifier_hex, origin, &half).await
    }

    /// The record to seal once the half is delivered. Takes the material by value, so the
    /// service's half is dropped here and cannot be kept by mistake.
    pub fn into_pairing(self, attempt_id_hex: String, now: i64) -> ServicePairing {
        ServicePairing {
            service_identifier_hex: self.service_identifier_hex,
            key_package_json: self.key_package_json,
            public_key_package_json: self.public_key_package_json,
            service_verifying_share_hex: self.service_verifying_share_hex,
            paired_at: now,
            attempt_id_hex,
            // Delivered, not yet shown to work: the service has one half of two, and neither party
            // has vouched for it.
            service_confirmed: false,
            wallet_confirmed: false,
        }
    }
}

// --- Reaching a service --------------------------------------------------------------------------

/// A service a wallet named, resolved against the image before anything is dealt.
pub(crate) struct Service {
    pub(crate) id: Identifier,
    pub(crate) origin: String,
}

impl Service {
    /// Where the service [identifier] names is, according to the IMAGE. Resolved before anything
    /// is dealt, so naming a service this enclave does not know costs nothing and reveals nothing.
    pub(crate) fn resolve(identifier: &[u8]) -> Result<Self, Status> {
        let origin = ServiceRegistry::from_env().origin_of(&hex::encode(identifier))?.to_string();
        let id = Identifier::try_from(identifier)
            .map_err(|e| Status::invalid_argument(format!("bad service identifier: {e}")))?;
        Ok(Self { id, origin })
    }
}

/// Which services this image will talk to, and where they are.
///
/// Keys are service identifiers as lowercase hex; values are origins (`https://host[:port]`). From
/// `SERVICE_ORIGINS` in the guest's environment — image configuration, so it is measured, and a
/// deployment that names no services simply cannot pair any.
#[derive(Debug, Clone, Default)]
pub struct ServiceRegistry {
    origins: BTreeMap<String, String>,
}

impl ServiceRegistry {
    /// Parse `id=origin,id=origin`. Whitespace around entries is ignored; a malformed entry is
    /// skipped rather than taken as something narrower than it is.
    pub fn parse(raw: &str) -> Self {
        let mut origins = BTreeMap::new();
        for entry in raw.split([',', '_']) {
            let entry = entry.trim();
            if entry.is_empty() {
                continue;
            }
            // The first `=` if there is one, else the first `:` — an origin's own `://` comes
            // later in the string and a hex id contains neither.
            let Some((id, origin)) = entry
                .split_once('=')
                .or_else(|| entry.split_once(':'))
            else {
                continue;
            };
            let id = id.trim().to_ascii_lowercase();
            let origin = origin.trim().trim_end_matches('/');
            // An id is a 32-byte FROST identifier; an origin is a scheme and a host, never a path.
            // Anything else is a typo, and a typo that resolved to something would be worse than
            // one that did not.
            if id.len() != 64 || !id.bytes().all(|b| b.is_ascii_hexdigit()) {
                continue;
            }
            if !(origin.starts_with("https://") || origin.starts_with("http://")) {
                continue;
            }
            match origin.get(8..) {
                Some(rest) if !rest.is_empty() && !rest.contains('/') => {}
                _ => continue,
            }
            origins.insert(id, origin.to_string());
        }
        Self { origins }
    }

    pub fn from_env() -> Self {
        Self::parse(&std::env::var("SERVICE_ORIGINS").unwrap_or_default())
    }

    /// Where a service is, or a refusal naming the reason.
    pub fn origin_of(&self, service_id_hex: &str) -> Result<&str, Status> {
        self.origins
            .get(&service_id_hex.to_ascii_lowercase())
            .map(String::as_str)
            .ok_or_else(|| {
                Status::failed_precondition(
                    "this enclave does not know that service: an image names the services it may \
                     reach, and adding one is a new image rather than a new request",
                )
            })
    }

    pub fn is_empty(&self) -> bool {
        self.origins.is_empty()
    }

    /// The services this image knows, for an operator checking a deployment.
    pub fn service_ids(&self) -> impl Iterator<Item = &str> {
        self.origins.keys().map(String::as_str)
    }
}

/// The stream this cosigner holds to one service.
///
/// Derived, not stored: a service identifier is 32 bytes and `valid_id` allows 64 characters of
/// `[A-Za-z0-9_-]`, so the identifier is truncated to twenty bytes. That is far beyond collision
/// among the handful of services an image names, and every message carries the escrow it is about
/// anyway — the id is a handle, never the answer.
///
/// # This is not what the service sees, and it must not be
///
/// It names the service and nothing else, so **every wallet the enclave serves produces the same
/// string**. That is correct here — a stream id is tenant-local by contract, and the runtime binds
/// every call to the current tenant, so nothing in this guest could collide with another's.
///
/// But a service would collide, and badly: it holds one connection per customer and a message sent
/// to it arrives as a POST with no connection identity in it. So the runtime does not put this on
/// the wire on its own. It sends `<tenant hex>-<this>`, which is what a service keys its
/// connections by — see `StreamRecord::wire_id` in the runtime, and the note in `stream.wit`.
/// Anything reading this function alone would conclude two wallets share a connection; they do not.
pub fn service_stream_id(service_id_hex: &str) -> String {
    let stem: String = service_id_hex
        .chars()
        .filter(|c| c.is_ascii_alphanumeric())
        .take(40)
        .collect::<String>()
        .to_ascii_lowercase();
    format!("svc-{stem}")
}

/// Open the connection to a service and send it one message.
///
/// Opening is idempotent for the same origin and an error for a different one, so a second escrow
/// with the same service reuses the connection rather than making a second.
///
/// The wait is for the runtime's supervisor to dial: `stream-open` records a standing instruction
/// and returns, and `stream-send` refuses while the connection is down rather than queueing a
/// message only the caller can know is still wanted. A service that is not answering fails the
/// pairing here, which is the right place — nothing has been sealed.
async fn send_to_service(
    host: &dyn Host,
    service_id_hex: &str,
    origin: &str,
    message: &ToService,
) -> Result<(), String> {
    let stream_id = service_stream_id(service_id_hex);
    host.stream_open(&stream_id, origin)
        .map_err(|e| format!("asking the runtime to connect to {origin}: {e}"))?;

    let payload = message.encode()?;
    let mut last = String::new();
    for attempt in 0..CONNECT_ATTEMPTS {
        match host.stream_send(&stream_id, &payload) {
            Ok(()) => return Ok(()),
            Err(e) => last = e,
        }
        // Bounded by attempts rather than by the clock: the only thing being waited for is the
        // first dial, and a guest has no deadline of its own to measure against.
        if attempt + 1 < CONNECT_ATTEMPTS {
            pause(CONNECT_PAUSE_MS).await;
        }
    }
    // What the runtime knows about it, which is the only account of *why*: whether it has ever
    // connected, how many dials have failed, and what the last one said. Without this the caller
    // learns only that the connection is down, which is the one thing it could already see.
    let account = host
        .stream_status(&stream_id)
        .unwrap_or_else(|e| format!("(the runtime would not say: {e})"));
    Err(format!("{origin} could not be reached: {last}; the runtime says {account}"))
}

/// How long to keep trying the send while the supervisor is still dialling, as attempts times
/// pause — about ten seconds.
///
/// Sized against what is actually being waited for: a TCP connect and a TLS handshake to a host
/// that may be a continent away, and, if the first dial fails, the runtime's first backoff step of
/// one second and the dial after it. Sized against a ceiling too — the whole pairing call is
/// bounded by the runtime's interaction deadline, and a guest that spent all of it here would fail
/// with a timeout instead of with a reason.
const CONNECT_ATTEMPTS: u32 = 20;
const CONNECT_PAUSE_MS: u64 = 500;

#[cfg(target_arch = "wasm32")]
async fn pause(ms: u64) {
    wstd::task::sleep(wstd::time::Duration::from_millis(ms)).await;
}

/// Off the component target there is no reactor to sleep on, and no runtime to connect either —
/// [`Detached`](crate::host::Detached) fails the first send, and a fake in a test either connects
/// at `stream_open` or never will. Spinning would only burn the attempts faster.
#[cfg(not(target_arch = "wasm32"))]
async fn pause(_ms: u64) {}

// --- What travels on the connection --------------------------------------------------------------
//
// The wire both sides speak, as JSON — the service's own code reads these same types.

/// What this cosigner sends a service.
///
/// Tagged, like [`Task`](crate::cosigner::Task), so the stored payload stays readable and a
/// new kind costs a variant rather than a new channel.
#[derive(Clone, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "kebab-case")]
pub enum ToService {
    /// This cosigner's half of the service's share in one pairing.
    ///
    /// The two halves must sum to the verifying share the pairing publishes — but that alone is a
    /// check any two halves chosen together pass, so a service takes this one only from a send the
    /// runtime attested (see the module note), and never over a share it already holds.
    PairingHalf {
        escrow_key: String,
        /// Which attempt this half belongs to, hex. The wallet's half arrives separately, by a
        /// different route, and carries the same label — that is what tells the service which two
        /// halves belong to each other. Halves from two attempts sum to nothing.
        attempt_id: String,
        service_identifier: String,
        /// Hex. **Secret**: with the wallet's half it is the service's signing share.
        half: String,
        public_key_package_json: String,
        service_verifying_share: String,
    },
    /// A message was understood and acted on.
    Ack { about: String },
    /// A message was refused, and why. Prose, for a service operator to read.
    Refused { about: String, reason: String },
    /// A release the cosigner approved: the transactions it built, and its half of each signature.
    ///
    /// Boxed because it is much the largest variant and every other one would otherwise be sized
    /// for it.
    ReleaseSigned(Box<SignedRelease>),
    /// A release the cosigner will not sign, and why. A conclusion, not a fault — the request is
    /// not redelivered.
    ReleaseRefused {
        request_id: String,
        reason: String,
        /// The deal the escrow is committed to — its deadline and which policy was sealed — told
        /// only to the escrow's own service, and only when there is a deal. What lets a service
        /// that asks before paying know it will be repaid, and until when, without taking the
        /// owner's app at its word. See [`SealedTerms`].
        #[serde(default, skip_serializing_if = "Option::is_none")]
        deal: Option<SealedTerms>,
    },
}

/// The secret half is redacted. A pairing that ends up in a log is a pairing given away.
impl core::fmt::Debug for ToService {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            ToService::PairingHalf {
                escrow_key,
                attempt_id,
                ..
            } => f
                .debug_struct("PairingHalf")
                .field("escrow_key", escrow_key)
                .field("attempt_id", attempt_id)
                .field("half", &"<redacted>")
                .finish_non_exhaustive(),
            ToService::Ack { about } => f.debug_struct("Ack").field("about", about).finish(),
            ToService::Refused { about, reason } => f
                .debug_struct("Refused")
                .field("about", about)
                .field("reason", reason)
                .finish(),
            // Nothing secret: a signature share is public once it exists, and the transactions are
            // the ones about to be broadcast.
            ToService::ReleaseSigned(approval) => f
                .debug_struct("ReleaseSigned")
                .field("request_id", &approval.request_id)
                .field("halves", &approval.halves.len())
                .field("already_counted", &approval.already_counted)
                .finish_non_exhaustive(),
            ToService::ReleaseRefused {
                request_id,
                reason,
                deal,
            } => f
                .debug_struct("ReleaseRefused")
                .field("request_id", request_id)
                .field("reason", reason)
                .field("deal", deal)
                .finish(),
        }
    }
}

impl ToService {
    /// The bytes that go on the connection.
    fn encode(&self) -> Result<Vec<u8>, String> {
        serde_json::to_vec(self).map_err(|e| format!("encoding a message for a service: {e}"))
    }
}

/// What arrives from a service.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "kebab-case")]
pub enum FromService {
    /// The service has both halves, and the share they sum to matches the verifying share the
    /// pairing published. This is the service's side of "the pairing works".
    PairingReady {
        escrow_key: String,
        attempt_id: String,
    },
    /// The service could not use what it was sent. Nothing is undone here — the wallet pairs
    /// again with a fresh half — but the reason is worth reporting.
    PairingRefused {
        escrow_key: String,
        attempt_id: String,
        reason: String,
    },
    /// Pay a service out of an escrow. See [`handle_service_message`].
    ReleaseRequest(Box<ReleaseRequest>),
    /// The service is done with this deal and will ask for nothing more from it — a payout that
    /// failed, say. The deal protects the service, so the service may end it; the owner may not.
    /// `policy_sha256` names the deal, so a late end cannot close the next one.
    EndDeal {
        escrow_key: String,
        policy_sha256: String,
    },
}

impl FromService {
    /// The tag, for a log line that names what arrived without quoting it.
    pub fn kind(&self) -> &'static str {
        match self {
            FromService::PairingReady { .. } => "pairing-ready",
            FromService::PairingRefused { .. } => "pairing-refused",
            FromService::ReleaseRequest(..) => "release-request",
            FromService::EndDeal { .. } => "end-deal",
        }
    }

    /// What a reply is matched by: the pairing attempt, the release request, or the deal it is
    /// about.
    pub fn correlation_id(&self) -> String {
        match self {
            FromService::PairingReady { attempt_id, .. }
            | FromService::PairingRefused { attempt_id, .. } => attempt_id.clone(),
            FromService::ReleaseRequest(r) => r.request_id.clone(),
            FromService::EndDeal { policy_sha256, .. } => policy_sha256.clone(),
        }
    }
}

/// Why a message could not be acted on. Each is a different thing to tell a service operator.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum StreamRefusal {
    /// The stream id is not one this cosigner opened for a service it knows.
    UnknownStream,
    /// No escrow of that name, or it has no pairing.
    UnknownEscrow,
    /// The escrow exists, but it is paired to a different service than the one that spoke.
    NotYourEscrow,
    /// The attempt named is not the one this cosigner dealt.
    StaleAttempt,
    /// The payload did not decode.
    Undecodable(String),
    /// Something a retry might genuinely fix. Reported to the runtime as an error, so the message
    /// comes back — unlike every other variant here, which is a decision.
    Faulted(String),
}

impl StreamRefusal {
    pub fn message(&self) -> String {
        match self {
            StreamRefusal::UnknownStream => {
                "this cosigner holds no connection under that name".into()
            }
            StreamRefusal::UnknownEscrow => {
                "this wallet holds no such escrow, or no service is paired into it".into()
            }
            StreamRefusal::NotYourEscrow => {
                "that escrow is paired to a different service than the one on this connection"
                    .into()
            }
            StreamRefusal::StaleAttempt => {
                "that pairing attempt is not the one this cosigner dealt a half for".into()
            }
            StreamRefusal::Undecodable(e) => format!("this message did not decode: {e}"),
            StreamRefusal::Faulted(e) => e.clone(),
        }
    }
}

/// One of the escrow's VTXOs, as the service resolved it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProposedInput {
    pub txid: String,
    pub vout: u32,
    /// What the VTXO is worth. See the module note on why taking this from the service is safe.
    pub amount_sats: u64,
    /// The VTXO's own unilateral exit delay, which is part of its taproot tree — a mixed set
    /// genuinely differs, and one input's script cannot stand for another's.
    pub exit_delay: u32,
}

/// One party's FROST commitments for one message.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct WireCommitment {
    /// Compressed point, hex.
    pub hiding: String,
    /// Compressed point, hex.
    pub binding: String,
}

/// The cosigner's half of one message's signature: its commitment, and its share over both.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SignedHalf {
    pub hiding: String,
    pub binding: String,
    /// The signature share, 32 bytes, hex.
    pub share: String,
}

/// What a service asks for.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ReleaseRequest {
    /// The service's idempotency key. A repeat of it must be a repeat of the same proposal.
    pub request_id: String,
    /// Which escrow. Compared x-only, so either parity resolves.
    pub escrow_key: String,
    /// Where the money goes. An Ark address, and the policy decides whether it is an allowed one.
    pub to_ark_address: String,
    pub amount_sats: u64,
    /// The escrow's VTXOs to spend, in the order their sighashes will be in.
    pub inputs: Vec<ProposedInput>,
    /// The external payment being claimed. The service chooses it; it reaches a provider only as a
    /// path segment of a URL the sealed policy wrote.
    pub payment_reference: String,
    /// The service's commitments, one per sighash, in order.
    ///
    /// A release over `n` inputs has `2n` sighashes — one per input on the ark tx, and one per
    /// checkpoint. A count that does not match what the cosigner built is refused before any nonce
    /// is made, so the service's unused nonces are simply discarded.
    pub commitments: Vec<WireCommitment>,
}

impl ReleaseRequest {
    /// What was approved, reduced to a value a repeat can be compared against.
    ///
    /// Everything that changes what is signed, and nothing that does not: the commitments are a
    /// party's own single-use material and a retry is expected to bring fresh ones.
    pub fn proposal_hash(&self) -> String {
        // Length-prefixed, so no two different proposals can feed the hash the same bytes by
        // running one field into the next.
        fn feed(hasher: &mut Sha256, s: &str) {
            hasher.update((s.len() as u64).to_be_bytes());
            hasher.update(s.as_bytes());
        }
        let mut hasher = Sha256::new();
        feed(&mut hasher, &self.escrow_key.to_ascii_lowercase());
        feed(&mut hasher, &self.to_ark_address);
        feed(&mut hasher, &self.payment_reference);
        hasher.update(self.amount_sats.to_be_bytes());
        hasher.update((self.inputs.len() as u64).to_be_bytes());
        for input in &self.inputs {
            feed(&mut hasher, &input.txid.to_ascii_lowercase());
            hasher.update(input.vout.to_be_bytes());
            hasher.update(input.amount_sats.to_be_bytes());
            hasher.update(input.exit_delay.to_be_bytes());
        }
        hex::encode(hasher.finalize())
    }
}

/// What a service gets back when a release is signed: the transactions as built, and this
/// cosigner's half of each signature.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SignedRelease {
    pub request_id: String,
    /// The ark transaction as built, base64 PSBT. Submit this, not a rebuild of it.
    pub ark_tx: String,
    /// One checkpoint transaction per input, base64 PSBTs, in input order.
    pub checkpoint_txs: Vec<String>,
    /// The cosigner's half of each sighash's signature, in sighash order.
    pub halves: Vec<SignedHalf>,
    /// Whether this was a fresh release or a repeat of one already counted. A service that lost a
    /// reply learns that its allowance was not charged twice.
    pub already_counted: bool,
}

// --- Answering a service -------------------------------------------------------------------------

/// One message from a service, as one invocation of `on-message`: decoded, acted on, answered.
///
/// The runtime's message id is not taken. It repeats when the runtime delivers a message again —
/// after a reconnect, or because the far side resent it — and nothing here needs it: every handler
/// is idempotent, and a release is deduplicated on its own durable record rather than on a
/// transport id that only holds within one connection.
///
/// An `Err` sends the service **nothing at all** — the runtime logs it and moves on — so the far
/// side learns only that its message went unanswered and asks again. That is right for a fault and
/// wrong for a decision, so anything concluded comes back as `Ok` carrying a
/// [`ToService::Refused`], and only a fault a retry might genuinely fix is an error.
pub async fn handle_service_message<A: AspApi, F: FetchEvidence>(
    wallet: &mut Cosigner,
    stream_id: &str,
    payload: &[u8],
    asp: Option<A>,
    fetcher: &F,
) -> Result<Vec<u8>, String> {
    let message: FromService = match serde_json::from_slice(payload) {
        Ok(message) => message,
        Err(e) => {
            let reason = StreamRefusal::Undecodable(e.to_string()).message();
            return ToService::Refused { about: String::new(), reason }.encode();
        }
    };
    let about = message.correlation_id();
    // Kinds, never bodies: a pairing half in a log is a pairing given away, and the same rule
    // applies to everything that travels beside one.
    tracing::debug!(stream = %stream_id, kind = message.kind(), "a service said something");

    match dispatch(wallet, stream_id, message, asp, fetcher).await {
        Ok(reply) => reply.encode(),
        // The one case that must NOT be answered: the runtime redelivers what a guest failed on,
        // which is exactly what a fault wants and exactly what a decision must not have.
        Err(StreamRefusal::Faulted(e)) => Err(e),
        Err(refusal) => ToService::Refused { about, reason: refusal.message() }.encode(),
    }
}

/// Act on one message, on the escrow it names — once the stream it arrived on is shown to be that
/// escrow's paired service.
async fn dispatch<A: AspApi, F: FetchEvidence>(
    wallet: &mut Cosigner,
    stream_id: &str,
    message: FromService,
    asp: Option<A>,
    fetcher: &F,
) -> Result<ToService, StreamRefusal> {
    match message {
        FromService::PairingReady {
            escrow_key,
            attempt_id,
        } => {
            let escrow = wallet
                .escrow_mut(&escrow_key)
                .map_err(|_| StreamRefusal::UnknownEscrow)?;
            escrow.verify_sender(stream_id, &attempt_id)?;
            escrow
                .confirm_pairing(&attempt_id, |p| p.service_confirmed = true)
                .map_err(|_| StreamRefusal::StaleAttempt)?;
            wallet.seal();
            Ok(ToService::Ack { about: attempt_id })
        }
        FromService::PairingRefused {
            escrow_key,
            attempt_id,
            reason,
        } => {
            wallet
                .get_escrow_session(&escrow_key)
                .ok_or(StreamRefusal::UnknownEscrow)?
                .verify_sender(stream_id, &attempt_id)?;
            // Nothing to undo: the pairing is `pending`, which is already "not usable", and the
            // wallet sets up a new escrow.
            tracing::info!(
                escrow = %escrow_key,
                attempt = %attempt_id,
                %reason,
                "a service refused a pairing half"
            );
            Ok(ToService::Ack { about: attempt_id })
        }
        FromService::ReleaseRequest(request) => {
            handle_release_request(wallet, stream_id, &request, asp, fetcher)
                .await
                .map_err(StreamRefusal::Faulted)
        }
        FromService::EndDeal {
            escrow_key,
            policy_sha256,
        } => {
            let escrow = wallet
                .escrow_mut(&escrow_key)
                .map_err(|_| StreamRefusal::UnknownEscrow)?;
            escrow.verify_sender(stream_id, "")?;
            if let Err(reason) = escrow.end_by_service(&policy_sha256, now_secs()) {
                return Ok(ToService::Refused {
                    about: policy_sha256,
                    reason,
                });
            }
            // Sealed before it is acknowledged: a service told the deal is over, when the seal
            // still says otherwise, would be wrong on the next invocation. A seal that fails is a
            // fault, so the runtime redelivers and this runs again.
            wallet.try_seal().map_err(StreamRefusal::Faulted)?;
            Ok(ToService::Ack {
                about: policy_sha256,
            })
        }
    }
}

/// A service asks to be paid: the release signed, or refused with the reason — and, for the
/// escrow's own service, the deal it was refused under.
///
/// `Err` means something a retry might genuinely fix — the ASP was unreachable, the seal could not
/// be written — and sends the service nothing, so it asks again. Everything the cosigner has
/// *decided* comes back as `Ok`, because a refusal the service never receives is a refusal it will
/// keep asking about.
///
/// **The time this has.** One invocation, bounded by the runtime's request timeout — thirty seconds
/// by default — and two outbound calls inside it: `get_info` from the ASP and the evidence GET.
/// Both are given timeouts that fit, so a slow provider fails the release with something to say
/// rather than having the whole call killed.
async fn handle_release_request<A: AspApi, F: FetchEvidence>(
    wallet: &mut Cosigner,
    stream_id: &str,
    request: &ReleaseRequest,
    asp: Option<A>,
    fetcher: &F,
) -> Result<ToService, String> {
    match sign_release(wallet, stream_id, request, asp, fetcher).await {
        Ok(signed) => Ok(ToService::ReleaseSigned(Box::new(signed))),
        Err(ReleaseError::Refused(reason)) => Ok(ToService::ReleaseRefused {
            request_id: request.request_id.clone(),
            reason,
            deal: wallet
                .get_escrow_session(&request.escrow_key)
                .and_then(|escrow| escrow.disclose_terms_to(stream_id)),
        }),
        Err(ReleaseError::Faulted(e)) => Err(e),
    }
}

/// The release itself: the escrow found and its service checked, the payment checked against every
/// escrow's releases, the escrow's own judgement — [`EscrowSession::approve_release`] — and the
/// release sealed before it is signed.
async fn sign_release<A: AspApi, F: FetchEvidence>(
    wallet: &mut Cosigner,
    stream_id: &str,
    request: &ReleaseRequest,
    asp: Option<A>,
    fetcher: &F,
) -> Result<SignedRelease, ReleaseError> {
    let escrow = wallet
        .get_escrow_session(&request.escrow_key)
        .cloned()
        .ok_or_else(|| ReleaseError::Refused(StreamRefusal::UnknownEscrow.message()))?;

    // --- 1. the service that spoke is the one paired into this escrow ----------------------------
    //
    // Not a check of anything in the request: the message arrived on a connection the runtime
    // holds to an origin this image resolved from the paired service's identifier, and nothing
    // a service sends can move it onto another service's connection.
    escrow
        .verify_sender(stream_id, "")
        .map_err(|r| ReleaseError::Refused(r.message()))?;
    let key = escrow.pairing_key()?;

    // --- 6, asked first: has this payment justified a release already? ---------------------------
    //
    // Before the deal is consulted, because a repeat is not the current deal's business. It is
    // answered from its own record, under the deal that approved it, until that deal's
    // deadline — even if its service has ended the deal since. A service whose reply was lost
    // has paid out already, and must not lose the signature it was owed. Pure, and needs no
    // ASP; and a reference that has already been spent needs no provider to tell us it
    // succeeded.
    let proposal_hash = request.proposal_hash();
    let admission = wallet
        .admit_release(
            &escrow.escrow_key,
            &request.request_id,
            &request.payment_reference,
            &proposal_hash,
        )
        .map_err(ReleaseError::Refused)?;
    if let Admission::AlreadyAnswered(record) = admission {
        return escrow.repeat_release(request, &record, &key, asp).await;
    }

    // --- 2 to 5: what the escrow decides for itself ----------------------------------------------
    let approved = escrow.approve_release(request, proposal_hash, asp, fetcher).await?;

    // --- written down and sealed, and only then signed — see `Cosigner::seal_release` ------------
    wallet
        .seal_release(&escrow.escrow_key, request.payment_reference.clone(), approved.record)
        .map_err(ReleaseError::Faulted)?;
    approved.built.sign(&key, request, false)
}

// --- Releasing, and taking back what is left -------------------------------------------------

/// The pay-to-anchor script every Ark transaction carries: `OP_1 <0x4e73>`.
///
/// Zero-value by construction, spendable by anyone, and there so a transaction can be fee-bumped.
/// It is not a party to the payment and must not be judged as one.
const ANCHOR_SCRIPT_HEX: &str = "51024e73";

/// How many VTXOs one release may spend. Each costs a checkpoint transaction and two sighashes, and
/// a proposal is a message on a connection with a ceiling of its own.
const MAX_RELEASE_INPUTS: usize = 64;

/// A conclusion the service is told, or a fault a retry might fix.
pub(crate) enum ReleaseError {
    Refused(String),
    Faulted(String),
}

/// A release the escrow approved: what to write down, and what to sign once it is.
pub(crate) struct ApprovedRelease {
    pub(crate) record: ReleaseRecord,
    pub(crate) built: BuiltRelease,
}

/// What a proposal builds to.
pub(crate) struct BuiltRelease {
    send: ark::client::send::SendSession,
    sighashes: Vec<Vec<u8>>,
    info: ark::client::types::ArkInfo,
}

impl BuiltRelease {
    /// Sign what was built, with [key], and hand the service what it submits. [already_counted]
    /// tells a service that lost a reply that its allowance was not charged twice.
    pub(crate) fn sign(
        self,
        key: &SigningKey,
        request: &ReleaseRequest,
        already_counted: bool,
    ) -> Result<SignedRelease, ReleaseError> {
        let halves = key
            .sign_second(&self.sighashes, &request.commitments)
            .map_err(ReleaseError::Refused)?;
        let (ark_tx, checkpoint_txs) = self.send.unsigned();
        Ok(SignedRelease {
            request_id: request.request_id.clone(),
            ark_tx,
            checkpoint_txs,
            halves,
            already_counted,
        })
    }
}

/// Everything the wallet needs to sign a reclaim, and to see what it is signing.
pub struct Reclaim {
    pub session: SendSession,
    pub sighashes: Vec<Vec<u8>>,
    /// The wallet's own Ark address, derived here.
    pub to_ark_address: String,
    /// What is being taken back — everything the named VTXOs hold.
    pub amount_sats: u64,
    /// The escrow's key, for signing as `{wallet, cosigner}`.
    pub key: crate::sign::SigningKey,
    /// The two halves the wallet needs to rebuild its share of the escrow key.
    pub wallet_dealt_share: Vec<u8>,
    pub escrow_delta_share: Vec<u8>,
}

impl EscrowSession {
    /// Mint, round one: take the wallet's dealing, deal ours, and hand ours back — with the reshare
    /// in flight, for the stream to hold until round two.
    ///
    /// `wallet_kp` is this cosigner's key package for the wallet key `V` — the reshare is dealt
    /// under the identifier it already has there, so the deltas land on the same points as the old
    /// shares.
    pub fn begin_mint(
        wallet_kp: &KeyPackage,
        wallet_identifier: &[u8],
        wallet_round1_json: &str,
        context: &[u8],
    ) -> Result<(EscrowMint, String), Status> {
        // Enough to be unrepeatable by accident, small enough to seal for every escrow a wallet
        // holds.
        if context.len() < 16 || context.len() > 32 {
            return Err(Status::invalid_argument(
                "an escrow derivation context must be 16 to 32 bytes",
            ));
        }

        let wallet_id = Identifier::try_from(wallet_identifier)
            .map_err(|e| Status::invalid_argument(format!("bad identifier: {e}")))?;
        let server_id = wallet_kp.identifier.clone();
        if wallet_id == server_id {
            // Both deltas would land on one point and the reshare would not be a sharing at all.
            return Err(Status::invalid_argument(
                "the wallet's identifier is this cosigner's own",
            ));
        }

        let wallet_round1 = Round1Package::from_json(wallet_round1_json)
            .map_err(|e| Status::invalid_argument(format!("bad round1 package: {e}")))?;

        // Our own Δ. Fresh every ceremony and from the enclave's RNG: a delta reused across two
        // escrows would put two of this cosigner's dealings on one line.
        let mut rng = OsRng;
        let secret = random::mod_n_random(&mut rng);
        let coefficients: Vec<_> = (0..THRESHOLD_COUNT - 1)
            .map(|_| random::mod_n_random(&mut rng))
            .collect();
        let (r1_secret, r1_pub) = dkg::dkg_reshare_part1(
            &server_id,
            TOTAL_PARTICIPANTS,
            THRESHOLD_COUNT,
            &secret,
            &coefficients,
            &mut rng,
        )
        .map_err(|e| Status::internal(format!("dkg_reshare_part1: {e}")))?;

        let mint = EscrowMint {
            wallet_id,
            wallet_round1,
            context_hex: hex::encode(context),
            server_id,
            round1_secret: r1_secret,
        };
        Ok((mint, r1_pub.to_json()))
    }

    /// Mint, round two: take the wallet's share of its delta, finalize `V'`, and hand back ours —
    /// with the escrow it minted, ready to seal: no service paired into it yet, and no deal.
    pub fn finalise_mint(
        mint: EscrowMint,
        wallet_kp: &KeyPackage,
        wallet_pkp: &PublicKeyPackage,
        wallet_round2_json: &str,
        now: i64,
    ) -> Result<(String, EscrowSession), Status> {
        let EscrowMint {
            wallet_id,
            wallet_round1,
            context_hex,
            server_id,
            round1_secret: r1_secret,
        } = mint;
        let wallet_round2 = Round2Package::from_json(wallet_round2_json)
            .map_err(|e| Status::invalid_argument(format!("bad round2 package: {e}")))?;

        let peers_round1: BTreeMap<Identifier, Round1Package> =
            [(wallet_id.clone(), wallet_round1)].into_iter().collect();

        // Our round 2: a share of our delta for the wallet. No passive receivers — both parties
        // deal and both finalize, so `dkg_part2` is given an empty receiver list.
        let (r2_secret, our_shares): (Round2SecretPackage, BTreeMap<Identifier, Round2Package>) =
            dkg::dkg_part2(&r1_secret, &peers_round1, &[])
                .map_err(|e| Status::internal(format!("dkg_part2: {e}")))?;
        let for_wallet = our_shares
            .get(&wallet_id)
            .ok_or_else(|| Status::internal("our reshare dealt the wallet nothing"))?
            .clone();

        let peers_round2: BTreeMap<Identifier, Round2Package> =
            [(wallet_id.clone(), wallet_round2)].into_iter().collect();
        let receivers = [wallet_id.clone(), server_id];

        let (new_kp, new_pkp) = dkg::dkg_reshare_part3(
            &r2_secret,
            &peers_round1,
            &peers_round2,
            wallet_pkp,
            wallet_kp,
            &receivers,
        )
        .map_err(|e| Status::internal(format!("dkg_reshare_part3: {e}")))?;

        let public_key_package_json = new_pkp.to_json();
        let escrow = EscrowSession {
            escrow_key: crate::serde::extract_verifying_key(&public_key_package_json)?,
            key_package_json: new_kp.to_json(),
            public_key_package_json,
            wallet_identifier_hex: hex::encode(wallet_id.serialize()),
            context_hex,
            // `Δ_cosigner(id_wallet)`: its own term, never summed with anything — see the module
            // note on the two normalisations.
            wallet_delta_share_hex: hex::encode(scalar_to_bytes(&for_wallet.secret_share)),
            created_at: now,
            stage: EscrowStage::Minted,
        };
        Ok((for_wallet.to_json(), escrow))
    }

    /// The service paired into it, once one is.
    pub fn pairing(&self) -> Option<&ServicePairing> {
        match &self.stage {
            EscrowStage::Minted => None,
            EscrowStage::Paired(pairing) | EscrowStage::Dealt { pairing, .. } => Some(pairing),
        }
    }

    fn pairing_mut(&mut self) -> Option<&mut ServicePairing> {
        match &mut self.stage {
            EscrowStage::Minted => None,
            EscrowStage::Paired(pairing) | EscrowStage::Dealt { pairing, .. } => Some(pairing),
        }
    }

    /// Its deal, once struck.
    pub fn terms(&self) -> Option<&DealTerms> {
        match &self.stage {
            EscrowStage::Dealt { terms, .. } => Some(terms),
            _ => None,
        }
    }

    /// Every payment it has released against — none before its deal.
    pub fn releases(&self) -> &BTreeMap<String, ReleaseRecord> {
        match &self.stage {
            EscrowStage::Dealt { releases, .. } => releases,
            _ => &NO_RELEASES,
        }
    }

    /// Its key material, to deal a pairing or sign a reclaim against. `None` when what was sealed
    /// does not parse.
    pub(crate) fn key_material(&self) -> Option<EscrowKeyMaterial> {
        let id_bytes: [u8; 32] = hex::decode(&self.wallet_identifier_hex).ok()?.try_into().ok()?;
        Some(EscrowKeyMaterial {
            key_package: KeyPackage::from_json(&self.key_package_json).ok()?,
            public_key_package: PublicKeyPackage::from_json(&self.public_key_package_json).ok()?,
            wallet_id: Identifier::deserialize(&id_bytes).ok()?,
        })
    }

    /// Deal this cosigner's half of a service pairing into this escrow, and refuse anything that
    /// would not be a pairing.
    ///
    /// `a_at_cosigner` is the wallet's contribution to *this cosigner*, a 32-byte scalar;
    /// `a_at_service_point` is its contribution to the service, a 33-byte compressed point. See
    /// the module note on pairing for what is checked, and why.
    pub fn prepare_pairing(
        &self,
        service_id: &Identifier,
        a_at_cosigner: &[u8],
        a_at_service_point: &[u8],
    ) -> Result<PairingMaterial, Status> {
        let keys = self
            .key_material()
            .ok_or_else(|| Status::internal("this escrow's sealed key material is unreadable"))?;
        let cosigner_id = keys.key_package.identifier.clone();
        if service_id == &cosigner_id || service_id == &keys.wallet_id {
            return Err(Status::invalid_argument(
                "a service must have an identifier of its own, not one already in the escrow",
            ));
        }

        let a_c: [u8; 32] = a_at_cosigner.try_into().map_err(|_| {
            Status::invalid_argument("the wallet's scalar contribution must be 32 bytes")
        })?;
        let a_c = scalar_from_bytes(&a_c)
            .map_err(|e| Status::invalid_argument(format!("bad scalar contribution: {e}")))?;
        let a_s: [u8; 33] = a_at_service_point.try_into().map_err(|_| {
            Status::invalid_argument("the wallet's point contribution must be 33 bytes")
        })?;
        let a_s_point = point::deserialize_compressed(&a_s)
            .map_err(|e| Status::invalid_argument(format!("bad point contribution: {e}")))?;

        // The half this cosigner cannot see, pinned down from public data. A wallet that lies here
        // steers the package everything downstream trusts.
        verify_user_contribution(
            &keys.public_key_package,
            &keys.wallet_id,
            &cosigner_id,
            service_id,
            &a_c,
            &a_s_point,
        )
        .map_err(|e| {
            Status::invalid_argument(format!(
                "the wallet's contribution to this service does not check out: {e}"
            ))
        })?;

        // This cosigner's own half is drawn from the enclave's RNG, never derived and never
        // influenced by a caller: it is the half that makes each pairing's slope distinct, and two
        // pairings on one slope are two points on one line.
        let mut id_partial = BTreeMap::new();
        id_partial.insert(keys.wallet_id.clone(), scalar_to_bytes(&a_c));
        let pairing = dkg::refresh_to_receiver(
            &keys.key_package,
            &Receiver {
                id: service_id.clone(),
                partial_verifying_share: a_s,
            },
            &id_partial,
            MIN_SIGNERS,
            &mut OsRng,
        )
        .map_err(|e| Status::internal(format!("refresh_to_receiver: {e}")))?;

        // A refresh preserves the key. If this one did not, the pairing signs for something that is
        // not the escrow — and money sent to the escrow would be unreachable through it.
        if !point::points_equal(
            &pairing.pairing_pkp.verifying_key.point,
            &keys.public_key_package.verifying_key.point,
        ) {
            return Err(Status::internal(
                "the pairing moved the escrow key; a refresh must preserve it",
            ));
        }

        // A zero slope would make the pairing polynomial constant and hand the service the group
        // secret. See the module note: nothing upstream prevents it.
        service_poly_commitment(&pairing.pairing_pkp, service_id, MIN_SIGNERS).map_err(|e| {
            Status::invalid_argument(format!(
                "this pairing would let the service sign alone, and is refused: {e}"
            ))
        })?;

        let pkp_json = pairing.pairing_pkp.to_json();
        let verifying_share = pairing
            .pairing_pkp
            .verifying_shares
            .get(service_id)
            .ok_or_else(|| Status::internal("the pairing does not name the service it is for"))?;

        Ok(PairingMaterial {
            service_identifier_hex: hex::encode(service_id.serialize()),
            key_package_json: pairing.my_kp.to_json(),
            public_key_package_json: pkp_json,
            service_half: pairing.receiver_half.to_vec(),
            service_verifying_share_hex: hex::encode(point::serialize_compressed(verifying_share)),
        })
    }

    /// Record the service paired into it.
    ///
    /// One service per escrow, and refused if there is already one: a second pairing would be a
    /// second way to be paid out of money committed to a single deal, and the escrow has no way to
    /// say which of them the deal was with.
    pub fn record_pairing(&mut self, pairing: ServicePairing) -> Result<(), String> {
        match &self.stage {
            // Replaceable only while unfinished — see the note at the call site in `session.rs`. A
            // retry deals fresh halves, so the record it replaces is one nothing could have used.
            EscrowStage::Paired(held) if held.state() == PairingState::Ready => {
                return Err("this escrow already has a service paired into it".into())
            }
            EscrowStage::Minted | EscrowStage::Paired(_) => {}
            EscrowStage::Dealt { .. } => {
                return Err(
                    "this escrow is committed to a deal with the service already paired into it"
                        .into(),
                )
            }
        }
        self.stage = EscrowStage::Paired(pairing);
        Ok(())
    }

    /// One party's word that pairing attempt `attempt_id_hex` works, recorded by `set`:
    ///
    /// - the WALLET's, `wallet_confirmed` — it delivered its own half and the service took it;
    /// - the SERVICE's, `service_confirmed` — it holds both halves and the share they sum to
    ///   matches the published verifying share. Arrives over the connection the runtime holds, as
    ///   [`FromService::PairingReady`].
    ///
    /// Neither is enough on its own: a pairing is usable once both have said so — see
    /// [`ServicePairing::state`] — because each party can see only its own side.
    ///
    /// Idempotent: confirming one that is already confirmed is what a retry looks like, and the
    /// answer to it is yes.
    pub fn confirm_pairing(
        &mut self,
        attempt_id_hex: &str,
        set: impl FnOnce(&mut ServicePairing),
    ) -> Result<(), String> {
        let pairing = self.pairing_mut().ok_or("this escrow has no service paired into it")?;
        if pairing.attempt_id_hex != attempt_id_hex {
            // Confirming attempt A on the strength of attempt B's delivery would mark a pairing
            // usable that nobody has shown to work.
            return Err(
                "that confirmation is for a different pairing attempt than the one this escrow \
                 holds"
                    .into(),
            );
        }
        set(pairing);
        Ok(())
    }

    /// Did the message on `stream_id` come from this escrow's paired service — and, when it names
    /// one, about the pairing attempt this escrow holds?
    ///
    /// The whole of the authentication, and it is a lookup rather than a check of anything in the
    /// message: the escrow's pairing names a service, that service resolves to a stream id, and a
    /// message cannot arrive on a stream other than the one the runtime holds to that service's
    /// origin. See *What authenticates the far side* in the module note.
    pub(crate) fn verify_sender(
        &self,
        stream_id: &str,
        attempt_id: &str,
    ) -> Result<(), StreamRefusal> {
        let pairing = self.pairing().ok_or(StreamRefusal::UnknownEscrow)?;
        if service_stream_id(&pairing.service_identifier_hex) != stream_id {
            return Err(StreamRefusal::NotYourEscrow);
        }
        if !attempt_id.is_empty() && pairing.attempt_id_hex != attempt_id {
            return Err(StreamRefusal::StaleAttempt);
        }
        Ok(())
    }

    /// Commit it to its deal: once, by the session that minted it and paired its service in.
    /// Refuses an escrow with no service, and refuses a second deal.
    ///
    /// No service means nobody could ever release, so a deal on such an escrow would lock the owner
    /// out of their own money until a deadline for no one's benefit. And never twice: once a
    /// reclaim may have been opened the owner may hold signatures that empty the escrow, and a deal
    /// struck over them would be one the owner could empty at will — so the next deal gets the next
    /// escrow, always.
    pub fn strike_deal(&mut self, terms: DealTerms) -> Result<(), String> {
        let pairing = match &self.stage {
            EscrowStage::Minted => {
                return Err(
                    "this escrow has no service paired into it: committing it would lock the \
                     money away until the deadline with nobody able to take it"
                        .into(),
                )
            }
            EscrowStage::Dealt { .. } => {
                return Err(
                    "this escrow is already committed to its deal; the next deal needs a new \
                     escrow"
                        .into(),
                )
            }
            EscrowStage::Paired(pairing) => pairing.clone(),
        };
        self.stage = EscrowStage::Dealt {
            pairing,
            terms,
            releases: BTreeMap::new(),
        };
        Ok(())
    }

    /// Whether its deal is running: struck, and before its deadline.
    ///
    /// The clock, and nothing else. Time passes without anybody writing anything down, so a restart
    /// reaches the same conclusion as the instance that struck the deal — from the seal and the
    /// clock, which is all there is.
    pub fn is_active(&self, now: i64) -> bool {
        self.terms().is_some_and(|t| now < t.deadline)
    }

    /// May `{service, cosigner}` sign? The *timing* question only — what a release pays and how
    /// much is the policy's business, and is checked separately against the transaction.
    pub fn may_release(&self, now: i64) -> Result<(), Refusal> {
        if self.is_active(now) {
            Ok(())
        } else {
            Err(Refusal::DealEnded)
        }
    }

    /// May `{wallet, cosigner}` sign? Only once the deal is no longer running — otherwise an owner
    /// could empty an escrow the service is still entitled to take from.
    pub fn may_reclaim(&self, now: i64) -> Result<(), Refusal> {
        if self.is_active(now) {
            Err(Refusal::StillOpen)
        } else {
            Ok(())
        }
    }

    /// Write down a release this escrow made, under the payment that justified it. Does not end the
    /// deal: an escrow is spent against, not spent once — see [`is_spent`](Self::is_spent).
    ///
    /// Only ever called for a release that was not recorded before — a second signature over an
    /// already-answered request adds nothing, because it spends the inputs the first one did.
    pub fn record_release(
        &mut self,
        reference: String,
        record: ReleaseRecord,
    ) -> Result<(), String> {
        let EscrowStage::Dealt { releases, .. } = &mut self.stage else {
            return Err("this escrow has no deal to release under".into());
        };
        releases.insert(reference, record);
        Ok(())
    }

    /// What this escrow has released, in all: read off its releases, never kept beside them.
    pub fn released_sats(&self) -> u64 {
        self.releases().values().fold(0, |total, r| total.saturating_add(r.sats))
    }

    /// Has everything its deal allows been released?
    ///
    /// Derived, never recorded: the cap is the policy's own `released_total_max`. A policy with no
    /// such cap is never spent, and runs to its deadline.
    pub fn is_spent(&self) -> bool {
        self.terms()
            .and_then(|t| t.policy.released_total_cap())
            .is_some_and(|cap| self.released_sats() >= cap)
    }

    /// Does its deal still hold the escrow — running, and with something left to release?
    pub fn is_open(&self, now: i64) -> bool {
        self.is_active(now) && !self.is_spent()
    }

    /// The service ends the deal: the deadline comes forward to `now`, and never goes back.
    ///
    /// Only the service may ask, because the deal protects the service — this gives up nothing but
    /// its own claim. What was already released keeps its own deadline in its record, so ending the
    /// deal early does not let the owner race a release the service has yet to submit.
    ///
    /// `policy_sha256` names the deal, so an end meant for another escrow's cannot end this one.
    /// Ending a deal that is already over is not an error: the service asked for something that is
    /// already true.
    pub fn end_by_service(&mut self, policy_sha256: &str, now: i64) -> Result<(), String> {
        let EscrowStage::Dealt { terms, .. } = &mut self.stage else {
            return Err("this escrow is not committed to a deal".into());
        };
        if crate::policy::policy_sha256(&terms.policy) != policy_sha256 {
            return Err("that is not the deal this escrow is committed to".into());
        }
        terms.deadline = terms.deadline.min(now);
        Ok(())
    }

    /// The earliest moment the owner may take this escrow back: the later of its deal's deadline
    /// and the deadline of every release it made.
    ///
    /// A deal can end early — spent, or ended by its service — and the service may still hold a
    /// release's signatures it has yet to submit; a reclaim spends the same VTXOs, so the deadline
    /// that release was promised still stands for the owner. Past it, nothing can be released.
    pub fn horizon(&self) -> i64 {
        let deadline = self.terms().map_or(0, |t| t.deadline);
        self.releases().values().map(|r| r.deadline).fold(deadline, i64::max)
    }

    /// What its service is told about the deal. See [`SealedTerms`].
    pub fn sealed_terms(&self) -> Option<SealedTerms> {
        self.terms().map(|t| SealedTerms {
            opened_at: t.opened_at,
            deadline: t.deadline,
            policy_sha256: crate::policy::policy_sha256(&t.policy),
        })
    }

    // --- Releasing, and taking back what is left -------------------------------------------

    /// The terms of this escrow's deal, for the service on `stream_id` if it is the one paired
    /// into it, and for nobody else. A refusal is where a service that asks before paying learns
    /// them: that the deal it offered is the one sealed, and how long it has to be repaid.
    pub(crate) fn disclose_terms_to(&self, stream_id: &str) -> Option<SealedTerms> {
        self.verify_sender(stream_id, "").ok()?;
        self.sealed_terms()
    }

    /// Judge a release against this escrow's deal — checks 2 to 5 of the module note — and, if it
    /// holds up, hand back what to write down and what to sign once it is.
    pub(crate) async fn approve_release<A: AspApi, F: FetchEvidence>(
        &self,
        request: &ReleaseRequest,
        proposal_hash: String,
        asp: Option<A>,
        fetcher: &F,
    ) -> Result<ApprovedRelease, ReleaseError> {
        let terms = self.terms().cloned().ok_or_else(|| {
            ReleaseError::Refused(
                "this escrow is not committed to a deal, so there is nothing to release".into(),
            )
        })?;

        // --- 2. the escrow permits a release now ---------------------------------------------
        //
        // Asked here to refuse early — a closed escrow needs no transaction built and no provider
        // told about a release that is not going to happen. It is asked AGAIN before signing, and
        // that is the one that decides; see below.
        self.may_release(crate::handlers::helpers::now_secs())
            .map_err(|r| ReleaseError::Refused(r.message().to_string()))?;

        // --- the transaction, built here from the proposal ------------------------------------
        let built = self.build_release(request, asp).await?;

        // What leaves the escrow, and what it costs. Change back to the escrow's own scripts is not
        // a payment to anybody, so it is not egress — the policy is told which scripts are ours.
        let mut owned = self.own_scripts(&built.info, &request.inputs).map_err(|e| {
            ReleaseError::Faulted(format!("working out this escrow's own scripts: {e}"))
        })?;
        let outputs = crate::policy::outputs_of_txouts(built.send.outputs());

        // The anchor is not a destination. Every Ark transaction carries a zero-value pay-to-anchor
        // output so the transaction can be fee-bumped; it pays nobody, and a policy that counted it
        // as egress would refuse every release ever made.
        //
        // Only at zero, and that matters: anyone can spend a P2A output, so one carrying value
        // would be money leaving the escrow to whoever claimed it first. If one ever does, that is
        // not an anchor and it is not waved through.
        if outputs.iter().any(|o| o.script_pubkey_hex == ANCHOR_SCRIPT_HEX) {
            if let Some(bearing) = outputs
                .iter()
                .find(|o| o.script_pubkey_hex == ANCHOR_SCRIPT_HEX && o.sats > 0)
            {
                return Err(ReleaseError::Refused(format!(
                    "this release puts {} sats in a pay-to-anchor output, which anybody may spend",
                    bearing.sats
                )));
            }
            owned.insert(ANCHOR_SCRIPT_HEX.to_string());
        }
        let paid_in: u64 = request.inputs.iter().map(|i| i.amount_sats).sum();
        let paid_out: u64 = outputs.iter().map(|o| o.sats).sum();
        let fee_sats = paid_in.checked_sub(paid_out).ok_or_else(|| {
            ReleaseError::Refused("this release pays out more than it spends".into())
        })?;
        let egress_sats: u64 = outputs
            .iter()
            .filter(|o| !owned.contains(&o.script_pubkey_hex))
            .map(|o| o.sats)
            .sum();

        // --- 3, 4 and 5. the policy, over what was built and what was fetched ------------------
        let facts = ReleaseFacts {
            reference: request.payment_reference.clone(),
            sats: egress_sats,
            fee_sats,
            already_released_sats: self.released_sats(),
        };
        let evidence =
            crate::evidence::gather(fetcher, &terms.policy.evidence_needed(&facts)).await;
        crate::policy::enforce_release(
            &terms.policy,
            Some(&outputs),
            &owned,
            &facts,
            &evidence,
        )
        .map_err(ReleaseError::Refused)?;

        // --- 2, again, and this is the check that counts --------------------------------------
        //
        // The clock moved while this was asking other people questions. Between the first check
        // and here there were two calls out — the ASP's `get_info` and the evidence GET — each
        // with seconds of budget, and a provider that takes its time is the normal case rather
        // than a strange one.
        //
        // It has to be asked again because this refusal is the ONLY thing holding the escrow's
        // boundary. Nothing in Bitcoin stops a signature made after the deadline: both pairs sign
        // the same key, so what stops a service taking money the owner is entitled to reclaim is
        // this cosigner declining to co-sign, and a decision made on a clock reading from before
        // the wait is not a decision about now.
        let signing_at = crate::handlers::helpers::now_secs();
        self.may_release(signing_at)
            .map_err(|r| ReleaseError::Refused(r.message().to_string()))?;

        Ok(ApprovedRelease {
            record: ReleaseRecord {
                request_id: request.request_id.clone(),
                sats: egress_sats,
                at: signing_at,
                proposal_hash,
                // What this release keeps of its deal once its service ends it early: how long a
                // repeat is answered, and how long the owner must wait to reclaim.
                deadline: terms.deadline,
            },
            built,
        })
    }

    /// A repeat of a release already approved: the same proposal, signed again over the fresh
    /// commitments a service that lost its reply brings, and counted nothing.
    ///
    /// Not judged again. The proposal hash is the same, so the transaction is the one the policy
    /// and the evidence were checked against when it was approved — and a payment that succeeded
    /// goes on having succeeded. What bounds a repeat is the deadline of the deal that approved it,
    /// sealed in its record: until then the owner may not reclaim ([`EscrowSession::horizon`]),
    /// so a signature over these inputs cannot race her; from then on, a repeat is refused. Asked
    /// twice, like a first answer, because the ASP is asked in between.
    pub(crate) async fn repeat_release<A: AspApi>(
        &self,
        request: &ReleaseRequest,
        record: &ReleaseRecord,
        key: &SigningKey,
        asp: Option<A>,
    ) -> Result<SignedRelease, ReleaseError> {
        let deal_over = |now: i64| {
            (now >= record.deadline).then(|| {
                ReleaseError::Refused(format!(
                    "request {} was approved under a deal that ended at {}; a repeat of it could \
                     be answered until then and not after",
                    request.request_id, record.deadline
                ))
            })
        };
        if let Some(refused) = deal_over(crate::handlers::helpers::now_secs()) {
            return Err(refused);
        }
        let built = self.build_release(request, asp).await?;
        if let Some(refused) = deal_over(crate::handlers::helpers::now_secs()) {
            return Err(refused);
        }
        built.sign(key, request, true)
    }

    /// Build the transaction a proposal describes — the same build for a first answer and a
    /// repeat, so a repeat signs exactly what was approved.
    async fn build_release<A: AspApi>(
        &self,
        request: &ReleaseRequest,
        asp: Option<A>,
    ) -> Result<BuiltRelease, ReleaseError> {
        if request.inputs.is_empty() {
            return Err(ReleaseError::Refused(
                "a release that spends nothing pays nobody".into(),
            ));
        }
        if request.inputs.len() > MAX_RELEASE_INPUTS {
            return Err(ReleaseError::Refused(format!(
                "a release may spend at most {MAX_RELEASE_INPUTS} VTXOs"
            )));
        }
        let mut seen = BTreeSet::new();
        for input in &request.inputs {
            if !seen.insert((input.txid.to_ascii_lowercase(), input.vout)) {
                return Err(ReleaseError::Refused(
                    "the same VTXO is named twice, which is not a transaction this chain accepts"
                        .into(),
                ));
            }
        }

        let mut asp = asp.ok_or_else(|| {
            ReleaseError::Refused(
                "this deployment names no ASP, so there is nothing to build a release against"
                    .into(),
            )
        })?;
        let info = asp
            .get_info()
            .await
            .map_err(|e| ReleaseError::Faulted(format!("asking the ASP what it is: {e}")))?;

        let vtxos: Vec<crate::types::VtxoInput> = request
            .inputs
            .iter()
            .map(|i| crate::types::VtxoInput {
                txid: i.txid.clone(),
                vout: i.vout,
                amount_sats: i.amount_sats,
                exit_delay: i.exit_delay,
                expires_at: 0,
            })
            .collect();
        let (send, _change_delay, sighashes) = crate::cosigner::build_send(
            &x_only(&self.escrow_key),
            &vtxos,
            &crate::types::SendVtxoStep1 {
                recipient_ark_address: request.to_ark_address.clone(),
                amount: request.amount_sats,
                vtxos: vtxos.clone(),
            },
            &info,
        )
        .map_err(|e| ReleaseError::Refused(format!("that release does not build: {e}")))?;

        if request.commitments.len() != sighashes.len() {
            // Before any nonce is made, so nothing of this cosigner's is spent on a mismatch. The
            // service discards its own unused nonces and asks again with the right count.
            return Err(ReleaseError::Refused(format!(
                "this release has {} things to sign and {} commitments arrived; send one \
                 commitment per signature, in order",
                sighashes.len(),
                request.commitments.len()
            )));
        }
        Ok(BuiltRelease {
            send,
            sighashes,
            info,
        })
    }

    /// The key this cosigner signs a release with: its side of the escrow's pairing, read out of
    /// the seal — once the pairing is finished, and not before.
    ///
    /// Read before anything is written down, so a pairing whose sealed material is unreadable is a
    /// fault reported before a release is recorded rather than after.
    pub(crate) fn pairing_key(&self) -> Result<SigningKey, ReleaseError> {
        let pairing = self
            .pairing()
            .ok_or_else(|| ReleaseError::Refused(StreamRefusal::UnknownEscrow.message()))?;
        if pairing.state() != PairingState::Ready {
            return Err(ReleaseError::Refused(format!(
                "this escrow's service pairing is not finished: {}",
                pairing.awaiting()
            )));
        }
        let unreadable = |what: &str, e: String| {
            ReleaseError::Faulted(format!("this pairing's sealed {what} is unreadable: {e}"))
        };
        Ok(SigningKey {
            key_package: KeyPackage::from_json(&pairing.key_package_json)
                .map_err(|e| unreadable("share", e.to_string()))?,
            public_key_package: PublicKeyPackage::from_json(&pairing.public_key_package_json)
                .map_err(|e| unreadable("package", e.to_string()))?,
            counterparty: pairing
                .service_identifier_hex
                .parse::<Identifier>()
                .map_err(|e| unreadable("identifier", e.to_string()))?,
        })
    }

    /// The scriptPubKeys that belong to this escrow: one per exit delay among the inputs, plus the
    /// one change is paid to. An output to any of these is not a payment to anybody — it is the
    /// escrow's own money staying where it was.
    fn own_scripts(
        &self,
        info: &ark::client::types::ArkInfo,
        inputs: &[ProposedInput],
    ) -> Result<BTreeSet<String>, String> {
        let owner = x_only(&self.escrow_key);
        let network = ark::client::parse_network(&info.network)?;
        let mut delays: BTreeSet<u32> = inputs.iter().map(|i| i.exit_delay).collect();
        // `build_send` derives change at the ASP's unilateral exit delay, whatever the inputs'
        // were.
        delays.insert(info.unilateral_exit_delay as u32);
        delays
            .into_iter()
            .map(|delay| {
                ark::client::vtxo_script_pubkey_hex(&owner, &info.signer_pubkey, delay, network)
                    .map(|s| s.to_ascii_lowercase())
            })
            .collect()
    }

    /// Build the reclaim of what this escrow holds, to [to_ark_address], or say why there is not
    /// one to build.
    pub fn prepare_reclaim(
        &self,
        vtxos: Vec<VtxoInput>,
        info: &ArkInfo,
        now: i64,
        to_ark_address: String,
        wallet_dealt_share: Vec<u8>,
    ) -> Result<Reclaim, Status> {
        // The deal first. An escrow with no deal was never committed to anything, so there is
        // nothing holding it and the owner may take it back whenever they like.
        if let Err(refusal) = self.may_reclaim(now) {
            return Err(match refusal {
                Refusal::StillOpen => Status::failed_precondition(refusal.message()),
                // `may_reclaim` returns nothing else, and a new variant should be decided about
                // rather than folded into the nearest existing answer.
                other => Status::failed_precondition(other.message()),
            });
        }
        // And every release it made. A deal can end early — spent, or ended by its service — and
        // the service may still be holding a release's signatures; it was promised until that
        // deal's deadline to submit them. See `EscrowSession::horizon`.
        let horizon = self.horizon();
        if now < horizon {
            return Err(Status::failed_precondition(format!(
                "a release from this escrow may still be on its way to the ASP until {horizon}; \
                 it can be taken back after that"
            )));
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

        let delta = hex::decode(&self.wallet_delta_share_hex)
            .map_err(|e| Status::internal(format!("sealed escrow delta is not hex: {e}")))?;
        let EscrowKeyMaterial {
            key_package,
            public_key_package,
            wallet_id: wallet_identifier,
        } = self
            .key_material()
            .ok_or_else(|| Status::internal("this escrow's sealed key material is unreadable"))?;

        // The escrow's key is the owner of what is being spent.
        let (session, _change_delay, sighashes) = crate::cosigner::build_send(
            &crate::cosigner::x_only(&self.escrow_key),
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
            key: crate::sign::SigningKey {
                key_package,
                public_key_package,
                counterparty: wallet_identifier,
            },
            wallet_dealt_share,
            escrow_delta_share: delta,
        })
    }

    // --- What a caller may see -------------------------------------------------------------

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
                .pairing()
                .map(|p| p.service_identifier_hex.clone())
                .unwrap_or_default(),
            service_ready: self
                .pairing()
                .is_some_and(|p| p.state() == PairingState::Ready),
            // Reported apart as well as together: they arrive by different routes, at
            // different moments, and a caller waiting on one wants to know which.
            service_confirmed: self
                .pairing()
                .is_some_and(|p| p.service_confirmed),
            wallet_confirmed: self
                .pairing()
                .is_some_and(|p| p.wallet_confirmed),
            session: self.terms().map(|t| proto::EscrowSessionSummary {
                // Whether it can still release: running, and not yet spent.
                open: self.is_open(now),
                deadline_secs: t.deadline,
                opened_at: t.opened_at,
                released_sats: self.released_sats(),
                policy_description: t.policy.describe(),
            }),
            context: hex::decode(&self.context_hex).unwrap_or_default(),
        }
    }
}

// --- Minting an escrow key ----------------------------------------------------------------------

/// A 2-of-2 reshare is degree 1: one constant term and one coefficient above it.
const THRESHOLD_COUNT: usize = 2;
const TOTAL_PARTICIPANTS: usize = 2;

/// The reshare in flight between [`EscrowSession::begin_mint`] and
/// [`EscrowSession::finalise_mint`]: the round-one secret an escrow key is born from, and what the
/// wallet dealt with it.
///
/// Held by the stream across its one round trip — never in a map, never sealed — and spent by
/// `finalise_mint`, so it is used once by construction. Like the onboarding ceremony and for the
/// same reason: a session parked anywhere is a window in which the secrets can be read. Here they
/// live on one frame and die with it.
pub struct EscrowMint {
    wallet_id: Identifier,
    wallet_round1: Round1Package,
    context_hex: String,
    server_id: Identifier,
    round1_secret: Round1SecretPackage,
}

#[cfg(test)]
mod tests {
    use super::*;

    const NOW: i64 = 1_000_000;
    const HOUR: i64 = 3_600;

    /// A service, paired in and confirmed by both parties. Its key is never read here.
    fn paired() -> ServicePairing {
        ServicePairing {
            service_identifier_hex: "44".repeat(32),
            key_package_json: String::new(),
            public_key_package_json: String::new(),
            service_verifying_share_hex: "55".repeat(33),
            paired_at: NOW,
            attempt_id_hex: "aa".repeat(16),
            service_confirmed: true,
            wallet_confirmed: true,
        }
    }

    /// An escrow struck on [policy] for an hour. Its key is never read here.
    fn struck(policy: Policy) -> EscrowSession {
        EscrowSession {
            escrow_key: String::new(),
            key_package_json: String::new(),
            public_key_package_json: String::new(),
            wallet_identifier_hex: String::new(),
            context_hex: String::new(),
            wallet_delta_share_hex: String::new(),
            created_at: NOW,
            stage: EscrowStage::Dealt {
                pairing: paired(),
                terms: DealTerms::validate(policy, NOW, NOW + HOUR).unwrap(),
                releases: BTreeMap::new(),
            },
        }
    }

    fn session() -> EscrowSession {
        struck(Policy::Always)
    }

    /// A release of [sats], recorded under its own reference.
    fn release(s: &mut EscrowSession, sats: u64) {
        let reference = format!("tx-{}", s.releases().len());
        s.record_release(
            reference,
            ReleaseRecord {
                request_id: "r".into(),
                sats,
                at: NOW,
                proposal_hash: "p".into(),
                deadline: NOW + HOUR,
            },
        )
        .expect("a dealt escrow records its releases");
    }

    fn deadline(s: &EscrowSession) -> i64 {
        s.terms().unwrap().deadline
    }

    /// Its service ends [s]'s deal at [now], naming it as a service does.
    fn end(s: &mut EscrowSession, now: i64) {
        let deal = crate::policy::policy_sha256(&s.terms().unwrap().policy);
        s.end_by_service(&deal, now).expect("its own deal");
    }

    #[test]
    fn while_it_is_running_the_service_may_take_and_the_owner_may_not() {
        let s = session();
        assert!(s.may_release(NOW).is_ok());
        assert!(s.may_release(NOW + HOUR - 1).is_ok());
        assert_eq!(s.may_reclaim(NOW), Err(Refusal::StillOpen));
    }

    /// The moment the clock passes, both answers swap — with nothing written down in between, and
    /// nothing to write. That is the whole of the design: one way for a deal to end, and it leaves
    /// no record because there is no record to leave.
    #[test]
    fn at_the_deadline_the_answers_swap_without_anybody_writing_anything() {
        let s = session();
        assert!(s.may_release(NOW + HOUR - 1).is_ok());
        assert_eq!(s.may_reclaim(NOW + HOUR - 1), Err(Refusal::StillOpen));

        assert_eq!(s.may_release(NOW + HOUR), Err(Refusal::DealEnded));
        assert!(s.may_reclaim(NOW + HOUR).is_ok());

        // And a reseated instance reads the same seal and agrees, because the seal never changed.
        let round_tripped: EscrowSession =
            serde_json::from_str(&serde_json::to_string(&s).unwrap()).unwrap();
        assert_eq!(round_tripped.may_release(NOW + HOUR), Err(Refusal::DealEnded));
        assert!(round_tripped.may_reclaim(NOW + HOUR).is_ok());
    }

    /// The owner has no way to end a deal early, and that is the point rather than an omission.
    ///
    /// A commitment the owner can revoke is not a commitment: a service that had already paid a
    /// merchant against it would be left holding the loss. Her control is the deadline she chose.
    /// The two things that shorten a deal both belong to the service: ending it, and taking all of
    /// it.
    #[test]
    fn only_the_service_can_cut_a_deal_short() {
        let s = session();
        // The whole of a deal's terms. If something else that ends a deal early is ever added, this
        // stops compiling — which is the point of writing it down.
        let DealTerms {
            policy: _,
            opened_at: _,
            deadline,
        } = s.terms().cloned().unwrap();
        assert_eq!(deadline, NOW + HOUR);
        assert!(s.may_release(NOW + HOUR - 1).is_ok(), "the owner cannot cut this short");
    }

    #[test]
    fn the_service_ending_a_deal_brings_the_deadline_forward_and_never_back() {
        let mut s = session();
        end(&mut s, NOW + 60);
        assert_eq!(deadline(&s), NOW + 60);
        assert_eq!(s.may_release(NOW + 60), Err(Refusal::DealEnded));
        assert!(s.may_reclaim(NOW + 60).is_ok());

        // Ending it again later is not a way to extend it.
        end(&mut s, NOW + HOUR * 2);
        assert_eq!(deadline(&s), NOW + 60);
    }

    /// An escrow whose session ended before its deal was struck has none, and never will:
    /// nothing is released from it, and it is its owner's to take back.
    #[test]
    fn an_escrow_with_no_deal_releases_nothing_and_is_its_owners() {
        for stage in [EscrowStage::Minted, EscrowStage::Paired(paired())] {
            let s = EscrowSession { stage, ..session() };
            assert_eq!(s.may_release(NOW), Err(Refusal::DealEnded));
            assert!(s.may_reclaim(NOW).is_ok());
            assert_eq!(s.horizon(), 0);
        }
    }

    /// Minted, paired, dealt — one way, each step from the one before it and from nowhere else.
    #[test]
    fn an_escrow_moves_through_its_stages_one_way() {
        let mut s = EscrowSession { stage: EscrowStage::Minted, ..session() };
        let terms = || DealTerms::validate(Policy::Always, NOW, NOW + HOUR).unwrap();
        let record = || ReleaseRecord {
            request_id: "r".into(),
            sats: 1,
            at: NOW,
            proposal_hash: "p".into(),
            deadline: NOW + HOUR,
        };

        let err = s.strike_deal(terms()).expect_err("a deal needs a service to take it");
        assert!(err.contains("no service paired"), "unexpected: {err}");
        assert!(s.record_release("tx".into(), record()).is_err(), "nor is anything released");

        s.record_pairing(paired()).expect("minted, then paired");
        assert!(s.record_release("tx".into(), record()).is_err(), "still no deal");
        assert!(s.end_by_service("deal", NOW).is_err(), "and none to end");

        s.strike_deal(terms()).expect("paired, then dealt");
        assert!(matches!(&s.stage, EscrowStage::Dealt { releases, .. } if releases.is_empty()));
        let err = s.strike_deal(terms()).expect_err("one deal, for good");
        assert!(err.contains("already committed"), "unexpected: {err}");
        let err = s.record_pairing(paired()).expect_err("its service is part of its deal");
        assert!(err.contains("committed to a deal"), "unexpected: {err}");
        s.record_release("tx".into(), record()).expect("dealt, so it releases");
        assert_eq!(s.released_sats(), 1);
    }

    /// The seal is the only copy of every key the wallet holds, so a seal written before the stage
    /// had a field of its own must still open — as the stage its escrows had reached.
    #[test]
    fn an_older_seal_reads_as_the_stage_it_reached() {
        let mut s = session();
        release(&mut s, 7);
        let with = |fields: &[(&str, serde_json::Value)]| {
            let mut sealed = serde_json::to_value(&s).unwrap();
            let sealed_map = sealed.as_object_mut().unwrap();
            sealed_map.remove("stage");
            for (field, value) in fields {
                sealed_map.insert(field.to_string(), value.clone());
            }
            serde_json::from_value::<EscrowSession>(sealed).expect("an older seal still opens")
        };
        let pairing = serde_json::to_value(paired()).unwrap();
        let terms = serde_json::to_value(s.terms()).unwrap();
        let releases = serde_json::to_value(s.releases()).unwrap();

        assert!(matches!(with(&[]).stage, EscrowStage::Minted));
        let paired_only = with(&[("pairing", pairing.clone()), ("releases", releases.clone())]);
        assert!(matches!(paired_only.stage, EscrowStage::Paired(_)));
        assert_eq!(paired_only.released_sats(), 0, "an older ledger is not read without its deal");
        assert_eq!(with(&[("pairing", pairing), ("terms", terms), ("releases", releases)]), s);
    }

    /// The horizon is the later of the deal's deadline and every release's: ending a deal early
    /// does not let the owner race a release its service has yet to submit.
    #[test]
    fn the_horizon_waits_for_every_release_made() {
        let mut s = session();
        release(&mut s, 1_000);
        end(&mut s, NOW + 60);
        assert_eq!(deadline(&s), NOW + 60);
        assert_eq!(s.horizon(), NOW + HOUR, "the release was promised until the old deadline");
    }

    fn capped(sats: u64) -> EscrowSession {
        let policy = Policy::AllOf {
            of: vec![Policy::TotalOutMax { sats }, Policy::ReleasedTotalMax { sats }],
        };
        struck(policy)
    }

    /// A payout of one agreed price releases it all at once, and then the deal has nothing left to
    /// give, while its deadline still stands.
    #[test]
    fn a_deal_whose_allowance_is_released_is_no_longer_open() {
        let mut s = capped(23_010);
        assert!(s.is_open(NOW));
        release(&mut s, 23_000);
        assert!(!s.is_spent(), "ten sats short of the cap is not spent");
        assert!(s.is_open(NOW));
        release(&mut s, 10);
        assert!(s.is_spent());
        assert!(!s.is_open(NOW), "spent");
        assert!(s.is_active(NOW), "and its deadline is untouched");
    }

    /// A cap is only a cap on the deal where it binds unconditionally. One branch of an `any_of`
    /// may be satisfied without it, so it cannot say the deal is spent.
    #[test]
    fn only_an_unconditional_cap_can_spend_a_deal() {
        let mut uncapped = session();
        release(&mut uncapped, u64::MAX);
        assert!(!uncapped.is_spent(), "a deal with no cap runs to its deadline");

        let either = Policy::AnyOf {
            of: vec![Policy::ReleasedTotalMax { sats: 1 }, Policy::Always],
        };
        let mut s = struck(either);
        release(&mut s, 1_000);
        assert!(!s.is_spent());

        // Nested all_of chains count, and the smallest cap wins.
        let nested = Policy::AllOf {
            of: vec![
                Policy::ReleasedTotalMax { sats: 500 },
                Policy::AllOf { of: vec![Policy::ReleasedTotalMax { sats: 100 }] },
            ],
        };
        let mut s = struck(nested);
        release(&mut s, 100);
        assert!(s.is_spent());
    }

    #[test]
    fn the_terms_name_the_sealed_policy_and_its_deadline() {
        let s = capped(1_000);
        let terms = s.sealed_terms().unwrap();
        assert_eq!(terms.opened_at, NOW);
        assert_eq!(terms.deadline, NOW + HOUR);
        assert_eq!(
            terms.policy_sha256,
            crate::policy::policy_sha256(&s.terms().unwrap().policy)
        );
        assert_ne!(
            terms.policy_sha256,
            capped(1_001).sealed_terms().unwrap().policy_sha256,
            "a different policy is a different deal"
        );
    }

    /// One escrow, many releases: a card is tapped more than once. Which payments have been spent
    /// is checked across every escrow of the wallet, in `release_test.rs`.
    #[test]
    fn releases_accumulate_and_do_not_end_the_deal() {
        let mut s = session();
        release(&mut s, 1_000);
        release(&mut s, 2_500);
        assert_eq!(s.released_sats(), 3_500);
        assert!(s.may_release(NOW + 60).is_ok(), "an escrow is spent against, not spent once");
    }

    #[test]
    fn a_release_total_cannot_be_made_to_wrap() {
        let mut s = session();
        release(&mut s, u64::MAX);
        release(&mut s, u64::MAX);
        assert_eq!(s.released_sats(), u64::MAX, "saturating, so a total never wraps to nothing");
    }

    #[test]
    fn a_deal_that_is_already_over_is_refused() {
        assert!(DealTerms::validate(Policy::Always, NOW, NOW).is_err());
        assert!(DealTerms::validate(Policy::Always, NOW, NOW - 1).is_err());
    }

    #[test]
    fn a_policy_that_is_not_one_is_refused_at_the_door() {
        let empty = Policy::AllOf { of: vec![] };
        assert!(DealTerms::validate(empty, NOW, NOW + HOUR).is_err());
    }

    /// The seal is the only thing that carries a deal across a restart, so what it omits must come
    /// back as the safe answer rather than the convenient one.
    #[test]
    fn terms_missing_their_policy_release_nothing() {
        let json = format!(r#"{{"opened_at":{NOW},"deadline":{}}}"#, NOW + HOUR);
        let restored: DealTerms = serde_json::from_str(&json).expect("terms with no policy");
        assert_eq!(restored.policy, Policy::Never);
    }

    /// The record holds this cosigner's share of `V'`, a term of the owner's escrow share, and this
    /// cosigner's share of the pairing. Printing it — for a log, or in a panic — must print none of
    /// them.
    #[test]
    fn printing_an_escrow_leaves_its_secrets_out() {
        let mut s = session();
        s.key_package_json = "SECRET-SHARE".into();
        s.wallet_delta_share_hex = "SECRET-DELTA".into();
        s.pairing_mut().unwrap().key_package_json = "SECRET-PAIRING".into();
        let printed = format!("{s:?}");
        for secret in ["SECRET-SHARE", "SECRET-DELTA", "SECRET-PAIRING"] {
            assert!(!printed.contains(secret), "{secret} was printed: {printed}");
        }
        assert!(printed.contains(&"44".repeat(32)), "the service is still named: {printed}");
    }

    #[test]
    fn an_escrow_survives_a_seal_round_trip() {
        let mut s = session();
        release(&mut s, 42);
        let round_tripped: EscrowSession =
            serde_json::from_str(&serde_json::to_string(&s).unwrap()).unwrap();
        assert_eq!(round_tripped, s);
        assert_eq!(round_tripped.released_sats(), 42);
    }

    /// A delivered half is not a working pairing. The record sealed after delivery starts with
    /// neither party's word, because neither has given it yet — and a release needs both.
    #[test]
    fn a_delivered_pairing_starts_with_nobody_vouching_for_it() {
        let material = PairingMaterial {
            service_identifier_hex: "44".repeat(32),
            key_package_json: "{}".into(),
            public_key_package_json: "{}".into(),
            service_half: vec![0x77; 32],
            service_verifying_share_hex: "55".repeat(33),
        };
        let pairing = material.into_pairing("aa".repeat(16), NOW);
        assert!(!pairing.service_confirmed && !pairing.wallet_confirmed);
        assert_eq!(pairing.state(), PairingState::Pending);
        assert_eq!(pairing.attempt_id_hex, "aa".repeat(16));
        assert_eq!(pairing.paired_at, NOW);
    }

    // --- The connection and what travels on it ---------------------------------------------

    #[test]
    fn a_stream_id_is_a_usable_handle_and_distinguishes_services() {
        let a = "11".repeat(32);
        let b = "22".repeat(32);
        assert!(crate::host::valid_task_id(&service_stream_id(&a)));
        assert_ne!(service_stream_id(&a), service_stream_id(&b));
        // Case is not part of the identity: an id may be written either way.
        assert_eq!(
            service_stream_id(&a.to_uppercase()),
            service_stream_id(&a),
        );
    }

    /// The half must not reach a log by the ordinary route a struct does.
    #[test]
    fn a_pairing_half_is_redacted_in_debug() {
        let secret = "deadbeef".repeat(8);
        let message = ToService::PairingHalf {
            escrow_key: "02aa".into(),
            attempt_id: "0011".into(),
            service_identifier: "33".repeat(32),
            half: secret.clone(),
            public_key_package_json: "{}".into(),
            service_verifying_share: "02bb".into(),
        };
        let rendered = format!("{message:?}");
        assert!(!rendered.contains(&secret), "the half is in the debug output");
        assert!(rendered.contains("<redacted>"));
    }

    #[test]
    fn the_envelope_round_trips_by_its_tag() {
        let message = FromService::PairingReady {
            escrow_key: "02aa".into(),
            attempt_id: "0011".into(),
        };
        let json = serde_json::to_string(&message).unwrap();
        assert!(json.contains(r#""kind":"pairing-ready""#), "{json}");
        let back: FromService = serde_json::from_str(&json).unwrap();
        assert_eq!(back.kind(), "pairing-ready");
    }

    // --- Where a service is -------------------------------------------------------------------

    const A: &str = "11";
    fn id(byte: &str) -> String {
        byte.repeat(32)
    }

    #[test]
    fn an_unknown_service_is_refused_with_a_reason() {
        let r = ServiceRegistry::parse("");
        assert!(r.is_empty());
        let err = r.origin_of(&id(A)).expect_err("nothing is allowlisted");
        assert!(format!("{err:?}").contains("does not know that service"));
    }

    #[test]
    fn a_named_service_resolves_and_its_id_is_case_insensitive() {
        let r = ServiceRegistry::parse(&format!("{}=https://a.example", id(A).to_uppercase()));
        assert_eq!(r.origin_of(&id(A)).unwrap(), "https://a.example");
        assert_eq!(r.origin_of(&id(A).to_uppercase()).unwrap(), "https://a.example");
    }

    #[test]
    fn several_services_and_untidy_whitespace() {
        let r = ServiceRegistry::parse(&format!(
            "  {}=https://a.example , {}=https://b.example:8443/  ",
            id(A),
            id("22")
        ));
        assert_eq!(r.origin_of(&id(A)).unwrap(), "https://a.example");
        assert_eq!(r.origin_of(&id("22")).unwrap(), "https://b.example:8443");
    }

    /// The spelling an image built through `dev-enclave.sh` has to use, because its `--guest-env`
    /// validator admits neither `=` nor `,`.
    #[test]
    fn the_restricted_spelling_parses_the_same_way() {
        let r = ServiceRegistry::parse(&format!(
            "{}:http://192.168.127.254:7099_{}:https://b.example",
            id(A),
            id("22")
        ));
        assert_eq!(r.origin_of(&id(A)).unwrap(), "http://192.168.127.254:7099");
        assert_eq!(r.origin_of(&id("22")).unwrap(), "https://b.example");
    }

    /// A malformed entry is dropped, never widened into something that resolves.
    #[test]
    fn malformed_entries_are_skipped_rather_than_guessed() {
        let r = ServiceRegistry::parse(&format!(
            "not-an-id=https://a.example,{}=not-a-url,{}=https://c.example/a/path,{}",
            id(A),
            id("22"),
            id("33")
        ));
        assert!(r.is_empty(), "every entry here is wrong in a different way");
    }

    /// A path in an origin would let one entry stand for a whole host.
    #[test]
    fn an_origin_with_a_path_is_refused() {
        let r = ServiceRegistry::parse(&format!("{}=https://a.example/only/here", id(A)));
        assert!(r.is_empty());
    }
}
