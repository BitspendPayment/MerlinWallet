//! The connection to an escrow service, and what travels on it.
//!
//! # Why the runtime holds it
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
//! # What reconnects, and what activates it
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
//!   deadline an inbound request does, NOT `--background-timeout` — it is a call with a counterparty
//!   waiting, not work scheduled for later.
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
//! # How long a connection lives
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
//! # One stream per service, not per escrow
//!
//! A tenant may hold eight connections and a wallet may hold sixty-four escrows, so a stream per
//! escrow would run out. A stream per *service* does not: the image names the services it will
//! talk to, and that list is what bounds this. Every message therefore names the escrow it is
//! about, and the escrow's pairing must resolve back to the stream it arrived on.
//!
//! # What authenticates the far side
//!
//! Nothing in the message. The connection was opened to an origin **this image names**, resolved
//! from a service identifier through [`ServiceRegistry`](crate::handlers::delivery::ServiceRegistry)
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
//! # Secrets and logs
//!
//! [`ToService::PairingHalf`] carries a scalar that, added to the wallet's half, IS the service's
//! signing share. It is never logged: the [`fmt::Debug`] impl below redacts it, and the dispatch
//! logs message kinds rather than bodies.

use std::fmt;

use serde::{Deserialize, Serialize};

use crate::cosigner::Cosigner;

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
    ReleaseSigned(Box<crate::handlers::release::ReleaseApproval>),
    /// A release the cosigner will not sign, and why. A conclusion, not a fault — the request is
    /// not redelivered.
    ReleaseRefused {
        request_id: String,
        reason: String,
        /// The deal the escrow is committed to — its deadline and which policy was sealed — told
        /// only to the escrow's own service, and only when there is a deal. What lets a service
        /// that asks before paying know it will be repaid, and until when, without taking the
        /// owner's app at its word. See [`SealedTerms`](crate::escrow_session::SealedTerms).
        #[serde(default, skip_serializing_if = "Option::is_none")]
        deal: Option<crate::escrow::SealedTerms>,
    },
}

/// The secret half is redacted. A pairing that ends up in a log is a pairing given away.
impl fmt::Debug for ToService {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
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
    /// Pay a service out of an escrow. See [`crate::handlers::release`].
    ReleaseRequest(Box<crate::handlers::release::ReleaseRequest>),
    /// The service is done with this deal and will ask for nothing more from it — a payout that
    /// failed, say. The deal protects the service, so the service may end it; the owner may not.
    /// `policy_sha256` names the deal, so a late end cannot close the next one.
    EndDeal {
        escrow_key: String,
        policy_sha256: String,
    },
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

impl Cosigner {
    /// One message from a service, with no ASP to build a release against and no way to fetch
    /// evidence. The shape the host build and the tests get, mirroring
    /// [`run_task`](Cosigner::run_task).
    pub fn on_service_message(
        &mut self,
        stream_id: &str,
        message_id: &str,
        payload: &[u8],
    ) -> Result<Vec<u8>, String> {
        crate::handlers::helpers::block_on_ready(self.on_service_message_with(
            stream_id,
            message_id,
            payload,
            None::<crate::asp::NoAsp>,
            &crate::evidence::NoEvidence,
        ))
    }

    /// One message from a service, as one invocation.
    ///
    /// `message_id` repeats if the runtime delivers the same message again — after a reconnect, or
    /// because the far side resent it. Nothing here needs it: every handler is idempotent, and a
    /// release is deduplicated on its own durable record rather than on a transport id that only
    /// holds within one connection. It is taken so the signature matches `on-message` and so a
    /// future kind that *does* need it has it.
    ///
    /// An `Err` sends the service **nothing at all** — the runtime logs it and moves on — so the
    /// far side learns only that its message went unanswered and asks again. That is right for a
    /// fault and wrong for a decision, so anything concluded comes back as `Ok` carrying a
    /// [`ToService::Refused`], and only a fault a retry might genuinely fix is an error.
    pub async fn on_service_message_with<A: crate::asp::AspApi, F: crate::evidence::FetchEvidence>(
        &mut self,
        stream_id: &str,
        _message_id: &str,
        payload: &[u8],
        asp: Option<A>,
        fetcher: &F,
    ) -> Result<Vec<u8>, String> {
        let message: FromService = match serde_json::from_slice(payload) {
            Ok(m) => m,
            Err(e) => {
                return encode(&ToService::Refused {
                    about: String::new(),
                    reason: StreamRefusal::Undecodable(e.to_string()).message(),
                })
            }
        };
        let about = message.about();
        // Kinds, never bodies: a pairing half in a log is a pairing given away, and the same rule
        // applies to everything that travels beside one.
        tracing::debug!(stream = %stream_id, kind = message.kind(), "a service said something");

        match self.act_on(stream_id, message, asp, fetcher).await {
            Ok(reply) => encode(&reply),
            // The one case that must NOT be answered: the runtime redelivers what a guest failed
            // on, which is exactly what a fault wants and exactly what a decision must not have.
            Err(StreamRefusal::Faulted(e)) => Err(e),
            Err(refusal) => encode(&ToService::Refused {
                about,
                reason: refusal.message(),
            }),
        }
    }

    async fn act_on<A: crate::asp::AspApi, F: crate::evidence::FetchEvidence>(
        &mut self,
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
                self.speaks_for(stream_id, &escrow_key, &attempt_id)?;
                self.escrow_mut(&escrow_key)
                    .and_then(|e| e.confirm_by_service(&attempt_id))
                    .map_err(|_| StreamRefusal::StaleAttempt)?;
                self.seal();
                Ok(ToService::Ack { about: attempt_id })
            }
            FromService::PairingRefused {
                escrow_key,
                attempt_id,
                reason,
            } => {
                self.speaks_for(stream_id, &escrow_key, &attempt_id)?;
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
            FromService::ReleaseRequest(request) => self
                .release(stream_id, &request, asp, fetcher)
                .await
                .map_err(StreamRefusal::Faulted),
            FromService::EndDeal {
                escrow_key,
                policy_sha256,
            } => {
                self.speaks_for(stream_id, &escrow_key, "")?;
                let now = crate::handlers::helpers::now_secs();
                let ended = self
                    .escrow_mut(&escrow_key)
                    .and_then(|e| e.end_by_service(&policy_sha256, now));
                if let Err(reason) = ended {
                    return Ok(ToService::Refused {
                        about: policy_sha256,
                        reason,
                    });
                }
                // Sealed before it is acknowledged: a service told the deal is over, when the seal
                // still says otherwise, would be wrong on the next invocation. A seal that fails is
                // a fault, so the runtime redelivers and this runs again.
                self.try_seal().map_err(StreamRefusal::Faulted)?;
                Ok(ToService::Ack {
                    about: policy_sha256,
                })
            }
        }
    }

    /// May the party on `stream_id` speak for this escrow's pairing?
    ///
    /// The whole of the authentication, and it is a lookup rather than a check of anything in the
    /// message: the escrow's pairing names a service, that service resolves to a stream id, and a
    /// message cannot arrive on a stream other than the one the runtime holds to that service's
    /// origin. See the module note.
    pub(crate) fn speaks_for(
        &self,
        stream_id: &str,
        escrow_key: &str,
        attempt_id: &str,
    ) -> Result<(), StreamRefusal> {
        let pairing = self
            .escrow(escrow_key)
            .and_then(|e| e.pairing.as_ref())
            .ok_or(StreamRefusal::UnknownEscrow)?;
        if service_stream_id(&pairing.service_identifier_hex) != stream_id {
            return Err(StreamRefusal::NotYourEscrow);
        }
        if !attempt_id.is_empty() && pairing.attempt_id_hex != attempt_id {
            return Err(StreamRefusal::StaleAttempt);
        }
        Ok(())
    }
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

    /// What a reply refers to, so a service can match an answer to what it asked.
    pub fn about(&self) -> String {
        match self {
            FromService::PairingReady { attempt_id, .. }
            | FromService::PairingRefused { attempt_id, .. } => attempt_id.clone(),
            FromService::ReleaseRequest(r) => r.request_id.clone(),
            FromService::EndDeal { policy_sha256, .. } => policy_sha256.clone(),
        }
    }
}

fn encode(message: &ToService) -> Result<Vec<u8>, String> {
    serde_json::to_vec(message).map_err(|e| format!("encoding a reply: {e}"))
}

/// A service to pair into an escrow: who it is, and where the image says it is.
pub(crate) struct Service {
    pub(crate) id: threshold::identifier::Identifier,
    pub(crate) origin: String,
}

impl Service {
    /// The service [identifier] names, checked before anything is dealt.
    pub(crate) fn named(identifier: &[u8]) -> Result<Self, crate::grpc::Status> {
        // Where this service is, according to the IMAGE. Resolved before anything is dealt, so
        // naming a service this enclave does not know costs nothing and reveals nothing.
        let origin = crate::handlers::delivery::ServiceRegistry::from_env()
            .origin_of(&hex::encode(identifier))?
            .to_string();
        let id = threshold::identifier::Identifier::try_from(identifier).map_err(|e| {
            crate::grpc::Status::invalid_argument(format!("bad service identifier: {e}"))
        })?;
        Ok(Self { id, origin })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

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
}

