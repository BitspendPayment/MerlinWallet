//! Handing a service its half of a pairing.
//!
//! # Why the cosigner sends this, and why it cannot be told where
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
//! # Two routes, one share
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
//! So the wallet is told where this enclave delivered ([`PairServiceDone::service_origin`]) and
//! sends its own half to the same place — the origin comes from the measured image either way, and
//! the wallet never chooses one.
//!
//! # Over the connection the runtime holds
//!
//! The half does not travel as a request of its own. It goes on the stream the runtime maintains
//! to this service — `stream-open` then `stream-send` — for one reason that has nothing to do with
//! pairing: the *service* has to be able to speak first later, when it asks for a release, and it
//! has no passkey for this tenant so it can never call in. A connection that only exists while the
//! wallet is here would be no use to it. So the connection is opened at pairing, outlives the call
//! that opened it, and is re-established by the runtime's supervisor whenever it drops. See
//! [`crate::service_stream`].
//!
//! One connection per *service*, not per escrow: a tenant may hold eight, and a wallet may hold
//! sixty-four escrows.
//!
//! # Deliver, then seal — but seal *pending*
//!
//! The cosigner's half is never retained, so a pairing whose delivery failed can never be
//! completed: the service would have no share and the half that would have given it one is gone.
//! Delivering first makes that harmless — nothing is sealed, and the wallet pairs again.
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
//! half; the wallet retries the same attempt, which is idempotent for the service, or pairs again
//! with a fresh one. A failure between 2 and 3 is the same picture from one step further on. What
//! is *not* possible is a pairing reported usable on one party's word: step 3 arrives over the
//! stream from the service and step 2 from the wallet, and
//! [`ServicePairing::state`](crate::types::ServicePairing::state) is `Ready` only with both. A
//! restart changes none of this — the flags are in the seal.

use std::collections::BTreeMap;

use crate::grpc::Status;

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
            if origin[8..].contains('/') {
                continue;
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

/// Open the connection to a service and hand it one pairing half.
///
/// Opening is idempotent for the same origin and an error for a different one, so a second escrow
/// with the same service reuses the connection rather than making a second.
///
/// The wait is for the runtime's supervisor to dial: `stream-open` records a standing instruction
/// and returns, and `stream-send` refuses while the connection is down rather than queueing a
/// message only the caller can know is still wanted. A service that is not answering fails the
/// pairing here, which is the right place — nothing has been sealed.
pub async fn deliver_pairing_half(
    host: &dyn crate::host::Host,
    service_id_hex: &str,
    origin: &str,
    half: &crate::service_stream::ToService,
) -> Result<String, String> {
    let stream_id = crate::service_stream::service_stream_id(service_id_hex);
    host.stream_open(&stream_id, origin)
        .map_err(|e| format!("asking the runtime to connect to {origin}: {e}"))?;

    let payload = serde_json::to_vec(half).map_err(|e| format!("encoding the half: {e}"))?;
    let mut last = String::new();
    for attempt in 0..CONNECT_ATTEMPTS {
        match host.stream_send(&stream_id, &payload) {
            Ok(()) => return Ok(stream_id),
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

#[cfg(test)]
mod tests {
    use super::*;

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
