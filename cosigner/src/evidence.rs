//! Evidence the cosigner fetches for itself, and what a policy may conclude from it.
//!
//! # The rule this exists to enforce
//!
//! A service asking to be paid out of an escrow may say **which** payment it is claiming. It may
//! not say **that** the payment happened. So a release policy names a provider, and the cosigner
//! goes and asks that provider directly:
//!
//! ```text
//!   service ──▶ "release for reference X"
//!   cosigner ──GET https://provider/…/X──▶ provider        the policy's provider, not the
//!            ◀──────── JSON evidence ─────                 service's, and not the service's JSON
//!            └── predicates from the SEALED policy decide
//! ```
//!
//! Three things follow, and each is enforced rather than assumed:
//!
//! - **The provider, the path and the predicates come from the sealed policy.** A request supplies
//!   one thing — the reference — and it is substituted into one place.
//! - **A 200 proves nothing.** Every condition must carry at least one predicate; a response that
//!   satisfies none of them is a denial, not an absence of denial.
//! - **Evidence is bound to what it is justifying.** A predicate can require the response to name
//!   the reference the release claimed and the amount it would pay, so a genuine receipt for some
//!   other payment does not authorise this one.
//!
//! # Why fetching is separate from deciding
//!
//! [`Policy::evaluate`](crate::policy::Policy::evaluate) is synchronous and pure, which is what
//! makes it cheap to test exhaustively. An HTTP GET is neither. So a policy *declares* what it
//! needs ([`Policy::evidence_needed`](crate::policy::Policy::evidence_needed)), the caller fetches
//! it, and evaluation reads what was fetched. The I/O sits where I/O belongs and the decision stays
//! a function of its inputs.
//!
//! # Credentials
//!
//! A policy names a credential by **key**, never by value: `credentials: "diva"` resolves to
//! `SERVICE_CREDENTIALS_DIVA` in the guest's environment, which is image configuration and measured
//! into PCR0 like the egress list. A sealed policy therefore cannot be edited into one that
//! exfiltrates a secret, because it never contains one.
//!
//! **A credential is presented to exactly one origin.** The provider is a policy field, the
//! reference is substituted into a path segment and nowhere else, and a response that is a redirect
//! is treated as evidence being unavailable — the request is never re-sent to wherever it points.

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};

/// What the cosigner must go and fetch before it can decide.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub struct EvidenceRequest {
    /// Scheme, host and port, from the policy. Must be an origin the image allows.
    pub provider: String,
    /// The path, with the reference already substituted.
    pub path: String,
    /// Which credential to present, by key. Resolved from the environment, never from a request.
    pub credentials: String,
}

impl EvidenceRequest {
    /// How a fetched response is looked up again at evaluation time. The credential is not part of
    /// it: what identifies evidence is what was asked, not what it was asked with.
    pub fn key(&self) -> String {
        format!("{}{}", self.provider, self.path)
    }
}

/// What came back. Never the raw body — parsed, or an honest account of why not.
#[derive(Debug, Clone, PartialEq)]
pub enum Evidence {
    /// A 2xx with a JSON body.
    Json(serde_json::Value),
    /// Reached, and unusable: a non-2xx, a redirect, a body that is not JSON. The reason is kept
    /// for the refusal message and is never itself evidence of anything.
    Unusable(String),
    /// Not reached at all.
    Unreachable(String),
}

/// What a condition concludes when its evidence is not usable.
///
/// [`Deny`](OnUnavailable::Deny) is the default and the only safe one for money: a provider that is
/// down has not told us a payment succeeded. [`Pending`](OnUnavailable::Pending) exists so a caller
/// can distinguish "no, and do not ask again" from "not yet, come back" without the policy having
/// to permit anything.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "snake_case")]
pub enum OnUnavailable {
    #[default]
    Deny,
    /// Deny, and say it is worth retrying.
    Pending,
}

/// One check against the fetched JSON.
///
/// Deliberately a closed vocabulary of typed comparisons rather than an expression language. A
/// policy is shown to a person before they agree to it ([`describe`](Predicate::describe)), and
/// something a person cannot read is not consent.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "is", rename_all = "snake_case")]
pub enum Predicate {
    /// The string at `at` equals `value`.
    Equals { at: String, value: String },
    /// The string at `at` is one of `values`.
    OneOf { at: String, values: Vec<String> },
    /// The number at `at` is at least / at most `value`. Money, so integers only — a float would
    /// make "at least" a question about rounding.
    AtLeast { at: String, value: i64 },
    AtMost { at: String, value: i64 },
    /// The value at `at` equals the reference this release claimed.
    ///
    /// **This is the binding.** Without it a real receipt for somebody else's payment satisfies
    /// everything else, and the evidence proves a payment happened rather than that *this* one did.
    MatchesReference { at: String },
    /// The number at `at` equals the sats this release would pay.
    ///
    /// The other half of the binding: evidence for the right payment, of the wrong size, is
    /// evidence for a different release.
    MatchesAmount { at: String },
    /// The fiat amount at `at`, converted at a FIXED rate, is exactly the sats this release pays.
    ///
    /// The binding for a release denominated in one currency against a payment denominated in
    /// another. Evidence that a $20 purchase cleared says nothing about how many sats are owed for
    /// it until something says what a dollar is worth, and whoever supplies that number decides how
    /// much leaves the escrow — verify a $5 coffee, release $500. So the rate is not supplied: it
    /// is written into the sealed policy, which the owner agreed to.
    ///
    /// **This is a demonstration setting, not a market quote.** A fixed rate means the escrow bears
    /// the whole of the price move between committing and clearing, which is a thing to decide
    /// deliberately rather than inherit.
    ///
    /// # Exact, or refused
    ///
    /// Money, so no floating point reaches the arithmetic. The amount is read as a decimal string
    /// and turned into whole minor units — cents — and the conversion is integer throughout. A
    /// conversion that does not come out whole is **refused rather than rounded**: rounding is
    /// where money goes missing, and a release is not the place to decide in whose favour.
    AmountAtFixedRate {
        at: String,
        /// Minor units in one whole unit of the fiat currency: 100 for dollars and cents.
        minor_units_per_unit: u32,
        /// Sats per one whole fiat unit.
        sats_per_unit: u64,
    },
}

impl Predicate {
    fn at(&self) -> &str {
        match self {
            Predicate::Equals { at, .. }
            | Predicate::OneOf { at, .. }
            | Predicate::AtLeast { at, .. }
            | Predicate::AtMost { at, .. }
            | Predicate::MatchesReference { at }
            | Predicate::MatchesAmount { at }
            | Predicate::AmountAtFixedRate { at, .. } => at,
        }
    }

    pub fn describe(&self) -> String {
        match self {
            Predicate::Equals { at, value } => format!("{at} is {value:?}"),
            Predicate::OneOf { at, values } => format!("{at} is one of {values:?}"),
            Predicate::AtLeast { at, value } => format!("{at} is at least {value}"),
            Predicate::AtMost { at, value } => format!("{at} is at most {value}"),
            Predicate::MatchesReference { at } => {
                format!("{at} is the payment this release claims")
            }
            Predicate::MatchesAmount { at } => format!("{at} is the amount this release pays"),
            Predicate::AmountAtFixedRate {
                at, sats_per_unit, ..
            } => format!(
                "{at}, at the agreed {sats_per_unit} sats per unit, is exactly what this release \
                 pays"
            ),
        }
    }

    fn validate(&self) -> Result<(), String> {
        if self.at().is_empty() {
            return Err("a predicate must say where to look".into());
        }
        if let Predicate::OneOf { values, .. } = self {
            if values.is_empty() {
                return Err("an empty one_of admits nothing; say never instead".into());
            }
        }
        if let Predicate::AmountAtFixedRate {
            minor_units_per_unit,
            sats_per_unit,
            ..
        } = self
        {
            if *minor_units_per_unit == 0 {
                return Err("a currency with no minor units cannot be converted exactly".into());
            }
            if *sats_per_unit == 0 {
                return Err("a rate of 0 sats makes every release pay nothing".into());
            }
        }
        Ok(())
    }

    /// `Ok(())` permits; `Err(reason)` denies.
    fn check(&self, body: &serde_json::Value, release: &ReleaseFacts) -> Result<(), String> {
        let at = self.at();
        let found = lookup(body, at).ok_or_else(|| format!("the evidence has no {at}"))?;
        match self {
            Predicate::Equals { value, .. } => match found.as_str() {
                Some(s) if s == value => Ok(()),
                Some(s) => Err(format!("{at} is {s:?}, not {value:?}")),
                None => Err(format!("{at} is not text")),
            },
            Predicate::OneOf { values, .. } => match found.as_str() {
                Some(s) if values.iter().any(|v| v == s) => Ok(()),
                Some(s) => Err(format!("{at} is {s:?}, which is not permitted")),
                None => Err(format!("{at} is not text")),
            },
            Predicate::AtLeast { value, .. } => match found.as_i64() {
                Some(n) if n >= *value => Ok(()),
                Some(n) => Err(format!("{at} is {n}, under {value}")),
                None => Err(format!("{at} is not a whole number")),
            },
            Predicate::AtMost { value, .. } => match found.as_i64() {
                Some(n) if n <= *value => Ok(()),
                Some(n) => Err(format!("{at} is {n}, over {value}")),
                None => Err(format!("{at} is not a whole number")),
            },
            Predicate::MatchesReference { .. } => match found.as_str() {
                Some(s) if s == release.reference => Ok(()),
                Some(s) => Err(format!(
                    "{at} is {s:?}, which is not the payment this release claims"
                )),
                None => Err(format!("{at} is not text")),
            },
            Predicate::MatchesAmount { .. } => match found.as_i64() {
                Some(n) if n == release.sats as i64 => Ok(()),
                Some(n) => Err(format!(
                    "{at} is {n}, and this release pays {}",
                    release.sats
                )),
                None => Err(format!("{at} is not a whole number")),
            },
            Predicate::AmountAtFixedRate {
                minor_units_per_unit,
                sats_per_unit,
                ..
            } => {
                let minor = minor_units(found, *minor_units_per_unit)
                    .ok_or_else(|| format!("{at} is not an amount of money"))?;
                if minor < 0 {
                    return Err(format!("{at} is negative, and a refund is not a release"));
                }
                let owed = i128::from(*sats_per_unit)
                    .checked_mul(minor)
                    .ok_or_else(|| format!("{at} converts to more sats than there are"))?;
                let per_unit = i128::from(*minor_units_per_unit);
                if owed % per_unit != 0 {
                    return Err(format!(
                        "{at} does not convert to a whole number of sats at {sats_per_unit} per \
                         unit, and a release is not the place to decide who keeps the remainder"
                    ));
                }
                let owed = owed / per_unit;
                if owed == i128::from(release.sats) {
                    Ok(())
                } else {
                    Err(format!(
                        "{at} is worth {owed} sats at the agreed rate, and this release pays {}",
                        release.sats
                    ))
                }
            }
        }
    }
}

/// A JSON amount of money, as whole minor units. `None` if it is not one.
///
/// # Why this is not `as_f64`
///
/// Because money. `0.1 + 0.2` is famously not `0.3` in binary, and an amount that arrives as a
/// float and leaves as a float can disagree with itself by a cent — which, converted, is a
/// disagreement about sats. So the value is read as **text** and parsed into integers.
///
/// A JSON number is turned into text by `serde_json`'s own formatting, which prints the shortest
/// decimal that round-trips to the same double. For any amount a payment system states — a few
/// digits, two decimal places — that string is the amount exactly as written. A string is taken as
/// written, which is what a provider that knows better than to send money as a float will send.
///
/// More decimal places than the currency has is refused rather than truncated: a payment of
/// `20.005` dollars is not a payment this can reason about, and picking a direction to round it is
/// deciding something that is not ours to decide.
fn minor_units(found: &serde_json::Value, minor_units_per_unit: u32) -> Option<i128> {
    let text = match found {
        serde_json::Value::String(s) => s.trim().to_string(),
        serde_json::Value::Number(n) => n.to_string(),
        _ => return None,
    };
    let (negative, digits) = match text.strip_prefix('-') {
        Some(rest) => (true, rest),
        None => (false, text.strip_prefix('+').unwrap_or(&text)),
    };
    let (whole, fraction) = match digits.split_once('.') {
        Some((w, f)) => (w, f),
        None => (digits, ""),
    };
    if whole.is_empty() && fraction.is_empty() {
        return None;
    }
    if !whole.bytes().all(|b| b.is_ascii_digit()) || !fraction.bytes().all(|b| b.is_ascii_digit()) {
        return None;
    }
    // How many decimal places this currency has: 100 minor units is two, 1000 is three.
    let places = (minor_units_per_unit as f64).log10().round() as u32;
    if 10u32.checked_pow(places) != Some(minor_units_per_unit) {
        return None; // not a power of ten, so "decimal places" is not a question with an answer
    }
    if fraction.len() > places as usize {
        return None; // more precision than the currency has
    }
    let whole: i128 = if whole.is_empty() { 0 } else { whole.parse().ok()? };
    let fraction: i128 = if fraction.is_empty() {
        0
    } else {
        fraction.parse::<i128>().ok()? * 10i128.pow(places - fraction.len() as u32)
    };
    let total = whole
        .checked_mul(i128::from(minor_units_per_unit))?
        .checked_add(fraction)?;
    Some(if negative { -total } else { total })
}

/// What the release being judged claims. The half of the binding that does not come from the
/// provider.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReleaseFacts {
    /// The external payment reference the service supplied. The ONE thing on a release the service
    /// gets to choose that reaches a provider — and it reaches it as a path segment of a URL the
    /// sealed policy wrote, through [`safe_reference`], never as a URL of its own.
    pub reference: String,
    /// What this release would pay out, in sats. Egress only: change back to the escrow is not a
    /// payment to anybody.
    pub sats: u64,
    /// What it would pay in fees. See [`Policy::FeeMax`](crate::policy::Policy::FeeMax) for why a
    /// number derived from service-supplied prevouts is safe to check.

    pub fee_sats: u64,
    /// What this escrow has released before now, so a running cap can be checked.
    pub already_released_sats: u64,
}

/// A condition satisfied by evidence the cosigner fetches itself.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct HttpGet {
    /// Scheme, host and port. **From the sealed policy**, and admitted by the image's egress list
    /// when fetched — a policy naming somewhere the image does not allow fetches nothing.
    pub provider: String,
    /// A path, with `{reference}` where the claimed payment's reference goes. That is the only
    /// substitution, and it is the only thing a request contributes to the URL.
    pub path: String,
    /// Which credential to present, by KEY. Resolved from `SERVICE_CREDENTIALS_<KEY>` in the
    /// guest's environment; a policy never carries a credential's value.
    pub credentials: String,
    /// What the response must satisfy. **Never empty** — a 200 alone proves nothing.
    pub expect: Vec<Predicate>,
    #[serde(default)]
    pub on_unavailable: OnUnavailable,
}

impl HttpGet {
    pub fn validate(&self) -> Result<(), String> {
        if !(self.provider.starts_with("https://") || self.provider.starts_with("http://")) {
            return Err(format!("{:?} is not an origin", self.provider));
        }
        // `get`, not a slice: `http://` is seven bytes, and a provider is owner-supplied.
        let rest = self.provider.trim_end_matches('/').get(8..).unwrap_or_default();
        if rest.is_empty() {
            return Err("a provider needs a host".into());
        }
        if rest.contains('/') {
            return Err("a provider is a scheme, a host and a port, never a path".into());
        }
        if !self.path.starts_with('/') {
            return Err("a provider path must start with '/'".into());
        }
        // One placeholder, one meaning. Anything else in braces is a policy that thinks it can
        // interpolate something this does not supply.
        let placeholders = self.path.matches('{').count();
        if placeholders != self.path.matches("{reference}").count() {
            return Err("the only path placeholder is {reference}".into());
        }
        if self.credentials.is_empty()
            || !self
                .credentials
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b == b'_')
        {
            return Err("a credential key is letters, digits and underscores".into());
        }
        if self.expect.is_empty() {
            return Err(
                "a condition with no predicates would treat any answer as proof; say what the \
                 evidence must show"
                    .into(),
            );
        }
        for predicate in &self.expect {
            predicate.validate()?;
        }
        Ok(())
    }

    /// What must be fetched to decide this, for the release in hand.
    ///
    /// `None` when the reference could not be put in a URL — which is a refusal, not an omission:
    /// see [`safe_reference`].
    pub fn request(&self, release: &ReleaseFacts) -> Option<EvidenceRequest> {
        let reference = safe_reference(&release.reference)?;
        Some(EvidenceRequest {
            provider: self.provider.trim_end_matches('/').to_string(),
            path: self.path.replace("{reference}", &reference),
            credentials: self.credentials.clone(),
        })
    }

    pub fn evaluate(
        &self,
        evidence: &BTreeMap<String, Evidence>,
        release: Option<&ReleaseFacts>,
    ) -> Result<(), String> {
        let Some(release) = release else {
            return Err(
                "this policy needs to know what release it is judging, and none was supplied"
                    .into(),
            );
        };
        let Some(request) = self.request(release) else {
            return Err(format!(
                "the payment reference {:?} is not one that can be looked up",
                release.reference
            ));
        };
        let body = match evidence.get(&request.key()) {
            Some(Evidence::Json(body)) => body,
            Some(Evidence::Unusable(why)) | Some(Evidence::Unreachable(why)) => {
                return Err(match self.on_unavailable {
                    OnUnavailable::Deny => format!("the evidence for this release is not usable: {why}"),
                    OnUnavailable::Pending => {
                        format!("the evidence for this release is not available yet: {why}")
                    }
                })
            }
            None => return Err("the evidence for this release was never fetched".into()),
        };
        for predicate in &self.expect {
            predicate.check(body, release)?;
        }
        Ok(())
    }

    pub fn describe(&self) -> String {
        let checks: Vec<String> = self.expect.iter().map(Predicate::describe).collect();
        format!(
            "only when {} says {}",
            self.provider,
            checks.join(" and ")
        )
    }
}

/// A reference that can be put in a path segment, or nothing.
///
/// **This is the URL-substitution guard.** A reference is supplied by the service, and the one
/// place it reaches is a path segment of a URL built from the policy. So it may not contain
/// anything that could end that segment, start a query, begin an authority, or walk upwards:
/// a reference like `../../elsewhere` or `x?to=` would otherwise turn the policy's provider into
/// somewhere else entirely, with the policy's credential attached.
///
/// Conservative on purpose — external payment references are opaque identifiers, and one that is
/// not is a request to be refused rather than a string to be cleverly escaped.
pub fn safe_reference(reference: &str) -> Option<String> {
    let ok = !reference.is_empty()
        && reference.len() <= 128
        && reference
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'-' | b'_' | b'.' | b':'))
        // `.` is allowed because references contain it; `..` is not, because it climbs.
        // `:` is allowed because Lightspark Grid's are `Transaction:<uuid>`. The URL is always
        // `provider + path`, and the path starts with `/`, so a colon lands inside a path segment,
        // where it cannot start a scheme or an authority.
        && !reference.contains("..");
    ok.then(|| reference.to_string())
}

/// A dotted path into a JSON object: `data.state`, `transaction.amount`.
///
/// Dots and names only. No wildcards and no array indices — a predicate that had to say "the third
/// one" would be describing a response shape too loose to be evidence.
fn lookup<'a>(body: &'a serde_json::Value, at: &str) -> Option<&'a serde_json::Value> {
    let mut cursor = body;
    for segment in at.split('.') {
        cursor = cursor.get(segment)?;
    }
    Some(cursor)
}

/// Going and asking.
///
/// A trait for the same reason [`Host`](crate::host::Host) is one: the transport
/// exists only on `wasm32`, and everything worth testing about evidence — what is asked, what a
/// redirect means, what an unusable answer does — is about the decision rather than the socket.
#[allow(async_fn_in_trait)]
pub trait FetchEvidence {
    /// Never fails: an evidence request that could not be answered is [`Evidence::Unreachable`],
    /// because "we could not ask" is a fact a policy has to be able to act on, not an error that
    /// aborts the decision.
    async fn fetch(&self, request: &EvidenceRequest) -> Evidence;
}

/// Why a credential was not handed over.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum NoCredential {
    /// The image carries nothing under that name.
    Unknown,
    /// The image carries it, but it is bound to a different origin than the one being asked.
    WrongOrigin { bound_to: String },
    /// The image carries it and did not say where it may go.
    Unbound,
}

impl NoCredential {
    pub fn message(&self, key: &str, provider: &str) -> String {
        match self {
            NoCredential::Unknown => format!("this image carries no credential named {key:?}"),
            NoCredential::WrongOrigin { bound_to } => format!(
                "the credential {key:?} belongs to {bound_to} and this policy points it at \
                 {provider}; a credential is not sent anywhere but to the provider it is for"
            ),
            NoCredential::Unbound => format!(
                "the credential {key:?} does not say which provider it is for, so there is no \
                 provider it may safely be sent to; set SERVICE_CREDENTIAL_ORIGIN_{}",
                key.to_ascii_uppercase()
            ),
        }
    }
}

/// The credential a policy named, **if** the provider it is being sent to is the one it belongs to.
///
/// `credentials: "DIVA"` resolves `SERVICE_CREDENTIALS_DIVA`, and `SERVICE_CREDENTIAL_ORIGIN_DIVA`
/// says the one origin it may be sent to. A policy carries the key and the environment carries the
/// value, so a sealed policy can never be edited into one that holds a secret — it never held one.
///
/// # Why the origin is not the policy's to choose
///
/// A policy names a provider AND a credential, and both come from the same sealed document — which
/// a wallet's owner writes. Without this binding, a policy could point the operator's provider
/// credential at any *other* origin the image allows, and the enclave would authenticate to it with
/// a secret that was never meant for it. The credential belongs to the deployment, not to the owner
/// of one wallet, so the deployment is what decides where it goes.
///
/// Fail closed: a credential the image did not bind has no safe destination and is not sent. That
/// is a deployment error, and the refusal names the variable to set.
pub fn credential(key: &str, provider: &str) -> Result<String, NoCredential> {
    let upper = key.to_ascii_uppercase();
    let secret = std::env::var(format!("SERVICE_CREDENTIALS_{upper}"))
        .ok()
        .filter(|v| !v.is_empty())
        .ok_or(NoCredential::Unknown)?;
    let bound_to = std::env::var(format!("SERVICE_CREDENTIAL_ORIGIN_{upper}"))
        .ok()
        .map(|v| v.trim().trim_end_matches('/').to_ascii_lowercase())
        .filter(|v| !v.is_empty())
        .ok_or(NoCredential::Unbound)?;
    if bound_to != provider.trim().trim_end_matches('/').to_ascii_lowercase() {
        return Err(NoCredential::WrongOrigin { bound_to });
    }
    Ok(secret)
}

/// Fetching over the guest's `wasi:http`, to a provider the image allows.
#[cfg(target_arch = "wasm32")]
pub struct HttpEvidence;

#[cfg(target_arch = "wasm32")]
impl FetchEvidence for HttpEvidence {
    async fn fetch(&self, request: &EvidenceRequest) -> Evidence {
        use wstd::http::{Body, Client, Method, Request};

        // Unusable, not Unreachable: a credential pointed at the wrong provider is a policy this
        // deployment will not honour, and no amount of retrying changes that. Both deny whatever
        // `on_unavailable` says, so the release is refused either way.
        let secret = match credential(&request.credentials, &request.provider) {
            Ok(secret) => secret,
            Err(why) => {
                return Evidence::Unusable(why.message(&request.credentials, &request.provider))
            }
        };
        // HTTP Basic, which is what the providers this is built for take. The credential goes to
        // the policy's provider and to nothing else: the URL is built from policy fields plus a
        // reference that `safe_reference` has already confined to one path segment.
        let authorization = {
            // `bitcoin` re-exports base64; the cosigner already depends on it, and one fewer
            // direct dependency is one fewer thing in the measured image.
            use bitcoin::base64::Engine;
            format!(
                "Basic {}",
                bitcoin::base64::engine::general_purpose::STANDARD.encode(secret.as_bytes())
            )
        };

        let built = Request::builder()
            .method(Method::GET)
            .uri(format!("{}{}", request.provider, request.path))
            .header("accept", "application/json")
            .header("authorization", authorization)
            .body(Body::empty());
        let built = match built {
            Ok(r) => r,
            Err(e) => return Evidence::Unreachable(format!("building the request: {e}")),
        };

        // Short, and deliberately so. This runs inside one `on-message` invocation, which the
        // runtime bounds at its request timeout — thirty seconds by default — and a release spends
        // that on two outbound calls, this one and the ASP's. A provider slower than this fails the
        // release rather than hanging until the runtime kills the call with nothing to say, and
        // what a failure MEANS is then the policy's `on_unavailable` to decide.
        let mut client = Client::new();
        client.set_connect_timeout(core::time::Duration::from_secs(5));
        client.set_first_byte_timeout(core::time::Duration::from_secs(10));
        let mut response = match client.send(built).await {
            Ok(r) => r,
            Err(e) => return Evidence::Unreachable(format!("asking {}: {e}", request.provider)),
        };

        let status = response.status();
        // A redirect is NOT followed. Following one would send this credential to wherever the
        // response pointed, which is the one thing a provider must not be able to talk us into.
        if status.is_redirection() {
            return Evidence::Unusable(format!(
                "{} answered {status} — a redirect is not evidence, and is not followed",
                request.provider
            ));
        }
        if !status.is_success() {
            return Evidence::Unusable(format!("{} answered {status}", request.provider));
        }

        let text = match response.body_mut().str_contents().await {
            Ok(t) => t.to_string(),
            Err(e) => return Evidence::Unusable(format!("reading the answer: {e}")),
        };
        match serde_json::from_str(&text) {
            Ok(json) => Evidence::Json(json),
            Err(e) => Evidence::Unusable(format!("the answer was not JSON: {e}")),
        }
    }
}

/// A fetcher with nowhere to fetch from. Mirrors [`NoAsp`](crate::asp::NoAsp).
///
/// Not gated off the component target, although [`HttpEvidence`] is: the release path takes a
/// fetcher whichever build it is in, and a guest whose image allowlists no provider is in exactly
/// the position this describes. Unreachable evidence is then judged by the policy's
/// [`OnUnavailable`], which is the point — a provider that cannot be reached must not read as one
/// that answered.
pub struct NoEvidence;

impl FetchEvidence for NoEvidence {
    async fn fetch(&self, _request: &EvidenceRequest) -> Evidence {
        Evidence::Unreachable("this build has no way to reach a provider".into())
    }
}

/// Gather everything a policy needs, in one place, so a caller cannot forget one.
pub async fn gather<F: FetchEvidence>(
    fetcher: &F,
    requests: &[EvidenceRequest],
) -> BTreeMap<String, Evidence> {
    let mut out = BTreeMap::new();
    for request in requests {
        out.insert(request.key(), fetcher.fetch(request).await);
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn condition() -> HttpGet {
        HttpGet {
            provider: "https://diva.example".into(),
            path: "/v1/transactions/{reference}".into(),
            credentials: "DIVA".into(),
            expect: vec![
                Predicate::Equals {
                    at: "state".into(),
                    value: "COMPLETION".into(),
                },
                Predicate::MatchesReference { at: "token".into() },
                Predicate::MatchesAmount { at: "amount_sats".into() },
            ],
            on_unavailable: OnUnavailable::Deny,
        }
    }

    fn release() -> ReleaseFacts {
        ReleaseFacts {
            reference: "tx_abc123".into(),
            sats: 50_000,
            fee_sats: 0,
            already_released_sats: 0,
        }
    }

    fn fetched(body: serde_json::Value) -> BTreeMap<String, Evidence> {
        let request = condition().request(&release()).unwrap();
        BTreeMap::from([(request.key(), Evidence::Json(body))])
    }

    #[test]
    fn evidence_that_satisfies_every_predicate_permits() {
        let body = json!({"state": "COMPLETION", "token": "tx_abc123", "amount_sats": 50_000});
        assert_eq!(condition().evaluate(&fetched(body), Some(&release())), Ok(()));
    }

    /// THE BINDING. A real receipt, for a real completed payment, that is not this one.
    #[test]
    fn evidence_for_another_payment_does_not_authorise_this_release() {
        let body = json!({"state": "COMPLETION", "token": "tx_somebody_else", "amount_sats": 50_000});
        let err = condition()
            .evaluate(&fetched(body), Some(&release()))
            .unwrap_err();
        assert!(err.contains("not the payment this release claims"), "{err}");
    }

    /// The other half: the right payment, the wrong size.
    #[test]
    fn evidence_of_a_smaller_payment_does_not_authorise_a_larger_release() {
        let body = json!({"state": "COMPLETION", "token": "tx_abc123", "amount_sats": 500});
        let err = condition()
            .evaluate(&fetched(body), Some(&release()))
            .unwrap_err();
        assert!(err.contains("this release pays 50000"), "{err}");
    }

    #[test]
    fn a_payment_that_has_not_completed_does_not_authorise_anything() {
        let body = json!({"state": "PENDING", "token": "tx_abc123", "amount_sats": 50_000});
        let err = condition()
            .evaluate(&fetched(body), Some(&release()))
            .unwrap_err();
        assert!(err.contains("not \"COMPLETION\""), "{err}");
    }

    /// A 200 with a body that says nothing the policy asked about proves nothing.
    #[test]
    fn a_response_missing_what_the_policy_checks_is_a_denial() {
        let err = condition()
            .evaluate(&fetched(json!({"ok": true})), Some(&release()))
            .unwrap_err();
        assert!(err.contains("has no state"), "{err}");
    }

    #[test]
    fn unusable_and_unreachable_evidence_both_deny() {
        for evidence in [
            Evidence::Unusable("302 to elsewhere".into()),
            Evidence::Unreachable("connection refused".into()),
        ] {
            let request = condition().request(&release()).unwrap();
            let map = BTreeMap::from([(request.key(), evidence)]);
            assert!(condition().evaluate(&map, Some(&release())).is_err());
        }
    }

    /// `pending` still denies — it only changes what the owner is told.
    #[test]
    fn pending_denies_and_says_it_is_worth_coming_back() {
        let mut c = condition();
        c.on_unavailable = OnUnavailable::Pending;
        let request = c.request(&release()).unwrap();
        let map = BTreeMap::from([(request.key(), Evidence::Unreachable("timeout".into()))]);
        let err = c.evaluate(&map, Some(&release())).unwrap_err();
        assert!(err.contains("not available yet"), "{err}");
    }

    #[test]
    fn evidence_that_was_never_fetched_denies_rather_than_passing() {
        let err = condition()
            .evaluate(&BTreeMap::new(), Some(&release()))
            .unwrap_err();
        assert!(err.contains("never fetched"), "{err}");
    }

    // --- The URL-substitution guard -------------------------------------------------------------

    /// The service supplies the reference, so the reference is the attack surface.
    #[test]
    fn a_reference_that_could_rewrite_the_url_is_refused() {
        for bad in [
            "../../../v1/somewhere",
            "x/../..",
            "abc?to=evil.example",
            "abc#frag",
            "abc/def",
            "//evil.example",
            // A colon is allowed, so a scheme-looking reference must still be stopped by its `/`.
            "https://evil.example",
            "abc\\def",
            "",
            &"x".repeat(129),
        ] {
            assert!(
                safe_reference(bad).is_none(),
                "{bad:?} must not reach a URL"
            );
        }
    }

    /// Lightspark Grid names a payment `Transaction:<uuid>`. The colon stays inside the path.
    #[test]
    fn a_grid_transaction_id_is_accepted_and_stays_in_the_path() {
        let id = "Transaction:019542f5-b3e7-1d02-0000-000000000004";
        let facts = ReleaseFacts {
            reference: id.into(),
            ..release()
        };
        let request = condition().request(&facts).unwrap();
        assert_eq!(request.provider, "https://diva.example");
        assert_eq!(request.path, format!("/v1/transactions/{id}"));
    }

    #[test]
    fn an_ordinary_reference_is_accepted_and_substituted_once() {
        let request = condition().request(&release()).unwrap();
        assert_eq!(request.provider, "https://diva.example");
        assert_eq!(request.path, "/v1/transactions/tx_abc123");
        assert_eq!(request.credentials, "DIVA");
    }

    #[test]
    fn a_release_whose_reference_cannot_be_looked_up_is_denied() {
        let bad = ReleaseFacts {
            reference: "../escape".into(),
            sats: 1,
            fee_sats: 0,
            already_released_sats: 0,
        };
        assert!(condition().request(&bad).is_none());
        let err = condition().evaluate(&BTreeMap::new(), Some(&bad)).unwrap_err();
        assert!(err.contains("not one that can be looked up"), "{err}");
    }

    // --- What a policy may be ------------------------------------------------------------------

    #[test]
    fn a_condition_with_no_predicates_is_refused_at_the_door() {
        let mut c = condition();
        c.expect.clear();
        let err = c.validate().unwrap_err();
        assert!(err.contains("any answer as proof"), "{err}");
    }

    #[test]
    fn a_provider_that_is_not_an_origin_is_refused() {
        for provider in [
            "diva.example",
            "https://diva.example/v1",
            "ftp://diva.example",
        ] {
            let mut c = condition();
            c.provider = provider.into();
            assert!(c.validate().is_err(), "{provider:?} should not be a provider");
        }
    }

    #[test]
    fn a_path_that_interpolates_something_else_is_refused() {
        let mut c = condition();
        c.path = "/v1/{account}/{reference}".into();
        let err = c.validate().unwrap_err();
        assert!(err.contains("only path placeholder"), "{err}");
    }

    #[test]
    fn a_credential_is_named_never_carried() {
        let mut c = condition();
        c.credentials = "not a key!".into();
        assert!(c.validate().is_err());
        // And a valid policy, serialized, contains no secret — only the key.
        let json = serde_json::to_string(&condition()).unwrap();
        assert!(json.contains("DIVA"));
        assert!(!json.to_lowercase().contains("token\":\"ey"), "no credential value");
    }

    #[test]
    fn a_policy_reads_as_a_sentence_somebody_could_agree_to() {
        let described = condition().describe();
        assert!(described.contains("https://diva.example"), "{described}");
        assert!(described.contains("is the payment this release claims"), "{described}");
    }

    #[test]
    fn a_dotted_path_reaches_into_nested_objects_and_nothing_else() {
        let body = json!({"data": {"state": "OK"}, "list": [1, 2]});
        assert_eq!(lookup(&body, "data.state").unwrap(), "OK");
        assert!(lookup(&body, "data.missing").is_none());
        assert!(lookup(&body, "list.0").is_none(), "no array indexing");
    }
    /// The credential belongs to the deployment, not to whoever wrote the policy — so the policy
    /// does not get to choose where it goes.
    ///
    /// These set process environment, so they run in one test to keep it deterministic.
    #[test]
    fn a_credential_goes_to_its_own_provider_and_nowhere_else() {
        // SAFETY: one test owns these variables, and reads them back within the same call.
        unsafe {
            std::env::set_var("SERVICE_CREDENTIALS_DIVATEST", "user:pass");
            std::env::set_var("SERVICE_CREDENTIAL_ORIGIN_DIVATEST", "https://diva.example");
        }

        assert_eq!(
            credential("DIVATEST", "https://diva.example").unwrap(),
            "user:pass"
        );
        // Spelling of the origin is not what decides it.
        assert_eq!(
            credential("divatest", "https://DIVA.example/").unwrap(),
            "user:pass"
        );

        // The whole point: another origin this image allows must not receive it.
        let err = credential("DIVATEST", "https://a-partner.example").unwrap_err();
        assert_eq!(
            err,
            NoCredential::WrongOrigin {
                bound_to: "https://diva.example".into()
            }
        );
        let message = err.message("DIVATEST", "https://a-partner.example");
        assert!(message.contains("belongs to https://diva.example"), "{message}");
        assert!(!message.contains("user:pass"), "a refusal must not quote the secret");

        // A credential with no stated destination has no safe destination.
        unsafe {
            std::env::remove_var("SERVICE_CREDENTIAL_ORIGIN_DIVATEST");
        }
        assert_eq!(
            credential("DIVATEST", "https://diva.example").unwrap_err(),
            NoCredential::Unbound
        );

        unsafe {
            std::env::remove_var("SERVICE_CREDENTIALS_DIVATEST");
        }
        assert_eq!(
            credential("DIVATEST", "https://diva.example").unwrap_err(),
            NoCredential::Unknown
        );
    }

    /// Money is read as text and converted with integers. A float on this path can disagree with
    /// itself by a cent, and a cent, converted, is a disagreement about sats.
    #[test]
    fn an_amount_becomes_whole_minor_units_or_nothing() {
        use serde_json::json;
        let cents = |v: serde_json::Value| minor_units(&v, 100);

        assert_eq!(cents(json!(20.00)), Some(2_000));
        assert_eq!(cents(json!("20.00")), Some(2_000));
        assert_eq!(cents(json!(19.99)), Some(1_999));
        assert_eq!(cents(json!("0.07")), Some(7));
        assert_eq!(cents(json!(20)), Some(2_000));
        assert_eq!(cents(json!("20.5")), Some(2_050), "one place is two places' worth");
        assert_eq!(cents(json!("-5.00")), Some(-500));

        // The classic one: a value no double holds exactly still reads as the cents it was written
        // as, because the text is what is parsed.
        assert_eq!(cents(json!(0.1)), Some(10));
        assert_eq!(cents(json!(0.3)), Some(30));

        // More precision than dollars have. Truncating would decide something that is not ours.
        assert_eq!(cents(json!("20.005")), None);
        assert_eq!(cents(json!("not money")), None);
        assert_eq!(cents(json!(true)), None);
        assert_eq!(cents(json!("")), None);
    }

    fn at_rate(sats_per_unit: u64) -> Predicate {
        Predicate::AmountAtFixedRate {
            at: "amount".into(),
            minor_units_per_unit: 100,
            sats_per_unit,
        }
    }

    fn paying(sats: u64) -> ReleaseFacts {
        ReleaseFacts {
            reference: "tx_1".into(),
            sats,
            fee_sats: 0,
            already_released_sats: 0,
        }
    }

    /// The scenario the example demonstrates: $20.00 at 1,000 sats per dollar is 20,000 sats.
    #[test]
    fn a_purchase_converts_at_the_agreed_rate_and_must_match_exactly() {
        use serde_json::json;
        let p = at_rate(1_000);
        assert!(p.check(&json!({"amount": 20.00}), &paying(20_000)).is_ok());
        assert!(p.check(&json!({"amount": "20.00"}), &paying(20_000)).is_ok());

        // A release for more than the purchase was worth. This is the whole point of the term:
        // without it, "a $20 purchase cleared" says nothing about how many sats are owed.
        let err = p.check(&json!({"amount": 20.00}), &paying(500_000)).unwrap_err();
        assert!(err.contains("worth 20000 sats"), "{err}");
        assert!(err.contains("pays 500000"), "{err}");

        // And a purchase for more than the release, which is the service short-changing itself.
        assert!(p.check(&json!({"amount": 25.00}), &paying(20_000)).is_err());
    }

    /// A conversion that does not come out whole is refused, not rounded. Rounding is where money
    /// goes missing, and a release is not the place to decide in whose favour.
    #[test]
    fn an_inexact_conversion_is_refused_rather_than_rounded() {
        use serde_json::json;
        // 3 sats per dollar: one cent is 3/100 of a sat.
        let p = at_rate(3);
        let err = p.check(&json!({"amount": "0.01"}), &paying(0)).unwrap_err();
        assert!(err.contains("whole number of sats"), "{err}");
        // A dollar exactly does divide, and is allowed.
        assert!(p.check(&json!({"amount": "1.00"}), &paying(3)).is_ok());
    }

    #[test]
    fn a_refund_is_not_a_release_and_a_rate_of_zero_is_not_a_rate() {
        use serde_json::json;
        let err = at_rate(1_000)
            .check(&json!({"amount": "-20.00"}), &paying(20_000))
            .unwrap_err();
        assert!(err.contains("negative"), "{err}");

        assert!(at_rate(0).validate().is_err());
        assert!(Predicate::AmountAtFixedRate {
            at: "amount".into(),
            minor_units_per_unit: 0,
            sats_per_unit: 1_000,
        }
        .validate()
        .is_err());
        assert!(at_rate(1_000).validate().is_ok());
    }

    /// A currency whose minor unit is not a power of ten has no "decimal places" to speak of, so
    /// there is no exact reading and none is guessed.
    #[test]
    fn a_currency_that_is_not_decimal_is_refused() {
        use serde_json::json;
        assert_eq!(minor_units(&json!("1.00"), 60), None);
    }

}
