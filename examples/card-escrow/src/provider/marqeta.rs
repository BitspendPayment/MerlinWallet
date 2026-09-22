//! Talking to a real Marqeta sandbox instead of the mock.
//!
//! # What is verified, and what is not
//!
//! Checked against the published documentation on 2026-09-20:
//!
//! - **Authentication is HTTP Basic** with API key credentials. "All operations require HTTP Basic
//!   Authentication using API key credentials."
//!   ([self-service-credentials](https://www.marqeta.com/docs/core-api/self-service-credentials))
//! - **There is a read-only role, and it is called `read`.** The roles are `read`, `write`, `pci`
//!   and `program-manager`. A token can only be created with roles the creating token already has,
//!   so a `read` token is provisioned by something that already holds `read`.
//! - **Admin access tokens are created** with
//!   `POST /credentials/apikeys/applications/self/accesstokens`, at most 20 per application,
//!   expiring in 1–365 days and defaulting to 90.
//! - **The secret is shown once**, in `secret_value`, at creation. There is no way to read it back,
//!   so a rotation is a redeploy of the image that carries it.
//! - **Limited release.** The self-service credential API "is currently in limited release,
//!   requiring authorization from a Marqeta representative for access." A programme without that
//!   authorization provisions credentials some other way, and this example cannot tell you which.
//!
//! **Not verified, and deliberately not guessed at:** the transaction object's field names, its
//! `type` and `state` enum values, and how a clearing refers to the authorization it settles. Both
//! documentation pages truncate before the schema. Inventing plausible names would be worse than
//! leaving a gap: a predicate pointed at a field that does not exist fails closed, but one pointed
//! at the *wrong* field can pass on the wrong thing. See [`FIELD_PATHS_UNVERIFIED`].
//!
//! # Why the adapter is so small
//!
//! The cosigner needs no Marqeta knowledge at all. Every field it looks at comes from the sealed
//! policy — `Predicate { at: "state", .. }` is a JSON path written into the deal, not a constant in
//! code — so pointing it at a real provider is *a different policy*, not a different code path.
//! What an adapter must supply is an origin, a credential name and a path template, and those are
//! configuration.
//!
//! What is left here is the half the cosigner must NOT have: making test payments, and finding the
//! clearing that settles an authorization. Both need credentials it is never given.
//!
//! # The credential split, which is the point
//!
//! ```text
//!   cosigner       SERVICE_CREDENTIALS_MARQETA         role: read
//!                  SERVICE_CREDENTIAL_ORIGIN_MARQETA   bound to the sandbox origin
//!                  └── can GET a transaction. Cannot create one, cannot move money.
//!
//!   this service   MARQETA_WRITE_KEY                   role: write
//!                  └── simulates purchases in the sandbox. NEVER reaches the enclave.
//! ```
//!
//! A cosigner holding a write credential could manufacture the evidence it then verifies, which
//! would make the verification theatre. That is why the roles are split, and why the read
//! credential is bound to one origin — see `cosigner::evidence::credential`.

use serde::Deserialize;

/// The field paths a Marqeta-backed policy would use — **unconfirmed**.
///
/// These are what would go in `Predicate.at`. They live here as one place to correct rather than
/// scattered through a policy builder, and they are not used by default: [`terms`] refuses to build
/// a policy until an operator has confirmed them against the live API.
///
/// Confirm each against the transaction object in the Core API reference before use:
///
/// | what the deal asks | path here | also confirm |
/// |---|---|---|
/// | payment identity | `token` | the field a single transaction is fetched by |
/// | purchase type | `type` | the enum value meaning "a clearing" |
/// | clearing state | `state` | the enum value meaning "completed" |
/// | card | `card_token` | |
/// | currency | `currency_code` | |
/// | amount | `amount` | whether it is a decimal or minor units |
pub const FIELD_PATHS_UNVERIFIED: &[(&str, &str)] = &[
    ("payment identity", "token"),
    ("purchase type", "type"),
    ("clearing state", "state"),
    ("card", "card_token"),
    ("currency", "currency_code"),
    ("amount", "amount"),
];

/// The single-transaction endpoint, as a path template for the sealed policy.
///
/// **Unconfirmed.** The documentation names the `/transactions` resource but truncates before the
/// per-token path.
pub const TRANSACTION_PATH_UNVERIFIED: &str = "/v3/transactions/{reference}";

/// An operator's statement that [`FIELD_PATHS_UNVERIFIED`] has been checked.
///
/// A type rather than a `bool` argument, so that saying yes is deliberate and greppable.
pub struct FieldPathsConfirmed(bool);

impl FieldPathsConfirmed {
    /// Only after reading the transaction object reference and checking every row of the table.
    pub fn yes() -> Self {
        Self(true)
    }
    pub fn not_yet() -> Self {
        Self(false)
    }
}

/// Marqeta terms, once an operator says the paths have been checked.
///
/// Refusing until then is not ceremony: a policy is sealed and then trusted for the life of a deal,
/// and one built on guessed field names would verify something other than what it claims to — and
/// would do so silently.
pub fn terms(
    origin: String,
    service_ark_address: String,
    confirmed: FieldPathsConfirmed,
) -> Result<crate::policy::Terms, String> {
    if !confirmed.0 {
        return Err(format!(
            "the Marqeta transaction field paths have not been checked against the live API. \
             Confirm these {} paths, then pass `FieldPathsConfirmed::yes()`: {}",
            FIELD_PATHS_UNVERIFIED.len(),
            FIELD_PATHS_UNVERIFIED
                .iter()
                .map(|(what, at)| format!("{what} => {at}"))
                .collect::<Vec<_>>()
                .join(", ")
        ));
    }
    Ok(crate::policy::Terms {
        provider_origin: origin,
        credential_key: "MARQETA".into(),
        // The origin is not the whole of a provider. Changing it without the path would send a real
        // credential to a path only the mock serves, and every fetch would 404 for a payment that
        // exists.
        provider_path: TRANSACTION_PATH_UNVERIFIED.into(),
        ..crate::policy::Terms::example(service_ark_address, String::new())
    })
}

/// The service's own Marqeta client: the half that needs credentials the cosigner never gets.
///
/// Holds a **write**-role key, and exists only to make test payments in a sandbox and to look up
/// what settled what. Nothing in this struct is reachable from the enclave.
pub struct SandboxDriver {
    base: String,
    /// `application_token:admin_access_token`, for HTTP Basic. Never logged — see `Debug`.
    basic: String,
    http: reqwest::Client,
}

impl std::fmt::Debug for SandboxDriver {
    /// Redacted. A sandbox key is still a key.
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SandboxDriver")
            .field("base", &self.base)
            .field("basic", &"<redacted>")
            .finish()
    }
}

/// What the sandbox said, kept opaque: this example does not claim to know the schema.
#[derive(Debug, Clone, Deserialize)]
pub struct RawTransaction(pub serde_json::Value);

impl SandboxDriver {
    /// From `MARQETA_BASE`, `MARQETA_APPLICATION_TOKEN` and `MARQETA_WRITE_KEY`.
    ///
    /// `None` when any is unset, which is the ordinary case: the example runs against the mock.
    pub fn from_env() -> Option<Self> {
        let base = std::env::var("MARQETA_BASE").ok().filter(|v| !v.is_empty())?;
        let application = std::env::var("MARQETA_APPLICATION_TOKEN")
            .ok()
            .filter(|v| !v.is_empty())?;
        let key = std::env::var("MARQETA_WRITE_KEY").ok().filter(|v| !v.is_empty())?;
        use base64::Engine;
        Some(Self {
            base: base.trim_end_matches('/').to_string(),
            basic: base64::engine::general_purpose::STANDARD
                .encode(format!("{application}:{key}")),
            http: reqwest::Client::new(),
        })
    }

    /// Fetch one transaction, as the service sees it.
    ///
    /// The service reads the sandbox too, to know when a clearing exists and is worth asking about.
    /// That is not a shortcut around verification: the cosigner fetches the same record for itself,
    /// with its own read-only credential, and believes nothing this service says about it.
    ///
    /// `Ok(None)` is a 404 — **delayed availability**, not "did not happen". A transaction is
    /// authoritative before it is queryable, so the service waits and asks again rather than
    /// concluding anything.
    pub async fn transaction(&self, token: &str) -> Result<Option<RawTransaction>, String> {
        let url = format!(
            "{}{}",
            self.base,
            TRANSACTION_PATH_UNVERIFIED.replace("{reference}", token)
        );
        let response = self
            .http
            .get(&url)
            .header("authorization", format!("Basic {}", self.basic))
            .send()
            .await
            .map_err(|e| format!("asking the sandbox: {e}"))?;
        if response.status() == reqwest::StatusCode::NOT_FOUND {
            return Ok(None);
        }
        if !response.status().is_success() {
            return Err(format!("the sandbox answered {}", response.status()));
        }
        response
            .json::<serde_json::Value>()
            .await
            .map(|v| Some(RawTransaction(v)))
            .map_err(|e| format!("the sandbox's answer was not JSON: {e}"))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The refusal is the feature. Guessed field names in a sealed policy verify the wrong thing
    /// quietly, and a deal is trusted for its whole life.
    #[test]
    fn marqeta_terms_are_refused_until_the_paths_are_checked() {
        let err = terms(
            "https://sandbox-api.marqeta.com".into(),
            "ark1example".into(),
            FieldPathsConfirmed::not_yet(),
        )
        .unwrap_err();
        assert!(err.contains("have not been checked"), "{err}");
        // And it says what to check, rather than only that something is wrong.
        assert!(err.contains("payment identity => token"), "{err}");

        let ok = terms(
            "https://sandbox-api.marqeta.com".into(),
            "ark1example".into(),
            FieldPathsConfirmed::yes(),
        )
        .expect("confirmed");
        assert_eq!(ok.credential_key, "MARQETA");
        assert_eq!(ok.provider_origin, "https://sandbox-api.marqeta.com");
        // And the path travels with the origin. A real provider reached at the mock's path would
        // 404 for every payment that exists.
        assert_eq!(ok.provider_path, TRANSACTION_PATH_UNVERIFIED);
        assert_ne!(
            ok.provider_path,
            crate::policy::Terms::example(String::new(), String::new()).provider_path
        );
        let asked = crate::policy::evidence(&ok);
        assert_eq!(asked.path, TRANSACTION_PATH_UNVERIFIED);
    }

    /// A write key is the one thing that must never be rendered.
    #[test]
    fn the_sandbox_driver_redacts_its_credential() {
        let driver = SandboxDriver {
            base: "https://sandbox-api.marqeta.com".into(),
            basic: "c3VwZXItc2VjcmV0".into(),
            http: reqwest::Client::new(),
        };
        let rendered = format!("{driver:?}");
        assert!(!rendered.contains("c3VwZXItc2VjcmV0"), "{rendered}");
        assert!(rendered.contains("<redacted>"));
    }
}
