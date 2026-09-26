# e2e fixtures

## `fcm_test_key.pem`

Throwaway 2048-bit RSA private key used by the e2e FCM mock-server test. The
cosigner's `FcmClient` (in [`cosigner/src/fcm_client.rs`])
signs an OAuth2 JWT bearer assertion with the private key from its
service-account JSON; that signature is then sent to the OAuth token endpoint.

The e2e test runs against a local `MockFcmServer` that does NOT verify the
JWT signature — it just hands back a fake access token. So the only thing
this key needs to be is **a syntactically valid PEM** so `jsonwebtoken`'s
`EncodingKey::from_rsa_pem` can parse it.

**This key has no real-world authority.** It cannot sign anything Google,
Firebase, or any production system would accept — there is no matching
service-account registered anywhere. Treat it as deterministic test data.

Regenerate with:

```sh
openssl genrsa -out e2e/fixtures/fcm_test_key.pem 2048
```
