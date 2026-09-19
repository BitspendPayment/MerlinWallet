# MerlinWallet — Security findings ledger

Working ledger for a **later one-pass fix**. Each item is traced to code with a verdict.
Do NOT fix yet — just record. Fix pass happens once, after this list is complete.

**Legend**
- Severity: `CRIT` / `HIGH` / `MED` / `LOW`
- Status: `CONFIRMED` (I traced the code) · `PLAUSIBLE` (surfaced, not yet traced) ·
  `REFUTED` (checked — not a bug) · `INVALID` (moot given architecture)
- Each entry: `[ID] [SEV] [STATUS] file:line — issue — fix`

---

## Architectural exclusions (from the user — do NOT re-raise)
- **On-chain single-key layer is intentionally passkey-free** (standalone Bitcoin / offline
  mode; works when Ark/cosigner/passkey are unavailable). Do not gate it behind the passkey,
  and do not treat "on-chain key usable without passkey" as a bug. → C3 INVALID.
- **Server persistence (Redis snapshots) sits inside the enclave's sealing/trust boundary.**
  App-level AEAD of snapshots is redundant. → C1 INVALID.

---

## ★ CONSOLIDATED MASTER LIST (fix-pass checklist, deduped + severity-ranked)

### HIGH — fix first
- [x] **CL-1** ✓ FIXED — strip `clientExtensionResults.prf` before the `assert/finish` POST (passkey_authenticator.dart). analyze clean; server confirmed not to use PRF.
- [x] **TH-1** ✓ FIXED — single-use FROST nonce via atomic spent-flag wrapper (ffi/src/threshold: mod.rs + ffi_signing.rs). ffi builds; full 2-party sign still to be verified on device/e2e.
- [ ] **CR-3** `verify_auth` (bound to group_key) on `contract/create` before dispatch (rest_api.rs). DEFERRED per user (contract work parked) — was implemented + verified (cargo check + dart analyze clean) then REVERTED; revisit alongside the contract/eVTXO feature.
- [ ] **IN-1** `is_kms_key_locked: true` + scope/remove host-role `kms:Decrypt` (enclave.yaml:11, main.tf:379-392). *Makes the enclave boundary real (the C1 rationale).* — INFRA/Terraform; needs a deploy.
- [ ] **IN-2** verify the KMS-signed (or Sigstore) PCR0 in the client instead of the unsigned GitHub manifest (manifest.dart:45-62; main.tf:198-257). — new client feature; needs pinned-key decision + deployment details.
- [x] **EC-3** ✓ FIXED — fail CLOSED on empty/unextractable appKeyHash (attested_wallet_api.dart). analyze clean.

### MEDIUM
- [ ] **CL-4** TLS cert pinning / attested transport for requests (amplifies CL-1).
- [ ] **EC-1** cert-chain expiry + CA/basicConstraints validation (nitro.rs:339-380).
- [ ] **CR-5** bind a body hash into the auth message + jti replay cache (auth/message.rs:28-35).
- [ ] **CR-1** assert `group_key_of(user_id)==group_key` before sign dispatch (DoS/griefing).
- [ ] **CR-2** wire the dead roster authz (`auth_check_group`) into sign/cosign.
- [ ] **CR-4** authenticate `register-template` + wasm size cap/quota (rest_api.rs:536-563).
- [~] **TH-5** PARTIAL — ✓ fixed the worst offenders: both ark hex decoders (`ark/send.rs`, `ark/mod.rs`) now use `hex::decode` (no panic on odd-length / multi-byte-UTF-8 ASP input). ffi builds. REMAINING (lower priority, all have odd-length guards): threshold-ffi str-slice decoders (ffi_signing/ffi_utils/ffi_auth/ffi_dkg) UTF-8-boundary edge; identity-point panics (point.rs:32/60, low reachability); `min_signers` underflow (ffi_dkg); a `catch_unwind` backstop on all `extern "C"` bodies.
- [ ] **TH-8** tag FFI handles by type (kill `free_handle` type-confusion / double-free / secret-leak). NOTE: FFI's only caller is the trusted Dart wrapper (correct type_ids + lifecycle), so this is defense-in-depth hardening, not a live exploit. Proper fix = enum-tagged handle across ~13 box/borrow/free sites (cargo-verifiable; handle lifecycle not e2e-testable here).
- [x] **TH-3** ✓ FIXED (Debug part) — redacting `Debug` on all 5 secret structs (KeyPackage, SigningNonce, Round1/2 secret pkgs, Round2Package); ffi builds + 38 threshold tests pass. Zeroize-on-drop DEFERRED: `Drop` fights Rust move-semantics on the `Copy` scalars (forces `.clone()` churn in the tweak/sign hot path) for marginal gain — needs a non-Copy secret-wrapper refactor.
- [~] **TH-6** PARTIAL — the wallet no longer uses the improvised seeded derivation: share blinding and
  the DKG polynomial both come from one labelled HKDF (`app-core/lib/passkey/key_derivation.dart`),
  so the Dart/Rust disagreement in `dkgRefreshPart1(seed:)` is no longer on any wallet path.
  REMAINING: `dkgRefreshPart1`/`modNRandomSeeded` and `dkg_refresh_part1` still exist and still
  disagree — drop the seeded path, or make the two definitions one.
- [ ] **CL-3** attestation from build-flavor/allowlist (not host-string); treat persisted serverHost untrusted; sign/pin manifest.
- [ ] **CL-5** attested transport in the FCM background isolate for remote hosts.
- [ ] **IN-6** [UNCERTAIN] verify an ASP tree leaf pays owner_pk+amount before signing (batch.rs:920-982) — confirm ark_core doesn't already.
- [x] **IN-4** ✓ FIXED — pinned `verify.yml` enclave CLI `@latest`→`@v0.0.79` (matches release-eif.yml). Also de-staled workflows: deleted dead `cosigner.yml` (built the removed `cosigner/` WASM guest, triggered on crates/threshold+ark → failing CI), and stripped the `cosigner.wasm` build + `--wasm` flag from `e2e.yml` + `flutter-integration.yml` (cosigner-runtime is native, CLI only takes `--port`).

### LOW / hygiene
- [ ] TH-7 reject non-canonical signature `s ≥ n`; TH-4 constant-time ECIES MAC compare; TH-9 PoK domain tag / seeded-zero / into_even_y.
- [ ] CL-2 encrypted store + shorter TTL for the session token; CR-6 bounds-check compose.rs:80-87; CR-7 tighten CORS / remove unauth redeem; EC-2/EC-4 doc-timestamp recency + attestation catch_unwind.
- [ ] IN-5 SHA-pin CI actions; ignore committed empty terraform.tfstate; Firebase API-key restrictions; docker-compose 0.0.0.0 bind comment.

### DO NOT TOUCH (verified correct / invalid) — avoid churn
- FROST core is sound: BIP-340 verify math, binding factor (no Drijvers/ROS), taptweak/taptree, hash domain separation, DKG proof-of-knowledge IS verified (TH-2), production RNG (OsRng+secret-mixed nonce), Ark handle maps memory-safe, ASP-PSBT parsing panic-free.
- Client clean: no secret logging, `Random.secure()` used, no insecure deep links, foreground attestation fails closed, evtxo endpoints self-scoped, doc-replay prevented by fresh nonce.
- **C1** (app-level snapshot AEAD) and **C3** (on-chain passkey gating) remain INVALID per architecture — do not reintroduce.

---

## CONFIRMED (traced to code this session)

- **[TH-1] HIGH CONFIRMED** — `ffi/src/threshold/ffi_signing.rs:164` — FROST signing takes the
  nonce via `borrow_handle` (non-consuming); `ffi/src/threshold/handles.rs:28` `take_handle`
  (the consuming variant) is `#[allow(dead_code)]`. Nothing at the FFI boundary enforces
  FROST's single-use-nonce requirement — a retry/re-sign on the same handle → nonce reuse →
  known share-recovery (ROS/Wagner). *Fix:* consume the nonce on `sign` (take + free), 2nd use
  fails closed. Check the Dart free path so this doesn't double-free.
- **[TH-3] LOW CONFIRMED** — `crates/threshold/src/nonce.rs:8,17` — `#[derive(Debug)]` on
  `SigningCommitments` and `SigningNonce` (holds secret `hiding`/`binding` scalars). Debug can
  leak secrets into logs/panics. *Fix:* custom redacted `Debug` + `ZeroizeOnDrop`. (Review also
  named keys.rs/dkg.rs/auth.rs — verify each.)
- **[TH-4] LOW CONFIRMED** — `crates/threshold/src/ecies.rs:88` — MAC compared with `!=`
  (non-constant-time). *Fix:* constant-time compare (`subtle`).

## ACCEPTED BY DESIGN (recorded so it is not re-raised as a finding)

- **[RC-1] The passkey is now the single factor.** `app-core/lib/passkey/key_derivation.dart`,
  `cosigner/src/handlers/recover.rs`. The wallet's FROST dealer polynomial is derived from the
  passkey's PRF, and the cosigner seals `f_cosigner(wallet_id)` — the half it dealt — so `Recover`
  plus the passkey reconstructs the share on any device. Before this, an attacker needed the
  device's Hive box **and** the PRF; now the passkey alone is enough. That is the stated goal
  (a wallet that survives a lost phone), and it moves the whole weight of the design onto two
  things worth stating plainly:
  - **the platform's passkey security** — Google Password Manager / iCloud Keychain sync, and the
    user verification in front of it. A passkey exported or synced to an attacker's device is the
    wallet.
  - **the runtime's tenant resolution** (`runtime/src/auth/credential.rs`) — the credential-id →
    tenant mapping is the only thing between a caller and the sealed half. It is not a new
    exposure (the same gate guards signing) but its blast radius is now larger: half the key
    material, rather than one signature.
  Mitigations already in place: `Recover` refuses unless the caller's re-derived identifier equals
  the one the ceremony recorded; it never installs a policy; and the returned scalar is useless
  without the PRF-derived half. Nothing is escrowed that could sign on its own.
- **[RC-2] PRF stability across devices is assumed, not guaranteed.** WebAuthn does not promise a
  synced passkey yields the same PRF output on another device; it holds in practice for the two
  platform providers and not at all for a hardware key. The design fails *loudly* — the rebuilt
  share is checked against the sealed verifying share and refused if it does not match — rather
  than producing a wallet that cannot sign. A two-device manual test is the only real check;
  see the plan's verification notes.

## REFUTED (checked — NOT a bug)

- **[TH-2] DKG proof-of-knowledge IS verified** — `crates/threshold/src/dkg.rs:227`
  (`verify_proof_of_knowledge` on each dealer's round-1 pkg; impl dkg.rs:119-133 returns
  `InvalidProofOfKnowledge`). The earlier review looked at `dkg_part3` (which verifies VSS
  *shares*, not PoKs) and wrongly concluded PoK was missing. No rogue-key hole in core DKG.

---

## PLAUSIBLE — surfaced by the initial review, NOT yet code-traced (agents verifying)

### cosigner-runtime (server-side authz)
- [CR-H1] HIGH — sign_step1/2 auth may bind body `user_id`, not the URL `group_key` that
  selects the actor → cross-user actor access / chosen-message signing oracle.
  rest_api.rs ~210/602-682, handlers/helpers.rs ~69, registry.rs ~218.
- [CR-H2] HIGH — group-membership authz (`auth_check_group`/`allowed_signers`) may be dead code.
- [CR-H3] HIGH — `contract/create` (rest_api.rs ~363) may be unauthenticated.
- [CR-H4] HIGH — `contract/register-template` (rest_api.rs ~535) unauth + unbounded wasm.
- [CR-M1] MED — auth signature may not bind the request body; no replay/nonce cache.
- [CR-M2] MED — no spending policy enforced for normal wallets.
- [CR-M4] MED — panics on malformed client PSBTs (handlers/ark_send.rs) → actor churn.
- [CR-L*] LOW — permissive CORS; unbounded onboarding sessions; session tokens exp-only;
  redeem_vtxo unauth (unimplemented); contract sandbox no wall-clock deadline.

### threshold / ffi (crypto)
- [TH-5] MED — no `catch_unwind` at FFI; input-driven panics (point.rs, vss.rs, lagrange.rs).
- [TH-6] MED — random.rs: zero-scalar rejection? deterministic seeded coeffs in refresh/reshare.
- [TH-7] LOW — scalar.rs / signature.rs: malleability / low-S / range checks.

### Flutter client
- [CL-H2] HIGH — passkey PRF seed may be sent to the server on assertion
  (app/lib/passkey/passkey_authenticator.dart) — strip `clientExtensionResults.prf` before POST.
- [CL-M1] MED — session token plaintext bearer, long TTL.
- [CL-M2] MED — no TLS cert pinning; secret shares in requests.
- [CL-M3] MED — attestation decided by client host-string (downgrade?).
- [CL-H3] — FCM background isolate uses unattested transport for a remote host.

### infra / CI
- [IN-H1] HIGH — `is_kms_key_locked: false` + IAM kms:* on resources=[*] → host can decrypt
  off-enclave. (Re-check under the "enclave boundary" context — may still be a real gap if the
  host role, not the enclave, holds the decrypt capability.)
- [IN-H2] HIGH — client pins an UNSIGNED PCR0 from a mutable GitHub release; KMS-signed PCR0
  unused.
- [IN-L1] LOW — CI actions unpinned (@latest / tag not SHA).

---

## NEW (found + verified this pass)

### Enclave attestation (crates/enclave-client + ffi/src/enclave + app-core attested transport)
- **[EC-3] MED→HIGH CONFIRMED** — **appKeyHash binding fails OPEN.**
  `ffi/src/enclave/mod.rs:108` `extract_app_key_hash(...).unwrap_or_default()` returns
  `ok:true` with an EMPTY `app_key_hash` when extraction fails; `app-core/lib/attested_wallet_api.dart:217`
  `if (v.appKeyHash.isNotEmpty)` then **skips** the `SHA256(attest_pubkey)==appKeyHash` check
  and caches the server-supplied `/v1/enclave-info` pubkey unbound (attested_wallet_api.dart:227-232).
  Response signatures (post(), :256-260) are then verified against an attacker-controllable key
  → MITM of "attested" responses. Practical window: enclave pre-registration (all-zeros appKeyHash,
  verify.rs:91) or non-nitriding UserData that still passes COSE+PCR0+nonce.
  *Fix:* FAIL CLOSED when attestation is required — reject empty/unextractable appKeyHash
  (Dart: `if (v.appKeyHash.isEmpty) throw`; consider Rust returning ok:false too).
- **[EC-1] MED CONFIRMED** — `crates/enclave-client/src/nitro.rs:339-380` `verify_cert_chain`
  does **signature-only** validation: no cert validity-period (not_before/not_after) check and no
  basicConstraints/CA/keyUsage/path-length enforcement (not full RFC 5280). An expired or non-CA
  cert in the chain passes. *Fix:* check validity vs `doc.timestamp`; enforce CA basicConstraints +
  keyUsage(keyCertSign) on non-leaf certs.
- **[EC-2] INFO/LOW (mitigated)** — no attestation-document timestamp-recency check
  (`nitro.rs:255` validate_document only requires `timestamp != 0`). Replay IS prevented because
  the Dart caller uses `Random.secure()` for a fresh 20-byte nonce per fetch
  (attested_wallet_api.dart:120,182) and Rust enforces the nonce match (verify.rs:32). Add a
  `|now - doc.timestamp|` bound as defense-in-depth. NOT a live bug.
- **[EC-4] LOW** — `ffi/src/enclave/mod.rs:78` `enclave_verify_attestation_doc` has no
  `catch_unwind`; underlying nitro.rs parsing looked panic-safe on my read, but wrap for
  defense-in-depth (same class as TH-5).

### Flutter client — VERIFIED (agent, traced end-to-end)
- **[CL-1] HIGH CONFIRMED** — **PRF blinding seed uploaded to the server on every assertion.**
  `app/lib/passkey/passkey_authenticator.dart:189-197` POSTs the full `authenticationResponseJson`
  (incl. `clientExtensionResults.prf.results.first` = the 32-byte seed) to `/api/passkey/assert/finish`;
  `_extractPrfResult` (L214-230) only reads, never strips. That seed reconstructs the real FROST share
  (`client.dart:667-672`), is deterministic/permanent (fixed salt `mpcwallet-prf-v1`), resent every
  refresh, over an unpinned plain http.Client. Defeats the blinding scheme. *Fix:* deep-copy resp and
  delete `clientExtensionResults.prf` before the POST (server only needs the assertion signature). ← top client fix
- **[CL-4] MED CONFIRMED** — **No TLS certificate pinning anywhere** (attested_wallet_api.dart:50/120/243,
  passkey_authenticator.dart:92, manifest.dart:56, push_service.dart:259, client.dart:619). Attestation
  authenticates only *responses* (Schnorr over body), NOT requests — so request-borne secrets (Bearer
  token, blinded share, and the CL-1 PRF seed) rest on system-trust TLS; a user-installed/compromised CA
  reads them. *Fix:* pin the enclave/API cert or bind transport to the attested key (attested TLS/HPKE).
  Amplifies CL-1.
- **[CL-3] MED CONFIRMED (bounded today)** — attestation decided by a string denylist on the mutable
  `_host` (mpc_service.dart:315-320): `127.0.0.1`/`localhost`/`10.0.2.2`/`192.168.*` get no attestation
  AND plain http. Not remotely settable today (release hides local presets behind kDebugMode; foreground
  fails closed at _createMpcClient L329-333). Residual: persisted Hive `serverHost` trusted on cold start
  + background isolate; classification by literal string not resolved IP. Also `expectedPcr0` is fetched
  from an UNSIGNED GitHub `deployment.json` (manifest.dart:45-61) — authenticity rests on GitHub+system CA
  (ties to IN-H2). *Fix:* attestation from build flavor/allowlist, treat serverHost untrusted, sign/pin manifest.
- **[CL-5] MED CONFIRMED (bounded)** — FCM background isolate (push_service.dart:259-262) uses the
  UNATTESTED `MpcClient.rest` for any host incl. remote (no PCR0, no response-sig check); the server then
  chooses the phase-1 sighashes the wallet FROST-signs. Bounded: a passkey-gated wallet fails closed
  (no seed → `_walletKeyPackage` throws); only an un-gated wallet signs, and a fake enclave harvests only
  partial shares (lacks the cosigner share), not a full spend. *Fix:* use attested transport for remote hosts in the isolate.
- **[CL-2] LOW CONFIRMED** — session Bearer token stored plaintext in the unencrypted `mpc_service_identity`
  Hive box (mpc_service.dart:471-473), ~30-day TTL. Device compromise = 30-day API access (spends still
  need the passkey seed). *Fix:* encrypted store + shorter TTL. NOTE: box-at-rest encryption is the
  keystore/device-security question — confirm it's in scope given your enclave/device model.
- **[CL-6] REFUTED (clean)** — no secret logging (grep clean); all security RNG is `Random.secure()` +
  Rust FFI CSPRNG (no insecure `dart:math` Random feeds anything); Android manifest has only the standard
  launcher intent-filter (no custom scheme / app-links / exported receivers). Foreground attestation fails closed.

### Infra / CI / ark — VERIFIED (agent)
- **[IN-1] HIGH CONFIRMED** — **KMS key NOT PCR0-locked.** `is_kms_key_locked: false`
  (infrastructure/mutiny/enclave.yaml:11, cosigner-runtime/enclave/enclave.yaml:12,
  flake.nix:134 → `ENCLAVE_KMS_KEY_LOCKED=false`). The EC2 **host** role holds
  `kms:Decrypt/Encrypt/GenerateDataKey` on `Resource "*"` (modules/enclave/main.tf:379-392) with SSM
  shell enabled (main.tf:284-288). ⇒ anyone who can borrow the host role can decrypt the enclave's
  signing key + Storage DEK OFF-enclave. **This is the mechanism that decides whether the "persistence
  is inside the enclave boundary" assumption (the C1 rationale) actually holds — with the lock off, the
  boundary is advisory, not cryptographically enforced.** (One step — the runtime omitting the PCR0
  condition when the flag is false — lives in the external introspector-enclave and was inferred, not
  read.) *Fix:* set `is_kms_key_locked: true`; scope the host role's KMS to the specific key ARN and drop
  `kms:Decrypt` from the host.
- **[IN-2] HIGH CONFIRMED** — client pins PCR0 from a MUTABLE, UNSIGNED GitHub release
  (`.../releases/download/eif-latest/deployment.json`, plain http, no sig check —
  app-core/lib/enclave/manifest.dart:45-62 → mpc_service.dart:143-144,178-182), and `eif-latest` is
  clobbered every build (release-eif.yml:60-61,109). A KMS-signed PCR0 (`/Signing/Signature` over
  `/Signing/PCR0`, main.tf:198-257) AND a Sigstore provenance attestation exist but NO client code uses
  either (both dead). Whoever can clobber the release repoints every client's attestation root.
  *Fix:* verify the KMS signature (or GH Sigstore attestation) over PCR0 instead of trusting the raw
  manifest. (Ties to CL-3 / EC. TLS-to-github mitigates passive network.)
- **[IN-6] MED UNCERTAIN** — **ark client may not verify it gets its own funds back before signing.**
  Sighashes ARE independently derived (good), but when FROST-signing the boarding input into the
  ASP-supplied commitment tx (crates/ark/src/client/batch.rs:920-982) and MuSig2 co-signing the
  ASP-supplied tree (batch.rs:226-275), there is NO check that a resulting tree-leaf output pays
  `owner_pk` with the expected amount. If the external `ark_core` doesn't enforce tree-output ownership,
  a malicious ASP could collect the client's signatures while redirecting funds. *Fix:* before signing,
  assert ≥1 tree leaf output == expected owner VTXO scriptPubKey + amount. (Verify whether ark_core covers this.)
- **[IN-4] MED CONFIRMED** — CI attestation verifier drift: verify.yml:24 installs the enclave CLI
  `@latest` while release-eif.yml:31 pins `@v0.0.79`. *Fix:* pin verify.yml to the same version.
- **[IN-5] LOW** — CI third-party actions are tag/branch-pinned, not SHA-pinned, in privileged workflows
  (id-token/attestations:write). *Fix:* pin to commit SHAs. (No `pull_request_target`, no script
  injection — REFUTED, good.)
- **[IN-EC] confirms EC-1/EC-2** — independently found nitro.rs `verify_cert_chain` lacks cert
  expiry/freshness validation (COSE + pinned-root chain + nonce ARE real and correct).

### Infra — DEV-ONLY / INFO (NOT findings, catalogued so we don't chase them)
- Firebase client API key committed (google-services.json / firebase_options.dart) — designed to ship;
  action = confirm API-key restrictions + Firebase rules are set. LOW/INFO.
- Dev-only secrets (all confirmed non-production): e2e/fixtures/fcm_test_key.pem (mock FCM),
  WEBAUTH_TOKEN_SECRET dev value (Makefile:150), regtest admin1:123 / testpass / ARKD signer key,
  debug.keystore. `.gitignore` correctly covers real secrets (FCM SA, tfvars, tfstate in tofu/).
- `infrastructure/mutiny/terraform.tfstate` committed but an empty 151-byte skeleton — add a .gitignore
  at that path so a future local apply can't commit real state. LOW.
- SSM env overrides use `type=String` (plaintext) not SecureString — documented accepted tradeoff. LOW.
- docker-compose.ark.yml:67-75 comment says redis is on 127.0.0.1 but maps `6379:6379` (0.0.0.0). Dev
  only; fix mapping to `127.0.0.1:6379:6379`.

### threshold / ffi crypto — VERIFIED (agent, deep)
Toolchain note: repo builds on rustc 1.94 and no in-scope crate sets `panic="abort"`, so an FFI-boundary
panic is a **defined process abort (DoS)**, NOT UB (UB only pre-1.81). No `catch_unwind` anywhere.

- **[TH-1] CRITICAL/HIGH CONFIRMED** (already established) — nonce single-use not enforced;
  `threshold_frost_sign` (ffi_signing.rs:164) borrows and never consumes/invalidates the nonce; no
  "spent" flag; `take_handle` dead. Two signs on one handle over different packages → linear share
  recovery. *Fix:* consume the handle (or one-shot spent flag).
- **[TH-5] MED CONFIRMED** — no `catch_unwind` in ANY `extern "C"` fn → every reachable panic aborts the
  app (DoS). Concrete input-reachable panic sites:
  - `ffi/src/ark/send.rs:676` `hex_decode` has **no odd-length guard** (`&hex[i..i+2]` str-slicing) —
    odd-length or multi-byte-UTF-8 hex ⇒ panic; reused by evtxo_spend.rs → affects ark_build_send_tx,
    ark_insert_send_signatures, ark_build_evtxo_spend, ark_finalize_evtxo_spend. (worst offender)
  - non-char-boundary `&s[i..i+2]` hex slicing: ffi_signing.rs:28, ffi_utils.rs:24, ffi_auth.rs:20,
    ffi_dkg.rs:759, keys.rs:294, vss.rs:113, dkg.rs:1103, ffi/src/ark/mod.rs:92.
  - identity-point panics: point.rs:60 (`.expect("point at infinity")` in has_even_y), point.rs:32
    (serialize_compressed copy_from_slice on the 1-byte identity encoding). Reachable if group commitment
    R = identity (low practical reachability — needs DL/grind — but should return Error::InvalidPoint).
  - vss.rs:34 `coeffs[0]` on empty commitment; ffi_dkg.rs:346/549 `min_signers - 1` underflow when
    min_signers==0 (before validate); send.rs:134/evtxo_spend.rs:108 `.lock().unwrap()` poison.
  - REFUTED: lagrange.rs:30 `invert().expect()` is safe (distinct non-zero identifiers ⇒ den≠0).
  *Fix:* wrap all extern "C" bodies in catch_unwind (or panic="abort" for clean crash); replace
  hand-rolled str-slice hex with the `hex` crate + reject odd length; make has_even_y/serialize return Result.
- **[TH-8] MED CONFIRMED** — `threshold_free_handle` (ffi/src/threshold/mod.rs:104-133) takes a
  caller-supplied `type_id` and does `Box::from_raw(handle as *mut WrongType)` on mismatch → drops with
  wrong Layout → **heap corruption/UB**. Also double-free / use-after-free are unguarded (caller
  discipline only). And `threshold_free_result` (mod.rs:47/86) intentionally does NOT free the secret
  `handle` → leak of un-zeroized SigningNonce/Round{1,2}SecretPackage/AuthSigner. *Fix:* tag handles with
  their type (box an enum); track liveness; zeroize on drop.
- **[TH-3] MED CONFIRMED** — **no zeroization anywhere**; k256 pulled WITHOUT the `zeroize` feature
  (crates/threshold/Cargo.toml:10) so `Scalar` isn't scrubbed. Secret structs, several also `derive(Debug)`
  (⇒ `{:?}` prints the secret — MED-HIGH on a mobile threat model): keys.rs:49 KeyPackage.secret_share,
  nonce.rs:18 SigningNonce, dkg.rs:37/53/47 Round1/2 secret pkgs + dealt share, dkg.rs:788
  RefreshedPairing.receiver_half, auth.rs:20 AuthSigner.secret (no Debug, good; still unzeroized).
  *Fix:* enable k256/zeroize, wrap in Zeroizing/ZeroizeOnDrop, drop Debug on secret structs.
- **[TH-6] MED CONFIRMED (footgun)** — deterministic-seed reuse: refresh/reshare coefficients are
  `SHA256(seed||counter) mod n` (random.rs:28/49), fully determined by the caller seed (exposed via
  ffi_utils.rs:112, ffi_dkg.rs:344/547). Reusing a seed across two refresh rounds regenerates the same
  masking polynomial → defeats proactive-refresh independence; low-entropy/logged seed → reconstructable.
  *Fix:* derive seeds from a CSPRNG + unique session context; document loudly or drop the seeded path in prod.
- **[TH-7] LOW CONFIRMED** — signature `s`/`z` not range-checked: `scalar_from_bytes_allow_zero`
  (scalar.rs:15-17) reduces mod n instead of rejecting `s ≥ n` (auth.rs:107 decodes z this way). BIP-340
  mandates rejecting `s ≥ n`; only a ~2^-128 alias band is affected so honest sigs are fine, but it's a
  malleability/spec gap. *Fix:* reject non-canonical `s` (compare to n before reduce).
- **[TH-9] LOW** — random.rs:28 seeded RNG doesn't reject zero (negligible 2^-256; only affects a
  non-constant coeff, not the shared secret). DKG PoK challenge (dkg.rs:67) is a bare `SHA256(id||vk||R)`
  with no domain tag — sound but add a context tag for hygiene. `into_even_y` (signature.rs:25) negates R
  not z — latent, not exploitable today (all call sites pre-normalize R even).
- **REFUTED (verified correct — do NOT touch):** BIP-340 verify math (signature.rs:49, auth.rs:92);
  binding factor is RFC-9591 correct, binds all commitments+msg ⇒ **no Drijvers/ROS weakness** (binding.rs:48,
  compute_group_commitment rejects identity); taptweak + taptree tags/sorting/leaf-version correct
  (tweak.rs, taptree.rs); hash.rs domain separation correct + distinct; production RNG sound (OsRng +
  nonce mixes secret share); Ark session handle maps are memory-safe (integer-keyed HashMap, idempotent free).

### cosigner-runtime authorization — VERIFIED (agent)
- **[CR-3] HIGH CONFIRMED** — **`contract/create` is unauthenticated.** rest_api.rs:363-394 collects
  `signature`/`timestamp_ms` but NEVER verifies them; dispatches ContractRefresh + AddContract + SeedPolicy
  (contract/manager.rs:45-184). Unauthenticated attacker can, vs any onboarded wallet V: run a key-refresh
  of V's cosigner share with attacker params (actor.rs:363-400 → dkg::refresh_to_receiver), mutate V's
  sealed state (unbounded `contracts` map growth), store arbitrary wasm/eVTXO scripts. Full drain REFUTED
  (pairing actor only co-signs the eVTXO coop leaf; V's normal funds still need V's user share; fresh
  blinding poly per refresh ⇒ cosigner key doesn't leak) — but it's an unauthenticated secret-share op +
  victim-state write. *Fix:* verify_auth (op bound to group_key) before any dispatch. ← top server fix
- **[CR-1] MED CONFIRMED (binding gap) / theft REFUTED** — sign_step1/2 auth binds the BODY `user_id`
  (signer_user_id, rest_api.rs:210-217), not the URL `group_key` that selects the actor
  (registry.rs:218-232); no `user_id==group_key`/roster check. Attacker A CAN drive V's actor ceremony —
  but `threshold::aggregate` verifies every share + the full sig (signing.rs:201,222-233) so step2 errors
  without V's genuine share. Net: **ceremony-reset griefing/DoS** of a concurrent legit signer (sign_step1
  overwrites in-flight ceremony, actor.rs:583), NOT the chosen-message share-extraction oracle the initial
  review claimed. *Fix:* assert group_key_of(user_id)==group_key before dispatch.
- **[CR-2] MED CONFIRMED dead code** — `auth_check_group`/`auth_check`/`is_authorized_share`
  (helpers.rs:151,17,141) are transitively dead; the roster control (`ContractPolicy.authorized_service_vks`,
  manager.rs:98) is never enforced. Only `verify_auth` runs, and it does no membership check. *Fix:* wire it in.
- **[CR-4] MED CONFIRMED** — `contract/register-template` (rest_api.rs:536-563) has no verify_auth
  (author_vk = URL group_key ⇒ authorship spoofing / directory poisoning) and no explicit wasm size cap
  (only axum's 2MB default; no per-author quota). Validates sha256(wasm)==id + no-wasi (good). *Fix:* auth
  binding author_vk==authenticated group_key + size cap + quota.
- **[CR-5] MED CONFIRMED** — replay / no body binding: signed auth message is
  `SHA256("MPC_WALLET_AUTH_V1:op:ts:user_id")` (auth/message.rs:28-35) — binds op/ts/user only, NOT
  amount/recipient/message_to_sign/body; ±5min drift, no jti/nonce cache (SessionClaims.jti never recorded).
  Captured (user,op,ts,sig) replayable 5min for ANY body of that op+user (e.g. replay register-device-token
  with a swapped fcm_token). Spends separately gated by FROST sighash. *Fix:* bind a body hash into the auth
  message + jti seen-cache.
- **[CR-6] LOW CONFIRMED (new panic)** — `src/contract/compose.rs:80-87` synthesize_provider does an
  unchecked `bytes[slot..slot+2]`/`bytes[slot+2..+kv_blob.len()]` write; a stub whose `CFGSLOT!` marker
  leaves <2+len trailing bytes panics — reachable UNAUTHENTICATED via contract/create. Memory-safe, aborts
  request. *Fix:* bounds-check slot vs bytes.len().
- **[CR-7] LOW** — `CorsLayer::permissive()` (main.rs:317) on a wallet API (limited impact — auth is
  header/body-sig, not cookies); `/u/{gk}/ark/redeem` unauthenticated (rest_api.rs:855-872) but RedeemVtxo
  is `unimplemented` (actor.rs:1593) → no-op today (latent trap). *Fix:* tighten CORS to app origins;
  remove/authenticate redeem before implementing.
- **REFUTED** — evtxo/pending + evtxo/ack are self-scoped by `req.user_id` (contract.rs:84,119), NOT
  cross-user exploitable; ark_send.rs:257-260 `outputs[idx]` guarded by len>=3, inputs[0] panic caught by
  run_blocking (registry.rs:286-306); DKG + passkey endpoints unauthenticated BY DESIGN (bootstrap); most
  /ark/* + push endpoints correctly force user_id==group_key.

