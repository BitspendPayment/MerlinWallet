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
- [x] **CL-1** ✓ FIXED — strip `clientExtensionResults.prf` before the assertion is sent (now `app/lib/passkey/platform_passkey.dart`, `_stripPrf`; the PRF is also no longer *evaluated* except for an assertion that a signing operation asked a seed from). analyze clean; server confirmed not to use PRF.
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
- [~] **TH-6** PARTIAL — the wallet no longer uses the improvised seeded derivation: the DKG
  polynomial comes from one labelled HKDF (`app-core/lib/passkey/key_derivation.dart`), so the
  Dart/Rust disagreement in `dkgRefreshPart1(seed:)` is no longer on any wallet path. Share blinding
  is gone altogether — no share is kept to blind — and its label, `merlin/frost/blind/v1`, is
  retired and must not be reused.
  REMAINING: `dkgRefreshPart1`/`modNRandomSeeded` and `dkg_refresh_part1` still exist and still
  disagree — drop the seeded path, or make the two definitions one.
- [ ] **CL-3** attestation from build-flavor/allowlist (not host-string); treat persisted serverHost untrusted; sign/pin manifest.
- [ ] **CL-5** attested transport in the FCM background isolate for remote hosts.
- [ ] **IN-6** [UNCERTAIN] verify an ASP tree leaf pays owner_pk+amount before signing (batch.rs:920-982) — confirm ark_core doesn't already.
- [x] **IN-4** ✓ FIXED — pinned `verify.yml` enclave CLI `@latest`→`@v0.0.79` (matches release-eif.yml). Also de-staled workflows: deleted dead `cosigner.yml` (built the removed `cosigner/` WASM guest, triggered on crates/threshold+ark → failing CI), and stripped the `cosigner.wasm` build + `--wasm` flag from `e2e.yml` + `flutter-integration.yml` (cosigner-runtime is native, CLI only takes `--port`).

- [x] **NK-1** ✓ DONE 2026-09-19 — enclave e2e re-run over the cancellation work (RC-4): `make
  e2e-enclave`, 22/22, no skips, against the staged tree. The earlier 22/22 predated the three
  rounds of cancellation fixes, which sit on the happy paths of `Send`, `Settle` and `Recover`
  (`CancelSignal.guard` around every ASP wait, a tracked `Recover` call, `_stillRunning` before
  every state change); this run is over them. Cancellation *itself* is still proved only in
  `app-core/test/operation_lifecycle_test.dart` — the e2e never cancels anything.
- [ ] **NK-2** let a stale fingerprint prompt be withdrawn: plumb a `CancellationSignal` through
  `app/android/.../PasskeyPlugin.kt` and `PasskeyChannel`. Today a prompt cannot be taken off the
  screen from Dart, so an operation queued behind a cancelled one waits for the owner to answer or
  dismiss a prompt for something they already cancelled — or for its 5-minute timeout. Safe (the
  late seed is overwritten, the late approval dropped — RC-4), but poor. Not written: Kotlin that
  cannot be device-tested from a dev box.
- [ ] **NK-3** a Flutter-side test of the queued-prompt fix against the real `PlatformPasskey` with a
  mocked platform channel — how the reviewer reproduced it. The app-core test uses a stand-in seed
  source that enforces the same one-capture-at-a-time rule; the fix lives in `MpcClient`, so it
  covers both, but the real class's capture/cleanup ordering is asserted nowhere.
- [ ] **NK-4** manual two-device PRF test (RC-2) — promoted from "before relying on recovery" to
  "before relying on payments": since RC-3 a PRF that answers differently stops every signing
  operation, not only a restore.

### LOW / hygiene
- [ ] NK-5 decide when the app cancels an operation. Wired today: the boarding screen's "Stop
  waiting", and `reconnect()` / `resetLocalWallet()` (which would otherwise hang behind a stuck
  operation on a graceful close). Deliberately NOT wired: app backgrounding, or any timer — a round
  abandoned after its intent is registered is one the ASP was counting on, and arkd may penalize it.
  Product/ASP-policy call. Also: send, protect and renew have no "Stop waiting" of their own.
- [x] NK-6 ✓ DONE 2026-09-26 — `.github/workflows/ci.yml` replaces `e2e.yml` (which built a native
  `cosigner` binary that no longer exists and ran an archived test, so it could not pass): cosigner,
  threshold and ffi `cargo test`; every Dart package analyzed; `app-core` tests against the built
  FFI; `flutter analyze` + `flutter test`. `AGENTS.md` rewritten for the current layout.
  Required-check names changed — branch protection, if any, needs `Rust (cosigner, threshold, ffi)`
  / `Dart (…)` / `Flutter (…)`. Later the same day: the `enclave-e2e` job boots the e2e from a
  *downloaded* dev-enclave bundle (a GitHub Release asset of enclave-runtime, pinned in
  `enclave-bundle.lock`). Its `image.env` is sourced as bash and its container images are
  `docker load`ed, so the sha256 in the lock is the trust boundary: `make enclave-bundle` verifies
  it before unpacking, and a lock bump is a review of what the runtime published, not a refresh.

### PR #55 review, 2026-09-26 — the escrow commits (b8b98050..50f9bd0c), fixed in this pass
Each was reproduced or read end to end before it was fixed, and each fix has a test that fails
without it. The enclave e2e was run over the fixed tree on 2026-09-26: 27/27, including the five
escrow tests — the branch's first end-to-end run since the escrow commits.
- [x] **P55-H1** escrow operations could not be cancelled, and a cancelled reclaim could still move
  money: the three escrow streams were built outside `CosignerConnection._track`, the polynomial
  and delta were moved out of the `WalletOperation` into closures, and `ReclaimSession` /
  `PairingSession` awaited the ASP, the HTTP delivery of a secret and the confirmation without
  `CancelSignal.guard`. Now tracked, rebuilt inside the operation (`escrowKeyPackage`, same
  first-round-only contract as the wallet's), guarded, and `_stillRunning`-checked. Also found on
  the way: `Duplex.close()` never returned for a stream nobody had listened to yet. Tests:
  `cancel_streams_test.dart`, `escrow_reconstruction_test.dart` ("inside an operation").
- [x] **P55-H2** a release was signed BEFORE it was recorded, and `seal()` only logged a failed
  write; one failed write after a signed release was one payment paid twice (reproduced). Now
  record → `try_seal` → sign, with the in-memory record rolled back on a failed seal, so the
  instance and the seal always agree. Test: `release_test.rs`
  `a_release_the_seal_cannot_record_is_not_signed`.
- [x] **P55-H3** a pre-signed reclaim bypassed a later deal: reclaim signatures taken while no deal
  was live could be kept and spent under a deal struck afterwards — nothing in Bitcoin stops it,
  both pairings sign the same key, and `EscrowOpenSession` neither invalidated them nor knew they
  existed. The cosigner cannot see whether signatures left the device or whether the outpoints
  they spend still exist, so the only sound rule with what it knows: an escrow a reclaim was ever
  OPENED on is retired from deals for good (`EscrowRecord.reclaim_opened_at`, set and sealed
  before the reclaim's first nonce, checked first in `open_escrow_session`). A reclaim empties
  the escrow anyway; the next deal gets a new one. Tests: `release_test.rs`
  `an_escrow_a_reclaim_was_opened_on_cannot_be_committed_again` (the bypass, and its survival of
  a reopen) and `…abandoned_after_its_first_message…` (over the wire, cut off before the wallet
  answers). Not done: invalidating the signatures themselves, which would need the escrow's funds
  moved at every deal open — a ceremony, not a check.
- [x] **P55-M1** `x_only` byte-sliced `k[2..]` after `to_ascii_lowercase`, so a 66-byte key with a
  multibyte character — which a paired service can send — panicked the guest. One `pub(crate)`
  copy now, sliced only when ASCII. Unit test in `cosigner.rs`.
- [x] **P55-M2** a seal that was present but unreadable opened as a wallet with no key, so a store
  read fault would have let a DKG re-key the tenant over sealed funds. `restore_snapshot` now
  distinguishes "no seal" from "unreadable seal" and `Cosigner::open` refuses the latter. Test:
  `seal_test.rs`. (Pre-existing; RC-3 made the seal the only copy of anything.)
- [x] **P55-M3** the plain-HTTP exception for the pairing contribution was a hostname prefix
  match (`10.attacker.com` passed). `isLocalDevelopmentHost` parses an address: loopback or
  RFC 1918, never a name. Test: `escrow_recovery_test.dart`.
- [x] **P55-M4** escrows were not recoverable (`recoverEscrows` existed only in a doc comment,
  `EscrowSummary` carried no context) and `resetLocalState` left `_escrows` populated, so a reset
  and a recovery of another wallet saved the old wallet's escrows under the new one. `Recover`
  now returns `EscrowSummary` with `context`; `recover()` rebuilds them (`fromSummary`, which
  refuses another wallet's identifier and skips a context-less escrow); reset and an empty
  restore clear them. Tests: `recover_test.rs`, `escrow_recovery_test.dart`.
- [x] **P55-M5** `restoreWallet` persisted the credential id before `recover()`, so a failed
  restore left a passkey the next Create reused for a DKG the cosigner refuses. Rolled back on
  failure. No automated test: needs the platform channel.
- [x] **P55-M6** `signing_screen` called `setState` after `await sendArk` with no `mounted` check,
  logging a completed send as failed. Plus the same guard in four onboarding screens.
- [x] **P55-L** a release answered under a previous deal is now refused rather than re-signed
  uncounted; `provider[8..]` / `origin[8..]` use `get`; `threshold_dkg_reshare_part1` exports
  again (a misplaced `#[no_mangle]`); `resetLocalWallet` clears the mirrored contact and request
  lists, as its copy says.
- [ ] **P55-open** — not fixed, recorded: ~~a reclaim checks the identifier against the sealed
  one, so the check cannot fail~~ — fixed 2026-10-02: a reclaim is a `Send`, which checks the
  caller's identifier first;
  evidence is not cryptographically bound to amount or reference — the policy author binds it
  with `MatchesReference`/`MatchesAmount`; `MAX_RELEASED_REFERENCES` is fail-closed but
  permanent and burnable by a paired service under an `Always` policy; `now_secs()` falls back
  to 0, fail-open for release; a cold start whose `restoreSession` fails has no retry
  (`reconnect()` is unreachable); no in-process test drives a reclaim past its
  first message (`PairService` was removed 2026-10-02: the `Escrow` stream pairs; `EscrowReclaim`
  too: a reclaim is a `Send` naming the escrow); `app/integration_test` still
  targets the deleted PIN screens; `EscrowRecord` /
  `ServicePairing` derive an un-redacted `Debug`; dead Makefile targets (`runtime-run` and what
  depends on it); wallet-level `SpendingPolicy` and `ServiceList`/`ServiceRevoke` have no
  equivalent on this branch.
- [ ] TH-7 reject non-canonical signature `s ≥ n`; TH-9 PoK domain tag / seeded-zero / into_even_y.
- [ ] CL-2 encrypted store + shorter TTL for the session token (the store no longer holds key material — see RC-3 — so this is now about privacy of outpoints and the exit address; the two-minute PRF seed cache is gone); CR-6 bounds-check compose.rs:80-87; CR-7 tighten CORS / remove unauth redeem; EC-2/EC-4 doc-timestamp recency + attestation catch_unwind.
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
- **[TH-4] LOW — RESOLVED 2026-10-02 by deletion.** `crates/threshold/src/ecies.rs` compared its
  MAC with `!=` (non-constant-time). The module had no caller left once the eVTXO onboarding that
  used it was removed (`2a86be70`), so it went, with its FFI exports and Dart wrappers.

## ACCEPTED BY DESIGN (recorded so it is not re-raised as a finding)

- **[RC-1] The passkey is now the single factor.** `app-core/lib/passkey/key_derivation.dart`,
  `cosigner/src/cosigner.rs`. The wallet's FROST dealer polynomial is derived from the
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
  share is checked against the verifying share and refused if it does not match — rather
  than producing a wallet that cannot sign. A two-device manual test is the only real check;
  see the plan's verification notes. Since RC-3 this is exercised by **every** signing operation,
  not only by recovery: a PRF that drifted on the *same* device would now stop payments there,
  loudly (`WrongPasskey`), where it used to stop only the unblinding.
- **[RC-3] The device stores no private-key material; the share is rebuilt per operation.**
  `app-core/lib/client.dart` (`_withOperation`), `app-core/lib/passkey/operation_secrets.dart`,
  `app-core/lib/passkey/share_reconstruction.dart`, `cosigner/src/cosigner.rs`
  (`dealt_share_for`), `cosigner/src/session.rs`. Development architecture; not production-ready.
  - *What changed.* The phone used to persist a blinded share (δ) and — in the clear — the DKG
    dealer secret `a0` as `onchainSecret`, in an unencrypted append-only Hive box, and kept the PRF
    output in memory for two minutes after any assertion. It now persists public state only
    (`WalletStore` refuses the old keys by name, at any depth), and `f_cosigner(wallet_id)` comes
    back on the first round of `Sign`, `Send` and `Settle` — under that stream's own approval, so
    still one fingerprint per operation — as well as from `Recover`.
  - *Why it is not a new exposure.* RC-1 already made `passkey PRF + an approved call` sufficient
    for the wallet's half. The contribution is released more *often*, to exactly the party that
    could already ask for it. It is never the cosigner's own share (tested:
    `cosigner/tests/stream_contribution_test.rs`). What is strictly better: a stolen, imaged or
    backed-up phone yields nothing secret, where it used to yield δ and `a0`.
  - *What binds it.* Tenant isolation is the runtime's (an instance can read one tenant's seal).
    In-guest, the stream's open names the wallet identifier and a mismatch is `permission_denied`
    before anything is answered. **The identifier is public** — this is a wrong-wallet check, not
    authentication, and must not be leaned on as one. The wallet, for its part, accepts a rebuilt
    share only against the verifying share *it* stored, not one that arrived with the contribution.
    The exception is `Recover` on a new device, which has nothing of its own to compare with and so
    trusts the enclave for the public key package; a substituted package yields a wallet whose
    addresses are not the owner's.
  - *What it does not do.* It does not zeroize: the seed buffer is overwritten, but coefficients and
    the share are Dart `BigInt`s (uncollectable on demand, never cleared), the FFI takes the key
    package as a JSON string, and the PRF output arrives from the platform channel inside an
    immutable string. The lifetime is bounded by reference — one serialized operation, disposed in
    a `finally`, cancellable (`MpcClient.cancelOperation`) — not by scrubbing.
  - *Availability.* Unchanged. Signing always required the cosigner (2-of-2). Pre-signed exits hold
    no secret and need none to broadcast; the cosigner's unattended renewals use no wallet share.
  - *No migration.* Old client state is refused (`IncompatibleWalletStateException`) and reset; a
    seal with no dealt share refuses every signing stream. Acceptable only because all existing
    wallets are development data.
  - *Known limits — accepted, recorded so they are not re-raised as findings.*
    - **No zeroization** (above): bounded by reference, not by scrubbing. Would need secrets held
      outside the Dart heap — the share living behind an FFI handle, as nonces already do.
    - **One rule is proved only end to end.** The second-and-later sighashes of a `Settle` carry an
      empty share — enforced on both sides (`dealt.take()` in `session.rs`; the memoized resolver in
      `operation_secrets.dart`, which throws `ContributionProtocolException` on a second share) —
      but the in-process cosigner tests cannot answer a round, so they cover the first message of
      each stream and the e2e suite covers the rest.
    - **`Recover` on a new device trusts the enclave for the public key package** (above). Every
      later operation checks against what the device itself stored; only the first has nothing to
      check against. Closing it needs something out of band — e.g. the owner confirming a known
      address — not more protocol.
    - **The client store is still unencrypted** (`PRODUCTION_READINESS.md` #10). It no longer holds
      key material, so this is privacy (group key, outpoints, exit address, pre-signed exits), not
      custody.
    - **The seal is now read on every signing operation**, not only on recovery: a lost seal stops
      payments the same day (`PRODUCTION_READINESS.md` #7). Not a new dependency — signing already
      needed the cosigner's own share out of the same blob — but nothing on the phone can stand in.
  - *Follow-ups:* NK-4, NK-6 in the master list (NK-1 done).
- **[RC-4] Cancelling an operation: what it guarantees, and what it cannot.**
  `app-core/lib/client.dart` (`_withOperation`, `_runOperation`, `_takeSeed`, `_stillRunning`,
  `cancelOperation`), `app-core/lib/passkey/operation_secrets.dart` (`CancelSignal`),
  `app-core/lib/cosigner/connection.dart` (`cancelOpenStreams`). Three review rounds; each finding
  below was reproduced, fixed, and its test mutation-checked
  (`app-core/test/operation_lifecycle_test.dart`).
  - *Why it exists.* An operation holds the rebuilt share for as long as it runs, and operations
    that sign are serialized behind one lock (RC-3). So an operation that cannot be stopped is a
    share that cannot be released **and** a wallet that cannot do anything else. `close()` is a
    graceful gRPC shutdown and waits for calls in flight — it was never a cancel.
  - *What is guaranteed.* `cancelOperation()` ends the running turn at once, wherever it is parked:
    the operation is disposed, its approval dropped and the lock released in the **outer** frame,
    before the next operation can start. Specifically:
    - a `Settle` waiting on a silent ASP (or a `Send` on `SubmitTx`/`FinalizeTx`) unwinds — every
      wait on a party other than the cosigner goes through `CancelSignal.guard`, so the driver's
      frame, and the share in it, go too;
    - a cancelled `Recover` stays cancelled: the gRPC call itself is cancelled, and `_stillRunning`
      refuses every state change (adopt, save, record delegate) on behalf of a turn that is over —
      a late reply adopts and saves nothing;
    - a cancel while a fingerprint prompt is showing starts nothing when the prompt is later
      answered: the late seed is overwritten and the late approval token discarded (also when the
      passkey fails after approving), so no later stream can ride a gesture made for a cancelled
      operation; and that cleanup cannot take a newer operation's approval with it, because the
      next operation waits for it (`_promptInFlight`) before asking for a gesture of its own;
    - operations still waiting their turn are untouched, and an operation waiting behind a stale
      prompt can itself be cancelled;
    - the escrow operations — mint, pair, reclaim — are held to the same rule since P55-H1: their
      streams are tracked, the escrow share is rebuilt inside the operation, and the ASP, the
      HTTP delivery of a contribution and the pairing confirmation are guarded waits.
  - *Known limits — accepted.*
    - **A prompt cannot be withdrawn** from Dart; the platform plugin takes no cancellation signal.
      The queue behind a stale prompt waits for it (NK-2).
    - **`guard` stops the waiting, not the work.** `Recover` is really cancelled; the ASP's unary
      calls are not. A send cancelled during `SubmitTx`/`FinalizeTx` may still have happened — the
      wallet learns of it from the indexer, and its local delegate record is stale until the next
      seal. Inherent to cancelling a request already on the wire.
    - **What an abandoned round costs is the ASP's to say.** After an intent is registered arkd is
      counting on the wallet; hence no cancel-on-background and no timer (NK-5).
    - **Cancellation is owner-initiated only.** Nothing detects a dead ASP by itself — a settle
      legitimately waits minutes, so nothing but the owner can tell slow from gone.
  - *Follow-ups:* NK-2, NK-3, NK-5 (NK-1 done).

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

