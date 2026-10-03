# TODO

Pending fixes diagnosed but not yet implemented. Each entry has the symptoms,
the root cause, and a concrete plan.

---

## 1. Boarding `Settle` deadlocks on `(Some, false)` poll arm

**Status:** ✅ fixed in
[cosigner-runtime/src/cosigner/handlers/ark_send.rs](cosigner-runtime/src/cosigner/handlers/ark_send.rs)
— stale-session-recovery guard coerces `existing` to `None` when the
client polls without sigs, so the match falls straight into the Phase 1
rebuild arm (one round-trip recovery, not two). The dead `(Some, false)`
arm is now `unreachable!` for exhaustiveness — any future regression that
parks a session back without sigs will trip the panic.

Manual verification (the practical recovery test): force-quit the app
mid-boarding (after Phase 1 returns `SIGNING_REQUIRED`, before sigs sent),
reopen, retry — boarding should succeed without an emulator wipe. The
existing happy-path e2e test guards against regressions in the rebuild
arm itself.

### Symptoms

User taps **Board** in the app. The spinner runs forever. The `enclave log`
shows the client polling `POST /api/u/<id>/ark/settle` every ~2 seconds, each
returning HTTP 200 in 2–3 ms with only the entry log line:

```
[<user>] Settle
```

No `"scanning electrum"`, `"intent registered"`, `"commitment sigs submitted"`,
`"VTXO recorded"`, or any error.

### Root cause

The handler at
[`cosigner-runtime/src/cosigner/handlers/ark_send.rs::settle`](cosigner-runtime/src/cosigner/handlers/ark_send.rs)
has a polling arm:

```rust
// Polling without signatures while a session is live.
(Some((session, boarding_amount, exit_delay)), false) => {
    state.settle_session = Some((session, boarding_amount, exit_delay));
    Ok(SettleResponse {
        status: settle_response::Status::WaitingForBatch as i32,
        ...
    })
}
```

If `state.settle_session` is `Some(...)` (a session was created on a previous
attempt) **and** the client sends a request with empty `signed_messages`, this
arm fires, parks the session back, and replies `WaitingForBatch` immediately.
The client's loop at
[`app-core/lib/client.dart::settle`](app-core/lib/client.dart) treats
`WAITING_FOR_BATCH` as "keep polling with empty sigs":

```dart
if (status == SettleResponse_Status.WAITING_FOR_BATCH) {
  await Future.delayed(Duration(seconds: 2));
  signedMessages = [];   // clears anything we had
  continue;
}
```

Neither side advances the batch state machine. Classic deadlock.

### How a stale session ends up there

The actor's `state.settle_session` is per-process state. A previous boarding
attempt that successfully completed Phase 1 (server creates session, returns
`SIGNING_REQUIRED`) but then never had its signatures delivered — because the
user backed out of the screen, the app was force-quit mid-flow, the network
dropped, etc. — leaves a stale `Some(...)`. On the next boarding attempt the
client starts its `while (true)` loop fresh with `signedMessages = []`, hits
the `(Some, false)` arm, and never escapes.

This is *structurally* the same as in the OLD `server/src/wallet_service.rs`
at commit `837f13f`, but in OLD the failure modes that left a stale session
typically surfaced as gRPC errors that closed the screen, so users rarely hit
this in practice. In NEW the actor lifecycle and per-actor state make stale
sessions stickier.

### Plan

Two layered fixes, do both:

1. **Drop the stale session on poll-without-sigs.** The `(Some, false)` arm is
   a footgun: there is no legitimate "poll while server is driving" case —
   the server holds the gRPC connection for the duration of `drive()` inside
   the `(Some, true)` arm. So a client polling without sigs is *always* a
   client that abandoned a previous attempt. Patch:

   ```rust
   (Some(_), false) => {
       // Client polled without sending sigs; assume previous attempt was
       // abandoned. Drop the session so the next call rebuilds Phase 1.
       tracing::info!("[{user_id_hex}] Settle: dropping stale session on poll-without-sigs");
       // state.settle_session is already taken at the top of the function
       Ok(SettleResponse {
           status: settle_response::Status::WaitingForBatch as i32,
           messages_to_sign: vec![],
           script_path_spend: false,
           commitment_txid: String::new(),
           error_message: String::new(),
       })
   }
   ```

   The next client call will see `state.settle_session == None`, hit the
   `(None, false)` arm, and rebuild Phase 1 with a fresh Electrum scan and a
   fresh `SIGNING_REQUIRED` response.

2. **UI escape hatch.** Add a "Reset boarding" action in the boarding screen
   that calls a new lightweight RPC clearing `state.settle_session`. Lets the
   user recover deterministically without waiting for fix #1's heuristic to
   take effect.

### Files to touch

- [cosigner-runtime/src/cosigner/handlers/ark_send.rs](cosigner-runtime/src/cosigner/handlers/ark_send.rs)
  — modify the `(Some, false)` arm; possibly add a `clear_settle_session`
  command for the UI escape hatch.
- [protocol/protos/mpc_wallet.proto](protocol/protos/mpc_wallet.proto) — add
  `rpc ClearBoardingSession` if implementing fix #2.
- [app/lib/screens/ark/ark_board_screen.dart](app/lib/screens/ark/ark_board_screen.dart)
  — add a "Reset" button wired to the new RPC.

### Verification

- Board succeeds end-to-end: `/api/u/<id>/ark/settle` returns
  `SIGNING_REQUIRED` on first call, then drives to `SETTLED`.
- After force-quitting the app mid-flow and reopening, board succeeds without
  an emulator wipe.
- e2e Ark test (`e2e/test/ark_e2e_test.dart`) still passes.

---

## 2. Server-side `ark_tx_history` drops receives during any active session

**Status:** ✅ fixed — gate removed in
[cosigner-runtime/src/cosigner/handlers/vtxo_stream.rs](cosigner-runtime/src/cosigner/handlers/vtxo_stream.rs);
the Dart-side workaround (`_mergeWithLocalReceives`, `_localReceives`,
load/save helpers, `dart:async` and `fixnum` imports) has been deleted from
`MpcService`. Pending: rebuild EIF + tofu apply with the new PCR0 to ship
the server change.

### Symptoms

Incoming Ark transactions never appear in the user's Ark transaction list.
`ListArkTransactions` returns server-recorded `send` / `board` / `settle`
entries fine, but `receive` entries are missing. `ListVtxos` correctly
includes the received VTXOs — only the *history* is lossy.

### Root cause

In
[`cosigner-runtime/src/cosigner/handlers/vtxo_stream.rs::apply_stream_update`](cosigner-runtime/src/cosigner/handlers/vtxo_stream.rs#L109-L120),
the receive-history append is gated:

```rust
let has_active_session = state.settle_session.is_some()
    || state.delegate_session.is_some()
    || state.send_session.is_some();
...
if !has_active_session {
    state.ark_tx_history.push(ArkTxEntry { tx_type: "receive".into(), ... });
}
...
if !has_active_session {
    save_user_ark_history(...);
}
```

The gate's intent is to avoid double-counting self-originated VTXOs — when
you settle or send, the resulting VTXO arrives via the stream and you've
already logged a `settle` / `send` entry. But the gate is too coarse:

1. It blocks **third-party receives** that arrive while *any* session is in
   flight, including a stale one. Combined with TODO #1, every incoming
   receive after a failed boarding attempt is silently dropped until the
   actor is restarted and the stale `settle_session` clears.
2. The gate is **redundant insurance** — the dedup at
   [vtxo_stream.rs:83-89](cosigner-runtime/src/cosigner/handlers/vtxo_stream.rs#L83-L89)
   already prevents double-counting. The `settle` and `send_vtxo` handlers
   push their resulting VTXO into `state.vtxos` synchronously *before* the
   stream notification arrives at the actor (single-threaded processing
   guarantees the ordering). When the stream notification then runs through
   `apply_stream_update`, the `(txid, vout)` already-present check `continue`s
   past the entire block, including the history append.

### Plan

Drop the `has_active_session` gate. Always append a `"receive"` entry for
genuinely-new VTXOs. The dedup at lines 83-89 still suppresses self-originated
ones.

```rust
// REMOVE:
let has_active_session = state.settle_session.is_some()
    || state.delegate_session.is_some()
    || state.send_session.is_some();

// In the loop, replace:
if !has_active_session {
    state.ark_tx_history.push(ArkTxEntry { ... });
}
// with:
state.ark_tx_history.push(ArkTxEntry { ... });

// And replace the conditional save with an unconditional one:
save_user_ark_history(shared.persistence.as_ref(), user_id_hex, &state.ark_tx_history);
```

### Files to touch

- [cosigner-runtime/src/cosigner/handlers/vtxo_stream.rs](cosigner-runtime/src/cosigner/handlers/vtxo_stream.rs)
  — drop the gate (~10 lines deleted, 0 added).

### Verification

Three cases that must pass after the change:

| Scenario | Expected behaviour |
|---|---|
| Third party sends a VTXO, no session in flight | `"receive"` entry appears in `ark_tx_history` |
| Third party sends a VTXO, user has any active session | `"receive"` entry still appears |
| User sends or settles, change/result VTXO arrives via stream | NOT double-logged — the dedup at lines 83-89 catches it |
| User boards | `"board"` entry from `ark_send::settle::Settled` path; no spurious `"receive"` for the same VTXO |

The Dart-side workaround in
[`app/lib/services/mpc_service.dart::_mergeWithLocalReceives`](app/lib/services/mpc_service.dart)
(synthesises receive entries client-side from `listVtxos()` minus
`listArkTransactions()`) can be **removed** once this lands and a release
ships, but is harmless to keep — its synthesis is a no-op when the server
already includes the entry (txid match against `knownTxids`).

### Cost

~10 line deletion. No proto change, no migration. The most surgical fix in
this entire file.

---

## 3. Plan A — Server is the source of truth for `bitcoin_network`

**Status:** ✅ fixed.

* Server: `rpc GetServerInfo` added to
  [protocol/protos/mpc_wallet.proto](protocol/protos/mpc_wallet.proto);
  unauthenticated handler in
  [cosigner-runtime/src/rest_api.rs](cosigner-runtime/src/rest_api.rs)
  serves `bitcoin_network` from `Config`.
  `AppState` widened to a struct with `FromRef` impls so existing handlers
  keep extracting `Arc<CosignerRegistry>` unchanged.
* Client: `getServerInfo()` added through the api stack
  (`WalletApi` / `RestWalletApi` / `GrpcWalletApi` / `AttestedWalletApi` /
  `MpcClient`); `RestWalletApi` gained a `_get` helper for the new
  unauthenticated GET endpoint.
* MpcService: dropped `_network` field, the `'network'` Hive read/write,
  the `network` getter, the `setNetwork` setter. `setHost` is single-arg
  again. The three wallet-construction sites in `doDkg` / `doRestore` /
  `restoreSession` now call `_client!.getServerInfo()` and pass
  `serverInfo.bitcoinNetwork` to `MpcBitcoinWallet` as a local variable.
* UI: dropdown removed from `server_connect_screen.dart`,
  `network_settings_screen.dart` deleted, `/settings/network` route gone,
  globe `IconButton` removed from `home_screen.dart`.

The Hive `'network'` key from older installs is left as harmless leftover
data (init no longer reads it).

### Context

The Dart app currently keeps a `_network` field in `MpcService`, persisted in
Hive under `'network'`, and uses it to pick the bech32 HRP when rendering the
wallet's plain receive address. There are *five* sources of "what network are
we on" across the stack:

1. User intent (what they typed in onboarding)
2. Cosigner-runtime config (`BITCOIN_NETWORK` env var,
   [config.rs:15](cosigner-runtime/src/config.rs#L15))
3. ASP (`arkInfo.network` from `getArkInfo`)
4. Electrum endpoint (implied)
5. App state (`_network` field, Hive key)

The plain receive address depends only on (5). They can drift, and they have:
the symptom is users seeing `bcrt1…` (regtest) addresses on a deployment
that's actually mutinynet.

The current stopgap is the network dropdown added to `server_connect_screen`
plus a settings entry under `/settings/network` to change it post-onboarding.
That works but doesn't fix the structural problem — the user has to know what
network to pick, and there's nothing preventing them from picking wrong.

### Plan

Make the cosigner-runtime the single source of truth. The server already
knows its network (env var). Expose it via a lightweight RPC; the client
fetches it once per session and passes it through to the wallet constructor.

#### Step 1 — Proto

Add to [protocol/protos/mpc_wallet.proto](protocol/protos/mpc_wallet.proto):

```proto
service MPCWallet {
  // ... existing rpcs ...
  rpc GetServerInfo (GetServerInfoRequest) returns (GetServerInfoResponse);
}

message GetServerInfoRequest {}

message GetServerInfoResponse {
  string bitcoin_network = 1;  // e.g. "mutinynet", "signet", "testnet", "regtest", "mainnet"
  string electrum_url = 2;     // optional, exposed for client-side sanity checks
}
```

This RPC is **unauthenticated** — it returns deployment config that's not
user-specific. No `signature` / `timestamp_ms` fields.

#### Step 2 — Cosigner-runtime handler

Implement in `cosigner-runtime/src/cosigner/handlers/` (probably a new
`server.rs` or fold into an existing `info.rs`). Stateless — reads from the
process-wide `Config`.

Wire into `actor.rs` dispatch and `rest_api.rs` REST route:
`GET /api/server-info` (no `/u/<user_id>/` prefix since it's not user-scoped).

Regenerate stubs: `make proto`.

#### Step 3 — Dart client

Add `getServerInfo()` to `MpcClient` in
[app-core/lib/client.dart](app-core/lib/client.dart). Returns a typed
`ServerInfo` struct.

#### Step 4 — Drop the duplicated state in MpcService

Delete from [app/lib/services/mpc_service.dart](app/lib/services/mpc_service.dart):

- `String _network = 'regtest';` field
- The Hive read at line 227 (`_identityBox!.get('network', ...)`)
- The Hive write at line 292 in `setHost`
- The `network` getter and `setNetwork` setter (currently used by the settings
  screen — those need rewiring too)
- The pre-existing inference block (already removed in the most recent change)

#### Step 5 — Wire `getServerInfo` into wallet construction

In `restoreSession`, `doDkg`, `doRestore`: after `_createMpcClient` succeeds,
call `_client.getServerInfo()`. Pass `serverInfo.bitcoinNetwork` to
`MpcBitcoinWallet` as a local variable, not a persisted field:

```dart
_client = await _createMpcClient(...);
final serverInfo = await _client!.getServerInfo();
_wallet = MpcBitcoinWallet(_client!,
    networkName: serverInfo.bitcoinNetwork,
    storageId: storageId);
```

#### Step 6 — UI cleanup

- Remove the network dropdown from
  [server_connect_screen.dart](app/lib/screens/onboarding/server_connect_screen.dart).
- Delete
  [network_settings_screen.dart](app/lib/screens/settings/network_settings_screen.dart)
  and its route in `main.dart`.
- Remove the globe `IconButton` from
  [home_screen.dart](app/lib/screens/home_screen.dart).
- `setHost` becomes single-arg again: `setHost(String host)`.

### Why this is the right shape

- The wallet's `networkName` is purely a render-time choice (HRP). The
  underlying P2TR pubkey is network-agnostic.
- The server already knows the network — every other "source of truth" is a
  copy that drifts.
- One RPC roundtrip per session in exchange for eliminating an entire class
  of "stale Hive value" bugs.
- Eliminates "user picked wrong network" footgun — the user doesn't pick;
  the server tells them.

### Cost

Roughly:
- ~40 lines Rust (proto handler + REST route + actor command/dispatch)
- ~15 lines Dart (`getServerInfo` wrapper + 3 call sites in MpcService)
- ~−80 lines Dart deleted (settings screen, dropdown, Hive plumbing)

Net deletion. Five sources of truth collapse to one.

### Verification

- Fresh install on a mutinynet deployment shows `tb1…` receive address
  immediately, no user input needed.
- Reinstall the app: same address renders correctly without re-picking a
  network.
- Switching the cosigner-runtime's `BITCOIN_NETWORK` env var (in tofu) and
  redeploying changes the rendering on next session — no client-side action
  required.
- e2e tests pass.

### Caveats

- The `getServerInfo` RPC must be reachable for the receive screen to render.
  Already a soft requirement (sync needs the server too). But if the server
  is down at app startup, the receive address won't render. Acceptable —
  matches Ark address behaviour today.
- Mutinynet vs signet HRP collision: both use `tb` HRP, so for mutinynet
  users the visible address is identical to a "real" signet address. Server
  reporting `bitcoin_network = "mutinynet"` is a label, not a different
  encoding. `parseBitcoinNetwork` already maps both to `BitcoinNetwork.signet`
  (correct).

---

## 4. `device_tokens` written to sled but never loaded back

### Symptoms

After the cosigner-runtime restarts, FCM pushes for newly-received VTXOs
silently no-op for any user who hasn't reopened their app since the restart.
The app does call `registerDeviceToken` on every launch, so users who
*are* opening the app re-register fine — but a user whose VTXO arrives
*while their app is closed* and the cosigner happens to have restarted will
never get a wake push.

### Root cause

[`device_token.rs::register_device_token`](cosigner-runtime/src/cosigner/handlers/device_token.rs)
writes through `save_user_device_tokens` to sled at
[`helpers.rs::save_user_device_tokens`](cosigner-runtime/src/cosigner/handlers/helpers.rs),
but no code path reads it back. `CosignerState::new(user_id_hex)` initializes
`device_tokens: Vec::new()` and only `register_device_token` ever mutates it.

When an actor (re)spawns post-restart, its `device_tokens` is empty until
the client makes a fresh `register_device_token` call. The `vtxo_stream`'s
push fan-out walks the empty vec and skips silently.

(This is the same "written but not read" pattern as `vtxo_store` and
`ark_tx_history`. Those happen to work — `vtxo_store` because the stream
reconstructs it on subscription, and `ark_tx_history` is acknowledged as a
pre-existing gap. `device_tokens` has no such reconstruction.)

### Plan

Load `device_tokens` from sled when the actor spawns. Two surgical edits:

1. Add `load_user_device_tokens` in
   [helpers.rs](cosigner-runtime/src/cosigner/handlers/helpers.rs) mirroring
   `save_user_device_tokens` — `persistence.get("device_tokens", user_id_hex)`
   then `serde_json::from_str::<Vec<DeviceToken>>`.

2. Call it from `CosignerRegistry::get_or_spawn` after `CosignerState::new`,
   before `tokio::spawn(run_actor(...))`. Best-effort: log a warning on
   parse failure and continue with an empty vec rather than failing the
   spawn.

### Files to touch

- [cosigner-runtime/src/cosigner/handlers/helpers.rs](cosigner-runtime/src/cosigner/handlers/helpers.rs)
  — add `load_user_device_tokens` (~10 lines).
- [cosigner-runtime/src/cosigner/registry.rs](cosigner-runtime/src/cosigner/registry.rs)
  — populate `state.device_tokens` before spawning the actor (~5 lines).

### Verification

- Register a token, restart the cosigner-runtime, send a VTXO to the user
  *without* the client re-opening the app first. Cosigner log should show
  the FCM push fire to the persisted token.
- e2e test: register a fake token via REST, kill+restart the cosigner-runtime
  process, call `listVtxos` (which respawns the actor), then assert the
  cosigner's debug-level log mentions the token in `push_vtxo_received`.

### Cost

~15 lines Rust. No proto change, no migration (existing sled rows are
already valid `Vec<DeviceToken>` JSON).

---

## 5. Cross-isolate Hive contention (push background handler)

### Context

[`push_service.dart::_runBackgroundDelegate`](app/lib/services/push_service.dart)
opens Hive boxes in the FCM background isolate to restore the
`MpcClient` and call `settleDelegate(storeOnly: true)`. If the foreground
app is also running, it holds the same boxes open through `MpcService`.

Hive supports multi-isolate access provided each isolate calls
`Hive.init(<same path>)`, and the background handler does that. Conflicts
should be rare because:

- The background handler is short-lived (~3-8s)
- The actor on the cosigner side serializes commands per-user, so
  concurrent settleDelegate calls queue up at the actor mailbox
- The stale-session-recovery guard in
  [ark_send.rs::settle](cosigner-runtime/src/cosigner/handlers/ark_send.rs)
  (TODO #1's fix) handles "two Phase-1 calls in flight" by dropping the
  stale session and rebuilding fresh

### Open monitoring

Watch for any of the following symptoms post-deploy:

- `HiveError`s in `_runBackgroundDelegate` log output
- Foreground app's `_normalPolicy` returning null unexpectedly after a
  push arrives (would suggest a Hive write from the background isolate
  corrupted the foreground's view)
- Two `settleDelegate` Phase 1 calls landing back-to-back in cosigner
  logs (visible as "dropping stale session on poll-without-sigs")

### If symptoms surface

Switch to a snapshot pattern: foreground writes a stable JSON snapshot
of the auth/policy/identity material to a separate file every time it
changes; background reads only that snapshot. No shared Hive boxes
across isolates.

### Why not preemptively switch

The snapshot file path adds operational complexity, and the multi-isolate
Hive path is well-trodden in Flutter ecosystem (firebase_messaging docs
explicitly support it). Monitor first, refactor only if needed.

---

## 6. Background handler: attested-mode for production deployment

### Context

`_handleBackgroundMessage` currently uses `MpcClient.rest()` only — no
attestation. Sufficient for the development + test stack where the
cosigner is `http://10.0.2.2:7074`, but production deployment routes
through `MpcClient.attested(...)` for enclave PCR0 verification.

### Status of the policy-bypass concern (the original second half of #6)

**Resolved**: settling never applies a spending policy.

- `MpcClient.settle()` and `MpcClient.settleDelegate({storeOnly})` no
  longer accept `pin`/`policyId` — those params were a footgun that
  could produce a FROST aggregation mismatch.
- Server-side
  [sign.rs::sign_step1](cosigner-runtime/src/cosigner/handlers/sign.rs)
  forces `selected_policy_id = None` whenever the actor has an active
  `settle_session` or `delegate_session`. This is the source-of-truth
  enforcement — even if a future client tried to send pin/policyId via
  some other call, the settle context wins.
- `ark_board_screen` no longer shows a PIN prompt before boarding.
- `app_test.dart` updated to drop boarding-PIN expectations.

Rationale: spending policies gate fund egress (sends + redeems), not
"promote my UTXO into a fresh VTXO" or "re-delegate so it doesn't
expire." Auto-settle happens in the background isolate / cosigner tick
task where no user PIN is available; requiring policy authorization
would break the whole class of unattended settlements.

### Remaining plan (attested mode in background)

Detect from persisted state whether the foreground was running attested;
if so, construct `MpcClient.attested(...)` instead in
`_runBackgroundDelegate`. `AttestedWalletApi.create()` is FFI-heavy but
doesn't need a UI thread.

### Verification

Run the existing background-push UI test
(`app/integration_test/ark_background_push_test.dart`) against an
attested deployment after the attested-mode flag lands.

### Cost

~20-30 LoC Dart. Pure deployment-mode wiring.
