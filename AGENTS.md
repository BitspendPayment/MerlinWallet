# Repository Guidelines

## Project Structure & Module Organization
- `app/` Flutter app (`app/lib/screens`, `app/lib/services/mpc_service.dart`, `app/lib/passkey/`).
- `app-core/` Dart wallet core: `client.dart` (`MpcClient`), `sessions/` (one driver per ceremony
  stream), `passkey/` (key derivation, share reconstruction, operation secrets), `cosigner/`
  (the gRPC connection), `enclave/` (attested gate), `persistence/` (public state only).
- `cosigner/` the Rust cosigner, a `wasm32-wasip2` component served by enclave-runtime — one
  instance per tenant, no listener of its own. `cosigner/src/session.rs` routes; `handlers/` hold
  the ceremonies; the seal (`store.rs`) is the only durable state.
- `protocol/` shared Dart package; `protocol/protos/*.proto` are the source of truth. Generated Dart
  (`protocol/lib/src/generated`) is **not checked in** — run `make proto`.
- `crates/threshold` FROST/DKG cryptography; `crates/ark` Ark protocol; `crates/enclave-client`
  attestation; `ffi/` the merged native library the Dart side loads (`make ffi-build`).
- `e2e/` the enclave end-to-end suite and its harness; `cli/` a Dart REPL against a dev enclave;
  `examples/card-escrow` a service paired into an escrow; `infrastructure/` the MutinyNet QEMU
  deployment; `scripts/` what the Makefile calls.

## Build, Test, and Development Commands
- `make proto` regenerate Dart stubs (needs `protoc` and `dart pub global activate protoc_plugin`);
  `make proto-check` diffs them.
- `make ffi-build` build `ffi/target/release/libmpcwallet_ffi.so`; `app-core` tests need it.
- `cd cosigner && cargo test` — the cosigner's tests run on the host. `make cosigner-wasm` builds
  the component (needs wasi-sdk); `make cosigner-check` also checks WIT drift against
  `ENCLAVE_RUNTIME` (the bundle in `.enclave/` once fetched, else `~/enclave-runtime`).
- `cd app-core && dart test`; `cd app && flutter analyze --no-fatal-infos && flutter test`;
  `dart analyze` in `protocol/`, `cli/`, `e2e/`. Flutter may be off PATH (`~/dev/flutter/bin`).
- `make up-enclave` boots a dev enclave (docker regtest + arkd + QEMU from the `~/enclave-runtime`
  checkout); `make e2e-enclave` runs the suite against one (or attaches with `ENCLAVE_RUN=`); `make cli`.
- `make enclave-bundle` fetches the prebuilt dev enclave pinned in `enclave-bundle.lock` into
  `.enclave/`, which then is the default `ENCLAVE_RUNTIME` for the e2e and the WIT check. The image
  options the suite needs live in `e2e/lib/e2e_profile.dart`; changing them means a new bundle
  (`make enclave-bundle-args` → the runtime's "Publish a dev enclave" workflow → the lock).
- CI is `.github/workflows/ci.yml`; its `enclave-e2e` job runs the suite from the pinned bundle on a
  hosted runner. Run it locally too before merging a change to a ceremony.

## Coding Style & Naming Conventions
- Dart: `UpperCamelCase` types, `lowerCamelCase` members, `snake_case` files. Rust: rustfmt defaults
  for new code. Both trees are hand-wrapped at 100 columns and are **not** `dart format` /
  `cargo fmt` clean at baseline — do not reformat files wholesale; match the surrounding style.
- Lints: `flutter_lints` in `app/`, `lints` in the Dart packages, clippy on the crates. Keep
  `dart analyze` clean and add no new clippy warnings.
- Comments explain why, at the depth the surrounding code does.

## Testing Guidelines
- Tests live under `*/test` (Dart, `_test.dart`) and `*/tests` (Rust). Crypto and core logic get
  unit tests; `app-core/test/operation_lifecycle_test.dart` drives `MpcClient` against an
  in-process cosigner; `cosigner/tests/*_test.rs` drive handlers and, through
  `tests/common::wire`, the router over real frames.
- A fix to a security-relevant path comes with a test that fails without it (mutation-check it).
- `make e2e-enclave` needs docker, KVM, vsock and the bundle (`make enclave-bundle`) or a runtime
  checkout; ~7 minutes warm.

## Security Invariants (see README "No key at rest", SECURITY_FINDINGS RC-3/RC-4)
- The device persists no private-key material. `WalletStore.saveClientState` refuses
  `secretShare`/`onchainSecret`/`shareBlinded`/`signingSecret` at any depth; keep it that way.
- Secrets live in a `WalletOperation`, one serialized operation at a time, disposed in a `finally`,
  and every wait on a party other than the cosigner goes through `CancelSignal.guard`. A new
  ceremony stream must be opened through `CosignerConnection._track`.
- The cosigner returns its dealt halves only through `dealt_share_for`, never its own share, and
  a change that must be durable goes through `try_seal()` before it is acted on.

## Commit & Pull Request Guidelines
- Conventional Commit prefixes (`feat:`, `fix:`, `refactor:`, `build:`), a short imperative summary,
  and a body that says what changed and why — the history is written that way.
- PRs: what was run, what was not (say so), and screenshots for Flutter UI changes.
