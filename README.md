# Merlin Wallet

A **2-of-2 FROST threshold Bitcoin wallet**. The full private key never exists on any single device: two independent identities — your phone and a remote cosigning service running inside an AWS Nitro Enclave — jointly control your funds. Neither can move funds alone.

The wallet spends across two value layers:

- **Ark (off-chain VTXOs).** The primary path. The FROST group key (phone + cosigner, 2-of-2) owns the VTXOs; boarding, sending, and settling go through an **Ark Service Provider (arkd)**.
- **On-chain Bitcoin.** A single key the wallet controls **alone** (the DKG dealer secret), for direct on-chain send/receive. It needs neither the cosigner nor the ASP, so it keeps working when they're unavailable — the app calls this **offline mode**.

Both parties are required to produce a valid Taproot (BIP-340) Schnorr signature on the Ark path. The server alone cannot move funds; the phone alone cannot move Ark funds.

## Architecture

```
   +-----------------------+         +-----------------------+
   |   Cosigner Runtime    |         |   Ark Service         |
   |   AWS Nitro Enclave   |         |   Provider (arkd)     |
   |   Rust · native FROST |         |   VTXO batching /     |
   |   Identity 2/2        |         |   settlement          |
   +-----------+-----------+         +-----------+-----------+
               |                                 |
        attested HTTPS                     Ark rounds
               |                                 |
   +-----------+---------------------------------+-----------+
   |   Android Phone — Flutter app — Identity 1/2            |
   |   in-app FROST signing (FFI) · passkey-gated share      |
   |   on-chain single-key path (wallet-alone / offline)     |
   +--------------------------------------------------------+
```

| Identity | Held by | Role |
|---|---|---|
| **Wallet share** | Phone (local, passkey-gated FROST share) | One half of the 2-of-2; signs in-app |
| **Cosigner share** | Cosigner runtime in the enclave | The other half; co-signs, never sees the full key |

## The Cosigner Runtime

The remote cosigning service is built on two isolation boundaries, each addressing a different class of threat.

```
┌─ AWS Nitro Enclave ──────────────────────────────────────────┐  hardware-attested VM
│  PCR0 measurement · KMS secrets PCR0-locked                  │  client trusts: "the right binary booted"
│                                                              │
│  ┌─ cosigner-runtime (Rust)   native actor per user ─────┐   │  concurrency + fault isolation
│  │  per-user mailbox · serial commands · keys in-process  │   │  trust: "no cross-user state / races"
│  │  FROST · DKG · Schnorr run natively here               │   │
│  └────────────────────────────────────────────────────────┘   │
└──────────────────────────────────────────────────────────────┘
```

### Outer layer: AWS Nitro Enclave

The runtime executes inside an AWS Nitro Enclave — an isolated VM with no persistent storage, no interactive shell, and no network except a vsock to the parent EC2 instance. The host's disk is invisible; the host operator can't read enclave RAM.

What the client gets in return: an **attestation document** signed by AWS, binding a `PCR0` measurement (the SHA-384 hash of the booted EIF image) to the enclave's attestation key. The client verifies `PCR0` matches a known build before trusting any response, and binds the enclave's response-signing key to the attestation (`appKeyHash`). Connecting to a different binary, or to the host itself, fails attestation — the client refuses to send DKG packets.

KMS-encrypted deployment secrets are decrypted inside the enclave via a **PCR0-locked KMS policy**: only an enclave measuring this exact `PCR0` can call `kms:Decrypt`. A modified runtime can't load secrets even with the same IAM role.

The enclave plumbing — supervisor, attestation server, vsock proxies — is upstream from [introspector-enclave](https://github.com/ArkLabsHQ/introspector-enclave). The cosigner-runtime is the userspace app that boots inside it.

### Inner layer: Per-user native actor

Inside the runtime, every user (keyed by FROST verifying-share / group key) gets a dedicated tokio actor task that owns its keys and state:

```rust
// cosigner-runtime/src/cosigner/registry.rs
const MAILBOX_CAPACITY: usize = 256;

let (tx, rx) = mpsc::channel::<CosignerCommand>(MAILBOX_CAPACITY);
tokio::spawn(run_cosigner(rx, shared, registry));
```

Properties this gives you:

- **No shared mutable state between users.** Each actor owns its `CosignerState` (key package, Ark secret, VTXOs, pending sessions) outright.
- **Serial command processing per user.** The actor pulls commands one at a time; a DKG step finishes before the next sign-step starts, removing a class of same-user races.
- **Fault isolation.** Handler work runs inside `spawn_blocking`; a panic on attacker input is caught (`JoinError::is_panic`), the request errors, and the actor is reseated from its snapshot rather than crashing the runtime.
- **Slow user can't starve others.** A user holding a settle session blocks only their own mailbox.
- **Constant-time routing.** [`CosignerRegistry`](cosigner-runtime/src/cosigner/registry.rs) is a `DashMap` from group key → mailbox handle; a request just looks up the handle and `send().await`. Idle actors are cheap — an idle actor is memory, not a thread.

## Other Components

```
MPCWallet/
├── app/                  Flutter mobile app (Android)
├── app-core/             Dart client library (DKG, signing, FFI wrapper, attested transport)
├── cosigner-runtime/     Enclave runtime — native per-user actors (described above)
├── crates/
│   ├── ark/              Ark protocol: boarding, VTXO send/settle, delegate/auto-settle, checkpoints
│   ├── threshold/        FROST + DKG core (no_std, secp256k1)
│   └── enclave-client/   Nitro attestation verification (COSE/X.509/PCR0) + signed-response client
├── ffi/                  Merged C-ABI shared library for Dart FFI (ark + threshold + enclave)
├── protocol/             gRPC stubs and proto definitions
├── infrastructure/       OpenTofu modules for enclave deployment (KMS, EC2, S3, SSM)
├── e2e/                  End-to-end integration tests + local signer-server
└── scripts/              Utilities (bitcoin.sh, arkd_init.sh, …)
```

### Flutter app ([app/](app/))

Android wallet UI built with Provider + GoRouter. Onboarding guides server connection, passkey setup, and DKG. Supports on-chain + Ark (VTXO) send/receive, an **offline mode** that falls back to on-chain-only when the ASP is unavailable, and passkey-gated signing.

### Dart client ([app-core/](app-core/))

High-level Dart API that orchestrates the full protocol: drives DKG, FROST signing, key refresh, Ark boarding/send/settle, and the on-chain single-key path. Talks to the cosigner over **attested transport** (verifies the enclave's `PCR0` and response signatures), and handles Taproot address derivation, UTXO/VTXO tracking, and PSBT construction.

### Threshold library ([crates/threshold/](crates/threshold/))

`#![no_std]` Rust implementation of FROST over secp256k1: the full 3-round DKG with proof-of-knowledge, Pedersen VSS, single-use nonce commitments, signature-share computation, Lagrange interpolation, Taproot key tweaking, and key refresh. Built for two targets: **native Rust** (the cosigner runtime) and **Dart FFI** (the phone, via `ffi/`).

## Build & Run

### Prerequisites

- Dart ≥ 3.3, Flutter ≥ 3.4
- Rust (stable toolchain)
- Docker + Docker Compose

```bash
rustup target add aarch64-linux-android          # FFI for Android arm64
```

### Local development (regtest)

```bash
make regtest-up        # bitcoind + electrs in Docker
make bitcoin-init      # mine blocks
make e2e               # Ark E2E: builds ffi + cosigner-runtime, starts regtest + arkd, runs the Dart harness
```

The local cosigner runtime runs as a plain Rust binary (no enclave, no attestation) — the per-user native-actor isolation still applies. Useful for fast iteration.

### Cloud deployment (mutinynet)

```bash
cd infrastructure/mutinynet-qemu/tofu && tofu init && tofu plan -out plan.out && tofu apply plan.out
make mutinynet-deploy  # build, pack, ship over S3, install over SSM
make mutinynet-smoke   # attestation, two wallets, DKG — and funds, with MUTINYNET_FUNDER_KEY
```

The cosigner runs in an **emulated** Nitro enclave (QEMU) on one EC2 instance at `mutiny.vtxos.network`, with a Let's Encrypt certificate and arkade's MutinyNet ASP. The app pins the image, the guest and the emulator's per-boot trust root from a manifest the host republishes on every boot. The step-by-step runbook is [infrastructure/mutinynet-qemu/README.md](infrastructure/mutinynet-qemu/README.md). Production is real Nitro, deployed with enclave-runtime's `deploy/tofu`.

### Mobile app

```bash
adb pair <ip>:<port>           # pair (wireless debugging)
adb connect <ip>:<port>
make adb-reverse               # forward server ports to the phone
cd app && flutter run
```

## Testing

```bash
make threshold-test               # threshold library unit tests
make ffi-test                     # merged FFI tests
make e2e                          # Ark E2E (regtest + arkd + cosigner runtime + Dart harness)
make crypto-bench                 # cryptography benchmarks (Criterion)
make stress-test                  # multi-user E2E stress test
```

## Security model summary

- **The full private key never exists on any single device.** The Ark owner key is a 2-of-2 FROST split between the phone and the cosigner.
- **The cosigner cannot unilaterally sign.** It always needs cooperation from the phone.
- **The phone's FROST share is passkey-gated.** It is stored blinded and reconstructed transiently, only for a sign, from a passkey PRF gesture.
- **The cosigner runs in a Nitro Enclave with attested boot.** Clients refuse to send DKG packets to a runtime whose `PCR0` doesn't match a known build, and bind its response-signing key to the attestation.
- **KMS secrets are PCR0-locked.** A modified runtime can't decrypt them even with the same IAM role.
- **FROST keys are held by an isolated per-user native actor** — no shared mutable state, serial per-user processing, panic-recovered from a sealed snapshot.
- **MPC requests are authenticated** with Schnorr signatures (or a passkey-minted session token) over timestamped messages, within a replay window.
- **The on-chain single-key path is wallet-alone.** It works without the cosigner or ASP (offline mode); it is not part of the 2-of-2.

The same 2-of-2 that stops the cosigner signing alone also stops *you* signing alone, which is
why Ark balances depend on the cosigner being reachable. See
[Trust assumptions & failure modes](#trust-assumptions--failure-modes) and
[Emergency exit](#emergency-exit) before relying on this with real money.

## Trust assumptions & failure modes

The security summary above is what holds when everything works. This is what breaks, and who
you have to trust for it not to.

### The one that matters: the Ark owner key is 2-of-2

Every VTXO and every boarding output is owned by the **FROST group key**, not by the phone's own
key ([`bitcoin.dart`](app-core/lib/bitcoin.dart#L191-L194) — *"the FROST group key stays the Ark
owner key (boarding + VTXO)"*). The stock Ark taptree gives a VTXO two spend paths:

```
forfeit leaf:  <asp_pk> OP_CHECKSIGVERIFY <owner_pk> OP_CHECKSIG
exit leaf:     <delay>  OP_CSV OP_DROP    <owner_pk> OP_CHECKSIG
```

(`Vtxo::new_default` → `multisig_script` + `csv_sig_script`, `ark-core/src/{vtxo,script}.rs`.)

Both name `owner_pk`, and here `owner_pk` is the group key. **The exit leaf's timelock controls
*when* you may leave, not *who* may leave.** So if the cosigner is permanently gone, the phone
holds one of two required shares and cannot produce a group-key signature at all — the unilateral
exit path that normally protects Ark users does not protect you. Ark funds and in-flight boarding
outputs are frozen, permanently. Waiting does not fix it.

**What survives regardless:** the on-chain single-key layer. Its key is the phone's own DKG dealer
secret, spending a plain BIP-341 key-path taproot address, and the cosigner is never involved.
Offline mode already routes there when Ark is unreachable. On-chain balance is genuinely
self-custodial today; Ark balance is not.

### AWS

The cosigner runs on AWS. In production it is a Nitro Enclave whose KMS secrets are PCR0-locked,
which is what stops *us* from extracting your share — and is also why an account termination,
a destroyed KMS key, or a lost data volume is unrecoverable **by anyone, including us**. The
sealing that makes the operator untrusted for confidentiality makes AWS trusted for availability.
That is a deliberate trade, and it is the whole reason the section below exists.

The mutinynet deployment ([infrastructure/mutinynet-qemu/](infrastructure/mutinynet-qemu/)) runs
the cosigner in an *emulated* enclave. The app attests it like any other, but on an emulator the
host's operator can read every tenant's data and sign attestation documents, so it proves the image
and the guest, not the hardware. It is signet-only for that reason.

### The ASP

Liveness for anything Ark: sends, settlements, receiving. If the ASP is down you fall back to
on-chain. If the ASP is *malicious* it cannot steal — the forfeit leaf needs your signature too —
but it can refuse service, and refusing service is what makes unilateral exit necessary, which
loops back to the 2-of-2 problem above. We depend on a third-party ASP
(`https://mutinynet.arkade.sh` today); we do not run it.

### What Ark's privacy does *not* give you

Ark keeps VTXOs off-chain. That is a scalability property, and it is routinely mistaken for a
privacy one. It is not CoinJoin and it is not a mixnet:

- **The ASP sees everything** — every VTXO, every amount, and the sender/recipient pairing inside
  every round. It is a full observer of your transaction graph, by construction.
- **So does our cosigner.** It persists `vtxo_store`, `ark_tx_history`, `ark_script_to_user`,
  `boarding_watches`, and your request-to-pay contacts. Enclave sealing keeps that from the
  *operator*; it does not make the data not exist, and a future compelled-access or
  implementation-flaw scenario is about that data.
- **Exiting is public and linking.** A unilateral exit publishes your branch of the VTXO tree
  on-chain, tying those outputs together for anyone watching.
- **Boarding and exit are on-chain events** with ordinary on-chain traceability.

Treat Ark here as cheap, fast custody-minimised payments — not as anonymity.

## Emergency exit

**Status: the fallback is built. The recovery leaf is still designed, not implemented.**

The wallet now holds **pre-signed exit transactions**, one per VTXO. At every seal — the end of
each send, settle and renewal — the cosigner co-signs a spend of each VTXO through its *existing*
exit leaf, paying an address in a wallet this app does not control, and the phone keeps it. They
are on the Exit tab, and can be copied out as raw transactions. Nothing else is needed to broadcast
them: no cosigner, no ASP, no key this phone does not already have.

What it costs is per-VTXO bookkeeping and reissue on every operation, both of which ride the seal
that already runs. What it does not cover is a VTXO created while nobody was here: a renewal the
cosigner performs on its own makes a new output, and only its owner can sign its exit, so those
funds have no exit until the wallet is next opened and seals again. The Exit tab says which funds
are covered and which are not.

An exit pays no fee. It carries a P2A anchor instead, so whoever broadcasts it attaches a child
that pays for both — a fee fixed at signing time would be a guess about a fee market years away,
and a wallet whose cosigner is gone cannot re-sign. Publishing the transactions that put the money
off-chain in the first place — the batch tree branch, and the checkpoint and Ark transactions for
funds not yet settled — is not in the app yet; the exit is the last hop, and the one that cannot be
obtained later.

Implementation: `crates/ark/src/exit.rs` (both sides build it), `ffi/src/ark/exit.rs` (and the
wallet's check that what it is asked to sign is its own), `cosigner/src/handlers/delegate.rs`,
`app-core/lib/sessions/exit_plan.dart`, `app/lib/screens/exit/exit_screen.dart`.

### The better answer, still to come

A pre-signed exit is a snapshot; a **third taptree leaf spendable by a recovery key the phone
controls alone**, after a long CSV delay, would need no snapshots at all:

```
forfeit  leaf:  <asp_pk>       OP_CHECKSIGVERIFY <group_pk>    OP_CHECKSIG   # cooperative, today
exit     leaf:  <exit_delay>   OP_CSV OP_DROP    <group_pk>    OP_CHECKSIG   # today (still 2-of-2)
recovery leaf:  <recov_delay>  OP_CSV OP_DROP    <recovery_pk> OP_CHECKSIG   # new
```

Three things make this cheap rather than speculative, and all three already exist in this
repository:

**The recovery key already exists and needs no new custody.** `recovery_pk` is the wallet's
on-chain single key — the DKG dealer secret, which the phone already holds and already backs up
because it secures the on-chain balance ([`client.dart:93-98`](app-core/lib/client.dart#L93-L98)).
No new secret, no new backup surface, no extra thing to lose.

**The cosigner already knows it.** That key's public point *is* the DKG `walletVk`, which the
wallet sends during onboarding and the cosigner already persists as `wallet_vk`
([`state.rs:192`](cosigner-runtime/src/cosigner/state.rs#L192)). Both sides can derive the same
three-leaf address today with no new protocol message.

**The ASP does not need to know or approve.** An Ark address is just `(server_key, vtxo_tap_key)`;
the taptree is committed inside the output key, and arkd mints and co-signs against the
cooperative path without inspecting the rest. That is not a hope — this project already ships
contract eVTXOs built exactly this way. [`evtxo_tree`](crates/ark/src/lib.rs#L181-L193) takes the
cooperative key and the exit-leaf key as **separate parameters**:

```rust
let cooperative = TapLeaf::new(contract_cooperative_script(commit, server_pk, evtxo_pk));
let exit        = TapLeaf::new(evtxo_exit_script(exit_delay, owner_pk));   // different key
```

`ContractPolicy.owner_pk` is literally documented as "user-supplied exit-leaf owner x-only key",
and the whole path is e2e-verified spending through arkd on regtest. The recovery leaf is the same
construction with the recovery key in that slot.

The gap is narrow: plain wallet VTXOs still go through `Vtxo::new_default`, which reuses one
`owner` for both leaves. eVTXOs got the better construction; ordinary VTXOs did not.

The honest costs:

- **A stolen phone gets the balance once `recov_delay` elapses.** Today a thief with the phone
  cannot touch Ark funds without the cosigner. `recov_delay` must therefore be long — months, not
  days — so the leaf only fires on genuine abandonment, and it must comfortably exceed the ASP's
  own exit delay so the ASP's forfeit assumptions are never undercut.
- **It is forward-only.** Changing the taptree changes the address, so existing VTXOs keep the
  old script until they are re-settled. Boarding outputs need the same treatment.
- **It depends on ASPs continuing not to constrain taptrees.** If arkade later requires
  registering or validating VTXO scripts, this needs their buy-in.

That last risk is why the pre-signed exits above were built first: they need no script change at
all, so they work even against an ASP that rejects non-default taptrees. The recovery leaf would
replace them with something that covers every VTXO the moment it exists, including the ones the
cosigner makes while nobody is watching.

Scope to close it: extend the taptree builder in `crates/ark` to the three-leaf form, thread
`wallet_vk` through as the recovery key on both sides, add an exit-broadcast flow in the app, and
a regtest E2E that permanently kills the cosigner *and* the ASP and still drains a wallet
on-chain.

## References

- [FROST: Flexible Round-Optimized Schnorr Threshold Signatures](https://eprint.iacr.org/2020/852)
- [BIP-340: Schnorr Signatures for secp256k1](https://github.com/bitcoin/bips/blob/master/bip-0340.mediawiki)
- [BIP-341: Taproot](https://github.com/bitcoin/bips/blob/master/bip-0341.mediawiki)
- [Ark protocol](https://arkdev.info/) — off-chain VTXOs via an Ark Service Provider
- [AWS Nitro Enclaves](https://docs.aws.amazon.com/enclaves/latest/user/nitro-enclave.html)
- [introspector-enclave](https://github.com/ArkLabsHQ/introspector-enclave) — enclave host/runtime plumbing

## License

[MIT](LICENSE) — use it, fork it, run your own cosigner. Nothing here is licensed in a way that
lets us strand you: the client, the cosigner runtime, the threshold library, and the deployment
stack are all in this repository.

Third-party code keeps its own licensing and is not covered by the above:
`third_party/rust-sdk` is a submodule ([arkade-os/rust-sdk](https://github.com/arkade-os/rust-sdk),
MIT, see its own `LICENSE`), and the vendored crates under `cosigner-runtime/vendor/`
remain under the licences of their respective upstreams.
