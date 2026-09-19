# Production Readiness Assessment

## Context

The MPC Wallet has working cryptography (FROST 2-of-2, Ark integration, MutinyNet support) but significant gaps in security, reliability, and operations. This document captures every finding from a deep codebase audit, prioritized by severity.

---

## CRITICAL (Must fix before any real funds)

### 1. No TLS on gRPC server
- **Server**: `server/src/main.rs:174-178` -- `Server::builder().serve(addr)` with no TLS
- **Client**: `app/lib/services/mpc_service.dart:192,229,284` -- `ChannelCredentials.insecure()`
- **Impact**: All traffic (auth signatures, key shares, signing data) in plaintext. MitM trivial.
- **Note**: If server runs inside an enclave that only accepts HTTP, TLS may be handled by the enclave's ingress layer.

### 2. Unauthenticated DKG endpoints
- **File**: `server/src/wallet_service.rs:745-1150` -- `dkg_step1/2/3` have NO `verify_auth()` calls
- **Impact**: Anyone can initiate key generation for arbitrary user IDs, create unbounded WASM instances, enumerate recovery IDs via `find_policy_by_recovery_id()` (line 480-513)

### 3. Unauthenticated broadcast_transaction
- **File**: `server/src/wallet_service.rs:2624-2644` -- no auth check
- **Impact**: Any client can broadcast arbitrary transactions

### 4. Unbounded WASM instance creation (DoS)
- **File**: `server/src/wasm_manager.rs:123-165` -- `HashMap<String, UserInstance>` grows indefinitely
- **Impact**: Each WASM Store allocates ~10+ MB. Combined with unauthenticated DKG, trivial memory exhaustion.

### 5. No user_id validation
- **File**: `server/src/wallet_service.rs:410-412` -- `user_id_hex()` accepts arbitrary bytes
- **Impact**: Invalid pubkeys (wrong length, bad prefix) accepted without validation. Potential crashes in crypto ops.

### 6. Electrum connection drops silently with no reconnection
- **File**: `server/src/bitcoin/electrum.rs:52-90` -- reader task ends silently when TCP drops
- **No reconnection logic after initial connect** -- retry loop is startup-only
- **No request timeout** -- `request()` hangs forever if reader dies
- **No write flush** -- `write_all()` never calls `flush()`
- **Impact**: Server becomes silently broken after any Electrum disconnection. All UTXO queries and broadcasts hang indefinitely.

### 7. Server key share loss is unrecoverable
- No key share backup/export mechanism anywhere in the codebase
- If Sled DB is lost, all user wallets are permanently unrecoverable
- **Impact**: Single point of failure for all funds
- **Note (client-side recovery):** the *phone* half is now recoverable — it is derived from the
  passkey's PRF, and the cosigner seals the half it dealt so a new device can rebuild the share
  (`cosigner/src/handlers/recover.rs`). That makes this item **more** load-bearing, not less: the
  cosigner's seal is now the only copy of anything, and losing it loses both the cosigner's share
  and the half a user would recover with.

---

## HIGH (Should fix before beta users)

### 8. 82 `.lock().unwrap()` calls on sync Mutex
- **File**: `server/src/wallet_service.rs` -- 82 instances of `self.wasm_manager.lock().unwrap()`
- If ANY WASM operation panics, mutex is poisoned and ALL subsequent requests crash
- Same pattern in `auth/verifier.rs:96,111,122` with RwLock

### 9. Multiple panic-prone unwrap() calls
- `wallet_service.rs:773,886,909` -- `user.dkg_session.unwrap()` assumes session exists
- `wallet_service.rs:1278` -- `user.round2_secret.take().unwrap()`
- `wallet_service.rs:1470,1518,1527` -- `user.signing_session.unwrap()`
- `bitcoin/history.rs:178` -- `duration_since()` panics if system clock goes backwards
- `main.rs:80` -- `panic!("Unknown persistence backend")`

### 10. Key shares unencrypted by default on client
- `app/lib/services/mpc_service.dart` never passes a `HiveCipher` to `MpcClient` or `WalletStore`
- Signing secret stored in plaintext Hive box on device
- PIN-derived encryption exists but is NOT wired up

### 11. No graceful shutdown
- In-flight DKG/signing sessions lost on kill
- No draining of active gRPC streams

### 12. No rate limiting
- Zero rate limiting on any endpoint

### 13. No health check endpoint
- No `/health` or gRPC health check service

### 14. No Dockerfile for server

---

## MEDIUM (Should fix before mainnet)

### 15. No CI pipeline for tests
- Only WASM build in GitHub Actions. No cargo test, dart test, or E2E automation.

### 16. Weak nonce cache cleanup
- Evicts arbitrarily instead of by timestamp expiration

### 17. 5-minute timestamp window too large
- Combined with no TLS, gives attacker 300s to replay captured signatures

### 18. No input size limits on gRPC messages

### 19. Cross-user policy disclosure via find_policy_by_recovery_id()

### 20. No fee estimation -- tests hardcode feeRate: 1

### 21. Dead code: BitcoinRpcClient initialized but never called

### 22. Enclave store has no retry logic

### 23. No data migration framework

### 24. No mid-DKG checkpoints on client

### 25. No timeout on most client operations

---

## LOW (Nice to have)

### 26. Transaction history in-memory only
### 27. No structured logging
### 28. No metrics (Prometheus/OpenTelemetry)
### 29. Log level not configurable at runtime

---

## Recommended Phasing

### Phase 1: Security Hardening
Items 1-5, 18, 21

### Phase 2: Reliability
Items 6, 8-13

### Phase 3: Operations
Items 14-15, 7, 20, 17, 27-28
