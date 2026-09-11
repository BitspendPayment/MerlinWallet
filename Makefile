# ═══════════════════════════════════════════════════════════════════════════════
#  MPC Wallet — Makefile
#
#  Primary commands:
#    make e2e     Run the Ark E2E suite (regtest + arkd, built and torn up fresh)
#    make up      Start regtest + arkd + the cosigner in the foreground
#    make down    Stop everything
#
#  Release (Firebase App Distribution):
#    make release                       Build arm64 release APK + push to testers
#    make release VERSION=1.2.0 BUILD_NUMBER=5 RELEASE_NOTES="..."  (override version)
#    make release-apk                   Build arm64 release APK only (FFI + signed)
#    make release-apk-fat               Fat APK: arm64 + arm32 + x86_64
#    make release-testers-add TESTERS="a@x.com,b@x.com"
#    make release-testers-remove TESTERS="a@x.com"
# ═══════════════════════════════════════════════════════════════════════════════

.PHONY: e2e up down \
	bob-up bob-down bob-send \
	ffi-build ffi-test ffi-android ffi-android-arm32 ffi-android-x86_64 ffi-android-all \
	contracts-build runtime-build \
	regtest-up regtest-down bitcoin-init mine-loop adb-reverse \
	runtime-run runtime-stop \
	arkd-up arkd-down arkd-init db-reset \
	proto threshold-test \
	flutter flutter-32 flutter-x86 ark-newaddress crypto-bench \
	stress-test load-test \
	signet-hardware-ark signet-down e2e-mutinynet e2e-mutinynet-ark \
	e2e-test e2e-ark-test regtest regtest-ark regtest-down \
	cli cli-build cli-up cli-stop cli-clear \
	release release-apk release-apk-fat release-testers-add release-testers-remove

# ── Variables ─────────────────────────────────────────────────────────────────

export DATA_DIR=/tmp/mpc_wallet_stress
# The cosigner-runtime's single embedded SQLite KV backend — a file on local disk.
export SQLITE_PATH=/tmp/mpc_cosigner/cosigner.db

NDK_VERSION ?= 27.0.12077973
NDK_HOME     = $(HOME)/Android/Sdk/ndk/$(NDK_VERSION)

MUTINYNET_ASP_URL ?= http://localhost:7070
SESSIONS          ?= 10
CONCURRENCY       ?= 5
SERVER            ?= 127.0.0.1:7074

# Firebase App Distribution. Read from app/android/app/google-services.json
# (the com.vtxos.app client's mobilesdk_app_id).
FIREBASE_APP_ID  ?= 1:575541915148:android:03d0cade16cd0393378829
FIREBASE_PROJECT ?= vtxos-7afb3
TESTERS_GROUP    ?= internal
RELEASE_NOTES    ?= Internal build

# Override the app version at build time without editing pubspec.yaml.
#   make release VERSION=1.2.0 BUILD_NUMBER=5 RELEASE_NOTES="..."
# VERSION sets --build-name (the x.y.z shown to testers); BUILD_NUMBER sets
# --build-number (the integer Android versionCode, must increase each upload).
# Leave either empty to fall back to the value in app/pubspec.yaml.
VERSION      ?=
BUILD_NUMBER ?=
VERSION_FLAGS = $(if $(VERSION),--build-name=$(VERSION)) $(if $(BUILD_NUMBER),--build-number=$(BUILD_NUMBER))

# ═══════════════════════════════════════════════════════════════════════════════
#  PRIMARY COMMANDS
# ═══════════════════════════════════════════════════════════════════════════════

# Run the Ark E2E suite — starts regtest + arkd, builds everything, tests, cleans up
e2e: runtime-stop arkd-up bitcoin-init arkd-init ffi-build runtime-build db-reset
	@echo "Running Ark E2E test..."
	cd e2e && dart test test/ark_e2e_test.dart

# Start regtest + arkd with the software 2-of-2 signer, cosigner in the foreground
up: runtime-build ffi-build ffi-android
	@echo "=== Starting regtest + arkd ==="
	docker compose -f docker-compose.yml -f docker-compose.ark.yml up -d
	@echo "Waiting for services to stabilize (20s)..."
	@sleep 20
	@echo "=== Initializing Bitcoin chain ==="
	./scripts/bitcoin.sh init
	@echo "=== Initializing arkd ==="
	./scripts/arkd_init.sh --fund
	@echo "=== Waiting 10s for NBXplorer to index initial blocks ==="
	@sleep 10
	@echo "=== Setting up Bob (ark-sample counter-party) ==="
	$(MAKE) bob-up 
	@echo "=== Setting up ADB reverse ==="
	-adb reverse tcp:7074 tcp:7074
	-adb reverse tcp:50001 tcp:50001
	-adb reverse tcp:7090 tcp:7090
	@echo ""
	@echo "==> Software 2-of-2 signer mode + Ark."
	@echo "==> Run Flutter in a separate terminal:  cd app && flutter run"
	@echo "==> Server logs below (Ctrl+C to stop server + mine loop):"
	@echo ""
	@bash -c 'set -m; \
		(while true; do ./scripts/bitcoin.sh mine 2>/dev/null; sleep 10; done) & \
		MINE_PID=$$!; \
		trap "kill $$MINE_PID 2>/dev/null || true; wait $$MINE_PID 2>/dev/null || true" EXIT INT TERM; \
		export ELECTRUM_URL=127.0.0.1 ELECTRUM_PORT=50001 \
		       BITCOIN_RPC_USER=admin1 BITCOIN_RPC_PASSWORD=123 \
		       ASP_URL=http://127.0.0.1:7070 \
		       FCM_SERVICE_ACCOUNT_JSON="$$(cat $${FCM_SA_FILE:-$$HOME/Downloads/vtxos-key.json} 2>/dev/null)" \
		       WEBAUTH_RP_ID=vtxos.com \
		       WEBAUTH_RP_ORIGIN=https://vtxos.com \
		       WEBAUTH_ANDROID_ORIGIN=android:apk-key-hash:u1pNepeObJUpSkSqH964HvFRqbhC_ejQP3GHA3-lreI,android:apk-key-hash:Lf1QIwQnlPBYPwDFhloUkYC-0tYAKSpKCQbEiyz118s \
		       WEBAUTH_TOKEN_SECRET=$${WEBAUTH_TOKEN_SECRET:-6d706377616c6c65742d6465762d746f6b656e2d7365637265742d3332622121}; \
		cd cosigner-runtime && cargo run --release --bin cosigner-runtime -- \
			--port 7074'

# Stop everything (cosigner, mine loop, Docker)
down:
	@echo "Stopping all services..."
	-pkill -f "target/release/cosigner-runtime" || true
	-pkill -f "bitcoin.sh mine" || true
	-pkill -f "bob_proxy" || true
	-sudo fuser -k 7074/tcp 2>/dev/null || true
	-sudo fuser -k 7090/tcp 2>/dev/null || true
	-docker compose -f docker-compose.yml -f docker-compose.ark.yml down -v 2>/dev/null || true
	sudo rm -rf /root/.mpc_wallet/cosigner-runtime/db 2>/dev/null || true
	sudo rm -rf $(DATA_DIR) 2>/dev/null || true
	@echo "All stopped."

# Bring up Bob — ark-sample wallet that acts as counter-party for the Flutter
# integration test. Requires arkd already running (call after arkd-init).
bob-up:
	@./scripts/bob_setup.sh
	@echo "==> Starting bob_proxy on :7090..."
	-pkill -f bob_proxy || true
	@nohup python3 scripts/bob_proxy.py > /tmp/bob_proxy.log 2>&1 &
	@sleep 1
	@curl -sf http://127.0.0.1:7090/ark-address | head -c 200 && echo

bob-down:
	-pkill -f bob_proxy || true
	-sudo fuser -k 7090/tcp 2>/dev/null || true

# Send a VTXO from Bob to any ark address. Requires bob-up to have run first.
# Usage: make bob-send ADDR=tark1... [AMT=50000]
bob-send:
	@test -n "$(ADDR)" || { echo "ADDR=<ark address> required (e.g. make bob-send ADDR=tark1... AMT=50000)"; exit 1; }
	$${RUST_SDK_DIR:-third_party/rust-sdk}/target/release/ark-client-sample \
		--config $${BOB_DIR:-/tmp/bob_ark}/ark.config.toml \
		--seed $${BOB_DIR:-/tmp/bob_ark}/ark.seed \
		send-to-ark-addresses "$(ADDR),$(or $(AMT),50000)"

# ═══════════════════════════════════════════════════════════════════════════════
#  BUILD TARGETS
# ═══════════════════════════════════════════════════════════════════════════════

# Merged FFI: ark + threshold + enclave bindings build into one libmpcwallet_ffi.so
ffi-build:
	@echo "Building merged FFI (ark + threshold + enclave)..."
	cargo build --release --manifest-path ffi/Cargo.toml
	@echo "Built: ffi/target/release/libmpcwallet_ffi.so"

ffi-android: ## Build merged FFI for Android arm64
	@echo "Building merged FFI for Android arm64..."
	export PATH="$(NDK_HOME)/toolchains/llvm/prebuilt/linux-x86_64/bin:$$PATH" && \
	cargo build --release --manifest-path ffi/Cargo.toml --target aarch64-linux-android
	mkdir -p app/android/app/src/main/jniLibs/arm64-v8a
	cp ffi/target/aarch64-linux-android/release/libmpcwallet_ffi.so \
		app/android/app/src/main/jniLibs/arm64-v8a/
	@echo "Installed: app/android/app/src/main/jniLibs/arm64-v8a/libmpcwallet_ffi.so"

ffi-android-arm32: ## Build merged FFI for Android arm32 (armv7)
	@echo "Building merged FFI for Android arm32..."
	export PATH="$(NDK_HOME)/toolchains/llvm/prebuilt/linux-x86_64/bin:$$PATH" && \
	export CC_armv7_linux_androideabi=armv7a-linux-androideabi21-clang && \
	export AR_armv7_linux_androideabi=llvm-ar && \
	cargo build --release --manifest-path ffi/Cargo.toml --target armv7-linux-androideabi
	mkdir -p app/android/app/src/main/jniLibs/armeabi-v7a
	cp ffi/target/armv7-linux-androideabi/release/libmpcwallet_ffi.so \
		app/android/app/src/main/jniLibs/armeabi-v7a/
	@echo "Installed: app/android/app/src/main/jniLibs/armeabi-v7a/libmpcwallet_ffi.so"

ffi-android-x86_64: ## Build merged FFI for Android x86_64 (emulator on Intel/AMD hosts)
	@echo "Building merged FFI for Android x86_64..."
	export PATH="$(NDK_HOME)/toolchains/llvm/prebuilt/linux-x86_64/bin:$$PATH" && \
	cargo build --release --manifest-path ffi/Cargo.toml --target x86_64-linux-android
	mkdir -p app/android/app/src/main/jniLibs/x86_64
	cp ffi/target/x86_64-linux-android/release/libmpcwallet_ffi.so \
		app/android/app/src/main/jniLibs/x86_64/
	@echo "Installed: app/android/app/src/main/jniLibs/x86_64/libmpcwallet_ffi.so"

ffi-android-all: ffi-android ffi-android-arm32 ffi-android-x86_64   # arm64 + arm32 + x86_64

ffi-test:
	@echo "Running merged FFI tests..."
	cargo test --release --manifest-path ffi/Cargo.toml

# Server & cosigner

# WASI sysroot for cross-compiling the C deps (secp256k1-sys) of the wasm guest.
# System clang targeting wasm32-wasip2 has no sysroot, so its stdint.h falls through
# to /usr/include (glibc) and fails on bits/libc-header-start.h. wasi-sdk 24 ships an
# LLVM-18 sysroot matching the system clang-18; point clang at it via --sysroot.
contracts-build:
	@echo "Building example WASM contracts (wasm32-wasip2 components)..."
	cd contracts/examples/spending-limit && cargo build --release
	@echo "Built: contracts/examples/spending-limit/target/wasm32-wasip2/release/spending_limit.wasm"
	cd contracts/examples/oracle-gate && cargo build --release
	@echo "Built: contracts/examples/oracle-gate/target/wasm32-wasip2/release/oracle_gate.wasm"
	cd contracts/examples/oracle-gate-template && cargo build --release
	@echo "Built: oracle-gate-template (Phase 2 template, imports oracle:gate/config)"
	cd contracts/examples/config-provider && cargo build --release
	@echo "Built: config-provider (Phase 2 provider stub, patchable config slot)"

runtime-build:
	@echo "Building server..."
	cd cosigner-runtime && cargo build --release

# ═══════════════════════════════════════════════════════════════════════════════
#  INFRASTRUCTURE
# ═══════════════════════════════════════════════════════════════════════════════

regtest-up:
	@echo "Starting Regtest environment..."
	docker compose up -d
	@echo "Waiting for services to stabilize..."
	@sleep 5

bitcoin-init:
	./scripts/bitcoin.sh init

mine-loop:
	@echo "Mining a block every 10s (Ctrl+C to stop)..."
	@while true; do ./scripts/bitcoin.sh mine; sleep 10; done

adb-reverse:
	@echo "Setting up ADB reverse port forwarding..."
	-adb reverse tcp:7074 tcp:7074
	-adb reverse tcp:50001 tcp:50001
	@echo "Forwarding active: phone 127.0.0.1:7074 -> PC REST server"
	@echo "Forwarding active: phone 127.0.0.1:50001 -> PC Electrs"

runtime-run: runtime-build
	@echo "Starting MPC Wallet Server on port 7074..."
	export ELECTRUM_URL=127.0.0.1 && \
	export ELECTRUM_PORT=50001 && \
	export BITCOIN_RPC_USER=admin1 && \
	export BITCOIN_RPC_PASSWORD=123 && \
	cd cosigner-runtime && cargo run --release --bin cosigner-runtime -- \
		--port 7074 &
	@sleep 2
	@echo "MPC Wallet Server running in background."

runtime-stop:
	@echo "Stopping MPC Wallet Server..."
	-sudo fuser -k 7074/tcp || true
	-sudo pkill -9 -f "target/release/cosigner-runtime" || true
	-sudo pkill -9 -f "cosigner-runtime" || true
	-sudo pkill -9 cosigner-runtime || true
	sudo rm -rf $(DATA_DIR) || true
	@sleep 2

arkd-up:
	@echo "Starting regtest + arkd (ASP) services..."
	docker compose -f docker-compose.yml -f docker-compose.ark.yml up -d
	@echo "Waiting for arkd to start (30s)..."
	@sleep 30

# Reset the cosigner-runtime's SQLite KV file for a clean test run. The reset is per-target
# (NOT on runtime restart), so the `sealed_state` snapshot survives the ark_e2e restart — the
# same guarantee the old FLUSHALL-on-redis-up gave. `-wal`/`-shm` are SQLite's sidecar files;
# leaving them behind next to a deleted DB would resurrect stale pages.
db-reset:
	@rm -f $(SQLITE_PATH) $(SQLITE_PATH)-wal $(SQLITE_PATH)-shm
	@mkdir -p $(dir $(SQLITE_PATH))
	@echo "cosigner SQLite reset ($(SQLITE_PATH))"

arkd-down:
	@echo "Stopping arkd services..."
	docker compose -f docker-compose.yml -f docker-compose.ark.yml down -v

arkd-init:
	@echo "Initializing arkd wallet..."
	./scripts/arkd_init.sh --fund

# ═══════════════════════════════════════════════════════════════════════════════
#  UTILITY
# ═══════════════════════════════════════════════════════════════════════════════

proto:
	@echo "Generating Dart gRPC stubs..."
	protoc -I protocol/protos --dart_out=grpc:protocol/lib/src/generated protocol/protos/mpc_wallet.proto

threshold-test:
	@echo "Running threshold tests..."
	cd crates/threshold && cargo test --features std

flutter: ffi-android
	cd app && flutter run

flutter-32: ffi-android-all
	cd app && flutter run

flutter-x86: ffi-android-x86_64
	cd app && flutter run

ark-newaddress:
	@cd e2e && dart run bin/ark_newaddress.dart

crypto-bench:
	@echo "Running Rust cryptography benchmarks..."
	cd crates/threshold && cargo bench

# ═══════════════════════════════════════════════════════════════════════════════
#  STRESS / LOAD TESTING
# ═══════════════════════════════════════════════════════════════════════════════

stress-test: runtime-stop regtest-up bitcoin-init runtime-run
	@echo "Running Multi-User E2E Stress Test..."
	cd e2e && dart test test/multi_user_stress_test.dart
	@$(MAKE) runtime-stop

load-test: runtime-stop regtest-up bitcoin-init runtime-run
	@echo "Running Dart Load Tester (sessions=$(SESSIONS), concurrency=$(CONCURRENCY))..."
	cd e2e && dart pub get && \
		dart run bin/load_tester.dart \
			--server $(SERVER) \
			--sessions $(SESSIONS) \
			--concurrency $(CONCURRENCY)
	@$(MAKE) runtime-stop

# ═══════════════════════════════════════════════════════════════════════════════
#  SIGNET / MUTINYNET
# ═══════════════════════════════════════════════════════════════════════════════

signet-hardware-ark: runtime-build ffi-build ffi-android
	@echo "=== Setting up ADB reverse ==="
	-adb reverse tcp:7074 tcp:7074
	@echo ""
	@echo "==> Run Flutter in a separate terminal:  cd app && flutter run"
	@echo "==> Server logs below (Ctrl+C to stop):"
	@echo ""
	export ELECTRUM_URL=electrum.mutinynet.com && \
	export ELECTRUM_PORT=50001 && \
	export BITCOIN_NETWORK=signet && \
	export ASP_URL=$(MUTINYNET_ASP_URL) && \
	cd cosigner-runtime && cargo run --release --bin cosigner-runtime -- \
		--port 7074

signet-down:
	@echo "Stopping MPC server..."
	-pkill -f "target/release/cosigner-runtime" || true
	@echo "Stopped."

e2e-mutinynet: ffi-build runtime-build
	@echo "Running MutinyNet E2E test..."
	cd e2e && dart test test/mutinynet_e2e_test.dart --timeout 600s

e2e-mutinynet-ark: ffi-build runtime-build
	@echo "Running MutinyNet Ark E2E test..."
	cd e2e && dart test test/mutinynet_ark_e2e_test.dart --timeout 900s

# ═══════════════════════════════════════════════════════════════════════════════
#  CLI — regtest REPL wallet
# ═══════════════════════════════════════════════════════════════════════════════

# Interactive wallet REPL for driving a running stack by hand: onboard, fund,
# board, send, contacts and payment requests. Point it at whatever cosigner is
# up — `make cli-up` locally, or a deployment.
#
# REGTEST ONLY. The keystore (~/.merlin-cli/wallets.json) holds PLAINTEXT
# signing secrets.
#
#   make cli                      # against the local runtime on :7074
#   make cli URL=https://mutiny.vtxos.network
CLI_URL ?= http://127.0.0.1:7074
URL     ?= $(CLI_URL)

# Everything the CLI needs, in one command: regtest + arkd, a funded ASP, a mine
# loop, and the cosigner with ASP_URL and WEBAUTH_TOKEN_SECRET set. 
#
# Foreground, mining every 10s. Drive the wallet from `make cli` in another
# terminal. Ctrl+C stops the cosigner and the mine loop; `make down` also stops
# Docker.
#
# Deliberately does NOT reset the cosigner's SQLite: it holds the server's half
# of every wallet in your CLI keystore, so wiping it here would silently orphan
# them. `make cli-clear` when you want a clean slate.
cli-up: runtime-build
	@echo "=== Starting regtest + arkd ==="
	docker compose -f docker-compose.yml -f docker-compose.ark.yml up -d
	@echo "Waiting for services to stabilize (20s)..."
	@sleep 20
	@echo "=== Initializing Bitcoin chain ==="
	./scripts/bitcoin.sh init
	@echo "=== Initializing arkd ==="
	./scripts/arkd_init.sh --fund
	@echo "=== Waiting 10s for NBXplorer to index initial blocks ==="
	@sleep 10
	@echo ""
	@echo "==> Cosigner on :7074. Drive it from another terminal:  make cli"
	@echo "==> Mining a block every 10s. Ctrl+C stops both."
	@echo ""
	@bash -c 'set -m; \
		(while true; do ./scripts/bitcoin.sh mine 2>/dev/null; sleep 10; done) & \
		MINE_PID=$$!; \
		trap "kill $$MINE_PID 2>/dev/null || true; wait $$MINE_PID 2>/dev/null || true" EXIT INT TERM; \
		export ELECTRUM_URL=127.0.0.1 ELECTRUM_PORT=50001 \
		       BITCOIN_RPC_USER=admin1 BITCOIN_RPC_PASSWORD=123 \
		       ASP_URL=http://127.0.0.1:7070 \
		       ESPLORA_URL=http://127.0.0.1:30000 \
		       BITCOIN_NETWORK=regtest \
		       WEBAUTH_TOKEN_SECRET=$${WEBAUTH_TOKEN_SECRET:-6d706377616c6c65742d6465762d746f6b656e2d7365637265742d3332622121}; \
		cd cosigner-runtime && cargo run --release --bin cosigner-runtime -- \
			--port 7074'

# Pause. Stops the containers but keeps the chain, arkd's records, the cosigner's
# database and your wallets, so `make cli-up` picks up where you left off.
cli-stop:
	@echo "Pausing the CLI stack..."
	-@pkill -f "[t]arget/release/cosigner-runtime" || true
	-@pkill -f "[b]itcoin.sh mine" || true
	docker compose -f docker-compose.yml -f docker-compose.ark.yml stop
	@echo "stopped, state kept. resume with: make cli-up"

# Wipe everything the CLI created: chain, cosigner state, keystore. Use `cli-stop`
# to pause instead. Stopping alone is not enough to reset — the chain goes with
# the Docker volumes, but the database and the keystore survive, leaving wallets
# whose coins no longer exist.
#
# Not built on `down`, which sudo-prompts for root-owned paths this flow never
# creates. The `[t]` and `[b]` stop pkill from matching its own shell. SQLite is
# removed here rather than by `db-reset` so it happens after the cosigner dies,
# not before.
cli-clear:
	@echo "Stopping the CLI stack..."
	-@pkill -f "[t]arget/release/cosigner-runtime" || true
	-@pkill -f "[b]itcoin.sh mine" || true
	-docker compose -f docker-compose.yml -f docker-compose.ark.yml down -v 2>/dev/null || true
	@rm -f $(SQLITE_PATH) $(SQLITE_PATH)-wal $(SQLITE_PATH)-shm
	@rm -f $(HOME)/.merlin-cli/wallets.json
	@echo "chain, cosigner state and CLI keystore cleared"

cli:
	@echo "merlin CLI → $(URL)  (regtest only: keystore secrets are plaintext)"
	cd cli && COSIGNER_URL=$(URL) cargo run --release

# Compile without running — what CI would check.
cli-build:
	cd cli && cargo build --release

# ═══════════════════════════════════════════════════════════════════════════════
#  LEGACY ALIASES (old names still work)
# ═══════════════════════════════════════════════════════════════════════════════

e2e-test: e2e
e2e-ark-test: e2e
regtest: regtest-up bitcoin-init runtime-run
regtest-ark: runtime-stop arkd-up bitcoin-init arkd-init
regtest-down: down

# ═══════════════════════════════════════════════════════════════════════════════
#  RELEASE — Firebase App Distribution
# ═══════════════════════════════════════════════════════════════════════════════

# Build a release APK signed with the upload key (app/android/key.properties).
# ffi-android compiles the merged Rust FFI (ark + threshold + enclave) for
# arm64 and drops libmpcwallet_ffi.so into app/android/app/src/main/jniLibs/.
# Without it the APK crashes on first native call. Mirrors `make flutter`.
# For arm64 + arm32 fat APK, run `make release-apk-fat` instead.
release-apk: ffi-android
	@echo "==> Building release APK (arm64)..."
	cd app && flutter build apk --release --target-platform android-arm64 $(VERSION_FLAGS)
	@echo "==> APK: app/build/app/outputs/flutter-apk/app-release.apk"

# Fat APK: arm64 + arm32 + x86_64. Larger (~3x) but installs on older phones
# and x86_64 emulators. Use when you don't know what device your tester runs.
release-apk-fat: ffi-android-all
	@echo "==> Building fat release APK (arm64 + arm32 + x86_64)..."
	cd app && flutter build apk --release $(VERSION_FLAGS)
	@echo "==> APK: app/build/app/outputs/flutter-apk/app-release.apk"

# Build + ship to Firebase App Distribution. Overrides:
#   make release RELEASE_NOTES="bug fix" TESTERS_GROUP=friends
release: release-apk
	@command -v firebase >/dev/null || { echo "firebase CLI missing — run: npm i -g firebase-tools && firebase login"; exit 1; }
	@echo "==> Distributing to Firebase group '$(TESTERS_GROUP)'..."
	firebase appdistribution:distribute \
		app/build/app/outputs/flutter-apk/app-release.apk \
		--app $(FIREBASE_APP_ID) \
		--release-notes "$(RELEASE_NOTES)" \
		--groups $(TESTERS_GROUP)
	@echo "==> Done. Testers in '$(TESTERS_GROUP)' will get an email + Firebase App Tester notification."

# Add testers later — they receive an invite email immediately.
#   make release-testers-add TESTERS="a@x.com,b@x.com"
release-testers-add:
	@[ -n "$(TESTERS)" ] || { echo "Pass TESTERS=\"a@x.com,b@x.com\""; exit 1; }
	firebase appdistribution:testers:add $(TESTERS) \
		--group-aliases $(TESTERS_GROUP) \
		--project $(FIREBASE_PROJECT)

# Remove testers — they lose access immediately.
#   make release-testers-remove TESTERS="a@x.com"
release-testers-remove:
	@[ -n "$(TESTERS)" ] || { echo "Pass TESTERS=\"a@x.com,b@x.com\""; exit 1; }
	firebase appdistribution:testers:remove $(TESTERS) \
		--project $(FIREBASE_PROJECT)
