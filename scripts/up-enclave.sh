#!/usr/bin/env bash
# A dev environment around the cosigner: regtest mining, and a QEMU Nitro enclave serving the
# cosigner component, in the foreground until Ctrl-C.
#
#   scripts/up-enclave.sh            (make up-enclave builds the component and starts the stack first)
#
# The enclave is enclave-runtime's deploy/qemu-nitro/dev-enclave.sh: a real attested boot under
# QEMU, a Pebble certificate for enclave.test on 127.0.0.1:$ENCLAVE_PORT, and every request gated on a
# passkey. It is a fresh store every start, so wallets from a previous boot do not carry over.
set -euo pipefail

cd "$(dirname "${BASH_SOURCE[0]}")/.."
repo="$PWD"
runtime="${ENCLAVE_RUNTIME:-$HOME/enclave-runtime}"
name="${ENCLAVE_NAME:-merlin}"
port="${ENCLAVE_PORT:-8443}"
wasm="$repo/cosigner/target/wasm32-wasip2/release/cosigner.wasm"

# The relying party, so the phone app can register a passkey against this enclave. Android creates
# one only for a domain whose assetlinks.json names the app — https://vtxos.com/.well-known/assetlinks.json
# names com.vtxos.app — and the app then claims android:apk-key-hash:<its signing key>, which the
# image must allow. Both are the app's signing keys as published there: the checked-in debug
# keystore (2D:FD:50:23…) and the release key (BB:5A:4D:7A…).
#
# ENCLAVE_RP_ID= (empty) boots the runtime's default, enclave.test, which only software passkeys —
# the CLI and the e2e suite — can use. Either way the certificate is still for enclave.test.
rp_id="${ENCLAVE_RP_ID-vtxos.com}"
allowed_origins="${ENCLAVE_ALLOWED_ORIGINS-android:apk-key-hash:Lf1QIwQnlPBYPwDFhloUkYC-0tYAKSpKCQbEiyz118s,android:apk-key-hash:u1pNepeObJUpSkSqH964HvFRqbhC_ejQP3GHA3-lreI}"
webauthn=()
if [[ -n "$rp_id" ]]; then
    webauthn+=(--rp-id "$rp_id")
    IFS=, read -ra origins <<<"$allowed_origins"
    for o in "${origins[@]}"; do webauthn+=(--allowed-origin "$o"); done
fi
run="$runtime/target/qemu-nitro/$name"

[[ -x "$runtime/deploy/qemu-nitro/dev-enclave.sh" ]] \
    || { echo "no enclave-runtime at $runtime — set ENCLAVE_RUNTIME" >&2; exit 1; }
[[ -f "$wasm" ]] || { echo "no component at $wasm — make cosigner-wasm" >&2; exit 1; }

# One enclave at a time: MinIO's port and the vsock CID are fixed. Say so now, rather than after
# minutes of image build, when the second one fails to bind.
if ss -ltn 2>/dev/null | grep -qE "[:.]($port|9000)\s"; then
    echo "port $port or 9000 is already taken — is an enclave up? make down-enclave stops it" >&2
    exit 1
fi

# Nothing moves on regtest unless somebody mines: boarding needs a confirmation before arkd accepts
# it, and a commitment needs one before its VTXOs are spendable.
(while true; do ./scripts/bitcoin.sh mine >/dev/null 2>&1 || true; sleep 10; done) &
miner=$!
watcher=""
stamp="$(mktemp)"
trap 'kill $miner $watcher 2>/dev/null || true; rm -f "$stamp"' EXIT

# A phone over USB reaches the enclave, arkd and electrs on its own loopback.
if command -v adb >/dev/null && adb get-state >/dev/null 2>&1; then
    for p in "$port" 7070 50001; do adb reverse "tcp:$p" "tcp:$p" >/dev/null || true; done
    echo "adb reverse: $port (enclave), 7070 (arkd), 50001 (electrs)"
fi

hints() {
    cat <<HINTS

== merlin: the cosigner is serving ==

  component  $wasm
  run dir    $run

  CLI        make cli                                   (wallets under ~/.merlin-cli/enclaves/<boot>/)
  e2e        make e2e-enclave ENCLAVE_RUN=$run
  app        make adb-reverse && make flutter           (pins this boot's root and PCRs into the build)
  rp id      ${rp_id:-enclave.test}

  Regtest is mined every 10s while this runs. make down-enclave stops it from another terminal.

HINTS
}

# The runtime's summary first, then ours once it is up. Watched from the side rather than by piping
# its output through a reader: Ctrl-C reaches the whole foreground group, and a reader that died
# first would take the enclave's cleanup trap down with SIGPIPE halfway through its teardown.
#
# Up means: the enclave answered on its port, after enrolling the passkey that dev-enclave.sh
# enrols last, just before it prints its summary. The run directory survives from earlier boots,
# so the passkey file has to be newer than this start.
(
    until [[ "$run/alice.json" -nt "$stamp" ]] &&
        curl -s -o /dev/null --resolve "enclave.test:$port:127.0.0.1" --cacert "$run/pebble-root.pem" \
            -H "x-enclave-nonce: AAAAAAAAAAAAAAAAAAAAAAAAAAA" "https://enclave.test:$port/auth/"; do
        sleep 3
    done
    sleep 2
    hints
) &
watcher=$!

cd "$runtime"
./deploy/qemu-nitro/dev-enclave.sh --guest "$wasm" --name "$name" --port "$port" "${webauthn[@]}"
