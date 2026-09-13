#!/usr/bin/env bash
# Build the cosigner to a wasm32-wasip2 component.
#
# The component exports `wasi:http/incoming-handler`, which is the only world enclave-runtime
# serves. There is no listener in the guest and no runtime to start: the host owns the socket, the
# TLS and the HTTP/2 negotiation, and calls the guest once per request.
#
# The C toolchain is needed for exactly one vendored C library — `secp256k1-sys`, which does the
# signing — and comes from wasi-sdk. It was two until the store stopped being SQLite; that one
# additionally needed `-DSQLITE_THREADSAFE=0`, because wasm32-wasip2 has no threads and SQLite's
# default fails the build on a `pthread_create` static assertion.
set -euo pipefail

cd "$(dirname "${BASH_SOURCE[0]}")/.."

sdk="${WASI_SDK:-$HOME/wasi-sdk}"
if [[ ! -x "$sdk/bin/clang" ]]; then
    echo "no wasi-sdk at $sdk" >&2
    echo "install it with enclave-runtime's scripts/wasi-sdk.sh, or set WASI_SDK" >&2
    exit 1
fi

export CC_wasm32_wasip2="$sdk/bin/clang"
export AR_wasm32_wasip2="$sdk/bin/ar"
export CFLAGS_wasm32_wasip2="--sysroot=$sdk/share/wasi-sysroot"

cd cosigner
cargo build --release --target wasm32-wasip2 "$@"

out="$PWD/target/wasm32-wasip2/release/cosigner.wasm"
[[ -f "$out" ]] || { echo "no component at $out" >&2; exit 1; }
echo "built $out ($(du -h "$out" | cut -f1))"
