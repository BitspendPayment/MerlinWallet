#!/usr/bin/env bash
# The payout platform on the regtest stack: MerlinPlatform, paying through a fake Grid.
#
#   scripts/platform.sh up            build both, start them in the background, wait until they answer
#   scripts/platform.sh down          stop them
#   scripts/platform.sh id            the platform's service identifier, as SERVICE_ORIGINS names it
#   scripts/platform.sh pins <run>    believe the dev enclave booted in <run> (its PCRs and root)
#
# MerlinPlatform is a repository of its own, found at $MERLIN_PLATFORM (default ../MerlinPlatform).
# It depends on this repository's crates by git revision; here it is built against THIS checkout's
# instead, so the platform always speaks the protocol of the cosigner being run. That takes a
# `--config patch`, which rewrites Cargo.lock — so what is built is a copy in .platform/build, and
# the MerlinPlatform checkout is never touched.
#
# With no MerlinPlatform checkout this says so and does nothing: the rest of the stack runs, and the
# app has no bank sends.
set -euo pipefail

cd "$(dirname "${BASH_SOURCE[0]}")/.."
repo="$PWD"
source_dir="${MERLIN_PLATFORM:-$repo/../MerlinPlatform}"
build="$repo/.platform/build"
run="$repo/.platform/run"
bin="$build/target/release"

# The fake Grid's two tokens, `id:secret`: the platform pays with the first, the enclave fetches its
# evidence with the second. Fakes, so they can be written down — and the second goes into the dev
# enclave's image, which nothing should ever say of a real one.
transact="dev-transact:dev-transact-secret"
view="dev-view:dev-view-secret"
grid_port=7300
platform_port=7200

have_source() { [[ -f "$source_dir/Cargo.toml" ]]; }

running() { [[ -f "$run/$1.pid" ]] && kill -0 "$(cat "$run/$1.pid")" 2>/dev/null; }

build() {
    mkdir -p "$build/src"
    rsync -a --delete --exclude target --exclude .git "$source_dir/" "$build/src/"
    local patch=() crate
    for crate in escrow-service=crates/escrow-service cosigner=cosigner ark=crates/ark \
                 threshold=crates/threshold; do
        patch+=(--config "patch.\"https://github.com/BitspendPayment/MerlinWallet\".${crate%%=*}.path=\"$repo/${crate#*=}\"")
    done
    cargo build --release --bins --manifest-path "$build/src/Cargo.toml" \
        --target-dir "$build/target" "${patch[@]}"
}

stop() {
    local name
    for name in platform fake-grid; do
        if running "$name"; then kill "$(cat "$run/$name.pid")" 2>/dev/null || true; fi
        rm -f "$run/$name.pid"
    done
}

up() {
    if ! have_source; then
        echo "no MerlinPlatform checkout at $source_dir — the stack runs without bank sends" \
             "(set MERLIN_PLATFORM to use one elsewhere)"
        return 0
    fi
    echo "==> building MerlinPlatform against this checkout's crates"
    build
    stop
    mkdir -p "$run"

    "$bin/fake_grid" --port "$grid_port" --transact "$transact" --view "$view" \
        >"$run/fake-grid.log" 2>&1 &
    echo $! >"$run/fake-grid.pid"

    # The platform dials the fake on this host; the enclave reaches the same fake at
    # 192.168.127.254, and that is the origin every policy it writes names. It believes an enclave
    # once a boot writes the pins file — see `pins` below.
    GRID_CLIENT_ID="${transact%%:*}" GRID_CLIENT_SECRET="${transact#*:}" \
    "$bin/merlin-platform" --port "$platform_port" \
        --store "$run/state.json" \
        --asp http://127.0.0.1:7070 \
        --grid-url "http://127.0.0.1:$grid_port" \
        --grid-origin-sealed "http://192.168.127.254:$grid_port" \
        --enclave-pins "$run/enclave-pins.json" \
        --sats-per-usd 1000 \
        >"$run/platform.log" 2>&1 &
    echo $! >"$run/platform.pid"

    local i
    for i in $(seq 1 60); do
        if curl -sf "http://127.0.0.1:$platform_port/corridors" >/dev/null; then
            echo "==> MerlinPlatform on :$platform_port, the fake Grid on :$grid_port" \
                 "(logs in $run)"
            return 0
        fi
        running platform || break
        sleep 1
    done
    echo "the platform did not come up:" >&2
    tail -20 "$run/platform.log" >&2 || true
    stop
    return 1
}

identifier() {
    [[ -x "$bin/merlin-platform" ]] || { echo "not built — scripts/platform.sh up" >&2; return 1; }
    "$bin/merlin-platform" --print-identifier
}

# The dev enclave in <run dir>, as the platform should believe it: `deployment.json`'s shape. A dev
# enclave mints its root at every boot, so this is written after each one, and the platform reads
# it again when it changes.
pins() {
    local enclave="$1" console pcr0 pcr16
    console="$(sed 's/\x1b\[[0-9;]*m//g' "$enclave/console.log")"
    pcr0="$(grep -o 'pcr0=[0-9a-f]\{96\}' <<<"$console" | tail -1 | cut -d= -f2)"
    pcr16="$(grep -o 'pcr16=[0-9a-f]\{96\}' <<<"$console" | tail -1 | cut -d= -f2)"
    [[ -n "$pcr0" && -n "$pcr16" ]] || { echo "no pcr0=/pcr16= in $enclave/console.log" >&2; return 1; }
    mkdir -p "$run"
    jq -n --arg pcr0 "$pcr0" --arg pcr16 "$pcr16" --arg root "$(base64 -w0 "$enclave/trust-root.der")" \
        '{pcr0: $pcr0, pcr16: $pcr16, trust_root: $root}' >"$run/enclave-pins.json.tmp"
    mv "$run/enclave-pins.json.tmp" "$run/enclave-pins.json"
}

case "${1:-}" in
    up) up ;;
    down) stop ;;
    id) identifier ;;
    pins) pins "${2:?the enclave run dir}" ;;
    *) echo "usage: $0 up|down|id|pins <enclave run dir>" >&2; exit 2 ;;
esac
