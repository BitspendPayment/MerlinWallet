#!/usr/bin/env bash
# Every WIT this repo vendors must equal the canonical copy in enclave-runtime.
#
# The cosigner vendors `tasks.wit` and `notify.wit` because wit-bindgen reads a path inside the
# crate that generates from them. Two copies of an interface that must be byte-identical is exactly
# the thing that drifts unnoticed: both sides still compile, and the mismatch surfaces much later as
# a runtime trap in a component that looked fine.
#
# Only `wit/deps/` is checked, which is the rule WIT itself imposes rather than a shortcut: every
# file directly in a crate's `wit/` belongs to that crate's own package, and foreign packages must
# live under `deps/`. So `deps/` is exactly the vendored set, and `wit/cosigner.wit` is correctly
# ignored.
#
# Modelled on enclave-runtime's own scripts/wit-drift.sh, which checks the same invariant from the
# other side.

set -euo pipefail

REPO="$(git rev-parse --show-toplevel)"
cd "$REPO"

RUNTIME="${ENCLAVE_RUNTIME:-$HOME/enclave-runtime}"
if [[ ! -d "$RUNTIME/wit" ]]; then
    echo "no enclave-runtime at $RUNTIME — set ENCLAVE_RUNTIME to check vendored WIT" >&2
    exit 1
fi

status=0
found=0

while IFS= read -r copy; do
    found=$((found + 1))
    base="$(basename "$copy")"

    # Matched by basename across the runtime's wit/, not by a constructed path: the canonical file
    # is wit/tasks/tasks.wit, not wit/tasks.wit, and hard-coding either shape breaks on whichever
    # one comes next.
    mapfile -t canonical < <(find "$RUNTIME/wit" -type f -name "$base" | sort)
    case "${#canonical[@]}" in
        1) ;;
        0)
            echo "no canonical WIT for $copy (looked for $base under $RUNTIME/wit/)" >&2
            status=1
            continue
            ;;
        *)
            echo "ambiguous: $base exists at ${canonical[*]}" >&2
            status=1
            continue
            ;;
    esac

    if cmp -s "$copy" "${canonical[0]}"; then
        echo "ok     $copy == ${canonical[0]}"
    else
        echo "DRIFT  $copy differs from ${canonical[0]}" >&2
        diff -u "${canonical[0]}" "$copy" >&2 || true
        status=1
    fi
done < <(find . -type f -path '*/wit/deps/*.wit' -not -path '*/target/*' -not -path '*/vendor/*' \
    -not -path './.enclave/*' | sort)  # .enclave/ is the runtime itself, not a copy of it

# A check that silently covers nothing is worse than no check, because it still reports green. If
# the vendored copies move, this says so instead.
if (( found == 0 )); then
    echo "no vendored WIT found under */wit/deps/ — this check has stopped checking anything" >&2
    exit 1
fi

exit "$status"
