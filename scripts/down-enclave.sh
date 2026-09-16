#!/usr/bin/env bash
# Stop a dev enclave started by up-enclave.sh (or the e2e harness), and everything it left behind.
#
# Ctrl-C in its terminal is the clean way. This is for another terminal, and for the case the
# script's own trap does not reach: interrupting it can take the QEMU container down before the
# trap runs, and then MinIO, Pebble, the FCM stub, gvproxy and the vsock bridge outlive it, still
# holding the fixed ports the next boot needs. Everything it creates carries the label
# enclave-harness=<name>, which is what the runtime's own cleanup removes; this is that cleanup.
set -uo pipefail

name="${ENCLAVE_NAME:-merlin}"

# Signal processes whose command line matches, but never a shell or make. A pattern naming the run
# directory also matches any shell whose command mentions it — including the one running this.
signal() {
    local sig="$1" pattern="$2" pid comm
    for pid in $(pgrep -f -- "$pattern"); do
        [[ "$pid" == "$$" ]] && continue
        comm="$(ps -o comm= -p "$pid" 2>/dev/null)" || continue
        case "$comm" in bash|sh|zsh|dash|fish|make) continue ;; esac
        kill "-$sig" "$pid" 2>/dev/null
    done
}

# The scripts themselves are bash, so they are matched by exactly how they were started instead.
enclave_script="^(/usr/bin/|/bin/)?bash [^ ]*dev-enclave\\.sh .*--name $name( |$)"
if pgrep -f -- "$enclave_script" >/dev/null; then
    pkill -INT -f -- "$enclave_script"
    # Its trap removes the containers; give it the chance before doing it by force.
    for _ in $(seq 20); do pgrep -f -- "$enclave_script" >/dev/null || break; sleep 1; done
fi
pkill -f -- "^(/usr/bin/|/bin/)?bash [^ ]*scripts/up-enclave\\.sh$"

containers="$(docker ps -aq --filter "label=enclave-harness=$name")"
if [[ -n "$containers" ]]; then
    # shellcheck disable=SC2086
    docker rm -f $containers >/dev/null
fi
# Host helpers carry no label, but each names the run directory on its command line.
signal TERM "qemu-nitro/$name/"
signal TERM "heartbeat.py 9000"
echo "enclave $name stopped"
