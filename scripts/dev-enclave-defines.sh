#!/usr/bin/env bash
# Print the --dart-define flags that pin a dev enclave, for a Flutter build to talk to it.
#
#   scripts/dev-enclave-defines.sh [run-dir]
#
# A dev enclave mints a new trust root every boot and its certificate comes from Pebble, so none of
# this can be compiled in once: the app reads it from these defines (see DevEnclaveConfig in
# app/lib/services/server_host.dart). Rebuild after restarting the enclave.
set -euo pipefail

run="${1:-${ENCLAVE_RUNTIME:-$HOME/enclave-runtime}/target/qemu-nitro/merlin}"
for f in trust-root.der pebble-root.pem console.log; do
    [[ -f "$run/$f" ]] || { echo "no $f in $run — is a dev enclave up?" >&2; exit 1; }
done

# The runtime logs in colour, and the escapes land between a field name and its value.
console="$(sed 's/\x1b\[[0-9;]*m//g' "$run/console.log")"
pcr0="$(grep -o 'pcr0=[0-9a-f]\{96\}' <<<"$console" | tail -1 | cut -d= -f2)"
pcr16="$(grep -o 'pcr16=[0-9a-f]\{96\}' <<<"$console" | tail -1 | cut -d= -f2)"
[[ -n "$pcr0" && -n "$pcr16" ]] || { echo "no pcr0=/pcr16= in $run/console.log" >&2; exit 1; }
# The relying party the image was built with, as the runtime logged it at boot. The app's passkey
# must be for that one, and its origin must be one the image allows.
rp_id="$(grep -o 'rp_id="[^"]*"' <<<"$console" | tail -1 | cut -d'"' -f2)"
allowed="$(grep -o 'allowed_origins=\[[^]]*\]' <<<"$console" | tail -1)"
[[ -n "$rp_id" ]] || { echo "no rp_id= in $run/console.log" >&2; exit 1; }
if [[ "$allowed" != *android:apk-key-hash:* ]]; then
    echo "warning: this enclave's relying party is $rp_id and it allows no Android origin" \
         "(${allowed:-allowed_origins=[]}) — a phone will not be able to create or use a passkey." \
         "Boot an image built for the app; see app/lib/passkey/platform_passkey.dart." >&2
fi

printf -- '--dart-define=%s ' \
    "DEV_ENCLAVE_TRUST_ROOT_B64=$(base64 -w0 "$run/trust-root.der")" \
    "DEV_ENCLAVE_CA_B64=$(base64 -w0 "$run/pebble-root.pem")" \
    "DEV_ENCLAVE_PCR0=$pcr0" \
    "DEV_ENCLAVE_PCR16=$pcr16" \
    "DEV_ENCLAVE_RP_ID=$rp_id"
echo
