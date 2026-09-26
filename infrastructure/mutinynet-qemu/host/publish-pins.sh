#!/bin/bash
# Publish what the app pins for this boot: the image and guest measurements and the attestation
# trust root, which the emulator mints fresh on every boot. Called by dev-enclave.sh with its run
# directory once the enclave is serving.
#
# Unsigned, over HTTPS from a bucket only this instance can write — see SECURITY_FINDINGS IN-2.
# Acceptable for test coins; real Nitro pins AWS's root and never publishes one.
set -euo pipefail
export PATH="$PATH:/snap/bin"
rundir="$1"
root=/srv/merlin
bucket="$(cat /etc/merlin-bucket)"

# shellcheck source=/dev/null
source "$root/bundle/image.env"
# shellcheck source=/dev/null
source "$root/bundle/release.env"

pcr0="$(jq -r .PCR0 "$root/bundle/eif/pcr.json")"
pcr16="$("$root/bundle/bin/nitro-attest" --measure "$root/guest/cosigner.wasm" | jq -r .PCR16)"
[[ "$pcr0" =~ ^[0-9a-f]{96}$ && "$pcr16" =~ ^[0-9a-f]{96}$ ]] || { echo "bad measurements" >&2; exit 1; }
[[ -s "$rundir/trust-root.der" ]] || { echo "no trust root in $rundir" >&2; exit 1; }

jq -n \
    --arg host "$TLS_DOMAIN" \
    --arg pcr0 "$pcr0" \
    --arg pcr16 "$pcr16" \
    --arg trust_root "$(base64 -w0 "$rundir/trust-root.der")" \
    --arg rp_id "$WEBAUTHN_RP_ID" \
    --arg commit "$MERLIN_COMMIT" \
    --arg runtime_commit "$RUNTIME_COMMIT" \
    --arg timestamp "$(date -u +%Y-%m-%dT%H:%M:%SZ)" \
    '{host: $host, pcr0: $pcr0, pcr16: $pcr16, trust_root: $trust_root, rp_id: $rp_id,
      commit: $commit, runtime_commit: $runtime_commit, timestamp: $timestamp}' \
  | aws s3 cp - "s3://$bucket/pins/deployment.json" \
        --content-type application/json --cache-control "no-cache, max-age=0"
echo "published pins: pcr16 ${pcr16:0:16}…, trust root $(sha256sum "$rundir/trust-root.der" | cut -c1-16)…"
