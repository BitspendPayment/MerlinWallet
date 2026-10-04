#!/usr/bin/env bash
# Deploy the cosigner to the MutinyNet enclave host. Run on a build machine, from anywhere.
#
#   infrastructure/mutinynet-qemu/deploy.sh [--staging]
#
# Builds here, runs there: the host has no Nix, no cargo and no checkout. This builds the cosigner
# and writes MutinyNet's settings into it, packs the enclave image (`dev-enclave.sh --pack`), ships
# everything to the stack's bucket, and has the instance install it and restart over SSM. Tenants
# resume — the store is on its own volume — and the new measurements and trust root are published
# to pins/ once the enclave is serving.
#
#   --staging   certificates from Let's Encrypt's staging CA. For a first deploy, or after changing
#               the domain: it proves issuance without spending the production rate limit (five
#               duplicate certificates a week). Nothing trusts a staging certificate, so the app
#               cannot use the host until a deploy without it.
#
# Needs: the stack applied (tofu/) and its push application's FCM channel loaded (README), the AWS
# profile, and enclave-runtime at $ENCLAVE_RUNTIME with its QEMU image built. No Firebase key: it
# lives on the push application's channel, in AWS.
set -euo pipefail

here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
repo="$(cd "$here/../.." && pwd)"
runtime="${ENCLAVE_RUNTIME:-$HOME/enclave-runtime}"
export AWS_PROFILE="${AWS_PROFILE:-mpc-deployer}"
export AWS_REGION="${AWS_REGION:-us-east-1}"

staging=()
case "${1:-}" in
    --staging) staging=(--acme-staging) ;;
    "") ;;
    *) echo "usage: ${0##*/} [--staging]" >&2; exit 2 ;;
esac

[[ -x "$runtime/deploy/qemu-nitro/dev-enclave.sh" ]] \
    || { echo "no enclave-runtime at $runtime — set ENCLAVE_RUNTIME" >&2; exit 1; }
bucket="$(tofu -chdir="$here/tofu" output -raw bucket)"
instance="$(tofu -chdir="$here/tofu" output -raw instance_id)"
push_app_id="$(tofu -chdir="$here/tofu" output -raw push_app_id)"

# --- What MutinyNet's image is ---------------------------------------------------------------------
#
# All of it is baked into the image, so all of it is PCR0: change any and the app's pins change with
# the next boot, which publishes them.
domain=mutiny.vtxos.network
image_args=(
    --domain "$domain" "${staging[@]}"
    # Passkeys for vtxos.com, whose assetlinks.json names com.vtxos.app; the app claims its signing
    # key's hash as its origin. The debug keystore (2D:FD:50:23…) and the release key (BB:5A:4D:7A…),
    # as in scripts/up-enclave.sh.
    --rp-id vtxos.com
    --allowed-origin android:apk-key-hash:Lf1QIwQnlPBYPwDFhloUkYC-0tYAKSpKCQbEiyz118s
    --allowed-origin android:apk-key-hash:u1pNepeObJUpSkSqH964HvFRqbhC_ejQP3GHA3-lreI
    # Wakes through this stack's push application, signed as the host's role.
    --push-app-id "$push_app_id"
)

# --- What MutinyNet's cosigner is ---------------------------------------------------------------
#
# Written into the cosigner's file before it ships, so the enclave measures them into PCR16 with its
# code. It runs sealed delegates itself, against arkade's ASP, from background tasks that wait on a
# batch round. The renewal margin is the cosigner's default (1800s).
asp=https://mutinynet.arkade.sh
guest_settings=("ASP_URL=$asp" BITCOIN_NETWORK=mutinynet)
docker image inspect s3fs-qemu-nitro:latest >/dev/null 2>&1 \
    || { echo "build the QEMU image first: docker build -t s3fs-qemu-nitro:latest $runtime/deploy/qemu-nitro" >&2; exit 1; }

say() { printf '\n== %s ==\n' "$*"; }

out="$(mktemp -d)"
trap 'rm -rf "$out"' EXIT

say "building the cosigner"
make -C "$repo" cosigner-wasm
mkdir -p "$out/guest"
cp "$repo/cosigner/target/wasm32-wasip2/release/cosigner.wasm" "$out/guest/"
python3 "$runtime/deploy/qemu-nitro/guest-env.py" "$out/guest/cosigner.wasm" "${guest_settings[@]}"

say "packing the enclave image"
"$runtime/deploy/qemu-nitro/dev-enclave.sh" --name mutinynet-pack --pack "$out/bundle" "${image_args[@]}"
commit() { git -C "$1" rev-parse --short HEAD 2>/dev/null | tr -d '\n'; git -C "$1" diff --quiet HEAD 2>/dev/null || printf -- '-dirty'; }
{
    printf 'MERLIN_COMMIT=%q\n' "$(commit "$repo")"
    printf 'RUNTIME_COMMIT=%q\n' "$(commit "$runtime")"
} > "$out/bundle/release.env"

say "the harness and the host scripts"
mkdir -p "$out/er/deploy" "$out/er/scripts"
rsync -a --exclude __pycache__ "$runtime/deploy/qemu-nitro" "$out/er/deploy/"
cp "$runtime/scripts/minio-up.sh" "$out/er/scripts/"
cp -r "$here/host" "$out/host"

say "container images"
docker build -q -t s3fs-qemu-nitro:slim -f "$here/qemu-slim.Dockerfile" "$here" >/dev/null
mkdir -p "$out/images"
docker image inspect -f '{{.Id}}' s3fs-qemu-nitro:slim > "$out/images/qemu.id"
existing="$(aws s3 ls "s3://$bucket/artifacts/images/" 2>/dev/null | awk '{print $4}' || true)"
for image in s3fs-qemu-nitro:slim minio/minio:latest minio/mc:latest; do
    id="$(docker image inspect -f '{{.Id}}' "$image")"; id="${id#sha256:}"
    if grep -qx "$id.tar.gz" <<<"$existing"; then
        echo "$image already shipped"
        # Kept by name so the sync below, with --delete, does not remove it.
        aws s3 cp --quiet "s3://$bucket/artifacts/images/$id.tar.gz" "$out/images/$id.tar.gz"
    else
        echo "$image: saving"
        docker save "$image" | gzip -1 > "$out/images/$id.tar.gz"
    fi
done

say "uploading to s3://$bucket/artifacts"
for part in host er bundle guest images; do
    aws s3 sync --delete --only-show-errors "$out/$part/" "s3://$bucket/artifacts/$part/"
done

say "installing on $instance"
started="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
command_id="$(aws ssm send-command \
    --instance-ids "$instance" \
    --document-name AWS-RunShellScript \
    --comment "merlin deploy $(commit "$repo")" \
    --parameters "commands=[\"export PATH=\$PATH:/snap/bin\",\"aws s3 cp s3://$bucket/artifacts/host/install.sh /usr/local/sbin/merlin-install\",\"chmod 755 /usr/local/sbin/merlin-install\",\"/usr/local/sbin/merlin-install\"]" \
    --timeout-seconds 1800 \
    --query Command.CommandId --output text)"
aws ssm wait command-executed --command-id "$command_id" --instance-id "$instance" || true
aws ssm get-command-invocation --command-id "$command_id" --instance-id "$instance" \
    --query '[Status, StandardOutputContent, StandardErrorContent]' --output text | tail -20

say "waiting for the enclave to publish its pins"
pins="https://$bucket.s3.amazonaws.com/pins/deployment.json"
for _ in $(seq 120); do
    stamp="$(curl -sf "$pins" | jq -r .timestamp 2>/dev/null || true)"
    if [[ -n "$stamp" && "$stamp" > "$started" ]]; then
        curl -sf "$pins" | jq '{host, pcr0: .pcr0[0:16], pcr16: .pcr16[0:16], commit, timestamp}'
        echo "serving: https://$domain"
        exit 0
    fi
    sleep 10
done
echo "no new pins after 20 minutes; see the host's journal:" >&2
echo "  aws ssm start-session --target $instance   then   journalctl -u merlin-enclave -n 100" >&2
exit 1
