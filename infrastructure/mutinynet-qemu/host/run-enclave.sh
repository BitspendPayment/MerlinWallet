#!/bin/bash
# The MutinyNet enclave, from what deploy.sh shipped. Run by merlin-enclave.service.
#
# Everything about the image — domain, CA, relying party, origins, egress, the guest's environment,
# Firebase — was fixed when the bundle was packed (deploy.sh). What is decided here is only how this
# host runs it.
set -euo pipefail
root=/srv/merlin

export WORK="$root/work"
export QEMU_IMAGE=s3fs-qemu-nitro:slim
# Let's Encrypt over the internet, on a 2-vCPU host: slower than Pebble on a laptop.
export TIMEOUT=600

exec "$root/er/deploy/qemu-nitro/dev-enclave.sh" \
    --prebuilt "$root/bundle" \
    --guest "$root/guest/cosigner.wasm" \
    --name mutinynet \
    --port 443 \
    --keep-store \
    --memory 1536M \
    --store-bind 127.0.0.1 \
    --publish-hook "$root/host/publish-pins.sh"
