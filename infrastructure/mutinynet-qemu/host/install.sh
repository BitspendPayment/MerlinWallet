#!/bin/bash
# Install what `deploy.sh` shipped, and (re)start the enclave. Run as root, by SSM or first boot.
#
#   artifacts/host/      this script, the enclave runner, the pins publisher, the systemd units
#   artifacts/er/        enclave-runtime's harness: deploy/qemu-nitro and scripts/minio-up.sh
#   artifacts/bundle/    `dev-enclave.sh --pack`: the image and every host binary
#   artifacts/guest/     cosigner.wasm
#   artifacts/images/    docker images, gzipped, each named by its image id
set -euo pipefail
export PATH="$PATH:/snap/bin"

bucket="$(cat /etc/merlin-bucket)"
root=/srv/merlin
src="s3://$bucket/artifacts"

# --exact-timestamps: by default a download skips any file the same size as the local copy, and two
# enclave images differing in one setting — staging CA or production — can be exactly the same size.
# That once left a host serving the staging image after a production deploy.
sync() { aws s3 sync --delete --exact-timestamps --only-show-errors "$src/$1/" "$root/$1/"; }
sync host
sync er
sync bundle
sync guest
sync images
chmod +x "$root"/host/*.sh "$root"/er/deploy/qemu-nitro/*.sh "$root"/er/deploy/qemu-nitro/*.py \
    "$root"/er/scripts/*.sh "$root"/bundle/bin/*

# Loaded only when new: an image is named by its id, and loading 700 MB to find it unchanged is
# the slow part of a deploy.
for archive in "$root"/images/*.tar.gz; do
    id="$(basename "$archive" .tar.gz)"
    docker image inspect "sha256:$id" >/dev/null 2>&1 || gunzip -c "$archive" | docker load
done
docker tag "$(cat "$root/images/qemu.id")" s3fs-qemu-nitro:slim

# The snap-packaged AWS CLI refuses to run for a user whose home is outside /home, which is where
# publish-pins.sh needs it. Hosts first booted with /srv/merlin as that home are moved.
if [[ "$(getent passwd merlin | cut -d: -f6)" != /home/merlin ]]; then
    systemctl stop merlin-enclave.service || true
    install -d -o merlin -g merlin /home/merlin
    usermod -d /home/merlin merlin
fi

install -m 0644 "$root/host/merlin-enclave.service"         /etc/systemd/system/
install -m 0644 "$root/host/merlin-enclave-restart.service" /etc/systemd/system/
install -m 0644 "$root/host/merlin-enclave-restart.timer"   /etc/systemd/system/
chown -R merlin:merlin "$root"
systemctl daemon-reload
systemctl enable --now merlin-enclave-restart.timer
systemctl enable merlin-enclave.service
systemctl restart merlin-enclave.service
echo "installed $(cat "$root/bundle/release.env" | tr '\n' ' ')"
