# MutinyNet enclave host

The cosigner at **`mutiny.vtxos.network`**, running as a wasm guest in an **emulated** Nitro enclave
(QEMU's `nitro-enclave` machine) on one small EC2 instance. It is the same image and harness as
`make up-enclave`, with a real domain, a Let's Encrypt certificate, arkade's MutinyNet ASP and real
wakes through AWS End User Messaging Push.

> **Test coins only.** On an emulator, whoever controls the instance can read every tenant's data
> (the master key is static) and sign attestation documents (the chain is minted inside the image).
> The app's attestation checks run, but they prove the image and guest, not the hardware.
> Production is real Nitro: enclave-runtime's `deploy/tofu`.

```
phone ──https──▶ mutiny.vtxos.network:443 (EIP) ──▶ c8i.large (nested virt)
                                                     ├─ gvproxy :443 ──▶ QEMU nitro-enclave ─▶ runtime ─▶ cosigner.wasm
                                                     ├─ MinIO 127.0.0.1:9000  (the store, on its own EBS volume)
                                                     └─ publish-pins ──▶ s3://vtxos-mutinynet-enclave/pins/deployment.json
cosigner ──────────▶ https://mutinynet.arkade.sh   (runs sealed delegates itself)
runtime  ──────────▶ Let's Encrypt, AWS push (signed as the host's role) ──▶ FCM
app      ──────────▶ pins/deployment.json          (PCR0, PCR16, trust root)
```

## What is where

| | |
|---|---|
| `tofu/` | VPC, security group (443 only), `c8i.large` with nested virtualisation, a 10 GB store volume, EIP, the `mutiny.vtxos.network` A record, and the bucket (`artifacts/` private, `pins/` public). State is in `s3://vtxos-tofu-state` |
| `deploy.sh` | runs on your machine: builds, packs, uploads, installs over SSM |
| `host/` | what runs on the instance: `install.sh`, `run-enclave.sh`, `publish-pins.sh`, the systemd units |
| `qemu-slim.Dockerfile` | the QEMU image without its toolchain (~100 MB compressed instead of 3.7 GB) |
| `secrets/` | gitignored. `fcm-service-account.json`: the Firebase key for project `vtxos-7afb3`, loaded once onto the push application's FCM channel (step 2) and used nowhere else |

On the instance, everything lives in `/srv/merlin`. The enclave's store and run directory are
`/srv/merlin/work` (the EBS volume): `work/mutinynet-store` holds tenants, `work/mutinynet/console.log`
holds the enclave's log.

**Cost:** about $75/month on demand. That is a `c8i.large` ($0.094/h), 30 GB of gp3 and a public
IPv4 address.

## Step by step

### 0. Prerequisites (once per machine)

1. **AWS access:** `aws configure --profile mpc-deployer` (account 639920118099, us-east-1).
2. **OpenTofu ≥ 1.10**, `jq`, `docker`, `git`, `make`.
3. **enclave-runtime** checked out at `~/enclave-runtime` (or set `ENCLAVE_RUNTIME`), with Nix
   working. It builds the enclave image and the host binaries.
4. **The QEMU build image**, which is slow to build the first time:
   ```
   docker build -t s3fs-qemu-nitro:latest ~/enclave-runtime/deploy/qemu-nitro
   ```
5. **MinIO images** in your local Docker: `minio/minio:latest` and `minio/mc:latest`. Docker Hub no
   longer serves `minio/minio`; if they are missing, load them from wherever you have them. The
   instance never pulls them itself; deploy ships them.
6. **The Firebase key** at `infrastructure/mutinynet-qemu/secrets/fcm-service-account.json`. It is a
   service account JSON for project `vtxos-7afb3`, with messaging rights. Only step 2 reads it, to
   load it onto the push application; no image or bundle carries it.
7. **The cosigner toolchain** used by `make cosigner-wasm` (wasm32-wasip2 target, wasi-sdk).

### 1. The state bucket (once per account; already done)

A stack cannot hold its own state, so this bucket is made by hand:

```
aws s3api create-bucket --profile mpc-deployer --bucket vtxos-tofu-state
aws s3api put-bucket-versioning --profile mpc-deployer --bucket vtxos-tofu-state \
    --versioning-configuration Status=Enabled
aws s3api put-public-access-block --profile mpc-deployer --bucket vtxos-tofu-state \
    --public-access-block-configuration BlockPublicAcls=true,IgnorePublicAcls=true,BlockPublicPolicy=true,RestrictPublicBuckets=true
```

### 2. The infrastructure

```
cd infrastructure/mutinynet-qemu/tofu
tofu init
tofu plan -out plan.out      # read it
tofu apply plan.out
```

This creates the instance and points `mutiny.vtxos.network` at its Elastic IP. First boot installs
Docker, the AWS CLI, `vsock_loopback`, swap and the store volume; it takes about 3 minutes. Check it
over SSM:

```
aws ssm send-command --profile mpc-deployer --instance-ids "$(tofu output -raw instance_id)" \
    --document-name AWS-RunShellScript --parameters 'commands=["cloud-init status","ls -l /dev/kvm /dev/vsock","df -h /srv/merlin/work"]'
```

It also creates the push application wakes go through. Load its FCM channel once, from the CLI, so
the Firebase key never reaches tofu state, an image or a bundle. `TOKEN` because the channel
defaults to the legacy server key, which Google has turned off; the enclave refuses to boot
against a channel that would use it:

```
aws pinpoint update-gcm-channel --profile mpc-deployer --region us-east-1 \
    --application-id "$(tofu output -raw push_app_id)" \
    --gcm-channel-request "$(jq -n --rawfile s ../secrets/fcm-service-account.json \
        '{ServiceJson: $s, DefaultAuthenticationMethod: "TOKEN", Enabled: true}')"
```

After the first good deploy with it, rotate that Firebase key: images built before this carried it.

### 3. First deploy: prove the certificate on staging

```
infrastructure/mutinynet-qemu/deploy.sh --staging
```

`deploy.sh` then does the following:
1. Builds `cosigner.wasm` and writes MutinyNet's settings into it — arkade's ASP and
   `BITCOIN_NETWORK=mutinynet` — so the enclave measures them into PCR16 with its code.
2. Packs the enclave image with MutinyNet's configuration: domain, relying party `vtxos.com` and
   both Android signing keys, and the push application.
3. Uploads the image, the harness, the host scripts and the container images to `artifacts/`.
   Images already there are skipped.
4. Runs `install.sh` on the instance over SSM, which starts `merlin-enclave.service`.
5. Waits for the enclave to publish `pins/deployment.json`.

A staging certificate is trusted by nothing, so the app refuses this host until step 4. The point is
to see issuance work without spending production's limit of 5 duplicate certificates a week. Check
it:

```
echo | openssl s_client -connect mutiny.vtxos.network:443 -servername mutiny.vtxos.network 2>/dev/null \
    | openssl x509 -noout -issuer      # issuer contains "(STAGING)"
```

### 4. Deploy for real

```
infrastructure/mutinynet-qemu/deploy.sh
```

The image changes (production CA), so PCR0 changes. The store is kept, so any tenant created in step
3 is still there. The certificate cache is keyed by CA, so production issues its own certificate.
Check:

```
curl -sI https://mutiny.vtxos.network/auth/ | grep -i x-enclave-attestation
curl -s https://vtxos-mutinynet-enclave.s3.amazonaws.com/pins/deployment.json | jq '{host, pcr16: .pcr16[0:16], commit, timestamp}'
```

### 5. The app

A release build needs no dart-defines for this host. In the app, choose **Mutiny** on the server
screen. The app:
- fetches `pins/deployment.json` (PCR0, PCR16 and the emulator's trust root) and refuses a manifest
  for another host or relying party;
- verifies every `/auth` response against those pins;
- if a document fails because the host was redeployed or restarted, fetches the pins once more and
  re-checks the same document.

The ASP is `mutinynet.arkade.sh` and Electrum is `electrum.mutinynet.com:50001`.

## Routine operations

| task | how |
|---|---|
| **ship a new cosigner** | `deploy.sh`. Tenants resume; new pins are published once serving |
| **change image settings** (origins, ASP, env) | edit `image_args` in `deploy.sh`, then `deploy.sh` |
| **logs** | SSM: `journalctl -u merlin-enclave -n 200`, and `/srv/merlin/work/mutinynet/console.log` for the enclave itself |
| **restart** | SSM: `systemctl restart merlin-enclave`. The store is kept; a new trust root is published |
| **scheduled restart** | `merlin-enclave-restart.timer`, on the 1st and 15th. The emulator's attestation chain is valid 30 days |
| **start over with empty tenants** | SSM: `systemctl stop merlin-enclave && rm -rf /srv/merlin/work/mutinynet-store && systemctl start merlin-enclave`. Every MutinyNet wallet becomes unspendable |
| **a shell** | `aws ssm start-session --target <instance>`, which needs the Session Manager plugin locally. `send-command` works without it |
| **replace the instance** | `tofu apply -replace=aws_instance.host`. The store volume is reattached, and first boot reinstalls from `artifacts/` |
| **tear down** | `tofu destroy`, which deletes the bucket (force_destroy) and the store |

## When something is wrong

| symptom | look at |
|---|---|
| `deploy.sh` waits and no new pins appear | `journalctl -u merlin-enclave`. The harness prints which step it is waiting on |
| certificate never issued | DNS for `mutiny.vtxos.network` must be the EIP; port 443 must be open. `grep -i acme work/mutinynet/console.log` |
| `too many certificates already issued` | Let's Encrypt's weekly limit. Wait, or deploy with `--staging` meanwhile |
| app: `attestation refused` | pins stale or wrong: compare `pins/deployment.json` with `console.log` (`pcr16=`, `trust_root=`) |
| app: passkey refused | the image's `--rp-id` and `--allowed-origin` in `deploy.sh`, against the APK's signing key hash |
| delegates never run | `console.log` for the cosigner's requests to `mutinynet.arkade.sh`, and its `ASP_URL` (the settings `deploy.sh` wrote) |
| boot refused: the push application cannot deliver | the FCM channel (step 2): `aws pinpoint get-gcm-channel --application-id …` must say `Enabled`, `HasFcmServiceCredentials` and `TOKEN` |
| out of memory | `run-enclave.sh --memory` (1536M) and `free -m`; the instance has 2 GB of swap |
