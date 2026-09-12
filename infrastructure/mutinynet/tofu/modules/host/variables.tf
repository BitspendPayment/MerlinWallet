variable "region" {
  description = "AWS region."
  type        = string
}

variable "account" {
  description = "AWS account ID. Used to scope the SSM/KMS IAM statements."
  type        = string
}

variable "aws_profile" {
  description = "Named AWS profile for the in-place redeploy's `aws ssm send-command`. That runs as a local-exec, which does NOT inherit the provider's credentials, so without this it would use the ambient default profile — a different account, where the instance ID does not exist. Empty means use ambient credentials."
  type        = string
  default     = ""
}

variable "deployment" {
  description = "Deployment prefix (e.g. \"mutinynet\"). First path segment of the SSM parameter namespace."
  type        = string
}

variable "app_name" {
  description = "Application name. Second path segment of the SSM parameter namespace."
  type        = string
}

variable "instance_type" {
  description = "EC2 instance type. No enclave here, so this only needs to fit the runtime's per-user actors."
  type        = string
  # 2 GiB is sized for what actually runs here: a Rust binary (no VM/JVM) whose KV is SQLite ON
  # DISK, whose idle actors evict via ACTOR_IDLE_THRESHOLD_SECS, and which never compiles — the
  # release binary is built elsewhere and pushed via S3 + SSM. Raise it back to t3.medium if
  # memory ever bites; it is a variable precisely so that costs an apply, not a migration.
  default = "t3.small"
}

variable "fqdn" {
  description = "Public hostname. Also the WebAuthn RP ID, so changing it invalidates every existing passkey."
  type        = string
}

variable "acme_email" {
  description = "Contact address for the Let's Encrypt account."
  type        = string
}

variable "route53_zone_id" {
  description = "Route53 zone to create the A record in. Empty means you manage DNS elsewhere — Caddy cannot get a certificate until the name resolves to the EIP."
  type        = string
  default     = ""
}

variable "binary_path" {
  description = "Local path to the release cosigner binary, uploaded to S3 and pulled by the instance at boot."
  type        = string
}

variable "webauthn_rp_id" {
  description = "WebAuthn Relying Party ID — the domain passkeys are scoped to. NOT this deployment's hostname: changing it orphans every existing credential, and Android verifies association via https://<rp_id>/.well-known/assetlinks.json, which is already live at vtxos.com."
  type        = string
  default     = "vtxos.com"
}

variable "webauthn_rp_origin" {
  description = "HTTPS origin matching webauthn_rp_id. The runtime rejects a mismatch at startup and disables WebAuthn."
  type        = string
  default     = "https://vtxos.com"
}

variable "asp_url" {
  description = "Ark Service Provider URL. The runtime refuses to boot without a reachable ASP."
  type        = string
  default     = "https://mutinynet.arkade.sh"
}

variable "esplora_url" {
  description = "Esplora REST base URL for the boarding watcher. Empty disables the watcher."
  type        = string
  default     = "https://mutinynet.com/api"
}

variable "app_port" {
  description = "Loopback port the runtime listens on behind Caddy. Never published to the internet."
  type        = number
  default     = 7074
}

variable "data_mount" {
  description = "Mount point for the persistent data volume (SQLite KV + Caddy ACME storage)."
  type        = string
  default     = "/mnt/data"
}

variable "data_volume_size" {
  description = "Size of the persistent data volume, in GiB. Holds only state.db and Caddy's ACME certs."
  type        = number
  default     = 4
}

variable "root_volume_size" {
  description = "Size of the root volume, in GiB. 8 is the floor — see below."
  type        = number
  # Do NOT lower this. EBS refuses a root volume smaller than the AMI's snapshot, and AL2023
  # ships an 8 GiB one, so 4 fails the apply with InvalidBlockDeviceMapping. Nothing persistent
  # lives here anyway — state.db and the certs are on the data volume.
  default = 8
}

variable "webauthn_rp_name" {
  description = "Human-readable relying-party name shown in the passkey prompt."
  type        = string
  default     = "Merlin"
}

variable "webauthn_android_origin" {
  description = "Android Credential Manager origin(s), `android:apk-key-hash:<b64url-sha256-of-signing-cert>`. Comma-separated list is supported (webauthn_server.rs splits on ','), so debug and release builds can share one server. Empty means https origins only, which blocks Android passkey assertions."
  type        = string

  # Both fingerprints from app/assetlinks.json, matching the `software` target
  # in the Makefile so regtest and this deployment accept the same builds.
  default = "android:apk-key-hash:u1pNepeObJUpSkSqH964HvFRqbhC_ejQP3GHA3-lreI,android:apk-key-hash:Lf1QIwQnlPBYPwDFhloUkYC-0tYAKSpKCQbEiyz118s"
}

variable "env_overrides" {
  description = "Extra (or overriding) plain environment variables for the runtime, written to SSM as String parameters."
  type        = map(string)
  default     = {}
}

variable "secret_env" {
  description = "Environment variables written to SSM as SecureString: WEBAUTH_TOKEN_SECRET, FCM_SERVICE_ACCOUNT_JSON."
  type        = map(string)
  default     = {}
  sensitive   = true
}

variable "caddy_version" {
  description = "Pinned Caddy release (no leading v)."
  type        = string
  default     = "2.11.4"
}

variable "caddy_sha512" {
  description = "SHA-512 of caddy_<version>_linux_amd64.tar.gz, from the release's checksums.txt. Verified on the instance before install."
  type        = string
  default     = "8220d1f013b6f27510247b2360c9e0ca9f018feebd82515f07635318b34ff9777ccc8fd0b6e6f2486ce3a33fe389fbb7db12d05baa474f4587509fb4f5ebf1c9"
}
