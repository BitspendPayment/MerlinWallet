# Root module for the mutinynet (signet) host-mode deployment.
#
# Separate from `infrastructure/mutiny/`, which is the Nitro-enclave stack and
# is generated/managed by the external `enclave` CLI. Keeping them apart means
# switching to the enclave later is a matter of which stack you apply, not an
# unpick of toggles inside one.
#
# THIS STACK IS FOR TESTNET ONLY. It runs the cosigner outside an enclave, so
# the sealed actor state — which contains each wallet's server-side FROST share
# — sits in plaintext SQLite on an EBS volume. The app waives attestation for
# this hostname (`app/lib/services/server_host.dart`). Mainnet must be served
# by the enclave stack, where that waiver does not apply.

terraform {
  required_version = ">= 1.6.0"

  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 5.0"
    }
  }
}

provider "aws" {
  region  = var.region
  profile = var.aws_profile != "" ? var.aws_profile : null

  # Belt and braces with aws_profile above. The default profile on a dev machine
  # is easily a different account, and nothing else here would notice: the stack
  # would be created there while the instance's IAM statements stay scoped to
  # var.account, so the role gets denied ssm:GetParametersByPath and the service
  # boots with an empty /etc/cosigner/env. Fail at plan time instead.
  allowed_account_ids = [var.account]

  default_tags {
    tags = {
      ManagedBy  = "opentofu"
      Deployment = var.deployment
      AppName    = var.app_name
      Network    = "mutinynet"
    }
  }
}

module "host" {
  source = "./modules/host"

  region      = var.region
  account     = var.account
  aws_profile = var.aws_profile
  deployment  = var.deployment
  app_name    = var.app_name

  instance_type    = var.instance_type
  data_volume_size = var.data_volume_size
  root_volume_size = var.root_volume_size

  fqdn            = var.fqdn
  acme_email      = var.acme_email
  route53_zone_id = var.route53_zone_id

  # Anchored to the stack directory rather than the process CWD, so `tofu apply`
  # works from anywhere. `filemd5` in the module would otherwise resolve a bare
  # relative path against wherever you happened to be standing.
  binary_path = var.binary_path != "" ? var.binary_path : "${path.module}/../../../cosigner/target/release/cosigner"

  asp_url     = var.asp_url
  esplora_url = var.esplora_url

  webauthn_rp_id          = var.webauthn_rp_id
  webauthn_rp_origin      = var.webauthn_rp_origin
  webauthn_rp_name        = var.webauthn_rp_name
  webauthn_android_origin = var.webauthn_android_origin

  env_overrides = var.env_overrides
  secret_env    = var.secret_env
}

# =============================================================================
# Variables
# =============================================================================

variable "region" {
  description = "AWS region."
  type        = string
  default     = "us-east-1"
}

variable "account" {
  description = "AWS account ID."
  type        = string
}

variable "aws_profile" {
  description = <<-EOT
    Named AWS profile to deploy with. Must resolve to `account` — the provider's
    allowed_account_ids check enforces it.

    Set because the default profile on the dev machine is a different account.
    Also passed to the module, so the in-place redeploy's `aws ssm send-command`
    (a local-exec, which does not inherit provider credentials) targets the same
    account as everything else.

    Empty means fall back to ambient credentials — AWS_PROFILE, instance role, CI.
  EOT
  type        = string
  default     = "mpc-deployer"
}

variable "deployment" {
  description = "Deployment prefix; first segment of the SSM namespace."
  type        = string
  default     = "mutinynet"
}

variable "app_name" {
  description = "Application name; second segment of the SSM namespace."
  type        = string
  default     = "cosigner"
}

variable "instance_type" {
  description = "EC2 instance type."
  type        = string
  default     = "t3.small"
}

variable "data_volume_size" {
  description = "Persistent data volume size, in GiB. Holds only state.db and Caddy's ACME certs."
  type        = number
  default     = 4
}

variable "root_volume_size" {
  description = "Root volume size, in GiB. 8 is the floor: EBS refuses a root smaller than the AL2023 AMI snapshot."
  type        = number
  default     = 8
}

variable "fqdn" {
  description = "Public hostname the app connects to, and the name Caddy gets a certificate for. Independent of the WebAuthn RP ID below."
  type        = string
  default     = "mutiny.vtxos.network"
}

variable "acme_email" {
  description = "Let's Encrypt account contact address."
  type        = string
  default     = "joshua@vtxos.app"
}

variable "route53_zone_id" {
  description = "Route53 zone for the A record. Empty means you manage DNS yourself."
  type        = string
  default     = "Z0182614JSFDPB9F5ALY"
}

variable "binary_path" {
  description = "Path to the release cosigner binary to deploy. Empty uses the in-repo release build."
  type        = string
  default     = ""
}

variable "asp_url" {
  description = "Ark Service Provider URL."
  type        = string
  default     = "https://mutinynet.arkade.sh"
}

variable "esplora_url" {
  description = "Esplora REST base URL for the boarding watcher."
  type        = string
  default     = "https://mutinynet.com/api"
}

variable "webauthn_rp_id" {
  description = <<-EOT
    WebAuthn Relying Party ID — the domain passkeys are scoped to.

    Deliberately NOT this deployment's hostname. Passkeys are bound to the RP ID,
    so moving it to mutiny.vtxos.network would orphan every credential already
    registered under vtxos.com. It also need not match the API host: the cosigner
    is its own Relying Party, and Android verifies association by fetching
    https://<rp_id>/.well-known/assetlinks.json — already served by vtxos.com.
  EOT
  type        = string
  default     = "vtxos.com"
}

variable "webauthn_rp_origin" {
  description = "HTTPS origin matching webauthn_rp_id."
  type        = string
  default     = "https://vtxos.com"
}

variable "webauthn_rp_name" {
  description = "Relying-party name shown in the passkey prompt."
  type        = string
  default     = "Merlin"
}

variable "webauthn_android_origin" {
  description = "Android Credential Manager origin(s), comma-separated. Defaults to both fingerprints from app/assetlinks.json, matching the Makefile's regtest target."
  type        = string
  default     = "android:apk-key-hash:u1pNepeObJUpSkSqH964HvFRqbhC_ejQP3GHA3-lreI,android:apk-key-hash:Lf1QIwQnlPBYPwDFhloUkYC-0tYAKSpKCQbEiyz118s"
}

variable "env_overrides" {
  description = "Extra/overriding plain env vars for the runtime."
  type        = map(string)
  default     = {}
}

variable "secret_env" {
  description = "SecureString env vars: WEBAUTH_TOKEN_SECRET, FCM_SERVICE_ACCOUNT_JSON. Supply via secrets.auto.tfvars.json (gitignored)."
  type        = map(string)
  default     = {}
  sensitive   = true
}

# =============================================================================
# Outputs
# =============================================================================

output "url" {
  description = "Public base URL — this is what you enter as the server host in the app."
  value       = module.host.url
}

output "elastic_ip" {
  description = "Public IP behind the A record."
  value       = module.host.elastic_ip
}

output "instance_id" {
  description = "EC2 instance ID (for `aws ssm start-session`)."
  value       = module.host.instance_id
}

output "data_volume_id" {
  description = "EBS volume holding the SQLite KV and Caddy's certs."
  value       = module.host.data_volume_id
}

output "ssm_env_path" {
  description = "SSM path holding the runtime environment."
  value       = module.host.ssm_env_path
}
