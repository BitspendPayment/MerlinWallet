# Host-mode cosigner deployment.
#
# The runtime runs as an ordinary systemd service on an EC2 instance, with its
# SQLite KV on a dedicated EBS volume and Caddy terminating TLS in front of it.
# There is NO Nitro enclave here — that is the whole point of this stack. The
# app waives attestation for this deployment's hostname (see the waiver list in
# `app/lib/services/server_host.dart`); mainnet must never be served this way.
#
# State that must survive an instance replacement lives on the data volume:
#   /mnt/data/cosigner/state.db   the KV, including each actor's sealed share
#   /mnt/data/caddy/              Caddy's ACME certs + account key
# Keeping the certs there is not just tidiness — re-issuing on every replace
# would burn Let's Encrypt's duplicate-certificate rate limit.

terraform {
  required_version = ">= 1.6.0"
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 5.0"
    }
  }
}

locals {
  name = "${var.deployment}-${var.app_name}"

  # The runtime's non-secret environment. Written to SSM and pulled at boot, so
  # changing one of these is an SSM write + service restart, never a rebuild.
  #
  # BITCOIN_NETWORK is only a display/HRP hint — the authoritative network comes
  # from the ASP's GetArkInfo. "mutinynet" is in the runtime's accepted set, and
  # the app maps it to BitcoinNetwork.signet the same as "signet".
  #
  # The WebAuthn RP ID is deliberately NOT this deployment's hostname. A passkey
  # is scoped to the RP ID, so pointing it at `mutiny.vtxos.network` would orphan
  # every credential already registered under `vtxos.com`. It also does not need
  # to match the API host — the cosigner is its own Relying Party, and Android's
  # Credential Manager verifies association by fetching
  # https://<rp_id>/.well-known/assetlinks.json (live at vtxos.com), not by any
  # same-origin check against the REST endpoint. Regtest already runs this way:
  # server on 127.0.0.1, RP ID vtxos.com (see the `software` target in Makefile).
  base_env = {
    BITCOIN_NETWORK        = "mutinynet"
    ASP_URL                = var.asp_url
    ESPLORA_URL            = var.esplora_url
    PORT                   = tostring(var.app_port)
    SQLITE_PATH            = "${var.data_mount}/cosigner/state.db"
    WEBAUTH_RP_ID          = var.webauthn_rp_id
    WEBAUTH_RP_ORIGIN      = var.webauthn_rp_origin
    WEBAUTH_RP_NAME        = var.webauthn_rp_name
    WEBAUTH_ANDROID_ORIGIN = var.webauthn_android_origin
  }

  env_values = merge(local.base_env, var.env_overrides)
}

data "aws_availability_zones" "available" {
  state = "available"
}

# Amazon Linux 2023, x86_64. Matched to the Caddy/binary architecture below.
data "aws_ami" "al2023" {
  most_recent = true
  owners      = ["amazon"]

  filter {
    name   = "name"
    values = ["al2023-ami-2023.*-kernel-6.1-x86_64"]
  }

  filter {
    name   = "architecture"
    values = ["x86_64"]
  }
}

# =============================================================================
# Network
# =============================================================================

resource "aws_vpc" "main" {
  cidr_block           = "10.20.0.0/16"
  enable_dns_support   = true
  enable_dns_hostnames = true

  tags = { Name = local.name }
}

resource "aws_internet_gateway" "main" {
  vpc_id = aws_vpc.main.id
  tags   = { Name = local.name }
}

resource "aws_subnet" "public" {
  vpc_id                  = aws_vpc.main.id
  cidr_block              = "10.20.1.0/24"
  availability_zone       = data.aws_availability_zones.available.names[0]
  map_public_ip_on_launch = true

  tags = { Name = "${local.name}-public" }
}

resource "aws_route_table" "public" {
  vpc_id = aws_vpc.main.id

  route {
    cidr_block = "0.0.0.0/0"
    gateway_id = aws_internet_gateway.main.id
  }

  tags = { Name = "${local.name}-public" }
}

resource "aws_route_table_association" "public" {
  subnet_id      = aws_subnet.public.id
  route_table_id = aws_route_table.public.id
}

# Only 80 and 443 are exposed. The runtime's own port is never published — Caddy
# reaches it on loopback. Shell access is via SSM Session Manager, so there is
# no SSH ingress and no key pair to manage.
resource "aws_security_group" "host" {
  name_prefix = "${local.name}-"
  description = "cosigner host: public HTTPS via Caddy"
  vpc_id      = aws_vpc.main.id

  # HTTP is required for the ACME http-01 challenge and for the ->HTTPS redirect.
  ingress {
    description = "HTTP (ACME challenge + redirect)"
    from_port   = 80
    to_port     = 80
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }

  ingress {
    description = "HTTPS"
    from_port   = 443
    to_port     = 443
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }

  egress {
    description = "All outbound (ASP, esplora, FCM, ACME, S3, SSM)"
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }

  lifecycle {
    create_before_destroy = true
  }
}

resource "aws_eip" "host" {
  domain = "vpc"
  tags   = { Name = local.name }
}

# =============================================================================
# IAM
# =============================================================================

resource "aws_iam_role" "instance" {
  name_prefix = "${local.name}-"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect    = "Allow"
      Action    = "sts:AssumeRole"
      Principal = { Service = "ec2.amazonaws.com" }
    }]
  })
}

resource "aws_iam_instance_profile" "instance" {
  name_prefix = "${local.name}-"
  role        = aws_iam_role.instance.name
}

# Enables SSM Session Manager (shell access without SSH) and the send-command
# redeploy path used when only the binary changed.
resource "aws_iam_role_policy_attachment" "ssm_core" {
  role       = aws_iam_role.instance.name
  policy_arn = "arn:aws:iam::aws:policy/AmazonSSMManagedInstanceCore"
}

data "aws_iam_policy_document" "instance" {
  statement {
    sid       = "ReadDeploymentAssets"
    effect    = "Allow"
    actions   = ["s3:GetObject"]
    resources = ["${aws_s3_bucket.assets.arn}/*"]
  }

  statement {
    sid       = "ListDeploymentAssets"
    effect    = "Allow"
    actions   = ["s3:ListBucket"]
    resources = [aws_s3_bucket.assets.arn]
  }

  # Scoped to this deployment's parameter path only.
  statement {
    sid    = "ReadRuntimeConfig"
    effect = "Allow"
    actions = [
      "ssm:GetParameter",
      "ssm:GetParameters",
      "ssm:GetParametersByPath",
    ]
    resources = [
      "arn:aws:ssm:${var.region}:${var.account}:parameter${local.ssm_prefix}",
      "arn:aws:ssm:${var.region}:${var.account}:parameter${local.ssm_prefix}/*",
    ]
  }

  # SecureString parameters are sealed with the account's SSM-managed key.
  statement {
    sid       = "DecryptSecureStrings"
    effect    = "Allow"
    actions   = ["kms:Decrypt"]
    resources = ["arn:aws:kms:${var.region}:${var.account}:key/*"]

    condition {
      test     = "StringEquals"
      variable = "kms:ViaService"
      values   = ["ssm.${var.region}.amazonaws.com"]
    }
  }
}

resource "aws_iam_role_policy" "instance" {
  name_prefix = "runtime-access-"
  role        = aws_iam_role.instance.id
  policy      = data.aws_iam_policy_document.instance.json
}

# =============================================================================
# Deployment assets (the runtime binary)
# =============================================================================

resource "aws_s3_bucket" "assets" {
  bucket_prefix = "${local.name}-assets-"
  force_destroy = true
}

resource "aws_s3_bucket_public_access_block" "assets" {
  bucket = aws_s3_bucket.assets.id

  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

resource "aws_s3_bucket_server_side_encryption_configuration" "assets" {
  bucket = aws_s3_bucket.assets.id

  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm = "AES256"
    }
  }
}

resource "aws_s3_object" "runtime" {
  bucket = aws_s3_bucket.assets.id
  key    = "cosigner"
  source = var.binary_path

  # Re-uploads whenever the local build changes; also the trigger for the
  # in-place redeploy below.
  #
  # source_hash, NOT etag. The binary is ~49 MB, so the provider uploads it in
  # parts and S3 returns "<hash-of-part-hashes>-<part-count>", which is not the
  # file's MD5. With `etag = filemd5(...)` terraform plans the MD5, gets the
  # multipart form back, and aborts with "Provider produced inconsistent final
  # plan" — identically on every retry, since the mismatch is recomputed each
  # time. source_hash triggers the same re-upload without being checked against
  # what S3 returns.
  source_hash = filemd5(var.binary_path)
}

# =============================================================================
# Runtime configuration in SSM
# =============================================================================

locals {
  ssm_prefix = "/${var.deployment}/${var.app_name}"
}

resource "aws_ssm_parameter" "env" {
  for_each = local.env_values

  name = "${local.ssm_prefix}/env/${each.key}"
  type = "String"

  # systemd's EnvironmentFile has no line continuation, so a value must be one
  # line. Stripping raw CR/LF is safe for what goes here: JSON documents are
  # unaffected (a raw newline can't appear inside a JSON string — it must be
  # escaped as \n), and any other value with an embedded newline would simply
  # be unparseable on the far side.
  value = replace(replace(each.value, "\r", ""), "\n", "")

  tier = length(each.value) > 4096 ? "Advanced" : "Standard"
}

# Values with custody or push-auth blast radius. SecureString keeps them
# encrypted at rest and out of plain `ssm:GetParameter` without kms:Decrypt.
resource "aws_ssm_parameter" "secret_env" {
  # A sensitive map can't drive for_each — the keys would show up as resource
  # addresses in state and plan output. Only the VALUES are secret here (the
  # keys are just env var names), so unwrap the key set and look values up.
  for_each = nonsensitive(toset(keys(var.secret_env)))

  name = "${local.ssm_prefix}/env/${each.value}"
  type = "SecureString"

  # Same single-line requirement as above. This matters most for
  # FCM_SERVICE_ACCOUNT_JSON, which is usually pretty-printed on disk.
  value = replace(replace(var.secret_env[each.value], "\r", ""), "\n", "")

  tier = length(var.secret_env[each.value]) > 4096 ? "Advanced" : "Standard"

  # Guard against a silent delete. `secret_env` defaults to {}, so an apply run
  # without secrets.auto.tfvars.json — renamed, or a second operator once state
  # is shared — makes this for_each empty and plans a DESTROY. That deletes
  # WEBAUTH_TOKEN_SECRET, and the next boot rewrites /etc/cosigner/env without
  # it (cosigner-env.sh replaces the file wholesale), leaving the runtime on
  # "Session-token auth DISABLED" — which rejects every passkey-gated wallet,
  # since those authenticate by session token with an empty Schnorr signature.
  #
  # Nothing else here fails that way: the String parameters are driven by
  # base_env, which is code and cannot go missing. Only the secrets can
  # evaporate, and only from a routine `tofu apply` — the same command the
  # README gives for shipping a new binary, where a stray "1 to destroy" is
  # easy to scroll past.
  #
  # So fail the plan loudly instead. To remove a key deliberately (dropping
  # FCM, say), delete this block first — same convention as the data volume.
  lifecycle {
    prevent_destroy = true
  }
}

# =============================================================================
# Data volume
# =============================================================================

# Deliberately a separate volume, not extra root capacity: an instance replace
# (new AMI, new binary, resize) must not take the sealed shares with it.
resource "aws_ebs_volume" "data" {
  availability_zone = aws_subnet.public.availability_zone
  size              = var.data_volume_size
  type              = "gp3"
  encrypted         = true

  tags = { Name = "${local.name}-data" }

  lifecycle {
    # Destroying this volume destroys every wallet's server-side share, which
    # makes those wallets permanently unspendable — 2-of-2 needs both halves.
    # `prevent_destroy` must be a literal, so a deliberate teardown means
    # deleting these three lines (or `tofu state rm` first). That friction is
    # the point; see the teardown section of the README.
    prevent_destroy = true
  }
}

resource "aws_volume_attachment" "data" {
  device_name = "/dev/sdf"
  volume_id   = aws_ebs_volume.data.id
  instance_id = aws_instance.host.id

  # Let the instance be replaced without terraform trying to force-detach a
  # busy volume; the replacement re-attaches and remounts by volume ID.
  stop_instance_before_detaching = true
}

# =============================================================================
# Instance
# =============================================================================

resource "aws_instance" "host" {
  ami                    = data.aws_ami.al2023.id
  instance_type          = var.instance_type
  subnet_id              = aws_subnet.public.id
  vpc_security_group_ids = [aws_security_group.host.id]
  iam_instance_profile   = aws_iam_instance_profile.instance.name

  root_block_device {
    volume_size           = var.root_volume_size
    volume_type           = "gp3"
    encrypted             = true
    delete_on_termination = true
  }

  user_data = templatefile("${path.module}/templates/user_data.sh.tftpl", {
    region         = var.region
    ssm_prefix     = local.ssm_prefix
    binary_s3_url  = "s3://${aws_s3_bucket.assets.id}/${aws_s3_object.runtime.key}"
    data_volume_id = aws_ebs_volume.data.id
    data_mount     = var.data_mount
    app_port       = var.app_port
    fqdn           = var.fqdn
    acme_email     = var.acme_email
    caddy_version  = var.caddy_version
    caddy_sha512   = var.caddy_sha512
  })

  # Bootstrap changes (mount layout, Caddy version, unit files) only take effect
  # on a fresh boot. A binary-only change does NOT land here — that is handled
  # in place by the redeploy below, so routine deploys don't replace the host.
  user_data_replace_on_change = true

  tags = { Name = local.name }

  lifecycle {
    ignore_changes = [ami]
  }
}

resource "aws_eip_association" "host" {
  instance_id   = aws_instance.host.id
  allocation_id = aws_eip.host.id
}

# =============================================================================
# DNS
# =============================================================================

# Caddy cannot complete an ACME challenge until this resolves, so it must exist
# before the instance finishes booting. The dependency is implicit through the
# EIP, which is allocated before the instance is created.
resource "aws_route53_record" "app" {
  count = var.route53_zone_id == "" ? 0 : 1

  zone_id = var.route53_zone_id
  name    = var.fqdn
  type    = "A"
  ttl     = 60
  records = [aws_eip.host.public_ip]
}

# =============================================================================
# In-place redeploy
# =============================================================================

# A new binary alone should not cost a new instance (and a fresh ACME issuance).
# When only the S3 object changed, push the new binary onto the running host and
# restart the unit.
resource "terraform_data" "redeploy" {
  triggers_replace = {
    # Same reason as source_hash above: the object's etag is the multipart form
    # for a binary this size, so key the redeploy off the local file's hash.
    binary_hash = aws_s3_object.runtime.source_hash
    instance_id = aws_instance.host.id
  }

  depends_on = [aws_volume_attachment.data]

  provisioner "local-exec" {
    # A local-exec does not inherit the provider's credentials — it gets the
    # ambient environment. Without this the send-command would run under the
    # default profile, in an account where this instance ID does not exist.
    environment = var.aws_profile != "" ? { AWS_PROFILE = var.aws_profile } : {}

    # local-exec defaults to ["/bin/sh", "-c"], and /bin/sh is dash on Debian
    # and Ubuntu — which has no `pipefail`, so the script below aborts with
    # "Illegal option -o pipefail" before it runs anything.
    interpreter = ["/bin/bash", "-c"]

    command = <<-EOT
      set -euo pipefail
      aws ssm send-command \
        --instance-ids ${aws_instance.host.id} \
        --document-name AWS-RunShellScript \
        --region ${var.region} \
        --comment "redeploy cosigner" \
        --parameters 'commands=["/usr/local/sbin/cosigner-deploy.sh"]' \
        --output text >/dev/null
    EOT
  }
}
