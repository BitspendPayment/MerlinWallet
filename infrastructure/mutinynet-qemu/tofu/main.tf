# MutinyNet: the cosigner in an emulated Nitro enclave, on one small VM.
#
# QEMU's nitro-enclave machine under nested virtualisation, which EC2 offers on 8th-generation Intel
# instances only. The same image and harness as `make up-enclave`, reached at a real name with a
# Let's Encrypt certificate.
#
# Test infrastructure, not a trust boundary: whoever controls this instance can read every tenant's
# data and sign attestation documents — the emulator's master key is static and its attestation
# chain is minted inside the image. Test coins only. Production is real Nitro.
#
# What is here: the network, one instance, a data volume for the enclave's store, the DNS name, and
# a bucket with two prefixes — `artifacts/` (private; what `deploy.sh` ships) and `pins/` (public;
# the measurements and trust root the app pins, rewritten on every boot).

terraform {
  required_version = ">= 1.10"
  required_providers {
    aws = { source = "hashicorp/aws", version = "~> 6.64" }
  }

  # In S3, versioned, so the state is not one laptop's file. The bucket is created by hand once
  # (see ../README.md), since a stack cannot hold its own state bucket. `use_lockfile` is S3's
  # native lock — no DynamoDB table.
  backend "s3" {
    bucket       = "vtxos-tofu-state"
    key          = "mutinynet-qemu/terraform.tfstate"
    region       = "us-east-1"
    profile      = "mpc-deployer"
    encrypt      = true
    use_lockfile = true
  }
}

provider "aws" {
  region  = var.region
  profile = var.aws_profile
  default_tags {
    tags = { Project = "merlin", Stack = "mutinynet-qemu" }
  }
}

locals {
  name = "merlin-mutinynet"
}

# =============================================================================
# Network
# =============================================================================

resource "aws_vpc" "main" {
  cidr_block           = "10.42.0.0/16"
  enable_dns_support   = true
  enable_dns_hostnames = true
  tags                 = { Name = local.name }
}

resource "aws_internet_gateway" "main" {
  vpc_id = aws_vpc.main.id
  tags   = { Name = local.name }
}

resource "aws_subnet" "public" {
  vpc_id                  = aws_vpc.main.id
  cidr_block              = "10.42.1.0/24"
  availability_zone       = var.availability_zone
  map_public_ip_on_launch = false
  tags                    = { Name = "${local.name}-public" }
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

# 443 and nothing else. It is the service and it is Let's Encrypt's TLS-ALPN-01 challenge. There is
# no SSH: administration is SSM, and deploys arrive through the bucket.
resource "aws_security_group" "host" {
  name        = local.name
  description = "HTTPS to the enclave only"
  vpc_id      = aws_vpc.main.id

  ingress {
    description = "the enclave, and ACME validation"
    from_port   = 443
    to_port     = 443
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }

  egress {
    description = "ASP, Firebase, Lets Encrypt, package mirrors, SSM"
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }
}

# =============================================================================
# Bucket: artifacts in, pins out
# =============================================================================

resource "aws_s3_bucket" "enclave" {
  bucket        = var.bucket_name
  force_destroy = true
}

resource "aws_s3_bucket_server_side_encryption_configuration" "enclave" {
  bucket = aws_s3_bucket.enclave.id
  rule {
    apply_server_side_encryption_by_default { sse_algorithm = "AES256" }
  }
}

# Public policies allowed, ACLs not: the only public thing is what the policy below names.
resource "aws_s3_bucket_public_access_block" "enclave" {
  bucket                  = aws_s3_bucket.enclave.id
  block_public_acls       = true
  ignore_public_acls      = true
  block_public_policy     = false
  restrict_public_buckets = false
}

# The pins are public by nature — measurements and a certificate — and the app fetches them before it
# has any identity to authenticate with.
resource "aws_s3_bucket_policy" "pins_public" {
  bucket     = aws_s3_bucket.enclave.id
  depends_on = [aws_s3_bucket_public_access_block.enclave]
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Sid       = "PublicPins"
      Effect    = "Allow"
      Principal = "*"
      Action    = "s3:GetObject"
      Resource  = "${aws_s3_bucket.enclave.arn}/pins/*"
    }]
  })
}

# =============================================================================
# Instance role: SSM, read artifacts, write pins
# =============================================================================

data "aws_iam_policy_document" "assume_ec2" {
  statement {
    actions = ["sts:AssumeRole"]
    principals {
      type        = "Service"
      identifiers = ["ec2.amazonaws.com"]
    }
  }
}

resource "aws_iam_role" "host" {
  name_prefix        = "${local.name}-"
  assume_role_policy = data.aws_iam_policy_document.assume_ec2.json
}

resource "aws_iam_role_policy_attachment" "ssm_core" {
  role       = aws_iam_role.host.name
  policy_arn = "arn:aws:iam::aws:policy/AmazonSSMManagedInstanceCore"
}

data "aws_iam_policy_document" "host" {
  statement {
    sid       = "ListArtifacts"
    actions   = ["s3:ListBucket"]
    resources = [aws_s3_bucket.enclave.arn]
    condition {
      test     = "StringLike"
      variable = "s3:prefix"
      values   = ["artifacts/*"]
    }
  }
  statement {
    sid       = "ReadArtifacts"
    actions   = ["s3:GetObject"]
    resources = ["${aws_s3_bucket.enclave.arn}/artifacts/*"]
  }
  statement {
    sid       = "PublishPins"
    actions   = ["s3:PutObject"]
    resources = ["${aws_s3_bucket.enclave.arn}/pins/*"]
  }
}

resource "aws_iam_role_policy" "host" {
  role   = aws_iam_role.host.id
  policy = data.aws_iam_policy_document.host.json
}

resource "aws_iam_instance_profile" "host" {
  name_prefix = "${local.name}-"
  role        = aws_iam_role.host.name
}

# =============================================================================
# The instance, and the volume the enclave's store lives on
# =============================================================================

data "aws_ssm_parameter" "ubuntu" {
  name = "/aws/service/canonical/ubuntu/server/24.04/stable/current/amd64/hvm/ebs-gp3/ami-id"
}

# Separate from the root volume so replacing the instance — a new AMI, a resize — keeps every
# tenant. Its loss makes every MutinyNet wallet unspendable, which on test coins is an inconvenience.
resource "aws_ebs_volume" "store" {
  availability_zone = var.availability_zone
  size              = var.store_volume_gb
  type              = "gp3"
  encrypted         = true
  tags              = { Name = "${local.name}-store" }
}

resource "aws_instance" "host" {
  ami                    = data.aws_ssm_parameter.ubuntu.insecure_value
  instance_type          = var.instance_type
  subnet_id              = aws_subnet.public.id
  vpc_security_group_ids = [aws_security_group.host.id]
  iam_instance_profile   = aws_iam_instance_profile.host.name

  # KVM inside the instance, which QEMU's nitro-enclave machine needs.
  cpu_options {
    nested_virtualization = "enabled"
  }

  root_block_device {
    volume_size = var.root_volume_gb
    volume_type = "gp3"
    encrypted   = true
  }

  metadata_options {
    http_tokens                 = "required"
    http_put_response_hop_limit = 1
  }

  user_data = templatefile("${path.module}/templates/user_data.sh.tftpl", {
    bucket    = aws_s3_bucket.enclave.id
    volume_id = aws_ebs_volume.store.id
  })

  # A new AMI is not a reason to replace a running host; `tofu taint` when it is.
  lifecycle {
    ignore_changes = [ami, user_data]
  }

  tags = { Name = local.name }
}

resource "aws_volume_attachment" "store" {
  device_name = "/dev/sdf"
  volume_id   = aws_ebs_volume.store.id
  instance_id = aws_instance.host.id
}

resource "aws_eip" "host" {
  domain = "vpc"
  tags   = { Name = local.name }
}

resource "aws_eip_association" "host" {
  instance_id   = aws_instance.host.id
  allocation_id = aws_eip.host.id
}

# Before the first boot of the enclave, not after: Let's Encrypt validates by connecting to this name.
resource "aws_route53_record" "host" {
  zone_id = var.route53_zone_id
  name    = var.fqdn
  type    = "A"
  ttl     = 60
  records = [aws_eip.host.public_ip]
}
