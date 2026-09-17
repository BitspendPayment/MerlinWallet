variable "region" {
  type    = string
  default = "us-east-1"
}

variable "aws_profile" {
  type    = string
  default = "mpc-deployer"
}

variable "availability_zone" {
  type    = string
  default = "us-east-1a"
}

# 2 vCPU, 4 GiB. The enclave runs in 1536M and used ~420 MiB in the spike; MinIO ~90 MiB.
# Nested virtualisation: c8i, m8i, r8i (and flex) only.
variable "instance_type" {
  type    = string
  default = "c8i.large"
}

variable "root_volume_gb" {
  type    = number
  default = 20
}

variable "store_volume_gb" {
  type    = number
  default = 10
}

variable "bucket_name" {
  type    = string
  default = "vtxos-mutinynet-enclave"
}

variable "fqdn" {
  type    = string
  default = "mutiny.vtxos.network"
}

variable "route53_zone_id" {
  type    = string
  default = "Z0182614JSFDPB9F5ALY"
}
