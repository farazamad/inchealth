# Secure example: a PHI data store composed from the hardened modules.
# `phi-scan` reports zero blocking findings against this configuration.
#
#   terraform init && terraform plan -out tfplan
#   terraform show -json tfplan > secure.plan.json
#   phi-scan -plan secure.plan.json -fail-on high

terraform {
  required_version = ">= 1.5"
  required_providers {
    aws = { source = "hashicorp/aws", version = ">= 5.0" }
  }
}

provider "aws" {
  region = "us-east-1"
}

variable "jit_broker_role_arn" {
  description = "Execution role ARN of the JIT access broker permitted to assume the PHI role."
  type        = string
  default     = "arn:aws:iam::111122223333:role/phi-guardian-jit-broker"
}

module "phi_exports" {
  source            = "../../modules/phi-bucket"
  bucket_name       = "ih-phi-exports-prod"
  access_log_bucket = "ih-access-logs-prod"
  tags              = { team = "data-platform" }
}

module "phi_reader_role" {
  source                 = "../../modules/least-priv-role"
  role_name              = "phi-exports-reader"
  trusted_principal_arns = [var.jit_broker_role_arn]
  bucket_arns            = [module.phi_exports.bucket_arn]
  kms_key_arns           = [module.phi_exports.kms_key_arn]
  max_session_duration   = 3600
}
