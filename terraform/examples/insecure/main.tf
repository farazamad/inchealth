# !!! DELIBERATELY INSECURE !!!
#
# This configuration exists only to demonstrate what `phi-scan` catches. It is
# a catalogue of the mistakes that leak PHI. DO NOT deploy it.
#
#   terraform init && terraform plan -out tfplan
#   terraform show -json tfplan > insecure.plan.json
#   phi-scan -plan insecure.plan.json      # exits non-zero
#
# A committed insecure.plan.json fixture lives in scanner/testdata/ so the demo
# runs without Terraform or AWS credentials.

terraform {
  required_version = ">= 1.5"
  required_providers {
    aws = { source = "hashicorp/aws", version = ">= 5.0" }
  }
}

provider "aws" {
  region = "us-east-1"
}

# PHI bucket with NO public-access block, NO encryption, NO TLS policy,
# NO versioning/logging. (PHI-S3-001..004)
resource "aws_s3_bucket" "phi_exports" {
  bucket = "ih-phi-exports-prod"
  tags   = { data_classification = "phi", team = "data-platform" }
}

# Wildcard admin policy. (PHI-IAM-001)
resource "aws_iam_policy" "data_admin" {
  name   = "data-admin"
  policy = jsonencode({
    Version   = "2012-10-17"
    Statement = [{ Effect = "Allow", Action = "*", Resource = "*" }]
  })
}

# PostgreSQL open to the entire internet. (PHI-SG-001)
resource "aws_security_group" "db" {
  name = "phi-db-sg"
  ingress {
    from_port   = 5432
    to_port     = 5432
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }
}

# Unencrypted, publicly accessible PHI database. (PHI-RDS-001, PHI-RDS-002)
resource "aws_db_instance" "clinical" {
  identifier          = "clinical-records"
  engine              = "postgres"
  instance_class      = "db.t3.medium"
  allocated_storage   = 20
  username            = "admin"
  password            = "changeme-in-secrets-manager"
  storage_encrypted   = false
  publicly_accessible = true
  skip_final_snapshot = true
  tags                = { data_classification = "phi" }
}

# Data store with no classification tag. (PHI-TAG-001)
resource "aws_dynamodb_table" "audit" {
  name         = "audit-events"
  billing_mode = "PAY_PER_REQUEST"
  hash_key     = "id"
  attribute {
    name = "id"
    type = "S"
  }
}
