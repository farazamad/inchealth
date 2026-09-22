# least-priv-role: an IAM role scoped to read a specific set of PHI bucket
# prefixes and decrypt with their KMS key — never Action:* on Resource:*.
# Intended to be assumed via the JIT access broker for a bounded session.

terraform {
  required_version = ">= 1.5"
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = ">= 5.0"
    }
  }
}

data "aws_iam_policy_document" "assume" {
  statement {
    effect  = "Allow"
    actions = ["sts:AssumeRole"]
    principals {
      type        = "AWS"
      identifiers = var.trusted_principal_arns
    }
    # Require MFA for assuming a PHI-scoped role.
    condition {
      test     = "Bool"
      variable = "aws:MultiFactorAuthPresent"
      values   = ["true"]
    }
  }
}

resource "aws_iam_role" "this" {
  name                 = var.role_name
  assume_role_policy   = data.aws_iam_policy_document.assume.json
  max_session_duration = var.max_session_duration
  tags                 = { data_classification = "phi", managed_by = "terraform" }
}

data "aws_iam_policy_document" "access" {
  statement {
    sid    = "ReadPHIObjects"
    effect = "Allow"
    actions = ["s3:GetObject", "s3:ListBucket"]
    resources = concat(
      var.bucket_arns,
      [for arn in var.bucket_arns : "${arn}/*"],
    )
  }

  statement {
    sid       = "DecryptPHI"
    effect    = "Allow"
    actions   = ["kms:Decrypt", "kms:DescribeKey"]
    resources = var.kms_key_arns
  }
}

resource "aws_iam_role_policy" "this" {
  name   = "${var.role_name}-access"
  role   = aws_iam_role.this.id
  policy = data.aws_iam_policy_document.access.json
}
