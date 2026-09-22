output "bucket_arn" {
  description = "ARN of the PHI bucket."
  value       = aws_s3_bucket.this.arn
}

output "bucket_name" {
  description = "Name of the PHI bucket."
  value       = aws_s3_bucket.this.bucket
}

output "kms_key_arn" {
  description = "ARN of the customer-managed KMS key encrypting the bucket."
  value       = aws_kms_key.this.arn
}
