variable "role_name" {
  description = "Name of the IAM role."
  type        = string
}

variable "trusted_principal_arns" {
  description = "Principals allowed to assume this role (e.g. the JIT broker's execution role)."
  type        = list(string)
}

variable "bucket_arns" {
  description = "PHI bucket ARNs this role may read."
  type        = list(string)
}

variable "kms_key_arns" {
  description = "KMS key ARNs this role may use to decrypt PHI."
  type        = list(string)
}

variable "max_session_duration" {
  description = "Maximum assumed-role session length in seconds (JIT keeps this short)."
  type        = number
  default     = 3600
}
