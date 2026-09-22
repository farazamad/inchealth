variable "bucket_name" {
  description = "Globally unique S3 bucket name."
  type        = string
}

variable "access_log_bucket" {
  description = "Bucket that receives S3 server access logs."
  type        = string
}

variable "tags" {
  description = "Additional tags. data_classification=phi is always set."
  type        = map(string)
  default     = {}
}
