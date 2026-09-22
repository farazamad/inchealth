# phi-scan

A policy-as-code scanner for Terraform plans, focused on misconfigurations that
expose PHI in AWS. Standard library only — builds and runs in air-gapped CI.

## Build & run

```bash
go build -o ../bin/phi-scan .
phi-scan -plan plan.json -fail-on high        # table output, CI gate
phi-scan -plan plan.json -format sarif        # for GitHub code scanning
phi-scan -plan plan.json -format json
phi-scan -plan plan.json -catalog ../compliance/controls.json  # annotate findings with framework IDs
phi-scan -list-rules
cat plan.json | phi-scan -plan -              # read from stdin
```

Generate the input from real Terraform:

```bash
terraform plan -out tfplan
terraform show -json tfplan > plan.json
phi-scan -plan plan.json -fail-on high
```

`-fail-on` controls the gate: the process exits `1` when any finding is at or
above the given severity (`low|medium|high|critical`), otherwise `0`.

## Rules

| ID | Severity | Checks |
|---|---|---|
| PHI-S3-001 | CRITICAL | S3 bucket has a public-access block with all four flags true |
| PHI-S3-002 | HIGH | S3 bucket encrypted with customer-managed KMS (`aws:kms`) |
| PHI-S3-003 | MEDIUM | Bucket policy denies non-TLS (`aws:SecureTransport=false`) |
| PHI-S3-004 | MEDIUM | Bucket has versioning enabled and access logging |
| PHI-IAM-001 | HIGH | No IAM policy granting `Action:*` on `Resource:*` |
| PHI-IAM-002 | MEDIUM | IAM account password policy strength (length ≥ 14 + complexity) |
| PHI-SG-001 | CRITICAL | No SG exposing SSH/RDP/DB ports to `0.0.0.0/0` |
| PHI-RDS-001 | HIGH | RDS `storage_encrypted = true` |
| PHI-RDS-002 | CRITICAL | RDS not `publicly_accessible` |
| PHI-EBS-001 | HIGH | EBS volumes encrypted |
| PHI-KMS-001 | MEDIUM | KMS key rotation enabled |
| PHI-CT-001 | HIGH | CloudTrail multi-region + log validation + KMS |
| PHI-TAG-001 | MEDIUM | Data stores carry a `data_classification` tag |

Resources tagged `data_classification = phi|restricted|pii` (or named for PHI)
are treated as in-scope for the strictest controls, so **data classification
drives the checks**.

## How matching works

The scanner reads `planned_values` from `terraform show -json`. Modern AWS S3
config is split across companion resources (`aws_s3_bucket_public_access_block`,
`..._server_side_encryption_configuration`, etc.); the scanner matches them to
their bucket on the literal `bucket` attribute. Fixtures under
[`testdata/`](testdata/) show the exact shape and drive the tests.

## Test

```bash
go vet ./... && go test ./...
```
