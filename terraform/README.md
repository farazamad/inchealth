# Terraform — hardened PHI infrastructure

Reusable modules that provision PHI data stores secure by construction, plus a
secure and an intentionally-insecure example that `phi-scan` grades.

## Modules

- **`modules/phi-bucket`** — an S3 bucket for PHI: customer-managed KMS
  encryption with key rotation, public-access block, TLS-only bucket policy,
  versioning, access logging, and an always-set `data_classification = phi` tag.
- **`modules/least-priv-role`** — an IAM role scoped to read specific PHI buckets
  and decrypt with their KMS keys (never `*:*`), assumable only with MFA and with
  a short max session duration — designed to be brokered by the JIT service.

## Examples

- **`examples/secure`** — composes the modules; `phi-scan` reports no blocking
  findings.
- **`examples/insecure`** — a catalogue of PHI-leaking mistakes for demonstration.
  **Do not deploy.**

## Producing a plan for the scanner

```bash
cd examples/secure     # or examples/insecure
terraform init
terraform plan -out tfplan
terraform show -json tfplan > plan.json
phi-scan -plan plan.json -fail-on high
```

No AWS credentials? Pre-generated plan fixtures equivalent to these examples are
committed at [`../scanner/testdata/`](../scanner/testdata/) so the scanner and
its tests run offline.

> These configs use fictional account IDs and placeholder names. The insecure
> example hardcodes a password purely to illustrate the anti-pattern — real
> deployments source secrets from AWS Secrets Manager.
