# Threat model — PHI exfiltration

A lightweight STRIDE-flavored model focused on the one outcome that matters most
in a HIPAA cloud: **unauthorized exfiltration of PHI**.

## Assets

- **PHI at rest** — S3 objects, RDS/DynamoDB rows containing member/patient data.
- **Access paths** — IAM roles, security groups, bucket policies, KMS keys.
- **Audit evidence** — CloudTrail, S3 access logs, the JIT audit trail.

## Trust boundaries

- Internet ↔ VPC edge (security groups, public buckets).
- Human/service identity ↔ production data (IAM, JIT grants).
- One AWS account ↔ another (cross-account copy, replication).

## Threats and controls

| # | Threat | Vector | Control in this repo |
|---|---|---|---|
| T1 | Public PHI bucket | S3 without public-access block / bucket ACL | `phi-scan` **PHI-S3-001**; `phi-bucket` module blocks public access |
| T2 | PHI readable in transit | non-TLS access | `phi-scan` **PHI-S3-003**; module TLS-only bucket policy |
| T3 | PHI readable at rest | unencrypted bucket/DB | `phi-scan` **PHI-S3-002 / PHI-RDS-001**; module KMS CMK |
| T4 | Over-broad identity | IAM `Action:* Resource:*` | `phi-scan` **PHI-IAM-001**; `least-priv-role` scopes actions/resources |
| T5 | Network exposure | SG open to `0.0.0.0/0` on DB/mgmt ports | `phi-scan` **PHI-SG-001** |
| T6 | Public DB | RDS `publicly_accessible = true` | `phi-scan` **PHI-RDS-002** |
| T7 | Untracked sensitive store | data store with no classification | `phi-scan` **PHI-TAG-001** |
| T8 | Standing access misuse | permanent broad prod access | JIT broker: short TTLs, approval, auto-expiry |
| T9 | Requester self-approval | insider grants themselves access | JIT broker: separation-of-duties (approver ≠ requester) |
| T10 | Weak-context PHI access | PHI access without MFA / off-corp / no grant | ABAC engine deny rules (fail closed) |
| T11 | Bulk download / scrape | legitimate identity pulls everything | PHI monitor **EXFIL-005** (bulk egress) |
| T12 | Cross-account / public copy | `CopyObject` to attacker bucket | PHI monitor **EXFIL-001 / EXFIL-002** |
| T13 | Access from unexpected geo | credential theft | PHI monitor **EXFIL-004** |
| T14 | Privilege probing | `AccessDenied` enumeration | PHI monitor **EXFIL-007** |
| T15 | Access with no active grant | bypassing JIT | PHI monitor **EXFIL-003** (cross-checks grant state) |

## Residual risk / next steps

- The ABAC engine here is illustrative; production would likely externalize to a
  policy service (e.g. Cedar/OPA) with the same data-classification inputs.
- The monitor is stateless per batch; volume/geo baselining would move to a
  stateful store (e.g. per-principal rolling windows in DynamoDB) to reduce false
  positives.
- Break-glass access should page and require post-hoc review; modeled here only
  by a tight TTL and audit entry.
