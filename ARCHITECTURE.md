# Architecture

PHI Guardian is four loosely-coupled components that share one idea: **data
sensitivity is a first-class attribute that governs infrastructure, access, and
monitoring.** Each is independently useful and independently testable.

```
                        ┌───────────────────────────────────────────┐
                        │            Data classification              │
                        │   public < internal < confidential < phi    │
                        └───────────────────────────────────────────┘
                              │              │               │
             tags on IaC ─────┘              │               └───── tags on events
                              ▼              ▼                       ▼
   ┌──────────────┐   ┌───────────────┐  ┌───────────────┐   ┌────────────────┐
   │  phi-scan    │   │  ABAC engine  │  │  JIT broker    │   │  PHI monitor   │
   │  (Go, CI)    │   │  (Python)     │  │  (FastAPI)     │   │  (Lambda)      │
   │              │   │               │  │                │   │                │
   │ scans TF     │   │ decides       │◄─┤ injects active │   │ scores access  │
   │ plans, gates │   │ allow/deny    │  │ grant into ctx │   │ events for     │
   │ the merge    │   │ from context  │  │ + audit log    │   │ exfiltration   │
   └──────┬───────┘   └───────────────┘  └────────────────┘   └───────┬────────┘
          │                                                            │
    build-time control                                          run-time control
```

## Build-time vs. run-time controls

- **Build time (`phi-scan`)** — shift left. A misconfiguration that would expose
  PHI never reaches production because the CI job fails the pull request. Output
  is SARIF so findings land in the GitHub Security tab.
- **Run time (JIT + ABAC + monitor)** — defense in depth. Access is granted only
  in bounded windows, every request is evaluated against sensitivity-aware
  policy, and the resulting access is watched for exfiltration.

## How the pieces connect

1. **Terraform** provisions PHI stores from hardened modules that always set
   `data_classification = phi`, KMS encryption, TLS-only, and least-privilege
   IAM roles assumable only with MFA.
2. **`phi-scan`** runs in CI on the plan. If a change drops a control (e.g.
   removes the public-access block), the merge is blocked.
3. At runtime, a principal asks the **JIT broker** for a short-lived role on a
   specific resource. A second principal approves (separation of duties). The
   broker mints/records the grant and it auto-expires.
4. On each data operation, the **ABAC engine** decides access from the subject's
   roles/attributes, the resource's **sensitivity**, and context (MFA, network
   tier, whether a JIT grant is active). Default-deny, deny-overrides.
5. **CloudTrail / S3 access logs** stream to the **PHI monitor** Lambda, which
   flags exfiltration patterns and (in a real deployment) publishes CRITICAL/HIGH
   alerts to SNS or Security Hub.

## Target AWS deployment

| Component | AWS shape |
|---|---|
| `phi-scan` | Runs in CI (GitHub Actions). Optionally a nightly ECS task scanning `terraform plan` of live state drift. |
| JIT broker | ECS Fargate or Lambda behind API Gateway; grants persisted to DynamoDB; approvals via Slack/OIDC; on approval, calls STS/updates an IAM permission set. |
| ABAC engine | Imported as a library by the broker and by service authorizers (e.g. a Lambda authorizer / Cedar-style sidecar). |
| PHI monitor | Lambda subscribed to a Kinesis stream of CloudTrail + S3 access logs; alerts to SNS → PagerDuty and AWS Security Hub. |
| Terraform | Applied via CI with OIDC-assumed roles; state in encrypted S3 + DynamoDB lock. |

## Compliance mapping layer

A shared catalog (`compliance/controls.json`) crosswalks every control —
automated (`phi-scan`), runtime (JIT/ABAC/monitor), and manual (process) — to
requirement IDs across HIPAA, NIST 800-53, CIS AWS, PCI DSS, and SOC 2. Both the
Go scanner (`-catalog`, to annotate findings) and the Python report generator
(`phi-compliance`) read it, so there is one source of truth. Reports are honest
by construction: coverage is computed only over mapped requirements, and manual
safeguards are represented, never silently assumed satisfied. See
[`docs/compliance.md`](docs/compliance.md).

## Design principles

- **Fail closed.** Missing signals (no MFA claim, unknown network tier, broken
  rule) result in *deny*, never allow.
- **Least privilege & short-lived.** No standing PHI access; role TTLs are capped
  per role, tightest for the most privileged.
- **Everything audited.** The broker keeps an append-only log; the monitor keeps
  the access record; the scanner leaves a SARIF trail in CI.
- **Pure cores, thin adapters.** Business logic has no framework/AWS imports, so
  it is fast to test and portable between Lambda, ECS, and CLI.
