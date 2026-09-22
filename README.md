# PHI Guardian

**A cloud-security toolkit for HIPAA-regulated AWS workloads** — policy-as-code
for Terraform, just-in-time access with attribute-based authorization, and
PHI-exfiltration detection.

> Built as a portfolio project for the **Staff Cloud Security Engineer** role at
> Included Health. That role is about *engineering* security into a healthcare
> cloud — designing access-control frameworks, JIT access, and data-classification–
> driven controls, and shipping the security tooling (in **Python** and **Go**,
> on **Terraform/IaC**) that prevents unauthorized PHI exfiltration. This repo is
> a small but working end-to-end system that does exactly that.

---

## Why this exists

In a HIPAA environment the worst outcome is **unauthorized exfiltration of PHI**
(protected health information). Three failure modes cause most of it:

1. **Misconfigured infrastructure** — a public S3 bucket, an unencrypted
   database, a security group open to the world.
2. **Standing access** — humans and services holding broad, permanent access to
   production data they rarely need.
3. **Undetected access** — data leaving through a legitimate identity with nobody
   watching.

PHI Guardian addresses each with a dedicated, testable component.

| Failure mode | Component | Language | JD skill demonstrated |
|---|---|---|---|
| Misconfigured IaC | [`scanner/`](scanner/) — `phi-scan` policy-as-code engine | **Go** | Policy-as-code, IaC auditing, security automation, CI gating |
| Standing access | [`jit_access/`](src/phi_guardian/jit_access/) — JIT access broker | **Python** (FastAPI) | JIT access, RBAC, separation of duties, audit |
| Coarse authorization | [`classification/`](src/phi_guardian/classification/) — ABAC engine | **Python** | ABAC, policy-as-code, **data classification ↔ access control** |
| Undetected access | [`phi_monitor/`](src/phi_guardian/phi_monitor/) — exfil detection + Lambda | **Python** (AWS Lambda) | Detection engineering, PHI logging, Lambda tooling |
| Audit evidence | [`compliance/`](src/phi_guardian/compliance/) — control crosswalk + reports | **Python** + JSON | HIPAA/NIST/CIS/PCI/SOC 2 mapping, coverage reporting |
| Secure baseline | [`terraform/`](terraform/) — hardened modules | **Terraform** | IaC, encryption/KMS, least-privilege IAM |

Everything runs locally with **no AWS account and no Terraform install** required
(committed plan fixtures and sample events drive the demo).

## Quick start

```bash
# Python components
python -m venv .venv && source .venv/bin/activate
pip install -e ".[dev,server]"
pytest                       # 39 tests

# Go scanner
cd scanner && go test ./... && cd ..

# Full end-to-end demo (scanner + monitor + JIT/ABAC)
./demo.sh
# or: make demo
```

## The four components

### 1. `phi-scan` — policy-as-code for Terraform (Go)

A dependency-free Go CLI that evaluates a `terraform show -json` plan against a
ruleset targeting concrete PHI-leak paths, and **exits non-zero** so it can gate
a merge in CI. Outputs `table`, `json`, or **SARIF** for the GitHub Security tab.

```bash
make build
./bin/phi-scan -plan scanner/testdata/insecure.plan.json -fail-on high   # exits 1
./bin/phi-scan -plan scanner/testdata/secure.plan.json   -fail-on high   # exits 0
./bin/phi-scan -list-rules
```

The 13 rules cover S3 (public access / KMS / TLS / versioning+logging), IAM
(`*:*` wildcards, password policy), security groups, RDS (encryption, public
access), EBS encryption, KMS key rotation, CloudTrail hardening, and a
**data-classification tagging** rule that ties every data store to a sensitivity
level. Pass `-catalog compliance/controls.json` to annotate each finding with the
framework requirements it maps to. See [`scanner/README.md`](scanner/README.md).

### 2. JIT access broker — time-bound, approval-gated access (Python/FastAPI)

Replaces standing production access with grants that are **requested → approved
by a *different* principal (separation of duties) → auto-expiring → fully
audited**. Role TTL ceilings are enforced (e.g. `break_glass` ≤ 15 min).

```bash
make serve   # http://127.0.0.1:8000/docs
```

```
POST /grants                 request time-bound access
POST /grants/{id}/approve    a second principal activates it
POST /access/check           RBAC + active grant + ABAC -> allow/deny
GET  /audit                  append-only audit trail
```

### 3. ABAC engine — data classification drives access (Python)

A fail-closed, deny-overrides, default-deny policy engine. Decisions depend on
subject attributes/roles, **resource sensitivity**, and request context (MFA,
network tier, active JIT grant). This is where *data classification is wired
directly into access control*: PHI requires MFA + a trusted network, and any
mutation/export of PHI requires an active JIT grant.

### 4. PHI monitor — exfiltration detection (Python/AWS Lambda)

Consumes normalized CloudTrail / S3 access events (also a Kinesis envelope) and
scores them for exfiltration: writes to public/untrusted destinations, PHI
access without a JIT grant, bulk egress, unexpected geography, off-hours access,
and `AccessDenied` probing bursts.

```bash
python -m phi_guardian.phi_monitor.cli samples/phi_access_events.json --fail-on critical
```

### 5. Compliance mapping — controls → framework requirements (Python + JSON)

A single source-of-truth catalog ([`compliance/controls.json`](compliance/controls.json))
crosswalks every control — automated, runtime, and manual — to specific control
IDs in **HIPAA Security Rule, NIST 800-53, CIS AWS Foundations Benchmark, PCI DSS,
and SOC 2**. `phi-compliance` turns a scan result into a per-framework report.

```bash
phi-scan -plan plan.json -format json > scan.json
phi-compliance --scan scan.json --framework all --format markdown
```

**An honest word on "covering all frameworks":** no tool can. Frameworks like
NIST 800-53 (1000+ controls) and HIPAA include many **administrative, physical,
and procedural** safeguards (BAAs, training, incident response) that infrastructure
scanning cannot verify. This layer therefore:

- reports coverage **only against the requirements the catalog maps**, never the
  whole framework;
- distinguishes `pass` / `fail` / **`manual`** (attestation required) / `not-assessed`,
  so a control needing a human is never counted as automatically satisfied;
- keeps manual safeguards (BAAs, training, IR, BCP, risk analysis, sanctions,
  physical, access reviews) **in** the catalog so the gap is visible, not hidden.

The result is a defensible coverage picture (e.g. 100% of *mapped* CIS AWS
requirements on the secure baseline; ~68% of mapped HIPAA requirements with the
remainder explicitly flagged as manual) rather than a false "100% compliant" badge.

## Architecture & security design

- [`ARCHITECTURE.md`](ARCHITECTURE.md) — how the pieces fit and deploy on AWS.
- [`docs/threat-model.md`](docs/threat-model.md) — assets, threats, and the
  control each component provides.
- [`docs/jit-access.md`](docs/jit-access.md) — the JIT grant lifecycle.
- [`docs/compliance.md`](docs/compliance.md) — the control→framework crosswalk
  and why "covers all frameworks" is the wrong goal.

## Tech stack

Go 1.24 (stdlib only) · Python 3.11 · FastAPI/Pydantic · Terraform (AWS provider) ·
GitHub Actions (tests + SARIF upload).

## Layout

```
scanner/                 Go policy-as-code CLI (phi-scan) + rules + tests
src/phi_guardian/
  classification/        data sensitivity + ABAC engine
  jit_access/            JIT broker: models, service, FastAPI app
  phi_monitor/           exfil detector, CloudTrail normalizer, Lambda handler, CLI
  compliance/            control catalog loader, report generator, CLI
compliance/controls.json shared control → framework crosswalk (source of truth)
terraform/               hardened modules + secure/insecure examples
tests/                   pytest suite
samples/                 sample access-event batch for the monitor
demo.sh                  end-to-end demo
```

## License

MIT — see [LICENSE](LICENSE). This is a demonstration project; the sample
identifiers, account numbers, and data are fictional.
