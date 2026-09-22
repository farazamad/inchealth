# Compliance mapping & reporting

## The claim we do *not* make

PHI Guardian does **not** "make you compliant with HIPAA / NIST / CIS / PCI /
SOC 2." No tool does. Two reasons:

1. **Most framework controls are not technical.** HIPAA has administrative and
   physical safeguards; NIST 800-53 has 1000+ controls across 20 families; SOC 2
   and ISO 27001 are largely governance and evidence. Business Associate
   Agreements, workforce training, incident-response plans, background checks,
   and facility access **cannot be verified by scanning infrastructure.**
2. **"Pass" has a precise meaning.** An automated check passing means *no
   violation was found in the scanned Terraform plan* — not that the control
   operates effectively in production over time (which is what an auditor tests).

Claiming otherwise is how teams fail audits and, worse, believe they are secure
when they are not.

## What we do instead

A single source-of-truth catalog, [`compliance/controls.json`](../compliance/controls.json),
maps every PHI Guardian control to specific requirement IDs across frameworks,
and classifies each control by **type**:

| Type | Meaning | How status is decided |
|---|---|---|
| `automated` | Verified by `phi-scan` against a Terraform plan | `fail` if the rule is in the scan findings, else `pass` |
| `runtime` | Enforced by a running platform component (JIT, ABAC, monitor) | `pass` = implemented (still needs operating-effectiveness evidence) |
| `manual` | Requires human attestation / process evidence | always `manual` — never auto-satisfied |

The report then rolls control statuses up to **framework requirements** and
computes coverage **only against the requirements the catalog maps** — stated
explicitly in every report's caveat.

Requirement status = `failing` if any mapped control fails; else `covered` if any
mapped control passes; else `manual` if only manual controls map there; else
`not_assessed`.

## Frameworks mapped

HIPAA Security Rule · NIST SP 800-53 Rev. 5 · CIS AWS Foundations Benchmark v3 ·
PCI DSS v4.0 · SOC 2 (2017 TSC). Manual safeguards are deliberately **kept in the
catalog** (BAAs, training, IR, BCP, risk analysis, sanctions, physical, access
recertification) so the gap between "automated" and "total" is visible.

## Usage

```bash
# Report from a live scan (fails CI if an automated control is failing)
phi-scan -plan plan.json -format json > scan.json
phi-compliance --scan scan.json --framework all --format markdown

# Target-state coverage (no scan = all automated controls assumed passing)
phi-compliance --framework hipaa --format text

# Gate on coverage of mapped requirements
phi-compliance --scan scan.json --fail-under 60
```

`--format` is `text`, `json`, or `markdown`. `--framework` is repeatable or `all`.

## Extending

- **Add a check:** add the Go rule in `scanner/internal/rules/`, then add a
  matching `automated` entry to `controls.json` with its framework mappings.
- **Add a framework:** add it under `frameworks` and add its keys to each
  control's `mappings`. No code change is needed — the report enumerates whatever
  the catalog contains.
- **Review before audit use.** The mappings are engineering's best-effort
  crosswalk; your GRC/compliance team owns the authoritative interpretation.
