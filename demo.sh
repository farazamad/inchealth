#!/usr/bin/env bash
# End-to-end demonstration of PHI Guardian. No AWS account required.
set -euo pipefail
cd "$(dirname "$0")"

bold() { printf '\n\033[1m%s\033[0m\n' "$1"; }
rule() { printf '%s\n' "------------------------------------------------------------"; }

bold "1. Policy-as-code: scan a SECURE Terraform plan (should pass)"
rule
cd scanner && go build -o ../bin/phi-scan . && cd ..
./bin/phi-scan -plan scanner/testdata/secure.plan.json -fail-on high
echo "exit: $? (0 = no blocking findings)"

bold "2. Policy-as-code: scan an INSECURE Terraform plan (should fail CI)"
rule
set +e
./bin/phi-scan -plan scanner/testdata/insecure.plan.json -fail-on high
echo "exit: $? (non-zero = CI gate would block the merge)"
set -e

bold "3. PHI exfiltration monitor: score a batch of access events"
rule
python -m phi_guardian.phi_monitor.cli samples/phi_access_events.json --fail-on critical \
  || echo "(non-zero exit: a CRITICAL exfiltration alert fired)"

bold "4. JIT access + ABAC: deny standing access, allow a time-bound grant"
rule
python - <<'PY'
from phi_guardian.jit_access import JITAccessService
from phi_guardian.classification import SensitivityLevel

svc = JITAccessService()
ctx = {"mfa": True, "network_tier": "corp"}

# Without a grant, exporting PHI is denied.
d1 = svc.check_access("alice", ["phi_operator"], "arn:phi-bucket",
                      SensitivityLevel.PHI, "export", context=ctx)
print(f"before grant : allowed={d1.allowed}  rule={d1.matched_rule}")

# Request + approve a 15-minute grant (separation of duties enforced).
g = svc.request_access("alice", "phi_operator", "arn:phi-bucket",
                       "Investigating INC-4821", 900)
svc.approve(g.id, approver="bob")

d2 = svc.check_access("alice", ["phi_operator"], "arn:phi-bucket",
                      SensitivityLevel.PHI, "export", context=ctx)
print(f"after grant  : allowed={d2.allowed}  rule={d2.matched_rule}")
print(f"grant expires in {svc.get(g.id).remaining_seconds()}s; audit trail:")
for e in svc.audit_log(g.id):
    print(f"  - {e.action:14s} by {e.actor}")
PY

bold "Demo complete."
