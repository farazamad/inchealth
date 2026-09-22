"""Generate honest per-framework compliance reports from a scan result."""

from __future__ import annotations

import enum
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Iterable, Mapping

from .catalog import Catalog, Control, ControlType


class ControlStatus(str, enum.Enum):
    PASS = "pass"            # automated check passed, or runtime control implemented
    FAIL = "fail"            # automated check found a violation
    MANUAL = "manual"        # requires human attestation
    NOT_ASSESSED = "not_assessed"


class RequirementStatus(str, enum.Enum):
    COVERED = "covered"          # at least one mapped control passes
    FAILING = "failing"         # a mapped control is failing
    MANUAL = "manual"           # only manual controls map here
    NOT_ASSESSED = "not_assessed"


@dataclass
class ControlResult:
    control: Control
    status: ControlStatus

    def as_dict(self) -> dict[str, Any]:
        return {
            "id": self.control.id,
            "title": self.control.title,
            "type": self.control.type.value,
            "component": self.control.component,
            "status": self.status.value,
        }


@dataclass
class FrameworkResult:
    key: str
    name: str
    total_requirements: int
    covered: int
    failing: int
    manual: int
    not_assessed: int
    requirements: dict[str, dict[str, Any]] = field(default_factory=dict)

    @property
    def coverage_percent(self) -> float:
        if self.total_requirements == 0:
            return 0.0
        return round(100.0 * self.covered / self.total_requirements, 1)

    def as_dict(self) -> dict[str, Any]:
        return {
            "framework": self.key,
            "name": self.name,
            "mapped_requirements": self.total_requirements,
            "covered": self.covered,
            "failing": self.failing,
            "manual_only": self.manual,
            "not_assessed": self.not_assessed,
            "coverage_percent_of_mapped": self.coverage_percent,
            "requirements": self.requirements,
        }


@dataclass
class ComplianceReport:
    generated_at: str
    control_results: list[ControlResult]
    frameworks: list[FrameworkResult]
    caveat: str

    def as_dict(self) -> dict[str, Any]:
        return {
            "generated_at": self.generated_at,
            "caveat": self.caveat,
            "controls": [c.as_dict() for c in self.control_results],
            "frameworks": [f.as_dict() for f in self.frameworks],
        }


_CAVEAT = (
    "Coverage is measured only against the requirements this catalog maps, not "
    "the entire framework. PASS on an automated control means no violation was "
    "found in the scanned Terraform plan; runtime controls are reported as "
    "implemented by the platform and still require operating-effectiveness "
    "evidence. MANUAL controls require human attestation and are never "
    "auto-satisfied. Review mappings with your GRC team before audit use."
)


def failed_rule_ids(scan_output: Any) -> set[str]:
    """Extract failing rule IDs from phi-scan JSON output.

    Accepts a list of finding dicts (``phi-scan -format json``) or a dict that
    contains such a list under 'findings'/'results'.
    """
    if isinstance(scan_output, Mapping):
        scan_output = scan_output.get("findings") or scan_output.get("results") or []
    ids: set[str] = set()
    for finding in scan_output or []:
        rid = finding.get("rule_id") if isinstance(finding, Mapping) else None
        if rid:
            ids.add(rid)
    return ids


def _evaluate_control(
    control: Control,
    failed_rules: set[str],
    disabled_runtime: Iterable[str],
) -> ControlStatus:
    if control.type is ControlType.AUTOMATED:
        return ControlStatus.FAIL if control.id in failed_rules else ControlStatus.PASS
    if control.type is ControlType.RUNTIME:
        if control.id in set(disabled_runtime):
            return ControlStatus.NOT_ASSESSED
        return ControlStatus.PASS
    return ControlStatus.MANUAL


def generate_report(
    catalog: Catalog,
    failed_rules: set[str] | None = None,
    frameworks: list[str] | None = None,
    disabled_runtime: Iterable[str] = (),
) -> ComplianceReport:
    failed_rules = failed_rules or set()
    frameworks = frameworks or catalog.framework_keys()

    control_results = [
        ControlResult(c, _evaluate_control(c, failed_rules, disabled_runtime))
        for c in catalog.controls
    ]
    status_by_id = {r.control.id: r.status for r in control_results}

    framework_results: list[FrameworkResult] = []
    for fw in frameworks:
        # requirement_id -> list of (control_id, status)
        req_map: dict[str, list[tuple[str, ControlStatus]]] = {}
        for control in catalog.controls_for_framework(fw):
            for req in control.requirements(fw):
                req_map.setdefault(req, []).append((control.id, status_by_id[control.id]))

        covered = failing = manual = not_assessed = 0
        requirements: dict[str, dict[str, Any]] = {}
        for req in sorted(req_map):
            statuses = [s for _, s in req_map[req]]
            if ControlStatus.FAIL in statuses:
                rstatus = RequirementStatus.FAILING
                failing += 1
            elif ControlStatus.PASS in statuses:
                rstatus = RequirementStatus.COVERED
                covered += 1
            elif ControlStatus.MANUAL in statuses:
                rstatus = RequirementStatus.MANUAL
                manual += 1
            else:
                rstatus = RequirementStatus.NOT_ASSESSED
                not_assessed += 1
            requirements[req] = {
                "status": rstatus.value,
                "controls": [cid for cid, _ in req_map[req]],
            }

        framework_results.append(FrameworkResult(
            key=fw,
            name=catalog.framework_name(fw),
            total_requirements=len(req_map),
            covered=covered,
            failing=failing,
            manual=manual,
            not_assessed=not_assessed,
            requirements=requirements,
        ))

    return ComplianceReport(
        generated_at=datetime.now(timezone.utc).isoformat(),
        control_results=control_results,
        frameworks=framework_results,
        caveat=_CAVEAT,
    )
