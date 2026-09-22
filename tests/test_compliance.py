"""Tests for the compliance mapping and report generator."""

from pathlib import Path

import pytest

from phi_guardian.compliance import (
    ControlStatus,
    ControlType,
    default_catalog_path,
    failed_rule_ids,
    generate_report,
    load_catalog,
)
from phi_guardian.compliance.cli import main as compliance_main

CATALOG = default_catalog_path(Path(__file__).parent)


@pytest.fixture
def catalog():
    return load_catalog(CATALOG)


def test_catalog_loads_and_has_frameworks(catalog):
    assert set(catalog.framework_keys()) >= {"hipaa", "nist_800_53", "cis_aws", "pci_dss", "soc2"}
    assert len(catalog.controls) >= 25


def test_every_control_maps_to_at_least_one_framework(catalog):
    for c in catalog.controls:
        assert c.mappings, f"control {c.id} has no framework mappings"


def test_failed_rule_ids_from_findings_list():
    findings = [{"rule_id": "PHI-S3-001"}, {"rule_id": "PHI-RDS-002"}]
    assert failed_rule_ids(findings) == {"PHI-S3-001", "PHI-RDS-002"}


def test_failed_rule_ids_from_wrapped_dict():
    assert failed_rule_ids({"findings": [{"rule_id": "PHI-IAM-001"}]}) == {"PHI-IAM-001"}


def test_target_state_report_has_no_failures(catalog):
    report = generate_report(catalog)  # no failed rules
    assert all(cr.status is not ControlStatus.FAIL for cr in report.control_results)
    # Manual controls must never be auto-passed.
    manual = [cr for cr in report.control_results if cr.control.type is ControlType.MANUAL]
    assert manual and all(cr.status is ControlStatus.MANUAL for cr in manual)


def test_failed_rule_marks_control_and_requirement_failing(catalog):
    report = generate_report(catalog, failed_rules={"PHI-S3-001"})
    s3 = next(cr for cr in report.control_results if cr.control.id == "PHI-S3-001")
    assert s3.status is ControlStatus.FAIL

    # HIPAA 164.312(e)(1) is mapped by PHI-S3-001; it should read as failing.
    hipaa = next(f for f in report.frameworks if f.key == "hipaa")
    assert hipaa.requirements["164.312(e)(1)"]["status"] == "failing"
    assert hipaa.failing >= 1


def test_coverage_percent_drops_when_controls_fail(catalog):
    clean = generate_report(catalog, frameworks=["cis_aws"]).frameworks[0]
    broken = generate_report(catalog, failed_rules={"PHI-S3-001", "PHI-S3-002"},
                             frameworks=["cis_aws"]).frameworks[0]
    assert broken.coverage_percent < clean.coverage_percent


def test_manual_only_requirement_reported_manual(catalog):
    # A HIPAA administrative safeguard only mapped by MANUAL controls.
    report = generate_report(catalog, frameworks=["hipaa"]).frameworks[0]
    # 164.308(b)(1) is mapped by MAN-BAA (manual).
    assert report.requirements["164.308(b)(1)"]["status"] == "manual"


def test_cli_text_output(capsys):
    rc = compliance_main(["--catalog", str(CATALOG), "--framework", "hipaa"])
    out = capsys.readouterr().out
    assert rc == 0
    assert "HIPAA Security Rule" in out
    assert "mapped requirements covered" in out


def test_cli_fails_when_scan_has_findings(tmp_path, capsys):
    scan = tmp_path / "scan.json"
    scan.write_text('[{"rule_id": "PHI-RDS-002", "severity": "CRITICAL"}]')
    rc = compliance_main(["--catalog", str(CATALOG), "--scan", str(scan), "--framework", "all"])
    assert rc == 1


def test_cli_json_format(capsys):
    rc = compliance_main(["--catalog", str(CATALOG), "--format", "json"])
    out = capsys.readouterr().out
    assert rc == 0
    assert '"frameworks"' in out and '"caveat"' in out
