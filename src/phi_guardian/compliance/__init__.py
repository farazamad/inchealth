"""Compliance mapping and reporting.

Crosswalks PHI Guardian's technical controls to compliance-framework
requirements (HIPAA, NIST 800-53, CIS AWS, PCI DSS, SOC 2) and generates honest
per-framework reports that distinguish automated pass/fail from controls that
require manual attestation. It never claims automated coverage of a control a
tool cannot verify.
"""

from .catalog import Catalog, Control, ControlType, load_catalog, default_catalog_path
from .report import (
    ComplianceReport,
    ControlStatus,
    FrameworkResult,
    RequirementStatus,
    generate_report,
    failed_rule_ids,
)

__all__ = [
    "Catalog",
    "Control",
    "ControlType",
    "load_catalog",
    "default_catalog_path",
    "ComplianceReport",
    "ControlStatus",
    "FrameworkResult",
    "RequirementStatus",
    "generate_report",
    "failed_rule_ids",
]
