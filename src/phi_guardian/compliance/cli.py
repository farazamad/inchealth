"""CLI: generate a compliance report by mapping a phi-scan result to frameworks.

    phi-scan -plan plan.json -format json > scan.json
    phi-compliance --scan scan.json --framework all --format markdown

With no --scan, all automated controls are treated as passing (target-state).
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Any

from .catalog import load_catalog, default_catalog_path
from .report import ComplianceReport, ControlStatus, failed_rule_ids, generate_report


def _render_text(report: ComplianceReport) -> str:
    lines: list[str] = ["PHI Guardian — Compliance Report", "=" * 34, ""]
    counts: dict[str, int] = {}
    for cr in report.control_results:
        counts[cr.status.value] = counts.get(cr.status.value, 0) + 1
    lines.append(
        "Controls: "
        f"{counts.get('pass', 0)} pass, {counts.get('fail', 0)} fail, "
        f"{counts.get('manual', 0)} manual, {counts.get('not_assessed', 0)} not-assessed"
    )
    lines.append("")
    for fw in report.frameworks:
        lines.append(f"{fw.name}")
        lines.append(
            f"  {fw.covered}/{fw.total_requirements} mapped requirements covered "
            f"({fw.coverage_percent}%)  |  {fw.failing} failing, {fw.manual} manual, "
            f"{fw.not_assessed} not-assessed"
        )
    lines.append("")
    lines.append("NOTE: " + report.caveat)
    return "\n".join(lines)


def _render_markdown(report: ComplianceReport) -> str:
    out: list[str] = ["# PHI Guardian — Compliance Report", "",
                      f"_Generated {report.generated_at}_", "",
                      "## Framework coverage", "",
                      "| Framework | Covered | Failing | Manual | Coverage of mapped |",
                      "|---|---|---|---|---|"]
    for fw in report.frameworks:
        out.append(
            f"| {fw.name} | {fw.covered}/{fw.total_requirements} | {fw.failing} | "
            f"{fw.manual} | {fw.coverage_percent}% |"
        )
    out += ["", "## Control status", "",
            "| Control | Type | Component | Status |",
            "|---|---|---|---|"]
    icon = {"pass": "✅", "fail": "❌", "manual": "📝", "not_assessed": "➖"}
    for cr in report.control_results:
        out.append(
            f"| {cr.control.id} — {cr.control.title} | {cr.control.type.value} | "
            f"{cr.control.component} | {icon.get(cr.status.value, '')} {cr.status.value} |"
        )
    out += ["", f"> **Scope note:** {report.caveat}"]
    return "\n".join(out)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="phi-compliance", description=__doc__)
    parser.add_argument("--catalog", help="path to controls.json (default: auto-discover)")
    parser.add_argument("--scan", help="phi-scan JSON output ('-' for stdin); omit for target-state")
    parser.add_argument("--framework", action="append", default=None,
                        help="framework key (repeatable), or 'all' (default)")
    parser.add_argument("--format", choices=["text", "json", "markdown"], default="text")
    parser.add_argument("--fail-under", type=float, default=None,
                        help="exit non-zero if any framework's mapped coverage is below this %%")
    parser.add_argument("--output", help="write to this file instead of stdout")
    args = parser.parse_args(argv)

    catalog_path = Path(args.catalog) if args.catalog else default_catalog_path()
    catalog = load_catalog(catalog_path)

    failed: set[str] = set()
    if args.scan:
        data = sys.stdin.read() if args.scan == "-" else Path(args.scan).read_text()
        failed = failed_rule_ids(json.loads(data))

    frameworks: list[str] | None
    if not args.framework or "all" in args.framework:
        frameworks = None
    else:
        unknown = [f for f in args.framework if f not in catalog.framework_keys()]
        if unknown:
            parser.error(f"unknown framework(s): {', '.join(unknown)}; "
                         f"choose from {', '.join(catalog.framework_keys())} or 'all'")
        frameworks = args.framework

    report = generate_report(catalog, failed_rules=failed, frameworks=frameworks)

    if args.format == "json":
        rendered = json.dumps(report.as_dict(), indent=2)
    elif args.format == "markdown":
        rendered = _render_markdown(report)
    else:
        rendered = _render_text(report)

    if args.output:
        Path(args.output).write_text(rendered + "\n")
    else:
        sys.stdout.write(rendered + "\n")

    if args.fail_under is not None:
        for fw in report.frameworks:
            if fw.coverage_percent < args.fail_under:
                return 1
    # Also fail if any automated control is failing.
    if any(cr.status is ControlStatus.FAIL for cr in report.control_results):
        return 1
    return 0


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
