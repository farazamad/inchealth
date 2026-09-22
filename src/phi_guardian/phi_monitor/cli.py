"""CLI for the PHI monitor: score a JSON batch of access events for exfiltration.

Usage:
    phi-monitor events.json
    cat events.json | phi-monitor -
"""

from __future__ import annotations

import argparse
import json
import sys
from typing import Any

from .handler import process_events


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="phi-monitor", description=__doc__)
    parser.add_argument("path", help="JSON file of access events ('-' for stdin)")
    parser.add_argument(
        "--fail-on",
        choices=["info", "low", "medium", "high", "critical"],
        default="high",
        help="exit non-zero if an alert at or above this severity is raised",
    )
    args = parser.parse_args(argv)

    data = sys.stdin.read() if args.path == "-" else open(args.path).read()
    payload: Any = json.loads(data)
    if isinstance(payload, dict):
        records = payload.get("records", payload.get("Records", []))
        classification_map = payload.get("classification_map")
    else:
        records = payload
        classification_map = None

    result = process_events(records, classification_map=classification_map)
    json.dump(result, sys.stdout, indent=2)
    sys.stdout.write("\n")

    from .models import AlertSeverity

    threshold = AlertSeverity[args.fail_on.upper()]
    worst = max(
        (AlertSeverity[a["severity"]] for a in result["alerts"]),
        default=AlertSeverity.INFO,
    )
    return 1 if result["alerts"] and worst >= threshold else 0


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
