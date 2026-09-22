"""Exfiltration detection heuristics for PHI access events."""

from __future__ import annotations

from collections import defaultdict
from dataclasses import dataclass, field

from .models import AccessEvent, Alert, AlertSeverity

# Read/export actions that move data out of a store.
_EGRESS_ACTIONS = {
    "GetObject", "get", "read", "download", "export", "SelectObjectContent",
    "CopyObject", "GetObjectTorrent",
}


@dataclass
class DetectorConfig:
    """Tunable thresholds. Defaults are deliberately conservative."""

    bulk_bytes_threshold: int = 100 * 1024 * 1024  # 100 MiB per principal/resource
    bulk_object_threshold: int = 500               # objects per principal/resource
    allowed_countries: frozenset[str] = frozenset({"US"})
    business_hours_utc: frozenset[int] = frozenset(range(12, 24))  # 12:00-23:59 UTC
    trusted_accounts: frozenset[str] = frozenset()


class DetectionEngine:
    def __init__(self, config: DetectorConfig | None = None) -> None:
        self.config = config or DetectorConfig()

    def evaluate(self, events: list[AccessEvent]) -> list[Alert]:
        alerts: list[Alert] = []
        alerts.extend(self._per_event(events))
        alerts.extend(self._bulk_egress(events))
        alerts.extend(self._privilege_probing(events))
        alerts.sort(key=lambda a: a.severity, reverse=True)
        return alerts

    # -- per-event rules ---------------------------------------------------

    def _per_event(self, events: list[AccessEvent]) -> list[Alert]:
        out: list[Alert] = []
        for ev in events:
            if not ev.is_phi:
                continue

            # R001 — PHI leaving to a public destination or untrusted account.
            if ev.succeeded and ev.is_public_destination:
                out.append(Alert(
                    "EXFIL-001", AlertSeverity.CRITICAL, ev.principal, ev.resource,
                    "PHI written/copied to a public destination",
                    {"action": ev.action, "dest": ev.raw.get("dest_resource")},
                ))
            elif (
                ev.succeeded
                and ev.dest_account
                and ev.dest_account not in self.config.trusted_accounts
            ):
                out.append(Alert(
                    "EXFIL-002", AlertSeverity.CRITICAL, ev.principal, ev.resource,
                    "PHI copied to an untrusted AWS account",
                    {"action": ev.action, "dest_account": ev.dest_account},
                ))

            # R003 — successful PHI access with no active JIT grant.
            if ev.succeeded and ev.action in _EGRESS_ACTIONS and not ev.jit_grant_active:
                out.append(Alert(
                    "EXFIL-003", AlertSeverity.HIGH, ev.principal, ev.resource,
                    "PHI accessed without an active just-in-time grant",
                    {"action": ev.action, "source_ip": ev.source_ip},
                ))

            # R004 — PHI access from an unexpected country.
            if (
                ev.succeeded
                and ev.country is not None
                and ev.country not in self.config.allowed_countries
            ):
                out.append(Alert(
                    "EXFIL-004", AlertSeverity.MEDIUM, ev.principal, ev.resource,
                    f"PHI accessed from unexpected country: {ev.country}",
                    {"country": ev.country, "source_ip": ev.source_ip},
                ))

            # R006 — PHI access outside business hours.
            if ev.succeeded and ev.timestamp.hour not in self.config.business_hours_utc:
                out.append(Alert(
                    "EXFIL-006", AlertSeverity.LOW, ev.principal, ev.resource,
                    "PHI accessed outside business hours",
                    {"hour_utc": ev.timestamp.hour},
                ))
        return out

    # -- aggregate rules ---------------------------------------------------

    def _bulk_egress(self, events: list[AccessEvent]) -> list[Alert]:
        """R002 — bulk download: many bytes/objects per principal+resource."""
        totals: dict[tuple[str, str], list[int]] = defaultdict(lambda: [0, 0])  # [bytes, count]
        for ev in events:
            if ev.is_phi and ev.succeeded and ev.action in _EGRESS_ACTIONS:
                agg = totals[(ev.principal, ev.resource)]
                agg[0] += ev.bytes_transferred
                agg[1] += 1

        out: list[Alert] = []
        for (principal, resource), (total_bytes, count) in totals.items():
            over_bytes = total_bytes >= self.config.bulk_bytes_threshold
            over_count = count >= self.config.bulk_object_threshold
            if over_bytes or over_count:
                out.append(Alert(
                    "EXFIL-005", AlertSeverity.HIGH, principal, resource,
                    "Bulk PHI egress detected",
                    {
                        "total_bytes": total_bytes,
                        "object_count": count,
                        "byte_threshold": self.config.bulk_bytes_threshold,
                        "object_threshold": self.config.bulk_object_threshold,
                    },
                ))
        return out

    def _privilege_probing(self, events: list[AccessEvent]) -> list[Alert]:
        """R007 — AccessDenied bursts on PHI (enumeration / probing)."""
        denials: dict[str, int] = defaultdict(int)
        for ev in events:
            if ev.is_phi and not ev.succeeded and ev.error_code in {"AccessDenied", "403"}:
                denials[ev.principal] += 1
        out: list[Alert] = []
        for principal, count in denials.items():
            if count >= 5:
                out.append(Alert(
                    "EXFIL-007", AlertSeverity.MEDIUM, principal, "(multiple)",
                    "Repeated AccessDenied on PHI resources (possible probing)",
                    {"denied_count": count},
                ))
        return out


def default_detector() -> DetectionEngine:
    return DetectionEngine()
