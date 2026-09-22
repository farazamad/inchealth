"""Models for PHI access monitoring."""

from __future__ import annotations

import enum
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Iterable


class AlertSeverity(enum.IntEnum):
    INFO = 0
    LOW = 1
    MEDIUM = 2
    HIGH = 3
    CRITICAL = 4

    def __str__(self) -> str:  # pragma: no cover - trivial
        return self.name


@dataclass
class AccessEvent:
    """A normalized data-access event.

    Fields are optional where a source may not populate them; detection rules
    fail safe when a signal is missing.
    """

    principal: str
    action: str
    resource: str
    timestamp: datetime
    source_ip: str | None = None
    bytes_transferred: int = 0
    data_classification: str = "unknown"
    error_code: str | None = None
    dest_account: str | None = None
    is_public_destination: bool = False
    jit_grant_active: bool = False
    country: str | None = None
    raw: dict[str, Any] = field(default_factory=dict)

    @property
    def is_phi(self) -> bool:
        return self.data_classification.lower() in {"phi", "restricted", "pii"}

    @property
    def succeeded(self) -> bool:
        return self.error_code in (None, "", "200")


@dataclass
class Alert:
    """A detection result."""

    rule_id: str
    severity: AlertSeverity
    principal: str
    resource: str
    description: str
    evidence: dict[str, Any] = field(default_factory=dict)
    created_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))

    def as_dict(self) -> dict[str, Any]:
        return {
            "rule_id": self.rule_id,
            "severity": str(self.severity),
            "principal": self.principal,
            "resource": self.resource,
            "description": self.description,
            "evidence": self.evidence,
            "created_at": self.created_at.isoformat(),
        }


def summarize(alerts: Iterable[Alert]) -> dict[str, int]:
    """Count alerts by severity name."""
    counts: dict[str, int] = {}
    for alert in alerts:
        counts[str(alert.severity)] = counts.get(str(alert.severity), 0) + 1
    return counts
