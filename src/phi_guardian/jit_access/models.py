"""Data models for the JIT access broker."""

from __future__ import annotations

import enum
import uuid
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any


def _utcnow() -> datetime:
    return datetime.now(timezone.utc)


def _new_id(prefix: str) -> str:
    return f"{prefix}_{uuid.uuid4().hex[:12]}"


class GrantStatus(str, enum.Enum):
    PENDING = "pending"
    APPROVED = "approved"
    DENIED = "denied"
    REVOKED = "revoked"
    EXPIRED = "expired"


# Roles that may be requested, and the maximum TTL (seconds) each may hold.
# Tighter ceilings for more privileged / more sensitive roles.
ROLE_MAX_TTL: dict[str, int] = {
    "phi_reader": 8 * 3600,
    "phi_operator": 3600,
    "db_admin": 1800,
    "break_glass": 900,
}

# Roles whose grants require a second (approver) principal, distinct from the
# requester (enforces separation of duties).
ROLES_REQUIRING_APPROVAL: set[str] = {"phi_operator", "db_admin", "break_glass"}


@dataclass
class Grant:
    """A request for time-bound access and its lifecycle state."""

    subject_id: str
    role: str
    target_resource: str
    justification: str
    requested_ttl: int
    status: GrantStatus = GrantStatus.PENDING
    id: str = field(default_factory=lambda: _new_id("grant"))
    requested_at: datetime = field(default_factory=_utcnow)
    decided_by: str | None = None
    decided_at: datetime | None = None
    activated_at: datetime | None = None
    expires_at: datetime | None = None
    revoked_reason: str | None = None

    def is_active(self, now: datetime | None = None) -> bool:
        now = now or _utcnow()
        return (
            self.status is GrantStatus.APPROVED
            and self.expires_at is not None
            and now < self.expires_at
        )

    def remaining_seconds(self, now: datetime | None = None) -> int:
        now = now or _utcnow()
        if not self.is_active(now):
            return 0
        return int((self.expires_at - now).total_seconds())  # type: ignore[operator]

    def as_dict(self) -> dict[str, Any]:
        def iso(dt: datetime | None) -> str | None:
            return dt.isoformat() if dt else None

        return {
            "id": self.id,
            "subject_id": self.subject_id,
            "role": self.role,
            "target_resource": self.target_resource,
            "justification": self.justification,
            "status": self.status.value,
            "requested_ttl": self.requested_ttl,
            "requested_at": iso(self.requested_at),
            "decided_by": self.decided_by,
            "decided_at": iso(self.decided_at),
            "activated_at": iso(self.activated_at),
            "expires_at": iso(self.expires_at),
            "remaining_seconds": self.remaining_seconds(),
            "revoked_reason": self.revoked_reason,
        }


@dataclass
class AuditEvent:
    """An append-only record of something that happened to a grant."""

    action: str
    grant_id: str
    actor: str
    detail: str = ""
    id: str = field(default_factory=lambda: _new_id("evt"))
    at: datetime = field(default_factory=_utcnow)

    def as_dict(self) -> dict[str, Any]:
        return {
            "id": self.id,
            "at": self.at.isoformat(),
            "action": self.action,
            "grant_id": self.grant_id,
            "actor": self.actor,
            "detail": self.detail,
        }
