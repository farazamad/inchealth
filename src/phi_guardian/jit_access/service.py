"""Business logic for the JIT access broker.

The service is deliberately framework-free (no FastAPI imports) so it can be
unit-tested directly and reused from a Lambda, a CLI, or the HTTP API. A clock
callable is injected so expiry behaviour is deterministic in tests.
"""

from __future__ import annotations

from datetime import datetime, timedelta, timezone
from typing import Callable

from ..classification import (
    AccessRequest,
    Decision,
    PolicyEngine,
    Resource,
    SensitivityLevel,
    Subject,
    default_engine,
)
from .models import (
    ROLE_MAX_TTL,
    ROLES_REQUIRING_APPROVAL,
    AuditEvent,
    Grant,
    GrantStatus,
)

Clock = Callable[[], datetime]


class AccessError(Exception):
    """Raised for invalid state transitions or bad requests."""


class JITAccessService:
    def __init__(
        self,
        engine: PolicyEngine | None = None,
        clock: Clock | None = None,
    ) -> None:
        self._grants: dict[str, Grant] = {}
        self._audit: list[AuditEvent] = []
        self._engine = engine or default_engine()
        self._clock = clock or (lambda: datetime.now(timezone.utc))

    # -- helpers -----------------------------------------------------------

    def _now(self) -> datetime:
        return self._clock()

    def _log(self, action: str, grant_id: str, actor: str, detail: str = "") -> None:
        self._audit.append(
            AuditEvent(action=action, grant_id=grant_id, actor=actor, detail=detail)
        )

    def _expire_due(self) -> None:
        """Lazily mark approved grants past their expiry as EXPIRED."""
        now = self._now()
        for grant in self._grants.values():
            if (
                grant.status is GrantStatus.APPROVED
                and grant.expires_at is not None
                and now >= grant.expires_at
            ):
                grant.status = GrantStatus.EXPIRED
                self._log("expire", grant.id, actor="system", detail="ttl elapsed")

    # -- lifecycle ---------------------------------------------------------

    def request_access(
        self,
        subject_id: str,
        role: str,
        target_resource: str,
        justification: str,
        requested_ttl: int,
    ) -> Grant:
        if role not in ROLE_MAX_TTL:
            raise AccessError(f"unknown role: {role!r}")
        if requested_ttl <= 0:
            raise AccessError("requested_ttl must be positive")
        if not justification or len(justification.strip()) < 8:
            raise AccessError("a substantive justification (>=8 chars) is required")
        ttl = min(requested_ttl, ROLE_MAX_TTL[role])

        grant = Grant(
            subject_id=subject_id,
            role=role,
            target_resource=target_resource,
            justification=justification.strip(),
            requested_ttl=ttl,
        )
        self._grants[grant.id] = grant
        self._log("request", grant.id, actor=subject_id, detail=f"role={role} ttl={ttl}s")

        # Roles that don't require human approval auto-activate immediately.
        if role not in ROLES_REQUIRING_APPROVAL:
            self._activate(grant, approver="auto-policy")
        return grant

    def approve(self, grant_id: str, approver: str) -> Grant:
        grant = self._require(grant_id)
        self._guard_pending(grant)
        if approver == grant.subject_id:
            raise AccessError("separation of duties: requester cannot approve own grant")
        self._activate(grant, approver=approver)
        return grant

    def deny(self, grant_id: str, approver: str, reason: str = "") -> Grant:
        grant = self._require(grant_id)
        self._guard_pending(grant)
        grant.status = GrantStatus.DENIED
        grant.decided_by = approver
        grant.decided_at = self._now()
        self._log("deny", grant.id, actor=approver, detail=reason)
        return grant

    def revoke(self, grant_id: str, actor: str, reason: str = "") -> Grant:
        grant = self._require(grant_id)
        if grant.status not in (GrantStatus.APPROVED, GrantStatus.PENDING):
            raise AccessError(f"cannot revoke grant in status {grant.status.value}")
        grant.status = GrantStatus.REVOKED
        grant.revoked_reason = reason
        grant.decided_by = actor
        grant.decided_at = self._now()
        self._log("revoke", grant.id, actor=actor, detail=reason)
        return grant

    def _activate(self, grant: Grant, approver: str) -> None:
        now = self._now()
        grant.status = GrantStatus.APPROVED
        grant.decided_by = approver
        grant.decided_at = now
        grant.activated_at = now
        grant.expires_at = now + timedelta(seconds=grant.requested_ttl)
        self._log(
            "approve", grant.id, actor=approver,
            detail=f"active until {grant.expires_at.isoformat()}",
        )

    # -- queries -----------------------------------------------------------

    def get(self, grant_id: str) -> Grant:
        self._expire_due()
        return self._require(grant_id)

    def list_grants(
        self, subject_id: str | None = None, status: GrantStatus | None = None
    ) -> list[Grant]:
        self._expire_due()
        grants = list(self._grants.values())
        if subject_id is not None:
            grants = [g for g in grants if g.subject_id == subject_id]
        if status is not None:
            grants = [g for g in grants if g.status is status]
        return sorted(grants, key=lambda g: g.requested_at, reverse=True)

    def active_grant_for(self, subject_id: str, target_resource: str) -> Grant | None:
        self._expire_due()
        now = self._now()
        for grant in self._grants.values():
            if (
                grant.subject_id == subject_id
                and grant.target_resource == target_resource
                and grant.is_active(now)
            ):
                return grant
        return None

    def audit_log(self, grant_id: str | None = None) -> list[AuditEvent]:
        if grant_id is None:
            return list(self._audit)
        return [e for e in self._audit if e.grant_id == grant_id]

    # -- access decision ---------------------------------------------------

    def check_access(
        self,
        subject_id: str,
        roles: list[str],
        resource_id: str,
        sensitivity: SensitivityLevel | str,
        action: str,
        context: dict | None = None,
    ) -> Decision:
        """Combine RBAC (roles + active JIT grant) with the ABAC engine.

        The presence of an active grant for this subject+resource is injected
        into the ABAC context as ``jit_grant_active``; the ABAC engine then
        makes the final call based on data sensitivity, MFA, and network tier.
        """
        self._expire_due()
        ctx = dict(context or {})
        grant = self.active_grant_for(subject_id, resource_id)
        ctx["jit_grant_active"] = grant is not None
        if grant is not None:
            ctx.setdefault("jit_grant_id", grant.id)
            # A grant confers its role for the decision.
            roles = list({*roles, grant.role})

        request = AccessRequest(
            subject=Subject(id=subject_id, roles=frozenset(roles)),
            resource=Resource(id=resource_id, sensitivity=SensitivityLevel.parse(sensitivity)),
            action=action,
            context=ctx,
        )
        decision = self._engine.evaluate(request)
        self._log(
            "access_check",
            grant.id if grant else "-",
            actor=subject_id,
            detail=f"{action} {resource_id} -> {decision.effect.value}",
        )
        return decision

    # -- internals ---------------------------------------------------------

    def _require(self, grant_id: str) -> Grant:
        grant = self._grants.get(grant_id)
        if grant is None:
            raise AccessError(f"no such grant: {grant_id}")
        return grant

    @staticmethod
    def _guard_pending(grant: Grant) -> None:
        if grant.status is not GrantStatus.PENDING:
            raise AccessError(
                f"grant {grant.id} is {grant.status.value}, expected pending"
            )
