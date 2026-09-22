"""Tests for the JIT access broker service logic."""

from datetime import datetime, timedelta, timezone

import pytest

from phi_guardian.classification import SensitivityLevel
from phi_guardian.jit_access import AccessError, GrantStatus, JITAccessService


class FakeClock:
    def __init__(self, start: datetime) -> None:
        self.now = start

    def __call__(self) -> datetime:
        return self.now

    def advance(self, seconds: int) -> None:
        self.now += timedelta(seconds=seconds)


@pytest.fixture
def clock():
    return FakeClock(datetime(2026, 1, 1, 15, 0, 0, tzinfo=timezone.utc))


@pytest.fixture
def svc(clock):
    return JITAccessService(clock=clock)


def test_request_validation(svc):
    with pytest.raises(AccessError):
        svc.request_access("alice", "not_a_role", "res", "valid justification", 60)
    with pytest.raises(AccessError):
        svc.request_access("alice", "phi_reader", "res", "short", 60)
    with pytest.raises(AccessError):
        svc.request_access("alice", "phi_reader", "res", "valid justification", 0)


def test_ttl_capped_to_role_ceiling(svc):
    grant = svc.request_access("alice", "db_admin", "db", "debugging prod issue", 999999)
    # db_admin ceiling is 1800s
    assert grant.requested_ttl == 1800


def test_auto_activation_for_non_approval_role(svc):
    grant = svc.request_access("alice", "phi_reader", "bucket", "reviewing exports", 3600)
    assert grant.status is GrantStatus.APPROVED
    assert grant.is_active(svc._now())


def test_approval_required_role_starts_pending(svc):
    grant = svc.request_access("alice", "phi_operator", "bucket", "fixing INC-1", 600)
    assert grant.status is GrantStatus.PENDING


def test_separation_of_duties(svc):
    grant = svc.request_access("alice", "phi_operator", "bucket", "fixing INC-1", 600)
    with pytest.raises(AccessError):
        svc.approve(grant.id, approver="alice")
    approved = svc.approve(grant.id, approver="bob")
    assert approved.status is GrantStatus.APPROVED
    assert approved.decided_by == "bob"


def test_grant_expires_after_ttl(svc, clock):
    grant = svc.request_access("alice", "phi_reader", "bucket", "reviewing exports", 300)
    assert grant.is_active(clock())
    clock.advance(301)
    refreshed = svc.get(grant.id)
    assert refreshed.status is GrantStatus.EXPIRED
    assert not refreshed.is_active(clock())


def test_revoke_active_grant(svc):
    grant = svc.request_access("alice", "phi_reader", "bucket", "reviewing exports", 300)
    revoked = svc.revoke(grant.id, actor="secops", reason="incident")
    assert revoked.status is GrantStatus.REVOKED
    assert revoked.revoked_reason == "incident"


def test_cannot_approve_non_pending(svc):
    grant = svc.request_access("alice", "phi_reader", "bucket", "reviewing exports", 300)
    with pytest.raises(AccessError):
        svc.approve(grant.id, approver="bob")  # already auto-approved


def test_audit_log_records_lifecycle(svc):
    grant = svc.request_access("alice", "phi_operator", "bucket", "fixing INC-1", 600)
    svc.approve(grant.id, approver="bob")
    svc.revoke(grant.id, actor="secops", reason="done")
    actions = [e.action for e in svc.audit_log(grant.id)]
    assert actions == ["request", "approve", "revoke"]


def test_check_access_uses_active_grant(svc):
    # No grant: PHI export denied.
    denied = svc.check_access(
        "alice", ["phi_operator"], "bucket", SensitivityLevel.PHI, "export",
        context={"mfa": True, "network_tier": "corp"},
    )
    assert not denied.allowed

    # With active grant on that resource: allowed.
    grant = svc.request_access("alice", "phi_operator", "bucket", "fixing INC-1", 600)
    svc.approve(grant.id, approver="bob")
    allowed = svc.check_access(
        "alice", ["phi_operator"], "bucket", SensitivityLevel.PHI, "export",
        context={"mfa": True, "network_tier": "corp"},
    )
    assert allowed.allowed
    assert allowed.matched_rule == "allow-phi-write-with-grant"


def test_active_grant_scoped_to_resource(svc):
    grant = svc.request_access("alice", "phi_operator", "bucket-a", "fixing INC-1", 600)
    svc.approve(grant.id, approver="bob")
    # Grant is for bucket-a; bucket-b should not be covered.
    assert svc.active_grant_for("alice", "bucket-a") is not None
    assert svc.active_grant_for("alice", "bucket-b") is None
