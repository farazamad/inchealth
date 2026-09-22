"""Tests for the data-classification ABAC engine."""

from phi_guardian.classification import (
    AccessRequest,
    Effect,
    Resource,
    SensitivityLevel,
    Subject,
    default_engine,
)


def make_request(**kw):
    subject = Subject(
        id=kw.get("subject_id", "alice"),
        roles=frozenset(kw.get("roles", [])),
        attributes=kw.get("subject_attrs", {}),
    )
    resource = Resource(
        id=kw.get("resource_id", "res"),
        sensitivity=SensitivityLevel.parse(kw.get("sensitivity", "phi")),
    )
    return AccessRequest(
        subject=subject,
        resource=resource,
        action=kw.get("action", "read"),
        context=kw.get("context", {}),
    )


def test_sensitivity_parsing_aliases():
    assert SensitivityLevel.parse("restricted") is SensitivityLevel.PHI
    assert SensitivityLevel.parse("PII") is SensitivityLevel.PHI
    assert SensitivityLevel.parse("internal") is SensitivityLevel.INTERNAL
    assert SensitivityLevel.PHI > SensitivityLevel.CONFIDENTIAL


def test_phi_read_denied_without_mfa():
    engine = default_engine()
    req = make_request(roles=["clinician"], action="read", context={"network_tier": "corp"})
    decision = engine.evaluate(req)
    assert decision.effect is Effect.DENY
    assert decision.matched_rule == "deny-phi-without-mfa"


def test_phi_read_denied_from_untrusted_network():
    engine = default_engine()
    req = make_request(roles=["clinician"], action="read", context={"mfa": True})
    decision = engine.evaluate(req)
    assert not decision.allowed
    assert decision.matched_rule == "deny-phi-untrusted-network"


def test_phi_read_allowed_for_clinician_with_mfa_on_trusted_net():
    engine = default_engine()
    req = make_request(
        roles=["clinician"], action="read",
        context={"mfa": True, "network_tier": "corp"},
    )
    decision = engine.evaluate(req)
    assert decision.allowed
    assert decision.matched_rule == "allow-phi-clinical-read"


def test_phi_write_requires_jit_grant():
    engine = default_engine()
    ctx = {"mfa": True, "network_tier": "vpn"}
    denied = engine.evaluate(make_request(roles=["phi_operator"], action="export", context=ctx))
    assert not denied.allowed
    assert denied.matched_rule == "deny-phi-write-without-jit"

    ctx_with_grant = {**ctx, "jit_grant_active": True}
    allowed = engine.evaluate(
        make_request(roles=["phi_operator"], action="export", context=ctx_with_grant)
    )
    assert allowed.allowed
    assert allowed.matched_rule == "allow-phi-write-with-grant"


def test_quarantined_subject_denied_even_on_public_data():
    engine = default_engine()
    req = make_request(
        sensitivity="public", action="read",
        subject_attrs={"quarantined": True},
    )
    decision = engine.evaluate(req)
    assert not decision.allowed
    assert decision.matched_rule == "deny-quarantined-subject"


def test_non_phi_allowed_for_authenticated_subject():
    engine = default_engine()
    decision = engine.evaluate(make_request(sensitivity="internal", action="read"))
    assert decision.allowed


def test_default_deny_when_no_rule_matches():
    engine = default_engine()
    # PHI read by someone with no clinical role, but MFA + trusted net so the
    # deny rules do not fire -> should fall through to default-deny.
    req = make_request(roles=["intern"], action="read", context={"mfa": True, "network_tier": "corp"})
    decision = engine.evaluate(req)
    assert not decision.allowed
    assert decision.matched_rule is None
    assert any("default-deny" in r for r in decision.reasons)
