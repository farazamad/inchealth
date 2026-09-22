"""A small, dependency-free ABAC policy engine.

Rules are ordered predicates that can ALLOW or DENY a request. Evaluation is
*deny-overrides* with an implicit default-deny: a request is permitted only if
at least one ALLOW rule matches and no DENY rule matches. This keeps PHI access
fail-closed.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Callable

from .models import AccessRequest, Decision, Effect, SensitivityLevel

Predicate = Callable[[AccessRequest], bool]


@dataclass
class Rule:
    """A named ABAC rule: if ``predicate`` holds, contribute ``effect``."""

    name: str
    effect: Effect
    predicate: Predicate
    description: str = ""


class PolicyEngine:
    """Evaluates access requests against an ordered set of rules."""

    def __init__(self, rules: list[Rule] | None = None) -> None:
        self._rules: list[Rule] = list(rules or [])

    def add(self, rule: Rule) -> "PolicyEngine":
        self._rules.append(rule)
        return self

    @property
    def rules(self) -> list[Rule]:
        return list(self._rules)

    def evaluate(self, request: AccessRequest) -> Decision:
        matched_allow: list[str] = []
        matched_deny: list[str] = []
        reasons: list[str] = []

        for rule in self._rules:
            try:
                hit = rule.predicate(request)
            except Exception:  # a broken rule must never fail open
                hit = False
                reasons.append(f"rule '{rule.name}' errored; treated as no-match")
            if not hit:
                continue
            if rule.effect is Effect.DENY:
                matched_deny.append(rule.name)
                reasons.append(f"DENY by '{rule.name}': {rule.description}")
            else:
                matched_allow.append(rule.name)
                reasons.append(f"ALLOW by '{rule.name}': {rule.description}")

        # Deny overrides.
        if matched_deny:
            return Decision(Effect.DENY, matched_deny[0], reasons)
        if matched_allow:
            return Decision(Effect.ALLOW, matched_allow[0], reasons)
        reasons.append("default-deny: no rule granted access")
        return Decision(Effect.DENY, None, reasons)


# --- default policy set -----------------------------------------------------

_WRITE_ACTIONS = {"write", "update", "delete", "export", "admin"}


def _is_phi(req: AccessRequest) -> bool:
    return req.resource.sensitivity >= SensitivityLevel.PHI


def _mfa_present(req: AccessRequest) -> bool:
    return bool(req.context.get("mfa"))


def _network_trusted(req: AccessRequest) -> bool:
    # Absence of an explicit tier is treated as untrusted (fail-closed).
    return req.context.get("network_tier") in {"corp", "vpn", "trusted"}


def _has_active_grant(req: AccessRequest) -> bool:
    return bool(req.context.get("jit_grant_active"))


def default_engine() -> PolicyEngine:
    """A policy set encoding a HIPAA-minded default for PHI access."""

    rules = [
        # --- DENY rules (evaluated with override priority) ---
        Rule(
            "deny-phi-without-mfa",
            Effect.DENY,
            lambda r: _is_phi(r) and not _mfa_present(r),
            "PHI access requires multi-factor authentication",
        ),
        Rule(
            "deny-phi-untrusted-network",
            Effect.DENY,
            lambda r: _is_phi(r) and not _network_trusted(r),
            "PHI may only be accessed from a trusted network (corp/VPN)",
        ),
        Rule(
            "deny-phi-write-without-jit",
            Effect.DENY,
            lambda r: _is_phi(r) and r.action in _WRITE_ACTIONS and not _has_active_grant(r),
            "mutating/exporting PHI requires an active just-in-time grant",
        ),
        Rule(
            "deny-quarantined-subject",
            Effect.DENY,
            lambda r: bool(r.subject.attributes.get("quarantined")),
            "subject is quarantined pending security review",
        ),
        # --- ALLOW rules ---
        Rule(
            "allow-phi-clinical-read",
            Effect.ALLOW,
            lambda r: _is_phi(r)
            and r.action == "read"
            and (r.subject.has_role("clinician") or r.subject.has_role("phi_reader")),
            "clinicians and PHI readers may read PHI (subject to the deny rules)",
        ),
        Rule(
            "allow-phi-write-with-grant",
            Effect.ALLOW,
            lambda r: _is_phi(r)
            and r.action in _WRITE_ACTIONS
            and r.subject.has_role("phi_operator")
            and _has_active_grant(r),
            "PHI operators with an active JIT grant may mutate PHI",
        ),
        Rule(
            "allow-nonphi-authenticated",
            Effect.ALLOW,
            lambda r: not _is_phi(r) and bool(r.subject.id),
            "any authenticated subject may access non-PHI resources",
        ),
    ]
    return PolicyEngine(rules)
