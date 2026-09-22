"""Core data models for classification and ABAC decisions."""

from __future__ import annotations

import enum
from dataclasses import dataclass, field
from typing import Any, Mapping


class SensitivityLevel(enum.IntEnum):
    """Ordered data-classification levels. Higher means more sensitive.

    PHI (protected health information) is the most sensitive tier and pulls in
    the strictest controls throughout the platform.
    """

    PUBLIC = 0
    INTERNAL = 1
    CONFIDENTIAL = 2
    PHI = 3

    @classmethod
    def parse(cls, value: str | "SensitivityLevel") -> "SensitivityLevel":
        if isinstance(value, SensitivityLevel):
            return value
        key = str(value).strip().upper()
        aliases = {"RESTRICTED": cls.PHI, "PII": cls.PHI, "SECRET": cls.CONFIDENTIAL}
        if key in aliases:
            return aliases[key]
        try:
            return cls[key]
        except KeyError as exc:  # pragma: no cover - defensive
            raise ValueError(f"unknown sensitivity level: {value!r}") from exc


class Effect(enum.Enum):
    ALLOW = "allow"
    DENY = "deny"


@dataclass(frozen=True)
class Subject:
    """The principal requesting access."""

    id: str
    roles: frozenset[str] = field(default_factory=frozenset)
    attributes: Mapping[str, Any] = field(default_factory=dict)

    def has_role(self, role: str) -> bool:
        return role in self.roles


@dataclass(frozen=True)
class Resource:
    """The thing being accessed, tagged with a sensitivity level."""

    id: str
    sensitivity: SensitivityLevel
    attributes: Mapping[str, Any] = field(default_factory=dict)


@dataclass(frozen=True)
class AccessRequest:
    """A subject asking to perform an action on a resource, in some context.

    ``context`` carries request-time facts such as whether MFA was used, the
    source IP trust tier, or whether an approved just-in-time grant is active.
    """

    subject: Subject
    resource: Resource
    action: str
    context: Mapping[str, Any] = field(default_factory=dict)


@dataclass
class Decision:
    """The outcome of evaluating an AccessRequest."""

    effect: Effect
    matched_rule: str | None
    reasons: list[str] = field(default_factory=list)

    @property
    def allowed(self) -> bool:
        return self.effect is Effect.ALLOW

    def as_dict(self) -> dict[str, Any]:
        return {
            "effect": self.effect.value,
            "allowed": self.allowed,
            "matched_rule": self.matched_rule,
            "reasons": self.reasons,
        }
