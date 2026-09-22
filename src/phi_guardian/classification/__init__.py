"""Data classification and attribute-based access control (ABAC).

This package models data sensitivity as a first-class attribute and lets access
decisions depend on it, so that "how sensitive is this data?" directly informs
"who may touch it, from where, and for how long?" — the integration of data
classification with access control the role calls for.
"""

from .models import (
    AccessRequest,
    Decision,
    Effect,
    Resource,
    SensitivityLevel,
    Subject,
)
from .engine import PolicyEngine, Rule, default_engine

__all__ = [
    "AccessRequest",
    "Decision",
    "Effect",
    "Resource",
    "SensitivityLevel",
    "Subject",
    "PolicyEngine",
    "Rule",
    "default_engine",
]
