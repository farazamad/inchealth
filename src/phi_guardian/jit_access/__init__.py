"""Just-in-time (JIT) access broker.

Standing access to production PHI is the largest blast radius in a HIPAA
environment. This package grants *time-bound, approval-gated, audited* access
instead: a subject requests a role on a target for a bounded window, an
approver signs off, the grant activates, and it auto-expires. Every state
change is written to an append-only audit log, and access checks are delegated
to the ABAC engine so data sensitivity still governs the final decision.
"""

from .models import Grant, GrantStatus, AuditEvent
from .service import JITAccessService, AccessError

__all__ = ["Grant", "GrantStatus", "AuditEvent", "JITAccessService", "AccessError"]
