"""PHI access monitoring and exfiltration detection.

Consumes normalized data-access events (from CloudTrail, S3 server access logs,
or an application audit stream), scores them against a set of exfiltration
heuristics, and emits alerts. The core is pure and deterministic; a thin
``lambda_handler`` adapts it to run as an AWS Lambda behind Kinesis/S3.
"""

from .models import AccessEvent, Alert, AlertSeverity
from .detector import DetectionEngine, default_detector
from .handler import lambda_handler, process_events

__all__ = [
    "AccessEvent",
    "Alert",
    "AlertSeverity",
    "DetectionEngine",
    "default_detector",
    "lambda_handler",
    "process_events",
]
