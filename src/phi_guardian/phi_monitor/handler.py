"""Normalization and the AWS Lambda entrypoint for the PHI monitor."""

from __future__ import annotations

import base64
import json
from datetime import datetime, timezone
from typing import Any, Mapping

from .detector import DetectionEngine, default_detector
from .models import AccessEvent, summarize


def _parse_ts(value: Any) -> datetime:
    if isinstance(value, datetime):
        return value
    if isinstance(value, (int, float)):
        return datetime.fromtimestamp(value, tz=timezone.utc)
    if isinstance(value, str):
        text = value.replace("Z", "+00:00")
        try:
            dt = datetime.fromisoformat(text)
        except ValueError:
            return datetime.now(timezone.utc)
        return dt if dt.tzinfo else dt.replace(tzinfo=timezone.utc)
    return datetime.now(timezone.utc)


def normalize(
    record: Mapping[str, Any],
    classification_map: Mapping[str, str] | None = None,
) -> AccessEvent:
    """Turn a CloudTrail-style or pre-normalized record into an AccessEvent.

    ``classification_map`` resolves a resource (e.g. an S3 bucket name) to a
    data-classification level, modeling a lookup against a data catalog.
    """
    classification_map = classification_map or {}

    # Already-normalized shape (has a top-level "principal").
    if "principal" in record:
        resource = str(record.get("resource", ""))
        classification = str(
            record.get("data_classification")
            or classification_map.get(resource, "unknown")
        )
        return AccessEvent(
            principal=str(record["principal"]),
            action=str(record.get("action", "")),
            resource=resource,
            timestamp=_parse_ts(record.get("timestamp")),
            source_ip=record.get("source_ip"),
            bytes_transferred=int(record.get("bytes_transferred", 0) or 0),
            data_classification=classification,
            error_code=record.get("error_code"),
            dest_account=record.get("dest_account"),
            is_public_destination=bool(record.get("is_public_destination", False)),
            jit_grant_active=bool(record.get("jit_grant_active", False)),
            country=record.get("country"),
            raw=dict(record),
        )

    # CloudTrail S3 data-event shape.
    params = record.get("requestParameters") or {}
    bucket = params.get("bucketName", "")
    extra = record.get("additionalEventData") or {}
    identity = record.get("userIdentity") or {}
    principal = identity.get("arn") or identity.get("principalId") or "unknown"
    classification = str(
        extra.get("dataClassification")
        or classification_map.get(bucket, "unknown")
    )
    return AccessEvent(
        principal=str(principal),
        action=str(record.get("eventName", "")),
        resource=bucket,
        timestamp=_parse_ts(record.get("eventTime")),
        source_ip=record.get("sourceIPAddress"),
        bytes_transferred=int(extra.get("bytesTransferredOut", 0) or 0),
        data_classification=classification,
        error_code=record.get("errorCode"),
        dest_account=record.get("destinationAccountId"),
        is_public_destination=bool(extra.get("isPublicDestination", False)),
        jit_grant_active=bool(extra.get("jitGrantActive", False)),
        country=(record.get("geoLocation") or {}).get("country"),
        raw=dict(record),
    )


def _iter_records(event: Mapping[str, Any]) -> list[Mapping[str, Any]]:
    """Yield underlying records from Lambda event envelopes.

    Supports a plain ``{"records": [...]}`` batch and Kinesis' base64 envelope.
    """
    raw = event.get("Records") or event.get("records") or []
    out: list[Mapping[str, Any]] = []
    for rec in raw:
        if isinstance(rec, Mapping) and "kinesis" in rec:
            data = rec["kinesis"].get("data", "")
            decoded = base64.b64decode(data).decode("utf-8")
            out.append(json.loads(decoded))
        elif isinstance(rec, Mapping):
            out.append(rec)
    return out


def process_events(
    records: list[Mapping[str, Any]],
    detector: DetectionEngine | None = None,
    classification_map: Mapping[str, str] | None = None,
) -> dict[str, Any]:
    """Normalize records, run detection, and return a result payload."""
    detector = detector or default_detector()
    events = [normalize(r, classification_map) for r in records]
    alerts = detector.evaluate(events)
    return {
        "processed": len(events),
        "alert_count": len(alerts),
        "summary": summarize(alerts),
        "alerts": [a.as_dict() for a in alerts],
    }


def lambda_handler(event: Mapping[str, Any], context: Any = None) -> dict[str, Any]:
    """AWS Lambda entrypoint.

    Wire behind a Kinesis stream of CloudTrail/S3 access events, or invoke
    directly with ``{"records": [...]}``. Returns a JSON-serializable result;
    a real deployment would additionally publish CRITICAL/HIGH alerts to SNS or
    Security Hub.
    """
    classification_map = None
    if isinstance(event, Mapping):
        classification_map = event.get("classification_map")
    records = _iter_records(event) if isinstance(event, Mapping) else []
    return process_events(records, classification_map=classification_map)
