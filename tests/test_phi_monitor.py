"""Tests for the PHI exfiltration detector and Lambda handler."""

import base64
import json
from datetime import datetime, timezone

from phi_guardian.phi_monitor import (
    AccessEvent,
    AlertSeverity,
    DetectionEngine,
    lambda_handler,
    process_events,
)
from phi_guardian.phi_monitor.detector import DetectorConfig


def ev(**kw) -> AccessEvent:
    defaults = dict(
        principal="arn:aws:sts::123:assumed-role/App/session",
        action="GetObject",
        resource="ih-phi-exports-prod",
        timestamp=datetime(2026, 1, 1, 15, 0, tzinfo=timezone.utc),
        data_classification="phi",
        jit_grant_active=True,
    )
    defaults.update(kw)
    return AccessEvent(**defaults)


def rule_ids(alerts):
    return {a.rule_id for a in alerts}


def test_public_destination_is_critical():
    alerts = DetectionEngine().evaluate([ev(action="CopyObject", is_public_destination=True)])
    assert "EXFIL-001" in rule_ids(alerts)
    assert any(a.severity is AlertSeverity.CRITICAL for a in alerts)


def test_untrusted_account_copy_is_critical():
    alerts = DetectionEngine().evaluate([ev(action="CopyObject", dest_account="999999999999")])
    assert "EXFIL-002" in rule_ids(alerts)


def test_access_without_jit_grant_flagged():
    alerts = DetectionEngine().evaluate([ev(jit_grant_active=False)])
    assert "EXFIL-003" in rule_ids(alerts)


def test_access_with_jit_grant_not_flagged_for_003():
    alerts = DetectionEngine().evaluate([ev(jit_grant_active=True)])
    assert "EXFIL-003" not in rule_ids(alerts)


def test_unexpected_country():
    alerts = DetectionEngine().evaluate([ev(country="RU")])
    assert "EXFIL-004" in rule_ids(alerts)


def test_allowed_country_not_flagged():
    alerts = DetectionEngine().evaluate([ev(country="US")])
    assert "EXFIL-004" not in rule_ids(alerts)


def test_non_phi_not_flagged():
    alerts = DetectionEngine().evaluate([ev(data_classification="internal", jit_grant_active=False)])
    assert alerts == []


def test_bulk_bytes_egress():
    config = DetectorConfig(bulk_bytes_threshold=1000, bulk_object_threshold=10_000)
    events = [ev(bytes_transferred=600), ev(bytes_transferred=600)]
    alerts = DetectionEngine(config).evaluate(events)
    assert "EXFIL-005" in rule_ids(alerts)


def test_bulk_object_count_egress():
    config = DetectorConfig(bulk_bytes_threshold=10**12, bulk_object_threshold=3)
    events = [ev(bytes_transferred=1) for _ in range(3)]
    alerts = DetectionEngine(config).evaluate(events)
    bulk = [a for a in alerts if a.rule_id == "EXFIL-005"]
    assert bulk and bulk[0].evidence["object_count"] == 3


def test_privilege_probing():
    events = [ev(error_code="AccessDenied") for _ in range(5)]
    alerts = DetectionEngine().evaluate(events)
    assert "EXFIL-007" in rule_ids(alerts)


def test_off_hours_low_severity():
    off = ev(timestamp=datetime(2026, 1, 1, 4, 0, tzinfo=timezone.utc))
    alerts = DetectionEngine().evaluate([off])
    assert "EXFIL-006" in rule_ids(alerts)


def test_lambda_handler_with_cloudtrail_record():
    record = {
        "eventTime": "2026-01-01T03:00:00Z",
        "eventName": "GetObject",
        "userIdentity": {"arn": "arn:aws:sts::123:assumed-role/App/leaky"},
        "sourceIPAddress": "203.0.113.9",
        "requestParameters": {"bucketName": "ih-phi-exports-prod"},
        "additionalEventData": {"bytesTransferredOut": 5, "jitGrantActive": False},
        "geoLocation": {"country": "RU"},
    }
    result = lambda_handler(
        {"records": [record], "classification_map": {"ih-phi-exports-prod": "phi"}}
    )
    assert result["processed"] == 1
    ids = {a["rule_id"] for a in result["alerts"]}
    assert {"EXFIL-003", "EXFIL-004"}.issubset(ids)


def test_lambda_handler_kinesis_envelope():
    payload = {
        "principal": "svc-etl",
        "action": "GetObject",
        "resource": "ih-phi-exports-prod",
        "data_classification": "phi",
        "jit_grant_active": False,
        "timestamp": "2026-01-01T15:00:00Z",
    }
    encoded = base64.b64encode(json.dumps(payload).encode()).decode()
    event = {"Records": [{"kinesis": {"data": encoded}}]}
    result = lambda_handler(event)
    assert result["processed"] == 1
    assert "EXFIL-003" in {a["rule_id"] for a in result["alerts"]}


def test_process_events_summary():
    result = process_events([{
        "principal": "p", "action": "GetObject", "resource": "b",
        "data_classification": "phi", "jit_grant_active": False,
        "timestamp": "2026-01-01T15:00:00Z",
    }])
    assert result["alert_count"] >= 1
    assert "HIGH" in result["summary"]
