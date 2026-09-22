"""End-to-end tests for the JIT broker HTTP API via FastAPI TestClient."""

from fastapi.testclient import TestClient

from phi_guardian.jit_access.app import create_app
from phi_guardian.jit_access.service import JITAccessService


def client() -> TestClient:
    return TestClient(create_app(JITAccessService()))


def test_healthz():
    assert client().get("/healthz").json() == {"status": "ok"}


def test_request_and_approve_flow():
    c = client()
    resp = c.post("/grants", json={
        "subject_id": "alice@ih.com",
        "role": "phi_operator",
        "target_resource": "arn:aws:s3:::ih-phi-exports-prod",
        "justification": "Investigating INC-4821",
        "requested_ttl": 900,
    })
    assert resp.status_code == 201
    grant = resp.json()
    assert grant["status"] == "pending"

    # Requester cannot approve their own grant.
    self_approve = c.post(f"/grants/{grant['id']}/approve", headers={"X-Actor": "alice@ih.com"})
    assert self_approve.status_code == 409

    # Approver activates it.
    approved = c.post(f"/grants/{grant['id']}/approve", headers={"X-Actor": "bob@ih.com"})
    assert approved.status_code == 200
    assert approved.json()["status"] == "approved"
    assert approved.json()["remaining_seconds"] > 0


def test_approve_requires_actor_header():
    c = client()
    grant = c.post("/grants", json={
        "subject_id": "alice@ih.com", "role": "phi_operator",
        "target_resource": "res", "justification": "valid reason here",
        "requested_ttl": 600,
    }).json()
    resp = c.post(f"/grants/{grant['id']}/approve")
    assert resp.status_code == 401


def test_access_check_endpoint():
    c = client()
    # PHI export with no grant -> denied.
    denied = c.post("/access/check", json={
        "subject_id": "alice@ih.com", "roles": ["phi_operator"],
        "resource_id": "res", "sensitivity": "phi", "action": "export",
        "context": {"mfa": True, "network_tier": "corp"},
    })
    assert denied.json()["allowed"] is False

    # Grant + approve, then re-check -> allowed.
    grant = c.post("/grants", json={
        "subject_id": "alice@ih.com", "role": "phi_operator",
        "target_resource": "res", "justification": "valid reason here",
        "requested_ttl": 600,
    }).json()
    c.post(f"/grants/{grant['id']}/approve", headers={"X-Actor": "bob@ih.com"})

    allowed = c.post("/access/check", json={
        "subject_id": "alice@ih.com", "roles": ["phi_operator"],
        "resource_id": "res", "sensitivity": "phi", "action": "export",
        "context": {"mfa": True, "network_tier": "corp"},
    })
    assert allowed.json()["allowed"] is True


def test_invalid_role_rejected():
    c = client()
    resp = c.post("/grants", json={
        "subject_id": "alice", "role": "root", "target_resource": "res",
        "justification": "valid reason here", "requested_ttl": 600,
    })
    assert resp.status_code == 400


def test_audit_endpoint_lists_events():
    c = client()
    grant = c.post("/grants", json={
        "subject_id": "alice", "role": "phi_reader", "target_resource": "res",
        "justification": "reviewing exports", "requested_ttl": 600,
    }).json()
    events = c.get("/audit", params={"grant_id": grant["id"]}).json()
    assert [e["action"] for e in events] == ["request", "approve"]
