"""FastAPI surface for the JIT access broker.

Endpoints:
    POST   /grants                 request time-bound access
    GET    /grants                 list grants (filter by subject/status)
    GET    /grants/{id}            fetch a grant
    POST   /grants/{id}/approve    approver activates a pending grant
    POST   /grants/{id}/deny       approver rejects a pending grant
    POST   /grants/{id}/revoke     revoke an active grant early
    POST   /access/check           evaluate an access decision (RBAC + ABAC)
    GET    /audit                  read the append-only audit log
    GET    /healthz                liveness

The header ``X-Actor`` identifies the calling principal for approve/deny/revoke;
in production this would be the authenticated identity from your IdP/mTLS.
"""

from __future__ import annotations

from typing import Any

from fastapi import FastAPI, Header, HTTPException
from pydantic import BaseModel, Field

from ..classification import SensitivityLevel
from .models import GrantStatus
from .service import AccessError, JITAccessService


class AccessRequestBody(BaseModel):
    subject_id: str = Field(..., examples=["alice@includedhealth.com"])
    role: str = Field(..., examples=["phi_operator"])
    target_resource: str = Field(..., examples=["arn:aws:s3:::ih-phi-exports-prod"])
    justification: str = Field(..., min_length=8, examples=["Investigating INC-4821 data mismatch"])
    requested_ttl: int = Field(..., gt=0, examples=[1800])


class DecisionBody(BaseModel):
    reason: str = ""


class CheckBody(BaseModel):
    subject_id: str
    roles: list[str] = Field(default_factory=list)
    resource_id: str
    sensitivity: str = Field("phi", examples=["phi", "confidential", "internal"])
    action: str = Field(..., examples=["read", "export", "write"])
    context: dict[str, Any] = Field(default_factory=dict)


def create_app(service: JITAccessService | None = None) -> FastAPI:
    svc = service or JITAccessService()
    app = FastAPI(
        title="PHI Guardian — JIT Access Broker",
        version="0.1.0",
        summary="Time-bound, approval-gated, audited access to production PHI.",
    )

    def _actor(x_actor: str | None) -> str:
        if not x_actor:
            raise HTTPException(status_code=401, detail="missing X-Actor header")
        return x_actor

    @app.get("/healthz")
    def healthz() -> dict[str, str]:
        return {"status": "ok"}

    @app.post("/grants", status_code=201)
    def request_grant(body: AccessRequestBody) -> dict[str, Any]:
        try:
            grant = svc.request_access(
                subject_id=body.subject_id,
                role=body.role,
                target_resource=body.target_resource,
                justification=body.justification,
                requested_ttl=body.requested_ttl,
            )
        except AccessError as exc:
            raise HTTPException(status_code=400, detail=str(exc)) from exc
        return grant.as_dict()

    @app.get("/grants")
    def list_grants(subject_id: str | None = None, status: str | None = None) -> list[dict[str, Any]]:
        parsed_status = None
        if status is not None:
            try:
                parsed_status = GrantStatus(status)
            except ValueError as exc:
                raise HTTPException(status_code=400, detail=f"bad status: {status}") from exc
        return [g.as_dict() for g in svc.list_grants(subject_id=subject_id, status=parsed_status)]

    @app.get("/grants/{grant_id}")
    def get_grant(grant_id: str) -> dict[str, Any]:
        try:
            return svc.get(grant_id).as_dict()
        except AccessError as exc:
            raise HTTPException(status_code=404, detail=str(exc)) from exc

    @app.post("/grants/{grant_id}/approve")
    def approve(grant_id: str, x_actor: str | None = Header(default=None)) -> dict[str, Any]:
        try:
            return svc.approve(grant_id, approver=_actor(x_actor)).as_dict()
        except AccessError as exc:
            raise HTTPException(status_code=409, detail=str(exc)) from exc

    @app.post("/grants/{grant_id}/deny")
    def deny(grant_id: str, body: DecisionBody, x_actor: str | None = Header(default=None)) -> dict[str, Any]:
        try:
            return svc.deny(grant_id, approver=_actor(x_actor), reason=body.reason).as_dict()
        except AccessError as exc:
            raise HTTPException(status_code=409, detail=str(exc)) from exc

    @app.post("/grants/{grant_id}/revoke")
    def revoke(grant_id: str, body: DecisionBody, x_actor: str | None = Header(default=None)) -> dict[str, Any]:
        try:
            return svc.revoke(grant_id, actor=_actor(x_actor), reason=body.reason).as_dict()
        except AccessError as exc:
            raise HTTPException(status_code=409, detail=str(exc)) from exc

    @app.post("/access/check")
    def check_access(body: CheckBody) -> dict[str, Any]:
        try:
            sensitivity = SensitivityLevel.parse(body.sensitivity)
        except ValueError as exc:
            raise HTTPException(status_code=400, detail=str(exc)) from exc
        decision = svc.check_access(
            subject_id=body.subject_id,
            roles=body.roles,
            resource_id=body.resource_id,
            sensitivity=sensitivity,
            action=body.action,
            context=body.context,
        )
        return decision.as_dict()

    @app.get("/audit")
    def audit(grant_id: str | None = None) -> list[dict[str, Any]]:
        return [e.as_dict() for e in svc.audit_log(grant_id=grant_id)]

    return app


# Module-level app for `uvicorn phi_guardian.jit_access.app:app`.
app = create_app()
