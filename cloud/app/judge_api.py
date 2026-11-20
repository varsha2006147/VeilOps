"""Judge Mode REST API: SLO report, render acknowledgements, injections, reconciliation,
alert feedback and CSV evidence export. Tenant comes only from the verified JWT."""
import csv
import io
import json
from datetime import datetime, timedelta, timezone
from typing import Literal
from uuid import UUID, uuid4

from fastapi import APIRouter, HTTPException, Query, Request
from fastapi.responses import StreamingResponse
from pydantic import BaseModel, ConfigDict, Field, field_validator

from cloud.app import judge
from cloud.app.api import require_role, tenant_from_request

router = APIRouter(prefix="/api/v1", tags=["judge-mode"])
MAX_CLOCK_OFFSET = timedelta(minutes=5)
WRITE_ROLES = {"operator", "approver", "tenant_admin"}


def _aware(value: datetime) -> datetime:
    if value.tzinfo is None:
        raise ValueError("timestamp must include a timezone")
    return value.astimezone(timezone.utc)


def _started_at(request: Request) -> datetime:
    return getattr(request.app.state, "started_at", None) or datetime.now(timezone.utc)


async def _publish(request: Request, tenant: str, payload: dict) -> None:
    try:
        await request.app.state.redis.publish(
            f"veilops:tenant:{tenant}:events", json.dumps(payload, default=str))
    except Exception:
        pass  # live push is best effort; the measurement is already committed


# ------------------------------------------------------------------ report

@router.get("/slo")
async def slo(request: Request, limit: int = Query(200, ge=0, le=10000)):
    tenant = tenant_from_request(request)
    now = datetime.now(timezone.utc)
    async with request.app.state.db_pool.acquire() as conn:
        async with conn.transaction():
            await conn.execute("SELECT set_config('app.tenant_id',$1,true)", tenant)
            report = await judge.judge_report(conn, tenant, now, _started_at(request))
            rows = await conn.fetch(
                """SELECT kind,sample_key,event_ts,observed_ts,delay_ms FROM slo_samples
                   WHERE tenant_id=$1 ORDER BY observed_ts DESC LIMIT $2""",
                tenant, limit,
            ) if limit else []
    report["samples"] = [dict(r) for r in rows]
    return report


@router.get("/slo/judge-mode")
async def judge_mode(request: Request):
    return await slo(request, limit=0)


# ------------------------------------------------------------------ collection -> dashboard

class RenderAck(BaseModel):
    model_config = ConfigDict(extra="forbid")
    record_key: str = Field(min_length=8, max_length=200)
    rendered_at: datetime
    client_sent_at: datetime | None = None

    @field_validator("record_key")
    @classmethod
    def _key(cls, v: str) -> str:
        if not judge.RECORD_KEY_RE.match(v):
            raise ValueError("record_key must be payload:<uuid>, alert:<uuid> or metric:<entity>|<metric>|<event_ts>")
        return v

    @field_validator("rendered_at", "client_sent_at")
    @classmethod
    def _tz(cls, v):
        return None if v is None else _aware(v)


@router.post("/slo/render-ack", status_code=202)
async def render_ack(payload: RenderAck, request: Request):
    tenant = tenant_from_request(request)
    received = datetime.now(timezone.utc)
    if payload.client_sent_at is not None:
        offset = received - payload.client_sent_at   # clock difference + one-way network time
        if abs(offset) > MAX_CLOCK_OFFSET:
            raise HTTPException(422, detail={"code": "CLOCK_SKEW_TOO_LARGE"})
        if payload.rendered_at > payload.client_sent_at:
            raise HTTPException(422, detail={"code": "INVALID_RENDER_TIMESTAMPS"})
    else:
        offset = timedelta(0)
    rendered = payload.rendered_at + offset
    if rendered > received + timedelta(seconds=1):
        raise HTTPException(422, detail={"code": "INVALID_RENDER_TIMESTAMPS"})

    async with request.app.state.db_pool.acquire() as conn:
        async with conn.transaction():
            await conn.execute("SELECT set_config('app.tenant_id',$1,true)", tenant)
            event_ts = await judge.resolve_record_event_ts(conn, tenant, payload.record_key)
            if event_ts is None:
                raise HTTPException(404, detail={"code": "RECORD_NOT_FOUND"})
            delay_ms = int((rendered - event_ts).total_seconds() * 1000)
            if delay_ms < 0:
                raise HTTPException(422, detail={"code": "INVALID_RENDER_TIMESTAMPS"})
            details = {"rendered_at_client": payload.rendered_at.isoformat(),
                       "clock_offset_ms": int(offset.total_seconds() * 1000),
                       "offset_corrected": payload.client_sent_at is not None,
                       "ack_received_at": received.isoformat()}
            inserted = await conn.fetchval(
                """INSERT INTO slo_samples
                   (tenant_id,kind,sample_key,event_ts,observed_ts,delay_ms,details)
                   VALUES($1,'collection_to_dashboard',$2,$3,$4,$5,$6::jsonb)
                   ON CONFLICT(tenant_id,kind,sample_key,event_ts) DO NOTHING
                   RETURNING 1""",
                tenant, payload.record_key, event_ts, rendered, delay_ms, json.dumps(details),
            )
            await conn.execute(
                """INSERT INTO audit_events(tenant_id,actor_id,action,resource_type,resource_id,details)
                   VALUES($1,$2,'slo.render_ack','slo_sample',$3,$4::jsonb)""",
                tenant, str(request.state.user_id), payload.record_key,
                json.dumps({"delay_ms": delay_ms, **details}),
            )
    if inserted:
        await _publish(request, tenant, {"event": "slo_sample", "kind": "collection_to_dashboard",
                                         "delay_ms": delay_ms})
    return {"accepted": True, "recorded": bool(inserted), "delay_ms": delay_ms,
            "clock_offset_ms": details["clock_offset_ms"]}


# ------------------------------------------------------------------ breach -> alert injections

class InjectionIn(BaseModel):
    model_config = ConfigDict(extra="forbid")
    scenario: str = Field(min_length=1, max_length=64, pattern=r"^[a-z0-9_.-]+$")
    entity: str = Field(min_length=1, max_length=64, pattern=r"^[A-Za-z0-9_.-]+$")
    rule: Literal[tuple(judge.RULE_METRIC)]  # type: ignore[valid-type]
    injected_at: datetime | None = None

    @field_validator("injected_at")
    @classmethod
    def _tz(cls, v):
        return None if v is None else _aware(v)


@router.post("/slo/injections", status_code=201)
async def register_injection(payload: InjectionIn, request: Request):
    tenant = await require_role(request, WRITE_ROLES)
    now = datetime.now(timezone.utc)
    injected_at = payload.injected_at or now
    if abs(now - injected_at) > MAX_CLOCK_OFFSET:
        raise HTTPException(422, detail={"code": "INJECTED_AT_OUT_OF_RANGE"})
    injection_id = uuid4()
    async with request.app.state.db_pool.acquire() as conn:
        async with conn.transaction():
            await conn.execute("SELECT set_config('app.tenant_id',$1,true)", tenant)
            await conn.execute(
                """INSERT INTO slo_injections
                   (injection_id,tenant_id,scenario,entity,rule,injected_at,registered_by)
                   VALUES($1,$2,$3,$4,$5,$6,$7)""",
                injection_id, tenant, payload.scenario, payload.entity, payload.rule,
                injected_at, str(request.state.user_id),
            )
            await conn.execute(
                """INSERT INTO audit_events(tenant_id,actor_id,action,resource_type,resource_id,details)
                   VALUES($1,$2,'slo.injection_registered','slo_injection',$3,$4::jsonb)""",
                tenant, str(request.state.user_id), str(injection_id),
                json.dumps({"scenario": payload.scenario, "entity": payload.entity, "rule": payload.rule}),
            )
    return {"injection_id": str(injection_id), "status": "pending", "injected_at": injected_at}


@router.get("/slo/injections")
async def list_injections(request: Request, limit: int = Query(100, ge=1, le=1000)):
    tenant = tenant_from_request(request)
    now = datetime.now(timezone.utc)
    async with request.app.state.db_pool.acquire() as conn:
        async with conn.transaction():
            await conn.execute("SELECT set_config('app.tenant_id',$1,true)", tenant)
            await judge.run_measurements(conn, tenant, now)
            rows = await conn.fetch(
                """SELECT injection_id,scenario,entity,rule,injected_at,status,alert_id,
                          first_breach_ts,alert_created_at,delay_ms
                   FROM slo_injections WHERE tenant_id=$1 ORDER BY injected_at DESC LIMIT $2""",
                tenant, limit,
            )
    items = [dict(r) for r in rows]
    measured = [r["delay_ms"] for r in items if r["status"] == "measured"]
    return {"injections": items, "aggregate": judge.percentiles(measured),
            "target_ms": judge.TARGETS_MS["breach_to_alert"]}


# ------------------------------------------------------------------ reconciliation

@router.get("/reconciliation")
async def reconciliation(request: Request, limit: int = Query(20, ge=1, le=200)):
    tenant = tenant_from_request(request)
    async with request.app.state.db_pool.acquire() as conn:
        async with conn.transaction():
            await conn.execute("SELECT set_config('app.tenant_id',$1,true)", tenant)
            summary = await judge.reconciliation_summary(conn, tenant)
            runs = await conn.fetch(
                """SELECT run_id,collector_id,from_seq,to_seq,received_count,missing_count,
                          duplicates_rejected,status,created_at
                   FROM reconciliation_runs WHERE tenant_id=$1 ORDER BY created_at DESC LIMIT $2""",
                tenant, limit,
            )
    return {"collectors": summary, "runs": [dict(r) for r in runs]}


# ------------------------------------------------------------------ alert feedback

class FeedbackIn(BaseModel):
    model_config = ConfigDict(extra="forbid")
    verdict: Literal["false_alarm", "not_an_issue", "valid"]


@router.post("/alerts/{alert_id}/feedback")
async def alert_feedback(alert_id: UUID, payload: FeedbackIn, request: Request):
    tenant = await require_role(request, WRITE_ROLES)
    async with request.app.state.db_pool.acquire() as conn:
        async with conn.transaction():
            await conn.execute("SELECT set_config('app.tenant_id',$1,true)", tenant)
            exists = await conn.fetchval(
                "SELECT 1 FROM alerts WHERE tenant_id=$1 AND alert_id=$2", tenant, alert_id)
            if not exists:
                raise HTTPException(404, detail={"code": "ALERT_NOT_FOUND"})
            await conn.execute(
                """INSERT INTO alert_feedback(tenant_id,alert_id,verdict,actor_id)
                   VALUES($1,$2,$3,$4)
                   ON CONFLICT(tenant_id,alert_id) DO UPDATE
                   SET verdict=EXCLUDED.verdict,actor_id=EXCLUDED.actor_id,at_utc=now()""",
                tenant, alert_id, payload.verdict, str(request.state.user_id),
            )
            await conn.execute(
                """INSERT INTO audit_events(tenant_id,actor_id,action,resource_type,resource_id,details)
                   VALUES($1,$2,'alert.feedback','alert',$3,$4::jsonb)""",
                tenant, str(request.state.user_id), str(alert_id),
                json.dumps({"verdict": payload.verdict}),
            )
    return {"alert_id": str(alert_id), "verdict": payload.verdict}


# ------------------------------------------------------------------ CSV evidence

@router.get("/slo/export.csv")
async def export_csv(request: Request, since: datetime | None = None):
    tenant = tenant_from_request(request)
    until = datetime.now(timezone.utc)
    if since is not None:
        if since.tzinfo is None:
            raise HTTPException(422, detail={"code": "SCHEMA_VIOLATION", "field": "since"})
        since = since.astimezone(timezone.utc)
    async with request.app.state.db_pool.acquire() as conn:
        async with conn.transaction():
            await conn.execute("SELECT set_config('app.tenant_id',$1,true)", tenant)
            rows = await judge.export_rows(conn, tenant, since, until)
    buf = io.StringIO()
    writer = csv.writer(buf, lineterminator="\n")
    writer.writerow(judge.EXPORT_COLUMNS)
    writer.writerows(rows)
    name = f"veilops-slo-evidence-{until.strftime('%Y%m%dT%H%M%SZ')}.csv"
    return StreamingResponse(iter([buf.getvalue()]), media_type="text/csv",
                             headers={"Content-Disposition": f'attachment; filename="{name}"'})
