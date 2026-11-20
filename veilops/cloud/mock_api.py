"""Offline-only Cloud API fallback for UI development.

Production deployments use the Cloud API supplied by Person C; do not mount this app
when that service is available.
"""
import asyncio
import os
from datetime import datetime, timedelta, timezone
from typing import Annotated

import jwt
from argon2 import PasswordHasher
from argon2.exceptions import VerifyMismatchError
from fastapi import Depends, FastAPI, HTTPException
from fastapi.responses import StreamingResponse
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from pydantic import BaseModel
from veilops.demo_data import DEMO_DATA

app = FastAPI(title="VeilOps Cloud")
security = HTTPBearer()
hasher = PasswordHasher()
JWT_SECRET = os.environ.get("VEILOPS_JWT_SECRET", "development-only-change-me-use-at-least-32-bytes")
ALGORITHM = "HS256"
# Passwords are deliberately known only for the demo; production users come from an IdP.
USERS = {
    "acme.operator@demo.local": ("acme", "operator", hasher.hash("veilops-demo")),
    "globex.operator@demo.local": ("globex", "operator", hasher.hash("veilops-demo")),
    "acme.admin@demo.local": ("acme", "tenant_admin", hasher.hash("veilops-demo")),
    "platform.admin@demo.local": ("platform", "platform_admin", hasher.hash("veilops-demo")),
}
@app.get("/demo/seed")
def demo_seed():
    """Read-only fixture powering every demo screen; never production data."""
    return DEMO_DATA

class LoginRequest(BaseModel):
    email: str
    password: str

class RefreshRequest(BaseModel):
    refresh_token: str

def issue_token(subject: str, tenant_id: str, role: str, minutes: int, token_type: str) -> str:
    now = datetime.now(timezone.utc)
    return jwt.encode({"sub": subject, "tenant_id": tenant_id, "role": role, "type": token_type, "iat": now, "exp": now + timedelta(minutes=minutes)}, JWT_SECRET, algorithm=ALGORITHM)

def tokens(email: str, tenant_id: str, role: str) -> dict[str, str | int]:
    return {"access_token": issue_token(email, tenant_id, role, 15, "access"), "refresh_token": issue_token(email, tenant_id, role, 60 * 24 * 7, "refresh"), "token_type": "bearer", "expires_in": 900}

def current_user(credentials: Annotated[HTTPAuthorizationCredentials, Depends(security)]) -> dict:
    try:
        claims = jwt.decode(credentials.credentials, JWT_SECRET, algorithms=[ALGORITHM])
    except jwt.PyJWTError as exc:
        raise HTTPException(status_code=401, detail="Invalid or expired session") from exc
    if claims.get("type") != "access":
        raise HTTPException(status_code=401, detail="Access token required")
    return claims

@app.post("/auth/login")
def login(body: LoginRequest):
    record = USERS.get(body.email.lower())
    try:
        valid = bool(record and hasher.verify(record[2], body.password))
    except VerifyMismatchError:
        valid = False
    if not valid:
        raise HTTPException(status_code=401, detail="Invalid email or password")
    tenant_id, role, _ = record
    return tokens(body.email.lower(), tenant_id, role)

@app.post("/auth/refresh")
def refresh(body: RefreshRequest):
    try:
        claims = jwt.decode(body.refresh_token, JWT_SECRET, algorithms=[ALGORITHM])
    except jwt.PyJWTError as exc:
        raise HTTPException(status_code=401, detail="Invalid or expired refresh token") from exc
    if claims.get("type") != "refresh":
        raise HTTPException(status_code=401, detail="Refresh token required")
    return tokens(claims["sub"], claims["tenant_id"], claims["role"])

@app.get("/auth/me")
def me(user: Annotated[dict, Depends(current_user)]):
    return {"tenant_id": user["tenant_id"], "role": user["role"], "email": user["sub"]}

@app.get("/api/tenants/{tenant_id}/incidents")
def tenant_incidents(tenant_id: str, user: Annotated[dict, Depends(current_user)]):
    # Hide cross-tenant resource existence by returning 404, not 403.
    if user["tenant_id"] != tenant_id:
        raise HTTPException(status_code=404, detail="Not found")
    return [{"id": f"inc_{tenant_id}_001", "title": "Credential-stuffing pattern", "tenant_id": tenant_id}]

@app.get("/fleet")
def fleet_overview(user: Annotated[dict, Depends(current_user)]):
    """Tenant-scoped, secret-free fleet shape suitable for the Cloud dashboard."""
    if user["role"] == "platform_admin":
        return {"redacted": True, "collectors": {"online": 42, "offline": 1}}
    return {
        "redacted": False,
        "entities": {"excellent": 18, "good": 9, "fair": 2, "poor": 1},
        "collectors": {"online": 3, "offline": 1},
        "open_incidents": 3,
        "noise_reduction": {"alerts": 38, "incidents": 3, "reduction_pct": 92},
        "active_security_events": 2,
    }

@app.get("/collectors/{collector_id}")
def collector_detail(collector_id: str, user: Annotated[dict, Depends(current_user)]):
    """Collector diagnostics: secret-free transport and liveness metadata only."""
    if user["role"] == "platform_admin":
        raise HTTPException(status_code=404, detail="Not found")
    if collector_id != "col_blr_01":
        raise HTTPException(status_code=404, detail="Not found")
    return {
        "collector_id": "col_blr_01", "tenant_id": user["tenant_id"], "region": "in",
        "state": "Good", "online": True, "last_seen": "2026-11-20T04:12:05Z", "uptime": "14d 06h 12m",
        "version": "1.8.2", "cpu_pct": 43, "ram_mb": 412, "outbox_depth": 2, "oldest_unsent_age": "4s",
        "last_acked_seq": 581244, "highest_contiguous_seq": 581244, "policy_version": "pol_2026.11.20",
        "policy_hash": "sha256:91ac…", "config_hash": "sha256:3c72…", "expected_config_hash": "sha256:3c72…",
        "clock_skew_seconds": 1.2, "sources": {"stream": True, "host": True, "probes": True, "syslog": False},
        "reconcile": {"sent": "581201–581246", "received": "581201–581244", "missing": [581245, 581246], "duplicates_rejected": 3},
    }

@app.get("/entities/{entity_id}")
def entity_detail(entity_id: str, user: Annotated[dict, Depends(current_user)]):
    """Pseudonym-only entity observability data; identity resolution stays local."""
    if user["role"] == "platform_admin" or not entity_id.startswith(("h_", "svc_", "lnk_")):
        raise HTTPException(status_code=404, detail="Not found")
    return {
        "id": entity_id, "kind": "link" if entity_id.startswith("lnk_") else "service" if entity_id.startswith("svc_") else "host",
        "environment": "prod", "collector_id": "col_blr_01", "state": "Fair", "late": True,
        "why": ["Fair: net.loss_pct 3.1 % (threshold 2 %) for 15 s on lnk_2b", "Good: net.latency_ms p95 78 ms (threshold 120 ms)"],
        "hysteresis": "To improve, sit 10% inside better band for 3 windows.",
        "staleness": "Latest point received 4s late; never treated as current.",
    }

@app.get("/incidents")
def incidents(user: Annotated[dict, Depends(current_user)]):
    if user["role"] == "platform_admin":
        return {"noise_ratio": None, "items": []}
    return {"noise_ratio": {"alerts": 38, "incidents": 3, "reduction_pct": 92}, "items": [
        {"id":"inc_014", "title":"Checkout path packet loss", "severity":"high", "status":"open", "opened_at":"04:12:00 UTC", "alert_count":14, "affected":3, "candidate":"lnk_2b packet loss", "confidence":0.82},
        {"id":"inc_013", "title":"Credential-stuffing pattern", "severity":"critical", "status":"investigating", "opened_at":"03:49:18 UTC", "alert_count":17, "affected":2, "candidate":"src_9c1e44aa01", "confidence":0.76},
    ]}

@app.get("/incidents/{incident_id}")
def incident_detail(incident_id: str, user: Annotated[dict, Depends(current_user)]):
    if user["role"] == "platform_admin" or incident_id != "inc_014":
        raise HTTPException(status_code=404, detail="Not found")
    return {"id":incident_id, "alerts":14, "affected":3, "alert_count":14, "components":3, "root":"lnk_2b", "confidence":0.82,
      "correlation":"±120 s, ≤ 2 hops, or same source pseudonym", "payload_ids":["pld_7ac1…","pld_8d20…","pld_a109…"],
      "ranking":[["lnk_2b packet loss",0.86],["h_app01 NIC saturation",0.51],["svc_checkout regression",0.32]]}

@app.get("/recommendations/{recommendation_id}")
def recommendation_detail(recommendation_id: str, user: Annotated[dict, Depends(current_user)]):
    if user["role"] == "platform_admin" or recommendation_id != "rec_014":
        raise HTTPException(status_code=404, detail="Not found")
    return {"id":recommendation_id,"entity":"h_7f3a21c90b","confidence":.84,"runbook":"RB-CPU-RUNAWAY","incident":"inc_014","payload_ids":["0193b7c2-5e1a-7f2a-8af1-000000000001","0193b7c2-5e1a-7f2a-8af1-000000000002"]}

@app.get("/payloads/{payload_id}")
def payload_view(payload_id: str, user: Annotated[dict, Depends(current_user)]):
    if user["role"] == "platform_admin":
        raise HTTPException(status_code=404, detail="Not found")
    return {"payload_id":payload_id,"seq":581244,"collector_id":"col_blr_01","region":"in","policy_version":"pol_2026.11.20","policy_hash":"sha256:91ac…","payload_hash":"sha256:4cd2…","prev_hash":"sha256:da10…","sent_at":"2026-11-20T04:12:02Z","received_at":"2026-11-20T04:12:03.2Z","clock_skew_seconds":1.2,"records":[{"type":"metric","name":"cpu.util_pct","value":93.8},{"type":"security_summary","risk":12},{"type":"alert","kind":"cpu_runaway"},{"type":"health","state":"Fair"}],"receipt":{"status":"stored","highest_contiguous_seq":581244,"ed25519_sig":"ed25519:8a7c…"},"evidence_links":[{"signal":"cpu.util_pct z=6.1","contribution":"52%","used_by":"rec_014"},{"signal":"incident correlation","contribution":"member alert","used_by":"inc_014"}]}

@app.get("/security_summaries")
def security_summaries(user: Annotated[dict, Depends(current_user)]):
    if user["role"] == "platform_admin": return []
    return [{"category":"auth.bruteforce","severity":"high","count":37,"distinct_principals":1,"distinct_sources":1,"principals":["usr_4f1a9c02de"],"sources":["src_9c1e44aa01"],"risk_score":82,"window_s":60,"event_ts":"04:12:00 UTC"},{"category":"auth.password_spray","severity":"warning","count":14,"distinct_principals":9,"distinct_sources":1,"principals":["usr_0e2a…","usr_114b…"],"sources":["src_47c2…"],"risk_score":64,"window_s":60,"event_ts":"03:51:12 UTC"}]

@app.post("/actions")
def propose_action(user: Annotated[dict, Depends(current_user)]): return {"id":"act_0193…","status":"PROPOSED","expires_in":600}
@app.post("/actions/{action_id}/approve")
def approve_action(action_id: str, user: Annotated[dict, Depends(current_user)]): return {"id":action_id,"status":"APPROVED","signature":"ed25519:41de…"}
@app.post("/actions/{action_id}/reject")
def reject_action(action_id: str, user: Annotated[dict, Depends(current_user)]): return {"id":action_id,"status":"REJECTED"}
@app.post("/actions/{action_id}/result")
def action_result(action_id: str, user: Annotated[dict, Depends(current_user)]): return {"id":action_id,"status":"dry_run_ok","local_policy_decision":"allow","health_before":"Fair","health_after":"Good","rollback":"not required"}
@app.get("/audit")
def audit(user: Annotated[dict, Depends(current_user)]): return {"saas_chain_verified":True,"collector_chain_verified":True,"events":[{"ts":"04:13:02 UTC","actor":"usr_approver","action":"APPROVED","detail":"act_0193…","prev_hash":"sha256:1a…","entry_hash":"sha256:2b…"}]}
@app.get("/slo")
def slo(user: Annotated[dict, Depends(current_user)]): return {"offset_ms":12,"latency":{"p50":4.2,"p95":4.8,"max":8.6},"breach_s":2,"offline_s":31,"drain_s":18,"duplicates_rejected":50,"lost":0,"duplicated":0}
@app.post("/slo/render-ack")
def slo_render_ack(user: Annotated[dict, Depends(current_user)]): return {"accepted":True}
@app.put("/thresholds/{metric}")
def update_threshold(metric: str, user: Annotated[dict, Depends(current_user)]): return {"metric":metric,"updated":True,"audit_event":"thr_0193…"}
@app.post("/collectors/enrollment-token")
def enrollment_token(user: Annotated[dict, Depends(current_user)]): return {"token":"enr_0193…","expires_in":900,"secret":"sec_col_8f3a…","ingest_url":"https://ingest.in.veilops.example/v1"}
@app.post("/collectors/{collector_id}/revoke")
def revoke_collector(collector_id: str, user: Annotated[dict, Depends(current_user)]): return {"collector_id":collector_id,"revoked":True}
@app.put("/residency")
def update_residency(user: Annotated[dict, Depends(current_user)]): return {"updated":True,"audit_event":"res_0193…"}
@app.put("/thresholds/{metric}")
def update_threshold(metric: str, user: Annotated[dict, Depends(current_user)]): return {"metric":metric,"updated":True,"audit_event":"thr_0193…"}
@app.post("/collectors/enroll")
def enroll_collector(user: Annotated[dict, Depends(current_user)]): return {"token":"enr_0193…","expires_in":900,"secret":"sec_once_7f3a…","region":"in","ingest_url":"https://ingest.in.veilops.example/v1"}
@app.post("/collectors/{collector_id}/revoke")
def revoke_collector(collector_id: str, user: Annotated[dict, Depends(current_user)]): return {"id":collector_id,"revoked":True}
@app.get("/residency")
def residency(user: Annotated[dict, Depends(current_user)]): return {"home_region":"in","allow_replication_to":[],"allow_support_access":False,"retention_days":{"metrics":30,"security":90,"audit":365}}

@app.get("/api/stream")
async def alert_stream():
    async def events():
        yield "event: alert\ndata: {\"title\":\"New protected signal\",\"severity\":\"high\"}\n\n"
        await asyncio.sleep(15)
    return StreamingResponse(events(), media_type="text/event-stream", headers={"Cache-Control": "no-cache", "X-Accel-Buffering": "no"})

@app.get("/fleet/stream")
async def fleet_stream():
    """Demo SSE event; production emits only the current tenant's minimised transition."""
    async def events():
        yield "event: fleet.transition\ndata: {\"entity\":\"lnk_2b8ea9\",\"state\":\"Fair\",\"reason\":\"net.loss_pct 3.1% (threshold 2%) for 15 s\"}\n\n"
        await asyncio.sleep(15)
    return StreamingResponse(events(), media_type="text/event-stream", headers={"Cache-Control": "no-cache", "X-Accel-Buffering": "no"})
