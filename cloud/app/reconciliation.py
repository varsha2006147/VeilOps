"""Collector/cloud sequence reconciliation API (Architecture §§13, 17)."""
from datetime import datetime, timezone
from uuid import uuid4

from fastapi import APIRouter, HTTPException, Query, Request

from cloud.app.judge import run_reconciliation
from cloud.app.security import authenticate_collector

router = APIRouter(prefix="/v1", tags=["reconciliation"])


@router.get("/reconcile")
async def reconcile(request: Request, collector_id: str,
                    from_seq: int = Query(ge=1), to_seq: int = Query(ge=1)):
    if to_seq < from_seq or to_seq - from_seq > 10000:
        raise HTTPException(422, detail={"code": "SCHEMA_VIOLATION"})
    # The request signature covers the exact query string so the requested
    # reconciliation range cannot be changed independently of its HMAC.
    body = await request.body()
    auth, collector = await authenticate_collector(request, body)
    if collector_id != auth.collector_id:
        raise HTTPException(403, detail={"code": "TENANT_MISMATCH"})

    observed = datetime.now(timezone.utc)
    async with request.app.state.db_pool.acquire() as conn:
        async with conn.transaction():
            await conn.execute(
                "SELECT set_config('app.tenant_id',$1,true)", collector["tenant_id"]
            )
            result = await run_reconciliation(
                conn, collector["tenant_id"], collector_id, from_seq, to_seq, uuid4(), observed,
            )
    return {
        "collector_id": collector_id, "tenant_id": collector["tenant_id"],
        "from_seq": from_seq, "to_seq": to_seq,
        "run_id": result["run_id"],
        "received_count": len(result["received"]), "missing_sequences": result["missing"],
        "duplicates_rejected": result["duplicates_rejected"],
        "reconciled": not result["missing"],
    }
