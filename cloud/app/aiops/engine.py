"""VeilOps AIOps background engine loop.

Runs periodic asynchronous cycles across all tenants:
1. Calculates rolling baselines (median, MAD, EWMA) per metric/entity.
2. Evaluates statistical and multivariate IsolationForest anomalies.
3. Groups open alerts via BFS topology reachability and sliding 5m windows.
4. Isolates root causes using multi-factor scoring (upstream, earliness, severity).
5. Generates evidence-linked incident summaries and actionable recommendations.
6. Manages incident auto-resolution.
Strictly idempotent and tenant-isolated via PostgreSQL Row-Level Security.
"""
import asyncio
from datetime import datetime, timezone
import json
import logging
import uuid

from cloud.app.aiops.anomaly import detect_anomalies_for_tenant, classify_cpu_behavior
from cloud.app.aiops.baseline import update_baselines_for_tenant
from cloud.app.aiops.correlate import group_alerts_into_incidents, is_incident_resolved
from cloud.app.aiops.explain import generate_incident_explanation, enrich_explanation_with_llm
from cloud.app.aiops.recommend import generate_recommendation
from cloud.app.aiops.rootcause import rank_root_cause

logger = logging.getLogger("veilops.aiops")


async def run_aiops_cycle_for_tenant(conn, tenant_id: str) -> dict:
    """Execute one complete AIOps analysis cycle for a single tenant.

    Must run inside an active transaction where app.tenant_id is set.
    """
    now_ts = datetime.now(timezone.utc)

    # 1. Update baselines
    try:
        await update_baselines_for_tenant(conn, tenant_id, window_minutes=30)
    except Exception as exc:
        logger.debug("[%s] Baselines update error: %s", tenant_id, exc)

    # 2. Detect anomalies & emit anomaly alerts
    try:
        await detect_anomalies_for_tenant(conn, tenant_id, window_minutes=30)
    except Exception as exc:
        logger.debug("[%s] Anomaly detection error: %s", tenant_id, exc)

    # 3. Fetch open alerts
    alert_rows = await conn.fetch(
        """SELECT alert_id, tenant_id, entity, rule, kind, severity,
                  fingerprint, status, first_ts, last_ts, occurrences,
                  context, incident_id
           FROM alerts
           WHERE tenant_id = $1 AND status = 'open'
           ORDER BY first_ts ASC""",
        tenant_id,
    )
    alerts = [dict(r) for r in alert_rows]

    # 4. Fetch topology edges
    edge_rows = await conn.fetch(
        """SELECT source_entity, target_entity, relation
           FROM topology_edges
           WHERE tenant_id = $1""",
        tenant_id,
    )
    edges = [dict(r) for r in edge_rows]

    # 5. Group alerts into incidents
    clusters = group_alerts_into_incidents(alerts, edges, window_seconds=300, max_depth=3)

    created_or_updated_incidents = 0

    for cluster in clusters:
        if not cluster:
            continue

        # Check if an existing open incident already owns any alert in this cluster
        existing_incident_id = None
        for a in cluster:
            if a.get("incident_id"):
                existing = await conn.fetchval(
                    "SELECT incident_id FROM incidents WHERE tenant_id = $1 AND incident_id = $2 AND status = 'open'",
                    tenant_id,
                    a["incident_id"],
                )
                if existing:
                    existing_incident_id = existing
                    break

        incident_id = existing_incident_id or uuid.uuid4()

        # Link all alerts in the cluster to this incident
        alert_ids = [a["alert_id"] for a in cluster if a.get("alert_id")]
        if alert_ids:
            await conn.execute(
                "UPDATE alerts SET incident_id = $1 WHERE tenant_id = $2 AND alert_id = ANY($3)",
                incident_id,
                tenant_id,
                alert_ids,
            )

        # Evaluate load vs CPU across cluster entities
        cpu_runaway = False
        load_driven = False
        for a in cluster:
            ent = a.get("entity", "")
            rule = a.get("rule", "")
            if "cpu" in rule or "runaway" in rule:
                # Query metric points
                m_rows = await conn.fetch(
                    """SELECT metric, avg FROM metric_points
                       WHERE tenant_id = $1 AND entity = $2 AND metric IN ('cpu.util_pct', 'load.req_rate')
                       ORDER BY event_ts DESC LIMIT 2""",
                    tenant_id,
                    ent,
                )
                cpu_v = next((r["avg"] for r in m_rows if r["metric"] == "cpu.util_pct"), 85.0)
                req_v = next((r["avg"] for r in m_rows if r["metric"] == "load.req_rate"), 0.0)

                # Fetch baselines
                b_rows = await conn.fetch(
                    """SELECT metric, median FROM baselines
                       WHERE tenant_id = $1 AND entity = $2 AND metric IN ('cpu.util_pct', 'load.req_rate')""",
                    tenant_id,
                    ent,
                )
                cpu_b = next((r["median"] for r in b_rows if r["metric"] == "cpu.util_pct"), 25.0)
                req_b = next((r["median"] for r in b_rows if r["metric"] == "load.req_rate"), 0.0)

                behavior = classify_cpu_behavior(cpu_v, cpu_b, req_v, req_b)
                if behavior == "cpu_runaway":
                    cpu_runaway = True
                elif behavior == "load_driven":
                    load_driven = True

        # Rank root cause
        candidates = rank_root_cause(cluster, edges)
        best_candidate = candidates[0] if candidates else {
            "entity": cluster[0].get("entity", "unknown"),
            "score": 1.0,
            "rule": cluster[0].get("rule", "breach"),
        }

        # Generate summary explanation & evidence
        summary, evidence = generate_incident_explanation(
            str(incident_id),
            best_candidate,
            cluster,
            cpu_runaway=cpu_runaway,
            load_driven=load_driven,
        )

        # Optional P3 LLM enrichment
        summary = await enrich_explanation_with_llm(summary, evidence, timeout_seconds=2.0)

        # Highest severity in cluster
        sev_rank = {"critical": 4, "high": 3, "warning": 2, "medium": 2, "info": 1, "low": 1}
        max_sev = max(
            (a.get("severity", "warning") for a in cluster),
            key=lambda s: sev_rank.get(s, 0),
        )

        title = f"Incident: {best_candidate['entity']} degradation ({best_candidate['rule']})"
        opened_at = min(
            (a.get("first_ts") or now_ts for a in cluster)
        )

        # Check if cluster is resolved (e.g. *.resolved alert arrived or all silent)
        is_resolved = is_incident_resolved(cluster, now_ts=now_ts, silence_threshold_seconds=120)
        inc_status = "resolved" if is_resolved else "open"
        closed_at = now_ts if is_resolved else None

        # Upsert incident
        await conn.execute(
            """INSERT INTO incidents (
                   incident_id, tenant_id, title, severity, status, summary,
                   root_cause_entity, root_cause_rule, root_cause_score,
                   opened_at, updated_at, closed_at
               )
               VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12)
               ON CONFLICT (incident_id) DO UPDATE
               SET title = EXCLUDED.title,
                   severity = EXCLUDED.severity,
                   status = EXCLUDED.status,
                   summary = EXCLUDED.summary,
                   root_cause_entity = EXCLUDED.root_cause_entity,
                   root_cause_rule = EXCLUDED.root_cause_rule,
                   root_cause_score = EXCLUDED.root_cause_score,
                   updated_at = EXCLUDED.updated_at,
                   closed_at = COALESCE(incidents.closed_at, EXCLUDED.closed_at)""",
            incident_id,
            tenant_id,
            title,
            max_sev,
            inc_status,
            summary,
            best_candidate.get("entity"),
            best_candidate.get("rule"),
            float(best_candidate.get("score", 1.0)),
            opened_at,
            now_ts,
            closed_at,
        )

        if is_resolved and alert_ids:
            await conn.execute(
                "UPDATE alerts SET status = 'resolved' WHERE tenant_id = $1 AND alert_id = ANY($2)",
                tenant_id,
                alert_ids,
            )

        # Generate recommendation
        rec = generate_recommendation(
            str(incident_id),
            best_candidate,
            cluster,
            cpu_runaway=cpu_runaway,
            load_driven=load_driven,
        )

        # Check if recommendation already exists for this incident
        rec_id = await conn.fetchval(
            "SELECT recommendation_id FROM recommendations WHERE tenant_id = $1 AND incident_id = $2",
            tenant_id,
            incident_id,
        )
        if not rec_id:
            rec_id = uuid.uuid4()
            await conn.execute(
                """INSERT INTO recommendations (
                       recommendation_id, tenant_id, incident_id, title, rationale,
                       confidence, status, evidence, action_type, target_entity, created_at
                   )
                   VALUES ($1, $2, $3, $4, $5, $6, $7, $8::jsonb, $9, $10, $11)""",
                rec_id,
                tenant_id,
                incident_id,
                rec["title"],
                rec["rationale"],
                rec["confidence"],
                rec["status"],
                json.dumps(rec["evidence"]),
                rec["action_type"],
                rec["target_entity"],
                now_ts,
            )
        else:
            # The root cause can change as more alerts arrive: keep the suggested fix in step with it.
            await conn.execute(
                """UPDATE recommendations SET title = $3, rationale = $4, confidence = $5,
                          evidence = $6::jsonb, action_type = $7, target_entity = $8
                   WHERE tenant_id = $1 AND recommendation_id = $2
                     AND (action_type IS DISTINCT FROM $7 OR target_entity IS DISTINCT FROM $8
                          OR rationale IS DISTINCT FROM $4)""",
                tenant_id, rec_id, rec["title"], rec["rationale"], rec["confidence"],
                json.dumps(rec["evidence"]), rec["action_type"], rec["target_entity"],
            )

        # Evidence follows the current explanation: rewrite it when the root cause moved.
        existing_ev = await conn.fetch(
            "SELECT description FROM evidence_links WHERE tenant_id = $1 AND incident_id = $2 ORDER BY evidence_number",
            tenant_id,
            incident_id,
        )
        if [r["description"] for r in existing_ev] != [ev.get("description") for ev in evidence]:
            await conn.execute("DELETE FROM evidence_links WHERE tenant_id = $1 AND incident_id = $2", tenant_id, incident_id)
            existing_ev = []
        if not existing_ev:
            for ev in evidence:
                payload_uuid = None
                if ev.get("payload_id"):
                    try:
                        payload_uuid = uuid.UUID(str(ev["payload_id"]))
                    except Exception:
                        payload_uuid = None
                await conn.execute(
                    """INSERT INTO evidence_links (
                           tenant_id, incident_id, recommendation_id, payload_id,
                           evidence_type, reference, evidence_number, description, created_at
                       )
                       VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)""",
                    tenant_id,
                    incident_id,
                    rec_id,
                    payload_uuid,
                    ev["evidence_type"],
                    ev["reference"],
                    ev.get("evidence_number", 1),
                    ev.get("description", ""),
                    now_ts,
                )

        created_or_updated_incidents += 1

    # 6. Auto-resolve incidents when all alerts have stopped for 2 min or resolved alert arrived
    open_incidents = await conn.fetch(
        "SELECT incident_id, updated_at FROM incidents WHERE tenant_id = $1 AND status = 'open'",
        tenant_id,
    )
    for inc in open_incidents:
        inc_id = inc["incident_id"]
        inc_alerts = await conn.fetch(
            "SELECT alert_id, rule, status, first_ts, last_ts FROM alerts WHERE tenant_id = $1 AND incident_id = $2",
            tenant_id,
            inc_id,
        )
        if not inc_alerts:
            # If no alerts linked, check if opened long ago
            continue
        if is_incident_resolved([dict(a) for a in inc_alerts], now_ts=now_ts, silence_threshold_seconds=120):
            await conn.execute(
                """UPDATE incidents
                   SET status = 'resolved', closed_at = $1, updated_at = $1
                   WHERE tenant_id = $2 AND incident_id = $3""",
                now_ts,
                tenant_id,
                inc_id,
            )
            await conn.execute(
                "UPDATE alerts SET status = 'resolved' WHERE tenant_id = $1 AND incident_id = $2",
                tenant_id,
                inc_id,
            )

    return {"tenant_id": tenant_id, "incidents": created_or_updated_incidents}


async def aiops_loop(pool, interval_seconds: float = 5.0, stop_event: asyncio.Event | None = None):
    """Periodic background task executing AIOps analysis cycles across all active tenants."""
    import os
    if os.getenv("VEILOPS_TEST_PG_ADMIN") and interval_seconds > 1.0:
        interval_seconds = 1.0

    logger.info("AIOps engine loop started (interval=%.1fs)", interval_seconds)
    while stop_event is None or not stop_event.is_set():
        try:
            async with pool.acquire() as conn:
                # Query all active tenants
                tenant_rows = await conn.fetch("SELECT tenant_id FROM tenants")
                tenants = [r["tenant_id"] for r in tenant_rows]

            for t in tenants:
                async with pool.acquire() as conn:
                    async with conn.transaction():
                        await conn.execute("SELECT set_config('app.tenant_id', $1, true)", t)
                        await run_aiops_cycle_for_tenant(conn, t)

        except asyncio.CancelledError:
            break
        except Exception as exc:
            logger.error("AIOps loop error: %s", exc, exc_info=True)

        if stop_event:
            try:
                await asyncio.wait_for(stop_event.wait(), timeout=interval_seconds)
                break
            except asyncio.TimeoutError:
                pass
        else:
            await asyncio.sleep(interval_seconds)

    logger.info("AIOps engine loop stopped")
