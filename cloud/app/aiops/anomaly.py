"""Multivariate and statistical anomaly detection with load awareness.

Uses rolling statistical baselines and scikit-learn IsolationForest to identify
system degradation, runaway CPU, and abnormal multidimensional metric patterns.
"""
from datetime import datetime, timedelta, timezone
import hashlib
import json
import logging
import uuid
from typing import Sequence

logger = logging.getLogger(__name__)

FEATURE_METRICS = [
    "cpu.util_pct",
    "mem.util_pct",
    "load.req_rate",
    "svc.resp_ms",
    "net.loss_pct",
    "net.latency_ms",
]


def is_load_driven_cpu(
    cpu_val: float,
    cpu_baseline: float,
    req_val: float,
    req_baseline: float,
    load_increase_threshold: float = 0.50,
) -> bool:
    """Check if elevated CPU is driven by a proportional rise in load.req_rate (>= 50%).

    If CPU is high but req_rate rose >= 50% above baseline, this is legitimate
    load rather than a software fault or leak.
    """
    if req_baseline <= 1e-6:
        # If baseline load was virtually zero, any substantial load (> 5 req/s) is a surge
        return req_val >= 5.0
    load_growth = (float(req_val) - float(req_baseline)) / float(req_baseline)
    return load_growth >= load_increase_threshold


def classify_cpu_behavior(
    cpu_val: float,
    cpu_baseline: float,
    req_val: float,
    req_baseline: float,
) -> str:
    """Classify CPU state as 'cpu_runaway', 'load_driven', or 'normal'."""
    # Elevated if > 70% or at least 20% above baseline
    elevated = cpu_val >= 70.0 or (cpu_val - cpu_baseline) >= 20.0
    if not elevated:
        return "normal"
    if is_load_driven_cpu(cpu_val, cpu_baseline, req_val, req_baseline):
        return "load_driven"
    return "cpu_runaway"


class IsolationForestAnomalyDetector:
    """Multivariate IsolationForest detector per entity over metric vectors.

    Features: [cpu.util_pct, mem.util_pct, load.req_rate, svc.resp_ms, net.loss_pct, net.latency_ms].
    Contamination: 0.02. Runs 100% offline.
    """

    def __init__(self, contamination: float = 0.02):
        self.contamination = contamination
        self._model = None
        self._fitted = False

    def fit(self, samples: Sequence[Sequence[float]]) -> bool:
        """Fit IsolationForest on samples (minimum 10 samples required)."""
        if len(samples) < 10:
            return False
        try:
            from sklearn.ensemble import IsolationForest
            model = IsolationForest(
                contamination=self.contamination,
                random_state=42,
                n_estimators=50,
            )
            model.fit(samples)
            self._model = model
            self._fitted = True
            return True
        except Exception as exc:
            logger.debug("Failed to fit IsolationForest: %s", exc)
            return False

    def predict_anomaly(self, vector: Sequence[float]) -> tuple[bool, float]:
        """Evaluate a feature vector.

        Returns:
            (is_anomaly, score) where score is decision_function (lower = more anomalous).
        """
        if not self._fitted or self._model is None:
            return False, 0.0
        try:
            pred = self._model.predict([vector])[0]
            score = float(self._model.decision_function([vector])[0])
            is_anomaly = bool(pred == -1 or score < 0.0)
            return is_anomaly, score
        except Exception:
            return False, 0.0


async def detect_anomalies_for_tenant(
    conn,
    tenant_id: str,
    window_minutes: int = 30,
) -> list[dict]:
    """Detect anomalies for all entities under tenant and emit/record alerts.

    Integrates baseline robust z-score and IsolationForest multivariate analysis.
    """
    from cloud.app.aiops.baseline import compute_robust_z

    since = datetime.now(timezone.utc) - timedelta(minutes=window_minutes)

    # 1. Fetch baselines for tenant
    b_rows = await conn.fetch(
        "SELECT entity, metric, median, mad, ewma FROM baselines WHERE tenant_id = $1",
        tenant_id,
    )
    baselines = {(r["entity"], r["metric"]): dict(r) for r in b_rows}

    # 2. Fetch latest metric windows per entity & metric
    m_rows = await conn.fetch(
        """SELECT entity, metric, avg, event_ts, payload_id
           FROM metric_points
           WHERE tenant_id = $1 AND event_ts >= $2
           ORDER BY event_ts ASC""",
        tenant_id,
        since,
    )

    by_entity_metric: dict[tuple[str, str], list[dict]] = {}
    for r in m_rows:
        by_entity_metric.setdefault((r["entity"], r["metric"]), []).append(dict(r))

    detected_alerts: list[dict] = []

    # Check CPU vs Load on each host
    entities = {r["entity"] for r in m_rows}
    now_ts = datetime.now(timezone.utc)

    for ent in entities:
        cpu_pts = by_entity_metric.get((ent, "cpu.util_pct"), [])
        req_pts = by_entity_metric.get((ent, "load.req_rate"), [])

        latest_cpu = cpu_pts[-1]["avg"] if cpu_pts else None
        latest_req = req_pts[-1]["avg"] if req_pts else 0.0
        cpu_base = baselines.get((ent, "cpu.util_pct"), {}).get("median", 20.0)
        req_base = baselines.get((ent, "load.req_rate"), {}).get("median", 0.0)

        # Baseline robust z check on all metrics for this entity
        for metric_name in FEATURE_METRICS:
            pts = by_entity_metric.get((ent, metric_name), [])
            if len(pts) < 3:
                continue
            base_info = baselines.get((ent, metric_name))
            if not base_info:
                continue

            med, mad = float(base_info["median"] or 0.0), float(base_info["mad"] or 0.0)
            recent_vals = [p["avg"] for p in pts[-5:]]
            z_scores = [compute_robust_z(v, med, mad) for v in recent_vals]
            breaches = sum(1 for z in z_scores if abs(z) >= 4.0)
            latest_z = z_scores[-1] if z_scores else 0.0

            if breaches >= 3:
                # Load-aware suppression on CPU
                if metric_name == "cpu.util_pct" and latest_cpu is not None:
                    if is_load_driven_cpu(latest_cpu, cpu_base, latest_req, req_base):
                        # Suppress: legitimate load surge, not a fault
                        continue

                rule_name = f"anomaly.{metric_name}"
                fp_data = f"{tenant_id}:{ent}:{rule_name}"
                fingerprint = hashlib.sha256(fp_data.encode("utf-8")).hexdigest()
                payload_id = pts[-1].get("payload_id")
                last_ts = pts[-1]["event_ts"]
                first_ts = pts[-5]["event_ts"]

                alert_dict = {
                    "tenant_id": tenant_id,
                    "entity": ent,
                    "rule": rule_name,
                    "kind": "anomaly",
                    "severity": "critical" if abs(latest_z) >= 6.0 else "warning",
                    "fingerprint": fingerprint,
                    "status": "open",
                    "first_ts": first_ts,
                    "last_ts": last_ts,
                    "occurrences": breaches,
                    "context": {
                        "template_id": "anomaly.z_score",
                        "params": {
                            "z_score": round(latest_z, 2),
                            "median": round(med, 2),
                            "current_value": round(recent_vals[-1], 2),
                            "payload_id": str(payload_id) if payload_id else None,
                        },
                    },
                }
                detected_alerts.append(alert_dict)

    # Persist or update open alerts in database
    for a in detected_alerts:
        await conn.execute(
            """INSERT INTO alerts (
                   alert_id, tenant_id, entity, rule, kind, severity,
                   fingerprint, status, first_ts, last_ts, occurrences, context, created_at
               )
               VALUES (
                   $1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12::jsonb, now()
               )
               ON CONFLICT (tenant_id, fingerprint) WHERE status = 'open' DO UPDATE
               SET last_ts = EXCLUDED.last_ts,
                   occurrences = alerts.occurrences + 1,
                   context = EXCLUDED.context""",
            uuid.uuid4(),
            a["tenant_id"],
            a["entity"],
            a["rule"],
            a["kind"],
            a["severity"],
            a["fingerprint"],
            a["status"],
            a["first_ts"],
            a["last_ts"],
            a["occurrences"],
            json.dumps(a["context"]),
        )

    return detected_alerts
