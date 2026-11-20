"""Baseline computation and robust z-score statistics.

Computes rolling median, Median Absolute Deviation (MAD), and Exponentially
Weighted Moving Average (EWMA) per (tenant, entity, metric).
Evaluates robust z-scores to detect statistical anomalies without normal distribution assumptions.
"""
from datetime import datetime, timedelta, timezone
from typing import Sequence
import statistics


def compute_baseline(values: Sequence[float], alpha: float = 0.2) -> tuple[float, float, float]:
    """Compute (median, MAD, EWMA) from a sequence of float observations.

    Returns:
        (median, mad, ewma). If values is empty, returns (0.0, 0.0, 0.0).
    """
    if not values:
        return 0.0, 0.0, 0.0

    vals = [float(v) for v in values]
    med = float(statistics.median(vals))
    diffs = [abs(v - med) for v in vals]
    mad = float(statistics.median(diffs))

    ewma = vals[0]
    for v in vals[1:]:
        ewma = alpha * v + (1.0 - alpha) * ewma

    return med, mad, float(ewma)


def compute_robust_z(val: float, median: float, mad: float) -> float:
    """Calculate robust z-score: (val - median) / (1.4826 * MAD).

    Normalizes scale factor 1.4826 for asymptotically normal consistency.
    Handles zero MAD safely.
    """
    scale = 1.4826 * mad
    diff = float(val) - float(median)
    if scale < 1e-9:
        if abs(diff) < 1e-9:
            return 0.0
        return diff / 1e-6
    return diff / scale


def check_baseline_anomalies(
    recent_values: Sequence[float],
    median: float,
    mad: float,
    threshold: float = 4.0,
    min_breaches: int = 3,
    window_size: int = 5,
) -> tuple[bool, float]:
    """Check if |z| >= threshold for at least min_breaches in the last window_size values.

    Returns:
        (is_anomalous, latest_z)
    """
    if not recent_values:
        return False, 0.0

    eval_window = recent_values[-window_size:]
    z_scores = [compute_robust_z(v, median, mad) for v in eval_window]
    breaches = sum(1 for z in z_scores if abs(z) >= threshold)
    latest_z = z_scores[-1] if z_scores else 0.0
    return breaches >= min_breaches, latest_z


async def update_baselines_for_tenant(
    conn,
    tenant_id: str,
    window_minutes: int = 30,
) -> int:
    """Query recent metric_points for tenant, calculate baselines, and persist to DB.

    Requires app.tenant_id to be set in the current transaction.
    """
    since = datetime.now(timezone.utc) - timedelta(minutes=window_minutes)
    rows = await conn.fetch(
        """SELECT entity, metric, avg
           FROM metric_points
           WHERE tenant_id = $1 AND event_ts >= $2
           ORDER BY entity, metric, event_ts ASC""",
        tenant_id,
        since,
    )

    by_series: dict[tuple[str, str], list[float]] = {}
    for r in rows:
        key = (r["entity"], r["metric"])
        by_series.setdefault(key, []).append(float(r["avg"]))

    updated_count = 0
    now_ts = datetime.now(timezone.utc)
    for (entity, metric), values in by_series.items():
        if not values:
            continue
        med, mad, ewma = compute_baseline(values)
        await conn.execute(
            """INSERT INTO baselines (tenant_id, entity, metric, median, mad, ewma, updated_at)
               VALUES ($1, $2, $3, $4, $5, $6, $7)
               ON CONFLICT (tenant_id, entity, metric) DO UPDATE
               SET median = EXCLUDED.median,
                   mad = EXCLUDED.mad,
                   ewma = EXCLUDED.ewma,
                   updated_at = EXCLUDED.updated_at""",
            tenant_id,
            entity,
            metric,
            med,
            mad,
            ewma,
            now_ts,
        )
        updated_count += 1

    return updated_count
