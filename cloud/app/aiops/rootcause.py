"""Root-cause analysis and candidate scoring.

Implements the multi-factor scoring formula:
score = 0.5 * upstream + 0.3 * earliness + 0.2 * severity
where upstream represents the fraction of other alerted entities in the incident
that depend on the candidate entity via dependency relations (runs_on, connects_via,
depends_on, routes_via).
"""
from datetime import datetime, timezone
from typing import Any, Sequence

SEVERITY_WEIGHTS = {
    "critical": 1.0,
    "high": 0.75,
    "warning": 0.50,
    "medium": 0.50,
    "info": 0.25,
    "low": 0.25,
}

DEPENDENCY_RELATIONS = {
    "runs_on",
    "depends_on",
    "routes_via",
    "connects_via",
}


def _is_dependent(
    source: str,
    target: str,
    dependency_graph: dict[str, set[str]],
    max_hops: int = 5,
) -> bool:
    """Check if source depends on target (source -> ... -> target)."""
    if source == target:
        return True
    visited = {source}
    q = [(source, 0)]
    while q:
        curr, hops = q.pop(0)
        if hops >= max_hops:
            continue
        for nxt in dependency_graph.get(curr, ()):
            if nxt == target:
                return True
            if nxt not in visited:
                visited.add(nxt)
                q.append((nxt, hops + 1))
    return False


def rank_root_cause(
    alerts: Sequence[dict[str, Any]],
    edges: Sequence[tuple[str, str, str] | dict[str, Any]],
) -> list[dict[str, Any]]:
    """Rank candidate entities in the incident by probable root cause.

    Returns:
        List of candidate dictionaries sorted descending by score:
        [
            {
                "entity": str,
                "score": float,
                "upstream": float,
                "earliness": float,
                "severity": float,
                "rule": str,
                "first_ts": datetime,
            },
            ...
        ]
    """
    if not alerts:
        return []

    # 1. Build directed dependency graph where u -> v means u depends on v
    dep_graph: dict[str, set[str]] = {}
    for edge in edges:
        if isinstance(edge, dict):
            src = edge.get("source_entity") or edge.get("src", "")
            tgt = edge.get("target_entity") or edge.get("dst", "")
            rel = edge.get("relation") or edge.get("rel", "")
        else:
            src, tgt, rel = edge[0], edge[1], edge[2] if len(edge) > 2 else "depends_on"

        if rel in DEPENDENCY_RELATIONS:
            dep_graph.setdefault(src, set()).add(tgt)

    # 2. Group alerts by entity
    by_entity: dict[str, list[dict[str, Any]]] = {}
    for a in alerts:
        ent = a.get("entity", "")
        if ent:
            by_entity.setdefault(ent, []).append(a)

    all_entities = list(by_entity.keys())
    if not all_entities:
        return []

    # 3. Determine earliest first_ts per entity
    entity_earliest: dict[str, datetime] = {}
    for ent, ent_alerts in by_entity.items():
        min_ts = datetime.max.replace(tzinfo=timezone.utc)
        for a in ent_alerts:
            ts = a.get("first_ts") or a.get("last_ts") or datetime.now(timezone.utc)
            if ts.tzinfo is None:
                ts = ts.replace(tzinfo=timezone.utc)
            if ts < min_ts:
                min_ts = ts
        entity_earliest[ent] = min_ts

    sorted_by_time = sorted(all_entities, key=lambda e: entity_earliest[e])
    total_ents = len(all_entities)

    candidates: list[dict[str, Any]] = []

    for ent, ent_alerts in by_entity.items():
        # A. Upstream score: fraction of other entities that depend on ent
        other_ents = [e for e in all_entities if e != ent]
        if not other_ents:
            upstream_score = 1.0
        else:
            dep_count = sum(1 for other in other_ents if _is_dependent(other, ent, dep_graph))
            upstream_score = dep_count / len(other_ents)

        # B. Earliness score
        if total_ents <= 1:
            earliness_score = 1.0
        else:
            # Rank 0 is earliest
            rank = sorted_by_time.index(ent)
            earliness_score = max(0.0, 1.0 - (rank / (total_ents - 1)))

        # C. Severity score
        max_sev = max(
            (SEVERITY_WEIGHTS.get(a.get("severity", "warning"), 0.5) for a in ent_alerts),
            default=0.5,
        )

        # Combined formula: 0.5 * upstream + 0.3 * earliness + 0.2 * severity
        final_score = round(0.5 * upstream_score + 0.3 * earliness_score + 0.2 * max_sev, 4)

        # Pick most severe or earliest rule on this entity
        best_rule = ent_alerts[0].get("rule", "threshold.breach")
        for a in ent_alerts:
            if SEVERITY_WEIGHTS.get(a.get("severity", ""), 0) >= SEVERITY_WEIGHTS.get(ent_alerts[0].get("severity", ""), 0):
                best_rule = a.get("rule", best_rule)

        candidates.append({
            "entity": ent,
            "score": final_score,
            "upstream": round(upstream_score, 4),
            "earliness": round(earliness_score, 4),
            "severity": round(max_sev, 4),
            "rule": best_rule,
            "first_ts": entity_earliest[ent],
        })

    candidates.sort(key=lambda c: (c["score"], c["upstream"], c["earliness"]), reverse=True)
    return candidates
