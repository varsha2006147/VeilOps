"""Alert correlation, topology-driven graph traversal, and incident clustering.

Groups open alerts within a sliding 5-minute temporal window if their pseudonymised
entities are connected in the topology graph (undirected BFS up to depth 3) or share
an entity. Manages incident lifecycle and auto-resolution after 2 minutes of silence
or on receipt of a *.resolved alert.
"""
from datetime import datetime, timezone
from typing import Any, Sequence
import uuid


def are_entities_connected(
    entity_a: str,
    entity_b: str,
    edges: Sequence[tuple[str, str] | dict[str, Any]],
    max_depth: int = 3,
) -> bool:
    """Perform undirected BFS to determine if entity_a and entity_b are connected (depth <= 3)."""
    if entity_a == entity_b:
        return True

    adj: dict[str, set[str]] = {}
    for edge in edges:
        if isinstance(edge, dict):
            u = edge.get("source_entity") or edge.get("src", "")
            v = edge.get("target_entity") or edge.get("dst", "")
        else:
            u, v = edge[0], edge[1]
        adj.setdefault(u, set()).add(v)
        adj.setdefault(v, set()).add(u)

    visited = {entity_a}
    queue: list[tuple[str, int]] = [(entity_a, 0)]
    while queue:
        curr, depth = queue.pop(0)
        if depth >= max_depth:
            continue
        for neighbor in adj.get(curr, ()):
            if neighbor == entity_b:
                return True
            if neighbor not in visited:
                visited.add(neighbor)
                queue.append((neighbor, depth + 1))

    return False


def group_alerts_into_incidents(
    alerts: Sequence[dict[str, Any]],
    edges: Sequence[tuple[str, str] | dict[str, Any]],
    window_seconds: int = 300,
    max_depth: int = 3,
) -> list[list[dict[str, Any]]]:
    """Cluster alerts into incident groups by topology connectivity and temporal proximity.

    Alerts belong to the same incident if:
    1. Their entities are connected in the topology graph (depth <= 3) or identical, AND
    2. Their timestamps fall within a sliding 5-minute window.
    """
    if not alerts:
        return []

    # Pre-build adjacency graph
    adj: dict[str, set[str]] = {}
    for edge in edges:
        if isinstance(edge, dict):
            u = edge.get("source_entity") or edge.get("src", "")
            v = edge.get("target_entity") or edge.get("dst", "")
        else:
            u, v = edge[0], edge[1]
        adj.setdefault(u, set()).add(v)
        adj.setdefault(v, set()).add(u)

    def _is_connected(e1: str, e2: str) -> bool:
        if e1 == e2:
            return True
        visited = {e1}
        q = [(e1, 0)]
        while q:
            curr, d = q.pop(0)
            if d >= max_depth:
                continue
            for nbr in adj.get(curr, ()):
                if nbr == e2:
                    return True
                if nbr not in visited:
                    visited.add(nbr)
                    q.append((nbr, d + 1))
        return False

    # Sort alerts by first_ts ascending
    sorted_alerts = sorted(
        alerts,
        key=lambda a: a.get("first_ts") or datetime.min.replace(tzinfo=timezone.utc),
    )

    clusters: list[list[dict[str, Any]]] = []

    for alert in sorted_alerts:
        a_ent = alert.get("entity", "")
        a_ts = alert.get("first_ts") or alert.get("last_ts") or datetime.now(timezone.utc)
        if hasattr(a_ts, "tzinfo") and a_ts.tzinfo is None:
            a_ts = a_ts.replace(tzinfo=timezone.utc)

        matching_cluster_indices = []
        for idx, cluster in enumerate(clusters):
            # Check temporal proximity against cluster
            cluster_min_ts = min(
                (c.get("first_ts") or a_ts).replace(tzinfo=timezone.utc)
                if getattr(c.get("first_ts"), "tzinfo", None) is None
                else c.get("first_ts")
                for c in cluster
            )
            cluster_max_ts = max(
                (c.get("last_ts") or c.get("first_ts") or a_ts).replace(tzinfo=timezone.utc)
                if getattr(c.get("last_ts") or c.get("first_ts"), "tzinfo", None) is None
                else (c.get("last_ts") or c.get("first_ts"))
                for c in cluster
            )

            # Within sliding 5-min window
            time_diff = max(0.0, (a_ts - cluster_max_ts).total_seconds())
            if time_diff > window_seconds:
                continue

            # Check topological connectivity to any entity in the cluster
            if any(_is_connected(a_ent, c.get("entity", "")) for c in cluster):
                matching_cluster_indices.append(idx)

        if not matching_cluster_indices:
            clusters.append([alert])
        elif len(matching_cluster_indices) == 1:
            clusters[matching_cluster_indices[0]].append(alert)
        else:
            # Merge multiple connected clusters
            merged: list[dict[str, Any]] = [alert]
            for idx in reversed(matching_cluster_indices):
                merged.extend(clusters.pop(idx))
            clusters.append(merged)

    return clusters


def is_incident_resolved(
    alerts: Sequence[dict[str, Any]],
    now_ts: datetime | None = None,
    silence_threshold_seconds: int = 120,
) -> bool:
    """Evaluate whether an incident should transition to 'resolved'.

    Resolved if:
    1. Any alert has rule ending in '.resolved', OR
    2. All alerts are not 'open', OR
    3. All alerts have been silent (no updates) for > 120 seconds.
    """
    if not alerts:
        return True

    now_ts = now_ts or datetime.now(timezone.utc)
    if now_ts.tzinfo is None:
        now_ts = now_ts.replace(tzinfo=timezone.utc)

    # 1. Any .resolved rule
    for a in alerts:
        rule = a.get("rule", "")
        if rule.endswith(".resolved"):
            return True

    # 2. All closed or non-open
    if all(a.get("status") != "open" for a in alerts):
        return True

    # 3. Silence check: no updates for 2 minutes
    latest_ts = datetime.min.replace(tzinfo=timezone.utc)
    for a in alerts:
        ts = a.get("last_ts") or a.get("first_ts")
        if ts:
            if ts.tzinfo is None:
                ts = ts.replace(tzinfo=timezone.utc)
            if ts > latest_ts:
                latest_ts = ts

    silence = (now_ts - latest_ts).total_seconds()
    return silence >= silence_threshold_seconds
