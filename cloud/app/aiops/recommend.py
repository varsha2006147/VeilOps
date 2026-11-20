"""Remediation recommendation generator.

Maps root causes and incident alerts to actionable, safe remediation operations
supported by the collector execution sandbox:
- RESTART_SERVICE: CPU runaway, service down, db connection exhaustion
- INVESTIGATE_TOP_PROCESSES: Unclear elevated CPU, general host memory pressure
- FAILOVER_TO_SECONDARY_LINK: Network link packet loss or latency degradation
- TEMP_BLOCK_SOURCE_15M: Authentication brute-force or credential spray
"""
from typing import Any, Sequence

ACTION_CATALOG = {
    "RESTART_SERVICE": {
        "title": "Restart Affected Service Container",
        "rationale": "Service container process shows runaway CPU consumption or connection failure. Recycling restores baseline state.",
    },
    "INVESTIGATE_TOP_PROCESSES": {
        "title": "Capture Top Host Process Profile",
        "rationale": "Elevated host CPU without clear single-service attribution requires detailed process introspection.",
    },
    "FAILOVER_TO_SECONDARY_LINK": {
        "title": "Reroute Traffic to Redundant Secondary Link",
        "rationale": "Primary link packet loss or latency exceeds SLA. Rerouting traffic prevents downstream timeouts.",
    },
    "TEMP_BLOCK_SOURCE_15M": {
        "title": "Temporarily Block Malicious Ingress Sources (15m)",
        "rationale": "High-volume credential attack detected. Temporary network edge block mitigates authentication service denial.",
    },
}


def generate_recommendation(
    incident_id: str,
    root_cause: dict[str, Any],
    alerts: Sequence[dict[str, Any]],
    cpu_runaway: bool = False,
    load_driven: bool = False,
) -> dict[str, Any]:
    """Generate an actionable recommendation from the fixed catalog.

    Confidence = root_cause_score * rule_match_strength (0.0 to 1.0).
    """
    root_ent = root_cause.get("entity", "")
    root_rule = root_cause.get("rule", "")
    root_score = float(root_cause.get("score", 0.9))

    # Determine action_type and match strength
    if root_ent.startswith("lnk_") or "loss" in root_rule or "latency" in root_rule:
        action_type = "FAILOVER_TO_SECONDARY_LINK"
        match_strength = 0.95
        target_entity = root_ent
        title = ACTION_CATALOG[action_type]["title"]
        rationale = f"Primary link {root_ent} packet loss or latency breach. Immediate failover required."
        params = {"link_id": root_ent, "action": "failover"}

    elif cpu_runaway or "runaway" in root_rule or "svc.down" in root_rule or "db.connect_error" in root_rule:
        action_type = "RESTART_SERVICE"
        match_strength = 0.90
        # If root entity is a service, target it; if host, find service running on it or target entity
        target_entity = root_ent
        for a in alerts:
            if a.get("entity", "").startswith("svc_"):
                target_entity = a.get("entity")
                break
        title = ACTION_CATALOG[action_type]["title"]
        rationale = f"CPU runaway detected on {root_ent}. Restarting target {target_entity} will reclaim resources."
        params = {"target": target_entity, "graceful": True}

    elif "auth" in root_rule or "spray" in root_rule or "bruteforce" in root_rule:
        action_type = "TEMP_BLOCK_SOURCE_15M"
        match_strength = 0.95
        target_entity = root_ent
        title = ACTION_CATALOG[action_type]["title"]
        rationale = f"Credential attack on {root_ent}. Block offending ingress sources for 15 minutes."
        params = {"target": target_entity, "duration_minutes": 15}

    elif "cpu" in root_rule:
        if load_driven:
            action_type = "INVESTIGATE_TOP_PROCESSES"
            match_strength = 0.60
            target_entity = root_ent
            title = ACTION_CATALOG[action_type]["title"]
            rationale = f"CPU load is driven by external requests on {root_ent}. Inspecting top processes to optimize throughput."
            params = {"target": target_entity}
        else:
            action_type = "RESTART_SERVICE"
            match_strength = 0.85
            target_entity = root_ent
            title = ACTION_CATALOG[action_type]["title"]
            rationale = f"Persistent high CPU on {root_ent} without proportional traffic growth."
            params = {"target": target_entity}

    else:
        action_type = "INVESTIGATE_TOP_PROCESSES"
        match_strength = 0.70
        target_entity = root_ent
        title = ACTION_CATALOG[action_type]["title"]
        rationale = f"Investigate root cause on {root_ent} for rule {root_rule}."
        params = {"target": target_entity}

    confidence = round(min(1.0, max(0.0, root_score * match_strength)), 3)

    return {
        "incident_id": incident_id,
        "action_type": action_type,
        "target_entity": target_entity,
        "title": title,
        "rationale": rationale,
        "confidence": confidence,
        "status": "pending",
        "evidence": params,
    }
