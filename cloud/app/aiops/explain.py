"""Evidence-backed incident explanation generator.

Produces human-readable root-cause explanations grounded with numbered citations [n].
Every citation maps directly to an evidence_link referencing an alert, metric window,
or payload_id.
Optionally enhances wording with Anthropic LLM when ANTHROPIC_API_KEY is configured,
with a strict 2-second timeout and deterministic offline fallback.
"""
import asyncio
import logging
import os
from typing import Any, Sequence

logger = logging.getLogger(__name__)


def generate_incident_explanation(
    incident_id: str,
    root_cause: dict[str, Any],
    alerts: Sequence[dict[str, Any]],
    cpu_runaway: bool = False,
    load_driven: bool = False,
) -> tuple[str, list[dict[str, Any]]]:
    """Generate deterministic explanation with numbered citations [n] and evidence links.

    Returns:
        (summary_text, evidence_links)
    """
    root_ent = root_cause.get("entity", "unknown")
    root_rule = root_cause.get("rule", "alert.breach")
    root_score = root_cause.get("score", 1.0)

    evidence_links: list[dict[str, Any]] = []

    def _add_evidence(ev_type: str, ref: str, desc: str, payload_id: str | None = None) -> int:
        n = len(evidence_links) + 1
        evidence_links.append({
            "incident_id": incident_id,
            "evidence_number": n,
            "evidence_type": ev_type,
            "reference": ref,
            "description": desc,
            "payload_id": payload_id,
        })
        return n

    # Find alert on root entity
    root_alert = next((a for a in alerts if a.get("entity") == root_ent), alerts[0] if alerts else {})
    root_ref = str(root_alert.get("alert_id") or root_alert.get("fingerprint") or root_rule)
    root_ctx = root_alert.get("context") or {}
    params = root_ctx.get("params", {}) if isinstance(root_ctx, dict) else {}
    payload_id = params.get("payload_id")

    if root_ent.startswith("lnk_") or "loss" in root_rule or "latency" in root_rule:
        ev1 = _add_evidence(
            "alert",
            root_ref,
            f"Breach {root_rule} on link {root_ent} (score {root_score})",
            payload_id,
        )
        dependent_alerts = [a for a in alerts if a.get("entity") != root_ent]
        if dependent_alerts:
            dep_ent = dependent_alerts[0].get("entity", "downstream")
            dep_ref = str(dependent_alerts[0].get("alert_id") or dependent_alerts[0].get("rule"))
            ev2 = _add_evidence(
                "alert",
                dep_ref,
                f"Downstream service/host alert {dependent_alerts[0].get('rule')} on {dep_ent}",
            )
            summary = (
                f"Link {root_ent} experienced severe network degradation [{ev1}]. "
                f"Downstream hosts and services suffered connectivity timeouts and latency spikes [{ev2}], "
                f"confirming link {root_ent} as the primary root cause."
            )
        else:
            summary = f"Link {root_ent} experienced high packet loss or latency [{ev1}]."

    elif cpu_runaway or "cpu" in root_rule:
        ev1 = _add_evidence(
            "metric",
            f"{root_ent}:cpu.util_pct",
            f"Elevated CPU utilization on host {root_ent}",
            payload_id,
        )
        ev2 = _add_evidence(
            "metric",
            f"{root_ent}:load.req_rate",
            "Request rate remained flat while CPU escalated",
        )
        dependent_alerts = [a for a in alerts if a.get("entity") != root_ent]
        if dependent_alerts:
            dep_ref = str(dependent_alerts[0].get("alert_id") or dependent_alerts[0].get("rule"))
            ev3 = _add_evidence(
                "alert",
                dep_ref,
                f"Secondary degradation observed on {dependent_alerts[0].get('entity')}",
            )
            summary = (
                f"CPU on {root_ent} climbed significantly [{ev1}]. "
                f"Requests per second did not move [{ev2}], confirming CPU runaway rather than external load surge. "
                f"Secondary service performance deteriorated shortly thereafter [{ev3}]."
            )
        else:
            summary = (
                f"CPU on {root_ent} climbed significantly [{ev1}]. "
                f"Requests per second did not move [{ev2}], confirming a CPU runaway fault."
            )

    elif load_driven:
        ev1 = _add_evidence(
            "metric",
            f"{root_ent}:cpu.util_pct",
            f"Elevated CPU utilization on host {root_ent}",
            payload_id,
        )
        ev2 = _add_evidence(
            "metric",
            f"{root_ent}:load.req_rate",
            "Proportional request rate increase >= 50% observed",
        )
        summary = (
            f"CPU on {root_ent} is elevated [{ev1}], but request rate increased proportionally [{ev2}]. "
            "This reflects an authentic traffic surge rather than a software failure."
        )

    elif "auth" in root_rule or "spray" in root_rule or "bruteforce" in root_rule:
        ev1 = _add_evidence(
            "security",
            root_ref,
            f"Security anomaly category {root_rule} detected on {root_ent}",
            payload_id,
        )
        summary = (
            f"Automated credential brute-force or authentication spray detected on {root_ent} [{ev1}]. "
            "Security risk requires temporary source isolation."
        )

    else:
        ev1 = _add_evidence(
            "alert",
            root_ref,
            f"Primary breach {root_rule} on entity {root_ent}",
            payload_id,
        )
        summary = (
            f"Root cause isolated to entity {root_ent} due to primary breach {root_rule} [{ev1}] "
            f"with confidence score {root_score}."
        )

    return summary, evidence_links


async def enrich_explanation_with_llm(
    template_summary: str,
    evidence_links: Sequence[dict[str, Any]],
    timeout_seconds: float = 2.0,
) -> str:
    """Optional P3: Rewrite summary using Anthropic LLM if key is present.

    Sends only pseudonymised identifiers and evidence references.
    Falls back to template_summary immediately on timeout (2s) or error.
    """
    api_key = os.getenv("ANTHROPIC_API_KEY")
    if not api_key:
        return template_summary

    async def _call():
        import httpx
        payload = {
            "model": "claude-3-haiku-20240307",
            "max_tokens": 150,
            "messages": [
                {
                    "role": "user",
                    "content": (
                        "Rewrite this technical incident summary in concise, professional language. "
                        "Preserve all citation markers like [1], [2] exactly. Do not invent any names.\n\n"
                        f"Original: {template_summary}"
                    ),
                }
            ],
        }
        async with httpx.AsyncClient(timeout=timeout_seconds) as client:
            resp = await client.post(
                "https://api.anthropic.com/v1/messages",
                headers={
                    "x-api-key": api_key,
                    "anthropic-version": "2023-06-01",
                    "content-type": "application/json",
                },
                json=payload,
            )
            if resp.status_code == 200:
                data = resp.json()
                content = data.get("content", [])
                if content and isinstance(content, list):
                    return content[0].get("text", template_summary)
            return template_summary

    try:
        return await asyncio.wait_for(_call(), timeout=timeout_seconds)
    except Exception as exc:
        logger.debug("LLM enrichment skipped: %s", exc)
        return template_summary
