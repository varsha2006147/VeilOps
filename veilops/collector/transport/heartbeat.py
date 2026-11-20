"""Heartbeat builder for periodic collector liveness and status telemetry."""
from __future__ import annotations

import time
from datetime import datetime, timezone
from typing import Any

from veilops.collector.config import CollectorConfig
from veilops.collector.contracts import SourceStatus
from veilops.schema.wire import Heartbeat, SourcesOk

# Alias for compatibility
HeartbeatPayload = Heartbeat


class HeartbeatBuilder:
    """Constructs schema-validated Heartbeat records with source name normalization."""

    def __init__(
        self,
        collector_id: str,
        tenant_id: str,
        *,
        version: str = "1.0.0",
        policy_version: int = 1,
        config_hash: str | None = None,
        config: CollectorConfig | None = None,
        start_time: float | None = None,
    ) -> None:
        if config:
            self.collector_id = config.collector_id
            self.tenant_id = config.tenant_id
            self.config_hash = config.config_hash or ("sha256:" + "0" * 64)
        else:
            self.collector_id = collector_id
            self.tenant_id = tenant_id
            self.config_hash = config_hash or ("sha256:" + "0" * 64)

        if not self.config_hash.startswith("sha256:"):
            self.config_hash = f"sha256:{self.config_hash}"

        self.version = version
        self.policy_version = policy_version
        self.start_time = start_time if start_time is not None else time.monotonic()

    @staticmethod
    def map_sources(
        sources_input: dict[str, Any] | list[SourceStatus] | SourcesOk | None,
    ) -> SourcesOk:
        """Map collector source statuses to schema SourcesOk."""
        if isinstance(sources_input, SourcesOk):
            return sources_input

        # Default all four required sources to True
        mapping: dict[str, bool] = {
            "stream": True,
            "host": True,
            "probes": True,
            "syslog": True,
        }

        if sources_input is None:
            return SourcesOk(**mapping)

        items: list[tuple[str, Any]] = []
        if isinstance(sources_input, dict):
            items = list(sources_input.items())
        elif isinstance(sources_input, list):
            for s in sources_input:
                if isinstance(s, SourceStatus):
                    items.append((s.name, s.ok))
                elif isinstance(s, dict) and "name" in s:
                    items.append((s["name"], s.get("ok", True)))

        for raw_name, val in items:
            name = str(raw_name).lower().strip()
            # Mapping per CONTRACTS.md: "sim" -> "stream"
            if name in ("sim", "simsource"):
                canonical_name = "stream"
            elif name in ("probe", "probes"):
                canonical_name = "probes"
            elif name in ("stream", "host", "syslog"):
                canonical_name = name
            else:
                continue

            if isinstance(val, SourceStatus):
                is_ok = bool(val.ok)
            elif isinstance(val, bool):
                is_ok = val
            elif isinstance(val, dict):
                is_ok = bool(val.get("ok", True))
            else:
                is_ok = bool(val)

            mapping[canonical_name] = is_ok

        return SourcesOk(**mapping)

    def build(
        self,
        *,
        outbox_depth: int = 0,
        oldest_unsent_s: float = 0.0,
        last_acked_seq: int = 0,
        cpu_pct: float = 0.0,
        mem_mb: float = 0.0,
        uptime_s: int | None = None,
        sources: dict[str, Any] | list[SourceStatus] | SourcesOk | None = None,
        ts: datetime | None = None,
        policy_version: int | None = None,
    ) -> Heartbeat:
        """Build and validate a wire-conforming Heartbeat record."""
        now_dt = ts.astimezone(timezone.utc) if ts else datetime.now(timezone.utc)
        ts_str = now_dt.strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3] + "Z"

        if uptime_s is None:
            uptime = max(0, int(time.monotonic() - self.start_time))
        else:
            uptime = max(0, int(uptime_s))

        sources_ok = self.map_sources(sources)
        pol_ver = policy_version if policy_version is not None else self.policy_version

        payload_dict = {
            "collector_id": self.collector_id,
            "tenant_id": self.tenant_id,
            "ts": ts_str,
            "version": self.version,
            "uptime_s": uptime,
            "cpu_pct": round(float(cpu_pct), 2),
            "mem_mb": round(float(mem_mb), 2),
            "outbox_depth": max(0, int(outbox_depth)),
            "oldest_unsent_s": round(max(0.0, float(oldest_unsent_s)), 3),
            "last_acked_seq": max(0, int(last_acked_seq)),
            "policy_version": max(1, int(pol_ver)),
            "config_hash": self.config_hash,
            "sources_ok": sources_ok.model_dump(mode="json"),
        }

        return Heartbeat.model_validate(payload_dict)
