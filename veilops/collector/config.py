"""Collector configuration (collector.yaml) with ${ENV} substitution."""
from __future__ import annotations

import hashlib
import os
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import yaml

_ENV = re.compile(r"\$\{([A-Z0-9_]+)(?::-([^}]*))?\}")


def _subst(text: str) -> str:
    return _ENV.sub(lambda m: os.environ.get(m.group(1), m.group(2) or ""), text)


@dataclass
class Thresholds:
    """Fast-path local breach thresholds (value >= limit is a breach unless `below` is set)."""
    rules: dict[str, dict[str, Any]] = field(default_factory=lambda: {
        "cpu.util_pct":   {"limit": 90.0, "severity": "warning", "template": "T_CPU_HIGH"},
        "mem.util_pct":   {"limit": 92.0, "severity": "warning", "template": "T_MEM_HIGH"},
        "disk.util_pct":  {"limit": 95.0, "severity": "critical", "template": "T_DISK_HIGH"},
        "net.loss_pct":   {"limit": 5.0, "severity": "critical", "template": "T_LOSS_HIGH"},
        "net.latency_ms": {"limit": 200.0, "severity": "warning", "template": "T_LATENCY_HIGH"},
        "svc.up":         {"limit": 0.5, "below": True, "severity": "critical", "template": "T_SVC_DOWN"},
        "net.reachable":  {"limit": 0.5, "below": True, "severity": "critical", "template": "T_UNREACHABLE"},
    })
    persistence: int = 3          # breaching samples ...
    of_last: int = 5              # ... out of the last N
    clear_after: int = 5          # consecutive healthy samples to clear
    hysteresis_pct: float = 10.0  # must drop this % below the limit to count as healthy


@dataclass
class AuthRules:
    window_s: int = 60
    bruteforce_failures: int = 10       # 1 principal, 1 source
    spray_principals: int = 8           # 1 source, many principals
    stuffing_min_failures: int = 3      # failures then success, same principal + source
    cooldown_s: int = 30


@dataclass
class CollectorConfig:
    collector_id: str
    tenant_id: str
    region: str
    ingest_url: str
    environment: str = "default"
    source_tz: str = "UTC"
    sources: dict[str, dict[str, Any]] = field(default_factory=dict)
    window_s: int = 5
    allowed_lateness_s: int = 300
    raw_retention_h: int = 72
    db_path: str = "data/collector.db"
    ui_host: str = "0.0.0.0"
    ui_port: int = 8100
    demo_mode: bool = False
    downstream: str = "privacy"        # "none" = drop after local detection (tests/offline)
    thresholds: Thresholds = field(default_factory=Thresholds)
    auth: AuthRules = field(default_factory=AuthRules)
    topology_file: str | None = None
    config_hash: str = ""

    @classmethod
    def load(cls, path: str | Path) -> "CollectorConfig":
        text = _subst(Path(path).read_text())
        data = yaml.safe_load(text) or {}
        windows = data.pop("windows", {}) or {}
        retention = data.pop("retention", {}) or {}
        ui = data.pop("ui", {}) or {}
        thr = data.pop("thresholds", None)
        auth = data.pop("auth", None)
        cfg = cls(**{k: v for k, v in data.items() if k in cls.__dataclass_fields__})
        cfg.window_s = int(windows.get("metrics_s", cfg.window_s))
        cfg.allowed_lateness_s = int(windows.get("allowed_lateness_s", cfg.allowed_lateness_s))
        cfg.raw_retention_h = int(retention.get("raw_h", cfg.raw_retention_h))
        cfg.ui_host = ui.get("host", cfg.ui_host)
        cfg.ui_port = int(ui.get("port", cfg.ui_port))
        if thr:
            t = Thresholds()
            t.rules.update(thr.get("rules", {}))
            for k in ("persistence", "of_last", "clear_after", "hysteresis_pct"):
                if k in thr:
                    setattr(t, k, thr[k])
            cfg.thresholds = t
        if auth:
            cfg.auth = AuthRules(**auth)
        cfg.demo_mode = cfg.demo_mode or os.environ.get("DEMO_MODE") == "1"
        cfg.config_hash = "sha256:" + hashlib.sha256(text.encode()).hexdigest()   # full 64 hex: schema Sha256Hash
        return cfg
