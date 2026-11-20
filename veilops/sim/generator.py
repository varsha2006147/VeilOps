"""veilops-sim: realistic telemetry for rehearsal, with the guide's Section 8 scenarios injectable on demand.

Output records use an organizer-like JSON shape (the collector maps it through stream_map.yaml exactly as
it will map the real organizer stream). Labelled SIMULATED (team) on every record via `origin`.
"""
from __future__ import annotations

import math
import random
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone

HOSTS = {
    "app-01": {"cpu": 30, "mem": 58, "disk": 52, "load": 120},
    "app-02": {"cpu": 28, "mem": 61, "disk": 48, "load": 110},
    "db-01": {"cpu": 22, "mem": 70, "disk": 63, "load": 0},
    "bastion-01": {"cpu": 6, "mem": 35, "disk": 40, "load": 0},
}
LINKS = {"core-sw1": {"lat": 1.8, "loss": 0.05}, "wan-1": {"lat": 22.0, "loss": 0.1}}
SERVICES = {"checkout": {"host": "app-01", "resp": 180}, "auth-api": {"host": "app-02", "resp": 95}}
TOPOLOGY = [  # (src, dst, relation) - real names; collector pseudonymizes before egress
    ("checkout", "app-01", "runs_on"), ("checkout", "app-02", "runs_on"), ("auth-api", "app-02", "runs_on"),
    ("app-01", "core-sw1", "connects_via"), ("app-02", "core-sw1", "connects_via"),
    ("db-01", "core-sw1", "connects_via"), ("core-sw1", "wan-1", "connects_via"),
    ("checkout", "db-01", "depends_on"), ("auth-api", "db-01", "depends_on"),
]
SCENARIOS = ("cpu_drift", "load_spike", "mem_leak", "latency", "failed_logins", "spray", "secret",
             "disk_fill", "svc_down", "out_of_order", "dupes")


def _iso(dt: datetime) -> str:
    return dt.astimezone(timezone.utc).isoformat(timespec="milliseconds").replace("+00:00", "Z")


@dataclass
class Active:
    name: str
    start: datetime
    duration_s: float
    target: str | None = None
    state: dict = field(default_factory=dict)

    def progress(self, now: datetime) -> float:
        return (now - self.start).total_seconds() / self.duration_s


class Simulator:
    def __init__(self, tenant: str = "t_acme", env: str = "blr-dc1", tz: str = "Asia/Kolkata",
                 seed: int = 7, period_s: int = 600) -> None:
        self.tenant, self.env, self.tz = tenant, env, tz
        self.rng = random.Random(seed)
        self.period = period_s
        self.active: list[Active] = []
        self.t0: datetime | None = None
        self.history: list[dict] = []           # for dupes
        self.reorder_buffer: list[dict] = []
        self.injections: list[dict] = []        # ground truth for Judge Mode (inject time per scenario)

    # ---------- scenario control ----------
    def inject(self, name: str, now: datetime | None = None, target: str | None = None,
               duration_s: float | None = None) -> dict:
        if name not in SCENARIOS:
            raise ValueError(f"unknown scenario {name}; choose from {SCENARIOS}")
        now = now or datetime.now(timezone.utc)
        defaults = {"cpu_drift": 90, "load_spike": 60, "mem_leak": 120, "latency": 75, "failed_logins": 35,
                    "spray": 25, "secret": 3, "disk_fill": 120, "svc_down": 40, "out_of_order": 12, "dupes": 2}
        a = Active(name, now, duration_s or defaults[name], target)
        self.active.append(a)
        rec = {"scenario": name, "injected_at": _iso(now), "target": target, "duration_s": a.duration_s}
        self.injections.append(rec)
        return rec

    def _scen(self, name: str, now: datetime) -> Active | None:
        for a in self.active:
            if a.name == name and 0 <= a.progress(now) <= 1:
                return a
        return None

    # ---------- record builders ----------
    def _base(self, now: datetime, kind: str, host: str) -> dict:
        return {"ts": _iso(now), "tz": self.tz, "tenant": self.tenant, "env": self.env, "kind": kind,
                "host": host, "origin": "SIMULATED"}

    def _metric(self, now, host, ek, metric, value) -> dict:
        r = self._base(now, "metric", host)
        r.update(entity_kind=ek, metric=metric, value=round(value, 3))
        return r

    def _log(self, now, host, level, msg) -> dict:
        r = self._base(now, "log", host)
        r.update(level=level, message=msg)
        return r

    def _auth(self, now, host, user, ip, outcome) -> dict:
        r = self._base(now, "auth", host)
        port = self.rng.randint(40000, 65000)
        msg = (f"Failed password for {user} from {ip} port {port} ssh2" if outcome == "failure"
               else f"Accepted password for {user} from {ip} port {port} ssh2")
        r.update(user=user, src_ip=ip, outcome=outcome, message=msg)
        return r

    # ---------- one tick (1 s of telemetry) ----------
    def tick(self, now: datetime | None = None) -> list[dict]:
        now = now or datetime.now(timezone.utc)
        if self.t0 is None:
            self.t0 = now
        g = self.rng.gauss
        t = (now - self.t0).total_seconds()
        diurnal = 1 + 0.3 * math.sin(2 * math.pi * t / self.period)
        out: list[dict] = []

        drift, spike, leak, disk = (self._scen(n, now) for n in ("cpu_drift", "load_spike", "mem_leak", "disk_fill"))
        for host, b in HOSTS.items():
            load = b["load"] * diurnal * (1 + 0.04 * g(0, 1)) if b["load"] else 0.0
            if spike and (spike.target or "app-01") == host:
                load *= 1 + 1.3 * min(1.0, spike.progress(now) * 4)
            base_cpu = b["cpu"] * (load / b["load"] if b["load"] else 1.0)
            cpu = base_cpu + g(0, 1.5)
            if drift and (drift.target or "app-01") == host:
                cpu += 62 * min(1.0, drift.progress(now) * 2)
            mem = b["mem"] + g(0, 0.6)
            if leak and (leak.target or "app-02") == host:
                mem += 30 * min(1.0, leak.progress(now) * 1.3)
            dsk = b["disk"] + t / 3600
            if disk and (disk.target or "db-01") == host:
                dsk += 35 * min(1.0, disk.progress(now) * 1.2)
            out += [self._metric(now, host, "host", "cpu", min(100, max(0, cpu))),
                    self._metric(now, host, "host", "memory", min(100, max(0, mem))),
                    self._metric(now, host, "host", "disk", min(100, dsk)),
                    self._metric(now, host, "host", "bw_in", max(0, 40 * diurnal + g(0, 3))),
                    self._metric(now, host, "host", "bw_out", max(0, 25 * diurnal + g(0, 2)))]
            if b["load"]:
                out.append(self._metric(now, host, "host", "req_rate", max(0, load)))

        lat_s = self._scen("latency", now)
        for link, b in LINKS.items():
            lat, loss = b["lat"] * (1 + 0.08 * g(0, 1)), max(0.0, b["loss"] + g(0, 0.03))
            if lat_s and (lat_s.target or "core-sw1") == link:
                ramp = min(1.0, lat_s.progress(now) * 3)
                lat *= 1 + 9 * ramp
                loss += 4.5 * ramp + abs(g(0, 0.5)) * ramp
            out += [self._metric(now, link, "link", "latency", lat),
                    self._metric(now, link, "link", "packet_loss", min(100, loss)),
                    self._metric(now, link, "link", "reachable", 1)]

        down = self._scen("svc_down", now)
        for svc, b in SERVICES.items():
            resp = b["resp"] * (1 + 0.06 * g(0, 1))
            if lat_s and lat_s.progress(now) * lat_s.duration_s > 5:   # cascade lags the link by ~5 s
                resp *= 3.2
            if drift and (drift.target or "app-01") == b["host"] and drift.progress(now) > 0.25:
                resp *= 2.5
            up = 0 if (down and (down.target or "auth-api") == svc) else 1
            out += [self._metric(now, svc, "service", "up", up),
                    self._metric(now, svc, "service", "response_ms", resp if up else 0)]
            if not up and self.rng.random() < 0.5:
                out.append(self._log(now, b["host"], "ERROR", f"{svc}: upstream connect error, connection refused"))

        fl = self._scen("failed_logins", now)
        if fl:
            st = fl.state
            for _ in range(2 if fl.progress(now) < 0.95 else 0):
                out.append(self._auth(now, "bastion-01", "admin", "203.0.113.50", "failure"))
            if fl.progress(now) >= 0.95 and not st.get("stuffed"):
                st["stuffed"] = True
                out.append(self._auth(now, "bastion-01", "admin", "203.0.113.50", "success"))
        sp = self._scen("spray", now)
        if sp:
            users = ["alice", "bob", "carol", "dave", "erin", "frank", "grace", "heidi", "ivan", "judy",
                     "mallory", "oscar"]
            idx = int(sp.progress(now) * len(users)) % len(users)
            out.append(self._auth(now, "bastion-01", users[idx], "198.51.100.23", "failure"))
        sec = self._scen("secret", now)
        if sec and not sec.state.get("done"):
            sec.state["done"] = True
            out += [
                self._log(now, "app-01", "ERROR",
                          "db connect failed: postgres://app_user:S3cr3t!Pass@db-01:5432/orders timeout after 5000ms"),
                self._log(now, "app-02", "WARN",
                          "auth retry with header Authorization: Bearer eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJ1MSJ9.c2lnbmF0dXJl"),
                self._log(now, "app-01", "ERROR",
                          "s3 upload failed key=AKIAIOSFODNN7EXAMPLE secret=wJalrXUtnFEMI/K7MDENG password=hunter2"),
            ]
        if self.rng.random() < 0.05:
            out.append(self._log(now, "app-02", "INFO", "GET /health 200 3ms"))

        out = self._delivery_effects(now, out)
        self.active = [a for a in self.active if a.progress(now) <= 1.2]
        return out

    def _delivery_effects(self, now: datetime, out: list[dict]) -> list[dict]:
        ooo = self._scen("out_of_order", now)
        if ooo:
            self.rng.shuffle(out)
            for r in out[: len(out) // 3]:          # a third arrive with 8 s old event time
                r["ts"] = _iso(now - timedelta(seconds=8))
        dup = self._scen("dupes", now)
        if dup and not dup.state.get("done"):
            dup.state["done"] = True
            out = out + [dict(r) for r in self.history[-50:]]
        self.history = (self.history + out)[-500:]
        return out

    def topology(self) -> list[tuple[str, str, str]]:
        return list(TOPOLOGY)
