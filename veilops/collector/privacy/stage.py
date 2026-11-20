"""Collector downstream: SourceBus -> privacy (B) -> outbox/ledger (B) -> cloud (C).

Member A's integration of the pieces built by B and C:
  windows/signals -> RecordSerializer (redact, pseudonymize, allow-list)
  -> OutboxLedger (hash chain, Ed25519) -> EgressGuard (fail closed)
  -> TransportSender (HMAC auth as the cloud requires, signed-receipt check)
plus heartbeats, reconciliation after an outage, and pull-based approved actions run
through the sandbox's safe executor (snapshot -> dry run -> execute -> verify -> rollback).

Started by ``python -m veilops.collector`` when ``downstream: privacy``.
"""
from __future__ import annotations

import asyncio
import base64
import json
import logging
import os
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import httpx

from veilops.collector.privacy.pseudonymizer import Pseudonymizer, PseudonymStore, load_or_create_key
from veilops.collector.privacy.serializer import RecordSerializer
from veilops.collector.transport.actions import LocalVetoPolicy
from veilops.collector.transport.guard import EgressGuard
from veilops.collector.transport.heartbeat import HeartbeatBuilder
from veilops.collector.transport.outbox import OutboxLedger
from veilops.collector.transport.sender import (
    BusBridge, CollectorCredentials, TransportSender, compute_backoff_s, hmac_headers, reconcile,
)
from veilops.collector.transport.signer import EnvelopeSigner, load_or_create_signing_key
from veilops.schema.policy import load_policy

log = logging.getLogger("veilops.stage")
CREDENTIALS_FILE = "cloud_credentials.json"
RECONCILE_SPAN = 10_000          # cloud limit per /v1/reconcile call


def cloud_base_url(ingest_url: str) -> str:
    base = ingest_url.rstrip("/")
    return base[: -len("/v1")] if base.endswith("/v1") else base


# ------------------------------------------------------------------ credentials

def _write_private(path: Path, data: dict) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "w") as fh:
        json.dump(data, fh)


async def ensure_credentials(cfg, data_dir: Path, client: httpx.AsyncClient) -> dict | None:
    """Cloud credentials: saved file > one-time enrollment token > env secret > none (offline)."""
    path = data_dir / CREDENTIALS_FILE
    if path.exists():
        return json.loads(path.read_text())
    token = os.environ.get("VEILOPS_ENROLLMENT_TOKEN")
    if token:
        resp = await client.post(f"{cloud_base_url(cfg.ingest_url)}/v1/enroll", json={
            "enrollment_token": token, "version": "1.0.0", "collector_pubinfo": {}})
        resp.raise_for_status()
        creds = resp.json()
        _write_private(path, creds)
        log.info("enrolled with cloud as %s (tenant %s)", creds["collector_id"], creds["tenant_id"])
        return creds
    secret = os.environ.get("VEILOPS_COLLECTOR_SECRET")
    if secret:
        return {"collector_id": cfg.collector_id, "collector_secret": secret,
                "tenant_id": cfg.tenant_id, "region": cfg.region,
                "saas_pubkey": os.environ.get("VEILOPS_SAAS_PUBKEY")}
    return None


# ------------------------------------------------------------------ the stage

class CloudLink:
    """Owns the outbox, sender and the loops that talk to the cloud. Exposed on ctx.cloud."""

    def __init__(self, cfg, bus, ctx, data_dir: Path) -> None:
        self.cfg, self.bus, self.ctx, self.data_dir = cfg, bus, ctx, data_dir
        self.status: dict[str, Any] = {"enrolled": False, "online": None, "last_ack_at": None,
                                       "last_error": None, "outage_started_at": None,
                                       "last_reconcile": None, "actions": []}
        self.client = httpx.AsyncClient(timeout=10)
        self.sender: TransportSender | None = None
        self.ledger: OutboxLedger | None = None
        self.bridge: BusBridge | None = None
        self.sandbox_url = _sandbox_url(cfg)
        self._backlog_seen = False

    async def setup(self) -> None:
        creds = await ensure_credentials(self.cfg, self.data_dir, self.client)
        if creds:
            # The cloud assigns the collector identity at enrollment; adopt it everywhere.
            self.cfg.collector_id, self.cfg.tenant_id = creds["collector_id"], creds["tenant_id"]
            self.cfg.region = creds.get("region", self.cfg.region)
            self.status["enrolled"] = True
        policy = load_policy()
        pseudo = Pseudonymizer(load_or_create_key(self.data_dir / "pseudonym.key"),
                               PseudonymStore(self.data_dir / "pseudonyms.db"))
        self.ctx.resolver = lambda p: (hit := pseudo.resolve(p)) and {"pseudo": p, "kind": hit[0], "real": hit[1]}
        self.ctx.codes = lambda: [{"pseudo": c, "kind": k, "real": r} for c, k, r in pseudo.codes()]
        signer = EnvelopeSigner(load_or_create_signing_key(self.data_dir / "envelope_signing.key"))
        self.ledger = OutboxLedger(self.data_dir / "outbox.db", signer, config=self.cfg, policy=policy)
        await self.ledger.open()
        self.ctx.ledger = self.ledger
        self.guard = EgressGuard()
        if creds:
            pub = creds.get("saas_pubkey")
            self.sender = TransportSender(
                cloud_base_url(self.cfg.ingest_url), self.ledger, signer, client=self.client,
                egress_guard=self.guard,
                verify_key_bytes=base64.b64decode(pub) if pub else None,
                credentials=CollectorCredentials(creds["collector_id"], creds["collector_secret"].encode()),
            )
        self.serializer = RecordSerializer(policy, pseudo)
        self.bridge = BusBridge(self.bus, self.serializer, self.ledger, sender=None)
        self.status["topology"] = {"version_sent": None, "edges": 0, "sent_at": None, "error": None}
        self.heartbeats = HeartbeatBuilder(self.cfg.collector_id, self.cfg.tenant_id,
                                           config=self.cfg, policy_version=_policy_int(policy.version))
        self.ctx.cloud = self

    # -- outbox -> cloud, in seq order, with backoff; reconcile after an outage
    async def send_loop(self) -> None:
        failures = 0
        while True:
            stats = await self.ledger.stats()
            if stats["outbox_depth"] == 0:
                if self._backlog_seen and self.status["online"]:
                    await self.reconcile_all(stats["last_acked_seq"])
                    self._backlog_seen = False
                await asyncio.sleep(0.3)
                continue
            if stats["outbox_depth"] > 5:
                self._backlog_seen = True
            await self.sender.flush_once(limit=50)
            after = await self.ledger.stats()
            if after["last_acked_seq"] > stats["last_acked_seq"]:
                failures = 0
                self.status.update(online=True, last_ack_at=_now(), last_error=None, outage_started_at=None)
                await asyncio.sleep(0.05)
            else:
                failures += 1
                if self.status["online"] is not False:
                    self.status["outage_started_at"] = _now()
                self.status.update(online=False, last_error=self.sender.last_error or self.sender.last_status)
                self._backlog_seen = True
                await asyncio.sleep(compute_backoff_s(failures - 1, base_s=0.5, max_s=10.0))

    async def topology_loop(self) -> None:
        """Send the dependency graph (pseudonymised) at start and whenever the topology file changes.

        The cloud replaces this collector's edges on each snapshot; incident correlation walks them.
        """
        from veilops.collector.privacy.serializer import SerializationError
        while True:
            self.bus.topology_changed.clear()   # clear first so a change during sending is not lost
            topo = self.bus.topology
            if topo.edges and topo.version != self.status["topology"]["version_sent"]:
                try:
                    record = self.serializer.serialize_topology(topo, datetime.now(timezone.utc))
                    await self.ledger.enqueue([record], priority=True)
                    self.status["topology"] = {"version_sent": topo.version, "edges": len(record.edges),
                                               "sent_at": _now(), "error": None}
                    log.info("topology v%s queued: %s edges", topo.version, len(record.edges))
                except SerializationError as exc:
                    self.status["topology"]["error"] = str(exc)   # field names/types only, never values
                    log.warning("topology not sent: %s", exc)
            await self.bus.topology_changed.wait()

    async def reconcile_all(self, last_acked: int) -> None:
        if last_acked < 1:
            return
        lo = max(1, last_acked - RECONCILE_SPAN + 1)
        result = await reconcile(self.sender, lo, last_acked)
        if result is not None:
            self.status["last_reconcile"] = {"at": _now(), **{k: result.get(k) for k in (
                "from_seq", "to_seq", "received_count", "missing_sequences", "duplicates_rejected",
                "reconciled", "run_id")}}
            log.info("reconciled %s..%s missing=%s", lo, last_acked, result.get("missing_sequences"))

    async def heartbeat_loop(self, interval_s: float = 5.0) -> None:
        import psutil
        proc = psutil.Process()
        while True:
            stats = await self.ledger.stats()
            hb = self.heartbeats.build(
                outbox_depth=stats["outbox_depth"], oldest_unsent_s=round(stats["oldest_unsent_s"], 3),
                last_acked_seq=stats["last_acked_seq"], cpu_pct=proc.cpu_percent(),
                mem_mb=round(proc.memory_info().rss / 1e6, 1),
                sources={n: s.ok for n, s in self.bus.status.items()},
            )
            await self.sender.send_heartbeat(hb)
            await asyncio.sleep(interval_s)

    # -- approved actions (pull). The cloud signs the whole response; verify before acting.
    async def action_loop(self, interval_s: float = 2.0) -> None:
        from veilops.collector.remediation import SandboxExecutor
        from veilops.collector.transport.signer import canonical_bytes
        executor = SandboxExecutor(self.sandbox_url) if self.sandbox_url else None
        veto = LocalVetoPolicy()
        url = f"{self.sender.base_url}/v1/actions"
        while True:
            await asyncio.sleep(interval_s)
            try:
                resp = await self.client.get(url, headers=hmac_headers(self.sender.credentials, "GET", url, b""))
                if resp.status_code != 200:
                    continue
                data = resp.json()
                sig = data.pop("sig", None)
                if self.sender.verify_key_bytes and not (sig and EnvelopeSigner.verify_signature(
                        self.sender.verify_key_bytes, canonical_bytes(data), sig)):
                    log.warning("action batch rejected: bad SaaS signature")
                    continue
                for action in data.get("actions", []):
                    await self._run_action(action, executor, veto)
            except httpx.HTTPError as exc:
                log.debug("action poll: cloud unreachable (%s)", type(exc).__name__)
            except Exception:
                log.exception("action poll failed")

    async def _run_action(self, action: dict, executor, veto: LocalVetoPolicy) -> None:
        expires = datetime.fromisoformat(action["expires_at"].replace("Z", "+00:00"))
        allowed, reason = veto.evaluate(action)
        if datetime.now(timezone.utc) > expires:
            allowed, reason = False, "expired"
        if executor is None:
            allowed, reason = False, "no local executor configured"
        if allowed:
            result = await executor.run_safe(action["type"])
        else:
            result = {"status": "vetoed", "local_policy_decision": "veto", "health_before": None,
                      "health_after": None, "ts": _now()}
        wire = {"status": result["status"],
                "local_policy_decision": "allow" if result["local_policy_decision"] == "allow" else "deny",
                "health_before": result.get("health_before"), "health_after": result.get("health_after"),
                "ts": result["ts"]}
        body = json.dumps(wire).encode()
        url = f"{self.sender.base_url}/v1/actions/{action['action_id']}/result"
        headers = {"Content-Type": "application/json", **hmac_headers(self.sender.credentials, "POST", url, body)}
        await self.client.post(url, content=body, headers=headers)
        self.status["actions"] = ([{"action_id": action["action_id"], "type": action["type"],
                                    "decision": wire["local_policy_decision"], "reason": reason,
                                    "status": wire["status"], "steps": result.get("steps", []), "at": _now(),
                                    "health_before": wire.get("health_before"), "health_after": wire.get("health_after")}]
                                  + self.status["actions"])[:20]
        log.info("action %s %s -> %s", action["type"], action["action_id"], wire["status"])

    async def snapshot(self) -> dict:
        stats = await self.ledger.stats() if self.ledger else {}
        return {**self.status, "outbox": stats, "collector_id": self.cfg.collector_id,
                "tenant_id": self.cfg.tenant_id, "dropped_invalid": self.bridge.dropped_invalid,
                "egress_blocked": self.guard.blocked_counter}


def _policy_int(version: str) -> int:
    """policy.yaml carries "1.0"; the wire contract wants the integer major version."""
    try:
        return max(1, int(float(version)))
    except (TypeError, ValueError):
        return 1


def _now() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3] + "Z"


def _sandbox_url(cfg) -> str | None:
    if os.environ.get("SANDBOX_URL"):
        return os.environ["SANDBOX_URL"]
    for extra in (cfg.sources or {}).get("extra_streams") or []:
        if extra.get("name") == "sandbox" and extra.get("enabled"):
            return str(extra.get("url", "")).rsplit("/metrics", 1)[0] or None
    return None


async def run_privacy_stage(cfg, bus, store, ctx, app) -> None:
    data_dir = Path(cfg.db_path).parent
    link = CloudLink(cfg, bus, ctx, data_dir)
    try:
        await link.setup()
    except Exception:
        log.exception("downstream setup failed; nothing will leave this collector")
        raise

    @app.get("/local/cloud")
    async def cloud_status() -> dict:
        return await link.snapshot()

    tasks = [asyncio.create_task(link.bridge.run(), name="privacy:bridge"),
             asyncio.create_task(link.topology_loop(), name="privacy:topology")]
    if link.sender is not None:
        tasks += [asyncio.create_task(link.send_loop(), name="cloud:send"),
                  asyncio.create_task(link.heartbeat_loop(), name="cloud:heartbeat"),
                  asyncio.create_task(link.action_loop(), name="cloud:actions")]
        log.info("downstream: privacy -> outbox -> %s as %s", cloud_base_url(cfg.ingest_url), cfg.collector_id)
    else:
        log.warning("downstream: not enrolled; payloads are kept in the local outbox until credentials exist")
    await store.audit("system", "downstream.start", f"enrolled={link.status['enrolled']}")
    try:
        await asyncio.gather(*tasks)
    except asyncio.CancelledError:
        raise
    except Exception:
        log.exception("downstream stopped")
        raise
    finally:
        for t in tasks:
            t.cancel()
        await link.client.aclose()
        await link.ledger.close()
