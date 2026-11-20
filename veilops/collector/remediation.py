"""Safe remediation executor (Member A) - called by B's action poller AFTER signature check + local veto.

    executor = SandboxExecutor("http://sandbox:9100")
    result = await executor.run_safe("RESTART_SERVICE")           # -> ActionResult-shaped dict

run_safe = snapshot -> dry-run -> execute -> verify (health must improve) -> auto-rollback if it does not.
B owns: pulling the signed action, Ed25519 + expiry check, local_policy veto, posting the result, audit.
For TEMP_BLOCK_SOURCE_15M, B resolves the `src_` pseudonym locally and passes the real address as `source`.
"""
from __future__ import annotations

import asyncio
from datetime import datetime, timezone

import httpx

_RANK = {"poor": 0, "fair": 1, "good": 2, "excellent": 3}
# Actions whose success is judged by health improving; the others succeed if they applied cleanly.
_MUST_IMPROVE = {"RESTART_SERVICE"}


def _iso() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="milliseconds").replace("+00:00", "Z")


class SandboxExecutor:
    def __init__(self, base_url: str, verify_timeout_s: float = 20.0, poll_s: float = 1.0,
                 transport: httpx.AsyncBaseTransport | None = None) -> None:
        self.base = base_url.rstrip("/")
        self.verify_timeout_s, self.poll_s = verify_timeout_s, poll_s
        self._transport = transport

    def _client(self) -> httpx.AsyncClient:
        return httpx.AsyncClient(base_url=self.base, timeout=10, transport=self._transport)

    async def health(self) -> dict:
        async with self._client() as c:
            return (await c.get("/health")).raise_for_status().json()

    async def action(self, action_type: str, dry_run: bool, source: str | None = None) -> dict:
        params = {"dry_run": str(dry_run).lower(), **({"source": source} if source else {})}
        async with self._client() as c:
            return (await c.post(f"/actions/{action_type}", params=params)).raise_for_status().json()

    async def rollback(self, action_id: str) -> dict:
        async with self._client() as c:
            return (await c.post(f"/rollback/{action_id}")).raise_for_status().json()

    async def run_safe(self, action_type: str, source: str | None = None,
                       local_policy_decision: str = "allow") -> dict:
        steps: list[dict] = []
        before = await self.health()
        steps.append({"step": "snapshot", "health": before["state"], "cpu_pct": before["cpu_pct"], "ts": _iso()})
        if local_policy_decision != "allow":
            return self._result("vetoed", local_policy_decision, before, before, steps)

        dry = await self.action(action_type, dry_run=True, source=source)
        steps.append({"step": "dry_run", "plan": dry["plan"], "ts": _iso()})
        done = await self.action(action_type, dry_run=False, source=source)
        steps.append({"step": "execute", "action_id": done["action_id"], "ts": _iso()})

        after = await self._wait_for_improvement(before) if action_type in _MUST_IMPROVE else await self.health()
        steps.append({"step": "verify", "health": after["state"], "cpu_pct": after["cpu_pct"], "ts": _iso()})
        improved = _RANK[after["state"]] > _RANK[before["state"]] or before["state"] == "excellent"
        if action_type in _MUST_IMPROVE and not improved and done.get("reversible"):
            rb = await self.rollback(done["action_id"])
            steps.append({"step": "rollback", "reason": "health did not improve", "ts": _iso()})
            return self._result("rolled_back", "allow", before, rb["health"], steps, done["action_id"])
        return self._result("executed", "allow", before, after, steps, done["action_id"])

    async def _wait_for_improvement(self, before: dict) -> dict:
        deadline = asyncio.get_running_loop().time() + self.verify_timeout_s
        last = await self.health()
        while asyncio.get_running_loop().time() < deadline:
            if _RANK[last["state"]] > _RANK[before["state"]]:
                return last
            await asyncio.sleep(self.poll_s)
            last = await self.health()
        return last

    @staticmethod
    def _result(status: str, decision: str, before: dict, after: dict, steps: list[dict],
                action_id: str | None = None) -> dict:
        # Fields match veilops.schema.ActionResult; `steps`/`sandbox_action_id` are for the local audit log.
        return {"status": status, "local_policy_decision": decision, "health_before": before["state"],
                "health_after": after["state"], "ts": _iso(), "steps": steps, "sandbox_action_id": action_id}
