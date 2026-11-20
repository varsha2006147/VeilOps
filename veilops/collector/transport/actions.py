"""Action polling, Ed25519 authorization verification, and local veto policy."""
from __future__ import annotations

import base64
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Awaitable, Callable

import rfc8785

from veilops.collector.remediation import SandboxExecutor
from veilops.collector.transport.signer import EnvelopeSigner, canonical_bytes
from veilops.schema.wire import Action, ActionResult


@dataclass
class LocalVetoPolicy:
    """Local policy determining whether an automated remediation action is safe to run."""

    disallowed_types: set[str] = field(default_factory=set)
    require_valid_target: bool = True
    allow_destructive: bool = True

    def evaluate(
        self,
        action: Action | dict[str, Any],
        health: dict[str, Any] | None = None,
    ) -> tuple[bool, str]:
        """Evaluate action safety against local node policies."""
        act_type = action.type if isinstance(action, Action) else action.get("type", "")
        target = action.target if isinstance(action, Action) else action.get("target", "")

        if act_type in self.disallowed_types:
            return False, f"action type {act_type} is disallowed by local node policy"

        if not self.allow_destructive and act_type in ("RESTART_SERVICE", "TEMP_BLOCK_SOURCE_15M"):
            return False, f"destructive action {act_type} forbidden by policy"

        if self.require_valid_target and not target:
            return False, "action target missing"

        if health and health.get("state") == "poor" and act_type == "INVESTIGATE_TOP_PROCESSES":
            # Avoid overhead when host is already under high stress
            return False, "node state poor: investigative actions deferred"

        return True, "allow"


class ActionPoller:
    """Polls, verifies, evaluates local veto, and executes remote remediation directives."""

    def __init__(
        self,
        fetch_actions_fn: Callable[[], Awaitable[list[Action | dict[str, Any]]]],
        *,
        executor: SandboxExecutor | None = None,
        veto_policy: LocalVetoPolicy | None = None,
        verify_key_bytes: bytes | None = None,
        resolver: Callable[[str], str | None] | None = None,
    ) -> None:
        self.fetch_actions_fn = fetch_actions_fn
        self.executor = executor
        self.veto_policy = veto_policy or LocalVetoPolicy()
        self.verify_key_bytes = verify_key_bytes
        self.resolver = resolver
        self.executed_history: list[ActionResult] = []

    async def poll_and_execute_once(self) -> list[ActionResult]:
        """Fetch pending actions, verify signatures/expiry, apply local veto, and execute."""
        actions_raw = await self.fetch_actions_fn()
        results: list[ActionResult] = []

        now = datetime.now(timezone.utc)
        now_iso = now.strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3] + "Z"

        for raw in actions_raw:
            try:
                action = raw if isinstance(raw, Action) else Action.model_validate(raw)
            except Exception:
                continue

            # 1. Signature verification
            if self.verify_key_bytes and action.sig:
                action_dict = action.model_dump(mode="json")
                action_dict_no_sig = {k: v for k, v in action_dict.items() if k != "sig"}
                canonical = canonical_bytes(action_dict_no_sig)
                if not EnvelopeSigner.verify_signature(
                    self.verify_key_bytes, canonical, action.sig
                ):
                    res = ActionResult(
                        status="vetoed",
                        local_policy_decision="veto",
                        health_before="good",
                        health_after="good",
                        ts=now_iso,
                    )
                    results.append(res)
                    self.executed_history.append(res)
                    continue

            # 2. Expiry check
            try:
                expires_dt = datetime.fromisoformat(action.expires_at.replace("Z", "+00:00"))
                if now > expires_dt:
                    res = ActionResult(
                        status="vetoed",
                        local_policy_decision="veto",
                        health_before="good",
                        health_after="good",
                        ts=now_iso,
                    )
                    results.append(res)
                    self.executed_history.append(res)
                    continue
            except Exception:
                pass

            # 3. Local Veto policy evaluation
            current_health = None
            if self.executor:
                try:
                    current_health = await self.executor.health()
                except Exception:
                    current_health = None

            allowed, reason = self.veto_policy.evaluate(action, current_health)
            if not allowed:
                health_state = (current_health or {}).get("state", "good")
                res = ActionResult(
                    status="vetoed",
                    local_policy_decision="veto",
                    health_before=health_state,
                    health_after=health_state,
                    ts=now_iso,
                )
                results.append(res)
                self.executed_history.append(res)
                continue

            # 4. Execution via SandboxExecutor
            if self.executor:
                real_source = None
                if action.target.startswith("src_") and self.resolver:
                    real_source = self.resolver(action.target)

                exec_result = await self.executor.run_safe(
                    action.type,
                    source=real_source,
                    local_policy_decision="allow",
                )
                res = ActionResult(
                    status=exec_result.get("status", "executed"),
                    local_policy_decision="allow",
                    health_before=exec_result.get("health_before", "good"),
                    health_after=exec_result.get("health_after", "good"),
                    ts=exec_result.get("ts", now_iso),
                )
                results.append(res)
                self.executed_history.append(res)
            else:
                res = ActionResult(
                    status="executed",
                    local_policy_decision="allow",
                    health_before="good",
                    health_after="good",
                    ts=now_iso,
                )
                results.append(res)
                self.executed_history.append(res)

        return results
