"""Ledger verification and policy diff command line tools."""
from __future__ import annotations

import argparse
import asyncio
import json
import sys
from pathlib import Path
from typing import Any

from veilops.collector.transport.outbox import OutboxLedger
from veilops.collector.transport.signer import EnvelopeSigner, load_or_create_signing_key
from veilops.schema.policy import Policy, PolicyError, load_policy


async def verify_ledger(db_path: str | Path) -> tuple[bool, str, int]:
    """Open and verify unbroken cryptographic chain on a ledger database."""
    p = Path(db_path)
    if not p.is_file():
        return False, f"database file not found: {p}", 0

    dummy_sk = load_or_create_signing_key(p.parent / ".cli_verify.key")
    signer = EnvelopeSigner(dummy_sk)

    async with OutboxLedger(p, signer) as ledger:
        valid, status = await ledger.verify_chain()
        stats = await ledger.stats()
        return valid, status, stats.get("highest_seq", 0)


def policy_diff(old_path: str | Path, new_path: str | Path) -> dict[str, Any]:
    """Compute structured difference between two policy YAML files."""
    old_p = load_policy(old_path)
    new_p = load_policy(new_path)

    old_rts = set(old_p.record_types.keys())
    new_rts = set(new_p.record_types.keys())

    added_types = sorted(new_rts - old_rts)
    removed_types = sorted(old_rts - new_rts)

    field_changes: dict[str, dict[str, list[str]]] = {}
    for rt in sorted(old_rts & new_rts):
        old_fields = set(old_p.record_types[rt].fields)
        new_fields = set(new_p.record_types[rt].fields)
        added_f = sorted(new_fields - old_fields)
        removed_f = sorted(old_fields - new_fields)
        if added_f or removed_f:
            field_changes[rt] = {
                "added": added_f,
                "removed": removed_f,
            }

    return {
        "old_version": old_p.version,
        "new_version": new_p.version,
        "old_hash": old_p.hash or old_p.policy_hash,
        "new_hash": new_p.hash or new_p.policy_hash,
        "added_record_types": added_types,
        "removed_record_types": removed_types,
        "field_changes": field_changes,
    }


def _run_async(coro: Any) -> Any:
    """Run an async coroutine safely whether an event loop is currently running or not."""
    try:
        loop = asyncio.get_running_loop()
    except RuntimeError:
        loop = None

    if loop and loop.is_running():
        import concurrent.futures
        with concurrent.futures.ThreadPoolExecutor(max_workers=1) as executor:
            return executor.submit(lambda: asyncio.run(coro)).result()
    return asyncio.run(coro)


def main(argv: list[str] | None = None) -> int:
    """CLI entrypoint for ledger verification and policy diffing."""
    parser = argparse.ArgumentParser(
        prog="veilops.collector.transport.cli",
        description="VeilOps Transport & Policy Utilities",
    )
    sub = parser.add_subparsers(dest="command", required=True)

    # verify-ledger
    vl = sub.add_parser("verify-ledger", help="Verify cryptographic chain on outbox database")
    vl.add_argument("--db", required=True, help="Path to outbox SQLite database")

    # policy-diff
    pd = sub.add_parser("policy-diff", help="Diff two egress policy YAML definitions")
    pd.add_argument("--old", required=True, help="Path to base policy YAML")
    pd.add_argument("--new", required=True, help="Path to comparison policy YAML")

    args = parser.parse_args(argv if argv is not None else sys.argv[1:])

    if args.command == "verify-ledger":
        valid, reason, count = _run_async(verify_ledger(args.db))
        if valid:
            print(f"LEDGER OK: {count} envelopes verified, hash chain intact.")
            return 0
        else:
            print(f"LEDGER INTEGRITY FAILED: {reason}", file=sys.stderr)
            return 1

    elif args.command == "policy-diff":
        try:
            diff = policy_diff(args.old, args.new)
            print(
                f"Policy diff: v{diff['old_version']} ({diff['old_hash'][:16]}...) -> "
                f"v{diff['new_version']} ({diff['new_hash'][:16]}...)"
            )
            if diff["added_record_types"]:
                print(f"  + Added record types: {', '.join(diff['added_record_types'])}")
            if diff["removed_record_types"]:
                print(f"  - Removed record types: {', '.join(diff['removed_record_types'])}")
            for rt, changes in diff["field_changes"].items():
                print(f"  Record type [{rt}]:")
                if changes["added"]:
                    print(f"    + Added fields: {', '.join(changes['added'])}")
                if changes["removed"]:
                    print(f"    - Removed fields: {', '.join(changes['removed'])}")
            if (
                not diff["added_record_types"]
                and not diff["removed_record_types"]
                and not diff["field_changes"]
            ):
                print("  No structural record type or field changes detected.")
            return 0
        except Exception as exc:
            print(f"Policy diff error: {exc}", file=sys.stderr)
            return 1

    return 0


if __name__ == "__main__":
    sys.exit(main())
