"""Gate 1 (part 2): deterministic keyed pseudonyms + local re-identification map.

pseudonym = prefix + "_" + hex(HMAC-SHA256(K_tenant_local, kind + ":" + value))[:10]

K_tenant_local lives only in a local key file (mode 0600) and is NEVER transmitted.
The (pseudonym -> real value) map lives only in the local SQLite database.
"""
from __future__ import annotations

import hashlib
import hmac
import os
import secrets
import sqlite3
import threading
from datetime import datetime, timezone
from pathlib import Path

KIND_PREFIX = {
    "host": "h",
    "service": "svc",
    "link": "lnk",
    "principal": "usr",
    "source": "src",
}
_KEY_BYTES = 32


class PseudonymError(Exception):
    """Base class. Messages never contain real values or key material."""


class KeyFileError(PseudonymError):
    pass


class PseudonymCollisionError(PseudonymError):
    pass


def _utc_now_iso() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3] + "Z"


def load_or_create_key(path: "str | Path") -> bytes:
    """Return the 32-byte tenant key, creating the key file (hex, mode 0600) if missing."""
    p = Path(path)
    if p.exists():
        try:
            key = bytes.fromhex(p.read_text(encoding="ascii").strip())
        except (ValueError, UnicodeDecodeError, OSError):
            raise KeyFileError(f"unreadable or malformed key file: {p}") from None
        if len(key) != _KEY_BYTES:
            raise KeyFileError(f"key file must hold {_KEY_BYTES} bytes of hex: {p}")
        return key
    key = secrets.token_bytes(_KEY_BYTES)
    p.parent.mkdir(parents=True, exist_ok=True)
    fd = os.open(p, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(fd, "w", encoding="ascii") as fh:
        fh.write(key.hex() + "\n")
    try:
        os.chmod(p, 0o600)
    except OSError:
        pass
    return key


class PseudonymStore:
    """SQLite table pseudonym_map(pseudo, kind, real_value, first_seen). Never leaves the host."""

    def __init__(self, db_path: "str | Path" = ":memory:") -> None:
        self._lock = threading.Lock()
        in_memory = str(db_path) == ":memory:"
        if not in_memory:
            Path(db_path).parent.mkdir(parents=True, exist_ok=True)
        self._conn = sqlite3.connect(str(db_path), check_same_thread=False)
        if not in_memory:
            self._conn.execute("PRAGMA journal_mode=WAL")
        self._conn.execute(
            "CREATE TABLE IF NOT EXISTS pseudonym_map ("
            "pseudo TEXT PRIMARY KEY, kind TEXT NOT NULL, "
            "real_value TEXT NOT NULL, first_seen TEXT NOT NULL)"
        )
        self._conn.commit()

    def remember(self, pseudo: str, kind: str, real_value: str) -> None:
        with self._lock:
            row = self._conn.execute(
                "SELECT kind, real_value FROM pseudonym_map WHERE pseudo = ?", (pseudo,)
            ).fetchone()
            if row is None:
                self._conn.execute(
                    "INSERT INTO pseudonym_map (pseudo, kind, real_value, first_seen) "
                    "VALUES (?, ?, ?, ?)",
                    (pseudo, kind, real_value, _utc_now_iso()),
                )
                self._conn.commit()
            elif tuple(row) != (kind, real_value):
                raise PseudonymCollisionError(f"pseudonym collision for {pseudo}")

    def resolve(self, pseudo: str) -> "tuple[str, str] | None":
        with self._lock:
            row = self._conn.execute(
                "SELECT kind, real_value FROM pseudonym_map WHERE pseudo = ?", (pseudo,)
            ).fetchone()
        return (row[0], row[1]) if row else None

    def all(self) -> "list[tuple[str, str, str]]":
        with self._lock:
            return [tuple(r) for r in self._conn.execute(
                "SELECT pseudo, kind, real_value FROM pseudonym_map ORDER BY kind, real_value")]

    def count(self) -> int:
        with self._lock:
            return self._conn.execute("SELECT COUNT(*) FROM pseudonym_map").fetchone()[0]

    def close(self) -> None:
        with self._lock:
            self._conn.close()


class Pseudonymizer:
    def __init__(self, key: bytes, store: PseudonymStore) -> None:
        if not isinstance(key, (bytes, bytearray)) or len(key) != _KEY_BYTES:
            raise PseudonymError(f"key must be exactly {_KEY_BYTES} bytes")
        self._key = bytes(key)
        self._store = store
        self._cache: "dict[tuple[str, str], str]" = {}

    def __repr__(self) -> str:
        return "Pseudonymizer(key=<hidden>)"

    def pseudonymize(self, kind: str, value: str) -> str:
        if kind not in KIND_PREFIX:
            raise PseudonymError(f"unknown kind: {kind!r}")
        if not isinstance(value, str) or value == "":
            raise PseudonymError("value must be a non-empty string")
        cache_key = (kind, value)
        hit = self._cache.get(cache_key)
        if hit is not None:
            return hit
        digest = hmac.new(
            self._key, f"{kind}:{value}".encode("utf-8"), hashlib.sha256
        ).hexdigest()[:10]
        pseudo = f"{KIND_PREFIX[kind]}_{digest}"
        self._store.remember(pseudo, kind, value)
        self._cache[cache_key] = pseudo
        return pseudo

    def resolve(self, pseudo: str) -> "tuple[str, str] | None":
        return self._store.resolve(pseudo)

    def codes(self) -> "list[tuple[str, str, str]]":
        return self._store.all()
