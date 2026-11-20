"""Ed25519 collector key management and canonical RFC 8785 payload signing."""
from __future__ import annotations

import base64
import hashlib
import os
from pathlib import Path
from typing import Any

import nacl.encoding
import nacl.exceptions
import nacl.signing
import rfc8785

from veilops.schema.common import GENESIS_HASH


class SignerError(ValueError):
    """Raised when key loading, parsing, or signing operations fail."""


def canonical_bytes(obj: Any) -> bytes:
    """Canonicalize a JSON-serializable Python object using RFC 8785."""
    return rfc8785.dumps(obj)


def sha256_hex(data: bytes) -> str:
    """Return lowercase 64-char SHA-256 hex digest of data."""
    return hashlib.sha256(data).hexdigest().lower()


def compute_payload_hash(records: list[dict[str, Any]]) -> str:
    """Compute 64-character lowercase SHA-256 hex digest of canonicalized records list."""
    return sha256_hex(canonical_bytes(records))


def load_or_create_signing_key(path: str | Path) -> nacl.signing.SigningKey:
    """Load or generate a 32-byte Ed25519 signing key stored as 64-char hex."""
    p = Path(path)
    if p.exists():
        try:
            hex_seed = p.read_text(encoding="ascii").strip()
        except Exception as exc:
            raise SignerError(f"unable to read signing key file at {p}: {exc}") from exc

        if len(hex_seed) != 64 or not all(c in "0123456789abcdefABCDEF" for c in hex_seed):
            raise SignerError("malformed key file: expected 64-char hex seed")

        try:
            raw_seed = bytes.fromhex(hex_seed)
            return nacl.signing.SigningKey(raw_seed)
        except Exception as exc:
            raise SignerError(f"invalid seed in signing key file: {exc}") from exc

    # Generate new key
    try:
        p.parent.mkdir(parents=True, exist_ok=True)
        sk = nacl.signing.SigningKey.generate()
        seed_hex = bytes(sk).hex()
        p.write_text(seed_hex, encoding="ascii")
        try:
            os.chmod(p, 0o600)
        except Exception:
            pass
        return sk
    except Exception as exc:
        raise SignerError(f"failed to create signing key file at {p}: {exc}") from exc


class EnvelopeSigner:
    """Manages Ed25519 envelope signing with private key redaction in representations."""

    def __init__(self, signing_key: nacl.signing.SigningKey) -> None:
        if not isinstance(signing_key, nacl.signing.SigningKey):
            raise SignerError("expected nacl.signing.SigningKey instance")
        self._sk = signing_key
        self._vk = signing_key.verify_key
        self._pub_bytes = bytes(self._vk)

    def __repr__(self) -> str:
        return f"<EnvelopeSigner public_key_hex={self.public_key_hex[:16]}...>"

    @property
    def public_key_bytes(self) -> bytes:
        return self._pub_bytes

    @property
    def public_key_hex(self) -> str:
        return self._pub_bytes.hex().lower()

    @property
    def public_key_b64(self) -> str:
        return base64.b64encode(self._pub_bytes).decode("ascii")

    def sign_bytes(self, data: bytes) -> str:
        """Sign bytes using Ed25519 and return base64-encoded signature."""
        signed = self._sk.sign(data)
        return base64.b64encode(signed.signature).decode("ascii")

    def sign_envelope_dict(self, envelope_without_sig_or_canonical: dict[str, Any]) -> str:
        """Canonicalize dictionary with RFC 8785 and sign resulting bytes."""
        canonical = canonical_bytes(envelope_without_sig_or_canonical)
        return self.sign_bytes(canonical)

    @staticmethod
    def verify_signature(public_key_bytes: bytes, data: bytes, sig_b64: str) -> bool:
        """Verify an Ed25519 signature cleanly, returning False on any failure."""
        if len(public_key_bytes) != 32:
            return False
        try:
            sig_bytes = base64.b64decode(sig_b64.encode("ascii"), validate=True)
            if len(sig_bytes) != 64:
                return False
            vk = nacl.signing.VerifyKey(public_key_bytes)
            vk.verify(data, sig_bytes)
            return True
        except Exception:
            return False
