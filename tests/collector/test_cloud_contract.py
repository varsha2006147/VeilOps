"""Collector <-> cloud wire contract: auth, receipts and actions must agree byte for byte."""
import base64
import json

from cloud.app.crypto import ReceiptSigner
from cloud.app.security import verify_hmac
from veilops.collector.privacy.stage import _policy_int, cloud_base_url
from veilops.collector.transport.sender import CollectorCredentials, hmac_headers
from veilops.collector.transport.signer import EnvelopeSigner, canonical_bytes
from veilops.schema.wire import Receipt

CREDS = CollectorCredentials("col_test", b"s3cret-key-material")


def _cloud_accepts(method, path, body, headers):
    return verify_hmac(CREDS.secret, method, path, headers["X-VeilOps-Timestamp"],
                       headers["X-VeilOps-Nonce"], body, headers["X-VeilOps-Signature"])


def test_collector_hmac_is_accepted_by_cloud_verifier():
    body = b'{"seq":1}'
    h = hmac_headers(CREDS, "POST", "http://cloud:8000/v1/ingest", body)
    assert h["X-VeilOps-Collector"] == "col_test" and len(h["X-VeilOps-Nonce"]) == 32
    assert _cloud_accepts("POST", "/v1/ingest", body, h)
    assert not _cloud_accepts("POST", "/v1/ingest", b'{"seq":2}', h)        # body is bound


def test_hmac_covers_query_string_for_reconcile():
    url = "http://cloud/v1/reconcile?collector_id=col_test&from_seq=1&to_seq=9"
    h = hmac_headers(CREDS, "GET", url, b"")
    assert _cloud_accepts("GET", "/v1/reconcile?collector_id=col_test&from_seq=1&to_seq=9", b"", h)
    assert not _cloud_accepts("GET", "/v1/reconcile?collector_id=col_test&from_seq=1&to_seq=99", b"", h)


def test_credentials_never_print_the_secret():
    assert "s3cret" not in repr(CREDS)


def test_cloud_receipt_matches_wire_schema_and_verifies_on_collector():
    seed = base64.urlsafe_b64encode(b"r" * 32).decode()
    signer = ReceiptSigner(seed)
    receipt = {"payload_id": "0196b8f2-1111-7abc-8def-0123456789ab", "payload_hash": "sha256:" + "a" * 64,
               "status": "stored", "received_at": "2026-11-21T04:00:00.123Z", "region": "in",
               "highest_contiguous_seq": 3}
    receipt["sig"] = signer.sign(json.dumps(receipt, sort_keys=True, separators=(",", ":")).encode())
    Receipt.model_validate(receipt)                                           # B's strict wire model
    raw = json.loads(json.dumps(receipt))                                      # as received over HTTP
    no_sig = {k: v for k, v in raw.items() if k != "sig"}
    pub = base64.b64decode(signer.public_key_b64())
    assert EnvelopeSigner.verify_signature(pub, canonical_bytes(no_sig), raw["sig"])
    no_sig["highest_contiguous_seq"] = 4
    assert not EnvelopeSigner.verify_signature(pub, canonical_bytes(no_sig), raw["sig"])


def test_ingest_url_and_policy_version_helpers():
    assert cloud_base_url("https://in.ingest.veilops.local/v1") == "https://in.ingest.veilops.local"
    assert cloud_base_url("http://c:8000/v1/") == "http://c:8000"
    assert (_policy_int("1.0"), _policy_int("2"), _policy_int("x")) == (1, 2, 1)
