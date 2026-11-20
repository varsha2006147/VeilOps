"""Tests for the local secret and sensitive-data redactor."""
from __future__ import annotations

import pytest

from veilops.collector.privacy.redactor import (
    contains_secret,
    redact_obj,
    redact_text,
    redact_with_report,
)


def test_redact_connection_strings():
    raw = "Failed connecting to postgres://admin:SuperSecret123@db-primary.internal:5432/orders"
    redacted = redact_text(raw)
    assert "SuperSecret123" not in redacted
    assert redacted == "Failed connecting to postgres://admin:[REDACTED]@db-primary.internal:5432/orders"
    assert contains_secret(raw) is True


def test_redact_bearer_and_jwt_tokens():
    jwt = "Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIn0.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c"
    redacted = redact_text(jwt)
    assert "eyJ" not in redacted
    assert "[REDACTED]" in redacted


def test_redact_aws_and_api_tokens():
    raw = "Error accessing S3 with key AKIAIOSFODNN7EXAMPLE and secret ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
    redacted, report = redact_with_report(raw)
    assert "AKIAIOSFODNN7EXAMPLE" not in redacted
    assert "ghp_" not in redacted
    assert "aws_key" in report
    assert "api_token" in report


def test_redact_private_key_blocks():
    pem = """-----BEGIN RSA PRIVATE KEY-----
MIIEowIBAAKCAQEA0Y1+abcdefghijklmnopqrstuvwxyz0123456789ABCDEF
-----END RSA PRIVATE KEY-----"""
    redacted = redact_text(pem)
    assert "MIIEow" not in redacted
    assert redacted == "[REDACTED]"


def test_redact_password_assignments():
    raw = "config error: password=hunter2 api_key: 'sk_live_1234567890abcdef'"
    redacted = redact_text(raw)
    assert "hunter2" not in redacted
    assert "sk_live_" not in redacted
    assert "password=[REDACTED]" in redacted


def test_redact_email_and_identifiers():
    raw = "Contact admin user at priya.sharma@corp.internal or alice@example.com"
    redacted = redact_text(raw)
    assert "priya.sharma@corp.internal" not in redacted
    assert "alice@example.com" not in redacted


def test_benign_observability_data_preserved():
    clean = "host=h_7f3a21c90b metric=cpu.util_pct avg=91.2 unit=pct window=5s"
    assert redact_text(clean) == clean
    assert contains_secret(clean) is False


def test_redact_nested_structures():
    data = {
        "entity": "h_7f3a21c90b",
        "auth": {
            "token": "ghp_111122223333444455556666777788889999",
            "connection": "mysql://root:P@ssword123@127.0.0.1:3306/test",
        },
        "log_messages": [
            "password=my_secret_pass",
            "cpu normal at 42%",
        ],
    }
    cleaned = redact_obj(data)
    assert cleaned["entity"] == "h_7f3a21c90b"
    assert "ghp_" not in cleaned["auth"]["token"]
    assert "P@ssword123" not in cleaned["auth"]["connection"]
    assert "my_secret_pass" not in cleaned["log_messages"][0]
    assert cleaned["log_messages"][1] == "cpu normal at 42%"


def test_redact_does_not_mutate_original_dict():
    original = {"secret": "password=dont_mutate_me"}
    _ = redact_obj(original)
    assert original["secret"] == "password=dont_mutate_me"
