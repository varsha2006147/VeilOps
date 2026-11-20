import hashlib
import hmac
import os
import re
import stat

import pytest
from hypothesis import given, settings
from hypothesis import strategies as st
from pydantic import TypeAdapter

from veilops.collector.privacy.pseudonymizer import (
    KIND_PREFIX,
    KeyFileError,
    PseudonymCollisionError,
    PseudonymError,
    Pseudonymizer,
    PseudonymStore,
    load_or_create_key,
)
from veilops.schema.common import EntityId, PrincipalId, SourceId

KEY = b"\x01" * 32
OTHER_KEY = b"\x02" * 32


def make(key=KEY):
    store = PseudonymStore()
    return Pseudonymizer(key, store), store


def test_formula_matches_specification():
    ps, _ = make()
    expected = "h_" + hmac.new(KEY, b"host:db-prod-02", hashlib.sha256).hexdigest()[:10]
    assert ps.pseudonymize("host", "db-prod-02") == expected


def test_all_kinds_produce_schema_valid_identifiers():
    assert set(KIND_PREFIX) == {"host", "service", "link", "principal", "source"}
    for kind in ("host", "service", "link"):
        ps, _ = make()
        TypeAdapter(EntityId).validate_python(ps.pseudonymize(kind, "x1"))
    ps, _ = make()
    TypeAdapter(PrincipalId).validate_python(ps.pseudonymize("principal", "priya"))
    ps, _ = make()
    TypeAdapter(SourceId).validate_python(ps.pseudonymize("source", "10.2.3.4"))


def test_deterministic_and_key_dependent_and_kind_dependent():
    ps1, _ = make(KEY)
    ps2, _ = make(KEY)
    ps3, _ = make(OTHER_KEY)
    assert ps1.pseudonymize("host", "db-prod-02") == ps2.pseudonymize("host", "db-prod-02")
    assert ps1.pseudonymize("host", "db-prod-02") != ps3.pseudonymize("host", "db-prod-02")
    assert ps1.pseudonymize("host", "db-prod-02")[2:] != ps1.pseudonymize("service", "db-prod-02")[4:]


def test_pseudonym_does_not_contain_real_value():
    ps, _ = make()
    assert "db-prod-02" not in ps.pseudonymize("host", "db-prod-02")


def test_resolve_roundtrip_and_unknown_returns_none():
    ps, store = make()
    pseudo = ps.pseudonymize("principal", "priya")
    assert ps.resolve(pseudo) == ("principal", "priya")
    assert Pseudonymizer(KEY, store).resolve(pseudo) == ("principal", "priya")
    assert ps.resolve("h_0000000000") is None


def test_repeat_calls_store_a_single_row():
    ps, store = make()
    ps.pseudonymize("host", "db-prod-02")
    ps.pseudonymize("host", "db-prod-02")
    assert store.count() == 1


def test_store_persists_to_disk(tmp_path):
    db = tmp_path / "local.db"
    store1 = PseudonymStore(db)
    pseudo = Pseudonymizer(KEY, store1).pseudonymize("host", "db-prod-02")
    store1.close()
    store2 = PseudonymStore(db)
    try:
        assert store2.resolve(pseudo) == ("host", "db-prod-02")
    finally:
        store2.close()


def test_collision_fails_closed():
    store = PseudonymStore()
    store.remember("h_0000000000", "host", "a")
    store.remember("h_0000000000", "host", "a")
    with pytest.raises(PseudonymCollisionError):
        store.remember("h_0000000000", "host", "b")


def test_invalid_inputs_rejected_without_leaking_value():
    ps, _ = make()
    with pytest.raises(PseudonymError) as info:
        ps.pseudonymize("bogus", "S3cr3t-value")
    assert "S3cr3t-value" not in str(info.value)
    for bad in ("", 123, None):
        with pytest.raises(PseudonymError):
            ps.pseudonymize("host", bad)  # type: ignore[arg-type]


def test_key_file_created_reused_and_private(tmp_path):
    p = tmp_path / "keys" / "tenant.key"
    k1 = load_or_create_key(p)
    assert len(k1) == 32 and p.exists()
    assert load_or_create_key(p) == k1
    assert re.fullmatch(r"[0-9a-f]{64}", p.read_text(encoding="ascii").strip())
    if os.name == "posix":
        assert stat.S_IMODE(p.stat().st_mode) == 0o600


def test_malformed_key_files_rejected(tmp_path):
    bad = tmp_path / "bad.key"
    bad.write_text("not-hex", encoding="ascii")
    with pytest.raises(KeyFileError):
        load_or_create_key(bad)
    short = tmp_path / "short.key"
    short.write_text("ab" * 16, encoding="ascii")
    with pytest.raises(KeyFileError):
        load_or_create_key(short)


def test_repr_hides_key_and_bad_key_length_rejected():
    ps, _ = make()
    assert KEY.hex() not in repr(ps)
    with pytest.raises(PseudonymError):
        Pseudonymizer(b"short", PseudonymStore())


@settings(max_examples=100, deadline=None)
@given(
    value=st.text(
        alphabet=st.characters(blacklist_categories=("Cs", "Cc")), min_size=1, max_size=50
    )
)
def test_fuzz_any_value_gives_well_formed_resolvable_pseudonym(value):
    store = PseudonymStore()
    try:
        ps = Pseudonymizer(KEY, store)
        pseudo = ps.pseudonymize("host", value)
        assert re.fullmatch(r"h_[0-9a-f]{10}", pseudo)
        assert ps.resolve(pseudo) == ("host", value)
    finally:
        store.close()
