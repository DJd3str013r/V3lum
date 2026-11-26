"""Keyed HMAC pseudonyms (A4, WP10): the installation secret is created once with 0600, pseudonyms
are stable per (type, value), differ between installations and never reveal the value."""

from __future__ import annotations

import hashlib
import hmac
import os
import stat
import threading

import pytest

from v3lum import paths
from v3lum.core import hmacid
from v3lum.core.entities import Entity, EntityType


def mode(path) -> int:
    return stat.S_IMODE(os.stat(path).st_mode)


def test_secret_is_created_once_with_0600():
    key_file = paths.secret_key_file()
    assert key_file == paths.home() / "secret.key" and not key_file.exists()
    first = hmacid.installation_secret()
    assert len(first) == hmacid.SECRET_BYTES == 32
    assert key_file.read_bytes() == first and mode(key_file) == 0o600
    stamp = key_file.stat().st_mtime_ns
    assert hmacid.installation_secret() == first
    assert key_file.stat().st_mtime_ns == stamp  # never rewritten
    assert not [p for p in paths.home().iterdir() if p.name != "secret.key" and "secret" in p.name]  # no temp leftovers


def test_secret_creation_race_yields_one_secret():
    results: list[bytes] = []
    lock = threading.Lock()

    def grab() -> None:
        value = hmacid.installation_secret()
        with lock:
            results.append(value)

    threads = [threading.Thread(target=grab) for _ in range(8)]
    for t in threads:
        t.start()
    for t in threads:
        t.join(10)
    assert len(results) == 8 and len(set(results)) == 1


def test_hmac_is_keyed_sha256_of_type_and_value():
    secret = hmacid.installation_secret()
    expected = hmac.new(secret, b"email:alice@corp.example", hashlib.sha256).hexdigest()
    assert hmacid.hmac_hex("email", "alice@corp.example") == expected
    assert hmacid.hmac_hex(EntityType.EMAIL, "alice@corp.example") == expected
    assert hmacid.hmac12("email", "alice@corp.example") == expected[:12]
    entity = Entity.make("email", "Alice@Corp.Example")
    assert hmacid.entity_hmac(entity) == expected  # normalized value
    plain = hashlib.sha256(b"email:alice@corp.example").hexdigest()
    assert expected != plain  # not guessable without the secret


def test_stable_per_type_and_value_and_distinct_otherwise():
    a = hmacid.hmac12("username", "octocat")
    assert a == hmacid.hmac12("username", "octocat") and len(a) == 12 and all(c in "0123456789abcdef" for c in a)
    assert hmacid.hmac12("email", "octocat") != a  # the type is part of the message
    assert hmacid.hmac12("username", "octocat2") != a


def test_another_installation_gets_other_pseudonyms(tmp_path, monkeypatch):
    here = hmacid.hmac12("phone", "+5511999990000")
    monkeypatch.setenv("V3LUM_HOME", str(tmp_path / "other_home"))
    there = hmacid.hmac12("phone", "+5511999990000")
    assert here != there


def test_pseudonyms_for_search_indexes():
    p = hmacid.pseudonymize_key("email:alice@corp.example")
    assert p == f"email:#{hmacid.hmac12('email', 'alice@corp.example')}" and hmacid.is_pseudonym(p)
    assert hmacid.pseudonymize_key(p) == p  # idempotent
    assert hmacid.pseudonymize_key("domain:evil.example") == "domain:evil.example"  # IOC types stay searchable
    assert hmacid.pseudonymize_key("ipv4:203.0.113.5") == "ipv4:203.0.113.5"
    assert hmacid.is_pseudonym(hmacid.pseudonymize_key("cpf:52998224725"))
    assert hmacid.is_pseudonym(hmacid.pseudonymize_key("text_blob:call me at alice@corp.example"))  # free text may be personal
    assert hmacid.is_pseudonym(hmacid.pseudonymize_key("mystery_type:value"))  # unknown type: fail closed
    assert hmacid.pseudonymize_key("no-colon") == "no-colon"
    assert EntityType.EMAIL in hmacid.PSEUDONYMISED_TYPES and EntityType.DOMAIN not in hmacid.PSEUDONYMISED_TYPES


def test_loose_secret_is_tightened_and_damage_is_reported():
    secret = hmacid.installation_secret()
    key_file = paths.secret_key_file()
    os.chmod(key_file, 0o644)
    assert hmacid.installation_secret() == secret and mode(key_file) == 0o600  # a loosened key is tightened
    key_file.write_bytes(b"short")
    with pytest.raises(RuntimeError, match="damaged"):
        hmacid.installation_secret()
    key_file.write_bytes(b"")  # an empty file (crash during creation) is replaced by a new secret
    fresh = hmacid.installation_secret()
    assert len(fresh) == 32 and fresh != secret and mode(key_file) == 0o600


def test_secret_types_are_pseudonymised_in_search_indexes():
    """Fail closed: a token or card number never sits in an index in clear, even unredacted."""
    for key in ("jwt:eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxIn0.c2lnbmF0dXJl", "payment_card:4111111111111111"):
        etype = key.split(":", 1)[0]
        assert EntityType.parse(etype) in hmacid.PSEUDONYMISED_TYPES
        out = hmacid.pseudonymize_key(key)
        assert hmacid.is_pseudonym(out) and key.split(":", 1)[1] not in out


@pytest.mark.skipif(os.name != "posix" or not hasattr(os, "geteuid") or os.geteuid() != 0, reason="chown to another user needs root")
def test_a_secret_owned_by_another_user_is_refused():
    """A planted secret.key (e.g. a V3LUM_HOME in a shared directory) would make every pseudonym
    reversible by whoever wrote it."""
    key_file = paths.secret_key_file()
    key_file.write_bytes(os.urandom(32))
    os.chmod(key_file, 0o600)
    os.chown(key_file, 12345, -1)
    try:
        with pytest.raises(RuntimeError, match="owned by uid 12345"):
            hmacid.installation_secret()
    finally:
        os.chown(key_file, os.getuid(), -1)
    assert len(hmacid.installation_secret()) == 32
