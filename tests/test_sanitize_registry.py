"""Thin sanitizer (WP01, P145/A4): schema registry, allow-list paths, body hook, second net, combos."""

from __future__ import annotations

import hashlib
import json

import pytest

from v3lum.core import sanitize
from v3lum.core.entities import Entity
from v3lum.core.entities import EntityType as T
from v3lum.core.models import ModuleResult, Pivot
from v3lum.core.sanitize import (
    SECOND_NET_FIELDS,
    SanitizerError,
    SanitizerSchema,
    apply_schema,
    drop_combos,
    mask_secret,
    register_schema,
    sanitize_body,
    sanitize_result,
    schema_for,
)

PID = "t_breachy"
BREACH_BODY = {
    "email": "alice@corp.example",
    "breaches": [
        {"Name": "ExampleBreach", "BreachDate": "2021-03-01", "DataClasses": ["Email addresses", "Passwords"], "Password": "hunter2"},
        {"Name": "OtherBreach", "BreachDate": "2019-07-12", "DataClasses": ["Usernames"], "PasswordHash": "5f4dcc3b5aa765d61d8327deb882cf99"},
    ],
    "stealers": [
        {"date_compromised": "2024-01-02", "computer_name": "DESKTOP-ALICE", "ip": "198.51.100.77",
         "malware_path": "C:\\Users\\alice\\AppData\\x.exe", "top_passwords": ["p***2"], "stealer_family": "RedLine"}
    ],
    "total_corporate_services": 3,
}


@pytest.fixture()
def breach_provider():
    """A sensitive provider fragment with a schema for one source, registered programmatically."""
    providers = pytest.importorskip("v3lum.core.providers")
    state = providers.snapshot()
    providers.register({
        "schema": "v3lum.provider/1",
        "id": PID,
        "name": "Test breach provider",
        "operator": "Example operator (test)",
        "hosts": ["breach.example.test"],
        "hosts_from_settings": [],
        "internal": False,
        "tier": "trusted",
        "tier_rationale": "test fixture",
        "tier_reviewer": "tests",
        "tier_date": "2026-11-26",
        "flags": {"publishes_queries": False, "reuses_queries": False, "fetches_target": False, "sensitive": True},
        "personal_data_review": None,
        "reliability": {"grade": "B", "justification": "test fixture"},
        "http_profile": {},
        "quota": None,
        "error_markers": [],
        "keys": {},
        "sources": {
            "lookup": {
                "title": "Breach lookup (test)",
                "terms": {"class": "open", "evidence_url": "https://breach.example.test/terms", "quote": "test", "checked_at": "2026-11-26",
                          "reviewer": "tests", "free_plan_business_use": True},
                "upstream_family": "t_breachy",
                "sanitizer": {"keep": ["breaches[].Name", "breaches[].BreachDate", "breaches[].DataClasses", "total_corporate_services"]},
                "dataset": None,
                "notes": "",
            },
            "stealers": {
                "title": "Stealer lookup (test)",
                "terms": {"class": "open", "evidence_url": "https://breach.example.test/terms", "quote": "test", "checked_at": "2026-11-26",
                          "reviewer": "tests", "free_plan_business_use": True},
                "upstream_family": "t_breachy",
                "sanitizer": None,
                "dataset": None,
                "notes": "",
            },
        },
    }, origin="tests/test_sanitize_registry.py")
    yield f"{PID}.lookup"
    providers.restore(state)


@pytest.fixture()
def registered():
    names: list[str] = []

    def add(source_id, keep, notes=""):
        names.append(source_id)
        return register_schema(source_id, keep=keep, notes=notes)

    yield add
    for name in names:
        sanitize.unregister_schema(name)


class BreachModule:
    name = "t_breach_mod"
    category = "breach_leak"
    sources = (f"{PID}.lookup",)


class MalwareModule:
    name = "t_malware_mod"
    category = "malware_hash"
    sources = ()


# ------------------------------------------------------------------ registry
def test_schema_from_provider_fragment(breach_provider):
    schema = schema_for(breach_provider)
    assert isinstance(schema, SanitizerSchema)
    assert schema.keep == ("breaches[].Name", "breaches[].BreachDate", "breaches[].DataClasses", "total_corporate_services")
    assert schema_for(f"{PID}.stealers") is None  # null sanitizer in the fragment
    assert schema_for("nobody.nothing") is None and schema_for("") is None


def test_registered_schema_wins_over_fragment(breach_provider, registered):
    registered(breach_provider, ["total_corporate_services"], notes="module-level schema")
    assert schema_for(breach_provider).keep == ("total_corporate_services",)
    assert schema_for(breach_provider).notes == "module-level schema"


def test_register_schema_validation(registered):
    s = registered("t_src.a", ["x.y", "items[].name", "*.count"])
    assert registered("t_src.a", ["*.count", "x.y", "items[].name"]) is s  # same paths again: no-op
    with pytest.raises(ValueError):
        register_schema("t_src.a", keep=["other"])  # a different schema for the same source
    with pytest.raises(ValueError):
        register_schema("", keep=["x"])
    with pytest.raises(ValueError):
        register_schema("t_src.b", keep=[])
    with pytest.raises(ValueError):
        register_schema("t_src.c", keep=["a..b"])
    with pytest.raises(ValueError):
        register_schema("t_src.d", keep=["a[x]"])


# ------------------------------------------------------------------ allow-list paths
def test_apply_schema_lists_and_wildcards():
    schema = SanitizerSchema("s", ("breaches[].Name", "meta.*.count", "total"))
    obj = {
        "breaches": [{"Name": "A", "Password": "p"}, {"Name": "B", "Hash": "h"}],
        "meta": {"x": {"count": 1, "secret": 2}, "y": {"count": 3}},
        "total": 7,
        "email": "alice@corp.example",
    }
    kept, dropped = apply_schema(obj, schema)
    assert kept == {"breaches": [{"Name": "A"}, {"Name": "B"}], "meta": {"x": {"count": 1}, "y": {"count": 3}}, "total": 7}
    assert dropped == ["breaches[].Hash", "breaches[].Password", "email", "meta.x.secret"]
    assert obj["breaches"][0]["Password"] == "p"  # the input is not modified


def test_apply_schema_nested_lists():
    kept, dropped = apply_schema({"rows": [[{"a": 1, "b": 2}], [{"a": 3}]]}, SanitizerSchema("s", ("rows[][].a",)))
    assert kept == {"rows": [[{"a": 1}], [{"a": 3}]]} and dropped == ["rows[][].b"]
    assert register_schema("t_src.nested", keep=["rows[][].a"]).keep == ("rows[][].a",)
    sanitize.unregister_schema("t_src.nested")


def test_apply_schema_top_level_list_and_whole_subtrees():
    kept, dropped = apply_schema([{"a": 1, "b": 2}, {"a": 3}], SanitizerSchema("s", ("[].a",)))
    assert kept == [{"a": 1}, {"a": 3}] and dropped == ["[].b"]
    kept, dropped = apply_schema({"stats": {"x": 1, "y": [1, 2]}, "z": 0}, SanitizerSchema("s", ("stats",)))
    assert kept == {"stats": {"x": 1, "y": [1, 2]}} and dropped == ["z"]
    kept, dropped = apply_schema("raw text body", SanitizerSchema("s", ("a",)))
    assert kept is None and dropped == ["$"]


# ------------------------------------------------------------------ cache hook
def test_sanitize_body_json_vs_html(breach_provider):
    body = json.dumps(BREACH_BODY).encode()
    clean = sanitize_body(breach_provider, body, "application/json; charset=utf-8")
    data = json.loads(clean)
    assert data == {
        "breaches": [
            {"Name": "ExampleBreach", "BreachDate": "2021-03-01", "DataClasses": ["Email addresses", "Passwords"]},
            {"Name": "OtherBreach", "BreachDate": "2019-07-12", "DataClasses": ["Usernames"]},
        ],
        "total_corporate_services": 3,
    }
    for needle in (b"hunter2", b"5f4dcc3b", b"DESKTOP-ALICE", b"198.51.100.77", b"alice@corp.example"):
        assert needle not in clean
    assert sanitize_body(breach_provider, b"<html>hunter2</html>", "text/html") is None
    assert sanitize_body(breach_provider, b"{broken", "application/json") is None
    assert sanitize_body(f"{PID}.stealers", body, "application/json") is None  # no schema -> do not cache
    assert sanitize_body("nobody.nothing", body, "application/json") is None


# ------------------------------------------------------------------ value detectors
def test_mask_secret():
    raw = "sk_live_0123456789abcdef"
    m = mask_secret(raw, "stripe_key")
    assert m == {"type": "stripe_key", "preview": "sk_l…cdef", "sha256": hashlib.sha256(raw.encode()).hexdigest()}
    assert mask_secret("short123", "")["preview"] == "****" and mask_secret("short123")["type"] == "secret"
    assert mask_secret("exactly12chr")["preview"] == "exac…2chr"


@pytest.mark.parametrize(
    ("text", "expected"),
    [
        ("alice@corp.example:hunter2", "alice@corp.example"),
        ("dump line: alice@corp.example;S3cr3t! end", "dump line: alice@corp.example end"),
        ("bob@corp.example|p@ss:word", "bob@corp.example"),
        ("ftp://bob:secret@files.example.net/x", "ftp://files.example.net/x"),
        ("bob:secret@files.example.net", "files.example.net"),
        ("contacts: alice@corp.example, bob@corp.example", "contacts: alice@corp.example, bob@corp.example"),
        ("alice@corp.example|bob@corp.example", "alice@corp.example|bob@corp.example"),
        ("mailto:alice@corp.example", "mailto:alice@corp.example"),
        ("no credentials here", "no credentials here"),
    ],
)
def test_drop_combos_keeps_the_email(text, expected):
    assert drop_combos(text) == expected


@pytest.mark.parametrize(
    ("text", "secret", "expected"),
    [
        ("redis://:s3cr3tpw@cache.example.net:6379", "s3cr3tpw", "redis://cache.example.net:6379"),  # empty user
        ("postgres://dbuser:S3cret@db.example.net:5432/app", "S3cret", "postgres://db.example.net:5432/app"),  # port/path kept
        ("https://bob:pa@ss@host.example.com/x", "pa@ss", "https://host.example.com/x"),  # '@' inside the password
        ("bob:p@ss@host.example.com", "p@ss", "host.example.com"),
        ("user:hunter2@192.0.2.10", "hunter2", "192.0.2.10"),  # a label-like user before an IP is a credential
        ("admin:secret@localhost:8080", "secret", "localhost:8080"),
        ("ALICE@CORP.EXAMPLE|S3cr3tpw", "S3cr3tpw", "ALICE@CORP.EXAMPLE"),
    ],
)
def test_drop_combos_never_leaks_the_password(text, secret, expected):
    out = drop_combos(text)
    assert secret not in out and out == expected


@pytest.mark.parametrize(
    "text",
    [
        "https://user@example.com:8443/path",  # URL user without password: the IOC stays intact
        "http://www.paypal.com@evil.example/login",
        "ssh://git@github.com:22/org/repo",
        "git@github.com:org/repo.git",
        "alice@corp.example;bob@corp.example",
        "alice@corp.example: please confirm",
        "security:security@corp.example",
        "https://evil.example/login?user=alice@corp.example",
    ],
)
def test_drop_combos_leaves_non_combos_alone(text):
    assert drop_combos(text) == text


def test_drop_combos_stays_linear_on_hostile_text():
    """Every string of every result passes drop_combos (hostile pages included): no ReDoS."""
    import time

    hostile = [
        "a-" * 60000 + "://@",  # scheme-like run: an unbounded scheme pattern is quadratic (~10 s here)
        "x@" + "a-" * 60000 + "a:" + "p" * 50,  # hyphen run after '@' (same)
        "a:b@" * 60000,  # user:password-like run without a host
        "@" + "a" * 60000 + "." + "b" * 60000,
        "alice@corp.example:hunter2 " * 5000,
    ]
    start = time.perf_counter()
    for text in hostile:
        drop_combos(text)
    assert time.perf_counter() - start < 2.0


def test_second_net_field_names():
    for name in ("password", "Password", "passwordHash", "top_passwords", "top_logins", "computer_name", "malware_path",
                 "cookies", "session_token", "salt", "senha", "password_hint", "ip", "infected_ip", "combo_line", "hash",
                 "api_key", "apiKey", "client_secret", "Authorization", "private_key", "cvv"):
        assert sanitize.is_second_net_field(name), name
    for name in ("password_form", "date_compromised", "stealer_family", "total_corporate_services", "DataClasses", "Name", "breach_date"):
        assert not sanitize.is_second_net_field(name), name
    assert {"password", "hash", "salt", "top_passwords", "top_logins", "cookies", "computer_name", "malware_path"} <= SECOND_NET_FIELDS


# ------------------------------------------------------------------ the engine stage
def test_sanitize_result_sensitive_module(breach_provider):
    res = ModuleResult(module=BreachModule.name, entity=Entity.make("email", "alice@corp.example"))
    res.raw = json.loads(json.dumps(BREACH_BODY))
    res.attributes = {"breaches": ["ExampleBreach"], "top_passwords": ["p***2"], "password_form": "plaintext"}
    f = res.finding("In 2 breaches", "medium", criterion="breach index lists the address", data={"password": "hunter2", "names": ["ExampleBreach"]})
    out = sanitize_result(res, BreachModule)
    assert out is res
    assert res.raw == {
        "breaches": [
            {"Name": "ExampleBreach", "BreachDate": "2021-03-01", "DataClasses": ["Email addresses", "Passwords"]},
            {"Name": "OtherBreach", "BreachDate": "2019-07-12", "DataClasses": ["Usernames"]},
        ],
        "total_corporate_services": 3,
    }
    assert res.attributes == {"breaches": ["ExampleBreach"], "password_form": "plaintext"}
    assert f.data == {"names": ["ExampleBreach"]}
    assert "raw.breaches[].Password" in res.redacted_fields and "attributes.top_passwords" in res.redacted_fields
    assert "findings.data.password" in res.redacted_fields and "raw.stealers" in res.redacted_fields
    blob = json.dumps(res.to_dict()) + json.dumps(res.raw) + json.dumps([x.to_dict() for x in res.findings])
    for needle in ("hunter2", "5f4dcc3b", "DESKTOP-ALICE", "198.51.100.77", "x.exe", "p***2"):
        assert needle not in blob


def test_sensitive_module_without_schema_drops_raw():
    class NoSchema:
        name = "t_no_schema"
        category = "breach_leak"
        sources = ("nobody.nothing",)

    res = ModuleResult(module="t_no_schema", entity=Entity.make("email", "alice@corp.example"))
    res.raw = {"password": "hunter2", "Name": "x"}
    sanitize_result(res, NoSchema)
    assert res.raw is None and "raw" in res.redacted_fields


def test_malware_module_keeps_hash_fields():
    res = ModuleResult(module=MalwareModule.name, entity=Entity.make("sha256", "a" * 64))
    res.raw = {"sha256": "a" * 64, "md5": "b" * 32, "hash": "c" * 64, "signature": "RedLine"}
    res.attributes = {"malware_family": "RedLine"}
    sanitize_result(res, MalwareModule)
    assert res.raw == {"sha256": "a" * 64, "md5": "b" * 32, "hash": "c" * 64, "signature": "RedLine"}
    assert res.redacted_fields == []


def test_every_module_loses_combos():
    res = ModuleResult(module="t_paste", entity=Entity.make("text_blob", "pasted text"))
    res.raw = {"lines": ["alice@corp.example:hunter2", "note"], "nested": {"x": "bob:pw@files.example.net"}}
    res.attributes = {"names": ["alice@corp.example;hunter2"]}
    f = res.finding("combo alice@corp.example:hunter2 seen", "info", "line alice@corp.example:hunter2")
    res.pivot(T.URL, "https://bob:pw@files.example.net/a", "mentions", note="from alice@corp.example:hunter2")
    res.link("x", "https://user:pw@example.net/y")
    sanitize_result(res, MalwareModule)
    assert res.raw == {"lines": ["alice@corp.example", "note"], "nested": {"x": "files.example.net"}}
    assert res.attributes == {"names": ["alice@corp.example"]}
    assert "hunter2" not in f.title + f.description
    assert res.pivots[0].note == "from alice@corp.example" and "pw@" not in res.pivots[0].entity.value
    assert res.links == [("x", "https://example.net/y")]
    assert {"raw:combo", "attributes:combo", "findings:combo", "pivots:combo", "links:combo"} <= set(res.redacted_fields)


def test_combos_are_dropped_from_keys_errors_keys_and_any_pivot_type():
    res = ModuleResult(module="t_paste", entity=Entity.make("text_blob", "pasted text"))
    res.raw = {"by_line": {"alice@corp.example:hunter2": 1}}
    res.error = "parser choked on alice@corp.example:hunter2"
    res.source_statuses = {"t.feed": {"status": "error", "reason_code": "error", "reason": "bad line bob:pw123@files.example.net"}}
    f = res.finding("Same", "info", key="alice@corp.example:hunter2")
    res.pivots.append(Pivot(Entity(T.KEYWORD, "alice@corp.example:hunter2"), "mentions"))
    sanitize_result(res, MalwareModule)
    blob = json.dumps([res.raw, res.error, res.source_statuses, f.key, [p.entity.value for p in res.pivots]])
    assert "hunter2" not in blob and "pw123" not in blob
    assert res.raw == {"by_line": {"alice@corp.example": 1}} and f.key == "alice@corp.example"
    assert [p.entity for p in res.pivots] == [Entity.make(T.KEYWORD, "alice@corp.example")]
    assert {"raw:combo", "error:combo", "findings:combo", "pivots:combo"} <= set(res.redacted_fields)


def test_pivot_left_invalid_by_the_scrub_is_dropped():
    res = ModuleResult(module="t_paste", entity=Entity.make("text_blob", "pasted text"))
    res.pivots.append(Pivot(Entity(T.URL, "https://bob:pw@files.example.net/a"), "mentions"))
    res.pivots.append(Pivot(Entity(T.DOMAIN, "user:hunter2@192.0.2.10"), "mentions"))  # nonsense entity built directly
    sanitize_result(res, MalwareModule)
    assert [p.entity.value for p in res.pivots] == ["https://files.example.net/a"]


def test_sanitizer_error_on_internal_failure(monkeypatch):
    def boom(*a, **k):
        raise RuntimeError("bug")

    monkeypatch.setattr(sanitize, "_scrub_strings", boom)
    res = ModuleResult(module="t_any", entity=Entity.make("domain", "example.org"))
    with pytest.raises(SanitizerError):
        sanitize_result(res, MalwareModule)
