"""Offline tests of emailrep (P089) with the fixtures in tests/fixtures/emailrep/.

The 401 (invalid key), 429 (anonymous API disabled) and HTML (no Accept header) answers are trimmed real
research captures; the success answers are documentation-shaped (no team key yet: P089 cond 6 keeps the
merge gate open until a trimmed real capture replaces them).
"""

from __future__ import annotations

import json

import pytest

from tests.fakes import FakeHttp, assert_no_secret, make_runtime, module_fixture, run_module
from v3lum import config
from v3lum.core.models import Status
from v3lum.core.tlp import TLP
from v3lum.modules.email import emailrep as mod
from v3lum.modules.email.emailrep import EmailRep, emailrep_headers, emailrep_url, parse_emailrep

KEY = "er-test-key-0123456789abcdef"  # fake key
KEYS = {"emailrep": KEY}
URL = "https://emailrep.io/user@example.com"


def fx(name: str):
    return module_fixture("emailrep", name)


def add(http: FakeHttp, url: str, envelope_or_body, **kw) -> FakeHttp:
    """Route one fixture: an envelope {status, headers, body} or a plain JSON body."""
    if isinstance(envelope_or_body, dict) and envelope_or_body.get("_envelope"):
        body = envelope_or_body["body"]
        extra = {"json": body} if isinstance(body, (dict, list)) else {"text": body}
        return http.add("GET", url, status=envelope_or_body["status"], headers=envelope_or_body.get("headers"), **extra, **kw)
    return http.add("GET", url, json=envelope_or_body, **kw)


def run(http: FakeHttp, value: str = "user@example.com", **kw):
    kw.setdefault("keys", KEYS)
    kw.setdefault("tlp", "green")
    return run_module(EmailRep, f"email:{value}", http, **kw)


# ------------------------------------------------------------------------------------------ metadata
def test_metadata_follows_the_council_decision():
    cls = EmailRep
    assert (cls.terms, cls.default_enabled, cls.run_on) == ("unknown", False, "seeds")  # cond 1, cond 2
    assert cls.trust_tier == "trusted" and cls.reuses_queries is True  # cond 2: fail closed
    assert cls.max_tlp == TLP.GREEN  # skipped at TLP:AMBER and above by the policy gate
    assert cls.requires_keys == ("emailrep",) and cls.hosts == ("emailrep.io",)
    assert cls.cache_ttl == 0 and cls.max_requests == 1
    assert "V3LUM_EMAILREP_KEY" in config.key_registry()["emailrep"].env


def test_only_the_address_url_and_the_key_headers_are_built():
    assert emailrep_url(" User@Example.COM ") == URL
    for bad in ("", "user", "a@b", "user@example.com/../x", "user@example.com?x=1", None):
        with pytest.raises(ValueError):
            emailrep_url(bad)
    assert emailrep_headers(" k ") == {"Key": "k", "Accept": "application/json"}
    with pytest.raises(ValueError):
        emailrep_headers("")


# ------------------------------------------------------------------------------------------ happy path
def test_kept_attributes_and_dropped_fields():
    http = add(FakeHttp(), URL, fx("ok.json"), match_headers={"Key": KEY, "Accept": "application/json"})
    res = run(http)
    assert res.status is Status.OK, res.error
    attrs = res.attributes
    assert attrs["reputation"] == {"emailrep": "high"} and attrs["suspicious"] is False
    assert attrs["first_seen"] == "2008-07-01" and attrs["last_seen"] == "2019-05-24"
    assert attrs["domain_age_days"] == 10289
    flags = attrs["emailrep_flags"]
    assert flags["leak_reported"] is True and flags["data_breach"] is True and flags["blacklisted"] is False
    assert set(flags) <= set(mod.KEPT_FLAGS.values())
    # cond 4: deliverability, accept-all and profiles never reach attributes, findings, raw or pivots
    dump = json.dumps({"a": attrs, "raw": res.raw, "f": [f.to_dict() for f in res.findings]})
    for dropped in ("deliverable", "accept_all", "valid_mx", "primary_mx", "free_provider"):
        assert f'"{dropped}"' not in json.dumps(attrs) and dropped in res.raw["dropped_fields"]
    for profile in ("twitter", "linkedin", "github"):
        assert profile not in dump
    assert not res.pivots
    titles = {f.title for f in res.findings}
    assert "EmailRep reports the address in breach or credential-leak data" in titles
    leak = next(f for f in res.findings if f.title.startswith("EmailRep reports"))
    assert "context_only" in leak.tags and leak.severity.name == "INFO"
    http.assert_hosts_within(EmailRep)


def test_suspicious_address_gets_a_flag_finding():
    body = fx("ok_suspicious.json")
    http = add(FakeHttp(), "https://emailrep.io/billing@example.net", body)
    res = run(http, "billing@example.net")
    assert res.status is Status.OK
    flagged = next(f for f in res.findings if f.title == "Address flagged by EmailRep")
    assert flagged.severity.name == "MEDIUM" and flagged.criterion and flagged.source == "emailrep.reputation"
    assert res.attributes["suspicious"] is True and "first_seen" not in res.attributes  # 'never' is no date
    assert res.attributes["domain_age_days"] == 3


def test_parser_ignores_wrong_types_and_drops_unknown_fields():
    parsed = parse_emailrep({"email": "user@example.com", "reputation": 7, "suspicious": "yes",
                             "details": {"blacklisted": "true", "first_seen": "13/45/2020", "days_since_domain_creation": -4,
                                         "profiles": ["twitter"], "deliverable": True}}, "user@example.com")
    assert parsed["reputation"] is None and parsed["suspicious"] is None and parsed["flags"] == {}
    assert parsed["first_seen"] is None and parsed["domain_age_days"] is None
    assert {"profiles", "deliverable"} <= set(parsed["dropped"])
    assert parse_emailrep(["not", "a", "result"]) is None and parse_emailrep({"status": "fail"}) is None


# ------------------------------------------------------------------------------------------ gates
def test_missing_key_is_needs_key_before_any_request():
    http = FakeHttp()
    res = run(http, keys={})
    assert res.status is Status.NEEDS_KEY and res.reason_code == "needs_key"
    assert http.calls == []


def test_pivots_and_amber_are_refused_before_any_request():
    http = FakeHttp()
    res = run(http, is_seed=False, depth=1, provenance=(("domain:example.com", "contact_email", "whois"),))
    assert res.status is Status.SKIPPED and res.reason_code == "privacy"
    for tlp in ("amber", "amber+strict", "red"):
        res = run(http, tlp=tlp)
        assert res.status is Status.SKIPPED and res.reason_code in ("tlp", "privacy"), tlp
    assert http.calls == []


# ------------------------------------------------------------------------------------------ errors (rule 5)
def test_invalid_key_401_is_needs_key():
    http = add(FakeHttp(), URL, fx("needs_key_401.json"))
    res = run(http)
    assert res.status is Status.NEEDS_KEY and res.reason_code == "needs_key"


def test_anonymous_or_throttled_429_is_rate_limited():
    http = add(FakeHttp(), URL, fx("rate_limited_429.json"))
    res = run(http)
    assert res.status is Status.RATE_LIMITED and res.reason_code == "rate_limited"


def test_html_site_in_http_200_is_an_error_never_empty():
    page = (__import__("pathlib").Path(__file__).resolve().parents[1] / "fixtures/emailrep/error_in_200_html.html").read_text()
    http = FakeHttp().add("GET", URL, text=page, headers={"content-type": "text/html; charset=utf-8"})
    res = run(http)
    assert res.status is Status.ERROR and res.status is not Status.EMPTY


def test_fail_object_in_http_200_is_an_error():
    http = FakeHttp().add("GET", URL, json={"status": "fail", "reason": "invalid email"})
    assert run(http).status is Status.ERROR


def test_400_and_5xx_are_errors():
    http = add(FakeHttp(), URL, fx("invalid_email_400.json"))
    assert run(http).status is Status.ERROR
    http = FakeHttp().add("GET", URL, status=503, text="unavailable", times=2)
    res = run(http)
    assert res.status is Status.ERROR


def test_malformed_json_and_other_address_are_errors():
    text = (__import__("pathlib").Path(__file__).resolve().parents[1] / "fixtures/emailrep/malformed.txt").read_text()
    http = FakeHttp().add("GET", URL, text=text, headers={"content-type": "application/json"})
    assert run(http).status is Status.ERROR
    other = dict(fx("ok.json"), email="someone.else@example.org")
    http = FakeHttp().add("GET", URL, json=other)
    assert run(http).status is Status.ERROR


def test_answer_is_never_cached_and_the_key_never_leaks(tmp_path):
    rt = make_runtime(add(FakeHttp(), URL, fx("ok.json"), times=2), keys=KEYS, cache=True)
    res1 = run_module(EmailRep, "email:user@example.com", runtime=rt, tlp="green")
    res2 = run_module(EmailRep, "email:user@example.com", runtime=rt, tlp="green")
    assert res1.status is Status.OK and res2.status is Status.OK
    transport = rt.http.transport
    assert len(transport.calls) == 2  # cache_ttl 0: no-store (cond 4)
    assert_no_secret(KEY, res1.to_dict(), res2.to_dict())
