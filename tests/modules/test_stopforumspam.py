"""Offline tests of stopforumspam (P164) with the fixtures in tests/fixtures/stopforumspam/.

Provenance: ``ip_clean.json`` (1.1.1.1), ``ip_email_username.json``, ``emailhash_listed.json``,
``emailhash_unix.json`` and ``error_503.json`` are real keyless answers (live 2026-11-26, the echoed
documentation address test@example.com kept as published); ``*_docs.json`` come from the
StopForumSpam usage page; ``*_synthetic.json`` use the live shape with documentation values."""

from __future__ import annotations

from datetime import datetime, timezone
from pathlib import Path
from urllib.parse import parse_qs, urlsplit

import pytest

from tests.fakes import FakeHttp, module_fixture, run_module
from v3lum.core.context import ScanOptions
from v3lum.core.models import Opsec, Severity, Status
from v3lum.core.orgprofile import OrgProfile
from v3lum.core.providers import registry
from v3lum.modules.threat_intel_ioc import stopforumspam as mod
from v3lum.modules.threat_intel_ioc.stopforumspam import (
    StopForumSpam,
    email_hash,
    field_verdict,
    parse,
    query_url,
    request_allowed,
)

FIX = "stopforumspam"
FIXTURES = Path(__file__).resolve().parents[1] / "fixtures" / FIX
TEST_MD5 = "55502f40dc8b7c769880b10874abc9d0"  # md5("test@example.com")
NOW = datetime(2026, 11, 26, 12, 0, tzinfo=timezone.utc)


def body(name: str) -> bytes:
    return (FIXTURES / name).read_bytes()


def route(http: FakeHttp, field: str, value: str, *, name: str | None = None, raw: bytes | None = None, status: int = 200) -> FakeHttp:
    content = raw if raw is not None else body(name or "")
    return http.add("GET", query_url(field, value), status=status, body=content,
                    headers={"content-type": "application/json"} if content else {})


@pytest.fixture(autouse=True)
def doc_ips(monkeypatch):
    monkeypatch.setattr(mod, "public_ip", lambda value: not value.startswith(("10.", "192.168.")))


def run(entity: str, http: FakeHttp, **kw):
    return run_module(StopForumSpam, entity, http, **kw)


# --------------------------------------------------------------------------------------
# metadata, hashing and the request allow-list (c1, c2)
# --------------------------------------------------------------------------------------


def test_metadata_matches_the_council_decision():
    cls = StopForumSpam
    assert (cls.terms, cls.default_enabled, cls.disclosure, cls.requires_keys) == ("noncommercial", True, "third_party", ())
    assert cls.opsec is Opsec.PASSIVE and cls.provider == "stopforumspam" and cls.hosts == ("api.stopforumspam.org",)
    assert cls.max_requests == 1 and cls.cache_ttl == 86400 and "BotScout" not in cls.description
    prov = registry().get("stopforumspam")
    assert prov.tier == "community" and not any(k.provider == "stopforumspam" for k in registry().keys().values())
    src = registry().source("stopforumspam.api")
    assert src.terms.class_ == "noncommercial" and src.terms.free_plan_business_use is False
    assert registry().provider_for_host("api.stopforumspam.org").id == "stopforumspam"


def test_email_is_hashed_lower_cased_and_idna_normalised():
    assert email_hash("test@example.com") == TEST_MD5
    assert email_hash("  Test@EXAMPLE.com ") == TEST_MD5
    assert email_hash("user@bücher.example") == email_hash("user@xn--bcher-kva.example")
    for bad in ("", "no-at-sign", "a@b", "@example.com", None, 5, "a b@example.com"):
        assert email_hash(bad) is None, bad


def test_query_urls_and_the_allow_list():
    assert query_url("ip", "203.0.113.5") == "https://api.stopforumspam.org/api?ip=203.0.113.5&json"
    assert query_url("emailhash", TEST_MD5) == f"https://api.stopforumspam.org/api?emailhash={TEST_MD5}&json"
    assert parse_qs(urlsplit(query_url("username", "spam bot")).query)["username"] == ["spam bot"]
    for field, value in [("ip", "203.0.113.5"), ("ip", "2001:db8::1"), ("emailhash", TEST_MD5), ("username", "octocat")]:
        assert request_allowed("GET", query_url(field, value)), (field, value)
    with pytest.raises(ValueError):
        query_url("email", "test@example.com")
    with pytest.raises(ValueError):
        query_url("emailhash", "test@example.com")
    base = "https://api.stopforumspam.org/api"
    for method, url in [
        ("GET", f"{base}?email=test%40example.com&json"), ("GET", f"{base}?emailhash=test%40example.com&json"),
        ("POST", f"{base}?ip=203.0.113.5&json"), ("GET", f"{base}?ip=203.0.113.5"),
        ("GET", "https://www.stopforumspam.com/add.php?username=a&ip_addr=203.0.113.5&evidence=x&api_key=k"),
        ("GET", "https://api.stopforumspam.org/add?ip=203.0.113.5&json"), ("GET", f"{base}?ip=203.0.113.5&json&api_key=k"),
        ("GET", "http://api.stopforumspam.org/api?ip=203.0.113.5&json"), ("GET", "https://evil.example/api?ip=203.0.113.5&json"),
        ("GET", f"{base}?json"), ("GET", f"{base}?ip=203.0.113.5&json#x"),
    ]:
        assert not request_allowed(method, url), (method, url)


def test_the_plaintext_address_never_leaves_the_machine():
    http = route(FakeHttp(), "emailhash", TEST_MD5, name="emailhash_listed.json")
    res = run("email:test@example.com", http)
    assert res.status is Status.OK and len(http.calls) == 1
    sent = http.calls[0]["url"]
    assert "example.com" not in sent and "%40" not in sent and TEST_MD5 in sent
    assert all(request_allowed(c["method"], c["url"]) for c in http.calls)
    http.assert_hosts_within(StopForumSpam)


# --------------------------------------------------------------------------------------
# verdicts (c3, c4)
# --------------------------------------------------------------------------------------


def test_recent_confident_ip_report_is_low_and_never_consensus():
    http = route(FakeHttp(), "ip", "198.51.100.77", name="recent_listed_synthetic.json")
    res = run("ipv4:198.51.100.77", http)
    finding = res.findings[0]
    assert finding.title == "Reported forum spammer (StopForumSpam)" and finding.severity is Severity.LOW and finding.tags == ["spam"]
    assert "reported as forum spammer 12 times, last 2026-11-20" in finding.description
    assert finding.data["counts_in_consensus"] is False and "malicious" not in finding.tags
    assert res.attributes["asn"] == "AS64496" and res.attributes["country"] == "BR"
    assert ("StopForumSpam IP check", "https://www.stopforumspam.com/ipcheck/198.51.100.77") in res.links
    http.assert_hosts_within(StopForumSpam)


def test_low_confidence_email_report_is_info():
    http = route(FakeHttp(), "emailhash", TEST_MD5, name="emailhash_listed.json")
    finding = run("email:test@example.com", http).findings[0]
    assert finding.severity is Severity.INFO and finding.tags == ["spam", "info"] and "confidence 1.26 < 25" in finding.description


def test_epoch_lastseen_is_parsed_like_the_text_form():
    entry = parse(module_fixture(FIX, "emailhash_unix.json"))["fields"]["emailhash"]
    text = parse(module_fixture(FIX, "emailhash_listed.json"))["fields"]["emailhash"]
    assert entry["lastseen"] == "2026-10-31T11:47:01Z" == text["lastseen"]


def test_frequency_255_is_a_list_rule_never_255_reports():
    http = route(FakeHttp(), "emailhash", TEST_MD5, name="wildcard_255_docs.json")
    finding = run("email:test@example.com", http).findings[0]
    assert finding.severity is Severity.INFO and "list rule" in finding.description and "255 times" not in finding.description
    assert finding.data["wildcard"] is True


def test_tor_exit_is_context_and_old_reports_are_info():
    http = route(FakeHttp(), "ip", "203.0.113.9", name="torexit_docs.json")
    res = run("ipv4:203.0.113.9", http)
    assert res.attributes["is_tor_exit"] is True
    finding = res.findings[0]
    assert finding.severity is Severity.INFO and "older than 90 days" in finding.description


def test_not_listed_is_empty_never_clean():
    http = route(FakeHttp(), "ip", "1.1.1.1", name="ip_clean.json")
    res = run("ipv4:1.1.1.1", http)
    assert res.status is Status.EMPTY and not res.findings and res.attributes["stopforumspam"]["ip"]["appears"] is False


def test_shared_cloud_ranges_are_info_only(monkeypatch):
    monkeypatch.setattr(mod.noise, "noise_kind", lambda entity: "cloud")
    http = route(FakeHttp(), "ip", "198.51.100.77", name="recent_listed_synthetic.json")
    finding = run("ipv4:198.51.100.77", http).findings[0]
    assert finding.severity is Severity.INFO and "shared cloud address range" in finding.description


def test_field_verdict_thresholds():
    entry = {"appears": True, "frequency": 12, "lastseen": "2026-11-20T10:00:00Z", "confidence": 87.5, "wildcard": False}
    assert field_verdict(entry, "ip", NOW)["severity"] == "low"
    assert field_verdict({**entry, "frequency": 2}, "ip", NOW)["severity"] == "info"
    assert field_verdict({**entry, "confidence": 24.9}, "ip", NOW)["severity"] == "info"
    assert field_verdict({**entry, "lastseen": "2026-08-01T00:00:00Z"}, "ip", NOW)["severity"] == "info"
    assert field_verdict({**entry, "lastseen": None}, "ip", NOW)["severity"] == "info"


# --------------------------------------------------------------------------------------
# what is never sent (c1, c4)
# --------------------------------------------------------------------------------------


def test_org_profile_addresses_are_never_sent():
    org = OrgProfile.from_dict({"domains": [{"name": "example.com", "verification": "confirmed"}]})
    http = FakeHttp()
    res = run("email:test@example.com", http, org_profile=org)
    assert res.status is Status.SKIPPED and res.reason_code == "own_asset" and not http.calls


def test_usernames_only_in_registration_abuse_cases():
    http = FakeHttp()
    res = run("username:octocat", http)
    assert res.status is Status.SKIPPED and res.reason_code == "not_applicable" and not http.calls
    http2 = route(FakeHttp(), "username", "octocat", name="ip_email_username.json")
    assert run("username:octocat", http2, settings={"stopforumspam_usernames": True}).status is Status.EMPTY
    http3 = route(FakeHttp(), "username", "octocat", name="ip_email_username.json")
    res3 = run("username:octocat", http3, options=ScanOptions(purpose="fake account registration abuse on our portal"))
    assert res3.status is Status.EMPTY and len(http3.calls) == 1


def test_private_addresses_are_never_sent():
    http = FakeHttp()
    res = run("ipv4:10.1.2.3", http)
    assert res.status is not Status.OK and not http.calls


# --------------------------------------------------------------------------------------
# statuses (c3, rule 5)
# --------------------------------------------------------------------------------------


def test_success_0_and_per_field_errors_are_could_not_verify():
    http = route(FakeHttp(), "ip", "203.0.113.10", name="error_in_200_docs.json")
    assert run("ipv4:203.0.113.10", http).status is Status.ERROR
    http2 = route(FakeHttp(), "ip", "203.0.113.11", name="field_error_in_200.json")
    res2 = run("ipv4:203.0.113.11", http2)
    assert res2.status is Status.ERROR and "invalid ip address" in res2.error
    http3 = route(FakeHttp(), "ip", "203.0.113.12", name="error_503.json", status=503)
    assert run("ipv4:203.0.113.12", http3).status is Status.ERROR


@pytest.mark.parametrize(("raw", "status", "expected"), [
    (None, 503, Status.RATE_LIMITED),
    (b"", 503, Status.RATE_LIMITED),
    (b"", 429, Status.RATE_LIMITED),
    (b"down", 500, Status.ERROR),
    (b'{"success":1,"ip":{"appears":1', 200, Status.ERROR),
    (b"<html><body>maintenance</body></html>", 200, Status.ERROR),
    (b"[]", 200, Status.ERROR),
    (b'{"success":1}', 200, Status.ERROR),
])
def test_http_statuses_and_unusable_bodies(raw, status, expected):
    content = body("rate_limited_503_synthetic.json") if raw is None else raw
    http = route(FakeHttp(), "ip", "203.0.113.20", raw=content, status=status)
    res = run("ipv4:203.0.113.20", http)
    assert res.status is expected, (res.status, res.error)
    assert not res.findings


def test_rate_words_inside_a_200_body_are_rate_limited():
    http = route(FakeHttp(), "ip", "203.0.113.21", name="rate_limited_503_synthetic.json", status=200)
    assert run("ipv4:203.0.113.21", http).status is Status.RATE_LIMITED


def test_challenge_page_is_blocked():
    page = "<!DOCTYPE html><html><head><title>Just a moment...</title></head><body>cf-chl-widget</body></html>"
    http = FakeHttp().add("GET", query_url("ip", "203.0.113.22"), status=403, text=page)
    assert run("ipv4:203.0.113.22", http).status is Status.BLOCKED


def test_fixture_shapes_are_documented():
    assert module_fixture(FIX, "wildcard_255_docs.json")["email"]["frequency"] == 255
