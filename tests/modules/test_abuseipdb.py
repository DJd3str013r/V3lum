"""Offline tests of abuseipdb (P157) with the fixtures in tests/fixtures/abuseipdb/.

Provenance: ``needs_key_401.json`` is the real keyless answer (research 2026-11-25); ``*_docs.json`` are
the API documentation examples (docs.abuseipdb.com, fetched 2026-11-26; addresses moved to
documentation ranges, the report comment replaced by a marker); ``*_synthetic.json`` are documented
field shapes with documentation values, until the team key exists (P157 c5, backlog)."""

from __future__ import annotations

import json

import pytest

from tests.fakes import FakeHttp, assert_no_secret, module_fixture, run_module
from v3lum.core.context import ModuleState
from v3lum.core.models import Severity, Status
from v3lum.core.providers import registry
from v3lum.modules.threat_intel_ioc import abuseipdb as mod
from v3lum.modules.threat_intel_ioc.abuseipdb import AbuseIPDB, check_block_url, check_url, request_allowed, verdict

FIX = "abuseipdb"
KEY_VALUE = "abuseipdb-test-key-0123456789abcdef0123456789"
KEYS = {"abuseipdb": KEY_VALUE}


def body(name: str) -> bytes:
    return json.dumps(module_fixture(FIX, name)).encode()


def route(ip: str, name: str | None = None, *, status: int = 200, raw: bytes | None = None, http: FakeHttp | None = None) -> FakeHttp:
    http = http or FakeHttp()
    content = raw if raw is not None else body(name or "")
    return http.add("GET", check_url(ip), status=status, body=content, headers={"content-type": "application/json"},
                    match_headers={"key": KEY_VALUE})


@pytest.fixture(autouse=True)
def doc_ips(monkeypatch):
    """The documented shapes use documentation addresses: let the module treat them as public."""
    monkeypatch.setattr(mod, "public_ip", lambda value: True)


def run(ip: str, http: FakeHttp, **kw):
    return run_module(AbuseIPDB, f"{'ipv6' if ':' in ip else 'ipv4'}:{ip}", http, keys=KEYS, **kw)


def assert_read_only(http: FakeHttp) -> None:
    """c1: every request the module built is an allow-listed GET; never verbose, report or clear."""
    for call in http.calls:
        assert request_allowed(call["method"], call["url"]), call["url"]
        assert "verbose" not in call["url"] and "/report" not in call["url"] and "clear-address" not in call["url"]


# --------------------------------------------------------------------------------------
# metadata and read-only construction (c1-c3)
# --------------------------------------------------------------------------------------


def test_metadata_matches_the_council_decision():
    cls = AbuseIPDB
    assert (cls.terms, cls.default_enabled, cls.trust_tier, cls.disclosure) == ("key-terms", True, "trusted", "third_party")
    assert cls.requires_keys == ("abuseipdb",) and cls.hosts == ("api.abuseipdb.com",) and cls.sources == ("abuseipdb.check",)
    assert cls.manual_link == "threat_intel_g07_p2:abuseipdb_check_ip" and cls.cache_ttl == 86400
    prov = registry().get("abuseipdb")
    assert prov.tier == "trusted" and prov.quota.day == 1000 and prov.quota.scope == "key"
    assert registry().source("abuseipdb.check").terms.free_plan_business_use is False
    assert "V3LUM_ABUSEIPDB_KEY" in registry().keys()["abuseipdb"].env


def test_allow_list_never_builds_report_bulk_report_or_clear_address():
    assert request_allowed("GET", check_url("198.51.100.23"))
    assert request_allowed("GET", check_block_url("198.51.100.0/24", 30))
    assert "maxAgeInDays=90" in check_url("198.51.100.23") and "verbose" not in check_url("198.51.100.23")
    for method, url in [
        ("POST", "https://api.abuseipdb.com/api/v2/report"),
        ("POST", "https://api.abuseipdb.com/api/v2/bulk-report"),
        ("DELETE", "https://api.abuseipdb.com/api/v2/clear-address?ipAddress=198.51.100.23"),
        ("GET", "https://api.abuseipdb.com/api/v2/reports?ipAddress=198.51.100.23"),
        ("GET", "https://api.abuseipdb.com/api/v2/blacklist"),
        ("GET", "https://api.abuseipdb.com/api/v2/check?ipAddress=198.51.100.23&maxAgeInDays=90&verbose"),
        ("GET", "https://api.abuseipdb.com/api/v2/check?ipAddress=198.51.100.23&key=x"),
        ("POST", "https://api.abuseipdb.com/api/v2/check?ipAddress=198.51.100.23"),
        ("GET", "http://api.abuseipdb.com/api/v2/check?ipAddress=198.51.100.23"),
        ("GET", "https://www.abuseipdb.com/check/198.51.100.23"),
    ]:
        assert not request_allowed(method, url), (method, url)


# --------------------------------------------------------------------------------------
# mapping (c4, c5)
# --------------------------------------------------------------------------------------


def test_many_reporters_and_high_score_is_malicious_medium():
    ip = "198.51.100.23"
    http = route(ip, "ok_malicious_synthetic.json")
    res = run(ip, http)
    assert res.status is Status.OK
    [f] = res.findings
    assert f.title == "Malicious IP (AbuseIPDB)" and f.severity is Severity.MEDIUM and f.tags == ["malicious"]
    assert f.data["distinct_reporters"] == 287 and f.data["usage_type"] == "Data Center/Web Hosting/Transit"
    assert f.data["isp"] == "Example Hosting B.V." and f.data["last_reported_at"] == "2026-11-25T21:14:02Z"
    assert f.data["high_eligible"] is True  # HIGH itself only through the P171 consensus
    assert str(f.observed_last).startswith("2026-11-25") and f.criterion and f.source == "abuseipdb.check"
    assert res.attributes["reputation"] == {"abuseipdb": 100} and res.attributes["isp"] == "Example Hosting B.V."
    assert res.attributes["export_restriction"]["redistributable"] is False
    assert ("AbuseIPDB check page", f"https://www.abuseipdb.com/check/{ip}") in res.links
    assert http.calls[0]["headers"]["Key"] == KEY_VALUE
    assert_read_only(http)
    assert_no_secret(KEY_VALUE, res.to_dict())
    http.assert_hosts_within(AbuseIPDB)


def test_one_reporter_is_suspicious_low():
    ip = "203.0.113.45"
    res = run(ip, route(ip, "ok_single_reporter_docs.json"))
    [f] = res.findings
    assert f.title == "Suspicious IP (AbuseIPDB)" and f.severity is Severity.LOW and f.tags == ["suspicious"]


def test_mobile_isp_is_capped_low_and_never_votes():
    ip = "203.0.113.200"
    res = run(ip, route(ip, "ok_mobile_isp_synthetic.json"))
    [f] = res.findings
    assert f.severity is Severity.LOW and "malicious" not in f.tags
    assert "CGNAT" in f.description


def test_whitelisted_cdn_is_dampened_to_info():
    ip = "192.0.2.53"
    res = run(ip, route(ip, "ok_whitelisted_cdn_synthetic.json"))
    [f] = res.findings
    assert f.severity is Severity.INFO and "suspicious" not in f.tags
    assert res.attributes["allowlisted"] == ["AbuseIPDB isWhitelisted", "AbuseIPDB usageType Content Delivery Network"]
    assert res.attributes["is_cdn"] is True


def test_unreported_ip_is_empty_and_a_low_score_is_an_attribute_only():
    res = run("2001:db8::25", route("2001:db8::25", "empty_unreported_synthetic.json"))
    assert res.status is Status.EMPTY and not res.findings
    doc = module_fixture(FIX, "ok_malicious_synthetic.json")
    doc["data"].update(abuseConfidenceScore=12, numDistinctUsers=2, totalReports=3)
    ip = "198.51.100.24"
    res2 = run(ip, route(ip, raw=json.dumps(doc).encode()))
    assert res2.status is Status.OK and not res2.findings and res2.attributes["abuseipdb"]["abuse_confidence_score"] == 12


def test_report_comments_are_never_kept_even_when_a_body_carries_them():
    ip = "203.0.113.45"
    res = run(ip, route(ip, "verbose_reports_docs.json"))
    assert res.raw["reports_dropped"] is True
    assert_no_secret("REPORTER-FREE-TEXT", res.to_dict())
    assert "reporterId" not in json.dumps(res.to_dict())


def test_verdict_bands():
    from datetime import datetime, timezone

    now = datetime(2026, 11, 26, tzinfo=timezone.utc)
    base = {"distinct_users": 5, "last_reported_at": "2026-10-01T00:00:00Z", "usage_type": "Fixed Line ISP", "is_whitelisted": False}
    old = verdict({**base, "score": 90}, now)
    assert old["band"] == "malicious" and old["high_eligible"] is False  # last report > 30 days
    assert verdict({**base, "score": 50}, now)["severity"] == "low"
    assert verdict({**base, "score": 10}, now)["band"] == "info"
    assert verdict({**base, "score": 90, "usage_type": "Search Engine Spider"}, now)["severity"] == "low"


# --------------------------------------------------------------------------------------
# statuses (c3): rule 5 everywhere
# --------------------------------------------------------------------------------------


def test_401_is_needs_key():
    ip = "198.51.100.23"
    res = run(ip, route(ip, "needs_key_401.json", status=401))
    assert res.status is Status.NEEDS_KEY


def test_daily_limit_429_is_quota_and_other_429_rate_limited():
    ip = "198.51.100.23"
    res = run(ip, route(ip, "quota_429_docs.json", status=429))
    assert res.status is Status.QUOTA and res.reason_code == "quota"
    ip2 = "198.51.100.25"
    res2 = run(ip2, route(ip2, raw=b'{"errors": [{"detail": "Too many requests", "status": 429}]}', status=429))
    assert res2.status is Status.RATE_LIMITED


def test_402_is_config_and_422_or_errors_in_200_are_errors():
    ip = "198.51.100.23"
    res = run(ip, route(ip, raw=b'{"errors": [{"detail": "Payment Required", "status": 402}]}', status=402))
    assert res.status is Status.SKIPPED and res.reason_code == "config"
    res2 = run(ip, route(ip, "invalid_422_docs.json", status=422))
    assert res2.status is Status.ERROR and "max age" in res2.error
    ip3 = "198.51.100.26"
    res3 = run(ip3, route(ip3, "invalid_422_docs.json", status=200))
    assert res3.status is Status.ERROR and "inside an HTTP 200" in res3.error


def test_malformed_5xx_timeout_and_challenge_are_could_not_verify():
    ip = "198.51.100.23"
    assert run(ip, route(ip, raw=b'{"data": {"abuseConfidenceScore": ')).status is Status.ERROR
    assert run(ip, route(ip, raw=b'{"data": []}')).status is Status.ERROR
    assert run(ip, route(ip, raw=b"oops", status=502)).status is Status.ERROR
    http = FakeHttp().add("GET", check_url(ip), error=TimeoutError("read timed out"))
    assert run(ip, http).status is Status.ERROR
    page = "<html><head><title>Just a moment...</title></head><body>cf-chl-widget</body></html>"
    http2 = FakeHttp().add("GET", check_url(ip), status=403, text=page)
    assert run(ip, http2).status is Status.BLOCKED


def test_private_addresses_are_never_sent(monkeypatch):
    monkeypatch.setattr(mod, "public_ip", lambda value: mod.noise.is_public_ip(value))
    res = run_module(AbuseIPDB, "ipv4:10.1.2.3", FakeHttp(), keys=KEYS)
    assert res.status is Status.SKIPPED


def test_without_a_key_nothing_is_sent():
    assert run_module(AbuseIPDB, "ipv4:198.51.100.23", FakeHttp()).status is Status.NEEDS_KEY


# --------------------------------------------------------------------------------------
# check-block (c1, c3)
# --------------------------------------------------------------------------------------


def test_check_block_for_a_24_with_the_plan_age_cap():
    http = FakeHttp().add("GET", check_block_url("198.51.100.0/24", 30), body=body("check_block_docs.json"),
                          headers={"content-type": "application/json"})
    res = run_module(AbuseIPDB, "cidr:198.51.100.0/24", http, keys=KEYS)
    assert res.status is Status.OK
    [f] = res.findings
    assert f.severity is Severity.LOW and f.data["max_score"] == 88 and f.data["max_age_days"] == 30
    assert res.attributes["abuseipdb_block"]["reported"][0]["ip"] == "198.51.100.1"
    assert_read_only(http)


def test_ranges_larger_than_24_and_single_hosts():
    res = run_module(AbuseIPDB, "cidr:198.51.0.0/16", FakeHttp(), keys=KEYS)
    assert res.status is Status.SKIPPED and "<= /24" in res.error
    ip = "198.51.100.23"
    res2 = run_module(AbuseIPDB, f"cidr:{ip}/32", route(ip, "ok_malicious_synthetic.json"), keys=KEYS)
    assert res2.status is Status.OK and res2.findings[0].title == "Malicious IP (AbuseIPDB)"


def test_check_block_daily_budget_is_counted():
    ModuleState("abuseipdb").set("check_block", {"day": "2026-11-26", "used": 80})  # standard plan: 100 x 80%
    res = run_module(AbuseIPDB, "cidr:198.51.100.0/24", FakeHttp(), keys=KEYS)
    assert res.status is Status.QUOTA and "check-block budget" in res.error
    basic = run_module(AbuseIPDB, "cidr:198.51.100.0/24",
                       FakeHttp().add("GET", check_block_url("198.51.100.0/24", 60), body=body("check_block_docs.json")),
                       keys=KEYS, settings={"abuseipdb_plan": "basic"})
    assert basic.status is Status.OK


# --------------------------------------------------------------------------------------
# licence (c2): the policy gate reads the key plan
# --------------------------------------------------------------------------------------


def test_licence_gate_needs_a_basic_or_higher_plan_under_corporate():
    from tests.fakes import make_runtime
    from v3lum.core import module as module_mod
    from v3lum.core import policy
    from v3lum.core.context import RunInfo, ScanOptions
    from v3lum.core.entities import Entity
    from v3lum.core.entities import EntityType as T

    module_mod.load_modules()
    ip = Entity.make(T.IPV4, "203.0.113.5")
    free = policy.make_context(make_runtime(keys=KEYS), ScanOptions(), path="scan")
    decision = policy.decide(AbuseIPDB, ip, free, run=RunInfo(entity=ip, is_seed=True))
    assert (decision.allowed, decision.reason_code) == (False, "licence") and decision.emit_manual_link
    business = policy.make_context(make_runtime(keys=KEYS, settings={"key_plans": {"abuseipdb": "business"}}), ScanOptions(), path="scan")
    assert policy.decide(AbuseIPDB, ip, business, run=RunInfo(entity=ip, is_seed=True)).allowed
