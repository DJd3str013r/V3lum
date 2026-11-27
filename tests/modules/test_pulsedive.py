"""Offline tests of pulsedive (P160) with the fixtures in tests/fixtures/pulsedive/.

Provenance: ``info_ip_feeds.json`` (1.1.1.1), ``info_domain_none.json`` (example.com),
``info_retired.json`` (registro.br) and ``info_ip_comments.json`` (8.8.8.8, one inert attacker probe
comment kept to prove comments are never copied; feed operator names scrubbed) are real keyless
answers (live 2026-11-26 / research 2026-11-25), minimised; ``bad_key_401.json`` is the research 401;
``*_docs.json`` come from docs.pulsedive.com; ``*_synthetic.json`` use the live shape with
documentation values until the team key exists (backlog)."""

from __future__ import annotations

from pathlib import Path

import pytest

from tests.fakes import FakeHttp, assert_no_secret, module_fixture, run_module
from v3lum.core.entities import EntityType as T
from v3lum.core.models import Opsec, Severity, Status
from v3lum.core.providers import registry
from v3lum.modules.threat_intel_ioc import pulsedive as mod
from v3lum.modules.threat_intel_ioc.pulsedive import Pulsedive, explore_url, info_url, request_allowed, vote_families

FIX = "pulsedive"
FIXTURES = Path(__file__).resolve().parents[1] / "fixtures" / FIX
KEY_VALUE = "pulsedive0123456789abcdef0123456789abcdef0123456789abcdef01234567"
KEYS = {"pulsedive": KEY_VALUE}


def body(name: str) -> bytes:
    return (FIXTURES / name).read_bytes()


def route(http: FakeHttp, indicator: str, *, name: str | None = None, raw: bytes | None = None, status: int = 200,
          headers: dict[str, str] | None = None) -> FakeHttp:
    content = raw if raw is not None else body(name or "")
    return http.add("GET", info_url(indicator, KEY_VALUE), status=status, body=content,
                    headers={"content-type": "application/json", **(headers or {})})


@pytest.fixture(autouse=True)
def doc_ips(monkeypatch):
    monkeypatch.setattr(mod, "public_ip", lambda value: True)


def run(entity: str, http: FakeHttp, **kw):
    return run_module(Pulsedive, entity, http, keys=KEYS, **kw)


# --------------------------------------------------------------------------------------
# metadata and the path allow-list (c1, c2)
# --------------------------------------------------------------------------------------


def test_metadata_matches_the_council_decision():
    cls = Pulsedive
    assert (cls.terms, cls.default_enabled, cls.trust_tier, cls.disclosure) == ("key-terms", True, "community", "third_party")
    assert cls.opsec is Opsec.PASSIVE and cls.requires_keys == ("pulsedive",) and cls.hosts == ("pulsedive.com",)
    assert cls.cache_ttl == 86400 and cls.max_requests == 1
    prov = registry().get("pulsedive")
    assert prov.tier == "community" and prov.quota.rate_per_second == 1
    src = registry().source("pulsedive.info")
    assert src.terms.class_ == "key-terms" and src.terms.free_plan_business_use is None
    assert {"abuse.ch", "openphish", "spamhaus"} <= set(src.embeds)
    assert {"PULSEDIVE_API_KEY", "V3LUM_PULSEDIVE_KEY"} <= set(registry().keys()["pulsedive"].env) | {"PULSEDIVE_API_KEY"}


def test_path_allow_list_never_builds_analyze_probe_scan_or_submit():
    assert request_allowed("GET", info_url("example.com"))
    assert request_allowed("GET", info_url("example.com", "k"))
    assert request_allowed("GET", explore_url("ioc=example.com", 5))
    base = "https://pulsedive.com/api"
    for method, url in [
        ("GET", f"{base}/analyze.php?value=example.com"), ("POST", f"{base}/analyze.php"), ("GET", f"{base}/analyze.php?qid=1"),
        ("POST", f"{base}/info.php?indicator=example.com"), ("GET", f"{base}/indicator.php?indicator=example.com"),
        ("GET", f"{base}/probe.php?indicator=example.com"), ("GET", f"{base}/scan.php?indicator=example.com"),
        ("GET", f"{base}/submit.php?indicator=example.com"), ("GET", f"{base}/threat.php?tid=1"), ("GET", f"{base}/feed.php?fid=1"),
        ("GET", f"{base}/info.php?iid=1&get=links"), ("GET", f"{base}/info.php?indicator=a&indicator=b"),
        ("GET", f"{base}/info.php?indicator=example.com&probe=1"), ("GET", f"{base}/info.php"),
        ("GET", "http://pulsedive.com/api/info.php?indicator=example.com"), ("GET", "https://evil.example/api/info.php?indicator=x"),
    ]:
        assert not request_allowed(method, url), (method, url)


def test_without_the_key_nothing_is_sent():
    http = FakeHttp()
    assert run_module(Pulsedive, "domain:example.com", http).status is Status.NEEDS_KEY and not http.calls


# --------------------------------------------------------------------------------------
# reports (c3, c4)
# --------------------------------------------------------------------------------------


def test_risk_none_is_no_finding_never_clean_and_keeps_feed_provenance():
    http = route(FakeHttp(), "1.1.1.1", name="info_ip_feeds.json")
    res = run("ipv4:1.1.1.1", http)
    assert res.status is Status.OK and not res.findings and not res.pivots
    facts = res.attributes["pulsedive"]
    assert facts["risk"] == "none" and {f["name"] for f in facts["feeds"]} == {"Bad IPs", "C&C IPs", "Example Mining IPs Feed"}
    assert facts["feed_families"] == ["pulsedive"]  # none of these feeds is consumed by V3LUM itself
    assert res.attributes["reputation"] == {"pulsedive": "none"} and res.attributes["asn"] == "AS13335"
    http.assert_hosts_within(Pulsedive)
    assert all(request_allowed(c["method"], c["url"]) for c in http.calls)
    assert_no_secret(KEY_VALUE, res.to_dict())


def test_threats_below_medium_are_never_pivoted():
    http = route(FakeHttp(), "example.com", name="info_domain_none.json")
    res = run("domain:example.com", http)
    assert res.status is Status.OK and not res.findings and not res.pivots
    assert "malware_family" not in res.attributes  # Emotet/TrickBot links at risk none are context only


def test_retired_indicator_is_info_only():
    http = route(FakeHttp(), "registro.br", name="info_retired.json")
    res = run("domain:registro.br", http)
    finding = res.findings[0]
    assert finding.title == "Retired Pulsedive indicator" and finding.severity is Severity.INFO
    assert "retired_indicator" in finding.tags and "malicious" not in finding.tags and not res.pivots


def test_high_risk_is_one_vote_per_upstream_family_with_listed_pivots():
    http = route(FakeHttp(), "203.0.113.50", name="info_high_synthetic.json")
    res = run("ipv4:203.0.113.50", http)
    finding = res.findings[0]
    assert finding.title == "Malicious per Pulsedive" and finding.severity is Severity.MEDIUM and "malicious" in finding.tags
    # Feodo Tracker relays abuse.ch (deduplicated against the local abuse.ch feeds by CR27); Bambenek is not consumed locally
    assert finding.data["upstream_families"] == ["abuse.ch", "pulsedive"]
    pivots = {(p.entity.type, p.entity.value, p.relation, p.expand) for p in res.pivots}
    assert (T.MALWARE, "Cobalt Strike", "family", False) in pivots and (T.THREAT_ACTOR, "Example Group", "attributed_to", False) in pivots
    assert res.attributes["threat_actors"] == ["Example Group"]


def test_medium_url_is_suspicious_and_pivots_to_its_host():
    url = "http://login.example.net/account/verify.php"
    http = route(FakeHttp(), url, name="info_url_medium_synthetic.json")
    res = run(f"url:{url}", http)
    finding = res.findings[0]
    assert finding.severity is Severity.LOW and finding.tags == ["suspicious"]
    assert finding.data["upstream_families"] == ["openphish", "pulsedive"]
    assert any(p.entity.value == "login.example.net" and p.relation == "url_host" and p.expand for p in res.pivots)


def test_comments_and_attacker_strings_are_never_copied():
    http = route(FakeHttp(), "8.8.8.8", name="info_ip_comments.json")
    res = run("ipv4:8.8.8.8", http)
    dumped = str(res.to_dict())
    assert "DBMS_PIPE" not in dumped and "comments" not in res.attributes["pulsedive"]


def test_vote_families_helper():
    assert vote_families({"feeds": [], "riskfactors": []}) == ["pulsedive"]
    assert vote_families({"feeds": [{"family": "abuse.ch"}], "riskfactors": [{"description": "found in threat feeds", "risk": "medium"}]}) == ["abuse.ch"]


# --------------------------------------------------------------------------------------
# statuses (c3, rule 5)
# --------------------------------------------------------------------------------------


def test_indicator_not_found_is_empty_never_clean():
    http = route(FakeHttp(), "unknown.example", name="not_found_404_docs.json", status=404)
    assert run("domain:unknown.example", http).status is Status.EMPTY
    http2 = route(FakeHttp(), "other.example", name="not_found_404_docs.json", status=200)
    assert run("domain:other.example", http2).status is Status.EMPTY


def test_invalid_key_is_needs_key():
    http = route(FakeHttp(), "example.org", name="bad_key_401.json", status=401)
    res = run("domain:example.org", http)
    assert res.status is Status.NEEDS_KEY
    assert_no_secret(KEY_VALUE, res.to_dict())


def test_rate_limit_and_daily_quota():
    http = route(FakeHttp(), "203.0.113.70", name="rate_limited_429_docs.json", status=429)
    assert run("ipv4:203.0.113.70", http).status is Status.RATE_LIMITED
    http2 = route(FakeHttp(), "203.0.113.71", name="rate_limited_429_docs.json", status=429,
                  headers={"x-requests-remaining-day": "0", "x-requests-remaining-second": "1"})
    res = run("ipv4:203.0.113.71", http2)
    assert res.status is Status.QUOTA and "daily" in res.error
    http3 = route(FakeHttp(), "203.0.113.72", raw=b'{"error":"API rate limit exceeded: 50 requests per day."}', status=429)
    assert run("ipv4:203.0.113.72", http3).status is Status.QUOTA


def test_errors_inside_200_and_unusable_bodies_are_could_not_verify():
    http = route(FakeHttp(), "203.0.113.73", name="error_in_200_synthetic.json")
    assert run("ipv4:203.0.113.73", http).status is Status.ERROR
    http2 = route(FakeHttp(), "203.0.113.74", name="malformed_truncated.json")
    assert run("ipv4:203.0.113.74", http2).status is Status.ERROR
    http3 = route(FakeHttp(), "203.0.113.75", raw=b'{"results": []}')
    assert run("ipv4:203.0.113.75", http3).status is Status.ERROR
    http4 = route(FakeHttp(), "203.0.113.76", raw=b"down", status=500)
    assert run("ipv4:203.0.113.76", http4).status is Status.ERROR
    page = "<!DOCTYPE html><html><head><title>Just a moment...</title></head><body>cf-chl-widget</body></html>"
    http5 = FakeHttp().add("GET", info_url("203.0.113.77", KEY_VALUE), status=403, text=page)
    assert run("ipv4:203.0.113.77", http5).status is Status.BLOCKED


def test_fixture_shapes_are_documented():
    assert module_fixture(FIX, "bad_key_401.json") == {"error": "Invalid API key."}
