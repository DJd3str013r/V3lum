"""Offline tests of leakix (P274). The 401 'Invalid API key' answers are recorded (research 2026-11-25);
the success shapes are synthetic (vendor docs + l9format, documentation values; CANARY-* strings mark the
content the P274 cond 2 allowlist must drop; files in tests/fixtures/leakix/): no team key exists yet, see docs/backlog/p2-G02-3.md (c7)."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from tests.fakes import DeadHttp, FakeHttp, assert_no_secret, make_runtime, module_fixture, run_module
from v3lum.core.entities import EntityType
from v3lum.core.evidence import EvidenceStore
from v3lum.core.models import Severity, Status
from v3lum.core.orgprofile import OrgProfile
from v3lum.core.sanitize import schema_for
from v3lum.modules.pentest_recon import leakix as mod
from v3lum.modules.pentest_recon.leakix import (
    Leakix,
    allowlist_event,
    event_path,
    exposure_kind,
    parse_events,
    parse_go_duration,
    parse_subdomains,
)

KEY = {"leakix": "lkx-test-key-0123456789abcdef"}
HOST = "https://leakix.net/host/{ip}"
DOMAIN = "https://leakix.net/domain/{domain}"
SUBS = "https://leakix.net/api/subdomains/{domain}"
SEARCH = "https://leakix.net/search?scope=leak&q={q}&page=0"
JSON = {"content-type": "application/json"}
OWN = OrgProfile.from_dict({"domains": [{"name": "example.com", "verification": "attested", "attested_by": "SOC (test)", "attested_date": "2026-11-26"}]})
CANARIES = (
    "CANARY-SUMMARY", "CANARY-LEAKED-ROW", "CANARY-PASSWORD", "CANARY-USER", "CANARY-KEY", "CANARY-RAW", "CANARY-RANSOM",
    "CANARY-COOKIE", "CANARY-QUERY-TOKEN", "CANARY-FRAGMENT", "CANARY-ENV-SECRET", "CANARY-SSH-BANNER", "CANARY-MOTD",
    "CANARYFINGERPRINT",
)


def raw(name: str) -> bytes:
    data = module_fixture(Leakix, name)
    return json.dumps(data).encode() if name.endswith(".json") else str(data).encode()


@pytest.fixture
def doc_ips(monkeypatch):
    """Synthetic shapes use documentation addresses: let applies() accept them in tests."""
    monkeypatch.setattr(mod, "is_public_ip", lambda value: True)


def host_http(ip: str = "192.0.2.10", name: str = "host_ok_synthetic.json") -> FakeHttp:
    return FakeHttp().add("GET", HOST.format(ip=ip), body=raw(name), headers=JSON, match_headers={"api-key": KEY["leakix"], "Accept": "application/json"})


# --------------------------------------------------------------------------------------
# metadata, schema and parsers (P274 c1-c3)
# --------------------------------------------------------------------------------------


def test_metadata_matches_the_council_decision():
    cls = Leakix
    assert (cls.terms, cls.default_enabled, cls.trust_tier, cls.disclosure, cls.shares_input) == ("key-terms", True, "community", "third_party", True)
    assert cls.requires_keys == ("leakix",) and cls.sensitive is True and cls.hosts == ("leakix.net",) and cls.sources == ("leakix.api",)
    assert set(cls.accepts) == {EntityType.IPV4, EntityType.DOMAIN, EntityType.KEYWORD} and cls.produces == frozenset({EntityType.DOMAIN})
    schema = schema_for("leakix.api")
    assert schema is not None and "Leaks[].leak.severity" in schema.keep
    assert not [p for p in schema.keep if any(w in p for w in ("summary", "dataset", "credentials", "header", "title", "banner"))]


def test_allowlist_keeps_metadata_only():
    event = module_fixture(Leakix, "host_ok_synthetic.json")["Leaks"][0]
    clean = allowlist_event(event)
    assert clean == {
        "event_type": "leak", "plugin": "ElasticSearchOpenPlugin", "host": "db.example.com", "port": 9200, "protocol": "elasticsearch",
        "path": "/_cat/indices", "leak_type": "placeholder_open_database", "severity": "high", "time": "2026-09-01T08:00:00Z",
    }
    assert "CANARY" not in json.dumps(clean)
    assert event_path("https://www.example.com/.env#CANARY-FRAGMENT") == "/.env" and event_path("") is None
    assert parse_go_duration("344.24ms") == 0.34424 and parse_go_duration("1m30s") == 90.0 and parse_go_duration("soon") is None
    assert exposure_kind(clean) == "database" and exposure_kind({"plugin": "GitConfigHttpPlugin", "path": "/.git/config"}) == "config"
    assert parse_events({"Services": None, "Leaks": None}) == ([], [], None)
    assert parse_events({"Services": "x"})[2] and parse_events({"unexpected": 1})[2] and parse_events("x")[2]
    subs, problem = parse_subdomains(module_fixture(Leakix, "subdomains_ok_synthetic.json"))
    assert problem is None and [s["subdomain"] for s in subs] == ["blog.example.com", "staging.example.com", "www.example.com"]


# --------------------------------------------------------------------------------------
# keys (P274 c1)
# --------------------------------------------------------------------------------------


def test_without_a_key_it_needs_one_and_sends_nothing():
    http = FakeHttp()
    res = run_module(Leakix, "domain:example.com", http)
    assert res.status is Status.NEEDS_KEY and not http.calls


@pytest.mark.parametrize(("url", "entity", "name"), [
    (HOST.format(ip="8.8.8.8"), "ipv4:8.8.8.8", "host_401_nokey.json"),
    (DOMAIN.format(domain="example.com"), "domain:example.com", "domain_401_nokey.json"),
])
def test_recorded_401_invalid_api_key_is_needs_key(url, entity, name):
    http = FakeHttp().add("GET", url, status=401, body=raw(name), headers=JSON)
    res = run_module(Leakix, entity, http, keys=KEY)
    assert res.status is Status.NEEDS_KEY and res.reason_code == "needs_key"
    assert_no_secret(KEY["leakix"], res.to_dict())


def test_invalid_key_string_in_a_200_is_needs_key():
    http = FakeHttp().add("GET", DOMAIN.format(domain="example.com"), status=200, body=raw("domain_401_nokey.json"), headers=JSON)
    assert run_module(Leakix, "domain:example.com", http, keys=KEY).status is Status.NEEDS_KEY


# --------------------------------------------------------------------------------------
# allowlist before evidence and cache (P274 c2-c3)
# --------------------------------------------------------------------------------------


def test_evidence_and_http_cache_hold_no_summary_or_leaked_content(doc_ips, tmp_path):
    http = host_http()
    rt = make_runtime(http, keys=KEY, cache=True)
    res = run_module(Leakix, "ipv4:192.0.2.10", runtime=rt)
    assert res.status is Status.OK
    path, _ = EvidenceStore(tmp_path / "case").save(res)
    path = Path(path)
    evidence = path.read_text(encoding="utf-8")
    fixture_text = json.dumps(module_fixture(Leakix, "host_ok_synthetic.json"))
    assert "CANARY-SUMMARY" in fixture_text and "CANARY-SUMMARY" not in evidence  # the cond 2 assertion
    for canary in CANARIES:
        assert canary not in evidence and canary not in json.dumps(res.to_dict(), default=str), canary
        assert_no_secret(canary, path)
    cache_file = Path(rt.http.cache.path)
    assert cache_file.exists()
    for canary in CANARIES:
        assert_no_secret(canary, cache_file)
    # an event URL kept with a fragment ('#CANARY-FRAGMENT') vetoes caching: the next run asks again
    again = run_module(Leakix, "ipv4:192.0.2.10", runtime=rt)
    assert again.status is Status.OK and len(http.calls) == 2


def test_allowlisted_answer_is_cached_sanitized_and_reused(doc_ips):
    doc = module_fixture(Leakix, "host_ok_synthetic.json")
    for event in doc["Leaks"]:
        event["http"]["url"] = event["http"].get("url", "").split("#")[0].split("?")[0]
    http = FakeHttp().add("GET", HOST.format(ip="192.0.2.10"), body=json.dumps(doc).encode(), headers=JSON)
    rt = make_runtime(http, keys=KEY, cache=True)
    first = run_module(Leakix, "ipv4:192.0.2.10", runtime=rt)
    again = run_module(Leakix, "ipv4:192.0.2.10", runtime=rt)
    assert first.status is again.status is Status.OK and len(http.calls) == 1  # served from the cache
    assert again.attributes["leakix_summary"] == first.attributes["leakix_summary"]
    cache_file = Path(rt.http.cache.path)
    for canary in CANARIES:
        assert_no_secret(canary, cache_file)
    # what the module keeps is the allowlist: no field outside it in the evidence payload
    kept_event_keys = {k for e in first.raw["leaks"] + first.raw["services"] for k in e}
    assert kept_event_keys <= {"event_type", "plugin", "host", "port", "protocol", "path", "leak_type", "severity", "time"}


# --------------------------------------------------------------------------------------
# seeds and own assets (P274 c4-c5)
# --------------------------------------------------------------------------------------


def test_host_seed_full_detail_capped_at_medium_with_historical_rule(doc_ips):
    http = host_http()
    res = run_module(Leakix, "ipv4:192.0.2.10", http, keys=KEY)
    assert res.status is Status.OK
    summary = res.attributes["leakix_summary"]
    assert (summary["detail"], summary["services"], summary["leaks"], summary["historical_leaks"]) == ("full", 2, 4, 1)
    assert summary["leaks_by_kind"] == {"database": 2, "config": 2}
    assert res.attributes["open_ports"] == [22, 443]
    titles = sorted((f.title, f.severity.label, "historical" in f.tags) for f in res.findings)
    assert titles == [
        ("Exposed configuration reported by LeakIX", "medium", False),
        ("Exposed configuration reported by LeakIX", "medium", True),
        ("Exposed database reported by LeakIX", "medium", False),
    ]
    stale = next(f for f in res.findings if "historical" in f.tags)
    assert stale.confidence_label.value == "possible" and "re-verify" in stale.criterion
    assert all(f.references and f.references[0].startswith("https://leakix.net/") for f in res.findings)
    http.assert_hosts_within(Leakix)


def test_own_asset_exposed_database_and_config_are_high(doc_ips):
    res = run_module(Leakix, "ipv4:192.0.2.10", host_http(), keys=KEY, org_profile=OWN)
    db = next(f for f in res.findings if f.title.startswith("Exposed database"))
    assert db.severity is Severity.HIGH and "org_profile own asset" in db.criterion
    assert {f.severity for f in res.findings if f.title.startswith("Exposed configuration")} == {Severity.HIGH}
    assert all(e["own_asset"] for e in res.attributes["leakix_exposures"])


def test_pivoted_third_party_asset_gets_counts_only(doc_ips):
    res = run_module(Leakix, "ipv4:192.0.2.10", host_http(), keys=KEY, is_seed=False, depth=1)
    assert res.attributes["leakix_summary"]["detail"] == "counts"
    assert "leakix_exposures" not in res.attributes and "leakix_services" not in res.attributes
    [finding] = res.findings
    assert finding.severity is Severity.INFO and "context_only" in finding.tags
    assert set(res.raw) == {"lookup", "detail", "counts"}


def test_domain_seed_with_subdomains(doc_ips):
    http = FakeHttp()
    http.add("GET", DOMAIN.format(domain="example.com"), body=raw("domain_ok_synthetic.json"), headers=JSON)
    http.add("GET", SUBS.format(domain="example.com"), body=raw("subdomains_ok_synthetic.json"), headers=JSON)
    res = run_module(Leakix, "domain:example.com", http, keys=KEY)
    assert res.status is Status.OK
    pivots = {p.entity.value: p for p in res.pivots}
    assert set(pivots) == {"www.example.com", "staging.example.com", "blog.example.com"}
    assert pivots["blog.example.com"].expand is False and pivots["www.example.com"].expand is True  # last seen 2025-05: historical
    assert res.attributes["subdomain_count"] == 3
    summary = res.attributes["leakix_summary"]
    assert summary["unattributed"] == 1  # the event without a hostname is never pinned on anyone
    on_cdn = [f for f in res.findings if f.entity is not None and f.entity.value == "cdn.example.com"]
    assert on_cdn and all(f.severity <= Severity.MEDIUM for f in res.findings)


def test_subdomain_list_failure_never_hides_the_domain_answer(doc_ips):
    http = FakeHttp()
    http.add("GET", DOMAIN.format(domain="example.com"), body=raw("domain_ok_synthetic.json"), headers=JSON)
    http.add("GET", SUBS.format(domain="example.com"), status=503, text="busy")
    res = run_module(Leakix, "domain:example.com", http, keys=KEY)
    assert res.status is Status.OK and "subdomain list: could not verify" in res.error and not res.pivots


# --------------------------------------------------------------------------------------
# CDN/shared IPs (P274 c6) and keyword search
# --------------------------------------------------------------------------------------


def test_shared_cdn_ip_hits_go_to_the_hostname_never_the_ip_owner():
    doc = module_fixture(Leakix, "host_ok_synthetic.json")
    http = FakeHttp().add("GET", HOST.format(ip="104.16.1.1"), body=json.dumps(doc).encode(), headers=JSON)
    third = run_module(Leakix, "ipv4:104.16.1.1", http, keys=KEY)
    summary = third.attributes["leakix_summary"]
    assert not third.findings and summary["unattributed"] == 1  # the ssh event has no hostname
    assert set(summary["third_party_counts"]) == {"www.example.com", "db.example.com"}
    assert "open_ports" not in third.attributes
    http2 = FakeHttp().add("GET", HOST.format(ip="104.16.1.1"), body=json.dumps(doc).encode(), headers=JSON)
    own = run_module(Leakix, "ipv4:104.16.1.1", http2, keys=KEY, org_profile=OWN)
    assert own.findings and all(f.entity is not None and f.entity.type is EntityType.DOMAIN for f in own.findings)
    assert {f.entity.value for f in own.findings} == {"db.example.com", "www.example.com"}
    assert {p.relation for p in own.pivots} == {"hosted_domain"}


def test_keyword_search_details_own_assets_only():
    events = module_fixture(Leakix, "host_ok_synthetic.json")["Leaks"]
    http = FakeHttp().add("GET", SEARCH.format(q="examplebrand"), body=json.dumps(events).encode(), headers=JSON)
    res = run_module(Leakix, "keyword:examplebrand", http, keys=KEY)
    assert not res.findings and res.attributes["leakix_summary"]["leaks"] == 4
    assert set(res.attributes["leakix_summary"]["third_party_counts"]) == {"db.example.com", "www.example.com"}
    http2 = FakeHttp().add("GET", SEARCH.format(q="examplebrand"), body=json.dumps(events).encode(), headers=JSON)
    own = run_module(Leakix, "keyword:examplebrand", http2, keys=KEY, org_profile=OWN)
    assert any(f.severity is Severity.HIGH for f in own.findings)


# --------------------------------------------------------------------------------------
# could not verify (rule 5)
# --------------------------------------------------------------------------------------


def test_empty_answer_is_empty(doc_ips):
    res = run_module(Leakix, "ipv4:192.0.2.10", host_http(name="host_empty_synthetic.json"), keys=KEY)
    assert res.status is Status.EMPTY and res.attributes["leakix_summary"]["leaks"] == 0


def test_429_with_x_limited_for_is_rate_limited(doc_ips):
    ex = module_fixture(Leakix, "rate_limited_429_synthetic.json")
    http = FakeHttp().add("GET", HOST.format(ip="192.0.2.10"), status=429, text="", headers=ex["headers"])
    res = run_module(Leakix, "ipv4:192.0.2.10", http, keys=KEY)
    assert res.status is Status.RATE_LIMITED and "0.344 s" in res.error


def test_login_wall_redirect_and_login_page_are_blocked():
    http = FakeHttp().add("GET", DOMAIN.format(domain="example.com"), status=302, redirect_to="https://leakix.net/auth/login")
    res = run_module(Leakix, "domain:example.com", http, keys=KEY)
    assert res.status is Status.BLOCKED and res.reason_code == "login_wall"
    http = FakeHttp().add("GET", DOMAIN.format(domain="example.com"), status=200, text=module_fixture(Leakix, "login_page_synthetic.html"))
    res = run_module(Leakix, "domain:example.com", http, keys=KEY)
    assert res.status is Status.BLOCKED and res.reason_code == "login_wall"


@pytest.mark.parametrize(("status", "content"), [
    (503, b"busy"),
    (404, b'{"error": "not found"}'),
    (200, b"{not json"),
    (200, b'{"error": "internal problem"}'),
    (200, b'["not", "events"]'),
    (200, b'{"message": "something went wrong"}'),
])
def test_errors_and_unexpected_answers_are_never_empty(status, content):
    http = FakeHttp().add("GET", DOMAIN.format(domain="example.com"), status=status, body=content, headers=JSON)
    res = run_module(Leakix, "domain:example.com", http, keys=KEY)
    assert res.status is Status.ERROR, (status, content, res.status, res.error)
    assert not res.findings and "leakix_summary" not in res.attributes


def test_dead_network_is_an_error():
    assert run_module(Leakix, "domain:example.com", DeadHttp(), keys=KEY).status is Status.ERROR
