"""Offline tests of greynoise_community (P148) with the recorded community fixtures in
tests/fixtures/greynoise_community/ (the 404 'not observed' answer for 8.8.8.8 and the two recorded 429
answers are real; the 200 shapes are synthetic: the keyless quota of the research egress was exhausted)."""

from __future__ import annotations

import json

import pytest

from tests.fakes import DeadHttp, FakeHttp, assert_no_secret, make_runtime, module_fixture, run_module
from v3lum.core.context import ScanOptions
from v3lum.core.models import Severity, Status
from v3lum.modules.threat_intel_ioc import greynoise_community as mod
from v3lum.modules.threat_intel_ioc.greynoise_community import (
    KEY_HINT,
    KEYED_HINT,
    NOT_OBSERVED,
    SCANNER_EXPLANATION,
    GreynoiseCommunity,
    parse_community,
    parse_rate_limit_window,
    quota_facts,
)

FIX = "greynoise_community"
URL = "https://api.greynoise.io/v3/community/{ip}"
KEY = {"greynoise": "gn-test-key-0123456789abcdef"}


def body(name: str) -> bytes:
    return json.dumps(module_fixture(FIX, name)).encode()


def route(ip: str, name: str, *, status: int = 200, headers: dict[str, str] | None = None, http: FakeHttp | None = None) -> FakeHttp:
    http = http or FakeHttp()
    return http.add("GET", URL.format(ip=ip), status=status, body=body(name), headers={"content-type": "application/json", **(headers or {})})


@pytest.fixture
def doc_ips(monkeypatch):
    """The synthetic 200 shapes use documentation addresses: let applies() accept them in tests."""
    monkeypatch.setattr(mod, "is_public_ip", lambda value: True)


# --------------------------------------------------------------------------------------
# metadata (P148 c1-c3, c7)
# --------------------------------------------------------------------------------------


def test_metadata_matches_the_council_decision():
    cls = GreynoiseCommunity
    assert (cls.terms, cls.default_enabled, cls.trust_tier, cls.disclosure, cls.shares_input) == ("noncommercial", True, "trusted", "third_party", True)
    assert cls.optional_keys == ("greynoise",) and not cls.requires_keys  # key-first, keyless works
    assert cls.absent_statuses == frozenset({404}) and cls.daily_quota == 3 and cls.run_on == "seeds"
    assert cls.hosts == ("api.greynoise.io",) and cls.sources == ("greynoise.community",)
    assert cls.manual_link == "scanner_intel_g02_3:greynoise_viz_ip" and cls.cache_ttl == 86400 and cls.min_interval >= 2.0
    assert "reputation" in cls.tags


def test_pure_parsers():
    assert parse_rate_limit_window("25-W") == {"count": 25, "period": "week", "raw": "25-W"}
    assert parse_rate_limit_window("junk") is None and parse_rate_limit_window(None) is None
    facts = quota_facts({"X-Ratelimit-Limit": "25", "x-ratelimit-remaining": "0", "x-ratelimit-reset": "1795842297"}, {"plan": "Community", "rate_limit": "25-W"})
    assert facts == {"limit": 25, "remaining": 0, "reset_at": "2026-11-28T05:04:57Z", "plan": "Community", "window": {"count": 25, "period": "week", "raw": "25-W"}}
    assert parse_community({"message": "no flags"}) is None and parse_community(["x"]) is None
    parsed = parse_community({"noise": "true", "riot": False, "classification": "weird", "name": "unknown", "link": "javascript:alert(1)"})
    assert parsed["noise"] is True and parsed["classification"] == "unknown" and parsed["name"] is None and parsed["link"] is None


# --------------------------------------------------------------------------------------
# recorded fixtures (P148 c4, c8)
# --------------------------------------------------------------------------------------


def test_recorded_404_is_not_observed_never_benign():
    http = route("8.8.8.8", "not_observed_404_8888.json", status=404)
    res = run_module(GreynoiseCommunity, "ipv4:8.8.8.8", http)
    assert res.status is Status.EMPTY
    assert res.attributes["greynoise"] == {"state": "not_observed", "noise": False, "riot": False}
    [finding] = res.findings
    assert finding.title.lower() == NOT_OBSERVED.lower() and finding.severity is Severity.INFO
    assert not {"known_good", "benign_scanner"} & set(finding.tags)
    assert "scanner_classification" not in res.attributes and "allowlisted" not in res.attributes
    http.assert_hosts_within(GreynoiseCommunity)


@pytest.mark.parametrize(("ip", "name"), [("8.8.8.8", "rate_limited_429_8888.json"), ("1.1.1.1", "rate_limited_429_1111.json")])
def test_recorded_429_fixtures_are_rate_limited_never_benign(ip, name):
    http = route(ip, name, status=429)
    res = run_module(GreynoiseCommunity, f"ipv4:{ip}", http)
    assert res.status is Status.RATE_LIMITED and res.reason_code == "rate_limited"
    assert "25 per week per egress IP" in res.error and KEY_HINT in res.error
    assert not res.findings and "greynoise" not in res.attributes
    assert all("benign" not in str(v).lower() for v in res.attributes.values())


def test_recorded_429_exchange_reports_the_reset_and_the_hint_once_per_run():
    ex = module_fixture(FIX, "rate_limited_429_exchange_9999.json")
    http = FakeHttp().add("GET", URL.format(ip="9.9.9.9"), status=429, body=json.dumps(ex["body"]).encode(), headers=ex["headers"])
    rt = make_runtime(http)
    res = run_module(GreynoiseCommunity, "ipv4:9.9.9.9", runtime=rt)
    assert res.status is Status.RATE_LIMITED and "resets 2026-11-28T05:04:57Z" in res.error
    # a second seed of the same run never reaches the network: the provider is backed off after the 429
    again = run_module(GreynoiseCommunity, "ipv4:9.9.9.9", runtime=rt)
    assert again.status is Status.RATE_LIMITED and KEY_HINT not in again.error
    assert len(http.calls) == 1


def test_keyed_lookup_sends_the_key_in_the_header_only_and_never_leaks_it():
    http = FakeHttp().add(
        "GET", URL.format(ip="8.8.8.8"), status=429, body=body("rate_limited_429_8888.json"), headers={"content-type": "application/json"},
        match_headers={"key": KEY["greynoise"]},
    )
    res = run_module(GreynoiseCommunity, "ipv4:8.8.8.8", http, keys=KEY)
    assert res.status is Status.RATE_LIMITED and KEYED_HINT in res.error and "for the key" in res.error
    assert KEY["greynoise"] not in http.calls[0]["url"]
    assert_no_secret(KEY["greynoise"], res.to_dict())


# --------------------------------------------------------------------------------------
# documented 200 shapes (P148 c5-c7)
# --------------------------------------------------------------------------------------


def test_riot_is_known_good_for_this_ip_only():
    http = route("8.8.8.8", "riot_synthetic.json")
    res = run_module(GreynoiseCommunity, "ipv4:8.8.8.8", http)
    assert res.status is Status.OK
    [finding] = res.findings
    assert finding.tags == ["known_good"] and finding.severity is Severity.INFO
    assert "Google Public DNS" in finding.title and finding.data["suppression_rule"] == "greynoise_riot" and finding.data["scope"] == "ip"
    assert res.attributes["allowlisted"] == ["GreyNoise RIOT: Google Public DNS (common business service)"]
    assert res.attributes["greynoise"]["state"] == "riot" and not res.pivots
    assert ("GreyNoise Visualizer", "https://viz.greynoise.io/ips/8.8.8.8") in res.links


def test_benign_noise_is_a_known_benign_scanner(doc_ips):
    res = run_module(GreynoiseCommunity, "ipv4:198.51.100.23", route("198.51.100.23", "noise_benign_synthetic.json"))
    assert res.status is Status.OK
    [finding] = res.findings
    assert finding.title == "Known benign scanner (Shodan.io)" and finding.tags == ["benign_scanner"] and finding.severity is Severity.INFO
    assert res.attributes["scanner_classification"] == "benign" and res.attributes["is_scanner"] is True
    assert finding.data["suppression_rule"] == "greynoise_benign_scanner"


def test_malicious_noise_is_an_opportunistic_mass_scanner_at_medium(doc_ips):
    res = run_module(GreynoiseCommunity, "ipv4:203.0.113.66", route("203.0.113.66", "noise_malicious_synthetic.json"))
    [finding] = res.findings
    assert finding.title == "Opportunistic mass scanner (GreyNoise)" and finding.severity is Severity.MEDIUM
    assert SCANNER_EXPLANATION in finding.description and finding.tags == ["scanner"] and finding.criterion
    assert finding.observed_last and str(finding.observed_last).startswith("2026-11-25")
    assert res.attributes["scanner_classification"] == "malicious"


def test_unclassified_noise_is_info_context(doc_ips):
    res = run_module(GreynoiseCommunity, "ipv4:203.0.113.67", route("203.0.113.67", "noise_unknown_synthetic.json"))
    [finding] = res.findings
    assert finding.severity is Severity.INFO and finding.tags == ["scanner"] and res.attributes["scanner_classification"] == "unknown"


def test_answer_without_flags_is_empty_never_benign():
    http = FakeHttp().add("GET", URL.format(ip="8.8.8.8"), json={"ip": "8.8.8.8", "noise": False, "riot": False, "message": "Success"})
    res = run_module(GreynoiseCommunity, "ipv4:8.8.8.8", http)
    assert res.status is Status.EMPTY and res.findings[0].title == "No GreyNoise noise or RIOT classification"


# --------------------------------------------------------------------------------------
# could not verify (rule 5)
# --------------------------------------------------------------------------------------


def test_error_in_200_rate_limit_message_is_rate_limited():
    http = route("8.8.8.8", "rate_limited_429_8888.json", status=200)
    res = run_module(GreynoiseCommunity, "ipv4:8.8.8.8", http)
    assert res.status is Status.RATE_LIMITED


def test_400_5xx_html_and_malformed_answers_are_errors():
    cases = [
        FakeHttp().add("GET", URL.format(ip="8.8.8.8"), status=400, body=body("invalid_ip_400_synthetic.json"), headers={"content-type": "application/json"}),
        FakeHttp().add("GET", URL.format(ip="8.8.8.8"), status=502, text=module_fixture(FIX, "gateway_502_synthetic.html")),
        FakeHttp().add("GET", URL.format(ip="8.8.8.8"), status=200, text=module_fixture(FIX, "gateway_502_synthetic.html")),
        FakeHttp().add("GET", URL.format(ip="8.8.8.8"), status=200, body=b"{not json", headers={"content-type": "application/json"}),
        FakeHttp().add("GET", URL.format(ip="8.8.8.8"), status=404, json={"detail": "route not found"}),
    ]
    for http in cases:
        res = run_module(GreynoiseCommunity, "ipv4:8.8.8.8", http)
        assert res.status is Status.ERROR, (res.status, res.error)
        assert not res.findings


def test_401_with_a_key_is_needs_key_and_403_keyless_is_blocked():
    http = FakeHttp().add("GET", URL.format(ip="8.8.8.8"), status=401, json={"message": "invalid key"})
    assert run_module(GreynoiseCommunity, "ipv4:8.8.8.8", http, keys=KEY).status is Status.NEEDS_KEY
    http = FakeHttp().add("GET", URL.format(ip="8.8.8.8"), status=403, json={"message": "forbidden"})
    assert run_module(GreynoiseCommunity, "ipv4:8.8.8.8", http).status is Status.BLOCKED


def test_dead_network_is_an_error_never_empty():
    res = run_module(GreynoiseCommunity, "ipv4:8.8.8.8", DeadHttp())
    assert res.status is Status.ERROR


# --------------------------------------------------------------------------------------
# seeds only (P148 c3)
# --------------------------------------------------------------------------------------


@pytest.mark.parametrize("kw", [
    {"is_seed": False, "depth": 1},
    {"depth": 1},
    {"provenance": (("text_blob:#abc", "mentions", "ioc_extract"),)},
])
def test_pivots_and_extracted_values_are_never_sent(kw):
    http = FakeHttp()
    res = run_module(GreynoiseCommunity, "ipv4:8.8.8.8", http, **kw)
    assert res.status is Status.SKIPPED and not http.calls


def test_unconfirmed_and_private_seeds_are_never_sent():
    http = FakeHttp()
    opts = ScanOptions()
    opts.unconfirmed_seeds = {"ipv4:8.8.8.8"}
    assert run_module(GreynoiseCommunity, "ipv4:8.8.8.8", http, options=opts).status is Status.SKIPPED
    assert run_module(GreynoiseCommunity, "ipv4:10.1.2.3", http).status is Status.SKIPPED
    assert not http.calls


# --------------------------------------------------------------------------------------
# budget and licence gate (P148 c2-c3)
# --------------------------------------------------------------------------------------


def test_interim_daily_quota_counts_every_lookup():
    http = FakeHttp()
    ips = ("8.8.8.8", "8.8.4.4", "1.1.1.1")
    for ip in ips:
        http.add("GET", URL.format(ip=ip), status=404, json={"ip": ip, "noise": False, "riot": False, "message": "IP not observed scanning the internet."})
    rt = make_runtime(http)
    for n, ip in enumerate(ips, 1):
        assert run_module(GreynoiseCommunity, f"ipv4:{ip}", runtime=rt).status is Status.EMPTY
        assert rt.quota.exhausted("greynoise_community", GreynoiseCommunity.daily_quota) is (n == len(ips))


def test_corporate_profile_skips_it_with_reason_licence():
    from v3lum.core import policy
    from v3lum.core.context import RunInfo
    from v3lum.core.entities import Entity, EntityType

    rt = make_runtime(FakeHttp())
    ent = Entity.make(EntityType.IPV4, "8.8.8.8")
    decision = policy.decide(GreynoiseCommunity, ent, policy.make_context(rt, ScanOptions(), path="run"), run=RunInfo(entity=ent, is_seed=True))
    assert not decision.allowed and decision.reason_code == "licence" and decision.emit_manual_link


def test_acceptance_routes_of_the_golden_ipv4_replay():
    from tests.fakes import FIXTURES

    doc = json.loads((FIXTURES / "acceptance" / "ipv4" / "greynoise_community.json").read_text(encoding="utf-8"))
    assert doc["schema"] == "v3lum.acceptance_routes/1" and doc["module"] == "greynoise_community"
    http = FakeHttp()
    for r in doc["routes"]:
        http.add(r["method"], r["url"], status=r["status"], json=r["json"], headers=r.get("headers") or {})
    res = run_module(GreynoiseCommunity, "ipv4:8.8.8.8", http)
    assert res.status is Status.EMPTY and len(http.calls) == len(doc["routes"])
    assert all(f.severity is Severity.INFO for f in res.findings)
