"""Offline tests of networksdb (P218) with the fixtures in tests/fixtures/networksdb/.

The success fixtures are documentation-shaped (no company key yet, P218 FC4: a trimmed real capture
made with the company key replaces them before merge); the missing-key answer is the real capture.
"""

from __future__ import annotations

import pytest

from tests.fakes import FakeHttp, add_dns, module_fixture, run_module
from v3lum import config
from v3lum.core.models import Status
from v3lum.modules.company_org.networksdb import (
    MAX_CONFIDENCE,
    NetworksDb,
    networksdb_request,
    org_match_score,
    parse_org_networks,
)
from v3lum.modules.ip_network.ip_geolocation import EndpointRefused

FIX = "networksdb"
KEY = "ndb-test-key-0123456789abcdef"  # fake key
KEYS = {"networksdb": KEY}
SEARCH = "https://networksdb.io/api/org-search?search={q}"
NETWORKS = "https://networksdb.io/api/org-networks?id={id}"
IP_INFO = "https://networksdb.io/api/ip-info?ip={ip}"


def fx(name: str):
    return module_fixture(FIX, name)


def org_routes() -> FakeHttp:
    http = FakeHttp()
    http.add("GET", SEARCH.format(q="Example+Bank+S.A."), json=fx("org_search_synthetic.json"), match_headers={"X-Api-Key": KEY})
    http.add("GET", NETWORKS.format(id="example-bank-s-a"), json=fx("org_networks_synthetic.json"))
    http.add("GET", NETWORKS.format(id="example-bank-holdings"), json={"total": 0, "page": 1, "results": []})
    return http


def test_metadata_follows_the_council_decision():
    cls = NetworksDb
    assert (cls.terms, cls.trust_tier, cls.default_enabled, cls.requires_keys) == ("key-terms", "community", False, ("networksdb",))
    assert {t.value for t in cls.produces} == {"cidr"}
    assert "V3LUM_NETWORKSDB_KEY" in config.key_registry()["networksdb"].env


@pytest.mark.parametrize("params", [{"apikey": KEY}, {"key": KEY}, {"API_KEY": KEY}])
def test_the_key_is_never_a_query_parameter(params):
    with pytest.raises(EndpointRefused):
        networksdb_request("org-search", search="x", **params)


def test_only_documented_read_endpoints_and_page_one():
    for endpoint in ("reverse-dns", "mass-reverse-dns", "org-info", "dns"):
        with pytest.raises(EndpointRefused):
            networksdb_request(endpoint, ip="8.8.8.8")
    with pytest.raises(ValueError):
        networksdb_request("org-networks", id="x", page=2)  # free keys: page 1 only, never sent
    with pytest.raises(ValueError):
        networksdb_request("ip-info", ip="10.0.0.1")
    assert networksdb_request("ip-info", ip="8.8.8.8") == "https://networksdb.io/api/ip-info?ip=8.8.8.8"


def test_organisation_ranges_are_low_confidence_candidates_never_expanded():
    http = org_routes()
    res = run_module(NetworksDb, "company_name:Example Bank S.A.", http, keys=KEYS)
    assert res.status is Status.OK
    cidrs = {p.entity.value: p for p in res.pivots}
    assert set(cidrs) == {"198.51.100.0/24", "203.0.113.0/25", "203.0.113.128/26"}  # the 'N/A' range summarised
    for p in res.pivots:
        assert p.expand is False and p.relation == "candidate_netblock" and p.confidence <= MAX_CONFIDENCE
    cand = res.attributes["network_candidates"]
    assert cand["scope_eligible"] is False and cand["confirm_with"] == ["rdap", "nicbr_asn"]
    best = cand["candidates"][0]
    assert best["org_id"] == "example-bank-s-a" and best["match_score"] == 1.0
    assert "examplebank-foods-ltda" in {c["org_id"] for c in cand["candidates"]}  # listed, never expanded
    assert all("apikey" not in c["url"] and KEY not in c["url"] for c in http.calls)
    assert all(c["headers"].get("X-Api-Key") == KEY for c in http.calls)
    (finding,) = res.findings
    assert "Candidates only" in finding.description
    http.assert_hosts_within(NetworksDb)


def test_missing_key_answer_is_needs_key_never_empty():
    http = FakeHttp().add("GET", SEARCH.format(q="Example+Bank"), status=400, json=fx("nokey_400.json"))
    res = run_module(NetworksDb, "company_name:Example Bank", http, keys=KEYS)
    assert res.status is Status.NEEDS_KEY and "X-Api-Key" in res.error
    empty = FakeHttp()
    assert run_module(NetworksDb, "company_name:Example Bank", empty).status is Status.NEEDS_KEY and empty.calls == []


def test_errors_quota_and_limits_are_could_not_verify():
    url = SEARCH.format(q="Example+Bank")
    cases = [(dict(json={"error": "API request limit exceeded for this month"}), Status.QUOTA),
             (dict(json={"error": "internal error"}), Status.ERROR), (dict(status=429, text="slow down"), Status.RATE_LIMITED),
             (dict(status=503, text="down"), Status.ERROR), (dict(json=["x"]), Status.ERROR),
             (dict(text="{broken", headers={"content-type": "application/json"}), Status.ERROR)]
    for kw, expected in cases:
        res = run_module(NetworksDb, "company_name:Example Bank", FakeHttp().add("GET", url, **kw), keys=KEYS)
        assert res.status is expected, (kw, res.status, res.error)


def test_no_match_is_empty_and_weak_matches_are_never_expanded():
    url = SEARCH.format(q="Acme+Widgets")
    res = run_module(NetworksDb, "company_name:Acme Widgets", FakeHttp().add("GET", url, json={"total": 0, "page": 1, "results": []}), keys=KEYS)
    assert res.status is Status.EMPTY
    weak = {"total": 1, "page": 1, "results": [{"organization": "Totally Different Org", "id": "tdo", "networks": {"ipv4": 3}}]}
    http = FakeHttp().add("GET", url, json=weak)
    res = run_module(NetworksDb, "company_name:Acme Widgets", http, keys=KEYS)
    assert res.status is Status.OK and not res.pivots and len(http.calls) == 1


def test_ip_and_domain_owner_networks():
    http = FakeHttp().add("GET", IP_INFO.format(ip="200.160.2.3"), json=fx("ip_info_synthetic.json"))
    res = run_module(NetworksDb, "ipv4:200.160.2.3", http, keys=KEYS)
    (pivot,) = res.pivots
    assert (pivot.entity.value, pivot.relation, pivot.expand, pivot.confidence) == ("198.51.100.0/24", "in_network", False, 0.4)
    assert res.attributes["org"] == "Example Bank S.A."
    http = FakeHttp().add("GET", IP_INFO.format(ip="200.160.2.3"), json=fx("ip_info_synthetic.json"))
    add_dns(http, "bank.example.com", "A", ["200.160.2.3"], provider="all")
    res = run_module(NetworksDb, "domain:bank.example.com", http, keys=KEYS)
    assert res.pivots[0].relation == "candidate_netblock"
    nodns = FakeHttp()
    add_dns(nodns, "private.example.com", "A", ["10.1.1.1"], provider="all")
    assert run_module(NetworksDb, "domain:private.example.com", nodns, keys=KEYS).status is Status.SKIPPED


def test_fuzzy_match_and_range_parsing():
    assert org_match_score("Banco Exemplo S.A.", "BANCO EXEMPLO SA") == 1.0
    assert org_match_score("Ação Ltda", "Acao") == 1.0
    assert org_match_score("Example Bank", "Example Bank Holdings") > 0.5 > org_match_score("Example Bank", "Totally Different")
    networks, invalid = parse_org_networks(fx("org_networks_synthetic.json"))
    assert invalid == 1 and networks[1]["cidrs"] == ["203.0.113.0/25", "203.0.113.128/26"]
    assert parse_org_networks({"results": "x"}) is None
