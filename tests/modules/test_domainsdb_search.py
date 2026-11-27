"""domainsdb_search (P005 cond 3-4): keyed DomainsDB keyword search, org brands only, unknown tier fail-closed.

Fixtures in tests/fixtures/domainsdb_search/: ``error_needs_key.json`` is the real anonymous answer of the
research (HTTP 401, 2026-11-25). Synthetic (documented v1 shape, documentation values; no key yet):
``search_ok_synthetic.json`` and ``not_found_synthetic.json``.
"""

from __future__ import annotations

import pytest

from tests.fakes import FakeHttp, assert_no_secret, module_fixture, run_module
from v3lum.core import policy
from v3lum.core.context import RunInfo, ScanOptions
from v3lum.core.entities import Entity, EntityType
from v3lum.core.models import Severity, Status
from v3lum.core.orgprofile import OrgProfile
from v3lum.modules.domain_dns import domainsdb_search as mod
from v3lum.modules.domain_dns.domainsdb_search import DomainsdbSearch

KEY = "domainsdb-test-key-0123456789"
KEYS = {"domainsdb": KEY}
URL = "https://api.domainsdb.info/v1/domains/search?domain=examplebrand"
ORG = OrgProfile.from_dict({"brands": [{"keyword": "ExampleBrand"}]})


def fx(name):
    return module_fixture(DomainsdbSearch, name)


@pytest.fixture
def promoted(monkeypatch):
    """A reviewer recorded the promotion from unknown to community tier (cond 4)."""
    monkeypatch.setattr(mod, "_provider_tier", lambda: "community")


def run(http, **kw):
    kw.setdefault("keys", KEYS)
    kw.setdefault("org_profile", ORG)
    return run_module(DomainsdbSearch, "keyword:ExampleBrand", http, **kw)


def test_contract_metadata():
    cls = DomainsdbSearch
    assert (cls.terms, cls.disclosure, cls.provider, cls.hosts, cls.requires_keys) == (
        "key-terms", "third_party", "domainsdb", ("api.domainsdb.info",), ("domainsdb",))
    assert cls.default_enabled is False and cls.trust_tier == "unknown" and cls.reuses_queries is True
    assert getattr(cls.max_tlp, "name", cls.max_tlp) in ("GREEN", "green")  # cond 4: excluded at AMBER and above


def test_unknown_tier_fails_closed_without_a_request():
    http = FakeHttp()
    res = run(http)
    assert res.status is Status.SKIPPED and res.reason_code == "tier" and not http.calls


def test_policy_gate_refuses_a_brand_keyword_to_an_unknown_tier_provider():
    from v3lum.core import module as module_mod
    from tests.fakes import make_runtime

    module_mod.load_modules()
    rt = make_runtime(keys=KEYS, org_profile=ORG)
    ent = Entity.make(EntityType.KEYWORD, "ExampleBrand")
    pctx = policy.make_context(rt, ScanOptions(tlp="green", allow_unknown=True), explicit={"domainsdb_search"}, path="scan")
    decision = policy.decide(module_mod.REGISTRY["domainsdb_search"], ent, pctx, run=RunInfo(entity=ent, is_seed=True))
    assert decision.allowed is False and decision.status is Status.SKIPPED


def test_keywords_must_be_org_brands(promoted):
    res = run_module(DomainsdbSearch, "keyword:paypal", FakeHttp(), keys=KEYS, org_profile=ORG)
    assert res.status is Status.SKIPPED and res.reason_code == "not_applicable"


def test_search_results_are_candidates(promoted):
    http = FakeHttp().add("GET", URL, json=fx("search_ok_synthetic.json"), match_headers={"Authorization": f"Bearer {KEY}"})
    res = run(http)
    assert res.status is Status.OK
    assert [d["domain"] for d in res.attributes["keyword_domains"]] == ["examplebrand-login.com", "examplebrand-ofertas.net"]
    assert {p.entity.value for p in res.pivots} == {"examplebrand-login.com", "examplebrand-ofertas.net"}
    assert all(p.expand is False and p.relation == "brand_match" for p in res.pivots)
    recent = [f for f in res.findings if f.title.startswith("Recently created")]
    assert {f.entity.value for f in recent} == {"examplebrand-login.com", "examplebrand-ofertas.net"}
    assert all(f.severity is Severity.LOW and "newly_registered" not in f.tags for f in recent)
    http.assert_hosts_within(DomainsdbSearch)
    assert_no_secret(KEY, res)


def test_documented_not_found_is_empty(promoted):
    http = FakeHttp().add("GET", URL, status=404, json=fx("not_found_synthetic.json"))
    assert run(http).status is Status.EMPTY


def test_real_401_is_needs_key(promoted):
    http = FakeHttp().add("GET", URL, status=401, json=fx("error_needs_key.json"))
    res = run(http)
    assert res.status is Status.NEEDS_KEY and "API key required" in res.error


def test_rate_limit_quota_and_junk(promoted):
    assert run(FakeHttp().add("GET", URL, status=429, json={"message": "Too many requests"})).status is Status.RATE_LIMITED
    assert run(FakeHttp().add("GET", URL, json={"message": "Daily limit exceeded"})).status is Status.QUOTA
    assert run(FakeHttp().add("GET", URL, body=b"{oops", headers={"content-type": "application/json"})).status is Status.ERROR
    assert run(FakeHttp().add("GET", URL, json={"domains": "x"})).status is Status.ERROR
    assert run(FakeHttp().add("GET", URL, status=500, text="oops")).status is Status.ERROR


def test_without_key_needs_key(promoted):
    http = FakeHttp()
    res = run_module(DomainsdbSearch, "keyword:ExampleBrand", http, org_profile=ORG)
    assert res.status is Status.NEEDS_KEY and not http.calls


def test_parser_tolerates_junk():
    assert mod.parse_search([]) is None
    rows = mod.parse_search({"domains": [{"domain": "Bad Host"}, {"domain": "ok.example.com", "MX": "x", "A": ["999.1.1.1", "192.0.2.1"]}, "x"]})
    assert rows == [{"domain": "ok.example.com", "created": None, "updated": None, "is_dead": False, "a": ["192.0.2.1"], "mx": []}]
