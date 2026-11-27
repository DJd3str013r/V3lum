"""cl0q (P018): favicon reverse pivots and ASN browse as hypotheses, offline.

Fixtures in tests/fixtures/cl0q/ (batch p3-G01-1 prep): ``nokey_401.json`` is the real research answer without a key;
``browse_favicon_documented.json`` and ``domain_profile_documented.json`` follow the documented response shapes
(cl0q.com/docs, read 2026-11-26) with documentation values; ``signin_required_401_documented.http.json`` is the
documented browse refusal. The favicon answers (field names are undocumented: prose only) and the 429/400 bodies are
synthetic. A trimmed real success capture with the team key is still owed (P018 cond 6, docs/backlog/p3-G01-1.md).
"""

from __future__ import annotations

import pytest

from tests.fakes import FakeHttp, assert_no_secret, module_fixture, run_module
from v3lum.core.entities import EntityType as T
from v3lum.core.models import Severity, Status
from v3lum.core.orgprofile import OrgProfile
from v3lum.modules.domain_dns import cl0q as C
from v3lum.modules.domain_dns.cl0q import Cl0q

KEY = "cl0q_test0123456789abcdef0123456789"
KEYS = {"cl0q": KEY}
HDR = {"X-API-Key": KEY}
SHA = "0f7e861db0a2eeb3045c061b5fa6e4afdecd9828ff44f4a53d418d8fac55f080"
FWD = C.FAVICON_URL + "?domain=example.com&limit=100"
REV = C.FAVICON_URL + f"?hash={SHA}&limit=100"
ASN = C.BROWSE_ASN_URL.format(asn=64496) + "?apex=1&limit=100"


def fx(name):
    return module_fixture("cl0q", name)


def envelope(name):
    resp = fx(name)["response"]
    return {"status": resp["status"], "headers": resp.get("headers") or {}, "json": resp["body"]}


def run(entity, http, **kw):
    kw.setdefault("keys", KEYS)
    return run_module(Cl0q, entity, http, **kw)


def test_contract_metadata():
    cls = Cl0q
    assert cls.default_enabled is False and cls.trust_tier == "unknown" and cls.terms == "key-terms"
    assert cls.max_tlp.label == "TLP:GREEN"  # unknown tier: excluded at AMBER and above (cond 1)
    assert cls.accepts == {T.DOMAIN, T.ASN}  # IOC types only: no keyword, no personal type
    assert cls.requires_keys == ("cl0q",) and cls.max_requests == 2 and cls.hosts == ("cl0q.com",)


def test_quota_block_and_header_only_key():
    from v3lum import config
    from v3lum.core import providers

    prov = providers.registry().get("cl0q")
    assert prov.tier == "unknown" and prov.quota.day == 1000 and prov.quota.rate_per_second == 0.5
    assert "V3LUM_CL0Q_KEY" in config.key_registry()["cl0q"].env


def test_without_key_needs_key():
    http = FakeHttp()
    res = run_module(Cl0q, "domain:example.com", http)
    assert res.status is Status.NEEDS_KEY and http.calls == []


def test_forward_then_reverse_favicon_lookup_gives_capped_hypotheses():
    http = FakeHttp()
    http.add("GET", FWD, json=fx("favicon_forward_ok_synthetic.json"), match_headers=HDR)
    http.add("GET", REV, json=fx("favicon_reverse_ok_synthetic.json"), match_headers=HDR)
    res = run("domain:example.com", http)
    assert res.status is Status.OK
    assert res.attributes["favicon_sha256"] == SHA
    shared = res.attributes["favicon_shared"]
    assert shared["shared_count"] == 41 and shared["truncated"] is True and shared["common"] is False
    pivots = {p.entity.value: p for p in res.pivots}
    assert set(pivots) == {"example.net", "example.org", "shop.example.net"}  # queried name and junk left out
    assert all(p.relation == "related" and p.expand is False and str(p.confidence_label).lower().endswith("possible") for p in pivots.values())
    assert res.findings[0].title == "Favicon shared with other sites" and res.findings[0].severity is Severity.INFO
    assert all("key=" not in c["url"] and KEY not in c["url"] for c in http.calls)  # header only, never ?key=
    assert_no_secret(KEY, res.to_dict())
    http.assert_hosts_within(Cl0q)


def test_own_site_favicon_on_outside_domains_is_low():
    org = OrgProfile.from_dict({"org": {"name": "Example Org"},
                                "domains": [{"name": "example.com", "verification": "attested", "attested_by": "analyst",
                                             "attested_date": "2026-11-20"}]})
    http = FakeHttp()
    http.add("GET", FWD, json={"domain": "example.com", "hash": SHA, "count": 2, "sample": ["example.net", "www.example.com"]})
    res = run("domain:example.com", http, org_profile=org)
    f = res.findings[0]
    assert f.title == "Own site favicon served by other domains" and f.severity is Severity.LOW
    assert f.criterion and f.data["domains"] == ["example.net"] and "possible_clone" in f.tags
    assert len(http.calls) == 1  # the sample already lists every sharing site: no reverse request


def test_common_icon_gives_no_pivot():
    http = FakeHttp().add("GET", FWD, json={"domain": "example.com", "hash": SHA, "count": 25000, "sample": ["example.net"]})
    res = run("domain:example.com", http)
    assert res.status is Status.OK and not res.pivots
    assert res.attributes["favicon_shared"]["common"] is True and res.findings[0].title == "Favicon is a common icon"
    assert len(http.calls) == 1  # a default icon is never reversed


def test_no_favicon_in_the_index_is_empty():
    http = FakeHttp().add("GET", FWD, json={"domain": "example.com", "hash": None, "count": 0, "sample": []})
    res = run("domain:example.com", http)
    assert res.status is Status.EMPTY


def test_empty_reverse_answer_keeps_the_sample():
    http = FakeHttp()
    http.add("GET", FWD, json={"domain": "example.com", "hash": SHA, "count": 3, "sample": ["example.net"]})
    http.add("GET", REV, json=fx("favicon_empty_synthetic.json"))
    res = run("domain:example.com", http)
    assert {p.entity.value for p in res.pivots} == {"example.net"}


def test_asn_browse_documented_shape():
    doc = fx("browse_favicon_documented.json")
    doc = {**doc, "kind": "asn", "key": "64496"}
    http = FakeHttp().add("GET", ASN, json=doc, match_headers=HDR)
    res = run("asn:AS64496", http)
    assert res.status is Status.OK
    sample = res.attributes["asn_domain_sample"]
    assert sample["asn"] == "AS64496" and sample["listed"] == 2 and sample["more"] is False
    assert {p.entity.value for p in res.pivots} == {"example.com", "example.net"}
    assert all(p.relation == "related" and p.expand is False for p in res.pivots)


@pytest.mark.parametrize("route,status", [
    ({"status": 401, "json": fx("nokey_401.json")}, Status.NEEDS_KEY),  # the real research answer
    (envelope("signin_required_401_documented.http.json"), Status.NEEDS_KEY),
    ({"status": 403, "json": {"error": "invalid API key"}}, Status.NEEDS_KEY),
    (envelope("rate_limited_429_synthetic.http.json"), Status.RATE_LIMITED),
    (envelope("daily_limit_429_synthetic.http.json"), Status.QUOTA),
    (envelope("malformed_hash_400_synthetic.http.json"), Status.ERROR),
    ({"status": 503, "json": {"error": "maintenance"}}, Status.ERROR),
    (envelope("not_in_index_404_synthetic.http.json"), Status.ERROR),  # 404 documented for /api/domain only: could not verify here
    ({"json": {"error": "backend unavailable"}}, Status.ERROR),
    ({"json": {"error": "daily limit reached (1000/day)"}}, Status.QUOTA),  # error-in-200
    ({"text": "<html><body>maintenance</body></html>"}, Status.ERROR),
    ({"json": ["not", "an", "object"]}, Status.ERROR),
])
def test_refusals_and_failures_are_never_empty(route, status):
    http = FakeHttp().add("GET", FWD, **route)
    res = run("domain:example.com", http)
    assert res.status is status
    assert "favicon_shared" not in res.attributes and not res.pivots


def test_reverse_rate_limit_keeps_the_forward_answer():
    http = FakeHttp()
    http.add("GET", FWD, json=fx("favicon_forward_ok_synthetic.json"))
    http.add("GET", REV, **envelope("rate_limited_429_synthetic.http.json"))
    res = run("domain:example.com", http)
    assert res.status is Status.OK and res.partial and res.stop_reason == "rate_limited"
    assert {p.entity.value for p in res.pivots} == {"example.net", "example.org"}


def test_reverse_setting_off():
    http = FakeHttp().add("GET", FWD, json=fx("favicon_forward_ok_synthetic.json"))
    res = run("domain:example.com", http, settings={"cl0q_reverse": False})
    assert res.status is Status.OK and len(http.calls) == 1 and res.attributes["favicon_shared"]["truncated"] is True


def test_parse_helpers():
    assert C.parse_sha256("SHA256:" + SHA.upper()) == SHA and C.parse_sha256("708578229") is None  # mmh3 is not a key
    got = C.parse_domain_list(fx("favicon_reverse_ok_synthetic.json"), exclude="example.com")
    assert got["domains"] == ["shop.example.net", "example.org"] and got["rejected"] == 1 and got["count"] == 3
    prof = fx("domain_profile_documented.json")
    assert C.parse_sha256(prof["favicon_sha256"]) == SHA  # the documented profile carries the same pivot key
