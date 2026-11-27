"""Offline tests of censys (P044) with the fixtures in tests/fixtures/censys/.

platform_nokey_401.http.json (v3 without a token) and legacy_decommissioned_403.http.json (legacy
Search API) are recorded research answers (C0079, 2026-11-25; request id zeroed). The success
fixtures are documentation-shaped from the official censys-sdk-python models (values on
documentation space): no company-plan capture exists (P044 cond 7). Credit and rate-limit answers
are synthetic in the SDK problem+json shape.
"""

from __future__ import annotations

import json

import pytest

from tests.fakes import FakeHttp, assert_no_secret, module_fixture, run_module
from v3lum.core.entities import EntityType as T
from v3lum.core.models import Status
from v3lum.core.tlp import TLP
from v3lum.modules.ip_network.censys import (
    ENDPOINTS,
    SOURCE_COMMERCIAL,
    SOURCE_FREE,
    Censys,
    censys_url,
    parse_cert,
    parse_host,
    parse_search,
    search_query,
)
from v3lum.modules.ip_network.scan_engines import EndpointRefused
from v3lum.core.entities import Entity

FIX = "censys"
PAT = "censys_pat_test_0123456789abcdef"  # fake token
KEYS = {"censys": PAT}
HOST = "https://api.platform.censys.io/v3/global/asset/host/{ip}"
CERT = "https://api.platform.censys.io/v3/global/asset/certificate/{sha}"
SEARCH = "https://api.platform.censys.io/v3/global/search/query"
AUTH = {"Authorization": f"Bearer {PAT}"}


def fx(name: str):
    return module_fixture(FIX, name)


def http_fx(name: str) -> dict:
    resp = fx(name)["response"]
    body = resp["body"]
    if isinstance(body, str):
        return {"status": resp["status"], "text": body, "headers": resp.get("headers") or {}}
    return {"status": resp["status"], "json": body, "headers": resp.get("headers") or {}}


def test_metadata_follows_the_council_decision():
    cls = Censys
    assert (cls.terms, cls.default_enabled, cls.trust_tier, cls.requires_keys) == ("noncommercial", True, "trusted", ("censys",))
    assert cls.terms_sources == {SOURCE_FREE: "noncommercial", SOURCE_COMMERCIAL: "key-terms"}  # c3
    assert cls.hosts == ("api.platform.censys.io",) and cls.max_tlp == TLP.AMBER_STRICT
    assert cls.absent_statuses == frozenset({404})
    assert cls.manual_link == "https://platform.censys.io/hosts/{ip}"  # c6: web UIs are manual links only


def test_v3_lookup_and_search_only_rescan_and_legacy_cannot_be_built():
    assert set(ENDPOINTS) == {"host", "certificate", "search"}
    method, url, accept = censys_url("host", "8.8.8.8")
    assert (method, url) == ("GET", "https://api.platform.censys.io/v3/global/asset/host/8.8.8.8") and "host.v1" in accept
    for forbidden in ("rescan", "scans", "live_rescan", "create_tracked_scan", "live_discovery", "censeye", "investigation",
                      "upload", "collections", "legacy_search", "search.censys.io/api/v2/hosts", "aggregate", "convert"):
        with pytest.raises(EndpointRefused):
            censys_url(forbidden, "8.8.8.8")
    for _op, (_m, path, _a) in ENDPOINTS.items():
        assert "scan" not in path and "search.censys.io" not in path
    with pytest.raises(ValueError):
        censys_url("certificate", "not-a-sha256")
    assert search_query(Entity.make(T.DOMAIN, "example.com")) == 'host.dns.names: "example.com"'


def test_host_lookup_parses_services_vulns_threats_and_certs():
    http = FakeHttp().add("GET", HOST.format(ip="8.8.8.8"), json=fx("host_ok_documented.json"), match_headers=AUTH)
    res = run_module(Censys, "ipv4:8.8.8.8", http, keys=KEYS)
    assert res.status is Status.OK
    a = res.attributes
    assert a["open_ports"] == [22, 443, 3389, 8080] and a["asn"] == "AS64500" and a["country"] == "BR"
    assert a["is_hosting"] is True and "remote-access" in a["tags"]
    # c5/P291: recog/third_party CVEs are version-inferred; the censys-sourced one with evidence is verified
    assert sorted(a["vulns"]) == ["CVE-2021-23017", "CVE-2021-41617", "CVE-2023-38408"]
    assert a["vulns_verified"] == ["CVE-2021-44228"]
    by_title = {f.title: f for f in res.findings}
    inferred = by_title["CVE(s) associated with exposed software (version-inferred)"]
    assert inferred.severity.name == "HIGH" and "version_inferred" in inferred.tags  # capped: never critical
    assert inferred.confidence_label.value == "possible" and inferred.criterion
    verified = by_title["Vulnerabilities verified by Censys on the host"]
    assert verified.severity.name == "CRITICAL" and "kev" in verified.tags and verified.confidence_label.value == "probable"
    threat = by_title["Threat detected by Censys on a service"]
    assert "third_party_verdict" in threat.tags and a["scan_threats"][0]["name"] == "Cobalt Strike"
    # every name and certificate is listed, never expanded (IP seed: no queried apex)
    assert res.pivots and all(p.expand is False for p in res.pivots)
    certs = [p for p in res.pivots if p.entity.type is T.CERT_FP]
    assert [p.relation for p in certs] == ["serves_certificate"]
    assert {p.entity.value for p in res.pivots if p.relation == "reverse_dns"} == {"host20.example.com"}
    assert all(f.source == SOURCE_FREE for f in res.findings)
    assert any(url == "https://platform.censys.io/hosts/8.8.8.8" for _, url in res.links)
    assert_no_secret(PAT, res)
    http.assert_hosts_within(Censys)


def test_commercial_plan_and_organization_id_are_used_and_masked():
    org = "0f1e2d3c-4b5a-6978-8796-a5b4c3d2e1f0"
    url = HOST.format(ip="8.8.8.8") + "?organization_id=" + org
    http = FakeHttp().add("GET", url, json=fx("host_ok_documented.json"), match_headers=AUTH)
    res = run_module(Censys, "ipv4:8.8.8.8", http, keys=KEYS,
                     settings={"censys_organization_id": org, "key_plans": {"censys": "business"}})
    assert res.status is Status.OK and res.raw["source"] == SOURCE_COMMERCIAL
    assert_no_secret(org, res)
    assert_no_secret(PAT, res)


def test_404_is_a_documented_absence():
    http = FakeHttp().add("GET", HOST.format(ip="8.8.4.4"), **http_fx("host_not_found_404_synthetic.http.json"))
    res = run_module(Censys, "ipv4:8.8.4.4", http, keys=KEYS)
    assert res.status is Status.EMPTY


def test_recorded_401_is_needs_key_and_legacy_403_is_a_clear_error():
    http = FakeHttp().add("GET", HOST.format(ip="8.8.8.8"), **http_fx("platform_nokey_401.http.json"))
    res = run_module(Censys, "ipv4:8.8.8.8", http, keys=KEYS)
    assert res.status is Status.NEEDS_KEY and res.reason_code == "needs_key"
    http = FakeHttp().add("GET", HOST.format(ip="8.8.8.8"), **http_fx("legacy_decommissioned_403.http.json"))
    res = run_module(Censys, "ipv4:8.8.8.8", http, keys=KEYS)
    assert res.status is Status.ERROR and "decommissioned on 2026-09-30" in res.error and "Platform API v3" in res.error


@pytest.mark.parametrize(
    ("fixture", "status", "code"),
    [
        ("quota_403_synthetic.http.json", Status.QUOTA, "quota"),
        ("rate_limited_429_synthetic.http.json", Status.RATE_LIMITED, "rate_limited"),
    ],
)
def test_credits_and_rate_limits_are_could_not_verify(fixture, status, code):
    http = FakeHttp().add("GET", HOST.format(ip="8.8.8.8"), **http_fx(fixture))
    res = run_module(Censys, "ipv4:8.8.8.8", http, keys=KEYS)
    assert res.status is status and res.reason_code == code


def test_402_and_5xx_and_malformed():
    http = FakeHttp().add("GET", HOST.format(ip="8.8.8.8"), status=402, json={"title": "Payment Required"})
    assert run_module(Censys, "ipv4:8.8.8.8", http, keys=KEYS).status is Status.QUOTA
    http = FakeHttp().add("GET", HOST.format(ip="8.8.8.8"), status=500, json={"title": "Internal"}, times=3)
    assert run_module(Censys, "ipv4:8.8.8.8", http, keys=KEYS).status is Status.ERROR
    http = FakeHttp().add("GET", HOST.format(ip="8.8.8.8"), json={"result": "nope"})
    assert run_module(Censys, "ipv4:8.8.8.8", http, keys=KEYS).status is Status.ERROR


def test_challenge_page_is_blocked():
    http = FakeHttp().add("GET", HOST.format(ip="8.8.8.8"), **http_fx("web_ui_challenge.http.json"))
    res = run_module(Censys, "ipv4:8.8.8.8", http, keys=KEYS)
    assert res.status is Status.BLOCKED and res.reason_code == "challenge"


def test_certificate_lookup_san_pivots_never_expand():
    doc = fx("cert_ok_documented.json")
    sha = doc["result"]["resource"]["fingerprint_sha256"]
    http = FakeHttp().add("GET", CERT.format(sha=sha), json=doc, match_headers=AUTH)
    res = run_module(Censys, f"cert_fingerprint:{sha}", http, keys=KEYS)
    assert res.status is Status.OK
    sans = {p.entity.value: p for p in res.pivots}
    assert set(sans) == {"example.com", "www.example.com", "api.example.com", "partner.example.net"}
    assert all(p.expand is False and p.relation == "cert_san" for p in sans.values())
    assert res.attributes["cert_issuer"] == "Example CA"


def test_shared_certificate_gives_shared_cert_and_no_pivots():
    doc = fx("cert_shared_documented.json")
    sha = doc["result"]["resource"]["fingerprint_sha256"]
    http = FakeHttp().add("GET", CERT.format(sha=sha), json=doc)
    res = run_module(Censys, f"cert_fingerprint:{sha}", http, keys=KEYS)
    assert res.status is Status.OK and not res.pivots
    (shared,) = res.attributes["shared_cert"]
    assert shared["san_count"] == 24 and "registrable domains" in shared["reason"]


def test_domain_search_for_seeds_only():
    http = FakeHttp().add("POST", SEARCH, json=fx("search_ok_documented.json"), match_headers=AUTH)
    res = run_module(Censys, "domain:example.com", http, keys=KEYS)
    assert res.status is Status.OK
    body = json.loads(http.calls[0]["body"])
    assert body == {"query": 'host.dns.names: "example.com"', "page_size": 25}
    rel = {(p.relation, p.entity.value): p for p in res.pivots}
    assert rel[("resolves_to", "198.51.100.20")].expand is False
    assert rel[("has_certificate", "f1315fa063454bb3303d41c3b6c222afc9ec7c47880c2f63caa647d9d290e200")].expand is False
    assert rel[("subdomain", "www.example.com")].expand is True  # in the queried apex
    assert res.attributes["censys_web_properties"] == [{"hostname": "www.example.com", "port": 443}]
    # pivots (not analyst-typed seeds) never spend search credits
    assert run_module(Censys, "domain:example.com", FakeHttp(), keys=KEYS, is_seed=False, depth=1).status is Status.SKIPPED


def test_empty_search_is_empty():
    http = FakeHttp().add("POST", SEARCH, json=fx("search_empty_documented.json"))
    assert run_module(Censys, "keyword:acme login", http, keys=KEYS).status is Status.EMPTY


def test_missing_key_and_unlicensed_mode():
    http = FakeHttp()
    assert run_module(Censys, "ipv4:8.8.8.8", http).status is Status.NEEDS_KEY and not http.calls
    # the gate allowed only the commercial plan (key_plans.censys='business' recorded): that source is named
    http = FakeHttp().add("GET", HOST.format(ip="8.8.8.8"), json=fx("host_ok_documented.json"))
    res = run_module(Censys, "ipv4:8.8.8.8", http, keys=KEYS, allowed_sources=[SOURCE_COMMERCIAL])
    assert res.status is Status.OK and res.raw["source"] == SOURCE_COMMERCIAL


def test_parsers_are_defensive():
    for junk in (None, 1, "x", [], {"result": {}}, {"result": {"resource": "x"}}):
        assert parse_host(junk) is None
    for junk in (None, {}, {"fingerprint_sha256": "zz"}):
        assert parse_cert(junk) is None
    for junk in (None, {}, {"result": {"hits": "x"}}):
        assert parse_search(junk) is None
    host = parse_host({"result": {"resource": {"ip": "8.8.8.8", "services": [{"port": "x", "vulns": [{"id": "junk"}]}, 7]}}})
    assert host["vulns"] == [] and host["ports"] == []
