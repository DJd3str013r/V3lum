"""Offline tests of zoomeye (P053) with the fixtures in tests/fixtures/zoomeye/.

The success fixture is documentation-shaped (no company key yet, P053 FC5: a trimmed real capture
made with the company key replaces it before merge); the 401 'login_required' answer is real.
"""

from __future__ import annotations

import base64
import json

import pytest

from tests.fakes import FakeHttp, assert_no_secret, module_fixture, run_module
from v3lum import config
from v3lum.core.entities import EntityType as T
from v3lum.core.models import Status
from v3lum.core.tlp import TLP
from v3lum.modules.ip_network import zoomeye as mod
from v3lum.modules.ip_network.ip_geolocation import EndpointRefused
from v3lum.modules.ip_network.zoomeye import SEARCH_URL, ZoomEye, parse_search, search_body, web_link, zoomeye_query

FIX = "zoomeye"
KEY = "zz-test-key-0123456789abcdef"  # fake key
KEYS = {"zoomeye": KEY}


def fx(name: str):
    return module_fixture(FIX, name)


def route(**kw) -> FakeHttp:
    return FakeHttp().add("POST", SEARCH_URL, **kw)


def test_metadata_follows_the_council_decision():
    cls = ZoomEye
    assert cls.trust_tier == "unknown" and cls.max_tlp == TLP.GREEN  # FC1: excluded at AMBER and above
    assert (cls.terms, cls.default_enabled, cls.requires_keys) == ("key-terms", False, ("zoomeye",))
    assert {t.value for t in cls.accepts} == {"ipv4", "ipv6", "cidr", "domain", "favicon_hash"}  # IOC_TYPES only
    assert T.KEYWORD not in cls.accepts
    assert "V3LUM_ZOOMEYE_KEY" in config.key_registry()["zoomeye"].env
    assert cls.hosts == ("api.zoomeye.ai",)  # the web deep link host is never requested (FC5)


def test_selectors_are_validated_and_non_ioc_types_refused():
    assert zoomeye_query(T.IPV4, "8.8.8.8") == 'ip="8.8.8.8"'
    assert zoomeye_query(T.CIDR, "8.8.8.0/24") == 'cidr="8.8.8.0/24"'
    assert zoomeye_query(T.DOMAIN, "Example.COM.") == 'domain="example.com"'
    assert zoomeye_query(T.FAVICON_HASH, "-1234567") == 'iconhash="-1234567"'
    for etype in (T.KEYWORD, T.EMAIL, T.PHONE, T.ORG, T.USERNAME, T.URL):
        with pytest.raises(EndpointRefused):
            zoomeye_query(etype, "x")
    for etype, bad in ((T.IPV4, "10.0.0.1"), (T.CIDR, "192.168.0.0/16"), (T.DOMAIN, 'a" || port="22'), (T.FAVICON_HASH, "abc")):
        with pytest.raises(ValueError):
            zoomeye_query(etype, bad)


def test_search_posts_a_base64_query_with_the_key_only_in_the_header():
    http = route(json=fx("search_ok_synthetic.json"), match_headers={"API-KEY": KEY})
    res = run_module(ZoomEye, "ipv4:8.8.8.8", http, keys=KEYS)
    assert res.status is Status.OK
    (call,) = http.calls
    body = json.loads(call["body"])
    assert base64.b64decode(body["qbase64"]).decode() == 'ip="8.8.8.8"' and body["pagesize"] == 20
    assert KEY not in call["url"] and KEY not in call["body"].decode() if isinstance(call["body"], bytes) else KEY not in str(call["body"])
    assets = res.attributes["zoomeye_assets"]
    assert assets["total"] == 3 and len(assets["rows"]) == 3
    assert res.attributes["open_ports"] == [80, 443]  # the honeypot row (22) is not a service of the host
    pivots = sorted(p.entity.value for p in res.pivots)
    assert pivots == ["shop.example.com", "www.example.com"]
    assert all(p.expand is False and p.relation == "hosted_domain" and p.confidence <= 0.4 for p in res.pivots)
    (finding,) = res.findings
    assert "1 flagged as honeypot" in finding.description and "unknown_operator" in finding.tags
    assert any(url.startswith("https://www.zoomeye.ai/searchResult?q=") for _, url in res.links)
    assert_no_secret(KEY, res)
    http.assert_hosts_within(ZoomEye)


def test_shared_hosting_selectors_give_a_count_only(monkeypatch):
    many = dict(fx("search_ok_synthetic.json"))
    many["data"] = [{"ip": "8.8.8.8", "port": 443, "domain": f"site{i}.example.com", "honeypot": 0} for i in range(30)]
    res = run_module(ZoomEye, "ipv4:8.8.8.8", route(json=many), keys=KEYS)
    assert not res.pivots and res.attributes["cohosting"]["mode"] == "count_only" and res.attributes["cohosting"]["count"] == 30
    monkeypatch.setattr(mod.noise, "is_cdn", lambda entity: True)
    res = run_module(ZoomEye, "ipv4:8.8.8.8", route(json=fx("search_ok_synthetic.json")), keys=KEYS)
    assert not res.pivots and "CDN" in res.attributes["cohosting"]["reason"]


def test_empty_search_is_a_documented_absence():
    res = run_module(ZoomEye, "domain:example.com", route(json=fx("search_empty_synthetic.json")), keys=KEYS)
    assert res.status is Status.EMPTY


def test_error_bodies_are_needs_key_quota_or_error_never_empty():
    res = run_module(ZoomEye, "ipv4:8.8.8.8", route(status=401, json=fx("nokey_401.json")), keys=KEYS)
    assert res.status is Status.NEEDS_KEY
    res = run_module(ZoomEye, "ipv4:8.8.8.8", route(json={"code": 50001, "error": "invalid_request", "message": "bad query"}), keys=KEYS)
    assert res.status is Status.ERROR
    res = run_module(ZoomEye, "ipv4:8.8.8.8", route(json={"code": 50002, "message": "Insufficient points, please recharge"}), keys=KEYS)
    assert res.status is Status.QUOTA
    res = run_module(ZoomEye, "ipv4:8.8.8.8", route(json={"code": 60000, "data": "oops"}), keys=KEYS)
    assert res.status is Status.ERROR
    assert run_module(ZoomEye, "ipv4:8.8.8.8", route(status=429, text="slow down"), keys=KEYS).status is Status.RATE_LIMITED
    assert run_module(ZoomEye, "ipv4:8.8.8.8", route(status=502, text="bad gateway"), keys=KEYS).status is Status.ERROR
    assert run_module(ZoomEye, "ipv4:8.8.8.8", route(text="<html>maintenance</html>"), keys=KEYS).status is Status.ERROR


def test_without_key_or_with_a_non_ioc_value_nothing_is_sent():
    http = FakeHttp()
    assert run_module(ZoomEye, "ipv4:8.8.8.8", http).status is Status.NEEDS_KEY
    assert run_module(ZoomEye, "ipv4:192.168.1.1", http, keys=KEYS).status is Status.SKIPPED
    assert http.calls == []


def test_helpers():
    assert search_body('ip="8.8.8.8"')["qbase64"] == base64.b64encode(b'ip="8.8.8.8"').decode()
    assert "API-KEY" not in json.dumps(search_body("x"))
    assert web_link('ip="8.8.8.8"').startswith("https://www.zoomeye.ai/searchResult?q=")
    assert parse_search({"code": 60000, "data": [{"ip": "8.8.8.8", "asn": 64500, "honeypot": 1, "domain": "x.example.com"}]})["domains"] == []
    assert parse_search(fx("nokey_401.json")) is None
