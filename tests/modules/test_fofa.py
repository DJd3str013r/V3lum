"""Offline tests of fofa (P049) with the fixtures in tests/fixtures/fofa/.

No paid key exists (P049 cond 6): search_*_documented.json follow the official fofa-py client
docstring (values on documentation space) and the error bodies inside HTTP 200 are synthetic in the
documented {"error": true, "errmsg": "[code] text"} form.
"""

from __future__ import annotations

import base64
from urllib.parse import parse_qs, urlsplit

import pytest

from tests.fakes import FakeHttp, assert_no_secret, module_fixture, run_module
from v3lum.core.context import ScanOptions
from v3lum.core.entities import EntityType as T
from v3lum.core.models import Opsec, Status
from v3lum.core.orgprofile import OrgProfile
from v3lum.core.tlp import TLP
from v3lum.modules.ip_network.fofa import SEARCH_URL, Fofa, fofa_query, parse_search
from v3lum.modules.ip_network.scan_engines import EndpointRefused

FIX = "fofa"
KEY = "fofa0123456789abcdef0123456789ab"  # fake key
KEYS = {"fofa_key": KEY}


def fx(name: str):
    return module_fixture(FIX, name)


def route(**kw) -> FakeHttp:
    return FakeHttp().add("GET", SEARCH_URL + "*", **kw)


def test_metadata_follows_the_council_decision():
    cls = Fofa
    assert (cls.terms, cls.default_enabled, cls.trust_tier, cls.requires_keys) == ("license", False, "unknown", ("fofa_key",))
    assert cls.max_tlp == TLP.GREEN  # c2: excluded at AMBER, AMBER+STRICT and RED
    assert {t.value for t in cls.accepts} == {"ipv4", "domain", "cert_fingerprint", "favicon_hash"}
    assert cls.manual_link == ""  # c5: FOFA manual links come from the G14 pack (pivots_ip_network)
    assert cls.cache_ttl == 604800


def test_only_ioc_selectors_and_no_query_injection():
    assert fofa_query(T.DOMAIN, "Example.COM") == 'domain="example.com"'
    assert fofa_query(T.IPV4, "8.8.8.8") == 'ip="8.8.8.8"'
    assert fofa_query(T.FAVICON_HASH, "-247388890") == 'icon_hash="-247388890"'
    sha = "90e589015dcbbb7728e13da5313f08161a476c588a90908d32ddba9dd63f5096"
    assert fofa_query(T.CERT_FP, sha) == f'cert="{sha}"'
    for etype in (T.EMAIL, T.PHONE, T.USERNAME, T.KEYWORD, T.URL, T.CNPJ, T.CPF, T.IPV6):
        with pytest.raises(EndpointRefused):
            fofa_query(etype, "x")
    for etype, bad in ((T.IPV4, "10.0.0.1"), (T.DOMAIN, 'x.com" || ip="1.1.1.1'), (T.FAVICON_HASH, "1 || 2"), (T.CERT_FP, "zz")):
        with pytest.raises(ValueError):
            fofa_query(etype, bad)


def test_search_with_base64_query_and_expand_false_pivots():
    http = route(json=fx("search_ok_documented.json"))
    res = run_module(Fofa, "domain:example.com", http, keys=KEYS)
    assert res.status is Status.OK
    (call,) = http.calls
    qs = parse_qs(urlsplit(call["url"]).query)
    assert base64.b64decode(qs["qbase64"][0]).decode() == 'domain="example.com"'
    assert qs["fields"] == ["host,ip,port,title"] and qs["key"] == [KEY]  # FOFA takes the key in the URL only
    assets = res.attributes["fofa_assets"]
    assert assets["total"] == 2 and len(assets["rows"]) == 2
    assert {(p.relation, p.entity.value) for p in res.pivots} == {
        ("resolves_to", "198.51.100.40"), ("resolves_to", "198.51.100.41"), ("scanner_match", "www.example.com")}
    assert all(p.expand is False for p in res.pivots)  # c4
    (finding,) = res.findings
    assert "unknown_operator" in finding.tags
    assert_no_secret(KEY, res)  # AR01: the key never leaves the request URL
    http.assert_hosts_within(Fofa)


def test_empty_result_is_empty():
    assert run_module(Fofa, "ipv4:8.8.8.8", route(json=fx("search_empty_documented.json")), keys=KEYS).status is Status.EMPTY


@pytest.mark.parametrize(
    ("fixture", "status", "code"),
    [
        ("error_in_200_account_invalid_synthetic.json", Status.NEEDS_KEY, "needs_key"),
        ("error_in_200_fpoints_synthetic.json", Status.QUOTA, "quota"),
    ],
)
def test_errors_inside_200_are_never_empty(fixture, status, code):
    res = run_module(Fofa, "ipv4:8.8.8.8", route(json=fx(fixture)), keys=KEYS)
    assert res.status is status and res.reason_code == code
    assert KEY not in res.error


def test_other_errors_rate_limit_and_malformed():
    res = run_module(Fofa, "ipv4:8.8.8.8", route(json={"error": True, "errmsg": "[-1] unknown"}), keys=KEYS)
    assert res.status is Status.ERROR
    res = run_module(Fofa, "ipv4:8.8.8.8", route(json={"error": True, "errmsg": "[-9] request too frequent"}), keys=KEYS)
    assert res.status is Status.RATE_LIMITED
    assert run_module(Fofa, "ipv4:8.8.8.8", route(status=429, text="slow"), keys=KEYS).status is Status.RATE_LIMITED
    assert run_module(Fofa, "ipv4:8.8.8.8", route(status=502, text="bad", times=3), keys=KEYS).status is Status.ERROR
    assert run_module(Fofa, "ipv4:8.8.8.8", route(json={"results": []}), keys=KEYS).status is Status.ERROR


def test_without_key_nothing_is_sent():
    http = FakeHttp()
    res = run_module(Fofa, "domain:example.com", http)
    assert res.status is Status.NEEDS_KEY and not http.calls


def test_own_assets_and_engagements_are_never_sent():
    http = FakeHttp()
    org = OrgProfile.from_dict({"org": {"name": "Example Org"}, "domains": [{"name": "example.com", "verification": "attested",
                                                                         "attested_by": "analyst", "attested_date": "2026-11-01"}]})
    res = run_module(Fofa, "domain:www.example.com", http, keys=KEYS, org_profile=org)
    assert res.status is Status.SKIPPED and res.reason_code == "own_asset"
    res = run_module(Fofa, "ipv4:8.8.8.8", http, keys=KEYS, options=ScanOptions(mode=Opsec.LIGHT))
    assert res.status is Status.SKIPPED and res.reason_code in ("own_asset", "opsec")
    res = run_module(Fofa, "ipv4:8.8.8.8", http, keys=KEYS, options=ScanOptions(authorization_ref="ENG-2026-001"))
    assert res.status is Status.SKIPPED and res.reason_code == "own_asset"
    assert not http.calls


def test_parser_is_defensive():
    for junk in (None, [], {"error": True}, {"error": False, "results": "x"}, {"results": []}):
        assert parse_search(junk) is None
    parsed = parse_search({"error": False, "results": [["https://a.example.com:8443/x", "bad-ip", "99999", 7], "junk"]})
    assert parsed["rows"][0]["hostname"] == "a.example.com" and "ip" not in parsed["rows"][0] and "port" not in parsed["rows"][0]
