"""Offline tests of ipqualityscore (P052, veto_lift form) with the fixtures in tests/fixtures/ipqualityscore/.

The success fixtures are documentation-shaped (no company key exists yet, P052 FC7: a trimmed real
capture made with the company key replaces them before merge); the invalid-key answer is real.
"""

from __future__ import annotations

import ast
import inspect
from pathlib import Path

import pytest

from tests.fakes import FakeHttp, assert_no_secret, make_ctx, make_runtime, module_fixture, run_module
from v3lum import config, paths
from v3lum.core import providers
from v3lum.core.models import Severity, Status
from v3lum.core.orgprofile import OrgProfile
from v3lum.modules.ip_network import ipqualityscore as mod
from v3lum.modules.ip_network.ip_geolocation import EndpointRefused
from v3lum.modules.ip_network.ipqualityscore import IpQualityScore, hostile_evidence, ipqs_endpoint, parse_ip, parse_url

FIX = "ipqualityscore"
KEY = "QwErTy0123456789AbCdEfGhIjKlMnOp"  # fake 32-character key (never a real one)
KEYS = {"ipqs": KEY}
IP_URL = f"https://ipqualityscore.com/api/json/ip/{KEY}/8.8.8.8?strictness=0"
PHISH = "https://login-example.example/verify"
URL_URL = f"https://ipqualityscore.com/api/json/url/{KEY}/https%3A%2F%2Flogin-example.example%2Fverify?strictness=0"
HOSTILE = (("domain:login-example.example", "listed_phishing_url", "phishstats"),)


def fx(name: str):
    return module_fixture(FIX, name)


def ip_route(**kw) -> FakeHttp:
    return FakeHttp().add("GET", IP_URL, **kw)


# --------------------------------------------------------------------------------------
# metadata and FC1 (no e-mail / phone endpoint can exist)
# --------------------------------------------------------------------------------------


def test_metadata_follows_the_council_decision():
    cls = IpQualityScore
    assert {t.value for t in cls.accepts} == {"ipv4", "url"}  # FC1: e-mail and phone removed
    assert cls.produces == frozenset()
    assert (cls.terms, cls.default_enabled, cls.trust_tier, cls.requires_keys) == ("key-terms", False, "trusted", ("ipqs",))
    spec = config.key_registry()["ipqs"]
    assert "V3LUM_IPQS_KEY" in spec.env and spec.provider == "ipqualityscore"  # FC3
    prov = providers.registry().get("ipqualityscore")
    assert prov.quota.month == 1000  # FC6: monthly budget (P334)
    assert prov.extra["x_source_flags"]["url"] == {"reuses_queries": True, "fetches_target": True}  # FC2 recorded as data


@pytest.mark.parametrize("kind", ["email", "phone", "EMAIL", "Phone", "mobile", "", "ip/../email", "json/email"])
def test_email_and_phone_endpoints_cannot_be_built(kind):
    with pytest.raises(EndpointRefused):
        ipqs_endpoint(kind, KEY, "someone@example.com")


def test_no_request_path_other_than_ip_and_url_exists():
    tree = ast.parse(inspect.getsource(mod))
    docstrings = {id(node.body[0].value) for node in ast.walk(tree)
                  if isinstance(node, (ast.Module, ast.FunctionDef, ast.ClassDef)) and node.body
                  and isinstance(node.body[0], ast.Expr) and isinstance(node.body[0].value, ast.Constant)}
    literals = [n.value for n in ast.walk(tree) if isinstance(n, ast.Constant) and isinstance(n.value, str) and id(n) not in docstrings]
    assert not [s for s in literals if "json/email" in s or "json/phone" in s]
    crafted = ipqs_endpoint("url", KEY, "https://a.example/../../email/x?y=/api/json/email/")
    assert crafted.startswith(f"https://ipqualityscore.com/api/json/url/{KEY}/https%3A%2F%2F")
    assert crafted.count("/") == 7  # the URL value is one fully encoded path segment
    with pytest.raises(ValueError):
        ipqs_endpoint("ip", KEY, "10.0.0.1")  # bogons are never sent
    with pytest.raises(ValueError):
        ipqs_endpoint("ip", "bad/key", "8.8.8.8")


# --------------------------------------------------------------------------------------
# IP reputation (FC4, FC5, FC6)
# --------------------------------------------------------------------------------------


def test_high_fraud_score_is_one_low_suspicious_vote_never_malicious():
    http = ip_route(json=fx("ip_ok_synthetic.json"))
    res = run_module(IpQualityScore, "ipv4:8.8.8.8", http, keys=KEYS)
    assert res.status is Status.OK
    (finding,) = res.findings
    assert finding.severity is Severity.LOW and "suspicious" in finding.tags and "malicious" not in finding.tags
    assert {"vpn", "proxy"} <= set(finding.tags) and finding.source == "ipqualityscore.ip"
    rec = res.attributes["ipqs_ip"]
    assert rec["fraud_score"] == 88 and rec["vote"] == "suspicious" and rec["asn"] is None  # AS64500 is reserved
    assert res.attributes["reputation"] == {"ipqualityscore": "suspicious (fraud score 88/100)"}
    assert not {"city", "region", "latitude", "longitude"} & set(rec) and "Sao Paulo" not in str(res.raw)
    assert not res.pivots
    http.assert_hosts_within(IpQualityScore)
    assert_no_secret(KEY, res)  # FC5: the path-embedded key never reaches the result


def test_low_fraud_score_is_context_only():
    doc = dict(fx("ip_ok_synthetic.json"), fraud_score=10, proxy=False, vpn=False, recent_abuse=False)
    res = run_module(IpQualityScore, "ipv4:8.8.8.8", ip_route(json=doc), keys=KEYS)
    (finding,) = res.findings
    assert finding.severity is Severity.INFO and "context_only" in finding.tags
    assert res.attributes["ipqs_ip"]["vote"] == "no_signal"


def test_key_never_reaches_cache_rows_events_or_errors():
    http = ip_route(json=fx("ip_ok_synthetic.json"))
    events = []
    rt = make_runtime(http, keys=KEYS, cache=True)
    rt.events.subscribe(lambda kind, payload: events.append((kind, payload)))
    res = run_module(IpQualityScore, "ipv4:8.8.8.8", http, runtime=rt)
    assert res.status is Status.OK
    cache_files = [p for p in Path(paths.home()).rglob("*") if p.is_file() and "cache" in p.name]
    assert cache_files, "the HTTP cache was used"
    assert_no_secret(KEY, res, *cache_files, [str(e) for e in events])
    failed = run_module(IpQualityScore, "ipv4:8.8.8.8", ip_route(status=500, text=f"error at /api/json/ip/{KEY}/8.8.8.8"), keys=KEYS)
    assert failed.status is Status.ERROR
    assert_no_secret(KEY, failed)


def test_success_false_bodies_map_to_needs_key_quota_or_error_never_empty():
    res = run_module(IpQualityScore, "ipv4:8.8.8.8", ip_route(json=fx("invalid_key.json")), keys=KEYS)
    assert res.status is Status.NEEDS_KEY and res.reason_code == "needs_key"
    res = run_module(IpQualityScore, "ipv4:8.8.8.8", ip_route(json=fx("insufficient_credits_documented.json")), keys=KEYS)
    assert res.status is Status.QUOTA and res.reason_code == "quota"
    res = run_module(IpQualityScore, "ipv4:8.8.8.8", ip_route(json=fx("invalid_ip_documented.json")), keys=KEYS)
    assert res.status is Status.ERROR and "Invalid IPv4 address" in res.error
    res = run_module(IpQualityScore, "ipv4:8.8.8.8", ip_route(json={"success": False, "message": "Too many requests per second."}), keys=KEYS)
    assert res.status is Status.RATE_LIMITED


def test_http_failures_are_could_not_verify():
    page = "<html><head><title>Just a moment...</title></head><body>cf-chl-widget</body></html>"
    cases = [(dict(status=429, text="slow down"), Status.RATE_LIMITED), (dict(status=403, text=page), Status.BLOCKED),
             (dict(status=503, text="down"), Status.ERROR), (dict(text="{not json", headers={"content-type": "application/json"}), Status.ERROR),
             (dict(json={"success": True, "message": "Success."}), Status.ERROR), (dict(json=["x"]), Status.ERROR)]
    for kw, expected in cases:
        assert run_module(IpQualityScore, "ipv4:8.8.8.8", ip_route(**kw), keys=KEYS).status is expected, kw


def test_without_a_key_nothing_is_sent():
    http = FakeHttp()
    res = run_module(IpQualityScore, "ipv4:8.8.8.8", http)
    assert res.status is Status.NEEDS_KEY and http.calls == []
    assert run_module(IpQualityScore, "ipv4:10.0.0.1", http, keys=KEYS).status is Status.SKIPPED and http.calls == []


# --------------------------------------------------------------------------------------
# URL reputation gate (FC2)
# --------------------------------------------------------------------------------------


def test_url_reputation_is_skipped_at_amber_and_above():
    http = FakeHttp()
    for level in ("amber", "amber+strict", "red"):
        res = run_module(IpQualityScore, f"url:{PHISH}", http, keys=KEYS, tlp=level, provenance=HOSTILE, is_seed=False, depth=1)
        assert res.status is Status.SKIPPED and res.reason_code == "tlp", level
    assert http.calls == []


def test_hostile_url_at_green_gets_one_vote():
    http = FakeHttp().add("GET", URL_URL, json=fx("url_phishing_synthetic.json"))
    res = run_module(IpQualityScore, f"url:{PHISH}", http, keys=KEYS, tlp="green", provenance=HOSTILE, is_seed=False, depth=1)
    assert res.status is Status.OK
    (finding,) = res.findings
    assert finding.severity is Severity.LOW and finding.tags == ["suspicious"] and finding.source == "ipqualityscore.url"
    assert res.attributes["ipqs_url"]["flags"] == ["phishing", "unsafe", "suspicious"]
    assert_no_secret(KEY, res)
    http.assert_hosts_within(IpQualityScore)


def test_url_not_tagged_hostile_internal_own_or_token_is_never_sent():
    http = FakeHttp()
    org = OrgProfile.from_dict({"domains": [{"name": "example.org", "verification": "attested", "attested_by": "cti", "attested_date": "2026-11-01"}]})
    cases = [
        ("https://unknown-site.example/page", {}, "not_applicable"),
        ("http://intranet/login", {"provenance": HOSTILE, "is_seed": False, "depth": 1}, "policy"),
        ("https://10.0.0.5/x", {"provenance": HOSTILE, "is_seed": False, "depth": 1}, "policy"),
        ("https://portal.corp/x", {"provenance": HOSTILE, "is_seed": False, "depth": 1}, "policy"),
        ("https://www.example.org/login", {"provenance": HOSTILE, "is_seed": False, "depth": 1, "org_profile": org}, "policy"),
        ("https://phish.example/r?u=someone%40example.com", {"provenance": HOSTILE, "is_seed": False, "depth": 1}, "policy"),
    ]
    for url, kw, code in cases:
        res = run_module(IpQualityScore, f"url:{url}", http, keys=KEYS, tlp="green", **kw)
        assert res.status is Status.SKIPPED and res.reason_code == code, (url, res.error)
    assert http.calls == []


def test_entity_tags_exposed_by_the_core_count_as_hostile():
    ctx = make_ctx(IpQualityScore, FakeHttp(), keys=KEYS, entity=f"url:{PHISH}", tlp="green")
    assert hostile_evidence(ctx.entity, ctx) == ""
    ctx.entity_tags = lambda: ["phishing"]
    assert hostile_evidence(ctx.entity, ctx) == "tagged phishing in the case"


def test_parsers_are_defensive():
    assert parse_ip({"success": False}) is None and parse_ip("x") is None
    assert parse_ip({"success": True, "fraud_score": 400})["fraud_score"] is None
    assert parse_url(fx("url_ok_synthetic.json"))["vote"] == "no_signal"
    assert parse_url({"success": True, "risk_score": "90"})["vote"] == "suspicious"
