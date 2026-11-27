"""Offline tests of hunter_io (P090, own-domain search) with the fixtures in tests/fixtures/hunter_io/.

The 401 authentication_failed answer is a real research capture; the success answers are
documentation-shaped Hunter v2 bodies (no team key yet: P090 cond 6 keeps the merge gate open until a
trimmed real capture replaces them).
"""

from __future__ import annotations

import json
import re

import pytest

from tests.fakes import FakeHttp, assert_no_secret, module_fixture, run_module
from v3lum import config
from v3lum.core.models import Status
from v3lum.core.orgprofile import OrgProfile
from v3lum.modules.email import hunter_io as mod
from v3lum.modules.email.hunter_io import EndpointRefused, HunterIo, hunter_url, parse_domain_search

KEY = "hu-test-key-0123456789abcdef"  # fake key
KEYS = {"hunter": KEY}
COUNT = re.compile(r"^https://api\.hunter\.io/v2/email-count\?")
SEARCH = re.compile(r"^https://api\.hunter\.io/v2/domain-search\?")


def fx(name: str):
    return module_fixture("hunter_io", name)


def add(http: FakeHttp, url, item, **kw) -> FakeHttp:
    if isinstance(item, dict) and item.get("_envelope"):
        body = item["body"]
        extra = {"json": body} if isinstance(body, (dict, list)) else {"text": body}
        return http.add("GET", url, status=item["status"], headers=item.get("headers"), **extra, **kw)
    return http.add("GET", url, json=item, **kw)


def org(verification: str = "attested") -> OrgProfile:
    entry = {"name": "example.com", "verification": verification}
    if verification == "attested":
        entry.update(attested_by="Analyst Example", attested_date="2026-11-20")
    return OrgProfile.from_dict({"domains": [entry]})


def run(http: FakeHttp, value: str = "example.com", **kw):
    kw.setdefault("keys", KEYS)
    kw.setdefault("org_profile", org())
    return run_module(HunterIo, f"domain:{value}", http, **kw)


# ------------------------------------------------------------------------------------------ metadata
def test_metadata_follows_the_council_decision():
    cls = HunterIo
    assert (cls.terms, cls.default_enabled, cls.run_on) == ("key-terms", False, "own_assets_only")  # cond 2/5/6
    assert cls.requires_keys == ("hunter",) and cls.sensitive is True and cls.trust_tier == "trusted"
    assert set(cls.sources) == {"hunter.domain_search", "hunter.email_count"}
    assert {"HUNTER_API_KEY", "V3LUM_HUNTER_KEY"} <= set(config.key_registry()["hunter"].env)


def test_endpoint_allow_list_never_builds_the_verifier():
    for bad in ("email-verifier", "v2/email-verifier", "/email-verifier/", "verifier", "email-verification", "account", "leads"):
        with pytest.raises(EndpointRefused):
            hunter_url(bad, KEY, email="user@example.com")
    with pytest.raises(EndpointRefused):
        hunter_url("domain-search", KEY, domain="example.com", email="user@example.com")  # unknown parameter
    with pytest.raises(EndpointRefused):
        hunter_url("email-finder", KEY, domain="example.com", first_name="Ana")  # needs a last name
    url = hunter_url("domain-search", KEY, domain="Example.COM", limit=500)
    assert url.startswith("https://api.hunter.io/v2/domain-search?") and "limit=10" in url and "domain=example.com" in url
    assert "verif" not in " ".join(mod.HUNTER_ENDPOINTS)


# ------------------------------------------------------------------------------------------ happy path
def test_own_verified_domain_gets_pattern_counts_and_minimised_addresses():
    http = add(FakeHttp(), COUNT, fx("email_count_ok.json"))
    add(http, SEARCH, fx("domain_search_ok.json"))
    res = run(http)
    assert res.status is Status.OK, res.error
    assert res.attributes["email_pattern"] == "{first}.{last}"
    assert res.attributes["email_counts"]["total"] == 37
    addresses = res.attributes["own_domain_addresses"]
    assert addresses and all(set(a) == {"email", "type", "confidence", "department", "source_count", "first_seen", "last_seen"} for a in addresses)
    assert all(a["email"].endswith("@example.com") for a in addresses)
    # cond 4: names, positions, phones, social handles and Hunter's verification verdicts never survive
    dump = json.dumps({"a": res.attributes, "raw": res.raw, "f": [f.to_dict() for f in res.findings], "p": [p.note for p in res.pivots]})
    for gone in ("Maria", "Souza", "position", "phone_number", "linkedin", "twitter", "verification", "accept_all", "Sao Paulo"):
        assert gone not in dump, gone
    assert res.pivots and all(p.expand is False and p.relation == "published_address" for p in res.pivots)
    finding = res.findings[0]
    assert "privacy" in finding.tags and finding.source == "hunter.domain_search"
    assert "hunter_sender_check_patterns" in finding.description
    http.assert_hosts_within(HunterIo)
    assert_no_secret(KEY, res.to_dict())


def test_api_key_is_sent_only_in_the_query_and_never_leaks():
    http = add(FakeHttp(), COUNT, fx("email_count_ok.json"))
    add(http, SEARCH, fx("domain_search_ok.json"))
    res = run(http)
    assert all(f"api_key={KEY}" in c["url"] for c in http.calls)
    assert_no_secret(KEY, res.to_dict(), res.error)


def test_empty_domain_search_is_empty():
    body = dict(fx("email_count_ok.json"))
    body["data"] = dict(body["data"], total=0, personal_emails=0, generic_emails=0, department={}, seniority={})
    http = add(FakeHttp(), COUNT, body)
    add(http, SEARCH, fx("domain_search_empty.json"))
    res = run(http)
    assert res.status is Status.EMPTY


def test_third_party_addresses_are_never_returned_by_the_parser():
    parsed = parse_domain_search(fx("domain_search_ok.json"), own_domain=False)
    assert parsed["addresses"] is None and parsed["pattern"] == "{first}.{last}" and parsed["returned"] >= 1


# ------------------------------------------------------------------------------------------ gates
@pytest.mark.parametrize("verification", ["confirmed", "seeded"])
def test_unverified_own_domain_is_skipped_own_asset(verification):
    http = FakeHttp()
    res = run(http, org_profile=org(verification))
    assert res.status is Status.SKIPPED and res.reason_code == "own_asset"
    assert http.calls == []


def test_third_party_domain_is_skipped_own_asset_and_no_key_is_needs_key():
    http = FakeHttp()
    res = run(http, "example.org")
    assert res.status is Status.SKIPPED and res.reason_code == "own_asset"
    res = run(http, keys={})
    assert res.status is Status.NEEDS_KEY
    assert http.calls == []


# ------------------------------------------------------------------------------------------ errors (rule 5)
def test_401_authentication_failed_is_needs_key():
    http = add(FakeHttp(), COUNT, fx("needs_key_401.json"))
    res = run(http)
    assert res.status is Status.NEEDS_KEY and res.reason_code == "needs_key"


def test_403_rate_limit_and_429_credits():
    http = add(FakeHttp(), COUNT, fx("rate_limited_403.json"))
    res = run(http)
    assert res.status is Status.RATE_LIMITED and res.reason_code == "rate_limited"
    http = add(FakeHttp(), COUNT, fx("email_count_ok.json"))
    add(http, SEARCH, fx("quota_429.json"))
    res = run(http)
    assert res.status is Status.QUOTA and res.reason_code == "quota"


def test_400_5xx_and_malformed_bodies_are_errors():
    http = add(FakeHttp(), COUNT, fx("wrong_params_400.json"))
    assert run(http).status is Status.ERROR
    http = FakeHttp().add("GET", COUNT, status=502, text="bad gateway", times=2)
    assert run(http).status is Status.ERROR
    http = FakeHttp().add("GET", COUNT, text='{"data": {"total": 3', headers={"content-type": "application/json"})
    assert run(http).status is Status.ERROR
    http = add(FakeHttp(), COUNT, fx("email_count_ok.json"))
    add(http, SEARCH, {"data": ["unexpected"]})
    assert run(http).status is Status.ERROR
