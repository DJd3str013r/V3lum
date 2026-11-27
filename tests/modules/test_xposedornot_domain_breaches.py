"""xposedornot_domain_breaches (P137 cond 2): POST /v1/domain-breaches/ with the key 'xon', for
txt_verified/attested own domains only. ``needs_key_401.json`` is the research 401 answer;
``domain_breaches_ok.json`` is SYNTHETIC (the documented success shape with documentation addresses:
the keyed endpoint has not been called yet, re-capture with the team key is due).
"""

from __future__ import annotations

from tests.fakes import FakeHttp, module_fixture, run_module
from v3lum.core.models import Status
from v3lum.core.orgprofile import OrgProfile
from v3lum.modules.breach_leak.xposedornot import XposedOrNotDomainBreaches, parse_domain_breaches

MOD = XposedOrNotDomainBreaches
URL = "https://api.xposedornot.com/v1/domain-breaches/"
KEY = "xon-fixture-key-0123456789"
ORG = {"domains": [{"name": "example.com", "verification": "txt_verified"}, {"name": "seeded.example.net", "verification": "seeded"}]}


def org():
    return OrgProfile.from_dict(ORG)


def test_verified_own_domain_lists_addresses_for_analyst_selection():
    http = FakeHttp().add("POST", URL, json=module_fixture(XposedOrNotDomainBreaches, "domain_breaches_ok.json"), match_headers={"x-api-key": KEY})
    res = run_module(MOD, "domain:example.com", http, keys={"xon": KEY}, org_profile=org())
    assert res.status is Status.OK
    card = res.attributes["own_domain_breaches"]
    assert card["addresses"] == 2
    assert {b["name"]: b["addresses"] for b in card["breaches"]} == {"8tracks": 2, "Adobe": 1}
    emails = {p.entity.value for p in res.pivots}
    assert emails == {"user1@example.com", "user2@example.com"}  # other domains and junk rows dropped
    assert all(p.expand is False for p in res.pivots)
    assert res.findings[0].severity.label == "medium"
    http.assert_hosts_within(MOD)


def test_unverified_domains_are_skipped_without_a_request():
    http = FakeHttp()
    res = run_module(MOD, "domain:seeded.example.net", http, keys={"xon": KEY}, org_profile=org())
    assert res.status is Status.SKIPPED and res.reason_code == "own_asset"
    res2 = run_module(MOD, "domain:example.com", http, keys={"xon": KEY})
    assert res2.status is Status.SKIPPED
    assert http.calls == []


def test_401_is_needs_key_and_no_key_sends_nothing():
    data = module_fixture(XposedOrNotDomainBreaches, "needs_key_401.json")
    http = FakeHttp().add("POST", URL, status=data["status"], json=data["body"], headers=data["headers"])
    assert run_module(MOD, "domain:example.com", http, keys={"xon": KEY}, org_profile=org()).status is Status.NEEDS_KEY
    http2 = FakeHttp()
    assert run_module(MOD, "domain:example.com", http2, org_profile=org()).status is Status.NEEDS_KEY
    assert http2.calls == []


def test_errors_and_odd_answers_are_never_empty():
    http = FakeHttp().add("POST", URL, status=429, json={"detail": "Too many requests"})
    assert run_module(MOD, "domain:example.com", http, keys={"xon": KEY}, org_profile=org()).status in (Status.RATE_LIMITED, Status.QUOTA)
    http2 = FakeHttp().add("POST", URL, json={"status": "success"})
    assert run_module(MOD, "domain:example.com", http2, keys={"xon": KEY}, org_profile=org()).status is Status.ERROR
    assert parse_domain_breaches("x", "example.com") is None
