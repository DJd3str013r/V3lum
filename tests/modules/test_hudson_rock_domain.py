"""hudson_rock_domain (P134 cond 5 and 8): stealer counts and infostealer-log URLs of a verified own domain.

Fixtures in tests/fixtures/hudson_rock_domain/: a search-by-domain answer (real counts and stealer
families; every URL, antivirus, application, password-statistics and third-party field is synthetic)
and an urls-by-domain answer (example.com hosts with synthetic user names, tokens and userinfo).
"""

from __future__ import annotations

import json

from tests.fakes import FakeHttp, make_runtime, module_fixture, run_module
from v3lum import paths
from v3lum.core.entities import EntityType as T
from v3lum.core.http import NetworkError
from v3lum.core.models import Status
from v3lum.core.orgprofile import OrgProfile
from v3lum.modules.breach_leak.hudson_rock import HudsonRockDomain

MOD = HudsonRockDomain
API = "https://cavalier.hudsonrock.com/api/json/v2/osint-tools/"
DOMAIN = API + "search-by-domain?domain=example.com"
URLS = API + "urls-by-domain?domain=example.com"
TIMEOUT = NetworkError("read timed out after 30 s", kind="ReadTimeout", reason_code="timeout", retryable=False)
#: synthetic values that must never survive (query strings, tokens, userinfo, user names, dropped fields)
NEVER = (
    "session=AbC123xYz789QwE456", "username=fixture.user", "fixture:secret", "fixture-user", "Zk9xQ2V4YW1wbGVUb2tlbjEyMzQ1Njc4OTA",
    "Fixture Antivirus", "fixture-app", "fixture-third-party.example.net", "fixture-logo.png", "totalPass", "too_weak",
    "last_employee_compromised", "is_shopify",
)


def fx(name):
    return module_fixture(MOD, name)


def org(verification="txt_verified"):
    return OrgProfile.from_dict({"domains": [{"name": "example.com", "verification": verification}]})


def both():
    return FakeHttp().add("GET", DOMAIN, json=fx("domain_ok.json")).add("GET", URLS, json=fx("urls_by_domain_ok.json"))


def test_counts_and_stripped_urls_for_a_verified_own_domain():
    http = both()
    res = run_module(MOD, "domain:example.com", http, org_profile=org())
    assert res.status is Status.OK
    exposure = res.attributes["stealer_exposure"]
    assert exposure["employees"] == 322 and exposure["users"] == 2730658 and exposure["third_parties"] == 142
    assert {"Vidar", "Raccoon", "Azorult"} <= set(exposure["stealer_families"])
    employees = next(f for f in res.findings if f.title == "Employee machines of this own domain in infostealer logs")
    assert employees.severity.label == "high" and employees.data["next_steps"] and "never used for login attempts" in employees.description
    urls = {p.entity.value: p for p in res.pivots if p.entity.type is T.URL}
    assert "https://sso.example.com/login" in urls and "https://ftp.example.com/files/report.pdf" in urls
    assert "https://gitlab.example.com/users/{redacted}/emails" in urls
    assert all(not p.expand and p.relation == "stealer_log_url" for p in urls.values())  # never contacted
    hosts = {p.entity.value for p in res.pivots if p.entity.type is T.DOMAIN}
    assert {"gitlab.example.com", "sso.example.com", "mail.example.com"} <= hosts
    assert all(not p.expand for p in res.pivots)
    http.assert_hosts_within(MOD)


def test_nothing_identifying_survives_and_urls_are_never_cached():
    http = both()
    rt = make_runtime(http, org_profile=org(), cache=True)
    res = run_module(MOD, "domain:example.com", runtime=rt)
    text = json.dumps([res.raw, res.attributes, [f.to_dict() for f in res.findings], [p.to_dict() for p in res.pivots]], default=str)
    stored = "\n".join(p.read_bytes().decode("utf-8", errors="replace") for p in paths.home().rglob("*") if p.is_file())
    for value in NEVER:
        assert value not in text, value
        assert value not in stored, value
    again = run_module(MOD, "domain:example.com", runtime=rt)
    assert again.cache_hits == 1  # search-by-domain is cached (sanitized); urls-by-domain never is
    assert [c["url"] for c in http.calls].count(URLS) == 2


def test_unverified_domains_are_never_queried():
    http = FakeHttp()
    seeded = run_module(MOD, "domain:example.com", http, org_profile=org("seeded"))
    assert seeded.status is Status.SKIPPED and seeded.reason_code == "own_asset"
    no_profile = run_module(MOD, "domain:example.com", http)
    assert no_profile.status is Status.SKIPPED and no_profile.reason_code == "own_asset"
    assert http.calls == []


def test_domain_search_timeout_keeps_the_url_feed():
    """The domain search hung > 70 s in research: 30 s per request, ERROR 'timeout' for that feed."""
    http = FakeHttp().add("GET", DOMAIN, error=TIMEOUT).add("GET", URLS, json=fx("urls_by_domain_ok.json"))
    res = run_module(MOD, "domain:example.com", http, org_profile=org())
    assert res.status is Status.OK
    assert res.source_statuses["hudsonrock.search_by_domain"] == {"status": "error", "reason_code": "timeout", "reason": res.source_statuses["hudsonrock.search_by_domain"]["reason"]}
    assert all(c["timeout"] is not None and c["timeout"] <= 30.0 for c in http.calls)
    both_down = FakeHttp().add("GET", DOMAIN, error=TIMEOUT).add("GET", URLS, error=TIMEOUT)
    res2 = run_module(MOD, "domain:example.com", both_down, org_profile=org())
    assert res2.status is Status.ERROR and res2.reason_code == "timeout" and not res2.attributes


def test_refusals_and_odd_answers_are_could_not_verify():
    limited = FakeHttp().add("GET", DOMAIN, status=429, text="Too Many Requests").add("GET", URLS, status=429, text="Too Many Requests")
    assert run_module(MOD, "domain:example.com", limited, org_profile=org()).status is Status.RATE_LIMITED
    odd = FakeHttp().add("GET", DOMAIN, json={"unexpected": True}).add("GET", URLS, json={"message": "no data key"})
    res = run_module(MOD, "domain:example.com", odd, org_profile=org())
    assert res.status is Status.ERROR and not res.attributes


def test_only_allowed_feeds_are_queried():
    http = FakeHttp().add("GET", URLS, json=fx("urls_by_domain_ok.json"))
    res = run_module(MOD, "domain:example.com", http, org_profile=org(), allowed_sources=["hudsonrock.urls_by_domain"])
    assert res.status is Status.OK and http.urls() == [URLS]


def test_metadata_matches_the_council_decision():
    assert MOD.run_on == "own_assets_only" and MOD.default_enabled is False and MOD.terms == "unknown"
    assert MOD.max_requests == 2 and MOD.sensitive is True
