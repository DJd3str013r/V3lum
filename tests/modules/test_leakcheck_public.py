"""leakcheck_public (P135): LeakCheck public API only - found count, source names/dates, field NAMES.

Fixtures in tests/fixtures/leakcheck_public/: ``email_generic.json`` (test@example.com, found 1715),
``username_org.json`` (handle 'github', found 1000), ``not_found.json`` and ``error_too_short.json`` are
trimmed live answers of 2026-11-26; ``email_small.json`` (a non-generic count), ``limit_body.json`` and
``rate_limited_429.json`` are synthetic (not provoked); ``hibp_catalogue_subset.json`` is a trimmed copy
of the keyless HIBP catalogue the P132 helper joins source names to.
"""

from __future__ import annotations

import json

import pytest

from tests.fakes import FakeHttp, module_fixture, run_module
from v3lum.core.context import ScanOptions
from v3lum.core.models import Status
from v3lum.core.orgprofile import OrgProfile
from v3lum.modules.breach_leak.leakcheck_public import (
    LeakcheckPublic,
    leakcheck_public_url,
    leakcheck_url_allowed,
    parse_public,
)

MOD = LeakcheckPublic
CATALOGUE = "https://haveibeenpwned.com/api/v3/breaches"
OWN = "analyst@acme.com.br"
ORG = {"domains": [{"name": "acme.com.br", "verification": "attested", "attested_by": "fixture analyst", "attested_date": "2026-11-26"}]}
SCOPE_ALL = ScanOptions(breach_scope="all", purpose="incident 2026-11 phishing triage")


@pytest.fixture(autouse=True)
def small_catalogue(monkeypatch):
    """The trimmed HIBP catalogue has a few breaches; the production floor (500) guards real downloads."""
    from v3lum.core import datasets
    from v3lum.modules.breach_leak import hibp_catalog as hc

    monkeypatch.setattr(hc, "MIN_BREACHES", 5)
    monkeypatch.setitem(datasets.DATASETS[hc.CATALOG_DATASET], "min_bytes", 1)


def fx(name):
    return module_fixture(MOD, name)


def url(value):
    return leakcheck_public_url(value)


def env(http, u, name):
    data = fx(name)
    if isinstance(data, dict) and data.get("_envelope"):
        body = data.get("body")
        if isinstance(body, (dict, list)):
            return http.add("GET", u, status=data["status"], json=body, headers=data.get("headers"))
        return http.add("GET", u, status=data["status"], text=body or "", headers=data.get("headers"))
    return http.add("GET", u, json=data)


def with_catalogue(http):
    return http.add("GET", CATALOGUE, json=fx("hibp_catalogue_subset.json")["body"])


def org():
    return OrgProfile.from_dict(ORG)


def test_only_the_public_endpoint_can_be_built():
    assert url(OWN) == "https://leakcheck.io/api/public?check=analyst%40acme.com.br"
    assert leakcheck_url_allowed(url(OWN))
    for bad in ("https://leakcheck.io/api/v2/query/analyst@acme.com.br", "https://leakcheck.io/api/public?check=x&type=email",
                "http://leakcheck.io/api/public?check=abc", "https://evil.example/api/public?check=abc",
                "https://leakcheck.io/api/public?check=", "https://leakcheck.io/api/public?key=abc&check=abc"):
        assert not leakcheck_url_allowed(bad)
    import v3lum.modules.breach_leak.leakcheck_public as mod

    source = json.dumps([v for k, v in vars(mod).items() if isinstance(v, str)])
    assert "/api/v2" not in source and "lookup" not in mod.PUBLIC_API  # cond 3: no v2 'lookup' builder or constant
    with pytest.raises(ValueError):
        leakcheck_public_url("ab")


def test_own_address_sources_are_joined_and_masked():
    http = with_catalogue(env(FakeHttp(), url(OWN), "email_small.json"))
    res = run_module(MOD, f"email:{OWN}", http, org_profile=org())
    assert res.status is Status.OK
    assert res.attributes["breach_hit_count"] == 3
    names = {f.data["name"]: f for f in res.findings}
    assert "8Tracks.com" in names and names["8Tracks.com"].data["breach_key"] == "8tracks"
    assert names["8Tracks.com"].data["date"] == "2017-06-27" and "Passwords" in names["8Tracks.com"].data["data_classes"]
    assert "sensitive breach (name withheld)" in names  # Hjedd.com -> HIBP Hjedd (IsSensitive)
    assert "Hjedd" not in json.dumps([res.attributes, [f.to_dict() for f in res.findings]])
    classes = res.attributes["breach_data_classes"]
    assert "Passwords" in classes and "IP addresses" in classes  # field NAMES only
    assert any("LeakCheck" in label for label, _ in res.links)
    http.assert_hosts_within(MOD, extra=("haveibeenpwned.com",))


def test_found_over_100_is_a_generic_value_never_scored():
    http = with_catalogue(env(FakeHttp(), url("test@example.com"), "email_generic.json"))
    res = run_module(MOD, "email:test@example.com", http, options=SCOPE_ALL)
    assert res.status is Status.OK
    assert res.attributes["breach_hit_count"] == 1715
    assert [f.title for f in res.findings] == ["Generic or shared identity listed in breaches"]
    f = res.findings[0]
    assert f.severity.label == "info" and "context_only" in f.tags and f.label.value == "possible"
    assert res.attributes["generic_address"]


def test_username_only_as_typed_seed_with_breach_scope_all():
    http = FakeHttp()
    assert run_module(MOD, "username:github", http).status is Status.SKIPPED
    http = with_catalogue(env(FakeHttp(), url("github"), "username_org.json"))
    res = run_module(MOD, "username:github", http, options=SCOPE_ALL)
    assert res.status is Status.OK
    assert res.attributes["generic_address"].startswith("shared (LeakCheck found 1000)")
    assert all("context_only" in f.tags for f in res.findings)


def test_not_found_is_a_declared_absence():
    http = env(FakeHttp(), url(OWN), "not_found.json")
    res = run_module(MOD, f"email:{OWN}", http, org_profile=org())
    assert res.status is Status.EMPTY and res.error == "not found in LeakCheck"


def test_error_in_200_and_limits_are_never_empty():
    http = env(FakeHttp(), url(OWN), "error_too_short.json")
    assert run_module(MOD, f"email:{OWN}", http, org_profile=org()).status is Status.ERROR
    http = env(FakeHttp(), url(OWN), "limit_body.json")
    res = run_module(MOD, f"email:{OWN}", http, org_profile=org())
    assert res.status is Status.QUOTA and res.reason_code == "quota"  # provider exhausted for the day
    http = env(FakeHttp(), url(OWN), "rate_limited_429.json")
    assert run_module(MOD, f"email:{OWN}", http, org_profile=org()).status in (Status.QUOTA, Status.RATE_LIMITED)
    page = "<html><head><title>Just a moment...</title></head><body>cf-chl-widget</body></html>"
    http = FakeHttp().add("GET", url(OWN), status=403, text=page)
    assert run_module(MOD, f"email:{OWN}", http, org_profile=org()).status is Status.BLOCKED


def test_malformed_answer_is_an_error():
    http = FakeHttp().add("GET", url(OWN), text="{not json", headers={"content-type": "application/json"})
    assert run_module(MOD, f"email:{OWN}", http, org_profile=org()).status is Status.ERROR
    assert parse_public(["x"])["state"] == "error"


def test_third_party_without_breach_scope_is_skipped_privacy():
    http = FakeHttp()
    res = run_module(MOD, "email:jdoe@other-corp.com.br", http, org_profile=org())
    assert res.status is Status.SKIPPED and res.reason_code == "privacy"
    assert http.calls == []


def test_catalogue_unavailable_still_reports_sources(monkeypatch):
    http = env(FakeHttp(), url(OWN), "email_small.json")
    http.add("GET", CATALOGUE, status=503, text="unavailable", times=3)
    res = run_module(MOD, f"email:{OWN}", http, org_profile=org())
    assert res.status is Status.OK
    assert any(s == "hibp.catalog" for s in res.source_statuses) or res.source_statuses


def test_licence_skip_when_terms_not_cleared():
    res = run_module(MOD, f"email:{OWN}", FakeHttp(), org_profile=org(), allowed_sources=["hibp.catalog"])
    assert res.status is Status.SKIPPED and res.reason_code == "licence"
