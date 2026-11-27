"""xposedornot (P137): check-email + breach-analytics, joined offline with the catalogues.

Fixtures in tests/fixtures/xposedornot/: ``check_email_ok.json`` (test@example.com, 12 of 215 ids),
``check_email_not_found.json`` (HTTP 200 {'Error': 'Not found'}), ``breach_analytics_ok.json`` (4 of 20
details, research sample), ``breach_analytics_not_found.json`` and ``catalogue_subset.json`` (14 of 801
entries) are trimmed live answers of 2026-11-25/26; ``check_email_not_found_404.json`` is the research
404 form, ``rate_limited_429.json`` and ``malformed.txt`` are synthetic; ``hibp_catalogue_subset.json``
is a trimmed copy of the HIBP catalogue the P132 helper joins names to.
"""

from __future__ import annotations

import copy
import json

import pytest

from tests.fakes import FakeHttp, module_fixture, run_module
from v3lum.core.context import ScanOptions
from v3lum.core.models import Status
from v3lum.core.orgprofile import OrgProfile
from v3lum.modules.breach_leak.xposedornot import XposedOrNot, parse_analytics, parse_catalogue, parse_check_email

MOD = XposedOrNot
API = "https://api.xposedornot.com/v1"
HIBP_CATALOGUE = "https://haveibeenpwned.com/api/v3/breaches"
OWN = "analyst@acme.com.br"
ORG = {"domains": [{"name": "acme.com.br", "verification": "txt_verified"}]}
SCOPE_ALL = ScanOptions(breach_scope="all", purpose="incident 2026-11 phishing triage")


@pytest.fixture(autouse=True)
def small_catalogues(monkeypatch):
    from v3lum.core import datasets
    from v3lum.modules.breach_leak import hibp_catalog as hc
    from v3lum.modules.breach_leak import xposedornot as xon

    monkeypatch.setattr(hc, "MIN_BREACHES", 5)
    monkeypatch.setattr(xon, "MIN_CATALOGUE", 5)
    monkeypatch.setitem(datasets.DATASETS[hc.CATALOG_DATASET], "min_bytes", 1)
    monkeypatch.setitem(datasets.DATASETS[xon.CATALOGUE_DATASET], "min_bytes", 1)


def fx(name):
    return module_fixture(MOD, name)


def org():
    return OrgProfile.from_dict(ORG)


def check(email):
    return f"{API}/check-email/{email.replace('@', '%40')}"


def analytics(email):
    return f"{API}/breach-analytics?email={email.replace('@', '%40')}"


def catalogues(http):
    http.add("GET", f"{API}/breaches", json=fx("catalogue_subset.json"))
    return http.add("GET", HIBP_CATALOGUE, json=fx("hibp_catalogue_subset.json")["body"])


def env(http, url, name):
    data = fx(name)
    body = data.get("body")
    if isinstance(body, (dict, list)):
        return http.add("GET", url, status=data["status"], json=body, headers=data.get("headers"))
    return http.add("GET", url, status=data["status"], text=body or "", headers=data.get("headers"))


def own_http(names):
    body = copy.deepcopy(fx("check_email_ok.json"))
    body["breaches"] = [names]
    body["email"] = OWN
    http = FakeHttp().add("GET", check(OWN), json=body)
    http.add("GET", analytics(OWN), json=fx("breach_analytics_ok.json"))
    return catalogues(http)


def test_own_address_breaches_joined_with_catalogues():
    http = own_http(["8tracks", "Zomato", "NetEase", "AlienStealerLogs", "Collection-1"])
    res = run_module(MOD, f"email:{OWN}", http, org_profile=org())
    assert res.status is Status.OK
    names = {f.data["name"]: f for f in res.findings if isinstance(f.data, dict) and "name" in f.data}
    assert {"8tracks", "Zomato", "AlienStealerLogs", "Collection-1", "Paidwork", "ACTMobile"} <= set(names)
    assert "NetEase" not in json.dumps([res.attributes, [f.to_dict() for f in res.findings]])  # XON 'sensitive': masked
    assert "sensitive breach (name withheld)" in names
    eight = names["8tracks"]
    assert eight.data["breach_key"] == "8tracks" and eight.data["sources"] == ["xposedornot.api"]
    assert eight.data["date"] == "2017-06-27"  # the HIBP catalogue's precise date wins over XON's month
    stealer = names["AlienStealerLogs"]
    assert stealer.severity.label == "high" and stealer.data["password_form"] == "plaintext"
    assert res.attributes["breach_risk"]["label"] == "Critical"
    blob = json.dumps([res.raw, res.attributes, [f.to_dict() for f in res.findings]], default=str)
    for dropped in ("logo", "static/logos", "gig economy platform", "23 billion rows"):
        assert dropped not in blob  # logos, descriptions and details are never kept (cond 5)
    http.assert_hosts_within(MOD, extra=("haveibeenpwned.com",))


def test_generic_address_follows_the_a4_generic_rule():
    http = FakeHttp().add("GET", check("test@example.com"), json=fx("check_email_ok.json"))
    http.add("GET", analytics("test@example.com"), json=fx("breach_analytics_ok.json"))
    catalogues(http)
    res = run_module(MOD, "email:test@example.com", http, options=SCOPE_ALL)
    assert [f.title for f in res.findings] == ["Generic or shared identity listed in breaches"]
    assert res.findings[0].severity.label == "info" and "context_only" in res.findings[0].tags


def test_not_found_forms_are_declared_absences():
    http = FakeHttp().add("GET", check(OWN), json=fx("check_email_not_found.json"))
    res = run_module(MOD, f"email:{OWN}", http, org_profile=org())
    assert res.status is Status.EMPTY and res.error == "not found in XposedOrNot"
    http2 = env(FakeHttp(), check(OWN), "check_email_not_found_404.json")
    assert run_module(MOD, f"email:{OWN}", http2, org_profile=org()).status is Status.EMPTY


def test_limits_and_errors_are_could_not_verify():
    http = env(FakeHttp(), check(OWN), "rate_limited_429.json")
    assert run_module(MOD, f"email:{OWN}", http, org_profile=org()).status in (Status.RATE_LIMITED, Status.QUOTA)
    http2 = FakeHttp().add("GET", check(OWN), json={"Error": "Rate limit exceeded, slow down"})
    assert run_module(MOD, f"email:{OWN}", http2, org_profile=org()).status is Status.RATE_LIMITED
    http3 = FakeHttp().add("GET", check(OWN), text=fx("malformed.txt"), headers={"content-type": "application/json"})
    assert run_module(MOD, f"email:{OWN}", http3, org_profile=org()).status is Status.ERROR
    http4 = FakeHttp().add("GET", check(OWN), json={"status": "weird"})
    assert run_module(MOD, f"email:{OWN}", http4, org_profile=org()).status is Status.ERROR
    page = "<html><head><title>Just a moment...</title></head><body>cf-chl-widget</body></html>"
    http5 = FakeHttp().add("GET", check(OWN), status=403, text=page)
    assert run_module(MOD, f"email:{OWN}", http5, org_profile=org()).status is Status.BLOCKED


def test_third_party_only_with_breach_scope_all_as_context():
    other = "jdoe@other-corp.com.br"
    http = FakeHttp()
    assert run_module(MOD, f"email:{other}", http, org_profile=org()).status is Status.SKIPPED
    assert http.calls == []
    body = copy.deepcopy(fx("check_email_ok.json"))
    body["breaches"] = [["8tracks", "Zomato"]]
    http = FakeHttp().add("GET", check(other), json=body)
    http.add("GET", analytics(other), json=fx("breach_analytics_not_found.json"))
    catalogues(http)
    res = run_module(MOD, f"email:{other}", http, options=SCOPE_ALL)
    assert res.status is Status.OK
    assert all("context_only" in f.tags and f.severity.label in ("info", "low", "medium") for f in res.findings)


def test_licence_skip_and_catalogue_outage():
    res = run_module(MOD, f"email:{OWN}", FakeHttp(), org_profile=org(), allowed_sources=["hibp.catalog"])
    assert res.status is Status.SKIPPED and res.reason_code == "licence"
    body = copy.deepcopy(fx("check_email_ok.json"))
    body["breaches"] = [["8tracks"]]
    http = FakeHttp().add("GET", check(OWN), json=body)
    http.add("GET", analytics(OWN), json=fx("breach_analytics_not_found.json"))
    http.add("GET", f"{API}/breaches", status=503, text="down", times=3)
    http.add("GET", HIBP_CATALOGUE, status=503, text="down", times=3)
    res2 = run_module(MOD, f"email:{OWN}", http, org_profile=org())
    assert res2.status is Status.OK and res2.source_statuses


def test_parsers_are_defensive():
    assert parse_check_email({"breaches": [["a", ["b", None]], 3]})["breaches"] == ["a", "b"]
    assert parse_check_email("x")["ok"] is False
    assert parse_analytics({"ExposedBreaches": None})["breaches"] == []
    assert parse_catalogue({"exposedBreaches": None}) == []
    cat = parse_catalogue(fx("catalogue_subset.json"))
    assert all(r["date"] is None or len(r["date"]) == 7 for r in cat)  # month precision upstream
