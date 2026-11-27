"""hibp_catalog (P132): HIBP keyless catalogue, local domain answers and the shared catalogue helper.

Recorded answers (2026-11-25/26) in tests/fixtures/hibp_catalog/: a trimmed /breaches catalogue (18
real breach objects; the one Attribution value is a synthetic example.org placeholder used to prove
the field is dropped), /breach/Adobe, /breaches?domain=adobe.com and ?domain=example.com, /dataclasses,
/latestbreach, the 404 'Not found' of an unknown name and the 401 of a keyed endpoint.
"""

from __future__ import annotations

import pytest

from tests.fakes import FakeClock, FakeHttp, assert_no_secret, make_ctx, make_runtime, module_fixture, run_module
from v3lum import paths
from v3lum.core.http import NetworkError
from v3lum.core.models import Status
from v3lum.modules.breach_leak import hibp_catalog as hc
from v3lum.modules.breach_leak.hibp_catalog import (
    CATALOG_URL,
    DATACLASSES_URL,
    LATEST_URL,
    SENSITIVE_BREACH_LABEL,
    HibpCatalog,
    breach_catalog,
    data_classes,
    password_form,
)

MOD = HibpCatalog
BREACH = "https://haveibeenpwned.com/api/v3/breach/{name}"
CHALLENGE = "<html><head><title>Just a moment...</title></head><body>cf-chl-widget</body></html>"


@pytest.fixture(autouse=True)
def small_catalogue(monkeypatch):
    """The trimmed fixture has 18 breaches; the production floor (500) guards real downloads."""
    monkeypatch.setattr(hc, "MIN_BREACHES", 10)
    from v3lum.core import datasets

    monkeypatch.setitem(datasets.DATASETS[hc.CATALOG_DATASET], "min_bytes", 1)


def fx(name):
    return module_fixture(MOD, name)


def catalogue_http():
    return FakeHttp().add("GET", CATALOG_URL, json=fx("catalog_ok.json"))


def by_title(res):
    return {f.title: f for f in res.findings}


# ------------------------------------------------------------------ domain lookups are local (C2, C6)
def test_domain_answered_locally_from_the_catalogue():
    http = catalogue_http()
    res = run_module(MOD, "domain:adobe.com", http)
    assert res.status is Status.OK
    assert http.urls() == [CATALOG_URL]  # the dataset download only: ?domain= is never called (C2)
    expected = {b["Name"] for b in fx("by_domain_ok.json")}  # HIBP's own ?domain=adobe.com answer
    assert {b["name"] for b in res.attributes["service_breaches"]} == expected
    entry = res.attributes["service_breaches"][0]
    assert entry["wording"] == "breaches of the service at adobe.com (this service was breached) - not accounts at this domain"
    assert entry["breach_date"] == "2013-10-04" and entry["pwn_count"] == 152445165 and entry["password_form"].startswith("hashed")
    finding = by_title(res)["HIBP: this service was breached"]
    assert finding.severity.label == "low" and finding.label.value == "confirmed"
    assert "this service was breached, not accounts at this domain" in finding.criterion  # C6 wording
    assert "https://haveibeenpwned.com/" in finding.references and "https://haveibeenpwned.com/Breach/Adobe" in finding.references
    assert ("Have I Been Pwned (CC BY 4.0)", "https://haveibeenpwned.com/") in res.links  # C7 attribution
    assert res.attributes["breach_count"] == 1
    assert res.raw["hibp.catalog"][0]["Name"] == "Adobe"
    http.assert_hosts_within(MOD)


def test_second_run_uses_the_local_copy():
    http = catalogue_http()
    run_module(MOD, "domain:adobe.com", http)
    rt = make_runtime(http)
    res = run_module(MOD, "domain:netshoes.com.br", runtime=rt)
    assert res.status is Status.OK and len(http.calls) == 1
    assert res.attributes["service_breaches"][0]["name"] == "Netshoes"


def test_domain_without_breach_is_empty():
    assert fx("by_domain_empty.json") == []  # HIBP's own answer for example.com
    res = run_module(MOD, "domain:example.com", catalogue_http())
    assert res.status is Status.EMPTY and not res.findings


def test_subdomain_falls_back_to_the_registrable_domain():
    res = run_module(MOD, "domain:accounts.adobe.com", catalogue_http())
    assert res.status is Status.OK and "adobe.com" in res.attributes["service_breaches"][0]["wording"]


def test_sensitive_breaches_are_masked_by_default(monkeypatch):
    res = run_module(MOD, "domain:adultfriendfinder.com", catalogue_http())
    names = {b["name"] for b in res.attributes["service_breaches"]}
    assert names == {SENSITIVE_BREACH_LABEL}
    assert all("AdultFriendFinder" not in (f.description + str(f.data)) for f in res.findings)
    assert all("haveibeenpwned.com/Breach/" not in r for f in res.findings for r in f.references)
    shown = run_module(MOD, "domain:adultfriendfinder.com", catalogue_http(), settings={"hibp_catalog_show_sensitive": True})
    assert any(b["name"].startswith("AdultFriendFinder") for b in shown.attributes["service_breaches"])


def test_spam_lists_and_fabricated_breaches_never_count_as_exposure():
    res = run_module(MOD, "domain:linkedin.com", catalogue_http())
    breaches = {b["name"]: b for b in res.attributes["service_breaches"]}
    assert breaches["LinkedInScrape2023"]["counts_as_exposure"] is False and breaches["LinkedIn"]["counts_as_exposure"] is True
    assert res.attributes["breach_count"] == 2  # LinkedIn + LinkedInScrape, not the spam list
    spam = by_title(res)["HIBP: spam list or fabricated breach (not exposure)"]
    assert spam.severity.label == "info" and "context_only" in spam.tags


# ------------------------------------------------------------------ keyword: a breach name
def test_breach_name_from_the_local_catalogue():
    res = run_module(MOD, "keyword:000webhost", catalogue_http())
    meta = res.attributes["breach_metadata"]
    assert meta["name"] == "000webhost" and meta["password_form"] == "plaintext" and meta["is_verified"] is True
    finding = by_title(res)["HIBP breach catalogue entry"]
    assert finding.source == "hibp.catalog" and finding.observed_first.startswith("2015-03-01")


def test_unknown_name_goes_to_breach_endpoint_and_404_is_empty():
    http = catalogue_http().add("GET", BREACH.format(name="NoSuchBreach"), status=404, text=fx("breach_not_found.txt"), headers={"content-type": "text/plain;charset=UTF-8"})
    res = run_module(MOD, "keyword:NoSuchBreach", http)
    assert res.status is Status.EMPTY
    adobe = fx("breach_single_ok.json")
    http2 = catalogue_http().add("GET", BREACH.format(name="NewBreach"), json={**adobe, "Name": "NewBreach", "Title": "New Breach"})
    res2 = run_module(MOD, "keyword:NewBreach", http2)
    assert res2.status is Status.OK and res2.attributes["breach_metadata"]["name"] == "NewBreach"


def test_refusals_are_could_not_verify():
    keyed = catalogue_http().add("GET", BREACH.format(name="Unknown1"), status=401, json=fx("needs_key.json"))
    assert run_module(MOD, "keyword:Unknown1", keyed).status is Status.BLOCKED  # keyless module: 401 is a refusal
    limited = catalogue_http().add("GET", BREACH.format(name="Unknown2"), status=429, text="Rate limit exceeded")
    assert run_module(MOD, "keyword:Unknown2", limited).status is Status.RATE_LIMITED
    challenge = catalogue_http().add("GET", BREACH.format(name="Unknown3"), status=200, text=CHALLENGE)
    assert run_module(MOD, "keyword:Unknown3", challenge).status is Status.BLOCKED
    down = catalogue_http().add("GET", BREACH.format(name="Unknown4"), status=503, text="unavailable")
    assert run_module(MOD, "keyword:Unknown4", down).status is Status.ERROR


def test_malformed_and_odd_answers_are_errors():
    garbled = catalogue_http().add("GET", BREACH.format(name="Odd"), text="{nope", headers={"content-type": "application/json"})
    assert run_module(MOD, "keyword:Odd", garbled).status is Status.ERROR
    nameless = catalogue_http().add("GET", BREACH.format(name="Odd2"), json={"Title": "no name"})
    res = run_module(MOD, "keyword:Odd2", nameless)
    assert res.status is Status.ERROR and not res.attributes


# ------------------------------------------------------------------ the catalogue dataset (C2)
def test_catalogue_download_failure_without_a_copy_is_an_error():
    res = run_module(MOD, "domain:adobe.com", FakeHttp().add("GET", CATALOG_URL, status=503, text="down"))
    assert res.status is Status.ERROR and not res.attributes


def test_challenge_page_never_replaces_the_catalogue():
    res = run_module(MOD, "domain:adobe.com", FakeHttp().add("GET", CATALOG_URL, status=200, text=CHALLENGE))
    assert res.status in (Status.BLOCKED, Status.ERROR) and not res.attributes  # could not verify, never EMPTY


def test_stale_copy_checked_with_latestbreach_probe():
    clock = FakeClock()
    http = FakeHttp(clock=clock).add("GET", CATALOG_URL, json=fx("catalog_ok.json"), times=1)
    run_module(MOD, "domain:adobe.com", http, clock=clock)
    clock.advance(2 * 86400)  # the local copy is now older than its 24 h TTL
    http.add("GET", LATEST_URL, json=fx("latestbreach_ok.json"))  # Bromcom: already in the copy
    res = run_module(MOD, "domain:adobe.com", http, clock=clock)
    assert res.status is Status.OK
    assert http.urls().count(CATALOG_URL) == 1 and http.urls().count(LATEST_URL) == 1  # no 1.1 MB re-download
    run_module(MOD, "domain:adobe.com", http, clock=clock)
    assert http.urls().count(LATEST_URL) == 1  # the probe is remembered for 24 h (ctx.state)


def test_changed_catalogue_is_downloaded_and_failure_keeps_the_stale_copy():
    clock = FakeClock()
    http = FakeHttp(clock=clock).add("GET", CATALOG_URL, json=fx("catalog_ok.json"), times=1)
    run_module(MOD, "domain:adobe.com", http, clock=clock)
    clock.advance(2 * 86400)
    newer = {**fx("latestbreach_ok.json"), "Name": "BrandNewBreach", "AddedDate": "2026-11-27T00:00:00Z"}
    http.add("GET", LATEST_URL, json=newer).add("GET", CATALOG_URL, status=503, text="down")
    res = run_module(MOD, "domain:adobe.com", http, clock=clock)
    assert res.status is Status.OK and res.attributes["service_breaches"][0]["name"] == "Adobe"  # stale copy kept


def test_latestbreach_failure_falls_back_to_the_normal_refresh():
    clock = FakeClock()
    http = FakeHttp(clock=clock).add("GET", CATALOG_URL, json=fx("catalog_ok.json"), times=1)
    run_module(MOD, "domain:adobe.com", http, clock=clock)
    clock.advance(2 * 86400)
    http.add("GET", LATEST_URL, error=NetworkError("reset", kind="ConnectionError")).add("GET", CATALOG_URL, json=fx("catalog_ok.json"))
    res = run_module(MOD, "domain:adobe.com", http, clock=clock)
    assert res.status is Status.OK  # the probe failure only skips the shortcut: the catalogue is refreshed
    assert http.urls().count(CATALOG_URL) == 2


def test_dropped_fields_never_reach_the_dataset_or_outputs():
    http = catalogue_http()
    res = run_module(MOD, "domain:500px.com", http)
    assert res.status is Status.OK
    assert_no_secret("fixture-source@example.org", res.to_dict(), [f.to_dict() for f in res.findings], res.raw, paths.home())
    stored = (paths.datasets_dir() / hc.CATALOG_DATASET).read_text(encoding="utf-8")
    assert "LogoPath" not in stored and "Attribution" not in stored and "DisclosureUrl" not in stored


# ------------------------------------------------------------------ the shared helper (C3, C4, C5)
def test_shared_helper_enriches_names_from_other_sources():
    http = catalogue_http()
    ctx = make_ctx(MOD, http, entity="domain:adobe.com")
    catalog = breach_catalog(ctx)
    facts = catalog.enrich(["Adobe", "linked in", "AdultFriendFinder2016", "NotInHibp"])
    assert facts[0]["known"] and facts[0]["breach_date"] == "2013-10-04" and facts[0]["is_verified"] is True
    assert facts[1]["known"] and facts[1]["name"] == "LinkedIn"  # normalised key
    assert facts[2]["name"] == SENSITIVE_BREACH_LABEL and facts[2]["sensitive"] is True
    assert facts[3] == {"source_name": "NotInHibp", "known": False}
    assert catalog.lookup("AlienStealerLogs")["is_stealer_log"] is True
    assert catalog.lookup("Zoosk")["is_fabricated"] is True and catalog.lookup("Zoosk")["counts_as_exposure"] is False
    assert catalog.lookup("MuslimDirectory")["category"] == "religion" and catalog.lookup("MuslimDirectory")["sensitive"] is True


def test_password_form_port():
    assert password_form("<p>The breach included plain text passwords.</p>", ["Passwords"]) == "plaintext"
    assert password_form("stored as bcrypt hashes", ["Passwords"]) == "hashed: bcrypt"
    assert password_form("either an MD5 or bcrypt hash", ["Passwords"]) == "hashed: bcrypt/md5"
    assert password_form("passwords and password hints in plain text", ["Passwords"]) == "unknown"  # hint phrase removed
    assert password_form("encrypted passwords quickly resolved back to plain text", ["Passwords"]) == "hashed: encrypted"
    assert password_form("emails only", ["Email addresses"]) is None


def test_dataclasses_dataset():
    http = FakeHttp().add("GET", DATACLASSES_URL, json=fx("dataclasses_ok.json"))
    from v3lum.core import datasets

    ctx = make_ctx(MOD, http, entity="domain:adobe.com")
    with pytest.MonkeyPatch.context() as mp:
        mp.setattr(hc, "_validate_dataclasses", lambda path: True)
        mp.setitem(datasets.DATASETS[hc.DATACLASSES_DATASET], "validate", None)
        names = data_classes(ctx)
    assert "Passwords" in names and "Email addresses" in names


def test_metadata_matches_the_council_decision():
    assert MOD.default_enabled is True and MOD.terms == "open" and MOD.trust_tier == "trusted"
    assert MOD.sensitive is True and MOD.disclosure == "third_party" and MOD.hosts == ("haveibeenpwned.com",)


def test_golden_path_acceptance_route_replays(monkeypatch):
    """tests/fixtures/acceptance/domain/hibp_catalog.json: the real catalogue (trimmed to Name, Domain,
    AddedDate, IsVerified) is the only request of a cold domain scan; example.com is no breached service."""
    from tests.fakes import fixture

    monkeypatch.setattr(hc, "MIN_BREACHES", 500)  # the production floor
    routes = fixture("acceptance/domain/hibp_catalog.json")
    assert routes["module"] == "hibp_catalog" and len(routes["routes"]) == 1
    http = FakeHttp()
    for route in routes["routes"]:
        http.add(route["method"], route["url"], status=route["status"], json=route["json"], headers=route["headers"])
    res = run_module(MOD, "domain:example.com", http)
    assert res.status is Status.EMPTY and http.urls() == [CATALOG_URL]
