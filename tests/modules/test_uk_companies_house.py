"""Offline tests for P227 ``uk_companies_house`` (batch p3-G10-1).

tests/fixtures/uk_companies_house/: the live keyless 401 plus documented-shape placeholders (README there; P227
cond 6 asks for captures made with the team key before the module is enabled).
"""

from __future__ import annotations

import base64
import json
import re

import pytest

from tests.fakes import FakeHttp, assert_no_secret, module_fixture, run_module
from v3lum.core.entities import Entity
from v3lum.core.entities import EntityType as T
from v3lum.core.models import Status
from v3lum.modules.company_org import uk_companies_house as ch
from v3lum.modules.company_org.uk_companies_house import UkCompaniesHouse

KEY = "ch-test-key-0b7e41d2"
KEYS = {"companies_house": KEY}
SEARCH = re.compile(r"^https://api\.company-information\.service\.gov\.uk/search/companies\?")
PROFILE = "https://api.company-information.service.gov.uk/company/00000001"
OFFICERS = PROFILE + "/officers"
PSC = PROFILE + "/persons-with-significant-control"


def fx(name: str):
    return module_fixture("uk_companies_house", name)


def add_exchange(http: FakeHttp, method: str, url, name: str) -> FakeHttp:
    ex = fx(name)
    return http.add(method, url, status=ex["status"], body=ex["body"].encode(), headers=ex["headers"])


def full_routes() -> FakeHttp:
    return (FakeHttp().add("GET", SEARCH, json=fx("search_ok.json")).add("GET", PROFILE, json=fx("company_ok.json"))
            .add("GET", OFFICERS, json=fx("officers_ok.json")).add("GET", PSC, json=fx("psc_ok.json")))


def test_key_is_basic_auth_username_never_in_urls():
    http = full_routes()
    res = run_module(UkCompaniesHouse, "company_name:Example Trading Ltd", http, keys=KEYS)
    assert res.status is Status.OK, res.error
    assert [c["url"].split("?")[0] for c in http.calls] == [ch.BASE + "/search/companies", PROFILE, OFFICERS, PSC]
    expected = "Basic " + base64.b64encode(f"{KEY}:".encode()).decode()
    for call in http.calls:
        assert call["headers"]["Authorization"] == expected and KEY not in call["url"]
    assert "q=Example%20Trading%20Ltd" in http.calls[0]["url"]
    assert_no_secret(KEY, res.raw, res.attributes, [f.to_dict() for f in res.findings], res.error)
    http.assert_hosts_within(UkCompaniesHouse)


def test_profile_officers_and_psc_are_minimised():
    res = run_module(UkCompaniesHouse, "company_name:EXAMPLE TRADING LIMITED", full_routes(), keys=KEYS)
    company = res.attributes["uk_company"]
    assert company["company_number"] == "00000001" and company["status"] == "active" and company["has_charges"] is True
    assert company["previous_names"] == ["EXAMPLE SOFTWARE LIMITED"] and company["url"].endswith("/company/00000001")
    officers, psc = res.attributes["uk_officers"], res.attributes["uk_psc"]
    assert {tuple(sorted(o)) for o in officers} == {("appointed_on", "corporate", "name", "resigned_on", "role")}
    assert {tuple(sorted(p)) for p in psc} == {("ceased_on", "corporate", "kind", "name", "natures_of_control", "notified_on")}
    dump = json.dumps([res.raw, res.attributes, [p.note for p in res.pivots]])
    for personal in ("1970", "British", "Irish", "Example Street", "Example Road", "EC1A", "England", "EXAMPLEAPPOINTMENTS1", "00000003"):
        assert personal not in dump, personal
    assert res.attributes["data_attribution"] == [ch.ATTRIBUTION]
    assert res.attributes["uk_company_candidates"][0]["company_number"] == "SC000002"


def test_current_officers_and_psc_become_non_expanding_pivots():
    res = run_module(UkCompaniesHouse, "company_name:Example Trading Limited", full_routes(), keys=KEYS)
    got = {(p.entity.type, p.entity.value, p.relation) for p in res.pivots}
    assert got == {
        (T.PERSON, "EXAMPLE, Person One", "officer_of"),
        (T.ORG, "EXAMPLE COMPANY SECRETARIES LIMITED", "officer_of"),  # corporate officer -> company name
        (T.PERSON, "Mr Person One EXAMPLE", "psc_of"),
    }  # resigned secretary and ceased corporate PSC are listed but not pivoted
    assert all(p.expand is False and "not investigated automatically" in p.note for p in res.pivots)
    assert res.findings == []


def test_no_exact_title_lists_candidates_only():
    http = FakeHttp().add("GET", SEARCH, json=fx("search_ok.json"))
    res = run_module(UkCompaniesHouse, "company_name:Example Trading Group", http, keys=KEYS)
    assert res.status is Status.OK and len(http.calls) == 1 and res.pivots == []
    assert [c["company_number"] for c in res.attributes["uk_company_candidates"]] == ["00000001", "SC000002"]
    assert "uk_company" not in res.attributes and "address_snippet" not in json.dumps(res.attributes)


def test_no_hits_is_empty():
    http = FakeHttp().add("GET", SEARCH, json={"kind": "search#companies", "items": [], "total_results": 0})
    assert run_module(UkCompaniesHouse, "company_name:Qwzx Vrklm Limited", http, keys=KEYS).status is Status.EMPTY


def test_keyword_company_number_goes_straight_to_the_profile():
    http = (FakeHttp().add("GET", PROFILE, json=fx("company_ok.json")).add("GET", OFFICERS, json={"items": []})
            .add("GET", PSC, json={"items": []}))
    res = run_module(UkCompaniesHouse, Entity.make(T.KEYWORD, "1"), http, keys=KEYS)
    assert res.status is Status.OK and http.calls[0]["url"] == PROFILE and res.pivots == []
    for value in ("Example Trading", "123456789", "AB12345"):
        skipped = run_module(UkCompaniesHouse, Entity.make(T.KEYWORD, value), FakeHttp(), keys=KEYS)
        assert skipped.status is Status.SKIPPED and skipped.reason_code == "not_applicable", value


def test_unknown_company_number_is_empty():
    http = add_exchange(FakeHttp(), "GET", PROFILE, "company_not_found.http.json")
    res = run_module(UkCompaniesHouse, Entity.make(T.KEYWORD, "00000001"), http, keys=KEYS)
    assert res.status is Status.EMPTY and len(http.calls) == 1


def test_missing_or_rejected_key_is_needs_key():
    http = FakeHttp()
    res = run_module(UkCompaniesHouse, "company_name:Example Trading Limited", http)
    assert res.status is Status.NEEDS_KEY and http.calls == []
    rejected = add_exchange(FakeHttp(), "GET", SEARCH, "search_nokey.http.json")
    res = run_module(UkCompaniesHouse, "company_name:Example Trading Limited", rejected, keys=KEYS)
    assert res.status is Status.NEEDS_KEY, (res.status, res.error)
    assert_no_secret(KEY, res.error, res.raw)


@pytest.mark.parametrize("status, expected", [(429, Status.RATE_LIMITED), (403, Status.NEEDS_KEY), (500, Status.ERROR)])
def test_failures_are_could_not_verify(status, expected):
    if status == 429:
        http = add_exchange(FakeHttp(), "GET", SEARCH, "rate_limited.http.json")
    else:
        http = FakeHttp().add("GET", SEARCH, status=status, text="unavailable")
    res = run_module(UkCompaniesHouse, "company_name:Example Trading Limited", http, keys=KEYS)
    assert res.status is expected and res.pivots == [] and "uk_company" not in res.attributes


def test_officer_failure_after_profile_is_partial_not_silently_empty():
    http = (FakeHttp().add("GET", PROFILE, json=fx("company_ok.json")).add("GET", OFFICERS, status=429, text="slow down"))
    res = run_module(UkCompaniesHouse, Entity.make(T.KEYWORD, "00000001"), http, keys=KEYS)
    assert res.partial and res.stop_reason == "rate_limited" and "rate limited" in res.error
    assert "uk_company" in res.attributes and "uk_officers" not in res.attributes and res.pivots == []


def test_uk_legal_form_spellings_compare_equal():
    assert ch.uk_name_key("Example Trading Ltd") == ch.uk_name_key("EXAMPLE TRADING LIMITED")
    assert ch.uk_name_key("Example Holdings Public Limited Company") == ch.uk_name_key("EXAMPLE HOLDINGS PLC")
    assert ch.uk_name_key("Example Trading Ltd") != ch.uk_name_key("EXAMPLE TRADING (SCOTLAND) LTD")


def test_helpers_and_contract_values():
    assert ch.company_number("sc 123456") == "SC123456" and ch.company_number("1234") == "00001234"
    assert ch.company_number("R1234567") == "R1234567" and ch.company_number("ABC") is None
    with pytest.raises(ValueError):
        ch.company_url("not a number")
    with pytest.raises(ValueError):
        ch.search_url("   ")
    assert ch.parse_company({"company_name": "X"}) is None
    with pytest.raises(ValueError):
        ch.parse_search([])
    assert UkCompaniesHouse.default_enabled is False and UkCompaniesHouse.requires_keys == ("companies_house",)
    assert UkCompaniesHouse.terms == "key-terms" and UkCompaniesHouse.hosts == ("api.company-information.service.gov.uk",)
