"""Offline tests for P225 ``eu_vies`` (batch p3-G10-1).

Fixtures in tests/fixtures/eu_vies/ are live VIES answers plus synthetic bodies on the live envelope (README there).
"""

from __future__ import annotations

import pytest

from tests.fakes import FakeHttp, module_fixture, run_module
from v3lum.core.entities import Entity
from v3lum.core.entities import EntityType as T
from v3lum.core.models import Severity, Status
from v3lum.modules.company_org import eu_vies as vies
from v3lum.modules.company_org.eu_vies import EuVies

LU = vies.VIES_URL.format(cc="LU", number="26375245")
LU_INVALID = vies.VIES_URL.format(cc="LU", number="10000053")
CZ = vies.VIES_URL.format(cc="CZ", number="00177041")


def fx(name: str):
    return module_fixture("eu_vies", name)


def test_valid_legal_entity_becomes_a_company_name_hint():
    http = FakeHttp().add("GET", LU, json=fx("valid_lu.json"))
    res = run_module(EuVies, "eu_vat:LU26375245", http)
    assert res.status is Status.OK
    info = res.attributes["vat_validation"]
    assert info["state"] == "valid" and info["holder"] == "legal_entity" and info["legal_form"] == "sarl"
    assert info["name"] == "AMAZON EUROPE CORE S.A R.L." and info["address"].startswith("38, AVENUE")
    (pivot,) = res.pivots
    assert pivot.entity.type is T.ORG and pivot.relation == "vat_holder" and pivot.expand is False
    http.assert_hosts_within(EuVies)


def test_czech_as_is_a_legal_entity_even_after_a_slow_answer():
    res = run_module(EuVies, "eu_vat:CZ00177041", FakeHttp().add("GET", CZ, json=fx("valid_cz.json")))
    assert res.attributes["vat_validation"]["legal_form"] == "as" and len(res.pivots) == 1


def test_possible_sole_trader_is_never_exposed():
    res = run_module(EuVies, "eu_vat:LU10000053", FakeHttp().add("GET", LU_INVALID, json=fx("valid_sole_trader_synthetic.json")))
    info = res.attributes["vat_validation"]
    assert info["state"] == "valid" and info["holder"] == "possible_sole_trader"
    assert "name" not in info and "address" not in info and res.pivots == []
    assert "EXEMPLO PESSOA" not in str(res.raw) and "EXAMPLE STREET" not in str(res.attributes)


def test_withheld_name_is_unknown_holder():
    res = run_module(EuVies, "eu_vat:LU10000053", FakeHttp().add("GET", LU_INVALID, json=fx("valid_name_withheld.json")))
    assert res.attributes["vat_validation"]["holder"] == "unknown" and res.pivots == []


def test_invalid_only_on_a_plain_invalid_answer():
    res = run_module(EuVies, "eu_vat:LU10000053", FakeHttp().add("GET", LU_INVALID, json=fx("invalid.json")))
    assert res.status is Status.OK and res.attributes["vat_validation"]["state"] == "invalid"
    (finding,) = res.findings
    assert finding.title == "EU VAT number not valid according to VIES" and finding.severity is Severity.LOW


@pytest.mark.parametrize("name, status, code", [
    ("ms_unavailable_in_200.json", Status.UNAVAILABLE, "offline"),
    ("rate_limited_in_200.json", Status.RATE_LIMITED, "rate_limited"),
    ("invalid_input_in_200.json", Status.ERROR, "error"),
])
def test_user_errors_inside_http_200_are_could_not_verify(name, status, code):
    res = run_module(EuVies, "eu_vat:CZ00177041", FakeHttp().add("GET", CZ, json=fx(name)))
    assert res.status is status and res.reason_code == code and "never read as 'invalid'" in res.error
    assert res.findings == [] and res.attributes["vat_validation"]["state"] == "not_verified"


def test_member_state_timeout_and_blocks():
    body = dict(fx("ms_unavailable_in_200.json"), userError="TIMEOUT")
    assert run_module(EuVies, "eu_vat:CZ00177041", FakeHttp().add("GET", CZ, json=body)).reason_code == "timeout"
    blocked = dict(fx("ms_unavailable_in_200.json"), userError="IP_BLOCKED")
    assert run_module(EuVies, "eu_vat:CZ00177041", FakeHttp().add("GET", CZ, json=blocked)).status is Status.BLOCKED


def test_http_failures_are_could_not_verify():
    for status, expected in ((429, Status.RATE_LIMITED), (403, Status.BLOCKED), (500, Status.ERROR), (503, Status.ERROR)):
        res = run_module(EuVies, "eu_vat:LU26375245", FakeHttp().add("GET", LU, status=status, text="down"))
        assert res.status is expected
    odd = run_module(EuVies, "eu_vat:LU26375245", FakeHttp().add("GET", LU, json={"foo": 1}))
    assert odd.status is Status.ERROR


def test_keywords_need_a_prefix_and_check_digit_and_collisions_are_refused():
    http = FakeHttp().add("GET", LU, json=fx("valid_lu.json"))
    assert run_module(EuVies, "keyword:LU 2637 5245", http).status is Status.OK
    for value in ("26375245", "+5511955550100", "d41d8cd98f00b204e9800998ecf8427e", "11222333000181", "LU26375246"):
        res = run_module(EuVies, Entity.make(T.KEYWORD, value), FakeHttp())
        assert res.status is Status.SKIPPED and res.reason_code == "not_applicable", value
    ambiguous = run_module(EuVies, Entity.make(T.KEYWORD, "NL100000009B20"), FakeHttp())
    assert ambiguous.status is Status.SKIPPED and "ambiguous" in ambiguous.error


def test_seeds_only_no_bulk_and_no_pivots():
    http = FakeHttp()
    res = run_module(EuVies, "eu_vat:LU26375245", http, is_seed=False, depth=1, provenance=[("company_name:x", "related", "y")])
    assert res.status is Status.SKIPPED and http.calls == []
    assert EuVies.max_requests == 1 and EuVies.default_enabled is False and EuVies.hosts == ("ec.europa.eu",)


def test_legal_form_rules():
    assert vies.legal_form("Example Trading GmbH") == "gmbh"
    assert vies.legal_form("EXEMPLO PESSOA TESTE") is None
    assert vies.legal_form("Max Example e.K.") is None
    assert vies.legal_form("Example Sp. z o.o.") == "spzoo"
    assert vies.holder("Example S.L.", "ES", "12345678Z") == "possible_sole_trader"  # DNI-shaped number
