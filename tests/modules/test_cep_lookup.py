"""Offline tests for P234 ``cep_lookup`` (batch p2-G10-1).

Fixtures in tests/fixtures/cep_lookup/ are trimmed real BrasilAPI, ViaCEP, OpenCEP and IBGE answers
captured 2026-11-25/26 (public places only: Praça da Sé in São Paulo, the Banco do Brasil head-office
CEP in Brasília) plus a few synthetic error shapes (``*_synthetic*``).
"""

from __future__ import annotations

import json

import pytest

from tests.fakes import FakeHttp, module_fixture, run_module
from v3lum.core.context import ScanOptions
from v3lum.core.datasets import DataStore
from v3lum.core.http import NetworkError
from v3lum.core.models import Status
from v3lum.modules.brazil_public_data import cep_lookup as cl
from v3lum.modules.brazil_public_data.cep_lookup import CepLookup

SE = "01001000"
BB_HQ = "70040912"
BOGUS = "99999999"
BRASILAPI = "https://brasilapi.com.br/api/cep/v2/{}"
VIACEP = "https://viacep.com.br/ws/{}/json/"
IBGE = "https://servicodados.ibge.gov.br/api/v1/localidades/municipios/{}"


def fx(name: str):
    return module_fixture("cep_lookup", name)


def add_json(http: FakeHttp, url: str, name: str) -> FakeHttp:
    return http.add("GET", url, json=fx(name))


def add_exchange(http: FakeHttp, url: str, name: str) -> FakeHttp:
    ex = fx(name)
    return http.add("GET", url, status=ex["status"], body=ex["body"].encode("utf-8"), headers=ex.get("headers") or {})


# ------------------------------------------------------------------ cond 1-2: the offline range table
@pytest.mark.parametrize(
    ("cep", "uf"),
    [("01000000", "SP"), ("19999999", "SP"), ("20000000", "RJ"), ("28999999", "RJ"), ("29000000", "ES"), ("39999999", "MG"),
     ("40000000", "BA"), ("49000000", "SE"), ("50000000", "PE"), ("57000000", "AL"), ("58000000", "PB"), ("59999999", "RN"),
     ("60000000", "CE"), ("64000000", "PI"), ("65999999", "MA"), ("66000000", "PA"), ("68899999", "PA"), ("68900000", "AP"),
     ("69000000", "AM"), ("69299999", "AM"), ("69300000", "RR"), ("69399999", "RR"), ("69400000", "AM"), ("69899999", "AM"),
     ("69900000", "AC"), ("70000000", "DF"), ("72799999", "DF"), ("72800000", "GO"), ("72999999", "GO"), ("73000000", "DF"),
     ("73699999", "DF"), ("73700000", "GO"), ("76799999", "GO"), ("76800000", "RO"), ("76999999", "RO"), ("77000000", "TO"),
     ("78000000", "MT"), ("78899999", "MT"), ("79000000", "MS"), ("80000000", "PR"), ("87999999", "PR"), ("88000000", "SC"),
     ("89999999", "SC"), ("90000000", "RS"), ("99999999", "RS")],
)
def test_range_table_boundaries(cep, uf):
    assert cl.cep_uf(cep) == uf


def test_range_table_covers_all_27_ufs_without_overlap():
    ranges = sorted(cl.cep_ranges())
    assert {uf for _lo, _hi, uf in ranges} == set(cl.UF_NAMES)
    for (_lo1, hi1, _u1), (lo2, _hi2, _u2) in zip(ranges, ranges[1:]):
        assert hi1 < lo2
    assert cl.cep_uf("00999999") is None and cl.cep_uf("78900000") is None  # outside every council range (backlog)
    assert DataStore.bundled_json(cl.BUNDLED_RANGES)["version"]


def test_offline_uf_needs_no_request_even_when_providers_fail():
    http = FakeHttp().add("GET", BRASILAPI.format(SE), status=503, text="down").add("GET", VIACEP.format(SE), status=503, text="down")
    res = run_module(CepLookup, f"cep:{SE}", http)
    assert res.status is Status.ERROR and "could not verify" in res.error
    assert res.attributes["cep_uf_hint"] == "SP"  # the offline answer stands
    assert "city" not in res.attributes


# ------------------------------------------------------------------ cond 3, 6: chain and normaliser
def test_brasilapi_answers_first_and_the_chain_stops():
    http = add_json(FakeHttp(), BRASILAPI.format(SE), "brasilapi_v2_ok.json")
    res = run_module(CepLookup, f"cep:{SE}", http)
    assert res.status is Status.OK and len(http.calls) == 1  # no fan-out
    assert res.attributes["city"] == "São Paulo" and res.attributes["region"] == "SP" and res.attributes["country"] == "BR"
    assert res.attributes["ibge_code"] == "3550308" and res.attributes["address"] == "Praça da Sé, Sé"
    rec = res.attributes["cep_record"]
    assert rec["postal_code"] == "01001-000" and rec["region_iso"] == "BR-SP" and rec["provider"] == "brasilapi"
    assert rec["coordinates"]["label"] == "CEP centroid (approximate)"
    [pivot] = res.pivots
    assert pivot.entity.type.value == "coordinates" and pivot.expand is False and pivot.relation == "located_at"
    assert "never a person's location" in pivot.note
    assert res.source_statuses["brasilapi.cep"]["status"] == "ok" and "viacep.cep" not in res.source_statuses
    http.assert_hosts_within(CepLookup)


def test_no_coordinates_pivot_when_the_provider_supplies_none():
    http = add_json(FakeHttp(), BRASILAPI.format(SE), "brasilapi_v2_empty_coordinates_synthetic.json")
    res = run_module(CepLookup, f"cep:{SE}", http)
    assert res.status is Status.OK and not res.pivots and "coordinates" not in res.attributes["cep_record"]


def test_brasilapi_not_found_is_a_vote_and_viacep_answers():
    http = add_exchange(FakeHttp(), BRASILAPI.format(SE), "brasilapi_v2_not_found.http.json")
    add_json(http, VIACEP.format(SE), "viacep_ok.json")
    res = run_module(CepLookup, f"cep:{SE}", http)
    assert res.status is Status.OK and res.attributes["cep_record"]["provider"] == "viacep"
    assert res.attributes["cep_ddd"] == "11" and "uf_mismatch" not in res.attributes
    chain = res.attributes["provider_chain"]
    assert [c["state"] for c in chain] == ["not_found", "ok"] and "a vote" in chain[0]["reason"]
    assert res.source_statuses["brasilapi.cep"]["status"] == "empty"


def test_viacep_erro_marker_is_the_only_empty():
    http = add_exchange(FakeHttp(), BRASILAPI.format(SE), "brasilapi_v2_not_found.http.json")
    add_json(http, VIACEP.format(SE), "viacep_erro.json")
    res = run_module(CepLookup, f"cep:{SE}", http)
    assert res.status is Status.EMPTY and res.attributes["cep_uf_hint"] == "SP"


@pytest.mark.parametrize("name", ["viacep_erro.json", "viacep_erro_bool_synthetic.json"])
def test_viacep_marker_string_and_boolean(name):
    assert cl.viacep_erro_marker(fx(name))
    assert cl.viacep_erro_marker(fx("viacep_ok.json")) is None


def test_inconsistent_bogus_record_is_discarded_and_the_chain_continues():
    http = add_json(FakeHttp(), BRASILAPI.format(BOGUS), "brasilapi_v2_range_mismatch.json")
    add_json(http, VIACEP.format(BOGUS), "viacep_erro.json")
    res = run_module(CepLookup, f"cep:{BOGUS}", http)
    assert res.status is Status.EMPTY  # ViaCEP's documented marker, after BrasilAPI's PR street for an RS CEP
    chain = res.attributes["provider_chain"]
    assert chain[0]["state"] == "inconsistent" and "contradicts the CEP range table (RS)" in chain[0]["reason"]
    assert not res.pivots  # the bogus record's coordinates never become a pivot


def test_bb_head_office_cep():
    http = add_json(FakeHttp(), BRASILAPI.format(BB_HQ), "brasilapi_v2_company_ok.json")
    res = run_module(CepLookup, f"cep:{BB_HQ}", http)
    assert res.status is Status.OK and res.attributes["city"] == "Brasília" and res.attributes["region"] == "DF"


def test_ibge_code_missing_from_the_table_is_asked_once():
    body = fx("brasilapi_v2_ok.json")
    body["ibge"]["city"] = "9999998"  # a code the offline table does not know
    http = FakeHttp().add("GET", BRASILAPI.format(SE), json=body)
    add_json(http, IBGE.format("9999998"), "ibge_municipio_empty.json")
    res = run_module(CepLookup, f"cep:{SE}", http)
    assert res.status is Status.OK and len(http.calls) == 2
    assert res.source_statuses["ibge.localidades"]["status"] == "empty"


def test_ibge_name_lookup_fills_a_missing_code_offline():
    rec = cl.parse_provider_record("opencep", fx("opencep_ok.json"))
    rec["ibge_code"] = None
    norm = cl.normalise_cep_record(rec, cl.municipios())
    assert norm["ibge_code"] == "3550308" and norm["city"] == "São Paulo"


def test_ibge_parsers():
    assert cl.parse_ibge_municipio(fx("ibge_municipio_ok.json")) == {"ibge_code": "3550308", "city": "São Paulo", "uf": "SP",
                                                                      "region": "Sudeste"}
    assert cl.parse_ibge_municipio(fx("ibge_municipio_empty.json")) is None
    flat = cl.parse_ibge_municipios_flat(fx("ibge_municipios_flat_sample.json"))
    assert flat["3550308"] == ["São Paulo", "SP"] and flat["1100015"][1] == "RO"
    assert len(cl.municipios()) == 5571


# ------------------------------------------------------------------ cond 4: OpenCEP waits for its tier review
def test_opencep_is_not_in_the_chain_while_its_tier_is_unknown():
    assert CepLookup().chain() == ["brasilapi", "viacep"]
    assert "opencep.com" not in CepLookup.hosts and cl.SRC_OPENCEP not in CepLookup.sources
    from v3lum.core import providers

    assert providers.registry().get("opencep").tier == "unknown"
    http = add_exchange(FakeHttp(), BRASILAPI.format(SE), "brasilapi_v2_not_found.http.json")
    http.add("GET", VIACEP.format(SE), status=503, text="down")
    res = run_module(CepLookup, f"cep:{SE}", http)  # an OpenCEP request would be an unmatched route
    assert res.status is Status.ERROR and all("opencep" not in u for u in http.urls())


def test_opencep_parser_is_ready_for_the_review():
    rec = cl.parse_provider_record("opencep", fx("opencep_ok.json"))
    assert rec["city"] == "São Paulo" and rec["ibge_code"] == "3550308" and "ddd" not in rec
    bogus = cl.parse_provider_record("opencep", fx("opencep_range_mismatch.json"))
    assert cl.cep_consistency(BOGUS, bogus)
    assert cl.opencep_not_found_marker(json.loads(fx("opencep_not_found.http.json")["body"]))


# ------------------------------------------------------------------ cond 5: rule 5
def test_429_and_403_are_could_not_verify():
    http = add_exchange(FakeHttp(), BRASILAPI.format(SE), "viacep_rate_limited_synthetic.http.json")
    add_exchange(http, VIACEP.format(SE), "viacep_blocked_synthetic.http.json")
    res = run_module(CepLookup, f"cep:{SE}", http)
    assert res.status is Status.BLOCKED and "could not verify" in res.error
    assert res.source_statuses["brasilapi.cep"]["status"] == "rate_limited"
    assert res.source_statuses["viacep.cep"]["status"] == "blocked"


def test_all_rate_limited_is_rate_limited():
    http = add_exchange(FakeHttp(), BRASILAPI.format(SE), "viacep_rate_limited_synthetic.http.json")
    add_exchange(http, VIACEP.format(SE), "viacep_rate_limited_synthetic.http.json")
    assert run_module(CepLookup, f"cep:{SE}", http).status is Status.RATE_LIMITED


def test_html_in_200_and_timeouts_are_errors():
    http = FakeHttp().add("GET", BRASILAPI.format(SE), error=NetworkError("read timed out", kind="ReadTimeout", retryable=False))
    add_exchange(http, VIACEP.format(SE), "viacep_html_200_synthetic.http.json")
    res = run_module(CepLookup, f"cep:{SE}", http)
    assert res.status is Status.ERROR and res.reason_code == "error"
    chain = res.attributes["provider_chain"]
    assert chain[0]["state"] == "error" and chain[1]["state"] == "error"


def test_error_object_in_200_is_never_empty():
    http = FakeHttp().add("GET", BRASILAPI.format(SE), json={"message": "internal error"})
    http.add("GET", VIACEP.format(SE), json={"error": "upstream"})
    res = run_module(CepLookup, f"cep:{SE}", http)
    assert res.status is Status.ERROR and "error in 200" in res.error


def test_viacep_400_html_is_an_error():
    http = add_exchange(FakeHttp(), BRASILAPI.format(SE), "brasilapi_v2_not_found.http.json")
    add_exchange(http, VIACEP.format(SE), "viacep_bad_request.http.json")
    assert run_module(CepLookup, f"cep:{SE}", http).status is Status.ERROR


def test_malformed_json_is_an_error():
    http = FakeHttp().add("GET", BRASILAPI.format(SE), body=b'{"cep": "01001000", "sta', headers={"content-type": "application/json"})
    http.add("GET", VIACEP.format(SE), body=b"[", headers={"content-type": "application/json"})
    assert run_module(CepLookup, f"cep:{SE}", http).status is Status.ERROR


# ------------------------------------------------------------------ cond 7: reverse search only for typed addresses
def test_reverse_search_for_an_analyst_typed_address():
    url = cl.viacep_reverse_url("SP", "São Paulo", "Praça da Sé")
    http = add_json(FakeHttp(), url, "viacep_reverse_ok.json")
    res = run_module(CepLookup, "keyword:Praça da Sé, 108, São Paulo - SP", http)
    assert res.status is Status.OK
    assert [m["postal_code"] for m in res.attributes["cep_reverse_matches"]][:2] == ["01001-000", "01001-901"]
    assert res.pivots and all(p.expand is False and p.relation == "located_at" for p in res.pivots)


def test_reverse_search_empty_list_is_empty():
    url = cl.viacep_reverse_url("SP", "São Paulo", "Rua Inexistente Exemplo")
    http = add_json(FakeHttp(), url, "viacep_reverse_empty_synthetic.json")
    res = run_module(CepLookup, "keyword:SP/São Paulo/Rua Inexistente Exemplo", http)
    assert res.status is Status.EMPTY


def test_reverse_search_never_runs_for_pivots_or_text_extracts():
    res = run_module(CepLookup, "keyword:Praça da Sé, São Paulo - SP", FakeHttp(), is_seed=False, depth=1,
                     provenance=(("text_blob:x", "mentions", "ioc_extract"),))
    assert res.status is Status.SKIPPED and res.reason_code == "privacy"
    opts = ScanOptions(unconfirmed_seeds={"keyword:Praça da Sé, São Paulo - SP"})
    res2 = run_module(CepLookup, "keyword:Praça da Sé, São Paulo - SP", FakeHttp(), options=opts)
    assert res2.status is Status.SKIPPED and res2.reason_code == "privacy"


def test_other_keywords_are_not_applicable():
    res = run_module(CepLookup, "keyword:banco do brasil", FakeHttp())
    assert res.status is Status.SKIPPED and res.reason_code == "not_applicable"


@pytest.mark.parametrize(
    ("text", "parsed"),
    [("Praça da Sé, São Paulo - SP", ("SP", "São Paulo", "Praça da Sé")), ("Praça da Sé, 108, São Paulo/SP", ("SP", "São Paulo", "Praça da Sé")),
     ("SP/São Paulo/Praça da Sé", ("SP", "São Paulo", "Praça da Sé")), ("banco do brasil", None), ("Rua X, Y - ZZ", None)],
)
def test_typed_address_parser(text, parsed):
    assert cl.parse_typed_address(text) == parsed


def test_reverse_url_needs_three_characters_per_segment():
    with pytest.raises(ValueError):
        cl.viacep_reverse_url("SP", "SP", "Praça da Sé")
    with pytest.raises(ValueError):
        cl.viacep_reverse_url("XX", "São Paulo", "Praça da Sé")


# ------------------------------------------------------------------ cond 8: weak cross-checks
def test_uf_mismatches_are_weak_info():
    out = cl.uf_mismatch_attributes(cep="01001000", ddd="21", cnpj_uf="DF")
    assert {m["check"] for m in out} == {"cep_ddd", "cep_cnpj", "ddd_cnpj"}
    assert all(m["weak"] and m["score_effect"] == 0 for m in out)
    assert cl.uf_mismatch_attributes(cep="72800000", ddd="61") == []  # DDD 61 also serves GO (Entorno)
    assert cl.uf_mismatch_attributes(cep="01001000", ddd="11", cnpj_uf="SP") == []


# ------------------------------------------------------------------ cond 9
def test_cache_ttl_is_thirty_days_and_failures_are_not_cacheable():
    assert CepLookup.cache_ttl == 30 * 86400

    class R:
        def __init__(self, status: int, content: bytes) -> None:
            self.status, self.content = status, content

    assert cl._cacheable(R(200, json.dumps(fx("viacep_ok.json")).encode()))
    assert not cl._cacheable(R(200, b"<html>down</html>"))
    assert not cl._cacheable(R(429, b"{}"))


def test_every_provider_timing_out_is_error_timeout():
    http = FakeHttp().add("GET", BRASILAPI.format(SE), error=NetworkError("read timed out", kind="ReadTimeout", retryable=False))
    http.add("GET", VIACEP.format(SE), error=NetworkError("read timed out", kind="ReadTimeout", retryable=False))
    res = run_module(CepLookup, f"cep:{SE}", http)
    assert res.status is Status.ERROR and res.reason_code == "timeout" and res.attributes["cep_uf_hint"] == "SP"
