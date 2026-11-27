"""Offline tests for P237 ``portal_transparencia_api`` (batch p2-G10-1).

There is no team key in this environment, so the success fixtures in tests/fixtures/portal_transparencia_api/
are SYNTHETIC answers derived from the API's OpenAPI document (``*_synthetic*``; company 11.222.333/0001-81
and sanction 900001 are invented identities shared with the P240 tests). ``needs_key_401.http.json`` is the
real keyless 401 (ISO-8859-1 body). Capturing real success answers with the team key is a merge-gate item
recorded in docs/backlog/p2-G10-1.md (P237 cond 9).
"""

from __future__ import annotations

import base64
import re

import pytest

from tests.fakes import FakeHttp, module_fixture, run_module
from v3lum.core.context import ScanOptions
from v3lum.core.http import NetworkError
from v3lum.core.models import Severity, Status
from v3lum.modules.brazil_public_data import portal_transparencia_api as pta
from v3lum.modules.brazil_public_data.portal_transparencia_api import PortalTransparenciaApi

CNPJ = "11222333000181"
KEY = "tk-test-0000-0000-0000-000000000000"
KEYS = {"transparencia": KEY}
FOUND_KEY = {"chave-api-dados": KEY}


def fx(name: str):
    return module_fixture("portal_transparencia_api", name)


def url(endpoint: str, page: int = 1, year: int | None = None) -> str:
    return pta.build_request(endpoint, CNPJ, page=page, year=year)


def add_exchange(http: FakeHttp, u: str, name: str) -> FakeHttp:
    ex = fx(name)
    body = base64.b64decode(ex["body_b64"]) if "body_b64" in ex else ex["body"].encode("utf-8")
    return http.add("GET", u, status=ex["status"], body=body, headers=ex.get("headers") or {})


def summary(**flags) -> dict:
    base = fx("pessoa_juridica_synthetic.json")
    base.update(flags)
    return base


def payments(n: int = 2) -> list[dict]:
    return [{"data": f"2026-0{i + 1}-15", "documento": f"2026OB0000{i}", "documentoResumido": f"OB{i}", "fase": "Pagamento",
             "codigoFavorecido": CNPJ, "nomeFavorecido": "EMPRESA EXEMPLO ALFA LTDA", "valor": "1.000,50", "orgao": "ORGAO EXEMPLO"}
            for i in range(n)]


def full_routes(http: FakeHttp | None = None, **flags) -> FakeHttp:
    http = http or FakeHttp()
    http.add("GET", url("pessoa_juridica"), json=summary(**flags), match_headers=FOUND_KEY)
    http.add("GET", url("ceis"), json=fx("ceis_synthetic.json"), match_headers=FOUND_KEY)
    http.add("GET", url("cnep"), json=fx("cnep_synthetic.json"), match_headers=FOUND_KEY)
    http.add("GET", url("acordos_leniencia"), json=fx("acordos_leniencia_synthetic.json"), match_headers=FOUND_KEY)
    http.add("GET", url("contratos"), json=fx("contratos_synthetic.json"), match_headers=FOUND_KEY)
    http.add("GET", url("despesas", year=2026), json=payments(), match_headers=FOUND_KEY)
    return http


@pytest.fixture(autouse=True)
def _no_bulk(monkeypatch):
    monkeypatch.setattr(pta, "bulk_fresh", lambda ctx, list_key: False)


# ------------------------------------------------------------------ cond 1-2: key handling
def test_without_a_key_nothing_is_sent_and_the_hint_is_given():
    http = FakeHttp()
    res = run_module(PortalTransparenciaApi, f"cnpj:{CNPJ}", http)
    assert res.status is Status.NEEDS_KEY and not http.calls
    assert pta.NO_KEY_HINT in PortalTransparenciaApi.notice


def test_the_keyless_401_body_maps_to_needs_key():
    body = base64.b64decode(fx("needs_key_401.http.json")["body_b64"])
    assert pta.key_error(pta.parse_json(body, "application/json;charset=ISO-8859-1")[0]).startswith("Chave de API não informada")
    http = add_exchange(FakeHttp(), url("pessoa_juridica"), "needs_key_401.http.json")
    res = run_module(PortalTransparenciaApi, f"cnpj:{CNPJ}", http, keys=KEYS)
    assert res.status is Status.NEEDS_KEY and res.reason_code == "needs_key"


def test_the_key_travels_only_in_the_header():
    http = full_routes()
    res = run_module(PortalTransparenciaApi, f"cnpj:{CNPJ}", http, keys=KEYS)
    assert res.status is Status.OK
    assert all(KEY not in u for u in http.urls())  # never in a URL
    assert KEY not in str(res.to_dict()) and KEY not in str(res.raw)
    http.assert_hosts_within(PortalTransparenciaApi)


# ------------------------------------------------------------------ cond 4, 5, 7: the CNPJ path
def test_stale_bulk_lists_make_api_rows_the_findings_with_the_shared_dedup_key():
    http = full_routes()
    res = run_module(PortalTransparenciaApi, f"cnpj:{CNPJ}", http, keys=KEYS)
    assert res.status is Status.OK
    keys = {f.data["dedup_key"] for f in res.findings}
    assert keys == {"ceis|11222333000181|900001", "cnep|11222333000181|900101", "acordos_leniencia|11222333000181|4242"}
    ceis = next(f for f in res.findings if f.data["list"] == "ceis")
    assert ceis.severity is Severity.HIGH and ceis.title.startswith("Listed in CEIS") and "sanctions" in ceis.tags
    assert ceis.data["start"] == "2024-06-03" and ceis.data["end"] == "2027-06-03" and ceis.criterion
    cnep = next(f for f in res.findings if f.data["list"] == "cnep")
    assert cnep.data["fine"] == 150000.0 and cnep.data["end"] is None
    assert res.attributes["sanctioned"] is True
    assert res.attributes["transparencia_summary"]["sanctioned_ceis"] is True
    contracts = res.attributes["federal_contracts"]
    assert contracts["count"] == len(fx("contratos_synthetic.json")) and contracts["most_recent"][0]["signed"] >= contracts["most_recent"][-1]["signed"]
    assert len(contracts["most_recent"]) <= 5 and not contracts["count_is_lower_bound"]
    assert res.attributes["federal_payments"]["count"] == 2 and res.attributes["federal_payments"]["total_value"] == 2001.0
    # cepim (flag False) and convenios (flag False) were not asked
    assert not any("/cepim" in u or "/convenios" in u for u in http.urls())
    assert len(http.calls) <= PortalTransparenciaApi.max_requests


def test_fresh_bulk_lists_keep_the_findings_in_p240_and_add_detail_only(monkeypatch):
    monkeypatch.setattr(pta, "bulk_fresh", lambda ctx, list_key: True)
    http = full_routes()
    res = run_module(PortalTransparenciaApi, f"cnpj:{CNPJ}", http, keys=KEYS)
    assert res.status is Status.OK and not res.findings  # sanctions are never parsed twice
    detail = res.attributes["cgu_api_sanctions"]
    assert {d["list"] for d in detail} == {"ceis", "cnep"}  # flagged listings only; leniency has no flag
    assert all(d["dedup_key"].startswith(("ceis|", "cnep|")) for d in detail)
    assert not any("acordos-leniencia" in u for u in http.urls())


def test_filter_ignored_rows_are_an_error_never_findings():
    http = FakeHttp().add("GET", url("pessoa_juridica"), json=summary(possuiContratacao=False, favorecidoDespesas=False, sancionadoCNEP=False))
    http.add("GET", url("ceis"), json=fx("ceis_filter_ignored_synthetic.json"))
    http.add("GET", url("acordos_leniencia"), json=[])
    res = run_module(PortalTransparenciaApi, f"cnpj:{CNPJ}", http, keys=KEYS)
    assert not res.findings and "filter ignored" in res.error
    assert "could not verify" in res.raw["endpoints"]["ceis"]


def test_iso_8859_1_body_is_decoded_as_declared():
    http = FakeHttp().add("GET", url("pessoa_juridica"), json=summary(possuiContratacao=False, favorecidoDespesas=False, sancionadoCNEP=False))
    add_exchange(http, url("ceis"), "ceis_latin1_synthetic.http.json")
    http.add("GET", url("acordos_leniencia"), json=[])
    res = run_module(PortalTransparenciaApi, f"cnpj:{CNPJ}", http, keys=KEYS)
    [finding] = res.findings
    assert finding.data["sanction_type"] == "Impedimento/proibição de contratar com prazo determinado"


def test_contract_pages_are_capped_at_three_and_the_run_is_partial():
    page = [dict(fx("contratos_synthetic.json")[0], id=i, numero=f"C{i:03d}") for i in range(15)]
    http = FakeHttp().add("GET", url("pessoa_juridica"), json=summary(sancionadoCEIS=False, sancionadoCNEP=False, favorecidoDespesas=False))
    http.add("GET", url("acordos_leniencia"), json=[])
    for p in (1, 2, 3):
        http.add("GET", url("contratos", page=p), json=page)
    res = run_module(PortalTransparenciaApi, f"cnpj:{CNPJ}", http, keys=KEYS)
    contracts = res.attributes["federal_contracts"]
    assert contracts["count"] == 45 and contracts["count_is_lower_bound"] and contracts["pages"] == 3
    assert res.partial and res.stop_reason == "request_cap"
    assert not any("pagina=4" in u for u in http.urls())


def test_plan_stays_within_max_requests():
    everything = {k: True for k in ("sancionadoCEIS", "sancionadoCNEP", "sancionadoCEPIM", "possuiContratacao", "convenios", "favorecidoDespesas")}
    steps = pta.plan(everything, {})
    assert len(steps) + 1 <= PortalTransparenciaApi.max_requests == 10
    assert steps.count("contratos") == 3 and "convenios" in steps and "despesas" in steps
    assert pta.plan({"sancionadoCEIS": False, "possuiContratacao": False}, {}) == ["cnep", "cepim", "acordos_leniencia"]


# ------------------------------------------------------------------ rule 5
def test_429_is_rate_limited():
    http = add_exchange(FakeHttp(), url("pessoa_juridica"), "rate_limited_429_synthetic.http.json")
    assert run_module(PortalTransparenciaApi, f"cnpj:{CNPJ}", http, keys=KEYS).status is Status.RATE_LIMITED


def test_error_json_inside_200_is_an_error():
    http = FakeHttp().add("GET", url("pessoa_juridica"), json=fx("error_in_200_synthetic.json"))
    res = run_module(PortalTransparenciaApi, f"cnpj:{CNPJ}", http, keys=KEYS)
    assert res.status is Status.ERROR and "Erro na API" in res.error


@pytest.mark.parametrize("status", [500, 503])
def test_server_errors_are_could_not_verify(status):
    http = FakeHttp().add("GET", url("pessoa_juridica"), status=status, text="error")
    assert run_module(PortalTransparenciaApi, f"cnpj:{CNPJ}", http, keys=KEYS).status is Status.ERROR


def test_timeout_is_an_error():
    http = FakeHttp().add("GET", url("pessoa_juridica"), error=NetworkError("read timed out", kind="ReadTimeout", retryable=False))
    res = run_module(PortalTransparenciaApi, f"cnpj:{CNPJ}", http, keys=KEYS)
    assert res.status is Status.ERROR and res.reason_code == "timeout"


def test_html_or_malformed_json_is_an_error():
    http = FakeHttp().add("GET", url("pessoa_juridica"), text="<html><body>maintenance</body></html>")
    assert run_module(PortalTransparenciaApi, f"cnpj:{CNPJ}", http, keys=KEYS).status is Status.ERROR
    http2 = FakeHttp().add("GET", url("pessoa_juridica"), body=b'{"cnpj": "1122', headers={"content-type": "application/json"})
    assert run_module(PortalTransparenciaApi, f"cnpj:{CNPJ}", http2, keys=KEYS).status is Status.ERROR


def test_a_failed_drill_down_keeps_the_summary():
    http = FakeHttp().add("GET", url("pessoa_juridica"), json=summary(possuiContratacao=False, favorecidoDespesas=False, sancionadoCNEP=False))
    http.add("GET", url("ceis"), status=429, text="slow down")
    http.add("GET", url("acordos_leniencia"), json=[])
    res = run_module(PortalTransparenciaApi, f"cnpj:{CNPJ}", http, keys=KEYS)
    assert res.status is Status.OK and res.partial and res.stop_reason == "rate_limited"
    assert "transparencia_summary" in res.attributes and not res.findings


# ------------------------------------------------------------------ cond 3: no CPF or NIS, ever
@pytest.mark.parametrize("endpoint", sorted(pta.ENDPOINTS))
def test_no_cpf_or_nis_parameter_is_ever_built(endpoint):
    for value in ("12345678909", "123.456.789-09", "12345678901", "00000000000"):
        with pytest.raises((ValueError, PermissionError)):
            pta.build_request(endpoint, value, year=2026)
    built = pta.build_request(endpoint, CNPJ, year=2026)
    assert pta.personal_param_violations(built) == []
    assert not re.search(r"(?<!\d)\d{11}(?!\d)", built)


@pytest.mark.parametrize(
    "forbidden",
    ["https://api.portaldatransparencia.gov.br/api-de-dados/pessoa-fisica?cpf=12345678909&nis=1",
     "https://api.portaldatransparencia.gov.br/api-de-dados/ceaf?cpfSancionado=12345678909&pagina=1",
     "https://api.portaldatransparencia.gov.br/api-de-dados/peps?cpf=12345678909&pagina=1",
     "https://api.portaldatransparencia.gov.br/api-de-dados/servidores?cpf=12345678909&pagina=1",
     "https://api.portaldatransparencia.gov.br/api-de-dados/novo-bolsa-familia-por-cpf-ou-nis?codigo=12345678909",
     "https://api.portaldatransparencia.gov.br/api-de-dados/contratos/cpf-cnpj?cpfCnpj=12345678909&pagina=1"],
)
def test_forbidden_requests_are_recognised(forbidden):
    assert pta.personal_param_violations(forbidden)


def test_unknown_endpoints_and_digit_names_are_refused():
    with pytest.raises(PermissionError):
        pta.build_request("pessoa_fisica", CNPJ)
    with pytest.raises(ValueError):
        pta.build_name_request("peps", "12345678909")
    with pytest.raises(PermissionError):
        pta.build_name_request("servidores", "FULANO DE TAL EXEMPLO")


def test_every_request_of_a_full_run_is_free_of_cpf_values():
    http = full_routes()
    run_module(PortalTransparenciaApi, f"cnpj:{CNPJ}", http, keys=KEYS)
    for u in http.urls():
        assert pta.personal_param_violations(u) == [] and not re.search(r"(?<!\d)\d{11}(?!\d)", u)


# ------------------------------------------------------------------ cond 4: PEP by name for a due-diligence subject
PEP_ROWS = [{"cpf": "***.123.456-**", "nome": "FULANO DE TAL EXEMPLO", "sigla_funcao": "DAS", "descricao_funcao": "DIRETOR EXEMPLO",
             "nivel_funcao": "101.5", "cod_orgao": "99000", "nome_orgao": "MINISTERIO EXEMPLO", "dt_inicio_exercicio": "01/02/2023",
             "dt_fim_exercicio": "", "dt_fim_carencia": ""},
            {"cpf": "***.987.654-**", "nome": "FULANO DE TAL EXEMPLO FILHO", "descricao_funcao": "ASSESSOR", "nome_orgao": "OUTRO ORGAO"}]


def test_pep_by_name_for_an_analyst_typed_subject_with_a_purpose():
    name = "Fulano de Tal Exemplo"
    http = FakeHttp().add("GET", pta.build_name_request("peps", name), json=PEP_ROWS)
    opts = ScanOptions(purpose="supplier due diligence (ticket DD-1)")
    res = run_module(PortalTransparenciaApi, f"person_name:{name}", http, keys=KEYS, options=opts)
    assert res.status is Status.OK
    [finding] = res.findings  # exact normalised name only
    assert finding.title == "PEP (possible match)" and finding.severity is Severity.INFO
    assert {"context_only", "pep", "privacy"} <= set(finding.tags)
    assert finding.data["cpf_as_published"] == "***.123.456-**"
    assert all("cpf=" not in u for u in http.urls())


def test_pep_needs_a_recorded_purpose_and_an_analyst_typed_subject():
    res = run_module(PortalTransparenciaApi, "person_name:Fulano de Tal Exemplo", FakeHttp(), keys=KEYS)
    assert res.status is Status.SKIPPED and res.reason_code == "privacy"
    res2 = run_module(PortalTransparenciaApi, "person_name:Fulano de Tal Exemplo", FakeHttp(), keys=KEYS, is_seed=False, depth=1,
                      provenance=(("cnpj:11222333000181", "partner_of", "cnpj_lookup"),), options=ScanOptions(purpose="dd"))
    assert res2.status is Status.SKIPPED and res2.reason_code == "privacy"


def test_full_cpfs_are_masked_if_the_api_ever_returns_them():
    assert pta.mask_cpf("12345678909") == "***.456.789-**"
    assert pta.mask_cpf("***.456.789-**") == "***.456.789-**"
    assert pta.mask_cpf("") is None


# ------------------------------------------------------------------ helpers
def test_money_and_dates():
    assert pta.parse_money("150.000,00") == 150000.0 and pta.parse_money("R$ 1.234,56") == 1234.56
    assert pta.parse_money(12000.0) == 12000.0 and pta.parse_money("n/a") is None
    assert pta.iso_date("03/06/2024") == "2024-06-03" and pta.iso_date("2024-03-10") == "2024-03-10"


def test_bulk_freshness_reads_the_p240_dataset_age(monkeypatch):
    monkeypatch.undo()
    from datetime import datetime, timedelta, timezone
    from types import SimpleNamespace

    now = datetime(2026, 11, 26, 12, 0, tzinfo=timezone.utc)

    def ctx(fetched: str | None) -> SimpleNamespace:
        info = SimpleNamespace(present=fetched is not None, fetched_at=fetched or "")
        return SimpleNamespace(data=SimpleNamespace(info=lambda name: info), now=lambda: now)

    assert pta.bulk_fresh(ctx((now - timedelta(hours=10)).isoformat()), "ceis") is True
    assert pta.bulk_fresh(ctx((now - timedelta(hours=60)).isoformat()), "ceis") is False
    assert pta.bulk_fresh(ctx(None), "ceis") is False


def test_acceptance_routes_are_empty_without_the_team_key():
    from tests.fakes import fixture

    doc = fixture("acceptance/cnpj/portal_transparencia_api.json")
    assert (doc["schema"], doc["module"], doc["routes"]) == ("v3lum.acceptance_routes/1", "portal_transparencia_api", [])
    http = FakeHttp()
    assert run_module(PortalTransparenciaApi, "cnpj:00000000000191", http).status is Status.NEEDS_KEY and not http.calls
