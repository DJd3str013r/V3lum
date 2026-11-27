"""Offline tests of tcu_certidoes (P239) over tests/fixtures/tcu_certidoes/.

ok.json and not_in_base_alnum.json are live captures (2026-11-26); sistema_indisponivel.json is the
research capture of 2026-11-25; CONSTA, missing-entry, 5xx and timeout answers are synthetic (no real
CONSTA shape was observed).
"""

from __future__ import annotations

from tests.fakes import FakeHttp, module_fixture, run_module
from v3lum.core.http import NetworkError
from v3lum.core.models import Status
from v3lum.modules.brazil_public_data import tcu_certidoes as mod
from v3lum.modules.brazil_public_data.tcu_certidoes import TcuCertidoes

BB = "00000000000191"
ALFA = "11222333000181"
ALNUM = "12ABC34501DE35"
URL = "https://certidoes-apf.apps.tcu.gov.br/api/rest/publico/certidoes/{}?seEmitirPDF=false"
LIST_SOURCES = mod.LIST_SOURCES


def fx(name: str):
    return module_fixture("tcu_certidoes", name)


def add_exchange(http: FakeHttp, url: str, name: str) -> FakeHttp:
    resp = fx(name)["response"]
    headers = {k: v for k, v in (resp.get("headers") or {}).items() if k.lower() != "content-length"}
    body = resp["body"]
    if isinstance(body, (dict, list)):
        return http.add("GET", url, status=resp["status"], json=body, headers=headers)
    return http.add("GET", url, status=resp["status"], text=body, headers=headers)


def test_nada_consta_for_a_cnpj_in_the_tcu_base():
    http = FakeHttp().add("GET", URL.format(BB), json=fx("ok.json"))
    res = run_module(TcuCertidoes, f"cnpj:{BB}", http)
    assert res.status is Status.OK
    assert res.attributes["tcu_base_found"] is True
    assert res.attributes["certificate_issued_at"] == "2026-11-26T02:11:00-03:00"
    lists = res.attributes["certificate_lists"]
    assert {lid: e["state"] for lid, e in lists.items()} == {"tcu_inidoneos": "nada_consta", "cnj_cnia": "nada_consta", "ceis": "nada_consta",
                                                             "cnep": "nada_consta"}
    assert lists["ceis"]["text"] == "no record in CEIS as of 26/11/2026 02:11"
    assert all(res.source_statuses[src]["status"] == "empty" for src in LIST_SOURCES.values())
    assert not res.findings
    # evidence: certificate time and per-list states (cond 5), never a PDF
    assert res.raw["issued_at"] == "2026-11-26T02:11:00-03:00"
    assert res.raw["states"]["cnj_cnia"] == "NADA_CONSTA" and res.raw["pdf_present"] is False
    # one keyless call, the 14-character CNPJ and seEmitirPDF=false (cond 1)
    assert http.urls() == [URL.format(BB)]
    http.assert_hosts_within(TcuCertidoes)


def test_cnpj_missing_from_the_tcu_base_is_never_a_clean_record():
    http = FakeHttp().add("GET", URL.format(ALNUM), json=fx("not_in_base_alnum.json"))
    res = run_module(TcuCertidoes, f"cnpj:{ALNUM}", http)
    assert res.status is Status.ERROR
    assert res.error == mod.TCU_NOT_IN_BASE
    assert res.attributes["tcu_base_found"] is False
    lists = res.attributes["certificate_lists"]
    assert {e["state"] for e in lists.values()} == {"unknown"}  # NADA_CONSTA in the body is ignored
    assert all(e["text"] == mod.TCU_NOT_IN_BASE for e in lists.values())
    assert {res.source_statuses[src]["status"] for src in LIST_SOURCES.values()} == {"error"}
    assert not res.findings


def test_consta_is_a_high_sanctions_finding_with_the_shared_dedup_key():
    http = FakeHttp().add("GET", URL.format(ALFA), json=fx("consta_synthetic.json"))
    res = run_module(TcuCertidoes, f"cnpj:{ALFA}", http)
    assert res.status is Status.OK
    by_list = {f.data["list"]: f for f in res.findings}
    assert set(by_list) == {"tcu_inidoneos", "ceis"}
    ceis = by_list["ceis"]
    assert ceis.severity.label == "high" and "sanctions" in ceis.tags and ceis.criterion
    assert ceis.data["dedup_key"] == f"ceis|{ALFA}|"
    assert ceis.data["emitter"] == "Portal da Transparência"
    assert ceis.references == ["http://www.portaltransparencia.gov.br/sancoes/ceis"]
    assert ceis.source == "tcu.certidoes_ceis" and ceis.observed_last
    assert by_list["tcu_inidoneos"].references == ["https://certidoes.apps.tcu.gov.br/lista-inidoneos"]
    assert res.attributes["sanctioned"] is True
    assert res.source_statuses["tcu.certidoes_cnep"]["status"] == "empty"


def test_sistema_indisponivel_is_unknown_never_clean():
    http = FakeHttp().add("GET", URL.format(BB), json=fx("sistema_indisponivel.json"))
    res = run_module(TcuCertidoes, f"cnpj:{BB}", http)
    assert res.status is Status.OK
    cnia = res.attributes["certificate_lists"]["cnj_cnia"]
    assert cnia["state"] == "unknown" and "SISTEMA_INDISPONIVEL" in cnia["text"] and cnia["text"].startswith("could not verify")
    row = res.source_statuses["tcu.certidoes_cnia"]
    assert row["status"] == "error" and row["reason"].startswith("could not verify CNJ CNIA")
    assert res.source_statuses["tcu.certidoes_ceis"]["status"] == "empty"


def test_missing_entry_is_unknown():
    http = FakeHttp().add("GET", URL.format(BB), json=fx("missing_entry_synthetic.json"))
    res = run_module(TcuCertidoes, f"cnpj:{BB}", http)
    cnep = res.attributes["certificate_lists"]["cnep"]
    assert cnep["state"] == "unknown" and "missing from the TCU answer" in cnep["text"]
    assert res.source_statuses["tcu.certidoes_cnep"]["status"] == "error"


def test_alphanumeric_cnia_state_is_unknown():
    parsed = mod.parse_tcu_certidoes({**fx("not_in_base_alnum.json"), "seCnpjEncontradoNaBaseTcu": True})
    assert parsed["lists"]["cnj_cnia"]["state"] == "unknown"
    assert "alphanumeric" in parsed["lists"]["cnj_cnia"]["text"]
    assert parsed["lists"]["ceis"]["state"] == "nada_consta"


def test_server_error_makes_every_list_unknown():
    http = add_exchange(FakeHttp(), URL.format(BB), "server_error_synthetic.http.json")
    http.add("GET", URL.format(BB), status=503, text="unavailable")  # the profile's single retry
    res = run_module(TcuCertidoes, f"cnpj:{BB}", http)
    assert res.status is Status.ERROR and "could not verify" in res.error
    assert {res.source_statuses[src]["status"] for src in LIST_SOURCES.values()} == {"error"}
    assert {e["state"] for e in res.attributes["certificate_lists"].values()} == {"unknown"}


def test_timeout_is_could_not_verify():
    http = FakeHttp().add("GET", URL.format(BB), error=NetworkError("read timed out", kind="ReadTimeout", retryable=False))
    res = run_module(TcuCertidoes, f"cnpj:{BB}", http)
    assert res.status is Status.ERROR and res.reason_code == "timeout"
    assert {res.source_statuses[src]["reason_code"] for src in LIST_SOURCES.values()} == {"timeout"}


def test_rate_limit_and_challenge():
    http = FakeHttp().add("GET", URL.format(BB), status=429, text="Too Many Requests", headers={"retry-after": "60"})
    res = run_module(TcuCertidoes, f"cnpj:{BB}", http)
    assert res.status is Status.RATE_LIMITED
    page = "<html><head><title>Just a moment...</title></head><body>cf-chl-widget</body></html>"
    http2 = FakeHttp().add("GET", URL.format(BB), status=403, text=page)
    res2 = run_module(TcuCertidoes, f"cnpj:{BB}", http2)
    assert res2.status is Status.BLOCKED


def test_error_body_inside_http_200_and_formatted_path_404():
    http = FakeHttp().add("GET", URL.format(BB), json={"mensagem": "Erro interno"})
    res = run_module(TcuCertidoes, f"cnpj:{BB}", http)
    assert res.status is Status.ERROR and "unexpected shape" in res.error
    http2 = FakeHttp().add("GET", URL.format(BB), text="<html>not json</html>", headers={"content-type": "application/json"})
    assert run_module(TcuCertidoes, f"cnpj:{BB}", http2).status is Status.ERROR
    # why the formatted CNPJ is never sent: the Apache front decodes %2F and answers 404 HTML (live capture)
    formatted = "https://certidoes-apf.apps.tcu.gov.br/api/rest/publico/certidoes/00.000.000%2F0001-91?seEmitirPDF=false"
    assert fx("formatted_cnpj_404.http.json")["request"] == f"GET {formatted}"
    assert mod.tcu_request_url("00.000.000/0001-91") == URL.format(BB)


def test_tcu_datetime_is_brasilia_time():
    assert mod.parse_tcu_datetime("26/11/2026 02:20") == "2026-11-26T02:20:00-03:00"
    assert mod.parse_tcu_datetime("2026-11-26") is None
