"""br_cnpj_risk_lists (P244): BR offline risk lists by CNPJ (MTE lista suja, CVM, BrasilAPI brokers, opt-in PGFN).

Fixtures in tests/fixtures/br_cnpj_risk_lists/ (prep capture 2026-11-26, minimised; module_fixture paths
"br_cnpj_risk_lists/<file>"):

* ``mte_ok.csv`` - the real MTE header, ISO-8859-1, CRLF and no final newline, with real ID/year/UF/workers/CNAE/
  decision/inclusion values (multi-period inclusions, '(*1)'/'(*4)' footnotes, an MEI row); every employer name and
  document is synthetic (documentation CNPJs; synthetic persons with documentation CPFs). ``mte_header_only.csv`` and
  ``mte_moved_html_synthetic.html`` cover the refused copies.
* ``pgfn_{sida,prev,fgts}_ok.zip`` - real member names and CSV headers from 64 KiB Range captures of the 2026 Q3 files
  with synthetic rows (persons with masked CPFs, the 01/01/1000 sentinel); ``pgfn_bad_header.zip`` (schema drift),
  ``pgfn_truncated.zip`` (partial download) and the real ``pgfn_index.html`` / ``pgfn_quarter_listing.html``
  Apache indexes.
* ``cvm_sancionador_ok.zip`` - real member names and headers, synthetic proceedings and accused (entities and
  persons); ``cvm_cia_aberta_ok.csv`` (5 real issuers, every contact/officer column blanked) and a truncated copy;
  ``cvm_intermed_ok.csv`` (real BB intermediary rows of the shared CVM loader, contacts replaced by documentation
  values).
* ``brasilapi_corretoras_ok.json`` (5 real brokers, contacts replaced) and a truncated copy.
"""

from __future__ import annotations

import io
import json
import os
import sqlite3
import time
import zipfile

import pytest

from tests.fakes import FIXTURES, FakeHttp, make_runtime, run_module
from v3lum import paths
from v3lum.core.context import ScanOptions
from v3lum.core.datasets import DATASETS
from v3lum.core.models import Status
from v3lum.modules.brazil_public_data import br_cnpj_risk_lists as R
from v3lum.modules.brazil_public_data import pgfn_import as P
from v3lum.modules.brazil_public_data.br_cnpj_risk_lists import BrCnpjRiskLists

FIX = FIXTURES / "br_cnpj_risk_lists"
PERSON_STRINGS = ("FULANO", "BELTRANO", "CICLANO", "123.456.789", "987.654.321", "111.444.777", "456.789XX", "654.321XX")


def fx(name: str) -> bytes:
    return (FIX / name).read_bytes()


def install(name: str, body: bytes, *, age_days: float = 0.0) -> None:
    path = paths.datasets_dir() / name
    path.write_bytes(body)
    if age_days:
        when = time.time() - age_days * 86400
        os.utime(path, (when, when))


def install_all(*, pgfn: bool = True, brokers: bytes | None = None) -> None:
    install(R.MTE_DATASET, fx("mte_ok.csv"))
    install(R.SANCTIONS_DATASET, fx("cvm_sancionador_ok.zip"))
    install(R.BROKERS_DATASET, brokers if brokers is not None else fx("brasilapi_corretoras_ok.json"))
    install(R.CIA_DATASET, fx("cvm_cia_aberta_ok.csv"))
    install("cvm_intermed.csv", fx("cvm_intermed_ok.csv"))
    if pgfn:
        build_pgfn()


def build_pgfn(**kw):
    zips = [fx("pgfn_sida_ok.zip"), fx("pgfn_prev_ok.zip"), fx("pgfn_fgts_ok.zip")]
    return P.build_index(zips, P.index_path(), quarter="2026_trimestre_03", **kw)


def run(value: str, **kw):
    http = FakeHttp()  # no routes: any download attempt fails the test
    kw.setdefault("runtime", make_runtime(http, settings=kw.pop("settings", None)))
    res = run_module(BrCnpjRiskLists, value, **kw)
    http.assert_hosts_within(BrCnpjRiskLists)
    assert not http.urls()
    return res


def blob(res) -> str:
    return json.dumps({"raw": res.raw, "attrs": res.attributes, "findings": [f.to_dict() for f in res.findings],
                       "statuses": res.source_statuses, "error": res.error}, default=str)


def finding(res, prefix: str):
    found = [f for f in res.findings if f.title.startswith(prefix)]
    assert found, [f.title for f in res.findings]
    return found


# ======================================================================================
# parsers, minimisation and validation (FC1, FC3)
# ======================================================================================


def test_mte_parse_drops_persons_and_withholds_mei_names():
    parsed = R.parse_mte_lista_suja(fx("mte_ok.csv"))
    assert parsed["header_ok"] and not parsed["errors"] and parsed["dropped_persons"] == 3
    by = {r["id"]: r for r in parsed["rows"]}
    assert set(by) == {"8", "35", "504", "401", "137", "454"}
    assert by["401"]["mei"] and by["401"]["name"] is None and by["401"]["cnpj"] == "11222333000262"
    assert by["454"]["name"] == "EXEMPLO CONSTRUTORA E INCORPORADORA LTDA" and by["454"]["footnote"] == "(*4)"
    assert by["35"]["inclusion_date"] == "2025-04-09" and by["35"]["inclusion_periods"] == [{"from": "2024-04-05", "to": "2024-05-10"}]
    text = json.dumps(parsed)
    for needle in PERSON_STRINGS + ("SITIO EXEMPLO", "RUA EXEMPLO", "OBRA EXEMPLO"):  # no person, no establishment address
        assert needle not in text


def test_mte_include_persons_keeps_masked_cpf_only():
    parsed = R.parse_mte_lista_suja(fx("mte_ok.csv"), include_persons=True)
    persons = [r for r in parsed["rows"] if r["kind"] == "person"]
    assert {p["name"] for p in persons} == {"FULANO DE TAL", "BELTRANO DA SILVA", "CICLANO SOUZA"}
    assert {p["cpf_masked"] for p in persons} == {"***.456.789-**", "***.654.321-**", "***.444.777-**"}
    assert "123.456.789-09" not in json.dumps(parsed)


def test_mte_validation():
    assert R.mte_problem(fx("mte_ok.csv"), min_rows=1) == ""
    assert "too few rows" in R.mte_problem(fx("mte_ok.csv"))  # production floor: ~500 rows
    assert "too few rows" in R.mte_problem(fx("mte_header_only.csv"), min_rows=1)
    assert "HTML" in R.mte_problem(fx("mte_moved_html_synthetic.html"))
    assert "schema drift" in R.mte_problem(b"A;B;C\r\n1;2;3")


def test_sanctions_parse_keeps_entities_only():
    parsed = R.parse_cvm_sancionador_zip(fx("cvm_sancionador_ok.zip"))
    assert not parsed["errors"] and parsed["dropped_persons"] == 2 and len(parsed["proceedings"]) == 3
    outcomes = {a["name"]: a["outcome"] for a in parsed["accused"]}
    assert outcomes == {"EXEMPLO CORRETORA DE VALORES S.A.": "pending", "AUDITORES INDEPENDENTES EXEMPLO S/S": "acquitted",
                        "EXEMPLO INVESTIMENTOS LTDA": "settlement", "BANCO EXEMPLO S.A.": "convicted"}
    assert "FULANO" not in json.dumps(parsed) and "BELTRANO" not in json.dumps(parsed)
    with_persons = R.parse_cvm_sancionador_zip(fx("cvm_sancionador_ok.zip"), include_persons=True)
    assert {a["name"] for a in with_persons["accused"] if a["kind"] == "person"} == {"FULANO DE TAL", "BELTRANO DA SILVA"}


@pytest.mark.parametrize(("name", "kind"), [("BANCO EXEMPLO S.A.", "entity"), ("AUDITORES EXEMPLO S/S", "entity"), ("JOAO DE SA", "person"),
                                            ("MARIA SA SILVA", "person"), ("EXEMPLO DTVM", "entity"), ("", "person")])
def test_accused_kind_fails_closed(name, kind):
    assert R.cvm_accused_kind(name) == kind


def test_sanctions_and_brokers_validation():
    assert R.sanctions_problem(fx("cvm_sancionador_ok.zip")) == ""
    assert "truncated" in R.sanctions_problem(fx("pgfn_truncated.zip"))
    assert "missing members" in R.sanctions_problem(fx("pgfn_sida_ok.zip"))
    assert "malformed JSON" in R.brokers_problem(fx("brasilapi_corretoras_truncated.json"))
    assert "too few brokers" in R.brokers_problem(fx("brasilapi_corretoras_ok.json"))
    assert "unexpected shape" in R.brokers_problem(b'{"message": "error", "type": "x"}')


def test_brokers_parse_drops_contacts():
    parsed = R.parse_brasilapi_corretoras(fx("brasilapi_corretoras_ok.json"))
    assert parsed["error"] is None and len(parsed["rows"]) == 5
    text = json.dumps(parsed)
    assert "contato@example.com" not in text and "1155550100" not in text and "RUA EXEMPLO" not in text
    assert {r["status"] for r in parsed["rows"]} == {"active", "cancelled"}


def test_severity_table_and_datasets():
    assert R.SEVERITY["mte_lista_suja"] == "high" and R.SEVERITY["cvm_sancionador"] == "medium"
    assert R.SEVERITY["pgfn_divida_ativa"] == "low" and R.SEVERITY["brasilapi_corretoras"] == "info"
    for name, source in ((R.MTE_DATASET, "govbr.br_cnpj_risk_lists_mte"), (R.SANCTIONS_DATASET, "cvm.sanctions"),
                         (R.BROKERS_DATASET, "brasilapi.cvm_brokers")):
        reg = DATASETS[name]
        assert reg["source"] == source and reg["terms_class"] == "open" and reg["essential"] and not reg["large"]
        assert reg["max_bytes"] <= 5 * 1024 * 1024  # small: never classified large, never fetched by the module


# ======================================================================================
# PGFN importer (FC2, FC3)
# ======================================================================================


def test_pgfn_index_is_built_by_streaming_and_drops_persons():
    info = build_pgfn()
    assert info["rows"] == 8 and info["dropped_persons"] == 3 and info["persons"] == 0 and info["ref_months"] == ["2026-09"]
    idx, problem = P.open_index()
    assert problem == "" and idx.meta["include_persons"] == "0" and idx.meta["quarter"] == "2026_trimestre_03"
    rows = idx.by_cnpj("11222333000181")
    assert {(r["nature"], r["match"]) for r in rows} == {("demais (nao previdenciaria)", "exact"), ("demais (nao previdenciaria)", "root"),
                                                         ("previdenciaria", "exact"), ("FGTS", "exact")}
    assert idx.by_name("Exemplo Alimentos SA")[0]["cnpj"] == "11444777000161"
    assert idx.persons_by_name("FULANO DE TAL") == []
    idx.close()
    raw = P.index_path().read_bytes()
    for needle in (b"FULANO", b"BELTRANO", b"CICLANO", b"XXX"):
        assert needle not in raw  # never in the on-disk index
    assert oct(P.index_path().stat().st_mode & 0o777) == "0o600"


def test_pgfn_include_persons_needs_a_purpose_and_records_it():
    with pytest.raises(P.ImportError_, match="purpose"):
        build_pgfn(include_persons=True)
    info = build_pgfn(include_persons=True, purpose="due diligence ticket DD-1")
    assert info["persons"] == 3
    idx, _ = P.open_index()
    assert idx.meta["include_persons"] == "1" and idx.meta["purpose"] == "due diligence ticket DD-1"
    assert idx.persons_by_name("Fulano de Tal")[0]["cpf_masked"] == "XXX456.789XX"
    idx.close()


def test_pgfn_schema_drift_keeps_the_previous_index():
    build_pgfn()
    before = P.index_path().read_bytes()
    with pytest.raises(P.FormatChanged, match="schema drift"):
        P.build_index([fx("pgfn_bad_header.zip")], P.index_path(), quarter="2026_trimestre_04")
    with pytest.raises(P.FormatChanged, match="truncated"):
        P.build_index([fx("pgfn_truncated.zip")], P.index_path(), quarter="2026_trimestre_04")
    assert P.index_path().read_bytes() == before
    assert not P.index_path().with_name("pgfn.sqlite.building").exists()


def test_pgfn_helpers():
    listing = P.parse_directory(fx("pgfn_index.html"))
    assert listing["latest"] == "2026_trimestre_03" and "Dados_abertos_Nao_Previdenciario.zip" in listing["zips"]
    assert P.parse_directory(fx("pgfn_quarter_listing.html"))["zips"] == [
        "Dados_abertos_FGTS.zip", "Dados_abertos_Previdenciario.zip", "Dados_abertos_Sistema_SIDA.zip"]
    assert P.member_info("arquivo_lai_PREV_-1_202609.csv") == {"kind": "PREV", "nature": "previdenciaria", "seq": -1, "ref_month": "2026-09"}
    assert P.parse_br_date("01/01/1000") is None and P.amount_band("150000000.00") == ">= R$ 100 mi"
    assert P.zip_problem(b"<!DOCTYPE html><html>") and "HTML" in P.zip_problem(b"<!DOCTYPE html><html>")


def _pgfn_site_http(files: dict[str, bytes]) -> FakeHttp:
    http = FakeHttp()
    http.add("GET", P.BASE_URL, body=fx("pgfn_index.html"), headers={"content-type": "text/html"})
    http.add("GET", P.BASE_URL + "2026_trimestre_03/", body=fx("pgfn_quarter_listing.html"), headers={"content-type": "text/html"})
    for name, body in files.items():
        url = f"{P.BASE_URL}2026_trimestre_03/{name}"
        http.add("GET", url, status=206, body=body[:1], match_headers={"Range": "bytes=0-0"},
                 headers={"content-range": f"bytes 0-0/{len(body)}", "etag": '"e1"', "content-type": "application/zip"})
        http.add("GET", url, status=206, body=body, match_headers={"Range": f"bytes=0-{len(body) - 1}"},
                 headers={"content-range": f"bytes 0-{len(body) - 1}/{len(body)}", "etag": '"e1"', "content-type": "application/zip"})
    return http


def test_pgfn_plan_and_import_through_the_pgfn_host_only():
    files = {"Dados_abertos_FGTS.zip": fx("pgfn_fgts_ok.zip"), "Dados_abertos_Previdenciario.zip": fx("pgfn_prev_ok.zip"),
             "Dados_abertos_Sistema_SIDA.zip": fx("pgfn_sida_ok.zip")}
    http = _pgfn_site_http(files)
    rt = make_runtime(http)
    plan = P.plan(rt)
    assert plan["quarter"] == "2026_trimestre_03" and plan["download_bytes"] == sum(len(b) for b in files.values())
    assert plan["ok"] and {f["name"] for f in plan["files"]} == set(files)
    res = P.import_pgfn(rt, confirm=lambda p: True)
    assert res["status"] == "imported" and res["rows"] == 8, res
    assert http.hosts() == {"dadosabertos.pgfn.gov.br"}
    assert not (P.index_path().parent / P.DOWNLOADS).exists()  # zips deleted after the import
    assert P.read_state()["imported"]["quarter"] == "2026_trimestre_03"


def test_pgfn_import_blocked_is_recorded_never_no_debt():
    http = FakeHttp().add("GET", P.BASE_URL, status=403, text="<html><body>Forbidden</body></html>")
    res = P.import_pgfn(make_runtime(http), confirm=lambda p: True)
    assert res["status"] in ("unavailable", "error") and P.read_state()["last_import"]["status"] == res["status"]
    assert P.open_index()[0] is None


# ======================================================================================
# the module (FC4-FC7)
# ======================================================================================


def test_cnpj_listed_in_mte_and_pgfn():
    install_all()
    res = run("cnpj:11.444.777/0001-61")
    assert res.status is Status.OK
    mte = finding(res, "Listed in the MTE")[0]
    assert mte.severity.name == "HIGH" and mte.confidence_label == "confirmed" and "esg_labour" in mte.tags
    assert "included 2025-04-09" in mte.description and "2024-04-05 a 2024-05-10" in mte.description
    pg = finding(res, "PGFN divida ativa")[0]
    assert pg.severity.name == "LOW" and pg.title == "PGFN divida ativa: demais (nao previdenciaria)" and "tax_debt" in pg.tags
    assert ">= R$ 100 mi" in pg.description and "judicial collection" in pg.description
    screening = res.attributes["risk_lists_screening"]
    assert screening["mte_lista_suja"]["state"] == "listed" and screening["pgfn_divida_ativa"]["state"] == "listed"
    assert screening["cvm_sancionador"]["state"] == "no_record"
    assert res.attributes["cvm_authorisation"].startswith("not found in CVM registries as of")
    assert {r["list"] for r in res.attributes["risk_lists"]} == {"mte_lista_suja", "pgfn_divida_ativa"}
    assert not res.pivots
    text = blob(res)
    for needle in PERSON_STRINGS:
        assert needle not in text
    cited = {c["name"] for c in res.datasets}
    assert {R.MTE_DATASET, R.SANCTIONS_DATASET, R.BROKERS_DATASET, R.CIA_DATASET} <= cited


def test_exact_and_root_matches_are_stated():
    install_all()
    res = run("cnpj:11.222.333/0002-62")
    mte = {f.data["id"]: f for f in finding(res, "Listed in the MTE")}
    assert mte["401"].confidence_label == "confirmed" and "MEI (entrepreneur name withheld)" in mte["401"].description
    assert mte["8"].confidence_label == "probable" and "same CNPJ root" in mte["8"].description
    pg = {f.title: f for f in finding(res, "PGFN divida ativa")}
    assert pg["PGFN divida ativa: demais (nao previdenciaria)"].data["match"] == "exact"
    assert pg["PGFN divida ativa: FGTS"].data["match"] == "root"


def test_company_name_finds_cvm_sanction_as_possible_match():
    install_all()
    res = run("company_name:Exemplo Investimentos Ltda")
    sanc = finding(res, "Named in a CVM sanction proceeding")[0]
    assert sanc.title == "Named in a CVM sanction proceeding (settlement)" and sanc.severity.name == "MEDIUM"
    assert sanc.confidence_label == "possible" and "name_only_match" in sanc.tags and "verify identifiers" in sanc.description
    assert sanc.data["nup"] == "19957000000000303"


def test_cnpj_seed_reaches_sanctions_through_the_registered_name():
    brokers = json.loads(fx("brasilapi_corretoras_ok.json"))
    brokers.append({"cnpj": "33444555000181", "type": "CORRETORAS", "nome_social": "EXEMPLO CORRETORA DE VALORES S.A.",
                    "nome_comercial": "", "status": "EM FUNCIONAMENTO NORMAL", "codigo_cvm": "9999", "data_registro": "2010-01-01",
                    "data_inicio_situacao": "2010-01-01"})
    install_all(brokers=json.dumps(brokers).encode())
    res = run("cnpj:33.444.555/0001-81")
    assert res.attributes["cvm_authorisation"].startswith("registered with CVM: active (brasilapi_corretoras)")
    assert finding(res, "Named in a CVM sanction proceeding (pending)")[0].confidence_label == "possible"
    assert finding(res, "Registered with CVM (active)")[0].confidence_label == "confirmed"


def test_cvm_authorisation_from_the_shared_loader():
    install_all()
    res = run("cnpj:00.000.000/0001-91")
    line = res.attributes["cvm_authorisation"]
    assert line.startswith("registered with CVM: active (") and "intermed" in line and "cia_aberta" in line
    regs = res.attributes["cvm_registrations"]
    assert {r["registry"] for r in regs} >= {"intermed", "cia_aberta"} and all(r["match"] == "exact" for r in regs)
    assert finding(res, "Registered with CVM (active)")[0].severity.name == "INFO"


def test_cancelled_broker_is_not_authorised():
    install_all()
    res = run("cnpj:76.621.457/0001-85")
    assert res.attributes["cvm_authorisation"].startswith("no active CVM registration as of")
    assert "brasilapi_corretoras cancelled" in res.attributes["cvm_authorisation"]
    assert not [f for f in res.findings if f.title.startswith("Registered with CVM")]


def test_clean_cnpj_reads_no_record_never_clean():
    install_all()
    res = run("cnpj:44.555.666/0001-81")
    assert res.status is Status.OK and not res.findings
    states = {k: v["state"] for k, v in res.attributes["risk_lists_screening"].items()}
    assert set(states.values()) == {"no_record"}
    assert res.attributes["risk_lists_screening"]["mte_lista_suja"]["line"].startswith("no record in MTE lista suja (Cadastro de Empregadores) as of ")
    assert res.attributes["cvm_authorisation"].startswith("not found in CVM registries as of")
    assert "clean" not in blob(res).lower() and "fraud" not in blob(res).lower()
    statuses = {k: v["status"] for k, v in res.source_statuses.items()}
    assert statuses["govbr.br_cnpj_risk_lists_mte"] == "empty" and statuses["pgfn.divida_ativa"] == "empty"


def test_nothing_downloaded_is_unavailable():
    res = run("cnpj:11.444.777/0001-61")
    assert res.status is Status.UNAVAILABLE and res.reason_code == "dataset"
    assert "not screened against MTE lista suja" in res.error and "opt-in import not done" in res.error


def test_missing_pgfn_and_stale_mte_read_not_screened():
    install_all(pgfn=False)
    install(R.MTE_DATASET, fx("mte_ok.csv"), age_days=30)
    res = run("cnpj:44.555.666/0001-81")
    screening = res.attributes["risk_lists_screening"]
    assert screening["pgfn_divida_ativa"]["state"] == "not_screened" and "opt-in import not done" in screening["pgfn_divida_ativa"]["line"]
    assert screening["mte_lista_suja"]["state"] == "not_screened" and screening["mte_lista_suja"]["line"].startswith(
        "not screened against MTE lista suja")
    statuses = res.source_statuses
    assert statuses["pgfn.divida_ativa"]["status"] == "unavailable" and statuses["pgfn.divida_ativa"]["reason_code"] == "dataset"
    assert statuses["govbr.br_cnpj_risk_lists_mte"]["status"] == "unavailable"
    assert "older than 14 days" in res.attributes["dataset_age"][0]
    # a stale copy still reports a hit, dated
    hit = run("cnpj:11.444.777/0001-61")
    assert finding(hit, "Listed in the MTE")


def test_broken_copy_is_an_error_for_that_list_only():
    install_all()
    install(R.MTE_DATASET, fx("mte_moved_html_synthetic.html"))
    res = run("cnpj:11.444.777/0001-61")
    statuses = res.source_statuses
    assert statuses["govbr.br_cnpj_risk_lists_mte"]["status"] == "error"
    assert res.attributes["risk_lists_screening"]["mte_lista_suja"]["state"] == "not_screened"
    assert finding(res, "PGFN divida ativa")


def test_only_allowed_sources_are_screened():
    install_all()
    res = run("cnpj:11.444.777/0001-61", allowed_sources={"govbr.br_cnpj_risk_lists_mte"})
    statuses = res.source_statuses
    assert statuses["pgfn.divida_ativa"]["status"] == "skipped" and statuses["pgfn.divida_ativa"]["reason_code"] == "licence"
    assert finding(res, "Listed in the MTE") and not [f for f in res.findings if f.title.startswith("PGFN")]


def test_cpf_shaped_company_name_is_never_a_key():
    install_all()
    res = run("company_name:123.456.789-09")
    assert res.status is Status.SKIPPED and res.reason_code == "not_applicable"


# ======================================================================================
# persons: explicit due diligence only (FC3)
# ======================================================================================


def test_person_seed_is_not_applicable_by_default():
    install_all()
    res = run("person_name:Fulano de Tal", options=ScanOptions(purpose="due diligence"))
    assert res.status is Status.SKIPPED and res.reason_code == "not_applicable"


def test_person_due_diligence_needs_a_purpose():
    install_all()
    res = run("person_name:Fulano de Tal", settings={"br_cnpj_risk_lists_include_persons": True})
    assert res.status is Status.SKIPPED and res.reason_code == "privacy" and "purpose" in res.error


def test_person_due_diligence_name_only_possible_match():
    install_all()
    build_pgfn(include_persons=True, purpose="due diligence ticket DD-1")
    res = run("person_name:Fulano de Tal", settings={"br_cnpj_risk_lists_include_persons": True},
              options=ScanOptions(purpose="supplier due diligence DD-1"))
    assert res.status is Status.OK
    rows = res.attributes["risk_lists_persons"]
    assert {r["list"] for r in rows} == {"mte_lista_suja", "cvm_sancionador", "pgfn_divida_ativa"}
    assert all(r["match"] == "possible" for r in rows)
    assert "123.456.789-09" not in blob(res) and "***.456.789-**" in blob(res)
    assert all(f.confidence_label == "possible" and "name_only_match" in f.tags for f in res.findings)
    assert not res.pivots
    assert res.attributes["homonym_risk"]["risk"] in ("unknown", "low", "medium", "high")


def test_person_single_word_or_cpf_is_refused():
    install_all()
    kw = {"settings": {"br_cnpj_risk_lists_include_persons": True}, "options": ScanOptions(purpose="dd")}
    assert run("person_name:Fulano", **kw).reason_code == "privacy"
    cpf = run("person_name:Fulano 123.456.789-09", **kw)
    assert cpf.status is Status.SKIPPED and "never a lookup key" in cpf.error


def test_pgfn_index_without_persons_reads_not_screened_for_persons():
    install_all()
    res = run("person_name:Ciclano Souza", settings={"br_cnpj_risk_lists_include_persons": True}, options=ScanOptions(purpose="dd"))
    statuses = res.source_statuses
    assert statuses["pgfn.divida_ativa"]["status"] == "unavailable"
    assert {r["list"] for r in res.attributes["risk_lists_persons"]} == {"mte_lista_suja"}


def test_fixtures_hold_only_documentation_identities():
    import re

    documentation_cpfs = {"123.456.789-09", "987.654.321-00", "111.444.777-35"}
    texts = []
    for name in ("pgfn_sida_ok.zip", "pgfn_prev_ok.zip", "pgfn_fgts_ok.zip", "cvm_sancionador_ok.zip"):
        with zipfile.ZipFile(io.BytesIO(fx(name))) as zf:
            texts.append(" ".join(zf.read(n).decode("latin-1") for n in zf.namelist()))
    for name in ("mte_ok.csv", "brasilapi_corretoras_ok.json", "cvm_cia_aberta_ok.csv", "cvm_intermed_ok.csv"):
        texts.append(fx(name).decode("latin-1"))
    text = " ".join(texts)
    assert set(re.findall(r"\d{3}\.\d{3}\.\d{3}-\d{2}", text)) <= documentation_cpfs
    assert {e.split("@")[1] for e in re.findall(r"[\w.+-]+@[\w.-]+", text)} <= {"example.com"}


def test_sqlite_index_is_read_only_for_the_module():
    install_all()
    idx, _ = P.open_index()
    with pytest.raises(sqlite3.OperationalError):
        idx.conn.execute("DELETE FROM debts")
    idx.close()


def test_truncated_listed_company_register_is_not_screened():
    install_all()
    install(R.CIA_DATASET, fx("cvm_cia_aberta_truncated.csv"))
    res = run("cnpj:00.000.000/0001-91")
    assert res.source_statuses["cvm.cnpj_name_resolver_cia_aberta"]["status"] == "error"
    assert res.attributes["risk_lists_screening"]["cvm_cia_aberta"]["state"] == "not_screened"
    assert "not screened: CVM listed companies" in res.attributes["cvm_authorisation"]
