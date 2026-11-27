"""cnpj_name_resolver (P361): company name -> ranked 'possible CNPJ' hypotheses.

Fixtures in tests/fixtures/cnpj_name_resolver/ (batch p2-G10-3 prep, 2026-11-25/26):

* GLEIF (CC0, live/research): ``gleif_fulltext_ok.json`` (Kirton without registeredAs, two funds, a
  DUPLICATE BB record whose registeredAs is neither a CPF nor a CNPJ), ``gleif_legalname_ok.json`` (the
  legalName filter is not exact: BB and BNB), ``gleif_legalname_research.json``, ``gleif_registeredas_ok.json``,
  ``gleif_registeredas_digits_empty.json`` (raw digits find nothing), ``gleif_lei_record_ok.json``,
  ``gleif_fuzzy_ok.json``, ``gleif_fuzzy_empty.json``, ``gleif_empty.json``, ``gleif_not_found_404.http.json``;
* the Wikidata captures live in tests/fixtures/cnpj_name_resolver_wikidata/ (companion module);
* BCB Olinda: ``bcb_dominios_ok.json``, ``bcb_sedes_bancos_ok.json`` (contacts dropped), ``bcb_empty.json``,
  ``bcb_odata_error_500.txt``; CVM: ``cvm_cia_aberta_ok.csv`` (real header, 14 rows, latin-1/CRLF, officer,
  phone, e-mail, street and auditor columns blanked), ``cvm_cia_aberta_truncated.csv``,
  ``cvm_ckan_package_show_ok.json``, ``cvm_intermed_ok.csv`` (batch p1-G10-3 fixture);
* RFB (synthetic slice in the real layout): ``rfb_empresas_synthetic.csv`` (an MEI name carrying the
  documentation CPF 123.456.789-09, an EI natural-person name, homonyms active and BAIXADA),
  ``rfb_estabelecimentos_synthetic.csv`` (contact columns with documentation values),
  ``rfb_municipios_synthetic.csv`` and ``rfb_month_listing.json`` (the research PROPFIND, parsed).
"""

from __future__ import annotations

import json
import random
import re
import sqlite3
import time

import pytest

from tests.fakes import FIXTURES, FakeHttp, make_runtime, module_fixture, run_module
from v3lum import paths
from v3lum.core import validators
from v3lum.core.context import ScanOptions
from v3lum.core.entities import EntityType as T
from v3lum.core.http import NetworkError
from v3lum.core.models import Status
from v3lum.modules.brazil_public_data import bcb_authorized_institutions as B
from v3lum.modules.brazil_public_data import cnpj_name_resolver as R
from v3lum.modules.brazil_public_data.cnpj_name_resolver import CnpjNameResolver

FIX = FIXTURES / "cnpj_name_resolver"
BB = "00000000000191"


def fx(name: str):
    return module_fixture("cnpj_name_resolver", name)


def raw(name: str) -> bytes:
    return (FIX / name).read_bytes()


def install(name: str, body: bytes) -> None:
    (paths.datasets_dir() / name).write_bytes(body)


def install_registries(*, cia: bytes | None = None, bcb: bool = True, intermed: bool = False) -> None:
    install(R.CIA_ABERTA_DATASET, raw("cvm_cia_aberta_ok.csv") if cia is None else cia)
    if intermed:
        install("cvm_intermed.csv", raw("cvm_intermed_ok.csv"))
    if bcb:
        install(B.DOMINIOS.dataset, raw("bcb_dominios_ok.json"))
        install("bcb_sedes_bancos.json", raw("bcb_sedes_bancos_ok.json"))
        for name in ("bcb_sedes_sociedades.json", "bcb_sedes_consorcios.json", "bcb_sedes_cooperativas.json"):
            install(name, raw("bcb_empty.json"))


def slice_index(path, *, force_fallback: bool = False, snapshot: str = "2026-11") -> dict:
    emp = R.parse_rfb_empresas(raw("rfb_empresas_synthetic.csv"))
    est = R.parse_rfb_estabelecimentos(raw("rfb_estabelecimentos_synthetic.csv"))
    mun = R.parse_rfb_municipios(raw("rfb_municipios_synthetic.csv"))
    return R.build_index(path, emp, est, mun, snapshot=snapshot, force_fallback=force_fallback)


def online_http(query: str, *, gleif: dict | None = None) -> FakeHttp:
    return FakeHttp().add("GET", R.gleif_url(query), **(gleif or {"json": fx("gleif_fulltext_ok.json")}))


def res_name(res) -> dict:
    return res.attributes["name_resolution"]


def cnpj_pivots(res) -> dict:
    return {p.entity.value: p for p in res.pivots if p.entity.type is T.CNPJ}


# ======================================================================================
# normalisation (FC3, FC4)
# ======================================================================================


@pytest.mark.parametrize(
    ("name", "core", "extra"),
    [
        ("BANCO DO BRASIL S.A.", "BANCO DO BRASIL", {"legal_forms": ["SA"]}),
        ("Banco do Brasil S/A", "BANCO DO BRASIL", {}),
        ("Padaria Exemplo Eireli", "PADARIA EXEMPLO", {}),
        ("Exemplo & Filhos Ltda - ME", "EXEMPLO E FILHOS", {}),
        ("Exemplo Servicos SLU", "EXEMPLO SERVICOS", {}),
        ("Exemplo Comercio EPP", "EXEMPLO COMERCIO", {}),
        ("Construtora Exemplo Sociedade Anonima", "CONSTRUTORA EXEMPLO", {}),
        ("2W ECOBANK S.A. - EM RECUPERAÇÃO JUDICIAL", "2W ECOBANK", {"status_suffix": "EM RECUPERACAO JUDICIAL"}),
        ("AÇÚCAR ÉXEMPLO LTDA", "ACUCAR EXEMPLO", {}),
        ("PESSOA EXEMPLO DA SILVA 12345678909", "PESSOA EXEMPLO DA SILVA", {"cpf_removed": 1}),
        ("PESSOA EXEMPLO 123.456.789-09", "PESSOA EXEMPLO", {"cpf_removed": 1}),
    ],
)
def test_normalize_company_name(name, core, extra):
    nn = R.normalize_company_name(name)
    assert nn["core"] == core
    for k, v in extra.items():
        assert nn[k] == v


def test_cpf_stripping_keeps_longer_numbers():
    clean, n = R.strip_cpf_sequences("CIA SIDERURGICA (sucedida pela UNIAO FEDERAL -CNPJ:37115383000153")
    assert n == 0 and "37115383000153" in clean
    clean, n = R.strip_cpf_sequences("FULANO 12345678909 E 98765432100")
    assert n == 2 and not re.search(r"\d", clean)


def test_match_kinds():
    assert R.match_kind("BANCO DO BRASIL", "BANCO DO BRASIL", "razao") == "exact_razao"
    assert R.match_kind("BANCO DO BRASIL", "BANCO DO BRASIL", "fantasia") == "exact_fantasia"
    assert R.match_kind("BANCO BRASIL", "BANCO DO BRASIL", "razao") == "contains"
    assert R.match_kind("BANCO DO BRASIL SUL", "BANCO DO BRASIL", "razao") == "fuzzy"
    assert R.match_kind("PADARIA", "BANCO DO BRASIL", "razao") is None
    assert R.match_kind("", "X", "razao") is None


# ======================================================================================
# RFB light index (FC2-FC4, FC9)
# ======================================================================================


def test_rfb_parsers_minimise_and_strip_cpf():
    emp = list(R.parse_rfb_empresas(raw("rfb_empresas_synthetic.csv")))
    mei = next(e for e in emp if e["cnpj_basico"] == "11222333")
    assert mei["razao_social"] == "PESSOA EXEMPLO DA SILVA" and mei["cpf_removed"] == 1 and mei["natural_person"]
    assert set(mei) == {"cnpj_basico", "razao_social", "cpf_removed", "natureza", "porte", "natural_person"}  # no capital
    est = list(R.parse_rfb_estabelecimentos(raw("rfb_estabelecimentos_synthetic.csv")))
    assert len(est) == 11
    assert all("@" not in json.dumps(e) and "5555" not in json.dumps(e) for e in est)  # contacts never read
    bb = next(e for e in est if e["cnpj"] == BB)
    assert bb["head_office"] and bb["active"] and bb["situacao"] == "ATIVA" and bb["uf"] == "DF"
    assert R.parse_rfb_municipios(raw("rfb_municipios_synthetic.csv"))["9701"] == "BRASILIA"


def test_light_file_selection_and_disk_check():
    listing = fx("rfb_month_listing.json")
    entries = listing["entries"] if isinstance(listing, dict) and "entries" in listing else listing
    sel = R.rfb_light_files(entries)
    names = {f["name"] for f in sel["files"]}
    assert sel["month"] and "Empresas0.zip" in names and "Estabelecimentos9.zip" in names
    assert not any(n.startswith(("Socios", "Simples")) for n in names)
    assert R.disk_space_check(10**9, 10**9)["ok"] is False
    assert R.disk_space_check(4 * 10**9, 10**9)["ok"] is True


@pytest.mark.parametrize("force_fallback", [False, True])
def test_index_build_and_query(tmp_path, force_fallback):
    info = slice_index(tmp_path / "names.sqlite", force_fallback=force_fallback)
    assert info["mode"] == ("tokens" if force_fallback else "fts5") and info["rows"] > 0
    assert info["cpf_removed"] >= 1
    with R.NameIndex(tmp_path / "names.sqlite") as idx:
        assert idx.snapshot == "2026-11"
        names = [r[0] for r in idx.conn.execute("SELECT name FROM names")]
        assert not any(re.search(r"(?<!\d)\d{11}(?!\d)", n) for n in names)  # FC4: no CPF digits indexed
        hyps = R.query_index(idx, "Exemplo Comercio de Alimentos Ltda")
        assert [h["match_kind"] for h in hyps][:3] == ["exact_razao", "exact_razao", "exact_fantasia"]
        assert hyps[0]["cnpj"] == "22333444000181" and hyps[0]["active"] and hyps[0]["head_office"]  # active head office first
        assert hyps[1]["situacao"] == "BAIXADA"
        assert R.auto_chain_decision(hyps)["auto"] is False  # three companies share the name
        mei = R.query_index(idx, "PESSOA EXEMPLO DA SILVA")
        assert len(mei) == 1 and mei[0]["natural_person_name"] and R.auto_chain_decision(mei)["auto"] is False
        assert R.query_index(idx, "PESSOA EXEMPLO") == []  # MEI/EI rows answer exact matches only
        with pytest.raises(ValueError):
            R.query_index(idx, "PESSOA EXEMPLO DA SILVA", input_type="person_name")


def test_fts5_and_token_modes_answer_the_same(tmp_path):
    slice_index(tmp_path / "a.sqlite")
    slice_index(tmp_path / "b.sqlite", force_fallback=True)
    with R.NameIndex(tmp_path / "a.sqlite") as a, R.NameIndex(tmp_path / "b.sqlite") as b:
        for q in ("BANCO DO BRASIL SA", "EXEMPLO ALIMENTOS", "PADARIA EXEMPLO", "BRASIL", "ZZQX NADA"):
            assert [h["cnpj"] for h in R.query_index(a, q)] == [h["cnpj"] for h in R.query_index(b, q)]


def test_fts5_detection():
    conn = sqlite3.connect(":memory:")
    ok, via = R.fts5_available(conn)
    assert isinstance(ok, bool) and via in ("compile_options", "probe", "absent")


def test_unreadable_index_is_could_not_verify(tmp_path):
    bad = tmp_path / "bad.sqlite"
    bad.write_bytes(b"not a database")
    with pytest.raises(R.NameIndexError):
        R.NameIndex(bad)
    res = run_module(CnpjNameResolver, "company_name:PADARIA EXEMPLO EIRELI", FakeHttp(),
                     settings={"cnpj_name_resolver_index_path": str(bad)}, allowed_sources=[R.SOURCE_INDEX])
    assert res.status is Status.ERROR and "local name index unreadable" in res.error
    res = run_module(CnpjNameResolver, "company_name:PADARIA EXEMPLO EIRELI", FakeHttp(),
                     settings={"cnpj_name_resolver_index_path": str(tmp_path / "absent.sqlite")}, allowed_sources=[R.SOURCE_INDEX])
    assert res.status is Status.UNAVAILABLE and res.reason_code == "dataset" and R.INDEX_MISSING_TEXT in res.error


BENCH_WORDS = (
    "ALFA BETA GAMA DELTA SOL LUA MAR RIO SERRA VALE NORTE SUL LESTE OESTE NOVA BOA SANTA COMERCIO INDUSTRIA",
    "SERVICOS TRANSPORTES ALIMENTOS CONSTRUTORA ENGENHARIA TECNOLOGIA SISTEMAS LOGISTICA AGRO ENERGIA SAUDE",
    "CLINICA FARMACIA EDUCACAO MODA MOVEIS METAIS PAPEL GRAFICA CONSULTORIA IMOBILIARIA HOTEL TURISMO PADARIA",
    "MERCADO ATACADO VAREJO DISTRIBUIDORA BRASIL PAULISTA MINEIRA CARIOCA GAUCHA",
)


@pytest.mark.slow
def test_benchmark_200k_companies_under_500ms(tmp_path):
    words = [w for line in BENCH_WORDS for w in line.split()]
    rnd = random.Random(7)
    n = 200_000
    emp, est = [], []
    for i in range(n):
        base = f"{10_000_000 + i:08d}"
        emp.append({"cnpj_basico": base, "razao_social": " ".join(rnd.sample(words, rnd.randint(2, 4))) + " LTDA", "natural_person": False})
        for k in range(1, rnd.randint(1, 2) + 1):
            b12 = f"{base}{k:04d}"
            est.append({"cnpj": b12 + validators.cnpj_check_digits(b12), "cnpj_basico": base, "head_office": k == 1,
                        "nome_fantasia": " ".join(rnd.sample(words, 2)) if rnd.random() < 0.4 else None,
                        "situacao": "ATIVA", "active": True, "uf": "SP", "municipio_code": "7107"})
    info = R.build_index(tmp_path / "bench.sqlite", emp, est, {"7107": "SAO PAULO"}, snapshot="synthetic")
    assert info["rows"] >= n
    with R.NameIndex(tmp_path / "bench.sqlite") as idx:
        for q in (emp[123]["razao_social"], emp[n // 2]["razao_social"], "COMERCIO DE ALIMENTOS", "BRASIL", "ALFA BETA", "ZZQX INEXISTENTE"):
            t = time.perf_counter()
            R.query_index(idx, q)
            assert time.perf_counter() - t < 0.5, q


# ======================================================================================
# module: local index answers (no network)
# ======================================================================================


def test_index_exact_unique_head_office_auto_chains_without_network(tmp_path):
    slice_index(tmp_path / "names.sqlite")
    http = FakeHttp()  # no route: any online fallback would fail the test
    res = run_module(CnpjNameResolver, "company_name:Padaria Exemplo Eireli", http, settings={"cnpj_name_resolver_index_path": str(tmp_path / "names.sqlite")})
    assert res.status is Status.OK and http.urls() == []
    piv = cnpj_pivots(res)
    assert list(piv) == ["44555666000181"]
    p = piv["44555666000181"]
    assert p.expand is True and p.relation == "possible_cnpj" and "investigated automatically" in p.note
    rn = res_name(res)
    assert rn["auto_chain"]["auto"] is True and rn["online_fallback"] is False
    assert rn["local_index"]["state"] == "installed" and rn["local_index"]["snapshot"] == "2026-11"
    assert res.source_statuses[R.SOURCE_INDEX]["status"] == "ok"
    f = res.findings[0]
    assert f.title == "Possible CNPJ for company name" and "name_only_match" in f.tags and f.confidence_label == "probable"
    assert "v3lum scan 44.555.666/0001-81" in f.description


def test_index_homonyms_never_auto_chain_and_list_followups(tmp_path):
    slice_index(tmp_path / "names.sqlite")
    res = run_module(CnpjNameResolver, "company_name:EXEMPLO COMERCIO DE ALIMENTOS LTDA", FakeHttp(),
                     settings={"cnpj_name_resolver_index_path": str(tmp_path / "names.sqlite")})
    assert res.status is Status.OK
    assert all(p.expand is False for p in res.pivots)
    rn = res_name(res)
    assert rn["auto_chain"]["auto"] is False and "3 companies share the exact name" in rn["auto_chain"]["reason"]
    assert len(rn["listing"]) == 3 and all("-> v3lum scan" in line for line in rn["listing"])
    hyps = res.attributes["cnpj_hypotheses"]
    assert hyps[0]["source"] == "rfb" and hyps[0]["snapshot"] == "2026-11" and hyps[0]["uf"] == "SP" and hyps[0]["city"] == "SAO PAULO"


def test_listing_caps_at_five_with_a_remainder_line():
    hyps = [R.hypothesis(f"{10_000_000 + i:08d}0001" + "00", f"EXEMPLO {i}", None, "EXEMPLO", "contains", source="rfb") for i in range(8)]
    lines = R.hypotheses_listing(hyps)
    assert len(lines) == 6 and lines[-1].startswith("... 3 more")


def test_cnpj_record_names_are_never_resolved():
    res = run_module(CnpjNameResolver, "company_name:BANCO DO BRASIL SA", FakeHttp(), is_seed=False, depth=1,
                     provenance=[(f"cnpj:{BB}", "legal_name", "cnpj_lookup")])
    assert res.status is Status.SKIPPED and res.reason_code == "not_applicable" and "CNPJ record" in res.error


def test_person_names_are_never_accepted():
    assert T.PERSON not in CnpjNameResolver.accepts
    assert set(CnpjNameResolver.accepts) == {T.ORG, T.KEYWORD}


def test_keywords_only_on_explicit_request():
    res = run_module(CnpjNameResolver, "keyword:banco exemplo", FakeHttp())
    assert res.status is Status.SKIPPED and res.reason_code == "not_default"


def test_too_short_names_are_skipped():
    res = run_module(CnpjNameResolver, "company_name:S.A.", FakeHttp())
    assert res.status is Status.SKIPPED and res.reason_code == "not_applicable"


# ======================================================================================
# module: registries + online fallbacks (FC1, FC7)
# ======================================================================================


def test_registries_and_fallbacks_without_local_index():
    install_registries()
    q = "BANCO DO BRASIL S.A."
    http = online_http(q)
    res = run_module(CnpjNameResolver, f"company_name:{q}", http)
    assert res.status is Status.OK
    rn = res_name(res)
    assert rn["local_index"] == {"state": "not_installed", "line": R.INDEX_MISSING_TEXT}
    assert rn["online_fallback"] is True and rn["online_label"] == R.ONLINE_LABEL
    assert rn["sources"]["cvm_cia_aberta"] == "match" and rn["sources"]["bcb"] == "match"
    assert rn["sources"]["cvm"] == "not_downloaded"  # the P360 company registries are not installed here
    assert res.source_statuses[R.SOURCE_CVM_CIA]["status"] == "ok" and res.source_statuses[R.SOURCE_CVM]["status"] == "unavailable"
    assert rn["sources"]["gleif"] in ("match", "no_match")
    hyps = res.attributes["cnpj_hypotheses"]
    top = hyps[0]
    assert top["cnpj"] == BB and top["source"] == "cvm" and top["match_kind"] == "exact_razao"
    assert "bcb" in top["also_in"]  # the same CNPJ from two sources: one hypothesis
    assert rn["auto_chain"] == {"auto": True, "cnpj": BB, "reason": "exact unique razao social of an active head office"}
    assert cnpj_pivots(res)[BB].expand is True
    doms = {p.entity.value: p for p in res.pivots if p.entity.type is T.DOMAIN}
    assert doms["bb.com.br"].relation == "bcb_verified_domain" and doms["bb.com.br"].expand is False
    assert "besc.com.br" in doms
    assert R.INDEX_MISSING_TEXT in res.findings[0].description
    http.assert_hosts_within(CnpjNameResolver)
    # GLEIF drops: funds, the DUPLICATE BB record and Kirton (no registeredAs) never become hypotheses
    assert not any(h.get("lei") == "81560032A9148CB5EB22" for h in hyps)
    assert all(h["cnpj"] not in ("11208723000105", "12030030000120") for h in hyps)


def test_gleif_hypotheses_drop_funds_duplicates_and_missing_cnpj():
    out = R.gleif_hypotheses(R.parse_gleif_records(fx("gleif_fulltext_ok.json")), "BANCO INDUSTRIAL DO BRASIL")
    assert out["dropped"]["fund"] == 2 and out["dropped"]["duplicate_or_annulled"] == 1 and out["dropped"]["no_cnpj"] >= 1
    h = out["hypotheses"][0]
    assert h["cnpj"] == "31895683000116" and h["match_kind"] == "exact_razao" and h["label"] == R.ONLINE_LABEL
    assert R.auto_chain_decision(out["hypotheses"])["auto"] is False  # online fallbacks never auto-chain


@pytest.mark.parametrize(
    ("name", "total", "cnpjs"),
    [
        ("gleif_registeredas_ok.json", 1, {BB}),
        ("gleif_registeredas_digits_empty.json", 0, set()),
        ("gleif_lei_record_ok.json", 1, {BB}),
        ("gleif_legalname_ok.json", 2, {BB, "07237373000120"}),
        ("gleif_legalname_research.json", None, None),
        ("gleif_empty.json", 0, set()),
    ],
)
def test_gleif_captures_parse(name, total, cnpjs):
    parsed = R.parse_gleif_records(fx(name))
    if total is not None:
        assert parsed["total"] == total
    if cnpjs is not None:
        assert {r["cnpj"] for r in parsed["records"] if r["cnpj"]} == cnpjs
    assert R.gleif_error_in_200(fx(name)) is None


def test_other_captures_have_the_expected_shapes():
    assert [x["attributes"]["value"] for x in fx("gleif_fuzzy_ok.json")["data"]][:1]
    assert fx("gleif_fuzzy_empty.json") == {"data": []}
    assert R.gleif_error_in_200(fx("gleif_not_found_404.http.json")["response"]["body"]).startswith("GLEIF error 404")
    pkg = fx("cvm_ckan_package_show_ok.json")
    assert "odbl" in json.dumps(pkg).lower()


def test_registry_parsing_status_and_cpf_safety():
    parsed = R.cvm.parse_cvm_csv(raw("cvm_cia_aberta_ok.csv"), "cia_aberta")
    assert parsed.ok
    rows = R.registry_rows(parsed.rows, {})
    by = {(r["cnpj"], r["field"]): r for r in rows}
    assert by[(BB, "razao")]["active"] is True  # 'ATIVO' counts as active for listed companies
    assert by[("60701190000104", "razao")]["active"] is False  # CANCELADA
    cosim = by[("61045381000110", "razao")]
    assert "37115383000153" in cosim["name"]  # a 14-digit CNPJ inside a name is not a CPF
    idx = R.RegistryIndex(rows)
    hits = idx.match("ITAU UNIBANCO")
    assert {h["match_kind"] for h in hits} >= {"exact_fantasia"}
    assert R.auto_chain_decision(hits)["auto"] is False  # nome fantasia never auto-chains


def test_missing_registries_are_not_screened_never_no_match():
    q = "EMPRESA EXEMPLO INEXISTENTE LTDA"
    http = online_http(q, gleif={"json": fx("gleif_empty.json")})
    res = run_module(CnpjNameResolver, f"company_name:{q}", http)
    assert res.status is Status.EMPTY
    assert res.source_statuses[R.SOURCE_CVM]["status"] == "unavailable" and res.source_statuses[R.SOURCE_CVM]["reason_code"] == "dataset"
    assert res.source_statuses[R.SOURCE_BCB]["status"] == "unavailable"
    assert "gleif" in res.error and R.INDEX_MISSING_TEXT in res.error
    assert res_name(res)["sources"]["cvm"] == "not_downloaded"


def test_partial_registry_copies_are_named():
    install_registries(intermed=True)
    q = "EMPRESA EXEMPLO INEXISTENTE LTDA"
    http = online_http(q, gleif={"json": fx("gleif_empty.json")})
    res = run_module(CnpjNameResolver, f"company_name:{q}", http)
    assert res.status is Status.EMPTY
    assert "not screened" in res_name(res)["sources"]["cvm"] and "cvm_crowdfunding.csv" in res_name(res)["sources"]["cvm"]


def test_truncated_cvm_copy_is_an_error():
    install_registries(cia=raw("cvm_cia_aberta_truncated.csv"), bcb=False)
    q = "BANCO DO BRASIL SA"
    http = online_http(q)
    res = run_module(CnpjNameResolver, f"company_name:{q}", http)
    assert res.source_statuses[R.SOURCE_CVM_CIA]["status"] == "error"


def test_bcb_odata_error_copy_is_an_error():
    install_registries()
    install(B.DOMINIOS.dataset, raw("bcb_odata_error_500.txt"))
    for name in ("bcb_sedes_bancos.json",):
        install(name, raw("bcb_odata_error_500.txt"))
    q = "BANCO DO BRASIL SA"
    res = run_module(CnpjNameResolver, f"company_name:{q}", online_http(q))
    assert res.source_statuses[R.SOURCE_BCB]["status"] == "error"


# ======================================================================================
# rule 5 for the online fallbacks (FC7)
# ======================================================================================


@pytest.mark.parametrize(
    ("route", "status", "code"),
    [
        ({"status": 429, "text": "slow down", "headers": {"retry-after": "60"}}, "rate_limited", "rate_limited"),
        ({"status": 403, "text": "Forbidden"}, "blocked", "challenge"),
        ({"status": 500, "text": "Internal Server Error"}, "error", "error"),
        ({"json": {"errors": [{"status": "500", "title": "Server Error"}]}}, "error", "error"),
        ({"body": b'{"meta": {', "headers": {"content-type": "application/vnd.api+json"}}, "error", "error"),
        ({"error": NetworkError("The read operation timed out", kind="ReadTimeout")}, "error", "timeout"),
    ],
)
def test_gleif_failures_are_per_source_could_not_verify(route, status, code):
    install_registries()
    q = "BANCO DO BRASIL S.A."
    http = online_http(q, gleif=route)
    res = run_module(CnpjNameResolver, f"company_name:{q}", http)
    assert res.status is Status.OK  # the registries answered
    row = res.source_statuses[R.SOURCE_GLEIF]
    assert row["status"] == status and row["reason_code"] == code
    assert res_name(res)["sources"]["gleif"].startswith("could not verify")


def test_nothing_answered_takes_the_failure_status():
    q = "EMPRESA EXEMPLO LTDA"
    http = FakeHttp().add("GET", R.gleif_url(q), status=429, text="slow down", headers={"retry-after": "60"})
    res = run_module(CnpjNameResolver, f"company_name:{q}", http)  # no registries, no index
    assert res.status is Status.RATE_LIMITED


def test_error_answers_are_never_cached():
    install_registries()
    q = "BANCO DO BRASIL S.A."
    http = online_http(q, gleif={"json": {"errors": [{"status": "500", "title": "Server Error"}]}})
    rt = make_runtime(http, cache=True)
    run_module(CnpjNameResolver, f"company_name:{q}", runtime=rt)
    run_module(CnpjNameResolver, f"company_name:{q}", runtime=rt)
    assert sum(1 for u in http.urls() if "api.gleif.org" in u) == 2


def test_allowed_sources_limit_the_queries():
    install_registries()
    res = run_module(CnpjNameResolver, "company_name:BANCO DO BRASIL S.A.", FakeHttp(), allowed_sources=[R.SOURCE_CVM, R.SOURCE_BCB])
    assert res.status is Status.OK
    assert set(res.source_statuses) == {R.SOURCE_CVM, R.SOURCE_BCB}


def test_explicit_keyword_runs():
    install_registries()
    res = run_module(CnpjNameResolver, "keyword:banco do brasil", FakeHttp(), allowed_sources=[R.SOURCE_CVM, R.SOURCE_BCB],
                     options=ScanOptions(include={"cnpj_name_resolver"}))
    assert res.status is Status.OK and BB in cnpj_pivots(res)


def test_metadata_matches_the_council_decision():
    C = CnpjNameResolver
    assert C.default_enabled is True and C.terms == "open" and C.trust_tier == "trusted"
    assert C.opsec.label == "passive" and C.shares_input is True
    assert C.hosts == ("api.gleif.org",)
    assert C.providers == frozenset({"rfb", "cvm", "bcb", "gleif"})


def _fake_rfb_import(path) -> None:
    """A SQLite in the layout of the shared P238 importer (rfb_import, --tables names), from the synthetic slice."""
    conn = sqlite3.connect(str(path))
    conn.executescript(
        "CREATE TABLE meta (k TEXT PRIMARY KEY, v TEXT);"
        "CREATE TABLE lookups (tbl TEXT, codigo TEXT, descricao TEXT, PRIMARY KEY (tbl, codigo));"
        "CREATE TABLE empresas (cnpj_basico TEXT, razao_social TEXT, natureza TEXT, porte TEXT, capital REAL, cpf_stripped INTEGER);"
        "CREATE TABLE estabelecimentos (cnpj TEXT, cnpj_basico TEXT, matriz INTEGER, nome_fantasia TEXT, situacao TEXT, uf TEXT, municipio TEXT);"
    )
    conn.execute("INSERT INTO meta VALUES ('snapshot', '2026-11')")
    conn.executemany("INSERT INTO lookups VALUES ('municipios', ?, ?)", list(R.parse_rfb_municipios(raw("rfb_municipios_synthetic.csv")).items()))
    import csv as _csv
    import io as _io

    for row in _csv.reader(_io.StringIO(raw("rfb_empresas_synthetic.csv").decode("latin-1")), delimiter=";"):
        conn.execute("INSERT INTO empresas VALUES (?,?,?,?,?,0)", (row[0], row[1], row[2], row[5], 0.0))  # CPF digits left in on purpose
    for e in R.parse_rfb_estabelecimentos(raw("rfb_estabelecimentos_synthetic.csv")):
        conn.execute("INSERT INTO estabelecimentos VALUES (?,?,?,?,?,?,?)",
                     (e["cnpj"], e["cnpj_basico"], int(e["head_office"]), e["nome_fantasia"], e["situacao"], e["uf"], e["municipio_code"]))
    conn.commit()
    conn.close()


def test_bridge_from_the_shared_rfb_import(tmp_path):
    src = tmp_path / "rfb_cnpj.sqlite"
    _fake_rfb_import(src)
    info = R.build_from_rfb_import(src, tmp_path / "names.sqlite")
    assert info["rows"] > 0 and info["cpf_removed"] >= 1
    with R.NameIndex(tmp_path / "names.sqlite") as idx:
        assert idx.snapshot == "2026-11"
        assert not any(re.search(r"(?<!\d)\d{11}(?!\d)", n) for (n,) in idx.conn.execute("SELECT name FROM names"))
        hyps = R.query_index(idx, "Padaria Exemplo Eireli")
        assert hyps[0]["cnpj"] == "44555666000181" and hyps[0]["city"] == "BRASILIA" and R.auto_chain_decision(hyps)["auto"]
    with pytest.raises(R.NameIndexError):
        R.build_from_rfb_import(tmp_path / "absent.sqlite", tmp_path / "x.sqlite")
