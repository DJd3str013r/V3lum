"""bcb_authorized_institutions (P360): BCB/CVM authorised institutions and their verified domains.

Fixtures in tests/fixtures/bcb_authorized_institutions/ (trimmed real data, 2026-11-25/26):
``dominios_ok.json`` (13 unmodified DominiosVerificados rows: BB own and member, Caixa .gov.br, BRB and the
nested dtvm.brb.com.br, Itau, an Itau-holding member with another registrant, Bradesco member, Nubank, an
independent .coop.br, a nested independent domain, C6 and Bari without a domain), ``dominios_empty.json``,
``odata_error_500.txt`` (the byte-exact comment-wrapped Olinda error body), the four ``sedes_*_ok.json``
sets (contacts replaced by contato@example.com and 5555-01xx numbers) and the CVM ``cvm_*_ok.csv``
registries (real latin-1/CRLF rows, contact columns blanked) plus a truncated ``cvm_cia_aberta`` download.
Bigger dataset-manager bodies are generated in the tests (synthetic institutions, ``.com.br`` names under
``inst<NNNN>``).
"""

from __future__ import annotations

import io
import json
import os
import time
import zipfile

import pytest

from tests.fakes import FIXTURES, FakeHttp, make_runtime, run_module
from v3lum import paths
from v3lum.core import datasets
from v3lum.core.context import ScanOptions
from v3lum.core.engine import Engine
from v3lum.core.entities import Entity
from v3lum.core.entities import EntityType as T
from v3lum.core.models import Status
from v3lum.modules.brazil_public_data import bcb_authorized_institutions as B
from v3lum.modules.brazil_public_data import cvm_registries as C
from v3lum.modules.brazil_public_data.bcb_authorized_institutions import BcbAuthorizedInstitutions

FIX = FIXTURES / "bcb_authorized_institutions"
SEDES_FIXTURES = {
    "bcb_sedes_bancos.json": "sedes_bancos_ok.json",
    "bcb_sedes_sociedades.json": "sedes_sociedades_ok.json",
    "bcb_sedes_consorcios.json": "sedes_consorcios_ok.json",
    "bcb_sedes_cooperativas.json": "sedes_cooperativas_ok.json",
}
CVM_FIXTURES = {
    "cvm_intermed.csv": "cvm_intermed_ok.csv",
    "cvm_adm_cart_pj.csv": "cvm_adm_cart_pj_ok.csv",
    "cvm_consultor_vlmob_pj.csv": "cvm_consultor_pj_ok.csv",
    "cvm_crowdfunding.csv": "cvm_crowdfunding_ok.csv",
}


def fx(name: str) -> bytes:
    return (FIX / name).read_bytes()


def install(name: str, body: bytes) -> None:
    (paths.datasets_dir() / name).write_bytes(body)


def install_bcb(*, sedes: bool = True, dominios: bytes | None = None) -> None:
    install(B.DOMINIOS.dataset, fx("dominios_ok.json") if dominios is None else dominios)
    for name, fixture in SEDES_FIXTURES.items() if sedes else ():
        install(name, fx(fixture))


def install_cvm() -> None:
    for name, fixture in CVM_FIXTURES.items():
        install(name, fx(fixture))


def run(value: str, http: FakeHttp | None = None, **kw):
    """Run through the engine over a FakeHttp without routes: any download attempt fails the test."""
    kw.setdefault("runtime", make_runtime(http or FakeHttp()))
    return run_module(BcbAuthorizedInstitutions, value, **kw)


def pivots(res, relation=None):
    return {(p.entity.type, p.entity.value): p for p in res.pivots if relation is None or p.relation == relation}


# ======================================================================================
# parsers (FC1, FC3, FC4)
# ======================================================================================


def test_dominios_rows_types_and_stats():
    parsed = B.parse_dominios(fx("dominios_ok.json"))
    assert not parsed.error
    assert parsed.stats["rows"] == 13 and parsed.stats["institutions"] == 12
    assert parsed.stats["institutions_without_domain"] == 2  # C6 and Bari: 'Sem dominio verificado'
    by = {(r["cnpj_root"], r["domain"]): r for r in parsed.rows}
    assert by[("00000000", "bb.com.br")]["domain_type"] == "own"
    assert by[("24933830", "bb.com.br")]["domain_type"] == "conglomerate_member"  # 'intregrante' (sic) still matched
    assert by[("01701201", "bradesco.com.br")]["registrant_cnpj_root"] == "60746948"  # conglomerate registrant differs
    coop = by[("00204963", "crediseara.coop.br")]
    assert coop["independent"] is True and coop["conglomerate"] is None and coop["conglomerate_code"] is None
    assert by[("31872495", None)]["domain_type"] == "none"


@pytest.mark.parametrize(
    ("body", "expected"),
    [
        (None, "Olinda error 500: Erro desconhecido (comment-wrapped body)"),  # the real fixture
        (b'/*{"codigo": 400, "mensagem": "Propriedade invalida"}*/', "Olinda error 400: Propriedade invalida (comment-wrapped body)"),
        (b"/* not json */", "Olinda error (comment-wrapped body, unparsable)"),
        (b'{"error": {"code": "500", "message": "boom"}}', "OData error 500: boom"),
        (b'{"codigo": 500, "mensagem": "Erro desconhecido"}', "Olinda error 500: Erro desconhecido"),
        (b"<!DOCTYPE html><html><body>Manutencao</body></html>", "an HTML page came back instead of JSON"),
        (b"Erro", "not JSON"),
        (b"", "empty body"),
        (b'{"@odata.context": "x", "value": "oops"}', "OData body without a 'value' list"),
        (b"[1, 2]", "unexpected JSON type list"),
    ],
)
def test_odata_error_bodies_are_errors_never_empty(body, expected):
    data = fx("odata_error_500.txt") if body is None else body
    assert B.odata_error(data) == expected
    parsed = B.parse_dominios(data)
    assert parsed.error == expected and parsed.rows == []  # FC3: an error, never an empty list


def test_empty_value_parses_but_never_installs_as_a_copy():
    parsed = B.parse_dominios(fx("dominios_empty.json"))
    assert parsed.error == "" and parsed.rows == []
    assert C.validate_copy("bcb_dominios_verificados.json", len(parsed.rows)) == "bcb_dominios_verificados.json: no rows"


def test_schema_drift_is_an_error():
    body = json.dumps({"value": [{"CNPJ": "00000000", "NOME": "X"}]}).encode()
    assert B.parse_dominios(body).error.startswith("schema drift")
    assert B.parse_sedes(body, "SedesBancoComMultCE").error.startswith("schema drift")


def test_sedes_segments_websites_minimisation_and_duplicates():
    bancos = {r["cnpj_root"]: r for r in B.parse_sedes(fx("sedes_bancos_ok.json"), "SedesBancoComMultCE").rows}
    assert bancos["00000000"]["segment"] == "Banco do Brasil - Banco Múltiplo"
    assert bancos["00000000"]["declared_hosts"] == ["www.bb.com.br"]
    assert bancos["00360305"]["declared_hosts"] == ["www.caixa.gov.br"]  # path dropped
    assert bancos["11970623"]["declared_hosts"] == []  # null website
    socs = {r["cnpj_root"]: r for r in B.parse_sedes(fx("sedes_sociedades_ok.json"), "SedesSociedades").rows}
    assert socs["16854999"]["declared_hosts"] == ["www.singratur.com.br"]  # 'WWW.SINGRATUR. COM.BR'
    assert socs["17904906"]["declared_hosts"] == ["brxcambio.com.br"]  # 'WWW:/BRXCAMBIO.COM.BR'
    cons = B.parse_sedes(fx("sedes_consorcios_ok.json"), "SedesConsorcios")
    assert {r["segment"] for r in cons.rows} == {"Administradora de Consorcio"}
    coops = B.parse_sedes(fx("sedes_cooperativas_ok.json"), "SedesCooperativas")
    by = {r["cnpj_root"]: r for r in coops.rows}
    assert by["00204963"]["segment"] == "Cooperativa de Credito - Singular"
    assert by["62912820"]["segment"] == "Cooperativa de Credito"  # null CLASSE
    assert by["43268960"]["declared_hosts"] == []  # an e-mail in the website field is never a host
    assert by["01374196"]["declared_hosts"] == ["www.sicoob.com.br"]  # 'WWW.SICOOB.COM.BR      COOPERATIVA 3167'
    assert by["10175348"]["declared_hosts"] == ["www.sicoob.com.br"]  # 'HTTPS: //WWW.SICOOB.COM.BR/...'
    assert coops.stats["duplicates_collapsed"] == 1  # the duplicated Sicredi row (phones are never kept)
    for row in coops.rows + cons.rows:
        assert not {"E_MAIL", "TELEFONE", "DDD", "e_mail", "phone"} & set(row)
        assert "example.com" not in json.dumps(row)


# ======================================================================================
# dataset registrations and the dataset manager (FC1, FC2, FC3)
# ======================================================================================


def test_datasets_are_registered_large_sourced_and_licensed():
    for spec in (B.DOMINIOS, *B.SEDES):
        reg = datasets.DATASETS[spec.dataset]
        assert reg["url"] == spec.url and "$format=json" in reg["url"] and "$filter" not in reg["url"]
        assert reg["large"] is True and reg["essential"] is True and reg["ttl"] == 86400
        assert reg["source"] == "bcb.olinda_institutions" and reg["terms_class"] == "open" and reg["licence"] and reg["attribution"]
        assert callable(reg["validate"]) and reg["expect"] == "json"
    for key, cvm_reg in C.REGISTRIES.items():
        if not cvm_reg.dataset:
            continue
        reg = datasets.DATASETS[cvm_reg.dataset]
        assert reg["archive"] == "zip" and reg["member"] == cvm_reg.member and not C.PEOPLE_MEMBER.search(cvm_reg.member)
        assert reg["large"] is True and reg["terms_class"] == "open"
        assert reg["essential"] is (cvm_reg.kind == "pj")
        assert reg["source"] == ("cvm.cvm_person_registry_pf" if key in C.PF_REGISTRIES else "cvm.cadastral")
    ours = [e for e in datasets.dataset_errors() if e.split(":")[0].split()[-1].startswith(("bcb_", "cvm_"))]
    assert ours == []


def synthetic_dominios(rows: int = 2400, with_domain: int = 600) -> bytes:
    value = []
    for i in range(rows):
        dom = f"inst{i:04d}.com.br" if i < with_domain else ""
        name = f"INSTITUICAO EXEMPLO {i:04d} S.A."
        value.append({
            "CNPJ": f"9{i:07d}", "INSTITUICAO_FINANCEIRA": name, "DOMINIO": dom,
            "TIPO_DE_DOMINIO": "Dominio próprio" if dom else "Sem domínio verificado",
            "CODIGO_DO_CONGLOMERADO": "", "CONGLOMERADO": "Instituição independente",
            "PROPRIETARIO_DO_DOMINIO": name if dom else "", "CNPJ_NO_REGISTRO_DO_DOMINIO": f"9{i:07d}" if dom else "",
        })
    doc = {"@odata.context": "https://was-p.bcnet.bcb.gov.br/olinda/servico/Instituicoes_em_funcionamento/versao/v1/odata$metadata#DominiosVerificados",
           "value": value}
    return json.dumps(doc, ensure_ascii=False, indent=1).encode("utf-8")


def update(name: str, url: str, **route):
    route.setdefault("headers", {"content-type": "application/json;charset=UTF-8;odata.metadata=minimal"})
    http = FakeHttp().add("GET", url, **route)
    rt = make_runtime(http)
    return rt.data.update(name), http


def test_update_validates_each_copy_before_replacing_it():
    name, url = B.DOMINIOS.dataset, B.DOMINIOS.url
    first, http = update(name, url, status=200, body=synthetic_dominios())
    assert first.status == "updated", first.reason
    assert http.hosts() == {"olinda.bcb.gov.br"}
    installed = (paths.datasets_dir() / name).read_bytes()
    # FC2: a copy 30% smaller than the previous one is rejected and the previous copy stays
    shrunk, _ = update(name, url, status=200, body=synthetic_dominios(rows=1600, with_domain=500))  # above every floor
    assert shrunk.status == "failed" and "below the previous copy" in shrunk.reason
    assert (paths.datasets_dir() / name).read_bytes() == installed
    # FC3: a comment-wrapped Olinda error, even with HTTP 200, never installs (provider marker)
    wrapped, _ = update(name, url, status=200, body=fx("odata_error_500.txt"), headers={})
    assert wrapped.status == "failed" and "comment" in wrapped.reason
    failed500, _ = update(name, url, status=500, body=fx("odata_error_500.txt"), headers={})
    assert failed500.status == "failed" and "500" in failed500.reason
    html, _ = update(name, url, status=200, text="<!DOCTYPE html><html><body>Manutencao programada</body></html>", headers={"content-type": "text/html"})
    assert html.status == "failed"
    empty, _ = update(name, url, status=200, body=fx("dominios_empty.json"))
    assert empty.status == "failed"
    few_domains, _ = update(name, url, status=200, body=synthetic_dominios(rows=2400, with_domain=300))
    assert few_domains.status == "failed" and "unique verified domains" in few_domains.reason
    assert (paths.datasets_dir() / name).read_bytes() == installed


def test_floors_apply_to_a_first_copy_and_the_relative_check_expires(monkeypatch):
    name, url = B.DOMINIOS.dataset, B.DOMINIOS.url
    tiny, _ = update(name, url, status=200, body=fx("dominios_ok.json"))  # 13 rows, 5 KB: below the byte floor
    assert tiny.status == "failed" and "short body" in tiny.reason
    few_rows, _ = update(name, url, status=200, body=synthetic_dominios(rows=1400, with_domain=500))  # bytes ok, rows not
    assert few_rows.status == "failed" and "1400 rows is below the floor of 1500" in few_rows.reason
    assert update(name, url, status=200, body=synthetic_dominios())[0].status == "updated"
    monkeypatch.setattr(C, "ROW_CHECK_MAX_AGE_HOURS", -1e9)  # any installed copy counts as older than a week
    lasting, _ = update(name, url, status=200, body=synthetic_dominios(rows=1600, with_domain=450))  # 33% fewer rows
    assert lasting.status == "updated"  # a lasting change is accepted; the floors still applied


def synthetic_cvm_zip(rows: int = 1700) -> bytes:
    lines = fx("cvm_intermed_ok.csv").decode("latin-1").split("\r\n")
    header, body = lines[0], [ln for ln in lines[1:] if ln]
    csv_text = "\r\n".join([header] + [body[i % len(body)] for i in range(rows)]) + "\r\n"
    people = "TP_PARTIC;CNPJ;DENOM_SOCIAL;DT_REG;TP_RESP;RESP;DT_INI_RESP;EMAIL_RESP\r\nCORRETORAS;02.332.886/0001-04;X;2020-01-01;DIRETOR;PESSOA EXEMPLO;2020-01-01;pessoa@example.com\r\n"
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
        zf.writestr("cad_intermed.csv", csv_text.encode("latin-1"))
        zf.writestr("cad_intermed_resp.csv", people.encode("latin-1"))
    return buf.getvalue()


def test_cvm_zip_installs_only_the_registry_member():
    reg = C.REGISTRIES["intermed"]
    result, http = update(reg.dataset, reg.url, status=200, body=synthetic_cvm_zip(), headers={"content-type": "application/zip"})
    assert result.status == "updated", result.reason
    assert http.hosts() == {"dados.cvm.gov.br"}
    stored = (paths.datasets_dir() / reg.dataset).read_bytes().decode("latin-1")
    assert stored.startswith("TP_PARTIC;CNPJ;DENOM_SOCIAL") and "EMAIL_RESP" not in stored
    for p in paths.datasets_dir().rglob("*"):  # the people list never lands on disk (rule 4)
        assert "resp" not in p.name.lower()
        if p.is_file():
            assert b"pessoa@example.com" not in p.read_bytes()


def test_cvm_challenge_page_never_installs():
    reg = C.REGISTRIES["crowdfunding"]
    page = "<!DOCTYPE html><html><head><title>Just a moment...</title></head><body>cf-chl-widget</body></html>"
    result, _ = update(reg.dataset, reg.url, status=403, text=page, headers={"content-type": "text/html", "cf-mitigated": "challenge"})
    assert result.status == "failed"
    assert not (paths.datasets_dir() / reg.dataset).exists()


# ======================================================================================
# domains and URLs (FC4-FC7)
# ======================================================================================


def test_verified_subdomain_is_known_good_with_institution_facts():
    install_bcb()
    http = FakeHttp()
    res = run("domain:www.bb.com.br", http)
    assert res.status is Status.OK
    a = res.attributes
    assert a["known_good"] is True and a["legal_name"] == "BANCO DO BRASIL S.A."
    vd = a["bcb_verified_domain"]
    assert vd["domain"] == "bb.com.br" and vd["match"] == "subdomain" and vd["registrable_domain"] == "bb.com.br"
    assert [i["cnpj_root"] for i in vd["institutions"]] == ["00000000", "24933830"]  # own domain first
    assert vd["as_of"] and vd["registrant_cnpj_roots"] == ["00000000"]
    assert any(line.startswith("bcb_dominios_verificados.json, fetched ") for line in a["dataset_age"])
    (finding,) = res.findings
    assert finding.title == "Verified domain of a BCB-authorised institution" and finding.severity.label == "info"
    assert {"verified_fi", "known_good"} <= set(finding.tags) and finding.source == "bcb.olinda_institutions"
    d = finding.data
    assert (d["legal_name"], d["cnpj_root"], d["segment"], d["conglomerate"]) == (
        "BANCO DO BRASIL S.A.", "00000000", "Banco do Brasil - Banco Múltiplo", "BB - PRUDENCIAL")
    assert d["datasets"][0]["name"] == B.DOMINIOS.dataset and d["datasets"][0]["date"] and d["attribution"].startswith("Fonte: Banco Central")
    cnpjs = pivots(res, "bcb_verified_domain_of")
    assert set(cnpjs) == {(T.CNPJ, "00000000000191"), (T.CNPJ, "24933830000130")}
    assert all(not p.expand and p.confidence_label.value == "probable" for p in cnpjs.values())
    assert res.source_statuses["bcb.olinda_institutions"]["status"] == "ok"
    assert {d["name"] for d in res.datasets} >= {B.DOMINIOS.dataset, "bcb_sedes_bancos.json"}
    assert http.calls == []  # offline matching: the value never leaves the machine, nothing is downloaded


@pytest.mark.parametrize(
    ("host", "expected"),
    [
        ("bb.com.br", [("bb.com.br", "exact")]),
        ("internetbanking.caixa.gov.br", [("caixa.gov.br", "subdomain")]),
        ("dtvm.brb.com.br", [("dtvm.brb.com.br", "exact"), ("brb.com.br", "subdomain")]),
        ("x.dtvm.brb.com.br", [("dtvm.brb.com.br", "subdomain"), ("brb.com.br", "subdomain")]),
        ("financeira.brb.com.br", [("brb.com.br", "subdomain")]),
        ("cia.sinosserra.com.br", [("cia.sinosserra.com.br", "exact")]),
        ("sinosserra.com.br", []),  # the verified domain sits below the registrable domain
        ("evilbb.com.br", []),  # never substrings
        ("bb.com.br.evil.example.com", []),  # never string suffixes or prefixes
        ("bb-com-br.com", []),
        ("bb.com", []),
        ("itau.com.br", []),  # Itau's verified domain is itau-unibanco.com.br: absence is not a signal
        ("com.br", []),
        ("", []),
    ],
)
def test_match_walks_labels_up_to_the_registrable_domain(host, expected):
    domains = B.build_domain_index(B.parse_dominios(fx("dominios_ok.json")).rows)
    assert [(m["verified_domain"], m["match"]) for m in B.match_host(host, domains)] == expected


@pytest.mark.parametrize("value", ["domain:example.com", "domain:itau.com.br", "domain:evilbb.com.br", "domain:bb-seguranca.example"])
def test_absence_is_empty_and_never_a_signal(value):
    install_bcb()
    res = run(value)
    assert res.status is Status.EMPTY and not res.findings and not res.attributes and not res.pivots
    st = res.source_statuses["bcb.olinda_institutions"]
    assert st["status"] == "empty" and "not a BCB-verified domain (DominiosVerificados as of " in st["reason"]


def test_nested_independent_coop_and_gov_domains():
    install_bcb()
    coop = run("domain:www.crediseara.coop.br")
    assert coop.attributes["known_good"] is True
    assert "conglomerate independent institution" in coop.findings[0].description
    caixa = run("url:https://internetbanking.caixa.gov.br/sinbc/login")
    assert caixa.attributes["bcb_verified_domain"]["domain"] == "caixa.gov.br" and caixa.attributes["known_good"] is True
    nested = run("domain:x.dtvm.brb.com.br")
    assert nested.attributes["bcb_verified_domain"]["matched_domains"] == ["dtvm.brb.com.br", "brb.com.br"]


@pytest.mark.parametrize(
    ("url", "target"),
    [
        ("https://www.bb.com.br/login?next=https%3A%2F%2Fevil.example.com%2F", "evil.example.com"),
        ("https://www.bb.com.br/r?url=%252F%252Fevil.example.com%252Fx", "evil.example.com"),
        ("https://www.bb.com.br/#/redirect?url=//evil.example.com", "evil.example.com"),
        ("https://www.bb.com.br/x#https://evil.example.com/login", "evil.example.com"),
        ("https://www.bb.com.br/x?goto=evil.example.com/phish", "evil.example.com"),
        ("https://www.bb.com.br/x?r=aHR0cHM6Ly9ldmlsLmV4YW1wbGUuY29tLw", "evil.example.com"),
        ("https://www.bb.com.br/x?u=https:\\\\evil.example.com", "evil.example.com"),
    ],
)
def test_redirect_via_verified_domain_is_not_known_good(url, target):
    install_bcb()
    res = run(f"url:{url}")
    assert res.status is Status.OK
    assert res.attributes["known_good"] is False and res.attributes["redirect_targets"] == [target]
    (finding,) = res.findings
    assert finding.title == "Redirect via verified domain" and finding.severity.label == "medium"
    assert finding.tags == ["redirect_via_verified_domain"] and finding.criterion and finding.attack == ["T1566.002"]
    assert "known_good" not in finding.tags
    tgt = pivots(res, "redirect_target")[(T.DOMAIN, target)]
    assert tgt.expand is True  # an IOC: expansion allowed
    assert res.attributes["bcb_verified_domain"]["domain"] == "bb.com.br"


@pytest.mark.parametrize(
    "url",
    [
        "https://www.bb.com.br/pt/x?next=/home",
        "https://www.bb.com.br/pt/x?next=https://www.bb.com.br/y",
        "https://www.bb.com.br/pt/x?next=https://apoio.bb.com.br/y",  # same verified domain: internal redirect
        "https://www.bb.com.br/x?next=home.html&return=index.php&goto=login.do",  # relative files, not hosts
        "https://www.bb.com.br/x?next=pagina.inexistente",  # no IANA TLD
    ],
)
def test_internal_redirects_and_relative_files_stay_known_good(url):
    install_bcb()
    res = run(f"url:{url}")
    assert res.attributes["known_good"] is True and "redirect_targets" not in res.attributes
    assert res.findings[0].title == "Verified domain of a BCB-authorised institution"


def test_verified_domain_in_userinfo_is_deceptive_and_never_matches():
    install_bcb()
    res = run("url:https://bb.com.br@evil.example.com/login")
    assert res.status is Status.OK
    assert "known_good" not in res.attributes and "bcb_verified_domain" not in res.attributes
    (finding,) = res.findings
    assert finding.title == "Verified institution domain in URL userinfo" and finding.severity.label == "medium"
    assert finding.tags == ["verified_domain_in_userinfo"] and finding.data["host"] == "evil.example.com"
    assert res.source_statuses["bcb.olinda_institutions"]["status"] == "empty"


def test_missing_list_is_unavailable_and_never_downloaded():
    http = FakeHttp()  # a network-capable runtime: any download attempt would fail the test
    res = run("domain:www.bb.com.br", http)
    assert res.status is Status.UNAVAILABLE and res.reason_code == "dataset"
    assert "not screened against BCB/CVM registries" in res.error and "v3lum data update bcb_dominios_verificados.json" in res.error
    assert http.calls == []
    company = run("cnpj:00000000000191", http)
    assert company.status is Status.UNAVAILABLE and company.reason_code == "dataset"


def test_corrupt_local_copy_is_unavailable_never_not_verified():
    install(B.DOMINIOS.dataset, fx("odata_error_500.txt"))
    res = run("domain:www.bb.com.br")
    assert res.status is Status.UNAVAILABLE and res.reason_code == "dataset" and "does not parse" in res.error


def test_stale_copy_is_served_without_any_refresh_and_flagged():
    install_bcb()
    old = time.time() - 3 * 86400
    for p in paths.datasets_dir().iterdir():
        os.utime(p, (old, old))
    http = FakeHttp()
    res = run("domain:bb.com.br", http)
    assert res.attributes["known_good"] is True and http.calls == []
    assert any("stale: run v3lum data update bcb_dominios_verificados.json" in line for line in res.attributes["dataset_age"])


def test_missing_sedes_still_answer_without_segment():
    install_bcb(sedes=False)
    res = run("domain:nubank.com.br")
    assert res.attributes["known_good"] is True
    assert "segment unknown (Sedes* sets not installed)" in res.findings[0].description


def test_licence_blocked_source_is_skipped():
    install_bcb()
    res = run("domain:bb.com.br", allowed_sources=())
    assert res.status is Status.SKIPPED and res.reason_code == "licence"


# ======================================================================================
# CNPJ and company names (FC7, FC9)
# ======================================================================================


def test_cnpj_answer_line_bcb_and_cvm():
    install_bcb()
    install_cvm()
    res = run("cnpj:00000000000191")
    a = res.attributes
    assert a["bcb_cvm_authorisation"] == (
        "authorised by BCB/CVM: yes (Banco do Brasil - Banco Múltiplo; CVM: Custodiantes de valores mobiliários, "
        "Escrituradores de valores mobiliários)")
    statuses = {(g["registry"], g["segment"], g["status"]) for g in a["cvm_registrations"]}
    assert ("intermed", "Custodiantes de valores mobiliários", "cancelled") in statuses
    assert ("adm_cart_pj", "Administrador de Carteira", "cancelled") in statuses
    (finding,) = res.findings
    assert finding.title == "Authorised by BCB/CVM" and finding.severity.label == "info"
    assert finding.confidence_label.value == "confirmed" and "verified_fi" in finding.tags
    assert finding.data["no_verified_domain"] is None
    dom = pivots(res, "bcb_verified_domain")[(T.DOMAIN, "bb.com.br")]
    assert dom.expand is True and dom.confidence_label.value == "confirmed"
    assert res.source_statuses["cvm.cadastral"]["status"] == "ok" and res.source_statuses["bcb.olinda_institutions"]["status"] == "ok"


def test_cnpj_not_found_is_one_line_and_no_finding():
    install_bcb()
    install_cvm()
    res = run("cnpj:11222333000181")
    assert res.status is Status.OK and not res.findings and not res.pivots
    line = res.attributes["bcb_cvm_authorisation"]
    assert line.startswith("authorised by BCB/CVM: not found as of 20") and "fraud" not in line


def test_inactive_cvm_registration_is_context_of_the_not_found_line():
    install_bcb()
    install_cvm()
    res = run("cnpj:02671743000119")  # BANVOX DTVM: adm_cart registration in extrajudicial liquidation
    line = res.attributes["bcb_cvm_authorisation"]
    assert line.startswith("authorised by BCB/CVM: not found as of ") and "(CVM Administrador de Carteira liquidation since 2026-09-03)" in line
    assert not res.findings


def test_institution_without_verified_domain_gets_only_the_info_line():
    install_bcb()
    install_cvm()
    res = run(f"cnpj:{C.head_office_cnpj('31872495')}")  # Banco C6: 'Sem dominio verificado', not in the Sedes fixtures
    a = res.attributes
    assert a["bcb_cvm_authorisation"] == "authorised by BCB/CVM: yes (BCB: segment not informed)"
    (finding,) = res.findings
    assert finding.severity.label == "info" and "No verified domain registered with BCB" in finding.description
    assert finding.data["no_verified_domain"] == B.LINE_NO_DOMAIN
    assert set(finding.tags) == {"verified_fi", "info"} and not pivots(res, "bcb_verified_domain")


def test_declared_websites_are_never_known_good():
    install_bcb()
    install_cvm()
    ebury = run(f"cnpj:{C.head_office_cnpj('13059145')}")  # Sedes only: declared BR.EBURY.COM, no verified domain
    declared = pivots(ebury, "declared_website")[(T.DOMAIN, "br.ebury.com")]
    assert declared.expand is False and declared.confidence_label.value == "possible" and "never verified" in declared.note
    nubank = run(f"cnpj:{C.head_office_cnpj('18236120')}")  # declared www.nubank.com.br is under its verified domain
    assert (T.DOMAIN, "nubank.com.br") in pivots(nubank, "bcb_verified_domain")
    assert not pivots(nubank, "declared_website")


def test_company_name_exact_legal_name_chains_only_when_unique_and_active():
    install_bcb()
    install_cvm()
    exact = run("company_name:BANCO DO BRASIL S.A.")
    cnpj = pivots(exact, "registry_name_match")[(T.CNPJ, "00000000000191")]
    assert cnpj.expand is True and cnpj.confidence_label.value == "probable"
    assert exact.findings[0].confidence_label.value == "probable"
    core = run("company_name:Banco do Brasil")  # without the legal form: no auto-chaining
    cnpj = pivots(core, "registry_name_match")[(T.CNPJ, "00000000000191")]
    assert cnpj.expand is False and cnpj.confidence_label.value == "possible" and "analyst confirmation" in cnpj.note
    assert "Matched by name without legal form" in core.findings[0].description
    trade = run("company_name:XP INVESTIMENTOS")  # the CVM trade name
    cnpj = pivots(trade, "registry_name_match")[(T.CNPJ, "02332886000104")]
    assert cnpj.expand is False and trade.attributes["bcb_cvm_authorisation"].startswith("authorised by BCB/CVM: yes (CVM: ")


def test_company_name_given_as_cnpj_digits_is_a_root_query():
    install_bcb()
    install_cvm()
    res = run("company_name:00.000.000/0001-91")
    assert res.attributes["bcb_cvm_authorisation"].startswith("authorised by BCB/CVM: yes (Banco do Brasil")
    assert res.findings[0].confidence_label.value == "confirmed"


@pytest.mark.parametrize("value", ["company_name:123.456.789-00", "company_name:12345678909"])
def test_cpf_is_never_a_lookup_key(value):
    install_bcb()
    install_cvm()
    res = run(value)
    assert res.status is Status.SKIPPED and res.reason_code == "not_applicable" and "CPF" in res.error


def test_ambiguous_names_list_at_most_five_hypotheses_without_chaining():
    rows = [{"CNPJ": f"8{i:07d}", "INSTITUICAO_FINANCEIRA": "BANCO EXEMPLO S.A.", "DOMINIO": f"exemplo{i}.com.br",
             "TIPO_DE_DOMINIO": "Dominio próprio", "CODIGO_DO_CONGLOMERADO": "", "CONGLOMERADO": "Instituição independente",
             "PROPRIETARIO_DO_DOMINIO": "BANCO EXEMPLO S.A.", "CNPJ_NO_REGISTRO_DO_DOMINIO": f"8{i:07d}"} for i in range(7)]
    install_bcb(dominios=json.dumps({"value": rows}).encode())
    res = run("company_name:Banco Exemplo S/A")
    line = res.attributes["bcb_cvm_authorisation"]
    assert "[5 institutions match the name]" in line and "(showing 5 of 7 matches)" in line
    assert "CVM not screened" in line  # the CVM registries are not installed in this test
    names = pivots(res, "registry_name_match")
    assert len(names) == 5 and all(not p.expand and p.confidence_label.value == "possible" for p in names.values())
    assert all(not p.expand for p in pivots(res, "bcb_verified_domain").values())
    assert res.findings[0].confidence_label.value == "possible"


def test_cvm_missing_is_reported_and_bcb_still_answers():
    install_bcb()
    res = run("cnpj:00000000000191")
    assert res.attributes["bcb_cvm_authorisation"] == (
        "authorised by BCB/CVM: yes (Banco do Brasil - Banco Múltiplo); CVM not screened (dataset missing: run v3lum data update)")
    st = res.source_statuses["cvm.cadastral"]
    assert st["status"] == "unavailable" and st["reason_code"] == "dataset" and "cvm_intermed.csv" in st["reason"]


def test_bcb_missing_cvm_answers_alone():
    install_cvm()
    res = run("cnpj:02332886000104")
    line = res.attributes["bcb_cvm_authorisation"]
    assert line.startswith("authorised by BCB/CVM: yes (CVM: Administrador de Carteira, Corretoras") and line.endswith("BCB not screened (dataset missing: run v3lum data update)")
    assert res.findings[0].tags == ["info"] and res.findings[0].source == "cvm.cadastral"


# ======================================================================================
# the shared CVM loader (FC1, FC9, rule 4)
# ======================================================================================


def test_cvm_registry_rows_are_minimised_and_statuses_mapped():
    parsed = C.parse_cvm_csv(fx("cvm_intermed_ok.csv"), "intermed")
    assert parsed.ok and parsed.stats["rows"] == 14
    for row in parsed.rows:
        assert not {"EMAIL", "TEL", "LOGRADOURO", "VL_PATRIM_LIQ", "CEP"} & {k.upper() for k in row}
        assert "example.com" not in json.dumps(row)
    placeholder = next(r for r in parsed.rows if r["cnpj"] == "00.999.999/9999-99")
    assert placeholder["cnpj_valid"] is False and placeholder["status"] == "liquidation"
    index = C.build_index([parsed])
    assert "00999999" not in index.by_root  # placeholders are never indexed
    adm = C.parse_cvm_csv(fx("cvm_adm_cart_pj_ok.csv"), "adm_cart_pj")
    bravia = next(r for r in adm.rows if r["cnpj_root"] == "11241034")
    assert bravia["trade_name"] is None and bravia["status"] == "suspended"  # '--' and 'AFASTADO - TERMO DE COMPROMISSO'
    crowd = C.parse_cvm_csv(fx("cvm_crowdfunding_ok.csv"), "crowdfunding")
    by = {r["cnpj"]: r for r in crowd.rows}
    assert by["11.854.914/0004-89"]["cnpj_root"] == "11854914" and by["11.854.914/0004-89"]["status"] == "denied"
    assert by["34.697.721/0001-14"]["status"] == "pending" and by["15.799.453/0001-05"]["status"] in ("cancelled", "unknown")


@pytest.mark.parametrize(
    ("sit", "label"),
    [("EM FUNCIONAMENTO NORMAL", "active"), ("Em Funcionamento Normal", "active"), ("CANCELADA", "cancelled"), ("Cancelado", "cancelled"),
     ("LIQUIDAÇÃO EXTRAJUDICIAL", "liquidation"), ("SUSPENSO(A) - A PEDIDO", "suspended"), ("SUSPENSO(A) - DECISÃO ADM", "suspended"),
     ("AFASTADO - TERMO DE COMPROMISSO", "suspended"), ("INTERVENTOR", "special"), ("EM SITUAÇÃO ESPECIAL", "special"),
     ("Em Análise", "pending"), ("Registro Não Concedido", "denied"), ("", "unknown"), (None, "unknown"), ("???", "unknown")],
)
def test_cvm_status_vocabulary(sit, label):
    assert C.cvm_status(sit) == label


def test_cvm_truncated_html_and_drifted_files_fail_closed():
    truncated = C.parse_cvm_csv(fx("cvm_cia_aberta_truncated.csv"), "cia_aberta")
    assert not truncated.ok and "truncated" in truncated.error and truncated.rows == []
    html = C.parse_cvm_csv(b"<!DOCTYPE html><html><body>erro</body></html>", "intermed")
    assert not html.ok and "HTML" in html.error
    drift = C.parse_cvm_csv("CNPJ;NOME\r\n00.000.000/0001-91;X\r\n".encode("latin-1"), "intermed")
    assert not drift.ok and drift.error.startswith("schema drift")
    assert not C.parse_cvm_csv(b"", "intermed").ok
    assert not C.parse_cvm_csv(fx("cvm_intermed_ok.csv"), "nope").ok


def test_people_lists_and_cpf_helpers():
    for member in ("cad_intermed_resp.csv", "cad_adm_cart_diretor.csv", "cad_adm_cart_socios.csv", "cad_crowdfunding_adm_resp.csv"):
        assert C.PEOPLE_MEMBER.search(member)
    assert C.head_office_cnpj("00000000") == "00000000000191"
    assert C.cnpj_root("12345678909") is None  # CPF-shaped: never a root
    assert C.cnpj_root("360305") == "00360305"  # leading zeros restored
    assert C.cnpj_root("12.ABC.345/01DE-35") == "12ABC345"  # alphanumeric CNPJ (IN RFB 2.229/2024)
    assert C.mask_cpf("123.456.789-09") == "***.456.789-**"
    assert C.strip_cpf_sequences("PESSOA EXEMPLO 123.456.789-09") == "PESSOA EXEMPLO"
    assert C.name_key("BB GESTAO DE RECURSOS DTVM S.A") == C.name_key("BB GESTÃO DE RECURSOS DTVM SA")
    assert C.core_name_key("Banco Exemplo Ltda.") == "BANCO EXEMPLO"


def test_name_index_never_matches_fuzzily():
    idx = C.NameIndex()
    idx.add("BANCO EXEMPLO S.A.", "11111111")
    idx.add("EXEMPLO PAY", "22222222", trade=True)
    assert idx.find("Banco Exemplo SA") == (["11111111"], "exact_name")
    assert idx.find("banco exemplo") == (["11111111"], "name_without_legal_form")
    assert idx.find("Exemplo Pay") == (["22222222"], "trade_name")
    assert idx.find("Banco Exempl") == ([], "") and idx.find("Exemplo") == ([], "")


# ======================================================================================
# FC5 and FC8 helpers, consumers' API, policy integration
# ======================================================================================


def test_reputation_adjustment_never_suppresses():
    verdicts = [
        {"source": "urlhaus", "verdict": "malicious", "level": "domain"},
        {"source": "age", "verdict": "young", "level": "domain", "kind": "age"},
        {"source": "phishtank", "verdict": "phishing", "level": "url"},
        "junk",
    ]
    res = B.reputation_adjustment(True, verdicts)
    assert res["flag"] == B.TITLE_COMPROMISE
    assert {v["source"]: v["weight_factor"] for v in res["verdicts"]} == {"urlhaus": 1.0, "age": 0.5, "phishtank": 1.0}
    assert all(v["suppressed"] is False for v in res["verdicts"])
    plain = B.reputation_adjustment(False, verdicts)
    assert plain["flag"] is None and all(v["weight_factor"] == 1.0 for v in plain["verdicts"])


def fixture_index() -> B.BcbIndex:
    return B.build_index(B.parse_dominios(fx("dominios_ok.json")))


def test_protected_brand_feed_and_lookalike_ladder():
    index = fixture_index()
    brands = {b["registrable_domain"]: b for b in B.protected_brands(index)}
    bb = brands["bb.com.br"]
    assert bb["institution_cnpj_roots"] == ["00000000", "24933830"] and bb["short_label"] is True
    itau = brands["itau-unibanco.com.br"]
    assert itau["conglomerate_member_roots"] == ["31749596", "60872504"]  # Itau holding and its member's registrant
    assert brands["brb.com.br"]["verified_domains"] == ["brb.com.br", "dtvm.brb.com.br"]
    assert B.protected_brand_for("www.itau-unibanco.com.br", index)["registrable_domain"] == "itau-unibanco.com.br"
    assert B.protected_brand_for("example.com", index) is None
    ladder = B.classify_lookalike
    assert ladder(bb, registered=True, resolves=True)["severity"] == "high"
    assert ladder(bb, registered=True, mx=True, fresh_cert=True)["signals"] == ["mx", "fresh_certificate"]
    assert ladder(bb, registered=True)["severity"] == "medium"
    assert ladder(bb, registered=True, resolves=True, parked=True)["severity"] == "medium"  # parking is not activity
    assert ladder(bb, registered=False, resolves=True) is None
    assert ladder(bb, registered=True, resolves=True, registrant_cnpj="00.000.000/0001-91")["severity"] == "suppressed"
    assert ladder(itau, registered=True, mx=True, registrant_cnpj="60872504")["severity"] == "suppressed"  # conglomerate member
    assert ladder(bb, registered=True, resolves=True, registrant_cnpj="123.456.789-09")["severity"] == "high"  # a CPF is never compared


def test_consumer_helpers_read_local_copies_only():
    assert B.local_index().dominios is False and B.verified_domain_match("www.bb.com.br") is None
    install_bcb()
    assert B.verified_domain_match("www.bb.com.br")["verified_domain"] == "bb.com.br"
    assert B.verified_domain_match("bb-seguranca.example") is None


def test_policy_gate_keeps_missing_datasets_out_of_scans():
    rt = make_runtime(FakeHttp())
    engine = Engine(rt, ScanOptions(include={"bcb_authorized_institutions"}))
    runnable, blocked = engine.select(Entity.make(T.DOMAIN, "www.bb.com.br"))
    assert not runnable
    (cls, decision), = blocked
    assert cls is BcbAuthorizedInstitutions and decision.reason_code == "dataset" and decision.status is Status.UNAVAILABLE
    install_bcb()
    install_cvm()
    runnable, _blocked = Engine(rt, ScanOptions(include={"bcb_authorized_institutions"})).select(Entity.make(T.DOMAIN, "www.bb.com.br"))
    assert [c for c, _d in runnable] == [BcbAuthorizedInstitutions]


def test_scan_runs_offline_and_sends_nothing():
    install_bcb()
    install_cvm()
    http = FakeHttp()
    rt = make_runtime(http)
    case = Engine(rt, ScanOptions(include={"bcb_authorized_institutions"})).investigate([Entity.make(T.DOMAIN, "www.bb.com.br")])
    ours = [r for r in case.results if r.module == "bcb_authorized_institutions"]
    assert ours and ours[0].status is Status.OK and ours[0].attributes["known_good"] is True
    assert http.calls == []


# ======================================================================================
# correlation rules (v3lum/correlations/p1_g10_3.py): the production path of FC8
# ======================================================================================


def _lookalike_graph(tmp_path, *, protected_attributes: bool):
    from v3lum.core import correlate

    doc = json.loads((FIXTURES / "rules" / "bcb_lookalike_activity" / "positive_active_lookalike.json").read_text(encoding="utf-8"))
    if not protected_attributes:  # the imitated domain was only listed (expand=False): nothing ran on it
        for node in doc["nodes"]:
            if node["key"] == "domain:bb.com.br":
                node.pop("attributes", None)
                node.pop("findings", None)
    path = tmp_path / "graph.json"
    path.write_text(json.dumps(doc), encoding="utf-8")
    fx_ = correlate.load_graph_fixture(path)
    return correlate.run_rules(fx_.graph, fx_.results, only={"bcb_lookalike_activity"}, rctx=fx_.rctx)


def test_lookalike_rule_reads_the_local_list_when_the_graph_lacks_brand_facts(tmp_path):
    assert _lookalike_graph(tmp_path, protected_attributes=False) == []  # no list installed: never guess, stay silent
    install_bcb()
    (corr,) = _lookalike_graph(tmp_path, protected_attributes=False)
    assert corr.severity.label == "high" and corr.label.value == "probable" and corr.attack == ["T1583.001"]
    assert "registered 2026-11-20, resolves yes, MX yes, first certificate 2026-11-21" in corr.description
    assert "malicious" not in corr.title.lower() and set(corr.tags) == {"typosquat", "verified_fi"}


def test_typosquat_discovers_the_protected_brand_dataset():
    """FC8: P012 typosquat finds this module's DominiosVerificados registration by source and URL."""
    from tests.fakes import make_ctx
    from v3lum.modules.domain_dns import typosquat as TS

    rows, note = TS._bcb_dataset(make_ctx(TS.Typosquat))
    assert rows == [] and "not downloaded" in note and B.DOMINIOS.dataset in note
    install_bcb()
    rows, note = TS._bcb_dataset(make_ctx(TS.Typosquat))
    assert note == "" and {r["domain"] for r in rows} >= {"bb.com.br", "itau-unibanco.com.br", "caixa.gov.br"}
