"""Offline tests of dou_search (P242) over tests/fixtures/dou_search/.

The dump fixtures follow the official DOU XML layout (INLABS / open-data base). ``dump_ok.zip`` reuses the
titles, organs and pages of three real acts of the research search sample with synthetic bodies (EMPRESA
EXEMPLO COMERCIO LTDA, FULANO DE TAL, BELTRANO DA SILVA; the Banco do Brasil act keeps only public company
facts): a CNPJ extrato, a penalty despacho, a routine BB act, a routine appointment, an edital quoting a CNJ
number and an unrelated act. A trimmed real dump excerpt could not be captured from the build egress
(www.in.gov.br drops the connection, backlog). Broken, DTD, traversal and not-a-zip dumps check the loud
failures. Every test runs on the isolated V3LUM_HOME of tests/conftest.py.
"""

from __future__ import annotations

import shutil
import zipfile

import pytest

from tests.fakes import FIXTURES, FakeHttp, run_module
from v3lum.core.context import ScanOptions
from v3lum.core.models import Status
from v3lum.modules.brazil_public_data import dou_search as mod
from v3lum.modules.brazil_public_data.dou_search import DouSearch

FX = FIXTURES / "dou_search"
CNPJ = "11222333000181"
PURPOSE = ScanOptions(purpose="due diligence of a supplier (ticket DD-7)")


def install(*names: str, **kw):
    return mod.install_dumps([FX / n for n in names], **kw)


# ---------------------------------------------------------------------------- parsing (cond 5)
def test_parse_single_article():
    arts = mod.parse_dou_xml((FX / "article_cnpj.xml").read_bytes())
    assert len(arts) == 1
    a = arts[0]
    assert a["section"] == 3 and a["date"] == "2026-11-25" and a["art_type"] == "Extrato de Contrato"
    assert a["url"].startswith("http://pesquisa.in.gov.br/") and "11.222.333/0001-81" in a["text"]


def test_safe_xml_refuses_dtd_but_not_doctype_text_in_cdata():
    with pytest.raises(mod.XmlRefused):
        mod.safe_xml_root(b'<?xml version="1.0"?><!DOCTYPE x [<!ENTITY a "b">]><x>&a;</x>')
    root = mod.safe_xml_root(b"<xml><t><![CDATA[<!DOCTYPE html><p>ok</p>]]></t></xml>")
    assert root.findtext("t").startswith("<!DOCTYPE html>")
    with pytest.raises(mod.XmlRefused):
        mod.safe_xml_root(b"<xml><unclosed></xml>")


@pytest.mark.parametrize("name", ["dump_broken_format.zip", "dump_doctype.zip", "dump_traversal.zip", "dump_not_zip.html"])
def test_broken_dumps_are_format_changed(name):
    out = install(name)
    assert out[0]["status"] == "format_changed" and out[0]["reason"].startswith("format changed")


def test_dump_name_window_and_penalty_helpers():
    assert mod.parse_dump_name("S01112026.zip") == {"section": 1, "month": "2026-11", "variant": None}
    assert mod.parse_dump_name("evil.zip") is None
    w = mod.window(["2024-10", "2024-11", "2026-11", "2025-12"], "2026-11", 24)
    assert w["prune"] == ["2024-10", "2024-11"] and w["keep"] == ["2025-12", "2026-11"]
    assert mod.penalty_terms("aplicar a penalidade de multa e a SANÇÃO de suspensão") == ["multa", "penalidade", "sancao", "suspensao"]
    assert mod.penalty_terms("sanciono a seguinte Lei") == []
    text = "x" * 500 + " EMPRESA EXEMPLO " + "y" * 500
    exc = mod.excerpt(text, 501, 516)
    assert len(exc) <= 300 and "EMPRESA EXEMPLO" in exc and exc.startswith("…") and exc.endswith("…")


# ---------------------------------------------------------------------------- module runs
def test_without_index_unavailable_dataset_with_manual_link():
    res = run_module(DouSearch, f"cnpj:{CNPJ}", FakeHttp())
    assert res.status is Status.UNAVAILABLE and res.reason_code == "dataset"
    assert "run v3lum data update dou" in res.error
    assert any(link_url.startswith("https://www.in.gov.br/consulta/-/buscar/dou?q=%2211.222.333%2F0001-81%22") for _l, link_url in res.links)


def test_cnpj_hits_ranked_penalty_first_with_minimised_records():
    out = install("dump_ok.zip")
    assert out[0]["status"] == "installed" and out[0]["articles"] == 6
    http = FakeHttp()
    res = run_module(DouSearch, f"cnpj:{CNPJ}", http)
    assert res.status is Status.OK and http.calls == []  # never any network
    m = res.attributes["dou_mentions"]
    assert m["count"] == 3 and m["as_of"] == "2026-11-25"
    top = m["top"]
    assert top[0]["penalty_terms"] == ["multa", "penalidade"] and top[0]["date"] == "2026-11-19"
    assert [t["date"] for t in top[1:]] == ["2026-11-25", "2026-10-10"]
    for t in top:
        assert set(t) == {"title", "date", "section", "organ", "url", "excerpt", "art_type", "penalty_terms", "match"}
        assert len(t["excerpt"]) <= 300
    assert res.attributes["dou_status"].startswith("DOU dump as of 2026-11-25: 3 mention(s)")
    by_title = {f.title: f for f in res.findings}
    low = by_title["DOU act with a penalty term mentions this CNPJ"]
    assert low.severity.name == "LOW" and low.criterion and "penalty_term" in low.tags
    routine = [f for f in res.findings if f.title == "DOU mention (routine act)"]
    assert routine and all(f.severity.name == "INFO" and "context_only" in f.tags for f in routine)
    # CNJ number of the edital excerpt: a KEYWORD pivot that never auto-expands; person names never pivot
    assert [(p.entity.type.value, p.entity.value, p.expand) for p in res.pivots] == [("keyword", "0001234-71.2024.8.26.0100", False)]
    assert "FULANO" not in str([p.entity.value for p in res.pivots])
    assert all("text" not in t and len(t["excerpt"]) <= 300 for t in res.raw["top"])  # never the full act text


def test_company_name_seed_routine_bank_act():
    install("dump_ok.zip")
    res = run_module(DouSearch, "company_name:Banco do Brasil S.A.", FakeHttp())
    assert res.status is Status.OK
    m = res.attributes["dou_mentions"]
    assert m["count"] == 1 and m["top"][0]["title"] == "EXTRATO DE TERMO DE CESSÃO DE USO"
    assert res.findings[0].severity.name == "INFO" and "context_only" in res.findings[0].tags


def test_company_name_pivot_is_not_matched():
    install("dump_ok.zip")
    res = run_module(DouSearch, "company_name:Banco do Brasil S.A.", FakeHttp(), is_seed=False, depth=1)
    assert res.status is Status.SKIPPED and res.reason_code == "not_applicable"


def test_person_names_need_a_typed_seed_and_purpose():
    install("dump_ok.zip")
    res = run_module(DouSearch, "person_name:FULANO DE TAL", FakeHttp())
    assert res.status is Status.SKIPPED and res.reason_code == "privacy"
    res2 = run_module(DouSearch, "person_name:FULANO DE TAL", FakeHttp(), options=PURPOSE, is_seed=False, depth=1)
    assert res2.status is Status.SKIPPED and res2.reason_code == "privacy"
    res3 = run_module(DouSearch, "person_name:FULANO DE TAL", FakeHttp(), options=PURPOSE)
    assert res3.status is Status.OK and res3.attributes["dou_mentions"]["count"] == 2
    assert res3.pivots == []


def test_keywords_only_on_explicit_request():
    install("dump_ok.zip")
    res = run_module(DouSearch, "keyword:terminal de autoatendimento", FakeHttp())
    assert res.status is Status.SKIPPED and res.reason_code == "not_applicable"
    res2 = run_module(DouSearch, "keyword:terminal de autoatendimento", FakeHttp(), options=ScanOptions(include={"dou_search"}))
    assert res2.status is Status.OK and res2.attributes["dou_mentions"]["count"] == 1


def test_no_match_is_empty_with_the_dump_date_never_no_mentions():
    install("dump_no_match.zip")
    res = run_module(DouSearch, f"cnpj:{CNPJ}", FakeHttp())
    assert res.status is Status.EMPTY
    assert res.error.startswith("not found in the local DOU dump as of 2026-11-25") and "recent acts may be missing" in res.error


def test_only_broken_dump_is_error_format_changed():
    install("dump_broken_format.zip")
    res = run_module(DouSearch, f"cnpj:{CNPJ}", FakeHttp())
    assert res.status is Status.ERROR and "format changed" in res.error and "never 'no mentions'" in res.error


def test_broken_newer_dump_keeps_the_previous_index_and_says_so():
    install("dump_ok.zip")
    install("dump_broken_format.zip")
    res = run_module(DouSearch, f"cnpj:{CNPJ}", FakeHttp())
    assert res.status is Status.OK and "newer dump rejected" in res.attributes["dou_status"]


def test_window_prunes_old_months_and_reinstall_replaces():
    install("dump_ok.zip", window_months=3)
    idx, _ = mod.open_index()
    try:
        assert idx.months() == ["2026-10", "2026-11"]
    finally:
        idx.close()
    install("dump_ok.zip", window_months=3)  # same months again: replaced, never duplicated
    res = run_module(DouSearch, f"cnpj:{CNPJ}", FakeHttp())
    assert res.attributes["dou_mentions"]["count"] == 3


def test_cnpj_seed_with_rfb_razao_social(monkeypatch):
    install("dump_ok.zip")
    monkeypatch.setattr(mod, "_rfb_company", lambda cnpj: ("BANCO DO BRASIL SA", "2038"))
    res = run_module(DouSearch, "cnpj:00000000000191", FakeHttp())
    assert res.status is Status.OK and res.attributes["dou_mentions"]["count"] == 1
    monkeypatch.setattr(mod, "_rfb_company", lambda cnpj: ("FULANO DE TAL", "2135"))  # MEI: a person's name, never matched
    res2 = run_module(DouSearch, "cnpj:00000000000191", FakeHttp())
    assert res2.attributes["dou_mentions"]["count"] == 1 and all("cnpj" in t["match"] for t in res2.attributes["dou_mentions"]["top"])


def test_index_file_is_private(tmp_path):
    install("dump_ok.zip")
    path = mod.index_dir() / mod.INDEX_FILE
    assert path.stat().st_mode & 0o077 == 0 and mod.index_dir().stat().st_mode & 0o077 == 0


def test_install_cli(tmp_path, capsys):
    src = tmp_path / "S03112026.zip"
    shutil.copy(FX / "dump_ok.zip", src)
    assert zipfile.is_zipfile(src)
    assert mod.main(["install", str(src)]) == 0
    assert "installed" in capsys.readouterr().out
    assert mod.main(["status"]) == 0


def test_metadata_contract():
    assert DouSearch.default_enabled is True and DouSearch.disclosure == "none" and DouSearch.hosts == ()
    assert DouSearch.terms == "open" and DouSearch.manual_link == "dou_search_links:dou_search"
