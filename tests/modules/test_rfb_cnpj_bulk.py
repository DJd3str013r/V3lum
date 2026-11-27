"""Offline tests of rfb_cnpj_bulk (P238) and the shared RFB importer over tests/fixtures/rfb_cnpj_bulk/.

Fixtures: live WebDAV captures of the RFB share (root and 2026-11 month listings, the 401 without
credentials, the 206 Range answer, the real Qualificacoes lookup zip) and synthetic zips in the real layout
(latin-1, ';', every field quoted, LF, no header, RFB member names) whose identities are documentation values
(FULANO DE TAL, BELTRANO DA SILVA, JOSE DA SILVA x3 homonyms, documentation CPFs 123.456.789-09 and
987.654.321-00 inside MEI names, synthetic masked CPFs, phones 5555-01xx, e-mails @example.com /
*.example). The share token in these tests is a fake value. The importer runs end to end over FakeHttp
on the isolated V3LUM_HOME of tests/conftest.py.
"""

from __future__ import annotations

import io
import json
import os
import tracemalloc
import zipfile

import pytest

from tests.fakes import FIXTURES, FakeHttp, make_runtime, module_fixture, run_module
from v3lum.core.context import ScanOptions
from v3lum.core.models import Status
from v3lum.modules.brazil_public_data import rfb_cnpj_bulk as mod
from v3lum.modules.brazil_public_data import rfb_import as imp
from v3lum.modules.brazil_public_data.rfb_cnpj_bulk import RfbCnpjBulk

FX = FIXTURES / "rfb_cnpj_bulk"
ROOT = imp.WEBDAV_URL
MONTH = "2026-11"
FAKE_TOKEN = "FixtureToken000"
SETTINGS = {
    "rfb_cnpj_bulk_share_link": f"https://arquivos.receitafederal.gov.br/index.php/s/{FAKE_TOKEN}",
    "rfb_cnpj_bulk_share_source": "https://www.gov.br/receitafederal/pt-br/acesso-a-informacao/dados-abertos/cadastros/cnpj",
    "rfb_cnpj_bulk_share_checked_at": "2026-11-26",
}
QUERY = ScanOptions(include={"rfb_cnpj_bulk"}, purpose="due diligence of a supplier (ticket DD-9)")


def _zip(member: str, rows: list[list[str]]) -> bytes:
    text = "".join(";".join(f'"{c}"' for c in r) + "\n" for r in rows).encode("latin-1")
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
        zf.writestr(member, text)
    return buf.getvalue()


def month_files() -> dict[str, bytes]:
    """The synthetic month in the real layout: fixture zips plus a tiny synthetic Municipios table."""
    files = {
        "Empresas0.zip": (FX / "empresas_synthetic.zip").read_bytes(),
        "Estabelecimentos0.zip": (FX / "estabelecimentos_synthetic.zip").read_bytes(),
        "Socios0.zip": (FX / "socios_synthetic.zip").read_bytes(),
        "Simples.zip": (FX / "simples_synthetic.zip").read_bytes(),
        "Naturezas.zip": (FX / "naturezas_synthetic.zip").read_bytes(),
        "Qualificacoes.zip": (FX / "qualificacoes_ok.zip").read_bytes(),
        "Municipios.zip": _zip("F.K03200$Z.D61114.MUNICCSV", [["7107", "SAO PAULO"], ["9701", "BRASILIA"]]),
    }
    return files


def month_listing(month: str, files: dict[str, bytes]) -> bytes:
    total = sum(len(b) for b in files.values())
    parts = [f'<d:response><d:href>/public.php/webdav/{month}/</d:href><d:propstat><d:prop><d:resourcetype><d:collection/>'
             f'</d:resourcetype><d:quota-used-bytes>{total}</d:quota-used-bytes></d:prop><d:status>HTTP/1.1 200 OK</d:status>'
             f'</d:propstat></d:response>']
    for name, body in files.items():
        parts.append(f'<d:response><d:href>/public.php/webdav/{month}/{name}</d:href><d:propstat><d:prop><d:getcontentlength>{len(body)}'
                     f'</d:getcontentlength><d:resourcetype/><d:getetag>&quot;etag-{name}&quot;</d:getetag><d:getlastmodified>'
                     f'Sat, 14 Nov 2026 10:00:00 GMT</d:getlastmodified></d:prop><d:status>HTTP/1.1 200 OK</d:status></d:propstat></d:response>')
    return ('<?xml version="1.0"?><d:multistatus xmlns:d="DAV:">' + "".join(parts) + "</d:multistatus>").encode()


def share(http: FakeHttp, files: dict[str, bytes] | None = None, *, month: str = MONTH) -> dict[str, bytes]:
    files = month_files() if files is None else files
    http.add("PROPFIND", ROOT, status=207, body=(FX / "webdav_root_ok.xml").read_bytes(), headers={"content-type": "application/xml"})
    http.add("PROPFIND", f"{ROOT}{month}/", status=207, body=month_listing(month, files), headers={"content-type": "application/xml"})
    for name, body in files.items():
        http.add("GET", f"{ROOT}{month}/{name}", status=206, body=body, match_headers={"Range": f"bytes=0-{len(body) - 1}"},
                 headers={"content-range": f"bytes 0-{len(body) - 1}/{len(body)}", "etag": f'"etag-{name}"', "content-type": "application/zip"})
    return files


def do_import(http: FakeHttp, settings: dict | None = None, **kw):
    rt = make_runtime(http, settings=SETTINGS if settings is None else settings)
    return imp.import_rfb(rt, **kw)


@pytest.fixture
def imported():
    http = FakeHttp()
    share(http)
    res = do_import(http)
    assert res["status"] == "imported", res
    return res


# ---------------------------------------------------------------------------- WebDAV parsing (cond 1-3)
def test_root_listing_months_and_size():
    months = imp.months_of(imp.parse_multistatus((FX / "webdav_root_ok.xml").read_bytes()))
    assert [m["month"] for m in months][-3:] == ["2026-09", "2026-10", "2026-11"]
    assert months[-1]["bytes"] == 7_870_490_248


def test_month_listing_and_three_times_free_space():
    summary = imp.month_files(imp.parse_multistatus((FX / "webdav_month_ok.xml").read_bytes()))
    assert not summary["missing_tables"] and summary["total_bytes"] == 7_870_490_248
    p = imp.download_plan(summary, 10 * 1024**3, imp.PRESETS["full"])
    assert not p["ok"] and "3x the download" in p["refusal"]
    ok = imp.download_plan(summary, 30 * 1024**3, imp.PRESETS["full"])
    assert ok["ok"] and ok["required_free_bytes"] == 3 * 7_870_490_248
    names = imp.download_plan(summary, 30 * 1024**3, imp.PRESETS["names"])
    assert {f["table"] for f in names["files"]} == {"empresas", "estabelecimentos", "naturezas", "municipios"}


def test_month_missing_socios_is_a_layout_change_never_no_companies():
    summary = imp.month_files(imp.parse_multistatus((FX / "webdav_month_missing_socios.xml").read_bytes()))
    assert summary["missing_tables"] == ["socios"]
    p = imp.download_plan(summary, 10**12, imp.PRESETS["qsa"])
    assert not p["ok"] and "layout change" in p["refusal"]


def test_safe_xml_refuses_dtd_and_truncated_answers():
    with pytest.raises(imp.FormatChanged):
        imp.parse_multistatus((FX / "webdav_doctype.xml").read_bytes())
    with pytest.raises(imp.FormatChanged):
        imp.parse_multistatus((FX / "webdav_truncated.xml").read_bytes())


@pytest.mark.parametrize(("name", "problem"), [
    ("webdav_noauth_401.http.json", "token_missing"), ("webdav_bad_token_401.http.json", "token_rejected"),
    ("webdav_login_redirect.http.json", "login_required"), ("webdav_html_200.http.json", "html_instead_of_dav"),
    ("old_path_404.http.json", "share_or_path_not_found"),
])
def test_webdav_problems(name, problem):
    resp = module_fixture(RfbCnpjBulk, name)["response"]
    assert imp.webdav_problem(resp["status"], resp["headers"], resp["body"]) == problem


def test_share_link_must_be_official():
    assert imp.share_token_from_link(SETTINGS["rfb_cnpj_bulk_share_link"]) == FAKE_TOKEN
    assert imp.share_token_from_link("https://github.com/example/s/YggdBLfdninEJX9") is None
    assert imp.share_token_from_link("http://arquivos.receitafederal.gov.br/s/FixtureToken000") is None
    assert imp.official_source(SETTINGS["rfb_cnpj_bulk_share_source"])
    assert not imp.official_source("https://github.com/cuducos/minha-receita")


# ---------------------------------------------------------------------------- rows (cond 3-4)
def test_minimisation_at_import():
    emp = {r[0]: r for r in imp.iter_rows((FX / "empresas_synthetic.zip").read_bytes(), "empresas")}
    assert emp["22333444"][1] == "FULANO DE TAL" and emp["22333444"][5] == 1
    assert emp["33444555"][1] == "BELTRANO DA SILVA" and emp["33444555"][5] == 1
    soc = list(imp.iter_rows((FX / "socios_synthetic.zip").read_bytes(), "socios"))
    assert all(len(r) == 9 for r in soc)  # faixa etaria and legal representatives are never stored
    assert all(r[8] is None or imp.MASKED_CPF_RE.match(r[8]) for r in soc)
    assert "FULANO DE TAL" not in json.dumps(soc)  # the foreign partner's legal representative is dropped
    assert imp.strip_cpf_from_name("LOJA 12345678900 LTDA", "2062") == ("LOJA 12345678900 LTDA", False)
    assert imp.strip_cpf_from_name("MEI 12345678900", "2135") == ("MEI", True)


@pytest.mark.parametrize("name", ["socios_bad_columns.zip", "two_members.zip", "traversal_member.zip", "not_a_zip.html"])
def test_malformed_zips_fail_loudly(name):
    with pytest.raises(imp.FormatChanged):
        list(imp.iter_rows((FX / name).read_bytes(), "socios"))


def test_one_bad_row_is_counted_and_skipped():
    stats: dict = {}
    rows = list(imp.iter_rows((FX / "socios_one_bad_row.zip").read_bytes(), "socios", stats))
    assert stats["bad_rows"] == 1 and len(rows) == stats["rows"]


def test_real_lookup_table_layout():
    rows = list(imp.iter_rows((FX / "qualificacoes_ok.zip").read_bytes(), "qualificacoes"))
    assert len(rows) == 68 and ("49", "Sócio-Administrador") in rows


# ---------------------------------------------------------------------------- importer end to end (cond 1-5, 9)
def test_import_end_to_end_installs_a_private_index(imported):
    assert imported["month"] == MONTH and imported["rows"]["socios"] == 7
    path = mod.index_path()
    assert path.is_file() and path.stat().st_mode & 0o077 == 0 and path.parent.stat().st_mode & 0o077 == 0
    blob = path.read_bytes()
    assert b"12345678909" not in blob and b"98765432100" not in blob and b"987.654.321-00" not in blob
    downloads = path.parent / imp.DOWNLOADS
    assert not (downloads / MONTH).exists()  # the dump is removed once imported (storage limitation)
    assert imp.read_state()["last_import"]["status"] == "imported"


def test_superseded_months_deleted_and_keep_downloads(tmp_path):
    old = imp.dataset_dir() / imp.DOWNLOADS / "2026-10"
    old.mkdir(parents=True)
    (old / "Empresas0.zip").write_bytes(b"old")
    http = FakeHttp()
    share(http)
    res = do_import(http, keep_downloads=True)
    assert res["status"] == "imported" and "2026-10" in res["removed"]
    assert not old.exists() and (imp.dataset_dir() / imp.DOWNLOADS / MONTH / "Empresas0.zip").is_file()


def test_resumed_download_sends_range_from_the_partial_file():
    files = month_files()
    body = files["Socios0.zip"]
    directory = imp.paths.private_dir(imp.dataset_dir() / imp.DOWNLOADS / MONTH)
    part = directory / "Socios0.zip.part"
    part.write_bytes(body[:100])
    imp._write_sidecar(part, {"etag": "etag-Socios0.zip", "size": len(body)})
    http = FakeHttp()
    http.add("GET", f"{ROOT}{MONTH}/Socios0.zip", status=206, body=body[100:], match_headers={"Range": f"bytes=100-{len(body) - 1}",
             "If-Range": '"etag-Socios0.zip"'}, headers={"content-range": f"bytes 100-{len(body) - 1}/{len(body)}", "etag": '"etag-Socios0.zip"'})
    rt = make_runtime(http, settings=SETTINGS)
    sh = imp.RfbShare(imp.scoped_http(rt), FAKE_TOKEN)
    out = sh.download(MONTH, {"name": "Socios0.zip", "bytes": len(body), "etag": "etag-Socios0.zip"}, directory)
    assert out.read_bytes() == body and not part.exists()


def test_free_space_below_three_times_is_refused(monkeypatch):
    http = FakeHttp()
    files = month_files()
    http.add("PROPFIND", ROOT, status=207, body=(FX / "webdav_root_ok.xml").read_bytes())
    http.add("PROPFIND", f"{ROOT}{MONTH}/", status=207, body=month_listing(MONTH, files))
    monkeypatch.setattr(imp.shutil, "disk_usage", lambda p: type("U", (), {"free": 10})())
    res = do_import(http)
    assert res["status"] == "refused" and "3x the download" in res["reason"]


@pytest.mark.parametrize(("name", "status"), [
    ("webdav_bad_token_401.http.json", "unavailable"), ("webdav_noauth_401.http.json", "unavailable"),
    ("webdav_login_redirect.http.json", "stopped"),
])
def test_rotated_token_or_login_is_never_no_companies(name, status):
    resp = module_fixture(RfbCnpjBulk, name)["response"]
    http = FakeHttp().add("PROPFIND", ROOT, status=resp["status"], text=resp["body"], headers=resp["headers"])
    res = do_import(http)
    assert res["status"] == status and res["hint"]
    scan = run_module(RfbCnpjBulk, "cnpj:11222333000181", FakeHttp())
    assert scan.status is Status.UNAVAILABLE and scan.reason_code == "dataset"
    assert "never read as 'no companies'" in scan.error and "last import" in scan.error


def test_no_share_link_or_unofficial_source_refuses_without_network():
    http = FakeHttp()
    assert do_import(http, settings={})["status"] == "unavailable"
    bad = {**SETTINGS, "rfb_cnpj_bulk_share_source": "https://github.com/cuducos/minha-receita"}
    res = do_import(http, settings=bad)
    assert res["status"] == "unavailable" and "official" in res["reason"] and http.calls == []


def test_month_missing_socios_import_is_format_changed():
    http = FakeHttp()
    files = {k: v for k, v in month_files().items() if not k.startswith("Socios")}
    http.add("PROPFIND", ROOT, status=207, body=(FX / "webdav_root_ok.xml").read_bytes())
    http.add("PROPFIND", f"{ROOT}{MONTH}/", status=207, body=month_listing(MONTH, files))
    assert do_import(http)["status"] == "format_changed"


def test_import_command_plan(capsys):
    http = FakeHttp()
    share(http)
    rt = make_runtime(http, settings=SETTINGS)
    app = type("App", (), {"runtime": lambda self: rt})()
    args = type("Args", (), {"tables": "qsa", "plan": True, "month": None, "yes": False, "keep_downloads": False})()
    assert imp.ImportRfbCommand.run(args, app, None) == 0
    assert "needs" in capsys.readouterr().out


# ---------------------------------------------------------------------------- module (cond 6-9)
def test_without_index_unavailable_dataset():
    res = run_module(RfbCnpjBulk, "cnpj:11222333000181", FakeHttp())
    assert res.status is Status.UNAVAILABLE and res.reason_code == "dataset" and "data import-rfb" in res.error


def test_cnpj_branches_hq_and_company_facts(imported):
    http = FakeHttp()
    res = run_module(RfbCnpjBulk, "cnpj:11222333000262", http)
    assert res.status is Status.OK and http.calls == []
    assert res.attributes["legal_name"] == "EMPRESA EXEMPLO COMERCIO LTDA" and res.attributes["rfb_hq_cnpj"] == "11222333000181"
    assert res.attributes["rfb_snapshot"] == MONTH and res.attributes["branch_type"] == "FILIAL"
    assert res.attributes["rfb_branches"]["total"] == 2
    piv = {(p.entity.value, p.relation, p.expand) for p in res.pivots}
    assert ("11222333000181", "same_cnpj_root", False) in piv


def test_mei_name_is_stripped_and_pj_partner_pivot(imported):
    res = run_module(RfbCnpjBulk, "cnpj:22333444000181", FakeHttp())
    assert res.attributes["legal_name"] == "FULANO DE TAL" and res.attributes["mei"]["optante"] is True
    res2 = run_module(RfbCnpjBulk, "cnpj:44555666000181", FakeHttp())
    assert any(p.entity.value == "11222333000181" and p.relation == "partner_of" and not p.expand for p in res2.pivots)
    assert "***" not in json.dumps(res2.attributes) and "***" not in json.dumps([f.to_dict() for f in res2.findings])


def test_shared_contact_tagged_possible_accountant(imported):
    res = run_module(RfbCnpjBulk, "cnpj:50000001000104", FakeHttp())
    shared = res.attributes.get("rfb_shared_contacts") or []
    assert {s["kind"] for s in shared} >= {"email", "phone", "address"} and all(s["companies"] >= 20 for s in shared)
    f = next(f for f in res.findings if "shared" in f.title)
    assert "shared_contact" in f.tags and "possible accountant/virtual office" in f.criterion and "RFB snapshot 2026-11" in f.description


def test_partner_name_lookup_is_purpose_bound_and_possible(imported):
    assert run_module(RfbCnpjBulk, "person_name:JOSE DA SILVA", FakeHttp()).reason_code == "privacy"
    no_case = run_module(RfbCnpjBulk, "person_name:JOSE DA SILVA", FakeHttp(), options=QUERY)
    assert no_case.status is Status.SKIPPED and "inside a case" in no_case.error
    pivot = run_module(RfbCnpjBulk, "person_name:JOSE DA SILVA", FakeHttp(), options=QUERY, case_id="C-1", is_seed=False, depth=1)
    assert pivot.status is Status.SKIPPED and pivot.reason_code == "privacy"
    res = run_module(RfbCnpjBulk, "person_name:José da Silva", FakeHttp(), options=QUERY, case_id="C-1")
    assert res.status is Status.OK
    assert {p.entity.value for p in res.pivots} == {"11222333000181", "44555666000181", "55666777000181"}
    assert all(p.relation == "partner_name_match" and not p.expand and p.confidence_label == "possible" for p in res.pivots)
    f = res.findings[0]
    assert "name_only_match" in f.tags and "never confirmed by CPF fragments" in f.criterion and "RFB snapshot 2026-11" in f.criterion
    assert res.attributes["rfb_reverse_lookup"]["kind"] == "partner_name" and res.attributes["rfb_reverse_lookup"]["total"] == 3
    assert "***" not in json.dumps(res.raw)


def test_email_lookup_capped_and_shared(imported, monkeypatch):
    monkeypatch.setattr(mod, "REVERSE_CAP", 5)
    monkeypatch.setattr(mod.RfbIndex.by_contact, "__defaults__", (5,))
    res = run_module(RfbCnpjBulk, "email:contabil@contabil-exemplo.example", FakeHttp(), options=QUERY, case_id="C-2")
    look = res.attributes["rfb_reverse_lookup"]
    assert look["total"] == 21 and look["shown"] == 5 and look["truncated"]
    assert "shared_contact" in res.findings[0].tags and len(res.pivots) == 5


def test_per_case_limit(imported):
    settings = {**SETTINGS, "rfb_cnpj_bulk_case_limit": 1}
    first = run_module(RfbCnpjBulk, "phone:+551155550101", FakeHttp(), options=QUERY, case_id="C-3", settings=settings)
    assert first.status is Status.OK and first.pivots[0].entity.value == "22333444000181"
    second = run_module(RfbCnpjBulk, "phone:+551155550101", FakeHttp(), options=QUERY, case_id="C-3", settings=settings)
    assert second.status is Status.SKIPPED and "per-case limit" in second.error


def test_unknown_cnpj_is_empty_with_snapshot(imported):
    res = run_module(RfbCnpjBulk, "cnpj:66777888000181", FakeHttp())
    assert res.status is Status.EMPTY and "RFB snapshot 2026-11" in res.error


def test_company_name_seed_exact_razao_social(imported):
    res = run_module(RfbCnpjBulk, "company_name:EMPRESA EXEMPLO COMERCIO LTDA", FakeHttp())
    assert [p.entity.value for p in res.pivots] == ["11222333000181"] and not res.pivots[0].expand
    mei = run_module(RfbCnpjBulk, "company_name:FULANO DE TAL", FakeHttp())
    assert mei.status is Status.EMPTY  # an MEI/EI name is a person's name: never resolved here


def test_dou_search_reads_the_razao_social(imported):
    assert mod.company_name_for("11.222.333/0001-81") == ("EMPRESA EXEMPLO COMERCIO LTDA", "2062")


def test_metadata_contract():
    assert RfbCnpjBulk.default_enabled is False and RfbCnpjBulk.disclosure == "none" and RfbCnpjBulk.terms == "open"
    assert RfbCnpjBulk.sources == ("rfb.cnpj_open_data",) and "bulk_download" in RfbCnpjBulk.tags


# ---------------------------------------------------------------------------- memory (cond 3)
def _big_socios(path, n: int) -> None:
    with zipfile.ZipFile(path, "w", zipfile.ZIP_DEFLATED) as zf, zf.open("K3241.K03200Y0.D61114.SOCIOCSV", "w") as fh:
        for i in range(n):
            fh.write(f'"{i % 99999999:08d}";"2";"FULANO DE TAL {i % 1000}";"***{i % 999999:06d}**";"49";"20150310";"";"***000000**";"";"00";"5"\n'.encode("latin-1"))


def _peak_mb(tmp_path, n: int) -> float:
    src = tmp_path / "Socios0.zip"
    _big_socios(src, n)
    tracemalloc.start()
    try:
        info = imp.build_index({"socios": [src]}, tmp_path / "idx.sqlite", month=MONTH)
        peak = tracemalloc.get_traced_memory()[1] / 1024 / 1024
    finally:
        tracemalloc.stop()
    assert info["rows"]["socios"] == n
    return peak


def test_streaming_memory_is_flat(tmp_path):
    assert _peak_mb(tmp_path, 50_000) < 50


@pytest.mark.slow
@pytest.mark.skipif(os.environ.get("V3LUM_SLOW") != "1", reason="slow: set V3LUM_SLOW=1 (P238 cond 3, 1M-row memory check)")
def test_streaming_memory_one_million_rows(tmp_path):
    assert _peak_mb(tmp_path, 1_000_000) < 500


def test_live_206_answer_of_the_real_lookup_file():
    """The live 206 capture (Content-Range, ETag = PROPFIND getetag) over the real Qualificacoes.zip bytes."""
    rec = module_fixture(RfbCnpjBulk, "range_206.http.json")["response"]
    body = (FX / "qualificacoes_ok.zip").read_bytes()
    headers = {k: v for k, v in rec["headers"].items() if k in ("etag", "oc-etag", "content-range", "content-type", "last-modified")}
    etag = headers["etag"].strip('"')
    http = FakeHttp().add("GET", f"{ROOT}{MONTH}/Qualificacoes.zip", status=206, body=body, headers=headers,
                          match_headers={"Range": f"bytes=0-{len(body) - 1}", "If-Range": f'"{etag}"'})
    rt = make_runtime(http, settings=SETTINGS)
    directory = imp.paths.private_dir(imp.dataset_dir() / imp.DOWNLOADS / MONTH)
    out = imp.RfbShare(imp.scoped_http(rt), FAKE_TOKEN).download(MONTH, {"name": "Qualificacoes.zip", "bytes": len(body), "etag": etag}, directory)
    assert out.read_bytes() == body and len(list(imp.iter_rows(out.read_bytes(), "qualificacoes"))) == 68
    assert http.calls[0]["headers"]["Authorization"].startswith("Basic ")


def test_empty_month_listing_is_a_layout_change():
    http = FakeHttp().add("PROPFIND", f"{ROOT}{MONTH}/", status=207, body=(FX / "webdav_month_empty.xml").read_bytes())
    rt = make_runtime(http, settings=SETTINGS)
    with pytest.raises(imp.FormatChanged):
        imp.RfbShare(imp.scoped_http(rt), FAKE_TOKEN).month(MONTH)
