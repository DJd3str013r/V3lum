"""Offline tests of cgu_sanctions_bulk (P240) over tests/fixtures/cgu_sanctions_bulk/.

The zips keep the real CGU headers (cp1252, ';', the published typos) and real non-identity fields of a
few rows; every identity is synthetic (EMPRESA EXEMPLO ..., FULANO DE TAL, JOSE DA SILVA) and person
CPFs are documentation values in the published full 11-digit form (masked at ingestion). The 403
AccessDenied and the 302 redirect exchanges are live captures (2026-11-26) without bodies of persons.
Datasets are installed through the real dataset manager (DataStore.update) over FakeHttp.
"""

from __future__ import annotations

import json
import sqlite3
from datetime import datetime, timezone

import pytest

from tests.fakes import FIXTURES, FakeClock, FakeHttp, make_runtime, module_fixture, run_module
from v3lum.core.context import ScanOptions
from v3lum.core.models import Status
from v3lum.modules.brazil_public_data import cgu_sanctions_bulk as mod
from v3lum.modules.brazil_public_data.cgu_sanctions_bulk import CguSanctionsBulk
from v3lum.modules.person_name import ibge_name_frequency as ibge

FX = FIXTURES / "cgu_sanctions_bulk"
S3 = "https://dadosabertos-download.cgu.gov.br/PortalDaTransparencia/saida/{slug}/{d}_{suffix}.zip"
SUFFIX = {"ceis": "CEIS", "cnep": "CNEP", "cepim": "CEPIM", "acordos_leniencia": "AcordosLeniencia", "pep": "PEP"}
GOOD = {"ceis": ("ceis_ok.zip", "20261125"), "cnep": ("cnep_ok.zip", "20261125"), "cepim": ("cepim_ok.zip", "20261124"),
        "acordos_leniencia": ("acordos_leniencia_ok.zip", "20261125"), "pep": ("pep_ok.zip", "202610")}
PURPOSE = ScanOptions(purpose="due diligence of a supplier (ticket DD-1)")


@pytest.fixture(autouse=True)
def _small_fixtures(monkeypatch, clean_registry):
    """Trimmed fixtures hold a handful of rows: lower the minimum-row validation (production: ~40-50% of today)."""
    monkeypatch.setattr(mod, "MIN_ROWS", {k: 1 for k in mod.LISTS})


def s3_url(key: str, label: str) -> str:
    spec = mod.LISTS[key]
    return S3.format(slug=spec.slug, d=label, suffix=SUFFIX[key])


def serve(http: FakeHttp, key: str, label: str, zip_name: str) -> None:
    http.add("GET", mod.dataset_url(key, label), redirect_to=s3_url(key, label))
    http.add("GET", s3_url(key, label), body=(FX / zip_name).read_bytes(),
             headers={"content-type": "application/zip", "etag": f'"{label}"', "last-modified": "Wed, 25 Nov 2026 21:18:30 GMT"})


def not_published(http: FakeHttp, key: str, label: str) -> None:
    ex = module_fixture("cgu_sanctions_bulk", "ceis_not_published_403.http.json")["response"]
    http.add("GET", mod.dataset_url(key, label), redirect_to=s3_url(key, label))
    http.add("GET", s3_url(key, label), status=ex["status"], text=ex["body"], headers={"content-type": "application/xml"})


def install(rt, http: FakeHttp, keys=tuple(mod.LIST_ORDER)) -> None:
    for key in keys:
        zip_name, label = GOOD[key]
        serve(http, key, label, zip_name)
        mod.register_list(key, label)
        result = rt.data.update(mod.LISTS[key].dataset)
        assert result.ok, result.reason


def runtime(clock: FakeClock | None = None, *, keys=tuple(mod.LIST_ORDER)):
    http = FakeHttp()
    rt = make_runtime(http, clock=clock or FakeClock())
    install(rt, http, keys)
    return rt


def run(entity: str, rt, **kw):
    return run_module(CguSanctionsBulk, entity, None, runtime=rt, **kw)


def by_title(res) -> dict[str, list]:
    out: dict[str, list] = {}
    for f in res.findings:
        out.setdefault(f.title, []).append(f)
    return out


# --------------------------------------------------------------------------------------
# dataset manager: walk-back, validation, safe archives, superseded copies (cond 1-2, 6)
# --------------------------------------------------------------------------------------


def test_update_walks_back_over_not_published_files_and_installs_an_indexed_store():
    http = FakeHttp()
    rt = make_runtime(http)
    not_published(http, "ceis", "20261126")
    serve(http, "ceis", "20261125", "ceis_ok.zip")
    (result,) = mod.update_lists(rt.data, ("ceis",), now=datetime(2026, 11, 26, 12, tzinfo=timezone.utc))
    assert result.ok, result.reason
    path = rt.data.path("cgu_sanctions_bulk.ceis")
    assert path.read_bytes()[:16] == b"SQLite format 3\x00"  # the raw zip is never kept
    conn = sqlite3.connect(path)
    meta = dict(conn.execute("SELECT k, v FROM meta").fetchall())
    assert meta["file_date"] == "2026-11-25" and meta["list"] == "ceis" and meta["rows"] == "6"
    rows = [json.loads(r[0]) for r in conn.execute("SELECT row_json FROM rows").fetchall()]
    conn.close()
    person = next(r for r in rows if r["name"] == "FULANO DE TAL")
    assert person["cpf_masked"] == "***.456.789-**" and person["cnpj"] is None and "process" not in person
    assert b"12345678909" not in path.read_bytes()  # full CPFs never reach the store (cond 6, AR24)
    assert rt.data.info("cgu_sanctions_bulk.ceis").url.endswith("/ceis/20261125")
    hosts = http.hosts()
    assert hosts == {"portaldatransparencia.gov.br", "dadosabertos-download.cgu.gov.br"}


def test_pep_walks_back_by_month():
    http = FakeHttp()
    rt = make_runtime(http)
    not_published(http, "pep", "202611")
    serve(http, "pep", "202610", "pep_ok.zip")
    (result,) = mod.update_lists(rt.data, ("pep",), now=datetime(2026, 11, 26, 12, tzinfo=timezone.utc))
    assert result.ok
    assert mod.candidate_labels("pep", datetime(2026, 1, 5).date()) == ["202601", "202512", "202511"]
    assert mod.candidate_labels("ceis", datetime(2026, 11, 26).date())[-1] == "20261119"  # at most 7 days back


def test_other_failures_stop_the_walk_back():
    http = FakeHttp()
    rt = make_runtime(http)
    http.add("GET", mod.dataset_url("ceis", "20261126"), redirect_to=s3_url("ceis", "20261126"))
    http.add("GET", s3_url("ceis", "20261126"), status=429, text="slow down")
    (result,) = mod.update_lists(rt.data, ("ceis",), now=datetime(2026, 11, 26, 12, tzinfo=timezone.utc))
    assert not result.ok
    assert mod.dataset_url("ceis", "20261125") not in http.urls()  # a rate limit is not 'not published'


@pytest.mark.parametrize("bad", ["ceis_bad_header.zip", "ceis_extra_member.zip", "ceis_ratio_bomb.zip", "ceis_traversal.zip",
                                 "not_a_zip.html"])
def test_invalid_downloads_never_replace_the_previous_copy(bad):
    rt = runtime(keys=("ceis",))
    before = rt.data.info("cgu_sanctions_bulk.ceis").sha256
    http = rt.http.transport
    serve(http, "ceis", "20261126", bad)
    mod.register_list("ceis", "20261126")
    result = rt.data.update("cgu_sanctions_bulk.ceis")
    assert not result.ok
    assert rt.data.info("cgu_sanctions_bulk.ceis").sha256 == before
    meta = dict(sqlite3.connect(rt.data.path("cgu_sanctions_bulk.ceis")).execute("SELECT k, v FROM meta").fetchall())
    assert meta["file_date"] == "2026-11-25"


def test_leniency_zip_needs_both_members(tmp_path):
    label, infos = mod._zip_members("acordos_leniencia", FX / "acordos_leniencia_ok.zip")
    assert label == "20261125" and sorted(i.filename for i in infos) == ["20261125_Acordos.csv", "20261125_Efeitos.csv"]
    with pytest.raises(ValueError):
        mod._zip_members("acordos_leniencia", FX / "ceis_ok.zip")
    target = tmp_path / "leniencia.zip"
    target.write_bytes((FX / "acordos_leniencia_ok.zip").read_bytes())
    meta = mod.build_store("acordos_leniencia", target)
    assert meta["members"] == "20261125_Acordos.csv,20261125_Efeitos.csv" and meta["rows"] == "3"


def test_minimum_rows_reject_an_incomplete_file(monkeypatch, tmp_path):
    monkeypatch.setattr(mod, "MIN_ROWS", {k: 1000 for k in mod.LISTS})
    target = tmp_path / "ceis.zip"
    target.write_bytes((FX / "ceis_ok.zip").read_bytes())
    with pytest.raises(ValueError, match="rows"):
        mod.build_store("ceis", target)


# --------------------------------------------------------------------------------------
# CNPJ screening (cond 3-4, 8)
# --------------------------------------------------------------------------------------


def test_exact_match_in_force_is_high_and_root_match_is_medium():
    rt = runtime()
    res = run("cnpj:11222333000181", rt)
    assert res.status is Status.OK
    found = by_title(res)
    (ceis,) = found["Listed in CEIS (in force)"]
    assert ceis.severity.label == "high" and "sanctions" in ceis.tags and ceis.criterion
    assert ceis.data["match_type"] == "exact_cnpj" and ceis.data["sanction_id"] == "900001"
    assert ceis.data["dedup_key"] == "ceis|11222333000181|900001"
    assert ceis.data["organ"] == "COMANDO DO EXERCITO" and ceis.data["end"] == "2027-06-03"
    assert "List as of 2026-11-25" in ceis.description and ceis.references == ["https://portaldatransparencia.gov.br/sancoes/ceis"]
    (cnep,) = found["Related establishment listed in CNEP (in force)"]
    assert cnep.severity.label == "medium" and cnep.data["match_type"] == "cnpj_root"
    assert cnep.data["matched_cnpj"] == "11222333000262"
    assert res.attributes["sanctioned"] is True
    assert res.attributes["sanctions_screening"]["cepim"]["state"] == "no_record"
    assert res.source_statuses["transparencia.cgu_sanctions_bulk_ceis"]["status"] == "ok"
    assert "transparencia.cgu_sanctions_bulk_pep" not in res.source_statuses  # PEP is for persons only


def test_expired_sanctions_are_info_formerly_sanctioned():
    rt = runtime()
    res = run("cnpj:22333444000181", rt)
    found = by_title(res)
    (ceis,) = found["Formerly listed in CEIS"]
    assert ceis.severity.label == "info" and "formerly sanctioned (2026-10-09)" in ceis.description
    (cnep,) = found["Formerly listed in CNEP"]
    assert cnep.data["status"] == "expired"
    assert "sanctioned" not in res.attributes


def test_no_end_date_is_in_force():
    rt = runtime()
    gama = run("cnpj:33444555000181", rt)
    assert by_title(gama)["Listed in CEIS (in force)"][0].data["end"] is None
    delta = run("cnpj:44555666000181", rt)
    (fine,) = by_title(delta)["Listed in CNEP (in force)"]
    assert fine.data["sanction_type"] == "Multa" and fine.data["fine"] == 184138.94


def test_cepim_and_leniency_agreements():
    rt = runtime()
    cepim = run("cnpj:55666777000181", rt)
    titles = by_title(cepim)
    assert titles["Listed in CEPIM (in force)"][0].severity.label == "high"
    assert titles["Related establishment listed in CEPIM (in force)"][0].data["matched_cnpj"] == "55666777000343"
    zeta = run("cnpj:66777888000181", rt)
    (agreement,) = by_title(zeta)["Listed in Acordos de Leniencia (in force)"]
    assert agreement.data["situation"] == "Em Execução" and len(agreement.data["effects"]) == 2
    eta = run("cnpj:77888999000181", rt)
    assert by_title(eta)["Formerly listed in Acordos de Leniencia"][0].severity.label == "info"  # 'Cumprido'


def test_no_record_reads_no_record_as_of_the_file_date():
    rt = runtime()
    res = run("cnpj:98765012000101", rt)
    assert res.status is Status.OK and not res.findings
    row = res.source_statuses["transparencia.cgu_sanctions_bulk_ceis"]
    assert row["status"] == "empty" and row["reason"] == "no record in CEIS as of 2026-11-25"
    assert {v["state"] for v in res.attributes["sanctions_screening"].values()} == {"no_record"}
    assert len(res.datasets) == 4  # the copies used are cited (name, sha256, fetched_at)


def test_missing_datasets_are_not_screened_never_clean():
    rt = make_runtime(FakeHttp())
    res = run("cnpj:11222333000181", rt)
    assert res.status is Status.UNAVAILABLE and res.reason_code == "dataset"
    assert "never read as 'not sanctioned'" in res.error
    row = res.source_statuses["transparencia.cgu_sanctions_bulk_cnep"]
    assert row["status"] == "unavailable" and row["reason"].startswith("not screened against CNEP (dataset missing")


def test_stale_list_is_not_screened_but_listings_still_count():
    rt = runtime(FakeClock("2026-12-05T12:00:00Z"))
    res = run("cnpj:11222333000181", rt)
    row = res.source_statuses["transparencia.cgu_sanctions_bulk_cepim"]
    assert row["status"] == "unavailable" and row["reason"] == "not screened against CEPIM (2026-11-24)"
    (ceis,) = by_title(res)["Listed in CEIS (in force)"]
    assert ceis.data["stale_list"] is True and ceis.data["file_date"] == "2026-11-25"


def test_pep_staleness_counts_from_its_publication_date():
    meta = {"file_date": "2026-10", "file_label": "202610", "published": "2026-11-16"}
    assert mod.staleness("pep", meta, datetime(2026, 12, 20).date()) is None  # 34 days after publication
    assert mod.staleness("pep", meta, datetime(2026, 12, 27).date()) == "not screened against PEP (2026-10)"
    assert mod.staleness("pep", {"file_label": "202610", "file_date": "2026-10"}, datetime(2026, 12, 20).date()) is None


# --------------------------------------------------------------------------------------
# names: purpose-bound persons, homonyms, PEP, companies (cond 5-7)
# --------------------------------------------------------------------------------------


def install_ranking(rt) -> None:
    http = rt.http.transport
    for name, url in ibge.RANKING_DATASETS.items():
        http.add("GET", url, json=module_fixture("ibge_name_frequency", "ranking_br.json"))
        assert rt.data.update(name).ok


def test_person_screening_needs_a_recorded_purpose():
    rt = runtime()
    res = run("person_name:JOSE DA SILVA", rt)
    assert res.status is Status.SKIPPED and res.reason_code == "privacy"


def test_person_pivots_are_never_screened_except_qsa_partners():
    rt = runtime()
    other = run("person_name:JOSE DA SILVA", rt, options=PURPOSE, is_seed=False, depth=1,
                provenance=[("email:someone@example.com", "mentions", "ioc_extract")])
    assert other.status is Status.SKIPPED and other.reason_code == "privacy"
    partner = run("person_name:FULANO DE TAL", rt, options=PURPOSE, is_seed=False, depth=1,
                  provenance=[("cnpj:98765432000198", "partner_of", "cnpj_lookup")])
    assert partner.status is Status.OK and partner.findings


def test_common_name_match_is_lowered_by_the_homonym_score():
    rt = runtime()
    install_ranking(rt)
    res = run("person_name:José da Silva", rt, options=PURPOSE)
    found = by_title(res)
    (ceis,) = found["Possible match in CEIS (person name only)"]
    assert ceis.severity.label == "info"  # very common name: never above INFO
    assert ceis.label.value == "possible" and ceis.confidence == pytest.approx(0.16)
    assert "name_only_match" in ceis.tags and ceis.data["homonym"]["risk"] == "high"
    assert ceis.data["homonym_applied"] is True
    assert ceis.data["cpf_as_published"] == "***.654.321-**"
    (pep,) = found["PEP (possible match)"]
    assert pep.severity.label == "info" and {"pep", "context_only"} <= set(pep.tags)
    assert pep.data["role"] == "ASSESSOR ESPECIAL"
    text = json.dumps({"raw": res.raw, "f": [f.to_dict() for f in res.findings]}, ensure_ascii=False)
    assert "98765432100" not in text and "FULANO DE TAL" not in text  # only matched rows enter the case
    assert any(c["name"].startswith("ibge_name_frequency.") for c in res.datasets)


def test_uncommon_name_match_is_medium_possible():
    rt = runtime()
    install_ranking(rt)
    res = run("person_name:Fulano de Tal", rt, options=PURPOSE)
    (ceis,) = by_title(res)["Possible match in CEIS (person name only)"]
    assert ceis.severity.label == "medium" and ceis.confidence <= 0.5 and ceis.label.value == "possible"
    assert ceis.data["homonym"]["risk"] == "unknown"
    assert "transparencia.cgu_sanctions_bulk_cepim" not in res.source_statuses  # companies only


def test_company_name_possible_match():
    rt = runtime()
    res = run("company_name:Empresa Exemplo Alfa Ltda.", rt)
    (ceis,) = by_title(res)["Possible match in CEIS (company name only)"]
    assert ceis.severity.label == "medium" and ceis.label.value == "possible"
    assert ceis.data["matched_cnpj"] == "11222333000181" and ceis.data["score"] == 1.0
    assert "homonym" not in ceis.data  # first-name frequency never applies to companies


def test_name_keys_and_scores():
    assert mod.name_key("EMPRESA EXEMPLO GAMA S.A.", company=True) == "EMPRESA EXEMPLO GAMA"
    assert mod.name_key("Empresa Exemplo Alfa Ltda - ME", company=True) == "EMPRESA EXEMPLO ALFA"
    assert mod.name_key("João de Sá", company=False) == "JOAO DE SA"
    assert mod.name_score("JOSE DA SILVA", "JOSE DA SILVA") == 1.0
    assert mod.name_score("JOSE DA SILVA", "JOSE DA SILVA FILHO") < mod.MIN_NAME_SCORE


def test_names_are_scored_by_the_shared_p219_matcher():
    from v3lum.modules.company_org import namematch as nm

    assert mod.MATCHER.startswith("token-set Jaro-Winkler")
    a, b = "JOSE CARLOS DA SILVA", "JOSE CARLOZ DA SILVA"
    assert mod.name_score(a, b) == round(nm.token_set_jw(nm.name_tokens(a, "person"), nm.name_tokens(b, "person")), 3)
    assert mod.name_score(a, b) >= mod.MIN_NAME_SCORE  # one typo in a middle token still matches
    assert mod.name_score("EMPRESA EXEMPLO GAMA", "EMPRESA EXEMPLO DELTA", person=False) < mod.MIN_NAME_SCORE
