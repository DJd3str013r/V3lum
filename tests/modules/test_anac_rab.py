"""anac_rab (P248): ANAC RAB aircraft registry, matched offline.

Fixtures in tests/fixtures/anac_rab/ (prep capture 2026-11-26): ``ok.csv`` keeps the real UTF-8 BOM, the
'Atualizado em: 2026-11-26' preamble and the real 34-column quoted header, with 7 synthetic rows in the exact
cell format (owner/operator JSON arrays): companies with documentation CNPJs, synthetic natural persons with
masked CPFs (they must be dropped), an 'Indisponivel' party, a short operator code, a 13-digit CNPJ that lost
its leading zero, a DV-invalid CNPJ and the reserved / cancelled / provisional statuses. Marks PR-ZZA..PT-ZZG
are synthetic (real marks of privately owned aircraft identify people). ``truncated.csv`` is cut mid-row and
``no_preamble.csv`` lacks the BOM and the preamble.
"""

from __future__ import annotations

import json
import os
import time

import pytest

from tests.fakes import FIXTURES, FakeHttp, make_runtime, run_module
from v3lum import paths
from v3lum.core.datasets import DATASETS
from v3lum.core.models import Status
from v3lum.modules.brazil_public_data import anac_rab as A
from v3lum.modules.brazil_public_data.anac_rab import AnacRab

FIX = FIXTURES / "anac_rab"
PERSON_STRINGS = ("FULANO", "BELTRANO", "CICLANO", "XXXXXX")


def fx(name: str) -> bytes:
    return (FIX / name).read_bytes()


def install(body: bytes | None = None, *, age_days: float = 0.0) -> None:
    path = paths.datasets_dir() / A.DATASET
    path.write_bytes(fx("ok.csv") if body is None else body)
    if age_days:
        when = time.time() - age_days * 86400
        os.utime(path, (when, when))


def run(value: str):
    http = FakeHttp()  # no routes: any download attempt fails the test
    res = run_module(AnacRab, value, runtime=make_runtime(http))
    http.assert_hosts_within(AnacRab)
    assert not http.urls()
    return res


def blob(res) -> str:
    return json.dumps({"raw": res.raw, "attrs": res.attributes, "findings": [f.to_dict() for f in res.findings],
                       "pivots": [(p.entity.value, p.note) for p in res.pivots]}, default=str)


# ======================================================================================
# parser, minimisation and validation (FC1, FC2, FC5)
# ======================================================================================


def test_parse_skips_bom_and_preamble_and_drops_people():
    parsed = A.parse_anac_rab(fx("ok.csv"))
    assert parsed["updated"] == "2026-11-26" and not parsed["errors"]
    assert parsed["stats"] == {"rows": 7, "dropped_parties": 6, "kept_parties": 9, "bad_json": 0, "bad_mark": 0}
    text = json.dumps(parsed)
    for needle in PERSON_STRINGS:
        assert needle not in text  # FC2: no person name or masked CPF survives the import
    by = {r["mark_display"]: r for r in parsed["rows"]}
    assert by["PT-ZZB"]["owners"] == [] and by["PT-ZZB"]["operators"][0]["cnpj"] == "11444777000161"
    assert by["PR-ZZF"]["operators"][0]["cnpj"] == "01222333000128" and by["PR-ZZF"]["operators"][0]["zero_restored"]
    assert by["PU-ZZE"]["operators"] == []  # the short operator code '1234' is not a company identifier
    assert by["PT-ZZG"]["owners"][0]["cnpj_valid"] is False


@pytest.mark.parametrize(("mark", "status"), [("PR-ZZA", "registered"), ("PS-ZZD", "reserved"), ("PU-ZZE", "cancelled"),
                                              ("PT-ZZG", "provisional")])
def test_registration_status(mark, status):
    by = {r["mark_display"]: r for r in A.parse_anac_rab(fx("ok.csv"))["rows"]}
    assert by[mark]["registration"]["status"] == status
    if status == "cancelled":
        assert by[mark]["registration"]["since"] == "2019-03-15" and by[mark]["registration"]["reason"] == "PERECIMENTO"


def test_validation_refuses_bad_copies(tmp_path):
    assert A.anac_problem(fx("ok.csv"), min_rows=1) == ""
    assert "too few rows" in A.anac_problem(fx("ok.csv"))  # the production floor
    assert "truncated" in A.anac_problem(fx("truncated.csv"), min_rows=1)
    assert "preamble" in A.anac_problem(fx("no_preamble.csv"), min_rows=1)
    assert "HTML" in A.anac_problem(b"<!DOCTYPE html><html><body>maintenance</body></html>\n", min_rows=1)
    cut = tmp_path / "rab.csv"
    cut.write_bytes(fx("truncated.csv"))
    with pytest.raises(ValueError, match="truncated"):
        A.validate_anac_rab(cut)


def test_truncated_copy_drops_the_cut_row():
    parsed = A.parse_anac_rab(fx("truncated.csv"))
    assert "truncated (no final newline)" in parsed["errors"] and len(parsed["rows"]) == 6


def test_header_drift_gives_no_rows():
    body = fx("ok.csv").replace(b'"DS_GRAVAME"', b'"GRAVAME"')
    parsed = A.parse_anac_rab(body)
    assert not parsed["rows"] and "schema drift" in parsed["errors"][0]


@pytest.mark.parametrize(("value", "expected"), [
    ("mark:PT-ZZB", ("mark", "PTZZB")), ("tail: ptzzb", ("mark", "PTZZB")), ("rab:PR-ZZA", ("mark", "PRZZA")),
    ("cnpj:11.444.777/0001-61", ("cnpj", "11444777000161")), ("company:Exemplo Agricola S.A.", ("company", "Exemplo Agricola S.A.")),
    ("PTZZB", None), ("mark:N12345", None), ("mark:PX-ABC", None), ("cnpj:11.444.777/0001-00", None), ("person:Fulano", None),
])
def test_typed_queries_only(value, expected):
    assert A.parse_typed_query(value) == expected


def test_dataset_registration():
    reg = DATASETS[A.DATASET]
    assert reg["url"] == A.ANAC_URL and reg["source"] == "anac.rab" and reg["large"] is True and reg["terms_class"] == "open"


# ======================================================================================
# the module (FC3, FC4)
# ======================================================================================


def test_mark_lookup_gives_model_status_and_company_pivots():
    install()
    res = run("keyword:mark:PR-ZZA")
    assert res.status is Status.OK
    ac = res.attributes["aircraft"][0]
    assert ac["mark"] == "PR-ZZA" and ac["model"] == "172S" and ac["registration"] == "registered"
    assert ac["owners"] == ["EMPRESA EXEMPLO TAXI AEREO LTDA"] and ac["lien"] == "ALIENAÇÃO FIDUCIÁRIA"
    assert res.attributes["anac_rab_date"] == "2026-11-26"
    pivots = {(p.entity.value, p.relation) for p in res.pivots}
    assert pivots == {("11222333000181", "aircraft_owner"), ("11222333000181", "aircraft_operator")}
    assert all(p.expand is False for p in res.pivots)
    f = res.findings[0]
    assert f.title == "Aircraft registration in the ANAC RAB" and "RAB as of 2026-11-26" in f.description
    assert any(c["name"] == A.DATASET for c in res.datasets)


def test_person_owned_aircraft_shows_no_person():
    install()
    res = run("keyword:mark:PT-ZZB")
    assert res.status is Status.OK
    assert res.attributes["aircraft"][0]["owners"] == []
    assert "person or undisclosed owner withheld" in res.findings[0].description
    assert {p.entity.value for p in res.pivots} == {"11444777000161"}
    text = blob(res)
    for needle in PERSON_STRINGS:
        assert needle not in text


def test_cnpj_lookup_exact_and_root():
    install()
    res = run("cnpj:22.333.444/0001-81")
    assert res.status is Status.OK and res.attributes["aircraft"][0]["mark"] == "PU-ZZE"
    assert res.attributes["aircraft"][0]["registration"] == "cancelled"
    branch = run("cnpj:11.222.333/0002-62")  # another establishment of the PR-ZZA owner
    assert branch.status is Status.OK and branch.attributes["aircraft"][0]["match"] == "root"
    assert branch.findings[0].confidence_label == "possible" and "CNPJ root" in branch.findings[0].description


def test_zero_restored_operator_is_found_by_cnpj():
    install()
    res = run("keyword:cnpj:01.222.333/0001-28")
    assert res.status is Status.OK and res.attributes["aircraft"][0]["mark"] == "PR-ZZF"


def test_exact_company_name_only():
    install()
    res = run("company_name:Exemplo Agricola SA")
    assert res.status is Status.OK and res.attributes["aircraft"][0]["mark"] == "PU-ZZE"
    assert run("company_name:Exemplo Agricola Industrial").status is Status.EMPTY  # never fuzzy
    assert run("company_name:Fulano de Tal").status is Status.EMPTY  # persons were dropped at import


def test_bare_tokens_and_untyped_keywords_are_not_applicable():
    install()
    for value in ("keyword:PRZZA", "keyword:PR-ZZA", "keyword:person:FULANO DE TAL"):
        res = run(value)
        assert res.status is Status.SKIPPED and res.reason_code == "not_applicable"


def test_unknown_mark_is_empty_with_the_dataset_date():
    install()
    res = run("keyword:mark:PP-AAA")
    assert res.status is Status.EMPTY and "RAB as of 2026-11-26" in res.error


def test_missing_dataset_is_unavailable_never_empty():
    res = run("keyword:mark:PR-ZZA")
    assert res.status is Status.UNAVAILABLE and res.reason_code == "dataset"
    assert "v3lum data update anac_rab_dados_aeronaves.csv" in res.error


def test_unusable_copy_is_an_error_never_empty():
    install(fx("ok.csv").replace(b'"MARCAS"', b'"MARCA"'))
    res = run("keyword:mark:PR-ZZA")
    assert res.status is Status.ERROR and "could not verify" in res.error


def test_stale_copy_is_flagged():
    install(age_days=10)
    res = run("keyword:mark:PR-ZZA")
    assert "older than 7 days" in res.attributes["dataset_age"][0]
