"""cvm_person_registry (P360 FC9): CVM natural-person registries, explicit due diligence only.

Fixtures in tests/fixtures/cvm_person_registry/ are SYNTHETIC rows under the real headers of
cad_adm_cart_pf.csv and cad_consultor_vlmob_pf.csv ('PESSOA EXEMPLO ...' names; the CPF-shaped digits are
invalid check-digit values used only to prove they are stripped). The real files carry no CPF column.
"""

from __future__ import annotations

import json

import pytest

from tests.fakes import FIXTURES, FakeHttp, make_runtime, run_module
from v3lum import paths
from v3lum.core import module as modreg
from v3lum.core.context import ScanOptions
from v3lum.core.models import Status
from v3lum.modules.brazil_public_data import cvm_registries as C
from v3lum.modules.brazil_public_data.cvm_person_registry import CvmPersonRegistry

FIX = FIXTURES / "cvm_person_registry"
PURPOSE = "due diligence of a portfolio manager before onboarding (ticket DD-0001)"


def install(*, consultor: bool = True) -> None:
    ds = paths.datasets_dir()
    (ds / "cvm_adm_cart_pf.csv").write_bytes((FIX / "adm_cart_pf_synthetic.csv").read_bytes())
    if consultor:
        (ds / "cvm_consultor_vlmob_pf.csv").write_bytes((FIX / "consultor_pf_synthetic.csv").read_bytes())


def run(value: str, *, purpose: str = PURPOSE, http: FakeHttp | None = None, **kw):
    kw.setdefault("runtime", make_runtime(http or FakeHttp()))  # no routes: a download attempt fails the test
    return run_module(CvmPersonRegistry, value, options=ScanOptions(purpose=purpose), **kw)


def test_declared_as_explicit_due_diligence_only():
    cls = modreg.get_module("cvm_person_registry")
    assert cls.default_enabled is False and cls.run_on == "seeds" and cls.disclosure == "none"
    assert cls.sources == ("cvm.cvm_person_registry_pf",) and cls.max_pivots == 0


def test_exact_full_name_gives_possible_context_only_hits():
    install()
    http = FakeHttp()
    res = run("person_name:Pessoa Exemplo Um", http=http)
    assert res.status is Status.OK and not res.pivots
    (reg,) = res.attributes["cvm_person_registrations"]
    assert reg == {"registry": "adm_cart_pf", "segment": "Administrador de Carteira (pessoa natural)", "category": "Gestor de Carteira",
                   "status": "active", "status_since": "2015-03-02"}
    (finding,) = res.findings
    assert finding.confidence_label.value == "possible" and finding.severity.label == "info"
    assert "context_only" in finding.tags and "does not prove identity" in finding.description
    assert res.source_statuses["cvm.cvm_person_registry_pf"]["status"] == "ok"
    assert {d["name"] for d in res.datasets} == {"cvm_adm_cart_pf.csv", "cvm_consultor_vlmob_pf.csv"}
    assert http.calls == []


def test_cpf_digits_are_stripped_from_names_and_never_shown():
    install()
    res = run("person_name:Pessoa Exemplo Quatro")  # the source row carried CPF-shaped digits after the name
    assert res.status is Status.OK
    dump = json.dumps([res.attributes, [f.to_dict() for f in res.findings], res.raw], default=str)
    assert "12345678900" not in dump and "123.456.789" not in dump
    rows = C.parse_cvm_csv((FIX / "consultor_pf_synthetic.csv").read_bytes(), "consultor_pf").rows
    assert {r["name"] for r in rows} == {"PESSOA EXEMPLO CINCO", "PESSOA EXEMPLO SEIS", "PESSOA EXEMPLO SETE"}
    assert all("cpf_masked" not in r and "SITE_ADMIN" not in r for r in rows)  # no CPF column; a person's website is not kept


def test_without_a_recorded_purpose_nothing_is_matched():
    install()
    res = run("person_name:Pessoa Exemplo Um", purpose="")
    assert res.status is Status.SKIPPED and res.reason_code == "privacy" and "purpose" in res.error


@pytest.mark.parametrize(
    ("value", "why"),
    [("person_name:Pessoa Exemplo 123.456.789-09", "CPF"), ("person_name:Exemplo", "two words")],
)
def test_cpf_and_single_words_are_never_keys(value, why):
    install()
    res = run(value)
    assert res.status is Status.SKIPPED and res.reason_code == "not_applicable" and why in res.error


def test_no_match_is_empty_and_missing_registries_are_reported():
    install(consultor=False)
    res = run("person_name:Pessoa Exemplo Nove")
    assert res.status is Status.EMPTY and not res.findings
    st = res.source_statuses["cvm.cvm_person_registry_pf"]
    assert "cvm_consultor_vlmob_pf.csv not installed" in st["reason"]


def test_missing_datasets_are_unavailable_and_never_downloaded():
    http = FakeHttp()
    res = run("person_name:Pessoa Exemplo Um", http=http)
    assert res.status is Status.UNAVAILABLE and res.reason_code == "dataset" and "v3lum data update" in res.error
    assert http.calls == []


def test_corrupt_copy_fails_closed():
    (paths.datasets_dir() / "cvm_adm_cart_pf.csv").write_bytes(b"<!DOCTYPE html><html><body>erro</body></html>")
    res = run("person_name:Pessoa Exemplo Um")
    assert res.status is Status.UNAVAILABLE and res.reason_code == "dataset" and "HTML" in res.error


def test_due_diligence_helper_gate():
    rows = C.parse_cvm_csv((FIX / "adm_cart_pf_synthetic.csv").read_bytes(), "adm_cart_pf").rows
    assert C.due_diligence_match("Pessoa Exemplo Um", rows, purpose="")["ok"] is False
    hits = C.due_diligence_match("PESSOA EXEMPLO TRÊS", rows, purpose=PURPOSE)["matches"]
    assert [h["status"] for h in hits] == ["suspended"]
