"""Offline tests for P235 ``cnae_tables`` (batch p2-G10-1): bundled IBGE/RFB tables, the sensitive-division
map, the LGPD floor for division 94 and the `v3lum data update cnae` refresher validation.

Fixtures in tests/fixtures/cnae_tables/ are real IBGE CNAE API answers captured 2026-11-25/26 (one subclass,
an 18-row sample of the full tree, the empty list for an unknown code), one truncated body and one
synthetic error object.
"""

from __future__ import annotations

import json
from pathlib import Path
from types import SimpleNamespace

import pytest

from tests.fakes import FakeHttp, module_fixture, run_module
from v3lum.core.datasets import DATASETS, DataStore
from v3lum.core.models import Status
from v3lum.modules.brazil_public_data import cnae_tables as ct
from v3lum.modules.brazil_public_data.cnae_tables import CnaeTables

DIVISION_94 = ["9411100", "9412001", "9412099", "9420100", "9430800", "9491000", "9492800", "9493600", "9499500", "9412000"]
PERSON_KINDS = ["qsa_partner", "natural_person", "mei_owner", "person_name", "person", "cpf"]


# ------------------------------------------------------------------ cond 1: bundled data with provenance
@pytest.mark.parametrize("name", [ct.BUNDLED_CNAE, ct.BUNDLED_NATUREZA, ct.BUNDLED_CODES])
def test_bundled_tables_carry_source_version_and_retrieval_date(name):
    data = DataStore.bundled_json(name)
    assert data["source"].startswith("https://") and data["version"] and data["retrieved"] == "2026-11-26"
    assert data["attribution"]


def test_bundled_cnae_tree_is_complete():
    t = ct.load_tables()
    counts = t.cnae["counts"]
    assert counts["subclasses"] == 1332 and counts["divisions"] == 87 and counts["sections"] == 21
    assert counts["rfb_only"] == 27  # legacy codes still found in CNPJ records


def test_official_natureza_table_and_lgpd_sensitive_codes():
    t = ct.load_tables()
    assert len(t.natureza["codes"]) == 92
    assert ct.natureza_label("2062") == "Sociedade Empresária Limitada"
    assert ct.natureza_label("203-8") == "Sociedade de Economia Mista"
    assert ct.natureza_label("9999") is None
    for code in ("3131", "3220", "3255", "3263", "3271", "3280", "3298", "4090"):
        assert ct.is_lgpd_sensitive_natureza(code)
    assert not ct.is_lgpd_sensitive_natureza("2062")


# ------------------------------------------------------------------ cond 6: subclasses -> descriptions and divisions
@pytest.mark.parametrize(
    ("code", "label", "division", "section", "tags"),
    [
        ("6422-1/00", "BANCOS MÚLTIPLOS, COM CARTEIRA COMERCIAL", "64", "K", ["financial_insurance"]),
        ("6619399", "OUTRAS ATIVIDADES AUXILIARES DOS SERVIÇOS FINANCEIROS NÃO ESPECIFICADAS ANTERIORMENTE", "66", "K",
         ["financial_insurance", "payments_crypto"]),
        ("8011-1/01", "ATIVIDADES DE VIGILÂNCIA E SEGURANÇA PRIVADA", "80", "N", ["private_security"]),
        ("9200399", "EXPLORAÇÃO DE JOGOS DE AZAR E APOSTAS NÃO ESPECIFICADOS ANTERIORMENTE", "92", "R", ["gambling_betting"]),
        ("4929902", "TRANSPORTE RODOVIÁRIO COLETIVO DE PASSAGEIROS, SOB REGIME DE FRETAMENTO, INTERMUNICIPAL, INTERESTADUAL E INTERNACIONAL",
         "49", "H", []),
        ("111301", "CULTIVO DE ARROZ", "01", "A", []),  # an int-like code that lost its leading zero
    ],
)
def test_subclasses_map_to_descriptions_and_divisions(code, label, division, section, tags):
    d = ct.cnae_describe(code)
    assert d["label"] == label and d["division"] == division and d["section"] == section
    assert d["sector_tags"] == tags and d["known"] == "ibge"
    assert d["code_formatted"] == ct.format_cnae(code)


def test_ibge_fixture_agrees_with_the_bundled_table():
    sub = module_fixture("cnae_tables", "ibge_subclass_6422100.json")
    d = ct.cnae_describe(sub["id"])
    assert d["label"] == sub["descricao"] and d["class"] == sub["classe"]["id"]
    assert d["division_label"] == sub["classe"]["grupo"]["divisao"]["descricao"]


def test_rfb_only_legacy_code_is_described():
    d = ct.cnae_describe("8020000")
    assert d["known"] == "rfb_only" and d["division"] == "80" and d["sector_tags"] == ["private_security"]


# ------------------------------------------------------------------ cond 4: sensitive map = business-risk sectors only
def test_sensitive_map_covers_business_risk_sectors_only():
    sens = DataStore.bundled_json(ct.BUNDLED_SENSITIVE)
    divisions = {d for spec in sens["sectors"].values() for d in spec["divisions"]}
    assert divisions == {"64", "65", "66", "80", "92"}
    assert "84" not in divisions and "94" not in divisions
    assert sens["reviewer"] and sens["reviewed_at"] and sens["version"]
    for code in sens["excluded"]:
        assert ct.sector_tags(code) == []  # considered and left out (generic activities)


def test_sector_tags_are_info_context_never_risk():
    for tag in ct.sector_tags("6438701"):
        assert tag["kind"] == "info" and tag["risk_signal"] is False and tag["score_effect"] == 0
    assert {t["tag"] for t in ct.sector_tags("6438701")} == {"financial_insurance", "payments_crypto"}


# ------------------------------------------------------------------ cond 5: LGPD floor (division 94)
@pytest.mark.parametrize("code", DIVISION_94)
def test_division_94_never_produces_a_risk_tag(code):
    assert ct.is_lgpd_protected_cnae(code)
    assert ct.sector_tags(code) == []
    d = ct.cnae_describe(code)
    assert d["lgpd_protected"] is True and d["sector_tags"] == []
    company = ct.cnae_attributes(code, "company")
    assert [a["name"] for a in company] == ["cnae"] and company[0]["lgpd_protected"] is True
    assert all(a["risk_signal"] is False for a in company)


@pytest.mark.parametrize("code", DIVISION_94)
@pytest.mark.parametrize("kind", PERSON_KINDS)
def test_division_94_is_never_a_partner_attribute(code, kind):
    assert ct.cnae_attributes(code, kind) == []


def test_no_company_activity_is_copied_onto_a_person():
    assert ct.cnae_attributes("6422100", "qsa_partner") == []
    assert [a["name"] for a in ct.cnae_attributes("6422100", "company")] == ["cnae", "sector"]


# ------------------------------------------------------------------ cond 3: CNPJ card labels from codes
def test_card_labels_from_codes_only():
    record = {"cnae_fiscal": 6422100, "codigo_natureza_juridica": 2038, "codigo_porte": 5, "situacao_cadastral": 2}
    labels = ct.cnpj_card_labels(record)
    assert labels["cnae"] == "6422-1/00 BANCOS MÚLTIPLOS, COM CARTEIRA COMERCIAL"
    assert labels["natureza"] == "2038 Sociedade de Economia Mista"
    assert labels["porte"] == "Demais" and labels["situacao"] == "Ativa"
    assert labels["sector_tags"] == ["financial_insurance"] and labels["lgpd_sensitive"] is False


def test_provider_labels_win_and_cnpj_lookup_shapes_are_accepted():
    record = {"cnae": {"code": "6422100", "label": "Bancos multiplos, com carteira comercial"},
              "legal_nature": {"code": "2038", "label": "Sociedade de Economia Mista"}, "company_size": "DEMAIS", "status": "ATIVA"}
    labels = ct.cnpj_card_labels(record)
    assert labels["cnae"] == "6422-1/00 Bancos multiplos, com carteira comercial"
    assert labels["natureza"] == "2038 Sociedade de Economia Mista" and labels["porte"] == "Demais" and labels["situacao"] == "Ativa"


def test_card_labels_flag_affiliation_revealing_legal_nature():
    labels = ct.cnpj_card_labels({"cnae_fiscal": "9420100", "codigo_natureza_juridica": "3131"})
    assert labels["lgpd_sensitive"] is True and labels["sector_tags"] == []


@pytest.mark.parametrize(("value", "label"), [("1", "Nula"), ("08", "Baixada"), ("INAPTA", "Inapta"), ("99", None)])
def test_situacao_labels(value, label):
    assert ct.situacao_label(value) == label


@pytest.mark.parametrize(("value", "label"), [("01", "Micro empresa"), ("EPP", "Empresa de pequeno porte"), ("ME", "Micro empresa"), ("0", "Não informado")])
def test_porte_labels(value, label):
    assert ct.porte_label(value) == label


# ------------------------------------------------------------------ cond 2: the refresher
def test_refresher_dataset_is_registered_for_data_update_only():
    spec = DATASETS["cnae"]
    assert spec["source"] == "ibge.cnae" and spec["terms_class"] == "open" and spec["url"] == ct.IBGE_CNAE_SUBCLASSES_URL
    assert CnaeTables.disclosure == "none" and CnaeTables.hosts == ()


def test_refresher_validation_rejects_bad_answers():
    sample = module_fixture("cnae_tables", "ibge_subclasses_sample.json")
    assert ct.validate_cnae_tree(sample) and "only 18 valid subclasses" in ct.validate_cnae_tree(sample)
    assert ct.validate_cnae_tree(sample, min_subclasses=18) is None
    assert ct.validate_cnae_tree(module_fixture("cnae_tables", "ibge_error_object_synthetic.json")).startswith("cnae refresh: expected a list")
    assert ct.validate_cnae_tree(module_fixture("cnae_tables", "ibge_subclass_unknown_empty.json")) is not None
    with pytest.raises(ValueError):
        json.loads(module_fixture("cnae_tables", "ibge_subclasses_truncated.txt"))


def test_build_table_from_the_ibge_tree():
    table = ct.build_cnae_table(module_fixture("cnae_tables", "ibge_subclasses_sample.json"), "2026-11-26")
    assert table["counts"]["subclasses"] == 18 and table["subclasses"]["9492800"]["division"] == "94"
    assert table["source"] == ct.IBGE_CNAE_SUBCLASSES_URL and table["retrieved"] == "2026-11-26"


def test_a_valid_local_refresh_wins_and_an_invalid_one_is_ignored(tmp_path: Path):
    full = DataStore.bundled_json(ct.BUNDLED_CNAE)
    tree = []
    for code, sub in full["subclasses"].items():
        tree.append({"id": code, "descricao": sub["label"] + (" (REFRESHED)" if code == "6422100" else ""),
                     "classe": {"id": sub["class"], "descricao": full["classes"].get(sub["class"]),
                                "grupo": {"id": sub["group"], "descricao": full["groups"].get(sub["group"]),
                                          "divisao": {"id": sub["division"], "descricao": full["divisions"].get(sub["division"]),
                                                      "secao": {"id": sub["section"], "descricao": full["sections"].get(sub["section"])}}}}})
    good = tmp_path / "cnae.json"
    good.write_text(json.dumps(tree), encoding="utf-8")

    def view(path: Path, sha: str) -> SimpleNamespace:
        info = SimpleNamespace(present=True, sha256=sha, fetched_at="2026-11-27T00:00:00Z", licence="open")
        return SimpleNamespace(info=lambda name: info, store=SimpleNamespace(path=lambda name: path), used=[])

    refreshed = ct.load_tables(view(good, "a" * 64))
    assert ct.cnae_describe("6422100", refreshed)["label"].endswith("(REFRESHED)")
    bad = tmp_path / "bad.json"
    bad.write_text('{"message": "Erro interno"}', encoding="utf-8")
    assert ct.cnae_describe("6422100", ct.load_tables(view(bad, "b" * 64)))["label"] == "BANCOS MÚLTIPLOS, COM CARTEIRA COMERCIAL"


# ------------------------------------------------------------------ the module (offline, no network)
def test_module_describes_a_cnae_code_offline():
    http = FakeHttp()  # no route: any request would fail the test
    res = run_module(CnaeTables, "keyword:6422-1/00", http)
    assert res.status is Status.OK and not http.calls
    assert res.attributes["cnae_detail"]["label"] == "BANCOS MÚLTIPLOS, COM CARTEIRA COMERCIAL"
    assert res.attributes["sector_tags"][0]["tag"] == "financial_insurance" and res.attributes["sector_tags"][0]["risk_signal"] is False
    assert res.attributes["cnae_lgpd_protected"] is False
    assert not res.findings and not res.pivots


def test_module_division_94_has_no_sector_tag_and_no_finding():
    res = run_module(CnaeTables, "keyword:cnae 9492800", FakeHttp())
    assert res.status is Status.OK and "sector_tags" not in res.attributes
    assert res.attributes["cnae_lgpd_protected"] is True and not res.findings


def test_module_description_search():
    res = run_module(CnaeTables, "keyword:cnae: apostas", FakeHttp())
    assert res.status is Status.OK
    assert {m["code_formatted"] for m in res.attributes["cnae_matches"]} == {"9200-3/02", "9200-3/99"}


def test_module_legal_nature_code():
    res = run_module(CnaeTables, "keyword:natureza juridica 2062", FakeHttp())
    assert res.status is Status.OK and res.attributes["legal_nature"]["label"] == "Sociedade Empresária Limitada"


def test_module_unknown_code_is_empty_and_other_keywords_are_not_applicable():
    assert run_module(CnaeTables, "keyword:9999999", FakeHttp()).status is Status.EMPTY
    res = run_module(CnaeTables, "keyword:banco do brasil", FakeHttp())
    assert res.status is Status.SKIPPED and res.reason_code == "not_applicable"
