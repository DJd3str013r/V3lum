"""djen_court_communications (P362): CNJ DJEN / Comunica PJe court communications.

Fixtures in tests/fixtures/djen_court_communications/ (batch p2-G10-3 prep, 2026-11-26):

* ``geo_block_403.http.json``: the live, byte-exact CloudFront 'configured to block access from your country'
  page of comunicaapi.pje.jus.br from a non-Brazilian datacenter egress (identical to the research capture);
* ``portal_reset.http.json``: comunica.pje.jus.br reset the connection (live);
* ``cloudfront_403_generic_synthetic.http.json``: a CloudFront 403 WITHOUT the country phrase (synthetic);
* ``ok_synthetic_unverified.json`` / ``empty_synthetic_unverified.json``: SYNTHETIC, SHAPE UNVERIFIED - the
  P362 build gate (FC1) requires replacing them with captures from the team's Brazilian egress before the
  automated query is enabled. Party and lawyer names in them are documentation values that must be dropped.
"""

from __future__ import annotations

import datetime as dt
import json

from tests.fakes import FakeHttp, module_fixture, run_module
from v3lum.core import links
from v3lum.core.context import ScanOptions
from v3lum.core.entities import Entity
from v3lum.core.entities import EntityType as T
from v3lum.core.http import Response, classify
from v3lum.core.models import Status
from v3lum.modules.brazil_public_data import djen_court_communications as D
from v3lum.modules.brazil_public_data.djen_court_communications import DjenCourtCommunications

BB = "00000000000191"


def fx(name: str):
    return module_fixture("djen_court_communications", name)


def response(name: str) -> Response:
    r = fx(name)["response"]
    return Response(r["status"], fx(name)["request"].split(" ", 1)[1], r["headers"], r["body"].encode("utf-8"))


# ======================================================================================
# FC1/FC2/FC3: build gate, legal floor, egress
# ======================================================================================


def test_no_request_before_the_brazilian_capture_only_the_manual_link():
    http = FakeHttp()  # no route: any request would fail the test
    res = run_module(DjenCourtCommunications, f"cnpj:{BB}", http)
    assert http.urls() == []
    assert res.status is Status.SKIPPED and res.reason_code == "config"
    assert "Brazilian egress" in res.error
    assert ("Comunica PJe (DJEN) - manual search", D.DJEN_MANUAL_LINK) in res.links
    assert "no communications" not in res.error


def test_metadata_matches_the_council_decision():
    C = DjenCourtCommunications
    assert C.terms == "unknown" and C.default_enabled is False
    assert C.requires_egress == frozenset({"BR"}) and C.max_requests == 0
    assert C.trust_tier == "trusted" and C.opsec.label == "passive"
    assert C.hosts == ("comunicaapi.pje.jus.br",) and C.sources == ("pje.djen_api",)
    assert links.validate_manual_link(C.manual_link) == []
    rendered = links.render_manual(C.manual_link, Entity.make(T.CNPJ, BB), include_privacy=True)
    assert rendered is not None and rendered.url == D.DJEN_MANUAL_LINK and BB not in rendered.url  # no value disclosed


def test_live_geo_block_is_blocked_geo_block_never_empty():
    c = classify(response("geo_block_403.http.json"), keyless=True)
    assert c is not None and c.status == "blocked" and c.reason_code == "geo_block"


def test_generic_cloudfront_403_is_blocked_never_empty():
    c = classify(response("cloudfront_403_generic_synthetic.http.json"), keyless=True)
    assert c is not None and c.status == "blocked" and c.reason_code in ("challenge", "geo_block")  # the core picks the code (P321)
    assert fx("portal_reset.http.json")["response"] is None  # the portal reset: could not verify, never 'no communications'


# ======================================================================================
# FC4: query policy
# ======================================================================================


def test_query_plan_for_cnpj_seeds_and_names():
    plan = D.query_plan("cnpj", BB, razao_social="BANCO DO BRASIL SA")
    assert plan == {"queries": ["00.000.000/0001-91", "BANCO DO BRASIL SA"], "skip": None}
    assert D.query_plan("cnpj", BB, is_seed=False)["skip"]["reason_code"] == "not_applicable"
    assert D.query_plan("cnpj", "00000000000192")["skip"]["reason"] == "invalid CNPJ"
    assert D.query_plan("company_name", "Empresa Exemplo Ltda")["queries"] == ["Empresa Exemplo Ltda"]
    assert D.date_window(dt.date(2026, 11, 26)) == ("2021-11-26", "2026-11-26")
    url = D.djen_url("00.000.000/0001-91", "2021-11-26", "2026-11-26")
    assert url.startswith(D.DJEN_API + "?texto=00.000.000%2F0001-91") and "itensPorPagina=20" in url


def test_person_names_need_due_diligence_and_screening_is_refused():
    assert D.query_plan("person_name", "Pessoa Exemplo")["skip"]["reason_code"] == "privacy"
    assert D.query_plan("person_name", "Pessoa Exemplo", purpose="due diligence of supplier X")["queries"] == ["Pessoa Exemplo"]
    for purpose in ("triagem de candidatos a vaga", "background check of new employees", "admissional", "Contratação de funcionários"):
        assert D.screening_purpose(purpose)
        assert D.query_plan("cnpj", BB, purpose=purpose)["skip"]["reason_code"] == "privacy"
    assert not D.screening_purpose("due diligence de fornecedor")


def test_module_refuses_screening_purposes_and_pivots():
    res = run_module(DjenCourtCommunications, f"cnpj:{BB}", FakeHttp(), options=ScanOptions(purpose="background check of employees"))
    assert res.status is Status.SKIPPED and res.reason_code == "privacy"
    res = run_module(DjenCourtCommunications, "company_name:EMPRESA EXEMPLO LTDA", FakeHttp(), is_seed=False, depth=1)
    assert res.status is Status.SKIPPED and res.reason_code == "not_applicable"


# ======================================================================================
# FC5/FC6: parser and summary (synthetic, shape unverified)
# ======================================================================================


def test_parse_keeps_minimal_fields_and_drops_parties():
    parsed = D.parse_djen(fx("ok_synthetic_unverified.json"), anchors=["00.000.000/0001-91"])
    assert parsed["ok"] and parsed["count"] == 4 and len(parsed["items"]) == 4
    text = json.dumps(parsed, ensure_ascii=False)
    assert "PESSOA EXEMPLO OITO" not in text and "PESSOA EXEMPLO NOVE" not in text and "numero_oab" not in text
    assert all(set(i) == {"court", "date", "type", "class_name", "litigation_class", "cnj", "organ", "excerpt", "link"} for i in parsed["items"])
    assert all(i["excerpt"] is None or len(i["excerpt"]) <= 300 for i in parsed["items"])
    first = parsed["items"][0]
    assert first["cnj"] == "0000001-92.2026.5.02.0001" and first["litigation_class"] == "trabalhista" and first["court"] == "TRT2"
    by_class = [i["litigation_class"] for i in parsed["items"]]
    assert by_class == ["trabalhista", "consumidor", "execucao_fiscal", "criminal"]
    assert parsed["items"][1]["cnj"] == "0700055-10.2018.8.01.0022"  # the bare 20 digits are parsed
    assert parsed["items"][2]["cnj"] is None and parsed["items"][2]["date"] == "2026-08-15"


def test_summary_counts_recent_and_cnj_numbers():
    summary = D.djen_summary(D.parse_djen(fx("ok_synthetic_unverified.json")))
    assert summary["by_class"] == {"trabalhista": 1, "consumidor": 1, "execucao_fiscal": 1, "criminal": 1}
    assert summary["by_court"]["TRT2"] == 1 and len(summary["recent"]) == 4
    assert summary["recent"][0]["date"] == "2026-11-10"
    assert summary["cnj_numbers"] == ["0000001-92.2026.5.02.0001", "0700055-10.2018.8.01.0022"]


def test_empty_and_error_bodies():
    empty = D.parse_djen(fx("empty_synthetic_unverified.json"))
    assert empty["ok"] and empty["items"] == []
    assert D.parse_djen({"status": "error", "message": "x"})["error"].startswith("status 'error'")
    assert D.parse_djen(["x"])["ok"] is False and D.parse_djen({"foo": 1})["error"] == "no item list"


def test_litigation_classes():
    assert D.classify_litigation("Reclamação Trabalhista") == "trabalhista"
    assert D.classify_litigation("Recuperação Judicial") == "falencia_recuperacao"
    assert D.classify_litigation("Ação Civil Pública") == "acao_civil_publica"
    assert D.classify_litigation("Procedimento Comum", "07000551020188010022") == "civel"
    assert D.classify_litigation("", None) == "outro"
