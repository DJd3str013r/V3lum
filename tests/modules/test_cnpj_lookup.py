"""Offline tests of cnpj_lookup (P236) over trimmed real captures in tests/fixtures/cnpj_lookup/.

Live captures (2026-11-26) of BrasilAPI, Minha Receita, Querido Diario and publica.cnpj.ws for the
public registration 00.000.000/0001-91 (Banco do Brasil), the RFB documentation alphanumeric CNPJ
12.ABC.345/01DE-35 and a DV-valid unregistered CNPJ; persons are scrubbed (FULANO DE TAL...), 429 and
challenge answers are synthetic (never provoked live).
"""

from __future__ import annotations

import copy
import json
import re

import pytest

from tests.fakes import FakeHttp, make_ctx, module_fixture, run_module
from v3lum.core.http import NetworkError
from v3lum.core.models import Status
from v3lum.core.providers import parse_marker
from v3lum.modules.brazil_public_data import cnpj_lookup as mod
from v3lum.modules.brazil_public_data.cnpj_lookup import CnpjLookup

BB = "00000000000191"
ALNUM = "12ABC34501DE35"
UNKNOWN = "98765012000101"
BRASILAPI = "https://brasilapi.com.br/api/cnpj/v1/{}"
MINHARECEITA = "https://minhareceita.org/{}"
QD_INFO = "https://api.queridodiario.org.br/company/info/{}"
QD_PARTNERS = "https://api.queridodiario.org.br/company/partners/{}"
CNPJWS = "https://publica.cnpj.ws/cnpj/{}"
SNAPSHOT = "https://minhareceita.org/updated"
RDAP = "https://rdap.registro.br/domain/{}"


def fx(name: str):
    return module_fixture("cnpj_lookup", name)


def add_exchange(http: FakeHttp, url: str, name: str) -> FakeHttp:
    """Serve a recorded exchange (tests/fixtures/cnpj_lookup/<name>.http.json) at ``url``."""
    ex = fx(name)
    resp = ex["response"]
    body = resp["body"]
    headers = {k: v for k, v in (resp.get("headers") or {}).items() if k.lower() != "content-length"}
    if isinstance(body, (dict, list)):
        return http.add("GET", url, status=resp["status"], json=body, headers=headers)
    return http.add("GET", url, status=resp["status"], text=str(body), headers=headers)


def snapshot(http: FakeHttp) -> FakeHttp:
    return http.add("GET", SNAPSHOT, json=fx("minhareceita_updated.json"))


def pivots(res, relation=None):
    return {(p.entity.type.value, p.entity.value): p for p in res.pivots if relation is None or p.relation == relation}


def dump(res) -> str:
    return json.dumps({"r": res.to_dict(), "raw": res.raw, "f": [f.to_dict() for f in res.findings]}, ensure_ascii=False, default=str)


# --------------------------------------------------------------------------------------
# happy path: BrasilAPI answers, the chain stops there
# --------------------------------------------------------------------------------------


def test_brasilapi_record_card_attributes_and_pivots():
    http = snapshot(FakeHttp().add("GET", BRASILAPI.format(BB), json=fx("brasilapi_ok.json")))
    res = run_module(CnpjLookup, f"cnpj:{BB}", http)
    assert res.status is Status.OK
    a = res.attributes
    assert a["legal_name"] == "BANCO DO BRASIL SA"
    assert a["trade_name"] == "DIRECAO GERAL"
    assert a["status"] == "ATIVA" and a["status_date"] == "2005-11-03"
    assert a["opened"] == "1966-08-01"
    assert a["cnae"] == {"code": "6422100", "label": "Bancos múltiplos, com carteira comercial"}
    assert a["cnaes_secondary"][0]["code"] == "6499999"
    assert a["legal_nature"] == {"code": "2038", "label": "Sociedade de Economia Mista"}
    assert a["company_size"] == "DEMAIS"
    assert a["capital"] == 120000000000.0
    assert a["address_details"]["ibge_code"] == "5300108" and a["address_details"]["cep"] == "70040912"
    assert a["individual_entrepreneur"] is False
    assert a["rfb_snapshot"] == "2026-11"
    card = a["cnpj_card"]
    assert card["provider"] == "BrasilAPI" and card["data_date"] == "2026-11" and card["status_plain"] == "active"
    assert card["opening_date"] == "1966-08-01" and card["age_years"] > 60
    assert a["field_sources"]["razao_social"]["provider"] == "BrasilAPI"
    assert a["providers_pending_review"] == [
        {"provider": "OpenCNPJ", "host": "api.opencnpj.org", "reason": "pending terms review"},
        {"provider": "CNPJa open", "host": "open.cnpja.com", "reason": "pending terms review"},
        {"provider": "ReceitaWS", "host": "receitaws.com.br", "reason": "pending terms review"},
    ]
    # QSA: names as published, CPF only as masked by the RFB, age band only in the card
    qsa = a["qsa"]
    assert [p["name"] for p in qsa] == ["FULANO DE TAL", "BELTRANO DA SILVA", "CICLANO SOUZA"]
    assert qsa[0]["doc_as_given"] == "***123456**" and qsa[0]["age_band"] == "41-50"
    assert a["partners"] == ["FULANO DE TAL", "BELTRANO DA SILVA", "CICLANO SOUZA"]
    # pivots: legal name never expands; partners name-only, weak; registry phones never expand
    pv = pivots(res)
    legal = pv[("company_name", "BANCO DO BRASIL SA")]
    assert legal.relation == "legal_name" and legal.expand is False
    person = pv[("person_name", "FULANO DE TAL")]
    assert person.relation == "partner_of" and person.expand is False and person.confidence < 0.6
    assert "***" not in person.entity.value and "41" not in person.note
    phone = pv[("phone", "+556134939002")]
    assert phone.relation == "rfb_contact" and phone.expand is False and "accounting firm" in phone.note
    assert pv[("cep", "70040912")].expand is False
    assert res.source_statuses["brasilapi.cnpj"]["status"] == "ok"
    assert "minhareceita.cnpj" not in res.source_statuses  # the chain stopped at the first full record
    assert not res.findings  # ATIVA: no status finding, never an age finding
    http.assert_hosts_within(CnpjLookup)


def test_minha_receita_shares_the_parser():
    rec = mod.parse_minhareceita(fx("minhareceita_ok.json"))
    ref = mod.parse_brasilapi(fx("brasilapi_ok.json"))
    assert rec["provider"] == "minhareceita"
    assert {k: v for k, v in rec.items() if k != "provider"} == {k: v for k, v in ref.items() if k != "provider"}


# --------------------------------------------------------------------------------------
# fallback chain (cond 3) and per-provider coverage
# --------------------------------------------------------------------------------------


def test_rate_limited_brasilapi_falls_back_to_minha_receita_without_waiting():
    http = FakeHttp()
    add_exchange(http, BRASILAPI.format(BB), "brasilapi_rate_limited.http.json")
    http.add("GET", MINHARECEITA.format(BB), json=fx("minhareceita_ok.json"))
    snapshot(http)
    res = run_module(CnpjLookup, f"cnpj:{BB}", http)
    assert res.status is Status.OK
    assert res.source_statuses["brasilapi.cnpj"]["status"] == "rate_limited"
    assert res.source_statuses["minhareceita.cnpj"]["status"] == "ok"
    assert res.attributes["cnpj_card"]["provider"] == "Minha Receita"
    chain = res.attributes["provider_chain"]
    assert [(c["provider"], c["state"]) for c in chain] == [("BrasilAPI", "rate_limited"), ("Minha Receita", "ok")]
    # the 429 carried Retry-After: 30 - the chain never waits for it (retries=0)
    assert sum(1 for c in http.calls if c["url"] == BRASILAPI.format(BB)) == 1


def test_querido_diario_info_and_partners_when_the_relays_fail():
    http = FakeHttp()
    http.add("GET", BRASILAPI.format(BB), status=502, text="bad gateway")
    http.add("GET", MINHARECEITA.format(BB), status=503, text="unavailable")
    http.add("GET", QD_INFO.format(BB), json=fx("qd_info_ok.json"))
    http.add("GET", QD_PARTNERS.format(BB), json=fx("qd_partners_ok.json"))
    http.add("GET", RDAP.format("bb.com.br"), json=fx("rdap_registrobr_bb.json"))
    res = run_module(CnpjLookup, f"cnpj:{BB}", http)
    assert res.status is Status.OK
    a = res.attributes
    assert a["cnpj_card"]["provider"] == "Querido Diario" and a["cnpj_card"]["data_date"] is None
    assert a["rfb_emails"] == ["secex@bb.com.br"]
    assert a["capital"] == 90000023475.34
    assert [p["name"] for p in a["qsa"]][:2] == ["FULANO DE TAL", "BELTRANO DA SILVA"]
    assert a["qsa"][0]["age_band"] == "51-60"
    assert res.source_statuses["brasilapi.cnpj"]["status"] == "error"
    assert res.source_statuses["querido_diario.company"]["status"] == "ok"
    assert pivots(res)[("email", "secex@bb.com.br")].expand is False
    assert SNAPSHOT not in http.urls()  # the dump month is read only for BrasilAPI / Minha Receita records


def test_contact_domain_expands_only_when_registrobr_ties_it_to_the_same_root():
    body = dict(fx("brasilapi_ok.json"), email="SECEX@BB.COM.BR")
    http = snapshot(FakeHttp().add("GET", BRASILAPI.format(BB), json=body))
    http.add("GET", RDAP.format("bb.com.br"), json=fx("rdap_registrobr_bb.json"))
    res = run_module(CnpjLookup, f"cnpj:{BB}", http)
    pv = pivots(res)
    email = pv[("email", "secex@bb.com.br")]
    assert email.relation == "rfb_contact" and email.expand is False and email.confidence < 0.6
    dom = pv[("domain", "bb.com.br")]
    assert dom.relation == "rfb_contact_domain" and dom.expand is True and "same root" in dom.note
    assert res.source_statuses["registrobr.rdap"]["status"] == "ok"
    http.assert_hosts_within(CnpjLookup)


def test_contact_domain_of_another_company_stays_unexpanded():
    body = dict(fx("brasilapi_ok.json"), email="fiscal@contabil-exemplo.com.br")
    rdap = copy.deepcopy(fx("rdap_registrobr_bb.json"))
    rdap["ldhName"] = "contabil-exemplo.com.br"
    rdap["entities"][0]["handle"] = "11222333000181"
    rdap["entities"][0]["publicIds"][0]["identifier"] = "11.222.333/0001-81"
    http = snapshot(FakeHttp().add("GET", BRASILAPI.format(BB), json=body))
    http.add("GET", RDAP.format("contabil-exemplo.com.br"), json=rdap)
    res = run_module(CnpjLookup, f"cnpj:{BB}", http)
    dom = pivots(res)[("domain", "contabil-exemplo.com.br")]
    assert dom.expand is False and "registrant is another company" in dom.note


def test_rdap_challenge_is_could_not_verify_and_keeps_the_domain_unexpanded():
    body = dict(fx("brasilapi_ok.json"), email="contato@empresa-exemplo.com.br")
    http = snapshot(FakeHttp().add("GET", BRASILAPI.format(BB), json=body))
    http.add("GET", RDAP.format("empresa-exemplo.com.br"), status=403, text="Forbidden")
    res = run_module(CnpjLookup, f"cnpj:{BB}", http)
    assert res.status is Status.OK
    assert res.source_statuses["registrobr.rdap"]["status"] == "blocked"
    dom = pivots(res)[("domain", "empresa-exemplo.com.br")]
    assert dom.expand is False and "could not verify" in dom.note


def test_webmail_contact_never_becomes_a_domain_pivot_and_mei_cpf_is_masked():
    mei = "45678901000175"
    http = snapshot(FakeHttp().add("GET", BRASILAPI.format(mei), json=fx("brasilapi_mei_synthetic.json")))
    res = run_module(CnpjLookup, f"cnpj:{mei}", http)
    assert res.status is Status.OK
    a = res.attributes
    assert a["individual_entrepreneur"] is True
    assert a["legal_name"] == "FULANO DE TAL ***.456.789-**"  # masked at parse time (cond 12)
    assert a["mei"]["optante"] is True
    pv = pivots(res)
    assert not [k for k in pv if k[0] == "domain"]  # gmail.com: no domain pivot (cond 9)
    assert not [k for k in pv if k[0] in ("company_name", "cep")]  # MEI name/address are personal data
    email = pv[("email", "fixture-mei-0001@gmail.com")]
    assert email.expand is False and "personal data" in email.note
    assert "12345678909" not in dump(res)  # never in attributes, pivots, findings or evidence


def test_inapta_status_partner_companies_and_foreign_partner():
    cnpj = "98765432000198"
    http = snapshot(FakeHttp().add("GET", BRASILAPI.format(cnpj), json=fx("brasilapi_inapta_partners_synthetic.json")))
    res = run_module(CnpjLookup, f"cnpj:{cnpj}", http)
    assert res.status is Status.OK
    (f,) = res.findings
    assert f.severity.label == "medium" and f.title == "CNPJ registration status INAPTA"
    assert "company_status" in f.tags and f.criterion and f.data["since"] and f.data["meaning"].startswith("unfit")
    assert res.attributes["cnpj_card"]["status_plain"] == "unfit (inapta)"
    pv = pivots(res)
    pj = pv[("cnpj", "11222333000181")]
    assert pj.relation == "partner_of" and pj.expand is True and "third party" in pj.note
    foreign = pv[("company_name", "EXAMPLE HOLDINGS LLC")]
    assert foreign.expand is False
    dom = pv[("domain", "contabil-exemplo.example")]
    assert dom.expand is False and "no registro.br RDAP" in dom.note  # not .br: never sent to registro.br


def test_partner_companies_expand_only_within_the_configured_depth():
    cnpj = "98765432000198"
    http = snapshot(FakeHttp().add("GET", BRASILAPI.format(cnpj), json=fx("brasilapi_inapta_partners_synthetic.json")))
    res = run_module(CnpjLookup, f"cnpj:{cnpj}", http, is_seed=False, depth=1)
    assert pivots(res)[("cnpj", "11222333000181")].expand is False  # depth 1 = default limit
    http2 = snapshot(FakeHttp().add("GET", BRASILAPI.format(cnpj), json=fx("brasilapi_inapta_partners_synthetic.json")))
    res2 = run_module(CnpjLookup, f"cnpj:{cnpj}", http2, is_seed=False, depth=1, settings={"cnpj_lookup_partner_depth": 2})
    assert pivots(res2)[("cnpj", "11222333000181")].expand is True


def test_at_most_twenty_partner_companies():
    body = copy.deepcopy(fx("brasilapi_inapta_partners_synthetic.json"))
    template = body["qsa"][1]
    body["qsa"] = []
    for i in range(25):
        base = f"{11222000 + i:08d}0001"
        row = dict(template, cnpj_cpf_do_socio=base + mod.cnpj_check_digits(base), nome_socio=f"EXEMPLO PARTICIPACOES {i} S.A.")
        body["qsa"].append(row)
    cnpj = "98765432000198"
    http = snapshot(FakeHttp().add("GET", BRASILAPI.format(cnpj), json=body))
    res = run_module(CnpjLookup, f"cnpj:{cnpj}", http)
    assert len([p for p in res.pivots if p.entity.type.value == "cnpj"]) == 20
    assert len(res.attributes["qsa"]) == 25  # the card keeps the whole QSA


# --------------------------------------------------------------------------------------
# not found (cond 6) and could not verify (rule 5)
# --------------------------------------------------------------------------------------


def test_numeric_not_found_needs_two_independent_pipelines():
    http = FakeHttp()
    add_exchange(http, BRASILAPI.format(UNKNOWN), "brasilapi_not_found_numeric.http.json")
    add_exchange(http, QD_INFO.format(UNKNOWN), "qd_info_not_found_numeric.http.json")
    snapshot(http)
    res = run_module(CnpjLookup, f"cnpj:{UNKNOWN}", http)
    assert res.status is Status.OK
    assert res.attributes["presence"]["state"] == "absent"
    (f,) = res.findings
    assert f.title == "CNPJ not found in RFB open data" and f.severity.label == "info"
    assert "as of 2026-11" in f.description and "may be missing" in f.description
    assert sorted(f.data["pipelines"]) == ["minhareceita", "querido_diario"]
    # Minha Receita is BrasilAPI's own pipeline: never asked; one fallback only, so cnpj.ws is not asked either
    assert MINHARECEITA.format(UNKNOWN) not in http.urls() and CNPJWS.format(UNKNOWN) not in http.urls()


def test_alphanumeric_cnpj_is_accepted_and_querido_diario_skipped():
    http = FakeHttp()
    add_exchange(http, BRASILAPI.format(ALNUM), "brasilapi_not_found_alnum.http.json")
    add_exchange(http, CNPJWS.format(ALNUM), "cnpjws_not_found_alnum.http.json")
    snapshot(http)
    res = run_module(CnpjLookup, "cnpj:12.ABC.345/01DE-35", http)
    assert res.status is Status.OK and res.attributes["presence"]["state"] == "absent"
    assert res.source_statuses["querido_diario.company"] == {"status": "skipped", "reason_code": "not_applicable",
                                                             "reason": "Querido Diario rejects alphanumeric CNPJs"}
    assert QD_INFO.format(ALNUM) not in http.urls()  # QD answers 400 for alphanumeric CNPJs: never asked


def test_one_not_found_while_the_fallback_errors_is_could_not_verify():
    http = FakeHttp()
    add_exchange(http, BRASILAPI.format(UNKNOWN), "brasilapi_not_found_numeric.http.json")
    http.add("GET", QD_INFO.format(UNKNOWN), status=503, text="unavailable")
    snapshot(http)
    res = run_module(CnpjLookup, f"cnpj:{UNKNOWN}", http)
    assert res.status is Status.ERROR
    assert "could not verify" in res.error
    assert "presence" not in res.attributes and not res.findings


def test_all_providers_rate_limited_is_rate_limited_never_empty():
    http = FakeHttp()
    add_exchange(http, BRASILAPI.format(BB), "brasilapi_rate_limited.http.json")
    add_exchange(http, MINHARECEITA.format(BB), "minhareceita_rate_limited.http.json")
    add_exchange(http, QD_INFO.format(BB), "qd_rate_limited.http.json")
    add_exchange(http, CNPJWS.format(BB), "cnpjws_rate_limited.http.json")
    res = run_module(CnpjLookup, f"cnpj:{BB}", http)
    assert res.status is Status.RATE_LIMITED and res.reason_code == "rate_limited"
    assert {v["status"] for v in res.source_statuses.values()} == {"rate_limited"}


def test_empty_cnpjws_bucket_skips_instead_of_waiting():
    # first run: cnpj.ws answers 429 with x-ratelimit-remaining 0 (the bucket state is kept in ctx.state)
    http = FakeHttp()
    for url in (BRASILAPI, MINHARECEITA, QD_INFO):
        http.add("GET", url.format(BB), status=503, text="unavailable", times=2)
    add_exchange(http, CNPJWS.format(BB), "cnpjws_rate_limited.http.json")
    first = run_module(CnpjLookup, f"cnpj:{BB}", http)
    assert first.source_statuses["cnpjws.public"]["status"] == "rate_limited"
    # second run in the same minute: no request to cnpj.ws at all (an unmatched request would fail the test)
    second = run_module(CnpjLookup, f"cnpj:{BB}", http)
    assert second.status is Status.RATE_LIMITED
    row = second.source_statuses["cnpjws.public"]
    assert row["status"] == "rate_limited" and "skipped instead of waiting" in row["reason"]
    assert sum(1 for u in http.urls() if u == CNPJWS.format(BB)) == 1


def test_cnpjws_last_resort_parses_state_registrations_and_former_partners():
    http = FakeHttp()
    for url in (BRASILAPI, MINHARECEITA, QD_INFO):
        http.add("GET", url.format(BB), status=500, text="error")
    add_exchange(http, CNPJWS.format(BB), "cnpjws_ok.http.json")
    http.add("GET", RDAP.format("bb.com.br"), json=fx("rdap_registrobr_bb.json"))
    res = run_module(CnpjLookup, f"cnpj:{BB}", http)
    assert res.status is Status.OK
    a = res.attributes
    assert a["state_registrations"] == [{"ie": "0809427800174", "uf": "DF", "active": True, "updated": "2025-10-10T13:40:01.080Z"}]
    assert [p["name"] for p in a["qsa"]] == ["FULANO DE TAL", "BELTRANO DA SILVA"]  # latest refresh month only
    assert {p["name"] for p in a["qsa_former"]} == {"CICLANO SOUZA", "FULANA DE TAL"}
    assert ("person_name", "CICLANO SOUZA") not in pivots(res)  # former partners are history, never pivots
    assert a["cnpj_card"]["data_date"] == "2026-11-14"
    assert pivots(res)[("domain", "bb.com.br")].expand is True


def test_state_registration_supplement_is_opt_in():
    http = snapshot(FakeHttp().add("GET", BRASILAPI.format(BB), json=fx("brasilapi_ok.json")))
    add_exchange(http, CNPJWS.format(BB), "cnpjws_ok.http.json")
    http.add("GET", RDAP.format("bb.com.br"), json=fx("rdap_registrobr_bb.json"))
    res = run_module(CnpjLookup, f"cnpj:{BB}", http, settings={"cnpj_lookup_state_registrations": True})
    a = res.attributes
    assert a["state_registrations"][0]["ie"] == "0809427800174"
    # cnpj.ws (atualizado_em 2026-11-14) is fresher than the 2026-11 dump: it wins conflicting fields
    conflicts = {c["field"]: c for c in a["field_conflicts"]}
    assert "qsa" in conflicts and conflicts["qsa"]["chosen"]["provider"] == "cnpjws"
    assert {alt["provider"] for alt in conflicts["qsa"]["alternatives"]} == {"brasilapi"}
    # without the setting the chain stops at BrasilAPI (no cnpj.ws route needed)
    http2 = snapshot(FakeHttp().add("GET", BRASILAPI.format(BB), json=fx("brasilapi_ok.json")))
    assert "state_registrations" not in run_module(CnpjLookup, f"cnpj:{BB}", http2).attributes


def test_challenge_page_is_blocked_never_empty():
    http = FakeHttp()
    for url in (BRASILAPI, MINHARECEITA, QD_INFO):
        http.add("GET", url.format(BB), status=403, text="Forbidden")
    add_exchange(http, CNPJWS.format(BB), "cnpjws_challenge.http.json")
    res = run_module(CnpjLookup, f"cnpj:{BB}", http)
    assert res.status is Status.BLOCKED and res.reason_code == "challenge"
    assert res.source_statuses["cnpjws.public"]["status"] == "blocked"


def test_error_inside_http_200_is_an_error_never_a_record():
    body = fx("receitaws_error_in_200.http.json")["response"]["body"]
    http = FakeHttp().add("GET", BRASILAPI.format(BB), json=body)
    http.add("GET", MINHARECEITA.format(BB), json=fx("minhareceita_ok.json"))
    snapshot(http)
    res = run_module(CnpjLookup, f"cnpj:{BB}", http)
    assert res.status is Status.OK
    row = res.source_statuses["brasilapi.cnpj"]
    assert row["status"] == "error" and "ERROR" in row["reason"]


def test_malformed_json_and_transport_errors_are_could_not_verify():
    truncated = fx("cnpjws_malformed_truncated.txt")  # a live body cut at 60% (the research capture was truncated)
    http = FakeHttp()
    http.add("GET", BRASILAPI.format(BB), status=200, text=truncated, headers={"content-type": "application/json"})
    http.add("GET", MINHARECEITA.format(BB), error=NetworkError("read timed out", kind="ReadTimeout"))
    http.add("GET", QD_INFO.format(BB), json=["not", "a", "record"])
    http.add("GET", CNPJWS.format(BB), status=500, text="error")
    res = run_module(CnpjLookup, f"cnpj:{BB}", http)
    assert res.status is Status.ERROR
    states = {c["provider"]: c["state"] for c in res.attributes["provider_chain"]}
    assert states == {"BrasilAPI": "error", "Minha Receita": "timeout", "Querido Diario": "error", "CNPJ.ws": "error"}
    assert res.source_statuses["minhareceita.cnpj"]["reason_code"] == "timeout"


def test_per_provider_timeout_and_chain_budget():
    http = FakeHttp()
    http.add("GET", BRASILAPI.format(BB), json=fx("brasilapi_ok.json"), latency=9.0)
    http.add("GET", MINHARECEITA.format(BB), json=fx("minhareceita_ok.json"), latency=9.0)
    http.add("GET", QD_INFO.format(BB), json=fx("qd_info_ok.json"), latency=9.0)
    res = run_module(CnpjLookup, f"cnpj:{BB}", http)
    states = [(c["provider"], c["state"]) for c in res.attributes["provider_chain"]]
    # 8 s per provider: each slow answer is a timeout; after ~24 s the 25 s budget leaves no room for cnpj.ws
    assert states[:3] == [("BrasilAPI", "timeout"), ("Minha Receita", "timeout"), ("Querido Diario", "timeout")]
    assert states[3] == ("CNPJ.ws", "deadline")
    assert res.status is Status.ERROR
    assert CNPJWS.format(BB) not in http.urls()


# --------------------------------------------------------------------------------------
# normaliser of the providers pending terms review (cond 2) and helpers
# --------------------------------------------------------------------------------------


def test_pending_providers_are_coded_but_never_called():
    assert set(mod.PENDING_TERMS_REVIEW) == {"opencnpj", "cnpja", "receitaws"}
    hosts = set(CnpjLookup.hosts)
    assert not hosts & {v["host"] for v in mod.PENDING_TERMS_REVIEW.values()}
    o = mod.parse_opencnpj(fx("opencnpj_ok.json"))
    c = mod.parse_cnpja(fx("cnpja_ok.json"))
    r = mod.parse_receitaws(fx("receitaws_ok.http.json")["response"]["body"])
    for rec in (o, c, r):
        assert rec["cnpj"] == BB and rec["razao_social"] and rec["situacao"] == "ATIVA"
        assert all("*" in (p.get("doc_as_given") or "*") for p in rec["qsa"] if p["kind"] == "PF")
    assert mod.receitaws_error(fx("receitaws_error_in_200.http.json")["response"]["body"]).startswith("ReceitaWS status ERROR")
    assert mod.parse_receitaws(fx("receitaws_error_in_200.http.json")["response"]["body"]) is None
    for name in ("opencnpj_not_found_alnum.http.json", "cnpja_not_found_alnum.http.json"):
        ex = fx(name)["response"]
        state, _ = mod.answer_state("brasilapi", ex["status"], json.dumps(ex["body"]))
        assert state == "not_found"


def test_status_error_marker_follows_the_schema():
    marker = parse_marker(mod.RECEITAWS_ERROR_MARKER)
    assert marker.maps_to == "error" and marker.json_path == "status"


@pytest.mark.parametrize(("raw", "expected"), [
    ("00.000.000/0001-91", BB),
    ("12.ABC.345/01DE-35", ALNUM),
    ("00000000000192", None),
    ("11111111111111", None),
])
def test_normalize_cnpj(raw, expected):
    assert mod.normalize_cnpj(raw) == expected


def test_cpf_masking_never_unmasks_or_completes():
    assert mod.mask_cpf("123.456.789-09") == "***.456.789-**"
    assert mod.mask_cpf("***123456**") == "***123456**"  # as published by the RFB: kept exactly
    assert mod.mask_cpfs_in_text("FULANO DE TAL 12345678909") == "FULANO DE TAL ***.456.789-**"
    assert mod.strip_cpf_fragments("FULANO DE TAL ***.456.789-**") == "FULANO DE TAL"
    assert mod.mask_cpfs_in_text("12.345.678 FULANO") == "12.345.678 FULANO"  # MEI CNPJ-root prefix untouched


def test_not_found_verdict_rules():
    one = [{"provider": "brasilapi", "state": "not_found"}, {"provider": "qd", "state": "error"}]
    assert mod.not_found_verdict(one)["verdict"] == "could_not_verify"
    same = [{"provider": "brasilapi", "state": "not_found"}, {"provider": "minhareceita", "state": "not_found"}]
    assert mod.not_found_verdict(same)["verdict"] == "could_not_verify"  # one pipeline
    two = [{"provider": "brasilapi", "state": "not_found"}, {"provider": "cnpjws", "state": "not_found"}]
    v = mod.not_found_verdict(two, "2026-11")
    assert v["verdict"] == "not_found" and "as of 2026-11" in v["message"]


def test_bucket_follows_registry_rate_and_headers():
    ctx = make_ctx(CnpjLookup, FakeHttp(), entity=f"cnpj:{BB}")
    now = ctx.now().timestamp()
    assert mod.bucket_wait(ctx, "cnpjws", now) == 0.0
    for _ in range(3):  # burst 3 at 3/min x 0.8
        mod.bucket_charge(ctx, "cnpjws", now, headers={"x-ratelimit-remaining": "2", "x-ratelimit-reset": "60"})
    assert mod.bucket_wait(ctx, "cnpjws", now) > mod.MAX_WAIT_S
    ctx2 = make_ctx(CnpjLookup, FakeHttp(), entity=f"cnpj:{BB}")
    ctx2.state.delete(mod.BUCKET_STATE_KEY)
    mod.bucket_charge(ctx2, "cnpjws", now, headers={"x-ratelimit-remaining": "0", "x-ratelimit-reset": "60"})
    assert mod.bucket_wait(ctx2, "cnpjws", now) == pytest.approx(60.0, abs=1.0)
    assert mod.bucket_wait(ctx2, "cnpjws", now + 61) == 0.0


def test_health_check_uses_the_public_test_cnpj():
    hc = CnpjLookup.health_check()
    assert hc.etype.value == "cnpj" and hc.value == BB and hc.entity is not None


def test_evidence_keeps_answers_masked():
    body = copy.deepcopy(fx("brasilapi_ok.json"))
    body["qsa"][0]["nome_socio"] = "FULANO DE TAL 12345678909"
    http = snapshot(FakeHttp().add("GET", BRASILAPI.format(BB), json=body))
    res = run_module(CnpjLookup, f"cnpj:{BB}", http)
    text = dump(res)
    assert "12345678909" not in text
    assert re.search(r"FULANO DE TAL \*\*\*\.456\.789-\*\*", json.dumps(res.raw, ensure_ascii=False))
