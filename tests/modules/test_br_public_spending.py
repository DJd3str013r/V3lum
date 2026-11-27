"""br_public_spending (P246): BNDES CKAN financing operations and SALIC sponsorship by CNPJ.

Fixtures in tests/fixtures/br_public_spending/ (prep capture 2026-11-26 from a non-BR datacenter egress):
``bndes_naut_ok.json`` (non-automatic operations resource, 2 real public-body/NGO clients, fields trimmed),
``bndes_aut_masked_ok.json`` (automatic indirect operations: masked CNPJs, plus one synthetic masked-CPF person row),
``bndes_empty.json`` (total 0), ``bndes_ckan_error_synthetic.json`` (CKAN success=false envelope),
``bndes_filters_blocked_403.http.json`` (the Apache 403 page the front WAF returns for a JSON filters parameter),
``salic_incentivadores_ok.json`` (BB as company sponsor, HAL JSON), ``salic_incentivadores_mixed_synthetic.json`` (a
synthetic natural-person sponsor that must be dropped plus a company) and ``salic_incentivadores_not_found.http.json``
(404 with message_code 11, the documented absence).
"""

from __future__ import annotations

import json

from tests.fakes import FIXTURES, FakeHttp, run_module
from v3lum.core.http import NetworkError
from v3lum.core.models import Status
from v3lum.modules.brazil_public_data import br_public_spending as S
from v3lum.modules.brazil_public_data.br_public_spending import BrPublicSpending

FIX = FIXTURES / "br_public_spending"
RIBEIRAO = "56024581000156"
BB = "00000000000191"
EXEMPLO = "11222333000181"


def fx(name: str):
    return json.loads((FIX / name).read_text(encoding="utf-8"))


def naut(cnpj: str) -> str:
    return S.bndes_query_url("naut", cnpj)


def salic(cnpj: str) -> str:
    return S.salic_query_url(cnpj)


def salic_not_found(http: FakeHttp, cnpj: str) -> FakeHttp:
    ex = fx("salic_incentivadores_not_found.http.json")["response"]
    return http.add("GET", salic(cnpj), status=404, body=ex["body"].encode(), headers={"content-type": "application/json"})


def run(cnpj: str, http: FakeHttp, **kw):
    res = run_module(BrPublicSpending, f"cnpj:{cnpj}", http, **kw)
    http.assert_hosts_within(BrPublicSpending)
    return res


def test_bndes_exact_cnpj_operations_and_salic_absence():
    http = FakeHttp().add("GET", naut(RIBEIRAO), json=fx("bndes_naut_ok.json"))
    salic_not_found(http, RIBEIRAO)
    res = run(RIBEIRAO, http)
    assert res.status is Status.OK
    ops = res.attributes["public_funding"]
    assert len(ops) == 1 and ops[0]["operation_id"] == "1247021" and ops[0]["match"] == "exact"
    assert ops[0]["organ"] == "BNDES" and ops[0]["value"] == 9090000.0 and ops[0]["date"] == "2002-01-02"
    assert ops[0]["status"] == "LIQUIDADO" and len(ops[0]["dedup_key"]) == 16
    assert ops[0]["url"].startswith("https://dadosabertos.bndes.gov.br/api/3/action/datastore_search?resource_id=6f56b78c")
    f = res.findings[0]
    assert f.title == "BNDES financing operations" and f.confidence_label == "confirmed" and f.source == S.SOURCE_BNDES
    cov = res.attributes["public_funding_coverage"]
    assert cov["bndes"]["state"] == "ok" and cov["salic"]["state"] == "empty"
    assert res.source_statuses["minc.salic_incentivadores"]["status"] == "empty"
    assert "filters=" not in " ".join(http.urls())  # never the JSON filters parameter (WAF 403)
    assert not res.pivots


def test_salic_company_sponsor():
    http = FakeHttp().add("GET", naut(BB), json=fx("bndes_naut_ok.json"))  # loose full-text hits, no exact CNPJ
    http.add("GET", salic(BB), json=fx("salic_incentivadores_ok.json"))
    res = run(BB, http)
    assert res.status is Status.OK
    row = res.attributes["public_funding"][0]
    assert row["source"] == "salic" and row["value"] == 658803983.73 and row["url"].endswith("/doacoes")
    assert res.attributes["public_funding_coverage"]["bndes"]["state"] == "empty"
    assert [f.title for f in res.findings] == ["Lei Rouanet cultural-incentive sponsor (SALIC)"]
    assert "responsavel" not in json.dumps(res.raw)


def test_salic_natural_persons_are_never_kept():
    http = FakeHttp().add("GET", naut(EXEMPLO), json=fx("bndes_empty.json"))
    http.add("GET", salic(EXEMPLO), json=fx("salic_incentivadores_mixed_synthetic.json"))
    res = run(EXEMPLO, http)
    rows = res.attributes["public_funding"]
    assert [r["operation_id"] for r in rows] == ["salic:11222333000181"]
    blob = json.dumps({"attrs": res.attributes, "raw": res.raw, "f": [f.to_dict() for f in res.findings]})
    assert "FULANO" not in blob and "12345678909" not in blob
    assert res.raw["dropped_persons"] == 1


def test_nothing_found_is_empty():
    http = FakeHttp().add("GET", naut(EXEMPLO), json=fx("bndes_empty.json"))
    salic_not_found(http, EXEMPLO)
    res = run(EXEMPLO, http)
    assert res.status is Status.EMPTY and "no BNDES operation and no SALIC sponsorship" in res.error


def test_waf_403_is_blocked_for_that_provider_only():
    ex = fx("bndes_filters_blocked_403.http.json")["response"]
    http = FakeHttp().add("GET", naut(BB), status=403, body=ex["body"].encode(), headers={"content-type": "text/html; charset=iso-8859-1"})
    http.add("GET", salic(BB), json=fx("salic_incentivadores_ok.json"))
    res = run(BB, http)
    assert res.status is Status.OK
    st = res.source_statuses["bndes.ckan_operations"]
    assert st["status"] == "blocked" and st["reason_code"] == "challenge" and "could not verify" in st["reason"]
    assert res.attributes["public_funding_coverage"]["bndes"]["state"] == "blocked"


def test_both_blocked_is_blocked_never_empty():
    page = "<html><head><title>Just a moment...</title></head><body>cf-chl-widget</body></html>"
    http = FakeHttp().add("GET", naut(BB), status=403, text=page).add("GET", salic(BB), status=403, text=page)
    res = run(BB, http)
    assert res.status is Status.BLOCKED and res.reason_code == "challenge"


def test_429_is_rate_limited():
    http = FakeHttp().add("GET", naut(BB), status=429, text="slow down").add("GET", salic(BB), status=429, text="slow down")
    res = run(BB, http)
    assert res.status is Status.RATE_LIMITED


def test_5xx_and_timeouts_are_errors_never_empty():
    http = FakeHttp().add("GET", naut(BB), status=503, text="unavailable")
    http.add("GET", salic(BB), error=NetworkError("ReadTimeout reading", kind="ReadTimeout", reason_code="timeout"))
    res = run(BB, http)
    assert res.status is Status.ERROR
    assert res.source_statuses["minc.salic_incentivadores"]["reason_code"] == "timeout"


def test_ckan_error_in_200_and_malformed_json_are_errors():
    http = FakeHttp().add("GET", naut(BB), json=fx("bndes_ckan_error_synthetic.json"))
    http.add("GET", salic(BB), status=200, body=b'{"_embedded": {"incentivadores": [', headers={"content-type": "application/json"})
    res = run(BB, http)
    assert res.status is Status.ERROR
    assert "CKAN error: Not Found Error" in res.source_statuses["bndes.ckan_operations"]["reason"]
    assert "malformed JSON" in res.source_statuses["minc.salic_incentivadores"]["reason"]


def test_salic_404_without_the_documented_code_is_not_an_absence():
    http = FakeHttp().add("GET", naut(BB), json=fx("bndes_empty.json"))
    http.add("GET", salic(BB), status=404, json={"message": "route not found"})
    res = run(BB, http)
    assert res.source_statuses["minc.salic_incentivadores"]["status"] == "error"
    assert res.status is Status.EMPTY and "could not verify" in res.error


def test_indirect_operations_are_possible_matches_and_persons_dropped():
    cnpj = "92816560000137"
    http = FakeHttp().add("GET", naut(cnpj), json=fx("bndes_empty.json"))
    http.add("GET", S.bndes_query_url("aut", cnpj), json=fx("bndes_aut_masked_ok.json"))
    salic_not_found(http, cnpj)
    res = run(cnpj, http, settings={"br_public_spending_bndes_indirect": True})
    rows = res.attributes["public_funding"]
    assert len(rows) == 2 and {r["match"] for r in rows} == {"masked_partial"}
    assert res.findings[0].confidence_label == "possible" and "possible match only" in res.findings[0].description
    assert "FULANO" not in json.dumps(res.attributes) and res.raw["dropped_persons"] == 1
    assert S.bndes_masked_cnpj(cnpj) == "**.*16.560/0001-**"


def test_at_most_20_rows_per_provider():
    big = fx("bndes_naut_ok.json")
    rec = big["result"]["records"][0]
    big["result"]["records"] = [dict(rec, _id=i, numero_do_contrato=1000 + i) for i in range(30)]
    http = FakeHttp().add("GET", naut(RIBEIRAO), json=big)
    salic_not_found(http, RIBEIRAO)
    res = run(RIBEIRAO, http)
    assert len(res.attributes["public_funding"]) == 20


def test_only_allowed_sources_are_queried():
    http = FakeHttp().add("GET", salic(BB), json=fx("salic_incentivadores_ok.json"))
    res = run(BB, http, allowed_sources={"minc.salic_incentivadores"})
    assert res.source_statuses["bndes.ckan_operations"]["status"] == "skipped"
    assert http.hosts() == {"api.salic.cultura.gov.br"}


def test_dedup_key_is_stable_and_normalised():
    a = S.contract_dedup_key("56.024.581/0001-56", "BNDES", "001247021", "2002-01-02T00:00:00", 9090000)
    b = S.contract_dedup_key("56024581000156", "bndes", "1247021", "2002-01-02", "9.090.000,00")
    assert a == b and len(a) == 16


def test_declarations():
    assert BrPublicSpending.default_enabled is False and BrPublicSpending.requires_egress == frozenset()
    assert set(BrPublicSpending.hosts) == {"dadosabertos.bndes.gov.br", "api.salic.cultura.gov.br"}
    assert BrPublicSpending.trust_tier == "trusted" and BrPublicSpending.terms == "open"
