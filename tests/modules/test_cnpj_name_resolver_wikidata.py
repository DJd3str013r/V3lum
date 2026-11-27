"""cnpj_name_resolver_wikidata (P361 FC7): the Wikidata P6204 fallback of the company-name resolver.

Fixtures in tests/fixtures/cnpj_name_resolver_wikidata/ (batch p2-G10-3 prep, 2026-11-25/26; Wikidata is CC0):
``wikidata_search_p6204_ok.json`` (list=search 'haswbstatement:P6204'), ``wikidata_wbsearchentities_ok.json``
(non-company items for 'Banco do Brasil'; a person name in a description and a street address replaced),
``wikidata_sparql_ok.json``, ``wikidata_sparql_count.json`` (2,895 items carry P6204), the live 429s
``wikidata_rate_limited.http.json`` (API, generic UA without contact) and ``wdqs_rate_limited.http.json``
(WDQS outage rule, egress IP scrubbed to 203.0.113.10), and synthetic ``wikidata_getentities_synthetic.json``
(the standard Wikibase JSON shape: wbgetentities answered 429 to the research egress) and
``wikidata_api_error_synthetic.json`` (MediaWiki maxlag error in an HTTP 200 body).
"""

from __future__ import annotations

import re

import pytest

from tests.fakes import FIXTURES, FakeHttp, make_runtime, module_fixture, run_module
from v3lum.core.context import ScanOptions
from v3lum.core.entities import EntityType as T
from v3lum.core.http import NetworkError
from v3lum.core.models import Status
from v3lum.modules.brazil_public_data import cnpj_name_resolver as R
from v3lum.modules.brazil_public_data.cnpj_name_resolver import CnpjNameResolverWikidata as W

CONTACT = {"contact_email": "soc@example.com"}
BB = "00000000000191"
Q = "Banco do Brasil"


def fx(name: str):
    return module_fixture("cnpj_name_resolver_wikidata", name)


def wiki_http(query: str = Q, *, search: dict | None = None, entities: dict | None = None) -> FakeHttp:
    http = FakeHttp().add("GET", R.wikidata_search_url(query), **(search or {"json": fx("wikidata_search_p6204_ok.json")}))
    http.add("GET", R.wikidata_entities_url(["Q130389677"]), **(entities or {"json": fx("wikidata_getentities_synthetic.json")}))
    return http


def test_p6204_items_become_non_expanding_hypotheses():
    http = wiki_http()
    res = run_module(W, f"company_name:{Q}", http, settings=CONTACT)
    assert res.status is Status.OK
    hyps = res.attributes["cnpj_hypotheses"]
    assert hyps[0]["cnpj"] == BB and hyps[0]["source"] == "wikidata" and hyps[0]["qid"] == "Q610817"
    assert hyps[0]["label"] == R.ONLINE_LABEL and hyps[0]["match_kind"] == "exact_razao"
    rn = res.attributes["name_resolution"]
    assert rn["auto_chain"]["auto"] is False  # online fallbacks never auto-chain (FC6)
    piv = {p.entity.value: p for p in res.pivots}
    assert piv[BB].expand is False and piv[BB].relation == "possible_cnpj"
    assert piv["www.bb.com.br"].relation == "wikidata_website" and piv["www.bb.com.br"].expand is False
    f = res.findings[0]
    assert "Wikidata fallback: large companies only" in f.description and "name_only_match" in f.tags
    http.assert_hosts_within(W)


def test_wikidata_needs_a_contact_email():
    http = FakeHttp()
    res = run_module(W, f"company_name:{Q}", http)
    assert res.status is Status.SKIPPED and res.reason_code == "config"
    assert http.urls() == []


def test_no_p6204_item_is_empty_never_could_not_verify():
    empty = {"batchcomplete": "", "query": {"searchinfo": {"totalhits": 0}, "search": []}}
    http = FakeHttp().add("GET", R.wikidata_search_url("EMPRESA EXEMPLO LTDA"), json=empty)
    res = run_module(W, "company_name:EMPRESA EXEMPLO LTDA", http, settings=CONTACT)
    assert res.status is Status.EMPTY and "large companies only" in res.error


@pytest.mark.parametrize(
    ("route", "status"),
    [
        ("rate_limited", Status.RATE_LIMITED),
        ({"status": 403, "text": "Forbidden: robot policy"}, Status.BLOCKED),
        ({"status": 503, "text": "Service Unavailable"}, Status.ERROR),
        ({"error": NetworkError("The read operation timed out", kind="ReadTimeout")}, Status.ERROR),
        ({"body": b'{"query": {', "headers": {"content-type": "application/json"}}, Status.ERROR),
    ],
)
def test_failures_are_could_not_verify(route, status):
    if route == "rate_limited":
        r = fx("wikidata_rate_limited.http.json")["response"]
        route = {"status": 429, "text": r["body"], "headers": r["headers"]}
    res = run_module(W, f"company_name:{Q}", wiki_http(search=route), settings=CONTACT)
    assert res.status is status


def test_mediawiki_error_in_200_is_an_error_and_never_cached():
    http = wiki_http(search={"json": fx("wikidata_api_error_synthetic.json")})
    rt = make_runtime(http, settings=CONTACT, cache=True)
    assert run_module(W, f"company_name:{Q}", runtime=rt).status is Status.ERROR
    assert run_module(W, f"company_name:{Q}", runtime=rt).status is Status.ERROR
    assert len(http.urls()) == 2


def test_wdqs_outage_page_is_recorded():
    r = fx("wdqs_rate_limited.http.json")["response"]
    assert r["status"] == 429 and "203.0.113.10" in r["body"] and r["headers"]["retry-after"] == "1000"


def test_runs_only_when_the_local_index_is_absent_or_empty(tmp_path):
    emp = R.parse_rfb_empresas((FIXTURES / "cnpj_name_resolver" / "rfb_empresas_synthetic.csv").read_bytes())
    est = R.parse_rfb_estabelecimentos((FIXTURES / "cnpj_name_resolver" / "rfb_estabelecimentos_synthetic.csv").read_bytes())
    R.build_index(tmp_path / "names.sqlite", emp, est, snapshot="2026-11")
    settings = dict(CONTACT, cnpj_name_resolver_index_path=str(tmp_path / "names.sqlite"))
    res = run_module(W, "company_name:BANCO DO BRASIL SA", FakeHttp(), settings=settings)
    assert res.status is Status.SKIPPED and res.reason_code == "not_applicable" and "local RFB name index answered" in res.error
    http = FakeHttp().add("GET", R.wikidata_search_url("ZZQX EMPRESA SEM INDICE"), json={"query": {"search": []}})
    res = run_module(W, "company_name:ZZQX EMPRESA SEM INDICE", http, settings=settings)
    assert res.status is Status.EMPTY  # the index returned nothing: the fallback ran


def test_refusals_match_the_main_resolver():
    res = run_module(W, "company_name:BANCO DO BRASIL SA", FakeHttp(), settings=CONTACT, is_seed=False, depth=1,
                     provenance=[(f"cnpj:{BB}", "legal_name", "cnpj_lookup")])
    assert res.status is Status.SKIPPED and res.reason_code == "not_applicable"
    res = run_module(W, "keyword:banco", FakeHttp(), settings=CONTACT)
    assert res.status is Status.SKIPPED and res.reason_code == "not_default"
    http = wiki_http("banco do brasil")
    res = run_module(W, "keyword:banco do brasil", http, settings=CONTACT, options=ScanOptions(include={"cnpj_name_resolver_wikidata"}))
    assert res.status is Status.OK
    assert T.PERSON not in W.accepts


def test_parsers_and_captures():
    assert R.parse_wikidata_search(fx("wikidata_search_p6204_ok.json")) == {"total": 1, "qids": ["Q130389677"]}
    ents = R.parse_wbgetentities(fx("wikidata_getentities_synthetic.json"))
    assert ents["Q610817"]["cnpjs"] == [BB]  # the deprecated raw-digits statement is ignored
    assert ents["Q610817"]["websites"] == ["https://www.bb.com.br/"] and ents["Q0"] == {"missing": True}
    assert all(re.fullmatch(r"Q\d+", s["id"]) for s in fx("wikidata_wbsearchentities_ok.json")["search"])
    assert fx("wikidata_sparql_ok.json")["results"]["bindings"] is not None
    assert int(fx("wikidata_sparql_count.json")["results"]["bindings"][0]["c"]["value"]) > 2000
    assert R.wikidata_error_in_200(fx("wikidata_api_error_synthetic.json")) == "Wikidata API error maxlag"


def test_metadata():
    assert W.default_enabled is True and W.terms == "open" and W.trust_tier == "trusted"
    assert W.hosts == ("www.wikidata.org",) and W.providers == frozenset({"wikidata"})
