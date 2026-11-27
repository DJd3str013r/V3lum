"""Offline tests for P224 ``wikidata`` and the shared Wikidata client (batch p3-G10-1).

Fixtures in tests/fixtures/wikidata/ are live/research Wikidata answers plus synthetic Q999999xx items (README there).
"""

from __future__ import annotations

import re
from urllib.parse import parse_qs, urlsplit

import pytest

from tests.fakes import FakeHttp, make_runtime, module_fixture, run_module
from v3lum.core.context import ScanOptions
from v3lum.core.entities import EntityType as T
from v3lum.core.models import Status
from v3lum.modules.company_org import wikidata_client as wd
from v3lum.modules.company_org.wikidata import Wikidata

CONTACT = {"contact_email": "cti-team@example.com"}
SEARCH = re.compile(r"^https://www\.wikidata\.org/w/api\.php\?action=wbsearchentities")
SPARQL = re.compile(r"^https://query\.wikidata\.org/sparql\?")


def fx(name: str):
    return module_fixture("wikidata", name)


def exchange(http: FakeHttp, pattern, name: str) -> FakeHttp:
    ex = fx(name)
    return http.add("GET", pattern, status=ex["status"], body=ex["body"].encode(), headers=ex["headers"])


def bb_routes() -> FakeHttp:
    return FakeHttp().add("GET", SEARCH, json=fx("wbsearchentities_ok.json")).add("GET", SPARQL, json=fx("sparql_claims_ok.json"))


def test_needs_contact_ua():
    http = FakeHttp()
    res = run_module(Wikidata, "company_name:Banco do Brasil", http)
    assert res.status is Status.SKIPPED and res.reason_code == "config" and "contact" in res.error and http.calls == []


def test_organisation_items_only_and_community_edited_hints():
    http = bb_routes()
    res = run_module(Wikidata, "company_name:Banco do Brasil", http, settings=CONTACT)
    assert res.status is Status.OK, res.error
    item = res.attributes["wikidata_item"]
    assert item["qid"] == "Q610817" and item["link"] == "label" and item["confidence"] == "possible"
    assert res.attributes["wikidata_summary"].endswith("; CC0") and "community-edited" in res.attributes["wikidata_summary"]
    pivots = {(p.entity.type, p.entity.value): p for p in res.pivots}
    site = pivots[(T.DOMAIN, "www.bb.com.br")]
    assert site.relation == "company_of" and site.confidence <= 0.7 and site.expand is False and "community-edited" in site.note
    sub = pivots[(T.ORG, "Banco do Brasil Americas")]
    assert sub.relation == "company_of" and sub.expand is False and sub.confidence <= 0.6
    assert res.findings == []  # one-line output, no item is never a signal
    search, sparql = http.calls
    assert "cti-team@example.com" in search["headers"]["User-Agent"] and "cti-team@example.com" in sparql["headers"]["User-Agent"]
    query = parse_qs(urlsplit(sparql["url"]).query)["query"][0]
    assert query.endswith("LIMIT 20") and "wd:Q108220676" in query and "wd:Q610817" in query
    http.assert_hosts_within(Wikidata)


def test_p6204_cnpj_is_the_only_automatic_link():
    http = FakeHttp().add("GET", SEARCH, json=fx("wbsearchentities_cnpj_synthetic.json")).add("GET", SPARQL, json=fx("sparql_claims_cnpj_synthetic.json"))
    res = run_module(Wikidata, "company_name:EXEMPLO EMPRESA BRASILEIRA LTDA", http, settings=CONTACT, is_seed=False, depth=1,
                     provenance=[("cnpj:11222333000181", "legal_name", "cnpj_lookup")])
    item = res.attributes["wikidata_item"]
    assert item["link"] == "cnpj" and item["confidence"] == "confirmed"
    site = next(p for p in res.pivots if p.entity.type is T.DOMAIN)
    assert site.entity.value == "www.example.com" and site.expand is True and site.confidence <= 0.7
    assert not any(p.entity.value == "Exemplo Holding S.A." for p in res.pivots)  # depth 1: no parent/subsidiary pivots


def test_label_match_without_cnpj_never_auto_links():
    http = FakeHttp().add("GET", SEARCH, json=fx("wbsearchentities_cnpj_synthetic.json")).add("GET", SPARQL, json=fx("sparql_claims_cnpj_synthetic.json"))
    res = run_module(Wikidata, "company_name:Exemplo Empresa Brasileira S.A.", http, settings=CONTACT)
    assert res.attributes["wikidata_item"]["link"] == "label"
    assert all(p.expand is False for p in res.pivots)
    assert any(p.entity.value == "Exemplo Holding S.A." for p in res.pivots)  # depth 0: parent pivot


def test_no_exact_match_is_empty_without_sparql():
    http = FakeHttp().add("GET", SEARCH, json=fx("wbsearchentities_ok.json"))
    res = run_module(Wikidata, "company_name:Banco Industrial", http, settings=CONTACT)
    assert res.status is Status.EMPTY and "no item is no signal" in res.error and len(http.calls) == 1
    empty = run_module(Wikidata, "company_name:Qwzx Vrklm", FakeHttp().add("GET", SEARCH, json=fx("wbsearchentities_empty.json")), settings=CONTACT)
    assert empty.status is Status.EMPTY


def test_non_organisation_items_are_rejected():
    claims = fx("sparql_claims_ok.json")
    claims["results"]["bindings"] = [b for b in claims["results"]["bindings"] if not b["item"]["value"].endswith("Q610817")]
    http = FakeHttp().add("GET", SEARCH, json=fx("wbsearchentities_ok.json")).add("GET", SPARQL, json=claims)
    res = run_module(Wikidata, "company_name:Banco do Brasil", http, settings=CONTACT)
    assert res.status is Status.EMPTY and res.pivots == []


def test_domain_input_uses_the_fixed_p856_template():
    http = FakeHttp().add("GET", SPARQL, json=fx("sparql_domain_derived.json"), times=1).add("GET", SPARQL, json=fx("sparql_claims_ok.json"))
    res = run_module(Wikidata, "domain:bb.com.br", http, settings=CONTACT)
    assert res.status is Status.OK
    company = next(p for p in res.pivots if p.entity.type is T.ORG and p.entity.value == "Banco do Brasil")
    assert company.relation == "company_of" and company.expand is False
    assert not any(p.entity.type is T.DOMAIN for p in res.pivots)  # its own site is not re-pivoted
    first = parse_qs(urlsplit(http.calls[0]["url"]).query)["query"][0]
    assert "<https://bb.com.br/>" in first and "<http://www.bb.com.br>" in first and first.endswith("LIMIT 20")


@pytest.mark.parametrize("name", ["rate_limited_envoy.http.json", "rate_limited_varnish.http.json", "rate_limited_wbgetclaims.http.json"])
def test_429_answers_are_rate_limited(name):
    res = run_module(Wikidata, "company_name:Banco do Brasil", exchange(FakeHttp(), SEARCH, name), settings=CONTACT)
    assert res.status is Status.RATE_LIMITED


def test_errors_inside_http_200_and_wdqs_timeouts_are_could_not_verify():
    maxlag = run_module(Wikidata, "company_name:Banco do Brasil", FakeHttp().add("GET", SEARCH, json=fx("api_error_in_200.json")), settings=CONTACT)
    assert maxlag.status is Status.RATE_LIMITED
    other = {"error": {"code": "badvalue", "info": "Unrecognized value"}}
    assert run_module(Wikidata, "company_name:Banco do Brasil", FakeHttp().add("GET", SEARCH, json=other), settings=CONTACT).status is Status.ERROR
    timeout = exchange(FakeHttp().add("GET", SEARCH, json=fx("wbsearchentities_ok.json")), SPARQL, "sparql_timeout.http.json")
    res = run_module(Wikidata, "company_name:Banco do Brasil", timeout, settings=CONTACT)
    assert res.status is Status.ERROR and res.reason_code == "timeout"
    odd = FakeHttp().add("GET", SEARCH, json={"unexpected": True})
    assert run_module(Wikidata, "company_name:Banco do Brasil", odd, settings=CONTACT).status is Status.ERROR


def test_persons_only_for_typed_public_figures_on_request():
    http = FakeHttp()
    rt = make_runtime(http, settings=CONTACT)
    rt.in_scan = True
    res = run_module(Wikidata, "person_name:Example Public Figure", http, runtime=rt)
    assert res.status is Status.SKIPPED and res.reason_code == "privacy" and http.calls == []
    pivoted = run_module(Wikidata, "person_name:Example Public Figure", FakeHttp(), settings=CONTACT, is_seed=False, depth=1,
                         provenance=[("cnpj:11222333000181", "partner_of", "cnpj_lookup")])
    assert pivoted.status is Status.SKIPPED and pivoted.reason_code == "privacy"
    http2 = FakeHttp().add("GET", SEARCH, json=fx("wbsearchentities_person_synthetic.json")).add("GET", SPARQL, json=fx("sparql_person_synthetic.json"))
    rt2 = make_runtime(http2, settings=CONTACT)
    rt2.in_scan = True
    ok = run_module(Wikidata, "person_name:Example Public Figure", http2, runtime=rt2, options=ScanOptions(include=["wikidata"]))
    assert ok.status is Status.OK and ok.attributes["wikidata_item"]["qid"] == "Q99999911"
    assert all(p.expand is False for p in ok.pivots) and not any(p.entity.type is T.ORG for p in ok.pivots)
    query = parse_qs(urlsplit(http2.calls[1]["url"]).query)["query"][0]
    assert "wd:Q5" in query and "P749" not in query


def test_keywords_only_on_request():
    http = FakeHttp()
    rt = make_runtime(http, settings=CONTACT)
    rt.in_scan = True
    res = run_module(Wikidata, "keyword:Banco do Brasil", http, runtime=rt)
    assert res.status is Status.SKIPPED and res.reason_code == "not_default"


def test_only_fixed_templates_are_ever_sent():
    with pytest.raises(ValueError):
        wd.sparql_url("SELECT * WHERE { ?s ?p ?o }")
    with pytest.raises(ValueError):
        wd.sparql_url("SELECT ?item ?itemLabel WHERE { } LIMIT 1000")
    with pytest.raises(ValueError):
        wd.claims_query(["Q1; DROP"])
    with pytest.raises(ValueError):
        wd.domain_query("bad domain/../x")
    for q in (wd.claims_query(["Q1"]), wd.person_query(["Q2"]), wd.domain_query("example.com")):
        assert wd.sparql_url(q).startswith(wd.SPARQL_URL) and q.endswith("LIMIT 20")
    assert Wikidata.default_enabled is True and Wikidata.min_interval >= 1.0 and Wikidata.expected_latency <= 10
