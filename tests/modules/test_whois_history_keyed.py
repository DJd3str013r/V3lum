"""Offline tests for whois_history_keyed (P022): WhoisXML, Whoxy and WhoisFreaks adapters.

Fixtures in tests/fixtures/whois_history_keyed/ (provenance in MANIFEST.json): the error bodies of the three
providers and the example.com Whoxy record are real; success bodies are documented examples or synthetic
(documentation values only) until the team keys capture real ones (P022 cond 8, docs/backlog/p3-G01-2.md).
"""

from __future__ import annotations

import json
from types import SimpleNamespace
from urllib.parse import urlencode

import pytest

from tests.fakes import FakeHttp, assert_no_secret, make_runtime, module_fixture, run_module
from v3lum.core.context import ModuleState, ScanOptions
from v3lum.core.entities import Entity
from v3lum.core.entities import EntityType as T
from v3lum.core.graph import Graph
from v3lum.core.models import Severity, Status
from v3lum.modules.domain_dns.whois_history_keyed import (
    WHOISFREAKS_URL,
    WHOISXML_HISTORY_URL,
    WHOISXML_REVERSE_URL,
    WHOXY_URL,
    WhoisHistoryKeyed,
    cr32_confidence,
    is_pre_gdpr,
    load_privacy,
    minimise_contact,
    registration_provenance,
)

MOD = WhoisHistoryKeyed
KEYS = {"whoisxml": "wxml-test-key-0123456789", "whoxy": "whoxy-test-key-0123456789", "whoisfreaks": "wfreaks-test-key-0123456789"}
DROPPED = ("5555", "Rua Exemplo", "01000-000", "Admin Example Two", "admin02@example.org", "tech03@example.org",
           "abuse@registrar.example", "trimmed raw WHOIS text")
PURPOSE = ScanOptions(purpose="fraud: phishing kit infrastructure (ticket FR-1)")


def fx(name: str):
    return module_fixture(MOD, name)


def http_fx(name: str) -> tuple[int, dict[str, str], str]:
    doc = fx(name)
    resp = doc["response"]
    return resp["status"], dict(resp.get("headers") or {}), resp["body"]


def whoxy_url(**params: str) -> str:
    return WHOXY_URL + "?" + urlencode({"key": KEYS["whoxy"], **params})


def freaks_url(**params: str) -> str:
    return WHOISFREAKS_URL + "?" + urlencode({**params, "apiKey": KEYS["whoisfreaks"]})


def keys(*names: str) -> dict[str, str]:
    return {n: KEYS[n] for n in names}


def blob(res) -> str:
    return json.dumps({"attributes": res.attributes, "raw": res.raw, "findings": [f.to_dict() for f in res.findings],
                       "pivots": [p.to_dict() for p in res.pivots], "error": res.error}, default=str)


def assert_minimised(res) -> None:
    text = blob(res)
    for value in DROPPED:
        assert value not in text, f"{value!r} survived minimisation"


def credits_spent(adapter: str) -> int:
    data = ModuleState("whois_history_keyed").all()
    return sum(v for k, v in data.items() if k.startswith(f"credits:{adapter}:"))


def case_runtime(http: FakeHttp, graph: Graph, **kw):
    rt = make_runtime(http, **kw)
    rt.policy_context = SimpleNamespace(graph=graph)  # the live case graph of a running investigation
    return rt


def graph_with_selectors(*selectors: dict, module: str = "whois_history_keyed") -> Graph:
    g = Graph()
    dom = Entity.make(T.DOMAIN, "example.com")
    g.add_node(dom, 0, seed=True)
    g.add_attributes(dom, {"registrant_selectors": list(selectors)}, module)
    return g


# ======================================================================================
# history (domain seeds)
# ======================================================================================


def test_whoisxml_history_preview_then_purchase_minimised():
    http = (FakeHttp()
            .add("POST", WHOISXML_HISTORY_URL, json=fx("whoisxml_history_preview_documented.json"), times=1)
            .add("POST", WHOISXML_HISTORY_URL, json=fx("whoisxml_history_ok_documented.json"), times=1))
    res = run_module(MOD, "domain:example.com", http, keys=keys("whoisxml"))
    assert res.status is Status.OK, res.error
    records = res.attributes["whois_history"]
    assert [r["record_date"] for r in records] == ["2024-06-30", "2019-07-01", "2017-12-01"]  # audit.updatedDate (cond 6)
    assert records[0]["record_date_source"] == "audit.updatedDate"
    assert [r["historical"] for r in records] == [False, False, True]
    assert records[2]["label"] == "historical (pre-GDPR)"
    assert [r["registrant_kind"] for r in records] == ["redacted", "redacted", "org"]
    assert records[0]["privacy_proxy"] and records[1]["privacy_proxy"] and not records[2]["privacy_proxy"]
    assert records[2]["registrant_organization"] == "Example Holdings Ltda" and records[2]["registrant_country"] == "Brazil"
    assert records[0]["registrant_organization"] is None  # 'REDACTED FOR PRIVACY' is never kept as an organisation
    assert records[0]["status"] == ["clientTransferProhibited"] and records[0]["nameservers"] == ["ns1.dns-provider.example", "ns2.dns-provider.example"]
    summary = res.attributes["whois_history_summary"]
    assert summary["records_count"] == 3 and summary["historical_count"] == 1 and summary["privacy_proxy_records"] == 2
    assert summary["registrars"] == ["Registrar Example Ltda"] and summary["preview"] is False
    selectors = {(s["kind"], s["value"]): s for s in res.attributes["registrant_selectors"]}
    # privacy/proxy and placeholder values never become selectors (cond 4)
    assert set(selectors) == {("email", "dns-admin@example.net"), ("company_name", "Example Holdings Ltda"), ("person_name", "Registrant Example One")}
    assert selectors[("email", "dns-admin@example.net")]["natural_person"] is False  # role mailbox
    assert selectors[("person_name", "Registrant Example One")]["natural_person"] is True
    pivots = {(p.entity.type, p.entity.value): p for p in res.pivots}
    assert set(pivots) == {(T.EMAIL, "dns-admin@example.net"), (T.ORG, "Example Holdings Ltda")}  # never a person-name pivot
    assert all(not p.expand for p in res.pivots)  # candidates, never scope (cond 2)
    assert pivots[(T.EMAIL, "dns-admin@example.net")].relation == "registrant_email"
    finding = res.findings[0]
    assert finding.severity is Severity.INFO and "historical" in finding.tags and "privacy" in finding.tags
    assert finding.source == "whoisxmlapi.drs" and finding.criterion
    assert res.source_statuses["whoisxmlapi.drs"]["status"] == "ok"
    assert_minimised(res)
    assert "domainsbyproxy" not in json.dumps(res.attributes["registrant_selectors"])
    # key in the header only (AR01), never in a URL; preview 1 + purchase 50 credits
    assert all(c["headers"].get("X-Authentication-Token") == KEYS["whoisxml"] for c in http.calls)
    assert [json.loads(c["body"])["mode"] for c in http.calls] == ["preview", "purchase"]
    assert all(KEYS["whoisxml"] not in c["url"] for c in http.calls)
    assert credits_spent("whoisxml") == 51
    assert_no_secret(KEYS["whoisxml"], res.attributes, res.raw, res.findings, res.error)
    http.assert_hosts_within(MOD)


def test_whoisxml_preview_mode_keeps_count_only():
    http = FakeHttp().add("POST", WHOISXML_HISTORY_URL, json=fx("whoisxml_history_preview_documented.json"), times=1)
    res = run_module(MOD, "domain:example.com", http, keys=keys("whoisxml"), settings={"whois_history_keyed_whoisxml_mode": "preview"})
    assert res.status is Status.OK
    assert res.attributes["whois_history_summary"]["preview"] is True and res.attributes["whois_history_summary"]["records_count"] == 7
    assert "whois_history" not in res.attributes
    assert "record count only" in res.findings[0].description
    assert credits_spent("whoisxml") == 1


def test_purchase_skipped_when_the_monthly_credit_budget_is_low():
    http = FakeHttp().add("POST", WHOISXML_HISTORY_URL, json=fx("whoisxml_history_preview_documented.json"), times=1)
    res = run_module(MOD, "domain:example.com", http, keys=keys("whoisxml"),
                     settings={"whois_history_keyed_monthly_credits": {"whoisxml": 10}})
    assert res.status is Status.OK and res.partial and res.stop_reason == "quota"
    assert len(http.calls) == 1  # 50-credit purchase never sent
    assert "purchase" in res.findings[0].description


def test_exhausted_budget_is_quota_without_request():
    http = FakeHttp()
    res = run_module(MOD, "domain:example.com", http, keys=keys("whoisxml"), settings={"whois_history_keyed_monthly_credits": {"whoisxml": 0}})
    assert res.status is Status.QUOTA and res.reason_code == "quota"
    assert http.calls == []
    assert res.source_statuses["whoisxmlapi.drs"]["status"] == "quota"


def test_whoisxml_history_empty():
    http = FakeHttp().add("POST", WHOISXML_HISTORY_URL, json=fx("whoisxml_history_empty_synthetic.json"))
    res = run_module(MOD, "domain:example.com", http, keys=keys("whoisxml"))
    assert res.status is Status.EMPTY
    assert not res.findings and not res.pivots


@pytest.mark.parametrize(
    ("fixture", "status", "code"),
    [
        ("whoisxml_nokey_401.http.json", Status.NEEDS_KEY, "needs_key"),
        ("whoisxml_quota_403_documented.http.json", Status.QUOTA, "quota"),
        ("whoisxml_rate_limited_429_documented.http.json", Status.RATE_LIMITED, "rate_limited"),
    ],
)
def test_whoisxml_error_answers_are_could_not_verify(fixture, status, code):
    st, headers, body = http_fx(fixture)
    http = FakeHttp().add("POST", WHOISXML_HISTORY_URL, status=st, headers=headers, body=body.encode())
    res = run_module(MOD, "domain:example.com", http, keys=keys("whoisxml"))
    assert res.status is status and res.reason_code == code
    assert res.source_statuses["whoisxmlapi.drs"]["status"] == status.value
    assert not res.findings


def test_whoisxml_5xx_html_and_malformed_answers_are_errors():
    http = FakeHttp().add("POST", WHOISXML_HISTORY_URL, status=502, text="<html><head><title>502 Bad Gateway</title></head><body>nginx</body></html>")
    res = run_module(MOD, "domain:example.com", http, keys=keys("whoisxml"))
    assert res.status is Status.ERROR and "could not verify" in res.error
    http2 = FakeHttp().add("POST", WHOISXML_HISTORY_URL, text="OK")
    res2 = run_module(MOD, "domain:example.com", http2, keys=keys("whoisxml"))
    assert res2.status is Status.ERROR and "not JSON" in res2.error
    http3 = FakeHttp().add("POST", WHOISXML_HISTORY_URL, json=["not", "an", "object"])
    assert run_module(MOD, "domain:example.com", http3, keys=keys("whoisxml")).status is Status.ERROR


def test_whoisxml_error_in_200_body_needs_key():
    http = FakeHttp().add("POST", WHOISXML_HISTORY_URL, json={"ErrorMessage": {"errorCode": "AUTHENTICATE_03", "msg": "API key invalid"}})
    res = run_module(MOD, "domain:example.com", http, keys=keys("whoisxml"))
    assert res.status is Status.NEEDS_KEY


def test_falls_back_to_the_next_adapter_and_reports_each_status():
    st, headers, body = http_fx("whoisxml_rate_limited_429_documented.http.json")
    http = (FakeHttp()
            .add("POST", WHOISXML_HISTORY_URL, status=st, headers=headers, body=body.encode())
            .add("GET", freaks_url(whois="historical", domainName="example.com"), json=fx("whoisfreaks_history_ok_documented.json")))
    res = run_module(MOD, "domain:example.com", http, keys=keys("whoisxml", "whoisfreaks"))
    assert res.status is Status.OK
    assert res.source_statuses["whoisxmlapi.drs"]["status"] == "rate_limited"
    assert res.source_statuses["whoisfreaks.api"]["status"] == "ok"
    assert res.findings[0].source == "whoisfreaks.api"


def test_stops_at_the_first_adapter_that_answers():
    http = (FakeHttp()
            .add("POST", WHOISXML_HISTORY_URL, json=fx("whoisxml_history_empty_synthetic.json")))
    res = run_module(MOD, "domain:example.com", http, keys=keys("whoisxml", "whoisfreaks"))
    assert res.status is Status.EMPTY
    assert {c["url"].split("?")[0] for c in http.calls} == {WHOISXML_HISTORY_URL}  # WhoisFreaks credits saved


def test_whoisfreaks_history_ok_personal_values_only_as_selectors():
    http = FakeHttp().add("GET", freaks_url(whois="historical", domainName="example.com"), json=fx("whoisfreaks_history_ok_documented.json"))
    res = run_module(MOD, "domain:example.com", http, keys=keys("whoisfreaks"))
    assert res.status is Status.OK
    records = res.attributes["whois_history"]
    assert [r["record_date"] for r in records] == ["2024-02-10", "2017-05-02"]
    assert records[1]["historical"] and records[1]["registrar"] == {"name": "Registrar Example Ltda", "iana_id": "9999"}
    assert "registrant01@example.org" not in json.dumps(records)  # natural-person values never in the records (cond 5)
    selectors = res.attributes["registrant_selectors"]
    email = next(s for s in selectors if s["kind"] == "email")
    assert email["value"] == "registrant01@example.org" and email["natural_person"] is True and email["historical"] is True
    pivot = next(p for p in res.pivots if p.entity.type is T.EMAIL)
    assert not pivot.expand and "privacy" in pivot.note
    assert "privacy" in res.findings[0].tags
    assert_minimised(res)
    assert all(KEYS["whoisfreaks"] not in json.dumps(v, default=str) for v in (res.attributes, res.raw, res.error))
    http.assert_hosts_within(MOD)


@pytest.mark.parametrize(
    ("fixture", "status"),
    [
        ("whoisfreaks_nokey_400.http.json", Status.NEEDS_KEY),
        ("whoisfreaks_invalid_key_401_documented.http.json", Status.NEEDS_KEY),
        ("whoisfreaks_credits_413_documented.http.json", Status.QUOTA),
        ("whoisfreaks_rate_limited_429_documented.http.json", Status.RATE_LIMITED),
        ("whoisfreaks_history_not_found_404_documented.http.json", Status.EMPTY),
    ],
)
def test_whoisfreaks_documented_statuses(fixture, status):
    st, headers, body = http_fx(fixture)
    http = FakeHttp().add("GET", freaks_url(whois="historical", domainName="example.com"), status=st, headers=headers, body=body.encode())
    res = run_module(MOD, "domain:example.com", http, keys=keys("whoisfreaks"))
    assert res.status is status, res.error
    if status is not Status.EMPTY:
        assert not res.findings


def test_whoxy_is_off_until_the_rule7_check_is_recorded():
    http = FakeHttp()
    res = run_module(MOD, "domain:example.com", http, keys=keys("whoxy"))
    assert res.status is Status.SKIPPED and res.reason_code == "config"
    assert http.calls == []
    assert res.source_statuses["whoxy_api.api"]["reason_code"] == "config"


WHOXY_ON = {"whois_history_keyed_providers": ["whoxy"]}


def test_whoxy_history_ok_and_key_never_leaks():
    http = FakeHttp().add("GET", whoxy_url(history="example.com"), json=fx("whoxy_history_ok_synthetic.json"))
    res = run_module(MOD, "domain:example.com", http, keys=keys("whoxy"), settings=WHOXY_ON)
    assert res.status is Status.OK
    records = res.attributes["whois_history"]
    assert [r["record_date"] for r in records] == ["2024-02-10", "2019-07-01", "2016-03-29"]
    assert [r["record_date_source"] for r in records] == ["query_time"] * 3
    assert records[0]["privacy_proxy"]  # contact-form e-mail + 'REDACTED FOR PRIVACY'
    values = {s["value"] for s in res.attributes["registrant_selectors"]}
    assert values == {"registrant01@example.org", "Example Holdings Ltda", "Registrant Example One"}
    assert_minimised(res)
    assert_no_secret(KEYS["whoxy"], res.attributes, res.raw, res.findings, res.error)
    assert credits_spent("whoxy") == 1
    http.assert_hosts_within(MOD)


def test_whoxy_real_record_shape():
    record = fx("whoxy_record_example_com.json")  # real Whoxy record (research sample, example.com)
    doc = {"status": 1, "status_reason": "Successful", "total_records_found": 1, "whois_records": [record]}
    http = FakeHttp().add("GET", whoxy_url(history="example.com"), json=doc)
    res = run_module(MOD, "domain:example.com", http, keys=keys("whoxy"), settings=WHOXY_ON)
    rec = res.attributes["whois_history"][0]
    assert rec["registrar"] == {"name": "RESERVED-Internet Assigned Numbers Authority", "iana_id": "376"}
    assert rec["created"] == "1995-08-14" and rec["expires"] == "2027-08-13" and rec["record_date"] == "2026-10-25"
    assert rec["nameservers"] == ["elliott.ns.cloudflare.com", "hera.ns.cloudflare.com"]
    assert rec["registrant_kind"] == "unknown" and "registrant_selectors" not in res.attributes


def test_whoxy_invalid_key_in_200_is_needs_key_and_not_cached():
    http = FakeHttp().add("GET", whoxy_url(history="example.com"), json=fx("whoxy_badkey.json"), times=2)
    rt = make_runtime(http, keys=keys("whoxy"), settings=WHOXY_ON, cache=True)
    res = run_module(MOD, "domain:example.com", runtime=rt)
    assert res.status is Status.NEEDS_KEY and res.reason_code == "needs_key"
    again = run_module(MOD, "domain:example.com", runtime=rt)
    assert again.status is Status.NEEDS_KEY
    assert len(http.calls) == 2  # the error-in-200 answer was never cached


def test_whoxy_balance_in_200_is_quota():
    http = FakeHttp().add("GET", whoxy_url(history="example.com"), json=fx("whoxy_quota_synthetic.json"))
    res = run_module(MOD, "domain:example.com", http, keys=keys("whoxy"), settings=WHOXY_ON)
    assert res.status is Status.QUOTA and res.reason_code == "quota"


def test_whoxy_non_json_200_is_error():
    st, headers, body = http_fx("whoxy_malformed_ok_text.http.json")  # live: 'OK' (2 bytes)
    http = FakeHttp().add("GET", whoxy_url(history="example.com"), status=st, headers=headers, body=body.encode())
    res = run_module(MOD, "domain:example.com", http, keys=keys("whoxy"), settings=WHOXY_ON)
    assert res.status is Status.ERROR and "could not verify" in res.error


def test_whoxy_empty_history():
    http = FakeHttp().add("GET", whoxy_url(history="example.com"), json=fx("whoxy_history_empty_synthetic.json"))
    res = run_module(MOD, "domain:example.com", http, keys=keys("whoxy"), settings=WHOXY_ON)
    assert res.status is Status.EMPTY


def test_cache_hits_are_free_30_day_ttl():
    http = (FakeHttp()
            .add("POST", WHOISXML_HISTORY_URL, json=fx("whoisxml_history_preview_documented.json"), times=1)
            .add("POST", WHOISXML_HISTORY_URL, json=fx("whoisxml_history_ok_documented.json"), times=1))
    rt = make_runtime(http, keys=keys("whoisxml"), cache=True)
    first = run_module(MOD, "domain:example.com", runtime=rt)
    second = run_module(MOD, "domain:example.com", runtime=rt)  # no route left: must come from the cache
    assert first.status is second.status is Status.OK
    assert len(http.calls) == 2 and credits_spent("whoisxml") == 51
    assert MOD.cache_ttl == 30 * 86400


def test_no_key_is_needs_key_without_request():
    http = FakeHttp()
    res = run_module(MOD, "domain:example.com", http)
    assert res.status is Status.NEEDS_KEY and http.calls == []


def test_licence_blocked_sources_are_never_queried():
    http = FakeHttp()
    res = run_module(MOD, "domain:example.com", http, keys=keys("whoisxml"), allowed_sources=[])
    assert res.status is Status.SKIPPED and res.reason_code == "licence"
    assert http.calls == []


def test_subdomain_queries_the_registrable_domain_and_public_suffix_is_not_applicable():
    http = (FakeHttp().add("POST", WHOISXML_HISTORY_URL, json=fx("whoisxml_history_empty_synthetic.json")))
    res = run_module(MOD, "domain:www.example.com", http, keys=keys("whoisxml"))
    assert json.loads(http.calls[0]["body"])["domainName"] == "example.com"
    assert res.status is Status.EMPTY
    assert run_module(MOD, "domain:co.uk", FakeHttp(), keys=keys("whoisxml")).status is Status.SKIPPED


# ======================================================================================
# reverse WHOIS (e-mail / organisation / person name)
# ======================================================================================

EMAIL_SEL = {"kind": "email", "value": "registrant01@example.org", "match_field": "email", "natural_person": True,
             "record_date": "2016-03-29", "historical": True, "provider": "whoxy"}
NAME_SEL = {"kind": "person_name", "value": "Registrant Example One", "match_field": "name", "natural_person": True,
            "record_date": "2016-03-29", "historical": True, "provider": "whoxy"}


def test_reverse_email_with_case_provenance_whoxy():
    page2 = {"status": 1, "status_reason": "Successful", "total_pages": 2, "current_page": 2, "total_results": 103, "search_result": []}
    http = (FakeHttp()
            .add("GET", whoxy_url(reverse="whois", email="registrant01@example.org", page="1"), json=fx("whoxy_reverse_ok_synthetic.json"))
            .add("GET", whoxy_url(reverse="whois", email="registrant01@example.org", page="2"), json=page2))
    rt = case_runtime(http, graph_with_selectors(EMAIL_SEL), keys=keys("whoxy"), settings=WHOXY_ON)
    res = run_module(MOD, "email:registrant01@example.org", runtime=rt, options=PURPOSE)
    assert res.status is Status.OK, res.error
    rev = res.attributes["reverse_whois"]
    assert rev["match_field"] == "email" and rev["total"] == 103 and rev["truncated"] and not rev["too_broad"]
    by_domain = {d["domain"]: d for d in rev["domains"]}
    assert set(by_domain) == {"examp1e-login.example", "example-secure-pay.example", "example-promo.example"}
    assert by_domain["example-secure-pay.example"]["match_confirmed"] is True  # case-insensitive e-mail match
    assert by_domain["example-promo.example"]["match_confirmed"] is False and by_domain["example-promo.example"]["historical"]
    assert set(by_domain["examp1e-login.example"]) == {"domain", "created", "updated", "expires", "registrar", "record_date", "historical",
                                                      "label", "match_confirmed"}  # cond 5: nothing else survives
    pivots = {p.entity.value: p for p in res.pivots}
    assert pivots["examp1e-login.example"].confidence == pytest.approx(0.7)  # e-mail match field (cond 6)
    assert pivots["example-promo.example"].confidence == pytest.approx(0.4)  # another e-mail in that field: POSSIBLE
    assert all(p.relation == "shared_registrant" and not p.expand for p in res.pivots)
    finding = res.findings[0]
    assert finding.title == "Domains sharing the registrant e-mail"
    assert {"privacy", "historical"} <= set(finding.tags)
    cluster = finding.data["cr32_candidate"]
    assert cluster["rule"] == "CR32" and cluster["candidates_only"] and cluster["confidence"] == pytest.approx(0.7)
    assert_minimised(res)
    assert "other05@example.net" not in blob(res) and "Registrant Example One" not in blob(res)
    assert_no_secret(KEYS["whoxy"], res.attributes, res.raw, res.findings, res.error)
    http.assert_hosts_within(MOD)


def test_reverse_email_refused_without_case_record_purpose_or_selection():
    http = FakeHttp()
    graph = graph_with_selectors(EMAIL_SEL)
    no_case = run_module(MOD, "email:registrant01@example.org", http, keys=keys("whoxy"), settings=WHOXY_ON, options=PURPOSE)
    assert no_case.status is Status.SKIPPED and no_case.reason_code == "privacy" and "WHOIS/RDAP record" in no_case.error
    no_purpose = run_module(MOD, "email:registrant01@example.org", runtime=case_runtime(http, graph, keys=keys("whoxy"), settings=WHOXY_ON))
    assert no_purpose.status is Status.SKIPPED and "purpose" in no_purpose.error
    pivot = run_module(MOD, "email:registrant01@example.org", runtime=case_runtime(http, graph, keys=keys("whoxy"), settings=WHOXY_ON),
                       options=PURPOSE, is_seed=False, depth=1)
    assert pivot.status is Status.SKIPPED and "analyst-selected" in pivot.error
    other = run_module(MOD, "email:someone.else@example.org", runtime=case_runtime(http, graph, keys=keys("whoxy"), settings=WHOXY_ON),
                       options=PURPOSE)
    assert other.status is Status.SKIPPED and other.reason_code == "privacy"  # free-text person search refused (rule 4)
    unconfirmed = ScanOptions(purpose="fraud", unconfirmed_seeds={"email:registrant01@example.org"})
    res = run_module(MOD, "email:registrant01@example.org", runtime=case_runtime(http, graph, keys=keys("whoxy"), settings=WHOXY_ON),
                     options=unconfirmed)
    assert res.status is Status.SKIPPED
    assert http.calls == []


def test_provenance_only_from_registration_modules():
    g = graph_with_selectors(EMAIL_SEL, module="github_email_pivot")
    ctx = SimpleNamespace(runtime=SimpleNamespace(policy_context=SimpleNamespace(graph=g)))
    assert registration_provenance(ctx, Entity.make(T.EMAIL, "registrant01@example.org")) is None
    g2 = Graph()
    dom, mail = Entity.make(T.DOMAIN, "example.com"), Entity.make(T.EMAIL, "registrant01@example.org")
    g2.add_node(dom, 0, seed=True)
    g2.add_node(mail, 0, seed=True)
    g2.add_edge(dom, mail, "registrant_email", "whois_history_keyed", 0.7, expand=False)
    ctx2 = SimpleNamespace(runtime=SimpleNamespace(policy_context=SimpleNamespace(graph=g2)))
    assert "registrant_email of domain:example.com" in registration_provenance(ctx2, mail)
    assert registration_provenance(SimpleNamespace(runtime=SimpleNamespace(policy_context=None)), mail) is None


@pytest.mark.parametrize(
    "entity",
    ["email:example.com@domainsbyproxy.com", "company_name:Domains By Proxy, LLC", "company_name:REDACTED FOR PRIVACY",
     "person_name:Registration Private", "company_name:N/A", "email:privacy-protect@example.org"],
)
def test_privacy_proxy_values_are_never_selectors(entity):
    http = FakeHttp()
    rt = case_runtime(http, graph_with_selectors(EMAIL_SEL), keys=keys("whoisxml"))
    res = run_module(MOD, entity, runtime=rt, options=PURPOSE)
    assert res.status is Status.SKIPPED and res.reason_code == "privacy" and "cond 4" in res.error
    assert http.calls == []


def test_reverse_organisation_whoisxml_preview_then_purchase():
    http = (FakeHttp()
            .add("POST", WHOISXML_REVERSE_URL, json=fx("whoisxml_reverse_preview_documented.json"), times=1)
            .add("POST", WHOISXML_REVERSE_URL, json=fx("whoisxml_reverse_audit_documented.json"), times=1))
    res = run_module(MOD, "company_name:Example Holdings Ltda", http, keys=keys("whoisxml"))
    assert res.status is Status.OK
    bodies = [json.loads(c["body"]) for c in http.calls]
    assert [b["mode"] for b in bodies] == ["preview", "purchase"]
    assert bodies[0]["advancedSearchTerms"] == [{"field": "RegistrantContact.Organization", "term": "Example Holdings Ltda", "exactMatch": True}]
    assert "basicSearchTerms" not in bodies[0]  # field-specific match only (cond 6)
    rev = res.attributes["reverse_whois"]
    by_domain = {d["domain"]: d for d in rev["domains"]}
    assert by_domain["example-promo.example"]["record_date"] == "2017-12-01" and by_domain["example-promo.example"]["historical"]
    assert all(p.confidence == pytest.approx(0.6) for p in res.pivots)  # organisation match field
    assert "privacy" not in res.findings[0].tags
    assert credits_spent("whoisxml") == 1  # preview free, purchase 1 credit


def test_reverse_selector_too_broad_is_not_clustered():
    http = FakeHttp().add("POST", WHOISXML_REVERSE_URL, json=fx("whoisxml_reverse_paged_synthetic.json"), times=1)
    res = run_module(MOD, "company_name:Example Holdings Ltda", http, keys=keys("whoisxml"))
    assert res.status is Status.OK and len(http.calls) == 1  # nothing purchased
    assert res.attributes["reverse_whois"]["too_broad"] is True and not res.pivots
    assert res.findings[0].title == "Reverse WHOIS selector too broad"


def test_reverse_person_name_whoisfreaks_mini():
    url = freaks_url(whois="reverse", owner="Registrant Example One", exact="true", mode="mini", page="1")
    http = FakeHttp().add("GET", url, json=fx("whoisfreaks_reverse_mini_synthetic.json"))
    rt = case_runtime(http, graph_with_selectors(NAME_SEL), keys=keys("whoisfreaks"))
    res = run_module(MOD, "person_name:Registrant Example One", runtime=rt, options=PURPOSE)
    assert res.status is Status.OK, res.error
    assert [p.entity.value for p in res.pivots] == ["examp1e-login.example"]
    assert res.pivots[0].confidence == pytest.approx(0.4)  # name: POSSIBLE (cond 6)
    assert res.findings[0].data["cr32_candidate"] is None  # one domain: no cluster
    assert "privacy" in res.findings[0].tags
    assert "registrant01@example.org" not in blob(res)


def test_reverse_whoisfreaks_documented_and_empty():
    url = freaks_url(whois="reverse", company="Example Holdings Ltda", exact="true", mode="mini", page="1")
    http = FakeHttp().add("GET", url, json=fx("whoisfreaks_reverse_ok_documented.json"))
    res = run_module(MOD, "company_name:Example Holdings Ltda", http, keys=keys("whoisfreaks"))
    assert {d["domain"] for d in res.attributes["reverse_whois"]["domains"]} == {"examp1e-login.example", "example-shop.example"}
    assert_minimised(res)
    assert "other04@example.net" not in blob(res)
    http2 = FakeHttp().add("GET", url, json=fx("whoisfreaks_reverse_empty_synthetic.json"))
    assert run_module(MOD, "company_name:Example Holdings Ltda", http2, keys=keys("whoisfreaks")).status is Status.EMPTY


def test_reverse_whoxy_empty_and_whoisxml_empty():
    http = FakeHttp().add("GET", whoxy_url(reverse="whois", company="Example Holdings Ltda", page="1"), json=fx("whoxy_reverse_empty_synthetic.json"))
    assert run_module(MOD, "company_name:Example Holdings Ltda", http, keys=keys("whoxy"), settings=WHOXY_ON).status is Status.EMPTY
    http2 = FakeHttp().add("POST", WHOISXML_REVERSE_URL, json=fx("whoisxml_reverse_empty_synthetic.json"))
    assert run_module(MOD, "company_name:Example Holdings Ltda", http2, keys=keys("whoisxml")).status is Status.EMPTY


def test_reverse_rate_limited_is_never_empty():
    st, headers, body = http_fx("whoisxml_rate_limited_429_documented.http.json")
    http = FakeHttp().add("POST", WHOISXML_REVERSE_URL, status=st, headers=headers, body=body.encode())
    res = run_module(MOD, "company_name:Example Holdings Ltda", http, keys=keys("whoisxml"))
    assert res.status is Status.RATE_LIMITED


# ======================================================================================
# helpers
# ======================================================================================


def test_minimise_contact_reads_only_four_fields():
    contact = fx("whoxy_history_ok_synthetic.json")["whois_records"][2]["registrant_contact"]
    reg = minimise_contact("whoxy", contact, load_privacy())
    assert set(reg) == {"email", "organization", "name", "country"}
    assert reg["country"] == "BR" and reg["organization"]["usable"] and not reg["organization"]["natural_person"]
    assert "5555" not in json.dumps(reg) and "Rua" not in json.dumps(reg)


def test_privacy_markers_and_confidence_and_gdpr_label():
    p = load_privacy()
    assert p.marker("REDACTED FOR PRIVACY", "organization") == "privacy_proxy"
    assert p.marker("Select Request Email Form at https://registrar.example/whois/x", "email") == "privacy_proxy"  # P003 list
    assert p.marker("Use the contact form at https://registrar.example/contact", "email") == "contact_form"
    assert p.marker("masked-owner@example.org", "email") == "placeholder_email"
    assert p.marker("hostmaster", "name") == "role_name"
    assert p.marker("Example Holdings Ltda", "organization") is None
    assert cr32_confidence("email") == ("probable", 0.7)
    assert cr32_confidence("organization") == ("probable", 0.6)
    assert cr32_confidence("name") == ("possible", 0.4)
    assert cr32_confidence("email", False) == ("possible", 0.4)
    assert is_pre_gdpr("2018-05-24 10:00:00") and not is_pre_gdpr("2018-05-25") and not is_pre_gdpr(None)
