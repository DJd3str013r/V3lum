"""saas_verification_tokens (P342): SaaS footprint from DNS TXT verification tokens.

Fixtures (tests/fixtures/saas_verification_tokens/): live DoH TXT answers of cloudflare.com (Cloudflare
and Google JSON shapes), google.com, example.com, registro.br and a NODATA name, all with every
verification-token value replaced by a deterministic placeholder (prefixes, separators, quoting,
duplicates and record counts kept); the recorded research sample gaps__saas_tenants (atlassian.com:
the stored json_extract summary plus the identical request re-recorded on 2026-11-26, scrubbed the
same way); synthetic SERVFAIL/NXDOMAIN/TC/HTML/429 shapes for the failure paths.
"""

from __future__ import annotations

import json
import re

import pytest

from tests.fakes import (
    DeadHttp,
    FakeHttp,
    fixture,
    add_dns,
    add_dns_failure,
    doh_url,
    make_runtime,
    module_fixture,
    run_module,
)
from v3lum.core.models import Severity, Status
from v3lum.modules.domain_dns import saas_verification_tokens as mod
from v3lum.modules.domain_dns.dns_records import DnsRecords
from v3lum.modules.domain_dns.saas_verification_tokens import (
    SaasVerificationTokens,
    classify_txt,
    footprint_from_doh,
    load_prefix_table,
    normalise_unknown_prefix,
    prefix_table,
    saas_footprint,
    split_txt_key,
)

NAME = "saas_verification_tokens"
CF_ONLY = {"doh_providers": ["cloudflare"]}


def fx(name: str):
    return module_fixture(NAME, name)


def serve(http: FakeHttp, name: str, body, *, provider: str = "google", status: int = 200, headers=None) -> None:
    url = doh_url(name, "TXT", provider=provider)
    if isinstance(body, (dict, list)):
        http.add("GET", url, json=body, status=status, headers=headers)
    else:
        http.add("GET", url, text=body, status=status, headers=headers)


def exchange(http: FakeHttp, name: str, doc: dict, *, provider: str) -> None:
    """Replay a recorded raw exchange ({'response': {status, headers, body}})."""
    resp = doc["response"]
    headers = {k: v for k, v in (resp.get("headers") or {}).items() if v is not None}
    http.add("GET", doh_url(name, "TXT", provider=provider), status=resp["status"], body=(resp.get("body") or "").encode(), headers=headers)


def tokens_after_separator(doh_json: dict) -> list[str]:
    """Placeholder token values of a fixture (what FC4 forbids in reports)."""
    out = []
    for ans in doh_json.get("Answer") or []:
        text = mod._unquote(ans["data"])
        if text.lower().startswith("v=spf1"):
            continue
        key, _sep, value = split_txt_key(text)
        value = value if key else text
        if len(value) >= 8:
            out.append(value)
    return out


def reported_text(res) -> str:
    """Everything a report can show: attributes, findings, pivots, links, error (never res.raw)."""
    parts = [json.dumps(res.attributes, default=str), res.error or ""]
    for f in res.findings:
        parts += [f.title, f.description, f.criterion, json.dumps(f.data, default=str)]
    parts += [p.entity.value for p in res.pivots]
    parts += [f"{label} {url}" for label, url in res.links]
    return "\n".join(parts)


# ------------------------------------------------------------------ metadata
def test_metadata_matches_the_council_decision():
    cls = SaasVerificationTokens
    assert cls.terms == "open" and cls.default_enabled is True and cls.disclosure == "third_party"
    assert cls.provider == "core_doh" and cls.sources == ("core_doh.resolvers",) and cls.hosts == ()
    assert cls.trust_tier == "trusted" and cls.shares_input is True
    assert cls.max_requests == 0 and cls.max_pivots == 0  # DoH only; FC4: no pivots ever
    hc = cls.health_check()
    assert hc.value == "example.com" and hc.expect == "empty"


# ------------------------------------------------------------------ FC2: the bundled table
def test_bundled_table_is_valid_and_covers_every_prefix_named_by_the_council():
    table = prefix_table()
    prefixes = {e.prefix for e in table.entries}
    named = [
        "atlassian-domain-verification=", "google-site-verification=", "ms=", "docusign=", "stripe-verification=",
        "zoom-domain-verification", "notion-domain-verification=", "knowbe4-site-verification=", "adobe-idp-site-verification=",
        "openai-domain-verification=", "anthropic-domain-verification", "directfedauthurl=",
        "miro-verification=", "jamf-site-verification=", "1password-site-verification=",  # synthesizer list
    ]
    assert not [p for p in named if p not in prefixes]
    assert [e.prefix for e in table.entries] == sorted(prefixes, key=lambda p: (-len(p), p))  # longest first
    assert set(table.groups) >= {"idp", "helpdesk", "e_signature", "security_awareness", "other_lures"}


def test_table_validation_refuses_broken_tables():
    good = {
        "schema": mod.TABLE_SCHEMA,
        "categories": {"idp_sso": {"label": "IdP", "hint": "h"}, "other": {"label": "other", "hint": "h"}},
        "phishing_groups": {g: {"label": g, "categories": ["idp_sso"]} for g in mod.GROUP_ORDER},
        "entries": [{"prefix": "abc-", "vendor": "A", "category": "other", "seen": "doc"},
                    {"prefix": "abc-def=", "vendor": "B", "category": "idp_sso", "seen": "live"}],
    }
    table = load_prefix_table(good)
    assert classify_txt("ABC-DEF=token", table)["vendor"] == "B"  # case-insensitive, longest prefix wins
    assert classify_txt("abc-zzz", table)["vendor"] == "A"
    dup = json.loads(json.dumps(good))
    dup["entries"].append({"prefix": "ABC-", "vendor": "C", "category": "other", "seen": "doc"})
    bad_cat = json.loads(json.dumps(good))
    bad_cat["entries"][0]["category"] = "nope"
    no_group = json.loads(json.dumps(good))
    del no_group["phishing_groups"]["idp"]
    for broken in (dup, bad_cat, no_group, {"schema": "x"}, []):
        with pytest.raises(ValueError):
            load_prefix_table(broken)


def test_classification_rules():
    table = prefix_table()
    assert classify_txt("v=spf1 include:_spf.google.com ~all", table)["kind"] == "policy"
    assert classify_txt("v=DMARC1; p=none", table)["kind"] == "policy"
    assert classify_txt("MS=ms00000001", table)["vendor"] == "Microsoft"
    assert classify_txt("DirectFedAuthUrl=https://sso.example.com/saml/1", table)["category"] == "idp_sso"
    assert classify_txt("ZOOM_verify_EXAMPLE0004", table)["vendor"] == "Zoom"  # no '=' at all
    assert classify_txt("asv=000000000000000005", table) == {"kind": "unknown_prefix", "prefix": "asv"}
    assert classify_txt("_EXAMPLE000000000000000000000002", table)["kind"] == "opaque"
    assert classify_txt("https://example.com/x", table)["kind"] != "unknown_prefix"  # a URL is not a key
    assert split_txt_key("SwdhbLH9TABXUXVsyv0iFHC0gtExgksKtVsvVoqGKZ4=")[0] is None  # base64 padding, not a key
    assert normalise_unknown_prefix("_saml-domain-challenge.00000000-0000-4000-8000-000000000026.x.cloudflare.com") == "_saml-domain-challenge"
    assert normalise_unknown_prefix("databank-domain-verification-abc123") == "databank-domain-verification"
    assert normalise_unknown_prefix("a1b2c3d4e5f6a7b8") == ""  # an id alone is never listed


# ------------------------------------------------------------------ FC5: the recorded gaps__saas_tenants fixture
def test_fc5_recorded_summary_is_could_not_verify_never_no_saas():
    gap = fx("gaps__saas_tenants.json")
    recorded = gap["requests"][0]
    assert recorded["body"] == {"Status": 0, "Answer.len": 98}
    out = footprint_from_doh(recorded["body"], prefix_table())
    assert out["outcome"] == "could_not_verify" and out["footprint"] is None and "summary" in out["reason"]


def test_fc5_rerecorded_atlassian_answer_through_the_module():
    gap = fx("gaps__saas_tenants.json")
    rec = gap["rerecorded"]
    assert rec["url"] == gap["requests"][0]["url"] == doh_url("atlassian.com", "TXT", provider="cloudflare")
    body = rec["body"]
    assert len(body["Answer"]) == gap["requests"][0]["body"]["Answer.len"] == 98  # the same RRset size as recorded
    http = FakeHttp()
    http.add("GET", rec["url"], json=body, headers=rec["headers"])
    res = run_module(SaasVerificationTokens, "domain:atlassian.com", http, settings=CF_ONLY)
    assert res.status is Status.OK
    vendors = res.attributes["saas_vendors"]
    assert len(vendors) >= 30
    assert {"Atlassian", "Microsoft", "Google", "DocuSign", "Stripe", "Zoom", "Notion", "KnowBe4", "Adobe", "OpenAI", "Anthropic", "Miro", "Jamf"} <= set(vendors)
    finding = res.findings[0]
    assert finding.title == "SaaS verification records present" and finding.severity is Severity.INFO
    groups = finding.data["phishing_simulation"]
    assert groups["idp"] == ["Microsoft"] and groups["helpdesk"] == ["Atlassian"] and groups["e_signature"] == ["DocuSign"]
    assert groups["security_awareness"] == ["KnowBe4"]
    assert finding.data["counts"]["txt_records"] == 98 and finding.data["counts"]["policy"] == 1
    assert "verification record present" in finding.description and "IdP/SSO: Microsoft" in finding.description
    assert res.pivots == []
    assert len(res.raw["txt_answer"]["records"]) == 98  # raw values: evidence only (FC4)
    assert not [t for t in tokens_after_separator(body) if t in reported_text(res)]
    http.assert_hosts_within(SaasVerificationTokens)


# ------------------------------------------------------------------ FC2-FC4: live answers
def test_cloudflare_com_live_answer_vendors_hints_and_unknown_prefixes():
    body = fx("ok_cloudflare_cf.json")
    http = FakeHttp()
    serve(http, "cloudflare.com", body, provider="cloudflare")
    res = run_module(SaasVerificationTokens, "domain:cloudflare.com", http, settings=CF_ONLY)
    assert res.status is Status.OK
    assert res.attributes["saas_vendors"] == [
        "Apple", "Atlassian", "Canva", "Cisco", "Creatopy", "Docker", "Google", "GoTo (LogMeIn)", "Jamf", "LiveRamp", "Meta",
        "Microsoft", "Miro", "OneTrust", "Salesloft", "Stripe", "Uber", "Zoom",
    ]
    # FC3: unknown prefixes listed raw, without values or embedded ids
    assert res.attributes["saas_unknown_prefixes"] == ["_saml-domain-challenge", "asv", "databank-domain-verification"]
    finding = res.findings[0]
    assert finding.criterion and finding.source == "core_doh.resolvers"
    assert "saas_footprint" in finding.tags and "phishing" not in finding.tags  # never a hostile signal
    micro = next(v for v in finding.data["vendors"] if v["vendor"] == "Microsoft")
    assert micro["records"] == 3 and micro["categories"] == ["idp_sso"]  # MS= + two DirectFedAuthUrl
    assert micro["text"].endswith("verification record present (proves a past domain verification, not current use)")
    # FC4: token values (and the federation URLs) never reach reports, only the evidence
    reported = reported_text(res)
    assert not [t for t in tokens_after_separator(body) if t in reported]
    assert "sso.example.com" not in reported and "00000000-0000-4000-8000-000000000026" not in reported
    assert "sso.example.com" in json.dumps(res.raw)


def test_resolvers_return_the_same_rrset_in_another_order_with_the_same_result():
    a = FakeHttp()
    serve(a, "cloudflare.com", fx("ok_cloudflare_cf.json"), provider="cloudflare")
    b = FakeHttp()
    serve(b, "cloudflare.com", fx("ok_cloudflare_g.json"))
    res_cf = run_module(SaasVerificationTokens, "domain:cloudflare.com", a, settings=CF_ONLY)
    res_g = run_module(SaasVerificationTokens, "domain:cloudflare.com", b)
    assert res_cf.attributes == res_g.attributes
    assert res_cf.findings[0].data == res_g.findings[0].data
    assert "edns_client_subnet=0.0.0.0%2F0" in b.urls()[0]  # Google always carries the zero ECS (A13)


def test_google_com_live_answer():
    http = FakeHttp()
    serve(http, "google.com", fx("ok_google_g.json"))
    res = run_module(SaasVerificationTokens, "domain:google.com", http)
    assert res.status is Status.OK
    assert {"DocuSign", "GlobalSign", "Microsoft", "Cisco"} <= set(res.attributes["saas_vendors"])
    assert res.attributes["saas_unknown_prefixes"] == ["work-accounts-domain-verification"]
    assert res.findings[0].data["phishing_simulation"]["e_signature"] == ["DocuSign"]


def test_multi_string_txt_records_are_joined_before_matching():
    http = FakeHttp()
    serve(http, "example.org", {"Status": 0, "Answer": [{"name": "example.org", "type": 16, "TTL": 60,
                                                          "data": '"atlassian-domain-" "verification=EXAMPLE0001"'}]}, provider="cloudflare")
    res = run_module(SaasVerificationTokens, "domain:example.org", http, settings=CF_ONLY)
    assert res.attributes["saas_vendors"] == ["Atlassian"]


# ------------------------------------------------------------------ absences (verified answers only)
def test_example_com_spf_and_opaque_token_is_empty():
    http = FakeHttp()
    serve(http, "example.com", fx("empty_example_cf.json"), provider="cloudflare")
    res = run_module(SaasVerificationTokens, "domain:example.com", http, settings=CF_ONLY)
    assert res.status is Status.EMPTY and "1 opaque token(s)" in res.error and not res.findings and not res.attributes


def test_spf_only_answer_is_empty():
    http = FakeHttp()
    serve(http, "registro.br", fx("empty_registrobr_g.json"))
    res = run_module(SaasVerificationTokens, "domain:registro.br", http)
    assert res.status is Status.EMPTY and "no SaaS verification records among 1 TXT record(s)" in res.error


def test_nodata_and_nxdomain_are_empty():
    http = FakeHttp()
    serve(http, "does-not-exist-0000.example.com", fx("nodata_cf.json"), provider="cloudflare")
    res = run_module(SaasVerificationTokens, "domain:does-not-exist-0000.example.com", http, settings=CF_ONLY)
    assert res.status is Status.EMPTY and "NODATA" in res.error
    http2 = FakeHttp()
    serve(http2, "does-not-exist-0000.example.net", fx("nxdomain_g.json"))
    res2 = run_module(SaasVerificationTokens, "domain:does-not-exist-0000.example.net", http2)
    assert res2.status is Status.EMPTY and "NXDOMAIN" in res2.error


# ------------------------------------------------------------------ FC1 / rule 5: could not verify, never 'no SaaS'
@pytest.mark.parametrize(
    ("kind", "status", "code"),
    [
        ("servfail", Status.ERROR, "error"),
        ("refused", Status.ERROR, "error"),
        ("http500", Status.ERROR, "error"),
        ("timeout", Status.ERROR, "timeout"),
        ("http429", Status.RATE_LIMITED, "rate_limited"),
        ("challenge", Status.BLOCKED, "challenge"),
    ],
)
def test_doh_failures_are_could_not_verify(kind, status, code):
    http = FakeHttp()
    add_dns_failure(http, "example.com", "TXT", kind=kind, provider="all")
    res = run_module(SaasVerificationTokens, "domain:example.com", http)
    assert res.status is status and res.reason_code == code
    assert "could not be verified" in res.error and not res.attributes and not res.findings


def test_servfail_fixture_and_dead_network():
    http = FakeHttp()
    serve(http, "example.com", fx("servfail_g.json"))
    res = run_module(SaasVerificationTokens, "domain:example.com", http)
    assert res.status is Status.ERROR and "SERVFAIL" in res.error
    dead = run_module(SaasVerificationTokens, "domain:example.com", DeadHttp())
    assert dead.status is Status.ERROR and not dead.attributes


def test_error_pages_in_http_200_and_bad_requests_are_never_answers():
    http = FakeHttp()
    page = fx("html_200.http.json")["response"]["body"]
    serve(http, "example.com", page)  # captive portal / filtering proxy in a 200 (Google)
    serve(http, "example.com", page, provider="cloudflare")
    res = run_module(SaasVerificationTokens, "domain:example.com", http)
    assert res.status is Status.ERROR and not res.attributes
    http2 = FakeHttp()
    exchange(http2, "example.com", fx("bad_request_cf.http.json"), provider="cloudflare")  # live: 400, empty body
    res2 = run_module(SaasVerificationTokens, "domain:example.com", http2, settings=CF_ONLY)
    assert res2.status is Status.ERROR and "HTTP 400" in res2.error
    http3 = FakeHttp()
    serve(http3, "example.com", "{not json")
    serve(http3, "example.com", "{not json", provider="cloudflare")
    assert run_module(SaasVerificationTokens, "domain:example.com", http3).status is Status.ERROR


def test_rate_limited_fixture_on_both_resolvers():
    http = FakeHttp()
    exchange(http, "example.com", fx("rate_limited_g.http.json"), provider="google")
    exchange(http, "example.com", fx("rate_limited_g.http.json"), provider="cloudflare")
    res = run_module(SaasVerificationTokens, "domain:example.com", http)
    assert res.status is Status.RATE_LIMITED and res.reason_code == "rate_limited"


def test_replayed_doh_json_failure_shapes():
    table = prefix_table()
    assert footprint_from_doh(fx("truncated_cf.json"), table)["outcome"] == "could_not_verify"  # TC=1
    assert footprint_from_doh(fx("servfail_g.json"), table)["outcome"] == "could_not_verify"
    assert footprint_from_doh({"error": "x"}, table)["outcome"] == "could_not_verify"
    assert footprint_from_doh(fx("nxdomain_g.json"), table)["outcome"] == "nxdomain"
    assert footprint_from_doh(fx("nodata_cf.json"), table)["outcome"] == "nodata"
    ok = footprint_from_doh(fx("ok_google_g.json"), table)
    assert ok["outcome"] == "answer" and ok["footprint"]["saas_vendors"]


def test_broken_bundled_table_is_an_error_not_an_absence(monkeypatch):
    def broken(_ctx=None):
        raise ValueError("duplicate prefix 'ms='")

    monkeypatch.setattr(mod, "prefix_table", broken)
    res = run_module(SaasVerificationTokens, "domain:example.com", FakeHttp())
    assert res.status is Status.ERROR and "prefix table" in res.error


# ------------------------------------------------------------------ FC1: reuse of the DoH answer
def test_fc1_reuses_the_txt_answer_dns_records_already_fetched():
    http = FakeHttp()
    serve(http, "cloudflare.com", fx("ok_cloudflare_g.json"))
    http.add("GET", re.compile(r"^https://dns\.google/resolve\?"), json={"Status": 0, "Answer": []})  # dns_records' other types
    rt = make_runtime(http, cache=True)
    run_module(DnsRecords, "domain:cloudflare.com", runtime=rt)
    before = len(http.calls)
    res = run_module(SaasVerificationTokens, "domain:cloudflare.com", runtime=rt)
    assert res.status is Status.OK and len(http.calls) == before  # a DoH cache hit: nothing sent


def test_fc1_at_most_one_txt_query_when_not_cached():
    http = FakeHttp()
    serve(http, "cloudflare.com", fx("ok_cloudflare_g.json"))
    res = run_module(SaasVerificationTokens, "domain:cloudflare.com", http)
    assert res.status is Status.OK
    assert http.urls() == [doh_url("cloudflare.com", "TXT")]
    assert res.requests == 0  # DoH is never charged to max_requests


def test_add_dns_helper_records_work_too():
    http = FakeHttp()
    add_dns(http, "example.net", "TXT", ["docusign=00000000-0000-4000-8000-000000000001", "v=spf1 -all"])
    res = run_module(SaasVerificationTokens, "domain:example.net", http)
    assert res.attributes["saas_vendors"] == ["DocuSign"] and res.attributes.get("saas_unknown_prefixes") is None


def test_footprint_never_carries_token_values():
    table = prefix_table()
    body = fx("ok_cloudflare_cf.json")
    records = [mod._unquote(a["data"]) for a in body["Answer"]]
    fp = saas_footprint(records, table)
    dumped = json.dumps(fp)
    assert not [t for t in tokens_after_separator(body) if t in dumped]
    assert fp["counts"]["txt_records"] == 29 and fp["counts"]["opaque"] == 2


def test_acceptance_routes_cover_the_golden_domain():
    doc = fixture("acceptance/domain/saas_verification_tokens.json")
    assert doc["schema"] == "v3lum.acceptance_routes/1" and doc["module"] == NAME
    http = FakeHttp()
    for route in doc["routes"]:
        http.add(route["method"], route["url"], status=route["status"], json=route["json"], headers=route.get("headers"))
    res = run_module(SaasVerificationTokens, "domain:example.com", http)
    assert res.status is Status.EMPTY and len(http.calls) == len(doc["routes"]) and not res.findings
