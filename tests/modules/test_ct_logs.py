"""ct_logs (P001): crt.sh + Cert Spotter + ctl.shodan.io, offline.

Fixtures in tests/fixtures/ct_logs/ (batch p1-G01-1 prep, 2026-11-26, scrubbed): live crt.sh answers for
example.com (multi-line name_value, '*.' wildcards, precertificate + leaf pairs, an e-mail SAN, a test-CA
record), a research crt.sh sample with out-of-apex and S/MIME records, a synthetic multi-tenant CDN
certificate (26 SANs over 9 registrable domains), the live crt.sh answer cut mid-record (size cap), live
Cert Spotter page 1 (7 issuances incl. an example.com/.net/.org/.edu certificate) and its empty last page
(200 + Retry-After: 3600), live ctl.shodan.io lists, crt.sh's HTML 'Unsupported output type' error-in-200
and an nginx 502 page.
"""

from __future__ import annotations

import pytest

from tests.fakes import (
    FIXTURES,
    FakeHttp,
    add_dns,
    add_dns_failure,
    add_nxdomain_everything,
    assert_no_secret,
    make_runtime,
    module_fixture,
    run_module,
)
from v3lum.core.entities import EntityType as T
from v3lum.core.http import NetworkError, Response
from v3lum.core.models import Status
from v3lum.core.orgprofile import OrgProfile
from v3lum.modules.domain_dns import ct_logs as ct
from v3lum.modules.domain_dns.ct_logs import CtLogs, HostnameSink, classify_cert_sharing, clean_ct_name, parse_crtsh, salvage_json_array

CRTSH = "https://crt.sh/?q=%25.example.com&output=json&exclude=expired"
CS = "https://api.certspotter.com/v1/issuances?domain=example.com&include_subdomains=true&expand=dns_names&expand=issuer"
CS_P2 = CS + "&after=17893124858"
CTL = "https://ctl.shodan.io/api/v1/domain/example.com/hostnames"
NO_DNS = {"ct_logs_check_liveness": False}
ALL = frozenset(CtLogs.sources)


def fx(name):
    return module_fixture(CtLogs, name)


def exchange(name):
    """status, headers and body of a recorded '*.http.json' exchange."""
    resp = fx(name)["response"]
    return resp["status"], resp.get("headers") or {}, resp.get("body")


def full_http(**overrides):
    http = FakeHttp()
    routes = {
        "crtsh": dict(json=fx("crtsh_ok.json")),
        "cs": dict(json=fx("certspotter_ok.json")),
        "cs2": dict(json=[], headers={"retry-after": "3600"}),
        "ctl": dict(json=fx("ctlshodan_ok.json")),
    }
    routes.update(overrides)
    for key, url in (("crtsh", CRTSH), ("cs", CS), ("cs2", CS_P2), ("ctl", CTL)):
        if routes[key] is not None:
            http.add("GET", url, **routes[key])
    return http


def pivots(res, relation=None, etype=None):
    return {p.entity.value: p for p in res.pivots if (relation is None or p.relation == relation) and (etype is None or p.entity.type is etype)}


def only(*sources):
    return {"allowed_sources": frozenset(sources)}


# ------------------------------------------------------------------ metadata (P001 cond 1-5)
def test_contract_metadata():
    cls = CtLogs
    assert cls.terms == "noncommercial" and cls.default_enabled is True and cls.trust_tier == "trusted"
    assert set(cls.sources) == {"crtsh.search", "sslmate.issuances", "sslmate.issuances_keyless", "shodan_ctl.hostnames"}
    assert cls.terms_sources["crtsh.search"] == "open" and cls.terms_sources["sslmate.issuances"] == "key-terms"
    assert cls.terms_sources["sslmate.issuances_keyless"] == "noncommercial" and cls.terms_sources["shodan_ctl.hostnames"] == "noncommercial"
    assert cls.hosts == ("crt.sh", "api.certspotter.com", "ctl.shodan.io")
    assert cls.optional_keys == ("certspotter",)
    assert cls.max_requests <= 10 and cls.expected_latency <= 10
    assert set(cls.settings) == {"ct_logs_budget", "ct_brand_search", "ct_logs_check_liveness"}
    assert cls.settings["ct_brand_search"].default is False  # brand mode is opt-in (cond 10)
    assert cls.settings["ct_logs_budget"].default == 30 and ct.MAX_BUDGET == 90


# ------------------------------------------------------------------ the hostname sink (cond 6, 11)
def test_name_value_split_wildcards_and_apex_boundary():
    sink = HostnameSink("example.com")
    certs = parse_crtsh(fx("crtsh_ok.json") + fx("crtsh_edge.json"), sink)
    assert sink.subdomains() == ["dev.example.com", "emudhra-lab.example.com", "products.example.com", "support.example.com", "www.example.com"]
    assert sink.wildcard_labels() == ["*.example.com"]  # '*.' stripped: a wildcard of the parent, never a name
    assert "m.testexample.com" in sink.out_of_apex and "m.testexample.com" not in sink.names  # label boundary
    assert sink.rejected["email"] >= 2  # e-mail SANs (user@example.com, subjectname@example.com)
    assert sink.rejected["not_hostname"] >= 1  # 'AS207960 Test Intermediate - example.com'
    # precertificate + leaf (same issuer and serial) are one certificate
    serials = [c["serial"] for c in certs]
    assert len(serials) == len(set(serials))
    assert sink.names["www.example.com"].sources == ["crtsh.search"]


@pytest.mark.parametrize(("raw", "expected"), [
    ("*.Example.COM.", ("example.com", True, "")),
    ("www.example.com\r", ("www.example.com", False, "")),
    ("user@example.com", (None, False, "email")),
    ("192.0.2.1", (None, False, "ip_literal")),
    ("a.*.example.com", (None, False, "wildcard_inner")),
    ("host.invalidtld", (None, False, "bad_tld")),
    ("com.br", (None, False, "public_suffix")),
    ("café.example.com", ("xn--caf-dma.example.com", False, "")),
])
def test_clean_ct_name(raw, expected):
    assert clean_ct_name(raw) == expected


def test_salvage_json_array_never_reads_a_cut_body_as_complete():
    body = '[{"id": 1, "name_value": "a.example.com"}, {"id": 2, "name_va'
    records, complete = salvage_json_array(body)
    assert records == [{"id": 1, "name_value": "a.example.com"}] and complete is False
    assert salvage_json_array("[]") == ([], True)


# ------------------------------------------------------------------ happy path (cond 4, 7, 8, 9)
def test_all_sources_merged_with_provenance():
    http = full_http()
    res = run_module(CtLogs, "domain:example.com", http, settings=NO_DNS)
    assert res.status is Status.OK and not res.partial
    assert res.attributes["subdomains"] == ["emudhra-lab.example.com", "www.example.com"]
    assert res.attributes["wildcard_cert"] == ["*.example.com"]
    assert res.attributes["first_cert_seen"] == "2023-01-27T01:21:18Z"
    summary = res.attributes["ct_summary"]
    assert summary["cert_count"] == 10  # the same certificate seen by crt.sh and Cert Spotter counts once
    assert summary["top_names"][0] == "www.example.com" and summary["sources"] == ["Cert Spotter", "crt.sh", "ctl.shodan.io"]
    assert dict(summary["issuers"])["Sectigo Limited"] == 4
    subs = pivots(res, "subdomain", T.DOMAIN)
    assert set(subs) == {"www.example.com", "emudhra-lab.example.com"} and all(p.expand for p in subs.values())
    fps = pivots(res, "has_certificate", T.CERT_FP)
    assert len(fps) == 7 and not any(p.expand for p in fps.values())  # cert sha256 -> expand=False (cond 7)
    affiliates = pivots(res, "cert_san")
    assert set(affiliates) == {"example.net", "example.org", "example.edu"} and not any(p.expand for p in affiliates.values())
    assert set(res.source_statuses) == {"crtsh.search", "sslmate.issuances_keyless", "shodan_ctl.hostnames"}
    assert all(s["status"] == "ok" for s in res.source_statuses.values())
    finding = next(f for f in res.findings if f.title == "Certificate Transparency summary")
    assert finding.severity.label == "info" and "lower bound" in finding.description and "registration date" in finding.description
    assert any(url.startswith("https://crt.sh/?q=%25.example.com") for _label, url in res.links)
    assert res.requests == 4
    http.assert_hosts_within(CtLogs)


def test_first_cert_seen_is_never_a_registration_date():
    res = run_module(CtLogs, "domain:example.com", full_http(), settings=NO_DNS)
    assert "created" not in res.attributes and "domain_age_days" not in res.attributes


def test_empty_answers_are_empty():
    http = full_http(crtsh=dict(json=fx("crtsh_empty.json")), cs=dict(json=[]), cs2=None, ctl=dict(json=fx("ctlshodan_empty.json")))
    res = run_module(CtLogs, "domain:example.com", http, settings=NO_DNS)
    assert res.status is Status.EMPTY and not res.findings and not res.pivots


# ------------------------------------------------------------------ could not verify (cond 4, 5, 11)
def test_crtsh_timeout_still_yields_cert_spotter_names_with_partial_status():
    http = full_http(crtsh=dict(error=NetworkError("ReadTimeout contacting crt.sh: timed out", kind="ReadTimeout")))
    res = run_module(CtLogs, "domain:example.com", http, settings=NO_DNS)
    assert res.status is Status.OK and res.partial and res.stop_reason == "deadline"
    assert "www.example.com" in res.attributes["subdomains"]
    assert res.source_statuses["crtsh.search"]["status"] == "error" and res.source_statuses["crtsh.search"]["reason_code"] == "timeout"
    assert "crt.sh" in res.error and "could not verify" in res.error


def test_crtsh_timeout_alone_is_could_not_verify_never_no_certificates():
    http = full_http(crtsh=dict(error=NetworkError("ReadTimeout contacting crt.sh: timed out", kind="ReadTimeout")))
    res = run_module(CtLogs, "domain:example.com", http, settings=NO_DNS, **only("crtsh.search"))
    assert res.status is Status.ERROR and res.reason_code == "timeout"
    assert "could not verify" in res.error and not res.findings and not res.attributes


def test_crtsh_502_after_retries_is_could_not_verify():
    http = FakeHttp().add("GET", CRTSH, status=502, text=fx("crtsh_502.html"))
    res = run_module(CtLogs, "domain:example.com", http, settings=NO_DNS, **only("crtsh.search"))
    assert res.status is Status.ERROR and "could not verify" in res.error
    assert len(http.calls) == 3  # the crtsh profile retries 502/503/timeouts twice inside the budget (cond 4)


def test_crtsh_error_in_200_is_detected():
    http = FakeHttp().add("GET", CRTSH, text=fx("crtsh_error_in_200.html"))
    res = run_module(CtLogs, "domain:example.com", http, settings=NO_DNS, **only("crtsh.search"))
    assert res.status is Status.ERROR and "unsupported output type" in res.error.lower()
    assert not res.attributes


def test_body_cut_mid_record_keeps_records_before_the_cut():
    text = (FIXTURES / "ct_logs" / "crtsh_truncated.json").read_text(encoding="utf-8")  # cut mid-record: not valid JSON
    http = FakeHttp().add("GET", CRTSH, body=text.encode(), headers={"content-type": "application/json"})
    res = run_module(CtLogs, "domain:example.com", http, settings=NO_DNS, **only("crtsh.search"))
    assert res.status is Status.OK and res.partial
    assert res.source_statuses["crtsh.search"]["status"] == "ok"
    assert "never read as complete" in res.error
    assert res.attributes["wildcard_cert"] == ["*.example.com"]


class TruncatingHttp(FakeHttp):
    """Marks crt.sh answers as cut at the core size cap (Response.truncated)."""

    def send(self, method, url, **kw):
        resp = super().send(method, url, **kw)
        if url.startswith("https://crt.sh/"):
            return Response(resp.status, resp.url, resp.headers, resp.content, resp.elapsed, False, True, [])
        return resp


def test_core_size_cap_truncation_is_partial_and_cert_spotter_still_answers():
    http = TruncatingHttp()
    http.add("GET", CRTSH, json=fx("crtsh_ok.json"))
    http.add("GET", CS, json=fx("certspotter_ok.json")).add("GET", CS_P2, json=[])
    res = run_module(CtLogs, "domain:example.com", http, settings=NO_DNS, **only("crtsh.search", "sslmate.issuances_keyless"))
    assert res.status is Status.OK and res.partial  # never parsed as complete (cond 5)
    assert "size cap" in res.error
    assert "emudhra-lab.example.com" in res.attributes["subdomains"]  # Cert Spotter fills in


def test_429_is_rate_limited():
    status, headers, body = exchange("certspotter_rate_limited.http.json")
    http = FakeHttp().add("GET", CS, status=status, headers=headers, json=body)
    res = run_module(CtLogs, "domain:example.com", http, settings=NO_DNS, **only("sslmate.issuances_keyless"))
    assert res.status is Status.RATE_LIMITED and res.reason_code == "rate_limited"


def test_challenge_page_is_blocked():
    page = "<!DOCTYPE html><html><head><title>Just a moment...</title></head><body>cf-chl-widget</body></html>"
    http = FakeHttp().add("GET", CTL, status=403, text=page)
    res = run_module(CtLogs, "domain:example.com", http, settings=NO_DNS, **only("shodan_ctl.hostnames"))
    assert res.status is Status.BLOCKED and res.reason_code == "challenge"


def test_ctl_error_object_in_200_is_detected():
    http = FakeHttp().add("GET", CTL, json={"error": "Request timed out"})
    res = run_module(CtLogs, "domain:example.com", http, settings=NO_DNS, **only("shodan_ctl.hostnames"))
    assert res.status is Status.ERROR and not res.attributes


def test_malformed_and_unexpected_answers_are_never_empty():
    for body in ("{not json", '{"certs": []}'):
        http = FakeHttp().add("GET", CRTSH, body=body.encode(), headers={"content-type": "application/json"})
        res = run_module(CtLogs, "domain:example.com", http, settings=NO_DNS, **only("crtsh.search"))
        assert res.status is Status.ERROR and "could not verify" in res.error, body
    http = FakeHttp().add("GET", CS, json={"code": "bad_query"})
    assert run_module(CtLogs, "domain:example.com", http, settings=NO_DNS, **only("sslmate.issuances_keyless")).status is Status.ERROR


def test_cert_spotter_400_error_object():
    status, headers, body = exchange("certspotter_bad_query.http.json")
    http = FakeHttp().add("GET", CS, status=status, headers=headers, json=body)
    res = run_module(CtLogs, "domain:example.com", http, settings=NO_DNS, **only("sslmate.issuances_keyless"))
    assert res.status is Status.ERROR


# ------------------------------------------------------------------ Cert Spotter keys and pagination (cond 3, 5)
def test_keyed_cert_spotter_sends_only_a_bearer_header():
    key = "certspotter-test-key-0123456789"
    http = FakeHttp()
    http.add("GET", CS, json=fx("certspotter_ok.json"), match_headers={"authorization": f"Bearer {key}"})
    http.add("GET", CS_P2, json=[], match_headers={"authorization": f"Bearer {key}"})
    res = run_module(CtLogs, "domain:example.com", http, keys={"certspotter": key}, settings=NO_DNS, **only("sslmate.issuances"))
    assert res.status is Status.OK and res.source_statuses["sslmate.issuances"]["status"] == "ok"
    assert all(key not in c["url"] for c in http.calls)  # never in the URL
    assert_no_secret(key, res.to_dict(), res.raw)


def test_keyed_source_without_key_needs_key():
    res = run_module(CtLogs, "domain:example.com", FakeHttp(), settings=NO_DNS, **only("sslmate.issuances"))
    assert res.status is Status.NEEDS_KEY


def test_refused_key_is_needs_key_for_that_source():
    http = FakeHttp().add("GET", CS, status=401, json={"code": "unauthorized", "message": "invalid key"})
    http.add("GET", CRTSH, json=fx("crtsh_ok.json"))
    res = run_module(CtLogs, "domain:example.com", http, keys={"certspotter": "bad-key-0123456789"}, settings=NO_DNS,
                     **only("sslmate.issuances", "crtsh.search"))
    assert res.status is Status.OK  # crt.sh answered
    assert res.source_statuses["sslmate.issuances"]["status"] == "needs_key"


def test_pagination_follows_after_and_stops_at_five_pages():
    http = FakeHttp()
    page = fx("certspotter_ok.json")
    http.add("GET", CS, json=page)
    for i in range(1, 6):
        http.add("GET", f"{CS}&after={17893124858 + i - 1}" if i > 1 else CS_P2, json=[dict(page[-1], id=str(17893124858 + i))])
    res = run_module(CtLogs, "domain:example.com", http, settings=NO_DNS, **only("sslmate.issuances_keyless"))
    assert res.status is Status.OK and res.partial and res.stop_reason == "request_cap"  # page cap reached: more issuances may exist
    assert len([c for c in http.calls if "certspotter" in c["url"]]) == 5
    assert "page cap" in res.error


def test_retry_after_on_the_empty_last_page_is_not_a_rate_limit():
    status, headers, body = exchange("certspotter_last_page.http.json")
    http = FakeHttp().add("GET", CS, json=fx("certspotter_ok.json")).add("GET", CS_P2, status=status, headers=headers, body=body.encode())
    res = run_module(CtLogs, "domain:example.com", http, settings=NO_DNS, **only("sslmate.issuances_keyless"))
    assert res.status is Status.OK and not res.partial


# ------------------------------------------------------------------ once per registrable domain (cond 7, 11)
def test_a_subdomain_triggers_no_ct_request():
    http = FakeHttp()
    res = run_module(CtLogs, "domain:www.example.com", http)
    assert res.status is Status.SKIPPED and res.reason_code == "not_applicable"
    assert http.calls == []


def test_public_suffix_and_unknown_tld_are_not_applicable():
    for value in ("com.br", "example.invalidtld"):
        assert run_module(CtLogs, f"domain:{value}", FakeHttp()).status is Status.SKIPPED


def test_historical_names_get_expand_false_and_unresolved_stay_unverified():
    http = full_http()
    add_dns(http, "www.example.com", "A", ["93.184.215.14"])
    add_dns_failure(http, "emudhra-lab.example.com", "A", kind="servfail")
    res = run_module(CtLogs, "domain:example.com", http)
    subs = pivots(res, "subdomain")
    assert subs["www.example.com"].expand is True
    assert res.attributes["ct_names_unresolved"] == ["emudhra-lab.example.com"]
    assert "unresolved" in subs["emudhra-lab.example.com"].note
    http2 = full_http()
    add_dns(http2, "www.example.com", "A", ["93.184.215.14"])
    add_nxdomain_everything(http2)
    res2 = run_module(CtLogs, "domain:example.com", http2)
    subs2 = pivots(res2, "subdomain")
    assert res2.attributes["ct_names_historical"] == ["emudhra-lab.example.com"]
    assert subs2["emudhra-lab.example.com"].expand is False and "historical" in subs2["emudhra-lab.example.com"].note
    assert [p.entity.value for p in res2.pivots if p.relation == "subdomain"][0] == "www.example.com"  # live names first


# ------------------------------------------------------------------ shared certificates (cond 8, 11)
def test_a_multi_tenant_certificate_links_nothing():
    http = FakeHttp().add("GET", CRTSH, json=fx("crtsh_multitenant.json"))
    res = run_module(CtLogs, "domain:example.com", http, settings=NO_DNS, **only("crtsh.search"))
    assert res.status is Status.OK
    assert not pivots(res, "cert_san")
    shared = res.attributes["shared_cert"]
    assert len(shared) == 1 and shared[0]["san_count"] == 26 and shared[0]["registrable_domains"] == 9


def test_cdn_pattern_marks_a_small_certificate_as_shared():
    verdict = classify_cert_sharing(["sni12345.cloudflaressl.com", "example.com", "other.example"])
    assert verdict["shared"] and "pattern" in verdict["reason"]
    assert classify_cert_sharing(["example.com", "example.net", "www.example.org"])["shared"] is False


def test_smime_certificate_creates_no_affiliate():
    http = FakeHttp().add("GET", CRTSH, json=fx("crtsh_edge.json"))
    res = run_module(CtLogs, "domain:example.com", http, settings=NO_DNS, **only("crtsh.search"))
    assert "testexample.com" in pivots(res, "cert_san")  # a real SAN of an example.com certificate
    assert not any("jivesoftware" in v for v in pivots(res))  # e-mail-only certificates link nothing


# ------------------------------------------------------------------ brand mode (cond 10)
BRAND_URL = "https://crt.sh/?q=%25examplebrand%25&output=json&exclude=expired"
PROFILE = {"domains": [{"name": "example.com", "verification": "confirmed"}], "brands": [{"keyword": "ExampleBrand"}]}


def _brand_records():
    rec = dict(fx("crtsh_ok.json")[0])
    return [dict(rec, name_value="login.examplebrand-secure.com\nexamplebrand.example.com", serial_number="aa01", id=1),
            dict(rec, name_value="shop.examplebrand-login.net", serial_number="aa02", id=2)]


def test_brand_search_is_off_by_default():
    http = full_http()
    run_module(CtLogs, "domain:example.com", http, settings=NO_DNS, org_profile=OrgProfile.from_dict(PROFILE))
    assert not any("examplebrand" in c["url"] for c in http.calls)


def test_brand_search_for_an_own_seed_gives_lookalike_pivots():
    http = full_http()
    http.add("GET", BRAND_URL, json=_brand_records())
    res = run_module(CtLogs, "domain:example.com", http, settings={**NO_DNS, "ct_brand_search": True},
                     org_profile=OrgProfile.from_dict(PROFILE), case_id="case-brand-1")
    looks = pivots(res, "lookalike")
    assert set(looks) == {"examplebrand-secure.com", "examplebrand-login.net"}  # own domains excluded
    assert not any(p.expand for p in looks.values())
    assert any(f.title.startswith("Certificates naming org brands") for f in res.findings)
    # one identity search per brand and scan
    http2 = full_http()
    run_module(CtLogs, "domain:example.com", http2, settings={**NO_DNS, "ct_brand_search": True},
               org_profile=OrgProfile.from_dict(PROFILE), case_id="case-brand-1")
    assert not any("examplebrand" in c["url"] for c in http2.calls)


def test_brand_search_needs_an_org_profile_domain_seed():
    http = full_http()
    run_module(CtLogs, "domain:example.com", http, settings={**NO_DNS, "ct_brand_search": True}, org_profile=OrgProfile.from_dict({"brands": ["examplebrand"]}))
    assert not any("examplebrand" in c["url"] for c in http.calls)
    http2 = full_http()
    run_module(CtLogs, "domain:example.com", http2, settings={**NO_DNS, "ct_brand_search": True}, org_profile=OrgProfile.from_dict(PROFILE), is_seed=False)
    assert not any("examplebrand" in c["url"] for c in http2.calls)


# ------------------------------------------------------------------ licence filtering (cond 3) and caps
def test_only_allowed_sources_are_queried():
    http = FakeHttp().add("GET", CRTSH, json=fx("crtsh_ok.json"))
    res = run_module(CtLogs, "domain:example.com", http, settings=NO_DNS, **only("crtsh.search"))
    assert res.status is Status.OK and {c["url"] for c in http.calls} == {CRTSH}  # crt.sh alone keeps the module useful
    assert set(res.source_statuses) == {"crtsh.search"}


def test_budget_setting_is_bounded():
    rt = make_runtime(FakeHttp(), settings={"ct_logs_budget": 1000})
    ctx = rt.context(CtLogs)
    assert ct._budget(ctx) == ct.MAX_BUDGET
    assert frozenset(ctx.allowed_sources) == ALL
