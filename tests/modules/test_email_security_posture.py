"""email_security_posture (P002): SPF/DMARC/DKIM/MTA-STS/TLS-RPT/BIMI/CAA/DNSSEC over DoH, offline.

Fixtures in tests/fixtures/email_security_posture/ (batch p1-G01-1 prep, 2026-11-26):
* answer maps ``{"domain", "expected", "answers": {"<name> <TYPE>": <DoH JSON>}}`` - an include loop, a
  12-lookup tree, the live github.com tree at exactly 10/10 lookups (derived), three void lookups, an
  org-profile domain with +all and p=none, a third-party subdomain without DMARC, the RFC 7489
  external-report authorization records and google.com TLS-RPT/BIMI/MTA-STS (live, Google format);
* single live DoH answers (Google unquoted / Cloudflare quoted TXT): cloudflare.com DMARC, example.com
  DMARC/DS/MX (null MX)/TXT, selector1._domainkey.example.com (null key), google.com MTA-STS/CAA,
  nic.br TXT/DMARC; a SERVFAIL in the live Google shape;
* a dead DoH exchange (HTML 503).
"""

from __future__ import annotations

import json
import re
from pathlib import Path

from tests.fakes import DeadHttp, FakeHttp, add_dns, add_dns_failure, add_nxdomain_everything, doh_url, module_fixture, run_module
from v3lum.core import vocab
from v3lum.core.entities import EntityType as T
from v3lum.core.models import Status
from v3lum.core.orgprofile import OrgProfile
from v3lum.modules.domain_dns import email_security_posture as esp
from v3lum.modules.domain_dns.email_security_posture import Answer, EmailSecurityPosture, dkim_summary, evaluate_spf, parse_dmarc, parse_spf

SELECTORS_FILE = Path(__file__).resolve().parents[2] / "v3lum" / "data" / "email_security_posture" / "dkim_selectors.json"
SELECTORS = json.loads(SELECTORS_FILE.read_text(encoding="utf-8"))["selectors"]
ANY_DOH = re.compile(r"^https://(dns\.google/resolve|cloudflare-dns\.com/dns-query)\?")
SUMMARY = "E-mail security posture summary"


def fx(name):
    return module_fixture(EmailSecurityPosture, name)


def load_answers(http, name, *, catch_all=True):
    """Serve an answer-map fixture on the Google DoH URLs (+ NXDOMAIN for every other name)."""
    data = fx(name)
    for key, answer in data["answers"].items():
        qname, rtype = key.rsplit(" ", 1)
        http.add("GET", doh_url(qname, rtype), json=answer)
    if catch_all:
        add_nxdomain_everything(http)
    return data


def own(domain):
    return OrgProfile.from_dict({"domains": [{"name": domain, "verification": "confirmed"}]})


def run(entity, http, **kw):
    return run_module(EmailSecurityPosture, entity, http, **kw)


def titles(res):
    return {f.title: f for f in res.findings}


def resolver_from(answers):
    """A resolve(name, rtype) over an answer map, for the pure SPF evaluator."""

    def resolve(name, rtype):
        ans = answers.get(f"{name} {rtype}")
        if ans is None:
            return Answer("NXDOMAIN")
        status = {0: "NOERROR", 2: "SERVFAIL", 3: "NXDOMAIN"}[ans["Status"]]
        return Answer(status, [a["data"] for a in ans.get("Answer") or []] if status == "NOERROR" else [])

    return resolve


# ------------------------------------------------------------------ metadata (P002 cond 1, 9)
def test_contract_metadata():
    cls = EmailSecurityPosture
    assert (cls.provider, cls.sources, cls.hosts, cls.max_requests) == ("core_doh", ("core_doh.resolvers",), (), 0)
    assert cls.terms == "open" and cls.default_enabled is True
    assert cls.accepts == frozenset({T.DOMAIN, T.EMAIL})
    for name in ("spf_lookups", "spf_void_lookups", "dmarc_pct", "dmarc_sp", "dmarc_rua_external", "dkim_selectors", "mta_sts", "tls_rpt", "bimi",
                 "third_party_mail_cidrs", "email_posture"):
        assert vocab.is_known_attribute(name), name
    for rel in ("spf_include", "spf_authorized"):
        assert vocab.is_known_relation(rel), rel


def test_bundled_selector_list_has_30_unique_names():
    assert len(SELECTORS) == len(set(SELECTORS)) == esp.MAX_SELECTORS


# ------------------------------------------------------------------ parsers
def test_parse_spf_terms_and_errors():
    parsed = parse_spf("v=spf1 ip4:192.0.2.0/24 ip6:2001:db8::/32 a mx:example.net/24 -include:_spf.example.net redirect=_spf.example.org ~all")
    assert [m["mechanism"] for m in parsed["mechanisms"]] == ["ip4", "ip6", "a", "mx", "include", "all"]
    assert parsed["redirect"] == "_spf.example.org" and not parsed["errors"]
    bad = parse_spf("v=spf1 ip4:2001:db8::1 foo:bar include -all")
    assert len(bad["errors"]) == 3 and all(e.startswith("permerror") for e in bad["errors"])


def test_parse_dmarc_tags():
    parsed = parse_dmarc("v=DMARC1; p=quarantine; sp=none; pct=25; rua=mailto:agg@example.net!10m,https://example.org/x; ruf=mailto:f@example.com")
    assert (parsed["p"], parsed["sp"], parsed["pct"], parsed["valid"]) == ("quarantine", "none", 25, True)
    assert [u["domain"] for u in parsed["rua"]] == ["example.net", None] and parsed["ruf"][0]["domain"] == "example.com"
    assert parse_dmarc("v=DMARC1; p=maybe")["valid"] is False
    assert parse_dmarc("v=DMARC1; p=reject; pct=500")["errors"] == ["invalid pct= tag"]


# ------------------------------------------------------------------ SPF evaluator (cond 2, 10)
def test_include_loop_is_a_permerror():
    data = fx("spf_include_loop.json")
    spf = evaluate_spf(data["domain"], resolver_from(data["answers"]))
    assert spf["status"] == "permerror" and any("include loop" in e for e in spf["errors"])


def test_more_than_ten_lookups_is_a_permerror():
    data = fx("spf_tree_over_limit.json")
    spf = evaluate_spf(data["domain"], resolver_from(data["answers"]))
    assert spf["spf_lookups"] == data["expected"]["spf_lookups"] == 12 and spf["status"] == "permerror"
    assert any("too many DNS lookups (12 > 10)" in e for e in spf["errors"])


def test_github_tree_is_exactly_at_the_limit():
    data = fx("spf_tree_at_limit.json")
    spf = evaluate_spf(data["domain"], resolver_from(data["answers"]))
    assert (spf["spf_lookups"], spf["spf_void_lookups"], spf["status"]) == (10, 0, "ok")
    assert len(spf["candidate_cidrs"]) == 8 and spf["all"] == "~all"


def test_void_lookups_above_two_are_a_permerror():
    data = fx("spf_void.json")
    spf = evaluate_spf(data["domain"], resolver_from(data["answers"]))
    assert spf["spf_void_lookups"] == 3 and spf["status"] == "permerror"
    assert any("too many void lookups (3 > 2)" in e for e in spf["errors"])


def test_query_cap_and_depth_are_bounded():
    calls = []

    def resolve(name, rtype):
        calls.append(name)
        depth = name.count(".")
        return Answer("NOERROR", [f"v=spf1 include:a{depth}.{name} include:b{depth}.{name} -all"])

    spf = evaluate_spf("example.com", resolve)
    assert len(calls) == esp.SPF_MAX_QUERIES and spf["partial"] is True
    assert spf["status"] == "permerror" and any("recursion depth" in e for e in spf["errors"])
    assert any("DoH query cap reached" in w for w in spf["warnings"])


def test_unverified_txt_is_could_not_verify():
    spf = evaluate_spf("example.com", lambda name, rtype: Answer("SERVFAIL"))
    assert spf["status"] == "could_not_verify" and spf["spf_lookups"] == 0 and not spf["tree"]


def test_unverified_include_is_temperror_not_absence():
    answers = {"example.com TXT": {"Status": 0, "Answer": [{"data": "v=spf1 include:_spf.example.net -all"}]},
               "_spf.example.net TXT": {"Status": 2}}
    spf = evaluate_spf("example.com", resolver_from(answers))
    assert spf["status"] == "temperror" and spf["partial"] is True


def test_dkim_summary_wording():
    nx = {s: Answer("NXDOMAIN") for s in ("a", "b")}
    assert dkim_summary(nx, 2)["wording"] == "not determined (2 common selectors checked)"
    mixed = {"a": Answer("NOERROR", ["v=DKIM1; p=MIIB"]), "b": Answer("SERVFAIL")}
    out = dkim_summary(mixed, 2)
    assert out["dkim_selectors"] == ["a"] and out["could_not_verify"] == ["b"] and "could not be verified" in out["wording"]


# ------------------------------------------------------------------ module runs (cond 4-10)
def test_github_posture_mines_only_direct_cidrs_and_lists_saas_netblocks():
    http = FakeHttp()
    load_answers(http, "spf_tree_at_limit.json")
    res = run("domain:github.com", http)
    assert res.status is Status.OK
    assert res.attributes["spf_lookups"] == 10 and res.attributes["spf_void_lookups"] == 0 and res.attributes["spf_status"] == "ok"
    direct = {p.entity.value: p for p in res.pivots if p.relation == "spf_authorized"}
    assert set(direct) == {"192.30.252.0/22", "172.170.10.240/28", "40.78.162.192/28", "172.170.3.48/28",
                           "62.253.227.114", "166.78.69.169", "166.78.69.170", "166.78.71.131"}
    assert {p.entity.type for p in direct.values()} == {T.CIDR, T.IPV4}
    assert not any(p.expand for p in direct.values())  # candidates until RDAP/NIC.br confirms ownership (cond 6)
    third = res.attributes["third_party_mail_cidrs"]
    third_cidrs = {c["cidr"] for c in third}
    assert "40.92.0.0/15" in third_cidrs and "74.125.0.0/16" in third_cidrs
    assert not any(p.entity.value in third_cidrs for p in res.pivots)  # third-party mail netblocks never pivot (cond 5)
    assert not any(p.relation == "spf_include" for p in res.pivots)  # every include is a known mail SaaS
    assert len(res.attributes["mail_providers"]) >= 6
    assert [f.title for f in res.findings] == [SUMMARY]
    http.assert_hosts_within(EmailSecurityPosture)


def test_over_limit_tree_pivots_non_vendor_includes():
    http = FakeHttp()
    load_answers(http, "spf_tree_over_limit.json")
    res = run("domain:example.org", http)
    assert res.attributes["spf_status"] == "permerror" and res.attributes["spf_lookups"] == 12
    includes = {p.entity.value: p for p in res.pivots if p.relation == "spf_include"}
    assert set(includes) == {"spf1.example.net", "spf2.example.net", "spf3.example.net", "spf1a.example.net", "spf1b.example.net", "spf3a.example.net"}
    assert not any(p.expand for p in includes.values())
    assert [p.entity.value for p in res.pivots if p.relation == "spf_authorized"] == ["192.0.2.0/24"]
    assert [f.title for f in res.findings] == [SUMMARY]  # third party: the summary only


def test_dead_doh_never_yields_a_missing_finding():
    res = run("domain:example.com", DeadHttp(), org_profile=own("example.com"))
    assert res.status is Status.ERROR and "could not verify" in res.error
    assert not res.findings and not res.pivots
    assert not any(k in res.attributes for k in ("dmarc", "spf_status", "email_posture"))


def test_dead_doh_html_503_never_yields_a_missing_finding():
    resp = fx("doh_dead.http.json")["response"]
    http = FakeHttp().add("GET", ANY_DOH, status=resp["status"], text=resp["body"], headers=resp["headers"])
    res = run("domain:example.org", http, org_profile=own("example.org"))
    assert res.status is Status.ERROR and not res.findings and not res.attributes.get("dmarc")


def test_servfail_on_txt_dmarc_and_mx_is_could_not_verify():
    http = FakeHttp()
    for name, rtype in (("example.org", "TXT"), ("_dmarc.example.org", "TXT"), ("example.org", "MX")):
        add_dns_failure(http, name, rtype, kind="servfail")
    add_nxdomain_everything(http)
    res = run("domain:example.org", http, org_profile=own("example.org"))
    assert res.status is Status.ERROR and not res.findings


def test_third_party_without_dmarc_gives_one_info_finding():
    http = FakeHttp()
    load_answers(http, "thirdparty_no_dmarc.json")
    res = run("domain:mail.example.net", http)
    assert res.status is Status.OK
    assert [(f.title, f.severity.label) for f in res.findings] == [(SUMMARY, "info")]
    table = res.attributes["email_posture"]
    assert table["dmarc"] == "absent" and table["dkim"].startswith("not checked (subdomain")
    assert not any("_domainkey" in c["url"] for c in http.calls)  # subdomain: no DKIM probing (cond 8)
    assert res.attributes["third_party_mail_cidrs"][0]["cidr"] == "40.92.0.0/15"


def test_own_domain_gets_medium_and_high():
    http = FakeHttp()
    load_answers(http, "own_domain_weak.json")
    res = run("domain:example.com", http, org_profile=own("example.com"))
    found = titles(res)
    assert set(found) == {"DMARC policy p=none on an own domain (monitoring only)", "SPF allows any sender (+all) on an own domain", SUMMARY}
    assert found["DMARC policy p=none on an own domain (monitoring only)"].severity.label == "medium"
    plus_all = found["SPF allows any sender (+all) on an own domain"]
    assert plus_all.severity.label == "high" and plus_all.criterion and plus_all.attack == ["T1566", "T1684.001"]
    assert "weak_email_security" in plus_all.tags
    assert found[SUMMARY].severity.label == "info"
    assert res.attributes["dmarc_policy"] == "none" and res.attributes["dmarc_pct"] == 100


def test_same_domain_outside_the_org_profile_is_info_only():
    http = FakeHttp()
    load_answers(http, "own_domain_weak.json")
    res = run("domain:example.com", http)
    assert [(f.title, f.severity.label) for f in res.findings] == [(SUMMARY, "info")]


def test_own_domain_without_dmarc_is_medium_but_third_party_is_info():
    for org, expected in ((own("example.net"), {"medium", "info"}), (None, {"info"})):
        http = FakeHttp()
        add_dns(http, "example.net", "TXT", ["v=spf1 -all"])
        add_nxdomain_everything(http)
        res = run("domain:example.net", http, org_profile=org)
        assert {f.severity.label for f in res.findings} == expected
        if org is not None:
            assert "DMARC record missing on an own domain" in titles(res)


def test_own_domain_spf_permerror_is_medium():
    http = FakeHttp()
    load_answers(http, "spf_tree_over_limit.json")
    res = run("domain:example.org", http, org_profile=own("example.org"))
    permerror = titles(res)["SPF permerror on an own domain"]
    assert permerror.severity.label == "medium" and "too many DNS lookups" in permerror.criterion
    assert permerror.attack == []  # a broken SPF record is not a spoofing technique by itself


def test_servfail_on_dmarc_is_could_not_verify_never_missing():
    http = FakeHttp()
    add_dns(http, "example.org", "TXT", ["v=spf1 -all"])
    http.add("GET", doh_url("_dmarc.example.org", "TXT"), json=fx("servfail_google.json"))
    add_nxdomain_everything(http)
    res = run("domain:example.org", http, org_profile=own("example.org"))
    assert res.status is Status.OK
    assert [f.title for f in res.findings] == [SUMMARY]  # never 'DMARC missing' on SERVFAIL (rule 5)
    assert res.attributes["email_posture"]["dmarc"] == "could not verify"
    assert res.source_statuses["core_doh.resolvers"]["status"] == "error" and "_dmarc" in res.error


def test_subdomain_uses_the_organisational_dmarc_sp():
    http = FakeHttp()
    add_dns(http, "mail.example.com", "TXT", ["v=spf1 -all"])
    http.add("GET", doh_url("_dmarc.example.com", "TXT"), json=fx("dmarc_example_cf.json"))
    add_nxdomain_everything(http)
    res = run("domain:mail.example.com", http)
    assert res.attributes["dmarc_policy"] == "reject" and res.attributes["dmarc_sp"] == "reject"
    assert "organisational domain example.com" in res.attributes["email_posture"]["dmarc"]
    asked = [c["url"] for c in http.calls]
    assert any("name=_dmarc.mail.example.com" in u for u in asked) and any("name=_dmarc.example.com" in u for u in asked)


def test_external_report_destinations_are_checked():
    http = FakeHttp()
    add_dns(http, "cloudflare.com", "TXT", ["v=spf1 -all"])
    http.add("GET", doh_url("_dmarc.cloudflare.com", "TXT"), json=fx("dmarc_cloudflare_google.json"))
    load_answers(http, "dmarc_report_auth.json")
    res = run("domain:cloudflare.com", http)
    assert res.attributes["dmarc_rua_external"] == [{"dest_domain": "dmarc-reports.cloudflare.net", "authorized": True}]
    assert not any("dmarc-reports" in str(p.entity.value) for p in res.pivots)  # report vendors are never pivots


def test_unauthorized_external_destination():
    http = FakeHttp()
    add_dns(http, "example.org", "TXT", ["v=spf1 -all"])
    add_dns(http, "_dmarc.example.org", "TXT", ["v=DMARC1; p=reject; rua=mailto:agg@reports.example.net"])
    load_answers(http, "dmarc_report_auth.json")
    res = run("domain:example.org", http)
    assert res.attributes["dmarc_rua_external"] == [{"dest_domain": "reports.example.net", "authorized": False}]
    assert not any(p.entity.value == "reports.example.net" for p in res.pivots)


def test_dkim_null_keys_are_never_dkim_missing():
    http = FakeHttp()
    null_key = fx("dkim_null_key_cf.json")
    for sel in SELECTORS:
        http.add("GET", doh_url(f"{sel}._domainkey.example.com", "TXT"), json=null_key)
    add_nxdomain_everything(http)
    res = run("domain:example.com", http)
    dkim = res.attributes["email_posture"]["dkim"]
    assert "missing" not in dkim and dkim == f"only null/revoked DKIM keys published ({len(SELECTORS)} common selectors checked)"
    assert "dkim_selectors" not in res.attributes  # recorded only when usable keys are found


def test_dkim_not_determined_wording():
    http = FakeHttp()
    add_nxdomain_everything(http)
    res = run("domain:example.com", http)
    assert res.attributes["email_posture"]["dkim"] == f"not determined ({len(SELECTORS)} common selectors checked)"
    assert sum("_domainkey.example.com" in c["url"] for c in http.calls) == len(SELECTORS)


def test_dkim_keys_found():
    http = FakeHttp()
    add_dns(http, "google._domainkey.example.com", "TXT", ["v=DKIM1; k=rsa; p=MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAexample"])
    add_dns(http, "selector1._domainkey.example.com", "TXT", ["v=DKIM1; k=rsa; p=MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAother"])
    add_nxdomain_everything(http)
    res = run("domain:example.com", http)
    assert res.attributes["dkim_selectors"] == ["google", "selector1"]
    assert res.attributes["email_posture"]["dkim"] == "DKIM keys found for selectors: google, selector1"


def test_mta_sts_tls_rpt_bimi_and_caa():
    http = FakeHttp()
    load_answers(http, "tlsrpt_bimi_google.json", catch_all=False)
    http.add("GET", doh_url("google.com", "CAA"), json=fx("caa_google_google.json"))
    add_nxdomain_everything(http)
    res = run("domain:google.com", http)
    assert res.attributes["mta_sts"] == {"present": True, "id": "20210803T010101"}
    assert res.attributes["tls_rpt"] == {"present": True, "rua": ["mailto:sts-reports@google.com"]}
    assert res.attributes["bimi"] == {"present": True, "logo": None, "authority": None, "declined": True}
    assert res.attributes["email_posture"]["caa"] == "pki.goog" and len(res.attributes["caa"]) == 1


def test_quoted_cloudflare_txt_answers_are_parsed():
    http = FakeHttp()
    http.add("GET", doh_url("_mta-sts.google.com", "TXT"), json=fx("mta_sts_google_cf.json"))
    http.add("GET", doh_url("_dmarc.google.com", "TXT"), json=fx("dmarc_google_cf.json"))
    add_nxdomain_everything(http)
    res = run("domain:google.com", http)
    assert res.attributes["mta_sts"]["id"] == "20210803T010101" and res.attributes["dmarc_policy"] == "reject"
    assert "dmarc_rua_external" not in res.attributes  # rua at google.com itself is not external


def test_dnssec_null_mx_and_spf_of_example_com():
    http = FakeHttp()
    http.add("GET", doh_url("example.com", "DS"), json=fx("ds_example_cf.json"))
    http.add("GET", doh_url("example.com", "MX"), json=fx("mx_example_cf.json"))
    http.add("GET", doh_url("example.com", "TXT"), json=fx("txt_example_cf.json"))
    http.add("GET", doh_url("_dmarc.example.com", "TXT"), json=fx("dmarc_example_cf.json"))
    add_nxdomain_everything(http)
    res = run("domain:example.com", http)
    table = res.attributes["email_posture"]
    assert table["mx"] == "null MX (no mail)" and table["dnssec"] == "DS present; validated by resolver (AD flag)"
    assert table["spf"] == "valid (-all)" and table["dmarc"] == "p=reject"
    assert table["mta_sts"] == table["tls_rpt"] == table["bimi"] == "absent"


def test_nic_br_spf_mx_and_dmarc():
    http = FakeHttp()
    http.add("GET", doh_url("nic.br", "TXT"), json=fx("txt_nicbr_google.json"))
    http.add("GET", doh_url("_dmarc.nic.br", "TXT"), json=fx("dmarc_nicbr_google.json"))
    add_nxdomain_everything(http)
    res = run("domain:nic.br", http)
    assert res.attributes["spf_status"] == "ok" and res.attributes["spf_lookups"] == 1 and res.attributes["spf_void_lookups"] == 1
    assert res.attributes["dmarc_policy"] == "reject" and res.attributes["email_posture"]["mx"] == "NXDOMAIN"


def test_email_entity_uses_its_domain_and_webmail_is_not_applicable():
    http = FakeHttp()
    add_dns(http, "example.org", "TXT", ["v=spf1 -all"])
    add_nxdomain_everything(http)
    res = run("email:someone@example.org", http)
    assert res.status is Status.OK and res.attributes["spf_status"] == "ok"
    assert any("_domainkey.example.org" in c["url"] for c in http.calls)  # e-mail domains get DKIM probing
    http2 = FakeHttp()
    res2 = run("email:someone@gmail.com", http2)
    assert res2.status is Status.SKIPPED and res2.reason_code == "not_applicable" and http2.calls == []


def test_once_per_scan():
    http = FakeHttp()
    add_nxdomain_everything(http)
    first = run("domain:example.net", http, case_id="case-posture-1")
    assert first.status is Status.OK
    calls = len(http.calls)
    second = run("email:someone@example.net", http, case_id="case-posture-1")
    assert second.status is Status.SKIPPED and second.reason_code == "not_applicable"
    assert len(http.calls) == calls
    third = run("domain:example.net", http, case_id="case-posture-2")
    assert third.status is Status.OK


def test_public_suffix_is_not_applicable():
    http = FakeHttp()
    assert run("domain:com.br", http).status is Status.SKIPPED and http.calls == []


def test_doh_query_budget():
    http = FakeHttp()
    load_answers(http, "spf_tree_over_limit.json")
    run("domain:example.org", http)
    assert len(http.calls) <= esp.SPF_MAX_QUERIES + esp.MAX_SELECTORS + esp.MAX_REPORT_DESTINATIONS + 10
