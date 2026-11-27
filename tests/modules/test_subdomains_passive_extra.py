"""subdomains_passive_extra (P016 cond 3, opt-in feeds): AnubisDB, Subdomain Center, subdomain.app, ScanMalware,
myssl.com and RapidDNS (toggles), offline.

Fixtures in tests/fixtures/subdomains_passive_extra/ (batch p2-G01-3 prep, recorded 2026-11-25/26 from a
datacenter egress, scrubbed): live AnubisDB answers (the operator's own out-of-apex domain replaced by
example.net) and its Cloudflare 'Attention Required' 403 page (research; egress IP and Ray ID scrubbed),
Subdomain Center (derived list: labels that looked like personal handles replaced by userNNNN; live 503
'server busy' and empty answers), subdomain.app (live google.com truncated answer, derived complete one,
live empty), ScanMalware (live degraded CT answer, live hosts answers, a synthetic non-degraded CT shape),
myssl.com (live answer with IPs remapped to 198.51.100.x, synthetic error and empty shapes) and RapidDNS
(live page, derived truncated and table-less pages, synthetic Cloudflare challenge, live robots.txt).
"""

from __future__ import annotations

import pytest

from tests.fakes import FIXTURES, FakeHttp, add_dns, add_nxdomain_everything, module_fixture, run_module
from v3lum.core.context import ScanOptions
from v3lum.core.models import Status
from v3lum.modules.domain_dns import subdomains_passive_extra as X
from v3lum.modules.domain_dns.subdomains_passive_extra import SubdomainsPassiveExtra

FX = FIXTURES / "subdomains_passive_extra"
APEX = "example.com"
ANUBIS = X.ANUBIS_URL.format(apex=APEX)
SUBCENTER = X.SUBCENTER_URL + "?domain=" + APEX
SUBAPP = X.SUBAPP_URL + "?domain=" + APEX
SM_CT = X.SM_CT_URL.format(apex=APEX) + "?subdomain_limit=5000"
SM_HOSTS = X.SM_HOSTS_URL.format(apex=APEX) + "?sources=observed,scripts&subdomains_only=true"
MYSSL = X.MYSSL_URL + "?domain=" + APEX
RAPID = X.RAPIDDNS_URL.format(apex=APEX) + "?full=1"
TOGGLES = {"subdomains_passive_extra_myssl": True, "subdomains_passive_extra_rapiddns": True}
CHALLENGE = "<html><head><title>Just a moment...</title></head><body><div id='cf-chl-widget'></div></body></html>"


def fx(name):
    return module_fixture("subdomains_passive_extra", name)


def page(name):
    return (FX / name).read_text(encoding="utf-8")


def full_http(**overrides):
    """Every feed answering with its recorded fixture; ``overrides`` replace one route (None = no route)."""
    http = FakeHttp()
    routes = {
        "anubis": (ANUBIS, dict(json=fx("anubis_ok.json"))),
        "subcenter": (SUBCENTER, dict(json=fx("subcenter_ok.json"))),
        "subapp": (SUBAPP, dict(json=fx("subapp_empty.json"))),
        "sm_ct": (SM_CT, dict(json=fx("scanmalware_ct_degraded.json"))),
        "sm_hosts": (SM_HOSTS, dict(json=fx("scanmalware_hosts_empty.json"))),
        "myssl": (MYSSL, dict(json=fx("myssl_ok.json"))),
        "rapid": (RAPID, dict(text=page("rapiddns_ok.html"))),
    }
    for key, value in overrides.items():
        routes[key] = (routes[key][0], value) if value is not None else (routes[key][0], None)
    for _key, (url, route) in routes.items():
        if route is not None:
            http.add("GET", url, **route)
    return http


def resolving(http, *names):
    for i, name in enumerate(names):
        add_dns(http, name, "A", [f"203.0.113.{100 + i}"])
    add_nxdomain_everything(http)  # every other name (and the random wildcard labels) answers NXDOMAIN


def statuses(res):
    return {k: v["status"] for k, v in res.source_statuses.items()}


# ------------------------------------------------------------------ metadata (P016 cond 3, 4)
def test_contract_metadata():
    cls = SubdomainsPassiveExtra
    assert cls.default_enabled is False and cls.terms == "unknown" and cls.trust_tier == "unknown"
    assert cls.max_tlp.label == "TLP:GREEN"  # unknown tier: excluded at AMBER and above
    assert cls.terms_sources == {
        "anubisdb.subdomains": "open", "subdomain_center.subdomains": "open", "subdomain_app.query": "unknown",
        "scanmalware.subdomains": "unknown", "myssl.discover_sub_domain": "unknown", "rapiddns.subdomain_pages": "unknown",
    }
    assert cls.max_requests == 7 and cls.max_pivots == 12
    assert cls.settings["subdomains_passive_extra_myssl"].default is False
    assert cls.settings["subdomains_passive_extra_rapiddns"].default is False
    assert "jldc.me" not in cls.hosts  # the legacy mirror 301s to an undeclared host: never used


# ------------------------------------------------------------------ the merged run (cond 1, 5, 7)
def test_all_feeds_merge_with_provenance_and_unconfirmed_names():
    http = full_http()
    resolving(http, "admin.example.com", "vpn.example.com")
    res = run_module(SubdomainsPassiveExtra, "domain:example.com", http, settings=TOGGLES)
    assert res.status is Status.OK
    assert set(statuses(res).values()) <= {"ok", "empty"} and len(statuses(res)) == 6
    cov = res.attributes["subdomain_coverage"]
    assert cov["line"] == "6/6 sources answered"
    prov = res.attributes["subdomain_provenance"]
    # seen by AnubisDB, myssl.com and RapidDNS: confirmed by agreement even though it does not resolve here
    assert set(prov["www.example.com"]["sources"]) >= {"anubisdb.subdomains", "myssl.discover_sub_domain", "rapiddns.subdomain_pages"}
    assert prov["www.example.com"]["confirmed"] is True and "www.example.com" in res.attributes["subdomains"]
    # single noisy source, resolves (non-wildcard): confirmed and pivoted
    assert prov["admin.example.com"]["confirmed"] is True and prov["admin.example.com"]["state"] == "live"
    # single noisy source, does not resolve: unconfirmed, listed apart, never an asset
    assert prov["staging.example.com"]["confirmed"] is False
    assert "staging.example.com" in res.attributes["subdomains_unconfirmed"]
    assert "staging.example.com" not in res.attributes["subdomains"]
    assert "user0001.example.com" in res.attributes["subdomains_unconfirmed"]
    # out-of-apex junk never becomes a name (label boundary: m.testexample.com is not under example.com)
    assert not any(n.endswith("example.net") or n == "m.testexample.com" for n in prov)
    pivots = {p.entity.value for p in res.pivots}
    assert pivots == {"admin.example.com", "vpn.example.com"}
    assert res.attributes["subdomain_provenance"]["www.example.com"]["tls_grade"] == "A"  # myssl fact, never an IP pivot
    assert not [p for p in res.pivots if p.entity.type.value != "domain"]
    http.assert_hosts_within(SubdomainsPassiveExtra)


def test_toggles_are_off_by_default():
    http = full_http(myssl=None, rapid=None)
    resolving(http)
    res = run_module(SubdomainsPassiveExtra, "domain:example.com", http)
    assert statuses(res)["myssl.discover_sub_domain"] == "skipped"
    assert res.source_statuses["rapiddns.subdomain_pages"]["reason_code"] == "config"
    assert not any("myssl.com" in u or "rapiddns.io" in u for u in http.urls())
    assert res.attributes["subdomain_coverage"]["line"] == "4/4 sources answered"


def test_licence_blocked_feeds_are_never_queried():
    allowed = {"anubisdb.subdomains", "subdomain_center.subdomains"}
    http = full_http(subapp=None, sm_ct=None, sm_hosts=None, myssl=None, rapid=None)
    resolving(http)
    res = run_module(SubdomainsPassiveExtra, "domain:example.com", http, settings=TOGGLES, allowed_sources=allowed)
    assert set(res.source_statuses) == allowed  # the engine reports the licence-blocked rest
    assert {u.split("/")[2] for u in http.urls() if "dns" not in u.split("/")[2]} == {"anubisdb.com", "api.subdomain.center"}


# ------------------------------------------------------------------ per-feed failures (cond 1, 9)
def test_anubis_challenge_page_is_blocked_while_others_answer():
    http = full_http(anubis=dict(status=403, text=page("anubis_challenge_403.html")))
    resolving(http)
    res = run_module(SubdomainsPassiveExtra, "domain:example.com", http)
    row = res.source_statuses["anubisdb.subdomains"]
    assert row["status"] == "blocked" and row["reason_code"] == "challenge"
    assert http.urls().count(ANUBIS) == 1  # never retried with another UA or identity (A9)
    assert res.status is Status.OK and res.partial
    assert res.attributes["subdomain_coverage"]["line"].startswith("3/4 sources answered")


def test_every_feed_failing_is_could_not_verify_never_empty():
    http = full_http(anubis=dict(status=403, text=page("anubis_challenge_403.html")), subcenter=dict(status=429, text="slow down"),
                     subapp=dict(status=403, text=CHALLENGE), sm_ct=dict(status=403, text=CHALLENGE), sm_hosts=None)
    res = run_module(SubdomainsPassiveExtra, "domain:example.com", http)
    assert res.status in (Status.RATE_LIMITED, Status.BLOCKED) and "could not verify" in res.error
    assert "subdomains" not in res.attributes


def test_subdomain_center_busy_503_is_could_not_verify():
    status, headers = 503, {"retry-after": "1", "content-type": "application/json"}
    busy = module_fixture("subdomains_passive_extra", "subcenter_busy_503.http.json")["response"]["body"]
    http = full_http(subcenter=dict(status=status, text=busy, headers=headers))
    resolving(http)
    res = run_module(SubdomainsPassiveExtra, "domain:example.com", http)
    row = res.source_statuses["subdomain_center.subdomains"]
    assert row["status"] == "error" and "could not verify" in row["reason"]
    assert res.status is Status.OK and res.partial


def test_subdomain_app_total_above_count_is_partial():
    http = FakeHttp().add("GET", X.SUBAPP_URL + "?domain=google.com", json=fx("subapp_truncated.json"))
    resolving(http)
    allowed = {"subdomain_app.query"}
    res = run_module(SubdomainsPassiveExtra, "domain:google.com", http, allowed_sources=allowed)
    assert res.partial and "truncated" in res.attributes["subdomain_coverage"]["sources"]["subdomain_app.query"]["partial"]
    assert "10000 of 211419" in res.error
    complete = FakeHttp().add("GET", X.SUBAPP_URL + "?domain=google.com", json=fx("subapp_complete.json"))
    resolving(complete)
    res2 = run_module(SubdomainsPassiveExtra, "domain:google.com", complete, allowed_sources=allowed)
    assert not res2.partial and res2.attributes["subdomain_coverage"]["names"] == 8


def test_scanmalware_degraded_ct_is_could_not_verify_never_zero_names():
    allowed = {"scanmalware.subdomains"}
    http = full_http(anubis=None, subcenter=None, subapp=None, myssl=None, rapid=None)
    resolving(http)
    res = run_module(SubdomainsPassiveExtra, "domain:example.com", http, allowed_sources=allowed)
    row = res.source_statuses["scanmalware.subdomains"]
    assert row["status"] == "empty" and "degraded" in row["reason"] and "could not verify" in row["reason"]
    assert res.partial  # the CT endpoint answered degraded: never a complete 'no names'
    # degraded CT and a failing hosts endpoint: nothing answered for the feed
    http2 = full_http(anubis=None, subcenter=None, subapp=None, myssl=None, rapid=None, sm_hosts=dict(status=500, text="error"))
    res2 = run_module(SubdomainsPassiveExtra, "domain:example.com", http2, allowed_sources=allowed)
    assert res2.status is Status.ERROR and "could not verify" in res2.error


def test_scanmalware_partial_flags_and_observed_hosts():
    allowed = {"scanmalware.subdomains"}
    http = FakeHttp()
    http.add("GET", X.SM_CT_URL.format(apex="google.com") + "?subdomain_limit=5000", json=fx("scanmalware_ct_degraded.json"))
    http.add("GET", X.SM_HOSTS_URL.format(apex="google.com") + "?sources=observed,scripts&subdomains_only=true",
             json=fx("scanmalware_hosts_ok.json"))
    resolving(http, "accounts.google.com")
    res = run_module(SubdomainsPassiveExtra, "domain:google.com", http, allowed_sources=allowed)
    prov = res.attributes["subdomain_provenance"]
    assert prov["accounts.google.com"]["sm_observed"] is True and prov["accounts.google.com"]["state"] == "live"
    flags = X.parse_scanmalware_ct(fx("scanmalware_ct_partial_synthetic.json"))
    assert flags["flags"] == ["partial", "stale", "subdomains_truncated"] and not flags["degraded"]
    assert [n for n, _f in flags["names"]] == ["api.example.com", "mail.example.com", "old-vpn.example.com"]


def test_myssl_error_and_empty_answers():
    allowed = {"myssl.discover_sub_domain"}
    err = full_http(anubis=None, subcenter=None, subapp=None, sm_ct=None, sm_hosts=None, rapid=None,
                    myssl=dict(json=fx("myssl_error_synthetic.json")))
    res = run_module(SubdomainsPassiveExtra, "domain:example.com", err, settings=TOGGLES, allowed_sources=allowed)
    assert res.status is Status.ERROR and "code 10001" in res.error  # error-in-200, never 'no names'
    empty = full_http(anubis=None, subcenter=None, subapp=None, sm_ct=None, sm_hosts=None, rapid=None,
                      myssl=dict(json=fx("myssl_empty_synthetic.json")))
    assert run_module(SubdomainsPassiveExtra, "domain:example.com", empty, settings=TOGGLES, allowed_sources=allowed).status is Status.EMPTY


def test_rapiddns_rows_truncation_layout_change_and_challenge():
    allowed = {"rapiddns.subdomain_pages"}
    out = X.parse_rapiddns(page("rapiddns_ok.html"))
    assert out["rows"] == out["total"] == len(out["names"]) and out["guest_limited"] is True
    name, facts = out["names"][0]
    assert facts["rr"][0]["type"] in ("A", "CNAME", "AAAA", "MX", "TXT", "NS")
    assert X.parse_rapiddns(page("rapiddns_truncated_derived.html"))["truncated"] is True
    with pytest.raises(X.UnexpectedAnswer):
        X.parse_rapiddns(page("rapiddns_no_table.html"))
    base = dict(anubis=None, subcenter=None, subapp=None, sm_ct=None, sm_hosts=None, myssl=None)
    truncated = full_http(rapid=dict(text=page("rapiddns_truncated_derived.html")), **base)
    resolving(truncated)
    res = run_module(SubdomainsPassiveExtra, "domain:example.com", truncated, settings=TOGGLES, allowed_sources=allowed)
    assert res.partial and "truncated" in res.attributes["subdomain_coverage"]["sources"]["rapiddns.subdomain_pages"]["partial"]
    layout = full_http(rapid=dict(text=page("rapiddns_no_table.html")), **base)
    res2 = run_module(SubdomainsPassiveExtra, "domain:example.com", layout, settings=TOGGLES, allowed_sources=allowed)
    assert res2.status is Status.ERROR and "table not found" in res2.error
    challenge = full_http(rapid=dict(text=page("rapiddns_challenge_synthetic.html")), **base)
    res3 = run_module(SubdomainsPassiveExtra, "domain:example.com", challenge, settings=TOGGLES, allowed_sources=allowed)
    assert res3.status is Status.BLOCKED and res3.reason_code == "challenge"  # a challenge served with HTTP 200 too
    assert challenge.urls().count(RAPID) == 1


def test_error_objects_inside_http_200_are_could_not_verify():
    allowed = {"anubisdb.subdomains"}
    http = FakeHttp().add("GET", ANUBIS, json={"error": "rate limit exceeded"})
    res = run_module(SubdomainsPassiveExtra, "domain:example.com", http, allowed_sources=allowed)
    assert res.status is Status.ERROR and "error object" in res.error
    junk = FakeHttp().add("GET", ANUBIS, text="<html><body>maintenance</body></html>")
    assert run_module(SubdomainsPassiveExtra, "domain:example.com", junk, allowed_sources=allowed).status is Status.ERROR
    empty = FakeHttp().add("GET", ANUBIS, json=fx("anubis_empty.json"))
    assert run_module(SubdomainsPassiveExtra, "domain:example.com", empty, allowed_sources=allowed).status is Status.EMPTY


# ------------------------------------------------------------------ demotion (cond 9, A3)
def test_feed_demoted_after_five_consecutive_blocked_runs():
    allowed = {"anubisdb.subdomains", "subdomain_app.query"}

    def run(options=None):
        http = FakeHttp()
        http.add("GET", ANUBIS, status=403, text=page("anubis_challenge_403.html"))
        http.add("GET", SUBAPP, json=fx("subapp_empty.json"))
        res = run_module(SubdomainsPassiveExtra, "domain:example.com", http, allowed_sources=allowed, options=options)
        return res, http

    for _ in range(X.DEMOTION_RUNS):
        res, http = run()
        assert res.source_statuses["anubisdb.subdomains"]["status"] == "blocked"
    res, http = run()
    row = res.source_statuses["anubisdb.subdomains"]
    assert row["status"] == "skipped" and row["reason_code"] == "demoted" and ANUBIS not in http.urls()
    explicit, http2 = run(ScanOptions(include={"subdomains_passive_extra"}))  # -M still runs it (A3)
    assert ANUBIS in http2.urls() and explicit.source_statuses["anubisdb.subdomains"]["status"] == "blocked"


def test_robots_fixture_documents_the_review_input():
    assert "Allow: /" in page("rapiddns_robots.txt")  # the ToS review itself is still a legal input (backlog)


def test_every_feed_answering_empty_is_empty_never_could_not_verify():
    """AnubisDB and Subdomain Center '[]' (live answers for a non-existent label), subdomain.app count 0 and the
    ScanMalware hosts endpoint with no host: EMPTY, while the degraded CT endpoint stays a could-not-verify note."""
    http = full_http(anubis=dict(json=fx("anubis_empty.json")), subcenter=dict(json=fx("subcenter_empty.json")),
                     sm_ct=dict(json={"subdomains": [], "subdomains_unresolved": []}), myssl=None, rapid=None)
    res = run_module(SubdomainsPassiveExtra, "domain:example.com", http)
    assert res.status is Status.EMPTY and not res.pivots
    assert statuses(res)["subdomain_center.subdomains"] == "empty" and statuses(res)["anubisdb.subdomains"] == "empty"
    assert res.attributes["subdomain_coverage"]["line"] == "4/4 sources answered"
