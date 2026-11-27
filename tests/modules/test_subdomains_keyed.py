"""subdomains_keyed (P007): Chaos, DNSDumpster, FullHunt and BeVigil adapters, offline.

Fixtures in tests/fixtures/subdomains_keyed/ (batch p3-G01-1 prep, 2026-11-25/26): ``dnsdumpster_nokey_401.json``
and ``fullhunt_nokey_401.json`` are the real research answers without a key (they drive the NEEDS_KEY tests);
``dnsdumpster_ok_documented.json`` is DNSDumpster's own published sample (the provider's infrastructure) and the
``*_documented`` envelopes are documented error bodies (FullHunt errors and rate limiting, DNSDumpster 429). Every
``*_synthetic`` answer is a documented shape with documentation values (example.com, 192.0.2.x, 198.51.100.x,
203.0.113.x): trimmed real success captures with the team keys are still owed (P007 cond 7, docs/backlog/p3-G01-1.md).
"""

from __future__ import annotations

import pytest

from tests.fakes import FIXTURES, FakeHttp, add_dns, add_nxdomain_everything, assert_no_secret, fixture, module_fixture, run_module
from v3lum.core.entities import EntityType as T
from v3lum.core.http import NetworkError
from v3lum.core.models import Status
from v3lum.modules.domain_dns import subdomains_keyed as K
from v3lum.modules.domain_dns.subdomains_keyed import SubdomainsKeyed

FX = FIXTURES / "subdomains_keyed"
APEX = "example.com"
CHAOS = K.CHAOS_URL.format(apex=APEX)
DD = K.DNSDUMPSTER_URL.format(apex=APEX)
FH = K.FULLHUNT_URL.format(apex=APEX)
BV_SUBS = K.BEVIGIL_SUBDOMAINS_URL.format(apex=APEX)
BV_URLS = K.BEVIGIL_URLS_URL.format(apex=APEX)
KEYS = {
    "chaos": "chaos-test-key-0123456789abcdef",
    "dnsdumpster": "dd-test-key-0123456789abcdef",
    "fullhunt": "fh-test-key-0123456789abcdef",
    "bevigil": "bv-test-key-0123456789abcdef",
}
HDR = {
    "chaos": {"Authorization": KEYS["chaos"]},
    "dnsdumpster": {"X-API-Key": KEYS["dnsdumpster"]},
    "fullhunt": {"X-API-KEY": KEYS["fullhunt"]},
    "bevigil": {"X-Access-Token": KEYS["bevigil"]},
}
CHALLENGE = "<html><head><title>Just a moment...</title></head><body><div id='cf-chl-widget'></div></body></html>"


def fx(name):
    return module_fixture("subdomains_keyed", name)


def envelope(name):
    """Route keywords of a recorded/documented exchange envelope (.http.json)."""
    resp = fx(name)["response"]
    body = resp["body"]
    kw = {"status": resp["status"], "headers": resp.get("headers") or {}}
    if isinstance(body, (dict, list)):
        kw["json"] = body
    else:
        kw["text"] = body or ""
    return kw


def keys(*names):
    return {n: KEYS[n] for n in names}


def no_names(http):
    add_nxdomain_everything(http)  # every DoH query (names and random wildcard labels) answers NXDOMAIN
    return http


def statuses(res):
    return {k: (v["status"], v.get("reason_code", "")) for k, v in res.source_statuses.items()}


# ------------------------------------------------------------------ metadata (cond 1, 2)
def test_contract_metadata():
    cls = SubdomainsKeyed
    assert cls.default_enabled is True and cls.terms == "key-terms" and cls.trust_tier == "community"
    assert cls.optional_keys == ("chaos", "dnsdumpster", "fullhunt", "bevigil") and cls.requires_keys == ()
    assert cls.terms_sources == {K.SRC_CHAOS: "key-terms", K.SRC_DNSDUMPSTER: "key-terms", K.SRC_FULLHUNT: "key-terms",
                                 K.SRC_BEVIGIL: "key-terms"}
    assert set(cls.hosts) == {"dns.projectdiscovery.io", "api.dnsdumpster.com", "fullhunt.io", "osint.bevigil.com"}
    assert cls.max_requests <= 10 and cls.cache_ttl == 86400 and cls.produces == {T.DOMAIN, T.URL}
    assert cls.max_tlp.label == "TLP:AMBER"  # community: allowed at AMBER, never AMBER+STRICT


def test_provider_fragments_keys_pacing_and_budgets():
    from v3lum import config
    from v3lum.core import providers

    reg = providers.registry()
    tiers = {p: reg.get(p).tier for p in ("projectdiscovery", "dnsdumpster", "fullhunt", "bevigil")}
    assert tiers == {"projectdiscovery": "trusted", "dnsdumpster": "community", "fullhunt": "community", "bevigil": "community"}
    assert reg.get("dnsdumpster").http_profile.min_interval == 2.0  # cond 4: one request per 2 s
    for pid in tiers:
        assert reg.get(pid).quota is not None  # cond 5: a P334 budget per provider
    keyreg = config.key_registry()
    for name, alias in (("chaos", "V3LUM_CHAOS_KEY"), ("dnsdumpster", "V3LUM_DNSDUMPSTER_KEY"), ("fullhunt", "V3LUM_FULLHUNT_KEY"),
                        ("bevigil", "V3LUM_BEVIGIL_KEY")):
        assert alias in keyreg[name].env  # cond 2: V3LUM_KEY_<NAME> always works, the alias is added
    for sid in SubdomainsKeyed.sources:
        src = reg.source(sid)
        assert src.terms.class_ == "key-terms" and src.terms.free_plan_business_use is None  # cond 3: legal records the plan


# ------------------------------------------------------------------ keys (cond 2)
def test_without_any_key_every_adapter_needs_key_and_nothing_is_sent():
    http = FakeHttp()
    res = run_module(SubdomainsKeyed, "domain:example.com", http)
    assert res.status is Status.NEEDS_KEY and res.reason_code == "needs_key"
    assert http.calls == []
    assert {v[0] for v in statuses(res).values()} == {"needs_key"} and len(res.source_statuses) == 4


def test_one_key_runs_one_adapter_and_the_others_report_needs_key():
    http = FakeHttp().add("GET", CHAOS, json=fx("chaos_ok_synthetic.json"), match_headers=HDR["chaos"])
    add_dns(http, "www.example.com", "A", ["203.0.113.80"])
    no_names(http)
    res = run_module(SubdomainsKeyed, "domain:example.com", http, keys=keys("chaos"))
    assert res.status is Status.OK
    st = statuses(res)
    assert st[K.SRC_CHAOS][0] == "ok"
    assert {st[s][0] for s in (K.SRC_DNSDUMPSTER, K.SRC_FULLHUNT, K.SRC_BEVIGIL)} == {"needs_key"}  # never EMPTY
    hosts = {c["url"].split("/")[2] for c in http.calls}
    assert "dns.projectdiscovery.io" in hosts and not hosts & {"api.dnsdumpster.com", "fullhunt.io", "osint.bevigil.com"}


# ------------------------------------------------------------------ parsing (cond 4)
def test_chaos_labels_get_the_apex_wildcards_and_junk():
    http = no_names(FakeHttp().add("GET", CHAOS, json=fx("chaos_ok_synthetic.json"), match_headers=HDR["chaos"]))
    res = run_module(SubdomainsKeyed, "domain:example.com", http, keys=keys("chaos"))
    names = set(res.attributes["subdomains"]) | set(res.attributes.get("subdomains_historical", [])) | set(res.attributes.get("subdomains_unresolved", []))
    prov = res.attributes["subdomain_provenance"]
    assert {"1.dev.example.com", "www.example.com", "api.example.com", "mail.example.com"} <= set(prov)
    assert "_dmarc.example.com" in prov  # an underscore label is a valid DNS name (SRV/TXT owners)
    assert not any("bad_label" in n or ".." in n for n in prov)
    assert res.attributes["subdomain_wildcards"] == ["*.cfe.example.com", "*.example.com"]  # '*' and '*.cfe': parent wildcards
    assert prov["www.example.com"]["sources"] == [K.SRC_CHAOS]
    assert names <= set(prov)
    assert res.raw["sources"][K.SRC_CHAOS]["rejected"]  # junk counted, never a name


def test_all_four_adapters_merge_with_provenance_urls_and_facts():
    http = FakeHttp()
    http.add("GET", CHAOS, json=fx("chaos_ok_synthetic.json"), match_headers=HDR["chaos"])
    http.add("GET", DD, json=fx("dnsdumpster_ok_synthetic.json"), match_headers=HDR["dnsdumpster"])
    http.add("GET", FH, json=fx("fullhunt_ok_synthetic.json"), match_headers=HDR["fullhunt"])
    http.add("GET", BV_SUBS, json=fx("bevigil_ok_synthetic.json"), match_headers=HDR["bevigil"])
    http.add("GET", BV_URLS, json=fx("bevigil_urls_ok_synthetic.json"), match_headers=HDR["bevigil"])
    add_dns(http, "www.example.com", "A", ["203.0.113.80"])
    add_dns(http, "vpn.example.com", "A", ["203.0.113.81"])
    add_dns(http, "api.example.com", "A", ["203.0.113.82"])
    no_names(http)
    res = run_module(SubdomainsKeyed, "domain:example.com", http, keys=KEYS)
    assert res.status is Status.OK
    assert {v[0] for v in statuses(res).values()} == {"ok"}
    cov = res.attributes["subdomain_coverage"]
    assert cov["line"].startswith("4/4 sources answered")
    prov = res.attributes["subdomain_provenance"]
    assert set(prov["www.example.com"]["sources"]) >= {K.SRC_CHAOS, K.SRC_DNSDUMPSTER, K.SRC_FULLHUNT}
    assert set(prov["api.example.com"]["sources"]) >= {K.SRC_CHAOS, K.SRC_FULLHUNT, K.SRC_BEVIGIL}
    assert "vpn.example.com" in prov  # DNSDumpster 'VPN.Example.com' lower-cased
    # out-of-apex provider hosts (MX at example.net, login.example.net) never become names
    assert not any(n.endswith("example.net") for n in prov)
    # FullHunt community plan: 250 results, 100 available -> partial for that source
    assert "provider_plan" in res.source_statuses[K.SRC_FULLHUNT]["reason"]
    # pivots: resolving names only, domains with relation subdomain
    pivots = {(p.entity.type, p.entity.value, p.relation) for p in res.pivots}
    assert (T.DOMAIN, "www.example.com", "subdomain") in pivots and (T.DOMAIN, "api.example.com", "subdomain") in pivots
    # BeVigil URLs: in-apex only, key-like values redacted, fragments dropped, never expanded
    urls = {u["url"] for u in res.attributes["mobile_app_urls"]}
    # REDACTED by the module; the engine's redaction pass then masks key-like parameters in attributes again
    assert any(u.startswith("https://maps.example.com/js?key=") and u.endswith("&v=3") for u in urls)
    assert "https://maps.example.com/js?key=REDACTED&v=3" in {p.entity.value for p in res.pivots}
    assert "https://api.example.com/v2/orders?id=1" in urls and not any("example.net" in u or "#" in u for u in urls)
    assert "PLACEHOLDER-NOT-A-REAL-KEY" not in repr(res.to_dict())
    url_pivots = [p for p in res.pivots if p.entity.type is T.URL]
    assert url_pivots and all(p.expand is False and p.relation == "hosts_url" for p in url_pivots)
    # DNSDumpster IP/ASN facts are evidence only (ipv4 is not produced)
    assert res.raw["provider_facts"][K.SRC_DNSDUMPSTER]["host_ips"]["www.example.com"][0]["ip"] == "192.0.2.11"
    assert not [p for p in res.pivots if p.entity.type in (T.IPV4, T.IPV6)]
    # keys only in headers, never in a URL, never in the result
    assert all(not any(k in c["url"] for k in KEYS.values()) for c in http.calls)
    for key in KEYS.values():
        assert_no_secret(key, res.to_dict())
    http.assert_hosts_within(SubdomainsKeyed)


def test_documented_dnsdumpster_sample_parses():
    http = no_names(FakeHttp().add("GET", "https://api.dnsdumpster.com/domain/dnsdumpster.com", json=fx("dnsdumpster_ok_documented.json"),
                                   match_headers=HDR["dnsdumpster"]))
    res = run_module(SubdomainsKeyed, "domain:dnsdumpster.com", http, keys=keys("dnsdumpster"))
    assert res.status in (Status.OK, Status.EMPTY)
    assert res.source_statuses[K.SRC_DNSDUMPSTER]["status"] in ("ok", "empty")
    assert res.raw["sources"][K.SRC_DNSDUMPSTER]["names"] == 0  # the apex and registrar NS only: no subdomain
    assert "banners" not in repr(res.raw)  # banners are never kept


def test_dnsdumpster_plus_pages_are_capped_at_three():
    page = {"a": [{"host": f"h{i}.example.com", "ips": []} for i in range(200)], "mx": [], "ns": [], "cname": [], "total_a_recs": 900}
    http = FakeHttp()
    http.add("GET", DD, json=page, match_headers=HDR["dnsdumpster"])
    http.add("GET", DD + "?page=2", json=page, match_headers=HDR["dnsdumpster"])
    http.add("GET", DD + "?page=3", json=page, match_headers=HDR["dnsdumpster"])
    no_names(http)
    res = run_module(SubdomainsKeyed, "domain:example.com", http, keys=keys("dnsdumpster"), settings={"subdomains_keyed_resolve": 0})
    assert res.status is Status.OK
    dd_calls = [c["url"] for c in http.calls if "dnsdumpster" in c["url"]]
    assert len(dd_calls) == 3  # never a 4th page
    assert "provider_plan" in res.source_statuses[K.SRC_DNSDUMPSTER]["reason"]


def test_free_plan_truncation_is_partial():
    doc = {"a": [{"host": "www.example.com", "ips": []}], "mx": [], "ns": [], "cname": [], "total_a_recs": 120}
    http = no_names(FakeHttp().add("GET", DD, json=doc, match_headers=HDR["dnsdumpster"]))
    res = run_module(SubdomainsKeyed, "domain:example.com", http, keys=keys("dnsdumpster"))
    assert res.status is Status.OK and "provider_plan" in res.source_statuses[K.SRC_DNSDUMPSTER]["reason"]
    assert len([c for c in http.calls if "dnsdumpster" in c["url"]]) == 1  # no page 2 on a short page


def test_empty_answers_are_empty():
    http = FakeHttp()
    http.add("GET", CHAOS, json=fx("chaos_empty_synthetic.json"), match_headers=HDR["chaos"])
    http.add("GET", BV_SUBS, json=fx("bevigil_empty_synthetic.json"), match_headers=HDR["bevigil"])
    http.add("GET", BV_URLS, json={"domain": "example.com", "urls": []}, match_headers=HDR["bevigil"])
    res = run_module(SubdomainsKeyed, "domain:example.com", http, keys=keys("chaos", "bevigil"))
    assert res.status is Status.EMPTY
    assert res.source_statuses[K.SRC_CHAOS]["status"] == "empty" and res.source_statuses[K.SRC_BEVIGIL]["status"] == "empty"


def test_bevigil_urls_setting_off_spends_one_request():
    http = no_names(FakeHttp().add("GET", BV_SUBS, json=fx("bevigil_ok_synthetic.json"), match_headers=HDR["bevigil"]))
    res = run_module(SubdomainsKeyed, "domain:example.com", http, keys=keys("bevigil"), settings={"subdomains_keyed_bevigil_urls": False})
    assert res.status is Status.OK and "mobile_app_urls" not in res.attributes
    assert [c["url"] for c in http.calls if "bevigil" in c["url"]] == [BV_SUBS]


# ------------------------------------------------------------------ refusals (cond 6) and rule 5
def test_real_401_bodies_are_needs_key_invalid_key():
    http = FakeHttp()
    http.add("GET", DD, status=401, json=fx("dnsdumpster_nokey_401.json"))
    http.add("GET", FH, status=401, json=fx("fullhunt_nokey_401.json"))
    res = run_module(SubdomainsKeyed, "domain:example.com", http, keys=keys("dnsdumpster", "fullhunt"))
    assert res.status is Status.NEEDS_KEY and res.reason_code == "needs_key"
    st = statuses(res)
    assert st[K.SRC_DNSDUMPSTER] == ("needs_key", "needs_key") and st[K.SRC_FULLHUNT] == ("needs_key", "needs_key")
    assert "invalid key" in res.source_statuses[K.SRC_DNSDUMPSTER]["reason"]
    assert len(http.calls) == 2  # a refusal is never retried


@pytest.mark.parametrize("url,name,status,code", [
    (FH, "fullhunt_unauthorized_documented.http.json", "needs_key", "needs_key"),
    (FH, "fullhunt_forbidden_documented.http.json", "needs_key", "needs_key"),
    (FH, "fullhunt_credits_exhausted_synthetic.http.json", "quota", "quota"),
    (FH, "fullhunt_rate_limited_documented.http.json", "rate_limited", "rate_limited"),
    (DD, "dnsdumpster_rate_limited_429.http.json", "rate_limited", "rate_limited"),
    (DD, "dnsdumpster_quota_synthetic.http.json", "quota", "quota"),
    (DD, "dnsdumpster_forbidden_403_synthetic.http.json", "needs_key", "needs_key"),
    (CHAOS, "chaos_unauthorized_synthetic.http.json", "needs_key", "needs_key"),
    (CHAOS, "chaos_rate_limited_synthetic.http.json", "rate_limited", "rate_limited"),
    (BV_SUBS, "bevigil_unauthorized_synthetic.http.json", "needs_key", "needs_key"),
    (BV_SUBS, "bevigil_credits_synthetic.http.json", "quota", "quota"),
])
def test_refusals_map_to_could_not_verify_statuses(url, name, status, code):
    adapter = {CHAOS: "chaos", DD: "dnsdumpster", FH: "fullhunt", BV_SUBS: "bevigil"}[url]
    http = FakeHttp().add("GET", url, **envelope(name))
    res = run_module(SubdomainsKeyed, "domain:example.com", http, keys=keys(adapter))
    assert res.status.value == status and res.reason_code == code
    assert "subdomains" not in res.attributes  # never EMPTY / zero names


@pytest.mark.parametrize("route", [
    {"status": 502, "text": "<html><body>502 Bad Gateway</body></html>"},
    {"error": NetworkError("ReadTimeout contacting fullhunt.io: timed out", kind="ReadTimeout")},
    {"text": '{"domain": "example.com", "hosts": ["www.exa', "headers": {"content-type": "application/json"}},
    {"text": "<html><body>maintenance</body></html>"},
    {"json": fx("fullhunt_error_in_200_synthetic.json")},
    {"json": {"error": "backend unavailable"}},
    {"json": ["not", "an", "object"]},
    {"status": 302, "headers": {"location": "https://fullhunt.io/login"}},
])
def test_failures_and_error_in_200_are_error(route):
    http = FakeHttp().add("GET", FH, **route)
    res = run_module(SubdomainsKeyed, "domain:example.com", http, keys=keys("fullhunt"))
    assert res.status in (Status.ERROR, Status.BLOCKED) and "could not verify" in res.error
    assert "subdomains" not in res.attributes


def test_error_body_in_200_with_quota_words_is_quota():
    http = FakeHttp().add("GET", CHAOS, json={"error": "monthly quota exceeded for this key"})
    res = run_module(SubdomainsKeyed, "domain:example.com", http, keys=keys("chaos"))
    assert res.status is Status.QUOTA


def test_challenge_page_is_blocked():
    http = FakeHttp().add("GET", BV_SUBS, status=403, text=CHALLENGE)
    res = run_module(SubdomainsKeyed, "domain:example.com", http, keys=keys("bevigil"))
    assert res.status is Status.BLOCKED and res.reason_code == "challenge"
    assert len(http.calls) == 1


def test_chaos_answer_for_another_domain_is_error():
    http = FakeHttp().add("GET", CHAOS, json=fx("chaos_wrong_domain_synthetic.json"))
    res = run_module(SubdomainsKeyed, "domain:example.com", http, keys=keys("chaos"))
    assert res.status is Status.ERROR and "another domain" in res.error


def test_one_failed_adapter_next_to_an_answer_keeps_its_status_and_marks_partial():
    http = FakeHttp()
    http.add("GET", CHAOS, json=fx("chaos_ok_synthetic.json"))
    http.add("GET", DD, **envelope("dnsdumpster_rate_limited_429.http.json"))
    no_names(http)
    res = run_module(SubdomainsKeyed, "domain:example.com", http, keys=keys("chaos", "dnsdumpster"))
    assert res.status is Status.OK and res.partial
    assert statuses(res)[K.SRC_DNSDUMPSTER] == ("rate_limited", "rate_limited")
    assert "DNSDumpster rate_limited" in res.attributes["subdomain_coverage"]["line"]


def test_bevigil_urls_failure_keeps_the_subdomains():
    http = FakeHttp()
    http.add("GET", BV_SUBS, json=fx("bevigil_ok_synthetic.json"))
    http.add("GET", BV_URLS, **envelope("bevigil_credits_synthetic.http.json"))
    no_names(http)
    res = run_module(SubdomainsKeyed, "domain:example.com", http, keys=keys("bevigil"))
    assert res.status is Status.OK and res.source_statuses[K.SRC_BEVIGIL]["status"] == "ok"
    assert "quota" in res.source_statuses[K.SRC_BEVIGIL]["reason"]


# ------------------------------------------------------------------ caps, applicability, licence (cond 3, 5)
def test_per_source_cap_of_5000_names():
    doc = {"domain": "example.com", "subdomains": [f"h{i}" for i in range(5100)], "count": 5100}
    http = no_names(FakeHttp().add("GET", CHAOS, json=doc))
    res = run_module(SubdomainsKeyed, "domain:example.com", http, keys=keys("chaos"), settings={"subdomains_keyed_resolve": 0})
    assert res.status is Status.OK
    assert res.raw["sources"][K.SRC_CHAOS]["names"] == 5000 and res.raw["sources"][K.SRC_CHAOS]["capped"] == 100
    assert "name_cap" in res.source_statuses[K.SRC_CHAOS]["reason"]


def test_chaos_count_above_labels_is_partial():
    doc = {"domain": "example.com", "subdomains": ["www"], "count": 7}
    http = no_names(FakeHttp().add("GET", CHAOS, json=doc))
    res = run_module(SubdomainsKeyed, "domain:example.com", http, keys=keys("chaos"))
    assert "provider_truncated" in res.source_statuses[K.SRC_CHAOS]["reason"]


def test_subdomain_entity_is_not_applicable():
    http = FakeHttp()
    res = run_module(SubdomainsKeyed, "domain:www.example.com", http, keys=KEYS)
    assert res.status is Status.SKIPPED and res.reason_code == "not_applicable" and http.calls == []


def test_a_source_outside_allowed_sources_is_never_queried():
    http = no_names(FakeHttp().add("GET", CHAOS, json=fx("chaos_ok_synthetic.json")))
    res = run_module(SubdomainsKeyed, "domain:example.com", http, keys=KEYS, allowed_sources={K.SRC_CHAOS})
    assert res.status is Status.OK
    assert {c["url"].split("/")[2] for c in http.calls if "projectdiscovery" in c["url"] or "dnsdumpster" in c["url"]} == {"dns.projectdiscovery.io"}
    assert K.SRC_FULLHUNT not in res.source_statuses  # licence-blocked feeds are reported by the engine


def test_every_source_licence_blocked_is_skipped_licence():
    http = FakeHttp()
    res = run_module(SubdomainsKeyed, "domain:example.com", http, keys=KEYS, allowed_sources=set())
    assert res.status is Status.SKIPPED and res.reason_code == "licence" and http.calls == []


# ------------------------------------------------------------------ pure helpers
def test_chaos_label_to_fqdn():
    assert K.chaos_label_to_fqdn("www", APEX) == "www.example.com"
    assert K.chaos_label_to_fqdn("*", APEX) == "*.example.com"
    assert K.chaos_label_to_fqdn("*.cfe", APEX) == "*.cfe.example.com"
    assert K.chaos_label_to_fqdn("mail.example.com", APEX) == "mail.example.com"
    assert K.chaos_label_to_fqdn("", APEX) is None and K.chaos_label_to_fqdn(None, APEX) is None


def test_limit_kind_and_refusal_classes():
    assert K.limit_kind("Rate limit exceeded", 429) == "rate_limited"
    assert K.limit_kind("Daily API limit reached", 429) == "quota"
    assert K.limit_kind("Limit Exceeded", 429) == "quota"
    assert K.limit_kind("", 429) == "rate_limited" and K.limit_kind("Forbidden", 403) is None
    assert type(K.classify_refusal("X", 402, "")).__name__ == "QuotaExceeded"
    assert type(K.classify_refusal("X", 401, "Unauthorized")).__name__ == "AuthRequired"


def test_sanitize_found_url():
    assert K.sanitize_found_url("https://u:p@API.example.com/a?token=abc&x=1#f") == {
        "url": "https://api.example.com/a?token=REDACTED&x=1", "host": "api.example.com", "redacted_params": 1}
    assert K.sanitize_found_url("ftp://files.example.com/a") is None
    assert K.sanitize_found_url("not a url") is None
    assert K.sanitize_found_url("https://192.0.2.1/x") is None  # IP literals are not host names


def test_auth_headers_refuse_unusable_keys():
    assert K.auth_headers("X-API-Key", "{key}", " k ") == {"X-API-Key": "k"}
    assert K.auth_headers("X-API-Key", "{key}", "") == {} and K.auth_headers("X-API-Key", "{key}", "a\r\nb") == {}


# ------------------------------------------------------------------ AR21 golden path
def test_acceptance_route_without_keys_makes_no_request():
    doc = fixture("acceptance/domain/subdomains_keyed.json")
    assert doc["schema"] == "v3lum.acceptance_routes/1" and doc["module"] == "subdomains_keyed" and doc["routes"] == []
    http = FakeHttp()
    res = run_module(SubdomainsKeyed, "domain:example.com", http)
    assert res.status is Status.NEEDS_KEY and http.calls == []
    assert (FX / "dnsdumpster_nokey_401.json").exists()
