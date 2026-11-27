"""hostio (P004): keyed host.io lookups - header token, endpoint plan, P061 reverse-id rules, statuses.

Fixtures in tests/fixtures/hostio/: ``error_token_required.json`` is the real research answer (HTTP 400,
2026-11-25, no token); ``full_google_docs.json``, ``domains_googleanalytics_docs.json`` and
``error_no_details_404.json`` are host.io's own documentation samples (https://host.io/docs, read
2026-11-26). Synthetic (documented shapes, documentation values; no team key yet - merge gate recorded in
docs/backlog/p2-G01-1.md): ``full_example_synthetic.json``, ``domains_*_synthetic.json`` and the quota,
throttling and invalid-token error bodies.
"""

from __future__ import annotations

from tests.fakes import FakeHttp, assert_no_secret, module_fixture, run_module
from v3lum.core.entities import EntityType as T
from v3lum.core.models import Severity, Status
from v3lum.modules.domain_dns import hostio as mod
from v3lum.modules.domain_dns.hostio import HostIo

KEY = "hostio-test-token-0123456789abcdef"
KEYS = {"hostio": KEY}
AUTH = {"Authorization": f"Bearer {KEY}"}
API = "https://host.io/api"
CHALLENGE = "<html><head><title>Just a moment...</title></head><body><div id=\"cf-chl-widget\"></div></body></html>"
ORG_OWNS_EXAMPLE_ORG = {"domains": [{"name": "example.org", "verification": "txt_verified"}]}


def fx(name):
    return module_fixture(HostIo, name)


def pivots(res, relation=None, etype=None):
    return {p.entity.value for p in res.pivots if (relation is None or p.relation == relation) and (etype is None or p.entity.type is etype)}


def pivot(res, value):
    return next(p for p in res.pivots if p.entity.value == value)


def example_http() -> FakeHttp:
    """The five requests of a full example.com run (full + redirects + backlinks + 2 reverse ids)."""
    http = FakeHttp()
    http.add("GET", f"{API}/full/example.com", json=fx("full_example_synthetic.json"), match_headers=AUTH)
    http.add("GET", f"{API}/domains/redirects/example.com?limit=5", json=fx("domains_redirects_ok_synthetic.json"), match_headers=AUTH)
    http.add("GET", f"{API}/domains/backlinks/example.com?limit=5", json=fx("domains_backlinks_ok_synthetic.json"), match_headers=AUTH)
    http.add("GET", f"{API}/domains/googleanalytics/UA-12345678?limit=5", json=fx("domains_googleanalytics_ok_synthetic.json"), match_headers=AUTH)
    http.add("GET", f"{API}/domains/adsense/pub-1234567890123456?limit=5", json=fx("domains_adsense_ok_synthetic.json"), match_headers=AUTH)
    return http


# ------------------------------------------------------------------ metadata (council decisions)
def test_contract_metadata():
    cls = HostIo
    assert (cls.terms, cls.disclosure, cls.provider, cls.sources, cls.hosts) == ("key-terms", "third_party", "hostio", ("hostio.api",), ("host.io",))
    assert cls.requires_keys == ("hostio",) and cls.run_on == "seeds" and cls.default_enabled is True
    assert (cls.max_requests, cls.cache_ttl) == (5, 604800)  # cond 3
    assert cls.daily_quota is not None and cls.daily_quota * 31 <= 800  # <= 80% of the free plan's 1,000/month
    assert cls.manual_link == "https://host.io/{domain}"  # cond 7
    assert {T.DOMAIN, T.ANALYTICS_ID} == set(cls.accepts)
    assert {getattr(m, "id", None) for m in cls.error_markers} == {"hostio_quota", "hostio_rate_limited"}


def test_key_aliases_registered():
    from v3lum import config

    spec = config.key_registry()["hostio"]
    assert set(spec.env) >= {"V3LUM_HOSTIO_TOKEN", "V3LUM_HOSTIO_KEY"}


def test_without_key_needs_key_and_no_request():
    http = FakeHttp()
    res = run_module(HostIo, "domain:example.com", http)
    assert res.status is Status.NEEDS_KEY and res.reason_code == "needs_key"
    assert not http.calls


# ------------------------------------------------------------------ domain run (cond 3-5)
def test_real_documentation_sample_parses_and_reverse_lists_are_documented_absences():
    http = FakeHttp()
    http.add("GET", f"{API}/full/google.com", json=fx("full_google_docs.json"), match_headers=AUTH)
    http.add("GET", f"{API}/domains/redirects/google.com?limit=5", status=404, json=fx("error_no_details_404.json"))
    http.add("GET", f"{API}/domains/backlinks/google.com?limit=5", status=404, json=fx("error_no_details_404.json"))
    res = run_module(HostIo, "domain:google.com", http, keys=KEYS)
    assert res.status is Status.OK
    snap = res.attributes["homepage_snapshot"]
    assert (snap["rank"], snap["title"], snap["server"], snap["ip"], snap["date"]) == (1, "Google", "gws", "216.58.193.68", "2019-11-25T18:58:31.543Z")
    info = res.attributes["ip_registration_info"]["216.58.193.68"]
    assert info["asn"] == "AS15169" and info["country"] == "US" and "loc" not in info and "postal" not in info
    assert res.attributes["related_domain_counts"]["asn"] == [{"value": "AS15169", "count": 16219992}]
    assert pivots(res, "resolves_to") == {"216.58.193.68"} and pivot(res, "216.58.193.68").expand is False
    assert pivots(res, "links_to") == {"about.google"}
    assert "redirect_relations" not in res.attributes  # www.google.com is the domain's own host
    assert all("token=" not in u and KEY not in u for u in http.urls())  # header token only (cond 1)
    http.assert_hosts_within(HostIo)


def test_full_run_plan_ids_redirects_and_backlinks():
    http = example_http()
    res = run_module(HostIo, "domain:example.com", http, keys=KEYS)
    assert res.status is Status.OK
    assert len(http.calls) == 5  # cond 3: at most 5 requests per entity
    # tracking ids (P061): the shared GTM id is never reverse-looked-up nor expanded
    assert res.attributes["analytics_ids"] == ["GTM-ABC1234", "UA-12345678", "pub-1234567890123456"]
    assert res.attributes["shared_tracking_ids"] == ["GTM-ABC1234"]
    assert pivot(res, "GTM-ABC1234").expand is False and pivot(res, "pub-1234567890123456").expand is True
    # cond 4: every same_analytics edge is at most PROBABLE, the seed's own ids included
    assert all(p.confidence <= 0.7 for p in res.pivots if p.relation == "same_analytics")
    # host.io indexes UA ids at account level ('UA-12345678'): no analytics_id entity without the property
    # suffix, so the id stays in the attribute and the reverse lookup is done here
    assert "UA-12345678" not in pivots(res, etype=T.ANALYTICS_ID)
    shared = next(f for f in res.findings if f.title == "Shared tracking id (agency or platform)")
    assert "shared_tracking_id" in shared.tags and shared.severity is Severity.INFO
    # same_analytics candidates: expand=False, PROBABLE at most, the subject itself never pivoted
    same = {p.entity.value: p for p in res.pivots if p.relation == "same_analytics" and p.entity.type is T.DOMAIN}
    assert set(same) == {"example.net", "example.org", "example-shop.example", "examplebank.example"}
    assert all(p.expand is False and p.confidence <= 0.7 for p in same.values())
    # redirects with their dates (cond 5)
    rels = res.attributes["redirect_relations"]
    assert {"from": "example.com", "to": "www.example.org", "observed_at": "2026-11-20", "date_source": "hostio_web_date"} in rels
    assert {"from": "example.net", "to": "example.com", "observed_at": "2026-11-26", "date_source": "fetch"} in rels
    assert pivots(res, "redirected_from") == {"example.net", "www.example.org"}
    assert pivots(res, "redirects_to") == {"www.example.org"}
    # backlinks: expand=False, capped at 10
    back = [p for p in res.pivots if p.relation == "linked_from"]
    assert len(back) == mod.PIVOT_CAP and all(p.expand is False for p in back)
    # outbound links normalised and deduplicated
    assert pivots(res, "links_to") == {"example.net", "www.example.org", "www.iana.org"}
    assert all(p.expand is False for p in res.pivots if p.entity.type is T.DOMAIN)
    http.assert_hosts_within(HostIo)


def test_shared_id_by_related_count_spends_no_request():
    doc = fx("full_example_synthetic.json")
    doc["related"] = {"googleanalytics": [{"value": "UA-12345678", "count": 51}]}
    http = FakeHttp().add("GET", f"{API}/full/example.com", json=doc)
    res = run_module(HostIo, "domain:example.com", http, keys=KEYS)
    assert len(http.calls) == 1 and res.attributes["shared_tracking_ids"] == ["UA-12345678"]
    assert not pivots(res, "same_analytics", T.DOMAIN)


def test_clone_indicator_on_a_non_own_site_is_never_same_owner():
    res = run_module(HostIo, "domain:example.com", example_http(), keys=KEYS, org_profile=_org())
    clone = next(f for f in res.findings if f.title == "Organisation tracking id on a non-own site (possible clone)")
    assert clone.entity.value == "example.com" and clone.severity is Severity.MEDIUM
    assert "brand_abuse" in clone.tags and clone.confidence_label.value == "possible" and "example.org" in clone.criterion
    # the GA id shared with the own site gives no same_analytics link; the AdSense id still does
    domains = pivots(res, "same_analytics", T.DOMAIN)
    assert "example.org" not in domains and "example.net" not in domains
    assert domains == {"example-shop.example", "examplebank.example"}


def test_own_site_id_on_other_sites_flags_them_as_clone_candidates():
    http = FakeHttp()
    doc = fx("full_example_synthetic.json")
    doc["related"] = {"googleanalytics": [{"value": "UA-12345678", "count": 3}]}
    doc["web"]["url"] = "https://example.org/"
    http.add("GET", f"{API}/full/example.org", json=doc)
    http.add("GET", f"{API}/domains/googleanalytics/UA-12345678?limit=5", json=fx("domains_googleanalytics_ok_synthetic.json"))
    res = run_module(HostIo, "domain:example.org", http, keys=KEYS, org_profile=_org())
    clones = [f for f in res.findings if f.title.startswith("Organisation tracking id")]
    assert {f.entity.value for f in clones} == {"example.com", "example.net"}
    assert all("brand_abuse" in f.tags and f.severity is Severity.MEDIUM for f in clones)
    assert pivots(res, "copied_tracking_id") == {"example.com", "example.net"}
    assert all(p.expand is False for p in res.pivots if p.relation == "copied_tracking_id")
    assert not pivots(res, "same_analytics", T.DOMAIN)


# ------------------------------------------------------------------ analytics_id input
def test_analytics_id_reverse_lookup_uses_the_indexed_account_id():
    http = FakeHttp().add("GET", f"{API}/domains/googleanalytics/UA-61330992?limit=5", json=fx("domains_googleanalytics_docs.json"), match_headers=AUTH)
    res = run_module(HostIo, "analytics_id:UA-61330992-1", http, keys=KEYS)
    assert res.status is Status.OK
    assert pivots(res, "same_analytics") == {"minilex.fi", "minilex.at", "minilex.sk", "minilex.se", "minilex.be"}
    finding = next(f for f in res.findings if f.title.startswith("Domains sharing"))
    assert finding.data["total"] == 10 and "never scope" in finding.description


def test_analytics_id_on_more_than_50_domains_is_a_shared_id():
    http = FakeHttp().add("GET", f"{API}/domains/googleanalytics/UA-87654321?limit=5", json=fx("domains_googleanalytics_shared_synthetic.json"))
    res = run_module(HostIo, "analytics_id:UA-87654321-1", http, keys=KEYS)
    assert res.attributes["shared_tracking_ids"] == ["UA-87654321"]
    assert not res.pivots and all("shared_tracking_id" in f.tags for f in res.findings)


def test_adsense_and_gtm_fields():
    assert mod.id_field("ca-pub-1234567890123456") == "adsense" and mod.hostio_id("ca-pub-1234567890123456") == "pub-1234567890123456"
    assert mod.id_field("GTM-ABC1234") == "gtm" and mod.id_field("G-ABCDEF1234") == "googleanalytics"
    assert mod.hostio_id("UA-12345678-3") == "UA-12345678" and mod.id_field("AW-123456789") is None
    http = FakeHttp().add("GET", f"{API}/domains/gtm/GTM-ABC1234?limit=5", status=404, json={"error": "No details on 'gtm' found for GTM-ABC1234"})
    res = run_module(HostIo, "analytics_id:GTM-ABC1234", http, keys=KEYS)
    assert res.status is Status.EMPTY and "No details" in res.error


def test_unindexed_id_kind_is_not_applicable():
    res = run_module(HostIo, "analytics_id:AW-123456789", FakeHttp(), keys=KEYS)
    assert res.status is Status.SKIPPED and res.reason_code == "not_applicable"


# ------------------------------------------------------------------ statuses (cond 6: never EMPTY)
def test_real_token_required_400_is_needs_key():
    http = FakeHttp().add("GET", f"{API}/full/example.com", status=400, json=fx("error_token_required.json"))
    res = run_module(HostIo, "domain:example.com", http, keys=KEYS)
    assert res.status is Status.NEEDS_KEY and res.reason_code == "needs_key" and "API Access Token Required" in res.error


def test_invalid_token_inside_200_is_needs_key():
    http = FakeHttp().add("GET", f"{API}/full/example.com", json=fx("error_invalid_token_synthetic.json"))
    res = run_module(HostIo, "domain:example.com", http, keys=KEYS)
    assert res.status is Status.NEEDS_KEY


def test_quota_inside_200_is_quota():
    http = FakeHttp().add("GET", f"{API}/full/example.com", json=fx("error_quota_synthetic.json"))
    res = run_module(HostIo, "domain:example.com", http, keys=KEYS)
    assert res.status is Status.QUOTA and res.reason_code == "quota"


def test_throttling_is_rate_limited_in_200_and_429():
    http = FakeHttp().add("GET", f"{API}/full/example.com", json=fx("error_rate_limited_synthetic.json"))
    assert run_module(HostIo, "domain:example.com", http, keys=KEYS).status is Status.RATE_LIMITED
    http2 = FakeHttp().add("GET", f"{API}/full/example.com", status=429, json={"error": "too many requests"})
    assert run_module(HostIo, "domain:example.com", http2, keys=KEYS).status is Status.RATE_LIMITED


def test_documented_404_is_the_only_absence():
    http = FakeHttp().add("GET", f"{API}/full/example.com", status=404, json=fx("error_no_details_404.json"))
    res = run_module(HostIo, "domain:example.com", http, keys=KEYS)
    assert res.status is Status.EMPTY


def test_server_errors_challenges_and_junk_are_could_not_verify():
    http = FakeHttp().add("GET", f"{API}/full/example.com", status=503, text="unavailable")
    assert run_module(HostIo, "domain:example.com", http, keys=KEYS).status is Status.ERROR
    http2 = FakeHttp().add("GET", f"{API}/full/example.com", status=403, text=CHALLENGE)
    assert run_module(HostIo, "domain:example.com", http2, keys=KEYS).status is Status.BLOCKED
    http3 = FakeHttp().add("GET", f"{API}/full/example.com", body=b"{not json", headers={"content-type": "application/json"})
    assert run_module(HostIo, "domain:example.com", http3, keys=KEYS).status is Status.ERROR
    http4 = FakeHttp().add("GET", f"{API}/full/example.com", json=["not", "an", "object"])
    assert run_module(HostIo, "domain:example.com", http4, keys=KEYS).status is Status.ERROR
    http5 = FakeHttp().add("GET", f"{API}/full/example.com", json={"domain": "example.com"})
    res5 = run_module(HostIo, "domain:example.com", http5, keys=KEYS)
    assert res5.status is Status.ERROR and "could not verify" in res5.error
    http6 = FakeHttp().add("GET", f"{API}/full/example.com", json={"error": "Something unexpected"})
    assert run_module(HostIo, "domain:example.com", http6, keys=KEYS).status is Status.ERROR


def test_401_and_403_without_challenge_are_needs_key():
    for status in (401, 403):
        http = FakeHttp().add("GET", f"{API}/full/example.com", status=status, json={"error": "Unauthorized"})
        assert run_module(HostIo, "domain:example.com", http, keys=KEYS).status is Status.NEEDS_KEY


def test_the_token_never_reaches_the_result():
    res = run_module(HostIo, "domain:example.com", example_http(), keys=KEYS)
    assert_no_secret(KEY, res)


# ------------------------------------------------------------------ helpers
def test_reverse_decision_rules():
    own = {"own.example.com"}.__contains__
    shared = mod.reverse_decision("UA-1", 51, ["a.example.net"], "b.example.net", own)
    assert shared["decision"] == "shared" and not shared["candidates"]
    clone = mod.reverse_decision("UA-1", 2, ["own.example.com", "b.example.net"], "b.example.net", own)
    assert clone["decision"] == "clone" and clone["clones"] == ["b.example.net"]
    same = mod.reverse_decision("UA-1", 3, ["a.example.net", "b.example.net", "c.example.net"], "a.example.net", own)
    assert same["decision"] == "same_analytics" and same["candidates"] == ["b.example.net", "c.example.net"]


def test_parsers_tolerate_junk():
    assert mod.parse_web(None)["links"] == [] and mod.parse_related("x") == {} and mod.parse_ipinfo([]) == {}
    assert mod.parse_domains({"error": "x"}) is None and mod.parse_domains({"domains": "x"}) is None
    assert mod.parse_domains({"domains": ["Example.COM", "bad host", 3], "total": "7"}) == {"total": 7, "domains": ["example.com"]}


def _org():
    from v3lum.core.orgprofile import OrgProfile

    return OrgProfile.from_dict(ORG_OWNS_EXAMPLE_ORG)
