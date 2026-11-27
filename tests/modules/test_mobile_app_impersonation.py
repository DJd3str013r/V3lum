"""mobile_app_impersonation (P346): official apps, look-alike review list, 403 handling, licence narrowing,
Digital Asset Links through the P008 client and Koodous with the company token.

Fixtures in tests/fixtures/mobile_app_impersonation/ (provenance in the prep notes of batch p2-G03-2):
real captures 2026-11-26 from a datacenter egress - ``itunes_search_bb_ok.json`` (term 'banco do brasil',
47 -> 8 records, fields trimmed; record 1 keeps one artwork and one screenshot URL to prove c3),
``itunes_search_google_ok.json`` (term 'google', 44 -> 10 records, with the real look-alike 'Google Forms
App'), ``itunes_lookup_ok.json``, ``itunes_blocked_403.headers.json`` (the empty-body 403),
``itunes_search_malformed.json`` (a real body cut in half), ``dal_google_ok.json`` (57 -> 10 statements),
``dal_not_published.json`` (example.com), ``dal_invalid_400.json``; the recorded research sample
``itunes_search_research_bb.json`` (gaps__app_store_search, P346 c9) and Koodous' keyless 401
(``koodous_needs_key_401.json``) and documentation example (``koodous_detail_docs_example.json``).
Synthetic (documentation values only): the files named ``*_synthetic.*`` and the two org profiles.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from tests.fakes import FakeClock, FakeHttp, make_ctx, module_fixture, run_module
from v3lum.core.context import ScanOptions
from v3lum.core.entities import EntityType as T
from v3lum.core.models import Status
from v3lum.core.orgprofile import OrgProfile
from v3lum.core.providers import registry
from v3lum.modules.domain_dns.digital_asset_links import statements_url
from v3lum.modules.url_web import mobile_app_impersonation as mod
from v3lum.modules.url_web.mobile_app_impersonation import MobileAppImpersonation

FIX = Path(__file__).resolve().parents[1] / "fixtures" / "mobile_app_impersonation"
JS = {"content-type": "text/javascript; charset=utf-8", "cache-control": "max-age=86400"}
DAL_SRC = "google_dal.statements"
KEY = "kd-test-token-0123456789abcdef"
EXPLICIT = ScanOptions(include={"mobile_app_impersonation"})


def raw(name: str) -> bytes:
    return (FIX / name).read_bytes()


def fx(name: str):
    return module_fixture(MobileAppImpersonation, name)


def org(name: str) -> OrgProfile:
    return OrgProfile.from_dict(fx(f"org_profile_{name}.json"))


def itunes(http: FakeHttp, term: str, name: str | None = None, *, status: int = 200, body: bytes | None = None,
           headers: dict | None = None, times: int | None = None) -> str:
    url = mod.itunes_search_url(term)
    content = raw(name) if name is not None else (body or b"")
    http.add("GET", url, status=status, body=content, headers=headers if headers is not None else JS, times=times)
    return url


def blocked_403(http: FakeHttp, term: str, *, times: int | None = None) -> str:
    hdrs = fx("itunes_blocked_403.headers.json")["headers"]
    return itunes(http, term, status=403, body=b"", headers=hdrs, times=times)


def dal(http: FakeHttp, domain: str, name: str, *, status: int = 200) -> str:
    url = statements_url(domain)
    http.add("GET", url, status=status, json=fx(name))
    return url


def calls(http: FakeHttp, url: str) -> list[dict]:
    return [c for c in http.calls if c.get("url") == url or str(c.get("url", "")).startswith(url)]


def review(res):
    return [f for f in res.findings if f.title.startswith("Possible ")]


# ---------------------------------------------------------------------------------------- metadata


def test_contract_metadata_matches_the_council():
    cls = MobileAppImpersonation
    assert cls.terms == "license" and cls.default_enabled is True  # c2: licence-gated default candidate (A3 BR4)
    assert cls.trust_tier == "community" and cls.disclosure == "third_party" and cls.opsec.label == "passive"
    assert cls.shares_input is True and cls.category == "url_web" and cls.run_on == "seeds"
    assert cls.accepts == {T.ORG, T.KEYWORD, T.DOMAIN} and cls.produces == {T.KEYWORD, T.SHA256, T.DOMAIN}
    assert set(cls.hosts) == {"itunes.apple.com", "digitalassetlinks.googleapis.com", "developer.koodous.com"}
    assert "f-droid.org" not in cls.hosts  # c4: F-Droid dropped from this build
    assert cls.sources == ("apple.itunes_search", DAL_SRC, "koodous.apks")  # c4: P008's source, no second client
    assert cls.terms_sources == {"apple.itunes_search": "license", DAL_SRC: "open", "koodous.apks": "key-terms"}
    assert cls.optional_keys == ("koodous",) and not cls.requires_keys  # c5
    assert cls.max_requests <= 10 and cls.expected_latency <= 10 and cls.cache_ttl == 86400
    assert cls.manual_link.startswith("https://play.google.com/store/search?q=")  # c5: Play as manual link only
    apple = registry().get("apple")
    assert apple.http_profile.min_interval == 3.0 and apple.quota.rate_per_second <= 20 / 60  # c3: <= 20 calls/min
    assert apple.tier == "trusted" and registry().get("koodous").tier == "community"
    assert registry().get("koodous").keys["koodous"].env == ("V3LUM_KOODOUS_TOKEN",)


# ---------------------------------------------------------------------------------------- c6/c9 official apps


def test_official_apps_recognised_in_the_real_bb_search():
    http = FakeHttp()
    itunes(http, "banco do brasil", "itunes_search_bb_ok.json")
    dal(http, "bb.com.br", "dal_not_published.json")
    res = run_module(MobileAppImpersonation, "company_name:Banco do Brasil", http, org_profile=org("bb"))
    assert res.status is Status.OK
    official = {a["track_id"]: a for a in res.attributes["official_apps"]}
    assert set(official) == {330984271, 1133309910, 1120718299}  # BB, Ourocard, Investimentos BB
    assert "developer_id" in official[330984271]["official_by"]
    assert "lookalike_apps" not in res.attributes  # Bradesco, Mercantil do Brasil, CNH do Brasil... are unrelated
    cov = res.attributes["app_store_coverage"]
    assert cov["terms_searched"] == ["banco do brasil"] and cov["dal_state"] == "not_published" and cov["unrelated"] == 5
    assert [f.title for f in res.findings] == ["Official apps recognised (known_good)"]
    assert ("Google Play search: banco do brasil (manual)",
            "https://play.google.com/store/search?q=banco%20do%20brasil&c=apps&hl=pt_BR&gl=BR") in res.links
    http.assert_hosts_within(MobileAppImpersonation)


def test_recorded_research_sample_recognises_the_official_app():
    """c9: the recorded gaps__app_store_search answer (research 2026-11-25)."""
    http = FakeHttp()
    itunes(http, "banco do brasil", "itunes_search_research_bb.json")
    dal(http, "bb.com.br", "dal_not_published.json")
    res = run_module(MobileAppImpersonation, "company_name:Banco do Brasil", http, org_profile=org("bb"))
    names = {a["name"]: a for a in res.attributes["official_apps"]}
    assert set(names) == {"BB: Banco, Cartão, Crédito", "Ourocard - Cartão de crédito."}
    assert names["BB: Banco, Cartão, Crédito"]["official_by"] == ["seller_name"]
    assert not review(res)


def test_c3_artwork_and_previews_never_leave_the_parser():
    http = FakeHttp()
    itunes(http, "banco do brasil", "itunes_search_bb_ok.json")
    dal(http, "bb.com.br", "dal_not_published.json")
    res = run_module(MobileAppImpersonation, "company_name:Banco do Brasil", http, org_profile=org("bb"))
    blob = json.dumps([res.attributes, res.raw, [f.to_dict() for f in res.findings], res.links], default=str)
    assert "mzstatic" not in blob and "artworkUrl" not in blob and "screenshot" not in blob.lower()
    assert "?uo=4" not in blob  # store URLs without Apple's tracking parameter


# ---------------------------------------------------------------------------------------- c6/c7/c9 look-alikes


def test_lookalikes_listed_for_review_at_low():
    http = FakeHttp()
    itunes(http, "banco do brasil", "itunes_search_lookalike_synthetic.json")
    dal(http, "bb.com.br", "dal_not_published.json")
    res = run_module(MobileAppImpersonation, "company_name:Banco do Brasil", http, org_profile=org("bb"))
    assert res.status is Status.OK
    items = res.attributes["lookalike_apps"]
    assert [i["track_id"] for i in items] == [102, 103, 101]  # the exact name copy ranks first
    assert all(i["category"] == "lookalike" for i in items)
    assert 104 not in {i["track_id"] for i in items}  # 'BBC News Example': 'bb' never matches inside 'bbc'
    claim = next(i for i in items if i["track_id"] == 103)  # seller URL bb.com.br + bundle br.com.bb.: not official (W4)
    assert any("organisation domain as seller URL" in r for r in claim["reasons"])
    assert any("bundle prefix" in r for r in claim["reasons"])
    assert any("publishes no Digital Asset Links" in r for r in claim["reasons"])
    findings = review(res)
    assert len(findings) == 3
    for f in findings:
        assert f.severity.label == "low" and f.confidence_label.value == "possible"  # c7
        assert f.data["label"] == "needs analyst review" and "lookalike_app" in f.tags
        assert "malicious" not in f.tags and "malicious" not in f.title.lower()
        assert f.criterion and f.source == "apple.itunes_search"
    assert any(f.title == "App-store review list" and f.severity.label == "info" for f in res.findings)
    # pivots expand=False only; the org domain used as a seller URL is never pivoted as a look-alike site
    assert res.pivots and all(p.expand is False for p in res.pivots)
    pivots = {(p.entity.type, p.entity.value, p.relation) for p in res.pivots}
    assert (T.KEYWORD, "net.example.bbtoken", "app_bundle_id") in pivots
    assert (T.DOMAIN, "apps.example.net", "app_seller_site") in pivots
    assert not any(p.entity.type is T.DOMAIN and p.entity.value.endswith("bb.com.br") for p in res.pivots)


def test_real_google_answers_official_and_one_lookalike():
    """c9 with real captures: Google LLC apps are official (also with non-google.com seller URLs), the real
    'Google Forms App' by another seller is listed for review, unrelated apps are only counted."""
    http = FakeHttp()
    itunes(http, "google", "itunes_search_google_ok.json")
    dal(http, "google.com", "dal_google_ok.json")
    dal(http, "youtube.com", "dal_not_published.json")
    res = run_module(MobileAppImpersonation, "domain:google.com", http, org_profile=org("google"))
    assert res.status is Status.OK
    official = res.attributes["official_apps"]
    apple = {a["name"] for a in official if a["store"] == "apple"}
    assert {"YouTube", "Google TV: assista filmes e TV", "Google Analytics", "Gmail: o e-mail do Google"} <= apple
    android = {a["bundle_id"]: a for a in official if a["store"] == "android"}
    assert "com.whereismytrain.android" in android  # c4: DAL lists apps outside the com.google. prefix
    assert android["com.google.android.calendar"]["official_by"] == ["digital_asset_links"]
    items = res.attributes["lookalike_apps"]
    assert [i["name"] for i in items] == ["Google Forms App"]
    assert items[0]["seller"] == "Aurora Innovation Limited" and items[0]["dal"] == "absent"
    assert "not listed in the official domain's Digital Asset Links" in items[0]["reasons"]
    assert res.attributes["app_store_coverage"]["dal_domains"] == ["google.com", "youtube.com"]


def test_review_list_is_capped_at_20():
    results = [{"kind": "software", "trackId": 5000 + i, "trackName": f"Banco do Brasil Token {i}", "bundleId": f"net.example.bb{i}",
                "sellerName": f"Example Apps {i} Ltd", "artistId": 900000 + i,
                "trackViewUrl": f"https://apps.apple.com/br/app/example/id{5000 + i}"} for i in range(25)]
    http = FakeHttp()
    itunes(http, "banco do brasil", body=json.dumps({"resultCount": 25, "results": results}).encode())
    dal(http, "bb.com.br", "dal_not_published.json")
    res = run_module(MobileAppImpersonation, "company_name:Banco do Brasil", http, org_profile=org("bb"))
    assert len(res.attributes["lookalike_apps"]) == 20 and len(review(res)) == 20  # c7
    summary = next(f for f in res.findings if f.title == "App-store review list")
    assert "25 app(s) for analyst review (showing 20, 5 more not shown)" in summary.description
    assert res.attributes["app_store_coverage"]["review_total"] == 25


# ---------------------------------------------------------------------------------------- c3/c9 403 handling


def test_403_is_retried_once_with_the_same_request_then_answers():
    clock = FakeClock()
    http = FakeHttp()
    url = blocked_403(http, "banco do brasil", times=1)
    itunes(http, "banco do brasil", "itunes_search_bb_ok.json")
    dal(http, "bb.com.br", "dal_not_published.json")
    res = run_module(MobileAppImpersonation, "company_name:Banco do Brasil", http, org_profile=org("bb"), clock=clock)
    assert res.status is Status.OK and len(res.attributes["official_apps"]) == 3
    sent = calls(http, url)
    assert len(sent) == 2
    ua = [{k.lower(): v for k, v in (c.get("headers") or {}).items()}.get("user-agent") for c in sent]
    assert ua[0] == ua[1] and ua[0]  # P326: never another UA after a 403
    assert sent[0].get("headers") == sent[1].get("headers")
    assert sum(clock.sleeps) >= mod.ITUNES_MIN_INTERVAL_S  # the retry waited Apple's politeness interval (c3)


def test_403_twice_is_blocked_could_not_verify():
    http = FakeHttp()
    url = blocked_403(http, "banco do brasil")
    dal(http, "bb.com.br", "dal_not_published.json")
    res = run_module(MobileAppImpersonation, "company_name:Banco do Brasil", http, org_profile=org("bb"))
    assert res.status is Status.BLOCKED and res.reason_code == "challenge"
    assert "could not verify" in res.error and "after one retry" in res.error
    assert "no apps" not in res.error.lower() and "not found" not in res.error.lower()  # rule 5
    assert len(calls(http, url)) == 2  # exactly one retry
    assert res.source_statuses["apple.itunes_search"]["status"] == "blocked"


def test_403_without_time_left_is_not_retried():
    clock = FakeClock()
    http = FakeHttp()
    url = blocked_403(http, "banco do brasil")
    dal(http, "bb.com.br", "dal_not_published.json")
    res = run_module(MobileAppImpersonation, "company_name:Banco do Brasil", http, org_profile=org("bb"), clock=clock,
                     deadline=clock.monotonic() + 6)
    assert res.status is Status.BLOCKED and "no time left for the retry" in res.error
    assert len(calls(http, url)) == 1


def test_403_with_a_configured_koodous_key_is_still_handled_as_apple_refusal():
    http = FakeHttp()
    blocked_403(http, "banco do brasil")
    dal(http, "bb.com.br", "dal_not_published.json")
    res = run_module(MobileAppImpersonation, "company_name:Banco do Brasil", http, org_profile=org("bb"), keys={"koodous": KEY})
    assert res.status is Status.BLOCKED and res.reason_code == "challenge"  # never NEEDS_KEY for keyless Apple


@pytest.mark.parametrize(("body", "code"), [
    ("itunes_akamai_denied_synthetic.html", "geo_block"),
    (None, "challenge"),
])
def test_challenge_and_edge_pages_are_blocked_without_retry(body, code):
    http = FakeHttp()
    content = raw(body) if body else (b"<html><head><title>Just a moment...</title></head><body>"
                                      b"<div id='cf-chl-widget'></div><script src='/cdn-cgi/challenge-platform/x'></script></body></html>")
    url = itunes(http, "banco do brasil", status=403, body=content, headers={"content-type": "text/html"})
    dal(http, "bb.com.br", "dal_not_published.json")
    res = run_module(MobileAppImpersonation, "company_name:Banco do Brasil", http, org_profile=org("bb"))
    assert res.status is Status.BLOCKED and res.reason_code == code
    assert len(calls(http, url)) == 1  # A9: a challenge or geo-block is never retried


# ---------------------------------------------------------------------------------------- other failures (rule 5)


def test_429_is_rate_limited():
    http = FakeHttp()
    itunes(http, "banco do brasil", status=429, body=b"", headers={})
    dal(http, "bb.com.br", "dal_not_published.json")
    res = run_module(MobileAppImpersonation, "company_name:Banco do Brasil", http, org_profile=org("bb"))
    assert res.status is Status.RATE_LIMITED and res.reason_code == "rate_limited"


def test_5xx_is_could_not_verify():
    http = FakeHttp()
    itunes(http, "banco do brasil", status=503, body=b"Service Unavailable", headers={"content-type": "text/plain"})
    dal(http, "bb.com.br", "dal_not_published.json")
    res = run_module(MobileAppImpersonation, "company_name:Banco do Brasil", http, org_profile=org("bb"))
    assert res.status is Status.ERROR and "could not verify" in res.error


@pytest.mark.parametrize("status", [200, 400])
def test_error_message_body_is_could_not_verify(status):
    http = FakeHttp()
    itunes(http, "banco do brasil", "itunes_error_400_synthetic.json", status=status)
    dal(http, "bb.com.br", "dal_not_published.json")
    res = run_module(MobileAppImpersonation, "company_name:Banco do Brasil", http, org_profile=org("bb"))
    assert res.status is Status.ERROR and "could not verify" in res.error


@pytest.mark.parametrize("body", [raw("itunes_search_malformed.json"), b"<html><body>maintenance</body></html>", b"[1, 2]"])
def test_malformed_answers_are_errors_never_empty(body):
    http = FakeHttp()
    itunes(http, "banco do brasil", body=body)
    dal(http, "bb.com.br", "dal_not_published.json")
    res = run_module(MobileAppImpersonation, "company_name:Banco do Brasil", http, org_profile=org("bb"))
    assert res.status is Status.ERROR and "could not verify" in res.error


def test_no_results_is_empty_with_honest_wording():
    http = FakeHttp()
    itunes(http, "banco do brasil", "itunes_search_empty_synthetic.json")
    dal(http, "bb.com.br", "dal_not_published.json")
    res = run_module(MobileAppImpersonation, "company_name:Banco do Brasil", http, org_profile=org("bb"))
    assert res.status is Status.EMPTY
    assert res.error.startswith("App Store BR: no apps found for 'banco do brasil'")
    assert "no impersonation" not in res.error.lower()


def test_only_unrelated_apps_is_empty_and_says_what_was_found():
    http = FakeHttp()
    itunes(http, "banco do brasil", "itunes_search_google_ok.json")
    dal(http, "bb.com.br", "dal_not_published.json")
    res = run_module(MobileAppImpersonation, "company_name:Banco do Brasil", http, org_profile=org("bb"))
    assert res.status is Status.EMPTY and res.error.startswith("App Store BR: 10 app(s) found for 'banco do brasil'")
    assert res.attributes["app_store_coverage"]["unrelated"] == 10


def test_dal_could_not_verify_still_lists_lookalikes():
    http = FakeHttp()
    itunes(http, "banco do brasil", "itunes_search_lookalike_synthetic.json")
    dal(http, "bb.com.br", "dal_forbidden_403_synthetic.json", status=403)
    res = run_module(MobileAppImpersonation, "company_name:Banco do Brasil", http, org_profile=org("bb"))
    assert res.status is Status.OK and len(res.attributes["lookalike_apps"]) == 3
    assert all("Digital Asset Links not verified (could not verify)" in i["reasons"] for i in res.attributes["lookalike_apps"])
    assert res.source_statuses[DAL_SRC]["status"] in ("blocked", "error")


def test_dal_error_object_is_could_not_verify():
    http = FakeHttp()
    itunes(http, "banco do brasil", "itunes_search_lookalike_synthetic.json")
    dal(http, "bb.com.br", "dal_invalid_400.json", status=400)
    res = run_module(MobileAppImpersonation, "company_name:Banco do Brasil", http, org_profile=org("bb"))
    assert res.status is Status.OK and res.source_statuses[DAL_SRC]["status"] == "error"
    assert res.attributes["app_store_coverage"]["dal_state"] == "unknown"


def test_real_keyless_koodous_401_maps_to_needs_key():
    hdrs = fx("koodous_needs_key_401.headers.json")
    http = FakeHttp()
    itunes(http, "google", "itunes_search_google_ok.json")
    dal(http, "google.com", "dal_google_ok.json")
    dal(http, "youtube.com", "dal_not_published.json")
    http.add("GET", koodous_url("com.google.android.calendar"), status=hdrs["status"], body=raw("koodous_needs_key_401.json"),
             headers=hdrs["headers"])
    res = run_module(MobileAppImpersonation, "domain:google.com", http, org_profile=org("google"), keys={"koodous": KEY})
    assert res.source_statuses["koodous.apks"]["status"] == "needs_key"
    assert "valid company token" in res.source_statuses["koodous.apks"]["reason"]


def test_network_error_is_could_not_verify():
    from v3lum.core.http import NetworkError

    http = FakeHttp()
    http.add("GET", mod.itunes_search_url("banco do brasil"), error=NetworkError("connection reset"))
    dal(http, "bb.com.br", "dal_not_published.json")
    res = run_module(MobileAppImpersonation, "company_name:Banco do Brasil", http, org_profile=org("bb"))
    assert res.status is Status.ERROR and "could not verify" in res.error


# ---------------------------------------------------------------------------------------- c1 brand terms


def test_c1_company_outside_the_profile_needs_explicit_selection():
    http = FakeHttp()
    res = run_module(MobileAppImpersonation, "company_name:Example Bank", http, org_profile=org("bb"))
    assert res.status is Status.SKIPPED and res.reason_code == "not_applicable" and "-M" in res.error
    assert http.calls == []


def test_c1_explicit_company_seed_is_searched_and_is_the_identity():
    http = FakeHttp()
    itunes(http, "banco do brasil", "itunes_search_bb_ok.json")
    res = run_module(MobileAppImpersonation, "company_name:Banco do Brasil S.A.", http, options=EXPLICIT)
    assert res.status is Status.OK  # no org profile: the typed company is the identity checked (c6)
    assert {a["track_id"] for a in res.attributes["official_apps"]} >= {330984271, 1133309910}
    assert res.attributes["app_store_coverage"]["sources"][DAL_SRC] == "not run (no org_profile domain)"


def test_c1_keyword_seed_without_profile_flags_missing_identity():
    http = FakeHttp()
    itunes(http, "ourocard", "itunes_search_bb_ok.json")
    res = run_module(MobileAppImpersonation, "keyword:Ourocard", http, options=EXPLICIT)
    items = res.attributes["lookalike_apps"]
    assert [i["name"] for i in items] == ["Ourocard - Cartão de crédito."]
    assert any("no organisation identity to compare" in r for r in items[0]["reasons"])


def test_c1_pivots_never_run():
    http = FakeHttp()
    res = run_module(MobileAppImpersonation, "keyword:Banco do Brasil", http, org_profile=org("bb"), is_seed=False, depth=1)
    assert res.status is Status.SKIPPED and res.reason_code == "not_applicable" and http.calls == []


def test_c1_domain_outside_the_profile_is_never_a_brand_source():
    http = FakeHttp()
    res = run_module(MobileAppImpersonation, "domain:example.com", http, org_profile=org("bb"), options=EXPLICIT)
    assert res.status is Status.SKIPPED and res.reason_code == "not_applicable" and http.calls == []


def test_c1_org_domain_searches_the_org_brands():
    http = FakeHttp()
    itunes(http, "banco do brasil", "itunes_search_bb_ok.json")
    dal(http, "bb.com.br", "dal_not_published.json")
    res = run_module(MobileAppImpersonation, "domain:bb.com.br", http, org_profile=org("bb"))
    assert res.status is Status.OK and res.attributes["app_store_coverage"]["terms_searched"] == ["banco do brasil"]


def test_no_brands_in_the_profile_is_a_configuration_skip():
    profile = OrgProfile.from_dict({"org": {"name": "Example Corp"}, "domains": [{"name": "example.com", "verification": "confirmed"}]})
    res = run_module(MobileAppImpersonation, "domain:example.com", FakeHttp(), org_profile=profile)
    assert res.status is Status.SKIPPED and res.reason_code == "config"


# ---------------------------------------------------------------------------------------- c2 licence narrowing


def test_c2_itunes_never_called_when_the_licence_profile_blocks_it():
    http = FakeHttp()
    dal(http, "google.com", "dal_google_ok.json")
    dal(http, "youtube.com", "dal_not_published.json")
    res = run_module(MobileAppImpersonation, "domain:google.com", http, org_profile=org("google"), allowed_sources={DAL_SRC})
    assert not [u for u in http.urls() if "itunes.apple.com" in u]
    assert res.status is Status.OK  # the official Android apps of the org domain still stand
    assert "licence profile" in res.attributes["app_store_coverage"]["sources"]["apple.itunes_search"]
    assert all(a["store"] == "android" for a in res.attributes["official_apps"])
    assert res.links  # coverage lost to the profile is backed by the manual Play link


def test_c2_nothing_allowed_but_dal_and_nothing_published_is_empty():
    http = FakeHttp()
    dal(http, "bb.com.br", "dal_not_published.json")
    res = run_module(MobileAppImpersonation, "company_name:Banco do Brasil", http, org_profile=org("bb"), allowed_sources={DAL_SRC})
    assert res.status is Status.EMPTY and "no app-store source ran" in res.error and "licence" in res.error


# ---------------------------------------------------------------------------------------- c5 Koodous


def koodous_url(pkg: str) -> str:
    return mod.koodous_search_url(package=pkg)


def test_c5_koodous_without_token_is_needs_key_and_never_called():
    http = FakeHttp()
    itunes(http, "google", "itunes_search_google_ok.json")
    dal(http, "google.com", "dal_google_ok.json")
    dal(http, "youtube.com", "dal_not_published.json")
    res = run_module(MobileAppImpersonation, "domain:google.com", http, org_profile=org("google"))
    assert res.status is Status.OK
    assert res.source_statuses["koodous.apks"] == {"status": "needs_key", "reason_code": "needs_key",
                                                   "reason": "Koodous: needs the company token (key 'koodous', V3LUM_KOODOUS_TOKEN)"}
    assert not [u for u in http.urls() if "koodous" in u]


def test_c5_koodous_package_lookup_with_the_company_token():
    http = FakeHttp()
    itunes(http, "google", "itunes_search_google_ok.json")
    dal(http, "google.com", "dal_google_ok.json")
    dal(http, "youtube.com", "dal_not_published.json")
    first = koodous_url("com.google.android.calendar")
    http.add("GET", first, json=fx("koodous_search_official_package_synthetic.json"), match_headers={"Authorization": f"Token {KEY}"})
    http.add("GET", koodous_url("com.google.android.gms"), json=fx("koodous_search_empty_synthetic.json"))
    res = run_module(MobileAppImpersonation, "domain:google.com", http, org_profile=org("google"), keys={"koodous": KEY})
    assert res.status is Status.OK and "koodous.apks" not in res.source_statuses
    assert len([u for u in http.urls() if "koodous" in u]) == 2  # KOODOUS_MAX_LOOKUPS
    official = [a for a in res.attributes["official_apps"] if a["name"] == "Google Calendar"]
    assert official and official[0]["official_by"] == ["seller_name"]
    repack = next(i for i in res.attributes["lookalike_apps"] if i["store"] == "android")
    assert repack["category"] == "unverified" and repack["sha256"].startswith("a1b2c3d4")
    assert repack["koodous"]["label"] == "detected"  # community context, never a verdict (c7)
    finding = next(f for f in review(res) if "unverified_app" in f.tags)
    assert finding.severity.label == "low" and finding.source == "koodous.apks" and "malicious" not in finding.tags
    assert (T.SHA256, repack["sha256"], "apk_sample") in {(p.entity.type, p.entity.value, p.relation) for p in res.pivots}
    assert any(url.startswith("https://play.google.com/store/apps/details?id=com.google.android.calendar") for _l, url in res.links)
    from tests.fakes import assert_no_secret

    assert_no_secret(KEY, res.raw, res.attributes, [f.to_dict() for f in res.findings], res.error)


@pytest.mark.parametrize(("name", "status", "expect"), [
    ("koodous_needs_key_401.json", 401, "needs_key"),
    ("koodous_invalid_token_401_synthetic.json", 401, "needs_key"),
    ("koodous_throttled_429_synthetic.json", 429, "quota"),
])
def test_c5_koodous_refusals_are_reported_per_feed(name, status, expect):
    http = FakeHttp()
    itunes(http, "google", "itunes_search_google_ok.json")
    dal(http, "google.com", "dal_google_ok.json")
    dal(http, "youtube.com", "dal_not_published.json")
    http.add("GET", koodous_url("com.google.android.calendar"), status=status, json=fx(name))
    res = run_module(MobileAppImpersonation, "domain:google.com", http, org_profile=org("google"), keys={"koodous": KEY})
    assert res.status is Status.OK  # the App Store results stand
    assert res.source_statuses["koodous.apks"]["status"] == expect
    assert len([u for u in http.urls() if "koodous" in u]) == 1  # a refusal stops further Koodous calls


def test_koodous_read_endpoints_only():
    assert mod.koodous_path_allowed(koodous_url("com.example.app"))
    assert mod.koodous_path_allowed(mod.koodous_detail_url("ab" * 32))
    for action in mod.KOODOUS_STATE_CHANGING:
        assert not mod.koodous_path_allowed(f"https://developer.koodous.com/apks/{'ab' * 32}/{action}/")
    assert mod.koodous_search_url(package="not a package") is None
    parsed = mod.parse_koodous_search(raw("koodous_detail_docs_example.json"))
    assert parsed["state"] == "ok" and parsed["apks"][0]["package"] == "com.samsung.android.stickercenter"
    assert "image" not in parsed["apks"][0]  # no artwork (c3 analogue)
    assert mod.parse_koodous_search(raw("koodous_search_empty_synthetic.json"))["state"] == "empty"
    listed = mod.parse_koodous_search(raw("koodous_search_ok_synthetic.json"))
    assert [a["package"] for a in listed["apks"]] == ["com.samsung.android.stickercenter", "com.example.bbtoken"]
    assert listed["apks"][1]["detected"] is True and mod.koodous_signal(listed["apks"][1])["label"] == "detected"
    assert mod.parse_koodous_search(raw("koodous_not_found_404_synthetic.json"))["state"] == "error"


# ---------------------------------------------------------------------------------------- helpers and c8


def test_parsers_never_raise_on_junk():
    for junk in (None, b"", b"\x00\xff", "[]", "{}", '{"results": "x"}', '{"results": [1, null, {"trackName": 5}]}', 42):
        out = mod.parse_itunes_results(junk)
        assert out["state"] in ("error", "empty") and isinstance(out["apps"], list)
    lookup = mod.parse_itunes_results(raw("itunes_lookup_ok.json"))
    assert lookup["state"] == "ok" and lookup["apps"][0]["developer_id"] == "330984274"
    assert lookup["apps"][0]["store_url"] == "https://apps.apple.com/br/app/bb-banco-cart%C3%A3o-cr%C3%A9dito/id330984271"
    assert mod.itunes_search_url("banco do brasil") == (
        "https://itunes.apple.com/search?term=banco%20do%20brasil&entity=software&country=br&limit=50")
    assert mod.itunes_lookup_url(track_id=330984271) == "https://itunes.apple.com/lookup?id=330984271&country=br"


def test_brand_matching_rules():
    assert mod.brand_hits("BB Token Seguro", ["bb"]) == ["bb"]
    assert mod.brand_hits("BBC News", ["bb"]) == []  # short terms only as whole tokens
    assert mod.brand_hits("G00gle Forms", ["google"]) == ["google"]  # leet folding
    assert mod.brand_hits("BancodoBrasil Token", ["banco do brasil"]) == ["banco do brasil"]
    assert mod.brand_hits("Itaú Personnalité", ["itau"]) == ["itau"]  # accents folded
    assert mod.seller_key("BANCO BRADESCO S.A.") == "banco bradesco" and mod.seller_key("Google LLC") == "google"


def test_c8_apk_links_are_url_entities_only():
    assert mod.is_apk_url("https://cdn.example.com/files/BB-Atualizacao.apk")
    assert mod.is_apk_url("https://example.com/dl?file=app.APK")
    assert not mod.is_apk_url("https://example.com/apk-info.html") and not mod.is_apk_url("ftp://example.com/a.apk")
    ents = mod.apk_url_entities(["https://cdn.example.com/files/BB-Atualizacao.apk", "https://example.com/x", 5,
                                 "https://cdn.example.com/files/BB-Atualizacao.apk"])
    assert ents == [{"type": T.URL, "value": "https://cdn.example.com/files/BB-Atualizacao.apk", "expand": False,
                     "fetch": False, "download": False, "tags": ["apk_link"], "filename": "BB-Atualizacao.apk"}]


def test_selftest_uses_the_central_benign_domain():
    http = FakeHttp()
    dal(http, "example.com", "dal_not_published.json")
    ctx = make_ctx(MobileAppImpersonation, http, allowed_sources={DAL_SRC})
    hc = MobileAppImpersonation.health_check()
    assert hc.offline is False and hc.selftest(ctx).status == "ok"
    http2 = FakeHttp()
    dal(http2, "example.com", "dal_not_published.json")
    itunes(http2, "wikipedia", status=403, body=b"", headers={})
    ctx2 = make_ctx(MobileAppImpersonation, http2)
    assert hc.selftest(ctx2).status == "blocked"
