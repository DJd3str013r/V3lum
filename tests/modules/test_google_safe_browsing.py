"""google_safe_browsing (P067, batch p2-G03-1).

Fixtures in tests/fixtures/google_safe_browsing/ (prep p2-G03-1, 2026-11-26): the live keyless and
invalid-key error answers of both APIs (``*_nokey_403.json``, ``*_invalid_key_400.json``) and synthetic
answers in the documented shapes (``*_hit_synthetic``, ``*_miss_synthetic`` = ``{}``, quota 429,
SERVICE_DISABLED 403, 503): no keyless real hit or miss exists. Every file holds ``{status, body}``.
"""

from __future__ import annotations

import json
import urllib.parse

from tests.fakes import FakeClock, FakeHttp, assert_no_secret, module_fixture, run_module
from v3lum.core.entities import Entity
from v3lum.core.entities import EntityType as T
from v3lum.core.models import Status
from v3lum.modules.url_web import google_safe_browsing as mod
from v3lum.modules.url_web.google_safe_browsing import GoogleSafeBrowsing

WEBRISK = "https://webrisk.googleapis.com/v1/uris:search"
GSB = "https://safebrowsing.googleapis.com/v4/threatMatches:find"
KEY = "AIzaTESTKEY-0000000000000000000000000"
KEYS = {"webrisk": KEY}
CLOCK = FakeClock()


def fx(name: str) -> dict:
    return module_fixture("google_safe_browsing", name)


def webrisk_url(uri: str) -> str:
    return WEBRISK + "?" + urllib.parse.urlencode(mod.webrisk_query_params(uri, KEY))


def add_webrisk(http: FakeHttp, uri: str, name: str) -> FakeHttp:
    f = fx(name)
    return http.add("GET", webrisk_url(uri), status=f["status"], json=f["body"], headers={"Content-Type": "application/json"})


def test_metadata():
    cls = GoogleSafeBrowsing
    assert cls.terms == "noncommercial" and cls.default_enabled is True and cls.trust_tier == "trusted"
    assert set(cls.sources) == {"google_webrisk.uris_search", "google_safebrowsing.v4_lookup"}
    assert cls.upstream_families == frozenset({"google_safe_browsing"})  # one vote in consensus (c5)
    assert cls.manual_link == "url_reporting_g03:safe_browsing_status"
    assert "transparencyreport.google.com" not in cls.hosts  # c3: never automated


# ------------------------------------------------------------------ c6 keys
def test_no_key_is_one_coverage_line():
    http = FakeHttp()
    res = run_module(GoogleSafeBrowsing, "url:https://evil.example/login", http)
    assert res.status is Status.NEEDS_KEY and res.error == "needs Web Risk key"
    assert http.calls == []


def test_recorded_safe_browsing_403_maps_to_needs_key():
    f = fx("gsb_v4_nokey_403.json")
    http = FakeHttp().add("POST", GSB + "?key=" + KEY, status=f["status"], json=f["body"], headers={"Content-Type": "application/json"})
    res = run_module(GoogleSafeBrowsing, "url:https://evil.example/login", http, keys={"google_safebrowsing": KEY},
                     allowed_sources={"google_safebrowsing.v4_lookup"})
    assert res.status is Status.NEEDS_KEY and res.reason_code == "needs_key"


def test_recorded_webrisk_errors_map_to_needs_key():
    for name in ("webrisk_nokey_403.json", "webrisk_invalid_key_400.json", "webrisk_service_disabled_403_synthetic.json"):
        http = add_webrisk(FakeHttp(), "https://evil.example/login", name)
        res = run_module(GoogleSafeBrowsing, "url:https://evil.example/login", http, keys=KEYS)
        assert res.status is Status.NEEDS_KEY, name


def test_invalid_key_on_safe_browsing_400():
    f = fx("gsb_v4_invalid_key_400.json")
    http = FakeHttp().add("POST", GSB + "?key=" + KEY, status=400, json=f["body"])
    res = run_module(GoogleSafeBrowsing, "url:https://evil.example/", http, keys={"google_safebrowsing": KEY},
                     allowed_sources={"google_safebrowsing.v4_lookup"})
    assert res.status is Status.NEEDS_KEY


# ------------------------------------------------------------------ c5 hit / miss wording
def test_synthetic_webrisk_hit_names_threat_and_time():
    http = add_webrisk(FakeHttp(), "https://evil.example/login", "webrisk_hit_synthetic.json")
    res = run_module(GoogleSafeBrowsing, "url:https://evil.example/login", http, keys=KEYS, clock=CLOCK)
    assert res.status is Status.OK
    verdict = res.attributes["google_safe_browsing"]
    assert verdict["status"] == "hit" and verdict["threat_types"] == ["SOCIAL_ENGINEERING"]
    assert verdict["text"].startswith("Google Web Risk: SOCIAL_ENGINEERING at ") and verdict["text"].endswith(" UTC")
    f = res.findings[0]
    assert f.severity.label == "high" and "phishing" in f.tags and f.source == "google_webrisk.uris_search" and f.criterion
    http.assert_hosts_within(GoogleSafeBrowsing)


def test_synthetic_webrisk_miss_is_never_safe():
    http = add_webrisk(FakeHttp(), "https://evil.example/login", "webrisk_miss_synthetic.json")
    res = run_module(GoogleSafeBrowsing, "url:https://evil.example/login", http, keys=KEYS)
    text = res.attributes["google_safe_browsing"]["text"]
    assert text.startswith("not on Google's lists at ")
    assert "safe" not in json.dumps([res.attributes, [f.to_dict() for f in res.findings]]).replace("safe_browsing", "").lower()
    assert res.findings == []


def test_gsb_v4_hit_and_miss_research_path():
    hit = fx("gsb_v4_hit_synthetic.json")
    http = FakeHttp().add("POST", GSB + "?key=" + KEY, json=hit["body"])
    res = run_module(GoogleSafeBrowsing, "url:http://malware.testing.google.test/testing/malware/", http,
                     keys={"google_safebrowsing": KEY}, allowed_sources={"google_safebrowsing.v4_lookup"})
    assert res.attributes["google_safe_browsing"]["api"] == "safe_browsing_v4"
    assert "malware" in res.findings[0].tags
    miss = fx("gsb_v4_miss_synthetic.json")
    http2 = FakeHttp().add("POST", GSB + "?key=" + KEY, json=miss["body"])
    res2 = run_module(GoogleSafeBrowsing, "domain:example.com", http2, keys={"google_safebrowsing": KEY},
                      allowed_sources={"google_safebrowsing.v4_lookup"})
    assert res2.attributes["google_safe_browsing"]["status"] == "miss"


def test_web_risk_preferred_when_both_allowed():
    http = add_webrisk(FakeHttp(), "http://example.com/", "webrisk_miss_synthetic.json")
    res = run_module(GoogleSafeBrowsing, "domain:example.com", http, keys={"webrisk": KEY, "google_safebrowsing": KEY})
    assert res.attributes["google_safe_browsing"]["api"] == "web_risk"
    assert len(http.calls) == 1


def test_licence_blocked_sources_are_never_queried():
    http = FakeHttp()
    res = run_module(GoogleSafeBrowsing, "domain:example.com", http, keys=KEYS, allowed_sources=set())
    assert res.status is Status.SKIPPED and res.reason_code == "licence"
    assert http.calls == []


# ------------------------------------------------------------------ c4 minimisation
def test_recipient_identifiers_are_removed_before_the_lookup():
    raw = "https://evil.example/owa/login.php?email=victim%40example.com&sid=5f3c1a9e8b7d6c5f4e3d2c1b0a998877#victim@example.com"
    out = mod.minimise_lookup_url(raw)
    assert out["url"] == "https://evil.example/owa/login.php" and out["reduced"] is True
    http = add_webrisk(FakeHttp(), "https://evil.example/owa/login.php", "webrisk_miss_synthetic.json")
    res = run_module(GoogleSafeBrowsing, f"url:{raw}", http, keys=KEYS)
    assert res.attributes["lookup_minimisation"]["reduced"] is True
    sent = http.urls()[0]
    assert "victim" not in sent and "5f3c1a9e8b7d" not in sent


def test_sensitive_path_segment_cuts_the_path():
    out = mod.minimise_lookup_url("https://evil.example/u/dmljdGltQGV4YW1wbGUuY29t/login?x=1")
    assert out["url"] == "https://evil.example/u/" and out["reduced"]
    plain = mod.minimise_lookup_url("https://user:pw@evil.example/login?lang=en#top")
    assert plain["url"] == "https://evil.example/login?lang=en" and plain["reduced"] is True


def test_key_never_reaches_results():
    http = add_webrisk(FakeHttp(), "https://evil.example/login", "webrisk_hit_synthetic.json")
    res = run_module(GoogleSafeBrowsing, "url:https://evil.example/login", http, keys=KEYS)
    assert_no_secret(KEY, res.raw, res.attributes, [f.to_dict() for f in res.findings], res.error)


# ------------------------------------------------------------------ rule 5
def test_quota_429_503_and_malformed():
    http = add_webrisk(FakeHttp(), "https://evil.example/a", "webrisk_quota_429_synthetic.json")
    assert run_module(GoogleSafeBrowsing, "url:https://evil.example/a", http, keys=KEYS).status is Status.RATE_LIMITED
    f = fx("server_error_503_synthetic.json")
    http2 = FakeHttp().add("GET", webrisk_url("https://evil.example/b"), status=503, json=f["body"], times=5)
    assert run_module(GoogleSafeBrowsing, "url:https://evil.example/b", http2, keys=KEYS).status is Status.ERROR
    http3 = FakeHttp().add("GET", webrisk_url("https://evil.example/c"), text="{not json", headers={"Content-Type": "application/json"})
    res3 = run_module(GoogleSafeBrowsing, "url:https://evil.example/c", http3, keys=KEYS)
    assert res3.status is Status.ERROR and "could not verify" in res3.error


def test_daily_quota_maps_to_quota():
    body = {"error": {"code": 429, "status": "RESOURCE_EXHAUSTED", "message": "Quota exceeded for 'Lookup requests per day'"}}
    assert mod.google_api_error(429, body)["status"] == "quota"


def test_challenge_page_is_blocked():
    page = "<html><head><title>Just a moment...</title></head><body>cf-chl-widget</body></html>"
    http = FakeHttp().add("GET", webrisk_url("https://evil.example/d"), status=200, text=page, headers={"Content-Type": "text/html"})
    res = run_module(GoogleSafeBrowsing, "url:https://evil.example/d", http, keys=KEYS)
    assert res.status in (Status.BLOCKED, Status.ERROR)


def test_coverage_line_helper():
    assert mod.google_coverage_line("corporate", True, False).startswith("Google Web Risk skipped: licence")
    assert mod.google_coverage_line("research", False, True) == "needs Web Risk key"
    assert mod.google_coverage_line("corporate", True, True) is None


def test_non_http_url_not_applicable():
    res = run_module(GoogleSafeBrowsing, Entity.make(T.URL, "ftp://evil.example/file"), FakeHttp(), keys=KEYS)
    assert res.status is Status.SKIPPED
