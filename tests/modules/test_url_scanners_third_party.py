"""Offline tests of url_scanners_third_party (P078: urlDNA + urlquery search, existing captures only)."""

from __future__ import annotations

import json
import re
from pathlib import Path

import pytest

from tests.fakes import FakeClock, FakeHttp, module_fixture, run_module
from v3lum.core.http import PolicyError
from v3lum.core.models import Opsec, Status
from v3lum.modules.url_web import url_scanners_third_party as mod
from v3lum.modules.url_web.url_scanners_third_party import UrlScannersThirdParty

KEYS = {"urldna": "dna-test-key-0000000000000000", "urlquery": "uq-test-key-0000000000000000"}
URLDNA_SEARCH = "https://api.urldna.io/v1/search"
URLDNA_SCAN = "https://api.urldna.io/v1/scan/6745aa00c0ffee0000000001"
URLQUERY = "https://api.urlquery.net/public/v2/reports/search*"
CHALLENGE = "<html><head><title>Just a moment...</title></head><body>cf-chl-widget</body></html>"


def fx(name: str) -> dict:
    return module_fixture("url_scanners_third_party", name)


def add(http: FakeHttp, method: str, url: str, envelope: dict, **kw) -> FakeHttp:
    body = envelope.get("body")
    headers = dict(envelope.get("headers") or {})
    if isinstance(body, (dict, list)):
        return http.add(method, url, status=envelope["status"], json=body, headers=headers, **kw)
    return http.add(method, url, status=envelope["status"], text=str(body or ""), headers=headers, **kw)


def run(entity: str, http: FakeHttp, keys: dict | None = KEYS):
    return run_module(UrlScannersThirdParty, entity, http, keys=dict(keys or {}), clock=FakeClock())


def happy_http() -> FakeHttp:
    http = FakeHttp()
    add(http, "POST", URLDNA_SEARCH, fx("urldna_search_ok_documented.http.json"),
        match_headers={"Authorization": "Bearer " + KEYS["urldna"]})
    add(http, "GET", URLDNA_SCAN, fx("urldna_scan_result_ok_documented.http.json"))
    add(http, "GET", URLQUERY, fx("urlquery_search_ok_documented.http.json"), match_headers={"x-apikey": KEYS["urlquery"]})
    return http


# ---- metadata (council decisions) -------------------------------------------------------------


def test_metadata_matches_the_council_decision():
    cls = UrlScannersThirdParty
    assert cls.default_enabled is False
    assert cls.terms == "key-terms"
    assert cls.trust_tier == "community"
    assert cls.disclosure == "third_party" and cls.shares_input is True
    assert cls.opsec is Opsec.PASSIVE  # c1/c2 removed every target-touching path
    assert cls.run_on == "seeds"
    assert set(cls.optional_keys) == {"urldna", "urlquery"}
    assert set(cls.hosts) == {"api.urldna.io", "api.urlquery.net"}
    assert cls.publishes_queries is False and cls.fetches_target is False


# ---- happy path ---------------------------------------------------------------------------------


def test_existing_scans_become_dated_third_party_verdicts():
    http = happy_http()
    res = run("domain:login.example.com", http)
    assert res.status is Status.OK, res.error
    scans = res.attributes["third_party_scans"]
    by_source = {}
    for s in scans:
        by_source.setdefault(s["source"], []).append(s)
    dna = by_source["urldna.search"]
    assert dna[0]["verdict"] == "malicious" and dna[0]["scan_date"] == "2026-11-20T10:15:00Z" and dna[0]["historical"] is False
    assert dna[0]["title"] == "Entrar - Example Bank"
    old = [s for s in dna if s["scan_id"].endswith("02")][0]
    assert old["historical"] is True and "verdict" not in old  # ERROR scan: no verdict read
    uq = by_source["urlquery.search"]
    assert {s["verdict_summary"] for s in uq} == {"malicious", "no_alerts"}  # never 'benign'
    assert [s for s in uq if s["verdict_summary"] == "no_alerts"][0]["historical"] is True
    votes = res.attributes["third_party_scan_votes"]
    assert votes["ground_truth"] is False
    assert {(v["source"], v["vote"]) for v in votes["votes"]} == {("urldna.search", "malicious"), ("urlquery.search", "malicious")}
    titles = {f.title for f in res.findings}
    assert "urlDNA: existing scan verdict 'malicious'" in titles and "urlquery: existing scan verdict 'malicious'" in titles
    for f in res.findings:
        if f.severity.label != "info":
            assert f.criterion and "third_party_verdict" in f.tags and f.source in UrlScannersThirdParty.sources
    pivots = {(p.entity.type.value, p.entity.value, p.relation) for p in res.pivots}
    assert ("url", "https://login.example.com/secure/index.php", "scanner_final_url") in pivots
    assert any(rel == "scanner_final_host" and val == "example.com" for _t, val, rel in pivots)
    assert res.attributes["third_party_scan_summary"]["urlquery"]["total"] == 2
    http.assert_hosts_within(UrlScannersThirdParty)
    # c1: only the approved endpoints were requested, and never a scan/submission
    for call in http.calls:
        assert mod.allowed_request(call["method"], call["url"]) is None, call["url"]


def test_emails_and_tokens_in_result_urls_are_redacted_before_evidence():
    http = FakeHttp()
    add(http, "POST", URLDNA_SEARCH, fx("urldna_search_ok_documented.http.json"))
    env = fx("urldna_scan_result_ok_documented.http.json")
    env = json.loads(json.dumps(env))
    env["body"]["scan"]["target_url"] = "https://login.example.com/secure/index.php?u=user%40example.com"
    add(http, "GET", URLDNA_SCAN, env)
    res = run("domain:login.example.com", http, keys={"urldna": KEYS["urldna"]})
    blob = json.dumps({"a": res.attributes, "raw": res.raw, "p": [p.entity.value for p in res.pivots]}, default=str)
    assert "user%40example.com" not in blob and "user@example.com" not in blob
    # a redacted URL is never a pivot (the other scan's plain final URL still is)
    assert not any(p.relation == "scanner_final_url" and "index.php" in p.entity.value for p in res.pivots)
    assert KEYS["urldna"] not in blob


def test_url_input_uses_submitted_url_and_url_addr_queries():
    http = FakeHttp()
    add(http, "POST", URLDNA_SEARCH, fx("urldna_search_empty_documented.http.json"))
    add(http, "GET", URLQUERY, fx("urlquery_search_empty_documented.http.json"))
    res = run("url:https://login.example.com/secure/", http)
    assert res.status is Status.EMPTY
    dna = [c for c in http.calls if "urldna" in c["url"]][0]
    assert json.loads(dna["body"])["query"] == 'submitted_url = "https://login.example.com/secure/"'
    uq = [c for c in http.calls if "urlquery" in c["url"]][0]
    assert "url.addr" in uq["url"] and "date%3A%5B2025-11-26+TO+2026-11-26%5D" in uq["url"].replace("%20", "+")


# ---- keys (c4) -----------------------------------------------------------------------------------


def test_no_keys_is_needs_key_and_sends_nothing():
    http = FakeHttp()
    res = run("domain:example.com", http, keys={})
    assert res.status is Status.NEEDS_KEY and res.reason_code == "needs_key"
    assert res.source_statuses["urldna.search"]["status"] == "needs_key"
    assert res.source_statuses["urlquery.search"]["status"] == "needs_key"
    assert http.calls == []


def test_each_adapter_has_its_own_status():
    http = FakeHttp()
    add(http, "GET", URLQUERY, fx("urlquery_search_ok_documented.http.json"))
    res = run("domain:example.com", http, keys={"urlquery": KEYS["urlquery"]})
    assert res.status is Status.OK
    assert res.source_statuses["urldna.search"]["status"] == "needs_key"
    assert res.source_statuses["urlquery.search"]["status"] == "ok"  # the answering source is counted by coverage
    assert {s["source"] for s in res.attributes["third_party_scans"]} == {"urlquery.search"}


def test_recorded_urldna_keyless_422_is_needs_key():
    http = FakeHttp()
    add(http, "POST", URLDNA_SEARCH, fx("urldna_nokey_422.http.json"))
    res = run("domain:example.com", http, keys={"urldna": KEYS["urldna"]})
    assert res.status is Status.NEEDS_KEY
    assert "authorization header field required" in res.source_statuses["urldna.search"]["reason"]


@pytest.mark.parametrize("fixture", ["urlquery_v1_nokey_401.http.json", "urlquery_nokey_401_documented.http.json",
                                     "urlquery_v2_nokey_401_observed.http.json", "urlquery_invalid_key_403_documented.http.json",
                                     "urlquery_invalid_key_403_observed.http.json"])
def test_urlquery_missing_or_invalid_key_is_needs_key(fixture):
    http = FakeHttp()
    add(http, "GET", URLQUERY, fx(fixture))
    res = run("domain:example.com", http, keys={"urlquery": KEYS["urlquery"]})
    assert res.status is Status.NEEDS_KEY and res.source_statuses["urlquery.search"]["status"] == "needs_key"


@pytest.mark.parametrize("fixture", ["urldna_invalid_key_401_documented.http.json", "urldna_invalid_key_401_observed.http.json"])
def test_urldna_invalid_key_and_urlquery_rate_limit_are_could_not_verify(fixture):
    http = FakeHttp()
    add(http, "POST", URLDNA_SEARCH, fx(fixture))
    add(http, "GET", URLQUERY, fx("urlquery_rate_limited_429_documented.http.json"))
    res = run("domain:example.com", http)
    assert res.status is Status.RATE_LIMITED and res.reason_code == "rate_limited"
    assert res.source_statuses["urldna.search"]["status"] == "needs_key"
    assert res.source_statuses["urlquery.search"]["status"] == "rate_limited"


def test_urldna_429_with_other_source_answering_keeps_the_answer():
    http = FakeHttp()
    add(http, "POST", URLDNA_SEARCH, fx("urldna_rate_limited_429_documented.http.json"))
    add(http, "GET", URLQUERY, fx("urlquery_search_empty_documented.http.json"))
    res = run("domain:example.com", http)
    assert res.status is Status.EMPTY  # urlquery answered with nothing; urlDNA could not verify
    assert res.source_statuses["urldna.search"]["status"] == "rate_limited"
    assert res.source_statuses["urlquery.search"]["status"] == "empty"


# ---- rule 5: errors are never absences -------------------------------------------------------------


def test_hidden_matches_are_not_not_found():
    http = FakeHttp()
    add(http, "GET", URLQUERY, fx("urlquery_search_hidden_documented.http.json"))
    res = run("domain:example.com", http, keys={"urlquery": KEYS["urlquery"]})
    assert res.status is Status.OK
    assert res.attributes["third_party_scan_summary"]["urlquery"]["hidden_matches"] == 42
    assert res.source_statuses["urlquery.search"]["status"] == "ok" and "not 'not found'" in res.source_statuses["urlquery.search"]["reason"]


def test_offline_and_deadline_keep_their_canonical_codes():
    from v3lum.core.http import DeadlineExceeded, OfflineError

    assert mod._fail_from_exception(OfflineError("offline"))[:2] == (Status.UNAVAILABLE, "offline")
    assert mod._fail_from_exception(DeadlineExceeded("deadline"))[:2] == (Status.ERROR, "timeout")
    res = mod.UrlScannersThirdParty().result(mod.Entity.make(mod.T.DOMAIN, "example.com"))
    out = mod._Outcome()
    out.fail(res, "urldna.search", Status.UNAVAILABLE, "offline", "offline")
    out.fail(res, "urlquery.search", Status.NEEDS_KEY, "needs_key", "no key")
    done = out.finish(res, False)
    assert done.status is Status.UNAVAILABLE and done.reason_code == "offline"


def test_both_empty_is_empty():
    http = FakeHttp()
    add(http, "POST", URLDNA_SEARCH, fx("urldna_search_empty_documented.http.json"))
    add(http, "GET", URLQUERY, fx("urlquery_search_empty_documented.http.json"))
    assert run("domain:example.com", http).status is Status.EMPTY


def test_server_errors_malformed_json_and_error_in_200_are_errors():
    http = FakeHttp()
    http.add("POST", URLDNA_SEARCH, status=500, json={"detail": "Internal Server Error"})
    http.add("GET", URLQUERY, status=200, json={"success": False, "error": {"error": "INTERNAL_ERROR"}})
    res = run("domain:example.com", http)
    assert res.status is Status.ERROR and res.reason_code == "error"
    assert res.source_statuses["urlquery.search"]["status"] == "error"
    http2 = FakeHttp()
    http2.add("POST", URLDNA_SEARCH, status=200, text='[{"id": "6745aa00c0ffee0000000001", "status": "DO')
    res2 = run("domain:example.com", http2, keys={"urldna": KEYS["urldna"]})
    assert res2.status is Status.ERROR and "could not verify" in res2.error


def test_challenge_page_is_blocked_never_empty():
    http = FakeHttp()
    http.add("POST", URLDNA_SEARCH, status=403, text=CHALLENGE)
    res = run("domain:example.com", http, keys={"urldna": KEYS["urldna"]})
    assert res.status in (Status.BLOCKED, Status.NEEDS_KEY)
    assert res.status is not Status.EMPTY


def test_a_missing_scan_detail_keeps_the_search():
    http = FakeHttp()
    add(http, "POST", URLDNA_SEARCH, fx("urldna_search_ok_documented.http.json"))
    http.add("GET", URLDNA_SCAN, status=404, json={"detail": "Scan not found"})
    res = run("domain:login.example.com", http, keys={"urldna": KEYS["urldna"]})
    assert res.status is Status.OK
    assert all("verdict" not in s for s in res.attributes["third_party_scans"])
    assert "third_party_scan_votes" in res.attributes and res.attributes["third_party_scan_votes"]["votes"] == []


# ---- c1/c2: no submission or scan request can be built --------------------------------------------

FORBIDDEN = [
    ("POST", "https://api.urldna.io/v1/scan"),
    ("POST", "https://api.urldna.io/v1/scan/"),
    ("POST", "https://api.urldna.io/v1/fast-check"),
    ("POST", "https://api.urldna.io/v1/query"),
    ("POST", "https://api.urlquery.net/public/v2/submissions"),
    ("POST", "https://api.urlquery.net/public/v1/submit/url"),
    ("DELETE", "https://api.urlquery.net/public/v2/reports/00000000-0000-4000-8000-000000000001"),
    ("POST", "https://api.urlquery.net/public/v2/detection/rulesets"),
    ("POST", "https://lookyloo.circl.lu/submit"),
    ("GET", "https://lookyloo.circl.lu/submit?url=https://example.com/"),
    ("GET", "https://lookyloo.circl.lu/capture"),
    ("POST", "https://lookyloo.circl.lu/json/upload"),
    ("GET", "https://lookyloo.circl.lu/json/9e173218-215c-4550-b302-29801096e268/trigger_modules"),
    ("GET", "https://sitecheck.sucuri.net/api/v3/?scan=example.com"),
    ("GET", "https://web-check.as93.net/api/ports?url=example.com"),
    ("POST", "https://developers.checkphish.ai/api/neo/scan"),
    ("GET", "http://api.urldna.io/v1/scan/6745aa00c0ffee0000000001"),
    ("GET", "https://api.urlquery.net/public/v1/search/reports/"),
]


@pytest.mark.parametrize(("method", "url"), FORBIDDEN)
def test_no_submission_or_dropped_request_can_be_built(method, url):
    with pytest.raises(PolicyError):
        mod.build_request(method, url)


@pytest.mark.parametrize(("method", "url"), [
    ("POST", "https://api.urldna.io/v1/search"),
    ("GET", "https://api.urldna.io/v1/scan/6745aa00c0ffee0000000001"),
    ("GET", "https://api.urlquery.net/public/v2/reports/search"),
    ("POST", "https://lookyloo.circl.lu/json/url_info"),
    ("POST", "https://lookyloo.circl.lu/json/hostname_info"),
    ("GET", "https://lookyloo.circl.lu/json/9e173218-215c-4550-b302-29801096e268/redirects"),
])
def test_only_lookup_endpoints_are_allowed(method, url):
    assert mod.build_request(method, url) == (method, url)


def test_the_dropped_providers_recorded_answers_are_never_requestable():
    for name in ("dropped_checkphish_nokey_error_in_200.http.json", "dropped_sucuri_sitecheck_ok.http.json"):
        req = fx(name)["_meta"]["request"]
        assert mod.allowed_request(req.get("method", "GET"), req["url"]) is not None


def test_no_scan_code_path_exists_in_the_module_source():
    source = Path(mod.__file__).read_text(encoding="utf-8")
    calls = re.findall(r"build_request\(\"(\w+)\",\s*([A-Z_]+)", source)
    assert calls and {name for _m, name in calls} <= {"URLDNA_SEARCH", "URLDNA_SCAN", "URLQUERY_SEARCH", "LOOKYLOO_REDIRECTS"}
    assert "ctx.http.post(" not in source and "ctx.http.get(" not in source  # every request goes through build_request


# ---- pure parsers ----------------------------------------------------------------------------------


def test_age_marker_and_votes():
    now = FakeClock().now()
    assert mod.age_marker("2026-10-01T00:00:00Z", now)["historical"] is True
    assert mod.age_marker("2026-11-25T00:00:00Z", now)["historical"] is False
    assert mod.age_marker("garbage", now) == {"scan_date": None, "age_days": None, "historical": False}
    votes = mod.consensus_votes([
        {"source": "urldna.search", "verdict": "safe", "scan_date": "2026-11-20T00:00:00Z", "historical": False},
        {"source": "urldna.search", "verdict": "malicious", "scan_date": "2026-11-25T00:00:00Z", "historical": False},
        {"source": "urlquery.search", "verdict_summary": "no_alerts", "scan_date": "2026-11-25T00:00:00Z", "historical": False},
        {"source": "urlquery.search", "verdict_summary": "malicious", "scan_date": "2026-01-01T00:00:00Z", "historical": True},
    ])
    assert votes == {"votes": [{"source": "urldna.search", "vote": "malicious", "scan_date": "2026-11-25T00:00:00Z"}], "ground_truth": False}


def test_parsers_survive_junk():
    now = FakeClock().now()
    assert mod.parse_urldna_search({"not": "a list"}, now)["reason"]
    assert mod.parse_urldna_search("<html>", now)["reason"] == "html"
    assert mod.parse_urldna_scan_result([1, 2], now)["reason"]
    assert mod.parse_urlquery_search({"success": True, "data": {"items": "x"}}, now)["reason"]
    assert mod.parse_urlquery_overview({"report_id": 5}, now) is None
    assert mod.urldna_search_body("url", "https://example.com/" + "a" * 300) is None
    assert mod.query_value(mod.Entity.make(mod.T.URL, "https://example.com/a\"b")) is None
