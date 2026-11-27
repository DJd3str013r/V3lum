"""security_headers (P063, offline, disclosure 'none'): audit of the cached homepage response.

Fixtures in tests/fixtures/security_headers/ (batch p9-G03-1 prep, 2026-11-26):

* ``third_party_google_recorded.json`` - www.google.com's homepage headers recorded by the research
  (2026-11-25): names and flags as recorded, the CSP nonce and the cookie values/dates replaced; it lacks
  exactly six graded headers;
* ``ok_github_raw_headers.json`` - real response headers of raw.githubusercontent.com (volatile ids dropped);
* ``error_status_400_recorded.json`` - github.com answered 400 to a non-browser client (research);
* ``multi_set_cookie_synthetic.json`` - five Set-Cookie headers (session, remember, __Host- prefix, SameSite=None);
* ``joined_set_cookie_synthetic.txt`` - the same cookies comma-joined the way requests merges them;
* ``blocked_challenge_synthetic.json``, ``homepage_with_recaptcha_synthetic.json``, ``http_only_synthetic.json``.

The module never makes a request: the frozen core gives offline modules no cache-only read yet, so the
cached response is offered here through the documented hook (``Context.cached_response``, the
requested core addition) with pytest's monkeypatch.
"""

from __future__ import annotations

from dataclasses import dataclass, field

import pytest

from tests.fakes import FIXTURES, FakeHttp, module_fixture, run_module
from v3lum.core.context import Context
from v3lum.core.models import Severity, Status
from v3lum.modules.url_web import security_headers as S
from v3lum.modules.url_web.light_fetch import headers_multi
from v3lum.modules.url_web.security_headers import SecurityHeaders

FX = FIXTURES / "security_headers"


@dataclass
class Cached:
    url: str
    status: int
    header_list: list = field(default_factory=list)
    content: bytes = b""


def offer(monkeypatch, fixture: str) -> dict:
    data = module_fixture("security_headers", fixture)
    cached = Cached(data["url"], data["status"], [tuple(p) for p in data["headers"]], str(data.get("body") or "").encode())

    def cached_response(self, url):  # the requested core hook: cache-only, never a request
        return cached

    monkeypatch.setattr(Context, "cached_response", cached_response, raising=False)
    return data


def test_no_cached_response_is_skipped_with_zero_requests():
    http = FakeHttp()
    res = run_module(SecurityHeaders, "domain:www.example.com", http)
    assert res.status is Status.SKIPPED and res.reason_code == "not_applicable"
    assert http.calls == []  # P063 c1: no request of its own


def test_third_party_site_missing_six_headers_gives_exactly_one_info_finding(monkeypatch):
    data = offer(monkeypatch, "third_party_google_recorded.json")
    http = FakeHttp()
    res = run_module(SecurityHeaders, "url:https://www.google.com/", http)
    assert http.calls == []
    assert res.status is Status.OK
    assert sorted(res.attributes["security_headers_missing"]) == sorted(data["expected_missing"])
    assert len(res.findings) == 1  # one aggregated finding, never one per header (c6)
    finding = res.findings[0]
    assert finding.severity is Severity.INFO and finding.criterion
    assert res.attributes["security_headers"]["monitoring_only"] == ["content-security-policy-report-only"]
    flags = {c["name"]: c for c in res.attributes["cookie_flags"]}
    assert flags["NID"]["secure"] is False and flags["AEC"]["httponly"] is True
    assert "EXAMPLEVALUE" not in str(res.attributes)  # cookie values are never kept


def test_own_asset_is_low_never_more(monkeypatch):
    offer(monkeypatch, "multi_set_cookie_synthetic.json")
    org = {"domains": [{"name": "example.com", "verification": "txt_verified"}]}
    res = run_module(SecurityHeaders, "url:https://portal.example.com/login", FakeHttp(), org_profile=org)
    (finding,) = res.findings
    assert finding.severity is Severity.LOW


def test_multiple_set_cookie_headers_are_all_audited():
    data = module_fixture("security_headers", "multi_set_cookie_synthetic.json")
    audit = S.audit_response({"url": data["url"], "status": data["status"], "headers": data["headers"]})
    names = [c["name"] for c in audit["cookies"]]
    assert names == ["PHPSESSID", "remember_token", "__Host-csrf", "lang", "tracking"]
    issues = {(i["name"], i["issue"]) for i in audit["cookie_issues"]}
    assert ("PHPSESSID", "session cookie without Secure") in issues
    assert ("PHPSESSID", "session cookie without HttpOnly") in issues
    assert ("remember_token", "session cookie without HttpOnly") in issues
    assert ("__Host-csrf", "__Host- prefix rules broken") in issues  # Domain= is forbidden with __Host-
    assert ("tracking", "invalid SameSite (None without Secure)") in issues
    assert {"header": "content-security-policy", "issue": "script-src allows 'unsafe-inline'"} in audit["weak"]
    assert any(w["header"] == "strict-transport-security" and "6 months" in w["issue"] for w in audit["weak"])
    assert {"header": "referrer-policy", "issue": "unsafe value no-referrer-when-downgrade"} in audit["weak"]
    assert {t["product"] for t in audit["tech"]} >= {"PHP", "Apache"}
    assert audit["info_leak"]["x-powered-by"] == "PHP/7.4.3"


def test_comma_joined_set_cookie_is_split_without_breaking_expires():
    joined = (FX / "joined_set_cookie_synthetic.txt").read_text().strip()
    audit = S.audit_response({"url": "https://portal.example.com/", "status": 200, "headers": [("Set-Cookie", joined)]})
    assert [c["name"] for c in audit["cookies"]] == ["PHPSESSID", "remember_token", "lang"]


def test_hsts_is_only_checked_over_https():
    data = module_fixture("security_headers", "http_only_synthetic.json")
    audit = S.audit_response({"url": data["url"], "status": data["status"], "headers": data["headers"]})
    assert "strict-transport-security" not in audit["missing"] and audit["hsts"] is None
    assert {"id": "hsts-not-applicable-http", "modifier": 0} in audit["tests"]
    assert ("sessionid", "session cookie without Secure") in {(i["name"], i["issue"]) for i in audit["cookie_issues"]}


def test_well_configured_response_grades_high():
    data = module_fixture("security_headers", "ok_github_raw_headers.json")
    audit = S.audit_response({"url": data["url"], "status": data["status"], "headers": data["headers"]})
    assert audit["grade"] in ("A+", "A", "A-", "B+")
    assert "content-security-policy" not in audit["missing"] and "x-frame-options" not in audit["missing"]


def test_recaptcha_contact_form_is_not_a_challenge():
    data = module_fixture("security_headers", "homepage_with_recaptcha_synthetic.json")
    audit = S.audit_response({"url": data["url"], "status": data["status"], "headers": data["headers"], "body": data["body"]})
    assert audit["inconclusive"] is None and audit["grade"] in ("A+", "A")


@pytest.mark.parametrize(("fixture", "status"), [("blocked_challenge_synthetic.json", Status.BLOCKED),
                                                 ("error_status_400_recorded.json", Status.ERROR)])
def test_block_pages_and_errors_are_inconclusive(monkeypatch, fixture, status):
    offer(monkeypatch, fixture)
    res = run_module(SecurityHeaders, "url:https://www.example.com/", FakeHttp())
    assert res.status is status
    assert res.findings == [] and "security_headers_missing" not in res.attributes
    assert res.attributes["security_headers"]["inconclusive"]


def test_hostile_sites_get_attributes_only():
    assert S.security_headers_severity(tags=["phishing"]) is None
    assert S.security_headers_severity(own_asset=True) == "low"
    assert S.security_headers_severity(authorized_in_scope=True) == "low"
    assert S.security_headers_severity() == "info"


def test_owasp_reference_is_bundled():
    ref = S.load_owasp_reference()
    assert len(ref["recommended"]) == 13 and len(ref["leaky"]) == 88
    assert "x-powered-by" in ref["leaky"] and "content-security-policy" in ref["recommended"]


def test_headers_multi_keeps_duplicates():
    pairs = headers_multi("HTTP/1.1 200 OK\r\nSet-Cookie: a=1\r\nSet-Cookie: b=2\r\nX-Long: one\r\n two\r\n")
    assert pairs == [("set-cookie", "a=1"), ("set-cookie", "b=2"), ("x-long", "one two")]


def test_contract_metadata():
    assert SecurityHeaders.disclosure == "none" and SecurityHeaders.hosts == ()
    assert SecurityHeaders.default_enabled is True and SecurityHeaders.terms == "open"


@pytest.mark.parametrize(("etype", "value"), [("domain", "example.com"), ("url", "https://example.com/")])
def test_acceptance_golden_inputs_need_no_route(etype, value):
    """AR21 golden path: security_headers is offline (disclosure 'none'): empty route files, nothing sent."""
    from tests.fakes import fixture

    assert fixture(f"acceptance/{etype}/security_headers.json") == {"schema": "v3lum.acceptance_routes/1", "module": "security_headers",
                                                                     "routes": []}
    http = FakeHttp()
    res = run_module(SecurityHeaders, f"{etype}:{value}", http)
    assert http.calls == [] and not res.findings
