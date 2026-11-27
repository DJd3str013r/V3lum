"""unshorten_me (P070, third-party API, opt-in): the unshorten.me JSON lookup, offline.

Fixtures in tests/fixtures/unshorten_me/ (batch p9-G03-1 prep): the recorded keyless v1 answer
(research C0175, 2026-11-25; the short code and landing URL scrubbed to example values), the documented
v2 example, and synthetic not-resolved, not-a-short-link, quota-in-200 and Cloudflare-challenge answers.
The service fetches the short link itself (provider flag fetches_target) and stores submitted URLs
(reuses_queries): token URLs are never sent.
"""

from __future__ import annotations

import json

from tests.fakes import FIXTURES, FakeHttp, module_fixture, run_module
from v3lum.core.models import Status
from v3lum.core.providers import registry
from v3lum.modules.url_web import unshorten as U
from v3lum.modules.url_web.unshorten import UnshortenMe

FX = FIXTURES / "unshorten_me"
API = "https://unshorten.me/json/bit.ly/3Example"


def run(http: FakeHttp, url: str = "https://bit.ly/3Example", **kw):
    return run_module(UnshortenMe, f"url:{url}", http, **kw)


def test_resolved_short_link_becomes_a_url_pivot():
    http = FakeHttp().add("GET", API, json=module_fixture("unshorten_me", "ok_v1_recorded.json"))
    res = run(http)
    assert res.status is Status.OK, res.error
    http.assert_hosts_within(UnshortenMe)
    assert [c["url"] for c in http.calls] == [API]
    (pivot,) = res.pivots
    assert pivot.relation == "redirects_to" and pivot.entity.value == "https://www.example.com/landing" and pivot.expand is True
    lookup = res.attributes["unshorten_lookup"]
    assert lookup["resolved"] == "https://www.example.com/landing" and lookup["remaining_calls"] == 9


def test_destination_with_a_recipient_token_is_pivoted_as_its_domain_only():
    body = {"requested_url": "bit.ly/3Example", "success": True, "resolved_url": "https://login.example.net/x?u=alice%40example.com",
            "usage_count": 1, "remaining_calls": 8}
    res = run(FakeHttp().add("GET", API, json=body))
    assert [p.entity.value for p in res.pivots] == ["login.example.net"]
    assert "alice" not in repr(res.attributes) and "alice" not in repr(res.raw)


def test_not_resolved_is_could_not_verify_and_not_short_is_empty():
    res = run(FakeHttp().add("GET", API, json=module_fixture("unshorten_me", "not_resolved_synthetic.json")))
    # the service's fetch failed: a dead link and a service failure look alike, so never EMPTY (rule 5)
    assert res.status is Status.ERROR and "could not verify" in res.error and res.pivots == []
    body = module_fixture("unshorten_me", "not_short_synthetic.json")
    assert U.parse_unshorten_me(200, json.dumps(body))["status"] == "empty"
    res = run(FakeHttp().add("GET", API, json=body))
    assert res.status is Status.EMPTY and res.pivots == []


def test_quota_inside_http_200_is_quota_not_empty():
    res = run(FakeHttp().add("GET", API, json=module_fixture("unshorten_me", "quota_synthetic.json")))
    assert res.status is Status.QUOTA


def test_challenge_and_errors_are_could_not_verify():
    html = (FX / "html_instead_of_json_synthetic.html").read_text()
    res = run(FakeHttp().add("GET", API, status=403, text=html))
    assert res.status is Status.BLOCKED
    res = run(FakeHttp().add("GET", API, status=200, text=html))
    assert res.status in (Status.BLOCKED, Status.ERROR) and res.status is not Status.EMPTY
    assert run(FakeHttp().add("GET", API, status=429, text="Too Many Requests")).status is Status.RATE_LIMITED
    assert run(FakeHttp().add("GET", API, status=500, text="oops")).status is Status.ERROR
    assert run(FakeHttp().add("GET", API, status=200, text="<html><body>maintenance</body></html>")).status is Status.ERROR


def test_token_short_link_is_never_sent():
    http = FakeHttp()
    res = run(http, "https://bit.ly/3Example?u=alice%40example.com")
    assert res.status is Status.SKIPPED and res.reason_code == "policy"
    assert http.calls == []


def test_ip_loggers_and_non_shorteners_do_not_apply():
    http = FakeHttp()
    assert run(http, "https://grabify.link/ABC123").status is Status.SKIPPED
    assert run(http, "https://www.example.com/landing").status is Status.SKIPPED
    assert http.calls == []


def test_parser_reads_v1_and_v2_shapes():
    v1 = U.parse_unshorten_me(200, (FX / "ok_v1_recorded.json").read_text())
    assert v1["status"] == "ok" and v1["resolved_url"] == "https://www.example.com/landing" and v1["remaining_calls"] == 9
    v2 = U.parse_unshorten_me(200, (FX / "ok_v2_docs_example.json").read_text())
    assert v2["status"] == "ok" and v2["resolved_url"] == "https://www.youtube.com/"
    assert U.parse_unshorten_me(200, '{"success": true, "resolved_url": "javascript:alert(1)"}')["status"] == "error"
    assert U.unshorten_me_url("https://bit.ly/3Example") == API


def test_contract_metadata_and_provider():
    assert UnshortenMe.default_enabled is False and UnshortenMe.disclosure == "third_party"
    assert UnshortenMe.hosts == ("unshorten.me",) and UnshortenMe.max_requests == 1 and UnshortenMe.terms == "open"
    prov = registry().get("unshorten_me")
    assert prov.tier == "unknown" and prov.flags.fetches_target is True and prov.flags.reuses_queries is True
    assert prov.quota.hour == 10
    terms = prov.sources["json_api"].terms
    assert terms.class_ == "open" and terms.evidence_url == "https://unshorten.me/terms-of-service"
