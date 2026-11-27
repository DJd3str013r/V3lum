"""phishtank_checkurl (P075, batch p3-G03-1): PhishTank checkurl single-URL verdict.

Fixtures in tests/fixtures/phishtank_checkurl/ (prep 2026-11-26; request ids replaced by REDACTED):
in_database_unverified.json (the research record's recorded example.com answer: in_database=true,
verified=false - the quirk of P075 cond 4), in_database_unverified_live.http.json (the same quirk
re-observed live with the X-Request-Limit headers), not_in_database.json and error_in_200.json (real
answers), challenge_403.html (the recorded Cloudflare managed challenge of another sweep) and
challenge_403.http.json (its standard header set); verified_valid_documented.json (PhishTank's own
api_info.php sample, 'y' strings), xml_default_documented.xml (format omitted) and the synthetic
verified_valid_recent.json, verified_not_valid.json and rate_limited_509.http.json (documented 509).
"""

from __future__ import annotations

import base64
import json
from pathlib import Path
from urllib.parse import parse_qs

import pytest

from tests.fakes import FakeClock, FakeHttp, make_runtime, module_fixture, run_module
from v3lum.core import providers
from v3lum.core.entities import Entity
from v3lum.core.entities import EntityType as T
from v3lum.core.models import Severity, Status
from v3lum.core.orgprofile import OrgProfile
from v3lum.modules.url_web import phishtank_checkurl as P
from v3lum.modules.url_web.phishtank_checkurl import PhishtankCheckurl

URL = P.CHECKURL_URL
FX = Path(__file__).resolve().parent.parent / "fixtures" / "phishtank_checkurl"
PHISH = "url:http://login-example.test/secure/"


def fx(name: str):
    return module_fixture(PhishtankCheckurl, name)


def raw(name: str) -> bytes:
    return (FX / name).read_bytes()


def capture(name: str) -> dict:
    return json.loads(raw(name))["response"]


def form(http: FakeHttp) -> dict[str, list[str]]:
    call = next(c for c in http.calls if c["method"] == "POST")
    return parse_qs(call["body"].decode())


# ------------------------------------------------------------------------------------------ metadata
def test_metadata_and_provider_profile():
    cls = PhishtankCheckurl
    assert cls.default_enabled is False and cls.terms == "open" and "reputation" in cls.tags  # c2
    assert cls.hosts == ("checkurl.phishtank.com",) and cls.sources == ("phishtank.phishtank_checkurl",)
    assert cls.optional_keys == ("phishtank",) and cls.upstream_families == frozenset({"phishtank"})  # one vote in consensus
    prov = providers.registry().provider_for_host("checkurl.phishtank.com")
    assert prov.id == "phishtank" and prov.http_profile.user_agent == "phishtank/{app}"  # c1: documented UA format
    assert {m.id for m in prov.error_markers} >= {"phishtank_checkurl_error_in_200", "phishtank_checkurl_over_limit"}


def test_form_is_base64_full_url_and_json_format_cond1():
    f = P.checkurl_form("http://login-example.test/secure/?a=1&b=2")
    assert f["format"] == "json" and base64.b64decode(f["url"]).decode() == "http://login-example.test/secure/?a=1&b=2"
    assert "app_key" not in f and P.checkurl_form("http://x.test/", "k123")["app_key"] == "k123"


# ---------------------------------------------------------------------------------------- verdicts
def test_in_database_alone_is_not_a_verdict_cond4_cond6():
    cap = capture("in_database_unverified_live.http.json")
    http = FakeHttp().add("POST", URL, text=cap["body"], headers=cap["headers"])
    res = run_module(PhishtankCheckurl, "url:http://example.com/", http)
    assert res.status is Status.OK and res.findings == []
    verdict = res.attributes["phishtank_verdict"]
    assert verdict["verdict"] == "unverified" and verdict["in_database"] is True and verdict["phish_id"] == 4866807
    assert res.attributes["phishtank_limits"] == {"limit": 250, "interval_s": 300, "count": 1, "remaining": 249}
    sent = form(http)
    assert sent["format"] == ["json"] and base64.b64decode(sent["url"][0]).decode() == "http://example.com/"
    call = http.calls[0]
    assert call["headers"].get("User-Agent") == "phishtank/v3lum"  # the provider profile's documented format, never set by the module
    assert any(link[1].startswith("https://www.phishtank.com/phish_detail.php?phish_id=4866807") for link in res.links)
    http.assert_hosts_within(PhishtankCheckurl)


def test_recorded_research_answer_parses_the_same_quirk():
    parsed = P.parse_checkurl(raw("in_database_unverified.json"), P.parse_iso("2026-11-26T12:00:00Z"))
    assert parsed["status"] is Status.OK and parsed["verdict"] == "unverified" and parsed["verified"] is False


def test_verified_and_valid_recent_is_a_high_finding():
    http = FakeHttp().add("POST", URL, json=fx("verified_valid_recent.json"))
    res = run_module(PhishtankCheckurl, PHISH, http, clock=FakeClock())
    assert res.status is Status.OK and len(res.findings) == 1
    f = res.findings[0]
    assert f.severity is Severity.HIGH and set(f.tags) == {"phishing", "malicious"} and f.criterion
    assert f.source == P.SOURCE and f.data["phish_id"] == 9000001 and f.data["consensus_votes"] == 1
    assert res.attributes["phishtank_verdict"]["historical"] is False


def test_old_verification_is_historical_cond4():
    http = FakeHttp().add("POST", URL, json=fx("verified_valid_documented.json"))  # 'y' strings, verified in 2006
    res = run_module(PhishtankCheckurl, "url:https://www.example.org/", http)
    f = res.findings[0]
    assert f.severity is Severity.LOW and "historical" in f.tags and "malicious" not in f.tags
    assert res.attributes["phishtank_verdict"]["historical"] is True


def test_verified_but_not_valid_is_no_finding():
    http = FakeHttp().add("POST", URL, json=fx("verified_not_valid.json"))
    res = run_module(PhishtankCheckurl, "url:https://www.example.net/", http)
    assert res.status is Status.OK and res.findings == [] and res.attributes["phishtank_verdict"]["verdict"] == "not_phish"


def test_not_in_database_is_empty_and_never_called_safe():
    http = FakeHttp().add("POST", URL, json=fx("not_in_database.json"))
    res = run_module(PhishtankCheckurl, "url:https://registro.br/", http)
    assert res.status is Status.EMPTY and "not proof" in res.error and "safe" in res.error and res.findings == []


# ------------------------------------------------------------------------------- could not verify
def test_recorded_403_challenge_is_blocked_never_bypassed_cond3_cond6():
    cap = capture("challenge_403.http.json")
    http = FakeHttp().add("POST", URL, status=403, text=raw("challenge_403.html").decode(), headers=cap["headers"])
    res = run_module(PhishtankCheckurl, PHISH, http)
    assert res.status is Status.BLOCKED and res.reason_code == "challenge"
    assert len(http.calls) == 1  # never retried with other headers
    assert any(link[1] == P.MANUAL_LINK for link in res.links)


def test_bare_403_with_an_app_key_is_still_blocked_cond3():
    http = FakeHttp().add("POST", URL, status=403, json={"message": "Forbidden"})
    res = run_module(PhishtankCheckurl, PHISH, http, keys={"phishtank": "apptest-key-0001"})
    assert res.status is Status.BLOCKED and res.reason_code == "challenge"
    assert form(http)["app_key"] == ["apptest-key-0001"]


@pytest.mark.parametrize("route, status, code", [
    ({"status": 200, "json": None, "name": "error_in_200.json"}, Status.ERROR, "error"),  # provider marker meta.status error
    ({"status": 200, "text": None, "name": "xml_default_documented.xml"}, Status.ERROR, "error"),
    ({"status": 200, "text": "<html><body>maintenance</body></html>"}, Status.ERROR, "error"),
    ({"status": 200, "text": "{not json"}, Status.ERROR, "error"),
    ({"status": 200, "json": {"meta": {"status": "success"}, "results": {"url": "x"}}}, Status.ERROR, "error"),
    ({"status": 503, "text": "unavailable"}, Status.ERROR, "error"),
    ({"status": 429, "text": "slow down"}, Status.RATE_LIMITED, "rate_limited"),
])
def test_errors_are_could_not_verify_never_empty(route, status, code):
    route = dict(route)
    name = route.pop("name", None)
    if name and route.get("json", 0) is None:
        route["json"] = fx(name)
    elif name:
        route["text"] = raw(name).decode()
    http = FakeHttp().add("POST", URL, **route)
    res = run_module(PhishtankCheckurl, PHISH, http)
    assert res.status is status and res.reason_code == code


def test_509_over_limit_is_rate_limited_and_closes_the_window_cond5():
    cap = capture("rate_limited_509.http.json")
    http = FakeHttp().add("POST", URL, status=509, text=cap["body"] or "over limit", headers=cap["headers"])
    rt = make_runtime(http, clock=FakeClock())
    res = run_module(PhishtankCheckurl, PHISH, runtime=rt)
    assert res.status is Status.RATE_LIMITED and res.reason_code == "rate_limited"
    again = run_module(PhishtankCheckurl, "url:http://other-example.test/login", runtime=rt)
    assert again.status is Status.RATE_LIMITED and len(http.calls) == 1  # no request while the window is used up


def test_used_up_window_from_headers_skips_the_request_cond5():
    headers = {"content-type": "application/json", "x-request-limit": "250", "x-request-limit-interval": "300 Seconds", "x-request-count": "250"}
    http = FakeHttp().add("POST", URL, json=fx("not_in_database.json"), headers=headers)
    rt = make_runtime(http, clock=FakeClock())
    assert run_module(PhishtankCheckurl, "url:https://registro.br/", runtime=rt).status is Status.EMPTY
    blocked = run_module(PhishtankCheckurl, PHISH, runtime=rt)
    assert blocked.status is Status.RATE_LIMITED and len(http.calls) == 1
    rt.clock.advance(301)
    http.add("POST", URL, json=fx("not_in_database.json"))
    assert run_module(PhishtankCheckurl, "url:https://registro.br/", runtime=rt).status is Status.EMPTY  # the window reset


def test_five_blocked_runs_demote_to_link_only_cond3():
    challenge = raw("challenge_403.html").decode()
    http = FakeHttp().add("POST", URL, status=403, text=challenge)
    rt = make_runtime(http, clock=FakeClock())
    for _ in range(P.DEMOTE_AFTER):  # one run per scan: each scan starts with a fresh host circuit
        rt.http.reset_circuit()
        assert run_module(PhishtankCheckurl, PHISH, runtime=rt).status is Status.BLOCKED
    rt.http.reset_circuit()
    listed = (("domain:login-example.test", "listed_phishing_url", "phishstats"),)
    demoted = run_module(PhishtankCheckurl, PHISH, runtime=rt, is_seed=False, provenance=listed)
    assert demoted.status is Status.SKIPPED and demoted.reason_code == "demoted"
    assert len(http.calls) == P.DEMOTE_AFTER and any(link[1] == P.MANUAL_LINK for link in demoted.links)
    # an analyst-typed seed still gets one attempt; a verdict resets the streak
    http.routes[0].remaining = 0  # PhishTank answers again
    http.add("POST", URL, json=fx("verified_valid_recent.json"))
    assert run_module(PhishtankCheckurl, PHISH, runtime=rt).status is Status.OK
    assert run_module(PhishtankCheckurl, PHISH, runtime=rt, is_seed=False, provenance=listed).status is Status.OK


# ------------------------------------------------------------------------------------------- scope
def test_only_urls_under_triage_are_sent_cond5():
    http = FakeHttp()
    pivot = run_module(PhishtankCheckurl, PHISH, http, is_seed=False, provenance=(("domain:example.net", "links_to", "web"),))
    assert pivot.status is Status.SKIPPED and pivot.reason_code == "not_applicable" and http.calls == []
    http.add("POST", URL, json=fx("not_in_database.json"))
    listed = run_module(PhishtankCheckurl, PHISH, http, is_seed=False, provenance=(("domain:login-example.test", "listed_phishing_url", "phishstats"),))
    assert listed.status is Status.EMPTY and len(http.calls) == 1


def test_org_profile_urls_are_never_sent_cond5():
    profile = OrgProfile.from_dict({"domains": [{"name": "example.com", "verification": "confirmed"}],
                                    "suppliers": [{"name": "Supplier", "domains": ["supplier-example.net"]}]})
    http = FakeHttp()
    own = run_module(PhishtankCheckurl, "url:https://login.example.com/reset", http, org_profile=profile)
    assert own.status is Status.SKIPPED and own.reason_code == "own_asset"
    supplier = run_module(PhishtankCheckurl, "url:https://portal.supplier-example.net/", http, org_profile=profile)
    assert supplier.status is Status.SKIPPED and supplier.reason_code == "policy"
    assert http.calls == []


def test_health_check_uses_the_benign_quirk():
    hc = PhishtankCheckurl.health_check()
    assert (hc.etype, hc.value, hc.expect) == (T.URL, "https://example.com/", "ok")
    assert Entity.make(T.URL, hc.value).value == "https://example.com/"
