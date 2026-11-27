"""ssllabs_assess (P076 cond 3, ACTIVE): offline tests.

Fixtures in tests/fixtures/ssllabs_assess/: ``ssllabs_analyze_cached_ready.json`` (a real READY analyze answer
recorded 2026-11-25, github.com), ``ssllabs_analyze_blacklisted_error.json`` (the real 'Hostname blacklisted'
answer) and ``ssllabs_analyze_in_progress_synthetic.json`` (the documented IN_PROGRESS shape, documentation IP).
The scope binds every ACTIVE request: the engagement scope lists the target and the SSL Labs API host.
"""

from __future__ import annotations

from urllib.parse import parse_qs, urlsplit

from tests.fakes import FakeClock, FakeHttp, add_dns, make_ctx, make_runtime, module_fixture, run_module
from v3lum.core.context import ScanOptions
from v3lum.core.entities import Entity
from v3lum.core.entities import EntityType as T
from v3lum.core.models import Opsec, Status
from v3lum.core.scope import Scope
from v3lum.modules.url_web import posture_third_party as pt
from v3lum.modules.url_web.posture_third_party import SslLabsAssess

REF = "PENTEST-2026-042"
TARGET = "www.acme.example"
URLS = pt.ssllabs_assess_requests(TARGET)
API_IP = "64.41.200.100"


def scope(*domains: str) -> Scope:
    return Scope.from_dict({
        "authorization_ref": REF, "owner": "Engagement owner (tests)", "contacts": ["soc@acme.example"], "ticket": "T-1",
        "window_start": "2026-11-26T00:00:00Z", "window_end": "2026-11-27T00:00:00Z",
        "targets": {"domains": list(domains or ("acme.example", "*.acme.example", "api.ssllabs.com"))},
    })


def active(sc: Scope | None = None) -> ScanOptions:
    sc = sc or scope()
    return ScanOptions(mode=Opsec.ACTIVE, authorized=True, authorization_ref=REF, scope=sc)


def api_dns(http: FakeHttp) -> None:
    add_dns(http, "api.ssllabs.com", "A", [API_IP])
    add_dns(http, "api.ssllabs.com", "AAAA", [])


def run(http: FakeHttp, value: str = f"domain:{TARGET}", **kw):
    kw.setdefault("options", active())
    kw.setdefault("clock", FakeClock())
    return run_module(SslLabsAssess, value, http, **kw)


def api_calls(http: FakeHttp) -> list[dict]:
    return [c for c in http.calls if c["url"].startswith("https://api.ssllabs.com/")]


def test_metadata_active_fresh_assessment_opt_in():
    cls = SslLabsAssess
    assert cls.opsec is Opsec.ACTIVE and cls.disclosure == "target" and cls.default_enabled is False
    assert "fresh_assessment" in cls.tags and cls.terms == "noncommercial" and cls.sources == (pt.SRC_ASSESS,)
    assert cls.health_check().offline is True
    ctx = make_ctx(SslLabsAssess, FakeHttp(), entity=Entity.make(T.DOMAIN, TARGET))
    assert cls.health_check().selftest(ctx).status == "ok"


def test_one_start_then_polls_until_ready():
    http = FakeHttp()
    api_dns(http)
    http.add("GET", URLS["start"], json=module_fixture(SslLabsAssess, "ssllabs_analyze_in_progress_synthetic.json"))
    http.add("GET", URLS["poll"], json=module_fixture(SslLabsAssess, "ssllabs_analyze_in_progress_synthetic.json"), times=1)
    http.add("GET", URLS["poll"], json=module_fixture(SslLabsAssess, "ssllabs_analyze_cached_ready.json"), times=1)
    res = run(http)
    assert res.status is Status.OK, res.error
    calls = api_calls(http)
    assert len(calls) == 3
    queries = [parse_qs(urlsplit(c["url"]).query) for c in calls]
    assert [("startNew" in q) for q in queries] == [True, False, False]  # startNew once, never repeated
    assert all(q["publish"] == ["off"] and "fromCache" not in q and "maxAge" not in q for q in queries)
    assessment = res.attributes["ssllabs_assessment"]
    assert assessment["status"] == "READY" and assessment["polls"] == 2 and assessment["publish"] == "off"
    eps = res.attributes["ssllabs_endpoints"]
    assert eps[0]["ip"] == "140.82.114.4" and eps[0]["grade"] == "A+"
    assert [(p.entity.value, p.expand) for p in res.pivots] == [("140.82.114.4", False)]
    assert {c["method"] for c in calls} == {"GET"}
    assert all(c.get("pin_ip") == API_IP for c in calls)


def test_requires_authorization_and_scope():
    http = FakeHttp()
    res = run(http, options=ScanOptions(mode=Opsec.ACTIVE))
    assert res.status is Status.SKIPPED and res.reason_code == "authorization"
    assert http.calls == []


def test_scope_must_list_the_api_host():
    http = FakeHttp()
    res = run(http, options=active(scope("acme.example", "*.acme.example")))
    assert res.status is Status.SKIPPED and res.reason_code == "scope" and "api.ssllabs.com" in res.error
    assert http.calls == []


def test_target_outside_scope_and_not_own_is_refused():
    http = FakeHttp()
    res = run(http, "domain:www.example.org")
    assert res.status is Status.SKIPPED and res.reason_code == "scope"
    assert http.calls == []


def test_blacklisted_host_is_an_error():
    http = FakeHttp()
    api_dns(http)
    http.add("GET", URLS["start"], json=module_fixture(SslLabsAssess, "ssllabs_analyze_blacklisted_error.json"))
    res = run(http)
    assert res.status is Status.ERROR and "Hostname blacklisted" in res.error
    assert len(api_calls(http)) == 1


def test_poll_cap_is_could_not_verify():
    http = FakeHttp()
    api_dns(http)
    progress = module_fixture(SslLabsAssess, "ssllabs_analyze_in_progress_synthetic.json")
    http.add("GET", URLS["start"], json=progress)
    http.add("GET", URLS["poll"], json=progress)
    res = run(http, settings={"ssllabs_assess_max_polls": 2})
    assert res.status is Status.ERROR and res.reason_code == "timeout"
    assert len(api_calls(http)) == 3


def test_429_on_start_is_rate_limited():
    http = FakeHttp()
    api_dns(http)
    http.add("GET", URLS["start"], status=429, text="Too many new assessments")
    res = run(http)
    assert res.status is Status.RATE_LIMITED
    assert len(api_calls(http)) == 1


def test_kill_switch_stops_before_any_request():
    http = FakeHttp()
    api_dns(http)
    http.add("GET", URLS["start"], json=module_fixture(SslLabsAssess, "ssllabs_analyze_in_progress_synthetic.json"))
    rt = make_runtime(http, clock=FakeClock())
    rt.cancel("test kill switch")
    res = run_module(SslLabsAssess, f"domain:{TARGET}", http, options=active(), runtime=rt)
    assert api_calls(http) == []
    assert res.status is not Status.OK or res.partial


def test_assess_guard():
    assert pt.check_assess_request(URLS["start"], first_call=True) is None
    assert pt.check_assess_request(URLS["start"], first_call=False) == "startNew repeated (would loop assessments)"
    assert pt.check_assess_request(URLS["poll"].replace("publish=off", "publish=on"), first_call=False) == "publish must be off"
    assert pt.check_assess_request(URLS["poll"] + "&fromCache=on", first_call=False)
    assert pt.check_assess_request("https://api.ssllabs.com/api/v3/getEndpointData?host=x&s=1.2.3.4", first_call=True)


def test_start_new_is_never_resent_by_a_core_retry():
    """A 5xx (or a short 429) on the startNew call is not retried by the core: a gateway error can hide an
    assessment that did start, and a second startNew=on would restart it (P076 cond 3)."""
    for status in (502, 503):
        http = FakeHttp()
        api_dns(http)
        http.add("GET", URLS["start"], status=status, text="<html>bad gateway</html>", times=1)
        http.add("GET", URLS["start"], json=module_fixture(SslLabsAssess, "ssllabs_analyze_in_progress_synthetic.json"))
        res = run(http)
        starts = [c for c in api_calls(http) if "startNew=on" in c["url"]]
        assert len(starts) == 1, (status, len(starts))
        assert res.status is not Status.OK
