"""retirejs_osv (P344 cond 3, batch p2-G03-1): OSV npm confirmation of RetireJS detections.

Fixtures in tests/fixtures/retirejs_osv/ (prep p2-G03-1, live api.osv.dev answers of 2026-11-26):
``osv_jquery_1.12.4.json`` (4 npm advisories, ranges trimmed to npm), ``osv_empty.json`` (``{}`` for
jquery 3.7.1) and ``osv_error_400.json`` (bad ecosystem: 400 ``{"code": 3, "message": "invalid ecosystem"}``).
"""

from __future__ import annotations

import pytest

from tests.fakes import FIXTURES, FakeHttp, module_fixture, run_module
from v3lum.core.entities import Entity
from v3lum.core.entities import EntityType as T
from v3lum.core.models import Status
from v3lum.modules.url_web import retirejs_check as mod
from v3lum.modules.url_web.retirejs_check import RetireJsOsv

OSV = "https://api.osv.dev/v1/query"
JQUERY = (FIXTURES / "retirejs_check" / "jquery_1.12.4_min_banner.js").read_text(encoding="utf-8")


@pytest.fixture(autouse=True)
def fresh_budget():
    mod.OSV_BUDGET.reset()
    yield
    mod.OSV_BUDGET.reset()


def test_metadata():
    cls = RetireJsOsv
    assert (cls.provider, cls.hosts, cls.disclosure, cls.terms) == ("osv", ("api.osv.dev",), "third_party", "open")
    assert cls.max_requests == 10 and cls.trust_tier == "trusted" and cls.default_enabled is True


def test_jquery_1124_confirmed_by_osv_name_and_version_only():
    http = FakeHttp().add("POST", OSV, json=module_fixture("retirejs_osv", "osv_jquery_1.12.4.json"))
    res = run_module(RetireJsOsv, Entity.make(T.TEXT, JQUERY), http)
    assert res.status is Status.OK
    row = res.attributes["js_libraries"][0]
    assert row["npm"] == "jquery" and row["version"] == "1.12.4"
    assert {"CVE-2019-11358", "CVE-2020-11022", "CVE-2020-11023", "CVE-2015-9251"} <= set(row["osv_cves"])
    assert set(row["confirmed"]) >= {"CVE-2019-11358", "GHSA-6c3j-c64m-qhgq"}
    # only the library name and version are sent, never the text
    assert len(http.calls) == 1
    http.assert_hosts_within(RetireJsOsv)


def test_osv_empty_answer():
    http = FakeHttp().add("POST", OSV, json={})
    res = run_module(RetireJsOsv, Entity.make(T.TEXT, JQUERY), http)
    assert res.status is Status.OK  # queried: the attribute says OSV lists nothing
    assert res.attributes["js_libraries"][0]["osv_ids"] == []


def test_osv_400_is_error():
    f = module_fixture("retirejs_osv", "osv_error_400.json")
    http = FakeHttp().add("POST", OSV, status=400, json=f["body"])
    res = run_module(RetireJsOsv, Entity.make(T.TEXT, JQUERY), http)
    assert res.status is Status.ERROR and "invalid ecosystem" in res.error


def test_osv_429_and_5xx_could_not_verify():
    http = FakeHttp().add("POST", OSV, status=429, text="slow down")
    assert run_module(RetireJsOsv, Entity.make(T.TEXT, JQUERY), http).status is Status.RATE_LIMITED
    http2 = FakeHttp().add("POST", OSV, status=503, text="unavailable", times=5)
    assert run_module(RetireJsOsv, Entity.make(T.TEXT, JQUERY), http2).status is Status.ERROR


def test_nothing_recognised_sends_nothing():
    http = FakeHttp()
    res = run_module(RetireJsOsv, Entity.make(T.TEXT, "var x = 1;"), http)
    assert res.status is Status.EMPTY and http.calls == []


def test_per_run_cap():
    mod.OSV_BUDGET.add("case:c1", mod.OSV_PER_RUN_CAP)
    http = FakeHttp()
    res = run_module(RetireJsOsv, Entity.make(T.TEXT, JQUERY), http, case_id="c1")
    assert res.status is Status.SKIPPED and res.reason_code == "policy"
    assert http.calls == []


def test_budget_helper_caps():
    planned = [("e1", f"lib{i}", "1.0") for i in range(15)] + [("e2", f"other{i}", "1.0") for i in range(12)]
    out = mod.osv_budget(planned)
    assert len(out["allowed"]) == 20
    assert sum(1 for a in out["allowed"] if a[0] == "e1") == 10
    assert any(d[3] == "per-entity cap" for d in out["deferred"]) and any(d[3] == "per-run cap" for d in out["deferred"])
    assert mod.osv_query_body("jquery", "1.12.4") == {"package": {"name": "jquery", "ecosystem": "npm"}, "version": "1.12.4"}
