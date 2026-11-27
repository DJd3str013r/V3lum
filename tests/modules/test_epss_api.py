"""epss_api (P184 cond 2): the FIRST API fallback for CVEs missing from the day's EPSS file.

Fixtures in tests/fixtures/epss_api/ (prep batch p1-G08-1, recorded 2026-11-26 from api.first.org):
``ok.json`` (CVE-2021-44228), ``empty.json`` (an unscored id: 'OK, total 0'), ``invalid_param.json``
(a malformed id gives the very same answer - why ids are validated locally) and ``batch_research.json``.
The EPSS daily-file fixture comes from tests/fixtures/epss/.
"""

from __future__ import annotations

from datetime import datetime, timezone

import pytest

from tests.fakes import FIXTURES, FakeClock, FakeHttp, make_runtime, module_fixture, run_module
from v3lum.core.datasets import DATASETS
from v3lum.core.models import Status
from v3lum.modules.vulnerability_cve import epss as epss_mod
from v3lum.modules.vulnerability_cve.cve_record import CASE_COUNTERS, CVE_FANOUT_SETTING
from v3lum.modules.vulnerability_cve.epss import EPSS_CSV_URL, EPSS_DATASET
from v3lum.modules.vulnerability_cve.epss_api import EPSS_API_URL, EpssApi

API = EPSS_API_URL + "?cve={cve}"
DATED_URL = "https://epss.empiricalsecurity.com/epss_scores-2026-11-25.csv.gz"
CHALLENGE = "<!DOCTYPE html><html><head><title>Just a moment...</title></head><body><div id='cf-chl-widget'></div></body></html>"


@pytest.fixture(autouse=True)
def small_file_and_fresh_counters(monkeypatch):
    monkeypatch.setitem(DATASETS[EPSS_DATASET], "min_bytes", 10)
    monkeypatch.setattr(epss_mod, "EPSS_MIN_ROWS", 1)
    CASE_COUNTERS.reset()
    yield
    CASE_COUNTERS.reset()


def api_http(cve: str = "CVE-2021-44228", name: str = "ok.json", **route) -> FakeHttp:
    if route:
        return FakeHttp().add("GET", API.format(cve=cve), **route)
    return FakeHttp().add("GET", API.format(cve=cve), json=module_fixture(EpssApi, name))


def with_local_file(http: FakeHttp, *, now: datetime | None = None):
    """A runtime whose home holds the 2026-11-25 daily file (installed like `v3lum data update`)."""
    hop = module_fixture("epss", "redirect_dated_302.http.json")["response"]
    http.add("GET", EPSS_CSV_URL, status=hop["status"], headers=hop["headers"], times=1)
    http.add("GET", DATED_URL, body=(FIXTURES / "epss" / "bulk_ok.csv.gz").read_bytes(), times=1)
    clock = FakeClock(now) if now else FakeClock()
    rt = make_runtime(http, clock=clock)
    assert rt.data.update(EPSS_DATASET).status == "updated"
    return rt


# ------------------------------------------------------------------ metadata (P184 council values)
def test_metadata_third_party_trusted_default():
    cls = EpssApi
    assert (cls.disclosure, cls.provider, cls.sources, cls.hosts) == ("third_party", "first", ("first.epss_api",), ("api.first.org",))
    assert cls.terms == "open" and cls.default_enabled is True and cls.trust_tier == "trusted"
    assert cls.max_requests == 1 and cls.expected_latency == 8.0 and cls.cache_ttl == 86400 and cls.min_interval == 1.0
    assert cls.shares_input is True and cls.max_tlp.value_str == "amber+strict"


# ------------------------------------------------------------------ when the API is called (cond 2)
def test_no_local_file_calls_the_api():
    http = api_http()
    res = run_module(EpssApi, "cve:CVE-2021-44228", http)
    assert res.status is Status.OK
    a = res.attributes
    assert (a["epss"], a["epss_percentile"], a["epss_date"]) == (0.99999, 1.0, "2026-11-25")
    assert a["epss_text"].startswith("EPSS 0.99+ (top 1%): likely to be exploited soon (FIRST API; no local EPSS file)")
    assert res.requests == 1 and http.urls() == [API.format(cve="CVE-2021-44228")]
    http.assert_hosts_within(EpssApi)


def test_cve_in_the_local_file_is_answered_offline_without_a_call():
    http = FakeHttp()
    rt = with_local_file(http)
    calls = len(http.calls)
    res = run_module(EpssApi, "cve:CVE-2021-44228", runtime=rt)
    assert res.status is Status.SKIPPED and res.reason_code == "not_applicable"
    assert "answered offline by epss" in res.error
    assert len(http.calls) == calls  # the CVE id never left the machine


def test_miss_in_the_days_file_is_not_sent():
    http = FakeHttp()
    rt = with_local_file(http, now=datetime(2026, 11, 26, 12, 0, tzinfo=timezone.utc))  # 2026-11-25 is the latest run
    calls = len(http.calls)
    res = run_module(EpssApi, "cve:CVE-2099-12345", runtime=rt)
    assert res.status is Status.SKIPPED and "the day's EPSS file (2026-11-25)" in res.error
    assert len(http.calls) == calls


def test_miss_in_an_older_file_calls_the_api():
    http = api_http("CVE-2099-12345", "empty.json")
    rt = with_local_file(http, now=datetime(2026, 11, 27, 15, 0, tzinfo=timezone.utc))  # the 2026-11-27 run exists
    res = run_module(EpssApi, "cve:CVE-2099-12345", runtime=rt)
    assert res.status is Status.EMPTY  # 'no score published', never a low score
    assert "this is not a low score" in res.attributes["epss_text"] and "epss" not in res.attributes
    assert http.urls()[-1] == API.format(cve="CVE-2099-12345")


def test_ids_the_api_cannot_score_are_never_sent():
    http = FakeHttp()
    res = run_module(EpssApi, "cve:CVE-1998-0001", http)  # the API would answer 'OK, total 0' (invalid_param.json)
    assert res.status is Status.SKIPPED and http.calls == []
    assert module_fixture(EpssApi, "invalid_param.json") == module_fixture(EpssApi, "empty.json")


# ------------------------------------------------------------------ CVE fan-out rule (P183 cond 3)
def test_fanout_budget_defers_pivots_never_seeds():
    http = api_http("CVE-2021-44228").add("GET", API.format(cve="CVE-2014-0160"), json=module_fixture(EpssApi, "batch_research.json"))
    settings = {CVE_FANOUT_SETTING: 1}
    first = run_module(EpssApi, "cve:CVE-2021-44228", http, settings=settings, is_seed=False, depth=1, case_id="case-fanout")
    assert first.status is Status.OK
    second = run_module(EpssApi, "cve:CVE-2014-0160", http, settings=settings, is_seed=False, depth=1, case_id="case-fanout")
    assert second.status is Status.QUOTA and second.reason_code == "quota" and "fan-out budget" in second.error
    again = run_module(EpssApi, "cve:CVE-2021-44228", http, settings=settings, is_seed=False, depth=1, case_id="case-fanout")
    assert again.status is Status.OK  # the same CVE counts once per case
    seed = run_module(EpssApi, "cve:CVE-2014-0160", http, settings=settings, case_id="case-fanout")
    assert seed.status is Status.OK and seed.attributes["epss_percentile"] == 0.99998  # analyst-typed CVEs always run


# ------------------------------------------------------------------ status mapping (rule 5, P321)
def test_429_is_rate_limited():
    res = run_module(EpssApi, "cve:CVE-2021-44228", api_http(status=429, json={"status": "error"}))
    assert res.status is Status.RATE_LIMITED and not res.attributes


def test_challenge_page_is_blocked():
    for status in (403, 200):
        res = run_module(EpssApi, "cve:CVE-2021-44228", api_http(status=status, text=CHALLENGE))
        assert res.status is Status.BLOCKED and res.reason_code == "challenge", status


def test_server_error_is_could_not_verify():
    res = run_module(EpssApi, "cve:CVE-2021-44228", api_http(status=503, text="upstream down"))
    assert res.status is Status.ERROR and not res.attributes


def test_error_inside_http_200_is_detected():
    res = run_module(EpssApi, "cve:CVE-2021-44228", api_http(json={"status": "error", "status-code": 400, "message": "Bad request"}))
    assert res.status is Status.ERROR and "inside an HTTP 200 answer" in res.error


def test_malformed_and_foreign_answers_are_never_empty():
    res = run_module(EpssApi, "cve:CVE-2021-44228", api_http(text="{not json", headers={"content-type": "application/json"}))
    assert res.status is Status.ERROR
    other = {"status": "OK", "status-code": 200, "total": 1, "data": [{"cve": "CVE-2014-0160", "epss": "0.9", "percentile": "0.99", "date": "2026-11-25"}]}
    res2 = run_module(EpssApi, "cve:CVE-2021-44228", api_http(json=other))
    assert res2.status is Status.ERROR and "other CVE ids" in res2.error


def test_tlp_red_never_sends_the_id():
    from tests.fakes import make_runtime as _rt
    from v3lum.core.context import ScanOptions
    from v3lum.core.engine import Engine
    from v3lum.core.entities import Entity

    http = FakeHttp()
    rt = _rt(http)
    case = Engine(rt, ScanOptions(tlp="red", include={"epss_api"})).investigate([Entity.make("cve", "CVE-2021-44228")])
    rows = [r for r in case.results if r.module == "epss_api"]
    assert http.calls == [] and all(r.status is not Status.OK for r in rows)


def test_network_timeout_is_could_not_verify():
    from v3lum.core.http import NetworkError

    res = run_module(EpssApi, "cve:CVE-2021-44228", api_http(error=NetworkError("read timed out (api.first.org)")))
    assert res.status is Status.ERROR and not res.attributes  # never EMPTY (rule 5)
