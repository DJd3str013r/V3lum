"""epss (P184 cond 1): offline lookups in the daily EPSS file.

Fixtures in tests/fixtures/epss/ (prep batch p1-G08-1, recorded 2026-11-26): ``bulk_ok.csv`` (7 of the
412,861 rows of the 2026-11-25 file, comment and header verbatim) and its gzip ``bulk_ok.csv.gz``,
``redirect_dated_302.http.json`` (the real 302 with a RELATIVE Location from the -current alias),
``redirect_legacy_301.http.json`` (epss.cyentia.com -> epss.empiricalsecurity.com),
``bulk_missing_403.http.json`` (S3 AccessDenied for a missing dated object), and the synthetic
``bulk_bomb_synthetic.csv.gz`` (14.6 KB -> 6 MB) and ``bulk_bad_header_synthetic.csv``.
"""

from __future__ import annotations

import gzip

import pytest

from tests.fakes import FIXTURES, FakeClock, FakeHttp, make_ctx, make_runtime, module_fixture, run_module
from v3lum import paths
from v3lum.core.datasets import DATASETS
from v3lum.core.models import Status
from v3lum.modules.vulnerability_cve import epss as epss_mod
from v3lum.modules.vulnerability_cve.cve_record import epss_plain_words
from v3lum.modules.vulnerability_cve.epss import (
    EPSS_CSV_URL,
    EPSS_DATASET,
    Epss,
    build_epss_index,
    check_epss_lines,
    epss_lookup,
    latest_model_date,
    parse_epss_api,
    parse_epss_comment,
)

DATED_URL = "https://epss.empiricalsecurity.com/epss_scores-2026-11-25.csv.gz"
BULK_GZ = (FIXTURES / "epss" / "bulk_ok.csv.gz").read_bytes()
BULK_CSV = (FIXTURES / "epss" / "bulk_ok.csv").read_text(encoding="utf-8")


@pytest.fixture(autouse=True)
def small_file(monkeypatch):
    """The trimmed fixture holds 7 rows: lower the completeness floors for the download tests (the real
    floor is tested below)."""
    monkeypatch.setitem(DATASETS[EPSS_DATASET], "min_bytes", 10)
    monkeypatch.setattr(epss_mod, "EPSS_MIN_ROWS", 1)


def epss_http(body: bytes = BULK_GZ, *, status: int = 200, times: int | None = None) -> FakeHttp:
    hop = module_fixture(Epss, "redirect_dated_302.http.json")["response"]
    http = FakeHttp().add("GET", EPSS_CSV_URL, status=hop["status"], headers=hop["headers"], times=times)
    return http.add("GET", DATED_URL, status=status, body=body, headers={"content-type": "binary/octet-stream"}, times=times)


def runtime(http: FakeHttp, **kw):
    clock = FakeClock()
    return make_runtime(http, clock=clock, **kw), clock


# ------------------------------------------------------------------ metadata (P184 council values)
def test_metadata_is_offline_default_and_large_dataset():
    cls = Epss
    assert (cls.disclosure, cls.hosts, cls.provider, cls.sources) == ("none", (), "", ("first.epss_csv",))
    assert cls.terms == "open" and cls.default_enabled is True and cls.trust_tier == "n/a" and cls.max_requests == 0
    assert cls.max_tlp.value_str == "red" and cls.shares_input is False
    reg = DATASETS[EPSS_DATASET]
    assert reg["url"] == EPSS_CSV_URL and "epss.empiricalsecurity.com" in reg["url"]  # the current host (cond 3)
    assert reg["archive"] == "gz" and reg["large"] is True and reg["max_bytes"] == 128 * 1024 * 1024  # safe decompression, size cap
    assert reg["source"] == "first.epss_csv" and reg["terms_class"] == "open" and "attribution" in reg["licence"]


# ------------------------------------------------------------------ lookups (cond 1, 3)
def test_scored_cve_gets_score_percentile_model_date_and_plain_words():
    http = epss_http()
    res = run_module(Epss, "cve:CVE-2021-44228", http)
    assert res.status is Status.OK
    a = res.attributes
    assert (a["epss"], a["epss_percentile"]) == (0.99999, 1.0)
    assert a["epss_date"] == "2026-11-25" and a["epss_model_version"] == "v2026.06.15"
    assert a["epss_text"] == "EPSS 0.99+ (top 1%): likely to be exploited soon"
    assert not res.findings and not res.pivots
    assert res.requests == 0  # zero per-CVE calls: the bulk download only
    assert http.urls() == [EPSS_CSV_URL, DATED_URL]  # the relative 302 Location is resolved by the core
    assert [d["name"] for d in res.datasets] == [EPSS_DATASET]


def test_low_score_wording_and_second_run_from_the_local_copy():
    http = epss_http(times=1)
    rt, _clock = runtime(http)
    low = run_module(Epss, "cve:CVE-2026-9999", runtime=rt)
    assert low.attributes["epss_text"] == "EPSS 0.00: low probability of exploitation in the next 30 days"
    mid = run_module(Epss, "cve:CVE-1999-0001", runtime=rt)
    assert mid.attributes["epss_text"] == "EPSS 0.05 (top 10%): elevated probability of exploitation in the next 30 days"
    assert len(http.calls) == 2  # one download (two hops), then the local copy


def test_unscored_cve_is_empty_never_a_low_score():
    res = run_module(Epss, "cve:CVE-2099-12345", epss_http())
    assert res.status is Status.EMPTY
    assert "epss" not in res.attributes
    assert "this is not a low score" in res.attributes["epss_text"] and "2026-11-25" in res.attributes["epss_text"]


def test_large_file_is_never_downloaded_during_a_scan():
    http = FakeHttp()
    rt, _clock = runtime(http)
    rt.in_scan = True
    res = run_module(Epss, "cve:CVE-2021-44228", runtime=rt)
    assert res.status is Status.UNAVAILABLE and res.reason_code == "dataset"
    assert "v3lum data update epss_scores" in res.error
    assert http.calls == []


def test_decompression_bomb_is_refused_never_empty():
    bomb = (FIXTURES / "epss" / "bulk_bomb_synthetic.csv.gz").read_bytes()
    assert len(gzip.decompress(bomb)) > 100 * len(bomb)  # the fixture really is a bomb
    res = run_module(Epss, "cve:CVE-2021-44228", epss_http(bomb))
    assert res.status is Status.ERROR and "could not verify" in res.error
    assert not (paths.datasets_dir() / EPSS_DATASET).exists()


def test_s3_access_denied_and_bad_header_are_refused():
    missing = module_fixture(Epss, "bulk_missing_403.http.json")["response"]
    res = run_module(Epss, "cve:CVE-2021-44228", epss_http(missing["body"].encode(), status=missing["status"]))
    assert res.status in (Status.BLOCKED, Status.ERROR) and "could not verify" in res.error
    bad = gzip.compress((FIXTURES / "epss" / "bulk_bad_header_synthetic.csv").read_bytes())
    res2 = run_module(Epss, "cve:CVE-2021-44228", epss_http(bad))
    assert res2.status is Status.ERROR and "header" in res2.error


def test_stale_file_is_flagged_and_still_served():
    http = epss_http(times=1)
    rt, clock = runtime(http)
    assert run_module(Epss, "cve:CVE-2021-44228", runtime=rt).status is Status.OK
    clock.advance(3 * 86400)
    rt.in_scan = True  # a scan never refreshes the large file: the stale copy is served at once
    res = run_module(Epss, "cve:CVE-2021-44228", runtime=rt)
    assert res.status is Status.OK and "local file stale" in res.attributes["epss_text"]
    stale = Epss.health_check().selftest(make_ctx(Epss, runtime=rt))
    assert stale.status == "dead" and "v3lum data update epss_scores" in stale.detail


def test_health_selftest_ok_and_missing():
    http = epss_http(times=1)
    rt, _clock = runtime(http)
    check = Epss.health_check()
    assert check.offline is True
    assert check.selftest(make_ctx(Epss, runtime=rt)).status == "dead"
    run_module(Epss, "cve:CVE-2021-44228", runtime=rt)
    ok = check.selftest(make_ctx(Epss, runtime=rt))
    assert ok.status == "ok" and "v2026.06.15" in ok.detail


def test_tlp_red_still_answers_offline():
    res = run_module(Epss, "cve:CVE-2021-44228", epss_http(), tlp="red")
    assert res.status is Status.OK


# ------------------------------------------------------------------ parsers (shared with epss_api)
def test_index_handles_unsorted_rows_duplicates_and_junk():
    lines = [
        "#model_version:v1,score_date:2026-11-25T12:00:00Z", "cve,epss,percentile",
        "CVE-2024-0002,0.5,0.9", "CVE-2021-44228,0.1,0.2", "garbage", "CVE-2024-0002,0.6,0.95",
        "CVE-INVALID,0.1,0.1", "CVE-2024-0003,1.5,0.1", "CVE-2024-0004,nan,0.1",
    ]
    index = build_epss_index(lines)
    assert index["rows"] == 2 and index["bad_rows"] == 4
    assert epss_lookup(index, "CVE-2024-0002") == {"epss": 0.6, "percentile": 0.95}  # the last duplicate wins
    assert epss_lookup(index, "cve-2021-44228") == {"epss": 0.1, "percentile": 0.2}
    assert epss_lookup(index, "CVE-2024-0003") is None and epss_lookup(index, "nonsense") is None
    assert index["meta"] == {"model_version": "v1", "score_date": "2026-11-25T12:00:00Z"}


def test_real_completeness_floor(monkeypatch):
    monkeypatch.setattr(epss_mod, "EPSS_MIN_ROWS", 100_000)
    assert check_epss_lines(BULK_CSV.splitlines()) == "only 7 EPSS rows (expected >= 100000)"
    assert "header" in check_epss_lines(["cve,score,rank", "CVE-2021-44228,0.1,0.2"], min_rows=1)
    assert check_epss_lines(BULK_CSV.splitlines(), min_rows=7) is None


def test_comment_and_model_dates():
    assert parse_epss_comment("#model_version:v2026.06.15,score_date:2026-11-25T12:00:23Z") == {
        "model_version": "v2026.06.15", "score_date": "2026-11-25T12:00:23Z"}
    assert parse_epss_comment("cve,epss,percentile") == {}
    from datetime import datetime, timezone

    assert latest_model_date(datetime(2026, 11, 26, 9, 0, tzinfo=timezone.utc)) == "2026-11-25"  # before ~13:30 UTC
    assert latest_model_date(datetime(2026, 11, 26, 15, 0, tzinfo=timezone.utc)) == "2026-11-26"


@pytest.mark.parametrize(("epss", "pct", "expected"), [
    (0.94358, 0.99962, "EPSS 0.94 (top 1%): likely to be exploited soon"),
    (0.6, 0.97, "EPSS 0.60 (top 5%): likely to be exploited soon"),
    (0.02, 0.96, "EPSS 0.02 (top 5%): elevated probability of exploitation in the next 30 days"),
    (0.001, 0.2, "EPSS 0.00: low probability of exploitation in the next 30 days"),
    (None, None, "no EPSS score published for this CVE: exploitation probability unknown"),
])
def test_plain_words(epss, pct, expected):
    assert epss_plain_words(epss, pct) == expected


def test_api_parser_detects_errors_inside_http_200():
    assert parse_epss_api({"status": "error", "status-code": 400, "message": "bad input"})["status"] == "error"
    assert parse_epss_api({"status": "OK", "status-code": 500, "data": []})["status"] == "error"
    assert parse_epss_api(["not", "an", "object"])["status"] == "error"
    assert parse_epss_api({"status": "OK", "status-code": 200, "total": 0, "data": []})["status"] == "empty"
    rows = parse_epss_api({"status": "OK", "data": [{"cve": "CVE-2021-44228", "epss": "0.5", "percentile": "2"}, {"cve": "x"}]})
    assert rows["status"] == "empty"  # a percentile above 1 and a junk id are dropped


def test_legacy_host_redirect_chain_stays_within_the_first_provider(clean_registry):
    """epss.cyentia.com (the spec's legacy host) answers 301 to the current host, whose -current alias
    answers 302 with a relative Location: the dataset manager follows both hops inside provider first."""
    from v3lum.core.datasets import register_dataset

    legacy = module_fixture(Epss, "redirect_legacy_301.http.json")
    hop = module_fixture(Epss, "redirect_dated_302.http.json")["response"]
    register_dataset("t_epss_legacy", legacy["request"]["url"], provider="first", source="first.epss_csv", archive="gz",
                     expect="csv", licence="FIRST EPSS", terms_class="open", min_bytes=10)
    http = FakeHttp().add("GET", legacy["request"]["url"], status=legacy["response"]["status"], headers=legacy["response"]["headers"])
    http.add("GET", EPSS_CSV_URL, status=hop["status"], headers=hop["headers"]).add("GET", DATED_URL, body=BULK_GZ)
    rt, _clock = runtime(http)
    assert rt.data.update("t_epss_legacy").status == "updated"
    assert http.urls() == [legacy["request"]["url"], EPSS_CSV_URL, DATED_URL]
