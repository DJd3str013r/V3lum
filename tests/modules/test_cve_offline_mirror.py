"""cve_offline_mirror (P352): the CVE List mirror (baseline archive + deltaLog changes) in SQLite.

Fixtures in tests/fixtures/cve_offline_mirror/ (prep batch p2-G08-2, 2026-11-26):
``record_ok.json`` - the real CVE-2021-44228 record (CNA + CVE Program + CISA ADP Vulnrichment containers;
``credits`` removed), ``record_rejected.json`` - synthetic REJECTED record, ``deltalog_ok.json`` - the 4 newest
real deltaLog entries, ``deltalog_truncated.json`` - a cut-off download, ``deltalog_hostile.json`` (synthetic:
foreign owners/hosts, http, dot segments, query strings, mismatched links, wrong types),
``baseline_ok.zip.zip`` (synthetic zip-of-zip: two records, an id mismatch, a '../' member name, other files)
and ``baseline_bomb.zip`` (synthetic: a 6 MB member and a 1000:1 member next to a good one). github.com was
refused by the prep session's proxy, so the release archives are synthetic.
"""

from __future__ import annotations

import io
import json
import zipfile

import pytest

from tests.fakes import FIXTURES, FakeClock, FakeHttp, make_ctx, make_runtime, module_fixture, run_module
from v3lum.core.datasets import DATASETS
from v3lum.core.models import Severity, Status
from v3lum.modules.vulnerability_cve import cve_offline_mirror as cm
from v3lum.modules.vulnerability_cve.cve_offline_mirror import (
    BASELINE_HINT,
    CISA_ADP_NOTICE,
    CVE_ATTRIBUTION,
    DELTALOG_DATASET,
    DELTALOG_URL,
    SOURCE,
    CveOfflineMirror,
    MirrorDB,
    baseline_asset_from_release,
    cvelist_record_url,
    decompress_record,
    import_baseline,
    iter_cve_zip_members,
    mirror_card_fields,
    mirror_path,
    mirror_row,
    mirror_status,
    parse_delta_log,
    plan_delta_updates,
    sync_cves,
    validate_delta_link,
)
from v3lum.modules.vulnerability_cve.cve_record import CveRecord, _mirror_record
from v3lum.modules.vulnerability_cve.g08_offline import JobRefused

BASELINE = FIXTURES / "cve_offline_mirror" / "baseline_ok.zip.zip"
BOMB = FIXTURES / "cve_offline_mirror" / "baseline_bomb.zip"
RECORD = module_fixture(CveOfflineMirror, "record_ok.json")
REJECTED = module_fixture(CveOfflineMirror, "record_rejected.json")
DELTALOG = module_fixture(CveOfflineMirror, "deltalog_ok.json")
WINDOW_START = {"fetchTime": "2026-10-27T00:10:00.000Z", "numberOfChanges": 0, "new": [], "updated": [], "error": []}
ASSET = "2026-11-25_all_CVEs_at_midnight.zip.zip"


def record_for(cve: str, updated: str) -> dict:
    """The real record re-labelled for a delta test (same containers, other id and dateUpdated)."""
    doc = json.loads(json.dumps(RECORD))
    doc["cveMetadata"]["cveId"] = cve
    doc["cveMetadata"]["dateUpdated"] = updated
    return doc


def import_fixture_baseline() -> dict:
    with MirrorDB(readonly=False) as db:
        return import_baseline(db, BASELINE, asset_name=ASSET, now="2026-11-26T08:00:00.000000Z")


def delta_http(log: list | None = None) -> FakeHttp:
    http = FakeHttp().add("GET", DELTALOG_URL, json=[*(log if log is not None else DELTALOG), WINDOW_START])
    for cve, updated in (("CVE-2026-137315", "2026-11-26T07:15:19.315Z"), ("CVE-2026-137314", "2026-11-26T07:00:24.603Z"),
                         ("CVE-2026-129838", "2026-11-26T06:11:21.330Z")):
        http.add("GET", cvelist_record_url(cve), json=record_for(cve, updated))
    return http


# ------------------------------------------------------------------ metadata (P352 council values)
def test_metadata_is_offline_tlp_red_safe_and_default():
    cls = CveOfflineMirror
    assert (cls.disclosure, cls.hosts, cls.provider, cls.sources) == ("none", (), "", (SOURCE,))
    assert cls.terms == "open" and cls.default_enabled is True and cls.trust_tier == "n/a" and cls.max_tlp.value_str == "red"
    assert cls.max_requests == 0 and cls.shares_input is False
    reg = DATASETS[DELTALOG_DATASET]
    assert reg["url"] == DELTALOG_URL and reg["large"] is True and reg["source"] == SOURCE and reg["terms_class"] == "open"
    assert CVE_ATTRIBUTION in reg["attribution"] and CISA_ADP_NOTICE in reg["attribution"]


# ------------------------------------------------------------------ baseline archive (cond 1)
def test_zip_of_zip_is_read_member_by_member_without_extraction(tmp_path, monkeypatch):
    work = tmp_path / "cwd"
    work.mkdir()
    monkeypatch.chdir(work)
    stats: dict = {}
    members = list(iter_cve_zip_members(BASELINE, stats))
    assert [(o, c) for o, c, _d in members] == [(1, "CVE-2021-44228"), (2, "CVE-2099-0001"), (3, "CVE-2021-44229")]
    assert stats["nested"] == 1 and stats["suspicious_names"] == 1 and stats["skipped_other"] == 3 and stats["stopped"] is None
    assert list(work.iterdir()) == []  # nothing written: member names never become paths


def test_caps_skip_oversized_and_high_ratio_members():
    stats: dict = {}
    members = list(iter_cve_zip_members(BOMB, stats))
    assert [c for _o, c, _d in members] == ["CVE-2021-44228"]
    assert stats["skipped_size"] == 1 and stats["skipped_ratio"] == 1


def test_member_count_and_total_caps_stop_the_walk():
    stats: dict = {}
    assert list(iter_cve_zip_members(BASELINE, stats, max_members=3)) == [] and stats["stopped"] == "member_cap"
    stats = {}
    list(iter_cve_zip_members(BASELINE, stats, max_total_bytes=5000))
    assert stats["stopped"] == "total_cap"


def test_nested_depth_and_unreadable_archives_are_refused():
    inner = io.BytesIO()
    with zipfile.ZipFile(inner, "w") as zf:
        zf.writestr("deeper.zip", BASELINE.read_bytes())
    stats: dict = {}
    assert list(iter_cve_zip_members(io.BytesIO(inner.getvalue()), stats)) == [] and stats["nested_refused"] == 1
    stats = {}
    assert list(iter_cve_zip_members(io.BytesIO(b"not a zip"), stats)) == [] and stats["stopped"].startswith("unreadable archive")


def test_baseline_import_indexes_through_the_shared_parser_and_resumes():
    out = import_fixture_baseline()
    assert out["status"] == "imported" and out["indexed"] == 2 and out["refused"] == 1  # CVE-2021-44229 carries the 44228 record
    with MirrorDB() as db:
        meta = db.meta()
        assert db.count() == 2 and meta["baseline_date"] == "2026-11-25" and meta["baseline_resume_ordinal"] == "done"
        assert meta["delta_newest_fetch"] == "2026-11-25T00:00:00.000000Z"
        row = db.get("CVE-2021-44228")
    assert row["kev"] == 1 and row["kev_date_added"] == "2021-12-10" and row["ssvc_exploitation"] == "active"
    assert row["adp_cvss_score"] == 10.0 and row["date_updated"] == "2025-10-21T23:25:23.121000Z"
    doc = json.loads(decompress_record(row["record"]))
    assert "credits" not in json.dumps(doc)  # minimised (LGPD)
    assert oct(mirror_path().stat().st_mode & 0o777) == "0o600"
    # the same archive again: nothing to do
    with MirrorDB(readonly=False) as db:
        assert import_baseline(db, BASELINE, asset_name=ASSET)["status"] == "unchanged"


def test_interrupted_import_continues_after_the_last_committed_record():
    calls = {"n": 0}

    def cancelled() -> bool:
        calls["n"] += 1
        return calls["n"] > 2  # stop when the third record comes

    with MirrorDB(readonly=False) as db:
        first = import_baseline(db, BASELINE, asset_name=ASSET, cancelled=cancelled, commit_every=1)
        assert first["status"] == "interrupted" and db.meta()["baseline_resume_ordinal"] == "2"
        second = import_baseline(db, BASELINE, asset_name=ASSET, commit_every=1)
        assert second["status"] == "imported" and second["resumed_from"] == 2 and second["resumed_past"] == 2
        assert db.count() == 2


def test_record_checks_refuse_mismatches_and_garbage():
    raw = json.dumps(RECORD).encode()
    assert mirror_row(raw, "CVE-2021-44229") == (None, "id mismatch")
    assert mirror_row(b"{not json", "CVE-2021-44228") == (None, "not a CVE record")
    assert mirror_row(b"x" * 10, max_bytes=5) == (None, "too large")
    row, reason = mirror_row(raw)
    assert reason is None and mirror_card_fields(row)["kev"] == {"value": True, "date_added": "2021-12-10", "provider": "cisa_adp"}
    assert decompress_record(b"garbage") is None
    assert decompress_record(__import__("zlib").compress(b"a" * 2000), max_bytes=100) is None  # capped inflation


def test_release_asset_discovery_accepts_only_the_canonical_download():
    release = {"tag_name": "cve_2026-11-25_at_end_of_day", "assets": [
        {"name": "2026-11-25_all_CVEs_at_midnight.zip.zip", "size": 1,
         "browser_download_url": "https://github.com/CVEProject/cvelistV5/releases/download/cve_2026-11-25_at_end_of_day/2026-11-25_all_CVEs_at_midnight.zip.zip"},
        {"name": "2026-11-26_all_CVEs_at_midnight.zip.zip", "size": 1,
         "browser_download_url": "https://github.com/attacker/cvelistV5/releases/download/x/2026-11-26_all_CVEs_at_midnight.zip.zip"},
        {"name": "2026-11-25_delta_CVEs_at_0100Z.zip", "browser_download_url": "https://github.com/CVEProject/cvelistV5/releases/download/x/2026-11-25_delta_CVEs_at_0100Z.zip"},
    ]}
    asset = baseline_asset_from_release(release)
    assert asset["date"] == "2026-11-25" and asset["url"].startswith(cm.RELEASE_DOWNLOAD_PREFIX)
    assert baseline_asset_from_release({"assets": [release["assets"][1]]}) is None
    assert baseline_asset_from_release("<html></html>") is None
    assert set(cm.RELEASE_DOWNLOAD_HOSTS) == {"github.com", "release-assets.githubusercontent.com", "objects.githubusercontent.com"}


# ------------------------------------------------------------------ deltas (cond 2)
@pytest.mark.parametrize("url", [
    "http://raw.githubusercontent.com/CVEProject/cvelistV5/main/cves/2026/0xxx/CVE-2026-0001.json",
    "https://raw.githubusercontent.com/attacker/cvelistV5/main/cves/2026/0xxx/CVE-2026-0001.json",
    "https://raw.githubusercontent.com.evil.example/CVEProject/cvelistV5/main/cves/2026/0xxx/CVE-2026-0001.json",
    "https://raw.githubusercontent.com/CVEProject/cvelistV5/main/cves/2026/0xxx/../CVE-2026-0001.json",
    "https://raw.githubusercontent.com/CVEProject/cvelistV5/main/cves/2026/0xxx/CVE-2026-0001.json?token=x",
    "https://raw.githubusercontent.com:8443/CVEProject/cvelistV5/main/cves/2026/0xxx/CVE-2026-0001.json",
    "https://raw.githubusercontent.com/CVEProject/cvelistV5/main/cves/2026/0xxx/CVE-2026-0002.json",
])
def test_delta_links_must_be_the_canonical_record_url(url):
    assert validate_delta_link(url, "CVE-2026-0001") is None


def test_delta_log_parsing_rejects_hostile_items():
    parsed = parse_delta_log(module_fixture(CveOfflineMirror, "deltalog_hostile.json"))
    assert [i["cve"] for i in parsed["items"]] == ["CVE-2026-0007"]
    assert len(parsed["rejected"]) == 10 and len(parsed["errors"]) == 1 and parsed["entries"] == 1
    truncated = (FIXTURES / "cve_offline_mirror" / "deltalog_truncated.json").read_bytes()
    assert parse_delta_log(truncated)["reason"] == "malformed JSON"


def test_plan_takes_the_newest_change_and_only_when_newer():
    parsed = parse_delta_log(DELTALOG)
    plan = plan_delta_updates(parsed, {"CVE-2026-137314": "2026-11-26T07:00:24.603Z"})
    assert [(i["cve"], i["date_updated"][:19]) for i in plan["apply"]] == [
        ("CVE-2026-129838", "2026-11-26T06:11:21"), ("CVE-2026-137315", "2026-11-26T07:15:19")]
    assert plan["skipped_not_newer"] == 1 and plan["baseline_required"] is False
    gap = plan_delta_updates(parsed, {}, last_delta_fetch="2026-09-01T00:00:00Z")
    assert gap["baseline_required"] is True and "window" in gap["reason"]
    many = plan_delta_updates(parsed, {}, max_records=1)
    assert many["baseline_required"] is True


def test_sync_applies_deltas_after_the_baseline_and_only_newer_records():
    import_fixture_baseline()
    http = delta_http()
    runtime = make_runtime(http, clock=FakeClock())
    out = sync_cves(runtime)
    assert out["status"] == "ok" and out["deltas"]["applied"] == 3 and out["deltas"]["planned"] == 3
    with MirrorDB() as db:
        assert db.count() == 5 and db.known_date("CVE-2026-129838") == "2026-11-26T06:11:21.330000Z"
        assert db.meta()["delta_newest_fetch"] == "2026-11-26T07:15:57.724000Z"
    hosts = {u.split("/")[2] for u in http.urls()}
    assert hosts == {"raw.githubusercontent.com"} and all(c["method"] == "GET" for c in http.calls)
    # a second run: nothing newer -> no record fetch
    before = len(http.calls)
    again = sync_cves(runtime)
    assert again["deltas"]["planned"] == 0 and all("CVE-2026" not in u for u in http.urls()[before:])


def test_sync_without_a_baseline_asks_for_one():
    out = sync_cves(make_runtime(FakeHttp(), clock=FakeClock()))
    assert out["status"] == "baseline_required" and out["reason"] == BASELINE_HINT


def test_sync_gap_larger_than_the_log_window_asks_for_a_new_baseline():
    import_fixture_baseline()
    with MirrorDB(readonly=False) as db:
        db.set_meta(delta_newest_fetch="2026-09-01T00:00:00.000000Z")
    out = sync_cves(make_runtime(delta_http(), clock=FakeClock()))
    assert out["status"] == "baseline_required" and "window" in out["reason"]


def test_a_rate_limited_record_keeps_the_window_for_the_next_run():
    import_fixture_baseline()
    http = FakeHttp().add("GET", DELTALOG_URL, json=[*DELTALOG, WINDOW_START])
    http.add("GET", cvelist_record_url("CVE-2026-129838"), status=429, text="slow down", headers={"Retry-After": "60"})
    out = sync_cves(make_runtime(http, clock=FakeClock()))
    assert out["status"] == "partial" and "RateLimited" in out["reason"]
    with MirrorDB() as db:
        assert db.meta()["delta_newest_fetch"] == "2026-11-25T00:00:00.000000Z"  # not advanced: retried next time


def test_sync_is_refused_inside_a_scan():
    runtime = make_runtime(FakeHttp(), clock=FakeClock())
    runtime.in_scan = True
    with pytest.raises(JobRefused):
        sync_cves(runtime)


# ------------------------------------------------------------------ the module (cond 3/4)
def test_without_a_mirror_the_module_is_unavailable():
    res = run_module(CveOfflineMirror, "cve:CVE-2021-44228", FakeHttp())
    assert res.status is Status.UNAVAILABLE and res.reason_code == "dataset" and "v3lum data sync cves" in res.error


def test_hit_exposes_ssvc_kev_relay_adp_cvss_and_attribution():
    import_fixture_baseline()
    http = FakeHttp()
    res = run_module(CveOfflineMirror, "cve:CVE-2021-44228", http, clock=FakeClock())
    assert res.status is Status.OK and http.calls == []
    a = res.attributes
    assert a["cve_state"] == "PUBLISHED" and a["kev"] is True and a["kev_date_added"] == "2021-12-10"
    assert a["ssvc"]["exploitation"] == "active" and a["ssvc"]["technical_impact"] == "total"
    assert a["exploited"] == {"CISA-ADP SSVC": "2025-02-04"}
    assert any(c["container"] == "adp" and c["score"] == 10.0 for c in a["cvss_scores"])
    assert a["data_notices"] == [CVE_ATTRIBUTION, CISA_ADP_NOTICE]
    assert a["cve_mirror"]["records"] == 2 and a["cve_mirror"]["record_sha256"]
    assert a["dataset_age"][0].startswith("CVE mirror: 2 records")
    assert "credits" not in json.dumps(res.raw)


def test_rejected_record_is_informational_with_its_replacement():
    import_fixture_baseline()
    res = run_module(CveOfflineMirror, "cve:CVE-2099-0001", FakeHttp())
    assert res.status is Status.OK and res.attributes["cve_state"] == "REJECTED"
    finding = res.findings[0]
    assert finding.severity is Severity.INFO and "context_only" in finding.tags
    assert [(p.entity.value, p.relation) for p in res.pivots] == [("CVE-2099-0002", "related")]


def test_miss_is_empty_with_the_mirror_age():
    import_fixture_baseline()
    res = run_module(CveOfflineMirror, "cve:CVE-2026-9999999", FakeHttp())
    assert res.status is Status.EMPTY and "not in the local CVE mirror" in res.error and "2 records" in res.error


def test_cve_record_reads_the_mirror_first_and_sends_nothing():
    import_fixture_baseline()
    http = FakeHttp()
    assert _mirror_record(None, "CVE-2021-44228")[1] == "cve_offline_mirror"
    res = run_module(CveRecord, "cve:CVE-2021-44228", http, is_seed=False)  # pivot CVE: no NVD call either
    assert res.status is Status.OK and http.calls == []
    assert res.raw["cve5_origin"] == "cve_offline_mirror" and res.attributes["kev"] is True


def test_cve_record_falls_back_when_the_mirror_misses():
    import_fixture_baseline()
    assert _mirror_record(None, "CVE-2026-0001") == (None, "")


def test_doctor_shows_age_records_and_disk_usage():
    clock = FakeClock()
    runtime = make_runtime(FakeHttp(), clock=clock)
    ctx = make_ctx(CveOfflineMirror, runtime=runtime)
    check = CveOfflineMirror.health_check()
    assert check.offline is True and check.selftest(ctx).status == "dead"
    with MirrorDB(readonly=False) as db:
        import_baseline(db, BASELINE, asset_name=ASSET, now=clock.now().isoformat())
    result = check.selftest(ctx)
    assert result.status == "ok" and "2 records" in result.detail and "MiB on disk" in result.detail
    status = mirror_status({"last_sync_at": "2026-01-01T00:00:00Z", "records": "5"}, "2026-11-26T00:00:00Z", 2**20)
    assert status["stale"] is True and "stale" in status["line"] and "1.0 MiB" in status["line"]
