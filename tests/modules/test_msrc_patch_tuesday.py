"""msrc_patch_tuesday (P353): MSRC CVRF v3 month documents indexed offline by CVE and KB.

Fixtures in tests/fixtures/msrc_patch_tuesday/ (prep batch p2-G08-2, recorded 2026-11-26 from
api.msrc.microsoft.com): ``updates_ok.json`` (10 of the 218 real /updates entries: odd ids '2017-May-B',
'2018-FEB', a 'Mariner Release Notes' document), ``updates_ims_ignored.http.json`` (the real answer to a GET with
If-Modified-Since: 200 + full list), ``month_ok.json`` (a 6-CVE cut of the real cvrf/2026-Nov document, the
same month as the gap-fill sample; Acknowledgments names replaced by 'Example Researcher'),
``month_truncated.json`` (a cut-off download), the real 404 exchange (a bare JSON string), a synthetic HTML
error page in a 200 and the research record of the 405 HEAD answer (never sent: GET only).
"""

from __future__ import annotations

import datetime as dt
import json

import pytest

from tests.fakes import FIXTURES, FakeClock, FakeHttp, make_ctx, make_runtime, module_fixture, run_module
from v3lum.core.datasets import DATASETS
from v3lum.core.models import Status
from v3lum.modules.vulnerability_cve import cisa_kev as kev_mod
from v3lum.modules.vulnerability_cve.msrc_patch_tuesday import (
    MSRC_CVRF_URL,
    MSRC_UPDATES_URL,
    SOURCE,
    UPDATES_DATASET,
    MsrcDB,
    MsrcPatchTuesday,
    index_path,
    msrc_keyword_kind,
    msrc_merge_rows,
    msrc_month_key,
    parse_cvrf_document,
    parse_exploit_status,
    parse_msrc_updates,
    refresh_msrc,
    select_msrc_refresh,
)

UPDATES = module_fixture(MsrcPatchTuesday, "updates_ok.json")
MONTH = (FIXTURES / "msrc_patch_tuesday" / "month_ok.json").read_bytes()
TRUNCATED = (FIXTURES / "msrc_patch_tuesday" / "month_truncated.json").read_bytes()
HTML_200 = module_fixture(MsrcPatchTuesday, "month_html.http.json")["response"]
NOT_FOUND = module_fixture(MsrcPatchTuesday, "month_not_found.http.json")["response"]
NOW = dt.datetime(2026, 11, 26, 9, 0, tzinfo=dt.timezone.utc)
JSON_HEADERS = {"content-type": "application/json; charset=utf-8"}


def url(doc_id: str) -> str:
    return MSRC_CVRF_URL.format(id=doc_id)


def full_http() -> FakeHttp:
    """/updates plus the five window documents: one good, a 404, an HTML error page in a 200, a truncated
    download and a document whose id does not match the URL."""
    http = FakeHttp().add("GET", MSRC_UPDATES_URL, json=UPDATES, match_headers={"Accept": "application/json"})
    http.add("GET", url("2026-Nov"), body=MONTH, headers=JSON_HEADERS, match_headers={"Accept": "application/json"})
    http.add("GET", url("2026-Oct"), status=404, body=str(NOT_FOUND["body"]).encode(), headers=NOT_FOUND["headers"])
    http.add("GET", url("2026-Sep"), status=200, body=str(HTML_200["body"]).encode(), headers=HTML_200["headers"])
    http.add("GET", url("2025-Dec"), body=TRUNCATED, headers=JSON_HEADERS)
    http.add("GET", url("2024-Dec"), body=MONTH, headers=JSON_HEADERS)  # carries id 2026-Nov: refused
    return http


@pytest.fixture
def indexed():
    """A runtime whose MSRC index holds the 2026-Nov cut."""
    http = full_http()
    runtime = make_runtime(http, clock=FakeClock(NOW))
    summary = refresh_msrc(runtime)
    return runtime, http, summary


# ------------------------------------------------------------------ metadata (P353 council values)
def test_metadata_is_offline_tlp_red_safe_and_default():
    cls = MsrcPatchTuesday
    assert (cls.disclosure, cls.hosts, cls.provider) == ("none", (), "") and cls.sources == (SOURCE, "cisa.kev")
    assert cls.terms == "open" and cls.default_enabled is True and cls.trust_tier == "n/a" and cls.max_tlp.value_str == "red"
    assert {t.value for t in cls.accepts} == {"cve", "keyword"} and cls.max_requests == 0
    reg = DATASETS[UPDATES_DATASET]
    assert reg["url"] == MSRC_UPDATES_URL and reg["source"] == SOURCE and reg["terms_class"] == "open"


# ------------------------------------------------------------------ refresh (cond 1/2)
def test_refresh_indexes_documents_one_at_a_time_and_refuses_broken_ones(indexed):
    runtime, http, summary = indexed
    assert summary["selected"] == ["2026-Nov", "2026-Oct", "2026-Sep", "2025-Dec", "2024-Dec"]  # 24-month window, newest first
    assert summary["indexed"] == [{"id": "2026-Nov", "vulnerabilities": 6}]
    assert summary["missing"] == ["2026-Oct"]
    refused = {r["id"]: r["why"] for r in summary["refused"]}
    assert refused["2026-Sep"] == "html instead of JSON" and refused["2025-Dec"] == "malformed JSON"
    assert "does not match" in refused["2024-Dec"] and summary["status"] == "partial"
    assert all(c["method"] == "GET" for c in http.calls)  # never HEAD (the API answers 405)
    assert {u.split("/")[2] for u in http.urls()} == {"api.msrc.microsoft.com"}
    assert oct(index_path().stat().st_mode & 0o777) == "0o600"
    assert not list(index_path().parent.glob(".msrc_patch_tuesday-*"))  # temporary document files removed
    with MsrcDB() as db:
        docs = db.documents()
    assert list(docs) == ["2026-Nov"] and docs["2026-Nov"]["current_release"] == "2026-11-25T01:14:17.000000Z"


def test_second_refresh_sends_if_modified_since_and_skips_unchanged_documents(indexed):
    runtime, http, _summary = indexed
    http.routes.clear()
    http.add("GET", MSRC_UPDATES_URL, json=UPDATES, match_headers={"If-Modified-Since": "Wed, 25 Nov 2026 01:14:17 GMT"})
    out = refresh_msrc(runtime, max_documents=0)
    assert "2026-Nov" not in out["selected"] and out["indexed"] == []


def test_changed_documents_follow_the_cadence_caps():
    docs = parse_msrc_updates(UPDATES)["documents"]
    known = {"2026-Nov": {"current_release": "2026-11-20T00:00:00Z", "fetched_at": "2026-11-26T01:00:00Z"},
             "2025-Dec": {"current_release": "2026-11-01T00:00:00Z", "fetched_at": "2026-11-25T00:00:00Z"}}
    picked = select_msrc_refresh(docs, known, NOW, min_refresh_hours=168, recent_months=2, recent_min_refresh_hours=24)
    ids = [d["id"] for d in picked]
    assert "2026-Nov" not in ids and "2025-Dec" not in ids  # changed but fetched within the cadence
    later = select_msrc_refresh(docs, known, NOW + dt.timedelta(days=8), min_refresh_hours=168, recent_months=2, recent_min_refresh_hours=24)
    assert {"2026-Nov", "2025-Dec"} <= {d["id"] for d in later if d["reason"] == "CurrentReleaseDate changed"}
    older = select_msrc_refresh(docs, {}, NOW, extra_ids=("2018-FEB",))
    assert "2018-FEB" in [d["id"] for d in older] and "2017-May-B" not in [d["id"] for d in older]  # older months on demand


def test_a_rate_limited_document_stops_the_refresh_as_could_not_verify():
    http = FakeHttp().add("GET", MSRC_UPDATES_URL, json=UPDATES)
    http.add("GET", url("2026-Nov"), status=429, text="Too Many Requests", headers={"Retry-After": "120"})
    out = refresh_msrc(make_runtime(http, clock=FakeClock(NOW)))
    assert out["status"] == "partial" and "RateLimited" in out["reason"] and out["indexed"] == []


def test_updates_error_page_is_refused_and_nothing_is_fetched():
    http = FakeHttp().add("GET", MSRC_UPDATES_URL, status=200, body=str(HTML_200["body"]).encode(), headers=HTML_200["headers"])
    out = refresh_msrc(make_runtime(http, clock=FakeClock(NOW)))
    assert out["status"] == "error" and "could not verify" in out["reason"] and len(http.calls) == 1


def test_refresh_is_refused_inside_a_scan():
    runtime = make_runtime(FakeHttp(), clock=FakeClock(NOW))
    runtime.in_scan = True
    with pytest.raises(Exception, match="inside a scan"):
        refresh_msrc(runtime)


# ------------------------------------------------------------------ the module (cond 3/4)
def test_without_an_index_the_module_is_unavailable():
    res = run_module(MsrcPatchTuesday, "cve:CVE-2026-124194", FakeHttp())
    assert res.status is Status.UNAVAILABLE and res.reason_code == "dataset" and "v3lum data sync msrc" in res.error


def test_exploited_yes_is_exploitation_evidence_never_kev(indexed):
    runtime, _http, _ = indexed
    res = run_module(MsrcPatchTuesday, "cve:CVE-2026-124194", runtime=runtime)
    assert res.status is Status.OK and res.requests == 0
    a = res.attributes
    assert a["exploited"] == {"msrc": "2026-11-10"} and a["msrc_exploited"] is True
    assert a["msrc_priority_line"] == "Exploited per Microsoft (not in CISA KEV yet): patch now"
    assert "kev" not in a and "kev_date_added" not in a  # kev stays CISA-only (cond 3)
    assert a["msrc_severity"] == "Moderate" and a["msrc_impact"] == "Spoofing" and a["msrc_documents"] == ["2026-Nov"]
    assert {"vendor": "Microsoft", "product": "Microsoft 365 Apps for Enterprise for 32-bit Systems"} in a["affected"]
    assert a["vendor_advisories"][0] == "https://msrc.microsoft.com/update-guide/vulnerability/CVE-2026-124194"
    assert a["cvss_scores"][0]["score"] == 6.5 and a["cvss_scores"][0]["source"] == "Microsoft (MSRC)"
    assert not res.findings and "Example Researcher" not in json.dumps(res.raw)  # Acknowledgments never stored


def test_remediations_carry_kbs_fixed_builds_and_supersedence(indexed):
    runtime, _http, _ = indexed
    res = run_module(MsrcPatchTuesday, "cve:CVE-2026-100223", runtime=runtime)
    a = res.attributes
    assert a["msrc_kbs"] == ["KB5132043", "KB5132061"] and a["msrc_exploited"] is False
    fix = next(r for r in a["msrc_remediation"] if r.get("sub_type") == "Security Hotpatch Update")
    assert fix["kb"] == "KB5132043" and fix["fixed_build"] == "10.0.26100.9911" and fix["supersedes"] == ["KB5127648"]
    assert any(f["fixed"] == "10.0.26100.9974" for f in a["fixed_versions"])
    assert "https://catalog.update.microsoft.com/v7/site/Search.aspx?q=KB5132061" in a["vendor_advisories"]
    assert "exploited" not in a and "msrc_priority_line" not in a


def test_kev_listed_cve_keeps_the_microsoft_line_without_the_not_in_kev_note(indexed, monkeypatch):
    runtime, http, _ = indexed
    monkeypatch.setitem(DATASETS["cisa_kev"], "min_bytes", 10)
    monkeypatch.setattr(kev_mod, "KEV_MIN_ENTRIES", 1)
    catalog = {"catalogVersion": "2026.11.25", "count": 1, "vulnerabilities": [{"cveID": "CVE-2026-124194", "dateAdded": "2026-11-20"}]}
    http.add("GET", kev_mod.KEV_FEED_URL, json=catalog)
    assert runtime.data.update("cisa_kev").status == "updated"
    res = run_module(MsrcPatchTuesday, "cve:CVE-2026-124194", runtime=runtime)
    assert res.attributes["msrc_priority_line"] == "Exploited per Microsoft: patch now" and "kev" not in res.attributes


def test_kb_keyword_lists_the_cves_it_fixes(indexed):
    runtime, _http, _ = indexed
    res = run_module(MsrcPatchTuesday, "keyword:KB5132061", runtime=runtime)
    assert res.status is Status.OK and res.attributes["msrc_kb_cves"] == ["CVE-2026-100223", "CVE-2026-119831"]
    assert all(p.relation == "fixes" and p.expand is False for p in res.pivots) and len(res.pivots) == 2
    bare = run_module(MsrcPatchTuesday, "keyword:5126835", runtime=runtime)
    assert bare.attributes["msrc_kb_cves"] == ["CVE-2026-105545"]


def test_product_keyword_searches_the_local_index(indexed):
    runtime, _http, _ = indexed
    res = run_module(MsrcPatchTuesday, "keyword:windows server 2012", runtime=runtime)
    assert res.status is Status.OK and [h["cve"] for h in res.attributes["msrc_search_hits"]] == ["CVE-2026-105545"]
    assert res.pivots[0].relation == "affected_by"
    assert run_module(MsrcPatchTuesday, "keyword:ab", runtime=runtime).status is Status.SKIPPED
    assert run_module(MsrcPatchTuesday, "keyword:solaris%", runtime=runtime).status is Status.EMPTY  # LIKE wildcards escaped


def test_unknown_cve_is_empty_with_the_index_window(indexed):
    runtime, _http, _ = indexed
    res = run_module(MsrcPatchTuesday, "cve:CVE-2026-9999999", runtime=runtime)
    assert res.status is Status.EMPTY and "MSRC index: 1 month documents (2026-Nov..2026-Nov)" in res.error


def test_doctor_reports_window_age_and_disk_usage(indexed):
    runtime, _http, _ = indexed
    result = MsrcPatchTuesday.health_check().selftest(make_ctx(MsrcPatchTuesday, runtime=runtime))
    assert result.status == "ok" and "1 month documents" in result.detail and "MiB on disk" in result.detail


# ------------------------------------------------------------------ parsers
def test_month_ids_and_keywords():
    assert msrc_month_key("2026-Nov") == (2026, 11, "") and msrc_month_key("2017-May-B") == (2017, 5, "B")
    assert msrc_month_key("2018-FEB") == (2018, 2, "") and msrc_month_key("2026-13") is None
    assert (msrc_keyword_kind("KB5066791"), msrc_keyword_kind("5066791"), msrc_keyword_kind("CVE-2026-1"), msrc_keyword_kind("excel")) == (
        "kb", "kb", "text", "text")
    assert msrc_keyword_kind("CVE-2026-12345") == "cve"


def test_updates_list_keeps_only_canonical_document_urls():
    docs = parse_msrc_updates(UPDATES)["documents"]
    assert len(docs) == 10 and all(d["cvrf_url"] == url(d["id"]) for d in docs)
    bad = {"value": [{"ID": "2026-Nov", "CvrfUrl": "https://evil.example/cvrf/2026-Nov"}]}
    assert parse_msrc_updates(bad)["reason"] == "no usable documents"
    assert parse_msrc_updates(b"<!DOCTYPE html><html><head><title>x</title></head></html>")["reason"] == "html instead of JSON"


def test_exploit_status_and_merge_rules():
    status = parse_exploit_status("Publicly Disclosed:No;Exploited:Yes;Latest Software Release:Exploitation Detected")
    assert status["exploited"] is True and status["publicly_disclosed"] is False and status["latest_release"] == "Exploitation Detected"
    merged = msrc_merge_rows([
        {"cve": "CVE-1", "doc_id": "2026-Oct", "exploited": 0, "max_severity": "Important", "first_published": "2026-10-14"},
        {"cve": "CVE-1", "doc_id": "2026-Nov", "exploited": 1, "max_severity": "Critical", "first_published": "2026-11-10"},
    ])
    assert merged["exploited"] is True and merged["max_severity"] == "Critical" and merged["first_published"] == "2026-10-14"
    assert msrc_merge_rows([]) is None


def test_document_parser_refuses_wrong_ids_and_oversized_bodies():
    assert parse_cvrf_document(MONTH, expected_id="2024-Dec")["reason"].startswith("CVRF id")
    assert parse_cvrf_document(b'"Unable to find the specified file."')["reason"].startswith("not a CVRF document")
    from v3lum.modules.vulnerability_cve.msrc_patch_tuesday import check_cvrf_document

    assert check_cvrf_document(MONTH, max_bytes=100).startswith("CVRF document larger")
