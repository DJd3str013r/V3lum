"""csaf_advisories (P354): generic CSAF 2.0 client (provider-metadata -> changes.csv / ROLIE -> documents)
and the offline CVE -> vendor advisory index.

Fixtures in tests/fixtures/csaf_advisories/ (prep batch p3-G08-1, live 2026-11-26): the three vendors'
``*_provider_metadata.json`` (verbatim), ``cisco_changes.csv`` (2,899 unquoted rows -> 7) and
``redhat_changes.csv`` (32,700 quoted rows -> 7), ``siemens_feed.json`` (ROLIE, 877 entries -> 3),
``redhat_doc.json`` / ``siemens_doc.json`` (verbatim, so their published ``.sha256``/``.sha512`` match),
``cisco_doc.json`` (minimised, so its published sha512 is a real mismatch case) and
``cisco_not_found.http.json`` (the HTML 404 page Cisco serves for a missing file and for ``.sha256``).
"""

from __future__ import annotations

from datetime import datetime, timezone
from pathlib import Path

import pytest

from tests.fakes import FakeClock, FakeHttp, make_runtime, module_fixture, run_module
from v3lum.core.entities import EntityType as T
from v3lum.core.models import Opsec, Status
from v3lum.modules.vulnerability_cve import csaf_advisories as mod
from v3lum.modules.vulnerability_cve.csaf_advisories import (
    CSAF_VENDORS,
    MAX_DOCS_PER_SYNC,
    CsafAdvisories,
    index_path,
    join_directory,
    lookup_cve,
    parse_changes_csv,
    parse_csaf_document,
    parse_provider_metadata,
    parse_rolie_feed,
    plan_sync,
    sync_csaf,
    url_allowed,
    verify_hash,
)
from v3lum.modules.vulnerability_cve.g08_offline import JobRefused, open_ro

FIX = Path(__file__).resolve().parents[1] / "fixtures" / "csaf_advisories"
NOW = datetime(2026, 11, 26, 12, 0, tzinfo=timezone.utc)
CISCO_DOC_URL = "https://www.cisco.com/.well-known/csaf/2021/cisco-sa-apache-log4j-qruknebd.json"
REDHAT_DOC_URL = "https://security.access.redhat.com/data/csaf/v2/advisories/2021/rhsa-2021_5138.json"
SIEMENS_DOC_URL = "https://cert-portal.siemens.com/productcert/csaf/ssa-479842.json"


def raw(name: str) -> bytes:
    return (FIX / name).read_bytes()


def fx(name: str):
    return module_fixture("csaf_advisories", name)


def cisco_404() -> dict:
    resp = fx("cisco_not_found.http.json")["response"]
    return {"status": 404, "headers": resp["headers"], "body": resp["body"].encode()}


# ------------------------------------------------------------------ council metadata
def test_metadata_matches_the_council_decision():
    cls = CsafAdvisories
    assert cls.default_enabled is True and cls.terms == "open" and cls.disclosure == "none" and cls.hosts == ()
    assert cls.opsec is Opsec.PASSIVE and cls.trust_tier == "n/a" and cls.shares_input is False
    assert set(cls.sources) == {"cisco.csaf", "siemens.productcert_csaf", "redhat.csaf_advisories"}
    assert cls.accepts == frozenset({T.CVE, T.KEYWORD}) and T.CVE in cls.produces
    assert MAX_DOCS_PER_SYNC == 2000 and mod.MAX_DOC_BYTES == 5_000_000 and mod.EXCERPT_CHARS == 300
    assert set(CSAF_VENDORS) == {"cisco", "siemens", "redhat"}


# ------------------------------------------------------------------ distributions (cond 1/2)
def test_provider_metadata_of_the_three_vendors():
    cisco = parse_provider_metadata(raw("cisco_provider_metadata.json"), CSAF_VENDORS["cisco"])
    assert cisco["canonical_ok"] and cisco["directories"][0]["changes_url"] == CSAF_VENDORS["cisco"]["index_url"]
    siemens = parse_provider_metadata(raw("siemens_provider_metadata.json"), CSAF_VENDORS["siemens"])
    assert any(f["url"] == CSAF_VENDORS["siemens"]["index_url"] and f["tlp"] in ("WHITE", "CLEAR") for f in siemens["rolie_feeds"])
    redhat = parse_provider_metadata(raw("redhat_provider_metadata.json"), CSAF_VENDORS["redhat"])
    sync = {d["url"]: d["sync"] for d in redhat["directories"]}
    assert sync["https://security.access.redhat.com/data/csaf/v2/advisories/"] is True
    assert sync["https://security.access.redhat.com/data/csaf/v2/vex/"] is False  # cond 3: VEX per CVE only
    assert parse_provider_metadata(b"<html>error</html>", CSAF_VENDORS["cisco"]) is None


def test_distributions_off_the_declared_hosts_are_rejected():
    doc = {"canonical_url": "https://evil.example/pm.json", "distributions": [
        {"directory_url": "http://www.cisco.com/.well-known/csaf/"},
        {"directory_url": "https://mirror.example.net/csaf/"},
        {"rolie": {"feeds": [{"url": "https://www.cisco.com.evil.example/feed.json", "tlp_label": "WHITE"}]}},
    ]}
    parsed = parse_provider_metadata(doc, CSAF_VENDORS["cisco"])
    assert not parsed["canonical_ok"] and not parsed["directories"] and not parsed["rolie_feeds"] and len(parsed["rejected"]) == 3


def test_url_rules_keep_documents_on_declared_hosts():
    hosts = ("www.cisco.com",)
    assert url_allowed("https://www.cisco.com/.well-known/csaf/2021/a.json", hosts) == (True, None)
    for bad in ("http://www.cisco.com/a.json", "https://user:pw@www.cisco.com/a.json", "https://www.cisco.com:8443/a.json",
                "https://www.cisco.com/x/../a.json", "https://other.example/a.json"):
        assert url_allowed(bad, hosts)[0] is False
    base = "https://www.cisco.com/.well-known/csaf/"
    assert join_directory(base, "2021/cisco-sa-x.json", hosts) == base + "2021/cisco-sa-x.json"
    for bad in ("https://evil.example/x.json", "../x.json", "2021/x.json?y=1", "/etc/x.json", "2021/../../x.json"):
        assert join_directory(base, bad, hosts) is None


def test_changes_csv_quoted_and_unquoted_newest_first():
    cisco = parse_changes_csv(raw("cisco_changes.csv"))
    redhat = parse_changes_csv(raw("redhat_changes.csv"))
    assert len(cisco["rows"]) == 7 and len(redhat["rows"]) == 7 and cisco["invalid"] == redhat["invalid"] == 0
    assert cisco["rows"][0]["updated"] >= cisco["rows"][-1]["updated"]
    assert redhat["rows"][-1]["path"] == "2021/rhsa-2021_5138.json"
    junk = parse_changes_csv(b"../etc/passwd.json,2026-01-01\nnot-a-row\nhttps://x.example/a.json,2026-01-01\n")
    assert junk["rows"] == [] and junk["invalid"] == 3
    assert parse_changes_csv(b"<!DOCTYPE html><html></html>").get("error")


def test_rolie_feed_entries_stay_on_declared_hosts():
    feed = parse_rolie_feed(raw("siemens_feed.json"), ("cert-portal.siemens.com",))
    assert len(feed["entries"]) == 3 and not feed["rejected"]
    assert all(e["url"].startswith("https://cert-portal.siemens.com/") for e in feed["entries"])
    assert all(e["hash_url"] and e["hash_url"].endswith(".sha512") for e in feed["entries"])
    elsewhere = parse_rolie_feed(raw("siemens_feed.json"), ("other.example",))
    assert not elsewhere["entries"] and len(elsewhere["rejected"]) == 3


def test_plan_is_incremental_newest_first_and_capped():
    items = [{"url": f"https://h/{i}.json", "updated": f"2026-11-{i:02d}T00:00:00Z"} for i in range(1, 11)]
    known = {"https://h/10.json": "2026-11-10T00:00:00Z"}
    plan = plan_sync(items, known, max_docs=3)
    assert [i["url"] for i in plan["fetch"]] == ["https://h/9.json", "https://h/8.json", "https://h/7.json"]
    assert plan["deferred"] == 6 and plan["unchanged"] == 1


# ------------------------------------------------------------------ hashes (cond 2)
def test_published_hashes_are_checked():
    assert verify_hash(raw("redhat_doc.json"), raw("redhat_doc_sha256.txt"), REDHAT_DOC_URL)["ok"] is True
    assert verify_hash(raw("siemens_doc.json"), raw("siemens_doc_sha512.txt"), SIEMENS_DOC_URL)["ok"] is True
    mismatch = verify_hash(raw("cisco_doc.json"), raw("cisco_doc_sha512.txt"), CISCO_DOC_URL)  # minimised fixture
    assert mismatch["ok"] is False and "mismatch" in mismatch["reason"]
    other = verify_hash(raw("redhat_doc.json"), raw("redhat_doc_sha256.txt"), "https://h/2021/rhsa-2021_0001.json")
    assert other["ok"] is False and "names" in other["reason"]
    assert verify_hash(raw("cisco_doc.json"), cisco_404()["body"])["ok"] is None  # HTML 404: hash not published


# ------------------------------------------------------------------ documents (cond 1/4)
def test_documents_keep_vendor_urls_licence_and_excerpts():
    rh = parse_csaf_document(raw("redhat_doc.json"), "redhat", REDHAT_DOC_URL)
    assert rh["advisory_id"] == "RHSA-2021:5138" and "CVE-2021-44228" in rh["cves"]
    assert rh["canonical_url"].startswith("https://access.redhat.com/errata/") and rh["distribution_url"] == REDHAT_DOC_URL
    assert rh["licence"] == "CC BY 4.0" and "Creative Commons Attribution 4.0" in rh["legal_note_excerpt"]
    vuln = next(v for v in rh["vulnerabilities"] if v["cve"] == "CVE-2021-44228")
    assert vuln["fixed_versions"] and vuln["cvss"] and vuln["exploitation"]
    assert all(len(v["excerpt"] or "") <= 304 for v in rh["vulnerabilities"])
    cisco = parse_csaf_document(raw("cisco_doc.json"), "cisco", CISCO_DOC_URL)
    assert cisco["advisory_id"].startswith("cisco-sa-apache-log4j") and "uncontrolled copy" in cisco["legal_note_excerpt"]
    assert cisco["distribution_url"] == CISCO_DOC_URL
    siemens = parse_csaf_document(raw("siemens_doc.json"), "siemens", SIEMENS_DOC_URL)
    assert siemens["advisory_id"] == "SSA-479842" and siemens["cves"]
    assert any(f["how"] in ("product_status fixed", "remediation text", "affected range upper bound")
               for v in siemens["vulnerabilities"] for f in v["fixed_versions"])


def test_documents_are_refused_when_off_host_too_large_or_not_csaf():
    assert "declared host" in parse_csaf_document(raw("redhat_doc.json"), "redhat", "https://evil.example/x.json")["error"]
    assert "cap" in parse_csaf_document(b"{" + b" " * 60, "redhat", REDHAT_DOC_URL, max_bytes=50)["error"]
    assert "not a CSAF" in parse_csaf_document({"document": {}}, "redhat")["error"]
    assert parse_csaf_document(b"<html>404</html>", "cisco")["error"]


# ------------------------------------------------------------------ the sync job (cond 1/2/3)
def sync_http(*, cisco_hash: bytes | None = None) -> FakeHttp:
    http = FakeHttp()
    http.add("GET", CSAF_VENDORS["cisco"]["provider_metadata_url"], body=raw("cisco_provider_metadata.json"),
             headers={"content-type": "application/json"})
    http.add("GET", CSAF_VENDORS["cisco"]["index_url"], body=raw("cisco_changes.csv"), headers={"content-type": "text/csv"})
    base = "https://www.cisco.com/.well-known/csaf/"
    for row in parse_changes_csv(raw("cisco_changes.csv"))["rows"]:
        url = base + row["path"]
        if url == CISCO_DOC_URL:
            http.add("GET", url, body=raw("cisco_doc.json"), headers={"content-type": "application/json"})
            if cisco_hash is None:
                http.add("GET", url + ".sha512", body=raw("cisco_doc_sha512.txt"))
            else:
                http.add("GET", url + ".sha512", **({"body": cisco_hash} if cisco_hash else cisco_404()))
        else:
            http.add("GET", url, **cisco_404())
    http.add("GET", CSAF_VENDORS["redhat"]["provider_metadata_url"], body=raw("redhat_provider_metadata.json"),
             headers={"content-type": "application/json"})
    http.add("GET", CSAF_VENDORS["redhat"]["index_url"], body=raw("redhat_changes.csv"), headers={"content-type": "text/csv"})
    rbase = "https://security.access.redhat.com/data/csaf/v2/advisories/"
    for row in parse_changes_csv(raw("redhat_changes.csv"))["rows"]:
        url = rbase + row["path"]
        if url == REDHAT_DOC_URL:
            http.add("GET", url, body=raw("redhat_doc.json"), headers={"content-type": "application/json"})
            http.add("GET", url + ".sha256", body=raw("redhat_doc_sha256.txt"))
        else:
            http.add("GET", url, status=404, text="<?xml version='1.0'?><Error><Code>NoSuchKey</Code></Error>")
    http.add("GET", CSAF_VENDORS["siemens"]["provider_metadata_url"], body=raw("siemens_provider_metadata.json"),
             headers={"content-type": "application/json"})
    http.add("GET", CSAF_VENDORS["siemens"]["index_url"], body=raw("siemens_feed.json"), headers={"content-type": "application/json"})
    for entry in parse_rolie_feed(raw("siemens_feed.json"), ("cert-portal.siemens.com",))["entries"]:
        if entry["url"] == SIEMENS_DOC_URL:
            http.add("GET", entry["url"], body=raw("siemens_doc.json"), headers={"content-type": "application/json"})
            http.add("GET", entry["hash_url"], body=raw("siemens_doc_sha512.txt"))
        else:
            http.add("GET", entry["url"], status=404, text="<?xml version='1.0'?><Error><Code>AccessDenied</Code></Error>")
    return http


@pytest.fixture
def synced():
    http = sync_http(cisco_hash=b"")  # Cisco: no hash published for the minimised document
    runtime = make_runtime(http, clock=FakeClock(NOW))
    summary = sync_csaf(runtime, doc_interval=0.0, lookback_years={"redhat": None})  # include the 2021 log4j advisory
    return runtime, http, summary


def test_sync_indexes_documents_with_hashes_and_stays_on_declared_hosts(synced):
    _runtime, http, summary = synced
    vendors = summary["vendors"]
    assert vendors["redhat"]["indexed"] == 1 and vendors["redhat"]["hash"] == {"verified sha256": 1}
    assert vendors["siemens"]["indexed"] == 1 and vendors["siemens"]["hash"] == {"verified sha512": 1}
    assert vendors["cisco"]["indexed"] == 1 and vendors["cisco"]["hash"] == {"hash not published": 1}
    assert vendors["redhat"]["missing"] == 6 and vendors["cisco"]["missing"] == 6 and vendors["siemens"]["missing"] == 2
    assert {u.split("/")[2] for u in http.urls()} == {"www.cisco.com", "security.access.redhat.com", "cert-portal.siemens.com"}
    assert not any("/vex/" in u for u in http.urls())  # cond 3: VEX never bulk-synced
    assert all(c["method"] == "GET" for c in http.calls)
    assert oct(index_path().stat().st_mode & 0o777) == "0o600"
    con = open_ro(index_path())
    try:
        vendors_of_log4j = {r["vendor"] for r in lookup_cve(con, "CVE-2021-44228")}
    finally:
        con.close()
    assert vendors_of_log4j == {"cisco", "redhat", "siemens"}
    assert "CSAF index: cisco, redhat, siemens synced 2026-11-26" in summary["line"]


def test_hash_mismatch_refuses_the_document():
    runtime = make_runtime(sync_http(), clock=FakeClock(NOW))
    summary = sync_csaf(runtime, vendors=["cisco"], doc_interval=0.0)
    cisco = summary["vendors"]["cisco"]
    assert cisco["indexed"] == 0 and cisco["status"] == "partial" and "mismatch" in cisco["refused"][0]["why"]


def test_second_sync_skips_unchanged_documents(synced):
    runtime, http, _ = synced
    before = len(http.calls)
    again = sync_csaf(runtime, vendors=["redhat"], doc_interval=0.0, lookback_years={"redhat": None})
    assert again["vendors"]["redhat"]["planned"] == 0 and again["vendors"]["redhat"]["unchanged"] == 7
    assert not [c for c in http.calls[before:] if c["url"].endswith((".json", ".sha256")) and "provider-metadata" not in c["url"]]


def test_document_cap_defers_the_rest():
    runtime = make_runtime(sync_http(cisco_hash=b""), clock=FakeClock(NOW))
    summary = sync_csaf(runtime, vendors=["redhat"], max_docs=2, doc_interval=0.0, lookback_years={"redhat": None})
    assert summary["vendors"]["redhat"]["planned"] == 2 and summary["vendors"]["redhat"]["deferred"] == 5


def test_red_hat_lookback_window_skips_old_paths():
    runtime = make_runtime(sync_http(cisco_hash=b""), clock=FakeClock(NOW))
    summary = sync_csaf(runtime, vendors=["redhat"], doc_interval=0.0)  # configured window: 2 path years
    assert summary["vendors"]["redhat"]["outside_lookback"] == 1 and summary["vendors"]["redhat"]["planned"] == 6


def test_blocked_document_stops_the_vendor_as_could_not_verify():
    http = sync_http(cisco_hash=b"")
    http.routes.clear()
    http.add("GET", CSAF_VENDORS["redhat"]["provider_metadata_url"], body=raw("redhat_provider_metadata.json"),
             headers={"content-type": "application/json"})
    http.add("GET", CSAF_VENDORS["redhat"]["index_url"], body=raw("redhat_changes.csv"), headers={"content-type": "text/csv"})
    http.add("GET", "https://security.access.redhat.com/data/csaf/v2/advisories/2026/*", status=429, text="slow down")
    summary = sync_csaf(make_runtime(http, clock=FakeClock(NOW)), vendors=["redhat"], doc_interval=0.0)
    assert summary["vendors"]["redhat"]["status"] == "partial" and "could not verify" in summary["vendors"]["redhat"]["reason"]


def test_failed_metadata_download_is_an_error_and_other_vendors_continue():
    http = sync_http(cisco_hash=b"")
    http.routes.clear()
    http.add("GET", CSAF_VENDORS["cisco"]["provider_metadata_url"], status=503, text="down", times=5)
    http.add("GET", CSAF_VENDORS["siemens"]["provider_metadata_url"], body=raw("siemens_provider_metadata.json"),
             headers={"content-type": "application/json"})
    http.add("GET", CSAF_VENDORS["siemens"]["index_url"], body=raw("siemens_feed.json"), headers={"content-type": "application/json"})
    http.add("GET", "https://cert-portal.siemens.com/productcert/csaf/*", status=404, text="<Error><Code>NoSuchKey</Code></Error>")
    summary = sync_csaf(make_runtime(http, clock=FakeClock(NOW)), vendors=["cisco", "siemens"], doc_interval=0.0)
    assert summary["vendors"]["cisco"]["status"] == "error" and "could not verify" in summary["vendors"]["cisco"]["reason"]
    assert summary["vendors"]["siemens"]["status"] == "ok" and summary["status"] == "partial"


def test_sync_is_refused_inside_a_scan():
    runtime = make_runtime(FakeHttp(), clock=FakeClock(NOW))
    runtime.in_scan = True
    with pytest.raises(JobRefused, match="inside a scan"):
        sync_csaf(runtime)


# ------------------------------------------------------------------ the module (offline lookups)
def test_without_an_index_the_module_is_unavailable():
    res = run_module(CsafAdvisories, "cve:CVE-2021-44228", FakeHttp())
    assert res.status is Status.UNAVAILABLE and res.reason_code == "dataset" and "sync" in res.error


def test_cve_lookup_feeds_the_vendor_fix_line_with_excerpts_and_links(synced):
    runtime, _http, _ = synced
    res = run_module(CsafAdvisories, "cve:CVE-2021-44228", runtime=runtime)
    assert res.status is Status.OK, res.error
    assert res.requests == 0  # offline: nothing is sent at lookup time
    a = res.attributes
    vendors = {adv["vendor"] for adv in a["csaf_advisories"]}
    assert vendors == {"cisco", "redhat", "siemens"}
    cisco = next(adv for adv in a["csaf_advisories"] if adv["vendor"] == "cisco")
    assert cisco["distribution_url"] == CISCO_DOC_URL and cisco["hash"] == "hash not published"
    assert all(len(adv.get("excerpt") or "") <= 304 for adv in a["csaf_advisories"])
    assert a["fixed_versions"] and all(f["product"].split(":")[0] in ("Cisco PSIRT", "Siemens ProductCERT", "Red Hat Product Security")
                                       for f in a["fixed_versions"])
    assert any(c["source"] == "Red Hat Product Security CSAF" for c in a["cvss_scores"])
    assert any("uncontrolled copy" in n for n in a["data_notices"]) and any("CC BY 4.0" in n for n in a["data_notices"])
    assert a["csaf_index"]["vendors"]["redhat"]["documents"] == 1
    assert "kev" not in a and "exploited" not in a  # vendor exploitation notes stay text
    assert any(label.startswith("redhat RHSA-2021:5138") for label, _ in res.links)


def test_licence_narrowed_sources_drop_that_vendor(synced):
    runtime, _http, _ = synced
    res = run_module(CsafAdvisories, "cve:CVE-2021-44228", runtime=runtime, allowed_sources=frozenset({"redhat.csaf_advisories"}))
    assert {adv["vendor"] for adv in res.attributes["csaf_advisories"]} == {"redhat"}


def test_absent_cve_is_empty_from_a_present_index(synced):
    runtime, _http, _ = synced
    res = run_module(CsafAdvisories, "cve:CVE-2020-0001", runtime=runtime)
    assert res.status is Status.EMPTY and "local index" in res.error


def test_keyword_lists_cves_of_matching_advisories(synced):
    runtime, _http, _ = synced
    res = run_module(CsafAdvisories, "keyword:log4j", runtime=runtime)
    assert res.status is Status.OK
    assert "CVE-2021-44228" in {p.entity.value for p in res.pivots}
    assert all(p.relation == "affected_by" for p in res.pivots)
    assert run_module(CsafAdvisories, "keyword:zz", runtime=runtime).status is Status.SKIPPED
    assert run_module(CsafAdvisories, "keyword:nonexistentproductxyz", runtime=runtime).status is Status.EMPTY


def test_selftest_reports_index_age(synced):
    runtime, _http, _ = synced
    check = CsafAdvisories.health_check()
    assert check.offline is True
    from tests.fakes import make_ctx

    result = check.selftest(make_ctx(CsafAdvisories, runtime=runtime, clock=FakeClock(NOW)))
    assert result.status == "ok" and "CSAF index" in result.detail
