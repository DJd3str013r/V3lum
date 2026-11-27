"""orkl (P293): public CTI reports from the ORKL library search.

Fixtures in tests/fixtures/orkl/ (prep batch p2-G11-1, captured 2026-11-26 from orkl.eu, minimised;
researcher names replaced by documentation values, ``files`` links kept to prove they are never used):
``ok.json`` (CVE-2021-44228, 3 reports), ``empty.json`` (``data: null``), ``fuzzy_only.json`` (a
non-existent CVE: 3 unrelated hits), ``actor_search_ok.json`` (Lazarus), ``entry_ok.json`` (one entry with
its plain text, truncated), ``error_406.http.json`` (the real error envelope of an empty query),
``error_in_200.json`` (the same envelope without its status) and ``malformed.txt`` (a cut JSON body).
"""

from __future__ import annotations

import subprocess

import pytest

from tests.fakes import FIXTURES, FakeHttp, module_fixture, run_module
from v3lum.core import providers
from v3lum.core.entities import EntityType as T
from v3lum.core.models import Severity, Status
from v3lum.modules.cti_framework import orkl as mod
from v3lum.modules.cti_framework.orkl import (
    ENTRY_URL,
    SEARCH_URL,
    Orkl,
    orkl_relevance,
    parse_search,
    report_date,
    search_params,
)

CVE = "CVE-2021-44228"


def search_url(query: str, limit: int = 10) -> str:
    return f"{SEARCH_URL}?query={query}&limit={limit}"


def fx(name: str):
    return module_fixture(Orkl, name)


# ------------------------------------------------------------------ metadata (council values, FC1/FC2/FC3)
def test_metadata_matches_the_council_decision():
    cls = Orkl
    assert cls.terms == "unknown" and cls.default_enabled is False  # FC1
    assert cls.trust_tier == "unknown" and cls.max_tlp.value_str == "green"  # FC2: excluded at AMBER+
    assert cls.disclosure == "third_party" and cls.hosts == ("orkl.eu",) and cls.sources == ("orkl.library",)
    assert cls.min_interval == 1.0 and cls.cache_ttl == 7 * 86400 and cls.opsec.label == "passive"  # FC3
    assert T.ORG not in cls.accepts and T.KEYWORD not in cls.accepts  # victim/company names never sent
    assert search_params("cve-2021-44228", 50) == {"query": CVE, "limit": 10}  # limit <= 10, stable key
    assert search_params("T1059.001", 0)["limit"] == 1


# ------------------------------------------------------------------ happy path (FC4)
def test_reports_are_links_most_recent_first_and_archive_files_never_used():
    http = FakeHttp().add("GET", search_url(CVE), json=fx("ok.json"))
    res = run_module(Orkl, f"cve:{CVE}", http)
    assert res.status is Status.OK
    reports = res.attributes["cti_reports"]
    assert [r["date"] for r in reports] == ["2026-04-06", "2021-12-15", "2021-12-10"]
    first = reports[1]
    assert first["publisher"] == "Zscaler ThreatLabz" and first["date_source"] == "title"
    assert first["url"].startswith("https://www.zscaler.com/")  # the publisher page wins over the PDF mirror
    assert reports[0]["date_source"] == "orkl_added"  # 0001-01-01 file date = unknown
    assert res.attributes["cti_report_count"] == 3
    assert all("archive.orkl.eu" not in str(v) for v in (res.attributes, res.links, [p.entity.value for p in res.pivots]))
    assert len(res.links) == 3 and all(url.startswith("https://") for _label, url in res.links)
    assert {p.relation for p in res.pivots} == {"reported_in"} and not any(p.expand for p in res.pivots)
    assert res.findings[0].severity is Severity.INFO and "context_only" in res.findings[0].tags
    assert http.urls() == [search_url(CVE)]  # one request; FC5 is opt-in
    http.assert_hosts_within(Orkl)


def test_terminal_links_are_capped_at_five():
    doc = fx("ok.json")
    entries = []
    for i in range(8):
        e = dict(doc["data"][1], id=f"id-{i}", created_at=f"2026-0{i + 1}-01T00:00:00Z",
                 references=[f"https://example.com/report-{i}"])
        entries.append(e)
    http = FakeHttp().add("GET", search_url(CVE), json={"data": entries, "message": "", "status": "success"})
    res = run_module(Orkl, f"cve:{CVE}", http)
    assert len(res.links) == 5 and len(res.attributes["cti_reports"]) == 8
    assert res.links[0][1] == "https://example.com/report-7"  # most recent first


def test_fuzzy_hits_are_never_shown_as_matches():
    http = FakeHttp().add("GET", search_url("CVE-2099-99999"), json=fx("fuzzy_only.json"))
    res = run_module(Orkl, "cve:CVE-2099-99999", http)
    assert res.status is Status.EMPTY
    assert res.attributes["cti_reports_fuzzy_dropped"] == 3 and "cti_reports" not in res.attributes
    assert "fuzzy" in res.error and not res.links and not res.pivots
    # digit boundary: CVE-2021-1732 never matches CVE-2021-17321
    entry = fx("fuzzy_only.json")["data"][2]
    assert orkl_relevance(entry, "CVE-2021-1732", T.CVE) == "exact"
    assert orkl_relevance(entry, "CVE-2021-173", T.CVE) == "fuzzy"


def test_empty_result_is_empty():
    http = FakeHttp().add("GET", search_url(CVE), json=fx("empty.json"))
    res = run_module(Orkl, f"cve:{CVE}", http)
    assert res.status is Status.EMPTY and "no ORKL report" in res.error


# ------------------------------------------------------------------ FC2 input gate
def test_actor_and_malware_names_wait_for_a_recorded_promotion():
    http = FakeHttp()
    for value in ("threat_actor:Lazarus Group", "malware_family:Kinsing"):
        res = run_module(Orkl, value, http)
        assert res.status is Status.SKIPPED and res.reason_code == "tier"
    assert http.calls == []  # nothing left the machine


def test_promoted_provider_receives_actor_names(monkeypatch):
    monkeypatch.setattr(mod, "provider_promoted", lambda: True)
    http = FakeHttp().add("GET", search_url("Lazarus Group"), json=fx("actor_search_ok.json"))
    res = run_module(Orkl, "threat_actor:Lazarus Group", http)
    assert res.status is Status.OK  # exact match through the threat_actors main name
    assert res.attributes["cti_reports"][0]["publisher"] == "Socket"
    assert "Lazarus Group" in res.attributes["cti_reports"][0]["actors"]


def test_promotion_is_read_from_the_registry():
    assert mod.provider_promoted() is False  # shipped fragment: tier unknown
    assert providers.registry().get("orkl").tier == "unknown"


# ------------------------------------------------------------------ rule 5 and error envelopes (FC3)
def test_error_envelope_in_http_200_is_error():
    http = FakeHttp().add("GET", search_url(CVE), json=fx("error_in_200.json"))
    res = run_module(Orkl, f"cve:{CVE}", http)
    assert res.status is Status.ERROR and res.status is not Status.EMPTY


def test_other_non_success_status_is_error():
    http = FakeHttp().add("GET", search_url(CVE), json={"data": [], "message": "busy", "status": "fail"})
    res = run_module(Orkl, f"cve:{CVE}", http)
    assert res.status is Status.ERROR and "status=fail" in res.error


def test_real_406_error_envelope_is_error():
    cap = fx("error_406.http.json")
    http = FakeHttp().add("GET", search_url(CVE), status=cap["status"], text=cap["body"], headers=cap["headers"])
    assert run_module(Orkl, f"cve:{CVE}", http).status is Status.ERROR


def test_malformed_json_is_error_never_empty():
    body = (FIXTURES / "orkl" / "malformed.txt").read_text(encoding="utf-8")
    http = FakeHttp().add("GET", search_url(CVE), text=body, headers={"Content-Type": "application/json"})
    res = run_module(Orkl, f"cve:{CVE}", http)
    assert res.status is Status.ERROR


def test_wrong_types_are_error():
    http = FakeHttp().add("GET", search_url(CVE), json=["not", "an", "object"])
    assert run_module(Orkl, f"cve:{CVE}", http).status is Status.ERROR
    assert parse_search({"data": "x", "status": "success"}, CVE)["status"] == "error"


@pytest.mark.parametrize("status,expected", [(429, Status.RATE_LIMITED), (403, Status.BLOCKED), (503, Status.ERROR)])
def test_could_not_verify_statuses(status, expected):
    http = FakeHttp().add("GET", search_url(CVE), status=status, text="nope", times=3)
    res = run_module(Orkl, f"cve:{CVE}", http)
    assert res.status is expected


def test_challenge_page_is_blocked():
    page = "<html><head><title>Just a moment...</title></head><body>cf-chl-widget</body></html>"
    http = FakeHttp().add("GET", search_url(CVE), status=403, text=page)
    assert run_module(Orkl, f"cve:{CVE}", http).status is Status.BLOCKED


def test_timeout_is_error():
    http = FakeHttp().add("GET", search_url(CVE), error=TimeoutError("timed out"), times=3)
    res = run_module(Orkl, f"cve:{CVE}", http)
    assert res.status is Status.ERROR


# ------------------------------------------------------------------ FC5 opt-in report IOCs
def test_report_iocs_are_opt_in_truncated_warninglisted_and_never_verdicts():
    entry_id = "331bc752-906a-4fc5-beda-0c82b139dd42"
    http = (FakeHttp().add("GET", search_url(CVE), json=fx("ok.json"))
            .add("GET", ENTRY_URL.format(id=entry_id), json=fx("entry_ok.json"))
            .add("GET", ENTRY_URL.format(id="9d622232-48b4-4a1d-85f9-cd0d86769ebd"), json=fx("empty.json"))
            .add("GET", ENTRY_URL.format(id="092c0b06-3e3b-409b-ad92-32b0ad53e0ef"), json=fx("error_in_200.json")))
    res = run_module(Orkl, f"cve:{CVE}", http, settings={"orkl_report_iocs": True})
    assert res.status is Status.OK
    iocs = [p for p in res.pivots if p.relation == "co_mentioned_in_report"]
    values = {p.entity.value for p in iocs}
    assert "45.155.205.233" in values and "lurchmath.org" in values  # refanged
    assert "8.8.8.8" not in values and "google.com" not in values  # benign examples: warninglisted (P169)
    assert CVE not in values  # the queried value itself is never re-emitted
    assert all(not p.expand and p.confidence_label == "possible" for p in iocs)
    assert all("from report" in p.note and "(2021-12-15)" in p.note and "never a verdict" in p.note for p in iocs if "45.155" in p.entity.value)
    assert not [f for f in res.findings if f.severity is not Severity.INFO]  # never a verdict
    summary = {row["report"][:10]: row for row in res.attributes["report_iocs"]}
    mined = summary["2021-12-15"]
    assert mined["iocs"] > 0 and mined["warninglisted"] >= 2 and mined["truncated"] is False
    assert "error" in summary["Logs of Lo"] and "error" in summary["2021-12-10"]  # error envelopes reported, not mined


def test_report_text_is_truncated_before_extraction():
    rep = {"title": "T", "date": "2026-01-01"}
    text = "x " * 15000 + " 45.155.205.233 "
    out = mod.report_iocs(text, rep, query=mod.Entity.make(T.CVE, CVE))
    assert out["truncated"] is True and out["chars_scanned"] == mod.TEXT_CAP and out["iocs"] == []


def test_report_iocs_fail_closed_without_warninglists(monkeypatch):
    monkeypatch.setattr(mod, "warninglist_drop", lambda entity: None)
    rep = {"title": "T", "date": "2026-01-01"}
    out = mod.report_iocs("C2 at 45.155.205.233 and evil-example.org", rep, query=mod.Entity.make(T.CVE, CVE))
    assert out["failed_closed"] is True and out["iocs"] == []


def test_dates_and_relevance_helpers():
    assert report_date({"title": "x", "file_creation_date": "0001-01-01T00:00:00Z", "created_at": "2026-04-06T00:11:08.1Z"}) == ("2026-04-06", "orkl_added")
    assert report_date({"title": "2021-12-10 - X"}) == ("2021-12-10", "title")


def test_module_never_spawns_a_process(monkeypatch):
    def boom(*a, **k):
        raise AssertionError("no process may be spawned")
    monkeypatch.setattr(subprocess, "Popen", boom)
    http = FakeHttp().add("GET", search_url(CVE), json=fx("ok.json"))
    assert run_module(Orkl, f"cve:{CVE}", http).status is Status.OK
