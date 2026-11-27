"""ransomware_matrices (P372): BushidoUK Tool Matrix + Vulnerability Matrix, offline joins.

Fixtures in tests/fixtures/ransomware_matrices/ (prep batch p2-G11-1 and p2-G11-1 downloads of 2026-11-26
from raw.githubusercontent.com, CC BY 4.0, trimmed to a few rows per table): one file per matrix file
(``rtm_*_ok.md``, ``rtm_alltools_ok.csv``, ``rvm_*_ok.md``), the derived ``rvm_changed_layout.md`` (an extra
'Notes' column and a renamed 'CVE' header), ``rtm_alltools_changed_layout.csv``, ``rvm_no_group_row.md``
(the Kaseya row with its group cell emptied), the real 304 answer and a KEV catalogue slice (8 real
entries, ``count`` rewritten to 8, ``notes`` dropped).
"""

from __future__ import annotations

import subprocess

import pytest

from tests.fakes import FIXTURES, FakeClock, FakeHttp, make_runtime, module_fixture, run_module
from v3lum.core.datasets import DATASETS
from v3lum.core.models import Severity, Status
from v3lum.modules.cti_framework import ransomware_matrices as mod
from v3lum.modules.cti_framework.ransomware_matrices import (
    DATASET_ALLTOOLS,
    DATASETS_RTM,
    DATASETS_RVM,
    MATRIX_ATTRIBUTION,
    RVM_SOURCE,
    RansomwareMatrices,
    build_cve_index,
    parse_alltools_csv,
    parse_group_cell,
    parse_tool_matrix_md,
    parse_vuln_matrix,
    ransomware_cve_card,
)
from v3lum.modules.vulnerability_cve import cisa_kev as kev_mod
from v3lum.modules.vulnerability_cve.cisa_kev import KEV_DATASET, KEV_FEED_URL

FX = FIXTURES / "ransomware_matrices"
FIXTURE_OF = {
    **{name: f"rtm_{name.rsplit('.', 1)[1].replace('_', '')}_ok.md" for name in DATASETS_RTM},
    DATASET_ALLTOOLS: "rtm_alltools_ok.csv",
    **{name: f"rvm_{name.rsplit('.', 1)[1]}_ok.md" for name in DATASETS_RVM},
}
FIXTURE_OF["ransomware_matrices.rtm.rmm_tools"] = "rtm_rmm_tools_ok.md"


@pytest.fixture(autouse=True)
def small_kev(monkeypatch):
    """The KEV slice holds 8 entries: lower the cisa_kev completeness floors (tested in test_cisa_kev)."""
    monkeypatch.setitem(DATASETS[KEV_DATASET], "min_bytes", 100)
    monkeypatch.setattr(kev_mod, "KEV_MIN_ENTRIES", 1)
    mod._MEMO.update(key=None, index=None)
    mod._REJECTED.clear()


def text(name: str) -> str:
    return (FX / name).read_text(encoding="utf-8")


def matrix_http(overrides: dict[str, str] | None = None, *, kev: bool = True, times: int | None = None) -> FakeHttp:
    http = FakeHttp()
    for name, fixture in FIXTURE_OF.items():
        body = text((overrides or {}).get(name, fixture))
        etag = f'W/"{name}"'
        http.add("GET", DATASETS[name]["url"], text=body, headers={"Content-Type": "text/plain; charset=utf-8", "ETag": etag}, times=times)
    if kev:
        http.add("GET", KEV_FEED_URL, json=module_fixture(RansomwareMatrices, "kev_slice.json"), times=times)
    return http


# ------------------------------------------------------------------ metadata (FC1, FC6)
def test_metadata_matches_the_council_decision():
    cls = RansomwareMatrices
    assert cls.default_enabled is True and cls.terms == "open" and cls.disclosure == "none" and cls.hosts == ()
    assert cls.trust_tier == "n/a" and cls.max_tlp.value_str == "red" and cls.max_requests == 0
    assert len(DATASETS_RTM) == 8 and len(DATASETS_RVM) == 8
    for name in [*DATASETS_RTM, DATASET_ALLTOOLS, *DATASETS_RVM]:
        reg = DATASETS[name]
        assert reg["ttl"] == 7 * 86400 and reg["licence"] == "CC-BY-4.0" and reg["terms_class"] == "open"
        assert reg["url"].startswith("https://raw.githubusercontent.com/BushidoUK/") and reg["attribution"] == MATRIX_ATTRIBUTION


# ------------------------------------------------------------------ FC2 parsing
def test_every_real_fixture_parses():
    for name, fixture in FIXTURE_OF.items():
        if name == DATASET_ALLTOOLS:
            assert parse_alltools_csv(text(fixture))["status"] == "ok"
        elif name in DATASETS_RTM:
            assert parse_tool_matrix_md(text(fixture), fixture)["status"] == "ok", fixture
        else:
            assert parse_vuln_matrix(text(fixture), fixture)["status"] == "ok", fixture


def test_changed_layout_is_format_changed_never_empty():
    res = parse_vuln_matrix(text("rvm_changed_layout.md"), "RMM_Tools.md")
    assert res["status"] == "error" and res["reason"].startswith("format changed: unexpected table header")
    csv_res = parse_alltools_csv(text("rtm_alltools_changed_layout.csv"))
    assert csv_res["status"] == "error" and "format changed" in csv_res["reason"]
    assert parse_vuln_matrix("no table here", "x.md")["reason"].startswith("format changed: no Markdown table")


def test_group_cell_markers_and_candidates():
    groups = {g["name"]: g for g in parse_group_cell("Pioneer Kitten+, *Br0k3r, Scattered Spider*, Storm-2603 (Warlock), Ghost/Cring, n/a")}
    assert groups["Pioneer Kitten"]["role"] == "state_sponsored"
    assert groups["Br0k3r"]["role"] == "initial_access_broker" and groups["Scattered Spider"]["role"] == "affiliate"
    assert groups["Storm-2603"]["candidates"] == ["Storm-2603", "Warlock"]
    assert groups["Ghost/Cring"]["candidates"] == ["Ghost/Cring", "Ghost", "Cring"]
    assert "n/a" not in groups


# ------------------------------------------------------------------ FC5 CVE cards
def test_cve_with_groups_and_kev_known_is_highest_priority():
    res = run_module(RansomwareMatrices, "cve:CVE-2024-1709", matrix_http())
    assert res.status is Status.OK
    card = res.attributes["ransomware_cve_card"]
    assert card["label"].startswith("reported exploited by ransomware groups BlackBasta, Cicada3301")
    assert card["status"] == "reported" and card["kev_known_ransomware_use"] == "Known"
    assert res.attributes["patch_priority"] == "highest"
    assert any(s["url"].startswith("https://www.cisa.gov/") for s in card["sources"])
    finding = res.findings[0]
    assert finding.severity is Severity.MEDIUM and finding.criterion and "kev" in finding.tags
    assert MATRIX_ATTRIBUTION in finding.description and res.attributes["data_attribution"] == MATRIX_ATTRIBUTION
    assert res.links and res.requests == 0
    assert {d["name"] for d in res.datasets} >= {KEV_DATASET, "ransomware_matrices.rvm.rmm_tools"}


def test_cve_without_kev_ransomware_use_is_raised():
    res = run_module(RansomwareMatrices, "cve:CVE-2025-59718", matrix_http())
    assert res.attributes["patch_priority"] == "raised" and res.findings[0].severity is Severity.LOW
    assert res.attributes["ransomware_cve_card"]["kev_known_ransomware_use"] == "Unknown"
    assert res.attributes["ransomware_groups_unresolved"] == ["Qilin"]  # listed, never guessed (FC3)


def test_row_without_group_stays_reported():
    http = matrix_http({"ransomware_matrices.rvm.rmm_tools": "rvm_no_group_row.md"})
    res = run_module(RansomwareMatrices, "cve:CVE-2021-30116", http)
    card = res.attributes["ransomware_cve_card"]
    assert card["label"] == "reported exploited by ransomware (no group named in the source row)" and card["status"] == "reported"
    assert res.attributes["patch_priority"] == "normal" and res.findings[0].severity is Severity.INFO


def test_kev_only_card_and_absent_cve():
    res = run_module(RansomwareMatrices, "cve:CVE-2021-44228", matrix_http())  # KEV Known, not in the trimmed matrix
    assert res.attributes["patch_priority"] == "raised" and "not in the ransomware matrix" in res.attributes["ransomware_cve_card"]["label"]
    absent = run_module(RansomwareMatrices, "cve:CVE-2000-0001", matrix_http())
    assert absent.status is Status.EMPTY and "not exhaustive" in absent.error


def test_kev_unavailable_is_reported_per_source():
    res = run_module(RansomwareMatrices, "cve:CVE-2024-1709", matrix_http(kev=False).add("GET", KEV_FEED_URL, status=503, text="down", times=3))
    assert res.status is Status.OK and res.attributes["patch_priority"] == "raised"
    assert "cisa.kev" in res.source_statuses


def test_cve_card_helper():
    idx = build_cve_index(parse_vuln_matrix(text("rvm_networkedge_ok.md"), "n")["rows"])
    card = ransomware_cve_card("CVE-2024-21887", idx, {"ransomware_use": "Known", "ransomware_known": True})
    assert card["patch_priority"] == "highest" and card["groups"] == ["Pioneer Kitten", "DragonForce"]
    assert ransomware_cve_card("CVE-2024-21887", idx, None)["patch_priority"] == "raised"
    assert ransomware_cve_card("CVE-1999-0001", idx, {"ransomware_use": "Unknown", "ransomware_known": False}) is None


# ------------------------------------------------------------------ FC3/FC4 actor and tool cards
def test_actor_card_joins_through_the_alias_index():
    res = run_module(RansomwareMatrices, "threat_actor:Black Basta", matrix_http())
    assert res.status is Status.OK
    tools = {t["tool"] for t in res.attributes["ransomware_tool_leads"]}
    assert {"AnyDesk", "Atera", "ScreenConnect", "Splashtop"} <= tools  # 'Black Basta' in the Tool Matrix
    cves = {c["cve"] for c in res.attributes["ransomware_exploited_cves"]}
    assert {"CVE-2024-1709", "CVE-2022-30190", "CVE-2020-1472"} <= cves  # 'BlackBasta' in the Vulnerability Matrix
    assert all(not p.expand and p.relation == "exploits" for p in res.pivots)
    finding = res.findings[0]
    assert finding.severity is Severity.INFO and {"dual_use", "context_only"} <= set(finding.tags)
    assert "not a malicious verdict" in finding.description
    assert all(t["note"].startswith("hunting lead") for t in res.attributes["ransomware_tool_leads"])


def test_tool_keyword_is_a_dual_use_lead_never_a_verdict():
    res = run_module(RansomwareMatrices, "keyword:AnyDesk", matrix_http())
    lead = res.attributes["ransomware_tool_leads"][0]
    assert lead["tool"] == "AnyDesk" and "RMM Tools" in lead["categories"] and "LockBit" in lead["groups"]
    assert all(f.severity is Severity.INFO and "dual_use" in f.tags for f in res.findings)
    defanged = run_module(RansomwareMatrices, "keyword:Catbox.moe", matrix_http())
    assert defanged.attributes["ransomware_tool_leads"][0]["tool"] == "Catbox[.]moe"  # keyed refanged


def test_unknown_name_is_empty():
    res = run_module(RansomwareMatrices, "threat_actor:Exemplo Inexistente", matrix_http())
    assert res.status is Status.EMPTY


# ------------------------------------------------------------------ FC1/FC2 dataset behaviour
def test_changed_layout_without_previous_copy_reports_the_source():
    http = matrix_http({"ransomware_matrices.rvm.rmm_tools": "rvm_changed_layout.md"})
    res = run_module(RansomwareMatrices, "cve:CVE-2025-59718", http)
    assert res.status is Status.OK  # the other files answer
    status = res.source_statuses[RVM_SOURCE]
    assert "format changed" in status["reason"]


def test_changed_layout_keeps_the_last_good_index():
    clock = FakeClock()
    http = matrix_http(times=1)
    http.add("GET", DATASETS["ransomware_matrices.rvm.rmm_tools"]["url"], text=text("rvm_changed_layout.md"))
    for name in FIXTURE_OF:
        if name != "ransomware_matrices.rvm.rmm_tools":
            cap = module_fixture(RansomwareMatrices, "not_modified_304.http.json")
            http.add("GET", DATASETS[name]["url"], status=304, headers=cap["headers"])
    http.add("GET", KEV_FEED_URL, status=304, headers={})
    rt = make_runtime(http, clock=clock)
    first = run_module(RansomwareMatrices, "cve:CVE-2024-1709", runtime=rt)
    assert first.status is Status.OK
    clock.advance(8 * 86400)
    mod._MEMO.update(key=None, index=None)
    second = run_module(RansomwareMatrices, "cve:CVE-2024-1709", runtime=rt)
    assert second.status is Status.OK and second.attributes["patch_priority"] == "highest"  # last good copy in use
    assert "last good index kept" in second.source_statuses[RVM_SOURCE]["reason"]


def test_every_download_blocked_is_could_not_verify():
    page = "<html><head><title>Just a moment...</title></head><body>cf-chl-widget</body></html>"
    http = FakeHttp()
    for name in FIXTURE_OF:
        http.add("GET", DATASETS[name]["url"], status=403, text=page)
    res = run_module(RansomwareMatrices, "cve:CVE-2024-1709", http)
    assert res.status is Status.BLOCKED and res.status is not Status.EMPTY


def test_every_download_failing_is_error():
    http = FakeHttp()
    for name in FIXTURE_OF:
        http.add("GET", DATASETS[name]["url"], status=503, text="down", times=3)
    res = run_module(RansomwareMatrices, "threat_actor:LockBit", http)
    assert res.status is Status.ERROR


def test_module_never_spawns_a_process(monkeypatch):
    def boom(*a, **k):
        raise AssertionError("no process may be spawned")
    monkeypatch.setattr(subprocess, "Popen", boom)
    assert run_module(RansomwareMatrices, "keyword:AnyDesk", matrix_http()).status is Status.OK
