"""technique_detections_tests (P373): SigmaHQ rule metadata + Atomic Red Team index, offline.

Fixtures in tests/fixtures/technique_detections_tests/ (prep batch p2-G11-1, from release r2026-07-01 and
the Atomic master index of 2026-11-26): ``sigma_core_slice.zip`` (version.txt plus the metadata of 11 real
rules at their real paths and ids - detection logic removed, author fields replaced by a placeholder, see
its NOTICE.txt; DRL 1.1 credit by path and id), ``atomic_index_head.csv`` (the first 51 real rows),
``atomic_index_changed_layout.csv`` (renamed headers), the real release redirect, and three synthetic zips
(status mix with broken/duplicate members, a symlink member, a '../' member).

PyYAML is an optional extra that the offline venv does not ship: tests exercise both paths - the
UNAVAILABLE 'package' answer, and the indexer with :func:`mini_yaml`, a test-only loader for the
fixture subset (the module itself only ever calls ``yaml.safe_load``).
"""

from __future__ import annotations

import os
import subprocess
from pathlib import Path

import pytest

from tests.fakes import FIXTURES, FakeHttp, module_fixture, run_module
from v3lum.core.datasets import DATASETS
from v3lum.core.models import Status
from v3lum.modules.cti_framework import technique_detections_tests as mod
from v3lum.modules.cti_framework.technique_detections_tests import (
    ATOMIC_DATASET,
    ATOMIC_SOURCE,
    ATOMIC_URL,
    SIGMA_DATASET,
    SIGMA_SOURCE,
    SIGMA_URL,
    TechniqueDetectionsTests,
    atomic_parse_index,
    atomic_tests_for,
    safe_zip_members,
    sigma_attribution,
    sigma_index_zip,
    sigma_rules_for,
)

FX = FIXTURES / "technique_detections_tests"
SLICE = (FX / "sigma_core_slice.zip").read_bytes()
ATOMIC = (FX / "atomic_index_head.csv").read_text(encoding="utf-8")


def mini_yaml(raw: bytes):
    """Test-only loader for the fixture subset: 'key: value', 'key:' + '- item' lists or '  sub: value' maps."""
    text = raw.decode("utf-8")
    lines = [ln for ln in text.splitlines() if ln.strip() and not ln.lstrip().startswith("#")]
    if lines and lines[0].startswith("- "):
        return [ln[2:].strip() for ln in lines]
    doc: dict = {}
    key = None
    for line in lines:
        if line.startswith("  - ") or line.startswith("- "):
            if not isinstance(doc.get(key), list):
                doc[key] = []
            doc[key].append(line.split("- ", 1)[1].strip())
        elif line.startswith("  ") and ":" in line:
            sub, _, value = line.strip().partition(":")
            if not isinstance(doc.get(key), dict):
                doc[key] = {}
            doc[key][sub.strip()] = value.strip().strip("'")
        elif ":" in line:
            key, _, value = line.partition(":")
            key, value = key.strip(), value.strip()
            if value.startswith("[") and not value.endswith("]"):
                raise ValueError("unclosed flow sequence")
            doc[key] = value.strip("'") if value else None
        else:
            raise ValueError("unexpected line")
    return doc


@pytest.fixture
def with_yaml(monkeypatch):
    monkeypatch.setattr(mod, "yaml_safe_load", lambda: mini_yaml)
    mod._MEMO.clear()


@pytest.fixture(autouse=True)
def fresh_memo():
    mod._MEMO.clear()


def data_http(*, sigma: bytes | None = SLICE, atomic: str | None = ATOMIC) -> FakeHttp:
    http = FakeHttp()
    if sigma is not None:
        http.add("GET", SIGMA_URL, body=sigma, headers={"Content-Type": "application/zip"})
    if atomic is not None:
        http.add("GET", ATOMIC_URL, text=atomic, headers={"Content-Type": "text/plain"})
    return http


# ------------------------------------------------------------------ metadata (council values)
def test_metadata_matches_the_council_decision():
    cls = TechniqueDetectionsTests
    assert cls.default_enabled is True and cls.terms == "open" and cls.disclosure == "none" and cls.hosts == ()
    assert cls.sources == (SIGMA_SOURCE, ATOMIC_SOURCE) and cls.max_requests == 0 and not cls.produces
    sig, ato = DATASETS[SIGMA_DATASET], DATASETS[ATOMIC_DATASET]
    assert sig["licence"] == "DRL-1.1" and ato["licence"] == "MIT" and sig["ttl"] == ato["ttl"] == 7 * 86400
    assert sig["archive"] is None  # read in memory by the module, never extracted (FC1)


# ------------------------------------------------------------------ FC1: optional PyYAML
def test_without_pyyaml_sigma_is_unavailable_package_and_atomic_still_answers(monkeypatch):
    monkeypatch.setattr(mod, "yaml_safe_load", lambda: None)
    http = data_http(sigma=None)
    res = run_module(TechniqueDetectionsTests, "mitre_technique:T1567.002", http)
    assert res.status is Status.OK
    assert res.source_statuses[SIGMA_SOURCE]["reason_code"] == "package"
    assert res.attributes["detection_coverage"] == "Sigma index unavailable / 2 atomic tests"
    assert SIGMA_URL not in http.urls()  # nothing downloaded that cannot be parsed safely
    cve = run_module(TechniqueDetectionsTests, "cve:CVE-2022-30190", FakeHttp())
    assert cve.status is Status.UNAVAILABLE and cve.reason_code == "package"


# ------------------------------------------------------------------ FC2/FC4/FC5 cards
def test_technique_card_counts_and_links(with_yaml):
    http = data_http()
    res = run_module(TechniqueDetectionsTests, "mitre_technique:T1567.002", http)
    assert res.status is Status.OK
    assert res.attributes["detection_coverage"] == "1 Sigma rules / 2 atomic tests"
    rule = res.attributes["sigma_rules"][0]
    assert rule["title"] == "PUA - Rclone Execution" or "Rclone" in rule["title"]
    assert rule["link"].startswith("https://github.com/SigmaHQ/sigma/blob/master/rules/windows/process_creation/")
    tests = res.attributes["atomic_tests"]
    assert len(tests) == 2 and all(t["link"].endswith("/atomics/T1567.002/T1567.002.md") for t in tests)
    assert res.attributes["sigma_release"]["release_date"] == "2026-07-09"
    assert res.attributes["sigma_release"]["commit"].startswith("552f3fee")
    assert "Detection Rule License 1.1" in res.attributes["data_attribution"] and "never executed" in res.attributes["data_attribution"]
    assert res.requests == 0 and {d["name"] for d in res.datasets} == {SIGMA_DATASET, ATOMIC_DATASET}
    http.assert_hosts_within(TechniqueDetectionsTests, extra=("github.com", "raw.githubusercontent.com"))


def test_parent_technique_includes_sub_techniques(with_yaml):
    res = run_module(TechniqueDetectionsTests, "mitre_technique:T1021", data_http())
    titles = [r["title"] for r in res.attributes["sigma_rules"]]
    assert any("Impacket" in t for t in titles)  # tagged attack.t1021.003
    assert {t["technique"] for t in res.attributes["atomic_tests"]} == {"T1021.002"}


def test_cve_and_name_cards(with_yaml):
    cve = run_module(TechniqueDetectionsTests, "cve:CVE-2022-30190", data_http(atomic=None))
    assert cve.status is Status.OK and cve.attributes["detection_coverage"] == "1 Sigma rules / 0 atomic tests"
    group = run_module(TechniqueDetectionsTests, "threat_actor:MuddyWater", data_http(atomic=None))  # G0069 through P295
    assert [r["id"] for r in group.attributes["sigma_rules"]] == ["3b4b232a-af90-427c-a22f-30b0c0837b95"]
    tool = run_module(TechniqueDetectionsTests, "keyword:AnyDesk", data_http(atomic=None))  # title words
    assert "anydesk" in tool.attributes["sigma_rules"][0]["title"].lower()


def test_nothing_known_is_empty(with_yaml):
    res = run_module(TechniqueDetectionsTests, "mitre_technique:T1001", data_http())
    assert res.status is Status.EMPTY and "0 Sigma rules / 0 atomic tests" in res.error


def test_status_ordering_and_marking(with_yaml):
    idx = sigma_index_zip((FX / "sigma_status_mix_synthetic.zip").read_bytes(), mini_yaml)
    assert idx["status"] == "ok"
    rules = sigma_rules_for(idx, technique="T1059")
    assert [r["status"] for r in rules] == ["stable", "test", "experimental", "deprecated"]  # parent includes sub-techniques
    ordered = sigma_rules_for(idx, technique="T1059.001")
    assert [r["status"] for r in ordered] == ["stable", "experimental", "deprecated"]
    assert [r["marked"] for r in ordered] == [False, True, True]
    assert {e["error"] for e in idx["errors"]} >= {"ValueError", "not a rule mapping", "duplicate rule id"}
    assert "stealth" in idx["tactics"]  # tactic names read from the data


def test_tactics_read_from_data_and_guids_deduplicated():
    idx = atomic_parse_index(ATOMIC)
    assert idx["status"] == "ok" and "stealth" in idx["tactics"] and "defense-evasion" not in idx["tactics"]
    tests = atomic_tests_for(idx, "T1205.002")
    assert len(tests) == len({t["guid"] for t in tests}) and set(tests[0]["tactics"]) == {"stealth", "persistence", "command-and-control"}


def test_attribution_line_for_reproduced_bodies():
    line = sigma_attribution({"title": "X", "author": "Example Author", "path": "rules/x.yml"})
    assert "Detection Rule License (DRL) 1.1" in line and "Example Author" in line and line.endswith("rules/x.yml")


# ------------------------------------------------------------------ FC1: untrusted archive
@pytest.mark.parametrize("name,reason", [("sigma_symlink_synthetic.zip", "symlink"), ("sigma_unsafe_path_synthetic.zip", "unsafe member path")])
def test_unsafe_archives_are_refused(name, reason):
    opened, problem = safe_zip_members((FX / name).read_bytes())
    assert opened is None and reason in problem


def test_zip_caps_and_garbage():
    assert safe_zip_members(SLICE, {"max_members": 3})[1].startswith("archive has")
    assert safe_zip_members(SLICE, {"max_member_bytes": 100})[1].startswith("member")
    assert "not a valid zip" in safe_zip_members(b"PK\x03\x04garbage")[1]


def test_unsafe_download_never_replaces_anything(with_yaml):
    http = data_http(sigma=(FX / "sigma_unsafe_path_synthetic.zip").read_bytes(), atomic=None)
    res = run_module(TechniqueDetectionsTests, "cve:CVE-2022-30190", http)
    assert res.status is Status.ERROR and "unsafe member path" in res.error


def test_atomic_layout_change_is_reported(with_yaml):
    http = data_http(atomic=(FX / "atomic_index_changed_layout.csv").read_text(encoding="utf-8"))
    res = run_module(TechniqueDetectionsTests, "mitre_technique:T1567.002", http)
    assert res.status is Status.OK  # Sigma answers
    assert "format changed" in res.source_statuses[ATOMIC_SOURCE]["reason"]


def test_release_redirect_hosts_are_registry_hosts(with_yaml):
    redirect = module_fixture(TechniqueDetectionsTests, "sigma_release_redirect.http.json")
    asset = "https://release-assets.githubusercontent.com/github-production-release-asset/1/sigma_core.zip"
    http = (FakeHttp().add("GET", SIGMA_URL, status=302, headers=redirect["headers"])
            .add("GET", redirect["headers"]["location"], status=302, headers={"Location": asset})
            .add("GET", asset, body=SLICE, headers={"Content-Type": "application/octet-stream"}))
    res = run_module(TechniqueDetectionsTests, "cve:CVE-2022-30190", http)
    assert res.status is Status.OK
    http.assert_hosts_within(TechniqueDetectionsTests, extra=("github.com", "release-assets.githubusercontent.com"))


def test_blocked_download_is_could_not_verify(with_yaml):
    page = "<html><head><title>Just a moment...</title></head><body>cf-chl-widget</body></html>"
    http = FakeHttp().add("GET", SIGMA_URL, status=403, text=page)
    res = run_module(TechniqueDetectionsTests, "cve:CVE-2022-30190", http)
    assert res.status is Status.BLOCKED


def test_5xx_download_is_error(with_yaml):
    http = FakeHttp().add("GET", SIGMA_URL, status=503, text="down", times=3)
    assert run_module(TechniqueDetectionsTests, "cve:CVE-2022-30190", http).status is Status.ERROR


# ------------------------------------------------------------------ FC3: never executed
def test_module_never_spawns_a_process(monkeypatch, with_yaml):
    def boom(*a, **k):
        raise AssertionError("no process may be spawned")
    monkeypatch.setattr(subprocess, "Popen", boom)
    monkeypatch.setattr(os, "system", boom)
    res = run_module(TechniqueDetectionsTests, "mitre_technique:T1567.002", data_http())
    assert res.status is Status.OK
    source = Path(mod.__file__).read_text(encoding="utf-8")
    assert "subprocess" not in source and "os.system" not in source and "run_tool" not in source
