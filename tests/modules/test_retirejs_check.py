"""retirejs_check (P344, batch p2-G03-1).

Fixtures in tests/fixtures/retirejs_check/ (prep p2-G03-1, 2026-11-26): ``jsrepository_min.json`` (the live
jsrepository-v4.json reduced to 4 libraries: retire-example, jquery, lodash, dojo; ast dropped),
``jquery_1.12.4_min_banner.js`` (banner line of jquery-1.12.4.min.js as served by code.jquery.com + stub),
``no_known_library.js`` and ``redos_repo_synthetic.json`` (synthetic). The full repository snapshot
bundled in v3lum/data/retirejs/ (651,449 bytes, Apache-2.0) is the default repository.
"""

from __future__ import annotations

import multiprocessing
import os
import time

import pytest

from tests.fakes import FIXTURES, FakeHttp, run_module
from v3lum import paths
from v3lum.core.entities import Entity
from v3lum.core.entities import EntityType as T
from v3lum.core.models import Status
from v3lum.core.orgprofile import OrgProfile
from v3lum.modules.url_web import retirejs_check as mod
from v3lum.modules.url_web.retirejs_check import RetireJsCheck

JQUERY_ADVISORIES = {"CVE-2019-11358", "CVE-2020-11022", "CVE-2020-11023", "CVE-2015-9251"}


def fx(name: str) -> str:
    return (FIXTURES / "retirejs_check" / name).read_text(encoding="utf-8")


def install_repo(name: str = "jsrepository_min.json") -> None:
    path = paths.datasets_dir() / mod.DATASET
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes((FIXTURES / "retirejs_check" / name).read_bytes())
    now = time.time()
    os.utime(path, (now, now))


def finding_ids(res) -> set[str]:
    return {i for f in res.findings for a in f.data["advisories"] for i in a["ids"]}


def test_metadata_offline_dataset_module():
    cls = RetireJsCheck
    assert (cls.disclosure, cls.hosts, cls.provider) == ("none", (), "")
    assert cls.sources == ("github.retirejs_check_jsrepository",) and cls.terms == "open" and cls.default_enabled is True
    assert cls.max_tlp.name == "RED"


# ------------------------------------------------------------------ c6 recorded jquery 1.12.4
def test_recorded_jquery_1124_has_four_cve_ghsa_advisories():
    http = FakeHttp()
    res = run_module(RetireJsCheck, Entity.make(T.TEXT, fx("jquery_1.12.4_min_banner.js")), http)
    assert res.status is Status.OK and http.calls == []
    assert len(res.findings) == 1  # c4: one finding per library+version
    f = res.findings[0]
    assert f.key == "jquery@1.12.4" and f.data["detection"] == "filecontent"
    assert {c for a in f.data["advisories"] for c in a["ids"]} >= JQUERY_ADVISORIES
    assert len(f.data["advisories"]) == 4 and f.data["other_notes"]  # id-less notes (end of life, parseHTML)
    assert f.severity.label == "info"  # text of unknown origin: not an own asset (c4)
    assert f.confidence >= 0.75 and "version_inferred" not in f.tags
    assert {p.entity.value for p in res.pivots} == JQUERY_ADVISORIES
    assert all(not p.expand and p.relation == "has_vuln" for p in res.pivots)
    assert res.attributes["retirejs_repository"]["source"] == "bundled"


def test_url_detection_is_version_inferred():
    res = run_module(RetireJsCheck, "url:https://code.jquery.com/jquery-1.12.4.min.js", FakeHttp())
    f = res.findings[0]
    assert f.data["detection"] in ("uri", "filename")
    assert f.confidence <= 0.5 and "version_inferred" in f.tags
    assert "version inferred from file name" in f.criterion


def test_own_asset_severity_capped_at_medium():
    org = OrgProfile.from_dict({"org": {"name": "Example"}, "domains": [{"name": "example.com", "verification": "txt_verified"}]})
    res = run_module(RetireJsCheck, "url:https://www.example.com/static/jquery-1.12.4.min.js", FakeHttp(), org_profile=org)
    assert res.findings[0].severity.label == "medium"


def test_kev_lifts_the_medium_cap():
    det = {"component": "x", "version": "1.0", "detection": "filecontent", "confidence": 0.8, "version_inferred": False}
    advisories = [{"ids": ["CVE-2099-0001"], "cves": ["CVE-2099-0001"], "severity": "critical", "summary": "s", "info": []}]
    assert mod.retire_finding(det, advisories, owned_or_in_scope=True)["severity"] == "medium"
    assert mod.retire_finding(det, advisories, owned_or_in_scope=True, kev_cves={"CVE-2099-0001"})["severity"] == "critical"
    assert mod.retire_finding(det, advisories, owned_or_in_scope=False, kev_cves={"CVE-2099-0001"})["severity"] == "info"


def test_no_known_library_is_empty():
    res = run_module(RetireJsCheck, Entity.make(T.TEXT, fx("no_known_library.js")), FakeHttp())
    assert res.status is Status.EMPTY


def test_file_input_and_installed_dataset_preferred(tmp_path):
    install_repo()
    js = tmp_path / "vendor.min.js"
    js.write_text(fx("jquery_1.12.4_min_banner.js"), encoding="utf-8")
    res = run_module(RetireJsCheck, Entity.make(T.FILE, str(js)), FakeHttp())
    assert res.status is Status.OK
    assert res.attributes["retirejs_repository"]["source"] == "dataset"
    assert finding_ids(res) >= JQUERY_ADVISORIES


def test_unusable_dataset_copy_falls_back_to_bundle():
    path = paths.datasets_dir() / mod.DATASET
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text("<html>oops</html>")
    res = run_module(RetireJsCheck, Entity.make(T.TEXT, fx("jquery_1.12.4_min_banner.js")), FakeHttp())
    assert res.status in (Status.OK, Status.ERROR, Status.UNAVAILABLE)  # never 'empty' on an unusable repository


def test_binary_file_not_applicable(tmp_path):
    blob = tmp_path / "logo.png"
    blob.write_bytes(b"\x89PNG")
    assert run_module(RetireJsCheck, Entity.make(T.FILE, str(blob)), FakeHttp()).status is Status.SKIPPED


# ------------------------------------------------------------------ c2 extractors and version logic
def test_repository_loading_skips_func_and_compiles_patterns():
    repo = mod.retire_load_repo(fx("jsrepository_min.json"))
    assert repo["error"] is None and set(repo["libraries"]) == {"retire-example", "jquery", "lodash", "dojo"}
    assert repo["skipped_func"] > 0 and repo["pattern_errors"] == []
    full = mod.retire_load_repo((mod.Path(mod.__file__).parents[2] / "data" / mod.BUNDLED).read_bytes())
    assert len(full["libraries"]) == 78 and len(full["pattern_errors"]) <= 1


def test_version_comparison_port():
    assert mod.retire_is_at_or_above("1.12.4", "1.12.4")
    assert not mod.retire_is_at_or_above("1.12.4", "3.5.0")
    assert mod.retire_is_at_or_above("1.10", "1.9.1")
    assert mod.retire_is_at_or_above("1.0.0", "1.0.0-beta")  # a number beats a string


def test_uri_hash_like_versions_are_dropped():
    repo = mod.retire_load_repo(fx("jsrepository_min.json"))
    assert mod.retire_scan(repo, uri="https://cdn.example/abcdef1234567/jquery.min.js") == []


# ------------------------------------------------------------------ c2 ReDoS harness (same kind as secret_scanner P312)
def _worker(pattern: str, inputs: list[str], q) -> None:  # pragma: no cover - runs in a child process
    import re

    rx = re.compile(pattern)
    for s in inputs:
        for _ in rx.finditer(s):
            pass
    q.put("ok")


def _scan_worker(repo_bytes: bytes, inputs: list[str], q) -> None:  # pragma: no cover - runs in a child process
    repo = mod.retire_load_repo(repo_bytes)
    worst = 0.0
    for s in inputs:
        t0 = time.perf_counter()
        mod.retire_scan(repo, content=s)
        mod.retire_scan(repo, uri=s[: mod.RETIRE_URI_MAX])
        worst = max(worst, time.perf_counter() - t0)
    q.put(worst)


def _fork_ctx():
    try:
        return multiprocessing.get_context("fork")
    except ValueError:  # pragma: no cover
        return multiprocessing.get_context("spawn")


def test_redos_harness_rejects_catastrophic_pattern():
    import json

    raw = json.loads(fx("redos_repo_synthetic.json"))
    pattern = mod.retire_repo_patterns(raw)[0]
    ctx = _fork_ctx()
    q = ctx.Queue()
    proc = ctx.Process(target=_worker, args=(pattern, ["a" * 40 + "c"] * 3, q))
    proc.start()
    proc.join(1.0)
    timed_out = proc.is_alive()
    if timed_out:
        proc.terminate()
        proc.join()
    assert timed_out, "the harness must reject a catastrophic pattern"


@pytest.mark.slow
def test_scan_level_budget_with_literal_windows():
    repo_bytes = (mod.Path(mod.__file__).parents[2] / "data" / mod.BUNDLED).read_bytes()
    literals = ["\nYUI ", " Ext JS Library ", "var c3_chart_fn,", "PDFObject v", "marked v", "select2"]
    size = 500_000
    inputs = ["1." * (size // 2), "a" * size, "/" * size + "jquery-"]
    for lit in literals:
        unit = "/" * 1000 + lit
        inputs.append((unit * (size // len(unit) + 1))[:size])
    ctx = _fork_ctx()
    q = ctx.Queue()
    proc = ctx.Process(target=_scan_worker, args=(repo_bytes, inputs, q))
    proc.start()
    proc.join(60.0)
    if proc.is_alive():
        proc.terminate()
        proc.join()
        pytest.fail("retire_scan exceeded the 60 s budget on adversarial inputs")
    worst = q.get(timeout=5)
    assert worst < 5.0, worst
