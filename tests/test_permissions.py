"""File permissions (AR03, A10; WP10): a 0700 home and subdirectories (existing loose ones tightened),
0600 databases, cache, quota DB, evidence, reports, config, secret.key and history files whatever
the umask; check_permissions (doctor) and insecure_reasons (plugin/spec/rule directories)."""

from __future__ import annotations

import json
import os
import stat
import sys

import pytest

from v3lum import paths
from v3lum.config import Config
from v3lum.core import hmacid
from v3lum.core.cache import HttpCache
from v3lum.core.http import Response
from v3lum.core.quota import QuotaBook
from v3lum.core.store import Store
from v3lum.report import write_reports

pytestmark = pytest.mark.skipif(os.name != "posix", reason="POSIX file modes")


def mode(path) -> int:
    return stat.S_IMODE(os.lstat(path).st_mode)


@pytest.fixture()
def loose_umask():
    old = os.umask(0o022)
    try:
        yield
    finally:
        os.umask(old)


def minimal_case(case_id: str = "20261126-120000-aaaa") -> dict:
    return {
        "schema": "v3lum.case/1",
        "case_id": case_id,
        "created": "2026-11-26T12:00:00+00:00",
        "tlp": "amber",
        "seeds": ["domain:evil.example"],
        "options": {"mode": "passive"},
        "summary": {"risk_score": 0.0, "risk_level": "clean", "findings": 0, "entities": 0},
        "entities": [],
        "risk": {},
        "edges": [],
        "findings": [],
        "correlations": [],
        "modules": [],
        "coverage": {},
        "links": {},
        "timeline": [],
        "notes": [],
    }


# --------------------------------------------------------------------------------------
# directories
# --------------------------------------------------------------------------------------


def test_home_and_subdirectories_are_0700_and_loose_ones_are_tightened(isolated_home, loose_umask):
    os.chmod(isolated_home, 0o755)  # an existing home with a loose mode (wave-1 installs)
    assert paths.home() == isolated_home and mode(isolated_home) == 0o700
    for directory in (paths.cases_dir(), paths.feeds_dir(), paths.datasets_dir(), paths.plugins_dir(), paths.cache_file().parent, paths.sub("state")):
        assert mode(directory) == 0o700, directory
    cases = paths.cases_dir()
    os.chmod(cases, 0o775)
    assert mode(cases) == 0o775
    assert paths.cases_dir() == cases and mode(cases) == 0o700  # tightened on the next use
    nested = paths.sub("cases/20261126-120000-aaaa/evidence")
    for p in (nested, nested.parent):
        assert mode(p) == 0o700
    assert paths.case_dir("20261126-120000-aaaa") == nested.parent
    for bad in ("../escape", "/abs", "a/../../b", ""):
        with pytest.raises(ValueError):
            paths.sub(bad)
    for bad in ("..", "a/b", "", "x" * 200):
        with pytest.raises(ValueError):
            paths.case_dir(bad)


def test_a_fresh_home_is_created_0700(tmp_path, monkeypatch, loose_umask):
    target = tmp_path / "deep" / "new_home"
    monkeypatch.setenv("V3LUM_HOME", str(target))
    assert paths.home() == target and mode(target) == 0o700


def test_shared_sticky_directories_are_never_chmodded(tmp_path, monkeypatch):
    shared = tmp_path / "shared_tmp"
    shared.mkdir()
    os.chmod(shared, 0o1777)
    monkeypatch.setenv("V3LUM_HOME", str(shared))
    paths.home()
    assert stat.S_IMODE(os.stat(shared).st_mode) == 0o1777  # a /tmp-like dir is reported, not locked down
    assert any("expected 0700" in line for line in paths.check_permissions())


def test_private_dir_creates_0700_but_keeps_an_outside_directory_mode(tmp_path, loose_umask):
    outside = tmp_path / "reports_out"
    outside.mkdir()
    os.chmod(outside, 0o755)
    assert paths.private_dir(outside) == outside and mode(outside) == 0o755  # the analyst's -o dir
    created = paths.private_dir(tmp_path / "new" / "reports")
    assert mode(created) == 0o700 and mode(created.parent) == 0o700
    inside = paths.home() / "reports"
    inside.mkdir()
    os.chmod(inside, 0o755)
    paths.private_dir(inside)
    assert mode(inside) == 0o700  # inside the home it is tightened
    assert paths.inside_home(inside) and not paths.inside_home(outside)


# --------------------------------------------------------------------------------------
# files
# --------------------------------------------------------------------------------------


def test_databases_are_0600_whatever_the_umask(loose_umask):
    store = Store()
    store.save_case(minimal_case())
    store.close()
    cache = HttpCache(str(paths.cache_file()))
    assert cache.put("k", Response(200, "https://a.example.test/x", {}, b"body"))
    quota = QuotaBook()
    quota.add("t_mod", 1)
    db_files = [paths.db_file(), paths.home() / "quota.db"] + [p for p in paths.cache_file().parent.iterdir() if p.name.startswith("http_cache.db")]
    try:
        for p in db_files:
            assert mode(p) == 0o600, p
    finally:
        cache.close()
        quota.close()
    loose = paths.home() / "quota.db"
    os.chmod(loose, 0o644)
    QuotaBook().close()
    assert mode(loose) == 0o600  # an existing loose quota DB in the home is tightened


def test_config_secret_history_evidence_and_reports_are_0600(tmp_path, loose_umask):
    cfg = Config()
    cfg.settings["timeout"] = 33.0
    cfg.save()
    assert mode(paths.config_file()) == 0o600
    hmacid.installation_secret()
    assert mode(paths.secret_key_file()) == 0o600
    history = paths.secure_write_text(paths.home() / "shell_history", "scan example.com\n")  # WP13's writer
    assert mode(history) == 0o600
    evidence_dir = paths.sub("cases/20261126-120000-aaaa/evidence")
    ev = paths.secure_write_bytes(evidence_dir / "mod__domain__0123456789ab__abcdef0123.json", b'{"data": 1}')
    assert mode(ev) == 0o600 and mode(evidence_dir) == 0o700
    case_out = paths.case_dir("20261126-120000-aaaa")
    written = write_reports(minimal_case(), ["json", "md", "html", "stix"], case_out)
    for path in written.values():
        assert mode(path) == 0o600, path
    out = tmp_path / "analyst_out"
    out.mkdir()
    os.chmod(out, 0o755)
    for path in write_reports(minimal_case(), ["json"], out).values():
        with open(path, encoding="utf-8") as fh:
            assert mode(path) == 0o600 and json.loads(fh.read())["case_id"]
    assert mode(out) == 0o755
    fresh = write_reports(minimal_case(), ["md"], tmp_path / "missing" / "dir")
    assert mode(tmp_path / "missing" / "dir") == 0o700 and all(mode(p) == 0o600 for p in fresh.values())


def test_secure_write_is_atomic_and_never_follows_links(tmp_path, monkeypatch):
    tmp_path = tmp_path / "work"
    tmp_path.mkdir()
    target = tmp_path / "file.txt"
    paths.secure_write_text(target, "old")
    elsewhere = tmp_path / "elsewhere.txt"
    elsewhere.write_text("keep me")
    link = tmp_path / "link.txt"
    link.symlink_to(elsewhere)
    paths.secure_write_text(link, "new")
    assert elsewhere.read_text() == "keep me" and not link.is_symlink() and link.read_text() == "new"

    def boom(fd):
        raise OSError("disk full")

    monkeypatch.setattr(os, "fsync", boom)
    with pytest.raises(OSError, match="disk full"):
        paths.secure_write_text(target, "half written")
    assert target.read_text() == "old"  # the previous version survives a failed write
    assert sorted(p.name for p in tmp_path.iterdir()) == ["elsewhere.txt", "file.txt", "link.txt"]  # no temp leftovers


def test_restrict_file_creates_owner_only_and_tightens_companions(tmp_path, loose_umask):
    db = tmp_path / "x.db"
    paths.restrict_file(db, create=True)
    assert db.exists() and mode(db) == 0o600
    for suffix in ("-wal", "-shm", "-journal"):
        companion = tmp_path / f"x.db{suffix}"
        companion.write_bytes(b"")
        os.chmod(companion, 0o644)
    paths.restrict_file(db)
    assert all(mode(tmp_path / f"x.db{s}") == 0o600 for s in ("-wal", "-shm", "-journal"))
    assert paths.restrict_file(":memory:").name == ":memory:"


# --------------------------------------------------------------------------------------
# doctor: check_permissions
# --------------------------------------------------------------------------------------


def test_check_permissions_reports_loosened_files_and_directories(loose_umask):
    Store().close()
    hmacid.installation_secret()
    paths.sub("cases/20261126-120000-aaaa/evidence")
    assert paths.check_permissions() == []
    os.chmod(paths.db_file(), 0o644)
    os.chmod(paths.cases_dir(), 0o755)
    report = paths.check_permissions()
    assert any(str(paths.db_file()) in line and "file mode 0644" in line for line in report)
    assert any(line.startswith(f"{paths.cases_dir()}:") and "directory mode 0755" in line for line in report)
    assert mode(paths.db_file()) == 0o644  # reporting only, nothing changed
    many = paths.sub("many")
    for i in range(5):
        f = many / f"f{i}"
        f.write_text("x")
        os.chmod(f, 0o644)
    limited = paths.check_permissions(limit=2)
    assert len(limited) == 3 and limited[-1].startswith("... and ")
    assert paths.check_permissions(paths.home() / "does-not-exist") == []


# --------------------------------------------------------------------------------------
# loaders: insecure_reasons (AR12 / P331 / P301)
# --------------------------------------------------------------------------------------


def test_insecure_reasons_for_group_and_world_writable_dirs(tmp_path):
    plugins = paths.plugins_dir()
    assert paths.insecure_reasons(plugins) == []
    os.chmod(plugins, 0o770)
    assert any("group-writable" in r for r in paths.insecure_reasons(plugins))
    os.chmod(plugins, 0o777)
    reasons = paths.insecure_reasons(plugins)
    assert any("group-writable" in r for r in reasons) and any("world-writable" in r for r in reasons)
    spec = tmp_path / "spec.json"
    spec.write_text("{}")
    os.chmod(spec, 0o646)
    assert any("world-writable" in r for r in paths.insecure_reasons(spec))
    assert paths.insecure_reasons(tmp_path / "missing") == []


@pytest.mark.skipif(not hasattr(os, "geteuid") or os.geteuid() != 0, reason="chown to another user needs root")
def test_insecure_reasons_for_a_directory_owned_by_someone_else(tmp_path):
    rules = tmp_path / "rules"
    rules.mkdir(mode=0o700)
    os.chown(rules, 12345, -1)
    try:
        reasons = paths.insecure_reasons(rules)
        assert any("owned by uid 12345" in r for r in reasons)
    finally:
        os.chown(rules, os.getuid(), -1)


def test_umask_never_loosens_secure_writes(tmp_path):
    old = os.umask(0o000)
    try:
        f = paths.secure_write_bytes(tmp_path / "a.bin", b"x")
        assert mode(f) == 0o600
    finally:
        os.umask(old)
    assert sys.platform != "win32"


def test_reports_are_never_written_outside_out_dir(tmp_path):
    """Report names come from the case id: a damaged or crafted id is refused (no path traversal)."""
    out = tmp_path / "out" / "dir"
    for bad in ("../../escape", "a/b", "..", "", ".hidden", "x" * 200):
        case = {**minimal_case(), "case_id": bad}
        with pytest.raises(ValueError, match="invalid case id"):
            write_reports(case, ["json"], out)
    assert not (tmp_path / "escape.json").exists() and not any(tmp_path.rglob("*escape*"))
    assert write_reports(minimal_case("20261126-120000-ok01"), ["json"], out)["json"].endswith("v3lum-20261126-120000-ok01.json")
