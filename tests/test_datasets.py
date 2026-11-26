"""Dataset manager v2 (AR10): validated atomic replace, conditional GET, MANIFEST, safe_extract,
scan-time rules, active pins, index(), DataView citations and the v1 API."""

from __future__ import annotations

import bz2
import gzip
import io
import json
import os
import stat
import zipfile
from datetime import datetime, timedelta, timezone

import pytest

from tests.fakes import FakeHttp
from v3lum import paths
from v3lum.core import datasets as ds
from v3lum.core.datasets import (
    DATASETS,
    DataStore,
    DatasetError,
    DatasetUnavailable,
    UpdateResult,
    register_dataset,
    safe_extract,
)
from v3lum.core.http import NetworkError, Response

T0 = datetime(2026, 11, 26, 12, 0, tzinfo=timezone.utc)
URL = "https://lists.example.test/feed.txt"
CHALLENGE = "<!DOCTYPE html><html><head><title>Just a moment...</title></head><body>cf-chl-widget</body></html>"


class Rt:
    """Minimal runtime: an HTTP client, the scan flag and a controllable clock."""

    def __init__(self, http=None, *, in_scan: bool = False, now: datetime = T0) -> None:
        self.http = http
        self.in_scan = in_scan
        self._now = now
        self.cancel_event = None
        self.config = None

    def now(self) -> datetime:
        return self._now

    def advance(self, **delta) -> None:
        self._now = self._now + timedelta(**delta)


@pytest.fixture(autouse=True)
def _isolated_registry():
    saved = dict(DATASETS)
    yield
    DATASETS.clear()
    DATASETS.update(saved)


def manifest() -> dict:
    return json.loads((paths.datasets_dir() / "MANIFEST.json").read_text(encoding="utf-8"))["datasets"]


def mode(path) -> int:
    return stat.S_IMODE(os.stat(path).st_mode)


# --------------------------------------------------------------------------------------
# registration
# --------------------------------------------------------------------------------------


def test_register_keeps_v1_keys_and_adds_v2_fields():
    name = register_dataset(
        "feed.txt", URL, ttl=3600, description="test feed", licence="CC0-1.0", terms_class="open",
        attribution="Example", provider="example", source="example.feed", expect="lines", essential=True,
    )
    reg = DATASETS[name]
    assert {"url", "ttl", "description", "max_bytes"} <= set(reg)
    assert reg["url"] == URL and reg["ttl"] == 3600 and reg["max_bytes"] == 200 * 1024 * 1024
    assert reg["licence"] == "CC0-1.0" and reg["source"] == "example.feed" and reg["essential"] is True


@pytest.mark.parametrize("name", ["a/b", "../etc", "/abs", ".hidden", "a\\b", "", "MANIFEST.json", "active.lock", "x" * 129])
def test_invalid_names_rejected(name):
    with pytest.raises(ValueError):
        register_dataset(name, URL)
    with pytest.raises(ValueError):
        DataStore(Rt(FakeHttp())).fetch(name, URL)


def test_duplicate_name_with_other_url_rejected():
    register_dataset("dup.txt", URL)
    register_dataset("dup.txt", URL, description="same url: fine")
    with pytest.raises(ValueError, match="another URL"):
        register_dataset("dup.txt", "https://other.example.test/feed.txt")


@pytest.mark.parametrize(
    "kwargs",
    [{"expect": "xml"}, {"archive": "rar"}, {"terms_class": "free"}, {"pinned_sha256": "abc"}, {"source": "nodot"},
     {"provider": "a", "source": "b.c"}, {"validate": "notcallable"}],
)
def test_invalid_fields_rejected(kwargs):
    with pytest.raises(ValueError):
        register_dataset("bad.txt", URL, **kwargs)
    with pytest.raises(ValueError):
        register_dataset("bad2.txt", "ftp://x.example.test/a")


# --------------------------------------------------------------------------------------
# download, MANIFEST, conditional GET
# --------------------------------------------------------------------------------------


def test_download_writes_file_and_manifest():
    register_dataset("feed.txt", URL + "?key=SUPERSECRET123", licence="CC0-1.0", terms_class="open", attribution="Example",
                     provider="example", source="example.feed", expect="lines")
    http = FakeHttp().add("GET", URL + "?key=SUPERSECRET123", text="a.example\nb.example\n", headers={"ETag": '"v1"', "Last-Modified": "Wed, 25 Nov 2026 03:06:59 GMT"})
    store = DataStore(Rt(http))
    path = store.fetch("feed.txt")
    assert path == paths.datasets_dir() / "feed.txt"
    assert path.read_text() == "a.example\nb.example\n"
    entry = manifest()["feed.txt"]
    for key in ("url", "fetched_at", "sha256", "bytes", "etag", "last_modified", "licence", "terms_class", "attribution", "provider", "source", "stale"):
        assert key in entry
    assert "SUPERSECRET123" not in entry["url"]
    assert entry["fetched_at"] == "2026-11-26T12:00:00Z" and entry["bytes"] == path.stat().st_size
    assert entry["etag"] == '"v1"' and entry["licence"] == "CC0-1.0" and entry["stale"] is False
    assert mode(path) == 0o600 and mode(paths.datasets_dir() / "MANIFEST.json") == 0o600
    assert not [p for p in paths.datasets_dir().iterdir() if p.name.startswith(".tmp-")]
    assert store.fetch_lines("feed.txt") == frozenset({"a.example", "b.example"})


def test_fresh_copy_is_not_downloaded_again():
    register_dataset("feed.txt", URL, ttl=3600)
    http = FakeHttp().add("GET", URL, text="x\n", times=1)
    rt = Rt(http)
    store = DataStore(rt)
    store.fetch("feed.txt")
    rt.advance(minutes=30)
    store.fetch("feed.txt")
    assert len(http.calls) == 1


def test_conditional_get_with_etag_and_304():
    register_dataset("feed.txt", URL, ttl=3600)
    http = FakeHttp()
    http.add("GET", URL, text="v1\n", headers={"ETag": '"abc"', "Last-Modified": "Wed, 25 Nov 2026 03:06:59 GMT"}, times=1)
    http.add("GET", URL, status=304, match_headers={"If-None-Match": '"abc"'})
    rt = Rt(http)
    store = DataStore(rt)
    path = store.fetch("feed.txt")
    sha = manifest()["feed.txt"]["sha256"]
    rt.advance(hours=2)
    assert store.fetch("feed.txt") == path
    second = http.calls[1]["headers"]
    assert second["If-None-Match"] == '"abc"' and second["If-Modified-Since"] == "Wed, 25 Nov 2026 03:06:59 GMT"
    entry = manifest()["feed.txt"]
    assert entry["sha256"] == sha and entry["fetched_at"] == "2026-11-26T14:00:00Z" and entry["stale"] is False
    assert path.read_text() == "v1\n"


BAD_BODIES = [
    ("challenge", {"status": 200, "text": CHALLENGE}, {"expect": "lines"}),
    ("challenge_json", {"status": 200, "text": CHALLENGE}, {"expect": "json"}),
    ("short", {"status": 200, "text": "x"}, {"min_bytes": 100}),
    ("bad_json", {"status": 200, "text": "{not json"}, {"expect": "json"}),
    ("http429", {"status": 429, "text": "slow down"}, {}),
    ("http503", {"status": 503, "text": "down"}, {}),
    ("transport", {"error": NetworkError("ConnectionError contacting lists.example.test")}, {}),
    ("validator", {"status": 200, "text": "not-the-format\n"}, {"validate": lambda p: False}),
    ("validator_raises", {"status": 200, "text": "x\n"}, {"validate": lambda p: (_ for _ in ()).throw(ValueError("bad header"))}),
    ("pin", {"status": 200, "text": "tampered\n"}, {"pinned_sha256": "0" * 64}),
]


@pytest.mark.parametrize(("label", "route", "reg"), BAD_BODIES, ids=[b[0] for b in BAD_BODIES])
def test_failed_refresh_keeps_previous_copy(label, route, reg):
    good = '["good"]' if reg.get("expect") == "json" else "good-entry-" + "x" * 120 + "\n"
    validate = reg.pop("validate", None)
    pinned = reg.pop("pinned_sha256", "")
    register_dataset("feed.dat", URL, ttl=60, **reg)
    http = FakeHttp().add("GET", URL, text=good, times=1).add("GET", URL, **route)
    rt = Rt(http)
    store = DataStore(rt)
    path = store.fetch("feed.dat")
    sha = manifest()["feed.dat"]["sha256"]
    # tighten the registration after the good copy exists (validator / pin)
    DATASETS["feed.dat"]["validate"] = validate
    DATASETS["feed.dat"]["pinned_sha256"] = pinned
    rt.advance(hours=1)
    assert store.fetch("feed.dat") == path  # stale copy served
    assert path.read_text() == good
    entry = manifest()["feed.dat"]
    assert entry["sha256"] == sha and entry["stale"] is True
    assert not [p for p in paths.datasets_dir().iterdir() if p.name.startswith(".tmp-")]
    result = store.update("feed.dat")
    assert result.status == "failed" and result.old_sha256 == sha and result.reason
    assert path.read_text() == good


def test_challenge_without_previous_copy_raises():
    register_dataset("feed.txt", URL, expect="lines")
    store = DataStore(Rt(FakeHttp().add("GET", URL, status=403, text=CHALLENGE)))
    with pytest.raises(DatasetError) as err:
        store.fetch("feed.txt")
    assert not isinstance(err.value, DatasetUnavailable)
    assert err.value.reason_code == "challenge"
    assert not (paths.datasets_dir() / "feed.txt").exists()


def test_html_page_never_replaces_a_lines_dataset():
    register_dataset("feed.txt", URL, expect="lines")
    store = DataStore(Rt(FakeHttp().add("GET", URL, text="<html><body>maintenance</body></html>")))
    with pytest.raises(DatasetError, match="HTML page"):
        store.fetch("feed.txt")


# --------------------------------------------------------------------------------------
# safe_extract and archive datasets
# --------------------------------------------------------------------------------------


def _zip(tmp_path, members, name="a.zip"):
    path = tmp_path / name
    with zipfile.ZipFile(path, "w", compression=zipfile.ZIP_DEFLATED) as zf:
        for member, data in members:
            zf.writestr(member, data)
    return path


@pytest.mark.parametrize(
    ("member", "problem"),
    [("../evil.txt", "parent directory"), ("/etc/evil", "absolute path"), ("C:/win.txt", "absolute path"), ("a/../../evil", "parent directory")],
)
def test_safe_extract_rejects_unsafe_paths(tmp_path, member, problem):
    archive = _zip(tmp_path, [("ok.txt", "fine"), (member, "boom")])
    with pytest.raises(DatasetError, match=problem):
        safe_extract(archive, "zip", tmp_path / "out")
    assert not (tmp_path / "evil.txt").exists()


def test_safe_extract_rejects_symlinks_and_special_files(tmp_path):
    path = tmp_path / "link.zip"
    with zipfile.ZipFile(path, "w") as zf:
        info = zipfile.ZipInfo("link")
        info.create_system = 3
        info.external_attr = (stat.S_IFLNK | 0o777) << 16
        zf.writestr(info, "/etc/passwd")
    with pytest.raises(DatasetError, match="symlink"):
        safe_extract(path, "zip", tmp_path / "out")
    path2 = tmp_path / "fifo.zip"
    with zipfile.ZipFile(path2, "w") as zf:
        info = zipfile.ZipInfo("pipe")
        info.create_system = 3
        info.external_attr = (stat.S_IFIFO | 0o644) << 16
        zf.writestr(info, "")
    with pytest.raises(DatasetError, match="special file"):
        safe_extract(path2, "zip", tmp_path / "out2")


def test_safe_extract_rejects_zip_bombs_and_limits(tmp_path):
    bomb = _zip(tmp_path, [("zeros.bin", b"\0" * (2 * 1024 * 1024))], "bomb.zip")
    with pytest.raises(DatasetError, match="ratio"):
        safe_extract(bomb, "zip", tmp_path / "out")
    many = _zip(tmp_path, [(f"f{i}.txt", "x") for i in range(5)], "many.zip")
    with pytest.raises(DatasetError, match="members"):
        safe_extract(many, "zip", tmp_path / "out", max_members=3)
    big = _zip(tmp_path, [("a.txt", os.urandom(4096).hex())], "big.zip")
    with pytest.raises(DatasetError, match="expands beyond"):
        safe_extract(big, "zip", tmp_path / "out", max_total=1000)
    gz_bomb = tmp_path / "bomb.gz"
    gz_bomb.write_bytes(gzip.compress(b"\0" * (2 * 1024 * 1024)))
    with pytest.raises(DatasetError, match="ratio"):
        safe_extract(gz_bomb, "gz", tmp_path / "gzout")
    assert not list((tmp_path / "gzout").iterdir())  # partial output removed


def test_safe_extract_ok(tmp_path):
    archive = _zip(tmp_path, [("dir/list.txt", "a\nb\n"), ("readme.md", "hi")])
    out = safe_extract(archive, "zip", tmp_path / "out", member="dir/list.txt")
    assert out.read_text() == "a\nb\n"
    whole = safe_extract(archive, "zip", tmp_path / "all")
    assert (whole / "readme.md").read_text() == "hi"
    gz = tmp_path / "list.txt.gz"
    gz.write_bytes(gzip.compress(b"one\ntwo\n"))
    assert safe_extract(gz, "gz", tmp_path / "g").read_text() == "one\ntwo\n"
    bz = tmp_path / "list.txt.bz2"
    bz.write_bytes(bz2.compress(b"three\n"))
    assert safe_extract(bz, "bz2", tmp_path / "b").read_text() == "three\n"
    with pytest.raises(ValueError):
        safe_extract(gz, "rar", tmp_path / "r")


def test_archive_dataset_is_extracted_and_validated():
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as zf:
        zf.writestr("data/list.txt", "evil.example\n")
        zf.writestr("LICENSE", "CC0")
    register_dataset("zipped.txt", URL, archive="zip", member="data/list.txt", expect="lines")
    store = DataStore(Rt(FakeHttp().add("GET", URL, body=buf.getvalue())))
    path = store.fetch("zipped.txt")
    assert path.read_text() == "evil.example\n"
    entry = manifest()["zipped.txt"]
    assert entry["archive"] == "zip" and entry["body_sha256"] != entry["sha256"]
    register_dataset("gzipped.txt", URL + "?gz", archive="gz", expect="lines")
    store2 = DataStore(Rt(FakeHttp().add("GET", URL + "?gz", body=gzip.compress(b"a.example\n"))))
    assert store2.fetch_lines("gzipped.txt") == frozenset({"a.example"})


# --------------------------------------------------------------------------------------
# scan-time rules (A6 BR9)
# --------------------------------------------------------------------------------------


@pytest.mark.parametrize("kwargs", [{"large": True}, {"max_bytes": 50 * 1024 * 1024}])
def test_large_dataset_during_scan_is_unavailable(kwargs):
    register_dataset("big.json", URL, **kwargs)
    http = FakeHttp()
    with pytest.raises(DatasetUnavailable) as err:
        DataStore(Rt(http, in_scan=True)).fetch("big.json")
    assert err.value.reason_code == "dataset"
    assert "run v3lum data update big.json" in str(err.value)
    assert http.calls == []


def test_stale_large_copy_served_at_once_during_scan():
    register_dataset("big.txt", URL, large=True, ttl=3600)
    http = FakeHttp().add("GET", URL, text="x\n", times=1)
    rt = Rt(http)
    store = DataStore(rt)
    path = store.fetch("big.txt")  # outside a scan: downloaded
    rt.advance(days=2)
    rt.in_scan = True
    assert store.fetch("big.txt") == path
    assert len(http.calls) == 1  # no refresh during the scan
    assert manifest()["big.txt"]["stale"] is True
    info = store.info("big.txt")
    assert info.stale and info.present and info.age_hours == 48.0


class CappedHttp(FakeHttp):
    """Legacy client that honours max_bytes like the real HTTP client (truncated responses)."""

    def request(self, method, url, **kw):
        resp = super().request(method, url, **kw)
        cap = kw.get("max_bytes")
        if cap is not None and len(resp.content) > cap:
            return Response(resp.status, resp.url, resp.headers, resp.content[:cap], truncated=True)
        return resp


def test_scan_download_capped_at_5mb_and_remembered():
    register_dataset("grows.txt", URL, expect="lines")
    http = CappedHttp().add("GET", URL, body=b"a.example\n" * (600 * 1024))  # ~6 MB
    store = DataStore(Rt(http, in_scan=True))
    with pytest.raises(DatasetUnavailable, match="larger than 5 MB"):
        store.fetch("grows.txt")
    assert http.calls[0]["max_bytes"] == ds.LARGE_BYTES
    with pytest.raises(DatasetUnavailable):
        store.fetch("grows.txt")
    assert len(http.calls) == 1  # known large: never downloaded again during scans
    outside = DataStore(Rt(http))
    assert outside.fetch("grows.txt").stat().st_size > ds.LARGE_BYTES


def test_small_dataset_downloads_during_scan():
    register_dataset("small.txt", URL, expect="lines", max_bytes=1_000_000)
    store = DataStore(Rt(FakeHttp().add("GET", URL, text="a\n"), in_scan=True))
    assert store.fetch_lines("small.txt") == frozenset({"a"})


def test_offline_and_runtimeless_access():
    register_dataset("feed.txt", URL)
    with pytest.raises(DatasetUnavailable):
        DataStore(None).fetch("feed.txt")
    DataStore(Rt(FakeHttp().add("GET", URL, text="x\n"))).fetch("feed.txt")
    assert DataStore(None).fetch_text("feed.txt") == "x\n"  # local copy, never a download


# --------------------------------------------------------------------------------------
# active datasets and pins
# --------------------------------------------------------------------------------------


def test_active_dataset_pin_mismatch_refused_and_accept_new():
    register_dataset("wordlist.txt", URL, active=True, expect="lines")
    http = FakeHttp()
    http.add("GET", URL, text="admin\nlogin\n", times=2)
    http.add("GET", URL, text="admin\nlogin\nbackup\n")
    rt = Rt(http)
    store = DataStore(rt)
    with pytest.raises(DatasetUnavailable, match="installed only by"):
        store.fetch("wordlist.txt")
    first = store.update("wordlist.txt")
    assert first.status == "needs_accept" and first.old_sha256 == "" and "new dataset" in first.diff_summary
    with pytest.raises(DatasetUnavailable):
        store.fetch("wordlist.txt")  # staged, not installed
    accepted = store.update("wordlist.txt", accept_new=True, expect_sha256=first.new_sha256)
    assert accepted.status == "updated" and accepted.new_sha256 == first.new_sha256
    assert len(http.calls) == 1  # the reviewed staged bytes were installed, no second download
    assert store.fetch_lines("wordlist.txt") == frozenset({"admin", "login"})
    assert ds.pins_for("wordlist.txt") == {"user": first.new_sha256}
    assert mode(paths.datasets_dir() / "active.lock") == 0o600
    # upstream changes: same bytes again -> unchanged; new bytes -> needs_accept, old copy kept
    assert store.update("wordlist.txt").status == "unchanged"
    changed = store.update("wordlist.txt")
    assert changed.status == "needs_accept" and "+1 / -0 lines" in changed.diff_summary
    assert store.fetch_lines("wordlist.txt") == frozenset({"admin", "login"})
    # a tampered local copy no longer matches any pin
    (paths.datasets_dir() / "wordlist.txt").write_text("admin\nlogin\nrm -rf\n")
    with pytest.raises(DatasetUnavailable, match="does not match its pin"):
        store.fetch("wordlist.txt")


def test_active_dataset_with_bundled_pin_installs_directly(monkeypatch):
    body = "a\nb\n"
    sha = ds._sha256_bytes(body.encode())
    register_dataset("fingerprints.txt", URL, active=True, expect="lines")
    monkeypatch.setattr(ds, "_bundled_pin", lambda name: {"schema": ds.ACTIVE_LOCK_SCHEMA, "name": name, "sha256": sha})
    store = DataStore(Rt(FakeHttp().add("GET", URL, text=body)))
    result = store.update("fingerprints.txt")
    assert result == UpdateResult("fingerprints.txt", "updated", "", sha, result.diff_summary)
    assert store.fetch_text("fingerprints.txt") == body


def test_active_accept_rejects_unreviewed_hash():
    register_dataset("wl.txt", URL, active=True, expect="lines")
    store = DataStore(Rt(FakeHttp().add("GET", URL, text="x\n")))
    staged = store.update("wl.txt")
    result = store.update("wl.txt", accept_new=True, expect_sha256="f" * 64)
    assert result.status == "failed" and "reviewed hash" in result.reason
    assert staged.status == "needs_accept"


def test_bundled_active_lock_files_parse():
    for ref in (ds.resources.files("v3lum.data") / "active_locks").iterdir():
        if ref.name.endswith(".json"):
            data = json.loads(ref.read_text(encoding="utf-8"))
            assert data["schema"] == ds.ACTIVE_LOCK_SCHEMA and data["name"] == ref.name[:-5]
            assert len(data["sha256"]) == 64


# --------------------------------------------------------------------------------------
# index(), info(), DataView, hints, v1 API
# --------------------------------------------------------------------------------------


def test_index_in_memory_and_above_threshold(monkeypatch):
    lines = "\n".join(f"Host{i}.Example" for i in range(10)) + "\n# comment\n"
    register_dataset("hosts.txt", URL, expect="lines")
    store = DataStore(Rt(FakeHttp().add("GET", URL, text=lines)))
    small = store.index("hosts.txt")
    assert small.in_memory and len(small) == 10 and small.contains("host3.example") and "HOST9.example" in small
    monkeypatch.setattr(ds, "INDEX_MEMORY_LIMIT", 3)
    fresh = DataStore(Rt(FakeHttp()))
    big = fresh.index("hosts.txt")
    assert not big.in_memory and len(big) == 10
    sha = manifest()["hosts.txt"]["sha256"]
    assert big.db_path == paths.datasets_dir() / ".index" / f"{sha}.sqlite"
    assert big.contains("host7.example") and not big.contains("host70.example") and not big.contains("")
    assert mode(big.db_path) == 0o600
    assert fresh.index("hosts.txt") is big
    again = DataStore(Rt(FakeHttp())).index("hosts.txt")  # reuses the SQLite file
    assert not again.in_memory and len(again) == 10 and again.contains("host1.example")
    big.close()
    again.close()


def test_index_columns_json_and_csv():
    register_dataset("wl.json", URL, expect="json")
    register_dataset("wl.csv", URL + "?csv", expect="csv")
    http = FakeHttp()
    http.add("GET", URL, json={"name": "List of known resolvers", "type": "cidr", "list": ["8.8.8.8", "1.1.1.1"]})
    http.add("GET", URL + "?csv", text="indicator,kind\nEvil.Example,domain\n198.51.100.7,ip\n")
    store = DataStore(Rt(http))
    idx = store.index("wl.json", column="list")
    assert idx.contains("8.8.8.8") and len(idx) == 2
    csv_idx = store.index("wl.csv", column="indicator")
    assert csv_idx.contains("evil.example") and csv_idx.contains("198.51.100.7") and len(csv_idx) == 2
    with pytest.raises(DatasetError):
        store.index("wl.csv", column="missing")


def test_info_and_dataview_citations():
    register_dataset("feed.txt", URL, licence="CC-BY-4.0", terms_class="open", source="example.feed", expect="lines")
    rt = Rt(FakeHttp().add("GET", URL, text="a\n"))
    store = DataStore(rt)
    missing = store.info("feed.txt")
    assert missing.present is False and missing.sha256 == "" and missing.licence == "CC-BY-4.0"
    view = store.scoped()
    assert view.fetch_lines("feed.txt") == frozenset({"a"})
    view.fetch_text("feed.txt")
    info = store.info("feed.txt")
    assert info.present and info.sha256 and info.fetched_at == "2026-11-26T12:00:00Z" and info.age_hours == 0.0
    assert info.provider == "example" and info.source == "example.feed" and not info.stale
    view.bundled_lines("iana_tlds.txt")
    assert view.used == [
        {"name": "feed.txt", "sha256": info.sha256, "fetched_at": info.fetched_at, "licence": "CC-BY-4.0"},
        {"name": "iana_tlds.txt", "sha256": DataStore.bundled_sha256("iana_tlds.txt"), "fetched_at": "bundled", "licence": "IANA public data"},
    ]
    assert store.scoped().used == []  # one view per run


def test_first_run_hint_and_update_all():
    DATASETS.clear()  # only this test's datasets (module batches register essential datasets of their own)
    register_dataset("core.txt", URL, essential=True)
    register_dataset("extra.txt", URL + "?x")
    http = FakeHttp().add("GET", URL, text="x\n").add("GET", URL + "?x", text="y\n")
    store = DataStore(Rt(http))
    hint = store.first_run_hint()
    assert hint and "v3lum data update --essential" in hint and "core.txt" in hint
    results = store.update_all(essential_only=True)
    assert [r.name for r in results] == ["core.txt"] and results[0].status == "updated"
    assert store.first_run_hint() is None
    statuses = {r.name: r.status for r in store.update_all()}
    assert statuses == {"core.txt": "unchanged", "extra.txt": "updated"}


def test_update_unknown_and_unchanged():
    assert DataStore(Rt(FakeHttp())).update("nope.txt").status == "failed"
    register_dataset("feed.txt", URL)
    http = FakeHttp().add("GET", URL, text="same\n")
    store = DataStore(Rt(http))
    assert store.update("feed.txt").status == "updated"
    assert store.update("feed.txt").status == "unchanged"


def test_v1_positional_api_and_cached_info():
    store = DataStore(Rt(FakeHttp().add("GET", URL, json={"a": 1}).add("GET", URL + "?l", text="X.example\n#c\n")))
    assert store.fetch_json("adhoc.json", URL, ttl=10) == {"a": 1}  # unregistered name + URL (v1)
    assert store.fetch_lines("adhoc.txt", URL + "?l") == frozenset({"x.example"})
    names = {d["name"] for d in store.cached_info()}
    assert names == {"adhoc.json", "adhoc.txt"}
    with pytest.raises(DatasetError, match="not registered"):
        store.fetch("never.txt")


def test_through_real_runtime():
    from tests.fakes import make_runtime

    register_dataset("feed.txt", URL, expect="lines")
    http = FakeHttp().add("GET", URL, text="evil.example\n")
    rt = make_runtime(http)
    assert rt.data.fetch_lines("feed.txt") == frozenset({"evil.example"})
    assert rt.data.scoped().index("feed.txt").contains("EVIL.example")


def test_error_in_200_marker_body_never_replaces_a_dataset():
    """AR10/P321 (audit of wave 1): a provider error marker on an HTTP-200 JSON answer (a quota
    message that is valid JSON) is classified before the install - the previous copy stays and is
    served stale; the refresh fails with the marker's reason."""
    from tests.fakes import make_runtime, test_provider

    marker = {"id": "lists_quota", "statuses": [200], "json_path": "error", "equals": "quota exceeded",
              "maps_to": "quota", "reason": "Lists: daily quota exhausted"}
    with test_provider("lists_src", hosts=("lists.example.test",), sources=("feed",), error_markers=[marker]):
        register_dataset("feed.json", URL, ttl=60, expect="json", provider="lists_src", source="lists_src.feed",
                         licence="CC0-1.0", terms_class="open")
        http = FakeHttp().add("GET", URL, json={"items": ["good"]}, times=1).add("GET", URL, json={"error": "quota exceeded"})
        rt = make_runtime(http)
        path = rt.data.fetch("feed.json")
        good = path.read_text(encoding="utf-8")
        sha = manifest()["feed.json"]["sha256"]
        rt.clock.advance(3600)
        assert rt.data.fetch("feed.json") == path  # the stale copy, never the quota message
        assert path.read_text(encoding="utf-8") == good
        assert manifest()["feed.json"]["sha256"] == sha and manifest()["feed.json"]["stale"] is True
        result = rt.data.update("feed.json")
        assert result.status == "failed" and "quota" in result.reason.lower()
        assert path.read_text(encoding="utf-8") == good


def test_dataset_errors_report_unregistered_sources():
    register_dataset("nosrc.txt", URL)
    register_dataset("badsrc.txt", URL + "?b", licence="CC0-1.0", source="nobody.feed")
    errors = ds.dataset_errors()
    assert any("nosrc.txt: no licence" in e for e in errors)
    assert any("nosrc.txt: no registry source" in e for e in errors)
    assert any("badsrc.txt: source 'nobody.feed'" in e for e in errors)


# --------------------------------------------------------------------------------------
# review hardening: reader memo, corrupt downloads, URL provenance, bundled paths, accept flow
# --------------------------------------------------------------------------------------


def test_text_json_and_lines_readers_never_share_a_memo_entry():
    register_dataset("mixed.json", URL, expect="json")
    store = DataStore(Rt(FakeHttp().add("GET", URL, text='["x", "y"]')))
    assert store.fetch_text("mixed.json") == '["x", "y"]'
    assert store.fetch_json("mixed.json") == ["x", "y"]  # not the text read just before
    assert store.fetch_lines("mixed.json") == frozenset({'["x",'})
    assert store.fetch_json("mixed.json") == ["x", "y"]


@pytest.mark.parametrize(
    ("label", "reg", "bad"),
    [
        ("zip_without_member_gets_html", {"archive": "zip", "expect": "lines"}, {"text": "<html><body>maintenance</body></html>"}),
        ("zip_without_member_gets_garbage", {"archive": "zip"}, {"body": b"PK\x03\x04 not really a zip"}),
        ("deeply_nested_json", {"expect": "json"}, {"text": "[" * 50000 + "]" * 50000}),
        ("html_for_a_text_dataset", {"expect": "text"}, {"text": "<!DOCTYPE html><html><body>error</body></html>"}),
    ],
    ids=lambda v: v if isinstance(v, str) else "",
)
def test_corrupt_refresh_is_a_dataset_error_and_keeps_the_previous_copy(label, reg, bad):
    good = io.BytesIO()
    if reg.get("archive") == "zip":
        with zipfile.ZipFile(good, "w") as zf:
            zf.writestr("list.txt", "good.example\n")
        body = {"body": good.getvalue()}
    else:
        body = {"text": '["good"]' if reg.get("expect") == "json" else "good text\n"}
    register_dataset("fragile.dat", URL, ttl=60, **reg)
    http = FakeHttp().add("GET", URL, times=1, **body).add("GET", URL, **bad)
    rt = Rt(http)
    store = DataStore(rt)
    path = store.fetch("fragile.dat")
    before = path.read_bytes()
    rt.advance(hours=1)
    assert store.fetch("fragile.dat") == path  # stale copy served, never an unexpected exception
    assert path.read_bytes() == before and manifest()["fragile.dat"]["stale"] is True
    result = store.update("fragile.dat")
    assert result.status == "failed" and result.reason
    assert not [p for p in paths.datasets_dir().iterdir() if p.name.startswith(".tmp-")]


def test_corrupt_download_without_previous_copy_raises_dataset_error():
    register_dataset("z.txt", URL, archive="zip", expect="lines")
    with pytest.raises(DatasetError, match="corrupt zip"):
        DataStore(Rt(FakeHttp().add("GET", URL, text="<html>nope</html>"))).fetch("z.txt")


def test_registered_name_cannot_be_fetched_from_another_url():
    register_dataset("feed.txt", URL)
    http = FakeHttp()
    with pytest.raises(DatasetError, match="another URL"):
        DataStore(Rt(http)).fetch_text("feed.txt", "https://elsewhere.example.test/feed.txt")
    assert http.calls == []
    http.add("GET", URL, text="x\n")
    assert DataStore(Rt(http)).fetch_text("feed.txt", URL) == "x\n"  # the registered URL itself is fine (v1 calls)


@pytest.mark.parametrize("name", ["../core/dns.py", "/etc/passwd", "noise/../../config.py", "C:/x.txt", "a\x00b", ""])
def test_bundled_names_stay_inside_the_package_data(name):
    with pytest.raises(ValueError):
        DataStore.bundled_text(name)
    with pytest.raises(ValueError):
        DataStore.bundled_path(name)
    assert DataStore.bundled_exists(name) is False


def test_bundled_subdirectories_still_work():
    assert DataStore.bundled_exists("noise/core.json")
    assert DataStore.bundled_json("noise/core.json")["schema"] == "v3lum.noise_kinds/1"


def test_accept_new_needs_the_diff_summary_first():
    """An active dataset is accepted only after its diff summary: accept_new alone stages it."""
    register_dataset("tpl.txt", URL, active=True, expect="lines")
    http = FakeHttp().add("GET", URL, text="a\nb\n", times=1)
    store = DataStore(Rt(http))
    first = store.update("tpl.txt", accept_new=True)
    assert first.status == "needs_accept" and "new dataset" in first.diff_summary
    with pytest.raises(DatasetUnavailable):
        store.fetch("tpl.txt")  # nothing installed blind
    second = store.update("tpl.txt", accept_new=True)  # accepts the staged, reviewed bytes
    assert second.status == "updated" and second.new_sha256 == first.new_sha256
    assert len(http.calls) == 1
    assert store.fetch_lines("tpl.txt") == frozenset({"a", "b"})


def test_accept_new_with_the_reviewed_hash_installs_directly():
    body = "x\ny\n"
    register_dataset("tpl2.txt", URL, active=True, expect="lines")
    store = DataStore(Rt(FakeHttp().add("GET", URL, text=body)))
    result = store.update("tpl2.txt", accept_new=True, expect_sha256=ds._sha256_bytes(body.encode()))
    assert result.status == "updated"
    assert ds.pins_for("tpl2.txt") == {"user": result.new_sha256}


def test_index_formats_of_one_dataset_never_share_a_sqlite_file(monkeypatch):
    register_dataset("both.json", URL, expect="json")
    store = DataStore(Rt(FakeHttp().add("GET", URL, text='[\n"alpha",\n"beta",\n"gamma"\n]\n')))
    monkeypatch.setattr(ds, "INDEX_MEMORY_LIMIT", 1)
    as_json = store.index("both.json")
    as_lines = store.index("both.json", fmt="lines")
    assert not as_json.in_memory and not as_lines.in_memory and as_json.db_path != as_lines.db_path
    assert as_json.contains("beta") and not as_lines.contains("beta")
    as_json.close()
    as_lines.close()
    assert not [p for p in (paths.datasets_dir() / ".index").iterdir() if p.name.startswith(".tmp-")]


def test_unreadable_local_copies_are_dataset_errors():
    register_dataset("broken.json", URL, expect="json")
    register_dataset("broken.csv", URL + "?csv", expect="csv")
    (paths.datasets_dir() / "broken.json").write_text("{not json")
    (paths.datasets_dir() / "broken.csv").write_text("col\n" + "x" * 200_000 + "\n")  # beyond the csv field limit
    store = DataStore(None)  # local copies only
    with pytest.raises(DatasetError, match="not valid JSON"):
        store.fetch_json("broken.json")
    with pytest.raises(DatasetError, match="cannot index"):
        store.index("broken.csv", column="col")


def test_active_dataset_is_never_refreshed_mid_scan():
    register_dataset("wl_scan.txt", URL, active=True, expect="lines")
    http = FakeHttp()
    result = DataStore(Rt(http, in_scan=True)).update("wl_scan.txt", accept_new=True)
    assert result.status == "failed" and "never mid-scan" in result.reason
    assert http.calls == []
