"""tor_exit_history (P040 c3-c6): dated Tor exit answers from local CollecTor archives and mthcht.

Fixtures in tests/fixtures/tor_exit_history/: a slice of the real CollecTor archive
exit-list-2026-10.tar.xz (the first member, 2026-10-31 04:12:27, trimmed to 4 relays with
documentation addresses, re-packed as tar.xz), a recent tordnsel exit list, and the first records
of the mthcht tor_nodes_history.json made valid JSON (nicknames, host names and one AS name
pseudonymised; the rDNS 'host' field is never kept by the module).
"""

from __future__ import annotations

import io
import lzma
import tarfile

import pytest

from tests.fakes import FakeHttp, make_runtime, module_fixture, run_module
from v3lum import paths
from v3lum.core.datasets import DATASETS
from v3lum.core.models import Severity, Status
from v3lum.modules.ip_network import ip_offline_db, tor_exit_history
from v3lum.modules.ip_network.tor_exit_history import (
    COLLECTOR_URL,
    MTHCHT_HISTORY,
    MTHCHT_URL,
    ArchiveError,
    TorExitHistory,
    collector_name,
    index_tordnsel,
    iter_tar_xz,
    register_collector_month,
)

FIXTURES = "tests/fixtures/tor_exit_history"
OCT = collector_name(2026, 10)


@pytest.fixture(autouse=True)
def months(monkeypatch):
    monkeypatch.setattr(ip_offline_db, "TEST_PUBLIC_LABELS", frozenset({"documentation"}))
    register_collector_month(2026, 10)
    register_collector_month(2026, 11, current=True)
    monkeypatch.setitem(DATASETS[OCT], "min_bytes", 10)  # the slice is 448 bytes (a real month is 8-15 MB)
    monkeypatch.setitem(DATASETS[MTHCHT_HISTORY], "min_bytes", 10)


def archive_bytes() -> bytes:
    with open(f"{FIXTURES}/collector_2026-10_slice.tar.xz", "rb") as fh:
        return fh.read()


def runtime_with(*, october: bool = True, mthcht: bool = False, http: FakeHttp | None = None):
    """A runtime where `v3lum data update` already installed the October archive / mthcht file."""
    http = http or FakeHttp()
    if october:
        http.add("GET", COLLECTOR_URL.format(y=2026, m=10), body=archive_bytes())
    if mthcht:
        assert module_fixture(TorExitHistory, "mthcht_tor_nodes_history_ok.json")["total_ips"] == 296101
        with open(f"{FIXTURES}/mthcht_tor_nodes_history_ok.json", "rb") as fh:
            http.add("GET", MTHCHT_URL, body=fh.read())
    rt = make_runtime(http)
    if october:
        assert rt.data.update(OCT).ok
    if mthcht:
        assert rt.data.update(MTHCHT_HISTORY).ok
    http.calls.clear()
    return http, rt


def run(rt, entity: str, *days: str):
    """Run with setting tor_exit_history_dates (the date the IOC carries, given by the analyst)."""
    rt.config.settings["tor_exit_history_dates"] = list(days)
    return run_module(TorExitHistory, entity, runtime=rt)


def answer(res, source: str, day: str) -> dict:
    return next(a for a in res.attributes["tor_exit_history"] if a["source"].startswith(source) and a["date"] == day)


def test_metadata():
    cls = TorExitHistory
    assert (cls.terms, cls.disclosure, cls.hosts) == ("open", "none", ())
    assert cls.sources == ("torproject.collector", "github.tor_exit_history_mthcht")
    reg = DATASETS[OCT]
    assert reg["large"] is True and reg["url"].endswith("/archive/exit-lists/exit-list-2026-10.tar.xz")
    assert DATASETS[MTHCHT_HISTORY]["large"] is True  # 54 MB: `v3lum data update` only (c4)
    assert "tor_exit_history_dates" in cls.settings
    assert cls.default_enabled is False  # opt-in: needs the event date and the downloaded history


def test_no_date_is_not_applicable():
    res = run_module(TorExitHistory, "ipv4:192.0.2.1", FakeHttp())
    assert res.status is Status.SKIPPED and res.reason_code == "not_applicable"


def test_was_an_exit_on_the_date_prints_date_and_source():
    http, rt = runtime_with()
    res = run(rt, "ipv4:192.0.2.1", "2026-10-31")
    ans = answer(res, "CollecTor", "2026-10-31")
    assert ans["state"] == "was_exit" and ans["text"] == "was an exit on 2026-10-31, CollecTor"
    assert ans["observed_first"] == "2026-10-31 03:27:36" and ans["fingerprints"] == ["5F44E683AFAF2E7D15AED060841CD34935E4A4D0"]
    (finding,) = res.findings
    assert finding.severity is Severity.LOW and finding.attack == ["T1090.003"] and "context_only" in finding.tags
    assert "was an exit on 2026-10-31, CollecTor" in finding.description
    assert any("timestamp=2026-10-31" in url for _l, url in res.links)  # dated ExoneraTor manual link
    assert not http.calls  # local only: nothing downloaded or sent during the run


def test_no_exit_record_on_a_downloaded_day():
    _http, rt = runtime_with()
    res = run(rt, "ipv4:192.0.2.1", "2026-10-29")
    ans = answer(res, "CollecTor", "2026-10-29")
    assert ans["state"] == "not_exit_on_date" and "month downloaded" in ans["text"]
    assert res.status is Status.OK and not res.findings


def test_month_not_downloaded_reads_history_not_downloaded_never_not_an_exit():
    http, rt = runtime_with(october=False)
    res = run(rt, "ipv4:192.0.2.1", "2026-10-31")
    assert res.status is Status.UNAVAILABLE and res.reason_code == "dataset"
    assert "history not downloaded (run v3lum data update" in res.error and "could not verify" in res.error
    assert not http.calls  # never downloaded during a run (A6 BR9)


def test_large_archives_are_never_downloaded_during_a_scan():
    http = FakeHttp()
    rt = make_runtime(http)
    rt.in_scan = True
    with pytest.raises(Exception, match="never downloaded during a scan"):
        rt.data.fetch(OCT)
    assert not http.calls


def test_ipv6_could_not_verify_for_collector_and_mthcht_relay_periods():
    _http, rt = runtime_with(mthcht=True)
    res = run(rt, "ipv6:2001:db8:ff::1", "2024-01-15")
    assert answer(res, "CollecTor", "2024-01-15")["state"] == "could_not_verify"
    mth = answer(res, "mthcht", "2024-01-15")
    assert mth["state"] == "relay_on_date" and "role at last sighting: unknown" in mth["text"]
    assert res.findings[0].severity is Severity.INFO


def test_mthcht_relay_with_exit_role_is_info_and_host_is_not_kept():
    _http, rt = runtime_with(mthcht=True)
    res = run(rt, "ipv4:192.0.2.13", "2026-10-30")
    assert answer(res, "mthcht", "2026-10-30")["text"] == "was a Tor relay on 2026-10-30 (role at last sighting: exit), mthcht Tor history"
    assert answer(res, "CollecTor", "2026-10-30")["state"] == "not_exit_on_date"
    assert "example.net" not in str(res.to_dict())  # rDNS host never kept
    assert all(f.severity is Severity.INFO for f in res.findings)


def test_outside_window_and_future_dates():
    _http, rt = runtime_with(mthcht=True)
    res = run(rt, "ipv4:192.0.2.12", "2023-09-01")
    assert answer(res, "CollecTor", "2023-09-01")["state"] == "outside_window"
    assert answer(res, "mthcht", "2023-09-01")["state"] == "relay_on_date"
    future = run(rt, "ipv4:192.0.2.12", "2031-01-01")
    assert future.status is Status.ERROR and "not in the future" in future.error


def test_tordnsel_index_and_member_days():
    with open(f"{FIXTURES}/collector_recent_ok.txt", "rb") as fh:
        index = index_tordnsel(fh.read())
    assert index["192.0.2.6"]["days"]["2026-11-26"] == ["2026-11-26 03:19:56", "2026-11-26 03:19:56"]
    assert set(index["192.0.2.6"]["fingerprints"]) == {"D73732E12351DDEF9C62AF38D7BBAA9958C0891C"}
    assert index["192.0.2.8"]["days"] == {"2026-11-24": ["2026-11-24 15:34:41", "2026-11-24 15:34:41"]}
    assert tor_exit_history.member_day("exit-list-2026-10/31/2026-10-31-04-12-27") == "2026-10-31"
    assert tor_exit_history.member_day("exit-list-2026-10/31/2026-09-30-04-12-27") is None


# ------------------------------------------------------------------ archive safety (c3)
def _tar_xz(members: list[tuple[str, bytes, bytes]]) -> bytes:
    raw = io.BytesIO()
    with tarfile.open(fileobj=raw, mode="w") as tf:
        for name, kind, data in members:
            info = tarfile.TarInfo(name)
            if kind == b"sym":
                info.type = tarfile.SYMTYPE
                info.linkname = "/etc/passwd"
                tf.addfile(info)
            else:
                info.size = len(data)
                tf.addfile(info, io.BytesIO(data))
    return lzma.compress(raw.getvalue())


@pytest.mark.parametrize(
    ("members", "caps", "message"),
    [
        ([("../evil", b"f", b"x")], {}, "unsafe member name"),
        ([("/abs/evil", b"f", b"x")], {}, "unsafe member name"),
        ([("exit-list-2026-10/31/link", b"sym", b"")], {}, "link or special file"),
        ([(f"exit-list-2026-10/31/m{i}", b"f", b"x") for i in range(4)], {"max_members": 3}, "too many members"),
        ([("exit-list-2026-10/31/big", b"f", b"x" * 64)], {"max_member_bytes": 32}, "too large"),
        ([(f"exit-list-2026-10/31/m{i}", b"f", b"x" * 40) for i in range(3)], {"max_total": 100}, "expands beyond"),
    ],
)
def test_archive_caps_and_unsafe_members(tmp_path, members, caps, message):
    path = tmp_path / "a.tar.xz"
    path.write_bytes(_tar_xz(members))
    with pytest.raises(ArchiveError, match=message):
        list(iter_tar_xz(path, **caps))


def test_corrupt_local_archive_is_could_not_verify():
    _http, rt = runtime_with()
    (paths.datasets_dir() / OCT).write_bytes(b"\xfd7zXZ\x00 not really")
    res = run(rt, "ipv4:192.0.2.1", "2026-10-30")
    assert res.status is Status.UNAVAILABLE and "unreadable" in res.error and not res.findings


def test_data_update_rejects_a_foreign_archive():
    http = FakeHttp().add("GET", COLLECTOR_URL.format(y=2026, m=10), body=_tar_xz([("other/file.txt", b"f", b"hello")]))
    rt = make_runtime(http)
    result = rt.data.update(OCT)
    assert result.status == "failed" and "not a CollecTor exit-list archive" in result.reason
