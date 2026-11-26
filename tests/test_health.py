"""Source health and A3 demotion: each trigger and its recovery, persistence (0600, tolerant load),
doctor notices and the P331 7-day auto-disable."""

from __future__ import annotations

import datetime as _dt
import json
import os
import stat

import pytest

from v3lum import paths
from v3lum.core.health import HealthState
from v3lum.core.models import Status
from v3lum.core.module import HealthResult

DAY = _dt.timedelta(days=1)
T0 = _dt.datetime(2026, 11, 1, 9, 0, tzinfo=_dt.timezone.utc)


@pytest.fixture()
def state(tmp_path):
    return HealthState(tmp_path / "health.json", autosave=False)


def test_p50_demotion_needs_20_runs_and_lifts_when_runs_get_faster(state):
    for _ in range(19):
        state.record_run("slow_source", 12.0, Status.OK)
    assert not state.is_demoted("slow_source")  # 19 runs: not enough evidence
    state.record_run("slow_source", 12.0, "ok")
    assert state.is_demoted("slow_source")
    assert "p50 12.0 s over 20 runs" in state.demotion_reasons("slow_source")[0]
    for _ in range(21):
        state.record_run("slow_source", 0.5, "ok")
    assert state.p50("slow_source") <= 10.0
    assert not state.is_demoted("slow_source")


def test_p50_ignores_runs_that_never_reached_the_source(state):
    for _ in range(25):
        state.record_run("keyless", 30.0, "needs_key")
        state.record_run("keyless", 30.0, Status.SKIPPED)
    assert state.p50("keyless") is None and not state.is_demoted("keyless")


def test_votes_demotion_after_10_votes_over_30_percent_and_recovery(state):
    state.record_votes("noisy", 5, 9)
    assert not state.is_demoted("noisy")  # fewer than 10 votes
    state.record_votes("noisy", 3, 10)
    assert not state.is_demoted("noisy")  # exactly 30% is not above 30%
    state.record_votes("noisy", 4, 10)
    assert state.is_demoted("noisy")
    assert "4/10 findings marked wrong" in state.demotion_reasons("noisy")[0]
    state.record_votes("noisy", 4, 20)  # totals, not increments
    assert not state.is_demoted("noisy")
    with pytest.raises(ValueError):
        state.record_votes("noisy", 5, 4)
    with pytest.raises(ValueError):
        state.record_votes("noisy", -1, 4)


def test_three_failed_checks_demote_and_a_passing_check_restores(state):
    state.record_check("flaky", "dead")
    state.record_check("flaky", HealthResult("blocked", "challenge page"))
    assert not state.is_demoted("flaky")
    state.record_check("flaky", "quota")  # neutral: neither a failure nor a pass
    assert not state.is_demoted("flaky")
    state.record_check("flaky", False)
    assert state.is_demoted("flaky")
    assert "3 consecutive doctor --sources runs" in state.demotion_reasons("flaky")[0]
    state.record_check("flaky", HealthResult("ok"))
    assert not state.is_demoted("flaky")
    assert [c["result"] for c in state.last_checks("flaky", 3)] == ["quota", "dead", "ok"]
    assert state.last_checks("flaky", 1)[0]["detail"] == ""
    with pytest.raises(ValueError):
        state.record_check("flaky", "")


def test_blocked_on_5_consecutive_runs_and_recovery(state):
    for _ in range(4):
        state.record_run("walled", 0.3, Status.BLOCKED)
    assert not state.is_demoted("walled")
    state.record_run("walled", 0.3, "error")  # neutral: does not reset the streak
    state.record_run("walled", 0.3, "blocked")
    assert state.is_demoted("walled")
    assert "BLOCKED on 5 consecutive runs" in state.demotion_reasons("walled")
    state.record_run("walled", 0.3, Status.EMPTY)  # answered again
    assert not state.is_demoted("walled")


def test_short_circuited_and_guard_blocked_runs_never_reached_the_source(state):
    """BLOCKED 'circuit' (host already short-circuited in the run) and 'hostile_host' (a redirect
    refused by the contact guard) say nothing about the source: no streak, no duration."""
    for _ in range(4):
        state.record_run("walled", 0.3, "blocked", reason_code="challenge")
    for _ in range(6):
        state.record_run("walled", 0.0, "blocked", reason_code="circuit")
    state.record_run("walled", 0.0, Status.BLOCKED, reason_code="hostile_host")
    assert not state.is_demoted("walled") and state.stats("walled")["blocked_streak"] == 4
    assert state.stats("walled")["runs"] == 11 and len(state.stats("walled")["durations"]) == 4

    class Result:  # a ModuleResult-like object carries its own reason code
        status = Status.BLOCKED
        reason_code = "circuit"

    state.record_run("walled", 0.0, Result())
    assert state.stats("walled")["blocked_streak"] == 4
    state.record_run("walled", 0.3, "blocked", reason_code="geo_block")
    assert state.is_demoted("walled")


def test_refresh_adopts_another_writer_but_keeps_unsaved_changes(tmp_path):
    path = tmp_path / "health.json"
    mine = HealthState(path)  # autosave
    mine.record_run("mod_a", 1.0, "ok")
    other = HealthState.load(path)
    other.record_votes("mod_b", 4, 10)
    assert "mod_b" not in mine.modules()
    assert mine.refresh() is True and mine.is_demoted("mod_b")
    assert mine.refresh() is False  # nothing new
    # a record adopts the other writer's records before it saves: nothing is dropped
    other.record_check("mod_c", "dead")
    mine.record_run("mod_a", 1.0, "ok")
    assert sorted(HealthState.load(path).modules()) == ["mod_a", "mod_b", "mod_c"]
    # unsaved changes of an instance without autosave are never replaced by the file, and its save
    # keeps the records another writer saved meanwhile (only the modules it changed come from memory)
    batch = HealthState.load(path, autosave=False)
    batch.record_run("mod_d", 1.0, "ok")
    batch.record_run("mod_a", 1.0, "ok")
    other.record_run("mod_e", 1.0, "ok")
    other.record_run("mod_a", 1.0, "ok")
    assert batch.refresh() is False and "mod_d" in batch.modules()
    assert batch.save()
    disk = HealthState.load(path)
    assert {"mod_a", "mod_b", "mod_c", "mod_d", "mod_e"} <= set(disk.modules())
    assert disk.stats("mod_a")["runs"] == 3  # the batch's own record of mod_a wins over the file's
    batch.reset("mod_e")
    other.record_run("mod_f", 1.0, "ok")
    assert batch.save() and "mod_e" not in HealthState.load(path).modules() and "mod_f" in HealthState.load(path).modules()


def test_concurrent_instances_on_one_file_keep_every_record(tmp_path):
    """Two instances (two processes in real life) writing the same file never drop records."""
    import threading

    path = tmp_path / "health.json"
    first, second = HealthState(path), HealthState(path)

    def worker(state: HealthState, name: str) -> None:
        for _ in range(40):
            state.record_run(name, 0.1, "ok")

    threads = [threading.Thread(target=worker, args=(s, n)) for s, n in ((first, "one"), (second, "two"), (first, "one"), (second, "two"))]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    disk = HealthState.load(path)
    assert disk.stats("one")["runs"] == 80 and disk.stats("two")["runs"] == 80
    if os.name == "posix":
        lock = tmp_path / "health.json.lock"
        assert lock.is_file() and stat.S_IMODE(lock.stat().st_mode) == 0o600


def test_every_save_changes_the_stamp(tmp_path):
    path = tmp_path / "health.json"
    state = HealthState(path)
    state.record_run("same", 1.0, "ok")
    first = state.stamp
    state.record_run("same", 1.0, "ok")  # same size possible: the new inode still changes the stamp
    assert state.stamp != first and state.stamp == HealthState.file_stamp(path)


def test_unknown_module_is_not_demoted(state):
    assert not state.is_demoted("never_seen") and state.demotion_reasons("never_seen") == []
    assert state.stats("never_seen") == {} and state.last_checks("never_seen") == []


def test_persistence_roundtrip_is_0600(tmp_path):
    path = tmp_path / "health.json"
    first = HealthState(path)  # autosave
    first.record_run("mod_a", 2.0, "ok")
    first.record_votes("mod_a", 1, 3)
    first.record_check("mod_a", "ok")
    assert path.is_file()
    if os.name == "posix":
        assert stat.S_IMODE(path.stat().st_mode) == 0o600
    data = json.loads(path.read_text(encoding="utf-8"))
    assert data["schema"] == "v3lum.health/1" and "mod_a" in data["modules"]
    again = HealthState.load(path)
    assert again.stats("mod_a")["runs"] == 1 and again.stats("mod_a")["votes"]["total"] == 3
    assert again.p50("mod_a") == 2.0 and again.errors == []
    assert again.stamp == HealthState.file_stamp(path)


def test_default_path_is_the_v3lum_home():
    state = HealthState.load()
    assert state.path == paths.home() / "health.json"
    assert state.modules() == [] and state.errors == []


@pytest.mark.parametrize("content", ["{broken", '{"modules": 7}', "[]", '"text"'])
def test_load_tolerates_corrupt_files(tmp_path, content):
    path = tmp_path / "health.json"
    path.write_text(content, encoding="utf-8")
    state = HealthState.load(path)
    assert state.modules() == [] and state.errors
    state.record_run("mod_b", 1.0, "ok")  # the next save overwrites the corrupt file
    assert HealthState.load(path).modules() == ["mod_b"]


def test_load_drops_malformed_module_records(tmp_path):
    path = tmp_path / "health.json"
    path.write_text(json.dumps({"modules": {"good": {"durations": [1.0, "x", -2, 3.0], "runs": 2}, "bad": "nope", "": {}}}), encoding="utf-8")
    state = HealthState.load(path)
    assert state.modules() == ["good"] and state.stats("good")["durations"] == [1.0, 3.0]
    assert len(state.errors) == 2


def test_save_failure_is_recorded_not_raised(tmp_path):
    blocker = tmp_path / "file"
    blocker.write_text("x", encoding="utf-8")
    state = HealthState(blocker / "health.json")
    state.record_run("mod_c", 1.0, "ok")  # the parent is a file: cannot save
    assert state.errors and "cannot save" in state.errors[-1]


def test_reset_one_or_all(state):
    for name in ("one", "two"):
        for _ in range(5):
            state.record_run(name, 1.0, "blocked")
    state.reset("one")
    assert not state.is_demoted("one") and state.is_demoted("two")
    state.reset()
    assert state.modules() == []


def test_notices_list_demoted_modules(state):
    for _ in range(5):
        state.record_run("walled", 0.2, "blocked")
    state.record_run("fine", 0.2, "ok")
    notices = state.notices()
    assert len(notices) == 1 and notices[0].startswith("walled: left the default set (BLOCKED on 5 consecutive runs)")
    assert "-M" in notices[0] and "returns once it passes again" in notices[0]
    assert state.notices(["fine"]) == []


def test_seven_consecutive_failed_days_auto_disable_and_recovery(state):
    for day in range(6):
        state.record_check("spec_source", "dead", now=T0 + day * DAY)
    assert state.consecutive_failed_days("spec_source") == 6 and not state.auto_disabled("spec_source")
    state.record_check("spec_source", "blocked", now=T0 + 6 * DAY)
    assert state.consecutive_failed_days("spec_source") == 7 and state.auto_disabled("spec_source")
    assert any("7 consecutive days" in n for n in state.notices())
    state.record_check("spec_source", "ok", now=T0 + 7 * DAY)
    assert state.consecutive_failed_days("spec_source") == 0 and not state.auto_disabled("spec_source")


def test_a_day_without_failure_breaks_the_day_streak(state):
    for day in (0, 1, 2, 4, 5, 6, 7):  # day 3 missing
        state.record_check("gappy", "dead", now=T0 + day * DAY)
    assert state.consecutive_failed_days("gappy") == 4
    assert not state.auto_disabled("gappy")
    assert state.auto_disabled("gappy", days=4)


def test_concurrent_records_are_all_counted(state):
    import threading

    def worker() -> None:
        for _ in range(50):
            state.record_run("busy", 0.1, "ok")

    threads = [threading.Thread(target=worker) for _ in range(4)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    assert state.stats("busy")["runs"] == 200
