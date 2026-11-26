"""``v3lum data`` (WP18, AR10): list with licence/terms/age/stale/size, update through
DataStore.update (named, --essential, every registered one), diff summaries of active (pinned)
datasets and --accept-new (staged copy, interactive confirmation, reviewed hash). FakeHttp only."""

from __future__ import annotations

import io
import json

import pytest

from tests.fakes import FakeClock, FakeHttp
from v3lum import paths
from v3lum.cli import main
from v3lum.core.datasets import DATASETS, register_dataset

URL = "https://lists.example.test/feed.txt"


@pytest.fixture(autouse=True)
def _env(monkeypatch):
    monkeypatch.setenv("COLUMNS", "250")
    saved = dict(DATASETS)
    DATASETS.clear()  # only this file's datasets (module files register theirs at import time)
    yield
    DATASETS.clear()
    DATASETS.update(saved)


@pytest.fixture()
def http(monkeypatch):
    from v3lum.app import App
    from v3lum.core.context import Runtime

    fake = FakeHttp()
    clock = FakeClock()
    fake.clock = clock

    def runtime(self, listener=None):
        return Runtime(self.config, transport=fake, clock=clock, no_cache=True, offline=self.offline, listener=listener)

    monkeypatch.setattr(App, "runtime", runtime)
    return fake


class _Tty(io.StringIO):
    def isatty(self) -> bool:  # noqa: D401 - a terminal that answers from the buffer
        return True


def _rows(capsys) -> dict[str, dict]:
    capsys.readouterr()
    assert main(["data", "list", "--json"]) == 0
    return {r["name"]: r for r in json.loads(capsys.readouterr().out)}


def test_update_named_dataset_then_list(http, capsys):
    register_dataset("wp18_feed.txt", URL, licence="CC0-1.0", terms_class="open", expect="lines", description="test feed")
    http.add("GET", URL, text="evil.example\nbad.example\n")
    assert main(["data", "update", "wp18_feed.txt"]) == 0
    out = capsys.readouterr().out
    assert "wp18_feed.txt" in out and "updated" in out
    assert (paths.datasets_dir() / "wp18_feed.txt").read_text() == "evil.example\nbad.example\n"
    row = _rows(capsys)["wp18_feed.txt"]
    assert row["present"] and row["licence"] == "CC0-1.0" and row["terms_class"] == "open"
    assert row["bytes"] == len("evil.example\nbad.example\n") and row["stale"] is False and row["age_hours"] == 0.0
    assert main(["data", "list"]) == 0
    table = capsys.readouterr().out
    assert "wp18_feed.txt" in table and "CC0-1.0" in table and "fresh" in table


def test_unchanged_and_failed_updates(http, capsys):
    register_dataset("wp18_feed.txt", URL, expect="lines")
    http.add("GET", URL, text="a\n", times=2)
    assert main(["data", "update", "wp18_feed.txt"]) == 0
    assert main(["data", "update", "wp18_feed.txt"]) == 0
    assert "unchanged" in capsys.readouterr().out
    assert main(["data", "update", "no_such_dataset.txt"]) == 1
    assert "not registered" in capsys.readouterr().out


def test_essential_only(http, capsys):
    register_dataset("wp18_core.txt", URL, essential=True, expect="lines")
    register_dataset("wp18_extra.txt", URL + "?extra", expect="lines")
    assert main(["data", "list"]) == 0
    assert "essential dataset" in capsys.readouterr().out  # the first-run hint (DataStore.first_run_hint)
    http.add("GET", URL, text="core\n")
    assert main(["data", "update", "--essential"]) == 0
    assert "wp18_core.txt" in capsys.readouterr().out
    assert http.urls() == [URL]  # the non-essential one was not downloaded
    rows = _rows(capsys)
    assert rows["wp18_core.txt"]["present"] and rows["wp18_core.txt"]["essential"]
    assert not rows["wp18_extra.txt"]["present"]


def test_active_dataset_shows_the_diff_and_is_never_installed_blind(http, capsys):
    register_dataset("wp18_words.txt", URL, active=True, expect="lines")
    http.add("GET", URL, text="admin\nlogin\n")
    assert main(["data", "update", "wp18_words.txt"]) == 0
    out = capsys.readouterr().out
    assert "needs_accept" in out and "new dataset" in out and "--accept-new" in out
    assert not (paths.datasets_dir() / "wp18_words.txt").exists()  # staged, not installed
    # --accept-new in a non-interactive run installs exactly the staged (reviewed) copy
    assert main(["data", "update", "wp18_words.txt", "--accept-new"]) == 0
    out = capsys.readouterr().out
    assert "updated" in out
    assert (paths.datasets_dir() / "wp18_words.txt").read_text() == "admin\nlogin\n"
    assert len(http.calls) == 1  # the staged bytes, no second download


def test_accept_new_first_call_stages_then_installs(http, capsys):
    """--accept-new with nothing staged: needs_accept and the diff summary first (non-TTY), the
    next --accept-new installs the staged copy."""
    register_dataset("wp18_words.txt", URL, active=True, expect="lines")
    http.add("GET", URL, text="x\ny\n")
    assert main(["data", "update", "wp18_words.txt", "--accept-new"]) == 0
    out = capsys.readouterr().out
    assert "needs_accept" in out and "new dataset" in out and "staged" in out
    assert not (paths.datasets_dir() / "wp18_words.txt").exists()
    assert main(["data", "update", "wp18_words.txt", "--accept-new"]) == 0
    assert (paths.datasets_dir() / "wp18_words.txt").read_text() == "x\ny\n"


def test_accept_new_interactive_confirmation(http, monkeypatch, capsys):
    register_dataset("wp18_words.txt", URL, active=True, expect="lines")
    http.add("GET", URL, text="one\n")
    monkeypatch.setattr("sys.stdin", _Tty("n\n"))
    assert main(["data", "update", "wp18_words.txt", "--accept-new"]) == 0
    assert "not installed" in capsys.readouterr().out
    assert not (paths.datasets_dir() / "wp18_words.txt").exists()
    monkeypatch.setattr("sys.stdin", _Tty("y\n"))
    http.add("GET", URL, text="one\n")
    assert main(["data", "update", "wp18_words.txt", "--accept-new"]) == 0
    assert (paths.datasets_dir() / "wp18_words.txt").read_text() == "one\n"


def test_accept_new_with_the_reviewed_hash(http, capsys):
    import hashlib

    register_dataset("wp18_words.txt", URL, active=True, expect="lines")
    body = "reviewed\n"
    http.add("GET", URL, text=body, times=1)
    http.add("GET", URL, text="tampered\n")
    sha = hashlib.sha256(body.encode()).hexdigest()
    assert main(["data", "update", "wp18_words.txt", "--accept-new", "--sha256", sha]) == 0
    assert (paths.datasets_dir() / "wp18_words.txt").read_text() == body
    # a copy that differs from the reviewed hash is refused and the installed copy stays
    assert main(["data", "update", "wp18_words.txt", "--accept-new", "--sha256", sha]) == 1
    assert "reviewed hash" in capsys.readouterr().out
    assert (paths.datasets_dir() / "wp18_words.txt").read_text() == body


def test_update_argument_errors_send_nothing(http, capsys):
    register_dataset("wp18_feed.txt", URL, licence="CC0-1.0", terms_class="open", expect="lines", description="test feed")
    assert main(["data", "update", "wp18_feed.txt", "--sha256", "ab" * 32]) == 1  # --sha256 belongs to --accept-new
    assert "--accept-new" in capsys.readouterr().err
    assert main(["data", "update", "wp18_feed.txt", "--accept-new", "--sha256", "not-a-hash"]) == 1
    assert "64-hex-digit" in capsys.readouterr().err
    assert main(["--offline", "data", "update", "wp18_feed.txt"]) == 1
    assert "without --offline" in capsys.readouterr().err
    assert http.calls == []
    assert main(["--offline", "data", "list"]) == 0  # listing stays offline
