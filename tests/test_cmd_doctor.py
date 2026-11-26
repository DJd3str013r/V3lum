"""``v3lum doctor`` (WP18): the v1 table moved to the command registry, with probes only to
providers whose sources pass the licence profile (P377 cond 2: no internetdb.shodan.io call under
corporate), permission warnings (A10) and command-module import errors. Offline: FakeHttp."""

from __future__ import annotations

import datetime as _dt
import json
import os

import pytest

from tests.fakes import FakeClock, FakeHttp, add_dns
from v3lum.cli import main
from v3lum.commands import doctor as doctor_cmd

INTERNETDB = "https://internetdb.shodan.io/1.1.1.1"
CRTSH = "https://crt.sh/?q=example.com&output=json"
ZEN = "https://api.github.com/zen"


@pytest.fixture(autouse=True)
def wide_console(monkeypatch):
    monkeypatch.setenv("COLUMNS", "250")  # rich wraps table cells at 80 columns otherwise


@pytest.fixture()
def http(monkeypatch):
    """Every runtime the App builds goes over this FakeHttp (the App's own config)."""
    from v3lum.app import App
    from v3lum.core.context import Runtime

    fake = FakeHttp()
    clock = FakeClock()
    fake.clock = clock

    def runtime(self, listener=None):
        return Runtime(self.config, transport=fake, clock=clock, no_cache=True, offline=self.offline, listener=listener)

    monkeypatch.setattr(App, "runtime", runtime)
    add_dns(fake, "example.com", "A", ["93.184.215.14"])
    fake.add("GET", CRTSH, json=[])
    fake.add("GET", ZEN, text="Keep it logically awesome.")
    fake.add("GET", INTERNETDB, json={"ip": "1.1.1.1", "ports": [53]})
    return fake


def _out(capsys) -> str:
    captured = capsys.readouterr()
    return captured.out + captured.err


def test_no_internetdb_call_under_the_corporate_profile(http, capsys):
    """A1 phase-0 fix: the default corporate profile never contacts internetdb.shodan.io
    (Shodan InternetDB is 'noncommercial'); open sources are still probed."""
    assert main(["doctor"]) == 0
    out = _out(capsys)
    assert "internetdb.shodan.io" not in http.hosts()
    assert "crt.sh" in http.hosts() and "api.github.com" in http.hosts()
    assert "noncommercial" in out and "licence profile corporate" in out
    assert "reach crt.sh" in out


def test_a_licence_allow_entry_lets_doctor_probe_internetdb(http, isolated_home, capsys):
    """The licence profile decides (not a hard-coded skip): an active licence_allow entry for
    shodan.internetdb clears the probe."""
    today = _dt.date(2026, 11, 26)
    entry = {
        "source_id": "shodan.internetdb", "basis": "licence", "scope": "own-network defence only",
        "legal_ref": "LEGAL-2026-099", "approver": "legal", "decided_at": (today - _dt.timedelta(days=10)).isoformat(),
        "review_by": (today + _dt.timedelta(days=100)).isoformat(), "evidence_url": "https://internetdb.shodan.io/", "quote": "test",
    }
    path = isolated_home / "licence_allow.json"
    path.write_text(json.dumps({"schema": "v3lum.licence_allow/1", "entries": [entry]}), encoding="utf-8")
    path.chmod(0o600)
    assert main(["doctor"]) == 0
    _out(capsys)
    assert "internetdb.shodan.io" in http.hosts()


def test_offline_doctor_sends_nothing(http, capsys):
    assert main(["--offline", "doctor"]) == 0
    out = _out(capsys)
    assert http.calls == []
    assert "offline mode" in out


@pytest.mark.skipif(os.name != "posix", reason="POSIX modes")
def test_permission_warnings_are_shown(http, isolated_home, capsys):
    loose = isolated_home / "notes.txt"
    loose.write_text("x", encoding="utf-8")
    loose.chmod(0o644)
    assert main(["--offline", "doctor"]) == 0
    out = _out(capsys)
    assert "permissions" in out and "0644" in out and "chmod 600" in out


def test_command_module_import_errors_are_listed(http, monkeypatch, capsys):
    import v3lum.commands as registry

    monkeypatch.setattr(registry, "load_errors", lambda: {"broken_cmd": "SyntaxError: invalid syntax (broken_cmd.py, line 3)"})
    assert main(["--offline", "doctor"]) == 0
    out = _out(capsys)
    assert "broken_cmd" in out and "SyntaxError" in out


def test_a_refused_probe_reads_could_not_verify(http, capsys, monkeypatch):
    """403/429 from a probed host is 'could not verify' (team rule 5), never a reachable [+] or a
    hard [x] failure."""
    import re

    fake = FakeHttp()
    fake.clock = http.clock
    add_dns(fake, "example.com", "A", ["93.184.215.14"])
    fake.add("GET", CRTSH, status=429, text="Too Many Requests", headers={"Retry-After": "3600"})
    fake.add("GET", ZEN, status=403, text="<html>Access denied</html>")
    from v3lum.app import App
    from v3lum.core.context import Runtime

    def runtime(self, listener=None):
        return Runtime(self.config, transport=fake, clock=fake.clock, no_cache=True, offline=self.offline, listener=listener)

    monkeypatch.setattr(App, "runtime", runtime)
    assert main(["doctor"]) == 0
    out = _out(capsys)
    for host in ("crt.sh", "api.github.com"):
        line = next(ln for ln in out.splitlines() if f"reach {host}" in ln)
        assert "[~]" in line and "could not verify" in line, line
        assert not re.search(r"\[\+\]|\[x\]", line), line


def test_unregistered_probe_hosts_are_never_contacted(http):
    """Fail closed: a host no provider owns counts as 'unknown' terms."""
    from v3lum.core import policy
    from v3lum.core.context import Runtime, ScanOptions
    from v3lum.config import Config

    rt = Runtime(Config(), transport=http, clock=FakeClock(), no_cache=True)
    pctx = policy.make_context(rt, ScanOptions(), path="doctor")
    allowed, reason = doctor_cmd.probe_allowed(doctor_cmd.Probe("https://unregistered.example.test/ping"), pctx)
    assert not allowed and "not in the provider registry" in reason
    allowed, reason = doctor_cmd.probe_allowed(doctor_cmd.Probe(CRTSH, "crtsh.search"), pctx)
    assert allowed
    allowed, reason = doctor_cmd.probe_allowed(doctor_cmd.Probe(INTERNETDB, "shodan.internetdb"), pctx)
    assert not allowed and "noncommercial" in reason
    allowed, _ = doctor_cmd.probe_allowed(doctor_cmd.Probe(INTERNETDB, "shodan.no_such_source"), pctx)
    assert not allowed


def test_app_doctor_delegates_to_the_command_module(http, capsys):
    """App.doctor (WP13 delegator) renders the same table."""
    from rich.console import Console

    from v3lum.app import App
    from v3lum.ui.theme import THEME

    console = Console(record=True, width=160, theme=THEME)
    app = App(console, offline=True)
    table = app.doctor()
    console.print(table)
    text = console.export_text()
    assert "permissions" in text and "commands" in text


# --------------------------------------------------------------------------------------
# keys (moved with doctor: list / set --plan / unset)
# --------------------------------------------------------------------------------------


def test_keys_list_comes_from_the_key_registry(capsys):
    """Fragment keys (misp, opencti) and their env aliases are listed, not only the legacy table."""
    assert main(["keys", "list"]) == 0
    out = capsys.readouterr().out
    for name in ("misp", "opencti", "MISP_API_KEY", "OPENCTI_TOKEN", "shodan", "SHODAN_API_KEY"):
        assert name in out, name
    assert "plan" in out


def test_keys_set_records_the_plan_and_never_prints_the_value(capsys):
    from v3lum.config import Config

    assert main(["keys", "set", "shodan", "abcdef123456", "--plan", "business"]) == 0
    out = capsys.readouterr().out
    assert "abcdef123456" not in out and "abc******456" in out and "business" in out
    cfg = Config.load()
    assert cfg.key("shodan") == "abcdef123456" and cfg.key_plan("shodan") == "business"
    assert main(["keys", "list"]) == 0
    listing = capsys.readouterr().out
    assert "abcdef123456" not in listing and "business" in listing
    # an existing key: --plan alone changes the plan, never prompts
    import getpass

    def no_prompt(*_a, **_k):  # pragma: no cover - would fail the test
        raise AssertionError("prompted for a key value")

    original = getpass.getpass
    getpass.getpass = no_prompt
    try:
        assert main(["keys", "set", "shodan", "--plan", "free"]) == 0
    finally:
        getpass.getpass = original
    assert Config.load().key_plan("shodan") == "free" and Config.load().key("shodan") == "abcdef123456"
    assert main(["keys", "unset", "shodan"]) == 0
    cfg = Config.load()
    assert cfg.key("shodan") == "" and cfg.key_plan("shodan") == ""


def test_keys_plan_for_a_key_from_the_environment(monkeypatch, capsys):
    from v3lum.config import Config

    monkeypatch.setenv("V3LUM_KEY_SHODAN", "envvalue987654")
    monkeypatch.setattr("getpass.getpass", lambda *_a, **_k: (_ for _ in ()).throw(AssertionError("prompted")))
    assert main(["keys", "set", "shodan", "--plan", "business"]) == 0
    assert "envvalue987654" not in capsys.readouterr().out
    cfg = Config.load()
    assert cfg.key_plan("shodan") == "business" and "shodan" not in cfg.file_keys  # the value stays in the env


def test_keys_bad_plan_and_unknown_key(capsys):
    with pytest.raises(SystemExit):
        main(["keys", "set", "shodan", "x" * 12, "--plan", "enterprise"])  # argparse choices
    capsys.readouterr()
    assert main(["keys", "set", "my_internal_tool", "value12345678"]) == 0
    assert "not a key any registered module or provider declares" in capsys.readouterr().out


def test_app_keys_table_delegates(capsys):
    from rich.console import Console

    from v3lum.app import App
    from v3lum.ui.theme import THEME

    console = Console(record=True, width=200, theme=THEME)
    console.print(App(console, offline=True).keys_table())
    text = console.export_text()
    assert "plan" in text and "opencti" in text


def test_keys_set_without_a_value_and_no_input_stores_nothing(monkeypatch, capsys):
    """End of input at the hidden prompt (an empty pipe) is a clean refusal, never a traceback."""
    from v3lum.config import Config

    def eof(*_a, **_k):
        raise EOFError

    monkeypatch.setattr("getpass.getpass", eof)
    assert main(["keys", "set", "shodan"]) == 1
    assert "nothing stored" in capsys.readouterr().err
    assert Config.load().key("shodan") == ""
    monkeypatch.setattr("getpass.getpass", lambda *_a, **_k: "piped-value-123456\n")
    assert main(["keys", "set", "shodan", "--plan", "business"]) == 0
    assert "piped-value-123456" not in capsys.readouterr().out
    assert Config.load().key("shodan") == "piped-value-123456" and Config.load().key_plan("shodan") == "business"
