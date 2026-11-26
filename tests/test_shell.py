"""Interactive console: built-ins, command dispatch and the 'type anything' scan path.

Wave 3 (WP13): the prompt shows mode and TLP (``v3lum[passive|AMBER]> ``), ``set tlp``, ``set
authorized`` bound to ``set scope`` (8 h), history written 0600 with timestamps, scrubbed, without
TLP:RED lines and pruned by retention_days, ``history clear``, registered commands in the command
table and completion.
"""

from __future__ import annotations

import datetime as _dt
import json
import os
import stat

import pytest

from v3lum import paths
from v3lum.app import App
from v3lum.cli import build_parser
from v3lum.shell import BINDING_TTL, Shell
from v3lum.ui.theme import make_console


def make_shell():
    console = make_console(no_color=True, width=120)
    app = App(console, offline=True, fx=False)
    return Shell(app, console, build_parser()), console


def write_scope(path, ref="PT-2026-042", *, start="2026-01-01T00:00:00Z", end="2099-01-01T00:00:00Z"):
    data = {
        "authorization_ref": ref, "owner": "ACME security", "contacts": ["soc@acme.example"], "ticket": "SEC-1",
        "window_start": start, "window_end": end, "targets": {"domains": ["acme.example"]},
    }
    path.write_text(json.dumps(data), encoding="utf-8")
    return str(path)


def test_set_show_and_validation(capsys):
    sh, _ = make_shell()
    assert sh.onecmd("set depth 2") is False
    assert sh.session["depth"] == 2
    sh.onecmd("set depth two")
    assert sh.session["depth"] == 2
    sh.onecmd("set mode turbo")
    assert sh.session["mode"] == "passive"
    sh.onecmd("set authorized PT-2026-01")
    assert sh.session["authorized"] == "PT-2026-01"
    sh.onecmd("set authorized off")
    assert sh.session["authorized"] == ""
    sh.onecmd("set authorized confirmed")  # a placeholder is never a reference (A7)
    assert sh.session["authorized"] == ""
    sh.onecmd("show")
    out = capsys.readouterr().out
    assert "depth" in out and "max_entities" in out and "tlp" in out and "placeholder" in out


def test_set_tlp(capsys):
    sh, _ = make_shell()
    assert sh.session["tlp"] == "amber"
    sh.onecmd("set tlp amber+strict")
    assert sh.session["tlp"] == "amber+strict"
    sh.onecmd("set tlp purple")
    assert sh.session["tlp"] == "amber+strict"
    sh.onecmd("set tlp clear")
    assert sh.session["tlp"] == "clear"
    assert "below the configured TLP:AMBER" in capsys.readouterr().out
    assert sh._scan_argv(["example.com"])[sh._scan_argv(["example.com"]).index("--tlp") + 1] == "clear"


def test_scan_argv_injects_session_settings():
    sh, _ = make_shell()
    sh.session.update({"mode": "light", "depth": 0, "format": "json", "feedback": False, "purpose": "triage", "ticket": "T-1"})
    argv = sh._scan_argv(["example.com"])
    assert argv[0] == "scan" and argv[-1] == "example.com"  # session values first, typed tokens last
    assert "--mode" in argv and "light" in argv and "--no-feedback" in argv
    assert argv[argv.index("--tlp") + 1] == "amber"
    assert argv[argv.index("--purpose") + 1] == "triage" and argv[argv.index("--ticket") + 1] == "T-1"
    argv2 = sh._scan_argv(["example.com", "-d", "3"])
    assert argv2.count("--depth") == 0 and "-d" in argv2
    assert build_parser().parse_args(argv2).depth == 3


@pytest.mark.parametrize("typed", [["--tlp", "red"], ["--tlp=red"], ["--tl", "red"], ["--tlp=RED"]])
def test_typed_flags_always_beat_the_session(typed):
    """A TLP (or mode, depth...) typed on the line is never overridden by the session value, in any
    argparse form: a typed RED must never silently become the session's AMBER."""
    sh, _ = make_shell()
    sh.session.update({"mode": "passive", "depth": 1})
    args = build_parser().parse_args(sh._scan_argv(["example.com", *typed, "--mode=light", "-d2"]))
    assert args.tlp.lower() == "red" and args.mode == "light" and args.depth == 2
    run = build_parser().parse_args(sh._engagement_argv(["run", "dns_records", "example.com", *typed, "-mlight"]))
    assert run.tlp.lower() == "red" and run.mode == "light"


def test_session_flags_reach_every_command_that_takes_them():
    sh, _ = make_shell()
    sh.session.update({"tlp": "red", "purpose": "-starts with a dash", "ticket": "T-9"})
    links = build_parser().parse_args(sh._engagement_argv(["links", "example.com"]))
    assert links.tlp == "red"  # `links` hides third-party links at RED (A2): the session TLP reaches it
    assert sh._engagement_argv(["modules", "-s", "dns"]) == ["modules", "-s", "dns"]  # takes none of them
    scan = build_parser().parse_args(sh._scan_argv(["example.com"]))
    assert scan.purpose == "-starts with a dash" and scan.ticket == "T-9" and scan.inputs == ["example.com"]


def test_a_bare_line_is_one_input_even_when_it_looks_like_options():
    sh, _ = make_shell()
    args = build_parser().parse_args(sh._scan_argv(["--tlp clear -rf"], bare=True))
    assert args.inputs == ["--tlp clear -rf"] and args.tlp == "amber"


def test_authorized_and_scope_are_bound_and_expire(tmp_path, capsys):
    sh, _ = make_shell()
    now = [1_000_000.0]
    sh.clock = lambda: now[0]
    good = write_scope(tmp_path / "scope.json")
    other = write_scope(tmp_path / "other.json", ref="PT-2026-999")
    sh.onecmd(f"set scope {good}")
    assert sh.session["scope"] == good
    sh.onecmd("set authorized PT-2026-999")  # the scope binds another reference
    assert sh.session["authorized"] == ""
    sh.onecmd("set authorized PT-2026-042")
    assert sh.session["authorized"] == "PT-2026-042"
    sh.onecmd(f"set scope {other}")  # refused: it does not bind PT-2026-042
    assert sh.session["scope"] == good
    argv = sh._scan_argv(["acme.example"])
    assert argv[argv.index("--authorized") + 1] == "PT-2026-042" and argv[argv.index("--scope") + 1] == good
    now[0] += BINDING_TTL + 1  # 8 h later: not a TTY -> both cleared, never silently reused
    argv = sh._scan_argv(["acme.example"])
    assert "--authorized" not in argv and "--scope" not in argv
    assert sh.session["authorized"] == "" and sh.session["scope"] == ""
    assert "expired after 8 h" in capsys.readouterr().out


def test_expired_binding_reprompts_in_a_tty(tmp_path, monkeypatch):
    sh, _ = make_shell()
    now = [5_000.0]
    sh.clock = lambda: now[0]
    good = write_scope(tmp_path / "scope.json")
    sh.onecmd("set authorized PT-2026-042")
    sh.onecmd(f"set scope {good}")
    now[0] += BINDING_TTL
    monkeypatch.setattr("sys.stdin.isatty", lambda: True)
    monkeypatch.setattr("sys.stdout.isatty", lambda: True)
    answers = iter(["PT-2026-042", good])
    monkeypatch.setattr("v3lum.shell.Prompt.ask", lambda *a, **k: next(answers))
    argv = sh._scan_argv(["acme.example"])
    assert argv[argv.index("--authorized") + 1] == "PT-2026-042" and argv[argv.index("--scope") + 1] == good


def test_bare_input_runs_a_scan(capsys):
    sh, _ = make_shell()
    sh.session.update({"format": "json", "feedback": False, "verbose": 0})
    assert sh.onecmd("scan -M ioc_extract 'text_blob:C2 45.33.32.156 and evil-site.xyz'") is False
    out = capsys.readouterr().out
    assert "V3LUM REPORT" in out and "45.33.32.156" in out


def test_commands_and_exit(capsys):
    sh, _ = make_shell()
    sh.onecmd("detect 8.8.8.8")
    sh.onecmd("help")
    sh.onecmd("modules")
    sh.onecmd("info dns_records")
    sh.onecmd("info nope_module")
    out = capsys.readouterr().out
    assert "ipv4" in out and "investigate it" in out and "dns_records" in out
    assert sh.onecmd("exit") is True


def test_registered_commands_in_table_and_completion():
    from v3lum.commands import load_commands

    sh, _ = make_shell()
    for name in load_commands():
        assert name in sh.commands
        assert f"{name} " in sh.completenames(name[:2])


def test_prompt_plain_when_not_a_tty():
    sh, _ = make_shell()
    assert sh.prompt == "v3lum[passive|AMBER]> "
    sh.session["tlp"] = "amber+strict"
    sh.session["mode"] = "light"
    assert sh.prompt == "v3lum[light|AMBER+STRICT]> "


def test_history_is_0600_timestamped_scrubbed_and_skips_red(capsys):
    sh, _ = make_shell()
    sh.session.update({"format": "", "feedback": False, "verbose": 0})
    sh.onecmd("detect 8.8.8.8")
    sh.onecmd("detect ana@example.com:Hunter2Secret!")
    sh.onecmd("set tlp red")
    sh.onecmd("detect internal-only.corp.example")
    sh.onecmd("set tlp amber")
    sh.onecmd("detect 1.1.1.1 --tlp red")  # an explicit RED line is not kept either
    for line in ("scan 9.9.9.9 --tlp=RED -f ''", "scan 9.9.9.8 --tl red -f ''"):  # nor in any argparse form
        assert sh.remember(line) is None
    sh.save_history()
    path = paths.home() / "shell_history"
    assert stat.S_IMODE(os.stat(path).st_mode) == 0o600
    text = path.read_text(encoding="utf-8")
    assert "Hunter2Secret" not in text and "internal-only" not in text and "1.1.1.1" not in text
    entries = [json.loads(line) for line in text.splitlines()]
    lines = [e["line"] for e in entries]
    assert "detect 8.8.8.8" in lines and "detect ana@example.com" in lines and "set tlp red" in lines
    assert all(_dt.datetime.fromisoformat(e["ts"]) for e in entries)


def test_history_retention_and_clear(capsys):
    old = (_dt.datetime.now(_dt.timezone.utc) - _dt.timedelta(days=400)).isoformat(timespec="seconds")
    fresh = _dt.datetime.now(_dt.timezone.utc).isoformat(timespec="seconds")
    path = paths.home() / "shell_history"
    path.write_text(
        json.dumps({"ts": old, "line": "scan old.example"}) + "\n" + json.dumps({"ts": fresh, "line": "scan fresh.example"}) + "\nlegacy readline line\n",
        encoding="utf-8",
    )
    sh, _ = make_shell()  # retention_days 180: the old entry and the untimestamped legacy line go
    assert [e["line"] for e in sh.history] == ["scan fresh.example"]
    assert "old.example" not in path.read_text(encoding="utf-8")
    sh.onecmd("history")
    assert "scan fresh.example" in capsys.readouterr().out
    sh.onecmd("history clear")
    assert sh.history == [] and path.read_text(encoding="utf-8") == ""


def test_history_never_stores_or_prints_terminal_escapes(capsys):
    """Pasted text is attacker-controlled: an escape sequence never reaches the history file or
    the analyst's terminal through `history`."""
    fresh = _dt.datetime.now(_dt.timezone.utc).isoformat(timespec="seconds")
    path = paths.home() / "shell_history"
    path.write_text(json.dumps({"ts": fresh, "line": "detect \x1b]0;pwned\x07evil.example"}) + "\n", encoding="utf-8")
    sh, _ = make_shell()
    sh.remember("detect \x1b[2Jbad.example")
    sh.save_history()
    assert "\x1b" not in path.read_text(encoding="utf-8")
    sh.onecmd("history")
    out = capsys.readouterr().out
    assert "\x1b" not in out and "\x07" not in out and "evil.example" in out and "bad.example" in out


@pytest.mark.parametrize("line", ["user@example.com:Hunter2Secret!", "scan 'user@example.com:Hunter2Secret!'"])
def test_pasted_combo_in_the_shell(line, capsys):
    from v3lum.core.store import Store

    sh, _ = make_shell()
    sh.session.update({"format": "json", "feedback": False, "verbose": 0, "purpose": "phishing report", "ticket": "INC-9"})
    sh.onecmd(line)
    sh.save_history()
    assert "Hunter2Secret" not in (paths.home() / "shell_history").read_text(encoding="utf-8")
    case = Store().get_case("last")
    assert case is not None and case["seeds"] == ["email:user@example.com"]
    assert "Hunter2Secret" not in json.dumps(case)
    assert "Hunter2Secret" not in capsys.readouterr().out
