"""Interactive console: built-ins, command dispatch and the 'type anything' scan path."""

from __future__ import annotations

from v3lum.app import App
from v3lum.cli import build_parser
from v3lum.shell import Shell
from v3lum.ui.theme import make_console


def make_shell():
    console = make_console(no_color=True, width=120)
    app = App(console, offline=True, fx=False)
    return Shell(app, console, build_parser()), console


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
    sh.onecmd("show")
    out = capsys.readouterr().out
    assert "depth" in out and "max_entities" in out


def test_scan_argv_injects_session_settings():
    sh, _ = make_shell()
    sh.session.update({"mode": "light", "depth": 0, "format": "json", "feedback": False})
    argv = sh._scan_argv(["example.com"])
    assert argv[:2] == ["scan", "example.com"]
    assert "--mode" in argv and "light" in argv and "--no-feedback" in argv
    argv2 = sh._scan_argv(["example.com", "-d", "3"])
    assert argv2.count("--depth") == 0 and "-d" in argv2


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


def test_prompt_plain_when_not_a_tty():
    sh, _ = make_shell()
    assert sh.prompt == "v3lum[passive]> "
