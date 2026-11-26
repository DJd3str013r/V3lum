"""Policy and rules of engagement on every CLI path (WP13: P327, AR15-AR17, A2, A5, A7, AR16, P145, P172).

The table runs every refusal cause on every execution path - ``scan``, batch input (``scan -i``),
``extract --scan``, ``run`` and a shell line - and asserts the readable reason:

* refusals of the rules of engagement and of the case metadata (ACTIVE without REF or scope, a
  placeholder REF, a scope bound to another REF or outside its window, the research licence profile
  without a recorded basis, a personal seed without purpose in a non-TTY) stop the path before any
  module runs: exit code 1 with the reason on stderr (the shell prints ``[x] <reason>``; no case);
* module refusals of the policy gate (TLP:RED with a third-party module, an exhausted quota, a LIGHT
  module without ``--mode light``) make ``v3lum run`` exit 1 with the gate's reason, while scans
  record them in the case coverage (status, reason_code and the readable reason).

Every module here is synthetic and offline; the runtime gets a FakeHttp transport (no network).
"""

from __future__ import annotations

import json
import os
import shlex
from dataclasses import dataclass
from typing import Any

import pytest

from tests.fakes import FakeHttp, define_module, provider_fragment
from v3lum import paths
from v3lum.app import App
from v3lum.cli import build_parser, main
from v3lum.config import Config
from v3lum.core import policy
from v3lum.core import providers as providers_mod
from v3lum.core.context import Runtime
from v3lum.core.models import Opsec
from v3lum.core.store import Store
from v3lum.shell import Shell
from v3lum.ui.theme import make_console

REF = "PT-2026-042"
SECRET = "Hunter2Secret!"


@pytest.fixture(autouse=True)
def _restore_umask():
    old = os.umask(0o022)
    os.umask(old)
    yield
    os.umask(old)


def _run(self: Any, entity: Any, ctx: Any) -> Any:
    return self.result(entity)  # offline: never touches ctx.http (EMPTY)


def _provider(pid: str, **flags: Any) -> tuple[str, str]:
    host = f"api.{pid}.example.test"
    providers_mod.register(provider_fragment(pid, hosts=(host,), **flags), origin="tests")
    return host, f"{pid}.default"


@pytest.fixture()
def env(clean_registry, tmp_path, monkeypatch):
    """Synthetic modules, a quiet config (depth 0, no report files), a FakeHttp runtime and
    the scope files of the ACTIVE rows."""
    host, source = _provider("clipol_tp")
    third = dict(disclosure="third_party", provider="clipol_tp", sources=(source,), hosts=(host,), access_model="free_noauth_unlimited", max_requests=1, expected_latency=1.0)
    define_module("clipol_third", ["domain", "email", "text_blob", "ipv4"], _run, **third)
    define_module("clipol_quota", ["domain", "text_blob"], _run, daily_quota=1, **third)
    define_module("clipol_light", ["domain", "text_blob"], _run, opsec=Opsec.LIGHT)
    fhost, fsource = _provider("clipol_fetch", fetches_target=True)
    define_module(
        "clipol_fetcher", ["url"], _run, disclosure="third_party", provider="clipol_fetch", sources=(fsource,), hosts=(fhost,),
        access_model="free_noauth_unlimited", max_requests=1, expected_latency=1.0, default_enabled=False,
    )
    from v3lum.core.quota import QuotaBook

    book = QuotaBook(paths.home() / "quota.db")
    book.add("clipol_quota", 5)
    cfg = Config.load()
    cfg.set("depth", 0)
    cfg.set("report_formats", [])
    cfg.set("feedback", False)
    cfg.save()

    def fake_runtime(self: App, listener: Any = None) -> Runtime:
        return Runtime(self.config, transport=FakeHttp(), offline=self.offline, no_cache=True, listener=listener)

    monkeypatch.setattr(App, "runtime", fake_runtime)
    scopes = {
        "good": _scope(tmp_path / "scope_good.json", REF, end="2099-01-01T00:00:00Z"),
        "closed": _scope(tmp_path / "scope_closed.json", REF, end="2026-02-01T00:00:00Z"),
    }
    return scopes


def _scope(path: Any, ref: str, *, end: str) -> str:
    data = {
        "authorization_ref": ref, "owner": "ACME security", "contacts": ["soc@acme.example"], "ticket": "SEC-1",
        "window_start": "2026-01-01T00:00:00Z", "window_end": end, "targets": {"domains": ["example.com"]},
    }
    path.write_text(json.dumps(data), encoding="utf-8")
    return str(path)


# --------------------------------------------------------------------------------------
# path runner
# --------------------------------------------------------------------------------------


@dataclass
class Outcome:
    rc: int | None
    out: str
    err: str
    case: dict[str, Any] | None


def _cases() -> list[str]:
    return [c["id"] for c in Store().list_cases(500)]


def run_path(path: str, target: str, flags: list[str], *, module: str, tmp_path: Any, capsys: Any) -> Outcome:
    """Run ``target`` with ``flags`` on one execution path; the new case (if any) is returned."""
    before = set(_cases())
    rc: int | None
    if path == "scan":
        rc = main(["scan", target, "--json", "-f", "", "-M", module, *flags])
    elif path == "batch":
        batch = tmp_path / "batch.txt"
        batch.write_text(f"# batch input\n{target}\n", encoding="utf-8")
        rc = main(["scan", "-i", str(batch), "--json", "-f", "", "-M", module, *flags])
    elif path == "extract":
        text = tmp_path / "input.txt"
        text.write_text(f"beacon seen at {target}\n", encoding="utf-8")
        rc = main(["extract", str(text), "--scan", "--json", *flags])
    elif path == "run":
        rc = main(["run", module, target, "--json", *flags])
    elif path == "shell":
        console = make_console(no_color=True, width=200)
        sh = Shell(App(console, fx=False), console, build_parser())
        sh.onecmd(shlex.join(["scan", target, "-M", module, "-f", "", *flags]))
        rc = None
    else:  # pragma: no cover
        raise AssertionError(path)
    captured = capsys.readouterr()
    new = [c for c in _cases() if c not in before]
    case = Store().get_case(new[0]) if new else None
    out = captured.out if path in ("scan", "batch", "extract", "run") and rc == 0 else _flat(captured.out)
    return Outcome(rc, out, _flat(captured.err), case)


def _flat(text: str) -> str:
    """Console output with the terminal line wrapping undone (one space between words)."""
    return " ".join(text.split())


# --------------------------------------------------------------------------------------
# the table: paths x refusal causes
# --------------------------------------------------------------------------------------

PATHS = ("scan", "batch", "extract", "run", "shell")


@dataclass(frozen=True)
class Cause:
    flags: tuple[str, ...]
    reason: str
    target: str = "example.com"
    module: str = "clipol_third"
    code: str = ""  # module refusal: coverage reason_code on scan paths ("" = refused before any module)
    extract_flags: tuple[str, ...] | None = None


CAUSES: dict[str, Cause] = {
    "active_without_ref": Cause(("--mode", "active", "--scope", "{good}"), "missing --authorized REF"),
    "placeholder_ref": Cause(("--mode", "active", "--authorized", "confirmed", "--scope", "{good}"), "placeholder"),
    "active_without_scope": Cause(("--mode", "active", "--authorized", REF), "missing --scope FILE"),
    "scope_ref_mismatch": Cause(("--mode", "active", "--authorized", "PT-2026-999", "--scope", "{good}"), "authorization_ref mismatch"),
    "closed_window": Cause(("--mode", "active", "--authorized", REF, "--scope", "{closed}"), "outside the window"),
    "research_without_basis": Cause(("--licence-profile", "research"), "licence_profile=research needs a recorded legal basis"),
    "personal_without_purpose": Cause((), "needs --purpose TEXT and --ticket TEXT", target="ana@example.com", extract_flags=("--expand-personal",)),
    "tlp_red_third_party": Cause(("--tlp", "red"), "TLP:RED", code="tlp"),
    "exhausted_quota": Cause((), "daily free quota used", module="clipol_quota", code="quota"),
    "light_without_mode": Cause((), "needs --mode light: contacts the target", module="clipol_light", code="opsec", extract_flags=("--preset", "deep")),
}


@pytest.mark.parametrize("cause_name", list(CAUSES))
@pytest.mark.parametrize("path", PATHS)
def test_refusals_on_every_path(path, cause_name, env, tmp_path, capsys):
    cause = CAUSES[cause_name]
    raw = cause.extract_flags if path == "extract" and cause.extract_flags is not None else cause.flags
    flags = [f.format(**env) for f in raw]
    target = "ana@example.com" if cause_name == "personal_without_purpose" and path != "extract" else cause.target
    res = run_path(path, target, flags, module=cause.module, tmp_path=tmp_path, capsys=capsys)
    if not cause.code or path == "run":
        # refused before any module ran: exit 1 (shell: '[x] <reason>') and no case written
        if path == "shell":
            assert "[x]" in res.out and cause.reason in res.out, res.out
        else:
            assert res.rc == 1, (res.rc, res.err)
            assert cause.reason in res.err, res.err
        assert res.case is None
        return
    # module refusal inside a scan: the case records it with the readable reason
    assert res.rc in (0, None), res.err
    assert res.case is not None, (res.out, res.err)
    cov = res.case["coverage"][cause.module]
    assert cov["reason_code"] == cause.code, cov
    assert cause.reason in cov["reason"], cov


# --------------------------------------------------------------------------------------
# acceptance: make_context on every path, no escalation, ACTIVE refused TTY or not
# --------------------------------------------------------------------------------------


@pytest.mark.parametrize("path,expected", [("scan", "scan"), ("batch", "batch"), ("extract", "extract"), ("run", "run"), ("shell", "shell")])
def test_every_path_builds_its_policy_context_with_make_context(path, expected, env, tmp_path, capsys, monkeypatch):
    seen: list[str] = []
    real = policy.make_context

    def spy(runtime: Any, options: Any = None, *, explicit: Any = (), graph: Any = None, path: str = "scan") -> Any:
        seen.append(path)
        return real(runtime, options, explicit=explicit, graph=graph, path=path)

    monkeypatch.setattr(policy, "make_context", spy)
    res = run_path(path, "example.com", [], module="clipol_third", tmp_path=tmp_path, capsys=capsys)
    assert res.rc in (0, None), res.err
    assert expected in seen, seen
    assert set(seen) <= {expected}, seen  # never another path's context


def test_run_never_escalates_the_mode(env, capsys):
    """`v3lum run` uses the configured mode (passive): a LIGHT module is refused with a hint."""
    assert main(["run", "clipol_light", "example.com"]) == 1
    err = _flat(capsys.readouterr().err)
    assert "needs --mode light: contacts the target" in err
    args = build_parser().parse_args(["run", "clipol_light", "example.com"])
    assert args.mode is None


@pytest.mark.parametrize("tty", [False, True])
@pytest.mark.parametrize("yes", [False, True])
@pytest.mark.parametrize("path", ["scan", "batch", "run", "shell"])
def test_active_needs_ref_and_scope_tty_or_not(path, tty, yes, env, tmp_path, capsys, monkeypatch):
    monkeypatch.setattr("v3lum.app._stdin_tty", lambda: tty)

    def no_prompt(*_a: Any, **_k: Any) -> Any:
        raise AssertionError("an ACTIVE refusal never asks anything")

    monkeypatch.setattr("v3lum.app.Confirm.ask", no_prompt)
    monkeypatch.setattr("v3lum.app.Prompt.ask", no_prompt)
    flags = ["--mode", "active"] + (["-y"] if yes and path != "run" and path != "shell" else [])
    res = run_path(path, "example.com", flags, module="clipol_third", tmp_path=tmp_path, capsys=capsys)
    text = res.out if path == "shell" else res.err
    assert "missing --authorized REF" in text and "--scope FILE" in text, text
    if path != "shell":
        assert res.rc == 1
    assert res.case is None


def test_active_scope_problems_are_listed(env, tmp_path, capsys):
    bad = tmp_path / "bad.json"
    bad.write_text(json.dumps({"authorization_ref": REF, "targets": {}}), encoding="utf-8")
    assert main(["scan", "example.com", "--mode", "active", "--authorized", REF, "--scope", str(bad), "-f", ""]) == 1
    err = _flat(capsys.readouterr().err)
    assert "scope file refused" in err and "owner is required" in err


# --------------------------------------------------------------------------------------
# AR03, AR17, AR16, A5, registry
# --------------------------------------------------------------------------------------


def test_umask_applied_first(monkeypatch, capsys):
    calls: list[int] = []
    real = os.umask

    def spy(mask: int) -> int:
        calls.append(mask)
        return real(mask)

    monkeypatch.setattr(os, "umask", spy)
    assert main(["version"]) == 0
    assert calls and calls[0] == 0o077


def test_tlp_lowering_is_recorded(env, capsys, monkeypatch):
    captured: list[Any] = []
    real = App.scan_options

    def spy(self: App, *a: Any, **k: Any) -> Any:
        options = real(self, *a, **k)
        captured.append(options)
        return options

    monkeypatch.setattr(App, "scan_options", spy)
    assert main(["scan", "example.com", "--json", "-f", "", "-M", "clipol_third", "--tlp", "clear"]) == 0
    out = capsys.readouterr()
    data = json.loads(out.out)
    change = captured[0].tlp_change
    assert change["from"] == "amber" and change["to"] == "clear" and change["os_user"] and change["at"]
    assert data["meta"]["tlp_change"]["to"] == "clear"
    rows = [r for r in Store().audit_rows(data["case_id"]) if r["kind"] == "tlp_change"]
    assert len(rows) == 1 and rows[0]["payload"]["from"] == "amber"
    assert "TLP lowered" in _flat(out.err)
    # the configured default (or a higher level) is no lowering
    assert main(["scan", "example.com", "--json", "-f", "", "-M", "clipol_third", "--tlp", "red"]) == 0
    assert captured[-1].tlp_change is None


def test_light_scans_are_raised_to_amber(env, capsys, monkeypatch):
    captured: list[Any] = []
    real = App.scan_options
    monkeypatch.setattr(App, "scan_options", lambda self, *a, **k: captured.append(real(self, *a, **k)) or captured[-1])
    assert main(["scan", "example.com", "--json", "-f", "", "-M", "clipol_third", "--tlp", "clear", "--mode", "light"]) == 0
    err = _flat(capsys.readouterr().err)
    assert "raised to AMBER" in err
    assert captured and captured[0].tlp == "amber" and captured[0].tlp_change is None


def test_registry_commands_are_dispatched(capsys):
    from v3lum.commands import COMMANDS, command

    try:
        @command("zz-wp13-probe", "probe command of the WP13 tests", aliases=("zzwp13",))
        class Probe:
            @staticmethod
            def add_arguments(parser: Any) -> None:
                parser.add_argument("--value", type=int, default=0)

            @staticmethod
            def run(args: Any, app: Any, console: Any) -> int:
                console.print(f"probe ran with {args.value} ({type(app).__name__})")
                return args.value

        assert main(["zz-wp13-probe", "--value", "7"]) == 7
        assert "probe ran with 7 (App)" in capsys.readouterr().out
        assert main(["zzwp13", "--value", "3"]) == 3
    finally:
        COMMANDS.pop("zz-wp13-probe", None)


def test_broken_command_module_never_breaks_the_cli(capsys):
    from v3lum.commands import COMMANDS, CommandSpec, load_errors, register

    def bad_arguments(parser: Any) -> None:
        raise RuntimeError("boom")

    register(CommandSpec("zz-broken", "broken", bad_arguments, lambda a, b, c: 0, module="tests.broken"))
    try:
        assert main(["version"]) == 0
        assert any("zz-broken" in text for text in load_errors().values())
    finally:
        COMMANDS.pop("zz-broken", None)


def test_personal_seed_purpose_prompted_in_a_tty(env, capsys, monkeypatch):
    monkeypatch.setattr("v3lum.app._stdin_tty", lambda: True)
    answers = iter(["fraud report 7", "FR-7"])
    monkeypatch.setattr("v3lum.app.Prompt.ask", lambda *a, **k: next(answers))
    assert main(["scan", "ana@example.com", "-M", "clipol_third", "-f", "", "--no-feedback"]) == 0
    case = Store().get_case("last")
    assert case["options"]["purpose"] == "fraud report 7" and case["options"]["ticket"] == "FR-7"


def test_breach_scope_all_and_incident_victim_need_a_purpose(env, capsys):
    assert main(["scan", "example.com", "-M", "clipol_third", "-f", "", "--breach-scope", "all"]) == 1
    assert "--breach-scope all needs --purpose TEXT and --ticket TEXT" in _flat(capsys.readouterr().err)
    assert main(["scan", "example.com", "-M", "clipol_third", "-f", "", "--incident-victim"]) == 1
    assert "--incident-victim needs --purpose TEXT" in _flat(capsys.readouterr().err)
    assert main(["scan", "example.com", "-M", "clipol_third", "-f", "", "--incident-victim", "--purpose", "ransomware incident", "--json"]) == 0
    assert json.loads(capsys.readouterr().out)["options"]["subject_roles"] == {"domain:example.com": "incident_victim"}


def test_low_confidence_username_is_announced_and_unconfirmed(env, capsys):
    assert main(["scan", "johndoe1983", "-M", "clipol_third", "-f", "", "--json", "--purpose", "fraud", "--ticket", "FR-1"]) == 0
    out = capsys.readouterr()
    assert "read as username (0.60); force with TYPE:value" in _flat(out.err)
    assert json.loads(out.out)["options"]["unconfirmed_seeds"] == ["username:johndoe1983"]
    assert main(["scan", "username:johndoe1983", "-M", "clipol_third", "-f", "", "--json", "--purpose", "fraud", "--ticket", "FR-1"]) == 0
    out = capsys.readouterr()
    assert "read as" not in out.err and json.loads(out.out)["options"]["unconfirmed_seeds"] == []


def test_low_confidence_username_confirmed_in_a_tty(env, capsys, monkeypatch):
    monkeypatch.setattr("v3lum.app._stdin_tty", lambda: True)
    monkeypatch.setattr("v3lum.app.Confirm.ask", lambda *a, **k: True)
    assert main(["scan", "johndoe1983", "-M", "clipol_third", "-f", "", "--purpose", "fraud", "--ticket", "FR-1", "--no-feedback"]) == 0
    assert Store().get_case("last")["options"]["unconfirmed_seeds"] == []


# --------------------------------------------------------------------------------------
# P145 cond 5: pasted credentials, A7 BR15: --confirm-url
# --------------------------------------------------------------------------------------


def test_pasted_combo_is_stored_as_the_email_only(env, tmp_path, capsys):
    out_dir = tmp_path / "reports"
    rc = main(["scan", f"user@example.com:{SECRET}", "--json", "-M", "clipol_third", "-f", "json,md", "-o", str(out_dir), "--purpose", "phishing", "--ticket", "INC-1"])
    assert rc == 0
    captured = capsys.readouterr()
    data = json.loads(captured.out)
    assert data["seeds"] == ["email:user@example.com"]
    assert [d["value"] for d in data["inputs"]] == ["user@example.com"]
    assert SECRET not in captured.out and SECRET not in captured.err
    assert "sensitive data in pasted text" in _flat(captured.err)
    stored = Store().get_case(data["case_id"])
    assert SECRET not in json.dumps(stored)
    for report in out_dir.iterdir():
        assert SECRET not in report.read_text(encoding="utf-8")
    # the same line pasted in the console: the case and the shell history hold the e-mail only
    console = make_console(no_color=True, width=200)
    sh = Shell(App(console, fx=False), console, build_parser())
    sh.session.update({"purpose": "phishing", "ticket": "INC-1", "format": "", "feedback": False, "verbose": 0})
    sh.onecmd(f"user@example.com:{SECRET}")
    sh.save_history()
    history = (paths.home() / "shell_history").read_text(encoding="utf-8")
    assert SECRET not in history and "user@example.com" in history
    last = Store().get_case("last")
    assert last["seeds"] == ["email:user@example.com"] and SECRET not in json.dumps(last)
    assert SECRET not in capsys.readouterr().out


def test_pasted_text_blob_is_scrubbed_before_the_seed_is_created(env, capsys):
    blob = f"phish kit drop\nlogin dump: user@example.com:{SECRET}\nC2 203.0.113.80"
    assert main(["scan", blob, "--json", "-f", "", "-M", "ioc_extract"]) == 0
    data = json.loads(capsys.readouterr().out)
    assert SECRET not in json.dumps(data)
    assert data["seeds"][0].startswith("text_blob:") and "user@example.com" in data["seeds"][0]
    assert any(n.startswith("sensitive data in pasted text") for n in data["notes"])


def test_confirm_url_lets_only_the_confirmed_url_through(env, capsys):
    first = "https://evil.example.test/t/9f8e7d6c5b4a39281706f5e4d3c2b1a0"
    second = "https://evil.example.test/t/0a1b2c3d4e5f60718293a4b5c6d7e8f9"
    rc = main(["scan", first, second, "--json", "-f", "", "-M", "clipol_fetcher", "--confirm-url", first])
    assert rc == 0
    data = json.loads(capsys.readouterr().out)
    rows = data["coverage"]["clipol_fetcher"]["entities"]
    assert rows[f"url:{first}"]["status"] in ("ok", "empty"), rows
    assert rows[f"url:{second}"]["status"] == "skipped" and rows[f"url:{second}"]["reason_code"] == "policy"
    assert "--confirm-url" in rows[f"url:{second}"]["reason"]
    # the run path: refused without the confirmation, allowed with it
    assert main(["run", "clipol_fetcher", second, "--json"]) == 1
    assert "--confirm-url" in _flat(capsys.readouterr().err)
    assert main(["run", "clipol_fetcher", second, "--json", "--confirm-url", second]) == 0
    assert json.loads(capsys.readouterr().out)["status"] in ("ok", "empty")


# --------------------------------------------------------------------------------------
# hints, preview, AR07 pick, research profile
# --------------------------------------------------------------------------------------


def test_first_scan_hints_are_shown_once(env, capsys):
    assert main(["scan", "example.com", "-f", "", "-M", "clipol_third", "--json"]) == 0
    first = _flat(capsys.readouterr().err)
    assert "no API keys configured: v3lum keys setup" in first
    assert main(["scan", "example.com", "-f", "", "-M", "clipol_third", "--json"]) == 0
    assert "no API keys configured" not in _flat(capsys.readouterr().err)


def test_daily_retention_reminder(env, capsys):
    store = Store()
    store.save_case({"case_id": "old-case-1", "created": "2020-01-01T00:00:00+00:00", "seeds": ["domain:example.com"], "summary": {}, "options": {}})
    assert main(["modules", "-s", "clipol"]) == 0
    assert "1 case older than 180 days: v3lum cases purge" in _flat(capsys.readouterr().out)
    assert main(["modules", "-s", "clipol"]) == 0
    assert "older than" not in _flat(capsys.readouterr().out)  # at most once per day


def test_extraction_preview_confirms_above_25_iocs(env, capsys, monkeypatch):
    monkeypatch.setattr("v3lum.app._stdin_tty", lambda: True)
    asked: list[str] = []

    def refuse(prompt: str, *a: Any, **k: Any) -> bool:
        asked.append(prompt)
        return False

    monkeypatch.setattr("v3lum.app.Confirm.ask", refuse)
    blob = "\n".join(f"beacon 203.0.113.{i}" for i in range(1, 31))
    assert main(["scan", blob, "-f", "", "-M", "ioc_extract", "--no-feedback"]) == 1
    captured = capsys.readouterr()
    assert "30 IOCs: 30 IPs" in _flat(captured.out)
    assert "cancelled at the extraction preview" in _flat(captured.err) and asked
    small = "beacon 203.0.113.1\nC2 203.0.113.2"
    asked.clear()
    assert main(["scan", small, "-f", "", "-M", "ioc_extract", "--no-feedback"]) == 0
    assert "2 IOCs: 2 IPs" in _flat(capsys.readouterr().out) and not asked


def test_pending_personal_pick_starts_a_follow_up_scan(env, capsys, monkeypatch):
    monkeypatch.setattr("v3lum.app._stdin_tty", lambda: True)
    monkeypatch.setattr("v3lum.app.Prompt.ask", lambda *a, **k: "1")
    monkeypatch.setattr("v3lum.app.Confirm.ask", lambda *a, **k: True)
    blob = "phishing mail\nfrom ana@example.com\nlink to 203.0.113.90"
    before = set(_cases())
    assert main(["scan", blob, "-f", "", "-M", "ioc_extract,clipol_third", "--purpose", "phishing triage", "--ticket", "INC-77", "--no-feedback"]) == 0
    new = [Store().get_case(c) for c in _cases() if c not in before]
    assert len(new) == 2
    follow = next(c for c in new if c["seeds"] == ["email:ana@example.com"])
    assert follow["options"]["purpose"] == "phishing triage" and follow["options"]["ticket"] == "INC-77"


def test_research_profile_with_a_recorded_basis_is_accepted(env, capsys):
    allow = paths.home() / "licence_allow.json"
    allow.write_text(json.dumps({"entries": [], "research_basis": {"legal_ref": "LEGAL-R", "approver": "legal", "date": "2026-11-01", "scope": "*"}}), encoding="utf-8")
    allow.chmod(0o600)
    assert main(["scan", "example.com", "--json", "-f", "", "-M", "clipol_third", "--licence-profile", "research"]) == 0
    assert json.loads(capsys.readouterr().out)["licence_profile"] == "research"


def test_light_run_writes_a_case_with_its_audit_record(env, capsys):
    pytest.importorskip("v3lum.core.audit")
    before = set(_cases())
    assert main(["run", "clipol_light", "example.com", "--mode", "light", "--json"]) == 0
    out = json.loads(capsys.readouterr().out)
    assert out["case_id"] and out["status"] in ("ok", "empty")
    new = [c for c in _cases() if c not in before]
    assert new == [out["case_id"]]
    assert Store().audit_rows(out["case_id"]), "a LIGHT run writes its audit record (A7)"


# --------------------------------------------------------------------------------------
# runtime wiring of App.scan (WP15/WP16 hooks, A10 cache keys)
# --------------------------------------------------------------------------------------


def test_scan_installs_the_sightings_lookup_and_records_cache_keys(env, capsys, monkeypatch):
    from v3lum.app import _PathEngine

    seen: dict[str, Any] = {}
    real_investigate = _PathEngine.investigate

    def spy(self: Any, seeds: Any, **kw: Any) -> Any:
        seen["meta"] = dict(self.runtime.meta)
        seen["hooks"] = list(self.runtime.case_hooks)
        case = real_investigate(self, seeds, **kw)
        case.cache_keys.add("cache-key-of-this-case")
        return case

    monkeypatch.setattr(_PathEngine, "investigate", spy)
    recorded: list[tuple[str, list[str]]] = []
    real_record = Store.record_cache_keys
    monkeypatch.setattr(Store, "record_cache_keys", lambda self, cid, keys: recorded.append((cid, sorted(keys))) or real_record(self, cid, keys))
    assert main(["scan", "example.com", "--json", "-f", "", "-M", "clipol_third"]) == 0
    data = json.loads(capsys.readouterr().out)
    lookup = seen["meta"].get("sightings_lookup")
    if hasattr(Store, "sightings_for"):
        assert callable(lookup) and getattr(lookup, "__name__", "") == "sightings_for"
    assert seen["meta"]["execution_path"] == "scan"
    try:
        from v3lum.core.audit import AuditHook
    except ImportError:  # pragma: no cover - WP15 absent: passive scans go on without the hook
        AuditHook = None  # noqa: N806
    if AuditHook is not None:
        hooks = [h for h in seen["hooks"] if isinstance(h, AuditHook)]
        assert len(hooks) == 1, seen["hooks"]
        # attached (case hooks + http_request events), not merely appended
        assert getattr(hooks[0], "runtime", None) is not None
    assert "sightings_lookup" not in data["meta"]  # a live object never reaches the case JSON
    assert data["meta"]["execution_path"] == "scan"
    assert recorded == [(data["case_id"], ["cache-key-of-this-case"])]
    assert Store().cache_keys(data["case_id"]) == ["cache-key-of-this-case"]


def test_run_output_carries_the_view_facts(env, capsys):
    assert main(["run", "clipol_third", "example.com", "--json", "--tlp", "amber+strict", "--no-defang"]) == 0
    out = json.loads(capsys.readouterr().out)
    assert out["tlp"] == "amber+strict" and out["no_defang"] is True and out["show_personal"] is False
    assert out["status"] == "empty" and out["partial"] is False
    assert main(["run", "clipol_third", "example.com"]) == 0  # rendered by ui.render.render_single
    assert "clipol_third" in capsys.readouterr().out


# --------------------------------------------------------------------------------------
# review additions: TLP lowering on `run`, follow-up TLP, data_update, listings under --tor
# --------------------------------------------------------------------------------------


def test_passive_run_below_the_configured_tlp_is_recorded_in_a_case_audit(env, capsys):
    """A2/AR17: a lowered TLP is recorded in the case audit on every path - a passive `run` that
    lowers it writes a case (a plain passive run writes none)."""
    before = set(_cases())
    assert main(["run", "clipol_third", "example.com", "--json"]) == 0
    assert set(_cases()) == before  # the configured TLP: nothing written
    capsys.readouterr()
    assert main(["run", "clipol_third", "example.com", "--json", "--tlp", "clear"]) == 0
    out = json.loads(capsys.readouterr().out)
    assert out["case_id"] and out["tlp"] == "clear" and out["status"] in ("ok", "empty")
    rows = [r for r in Store().audit_rows(out["case_id"]) if r["kind"] == "tlp_change"]
    assert rows and rows[0]["payload"]["from"] == "amber" and rows[0]["payload"]["to"] == "clear"


def test_follow_up_pick_never_lowers_the_case_tlp(env, monkeypatch):
    from v3lum.app import ScanRequest
    from v3lum.ui.theme import make_console as mk

    monkeypatch.setattr("v3lum.app._stdin_tty", lambda: True)
    monkeypatch.setattr("v3lum.app.Prompt.ask", lambda *a, **k: "1")
    app = App(mk(no_color=True, width=120), fx=False)
    data = {"tlp": "red", "options": {"purpose": "triage", "ticket": "T-1"}, "pending_personal": [{"entity": "email:ana@example.com", "relation": "mentions", "parent": "text_blob:x"}]}
    follow = app.follow_up_personal(data, ScanRequest(inputs=["text_blob:x"], tlp="amber"))
    assert follow is not None and follow.tlp == "red" and follow.inputs == ["email:ana@example.com"]
    assert follow.purpose == "triage" and follow.ticket == "T-1"
    data["tlp"] = "clear"  # a lower case TLP never lowers the request
    assert app.follow_up_personal(data, ScanRequest(inputs=["text_blob:x"], tlp="amber")).tlp == "amber"


def test_app_data_update_goes_through_the_dataset_review_flow(env, monkeypatch):
    """App.data_update never re-downloads raw: it calls DataStore.update (pins, review of changed
    active datasets) for registered datasets only."""
    from v3lum.core import datasets as ds
    from v3lum.ui.theme import make_console as mk

    calls: list[str] = []

    def fake_update(self: Any, name: str, **_k: Any) -> Any:
        calls.append(name)
        return ds.UpdateResult(name, "needs_accept", reason="changed upstream")

    monkeypatch.setattr(ds.DataStore, "update", fake_update)
    monkeypatch.setattr(ds.DataStore, "fetch", lambda *a, **k: (_ for _ in ()).throw(AssertionError("raw fetch")))
    monkeypatch.setitem(ds.DATASETS, "wp13_probe", {"url": "https://example.test/x.json", "essential": False})
    rows = App(mk(no_color=True), fx=False).data_update(["wp13_probe", "not_registered"])
    assert calls == ["wp13_probe"]
    assert rows == [("wp13_probe", "needs_accept: changed upstream"), ("not_registered", "failed: not a registered dataset")]


def test_catalog_listing_needs_no_socks_package(monkeypatch, capsys):
    """`v3lum --tor modules` lists the catalog even without PySocks (a listing sends nothing). No
    `env` fixture: the real App.runtime, which refuses SOCKS without PySocks, is the one exercised
    (never monkeypatch.undo() here - it would also undo the isolated home and the network guard)."""
    import v3lum.app as app_mod

    monkeypatch.setattr(app_mod, "package_available", lambda name: False)
    with pytest.raises(app_mod.UserError):
        App(make_console(no_color=True), fx=False, proxy=app_mod.TOR_PROXY).runtime()  # scans still refuse
    assert main(["--tor", "modules", "-s", "dns_records"]) == 0
    assert "dns_records" in capsys.readouterr().out
    assert main(["--tor", "info", "dns_records"]) == 0
