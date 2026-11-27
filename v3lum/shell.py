"""Interactive console. Anything that is not a command is investigated directly.

    v3lum[passive|AMBER]> john.doe@acme.com            # auto-detect + scan (path 'shell')
    v3lum[passive|AMBER]> set depth 2
    v3lum[passive|AMBER]> set tlp red                  # lines typed now are not written to history
    v3lum[passive|AMBER]> set authorized PT-2026-042   # bound to `set scope <file>`, expires after 8 h
    v3lum[passive|AMBER]> run shodan_internetdb 1.1.1.1
    v3lum[passive|AMBER]> history clear

Shell history (A10): ``~/.v3lum/shell_history`` holds one JSON line per entry (``{ts, line}``),
written 0600 through ``paths.secure_write_text``; entries older than setting ``retention_days`` are
dropped at shell start, every line is scrubbed like pasted text (``ioc.scrub``: ``sanitize.scrub_text`` plus card numbers and pattern-DB secrets, P145/P323) and
lines typed while the session TLP is RED are never written.
"""

from __future__ import annotations

import argparse
import cmd
import datetime as _dt
import json
import os
import re
import shlex
import sys
import time
from typing import Any

from rich.prompt import Prompt
from rich.table import Table
from rich.text import Text

from v3lum import paths
from v3lum.ui.banner import print_banner

#: The console's own commands (the inline CLI commands and the shell built-ins); commands of the
#: ``v3lum.commands`` registry are appended when a Shell starts (``shell_commands()``).
BASE_COMMANDS: tuple[str, ...] = (
    "scan", "detect", "run", "modules", "info", "extract", "feedback", "cache", "config",
    "set", "show", "help", "clear", "history", "exit", "quit", "version",
)
COMMANDS: list[str] = list(BASE_COMMANDS)
SETTABLE = {
    "mode": "passive | light | active",
    "tlp": "clear | green | amber | amber+strict | red (TLP of this session's inputs; RED lines are not kept in history)",
    "depth": "pivot depth (0-3)",
    "format": "report formats, e.g. html,md,json,stix",
    "verbose": "0 quiet · 1 normal · 2 verbose",
    "feedback": "on | off (ask 'did this make sense?')",
    "max_entities": "entity budget per scan",
    "authorized": "<reference> of the engagement, bound to `set scope` (expires after 8 h) · off",
    "scope": "<file> scope file bound to `set authorized` (expires after 8 h) · off",
    "purpose": "purpose recorded in this session's cases (personal identifiers need one) · off",
    "ticket": "ticket recorded in this session's cases · off",
    "full": "on | off (print the full terminal report)",
}
#: `set authorized` + `set scope` expire this many seconds after they were bound (A7).
BINDING_TTL = 8 * 3600
HISTORY_FILE = "shell_history"
HISTORY_MAX = 2000
_OFF = ("off", "no", "none", "")
#: C0/C1 control characters (ESC included): never stored in or printed from the history (pasted
#: text is attacker-controlled; an escape sequence must not reach the analyst's terminal).
_CONTROL_RE = re.compile(r"[\x00-\x08\x0a-\x1f\x7f-\x9f]")


def shell_commands() -> list[str]:
    """The console commands: :data:`COMMANDS` plus every registered command name and alias
    (``v3lum.commands.load_commands()``). The module-level list is extended in place."""
    try:
        from v3lum.commands import load_commands

        registered = load_commands()
    except Exception:  # noqa: BLE001 - a broken registry never breaks the console
        registered = {}
    for spec in registered.values():
        for name in getattr(spec, "names", (spec.name,)):
            if name not in COMMANDS:
                COMMANDS.append(name)
    return list(COMMANDS)


def _given(tokens: list[str], option_strings: tuple[str, ...]) -> bool:
    """True when ``tokens`` (a typed command line, without the command) set one of
    ``option_strings`` in any argparse form: ``--tlp red``, ``--tlp=red``, an abbreviation such as
    ``--tl red``, or a short flag with its value attached (``-mlight``)."""
    longs = [o for o in option_strings if o.startswith("--")]
    shorts = [o for o in option_strings if not o.startswith("--")]
    for tok in tokens:
        if tok == "--":
            break
        if tok.startswith("--"):
            name = tok.split("=", 1)[0]
            if len(name) > 2 and any(o == name or o.startswith(name) for o in longs):
                return True
        elif tok.startswith("-") and any(tok.startswith(o) for o in shorts):
            return True
    return False


def _utcnow() -> _dt.datetime:
    return _dt.datetime.now(_dt.timezone.utc)


def _parse_ts(value: Any) -> _dt.datetime | None:
    try:
        ts = _dt.datetime.fromisoformat(str(value))
    except (TypeError, ValueError):
        return None
    return ts if ts.tzinfo else ts.replace(tzinfo=_dt.timezone.utc)


class Shell(cmd.Cmd):
    def __init__(self, app: Any, console: Any, parser: argparse.ArgumentParser) -> None:
        super().__init__()
        self.app = app
        self.console = console
        self.parser = parser
        cfg = app.config
        self.session: dict[str, Any] = {
            "mode": str(cfg.get("mode")),
            "tlp": str(cfg.get("tlp") or "amber"),
            "depth": int(cfg.get("depth")),
            "format": ",".join(cfg.get("report_formats")),
            "verbose": app.verbosity,
            "feedback": bool(cfg.get("feedback")),
            "max_entities": int(cfg.get("max_entities")),
            "authorized": "",
            "scope": "",
            "purpose": "",
            "ticket": "",
            "full": False,
        }
        #: wall clock of the authorization binding (``time.time``; injectable in tests)
        self.clock = time.time
        self._bound_at: float | None = None
        self.commands = shell_commands()
        self._history_path = paths.home() / HISTORY_FILE
        self._readline: Any = None
        self.history: list[dict[str, str]] = []
        self.load_history()

    # ------------------------------------------------------------------ prompt
    def _tlp_label(self) -> str:
        from v3lum.core import tlp as _tlp

        try:
            return _tlp.parse(self.session.get("tlp") or "amber").value_str.upper()
        except ValueError:
            return "RED"

    @property
    def prompt(self) -> str:  # type: ignore[override]
        mode = self.session["mode"]
        level = self._tlp_label()
        if self.console.no_color or not sys.stdout.isatty() or not sys.stdin.isatty():
            return f"v3lum[{mode}|{level}]> "
        color = {"passive": "32", "light": "36", "active": "33"}.get(mode, "32")
        tlp_color = {"CLEAR": "37", "GREEN": "32", "AMBER": "33", "AMBER+STRICT": "33", "RED": "31"}.get(level, "33")
        return (
            f"\001\033[1;32m\002v3lum\001\033[0m\002\001\033[2m\002[\001\033[0;{color}m\002{mode}\001\033[0m\033[2m\002|"
            f"\001\033[0;{tlp_color}m\002{level}\001\033[0m\033[2m\002]\001\033[0m\002\001\033[1;35m\002▸\001\033[0m\002 "
        )

    # ------------------------------------------------------------------ history (A10)
    def _retention_days(self) -> int:
        try:
            return max(0, int(float(self.app.config.get("retention_days") or 0)))
        except (TypeError, ValueError):
            return 180

    def load_history(self) -> list[dict[str, str]]:
        """Read the history file, dropping entries older than retention_days (and legacy lines
        without a timestamp); the file is rewritten 0600 when something was dropped."""
        try:
            text = self._history_path.read_text(encoding="utf-8")
        except OSError:
            text = ""
        days = self._retention_days()
        cutoff = _utcnow() - _dt.timedelta(days=days) if days > 0 else None
        kept: list[dict[str, str]] = []
        dropped = 0
        for raw in text.splitlines():
            if not raw.strip():
                continue
            try:
                item = json.loads(raw)
            except ValueError:
                dropped += 1  # a legacy readline line: no timestamp, retention unknown
                continue
            ts = _parse_ts(item.get("ts")) if isinstance(item, dict) else None
            line = item.get("line") if isinstance(item, dict) else None
            if ts is None or not isinstance(line, str) or (cutoff is not None and ts < cutoff):
                dropped += 1
                continue
            kept.append({"ts": ts.isoformat(timespec="seconds"), "line": _CONTROL_RE.sub(" ", line)})
        self.history = kept[-HISTORY_MAX:]
        if dropped or len(kept) > HISTORY_MAX:
            self.save_history()
        return self.history

    def save_history(self) -> None:
        """Write the history file 0600 (``paths.secure_write_text``)."""
        body = "".join(json.dumps(e, ensure_ascii=False) + "\n" for e in self.history[-HISTORY_MAX:])
        try:
            paths.secure_write_text(self._history_path, body)
        except OSError:  # pragma: no cover - a read-only home keeps the session history in memory
            pass

    def clear_history(self) -> None:
        """``history clear``: forget every entry (file and readline buffer)."""
        self.history = []
        self.save_history()
        if self._readline is not None:
            try:
                self._readline.clear_history()
            except Exception:  # noqa: BLE001 - readline variants without clear_history
                pass

    def _red_line(self, line: str) -> bool:
        if self._tlp_label() == "RED":
            return True
        try:
            parts = shlex.split(line)
        except ValueError:
            parts = line.split()
        for i, part in enumerate(parts):
            name, eq, value = part.partition("=")
            if not (name.startswith("--") and len(name) > 2 and "--tlp".startswith(name)):
                continue  # --tlp in any argparse form: --tlp red, --tlp=red, --tl red
            if not eq:
                value = parts[i + 1] if i + 1 < len(parts) else ""
            if value.strip().lower() == "red":
                return True
        return False

    def remember(self, line: str) -> str | None:
        """Record a typed line (scrubbed, P145); lines of a TLP:RED session are not kept.
        Returns the recorded text (None when nothing was recorded)."""
        from v3lum.core import ioc

        text = line.strip()
        if not text:
            return None
        red = self._red_line(text)
        scrubbed = None if red else _CONTROL_RE.sub(" ", ioc.scrub(text)).strip()
        self._sync_readline(line, scrubbed)
        if scrubbed is None or not scrubbed.strip():
            return None
        self.history.append({"ts": _utcnow().isoformat(timespec="seconds"), "line": scrubbed})
        if len(self.history) > HISTORY_MAX:
            self.history = self.history[-HISTORY_MAX:]
        return scrubbed

    def _sync_readline(self, raw: str, scrubbed: str | None) -> None:
        """Make readline's in-memory buffer match: the raw line typed is replaced by its scrubbed
        form, or removed (RED session)."""
        rl = self._readline
        if rl is None:
            return
        try:
            n = rl.get_current_history_length()
            if n <= 0 or rl.get_history_item(n) not in (raw, raw.strip()):
                return
            if scrubbed is None or not scrubbed.strip():
                rl.remove_history_item(n - 1)
            elif scrubbed != rl.get_history_item(n):
                rl.replace_history_item(n - 1, scrubbed)
        except Exception:  # noqa: BLE001 - libedit and other readline variants
            pass

    # ------------------------------------------------------------------ loop
    def run(self) -> int:
        try:
            import readline

            readline.clear_history()
            for entry in self.history:
                readline.add_history(entry["line"])
            readline.set_history_length(HISTORY_MAX)
            readline.set_completer_delims(" \t\n")
            self._readline = readline
        except (ImportError, OSError, AttributeError):
            self._readline = None
        print_banner(self.console, fx=self.app.fx, status=self.app.status_line())
        self.console.print(Text("  type anything to investigate it (email, domain, IP, hash, @user, CNPJ, wallet, CVE, file...)", style="v.dim"))
        self.console.print(Text("  `help` for commands · `modules` for the arsenal · `exit` to leave\n", style="v.ghost"))
        try:
            while True:
                try:
                    self.cmdloop()
                    break
                except KeyboardInterrupt:
                    self.console.print(Text("\n(^C) type exit to quit", style="v.ghost"))
        finally:
            self.save_history()
        return 0

    def emptyline(self) -> bool:
        return False

    # ------------------------------------------------------------------ dispatch
    def onecmd(self, line: str) -> bool:
        raw = line
        line = line.strip()
        if not line:
            return False
        if line in ("exit", "quit", "q", "EOF"):
            self.console.print(Text("veil restored. bye.", style="v.dim"))
            return True
        try:
            parts = shlex.split(line)
        except ValueError as exc:
            self.remember(raw)
            self.console.print(Text(f"[x] {exc}", style="v.err"))
            return False
        head = parts[0].lower()
        if head == "history":
            self._history(parts[1:])
            return False
        self.remember(raw)
        if head in ("help", "?"):
            self._help(parts[1:])
            return False
        if head == "clear":
            self.console.clear()
            return False
        if head == "set":
            self._set(parts[1:])
            return False
        if head == "show":
            self._show()
            return False
        if head in self.commands:
            if head == "scan":
                argv = self._scan_argv(parts[1:])
            else:  # run, extract, links...: the session flags their parser takes (never overriding typed ones)
                argv = self._engagement_argv(parts)
        else:
            # Not a command: the whole line is ONE input to investigate ('--' keeps a value that
            # starts with '-' from being read as an option).
            argv = self._scan_argv([line], bare=True)
        if argv is not None:
            self._dispatch(argv)
        return False

    def _binding_expired(self) -> bool:
        return self._bound_at is not None and self.clock() - self._bound_at >= BINDING_TTL

    def _check_binding(self) -> None:
        """`set authorized` + `set scope` expire 8 h after they were bound (A7): re-prompt in a
        TTY, else clear both."""
        if not self._binding_expired():
            return
        ref, scope = self.session["authorized"], self.session["scope"]
        self.session["authorized"] = ""
        self.session["scope"] = ""
        self._bound_at = None
        self.console.print(Text("[!] the authorization binding expired after 8 h (A7): confirm it again", style="v.warn"))
        if not (sys.stdin.isatty() and sys.stdout.isatty()):
            self.console.print(Text("    `set authorized <ref>` and `set scope <file>` to bind it again", style="v.dim"))
            return
        new_ref = Prompt.ask("[v.warn]authorization reference[/]", default=ref or "", console=self.console).strip()
        if new_ref and self._set_authorized(new_ref) and (scope or "").strip():
            new_scope = Prompt.ask("[v.warn]scope file[/]", default=scope, console=self.console).strip()
            if new_scope:
                self._set_scope(new_scope)

    def _option_strings(self, command: str, dest: str) -> tuple[str, ...]:
        """The option strings of ``dest`` on the sub-parser of ``command`` (name or alias); () when
        that command takes no such option."""
        for action in getattr(self.parser, "_actions", ()):
            if isinstance(action, argparse._SubParsersAction):  # noqa: SLF001 - argparse has no public accessor
                sub = action.choices.get(command)
                if sub is None:
                    return ()
                for opt in sub._actions:  # noqa: SLF001
                    if opt.dest == dest and opt.option_strings:
                        return tuple(opt.option_strings)
        return ()

    def _session_flags(self, command: str, typed: list[str], wanted: list[tuple[str, Any]]) -> list[str]:
        """Session values as ``[flag, value...]`` for the options ``command`` takes and the analyst
        did not type (any argparse form: ``--tlp red``, ``--tlp=red``, an abbreviation, ``-mlight``).
        ``wanted``: ``(dest, value)``; value None = skip, True = a store_true flag."""
        out: list[str] = []
        for dest, value in wanted:
            if value is None or value is False:
                continue
            opts = self._option_strings(command, dest)
            if not opts or _given(typed, opts):
                continue
            flag = next((o for o in opts if o.startswith("--")), opts[0])
            if value is True:
                out.append(flag)
            elif str(value).startswith("-"):
                out.append(f"{flag}={value}")  # a value that looks like an option stays a value
            else:
                out += [flag, str(value)]
        return out

    def _engagement_wanted(self, command: str) -> list[tuple[str, Any]]:
        """The session's rules-of-engagement values (TLP, binding, purpose, ticket) for ``command``;
        an expired authorization binding is re-confirmed first (A7)."""
        if self._option_strings(command, "authorized"):
            self._check_binding()
        s = self.session
        return [
            ("tlp", s.get("tlp") or None),
            ("authorized", s["authorized"] or None),
            ("scope", s["scope"] or None),
            ("purpose", s["purpose"] or None),
            ("ticket", s["ticket"] or None),
        ]

    def _engagement_argv(self, parts: list[str]) -> list[str]:
        """``parts`` with the session TLP, authorization, scope, purpose and ticket (and, for run and
        extract, the session mode) for every option its command takes. The session values come
        right after the command name, so whatever the analyst typed wins (argparse: last wins)."""
        if not parts:
            return []
        command, typed = parts[0], list(parts[1:])
        wanted = self._engagement_wanted(command)
        if command.lower() in ("run", "extract"):
            wanted.append(("mode", self.session["mode"]))
        return [command, *self._session_flags(command, typed, wanted), *typed]

    def _scan_argv(self, rest: list[str], *, bare: bool = False) -> list[str]:
        """A ``scan`` argv with the session settings. ``bare``: ``rest`` is one typed line to
        investigate as a whole (after ``--``), not options."""
        s = self.session
        typed = [] if bare else list(rest)
        wanted = self._engagement_wanted("scan") + [
            ("mode", s["mode"]),
            ("depth", str(s["depth"])),
            ("format", str(s["format"])),
            ("max_entities", str(s["max_entities"])),
            ("no_feedback", not s["feedback"]),
            ("full", bool(s["full"])),
        ]
        tail = ["--", *rest] if bare else typed
        return ["scan", *self._session_flags("scan", typed, wanted), *tail]

    def _dispatch(self, argv: list[str]) -> None:
        from v3lum.app import UserError
        from v3lum.cli import dispatch

        try:
            args = self.parser.parse_args(argv)
        except SystemExit:
            return
        self.app.verbosity = int(self.session["verbose"])
        self.app.machine = False
        try:
            dispatch(args, self.app, self.console, path="shell")
        except UserError as exc:
            self.console.print(Text(f"[x] {exc}", style="v.err"))
        except KeyboardInterrupt:
            self.console.print(Text("[!] interrupted", style="v.warn"))
        except Exception as exc:
            if self.app.debug:
                raise
            self.console.print(Text(f"[x] {type(exc).__name__}: {exc}", style="v.err"))

    # ------------------------------------------------------------------ built-ins
    def _set_authorized(self, value: str) -> bool:
        from v3lum.core import policy

        problem = policy.authorization_problem(value)
        if problem:
            self.console.print(Text(f"[x] {problem}", style="v.err"))
            return False
        scope_path = self.session["scope"]
        if scope_path:
            problems = self._scope_problems(scope_path, value)
            if problems:
                self.console.print(Text(f"[x] the session scope does not bind {value!r}: {'; '.join(problems[:3])}", style="v.err"))
                return False
        self.session["authorized"] = value
        self._bound_at = self.clock()
        tail = "" if scope_path else " · bind its scope file: `set scope <file>`"
        self.console.print(Text(f"[!] authorization {value} set for 8 h: only scan assets inside its scope{tail}", style="v.warn"))
        return True

    def _scope_problems(self, path: str, ref: str) -> list[str]:
        from v3lum.core.scope import Scope, ScopeError

        try:
            scope = Scope.load(path)
        except ScopeError as exc:
            return [str(exc)]
        if not ref:
            return [str(p) for p in scope.problems]
        return [str(p) for p in scope.validate(ref, _utcnow())]

    def _set_scope(self, value: str) -> bool:
        path = os.path.abspath(os.path.expanduser(value))
        problems = self._scope_problems(path, self.session["authorized"])
        if problems:
            self.console.print(Text(f"[x] scope file refused: {'; '.join(problems[:3])}", style="v.err"))
            return False
        self.session["scope"] = path
        self._bound_at = self.clock()
        tail = "" if self.session["authorized"] else " · bind it: `set authorized <ref>`"
        self.console.print(Text(f"[✓] scope = {path} (expires after 8 h){tail}", style="v.ok"))
        return True

    def _set(self, parts: list[str]) -> None:
        if len(parts) < 2:
            self._show()
            return
        key, value = parts[0].lower(), " ".join(parts[1:])
        s = self.session
        if key not in SETTABLE:
            self.console.print(Text(f"[x] unknown setting {key!r}; settable: {', '.join(SETTABLE)}", style="v.err"))
            return
        if key == "mode":
            if value not in ("passive", "light", "active"):
                self.console.print(Text("[x] mode must be passive, light or active", style="v.err"))
                return
            if value == "active" and not (s["authorized"] and s["scope"]):
                self.console.print(Text("[!] active mode needs `set authorized <ref>` and `set scope <file>` (A7)", style="v.warn"))
        elif key == "tlp":
            from v3lum.core import tlp as _tlp

            try:
                level = _tlp.parse(value)
            except ValueError as exc:
                self.console.print(Text(f"[x] {exc}", style="v.err"))
                return
            value = level.value_str
            default = self.app.configured_tlp() if hasattr(self.app, "configured_tlp") else _tlp.TLP.AMBER
            if level < default:
                self.console.print(Text(f"[!] {level.label} is below the configured {default.label}: every scan records the lowering in its case audit", style="v.warn"))
            if level is _tlp.TLP.RED:
                self.console.print(Text("[i] TLP:RED: only offline and internal sources run; lines typed now are not written to history", style="v.dim"))
        elif key in ("depth", "verbose", "max_entities"):
            if not value.isdigit():
                self.console.print(Text(f"[x] {key} must be a number", style="v.err"))
                return
            value = int(value)  # type: ignore[assignment]
        elif key in ("feedback", "full"):
            value = value.lower() in ("on", "yes", "true", "1")  # type: ignore[assignment]
        elif key == "authorized":
            if value.lower() in _OFF:
                s["authorized"] = ""
                self._bound_at = None if not s["scope"] else self._bound_at
                self.console.print(Text("[✓] authorized = ''", style="v.ok"))
                return
            self._set_authorized(value)
            return
        elif key == "scope":
            if value.lower() in _OFF:
                s["scope"] = ""
                self.console.print(Text("[✓] scope = ''", style="v.ok"))
                return
            self._set_scope(value)
            return
        elif key in ("purpose", "ticket") and value.lower() in _OFF:
            value = ""
        s[key] = value
        self.console.print(Text(f"[✓] {key} = {value!r}", style="v.ok"))

    def _show(self) -> None:
        t = Table(show_header=False, box=None)
        t.add_column(style="v.module")
        t.add_column(style="v.text")
        t.add_column(style="v.ghost")
        for k, desc in SETTABLE.items():
            value = repr(self.session[k])
            if k in ("authorized", "scope") and self.session[k] and self._bound_at is not None:
                left = max(0, int(BINDING_TTL - (self.clock() - self._bound_at)))
                value += f" ({left // 3600} h {left % 3600 // 60} min left)"
            t.add_row(k, value, desc)
        self.console.print(t)

    def _history(self, parts: list[str]) -> None:
        if parts and parts[0].lower() == "clear":
            self.clear_history()
            self.console.print(Text("[✓] shell history cleared", style="v.ok"))
            return
        if not self.history:
            self.console.print(Text("history is empty", style="v.dim"))
            return
        for entry in self.history[-20:]:
            self.console.print(Text.assemble((f"{_CONTROL_RE.sub(' ', entry['ts'][:19])}  ", "v.ghost"), (_CONTROL_RE.sub(" ", entry["line"]), "v.text")))

    def _help(self, parts: list[str]) -> None:
        if parts and parts[0] in self.commands and parts[0] not in ("set", "show", "help", "clear", "history", "exit", "quit"):
            try:
                self.parser.parse_args([parts[0], "--help"])
            except SystemExit:
                pass
            return
        rows = [
            ("<anything>", "investigate it: auto-detects email, domain, IP, URL, hash, phone, @user, CNPJ, wallet, CVE, file..."),
            ("scan <in...> [opts]", "same with options: -d depth, -m mode, -M modules, -c categories, -f formats, --tlp, --purpose"),
            ("detect <in...>", "show how an input is recognized (force with TYPE:value)"),
            ("run <module> <in>", "run one module (never above the session mode)"),
            ("modules [-c cat] [-s txt]", "list modules · `modules --categories`"),
            ("info <module>", "module details and the policy that applies to it"),
            ("extract <file>", "pull IOCs out of a text file (defanged)"),
            ("feedback", "your verdicts and source reliability"),
            ("set <k> <v> / show", "session settings: " + ", ".join(SETTABLE)),
            ("history [clear]", "recent lines (scrubbed; TLP:RED lines are never kept) · forget them"),
            ("clear · exit", ""),
        ]
        extra = sorted(c for c in self.commands if c not in BASE_COMMANDS)
        try:
            from v3lum.commands import lookup

            for name in extra:
                spec = lookup(name)
                if spec is not None and name == spec.name:
                    rows.append((name, spec.help))
        except Exception:  # noqa: BLE001
            pass
        t = Table(show_header=False, box=None, padding=(0, 2))
        t.add_column(style="v.module", no_wrap=True)
        t.add_column(style="v.text")
        for a, b in rows:
            t.add_row(a, b)
        self.console.print(t)

    # ------------------------------------------------------------------ completion
    def completenames(self, text: str, *ignored: Any) -> list[str]:
        return [c + " " for c in self.commands if c.startswith(text)]

    def completedefault(self, text: str, line: str, begidx: int, endidx: int) -> list[str]:
        from v3lum.core.module import REGISTRY

        head = line.split()[0] if line.split() else ""
        if head in ("run", "info"):
            return [n + " " for n in sorted(REGISTRY) if n.startswith(text)]
        if head == "set":
            return [k + " " for k in SETTABLE if k.startswith(text)]
        if head == "history":
            return ["clear "] if "clear".startswith(text) else []
        return []

    def complete(self, text: str, state: int) -> str | None:  # pragma: no cover - readline glue
        import readline

        line = readline.get_line_buffer()
        begidx = readline.get_begidx()
        if begidx == 0:
            matches = self.completenames(text)
        else:
            matches = self.completedefault(text, line, begidx, readline.get_endidx())
        return matches[state] if state < len(matches) else None
