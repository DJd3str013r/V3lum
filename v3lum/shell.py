"""Interactive console. Anything that is not a command is investigated directly.

    v3lum[passive]▸ john.doe@acme.com            # auto-detect + scan
    v3lum[passive]▸ set depth 2
    v3lum[passive]▸ run shodan_internetdb 1.1.1.1
    v3lum[passive]▸ modules -c email
"""

from __future__ import annotations

import argparse
import cmd
import os
import shlex
import sys
from typing import Any

from rich.table import Table
from rich.text import Text

from v3lum import paths
from v3lum.ui.banner import print_banner

COMMANDS = [
    "scan", "detect", "run", "modules", "info", "links", "extract", "keys", "cases", "feedback",
    "data", "cache", "doctor", "config", "set", "show", "help", "clear", "exit", "quit", "version",
]
SETTABLE = {
    "mode": "passive | light | active",
    "depth": "pivot depth (0-3)",
    "format": "report formats, e.g. html,md,json,stix",
    "verbose": "0 quiet · 1 normal · 2 verbose",
    "feedback": "on | off (ask 'did this make sense?')",
    "max_entities": "entity budget per scan",
    "authorized": "<reference> to enable active mode for this session · off to disable",
    "full": "on | off (print the full terminal report)",
}


class Shell(cmd.Cmd):
    def __init__(self, app: Any, console: Any, parser: argparse.ArgumentParser) -> None:
        super().__init__()
        self.app = app
        self.console = console
        self.parser = parser
        cfg = app.config
        self.session: dict[str, Any] = {
            "mode": str(cfg.get("mode")),
            "depth": int(cfg.get("depth")),
            "format": ",".join(cfg.get("report_formats")),
            "verbose": app.verbosity,
            "feedback": bool(cfg.get("feedback")),
            "max_entities": int(cfg.get("max_entities")),
            "authorized": "",
            "full": False,
        }
        self._history = str(paths.home() / "shell_history")

    # ------------------------------------------------------------------ prompt
    @property
    def prompt(self) -> str:  # type: ignore[override]
        mode = self.session["mode"]
        color = {"passive": "32", "light": "36", "active": "33"}.get(mode, "32")
        if self.console.no_color or not sys.stdout.isatty() or not sys.stdin.isatty():
            return f"v3lum[{mode}]> "
        return f"\001\033[1;32m\002v3lum\001\033[0m\002\001\033[2m\002[\001\033[0;{color}m\002{mode}\001\033[0m\033[2m\002]\001\033[0m\002\001\033[1;35m\002▸\001\033[0m\002 "

    def run(self) -> int:
        try:
            import readline

            if os.path.exists(self._history):
                readline.read_history_file(self._history)
            readline.set_history_length(2000)
            readline.set_completer_delims(" \t\n")
        except (ImportError, OSError):
            readline = None  # type: ignore[assignment]
        print_banner(self.console, fx=self.app.fx, status=self.app.status_line())
        self.console.print(Text("  type anything to investigate it (email, domain, IP, hash, @user, CNPJ, wallet, CVE, file...)", style="v.dim"))
        self.console.print(Text("  `help` for commands · `modules` for the arsenal · `exit` to leave\n", style="v.ghost"))
        while True:
            try:
                self.cmdloop()
                break
            except KeyboardInterrupt:
                self.console.print(Text("\n(^C) type exit to quit", style="v.ghost"))
        if readline is not None:
            try:
                readline.write_history_file(self._history)
            except OSError:
                pass
        return 0

    def emptyline(self) -> bool:
        return False

    # ------------------------------------------------------------------ dispatch
    def onecmd(self, line: str) -> bool:
        line = line.strip()
        if not line:
            return False
        if line in ("exit", "quit", "q", "EOF"):
            self.console.print(Text("veil restored. bye.", style="v.dim"))
            return True
        try:
            parts = shlex.split(line)
        except ValueError as exc:
            self.console.print(Text(f"[x] {exc}", style="v.err"))
            return False
        head = parts[0].lower()
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
        if head in COMMANDS:
            argv = parts
            if head == "scan":
                argv = self._scan_argv(parts[1:])
        else:
            # Not a command: the whole line is something to investigate.
            argv = self._scan_argv([line])
        self._dispatch(argv)
        return False

    def _scan_argv(self, rest: list[str]) -> list[str]:
        s = self.session
        argv = ["scan", *rest]
        flags = set(rest)
        if not flags & {"-m", "--mode"}:
            argv += ["--mode", s["mode"]]
        if not flags & {"-d", "--depth"}:
            argv += ["--depth", str(s["depth"])]
        if not flags & {"-f", "--format"}:
            argv += ["--format", s["format"]]
        if not flags & {"--max-entities"}:
            argv += ["--max-entities", str(s["max_entities"])]
        if s["authorized"] and "--authorized" not in flags:
            argv += ["--authorized", s["authorized"]]
        if not s["feedback"] and "--no-feedback" not in flags:
            argv += ["--no-feedback"]
        if s["full"] and "--full" not in flags:
            argv += ["--full"]
        return argv

    def _dispatch(self, argv: list[str]) -> None:
        from v3lum.app import UserError
        from v3lum.cli import dispatch

        try:
            args = self.parser.parse_args(argv)
        except SystemExit:
            return
        self.app.verbosity = int(self.session["verbose"])
        try:
            dispatch(args, self.app, self.console)
        except UserError as exc:
            self.console.print(Text(f"[x] {exc}", style="v.err"))
        except KeyboardInterrupt:
            self.console.print(Text("[!] interrupted", style="v.warn"))
        except Exception as exc:
            if self.app.debug:
                raise
            self.console.print(Text(f"[x] {type(exc).__name__}: {exc}", style="v.err"))

    # ------------------------------------------------------------------ built-ins
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
            if value == "active" and not s["authorized"]:
                self.console.print(Text("[!] active mode needs authorization: `set authorized <contract/scope ref>` first", style="v.warn"))
        elif key in ("depth", "verbose", "max_entities"):
            if not value.isdigit():
                self.console.print(Text(f"[x] {key} must be a number", style="v.err"))
                return
            value = int(value)  # type: ignore[assignment]
        elif key in ("feedback", "full"):
            value = value.lower() in ("on", "yes", "true", "1")  # type: ignore[assignment]
        elif key == "authorized":
            if value.lower() in ("off", "no", "none", ""):
                value = ""
            else:
                self.console.print(Text("[!] active testing enabled for this session: only scan assets you are authorized to test", style="v.warn"))
        s[key] = value
        self.console.print(Text(f"[✓] {key} = {value!r}", style="v.ok"))

    def _show(self) -> None:
        t = Table(show_header=False, box=None)
        t.add_column(style="v.module")
        t.add_column(style="v.text")
        t.add_column(style="v.ghost")
        for k, desc in SETTABLE.items():
            t.add_row(k, repr(self.session[k]), desc)
        self.console.print(t)

    def _help(self, parts: list[str]) -> None:
        if parts and parts[0] in COMMANDS:
            try:
                self.parser.parse_args([parts[0], "--help"])
            except SystemExit:
                pass
            return
        rows = [
            ("<anything>", "investigate it: auto-detects email, domain, IP, URL, hash, phone, @user, CNPJ, wallet, CVE, file..."),
            ("scan <in...> [opts]", "same with options: -d depth, -m mode, -M modules, -c categories, -f formats"),
            ("detect <in...>", "show how an input is recognized (force with TYPE:value)"),
            ("run <module> <in>", "run one module"),
            ("modules [-c cat] [-s txt]", "list modules · `modules --categories`"),
            ("info <module>", "module details (sources, keys, opsec)"),
            ("links <in>", "manual pivot links for web tools"),
            ("extract <file>", "pull IOCs out of a text file"),
            ("keys [set|unset|list]", "API keys"),
            ("cases [list|show|report]", "past investigations ('last' = latest)"),
            ("feedback", "your verdicts and module reliability"),
            ("data [list|update]", "refresh offline datasets"),
            ("doctor", "health check"),
            ("set <k> <v> / show", "session settings: " + ", ".join(SETTABLE)),
            ("clear · exit", ""),
        ]
        t = Table(show_header=False, box=None, padding=(0, 2))
        t.add_column(style="v.module", no_wrap=True)
        t.add_column(style="v.text")
        for a, b in rows:
            t.add_row(a, b)
        self.console.print(t)

    # ------------------------------------------------------------------ completion
    def completenames(self, text: str, *ignored: Any) -> list[str]:
        return [c + " " for c in COMMANDS if c.startswith(text)]

    def completedefault(self, text: str, line: str, begidx: int, endidx: int) -> list[str]:
        from v3lum.core.module import REGISTRY

        head = line.split()[0] if line.split() else ""
        if head in ("run", "info"):
            return [n + " " for n in sorted(REGISTRY) if n.startswith(text)]
        if head == "set":
            return [k + " " for k in SETTABLE if k.startswith(text)]
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
