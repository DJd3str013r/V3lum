"""Live scan feed: one line per meaningful event, printed above a spinner/status line."""

from __future__ import annotations

import threading
import time
from typing import Any

from rich.console import Console
from rich.status import Status as RichStatus
from rich.text import Text

from v3lum.core.models import ModuleResult, Severity, Status
from v3lum.ui.theme import STATUS_ICON


class LiveFeed:
    """Event listener for the engine. ``verbosity``: 0 quiet, 1 normal, 2 verbose (HTTP lines)."""

    def __init__(self, console: Console, verbosity: int = 1) -> None:
        self.console = console
        self.verbosity = verbosity
        self._lock = threading.Lock()
        self._status: RichStatus | None = None
        self.started = time.monotonic()
        self.runs_done = 0
        self.runs_total = 0
        self.entities = 0
        self.findings = 0

    # ------------------------------------------------------------------ lifecycle
    def __enter__(self) -> LiveFeed:
        if self.verbosity > 0 and self.console.is_terminal:
            self._status = self.console.status(self._status_text(), spinner="dots12", spinner_style="v.accent")
            self._status.__enter__()
        return self

    def __exit__(self, *exc: Any) -> None:
        if self._status is not None:
            self._status.__exit__(*exc)
            self._status = None

    def _status_text(self) -> Text:
        t = Text()
        t.append(" scanning ", style="v.accent")
        t.append(f"{self.runs_done}/{self.runs_total} module runs", style="v.text")
        t.append(" · ", style="v.ghost")
        t.append(f"{self.entities} entities", style="v.entity")
        t.append(" · ", style="v.ghost")
        t.append(f"{self.findings} findings", style="v.warn" if self.findings else "v.dim")
        t.append(" · ", style="v.ghost")
        t.append(f"{time.monotonic() - self.started:5.1f}s", style="v.dim")
        t.append("   (Ctrl+C = stop with partial results)", style="v.ghost")
        return t

    def _refresh(self) -> None:
        if self._status is not None:
            self._status.update(self._status_text())

    def _print(self, text: Text) -> None:
        if self.verbosity <= 0:
            return
        self.console.print(text)

    # ------------------------------------------------------------------ events
    def __call__(self, kind: str, payload: dict[str, Any]) -> None:
        with self._lock:
            handler = getattr(self, f"on_{kind}", None)
            if handler:
                handler(**payload)
            self._refresh()

    def on_scan_start(self, case_id: str, seeds: list, options: Any) -> None:
        self.started = time.monotonic()
        self.entities = len(seeds)
        t = Text()
        t.append("[*] ", style="v.accent")
        t.append(f"case {case_id}", style="v.title")
        t.append(f"  mode={options.mode.label} depth={options.depth}", style="v.dim")
        if options.authorized:
            t.append("  AUTHORIZED ACTIVE TESTING", style="v.warn")
        self._print(t)

    def on_investigate(self, entity: Any, depth: int, modules: list[str]) -> None:
        self.runs_total += len(modules)
        t = Text()
        t.append("[>] " if depth == 0 else "  [>] ", style="v.info")
        t.append(f"{entity.type.value}:", style="v.type")
        t.append(entity.display, style="v.entity")
        t.append(f"  ({len(modules)} modules, depth {depth})", style="v.dim")
        self._print(t)

    def on_module_start(self, module: str, entity: Any) -> None:
        return

    def on_module_done(self, result: ModuleResult) -> None:
        self.runs_done += 1
        st = result.status
        if self.verbosity < 2 and st in (Status.SKIPPED,):
            return
        if self.verbosity < 2 and st is Status.EMPTY:
            return
        style = f"status.{st.value}"
        t = Text("    ")
        t.append(STATUS_ICON.get(st.value, "[?]") + " ", style=style)
        t.append(result.module, style="v.module")
        t.append(" → ", style="v.ghost")
        if st is Status.OK:
            parts = []
            if result.findings:
                parts.append(f"{len(result.findings)} finding{'s' if len(result.findings) != 1 else ''}")
            if result.attributes:
                parts.append(f"{len(result.attributes)} facts")
            if result.pivots:
                parts.append(f"{len(result.pivots)} pivots")
            if result.links:
                parts.append(f"{len(result.links)} links")
            t.append(", ".join(parts) or "ok", style="v.text")
        else:
            t.append(st.value.replace("_", " "), style=style)
            if result.error and st is not Status.EMPTY:
                t.append(f": {result.error[:110]}", style="v.dim")
        t.append(f"  {result.duration:.1f}s", style="v.ghost")
        if result.cache_hits and not result.requests:
            t.append(" (cache)", style="v.ghost")
        self._print(t)

    def on_entity(self, entity: Any, parent: Any, relation: str, module: str, depth: int) -> None:
        self.entities += 1
        if self.verbosity < 2:
            return
        t = Text("      ")
        t.append("◆ ", style="v.glitch")
        t.append(f"{entity.type.value}:", style="v.type")
        t.append(entity.display, style="v.entity")
        t.append(f"  ← {relation} ({module})", style="v.ghost")
        self._print(t)

    def on_finding(self, finding: Any) -> None:
        self.findings += 1
        if finding.severity < Severity.MEDIUM:
            return
        sev = finding.severity.label
        t = Text("      ")
        t.append(f"{sev.upper():>8} ", style=f"sev.{sev}")
        t.append(finding.title[:120], style="v.text")
        self._print(t)

    def on_http(self, method: str, url: str, status: int, elapsed: float, cached: bool, error: str) -> None:
        if self.verbosity < 2:
            return
        t = Text("        ")
        t.append(f"{method} ", style="v.ghost")
        t.append(url[:120], style="v.ghost")
        if error:
            t.append(f"  {error}", style="status.error")
        else:
            t.append(f"  {status}", style="status.ok" if 200 <= status < 400 else "status.error")
            t.append("  cache" if cached else f"  {elapsed * 1000:.0f}ms", style="v.ghost")
        self._print(t)

    def on_log(self, module: str, message: str, level: str = "info") -> None:
        if self.verbosity < 2 and level == "debug":
            return
        style = {"warn": "v.warn", "error": "v.err", "debug": "v.ghost"}.get(level, "v.dim")
        self._print(Text(f"      [{module}] {message}", style=style))

    def on_correlation(self, correlation: Any) -> None:
        return

    def on_scan_done(self, case: Any) -> None:
        t = Text()
        t.append("[✓] ", style="v.ok")
        t.append(f"done in {case.duration if case.duration else time.monotonic() - self.started:.1f}s", style="v.text")
        self._print(t)
