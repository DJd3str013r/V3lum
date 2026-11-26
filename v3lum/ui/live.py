"""Live scan feed: one line per meaningful event, printed above a spinner/status line.

Every printed value goes through ``ui.safe`` (AR13): module names, entity displays (masked through
``entities.display_value``; URLs and hostile values defanged unless the scan ran with
``--no-defang``), finding titles, errors, log messages and URLs reach the terminal as
:class:`rich.text.Text` with control characters removed, never as markup; valid CPFs quoted in
module text (titles, errors, log lines) are masked unless the scan runs with ``--show-personal``
(AR24). HTTP lines re-apply
``redact.redact_url`` (and errors ``redact.redact_text``) defensively, although the HTTP client already
redacts what it emits (AR01). Module lines show the canonical reason code of non-ok outcomes
('blocked (challenge)', 'quota (quota)') and partial runs ('partial: request_cap'). Handlers accept
extra payload keys, so new event fields never break the feed.
"""

from __future__ import annotations

import threading
import time
from typing import Any

from rich.console import Console
from rich.status import Status as RichStatus
from rich.text import Text

from v3lum.core import redact as _redact
from v3lum.core.models import ModuleResult, Severity, Status
from v3lum.ui.safe import clean_text, display_text, entity_display, safe_rich
from v3lum.ui.theme import STATUS_ICON, tlp_style


def _clip(text: str, limit: int) -> str:
    return text if len(text) <= limit else text[: max(0, limit - 1)] + "…"


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
        self.show_personal = False
        self.no_defang = False

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

    def _text(self, value: Any) -> str:
        """Module free text of this scan: controls removed, valid CPFs masked unless the scan runs
        with ``--show-personal`` (``ui.safe.display_text``)."""
        return display_text(value, show_personal=self.show_personal)

    def _entity(self, entity: Any) -> Text:
        etype = getattr(getattr(entity, "type", None), "value", "?")
        t = Text()
        t.append(f"{clean_text(etype)}:", style="v.type")
        value = getattr(entity, "value", "")
        t.append(entity_display(etype, value, show_personal=self.show_personal, no_defang=self.no_defang), style="v.entity")
        return t

    # ------------------------------------------------------------------ events
    def __call__(self, kind: str, payload: dict[str, Any]) -> None:
        with self._lock:
            handler = getattr(self, f"on_{kind}", None)
            if handler:
                handler(**payload)
            self._refresh()

    def on_scan_start(self, case_id: str, seeds: list, options: Any, **_: Any) -> None:
        self.started = time.monotonic()
        self.entities = len(seeds)
        self.show_personal = bool(getattr(options, "show_personal", False))
        self.no_defang = bool(getattr(options, "no_defang", False))
        t = Text()
        t.append("[*] ", style="v.accent")
        t.append_text(safe_rich(f"case {case_id}", "v.title"))
        mode = getattr(getattr(options, "mode", None), "label", str(getattr(options, "mode", "?")))
        t.append(f"  mode={clean_text(mode)} depth={clean_text(getattr(options, 'depth', '?'))}", style="v.dim")
        tlp = getattr(options, "tlp", "") or "amber"
        try:
            from v3lum.core import tlp as _tlp

            label = _tlp.parse(tlp).label
        except ValueError:
            label = "TLP:RED"
        t.append("  ")
        t.append(f" {label} ", style=tlp_style(tlp))
        if getattr(options, "authorized", False):
            t.append("  AUTHORIZED ACTIVE TESTING", style="v.warn")
        self._print(t)

    def on_investigate(self, entity: Any, depth: int, modules: list[str], **_: Any) -> None:
        self.runs_total += len(modules)
        t = Text()
        t.append("[>] " if depth == 0 else "  [>] ", style="v.info")
        t.append_text(self._entity(entity))
        t.append(f"  ({len(modules)} modules, depth {depth})", style="v.dim")
        self._print(t)

    def on_module_start(self, module: str, entity: Any, **_: Any) -> None:
        return

    def on_module_done(self, result: ModuleResult, **_: Any) -> None:
        self.runs_done += 1
        st = result.status
        if self.verbosity < 2 and st in (Status.SKIPPED,):
            return
        if self.verbosity < 2 and st is Status.EMPTY and not result.partial:
            return
        style = f"status.{st.value}"
        t = Text("    ")
        t.append(STATUS_ICON.get(st.value, "[?]") + " ", style=style)
        t.append_text(safe_rich(result.module, "v.module"))
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
            code = clean_text(getattr(result, "reason_code", "") or "")
            if code and code != st.value:
                t.append(f" ({code})", style=style)
            if result.error and st is not Status.EMPTY:
                t.append(": " + _clip(self._text(_redact.redact_text(result.error)), 110), style="v.dim")
        if getattr(result, "partial", False):
            t.append(f"  partial: {clean_text(getattr(result, 'stop_reason', '') or 'stopped early')}", style="v.warn")
        t.append(f"  {result.duration:.1f}s", style="v.ghost")
        if result.cache_hits and not result.requests:
            t.append(" (cache)", style="v.ghost")
        self._print(t)

    def on_entity(self, entity: Any, parent: Any, relation: str, module: str, depth: int, **_: Any) -> None:
        self.entities += 1
        if self.verbosity < 2:
            return
        t = Text("      ")
        t.append("◆ ", style="v.glitch")
        t.append_text(self._entity(entity))
        t.append(f"  ← {clean_text(relation)} ({clean_text(module)})", style="v.ghost")
        self._print(t)

    def on_finding(self, finding: Any, **_: Any) -> None:
        self.findings += 1
        if finding.severity < Severity.MEDIUM:
            return
        sev = finding.severity.label
        t = Text("      ")
        t.append(f"{sev.upper():>8} ", style=f"sev.{sev}")
        label = getattr(getattr(finding, "label", None), "value", "")
        if label:
            t.append(f"{label.upper():<9} ", style=f"conf.{label}")
        t.append(_clip(self._text(finding.title), 120), style="v.text")
        self._print(t)

    def on_http(self, method: str, url: str, status: int, elapsed: float, cached: bool, error: str, **_: Any) -> None:
        if self.verbosity < 2:
            return
        t = Text("        ")
        t.append(f"{clean_text(method)} ", style="v.ghost")
        t.append(_clip(self._text(_redact.redact_url(str(url or ""))), 120), style="v.ghost")
        if error:
            t.append("  " + _clip(self._text(_redact.redact_text(error)), 160), style="status.error")
        else:
            try:
                code = int(status)
            except (TypeError, ValueError):
                code = 0
            t.append(f"  {code}", style="status.ok" if 200 <= code < 400 else "status.error")
            t.append("  cache" if cached else f"  {float(elapsed or 0) * 1000:.0f}ms", style="v.ghost")
        self._print(t)

    def on_log(self, module: str, message: str, level: str = "info", **_: Any) -> None:
        if self.verbosity < 2 and level == "debug":
            return
        style = {"warn": "v.warn", "error": "v.err", "debug": "v.ghost"}.get(level, "v.dim")
        self._print(Text(f"      [{clean_text(module)}] {self._text(_redact.redact_text(message))}", style=style))

    def on_correlation(self, correlation: Any, **_: Any) -> None:
        return

    def on_scan_done(self, case: Any, **_: Any) -> None:
        t = Text()
        t.append("[✓] ", style="v.ok")
        t.append(f"done in {case.duration if case.duration else time.monotonic() - self.started:.1f}s", style="v.text")
        self._print(t)
