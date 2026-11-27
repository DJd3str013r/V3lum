"""``v3lum rules [--json] [--precision] [FILTER]``: the correlation-rule listing (P301, WP22).

One registry, one listing for both kinds of rule (Python ``@rule`` packs and ``v3lum.rule/1`` data
rules): id, code, version, kind, severity, criterion, ATT&CK ids, the legacy flag and the graph
fixtures (``correlate.rules_listing``). ``--precision`` reads the per-rule precision from the case
database (P325 analyst votes, ``Store.rule_precision()``) and marks the rules that ``run_rules``
demotes one severity level (precision < 0.3 after >= 10 votes; never disabled). ``FILTER`` keeps the
rules whose id, code or title contains it. Registration problems (``correlate.RULE_ERRORS``) and the
user rule directory (``~/.v3lum/rules``: loaded, refused by the AR12 ownership checks or the P327
lint) are listed after the table; the exit code is 1 when a rule has a registration error.
"""

from __future__ import annotations

import json
from typing import Any

from rich.markup import escape
from rich.table import Table

from v3lum.commands import command
from v3lum.core import correlate

__all__ = ["Rules", "collect"]


def _clean(value: Any) -> str:
    try:
        from v3lum.ui.safe import clean_text

        return clean_text(value)
    except Exception:  # noqa: BLE001 - WP14 helper unavailable: drop control characters here
        return "".join(ch for ch in str(value or "") if ch in "\n\t" or (ord(ch) >= 32 and not 0x7F <= ord(ch) <= 0x9F))


def collect(*, precision: bool = False, store: Any = None, pattern: str = "") -> dict[str, Any]:
    """The data behind ``v3lum rules``: ``{rules: [...rules_listing rows], errors: {key: message},
    user_rules: [user_rules_report rows], precision_loaded: bool, demoted: [demoted_rules rows]}``."""
    table: Any = None
    loaded = False
    if precision and store is not None:
        try:
            table = store.rule_precision()
            loaded = True
        except Exception:  # noqa: BLE001 - a broken case DB never hides the listing
            table = None
    rows = correlate.rules_listing(precision=table)
    needle = (pattern or "").strip().lower()
    if needle:
        rows = [r for r in rows if needle in r["id"].lower() or needle in (r["code"] or "").lower() or needle in (r["title"] or "").lower()]
    return {
        "rules": rows,
        "errors": dict(sorted(correlate.RULE_ERRORS.items())),
        "user_rules": correlate.user_rules_report(),
        "precision_loaded": loaded,
        # every name run_rules demotes, including correlation names that differ from the registered
        # rule id (high_signal_tags emits tag_sanctions, tag_ransomware...)
        "demoted": [d for d in (correlate.demoted_rules(precision=table) if loaded else []) if not needle or needle in d["id"].lower()],
    }


def _fixtures_cell(row: dict[str, Any]) -> str:
    fixtures = row.get("fixtures") or []
    if not fixtures:
        return "legacy (exempt)" if row.get("legacy") else "-"
    pos = sum(1 for f in fixtures if "/positive_" in f or str(f).startswith("positive_"))
    neg = sum(1 for f in fixtures if "/negative_" in f or str(f).startswith("negative_"))
    return f"{pos}+ / {neg}-" if (pos or neg) else str(len(fixtures))


def _precision_cell(row: dict[str, Any]) -> str:
    if row.get("precision") is None:
        return "-"
    text = f"{float(row['precision']):.2f} ({int(row.get('votes') or 0)})"
    return f"[v.warn]{text} demoted[/]" if row.get("demoted") else text


def render(data: dict[str, Any], console: Any, *, precision: bool) -> None:
    rows = data["rules"]
    table = Table(title=f"correlation rules ({len(rows)})", show_lines=False, expand=False)
    for name in ("id", "code", "ver", "kind", "severity", "criterion", "ATT&CK"):
        table.add_column(name, overflow="fold")
    if precision:
        table.add_column("precision (votes)")
    table.add_column("legacy")
    table.add_column("fixtures")
    for r in rows:
        kind = r["kind"] + (" (user)" if r.get("user") else "")
        cells = [
            escape(_clean(r["id"])), escape(_clean(r["code"] or "-")), escape(_clean(r["version"])), escape(_clean(kind)),
            escape(_clean(r["severity"])), escape(_clean(r["criterion"] or "-"))[:160], escape(", ".join(r["attack"]) or "-"),
        ]
        if precision:
            cells.append(_precision_cell(r))
        cells += ["yes" if r["legacy"] else "", escape(_fixtures_cell(r))]
        table.add_row(*cells)
    console.print(table)
    if precision and not data.get("precision_loaded"):
        console.print("[v.dim]rule precision unavailable (no case database)[/]")
    elif precision:
        demoted = [str(r["id"]) for r in data.get("demoted") or ()] or [r["id"] for r in rows if r.get("demoted")]
        if demoted:
            console.print(
                f"[v.warn]{len(demoted)} rule(s) demoted one severity level (precision < {correlate.PRECISION_THRESHOLD} after "
                f">= {correlate.PRECISION_MIN_VOTES} votes): {escape(', '.join(demoted))}[/]"
            )
    for row in data.get("user_rules") or ():
        line = f"user rules {escape(_clean(row['path']))}: {row['status']}"
        if row.get("reason"):
            line += f" - {escape(_clean(row['reason']))}"
        console.print(f"[v.dim]{line}[/]" if row["status"] == "loaded" else f"[v.warn]{line}[/]")
    errors = data.get("errors") or {}
    if errors:
        console.print(f"[v.bad]{len(errors)} rule registration problem(s):[/]")
        for key, message in errors.items():
            console.print(f"  [v.bad]{escape(_clean(key))}[/]: {escape(_clean(message))}")


@command("rules", "correlation rules: id, code, version, kind, severity, ATT&CK, precision")
class Rules:
    """List every registered correlation rule (Python packs and v3lum.rule/1 data rules)."""

    @staticmethod
    def add_arguments(parser: Any) -> None:
        parser.add_argument("pattern", nargs="?", default="", help="keep rules whose id, code or title contains this text")
        parser.add_argument("--json", action="store_true", help="machine-readable output")
        parser.add_argument("--precision", action="store_true", help="per-rule precision and votes from the case database (P325)")

    @staticmethod
    def run(args: Any, app: Any, console: Any) -> int:
        precision = bool(getattr(args, "precision", False))
        store = None
        if precision:
            try:
                store = app.store
            except Exception:  # noqa: BLE001 - no case DB: listed without precision
                store = None
        data = collect(precision=precision, store=store, pattern=str(getattr(args, "pattern", "") or ""))
        if getattr(args, "json", False):
            console.print_json(json.dumps(data, default=str))
        else:
            render(data, console, precision=precision)
        return 1 if data["errors"] else 0
