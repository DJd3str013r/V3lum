"""``v3lum data``: downloadable datasets (dataset manager v2, AR10).

* ``data list``: every registered dataset with its licence, terms class, age, stale flag, size and
  flags (essential, active), plus the first-run hint (``DataStore.first_run_hint()``).
* ``data update [names...] [--essential] [--accept-new [--sha256 HEX]]``: ``DataStore.update`` for
  the named datasets, the essential ones (``--essential``) or every registered dataset. Downloads
  are conditional, validated and atomic (the previous copy survives a bad refresh).

Active datasets (they drive LIGHT/ACTIVE behaviour and are pinned) are never installed blind: a
changed copy comes back ``needs_accept`` with its diff summary, which is printed, and is staged.
``--accept-new`` then installs exactly the staged (reviewed) bytes: in a terminal right after the
summary when the analyst confirms; in a non-interactive run on the next ``--accept-new`` call
(the summary was shown by the first one); directly when ``--sha256`` names the reviewed hash.
"""

from __future__ import annotations

import json
import re
import sys
from typing import Any

from rich import box
from rich.prompt import Confirm
from rich.table import Table
from rich.text import Text

from v3lum.commands import command

__all__ = ["Data", "datasets_rows", "datasets_table", "update_datasets"]


def _clean(value: Any) -> str:
    try:
        from v3lum.ui.safe import clean_text

        return clean_text(value)
    except Exception:  # noqa: BLE001 - WP14 helper unavailable: drop control characters here
        return "".join(ch for ch in str(value or "") if ch in "\n\t" or (ord(ch) >= 32 and not 0x7F <= ord(ch) <= 0x9F))


def _user_error(message: str) -> Exception:
    from v3lum.app import UserError

    return UserError(message)


def _tty() -> bool:
    try:
        return bool(sys.stdin.isatty())
    except (AttributeError, ValueError):
        return False


def _size(n: int) -> str:
    if n >= 1024 * 1024:
        return f"{n / (1024 * 1024):.1f} MB"
    if n >= 1024:
        return f"{n // 1024} KB"
    return f"{n} B"


def datasets_rows(store: Any) -> list[dict[str, Any]]:
    """Machine form of ``data list``: one dict per registered dataset (no URL, never a key)."""
    from v3lum.core.datasets import DATASETS

    out = []
    for name in sorted(DATASETS):
        reg = DATASETS[name]
        try:
            info = store.info(name)
        except Exception as exc:  # noqa: BLE001
            out.append({"name": name, "error": str(exc)[:200]})
            continue
        out.append({
            "name": name, "present": info.present, "licence": info.licence, "terms_class": info.terms_class,
            "age_hours": info.age_hours, "stale": info.stale, "bytes": info.bytes, "sha256": info.sha256,
            "fetched_at": info.fetched_at, "essential": bool(reg.get("essential")), "active": bool(reg.get("active")),
            "description": str(reg.get("description") or ""),
        })
    return out


def datasets_table(store: Any) -> Table:
    """Registered datasets: licence, terms class, age, stale, size, flags and description."""
    from v3lum.core.datasets import DATASETS

    t = Table(box=box.SIMPLE_HEAVY, header_style="v.dim", expand=True, title="[v.accent]◫ datasets[/]", title_justify="left")
    t.add_column("dataset", style="v.module", no_wrap=True)
    t.add_column("licence", overflow="fold", max_width=18)
    t.add_column("terms", no_wrap=True)
    t.add_column("age", justify="right", no_wrap=True)
    t.add_column("stale", no_wrap=True)
    t.add_column("size", justify="right", no_wrap=True)
    t.add_column("flags", no_wrap=True)
    t.add_column("description", style="v.text", overflow="fold", ratio=2)
    for name in sorted(DATASETS):
        reg = DATASETS[name]
        try:
            info = store.info(name)
        except Exception as exc:  # noqa: BLE001 - one broken entry never hides the others
            t.add_row(Text(_clean(name)), "", "", "", "", "", "", Text(f"error: {_clean(exc)[:120]}", style="status.error"))
            continue
        flags = ",".join(f for f, on in (("essential", reg.get("essential")), ("active", reg.get("active"))) if on)
        if info.present:
            age = f"{info.age_hours:.1f} h" if info.age_hours is not None else "?"
            stale = Text("stale", style="v.warn") if info.stale else Text("fresh", style="v.ok")
            size = _size(int(info.bytes or 0))
        else:
            age, stale, size = "-", Text("not downloaded", style="v.ghost"), "-"
        terms_style = "v.ok" if info.terms_class == "open" else ("v.warn" if info.terms_class in ("noncommercial", "license", "unknown") else "v.text")
        t.add_row(
            Text(_clean(name)), Text(_clean(info.licence or "-")), Text(_clean(info.terms_class), style=terms_style), age, stale, size, flags,
            Text(_clean(reg.get("description") or "")),
        )
    t.caption = f"{len(DATASETS)} registered · refresh: v3lum data update [names] [--essential]"
    return t


def _result_line(console: Any, res: Any) -> None:
    style = {"updated": "status.ok", "unchanged": "v.dim", "needs_accept": "v.warn"}.get(res.status, "status.error")
    detail = res.status
    if res.status == "updated" and res.new_sha256:
        detail += f" (sha256 {res.new_sha256[:16]})"
    if res.reason:
        detail += f": {res.reason}"
    console.print(Text.assemble((f"{_clean(res.name):40} ", "v.module"), (_clean(detail), style)), soft_wrap=True)
    if res.status == "needs_accept" and res.diff_summary:
        for line in str(res.diff_summary).splitlines()[:40]:
            console.print(Text(f"    {_clean(line)}", style="v.text"))
        if res.new_sha256:
            console.print(Text(f"    staged copy sha256 {res.new_sha256}", style="v.dim"))


def update_datasets(app: Any, console: Any, names: list[str], *, essential: bool = False, accept_new: bool = False, sha256: str = "") -> list[Any]:
    """Run ``DataStore.update`` for the selected datasets and print one line per result (diff
    summaries of active datasets included). Returns the final UpdateResult list."""
    from v3lum.core.datasets import DATASETS

    rt = app.runtime()
    store = rt.data
    if names:
        selected = list(dict.fromkeys(names))
    elif essential:
        selected = sorted(n for n, reg in DATASETS.items() if reg.get("essential"))
    else:
        selected = sorted(DATASETS)
    if not selected:
        console.print(Text("no essential datasets registered" if essential else "no downloadable datasets registered", style="v.dim"))
        return []
    from v3lum.core.datasets import UpdateResult

    results = []
    for name in selected:
        try:
            res = store.update(name, accept_new=accept_new, expect_sha256=sha256 if accept_new else "")
        except Exception as exc:  # noqa: BLE001 - one broken dataset never stops the others
            res = UpdateResult(name, "failed", reason=f"{type(exc).__name__}: {str(exc).splitlines()[0][:200] if str(exc) else ''}")
        _result_line(console, res)
        if res.status == "needs_accept" and accept_new and not sha256:
            if _tty():
                question = f"[v.warn]install the reviewed copy of {_clean(name)} (sha256 {res.new_sha256[:16]})?[/]"
                if Confirm.ask(question, default=False, console=console):
                    res = store.update(name, accept_new=True, expect_sha256=res.new_sha256)
                    _result_line(console, res)
                else:
                    console.print(Text("    not installed: the staged copy waits for v3lum data update --accept-new", style="v.dim"))
            else:
                console.print(Text(f"    staged: review the summary, then run `v3lum data update {_clean(name)} --accept-new` to install it", style="v.dim"))
        elif res.status == "needs_accept":
            console.print(Text(f"    review the summary, then: v3lum data update {_clean(name)} --accept-new", style="v.dim"))
        results.append(res)
    return results


@command("data", "downloadable datasets (KEV, ATT&CK, blocklists...): list and update")
class Data:
    """List the registered datasets or refresh them ahead of an offline engagement."""

    @staticmethod
    def add_arguments(parser: Any) -> None:
        sub = parser.add_subparsers(dest="data_cmd", metavar="<action>")
        ls = sub.add_parser("list", help="registered datasets: licence, terms class, age, stale, size")
        ls.add_argument("--json", action="store_true")
        u = sub.add_parser("update", help="download/refresh datasets now (before going offline)")
        u.add_argument("names", nargs="*", help="datasets to refresh (default: every registered one)")
        u.add_argument("--essential", action="store_true", help="only the essential datasets")
        u.add_argument(
            "--accept-new", action="store_true",
            help="install a changed active (pinned) dataset after its diff summary (interactive confirmation, or the copy staged by an earlier run)",
        )
        u.add_argument("--sha256", default="", metavar="HEX", help="with --accept-new: the reviewed SHA-256 the new copy must have")

    @staticmethod
    def run(args: Any, app: Any, console: Any) -> int:
        action = getattr(args, "data_cmd", None) or "list"
        if action == "update":
            reviewed = str(getattr(args, "sha256", "") or "").strip().lower()
            accept_new = bool(getattr(args, "accept_new", False))
            if reviewed and not accept_new:
                raise _user_error("--sha256 names the reviewed copy to install: use it with --accept-new")
            if reviewed and not re.fullmatch(r"[0-9a-f]{64}", reviewed):
                raise _user_error("--sha256 must be the 64-hex-digit SHA-256 printed with the diff summary")
            if getattr(app, "offline", False):
                raise _user_error("data update downloads datasets: run it without --offline (before going offline)")
            results = update_datasets(
                app, console, list(getattr(args, "names", None) or []), essential=bool(getattr(args, "essential", False)),
                accept_new=accept_new, sha256=reviewed,
            )
            failed = [r for r in results if r.status == "failed"]
            if results:
                console.print(Text(
                    f"\n{sum(1 for r in results if r.status == 'updated')} updated, {sum(1 for r in results if r.status == 'unchanged')} unchanged, "
                    f"{sum(1 for r in results if r.status == 'needs_accept')} awaiting review, {len(failed)} failed",
                    style="v.dim",
                ))
            return 1 if failed else 0
        store = app.runtime().data
        if getattr(args, "json", False):
            sys.stdout.write(json.dumps(datasets_rows(store), indent=2, ensure_ascii=False) + "\n")
            return 0
        console.print(datasets_table(store))
        hint = store.first_run_hint()
        if hint:
            console.print(Text(f"[i] {_clean(hint)}", style="v.warn"))
        return 0
