"""The closing feedback loop (P325 cond 1, 2, 4, 6, 7): ``ask_feedback(console, store, case, *, analyst)``.

Called after an interactive scan and by ``v3lum cases feedback <id>`` (terminal only):

1. the overall verdict takes **one keypress**: ``[y]es / [p]artially / [n]o / [s]kip`` (Enter = skip);
2. **yes** stores only the case verdict and credits no finding; an optional *which were right?* step
   records explicit positive votes;
3. **partially / no** list at most :data:`MAX_ITEMS` items - findings and correlations (voted per
   rule) - ordered by their score contribution and ask which were **wrong**; each wrong item takes an
   optional one-key reason (``[h]omonym [o]utdated [b]enign infra [w]rong type``) kept for tuning;
   ``Np`` marks item N partly right (counts 0.5);
4. items the analyst does not list stay **unrated** (no row): 'no' + Enter marks nothing correct;
5. optional notes for the record (case data, purged with the case, A10).

Everything is written through :meth:`v3lum.core.store.Store.record_verdict` (one verdict per case and
analyst) and :meth:`v3lum.core.store.Store.vote` (idempotent per case, item and analyst), so running
the loop again replaces the earlier answers and never double-counts. Feedback never deletes or hides
a finding. Module-derived text (titles, entity values) is shown through the safe-text helpers.
"""

from __future__ import annotations

import contextlib
import getpass
import os
import re
import sqlite3
import sys
from collections.abc import Callable, Mapping
from dataclasses import dataclass, field
from typing import Any

from rich import box
from rich.table import Table
from rich.text import Text

__all__ = [
    "MAX_ITEMS",
    "REASON_KEYS",
    "SEVERITY_WEIGHTS",
    "VERDICT_KEYS",
    "FeedbackResult",
    "ask_feedback",
    "default_analyst",
    "parse_selection",
    "review_items",
]

#: At most this many items are offered for per-item votes (P325 cond 4).
MAX_ITEMS = 10
#: One keypress -> overall verdict (None = skip).
VERDICT_KEYS: dict[str, str | None] = {"y": "yes", "p": "partial", "n": "no", "s": None}
#: One keypress -> reason of a 'wrong' vote (stored for tuning, P325 cond 4).
REASON_KEYS: dict[str, str] = {"h": "homonym", "o": "outdated", "b": "benign_infra", "w": "wrong_type"}
#: Severity weights that order the items by score contribution (P302 W_SEV).
SEVERITY_WEIGHTS: dict[str, float] = {"critical": 10.0, "high": 7.0, "medium": 4.0, "low": 2.0, "info": 0.0}
_LABEL_WEIGHTS = {"confirmed": 1.0, "probable": 0.7, "possible": 0.4}
_TOKEN_RE = re.compile(r"^(\d{1,3})(?:-(\d{1,3}))?([prw]?)$")

Ask = Callable[[str], str]


@dataclass
class FeedbackResult:
    """What one feedback round stored: ``verdict`` None = skipped (nothing stored); ``right`` /
    ``wrong`` / ``partly`` are item ids; ``reasons`` maps wrong item ids to their reason."""

    case_id: str
    verdict: str | None = None
    right: list[str] = field(default_factory=list)
    wrong: list[str] = field(default_factory=list)
    partly: list[str] = field(default_factory=list)
    reasons: dict[str, str] = field(default_factory=dict)
    notes: str = ""

    @property
    def skipped(self) -> bool:
        return self.verdict is None


# --------------------------------------------------------------------------------------
# items and answers (pure)
# --------------------------------------------------------------------------------------


def _severity(item: Mapping[str, Any]) -> str:
    sev = str(item.get("severity") or "info").strip().lower()
    return sev if sev in SEVERITY_WEIGHTS else "info"


def _confidence(item: Mapping[str, Any]) -> float:
    try:
        value = float(item.get("confidence"))
    except (TypeError, ValueError):
        value = _LABEL_WEIGHTS.get(str(item.get("confidence_label") or "").lower(), 0.7)
    return max(0.0, min(1.0, value))


def review_items(case: Mapping[str, Any], limit: int = MAX_ITEMS) -> list[dict[str, Any]]:
    """The items offered for per-item votes (P325 cond 4), highest score contribution first, at most
    ``limit``: findings (severity above info, not ``context_only``) and correlations (voted per
    rule). Items listed in ``case['risk']['contributors']`` (the risk model's top contributors) come
    first in their order, then the others by severity weight x confidence. Each item:
    ``{kind ('finding'|'correlation'), id, title, severity, label, module, source, rule, entity,
    contribution}``."""
    risk = case.get("risk") if isinstance(case.get("risk"), Mapping) else {}
    ranked = [str(c.get("finding_id") or c.get("id") or "") for c in risk.get("contributors") or () if isinstance(c, Mapping)]
    rank = {fid: i for i, fid in enumerate(ranked) if fid}
    items: list[dict[str, Any]] = []
    for group, kind in (("findings", "finding"), ("correlations", "correlation")):
        for raw in case.get(group) or ():
            if not isinstance(raw, Mapping) or not raw.get("id"):
                continue
            if kind == "finding" and "context_only" in {str(t) for t in raw.get("tags") or ()}:
                continue
            sev = _severity(raw)
            contribution = SEVERITY_WEIGHTS[sev] * _confidence(raw)
            fid = str(raw["id"])
            if contribution <= 0 and fid not in rank:
                continue
            entities = raw.get("entities") if kind == "correlation" else [raw.get("entity")]
            items.append({
                "kind": kind,
                "id": fid,
                "title": str(raw.get("title") or ""),
                "severity": sev,
                "label": str(raw.get("confidence_label") or ""),
                "module": str(raw.get("module") or "") if kind == "finding" else "",
                "source": str(raw.get("source") or "") if kind == "finding" else "",
                "rule": str(raw.get("rule") or "") if kind == "correlation" else "",
                "entity": str((entities or [""])[0] or ""),
                "contribution": round(contribution, 4),
            })
    items.sort(key=lambda it: (rank.get(it["id"], len(rank)), -it["contribution"], 0 if it["kind"] == "correlation" else 1, it["title"], it["id"]))
    return items[: max(0, int(limit))]


def parse_selection(text: str, count: int, *, vote: str) -> dict[int, str]:
    """Item numbers typed by the analyst -> ``{number: vote}``.

    Numbers are separated by commas or spaces; ``a-b`` is a range; a trailing ``p`` marks the item
    partly right ('partly'), ``w`` wrong and ``r`` right; a bare number takes ``vote``. Numbers
    outside 1..``count`` and unreadable tokens are ignored; '' selects nothing (unlisted items stay
    unrated)."""
    out: dict[int, str] = {}
    suffix = {"p": "partly", "w": "wrong", "r": "right"}
    for token in re.split(r"[,\s;]+", str(text or "").strip().lower()):
        m = _TOKEN_RE.match(token)
        if not m:
            continue
        first = int(m.group(1))
        last = int(m.group(2)) if m.group(2) else first
        choice = suffix.get(m.group(3), vote)
        for number in range(min(first, last), max(first, last) + 1):
            if 1 <= number <= count:
                out[number] = choice
    return out


def default_analyst(store: Any = None) -> str:
    """Setting ``analyst`` (through the store's settings), else the OS user."""
    name = ""
    getter = getattr(store, "setting", None)
    if callable(getter):
        try:
            name = str(getter("analyst", "") or "").strip()
        except Exception:  # noqa: BLE001
            name = ""
    if name:
        return name
    try:
        return getpass.getuser()
    except Exception:  # noqa: BLE001 - no user database entry
        return os.environ.get("USER") or os.environ.get("USERNAME") or ""


# --------------------------------------------------------------------------------------
# terminal input/output
# --------------------------------------------------------------------------------------


def _safe(value: Any, style: str = "") -> Text:
    """Untrusted text as a rich Text (never parsed as markup; control characters removed)."""
    try:
        from v3lum.ui.safe import safe_rich

        return safe_rich(value, style)
    except Exception:  # noqa: BLE001 - WP14 helper unavailable: a local equivalent
        text = re.sub(r"[\x00-\x08\x0b-\x1f\x7f-\x9f‪-‮⁦-⁩]", "", str(value if value is not None else ""))
        return Text(text, style=style)


def _entity_display(key: str) -> str:
    etype, sep, value = str(key or "").partition(":")
    if not sep:
        return key
    try:
        from v3lum.core.entities import EntityType, display_value

        return display_value(EntityType.parse(etype), value)
    except Exception:  # noqa: BLE001
        return value


def _stdin_tty() -> bool:
    try:
        return bool(sys.stdin and sys.stdin.isatty())
    except (AttributeError, ValueError):
        return False


def _read_key(console: Any, prompt: str) -> str:
    """One keypress from the terminal, no Enter needed (POSIX cbreak or Windows msvcrt); a line is
    read when stdin is not a terminal."""
    console.print(Text(prompt, style="v.accent"), end="")
    try:
        import termios
        import tty

        fd = sys.stdin.fileno()
        saved = termios.tcgetattr(fd)
    except Exception:  # noqa: BLE001 - not a POSIX terminal
        try:
            import msvcrt  # type: ignore[import-not-found]

            key = msvcrt.getwch()
        except ImportError:
            key = (sys.stdin.readline() or "").strip()[:1]
        console.print(Text(key if key.isprintable() else ""))
        return key
    try:
        tty.setcbreak(fd)
        key = sys.stdin.read(1)
    finally:
        termios.tcsetattr(fd, termios.TCSADRAIN, saved)
    console.print(Text(key if key.isprintable() else ""))
    return key


def _items_table(items: list[dict[str, Any]], title: str) -> Table:
    table = Table(box=box.SIMPLE, show_header=True, header_style="v.dim", title=Text(title, style="v.accent"), title_justify="left")
    table.add_column("#", justify="right", style="v.dim")
    table.add_column("sev")
    table.add_column("conf", style="v.dim")
    table.add_column("item", overflow="fold")
    table.add_column("on", overflow="fold", style="v.entity")
    table.add_column("from", style="v.module")
    for number, item in enumerate(items, 1):
        origin = f"rule {item['rule']}" if item["kind"] == "correlation" else (item["source"] or item["module"])
        table.add_row(
            str(number),
            Text(item["severity"], style=f"sev.{item['severity']}"),
            _safe(item["label"] or "-"),
            _safe(item["title"]),
            _safe(_entity_display(item["entity"])),
            _safe(origin),
        )
    return table


# --------------------------------------------------------------------------------------
# the loop
# --------------------------------------------------------------------------------------


def ask_feedback(console: Any, store: Any, case: Mapping[str, Any], *, analyst: str = "", ask: Ask | None = None) -> FeedbackResult | None:
    """Ask the closing question and store the answers (P325; see the module docstring).

    ``store`` is a :class:`v3lum.core.store.Store` holding ``case`` (the stored case dict);
    ``analyst`` defaults to :func:`default_analyst`. ``ask(prompt) -> str`` replaces the terminal
    (tests, other front ends): one-key questions use the first character of the answer. Without
    ``ask`` and outside a terminal nothing is asked (returns None). Returns what was stored
    (``FeedbackResult.verdict`` None = skipped, nothing stored), or None when nothing was asked, the
    analyst aborted (Ctrl+C / end of input: nothing stored) or the verdict could not be stored (the
    reason is printed). A vote that cannot be stored is reported and skipped; the others are kept."""
    case_id = str(case.get("case_id") or "")
    if not case_id or (ask is None and not _stdin_tty()):
        return None
    if ask is not None:
        def key_in(prompt: str) -> str:
            return str(ask(prompt) or "").strip().lower()[:1]

        line_in: Ask = ask
    else:
        def key_in(prompt: str) -> str:
            return _read_key(console, prompt).strip().lower()[:1]

        def line_in(prompt: str) -> str:
            return str(console.input(Text(prompt, style="v.dim")) or "")

    who = str(analyst or "").strip() or default_analyst(store)
    with _themed(console):
        if not _stored(store, case_id):
            console.print(Text("feedback not asked: the case is not in the case DB (feedback is kept for stored cases only)", style="v.dim"))
            return None
        return _ask(console, store, case, case_id=case_id, who=who, key_in=key_in, line_in=line_in)


def _stored(store: Any, case_id: str) -> bool:
    """Whether the case DB holds the case (verdicts and votes are recorded for stored cases only)."""
    info = getattr(store, "case_info", None) or getattr(store, "get_case", None)
    if not callable(info):
        return True  # another store implementation: let its writes decide
    try:
        return info(case_id) is not None
    except Exception:  # noqa: BLE001 - an unreadable DB: nothing is asked
        return False


def _themed(console: Any) -> Any:
    """The V3LUM theme pushed on ``console`` for the round (a plain rich Console has no 'v.*' styles)."""
    use_theme = getattr(console, "use_theme", None)
    if callable(use_theme):
        try:
            from v3lum.ui.theme import THEME

            return use_theme(THEME)
        except Exception:  # noqa: BLE001 - an unthemed console still prints
            pass
    return contextlib.nullcontext()


def _ask(console: Any, store: Any, case: Mapping[str, Any], *, case_id: str, who: str, key_in: Ask, line_in: Ask) -> FeedbackResult | None:
    """The questions of :func:`ask_feedback` and the writes (one round)."""
    try:
        console.print()
        answer = key_in("did this make sense? [y]es / [p]artially / [n]o / [s]kip: ")
        verdict = VERDICT_KEYS.get(answer)
        if verdict is None:
            console.print(Text("feedback skipped (nothing stored)", style="v.dim"))
            return FeedbackResult(case_id=case_id)
        items = review_items(case)
        picks: dict[int, str] = {}
        reasons: dict[int, str] = {}
        if items and verdict == "yes":
            console.print(_items_table(items, "which were right? (optional: only the items you list are credited)"))
            picks = parse_selection(line_in("numbers of RIGHT items (e.g. 1,3; 2p = partly), Enter = skip: "), len(items), vote="right")
        elif items:
            console.print(_items_table(items, "which were wrong? (unlisted items stay unrated)"))
            picks = parse_selection(line_in("numbers of WRONG items (e.g. 1,4; 2p = partly), Enter = none: "), len(items), vote="wrong")
            for number in sorted(n for n, v in picks.items() if v == "wrong"):
                key = key_in(f"reason for #{number}: [h]omonym [o]utdated [b]enign infra [w]rong type, Enter = none: ")
                if key in REASON_KEYS:
                    reasons[number] = REASON_KEYS[key]
        notes = str(line_in("notes for the record (optional): ") or "").strip()
    except (KeyboardInterrupt, EOFError):
        console.print(Text("\nfeedback not stored", style="v.dim"))
        return None

    result = FeedbackResult(case_id=case_id, verdict=verdict, notes=notes)
    try:
        store.record_verdict(case_id, verdict, notes, analyst=who)
    except (ValueError, sqlite3.Error) as exc:  # e.g. the case was purged meanwhile, a locked DB
        console.print(_safe(f"feedback not stored: {exc}", "v.warn"))
        return None
    for number in sorted(picks):
        item, choice = items[number - 1], picks[number]
        try:
            store.vote(
                case_id,
                item["id"],
                analyst=who,
                vote=choice,
                reason=reasons.get(number),
                source_id=item["source"],
                rule_id=item["rule"],
                module=item["module"],
            )
        except (ValueError, sqlite3.Error) as exc:  # one bad item never loses the others
            console.print(_safe(f"vote on #{number} not stored: {exc}", "v.warn"))
            continue
        getattr(result, choice).append(item["id"])
        if number in reasons:
            result.reasons[item["id"]] = reasons[number]
    parts = [f"verdict {verdict}"]
    for name in ("right", "wrong", "partly"):
        if getattr(result, name):
            parts.append(f"{len(getattr(result, name))} {name}")
    console.print(Text(f"[✓] feedback stored: {', '.join(parts)} (answers replace earlier ones; unlisted items stay unrated)", style="v.ok"))
    return result
