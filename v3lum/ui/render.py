"""Render a case (report model dict) in the terminal: safe text and an honest first screen.

Safety (AR13): every module-derived value - titles, descriptions, criteria, attribute values, entity
displays, reasons, link labels, notes - reaches rich only as a :class:`rich.text.Text` built by
``ui.safe.safe_rich`` / ``ui.safe.display_text`` (control characters removed, never parsed as
markup; valid CPFs quoted in module text masked unless ``show_personal``, AR24) or through
``ui.safe.safe_text`` in a markup string, so ``[/bold]`` in a page title cannot abort the report and
ESC/OSC sequences never reach the terminal. Entity displays go through ``entities.display_value``
(CPF ``***.456.789-**`` unless ``show_personal``) and are defanged when the entity is hostile
(tagged malicious/phishing/c2/suspicious...) and for URLs (the investigated URL is never a clickable
link), unless ``no_defang``. Severity/status/confidence values coming from the case pick a style
only from a fixed table.

Order of :func:`render_case` (AR14, P322 cond 7, P311, A2):

1. header panel - TLP label in its TLP 2.0 colour, case id, inputs, mode and egress, the engagement
   banner, partial-result notes, per seed 'N of M applicable sources answered; K could not verify'
   with its reading ('inconclusive' / 'no findings' / level - never 'clean'), 'value disclosed to N
   third-party providers', the licence banner, purpose/ticket/legal basis, header notes, statistics
   and the score bar ('triage aid, not a conclusion');
2. bottom line - what it is, why, next step (``report.summary.bottom_line``);
3. attention points and limitations (``core.attention``, WP16; suggestions - the analyst's verdict
   prevails);
4. correlations;
5. findings - a confidence label on every finding, the criterion for HIGH/CRITICAL (always with
   ``full``); POSSIBLE identity links are never listed here (entity map and HTML only);
6. details - entity map, facts about the seeds, timeline;
7. grouped skip lines (one per reason code, quota lines, follow-ups; with ``full`` the coverage lost
   under the licence profile per entity type);
8. coverage per status with reason codes (feeds of aggregators that could not verify included);
9. manual pivots - at most 8 per seed, grouped by analyst question, manual fallbacks and verified
   links first, badges; clickable only at TLP:CLEAR/GREEN; at AMBER and above plain defanged text with
   'opening sends <value> to <host>'; touches_target links - declared, or pointing at the
   investigated host or a hostile entity's host - defanged/non-clickable with a warning and hidden
   for hostile entities (unless ``full``); at RED third-party links are hidden (only
   ``v3lum links`` shows them);
10. notes, then the TLP marking again as a footer.

:func:`render_single` renders the output of ``App.run_single`` (``v3lum run``) with the same rules;
:func:`render_detections` the detection table of ``v3lum detect``.
"""

from __future__ import annotations

import json
from collections import defaultdict
from collections.abc import Iterable
from typing import Any
from urllib.parse import urlsplit

from rich import box
from rich.console import Console, Group, RenderableType
from rich.panel import Panel
from rich.style import Style
from rich.table import Table
from rich.text import Text
from rich.tree import Tree

from v3lum.core import redact as _redact
from v3lum.core import tlp as _tlp
from v3lum.core.entities import PERSONAL_TYPES, EntityType
from v3lum.core.entities import defang as _defang
from v3lum.report import summary as S
from v3lum.ui.safe import clean_text, display_text, entity_display, is_hostile, mask_cpf_in_text, safe_href, safe_rich
from v3lum.ui.theme import CONFIDENCE_ICON, SEVERITY_ICON, STATUS_ICON, risk_style, tlp_style

__all__ = [
    "LINK_CATEGORY_ORDER",
    "MAX_HEADER_SEEDS",
    "MAX_LINKS_PER_SEED",
    "SEV_ORDER",
    "render_case",
    "render_detections",
    "render_single",
    "risk_bar",
]

SEV_ORDER = ["critical", "high", "medium", "low", "info"]
#: Manual pivots are grouped by analyst question in this order (P311 cond 10).
LINK_CATEGORY_ORDER: tuple[str, ...] = ("reputation", "history", "passive_dns", "code_paste", "social", "company", "crypto", "geo", "search", "other")
#: The terminal shows at most this many manual pivots per seed (the rest: HTML report, `v3lum links`).
MAX_LINKS_PER_SEED = 8
#: The header lists at most this many inputs (and answered lines) unless ``full``; the rest are summed.
MAX_HEADER_SEEDS = 10
#: Statuses that mean 'could not verify' (rule 5).
_CNV = ("quota", "rate_limited", "blocked", "error", "needs_key", "unavailable")
_COVERAGE_ORDER = ["ok", "empty", "rate_limited", "quota", "blocked", "error", "needs_key", "unavailable", "skipped", "not_run"]
_CATEGORY_TITLES = {
    "reputation": "reputation", "history": "history", "passive_dns": "passive DNS", "code_paste": "code / paste", "social": "social",
    "company": "company", "crypto": "crypto", "geo": "geo", "search": "search", "other": "other",
}


# ======================================================================================
# small helpers
# ======================================================================================


def _d(value: Any) -> dict[str, Any]:
    return value if isinstance(value, dict) else {}


def _l(value: Any) -> list[Any]:
    return list(value) if isinstance(value, (list, tuple)) else []


def _sev(value: Any) -> str:
    text = str(value or "info").strip().lower()
    return text if text in SEV_ORDER else "info"


def _status(value: Any) -> str:
    text = str(value or "not_run").strip().lower()
    return text if text in STATUS_ICON else "not_run"


def _clip(text: str, limit: int) -> str:
    return text if len(text) <= limit else text[: max(0, limit - 3)].rstrip() + "..."


def _conf_text(item: dict[str, Any]) -> Text:
    label = S.confidence_label(item)
    return Text(f"{CONFIDENCE_ICON.get(label, '')} {label.upper()}", style=f"conf.{label}")


def _sev_text(sev: str, *, upper: bool = False) -> Text:
    return Text(f"{SEVERITY_ICON.get(sev, '')} {sev.upper() if upper else sev}", style=f"sev.{sev}")


def _tlp_of(value: Any) -> _tlp.TLP:
    try:
        return _tlp.parse(value) if value else _tlp.TLP.AMBER
    except ValueError:
        return _tlp.TLP.RED  # unreadable: most restrictive


def _is_personal_type(etype: str) -> bool:
    try:
        return EntityType(etype) in PERSONAL_TYPES
    except ValueError:
        return False


def _internal_host(host: str) -> bool:
    """Is ``host`` owned by an internal (company-operated) provider? Unknown hosts are not."""
    try:
        from v3lum.core import providers

        prov = providers.registry().provider_for_host(host)
    except Exception:  # noqa: BLE001 - a broken registry means 'not internal' (fail closed)
        return False
    return bool(getattr(prov, "internal", False)) if prov is not None else False


def risk_bar(score: float, level: str, width: int = 30) -> Text:
    """The score bar: ' RISK ████░░ 42.0/100 MEDIUM ' plus the P302 label. The reading never says
    'clean' (v1 levels are mapped: 'clean' -> 'no findings'); 'inconclusive' is shown as given."""
    try:
        value = max(0.0, min(100.0, float(score or 0.0)))
    except (TypeError, ValueError):
        value = 0.0
    reading = S.INCONCLUSIVE if str(level or "").strip().lower() == S.INCONCLUSIVE else S.level_label(level)
    style = risk_style(reading)
    filled = int(round(value / 100 * width))
    t = Text()
    t.append(" RISK ", style="v.accent")
    t.append("█" * filled, style=style)
    t.append("░" * (width - filled), style="v.ghost")
    t.append(f" {value:5.1f}/100 ", style="v.text")
    t.append(f" {reading.upper()} ", style=style)
    t.append(f"  {S.SCORE_LABEL}", style="v.ghost")
    return t


class _View:
    """One rendering of a case: the flags of this view and the case index."""

    def __init__(self, case: dict[str, Any], *, full: bool, show_personal: bool, no_defang: bool) -> None:
        self.case = case if isinstance(case, dict) else {}
        self.full = full
        self.show_personal = show_personal
        self.no_defang = no_defang
        self.idx = S.CaseIndex(self.case, show_personal=show_personal, no_defang=no_defang)
        self.tlp = S.tlp_value(self.case)
        self.seeds = [str(s) for s in _l(self.case.get("seeds")) if s]

    def plain(self, value: Any) -> str:
        """Module-derived free text of this view: controls removed, valid CPFs masked unless
        ``show_personal`` (``ui.safe.display_text``)."""
        return display_text(value, show_personal=self.show_personal)

    def txt(self, value: Any, style: str = "") -> Text:
        """:meth:`plain` as a :class:`rich.text.Text` (never parsed as markup)."""
        return Text(self.plain(value), style=style)

    def ent(self, key: str) -> Text:
        """'type:display' of an entity key (masked, defanged when hostile and for URLs)."""
        etype, _ = self.idx.type_value(key)
        t = Text()
        t.append(f"{clean_text(etype)}:", style="v.type")
        t.append(self.idx.display(key), style="v.defanged" if self.idx.hostile(key) else "v.entity")
        return t


# ======================================================================================
# render_case
# ======================================================================================


def _view_flag(value: bool | None, case: Any, name: str) -> bool:
    """An explicit view flag wins; None means the flag recorded in the case options (the analyst
    asked for it on the run that produced the case, and the audit recorded it)."""
    if value is not None:
        return bool(value)
    return bool(_d(_d(case).get("options")).get(name, False)) if isinstance(case, dict) else False


def render_case(
    console: Console,
    case: dict[str, Any],
    *,
    full: bool = False,
    max_findings: int = 25,
    show_personal: bool | None = None,
    no_defang: bool | None = None,
) -> None:
    """Print a case (``CaseResult.to_dict()`` or a stored v1/v2 case) in the order of the module
    docstring. ``show_personal`` unmasks CPF/VIN/personal-form VAT numbers in this view (the caller
    records it in the case audit); ``no_defang`` shows hostile entities and URLs as they are
    (``--no-defang``). Both default to the flags recorded in ``case['options']`` (False when absent);
    pass ``show_personal=False`` to re-mask a stored case."""
    show_personal = _view_flag(show_personal, case, "show_personal")
    no_defang = _view_flag(no_defang, case, "no_defang")
    v = _View(case, full=full, show_personal=show_personal, no_defang=no_defang)
    blocks: list[RenderableType | None] = [_header(v), _bottom(v)]
    blocks += _attention(v)
    blocks += _correlations(v)
    blocks += _findings(v, max_findings)
    blocks += _details(v)
    blocks += _skips(v)
    blocks.append(_coverage(v.case, full=full, show_personal=show_personal))
    blocks += _pivots(v)
    blocks += [Text(f"[!] {note}", style="v.warn") for note in S.note_lines(v.case, show_personal=show_personal)]
    blocks.append(_footer(v))
    for block in blocks:
        if block is not None:
            console.print(block)


def _header(v: _View) -> Panel:
    case = v.case
    s = _d(case.get("summary"))
    cap = None if v.full else MAX_HEADER_SEEDS
    items = S.header_items(case, show_personal=v.show_personal, no_defang=v.no_defang, max_seeds=cap)
    tlp_text = items[0][1] if items and items[0][0] == "tlp" else S.tlp_label(case)
    grid = Table.grid(padding=(0, 2))
    grid.add_column(style="v.dim", justify="right", no_wrap=True)
    grid.add_column(style="v.text", overflow="fold")
    grid.add_row("TLP", Text(f" {tlp_text} ", style=tlp_style(v.tlp)))
    grid.add_row("case", safe_rich(case.get("case_id") or "?", "v.title"))
    inputs = _inputs(case)
    for key, reason in inputs if cap is None else inputs[:cap]:
        row = v.ent(key)
        if reason:
            row.append(f"  ({v.plain(reason)})", style="v.ghost")
        grid.add_row("input", row)
    if cap is not None and len(inputs) > cap:
        grid.add_row("input", Text(f"+{len(inputs) - cap} more inputs (--full or the HTML report)", style="v.ghost"))
    labels = {
        "mode": ("run", "v.text"), "engagement": ("engagement", "v.warn"), "partial": ("warning", "v.warn"),
        "answered": ("answered", "v.text"), "disclosure": ("disclosure", "v.text"), "licence": ("banner", "v.warn"),
        "purpose": ("recorded", "v.text"), "note": ("note", "v.dim"),
    }
    for kind, text in items:
        if kind == "tlp":
            continue
        label, style = labels.get(kind, ("note", "v.dim"))
        if kind == "answered":
            style = "v.warn" if f"reading: {S.INCONCLUSIVE}" in text else "v.text"
        grid.add_row(label, safe_rich(text, style))
    grid.add_row(
        "stats",
        safe_rich(
            f"{s.get('entities', 0)} entities · {s.get('relations', 0)} relations · {s.get('findings', 0)} findings · "
            f"{s.get('module_runs', 0)} module runs · {s.get('requests', 0)} requests ({s.get('cache_hits', 0)} cached) · {s.get('duration', 0)}s"
        ),
    )
    score = _d(case.get("risk")).get("score", s.get("risk_score", 0))
    title = Text.assemble(("▌V3LUM REPORT▐ ", "v.title"), (f" {tlp_text} ", tlp_style(v.tlp)))
    return Panel(Group(grid, Text(), risk_bar(score, S.case_level(case))), title=title, border_style="v.accent", box=box.HEAVY, padding=(1, 2))


def _inputs(case: dict[str, Any]) -> list[tuple[str, str]]:
    out: list[tuple[str, str]] = []
    for inp in _l(case.get("inputs")):
        if isinstance(inp, dict) and inp.get("type") and inp.get("value") is not None:
            out.append((f"{inp['type']}:{inp['value']}", str(inp.get("reason") or "")))
    if out:
        return out
    return [(str(k), "") for k in _l(case.get("seeds")) if k]


def _bottom(v: _View) -> Panel:
    body = Text()
    for i, line in enumerate(S.bottom_line(v.case, show_personal=v.show_personal, no_defang=v.no_defang)):
        label, sep, rest = line.partition(": ")
        if i:
            body.append("\n")
        if sep:
            body.append(label + ": ", style="v.accent")
            body.append(rest, style="v.text")
        else:
            body.append(line, style="v.text")
    return Panel(body, title=Text("bottom line", style="v.accent"), title_align="left", border_style="v.accent", box=box.ROUNDED, padding=(0, 1))


def _attention_lines(case: dict[str, Any]) -> tuple[list[str], list[str]]:
    """``core.attention.attention_points`` / ``limitations`` (WP16); until that module exists (or if
    it fails) the limitations fall back to the could-not-verify coverage groups."""
    try:
        from v3lum.core import attention as att  # WP16 (same wave)
    except Exception:  # noqa: BLE001 - not there yet, or broken: the fallback below keeps rule 5 visible
        att = None
    points: list[str] | None = None
    limits: list[str] | None = None
    if att is not None:
        try:
            points = [str(p) for p in att.attention_points(case) or ()]
        except Exception:  # noqa: BLE001
            points = None
        try:
            limits = [str(x) for x in att.limitations(case) or ()]
        except Exception:  # noqa: BLE001
            limits = None
    return points or [], limits if limits is not None else _fallback_limitations(case)


def _fallback_limitations(case: dict[str, Any]) -> list[str]:
    groups: dict[str, list[str]] = defaultdict(list)
    for name, info in sorted(_d(case.get("coverage")).items()):
        info = _d(info)
        st = str(info.get("status") or "")
        if st in _CNV:
            groups[str(info.get("reason_code") or st)].append(clean_text(name))
    out = []
    for code, names in sorted(groups.items()):
        shown = ", ".join(names[:8]) + (f", +{len(names) - 8} more" if len(names) > 8 else "")
        out.append(f"could not verify: {shown} ({clean_text(code)}) - not a finding of absence")
    return out


def _attention(v: _View) -> list[RenderableType]:
    points, limits = _attention_lines(v.case)
    if not points and not limits:
        return []
    t = Table(
        box=box.SIMPLE, show_header=False, expand=True, title_justify="left",
        title=Text("⚠ attention points and limitations (suggestions: the analyst's verdict prevails)", style="v.accent"),
    )
    t.add_column(no_wrap=True, width=12)
    t.add_column(overflow="fold")
    for p in points:
        t.add_row(Text("attention", style="v.warn"), v.txt(p, "v.text"))
    for lim in limits:
        t.add_row(Text("limitation", style="v.dim"), v.txt(lim, "v.dim"))
    return [t]


def _correlations(v: _View) -> list[RenderableType]:
    all_corrs = [c for c in _l(v.case.get("correlations")) if isinstance(c, dict)]
    corrs = [c for c in all_corrs if not S.is_identity_link(c)]
    if not corrs:
        return []
    limit = None if v.full else 15
    t = Table(
        box=box.SIMPLE_HEAVY, show_header=True, header_style="v.dim", expand=True, title_justify="left",
        title=Text("⟁ cross-referenced intelligence", style="v.accent"),
    )
    t.add_column("sev", width=11, no_wrap=True)
    t.add_column("confidence", width=12, no_wrap=True)
    t.add_column("conclusion", ratio=3)
    t.add_column("what to do", ratio=2, style="v.dim")
    for c in corrs[:limit]:
        sev = _sev(c.get("severity"))
        body = v.txt(c.get("title") or c.get("rule") or "?", "v.text")
        ents = [str(k) for k in _l(c.get("entities"))][:3]
        if ents:
            body.append("\non: ", style="v.ghost")
            for i, key in enumerate(ents):
                if i:
                    body.append(", ", style="v.ghost")
                body.append_text(v.ent(key))
        if c.get("description"):
            body.append("\n" + _clip(v.plain(c["description"]), 300), style="v.dim")
        if c.get("criterion") and (v.full or sev in ("critical", "high")):
            body.append("\ncriterion: " + _clip(v.plain(c["criterion"]), 300), style="v.dim")
        t.add_row(_sev_text(sev, upper=True), _conf_text(c), body, v.txt(c.get("recommendation") or "", "v.dim"))
    out: list[RenderableType] = [t]
    if limit is not None and len(corrs) > limit:
        out.append(Text(f"  … {len(corrs) - limit} more correlations (use --full or the HTML report)", style="v.ghost"))
    return out


def _override_text(f: dict[str, Any], v: _View) -> str:
    ov = _d(f.get("override"))
    if not ov:
        return ""
    parts = [str(ov.get(k)) for k in ("label", "severity", "verdict") if ov.get(k)]
    note = f" ({v.plain(ov.get('note'))})" if ov.get("note") else ""
    return f"analyst: {' / '.join(clean_text(p) for p in parts) or 'reviewed'}{note}"


def _findings(v: _View, max_findings: int) -> list[RenderableType]:
    every = list(v.idx.findings)
    findings = [f for f in every if v.full or _sev(f.get("severity")) != "info"]
    identity = [f for f in findings if S.is_identity_link(f)]
    findings = [f for f in findings if not S.is_identity_link(f)]
    infos = [f for f in every if _sev(f.get("severity")) == "info"]
    out: list[RenderableType] = []
    if findings:
        t = Table(
            box=box.SIMPLE, show_header=True, header_style="v.dim", expand=True, title_justify="left",
            title=Text("⚑ findings", style="v.accent"),
        )
        t.add_column("sev", width=10, no_wrap=True)
        t.add_column("confidence", width=12, no_wrap=True)
        t.add_column("entity", ratio=2, overflow="fold")
        t.add_column("finding", ratio=4, overflow="fold")
        t.add_column("source", ratio=1, style="v.module", overflow="fold")
        shown = findings if v.full else findings[: max(0, int(max_findings))]
        for f in shown:
            sev = _sev(f.get("severity"))
            body = v.txt(f.get("title") or "?", "v.text")
            if f.get("criterion") and (v.full or sev in ("critical", "high")):
                body.append("\ncriterion: " + _clip(v.plain(f["criterion"]), 300), style="v.dim")
            override = _override_text(f, v)
            if override:
                body.append("\n" + override, style="v.warn")
            if f.get("description") and (v.full or sev in ("critical", "high")):
                body.append("\n" + _clip(v.plain(f["description"]), 300), style="v.dim")
            entity = v.ent(str(f["entity"])) if f.get("entity") else Text("-")
            t.add_row(_sev_text(sev), _conf_text(f), entity, body, safe_rich(f.get("module") or "", "v.module"))
        out.append(t)
        hidden = len(findings) - len(shown)
        if hidden > 0:
            out.append(Text(f"  … {hidden} more findings (use --full or open the HTML report)", style="v.ghost"))
    if infos and not v.full:
        out.append(Text(f"  ({len(infos)} informational findings hidden: see the HTML/Markdown report)", style="v.ghost"))
    if identity:
        out.append(Text(
            f"  ({len(identity)} possible identity link(s) not listed here - the same handle does not prove identity: "
            "see the entity map and the HTML report)", style="v.ghost",
        ))
    return out


# ---------------------------------------------------------------------------------------- details


def _details(v: _View) -> list[RenderableType]:
    out: list[RenderableType] = [_entity_tree(v)]
    for key in v.seeds:
        node = v.idx.nodes.get(key)
        attrs = _d(node.get("attributes")) if node else {}
        if not attrs:
            continue
        t = Table(box=box.MINIMAL, show_header=False, expand=False, title=Text.assemble(("▸ facts: ", "v.accent"), v.ent(key)), title_justify="left")
        t.add_column(style="v.dim", no_wrap=True)
        t.add_column(style="v.text", overflow="fold", max_width=90)
        t.add_column(style="v.ghost", overflow="fold")
        for attr, vals in list(attrs.items())[: (None if v.full else 30)]:
            vals = [x for x in _l(vals) if isinstance(x, dict)]
            if not vals:
                continue
            srcs = sorted({clean_text(x.get("source") or "") for x in vals} - {""})
            t.add_row(safe_rich(attr), v.txt(_fmt_value(vals[0].get("value"))), safe_rich(", ".join(srcs)[:40]))
        out.append(t)
    timeline = [ev for ev in _l(v.case.get("timeline")) if isinstance(ev, dict)]
    if timeline:
        t = Table(box=box.SIMPLE, show_header=False, title=Text("⧗ timeline", style="v.accent"), title_justify="left")
        t.add_column(style="v.info", no_wrap=True)
        t.add_column(overflow="fold")
        t.add_column(style="v.text", overflow="fold")
        for ev in timeline[-(len(timeline) if v.full else 15):]:
            t.add_row(safe_rich(ev.get("date") or ""), v.ent(str(ev.get("entity") or "")), v.txt(ev.get("event") or ""))
        out.append(t)
    return out


def _fmt_value(value: Any) -> str:
    if isinstance(value, list):
        items = [str(v.get("platform") or v.get("url") or v) if isinstance(v, dict) else str(v) for v in value]
        return ", ".join(items[:12]) + (f" … (+{len(items) - 12})" if len(items) > 12 else "")
    if isinstance(value, dict):
        return ", ".join(f"{k}={v}" for k, v in list(value.items())[:8])
    return str(value)


def _entity_tree(v: _View) -> Tree:
    children: dict[str, list[tuple[str, str, str]]] = defaultdict(list)
    placed = set(v.seeds)
    for e in _l(v.case.get("edges")):
        if not isinstance(e, dict) or not e.get("dst"):
            continue
        dst = str(e["dst"])  # a stored case is untrusted: never hash what it holds
        if dst in placed:
            continue
        placed.add(dst)
        children[str(e.get("src"))].append((dst, str(e.get("relation") or ""), S.confidence_label(e)))
    risk = _d(_d(v.case.get("risk")).get("entities"))
    root = Tree(Text("⌬ entity map", style="v.accent"), guide_style="v.ghost")
    limit = None if v.full else 12

    def label(key: str, relation: str = "", conf: str = "") -> Text:
        t = Text()
        if relation:
            t.append(f"{clean_text(relation)} → ", style="v.ghost")
        t.append_text(v.ent(key))
        level = S.level_label(_d(risk.get(key)).get("level"))
        if level != S.NO_FINDINGS:
            etype, _ = v.idx.type_value(key)
            if _is_personal_type(etype):
                # P302 cond 10: a score about a person is shown only with its top contributor
                top = sorted(
                    (f for f in v.idx.by_entity.get(key, ()) if _sev(f.get("severity")) != "info" and not S.is_identity_link(f)),
                    key=lambda f: SEV_ORDER.index(_sev(f.get("severity"))),
                )
                why = _clip(v.plain(top[0].get("title") or ""), 50) if top else "see the findings"
                t.append(f"  [{level}: {why}]", style=risk_style(level))
            else:
                score = _d(risk.get(key)).get("score") or 0
                try:
                    t.append(f"  [{level} {float(score):.0f}]", style=risk_style(level))
                except (TypeError, ValueError):
                    t.append(f"  [{level}]", style=risk_style(level))
        if relation and conf == "possible":
            t.append("  (possible link)", style="v.ghost")
        node = v.idx.nodes.get(key) or {}
        if node.get("noise"):
            t.append("  (common infra)", style="v.ghost")
        return t

    def add(branch: Tree, key: str, depth: int) -> None:
        kids = children.get(key, [])
        for child, rel, conf in kids[:limit]:
            sub = branch.add(label(child, rel, conf))
            if depth < 3:
                add(sub, child, depth + 1)
        if limit and len(kids) > limit:
            branch.add(Text(f"… +{len(kids) - limit} more", style="v.ghost"))

    for seed in v.seeds:
        add(root.add(label(seed)), seed, 1)
    return root


# ---------------------------------------------------------------------------------------- skips / coverage


def _skips(v: _View) -> list[RenderableType]:
    lines = S.skip_lines(v.case) + S.followup_lines(v.case)
    licence = S.licence_lines(v.case) if v.full else []
    if not lines and not licence:
        return []
    t = Table(box=box.SIMPLE, show_header=False, expand=True, title=Text("⊘ not run or could not verify", style="v.accent"), title_justify="left")
    t.add_column(overflow="fold")
    for line in lines:
        t.add_row(v.txt(line, "v.dim"))
    if licence:
        t.add_row(safe_rich(f"coverage lost under licence profile {clean_text(v.case.get('licence_profile') or 'corporate')}:", "v.dim"))
        for line in licence:
            t.add_row(safe_rich("  " + line, "v.dim"))
    return [t]


def _counts_text(info: dict[str, Any]) -> str:
    """' (blocked 1 · empty 2)' when a module's per-entity outcomes differ (coverage v2 counts, P328
    cond 3: a source blocked on the seed and empty on a pivot is not summarised as empty); '' else."""
    counts = {str(k): v for k, v in _d(info.get("counts")).items() if isinstance(v, int) and v > 0}
    if len(counts) < 2:
        return ""
    order = {st: i for i, st in enumerate(_COVERAGE_ORDER)}
    ranked = sorted(counts.items(), key=lambda kv: (_CNV.index(kv[0]) if kv[0] in _CNV else len(_CNV), order.get(kv[0], len(order))))
    return " (" + " · ".join(f"{clean_text(st).replace('_', ' ')} {n}" for st, n in ranked) + ")"


def _coverage(case: dict[str, Any], *, full: bool, show_personal: bool = False) -> Table | Text:
    """Coverage per status with reason codes ('quota (1)', 'blocked (2): dnsbl [challenge] ...');
    could-not-verify statuses always list their modules and the could-not-verify feeds of aggregators.
    Reasons are module/provider text: valid CPFs in them are masked unless ``show_personal``."""
    cov = _d(_d(case).get("coverage"))
    if not cov:
        return Text()
    groups: dict[str, list[tuple[str, dict[str, Any]]]] = defaultdict(list)
    feeds: list[tuple[str, str, str]] = []
    for name, info in sorted(cov.items()):
        info = _d(info)
        groups[_status(info.get("status"))].append((clean_text(name), info))
        for sid, row in sorted(_d(info.get("sources")).items()):
            st = str(_d(row).get("status") or "")
            if st in _CNV:
                feeds.append((f"{clean_text(name)}/{clean_text(sid)}", st, clean_text(_d(row).get("reason_code") or st)))
    t = Table(box=box.SIMPLE, show_header=False, title=Text("◎ source coverage", style="v.accent"), title_justify="left", expand=True)
    t.add_column(no_wrap=True, width=18)
    t.add_column(overflow="fold", style="v.dim")
    for st in _COVERAGE_ORDER:
        rows = groups.get(st)
        if not rows:
            continue
        label = Text(f"{STATUS_ICON.get(st, '')} {st.replace('_', ' ')} ({len(rows)})", style=f"status.{st}")
        if st in _CNV:
            parts = []
            for name, info in rows:
                code = clean_text(info.get("reason_code") or st)
                reason = display_text(_redact.redact_text(clean_text(info.get("reason") or "")), show_personal=show_personal)  # AR01, defensively
                parts.append(f"{name} [{code}" + (f": {_clip(reason, 60)}" if reason and (full or st in ("error", "needs_key", "blocked", "quota")) else "") + "]" + _counts_text(info))
            detail = ", ".join(parts)
        elif st == "skipped":
            by_code: dict[str, list[str]] = defaultdict(list)
            for name, info in rows:
                by_code[clean_text(info.get("reason_code") or "skipped")].append(name)
            chunks = []
            for code, names in sorted(by_code.items()):
                shown = names if full else names[:25]
                chunks.append(f"{code}: {', '.join(shown)}" + (f" … +{len(names) - len(shown)}" if len(names) > len(shown) else ""))
            detail = "; ".join(chunks)
        else:
            names = []
            for name, info in rows:
                partial = info.get("partial")
                names.append(name + (f" (partial: {clean_text(info.get('stop_reason') or 'stopped early')})" if partial else ""))
            shown = names if full else names[:25]
            detail = ", ".join(shown) + (f" … +{len(names) - len(shown)}" if len(names) > len(shown) else "")
        t.add_row(label, safe_rich(detail, "v.dim"))
    if feeds:
        detail = ", ".join(f"{name} [{code}]" for name, _st, code in feeds)
        t.add_row(Text(f"{STATUS_ICON['blocked']} feeds ({len(feeds)})", style="status.blocked"), safe_rich(f"could not verify: {detail}", "v.dim"))
    return t


# ---------------------------------------------------------------------------------------- manual pivots


def _link_host(item: dict[str, Any]) -> str:
    """The host a link sends the value to: the declared ``host`` (pivot packs), else the URL's host
    (module ``res.link`` items carry no host); lower case, no trailing dot."""
    host = str(item.get("host") or "").strip().lower()
    if not host:
        try:
            host = (urlsplit(str(item.get("url") or "").strip()).hostname or "").lower()
        except ValueError:
            host = ""
    return host.rstrip(".")


def _host_in(host: str, targets: Iterable[str]) -> bool:
    return bool(host) and any(t and (host == t or host.endswith("." + t)) for t in targets)


def _target_hosts(v: _View, key: str) -> set[str]:
    """Hosts whose links contact the target rather than a third party: the host of the entity the
    links belong to and of every hostile entity of the case (P311 cond 8: the investigated URL, or
    a hostile host, is never a clickable link)."""
    hosts = {S.entity_host(key)}
    hosts.update(S.entity_host(k) for k in v.idx.nodes if v.idx.hostile(k))
    return {h for h in hosts if h}


def _touches(item: dict[str, Any], targets: Iterable[str]) -> bool:
    """Does opening this link contact the target (declared touches_target, or its host is the
    investigated host or a hostile entity's host)?"""
    return bool(item.get("touches_target")) or _host_in(_link_host(item), targets)


def _link_rows(item: dict[str, Any], *, tlp: _tlp.TLP, value: str, touches: bool | None = None) -> tuple[Text, Text]:
    """(label, link text) of one manual pivot under the TLP and touches_target rules (``touches``:
    the caller's verdict, default the item's own ``touches_target``)."""
    url = clean_text(item.get("url") or "")
    host = clean_text(_link_host(item))
    label = safe_rich(item.get("label") or host or "link", "v.text")
    badge = clean_text(item.get("badge") or "")
    if badge:
        label.append(f" [{badge}]", style="v.warn" if "unknown" in badge else "v.ghost")
    if item.get("manual"):
        label.append(f" ({clean_text(item.get('note') or 'manual lookup')})", style="v.ghost")
    if touches if touches is not None else item.get("touches_target"):
        text = Text(_defang(url), style="v.defanged")
        text.append("  ⚠ opens the target (or makes a third party fetch it live): not clickable", style="v.warn")
        return label, text
    href = safe_href(url)
    if tlp <= _tlp.TLP.GREEN and href:
        text = Text(url, style="v.url")
        text.stylize(Style(link=href))
        return label, text
    text = Text(_defang(url), style="v.defanged")
    text.append(f"  opening sends {value} to {host or 'its host'}", style="v.warn")
    return label, text


def _pivots(v: _View) -> list[RenderableType]:
    links = _d(v.case.get("links"))
    tlp = _tlp_of(v.tlp)
    clickable = tlp <= _tlp.TLP.GREEN
    title = "↗ manual pivots (open in your browser)" if clickable else f"↗ manual pivots (not clickable at {S.tlp_label(v.case)}: opening a link sends the value to its host)"
    t = Table(box=box.SIMPLE, show_header=False, title=Text(title, style="v.accent"), title_justify="left", expand=True)
    t.add_column(overflow="fold", ratio=2)
    t.add_column(overflow="fold", ratio=5)
    rows = 0
    hidden_red = hidden_hostile = hidden_privacy = more = dropped = 0
    for key in v.seeds:
        candidates = [i for i in _l(links.get(key)) if isinstance(i, dict) and i.get("url")]
        items = [i for i in candidates if safe_href(str(i.get("url"))) is not None]
        dropped += len(candidates) - len(items)  # javascript:, data:, file:... never rendered (AR13)
        if not items:
            continue
        hostile = v.idx.hostile(key)
        targets = _target_hosts(v, key)
        visible = []
        for item in items:
            host = _link_host(item)
            touches = _touches(item, targets)
            if tlp >= _tlp.TLP.RED and not _internal_host(host):
                hidden_red += 1
                continue
            if item.get("privacy") and not v.show_personal:
                hidden_privacy += 1
                continue
            if touches and (hostile or _host_in(host, targets - {S.entity_host(key)})) and not v.full:
                hidden_hostile += 1
                continue
            visible.append(item)
        order = {c: i for i, c in enumerate(LINK_CATEGORY_ORDER)}
        ranked = sorted(visible, key=lambda i: (not i.get("manual"), not i.get("verified"), order.get(str(i.get("category") or "other"), len(order))))
        shown = ranked if v.full else ranked[:MAX_LINKS_PER_SEED]
        more += len(ranked) - len(shown)
        if not shown:
            continue
        value = v.idx.display(key)
        t.add_row(v.ent(key), Text(""))
        by_cat: dict[str, list[dict[str, Any]]] = defaultdict(list)
        for item in shown:
            cat = str(item.get("category") or "other")
            by_cat[cat if cat in order else "other"].append(item)
        for cat in sorted(by_cat, key=lambda c: order.get(c, len(order))):
            t.add_row(Text(f"  {_CATEGORY_TITLES.get(cat, cat)}", style="v.dim"), Text(""))
            for item in by_cat[cat]:
                label, text = _link_rows(item, tlp=tlp, value=value, touches=_touches(item, targets))
                t.add_row(Text("    ").append_text(label), text)
                rows += 1
    out: list[RenderableType] = [t] if rows else []
    notes = []
    if more:
        notes.append(f"+{more} more manual pivots: the HTML report or `v3lum links <input>`")
    if hidden_red:
        notes.append(f"{hidden_red} third-party manual pivot(s) hidden at {S.tlp_label(v.case)}: only `v3lum links <input>` shows them, with the disclosure warning")
    if hidden_hostile:
        notes.append(f"{hidden_hostile} target-contact link(s) hidden for hostile entities (use --full to list them, defanged)")
    if hidden_privacy:
        notes.append(f"{hidden_privacy} personal-data link(s) hidden in this view (--show-personal)")
    if dropped:
        notes.append(f"{dropped} link(s) dropped: not an http(s) URL")
    others = sum(len(_l(items)) for key, items in links.items() if key not in set(v.seeds))
    if others:
        notes.append(f"{others} manual pivot(s) for discovered entities: the HTML report or `v3lum links <value>`")
    out += [Text(f"  {n}", style="v.ghost") for n in notes]
    return out


def _footer(v: _View) -> Text:
    t = Text()
    t.append(f" {S.tlp_label(v.case)} ", style=tlp_style(v.tlp))
    t.append(f"  case {clean_text(v.case.get('case_id') or '?')} · scores are a {S.SCORE_LABEL}", style="v.ghost")
    return t


# ======================================================================================
# render_single (v3lum run)
# ======================================================================================


def render_single(console: Console, out: dict[str, Any], *, show_personal: bool | None = None, no_defang: bool | None = None) -> None:
    """Print the result of one module run (``App.run_single``: module, entity, status, error,
    duration, findings, attributes, pivots, links; optional reason_code, partial, stop_reason, tlp,
    show_personal, no_defang) with the safety rules of :func:`render_case`. Links follow the TLP
    rules (``out['tlp']``, default AMBER): clickable only at CLEAR/GREEN, plain defanged text with
    'opening sends <value> to <host>' at AMBER and above, hidden at RED. The view flags default to
    ``out['show_personal']`` / ``out['no_defang']`` (False when absent)."""
    out = out if isinstance(out, dict) else {}
    show_personal = bool(out.get("show_personal", False)) if show_personal is None else bool(show_personal)
    no_defang = bool(out.get("no_defang", False)) if no_defang is None else bool(no_defang)
    st = _status(out.get("status"))
    key = str(out.get("entity") or "")
    etype, _, value = key.partition(":")
    findings = [f for f in _l(out.get("findings")) if isinstance(f, dict)]
    tags: set[str] = set()
    for f in findings:
        tags.update(str(t) for t in _l(f.get("tags")))
    display = entity_display(etype, value, show_personal=show_personal, tags=tags, no_defang=no_defang)
    tlp = _tlp_of(out.get("tlp") or "amber")
    head = Text()
    head.append(f"{clean_text(out.get('module') or '?')} ", style="v.module")
    head.append("→ ", style="v.ghost")
    head.append(f"{clean_text(etype)}:", style="v.type")
    head.append(display, style="v.defanged" if is_hostile(tags) else "v.entity")
    code = clean_text(out.get("reason_code") or "")
    head.append(f"   [{st}" + (f": {code}" if code else "") + "]", style=f"status.{st}")
    if out.get("partial"):
        head.append(f" partial ({clean_text(out.get('stop_reason') or 'stopped early')})", style="v.warn")
    head.append(f"  {clean_text(out.get('duration', 0))}s", style="v.ghost")
    head.append(f"  {tlp.label}", style=tlp_style(tlp.value_str))
    console.print(head)
    if out.get("error"):
        console.print(Text("  " + display_text(_redact.redact_text(clean_text(out["error"])), show_personal=show_personal), style="v.dim"))
    if findings:
        t = Table(box=box.SIMPLE, show_header=False)
        t.add_column(no_wrap=True)
        t.add_column(no_wrap=True)
        t.add_column(overflow="fold")
        for f in findings:
            sev = _sev(f.get("severity"))
            body = Text(display_text(f.get("title") or "?", show_personal=show_personal), style="v.text")
            if f.get("criterion") and sev in ("critical", "high"):
                body.append("\ncriterion: " + _clip(display_text(f["criterion"], show_personal=show_personal), 300), style="v.dim")
            if f.get("description"):
                body.append("\n" + display_text(f["description"], show_personal=show_personal), style="v.dim")
            t.add_row(_sev_text(sev), _conf_text(f), body)
        console.print(t)
    attrs = _d(out.get("attributes"))
    if attrs:
        t = Table(box=box.MINIMAL, show_header=False)
        t.add_column(style="v.dim", no_wrap=True)
        t.add_column(style="v.text", overflow="fold")
        for k, val in attrs.items():
            text = json.dumps(val, ensure_ascii=False, default=str)[:400] if isinstance(val, (list, dict)) else str(val)
            t.add_row(safe_rich(k), Text(display_text(text, show_personal=show_personal)))
        console.print(t)
    pivots = [p for p in _l(out.get("pivots")) if isinstance(p, dict)]
    if pivots:
        t = Table(box=box.MINIMAL, show_header=False, title=Text("pivots", style="v.dim"), title_justify="left")
        t.add_column(style="v.ghost")
        t.add_column(style="v.entity", overflow="fold")
        for p in pivots[:100]:
            pkey = str(p.get("entity") or "")
            ptype, _, pvalue = pkey.partition(":")
            t.add_row(safe_rich(p.get("relation") or ""), safe_rich(f"{ptype}:" + entity_display(ptype, pvalue, show_personal=show_personal, no_defang=no_defang)))
        if len(pivots) > 100:
            t.add_row("…", f"+{len(pivots) - 100} more")
        console.print(t)
    targets = {S.entity_host(key)} - {""}
    links = [x for x in _l(out.get("links")) if isinstance(x, dict) and x.get("url")]
    _single_links(console, links, tlp=tlp, value=display, targets=targets, hostile=is_hostile(tags))


def _single_links(
    console: Console, links: list[dict[str, Any]], *, tlp: _tlp.TLP, value: str, targets: set[str] | None = None, hostile: bool = False,
) -> None:
    """The follow-up links of ``v3lum run``: TLP rules as in :func:`render_case`; a link to the
    investigated host itself (``targets``) is never clickable and is hidden for a hostile entity."""
    targets = targets or set()
    valid = [x for x in links if safe_href(str(x.get("url"))) is not None]
    dropped = len(links) - len(valid)
    if dropped:
        console.print(Text(f"  {dropped} link(s) dropped: not an http(s) URL", style="v.ghost"))
    if not valid:
        return
    if tlp >= _tlp.TLP.RED:
        console.print(Text(f"  {len(valid)} follow-up link(s) hidden at {tlp.label}: opening them would send the value to a third party", style="v.ghost"))
        return
    touching = [x for x in valid if _touches(x, targets)]
    if hostile and touching:
        console.print(Text(f"  {len(touching)} target-contact link(s) hidden for a hostile entity", style="v.ghost"))
        valid = [x for x in valid if x not in touching]
    for link in valid[:30]:
        url = str(safe_href(str(link.get("url"))))
        row = Text("  ↗ ", style="v.accent")
        row.append_text(safe_rich(link.get("label") or "link", "v.text"))
        row.append("  ")
        if link in touching:
            row.append(_defang(url), style="v.defanged")
            row.append("  ⚠ opens the target (or makes a third party fetch it live): not clickable", style="v.warn")
        elif tlp <= _tlp.TLP.GREEN:
            text = Text(url, style="v.url")
            text.stylize(Style(link=url))
            row.append_text(text)
        else:
            host = _link_host(link)
            row.append(_defang(url), style="v.defanged")
            row.append(f"  opening sends {value} to {clean_text(host) or 'its host'}", style="v.warn")
        console.print(row)


# ======================================================================================
# detections (v3lum detect, ambiguous inputs)
# ======================================================================================


def render_detections(console: Console, raw: str, detections: Iterable[Any]) -> None:
    """The detection table of an input (types, normalized values, confidence, why): the echoed input
    and every value are safe text; CPF values are masked."""
    t = Table(
        box=box.SIMPLE, show_header=True, header_style="v.dim", title_justify="left",
        title=Text.assemble(("detect ", "v.accent"), (_clip(mask_cpf_in_text(clean_text(raw)), 80), "v.entity")),
    )
    t.add_column("type", style="v.type")
    t.add_column("normalized value", style="v.entity", overflow="fold")
    t.add_column("confidence", justify="right")
    t.add_column("why", style="v.dim")
    for d in detections:
        etype = getattr(getattr(d, "type", None), "value", str(getattr(d, "type", "?")))
        value = str(getattr(d, "value", ""))
        try:
            conf = float(getattr(d, "confidence", 0.0))
        except (TypeError, ValueError):
            conf = 0.0
        conf_style = "v.ok" if conf >= 0.75 else "v.warn" if conf >= 0.5 else "v.dim"
        shown = f"{len(value)} chars" if etype == "text_blob" else entity_display(etype, value, defang_urls=False)
        t.add_row(safe_rich(etype), safe_rich(shown), Text(f"{conf:.2f}", style=conf_style), Text(display_text(getattr(d, "reason", ""))))
    console.print(t)
