"""Markdown report (tickets, wikis, chat) - reports v2 (P336, P311, A2, A7, A8, A11, AR13, AR14, AR24).

* The first line is the generated TLP marking ``**TLP:<LABEL>**``, followed by the TLP 2.0 banner
  (and the LIGHT/ACTIVE engagement banner and the licence banner when they apply); every ``##``
  section starts with the marking again (A2, A7).
* Every module-derived string is escaped for Markdown (backslash escapes for the CommonMark
  punctuation, so ``<script>``, ``[x](javascript:...)``, ``|`` and emphasis never become markup),
  control characters are removed, valid CPFs are masked unless ``show_personal`` (AR24) and URLs
  inside free text are defanged (no autolink of a hostile URL, AR13).
* Links: only pivot-pack templates (at TLP:CLEAR/GREEN) and allow-listed documentation hosts become
  ``[label](<url>)`` links, through ``ui.safe.safe_href``; everything else is defanged inline code with
  the disclosure warning ('opening sends <value> to <host>'); at TLP:RED third-party pivots are
  omitted (``report.summary.pivot_plan`` / ``reference_view``).
* Same content order as the HTML report (``report.summary`` is shared): header, notices, bottom line
  and top contributors, attention points, your assets, correlations, findings (grouped rows with
  the confidence label and criterion on every row; POSSIBLE identity links only counted here - they
  are listed in the HTML details), entities, relations, timeline, manual pivots, coverage, the
  appendices 'Coverage lost under licence profile' and 'Disclosure ledger', evidence manifest,
  notes, attributions and the content hash note.
"""

from __future__ import annotations

import re
from typing import Any

from v3lum.report import summary as S
from v3lum.report.html import _depth
from v3lum.ui.safe import clean_text, display_text, entity_display, safe_href

__all__ = ["md_escape", "render"]

_MD_SPECIAL = re.compile(r"([\\`*_\[\]<>|~&])")
_SEVS = ("critical", "high", "medium", "low", "info")
#: How a value quoting the content-end marker is shown (the real marker occurs exactly once).
_QUOTED_MARKER = S.CONTENT_END_MARKER.replace("<!--", "<!-- quoted:")


def md_escape(value: Any) -> str:
    """Markdown-safe text: controls removed, newlines folded to spaces, and the characters that can
    open markup backslash-escaped (backslash, backtick, ``*``, ``_``, brackets, ``<``/``>`` - raw HTML
    never renders -, ``|`` table cells, ``~`` and ``&`` entities)."""
    text = clean_text(value).replace("\r", " ").replace("\n", " ").strip()
    return _MD_SPECIAL.sub(r"\\\1", text)


def _code(value: Any) -> str:
    """Inline code span for a (defanged) value; backticks inside are replaced and ``|`` is escaped
    (GFM splits table cells at a bare pipe *before* parsing code spans, so a value such as
    ``a|[x](https://evil)`` would otherwise open a new cell holding a live link)."""
    text = clean_text(value).replace("\n", " ").replace("`", "'").replace("|", "\\|")
    return f"`{text}`" if text else "``"


def _flag(value: bool | None, case: Any, name: str) -> bool:
    if value is not None:
        return bool(value)
    opts = case.get("options") if isinstance(case, dict) else None
    return bool(opts.get(name, False)) if isinstance(opts, dict) else False


def _l(value: Any) -> list[Any]:
    return list(value) if isinstance(value, (list, tuple)) else []


def _d(value: Any) -> dict[str, Any]:
    return value if isinstance(value, dict) else {}


class _Doc:
    def __init__(self, case: dict[str, Any], *, show_personal: bool, no_defang: bool) -> None:
        self.case = case
        self.show_personal = show_personal
        self.no_defang = no_defang
        self.idx = S.CaseIndex(case, show_personal=show_personal, no_defang=no_defang)
        self.label = S.tlp_label(case)
        self.engagement = S.engagement_banner(case)
        self.targets = S.target_hosts(case, idx=self.idx)
        self.values = S.case_values(case)
        self.out: list[str] = []

    def text(self, value: Any) -> str:
        plain = display_text(value, show_personal=self.show_personal)
        if not self.no_defang:  # no autolink of a URL or an e-mail address found in module text
            plain = S.defang_urls_in_text(plain).replace("@", "[@]")
        return md_escape(plain)

    def ent(self, key: str) -> str:
        etype, _ = self.idx.type_value(key)
        return _code(f"{clean_text(etype)}:{self.idx.display(key)}")

    def section(self, title: str) -> None:
        self.out += ["", f"## {md_escape(title)}", "", f"**{self.label}**" + (f" · {md_escape(self.engagement)}" if self.engagement else ""), ""]

    def ref(self, url: Any) -> str:
        href, text = S.reference_view(self.case, url, no_defang=self.no_defang, targets=self.targets, values=self.values)
        if href and safe_href(href):
            return f"[{md_escape(text)}](<{href}>)"
        return _code(text)


def render(case: dict[str, Any], *, show_personal: bool | None = None, no_defang: bool | None = None) -> str:
    """The Markdown report of a case; first line ``**TLP:<LABEL>**``. ``show_personal`` /
    ``no_defang`` default to the flags recorded in ``case['options']``; at TLP:CLEAR/GREEN
    cross-case and internal-platform references are left out (``summary.shareable_view``)."""
    case = case if isinstance(case, dict) else {}
    show_personal = _flag(show_personal, case, "show_personal")
    no_defang = _flag(no_defang, case, "no_defang")
    case = S.shareable_view(case)
    d = _Doc(case, show_personal=show_personal, no_defang=no_defang)
    out = d.out
    out.append(f"**{d.label}**")
    out.append("")
    out.append(f"> {md_escape(S.tlp_description(case))}")
    for line in S.engagement_block(case, show_personal=show_personal, no_defang=no_defang):
        out.append(">")  # refusal lines name out-of-scope targets: defanged, never autolinked
        out.append(f"> **{d.text(line)}**" if line == d.engagement else f"> {d.text(line)}")
    banner = S.appendix_licence(case)["banner"]
    if banner:
        out += [">", f"> **{md_escape(banner)}**"]
    out.append("")
    tool = _d(case.get("tool"))
    out.append(f"# V3LUM report - case {md_escape(case.get('case_id') or '?')}")
    out.append("")
    out.append(f"*Generated {md_escape(case.get('created') or '')} by V3LUM {md_escape(tool.get('version') or '')}*")
    _header(d)
    _bottom(d)
    _attention(d)
    _assets(d)
    _correlations(d)
    _findings(d)
    _entities(d)
    _relations(d)
    _timeline(d)
    _pivots(d)
    _coverage(d)
    _appendices(d)
    _evidence(d)
    _notes(d)
    _attributions(d)
    out += ["", "---", "", f"**{d.label}**", ""]
    # The marker appears once, right after the content: a value quoting it (inside a code span) is
    # neutralised so every verifier finds the same boundary.
    content = ("\n".join(out) + "\n").replace(S.CONTENT_END_MARKER, _QUOTED_MARKER)
    note = S.content_hash_note(S.content_hash(content))  # covers every byte before the marker
    return content + S.CONTENT_END_MARKER + "\n" + f"*{md_escape(note)}*\n"


def _header(d: _Doc) -> None:
    case = d.case
    s = _d(case.get("summary"))
    d.section("Summary")
    for inp in _l(case.get("inputs")) or [{"type": str(k).partition(":")[0], "value": str(k).partition(":")[2]} for k in _l(case.get("seeds"))]:
        if not isinstance(inp, dict):
            continue
        key = f"{inp.get('type')}:{inp.get('value')}"
        shown = entity_display(inp.get("type"), inp.get("value"), show_personal=d.show_personal, tags=d.idx.tags(key), no_defang=d.no_defang)
        reason = f" - {d.text(inp['reason'])}" if inp.get("reason") else ""
        label = clean_text(inp.get("type")) + ":" + shown[:200]
        d.out.append(f"- input {_code(label)}{reason}")
    for kind, text in S.header_items(case, show_personal=d.show_personal, no_defang=d.no_defang):
        if kind == "tlp":
            continue
        d.out.append(f"- **{md_escape(S.HEADER_LABELS.get(kind, 'note'))}:** {d.text(text)}")
    for _kind, text in S.report_notices(case, show_personal=d.show_personal):
        d.out.append(f"- **notice:** {md_escape(text)}")
    reading = S.case_level(case)
    score = _d(case.get("risk")).get("score", s.get("risk_score", 0))
    try:
        score_text = f"{float(score or 0):.0f}/100"
    except (TypeError, ValueError):
        score_text = "0/100"
    d.out.append("")
    d.out.append(
        f"**Reading: {md_escape(reading.upper())} ({score_text}, {md_escape(S.SCORE_LABEL)})** · {md_escape(s.get('entities', 0))} entities · "
        f"{md_escape(s.get('findings', 0))} findings · {md_escape(s.get('correlations', 0))} correlations · {md_escape(s.get('module_runs', 0))} module runs · "
        f"{md_escape(s.get('duration', 0))}s"
    )


def _bottom(d: _Doc) -> None:
    d.section("Bottom line")
    for line in S.bottom_line(d.case, show_personal=d.show_personal, no_defang=d.no_defang):
        head, sep, rest = line.partition(": ")
        d.out.append(f"- **{md_escape(head)}:** {d.text(rest)}" if sep else f"- {d.text(line)}")
    contributors = S.contributor_lines(d.case, show_personal=d.show_personal, no_defang=d.no_defang)
    if contributors:
        d.out += ["", f"Top contributors to the score ({md_escape(S.SCORE_LABEL)}):", ""]
        d.out += [f"- {d.text(c)}" for c in contributors]


def _attention(d: _Doc) -> None:
    points, limits = S.attention(d.case)
    if not points and not limits:
        return
    d.section("Attention points and limitations")
    d.out.append("*Suggestions: the analyst's verdict prevails.*")
    d.out.append("")
    d.out += [f"- **attention:** {d.text(x)}" for x in points]
    d.out += [f"- *limitation:* {d.text(x)}" for x in limits]


def _finding_table(d: _Doc, rows: list[S.FindingRow]) -> None:
    d.out.append("| Severity | Confidence | Entity | Finding | Source |")
    d.out.append("|---|---|---|---|---|")
    for row in rows:
        f = row.lead
        entities = list(dict.fromkeys(str(m.get("entity")) for m in row.members if m.get("entity")))
        ent = d.ent(entities[0]) if entities else "-"
        if len(entities) > 1:
            ent += f" (+{len(entities) - 1} variants)"
        parts = [f"**{d.text(f.get('title') or '?')}**"]
        for member in row.members:
            ov = S.override_text(member, show_personal=d.show_personal)
            if ov:
                parts.append(f"*{d.text(ov)}*")
                break
        parts += [md_escape(x) for x in S.breach_facts(f, show_personal=d.show_personal)]
        if f.get("description"):
            parts.append(d.text(str(f["description"])[:300]))
        refs = [r for r in dict.fromkeys(str(r) for m in row.members for r in _l(m.get("references"))) if safe_href(clean_text(r).strip())]
        if refs:
            parts.append("references: " + " ".join(d.ref(r) for r in refs[:5]))
        if row.grouped:
            parts.append(md_escape(row.sources_text() or f"{row.count} findings") + " · ids " + ", ".join(_code(i) for i in row.member_ids[:8]))
        conf = f"{row.confidence_label.upper()}<br>criterion: {d.text(row.criterion) if row.criterion else 'not recorded'}"
        sources = md_escape(", ".join(row.sources) or clean_text(f.get("module") or ""))
        d.out.append(f"| {row.severity.upper()} | {conf} | {ent} | {'<br>'.join(parts)} | {sources} |")


def _split(d: _Doc) -> tuple[list[dict[str, Any]], list[dict[str, Any]], list[dict[str, Any]]]:
    own, other, identity = [], [], []
    for f in d.idx.findings:
        (identity if S.is_identity_link(f) else own if S.is_own_asset(f) else other).append(f)
    return own, other, identity


def _corr_table(d: _Doc, corrs: list[dict[str, Any]]) -> None:
    d.out.append("| Severity | Confidence | Conclusion | Recommendation |")
    d.out.append("|---|---|---|---|")
    for c in corrs:
        sev = str(c.get("severity") or "info").lower()
        sev = sev if sev in _SEVS else "info"
        label = S.confidence_label(c)
        crit = d.text(c.get("criterion")) if c.get("criterion") else "not recorded"
        ents = ", ".join(d.ent(str(k)) for k in _l(c.get("entities"))[:5])
        desc = f"<br>{d.text(c.get('description'))}" if c.get("description") else ""
        d.out.append(
            f"| {sev.upper()} | {label.upper()}<br>criterion: {crit} | **{d.text(c.get('title') or c.get('rule') or '?')}**{desc}<br>on: {ents} | "
            f"{d.text(c.get('recommendation') or '')} |"
        )


def _assets(d: _Doc) -> None:
    own, _other, _identity = _split(d)
    corrs = [c for c in _l(d.case.get("correlations")) if isinstance(c, dict) and S.is_own_asset(c) and not S.is_identity_link(c)]
    if not own and not corrs:
        return
    d.section("Your assets")
    if corrs:
        _corr_table(d, corrs)
        d.out.append("")
    if own:
        _finding_table(d, S.finding_rows(own))


def _correlations(d: _Doc) -> None:
    corrs = [c for c in _l(d.case.get("correlations")) if isinstance(c, dict) and not S.is_identity_link(c) and not S.is_own_asset(c)]
    if not corrs:
        return
    d.section("Cross-referenced intelligence")
    _corr_table(d, corrs)


def _findings(d: _Doc) -> None:
    _own, other, identity = _split(d)
    if not other and not identity:
        return
    d.section("Findings")
    if other:
        _finding_table(d, S.finding_rows(other))
    if identity:
        d.out += ["", f"*{len(identity)} possible identity link(s) are listed only in the HTML report (entity details): the same handle does not prove identity.*"]


def _entities(d: _Doc) -> None:
    nodes = [n for n in _l(d.case.get("entities")) if isinstance(n, dict) and n.get("key")]
    if not nodes:
        return
    d.section("Entities")
    d.out.append("| Entity | Depth | Sources | Risk | Seen before |")
    d.out.append("|---|---|---|---|---|")
    for n in sorted(nodes, key=lambda x: (_depth(x), str(x.get("type")), str(x.get("value")))):
        key = str(n["key"])
        flags = (" (seed)" if n.get("seed") else "") + (" (common infra)" if n.get("noise") else "")
        risk = S.score_text(d.case, key, show_personal=d.show_personal, no_defang=d.no_defang, idx=d.idx)
        seen = "; ".join(S.sighting_lines(d.case, key, idx=d.idx))
        sources = md_escape(", ".join(clean_text(s) for s in _l(n.get("sources")))[:80])
        d.out.append(f"| {d.ent(key)}{flags} | {md_escape(n.get('depth', 0))} | {sources} | {d.text(risk)} | {d.text(seen)} |")


def _relations(d: _Doc) -> None:
    edges = [x for x in _l(d.case.get("edges")) if isinstance(x, dict)]
    if not edges:
        return
    d.section("Relations")
    for edge in edges[:500]:
        possible = " *(possible link)*" if S.confidence_label(edge) == "possible" else ""
        d.out.append(f"- {d.ent(str(edge.get('src')))} **{md_escape(edge.get('relation') or '')}** {d.ent(str(edge.get('dst')))} *(via {md_escape(edge.get('module') or '')})*{possible}")


def _timeline(d: _Doc) -> None:
    tl = [x for x in _l(d.case.get("timeline")) if isinstance(x, dict)]
    if not tl:
        return
    d.section("Timeline")
    for ev in tl:
        d.out.append(f"- **{md_escape(ev.get('date') or '')}** {d.ent(str(ev.get('entity') or ''))} - {d.text(ev.get('event') or '')} *({md_escape(ev.get('source') or '')})*")


def _pivots(d: _Doc) -> None:
    plan = S.pivot_plan(d.case, show_personal=d.show_personal, no_defang=d.no_defang, full=False)
    if not plan.entities and not (plan.hidden_red or plan.hidden_privacy or plan.hidden_hostile or plan.dropped):
        return
    d.section("Manual pivots")
    if plan.clickable:
        d.out.append("> Opening these links contacts third-party sites from your browser (they see your IP and the value). V3LUM never fetches them.")
    else:
        d.out.append(f"> At {d.label} manual pivots are not clickable: opening one sends the value to its host. V3LUM never fetches them.")
    for ent in plan.entities:
        d.out += ["", f"**{d.ent(ent.key)}**", ""]
        for cat, items in ent.groups:
            d.out.append(f"*{md_escape(cat.replace('_', ' '))}*")
            d.out.append("")
            for it in items:
                # labels may fall back to the link host (the target's, for touches_target links):
                # d.text defangs it so a renderer never autolinks it
                extra = (f" [{d.text(it.badge)}]" if it.badge else "") + (f" ({d.text(it.note or 'manual lookup')})" if it.manual else "")
                if it.href and safe_href(it.href):
                    d.out.append(f"- [{d.text(it.label)}](<{it.href}>){extra}")
                else:
                    warn = f" - {d.text(it.warning)}" if it.warning else ""
                    d.out.append(f"- {d.text(it.label)}{extra}: {_code(it.text[:300])}{warn}")
            d.out.append("")
    notes = []
    if plan.hidden_red:
        notes.append(f"{plan.hidden_red} third-party manual pivot(s) omitted at {d.label}: only `v3lum links <input>` shows them")
    if plan.hidden_privacy:
        notes.append(f"{plan.hidden_privacy} personal-data link(s) omitted (analyst-typed seeds only, with --show-personal)")
    if plan.hidden_hostile:
        notes.append(f"{plan.hidden_hostile} target-contact link(s) of hostile entities omitted (HTML report: expand them)")
    if plan.dropped:
        notes.append(f"{plan.dropped} link(s) dropped: not an http(s) URL")
    d.out += [f"*{md_escape(n)}*" for n in notes]


def _coverage(d: _Doc) -> None:
    case = d.case
    d.section("Source coverage")
    for line in S.skip_lines(case) + S.followup_lines(case):
        d.out.append(f"- {d.text(line)}")
    lic = S.appendix_licence(case)
    for a in lic["allow_entries"]:
        d.out.append(f"- licence allow-list entry used: {md_escape(a['source'])} ({md_escape(a['class'])}), legal reference {md_escape(a['legal_ref'])}")
    for line in lic["deferred"]:
        d.out.append(f"- deferred: {md_escape(line)}")
    eng = S.engagement_details(case, show_personal=d.show_personal, no_defang=d.no_defang)
    for target, n in eng["touched"]:  # A7: targets touched with their request counts
        d.out.append(f"- target touched: {_code(target)} ({n} requests)")
    for line in eng["refusals"]:  # A7: every out-of-scope refusal with its reason
        d.out.append(f"- {d.text(line)}")
    if eng["omitted"]:
        d.out.append(f"- +{eng['omitted']} more refusals not kept by the engine (see the case audit)")
    d.out += ["", "| Module | Status | Reason code | Runs | Note |", "|---|---|---|---|---|"]
    for name, info in sorted(_d(case.get("coverage")).items()):
        info = _d(info)
        d.out.append(
            f"| {md_escape(name)} | {md_escape(info.get('status') or '')} | {md_escape(info.get('reason_code') or '')} | {md_escape(info.get('runs', 0))} | "
            f"{d.text(str(info.get('reason') or '')[:120])} |"
        )


def _appendices(d: _Doc) -> None:
    lic = S.appendix_licence(d.case)
    d.section("Appendix: Coverage lost under licence profile")
    d.out.append(f"Licence profile {md_escape(lic['profile'])}.")
    if lic["skipped_line"]:
        d.out.append(md_escape(lic["skipped_line"]))
    d.out.append("")
    if lic["lost"]:
        d.out += [f"- {md_escape(x)}" for x in lic["lost"]]
    else:
        d.out.append("No coverage was lost to the licence profile in this run.")
    for u in lic["used"]:
        d.out.append(f"- used: {md_escape(u['source'])} ({md_escape(u['class'])}, {md_escape(u['basis'])})")
    app = S.appendix_disclosure(d.case, show_personal=d.show_personal, no_defang=d.no_defang)
    d.section("Appendix: Disclosure ledger")
    d.out.append(md_escape(app["line"]))
    if app["hosts"]:
        d.out += ["", "| Host contacted | Provider | Tier | Terms | Requests | Role |", "|---|---|---|---|---|---|"]
        for row in app["hosts"]:
            d.out.append(  # hosts in code spans: an investigated target's host is never autolinked
                f"| {_code(row['host'])} | {md_escape(row['name'] or row['provider'])} | {md_escape(row['tier'])} | {md_escape(row['terms'])} | "
                f"{row['requests']} | {md_escape(row['role'])} |"
            )
    if app["by_entity"]:
        d.out += ["", "Who received each value:", ""]
        d.out += [f"- {_code(who)}: {md_escape(', '.join(names))}" for who, names in app["by_entity"]]


def _evidence(d: _Doc) -> None:
    from v3lum.report.html import evidence_manifest

    rows = evidence_manifest(d.case)
    d.section("Evidence manifest (SHA-256)")
    if not rows:
        d.out.append("No evidence files were recorded for this case.")
        return
    for f, h, m in rows:
        d.out.append(f"- {_code(h)} {md_escape(f)}" + (f" ({md_escape(m)})" if m else ""))


def _notes(d: _Doc) -> None:
    notes = S.note_lines(d.case, show_personal=d.show_personal)
    if not notes:
        return
    d.section("Notes")
    d.out += [f"> **Note:** {d.text(n)}" for n in notes]


def _attributions(d: _Doc) -> None:
    atts = S.attributions(d.case)
    if not atts:
        return
    d.section("Attributions")
    for a in atts:
        d.out.append(f"- **{md_escape(a['name'])}** ({md_escape(a['licence'] or 'licence not recorded')}): {md_escape(a['text'])}")
