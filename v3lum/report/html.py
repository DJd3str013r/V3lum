"""Self-contained HTML report (reports v2: P336, P311, A2, A7, A8, A11, AR13, AR14, AR24).

Integrity and safety (P336):

* a Content-Security-Policy meta ``default-src 'none'; img-src data:; style-src 'unsafe-inline';
  script-src 'sha256-<hash of the bundled JS>'`` (:func:`csp_hash`; never ``'unsafe-inline'``
  scripts), plus ``base-uri 'none'; form-action 'none'`` and the no-referrer meta: everything is
  embedded and nothing external ever loads (no fonts, images, scripts or styles from anywhere);
* every anchor goes through ``ui.safe.safe_href`` (http/https only) and carries
  ``rel="noreferrer noopener"``; only pivot-pack templates (at TLP:CLEAR/GREEN) and allow-listed
  documentation hosts are clickable (``report.summary.pivot_plan`` / ``reference_view``); entity
  values, entity-derived URLs and hostile entities are defanged plain text; touches_target links are
  never clickable and collapsed for hostile entities; at AMBER and above pivot links are text with
  'opening sends <value> to <host>', at RED third-party links are omitted;
* the TLP 2.0 marking (label and colour) is generated from the case TLP in the header, at the top of
  every section, in the footer and in print CSS (A2); a LIGHT/ACTIVE engagement banner is repeated
  under the marking of every section (A7);
* the evidence manifest (file, SHA-256) is embedded and the footer note gives the SHA-256 of the
  content above it (:data:`report.summary.CONTENT_END_MARKER`); the file's own SHA-256 goes to the
  ``<report>.sha256`` sidecar and the case DB (``report.write_reports``);
* every module-derived string is escaped (``html.escape``) after control characters were removed and
  valid CPFs masked (``ui.safe.display_text``; ``show_personal`` unmasks the view, AR24); URLs inside
  free text are defanged.

Content follows the first-screen order of AR14 (shared with the terminal through
``report.summary``): header (TLP, mode/egress, engagement, partial notes, answered/could-not-verify
lines, internal sightings, disclosure, licence banner, notices) -> bottom line with the top-3 score
contributors -> attention points and limitations -> your assets -> correlations -> findings (grouped
rows, P335; confidence label and criterion on every row, P322) -> entity map and details (internal
sightings first, POSSIBLE identity links only here, P258) -> timeline -> manual pivots -> coverage
(skip reasons, licence allow-list entries used, deferred lookups) -> appendices 'Coverage lost under
licence profile' and 'Disclosure ledger' -> evidence manifest -> notes -> footer (attributions in a
collapsed section, hash note).
"""

from __future__ import annotations

import base64
import hashlib
import html
import json
import os
from collections import defaultdict
from pathlib import Path
from typing import Any

from v3lum.report import summary as S
from v3lum.ui.safe import clean_text, display_text, entity_display, safe_href

__all__ = ["CSP_TEMPLATE", "JS", "RISK_COLORS", "csp", "csp_hash", "e", "render"]

CSS = """
:root{--bg:#07090a;--panel:#0d1114;--panel2:#11171b;--line:#1d272d;--text:#d6e2e4;--dim:#7d8b94;--ghost:#4a555c;
--neon:#00ff9f;--acid:#b4ff39;--violet:#bd5cff;--magenta:#ff3caa;--cyan:#00d7ff;--amber:#ffb000;--orange:#ff6b2b;--blood:#ff2e4d}
*{box-sizing:border-box}html,body{margin:0;background:var(--bg);color:var(--text);
font:14px/1.5 ui-monospace,SFMono-Regular,Menlo,Consolas,"Liberation Mono",monospace}
a{color:var(--cyan)}a:hover{color:var(--neon)}
.wrap{max-width:1280px;margin:0 auto;padding:24px 18px 60px}
header{border:1px solid var(--line);background:linear-gradient(135deg,#0b1012,#0f0b16);padding:22px 24px;border-radius:6px}
.logo{font-weight:800;letter-spacing:.35em;font-size:28px;color:var(--neon)}
.tag{color:var(--violet);margin-top:2px}.muted{color:var(--dim)}.ghost{color:var(--ghost)}
.grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(180px,1fr));gap:10px;margin-top:16px}
.kpi{background:var(--panel);border:1px solid var(--line);border-radius:4px;padding:10px 12px}.kpi b{display:block;font-size:20px;color:var(--text)}
.kpi span{color:var(--dim);font-size:12px;text-transform:uppercase;letter-spacing:.08em}
.gauge{margin-top:16px;height:14px;background:#0a0f11;border:1px solid var(--line);border-radius:2px;overflow:hidden}
.gauge i{display:block;height:100%}
ul.hdr{list-style:none;margin:12px 0 0;padding:0}ul.hdr li{margin:2px 0}ul.hdr li b{color:var(--dim);font-weight:normal;display:inline-block;min-width:96px}
.k-engagement,.k-partial,.k-licence,.k-tls{color:var(--amber)}
section{margin-top:26px}h2{font-size:15px;letter-spacing:.18em;text-transform:uppercase;color:var(--neon);border-bottom:1px solid var(--line);padding-bottom:6px;margin-top:6px}
h2 small{color:var(--ghost);letter-spacing:0;text-transform:none;font-weight:normal}
h3{font-size:13px;color:var(--violet);margin:14px 0 6px}
.secmark{font-size:11px;color:var(--dim)}
.tlp{display:inline-block;background:#000;padding:1px 8px;border-radius:2px;font-weight:800;letter-spacing:.06em}
.tlp-clear{color:#ffffff}.tlp-green{color:#33ff00}.tlp-amber,.tlp-amber-strict{color:#ffc000}.tlp-red{color:#ff2b2b}
.tlpdesc{color:var(--dim);font-size:12px}
.engbar{display:inline-block;margin-left:8px;color:var(--amber)}
table{width:100%;border-collapse:collapse;background:var(--panel);border:1px solid var(--line)}
th,td{padding:7px 10px;border-bottom:1px solid var(--line);vertical-align:top;text-align:left}
th{color:var(--dim);font-weight:normal;text-transform:uppercase;font-size:11px;letter-spacing:.08em;background:var(--panel2)}
.sev{display:inline-block;min-width:74px;text-align:center;padding:1px 6px;border-radius:2px;font-size:11px;font-weight:700;letter-spacing:.06em;text-transform:uppercase}
.sev.info{color:var(--cyan);border:1px solid rgba(0,215,255,.4)}.sev.low{color:var(--acid);border:1px solid rgba(180,255,57,.4)}
.sev.medium{color:#000;background:var(--amber)}.sev.high{color:#000;background:var(--orange)}.sev.critical{color:#fff;background:var(--blood)}
.conf{font-size:11px;letter-spacing:.06em;text-transform:uppercase}.conf.confirmed{color:var(--neon)}.conf.probable{color:var(--amber)}.conf.possible{color:var(--dim)}
.risk-none{color:var(--neon)}.risk-inconclusive{color:var(--dim)}.risk-low{color:var(--acid)}.risk-medium{color:var(--amber)}.risk-high{color:var(--orange)}.risk-critical{color:var(--blood)}
.ent{color:var(--cyan);word-break:break-all}.ent.hostile{color:var(--magenta)}.typ{color:var(--violet)}.mod{color:var(--acid)}
.desc{color:var(--dim);font-size:12.5px;margin-top:3px}.crit{color:var(--dim);font-size:12px;margin-top:3px}
.analyst{color:var(--amber);font-size:12px;margin-top:3px}.facts{color:var(--text);font-size:12px;margin-top:3px}
.warn{border-left:3px solid var(--amber);padding:6px 12px;background:#15120a;color:var(--amber);margin:8px 0}
.notice{border-left:3px solid var(--violet);padding:6px 12px;background:#100c16;color:var(--text);margin:6px 0}
.defanged{color:var(--magenta);word-break:break-all}.linkwarn{color:var(--amber);font-size:12px}
.toolbar{display:flex;gap:8px;flex-wrap:wrap;margin:10px 0}
.toolbar button,.toolbar input{background:var(--panel);color:var(--text);border:1px solid var(--line);padding:5px 10px;border-radius:3px;font:inherit}
.toolbar button.on{border-color:var(--neon);color:var(--neon)}.toolbar input{flex:1;min-width:200px}
ul.tree,ul.tree ul{list-style:none;margin:0;padding-left:18px;border-left:1px dashed var(--line)}
ul.tree{padding-left:6px;border:0}ul.tree li{margin:2px 0}.rel{color:var(--ghost)}
details{background:var(--panel);border:1px solid var(--line);border-radius:4px;margin:6px 0;padding:6px 10px}
summary{cursor:pointer;color:var(--text)}code{color:var(--acid);word-break:break-all}
footer{margin-top:40px;color:var(--ghost);font-size:12px}footer .hash{word-break:break-all;margin-top:8px}
.st-ok{color:var(--neon)}.st-empty{color:var(--dim)}.st-error{color:var(--blood)}.st-needs_key,.st-rate_limited{color:var(--amber)}
.st-quota{color:var(--amber)}.st-blocked{color:var(--magenta)}.st-skipped,.st-unavailable,.st-not_run{color:var(--ghost)}
.tlp-print{display:none}
@media print{html,body{background:#fff;color:#000}*{-webkit-print-color-adjust:exact;print-color-adjust:exact}
header,table,.kpi,details{background:#fff}.toolbar{display:none}
.tlp-print{display:block;position:fixed;top:0;right:0;background:#000;padding:2px 10px;font-weight:800}
section{break-inside:auto}}
"""

#: The only script of the report (filters; opens every collapsed section before printing). Its
#: SHA-256 is the only script source the CSP allows (:func:`csp_hash`).
JS = (
    "(function(){var q=document.getElementById('q');var btns=document.querySelectorAll('[data-sev]');var active='all';"
    "function apply(){var t=((q&&q.value)||'').toLowerCase();document.querySelectorAll('[data-row]').forEach(function(r){"
    "var s=active==='all'||r.getAttribute('data-sevv')===active;var x=!t||r.textContent.toLowerCase().indexOf(t)>=0;"
    "r.style.display=(s&&x)?'':'none';});}"
    "btns.forEach(function(b){b.addEventListener('click',function(){active=b.getAttribute('data-sev');"
    "btns.forEach(function(o){o.classList.toggle('on',o===b);});apply();});});"
    "if(q){q.addEventListener('input',apply);}"
    "window.addEventListener('beforeprint',function(){document.querySelectorAll('details').forEach(function(d){d.setAttribute('open','');});});"
    "})();"
)

#: Content-Security-Policy of every V3LUM HTML page (``{script}`` = :func:`csp_hash` of its script).
CSP_TEMPLATE = "default-src 'none'; img-src data:; style-src 'unsafe-inline'; script-src '{script}'; base-uri 'none'; form-action 'none'"

#: Gauge colour per reading ('clean' is never printed: v1 cases read 'no findings').
RISK_COLORS = {
    "no findings": "#00ff9f", "inconclusive": "#7d8b94", "low": "#b4ff39", "medium": "#ffb000", "high": "#ff6b2b", "critical": "#ff2e4d",
}
_SEVS = ("critical", "high", "medium", "low", "info")
_TLP_CLASSES = {"clear": "clear", "green": "green", "amber": "amber", "amber+strict": "amber-strict", "red": "red"}
_STATUSES = ("ok", "empty", "rate_limited", "quota", "blocked", "error", "needs_key", "unavailable", "skipped", "not_run")
_CATEGORY_TITLES = {
    "reputation": "reputation", "history": "history", "passive_dns": "passive DNS", "code_paste": "code / paste", "social": "social",
    "company": "company", "crypto": "crypto", "geo": "geo", "search": "search", "other": "other",
}


def e(value: Any) -> str:
    """HTML-escape a value (quotes included); None -> ''."""
    return html.escape("" if value is None else str(value), quote=True)


def csp_hash(script: str = JS) -> str:
    """The CSP source of a script: ``'sha256-<base64 of the SHA-256 of its UTF-8 text>'`` without the
    quotes (``csp_hash()`` = the hash of :data:`JS`)."""
    digest = hashlib.sha256(script.encode("utf-8")).digest()
    return "sha256-" + base64.b64encode(digest).decode("ascii")


def csp(script: str = JS) -> str:
    """The Content-Security-Policy of a page whose only script is ``script``."""
    return CSP_TEMPLATE.format(script=csp_hash(script))


def _flag(value: bool | None, case: Any, name: str) -> bool:
    if value is not None:
        return bool(value)
    opts = case.get("options") if isinstance(case, dict) else None
    return bool(opts.get(name, False)) if isinstance(opts, dict) else False


def _d(value: Any) -> dict[str, Any]:
    return value if isinstance(value, dict) else {}


def _l(value: Any) -> list[Any]:
    return list(value) if isinstance(value, (list, tuple)) else []


def _depth(node: dict[str, Any]) -> int:
    """The pivot depth of an entity dict for sorting (a damaged stored case never breaks a report)."""
    try:
        return int(node.get("depth") or 0)
    except (TypeError, ValueError):
        return 99


def _sev(value: Any) -> str:
    text = str(value or "info").strip().lower()
    return text if text in _SEVS else "info"


def _risk_class(reading: str) -> str:
    if reading == S.NO_FINDINGS:
        return "risk-none"
    return f"risk-{reading}" if reading in ("inconclusive", "low", "medium", "high", "critical") else "risk-none"


def tlp_badge(case: dict[str, Any]) -> str:
    """The TLP 2.0 marking of a case as an HTML badge (label in its colour on black)."""
    value = S.tlp_value(case)
    return f'<span class="tlp tlp-{_TLP_CLASSES.get(value, "red")}">{e(S.tlp_label(case))}</span>'


class _Page:
    """One rendering of a case: view flags, the case index and the per-section marking."""

    def __init__(self, case: dict[str, Any], *, show_personal: bool, no_defang: bool) -> None:
        self.case = case
        self.show_personal = show_personal
        self.no_defang = no_defang
        self.idx = S.CaseIndex(case, show_personal=show_personal, no_defang=no_defang)
        self.badge = tlp_badge(case)
        banner = S.engagement_banner(case)
        self.mark = f'<div class="secmark">{self.badge}' + (f'<span class="engbar">{e(banner)}</span>' if banner else "") + "</div>"
        self.targets = S.target_hosts(case, idx=self.idx)  # investigated/hostile hosts: never clickable
        self.values = S.case_values(case)

    # ---- text helpers
    def text(self, value: Any) -> str:
        """Module free text: controls removed, CPFs masked unless show_personal, URLs defanged, escaped."""
        plain = display_text(value, show_personal=self.show_personal)
        return e(plain if self.no_defang else S.defang_urls_in_text(plain))

    def ent(self, key: str) -> str:
        etype, _ = self.idx.type_value(key)
        hostile = " hostile" if self.idx.hostile(key) else ""
        return f'<span class="typ">{e(clean_text(etype))}:</span><span class="ent{hostile}">{e(self.idx.display(key))}</span>'

    def section(self, sid: str, title: str, body: str, count: int | None = None) -> str:
        small = f" <small>({count})</small>" if count is not None else ""
        return f'<section id="{e(sid)}">{self.mark}<h2>{e(title)}{small}</h2>{body}</section>'

    def conf(self, item: dict[str, Any], *, criterion: bool = True) -> str:
        label = S.confidence_label(item)
        out = f'<span class="conf {label}">{e(label.upper())}</span>'
        if criterion:
            crit = item.get("criterion") or ""
            out += f'<div class="crit">criterion: {self.text(crit) if crit else "not recorded"}</div>'
        return out

    def ref(self, url: Any) -> str:
        href, text = S.reference_view(self.case, url, no_defang=self.no_defang, targets=self.targets, values=self.values)
        if href and safe_href(href):
            return f'<a href="{e(href)}" rel="noreferrer noopener" target="_blank">{e(text)}</a>'
        return f'<span class="defanged">{e(text)}</span>'


def render(case: dict[str, Any], *, show_personal: bool | None = None, no_defang: bool | None = None) -> str:
    """The self-contained HTML report of a case (``CaseResult.to_dict()`` or a stored v1/v2 case).

    ``show_personal`` unmasks CPF and other masked values in this view (the caller records it in the
    case audit); ``no_defang`` shows hostile values as they are (links stay non-clickable). Both
    default to the flags recorded in ``case['options']``. At TLP:CLEAR/GREEN cross-case and
    internal-platform references are left out (``summary.shareable_view``)."""
    case = case if isinstance(case, dict) else {}
    show_personal = _flag(show_personal, case, "show_personal")
    no_defang = _flag(no_defang, case, "no_defang")
    case = S.shareable_view(case)
    p = _Page(case, show_personal=show_personal, no_defang=no_defang)
    body: list[str] = [_header(p)]
    body.append(_bottom(p))
    body += [_attention(p), _your_assets(p), _correlations(p), _findings(p), _entity_map(p), _entities(p), _timeline(p)]
    body += [_pivots(p), _coverage(p), _appendix_licence(p), _appendix_disclosure(p), _evidence(p), _notes(p)]
    content = "".join(
        [
            '<!doctype html><html lang="en"><head><meta charset="utf-8">',
            f'<meta http-equiv="Content-Security-Policy" content="{e(csp())}">',
            '<meta name="referrer" content="no-referrer">',
            '<meta name="robots" content="noindex,nofollow">',
            '<meta name="viewport" content="width=device-width,initial-scale=1">',
            f"<title>V3LUM case {e(clean_text(case.get('case_id') or '?'))} - {e(S.tlp_label(case))}</title>",
            f"<style>{CSS}{_print_css(case)}</style></head><body>",
            f'<div class="tlp-print tlp tlp-{_TLP_CLASSES.get(S.tlp_value(case), "red")}" aria-hidden="true">{e(S.tlp_label(case))}</div>',
            '<div class="wrap">',
            *[b for b in body if b],
            _footer_head(p),
        ]
    )
    note = S.content_hash_note(S.content_hash(content))  # covers every byte before the marker
    tail = f'<div class="hash">{e(note)}</div></footer></div><script>{JS}</script></body></html>'
    return content + S.CONTENT_END_MARKER + tail


def _print_css(case: dict[str, Any]) -> str:
    """Print CSS with the TLP label in every page margin (A2: the marking prints on every page)."""
    label = S.tlp_label(case).replace('"', "")
    color = S.tlp_color(case)
    return f'@page{{margin:16mm 12mm;@top-right{{content:"{label}";color:{color};background:#000;font-weight:800}}@bottom-right{{content:"{label}";color:{color};background:#000;font-weight:800}}}}'


# ======================================================================================
# header and first screen (AR14)
# ======================================================================================


def _inputs(case: dict[str, Any]) -> list[tuple[str, str, str]]:
    out = []
    for inp in _l(case.get("inputs")):
        if isinstance(inp, dict) and inp.get("type") and inp.get("value") is not None:
            out.append((str(inp["type"]), str(inp["value"]), str(inp.get("reason") or "")))
    if out:
        return out
    return [(k.partition(":")[0], k.partition(":")[2], "") for k in (str(s) for s in _l(case.get("seeds"))) if k]


def _header(p: _Page) -> str:
    case = p.case
    s = _d(case.get("summary"))
    reading = S.case_level(case)
    score = _d(case.get("risk")).get("score", s.get("risk_score", 0))
    try:
        score_f = max(0.0, min(100.0, float(score or 0)))
    except (TypeError, ValueError):
        score_f = 0.0
    out = ["<header>", f'<div>{p.badge} <span class="tlpdesc">{e(S.tlp_description(case))}</span></div>']
    out.append('<div class="logo">V3LUM</div><div class="tag">lift the veil :: osint · cti · recon</div>')
    tool = _d(case.get("tool"))
    out.append(
        f'<div class="muted" style="margin-top:10px">case <b style="color:var(--neon)">{e(clean_text(case.get("case_id") or "?"))}</b>'
        f' · {e(clean_text(case.get("created") or ""))} · V3LUM {e(clean_text(tool.get("version") or ""))}</div>'
    )
    tags = {}
    for etype, value, reason in _inputs(case):
        key = f"{etype}:{value}"
        tags[key] = p.idx.tags(key)
        shown = entity_display(etype, value, show_personal=p.show_personal, tags=tags[key], no_defang=p.no_defang)
        hostile = " hostile" if p.idx.hostile(key) else ""
        out.append(
            f'<div>input <span class="typ">{e(clean_text(etype))}:</span><span class="ent{hostile}">{e(shown[:300])}</span>'
            + (f' <span class="ghost">{p.text(reason)}</span>' if reason else "")
            + "</div>"
        )
    out.append('<ul class="hdr">')
    for kind, text in S.header_items(case, show_personal=p.show_personal, no_defang=p.no_defang):
        if kind == "tlp":
            continue
        label = S.HEADER_LABELS.get(kind, "note")
        shown = e(text) if kind in ("answered", "engagement", "sightings") else p.text(text)
        out.append(f'<li class="k-{e(kind)}"><b>{e(label)}</b> {shown}</li>')
    out.append("</ul>")
    for _kind, text in S.report_notices(case, show_personal=p.show_personal):
        out.append(f'<div class="notice">{e(text)}</div>')
    kpis = [
        (f'<span class="{_risk_class(reading)}">{score_f:.0f}/100 {e(reading.upper())}</span>', "reading"),
        (e(s.get("entities", len(_l(case.get("entities"))))), "entities"),
        (e(s.get("findings", len(_l(case.get("findings"))))), "findings"),
        (e(s.get("correlations", len(_l(case.get("correlations"))))), "correlations"),
        (e(s.get("module_runs", len(_l(case.get("modules"))))), "module runs"),
        (f'{e(s.get("duration", 0))}s', "duration"),
    ]
    out.append('<div class="grid">' + "".join(f'<div class="kpi"><b>{v}</b><span>{e(lbl)}</span></div>' for v, lbl in kpis) + "</div>")
    color = RISK_COLORS.get(reading, RISK_COLORS["no findings"])
    out.append(f'<div class="gauge"><i style="width:{max(1.0, score_f):.1f}%;background:{color}"></i></div>')
    out.append(f'<div class="ghost" style="margin-top:4px">score: {e(S.SCORE_LABEL)}</div>')
    out.append("</header>")
    return "".join(out)


def _bottom(p: _Page) -> str:
    lines = S.bottom_line(p.case, show_personal=p.show_personal, no_defang=p.no_defang)
    body = ["<ul>"]
    for line in lines:
        head, sep, rest = line.partition(": ")
        body.append(f"<li><b>{e(head)}:</b> {p.text(rest)}</li>" if sep else f"<li>{p.text(line)}</li>")
    body.append("</ul>")
    contributors = S.contributor_lines(p.case, show_personal=p.show_personal, no_defang=p.no_defang)
    if contributors:
        body.append(f"<h3>top contributors to the score ({e(S.SCORE_LABEL)})</h3><ul>")
        body += [f"<li>{p.text(c)}</li>" for c in contributors]
        body.append("</ul>")
    return p.section("bottom-line", "Bottom line", "".join(body))


def _attention(p: _Page) -> str:
    points, limits = S.attention(p.case)
    if not points and not limits:
        return ""
    body = ['<p class="muted">Suggestions: the analyst\'s verdict prevails.</p><ul>']
    body += [f"<li><b>attention</b> {p.text(x)}</li>" for x in points]
    body += [f'<li class="muted"><b>limitation</b> {p.text(x)}</li>' for x in limits]
    body.append("</ul>")
    return p.section("attention", "Attention points and limitations", "".join(body))


# ======================================================================================
# findings and correlations
# ======================================================================================


def _finding_table(p: _Page, rows: list[S.FindingRow], *, toolbar: bool) -> str:
    out = []
    if toolbar:
        out.append('<div class="toolbar"><button class="on" data-sev="all">all</button>')
        for sev in _SEVS:
            n = sum(1 for r in rows if r.severity == sev)
            if n:
                out.append(f'<button data-sev="{sev}">{sev} ({n})</button>')
        out.append('<input id="q" placeholder="filter findings, entities, sources..."></div>')
    out.append("<table><tr><th>severity</th><th>confidence</th><th>entity</th><th>finding</th><th>source</th></tr>")
    for row in rows:
        f = row.lead
        entities = list(dict.fromkeys(str(m.get("entity")) for m in row.members if m.get("entity")))
        ent_html = p.ent(entities[0]) if entities else "-"
        if len(entities) > 1:
            ent_html += f' <span class="ghost">(+{len(entities) - 1} variant{"s" if len(entities) > 2 else ""})</span>'
        body = [p.text(f.get("title") or "?")]
        for member in row.members:
            ov = S.override_text(member, show_personal=p.show_personal)
            if ov:
                body.append(f'<div class="analyst">{p.text(ov)}</div>')
                break
        for fact in S.breach_facts(f, show_personal=p.show_personal):
            body.append(f'<div class="facts">{e(fact)}</div>')
        if f.get("description"):
            body.append(f'<div class="desc">{p.text(f["description"])}</div>')
        refs = list(dict.fromkeys(str(r) for m in row.members for r in _l(m.get("references"))))
        web = [r for r in refs if safe_href(clean_text(r).strip())]
        if web:
            more = f' <span class="ghost">(+{len(web) - 8})</span>' if len(web) > 8 else ""
            body.append('<div class="desc">references: ' + " ".join(p.ref(r) for r in web[:8]) + more + "</div>")
        if len(refs) > len(web):
            body.append(f'<div class="desc ghost">{len(refs) - len(web)} non-http(s) reference(s) dropped</div>')
        if row.grouped:
            body.append(f'<div class="desc">{e(row.sources_text() or f"{row.count} findings")}</div>')
            body.append(f"<details><summary class=\"ghost\">{row.count} grouped findings (each keeps its evidence)</summary><table>")
            body.append("<tr><th>finding id</th><th>source</th><th>entity</th><th>confidence</th></tr>")
            for m in row.members:
                ment = p.ent(str(m["entity"])) if m.get("entity") else "-"
                body.append(
                    f'<tr><td><code>{e(clean_text(m.get("id") or ""))}</code></td><td class="mod">{e(clean_text(m.get("source") or m.get("module") or ""))}</td>'
                    f"<td>{ment}</td><td>{p.conf(m, criterion=False)}</td></tr>"
                )
            body.append("</table></details>")
        if f.get("data"):
            data = json.dumps(f["data"], ensure_ascii=False, default=str)[:3000]
            body.append(f'<details><summary class="ghost">data</summary><code>{p.text(data)}</code></details>')
        sources = ", ".join(row.sources) if row.sources else clean_text(f.get("module") or "")
        crit = {"criterion": row.criterion, "confidence_label": row.confidence_label}
        out.append(
            f'<tr data-row data-sevv="{row.severity}"><td><span class="sev {row.severity}">{row.severity}</span></td>'
            f"<td>{p.conf(crit)}</td><td>{ent_html}</td><td>{''.join(body)}</td><td class=\"mod\">{e(sources)}</td></tr>"
        )
    out.append("</table>")
    return "".join(out)


def _split_findings(p: _Page) -> tuple[list[dict[str, Any]], list[dict[str, Any]], list[dict[str, Any]]]:
    own, other, identity = [], [], []
    for f in p.idx.findings:
        if S.is_identity_link(f):
            identity.append(f)
        elif S.is_own_asset(f):
            own.append(f)
        else:
            other.append(f)
    return own, other, identity


def _your_assets(p: _Page) -> str:
    own, _other, _identity = _split_findings(p)
    corrs = [c for c in _l(p.case.get("correlations")) if isinstance(c, dict) and S.is_own_asset(c) and not S.is_identity_link(c)]
    if not own and not corrs:
        return ""
    body = ['<p class="muted">Findings about the organisation\'s own assets (org profile), listed first (A11).</p>']
    if corrs:
        body.append(_corr_table(p, corrs))
    if own:
        body.append(_finding_table(p, S.finding_rows(own), toolbar=False))
    return p.section("your-assets", "Your assets", "".join(body), len(own) + len(corrs))


def _corr_table(p: _Page, corrs: list[dict[str, Any]]) -> str:
    out = ["<table><tr><th>severity</th><th>confidence</th><th>conclusion</th><th>entities</th><th>recommendation</th></tr>"]
    for c in corrs:
        sev = _sev(c.get("severity"))
        ents = "<br>".join(p.ent(str(k)) for k in _l(c.get("entities"))[:8])
        desc = f'<div class="desc">{p.text(c.get("description"))}</div>' if c.get("description") else ""
        evidence = _l(c.get("evidence"))
        ev = ("<details><summary class=\"ghost\">evidence</summary><ul>" + "".join(f"<li>{p.text(x)}</li>" for x in evidence[:20]) + "</ul></details>") if evidence else ""
        refs = _l(c.get("references"))
        rf = ('<div class="desc">references: ' + " ".join(p.ref(r) for r in refs[:5]) + "</div>") if refs else ""
        out.append(
            f'<tr><td><span class="sev {sev}">{sev}</span></td><td>{p.conf(c)}</td>'
            f"<td><b>{p.text(c.get('title') or c.get('rule') or '?')}</b>{desc}{ev}{rf}</td><td>{ents}</td>"
            f"<td class=\"muted\">{p.text(c.get('recommendation') or '')}</td></tr>"
        )
    out.append("</table>")
    return "".join(out)


def _correlations(p: _Page) -> str:
    corrs = [c for c in _l(p.case.get("correlations")) if isinstance(c, dict) and not S.is_identity_link(c) and not S.is_own_asset(c)]
    body = _corr_table(p, corrs) if corrs else '<p class="muted">No cross-source conclusions were reached.</p>'
    return p.section("correlations", "Cross-referenced intelligence", body, len(corrs))


def _findings(p: _Page) -> str:
    _own, other, identity = _split_findings(p)
    rows = S.finding_rows(other)
    body = [_finding_table(p, rows, toolbar=True)] if rows else ['<p class="muted">No findings outside your assets.</p>']
    if identity:
        body.append(
            f'<p class="ghost">{len(identity)} possible identity link(s) are listed only in the entity details below: '
            "the same handle does not prove identity (P258).</p>"
        )
    return p.section("findings", "Findings", "".join(body), len(other))


# ======================================================================================
# entities
# ======================================================================================


def _entity_map(p: _Page) -> str:
    case = p.case
    seeds = [str(s) for s in _l(case.get("seeds")) if s]
    children: dict[str, list[tuple[str, str, str]]] = defaultdict(list)
    placed = set(seeds)
    for edge in _l(case.get("edges")):
        if not isinstance(edge, dict) or not edge.get("dst"):
            continue
        dst = str(edge["dst"])
        if dst in placed:
            continue
        placed.add(dst)
        children[str(edge.get("src"))].append((dst, clean_text(edge.get("relation") or ""), S.confidence_label(edge)))

    def badge(key: str) -> str:
        text = S.score_text(case, key, show_personal=p.show_personal, no_defang=p.no_defang, idx=p.idx)
        if not text:
            return ""
        level = text.split(":", 1)[0].split(" ", 1)[0]
        return f' <span class="{_risk_class(level)}">[{p.text(text)}]</span>'

    def branch(key: str, depth: int) -> str:
        kids = children.get(key, [])
        if not kids or depth > 6:
            return ""
        items = []
        for child, rel, conf in kids:
            possible = ' <span class="ghost">(possible link)</span>' if conf == "possible" else ""
            items.append(f'<li><span class="rel">{e(rel)} →</span> {p.ent(child)}{badge(child)}{possible}{branch(child, depth + 1)}</li>')
        return "<ul>" + "".join(items) + "</ul>"

    tree = ['<ul class="tree">']
    for seed in seeds:
        tree.append(f"<li><b>{p.ent(seed)}</b>{badge(seed)}{branch(seed, 1)}</li>")
    tree.append("</ul>")
    return p.section("entity-map", "Entity map", "".join(tree))


def _value_html(p: _Page, value: Any) -> str:
    """An attribute value as text: never a link (entity-derived URLs stay plain, defanged)."""
    if isinstance(value, (list, tuple)):
        parts = [_value_html(p, x) for x in value[:40]]
        more = f' <span class="ghost">(+{len(value) - 40})</span>' if len(value) > 40 else ""
        return ", ".join(parts) + more
    if isinstance(value, dict):
        return p.text(json.dumps(value, ensure_ascii=False, default=str)[:400])
    return p.text(value)


def _identity_links_of(p: _Page, key: str) -> list[dict[str, Any]]:
    items = [f for f in p.idx.by_entity.get(key, ()) if S.is_identity_link(f)]
    items += [c for c in _l(p.case.get("correlations")) if isinstance(c, dict) and S.is_identity_link(c) and key in {str(k) for k in _l(c.get("entities"))}]
    return items


def _entities(p: _Page) -> str:
    case = p.case
    nodes = [n for n in _l(case.get("entities")) if isinstance(n, dict) and n.get("key")]
    disclosed = S.disclosure_by_entity(case)
    out = []
    for node in sorted(nodes, key=lambda x: (not x.get("seed"), _depth(x), str(x.get("type")), str(x.get("value")))):
        key = str(node["key"])
        attrs = _d(node.get("attributes"))
        flags = (' <span class="ghost">(seed)</span>' if node.get("seed") else "") + (' <span class="ghost">(common infrastructure)</span>' if node.get("noise") else "")
        score = S.score_text(case, key, show_personal=p.show_personal, no_defang=p.no_defang, idx=p.idx)
        score_html = f' <span class="{_risk_class(score.split(":", 1)[0].split(" ", 1)[0])}">[{p.text(score)}]</span>' if score else ""
        sources = ", ".join(clean_text(x) for x in _l(node.get("sources")))[:120]
        out.append(f'<details{" open" if node.get("seed") else ""}><summary>{p.ent(key)}{score_html}{flags} <span class="ghost">depth {e(node.get("depth", 0))} · {e(sources)}</span></summary>')
        seen = S.sighting_lines(case, key, idx=p.idx)
        if seen:  # internal sightings first (P375 cond 6, A12)
            out.append('<div class="notice"><b>internal sightings:</b> ' + "; ".join(e(x) for x in seen) + "</div>")
        if attrs:
            out.append("<table><tr><th>fact</th><th>value</th><th>source</th></tr>")
            for name, vals in attrs.items():
                if name in ("sightings", "internal_sightings"):
                    continue
                for item in _l(vals)[:4]:
                    if not isinstance(item, dict):
                        continue
                    out.append(f'<tr><td class="muted">{e(clean_text(name))}</td><td>{_value_html(p, item.get("value"))}</td><td class="mod">{e(clean_text(item.get("source") or ""))}</td></tr>')
            out.append("</table>")
        links = _identity_links_of(p, key)
        if links:
            out.append('<div class="desc">possible identity links (the same handle does not prove identity; analyst validation needed):</div><ul>')
            for item in links:
                evidence = "; ".join(display_text(x, show_personal=p.show_personal) for x in _l(item.get("evidence"))[:6])
                crit = item.get("criterion") or ""
                out.append(
                    f'<li><span class="conf possible">POSSIBLE</span> {p.text(item.get("title") or "?")}'
                    + (f' <span class="crit">criterion: {p.text(crit)}</span>' if crit else "")
                    + (f' <span class="desc">evidence: {e(evidence)}</span>' if evidence else "")
                    + "</li>"
                )
            out.append("</ul>")
        if disclosed.get(key):
            out.append(f'<div class="desc">value sent to: {e(", ".join(disclosed[key]))}</div>')
        out.append("</details>")
    return p.section("entities", "Entities and facts", "".join(out), len(nodes))


def _timeline(p: _Page) -> str:
    tl = [ev for ev in _l(p.case.get("timeline")) if isinstance(ev, dict)]
    if not tl:
        return ""
    out = ["<table><tr><th>date</th><th>entity</th><th>event</th><th>source</th></tr>"]
    for ev in tl:
        ent = p.ent(str(ev.get("entity"))) if ev.get("entity") else "-"
        out.append(f'<tr><td style="color:var(--cyan)">{e(clean_text(ev.get("date") or ""))}</td><td>{ent}</td><td>{p.text(ev.get("event") or "")}</td><td class="mod">{e(clean_text(ev.get("source") or ""))}</td></tr>')
    out.append("</table>")
    return p.section("timeline", "Timeline", "".join(out), len(tl))


# ======================================================================================
# manual pivots (P311)
# ======================================================================================


def pivot_items_html(p: _Page, items: list[S.PivotItem], *, filterable: bool = False) -> str:
    """The list items of manual pivots (shared with the pivot page; ``filterable`` marks them for the
    page's filter box)."""
    row = " data-row" if filterable else ""
    out = []
    for it in items:
        label = e(it.label)
        extras = []
        if it.badge:
            extras.append(f'<span class="linkwarn">[{e(it.badge)}]</span>')
        if it.manual:
            extras.append(f'<span class="ghost">({e(it.note or "manual lookup")})</span>')
        if it.href and safe_href(it.href):
            link = f'<a href="{e(it.href)}" rel="noreferrer noopener" target="_blank">{label}</a>'
            out.append(f'<li{row}>{link} {" ".join(extras)} <span class="ghost">{e(it.href[:160])}</span></li>')
        else:
            warn = f' <span class="linkwarn">{e(it.warning)}</span>' if it.warning else ""
            out.append(f'<li{row}>{label} {" ".join(extras)} <span class="defanged">{e(it.text[:300])}</span>{warn}</li>')
    return "".join(out)


def pivot_body(p: _Page, plan: S.PivotPlan, *, filterable: bool = False) -> str:
    """The body of a manual-pivot listing (report section and pivot page)."""
    out = []
    if plan.clickable:
        out.append('<div class="warn">Opening these links contacts third-party websites from your browser (they see your IP and the value). V3LUM never fetches them. Use your OPSEC setup.</div>')
    else:
        out.append(f'<div class="warn">At {e(S.tlp_label(p.case))} manual pivots are not clickable: opening one sends the value to its host. V3LUM never fetches them.</div>')
    for ent in plan.entities:
        out.append(f'<details{" open" if ent.seed else ""}><summary>{p.ent(ent.key)} <span class="ghost">({ent.count} links)</span></summary>')
        for cat, items in ent.groups:
            visible = [i for i in items if not i.collapsed]
            collapsed = [i for i in items if i.collapsed]
            out.append(f"<h3>{e(_CATEGORY_TITLES.get(cat, cat))}</h3><ul>{pivot_items_html(p, visible, filterable=filterable)}</ul>")
            if collapsed:
                out.append(
                    f'<details><summary class="linkwarn">{len(collapsed)} target-contact link(s) of a hostile entity (expand to show, defanged)</summary>'
                    f"<ul>{pivot_items_html(p, collapsed, filterable=filterable)}</ul></details>"
                )
        out.append("</details>")
    notes = []
    if plan.hidden_red:
        notes.append(f"{plan.hidden_red} third-party manual pivot(s) omitted at {S.tlp_label(p.case)}: only `v3lum links <input>` shows them, with the disclosure warning")
    if plan.hidden_privacy:
        notes.append(f"{plan.hidden_privacy} personal-data link(s) omitted (analyst-typed seeds only, with --show-personal)")
    if plan.hidden_hostile:
        notes.append(f"{plan.hidden_hostile} target-contact link(s) of hostile entities omitted")
    if plan.dropped:
        notes.append(f"{plan.dropped} link(s) dropped: not an http(s) URL")
    out += [f'<p class="ghost">{e(n)}</p>' for n in notes]
    return "".join(out)


def _pivots(p: _Page) -> str:
    plan = S.pivot_plan(p.case, show_personal=p.show_personal, no_defang=p.no_defang, full=True)
    if not plan.entities and not (plan.hidden_red or plan.hidden_privacy or plan.dropped):
        return ""
    return p.section("pivots", "Manual pivots", pivot_body(p, plan), plan.count)


# ======================================================================================
# coverage, appendices, evidence, notes, footer
# ======================================================================================


def _coverage(p: _Page) -> str:
    case = p.case
    out = []
    lines = S.skip_lines(case) + S.followup_lines(case)
    if lines:
        out.append("<ul>" + "".join(f"<li>{p.text(x)}</li>" for x in lines) + "</ul>")
    lic = S.appendix_licence(case)
    if lic["allow_entries"]:
        out.append("<h3>licence allow-list entries used (A1)</h3><ul>")
        out += [f"<li>{e(a['source'])} ({e(a['class'])}): legal reference {e(a['legal_ref'])}</li>" for a in lic["allow_entries"]]
        out.append("</ul>")
    if lic["deferred"]:
        out.append("<h3>deferred lookups (provider quota)</h3><ul>" + "".join(f"<li>{e(x)}</li>" for x in lic["deferred"]) + "</ul>")
    eng = S.engagement_details(case, show_personal=p.show_personal, no_defang=p.no_defang)
    if eng["touched"]:  # A7: targets touched with their request counts
        out.append("<h3>targets touched (engagement)</h3><table><tr><th>target</th><th>requests</th></tr>")
        out += [f'<tr><td class="defanged">{e(t)}</td><td>{e(n)}</td></tr>' for t, n in eng["touched"]]
        out.append("</table>")
    if eng["refusals"] or eng["omitted"]:  # A7: every out-of-scope refusal with its reason
        out.append(f"<h3>out-of-scope refusals ({len(eng['refusals']) + eng['omitted']})</h3><ul>")
        out += [f"<li>{p.text(x)}</li>" for x in eng["refusals"]]
        if eng["omitted"]:
            out.append(f'<li class="muted">+{e(eng["omitted"])} more refusals not kept by the engine (see the case audit)</li>')
        out.append("</ul>")
    cov = _d(case.get("coverage"))
    out.append("<table><tr><th>module</th><th>status</th><th>reason code</th><th>runs</th><th>note</th></tr>")
    feeds = []
    for name, info in sorted(cov.items()):
        info = _d(info)
        st = str(info.get("status") or "")
        st = st if st in _STATUSES else "not_run"
        out.append(
            f'<tr><td class="mod">{e(clean_text(name))}</td><td class="st-{st}">{e(st)}</td><td>{e(clean_text(info.get("reason_code") or ""))}</td>'
            f'<td>{e(info.get("runs", 0))}</td><td class="muted">{p.text(info.get("reason") or "")}</td></tr>'
        )
        for sid, row in sorted(_d(info.get("sources")).items()):
            row = _d(row)
            if str(row.get("status") or "") not in ("ok", "empty"):
                feeds.append((f"{clean_text(name)}/{clean_text(sid)}", clean_text(row.get("status") or ""), clean_text(row.get("reason_code") or ""), row.get("reason") or ""))
    out.append("</table>")
    if feeds:
        out.append("<h3>feeds of aggregators that did not answer (could not verify, never absent)</h3><table><tr><th>feed</th><th>status</th><th>reason code</th><th>note</th></tr>")
        out += [f'<tr><td class="mod">{e(n)}</td><td>{e(s)}</td><td>{e(c)}</td><td class="muted">{p.text(r)}</td></tr>' for n, s, c, r in feeds]
        out.append("</table>")
    return p.section("coverage", "Source coverage", "".join(out))


def _appendix_licence(p: _Page) -> str:
    lic = S.appendix_licence(p.case)
    out = [f'<p class="muted">licence profile {e(lic["profile"])}</p>']
    if lic["banner"]:
        out.append(f'<div class="warn">{e(lic["banner"])}</div>')
    if lic["skipped_line"]:
        out.append(f"<p>{e(lic['skipped_line'])}</p>")
    if lic["lost"]:
        out.append("<ul>" + "".join(f"<li>{e(x)}</li>" for x in lic["lost"]) + "</ul>")
    else:
        out.append('<p class="muted">No coverage was lost to the licence profile in this run.</p>')
    if lic["used"]:
        out.append("<h3>noncommercial/license sources used</h3><ul>" + "".join(f"<li>{e(u['source'])} ({e(u['class'])}, {e(u['basis'])})</li>" for u in lic["used"]) + "</ul>")
    return p.section("appendix-licence", "Appendix: Coverage lost under licence profile", "".join(out))


def _appendix_disclosure(p: _Page) -> str:
    app = S.appendix_disclosure(p.case, show_personal=p.show_personal, no_defang=p.no_defang)
    out = [f"<p>{e(app['line'])}</p>"]
    if app["hosts"]:
        out.append("<table><tr><th>host contacted</th><th>provider</th><th>tier</th><th>terms</th><th>requests</th><th>role</th></tr>")
        for row in app["hosts"]:
            out.append(
                f'<tr><td class="mod">{e(row["host"])}</td><td>{e(row["name"] or row["provider"])}</td><td>{e(row["tier"])}</td>'
                f'<td>{e(row["terms"])}</td><td>{e(row["requests"])}</td><td>{e(row["role"])}</td></tr>'
            )
        out.append("</table>")
    if app["by_entity"]:
        out.append("<h3>who received each value</h3><ul>")
        out += [f"<li>{e(who)}: {e(', '.join(names))}</li>" for who, names in app["by_entity"]]
        out.append("</ul>")
    return p.section("appendix-disclosure", "Appendix: Disclosure ledger", "".join(out), len(app["hosts"]))


def evidence_manifest(case: dict[str, Any]) -> list[tuple[str, str, str]]:
    """``[(file, sha256, module)]`` of the case's evidence: the case directory's evidence index
    (``core.evidence.manifest``) when it exists, else the module results' evidence hashes. Paths are
    relative to the case directory (never the analyst's home path)."""
    case_dir = str(case.get("case_dir") or "")
    modules_by_file: dict[str, str] = {}
    for m in _l(case.get("modules")):
        if isinstance(m, dict) and m.get("evidence"):
            modules_by_file[os.path.basename(str(m["evidence"]))] = clean_text(m.get("module") or "")
    if case_dir and Path(case_dir).is_dir():
        try:
            from v3lum.core.evidence import manifest

            rows = manifest(case_dir)
        except Exception:  # noqa: BLE001 - a broken index never breaks a report (cases verify reports it)
            rows = []
        if rows:
            return [(clean_text(f), clean_text(h), modules_by_file.get(os.path.basename(f), "")) for f, h in rows]
    out = []
    for m in _l(case.get("modules")):
        if isinstance(m, dict) and m.get("evidence_sha256"):
            path = str(m.get("evidence") or "")
            rel = os.path.relpath(path, case_dir) if case_dir and path.startswith(case_dir) else os.path.basename(path)
            out.append((clean_text(rel), clean_text(m["evidence_sha256"]), clean_text(m.get("module") or "")))
    return out


def _evidence(p: _Page) -> str:
    rows = evidence_manifest(p.case)
    if not rows:
        return p.section("evidence", "Evidence manifest", '<p class="muted">No evidence files were recorded for this case (--no-evidence or nothing collected).</p>', 0)
    out = ['<p class="muted">Sanitized evidence files of the case directory with their SHA-256 (v3lum cases verify recomputes them).</p>']
    out.append("<table><tr><th>file</th><th>sha-256</th><th>module</th></tr>")
    out += [f'<tr><td class="ghost">{e(f)}</td><td><code>{e(h)}</code></td><td class="mod">{e(m)}</td></tr>' for f, h, m in rows]
    out.append("</table>")
    return p.section("evidence", "Evidence manifest", "".join(out), len(rows))


def _notes(p: _Page) -> str:
    notes = S.note_lines(p.case, show_personal=p.show_personal)
    if not notes:
        return ""
    return p.section("notes", "Notes", "".join(f'<div class="warn">{p.text(n)}</div>' for n in notes))


def _footer_head(p: _Page) -> str:
    out = [f"<footer>{p.mark}<div class=\"tlpdesc\">{e(S.tlp_description(p.case))}</div>"]
    atts = S.attributions(p.case)
    if atts:
        out.append(f"<details><summary>Attributions and licences of the sources and datasets used ({len(atts)})</summary><ul>")
        for a in atts:
            src = safe_href(a.get("source_url") or "")
            url = f' <span class="ghost">{e(src)}</span>' if src else ""
            out.append(f"<li><b>{e(a['name'])}</b> ({e(a['licence'] or 'licence not recorded')}): {e(a['text'])}{url}</li>")
        out.append("</ul></details>")
    out.append(f"<p>Generated by V3LUM - passive by default; findings are leads, not verdicts: verify before acting. Scores are a {e(S.SCORE_LABEL)}.</p>")
    out.append(f"<div>{p.badge}</div>")
    return "".join(out)
