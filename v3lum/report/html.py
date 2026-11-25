"""Self-contained HTML report (dark theme).

Rules: no external resources of any kind (fonts, scripts, images, CSS) so opening the
report never contacts a third party or the target. All values are HTML-escaped.
"""

from __future__ import annotations

import html
import json
from collections import defaultdict
from typing import Any

CSS = """
:root{--bg:#07090a;--panel:#0d1114;--panel2:#11171b;--line:#1d272d;--text:#d6e2e4;--dim:#7d8b94;--ghost:#4a555c;
--neon:#00ff9f;--acid:#b4ff39;--violet:#bd5cff;--magenta:#ff3caa;--cyan:#00d7ff;--amber:#ffb000;--orange:#ff6b2b;--blood:#ff2e4d}
*{box-sizing:border-box}html,body{margin:0;background:var(--bg);color:var(--text);
font:14px/1.5 ui-monospace,SFMono-Regular,Menlo,Consolas,"Liberation Mono",monospace}
body{background-image:repeating-linear-gradient(0deg,rgba(255,255,255,.012) 0 1px,transparent 1px 3px)}
a{color:var(--cyan)}a:hover{color:var(--neon)}
.wrap{max-width:1280px;margin:0 auto;padding:24px 18px 60px}
header{border:1px solid var(--line);background:linear-gradient(135deg,#0b1012,#0f0b16);padding:22px 24px;border-radius:6px;position:relative;overflow:hidden}
header:after{content:"";position:absolute;inset:0;background:linear-gradient(90deg,transparent,rgba(189,92,255,.06),transparent);pointer-events:none}
.logo{font-weight:800;letter-spacing:.35em;font-size:28px;color:var(--neon);text-shadow:0 0 12px rgba(0,255,159,.35),2px 0 var(--magenta)}
.tag{color:var(--violet);margin-top:2px}.muted{color:var(--dim)}.ghost{color:var(--ghost)}
.grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(180px,1fr));gap:10px;margin-top:16px}
.kpi{background:var(--panel);border:1px solid var(--line);border-radius:4px;padding:10px 12px}.kpi b{display:block;font-size:20px;color:var(--text)}
.kpi span{color:var(--dim);font-size:12px;text-transform:uppercase;letter-spacing:.08em}
.gauge{margin-top:16px;height:14px;background:#0a0f11;border:1px solid var(--line);border-radius:2px;overflow:hidden}
.gauge i{display:block;height:100%}
section{margin-top:26px}h2{font-size:15px;letter-spacing:.18em;text-transform:uppercase;color:var(--neon);border-bottom:1px solid var(--line);padding-bottom:6px}
h2 small{color:var(--ghost);letter-spacing:0;text-transform:none;font-weight:normal}
table{width:100%;border-collapse:collapse;background:var(--panel);border:1px solid var(--line)}
th,td{padding:7px 10px;border-bottom:1px solid var(--line);vertical-align:top;text-align:left}
th{color:var(--dim);font-weight:normal;text-transform:uppercase;font-size:11px;letter-spacing:.08em;background:var(--panel2)}
tr:hover td{background:#10161a}
.sev{display:inline-block;min-width:74px;text-align:center;padding:1px 6px;border-radius:2px;font-size:11px;font-weight:700;letter-spacing:.06em;text-transform:uppercase}
.sev.info{color:var(--cyan);border:1px solid rgba(0,215,255,.4)}.sev.low{color:var(--acid);border:1px solid rgba(180,255,57,.4)}
.sev.medium{color:#000;background:var(--amber)}.sev.high{color:#000;background:var(--orange)}.sev.critical{color:#fff;background:var(--blood);box-shadow:0 0 10px rgba(255,46,77,.5)}
.risk-clean{color:var(--neon)}.risk-low{color:var(--acid)}.risk-medium{color:var(--amber)}.risk-high{color:var(--orange)}.risk-critical{color:var(--blood)}
.ent{color:var(--cyan);word-break:break-all}.typ{color:var(--violet)}.mod{color:var(--acid)}
.desc{color:var(--dim);font-size:12.5px;margin-top:3px}
.toolbar{display:flex;gap:8px;flex-wrap:wrap;margin:10px 0}
.toolbar button,.toolbar input{background:var(--panel);color:var(--text);border:1px solid var(--line);padding:5px 10px;border-radius:3px;font:inherit}
.toolbar button.on{border-color:var(--neon);color:var(--neon)}
.toolbar input{flex:1;min-width:200px}
ul.tree,ul.tree ul{list-style:none;margin:0;padding-left:18px;border-left:1px dashed var(--line)}
ul.tree{padding-left:6px;border:0}ul.tree li{margin:2px 0}.rel{color:var(--ghost)}
details{background:var(--panel);border:1px solid var(--line);border-radius:4px;margin:6px 0;padding:6px 10px}
summary{cursor:pointer;color:var(--text)}code{color:var(--acid);word-break:break-all}
.warn{border-left:3px solid var(--amber);padding:6px 12px;background:#15120a;color:var(--amber);margin:8px 0}
footer{margin-top:40px;color:var(--ghost);font-size:12px;text-align:center}
.st-ok{color:var(--neon)}.st-empty{color:var(--dim)}.st-error{color:var(--blood)}.st-needs_key,.st-rate_limited{color:var(--amber)}.st-blocked{color:var(--magenta)}.st-skipped,.st-unavailable,.st-not_run{color:var(--ghost)}
@media print{body{background:#fff;color:#000}header,table,.kpi,details{background:#fff}}
"""

JS = """
(function(){var q=document.getElementById('q');var btns=document.querySelectorAll('[data-sev]');var active='all';
function apply(){var term=(q.value||'').toLowerCase();document.querySelectorAll('tr[data-row]').forEach(function(r){
var okSev=active==='all'||r.getAttribute('data-sevv')===active;var okTxt=!term||r.textContent.toLowerCase().indexOf(term)>=0;
r.style.display=(okSev&&okTxt)?'':'none';});}
btns.forEach(function(b){b.addEventListener('click',function(){active=b.getAttribute('data-sev');btns.forEach(function(x){x.classList.toggle('on',x===b)});apply();});});
if(q){q.addEventListener('input',apply);}})();
"""

RISK_COLORS = {"clean": "#00ff9f", "low": "#b4ff39", "medium": "#ffb000", "high": "#ff6b2b", "critical": "#ff2e4d"}


def e(value: Any) -> str:
    return html.escape("" if value is None else str(value), quote=True)


def _ent(key: str, ents: dict[str, dict[str, Any]]) -> str:
    node = ents.get(key)
    if node:
        return f'<span class="typ">{e(node["type"])}:</span><span class="ent">{e(node.get("display") or node["value"])}</span>'
    t, _, v = key.partition(":")
    return f'<span class="typ">{e(t)}:</span><span class="ent">{e(v)}</span>'


def _value(v: Any) -> str:
    if isinstance(v, (list, tuple)):
        parts = [_value(x) for x in v[:40]]
        more = f' <span class="ghost">(+{len(v) - 40})</span>' if len(v) > 40 else ""
        return ", ".join(parts) + more
    if isinstance(v, dict):
        if "url" in v and isinstance(v["url"], str) and v["url"].startswith(("http://", "https://")):
            label = v.get("platform") or v.get("name") or v["url"]
            return f'<a href="{e(v["url"])}" rel="noreferrer noopener" target="_blank">{e(label)}</a>'
        return e(json.dumps(v, ensure_ascii=False, default=str)[:400])
    return e(v)


def render(case: dict[str, Any]) -> str:
    s = case.get("summary", {})
    ents = {x["key"]: x for x in case.get("entities", [])}
    level = s.get("risk_level", "clean")
    score = float(s.get("risk_score", 0))
    out: list[str] = []
    out.append("<!doctype html><html lang=\"en\"><head><meta charset=\"utf-8\">")
    out.append('<meta name="viewport" content="width=device-width,initial-scale=1">')
    out.append('<meta name="referrer" content="no-referrer">')
    out.append("<meta http-equiv=\"Content-Security-Policy\" content=\"default-src 'none'; style-src 'unsafe-inline'; script-src 'unsafe-inline'; img-src data:\">")
    out.append(f"<title>V3LUM case {e(case['case_id'])}</title><style>{CSS}</style></head><body><div class=\"wrap\">")

    # header
    out.append("<header>")
    out.append('<div class="logo">V3LUM</div><div class="tag">lift the veil :: osint · cti · recon</div>')
    out.append(f'<div class="muted" style="margin-top:10px">case <b style="color:var(--neon)">{e(case["case_id"])}</b> · {e(case.get("created", ""))} · V3LUM {e(case.get("tool", {}).get("version", ""))}</div>')
    for inp in case.get("inputs", []) or []:
        out.append(f'<div>input <span class="typ">{e(inp["type"])}:</span><span class="ent">{e(str(inp["value"])[:300])}</span> <span class="ghost">{e(inp.get("reason", ""))}</span></div>')
    opts = case.get("options", {})
    out.append(f'<div class="muted">mode <b>{e(opts.get("mode"))}</b> · depth {e(opts.get("depth"))}' + (' · <b style="color:var(--amber)">AUTHORIZED ACTIVE TESTING</b>' if opts.get("authorized") else "") + "</div>")
    out.append('<div class="grid">')
    kpis = [
        (f'<span class="risk-{e(level)}">{score:.0f}/100 {e(level.upper())}</span>', "risk"),
        (s.get("entities", 0), "entities"),
        (s.get("findings", 0), "findings"),
        (s.get("correlations", 0), "correlations"),
        (s.get("module_runs", 0), "module runs"),
        (f'{s.get("duration", 0)}s', "duration"),
    ]
    for val, label in kpis:
        out.append(f'<div class="kpi"><b>{val}</b><span>{e(label)}</span></div>')
    out.append("</div>")
    out.append(f'<div class="gauge"><i style="width:{max(1.0, score):.1f}%;background:{RISK_COLORS.get(level, "#00ff9f")}"></i></div>')
    out.append("</header>")

    # correlations
    corrs = case.get("correlations", [])
    out.append(f"<section><h2>Cross-referenced intelligence <small>({len(corrs)})</small></h2>")
    if corrs:
        out.append("<table><tr><th>severity</th><th>conclusion</th><th>entities</th><th>recommendation</th></tr>")
        for c in corrs:
            ents_html = "<br>".join(_ent(k, ents) for k in c.get("entities", [])[:8])
            out.append(
                f'<tr><td><span class="sev {e(c["severity"])}">{e(c["severity"])}</span></td>'
                f'<td><b>{e(c["title"])}</b><div class="desc">{e(c.get("description", ""))}</div></td>'
                f"<td>{ents_html}</td><td class=\"muted\">{e(c.get('recommendation', ''))}</td></tr>"
            )
        out.append("</table>")
    else:
        out.append('<p class="muted">No cross-source conclusions were reached.</p>')
    out.append("</section>")

    # findings
    findings = case.get("findings", [])
    out.append(f"<section><h2>Findings <small>({len(findings)})</small></h2>")
    out.append('<div class="toolbar"><button class="on" data-sev="all">all</button>')
    for sev in ("critical", "high", "medium", "low", "info"):
        n = sum(1 for f in findings if f["severity"] == sev)
        if n:
            out.append(f'<button data-sev="{sev}">{sev} ({n})</button>')
    out.append('<input id="q" placeholder="filter findings, entities, sources..."></div>')
    out.append("<table><tr><th>severity</th><th>entity</th><th>finding</th><th>source</th><th>conf.</th></tr>")
    for f in findings:
        refs = "".join(f' <a href="{e(r)}" rel="noreferrer noopener" target="_blank">[ref]</a>' for r in f.get("references", [])[:3] if str(r).startswith(("http://", "https://")))
        data = ""
        if f.get("data"):
            data = f'<details><summary class="ghost">data</summary><code>{e(json.dumps(f["data"], ensure_ascii=False, default=str)[:3000])}</code></details>'
        out.append(
            f'<tr data-row data-sevv="{e(f["severity"])}"><td><span class="sev {e(f["severity"])}">{e(f["severity"])}</span></td>'
            f'<td>{_ent(f["entity"], ents) if f.get("entity") else "-"}</td>'
            f'<td>{e(f["title"])}{refs}<div class="desc">{e(f.get("description", ""))}</div>{data}</td>'
            f'<td class="mod">{e(f["module"])}</td><td class="muted">{e(f.get("confidence", ""))}</td></tr>'
        )
    out.append("</table></section>")

    # entity tree
    out.append("<section><h2>Entity map</h2>")
    children: dict[str, list[tuple[str, str]]] = defaultdict(list)
    placed = set(case.get("seeds", []))
    for edge in case.get("edges", []):
        if edge["dst"] in placed:
            continue
        placed.add(edge["dst"])
        children[edge["src"]].append((edge["dst"], edge["relation"]))
    risk = case.get("risk", {}).get("entities", {})

    def branch(key: str, depth: int) -> str:
        kids = children.get(key, [])
        if not kids or depth > 6:
            return ""
        items = []
        for child, rel in kids:
            r = risk.get(child)
            badge = f' <span class="risk-{e(r["level"])}">[{e(r["level"])} {r["score"]:.0f}]</span>' if r else ""
            items.append(f'<li><span class="rel">{e(rel)} →</span> {_ent(child, ents)}{badge}{branch(child, depth + 1)}</li>')
        return "<ul>" + "".join(items) + "</ul>"

    out.append('<ul class="tree">')
    for seed in case.get("seeds", []):
        r = risk.get(seed)
        badge = f' <span class="risk-{e(r["level"])}">[{e(r["level"])} {r["score"]:.0f}]</span>' if r else ""
        out.append(f"<li><b>{_ent(seed, ents)}</b>{badge}{branch(seed, 1)}</li>")
    out.append("</ul></section>")

    # entities + facts
    out.append(f"<section><h2>Entities & facts <small>({len(ents)})</small></h2>")
    for node in sorted(case.get("entities", []), key=lambda x: (not x.get("seed"), x["depth"], x["type"], x["value"])):
        attrs = node.get("attributes") or {}
        r = risk.get(node["key"])
        badge = f' <span class="risk-{e(r["level"])}">[{e(r["level"])} {r["score"]:.0f}]</span>' if r else ""
        flags = (" <span class=\"ghost\">(seed)</span>" if node.get("seed") else "") + (" <span class=\"ghost\">(common infrastructure)</span>" if node.get("noise") else "")
        out.append(f'<details{" open" if node.get("seed") else ""}><summary>{_ent(node["key"], ents)}{badge}{flags} <span class="ghost">depth {node["depth"]} · {e(", ".join(node.get("sources", []))[:120])}</span></summary>')
        if attrs:
            out.append("<table><tr><th>fact</th><th>value</th><th>source</th></tr>")
            for k, vals in attrs.items():
                for item in vals[:4]:
                    out.append(f'<tr><td class="muted">{e(k)}</td><td>{_value(item["value"])}</td><td class="mod">{e(item["source"])}</td></tr>')
            out.append("</table>")
        out.append("</details>")
    out.append("</section>")

    # timeline
    tl = case.get("timeline", [])
    if tl:
        out.append(f"<section><h2>Timeline <small>({len(tl)})</small></h2><table><tr><th>date</th><th>entity</th><th>event</th><th>source</th></tr>")
        for ev in tl:
            out.append(f'<tr><td style="color:var(--cyan)">{e(ev["date"])}</td><td>{_ent(ev["entity"], ents)}</td><td>{e(ev["event"])}</td><td class="mod">{e(ev.get("source", ""))}</td></tr>')
        out.append("</table></section>")

    # manual pivots
    links = case.get("links", {})
    if links:
        out.append("<section><h2>Manual pivots</h2>")
        out.append('<div class="warn">Opening these links contacts third-party websites from your browser (they will see your IP and the searched value). Use your OPSEC setup.</div>')
        for key, items in links.items():
            out.append(f"<details><summary>{_ent(key, ents)} <span class=\"ghost\">({len(items)} links)</span></summary><ul>")
            for item in items:
                out.append(f'<li><a href="{e(item["url"])}" rel="noreferrer noopener" target="_blank">{e(item["label"])}</a> <span class="ghost">{e(item["url"][:120])}</span></li>')
            out.append("</ul></details>")
        out.append("</section>")

    # coverage + evidence
    out.append("<section><h2>Source coverage & evidence</h2><table><tr><th>module</th><th>status</th><th>runs</th><th>note</th></tr>")
    for name, info in sorted(case.get("coverage", {}).items()):
        st = info.get("status", "")
        out.append(f'<tr><td class="mod">{e(name)}</td><td class="st-{e(st)}">{e(st)}</td><td>{e(info.get("runs", 0))}</td><td class="muted">{e(info.get("reason", ""))}</td></tr>')
    out.append("</table>")
    ev = [m for m in case.get("modules", []) if m.get("evidence_sha256")]
    if ev:
        out.append(f"<details><summary>Evidence files ({len(ev)}) — raw responses with SHA-256</summary><table><tr><th>sha-256</th><th>module</th><th>entity</th><th>file</th></tr>")
        for m in ev:
            out.append(f'<tr><td><code>{e(m["evidence_sha256"])}</code></td><td class="mod">{e(m["module"])}</td><td>{_ent(m["entity"], ents)}</td><td class="ghost">{e(m.get("evidence", ""))}</td></tr>')
        out.append("</table></details>")
    out.append("</section>")

    for note in case.get("notes", []):
        out.append(f'<div class="warn">{e(note)}</div>')
    out.append('<footer>Generated by V3LUM — passive by default; findings are leads, not verdicts: verify before acting.</footer>')
    out.append(f"</div><script>{JS}</script></body></html>")
    return "".join(out)
