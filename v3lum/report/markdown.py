"""Markdown report (tickets, wikis, chat)."""

from __future__ import annotations

from typing import Any


def _esc(text: Any) -> str:
    return str(text).replace("|", "\\|").replace("\n", " ").strip()


def render(case: dict[str, Any]) -> str:
    s = case.get("summary", {})
    ents = {e["key"]: e for e in case.get("entities", [])}

    def ent(key: str) -> str:
        e = ents.get(key)
        return f"`{e['type']}:{e.get('display') or e['value']}`" if e else f"`{key}`"

    out: list[str] = []
    out.append(f"# V3LUM report — case {case['case_id']}")
    out.append("")
    out.append(f"*Generated {case.get('created', '')} by V3LUM {case.get('tool', {}).get('version', '')}*")
    out.append("")
    out.append(f"**Risk: {s.get('risk_level', 'clean').upper()} ({s.get('risk_score', 0)}/100)** · "
               f"{s.get('entities', 0)} entities · {s.get('findings', 0)} findings · {s.get('correlations', 0)} correlations · "
               f"{s.get('module_runs', 0)} module runs · {s.get('duration', 0)}s")
    out.append("")
    out.append("## Inputs")
    out.append("")
    for inp in case.get("inputs", []) or [{"type": k.split(':', 1)[0], "value": k.split(':', 1)[1], "reason": ""} for k in case.get("seeds", [])]:
        out.append(f"- `{inp['type']}:{_esc(inp['value'])[:200]}` {('— ' + _esc(inp['reason'])) if inp.get('reason') else ''}")
    opts = case.get("options", {})
    out.append("")
    out.append(f"Mode `{opts.get('mode')}`, depth `{opts.get('depth')}`" + (", **authorized active testing**" if opts.get("authorized") else ""))
    out.append("")

    corrs = case.get("correlations", [])
    if corrs:
        out.append("## Cross-referenced intelligence")
        out.append("")
        out.append("| Severity | Conclusion | Recommendation |")
        out.append("|---|---|---|")
        for c in corrs:
            out.append(f"| {c['severity'].upper()} | **{_esc(c['title'])}**<br>{_esc(c.get('description', ''))} | {_esc(c.get('recommendation', ''))} |")
        out.append("")

    findings = case.get("findings", [])
    if findings:
        out.append("## Findings")
        out.append("")
        out.append("| Severity | Entity | Finding | Source | Confidence |")
        out.append("|---|---|---|---|---|")
        for f in findings:
            desc = f" — {_esc(f['description'])[:300]}" if f.get("description") else ""
            out.append(f"| {f['severity']} | {ent(f['entity']) if f.get('entity') else '-'} | {_esc(f['title'])}{desc} | {f['module']} | {f.get('confidence', '')} |")
        out.append("")

    out.append("## Entities")
    out.append("")
    out.append("| Entity | Depth | Sources | Risk |")
    out.append("|---|---|---|---|")
    risk = case.get("risk", {}).get("entities", {})
    for e in sorted(case.get("entities", []), key=lambda x: (x["depth"], x["type"], x["value"])):
        r = risk.get(e["key"])
        out.append(f"| {ent(e['key'])}{' (seed)' if e.get('seed') else ''}{' (common infra)' if e.get('noise') else ''} | {e['depth']} | {', '.join(e.get('sources', []))[:80]} | {(r['level'] + ' ' + str(r['score'])) if r else ''} |")
    out.append("")

    if case.get("edges"):
        out.append("## Relations")
        out.append("")
        for edge in case["edges"][:500]:
            out.append(f"- {ent(edge['src'])} **{edge['relation']}** {ent(edge['dst'])} _(via {edge['module']})_")
        out.append("")

    if case.get("timeline"):
        out.append("## Timeline")
        out.append("")
        for ev in case["timeline"]:
            out.append(f"- **{ev['date']}** {ent(ev['entity'])} — {_esc(ev['event'])} _({ev.get('source', '')})_")
        out.append("")

    links = case.get("links", {})
    if links:
        out.append("## Manual pivots")
        out.append("")
        out.append("> Opening these links contacts third-party sites from your browser.")
        out.append("")
        for key, items in links.items():
            out.append(f"**{ent(key)}**")
            out.append("")
            for item in items:
                out.append(f"- [{_esc(item['label'])}]({item['url']})")
            out.append("")

    out.append("## Source coverage")
    out.append("")
    out.append("| Module | Status | Runs | Note |")
    out.append("|---|---|---|---|")
    for name, info in sorted(case.get("coverage", {}).items()):
        out.append(f"| {name} | {info.get('status', '')} | {info.get('runs', 0)} | {_esc(info.get('reason', ''))[:120]} |")
    out.append("")

    ev = [m for m in case.get("modules", []) if m.get("evidence_sha256")]
    if ev:
        out.append("## Evidence (SHA-256)")
        out.append("")
        for m in ev:
            out.append(f"- `{m['evidence_sha256']}` {m['module']} → {ent(m['entity'])}")
        out.append("")

    for note in case.get("notes", []):
        out.append(f"> **Note:** {_esc(note)}")
    out.append("")
    return "\n".join(out)
