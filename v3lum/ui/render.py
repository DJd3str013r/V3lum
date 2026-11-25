"""Render a case (report model dict) in the terminal."""

from __future__ import annotations

from collections import defaultdict
from typing import Any

from rich import box
from rich.console import Console, Group
from rich.panel import Panel
from rich.table import Table
from rich.text import Text
from rich.tree import Tree

from v3lum.ui.theme import SEVERITY_ICON, STATUS_ICON

SEV_ORDER = ["critical", "high", "medium", "low", "info"]


def _ent(key: str, entities: dict[str, dict[str, Any]]) -> Text:
    node = entities.get(key)
    t = Text()
    if node:
        t.append(f"{node['type']}:", style="v.type")
        t.append(str(node.get("display") or node["value"]), style="v.entity")
    else:
        etype, _, value = key.partition(":")
        t.append(f"{etype}:", style="v.type")
        t.append(value, style="v.entity")
    return t


def risk_bar(score: float, level: str, width: int = 30) -> Text:
    filled = int(round(score / 100 * width))
    t = Text()
    t.append(" RISK ", style="v.accent")
    t.append("█" * filled, style=f"risk.{level}" if level != "critical" else "bold #ff2e4d")
    t.append("░" * (width - filled), style="v.ghost")
    t.append(f" {score:5.1f}/100 ", style="v.text")
    t.append(f" {level.upper()} ", style=f"risk.{level}")
    return t


def render_case(console: Console, case: dict[str, Any], *, full: bool = False, max_findings: int = 25) -> None:
    entities = {e["key"]: e for e in case.get("entities", [])}
    s = case.get("summary", {})

    # ---------------------------------------------------------------- header
    head = Table.grid(padding=(0, 2))
    head.add_column(style="v.dim", justify="right")
    head.add_column(style="v.text")
    head.add_row("case", Text(case["case_id"], style="v.title"))
    for inp in case.get("inputs", []) or [{"type": k.split(":", 1)[0], "value": k.split(":", 1)[1], "reason": ""} for k in case.get("seeds", [])]:
        row = Text()
        row.append(f"{inp['type']}:", style="v.type")
        row.append(str(inp["value"])[:90], style="v.entity")
        if inp.get("reason"):
            row.append(f"  ({inp['reason']})", style="v.ghost")
        head.add_row("input", row)
    opts = case.get("options", {})
    head.add_row("mode", f"{opts.get('mode', '?')} · depth {opts.get('depth', '?')}" + (" · AUTHORIZED" if opts.get("authorized") else ""))
    head.add_row(
        "stats",
        f"{s.get('entities', 0)} entities · {s.get('relations', 0)} relations · {s.get('findings', 0)} findings · "
        f"{s.get('module_runs', 0)} module runs · {s.get('requests', 0)} requests ({s.get('cache_hits', 0)} cached) · {s.get('duration', 0)}s",
    )
    console.print(Panel(Group(head, Text(), risk_bar(float(s.get("risk_score", 0)), s.get("risk_level", "clean"))),
                        title="[v.title]▌V3LUM REPORT▐[/]", border_style="v.accent", box=box.HEAVY, padding=(1, 2)))

    # ---------------------------------------------------------------- correlations
    corrs = case.get("correlations", [])
    if corrs:
        t = Table(box=box.SIMPLE_HEAVY, show_header=True, header_style="v.dim", expand=True, title="[v.accent]⟁ cross-referenced intelligence[/]", title_justify="left")
        t.add_column("sev", width=10, no_wrap=True)
        t.add_column("conclusion", ratio=3)
        t.add_column("what to do", ratio=2, style="v.dim")
        for c in corrs[: (None if full else 15)]:
            sev = c["severity"]
            body = Text(c["title"], style="v.text")
            if c.get("description"):
                body.append("\n" + c["description"], style="v.dim")
            t.add_row(Text(f"{SEVERITY_ICON.get(sev, '')} {sev.upper()}", style=f"sev.{sev}"), body, c.get("recommendation", ""))
        console.print(t)
        if not full and len(corrs) > 15:
            console.print(Text(f"  … {len(corrs) - 15} more correlations (use --full or the HTML report)", style="v.ghost"))

    # ---------------------------------------------------------------- findings
    findings = [f for f in case.get("findings", []) if full or f["severity"] != "info"]
    infos = [f for f in case.get("findings", []) if f["severity"] == "info"]
    if findings:
        t = Table(box=box.SIMPLE, show_header=True, header_style="v.dim", expand=True, title="[v.accent]⚑ findings[/]", title_justify="left")
        t.add_column("sev", width=10, no_wrap=True)
        t.add_column("entity", ratio=2, overflow="fold")
        t.add_column("finding", ratio=4)
        t.add_column("source", ratio=1, style="v.module", overflow="fold")
        shown = findings if full else findings[:max_findings]
        for f in shown:
            sev = f["severity"]
            body = Text(f["title"], style="v.text")
            if f.get("description") and (full or sev in ("critical", "high")):
                body.append("\n" + f["description"][:300], style="v.dim")
            t.add_row(Text(f"{SEVERITY_ICON.get(sev, '')} {sev}", style=f"sev.{sev}"), _ent(f["entity"], entities) if f.get("entity") else Text("-"), body, f["module"])
        console.print(t)
        hidden = len(findings) - len(shown)
        if hidden > 0:
            console.print(Text(f"  … {hidden} more findings (use --full or open the HTML report)", style="v.ghost"))
    if infos and not full:
        console.print(Text(f"  ({len(infos)} informational findings hidden — see the HTML/Markdown report)", style="v.ghost"))

    # ---------------------------------------------------------------- entity tree
    console.print(_entity_tree(case, entities, full=full))

    # ---------------------------------------------------------------- facts about seeds
    for key in case.get("seeds", []):
        node = entities.get(key)
        if not node or not node.get("attributes"):
            continue
        t = Table(box=box.MINIMAL, show_header=False, expand=False, title=Text.assemble(("▸ facts: ", "v.accent"), _ent(key, entities)), title_justify="left")
        t.add_column(style="v.dim", no_wrap=True)
        t.add_column(style="v.text", overflow="fold", max_width=90)
        t.add_column(style="v.ghost", overflow="fold")
        for attr, vals in list(node["attributes"].items())[: (None if full else 30)]:
            shown = vals[0]["value"]
            text = _fmt_value(shown)
            srcs = sorted({v["source"] for v in vals})
            t.add_row(attr, text, ", ".join(srcs)[:40])
        console.print(t)

    # ---------------------------------------------------------------- timeline
    tl = case.get("timeline", [])
    if tl:
        t = Table(box=box.SIMPLE, show_header=False, title="[v.accent]⧗ timeline[/]", title_justify="left")
        t.add_column(style="v.info", no_wrap=True)
        t.add_column(overflow="fold")
        t.add_column(style="v.text", overflow="fold")
        for ev in tl[-(len(tl) if full else 15):]:
            t.add_row(ev["date"], _ent(ev["entity"], entities), ev["event"])
        console.print(t)

    # ---------------------------------------------------------------- coverage
    console.print(_coverage(case, full=full))

    # ---------------------------------------------------------------- manual pivots
    links = case.get("links", {})
    seed_links = [(k, v) for k, v in links.items() if k in case.get("seeds", [])]
    if seed_links:
        t = Table(box=box.SIMPLE, show_header=False, title="[v.accent]↗ manual pivots (open in your browser)[/]", title_justify="left")
        t.add_column(style="v.text", no_wrap=True)
        t.add_column(style="v.url", overflow="fold")
        for _key, items in seed_links:
            for item in items[: (None if full else 8)]:
                t.add_row(item["label"], item["url"])
            if not full and len(items) > 8:
                t.add_row(Text(f"+{len(items) - 8} more", style="v.ghost"), Text("v3lum links <input>  or the HTML report", style="v.ghost"))
        console.print(t)

    for note in case.get("notes", []):
        console.print(Text(f"[!] {note}", style="v.warn"))


def _fmt_value(value: Any) -> str:
    if isinstance(value, list):
        items = [str(v.get("platform") or v.get("url") or v) if isinstance(v, dict) else str(v) for v in value]
        text = ", ".join(items[:12]) + (f" … (+{len(items) - 12})" if len(items) > 12 else "")
        return text
    if isinstance(value, dict):
        return ", ".join(f"{k}={v}" for k, v in list(value.items())[:8])
    return str(value)


def _entity_tree(case: dict[str, Any], entities: dict[str, dict[str, Any]], *, full: bool) -> Tree:
    children: dict[str, list[tuple[str, str]]] = defaultdict(list)
    placed = set(case.get("seeds", []))
    for e in case.get("edges", []):
        if e["dst"] in placed:
            continue
        placed.add(e["dst"])
        children[e["src"]].append((e["dst"], e["relation"]))
    risk = case.get("risk", {}).get("entities", {})
    root = Tree(Text("⌬ entity map", style="v.accent"), guide_style="v.ghost")
    limit = None if full else 12

    def label(key: str, relation: str = "") -> Text:
        t = Text()
        if relation:
            t.append(f"{relation} → ", style="v.ghost")
        t.append_text(_ent(key, entities))
        r = risk.get(key)
        if r and r["level"] not in ("clean",):
            t.append(f"  [{r['level']} {r['score']:.0f}]", style=f"risk.{r['level']}")
        node = entities.get(key, {})
        if node.get("noise"):
            t.append("  (common infra)", style="v.ghost")
        return t

    def add(branch: Tree, key: str, depth: int) -> None:
        kids = children.get(key, [])
        for child, rel in kids[:limit]:
            sub = branch.add(label(child, rel))
            if depth < 3:
                add(sub, child, depth + 1)
        if limit and len(kids) > limit:
            branch.add(Text(f"… +{len(kids) - limit} more", style="v.ghost"))

    for seed in case.get("seeds", []):
        b = root.add(label(seed))
        add(b, seed, 1)
    return root


def _coverage(case: dict[str, Any], *, full: bool) -> Table | Text:
    cov = case.get("coverage", {})
    if not cov:
        return Text()
    groups: dict[str, list[str]] = defaultdict(list)
    for name, info in sorted(cov.items()):
        groups[info.get("status", "not_run")].append(name)
    t = Table(box=box.SIMPLE, show_header=False, title="[v.accent]◎ source coverage[/]", title_justify="left", expand=True)
    t.add_column(no_wrap=True, width=16)
    t.add_column(overflow="fold", style="v.dim")
    order = ["ok", "empty", "rate_limited", "blocked", "error", "needs_key", "unavailable", "skipped", "not_run"]
    for st in order:
        names = groups.get(st)
        if not names:
            continue
        label = Text(f"{STATUS_ICON.get(st, '')} {st.replace('_', ' ')} ({len(names)})", style=f"status.{st}")
        if st in ("error", "rate_limited", "blocked", "needs_key") or full:
            detail = ", ".join(f"{n}" + (f" [{cov[n].get('reason', '')[:60]}]" if st in ("error", "needs_key") and cov[n].get("reason") else "") for n in names)
        else:
            detail = ", ".join(names[:25]) + (f" … +{len(names) - 25}" if len(names) > 25 else "")
        t.add_row(label, detail)
    return t


def render_detections(console: Console, raw: str, detections: list[Any]) -> None:
    t = Table(box=box.SIMPLE, show_header=True, header_style="v.dim", title=Text.assemble(("detect ", "v.accent"), (raw[:80], "v.entity")), title_justify="left")
    t.add_column("type", style="v.type")
    t.add_column("normalized value", style="v.entity", overflow="fold")
    t.add_column("confidence", justify="right")
    t.add_column("why", style="v.dim")
    for d in detections:
        conf_style = "v.ok" if d.confidence >= 0.75 else "v.warn" if d.confidence >= 0.5 else "v.dim"
        t.add_row(d.type.value, d.value if d.type.value != "text_blob" else f"{len(d.value)} chars", Text(f"{d.confidence:.2f}", style=conf_style), d.reason)
    console.print(t)
