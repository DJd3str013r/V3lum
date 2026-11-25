"""Application layer shared by the command line (cli.py) and the interactive shell (shell.py)."""

from __future__ import annotations

import getpass
import json
import os
import platform
import sys
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from rich import box
from rich.console import Console
from rich.panel import Panel
from rich.prompt import Confirm, Prompt
from rich.table import Table
from rich.text import Text

from v3lum import __version__, paths
from v3lum.config import KNOWN_KEYS, Config, mask
from v3lum.core import detect as det
from v3lum.core.context import Runtime, ScanOptions
from v3lum.core.datasets import DATASETS
from v3lum.core.engine import Engine
from v3lum.core.entities import Entity, EntityType, defang
from v3lum.core.models import Opsec, Status
from v3lum.core.module import CATEGORIES, REGISTRY, get_module, load_errors, load_modules, package_available, readiness
from v3lum.core.store import Store
from v3lum.report import FORMATS, write_reports
from v3lum.ui.live import LiveFeed
from v3lum.ui.render import render_case, render_detections

TOR_PROXY = os.environ.get("V3LUM_TOR_PROXY", "socks5h://127.0.0.1:9050")
LEVEL_ORDER = ["clean", "low", "medium", "high", "critical"]


class UserError(Exception):
    """A problem the analyst can fix (bad input, missing flag...). Printed without a traceback."""


@dataclass
class ScanRequest:
    inputs: list[str]
    etype: EntityType | None = None
    mode: Opsec = Opsec.PASSIVE
    authorized: bool = False
    authorization_note: str = ""
    depth: int = 1
    include: set[str] = field(default_factory=set)
    exclude: set[str] = field(default_factory=set)
    categories: set[str] = field(default_factory=set)
    all_modules: bool = False
    max_entities: int = 150
    threads: int = 12
    timeout_total: float = 0.0
    formats: list[str] = field(default_factory=lambda: ["html", "md", "json"])
    out_dir: str = ""
    save_evidence: bool = True
    assume_yes: bool = False
    interactive: bool = True
    tlp: str = "clear"


class App:
    def __init__(
        self,
        console: Console,
        *,
        config: Config | None = None,
        verbosity: int = 1,
        fx: bool = True,
        proxy: str | None = None,
        offline: bool = False,
        no_cache: bool = False,
        debug: bool = False,
    ) -> None:
        self.console = console
        self.config = config or Config.load()
        self.verbosity = verbosity
        self.fx = fx and bool(self.config.get("fx"))
        self.proxy = proxy
        self.offline = offline
        self.no_cache = no_cache
        self.debug = debug
        self._store: Store | None = None
        load_modules(extra_dirs=[str(paths.plugins_dir())])

    # ------------------------------------------------------------------ plumbing
    @property
    def store(self) -> Store:
        if self._store is None:
            self._store = Store()
        return self._store

    def runtime(self, listener: Any = None) -> Runtime:
        proxy = self.proxy
        if proxy and proxy.startswith("socks") and not package_available("socks"):
            raise UserError("SOCKS/Tor proxy needs PySocks: pip install 'v3lum[full]' (or pip install PySocks)")
        return Runtime(self.config, offline=self.offline, no_cache=self.no_cache, listener=listener, proxy=proxy)

    def status_line(self) -> list[tuple[str, str, str]]:
        keys = self.config.keys()
        mode = str(self.config.get("mode"))
        ready = sum(1 for m in REGISTRY.values() if readiness(m, keys, Opsec.parse(mode))[0])
        need = sum(1 for m in REGISTRY.values() if m.requires_keys and not all(keys.get(k) for k in m.requires_keys))
        proxy = self.proxy or str(self.config.get("proxy") or "")
        route = "tor" if proxy == TOR_PROXY else ("proxy" if proxy else "direct")
        return [
            ("modules", f"{ready} ready", "v.ok"),
            ("need keys", str(need), "v.warn" if need else "v.dim"),
            ("mode", mode, "v.accent"),
            ("route", route, "v.warn" if route == "direct" else "v.ok"),
            ("cache", "off" if self.no_cache else "on", "v.dim"),
        ]

    # ------------------------------------------------------------------ detection
    def resolve_inputs(self, inputs: list[str], etype: EntityType | None, interactive: bool) -> tuple[list[Entity], list[det.Detection]]:
        seeds: list[Entity] = []
        chosen: list[det.Detection] = []
        for raw in inputs:
            found = det.detect(raw, explicit=etype)
            if not found:
                if etype:
                    raise UserError(f"{raw!r} is not a valid {etype.value}")
                raise UserError(f"could not interpret {raw!r}")
            picks = det.primary(found)
            ambiguous = len(found) > 1 and found[0].confidence < 0.9 and found[1].confidence >= 0.5
            if ambiguous and interactive and sys.stdin.isatty():
                render_detections(self.console, raw, found)
                options = [str(i + 1) for i in range(len(found))] + ["a"]
                answer = Prompt.ask(
                    "[v.accent]which interpretation?[/] (number, or [b]a[/] for all)", choices=options, default="1", console=self.console
                )
                picks = found if answer == "a" else [found[int(answer) - 1]]
            elif ambiguous and self.verbosity > 0:
                alts = ", ".join(f"{d.type.value} ({d.confidence:.2f})" for d in found[1:4])
                self.console.print(Text(f"[i] {raw[:60]!s} read as {picks[0].type.value}; also possible: {alts}. Force with TYPE:value", style="v.dim"))
            for d in picks:
                if d.entity not in seeds:
                    seeds.append(d.entity)
                    chosen.append(d)
        return seeds, chosen

    # ------------------------------------------------------------------ scan
    def scan(self, req: ScanRequest) -> dict[str, Any]:
        if not req.inputs:
            raise UserError("nothing to investigate: give at least one input")
        seeds, chosen = self.resolve_inputs(req.inputs, req.etype, req.interactive)
        if req.mode is Opsec.ACTIVE:
            self._authorization_gate(req, seeds)
        options = ScanOptions(
            mode=req.mode,
            authorized=req.authorized and req.mode is Opsec.ACTIVE,
            depth=max(0, req.depth),
            max_entities=req.max_entities,
            threads=req.threads,
            include=set(req.include),
            exclude=set(req.exclude),
            categories=set(req.categories),
            include_disabled=req.all_modules,
            offline=self.offline,
            no_cache=self.no_cache,
            timeout_total=req.timeout_total,
            save_evidence=req.save_evidence,
            authorization_note=req.authorization_note,
            tlp=req.tlp,
        )
        for name in list(options.include) + list(options.exclude):
            try:
                get_module(name)
            except KeyError as exc:
                raise UserError(str(exc)) from exc
        unknown = [c for c in options.categories if c not in CATEGORIES]
        if unknown:
            raise UserError(f"unknown categories: {', '.join(unknown)} (see `v3lum modules --categories`)")
        feed = LiveFeed(self.console, verbosity=self.verbosity)
        rt = self.runtime(listener=feed)
        engine = Engine(rt, options, reliability=self.store.reliability())
        with feed:
            case = engine.investigate(seeds, detections=chosen)
        data = case.to_dict()
        out_dir = req.out_dir or str(self.config.get("report_dir") or "") or case.case_dir
        if req.formats:
            data["reports"] = write_reports(data, req.formats, out_dir)
        self.store.save_case(data)
        return data

    def _authorization_gate(self, req: ScanRequest, seeds: list[Entity]) -> None:
        if not req.authorized:
            raise UserError(
                "active mode sends intrusive probes (port scans, path discovery, AXFR...). "
                "Use it only on assets you are authorized to test, and add --authorized to confirm."
            )
        if req.assume_yes or not sys.stdin.isatty():
            return
        targets = "\n".join(f"  • {s.type.value}: {s.display}" for s in seeds)
        self.console.print(
            Panel(
                Text.from_markup(
                    "[v.warn]ACTIVE MODE[/]: V3LUM will interact directly and intrusively with:\n"
                    f"{targets}\n\nOnly continue if you hold written authorization (pentest contract / scope) "
                    "for every target above. The authorization note is stored in the case."
                ),
                border_style="v.warn",
                title="authorization required",
            )
        )
        if not Confirm.ask("[v.warn]I am authorized to actively test these targets[/]", default=False, console=self.console):
            raise UserError("active scan cancelled: authorization not confirmed")
        if not req.authorization_note:
            req.authorization_note = Prompt.ask("[v.dim]authorization reference (contract/ticket/scope id)[/]", default="not provided", console=self.console)

    def show_case(self, data: dict[str, Any], full: bool = False) -> None:
        render_case(self.console, data, full=full)
        reports = data.get("reports") or {}
        if reports:
            self.console.print(Text("\n[◈] reports", style="v.accent"))
            for fmt, path in reports.items():
                self.console.print(Text.assemble((f"    {fmt:5} ", "v.dim"), (path, "v.url")), soft_wrap=True)

    def ask_feedback(self, data: dict[str, Any]) -> None:
        """The closing question: did the result make sense? Feeds module reliability."""
        if not sys.stdin.isatty():
            return
        self.console.print()
        answer = Prompt.ask(
            "[v.accent]⟁ did this report make sense?[/] [v.dim]([b]y[/]es / [b]p[/]artially / [b]n[/]o / [b]s[/]kip)[/]",
            choices=["y", "p", "n", "s"],
            default="s",
            console=self.console,
            show_choices=False,
        )
        if answer == "s":
            return
        verdict = {"y": "yes", "p": "partial", "n": "no"}[answer]
        notes = ""
        reviewable = [f for f in data.get("findings", []) if f["severity"] != "info"][:30]
        if verdict == "yes":
            for f in reviewable:
                self.store.flag_finding(data["case_id"], f["id"], f["module"], True)
        elif reviewable:
            t = Table(box=box.SIMPLE, show_header=True, header_style="v.dim", title="[v.accent]which findings were wrong?[/]", title_justify="left")
            t.add_column("#", justify="right", style="v.dim")
            t.add_column("sev")
            t.add_column("finding", overflow="fold")
            t.add_column("source", style="v.module")
            for i, f in enumerate(reviewable, 1):
                t.add_row(str(i), Text(f["severity"], style=f"sev.{f['severity']}"), f["title"], f["module"])
            self.console.print(t)
            raw = Prompt.ask("[v.dim]numbers of WRONG findings (e.g. 1,4,7; empty = none)[/]", default="", console=self.console)
            wrong = {int(x) for x in raw.replace(" ", "").split(",") if x.isdigit() and 1 <= int(x) <= len(reviewable)}
            for i, f in enumerate(reviewable, 1):
                self.store.flag_finding(data["case_id"], f["id"], f["module"], i not in wrong)
        notes = Prompt.ask("[v.dim]notes for the record (optional)[/]", default="", console=self.console)
        self.store.add_feedback(data["case_id"], verdict, notes)
        self.console.print(Text("[✓] feedback stored — noisy sources lose weight in future risk scores.", style="v.ok"))

    # ------------------------------------------------------------------ single module
    def run_single(self, module_name: str, raw: str, etype: EntityType | None, mode: Opsec, authorized: bool) -> dict[str, Any]:
        try:
            cls = get_module(module_name)
        except KeyError as exc:
            raise UserError(str(exc)) from exc
        found = det.detect(raw, explicit=etype)
        target = next((d for d in found if d.type in cls.accepts), None)
        if target is None:
            accepted = ", ".join(sorted(t.value for t in cls.accepts))
            raise UserError(f"{cls.name} accepts {accepted}; {raw!r} was read as {found[0].type.value if found else 'nothing'} (force with TYPE:value)")
        effective_mode = max(mode, cls.opsec) if cls.opsec is not Opsec.ACTIVE else mode
        ready, reason = readiness(cls, self.config.keys(), effective_mode, authorized)
        if not ready:
            raise UserError(f"{cls.name} cannot run: {reason}")
        rt = self.runtime()
        engine = Engine(rt, ScanOptions(mode=effective_mode, authorized=authorized, save_evidence=False, include={cls.name}))
        res = engine.run_module(cls, target.entity)
        return {
            "module": cls.name,
            "entity": target.entity.key,
            "status": res.status.value,
            "error": res.error,
            "duration": round(res.duration, 2),
            "findings": [f.to_dict() for f in res.findings],
            "attributes": res.attributes,
            "pivots": [{"entity": p.entity.key, "relation": p.relation, "confidence": p.confidence} for p in res.pivots],
            "links": [{"label": lbl, "url": url} for lbl, url in res.links],
            "raw": res.raw if self.debug else None,
        }

    def show_single(self, out: dict[str, Any]) -> None:
        st = out["status"]
        head = Text()
        head.append(f"{out['module']} ", style="v.module")
        head.append("→ ", style="v.ghost")
        head.append(out["entity"], style="v.entity")
        head.append(f"   [{st}]", style=f"status.{st}")
        head.append(f"  {out['duration']}s", style="v.ghost")
        self.console.print(head)
        if out.get("error"):
            self.console.print(Text(f"  {out['error']}", style="v.dim"))
        if out["findings"]:
            t = Table(box=box.SIMPLE, show_header=False)
            t.add_column(no_wrap=True)
            t.add_column(overflow="fold")
            for f in out["findings"]:
                body = Text(f["title"], style="v.text")
                if f.get("description"):
                    body.append("\n" + f["description"], style="v.dim")
                t.add_row(Text(f["severity"], style=f"sev.{f['severity']}"), body)
            self.console.print(t)
        if out["attributes"]:
            t = Table(box=box.MINIMAL, show_header=False)
            t.add_column(style="v.dim", no_wrap=True)
            t.add_column(style="v.text", overflow="fold")
            for k, v in out["attributes"].items():
                t.add_row(k, json.dumps(v, ensure_ascii=False, default=str)[:400] if isinstance(v, (list, dict)) else str(v))
            self.console.print(t)
        if out["pivots"]:
            t = Table(box=box.MINIMAL, show_header=False, title="[v.dim]pivots[/]", title_justify="left")
            t.add_column(style="v.ghost")
            t.add_column(style="v.entity", overflow="fold")
            for p in out["pivots"][:100]:
                t.add_row(p["relation"], p["entity"])
            if len(out["pivots"]) > 100:
                t.add_row("…", f"+{len(out['pivots']) - 100} more")
            self.console.print(t)
        for link in out["links"][:30]:
            self.console.print(Text.assemble(("  ↗ ", "v.accent"), (link["label"] + "  ", "v.text"), (link["url"], "v.url")))

    # ------------------------------------------------------------------ catalog
    def modules_table(self, category: str = "", search: str = "", etype: EntityType | None = None, ready_only: bool = False) -> Table:
        keys = self.config.keys()
        mode = Opsec.parse(str(self.config.get("mode")))
        t = Table(box=box.SIMPLE_HEAVY, header_style="v.dim", expand=True, title=f"[v.accent]⌬ modules[/] [v.dim]({len(REGISTRY)} loaded, mode {mode.label})[/]", title_justify="left")
        t.add_column("module", style="v.module", no_wrap=True)
        t.add_column("accepts", style="v.type", overflow="fold", max_width=22)
        t.add_column("opsec", no_wrap=True)
        t.add_column("status", overflow="fold", max_width=22)
        t.add_column("description", style="v.text", overflow="fold", ratio=3, min_width=28)
        count = 0
        current_cat = None
        for cls in sorted(REGISTRY.values(), key=lambda m: (m.category, m.name)):
            if category and cls.category != category:
                continue
            if etype and etype not in cls.accepts:
                continue
            blob = f"{cls.name} {cls.title} {cls.description} {' '.join(cls.tags)} {' '.join(cls.hosts)}".lower()
            if search and search.lower() not in blob:
                continue
            ok, reason = readiness(cls, keys, Opsec.ACTIVE, True)
            if ready_only and not ok:
                continue
            status = Text("ready", style="status.ok") if ok else Text(reason, style="status.needs_key" if "key" in reason else "status.unavailable")
            if ok and cls.opsec > mode:
                status = Text(f"needs --mode {cls.opsec.label}", style="v.dim")
            if not cls.default_enabled:
                status.append(" (opt-in)", style="v.ghost")
            opsec_style = {"passive": "v.ok", "light": "v.info", "active": "v.warn"}[cls.opsec.label]
            if cls.category != current_cat:
                current_cat = cls.category
                t.add_row(Text(f"▌{CATEGORIES.get(cls.category, cls.category)}", style="v.accent"), "", "", "", Text(cls.category, style="v.ghost"))
            t.add_row(" " + cls.name, ", ".join(sorted(x.value for x in cls.accepts)), Text(cls.opsec.label, style=opsec_style), status, cls.description)
            count += 1
        t.caption = f"{count} shown · `v3lum info <module>` for details · keys: `v3lum keys`"
        return t

    def module_info(self, name: str) -> Panel:
        try:
            cls = get_module(name)
        except KeyError as exc:
            raise UserError(str(exc)) from exc
        d = cls.describe()
        ok, reason = readiness(cls, self.config.keys(), Opsec.ACTIVE, True)
        g = Table.grid(padding=(0, 2))
        g.add_column(style="v.dim", justify="right")
        g.add_column(style="v.text", overflow="fold")
        g.add_row("title", d["title"])
        g.add_row("category", f"{d['category']} — {CATEGORIES.get(d['category'], '')}")
        g.add_row("accepts", ", ".join(d["accepts"]))
        g.add_row("produces", ", ".join(d["produces"]) or "-")
        g.add_row("opsec", d["opsec"])
        g.add_row("keys", (", ".join(d["requires_keys"]) or "none") + (f" (optional: {', '.join(d['optional_keys'])})" if d["optional_keys"] else ""))
        g.add_row("packages", ", ".join(d["requires_packages"]) or "-")
        g.add_row("hosts", ", ".join(d["hosts"]) or "offline")
        g.add_row("reference", d["reference"] or "-")
        g.add_row("tags", ", ".join(d["tags"]) or "-")
        g.add_row("auto-run", "yes" if d["default_enabled"] else "no (select with -M or --all-modules)")
        g.add_row("shares input", "yes (value sent to the provider)" if d["shares_input"] else "no (offline / local data)")
        g.add_row("terms", d["terms"])
        g.add_row("status", Text("ready", style="status.ok") if ok else Text(reason, style="status.needs_key"))
        if d["notice"]:
            g.add_row("notice", Text(d["notice"], style="v.warn"))
        return Panel(g, title=f"[v.module]{d['name']}[/]", subtitle=d["description"][:100], border_style="v.accent")

    def keys_table(self) -> Table:
        needed: dict[str, list[str]] = {}
        for cls in REGISTRY.values():
            for k in cls.requires_keys:
                needed.setdefault(k, []).append(cls.name)
            for k in cls.optional_keys:
                needed.setdefault(k, []).append(cls.name + "*")
        names = sorted(set(KNOWN_KEYS) | set(needed) | set(self.config.file_keys))
        t = Table(box=box.SIMPLE_HEAVY, header_style="v.dim", expand=True, title="[v.accent]⚿ API keys[/]", title_justify="left")
        t.add_column("name", style="v.module", no_wrap=True)
        t.add_column("status", no_wrap=True)
        t.add_column("used by", style="v.dim", overflow="fold", ratio=2)
        t.add_column("what / where to get it", style="v.text", overflow="fold", ratio=3)
        for n in names:
            val = self.config.key(n)
            src = self.config.key_source(n)
            status = Text(f"{mask(val)} ({src})", style="status.ok") if val else Text("missing", style="v.ghost")
            desc, url, aliases = KNOWN_KEYS.get(n, ("", "", ()))
            env = f"env V3LUM_KEY_{n.upper()}" + (f" / {aliases[0]}" if aliases else "")
            t.add_row(n, status, ", ".join(sorted(needed.get(n, [])))[:200] or "-", f"{desc}\n{url}\n{env}".strip())
        t.caption = "set: v3lum keys set <name>   (* = optional key, the module works without it)"
        return t

    def set_key(self, name: str, value: str | None) -> None:
        if not value:
            value = getpass.getpass(f"value for {name} (hidden): ")
        if not value.strip():
            raise UserError("empty key not stored")
        self.config.set_key(name, value)
        self.console.print(Text(f"[✓] {name} stored in {paths.config_file()} ({mask(value)})", style="v.ok"))

    # ------------------------------------------------------------------ cases
    def cases_table(self, limit: int = 30, search: str = "") -> Table:
        t = Table(box=box.SIMPLE_HEAVY, header_style="v.dim", expand=True, title="[v.accent]☰ cases[/]", title_justify="left")
        t.add_column("case", style="v.title", no_wrap=True)
        t.add_column("created", style="v.dim", no_wrap=True)
        t.add_column("inputs", style="v.entity", overflow="fold", ratio=3)
        t.add_column("risk", no_wrap=True)
        t.add_column("findings", justify="right")
        t.add_column("entities", justify="right")
        for c in self.store.list_cases(limit, search):
            lvl = c.get("risk_level") or "clean"
            t.add_row(c["id"], c["created"][:19], ", ".join(c["seeds"])[:160], Text(f"{lvl} {c.get('risk_score') or 0:.0f}", style=f"risk.{lvl}"), str(c.get("findings") or 0), str(c.get("entities") or 0))
        return t

    def load_case(self, case_id: str) -> dict[str, Any]:
        data = self.store.get_case(case_id)
        if data is None:
            raise UserError(f"case {case_id!r} not found (see `v3lum cases list`)")
        return data

    # ------------------------------------------------------------------ links / extract
    def links(self, raw: str, etype: EntityType | None) -> list[tuple[str, str, str]]:
        from v3lum.core.links import links_for

        found = det.detect(raw, explicit=etype)
        if not found:
            raise UserError(f"could not interpret {raw!r}")
        out = []
        for d in det.primary(found):
            for label, url in links_for(d.entity):
                out.append((d.entity.key, label, url))
        return out

    def extract(self, text: str, types: set[str] | None = None) -> list[Entity]:
        ents = det.extract_iocs(text)
        if types:
            ents = [e for e in ents if e.type.value in types]
        return ents

    # ------------------------------------------------------------------ maintenance
    def data_update(self, names: list[str] | None = None) -> list[tuple[str, str]]:
        rt = self.runtime()
        results = []
        for name, meta in sorted(DATASETS.items()):
            if names and name not in names:
                continue
            try:
                path = rt.data.fetch(name, meta["url"], ttl=0, max_bytes=meta.get("max_bytes", 200 * 1024 * 1024))
                results.append((name, f"ok ({Path(path).stat().st_size // 1024} KB)"))
            except Exception as exc:
                results.append((name, f"failed: {exc}"))
        return results

    def doctor(self) -> Table:
        t = Table(box=box.SIMPLE_HEAVY, header_style="v.dim", expand=True, title="[v.accent]✚ doctor[/]", title_justify="left")
        t.add_column("check", style="v.text", no_wrap=True)
        t.add_column("result", overflow="fold")

        def row(name: str, ok: bool | None, detail: str) -> None:
            style = "status.ok" if ok else ("v.warn" if ok is None else "status.error")
            mark = "[+]" if ok else ("[~]" if ok is None else "[x]")
            t.add_row(name, Text(f"{mark} {detail}", style=style))

        row("python", sys.version_info >= (3, 10), f"{platform.python_version()} ({sys.executable})")
        row("v3lum", True, f"{__version__} · home {paths.home()}")
        for pkg, why in (("phonenumbers", "phone parsing"), ("dns", "system DNS (dnspython)"), ("PIL", "image EXIF"), ("pypdf", "PDF metadata"), ("socks", "Tor/SOCKS proxy")):
            row(f"package {pkg}", True if package_available(pkg) else None, why if package_available(pkg) else f"missing (optional: {why}) — pip install 'v3lum[full]'")
        try:
            test = paths.home() / ".write_test"
            test.write_text("ok")
            test.unlink()
            row("data dir", True, f"{paths.home()} writable")
        except OSError as exc:
            row("data dir", False, str(exc))
        errs = load_errors()
        row("modules", not errs, f"{len(REGISTRY)} loaded" + (f", {len(errs)} failed: {', '.join(errs)}" if errs else ""))
        keys = self.config.keys()
        row("API keys", True if keys else None, f"{len(keys)} configured: {', '.join(sorted(keys)) or 'none (free sources only)'}")
        if self.offline:
            row("network", None, "offline mode")
        else:
            rt = self.runtime()
            ctx = rt.context(type("Doctor", (), {"name": "doctor", "cache_ttl": 0, "min_interval": 0}))
            try:
                ans = ctx.dns.query("example.com", "A")
                row("DNS (DoH)", ans.ok and bool(ans.records), f"{self.config.get('doh_provider')}: example.com -> {', '.join(ans.records) or ans.error}")
            except Exception as exc:
                row("DNS (DoH)", False, str(exc))
            for host in ("https://internetdb.shodan.io/1.1.1.1", "https://crt.sh/?q=example.com&output=json", "https://api.github.com/zen"):
                try:
                    r = ctx.http.get(host, ttl=0, timeout=15)
                    row(f"reach {host.split('/')[2]}", r.status < 500, f"HTTP {r.status} in {r.elapsed * 1000:.0f} ms")
                except Exception as exc:
                    row(f"reach {host.split('/')[2]}", False, str(exc)[:120])
        proxy = self.proxy or str(self.config.get("proxy") or "")
        row("route", None if not proxy else True, proxy or "direct (consider --tor for sensitive lookups)")
        return t


def level_at_least(level: str, threshold: str) -> bool:
    return LEVEL_ORDER.index(level) >= LEVEL_ORDER.index(threshold)


def entity_type_or_none(value: str | None) -> EntityType | None:
    if not value:
        return None
    try:
        return EntityType.parse(value)
    except ValueError as exc:
        raise UserError(f"{exc}. Valid types: {', '.join(t.value for t in EntityType)}") from exc


def defanged(value: str) -> str:
    return defang(value)


__all__ = ["App", "ScanRequest", "UserError", "FORMATS", "TOR_PROXY", "level_at_least", "entity_type_or_none", "Status"]
