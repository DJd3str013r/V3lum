"""Command-line interface.

    v3lum                          interactive console (type anything to investigate it)
    v3lum scan <input...>          detect, collect, pivot, correlate, report
    v3lum detect <input...>        show how inputs are recognized
    v3lum run <module> <input>     run a single module
    v3lum modules / info <module>  catalog of collectors
    v3lum links <input>            manual pivot links (web tools pre-filled)
    v3lum extract <file|->         pull IOCs out of text (defanged too)
    v3lum keys / cases / feedback / data / cache / doctor / config
"""

from __future__ import annotations

import argparse
import json
import os
import sys
import webbrowser
from typing import Any

from rich.text import Text

from v3lum import __version__

EPILOG = """examples:
  v3lum scan suspicious-domain.com
  v3lum scan john.doe@acme.com --depth 2 -f html,md,stix
  v3lum scan 185.220.101.4 44d88612fea8a8f36de82e1278abb02f CVE-2024-3400
  v3lum scan "user:johndoe" -M username_check
  v3lum scan acme.com --mode light            # also fetch the site itself (normal visitor traffic)
  v3lum scan 10.0.0.5 --mode active --authorized "PT-2026-042"   # intrusive, only with permission
  v3lum extract report.txt --defang
  v3lum --tor scan target.onion
"""


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="v3lum",
        description="V3LUM - lift the veil. OSINT · CTI · recon multikit.",
        epilog=EPILOG,
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    p.add_argument("--version", action="version", version=f"V3LUM {__version__}")
    g = p.add_argument_group("global options")
    g.add_argument("--home", metavar="DIR", help="data directory (default ~/.v3lum or $V3LUM_HOME)")
    g.add_argument("--no-color", action="store_true", help="disable colors (also honours NO_COLOR)")
    g.add_argument("--no-fx", action="store_true", help="no banner animation")
    g.add_argument("-v", "--verbose", action="count", default=0, help="more output (-v: HTTP requests and every module)")
    g.add_argument("-q", "--quiet", action="store_true", help="no live feed (report only)")
    g.add_argument("--debug", action="store_true", help="show tracebacks and raw module data")
    g.add_argument("--proxy", metavar="URL", help="route traffic through a proxy (http://, socks5h://)")
    g.add_argument("--tor", action="store_true", help="route traffic through Tor (socks5h://127.0.0.1:9050)")
    g.add_argument("--offline", action="store_true", help="no network: cached data and offline modules only")
    g.add_argument("--no-cache", action="store_true", help="do not read or write the HTTP cache")

    sub = p.add_subparsers(dest="command", metavar="<command>")

    s = sub.add_parser("scan", help="investigate one or more inputs (auto-detected)", epilog=EPILOG, formatter_class=argparse.RawDescriptionHelpFormatter)
    s.add_argument("inputs", nargs="*", help="anything: email, domain, IP, URL, hash, phone, @user, CNPJ, wallet, CVE, file path... (TYPE:value forces a type)")
    s.add_argument("-i", "--input-file", metavar="FILE", help="read inputs from a file, one per line ('-' = stdin)")
    s.add_argument("-t", "--type", help="force the entity type of every input (see `v3lum detect`)")
    s.add_argument("-d", "--depth", type=int, help="pivot depth: 0 = only inputs, 1 = + discovered entities (default), 2+ = deeper")
    s.add_argument("-m", "--mode", choices=["passive", "light", "active"], help="passive (default) | light (touch target like a visitor) | active (intrusive)")
    s.add_argument("--authorized", nargs="?", const="confirmed", metavar="REF", help="confirm written authorization for active mode (optional reference)")
    s.add_argument("--tlp", choices=["clear", "green", "amber", "red"], default="clear", help="TLP of the inputs: red = never send them to third-party services (offline modules only)")
    s.add_argument("-M", "--modules", help="run only these modules (comma separated)")
    s.add_argument("-x", "--exclude", help="skip these modules (comma separated)")
    s.add_argument("-c", "--categories", help="only modules of these categories (comma separated)")
    s.add_argument("--all-modules", action="store_true", help="also run opt-in modules (noisy/slow ones)")
    s.add_argument("--max-entities", type=int, help="budget of investigated entities (default 150)")
    s.add_argument("--threads", type=int, help="parallel module runs (default 12)")
    s.add_argument("--timeout", type=float, default=0.0, help="global time limit in seconds (partial results)")
    s.add_argument("-f", "--format", help="report formats: html,md,json,stix (default from config)")
    s.add_argument("-o", "--out", help="report directory (default: the case folder)")
    s.add_argument("--no-evidence", action="store_true", help="do not save raw evidence files")
    s.add_argument("--full", action="store_true", help="print everything in the terminal report")
    s.add_argument("--json", action="store_true", help="print the case as JSON on stdout (machine mode)")
    s.add_argument("--no-feedback", action="store_true", help="do not ask 'did this make sense?'")
    s.add_argument("-y", "--yes", action="store_true", help="assume yes for prompts (keeps --authorized mandatory)")
    s.add_argument("--fail-on", choices=["low", "medium", "high", "critical"], help="exit code 3 if risk >= level (automation)")

    d = sub.add_parser("detect", help="show how inputs are recognized")
    d.add_argument("inputs", nargs="+")
    d.add_argument("--json", action="store_true")

    r = sub.add_parser("run", help="run a single module on an input")
    r.add_argument("module")
    r.add_argument("input")
    r.add_argument("-t", "--type", help="force entity type")
    r.add_argument("-m", "--mode", choices=["passive", "light", "active"], default="light")
    r.add_argument("--authorized", nargs="?", const="confirmed", metavar="REF")
    r.add_argument("--json", action="store_true")

    m = sub.add_parser("modules", help="list modules and their readiness")
    m.add_argument("-c", "--category", help="filter by category")
    m.add_argument("-s", "--search", help="text search")
    m.add_argument("-t", "--type", help="modules accepting this entity type")
    m.add_argument("--ready", action="store_true", help="only modules ready to run")
    m.add_argument("--categories", action="store_true", help="list categories")
    m.add_argument("--json", action="store_true")

    i = sub.add_parser("info", help="details of a module")
    i.add_argument("module")

    lk = sub.add_parser("links", help="manual pivot links for an input (web tools pre-filled)")
    lk.add_argument("input")
    lk.add_argument("-t", "--type", help="force entity type")
    lk.add_argument("--open", type=int, metavar="N", help="open link number N in the browser")
    lk.add_argument("--json", action="store_true")

    ex = sub.add_parser("extract", help="extract IOCs from a text file or stdin")
    ex.add_argument("source", nargs="?", default="-", help="file path or '-' for stdin")
    ex.add_argument("--defang", action="store_true", help="print defanged values")
    ex.add_argument("-t", "--types", help="only these types (comma separated)")
    ex.add_argument("--json", action="store_true")
    ex.add_argument("--scan", action="store_true", help="investigate the extracted IOCs right away")

    k = sub.add_parser("keys", help="manage API keys (stored with 0600 permissions)")
    ksub = k.add_subparsers(dest="keys_cmd", metavar="<action>")
    ksub.add_parser("list", help="list keys and which modules use them")
    ks = ksub.add_parser("set", help="store a key (prompted hidden if VALUE omitted)")
    ks.add_argument("name")
    ks.add_argument("value", nargs="?")
    ku = ksub.add_parser("unset", help="remove a stored key")
    ku.add_argument("name")

    c = sub.add_parser("cases", help="stored investigations")
    csub = c.add_subparsers(dest="cases_cmd", metavar="<action>")
    cl = csub.add_parser("list", help="list cases")
    cl.add_argument("-n", "--limit", type=int, default=30)
    cl.add_argument("-s", "--search", default="")
    cs = csub.add_parser("show", help="print a case report ('last' = latest)")
    cs.add_argument("case_id")
    cs.add_argument("--full", action="store_true")
    cr = csub.add_parser("report", help="write report files for a case")
    cr.add_argument("case_id")
    cr.add_argument("-f", "--format", default="html,md,json,stix")
    cr.add_argument("-o", "--out", help="output directory")
    cd = csub.add_parser("delete", help="delete a case from the database")
    cd.add_argument("case_id")
    cf = csub.add_parser("feedback", help="give feedback on a case")
    cf.add_argument("case_id")

    fb = sub.add_parser("feedback", help="feedback statistics and module reliability")
    fb.add_argument("--json", action="store_true")

    da = sub.add_parser("data", help="downloadable datasets (KEV, ATT&CK, blocklists...)")
    dsub = da.add_subparsers(dest="data_cmd", metavar="<action>")
    dsub.add_parser("list", help="registered and cached datasets")
    du = dsub.add_parser("update", help="download/refresh datasets now (before going offline)")
    du.add_argument("names", nargs="*")

    ca = sub.add_parser("cache", help="HTTP cache")
    casub = ca.add_subparsers(dest="cache_cmd", metavar="<action>")
    casub.add_parser("stats", help="cache statistics")
    cc = casub.add_parser("clear", help="clear the cache")
    cc.add_argument("--host", help="only entries for this host")

    sub.add_parser("doctor", help="check environment, dependencies, network and keys")

    cfg = sub.add_parser("config", help="show or change settings")
    cfgsub = cfg.add_subparsers(dest="config_cmd", metavar="<action>")
    cfgsub.add_parser("show", help="current settings")
    cfs = cfgsub.add_parser("set", help="change a setting")
    cfs.add_argument("key")
    cfs.add_argument("value")
    cfgsub.add_parser("path", help="where files are stored")

    sub.add_parser("shell", help="interactive console (default when no command is given)")
    sub.add_parser("version", help="print version")
    return p


def _split(value: str | None) -> list[str]:
    return [v.strip() for v in (value or "").split(",") if v.strip()]


def _read_inputs(args: argparse.Namespace) -> list[str]:
    items = list(args.inputs or [])
    if getattr(args, "input_file", None):
        src = sys.stdin if args.input_file == "-" else open(args.input_file, encoding="utf-8")  # noqa: SIM115
        with src if src is not sys.stdin else _nullctx():
            for line in src:
                line = line.strip()
                if line and not line.startswith("#"):
                    items.append(line)
    if items == ["-"]:
        items = [sys.stdin.read()]
    return items


class _nullctx:
    def __enter__(self) -> None:
        return None

    def __exit__(self, *exc: Any) -> None:
        return None


def make_app(args: argparse.Namespace, console: Any) -> Any:
    from v3lum.app import TOR_PROXY, App

    proxy = TOR_PROXY if args.tor else (args.proxy or None)
    verbosity = 0 if args.quiet else 1 + int(args.verbose or 0)
    return App(console, verbosity=verbosity, fx=not args.no_fx, proxy=proxy, offline=args.offline, no_cache=args.no_cache, debug=args.debug)


def dispatch(args: argparse.Namespace, app: Any, console: Any) -> int:  # noqa: C901 - command router
    from v3lum.app import ScanRequest, UserError, entity_type_or_none, level_at_least
    from v3lum.core import detect as det
    from v3lum.core.models import Opsec
    from v3lum.core.module import CATEGORIES, REGISTRY
    from v3lum.report import write_reports
    from v3lum.ui.render import render_detections

    cmd = args.command
    if cmd == "version":
        console.print(f"V3LUM {__version__}")
        return 0

    if cmd == "scan":
        inputs = _read_inputs(args)
        if not inputs:
            raise UserError("give at least one input, e.g.  v3lum scan example.com")
        if args.json:
            app.verbosity = 0
        cfg = app.config
        req = ScanRequest(
            inputs=inputs,
            etype=entity_type_or_none(args.type),
            mode=Opsec.parse(args.mode or str(cfg.get("mode"))),
            authorized=bool(args.authorized),
            authorization_note="" if args.authorized in (None, "confirmed") else str(args.authorized),
            depth=args.depth if args.depth is not None else int(cfg.get("depth")),
            include=set(_split(args.modules)),
            exclude=set(_split(args.exclude)),
            categories=set(_split(args.categories)),
            all_modules=args.all_modules,
            max_entities=args.max_entities or int(cfg.get("max_entities")),
            threads=args.threads or int(cfg.get("threads")),
            timeout_total=args.timeout,
            formats=_split(args.format) if args.format is not None else list(cfg.get("report_formats")),
            out_dir=args.out or "",
            save_evidence=not args.no_evidence,
            assume_yes=args.yes,
            interactive=not args.json and not args.yes,
            tlp=args.tlp,
        )
        data = app.scan(req)
        if args.json:
            sys.stdout.write(json.dumps(data, ensure_ascii=False, indent=2, default=str) + "\n")
        else:
            app.show_case(data, full=args.full)
            if cfg.get("feedback") and not args.no_feedback and not args.yes:
                app.ask_feedback(data)
        if args.fail_on and level_at_least(data["summary"]["risk_level"], args.fail_on):
            return 3
        return 0

    if cmd == "detect":
        out = []
        for raw in args.inputs:
            found = det.detect(raw)
            if args.json:
                out.append({"input": raw, "detections": [{"type": d.type.value, "value": d.value, "confidence": d.confidence, "reason": d.reason} for d in found]})
            else:
                render_detections(console, raw, found)
        if args.json:
            sys.stdout.write(json.dumps(out, ensure_ascii=False, indent=2) + "\n")
        return 0

    if cmd == "run":
        out = app.run_single(args.module, args.input, entity_type_or_none(args.type), Opsec.parse(args.mode), bool(args.authorized))
        if args.json:
            sys.stdout.write(json.dumps(out, ensure_ascii=False, indent=2, default=str) + "\n")
        else:
            app.show_single(out)
        return 0

    if cmd == "modules":
        if args.categories:
            for key, label in CATEGORIES.items():
                n = sum(1 for m in REGISTRY.values() if m.category == key)
                console.print(Text.assemble((f"{key:22}", "v.module"), (f"{n:3} modules  ", "v.dim"), (label, "v.text")))
            return 0
        if args.json:
            data = [cls.describe() for cls in sorted(REGISTRY.values(), key=lambda m: m.name)]
            sys.stdout.write(json.dumps(data, indent=2) + "\n")
            return 0
        console.print(app.modules_table(args.category or "", args.search or "", entity_type_or_none(args.type), args.ready))
        return 0

    if cmd == "info":
        console.print(app.module_info(args.module))
        return 0

    if cmd == "links":
        rows = app.links(args.input, entity_type_or_none(args.type))
        if args.json:
            sys.stdout.write(json.dumps([{"entity": e, "label": lbl, "url": u} for e, lbl, u in rows], indent=2) + "\n")
            return 0
        if not rows:
            console.print(Text("no pivot links for this type yet", style="v.dim"))
            return 0
        for n, (_ent, label, url) in enumerate(rows, 1):
            console.print(Text.assemble((f"{n:3} ", "v.dim"), (f"{label:34} ", "v.text"), (url, "v.url")))
        if args.open:
            if not 1 <= args.open <= len(rows):
                raise UserError(f"--open must be between 1 and {len(rows)}")
            webbrowser.open(rows[args.open - 1][2])
        else:
            console.print(Text("\n  opening a link contacts that site from your machine · --open N to launch one", style="v.ghost"))
        return 0

    if cmd == "extract":
        if args.source == "-":
            text = sys.stdin.read()
        else:
            if not os.path.isfile(args.source):
                raise UserError(f"file not found: {args.source}")
            with open(args.source, encoding="utf-8", errors="replace") as fh:
                text = fh.read()
        ents = app.extract(text, set(_split(args.types)) or None)
        if args.scan:
            if not ents:
                raise UserError("no IOCs found")
            req = ScanRequest(inputs=[e.key for e in ents], formats=list(app.config.get("report_formats")))
            data = app.scan(req)
            app.show_case(data)
            return 0
        if args.json:
            sys.stdout.write(json.dumps([{"type": e.type.value, "value": e.value} for e in ents], indent=2) + "\n")
            return 0
        from v3lum.core.entities import defang

        for e in ents:
            val = defang(e.value) if args.defang and e.type.value in ("url", "domain", "email", "ipv4", "ipv6") else e.value
            console.print(Text.assemble((f"{e.type.value:18}", "v.type"), (val, "v.entity")))
        console.print(Text(f"\n{len(ents)} indicators", style="v.dim"))
        return 0

    if cmd == "keys":
        action = args.keys_cmd or "list"
        if action == "list":
            console.print(app.keys_table())
        elif action == "set":
            app.set_key(args.name, args.value)
        elif action == "unset":
            ok = app.config.unset_key(args.name)
            console.print(Text(f"[✓] {args.name} removed" if ok else f"{args.name} was not stored in the config file", style="v.ok" if ok else "v.dim"))
        return 0

    if cmd == "cases":
        action = args.cases_cmd or "list"
        if action == "list":
            console.print(app.cases_table(getattr(args, "limit", 30), getattr(args, "search", "")))
        elif action == "show":
            app.show_case(app.load_case(args.case_id), full=args.full)
        elif action == "report":
            data = app.load_case(args.case_id)
            out = args.out or data.get("case_dir") or "."
            for fmt, path in write_reports(data, _split(args.format), out).items():
                console.print(Text.assemble((f"{fmt:5} ", "v.dim"), (path, "v.url")))
        elif action == "delete":
            ok = app.store.delete_case(args.case_id)
            console.print(Text(f"[✓] case {args.case_id} deleted" if ok else "case not found", style="v.ok" if ok else "v.warn"))
        elif action == "feedback":
            app.ask_feedback(app.load_case(args.case_id))
        return 0

    if cmd == "feedback":
        summary = app.store.feedback_summary()
        if args.json:
            sys.stdout.write(json.dumps(summary, indent=2) + "\n")
            return 0
        from rich import box
        from rich.table import Table

        v = summary["verdicts"]
        console.print(Text.assemble(("verdicts  ", "v.accent"), (f"yes {v.get('yes', 0)} · partial {v.get('partial', 0)} · no {v.get('no', 0)}", "v.text")))
        t = Table(box=box.SIMPLE, header_style="v.dim", title="[v.accent]module reliability (from your feedback)[/]", title_justify="left")
        t.add_column("module", style="v.module")
        t.add_column("right", justify="right")
        t.add_column("wrong", justify="right")
        t.add_column("weight", justify="right")
        for m in summary["modules"]:
            t.add_row(m["module"], str(m["correct"]), str(m["wrong"]), f"{m['reliability']:.2f}")
        console.print(t)
        return 0

    if cmd == "data":
        from v3lum.core.datasets import DATASETS

        action = args.data_cmd or "list"
        if action == "update":
            for name, status in app.data_update(args.names or None):
                console.print(Text.assemble((f"{name:40}", "v.module"), (status, "status.ok" if status.startswith("ok") else "status.error")))
            return 0
        cached = {d["name"]: d for d in app.runtime().data.cached_info()}
        for name, meta in sorted(DATASETS.items()):
            c = cached.get(name)
            state = f"cached {c['bytes'] // 1024} KB, {c['age_hours']} h old" if c else "not downloaded"
            console.print(Text.assemble((f"{name:40}", "v.module"), (f"{state:34}", "v.dim"), (meta.get("description", ""), "v.text")))
        if not DATASETS:
            console.print(Text("no downloadable datasets registered", style="v.dim"))
        return 0

    if cmd == "cache":
        from v3lum import paths
        from v3lum.core.http import HttpCache

        cache = HttpCache(str(paths.cache_file()))
        if (args.cache_cmd or "stats") == "clear":
            n = cache.clear(host=args.host)
            console.print(Text(f"[✓] {n} cached responses removed", style="v.ok"))
        else:
            st = cache.stats()
            console.print(Text(f"{st['entries']} responses · {st['bytes'] // 1024} KB · {st['path']}", style="v.text"))
            for host, n in st["top_hosts"]:
                console.print(Text.assemble((f"  {n:6} ", "v.dim"), (host or "?", "v.entity")))
        return 0

    if cmd == "doctor":
        console.print(app.doctor())
        return 0

    if cmd == "config":
        from v3lum import paths
        from v3lum.config import DEFAULT_SETTINGS

        action = args.config_cmd or "show"
        if action == "set":
            try:
                app.config.set(args.key, args.value)
            except (KeyError, ValueError) as exc:
                raise UserError(f"{exc}. Settings: {', '.join(DEFAULT_SETTINGS)}") from exc
            console.print(Text(f"[✓] {args.key} = {app.config.get(args.key)!r}", style="v.ok"))
        elif action == "path":
            console.print(Text(f"home   {paths.home()}\nconfig {paths.config_file()}\ndb     {paths.db_file()}\ncache  {paths.cache_file()}\ncases  {paths.cases_dir()}\nplugins {paths.plugins_dir()}", style="v.text"))
        else:
            for k in DEFAULT_SETTINGS:
                console.print(Text.assemble((f"{k:16}", "v.module"), (repr(app.config.get(k)), "v.text")))
        return 0

    raise UserError(f"unknown command {cmd!r}")


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    if args.home:
        os.environ["V3LUM_HOME"] = os.path.abspath(os.path.expanduser(args.home))
    from v3lum.app import UserError
    from v3lum.ui.theme import make_console

    console = make_console(no_color=args.no_color)
    err_console = make_console(no_color=args.no_color, stderr=True)
    try:
        app = make_app(args, console)
        if args.command in (None, "shell"):
            from v3lum.shell import Shell

            return Shell(app, console, parser).run()
        return dispatch(args, app, console)
    except UserError as exc:
        err_console.print(Text(f"[x] {exc}", style="v.err"))
        return 1
    except KeyboardInterrupt:
        err_console.print(Text("\n[!] interrupted", style="v.warn"))
        return 130
    except Exception as exc:  # last resort: never dump a raw traceback on the analyst
        if args.debug:
            raise
        err_console.print(Text(f"[x] unexpected error: {type(exc).__name__}: {exc}  (re-run with --debug for details)", style="v.err"))
        return 1


if __name__ == "__main__":  # pragma: no cover
    sys.exit(main())
