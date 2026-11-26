"""Command-line interface.

    v3lum                          interactive console (type anything to investigate it)
    v3lum scan <input...>          detect, collect, pivot, correlate, report (-i FILE: batch input)
    v3lum detect <input...>        show how inputs are recognized
    v3lum run <module> <input>     run a single module (never above the configured/explicit mode)
    v3lum modules / info <module>  catalog of collectors and the policy that applies to them
    v3lum extract <file|->         pull IOCs out of text (defanged by default; --scan investigates)
    v3lum feedback / cache / config
    + every command registered in ``v3lum.commands`` (cases, data, links, doctor, keys, org, scope...)

Every execution path (scan, run, the shell, extract --scan, scan -i) goes through the single policy
gate (P327, AR15) and the rules of engagement: ACTIVE needs ``--authorized REF`` and ``--scope FILE``
(A7), personal identifiers need ``--purpose`` and ``--ticket`` (AR16), scans default to TLP:AMBER (A2).
"""

from __future__ import annotations

import argparse
import difflib
import json
import os
import sys
from typing import Any

from rich.text import Text

from v3lum import __version__

EPILOG = """examples:
  v3lum scan suspicious-domain.com
  v3lum scan john.doe@acme.com --purpose "phishing report" --ticket INC-4211 -f html,md,stix
  v3lum scan 185.220.101.4 44d88612fea8a8f36de82e1278abb02f CVE-2024-3400
  v3lum scan "user:johndoe" -M username_check --purpose "fraud case" --ticket FR-77
  v3lum scan acme.com --mode light            # also fetch the site itself (normal visitor traffic)
  v3lum scan 10.0.0.5 --mode active --authorized PT-2026-042 --scope scope.toml   # only with permission
  v3lum extract report.txt                    # IOCs defanged (--no-defang for raw values)
  v3lum --tor scan target.onion
"""

#: Commands implemented in this file (everything else comes from the ``v3lum.commands`` registry).
INLINE = ("version", "detect", "run", "scan", "modules", "info", "extract", "feedback", "cache", "config", "shell")
#: ``--tlp`` choices (FIRST TLP 2.0, A2).
_TLP_CHOICES = ("clear", "green", "amber", "amber+strict", "red")


def add_engagement_flags(parser: argparse.ArgumentParser, *, single: bool = False, scan: bool = False) -> None:
    """The rules-of-engagement and case-metadata flags shared by scan, batch input (-i), run and
    extract --scan (A2, A3, A4, A7, A8, A9, AR16, P376). ``single``: ``v3lum run``; ``scan``: adds
    --incident-victim."""
    from v3lum.app import BREACH_SCOPES, LEGAL_BASES, LICENCE_PROFILES, PRESETS

    g = parser.add_argument_group("rules of engagement and case metadata")
    g.add_argument(
        "-m", "--mode", choices=["passive", "light", "active"], type=str.lower,
        help="passive (default: setting mode) | light (touch the target like a visitor) | active (intrusive: --authorized REF and --scope FILE)",
    )
    g.add_argument("--tlp", choices=_TLP_CHOICES, type=str.lower, help="TLP of the inputs (default: setting tlp, amber); red = offline and internal sources only")
    g.add_argument("--authorized", metavar="REF", help="authorization reference of the engagement (required for --mode active; never a placeholder)")
    g.add_argument("--scope", metavar="FILE", help="scope file bound to --authorized REF (required for --mode active; docs/ROE.md)")
    g.add_argument(
        "--preset", choices=PRESETS,
        help="quick (the effective default set) | deep (every ready module that passes the gates)" + ("; `run` selects its module explicitly" if single else ""),
    )
    g.add_argument("--purpose", metavar="TEXT", help="why this investigation needs the data (required for personal identifiers, LGPD)")
    g.add_argument("--ticket", metavar="TEXT", help="ticket / case reference (required for personal identifiers)")
    g.add_argument("--legal-basis", choices=LEGAL_BASES, metavar="CODE", help=f"legal basis code (docs/LEGAL.md): {', '.join(LEGAL_BASES)}")
    g.add_argument("--breach-scope", choices=BREACH_SCOPES, help="own (default: verified org domains only) | all (also typed seed addresses; needs --purpose)")
    g.add_argument("--expand-personal", action="store_true", help="auto-investigate personal identifiers found in text (needs --purpose and --ticket)")
    g.add_argument("--allow-unknown", action="store_true", help="allow unknown-tier providers (TLP:CLEAR/GREEN only, IOC values only)")
    g.add_argument("--licence-profile", choices=LICENCE_PROFILES, help="corporate (default) | research (needs a recorded legal basis)")
    g.add_argument("--egress-override", metavar="REASON", help="let LIGHT/ACTIVE contact a hostile host from the current egress (recorded in the audit)")
    g.add_argument("--show-personal", action="store_true", help="show personal identifiers unmasked in this case (recorded)")
    g.add_argument("--no-defang", action="store_true", help="print indicators refanged in the terminal report")
    g.add_argument("--confirm-url", action="append", metavar="URL", help="fetch this per-recipient token URL anyway (repeatable; A7 BR15)")
    if scan:
        g.add_argument("--incident-victim", action="store_true", help="the typed seeds are incident victims (posture; needs --purpose)")


def _registered_commands() -> dict[str, Any]:
    from v3lum.commands import load_commands

    return load_commands()


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
    g.add_argument("--proxy", metavar="URL", help="route third-party traffic through a proxy (http://, socks5h://)")
    g.add_argument("--tor", action="store_true", help="route third-party traffic through Tor (socks5h://127.0.0.1:9050)")
    g.add_argument("--offline", action="store_true", help="no network: offline modules only")
    g.add_argument("--no-cache", action="store_true", help="do not read or write the HTTP cache")

    sub = p.add_subparsers(dest="command", metavar="<command>")

    s = sub.add_parser("scan", help="investigate one or more inputs (auto-detected)", epilog=EPILOG, formatter_class=argparse.RawDescriptionHelpFormatter)
    s.add_argument("inputs", nargs="*", help="anything: email, domain, IP, URL, hash, phone, @user, CNPJ, wallet, CVE, file path... (TYPE:value forces a type)")
    s.add_argument("-i", "--input-file", metavar="FILE", help="batch input: read inputs from a file, one per line ('-' = stdin)")
    s.add_argument("-t", "--type", help="force the entity type of every input (see `v3lum detect`)")
    s.add_argument("-d", "--depth", type=int, help="pivot depth: 0 = only inputs, 1 = + discovered entities (default), 2+ = deeper")
    add_engagement_flags(s, scan=True)
    s.add_argument("-M", "--modules", help="run only these modules (comma separated; they still pass every gate)")
    s.add_argument("-x", "--exclude", help="skip these modules (comma separated)")
    s.add_argument("-c", "--categories", help="only modules of these categories (comma separated)")
    s.add_argument("--all-modules", action="store_true", help="alias of --preset deep (also run opt-in modules)")
    s.add_argument("--max-entities", type=int, help="budget of investigated entities (default 150)")
    s.add_argument("--threads", type=int, help="parallel module runs (default 12)")
    s.add_argument("--timeout", type=float, default=0.0, help="scan deadline in seconds (overrides setting scan_deadline; partial results)")
    s.add_argument("-f", "--format", help="report formats: html,md,json,stix (default from config)")
    s.add_argument("-o", "--out", help="report directory (default: the case folder)")
    s.add_argument("--no-evidence", action="store_true", help="do not save raw evidence files (the LIGHT/ACTIVE request ledger is always written)")
    s.add_argument("--full", action="store_true", help="print everything in the terminal report")
    s.add_argument("--json", action="store_true", help="print the case as JSON on stdout (machine mode)")
    s.add_argument("--no-feedback", action="store_true", help="do not ask 'did this make sense?'")
    s.add_argument("-y", "--yes", action="store_true", help="assume yes for prompts (never replaces --authorized/--scope/--purpose)")
    s.add_argument("--fail-on", choices=["low", "medium", "high", "critical"], help="exit code 3 if risk >= level (automation)")

    d = sub.add_parser("detect", help="show how inputs are recognized")
    d.add_argument("inputs", nargs="+")
    d.add_argument("--json", action="store_true")

    r = sub.add_parser("run", help="run a single module on an input (through the policy gate; never escalates the mode)")
    r.add_argument("module")
    r.add_argument("input")
    r.add_argument("-t", "--type", help="force entity type")
    add_engagement_flags(r, single=True)
    r.add_argument("--json", action="store_true")

    m = sub.add_parser("modules", help="list modules, their sources and the effective default set")
    m.add_argument("-c", "--category", help="filter by category")
    m.add_argument("-s", "--search", help="text search")
    m.add_argument("-t", "--type", help="modules accepting this entity type")
    m.add_argument("--ready", action="store_true", help="only modules ready to run (keys, packages)")
    m.add_argument("--categories", action="store_true", help="list categories")
    m.add_argument("--json", action="store_true")

    i = sub.add_parser("info", help="details of a module and the policy that applies to it")
    i.add_argument("module")

    ex = sub.add_parser("extract", help="extract IOCs from a text file or stdin (defanged by default)")
    ex.add_argument("source", nargs="?", default="-", help="file path or '-' for stdin")
    ex.add_argument("--defang", action="store_true", help="print defanged values (the default; kept for compatibility)")
    ex.add_argument("-t", "--types", help="only these types (comma separated)")
    ex.add_argument("--json", action="store_true", help="raw values as JSON (with --scan: the case)")
    ex.add_argument("--scan", action="store_true", help="investigate the extracted IOCs (pivots of the text: passive only, personal values listed for selection)")
    add_engagement_flags(ex)

    fb = sub.add_parser("feedback", help="feedback statistics and source reliability")
    fb.add_argument("--json", action="store_true")

    ca = sub.add_parser("cache", help="HTTP cache")
    casub = ca.add_subparsers(dest="cache_cmd", metavar="<action>")
    casub.add_parser("stats", help="cache statistics (size, oldest entry, top hosts)")
    cc = casub.add_parser("clear", help="clear the cache")
    cc.add_argument("--host", help="only entries for this host")

    cfg = sub.add_parser("config", help="show or change settings")
    cfgsub = cfg.add_subparsers(dest="config_cmd", metavar="<action>")
    cfgsub.add_parser("show", help="current settings (core and module settings)")
    cfs = cfgsub.add_parser("set", help="change a setting")
    cfs.add_argument("key")
    cfs.add_argument("value")
    cfgsub.add_parser("path", help="where files are stored")

    _add_registered(sub)

    sub.add_parser("shell", help="interactive console (default when no command is given)")
    sub.add_parser("version", help="print version")
    return p


def _add_registered(sub: Any) -> None:
    """One sub-parser per registered command (``v3lum.commands``). A command whose
    ``add_arguments`` fails is left out and recorded for doctor (never fatal)."""
    from v3lum.commands import note_error

    for name, spec in sorted(_registered_commands().items()):
        if name in INLINE:
            continue
        try:
            probe = argparse.ArgumentParser(prog=f"v3lum {name}", add_help=False)
            spec.add_arguments(probe)
        except Exception as exc:  # noqa: BLE001 - a broken command module never breaks the CLI
            note_error(spec.module or name, f"{name}: add_arguments failed: {type(exc).__name__}: {exc}")
            continue
        cp = sub.add_parser(
            name, help=spec.help, aliases=list(spec.aliases), description=spec.description or spec.help,
            formatter_class=argparse.RawDescriptionHelpFormatter,
        )
        spec.add_arguments(cp)
        cp.set_defaults(registered_command=name)


def _split(value: str | None) -> list[str]:
    return [v.strip() for v in (value or "").split(",") if v.strip()]


def _read_inputs(args: argparse.Namespace) -> list[str]:
    items = list(args.inputs or [])
    if getattr(args, "input_file", None):
        if args.input_file == "-":
            lines = sys.stdin.read().splitlines()
        else:
            from v3lum.app import UserError

            try:
                with open(args.input_file, encoding="utf-8") as src:
                    lines = src.read().splitlines()
            except OSError as exc:
                raise UserError(f"cannot read the input file: {exc.strerror or exc}") from None
        for line in lines:
            line = line.strip()
            if line and not line.startswith("#"):
                items.append(line)
    if items == ["-"]:
        items = [sys.stdin.read()]
    return items


def engagement_kwargs(args: argparse.Namespace) -> dict[str, Any]:
    """ScanRequest keyword arguments of the shared engagement flags (missing flags -> defaults)."""
    from v3lum.app import UserError

    egress = getattr(args, "egress_override", None)
    if egress is not None and not str(egress).strip():
        raise UserError("--egress-override needs a reason (it is recorded in the case audit and the report banner)")
    authorized = getattr(args, "authorized", None)
    if authorized is not None and not str(authorized).strip():
        raise UserError("--authorized needs a non-empty authorization reference (A7), e.g. --authorized PT-2026-042")
    return {
        "tlp": getattr(args, "tlp", None) or "",
        "authorization_ref": str(getattr(args, "authorized", None) or "").strip(),
        "scope_path": str(getattr(args, "scope", None) or "").strip(),
        "preset": getattr(args, "preset", None) or "",
        "purpose": str(getattr(args, "purpose", None) or "").strip(),
        "ticket": str(getattr(args, "ticket", None) or "").strip(),
        "legal_basis": getattr(args, "legal_basis", None) or "",
        "breach_scope": getattr(args, "breach_scope", None) or "own",
        "expand_personal": bool(getattr(args, "expand_personal", False)),
        "allow_unknown": bool(getattr(args, "allow_unknown", False)),
        "licence_profile": getattr(args, "licence_profile", None) or "",
        "egress_override": str(egress or "").strip(),
        "show_personal": bool(getattr(args, "show_personal", False)),
        "no_defang": bool(getattr(args, "no_defang", False)),
        "confirmed_urls": [u for u in (getattr(args, "confirm_url", None) or []) if str(u).strip()],
        "incident_victim": bool(getattr(args, "incident_victim", False)),
    }


def scan_request(args: argparse.Namespace, app: Any, inputs: list[str], *, path: str = "scan") -> Any:
    """The ScanRequest of a ``scan`` namespace (shared by the CLI, batch input and the shell)."""
    from v3lum.app import ScanRequest, entity_type_or_none
    from v3lum.core.models import Opsec

    cfg = app.config
    return ScanRequest(
        inputs=inputs,
        etype=entity_type_or_none(getattr(args, "type", None)),
        mode=Opsec.parse(getattr(args, "mode", None) or str(cfg.get("mode") or "passive")),
        depth=args.depth if getattr(args, "depth", None) is not None else int(cfg.get("depth")),
        include=set(_split(getattr(args, "modules", None))),
        exclude=set(_split(getattr(args, "exclude", None))),
        categories=set(_split(getattr(args, "categories", None))),
        all_modules=bool(getattr(args, "all_modules", False)),
        max_entities=getattr(args, "max_entities", None) or int(cfg.get("max_entities")),
        threads=getattr(args, "threads", None) or int(cfg.get("threads")),
        timeout_total=float(getattr(args, "timeout", 0.0) or 0.0),
        formats=_split(args.format) if getattr(args, "format", None) is not None else list(cfg.get("report_formats")),
        out_dir=getattr(args, "out", None) or "",
        save_evidence=not getattr(args, "no_evidence", False),
        assume_yes=bool(getattr(args, "yes", False)),
        interactive=not getattr(args, "json", False) and not getattr(args, "yes", False),
        path=path,
        **engagement_kwargs(args),
    )


def make_app(args: argparse.Namespace, console: Any) -> Any:
    from v3lum.app import TOR_PROXY, App

    proxy = TOR_PROXY if args.tor else (args.proxy or None)
    verbosity = 0 if args.quiet else 1 + int(args.verbose or 0)
    return App(console, verbosity=verbosity, fx=not args.no_fx, proxy=proxy, offline=args.offline, no_cache=args.no_cache, debug=args.debug)


def _show_case_and_follow_up(app: Any, data: dict[str, Any], req: Any, *, full: bool = False) -> None:
    """Render the case, then offer the AR07 pick of personal identifiers found in text (TTY)."""
    app.show_case(data, full=full)
    follow = app.follow_up_personal(data, req)
    if follow is not None:
        app.show_case(app.scan(follow), full=full)


def dispatch(args: argparse.Namespace, app: Any, console: Any, *, path: str | None = None) -> int:  # noqa: C901 - command router
    """Run one parsed command. ``path`` is the execution path of the caller ('shell' from the
    interactive console; default: 'scan', or 'batch' with ``scan -i``)."""
    from v3lum.app import UserError, entity_type_or_none, level_at_least
    from v3lum.core import detect as det
    from v3lum.core.module import CATEGORIES, REGISTRY
    from v3lum.ui.render import render_detections

    cmd = args.command
    registered = getattr(args, "registered_command", None)
    if registered and cmd not in INLINE:
        from v3lum.commands import lookup

        spec = lookup(registered) or lookup(cmd)
        if spec is None:
            raise UserError(f"unknown command {cmd!r}")
        return int(spec.run(args, app, console) or 0)

    if cmd == "version":
        console.print(f"V3LUM {__version__}")
        return 0

    if cmd == "scan":
        inputs = _read_inputs(args)
        if not inputs:
            raise UserError("give at least one input, e.g.  v3lum scan example.com")
        if args.json:
            app.verbosity = 0
            app.machine = True
        exec_path = "batch" if args.input_file else (path or "scan")
        req = scan_request(args, app, inputs, path=exec_path)
        data = app.scan(req)
        if args.json:
            sys.stdout.write(json.dumps(data, ensure_ascii=False, indent=2, default=str) + "\n")
        else:
            _show_case_and_follow_up(app, data, req, full=args.full)
            if app.config.get("feedback") and not args.no_feedback and not args.yes:
                app.ask_feedback(data)
        if args.fail_on and level_at_least(data["summary"]["risk_level"], args.fail_on):
            return 3
        return 0

    if cmd == "detect":
        out = []
        for raw in args.inputs:
            value = app.scrub_input(raw)
            found = det.detect(value)
            if args.json:
                out.append({"input": value, "detections": [{"type": d.type.value, "value": d.value, "confidence": d.confidence, "reason": d.reason} for d in found]})
            else:
                render_detections(console, value, found)
        if args.json:
            sys.stdout.write(json.dumps(out, ensure_ascii=False, indent=2) + "\n")
        return 0

    if cmd == "run":
        from v3lum.app import ScanRequest
        from v3lum.core.models import Opsec

        if args.json:
            app.machine = True
        req = ScanRequest(
            inputs=[args.input],
            etype=entity_type_or_none(args.type),
            mode=Opsec.parse(args.mode or str(app.config.get("mode") or "passive")),
            interactive=not args.json,
            path="run",
            **{k: v for k, v in engagement_kwargs(args).items() if k != "incident_victim"},
        )
        out = app.run_single(args.module, args.input, req.etype, request=req)
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
            member = app.default_membership()
            data = []
            for cls in sorted(REGISTRY.values(), key=lambda m: m.name):
                item = cls.describe()
                in_default, code, reason = member.get(cls.name, (False, "", ""))
                item["default_set"] = {"member": in_default, "reason_code": code, "reason": reason}
                data.append(item)
            sys.stdout.write(json.dumps(data, indent=2, default=str) + "\n")
            return 0
        console.print(app.modules_table(args.category or "", args.search or "", entity_type_or_none(args.type), args.ready))
        return 0

    if cmd == "info":
        console.print(app.module_info(args.module))
        return 0

    if cmd == "extract":
        return _extract(args, app, console)

    if cmd == "feedback":
        summary = app.store.feedback_summary()
        if args.json:
            sys.stdout.write(json.dumps(summary, indent=2, default=str) + "\n")
            return 0
        from rich import box
        from rich.table import Table

        v = summary.get("verdicts") or {}
        console.print(Text.assemble(("verdicts  ", "v.accent"), (f"yes {v.get('yes', 0)} · partial {v.get('partial', 0)} · no {v.get('no', 0)}", "v.text")))
        t = Table(box=box.SIMPLE, header_style="v.dim", title="[v.accent]module reliability (from your feedback)[/]", title_justify="left")
        t.add_column("module", style="v.module")
        t.add_column("right", justify="right")
        t.add_column("wrong", justify="right")
        t.add_column("weight", justify="right")
        for row in summary.get("modules") or []:
            t.add_row(str(row.get("module", "")), str(row.get("correct", 0)), str(row.get("wrong", 0)), f"{float(row.get('reliability', 0) or 0):.2f}")
        console.print(t)
        return 0

    if cmd == "cache":
        from v3lum import paths
        from v3lum.core.http import HttpCache

        try:
            max_age = float(app.config.get("cache_max_age_days") or 0) or None
        except (TypeError, ValueError):
            max_age = None
        cache = HttpCache(str(paths.cache_file()), max_age_days=max_age)
        if (args.cache_cmd or "stats") == "clear":
            n = cache.clear(host=args.host)
            console.print(Text(f"[✓] {n} cached responses removed", style="v.ok"))
        else:
            st = cache.stats()
            console.print(Text(f"{st['entries']} responses · {st['bytes'] // 1024} KB · {st['path']}", style="v.text"))
            oldest = st.get("oldest") or ""
            console.print(Text(f"oldest entry: {oldest or 'none'} · rows older than {app.config.get('cache_max_age_days')} days are deleted (A10)", style="v.dim"))
            if st.get("last_prune"):
                console.print(Text(f"last prune: {st['last_prune']}", style="v.dim"))
            for host, n in st["top_hosts"]:
                console.print(Text.assemble((f"  {n:6} ", "v.dim"), (host or "?", "v.entity")))
        return 0

    if cmd == "config":
        return _config(args, app, console)

    raise UserError(f"unknown command {cmd!r}")


def _extract(args: argparse.Namespace, app: Any, console: Any) -> int:
    """``v3lum extract``: IOCs of a file or stdin, scrubbed first (P145 cond 5), defanged in the
    terminal by default (P172 cond 11); ``--scan`` investigates them as the pivots of ONE text_blob
    seed, so they keep their text provenance (passive only, personal values listed for selection)."""
    from v3lum.app import ScanRequest, UserError
    from v3lum.core import sanitize
    from v3lum.core.entities import defang
    from v3lum.core.models import Opsec

    if args.source == "-":
        text = sys.stdin.read()
    else:
        if not os.path.isfile(args.source):
            raise UserError(f"file not found: {args.source}")
        with open(args.source, encoding="utf-8", errors="replace") as fh:
            text = fh.read(20 * 1024 * 1024)
    if getattr(args, "json", False):
        app.machine = True
    hits: list[dict[str, str]] = []
    clean = sanitize.scrub_text(text, hits=hits) if text else text
    app._report_scrub(hits)
    types = set(_split(args.types)) or None
    ents = app.extract(clean, types)
    if args.scan:
        if not ents:
            raise UserError("no IOCs found")
        blob = "\n".join(e.value for e in ents) if types else clean
        req = ScanRequest(
            inputs=[f"text_blob:{blob}"],
            mode=Opsec.parse(getattr(args, "mode", None) or str(app.config.get("mode") or "passive")),
            depth=int(app.config.get("depth")),
            max_entities=int(app.config.get("max_entities")),
            threads=int(app.config.get("threads")),
            formats=list(app.config.get("report_formats")),
            interactive=not getattr(args, "json", False),
            path="extract",
            **{k: v for k, v in engagement_kwargs(args).items() if k != "incident_victim"},
        )
        if getattr(args, "json", False):
            app.verbosity = 0
        data = app.scan(req)
        if getattr(args, "json", False):
            sys.stdout.write(json.dumps(data, ensure_ascii=False, indent=2, default=str) + "\n")
        else:
            _show_case_and_follow_up(app, data, req)
        return 0
    if args.json:
        sys.stdout.write(json.dumps([{"type": e.type.value, "value": e.value} for e in ents], indent=2) + "\n")
        return 0
    raw = bool(getattr(args, "no_defang", False)) and not args.defang
    for e in ents:
        val = e.value if raw or e.type.value not in ("url", "domain", "email", "ipv4", "ipv6") else defang(e.value)
        console.print(Text.assemble((f"{e.type.value:18}", "v.type"), (val, "v.entity")))
    console.print(Text(f"\n{len(ents)} indicators" + ("" if raw else " (defanged: --no-defang for raw values)"), style="v.dim"))
    return 0


def _shown_setting(value: Any) -> str:
    """A setting value (or a refusal naming it) as printed: URL passwords (``proxy``,
    ``proxy_light``, ``proxy_active`` = ``http://user:pass@host``), key-like URL parameters and every
    registered secret masked by the central redactor (AR01); control characters dropped."""
    from v3lum.core.redact import redact_text

    return "".join(ch for ch in redact_text(str(value)) if ch.isprintable() or ch in "\t")


def _config(args: argparse.Namespace, app: Any, console: Any) -> int:
    """``v3lum config show|set|path``: every setting of SETTINGS_META (core and module settings);
    values are printed through the central redactor (a proxy URL never shows its password)."""
    from v3lum import paths
    from v3lum.app import UserError
    from v3lum.config import SETTINGS_META

    action = args.config_cmd or "show"
    if action == "set":
        try:
            app.config.set(args.key, args.value)
        except (KeyError, ValueError) as exc:
            close = difflib.get_close_matches(str(args.key), list(SETTINGS_META), n=3)
            hint = f" Did you mean: {', '.join(close)}?" if close else ""
            raise UserError(f"{_shown_setting(exc)}.{hint} Every setting: `v3lum config show`") from None
        console.print(Text(f"[✓] {args.key} = {_shown_setting(repr(app.config.get(args.key)))}", style="v.ok"))
        return 0
    if action == "path":
        console.print(Text(
            f"home   {paths.home()}\nconfig {paths.config_file()}\ndb     {paths.db_file()}\ncache  {paths.cache_file()}\n"
            f"cases  {paths.cases_dir()}\nplugins {paths.plugins_dir()}",
            style="v.text",
        ))
        return 0
    specs = sorted(SETTINGS_META.items(), key=lambda kv: (kv[1].owner != "core", kv[1].owner, kv[0]))
    owner = None
    for name, spec in specs:
        if spec.owner != owner:
            owner = spec.owner
            if owner != "core":
                console.print(Text(f"\n▌module {owner}", style="v.accent"))
        console.print(Text.assemble((f"{name:24} ", "v.module"), (_shown_setting(repr(app.config.get(name))), "v.text"), (f"  {spec.description}" if spec.description else "", "v.ghost")), soft_wrap=True)
    return 0


def main(argv: list[str] | None = None) -> int:
    os.umask(0o077)  # AR03: every file V3LUM writes is owner-only, whoever opens it
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
        if not getattr(args, "json", False) and args.command not in ("version",):
            app.startup_reminder()  # A10: at most once a day
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
