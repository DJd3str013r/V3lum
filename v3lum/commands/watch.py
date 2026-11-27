"""``v3lum watch``: foreground brand/domain watch over the org profile (P030, A14). No daemon.

* ``watch [--once] [--max-runtime SECONDS] [--max-alerts N] [--tlp LEVEL] [--sources NAMES] [--no-certstream]``
  - runs :class:`v3lum.core.watch.Watcher` in the foreground: polling cycles over the registered
  ``watch_source`` modules (through the policy gate, path 'watch') every setting ``watch_interval``
  seconds, plus the optional CertStream consumer (extra ``v3lum[watch]``; reported unavailable without
  it, never an error). ``--once`` runs one bounded polling cycle and exits (cron/systemd timers);
  Ctrl+C stops at once. One terminal line per new alert (above 200 per hour a summary line replaces the
  rest), JSONL in ``~/.v3lum/watch/alerts-<date>.jsonl`` and the day's watch case in the case DB.
* ``watch rules`` - the rules derived from the org profile (natural persons never become rules), with
  mutes and per-rule precision from analyst votes (P325).
* ``watch mute <rule|domain>`` / ``watch unmute <rule|domain>`` - mutes per rule id or registrable domain.
* ``watch alerts [--limit N] [--rule ID]`` - recent alerts; ``watch vote <alert id> right|wrong|partly``
  records a P325 vote on an alert (the rule's precision follows).
* ``watch status [--probe]`` - CertStream availability (and, with ``--probe``, one handshake that sends
  nothing) and the polling-source status (:func:`v3lum.core.watch.health`; doctor shows the same data).
"""

from __future__ import annotations

from typing import Any

from rich import box
from rich.table import Table
from rich.text import Text

from v3lum.commands import command

__all__ = ["Watch"]

_TLP_CHOICES = ("clear", "green", "amber", "amber+strict", "red")


def _clean(value: Any) -> str:
    try:
        from v3lum.ui.safe import clean_text

        return clean_text(value)
    except Exception:  # noqa: BLE001 - WP14 helper unavailable: drop control characters here
        return "".join(ch for ch in str(value or "") if ch in "\n\t" or (ord(ch) >= 32 and not 0x7F <= ord(ch) <= 0x9F))


def _user_error(message: str) -> Exception:
    from v3lum.app import UserError

    return UserError(message)


def _print(console: Any, text: str, style: str = "v.text") -> None:
    console.print(Text(_clean(text), style=style), soft_wrap=True)


def _analyst(app: Any) -> str:
    fn = getattr(app, "analyst", None)
    if callable(fn):
        try:
            return str(fn() or "")
        except Exception:  # noqa: BLE001
            pass
    return str(app.config.get("analyst") or "").strip() or "unknown"


def _org(app: Any, rt: Any = None) -> Any:
    if rt is not None:
        try:
            return rt.org
        except Exception:  # noqa: BLE001 - org profile problems: no rules
            return None
    from v3lum.core import orgprofile

    return orgprofile.load_default(app.config)


def _tlp(app: Any, value: str | None) -> Any:
    from v3lum.core import tlp as _tlp_mod

    try:
        return _tlp_mod.parse(value or app.config.get("tlp") or "amber")
    except ValueError as exc:
        raise _user_error(str(exc)) from exc


def _split(value: str | None) -> list[str]:
    return [p.strip() for p in str(value or "").split(",") if p.strip()]


def _tlp_change(app: Any, level: Any, console: Any) -> dict[str, Any] | None:
    """A2: a watch TLP below the configured default ({os_user, analyst, at, from, to}), announced on
    the terminal and recorded by the watcher in the watch case's audit and each enrichment case's."""
    import datetime as _dt
    import getpass

    configured = _tlp(app, None)
    if not level < configured:
        return None
    try:
        user = getpass.getuser()
    except Exception:  # noqa: BLE001 - no login name (containers): still recorded
        user = "unknown"
    stamp = _dt.datetime.now(_dt.timezone.utc).isoformat(timespec="seconds")
    _print(console, f"[!] TLP lowered from {configured.label} to {level.label}: recorded in the audit of the watch case "
                    f"and of each enrichment case ({user}, {stamp})", "v.warn")
    return {"os_user": user, "analyst": _analyst(app), "at": stamp, "from": configured.value_str, "to": level.value_str}


def _defang(value: str) -> str:
    try:
        from v3lum.core.entities import defang

        return defang(value)
    except Exception:  # noqa: BLE001
        return str(value).replace(".", "[.]")


# --------------------------------------------------------------------------------------
# watch (the loop)
# --------------------------------------------------------------------------------------


def _run(args: Any, app: Any, console: Any) -> int:
    from v3lum.core import watch as W
    from v3lum.core.context import ScanOptions
    from v3lum.core.models import Opsec
    from v3lum.core.module import REGISTRY

    level = _tlp(app, getattr(args, "tlp", None))
    if args.max_runtime is not None and args.max_runtime <= 0:
        raise _user_error("--max-runtime takes a positive number of seconds")
    if args.max_alerts is not None and args.max_alerts < 0:
        raise _user_error("--max-alerts takes 0 (unlimited) or a positive number")
    sources = _split(getattr(args, "sources", None))
    unknown = [s for s in sources if s not in REGISTRY]
    if unknown:
        raise _user_error(f"unknown module(s) in --sources: {', '.join(unknown)} (v3lum watch status lists the polling sources)")
    not_sources = [s for s in sources if "watch_source" not in (getattr(REGISTRY[s], "tags", ()) or ())]
    if not_sources:
        raise _user_error(f"not a watch source (tag watch_source): {', '.join(not_sources)}")
    rt = app.runtime()
    prepare = getattr(app, "prepare_runtime", None)
    if callable(prepare):  # sightings lookup, case audit of the enrichment scans, execution path 'watch'
        prepare(rt, ScanOptions(mode=Opsec.PASSIVE, tlp=level.value_str), path="watch")
    org = _org(app, rt)
    change = _tlp_change(app, level, console)
    watcher = W.Watcher(
        rt, app.store, org, clock=rt.clock, tlp=level, out=lambda text, style: _print(console, text, style),
        sources=sources or None, certstream=not getattr(args, "no_certstream", False), tlp_change=change,
    )
    if not watcher.rules:
        if org is None or getattr(org, "is_empty", True):
            raise _user_error("no org profile: watch rules come only from it (v3lum org seed <domain> / v3lum org verify <domain>)")
        raise _user_error("the org profile yields no watch rule (brands, domains, CNPJ roots, card BINs or suppliers): v3lum org show")
    status = watcher.certstream_status(once=bool(args.once))
    head = Text.assemble(("◈ v3lum watch ", "v.accent"), (level.label, "v.accent"),
                         (f"  rules {len(watcher.rules)}  sources {len(watcher.watch_sources())}", "v.text"),
                         ("  foreground only (Ctrl+C stops; no daemon)", "v.dim"))
    console.print(head)
    cs_style = "v.ok" if status["state"] == "running" else "v.dim"
    _print(console, f"  certstream: {status['state']} - {status['detail']} ({status.get('kind')}, {status.get('disclosure')}, tier {status.get('tier')})", cs_style)
    report = watcher.run(once=bool(args.once), max_runtime=args.max_runtime, max_alerts=args.max_alerts)
    _summary(console, report)
    return 0


def _summary(console: Any, report: Any) -> None:
    for name, state in sorted(report.sources.items()):
        status = str(state.get("status") or "")
        style = "v.ok" if status in ("ok", "empty") else "v.warn"
        reason = str(state.get("reason") or "")
        _print(console, f"  source {name}: {status}" + (f" ({state.get('reason_code')}: {reason})" if status not in ("ok", "empty") else ""), style)
    if report.keywords_kept_local:
        _print(console, f"  [i] {report.keywords_kept_local} source run(s) skipped: brand keywords are never sent to a third-party source", "v.dim")
    stream = report.stream or {}
    if stream:
        _print(console, "  certstream: " + ", ".join(f"{k} {stream.get(k, 0)}" for k in (
            "received", "queued", "prefiltered", "dropped_queue", "oversize", "connects", "connect_errors", "rate_capped")), "v.dim")
    pruned = report.pruned or {}
    if any(pruned.values()):
        _print(console, "  retention: removed " + ", ".join(f"{v} {k.replace('_', ' ')}" for k, v in pruned.items() if v), "v.dim")
    enriched = [e for e in report.enriched if e.get("case_id")]
    if report.enriched:
        _print(console, f"  enriched {len(enriched)} hit(s) with a passive scan" + (": " + ", ".join(e["case_id"] for e in enriched[:10]) if enriched else ""), "v.text")
    if report.enrich_listed:
        total = len(report.enrich_listed) + int(getattr(report, "enrich_listed_more", 0) or 0)
        shown = ", ".join(_defang(d) for d in report.enrich_listed[:20]) + (f" ... ({total} in all)" if total > 20 else "")
        _print(console, f"  not enriched automatically (cap per hour): {shown} - run `v3lum scan <domain>` when needed", "v.warn")
    if getattr(report, "rejected", 0):
        _print(console, f"  [i] {report.rejected} hit(s) dropped: not a host name, URL or verified own-domain address "
                        "(people, phone numbers and third-party addresses are never watched)", "v.dim")
    for note in report.notes:
        if note:
            _print(console, f"  [i] {note}", "v.dim")
    why = {"once": "one cycle done (--once)", "max_runtime": "maximum runtime reached", "max_alerts": "maximum alerts reached",
           "interrupted": "interrupted", "no_rules": "no rules"}.get(report.stop_reason, report.stop_reason or "stopped")
    tail = f"  case {report.case_id}" if report.case_id and report.alerts else ""
    _print(console, f"[✓] watch stopped: {why} - {report.cycles} cycle(s), {report.alerts} new alert(s)"
                    f" ({report.summarized} summarized, {report.muted} muted, {report.known} already seen, {report.duplicates} duplicates){tail}",
           "v.ok")


# --------------------------------------------------------------------------------------
# rules / mutes / alerts / vote / status
# --------------------------------------------------------------------------------------


def _rules(app: Any, console: Any) -> int:
    from v3lum.core import watch as W

    org = _org(app)
    problems: list[str] = []
    rules = W.rules_from_profile(org, problems=problems)
    if not rules:
        _print(console, "no watch rule: the org profile has no brands, domains, CNPJ roots, card BINs or suppliers (v3lum org show)", "v.dim")
        return 0
    muted = W.mutes(app.store)
    muted_rules = {m["rule_id"] for m in muted if m["rule_id"]}
    try:
        precision = app.store.rule_precision()
    except Exception:  # noqa: BLE001 - feedback tables unavailable: no precision
        precision = {}
    t = Table(box=box.SIMPLE, header_style="v.dim", title="[v.accent]watch rules (from the org profile; local matching only)[/]", title_justify="left")
    for col in ("rule", "kind", "terms / domains", "permutations", "IOC types", "precision", "state"):
        t.add_column(col, overflow="fold")
    for rule in rules:
        prec = precision.get(rule.id)
        shown = ", ".join([*rule.terms[:4], *rule.domains[:3]])
        t.add_row(
            Text(_clean(rule.id), style="v.entity"), rule.kind, Text(_clean(shown)), str(len(rule.permutations)), ", ".join(rule.ioc_types),
            f"{prec[0]:.2f} ({prec[1]} votes)" if prec else "-", "muted" if rule.id in muted_rules else "active",
        )
    console.print(t)
    domains = [m["domain"] for m in muted if m["domain"]]
    if domains:
        _print(console, f"  muted domains: {', '.join(domains[:30])}", "v.dim")
    for note in problems:
        _print(console, f"  [i] {note}", "v.dim")
    _print(console, "  executives and other natural persons are never watch rules (A14)", "v.ghost")
    return 0


def _mute(app: Any, console: Any, target: str, *, undo: bool) -> int:
    from v3lum.core import watch as W

    rules = W.rules_from_profile(_org(app))
    try:
        if undo:
            removed = W.unmute(app.store, target, rules=rules)
            _print(console, f"[✓] unmuted {target}" if removed else f"[i] {target} was not muted", "v.ok" if removed else "v.dim")
            return 0
        rule_id, domain = W.mute(app.store, target, rules=rules)
    except ValueError as exc:
        raise _user_error(str(exc)) from exc
    _print(console, f"[✓] muted rule {rule_id}" if rule_id else f"[✓] muted domain {domain} (every rule)", "v.ok")
    return 0


def _alerts(app: Any, console: Any, args: Any) -> int:
    from v3lum.core import watch as W

    alerts = W.recent_alerts(app.store, limit=max(1, int(args.limit)), rule_id=str(args.rule or ""))
    if not alerts:
        _print(console, "no watch alert recorded", "v.dim")
        return 0
    for alert in alerts:
        _print(console, f"{alert.id}  {alert.line()[4:]}", "v.text")
    return 0


def _vote(app: Any, console: Any, args: Any) -> int:
    from v3lum.core import watch as W

    try:
        vote = W.vote_alert(app.store, args.alert_id, args.vote, analyst=_analyst(app), reason=args.reason)
    except ValueError as exc:
        raise _user_error(str(exc)) from exc
    _print(console, f"[✓] vote '{vote['vote']}' recorded on alert {vote['finding_id']} (rule {vote['rule_id']})", "v.ok")
    return 0


def _status(app: Any, console: Any, probe: bool) -> int:
    from v3lum.core import watch as W

    data = W.health(app.config, org=_org(app), probe=probe)
    cs = data["certstream"]
    state = "available" if cs.get("available") else "unavailable"
    reach = {True: "reachable", False: "could not verify", None: "not probed"}[cs.get("reachable")]
    _print(console, f"certstream: {state} - {cs.get('url')} ({cs.get('kind')}, {cs.get('disclosure')}, tier {cs.get('tier')}, "
                    f"allowed up to TLP:{str(cs.get('max_tlp') or '').upper()}) - {reach}: {cs.get('detail')}",
           "v.ok" if cs.get("reachable") else "v.dim")
    if not data["polling_sources"]:
        _print(console, "polling sources: none registered (modules tagged watch_source)", "v.warn")
    for src in data["polling_sources"]:
        last = f"; last cycle {src['last_status']} {src['last_at']}" if src.get("last_status") else ""
        ready = "ready" if src["ready"] else f"not ready ({src['reason']})"
        _print(console, f"source {src['module']} ({src['disclosure']}): {ready}{last}", "v.text" if src["ready"] else "v.warn")
    if data.get("rules") is not None:
        _print(console, f"rules: {data['rules']}  last cycle: {data.get('last_cycle') or '-'}  last run: {data.get('last_run') or '-'}", "v.dim")
    return 0


# --------------------------------------------------------------------------------------
# the command
# --------------------------------------------------------------------------------------


@command("watch", "foreground brand/domain watch: CT/NRD polling with first_seen diffing, optional CertStream (no daemon)")
class Watch:
    """Watch mode (P030): rules only from the org profile, local matching, capped passive enrichment."""

    @staticmethod
    def add_arguments(parser: Any) -> None:
        parser.add_argument("--once", action="store_true", help="one bounded polling cycle, then exit (cron/systemd timers)")
        parser.add_argument("--max-runtime", type=float, metavar="SECONDS", help="stop after this many seconds (default: setting watch_max_runtime, 8 h)")
        parser.add_argument("--max-alerts", type=int, metavar="N", help="stop after N new alerts (default: setting watch_max_alerts, 0 = unlimited)")
        parser.add_argument("--tlp", choices=_TLP_CHOICES, type=str.lower, help="TLP of the watch, its alerts and enrichment scans (default: setting tlp, amber)")
        parser.add_argument("--sources", metavar="MODULES", help="only these polling sources (comma separated watch_source modules)")
        parser.add_argument("--no-certstream", action="store_true", help="polling only (do not consume the CertStream firehose)")
        sub = parser.add_subparsers(dest="watch_cmd", metavar="<action>")
        sub.add_parser("rules", help="rules derived from the org profile (with mutes and precision)")
        mu = sub.add_parser("mute", help="mute a rule id or a registrable domain")
        mu.add_argument("target", help="rule id (v3lum watch rules) or domain")
        um = sub.add_parser("unmute", help="remove a mute")
        um.add_argument("target", help="rule id or domain")
        al = sub.add_parser("alerts", help="recent alerts")
        al.add_argument("--limit", type=int, default=50, help="how many (default 50)")
        al.add_argument("--rule", metavar="ID", help="only this rule")
        vo = sub.add_parser("vote", help="vote on an alert (P325: per-rule precision)")
        vo.add_argument("alert_id")
        vo.add_argument("vote", choices=["right", "wrong", "partly"])
        vo.add_argument("--reason", help="wrong/partly only: benign_infra, wrong_entity, outdated, wrong_type, other")
        st = sub.add_parser("status", help="CertStream availability and polling-source status")
        st.add_argument("--probe", action="store_true", help="one CertStream handshake (nothing is sent)")

    @staticmethod
    def run(args: Any, app: Any, console: Any) -> int:
        action = getattr(args, "watch_cmd", None)
        if action is None:
            return _run(args, app, console)
        if action == "rules":
            return _rules(app, console)
        if action in ("mute", "unmute"):
            return _mute(app, console, args.target, undo=action == "unmute")
        if action == "alerts":
            return _alerts(app, console, args)
        if action == "vote":
            return _vote(app, console, args)
        if action == "status":
            return _status(app, console, bool(getattr(args, "probe", False)))
        raise _user_error(f"unknown watch action {action!r}")
