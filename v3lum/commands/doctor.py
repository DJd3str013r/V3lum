"""``v3lum doctor``: environment, dependencies, permissions, network and keys (the v1 table, moved).

Changes from the v1 ``App.doctor`` table (WP18; wave 5 extends this file with ``--licences``,
``--egress`` and the per-source health checks of P337):

* reachability probes go only to providers whose sources pass the licence profile (P377 cond 2,
  A1 phase-0 fix): each probe names the registry source it exercises (``shodan.internetdb`` for
  ``internetdb.shodan.io``, ``crtsh.search`` for ``crt.sh``) or, for a data-free endpoint
  (``api.github.com/zen``), needs at least one allowed source of its provider. The verdict comes from
  ``licence.evaluate_source`` with the licence state and profile of a ``policy.make_context(...,
  path='doctor')`` context, so no ``internetdb.shodan.io`` call happens under the default corporate
  profile unless a licence_allow entry (or a research basis) clears that source. An unregistered
  probe host counts as 'unknown' terms and is never contacted. The core DoH resolver is not a
  source and is always checked;
* permission warnings from ``paths.check_permissions()`` (A10/AR03: 0700 directories, 0600 files);
* import errors of the command modules (``v3lum.commands.load_errors()``);
* the licence profile with its allow-list warnings (entries expiring within 30 days, P377 cond 5),
  provider quota state (exhausted budgets and provider signals, P334 cond 10) and the org profile
  summary (entries, verified domains, strict validation problems; A11).

``App.doctor`` delegates here (:func:`doctor_table`).
"""

from __future__ import annotations

import platform
import sys
from dataclasses import dataclass
from typing import Any
from urllib.parse import urlsplit

from rich import box
from rich.table import Table
from rich.text import Text

from v3lum import __version__, paths
from v3lum.commands import command
from v3lum.core.http import HttpError

__all__ = ["PROBES", "Doctor", "Probe", "doctor_table", "probe_allowed"]

#: How many permission problems doctor prints (the rest is counted).
MAX_PERMISSION_LINES = 8
#: Statuses that mean "the host answered but refused": a probe reads them as 'could not verify'
#: (team rule 5), never as reachable or absent.
_REFUSED_STATUSES = frozenset({401, 403, 407, 429, 430, 451})


@dataclass(frozen=True)
class Probe:
    """One reachability probe: ``source`` is the registry source id the request exercises ('' = a
    data-free endpoint: at least one allowed source of the host's provider is enough)."""

    url: str
    source: str = ""

    @property
    def host(self) -> str:
        return (urlsplit(self.url).hostname or "").lower()


#: The v1 probes, each bound to the registry source whose terms decide whether it may run.
PROBES: tuple[Probe, ...] = (
    Probe("https://internetdb.shodan.io/1.1.1.1", "shodan.internetdb"),
    Probe("https://crt.sh/?q=example.com&output=json", "crtsh.search"),
    Probe("https://api.github.com/zen", ""),
)

_OPTIONAL_PACKAGES = (
    ("phonenumbers", "phone parsing"),
    ("dns", "system DNS (dnspython)"),
    ("PIL", "image EXIF"),
    ("pypdf", "PDF metadata"),
    ("socks", "Tor/SOCKS proxy"),
)


def _clean(value: Any) -> str:
    try:
        from v3lum.ui.safe import clean_text

        return clean_text(value)
    except Exception:  # noqa: BLE001 - WP14 helper unavailable: drop control characters here
        return "".join(ch for ch in str(value or "") if ch in "\n\t" or (ord(ch) >= 32 and not 0x7F <= ord(ch) <= 0x9F))


class _DoctorProbe:
    """Plain core helper class (no module metadata): a doctor request scope (v1 behaviour)."""

    name = "doctor"
    cache_ttl = 0
    min_interval = 0


def probe_allowed(probe: Probe, pctx: Any) -> tuple[bool, str]:
    """(allowed, reason) for one probe under the licence profile of ``pctx`` (a doctor-path
    ``policy.PolicyContext``). Fail closed: an unregistered host or source is never probed."""
    from v3lum.core import licence as _licence

    reg = getattr(pctx, "registry", None)
    provider = reg.provider_for_host(probe.host) if reg is not None else None
    if provider is None:
        return False, f"skipped: {probe.host} is not in the provider registry (unknown terms, licence profile {pctx.licence_profile})"
    plan = _licence.key_plan_lookup(pctx.config) if pctx.config is not None else None

    def verdict(source: Any) -> Any:
        return _licence.evaluate_source(
            source, provider, profile=pctx.licence_profile, now=pctx.now, state=pctx.licence, key_plan=plan, keys=pctx.keys,
            source_id=str(getattr(source, "id", "") or probe.source),
        )

    if probe.source:
        source = reg.source(probe.source)
        if source is None:
            return False, f"skipped: source {probe.source} is not registered (unknown terms)"
        result = verdict(source)
        return result.allowed, result.reason
    verdicts = [verdict(s) for s in provider.sources.values()]
    allowed = [v for v in verdicts if v.allowed]
    if allowed:
        return True, allowed[0].reason
    if not verdicts:
        return False, f"skipped: provider {provider.id} has no registered source (unknown terms)"
    return False, verdicts[0].reason


def _policy_context(app: Any, rt: Any) -> Any:
    from v3lum.core import policy
    from v3lum.core.context import ScanOptions

    return policy.make_context(rt, ScanOptions(offline=bool(getattr(app, "offline", False))), path="doctor")


def doctor_table(app: Any) -> Table:
    """The doctor table (see the module docstring)."""
    from v3lum.core.module import REGISTRY, load_errors, package_available

    t = Table(box=box.SIMPLE_HEAVY, header_style="v.dim", expand=True, title="[v.accent]✚ doctor[/]", title_justify="left")
    t.add_column("check", style="v.text", no_wrap=True)
    t.add_column("result", overflow="fold")

    def row(name: str, ok: bool | None, detail: str) -> None:
        style = "status.ok" if ok else ("v.warn" if ok is None else "status.error")
        mark = "[+]" if ok else ("[~]" if ok is None else "[x]")
        t.add_row(name, Text(f"{mark} {_clean(detail)}", style=style))

    row("python", sys.version_info >= (3, 10), f"{platform.python_version()} ({sys.executable})")
    row("v3lum", True, f"{__version__} · home {paths.home()}")
    for pkg, why in _OPTIONAL_PACKAGES:
        present = package_available(pkg)
        row(f"package {pkg}", True if present else None, why if present else f"missing (optional: {why}) — pip install 'v3lum[full]'")
    try:
        test = paths.home() / ".write_test"
        paths.secure_write_text(test, "ok")
        test.unlink()
        row("data dir", True, f"{paths.home()} writable")
    except OSError as exc:
        row("data dir", False, str(exc))
    _permissions(row)
    errs = load_errors()
    row("modules", not errs, f"{len(REGISTRY)} loaded" + (f", {len(errs)} failed: {', '.join(errs)}" if errs else ""))
    _commands(row)
    keys = app.config.keys()
    row("API keys", True if keys else None, f"{len(keys)} configured: {', '.join(sorted(keys)) or 'none (free sources only)'}")
    rt = app.runtime()
    pctx = None
    try:
        pctx = _policy_context(app, rt)
    except Exception as exc:  # noqa: BLE001 - doctor reports, never crashes
        row("licence profile", False, f"policy context unavailable: {type(exc).__name__}: {exc} (no source is probed)")
    if pctx is not None:
        _licence_row(row, pctx)
    _quota_row(row, rt)
    _org_row(row, app)
    if getattr(app, "offline", False):
        row("network", None, "offline mode")
    else:
        _network(row, app, rt, pctx)
    proxy = getattr(app, "proxy", None) or str(app.config.get("proxy") or "")
    row("route", None if not proxy else True, proxy or "direct (consider --tor for sensitive lookups)")
    return t


def _permissions(row: Any) -> None:
    try:
        problems = paths.check_permissions(limit=200)
    except Exception as exc:  # noqa: BLE001
        row("permissions", None, f"could not check: {exc}")
        return
    if not problems:
        row("permissions", True, f"{paths.home()}: directories 0700, files 0600")
        return
    shown = problems[:MAX_PERMISSION_LINES]
    more = len(problems) - len(shown)
    detail = f"{len(problems)} looser than 0700/0600 (A10):\n" + "\n".join(shown) + (f"\n... and {more} more" if more > 0 else "")
    row("permissions", None, detail)


def _commands(row: Any) -> None:
    try:
        from v3lum.commands import load_commands
        from v3lum.commands import load_errors as command_errors

        loaded = load_commands()
        errors = command_errors()
    except Exception as exc:  # noqa: BLE001
        row("commands", False, f"command registry unavailable: {type(exc).__name__}: {exc}")
        return
    if errors:
        row("commands", False, f"{len(loaded)} loaded, {len(errors)} failed: " + "; ".join(f"{k}: {v}" for k, v in sorted(errors.items())))
    else:
        row("commands", True, f"{len(loaded)} command modules loaded")


def _licence_row(row: Any, pctx: Any) -> None:
    state = pctx.licence
    active = len(state.active_entries(pctx.now)) if hasattr(state, "active_entries") else 0
    detail = f"{pctx.licence_profile} · {active} active licence_allow entr{'y' if active == 1 else 'ies'}"
    warnings = []
    try:
        for entry in state.expiring(pctx.now, 30):
            warnings.append(f"{entry.source_id}: review_by {entry.review_by} (expires within 30 days)")
    except Exception:  # noqa: BLE001
        pass
    warnings += [str(e) for e in (getattr(state, "warnings", None) or ())]
    warnings += [str(e) for e in (getattr(state, "errors", None) or ())]
    seen: list[str] = []
    for w in warnings:
        if w not in seen:
            seen.append(w)
    if seen:
        detail += "\n" + "\n".join(seen[:6])
    row("licence profile", None if seen else True, detail)


def _quota_row(row: Any, rt: Any) -> None:
    try:
        summary = rt.quota.provider_summary()
    except Exception as exc:  # noqa: BLE001
        row("quotas", None, f"quota DB unavailable: {type(exc).__name__}")
        return
    exhausted = []
    for pid, entry in sorted(summary.items()):
        if entry.get("signal_until"):
            exhausted.append(f"{pid}: provider signal until {entry['signal_until']}")
            continue
        for window, info in entry.items():
            if isinstance(info, dict) and info.get("budget") and info.get("used", 0) >= info["budget"]:
                exhausted.append(f"{pid}: {info['used']}/{info['budget']} {window}")
                break
    if exhausted:
        row("quotas", None, f"{len(exhausted)} exhausted (lookups are deferred: v3lum cases resume <id>):\n" + "\n".join(exhausted[:8]))
    else:
        row("quotas", True, f"{len(summary)} budgeted provider(s), none exhausted")


def _org_row(row: Any, app: Any) -> None:
    from v3lum.core import orgprofile

    try:
        prof = orgprofile.load_default(app.config)
    except Exception as exc:  # noqa: BLE001
        row("org profile", False, f"cannot load: {type(exc).__name__}")
        return
    if prof.is_empty and not prof.errors:
        row("org profile", None, "none: own-asset-only modules stay off (v3lum org seed / v3lum org verify)")
        return
    verified = sum(1 for d in prof.domains if d.verified)
    detail = f"{prof.path}: {len(prof.domains)} domains ({verified} verified), {len(prof.cidrs)} networks, {len(prof.asns)} ASNs"
    problems = orgprofile.validate(prof.path) if prof.path else []
    if problems:
        detail += f"; {len(problems)} problem(s): v3lum org check"
    row("org profile", None if problems else True, detail)


def _network(row: Any, app: Any, rt: Any, pctx: Any) -> None:
    ctx = rt.context(_DoctorProbe)
    try:
        ans = ctx.dns.query("example.com", "A")
        row("DNS (DoH)", ans.ok and bool(ans.records), f"{', '.join(ctx.dns.providers)}: example.com -> {', '.join(ans.records) or ans.error or ans.status}")
    except Exception as exc:  # noqa: BLE001
        row("DNS (DoH)", False, str(exc)[:160])
    for probe in PROBES:
        label = f"reach {probe.host}"
        if pctx is None:
            row(label, None, "skipped: no licence decision (fail closed)")
            continue
        allowed, reason = probe_allowed(probe, pctx)
        if not allowed:
            row(label, None, reason)
            continue
        try:
            r = ctx.http.get(probe.url, ttl=0, timeout=15)
        except HttpError as exc:  # 401/403/429/WAF/quota: the host answered but refused - could not verify
            row(label, None, f"could not verify: {type(exc).__name__}: {str(exc)[:120]}")
            continue
        except Exception as exc:  # noqa: BLE001 - network/policy failure: reported, never raised
            row(label, False, str(exc)[:120])
            continue
        status = int(getattr(r, "status", 0) or 0)
        if status in _REFUSED_STATUSES:
            row(label, None, f"could not verify: HTTP {status} (the host answered but refused)")
        else:
            row(label, 0 < status < 500, f"HTTP {status} in {float(getattr(r, 'elapsed', 0.0) or 0.0) * 1000:.0f} ms")


@command("doctor", "check environment, dependencies, permissions, network and keys")
class Doctor:
    """The environment check (wave 5 adds --licences, --egress and per-source health checks)."""

    @staticmethod
    def add_arguments(parser: Any) -> None:
        return None

    @staticmethod
    def run(args: Any, app: Any, console: Any) -> int:
        console.print(doctor_table(app))
        return 0
