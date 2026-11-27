"""Application layer shared by the command line (cli.py) and the interactive shell (shell.py).

Every execution path - ``scan``, ``run``, the shell, ``extract --scan`` and batch input (``scan -i``)
- goes through :class:`App`, which turns the analyst's flags (:class:`ScanRequest`) into
``ScanOptions`` v2 and lets the single policy gate decide (``v3lum.core.policy``, P327/AR15): the
engine builds the run's PolicyContext with ``policy.make_context(..., path=<execution path>)`` and
``v3lum run`` asks ``Engine.decide_single``. App adds the rules of engagement that need the analyst
(A7 authorization reference and scope file, AR16 purpose/ticket/legal basis, A2 TLP and its
lowering record, the A1 research-profile refusal, A5 confirmation of low-confidence usernames,
P145 scrubbing of pasted text, the P172 extraction preview and the AR07 pick of personal pivots).
"""

from __future__ import annotations

import dataclasses
import datetime as _dt
import getpass
import json
import logging
import os
import re
import sys
from collections import Counter
from collections.abc import Iterable, Mapping
from dataclasses import dataclass, field
from pathlib import Path
from types import SimpleNamespace
from typing import Any

from rich import box
from rich.console import Console
from rich.markup import escape
from rich.panel import Panel
from rich.prompt import Confirm, Prompt
from rich.table import Table
from rich.text import Text

from v3lum import paths
from v3lum.config import Config
from v3lum.core import detect as det
from v3lum.core import licence as _licence
from v3lum.core import policy
from v3lum.core import ioc as _ioc
from v3lum.core import tlp as _tlp
from v3lum.core.context import RunInfo, Runtime, ScanOptions
from v3lum.core.datasets import DATASETS, DataStore
from v3lum.core.engine import Engine
from v3lum.core.entities import PERSONAL_TYPES, SECRET_TYPES, Entity, EntityType, defang, display_value
from v3lum.core.graph import redact_secret_values, secret_value_map
from v3lum.core.models import Opsec, Status
from v3lum.core.module import CATEGORIES, REGISTRY, get_module, load_modules, package_available, readiness
from v3lum.core.store import Store
from v3lum.report import FORMATS, write_reports
from v3lum.ui.live import LiveFeed
from v3lum.ui.render import render_case, render_detections

log = logging.getLogger("v3lum.app")

TOR_PROXY = os.environ.get("V3LUM_TOR_PROXY", "socks5h://127.0.0.1:9050")
LEVEL_ORDER = ["clean", "low", "medium", "high", "critical"]

#: Execution paths of the App (``policy.make_context(path=...)``, AR15).
EXECUTION_PATHS: tuple[str, ...] = ("scan", "run", "shell", "extract", "batch")
#: Legal basis codes of docs/LEGAL.md (``--legal-basis``, AR16; LGPD arts. 7 and 11).
LEGAL_BASES: tuple[str, ...] = (
    "consent", "contract", "legal_obligation", "vital_interest", "public_interest", "legitimate_interest",
    "credit_protection", "fraud_prevention",
)
TLP_CHOICES: tuple[str, ...] = _tlp.TLP_VALUES
PRESETS: tuple[str, ...] = ("quick", "deep")
BREACH_SCOPES: tuple[str, ...] = ("own", "all")
LICENCE_PROFILES: tuple[str, ...] = ("corporate", "research")
#: Detections below this confidence are announced ('read as <type> (<confidence>); force with
#: TYPE:value', AR18) and single-token usernames/person names below it need a TTY confirmation (A5).
LOW_CONFIDENCE = 0.75
#: The extraction preview asks for a confirmation above this many indicators (P172 cond 11).
PREVIEW_CONFIRM_ABOVE = 25
#: Entity types that are free text to mine, never a subject (no incident-victim role, P145 cond 5).
TEXT_TYPES: frozenset[EntityType] = frozenset({EntityType.TEXT, EntityType.FILE, EntityType.EMAIL_HEADERS})
#: Single-token detections confirmed in a TTY before username/people packs may run on them (A5, AR18).
CONFIRM_TYPES: frozenset[EntityType] = frozenset({EntityType.USERNAME, EntityType.PERSON})
#: The first-scan hints shown once per V3LUM home (A15, AR10).
NO_KEYS_HINT = "no API keys configured: v3lum keys setup"
_HINTS_FILE = "hints.json"
_PREFIX_RE = re.compile(r"^([A-Za-z_][A-Za-z0-9_-]{0,20}):(?!//)(.+)$", re.S)
_CONTROL_RE = re.compile(r"[\x00-\x08\x0b-\x1f\x7f-\x9f]")
_EXTRACT_MAX_READ = 20 * 1024 * 1024


class UserError(Exception):
    """A problem the analyst can fix (bad input, missing flag...). Printed without a traceback."""


@dataclass
class ScanRequest:
    """What the analyst asked for on one execution path (the CLI/shell flags).

    :meth:`App.scan` and :meth:`App.run_single` turn it into ``ScanOptions`` v2. Empty strings mean
    "use the configured default" (``tlp`` -> setting tlp, A2 amber; ``preset`` -> setting preset;
    ``licence_profile`` -> setting licence_profile). ``authorization_ref`` (``--authorized REF``) and
    ``scope_path`` (``--scope FILE``) are required for ACTIVE on every path (A7); ``purpose`` and
    ``ticket`` are required when a seed is a personal identifier, with ``breach_scope='all'`` and with
    ``expand_personal`` (AR16). ``path`` is the policy execution path ('scan' | 'shell' | 'extract' |
    'batch'; ``run_single`` uses 'run'). ``authorized``/``authorization_note`` are the v1 fields:
    a v1 caller's note counts as the reference only when ``authorized`` is set.
    """

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
    tlp: str = ""
    # ---- v2 (WP13) ---------------------------------------------------------------------------
    authorization_ref: str = ""
    scope_path: str = ""
    preset: str = ""
    purpose: str = ""
    ticket: str = ""
    legal_basis: str = ""
    breach_scope: str = "own"
    expand_personal: bool = False
    allow_unknown: bool = False
    licence_profile: str = ""
    egress_override: str = ""
    show_personal: bool = False
    no_defang: bool = False
    confirmed_urls: list[str] = field(default_factory=list)
    incident_victim: bool = False
    path: str = "scan"


@dataclass
class _Engagement:
    """The seed-independent part of a request, validated (mode, TLP, authorization, scope...)."""

    mode: Opsec
    tlp: _tlp.TLP
    configured_tlp: _tlp.TLP
    tlp_raised: bool
    preset: str
    breach_scope: str
    legal_basis: str
    licence_profile: str
    egress_override: str
    authorization_ref: str
    scope: Any = None
    scope_path: str = ""
    notes: list[str] = field(default_factory=list)


class _PathEngine(Engine):
    """The engine of one App execution path: its investigations build their PolicyContext with the
    App's path ('shell', 'extract', 'batch', 'run'...) instead of the engine default 'scan'
    (``policy.make_context(path=...)`` on every path, AR15)."""

    def __init__(
        self, runtime: Runtime, options: ScanOptions | None = None, *, reliability: dict[str, float] | None = None, path: str = "scan", **feedback: Any,
    ) -> None:
        """``feedback``: the other Engine keyword inputs (``source_reliability``, ``overrides``; WP19)."""
        self.policy_path = path if path in policy.PATHS else "scan"
        super().__init__(runtime, options, reliability=reliability, **feedback)

    def policy_context(self, *, graph: Any = None, path: str = "scan", explicit: Iterable[str] | None = None) -> Any:
        if path == "scan":
            path = self.policy_path
        return super().policy_context(graph=graph, path=path, explicit=explicit)


def _stdin_tty() -> bool:
    """True when the analyst can answer prompts (stdin is a terminal)."""
    try:
        return bool(sys.stdin and sys.stdin.isatty())
    except (AttributeError, ValueError, OSError):
        return False


try:  # WP14's helper also drops bidi overrides; the local pattern is the fallback
    from v3lum.ui.safe import clean_text as _clean_text
except Exception:  # noqa: BLE001 - UI safety helper unavailable
    _clean_text = None


def _plain(value: Any) -> str:
    """Text without C0/C1 control characters (newline and tab kept): never an escape sequence."""
    if _clean_text is not None:
        try:
            return str(_clean_text(value))
        except Exception:  # noqa: BLE001
            pass
    return _CONTROL_RE.sub("", str(value))


def _short(value: Any, limit: int = 60) -> str:
    """One-line, control-free preview of an input."""
    text = " ".join(_plain(value).split())
    return text if len(text) <= limit else text[: limit - 1] + "…"


def _now_iso() -> str:
    return _dt.datetime.now(_dt.timezone.utc).isoformat(timespec="seconds")


def _os_user() -> str:
    try:
        return getpass.getuser()
    except Exception:  # noqa: BLE001 - no login name (containers): still recorded
        return "unknown"


def _explicit_prefix(raw: str) -> EntityType | None:
    """The entity type of an explicit ``TYPE:value`` prefix (None without one)."""
    match = _PREFIX_RE.match(str(raw).strip())
    if not match:
        return None
    try:
        return EntityType.parse(match.group(1))
    except ValueError:
        return None


#: extraction preview groups: entity type -> (singular, plural) label.
_PREVIEW_GROUPS: dict[str, tuple[str, str]] = {
    "domain": ("domain", "domains"), "ipv4": ("IP", "IPs"), "ipv6": ("IP", "IPs"), "url": ("URL", "URLs"),
    "email": ("e-mail", "e-mails"), "md5": ("hash", "hashes"), "sha1": ("hash", "hashes"), "sha256": ("hash", "hashes"),
    "sha512": ("hash", "hashes"), "cve": ("CVE", "CVEs"), "mitre_technique": ("ATT&CK id", "ATT&CK ids"),
}


def _preview_counts(type_names: Iterable[str]) -> str:
    """'12 domains, 5 IPs, 1 URL' (largest groups first)."""
    groups: Counter[tuple[str, str]] = Counter()
    for name in type_names:
        groups[_PREVIEW_GROUPS.get(name, (name, name))] += 1
    return ", ".join(f"{n} {one if n == 1 else many}" for (one, many), n in groups.most_common())


class App:
    """The V3LUM application: scans, single runs, catalog views and maintenance helpers."""

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
        #: machine output (``--json``): notices go to stderr, never into the JSON on stdout.
        self.machine = False
        self._store: Store | None = None
        self._err_console: Console | None = None
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

    def analyst(self) -> str:
        """Setting ``analyst``, else the OS user (case audit, feedback, overrides)."""
        return str(self.config.get("analyst") or "").strip() or _os_user()

    def _engine_feedback(self) -> dict[str, Any]:
        """The case-DB inputs of the engine (WP19): ``reliability`` (v1 module view),
        ``source_reliability`` (Beta per source, P302 R_src) and ``overrides`` (``Store.overrides_for``,
        applied before suppression, correlations and scoring: analyst decisions survive re-runs,
        P322 cond 3). A case-DB problem never blocks a scan: that input is left out (Admiralty
        priors, no overrides) and the reason is logged."""
        out: dict[str, Any] = {}
        try:
            store = self.store
        except Exception as exc:  # noqa: BLE001 - no case DB: priors only
            log.warning("case DB unavailable for scoring inputs: %s", type(exc).__name__)
            return out
        for name, method in (("reliability", "reliability"), ("source_reliability", "source_reliability")):
            fn = getattr(store, method, None)
            if not callable(fn):
                continue
            try:
                out[name] = fn()
            except Exception as exc:  # noqa: BLE001
                log.warning("%s unavailable: %s", name, type(exc).__name__)
        lookup = getattr(store, "overrides_for", None)
        if callable(lookup):
            out["overrides"] = lookup
        return out

    def notice(self, text: str, style: str = "v.dim") -> None:
        """One analyst-facing line (stderr in machine mode: the JSON on stdout stays clean)."""
        target = self.console
        if self.machine:
            if self._err_console is None:
                from v3lum.ui.theme import make_console

                self._err_console = make_console(no_color=bool(getattr(self.console, "no_color", False)), stderr=True)
            target = self._err_console
        target.print(Text(_plain(text), style=style), soft_wrap=True)

    def configured_mode(self) -> Opsec:
        """Setting ``mode`` (passive by default; LIGHT/ACTIVE still need their flags, A7)."""
        try:
            return Opsec.parse(str(self.config.get("mode") or "passive"))
        except (KeyError, ValueError):
            return Opsec.PASSIVE

    def configured_tlp(self) -> _tlp.TLP:
        """Setting ``tlp`` (A2 default AMBER; an unreadable value counts as AMBER)."""
        try:
            return _tlp.parse(self.config.get("tlp") or "amber")
        except ValueError:
            return _tlp.TLP.AMBER

    def status_line(self) -> list[tuple[str, str, str]]:
        keys = self.config.keys()
        mode = self.configured_mode()
        ready = sum(1 for m in REGISTRY.values() if readiness(m, keys, mode)[0])
        need = sum(1 for m in REGISTRY.values() if m.requires_keys and not all(keys.get(k) for k in m.requires_keys))
        proxy = self.proxy or str(self.config.get("proxy") or "")
        route = "tor" if proxy == TOR_PROXY else ("proxy" if proxy else "direct")
        return [
            ("modules", f"{ready} ready", "v.ok"),
            ("need keys", str(need), "v.warn" if need else "v.dim"),
            ("mode", mode.label, "v.accent"),
            ("tlp", self.configured_tlp().label, "v.accent"),
            ("route", route, "v.warn" if route == "direct" else "v.ok"),
            ("cache", "off" if self.no_cache else "on", "v.dim"),
        ]

    # ------------------------------------------------------------------ hints and reminders
    def _hint_state(self) -> tuple[Path, dict[str, Any]]:
        path = paths.home() / _HINTS_FILE
        try:
            state = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, ValueError):
            state = {}
        return path, state if isinstance(state, dict) else {}

    def first_run_hints(self) -> list[str]:
        """The first-scan hints, each shown once per V3LUM home: no API keys configured (A15) and
        essential datasets never downloaded (``DataStore.first_run_hint()``, AR10)."""
        path, state = self._hint_state()
        shown: list[str] = []
        try:
            keys = self.config.keys()
        except Exception:  # noqa: BLE001 - a broken key store: no hint
            keys = {"?": "?"}
        if not keys and not state.get("no_keys"):
            shown.append(NO_KEYS_HINT)
            state["no_keys"] = _now_iso()
        try:
            hint = DataStore(None).first_run_hint()
        except Exception:  # noqa: BLE001 - dataset problems are doctor's
            hint = None
        if hint and not state.get("datasets"):
            shown.append(hint)
            state["datasets"] = _now_iso()
        if shown:
            try:
                paths.secure_write_text(path, json.dumps(state, sort_keys=True))
            except OSError:  # pragma: no cover - a read-only home shows the hints again
                pass
            for line in shown:
                self.notice(f"[i] {line}")
        return shown

    def startup_reminder(self) -> str:
        """The daily retention reminder ('3 cases older than 180 days: v3lum cases purge', A10):
        at most once per day, '' otherwise."""
        try:
            line = self.store.retention_reminder()
        except Exception as exc:  # noqa: BLE001 - the reminder never blocks the CLI
            log.warning("retention reminder unavailable: %s", type(exc).__name__)
            return ""
        if line:
            self.notice(f"[i] {line}", "v.warn")
        return line

    # ------------------------------------------------------------------ inputs
    def scrub_input(self, raw: str, etype: EntityType | None = None, *, hits: list[dict[str, str]] | None = None) -> str:
        """The input with credentials removed before any entity is created (P145 cond 5):
        ``ioc.scrub`` (``sanitize.scrub_text`` plus the P323 pattern-DB secrets and card numbers as
        BIN6...last4, PIX BR Codes intact) drops combos ('user@example.com:secret' -> 'user@example.com'), URL
        userinfo, password hashes and masked hints and masks other secrets. Local file paths and
        inputs that ARE a secret value (JWT, token... - detect-only, persisted redacted) are kept;
        an explicit ``TYPE:`` prefix is kept. ``hits`` receives the removals."""
        text = str(raw)
        forced = etype or _explicit_prefix(text)
        if forced is not None and (forced in SECRET_TYPES or forced is EntityType.FILE):
            return text
        if forced is None:
            found = det.detect(text)
            if found and (found[0].type in SECRET_TYPES or found[0].type is EntityType.FILE):
                return text
        if etype is None and forced is not None:
            prefix, _, rest = text.strip().partition(":")
            return f"{prefix}:{_ioc.scrub(rest, hits=hits)}"
        return _ioc.scrub(text, hits=hits)

    def _report_scrub(self, hits: list[dict[str, str]]) -> str:
        """'sensitive data in pasted text: ...' (P145 cond 5, P323 cond 6) - printed once."""
        if not hits:
            return ""
        counts = Counter(str(h.get("kind") or "secret") for h in hits)
        detail = ", ".join(f"{n} {kind.replace('_', ' ')}" for kind, n in sorted(counts.items()))
        line = f"sensitive data in pasted text: {detail} removed or masked before anything was stored (P145)"
        self.notice(f"[!] {line}", "v.warn")
        return line

    def resolve_inputs(
        self,
        inputs: list[str],
        etype: EntityType | None,
        interactive: bool,
        *,
        unconfirmed: set[str] | None = None,
        hits: list[dict[str, str]] | None = None,
    ) -> tuple[list[Entity], list[det.Detection]]:
        """Detect what every input is and return ``(seeds, chosen detections)``.

        Inputs are scrubbed first (:meth:`scrub_input`, P145 cond 5): the seed value, the
        detections, the case JSON and the reports hold only the scrubbed text. Every detection below
        0.75 confidence prints 'read as <type> (<confidence>); force with TYPE:value' (AR18). An
        ambiguous input is asked about in a TTY. A single token read as a username or person name
        below 0.75 without an explicit prefix needs a TTY confirmation: unconfirmed ones are added
        to ``unconfirmed`` (``ScanOptions.unconfirmed_seeds``: username/people packs and LIGHT never
        run on them, A5).
        """
        seeds: list[Entity] = []
        chosen: list[det.Detection] = []
        tty = bool(interactive) and _stdin_tty()
        for raw in inputs:
            value = self.scrub_input(raw, etype, hits=hits)
            if not value.strip():
                raise UserError("nothing left to investigate in an input once credentials were removed (P145)")
            found = det.detect(value, explicit=etype)
            shown = _short(value)
            if not found:
                if etype:
                    raise UserError(f"{shown!r} is not a valid {etype.value}")
                raise UserError(f"could not interpret {shown!r}")
            picks = det.primary(found)
            ambiguous = len(found) > 1 and found[0].confidence < 0.9 and found[1].confidence >= 0.5
            if ambiguous and tty:
                render_detections(self.console, value, found)
                options = [str(i + 1) for i in range(len(found))] + ["a"]
                answer = Prompt.ask("[v.accent]which interpretation?[/] (number, or [b]a[/] for all)", choices=options, default="1", console=self.console)
                picks = found if answer == "a" else [found[int(answer) - 1]]
            elif ambiguous and picks[0].confidence >= LOW_CONFIDENCE:
                alts = ", ".join(f"{d.type.value} ({d.confidence:.2f})" for d in found[1:4])
                self.notice(f"[i] {shown} read as {picks[0].type.value}; also possible: {alts}. Force with TYPE:value")
            for d in picks:
                if d.confidence < LOW_CONFIDENCE:
                    others = [f"{x.type.value} ({x.confidence:.2f})" for x in found if x is not d][:3]
                    tail = f"; also possible: {', '.join(others)}" if others else ""
                    self.notice(f"[i] {shown} read as {d.type.value} ({d.confidence:.2f}); force with TYPE:value{tail}")
                if d.entity in seeds:
                    continue
                if d.type in CONFIRM_TYPES and d.confidence < LOW_CONFIDENCE:
                    ok = tty and Confirm.ask(
                        f"[v.warn]investigate {escape(shown)!r} as a {d.type.value}?[/] [v.dim](username/people packs query public sites)[/]",
                        default=False,
                        console=self.console,
                    )
                    if not ok and unconfirmed is not None:
                        unconfirmed.add(d.entity.key)
                seeds.append(d.entity)
                chosen.append(d)
        return seeds, chosen

    # ------------------------------------------------------------------ rules of engagement
    def _engagement(self, req: ScanRequest) -> _Engagement:
        """Validate the seed-independent flags (A1, A2, A3, A4, A7, A9) - UserError on a refusal."""
        cfg = self.config
        mode = Opsec.parse(req.mode)
        configured = self.configured_tlp()
        try:
            requested = _tlp.parse(req.tlp) if str(req.tlp or "").strip() else configured
        except ValueError as exc:
            raise UserError(f"{exc}") from exc
        notes: list[str] = []
        raised = False
        effective = requested
        if mode >= Opsec.LIGHT and requested < _tlp.TLP.AMBER:
            effective, raised = _tlp.TLP.AMBER, True
            notes.append(f"TLP raised to AMBER: LIGHT/ACTIVE cases are at least TLP:AMBER (--tlp {requested.value_str} was given, A2)")
        preset = str(req.preset or cfg.get("preset") or "quick").strip().lower()
        if req.all_modules:
            preset = "deep"  # --all-modules is an alias of --preset deep (A3)
        if preset not in PRESETS:
            raise UserError(f"unknown preset {preset!r} (quick or deep)")
        breach_scope = str(req.breach_scope or "own").strip().lower()
        if breach_scope not in BREACH_SCOPES:
            raise UserError(f"--breach-scope must be own or all, not {breach_scope!r}")
        legal_basis = str(req.legal_basis or "").strip().lower()
        if legal_basis and legal_basis not in LEGAL_BASES:
            raise UserError(f"unknown legal basis {legal_basis!r}: one of {', '.join(LEGAL_BASES)} (docs/LEGAL.md)")
        requested_profile = str(req.licence_profile or "").strip().lower()
        if requested_profile and requested_profile not in LICENCE_PROFILES:
            raise UserError(f"unknown licence profile {requested_profile!r} (corporate or research)")
        try:
            profile = _licence.resolve_profile(cfg, SimpleNamespace(licence_profile=requested_profile))
        except _licence.LicenceError as exc:
            raise UserError(str(exc)) from exc
        egress_override = str(req.egress_override or "").strip()
        ref = str(req.authorization_ref or "").strip() or (str(req.authorization_note or "").strip() if req.authorized else "")
        if ref:
            problem = policy.authorization_problem(ref)
            if problem:
                raise UserError(f"refused: {problem} (A7)")
        scope = None
        scope_path = str(req.scope_path or "").strip()
        if mode is Opsec.ACTIVE:
            scope = self._active_preflight(ref, scope_path)
        elif scope_path:
            notes.append("--scope applies to --mode active only: the scope file was not used")
            scope_path = ""
        return _Engagement(
            mode=mode, tlp=effective, configured_tlp=configured, tlp_raised=raised, preset=preset, breach_scope=breach_scope,
            legal_basis=legal_basis, licence_profile=profile, egress_override=egress_override, authorization_ref=ref,
            scope=scope, scope_path=scope_path, notes=notes,
        )

    def _active_preflight(self, ref: str, scope_path: str) -> Any:
        """ACTIVE needs --authorized REF and a --scope FILE bound to it, inside its window, on every
        path - TTY or not, -y included (A7). The refusal lists exactly what is missing."""
        from v3lum.core.scope import Scope, ScopeError

        missing: list[str] = []
        problems: list[str] = []
        if not ref:
            missing.append("--authorized REF (a real authorization reference, e.g. the ticket of the engagement)")
        if not scope_path:
            missing.append("--scope FILE (the scope file bound to that reference, docs/ROE.md)")
        scope = None
        if scope_path:
            try:
                scope = Scope.load(scope_path)
            except ScopeError as exc:
                problems.append(str(exc))
            else:
                if ref:
                    problems += scope.validate(ref, _dt.datetime.now(_dt.timezone.utc), org_terms=self._org_terms())
                else:
                    problems += [str(p) for p in scope.problems]
        if missing or problems:
            parts = []
            if missing:
                parts.append("missing " + " and ".join(missing))
            if problems:
                parts.append("scope file refused: " + "; ".join(problems[:6]))
            raise UserError("active mode refused (A7): " + "; ".join(parts))
        return scope

    def _org_terms(self) -> list[str]:
        """Organisation name and brand keywords (an ROE identity must never name them, A7)."""
        try:
            from v3lum.core import orgprofile

            org = orgprofile.load_default(self.config)
        except Exception:  # noqa: BLE001 - no profile: nothing to compare
            return []
        terms = [str(getattr(org, "name", "") or "")]
        brand_terms = getattr(org, "brand_terms", None)
        if callable(brand_terms):
            try:
                terms += [str(t) for t in brand_terms()]
            except Exception:  # noqa: BLE001
                pass
        return [t for t in terms if t]

    def _ask(self, label: str, *, password: bool = False) -> str:
        for _ in range(3):
            answer = Prompt.ask(label, default="", console=self.console, password=password, show_default=False).strip()
            if answer:
                return answer
        return ""

    def _case_metadata(self, req: ScanRequest, seeds: list[Entity], eng: _Engagement) -> tuple[str, str, str]:
        """Purpose, ticket and legal basis (AR16): required (TTY prompt, non-TTY refusal) for a
        personal seed, --breach-scope all and --expand-personal (--incident-victim needs a purpose);
        the default_* settings fill IOC-only scans."""
        purpose = str(req.purpose or "").strip()
        ticket = str(req.ticket or "").strip()
        legal_basis = eng.legal_basis
        personal = [s for s in seeds if s.type in PERSONAL_TYPES]
        reasons: list[str] = []
        if personal:
            first = personal[0]
            reasons.append(f"personal identifier ({first.type.value} {display_value(first.type, first.value)})")
        if eng.breach_scope == "all":
            reasons.append("--breach-scope all")
        if req.expand_personal:
            reasons.append("--expand-personal")
        needed = [("--purpose TEXT", "purpose"), ("--ticket TEXT", "ticket")] if reasons else []
        if req.incident_victim and not reasons:
            reasons.append("--incident-victim")
            needed = [("--purpose TEXT", "purpose")]
        if not reasons:
            cfg = self.config
            return (
                purpose or str(cfg.get("default_purpose") or "").strip(),
                ticket or str(cfg.get("default_ticket") or "").strip(),
                legal_basis or str(cfg.get("default_legal_basis") or "").strip().lower(),
            )
        values = {"purpose": purpose, "ticket": ticket}
        missing = [(flag, name) for flag, name in needed if not values[name]]
        if missing and req.interactive and not req.assume_yes and _stdin_tty():
            self.console.print(Text(f"[!] {' and '.join(reasons)}: LGPD needs a recorded purpose and ticket (AR16)", style="v.warn"))
            for _flag, name in missing:
                label = "[v.accent]purpose of this investigation[/] (why these personal data are needed)" if name == "purpose" else "[v.accent]ticket / case reference[/]"
                values[name] = self._ask(label)
            missing = [(flag, name) for flag, name in needed if not values[name]]
        if missing:
            raise UserError(f"refused: {' and '.join(reasons)} needs {' and '.join(f for f, _ in missing)} (LGPD purpose limitation, AR16)")
        if legal_basis and legal_basis not in LEGAL_BASES:
            raise UserError(f"unknown legal basis {legal_basis!r}: one of {', '.join(LEGAL_BASES)}")
        return values["purpose"], values["ticket"], legal_basis

    def scan_options(
        self,
        req: ScanRequest,
        seeds: list[Entity],
        *,
        unconfirmed: Iterable[str] = (),
        engagement: _Engagement | None = None,
    ) -> ScanOptions:
        """ScanOptions v2 for ``req`` and its resolved ``seeds``: every rule of engagement that needs
        the analyst is checked here (UserError on a refusal); everything else is the policy gate's.

        A TLP below the configured default is recorded as ``options.tlp_change`` = ``{os_user,
        analyst, at, from, to}`` (case audit row 'tlp_change' and ``case['meta']['tlp_change']``)."""
        eng = engagement or self._engagement(req)
        purpose, ticket, legal_basis = self._case_metadata(req, seeds, eng)
        tlp_value = eng.tlp.value_str
        options = ScanOptions(
            mode=eng.mode,
            authorized=bool(eng.mode is Opsec.ACTIVE and eng.authorization_ref and eng.scope is not None),
            depth=max(0, int(req.depth)),
            max_entities=int(req.max_entities),
            threads=int(req.threads),
            include=set(req.include),
            exclude=set(req.exclude),
            categories=set(req.categories),
            include_disabled=bool(req.all_modules),
            offline=self.offline,
            no_cache=self.no_cache,
            timeout_total=float(req.timeout_total or 0.0),
            save_evidence=bool(req.save_evidence),
            authorization_note=eng.authorization_ref,
            tlp=tlp_value,
            authorization_ref=eng.authorization_ref,
            scope_path=eng.scope_path,
            scope=eng.scope,
            preset=eng.preset,
            purpose=purpose,
            ticket=ticket,
            legal_basis=legal_basis,
            breach_scope=eng.breach_scope,
            expand_personal=bool(req.expand_personal),
            allow_unknown=bool(req.allow_unknown),
            egress_override=eng.egress_override,
            licence_profile=eng.licence_profile,
            show_personal=bool(req.show_personal),
            no_defang=bool(req.no_defang),
            seed_tlp={s.key: tlp_value for s in seeds},
            unconfirmed_seeds=set(unconfirmed or ()),
            confirmed_urls={str(u).strip() for u in (req.confirmed_urls or ()) if str(u).strip()},
            subject_roles={s.key: "incident_victim" for s in seeds if s.type not in TEXT_TYPES} if req.incident_victim else {},
        )
        change = None
        if eng.tlp < eng.configured_tlp:
            change = {"os_user": _os_user(), "analyst": self.analyst(), "at": _now_iso(), "from": eng.configured_tlp.value_str, "to": tlp_value}
            self.notice(f"[!] TLP lowered from {eng.configured_tlp.label} to {eng.tlp.label}: recorded in the case audit ({change['os_user']}, {change['at']})", "v.warn")
        options.tlp_change = change  # type: ignore[attr-defined] - read by the case audit (contract_additions/WP13.md)
        for note in eng.notes:
            self.notice(f"[i] {note}", "v.warn")
        if eng.egress_override:  # P376 cond 8: the case audit (AuditHook overrides) and the report header record it
            self.notice(f"[!] egress override: {_short(eng.egress_override, 120)} - LIGHT/ACTIVE may contact hosts flagged hostile from the current egress (recorded in the case audit)", "v.warn")
        return options

    def _confirm_active(self, req: ScanRequest, options: ScanOptions, seeds: list[Entity]) -> None:
        """The interactive ACTIVE confirmation (TTY without -y); never a substitute for REF + scope."""
        if options.mode is not Opsec.ACTIVE or req.assume_yes or not req.interactive or not _stdin_tty():
            return
        targets = "\n".join(f"  • {s.type.value}: {_short(s.display, 120)}" for s in seeds)
        summary = getattr(options.scope, "summary", None)
        scope_line = summary() if callable(summary) else options.scope_path
        self.console.print(
            Panel(
                Text.from_markup(
                    "[v.warn]ACTIVE MODE[/]: V3LUM will probe directly (only inside the scope file):\n"
                    f"{escape(targets)}\n\nauthorization: {escape(options.authorization_ref)}\n{escape(str(scope_line))}\n\n"
                    "The authorization reference, the scope SHA-256 and every request are recorded in the case audit."
                ),
                border_style="v.warn",
                title="authorization required",
            )
        )
        if not Confirm.ask("[v.warn]I am authorized to actively test these targets[/]", default=False, console=self.console):
            raise UserError("active scan cancelled: authorization not confirmed")

    # ------------------------------------------------------------------ runtime wiring
    def _audit_hook(self) -> Any:
        """``v3lum.core.audit.AuditHook`` (WP15) for the case, or None when unavailable."""
        try:
            from v3lum.core.audit import AuditHook
        except Exception as exc:  # noqa: BLE001 - reported by the caller (LIGHT/ACTIVE fail closed)
            log.debug("case audit unavailable: %s", type(exc).__name__)
            return None
        try:
            return AuditHook(self.store, analyst=self.analyst())
        except Exception as exc:  # noqa: BLE001
            log.warning("case audit hook could not be created: %s", type(exc).__name__)
            return None

    def prepare_runtime(self, rt: Runtime, options: ScanOptions, *, path: str, notes: Iterable[str] = (), audit: bool = True) -> None:
        """Install what the engine and the modules read from the runtime before an investigation:
        ``meta['sightings_lookup']`` = ``Store.sightings_for`` (WP16; policy guard and the
        case_sightings module), the case audit hook (WP15; every case - LIGHT/ACTIVE runs are
        refused without it, A7; ``audit=False`` for runs that write no case), ``meta['header_notes']``
        (report header lines), the TLP change, the execution path and the analyst-override hook
        (``store.OverrideHook``, WP16/WP19: stored analyst decisions are re-applied before suppression,
        correlations and scoring on every path, engines built without ``overrides=`` included, e.g.
        ``cases resume``; applying a decision twice is idempotent)."""
        meta = rt.meta
        lookup = getattr(self.store, "sightings_for", None)
        if callable(lookup):
            meta["sightings_lookup"] = lookup
        self._install_override_hook(rt)
        lines = [str(n) for n in notes if n]
        if lines:
            meta.setdefault("header_notes", [])
            meta["header_notes"] += [n for n in lines if n not in meta["header_notes"]]
        change = getattr(options, "tlp_change", None)
        if change:
            meta["tlp_change"] = dict(change)
        meta["execution_path"] = path
        if audit:
            self.install_audit(rt, options)

    def _install_override_hook(self, rt: Runtime) -> None:
        """Add one ``store.OverrideHook`` to ``rt.case_hooks`` (P322 cond 3) when the case DB offers
        ``overrides_for``; a missing hook class or case DB leaves the run without it (logged)."""
        store = self.store
        if not callable(getattr(store, "overrides_for", None)):
            return
        try:
            from v3lum.core.store import OverrideHook
        except ImportError as exc:  # pragma: no cover - the case DB of an older wave
            log.warning("analyst override hook unavailable: %s", type(exc).__name__)
            return
        hooks = getattr(rt, "case_hooks", None)
        if hooks is None or any(isinstance(h, OverrideHook) for h in hooks):
            return
        hooks.append(OverrideHook(store))

    def install_audit(self, rt: Runtime, options: ScanOptions) -> Any:
        """Add the case audit hook (WP15) to ``rt.case_hooks`` and return it. Without it LIGHT/ACTIVE
        runs are refused (A7: every LIGHT/ACTIVE run writes an audit record and a request ledger);
        passive scans go on (None is returned)."""
        hook = self._audit_hook()
        if hook is not None:
            attach = getattr(hook, "attach", None)
            try:
                if callable(attach):
                    attach(rt)  # case hooks + the http_request events (ledger lines as they happen)
                elif hook not in rt.case_hooks:
                    rt.case_hooks.append(hook)
            except Exception as exc:  # noqa: BLE001 - treated as an unavailable audit below
                log.warning("case audit hook could not be attached: %s", type(exc).__name__)
                hook = None
        if hook is None:
            if Opsec.parse(options.mode) >= Opsec.LIGHT:
                raise UserError("LIGHT/ACTIVE runs need the case audit trail and the request ledger (A7), which are unavailable: refused")
            return None
        return hook

    def _record_case(self, case: Any, data: dict[str, Any], options: ScanOptions) -> None:
        """Persist the case: DB row, cache keys (A10 purge), report paths and the TLP change."""
        self.store.save_case(data)
        try:
            self.store.record_cache_keys(case.case_id, getattr(case, "cache_keys", None) or ())
        except Exception as exc:  # noqa: BLE001 - the case is stored; the purge falls back to the case dir
            log.warning("cache keys not recorded: %s", type(exc).__name__)
        change = getattr(options, "tlp_change", None)
        if change:
            self._audit_tlp_change(case.case_id, getattr(case, "case_dir", "") or "", dict(change))

    def _audit_tlp_change(self, case_id: str, case_dir: str, change: dict[str, Any]) -> None:
        """Audit row 'tlp_change' (once per case; the audit hook may already have written it)."""
        try:
            if any(str(r.get("kind")) == "tlp_change" for r in self.store.audit_rows(case_id)):
                return
        except Exception:  # noqa: BLE001
            pass
        try:
            from v3lum.core.audit import CaseAudit

            CaseAudit(self.store, case_id, case_dir).append("tlp_change", change)
            return
        except Exception as exc:  # noqa: BLE001 - WP15 not available: the store's chain still records it
            log.debug("CaseAudit unavailable for tlp_change: %s", type(exc).__name__)
        try:
            self.store.append_audit(case_id, "tlp_change", change)
        except Exception as exc:  # noqa: BLE001
            log.warning("TLP change not written to the audit: %s", type(exc).__name__)

    # ------------------------------------------------------------------ extraction preview (P172)
    def ioc_preview(self, text: str) -> tuple[str, int]:
        """('37 IOCs: 12 domains, 5 IPs, 4 low-confidence', 37) for scrubbed ``text`` (offline)."""
        entities: list[Any] = []
        low = 0
        try:
            from v3lum.core import ioc as _ioc

            result = _ioc.extract(text)
            preview = getattr(result, "preview", None)
            if callable(preview):  # WP17's own line: the same groups and low-confidence rule as `extract`
                return _plain(preview()), len(result)
            items = list(getattr(result, "entities", None) or [])
            entities = [getattr(i, "entity", i) for i in items]
            for item in items:
                flags = {str(f) for f in (getattr(item, "flags", None) or ())}
                if float(getattr(item, "confidence", 1.0) or 0.0) < LOW_CONFIDENCE or "low_confidence_tld" in flags:
                    low += 1
        except Exception:  # noqa: BLE001 - WP17 engine absent: the v1 extractor counts by type
            entities = det.extract_iocs(text)
        names = [e.type.value for e in entities if isinstance(getattr(e, "type", None), EntityType)]
        total = len(entities)
        parts = _preview_counts(names)
        line = f"{total} IOC{'s' if total != 1 else ''}" + (f": {parts}" if parts else "")
        if low:
            line += f", {low} low-confidence"
        return line, total

    def _extraction_preview(self, seeds: list[Entity], req: ScanRequest) -> None:
        """One screen per text/file seed before scanning, confirmed above 25 IOCs (TTY only)."""
        if not req.interactive or not _stdin_tty():
            return
        for seed in seeds:
            if seed.type not in (EntityType.TEXT, EntityType.FILE):
                continue
            if seed.type is EntityType.TEXT:
                text = seed.value
            else:
                try:
                    with open(seed.value, encoding="utf-8", errors="replace") as fh:
                        text = _ioc.scrub(fh.read(_EXTRACT_MAX_READ))
                except OSError:
                    continue
            line, total = self.ioc_preview(text)
            label = "pasted text" if seed.type is EntityType.TEXT else f"file {_short(seed.value)}"
            self.console.print(Text(f"[◈] {label}: {line}", style="v.accent"))
            confirm = total > PREVIEW_CONFIRM_ABOVE and not req.assume_yes
            if confirm and not Confirm.ask(f"[v.accent]investigate these {total} indicators?[/]", default=True, console=self.console):
                raise UserError("scan cancelled at the extraction preview")

    # ------------------------------------------------------------------ scan
    def scan(self, req: ScanRequest) -> dict[str, Any]:
        """Investigate ``req.inputs`` on the request's execution path and store the case."""
        if not req.inputs:
            raise UserError("nothing to investigate: give at least one input")
        path = req.path if req.path in EXECUTION_PATHS and req.path != "run" else "scan"
        eng = self._engagement(req)  # refusals that do not depend on the inputs come first
        hits: list[dict[str, str]] = []
        unconfirmed: set[str] = set()
        seeds, chosen = self.resolve_inputs(req.inputs, req.etype, req.interactive, unconfirmed=unconfirmed, hits=hits)
        scrub_line = self._report_scrub(hits)
        options = self.scan_options(req, seeds, unconfirmed=unconfirmed, engagement=eng)
        for name in list(options.include) + list(options.exclude):
            try:
                get_module(name)
            except KeyError as exc:
                raise UserError(str(exc)) from exc
        unknown = [c for c in options.categories if c not in CATEGORIES]
        if unknown:
            raise UserError(f"unknown categories: {', '.join(unknown)} (see `v3lum modules --categories`)")
        self._confirm_active(req, options, seeds)
        self._extraction_preview(seeds, req)
        self.first_run_hints()
        feed = LiveFeed(self.console, verbosity=self.verbosity)
        rt = self.runtime(listener=feed)
        self.prepare_runtime(rt, options, path=path, notes=[*eng.notes, scrub_line])
        engine = _PathEngine(rt, options, path=path, **self._engine_feedback())
        with feed:
            case = engine.investigate(seeds, detections=chosen)
        data = case.to_dict()
        if scrub_line and scrub_line not in data.get("notes", []):
            data.setdefault("notes", []).append(scrub_line)
        out_dir = req.out_dir or str(self.config.get("report_dir") or "") or case.case_dir
        if req.formats:
            data["reports"] = write_reports(data, req.formats, out_dir)
            try:
                self.store.record_report_paths(case.case_id, data["reports"])
            except Exception as exc:  # noqa: BLE001 - save_case records them from the case dict too
                log.warning("report paths not recorded: %s", type(exc).__name__)
        self._record_case(case, data, options)
        return data

    def follow_up_personal(self, data: dict[str, Any], req: ScanRequest) -> ScanRequest | None:
        """AR07: after a TTY scan whose case lists personal identifiers awaiting selection
        (``case['pending_personal']``), ask which to investigate; returns the follow-up request
        (chosen entities as seeds, the recorded purpose and ticket) or None."""
        items = [i for i in (data.get("pending_personal") or []) if isinstance(i, dict) and i.get("entity")]
        if not items or not req.interactive or req.assume_yes or not _stdin_tty():
            return None
        t = Table(box=box.SIMPLE, header_style="v.dim", title="[v.accent]personal identifiers found (not investigated automatically)[/]", title_justify="left")
        t.add_column("#", justify="right", style="v.dim")
        t.add_column("entity", style="v.entity", overflow="fold")
        t.add_column("found in", style="v.dim", overflow="fold")
        for n, item in enumerate(items[:50], 1):
            etype_name, _, value = str(item["entity"]).partition(":")
            try:
                shown = f"{etype_name}:{display_value(EntityType.parse(etype_name), value)}"
            except ValueError:
                shown = str(item["entity"])
            t.add_row(str(n), _plain(shown), _short(f"{item.get('relation', '')} {item.get('parent', '')}", 70))
        self.console.print(t)
        raw = Prompt.ask("[v.dim]numbers to investigate as seeds (e.g. 1,3; empty = none)[/]", default="", console=self.console)
        picks = sorted({int(x) for x in raw.replace(" ", "").split(",") if x.isdigit() and 1 <= int(x) <= min(len(items), 50)})
        if not picks:
            return None
        options = data.get("options") or {}
        tlp_value = str(req.tlp or "")
        try:  # the picked identifiers inherit the case TLP (A2): the follow-up is never lower
            current = _tlp.parse(tlp_value) if tlp_value.strip() else self.configured_tlp()
            case_tlp = _tlp.parse(str(data.get("tlp") or current.value_str))
            if case_tlp > current:
                tlp_value = case_tlp.value_str
        except ValueError:
            pass
        return dataclasses.replace(
            req,
            inputs=[str(items[i - 1]["entity"]) for i in picks],
            etype=None,
            tlp=tlp_value,
            purpose=str(options.get("purpose") or req.purpose or ""),
            ticket=str(options.get("ticket") or req.ticket or ""),
            legal_basis=str(options.get("legal_basis") or req.legal_basis or ""),
            expand_personal=False,
            incident_victim=False,
            confirmed_urls=list(req.confirmed_urls),
        )

    def show_case(self, data: dict[str, Any], full: bool = False, *, show_personal: bool | None = None) -> None:
        """Render a case. ``show_personal`` is the unmasked view of THIS rendering only (AR24): the
        post-scan view passes the request flag, ``cases show`` passes False unless asked; None keeps
        the v1 behaviour (the flag recorded in the case options)."""
        render_case(self.console, data, full=full, show_personal=show_personal)
        reports = data.get("reports") or {}
        if reports:
            self.console.print(Text("\n[◈] reports", style="v.accent"))
            for fmt, path in reports.items():
                self.console.print(Text.assemble((f"    {fmt:5} ", "v.dim"), (_plain(path), "v.url")), soft_wrap=True)

    def ask_feedback(self, data: dict[str, Any]) -> None:
        """The closing question (P325): delegated to ``v3lum.ui.feedback.ask_feedback`` (WP16)."""
        if not _stdin_tty():
            return
        try:
            from v3lum.ui.feedback import ask_feedback
        except Exception:  # noqa: BLE001 - WP16 not installed: record the overall verdict only
            ask_feedback = None
        if ask_feedback is not None:
            ask_feedback(self.console, self.store, data, analyst=self.analyst())
            return
        self.console.print()
        answer = Prompt.ask(
            "[v.accent]⟁ did this report make sense?[/] [v.dim]([b]y[/]es / [b]p[/]artially / [b]n[/]o / [b]s[/]kip)[/]",
            choices=["y", "p", "n", "s"], default="s", console=self.console, show_choices=False,
        )
        if answer == "s":
            return
        verdict = {"y": "yes", "p": "partial", "n": "no"}[answer]
        notes = Prompt.ask("[v.dim]notes for the record (optional)[/]", default="", console=self.console)
        self.store.add_feedback(data["case_id"], verdict, notes, analyst=self.analyst())
        self.console.print(Text("[✓] feedback stored", style="v.ok"))

    # ------------------------------------------------------------------ single module
    def run_single(
        self,
        module_name: str,
        raw: str,
        etype: EntityType | None = None,
        mode: Opsec | str | None = None,
        authorized: Any = None,
        *,
        request: ScanRequest | None = None,
    ) -> dict[str, Any]:
        """``v3lum run``: one module on one input through the policy gate (``Engine.decide_single``,
        path 'run'). The mode is ``mode``/``request.mode`` (default: setting mode, passive) and is
        never escalated: a LIGHT module in passive mode is refused with 'needs --mode light:
        contacts the target' (A7). Refusals (TLP:RED, exhausted quota, missing authorization...)
        raise UserError with the readable reason. LIGHT/ACTIVE runs write a case with its audit
        record and request ledger (A7); PASSIVE runs write nothing, unless ``--tlp`` is below the
        configured default: that run writes a case so the lowering reaches its audit (A2, AR17).
        """
        try:
            cls = get_module(module_name)
        except KeyError as exc:
            raise UserError(str(exc)) from exc
        if request is None:
            request = ScanRequest(inputs=[raw], etype=etype, mode=Opsec.parse(mode) if mode is not None else self.configured_mode(), interactive=False)
            if isinstance(authorized, str):
                request.authorization_ref = authorized
        req = dataclasses.replace(request, inputs=[raw], etype=etype if etype is not None else request.etype, path="run")
        eng = self._engagement(req)
        hits: list[dict[str, str]] = []
        value = self.scrub_input(raw, req.etype, hits=hits)
        if not value.strip():
            raise UserError("nothing left to investigate once credentials were removed (P145)")
        found = det.detect(value, explicit=req.etype)
        target = next((d for d in found if d.type in cls.accepts), None)
        if target is None:
            accepted = ", ".join(sorted(t.value for t in cls.accepts))
            raise UserError(f"{cls.name} accepts {accepted}; {_short(value)!r} was read as {found[0].type.value if found else 'nothing'} (force with TYPE:value)")
        self._report_scrub(hits)
        if target.confidence < LOW_CONFIDENCE:
            self.notice(f"[i] {_short(value)} read as {target.type.value} ({target.confidence:.2f}); force with TYPE:value")
        unconfirmed: set[str] = set()
        if target.type in CONFIRM_TYPES and target.confidence < LOW_CONFIDENCE:
            ok = req.interactive and _stdin_tty() and Confirm.ask(
                f"[v.warn]investigate {escape(_short(value))!r} as a {target.type.value}?[/]", default=False, console=self.console,
            )
            if not ok:
                unconfirmed.add(target.entity.key)
        contact = cls.opsec >= Opsec.LIGHT
        req.include = {cls.name}
        req.depth = 0
        req.save_evidence = bool(req.save_evidence and contact)
        options = self.scan_options(req, [target.entity], unconfirmed=unconfirmed, engagement=eng)
        options.include = {cls.name}
        rt = self.runtime()
        self.prepare_runtime(rt, options, path="run", notes=eng.notes, audit=False)
        engine = _PathEngine(rt, options, path="run", **self._engine_feedback())
        decision = engine.decide_single(cls, target.entity, path="run")
        if not getattr(decision, "allowed", False):
            raise UserError(f"{cls.name} cannot run: {getattr(decision, 'reason', '') or 'refused by the policy gate'}")
        if not contact and getattr(options, "tlp_change", None) is None:
            res = engine.run_module(cls, target.entity, decision=decision)
            return self._single_out(cls, target.entity, res, options)
        # LIGHT/ACTIVE (A7), or a TLP below the configured default (A2: the lowering is recorded in
        # the case audit): a case with its audit record (and, for contact, the request ledger)
        self.install_audit(rt, options)
        self._confirm_active(req, options, [target.entity])
        case = engine.investigate([target.entity], detections=[target])
        data = case.to_dict()
        self._record_case(case, data, options)
        res = next((r for r in case.results if r.module == cls.name and r.entity == target.entity), None)
        if res is None:  # refused or stopped inside the investigation (guard after passive results)
            row = ((data.get("coverage") or {}).get(cls.name) or {}).get("entities", {}).get(target.entity.key, {})
            out = self._single_out(cls, target.entity, None, options)
            out.update(status=str(row.get("status") or "skipped"), reason_code=str(row.get("reason_code") or ""), error=str(row.get("reason") or ""))
        else:
            out = self._single_out(cls, target.entity, res, options)
        out["case_id"] = case.case_id
        self.notice(f"[i] case {case.case_id} recorded with its audit trail (v3lum cases show {case.case_id})")
        return out

    def _single_out(self, cls: Any, entity: Entity, res: Any, options: ScanOptions | None = None) -> dict[str, Any]:
        """The ``v3lum run`` result dict (``render_single`` / ``--json``): module, entity, status,
        reason_code, error, duration, findings, attributes, pivots, links, raw (``--debug``), partial,
        stop_reason and the view facts tlp, show_personal, no_defang; SECRET values redacted."""
        view = {
            "tlp": str(getattr(options, "tlp", "") or self.configured_tlp().value_str),
            "show_personal": bool(getattr(options, "show_personal", False)),
            "no_defang": bool(getattr(options, "no_defang", False)),
        }
        if res is None:
            out: dict[str, Any] = {
                "module": cls.name, "entity": entity.key, "status": "skipped", "reason_code": "", "error": "", "duration": 0.0,
                "findings": [], "attributes": {}, "pivots": [], "links": [], "raw": None, "partial": False, "stop_reason": "", **view,
            }
            return redact_secret_values(out, secret_value_map([entity]))
        links = []
        for item in res.links or ():
            if isinstance(item, dict):
                links.append({"label": item.get("label", ""), "url": item.get("url", "")})
            else:
                label, url = item[0], item[1]
                links.append({"label": label, "url": url})
        out = {
            "module": cls.name,
            "entity": entity.key,
            "status": res.status.value,
            "reason_code": getattr(res, "reason_code", "") or "",
            "error": res.error,
            "duration": round(res.duration, 2),
            "findings": [f.to_dict() for f in res.findings],
            "attributes": res.attributes,
            "pivots": [{"entity": p.entity.key, "relation": p.relation, "confidence": p.confidence} for p in res.pivots],
            "links": links,
            "raw": res.raw if self.debug else None,
            "partial": bool(getattr(res, "partial", False)),
            "stop_reason": str(getattr(res, "stop_reason", "") or ""),
            **view,
        }
        return redact_secret_values(out, secret_value_map([entity, *(p.entity for p in res.pivots)]))

    def show_single(self, out: dict[str, Any]) -> None:
        """Delegated to ``v3lum.ui.render.render_single`` (WP14, safe text)."""
        try:
            from v3lum.ui.render import render_single
        except ImportError:
            render_single = None
        if render_single is not None:
            render_single(self.console, out)
            return
        st = str(out.get("status", ""))
        head = Text()
        head.append(f"{_plain(out['module'])} ", style="v.module")
        head.append("→ ", style="v.ghost")
        head.append(_plain(out["entity"]), style="v.entity")
        head.append(f"   [{st}]", style=f"status.{st}")
        head.append(f"  {out.get('duration', 0)}s", style="v.ghost")
        self.console.print(head)
        if out.get("error"):
            self.console.print(Text(f"  {_plain(out['error'])}", style="v.dim"))
        for f in out.get("findings") or ():
            self.console.print(Text.assemble((f"  {f.get('severity', '')} ", f"sev.{f.get('severity', 'info')}"), (_plain(f.get("title", "")), "v.text")))
        for k, v in (out.get("attributes") or {}).items():
            shown = json.dumps(v, ensure_ascii=False, default=str)[:400] if isinstance(v, (list, dict)) else str(v)
            self.console.print(Text.assemble((f"  {_plain(k)}: ", "v.dim"), (_plain(shown), "v.text")))
        for p in (out.get("pivots") or [])[:100]:
            self.console.print(Text.assemble(("  ↳ ", "v.ghost"), (f"{_plain(p['relation'])} ", "v.ghost"), (_plain(p["entity"]), "v.entity")))
        for link in (out.get("links") or [])[:30]:
            self.console.print(Text.assemble(("  ↗ ", "v.accent"), (_plain(link["label"]) + "  ", "v.text"), (_plain(link["url"]), "v.url")))

    # ------------------------------------------------------------------ catalog
    def policy_listing_context(self) -> Any:
        """A PolicyContext for catalog views (``v3lum modules``/``info``: the effective default
        set of a plain scan, A3), built with ``policy.make_context`` like every path."""
        try:
            rt = self.runtime()
        except UserError:  # e.g. --tor without PySocks: a listing sends nothing, so no proxy is needed
            rt = Runtime(self.config, offline=self.offline, no_cache=True)
        return policy.make_context(rt, ScanOptions(offline=self.offline, tlp=self.configured_tlp().value_str), path="scan")

    def default_membership(self, pctx: Any = None, *, modules: Iterable[Any] | None = None) -> dict[str, tuple[bool, str, str]]:
        """module name -> (in the effective default set, reason_code, reason) - A3: in the default
        set when a plain scan of some accepted type runs it; else the first refusal. ``modules``
        restricts the evaluated entity types to theirs (``v3lum info``)."""
        pctx = pctx if pctx is not None else self.policy_listing_context()
        out: dict[str, tuple[bool, str, str]] = {}
        wanted = list(modules) if modules is not None else list(REGISTRY.values())
        types = sorted({t for cls in wanted for t in cls.accepts}, key=lambda t: t.value)
        for etype in types:
            try:
                rows = policy.effective_default_set(etype, pctx, include_blocked=True)
            except Exception as exc:  # noqa: BLE001 - a listing never breaks on one type
                log.warning("default set for %s unavailable: %s", etype.value, exc)
                continue
            for cls, decision in rows:
                current = out.get(cls.name)
                if decision.allowed:
                    out[cls.name] = (True, "", str(decision.reason or ""))
                elif current is None:
                    out[cls.name] = (False, str(decision.reason_code or ""), str(decision.reason or ""))
        return out

    @staticmethod
    def _source_cell(d: dict[str, Any]) -> Text:
        disclosure = str(d.get("disclosure") or "?")
        tier = str(d.get("trust_tier") or "n/a")
        text = Text(disclosure, style="v.text")
        if disclosure in ("third_party", "internal"):
            text.append(f" · {tier}", style="v.warn" if tier == "unknown" else "v.dim")
        text.append(f" · {d.get('terms', '?')}", style="v.warn" if d.get("terms") in ("unknown", "noncommercial", "license") else "v.dim")
        flags = [name for key, name in (("publishes_queries", "publishes"), ("reuses_queries", "reuses"), ("fetches_target", "fetches target"), ("sensitive", "sensitive")) if d.get(key)]
        if flags:
            text.append(f" · {', '.join(flags)}", style="v.warn")
        access = str(d.get("access_label") or "")
        if access and disclosure != "none":
            text.append(f" · {access}", style="v.ghost")
        return text

    def modules_table(self, category: str = "", search: str = "", etype: EntityType | None = None, ready_only: bool = False) -> Table:
        """The module catalog: opsec, disclosure · tier · terms class (+ publishes/reuses/
        fetches-target/sensitive flags), access, run_on and the effective-default-set membership
        (or its reason code, A3/A8/P327)."""
        keys = self.config.keys()
        mode = self.configured_mode()
        pctx = self.policy_listing_context()
        member = self.default_membership(pctx)
        t = Table(
            box=box.SIMPLE_HEAVY, header_style="v.dim", expand=True, title_justify="left",
            title=f"[v.accent]⌬ modules[/] [v.dim]({len(REGISTRY)} loaded, mode {mode.label}, licence profile {escape(str(pctx.licence_profile))})[/]",
        )
        t.add_column("module", style="v.module", no_wrap=True)
        t.add_column("accepts", style="v.type", overflow="fold", max_width=22)
        t.add_column("opsec", no_wrap=True)
        t.add_column("source", overflow="fold", max_width=34)
        t.add_column("default set", overflow="fold", max_width=18)
        t.add_column("description", style="v.text", overflow="fold", ratio=3, min_width=24)
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
            ok, _reason = readiness(cls, keys, Opsec.ACTIVE, True)
            if ready_only and not ok:
                continue
            d = cls.describe()
            in_default, code, _why = member.get(cls.name, (False, "", ""))
            if in_default:
                default_cell = Text("yes", style="status.ok")
            else:
                default_cell = Text(code or "no", style="status.needs_key" if code == "needs_key" else "v.dim")
            run_on = str(d.get("run_on") or "any")
            if run_on != "any":
                default_cell.append(f" · {run_on}", style="v.ghost")
            opsec_style = {"passive": "v.ok", "light": "v.info", "active": "v.warn"}[cls.opsec.label]
            if cls.category != current_cat:
                current_cat = cls.category
                t.add_row(Text(f"▌{CATEGORIES.get(cls.category, cls.category)}", style="v.accent"), "", "", "", "", Text(cls.category, style="v.ghost"))
            t.add_row(
                " " + cls.name, ", ".join(sorted(x.value for x in cls.accepts)), Text(cls.opsec.label, style=opsec_style),
                self._source_cell(d), default_cell, Text(_plain(cls.description)),
            )
            count += 1
        t.caption = f"{count} shown · default set = runs in a plain `v3lum scan` (else the reason code) · `v3lum info <module>` explains the policy"
        return t

    def module_info(self, name: str) -> Panel:
        """Module details with the policy that applies to it and why (``policy.describe_policy``),
        the effective-default-set membership and the active licence_allow entries of its sources."""
        try:
            cls = get_module(name)
        except KeyError as exc:
            raise UserError(str(exc)) from exc
        d = cls.describe()
        ok, reason = readiness(cls, self.config.keys(), Opsec.ACTIVE, True)
        pctx = self.policy_listing_context()
        in_default, code, why = self.default_membership(pctx, modules=[cls]).get(cls.name, (False, "", ""))
        try:
            lines = policy.describe_policy(cls, pctx)
        except Exception as exc:  # noqa: BLE001 - the panel still shows the metadata
            lines = [f"policy explanation unavailable: {type(exc).__name__}"]
        g = Table.grid(padding=(0, 2))
        g.add_column(style="v.dim", justify="right")
        g.add_column(style="v.text", overflow="fold")

        def row(label: str, value: Any) -> None:
            g.add_row(label, value if isinstance(value, Text) else Text(_plain(value)))

        row("title", d["title"])
        row("category", f"{d['category']} — {CATEGORIES.get(d['category'], '')}")
        row("accepts", ", ".join(d["accepts"]))
        row("produces", ", ".join(d["produces"]) or "-")
        row("opsec", d["opsec"])
        row("disclosure", d.get("disclosure", "?"))
        row("provider tier", d.get("trust_tier", "n/a"))
        terms_sources = d.get("terms_sources") or {}
        row("terms", f"{d['terms']}" + (f" ({', '.join(f'{s}: {c}' for s, c in sorted(terms_sources.items()))})" if terms_sources else ""))
        flags = [n for k, n in (("publishes_queries", "publishes lookups (rule 7)"), ("reuses_queries", "reuses queries"), ("fetches_target", "fetches the target"), ("sensitive", "sensitive (P145 sanitizer)")) if d.get(k)]
        row("flags", ", ".join(flags) or "none")
        row("access", d.get("access_label") or d.get("access_model") or "-")
        row("run on", d.get("run_on", "any"))
        row("keys", (", ".join(d["requires_keys"]) or "none") + (f" (optional: {', '.join(d['optional_keys'])})" if d["optional_keys"] else ""))
        row("packages", ", ".join(d["requires_packages"]) or "-")
        row("hosts", ", ".join(d["hosts"]) or ("target (contact)" if d.get("disclosure") == "target" else "offline"))
        row("reference", d["reference"] or "-")
        row("tags", ", ".join(d["tags"]) or "-")
        row("default set", Text("yes (runs in a plain scan)", style="status.ok") if in_default else Text(f"no - {code}: {_plain(why)}" if code else "no", style="v.warn"))
        row("status", Text("ready", style="status.ok") if ok else Text(_plain(reason), style="status.needs_key"))
        if d["notice"]:
            row("notice", Text(_plain(d["notice"]), style="v.warn"))
        row("policy", Text("\n".join(_plain(line) for line in lines), style="v.text"))
        return Panel(g, title=f"[v.module]{escape(d['name'])}[/]", subtitle=escape(d["description"][:100]), border_style="v.accent")

    def keys_table(self) -> Table:
        """API keys: delegated to ``v3lum.commands.keys.keys_table`` (WP18)."""
        return self._command_function("keys", "keys_table")(self)

    def set_key(self, name: str, value: str | None, *, plan: str | None = None) -> None:
        """Store a key 0600 (prompted hidden when ``value`` is empty) and its plan: delegated to
        ``v3lum.commands.keys.set_key`` (WP18)."""
        self._command_function("keys", "set_key")(self, name, value, plan=plan)

    @staticmethod
    def _command_function(module: str, name: str) -> Any:
        """``v3lum.commands.<module>.<name>`` (UserError when the command module is unavailable)."""
        import importlib

        try:
            fn = getattr(importlib.import_module(f"v3lum.commands.{module}"), name)
        except Exception as exc:  # noqa: BLE001 - doctor lists command-module load errors
            raise UserError(f"`v3lum {module}` is unavailable: {type(exc).__name__}: {exc}") from exc
        if not callable(fn):
            raise UserError(f"`v3lum {module}` is unavailable: {name} is not callable")
        return fn

    # ------------------------------------------------------------------ cases
    def cases_table(self, limit: int = 30, search: str = "") -> Table:
        t = Table(box=box.SIMPLE_HEAVY, header_style="v.dim", expand=True, title="[v.accent]☰ cases[/]", title_justify="left")
        t.add_column("case", style="v.title", no_wrap=True)
        t.add_column("created", style="v.dim", no_wrap=True)
        t.add_column("tlp", no_wrap=True)
        t.add_column("inputs", style="v.entity", overflow="fold", ratio=3)
        t.add_column("risk", no_wrap=True)
        t.add_column("findings", justify="right")
        t.add_column("entities", justify="right")
        for c in self.store.list_cases(limit, search):
            lvl = _level_word(c.get("risk_level"))  # v1 'clean' is never printed (P302 cond 6, AR14)
            held = " (held)" if c.get("legal_hold") else ""
            t.add_row(
                Text(_plain(str(c["id"])) + held), Text(_plain(str(c["created"])[:19])), Text(_plain(str(c.get("tlp") or ""))),
                Text(_seeds_display(c.get("seeds"))),
                Text(f"{lvl} {c.get('risk_score') or 0:.0f}", style=_risk_style(lvl)), str(c.get("findings") or 0), str(c.get("entities") or 0),
            )
        return t

    def load_case(self, case_id: str) -> dict[str, Any]:
        data = self.store.get_case(case_id)
        if data is None:
            raise UserError(f"case {case_id!r} not found (see `v3lum cases list`)")
        return data

    # ------------------------------------------------------------------ links / extract
    def links(self, raw: str, etype: EntityType | None) -> list[tuple[str, str, str]]:
        from v3lum.core.links import links_for

        value = self.scrub_input(raw, etype)
        found = det.detect(value, explicit=etype)
        if not found:
            raise UserError(f"could not interpret {_short(value)!r}")
        out = []
        for d in det.primary(found):
            for label, url in links_for(d.entity):
                out.append((d.entity.key, label, url))
        return out

    def extract(self, text: str, types: set[str] | None = None, *, hits: list[dict[str, str]] | None = None) -> list[Entity]:
        """IOCs of ``text`` after ``ioc.scrub`` (P145 cond 5, P323 cond 5-7: combos, secrets and
        card numbers never reach the output)."""
        clean = _ioc.scrub(text, hits=hits) if text else text
        ents = det.extract_iocs(clean)
        if types:
            ents = [e for e in ents if e.type.value in types]
        return ents

    # ------------------------------------------------------------------ maintenance
    def data_update(self, names: list[str] | None = None) -> list[tuple[str, str]]:
        """Refresh datasets the way ``v3lum data update`` does (WP18): ``DataStore.update`` per
        registered dataset (SHA-256 pins, a changed active dataset waits for review, terms-gated
        datasets are not registered). Returns ``(name, status)`` rows; never a raw re-download."""
        rt = self.runtime()
        selected = list(dict.fromkeys(names)) if names else sorted(DATASETS)
        results: list[tuple[str, str]] = []
        for name in selected:
            if name not in DATASETS:
                results.append((name, "failed: not a registered dataset"))
                continue
            try:
                res = rt.data.update(name)
            except Exception as exc:  # noqa: BLE001 - one broken dataset never stops the others
                results.append((name, f"failed: {type(exc).__name__}"))
                continue
            status = str(getattr(res, "status", "") or "failed")
            reason = str(getattr(res, "reason", "") or "")
            results.append((name, _plain(f"{status}: {reason}" if reason else status)))
        return results

    def doctor(self) -> Table:
        """Environment check: delegated to ``v3lum.commands.doctor.doctor_table`` (WP18; it probes only
        sources the licence profile allows, A1/P377 cond 2)."""
        return self._command_function("doctor", "doctor_table")(self)


def level_at_least(level: str | Mapping[str, Any], threshold: str) -> bool:
    """Is the case ``level`` at or above ``threshold`` (low..critical)? The lowest readings - 'no findings'
    (risk model v2), 'inconclusive' and v1 'clean' - are below every threshold.

    ``level`` may also be the case dict: the automation level ``risk['automation']['level']`` is then
    used (P302 cond 10: scores of PERSONAL_TYPES entities never drive an automated action such as
    ``--fail-on``), falling back to ``summary.risk_level`` for a v1 case without it."""
    if isinstance(level, Mapping):
        risk = level.get("risk") if isinstance(level.get("risk"), Mapping) else {}
        auto = risk.get("automation") if isinstance(risk.get("automation"), Mapping) else None
        summary = level.get("summary") if isinstance(level.get("summary"), Mapping) else {}
        level = str((auto or {}).get("level") or "") if auto is not None else str(summary.get("risk_level") or risk.get("level") or "")
    text = str(level or "").strip().lower()
    rank = LEVEL_ORDER.index(text) if text in LEVEL_ORDER else 0
    return rank >= LEVEL_ORDER.index(threshold)


def _seeds_display(seeds: Any) -> str:
    """Seed keys for a listing with personal identifiers masked (AR24; the WP18 `cases list` helper)."""
    from v3lum.commands.cases import seeds_display

    return seeds_display(seeds)


def _level_word(level: Any) -> str:
    """A stored risk level for display: v1 'clean' and empty read 'no findings' (P302 cond 6)."""
    text = str(level or "").strip().lower()
    return "no findings" if text in ("", "clean", "none", "no_findings") else text


def _risk_style(level: str) -> str:
    """The theme style of a displayed level ('no findings' -> risk.no_findings)."""
    try:
        from v3lum.ui.theme import risk_style
    except ImportError:  # pragma: no cover - an older theme module
        return "v.text"
    return risk_style(level)


def entity_type_or_none(value: str | None) -> EntityType | None:
    if not value:
        return None
    try:
        return EntityType.parse(value)
    except ValueError as exc:
        raise UserError(f"{exc}. Valid types: {', '.join(t.value for t in EntityType)}") from exc


def defanged(value: str) -> str:
    return defang(value)


__all__ = [
    "App",
    "BREACH_SCOPES",
    "EXECUTION_PATHS",
    "FORMATS",
    "LEGAL_BASES",
    "LICENCE_PROFILES",
    "PRESETS",
    "RunInfo",
    "ScanRequest",
    "Status",
    "TLP_CHOICES",
    "TOR_PROXY",
    "UserError",
    "defanged",
    "entity_type_or_none",
    "level_at_least",
]
