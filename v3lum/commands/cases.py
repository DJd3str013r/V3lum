"""``v3lum cases``: the case lifecycle (A10, P324, P325, P334, P322).

Sub-commands (``cases`` alone = ``cases list``):

* ``list [-n N] [-s TEXT] [--json]`` - stored cases, newest first; held cases are marked
  ('held'), LIGHT/ACTIVE engagements too. Personal seeds match only when typed exactly (A4).
* ``show <id> [--full] [--json]`` and ``report <id> [-f FORMATS] [-o DIR]`` - the stored case
  ('last' and unique id prefixes work) with the analyst overrides applied (:func:`apply_overrides`);
  written reports are recorded with their SHA-256 (:func:`record_reports`: the purge removes them,
  ``cases verify`` recomputes them) and the re-render is written to the case audit trail.
* ``delete <id> [--dry-run]`` - the one A10 purge routine (``Store.purge_case``): every copy goes,
  a value-free tombstone stays; a case under legal hold is refused, and so is the org-profile
  audit trail (:data:`RESERVED_TRAILS`: not a case; ``cases verify org-profile`` checks its chain).
* ``purge [--older-than DAYS] [--dry-run]`` - ``Store.purge_older_than`` (default: setting
  ``retention_days``); held cases are skipped and listed.
* ``hold <id> --reason TEXT --requester NAME`` / ``unhold <id>`` - legal hold (audited).
* ``verify <id>`` - ``audit.verify_case``: evidence and report hashes, audit and ledger chains,
  offline; prints PASS or FAIL with every problem (exit 1 on FAIL).
* ``feedback <id>`` - ``ui.feedback.ask_feedback`` (P325: verdict, explicit votes).
* ``override <case> <finding> [--label L] [--severity S] [--verdict right|wrong] [--note TEXT]``
  and ``confirm <case> <finding>`` (= ``--label confirmed``) - ``Store.set_override`` (P322 cond 3),
  each written to the case audit trail (kind 'override'); they take effect on the next render or
  re-run.
* ``resume <id>`` - re-runs only the deferred (``QuotaBook.deferred``) and could-not-verify
  (module, entity) pairs of a stored case (P334 cond 7) through ``Engine.investigate(only_pairs=...)``
  with each pair's recorded run facts (is_seed, depth, provenance, TLP) and the stored options
  (TLP, purpose, mode, scope reference); the new case records ``meta['resumed_from']``. A pivot is
  never promoted to a typed seed and the mode never escalates; an ACTIVE case needs
  ``--authorized REF --scope FILE`` again (A7: every path).
"""

from __future__ import annotations

import datetime as _dt
import getpass
import hashlib
import math
import os
import json
import logging
import sys
from collections.abc import Iterable, Mapping
from typing import Any

from rich import box
from rich.table import Table
from rich.text import Text

from v3lum import paths
from v3lum.commands import command

log = logging.getLogger("v3lum.commands.cases")

__all__ = [
    "CNV_STATUSES",
    "Cases",
    "RESERVED_TRAILS",
    "apply_overrides",
    "record_reports",
    "resume_plan",
    "run_info_of",
]

def _cnv_statuses() -> frozenset[str]:
    try:
        from v3lum.core.models import Status

        return frozenset(s.value for s in Status if s.could_not_verify)
    except Exception:  # noqa: BLE001 - the wave-1 set
        return frozenset({"quota", "rate_limited", "blocked", "error", "needs_key", "unavailable"})


#: Execution statuses that read 'could not verify' (``models.Status.could_not_verify``) - resumable.
CNV_STATUSES = _cnv_statuses()
#: Partial runs cut by one of these stop reasons are resumable too.
RESUMABLE_STOPS = frozenset({"deadline", "quota", "cancelled", "window"})
LABELS = ("confirmed", "probable", "possible")
SEVERITIES = ("info", "low", "medium", "high", "critical")
VERDICTS = ("right", "wrong")
OVERRIDE_AUDIT_KIND = "override"
#: Audit trails that are not cases (``v3lum.commands.org.AUDIT_CASE_ID``): ``cases verify`` checks
#: their hash chain, ``cases delete`` refuses them (P378 cond 11: profile changes stay logged).
RESERVED_TRAILS = frozenset({"org-profile"})
#: Largest ``cases purge --older-than`` (100 years; larger values overflow the date arithmetic).
MAX_PURGE_DAYS = 36500


# --------------------------------------------------------------------------------------
# small helpers
# --------------------------------------------------------------------------------------


def _clean(value: Any) -> str:
    try:
        from v3lum.ui.safe import clean_text

        return clean_text(value)
    except Exception:  # noqa: BLE001 - WP14 helper unavailable: drop control characters here
        return "".join(ch for ch in str(value or "") if ch in "\n\t" or (ord(ch) >= 32 and not 0x7F <= ord(ch) <= 0x9F))


def _user_error(message: str) -> Exception:
    from v3lum.app import UserError

    return UserError(message)


def _analyst(app: Any) -> str:
    fn = getattr(app, "analyst", None)
    if callable(fn):
        try:
            return str(fn() or "")
        except Exception:  # noqa: BLE001
            pass
    configured = str(app.config.get("analyst") or "").strip()
    if configured:
        return configured
    try:
        return getpass.getuser()
    except Exception:  # noqa: BLE001 - no OS user name available
        return "unknown"


def _split(value: str | None) -> list[str]:
    return [v.strip() for v in (value or "").split(",") if v.strip()]


def _stdin_tty() -> bool:
    try:
        return bool(sys.stdin.isatty())
    except (AttributeError, ValueError):
        return False


def _stored(app: Any, case_id: str) -> dict[str, Any]:
    data = app.store.get_case(case_id)
    if data is None:
        raise _user_error(f"case {_clean(case_id)[:80]!r} not found (see `v3lum cases list`)")
    return data


def _exact_id(app: Any, case_id: str) -> str:
    """The stored id for 'last'/a unique prefix, else ``case_id`` as given (purge also cleans case
    directories and engagement audits of cases without a row)."""
    data = app.store.get_case(case_id)
    return str(data["case_id"]) if data is not None else case_id


def audit_append(store: Any, case_id: str, case_dir: str, kind: str, payload: Mapping[str, Any]) -> None:
    """One hash-chained audit row: ``audit.CaseAudit`` (WP15; mirrored to ``audit.jsonl``) when it
    is available, else the store's own chain (the same hash format)."""
    try:
        from v3lum.core.audit import CaseAudit
    except Exception:  # noqa: BLE001 - WP15 not installed: the store's chain still records it
        store.append_audit(case_id, kind, dict(payload))
        return
    CaseAudit(store, case_id, case_dir).append(kind, dict(payload))


def _file_sha256(path: str) -> str:
    digest = hashlib.sha256()
    with open(path, "rb") as fh:
        for block in iter(lambda: fh.read(1 << 20), b""):
            digest.update(block)
    return digest.hexdigest()


def record_reports(store: Any, case_id: str, written: Mapping[str, Any], *, analyst: str = "", audit: bool = False) -> dict[str, str]:
    """Record report files written for a case: their paths (the A10 purge removes them, ``-o``
    included) and their SHA-256 (``Store.record_report_hashes``: ``cases verify`` recomputes them,
    P324 cond 6; a re-rendered report replaces the recorded hash). With ``audit`` the re-render is
    also written to the case audit trail (kind 'report': format, file name and SHA-256 - no
    directory). Returns ``{path: sha256}`` of the files that could be hashed."""
    store.record_report_paths(case_id, written)
    hashes: dict[str, str] = {}
    for path in (written or {}).values():
        try:
            hashes[os.path.abspath(os.fspath(path))] = _file_sha256(os.fspath(path))
        except (OSError, TypeError):
            continue
    record = getattr(store, "record_report_hashes", None)
    if hashes and callable(record):
        record(case_id, hashes)
    if audit and hashes:
        files = [
            {"format": str(fmt), "file": os.path.basename(os.fspath(path)), "sha256": hashes[os.path.abspath(os.fspath(path))]}
            for fmt, path in sorted((written or {}).items())
            if os.path.abspath(os.fspath(path)) in hashes
        ]
        try:
            case_dir = str(paths.case_dir(case_id))
        except ValueError:
            case_dir = ""
        payload: dict[str, Any] = {"action": "render", "reports": files}
        if analyst:
            payload["analyst"] = analyst
        audit_append(store, case_id, case_dir, "report", payload)
    return hashes


# --------------------------------------------------------------------------------------
# overrides (P322 cond 3)
# --------------------------------------------------------------------------------------


def _finding_ids(case: Mapping[str, Any]) -> list[str]:
    ids = [str(f.get("id")) for f in case.get("findings") or () if isinstance(f, Mapping) and f.get("id")]
    ids += [str(c.get("id")) for c in case.get("correlations") or () if isinstance(c, Mapping) and c.get("id")]
    return ids


def _resolve_finding(case: Mapping[str, Any], finding_id: str) -> str:
    ids = _finding_ids(case)
    if finding_id in ids:
        return finding_id
    matches = sorted({i for i in ids if i.startswith(finding_id)}) if len(finding_id) >= 4 else []
    if len(matches) == 1:
        return matches[0]
    if matches:
        raise _user_error(f"finding id {finding_id!r} is ambiguous in case {case.get('case_id')}: {', '.join(m[:16] for m in matches[:5])}")
    raise _user_error(f"finding {finding_id!r} is not in case {case.get('case_id')} (ids: `v3lum cases show {case.get('case_id')} --json`)")


def _overrides_for(store: Any, ids: list[str]) -> dict[str, list[dict[str, Any]]]:
    """finding id -> override rows (newest last) from ``Store.overrides_for`` (WP16) or the table."""
    if not ids:
        return {}
    fn = getattr(store, "overrides_for", None)
    raw: Any = None
    if callable(fn):
        try:
            raw = fn(ids)
        except Exception as exc:  # noqa: BLE001 - fall back to the table
            log.debug("overrides_for failed: %s", type(exc).__name__)
            raw = None
    out: dict[str, list[dict[str, Any]]] = {}
    if isinstance(raw, Mapping):
        for fid, value in raw.items():
            rows = value if isinstance(value, list) else [value]
            out[str(fid)] = [dict(r) for r in rows if isinstance(r, Mapping)]
        return out
    try:
        with store.connection() as conn:
            marks = ",".join("?" for _ in ids)
            cur = conn.execute(
                f"SELECT finding_id, analyst, label, severity, verdict, note, created FROM overrides WHERE finding_id IN ({marks}) ORDER BY created",  # noqa: S608 - placeholders only
                list(ids),
            )
            names = [d[0] for d in cur.description]
            for row in cur.fetchall():
                item = dict(zip(names, row))
                out.setdefault(str(item["finding_id"]), []).append(item)
    except Exception as exc:  # noqa: BLE001 - no overrides table: nothing to apply
        log.debug("overrides table unavailable: %s", type(exc).__name__)
    return out


def _merge(rows: list[dict[str, Any]]) -> dict[str, Any]:
    """One effective override from several analysts' rows (the newest non-empty value of each field)."""
    merged: dict[str, Any] = {}
    for row in sorted(rows, key=lambda r: str(r.get("created") or r.get("at") or "")):
        for key in ("label", "severity", "verdict", "note", "analyst"):
            value = row.get(key)
            if value not in (None, ""):
                merged[key] = value
        stamp = row.get("created") or row.get("at")
        if stamp:
            merged["at"] = stamp
    return merged


def apply_overrides(case: dict[str, Any], overrides: Mapping[str, list[dict[str, Any]]]) -> int:
    """Apply analyst overrides to a stored case dict for display (the analyst's decision wins,
    P322 cond 3), in the format of ``models.Finding.apply_override``: each overridden finding or
    correlation gets ``override`` = {analyst, label, severity, verdict, note, at, auto: {label,
    severity, criterion}} and its ``confidence_label`` / ``severity`` take the override values (the
    automatic ones stay under ``override['auto']``). Returns the number of items changed. Only the
    dict passed in is changed (the stored case is not)."""
    changed = 0
    for collection in ("findings", "correlations"):
        for item in case.get(collection) or ():
            if not isinstance(item, dict):
                continue
            rows = overrides.get(str(item.get("id") or ""))
            if not rows:
                continue
            merged = _merge(rows)
            previous = item.get("override") if isinstance(item.get("override"), dict) else {}
            auto = previous.get("auto") if isinstance(previous.get("auto"), dict) else {
                "label": item.get("confidence_label"), "severity": item.get("severity"), "criterion": item.get("criterion", ""),
            }
            if merged.get("label"):
                item["confidence_label"] = merged["label"]
            if merged.get("severity"):
                item["severity"] = merged["severity"]
            item["override"] = {
                "analyst": merged.get("analyst", previous.get("analyst", "")),
                "label": merged.get("label", previous.get("label")),
                "severity": merged.get("severity", previous.get("severity")),
                "verdict": merged.get("verdict", previous.get("verdict")),
                "note": merged.get("note", previous.get("note", "")),
                "at": merged.get("at", previous.get("at", "")),
                "auto": dict(auto),
            }
            changed += 1
    return changed


def _with_overrides(app: Any, case: dict[str, Any]) -> dict[str, Any]:
    ids = _finding_ids(case)
    if ids:
        apply_overrides(case, _overrides_for(app.store, ids))
    return case


def _set_override(
    store: Any, finding_id: str, *, analyst: str, label: str | None, severity: str | None, verdict: str | None, note: str, case_id: str = ""
) -> None:
    fn = getattr(store, "set_override", None)
    if callable(fn):
        try:
            fn(finding_id, analyst=analyst, label=label, severity=severity, verdict=verdict, note=note, case_id=case_id)
        except ValueError as exc:
            raise _user_error(str(exc)) from exc
        return
    # interim (WP16 not installed yet): the same row in the overrides table, one per (finding, analyst)
    stamp = _dt.datetime.now(_dt.timezone.utc).isoformat(timespec="seconds")
    with store.connection() as conn:
        conn.execute(
            "INSERT INTO overrides (finding_id, analyst, label, severity, verdict, note, created) VALUES (?,?,?,?,?,?,?)"
            " ON CONFLICT(finding_id, analyst) DO UPDATE SET label = COALESCE(excluded.label, overrides.label),"
            " severity = COALESCE(excluded.severity, overrides.severity), verdict = COALESCE(excluded.verdict, overrides.verdict),"
            " note = CASE WHEN excluded.note != '' THEN excluded.note ELSE overrides.note END, created = excluded.created",
            (finding_id, analyst, label, severity, verdict, note or "", stamp),
        )


# --------------------------------------------------------------------------------------
# resume (P334 cond 7)
# --------------------------------------------------------------------------------------


def _entity_from_key(key: str) -> Any:
    from v3lum.core.entities import Entity, EntityType

    etype, sep, value = str(key or "").partition(":")
    if not sep:
        return None
    try:
        return Entity(EntityType(etype), value)
    except ValueError:
        try:
            return Entity.make(EntityType.parse(etype), value)
        except ValueError:
            return None


def run_info_of(case: Mapping[str, Any], key: str) -> dict[str, Any]:
    """The recorded run facts of one entity of a stored case: ``{is_seed, depth, provenance, tlp}``.

    ``is_seed`` only for analyst-typed seeds (seed node, not in ``options.unconfirmed_seeds``);
    ``depth`` and ``tlp`` from the entity node; ``provenance`` rebuilt from the case edges as the
    chain of ``(parent_key, relation, module)`` from the seed, choosing the shallowest parent at
    each step. An entity missing from the graph counts as a pivot at depth 1 (never a seed)."""
    nodes = {str(n.get("key")): n for n in case.get("entities") or () if isinstance(n, Mapping) and n.get("key")}
    options = case.get("options") or {}
    unconfirmed = {str(k) for k in options.get("unconfirmed_seeds") or ()}
    default_tlp = str(case.get("tlp") or options.get("tlp") or "amber")
    node = nodes.get(key)
    if node is None:
        return {"is_seed": False, "depth": 1, "provenance": [], "tlp": default_tlp}
    parents: dict[str, list[tuple[str, str, str]]] = {}
    for edge in case.get("edges") or ():
        if isinstance(edge, Mapping) and edge.get("src") and edge.get("dst"):
            parents.setdefault(str(edge["dst"]), []).append((str(edge["src"]), str(edge.get("relation") or "related"), str(edge.get("module") or "")))
    chain: list[list[str]] = []
    current, seen = key, {key}
    while len(chain) < 64:
        cur_node = nodes.get(current)
        if cur_node is None or cur_node.get("seed"):
            break
        options_up = [
            (int(nodes.get(src, {}).get("depth", 10**6) or 0), src, rel, mod) for src, rel, mod in parents.get(current, []) if src not in seen
        ]
        if not options_up:
            break
        _depth, src, rel, mod = min(options_up)
        chain.append([src, rel, mod])
        seen.add(src)
        current = src
    is_seed = bool(node.get("seed")) and key not in unconfirmed
    return {
        "is_seed": is_seed,
        "depth": int(node.get("depth", 0) or 0),
        "provenance": [] if is_seed else list(reversed(chain)),
        "tlp": str(node.get("tlp") or default_tlp),
    }


def resume_plan(case: Mapping[str, Any], deferred: Iterable[Mapping[str, Any]] = ()) -> tuple[dict[tuple[str, str], dict[str, Any]], list[str]]:
    """``(only_pairs, notes)`` for ``cases resume``: the deferred pairs (``QuotaBook.deferred`` rows
    and ``case['deferred']``) and the could-not-verify pairs of ``case['execution']`` (statuses in
    :data:`CNV_STATUSES`, deadline skips, runs cut by :data:`RESUMABLE_STOPS`), each with its
    :func:`run_info_of`. Pairs whose entity cannot be restored (a pseudonymised deferral that does
    not map back, a redacted secret) are left out with a note."""
    from v3lum.core import hmacid
    from v3lum.core.entities import SECRET_TYPES

    wanted: dict[tuple[str, str], str] = {}
    for row in deferred:
        module, key = str(row.get("module") or ""), str(row.get("entity_key") or row.get("entity") or "")
        if module and key:
            wanted.setdefault((module, key), "deferred")
    for row in case.get("deferred") or ():
        if isinstance(row, Mapping) and row.get("module") and row.get("entity"):
            wanted.setdefault((str(row["module"]), str(row["entity"])), "deferred")
    for row in case.get("execution") or ():
        if not isinstance(row, Mapping) or not row.get("module") or not row.get("entity"):
            continue
        status, code = str(row.get("status") or ""), str(row.get("reason_code") or "")
        partial_stop = bool(row.get("partial")) and str(row.get("stop_reason") or "") in RESUMABLE_STOPS
        if status in CNV_STATUSES or (status == "skipped" and code == "deadline") or partial_stop:
            wanted.setdefault((str(row["module"]), str(row["entity"])), status or "partial")
    pairs: dict[tuple[str, str], dict[str, Any]] = {}
    skipped_pseudo = skipped_secret = 0
    for (module, key), _why in sorted(wanted.items()):
        if hmacid.is_pseudonym(key):  # a deferral whose keyed pseudonym did not map back
            skipped_pseudo += 1
            continue
        entity = _entity_from_key(key)
        if entity is None:
            skipped_pseudo += 1
            continue
        if entity.type in SECRET_TYPES:
            skipped_secret += 1
            continue
        pairs[(module, entity.key)] = run_info_of(case, key)
    notes = []
    if skipped_pseudo:
        notes.append(f"{skipped_pseudo} deferred lookup(s) could not be mapped back to an entity of the stored case (left out)")
    if skipped_secret:
        notes.append(f"{skipped_secret} lookup(s) of secret values are stored redacted and cannot be resumed (re-scan the input)")
    return pairs, notes


def _stored_options(case: Mapping[str, Any], app: Any, args: Any) -> Any:
    """ScanOptions of the resumed run from the stored case options (TLP, purpose, mode, scope
    reference...), with the A7 checks of this execution path."""
    from v3lum.core.context import ScanOptions
    from v3lum.core.models import Opsec

    stored = dict(case.get("options") or {})
    try:
        stored_mode = Opsec.parse(str(stored.get("mode") or "passive"))
    except (KeyError, ValueError):
        stored_mode = Opsec.PASSIVE
    mode = stored_mode
    if getattr(args, "mode", None):
        requested = Opsec.parse(args.mode)
        if requested > stored_mode:
            raise _user_error(f"cases resume never escalates the mode: the case ran {stored_mode.label}, --mode {requested.label} refused (start a new scan)")
        mode = requested
    options = ScanOptions(
        mode=mode,
        depth=int(stored.get("depth", 1) or 0),
        max_entities=int(stored.get("max_entities", 150) or 150),
        threads=int(stored.get("threads", 12) or 12),
        include_disabled=bool(stored.get("include_disabled", False)),
        offline=bool(getattr(app, "offline", False)),
        no_cache=bool(getattr(app, "no_cache", False)),
        timeout_total=float(getattr(args, "timeout", 0.0) or 0.0),
        save_evidence=not bool(getattr(args, "no_evidence", False)),
        tlp=str(stored.get("tlp") or case.get("tlp") or "amber"),
        preset=str(stored.get("preset") or "quick"),
        purpose=str(stored.get("purpose") or ""),
        ticket=str(stored.get("ticket") or ""),
        legal_basis=str(stored.get("legal_basis") or ""),
        breach_scope=str(stored.get("breach_scope") or "own"),
        expand_personal=bool(stored.get("expand_personal", False)),
        allow_unknown=bool(stored.get("allow_unknown", False)),
        egress_override=str(stored.get("egress_override") or ""),
        licence_profile=str(stored.get("licence_profile") or case.get("licence_profile") or ""),
        show_personal=bool(stored.get("show_personal", False)),
        no_defang=bool(stored.get("no_defang", False)),
        seed_tlp={str(k): str(v) for k, v in (stored.get("seed_tlp") or {}).items()},
        unconfirmed_seeds={str(k) for k in stored.get("unconfirmed_seeds") or ()},
        subject_roles={str(k): str(v) for k, v in (stored.get("subject_roles") or {}).items()},
        authorization_note=str(stored.get("authorization_note") or ""),
    )
    if mode is Opsec.ACTIVE:
        _bind_active_scope(options, stored, args, app)
    return options


def _org_terms(app: Any) -> list[str]:
    """Organisation name and brand keywords: an ROE identity of the scope must never name them (A7)."""
    try:
        from v3lum.core import orgprofile

        prof = orgprofile.load_default(app.config)
        return [t for t in [prof.name, *prof.brand_terms()] if t]
    except Exception:  # noqa: BLE001 - no profile: nothing to compare
        return []


def _bind_active_scope(options: Any, stored: Mapping[str, Any], args: Any, app: Any = None) -> None:
    """A7 on the resume path: ACTIVE needs --authorized REF and --scope FILE again; both must be the
    case's own (same reference, same scope SHA-256) and the scope must be usable now."""
    from v3lum.core.scope import Scope, ScopeError

    missing = [flag for flag, value in (("--authorized REF", getattr(args, "authorized", None)), ("--scope FILE", getattr(args, "scope", None))) if not value]
    if missing:
        raise _user_error(f"resuming an ACTIVE case needs {' and '.join(missing)} (A7: every execution path)")
    ref = str(args.authorized).strip()
    if ref != str(stored.get("authorization_ref") or ""):
        raise _user_error("--authorized differs from the case's authorization reference: start a new scan for a new engagement")
    try:
        scope = Scope.load(args.scope)
    except ScopeError as exc:
        raise _user_error(f"scope file refused: {'; '.join(exc.problems)}") from exc
    if stored.get("scope") and scope.sha256 != stored.get("scope"):
        raise _user_error("the scope file differs from the one recorded in the case (SHA-256): start a new scan")
    problems = scope.validate(ref, _dt.datetime.now(_dt.timezone.utc), org_terms=_org_terms(app))
    if problems:
        raise _user_error("scope not usable now: " + "; ".join(problems))
    options.authorization_ref = ref
    options.authorization_note = ref
    options.scope = scope
    options.scope_path = str(args.scope)
    options.authorized = True


def _prepare_runtime(app: Any, rt: Any, options: Any) -> None:
    prepare = getattr(app, "prepare_runtime", None)
    if callable(prepare):
        prepare(rt, options, path="scan")
        return
    lookup = getattr(app.store, "sightings_for", None)  # interim wiring (WP13 not installed yet)
    if callable(lookup):
        rt.meta["sightings_lookup"] = lookup
    try:
        from v3lum.core.audit import AuditHook

        rt.case_hooks.append(AuditHook(app.store, analyst=_analyst(app)))
    except Exception as exc:  # noqa: BLE001
        from v3lum.core.models import Opsec

        if options.mode >= Opsec.LIGHT:
            raise _user_error("LIGHT/ACTIVE runs need the case audit trail and the request ledger (A7), which are unavailable: refused") from exc


def _resume(app: Any, console: Any, args: Any) -> int:
    from v3lum.core.engine import Engine
    from v3lum.report import write_reports

    stored = _stored(app, args.case_id)
    case_id = str(stored["case_id"])
    if args.json:
        app.verbosity = 0
    feed: Any = None
    try:
        from v3lum.ui.live import LiveFeed

        feed = LiveFeed(console, verbosity=0 if args.json else getattr(app, "verbosity", 1))
    except Exception:  # noqa: BLE001 - no live feed: a plain runtime
        feed = None
    rt = app.runtime(listener=feed) if feed is not None else app.runtime()
    deferred: list[dict[str, Any]] = []
    try:
        deferred = list(rt.quota.deferred(case_id, case=stored))
    except Exception as exc:  # noqa: BLE001 - the case dict still lists its deferrals
        log.warning("quota DB unavailable for resume: %s", type(exc).__name__)
    pairs, notes = resume_plan(stored, deferred)
    for note in notes:
        console.print(Text(f"[i] {note}", style="v.dim"))
    if not pairs:
        console.print(Text(f"nothing to resume: case {case_id} has no deferred or could-not-verify lookups", style="v.dim"))
        return 0
    options = _stored_options(stored, app, args)
    seeds = [e for e in (_entity_from_key(k) for k in stored.get("seeds") or ()) if e is not None]
    if not seeds:
        raise _user_error(f"case {case_id} has no restorable seed")
    options.only_pairs = pairs
    rt.meta["resumed_from"] = case_id
    _prepare_runtime(app, rt, options)
    engine = Engine(rt, options, reliability=app.store.reliability())
    if feed is not None:
        with feed:
            case = engine.investigate(seeds, only_pairs=pairs)
    else:
        case = engine.investigate(seeds, only_pairs=pairs)
    data = case.to_dict()
    data.setdefault("meta", {})["resumed_from"] = case_id
    formats = _split(args.format) if args.format is not None else list(app.config.get("report_formats") or [])
    if formats:
        out_dir = args.out or str(app.config.get("report_dir") or "") or case.case_dir
        data["reports"] = write_reports(data, formats, out_dir)
        record_reports(app.store, case.case_id, data["reports"])
    app.store.save_case(data)
    try:
        app.store.record_cache_keys(case.case_id, getattr(case, "cache_keys", None) or ())
    except Exception as exc:  # noqa: BLE001
        log.warning("cache keys not recorded: %s", type(exc).__name__)
    if args.json:
        sys.stdout.write(json.dumps(data, ensure_ascii=False, indent=2, default=str) + "\n")
    else:
        app.show_case(data)
        console.print(Text(f"\n[✓] resumed {len(pairs)} lookup(s) of case {case_id}: new case {case.case_id}", style="v.ok"))
    return 0


# --------------------------------------------------------------------------------------
# list / purge output
# --------------------------------------------------------------------------------------


def _cases_table(app: Any, limit: int, search: str) -> Table:
    t = Table(box=box.SIMPLE_HEAVY, header_style="v.dim", expand=True, title="[v.accent]☰ cases[/]", title_justify="left")
    t.add_column("case", style="v.title", no_wrap=True)
    t.add_column("created", style="v.dim", no_wrap=True)
    t.add_column("tlp", no_wrap=True)
    t.add_column("hold", no_wrap=True)
    t.add_column("inputs", style="v.entity", overflow="fold", ratio=3)
    t.add_column("risk", no_wrap=True)
    t.add_column("findings", justify="right")
    t.add_column("entities", justify="right")
    rows = app.store.list_cases(limit, search)
    for c in rows:
        lvl = str(c.get("risk_level") or "clean")
        hold = Text("held", style="v.warn") if c.get("legal_hold") else Text("")
        name = Text(_clean(c["id"]))
        if c.get("engagement"):
            name.append(" (engagement)", style="v.warn")
        t.add_row(
            name, str(c.get("created") or "")[:19], str(c.get("tlp") or ""), hold, Text(_clean(", ".join(c.get("seeds") or []))[:160]),
            Text(f"{lvl} {float(c.get('risk_score') or 0):.0f}", style=f"risk.{lvl}"), str(c.get("findings") or 0), str(c.get("entities") or 0),
        )
    held = sum(1 for c in rows if c.get("legal_hold"))
    t.caption = f"{len(rows)} shown" + (f" · {held} under legal hold (exempt from purge)" if held else "") + " · v3lum cases show <id>"
    return t


def _purge_line(console: Any, report: Any) -> None:
    style = "v.warn" if report.held or report.errors else ("v.dim" if report.dry_run or not report.purged else "status.ok")
    console.print(Text(_clean(report.line()), style=style), soft_wrap=True)


# --------------------------------------------------------------------------------------
# the command
# --------------------------------------------------------------------------------------


@command("cases", "stored investigations: list, show, report, purge, legal hold, verify, resume, overrides")
class Cases:
    """The case lifecycle (see the module docstring)."""

    @staticmethod
    def add_arguments(parser: Any) -> None:
        sub = parser.add_subparsers(dest="cases_cmd", metavar="<action>")
        cl = sub.add_parser("list", help="list cases (held cases are marked)")
        cl.add_argument("-n", "--limit", type=int, default=30)
        cl.add_argument("-s", "--search", default="")
        cl.add_argument("--json", action="store_true")
        cs = sub.add_parser("show", help="print a case report ('last' = latest)")
        cs.add_argument("case_id")
        cs.add_argument("--full", action="store_true")
        cs.add_argument("--json", action="store_true", help="print the stored case (overrides applied) as JSON")
        cr = sub.add_parser("report", help="write report files for a case")
        cr.add_argument("case_id")
        cr.add_argument("-f", "--format", default="html,md,json,stix")
        cr.add_argument("-o", "--out", help="output directory")
        cd = sub.add_parser("delete", help="purge one case: every copy goes, a value-free tombstone stays")
        cd.add_argument("case_id")
        cd.add_argument("--dry-run", action="store_true", help="only list what would be removed")
        cf = sub.add_parser("feedback", help="give feedback on a case (verdict and explicit votes)")
        cf.add_argument("case_id")
        cp = sub.add_parser("purge", help="purge cases past retention (held cases are skipped and listed)")
        cp.add_argument("--older-than", type=float, metavar="DAYS", help="age in days (default: setting retention_days)")
        cp.add_argument("--dry-run", action="store_true", help="only list what would be removed")
        ch = sub.add_parser("hold", help="put a case under legal hold (exempt from every purge)")
        ch.add_argument("case_id")
        ch.add_argument("--reason", required=True, help="why the case is held (e.g. litigation, regulator request)")
        ch.add_argument("--requester", required=True, help="who requested the hold")
        cu = sub.add_parser("unhold", help="release a legal hold")
        cu.add_argument("case_id")
        cv = sub.add_parser("verify", help="recompute evidence/report hashes and the audit/ledger chains (offline)")
        cv.add_argument("case_id")
        rs = sub.add_parser("resume", help="re-run only the deferred and could-not-verify lookups of a case")
        rs.add_argument("case_id")
        rs.add_argument("-m", "--mode", choices=["passive", "light", "active"], help="lower the stored mode (never raise it)")
        rs.add_argument("--authorized", metavar="REF", help="ACTIVE cases: the case's authorization reference")
        rs.add_argument("--scope", metavar="FILE", help="ACTIVE cases: the case's scope file")
        rs.add_argument("--timeout", type=float, default=0.0, help="global time limit in seconds")
        rs.add_argument("--no-evidence", action="store_true", help="do not save raw evidence files")
        rs.add_argument("-f", "--format", help="report formats (default from config; '' = none)")
        rs.add_argument("-o", "--out", help="report directory (default: the case folder)")
        rs.add_argument("--json", action="store_true", help="print the new case as JSON")
        ov = sub.add_parser("override", help="record an analyst decision on a finding (wins over automatic labels)")
        ov.add_argument("case_id")
        ov.add_argument("finding_id", help="finding or correlation id (a unique prefix works)")
        ov.add_argument("--label", choices=LABELS, help="confidence label")
        ov.add_argument("--severity", choices=SEVERITIES)
        ov.add_argument("--verdict", choices=VERDICTS, help="right or wrong (wrong takes the finding out of the evidence)")
        ov.add_argument("--note", default="", help="free-text note (case data, purged with the case)")
        cc = sub.add_parser("confirm", help="mark a finding confirmed (= override --label confirmed)")
        cc.add_argument("case_id")
        cc.add_argument("finding_id")

    @staticmethod
    def run(args: Any, app: Any, console: Any) -> int:  # noqa: C901 - sub-command router
        action = getattr(args, "cases_cmd", None) or "list"
        store = app.store
        analyst = _analyst(app)
        if action == "list":
            limit, search = int(getattr(args, "limit", 30) or 30), str(getattr(args, "search", "") or "")
            if getattr(args, "json", False):
                sys.stdout.write(json.dumps(store.list_cases(limit, search), ensure_ascii=False, indent=2, default=str) + "\n")
            else:
                console.print(_cases_table(app, limit, search))
            return 0
        if action == "show":
            data = _with_overrides(app, _stored(app, args.case_id))
            if args.json:
                sys.stdout.write(json.dumps(data, ensure_ascii=False, indent=2, default=str) + "\n")
            else:
                app.show_case(data, full=args.full)
                info = store.case_info(str(data["case_id"])) or {}
                if info.get("legal_hold"):
                    console.print(Text(f"[!] under legal hold since {info.get('held_at')}: {_clean(info.get('hold_reason'))} (requested by {_clean(info.get('hold_requester'))})", style="v.warn"))
            return 0
        if action == "report":
            from v3lum.report import write_reports

            data = _with_overrides(app, _stored(app, args.case_id))
            out = args.out or data.get("case_dir") or "."
            written = write_reports(data, _split(args.format), out)
            record_reports(store, str(data["case_id"]), written, analyst=analyst, audit=True)
            for fmt, path in written.items():
                console.print(Text.assemble((f"{fmt:5} ", "v.dim"), (_clean(path), "v.url")))
            return 0
        if action == "delete":
            target = _exact_id(app, args.case_id)
            if target in RESERVED_TRAILS:
                raise _user_error(f"{target!r} is the audit trail of the org profile, not a case: it is never purged (v3lum cases verify {target})")
            report = store.purge_case(target, by=analyst, dry_run=bool(args.dry_run))
            _purge_line(console, report)
            if report.held:
                raise _user_error(f"case {report.case_id} is under legal hold: `v3lum cases unhold {report.case_id}` first")
            if not report.found and not report.total:
                return 1
            return 1 if report.errors else 0
        if action == "purge":
            days = args.older_than
            if days is None and store.retention_days() <= 0:
                console.print(Text("retention_days is 0 (no automatic retention): pass --older-than DAYS", style="v.dim"))
                return 0
            if days is not None and not (math.isfinite(days) and 0 <= days <= MAX_PURGE_DAYS):
                raise _user_error(f"--older-than must be a number of days between 0 and {MAX_PURGE_DAYS}")
            reports = store.purge_older_than(days, by=analyst, dry_run=bool(args.dry_run))
            for report in reports:
                _purge_line(console, report)
            purged = [r for r in reports if (r.purged or (r.dry_run and r.total)) and not r.held]
            held = [r for r in reports if r.held]
            age = days if days is not None else store.retention_days()
            verb = "would be purged" if args.dry_run else "purged"
            summary = f"{len(purged)} case(s) {verb} (older than {age:g} days)"
            if held:
                summary += f"; {len(held)} under legal hold kept: {', '.join(r.case_id for r in held)}"
            console.print(Text(summary if reports else f"nothing to purge (no case older than {age:g} days)", style="v.ok" if reports else "v.dim"))
            return 1 if any(r.errors for r in reports) else 0
        if action == "hold":
            case_id = _exact_id(app, args.case_id)
            try:
                ok = store.hold(case_id, args.reason, args.requester)
            except ValueError as exc:
                raise _user_error(str(exc)) from exc
            if not ok:
                raise _user_error(f"case {_clean(args.case_id)!r} not found (see `v3lum cases list`)")
            console.print(Text(f"[✓] {case_id} under legal hold: exempt from purge (audited)", style="v.ok"))
            return 0
        if action == "unhold":
            case_id = _exact_id(app, args.case_id)
            if not store.unhold(case_id, by=analyst):
                raise _user_error(f"case {_clean(args.case_id)!r} not found or not under legal hold")
            console.print(Text(f"[✓] legal hold of {case_id} released (audited)", style="v.ok"))
            return 0
        if action == "verify":
            try:
                from v3lum.core.audit import verify_case
            except Exception as exc:  # noqa: BLE001
                raise _user_error(f"cases verify needs the evidence/audit engine (v3lum.core.audit): {type(exc).__name__}") from exc
            case_id = _exact_id(app, args.case_id)
            report = verify_case(store, case_id)
            problems = list(getattr(report, "problems", None) or [])
            ok = bool(getattr(report, "ok", False)) and not problems
            lines_fn = getattr(report, "lines", None)
            if callable(lines_fn):
                lines = [str(line) for line in lines_fn()]
            else:
                head = f"PASS {case_id}: evidence and report hashes match, audit and ledger chains intact" if ok else f"FAIL {case_id}: {len(problems)} problem(s)"
                lines = [head] + [f"  problem: {p}" for p in problems]
            for n, line in enumerate(lines):
                style = ("status.ok" if ok else "status.error") if n == 0 or "problem:" in line else "v.warn"
                console.print(Text(_clean(line), style=style), soft_wrap=True)
            return 0 if ok else 1
        if action == "feedback":
            data = _stored(app, args.case_id)
            try:
                from v3lum.ui.feedback import ask_feedback
            except Exception:  # noqa: BLE001 - WP16 not installed: the App's v1 loop
                app.ask_feedback(data)
                return 0
            result = ask_feedback(console, store, data, analyst=analyst)
            if result is None and not _stdin_tty():
                console.print(Text("feedback needs an interactive terminal: nothing recorded", style="v.dim"))
            return 0
        if action == "resume":
            return _resume(app, console, args)
        if action in ("override", "confirm"):
            data = _stored(app, args.case_id)
            finding_id = _resolve_finding(data, args.finding_id)
            label = "confirmed" if action == "confirm" else args.label
            severity = None if action == "confirm" else args.severity
            verdict = None if action == "confirm" else args.verdict
            note = "" if action == "confirm" else str(args.note or "")
            if not any((label, severity, verdict, note)):
                raise _user_error("nothing to record: give --label, --severity, --verdict or --note")
            _set_override(store, finding_id, analyst=analyst, label=label, severity=severity, verdict=verdict, note=note, case_id=str(data["case_id"]))
            payload = {"finding_id": finding_id, "analyst": analyst, "label": label, "severity": severity, "verdict": verdict, "note": note, "action": action}
            case_dir = str(data.get("case_dir") or "")
            if not case_dir:
                try:
                    case_dir = str(paths.case_dir(str(data["case_id"])))
                except ValueError:
                    case_dir = ""
            audit_append(store, str(data["case_id"]), case_dir, OVERRIDE_AUDIT_KIND, {k: v for k, v in payload.items() if v not in (None, "")})
            shown = ", ".join(f"{k} {v}" for k, v in (("label", label), ("severity", severity), ("verdict", verdict)) if v)
            console.print(Text(f"[✓] override recorded for {finding_id[:16]} ({shown or 'note'}): applied on the next render or re-run (audited)", style="v.ok"))
            return 0
        raise _user_error(f"unknown cases action {action!r}")
