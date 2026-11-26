"""Attention points and limitations of a case (P325 cond 5): pure functions over the stored case dict.

Both lists are generated from the coverage statuses and canonical reason codes the engine records
(``case['coverage'][module]['entities']`` per (module, entity), ``['sources']`` per aggregator feed,
the module summary for older case dicts), plus ``case['partial']``, ``case['deferred']``,
``case['answered']``, ``case['pending_personal']`` and the ``sightings`` attribute of the entities.
They are shown on the first screen (terminal) and in the reports:

* :func:`limitations` - what could **not** be verified and why, one line per reason
  ('could not verify: Shodan InternetDB, URLhaus (blocked: anti-bot challenge)'), the partial-run
  notes and the reminder that a source that did not answer is no evidence of absence (rule 5);
* :func:`attention_points` - suggestions for the analyst (keys to add, lookups to resume, sources to
  check manually, earlier cases to review...).

They are worded as suggestions, never as conclusions: the analyst's verdict prevails (pass
``verdict=`` to put it first). Same case -> same lines (sorted names, fixed reason order); module
titles, source ids and the case id are the only names used - never an investigated value.
"""

from __future__ import annotations

from collections.abc import Mapping
from typing import Any

__all__ = [
    "BLOCKED_CODES",
    "LIMITATION_REASONS",
    "MAX_NAMES",
    "PARTIAL_REASONS",
    "SUGGESTION_NOTE",
    "attention_points",
    "could_not_verify",
    "limitations",
    "partially_verified",
]

#: Heading renderers show above the attention points.
SUGGESTION_NOTE = "suggestions only: the analyst's verdict prevails"
#: Reason codes that make a source 'could not verify' in the limitations, in display order, with the
#: words shown in brackets (the eight of P325 cond 5 - blocked, quota, needs_key, licence, tlp, policy,
#: timeout, deadline - plus the other could-not-verify codes of rule 5).
LIMITATION_REASONS: dict[str, str] = {
    "challenge": "blocked: anti-bot challenge",
    "geo_block": "blocked: geo restriction",
    "login_wall": "blocked: login wall",
    "circuit": "blocked: host failing earlier in this scan",
    "hostile_host": "blocked: contact refused for a hostile host",
    "quota": "quota used up",
    "rate_limited": "rate limited",
    "needs_key": "API key needed",
    "licence": "licence profile",
    "tlp": "TLP",
    "policy": "policy",
    "timeout": "timeout",
    "deadline": "scan deadline",
    "error": "error",
    "sanitizer": "unsafe data dropped",
    "offline": "offline",
    "dataset": "dataset missing",
    "package": "optional package missing",
}
#: Stop reasons of partial runs (status ok/empty with ``partial``: the source answered, but not
#: completely), in display order, with the words shown in brackets.
PARTIAL_REASONS: dict[str, str] = {
    "quota": "quota used up",
    "rate_limited": "rate limited",
    "request_cap": "request cap reached",
    "deadline": "scan deadline",
    "cancelled": "cancelled",
}
#: The BLOCKED reason codes (anti-bot, geo, login wall, short-circuit, hostile host).
BLOCKED_CODES: tuple[str, ...] = ("challenge", "geo_block", "login_wall", "circuit", "hostile_host")
#: Names listed per line before '+N more'.
MAX_NAMES = 6

_DEFAULT_CODE = {
    "skipped": "not_applicable",
    "needs_key": "needs_key",
    "unavailable": "offline",
    "quota": "quota",
    "rate_limited": "rate_limited",
    "blocked": "challenge",
    "error": "error",
}
_PARTIAL_NOTES = {
    "deadline": "the scan deadline ended the run: results are partial (sources still pending are listed as 'scan deadline')",
    "cancelled": "the scan was cancelled: results are partial",
    "window": "the authorization window ended during the run: results are partial",
}


# --------------------------------------------------------------------------------------
# reading the case
# --------------------------------------------------------------------------------------


def _code(row: Mapping[str, Any]) -> str:
    status = str(row.get("status") or "")
    if status in ("ok", "empty", "not_run", ""):
        return ""
    return str(row.get("reason_code") or "") or _DEFAULT_CODE.get(status, "")


def _coverage(case: Mapping[str, Any]) -> list[tuple[str, Mapping[str, Any]]]:
    coverage = case.get("coverage") if isinstance(case.get("coverage"), Mapping) else {}
    return [(str(name), cov) for name, cov in sorted(coverage.items(), key=lambda kv: str(kv[0])) if isinstance(cov, Mapping)]


def _entity_rows(cov: Mapping[str, Any]) -> list[Mapping[str, Any]]:
    entities = cov.get("entities") if isinstance(cov.get("entities"), Mapping) else {}
    return [r for r in entities.values() if isinstance(r, Mapping)] or [cov]


def could_not_verify(case: Mapping[str, Any]) -> dict[str, list[str]]:
    """``{reason_code: sorted names}`` of the sources that could not answer, for the codes of
    :data:`LIMITATION_REASONS`: module titles from the per-entity coverage rows (the module summary
    when a case has none) and ``'<module title>: <source id>'`` for aggregator feeds (a feed is not
    listed again under a reason its module is already listed with)."""
    groups: dict[str, set[str]] = {}
    for name, cov in _coverage(case):
        title = str(cov.get("title") or name)
        module_codes: set[str] = set()
        for row in _entity_rows(cov):
            code = _code(row)
            if code in LIMITATION_REASONS:
                groups.setdefault(code, set()).add(title)
                module_codes.add(code)
        sources = cov.get("sources") if isinstance(cov.get("sources"), Mapping) else {}
        for sid, row in sorted(sources.items(), key=lambda kv: str(kv[0])):
            if not isinstance(row, Mapping):
                continue
            code = _code(row)
            if code in LIMITATION_REASONS and code not in module_codes:
                groups.setdefault(code, set()).add(f"{title}: {sid}")
    return {code: sorted(groups[code]) for code in LIMITATION_REASONS if code in groups}


def partially_verified(case: Mapping[str, Any]) -> dict[str, list[str]]:
    """``{stop_reason: sorted module titles}`` of the runs that answered only in part (status ok or
    empty with ``partial`` and a :data:`PARTIAL_REASONS` stop reason): what they did not get to is
    unknown, never absent (rule 5)."""
    groups: dict[str, set[str]] = {}
    for name, cov in _coverage(case):
        title = str(cov.get("title") or name)
        for row in _entity_rows(cov):
            if str(row.get("status") or "") not in ("ok", "empty") or not row.get("partial"):
                continue
            reason = str(row.get("stop_reason") or "")
            if reason in PARTIAL_REASONS:
                groups.setdefault(reason, set()).add(title)
    return {reason: sorted(groups[reason]) for reason in PARTIAL_REASONS if reason in groups}


def _names(names: list[str]) -> str:
    shown = ", ".join(names[:MAX_NAMES])
    more = len(names) - MAX_NAMES
    return f"{shown} +{more} more" if more > 0 else shown


def _count(n: int, word: str) -> str:
    return f"{n} {word}{'' if n == 1 else 's'}"


# --------------------------------------------------------------------------------------
# public functions
# --------------------------------------------------------------------------------------


def limitations(case: Mapping[str, Any]) -> list[str]:
    """The limitations section of a case: one 'could not verify: X, Y (reason)' line per reason code
    (:data:`LIMITATION_REASONS` order, names sorted, at most :data:`MAX_NAMES` then '+N more'), one
    'partially verified: X (reason)' line per stop reason of partial runs (:func:`partially_verified`),
    the partial-run notes (``case['partial']``: deadline, cancelled, authorization window) and, when any
    source could not answer, the reminder that this is no evidence of absence. [] when every source
    answered."""
    lines: list[str] = []
    groups = could_not_verify(case)
    for code, names in groups.items():
        lines.append(f"could not verify: {_names(names)} ({LIMITATION_REASONS[code]})")
    partly = partially_verified(case)
    for reason, names in partly.items():
        lines.append(f"partially verified: {_names(names)} ({PARTIAL_REASONS[reason]})")
    partial = case.get("partial") if isinstance(case.get("partial"), Mapping) else {}
    for reason, text in _PARTIAL_NOTES.items():
        if partial.get(reason):
            lines.append(text)
    if groups or partly:
        lines.append("a source that could not answer is no evidence of absence: what it would have shown is unknown")
    return lines


def attention_points(case: Mapping[str, Any], *, verdict: str | None = None) -> list[str]:
    """Suggestions for the analyst, derived from the same coverage data (P325 cond 5): API keys to
    configure, quota-deferred lookups to resume (``v3lum cases resume <id>``), blocked sources to
    check through their manual pivot links, licence/TLP/policy skips to review, sources to re-run
    after a timeout or the scan deadline, seeds left inconclusive (fewer than 2 reputation sources
    answered), entities seen in earlier cases and personal identifiers awaiting selection. Every
    line is a suggestion; with ``verdict`` (the analyst's recorded verdict) the first line says it
    prevails."""
    lines: list[str] = []
    if verdict:
        lines.append(f"analyst verdict: {verdict} - it prevails over the suggestions below")
    groups = could_not_verify(case)
    partly = partially_verified(case)
    case_id = str(case.get("case_id") or "<case id>")
    tlp_value = str(case.get("tlp") or "").strip().upper()
    at_tlp = f"TLP:{tlp_value}" if tlp_value else "the case TLP"
    if "needs_key" in groups:
        lines.append(f"consider configuring API keys for {_names(groups['needs_key'])} (v3lum keys setup)")
    deferred = [d for d in case.get("deferred") or () if isinstance(d, Mapping)]
    quota_names = sorted(set(groups.get("quota", [])) | set(partly.get("quota", [])))
    if quota_names or deferred:
        names = _names(quota_names or sorted({str(d.get("module") or "") for d in deferred if d.get("module")}))
        what = _count(len(deferred), "deferred lookup") if deferred else "the lookups"
        lines.append(f"consider resuming {what} once the provider quota resets ({names}): v3lum cases resume {case_id}")
    limited = sorted(set(groups.get("rate_limited", [])) | set(partly.get("rate_limited", [])))
    if limited:
        lines.append(f"consider re-running later: {_names(limited)} rate-limited the requests")
    manual = sorted({n for code in ("challenge", "geo_block", "login_wall") for n in groups.get(code, [])})
    if manual:
        lines.append(f"consider checking {_names(manual)} by hand (manual pivot links): automated access was blocked")
    if "circuit" in groups:
        lines.append(f"consider re-running later: {_names(groups['circuit'])} failed earlier in this scan")
    if "hostile_host" in groups:
        lines.append(
            f"consider passive alternatives for {_names(groups['hostile_host'])}: contact with a hostile host needs a "
            "non-corporate egress (proxy_light/proxy_active) or a recorded --egress-override"
        )
    if "licence" in groups:
        lines.append(f"consider reviewing the licence profile ({_names(groups['licence'])}): v3lum doctor --licences")
    if "tlp" in groups:
        lines.append(f"{_names(groups['tlp'])} may not receive values at {at_tlp}: lower the TLP only if the case allows it (the change is audited)")
    if "policy" in groups:
        lines.append(f"see `v3lum info <module>` for why {_names(groups['policy'])} were skipped by policy")
    slow = sorted(
        {n for code in ("timeout", "deadline") for n in groups.get(code, [])}
        | {n for reason in ("deadline", "request_cap", "cancelled") for n in partly.get(reason, [])}
    )
    if slow:
        lines.append(f"consider a longer --timeout or a re-run: {_names(slow)} did not finish")
    failed = sorted({n for code in ("error", "sanitizer") for n in groups.get(code, [])})
    if failed:
        lines.append(f"consider re-running with --debug: {_names(failed)} failed")
    if "offline" in groups:
        lines.append(f"consider re-running later (or without --offline): {_names(groups['offline'])} were unavailable")
    if "dataset" in groups:
        lines.append(f"consider `v3lum data update`: {_names(groups['dataset'])} need a local dataset")
    if "package" in groups:
        lines.append(f"consider installing the optional extras (v3lum doctor): {_names(groups['package'])} need them")
    answered = case.get("answered") if isinstance(case.get("answered"), Mapping) else {}
    inconclusive = 0
    for row in answered.values():
        if not isinstance(row, Mapping):
            continue
        try:
            applicable, got = int(row.get("reputation_applicable") or 0), int(row.get("reputation_answered") or 0)
        except (TypeError, ValueError):
            continue
        if applicable and got < 2:
            inconclusive += 1
    if inconclusive:
        lines.append(f"consider more reputation sources: {_count(inconclusive, 'seed')} had fewer than 2 answering (inconclusive)")
    seen = _seen_before(case)
    if seen:
        lines.append(f"consider reviewing earlier cases: {_count(seen, 'entity')} appeared in previous cases (case-DB sightings)")
    pending = [p for p in case.get("pending_personal") or () if p]
    if pending:
        lines.append(f"{_count(len(pending), 'personal identifier')} await your selection: they are never investigated automatically")
    return lines


def _seen_before(case: Mapping[str, Any]) -> int:
    """Entities whose case-DB sightings attribute shows at least one earlier case."""
    seen = 0
    for node in case.get("entities") or ():
        if not isinstance(node, Mapping):
            continue
        attrs = node.get("attributes") if isinstance(node.get("attributes"), Mapping) else {}
        entries = attrs.get("sightings") or ()
        for entry in entries if isinstance(entries, list) else [entries]:
            value = entry.get("value") if isinstance(entry, Mapping) and "value" in entry else entry
            if isinstance(value, Mapping):
                try:
                    total = int(value.get("count") or 0) + int(value.get("restricted") or 0)
                except (TypeError, ValueError):
                    total = 0
                if total > 0:
                    seen += 1
                    break
    return seen
