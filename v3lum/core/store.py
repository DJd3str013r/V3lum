"""Case storage (SQLite), retention and purge, legal hold, analyst feedback and module reliability.

The case DB (``~/.v3lum/v3lum.db``, 0600) is versioned by :mod:`v3lum.core.migrations` (kind
``'cases'``); :class:`Store` migrates it when it opens it, so databases written by older versions
upgrade in place.

* ``cases``: one row per investigation with the full case JSON (the only place, with the 0600 report
  files, where plain investigated values live) plus derived columns: case TLP, legal hold, purpose,
  ticket, legal basis, licence profile, recorded report paths and the LIGHT/ACTIVE engagement flag.
  The ``seeds`` column is a **search index**: PERSONAL_TYPES seeds (and free-text/file inputs) are
  stored as the keyed pseudonym ``'<type>:#<hmac12>'`` (A4), so ``list_cases(search=...)`` matches a
  personal value only when the exact value is typed (the query is hashed); substrings of personal
  values never match (no people search over past cases).
* Case DB v2 (WP16; P325, P322, P375):

  - **verdicts** (``feedback``): :meth:`Store.record_verdict` - the analyst's overall verdict
    (yes | partial | no) and notes, one per case and analyst (replaced on re-vote);
  - **votes** (``finding_votes``): :meth:`Store.vote` - explicit per-item judgements (right | wrong |
    partly, optional reason) on findings and correlations, idempotent per (case, deterministic item
    id, analyst): a re-vote replaces the earlier one and moves its contribution, never adds a
    second one. Unrated items have no row ('no' + Enter marks nothing correct);
  - **aggregates** (``source_stats`` / ``rule_stats`` / ``module_stats``): updated by every vote in the
    same transaction and kept by the purge (A10: they hold no entity value, analyst or case id).
    ``source_stats``/``rule_stats`` rows are **monthly buckets** keyed ``'<id>@<YYYY-MM>'`` (the
    unweighted sums: 'right' adds 1 to alpha, 'wrong' 1 to beta, 'partly' 0.5 to each), so the age
    rule of P325 still applies after the votes themselves are purged; a key without '@' is a legacy
    aggregate dated by its ``updated`` column. :meth:`Store.source_reliability` turns them into the
    Beta weight with the Admiralty prior (:func:`beta_weight`), :meth:`Store.rule_precision` into
    per-rule precision; votes still on record use their exact age (:func:`vote_weight`), purged
    ones the age of their month (:func:`bucket_weight`). ``module_stats`` is the v1 module view
    (correct/wrong counts; 'partly' counts half each) behind :meth:`Store.reliability` and the A3
    demotion totals (``HealthState.record_votes``);
  - **overrides** (``overrides``): :meth:`Store.set_override` / :meth:`Store.overrides_for` - analyst
    decisions keyed by deterministic finding id, applied on re-runs (:class:`OverrideHook`,
    :func:`apply_overrides`);
  - **sightings** (``sightings``): :meth:`Store.index_case` (run by :meth:`Store.save_case`) and
    :meth:`Store.sightings_for` -> :class:`SightingsSummary`, TLP-safe (A2) and pseudonymised for
    personal identifiers (A4). Exports and shareable reports at CLEAR/GREEN drop the cross-case
    references of a case dict with :func:`omit_cross_case` (AMBER+ exports keep counts only).

  The audit/evidence tables serve the evidence store (WP15) and the watch tables ``v3lum watch``
  (WP26). Siblings use :meth:`Store.connection`.
* One purge routine (A10, AR04) for ``cases delete`` and ``cases purge``: :meth:`Store.purge_case`
  removes the case rows and every table row of the case (every table with a ``case_id`` column,
  tables added by later migrations included), the case directory (evidence, reports, audit mirror),
  every recorded report path (``-o`` included), the HTTP-cache rows fetched during the case and its
  deferred quota lookups, then runs ``PRAGMA secure_delete`` + ``VACUUM`` and keeps a value-free
  tombstone (case id, created, purged_at, purged_by, counts). Cases under legal hold are never
  purged. A LIGHT/ACTIVE case keeps only its **minimal engagement audit** until
  ``audit_retention_days`` after the case was created (0 = ``retention_days``): the audit rows reduced
  to :data:`ENGAGEMENT_AUDIT_FIELDS` (authorization reference, scope SHA-256, window, analyst, mode,
  egress, targets and request counts - purpose, ticket, hold reasons and every other field go with
  the case), re-sealed into a fresh hash chain closed by a ``purge`` row that names the previous
  chain head, plus the request ledger file (``ledger.jsonl``: no bodies, paths redacted); a later
  purge run removes them. :meth:`Store.purge_older_than` also sweeps case directories left without
  a case row (a crashed scan, a v1 ``cases delete``) once they are older than the retention.
  Aggregated per-source/per-rule/per-module counters survive (they hold no values).
"""

from __future__ import annotations

import calendar
import contextlib
import copy
import datetime as _dt
import hashlib
import json
import logging
import math
import os
import re
import sqlite3
import stat
import threading
from collections.abc import Iterable, Iterator, Mapping
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any

from v3lum import paths
from v3lum.core import hmacid
from v3lum.core import tlp as _tlp
from v3lum.core.clock import SYSTEM_CLOCK, Clock
from v3lum.core.migrations import CASES_V1_SCHEMA, migrate

__all__ = [
    "AUDIT_GENESIS",
    "BUCKET_SEP",
    "CROSS_CASE_ATTRIBUTES",
    "CROSS_CASE_MODULES",
    "CROSS_CASE_RULES",
    "ENGAGEMENT_AUDIT_FIELDS",
    "ENGAGEMENT_AUDIT_FILES",
    "ENGAGEMENT_MODES",
    "MIN_VOTES",
    "NOISE_TAGS",
    "OLD_VOTE_MONTHS",
    "OLD_VOTE_WEIGHT",
    "PRIOR_STRENGTH",
    "PURGE_AUDIT_KIND",
    "REJECT_VERDICTS",
    "RELIABILITY_FLOOR",
    "SCHEMA",
    "SIGHTING_VERDICTS",
    "TAG_VERDICTS",
    "UNKNOWN_PRIOR",
    "VERDICTS",
    "VOTE_REASONS",
    "VOTE_SCORES",
    "OverrideHook",
    "PurgeReport",
    "SightingsSummary",
    "Store",
    "admiralty_prior",
    "apply_overrides",
    "audit_hash",
    "beta_weight",
    "bucket_weight",
    "canonical_json",
    "case_columns",
    "cross_case_allowed",
    "entity_verdicts",
    "minimal_audit_payload",
    "omit_cross_case",
    "reliability_from",
    "sighting_rows",
    "vote_weight",
]

log = logging.getLogger("v3lum.store")

#: The v1 schema (kept for compatibility); the live schema is ``migrations.MIGRATIONS['cases']``.
SCHEMA = CASES_V1_SCHEMA
#: Scan modes that make a case a LIGHT/ACTIVE engagement (A7 audit, A10 audit retention).
ENGAGEMENT_MODES = frozenset({"light", "active"})
#: Files of the minimal engagement audit kept in the case directory until audit_retention_days: the
#: request ledger (no bodies, paths redacted; P324 cond 5/7). The full audit mirror (``audit.jsonl``)
#: is case data and goes with the case; the minimal audit stays in the (minimised) audit rows.
ENGAGEMENT_AUDIT_FILES: tuple[str, ...] = ("ledger.jsonl",)
#: Audit payload fields of the minimal LIGHT/ACTIVE engagement audit (A10 BR3 and the A7 audit
#: record): the only audit content kept once the case is purged, until audit_retention_days. Purpose,
#: ticket, legal basis, TLP changes, hold reasons, overrides and every other field follow
#: retention_days. A nested ``engagement`` object is reduced to the same fields.
ENGAGEMENT_AUDIT_FIELDS: frozenset[str] = frozenset({
    "analyst", "os_user", "authorization_ref", "scope_sha256", "window", "window_start", "window_end",
    "mode", "opsec", "egress", "egress_profile", "egress_ip", "targets", "targets_touched", "modules",
    "request_count", "requests", "started", "ended", "engagement",
})
#: Kind of the audit row that closes a minimised engagement audit (who purged, how many rows were
#: minimised, the previous chain head and whether that chain was intact).
PURGE_AUDIT_KIND = "purge"
#: ``prev_hash`` of the first audit row of a case.
AUDIT_GENESIS = "0" * 64

_CASE_ID_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_-]{0,127}$")
#: Case ids the engine generates (``YYYYmmdd-HHMMSS-<hex>``): the only directory names the retention
#: sweep treats as abandoned case directories (other names under cases/ are never swept).
_GENERATED_ID_RE = re.compile(r"^(\d{8})-(\d{6})-[0-9a-f]{2,32}$")
#: Overall analyst verdicts on a case (P325): one per case and analyst, replaced on re-vote.
VERDICTS: tuple[str, ...] = ("yes", "partial", "no")
_VERDICTS = VERDICTS  # v1 name
_VERDICT_ALIASES: dict[str, str] = {"y": "yes", "p": "partial", "partially": "partial", "n": "no"}
#: Per-item votes (P325 cond 2-3) -> the share of 'right' each one counts ('partly' = 0.5).
VOTE_SCORES: dict[str, float] = {"right": 1.0, "partly": 0.5, "wrong": 0.0}
#: Optional reasons of a 'wrong' (or 'partly') vote (P325 cond 4), kept for tuning.
VOTE_REASONS: tuple[str, ...] = ("homonym", "outdated", "benign_infra", "wrong_type")
#: Beta reliability per source (P325 cond 3): prior strength (pseudo-votes of the Admiralty prior),
#: votes needed before a weight moves, floor, and the age rule (older votes weigh half).
PRIOR_STRENGTH = 4.0
MIN_VOTES = 5
RELIABILITY_FLOOR = 0.3
OLD_VOTE_MONTHS = 12
OLD_VOTE_WEIGHT = 0.5
#: Prior mean of a source whose provider is not registered (Admiralty F: reliability cannot be judged).
UNKNOWN_PRIOR = 0.5
#: Separator of the monthly aggregate buckets in source_stats/rule_stats keys ('<id>@<YYYY-MM>').
BUCKET_SEP = "@"
#: Entity verdicts recorded in the sightings index, most severe first ('' = no verdict).
SIGHTING_VERDICTS: tuple[str, ...] = ("malicious", "c2", "phishing", "compromised", "suspicious", "benign")
#: Finding/entity tags -> the sighting verdict they imply (the hostile tags of policy GUARD-01).
TAG_VERDICTS: dict[str, str] = {
    "malicious": "malicious",
    "c2": "c2",
    "phishing": "phishing",
    "phishing_kit_exfil": "phishing",
    "compromised": "compromised",
    "suspicious": "suspicious",
    "crypto_scam": "malicious",
    "fraud": "malicious",
    "hijacked_netblock": "malicious",
}
#: Analyst verdicts (override verdict or latest vote) that reject a finding: it no longer backs an
#: entity verdict (the words of ``v3lum.correlations.generic.FALSE_POSITIVE_VERDICTS``).
REJECT_VERDICTS: frozenset[str] = frozenset({"false_positive", "false positive", "fp", "benign", "wrong", "negative", "not_malicious"})
#: Entity tags that make an entity noise for the sightings index and the recurrence rule (AR06, P375
#: cond 4): sinkholes, parking, benign scanners, allow-listed values.
NOISE_TAGS: frozenset[str] = frozenset({"sinkhole", "parked", "benign_scanner", "noise", "known_good"})
#: The cross-case references a case dict may carry (P375, A2): the entity attribute the case_sightings
#: module records, that module's findings and the recurrence rule's correlations. CLEAR/GREEN exports
#: and shareable reports omit them (:func:`omit_cross_case`); AMBER+ exports keep counts only.
CROSS_CASE_ATTRIBUTES: frozenset[str] = frozenset({"sightings"})
CROSS_CASE_MODULES: frozenset[str] = frozenset({"case_sightings"})
CROSS_CASE_RULES: frozenset[str] = frozenset({"recurrent_infrastructure"})
_SIGHTINGS_INSERT = (
    "INSERT OR REPLACE INTO sightings (entity_key, entity_hmac, entity_type, case_id, case_tlp, engagement, created, verdict)"
    " VALUES (?, ?, ?, ?, ?, ?, ?, ?)"
)
_OVERRIDE_VERDICT_RE = re.compile(r"^[a-z][a-z0-9_+]{0,31}$")
#: Tables whose rows belong to one case (``case_id`` column) and go with it. :func:`_case_tables` adds
#: every other table with a ``case_id`` column (tables of later migrations are purged too).
_CASE_TABLES: tuple[str, ...] = (
    "feedback",
    "finding_feedback",
    "finding_votes",
    "sightings",
    "evidence_versions",
    "report_hashes",
    "alerts",
    "watch_first_seen",
    "case_cache_keys",
    "case_findings",
)
#: Tables with a ``case_id`` column that the purge handles itself (never bulk-deleted).
_SPECIAL_TABLES = frozenset({"tombstones", "audit"})


# ======================================================================================
# helpers
# ======================================================================================


def canonical_json(obj: Any) -> str:
    """Canonical JSON (sorted keys, no spaces, UTF-8 kept): the hashed form of audit rows."""
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False, default=str)


def audit_hash(prev_hash: str, record: Mapping[str, Any]) -> str:
    """Hash of one audit row: ``sha256(prev_hash + canonical_json(record))`` where ``record`` is
    ``{case_id, seq, ts, kind, payload}`` (payload as an object). The first row of a case chains to
    :data:`AUDIT_GENESIS`."""
    body = {k: record.get(k) for k in ("case_id", "seq", "ts", "kind", "payload")}
    return hashlib.sha256((str(prev_hash) + canonical_json(body)).encode("utf-8")).hexdigest()


def _iso(dt: _dt.datetime) -> str:
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=_dt.timezone.utc)
    return dt.astimezone(_dt.timezone.utc).isoformat(timespec="seconds")


def _parse_iso(text: Any) -> _dt.datetime | None:
    if not text:
        return None
    raw = str(text).strip().replace("Z", "+00:00")
    try:
        dt = _dt.datetime.fromisoformat(raw)
    except ValueError:
        try:
            dt = _dt.datetime.fromisoformat(raw[:10])
        except ValueError:
            return None
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=_dt.timezone.utc)
    return dt


def _json_list(text: Any) -> list[str]:
    if not text:
        return []
    try:
        data = json.loads(text) if isinstance(text, str) else text
    except ValueError:
        return []
    return [str(x) for x in data if x] if isinstance(data, list) else []


def _report_paths_of(case: Mapping[str, Any]) -> list[str]:
    reports = case.get("reports")
    if isinstance(reports, Mapping):
        values: Iterable[Any] = reports.values()
    elif isinstance(reports, (list, tuple)):
        values = reports
    else:
        values = ()
    return _unique_paths(values)


def _unique_paths(*groups: Iterable[Any]) -> list[str]:
    out: list[str] = []
    seen: set[str] = set()
    for group in groups:
        for item in group or ():
            if not item or not isinstance(item, (str, os.PathLike)):
                continue
            text = os.path.abspath(os.fspath(item))
            if text not in seen:
                seen.add(text)
                out.append(text)
    return out


def case_columns(case: Mapping[str, Any]) -> dict[str, Any]:
    """Derived case-row columns of a case dict (also used by the v2 migration for old rows):
    ``seeds`` (JSON search index, personal seeds pseudonymised), ``tlp``, ``purpose``, ``ticket``,
    ``legal_basis``, ``licence_profile``, ``report_paths`` (JSON), ``engagement`` (0/1) and
    ``finding_ids`` (finding and correlation ids, for the override clean-up)."""
    options = case.get("options") if isinstance(case.get("options"), Mapping) else {}
    seeds = [str(s) for s in (case.get("seeds") or []) if s]
    mode = str(options.get("mode") or case.get("mode") or "").strip().lower()
    engagement = 1 if (mode in ENGAGEMENT_MODES or case.get("engagement")) else 0
    ids: set[str] = set()
    for group in ("findings", "correlations"):
        for item in case.get(group) or ():
            if isinstance(item, Mapping) and item.get("id"):
                ids.add(str(item["id"]))
    return {
        "seeds": json.dumps([hmacid.pseudonymize_key(k) for k in seeds], ensure_ascii=False),
        "tlp": str(case.get("tlp") or options.get("tlp") or ""),
        "purpose": str(options.get("purpose") or case.get("purpose") or ""),
        "ticket": str(options.get("ticket") or case.get("ticket") or ""),
        "legal_basis": str(options.get("legal_basis") or case.get("legal_basis") or ""),
        "licence_profile": str(case.get("licence_profile") or options.get("licence_profile") or ""),
        "report_paths": json.dumps(_report_paths_of(case), ensure_ascii=False),
        "engagement": engagement,
        "finding_ids": sorted(ids),
    }


def _display_seed(key: str) -> str:
    """'type:value' with the value masked for display (CPF, VIN, secrets...)."""
    etype_name, sep, value = str(key).partition(":")
    if not sep:
        return str(key)
    try:
        from v3lum.core.entities import EntityType, display_value

        return f"{etype_name}:{display_value(EntityType.parse(etype_name), value)}"
    except Exception:  # an unreadable seed is shown as stored
        return str(key)


def _like(text: str) -> str:
    escaped = text.replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_")
    return f"%{escaped}%"


def minimal_audit_payload(payload: Any) -> dict[str, Any]:
    """An audit payload reduced to the minimal engagement audit (:data:`ENGAGEMENT_AUDIT_FIELDS`;
    a nested ``engagement`` object is reduced the same way). Anything that is not an object gives {}."""
    if not isinstance(payload, Mapping):
        return {}
    out: dict[str, Any] = {}
    for key, value in payload.items():
        if key not in ENGAGEMENT_AUDIT_FIELDS:
            continue
        out[key] = minimal_audit_payload(value) if key == "engagement" else value
    return out


def _parse_payload(text: Any) -> Any:
    try:
        return json.loads(text) if isinstance(text, str) else text
    except ValueError:
        return text


def _quote_ident(name: str) -> str:
    return '"' + str(name).replace('"', '""') + '"'


def _case_tables(conn: sqlite3.Connection) -> list[str]:
    """Every table whose rows belong to one case: :data:`_CASE_TABLES` plus any other table with a
    ``case_id`` column (added by a later migration), except the tombstones and the audit."""
    found = list(_CASE_TABLES)
    for (name,) in conn.execute("SELECT name FROM sqlite_master WHERE type = 'table' ORDER BY name").fetchall():
        name = str(name)
        if name in _SPECIAL_TABLES or name in found or name.startswith("sqlite_"):
            continue
        if "case_id" in {r[1] for r in conn.execute(f"PRAGMA table_info({_quote_ident(name)})")}:
            found.append(name)
    present = {str(r[0]) for r in conn.execute("SELECT name FROM sqlite_master WHERE type = 'table'")}
    return [t for t in found if t in present]


def _created_from_id(case_id: str) -> str:
    """Creation time encoded in a generated case id ('' for other ids)."""
    m = _GENERATED_ID_RE.match(case_id or "")
    if not m:
        return ""
    try:
        when = _dt.datetime.strptime(m.group(1) + m.group(2), "%Y%m%d%H%M%S").replace(tzinfo=_dt.timezone.utc)
    except ValueError:
        return ""
    return _iso(when)


def _row_payload(row: Mapping[str, Any]) -> Any:
    return _parse_payload(row["payload"])


def _minimisable(rows: Iterable[Mapping[str, Any]]) -> int:
    """How many audit rows carry more than the minimal engagement audit (purge rows excluded)."""
    count = 0
    for r in rows:
        if r["kind"] == PURGE_AUDIT_KIND:
            continue
        payload = _row_payload(r)
        if minimal_audit_payload(payload) != payload:
            count += 1
    return count


def _minimise_audit(conn: sqlite3.Connection, case_id: str, rows: list[Any], *, by: str, stamp: str) -> int:
    """Reduce the audit rows of a purged engagement case to :data:`ENGAGEMENT_AUDIT_FIELDS`, re-seal
    them into a fresh hash chain (the old hashes covered fields that no longer exist) and close it
    with a :data:`PURGE_AUDIT_KIND` row naming the purger, the rows minimised, the previous chain head
    and whether the previous chain verified (a chain broken before the purge stays on record).
    Runs inside the caller's transaction; returns the number of rows minimised."""
    prev_stored = AUDIT_GENESIS
    intact = True
    for index, r in enumerate(rows, 1):
        payload = _row_payload(r)
        record = {"case_id": case_id, "seq": r["seq"], "ts": r["ts"], "kind": r["kind"], "payload": payload}
        if int(r["seq"]) != index or r["prev_hash"] != prev_stored or audit_hash(r["prev_hash"], record) != r["hash"]:
            intact = False
        prev_stored = r["hash"]
    prev = AUDIT_GENESIS
    changed = 0
    updates: list[tuple[str, str, str, str, int]] = []
    last_seq = 0
    for r in rows:
        payload = _row_payload(r)
        minimal = payload if r["kind"] == PURGE_AUDIT_KIND else minimal_audit_payload(payload)
        if minimal != payload:
            changed += 1
        record = {"case_id": case_id, "seq": int(r["seq"]), "ts": r["ts"], "kind": r["kind"], "payload": minimal}
        digest = audit_hash(prev, record)
        updates.append((canonical_json(minimal), prev, digest, case_id, int(r["seq"])))
        prev = digest
        last_seq = max(last_seq, int(r["seq"]))
    conn.executemany("UPDATE audit SET payload = ?, prev_hash = ?, hash = ? WHERE case_id = ? AND seq = ?", updates)
    closing = {"by": by, "rows": len(rows), "minimised_rows": changed, "previous_head": prev_stored, "previous_chain_intact": intact}
    record = {"case_id": case_id, "seq": last_seq + 1, "ts": stamp, "kind": PURGE_AUDIT_KIND, "payload": closing}
    conn.execute(
        "INSERT INTO audit (case_id, seq, ts, kind, payload, prev_hash, hash) VALUES (?, ?, ?, ?, ?, ?, ?)",
        (case_id, last_seq + 1, stamp, PURGE_AUDIT_KIND, canonical_json(closing), prev, audit_hash(prev, record)),
    )
    return changed


# ======================================================================================
# purge report
# ======================================================================================


@dataclass
class PurgeReport:
    """Outcome of :meth:`Store.purge_case` (one case).

    ``found``: a case row existed. ``purged``: artefacts were removed (False on a dry run, for a held
    case and when nothing was found). ``held``: legal hold, nothing touched. ``counts``: artefact ->
    number removed (or that a dry run would remove; ``audit_minimised`` = engagement audit rows
    reduced to the minimal audit). ``files``: the file paths removed (in memory only, never stored).
    ``audit_until``: the engagement audit is kept until this UTC time ('' when nothing is kept).
    ``previously_purged``: purged_at of the tombstone when the case had been purged before.
    ``errors``: what could not be removed (the purge is then incomplete).
    """

    case_id: str
    found: bool = False
    purged: bool = False
    dry_run: bool = False
    held: bool = False
    reason: str = ""
    counts: dict[str, int] = field(default_factory=dict)
    files: list[str] = field(default_factory=list)
    audit_until: str = ""
    errors: list[str] = field(default_factory=list)
    previously_purged: str = ""

    @property
    def total(self) -> int:
        """Number of artefacts removed (or that would be)."""
        return sum(int(v) for v in self.counts.values())

    @property
    def complete(self) -> bool:
        """True when nothing that should have been removed was left behind."""
        return not self.errors

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)

    def line(self) -> str:
        """One human line for the CLI."""
        if self.held:
            return f"{self.case_id}: kept (legal hold{': ' + self.reason if self.reason else ''})"
        if not self.found and not self.total:
            if self.previously_purged:
                text = f"{self.case_id}: already purged ({self.previously_purged})"
                return text + (f"; engagement audit kept until {self.audit_until}" if self.audit_until else "")
            return f"{self.case_id}: not found"
        verb = "would remove" if self.dry_run else "removed"
        parts = [f"{name.replace('_', ' ')} {n}" for name, n in sorted(self.counts.items()) if n]
        text = f"{self.case_id}: {verb} {', '.join(parts) if parts else 'nothing'}"
        if self.audit_until:
            text += f"; engagement audit kept until {self.audit_until}"
        if self.errors:
            text += f"; {len(self.errors)} problem(s): {self.errors[0]}"
        return text


# ======================================================================================
# case DB v2 (WP16): Beta reliability, entity verdicts, sightings
# ======================================================================================


def _aware(moment: _dt.datetime) -> _dt.datetime:
    return moment if moment.tzinfo else moment.replace(tzinfo=_dt.timezone.utc)


def _truthy(value: Any) -> bool:
    """A boolean setting (bool, or 'true'/'1'/'yes'/'on' text)."""
    if isinstance(value, str):
        return value.strip().lower() in ("1", "true", "yes", "on")
    return bool(value)


def _word(value: Any) -> str:
    """Lower-case text with single spaces ('' for None)."""
    return " ".join(str(value or "").strip().lower().split())


def _months_back(now: _dt.datetime, months: int) -> _dt.datetime:
    """``now`` minus ``months`` calendar months (the day clamped to the target month: 29 Feb -> 28 Feb)."""
    index = now.year * 12 + (now.month - 1) - int(months)
    year, month0 = divmod(index, 12)
    day = min(now.day, calendar.monthrange(year, month0 + 1)[1])
    return now.replace(year=year, month=month0 + 1, day=day)


def _month_of(stamp: Any) -> str:
    """'YYYY-MM' (UTC) of an ISO timestamp ('' when unreadable)."""
    when = _parse_iso(stamp)
    if when is None:
        return ""
    when = when.astimezone(_dt.timezone.utc)
    return f"{when.year:04d}-{when.month:02d}"


def vote_weight(created: Any, now: _dt.datetime) -> float:
    """Weight of one vote at ``now`` (P325 cond 3): 1.0, or :data:`OLD_VOTE_WEIGHT` (0.5) when it was
    cast more than :data:`OLD_VOTE_MONTHS` (12) calendar months before ``now``. A vote whose date
    cannot be read counts fully."""
    when = _parse_iso(created)
    if when is None:
        return 1.0
    return OLD_VOTE_WEIGHT if when < _months_back(_aware(now), OLD_VOTE_MONTHS) else 1.0


def bucket_weight(month: str, now: _dt.datetime) -> float:
    """Weight of a monthly aggregate bucket ('YYYY-MM') at ``now``: :data:`OLD_VOTE_WEIGHT` once
    every vote in it is older than 12 months (the month ended at least 12 calendar months before
    ``now``), else 1.0. Purged votes survive only in these buckets: their age is known to the month,
    and they are never weighed half before they really are 12 months old. An unreadable month
    counts fully."""
    try:
        year_text, month_text = str(month).split("-", 1)
        year, mon = int(year_text), int(month_text)
        if not 1 <= mon <= 12:
            return 1.0
        end = _dt.datetime(year + mon // 12, mon % 12 + 1, 1, tzinfo=_dt.timezone.utc)
    except (TypeError, ValueError, OverflowError):
        return 1.0
    return OLD_VOTE_WEIGHT if end <= _months_back(_aware(now), OLD_VOTE_MONTHS) else 1.0


def beta_weight(prior: float, alpha: float, beta: float, votes: int) -> float:
    """Reliability weight of a source (P325 cond 3, P302 R_SRC): the mean of
    ``Beta(prior x 4 + alpha, (1 - prior) x 4 + beta)`` - the Admiralty prior mean counted as
    :data:`PRIOR_STRENGTH` (4) pseudo-votes plus the age-weighted votes ('right' adds 1 to alpha,
    'wrong' 1 to beta, 'partly' 0.5 to each). With fewer than :data:`MIN_VOTES` (5) votes the weight
    stays the prior mean; it never falls below :data:`RELIABILITY_FLOOR` (0.3) nor exceeds 1.0."""
    mean = min(1.0, max(0.0, float(prior)))
    if int(votes) >= MIN_VOTES:
        a = mean * PRIOR_STRENGTH + max(0.0, float(alpha))
        b = (1.0 - mean) * PRIOR_STRENGTH + max(0.0, float(beta))
        if a + b > 0:
            mean = a / (a + b)
    return max(RELIABILITY_FLOOR, min(1.0, mean))


def admiralty_prior(source_id: str, registry: Any = None) -> tuple[str, float]:
    """(Admiralty grade, prior mean) of the provider of a registry source id ('provider.source'):
    A 1.0, B 0.85, C 0.7, D 0.5, E 0.3, F 0.5 (``providers.ADMIRALTY``); ``('', UNKNOWN_PRIOR)``
    when the provider is not registered."""
    pid = str(source_id or "").split(".", 1)[0]
    try:
        from v3lum.core import providers as _providers

        reg = registry if registry is not None else _providers.registry()
        provider = reg.get(pid) if pid else None
    except Exception:  # noqa: BLE001 - a broken registry never breaks feedback
        return "", UNKNOWN_PRIOR
    if provider is None:
        return "", UNKNOWN_PRIOR
    grade = str(getattr(getattr(provider, "reliability", None), "grade", "") or "F")
    return grade, float(_providers.ADMIRALTY.get(grade, UNKNOWN_PRIOR))


def _tlp_text(value: Any, *, fallback: str = "red") -> str:
    """Canonical TLP value of ``value``; ``fallback`` when empty or unreadable (fail closed: red)."""
    try:
        return _tlp.parse(value).value_str if value not in (None, "") else fallback
    except ValueError:
        return fallback


def _node_key(node: Mapping[str, Any]) -> str:
    key = node.get("key")
    if isinstance(key, str) and key:
        return key
    etype, value = node.get("type"), node.get("value")
    return f"{etype}:{value}" if etype and isinstance(value, str) else ""


def _entity_of(value: Any) -> Any:
    """An ``Entity`` from an Entity, a 'type:value' key or a case node dict (None when unreadable)."""
    from v3lum.core.entities import Entity, EntityType

    if isinstance(value, Entity):
        return value
    if isinstance(value, Mapping):
        value = _node_key(value)
    etype, sep, raw = str(value or "").partition(":")
    if not sep:
        return None
    try:
        return Entity.make(EntityType.parse(etype), raw)
    except (ValueError, TypeError):
        return None


def _suppressed(item: Mapping[str, Any]) -> bool:
    """Downgraded by a core suppression rule (SUP-*) that no analyst decision blocked."""
    for record in item.get("suppressed_by") or ():
        if isinstance(record, Mapping) and str(record.get("rule", "")).startswith("SUP-") and not record.get("blocked_by"):
            return True
    return False


def _attr_true(entry: Any) -> bool:
    value = entry.get("value") if isinstance(entry, Mapping) else entry
    return value is True or (isinstance(value, str) and value.strip().lower() == "true")


def _decision(item: Mapping[str, Any], overrides: Mapping[str, Mapping[str, Any]]) -> str:
    """The analyst's override verdict on a case item (stored override first, then the one recorded
    in the case JSON), normalised ('false positive' -> 'false_positive')."""
    stored = overrides.get(str(item.get("id") or ""))
    if not stored and isinstance(item.get("override"), Mapping):
        stored = item.get("override")
    return _word((stored or {}).get("verdict")).replace(" ", "_").replace("-", "_")


def entity_verdicts(
    case: Mapping[str, Any],
    overrides: Mapping[str, Mapping[str, Any]] | None = None,
    votes: Mapping[str, str] | None = None,
) -> dict[str, str]:
    """The verdict of every entity of a stored case: entity key -> a :data:`SIGHTING_VERDICTS` member.

    Analyst decisions win: an override verdict that is a sighting verdict (malicious, c2, phishing,
    compromised, suspicious, benign) on one of the entity's findings decides (the most severe one; a
    hostile verdict beats 'benign'). Otherwise the most severe hostile tag (:data:`TAG_VERDICTS`) of
    the entity, of its findings and of the correlations naming it, the boolean attributes
    ``malicious``/``suspicious`` included - ignoring findings and correlations the analyst rejected
    (override verdict or latest vote in :data:`REJECT_VERDICTS`), ``context_only`` findings and
    findings downgraded by a core suppression rule (SUP-*). Entities without a verdict are absent.
    ``overrides`` is :meth:`Store.overrides_for` output and ``votes`` maps item ids to the latest vote
    of the case.
    """
    overrides = overrides or {}
    votes = votes or {}
    explicit: dict[str, set[str]] = {}
    auto: dict[str, set[str]] = {}

    def rejected(item: Mapping[str, Any], verdict: str) -> bool:
        return verdict in REJECT_VERDICTS or votes.get(str(item.get("id") or "")) == "wrong"

    def hits(tags: Any) -> set[str]:
        return {TAG_VERDICTS[t] for t in (str(x) for x in tags or ()) if t in TAG_VERDICTS}

    for item in case.get("findings") or ():
        if not isinstance(item, Mapping):
            continue
        key = str(item.get("entity") or "")
        if not key:
            continue
        verdict = _decision(item, overrides)
        if verdict in SIGHTING_VERDICTS:
            explicit.setdefault(key, set()).add(verdict)
        tags = {str(t) for t in item.get("tags") or ()}
        if rejected(item, verdict) or "context_only" in tags or _suppressed(item):
            continue
        found = hits(tags)
        if found:
            auto.setdefault(key, set()).update(found)
    for item in case.get("correlations") or ():
        if not isinstance(item, Mapping) or rejected(item, _decision(item, overrides)) or _suppressed(item):
            continue
        found = hits(item.get("tags"))
        if not found:
            continue
        for key in item.get("entities") or ():
            auto.setdefault(str(key), set()).update(found)
    for node in case.get("entities") or ():
        if not isinstance(node, Mapping):
            continue
        key = _node_key(node)
        found = hits(node.get("tags"))
        attrs = node.get("attributes") if isinstance(node.get("attributes"), Mapping) else {}
        for name in ("malicious", "suspicious"):
            entries = attrs.get(name)
            if any(_attr_true(e) for e in (entries if isinstance(entries, list) else [entries]) if e is not None):
                found.add(name)
        if key and found:
            auto.setdefault(key, set()).update(found)
    out: dict[str, str] = {}
    for key in sorted(set(explicit) | set(auto)):
        chosen = explicit.get(key, set())
        hostile = [v for v in SIGHTING_VERDICTS if v != "benign" and v in chosen]
        if hostile:
            out[key] = hostile[0]
        elif "benign" in chosen:
            out[key] = "benign"
        else:
            found = auto.get(key, set())
            out[key] = next((v for v in SIGHTING_VERDICTS if v in found), "")
    return {k: v for k, v in out.items() if v}


def _is_noise_node(node: Mapping[str, Any], entity: Any) -> bool:
    """Noise for the sightings index (P375 cond 4): recorded noise (public resolvers, CDNs, big
    providers, sinkholes, parking...), :data:`NOISE_TAGS`, or noise/warninglist lists today."""
    if node.get("noise") or node.get("noise_kind"):
        return True
    if NOISE_TAGS.intersection(str(t) for t in node.get("tags") or ()):
        return True
    try:
        from v3lum.core import noise

        return bool(noise.is_noise(entity) or noise.warninglists(entity))
    except Exception:  # noqa: BLE001 - an unusable list never hides an entity from the index
        return False


def _is_own(node: Mapping[str, Any], entity: Any, org: Any) -> bool:
    """Own org asset (P375 cond 4): recorded ownership, or the organisation profile today."""
    if str(node.get("ownership") or "") == "own_asset" or "own_asset" in {str(t) for t in node.get("tags") or ()}:
        return True
    if org is None:
        return False
    try:
        return bool(getattr(org.owns(entity), "own", False))
    except Exception:  # noqa: BLE001
        return False


def sighting_rows(
    case: Mapping[str, Any],
    *,
    personal: bool = False,
    org: Any = None,
    overrides: Mapping[str, Mapping[str, Any]] | None = None,
    votes: Mapping[str, str] | None = None,
) -> list[tuple[Any, ...]]:
    """The sightings index rows of one stored case (P375 cond 1-4, A2, A4):
    ``(entity_key, entity_hmac, entity_type, case_id, case_tlp, engagement, created, verdict)``.

    * IOC_TYPES entities are indexed by their entity key (plus the keyed HMAC); PERSONAL_TYPES only
      when ``personal`` (setting sightings_personal on and the case has a purpose), and then only as
      the keyed HMAC (``hmacid.hmac_hex``; ``entity_key`` stays '') - never the value. Every other
      type (text, files, secrets, company ids...) is never indexed.
    * Noise entities (recorded noise, :data:`NOISE_TAGS`, noise lists and warninglists) and own org
      assets (recorded ownership or ``org.owns``) are not indexed.
    * ``case_tlp`` is the highest of the case TLP and the entity TLP (unreadable -> red), and at
      least AMBER for LIGHT/ACTIVE cases (A2: a mislabelled engagement case never becomes visible to
      CLEAR/GREEN cases); ``engagement`` is 1 for LIGHT/ACTIVE cases; ``verdict`` comes from
      :func:`entity_verdicts`.
    """
    from v3lum.core.entities import IOC_TYPES, PERSONAL_TYPES

    case_id = str(case.get("case_id") or "").strip()
    if not case_id:
        return []
    options = case.get("options") if isinstance(case.get("options"), Mapping) else {}
    base_tlp = _tlp_text(case.get("tlp") or options.get("tlp"))
    created = str(case.get("created") or "")
    engagement = int(case_columns(case)["engagement"])
    verdicts = entity_verdicts(case, overrides, votes)
    nodes: list[Any] = list(case.get("entities") or ()) or [{"key": s} for s in case.get("seeds") or ()]
    rows: dict[tuple[str, str], tuple[Any, ...]] = {}
    for raw in nodes:
        node = raw if isinstance(raw, Mapping) else {"key": str(raw)}
        entity = _entity_of(node)
        if entity is None:
            continue
        is_personal = entity.type in PERSONAL_TYPES
        if (is_personal and not personal) or (not is_personal and entity.type not in IOC_TYPES):
            continue
        if _is_noise_node(node, entity) or _is_own(node, entity, org):
            continue
        try:
            digest = hmacid.hmac_hex(entity.type, entity.value)
        except Exception as exc:  # noqa: BLE001 - no secret: personal values are never indexed in clear (A4)
            if is_personal:
                log.warning("sightings: personal entity not indexed (no installation secret: %s)", type(exc).__name__)
                continue
            digest = ""
        key = "" if is_personal else entity.key
        try:
            levels = [base_tlp, node.get("tlp") or base_tlp] + (["amber"] if engagement else [])
            tlp = _tlp.highest(*levels).value_str  # LIGHT/ACTIVE cases are at least AMBER (A2)
        except ValueError:
            tlp = _tlp.TLP.RED.value_str
        verdict = verdicts.get(_node_key(node)) or verdicts.get(entity.key, "")
        rows[(key, digest)] = (key, digest, entity.type.value, case_id, tlp, engagement, created, verdict)
    return list(rows.values())


@dataclass
class SightingsSummary:
    """Cross-case sightings of one entity as one case may see them (P375, A2).

    ``visible``: one row per earlier case whose TLP is <= the viewing case's TLP, newest first:
    ``{case_id, created, verdict, tlp, case_verdict}`` - ``verdict`` is the entity's verdict in that
    case ('' = none; malicious | c2 | phishing | compromised | suspicious | benign), ``case_verdict``
    the analyst's overall verdict on that case (yes | partial | no, '' = none). ``restricted_count``:
    earlier non-RED, non-engagement cases above the viewer's TLP (AMBER/AMBER+STRICT; GREEN seen from
    CLEAR) - counted only, never with ids, dates or verdicts. RED and LIGHT/ACTIVE engagement cases
    above the viewer's TLP are not counted at all. Findings are never copied across cases.
    """

    visible: list[dict[str, str]] = field(default_factory=list)
    restricted_count: int = 0

    @property
    def count(self) -> int:
        """Number of visible earlier cases."""
        return len(self.visible)

    @property
    def total(self) -> int:
        """Visible plus restricted earlier cases."""
        return self.count + max(0, int(self.restricted_count))

    @property
    def last(self) -> str:
        """Date (YYYY-MM-DD) of the newest visible case ('' when none)."""
        dates = [str(v.get("created") or "")[:10] for v in self.visible if v.get("created")]
        return max(dates) if dates else ""

    @property
    def verdict(self) -> str:
        """Verdict of the newest visible case that recorded one ('' when none)."""
        for row in sorted(self.visible, key=lambda v: (str(v.get("created") or ""), str(v.get("case_id") or "")), reverse=True):
            if row.get("verdict"):
                return str(row["verdict"])
        return ""

    def verdicts(self) -> dict[str, int]:
        """Visible cases per recorded verdict."""
        out: dict[str, int] = {}
        for row in self.visible:
            if row.get("verdict"):
                out[str(row["verdict"])] = out.get(str(row["verdict"]), 0) + 1
        return dict(sorted(out.items()))

    def attribute(self) -> dict[str, Any]:
        """The value of attribute ``sightings``: ``{count, last, verdict, restricted, verdicts}``
        (no case ids, so stored cases and exports never carry cross-case references)."""
        return {"count": self.count, "last": self.last, "verdict": self.verdict, "restricted": max(0, int(self.restricted_count)), "verdicts": self.verdicts()}

    def headline(self) -> str:
        """'seen in 3 previous cases, last 2026-11-20, verdict: malicious' (visible cases), 'seen in 2
        restricted cases' (restricted only) or '' (never seen)."""
        if self.count:
            plural = "s" if self.count != 1 else ""
            return f"seen in {self.count} previous case{plural}, last {self.last or 'unknown'}, verdict: {self.verdict or 'none'}"
        if self.restricted_count > 0:
            return f"seen in {self.restricted_count} restricted case{'s' if self.restricted_count != 1 else ''}"
        return ""

    def line(self) -> str:
        """:meth:`headline` plus the restricted count when there are visible cases too."""
        text = self.headline()
        if self.count and self.restricted_count > 0:
            text += f"; also in {self.restricted_count} restricted case{'s' if self.restricted_count != 1 else ''} (higher TLP)"
        return text

    def to_dict(self) -> dict[str, Any]:
        return {"visible": [dict(v) for v in self.visible], "restricted_count": max(0, int(self.restricted_count))}


def cross_case_allowed(tlp: Any) -> bool:
    """Whether an export or shareable report at ``tlp`` may carry cross-case references (A2): only
    AMBER and above. CLEAR/GREEN and an empty or unreadable TLP (fail closed) -> False."""
    try:
        return _value_tlp(tlp) >= _tlp.TLP.AMBER
    except ValueError:
        return False


def _value_tlp(value: Any) -> _tlp.TLP:
    """``tlp.parse`` of a non-empty value (ValueError for an empty or unreadable one)."""
    if value in (None, ""):
        raise ValueError("no TLP")
    return _tlp.parse(value)


def _sightings_counts(entry: Any) -> tuple[int, int]:
    """(visible count, restricted count) of one ``sightings`` attribute entry."""
    value = entry.get("value") if isinstance(entry, Mapping) and "value" in entry else entry
    if not isinstance(value, Mapping):
        return 0, 0
    try:
        return max(0, int(value.get("count") or 0)), max(0, int(value.get("restricted") or 0))
    except (TypeError, ValueError):
        return 0, 0


def omit_cross_case(case: Mapping[str, Any], *, keep_count: bool = False) -> dict[str, Any]:
    """A copy of a case dict without cross-case references (A2, P375 cond 3) for exports and
    shareable reports; the stored case is never changed.

    Default (CLEAR/GREEN): the :data:`CROSS_CASE_ATTRIBUTES` entity attributes, the findings of
    :data:`CROSS_CASE_MODULES` (and their ids on entities and in the risk contributors) and the
    correlations of :data:`CROSS_CASE_RULES` are removed. ``keep_count=True`` (AMBER+ exports): they
    stay, reduced to the counts - attribute ``{count, restricted}``, finding titles 'seen in N
    previous cases' / 'seen in N restricted cases' with data ``{count, restricted}``, recurrence
    descriptions and evidence without the last date or the earlier verdicts. Other cases' ids are
    never part of a case in the first place."""
    out: dict[str, Any] = copy.deepcopy(dict(case))
    counts: dict[str, tuple[int, int]] = {}
    removed: set[str] = set()
    for node in out.get("entities") or ():
        if not isinstance(node, dict):
            continue
        attrs = node.get("attributes")
        if not isinstance(attrs, dict):
            continue
        for name in CROSS_CASE_ATTRIBUTES & set(attrs):
            entries = attrs[name] if isinstance(attrs[name], list) else [attrs[name]]
            seen = [_sightings_counts(e) for e in entries]
            visible, restricted = (max((c[0] for c in seen), default=0), max((c[1] for c in seen), default=0))
            counts[_node_key(node)] = (visible, restricted)
            if keep_count:
                attrs[name] = [{"value": {"count": visible, "restricted": restricted}, "source": next(iter(CROSS_CASE_MODULES))}]
            else:
                del attrs[name]
    findings: list[Any] = []
    for item in out.get("findings") or ():
        if isinstance(item, dict) and str(item.get("module") or "") in CROSS_CASE_MODULES:
            if not keep_count:
                removed.add(str(item.get("id") or ""))
                continue
            visible, restricted = counts.get(str(item.get("entity") or ""), _sightings_counts(item.get("data")))
            if visible:
                item["title"] = f"seen in {visible} previous case{'s' if visible != 1 else ''}"
            else:
                item["title"] = f"seen in {restricted} restricted case{'s' if restricted != 1 else ''}"
            item["description"] = "Earlier V3LUM cases contain the same indicator (count only: no ids, dates or verdicts)."
            item["data"] = {"count": visible, "restricted": restricted}
        findings.append(item)
    if "findings" in out:
        out["findings"] = findings
    correlations: list[Any] = []
    for item in out.get("correlations") or ():
        if isinstance(item, dict) and str(item.get("rule") or "") in CROSS_CASE_RULES:
            if not keep_count:
                continue
            keys = [str(k) for k in item.get("entities") or ()]
            total = sum(sum(counts.get(k, (0, 0))) for k in keys)
            plural = "s" if total != 1 else ""
            item["description"] = f"The same indicator appears in {total} earlier V3LUM case{plural} (count only)."
            item["evidence"] = [f"seen in {total} earlier case{plural}"]
            item["why"] = f"same indicator in this case and {total} earlier case{plural}"
        correlations.append(item)
    if "correlations" in out:
        out["correlations"] = correlations
    removed.discard("")
    if removed:
        for node in out.get("entities") or ():
            if isinstance(node, dict) and isinstance(node.get("findings"), list):
                node["findings"] = [f for f in node["findings"] if str(f) not in removed]
        risk = out.get("risk")
        if isinstance(risk, dict) and isinstance(risk.get("contributors"), list):
            risk["contributors"] = [
                c for c in risk["contributors"] if not (isinstance(c, Mapping) and str(c.get("finding_id") or "") in removed)
            ]
    return out


# ======================================================================================
# store
# ======================================================================================


class Store:
    """The case DB. ``Store(path=None, *, settings=None, clock=None, cache_path=None, quota_path=None, health=None)``.

    ``path`` defaults to ``paths.db_file()``; ``settings`` (Config or mapping; default
    ``Config.load()`` on first use) provides retention_days, audit_retention_days, quota_db_path,
    sightings_personal and org_profile_path; ``clock`` stamps rows and drives retention;
    ``cache_path``/``quota_path`` override the HTTP-cache and quota DBs the purge cleans (defaults:
    ``paths.cache_file()`` and the quota DB of the settings). ``health`` receives the per-module
    vote totals of the A3 demotion (``HealthState.record_votes``): default the home's
    ``~/.v3lum/health.json`` when this store is the home's case DB, nothing otherwise; ``False``
    disables it. Thread-safe (one connection behind a re-entrant lock).
    """

    def __init__(
        self,
        path: str | Path | None = None,
        *,
        settings: Any = None,
        clock: Clock | None = None,
        cache_path: str | Path | None = None,
        quota_path: str | Path | None = None,
        health: Any = None,
    ) -> None:
        self.path = str(path or paths.db_file())
        self.clock: Clock = clock or SYSTEM_CLOCK
        self._settings = settings
        self._cache_path = cache_path
        self._quota_path = quota_path
        self._health = health
        self._lock = threading.RLock()
        paths.restrict_file(self.path, create=True)  # never exists with a looser mode (AR03)
        self._conn = sqlite3.connect(self.path, check_same_thread=False, timeout=30)
        self._conn.row_factory = sqlite3.Row
        self._conn.execute("PRAGMA secure_delete = ON")
        backfill = _needs_sightings_backfill(self._conn)
        #: schema version after the migrations ran
        self.version = migrate(self._conn, "cases")
        paths.restrict_file(self.path)
        if backfill:  # cases stored before the sightings index existed become visible to later cases (P375)
            try:
                self.reindex_sightings()
            except Exception as exc:  # noqa: BLE001 - a backfill problem never blocks opening the case DB
                log.warning("sightings index backfill failed: %s", type(exc).__name__)

    # ------------------------------------------------------------------ plumbing
    def close(self) -> None:
        with self._lock:
            self._conn.close()

    def __enter__(self) -> Store:
        return self

    def __exit__(self, *exc: Any) -> None:
        self.close()

    @contextlib.contextmanager
    def connection(self) -> Iterator[sqlite3.Connection]:
        """The case-DB connection for sibling packages (audit, feedback, sightings, watch), held
        under the store lock for the block: committed on success, rolled back on an exception."""
        with self._lock:
            try:
                yield self._conn
            except BaseException:
                self._conn.rollback()
                raise
            else:
                self._conn.commit()

    def _now(self, now: _dt.datetime | None = None) -> _dt.datetime:
        current = now or self.clock.now()
        return current if current.tzinfo else current.replace(tzinfo=_dt.timezone.utc)

    def setting(self, name: str, default: Any = None) -> Any:
        """A setting from the injected settings, else the loaded Config (cached per store)."""
        settings = self._settings
        if settings is None:
            try:
                from v3lum.config import Config

                settings = self._settings = Config.load()
            except Exception:  # pragma: no cover - a broken config never breaks the store
                return default
        try:
            getter = getattr(settings, "get", None)
            value = getter(name, default) if callable(getter) else getattr(settings, name, default)
        except Exception:  # pragma: no cover
            return default
        return default if value is None else value

    def _int_setting(self, name: str, default: int) -> int:
        try:
            return int(float(self.setting(name, default)))
        except (TypeError, ValueError):
            return default

    def retention_days(self) -> int:
        """Setting retention_days (A10; 0 = no automatic retention purge)."""
        return max(0, self._int_setting("retention_days", 180))

    def audit_retention_days(self) -> int:
        """Setting audit_retention_days (0 = retention_days), the minimal engagement audit's retention."""
        days = max(0, self._int_setting("audit_retention_days", 0))
        return days or self.retention_days()

    # ------------------------------------------------------------------ cases
    def save_case(self, case: Mapping[str, Any]) -> None:
        """Insert or update a case (the legal hold and earlier recorded report paths are kept) and
        (re)build its sightings index rows (:meth:`index_case`, P375). An index problem never fails
        the save: the case is stored without index rows and the problem is logged."""
        summary = case.get("summary", {}) or {}
        cols = case_columns(case)
        case_id = str(case["case_id"])
        created = str(case.get("created") or _iso(self._now()))
        data = json.dumps(case, ensure_ascii=False, default=str)
        with self.connection() as conn:
            row = conn.execute("SELECT report_paths FROM cases WHERE id = ?", (case_id,)).fetchone()
            recorded = [r[0] for r in conn.execute("SELECT path FROM report_hashes WHERE case_id = ?", (case_id,))]
            merged = _unique_paths(_json_list(row["report_paths"]) if row else [], _json_list(cols["report_paths"]), recorded)
            conn.execute(
                "INSERT INTO cases (id, created, seeds, risk_score, risk_level, findings, entities, data, tlp, purpose,"
                " ticket, legal_basis, licence_profile, report_paths, engagement) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)"
                " ON CONFLICT(id) DO UPDATE SET created = excluded.created, seeds = excluded.seeds,"
                " risk_score = excluded.risk_score, risk_level = excluded.risk_level, findings = excluded.findings,"
                " entities = excluded.entities, data = excluded.data, tlp = excluded.tlp, purpose = excluded.purpose,"
                " ticket = excluded.ticket, legal_basis = excluded.legal_basis,"
                " licence_profile = excluded.licence_profile, report_paths = excluded.report_paths,"
                " engagement = MAX(cases.engagement, excluded.engagement)",
                (
                    case_id,
                    created,
                    cols["seeds"],
                    summary.get("risk_score", 0.0),
                    summary.get("risk_level", "clean"),
                    summary.get("findings", 0),
                    summary.get("entities", 0),
                    data,
                    cols["tlp"],
                    cols["purpose"],
                    cols["ticket"],
                    cols["legal_basis"],
                    cols["licence_profile"],
                    json.dumps(merged, ensure_ascii=False),
                    cols["engagement"],
                ),
            )
            conn.execute("DELETE FROM case_findings WHERE case_id = ?", (case_id,))
            conn.executemany(
                "INSERT OR IGNORE INTO case_findings (case_id, finding_id) VALUES (?, ?)",
                [(case_id, fid) for fid in cols["finding_ids"]],
            )
            self._index_safely(conn, case)  # the sightings index is written at save time (P375 cond 1)

    def _search_patterns(self, search: str) -> list[str]:
        """LIKE patterns for the seeds index: the text itself (non-personal values match by
        substring) plus the pseudonym of every personal type the exact query parses as (A4 BR8)."""
        query = search.strip()
        patterns = [_like(query)]
        try:
            from v3lum.core.entities import Entity, EntityType
        except ImportError:  # pragma: no cover
            return patterns
        candidates: list[tuple[Any, str]] = []
        etype_name, sep, value = query.partition(":")
        if sep:
            try:
                candidates.append((EntityType.parse(etype_name), value))
            except ValueError:
                pass
        candidates.extend((t, query) for t in sorted(hmacid.PSEUDONYMISED_TYPES, key=lambda t: t.value))
        for etype, raw in candidates:
            if etype not in hmacid.PSEUDONYMISED_TYPES:
                continue
            entity = Entity.try_make(etype, raw)
            if entity is not None:
                pattern = _like(f'"{hmacid.pseudonym(entity.type, entity.value)}"')
                if pattern not in patterns:
                    patterns.append(pattern)
        return patterns

    def list_cases(self, limit: int = 30, search: str = "") -> list[dict[str, Any]]:
        """Newest cases first: id, created, seeds (display form, sensitive values masked), risk,
        counts, tlp, legal_hold, engagement. ``search`` matches the case id, non-personal seeds by
        substring and personal seeds only by their exact value (hashed before matching)."""
        sql = (
            "SELECT id, created, seeds, risk_score, risk_level, findings, entities, tlp, legal_hold, engagement,"
            " json_extract(data, '$.seeds') AS display_seeds FROM cases"
        )
        params: list[Any] = []
        if search and search.strip():
            patterns = self._search_patterns(search)
            clauses = ["id LIKE ? ESCAPE '\\'"] + ["seeds LIKE ? ESCAPE '\\'"] * len(patterns)
            sql += " WHERE " + " OR ".join(clauses)
            params += [_like(search.strip()), *patterns]
        sql += " ORDER BY created DESC LIMIT ?"
        params.append(int(limit))
        with self._lock:
            try:
                rows = self._conn.execute(sql, params).fetchall()
            except sqlite3.OperationalError:  # SQLite without JSON1: parse the case JSON in Python
                rows = self._conn.execute(sql.replace("json_extract(data, '$.seeds')", "data"), params).fetchall()
        out = []
        for r in rows:
            d = dict(r)
            raw = d.pop("display_seeds", None)
            seeds: list[str] = []
            try:
                parsed = json.loads(raw) if raw else []
                if isinstance(parsed, dict):
                    parsed = parsed.get("seeds") or []
                seeds = [str(s) for s in parsed] if isinstance(parsed, list) else []
            except ValueError:
                seeds = []
            if not seeds:
                seeds = _json_list(d.get("seeds"))
            d["seeds"] = [_display_seed(s) if not hmacid.is_pseudonym(s) else s for s in seeds]
            d["legal_hold"] = bool(d.get("legal_hold"))
            d["engagement"] = bool(d.get("engagement"))
            out.append(d)
        return out

    def get_case(self, case_id: str) -> dict[str, Any] | None:
        """The stored case dict: exact id, 'last'/'latest', or a unique id prefix."""
        with self._lock:
            row = self._conn.execute("SELECT data FROM cases WHERE id = ?", (case_id,)).fetchone()
            if row is None and case_id in ("last", "latest"):
                row = self._conn.execute("SELECT data FROM cases ORDER BY created DESC LIMIT 1").fetchone()
            if row is None:
                rows = self._conn.execute(
                    "SELECT data FROM cases WHERE id LIKE ? ESCAPE '\\' ORDER BY created DESC", (_like(case_id)[1:],)
                ).fetchall()
                row = rows[0] if len(rows) == 1 else None
        return json.loads(row["data"]) if row else None

    def case_info(self, case_id: str) -> dict[str, Any] | None:
        """The case row without its JSON: created, tlp, legal hold fields, purpose, ticket,
        legal_basis, licence_profile, report_paths (list), engagement. None when unknown."""
        with self._lock:
            row = self._conn.execute(
                "SELECT id, created, tlp, legal_hold, hold_reason, hold_requester, held_at, purpose, ticket, legal_basis,"
                " licence_profile, report_paths, engagement, risk_score, risk_level, findings, entities FROM cases WHERE id = ?",
                (case_id,),
            ).fetchone()
        if row is None:
            return None
        d = dict(row)
        d["report_paths"] = _json_list(d.get("report_paths"))
        d["legal_hold"] = bool(d.get("legal_hold"))
        d["engagement"] = bool(d.get("engagement"))
        return d

    def delete_case(self, case_id: str) -> bool:
        """v1 entry point, now the A10 purge: ``purge_case(case_id, by='cli')``. True when the case
        existed and was purged (False for an unknown case or one under legal hold)."""
        report = self.purge_case(case_id, by="cli")
        return report.found and report.purged

    # ------------------------------------------------------------------ recorded artefacts
    def record_report_paths(self, case_id: str, report_paths: Mapping[str, Any] | Iterable[Any]) -> int:
        """Remember report files written for a case (any directory, ``-o`` included) so the purge
        removes them. Works before the case row exists. Returns the number of new paths."""
        values = report_paths.values() if isinstance(report_paths, Mapping) else report_paths
        items = _unique_paths(values)
        if not items:
            return 0
        stamp = _iso(self._now())
        with self.connection() as conn:
            before = conn.total_changes
            conn.executemany(
                "INSERT OR IGNORE INTO report_hashes (case_id, path, sha256, created) VALUES (?, ?, NULL, ?)",
                [(case_id, p, stamp) for p in items],
            )
            added = conn.total_changes - before
            self._merge_report_paths(conn, case_id, items)
        return added

    def record_report_hashes(self, case_id: str, hashes: Mapping[str, str]) -> int:
        """Record ``{path: sha256}`` of written reports (WP20 writes them, WP15's verify reads them);
        the paths are also recorded for the purge. Returns the number of rows written."""
        rows = [(os.path.abspath(os.fspath(p)), str(h or "").lower() or None) for p, h in (hashes or {}).items() if p]
        if not rows:
            return 0
        stamp = _iso(self._now())
        with self.connection() as conn:
            conn.executemany(
                "INSERT INTO report_hashes (case_id, path, sha256, created) VALUES (?, ?, ?, ?)"
                " ON CONFLICT(case_id, path) DO UPDATE SET sha256 = excluded.sha256, created = excluded.created",
                [(case_id, p, h, stamp) for p, h in rows],
            )
            self._merge_report_paths(conn, case_id, [p for p, _ in rows])
        return len(rows)

    def report_hashes(self, case_id: str) -> dict[str, str]:
        """``{path: sha256}`` of the reports recorded with a hash for ``case_id``."""
        with self._lock:
            rows = self._conn.execute(
                "SELECT path, sha256 FROM report_hashes WHERE case_id = ? AND sha256 IS NOT NULL AND sha256 != '' ORDER BY path",
                (case_id,),
            ).fetchall()
        return {r["path"]: r["sha256"] for r in rows}

    def report_paths(self, case_id: str) -> list[str]:
        """Every report path recorded for ``case_id`` (case row, recorded paths and hashes)."""
        with self._lock:
            row = self._conn.execute("SELECT report_paths FROM cases WHERE id = ?", (case_id,)).fetchone()
            recorded = [r[0] for r in self._conn.execute("SELECT path FROM report_hashes WHERE case_id = ? ORDER BY path", (case_id,))]
        return _unique_paths(_json_list(row["report_paths"]) if row else [], recorded)

    @staticmethod
    def _merge_report_paths(conn: sqlite3.Connection, case_id: str, items: list[str]) -> None:
        row = conn.execute("SELECT report_paths FROM cases WHERE id = ?", (case_id,)).fetchone()
        if row is None:
            return
        merged = _unique_paths(_json_list(row["report_paths"]), items)
        conn.execute("UPDATE cases SET report_paths = ? WHERE id = ?", (json.dumps(merged, ensure_ascii=False), case_id))

    def record_cache_keys(self, case_id: str, keys: Iterable[str]) -> int:
        """Remember the HTTP-cache keys written or served during a case (HttpClient cache_key_sink)
        so the purge removes those cache rows (A10). Returns the number of new keys."""
        items = sorted({str(k) for k in (keys or ()) if k})
        if not items:
            return 0
        with self.connection() as conn:
            before = conn.total_changes
            conn.executemany("INSERT OR IGNORE INTO case_cache_keys (case_id, cache_key) VALUES (?, ?)", [(case_id, k) for k in items])
            return conn.total_changes - before

    def cache_keys(self, case_id: str) -> list[str]:
        """The cache keys recorded for ``case_id``."""
        with self._lock:
            return [r[0] for r in self._conn.execute("SELECT cache_key FROM case_cache_keys WHERE case_id = ? ORDER BY cache_key", (case_id,))]

    # ------------------------------------------------------------------ audit (hash chain)
    def append_audit(self, case_id: str, kind: str, payload: Mapping[str, Any] | None = None, *, ts: str | None = None) -> dict[str, Any]:
        """Append one hash-chained audit row (``seq`` 1, 2, ...; ``hash`` = :func:`audit_hash`) and
        return it. Payloads hold metadata only (no bodies, no secrets); they are stored as
        canonical JSON."""
        body = dict(payload or {})
        with self.connection() as conn:
            if not conn.in_transaction:  # take the write lock before reading the chain head (other processes)
                conn.execute("BEGIN IMMEDIATE")
            last = conn.execute("SELECT seq, hash FROM audit WHERE case_id = ? ORDER BY seq DESC LIMIT 1", (case_id,)).fetchone()
            seq = int(last["seq"]) + 1 if last else 1
            prev = str(last["hash"]) if last else AUDIT_GENESIS
            stamp = ts or _iso(self._now())
            record = {"case_id": case_id, "seq": seq, "ts": stamp, "kind": str(kind), "payload": body}
            digest = audit_hash(prev, record)
            conn.execute(
                "INSERT INTO audit (case_id, seq, ts, kind, payload, prev_hash, hash) VALUES (?, ?, ?, ?, ?, ?, ?)",
                (case_id, seq, stamp, str(kind), canonical_json(body), prev, digest),
            )
        return {**record, "prev_hash": prev, "hash": digest}

    def audit_rows(self, case_id: str) -> list[dict[str, Any]]:
        """The audit rows of ``case_id`` in order (payload parsed)."""
        with self._lock:
            rows = self._conn.execute(
                "SELECT case_id, seq, ts, kind, payload, prev_hash, hash FROM audit WHERE case_id = ? ORDER BY seq", (case_id,)
            ).fetchall()
        out = []
        for r in rows:
            d = dict(r)
            try:
                d["payload"] = json.loads(d["payload"])
            except ValueError:
                pass
            out.append(d)
        return out

    def verify_audit_chain(self, case_id: str) -> list[str]:
        """Problems of the audit chain of ``case_id`` (empty list = intact)."""
        problems: list[str] = []
        prev = AUDIT_GENESIS
        for index, row in enumerate(self.audit_rows(case_id), 1):
            if int(row["seq"]) != index:
                problems.append(f"audit row {row['seq']}: expected sequence number {index}")
            if row["prev_hash"] != prev:
                problems.append(f"audit row {row['seq']}: prev_hash does not match the previous row")
            if audit_hash(row["prev_hash"], row) != row["hash"]:
                problems.append(f"audit row {row['seq']}: hash mismatch (row edited)")
            prev = row["hash"]
        return problems

    # ------------------------------------------------------------------ legal hold
    def hold(self, case_id: str, reason: str, requester: str, *, now: _dt.datetime | None = None) -> bool:
        """Put a case under legal hold (exempt from every purge, A10); writes an audit row 'hold'.
        Reason and requester are required. False when the case does not exist."""
        reason, requester = str(reason or "").strip(), str(requester or "").strip()
        if not reason or not requester:
            raise ValueError("a legal hold needs a reason and a requester")
        stamp = _iso(self._now(now))
        with self.connection() as conn:
            cur = conn.execute(
                "UPDATE cases SET legal_hold = 1, hold_reason = ?, hold_requester = ?, held_at = ? WHERE id = ?",
                (reason, requester, stamp, case_id),
            )
            if cur.rowcount == 0:
                return False
            self.append_audit(case_id, "hold", {"reason": reason, "requester": requester}, ts=stamp)
        return True

    def unhold(self, case_id: str, *, by: str = "", now: _dt.datetime | None = None) -> bool:
        """Release a legal hold; writes an audit row 'unhold'. False when the case is unknown or not held."""
        stamp = _iso(self._now(now))
        with self.connection() as conn:
            row = conn.execute("SELECT legal_hold, hold_reason, hold_requester FROM cases WHERE id = ?", (case_id,)).fetchone()
            if row is None or not row["legal_hold"]:
                return False
            conn.execute("UPDATE cases SET legal_hold = 0, hold_reason = NULL, hold_requester = NULL, held_at = NULL WHERE id = ?", (case_id,))
            payload = {"previous_reason": row["hold_reason"] or "", "previous_requester": row["hold_requester"] or ""}
            if by:
                payload["by"] = str(by)
            self.append_audit(case_id, "unhold", payload, ts=stamp)
        return True

    def held_cases(self) -> list[dict[str, Any]]:
        """Cases under legal hold: id, created, hold_reason, hold_requester, held_at."""
        with self._lock:
            rows = self._conn.execute(
                "SELECT id, created, hold_reason, hold_requester, held_at FROM cases WHERE legal_hold = 1 ORDER BY created"
            ).fetchall()
        return [dict(r) for r in rows]

    # ------------------------------------------------------------------ retention
    def cases_past_retention(self, now: _dt.datetime | None = None) -> list[dict[str, Any]]:
        """Cases older than retention_days that are not held (startup reminder, ``cases purge``):
        ``[{id, created, age_days}]`` oldest first; [] when retention_days is 0."""
        days = self.retention_days()
        if days <= 0:
            return []
        current = self._now(now)
        cutoff = current - _dt.timedelta(days=days)
        with self._lock:
            rows = self._conn.execute("SELECT id, created FROM cases WHERE legal_hold = 0 ORDER BY created").fetchall()
        out = []
        for r in rows:
            created = _parse_iso(r["created"])
            if created is not None and created < cutoff:
                out.append({"id": r["id"], "created": r["created"], "age_days": (current - created).days})
        return out

    def retention_reminder(self, now: _dt.datetime | None = None) -> str:
        """The startup reminder line ('3 cases older than 180 days: v3lum cases purge'), at most once
        per day (state in ``paths.reminder_file()``); '' when nothing is due or it was shown today."""
        current = self._now(now)
        today = current.date().isoformat()
        state_path = paths.reminder_file()
        try:
            state = json.loads(state_path.read_text(encoding="utf-8"))
        except (OSError, ValueError):
            state = {}
        if isinstance(state, dict) and state.get("last") == today:
            return ""
        due = self.cases_past_retention(current)
        if not due:
            return ""
        try:
            paths.secure_write_text(state_path, json.dumps({"last": today}))
        except OSError:  # pragma: no cover - a read-only home shows the line again tomorrow too
            pass
        n = len(due)
        return f"{n} case{'s' if n != 1 else ''} older than {self.retention_days()} days: v3lum cases purge"

    # ------------------------------------------------------------------ purge (A10)
    def tombstone(self, case_id: str) -> dict[str, Any] | None:
        """The value-free tombstone of a purged case (counts parsed) or None."""
        with self._lock:
            row = self._conn.execute(
                "SELECT case_id, created, purged_at, purged_by, counts, audit_until FROM tombstones WHERE case_id = ?", (case_id,)
            ).fetchone()
        if row is None:
            return None
        d = dict(row)
        try:
            d["counts"] = json.loads(d["counts"] or "{}")
        except ValueError:
            d["counts"] = {}
        return d

    def tombstones(self) -> list[dict[str, Any]]:
        """Every tombstone, newest purge first."""
        with self._lock:
            ids = [r[0] for r in self._conn.execute("SELECT case_id FROM tombstones ORDER BY purged_at DESC, case_id")]
        return [t for t in (self.tombstone(i) for i in ids) if t is not None]

    def purge_case(self, case_id: str, *, by: str, dry_run: bool = False, now: _dt.datetime | None = None, vacuum: bool = True) -> PurgeReport:
        """THE purge routine (A10/AR04) behind ``cases delete`` and ``cases purge``.

        Removes the case row and its rows in every case table (feedback, votes, sightings, evidence
        versions, report hashes, alerts, watch first-seen state, cache keys and any table a later
        migration adds with a ``case_id`` column), the analyst overrides of its finding ids that no
        other stored case still contains, the case directory (evidence, reports, the audit mirror),
        every recorded report file outside it whose name contains the case id (and its ``.sha256``
        sidecar), the HTTP-cache rows recorded for the case and its deferred quota lookups; then
        ``PRAGMA secure_delete`` + ``VACUUM`` of the case DB and the cache (``vacuum=False`` defers
        both to the caller) and writes a value-free tombstone. A case under legal hold is left
        untouched (``held=True``).

        For a LIGHT/ACTIVE engagement only the minimal engagement audit stays until
        audit_retention_days after the case creation: the audit rows reduced to
        :data:`ENGAGEMENT_AUDIT_FIELDS` and re-sealed into a fresh hash chain closed by a
        :data:`PURGE_AUDIT_KIND` row (purged by, rows minimised, the previous chain head and whether
        it was intact), and the :data:`ENGAGEMENT_AUDIT_FILES` (the request ledger). Purging again
        after that date removes them. A directory left without a case row is purged too (its
        ledger, if any, follows the same audit retention). ``dry_run`` only counts.
        """
        case_id = str(case_id or "").strip()
        report = PurgeReport(case_id=case_id, dry_run=bool(dry_run))
        if not case_id:
            report.reason = "empty case id"
            return report
        current = self._now(now)
        with self._lock:
            conn = self._conn
            row = conn.execute(
                "SELECT id, created, legal_hold, hold_reason, engagement, report_paths FROM cases WHERE id = ?", (case_id,)
            ).fetchone()
            tomb = self.tombstone(case_id)
            report.found = row is not None
            report.previously_purged = str((tomb or {}).get("purged_at") or "")
            if row is not None and row["legal_hold"]:
                report.held = True
                report.reason = str(row["hold_reason"] or "")
                return report
            directory = paths.cases_dir() / case_id if _CASE_ID_RE.match(case_id) else None
            created = (row["created"] if row is not None else (tomb or {}).get("created")) or _created_from_id(case_id)
            if row is not None:
                engagement = bool(row["engagement"])
            elif tomb is not None:
                engagement = bool(tomb.get("audit_until"))
            else:  # a directory without a case row: a request ledger means LIGHT/ACTIVE contact happened
                engagement = directory is not None and any(os.path.lexists(directory / n) for n in ENGAGEMENT_AUDIT_FILES)
            keep_until = ""
            if engagement:
                base = _parse_iso(created) or current
                until = base + _dt.timedelta(days=self.audit_retention_days())
                if until > current:
                    keep_until = _iso(until)
            report.audit_until = keep_until
            counts: dict[str, int] = {}
            tables = _case_tables(conn)

            # -- database rows (counted first; removed below unless dry run)
            counts["cases"] = 1 if row is not None else 0
            for table in tables:
                counts[table] = int(conn.execute(f"SELECT COUNT(*) FROM {_quote_ident(table)} WHERE case_id = ?", (case_id,)).fetchone()[0])
            override_sql = (
                " FROM overrides WHERE finding_id IN (SELECT finding_id FROM case_findings WHERE case_id = ?)"
                " AND finding_id NOT IN (SELECT finding_id FROM case_findings WHERE case_id != ?)"
            )
            counts["overrides"] = int(conn.execute("SELECT COUNT(*)" + override_sql, (case_id, case_id)).fetchone()[0])
            audit = conn.execute("SELECT seq, ts, kind, payload, prev_hash, hash FROM audit WHERE case_id = ? ORDER BY seq", (case_id,)).fetchall()
            minimise = bool(keep_until and audit and row is not None)  # minimised once, when the case itself goes
            counts["audit"] = 0 if keep_until else len(audit)
            counts["audit_minimised"] = _minimisable(audit) if minimise else 0
            cache_keys = [r[0] for r in conn.execute("SELECT cache_key FROM case_cache_keys WHERE case_id = ?", (case_id,))]
            report_files = _unique_paths(
                _json_list(row["report_paths"]) if row is not None else [],
                [r[0] for r in conn.execute("SELECT path FROM report_hashes WHERE case_id = ?", (case_id,))],
            )

            # -- files
            keep_names = set(ENGAGEMENT_AUDIT_FILES) if keep_until else set()
            dir_files = _case_dir_files(directory, keep_names) if directory is not None else []
            outside, skipped = _report_files(report_files, case_id, directory)
            report.errors.extend(skipped)
            counts["files"] = len(dir_files)
            counts["report_files"] = len(outside)
            report.files = [str(p) for p in dir_files + outside]

            # -- HTTP cache rows and deferred quota lookups (other databases)
            cache = self._open_cache(report.errors) if cache_keys else None
            try:
                counts["cache_rows"] = cache.count_keys(cache_keys) if (cache is not None and cache_keys) else 0
                quota = self._open_quota(report.errors)
                try:
                    counts["deferred"] = quota.forget_case(case_id, dry_run=True) if quota is not None else 0
                    nothing = not any(counts.values()) and not (tomb and tomb.get("audit_until") and not keep_until)
                    if dry_run or nothing:
                        report.counts = {k: v for k, v in counts.items() if v}
                        if nothing and not report.found:
                            report.reason = "already purged" if tomb is not None else "not found"
                        return report

                    # -- remove: files first (a crash leaves rows that a new purge finishes), then rows
                    for p in dir_files + outside:
                        try:
                            os.unlink(p)
                        except FileNotFoundError:
                            pass
                        except OSError as exc:
                            report.errors.append(f"{p}: {exc.strerror or exc}")
                    if directory is not None:
                        _remove_empty_dirs(directory, report.errors)
                    if cache is not None and cache_keys:
                        try:
                            cache.delete_many(cache_keys)
                            if vacuum:
                                cache.vacuum()
                        except sqlite3.Error as exc:  # pragma: no cover - cache I/O problems are reported
                            report.errors.append(f"HTTP cache: {exc}")
                    if quota is not None and counts["deferred"]:
                        try:
                            quota.forget_case(case_id)
                        except sqlite3.Error as exc:  # pragma: no cover
                            report.errors.append(f"quota DB: {exc}")
                finally:
                    if quota is not None:
                        quota.close()
            finally:
                if cache is not None:
                    cache.close()

            with self.connection() as c:
                c.execute("DELETE" + override_sql, (case_id, case_id))
                for table in tables:
                    c.execute(f"DELETE FROM {_quote_ident(table)} WHERE case_id = ?", (case_id,))
                if not keep_until:
                    c.execute("DELETE FROM audit WHERE case_id = ?", (case_id,))
                elif minimise:
                    _minimise_audit(c, case_id, audit, by=str(by or "unknown"), stamp=_iso(current))
                c.execute("DELETE FROM cases WHERE id = ?", (case_id,))
                previous = (tomb or {}).get("counts") or {}
                merged = {k: int(previous.get(k, 0)) + int(counts.get(k, 0)) for k in sorted(set(previous) | set(counts))}
                merged = {k: v for k, v in merged.items() if v}
                if tomb is None:
                    c.execute(
                        "INSERT INTO tombstones (case_id, created, purged_at, purged_by, counts, audit_until) VALUES (?, ?, ?, ?, ?, ?)",
                        (case_id, created or None, _iso(current), str(by or "unknown"), json.dumps(merged, sort_keys=True), keep_until or None),
                    )
                else:
                    c.execute(
                        "UPDATE tombstones SET counts = ?, audit_until = ? WHERE case_id = ?",
                        (json.dumps(merged, sort_keys=True), keep_until or None, case_id),
                    )
            if vacuum:
                self.vacuum()
            report.counts = {k: v for k, v in counts.items() if v}
            report.purged = True
            return report

    def purge_older_than(
        self, days: float | None = None, *, by: str = "retention", dry_run: bool = False, now: _dt.datetime | None = None
    ) -> list[PurgeReport]:
        """Purge every case created more than ``days`` ago (default: setting retention_days; with the
        setting at 0 nothing is purged) through :meth:`purge_case`. Held cases are skipped and listed
        (``held=True``); engagement audits whose retention ended are removed too, and so are case
        directories older than ``days`` that have no case row (a crashed scan, a v1 delete) - only
        directories named like generated case ids, and only for the home's own case DB. One VACUUM
        at the end. Returns one report per case considered (abandoned directories only when there
        was something to remove)."""
        if days is None:
            days = self.retention_days()
            if days <= 0:
                return []
        if float(days) < 0:
            raise ValueError("days must be >= 0")
        current = self._now(now)
        cutoff = current - _dt.timedelta(days=float(days))
        with self._lock:
            rows = self._conn.execute("SELECT id, created, legal_hold, hold_reason FROM cases ORDER BY created").fetchall()
            expired_audits = [
                r[0]
                for r in self._conn.execute("SELECT case_id, audit_until FROM tombstones WHERE audit_until IS NOT NULL").fetchall()
                if (_parse_iso(r[1]) or current) <= current
            ]
        reports: list[PurgeReport] = []
        for r in rows:
            created = _parse_iso(r["created"])
            if created is None or created >= cutoff:
                continue
            if r["legal_hold"]:
                reports.append(PurgeReport(case_id=r["id"], found=True, dry_run=dry_run, held=True, reason=str(r["hold_reason"] or "")))
                continue
            reports.append(self.purge_case(r["id"], by=by, dry_run=dry_run, now=current, vacuum=False))
        done = {rep.case_id for rep in reports}
        for case_id in expired_audits:
            if case_id not in done:
                reports.append(self.purge_case(case_id, by=by, dry_run=dry_run, now=current, vacuum=False))
                done.add(case_id)
        for case_id in self._abandoned_case_dirs(cutoff):
            if case_id in done:
                continue
            rep = self.purge_case(case_id, by=by, dry_run=dry_run, now=current, vacuum=False)
            if rep.purged or rep.counts:
                reports.append(rep)
        if not dry_run and any(rep.purged for rep in reports):
            self.vacuum()
            if any(rep.counts.get("cache_rows") for rep in reports):
                cache = self._open_cache([])
                if cache is not None:
                    try:
                        cache.vacuum()
                    except sqlite3.Error:  # pragma: no cover - the rows are deleted (secure delete) already
                        pass
                    finally:
                        cache.close()
        return reports

    def _abandoned_case_dirs(self, cutoff: _dt.datetime) -> list[str]:
        """Case directories (named like generated case ids) created before ``cutoff`` that have no
        case row. Only for the home's own case DB: a store on another file never sweeps the home."""
        try:
            if os.path.realpath(self.path) != os.path.realpath(paths.db_file()):
                return []
            names = sorted(os.listdir(paths.cases_dir()))
        except OSError:
            return []
        with self._lock:
            known = {str(r[0]) for r in self._conn.execute("SELECT id FROM cases")}
        out: list[str] = []
        for name in names:
            if name in known:
                continue
            created = _parse_iso(_created_from_id(name))
            if created is not None and created < cutoff:
                out.append(name)
        return out

    def vacuum(self) -> None:
        """``PRAGMA secure_delete = ON`` + ``VACUUM`` (deleted case data is overwritten and the file
        rebuilt without free pages)."""
        with self._lock:
            if self._conn.in_transaction:
                self._conn.commit()
            self._conn.execute("PRAGMA secure_delete = ON")
            self._conn.execute("VACUUM")
        paths.restrict_file(self.path)

    def _open_cache(self, errors: list[str]) -> Any:
        """The HTTP cache the purge cleans (None when it does not exist; a cache that cannot be
        opened is reported in ``errors``: its rows of the case stay until cache_max_age_days)."""
        target = Path(self._cache_path) if self._cache_path else paths.cache_file()
        if not target.exists():
            return None
        from v3lum.core.cache import HttpCache

        try:
            return HttpCache(str(target))
        except (sqlite3.Error, OSError) as exc:
            errors.append(f"HTTP cache {target}: {exc} (the case's cache rows expire with cache_max_age_days)")
            return None

    def _open_quota(self, errors: list[str]) -> Any:
        """The quota DB holding the case's deferred lookups (None when it does not exist; a DB that
        cannot be opened is reported in ``errors``)."""
        from v3lum.core import quota as quota_mod

        target = Path(self._quota_path) if self._quota_path else quota_mod.default_path(self._settings_or_none())
        if not target.exists():
            return None
        try:
            return quota_mod.QuotaBook(target)
        except (sqlite3.Error, OSError) as exc:
            errors.append(f"quota DB {target}: {exc} (deferred lookups of the case not removed)")
            return None

    def _settings_or_none(self) -> Any:
        if self._settings is None:
            self.setting("retention_days")  # loads the Config once
        return self._settings

    # ------------------------------------------------------------------ verdicts (P325)
    def record_verdict(self, case_id: str, verdict: str, notes: str = "", *, analyst: str) -> dict[str, Any]:
        """Record the analyst's overall verdict on a stored case (P325): 'yes' | 'partial' | 'no' ('y',
        'p', 'n' and 'partially' are accepted). One verdict per case and analyst: a new one replaces
        the earlier one, so re-running ``cases feedback`` never double-counts. 'yes' credits no
        finding (explicit 'right' votes do, :meth:`vote`). ``notes`` are case data (configured key
        values masked), purged with the case (A10). Raises ValueError for another verdict or an
        unknown case. Returns the stored row."""
        word = _word(verdict)
        word = _VERDICT_ALIASES.get(word, word)
        if word not in VERDICTS:
            raise ValueError("verdict must be yes, partial or no")
        cid = str(case_id or "").strip()
        who = str(analyst or "").strip()
        text = _clean_note(notes, 2000)
        stamp = _iso(self._now())
        with self.connection() as conn:
            if conn.execute("SELECT 1 FROM cases WHERE id = ?", (cid,)).fetchone() is None:
                raise ValueError(f"unknown case {cid!r}: verdicts are recorded for stored cases only")
            conn.execute("DELETE FROM feedback WHERE case_id = ? AND analyst = ?", (cid, who))
            conn.execute(
                "INSERT INTO feedback (case_id, verdict, notes, created, analyst) VALUES (?,?,?,?,?)",
                (cid, word, text, stamp, who),
            )
        return {"case_id": cid, "verdict": word, "notes": text, "created": stamp, "analyst": who}

    def add_feedback(self, case_id: str, verdict: str, notes: str = "", *, analyst: str = "") -> None:
        """v1 entry point, now :meth:`record_verdict` (one verdict per case and analyst)."""
        self.record_verdict(case_id, verdict, notes, analyst=analyst)

    def feedback_for(self, case_id: str) -> list[dict[str, Any]]:
        """The verdicts recorded for a case: ``[{verdict, notes, created, analyst}]`` oldest first."""
        with self._lock:
            rows = self._conn.execute(
                "SELECT verdict, notes, created, analyst FROM feedback WHERE case_id = ? ORDER BY created, id", (case_id,)
            ).fetchall()
        return [dict(r) for r in rows]

    # ------------------------------------------------------------------ votes (P325)
    def vote(
        self,
        case_id: str,
        finding_id: str,
        *,
        analyst: str,
        vote: str,
        reason: str | None = None,
        source_id: str = "",
        rule_id: str = "",
        module: str = "",
    ) -> dict[str, Any]:
        """Record one explicit judgement on a finding or correlation of a stored case (P325 cond 2-4).

        ``vote`` is 'right' | 'wrong' | 'partly' ('partly' counts 0.5); ``reason`` (wrong/partly only)
        one of :data:`VOTE_REASONS` ('benign infra' and 'wrong type' spellings accepted), kept for
        tuning. Idempotent per (case, deterministic item id, analyst): an UPSERT whose earlier
        contribution is removed from the aggregates before the new one is added, in one
        transaction, so a repeated ``cases feedback`` never double-counts. ``source_id`` (registry
        source), ``rule_id`` (correlation rule) and ``module`` default to the item's ``source`` /
        ``rule`` / ``module`` in the stored case (a finding without a source falls back to the
        module's only declared source). The aggregates are the monthly buckets of ``source_stats``
        and ``rule_stats`` and the module counters of ``module_stats``; the module's vote totals go
        to the A3 demotion state (``HealthState.record_votes``). The entity verdicts of the case's
        sightings rows are refreshed. Raises ValueError for an unknown case, an item that is not in
        it, or an invalid vote/reason. Returns the stored vote."""
        choice = _word(vote)
        if choice not in VOTE_SCORES:
            raise ValueError("vote must be right, wrong or partly")
        why = _vote_reason(reason)
        if why and choice == "right":
            raise ValueError("a reason is recorded for 'wrong' or 'partly' votes only")
        cid = str(case_id or "").strip()
        fid = str(finding_id or "").strip()
        if not cid or not fid:
            raise ValueError("a vote needs a case id and a finding (or correlation) id")
        who = str(analyst or "").strip()
        stamp = _iso(self._now())
        with self.connection() as conn:
            if not conn.in_transaction:  # read the earlier vote and write the new one under one write lock
                conn.execute("BEGIN IMMEDIATE")
            case = self._case_json(conn, cid)
            if case is None:
                raise ValueError(f"unknown case {cid!r}: votes are recorded for stored cases only")
            item = _case_item(case, fid)
            if item is None:
                raise ValueError(f"{fid!r} is not a finding or correlation of case {cid}")
            mod = str(module or item.get("module") or "").strip()
            src = str(source_id or item.get("source") or "").strip() or _single_source(mod)
            rid = str(rule_id or item.get("rule") or "").strip()
            old = conn.execute(
                "SELECT vote, source_id, rule_id, created FROM finding_votes WHERE case_id = ? AND finding_id = ? AND analyst = ?",
                (cid, fid, who),
            ).fetchone()
            if old is not None:
                self._count_vote(conn, source_id=str(old["source_id"] or ""), rule_id=str(old["rule_id"] or ""), module=mod,
                                 vote=str(old["vote"]), created=old["created"], sign=-1)
            conn.execute(
                "INSERT INTO finding_votes (case_id, finding_id, analyst, vote, reason, source_id, rule_id, created)"
                " VALUES (?, ?, ?, ?, ?, ?, ?, ?) ON CONFLICT(case_id, finding_id, analyst) DO UPDATE SET"
                " vote = excluded.vote, reason = excluded.reason, source_id = excluded.source_id,"
                " rule_id = excluded.rule_id, created = excluded.created",
                (cid, fid, who, choice, why, src, rid, stamp),
            )
            self._count_vote(conn, source_id=src, rule_id=rid, module=mod, vote=choice, created=stamp, sign=1)
            self._reindex(conn, cid)
        self._record_health(mod)
        return {"case_id": cid, "finding_id": fid, "analyst": who, "vote": choice, "reason": why, "source_id": src,
                "rule_id": rid, "module": mod, "created": stamp}

    def votes_for(self, case_id: str) -> list[dict[str, Any]]:
        """The votes of a case: ``[{finding_id, analyst, vote, reason, source_id, rule_id, created}]``."""
        with self._lock:
            rows = self._conn.execute(
                "SELECT finding_id, analyst, vote, reason, source_id, rule_id, created FROM finding_votes"
                " WHERE case_id = ? ORDER BY created, finding_id, analyst",
                (case_id,),
            ).fetchall()
        return [dict(r) for r in rows]

    def flag_finding(self, case_id: str, finding_id: str, module: str, correct: bool) -> None:
        """v1 entry point, now idempotent: one 'right'/'wrong' :meth:`vote` of the unnamed analyst ('')
        plus the v1 ``finding_feedback`` row (replaced, never duplicated)."""
        self.vote(case_id, finding_id, analyst="", vote="right" if correct else "wrong", module=module)
        with self.connection() as conn:
            conn.execute("DELETE FROM finding_feedback WHERE case_id = ? AND finding_id = ?", (case_id, finding_id))
            conn.execute(
                "INSERT INTO finding_feedback (case_id, finding_id, module, correct, created) VALUES (?,?,?,?,?)",
                (case_id, finding_id, module, 1 if correct else 0, _iso(self._now())),
            )

    def _count_vote(self, conn: sqlite3.Connection, *, source_id: str, rule_id: str, module: str, vote: str, created: Any, sign: int) -> None:
        """Add (sign 1) or remove (sign -1) one vote's contribution to the aggregates: the monthly
        bucket of its source and of its rule (the month it was cast) and its module's counters."""
        score = VOTE_SCORES.get(str(vote or ""))
        if score is None:
            return
        stamp = _iso(self._now())
        month = _month_of(created) or _month_of(stamp)
        for table, column, base in (("source_stats", "source_id", source_id), ("rule_stats", "rule_id", rule_id)):
            if not base:
                continue
            key = f"{base}{BUCKET_SEP}{month}"
            if sign > 0:
                conn.execute(
                    f"INSERT INTO {table} ({column}, alpha, beta, votes, updated) VALUES (?, ?, ?, 1, ?)"
                    f" ON CONFLICT({column}) DO UPDATE SET alpha = alpha + excluded.alpha, beta = beta + excluded.beta,"
                    " votes = votes + 1, updated = excluded.updated",
                    (key, score, 1.0 - score, stamp),
                )
            else:
                conn.execute(
                    f"UPDATE {table} SET alpha = MAX(0, alpha - ?), beta = MAX(0, beta - ?), votes = votes - 1, updated = ? WHERE {column} = ?",
                    (score, 1.0 - score, stamp, key),
                )
                conn.execute(f"DELETE FROM {table} WHERE {column} = ? AND votes <= 0", (key,))
        if module:
            if sign > 0:
                conn.execute(
                    "INSERT INTO module_stats (module, correct, wrong) VALUES (?, ?, ?)"
                    " ON CONFLICT(module) DO UPDATE SET correct = correct + excluded.correct, wrong = wrong + excluded.wrong",
                    (module, score, 1.0 - score),
                )
            else:
                conn.execute(
                    "UPDATE module_stats SET correct = MAX(0, correct - ?), wrong = MAX(0, wrong - ?) WHERE module = ?",
                    (score, 1.0 - score, module),
                )

    def _health_state(self) -> Any:
        """The A3 health state the vote totals go to (None: not recorded for this store)."""
        if self._health is False:
            return None
        if self._health is not None:
            return self._health
        try:
            home_db = os.path.realpath(self.path) == os.path.realpath(paths.db_file())
        except OSError:
            home_db = False
        if not home_db:
            self._health = False
            return None
        try:
            from v3lum.core.health import HealthState

            self._health = HealthState.load()
        except Exception as exc:  # noqa: BLE001 - demotion bookkeeping never breaks feedback
            log.warning("health state unavailable: %s", type(exc).__name__)
            self._health = False
            return None
        return self._health

    def _record_health(self, module: str) -> None:
        """Hand a module's current vote totals to the A3 demotion state (> 30% wrong after >= 10
        votes): ``wrong`` = wrong votes ('partly' counts half), ``total`` = every vote."""
        if not module:
            return
        state = self._health_state()
        if state is None:
            return
        with self._lock:
            row = self._conn.execute("SELECT correct, wrong FROM module_stats WHERE module = ?", (module,)).fetchone()
        if row is None:
            return
        correct, wrong = float(row["correct"] or 0), float(row["wrong"] or 0)
        bad = max(0, int(math.floor(wrong + 1e-9)))
        total = max(bad, int(round(correct + wrong)))
        try:
            state.record_votes(module, bad, total, now=self._now())
        except Exception as exc:  # noqa: BLE001
            log.warning("health votes of %s not recorded: %s", module, type(exc).__name__)

    # ------------------------------------------------------------------ reliability (P325 cond 3)
    def _weighted_stats(self, kind: str, now: _dt.datetime) -> dict[str, dict[str, float]]:
        """``{id: {alpha, beta, votes}}`` of the sources ('source') or rules ('rule') at ``now``: the
        monthly buckets weighted by :func:`bucket_weight` (legacy keys by the age of ``updated``),
        corrected to the exact :func:`vote_weight` of the votes still on record."""
        table, column = ("source_stats", "source_id") if kind == "source" else ("rule_stats", "rule_id")
        with self._lock:
            rows = self._conn.execute(f"SELECT {column} AS k, alpha, beta, votes, updated FROM {table}").fetchall()
            live = self._conn.execute(f"SELECT {column} AS k, vote, created FROM finding_votes WHERE {column} != ''").fetchall()
        out: dict[str, dict[str, float]] = {}
        for r in rows:
            base, sep, month = str(r["k"] or "").partition(BUCKET_SEP)
            if not base:
                continue
            weight = bucket_weight(month, now) if sep else vote_weight(r["updated"], now)
            entry = out.setdefault(base, {"alpha": 0.0, "beta": 0.0, "votes": 0.0})
            entry["alpha"] += weight * max(0.0, float(r["alpha"] or 0))
            entry["beta"] += weight * max(0.0, float(r["beta"] or 0))
            entry["votes"] += max(0, int(r["votes"] or 0))
        for r in live:  # votes on record: exact age instead of their month's
            entry = out.get(str(r["k"] or ""))
            score = VOTE_SCORES.get(str(r["vote"] or ""))
            if entry is None or score is None:
                continue
            delta = vote_weight(r["created"], now) - bucket_weight(_month_of(r["created"]), now)
            if delta:
                entry["alpha"] = max(0.0, entry["alpha"] + delta * score)
                entry["beta"] = max(0.0, entry["beta"] + delta * (1.0 - score))
        return out

    def source_reliability(self, now: _dt.datetime | None = None) -> dict[str, float]:
        """``{source_id: weight}`` for every registry source with votes (P325 cond 3; the P302 R_SRC
        that replaces the Admiralty prior): :func:`beta_weight` of the Admiralty prior of the source's
        provider (A 1.0, B 0.85, C 0.7, D 0.5, E 0.3, F 0.5; strength 4) and the age-weighted votes
        ('partly' 0.5; votes older than 12 months weigh half). The weight equals the prior until the
        source has 5 votes and never falls below 0.3. Sources without votes are absent (use the
        Admiralty prior). Purged cases keep counting through the aggregates (A10)."""
        current = self._now(now)
        out: dict[str, float] = {}
        for sid, entry in self._weighted_stats("source", current).items():
            if entry["votes"] <= 0:
                continue
            _grade, prior = admiralty_prior(sid)
            out[sid] = round(beta_weight(prior, entry["alpha"], entry["beta"], int(entry["votes"])), 4)
        return dict(sorted(out.items()))

    def source_stats(self, now: _dt.datetime | None = None) -> list[dict[str, Any]]:
        """One row per source with votes: ``{source_id, grade, prior, votes, alpha, beta, weight,
        active}`` (``alpha``/``beta`` age-weighted; ``active`` = the weight moved off the prior: at
        least 5 votes). Feeds ``feedback_summary`` and doctor."""
        current = self._now(now)
        rows: list[dict[str, Any]] = []
        for sid, entry in sorted(self._weighted_stats("source", current).items()):
            if entry["votes"] <= 0:
                continue
            grade, prior = admiralty_prior(sid)
            votes = int(entry["votes"])
            rows.append({
                "source_id": sid, "grade": grade, "prior": prior, "votes": votes,
                "alpha": round(entry["alpha"], 3), "beta": round(entry["beta"], 3),
                "weight": round(beta_weight(prior, entry["alpha"], entry["beta"], votes), 4), "active": votes >= MIN_VOTES,
            })
        return rows

    def rule_precision(self, now: _dt.datetime | None = None) -> dict[str, tuple[float, int]]:
        """``{rule_id: (precision, votes)}`` of the correlation rules with votes (P325 cond 6; feeds the
        P301 per-rule demotion, WP22): precision = age-weighted 'right' share ('partly' 0.5, votes
        older than 12 months weigh half), rounded to 3 decimals; ``votes`` = the number of votes.
        Consumers apply their own minimum (e.g. >= 10 votes before demoting)."""
        current = self._now(now)
        out: dict[str, tuple[float, int]] = {}
        for rid, entry in self._weighted_stats("rule", current).items():
            total = entry["alpha"] + entry["beta"]
            if entry["votes"] <= 0 or total <= 0:
                continue
            out[rid] = (round(entry["alpha"] / total, 3), int(entry["votes"]))
        return dict(sorted(out.items()))

    def feedback_summary(self) -> dict[str, Any]:
        """``{verdicts: {verdict: n}, modules: [{module, correct, wrong, reliability}], sources:
        [source_stats rows], rules: [{rule_id, precision, votes}]}`` (v1 keys kept)."""
        with self._lock:
            verdicts = dict(self._conn.execute("SELECT verdict, COUNT(*) FROM feedback GROUP BY verdict").fetchall())
            mods = [dict(r) for r in self._conn.execute("SELECT module, correct, wrong FROM module_stats ORDER BY wrong DESC, module").fetchall()]
        for m in mods:
            m["reliability"] = round(reliability_from(m["correct"], m["wrong"]), 3)
        rules = [{"rule_id": rid, "precision": p, "votes": n} for rid, (p, n) in self.rule_precision().items()]
        return {"verdicts": verdicts, "modules": mods, "sources": self.source_stats(), "rules": rules}

    def reliability(self) -> dict[str, float]:
        """The v1 module view ``{module: weight}`` (``reliability_from`` of the vote counters)."""
        with self._lock:
            rows = self._conn.execute("SELECT module, correct, wrong FROM module_stats").fetchall()
        return {r["module"]: reliability_from(r["correct"], r["wrong"]) for r in rows}

    # ------------------------------------------------------------------ analyst overrides (P322)
    def set_override(
        self,
        finding_id: str,
        *,
        analyst: str,
        label: Any = None,
        severity: Any = None,
        verdict: str | None = None,
        note: str = "",
        case_id: str = "",
    ) -> dict[str, Any]:
        """Store an analyst decision on a finding, keyed by its deterministic id (P322 cond 3).

        ``label`` confirmed | probable | possible; ``severity`` info..critical; ``verdict`` a short
        word (e.g. right | wrong | malicious | benign | false_positive); ``note`` free text (case
        data, configured key values masked). One decision per (finding, analyst): fields given again
        replace the earlier ones, fields left out keep them. The finding must belong to a stored case
        (``case_id`` when given, else any case): an override of a finding no stored case contains
        would outlive every purge. Analyst decisions always win and survive re-runs: the same
        finding id in a later case gets them through :meth:`overrides_for` (:class:`OverrideHook`).
        The entity verdicts of the cases holding the finding are refreshed. Returns the merged
        override of the finding (:meth:`overrides_for` form). Raises ValueError for invalid values,
        an empty decision or an unknown finding."""
        from v3lum.core.models import Confidence, Severity

        fid = str(finding_id or "").strip()
        if not fid:
            raise ValueError("an override needs a finding id")
        who = str(analyst or "").strip()
        lab = Confidence.from_value(label).value if label not in (None, "") else None
        try:
            sev = Severity.parse(severity).label if severity not in (None, "") else None
        except (KeyError, ValueError):
            raise ValueError(f"invalid severity {str(severity)[:40]!r} (info, low, medium, high or critical)") from None
        ver = _override_verdict(verdict) if verdict not in (None, "") else None
        text = _clean_note(note, 500)
        if lab is None and sev is None and ver is None and not text:
            raise ValueError("an override needs a label, a severity, a verdict or a note")
        stamp = _iso(self._now())
        cid = str(case_id or "").strip()
        with self.connection() as conn:
            if cid:
                if conn.execute("SELECT 1 FROM case_findings WHERE case_id = ? AND finding_id = ?", (cid, fid)).fetchone() is None:
                    raise ValueError(f"{fid!r} is not a finding of case {cid}")
            elif conn.execute("SELECT 1 FROM case_findings WHERE finding_id = ? LIMIT 1", (fid,)).fetchone() is None:
                raise ValueError(f"no stored case contains finding {fid!r}: overrides are kept for stored findings only")
            conn.execute(
                "INSERT INTO overrides (finding_id, analyst, label, severity, verdict, note, created) VALUES (?, ?, ?, ?, ?, ?, ?)"
                " ON CONFLICT(finding_id, analyst) DO UPDATE SET label = COALESCE(excluded.label, overrides.label),"
                " severity = COALESCE(excluded.severity, overrides.severity), verdict = COALESCE(excluded.verdict, overrides.verdict),"
                " note = CASE WHEN excluded.note != '' THEN excluded.note ELSE overrides.note END, created = excluded.created",
                (fid, who, lab, sev, ver, text, stamp),
            )
            for (holder,) in conn.execute("SELECT case_id FROM case_findings WHERE finding_id = ? ORDER BY case_id", (fid,)).fetchall():
                self._reindex(conn, str(holder))
        return self.overrides_for([fid]).get(fid, {})

    def overrides_for(self, finding_ids: Iterable[str]) -> dict[str, dict[str, Any]]:
        """``{finding_id: {label, severity, verdict, analyst, note, at}}`` - the stored analyst
        decisions of the given ids (missing ids are absent), the keyword arguments of
        ``Finding.apply_override``. Decisions of several analysts merge in time order: a later
        decision replaces the fields it sets; ``analyst``/``at`` name the latest one."""
        ids = sorted({str(i).strip() for i in (finding_ids or ()) if i and str(i).strip()})
        rows: list[Any] = []
        with self._lock:
            for start in range(0, len(ids), 500):
                chunk = ids[start:start + 500]
                marks = ",".join("?" * len(chunk))
                rows += self._conn.execute(
                    f"SELECT finding_id, analyst, label, severity, verdict, note, created FROM overrides WHERE finding_id IN ({marks})", chunk
                ).fetchall()
        out: dict[str, dict[str, Any]] = {}
        for r in sorted(rows, key=lambda r: (str(r["created"] or ""), str(r["analyst"] or ""))):
            merged = out.setdefault(str(r["finding_id"]), {"label": None, "severity": None, "verdict": None, "analyst": "", "note": "", "at": ""})
            for name in ("label", "severity", "verdict"):
                if r[name]:
                    merged[name] = str(r[name])
            if r["note"]:
                merged["note"] = str(r["note"])
            merged["analyst"] = str(r["analyst"] or "")
            merged["at"] = str(r["created"] or "")
        return out

    # ------------------------------------------------------------------ sightings (P375)
    def index_case(self, case: Mapping[str, Any], *, org: Any = None) -> int:
        """(Re)build the sightings index rows of one stored case (P375 cond 1-4; :meth:`save_case`
        calls it; a case that is not stored gets no rows - 0): IOC_TYPES by entity key, PERSONAL_TYPES only as the keyed HMAC and only with
        setting ``sightings_personal`` on and a case purpose (A4), no noise entity and no own org
        asset (``org`` = an OrgProfile; default: the configured profile), the case TLP, the
        engagement flag and each entity's verdict (:func:`sighting_rows`). Returns the number of
        rows."""
        with self.connection() as conn:
            return self._index_case(conn, case, org=org)

    def reindex_sightings(self) -> int:
        """Rebuild the sightings index of every stored case (after enabling sightings_personal, a
        changed org profile or noise lists, or for cases stored before the index existed - the
        store runs it once when it upgrades a case DB that had cases but no index). A case whose
        index cannot be built keeps its previous rows (logged); the others are still indexed.
        Returns the number of rows written."""
        with self._lock:
            ids = [str(r[0]) for r in self._conn.execute("SELECT id FROM cases ORDER BY created, id")]
        org = self._org_profile()
        total = 0
        for cid in ids:
            with self.connection() as conn:
                case = self._case_json(conn, cid)
                if case is not None:
                    total += self._index_safely(conn, case, org=org)
        return total

    def sightings_for(self, entity: Any, *, case_id: str = "", case_tlp: str = "") -> SightingsSummary:
        """Earlier cases in which ``entity`` (Entity or 'type:value') appeared, as the case ``case_id``
        at TLP ``case_tlp`` may see them (P375, A2) - the ``runtime.meta['sightings_lookup']``
        protocol of the policy guard and the case_sightings module.

        * a case sees sightings only from cases with TLP <= ``case_tlp`` (``visible``: id, date,
          entity verdict, TLP and the analyst's case verdict); higher non-RED, non-engagement cases
          are only counted (``restricted_count``: no ids, dates or verdicts); RED cases and
          LIGHT/ACTIVE engagement cases above ``case_tlp`` never surface. An empty or unreadable
          ``case_tlp`` is read as CLEAR (fail closed: the least is visible);
        * PERSONAL_TYPES are looked up by their keyed HMAC and only while setting
          ``sightings_personal`` is on; types outside IOC_TYPES/PERSONAL_TYPES have no sightings;
        * ``case_id`` itself is never listed. Read only: findings are never copied across cases.
        """
        from v3lum.core.entities import IOC_TYPES, PERSONAL_TYPES

        ent = _entity_of(entity)
        if ent is None:
            return SightingsSummary()
        if ent.type in PERSONAL_TYPES:
            if not _truthy(self.setting("sightings_personal", False)):
                return SightingsSummary()
            try:
                digest = hmacid.hmac_hex(ent.type, ent.value)
            except Exception:  # noqa: BLE001 - no secret: personal values are never matched in clear
                return SightingsSummary()
            where, args = "entity_key = '' AND entity_hmac = ?", (digest,)
        elif ent.type in IOC_TYPES:
            where, args = "entity_key = ?", (ent.key,)
        else:
            return SightingsSummary()
        viewer = _viewer_tlp(case_tlp)
        with self._lock:
            rows = self._conn.execute(
                f"SELECT case_id, case_tlp, engagement, created, verdict FROM sightings WHERE {where} AND case_id != ?",
                (*args, str(case_id or "").strip()),
            ).fetchall()
        per_case: dict[str, dict[str, Any]] = {}
        for r in rows:
            cid = str(r["case_id"])
            level = _row_tlp(r["case_tlp"])
            info = per_case.setdefault(cid, {"tlp": level, "engagement": False, "created": str(r["created"] or ""), "verdict": ""})
            info["tlp"] = max(info["tlp"], level)
            info["engagement"] = info["engagement"] or bool(r["engagement"])
            info["verdict"] = _worse_verdict(info["verdict"], str(r["verdict"] or ""))
        visible_ids: list[str] = []
        restricted = 0
        for cid, info in per_case.items():
            if info["tlp"] <= viewer:
                visible_ids.append(cid)
            elif info["tlp"] >= _tlp.TLP.RED or info["engagement"]:
                continue  # never surfaces in a lower-TLP case (A2)
            else:
                restricted += 1
        verdicts = self._case_verdicts(visible_ids)
        visible = [
            {
                "case_id": cid,
                "created": per_case[cid]["created"],
                "verdict": per_case[cid]["verdict"],
                "tlp": per_case[cid]["tlp"].value_str,
                "case_verdict": verdicts.get(cid, ""),
            }
            for cid in visible_ids
        ]
        visible.sort(key=lambda v: (v["created"], v["case_id"]), reverse=True)
        return SightingsSummary(visible=visible, restricted_count=restricted)

    def _case_verdicts(self, case_ids: Iterable[str]) -> dict[str, str]:
        """The latest analyst verdict (any analyst) of each case."""
        ids = sorted({str(c) for c in case_ids if c})
        out: dict[str, str] = {}
        with self._lock:
            for start in range(0, len(ids), 500):
                chunk = ids[start:start + 500]
                marks = ",".join("?" * len(chunk))
                for r in self._conn.execute(
                    f"SELECT case_id, verdict FROM feedback WHERE case_id IN ({marks}) ORDER BY created, id", chunk
                ).fetchall():
                    out[str(r["case_id"])] = str(r["verdict"] or "")
        return out

    def _index_case(self, conn: sqlite3.Connection, case: Mapping[str, Any], *, org: Any = None) -> int:
        case_id = str(case.get("case_id") or "").strip()
        if not case_id:
            return 0
        if conn.execute("SELECT 1 FROM cases WHERE id = ?", (case_id,)).fetchone() is None:
            # only stored cases are indexed: rows of a case without a case row would escape the
            # retention purge (A10) and surface a case nobody can open
            conn.execute("DELETE FROM sightings WHERE case_id = ?", (case_id,))
            return 0
        options = case.get("options") if isinstance(case.get("options"), Mapping) else {}
        purpose = str(options.get("purpose") or case.get("purpose") or "").strip()
        personal = _truthy(self.setting("sightings_personal", False)) and bool(purpose)
        overrides, votes = self._case_decisions(conn, case)
        rows = sighting_rows(case, personal=personal, org=org if org is not None else self._org_profile(), overrides=overrides, votes=votes)
        conn.execute("DELETE FROM sightings WHERE case_id = ?", (case_id,))
        conn.executemany(_SIGHTINGS_INSERT, rows)
        return len(rows)

    def _index_safely(self, conn: sqlite3.Connection, case: Mapping[str, Any], *, org: Any = None) -> int:
        """:meth:`_index_case` inside the caller's transaction, isolated by a savepoint: a failure
        keeps the previous index rows of the case (logged; 0 rows) and never fails the caller."""
        conn.execute("SAVEPOINT v3lum_sightings")
        try:
            return self._index_case(conn, case, org=org)
        except Exception as exc:  # noqa: BLE001 - the case itself must still be saved
            conn.execute("ROLLBACK TO v3lum_sightings")
            log.warning("sightings index of case %s not updated: %s", str(case.get("case_id") or "?")[:64], type(exc).__name__)
            return 0
        finally:
            conn.execute("RELEASE v3lum_sightings")

    def _reindex(self, conn: sqlite3.Connection, case_id: str) -> None:
        case = self._case_json(conn, case_id)
        if case is not None:
            self._index_safely(conn, case)

    def _case_decisions(self, conn: sqlite3.Connection, case: Mapping[str, Any]) -> tuple[dict[str, dict[str, Any]], dict[str, str]]:
        """(overrides of the case's item ids, latest vote per item of the case)."""
        ids = [
            str(item.get("id"))
            for group in ("findings", "correlations")
            for item in case.get(group) or ()
            if isinstance(item, Mapping) and item.get("id")
        ]
        overrides = self.overrides_for(ids)
        votes: dict[str, str] = {}
        rows = conn.execute(
            "SELECT finding_id, vote FROM finding_votes WHERE case_id = ? ORDER BY created, analyst", (str(case.get("case_id") or ""),)
        ).fetchall()
        for r in rows:
            votes[str(r["finding_id"])] = str(r["vote"] or "")
        return overrides, votes

    @staticmethod
    def _case_json(conn: sqlite3.Connection, case_id: str) -> dict[str, Any] | None:
        row = conn.execute("SELECT data FROM cases WHERE id = ?", (case_id,)).fetchone()
        if row is None:
            return None
        try:
            data = json.loads(row["data"] or "{}")
        except ValueError:
            return {"case_id": case_id}
        if not isinstance(data, dict):
            return {"case_id": case_id}
        data.setdefault("case_id", case_id)
        return data

    def _org_profile(self) -> Any:
        """The organisation profile (own assets are never indexed); None when there is none or it
        cannot be read."""
        try:
            from v3lum.core import orgprofile

            profile = orgprofile.load_default(self._settings_or_none())
        except Exception as exc:  # noqa: BLE001 - recorded ownership still applies
            log.debug("org profile unavailable for the sightings index: %s", type(exc).__name__)
            return None
        return None if getattr(profile, "is_empty", True) else profile


def _needs_sightings_backfill(conn: sqlite3.Connection) -> bool:
    """Whether the case DB holds cases but no sightings index yet (a pre-v2 database about to be
    migrated): the store then indexes the stored cases once after the migration."""
    try:
        tables = {str(r[0]) for r in conn.execute("SELECT name FROM sqlite_master WHERE type = 'table'")}
        return "cases" in tables and "sightings" not in tables and conn.execute("SELECT 1 FROM cases LIMIT 1").fetchone() is not None
    except sqlite3.Error:
        return False


def reliability_from(correct: int, wrong: int) -> float:
    """Laplace-smoothed precision, scaled so an unknown module weighs 1.0 and a bad one ~0.3."""
    precision = (correct + 2) / (correct + wrong + 2)  # starts at 1.0 with no data
    return max(0.3, min(1.0, precision))


# ======================================================================================
# helpers of the case DB v2 API
# ======================================================================================


def _clean_note(text: Any, limit: int) -> str:
    """Analyst free text as stored: stripped, configured key values masked, at most ``limit`` chars."""
    value = str(text or "").strip()
    if not value:
        return ""
    try:
        from v3lum.core import redact

        value = redact.redact_text(value)
    except Exception:  # noqa: BLE001 - the redactor never blocks a note
        pass
    return value[:limit]


def _vote_reason(reason: Any) -> str | None:
    """A :data:`VOTE_REASONS` member (spaces/hyphens accepted) or None; ValueError otherwise."""
    if reason in (None, ""):
        return None
    word = _word(reason).replace(" ", "_").replace("-", "_")
    if word not in VOTE_REASONS:
        raise ValueError(f"reason must be one of {', '.join(VOTE_REASONS)}")
    return word


def _override_verdict(verdict: Any) -> str:
    """An override verdict as stored: one short lower-case word ('false positive' -> 'false_positive')."""
    word = _word(verdict).replace(" ", "_").replace("-", "_")
    if not _OVERRIDE_VERDICT_RE.match(word):
        raise ValueError(f"invalid override verdict {str(verdict)[:40]!r} (one word: right, wrong, malicious, benign, false_positive...)")
    return word


def _case_item(case: Mapping[str, Any], item_id: str) -> dict[str, str] | None:
    """``{module, source, rule}`` of a finding or correlation of a stored case (None when absent)."""
    for item in case.get("findings") or ():
        if isinstance(item, Mapping) and str(item.get("id") or "") == item_id:
            return {"module": str(item.get("module") or ""), "source": str(item.get("source") or ""), "rule": ""}
    for item in case.get("correlations") or ():
        if isinstance(item, Mapping) and str(item.get("id") or "") == item_id:
            return {"module": "", "source": "", "rule": str(item.get("rule") or "")}
    return None


def _single_source(module: str) -> str:
    """The only registry source a registered module declares ('' when it declares none or several)."""
    if not module:
        return ""
    try:
        from v3lum.core.module import REGISTRY

        cls = REGISTRY.get(module)
    except Exception:  # noqa: BLE001
        return ""
    sources = tuple(getattr(cls, "sources", ()) or ()) if cls is not None else ()
    return str(sources[0]) if len(sources) == 1 else ""


def _viewer_tlp(value: Any) -> _tlp.TLP:
    """TLP of the case asking for sightings; empty or unreadable -> CLEAR (fail closed: sees least)."""
    try:
        return _tlp.parse(value) if value not in (None, "") else _tlp.TLP.CLEAR
    except ValueError:
        return _tlp.TLP.CLEAR


def _row_tlp(value: Any) -> _tlp.TLP:
    """TLP of an indexed case; empty or unreadable -> RED (fail closed: never surfaces lower)."""
    try:
        return _tlp.parse(value) if value not in (None, "") else _tlp.TLP.RED
    except ValueError:
        return _tlp.TLP.RED


def _worse_verdict(a: str, b: str) -> str:
    """The more severe of two sighting verdicts (:data:`SIGHTING_VERDICTS` order; '' loses)."""
    for verdict in SIGHTING_VERDICTS:
        if verdict in (a, b):
            return verdict
    return a or b


def apply_overrides(findings: Iterable[Any], overrides: Mapping[str, Mapping[str, Any]]) -> int:
    """Apply stored analyst decisions (:meth:`Store.overrides_for` output) to ``Finding`` objects by
    deterministic id through ``Finding.apply_override`` (analyst decisions always win, P322 cond 3);
    returns how many findings got one. Applying the same decision twice changes nothing."""
    applied = 0
    for finding in findings:
        ensure = getattr(finding, "ensure_id", None)
        fid = ensure() if callable(ensure) else str(getattr(finding, "id", "") or "")
        decision = overrides.get(fid) if fid else None
        if not decision:
            continue
        finding.apply_override(
            label=decision.get("label") or None,
            severity=decision.get("severity") or None,
            verdict=decision.get("verdict") or None,
            analyst=str(decision.get("analyst") or ""),
            note=str(decision.get("note") or ""),
            at=str(decision.get("at") or ""),
        )
        applied += 1
    return applied


class OverrideHook:
    """Runtime case hook (``runtime.case_hooks``) that re-applies stored analyst overrides on re-runs.

    ``on_before_finish(case)`` runs after the BFS and before the engine's suppression stage,
    correlation rules and scoring: every finding whose deterministic id has a stored decision
    (:meth:`Store.overrides_for`) gets it through ``Finding.apply_override``, so the analyst's
    decision wins and survives a re-run (P322 cond 3). A failing lookup leaves the findings as they
    are (the engine records a case note).
    """

    def __init__(self, store: Store) -> None:
        self.store = store

    def on_before_finish(self, case: Any) -> None:
        findings = list(getattr(case, "findings", None) or ())
        if findings:
            ids = [f.ensure_id() if callable(getattr(f, "ensure_id", None)) else str(getattr(f, "id", "")) for f in findings]
            apply_overrides(findings, self.store.overrides_for(ids))


# ======================================================================================
# file helpers of the purge
# ======================================================================================


def _case_dir_files(directory: Path, keep: set[str]) -> list[Path]:
    """Every file and symbolic link under the case directory (links are never followed), except
    the top-level ``keep`` names. A case directory that is itself a link counts as one entry."""
    if not os.path.lexists(directory):
        return []
    if os.path.islink(directory):
        return [directory]
    out: list[Path] = []
    for dirpath, dirnames, filenames in os.walk(directory, followlinks=False):
        here = Path(dirpath)
        for name in filenames:
            if here == directory and name in keep:
                continue
            out.append(here / name)
        for name in dirnames:
            candidate = here / name
            if os.path.islink(candidate):  # a linked directory: remove the link, never its target
                out.append(candidate)
    return sorted(out)


def _remove_empty_dirs(directory: Path, errors: list[str]) -> None:
    if not os.path.isdir(directory) or os.path.islink(directory):
        return
    for dirpath, _dirnames, _filenames in os.walk(directory, topdown=False, followlinks=False):
        try:
            os.rmdir(dirpath)
        except FileNotFoundError:
            pass
        except OSError as exc:
            if os.listdir(dirpath):
                continue  # kept engagement audit files (or a file that could not be removed)
            errors.append(f"{dirpath}: {exc.strerror or exc}")


def _report_files(report_paths: list[str], case_id: str, directory: Path | None) -> tuple[list[Path], list[str]]:
    """Recorded report files outside the case directory to remove (and their ``.sha256``
    sidecars). Only regular files or links whose name contains the case id are removed: a damaged
    or forged record can never point the purge at an unrelated file."""
    inside = os.path.realpath(directory) if directory is not None else None
    out: list[Path] = []
    skipped: list[str] = []
    for text in report_paths:
        p = Path(text)
        candidates = [p, Path(text + ".sha256")]
        for candidate in candidates:
            if not os.path.lexists(candidate):
                continue
            if inside is not None and os.path.realpath(candidate.parent).startswith(inside + os.sep):
                continue  # removed with the case directory
            if inside is not None and os.path.realpath(candidate.parent) == inside:
                continue
            if case_id not in candidate.name:
                skipped.append(f"{candidate}: recorded for the case but its name does not contain the case id (not removed)")
                continue
            try:
                mode = os.lstat(candidate).st_mode
            except OSError:
                continue
            if stat.S_ISREG(mode) or stat.S_ISLNK(mode):
                out.append(candidate)
            else:
                skipped.append(f"{candidate}: not a regular file (not removed)")
    unique: list[Path] = []
    seen: set[str] = set()
    for item in out:
        if str(item) not in seen:
            seen.add(str(item))
            unique.append(item)
    return unique, skipped
