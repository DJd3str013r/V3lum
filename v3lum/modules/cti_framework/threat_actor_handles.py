"""Threat-actor handle lookup in scraped forum user lists (P195, batch p2-G05-2).

Offline, disclosure ``none``: the spmedia Threat-Actor-Usernames-Scrape lists (MIT; ~1.1 M handles
in 26 per-forum files) are downloaded by ``v3lum data update`` (weekly, never during a scan: the set
is larger than 5 MB) and matched locally. The handle never leaves the machine.

Final conditions:

* cond 1 - one registered dataset per list file (``threat_actor_handles.<file stem>``, provider
  source ``github.threat_actor_handles_spmedia``, licence MIT, ``large=True``) plus the README (scrape
  date ranges). The lookup streams each local list once per run: the file text is NFC-normalised and
  case-folded and searched for the exact line, so no 1.1 M-entry set is ever held in memory. The
  SQLite index at refresh time named by the council needs a dataset-manager hook (core request); the
  streamed exact match is the interim, memory-bounded equivalent. default_enabled False (opt-in).
* cond 2 - the threatactorusernames.com API is not in this build (unknown tier, no terms; A8).
* cond 3 - exact, case-folded match only; handles shorter than 5 characters, purely numeric or on
  the bundled common-username/first-name list are skipped; dictionary words are labelled 'common
  handle: low signal' (``v3lum/data/threat_actor_handles/*.txt``, V3LUM-authored lists).
* cond 4 - a hit is one INFO finding 'a user with the same handle appears on forum lists: X, Y
  (scrape date)', confidence POSSIBLE (0.3), 'handle collision likely', tags ``weak_signal`` and
  ``context_only`` (never scored, never counted by CR27), no pivots and no identity link.
* cond 5 - runs only on analyst-typed usernames and threat_actor entities (``run_on='seeds'``) and
  never on an identifier derived from an org_profile identity (the local part of an own-domain e-mail,
  an org public-members list) unless the seed is marked as an insider case
  (``ScanOptions.subject_roles[seed] == 'insider'``) with a recorded purpose.
* cond 6 - reports show only the matched handle, forum names and list date; the lists are never
  exported, cited only by name and SHA-256.
"""

from __future__ import annotations

import re
import unicodedata
from pathlib import Path
from typing import Any

from v3lum.core.datasets import DatasetError, DatasetUnavailable, register_dataset
from v3lum.core.entities import Entity
from v3lum.core.entities import EntityType as T
from v3lum.core.models import ModuleResult, Opsec
from v3lum.core.module import HealthCheck, HealthResult, Module, register

__all__ = [
    "CONFIDENCE",
    "DATASET_PREFIX",
    "MIN_LENGTH",
    "README_DATASET",
    "SOURCE",
    "ThreatActorHandles",
    "dataset_name",
    "handle_decision",
    "lists_manifest",
    "lookup_in_text",
    "missing_upstream_lists",
    "normalise_handle",
    "provenance_block",
]

SOURCE = "github.threat_actor_handles_spmedia"
RAW = "https://raw.githubusercontent.com/spmedia/Threat-Actor-Usernames-Scrape/main/{file}"
DATASET_PREFIX = "threat_actor_handles."
README_DATASET = "threat_actor_handles.readme"
MANIFEST = "threat_actor_handles/lists.json"
COMMON_LIST = "threat_actor_handles/common_handles.txt"
DICTIONARY_LIST = "threat_actor_handles/dictionary_words.txt"
MIN_LENGTH = 5  # cond 3
CONFIDENCE = 0.3  # cond 4: POSSIBLE
ATTRIBUTION = "spmedia/Threat-Actor-Usernames-Scrape (MIT, Edmond Major III)"
TITLE = "Same handle on scraped forum user lists"
COLLISION_NOTE = "handle collision likely: a shared handle is a weak signal and never identifies a person"
#: provenance relations that come from an organisation identity (cond 5)
ORG_IDENTITY_RELATIONS = frozenset({"email_local_part", "org_member", "org_public_member"})
_FILE_RE = re.compile(r"^(?:dead_|z_dead_)?(?:forum|dnm)_users_[A-Za-z0-9_.-]+\.txt$")


def dataset_name(file_name: str) -> str:
    """'forum_users_xss.txt' -> 'threat_actor_handles.forum_users_xss'."""
    return DATASET_PREFIX + file_name[:-4] if file_name.endswith(".txt") else DATASET_PREFIX + file_name


def _manifest_path() -> Path:
    return Path(__file__).resolve().parents[2] / "data" / MANIFEST


def _manifest_doc() -> dict[str, Any]:
    import json

    try:
        doc = json.loads(_manifest_path().read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return {}
    return doc if isinstance(doc, dict) else {}


def lists_manifest() -> list[dict[str, Any]]:
    """The bundled per-list manifest of the lists available upstream (file, forum, title, status, dates)."""
    return [item for item in _manifest_doc().get("lists") or []
            if isinstance(item, dict) and isinstance(item.get("file"), str) and _FILE_RE.match(item["file"])]


def missing_upstream_lists() -> list[dict[str, Any]]:
    """README-linked lists that answered 404 upstream: not registered, reported as not covered."""
    return [item for item in _manifest_doc().get("missing_upstream") or [] if isinstance(item, dict) and item.get("file")]


def _validate_list(path: Path) -> bool:
    """register_dataset(validate=): a plain one-handle-per-line text, never an HTML page."""
    head = Path(path).read_bytes()[:4096]
    if b"<html" in head.lower() or b"<!doctype" in head.lower():
        raise ValueError("an HTML page instead of a username list")
    if not head.strip():
        raise ValueError("empty list")
    return True


def _validate_readme(path: Path) -> bool:
    text = Path(path).read_text(encoding="utf-8", errors="replace")[:65536]
    if "users_" not in text:
        raise ValueError("not the Threat-Actor-Usernames-Scrape README (no list file links)")
    return True


register_dataset(
    README_DATASET,
    RAW.format(file="README.md"),
    ttl=7 * 86400,
    description="spmedia Threat-Actor-Usernames-Scrape README: per-list scrape date ranges (P195 cond 4)",
    licence="MIT",
    terms_class="open",
    attribution=ATTRIBUTION,
    provider="github",
    source=SOURCE,
    validate=_validate_readme,
    min_bytes=200,
    expect="text",
    max_bytes=1_000_000,
    large=True,
)
for _item in lists_manifest():
    register_dataset(
        dataset_name(_item["file"]),
        RAW.format(file=_item["file"]),
        ttl=7 * 86400,
        description=f"spmedia forum username list: {_item.get('title') or _item['file']} ({_item.get('status') or 'status unknown'}; P195)",
        licence="MIT",
        terms_class="open",
        attribution=ATTRIBUTION,
        provider="github",
        source=SOURCE,
        validate=_validate_list,
        min_bytes=1,
        expect="text",
        max_bytes=20_000_000,
        large=True,  # A6 BR9: the whole set is > 5 MB: refreshed by `v3lum data update`, never mid-scan
    )


def normalise_handle(value: Any) -> str | None:
    """cond 3: exact, case-folded key (NFC + casefold + strip); inner spaces and a leading '#' are kept."""
    if not isinstance(value, str):
        return None
    text = unicodedata.normalize("NFC", value).strip()
    if not text or "\x00" in text or "\n" in text or "�" in text or len(text) > 256:
        return None
    return text.casefold()


def _word_list(text: str) -> frozenset[str]:
    return frozenset(line.strip().casefold() for line in text.splitlines() if line.strip() and not line.lstrip().startswith("#"))


def handle_decision(key: str, common: frozenset[str], dictionary: frozenset[str]) -> tuple[bool, str | None]:
    """cond 3: (query?, label-or-reason). Skip < 5 characters, purely numeric or common usernames/first
    names; dictionary words run with the label 'common handle: low signal'."""
    if len(key) < MIN_LENGTH:
        return False, f"handle shorter than {MIN_LENGTH} characters: too many collisions"
    if key.isdigit():
        return False, "purely numeric handle: too many collisions"
    if key in common:
        return False, "common username or first name: a match says nothing"
    if key in dictionary:
        return True, "common handle: low signal"
    return True, None


def lookup_in_text(raw: bytes | str, key: str) -> bool:
    """cond 1/3: exact case-folded line match over one list, without building a set of its lines."""
    text = raw.decode("utf-8", "replace") if isinstance(raw, (bytes, bytearray)) else str(raw)
    if text.startswith("﻿"):
        text = text[1:]
    folded = unicodedata.normalize("NFC", text.replace("\r\n", "\n").replace("\r", "\n")).casefold()
    folded = re.sub(r"[ \t]+\n", "\n", re.sub(r"\n[ \t]+", "\n", "\n" + folded + "\n"))
    return f"\n{key}\n" in folded


def provenance_block(ctx: Any) -> str | None:
    """cond 5: why an identifier derived from an org_profile identity may not be queried (None = allowed)."""
    steps = tuple(getattr(ctx, "provenance", ()) or ())
    org = getattr(ctx, "org", None)
    reasons: list[str] = []
    for step in steps:
        parent, relation = (step[0], step[1]) if isinstance(step, (tuple, list)) and len(step) >= 2 else ("", "")
        if relation in ORG_IDENTITY_RELATIONS:
            reasons.append(f"derived through '{relation}'")
        parent_type, _, parent_value = str(parent).partition(":")
        if parent_type == "email" and org is not None:
            try:
                own = bool(org.owns(Entity.make(T.EMAIL, parent_value)).own)
            except (ValueError, AttributeError, TypeError):
                own = False
            if own:
                reasons.append("derived from an own-domain e-mail")
    if not reasons:
        return None
    options = getattr(ctx, "options", None)
    roles = dict(getattr(options, "subject_roles", {}) or {})
    root = str(steps[0][0]) if steps and isinstance(steps[0], (tuple, list)) and steps[0] else str(getattr(getattr(ctx, "entity", None), "key", ""))
    if roles.get(root) == "insider" and str(getattr(ctx, "purpose", "") or "").strip():
        return None
    return "; ".join(sorted(set(reasons))) + ": an org_profile identity is never checked against forum lists outside an insider case with a recorded purpose (P195 cond 5)"


def _selftest(ctx: Any) -> HealthResult:
    """Offline: how many lists are present locally."""
    present = sum(1 for item in lists_manifest() if ctx.data.info(dataset_name(item["file"])).present)
    total = len(lists_manifest())
    if present == 0:
        return HealthResult("dead", f"no forum list downloaded: run v3lum data update ({total} lists)")
    return HealthResult("ok", f"{present}/{total} forum lists present")


@register
class ThreatActorHandles(Module):
    name = "threat_actor_handles"
    title = "Handle on scraped threat-actor forum lists"
    description = (
        "Offline exact match of an analyst-typed handle against the spmedia scraped forum user lists (XSS, Dread, "
        "HackForums, Cracked, BreachForums...): a weak signal, handle collisions are common."
    )
    category = "cti_framework"
    accepts = {T.USERNAME, T.THREAT_ACTOR}
    produces = frozenset()
    run_on = "seeds"
    tags = {"offline", "free"}
    reference = "https://github.com/spmedia/Threat-Actor-Usernames-Scrape"
    notice = (
        "Weak signal: the same handle on a forum list does not identify a person (benign 'octocat' is on two carding forums). "
        "Never run on employees' handles outside an insider case with a recorded purpose. The lists stay local and are "
        "never exported."
    )
    terms = "open"
    opsec = Opsec.PASSIVE
    disclosure = "none"  # matched locally: the handle never leaves the machine
    hosts = ()
    sources = (SOURCE,)
    access_model = "offline"
    max_requests = 0
    expected_latency = 1.5
    timeout = 60.0
    max_pivots = 0
    default_enabled = False  # cond 1: opt-in per scan

    @classmethod
    def health_check(cls) -> HealthCheck:
        return HealthCheck(offline=True, selftest=_selftest)

    def run(self, entity: Entity, ctx: Any) -> ModuleResult:
        res = self.result(entity)
        if not getattr(ctx, "is_seed", True):
            return res.mark("skipped", "runs only on analyst-typed usernames and threat_actor entities (P195 cond 5)",
                            reason_code="privacy")
        blocked = provenance_block(ctx)
        if blocked:
            return res.mark("skipped", blocked, reason_code="privacy")
        key = normalise_handle(str(entity.value).lstrip("@") if entity.type is T.USERNAME else str(entity.value))
        if not key:
            return res.mark("skipped", "not a handle that can be matched exactly", reason_code="not_applicable")
        common = _word_list(ctx.data.bundled_text(COMMON_LIST))
        dictionary = _word_list(ctx.data.bundled_text(DICTIONARY_LIST))
        query, label = handle_decision(key, common, dictionary)
        if not query:
            return res.mark("skipped", f"{label} (P195 cond 3)", reason_code="not_applicable")
        lists = lists_manifest()
        if not lists:
            return res.mark("error", "the bundled forum list manifest is missing or unreadable")
        readme_dates = self._readme_dates(ctx)
        hits: list[dict[str, Any]] = []
        missing: list[str] = []
        unavailable: DatasetUnavailable | None = None
        checked = 0
        for item in lists:
            name = dataset_name(item["file"])
            try:
                path = ctx.data.fetch(name)
                found = lookup_in_text(Path(path).read_bytes(), key)
            except DatasetUnavailable as exc:
                unavailable = unavailable or exc
                missing.append(item.get("title") or item["file"])
                continue
            except (DatasetError, OSError) as exc:
                ctx.log(f"forum list {item['file']} unreadable ({str(exc)[:120]})", "warning")
                missing.append(item.get("title") or item["file"])
                continue
            checked += 1
            if found:
                hits.append(self._hit(ctx, item, name, readme_dates))
        if checked == 0 and unavailable is not None:
            raise unavailable  # never downloaded: UNAVAILABLE 'dataset' ('run v3lum data update')
        if checked == 0:
            return res.mark("error", "could not verify: no forum list could be read")
        gone = missing_upstream_lists()
        res.raw = {"lists_checked": checked, "lists_missing": len(missing), "lists_missing_upstream": len(gone), "matches": len(hits)}
        if missing:
            res.source_status(SOURCE, "unavailable", reason_code="dataset",
                              reason=f"{len(missing)} forum list(s) not available locally: run v3lum data update")
        if not hits:
            res.error = (f"handle not on the {checked} local forum list(s)" + (f"; {len(missing)} list(s) missing: could not verify those" if missing else "")
                         + (f"; {len(gone)} dead-forum list(s) are gone upstream and not covered" if gone else ""))
            return res.mark("empty")
        if label:
            res.attr("collision_reason", label)
        res.attr("forum_handle_lists", hits)
        shown = ", ".join(f"{h['title']} ({h['list_date'] or 'date unknown'})" for h in hits)
        res.finding(
            TITLE,
            "info",
            f"a user with the same handle appears on forum lists: {shown}. {COLLISION_NOTE}."
            + (f" Label: {label}." if label else "")
            + (f" {len(missing)} list(s) were not available locally." if missing else "")
            + (f" {len(gone)} dead-forum list(s) are gone upstream and not covered." if gone else ""),
            confidence=CONFIDENCE,
            criterion="exact case-folded match of the analyst-typed handle on scraped forum user lists (spmedia, MIT); "
            "collisions are common, so this is context only",
            data={"handle": key, "forums": [h["forum"] for h in hits], "lists_checked": checked},
            tags=["weak_signal", "context_only", "high_collision"] if label else ["weak_signal", "context_only"],
            source=SOURCE,
        )
        return res

    @staticmethod
    def _hit(ctx: Any, item: dict[str, Any], name: str, readme_dates: dict[str, str]) -> dict[str, Any]:
        list_date = item.get("date_end") if not item.get("ongoing") else None
        if not list_date:
            info = ctx.data.info(name)
            list_date = str(getattr(info, "fetched_at", "") or "")[:10] or None  # ongoing list: the local copy's date
        return {"forum": item.get("forum"), "title": item.get("title") or item.get("forum"), "status": item.get("status"),
                "list_date": list_date, "date_range": readme_dates.get(item["file"]) or item.get("date_range")}

    @staticmethod
    def _readme_dates(ctx: Any) -> dict[str, str]:
        """Scrape date ranges from the local README copy when present (never downloaded mid-scan)."""
        try:
            if not ctx.data.info(README_DATASET).present:
                return {}
            text = ctx.data.fetch_text(README_DATASET)
        except (DatasetError, OSError, ValueError):
            return {}
        out: dict[str, str] = {}
        current = None
        for line in text.splitlines()[:5000]:
            m = re.match(r"^\*\*\[([^\]]+\.txt)\]\(", line.strip())
            if m:
                current = m.group(1)
                continue
            d = re.match(r"^\*\*Date Range of scrape:\*\*\s*(.+)$", line.strip())
            if d and current:
                dates = re.findall(r"\b(?:[A-Z][a-z]{2,8}\.? \d{1,2},? \d{4}|[A-Z][a-z]{2,8} \d{4}|\d{1,2}/\d{1,2}/\d{2,4}|current date|\d{4})\b", d.group(1))
                out[current] = " to ".join(dates[:2]) if dates else ""
                current = None
        return out
