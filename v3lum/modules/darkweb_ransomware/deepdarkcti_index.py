"""deepdarkCTI source index: onion leak sites, forums, markets and Telegram channels -> groups (P198).

Final conditions (P198):

* cond 1 - offline module (disclosure ``none``): the deepdarkCTI markdown lists are downloaded weekly at
  run time only through the dataset manager (GPL-3.0 data: never vendored; attribution in the notice
  fragment ``v3lum/data/notices/deepdarkcti.json``, A6). Seven lists yield onion hosts or t.me handles:
  ransomware_gang, forum, markets, maas, exploits, telegram_threat_actors, telegram_infostealer.
* cond 2 - :func:`parse_markdown_table` is a tolerant reader for ``|Name|Status|...`` tables (rows
  without a leading pipe, 2-8 cells, a status shifted one cell, a name fused with its status, a cut
  last line); malformed rows are skipped and counted. A parse below the expected row/entry floor marks
  the dataset unhealthy (the download is refused by its validator and the previous copy is kept; a
  local copy that fails the floor reads 'unhealthy' in ``feed_status``), never empty. P357 (Telegram
  watch) reuses :func:`parse_ddc_list` on its own copy of the two Telegram lists.
* cond 3 - only v3 onion hosts (checksum, core validator P217) and public t.me handles are indexed
  (onion host / Telegram handle -> group and category); each entry keeps its Status column and the
  list's repository commit date (GitHub REST commits API, a registered dataset per list).
* cond 4 - a match reads 'listed in deepdarkCTI as <category> of <group> (status ONLINE/OFFLINE, list
  date <commit date>)': medium for an active entry of a fresh list, info otherwise, confidence
  POSSIBLE (context, not attribution); OFFLINE/seized/expired entries or a list older than 180 days
  are labelled historical.
* cond 5 - listed addresses are hostile-tagged (``suspicious``), rendered defanged and never fetched:
  this module has no network at all; group pivots are ``expand=False``. Onion inputs pass the Ahmia
  banned-list filter first (P199 cond 2-3, :mod:`onion_safety`).

The tables also hold leak-site credentials (User:Password column) and actor contact e-mails/Tox IDs in
misaligned columns: :func:`parse_ddc_list` keeps only the indexed key, the group name, the status and
the row number - nothing else of a row ever leaves the parser.
"""

from __future__ import annotations

import html
import re
import threading
import unicodedata
from datetime import date
from pathlib import Path
from typing import Any

from v3lum.core.datasets import DatasetError, DatasetUnavailable, register_dataset
from v3lum.core.entities import Entity, defang
from v3lum.core.entities import EntityType as T
from v3lum.core.models import ModuleResult, Opsec
from v3lum.core.module import Module, register
from v3lum.core.validators import onion_valid
from v3lum.modules.darkweb_ransomware.onion_safety import (
    AHMIA_SOURCE,
    add_banned_finding,
    banned_hashes,
    fetch_dataset,
    is_banned_onion,
    onion_ban_hashes,
    onion_service_domain,
)

SOURCE_LISTS = "github.deepdarkcti_index_lists"
SOURCE_COMMITS = "github.deepdarkcti_index_commits"
LIST_URL = "https://raw.githubusercontent.com/fastfire/deepdarkCTI/main/{name}.md"
COMMIT_URL = "https://api.github.com/repos/fastfire/deepdarkCTI/commits?path={name}.md&per_page=1"
REPO_URL = "https://github.com/fastfire/deepdarkCTI"
ATTRIBUTION = "deepdarkCTI by fastfire (github.com/fastfire/deepdarkCTI), GPL-3.0, downloaded at run time"
WEEK = 7 * 86400
#: a list whose newest commit is older than this is labelled historical (P198 cond 4)
STALE_AFTER_DAYS = 180
MAX_MATCH_FINDINGS = 20
HOSTILE_NOTE = "hostile infrastructure listed by deepdarkCTI: never visited automatically (shown defanged)"

#: list -> (category of a site, category of a contact column, category of an index/tracker row, tag)
LISTS: dict[str, tuple[str, str, str, str]] = {
    "ransomware_gang": ("ransomware leak site", "ransomware gang contact channel", "ransomware tracker/index site", "ransomware"),
    "telegram_threat_actors": ("Telegram threat-actor channel", "Telegram threat-actor channel", "Telegram threat-actor channel", "cybercrime"),
    "telegram_infostealer": ("Telegram infostealer channel", "Telegram infostealer channel", "Telegram infostealer channel", "infostealer"),
    "forum": ("cybercrime forum", "cybercrime forum Telegram channel", "cybercrime forum", "cybercrime"),
    "markets": ("dark-web market", "dark-web market Telegram channel", "dark-web market", "darknet_market"),
    "maas": ("malware-as-a-service shop", "malware-as-a-service channel", "malware-as-a-service shop", "cybercrime"),
    "exploits": ("exploit source", "exploit source channel", "exploit source", "cybercrime"),
}
#: (min rows, min onion/t.me entries) per list: ~40% of the live counts of 2026-11-26 (P198 cond 2)
FLOORS: dict[str, tuple[int, int]] = {
    "ransomware_gang": (300, 200),
    "telegram_threat_actors": (400, 300),
    "telegram_infostealer": (50, 30),
    "forum": (150, 30),
    "markets": (70, 30),
    "maas": (5, 3),
    "exploits": (10, 1),
}

_CONTROL_RE = re.compile("[\x00-\x08\x0b-\x1f\x7f-\x9f​-‏‪-‮⁦-⁩]")
_ONION_V3_RE = re.compile(r"(?<![A-Za-z0-9])([A-Za-z2-7]{56})\.onion(?![A-Za-z0-9-])", re.I)
_ONION_V2_RE = re.compile(r"(?<![A-Za-z0-9])([A-Za-z2-7]{16})\.onion(?![A-Za-z0-9-])", re.I)
_STATUS_RE = re.compile(r"^\W*(ONLINE|OFFLINE|OFFILINE|OFLINE|VALID|EXPIRED|PRIVATE|SEIZED|SIEZED|REBRANDED|REDIRECT\b[^|]*|DOWN|CLOSED)\b", re.I)
_MD_LINK_RE = re.compile(r"\[(?P<text>[^\]\n]*)\]\((?P<url>[^)\s]*)\)?")
_URL_RE = re.compile(r"https?://[^\s|<>\"'\])]+", re.I)
_TG_RE = re.compile(r"(?:https?://)?(?:www\.)?(?:t\.me|telegram\.me|telegram\.dog)/(?P<path>[^\s|<>\"'\])]*)", re.I)
_TG_HANDLE_RE = re.compile(r"[A-Za-z][A-Za-z0-9_]{3,31}")
_TG_RESERVED = frozenset({
    "s", "c", "joinchat", "addstickers", "addemoji", "addtheme", "share", "proxy", "socks", "iv", "login", "setlanguage",
    "bg", "invoice", "boost", "contact", "confirmphone", "addlist", "m",
})
_FUSED_STATUS_RE = re.compile(r"\)\s*(ONLINE|OFFLINE|OFFILINE|VALID|EXPIRED|PRIVATE|SEIZED)\b\s*$", re.I)
_DETAIL_RE = re.compile(r"^[A-Za-z0-9 ,.'/&-]{1,60}$")
_INDEX_ROW_RE = re.compile(r"monitoring|tracker|group sites", re.I)


# ------------------------------------------------------------------ small helpers
def safe_plain(value: Any, limit: int = 200) -> str:
    """Plain single-line text: entities decoded, control/bidi characters removed, whitespace collapsed,
    capped at ``limit`` characters (untrusted text, AR13)."""
    if value is None:
        return ""
    text = _CONTROL_RE.sub(" ", html.unescape(str(value)))
    text = " ".join(text.split())
    return text if len(text) <= limit else text[: max(0, limit - 1)].rstrip() + "…"


def parse_day(value: Any) -> str | None:
    """ISO date/datetime string -> 'YYYY-MM-DD' (None otherwise)."""
    if not isinstance(value, str):
        return None
    m = re.match(r"\s*(\d{4})-(\d{2})-(\d{2})", value)
    if not m:
        return None
    try:
        return date(int(m.group(1)), int(m.group(2)), int(m.group(3))).isoformat()
    except ValueError:
        return None


def fold(text: Any) -> str:
    """Accent/case/punctuation-insensitive key ('LockBit 3.0' -> 'lockbit30')."""
    value = unicodedata.normalize("NFKD", str(text or ""))
    value = "".join(ch for ch in value if not unicodedata.combining(ch))
    return re.sub(r"[^a-z0-9]+", "", value.lower())


def defang_handle(handle: str) -> str:
    return f"t[.]me/{handle}"


# ------------------------------------------------------------------ status column
def normalize_status(raw: Any) -> dict[str, Any]:
    """Status cell -> {'status', 'detail', 'text', 'active'} (P198 cond 3/4).

    status: ONLINE, OFFLINE, VALID, EXPIRED, PRIVATE, SEIZED, REBRANDED, REDIRECT or UNKNOWN; live typos
    ('OFFILINE', 'Siezed') are folded. Only ONLINE (not parked) and VALID are active. The original text is
    kept only for a recognised status: an unrecognised cell may be a misaligned credential or contact
    column and is never kept.
    """
    text = safe_plain(raw, 160)
    upper = text.upper().strip("\"' ")
    m = re.search(r"\(([^)]*)\)?", text)
    detail = m.group(1).strip() if m else None
    if not upper:
        status = "UNKNOWN"
    elif "SEIZ" in upper or "SIEZ" in upper:
        status = "SEIZED"
    elif upper.startswith(("OFFLINE", "OFFILINE", "OFLINE")):
        status = "OFFLINE"
    elif upper.startswith("ONLINE"):
        status = "ONLINE"
    elif upper.startswith("VALID"):
        status = "VALID"
    elif upper.startswith("EXPIRED"):
        status = "EXPIRED"
    elif upper.startswith("PRIVATE"):
        status = "PRIVATE"
    elif "REBRANDED" in upper:
        status, detail = "REBRANDED", None
    elif upper.startswith("REDIRECT"):
        status, detail = "REDIRECT", None
    else:
        status = "UNKNOWN"
    if detail and (not _DETAIL_RE.match(detail) or re.fullmatch(r"(?i)\s*s(?:ei|ie)zed\s*", detail)):
        detail = None
    parked = bool(detail and "park" in detail.lower())
    return {
        "status": status,
        "detail": detail,
        "text": text if status != "UNKNOWN" else "",
        "active": status in ("ONLINE", "VALID") and not parked,
    }


# ------------------------------------------------------------------ tolerant markdown table reader
def split_md_row(line: str) -> list[str] | None:
    """'|a|b||' -> ['a', 'b', '']; tolerant to a missing leading/trailing pipe and escaped pipes; None for
    a line without any pipe."""
    text = str(line or "").strip()
    if "|" not in text:
        return None
    text = text.replace("\\|", "\x00")
    if text.startswith("|"):
        text = text[1:]
    if text.endswith("|"):
        text = text[:-1]
    return [cell.replace("\x00", "|").strip() for cell in text.split("|")]


def _is_separator(cells: list[str]) -> bool:
    return bool(cells) and all(re.fullmatch(r":?-{2,}:?", c) or c == "" for c in cells) and any("-" in c for c in cells)


def parse_markdown_table(text: str) -> dict[str, Any]:
    """Tolerant markdown table reader (P198 cond 2, shared with P357).

    Returns {'header': [...], 'rows': [{'row': n, 'cells': [...]}], 'skipped': {reason: count},
    'problem': None | 'empty' | 'html' | 'no_table'}. The header is the first pipe row followed by a
    separator row; rows without a leading pipe are accepted; a last line cut mid-row (no newline, no
    closing pipe) is skipped as 'truncated_row'.
    """
    body = str(text or "").lstrip("﻿")
    out: dict[str, Any] = {"header": [], "rows": [], "skipped": {}, "problem": None}
    if not body.strip():
        out["problem"] = "empty"
        return out
    head = body[:2048].lstrip().lower()
    if head.startswith(("<!doctype html", "<html")) or ("<head" in head and "<body" in head):
        out["problem"] = "html"
        return out
    lines = body.splitlines()
    header_at = None
    for i in range(len(lines) - 1):
        cells, nxt = split_md_row(lines[i]), split_md_row(lines[i + 1])
        if cells and nxt and _is_separator(nxt) and not _is_separator(cells):
            header_at = i
            out["header"] = cells
            break
    if header_at is None:
        out["problem"] = "no_table"
        return out
    ends_with_newline = body.endswith("\n")

    def skip(reason: str) -> None:
        out["skipped"][reason] = out["skipped"].get(reason, 0) + 1

    for i in range(header_at + 2, len(lines)):
        line = lines[i]
        if not line.strip():
            continue
        cells = split_md_row(line)
        if cells is None:
            skip("not_a_row")
            continue
        if _is_separator(cells):
            continue
        if i == len(lines) - 1 and not ends_with_newline and not line.rstrip().endswith("|"):
            skip("truncated_row")
            continue
        if not any(cells):
            skip("empty_row")
            continue
        out["rows"].append({"row": i + 1, "cells": cells})
    return out


def _columns(header: list[str]) -> tuple[str, dict[str, int | None]]:
    names = [safe_plain(h, 60).lower() for h in header]
    layout = "telegram" if names and names[0] == "telegram" else "name"
    cols: dict[str, int | None] = {"status": None, "actor": None, "type": None}
    for i, name in enumerate(names):
        if name == "status" and cols["status"] is None:
            cols["status"] = i
        elif layout == "telegram" and i > 0 and name in ("threat actor name", "name") and cols["actor"] is None:
            cols["actor"] = i
        elif layout == "telegram" and name.startswith("type") and cols["type"] is None:
            cols["type"] = i
    if cols["status"] is None:
        cols["status"] = 1
    return layout, cols


def split_name_qualifier(text: str) -> tuple[str, str | None]:
    """'LOCKBIT 2.0 (Dark mirror 1)' -> ('LOCKBIT 2.0', 'Dark mirror 1'); an unbalanced
    'DARKCLUB (Onion Site 2' (seen live) -> ('DARKCLUB', 'Onion Site 2')."""
    text = safe_plain(text, 160)
    if "(" not in text:
        return text, None
    base, _, rest = text.partition("(")
    qualifier = " ".join(rest.replace(")", " ").replace("(", " ").split()) or None
    return base.strip() or text, qualifier


def classify_telegram_path(path: str) -> tuple[str, str | None]:
    """t.me path -> ('handle', key) | ('invite', None) | ('private_link', None) | ('reserved', None) |
    ('invalid', None). Keys are lower-case handles."""
    path = str(path or "").split("?", 1)[0].split("#", 1)[0].strip("/")
    if not path:
        return "invalid", None
    if path.startswith("+") or path.lower().startswith("joinchat"):
        return "invite", None
    parts = path.split("/")
    first = parts[0]
    if first.lower() == "c":
        return "private_link", None
    if first.lower() == "s" and len(parts) > 1:
        first = parts[1]
    elif first.lower() in _TG_RESERVED:
        return "reserved", None
    if _TG_HANDLE_RE.fullmatch(first) and not first.endswith("_"):
        return "handle", first.lower()
    return "invalid", None


def telegram_key(value: Any) -> str | None:
    """'@Name', 'name', 't.me/name', 'https://t.me/s/name/12', 'telegram.me/name' -> 'name', else None
    (invites and private links have no public handle)."""
    text = str(value or "").strip()
    if not text:
        return None
    m = _TG_RE.search(text)
    if m:
        kind, key = classify_telegram_path(m.group("path"))
        return key if kind == "handle" else None
    text = text.lstrip("@")
    if _TG_HANDLE_RE.fullmatch(text) and not text.endswith("_") and text.lower() not in _TG_RESERVED:
        return text.lower()
    return None


def _status_cell(cells: list[str], cols: dict[str, int | None], layout: str) -> str:
    idx = int(cols["status"] or 1)
    cell = cells[idx] if idx < len(cells) else ""
    if _STATUS_RE.match(cell):
        return cell
    if not cell and idx + 1 < len(cells) and _STATUS_RE.match(cells[idx + 1]):
        return cells[idx + 1]
    if layout == "name" and cells:
        fused = _FUSED_STATUS_RE.search(cells[0])
        if fused:
            return fused.group(1)
    return cell


def parse_ddc_list(text: str, list_name: str, *, commit_date: str | None = None) -> dict[str, Any]:
    """One deepdarkCTI list -> index entries (P198 cond 2, 3, 5).

    Only valid v3 onion hosts and public t.me handles become entries; v2 onions, bad checksums,
    invite/private links and clearnet-only rows are counted in 'skipped'. Each entry keeps its Status
    and the list's commit date; nothing else of the row (credentials, contacts) is kept.
    """
    site_cat, contact_cat, index_cat, tag = LISTS.get(list_name, (list_name, list_name, list_name, "cybercrime"))
    table = parse_markdown_table(text)
    result: dict[str, Any] = {
        "list": list_name, "category": site_cat, "commit_date": parse_day(commit_date), "rows": len(table["rows"]),
        "entries": [], "skipped": dict(table["skipped"]), "problem": table["problem"],
    }
    if table["problem"]:
        return result
    layout, cols = _columns(table["header"])

    def skip(reason: str) -> None:
        result["skipped"][reason] = result["skipped"].get(reason, 0) + 1

    for row in table["rows"]:
        cells = row["cells"]
        first = cells[0] if cells else ""
        status = normalize_status(_status_cell(cells, cols, layout))
        if layout == "telegram":
            actor_i, type_i = cols["actor"], cols["type"]
            group = safe_plain(cells[actor_i], 120) if actor_i is not None and actor_i < len(cells) else ""
            group, qualifier = group or None, None
            attack = safe_plain(cells[type_i], 60) if type_i is not None and type_i < len(cells) else ""
            attack = attack or None
        else:
            links = list(_MD_LINK_RE.finditer(first))
            name_text = links[0].group("text") if links else _URL_RE.sub("", first)
            name, qualifier = split_name_qualifier(name_text)
            group, attack = name or None, None
        found: dict[tuple[str, str], str] = {}
        for pos, cell in enumerate(cells):
            if layout == "telegram" and pos == cols["status"]:
                continue
            role = ("channel" if layout == "telegram" else "site") if pos == 0 else "contact"
            for m in _ONION_V3_RE.finditer(cell):
                domain = f"{m.group(1).lower()}.onion"
                if onion_valid(domain):
                    found.setdefault(("onion", domain), role)
                else:
                    skip("onion_bad_checksum")
            for _m in _ONION_V2_RE.finditer(cell):
                skip("onion_v2")
            for m in _TG_RE.finditer(cell):
                kind, key = classify_telegram_path(m.group("path"))
                if kind == "handle" and key:
                    found.setdefault(("telegram", key), role)
                else:
                    skip(f"telegram_{kind}")
        if not found:
            skip("no_indexable_address")
            continue
        is_index = bool((qualifier and qualifier.lower() in ("list", "index")) or (group and _INDEX_ROW_RE.search(group)))
        for (kind, key), role in found.items():
            category = index_cat if is_index else (contact_cat if role == "contact" else site_cat)
            result["entries"].append({
                "kind": kind, "key": key, "display": defang(key) if kind == "onion" else defang_handle(key),
                "group": group, "qualifier": qualifier, "attack_type": attack, "category": category, "role": role,
                "index_row": is_index, "list": list_name, "list_tag": tag, "status": status["status"],
                "status_detail": status["detail"], "status_text": status["text"], "active": status["active"],
                "row": row["row"], "commit_date": result["commit_date"],
            })
    return result


def list_health(parsed: dict[str, Any]) -> str | None:
    """Why a parsed list is unhealthy (P198 cond 2: a parse below the floor is never 'empty'), or None."""
    name = parsed.get("list", "?")
    if parsed.get("problem"):
        return f"deepdarkCTI {name}.md is not a markdown table ({parsed['problem']})"
    min_rows, min_entries = FLOORS.get(name, (1, 1))
    rows, entries = parsed.get("rows", 0), len(parsed.get("entries", []))
    if rows < min_rows:
        return f"deepdarkCTI {name}.md parsed {rows} rows (< expected {min_rows}): unhealthy"
    if entries < min_entries:
        return f"deepdarkCTI {name}.md yielded {entries} onion/t.me entries (< expected {min_entries}): unhealthy"
    return None


def parse_commit_date(doc: Any) -> str | None:
    """GitHub REST commits answer (GET /repos/{o}/{r}/commits?path=<file>&per_page=1, a list, or one commit
    object) -> 'YYYY-MM-DD' of commit.committer.date. Author/committer names and e-mails are never read."""
    if isinstance(doc, list):
        doc = doc[0] if doc and isinstance(doc[0], dict) else None
    if not isinstance(doc, dict):
        return None
    commit = doc.get("commit") if isinstance(doc.get("commit"), dict) else {}
    for who in ("committer", "author"):
        part = commit.get(who) if isinstance(commit.get(who), dict) else {}
        day = parse_day(part.get("date"))
        if day:
            return day
    return None


def build_index(parsed_lists: list[dict[str, Any]]) -> dict[str, dict[str, list[dict[str, Any]]]]:
    """Merge parsed lists into {'onion': {key: [entries]}, 'telegram': {...}}; identical (group, category,
    status) duplicates of one key are merged. 30 live onions sit under two groups: every match is kept."""
    index: dict[str, dict[str, list[dict[str, Any]]]] = {"onion": {}, "telegram": {}}
    for parsed in parsed_lists:
        for entry in parsed.get("entries", []):
            bucket = index[entry["kind"]].setdefault(entry["key"], [])
            sig = (entry["group"], entry["category"], entry["status_text"])
            if not any((e["group"], e["category"], e["status_text"]) == sig for e in bucket):
                bucket.append(entry)
    return index


def match_wording(entry: dict[str, Any], today: str, *, fetched: str = "") -> tuple[str, bool, bool]:
    """P198 cond 4 wording -> (text, historical, stale)."""
    list_date = entry.get("commit_date")
    when = f"list date {list_date}" if list_date else (f"list date unknown, fetched {fetched}" if fetched else "list date unknown")
    reference = list_date or fetched
    stale = False
    if reference and today:
        try:
            stale = (date.fromisoformat(today) - date.fromisoformat(reference)).days > STALE_AFTER_DAYS
        except ValueError:
            stale = False
    historical = (not entry.get("active")) or stale
    subject = f"{entry['category']} of {entry['group']}" if entry.get("group") else entry["category"]
    status = entry.get("status") or "UNKNOWN"
    if entry.get("status_detail"):
        status = f"{status} ({entry['status_detail']})"
    text = f"listed in deepdarkCTI as {subject} (status {status}, {when})"
    if historical:
        text += "; historical entry" + (" (list older than 180 days)" if stale and entry.get("active") else "")
    return text, historical, stale


def group_matches(group: Any, query: str) -> bool:
    """Exact folded match, or the query plus a version suffix ('lockbit' ~ 'LOCKBIT 3.0')."""
    g, q = fold(group), fold(query)
    if not g or not q:
        return False
    return g == q or (g.startswith(q) and g[len(q):].isdigit())


def group_summary(index: dict[str, Any], name: str, *, banned: frozenset[str] | None, max_examples: int = 10) -> dict[str, Any] | None:
    """threat_actor/keyword input: what the lists hold for that group name. Examples are defanged and
    attributes only (P198 produces threat_actor, never onion pivots); onions on Ahmia's banned list are
    withheld, and every onion example is withheld when the banned list is unavailable (fail closed)."""
    summary: dict[str, Any] = {"group": safe_plain(name, 120), "onion": 0, "telegram": 0, "active": 0, "lists": [], "examples": []}
    withheld = 0
    for kind in ("onion", "telegram"):
        for key, entries in index.get(kind, {}).items():
            for entry in entries:
                if not group_matches(entry.get("group"), name):
                    continue
                summary[kind] += 1
                summary["active"] += 1 if entry.get("active") else 0
                if entry["list"] not in summary["lists"]:
                    summary["lists"].append(entry["list"])
                if kind == "onion" and (banned is None or any(h in banned for h in onion_ban_hashes(key))):
                    withheld += 1
                    continue
                if len(summary["examples"]) < max_examples and entry["display"] not in summary["examples"]:
                    summary["examples"].append(entry["display"])
    if not summary["onion"] and not summary["telegram"]:
        return None
    if withheld:
        summary["examples_withheld"] = withheld
    return summary


# ------------------------------------------------------------------ datasets (cond 1 and 3)
def list_dataset(name: str) -> str:
    return f"deepdarkcti_index_{name}"


def commit_dataset(name: str) -> str:
    return f"deepdarkcti_index_commit_{name}"


def _list_validator(name: str) -> Any:
    def validate(path: Path) -> bool:
        problem = list_health(parse_ddc_list(Path(path).read_text(encoding="utf-8", errors="replace"), name))
        if problem:
            raise ValueError(problem)
        return True

    return validate


def _commit_validator(path: Path) -> bool:
    import json

    try:
        doc = json.loads(Path(path).read_text(encoding="utf-8", errors="replace"))
    except ValueError as exc:
        raise ValueError("not a GitHub commits answer") from exc
    if parse_commit_date(doc) is None:
        raise ValueError("GitHub commits answer without a commit date")
    return True


for _name in LISTS:
    register_dataset(
        list_dataset(_name),
        LIST_URL.format(name=_name),
        ttl=WEEK,
        description=f"deepdarkCTI {_name}.md (GPL-3.0, weekly runtime download; P198 cond 1)",
        licence="GPL-3.0-only (runtime download, never bundled or modified)",
        terms_class="open",
        attribution=ATTRIBUTION,
        provider="github",
        source=SOURCE_LISTS,
        validate=_list_validator(_name),
        min_bytes=64,
        expect="text",
        max_bytes=2_000_000,
        large=False,
    )
    register_dataset(
        commit_dataset(_name),
        COMMIT_URL.format(name=_name),
        ttl=WEEK,
        description=f"deepdarkCTI {_name}.md newest commit (date only; P198 cond 3)",
        licence="GitHub REST API repository metadata of fastfire/deepdarkCTI (only the commit date is read)",
        terms_class="open",
        attribution=ATTRIBUTION,
        provider="github",
        source=SOURCE_COMMITS,
        validate=_commit_validator,
        min_bytes=2,
        expect="json",
        max_bytes=200_000,
        large=False,
    )

_MEMO: dict[str, tuple[tuple[str, str | None], dict[str, Any]]] = {}
_LOCK = threading.Lock()


def _commit_date(ctx: Any, name: str) -> str | None:
    try:
        return parse_commit_date(fetch_dataset(ctx, commit_dataset(name), "json"))
    except (DatasetError, DatasetUnavailable, OSError, ValueError):
        return None


def load_lists(ctx: Any) -> tuple[list[dict[str, Any]], dict[str, dict[str, Any]]]:
    """Parse the local lists (memoised per copy). Returns (healthy parsed lists, feed_status)."""
    parsed_lists: list[dict[str, Any]] = []
    feeds: dict[str, dict[str, Any]] = {}
    for name in LISTS:
        dataset = list_dataset(name)
        try:
            text = fetch_dataset(ctx, dataset, "text")
        except (DatasetError, DatasetUnavailable, OSError) as exc:
            feeds[name] = {"state": "missing", "reason": safe_plain(str(exc), 160)}
            continue
        info = ctx.data.info(dataset)
        commit = _commit_date(ctx, name)
        stamp = (info.sha256 or str(len(text)), commit)
        with _LOCK:
            cached = _MEMO.get(name)
        if cached is not None and cached[0] == stamp:
            parsed = cached[1]
        else:
            parsed = parse_ddc_list(text, name, commit_date=commit)
            with _LOCK:
                _MEMO[name] = (stamp, parsed)
        fetched = parse_day(info.fetched_at) or ""
        problem = list_health(parsed)
        if problem:
            feeds[name] = {"state": "unhealthy", "reason": problem, "fetched_at": fetched, "list_date": commit}
            continue
        feeds[name] = {
            "state": "stale" if info.stale else "ok", "age_hours": info.age_hours, "fetched_at": fetched,
            "list_date": commit, "rows": parsed["rows"], "entries": len(parsed["entries"]),
        }
        parsed_lists.append(parsed)
    return parsed_lists, feeds


@register
class DeepdarkctiIndex(Module):
    name = "deepdarkcti_index"
    title = "deepdarkCTI index (onion leak sites, forums, markets, Telegram channels)"
    description = (
        "Matches an onion host or a Telegram handle against the deepdarkCTI curated lists (downloaded weekly, "
        "matched offline) and names the group and category it is listed for; a group name shows what the lists hold "
        "for that group. Context, not attribution."
    )
    category = "darkweb_ransomware"
    accepts = {T.ONION, T.TELEGRAM_HANDLE, T.USERNAME, T.THREAT_ACTOR, T.KEYWORD}
    produces = {T.THREAT_ACTOR}
    tags = {"offline"}
    reference = REPO_URL
    notice = (
        "deepdarkCTI lists (GPL-3.0) are downloaded at run time and never bundled. Listed onion, Telegram and forum "
        "addresses are hostile infrastructure: shown defanged and never fetched. A listing is context, not attribution."
    )
    terms = "open"
    opsec = Opsec.PASSIVE
    disclosure = "none"  # the value never leaves the machine: lists come through the dataset manager
    hosts = ()
    sources = (SOURCE_LISTS, SOURCE_COMMITS, AHMIA_SOURCE)
    access_model = "offline"
    max_requests = 0
    expected_latency = 0.05
    max_pivots = 20
    default_enabled = True

    def applies(self, entity: Entity, ctx: Any) -> bool:
        return self._query(entity)[0] is not None

    @staticmethod
    def _query(entity: Entity) -> tuple[str | None, str | None]:
        if entity.type is T.ONION:
            domain = onion_service_domain(entity.value)
            return ("onion", domain) if domain else (None, None)
        if entity.type in (T.TELEGRAM_HANDLE, T.USERNAME):
            key = telegram_key(entity.value)
            return ("telegram", key) if key else (None, None)
        text = safe_plain(entity.value, 120)
        return ("group", text) if fold(text) else (None, None)

    def run(self, entity: Entity, ctx: Any) -> ModuleResult:
        res = self.result(entity)
        kind, key = self._query(entity)
        if kind is None or key is None:
            return res.mark("skipped", "not an onion v3 host, a public Telegram handle or a group name", reason_code="not_applicable")
        if kind == "onion":
            banned = is_banned_onion(entity.value, ctx)  # service domain and full host (subdomains) are tested
            if banned is None:  # P199 cond 2: no filter, no details (fail closed)
                return res.mark("unavailable", "Ahmia banned-onion list unavailable: onion details withheld (run v3lum data update ahmia_banned_onions)", reason_code="dataset")
            if banned:
                return add_banned_finding(res)
        parsed_lists, feeds = load_lists(ctx)
        if not parsed_lists:
            res.attr("feed_status", feeds)
            return res.mark("unavailable", "no usable deepdarkCTI list (run v3lum data update): could not verify", reason_code="dataset")
        index = build_index(parsed_lists)
        today = ctx.now().date().isoformat()
        if kind == "group":
            return self._group(res, ctx, index, key, feeds)
        return self._match(res, kind, key, index, feeds, today, entity)

    # ------------------------------------------------------------------ onion / Telegram matches
    def _match(self, res: ModuleResult, kind: str, key: str, index: dict[str, Any], feeds: dict[str, Any], today: str, entity: Entity) -> ModuleResult:
        entries = index.get(kind, {}).get(key, [])
        unusable = sorted(n for n, f in feeds.items() if f.get("state") in ("missing", "unhealthy"))
        res.attr("feed_status", feeds)
        if not entries:
            res.raw = {"query": kind, "matches": 0, "lists": feeds}
            if unusable:  # rule 5: a list that could not be read makes a miss 'could not verify'
                return res.mark("error", f"deepdarkCTI list(s) {', '.join(unusable)} could not be read: could not verify")
            return res.mark("empty")
        what = "onion host" if kind == "onion" else ("Telegram channel" if entity.type is T.TELEGRAM_HANDLE else "Telegram channel with this handle")
        listings, actors = [], []
        for entry in entries[:MAX_MATCH_FINDINGS]:
            fetched = feeds.get(entry["list"], {}).get("fetched_at", "")
            wording, historical, stale = match_wording(entry, today, fetched=fetched)
            listing = {
                "list": entry["list"], "category": entry["category"], "group": entry["group"], "status": entry["status"],
                "status_text": entry["status_text"], "list_date": entry["commit_date"], "historical": historical,
                "display": entry["display"], "row": entry["row"],
            }
            listings.append(listing)
            tags = ["suspicious", entry["list_tag"]] + (["darkweb"] if kind == "onion" else []) + (["historical"] if historical else [])
            res.finding(
                f"Listed in deepdarkCTI: {entry['category']}",
                "info" if historical else "medium",
                f"{entry['display']}: {wording}. Hostile infrastructure: never visit it from the corporate egress (shown "
                f"defanged). A curated-list entry is context, not attribution. Source: {ATTRIBUTION}.",
                confidence="possible",
                criterion=f"the {what} appears in deepdarkCTI {entry['list']}.md (row {entry['row']}); "
                + ("historical: offline/seized/expired entry or list older than 180 days" if historical else "active entry of a list updated in the last 180 days"),
                data=listing,
                tags=sorted(set(tags)),
                source=SOURCE_LISTS,
                observed_last=entry["commit_date"],
                key=f"{entry['list']}:{entry['row']}:{fold(entry['group'])}",
            )
            group = entry.get("group")
            if group and not entry.get("index_row") and not _INDEX_ROW_RE.search(group):
                relation = "leak_site_of" if (kind == "onion" and entry["list"] == "ransomware_gang" and entry["role"] == "site") else "listed_for_actor"
                pivot = res.pivot(
                    T.THREAT_ACTOR, group, relation, confidence="possible", expand=False,
                    note=f"deepdarkCTI {entry['list']}.md lists this {what} for {group} (context, not attribution)",
                )
                if pivot is not None and group not in actors:
                    actors.append(group)
        res.attr("ddc_listings", listings)
        res.attr("threat_actors", actors)
        res.attr("data_attribution", ATTRIBUTION)
        res.raw = {"query": kind, "matches": listings, "lists": feeds}
        res.link("deepdarkCTI repository (source lists)", REPO_URL)
        return res

    # ------------------------------------------------------------------ group summary
    def _group(self, res: ModuleResult, ctx: Any, index: dict[str, Any], name: str, feeds: dict[str, Any]) -> ModuleResult:
        summary = group_summary(index, name, banned=banned_hashes(ctx))
        res.attr("feed_status", feeds)
        unusable = sorted(n for n, f in feeds.items() if f.get("state") in ("missing", "unhealthy"))
        if summary is None:
            res.raw = {"query": "group", "matches": 0, "lists": feeds}
            if unusable:
                return res.mark("error", f"deepdarkCTI list(s) {', '.join(unusable)} could not be read: could not verify")
            return res.mark("empty")
        res.attr("ddc_group_summary", summary)
        res.attr("data_attribution", ATTRIBUTION)
        withheld = summary.get("examples_withheld")
        res.finding(
            "deepdarkCTI lists infrastructure for this group",
            "info",
            f"deepdarkCTI lists {summary['onion']} onion host(s) and {summary['telegram']} Telegram channel(s) for "
            f"{summary['group']} ({summary['active']} active) in {', '.join(summary['lists'])}. Examples (defanged): "
            f"{', '.join(summary['examples']) or 'none shown'}"
            + (f"; {withheld} onion example(s) withheld by the Ahmia safety filter" if withheld else "")
            + f". Hostile infrastructure: never visited. Source: {ATTRIBUTION}.",
            confidence="possible",
            criterion="the group name matches a deepdarkCTI row name (case/accent-insensitive, version suffix allowed)",
            data=summary,
            tags=["darkweb"],
            source=SOURCE_LISTS,
        )
        res.raw = {"query": "group", "summary": summary, "lists": feeds}
        res.link("deepdarkCTI repository (source lists)", REPO_URL)
        return res


__all__ = [
    "COMMIT_URL",
    "DeepdarkctiIndex",
    "FLOORS",
    "LISTS",
    "LIST_URL",
    "build_index",
    "classify_telegram_path",
    "commit_dataset",
    "group_matches",
    "group_summary",
    "list_dataset",
    "list_health",
    "load_lists",
    "match_wording",
    "normalize_status",
    "parse_commit_date",
    "parse_ddc_list",
    "parse_markdown_table",
    "split_md_row",
    "split_name_qualifier",
    "telegram_key",
]
