"""Offline import of an X/Twitter archive the analyst already holds + automation indicators (P121, Ceos port).

* cond 1 - offline: disclosure 'none' (no network at all; a unit test asserts no HTTP call), runs only when
  selected (``-M x_archive_import`` or ``v3lum run``), default_enabled False.
* cond 2 - only lawfully obtained archives (provided by the account holder or produced under legal
  process) are imported, with provenance recorded before import: a sidecar ``<archive>.provenance.json``
  next to the file ``{"source", "date": "YYYY-MM-DD", "legal_basis": "account_holder" | "legal_process",
  "reference", "account_handle"}``. Without it nothing is read (SKIPPED reason_code 'config'); the
  provenance and the archive SHA-256 are copied into the result (attribute ``archive_provenance``), so the
  case records them. ``account_handle`` (optional) is compared with the archive's account: a mismatch is
  reported, the handle is never looked up anywhere.
* cond 3 - archives are untrusted: read in memory with the standard ZIP reader, never extracted; member
  names are never used as paths (absolute, '..', backslash and NUL names reject the archive); at most
  2,000 members, 200 MB uncompressed (declared and while inflating), compression ratio capped at 100x
  (after a 64 KiB grace); encrypted, symlink and duplicate members reject it. Only
  ``data/{manifest,account,profile,tweet(s),deleted-tweet(s)}[-partN].js`` are read: the bundled HTML/JS
  viewer is never opened or rendered, media files are never decoded, and direct messages, IP audit and
  every other data file are never read. A bare ``data/tweets.js`` file is accepted too.
* cond 4 - the ``window.YTD.<name>.part<N> = `` prefix (``window.__THAR_CONFIG = `` for the manifest) is
  stripped and the rest parsed with ``json.loads``; nothing is evaluated. The reader follows X's documented
  archive layout; twitter-archive-parser (GPL-3.0) was not used as a template (A6).
* cond 5 - automation indicators with the Ceos thresholds (interval CV < 0.5 with >= 20 gaps; > 80%
  reposts with n >= 20; >= 23 distinct active hours with n >= 50; handle ending in >= 6 digits; default
  avatar; > 72 posts/day; < 90 days old with > 1,000 posts); likelihood high at >= 3 signals, medium at 2,
  as an attribute.
* cond 6 - findings from the indicators are info/low with confidence <= 0.4 and carry the underlying
  metrics; they are never the sole basis of a decision about a person (LGPD art. 20).

The Ceos code (ceos/x/importar.py, ceos/x/analise.py) is team-owned; no third-party code was copied.
"""

from __future__ import annotations

import hashlib
import io
import json
import os
import re
import stat
import statistics
import zipfile
import zlib
from collections import Counter
from datetime import datetime, timedelta, timezone
from typing import Any

from v3lum.core.entities import Entity
from v3lum.core.entities import EntityType as T
from v3lum.core.models import ModuleResult, Opsec
from v3lum.core.module import Module, register

ARCHIVE_LIMITS = {
    "members": 2000,  # cond 3
    "total_bytes": 200 * 1024 * 1024,  # cond 3 (uncompressed)
    "ratio": 100,  # cond 3
    "ratio_grace": 64 * 1024,  # ratio enforced once a member inflates past this
}
MAX_FILE_BYTES = ARCHIVE_LIMITS["total_bytes"]
PROVENANCE_SUFFIX = ".provenance.json"
PROVENANCE_MAX_BYTES = 64 * 1024
LEGAL_BASES = ("account_holder", "legal_process")  # cond 2
INTERACTION_CAP = 10
DELETED_LISTED = 50
_PARSED_BASENAMES = re.compile(r"^(manifest|account|profile|tweets?|deleted-tweets?)(?:-part\d{1,3})?\.js$")
_YTD_PREFIX_RE = re.compile(
    r"^\s*window\.(?:YTD\.(?P<name>[A-Za-z0-9_]{1,64})\.part(?P<part>\d{1,4})|(?P<thar>__THAR_CONFIG))\s*=\s*")
_HANDLE_RE = re.compile(r"^[A-Za-z0-9_]{1,15}$")
_X_DATE_RE = re.compile(r"^[A-Za-z]{3} ([A-Za-z]{3}) (\d{1,2}) (\d{2}):(\d{2}):(\d{2}) ([+-])(\d{2})(\d{2}) (\d{4})$")
_MONTHS = {m: i for i, m in enumerate(("jan", "feb", "mar", "apr", "may", "jun", "jul", "aug", "sep", "oct", "nov", "dec"), 1)}
AUTOMATION_THRESHOLDS = {  # cond 5 (Ceos analise.sinais_automacao)
    "interval_cv_max": 0.5, "interval_min_gaps": 20,
    "repost_pct_min": 80, "repost_min_posts": 20,
    "distinct_hours_min": 23, "distinct_hours_min_posts": 50,
    "handle_digits_min": 6,
    "posts_per_day_max": 72,
    "young_account_days": 90, "young_account_posts": 1000,
}
BRASILIA = timezone(timedelta(hours=-3))  # no DST since 2019: activity histogram in Brasilia time (Ceos)
BASIS = "indicators of automation, not a verdict; never the sole basis of a decision about a person (LGPD art. 20)"


class ArchiveRefused(ValueError):
    """args[0] = reason code ('members', 'size_cap', 'ratio', 'unsafe_name', 'encrypted', 'symlink', ...)."""


class FileRefused(OSError):
    """The path is not a readable regular file; ``kind`` is 'missing' | 'special' | 'unreadable'."""

    def __init__(self, kind: str, reason: str) -> None:
        super().__init__(reason)
        self.kind = kind
        self.reason = reason


# ================================================================================ files and provenance


def read_regular(path: str, cap: int) -> tuple[bytes, int]:
    """(content of at most ``cap`` bytes, real size) of a regular file: FIFOs, devices, sockets and
    directories are refused before opening and re-checked with fstat after opening."""
    try:
        st = os.stat(path)
    except FileNotFoundError:
        raise FileRefused("missing", "the file no longer exists") from None
    except OSError as exc:
        raise FileRefused("unreadable", f"cannot stat the file ({exc.strerror or type(exc).__name__})") from None
    if not stat.S_ISREG(st.st_mode):
        raise FileRefused("special", "not a regular file")
    flags = os.O_RDONLY | getattr(os, "O_NONBLOCK", 0) | getattr(os, "O_NOCTTY", 0) | getattr(os, "O_BINARY", 0)
    try:
        fd = os.open(path, flags)
    except OSError as exc:
        raise FileRefused("unreadable", f"cannot open the file ({exc.strerror or type(exc).__name__})") from None
    with os.fdopen(fd, "rb", buffering=0) as fh:
        st2 = os.fstat(fh.fileno())
        if not stat.S_ISREG(st2.st_mode):
            raise FileRefused("special", "not a regular file")
        chunks: list[bytes] = []
        got = 0
        while got < cap:
            block = fh.read(min(1 << 20, cap - got))
            if not block:
                break
            chunks.append(block)
            got += len(block)
        return b"".join(chunks), int(st2.st_size)


def provenance_reason(prov: Any) -> str | None:
    """cond 2: None when the provenance records source, ISO date and a lawful basis, else the refusal reason."""
    if not isinstance(prov, dict):
        return "archive provenance (source, date, legal basis) must be recorded before import"
    missing = [k for k in ("source", "date", "legal_basis") if not str(prov.get(k) or "").strip()]
    if missing:
        return "archive provenance incomplete: missing " + ", ".join(missing)
    if str(prov["legal_basis"]).strip() not in LEGAL_BASES:
        return ("only archives provided by the account holder or produced under legal process are imported "
                "(legal_basis account_holder | legal_process)")
    if not re.fullmatch(r"\d{4}-\d{2}-\d{2}", str(prov["date"]).strip()[:10]):
        return "archive provenance date must be an ISO date (YYYY-MM-DD)"
    return None


def read_provenance(path: str) -> tuple[dict[str, Any] | None, str | None]:
    """The sidecar ``<archive>.provenance.json`` -> (record, None) or (None, refusal reason)."""
    side = path + PROVENANCE_SUFFIX
    howto = (f"record the archive provenance before import in {os.path.basename(side)} next to the archive: "
             '{"source": ..., "date": "YYYY-MM-DD", "legal_basis": "account_holder" | "legal_process", "reference": ...}')
    try:
        raw, size = read_regular(side, PROVENANCE_MAX_BYTES + 1)
    except FileRefused:
        return None, "archive provenance not recorded: " + howto
    if size > PROVENANCE_MAX_BYTES:
        return None, "archive provenance record too large (64 KiB at most)"
    try:
        prov = json.loads(raw.decode("utf-8"))
    except (UnicodeDecodeError, ValueError):
        return None, "archive provenance record is not valid JSON: " + howto
    why = provenance_reason(prov)
    if why:
        return None, f"{why}: {howto}"
    out = {"source": str(prov["source"]).strip()[:300], "date": str(prov["date"]).strip()[:10],
           "legal_basis": str(prov["legal_basis"]).strip(), "reference": str(prov.get("reference") or "").strip()[:300] or None}
    handle = normalise_handle(prov.get("account_handle"))
    if handle:
        out["account_handle"] = handle
    return out, None


# ================================================================================ archive reader (cond 3/4)


def normalise_handle(value: Any) -> str | None:
    v = value.strip().lstrip("@") if isinstance(value, str) else ""
    return v if _HANDLE_RE.match(v) else None


def member_name_reason(name: Any) -> str | None:
    """cond 3: member names are never used as paths; names that would escape or are odd reject the archive."""
    if not isinstance(name, str) or not name:
        return "empty member name"
    if "\x00" in name:
        return "NUL in member name"
    if "\\" in name:
        return "backslash in member name"
    if name.startswith("/") or re.match(r"^[A-Za-z]:", name):
        return "absolute member path"
    if any(seg == ".." for seg in name.split("/")):
        return "'..' in member path (zip-slip)"
    return None


def strip_ytd_prefix(text: str) -> tuple[str, int, str]:
    """cond 4: 'window.YTD.<name>.part<N> = ' (or 'window.__THAR_CONFIG = ') -> (name, part, rest). The rest
    must be pure JSON; nothing is evaluated. ValueError when the prefix is missing."""
    t = text[1:] if text.startswith("﻿") else text
    m = _YTD_PREFIX_RE.match(t)
    if not m:
        raise ValueError("missing window.YTD.<name>.partN prefix")
    name = "manifest" if m.group("thar") else m.group("name")
    part = int(m.group("part")) if m.group("part") else 0
    rest = t[m.end():].strip()
    if rest.endswith(";"):
        rest = rest[:-1].rstrip()
    return name, part, rest


def parse_ytd_js(text: str) -> dict[str, Any]:
    """cond 4: one data/*.js member -> {name, part, data, error}; json.loads only (a JS expression fails)."""
    try:
        name, part, rest = strip_ytd_prefix(text)
    except ValueError as exc:
        return {"name": None, "part": None, "data": None, "error": str(exc)}
    try:
        data = json.loads(rest)
    except ValueError:
        return {"name": name, "part": part, "data": None, "error": "not JSON after the window.YTD prefix"}
    return {"name": name, "part": part, "data": data, "error": None}


def _bounded_read(zf: zipfile.ZipFile, info: zipfile.ZipInfo, budget: int) -> bytes:
    out = bytearray()
    with zf.open(info) as fh:
        while True:
            chunk = fh.read(65536)
            if not chunk:
                break
            out += chunk
            if len(out) > budget:
                raise ArchiveRefused("size_cap")
            if len(out) > ARCHIVE_LIMITS["ratio_grace"] and len(out) > ARCHIVE_LIMITS["ratio"] * max(info.compress_size, 1):
                raise ArchiveRefused("ratio")
    return bytes(out)


def scan_x_archive(data: bytes) -> dict[str, Any]:
    """cond 3: read an X archive ZIP in memory -> {state ok|rejected|error, reason, reason_code, members,
    declared_bytes, files {basename: text}, skipped_data, ignored_outside_data}."""
    res: dict[str, Any] = {"state": "error", "reason": None, "reason_code": None, "members": 0, "declared_bytes": 0, "files": {},
                           "skipped_data": [], "ignored_outside_data": 0}
    if not isinstance(data, (bytes, bytearray)) or bytes(data[:2]) != b"PK":
        return dict(res, reason="not a ZIP archive", reason_code="not_archive")
    try:
        zf = zipfile.ZipFile(io.BytesIO(bytes(data)))
        infos = zf.infolist()
    except (zipfile.BadZipFile, zipfile.LargeZipFile, ValueError, OSError, EOFError, NotImplementedError) as exc:
        return dict(res, reason=f"invalid ZIP ({type(exc).__name__})", reason_code="bad_zip")
    res["members"] = len(infos)
    if len(infos) > ARCHIVE_LIMITS["members"]:
        return dict(res, state="rejected", reason=f"too many members ({len(infos)} > {ARCHIVE_LIMITS['members']})",
                    reason_code="members")
    names = Counter(i.filename for i in infos)
    declared = 0
    for i in infos:
        why = member_name_reason(i.filename)
        if why:
            return dict(res, state="rejected", reason=f"unsafe member name: {why}", reason_code="unsafe_name")
        if names[i.filename] > 1:
            return dict(res, state="rejected", reason="duplicate member name", reason_code="duplicate")
        if i.flag_bits & 0x1:
            return dict(res, state="rejected", reason="encrypted member", reason_code="encrypted")
        if ((i.external_attr >> 16) & 0o170000) == 0o120000:
            return dict(res, state="rejected", reason="symlink member", reason_code="symlink")
        declared += max(int(i.file_size), 0)
        if i.file_size > ARCHIVE_LIMITS["ratio_grace"] and i.file_size > ARCHIVE_LIMITS["ratio"] * max(i.compress_size, 1):
            return dict(res, state="rejected", reason=f"compression ratio above {ARCHIVE_LIMITS['ratio']}x (zip bomb)",
                        reason_code="ratio")
    res["declared_bytes"] = declared
    if declared > ARCHIVE_LIMITS["total_bytes"]:
        return dict(res, state="rejected", reason="declared uncompressed size above 200 MB", reason_code="size_cap")
    budget = ARCHIVE_LIMITS["total_bytes"]
    files: dict[str, str] = {}
    skipped: list[str] = []
    for i in infos:
        if i.is_dir():
            continue
        name = i.filename
        if not name.startswith("data/") or name.count("/") != 1:
            if name.startswith("data/"):
                skipped.append(name)
            else:
                res["ignored_outside_data"] += 1  # the bundled HTML/JS viewer and assets are never opened
            continue
        base = name[len("data/"):]
        if not _PARSED_BASENAMES.match(base):
            skipped.append(name)  # direct messages, IP audit, media and every other data file are never read
            continue
        try:
            raw = _bounded_read(zf, i, budget)
        except ArchiveRefused as exc:
            return dict(res, state="rejected", reason=f"archive limit while reading {name}: {exc.args[0]}", reason_code=str(exc.args[0]))
        except (zipfile.BadZipFile, zlib.error, OSError, EOFError, RuntimeError, NotImplementedError, ValueError) as exc:
            return dict(res, state="rejected", reason=f"corrupt member {name} ({type(exc).__name__})", reason_code="corrupt")
        budget -= len(raw)
        files[base] = raw.decode("utf-8", "replace")
    res["skipped_data"] = sorted(skipped)
    return dict(res, state="ok", files=files)


def parse_x_date(value: Any) -> datetime | None:
    """'Wed Oct 10 20:19:24 +0000 2018' (locale-independent) or ISO-8601 -> aware UTC datetime, else None."""
    if not isinstance(value, str) or len(value) > 64:
        return None
    m = _X_DATE_RE.match(value.strip())
    if m:
        mon = _MONTHS.get(m.group(1).lower())
        if not mon:
            return None
        try:
            off = timedelta(hours=int(m.group(7)), minutes=int(m.group(8))) * (1 if m.group(6) == "+" else -1)
            dt = datetime(int(m.group(9)), mon, int(m.group(2)), int(m.group(3)), int(m.group(4)), int(m.group(5)),
                          tzinfo=timezone(off))
        except ValueError:
            return None
        return dt.astimezone(timezone.utc)
    v = value.strip()
    if v.endswith("Z"):
        v = v[:-1] + "+00:00"
    try:
        dt = datetime.fromisoformat(v)
    except ValueError:
        return None
    return (dt if dt.tzinfo else dt.replace(tzinfo=timezone.utc)).astimezone(timezone.utc)


def _iso(dt: datetime | None) -> str | None:
    return dt.strftime("%Y-%m-%dT%H:%M:%SZ") if isinstance(dt, datetime) else None


def _source_name(src: Any) -> str | None:
    if not isinstance(src, str):
        return None
    m = re.search(r">([^<]{1,80})</a>", src)
    return ((m.group(1) if m else re.sub(r"<[^>]*>", "", src)).strip() or None) if src else None


def _ytd_items(files: dict[str, str], base_names: tuple[str, ...]) -> tuple[list[Any], list[str]]:
    """The arrays of every part of one data type (tweets.js, tweets-part1.js...), in part order."""
    items: list[Any] = []
    errors: list[str] = []
    pat = re.compile(r"^(?:" + "|".join(re.escape(b) for b in base_names) + r")(?:-part(\d{1,3}))?\.js$")
    matched = sorted((int(m.group(1) or 0), b) for b in files for m in [pat.match(b)] if m)
    for _, base in matched:
        r = parse_ytd_js(files[base])
        if r["error"]:
            errors.append(f"data/{base}: {r['error']}")
        elif isinstance(r["data"], list):
            items.extend(r["data"])
        else:
            errors.append(f"data/{base}: not a JSON array")
    return items, errors


def _post(t: Any, handle: str | None) -> dict[str, Any] | None:
    if not isinstance(t, dict):
        return None
    sid = t.get("id_str") if isinstance(t.get("id_str"), str) else (str(t.get("id")) if isinstance(t.get("id"), (int, str)) else None)
    if not isinstance(sid, str) or not sid.isdigit() or len(sid) > 20:
        return None
    text = t.get("full_text") if isinstance(t.get("full_text"), str) else (t.get("text") if isinstance(t.get("text"), str) else "")
    ent = t.get("entities") if isinstance(t.get("entities"), dict) else {}

    def _list(key: str) -> list[Any]:
        v = ent.get(key)
        return v if isinstance(v, list) else []

    mentions = [m["screen_name"] for m in _list("user_mentions") if isinstance(m, dict) and isinstance(m.get("screen_name"), str)]
    tags = [h["text"] for h in _list("hashtags") if isinstance(h, dict) and isinstance(h.get("text"), str)]
    rt = re.match(r"RT @(\w{1,15}):", text or "")
    reply_to = t.get("in_reply_to_screen_name") if isinstance(t.get("in_reply_to_screen_name"), str) else None
    if rt:
        kind = "repost"
    elif reply_to and (not handle or reply_to.lower() != handle.lower()):
        kind = "reply"
    else:
        kind = "post"
    return {"id": sid, "created_at": _iso(parse_x_date(t.get("created_at"))), "kind": kind,
            "repost_of": rt.group(1) if rt else None, "reply_to": reply_to, "mentions": mentions[:50], "hashtags": tags[:50],
            "client": _source_name(t.get("source")), "deleted_at": _iso(parse_x_date(t.get("deleted_at")))}


def normalise_x_archive(files: dict[str, str]) -> dict[str, Any]:
    """cond 1/4: parsed data/*.js texts -> {state ok|empty|error, reason, account, profile, posts,
    deleted_posts, generated_at, warnings}. The account keeps id, handle, display name and creation date only
    (the archive e-mail, phone and created-via fields are never copied)."""
    warnings: list[str] = []
    account: dict[str, Any] = {}
    profile: dict[str, Any] = {}
    gen = None
    if "manifest.js" in files:
        r = parse_ytd_js(files["manifest.js"])
        if r["error"]:
            warnings.append(f"data/manifest.js: {r['error']}")
        elif isinstance(r["data"], dict):
            ai = r["data"].get("archiveInfo") if isinstance(r["data"].get("archiveInfo"), dict) else {}
            gen = ai.get("generationDate") if isinstance(ai.get("generationDate"), str) else None
    if "account.js" in files:
        r = parse_ytd_js(files["account.js"])
        if r["error"]:
            warnings.append(f"data/account.js: {r['error']}")
        elif isinstance(r["data"], list) and r["data"] and isinstance(r["data"][0], dict):
            a = r["data"][0].get("account") if isinstance(r["data"][0].get("account"), dict) else {}
            account = {"account_id": str(a.get("accountId"))[:24] if isinstance(a.get("accountId"), (str, int)) else None,
                       "handle": normalise_handle(a.get("username")),
                       "display_name": a.get("accountDisplayName")[:100] if isinstance(a.get("accountDisplayName"), str) else None,
                       "created_at": _iso(parse_x_date(a.get("createdAt")))}
            if a.get("username") and not account["handle"]:
                warnings.append("data/account.js: username is not a valid X handle (kept out of pivots)")
    else:
        warnings.append("data/account.js missing: the author of the posts is unknown")
    if "profile.js" in files:
        r = parse_ytd_js(files["profile.js"])
        if r["error"]:
            warnings.append(f"data/profile.js: {r['error']}")
        elif isinstance(r["data"], list) and r["data"] and isinstance(r["data"][0], dict):
            p = r["data"][0].get("profile") if isinstance(r["data"][0].get("profile"), dict) else {}
            d = p.get("description") if isinstance(p.get("description"), dict) else {}

            def _s(v: Any, n: int) -> str | None:
                return v[:n] if isinstance(v, str) and v else None

            profile = {"bio": _s(d.get("bio"), 500), "website": _s(d.get("website"), 300), "location": _s(d.get("location"), 120),
                       "avatar_url": _s(p.get("avatarMediaUrl"), 300)}
    handle = account.get("handle")
    tweets, terrs = _ytd_items(files, ("tweets", "tweet"))
    warnings.extend(terrs)
    deleted, derrs = _ytd_items(files, ("deleted-tweets", "deleted-tweet"))
    warnings.extend(derrs)
    posts: list[dict[str, Any]] = []
    seen: set[str] = set()
    for item in tweets:
        p = _post(item.get("tweet", item) if isinstance(item, dict) else None, handle)
        if p and p["id"] not in seen:
            seen.add(p["id"])
            posts.append(p)
    dposts = [p for p in (_post(item.get("tweet", item) if isinstance(item, dict) else None, handle) for item in deleted) if p]
    has_tweets = any(re.match(r"^tweets?(?:-part\d+)?\.js$", b) for b in files)
    if not has_tweets:
        state, reason = "error", "not an X archive (no data/tweets.js or data/tweet.js)"
    elif not posts and terrs:
        state, reason = "error", "malformed data/tweets.js (" + "; ".join(terrs[:3]) + ")"
    else:
        state, reason = ("ok" if posts else "empty"), None
    posts.sort(key=lambda p: (p["created_at"] or "", int(p["id"])))
    return {"state": state, "reason": reason, "account": account, "profile": profile, "posts": posts, "deleted_posts": dposts,
            "generated_at": gen, "warnings": warnings[:20]}


def read_x_input(data: bytes) -> dict[str, Any]:
    """cond 1/3: analyst-held file -> normalised archive. A ZIP goes through :func:`scan_x_archive`; a bare
    data/tweets.js (window.YTD prefix) is a one-file archive. Never extracted or executed."""
    if bytes(data[:2]) == b"PK":
        sc = scan_x_archive(data)
        if sc["state"] != "ok":
            return {"state": sc["state"], "reason": sc["reason"], "reason_code": sc["reason_code"]}
        out = normalise_x_archive(sc["files"])
        out["scan"] = {k: sc[k] for k in ("members", "declared_bytes", "skipped_data", "ignored_outside_data")}
        return out
    text = bytes(data).decode("utf-8", "replace")
    if text.lstrip("﻿").lstrip().startswith("window.YTD."):
        try:
            name = strip_ytd_prefix(text.lstrip())[0]
        except ValueError:
            name = None
        if name in ("tweets", "tweet"):
            out = normalise_x_archive({"tweets.js": text})
            out["scan"] = {"members": 1, "single_file": True}
            return out
    return {"state": "not_archive", "reason": "not an X archive ZIP or data/tweets.js file", "reason_code": "not_archive"}


# ================================================================================ indicators (cond 5/6)


def automation_indicators(posts: list[dict[str, Any]], account: dict[str, Any] | None = None, profile: dict[str, Any] | None = None,
                          now: Any = None, posts_total: int | None = None) -> dict[str, Any]:
    """cond 5/6: Ceos automation signals over imported posts -> {signals, signal_count, likelihood, metrics,
    small_sample, severity, confidence, basis}. likelihood high (>= 3 signals), medium (2), low (0-1); never a
    verdict. posts_total defaults to the archive post count (a lower bound); ``now`` to the latest post."""
    th = AUTOMATION_THRESHOLDS
    posts = [p for p in posts or [] if isinstance(p, dict)]
    dts = sorted(d for d in (parse_x_date(p.get("created_at")) for p in posts) if d)
    gaps = [(b - a).total_seconds() for a, b in zip(dts, dts[1:]) if b > a]
    signals: list[dict[str, Any]] = []
    metrics: dict[str, Any] = {"posts": len(posts), "dated_posts": len(dts), "gaps": len(gaps)}
    cv = None
    if len(gaps) >= th["interval_min_gaps"]:
        mean = statistics.mean(gaps)
        cv = statistics.pstdev(gaps) / mean if mean else None
        if cv is not None and cv < th["interval_cv_max"]:
            signals.append({"id": "regular_intervals", "metric": round(cv, 3),
                            "text": f"very regular intervals between posts (CV {cv:.2f} < {th['interval_cv_max']}; {len(gaps)} gaps)"})
    metrics["interval_cv"] = round(cv, 3) if cv is not None else None
    n = len(posts)
    reposts = sum(1 for p in posts if p.get("kind") == "repost")
    pct = round(100 * reposts / n) if n else 0
    metrics["repost_pct"] = pct
    if n >= th["repost_min_posts"] and pct > th["repost_pct_min"]:
        signals.append({"id": "mostly_reposts", "metric": pct, "text": f"{pct}% of the posts are reposts (n={n})"})
    hours = Counter(d.astimezone(BRASILIA).hour for d in dts)
    metrics["hours_brasilia"] = [hours.get(h, 0) for h in range(24)]
    metrics["distinct_hours"] = len(hours)
    if n >= th["distinct_hours_min_posts"] and len(hours) >= th["distinct_hours_min"]:
        signals.append({"id": "all_hours", "metric": len(hours), "text": f"active in {len(hours)} distinct hours of the day (n={n})"})
    handle = (account or {}).get("handle") or ""
    m = re.search(r"\d+$", handle)
    metrics["handle_trailing_digits"] = len(m.group()) if m else 0
    if m and len(m.group()) >= th["handle_digits_min"]:
        signals.append({"id": "numeric_handle", "metric": len(m.group()), "text": "handle ends in a long digit sequence"})
    avatar = (profile or {}).get("avatar_url")
    default_avatar = isinstance(avatar, str) and "default_profile" in avatar  # Ceos: the explicit default image URL
    metrics["default_avatar"] = default_avatar
    if default_avatar:
        signals.append({"id": "default_avatar", "metric": True, "text": "default profile image"})
    created = parse_x_date((account or {}).get("created_at"))
    ref = parse_x_date(now) if isinstance(now, str) else (now if isinstance(now, datetime) else None)
    ref = ref or (dts[-1] if dts else None)
    total = posts_total if isinstance(posts_total, int) else n
    metrics["posts_total"] = total
    metrics["account_age_days"] = metrics["posts_per_day"] = None
    if created and ref and total:
        days = max(1, (ref - created).days)
        per_day = total / days
        metrics["account_age_days"] = days
        metrics["posts_per_day"] = round(per_day, 1)
        if per_day > th["posts_per_day_max"]:
            signals.append({"id": "high_volume", "metric": round(per_day, 1),
                            "text": f"average of {per_day:.0f} posts per day since the account was created"})
        if days < th["young_account_days"] and total > th["young_account_posts"]:
            signals.append({"id": "young_and_prolific", "metric": days,
                            "text": f"account {days} days old with more than {th['young_account_posts']} posts"})
    clients = Counter(p.get("client") for p in posts if p.get("client"))
    metrics["clients"] = [[c, k] for c, k in clients.most_common(5)]
    k = len(signals)
    likelihood = "high" if k >= 3 else "medium" if k == 2 else "low"
    return {"signals": signals, "signal_count": k, "likelihood": likelihood, "metrics": metrics, "small_sample": n < 50,
            "severity": "low" if k >= 2 else "info", "confidence": {"high": 0.4, "medium": 0.3, "low": 0.1}[likelihood],
            "basis": BASIS}


def interaction_counts(norm: dict[str, Any], cap: int = INTERACTION_CAP) -> list[tuple[str, int]]:
    """The most frequent reposted/replied/mentioned handles (own handle excluded), capped."""
    own = ((norm.get("account") or {}).get("handle") or "").lower()
    cnt: Counter[str] = Counter()
    for p in norm.get("posts") or []:
        for h in [p.get("repost_of"), p.get("reply_to"), *(p.get("mentions") or [])]:
            if isinstance(h, str) and h.lower() != own and normalise_handle(h):
                cnt[h] += 1
    return cnt.most_common(cap)


# ================================================================================ module


@register
class XArchiveImport(Module):
    name = "x_archive_import"
    title = "X/Twitter archive import (offline) + automation indicators"
    description = (
        "Imports an X/Twitter archive the analyst already holds (account holder's export or legal process; provenance "
        "recorded first): account, profile, post counts and dates, deleted posts, interactions and the Ceos automation "
        "indicators - offline, read in memory, never extracted or executed."
    )
    category = "username_social"
    accepts = frozenset({T.FILE})
    produces = frozenset({T.USERNAME, T.URL})
    tags = frozenset({"offline"})
    reference = "https://help.x.com/en/managing-your-account/how-to-download-your-x-archive"
    notice = (
        "Only lawfully obtained archives (provided by the account holder or produced under legal process); write "
        "<archive>.provenance.json (source, date, legal_basis) before import. Automation indicators are indications, never "
        "a verdict, and never the sole basis of a decision about a person (LGPD art. 20)."
    )
    terms = "open"  # offline, no registry source (A1 BR20)
    opsec = Opsec.PASSIVE
    disclosure = "none"
    hosts = ()
    access_model = "offline"
    timeout = 120.0
    max_pivots = 2 + INTERACTION_CAP
    default_enabled = False  # cond 1: runs only when selected

    def applies(self, entity: Entity, ctx: Any) -> bool:
        try:
            head, _size = read_regular(entity.value, 64)
        except FileRefused:
            return False
        h = head.lstrip(b"\xef\xbb\xbf").lstrip()
        return head[:2] == b"PK" or h.startswith(b"window.YTD.")

    def run(self, entity: Entity, ctx: Any) -> ModuleResult:
        res = self.result(entity)
        path = entity.value
        prov, why = read_provenance(path)
        if prov is None:
            return res.mark("skipped", str(why), reason_code="config")  # cond 2: nothing is read without provenance
        try:
            size = os.stat(path).st_size
            if size > MAX_FILE_BYTES:
                return res.mark("error", "archive refused: larger than 200 MB (cond 3); repack only the data/*.js files into a "
                                         "new ZIP or import data/tweets.js directly")
            data, _size = read_regular(path, MAX_FILE_BYTES + 1)
        except (FileRefused, OSError) as exc:
            reason = getattr(exc, "reason", None) or str(exc)
            if getattr(exc, "kind", "") in ("missing", "special"):
                return res.mark("skipped", f"not applicable: {reason}", reason_code="not_applicable")
            return res.mark("error", f"archive could not be read: {reason}")
        prov["sha256"] = hashlib.sha256(data).hexdigest()
        prov["bytes"] = len(data)
        res.attr("archive_provenance", prov)
        out = read_x_input(data)
        if out["state"] == "not_archive":
            return res.mark("skipped", out["reason"], reason_code="not_applicable")
        if out["state"] in ("rejected", "error") and "account" not in out:
            return res.mark("error", f"archive refused as unsafe or unreadable: {out['reason']}")
        if out["state"] == "error" and str(out.get("reason") or "").startswith("not an X archive"):
            return res.mark("skipped", str(out["reason"]), reason_code="not_applicable")
        if out["state"] == "error":
            return res.mark("error", f"archive could not be parsed: {out['reason']}")
        self._report(res, out, prov)
        if out["state"] == "empty":
            res.error = "the archive holds no posts"
            return res.mark("empty")
        return res

    def _report(self, res: ModuleResult, norm: dict[str, Any], prov: dict[str, Any]) -> None:
        account, profile, posts = norm["account"], norm["profile"], norm["posts"]
        kinds = Counter(p["kind"] for p in posts)
        tags = Counter(t.lower() for p in posts for t in p.get("hashtags") or [])
        clients = Counter(p["client"] for p in posts if p.get("client"))
        summary = {
            "account": account, "profile": profile, "posts": len(posts), "reposts": kinds.get("repost", 0),
            "replies": kinds.get("reply", 0), "first_post": posts[0]["created_at"] if posts else None,
            "last_post": posts[-1]["created_at"] if posts else None, "generated_at": norm.get("generated_at"),
            "deleted_posts": len(norm["deleted_posts"]),
            "deleted_listed": [{k: p[k] for k in ("id", "created_at", "deleted_at")} for p in norm["deleted_posts"][:DELETED_LISTED]],
            "clients": [[c, n] for c, n in clients.most_common(5)], "hashtags": [[t, n] for t, n in tags.most_common(10)],
            "warnings": norm.get("warnings") or [], **(norm.get("scan") or {}),
        }
        res.attr("x_archive", summary)
        ind = automation_indicators(posts, account, profile, now=norm.get("generated_at"))
        res.attr("automation_indicators", {k: ind[k] for k in ("signals", "signal_count", "metrics", "small_sample", "basis")})
        res.attr("automation_likelihood", ind["likelihood"])
        res.raw = {"summary": {k: v for k, v in summary.items() if k not in ("profile",)}, "automation": ind,
                   "provenance": {k: prov.get(k) for k in ("source", "date", "legal_basis", "sha256")}}
        handle = account.get("handle")
        if handle:
            res.pivot(T.USERNAME, handle, "archive_account", confidence="confirmed", expand=False,
                      note="account handle of the imported archive (offline; never looked up automatically)")
        site = profile.get("website")
        if isinstance(site, str) and site.startswith(("http://", "https://")):
            res.pivot(T.URL, site, "link_on_profile", confidence="probable", expand=False, note="website declared on the archived X profile")
        for h, count in interaction_counts(norm):
            res.pivot(T.USERNAME, h, "interacted_with", confidence="possible", expand=False,
                      note=f"interaction ({count}x): reposted, replied to or mentioned by the archive account")
        res.finding(
            "X archive imported",
            "info",
            f"Archive of @{handle or '?'}: {len(posts)} post(s) ({kinds.get('repost', 0)} reposts, {kinds.get('reply', 0)} replies)"
            + (f" from {summary['first_post'][:10]} to {summary['last_post'][:10]}" if posts and summary["first_post"] and summary["last_post"] else "")
            + f", {len(norm['deleted_posts'])} deleted post(s) listed by the archive. Provenance: {prov['legal_basis']}, {prov['date']}.",
            confidence="confirmed",
            data={"posts": len(posts), "deleted_posts": len(norm["deleted_posts"]), "sha256": prov.get("sha256")},
        )
        expected = prov.get("account_handle")
        if expected and handle and expected.lower() != handle.lower():
            res.finding(
                "Archive account differs from the recorded subject",
                "info",
                f"The provenance record names @{expected} but the archive belongs to @{handle}: check the provenance before use.",
                confidence="confirmed",
            )
        if ind["signal_count"]:
            res.finding(
                "Automation indicators (Ceos thresholds)",
                ind["severity"],
                f"{ind['signal_count']} of 7 automation indicator(s) met - likelihood {ind['likelihood']}: "
                + "; ".join(s["text"] for s in ind["signals"])
                + (". Small sample (fewer than 50 posts)." if ind["small_sample"] else ".") + f" {BASIS}.",
                confidence=ind["confidence"],
                criterion="Ceos automation thresholds (interval CV < 0.5 with >= 20 gaps; > 80% reposts n >= 20; >= 23 active "
                          "hours n >= 50; handle ending in >= 6 digits; default avatar; > 72 posts/day; < 90 days with > 1,000 "
                          "posts): high >= 3 signals, medium 2",
                tags=["automation_indicator", "weak_signal"],
                data={"likelihood": ind["likelihood"], "signals": ind["signals"], "metrics": ind["metrics"]},
            )
