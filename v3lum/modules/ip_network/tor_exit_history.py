"""Dated Tor exit history: 'was this IP a Tor exit on <date>?' from local CollecTor archives (P040).

Batch p1-G02-2, proposal P040 ``tor_relays``, final conditions 3-5 (the dated, historical part of
the Tor check; ``tor_exit_local`` answers for now):

* c3 - only when the IOC carries a date: V3LUM entities carry no timestamp yet, so the analyst
  gives the date(s) of the event in the module setting ``tor_exit_history_dates`` (YYYY-MM-DD,
  e.g. ``V3LUM_TOR_EXIT_HISTORY_DATES=2026-11-20 v3lum run tor_exit_history <ip>``); without a
  date the module is not applicable. CollecTor exit-lists are monthly tar.xz archives read in
  memory - streamed, never extracted to disk, with member-count, member-size and total-size caps
  and refusal of absolute/'..' names, links and special files - and indexed locally
  ip -> day -> first/last timestamps from the tordnsel records (ExitNode / Published /
  LastStatus / ExitAddress). The mthcht Tor node history (MIT) adds relay presence periods.
* c4 - the archives (8-15 MB a month) and the mthcht file (54 MB) are fetched by
  ``v3lum data update`` only (``large=True``; ``v3lum data update --essential`` skips them), never
  during a scan or by this module. A month that is not downloaded reads 'history not downloaded
  (run v3lum data update)', never 'not an exit'.
* c5 - every answer prints the date checked and the source ('was an exit on 2026-11-20,
  CollecTor'); dan.me.uk is not used. The dated ExoneraTor page is offered as a manual link.
* c6 - an exit on the date is LOW context (tag ``anonymizer``, never malicious, T1090.003).

The CollecTor window is the current month and the previous ``WINDOW_MONTHS - 1`` months; older
dates fall back to the mthcht relay periods and the ExoneraTor link.
"""

from __future__ import annotations

import json
import lzma
import mmap
import re
import tarfile
import threading
import zlib
from collections.abc import Callable, Iterator
from datetime import date, datetime, timedelta, timezone
from pathlib import Path
from typing import Any

from v3lum.config import SettingSpec
from v3lum.core.datasets import DATASETS, DatasetError, register_dataset
from v3lum.core.entities import Entity
from v3lum.core.entities import EntityType as T
from v3lum.core.models import ModuleResult, Opsec, Status
from v3lum.core.module import Module, register
from v3lum.modules.ip_network.ip_offline_db import local_dataset, special_purpose
from v3lum.modules.ip_network.tor_exit_local import TOR_ATTRIBUTION, TOR_EXIT_NOTE, _norm_ip, exonerator_link

COLLECTOR_SOURCE = "torproject.collector"
MTHCHT_SOURCE = "github.tor_exit_history_mthcht"
HISTORY_NOT_DOWNLOADED = "history not downloaded (run v3lum data update)"
COLLECTOR_URL = "https://collector.torproject.org/archive/exit-lists/exit-list-{y:04d}-{m:02d}.tar.xz"
MTHCHT_URL = "https://raw.githubusercontent.com/mthcht/awesome-lists/main/Lists/TOR/tor_nodes_history.json"
#: CollecTor months registered as datasets: the current month and the previous five.
WINDOW_MONTHS = 6
MAX_DATES = 10

# archive safety caps (a month is ~720 members of ~430 KB, ~300 MB decompressed)
MAX_MEMBERS = 3000
MAX_MEMBER_BYTES = 16 * 1024 * 1024
MAX_TOTAL_BYTES = 2 * 1024 * 1024 * 1024

_MEMBER_RE = re.compile(r"exit-list-(\d{4})-(\d{2})/(\d{2})/(\d{4})-(\d{2})-(\d{2})-(\d{2})-(\d{2})-(\d{2})$")
_RECORD_RE = re.compile(rb"^(ExitNode|ExitAddress)[ \t]+(\S+)(?:[ \t]+(\d{4}-\d{2}-\d{2})[ \t]+(\d{2}:\d{2}:\d{2}))?", re.M)
_FP_RE = re.compile(r"^[0-9A-F]{40}$")
_DAY_RE = re.compile(r"^\d{4}-\d{2}-\d{2}$")


class ArchiveError(ValueError):
    """An archive was refused: unsafe member or a size/member cap exceeded (never extracted)."""


def iter_tar_xz(path: Path, *, wanted: Callable[[str], bool] | None = None, max_members: int = MAX_MEMBERS,
                max_member_bytes: int = MAX_MEMBER_BYTES, max_total: int = MAX_TOTAL_BYTES) -> Iterator[tuple[str, bytes]]:
    """Stream a .tar.xz in memory and yield (name, bytes) of the regular members ``wanted`` keeps.

    Nothing is written to disk. Raises ArchiveError on absolute or '..' names, links, devices and
    other special members, and when the member count, a member size or the total size exceeds its
    cap. (The core ``safe_extract`` covers gz/bz2/zip only: tar/xz support is a core request.)"""
    count = total = 0
    try:
        with lzma.open(path, "rb") as xz, tarfile.open(fileobj=xz, mode="r|") as tf:
            for member in tf:
                name = member.name
                parts = [p for p in name.replace("\\", "/").split("/") if p]
                if not name or name.startswith(("/", "\\")) or ".." in parts or re.match(r"^[A-Za-z]:", name) or "\x00" in name:
                    raise ArchiveError(f"unsafe member name {name[:80]!r}")
                if member.isdir():
                    continue
                if not member.isfile():
                    raise ArchiveError(f"unsafe member type in {name[:80]!r} (link or special file)")
                count += 1
                if count > max_members:
                    raise ArchiveError(f"too many members (> {max_members})")
                if member.size > max_member_bytes:
                    raise ArchiveError(f"member {name[:80]!r} too large ({member.size} > {max_member_bytes} bytes)")
                total += member.size
                if total > max_total:
                    raise ArchiveError(f"archive expands beyond {max_total} bytes")
                if wanted is not None and not wanted(name):
                    continue
                fh = tf.extractfile(member)
                data = fh.read(max_member_bytes + 1) if fh is not None else b""
                if len(data) > max_member_bytes:
                    raise ArchiveError(f"member {name[:80]!r} larger than declared")
                yield name, data
    except ArchiveError:
        raise
    except (tarfile.TarError, lzma.LZMAError, zlib.error, EOFError, OSError, ValueError) as exc:
        raise ArchiveError(f"corrupt archive: {type(exc).__name__}: {exc}") from None


def member_day(name: str) -> str | None:
    """'exit-list-2026-10/31/2026-10-31-04-12-27' -> '2026-10-31' (None for foreign names)."""
    m = _MEMBER_RE.search(name or "")
    if not m or (m.group(1), m.group(2)) != (m.group(4), m.group(5)) or m.group(3) != m.group(6):
        return None
    return f"{m.group(4)}-{m.group(5)}-{m.group(6)}"


def index_tordnsel(data: bytes, index: dict[str, dict[str, Any]] | None = None) -> dict[str, dict[str, Any]]:
    """Merge one tordnsel exit list into ``index``: ip -> {'days': {YYYY-MM-DD: [first, last]},
    'fingerprints': [...]} (day granularity keeps a month small)."""
    index = {} if index is None else index
    fingerprint = ""
    for m in _RECORD_RE.finditer(data):
        if m.group(1) == b"ExitNode":
            fp = m.group(2).decode("ascii", "replace").upper()
            fingerprint = fp if _FP_RE.match(fp) else ""
            continue
        if not m.group(3):
            continue
        ip = _norm_ip(m.group(2).decode("ascii", "replace"))
        if ip is None:
            continue
        day = m.group(3).decode()
        stamp = f"{day} {m.group(4).decode()}"
        entry = index.setdefault(ip, {"days": {}, "fingerprints": []})
        span = entry["days"].setdefault(day, [stamp, stamp])
        span[0] = min(span[0], stamp)
        span[1] = max(span[1], stamp)
        if fingerprint and fingerprint not in entry["fingerprints"] and len(entry["fingerprints"]) < 20:
            entry["fingerprints"].append(fingerprint)
    return index


def _validate_archive(path: Path) -> bool:
    for name, data in iter_tar_xz(path, max_members=MAX_MEMBERS):
        if member_day(name) is None or b"@type tordnsel" not in data[:4096]:
            raise ValueError(f"not a CollecTor exit-list archive (first member {name[:60]!r})")
        return True
    raise ValueError("empty archive")


def _validate_mthcht(path: Path) -> bool:
    with open(path, "rb") as fh:
        head = fh.read(65536)
        fh.seek(max(0, path.stat().st_size - 16))
        tail = fh.read()
    if not head.lstrip().startswith(b"{") or b'"ips"' not in head or not tail.rstrip().endswith(b"}"):
        raise ValueError("not the mthcht tor_nodes_history.json document")
    return True


def collector_name(year: int, month: int) -> str:
    return f"tor_exit_history.collector_{year:04d}-{month:02d}.tar.xz"


def register_collector_month(year: int, month: int, *, current: bool = False) -> str:
    """Register the CollecTor archive of one month (idempotent; same name, same URL)."""
    return register_dataset(
        collector_name(year, month),
        COLLECTOR_URL.format(y=year, m=month),
        ttl=86400 if current else 30 * 86400,
        description=f"CollecTor exit lists of {year:04d}-{month:02d} (tordnsel records, monthly tar.xz); fetched by `v3lum data update` only",
        licence="CC0-1.0",
        terms_class="open",
        attribution=TOR_ATTRIBUTION,
        provider="torproject",
        source=COLLECTOR_SOURCE,
        validate=_validate_archive,
        min_bytes=10_000,
        expect="bytes",
        max_bytes=64 * 1024 * 1024,
        large=True,
    )


def window_months(today: date, size: int = WINDOW_MONTHS) -> list[tuple[int, int]]:
    """The current month first, then the ``size - 1`` previous months."""
    out = []
    y, m = today.year, today.month
    for _ in range(size):
        out.append((y, m))
        y, m = (y - 1, 12) if m == 1 else (y, m - 1)
    return out


_TODAY = datetime.now(timezone.utc).date()
COLLECTOR_MONTHS = [register_collector_month(y, m, current=(i == 0)) for i, (y, m) in enumerate(window_months(_TODAY))]
MTHCHT_HISTORY = register_dataset(
    "tor_exit_history.mthcht_tor_nodes_history.json",
    MTHCHT_URL,
    ttl=7 * 86400,
    description="mthcht/awesome-lists Tor node history (relay presence periods per IP, 2007 onwards, 54 MB); fetched by `v3lum data update` only",
    licence="MIT",
    terms_class="open",
    attribution="Tor node history from mthcht/awesome-lists (https://github.com/mthcht/awesome-lists, MIT), derived from Tor Project data",
    provider="github",
    source=MTHCHT_SOURCE,
    validate=_validate_mthcht,
    min_bytes=1_000_000,
    expect="bytes",
    max_bytes=256 * 1024 * 1024,
    large=True,
)

_INDEX_LOCK = threading.Lock()
_INDEXES: dict[tuple[str, str, frozenset[str]], dict[str, dict[str, Any]]] = {}


def collector_index(path: Path, sha256: str, days: frozenset[str]) -> dict[str, dict[str, Any]]:
    """Exit addresses of the archive members of ``days`` (cached per archive version and days)."""
    key = (str(path), sha256, days)
    with _INDEX_LOCK:
        hit = _INDEXES.get(key)
    if hit is not None and sha256:
        return hit
    index: dict[str, dict[str, Any]] = {}
    for _name, data in iter_tar_xz(path, wanted=lambda n: member_day(n) in days):
        index_tordnsel(data, index)
    with _INDEX_LOCK:
        if len(_INDEXES) > 32:
            _INDEXES.clear()
        _INDEXES[key] = index
    return index


def mthcht_meta(path: Path) -> dict[str, Any]:
    """Metadata block of tor_nodes_history.json (keys before "ips"): updated, range."""
    with open(path, "rb") as fh:
        head = fh.read(65536).decode("utf-8", "replace")
    idx = head.find('"ips"')
    if idx < 0:
        return {}
    try:
        meta = json.loads(head[:idx].rstrip().rstrip(",") + "}")
    except ValueError:
        return {}
    rng = meta.get("range") if isinstance(meta, dict) and isinstance(meta.get("range"), list) else []
    days = [_day(v) for v in rng[:2]] if len(rng) >= 2 else [None, None]
    return {"updated": meta.get("updated") if isinstance(meta.get("updated"), str) else "", "range": days}


def mthcht_entry(path: Path, ip: str) -> dict[str, Any] | None:
    """The mthcht record of ``ip`` (relay periods, role at last sighting, fingerprint, AS) found by
    a byte search of the 54 MB single-line JSON - no full parse; the rDNS 'host' is never kept."""
    needle = f'"{ip}":'.encode()
    with open(path, "rb") as fh:
        if path.stat().st_size == 0:
            return None
        with mmap.mmap(fh.fileno(), 0, access=mmap.ACCESS_READ) as mm:
            pos = mm.find(needle)
            if pos < 0:
                return None
            start = pos + len(needle)
            chunk = mm[start:start + 65536].decode("utf-8", "replace")
    try:
        value, _end = json.JSONDecoder().raw_decode(chunk.lstrip())
    except ValueError:
        return None
    if not isinstance(value, dict):
        return None
    meta = value.get("m") if isinstance(value.get("m"), dict) else {}
    periods = []
    for item in value.get("p") or []:
        if isinstance(item, list) and len(item) == 2 and _day(item[0]) and _day(item[1]):
            periods.append((_day(item[0]), _day(item[1])))
    fp = meta.get("fp").upper() if isinstance(meta.get("fp"), str) else ""
    asn = meta.get("as") if isinstance(meta.get("as"), str) and re.fullmatch(r"AS\d+", str(meta.get("as"))) else ""
    return {
        "periods": periods,
        "role": meta.get("role") if isinstance(meta.get("role"), str) else "unknown",
        "fingerprint": fp if _FP_RE.match(fp) else "",
        "nickname": (meta.get("nick") if isinstance(meta.get("nick"), str) else "")[:64],
        "asn": asn,
    }


def _day(value: Any) -> str | None:
    if isinstance(value, datetime):
        return value.astimezone(timezone.utc).strftime("%Y-%m-%d")
    if isinstance(value, date):
        return value.isoformat()
    if isinstance(value, str):
        text = value.strip()[:10]
        if _DAY_RE.match(text):
            try:
                date.fromisoformat(text)
            except ValueError:
                return None
            return text
    return None


def requested_dates(ctx: Any) -> tuple[list[str], list[str]]:
    """(valid dates, rejected values) of setting tor_exit_history_dates (future dates rejected)."""
    raw = ctx.setting("tor_exit_history_dates", []) or []
    if isinstance(raw, str):
        raw = [p for p in re.split(r"[,\s]+", raw) if p]
    today = ctx.now().date()
    good: list[str] = []
    bad: list[str] = []
    for item in raw if isinstance(raw, list) else []:
        day = _day(item)
        if day is None or date.fromisoformat(day) > today:
            bad.append(str(item)[:40])
        elif day not in good:
            good.append(day)
    return sorted(good)[:MAX_DATES], bad


@register
class TorExitHistory(Module):
    name = "tor_exit_history"
    title = "Tor exit history on a date (CollecTor, local)"
    description = (
        "Was the IP a Tor exit on the date of the event? Answered locally from the CollecTor exit-list archives "
        "and the mthcht Tor node history fetched by `v3lum data update`; the date comes from setting "
        "tor_exit_history_dates."
    )
    category = "ip_network"
    accepts = {T.IPV4, T.IPV6}
    produces = frozenset()
    terms = "open"
    opsec = Opsec.PASSIVE
    disclosure = "none"
    hosts = ()
    sources = (COLLECTOR_SOURCE, MTHCHT_SOURCE)
    reference = "https://metrics.torproject.org/collector.html"
    notice = (
        f"Dated check only (setting tor_exit_history_dates, YYYY-MM-DD). {TOR_EXIT_NOTE}. The monthly CollecTor "
        "archives and the mthcht history are large: run `v3lum data update` first."
    )
    manual_link = "tor_relays:exonerator"
    tags = {"offline", "free"}
    max_pivots = 0
    timeout = 120.0
    #: Opt-in (-M tor_exit_history / --preset deep): the check needs the event date the analyst gives and
    #: ~130 MB of history from `v3lum data update`; as a default module the dataset gate would add a
    #: 'could not verify' line to every IP scan without a date. The current exit check (tor_exit_local,
    #: tor_onionoo) stays in the default set.
    default_enabled = False
    settings = {
        "tor_exit_history_dates": SettingSpec(
            [], "date(s) of the event (YYYY-MM-DD) for the dated Tor exit check of tor_exit_history; empty = no dated check"
        ),
    }

    def applies(self, entity: Entity, ctx: Any) -> bool:
        if special_purpose(entity.value) is not None:
            return False
        good, bad = requested_dates(ctx)
        return bool(good or bad)

    def run(self, entity: Entity, ctx: Any) -> ModuleResult:
        res = self.result(entity)
        ip = _norm_ip(entity.value) or entity.value
        dates, rejected = requested_dates(ctx)
        if not dates:
            return res.mark(Status.ERROR, f"setting tor_exit_history_dates holds no usable date ({', '.join(rejected)}): use YYYY-MM-DD, not in the future", reason_code="error")
        answers: list[dict[str, Any]] = []
        mthcht = self._mthcht(ctx, ip)
        for day in dates:
            answers.append(self._collector(ctx, ip, day))
            if mthcht is not None:
                answers.append(_mthcht_answer(mthcht, day))
        res.attr("tor_exit_history", answers)
        res.raw = {"dates": dates, "rejected": rejected, "answers": answers}
        for day in dates:
            res.link(f"ExoneraTor on {day} (Tor Metrics)", exonerator_link(ip, day))
        for ans in answers:
            if ans["state"] == "was_exit":
                res.finding(
                    "Tor exit on the date checked (CollecTor)",
                    "low",
                    f"{ans['text']}: ExitAddress observed {ans['observed_first']} - {ans['observed_last']} UTC. {TOR_EXIT_NOTE}. "
                    "Context only: never malicious on its own and never higher without other evidence (CR28).",
                    confidence="confirmed",
                    criterion=f"CollecTor tordnsel ExitAddress record for this IP on {ans['date']} (local archive)",
                    data={"date": ans["date"], "fingerprints": ans.get("fingerprints", [])},
                    tags=["anonymizer", "tor", "context_only"],
                    references=["https://metrics.torproject.org/collector.html"],
                    source=COLLECTOR_SOURCE,
                    observed_first=ans["observed_first"].replace(" ", "T") + "Z",
                    observed_last=ans["observed_last"].replace(" ", "T") + "Z",
                    attack=["T1090.003"],
                    key=ans["date"],
                )
            elif ans["state"] == "relay_on_date":
                res.finding(
                    "Tor relay on the date checked (mthcht history)",
                    "info",
                    f"{ans['text']}. Relay periods only: CollecTor stays the authority for 'was an exit'.",
                    confidence="probable",
                    data={"date": ans["date"], "role_at_last_sighting": ans.get("role")},
                    tags=["tor", "context_only"],
                    source=MTHCHT_SOURCE,
                    key=ans["date"],
                )
        verified = [a for a in answers if a["state"] not in ("not_downloaded", "could_not_verify", "outside_window")]
        if not verified:
            reasons = "; ".join(sorted({f"{a['source']} {a['date']}: {a['text']}" for a in answers}))
            return res.mark(Status.UNAVAILABLE, f"{reasons}: could not verify, never 'not an exit'", reason_code="dataset")
        return res

    # ------------------------------------------------------------------ CollecTor
    def _collector(self, ctx: Any, ip: str, day: str) -> dict[str, Any]:
        base = {"date": day, "source": "CollecTor", "observed_first": "", "observed_last": "", "fingerprints": []}
        if COLLECTOR_SOURCE not in ctx.allowed_sources:
            return {**base, "state": "could_not_verify", "text": "CollecTor not allowed by the licence profile"}
        if ":" in ip:
            return {**base, "state": "could_not_verify", "text": f"could not verify {day}: CollecTor exit lists record IPv4 exit addresses only"}
        d = date.fromisoformat(day)
        name = collector_name(d.year, d.month)
        if name not in DATASETS:
            return {**base, "state": "outside_window", "text": f"{day} is outside the CollecTor window of {WINDOW_MONTHS} months (see the ExoneraTor link)"}
        try:
            path, info = local_dataset(ctx, name)
        except DatasetError:
            return {**base, "state": "not_downloaded", "text": f"{HISTORY_NOT_DOWNLOADED.removesuffix(')')} {name})"}
        days = frozenset({day, (d + timedelta(days=1)).isoformat()})
        try:
            index = collector_index(path, info.sha256, days)
            nxt = d + timedelta(days=1)
            nxt_name = collector_name(nxt.year, nxt.month)
            if nxt.month != d.month and nxt_name in DATASETS and ctx.data.info(nxt_name).present:
                npath, ninfo = local_dataset(ctx, nxt_name)
                for nip, entry in collector_index(npath, ninfo.sha256, frozenset({nxt.isoformat()})).items():
                    merged = index.setdefault(nip, {"days": {}, "fingerprints": []})
                    merged["days"].update({k: v for k, v in entry["days"].items() if k not in merged["days"]})
        except (ArchiveError, OSError, DatasetError) as exc:
            return {**base, "state": "could_not_verify", "text": f"could not verify {day}: CollecTor archive unreadable ({exc})"}
        entry = index.get(ip)
        span = entry["days"].get(day) if entry else None
        if span:
            return {**base, "state": "was_exit", "text": f"was an exit on {day}, CollecTor", "observed_first": span[0],
                    "observed_last": span[1], "fingerprints": list(entry["fingerprints"])}
        return {**base, "state": "not_exit_on_date", "text": f"no exit record on {day} (CollecTor, month downloaded)"}

    # ------------------------------------------------------------------ mthcht
    def _mthcht(self, ctx: Any, ip: str) -> dict[str, Any] | None:
        if MTHCHT_SOURCE not in ctx.allowed_sources:
            return None
        try:
            path, _info = local_dataset(ctx, MTHCHT_HISTORY)
        except DatasetError:
            return {"present": False}
        try:
            return {"present": True, "meta": mthcht_meta(path), "entry": mthcht_entry(path, ip)}
        except (OSError, ValueError) as exc:
            return {"present": True, "error": f"{type(exc).__name__}: {exc}"}


def _mthcht_answer(mthcht: dict[str, Any], day: str) -> dict[str, Any]:
    base = {"date": day, "source": "mthcht Tor history", "observed_first": "", "observed_last": ""}
    if not mthcht.get("present"):
        return {**base, "state": "not_downloaded", "text": f"{HISTORY_NOT_DOWNLOADED.removesuffix(')')} {MTHCHT_HISTORY})"}
    if mthcht.get("error"):
        return {**base, "state": "could_not_verify", "text": f"could not verify {day}: mthcht history unreadable ({mthcht['error']})"}
    low, high = (mthcht.get("meta") or {}).get("range") or [None, None]
    if low and high and not (low <= day <= high):
        return {**base, "state": "could_not_verify", "text": f"could not verify {day}: outside the mthcht history range {low}..{high}"}
    entry = mthcht.get("entry")
    if not entry:
        return {**base, "state": "not_relay", "text": f"not a known Tor relay address (mthcht Tor history, checked {day})"}
    role = entry.get("role") or "unknown"
    for first, last in entry.get("periods", []):
        if first <= day <= last:
            return {**base, "state": "relay_on_date", "role": role, "observed_first": first, "observed_last": last,
                    "text": f"was a Tor relay on {day} (role at last sighting: {role}), mthcht Tor history"}
    return {**base, "state": "not_relay_on_date", "role": role, "text": f"no Tor relay period covers {day} (mthcht Tor history)"}
