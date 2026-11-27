"""Onion safety helpers shared by the darkweb modules (P199 cond 2-4; P198 cond 3 and 5).

P199 cond 2 places a safety filter ``is_banned_onion()`` in the core: Ahmia's banned/abuse list (md5 of
the onion domain, one per line, offered by Ahmia for filtering its own index) is a registered dataset
refreshed at most daily, and every module applies it before any onion is displayed, stored, enriched
or fetched. Batches cannot edit ``v3lum/core``, so this file is the stand-in until the core adopts it
(core request in docs/backlog/p2-G09-1.md): the dataset is registered here and modules import
:func:`is_banned_onion` and :func:`add_banned_finding` from here.

* A hit shows only "onion on Ahmia's abuse (banned) list: details withheld" (P199 cond 3): one finding
  with that text, no attributes, no pivots, no raw evidence, and the onion is never enriched further.
* No list available -> :func:`is_banned_onion` returns ``None`` and callers fail closed (no details,
  no enrichment, no request).
* Onion v3 checksums are checked with the core validator (P217, ``v3lum.core.validators.onion_valid``).

The core HTTP layer already refuses ``.onion`` hosts outside a LIGHT Tor ``proxy_light`` (WP11); the
DNS layer does not yet (P199 cond 4, core request). Modules here never resolve or fetch onions.
"""

from __future__ import annotations

import hashlib
import re
import threading
import time
from pathlib import Path
from typing import Any
from urllib.parse import urlsplit

from v3lum.core.datasets import DatasetError, DatasetUnavailable, register_dataset
from v3lum.core.validators import onion_valid

AHMIA_SOURCE = "ahmia.banned_list"
AHMIA_DATASET = "ahmia_banned_onions"
AHMIA_BANNED_URL = "https://ahmia.fi/blacklist/banned/"
AHMIA_EVIDENCE_URL = "https://ahmia.fi/blacklist/"
#: Ahmia search is manual-only (rotating form token, ToS: no scraping; P199 cond 5)
AHMIA_SEARCH_URL = "https://ahmia.fi/"
BANNED_ONION_TEXT = "onion on Ahmia's abuse (banned) list: details withheld"
#: a list with fewer md5 lines is not installed (60,407 lines on 2026-11-26); tests lower it
MIN_HASHES = 10000
ATTRIBUTION = "Ahmia abuse (banned) onion filter list (ahmia.fi/blacklist), used for filtering as Ahmia offers it"

_MD5_RE = re.compile(r"^[0-9a-f]{32}$")
_LABEL_RE = re.compile(r"^[a-z2-7]{16}$|^[a-z2-7]{56}$")


# ------------------------------------------------------------------ onion host helpers
def onion_host(value: Any) -> str:
    """Lower-case host of a URL or host string (port, userinfo and trailing dot removed), '' if none."""
    text = str(value or "").strip()
    if not text:
        return ""
    if "://" not in text:
        text = "http://" + text.lstrip("/")
    try:
        host = urlsplit(text).hostname or ""
    except ValueError:
        return ""
    return host.rstrip(".").lower()


def is_onion_hostname(value: Any) -> bool:
    """True for any ``.onion`` host or URL, valid or not (P199 cond 4: never resolved or fetched)."""
    host = onion_host(value)
    return host == "onion" or host.endswith(".onion")


def onion_service_domain(value: Any) -> str | None:
    """``'<56-char label>.onion'`` for a valid v3 onion (URL, host or subdomain; checksum checked with the
    core validator), else None: invalid or v2 onions are never sent anywhere (P199 cond 1)."""
    host = onion_host(value)
    if not host.endswith(".onion"):
        return None
    label = host[: -len(".onion")].rsplit(".", 1)[-1]
    domain = f"{label}.onion"
    return domain if len(label) == 56 and onion_valid(domain) else None


def onion_ban_hashes(value: Any) -> list[str]:
    """md5 keys to test against Ahmia's list: the onion service domain ('<label>.onion', any onion
    version, checksum not required) and the full host when it has subdomains, so a 'www.' prefix cannot
    dodge the filter. Ahmia: 'Onion addresses are masked by creating an MD5 sum of the onion domain'
    (md5('abcdefghijklmnop.onion') = c50b9578b6357a561909ff29331ad7ad)."""
    host = onion_host(value)
    if not host.endswith(".onion"):
        return []
    labels = host.split(".")
    candidates = []
    if len(labels) >= 2 and _LABEL_RE.match(labels[-2]):
        candidates.append(".".join(labels[-2:]))
    candidates.append(host)
    out: list[str] = []
    for candidate in candidates:
        digest = hashlib.md5(candidate.encode("utf-8"), usedforsecurity=False).hexdigest()
        if digest not in out:
            out.append(digest)
    return out


# ------------------------------------------------------------------ the Ahmia banned list
def parse_ahmia_banned(text: str, *, min_hashes: int | None = None) -> dict[str, Any]:
    """Ahmia banned list -> {'status': 'ok'|'invalid', 'hashes': frozenset, 'count', 'reason'}.
    'invalid' (HTML, a junk line, fewer than ``min_hashes`` lines) means the copy is not used."""
    floor = MIN_HASHES if min_hashes is None else min_hashes
    body = str(text or "")
    out: dict[str, Any] = {"status": "invalid", "hashes": frozenset(), "count": 0, "reason": ""}
    if not body.strip():
        out["reason"] = "Ahmia banned list is empty"
        return out
    if "<" in body[:2048]:
        out["reason"] = "Ahmia banned list answered HTML instead of md5 lines"
        return out
    hashes: set[str] = set()
    for line in body.splitlines():
        item = line.strip().lower()
        if not item:
            continue
        if not _MD5_RE.match(item):
            out["reason"] = "Ahmia banned list has a line that is not an md5 digest"
            return out
        hashes.add(item)
    out.update(hashes=frozenset(hashes), count=len(hashes))
    if len(hashes) < floor:
        out["reason"] = f"Ahmia banned list has {len(hashes)} hashes (< expected {floor})"
        return out
    out["status"] = "ok"
    return out


def _validate(path: Path) -> bool:
    """register_dataset(validate=): refuse an HTML page, junk lines or a shrunken list (the previous copy is
    kept and served, AR10)."""
    parsed = parse_ahmia_banned(Path(path).read_text(encoding="utf-8", errors="replace"))
    if parsed["status"] != "ok":
        raise ValueError(parsed["reason"])
    return True


register_dataset(
    AHMIA_DATASET,
    AHMIA_BANNED_URL,
    ttl=86400,
    description="Ahmia abuse (banned) onion list: md5 of the onion domain, one per line; safety filter applied before any onion is shown, stored, enriched or fetched (P199 cond 2)",
    licence="LicenseRef-Ahmia-abuse-filter-offer (filtering use offered by Ahmia on ahmia.fi/blacklist/)",
    terms_class="open",
    attribution=ATTRIBUTION,
    provider="ahmia",
    source=AHMIA_SOURCE,
    validate=_validate,
    min_bytes=32,
    expect="lines",
    max_bytes=5_000_000,
    large=False,
    essential=True,
)

_MEMO: dict[str, tuple[tuple[int, int], frozenset[str] | None]] = {}
_FAILED: dict[str, float] = {}
_LOCK = threading.Lock()
#: a dataset whose download failed (and that has no local copy) is not retried for an hour in this process
RETRY_AFTER = 3600.0


def fetch_dataset(ctx: Any, name: str, kind: str = "path") -> Any:
    """``ctx.data.fetch`` / ``fetch_text`` / ``fetch_json`` (kind 'path' | 'text' | 'json') with an in-process
    back-off: a dataset that could not be downloaded and has no local copy is not retried by every run for an
    hour (a dead mirror never costs each lookup a request). Raises DatasetError/DatasetUnavailable."""
    now = time.monotonic()
    with _LOCK:
        failed = _FAILED.get(name)
    if failed is not None and now - failed < RETRY_AFTER and not ctx.data.info(name).present:
        raise DatasetUnavailable(name, f"dataset {name} could not be downloaded in the last hour: run v3lum data update {name}")
    try:
        if kind == "text":
            return ctx.data.fetch_text(name)
        if kind == "json":
            return ctx.data.fetch_json(name)
        return ctx.data.fetch(name)
    except (DatasetError, DatasetUnavailable):
        with _LOCK:
            _FAILED[name] = now
        raise


def _hashes_from(path: Path) -> frozenset[str] | None:
    st = Path(path).stat()
    stamp = (st.st_mtime_ns, st.st_size)
    with _LOCK:
        cached = _MEMO.get(str(path))
        if cached is not None and cached[0] == stamp:
            return cached[1]
    parsed = parse_ahmia_banned(Path(path).read_text(encoding="utf-8", errors="replace"))
    hashes = parsed["hashes"] if parsed["status"] == "ok" else None
    with _LOCK:
        _MEMO[str(path)] = (stamp, hashes)
    return hashes


def banned_hashes(ctx: Any) -> frozenset[str] | None:
    """The local Ahmia list as a set of md5 digests (cited in ``res.datasets``), or None when no usable
    copy exists (never downloaded and the download failed, or the copy does not parse): fail closed."""
    try:
        path = fetch_dataset(ctx, AHMIA_DATASET)
    except (DatasetError, DatasetUnavailable, OSError, ValueError):
        return None
    try:
        return _hashes_from(Path(path))
    except OSError:
        return None


def is_banned_onion(value: Any, ctx: Any = None, *, banned: frozenset[str] | None = None) -> bool | None:
    """Safety filter (P199 cond 2): True when the onion's md5 is on Ahmia's banned list, False when it is
    not, None when the list is unavailable (callers fail closed: nothing displayed, enriched or fetched).
    Values that are not onion hosts are never banned (False)."""
    if not is_onion_hostname(value):
        return False
    if banned is None and ctx is not None:
        banned = banned_hashes(ctx)
    if not banned:
        return None
    return any(digest in banned for digest in onion_ban_hashes(value))


def add_banned_finding(res: Any) -> Any:
    """P199 cond 3: the only thing a banned onion gets - one finding with the fixed text. No attributes,
    pivots, links or raw evidence are added; the caller stops there (never enriched or fetched)."""
    res.finding(
        BANNED_ONION_TEXT,
        "high",
        BANNED_ONION_TEXT,
        confidence="probable",
        criterion="md5 of the onion domain is on Ahmia's abuse (banned) filter list",
        tags=["banned_onion", "suspicious"],
        source=AHMIA_SOURCE,
    )
    res.raw = None
    return res


__all__ = [
    "AHMIA_BANNED_URL",
    "AHMIA_DATASET",
    "AHMIA_EVIDENCE_URL",
    "AHMIA_SEARCH_URL",
    "AHMIA_SOURCE",
    "BANNED_ONION_TEXT",
    "add_banned_finding",
    "banned_hashes",
    "fetch_dataset",
    "is_banned_onion",
    "is_onion_hostname",
    "onion_ban_hashes",
    "onion_host",
    "onion_service_domain",
    "parse_ahmia_banned",
]
