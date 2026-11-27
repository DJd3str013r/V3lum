"""Newly registered / released domain feeds (P005): WhoisDS and registro.br lists matched locally.

Modules of this file (one source family, one matcher):

* ``nrd_feeds`` - the default module: the WhoisDS free daily list of newly registered domains (terms
  open: 'may be reused, including for commercial purposes') and the registro.br release list
  ``lista-processo-liberacao.txt`` (open; NIC.br), both registered datasets matched on this machine.
* ``nrd_smet`` - the smet.cz ``today.txt`` list as a separate dataset source with terms 'unknown': off by
  default and disabled in every licence profile until legal records its terms (cond 2). Its dataset is
  registered (and so downloaded by ``v3lum data update``) only once the registry class of
  ``smet.nrd_today`` is no longer 'unknown'.

Final conditions (council #1, P005) and where they live:

1. Local matching (disclosure ``none``) against the registered datasets; lists are never redistributed.
2. smet.cz split out as ``nrd_smet``; ICANN CZDS deferred (docs/backlog/p2-G01-1.md).
3/4. DomainsDB keyword search is the separate module ``domainsdb_search`` (its own file).
5. Lists are fetched only by ``v3lum data update`` (datasets ``large=True``: never downloaded during a
   scan). A missing or more than 48 h old list (:data:`MAX_AGE_HOURS`, measured on the local copy) gives
   UNAVAILABLE ``dataset`` ('NRD lists not downloaded/stale'), never EMPTY; a feed that cannot be used
   while another answered is reported per source (``res.source_status``). A challenge page, an empty
   file or a list below :data:`MIN_NAMES` never replaces the last good copy (``validate=`` hooks; the
   dataset manager keeps the previous copy).
6. WhoisDS zips go through the core ``safe_extract`` helper at download time with the condition's
   limits (:func:`validate_whoisds_zip`: at most 3 members, <= 50 MB uncompressed, ratio cap 100x, only
   the member named ``domain-names.txt`` is taken); at scan time the stored zip is read in memory
   (:func:`read_zip_member`, same limits, member names only compared, never used as paths). The
   registro.br file is decoded as ISO-8859-1 and '#' lines are comments.
7. Rolling 30-day window: one dataset per WhoisDS list date (``whoisds_nrd.YYYY-MM-DD``; the four dates
   the free page offers are registered at import, older local copies are read in place), first_seen =
   list date. The first_seen diffing for ``v3lum watch`` alerts (P030) is persisted by the watch engine
   in the case DB (``watch_first_seen``): this module reports every match with its list date
   (``watch_hits``) and keeps no state of its own.
8. Brand matching uses only org_profile brands and domains (P378) and the shared P012 permutation helper
   (``typosquat_permutations``: candidate generation incl. pt-BR combo-squats with lure words and accent
   homoglyphs, and the reverse lookalike matcher). No brand or keyword leaves the machine.
9. ``newly_registered`` (and ``typosquat`` for a brand match) is tagged only after DoH confirms an A or a
   non-null MX answer, at most 100 confirmations per run (:data:`DOH_CAP`). As a disclosure-``none``
   module this module may use only the organisation's internal resolver (setting ``doh_internal``;
   public DoH is refused to offline modules by the core): without one, hits stay untagged with 'could
   not verify'. registro.br hits are tagged ``in_release``, never ``newly_registered``. An NRD hit alone
   is LOW; it rises to MEDIUM only with a brand match plus MX (a fresh certificate, P028, is the CT
   modules' signal and their correlation's decision).
10. Miss wording: 'not in the last N days of WhoisDS lists (gTLD coverage only)', never 'not newly
    registered'; for .br: 'no NRD feed for .br: CT + permutations + DoH only'.
11. Tests: ``tests/modules/test_nrd_feeds.py`` (local match, DoH-confirmed tagging, stale UNAVAILABLE,
    zip bomb / members / unsafe names, challenge pages never replacing the last good copy).
"""

from __future__ import annotations

import base64
import io
import re
import stat
import tempfile
import threading
import zipfile
from collections.abc import Iterable, Mapping
from datetime import date, datetime, timedelta, timezone
from pathlib import Path
from typing import Any

from v3lum.config import SettingSpec
from v3lum.core import psl
from v3lum.core.datasets import DATASETS, DatasetError, register_dataset, safe_extract
from v3lum.core.entities import Entity
from v3lum.core.entities import EntityType as T
from v3lum.core.models import ModuleResult, Opsec, Status
from v3lum.core.module import Module, register
from v3lum.modules.domain_dns import typosquat_permutations as perm

WHOISDS_SOURCE = "whoisds.nrd_daily"
RELEASE_SOURCE = "registrobr.release_list"
SMET_SOURCE = "smet.nrd_today"
WHOISDS_URL = "https://www.whoisds.com//whois-database/newly-registered-domains/{token}/nrd"
RELEASE_URL = "https://registro.br/dominio/lista-processo-liberacao.txt"
SMET_URL = "https://smet.cz/nrd/data/today.txt"
WHOISDS_PREFIX = "whoisds_nrd."
RELEASE_DATASET = "registrobr_release_list.txt"
SMET_DATASET = "smet_nrd_today.txt"
MEMBER = "domain-names.txt"
#: cond 7: rolling window of daily lists; the WhoisDS free page offers the last FREE_DAYS list dates
WINDOW_DAYS = 30
FREE_DAYS = 4
#: cond 5: a list whose local copy is older than this is stale (UNAVAILABLE 'dataset')
MAX_AGE_HOURS = 48.0
#: cond 5: a download with fewer names never replaces the cached copy (real: 70,000 / 125,922 / 139,927)
MIN_NAMES = 1000
#: cond 6: archive limits
ZIP_MAX_MEMBERS = 3
ZIP_MAX_TOTAL = 50 * 1024 * 1024
ZIP_MAX_RATIO = 100
#: cond 9: DoH confirmations per run
DOH_CAP = 100
#: hits kept per run (attribute, pivots, per-hit findings)
MAX_HITS = 200
MAX_PIVOTS = 100
MAX_HIT_FINDINGS = 50
LIST_LICENCE = "WhoisDS free newly registered domains list: free reuse incl. commercial; never redistributed"
WHOISDS_ATTRIBUTION = "Newly registered domains list from WhoisDS.com (free daily list)"
RELEASE_ATTRIBUTION = "Registro.br (NIC.br): lista de dominios em processo de liberacao"
NOT_DOWNLOADED = "NRD lists not downloaded/stale - run v3lum data update"

_CTRL_RE = re.compile(r"[\x00-\x08\x0b-\x1f\x7f-\x9f]")
_NAME_RE = re.compile(r"^[^\s/\\:@*?#<>\"']{1,253}\.[^\s/\\:@*?#<>\"'.]{2,63}$")
_WINDOW_RE = re.compile(r"per\S{1,2}odo de (\d{4}-\d{2}-\d{2}T[\d:]+[+-]\d{2}:\d{2}) a (\d{4}-\d{2}-\d{2}T[\d:]+[+-]\d{2}:\d{2})", re.I)
_GENERATED_RE = re.compile(r"gerado em (\d{4}-\d{2}-\d{2}T[\d:]+[+-]\d{2}:\d{2})", re.I)
_TEXT_LOCK = threading.Lock()
_TEXTS: dict[str, tuple[str, str]] = {}
_TEXT_CACHE_MAX = 40
_RELEASE_META: dict[str, dict[str, Any]] = {}
#: TTL passed when reading local copies: the module never downloads (cond 5); staleness is checked on fetched_at
_LOCAL_ONLY_TTL = 10 * 365 * 86400


class ZipProblem(ValueError):
    """An archive that breaks the cond 6 limits (read in memory at scan time)."""


# --------------------------------------------------------------------------------------
# list dates, URLs and dataset registration
# --------------------------------------------------------------------------------------


def whoisds_url(day: date) -> str:
    """Daily list URL: the base64 of 'YYYY-MM-DD.zip' (research C0022)."""
    token = base64.b64encode(f"{day.isoformat()}.zip".encode("ascii")).decode("ascii")
    return WHOISDS_URL.format(token=token)


def whoisds_name(day: date) -> str:
    return f"{WHOISDS_PREFIX}{day.isoformat()}"


def window_days(today: date, days: int = WINDOW_DAYS) -> list[date]:
    """The list dates of the window, newest first: each list is published the day after its date."""
    return [today - timedelta(days=i) for i in range(1, max(1, int(days)) + 1)]


def _is_html(head: bytes) -> bool:
    text = head[:2048].lstrip().lower()
    return text.startswith((b"<!doctype", b"<html", b"<head", b"<body")) or b"<html" in text[:512]


def count_names(text: str) -> int:
    """Lines that look like host names (cheap check for the validation floor; never raises)."""
    return sum(1 for line in text.splitlines() if _NAME_RE.match(line.strip()))


def read_zip_member(data: bytes, member: str = MEMBER, *, max_members: int = ZIP_MAX_MEMBERS, max_total: int = ZIP_MAX_TOTAL,
                    max_ratio: int = ZIP_MAX_RATIO) -> str:
    """The text of one member of an untrusted zip, read in memory with the cond 6 limits.

    At most ``max_members`` members, <= ``max_total`` bytes declared and read, per-member ratio <=
    ``max_ratio`` (above 1 MiB), no encrypted members, links, absolute/'..'/backslash names; the member
    is chosen by comparing names only (never used as a path). Raises :class:`ZipProblem`."""
    if not isinstance(data, (bytes, bytearray)) or bytes(data[:4]) != b"PK\x03\x04":
        raise ZipProblem("not a zip archive")
    try:
        zf = zipfile.ZipFile(io.BytesIO(bytes(data)))
        infos = zf.infolist()
    except (zipfile.BadZipFile, zipfile.LargeZipFile, ValueError, OSError, EOFError) as exc:
        raise ZipProblem(f"corrupt zip archive ({type(exc).__name__})") from None
    if len(infos) > max_members:
        raise ZipProblem(f"zip archive has {len(infos)} members (limit {max_members})")
    if sum(max(i.file_size, 0) for i in infos) > max_total:
        raise ZipProblem(f"zip archive expands beyond {max_total} bytes")
    for info in infos:
        name = info.filename
        if not name or "\x00" in name or "\\" in name or name.startswith("/") or re.match(r"^[A-Za-z]:", name) or ".." in name.split("/"):
            raise ZipProblem("unsafe zip member name")
        if stat.S_IFMT((info.external_attr >> 16) & 0xFFFF) not in (0, stat.S_IFREG, stat.S_IFDIR):
            raise ZipProblem("zip member is a link or special file")
        if info.flag_bits & 0x1:
            raise ZipProblem("encrypted zip member")
        if info.file_size > 1024 * 1024 and info.file_size > max(info.compress_size, 1) * max_ratio:
            raise ZipProblem(f"zip member compression ratio above {max_ratio} (zip bomb?)")
    files = [i for i in infos if not i.is_dir()]
    pick = next((i for i in files if i.filename == member), None)
    if pick is None:
        raise ZipProblem(f"zip archive has no member {member!r}")
    try:
        with zf.open(pick) as fh:
            blob = fh.read(max_total + 1)
    except (zipfile.BadZipFile, OSError, EOFError, RuntimeError, ValueError, NotImplementedError) as exc:
        raise ZipProblem(f"corrupt zip member ({type(exc).__name__})") from None
    if len(blob) > max_total or len(blob) > pick.file_size:
        raise ZipProblem("zip member larger than declared")
    return blob.decode("utf-8", errors="replace")


def validate_whoisds_zip(path: Path) -> bool:
    """``register_dataset(validate=)`` hook (cond 5-6): the core ``safe_extract`` with the condition's
    limits, then a plausible list (>= MIN_NAMES names). Raises with the reason; the previous copy stays."""
    path = Path(path)
    with open(path, "rb") as fh:
        head = fh.read(4096)
    if not head:
        raise ValueError("empty body (the date is outside the free window or not published yet)")
    if _is_html(head):
        raise ValueError("an HTML page came back instead of the zip (challenge or error page?)")
    with tempfile.TemporaryDirectory(prefix=".nrd-check-", dir=str(path.parent)) as tmp:
        try:
            extracted = safe_extract(path, "zip", tmp, max_total=ZIP_MAX_TOTAL, max_ratio=ZIP_MAX_RATIO, max_members=ZIP_MAX_MEMBERS, member=MEMBER)
        except DatasetError as exc:
            raise ValueError(str(exc)) from None
        text = Path(extracted).read_text(encoding="utf-8", errors="replace")
    found = count_names(text)
    if found < MIN_NAMES:
        raise ValueError(f"only {found} names in {MEMBER} (< {MIN_NAMES}): not a daily list")
    return True


def parse_release_list(raw: bytes | str) -> dict[str, Any]:
    """lista-processo-liberacao.txt -> {names, window_start, window_end, generated_at, complete, error}.

    Decoded as ISO-8859-1, '#' lines are comments: the header gives the release window and the generation
    time, the trailer '# Fim do arquivo' proves the transfer was complete (cond 6)."""
    text = bytes(raw).decode("iso-8859-1") if isinstance(raw, (bytes, bytearray)) else str(raw or "")
    out: dict[str, Any] = {"names": [], "window_start": None, "window_end": None, "generated_at": None, "complete": False, "error": None}
    if _is_html(text[:2048].encode("utf-8", "replace")):
        out["error"] = "HTML page instead of the list"
        return out
    names: list[str] = []
    for line in text.splitlines():
        s = line.strip()
        if not s:
            continue
        if s.startswith("#"):
            m = _WINDOW_RE.search(s)
            if m:
                out["window_start"], out["window_end"] = _utc(m.group(1)), _utc(m.group(2))
            m = _GENERATED_RE.search(s)
            if m:
                out["generated_at"] = _utc(m.group(1))
            if re.search(r"fim do arquivo", s, re.I):
                out["complete"] = True
            continue
        name = s.lower().rstrip(".")
        if name.endswith(".br") and _NAME_RE.match(name):
            names.append(name)
    out["names"] = names
    if not out["window_start"]:
        out["error"] = "missing release-window header"
    elif not out["complete"]:
        out["error"] = "truncated list (no '# Fim do arquivo' trailer)"
    elif len(names) < MIN_NAMES:
        out["error"] = f"only {len(names)} names (< {MIN_NAMES})"
    return out


def _utc(value: str) -> str | None:
    try:
        return datetime.fromisoformat(value).astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    except (TypeError, ValueError):
        return None


def validate_release_list(path: Path) -> bool:
    parsed = parse_release_list(Path(path).read_bytes())
    if parsed["error"]:
        raise ValueError(f"registro.br release list rejected: {parsed['error']}")
    return True


def validate_plain_list(path: Path) -> bool:
    data = Path(path).read_bytes()
    if not data.strip():
        raise ValueError("empty list")
    if _is_html(data[:2048]):
        raise ValueError("an HTML page came back instead of the list (challenge or error page?)")
    found = count_names(data.decode("utf-8", errors="replace"))
    if found < MIN_NAMES:
        raise ValueError(f"only {found} names (< {MIN_NAMES}): not a list")
    return True


def register_whoisds_day(day: date) -> str:
    """Register the WhoisDS list of one date (idempotent: same name, same URL)."""
    return register_dataset(
        whoisds_name(day),
        whoisds_url(day),
        ttl=400 * 86400,  # a dated list never changes: a local copy is current until it leaves the window
        description=f"WhoisDS free newly registered domains list of {day.isoformat()} (zip, domain-names.txt); `v3lum data update` only",
        licence=LIST_LICENCE,
        terms_class="open",
        attribution=WHOISDS_ATTRIBUTION,
        provider="whoisds",
        source=WHOISDS_SOURCE,
        validate=validate_whoisds_zip,
        min_bytes=100,
        expect="bytes",
        max_bytes=ZIP_MAX_TOTAL,
        large=True,  # cond 5: never downloaded during a scan
    )


def _register_free_window() -> list[str]:
    today = datetime.now(timezone.utc).date()
    return [register_whoisds_day(day) for day in window_days(today, FREE_DAYS)]


WHOISDS_DATASETS = _register_free_window()

register_dataset(
    RELEASE_DATASET,
    RELEASE_URL,
    ttl=86400,
    description="Registro.br .br domains entering the release process (lista-processo-liberacao.txt, ISO-8859-1); `v3lum data update` only",
    licence="Registro.br public registry notice (NIC.br)",
    terms_class="open",
    attribution=RELEASE_ATTRIBUTION,
    provider="registrobr",
    source=RELEASE_SOURCE,
    validate=validate_release_list,
    min_bytes=1000,
    expect="lines",
    max_bytes=20 * 1024 * 1024,
    large=True,
)


def _smet_terms_class() -> str:
    try:
        from v3lum.core import providers

        src = providers.registry().source(SMET_SOURCE)
        return str(getattr(getattr(src, "terms", None), "class_", "unknown") or "unknown")
    except Exception:  # noqa: BLE001 - fail closed: unknown terms
        return "unknown"


def register_smet_dataset() -> str:
    """The smet.cz list as a dataset (registered at import only once legal changed its 'unknown' class)."""
    return register_dataset(
        SMET_DATASET,
        SMET_URL,
        ttl=86400,
        description="smet.cz newly registered domains today.txt (terms unknown: P005 cond 2); `v3lum data update` only",
        licence="unknown: no published terms (P005 cond 2)",
        terms_class=_smet_terms_class(),
        attribution="smet.cz newly registered domains list",
        provider="smet",
        source=SMET_SOURCE,
        validate=validate_plain_list,
        min_bytes=1000,
        expect="lines",
        max_bytes=ZIP_MAX_TOTAL,
        large=True,
    )


def smet_registration_allowed() -> bool:
    """cond 2: the smet.cz dataset is registered (and so fetched by `v3lum data update`) only once legal
    recorded a class other than 'unknown' for ``smet.nrd_today`` in the provider registry."""
    return _smet_terms_class() != "unknown"


if smet_registration_allowed():
    register_smet_dataset()


# --------------------------------------------------------------------------------------
# local list access (no network: datasets are large=True)
# --------------------------------------------------------------------------------------


def _fetched(info: Any) -> datetime | None:
    raw = str(getattr(info, "fetched_at", "") or "")
    try:
        dt = datetime.fromisoformat(raw.replace("Z", "+00:00"))
    except ValueError:
        return None
    return dt if dt.tzinfo else dt.replace(tzinfo=timezone.utc)


def _remember(key: str, sha: str, text: str) -> str:
    with _TEXT_LOCK:
        if len(_TEXTS) >= _TEXT_CACHE_MAX:
            _TEXTS.pop(next(iter(_TEXTS)))
        _TEXTS[key] = (sha, text)
    return text


def _cached(key: str, sha: str) -> str | None:
    with _TEXT_LOCK:
        hit = _TEXTS.get(key)
    return hit[1] if hit is not None and hit[0] == sha and sha else None


def _normalise_list(text: str) -> str:
    """One lower-case name per line, '\\n' separated, framed by newlines (for exact line searches)."""
    lines = (line.strip().lower().rstrip(".") for line in text.replace("\r\n", "\n").split("\n"))
    return "\n" + "\n".join(line for line in lines if line and not line.startswith("#")) + "\n"


class Lists:
    """The local lists of one run: WhoisDS days, the registro.br release list and (nrd_smet) smet.cz."""

    def __init__(self) -> None:
        self.days: dict[str, str] = {}  # list date -> normalised text
        self.release: dict[str, Any] | None = None
        self.release_text = ""
        self.smet = ""
        self.smet_date: str | None = None
        self.problems: dict[str, str] = {}
        self.stale: dict[str, bool] = {}
        self.missing_days: list[str] = []


def load_whoisds(ctx: Any, lists: Lists, today: date, days: int) -> None:
    newest: datetime | None = None
    for day in window_days(today, days):
        name = whoisds_name(day)
        try:
            info = ctx.data.info(name)
        except Exception:  # noqa: BLE001 - an unreadable manifest entry means 'not downloaded'
            info = None
        if not getattr(info, "present", False):
            lists.missing_days.append(day.isoformat())
            continue
        if name not in DATASETS:
            register_whoisds_day(day)  # an older copy of the rolling window (cond 7), read in place
        sha = str(getattr(info, "sha256", "") or "")
        text = _cached(name, sha)
        if text is None:
            try:
                data = Path(ctx.data.fetch(name, ttl=_LOCAL_ONLY_TTL)).read_bytes()
                text = _remember(name, sha, _normalise_list(read_zip_member(data)))
            except (DatasetError, OSError, ZipProblem) as exc:
                lists.problems[f"whoisds {day.isoformat()}"] = str(exc)[:160]
                continue
        else:
            ctx.data.fetch(name, ttl=_LOCAL_ONLY_TTL)  # cite the dataset of this run (local copy only)
        lists.days[day.isoformat()] = text
        fetched = _fetched(info)
        if fetched is not None and (newest is None or fetched > newest):
            newest = fetched
    if not lists.days:
        lists.problems.setdefault("whoisds", "no WhoisDS list downloaded")
    elif newest is None or (ctx.now() - newest).total_seconds() > MAX_AGE_HOURS * 3600:
        lists.stale["whoisds"] = True


def load_release(ctx: Any, lists: Lists) -> None:
    try:
        info = ctx.data.info(RELEASE_DATASET)
    except Exception:  # noqa: BLE001
        info = None
    if not getattr(info, "present", False):
        lists.problems["registrobr"] = "registro.br release list not downloaded"
        return
    sha = str(getattr(info, "sha256", "") or "")
    try:
        path = Path(ctx.data.fetch(RELEASE_DATASET, ttl=_LOCAL_ONLY_TTL))
        text = _cached(RELEASE_DATASET, sha)
        with _TEXT_LOCK:
            meta = _RELEASE_META.get(sha) if sha else None
        if text is None or meta is None:
            parsed = parse_release_list(path.read_bytes())
            if parsed["error"] and not parsed["names"]:
                lists.problems["registrobr"] = f"local copy unusable ({parsed['error']})"
                return
            meta = {k: parsed[k] for k in ("window_start", "window_end", "generated_at", "complete")}
            text = _remember(RELEASE_DATASET, sha, "\n" + "\n".join(parsed["names"]) + "\n")
            with _TEXT_LOCK:
                _RELEASE_META.clear()
                _RELEASE_META[sha] = meta
    except (DatasetError, OSError) as exc:
        lists.problems["registrobr"] = str(exc)[:160]
        return
    lists.release = dict(meta)
    lists.release_text = text
    fetched = _fetched(info)
    if fetched is None or (ctx.now() - fetched).total_seconds() > MAX_AGE_HOURS * 3600:
        lists.stale["registrobr"] = True


def load_smet(ctx: Any, lists: Lists) -> None:
    if SMET_DATASET not in DATASETS:
        register_smet_dataset()  # nrd_smet runs only once legal cleared the terms (policy gate)
    try:
        info = ctx.data.info(SMET_DATASET)
    except Exception:  # noqa: BLE001
        info = None
    if not getattr(info, "present", False):
        lists.problems["smet"] = "smet.cz list not downloaded"
        return
    sha = str(getattr(info, "sha256", "") or "")
    try:
        text = _cached(SMET_DATASET, sha) or _remember(SMET_DATASET, sha, _normalise_list(Path(ctx.data.fetch(SMET_DATASET, ttl=_LOCAL_ONLY_TTL)).read_text(encoding="utf-8", errors="replace")))
    except (DatasetError, OSError) as exc:
        lists.problems["smet"] = str(exc)[:160]
        return
    lists.smet = text
    fetched = _fetched(info)
    lists.smet_date = fetched.date().isoformat() if fetched else None
    if fetched is None or (ctx.now() - fetched).total_seconds() > MAX_AGE_HOURS * 3600:
        lists.stale["smet"] = True


# --------------------------------------------------------------------------------------
# matching (pure: P012 helper, local only)
# --------------------------------------------------------------------------------------


def name_forms(domain: str) -> list[str]:
    """ASCII (punycode) and Unicode forms of a name, as the lists may carry either."""
    forms = [domain]
    uni = perm.idna_unicode(domain)
    if uni and uni != domain:
        forms.append(uni.lower())
    return forms


def in_text(text: str, domain: str) -> bool:
    return any(f"\n{form}\n" in text for form in name_forms(domain))


def lines_containing(text: str, needle: str, limit: int = 2000) -> list[str]:
    """Lines of a normalised list that contain ``needle`` (C-speed find, no per-line Python loop)."""
    out: list[str] = []
    if not needle:
        return out
    pos = text.find(needle)
    while pos != -1 and len(out) < limit:
        start = text.rfind("\n", 0, pos) + 1
        end = text.find("\n", pos)
        if end == -1:
            end = len(text)
        out.append(text[start:end])
        pos = text.find(needle, end)
    return out


def candidates_for(seeds: Iterable[str], lures: list[str]) -> dict[str, tuple[str, str]]:
    """P012 candidates of every protected seed (registrable domain or brand keyword): {name form:
    (seed, fuzzer)} for ASCII and Unicode forms (the one permutation implementation, cond 8)."""
    out: dict[str, tuple[str, str]] = {}
    for seed in seeds:
        for cand in perm.generate(seed, lures=lures, dictionary=lures[:10]):
            if cand.get("fuzzer") == "*original":
                continue
            for form in (cand.get("domain"), cand.get("domain_unicode")):
                if isinstance(form, str) and form and form not in out:
                    out[form.lower()] = (seed, str(cand.get("fuzzer")))
    return out


def match_list(text: str, *, index: list[dict[str, Any]], labels: Iterable[str], candidates: Mapping[str, tuple[str, str]],
               lures: list[str], own: Any) -> list[dict[str, Any]]:
    """Brand/domain lookalikes in one normalised list: exact P012 candidates plus the lines that contain a
    protected label, classified by the P012 reverse matcher. Own names are never hits."""
    hits: dict[str, dict[str, Any]] = {}
    lines = set(text.split("\n"))
    lines.discard("")
    for name in lines.intersection(candidates):
        seed, fuzzer = candidates[name]
        hits[name] = {"domain": name, "protected": seed, "technique": fuzzer, "score": perm.FUZZER_WEIGHT.get(fuzzer, 50), "lure": None}
    for label in labels:
        for line in lines_containing(text, label):
            if line in hits:
                continue
            match = perm.reverse_match(line, index, lures=lures)
            if match["own_asset"] is not None or not match["matches"]:
                continue
            top = match["matches"][0]
            hits[line] = {"domain": line, "protected": top["protected"], "technique": top["technique"], "score": top["score"], "lure": top["lure"]}
    out = []
    for name, hit in hits.items():
        ascii_name = perm.idna_ascii(name) or name
        ent = Entity.try_make(T.DOMAIN, ascii_name)
        if ent is None or own(ent.value):
            continue
        out.append({**hit, "domain": str(ent.value)})
    out.sort(key=lambda h: (-int(h["score"]), h["domain"]))
    return out


def doh_confirmation(a: Any, mx: Any) -> dict[str, Any]:
    """cond 9 on core DnsAnswer objects: confirmed only by an IPv4 A answer or a non-null MX (RFC 7505
    '0 .' does not confirm); NXDOMAIN = not confirmed; SERVFAIL/refused = could not verify."""
    out: dict[str, Any] = {"confirmed": False, "by": None, "state": "nodata", "mx": False, "error": ""}
    a_records = [r for r in (getattr(a, "records", None) or []) if isinstance(r, str) and re.fullmatch(r"\d{1,3}(?:\.\d{1,3}){3}", r.strip())] if getattr(a, "ok", False) else []
    mx_records = []
    if mx is not None and getattr(mx, "ok", False):
        for r in getattr(mx, "records", None) or []:
            host = str(r).split()[-1].rstrip(".") if str(r).split() else ""
            if host and host != ".":
                mx_records.append(host)
    out["mx"] = bool(mx_records)
    if a_records:
        out.update(confirmed=True, by="A", state="resolves")
    elif mx_records:
        out.update(confirmed=True, by="MX", state="mx")
    elif any(getattr(x, "nxdomain", False) for x in (a, mx) if x is not None):
        out["state"] = "nxdomain"
    elif any(getattr(x, "could_not_verify", False) for x in (a, mx) if x is not None):
        out["state"] = "could_not_verify"
        out["error"] = next((str(getattr(x, "error", "") or "") for x in (a, mx) if x is not None and getattr(x, "could_not_verify", False)), "")
    return out


def severity_for(source: str, confirmed: bool, brand: bool, has_mx: bool) -> str:
    """cond 9 ladder: an NRD hit alone is LOW; MEDIUM only with a brand match plus MX (HIGH is P012/P028's)."""
    if source == "registrobr":
        return "low"
    if confirmed and brand and has_mx:
        return "medium"
    return "low"


def order_hits(hits: Iterable[dict[str, Any]], *, subject_first: bool = False) -> list[dict[str, Any]]:
    """Strong matches first, then the newest list, then the name (cond 9: confirmation order)."""
    out = sorted(hits, key=lambda h: h["domain"])
    out.sort(key=lambda h: str(h.get("list_date") or ""), reverse=True)
    out.sort(key=lambda h: -int(h.get("score") or 0))
    if subject_first:
        out.sort(key=lambda h: not h.get("subject"))
    return out


def miss_wording(domain: str, days_present: int) -> str:
    """cond 10: honest wording - never 'not newly registered'."""
    if domain == "br" or domain.endswith(".br"):
        return "no NRD feed for .br: CT + permutations + DoH only"
    return f"not in the last {int(days_present)} days of WhoisDS lists (gTLD coverage only)"


# --------------------------------------------------------------------------------------
# the modules
# --------------------------------------------------------------------------------------


def _fold(text: str) -> str:
    return perm.fold(re.sub(r"[\s_.'\"/\\]+", "", text or ""))


class _NrdBase(Module):
    """Shared run of nrd_feeds / nrd_smet (one matcher, one set of rules)."""

    feeds: tuple[str, ...] = ("whoisds", "registrobr")

    # ---- protected entries (cond 8: org_profile only) -----------------------------------------
    @staticmethod
    def _own(ctx: Any) -> Any:
        org = getattr(ctx, "org", None)

        def is_own(domain: str) -> bool:
            if org is None:
                return False
            try:
                return bool(org.owns(Entity.make(T.DOMAIN, domain)).own)
            except Exception:  # noqa: BLE001
                return False

        return is_own

    def _protected(self, entity: Entity, ctx: Any) -> tuple[list[dict[str, Any]], list[dict[str, Any]], str]:
        """(domains, brands, why) protected in this run: an own registrable domain, or an org brand."""
        org = getattr(ctx, "org", None)
        if entity.type is T.DOMAIN:
            reg = psl.registrable_domain(entity.value)
            if reg and self._own(ctx)(reg):
                return [{"domain": reg, "source": "org_profile"}], [], f"own domain {reg}"
            return [], [], ""
        try:
            terms = {_fold(t): t for t in (org.brand_terms() if org is not None else [])}
        except Exception:  # noqa: BLE001
            terms = {}
        key = _fold(entity.value)
        if key and key in terms:
            return [], [{"keyword": terms[key], "source": "org_profile"}], f"org brand {terms[key]}"
        return [], [], ""

    def applies(self, entity: Entity, ctx: Any) -> bool:
        if entity.type is T.DOMAIN:
            return psl.registrable_domain(entity.value) is not None
        return bool(self._protected(entity, ctx)[1])  # cond 8: keywords and company names only as org brands

    # ---- run --------------------------------------------------------------------------------
    def _load(self, ctx: Any) -> Lists:
        lists = Lists()
        today = ctx.now().date()
        try:
            days = int(ctx.setting("nrd_feeds_window_days", WINDOW_DAYS))
        except (TypeError, ValueError):
            days = WINDOW_DAYS
        days = max(1, min(WINDOW_DAYS, days))
        if "whoisds" in self.feeds:
            load_whoisds(ctx, lists, today, days)
        if "registrobr" in self.feeds:
            load_release(ctx, lists)
        if "smet" in self.feeds:
            load_smet(ctx, lists)
        return lists

    def _relevant(self, entity: Entity, brand_mode: bool) -> tuple[str, ...]:
        """Feeds that decide 'not found' for this entity: brand searches need every feed; a .br name has no
        NRD feed (cond 10: the release list is its only list); other names only the NRD lists."""
        if brand_mode or entity.type is not T.DOMAIN:
            return self.feeds
        if entity.value.endswith(".br"):
            return tuple(f for f in self.feeds if f == "registrobr") or self.feeds
        return tuple(f for f in self.feeds if f != "registrobr") or self.feeds

    def _usable(self, lists: Lists) -> dict[str, bool]:
        return {
            "whoisds": bool(lists.days) and "whoisds" in self.feeds,
            "registrobr": lists.release is not None and "registrobr" in self.feeds,
            "smet": bool(lists.smet) and "smet" in self.feeds,
        }

    def run(self, entity: Entity, ctx: Any) -> ModuleResult:
        res = self.result(entity)
        lists = self._load(ctx)
        usable = self._usable(lists)
        domains, brands, why = self._protected(entity, ctx)
        relevant = self._relevant(entity, bool(domains or brands))
        if not any(usable.get(f) for f in self.feeds):
            detail = "; ".join(f"{k}: {v}" for k, v in sorted(lists.problems.items())) or "no list"
            return res.mark("unavailable", f"{NOT_DOWNLOADED} ({detail})", reason_code="dataset")
        hits: list[dict[str, Any]] = []
        lures = self._lures(ctx)
        if domains or brands:
            hits = self._brand_hits(entity, ctx, lists, usable, domains, brands, lures)
        subject = self._subject_hits(entity, ctx, lists, usable, domains, brands, lures)
        self._confirm(ctx, res, subject + hits)
        coverage = self._coverage(entity, lists, relevant)
        res.attr("nrd_coverage", coverage)
        self._report_subject(entity, ctx, res, subject, lists)
        self._report_hits(entity, res, hits, why)
        self._source_statuses(res, lists, usable, relevant)
        res.raw = {"coverage": coverage, "hits": hits[:MAX_HITS], "subject": subject, "problems": lists.problems}
        if res.findings or res.pivots or subject:
            return res
        blind = [f for f in relevant if not usable.get(f) or lists.stale.get(f)]
        if blind:
            reasons = ", ".join(f"{f}: {lists.problems.get(f) or ('stale' if lists.stale.get(f) else 'missing')}" for f in blind)
            return res.mark("unavailable", f"{NOT_DOWNLOADED} ({reasons}); {coverage['wording']}", reason_code="dataset")
        return res.mark("empty", coverage["wording"])

    def _lures(self, ctx: Any) -> list[str]:
        try:
            from v3lum.modules.domain_dns import typosquat

            return typosquat.load_lures(ctx)
        except Exception:  # noqa: BLE001 - lure words only widen the combo-squat set
            return []

    # ---- the subject itself -------------------------------------------------------------------
    def _subject_hits(self, entity: Entity, ctx: Any, lists: Lists, usable: Mapping[str, bool], domains: list[dict[str, Any]],
                      brands: list[dict[str, Any]], lures: list[str]) -> list[dict[str, Any]]:
        if entity.type is not T.DOMAIN:
            return []
        reg = psl.registrable_domain(entity.value) or entity.value
        out: list[dict[str, Any]] = []
        if usable.get("whoisds"):
            dates = sorted(d for d, text in lists.days.items() if in_text(text, reg))
            if dates:
                out.append({"domain": reg, "source": "whoisds", "list_date": dates[0], "subject": True})
        if usable.get("smet") and in_text(lists.smet, reg):
            out.append({"domain": reg, "source": "smet", "list_date": lists.smet_date, "subject": True})
        if usable.get("registrobr") and in_text(lists.release_text, reg):
            out.append({"domain": reg, "source": "registrobr", "list_date": (lists.release or {}).get("generated_at"), "subject": True})
        if out and not domains:
            # a newly registered input that imitates an org brand: typosquat when confirmed (cond 9)
            org = getattr(ctx, "org", None)
            prot_domains = [{"domain": d.name, "source": "org_profile"} for d in (getattr(org, "domains", None) or []) if getattr(d, "name", "")]
            prot_brands = [{"keyword": t, "source": "org_profile"} for t in (org.brand_terms() if org is not None else [])]
            index = perm.build_protected_index(prot_domains, prot_brands)
            match = perm.reverse_match(reg, index, lures=lures) if index else {"own_asset": None, "matches": []}
            if match["matches"] and match["own_asset"] is None:
                top = match["matches"][0]
                for hit in out:
                    hit.update(protected=top["protected"], technique=top["technique"], score=top["score"], lure=top["lure"])
        return out

    # ---- brand matching -------------------------------------------------------------------------
    def _brand_hits(self, entity: Entity, ctx: Any, lists: Lists, usable: Mapping[str, bool], domains: list[dict[str, Any]],
                    brands: list[dict[str, Any]], lures: list[str]) -> list[dict[str, Any]]:
        index = perm.build_protected_index(domains, brands)
        seeds = [d["domain"] for d in domains] + [b["keyword"] for b in brands]
        candidates = candidates_for(seeds, lures)
        labels = sorted({e["label"] for e in index if len(e["label"]) >= 4})
        own = self._own(ctx)
        hits: dict[tuple[str, str], dict[str, Any]] = {}

        def add(found: list[dict[str, Any]], source: str, list_date: str | None) -> None:
            for hit in found:
                key = (source, hit["domain"])
                if key not in hits or (list_date and (hits[key]["list_date"] or "9999") > list_date):
                    hits[key] = {**hit, "source": source, "list_date": list_date}

        if usable.get("whoisds"):
            for day in sorted(lists.days):  # oldest first: first_seen = the earliest list date
                if ctx.cancelled():
                    break
                add(match_list(lists.days[day], index=index, labels=labels, candidates=candidates, lures=lures, own=own), "whoisds", day)
        if usable.get("smet"):
            add(match_list(lists.smet, index=index, labels=labels, candidates=candidates, lures=lures, own=own), "smet", lists.smet_date)
        if usable.get("registrobr"):
            add(match_list(lists.release_text, index=index, labels=labels, candidates=candidates, lures=lures, own=own), "registrobr",
                (lists.release or {}).get("generated_at"))
        return order_hits(hits.values())[:MAX_HITS]

    # ---- DoH confirmation (cond 9) ----------------------------------------------------------------
    def _confirm(self, ctx: Any, res: ModuleResult, hits: list[dict[str, Any]]) -> None:
        nrd = [h for h in hits if h["source"] in ("whoisds", "smet")]
        try:
            cap = int(ctx.setting("nrd_feeds_confirmations", DOH_CAP))
        except (TypeError, ValueError):
            cap = DOH_CAP
        cap = max(0, min(DOH_CAP, cap))
        order = order_hits(nrd, subject_first=True)
        done: dict[str, dict[str, Any]] = {}
        blocked = ""
        for hit in order:
            if hit["domain"] in done:
                hit["confirmation"] = done[hit["domain"]]
                continue
            if len(done) >= cap or blocked or ctx.cancelled() or (ctx.remaining() is not None and ctx.remaining() < 2.0):
                hit["confirmation"] = {"confirmed": False, "state": "not_checked",
                                       "error": blocked or f"over the {cap} DoH confirmations of this run (cond 9): listed, untagged"}
                continue
            a = ctx.dns.query(hit["domain"], "A")
            mx = ctx.dns.query(hit["domain"], "MX") if (hit.get("protected") or not a.ok) else None
            conf = doh_confirmation(a, mx)
            if conf["state"] == "could_not_verify" and "not allowed" in conf.get("error", ""):
                blocked = "DoH confirmation needs the organisation's internal resolver (setting doh_internal): could not verify"
                conf["error"] = blocked
            done[hit["domain"]] = conf
            hit["confirmation"] = conf
        for hit in hits:
            hit.setdefault("confirmation", {"confirmed": False, "state": "not_applicable"})

    # ---- reporting ---------------------------------------------------------------------------------
    def _coverage(self, entity: Entity, lists: Lists, relevant: Iterable[str]) -> dict[str, Any]:
        """What a miss covers, worded honestly (cond 10): never 'not newly registered'."""
        days_present = len(lists.days)
        relevant = tuple(relevant)
        wording_parts = []
        domain = entity.value if entity.type is T.DOMAIN else ""
        if domain.endswith(".br"):
            wording_parts.append(miss_wording(domain, days_present))
        elif "whoisds" in relevant:
            wording_parts.append(miss_wording(domain, days_present) if domain
                                 else f"no lookalike in the last {days_present} days of WhoisDS lists (gTLD coverage only)")
        if "smet" in relevant:
            wording_parts.append(f"not in the smet.cz list of {lists.smet_date or '?'}")
        if "registrobr" in relevant and lists.release is not None:
            wording_parts.append(f"not in the registro.br release list ({(lists.release.get('window_start') or '?')[:10]} to "
                                 f"{(lists.release.get('window_end') or '?')[:10]})")
        return {
            "whoisds_days": days_present,
            "newest_list": max(lists.days) if lists.days else None,
            "missing_days": lists.missing_days[:WINDOW_DAYS],
            "registrobr_window": [lists.release.get("window_start"), lists.release.get("window_end")] if lists.release else None,
            "registrobr_generated_at": (lists.release or {}).get("generated_at"),
            "stale": sorted(k for k, v in lists.stale.items() if v),
            "problems": dict(sorted(lists.problems.items())),
            "wording": "; ".join(wording_parts),
        }

    def _report_subject(self, entity: Entity, ctx: Any, res: ModuleResult, subject: list[dict[str, Any]], lists: Lists) -> None:
        own = self._own(ctx)(entity.value) if entity.type is T.DOMAIN else False
        for hit in subject:
            conf = hit.get("confirmation") or {}
            if hit["source"] == "registrobr":
                window = lists.release or {}
                res.attr("release_window", {"start": window.get("window_start"), "end": window.get("window_end"), "generated_at": window.get("generated_at")})
                res.finding(
                    "Own domain in the registro.br release process" if own else "Domain in the registro.br release process",
                    "high" if own else "low",
                    f"{entity.display} is listed in the registro.br release list for {(window.get('window_start') or '?')[:10]} to "
                    f"{(window.get('window_end') or '?')[:10]} (generated {window.get('generated_at') or '?'}): an expired name about to be "
                    "released can be re-registered by anyone. It may have been renewed or re-registered since.",
                    confidence="probable",
                    criterion="registro.br lista-processo-liberacao.txt names the domain (registry list)",
                    tags=["in_release"],
                    data={"window": window},
                    source=RELEASE_SOURCE,
                    key="in_release",
                )
                continue
            source_id = WHOISDS_SOURCE if hit["source"] == "whoisds" else SMET_SOURCE
            res.attr("nrd_first_seen", hit.get("list_date"))
            confirmed = bool(conf.get("confirmed"))
            brand = bool(hit.get("protected"))
            tags = (["newly_registered"] + (["typosquat"] if brand else [])) if confirmed else []
            sev = severity_for(hit["source"], confirmed, brand, bool(conf.get("mx")))
            res.finding(
                "Listed in a newly registered domains list",
                sev,
                f"{entity.display} appears in the {hit['source']} list of {hit.get('list_date') or '?'} (names are 24-48 h old at publication)"
                + (f"; it imitates {hit['protected']} ({hit.get('technique')})" if brand else "")
                + ("; DoH confirms it " + ("resolves" if conf.get("by") == "A" else "has MX") if confirmed
                   else f"; registration not confirmed by DoH ({conf.get('error') or conf.get('state') or 'not checked'})") + ".",
                confidence="probable" if confirmed else "possible",
                criterion=f"{hit['source']} newly-registered list of {hit.get('list_date') or '?'}"
                          + (f" + DoH {conf.get('by')} answer" if confirmed else " (not DoH-confirmed: untagged)")
                          + (f" + lookalike of {hit['protected']}" if brand else ""),
                tags=tags,
                data={"list_date": hit.get("list_date"), "confirmation": conf, "protected": hit.get("protected")},
                source=source_id,
                observed_first=hit.get("list_date"),
                key=hit["source"],
            )

    def _report_hits(self, entity: Entity, res: ModuleResult, hits: list[dict[str, Any]], why: str) -> None:
        if not hits:
            return
        table = []
        for hit in hits[:MAX_HITS]:
            conf = hit.get("confirmation") or {}
            confirmed = bool(conf.get("confirmed"))
            if hit["source"] == "registrobr":
                tags, sev = ["in_release"], "low"
            else:
                tags = ["newly_registered", "typosquat"] if confirmed else []
                sev = severity_for(hit["source"], confirmed, True, bool(conf.get("mx")))
            hit["severity"], hit["tags"], hit["confirmed"] = sev, tags, confirmed
            table.append({k: hit.get(k) for k in ("domain", "source", "list_date", "protected", "technique", "score", "confirmed", "severity", "tags")}
                         | {"confirmation": conf.get("state")})
        res.attr("nrd_hits", table)
        res.attr("watch_hits", [{"name": h["domain"], "registrable_domain": psl.registrable_domain(h["domain"]) or h["domain"], "serial": None,
                                 "cert_sha256": None, "issuer": None, "not_before": None, "source": h["source"], "first_seen": h.get("list_date")}
                                for h in hits[:MAX_HITS]])
        counts: dict[str, int] = {}
        for hit in hits:
            counts[hit["source"]] = counts.get(hit["source"], 0) + 1
        res.finding(
            "Lookalikes of a protected brand in newly registered or released domain lists",
            "info",
            f"{why}: " + ", ".join(f"{n} in {s}" for s, n in sorted(counts.items())) + " (matched locally; per-name findings follow).",
            confidence="probable",
            data={"counts": counts},
            key="summary",
        )
        for hit in hits[:MAX_PIVOTS]:
            res.pivot(T.DOMAIN, hit["domain"], "brand_match", confidence="probable" if hit["confirmed"] or hit["source"] == "registrobr" else "possible",
                      expand=False, note=f"{hit['source']} list {hit.get('list_date') or '?'}: {hit.get('technique')} of {hit.get('protected')}")
        for hit in hits[:MAX_HIT_FINDINGS]:
            ent = Entity.try_make(T.DOMAIN, hit["domain"])
            if ent is None:
                continue
            conf = hit.get("confirmation") or {}
            if hit["source"] == "registrobr":
                title, src = "Lookalike in the registro.br release process", RELEASE_SOURCE
                desc = (f"{hit['domain']} ({hit.get('technique')} of {hit.get('protected')}) is about to be released by registro.br "
                        f"(list generated {hit.get('list_date') or '?'}): re-registration risk; it may have been renewed since.")
                crit = f"registro.br release list + P012 {hit.get('technique')} of {hit.get('protected')}"
            else:
                title, src = "Newly registered lookalike of a protected brand", WHOISDS_SOURCE if hit["source"] == "whoisds" else SMET_SOURCE
                desc = (f"{hit['domain']} ({hit.get('technique')} of {hit.get('protected')}) appears in the {hit['source']} list of "
                        f"{hit.get('list_date') or '?'}" + ("; DoH confirms it " + ("resolves" if conf.get("by") == "A" else "has MX")
                                                            + (" and has MX" if conf.get("mx") and conf.get("by") == "A" else "") if hit["confirmed"]
                                                            else f"; registration not confirmed by DoH ({conf.get('error') or conf.get('state')})") + ".")
                crit = (f"{hit['source']} newly-registered list of {hit.get('list_date') or '?'} + P012 {hit.get('technique')} of {hit.get('protected')}"
                        + (f" + DoH {conf.get('by')}" if hit["confirmed"] else " (not DoH-confirmed: untagged)") + (" + MX" if conf.get("mx") else ""))
            finding = res.finding(title, hit["severity"], desc, confidence="probable" if hit["confirmed"] or hit["source"] == "registrobr" else "possible",
                                  criterion=crit, tags=hit["tags"], data={k: hit.get(k) for k in ("source", "list_date", "protected", "technique", "score")},
                                  source=src, observed_first=hit.get("list_date") if hit["source"] != "registrobr" else None, key=f"{hit['source']}:{hit['domain']}")
            finding.entity = ent  # the finding is about the lookalike, never the protected input
            finding.ensure_id()

    def _source_statuses(self, res: ModuleResult, lists: Lists, usable: Mapping[str, bool], relevant: Iterable[str]) -> None:
        ids = {"whoisds": WHOISDS_SOURCE, "registrobr": RELEASE_SOURCE, "smet": SMET_SOURCE}
        for feed in relevant:
            if not usable.get(feed):
                res.source_status(ids[feed], Status.UNAVAILABLE, reason_code="dataset", reason=f"{NOT_DOWNLOADED} ({lists.problems.get(feed, 'missing')})")
            elif lists.stale.get(feed):
                res.source_status(ids[feed], Status.UNAVAILABLE, reason_code="dataset",
                                  reason=f"{feed} list older than {int(MAX_AGE_HOURS)} h (stale): run v3lum data update")


@register
class NrdFeeds(_NrdBase):
    name = "nrd_feeds"
    title = "Newly registered and released domains (WhoisDS, registro.br)"
    description = (
        "Local match against the WhoisDS free daily newly-registered-domains lists (30-day window) and the registro.br "
        "release list: first_seen of a domain, and lookalikes of org-profile brands/domains (P012 matcher), DoH-confirmed "
        "through the organisation's resolver before tagging."
    )
    category = "domain_dns"
    accepts = {T.DOMAIN, T.KEYWORD, T.ORG}
    produces = {T.DOMAIN}
    tags = {"offline", "brazil", "watch_source"}
    reference = "https://www.whoisds.com/newly-registered-domains"
    notice = (
        "Lists are fetched by `v3lum data update` only and matched on this machine; no brand or keyword leaves it. "
        "The WhoisDS free list is a capped daily sample (gTLDs and some ccTLDs): absence proves nothing. DoH confirmation "
        "uses only the organisation's internal resolver (setting doh_internal)."
    )
    terms = "open"
    opsec = Opsec.PASSIVE
    disclosure = "none"
    hosts = ()
    sources = (WHOISDS_SOURCE, RELEASE_SOURCE)
    access_model = "offline"
    max_requests = 0
    expected_latency = 2.0
    timeout = 30.0
    max_pivots = MAX_PIVOTS + 5
    default_enabled = True
    feeds = ("whoisds", "registrobr")
    settings = {
        "nrd_feeds_window_days": SettingSpec(WINDOW_DAYS, "nrd_feeds: WhoisDS list dates kept in the local window (1-30, P005 cond 7)"),
        "nrd_feeds_confirmations": SettingSpec(DOH_CAP, "nrd_feeds: DoH confirmations per run (at most 100, P005 cond 9)"),
    }


@register
class NrdSmet(_NrdBase):
    name = "nrd_smet"
    title = "Newly registered domains (smet.cz list, terms unknown)"
    description = (
        "Local match against the smet.cz today.txt newly-registered-domains list (cross-check of WhoisDS). Disabled in "
        "every licence profile until legal records the list's terms."
    )
    category = "domain_dns"
    accepts = {T.DOMAIN, T.KEYWORD, T.ORG}
    produces = {T.DOMAIN}
    tags = {"offline"}
    reference = "https://smet.cz/nrd/data/today.txt"
    notice = "smet.cz publishes no terms: 'unknown' terms never run in any licence profile (P005 cond 2)."
    terms = "unknown"
    opsec = Opsec.PASSIVE
    disclosure = "none"
    hosts = ()
    sources = (SMET_SOURCE,)
    access_model = "offline"
    max_requests = 0
    expected_latency = 2.0
    timeout = 30.0
    max_pivots = MAX_PIVOTS + 5
    default_enabled = False
    feeds = ("smet",)
