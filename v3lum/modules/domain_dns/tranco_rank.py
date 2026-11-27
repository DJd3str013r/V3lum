"""Tranco popularity rank of a domain, matched offline against the daily top-1M list (P010).

Batch p2-G01-2, proposal P010 ``tranco_rank``. Final conditions implemented here:

* c1 - local list only: the Tranco daily top-1M zip is the dataset ``tranco_rank.top1m`` fetched
  by ``v3lum data update`` (9.7 MB, ``large=True``: never downloaded during a scan, A6/AR10),
  extracted by the core ``safe_extract`` (``archive='zip'``, member ``top-1m.csv``) and indexed on
  disk at refresh time by the dataset validator (:func:`validate_list`: an SQLite table
  ``tranco(domain PRIMARY KEY, rank) WITHOUT ROWID`` next to the datasets). Lookups are one
  indexed SELECT; the list is never loaded into a Python dict or set.
* c2 - no API fallback: a missing list gives UNAVAILABLE reason_code 'dataset' (the policy gate
  says so before the run, POL-14; the module says it again on the single-run path). Disclosure
  'none': the investigated value never leaves the machine and the module runs under TLP:RED.
  The list id (dataset ``tranco_rank.top1m_id``, fetched right after the list) and the list date
  are recorded in the evidence and in attribute ``tranco_list``; the dataset citation (name,
  SHA-256, fetch time) is recorded by the core.
* c3 - the rank is a score-dampening hint only (attribute ``tranco_dampener`` for P302), never
  ``known_good`` and never an allow-list, and only for the exact registrable domain: a subdomain of
  a ranked domain, a URL (URL-level verdict) and consensus verdicts are never dampened.
* c4 - ``v3lum/data/shared_platforms.json`` (V3LUM own list: file sharing, forms, site builders,
  app hosting, object storage, free hosting, dynamic DNS, URL shorteners, tunnels...): hosts on it
  show their rank but never dampen a score.
* c5 - PSL private suffixes (github.io, pages.dev, web.app, workers.dev...) are ranked per
  registrable domain under the suffix (the core PSL includes the private section), never by the
  platform's rank: evil.github.io is looked up as evil.github.io.
* c6 - context line 'Tranco #1,234 - popular' / 'not in top 1M' with the list date; 'not in top
  1M' is never a finding; 'young and unpopular' is the LOW correlation rule
  ``tranco_young_unpopular`` (v3lum/correlations/p2_g01_2.py).
* c7 - the Le Pochat et al. (NDSS 2019) citation is the dataset attribution
  (``register_dataset(attribution=...)``, notice ``v3lum/data/notices/tranco.json``).
"""

from __future__ import annotations

import hashlib
import os
import re
import sqlite3
import tempfile
import threading
from collections.abc import Iterable, Iterator, Mapping
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any
from urllib.parse import quote

from v3lum import paths
from v3lum.core import psl
from v3lum.core.datasets import DataStore, DatasetError, DatasetUnavailable, register_dataset
from v3lum.core.entities import Entity, url_host
from v3lum.core.entities import EntityType as T
from v3lum.core.models import ModuleResult, Opsec
from v3lum.core.module import Module, register

TRANCO_CITATION = (
    'Victor Le Pochat, Tom Van Goethem, Samaneh Tajalizadehkhoob, Maciej Korczyński, and Wouter Joosen. 2019. '
    '"Tranco: A Research-Oriented Top Sites Ranking Hardened Against Manipulation," Proceedings of the 26th Annual '
    "Network and Distributed System Security Symposium (NDSS 2019). https://doi.org/10.14722/ndss.2019.23386"
)
LIST_DATASET = "tranco_rank.top1m"
ID_DATASET = "tranco_rank.top1m_id"
LIST_SOURCE = "tranco.top1m"
ID_SOURCE = "tranco.list_id"
LIST_URL = "https://tranco-list.eu/top-1m.csv.zip"
ID_URL = "https://tranco-list.eu/top-1m-id"
LIST_PAGE = "https://tranco-list.eu/list/{list_id}"
MEMBER = "top-1m.csv"
LICENCE = "Tranco list terms: free to use; cite Le Pochat et al. (NDSS 2019)"
SHARED_PLATFORMS_FILE = "shared_platforms.json"
#: Validation floor of a downloaded list (the real daily list has exactly 1,000,000 rows); tests
#: lower it for the trimmed slice.
MIN_ROWS = 900_000
#: First rows whose ranks must be 1, 2, 3... (a reordered or truncated head is not a Tranco list).
CHECK_ROWS = 1000
#: (upper rank bound, popularity label) - thresholds for the context line and the dampener hint.
BUCKETS: tuple[tuple[int, str], ...] = ((10_000, "popular"), (100_000, "established"), (1_000_000, "long tail"))
#: Dampener factors proposed to P302 (domain-level single-source reputation only); long tail: none.
DAMPENER_FACTORS = {"popular": 0.6, "established": 0.8}
NOT_RANKED = "not in top 1M"
SUFFIX_LABEL = "public suffix host"
#: Tranco generates the daily list at ~22:00 UTC (observed created_on 22:00:01, Last-Modified 22:20:48):
#: a list downloaded at time T is the list of day (T - 22h30m).
PUBLICATION_LAG = timedelta(hours=22, minutes=30)
#: A copy older than this is flagged in the context line (the list refreshes daily).
OLD_LIST_DAYS = 7
#: Never refresh during a run: the list and its id are installed only by `v3lum data update`.
NO_REFRESH_TTL = 10.0**12
INDEX_PREFIX = "tranco_rank-"
INDEX_SUFFIX = ".sqlite"

_ROW = re.compile(r"^(\d{1,7}),([a-z0-9._-]{1,253})$")
_LIST_ID = re.compile(r"^[A-Z0-9]{4,8}$")
_BUILD_LOCK = threading.Lock()


# ======================================================================================
# dataset: validation and the on-disk index (refresh time, P010 c1)
# ======================================================================================


def iter_rows(lines: Iterable[Any]) -> Iterator[tuple[int, str]]:
    """(rank, domain) from 'rank,domain' lines; malformed lines are skipped."""
    for line in lines:
        if isinstance(line, (bytes, bytearray)):
            line = line.decode("utf-8", "replace")
        if not isinstance(line, str):
            continue
        m = _ROW.match(line.strip().lower())
        if m and int(m.group(1)) > 0:
            yield int(m.group(1)), m.group(2)


def check_head(lines: Iterable[Any], *, min_rows: int | None = None, check_rows: int | None = None) -> str | None:
    """Reason why ``lines`` is not a Tranco list (None when it is): an HTML page, a first row that is
    not rank 1, non-monotonic ranks in the first ``check_rows`` rows (default :data:`CHECK_ROWS`),
    malformed head rows, fewer than ``min_rows`` rows (default :data:`MIN_ROWS`)."""
    floor = MIN_ROWS if min_rows is None else int(min_rows)
    check_rows = CHECK_ROWS if check_rows is None else int(check_rows)
    count = 0
    previous = 0
    for line in lines:
        if isinstance(line, (bytes, bytearray)):
            line = line.decode("utf-8", "replace")
        if not isinstance(line, str):
            return "non-text line"
        if count == 0 and line.lstrip().startswith("<"):
            return "HTML instead of the CSV list (challenge or error page?)"
        m = _ROW.match(line.strip().lower())
        if not m:
            if count < check_rows and line.strip():
                return f"malformed row {count + 1}"
            continue
        rank = int(m.group(1))
        if count == 0 and rank != 1:
            return "the first row is not rank 1"
        if count < check_rows and rank != previous + 1:
            return f"non-monotonic rank at row {count + 1}"
        previous = rank
        count += 1
    if count == 0:
        return "empty list"
    if count < floor:
        return f"only {count} rows (a daily Tranco list has 1,000,000)"
    return None


def _sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with open(path, "rb") as fh:
        for chunk in iter(lambda: fh.read(1 << 20), b""):
            digest.update(chunk)
    return digest.hexdigest()


def index_dir() -> Path:
    """Directory of the on-disk indexes (next to the core dataset indexes)."""
    return paths.datasets_dir() / ".index"


def index_path(sha256: str) -> Path:
    """Index file of one list version (keyed by the SHA-256 of the extracted CSV)."""
    if not re.fullmatch(r"[0-9a-f]{64}", str(sha256 or "")):
        raise ValueError("Tranco index: a SHA-256 hex digest is required")
    return index_dir() / f"{INDEX_PREFIX}{sha256}{INDEX_SUFFIX}"


def build_index(csv_path: Path | str, sha256: str = "", *, keep: Iterable[str] = ()) -> Path:
    """Build the SQLite index of a validated list (temp file + atomic rename, 0600). Duplicate
    domains keep their best rank. Stale indexes of other list versions are removed, except the
    versions in ``keep`` (the copy that is still installed). Returns the index path."""
    src = Path(csv_path)
    sha = sha256 or _sha256_file(src)
    target = index_path(sha)
    directory = paths.private_dir(index_dir())
    fd, tmp_name = tempfile.mkstemp(prefix=f".{INDEX_PREFIX}", suffix=INDEX_SUFFIX, dir=str(directory))
    os.close(fd)
    tmp = Path(tmp_name)
    try:
        con = sqlite3.connect(str(tmp))
        try:
            con.execute("PRAGMA journal_mode=OFF")
            con.execute("PRAGMA synchronous=OFF")
            con.execute("PRAGMA cache_size=-32768")
            con.execute("CREATE TABLE tranco(domain TEXT PRIMARY KEY, rank INTEGER NOT NULL) WITHOUT ROWID")
            con.execute("CREATE TABLE meta(key TEXT PRIMARY KEY, value TEXT)")
            sql = "INSERT INTO tranco(domain, rank) VALUES(?, ?) ON CONFLICT(domain) DO UPDATE SET rank=min(rank, excluded.rank)"
            batch: list[tuple[str, int]] = []
            with open(src, encoding="utf-8", errors="replace") as fh:
                for rank, domain in iter_rows(fh):
                    batch.append((domain, rank))
                    if len(batch) >= 50_000:
                        con.executemany(sql, batch)
                        batch.clear()
            if batch:
                con.executemany(sql, batch)
            rows = con.execute("SELECT count(*) FROM tranco").fetchone()[0]
            con.executemany("INSERT INTO meta(key, value) VALUES(?, ?)", [("sha256", sha), ("rows", str(rows))])
            con.commit()
        finally:
            con.close()
        os.chmod(tmp, 0o600)
        os.replace(tmp, target)
    except BaseException:
        tmp.unlink(missing_ok=True)
        raise
    _prune({sha, *[k for k in keep if k]})
    return target


def _prune(keep: set[str]) -> None:
    """Remove indexes of list versions that are neither new nor installed (best effort)."""
    try:
        for path in index_dir().glob(f"{INDEX_PREFIX}*{INDEX_SUFFIX}"):
            sha = path.name[len(INDEX_PREFIX) : -len(INDEX_SUFFIX)]
            if sha not in keep:
                path.unlink(missing_ok=True)
    except OSError:  # pragma: no cover - pruning never fails a refresh
        pass


def validate_list(path: Path) -> bool:
    """Dataset validator of ``tranco_rank.top1m`` (runs at refresh time on the extracted CSV, before
    the previous copy is replaced): checks the list, then builds its on-disk index (P010 c1)."""
    with open(path, encoding="utf-8", errors="replace") as fh:
        problem = check_head(fh)
    if problem:
        raise ValueError(problem)
    try:
        installed = DataStore(None).info(LIST_DATASET).sha256
    except (ValueError, OSError):
        installed = ""
    build_index(path, keep=(installed,))
    return True


def validate_list_id(path: Path) -> bool:
    """Dataset validator of ``tranco_rank.top1m_id``: a Tranco list id such as '947P2'."""
    text = Path(path).read_text(encoding="utf-8", errors="replace").strip()
    if not _LIST_ID.match(text):
        raise ValueError("not a Tranco list id")
    return True


register_dataset(
    LIST_DATASET,
    LIST_URL,
    ttl=86400,
    description="Tranco daily top-1M list (rank,domain; registrable domains), indexed on disk at refresh time",
    licence=LICENCE,
    terms_class="open",
    attribution=TRANCO_CITATION,
    provider="tranco",
    source=LIST_SOURCE,
    validate=validate_list,
    min_bytes=5_000_000,
    expect="csv",
    max_bytes=64 * 1024 * 1024,
    large=True,
    essential=True,
    archive="zip",
    member=MEMBER,
)
register_dataset(
    ID_DATASET,
    ID_URL,
    ttl=86400,
    description="Id of the latest Tranco daily list (provenance of tranco_rank.top1m; fetched right after it)",
    licence=LICENCE,
    terms_class="open",
    attribution=TRANCO_CITATION,
    provider="tranco",
    source=ID_SOURCE,
    validate=validate_list_id,
    min_bytes=4,
    expect="text",
    max_bytes=1024,
    large=False,
    essential=True,
)


class TrancoIndex:
    """Read-only access to one on-disk index (one indexed SELECT per lookup)."""

    def __init__(self, path: Path) -> None:
        self.path = Path(path)
        uri = "file:" + quote(str(self.path.resolve())) + "?mode=ro"
        self._con = sqlite3.connect(uri, uri=True, check_same_thread=False)

    def lookup(self, domain: str) -> int | None:
        if not isinstance(domain, str) or not domain:
            return None
        row = self._con.execute("SELECT rank FROM tranco WHERE domain = ?", (domain.strip().lower(),)).fetchone()
        return int(row[0]) if row else None

    def meta(self) -> dict[str, str]:
        return {str(k): str(v) for k, v in self._con.execute("SELECT key, value FROM meta")}

    def close(self) -> None:
        self._con.close()


def open_index(csv_path: Path, sha256: str) -> TrancoIndex:
    """The index of the installed list, built now when it is missing (a copy installed before this
    module existed, or an index removed by hand): a one-off cost of a few seconds."""
    target = index_path(sha256)
    if not target.is_file():
        with _BUILD_LOCK:
            if not target.is_file():
                build_index(csv_path, sha256)
    index = TrancoIndex(target)
    try:
        rows = int(index.meta().get("rows") or 0)
    except (sqlite3.Error, ValueError):
        index.close()
        raise
    if rows <= 0:
        index.close()
        raise ValueError("the Tranco index is empty")
    return index


# ======================================================================================
# facts, display and dampener (P010 c3-c6)
# ======================================================================================


def load_shared_platforms(data: Any) -> dict[str, str]:
    """{host: category} from data/shared_platforms.json (invalid entries are skipped)."""
    out: dict[str, str] = {}
    cats = data.get("categories") if isinstance(data, Mapping) else None
    if not isinstance(cats, Mapping):
        return out
    for category, hosts in cats.items():
        if not isinstance(hosts, list):
            continue
        for host in hosts:
            if isinstance(host, str) and host.strip():
                out.setdefault(host.strip().lower().rstrip("."), str(category))
    return out


def shared_platform(host: str, platforms: Mapping[str, str]) -> dict[str, str] | None:
    """{platform, category} when ``host`` is a listed platform or a name under one (label boundary)."""
    labels = host.lower().rstrip(".").split(".")
    for i in range(len(labels) - 1):
        candidate = ".".join(labels[i:])
        if candidate in platforms:
            return {"platform": candidate, "category": platforms[candidate]}
    return None


def bucket(rank: int | None) -> str | None:
    if not isinstance(rank, int) or isinstance(rank, bool) or rank <= 0:
        return None
    for limit, label in BUCKETS:
        if rank <= limit:
            return label
    return None


def rank_facts(host: str, lookup: Any, platforms: Mapping[str, str]) -> dict[str, Any]:
    """Lookup key, rank and labels of a host (P010 c3-c5).

    The key is the registrable domain computed with the PSL private section (c5); a host that is
    itself a public suffix (github.io, s3.amazonaws.com) is looked up as itself and flagged.
    """
    reg = psl.registrable_domain(host)
    suffix_host = reg is None
    key = host if suffix_host else reg
    rank = lookup(key)
    if not isinstance(rank, int) or isinstance(rank, bool) or rank <= 0:
        rank = None
    return {
        "host": host,
        "lookup_key": key,
        "exact": host == key,
        "public_suffix_host": suffix_host,
        "rank": rank,
        "bucket": bucket(rank),
        "shared_platform": shared_platform(host, platforms),
    }


def popularity(facts: Mapping[str, Any]) -> str:
    if facts.get("rank"):
        return str(facts.get("bucket") or "ranked")
    return SUFFIX_LABEL if facts.get("public_suffix_host") else NOT_RANKED


def context_line(facts: Mapping[str, Any], list_id: str, list_date: str, *, old_days: int | None = None) -> str:
    """'Tranco #1,234 - popular (list 947P2, 2026-11-25)' / 'not in top 1M (list ...)' (P010 c6)."""
    tag = ", ".join(x for x in (f"list {list_id}" if list_id else "", list_date) if x)
    if old_days is not None and old_days >= OLD_LIST_DAYS:
        tag = ", ".join(x for x in (tag, f"{old_days} days old: run v3lum data update {LIST_DATASET}") if x)
    tail = f" ({tag})" if tag else ""
    rank = facts.get("rank")
    if facts.get("public_suffix_host"):
        if rank:
            line = f"Tranco #{rank:,} - {facts.get('bucket') or 'ranked'}: the public suffix {facts.get('lookup_key')} itself (names under it are ranked per registrable domain)"
        else:
            line = f"{SUFFIX_LABEL} - not ranked by Tranco"
    elif rank:
        via = f" via {facts.get('lookup_key')}" if not facts.get("exact") else ""
        line = f"Tranco #{rank:,} - {facts.get('bucket') or 'ranked'}{via}"
    else:
        line = NOT_RANKED
    shared = facts.get("shared_platform")
    if shared:
        line += f" - shared platform {shared['platform']} ({shared['category'].replace('_', ' ')}): never dampens a score"
    return line + tail


def dampener(facts: Mapping[str, Any], etype: T) -> dict[str, Any]:
    """Score-dampening hint for P302 (P010 c3-c5): never an allow-list, never known_good, only for
    the exact registrable domain, never for URL-level or consensus (P171) verdicts."""

    def refuse(reason: str) -> dict[str, Any]:
        return {"dampen": False, "factor": 1.0, "reason": reason, "scope": "domain"}

    if etype is T.URL:
        return refuse("url_level_verdict")
    if facts.get("shared_platform"):
        return refuse("shared_platform")
    if facts.get("public_suffix_host"):
        return refuse("public_suffix_host")
    if not facts.get("rank"):
        return refuse("not_ranked")
    if not facts.get("exact"):
        return refuse("subdomain_of_ranked_domain")
    factor = DAMPENER_FACTORS.get(str(facts.get("bucket") or ""))
    if factor is None:
        return refuse("long_tail")
    return {
        "dampen": True,
        "factor": factor,
        "reason": f"tranco_{facts.get('bucket')}",
        "scope": "domain",
        "never": "URL-level or consensus (P171) verdicts; never an allow-list",
    }


def list_date_of(fetched_at: str) -> str:
    """Date of the Tranco daily list current at download time (generated ~22:00 UTC each day)."""
    try:
        when = datetime.fromisoformat(str(fetched_at).replace("Z", "+00:00"))
    except ValueError:
        return ""
    if when.tzinfo is None:
        when = when.replace(tzinfo=timezone.utc)
    return (when.astimezone(timezone.utc) - PUBLICATION_LAG).date().isoformat()


def _age_days(fetched_at: str, now: datetime) -> int | None:
    try:
        when = datetime.fromisoformat(str(fetched_at).replace("Z", "+00:00"))
    except ValueError:
        return None
    if when.tzinfo is None:
        when = when.replace(tzinfo=timezone.utc)
    return max(0, int((now - when).total_seconds() // 86400))


def _list_id(ctx: Any) -> tuple[str, str]:
    """(list id, its fetch time) from the local copy of tranco_rank.top1m_id ('' when absent)."""
    try:
        info = ctx.data.info(ID_DATASET)
        if not info.present:
            return "", ""
        text = str(ctx.data.fetch_text(ID_DATASET, ttl=NO_REFRESH_TTL)).strip()
    except (DatasetError, OSError, ValueError):
        return "", ""
    return (text, str(info.fetched_at or "")) if _LIST_ID.match(text) else ("", "")


@register
class TrancoRank(Module):
    name = "tranco_rank"
    title = "Tranco popularity rank"
    description = (
        "Tranco top-1M rank of the registrable domain (PSL private suffixes included) from the local daily list: "
        "popularity context and a domain-level dampening hint, never an allow-list."
    )
    category = "domain_dns"
    accepts = {T.DOMAIN, T.URL}
    produces: set[T] = set()
    tags = {"offline", "free"}
    reference = "https://tranco-list.eu/"
    terms = "open"
    opsec = Opsec.PASSIVE
    disclosure = "none"
    hosts = ()
    sources = (LIST_SOURCE, ID_SOURCE)
    max_requests = 0
    expected_latency = 0.05
    timeout = 60.0
    default_enabled = True
    notice = (
        "Local Tranco list only (v3lum data update tranco_rank.top1m): no lookup ever leaves the machine. Popularity is "
        "context and a score dampener for the exact registrable domain, never known_good. Cite: Le Pochat et al., "
        "'Tranco: A Research-Oriented Top Sites Ranking Hardened Against Manipulation', NDSS 2019."
    )

    def applies(self, entity: Entity, ctx: Any) -> bool:
        return bool(_host_of(entity))

    def run(self, entity: Entity, ctx: Any) -> ModuleResult:
        res = self.result(entity)
        host = _host_of(entity)
        if not host:
            return res.mark("skipped", "no domain host to rank", reason_code="not_applicable")
        info = ctx.data.info(LIST_DATASET)
        if not info.present:
            # P010 c2: no API fallback, never downloaded mid-scan
            return res.mark("unavailable", f"Tranco list not downloaded: run v3lum data update {LIST_DATASET}", reason_code="dataset")
        try:
            csv_path = Path(ctx.data.fetch(LIST_DATASET, ttl=NO_REFRESH_TTL))
            index = open_index(csv_path, info.sha256 or _sha256_file(csv_path))
        except DatasetUnavailable as exc:
            return res.mark("unavailable", str(exc), reason_code="dataset")
        except (DatasetError, OSError, ValueError, sqlite3.Error) as exc:
            return res.mark("error", f"Tranco list unreadable ({type(exc).__name__}: {str(exc)[:120]}): could not verify")
        try:
            try:
                platforms = load_shared_platforms(ctx.data.bundled_json(SHARED_PLATFORMS_FILE))
            except (OSError, ValueError):
                platforms = {}
            facts = rank_facts(host, index.lookup, platforms)
        except sqlite3.Error as exc:
            return res.mark("error", f"Tranco index lookup failed ({type(exc).__name__}): could not verify")
        finally:
            index.close()
        list_id, id_fetched = _list_id(ctx)
        list_date = list_date_of(info.fetched_at)
        age = _age_days(info.fetched_at, ctx.now())
        provenance = {
            "dataset": LIST_DATASET,
            "list_id": list_id,
            "list_date": list_date,
            "list_date_basis": "download time (Tranco publishes each daily list at ~22:00 UTC)",
            "sha256": info.sha256,
            "fetched_at": info.fetched_at,
            "list_id_fetched_at": id_fetched,
            "stale": bool(info.stale),
            "list_url": LIST_PAGE.format(list_id=list_id) if list_id else "",
        }
        res.attr("tranco_lookup_domain", facts["lookup_key"])
        if facts["rank"]:
            res.attr("tranco_rank", facts["rank"])
        res.attr("tranco_popularity", popularity(facts))
        res.attr("tranco_context", context_line(facts, list_id, list_date, old_days=age))
        res.attr("tranco_list", {k: v for k, v in provenance.items() if v not in ("", None)})
        if facts["shared_platform"]:
            res.attr("shared_platform", facts["shared_platform"])
        res.attr("tranco_dampener", dampener(facts, entity.type))
        res.raw = {"host": host, **{k: v for k, v in facts.items() if k != "host"}, "provenance": provenance, "citation": TRANCO_CITATION}
        if list_id:
            res.link(f"Tranco list {list_id}", LIST_PAGE.format(list_id=list_id))
        return res


def _host_of(entity: Entity) -> str:
    if entity.type is T.URL:
        host = url_host(entity.value) or ""
    else:
        host = entity.value
    host = str(host or "").strip().lower().rstrip(".")
    if not host or "." not in host or re.fullmatch(r"[0-9.]+|[0-9a-f:]+", host):
        return ""  # IP literals and single labels have no Tranco rank
    return host


__all__ = [
    "BUCKETS",
    "ID_DATASET",
    "LIST_DATASET",
    "TRANCO_CITATION",
    "TrancoIndex",
    "TrancoRank",
    "build_index",
    "check_head",
    "context_line",
    "dampener",
    "index_path",
    "iter_rows",
    "list_date_of",
    "load_shared_platforms",
    "open_index",
    "rank_facts",
    "shared_platform",
    "validate_list",
    "validate_list_id",
]

