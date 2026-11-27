"""Intelligence X selector metadata (P139): intelligent-search metadata and the own-domain phonebook.

Two modules over one allow-listed client (sources C0311 and C0312, host ``free.intelx.io``, key
``intelx`` sent in the ``x-key`` header):

* ``intelx_metadata`` - intelligent search for an e-mail address, domain or URL: per indexed item
  only its system id, bucket and date (cond 4). ``run_on='own_assets'`` (A4): own assets, or
  analyst-typed seeds with ``--breach-scope all`` and ``--purpose``; for a selector that is not an own
  asset only bucket names and dates are kept - no system ids and no analyst links (cond 5).
* ``intelx_phonebook`` - phonebook selectors (e-mails, subdomains, URLs) of a VERIFIED own domain
  (``run_on='own_assets_only'``, A11 BR4: txt_verified or attested): harvesting third parties' e-mails
  from a leak index is people-search over leaks (rule 4), so selectors outside the organisation's
  verified domains are counted and dropped, never kept (cond 5).

Binding rules (P139 final conditions):

1. Endpoint allow-list (:data:`ENDPOINTS`): intelligent search and phonebook search, their result
   polling and terminate - nothing else can be built (:func:`intelx_url`) or sent
   (:func:`intelx_url_allowed` is checked before every request). File preview/view/read/download/export
   and account endpoints are not in the table: leaked content is never fetched (rule 3).
2. ``x-key`` header (:func:`intelx_headers`); key-terms: legal records the plan before it runs under
   the corporate profile; the provider quota block (P334) and the HTTP 402 marker keep the daily
   credits; 401 is NEEDS_KEY.
3. Bounded polling: at most :data:`MAX_POLLS` result polls within :data:`MAX_POLL_SECONDS` (delays
   :data:`POLL_DELAYS`), then a terminate call (:func:`next_action`).
4. Stored: system id, bucket, date and selector type only; sensitive bucket names are masked
   (:func:`bucket_display`). The P145 schemas of ``intelx.search``/``intelx.phonebook`` (provider
   fragment) drop item names, descriptions and every other field before the module reads a body.
5. Phonebook own-asset-only; non-own selectors keep bucket names and dates only; e-mails follow A4.
6. Analyst link ``https://intelx.io/?did={systemid}`` (:func:`manual_link`) for own assets only,
   never fetched (P311 rendering rules apply). ``default_enabled=False``. Every success fixture is
   synthetic (IntelX SDK shapes) until a trimmed real answer is captured with the company key.
"""

from __future__ import annotations

import re
import time
import urllib.parse
from collections.abc import Iterable
from typing import Any

from v3lum.core.clock import SystemClock
from v3lum.core.entities import Entity, generic_address_kind
from v3lum.core.entities import EntityType as T
from v3lum.core.http import Cancelled, HttpError, NetworkError
from v3lum.core.models import ModuleResult, Opsec
from v3lum.core.module import Module, register
from v3lum.modules.breach_leak.breach_accounts import LGPD_NOTE, SCOPE_SKIP
from v3lum.modules.breach_leak.leak_lookup_public import sensitive_breach_name

__all__ = [
    "BASE",
    "ENDPOINTS",
    "FORBIDDEN_WORDS",
    "HOST",
    "KEY_HEADER",
    "KEY_NAME",
    "MANUAL_LINK",
    "MAX_POLLS",
    "MAX_POLL_SECONDS",
    "POLL_DELAYS",
    "SRC_PHONEBOOK",
    "SRC_SEARCH",
    "IntelxMetadata",
    "IntelxPhonebook",
    "bucket_display",
    "clean_url_selector",
    "intelx_headers",
    "intelx_url",
    "intelx_url_allowed",
    "manual_link",
    "next_action",
    "parse_intelligent_result",
    "parse_phonebook_result",
    "parse_search_start",
    "search_body",
    "summarise_records",
]

SRC_SEARCH = "intelx.search"
SRC_PHONEBOOK = "intelx.phonebook"
KEY_NAME = "intelx"
KEY_HEADER = "x-key"
HOST = "free.intelx.io"
BASE = "https://" + HOST
#: cond 1 allow-list: operation -> (method, path, allowed query parameters)
ENDPOINTS: dict[str, tuple[str, str, tuple[str, ...]]] = {
    "intelligent_search": ("POST", "/intelligent/search", ()),
    "intelligent_result": ("GET", "/intelligent/search/result", ("id", "limit")),
    "phonebook_search": ("POST", "/phonebook/search", ()),
    "phonebook_result": ("GET", "/phonebook/search/result", ("id", "limit", "offset")),
    "terminate": ("GET", "/intelligent/search/terminate", ("id",)),
}
#: words no allowed path may contain (content and account endpoints, cond 1)
FORBIDDEN_WORDS = ("file", "preview", "view", "read", "download", "export", "authenticate")
MAX_POLLS = 5
MAX_POLL_SECONDS = 30.0
POLL_DELAYS = (1.0, 2.0, 3.0, 5.0, 8.0)  # 19 s of waiting at most, inside the 30 s budget
SEARCH_TIMEOUT = 10  # server-side search timeout (seconds) sent in the request body
MAXRESULTS = {"intelligent": 100, "phonebook": 1000}
PHONEBOOK_TARGETS = {"all": 0, "domain": 1, "email": 2, "url": 3}
MANUAL_LINK = "https://intelx.io/?did={systemid}"
LINK_CAP = 20
SELECTOR_CAP = 200
_SELECTOR_TYPES = {"email address": "email", "domain": "domain", "url": "url"}
_SELECTOR_CODES = {1: "email", 2: "domain", 3: "url"}
_UUID = re.compile(r"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$", re.I)
_LABEL = re.compile(r"^(?!-)[a-z0-9-]{1,63}(?<!-)$")
_EDGE = " \t\r\n()[]<>{},;:'\"`"
_RESULT_STATES = {0: "results", 1: "done", 2: "not_found", 3: "pending"}

#: documented IntelX buckets (product categories, not personal data) and their display category
KNOWN_BUCKETS = {
    "pastes": "pastes",
    "darknet.tor": "darknet", "darknet.i2p": "darknet",
    "leaks.public.general": "data leaks", "leaks.private.general": "data leaks",
    "leaks.public.wikileaks": "data leaks", "leaks.private.comb": "data leaks",
    "leaks.logs": "stealer logs",
    "dumpster": "dumpster", "dumpster.web.1": "dumpster",
    "documents.public.scihub": "documents",
    "usenet": "usenet", "whois": "whois",
}
BUCKET_ROOTS = {"pastes": "pastes", "darknet": "darknet", "leaks": "data leaks", "dumpster": "dumpster",
                "documents": "documents", "usenet": "usenet", "whois": "whois", "web": "web"}
SENSITIVE_BUCKET = "sensitive bucket (name withheld)"
_WITHHELD = "(name withheld)"
#: bucket categories that make an own-asset listing MEDIUM (credentials may be involved); never higher
_MEDIUM_CATEGORIES = frozenset({"stealer logs", "data leaks"})


# --------------------------------------------------------------------------------------
# small parsers (untrusted data: wrong types never raise)
# --------------------------------------------------------------------------------------


def _str(value: Any, cap: int = 300) -> str | None:
    if isinstance(value, str):
        s = " ".join(value.split())[:cap]
        return s or None
    return None


def _int(value: Any) -> int | None:
    if isinstance(value, bool):
        return None
    if isinstance(value, int):
        return value
    if isinstance(value, str) and re.fullmatch(r"\s*-?\d{1,9}\s*", value):
        return int(value)
    return None


def _domain(value: Any) -> str | None:
    """Lower-case ASCII (IDNA) host name without trailing dot or leading '*.', else None."""
    if not isinstance(value, str):
        return None
    text = value.strip(_EDGE).lower().rstrip(".")
    if text.startswith("*."):
        text = text[2:]
    if not text or len(text) > 253:
        return None
    try:
        text = text.encode("idna").decode("ascii")
    except UnicodeError:
        return None
    labels = text.split(".")
    if len(labels) < 2 or not all(_LABEL.match(x) for x in labels) or labels[-1].isdigit():
        return None
    return text


def _email(value: Any) -> str | None:
    if not isinstance(value, str):
        return None
    v = value.strip(_EDGE).lower()
    if v.count("@") != 1 or any(c.isspace() for c in v):
        return None
    local, dom = v.split("@")
    host = _domain(dom)
    if not local or len(local) > 64 or host is None:
        return None
    return f"{local}@{host}"


def clean_url_selector(url: Any) -> str | None:
    """http(s) URL reduced to scheme://host[:port]/path, else None: userinfo, query and fragment are
    dropped (they can carry credentials or per-recipient tokens; rule 3, A7 BR12)."""
    if not isinstance(url, str):
        return None
    text = url.strip(_EDGE)
    try:
        parts = urllib.parse.urlsplit(text)
        port = parts.port
    except ValueError:
        return None
    if parts.scheme.lower() not in ("http", "https") or not parts.hostname:
        return None
    host = _domain(parts.hostname)
    if host is None:
        return None
    netloc = host + (f":{port}" if port else "")
    path = (parts.path or "/")[:200]
    return urllib.parse.urlunsplit((parts.scheme.lower(), netloc, path, "", ""))


# --------------------------------------------------------------------------------------
# cond 1-2: the allow-listed client pieces
# --------------------------------------------------------------------------------------


def intelx_url(op: str, **params: Any) -> tuple[str, str]:
    """(method, url) of an allow-listed operation; ValueError for anything else (cond 1).

    Only intelligent/phonebook search, their result polling and terminate can be built; the key never
    goes in the URL (``x-key`` header only, AR01)."""
    if op not in ENDPOINTS:
        raise ValueError(f"Intelligence X operation not allow-listed: {op!r} (P139 cond 1)")
    method, path, allowed = ENDPOINTS[op]
    query: list[tuple[str, str]] = []
    for pname, value in params.items():
        if pname not in allowed:
            raise ValueError(f"parameter {pname!r} not allowed for {op}")
        if pname == "id":
            if not isinstance(value, str) or not _UUID.match(value):
                raise ValueError("Intelligence X search id must be a UUID")
        elif pname == "limit":
            n = _int(value)
            if n is None or not 1 <= n <= 10000:
                raise ValueError("limit must be 1..10000")
            value = n
        elif pname == "offset":
            n = _int(value)
            if n is None or n < -1:
                raise ValueError("offset must be >= -1")
            value = n
        query.append((pname, str(value)))
    if "id" in allowed and "id" not in params:
        raise ValueError(f"{op} needs the search id")
    return method, BASE + path + ("?" + urllib.parse.urlencode(query) if query else "")


def intelx_url_allowed(method: Any, url: Any) -> bool:
    """True only for an allow-listed (method, URL) on free.intelx.io (cond 1): https, exact host and
    path, matching method, only the path's own parameters, no userinfo/fragment, no key in the URL."""
    if not isinstance(url, str) or not isinstance(method, str):
        return False
    try:
        parts = urllib.parse.urlsplit(url)
        port = parts.port
    except ValueError:
        return False
    if parts.scheme != "https" or (parts.hostname or "").lower() != HOST or port not in (None, 443):
        return False
    if parts.username or parts.password or parts.fragment:
        return False
    if any(word in parts.path.lower() for word in FORBIDDEN_WORDS):
        return False
    for m, path, allowed in ENDPOINTS.values():
        if parts.path == path and method.upper() == m:
            names = [k for k, _v in urllib.parse.parse_qsl(parts.query, keep_blank_values=True)]
            return all(n in allowed for n in names) and len(names) == len(set(names))
    return False


def intelx_headers(key: Any) -> dict[str, str]:
    """The key header (cond 2: ``x-key``); ValueError for a missing or malformed key."""
    key = key.strip() if isinstance(key, str) else ""
    if not key or any(c in key for c in "\r\n\t "):
        raise ValueError("Intelligence X key missing or malformed")
    return {KEY_HEADER: key}


def search_body(term: Any, kind: str, etype: T, target: str = "all") -> dict[str, Any]:
    """JSON body of an intelligent or phonebook search (cond 1, 3, 5). Phonebook takes a domain only."""
    if kind not in MAXRESULTS:
        raise ValueError(f"unknown Intelligence X search kind {kind!r}")
    if kind == "phonebook" and etype is not T.DOMAIN:
        raise ValueError("phonebook searches take an own domain only (P139 cond 5)")
    if etype is T.EMAIL:
        value = _email(term)
    elif etype is T.DOMAIN:
        value = _domain(term)
    elif etype is T.URL:
        value = clean_url_selector(term)
    else:
        raise ValueError("Intelligence X selectors: email, domain or url only")
    if not value or len(value) > 2048:
        raise ValueError("unusable Intelligence X search term")
    body: dict[str, Any] = {
        "term": value, "buckets": [], "lookuplevel": 0, "maxresults": MAXRESULTS[kind], "timeout": SEARCH_TIMEOUT,
        "datefrom": "", "dateto": "", "sort": 4, "media": 0, "terminate": [],
    }
    if kind == "phonebook":
        body["target"] = PHONEBOOK_TARGETS[target]
    return body


# --------------------------------------------------------------------------------------
# cond 3-6: answers, polling, masking, summaries
# --------------------------------------------------------------------------------------


def bucket_display(bucket: Any) -> dict[str, Any]:
    """{'bucket', 'category', 'masked'} of an IntelX bucket (cond 4): documented buckets and
    web.public.<cc>/web.gov.<cc> keep their name; a sensitive-category word masks the whole name;
    unknown leaves keep their first two labels ('leaks.private (name withheld)'). Idempotent."""
    name = _str(bucket, 120)
    if name is None:
        return {"bucket": None, "category": None, "masked": False}
    low = name.lower()
    if low == SENSITIVE_BUCKET or (not low.endswith(_WITHHELD) and sensitive_breach_name(low)):
        return {"bucket": SENSITIVE_BUCKET, "category": "sensitive", "masked": True}
    root = low.split(".", 1)[0].split(" ", 1)[0]
    category = BUCKET_ROOTS.get(root, "other")
    if low.endswith(_WITHHELD):
        return {"bucket": low, "category": category, "masked": True}
    if low in KNOWN_BUCKETS:
        return {"bucket": low, "category": KNOWN_BUCKETS[low], "masked": False}
    if re.fullmatch(r"web\.(public|gov)\.[a-z]{2,3}", low):
        return {"bucket": low, "category": "web", "masked": False}
    head = ".".join(low.split(".")[:2]) if "." in low else root
    return {"bucket": f"{head} {_WITHHELD}", "category": category, "masked": True}


def _ix_date(value: Any) -> str | None:
    """'YYYY-MM-DD' of an IntelX timestamp; None for missing or placeholder (< 1990) dates."""
    text = _str(value, 40)
    if text is None:
        return None
    m = re.match(r"^(\d{4})-(\d{2})-(\d{2})", text)
    if not m or int(m.group(1)) < 1990 or not 1 <= int(m.group(2)) <= 12 or not 1 <= int(m.group(3)) <= 31:
        return None
    return "-".join(m.groups())


def parse_search_start(data: Any) -> dict[str, Any]:
    """Search-start answer -> {'id', 'status', 'soft_selector_warning', 'problem', 'kind'}.

    status 0 = started; 1 = invalid term (strong selectors only) -> error; 2 = too many concurrent
    searches -> rate_limited; a missing id -> error."""
    out: dict[str, Any] = {"id": None, "status": None, "soft_selector_warning": False, "problem": "", "kind": ""}
    if not isinstance(data, dict):
        out.update(problem="search start: the answer is not a JSON object", kind="error")
        return out
    status = _int(data.get("status"))
    out["status"] = status
    out["soft_selector_warning"] = data.get("softselectorwarning") is True
    sid = data.get("id")
    if status == 1:
        out.update(problem="Intelligence X rejected the term (invalid or soft selector)", kind="error")
    elif status == 2:
        out.update(problem="Intelligence X: maximum concurrent searches reached", kind="rate_limited")
    elif status != 0:
        out.update(problem=f"Intelligence X search start status {status!r}", kind="error")
    elif not isinstance(sid, str) or not _UUID.match(sid):
        out.update(problem="Intelligence X search start without a search id", kind="error")
    else:
        out["id"] = sid.lower()
    return out


def parse_intelligent_result(data: Any) -> dict[str, Any]:
    """Result poll -> {'status', 'state', 'records': [{systemid, bucket, category, masked, date, date_kind}]}.

    state: results (0, keep polling) | done (1) | not_found (2, search expired) | pending (3) |
    malformed. The date is the item date, else its indexing date (placeholder dates ignored)."""
    if not isinstance(data, dict):
        return {"status": None, "state": "malformed", "records": []}
    status = _int(data.get("status"))
    records = []
    raw = data.get("records")
    for rec in raw if isinstance(raw, list) else []:
        if not isinstance(rec, dict):
            continue
        sid = rec.get("systemid")
        if not isinstance(sid, str) or not _UUID.match(sid):
            continue
        date, kind = _ix_date(rec.get("date")), "item"
        if date is None:
            date, kind = _ix_date(rec.get("added")), "indexed"
        disp = bucket_display(rec.get("bucket"))
        if not disp["bucket"]:
            continue
        records.append({"systemid": sid.lower(), "bucket": disp["bucket"], "category": disp["category"],
                        "masked": disp["masked"], "date": date, "date_kind": kind if date else None})
    state = _RESULT_STATES.get(status, "malformed") if raw is None or isinstance(raw, list) else "malformed"
    return {"status": status, "state": state, "records": records}


def _selector_kind(sel: dict[str, Any]) -> str:
    label = (_str(sel.get("selectortypeh"), 40) or "").lower()
    if label in _SELECTOR_TYPES:
        return _SELECTOR_TYPES[label]
    if label:
        return "other"
    return _SELECTOR_CODES.get(_int(sel.get("selectortype")) or -1, "other")


def parse_phonebook_result(data: Any) -> dict[str, Any]:
    """Phonebook poll -> {'status', 'state', 'selectors': [{type, value}], 'dropped'} (cond 5): only
    e-mail, domain and URL selectors with a well-formed value; others are counted in 'dropped'."""
    if not isinstance(data, dict):
        return {"status": None, "state": "malformed", "selectors": [], "dropped": 0}
    status = _int(data.get("status"))
    out, dropped = [], 0
    raw = data.get("selectors")
    for sel in raw if isinstance(raw, list) else []:
        if not isinstance(sel, dict):
            dropped += 1
            continue
        kind = _selector_kind(sel)
        value = sel.get("selectorvalue")
        clean = _email(value) if kind == "email" else _domain(value) if kind == "domain" else clean_url_selector(value) if kind == "url" else None
        if clean:
            out.append({"type": kind, "value": clean})
        else:
            dropped += 1
    state = _RESULT_STATES.get(status, "malformed") if raw is None or isinstance(raw, list) else "malformed"
    return {"status": status, "state": state, "selectors": out, "dropped": dropped}


def next_action(polls_done: int, elapsed: float, last_state: str | None, collected: int = 0, maxresults: int | None = None) -> dict[str, Any]:
    """Bounded polling decision (cond 3: <= 5 polls, <= 30 s in total, terminate call).

    {'action': 'poll'|'stop', 'delay', 'terminate', 'partial', 'reason'}: done / not_found stop without
    terminate; maxresults, the poll cap and the time budget stop with terminate=True; otherwise the
    next delay of :data:`POLL_DELAYS`. ``elapsed`` = seconds since the search start was sent."""
    polls = max(0, int(polls_done or 0))
    try:
        spent = float(elapsed)
    except (TypeError, ValueError):
        spent = MAX_POLL_SECONDS
    if last_state == "done":
        return {"action": "stop", "delay": None, "terminate": False, "partial": False, "reason": "done"}
    if last_state == "not_found":
        return {"action": "stop", "delay": None, "terminate": False, "partial": True, "reason": "search_id_not_found"}
    if last_state not in ("results", "pending", None):
        return {"action": "stop", "delay": None, "terminate": True, "partial": True, "reason": "malformed"}
    if maxresults is not None and collected >= maxresults:
        return {"action": "stop", "delay": None, "terminate": True, "partial": False, "reason": "maxresults"}
    if polls >= MAX_POLLS:
        return {"action": "stop", "delay": None, "terminate": True, "partial": True, "reason": "poll_cap"}
    delay = POLL_DELAYS[polls]
    if spent + delay > MAX_POLL_SECONDS:
        return {"action": "stop", "delay": None, "terminate": True, "partial": True, "reason": "time_budget"}
    return {"action": "poll", "delay": delay, "terminate": False, "partial": False, "reason": None}


def manual_link(systemid: Any) -> str | None:
    """Analyst link https://intelx.io/?did={systemid} for a UUID system id, else None (cond 6). Manual
    only: V3LUM never requests it."""
    sid = _str(systemid, 64)
    if sid is None or not _UUID.match(sid):
        return None
    return MANUAL_LINK.format(systemid=sid.lower())


def summarise_records(records: Iterable[dict[str, Any]], *, own: bool, selector_type: str) -> dict[str, Any]:
    """Per-selector metadata (cond 4-6): always {selector_type, total, buckets [{bucket, category,
    masked, count, first_date, last_date}]}; only for own assets 'records' (systemid, bucket, date)
    and up to :data:`LINK_CAP` analyst links. Non-own selectors keep bucket names and dates only."""
    buckets: dict[str, dict[str, Any]] = {}
    kept: list[dict[str, Any]] = []
    seen: set[str] = set()
    for rec in records:
        if not isinstance(rec, dict) or not rec.get("bucket"):
            continue
        sid = rec.get("systemid")
        if sid:
            if sid in seen:  # the same item can come back in several polls
                continue
            seen.add(sid)
        b = buckets.setdefault(rec["bucket"], {"bucket": rec["bucket"], "category": rec.get("category"),
                                               "masked": bool(rec.get("masked")), "count": 0, "first_date": None, "last_date": None})
        b["count"] += 1
        d = rec.get("date")
        if d:
            b["first_date"] = d if b["first_date"] is None else min(b["first_date"], d)
            b["last_date"] = d if b["last_date"] is None else max(b["last_date"], d)
        if own and sid:
            kept.append({"systemid": sid, "bucket": rec["bucket"], "date": d})
    out: dict[str, Any] = {
        "selector_type": selector_type,
        "total": sum(b["count"] for b in buckets.values()),
        "buckets": sorted(buckets.values(), key=lambda b: (-b["count"], b["bucket"])),
    }
    if own:
        kept.sort(key=lambda r: (r["date"] or "", r["systemid"]), reverse=True)
        out["records"] = kept
        out["links"] = [link for link in (manual_link(r["systemid"]) for r in kept[:LINK_CAP]) if link]
    return out


# --------------------------------------------------------------------------------------
# the shared polling client
# --------------------------------------------------------------------------------------


class _Refused(Exception):
    """An allow-list or input refusal decided before any request (status, reason_code, reason)."""

    def __init__(self, status: str, reason: str, reason_code: str = "") -> None:
        super().__init__(reason)
        self.status, self.reason, self.reason_code = status, reason, reason_code


def _clock(ctx: Any) -> Any:
    clock = getattr(getattr(ctx, "runtime", None), "clock", None)
    return clock if clock is not None and callable(getattr(clock, "monotonic", None)) else None


def _monotonic(ctx: Any) -> float:
    clock = _clock(ctx)
    return float(clock.monotonic()) if clock is not None else time.monotonic()


def _pause(ctx: Any, seconds: float) -> None:
    """Wait between polls; the kill switch cuts it short (a test clock only advances)."""
    if seconds <= 0:
        return
    clock = _clock(ctx)
    if clock is not None and not isinstance(clock, SystemClock):
        clock.sleep(seconds)
    else:
        event = getattr(ctx, "cancel_event", None)
        if event is not None and callable(getattr(event, "wait", None)):
            event.wait(seconds)
        else:  # pragma: no cover - every Context has a cancel event
            time.sleep(seconds)
    cancelled = getattr(ctx, "cancelled", None)
    if callable(cancelled) and cancelled():
        raise Cancelled("cancelled while waiting for Intelligence X results")


def _send(ctx: Any, op: str, *, source: str, headers: dict[str, str], body: Any = None, **params: Any) -> Any:
    method, url = intelx_url(op, **params)
    if not intelx_url_allowed(method, url):  # cond 1: checked before every request
        raise _Refused("skipped", f"Intelligence X URL outside the allow-list ({op})", "policy")
    try:
        if method == "POST":
            return ctx.http.post_json(url, json_body=body, headers=headers, source=source, allow_redirects=False)
        return ctx.http.get_json(url, headers=headers, source=source, allow_redirects=False)
    except ValueError as exc:  # a 2xx body that is not JSON
        raise _Refused("error", f"Intelligence X answered something that is not JSON ({op}): could not verify") from exc


def _terminate(ctx: Any, sid: str, headers: dict[str, str], source: str) -> bool:
    """Best-effort terminate (cond 3): a failure never changes the run's outcome."""
    method, url = intelx_url("terminate", id=sid)
    if not intelx_url_allowed(method, url):
        return False
    remaining = ctx.remaining() if callable(getattr(ctx, "remaining", None)) else None
    if remaining is not None and remaining < 2.0:
        return False
    try:
        resp = ctx.http.get(url, headers=headers, source=source, allow_redirects=False)
    except (HttpError, NetworkError):
        return False
    return 200 <= int(getattr(resp, "status", 0) or 0) < 300


def run_search(ctx: Any, *, kind: str, body: dict[str, Any], source: str) -> dict[str, Any]:
    """Start a search, poll it within the cond 3 bounds and terminate it when it is left running.

    Returns {'records'|'selectors', 'dropped', 'polls', 'stop', 'partial', 'terminated', 'status',
    'soft_selector_warning'}; raises :class:`_Refused` for a refused start or an unusable answer.
    HTTP failures (401, 402, 429, 5xx, challenges) propagate: the engine maps them to NEEDS_KEY,
    QUOTA, RATE_LIMITED, ERROR or BLOCKED - never to an absence."""
    try:
        headers = intelx_headers(ctx.key(KEY_NAME))
    except ValueError as exc:
        raise _Refused("needs_key", "Intelligence X key missing or malformed (v3lum keys set intelx)") from exc
    started_at = _monotonic(ctx)
    start = parse_search_start(_send(ctx, f"{kind}_search", source=source, headers=headers, body=body))
    if start["kind"] == "rate_limited":
        raise _Refused("rate_limited", start["problem"] + ": could not verify now")
    if start["kind"]:
        raise _Refused("error", start["problem"] + ": could not verify")
    sid = start["id"]
    maxresults = int(body.get("maxresults") or MAXRESULTS[kind])
    items: list[dict[str, Any]] = []
    seen: set[str] = set()
    dropped = polls = 0
    state: str | None = None
    status = None
    while True:
        act = next_action(polls, _monotonic(ctx) - started_at, state, len(items), maxresults)
        if act["action"] == "stop":
            break
        remaining = ctx.remaining() if callable(getattr(ctx, "remaining", None)) else None
        if remaining is not None and remaining < float(act["delay"]) + 3.0:
            act = {"action": "stop", "delay": None, "terminate": True, "partial": True, "reason": "time_budget"}
            break
        _pause(ctx, float(act["delay"]))
        if kind == "phonebook":
            data = _send(ctx, "phonebook_result", source=source, headers=headers, id=sid, limit=maxresults, offset=-1)
            parsed = parse_phonebook_result(data)
            batch = parsed["selectors"]
            dropped += parsed["dropped"]
            key_of = "value"
        else:
            data = _send(ctx, "intelligent_result", source=source, headers=headers, id=sid, limit=maxresults)
            parsed = parse_intelligent_result(data)
            batch = parsed["records"]
            key_of = "systemid"
        polls += 1
        state, status = parsed["state"], parsed["status"]
        for item in batch:
            ident = f"{item.get('type', '')}:{item[key_of]}"
            if ident not in seen:
                seen.add(ident)
                items.append(item)
    terminated = _terminate(ctx, sid, headers, source) if act["terminate"] else False
    if act["reason"] == "malformed" and not items:
        raise _Refused("error", "Intelligence X result answer malformed: could not verify")
    if act["reason"] == "search_id_not_found" and not items:
        raise _Refused("error", "Intelligence X lost the search (id not found while polling): could not verify")
    return {"items": items[:maxresults], "dropped": dropped, "polls": polls, "stop": act["reason"], "partial": bool(act["partial"]),
            "terminated": terminated, "status": status, "soft_selector_warning": start["soft_selector_warning"]}


def _own(entity: Entity, ctx: Any) -> bool:
    """Own asset (A11 BR4): an entity covered by a txt_verified/attested org-profile entry."""
    org = getattr(ctx, "org", None)
    if org is None:
        return False
    try:
        return bool(getattr(org.owns(entity), "verified", False))
    except Exception:  # noqa: BLE001 - an unreadable profile owns nothing
        return False


def _third_party_allowed(ctx: Any) -> bool:
    options = getattr(ctx, "options", None)
    scope_all = str(getattr(options, "breach_scope", "own") or "own").strip().lower() == "all"
    purpose = str(getattr(options, "purpose", "") or "").strip()
    return scope_all and bool(purpose) and bool(getattr(ctx, "is_seed", False))


def _summary(kind: str, selector_type: str, out: dict[str, Any], total: int) -> dict[str, Any]:
    return {"kind": kind, "selector_type": selector_type, "polls": out["polls"], "stop": out["stop"], "partial": out["partial"],
            "total": total, "terminated": out["terminated"], "soft_selector_warning": out["soft_selector_warning"]}


@register
class IntelxMetadata(Module):
    name = "intelx_metadata"
    title = "Intelligence X selector metadata (buckets and dates)"
    description = (
        "Where an e-mail address, domain or URL appears in the Intelligence X leak/paste index: per item only its bucket "
        "and date (system ids and analyst links for own assets); the items themselves are never opened."
    )
    category = "breach_leak"
    accepts = {T.EMAIL, T.DOMAIN, T.URL}
    run_on = "own_assets"
    tags = {"breach", "leak_index"}
    reference = "https://github.com/IntelligenceX/SDK"
    notice = (
        "Key-terms: legal records the company Intelligence X plan before it runs under the corporate profile (the free tier "
        "forbids integrating the API without written consent; default off). Metadata only: file preview/view/read/download "
        "are never called. Third-party selectors keep bucket names and dates only. " + LGPD_NOTE
    )
    terms = "key-terms"
    opsec = Opsec.PASSIVE
    disclosure = "third_party"  # Intelligence X receives the selector
    provider = "intelx"
    sources = (SRC_SEARCH,)
    hosts = (HOST,)
    access_model = "free_auth_limited"
    requires_keys = (KEY_NAME,)
    max_requests = 7  # start + <= 5 polls + terminate (cond 3)
    expected_latency = 6.0
    timeout = 45.0  # <= 30 s of polling plus the requests themselves
    min_interval = 1.0
    cache_ttl = 0  # no-store: search ids are single use, third-party selectors stay out of the cache
    max_pivots = 0
    default_enabled = False  # cond 6

    def applies(self, entity: Entity, ctx: Any) -> bool:
        if entity.type is T.URL:
            return clean_url_selector(entity.value) is not None
        return True

    def run(self, entity: Entity, ctx: Any) -> ModuleResult:
        res = self.result(entity)
        allowed = getattr(ctx, "allowed_sources", None)
        if allowed is not None and SRC_SEARCH not in allowed:
            return res.mark("skipped", "Intelligence X terms not cleared under this licence profile", reason_code="licence")
        own = _own(entity, ctx)
        if not own and not _third_party_allowed(ctx):  # A4 scope, defence in depth next to run_on
            return res.mark("skipped", SCOPE_SKIP, reason_code="privacy")
        try:
            body = search_body(entity.value, "intelligent", entity.type)
        except ValueError:
            return res.mark("skipped", "value not usable as an Intelligence X selector", reason_code="not_applicable")
        try:
            out = run_search(ctx, kind="intelligent", body=body, source=SRC_SEARCH)
        except _Refused as ref:
            return res.mark(ref.status, ref.reason, reason_code=ref.reason_code)
        stype = entity.type.value
        summary = summarise_records(out["items"], own=own, selector_type=stype)
        total = summary["total"]
        res.attr("intelx_search", _summary("intelligent", stype, out, total))
        # evidence (sanitized again by the intelx.search schema): masked buckets and dates; ids only for own assets
        res.raw = {"status": out["status"], "records": [
            {**({"systemid": r["systemid"]} if own else {}), "bucket": r["bucket"], "date": r.get("date")} for r in (
                summary.get("records") if own else [{"bucket": b["bucket"], "date": b["last_date"]} for b in summary["buckets"]])
        ]}
        if total == 0:
            if out["stop"] == "done":
                res.presence("absent", marker="search finished (status 1) with no items: not found in the Intelligence X buckets of the plan",
                             checked_at=ctx.now(), source=SRC_SEARCH)
                res.error = "not found in the Intelligence X buckets of the plan"
                return res.mark("empty")
            return res.mark("error", f"Intelligence X search did not finish ({out['stop']}, {out['polls']} polls): could not verify")
        res.attr("intelx_buckets", summary["buckets"])
        if own:
            res.attr("intelx_records", summary["records"][:200])
            for link in summary["links"]:
                res.link(f"Intelligence X item {link.rsplit('=', 1)[-1][:8]} (manual; opens intelx.io)", link)
        generic = None
        if entity.type is T.EMAIL:
            try:
                generic = generic_address_kind(entity.value) or None
            except Exception:  # noqa: BLE001
                generic = None
            if generic:
                res.attr("generic_address", generic)
        self._finding(res, entity, summary, own=own, generic=generic, partial=out["partial"])
        return res

    @staticmethod
    def _finding(res: ModuleResult, entity: Entity, summary: dict[str, Any], *, own: bool, generic: str | None, partial: bool) -> None:
        buckets = summary["buckets"]
        categories = sorted({b["category"] for b in buckets if b.get("category")})
        firsts = [b["first_date"] for b in buckets if b.get("first_date")]
        lasts = [b["last_date"] for b in buckets if b.get("last_date")]
        parts = [f"{b['bucket']} x{b['count']}" + (f" ({b['first_date']} - {b['last_date']})" if b.get("first_date") else "") for b in buckets[:12]]
        what = (f"{summary['total']} indexed item(s) mention this {summary['selector_type']}: " + "; ".join(parts)
                + (" ..." if len(buckets) > 12 else "") + (" (partial: polling stopped at its bound)" if partial else "")
                + ". Bucket names and dates only: the items were not opened or read (rule 3).")
        tags = ["leak_index"]
        if entity.type is T.EMAIL:
            tags.append("privacy")
        if generic:
            severity, conf = "info", "possible"
            criterion = f"POSSIBLE - generic or role address ({generic}): flagged, never scored (A4 BR6)"
            tags += ["context_only"] + ([] if own else ["third_party"])
        elif not own:
            severity, conf = "info", "possible"
            criterion = "Intelligence X lists items mentioning a third-party selector: context only, bucket names and dates only (P139 cond 5)"
            tags += ["context_only", "third_party"]
        else:
            medium = bool(set(categories) & _MEDIUM_CATEGORIES)
            severity, conf = ("medium" if medium else "low"), "possible"
            criterion = ("own asset mentioned in Intelligence X " + ("data-leak or stealer-log buckets" if medium else "paste/darknet/web buckets")
                         + ": the selector string appears in indexed items (not read); confirm with the analyst links")
            tags.append("own_asset")
        res.finding(
            "Mentioned in the Intelligence X leak/paste index",
            severity,
            what,
            confidence=conf,
            criterion=criterion,
            data={"total": summary["total"], "buckets": buckets[:50], "categories": categories, "own_asset": own},
            tags=tags,
            references=["https://intelx.io/"],
            source=SRC_SEARCH,
            observed_first=min(firsts) if firsts else None,
            observed_last=max(lasts) if lasts else None,
        )


@register
class IntelxPhonebook(Module):
    name = "intelx_phonebook"
    title = "Intelligence X phonebook (own domains only)"
    description = (
        "E-mail addresses, subdomains and URLs the Intelligence X phonebook lists for a VERIFIED own domain (selectors only, "
        "never content); selectors outside the organisation's verified domains are counted, never kept."
    )
    category = "breach_leak"
    accepts = {T.DOMAIN}
    produces = {T.EMAIL, T.DOMAIN, T.URL}
    run_on = "own_assets_only"
    tags = {"breach", "leak_index"}
    reference = "https://github.com/IntelligenceX/SDK"
    notice = (
        "Own assets only (txt_verified or attested org-profile domains): harvesting third parties' addresses from a leak "
        "index is people-search over leaks (rule 4). Key-terms: legal records the company plan first (phonebook lookups are "
        "not part of the free tier); default off. Harvested addresses are listed for the analyst, never checked "
        "automatically. " + LGPD_NOTE
    )
    terms = "key-terms"
    opsec = Opsec.PASSIVE
    disclosure = "third_party"
    provider = "intelx"
    sources = (SRC_PHONEBOOK,)
    hosts = (HOST,)
    access_model = "free_auth_limited"
    requires_keys = (KEY_NAME,)
    max_requests = 7  # start + <= 5 polls + terminate (cond 3)
    expected_latency = 6.0
    timeout = 45.0
    min_interval = 1.0
    cache_ttl = 0
    max_pivots = 3 * SELECTOR_CAP
    default_enabled = False  # cond 6

    def run(self, entity: Entity, ctx: Any) -> ModuleResult:
        res = self.result(entity)
        allowed = getattr(ctx, "allowed_sources", None)
        if allowed is not None and SRC_PHONEBOOK not in allowed:
            return res.mark("skipped", "Intelligence X terms not cleared under this licence profile", reason_code="licence")
        org = getattr(ctx, "org", None)
        if not _verified(org, entity.value):  # cond 5 / A11 BR4, defence in depth next to run_on
            return res.mark("skipped", "Intelligence X phonebook: own verified domains only (v3lum org verify)", reason_code="own_asset")
        try:
            body = search_body(entity.value, "phonebook", T.DOMAIN)
        except ValueError:
            return res.mark("skipped", "domain not usable as an Intelligence X phonebook term", reason_code="not_applicable")
        try:
            out = run_search(ctx, kind="phonebook", body=body, source=SRC_PHONEBOOK)
        except _Refused as ref:
            return res.mark(ref.status, ref.reason, reason_code=ref.reason_code)
        kept: dict[str, set[str]] = {"email": set(), "domain": set(), "url": set()}
        third = 0
        for sel in out["items"]:
            value = sel["value"]
            host = value.rsplit("@", 1)[-1] if sel["type"] == "email" else value if sel["type"] == "domain" else urllib.parse.urlsplit(value).hostname
            if not host or not _verified(org, host):
                third += 1  # people-search over leaks: counted, never kept (rule 4)
                continue
            kept[sel["type"]].add(value)
        truncated = any(len(v) > SELECTOR_CAP for v in kept.values())
        emails = sorted(kept["email"])[:SELECTOR_CAP]
        domains = sorted(d for d in kept["domain"] if d != entity.value)[:SELECTOR_CAP]
        urls = sorted(kept["url"])[:SELECTOR_CAP]
        generic = {}
        for e in emails:
            try:
                kind = generic_address_kind(e)
            except Exception:  # noqa: BLE001
                kind = None
            if kind:
                generic[e] = kind
        total = len(emails) + len(domains) + len(urls)
        res.attr("intelx_search", _summary("phonebook", "domain", out, total))
        res.attr("intelx_phonebook", {"emails": len(emails), "domains": len(domains), "urls": len(urls), "generic_emails": len(generic),
                                      "third_party_dropped": third, "other_dropped": out["dropped"], "truncated": truncated})
        if third:
            res.attr("third_party_counts", {"selectors": third})
        res.raw = {"status": out["status"], "selectors": (
            [{"selectorvalue": v, "selectortype": "email"} for v in emails]
            + [{"selectorvalue": v, "selectortype": "domain"} for v in domains]
            + [{"selectorvalue": v, "selectortype": "url"} for v in urls])}
        if total == 0:
            if out["stop"] == "done":
                res.presence("absent", marker="phonebook search finished (status 1) with no own-domain selectors", checked_at=ctx.now(), source=SRC_PHONEBOOK)
                res.error = "no own-domain selectors in the Intelligence X phonebook"
                return res.mark("empty")
            return res.mark("error", f"Intelligence X phonebook search did not finish ({out['stop']}, {out['polls']} polls): could not verify")
        for e in emails:
            note = "own-domain address listed by a leak-index phonebook: analyst selection required"
            if e in generic:
                note += f" (generic/role address: {generic[e]}, never scored)"
            res.pivot(T.EMAIL, e, "leak_index_selector", confidence="possible", expand=False, note=note)
        for d in domains:
            res.pivot(T.DOMAIN, d, "subdomain", confidence="possible", expand=False, note="own subdomain listed by a leak-index phonebook")
        for u in urls:
            res.pivot(T.URL, u, "hosts_url", confidence="possible", expand=False, note="own URL listed by a leak-index phonebook (query and userinfo removed)")
        personal = len(emails) - len(generic)
        res.finding(
            "Own-domain selectors listed in the Intelligence X phonebook",
            "low" if personal else "info",
            f"The Intelligence X phonebook lists {len(emails)} address(es) ({len(generic)} generic/role), {len(domains)} subdomain(s) and "
            f"{len(urls)} URL(s) of this verified own domain" + (" (capped)" if truncated else "")
            + (f"; {third} selector(s) outside the organisation's verified domains were counted and dropped" if third else "")
            + ". Selectors only: the leaked items were not read. Review exposed addresses with the per-address breach modules.",
            confidence="possible",
            criterion="Intelligence X phonebook on a verified own domain: selectors seen in indexed leaks/pastes, metadata only (P139 cond 5)",
            data={"emails": len(emails), "domains": len(domains), "urls": len(urls), "generic_emails": len(generic), "third_party_dropped": third},
            tags=["leak_index", "privacy", "own_asset"],
            references=["https://intelx.io/"],
            source=SRC_PHONEBOOK,
        )
        return res


def _verified(org: Any, domain: Any) -> bool:
    if org is None or not isinstance(domain, str):
        return False
    try:
        return bool(org.is_verified_domain(domain))
    except Exception:  # noqa: BLE001 - an unreadable profile owns nothing
        return False
