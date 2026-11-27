"""X/Twitter public data without login (P119): oEmbed for status URLs + opt-in deleted-post recovery.

Two modules share this file (batch p3-G05-3):

* ``x_twitter_public`` (input: an X/Twitter status URL) - cond 1: the published oEmbed interface
  ``publish.twitter.com/oembed?url=<status URL>&omit_script=true&dnt=true`` (its 301 to publish.x.com is
  followed only to that oEmbed endpoint). It returns the author handle (username pivot, expand=False), the
  embed text and whether X still serves the post. cond 3: a 404 is 'no longer available (deleted,
  protected or suspended)', never 'deleted' or 'never existed'; 429/5xx/challenges are could-not-verify.
  twitter.com / x.com pages are never requested (they are not declared hosts: the core refuses them).
* ``x_twitter_recovery`` (input: an analyst-typed X handle, ``run_on='seeds'``) - cond 4: deleted-post
  recovery, opt-in per run (a separate module that runs only when selected explicitly: usernames reach an
  unreviewed provider only with ``-M`` and a purpose, POL-07). The status URLs archived for the handle come
  from the Wayback CDX index through the shared CDX helpers of ``web_archives`` (P059:
  ``parse_wayback_cdx``, ``failure``) with collapse=urlkey, limit <= 500, archive hosts only; each unique
  status id is checked with oEmbed and the ones that are no longer available are labelled 'archived copy'
  (an id_ link on web.archive.org, never fetched from X).

cond 2: the cdn.syndication.twimg.com tweet-result adapter is NOT built (X's terms: published interfaces
only); no crawler or search-engine User-Agent is ever sent (the twayback DuckDuckBot trick is excluded:
the provider profiles use the neutral V3LUM UA and a test asserts no bot UA reaches the transport).
cond 5: status ids are decoded offline by the shared P314 decoder and labelled 'derived from id'; the
oEmbed interface carries no numeric user id, so only author handles become username pivots (expand=False).
cond 6: terms 'unknown' until legal records the X oEmbed terms and the Internet Archive decision for this
use - disabled in every licence profile, default_enabled False.
"""

from __future__ import annotations

import re
from datetime import datetime, timedelta, timezone
from html.parser import HTMLParser
from typing import Any
from urllib.parse import urlencode, urljoin, urlsplit

from v3lum.config import SettingSpec
from v3lum.core.entities import Entity
from v3lum.core.entities import EntityType as T
from v3lum.core.http import (
    AuthRequired,
    Blocked,
    DeadlineExceeded,
    HttpError,
    NetworkError,
    QuotaExceeded,
    RateLimited,
)
from v3lum.core.models import ModuleResult, Opsec, Status
from v3lum.core.module import Module, register
from v3lum.modules.url_web.web_archives import CDX, failure, parse_wayback_cdx, wayback_ts_to_iso

try:  # the shared P314 decoder (batch p2-G12-2); the core snowflake decoder below is the fallback
    from v3lum.modules.utility.id_timestamp_decoders import decode_platform_id as _p314_decode
except ImportError:  # pragma: no cover - only when the P314 module is absent
    _p314_decode = None

SOURCE_OEMBED = "x_corp.oembed"
SOURCE_SOCIAL = "internet_archive.wayback_social"
OEMBED_HOSTS = ("publish.twitter.com", "publish.x.com")  # cond 1 (+ its 301 target)
OEMBED_PATH = "/oembed"
X_UNAVAILABLE_TEXT = "no longer available (deleted, protected or suspended)"  # cond 3, verbatim
COULD_NOT_VERIFY = "could not verify"
DERIVED_LABEL = "derived from id"
ARCHIVED_COPY = "archived copy"
OEMBED_TTL = 86400  # 24 h for 200 and 404 answers (the provider's 100-year max-age is capped)
CDX_TTL = 86400
CDX_LIMIT_MAX = 500  # cond 4
X_EPOCH_MS = 1288834974657
X_MIN_SNOWFLAKE_ID = 29_000_000_000_000  # P314 c3: ids below ~2.9e13 are sequential (pre-November 2010)
_ROLLOUT = datetime(2010, 11, 4, tzinfo=timezone.utc)
_EPOCH_LABEL = "X snowflake epoch 1288834974657 ms: (id >> 22) + epoch"

_HANDLE_RE = re.compile(r"^[A-Za-z0-9_]{1,15}$")
_RESERVED = frozenset({"i", "home", "search", "intent", "share", "hashtag", "explore", "settings", "login", "signup",
                       "messages", "notifications", "compose", "account", "tos", "privacy"})
_STATUS_RE = re.compile(
    r"^(?:https?://)?(?:(?:www|mobile|m)\.)?(?P<host>twitter\.com|x\.com)(?::\d+)?/(?:#!/)?"
    r"(?:(?P<web>i/web|i)|(?P<handle>[A-Za-z0-9_]{1,15}))/status(?:es)?/(?P<id>\d{1,20})(?P<rest>[/?#].*)?$",
    re.I,
)
_LOGIN_PATHS = ("/login", "/i/flow/login", "/account/access", "/i/flow/signup")

#: Crawler / search-engine UA tokens (cond 4: twayback's DuckDuckBot trick and any crawler UA are excluded).
_BOT_UA_TOKENS = (
    "duckduckbot", "googlebot", "bingbot", "slurp", "baiduspider", "yandexbot", "applebot", "twitterbot",
    "facebookexternalhit", "facebot", "adsbot", "mediapartners-google", "ia_archiver", "archive.org_bot",
    "bytespider", "petalbot", "sogou", "exabot", "semrushbot", "ahrefsbot", "mj12bot", "dotbot", "gptbot",
    "claudebot", "ccbot", "seznambot", "linkedinbot", "slackbot", "discordbot", "telegrambot", "whatsapp",
    "embedly", "redditbot", "pinterestbot", "skypeuripreview",
)
_BOT_UA_GENERIC = re.compile(r"(?i)(?:^|[\s;(])[\w.-]*(?:bot|spider|crawler)/\d|compatible;\s*[\w.-]*(?:bot|spider|crawler)\b")


# ================================================================================ pure helpers


def normalise_x_handle(value: Any) -> str | None:
    """'@Handle', 'https://x.com/Handle' or 'Handle' -> 'Handle' (case kept), else None."""
    if not isinstance(value, str):
        return None
    v = value.strip()
    m = re.match(r"^(?:https?://)?(?:(?:www|mobile|m)\.)?(?:twitter|x)\.com/(?:#!/)?([^/?#]+)", v, re.I)
    if m:
        v = m.group(1)
    v = v.lstrip("@")
    if not _HANDLE_RE.match(v) or v.lower() in _RESERVED:
        return None
    return v


def parse_status_url(url: Any) -> dict[str, Any] | None:
    """cond 1 + the P333 tweet/status URL detector pattern: twitter.com / x.com (www., mobile., m.),
    '/statuses/', '#!/' hashbang URLs, '/i/web/status/', trailing '/photo/1', query strings and fragments.
    -> {status_id, handle (None for /i/ URLs), host, canonical_url} or None. Bare numbers never match."""
    if not isinstance(url, str) or len(url) > 2048:
        return None
    m = _STATUS_RE.match(url.strip())
    if not m:
        return None
    sid = m.group("id").lstrip("0")
    if not sid or int(sid) >= 1 << 64:
        return None
    handle = None if m.group("web") else m.group("handle")
    if handle and handle.lower() in _RESERVED:
        return None
    canonical = f"https://twitter.com/{handle}/status/{sid}" if handle else f"https://twitter.com/i/web/status/{sid}"
    return {"status_id": sid, "handle": handle, "host": m.group("host").lower(), "canonical_url": canonical}


def oembed_request_url(status_url: Any, host: str = "publish.twitter.com") -> str | None:
    """cond 1 default path: https://publish.twitter.com/oembed?url=<status URL>&omit_script=true&dnt=true
    (documented oEmbed parameters; dnt=true opts out of personalisation). None for non-status input."""
    p = parse_status_url(status_url)
    if not p or host not in OEMBED_HOSTS:
        return None
    return f"https://{host}{OEMBED_PATH}?" + urlencode({"url": p["canonical_url"], "omit_script": "true", "dnt": "true"})


def redirect_verdict(target: str) -> str:
    """'follow' (https to a declared oEmbed host and path), 'login' (a login/sign-up wall) or 'other'."""
    try:
        parts = urlsplit(target)
    except ValueError:
        return "other"
    host = (parts.hostname or "").lower()
    path = (parts.path or "").lower()
    if parts.scheme == "https" and host in OEMBED_HOSTS and path.startswith(OEMBED_PATH):
        return "follow"
    if any(path.startswith(p) for p in _LOGIN_PATHS):
        return "login"
    return "other"


def bot_user_agent_reason(ua: Any) -> str | None:
    """cond 4 ('a test asserts no bot UA is sent'): why ``ua`` impersonates a crawler, else None."""
    if not isinstance(ua, str) or not ua.strip():
        return "empty user agent"
    low = ua.lower()
    for tok in _BOT_UA_TOKENS:
        if tok in low:
            return f"crawler/search-engine UA token '{tok}'"
    if _BOT_UA_GENERIC.search(ua):
        return "crawler-style UA (bot/spider/crawler product token)"
    return None


def decode_status_time(status_id: Any, now: datetime | None = None) -> dict[str, Any]:
    """cond 5: creation time of a status id through the shared P314 decoder, labelled 'derived from id'.
    -> {decoded: True, created, epoch, label} or {decoded: False, reason}."""
    if _p314_decode is not None:
        out = _p314_decode("x", str(status_id), now=now)
        if out.get("status") == "ok":
            return {"decoded": True, "created": out["created"], "epoch": f"{out['epoch']} ({DERIVED_LABEL})", "label": DERIVED_LABEL}
        reasons = {"pre_snowflake": "sequential id (pre-November 2010): no time can be derived from it",
                   "out_of_window": "decoded time outside the platform's lifetime: discarded"}
        return {"decoded": False, "reason": reasons.get(str(out.get("status")), "not a canonical 64-bit id")}
    try:  # pragma: no cover - fallback with the same rules when the P314 module is not installed
        n = int(str(status_id))
    except ValueError:
        return {"decoded": False, "reason": "not a canonical 64-bit id"}
    if n < X_MIN_SNOWFLAKE_ID:
        return {"decoded": False, "reason": "sequential id (pre-November 2010): no time can be derived from it"}
    ms = (n >> 22) + X_EPOCH_MS
    dt = datetime.fromtimestamp(ms // 1000, tz=timezone.utc)
    now = now or datetime.now(timezone.utc)
    if dt < _ROLLOUT or dt > now + timedelta(days=1):
        return {"decoded": False, "reason": "decoded time outside the platform's lifetime: discarded"}
    return {"decoded": True, "created": dt.strftime("%Y-%m-%dT%H:%M:%S.") + f"{ms % 1000:03d}Z",
            "epoch": f"{_EPOCH_LABEL} ({DERIVED_LABEL})", "label": DERIVED_LABEL}


class _EmbedText(HTMLParser):
    """Text and links of the untrusted oEmbed blockquote (parsed as data; never rendered, scripts skipped)."""

    def __init__(self) -> None:
        super().__init__(convert_charrefs=True)
        self.depth_p = 0
        self.p_done = False
        self.p_lang: str | None = None
        self.p_text: list[str] = []
        self.anchors: list[dict[str, Any]] = []
        self._a: dict[str, Any] | None = None
        self.skip = 0

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        a = {k: (v or "") for k, v in attrs}
        if tag in ("script", "style"):
            self.skip += 1
        elif tag == "p" and not self.p_done:
            self.depth_p += 1
            self.p_lang = a.get("lang") or None
        elif tag == "a":
            self._a = {"href": a.get("href", ""), "text": "", "in_p": bool(self.depth_p)}
        elif tag == "br" and self.depth_p:
            self.p_text.append("\n")

    def handle_endtag(self, tag: str) -> None:
        if tag in ("script", "style") and self.skip:
            self.skip -= 1
        elif tag == "p" and self.depth_p:
            self.depth_p -= 1
            if not self.depth_p:
                self.p_done = True
        elif tag == "a" and self._a is not None:
            self.anchors.append(self._a)
            self._a = None

    def handle_data(self, data: str) -> None:
        if self.skip:
            return
        if self._a is not None:
            self._a["text"] += data
        if self.depth_p:
            self.p_text.append(data)


def parse_oembed(obj: Any, requested_id: str | None = None) -> dict[str, Any]:
    """cond 1/5: one oEmbed JSON answer (HTTP 200) -> {state 'available'|'error', status_id, handle,
    author_name, text, lang, date_text, mentions, hashtags, links, reason}. The embed HTML is parsed as
    untrusted text; an error object, a non-post embed or an answer about another status is 'error'."""
    out: dict[str, Any] = {"state": "error", "status_id": requested_id, "handle": None, "author_name": None, "text": None,
                           "lang": None, "date_text": None, "mentions": [], "hashtags": [], "links": [], "reason": None}
    if not isinstance(obj, dict):
        out["reason"] = "unexpected oEmbed answer (not a JSON object)"
        return out
    if obj.get("error") or obj.get("errors"):
        out["reason"] = "X oEmbed: error object inside HTTP 200"
        return out
    emb = obj.get("html")
    if not isinstance(emb, str) or "twitter-tweet" not in emb or len(emb) > 200_000:
        out["reason"] = "X oEmbed: answer is not a single-post embed"
        return out
    resp = parse_status_url(obj.get("url")) if isinstance(obj.get("url"), str) else None
    if requested_id and resp and resp["status_id"] != requested_id:
        out["reason"] = "X oEmbed: answer is about another status id"
        return out
    sid = resp["status_id"] if resp else requested_id
    handle = normalise_x_handle(obj.get("author_url")) if isinstance(obj.get("author_url"), str) else None
    if not handle and resp:
        handle = resp["handle"]
    col = _EmbedText()
    try:
        col.feed(emb)
        col.close()
    except Exception:  # noqa: BLE001 - malformed markup is data, not a crash
        pass
    mentions: list[str] = []
    hashtags: list[str] = []
    links: list[str] = []
    for a in col.anchors:
        if not a.get("in_p"):
            continue
        label = (a.get("text") or "").strip()
        href = a.get("href") or ""
        mention = normalise_x_handle(label) if label.startswith("@") else None
        if mention:
            if mention not in mentions:
                mentions.append(mention)
        elif label.startswith("#") and 1 < len(label) <= 140:
            if label[1:] not in hashtags:
                hashtags.append(label[1:])
        elif href.startswith(("http://", "https://")) and len(href) <= 2048 and href not in links:
            links.append(href)
    status_anchors = [a for a in col.anchors if not a.get("in_p") and parse_status_url(a.get("href", ""))]
    date_text = (status_anchors[-1].get("text") or "").strip()[:64] or None if status_anchors else None
    text = re.sub(r"[ \t]+", " ", "".join(col.p_text)).strip()[:4000] or None
    author = obj.get("author_name")
    out.update(state="available", status_id=sid, handle=handle, author_name=author[:200] if isinstance(author, str) else None,
               text=text, lang=(col.p_lang or "")[:16] or None, date_text=date_text, mentions=mentions[:20],
               hashtags=hashtags[:20], links=links[:20])
    return out


def cdx_params(handle: str, host: str, limit: int = CDX_LIMIT_MAX) -> dict[str, str]:
    """cond 4: one Wayback CDX query for <host>/<handle>/status/* (collapse=urlkey, statuscode 200, limit <= 500)."""
    n = max(1, min(int(limit), CDX_LIMIT_MAX))
    return {"url": f"{host}/{handle}/status/*", "output": "json", "fl": "original,timestamp,statuscode",
            "collapse": "urlkey", "filter": "statuscode:200", "limit": str(n)}


def x_status_rows(rows: list[dict[str, Any]], handle: str | None = None) -> dict[str, Any]:
    """cond 4/5: CDX rows of the shared parser -> unique status ids of ``handle``.

    Each archived URL is normalised with :func:`parse_status_url` (/photo/1, query strings, '#!/' removed),
    deduplicated by status id with first/last capture and capture count; the archived copy is the id_ link
    https://web.archive.org/web/<ts>id_/<url> on the archive host only (query-less original preferred).
    -> {statuses (newest capture first), skipped, other_handle}."""
    want = (handle or "").lower()
    by_id: dict[str, dict[str, Any]] = {}
    skipped = other = 0
    for row in rows or []:
        url, ts = row.get("url"), row.get("timestamp")
        p = parse_status_url(url) if isinstance(url, str) else None
        if not p or not isinstance(ts, str) or not re.fullmatch(r"\d{14}", ts):
            skipped += 1
            continue
        if want and p["handle"] and p["handle"].lower() != want:
            other += 1
            continue
        e = by_id.get(p["status_id"])
        clean = "?" not in url and "#" not in url and re.search(r"/status(?:es)?/0*" + p["status_id"] + r"/?$", url) is not None
        if e is None:
            e = by_id[p["status_id"]] = {"status_id": p["status_id"], "handle": p["handle"] or handle, "canonical_url": p["canonical_url"],
                                         "first_ts": ts, "last_ts": ts, "captures": 0, "_best": None}
        e["captures"] += 1
        e["first_ts"] = min(e["first_ts"], ts)
        e["last_ts"] = max(e["last_ts"], ts)
        if clean and (e["_best"] is None or ts > e["_best"][1]):
            e["_best"] = (url, ts)
    out: list[dict[str, Any]] = []
    for e in by_id.values():
        best = e.pop("_best")
        if best:
            orig = best[0] if best[0].startswith(("http://", "https://")) else "https://" + best[0]
            snap = f"https://web.archive.org/web/{best[1]}id_/{orig}"
        else:
            snap = f"https://web.archive.org/web/{e['last_ts']}id_/{e['canonical_url']}"
        e["first_capture"] = wayback_ts_to_iso(e.pop("first_ts"))
        e["last_capture"] = wayback_ts_to_iso(e.pop("last_ts"))
        e["archived_copy_url"] = snap
        out.append(e)
    out.sort(key=lambda r: (r["last_capture"] or "", int(r["status_id"])), reverse=True)
    return {"statuses": out, "skipped": skipped, "other_handle": other}


# ================================================================================ oEmbed fetch


def _json_obj(resp: Any) -> Any:
    try:
        return resp.json()
    except (HttpError, ValueError):
        return None


def fetch_oembed(ctx: Any, status_url: str, state: dict[str, str]) -> dict[str, Any]:
    """One oEmbed check (cond 1/3). ``state['host']`` is the oEmbed host to call (switched to publish.x.com
    after the first permanent redirect of a run). -> parse result with state 'available' | 'unavailable' |
    'blocked' | 'error'; 429, 403, challenges, 5xx and markers raise through the core (could not verify)."""
    p = parse_status_url(status_url)
    requested = p["status_id"] if p else None
    url = oembed_request_url(status_url, host=state.get("host", OEMBED_HOSTS[0]))
    if url is None:
        return {"state": "error", "status_id": requested, "reason": "not an X status URL"}
    for _hop in range(3):
        resp = ctx.http.get(url, source=SOURCE_OEMBED, allow_redirects=False, ttl=OEMBED_TTL)
        if resp.status in (301, 302, 303, 307, 308) and resp.classification is None:
            target = urljoin(url, str(resp.headers.get("location") or ""))
            verdict = redirect_verdict(target)
            if verdict == "follow":
                state["host"] = (urlsplit(target).hostname or OEMBED_HOSTS[1]).lower()
                url = target
                continue
            if verdict == "login":
                return {"state": "blocked", "status_id": requested, "reason_code": "login_wall",
                        "reason": "X oEmbed redirected to a login page: could not verify"}
            return {"state": "error", "status_id": requested, "reason_code": "error",
                    "reason": "X oEmbed redirected to an undeclared host: could not verify"}
        if resp.status == 404 and resp.classification is None:
            return {"state": "unavailable", "status_id": requested, "reason": X_UNAVAILABLE_TEXT}
        ctx.http.check(resp)  # 429/430 RateLimited, 401/403 AuthRequired, challenges Blocked, 5xx/markers HttpError
        if resp.status != 200:
            raise HttpError(f"X oEmbed HTTP {resp.status}: could not verify", resp.status, resp.url)
        obj = _json_obj(resp)
        if obj is None:
            ctx.http.evict(resp)
            return {"state": "error", "status_id": requested, "reason_code": "error",
                    "reason": "X oEmbed answered HTTP 200 without a JSON object: could not verify"}
        parsed = parse_oembed(obj, requested)
        if parsed["state"] != "available":
            ctx.http.evict(resp)
        return parsed
    return {"state": "error", "status_id": requested, "reason_code": "error", "reason": "X oEmbed: too many redirects"}


def _failure_outcome(exc: BaseException) -> tuple[Status, str, str]:
    """(status, reason_code, reason) of a failed request (rule 5: could not verify, never absent)."""
    out = failure("X oEmbed", exc)
    status = {"rate_limited": Status.RATE_LIMITED, "quota": Status.QUOTA, "blocked": Status.BLOCKED}.get(out["status"], Status.ERROR)
    code = str(out.get("reason_code") or "error")
    if status is Status.ERROR and code not in ("timeout", "error"):
        code = "error"
    return status, code, str(out.get("reason") or COULD_NOT_VERIFY)


# ================================================================================ modules


@register
class XTwitterPublic(Module):
    name = "x_twitter_public"
    title = "X/Twitter post via oEmbed (author handle, text, still available)"
    description = (
        "Checks an X/Twitter status URL through X's published oEmbed interface (publish.twitter.com/oembed, no login): "
        "author handle, embed text, date and whether X still serves the post (404 = no longer available: deleted, "
        "protected or suspended). The status id is decoded offline to a creation time (derived from id)."
    )
    category = "username_social"
    accepts = frozenset({T.URL})
    produces = frozenset({T.USERNAME, T.URL})
    tags = frozenset({"free"})
    reference = "https://developer.x.com/en/docs/x-for-websites/oembed-api"
    notice = (
        "Terms 'unknown' until legal records the X oEmbed terms (P119 cond 6): disabled in every licence profile until then. "
        "Published interface only: the syndication tweet-result endpoint is never used and twitter.com/x.com pages are never "
        "requested. A 404 means 'no longer available (deleted, protected or suspended)', never 'deleted'."
    )
    terms = "unknown"
    opsec = Opsec.PASSIVE
    disclosure = "third_party"  # X receives the status URL
    provider = "x_corp"
    sources = (SOURCE_OEMBED,)
    hosts = OEMBED_HOSTS
    access_model = "free_noauth_limited"
    max_requests = 3  # oEmbed + its 301 hop (+1 spare hop)
    expected_latency = 0.8
    timeout = 30.0
    min_interval = 1.0
    cache_ttl = OEMBED_TTL
    max_pivots = 5
    default_enabled = False  # cond 6 / A3: unknown terms

    def applies(self, entity: Entity, ctx: Any) -> bool:
        return parse_status_url(entity.value) is not None

    def run(self, entity: Entity, ctx: Any) -> ModuleResult:
        res = self.result(entity)
        status = parse_status_url(entity.value)
        if status is None:
            return res.mark("skipped", "not an X/Twitter status URL", reason_code="not_applicable")
        out = fetch_oembed(ctx, entity.value, {"host": OEMBED_HOSTS[0]})
        checked_at = ctx.now().isoformat()
        decoded = decode_status_time(status["status_id"], ctx.now())
        raw: dict[str, Any] = {"status_id": status["status_id"], "oembed_state": out["state"], "checked_at": checked_at,
                               "created": decoded.get("created"), "created_basis": decoded.get("label") or decoded.get("reason")}
        res.raw = raw
        if out["state"] == "blocked":
            return res.mark("blocked", str(out["reason"]), reason_code=str(out.get("reason_code") or "challenge"))
        if out["state"] == "error":
            reason = str(out.get("reason") or "unexpected X oEmbed answer")
            return res.mark("error", reason if COULD_NOT_VERIFY in reason else f"{reason}: {COULD_NOT_VERIFY}")
        if decoded["decoded"]:
            res.attr("created", decoded["created"])
            res.attr("created_epoch", decoded["epoch"])
        manual = f"https://x.com/{status['handle'] or 'i/web'}/status/{status['status_id']}"
        res.link("X post (manual check in a browser; never fetched by V3LUM)", manual)
        if out["state"] == "unavailable":
            res.attr("post_availability", X_UNAVAILABLE_TEXT)
            res.attr("x_post", {"status_id": status["status_id"], "handle": status["handle"], "availability": X_UNAVAILABLE_TEXT,
                                "checked_at": checked_at})
            res.finding(
                "X post no longer available",
                "info",
                f"X's oEmbed interface answered HTTP 404 for status {status['status_id']}: the post is {X_UNAVAILABLE_TEXT}. "
                "This does not prove it was deleted or that it never existed."
                + (f" Creation time {decoded['created']} ({DERIVED_LABEL})." if decoded["decoded"] else ""),
                confidence="probable",
                criterion="X oEmbed HTTP 404 for the status URL (published interface; P119 cond 3)",
                source=SOURCE_OEMBED,
                observed_first=decoded.get("created"),
            )
            return res
        post = {"status_id": out["status_id"], "handle": out["handle"], "author_name": out["author_name"], "text": out["text"],
                "lang": out["lang"], "date_text": out["date_text"], "mentions": out["mentions"], "hashtags": out["hashtags"],
                "links": out["links"], "availability": "available", "checked_at": checked_at}
        res.attr("post_availability", "available")
        res.attr("x_post", post)
        res.presence("found", marker="HTTP 200 X oEmbed single-post embed", url=manual, checked_at=ctx.now(), source=SOURCE_OEMBED)
        if out["handle"]:
            res.pivot(T.USERNAME, out["handle"], "post_author", confidence="probable", expand=False,
                      note="author handle of the post as embedded by X oEmbed: same handle elsewhere does not prove the same person")
        res.finding(
            "X post available through oEmbed",
            "info",
            f"Post {out['status_id']} by @{out['handle'] or '?'}"
            + (f" ({out['author_name']})" if out["author_name"] else "")
            + (f", dated '{out['date_text']}'" if out["date_text"] else "")
            + (f"; created {decoded['created']} ({DERIVED_LABEL})" if decoded["decoded"] else "") + ".",
            confidence="confirmed",
            source=SOURCE_OEMBED,
            observed_first=decoded.get("created"),
        )
        return res


@register
class XTwitterRecovery(Module):
    name = "x_twitter_recovery"
    title = "X/Twitter deleted-post recovery from archived copies (opt-in)"
    description = (
        "Opt-in per run for a case subject's X handle: archived status URLs from the Wayback CDX index (twitter.com and "
        "x.com, collapse=urlkey, limit <= 500), each checked with X oEmbed; posts X no longer serves are listed as "
        "'archived copy' links on web.archive.org with their id-derived creation time."
    )
    category = "username_social"
    accepts = frozenset({T.USERNAME})
    produces = frozenset({T.URL})
    run_on = "seeds"  # cond 5: case subjects only
    tags = frozenset({"slow"})
    reference = "https://github.com/Mennaruuk/twayback"
    notice = (
        "Opt-in per run (select it with -M and a recorded purpose): archived copies are used only for case subjects. Terms "
        "'unknown' until legal records the X oEmbed terms and confirms the Internet Archive decision for this use (P119 cond 6). "
        "Archive hosts only; no crawler or search-engine User-Agent is ever sent (twayback's DuckDuckBot trick is excluded)."
    )
    terms = "unknown"
    opsec = Opsec.PASSIVE
    disclosure = "third_party"  # the Internet Archive receives the handle, X the archived status URLs
    provider = "internet_archive"
    sources = (SOURCE_SOCIAL, SOURCE_OEMBED)
    hosts = ("web.archive.org", *OEMBED_HOSTS)
    access_model = "free_noauth_limited"
    max_requests = 45  # 2 CDX queries + 1 redirect hop + up to 40 oEmbed checks (+2 spare)
    expected_latency = 60.0
    timeout = 150.0
    min_interval = 1.0
    cache_ttl = CDX_TTL
    max_pivots = 40
    default_enabled = False  # cond 4/6: opt-in, unknown terms, slow
    settings = {
        "x_twitter_recovery_cdx_limit": SettingSpec(CDX_LIMIT_MAX, "Wayback CDX rows per query (twitter.com and x.com), at most 500 (P119 cond 4)"),
        "x_twitter_recovery_max_checks": SettingSpec(40, "oEmbed checks of archived status ids per run (the rest stays 'could not verify')"),
    }

    def run(self, entity: Entity, ctx: Any) -> ModuleResult:
        res = self.result(entity)
        handle = normalise_x_handle(entity.value)
        if not handle:
            return res.mark("skipped", "not a valid X handle (1-15 letters, digits or _)", reason_code="not_applicable")
        allowed = set(self.sources if ctx.allowed_sources is None else ctx.allowed_sources)
        if SOURCE_SOCIAL not in allowed:
            return res.mark("skipped", "the Wayback CDX source for this use is not allowed in this run", reason_code="licence")
        limit = _bounded_int(ctx.setting("x_twitter_recovery_cdx_limit", CDX_LIMIT_MAX), 1, CDX_LIMIT_MAX, CDX_LIMIT_MAX)
        rows: list[dict[str, Any]] = []
        answered = 0
        failures: list[tuple[Status, str, str]] = []
        cdx_partial = False
        for host in ("twitter.com", "x.com"):
            try:
                resp = ctx.http.get(CDX, params=cdx_params(handle, host, limit), source=SOURCE_SOCIAL, ttl=CDX_TTL,
                                    max_bytes=4 * 1024 * 1024)
                ctx.http.check(resp)
            except (RateLimited, QuotaExceeded, Blocked, AuthRequired, HttpError, NetworkError, DeadlineExceeded) as exc:
                out = failure("Wayback CDX", exc)
                status = {"rate_limited": Status.RATE_LIMITED, "quota": Status.QUOTA, "blocked": Status.BLOCKED}.get(out["status"], Status.ERROR)
                code = str(out["reason_code"]) if status is not Status.ERROR or out["reason_code"] in ("timeout", "error") else "error"
                failures.append((status, code, f"{host}: {out['reason']}"))
                continue
            parsed = parse_wayback_cdx(resp.content, CDX_LIMIT_MAX, body_truncated=bool(getattr(resp, "truncated", False)))
            if parsed["state"] == "error":
                ctx.http.evict(resp)
                failures.append((Status.ERROR, "error", f"{host}: unusable CDX answer ({parsed['error']}): archive could not be verified"))
                continue
            answered += 1
            cdx_partial = cdx_partial or bool(parsed["partial"])
            rows.extend(parsed["rows"])
        if not answered:
            status, code, reason = failures[0] if failures else (Status.ERROR, "error", "archive unreachable")
            return res.mark(status, f"Wayback CDX could not be queried ({'; '.join(f[2] for f in failures)}): {COULD_NOT_VERIFY} "
                                    "(never 'no archived posts')", reason_code=code)
        for status, code, reason in failures:
            res.source_status(SOURCE_SOCIAL, status, reason_code=code, reason=reason)
        found = x_status_rows(rows, handle)
        statuses = found["statuses"]
        summary: dict[str, Any] = {"handle": handle, "cdx_queries": 2, "cdx_answered": answered, "archived_statuses": len(statuses),
                                   "checked": 0, "recovered": [], "still_available": 0, "unverified": 0, "partial": False,
                                   "label": ARCHIVED_COPY, "archive_host": "web.archive.org"}
        res.raw = {"handle": handle, "cdx_rows": len(rows), "skipped_rows": found["skipped"], "other_handle_rows": found["other_handle"],
                   "statuses": [{k: s[k] for k in ("status_id", "first_capture", "last_capture", "captures")} for s in statuses[:CDX_LIMIT_MAX]]}
        if not statuses:
            res.attr("x_recovery", summary)
            if failures:  # one query answered empty, the other could not be verified: never 'no archived posts'
                status, code, _reason = failures[0]
                return res.mark(status, f"Wayback CDX answered for only one of twitter.com/x.com ({'; '.join(f[2] for f in failures)}): "
                                        f"{COULD_NOT_VERIFY}", reason_code=code)
            return res.mark("empty", f"no archived status URLs of @{handle} in the Wayback CDX index (twitter.com, x.com); this is "
                                     "not proof that no post existed")
        max_checks = _bounded_int(ctx.setting("x_twitter_recovery_max_checks", 40), 0, 40, 40)
        checks: dict[str, dict[str, Any]] = {}
        stop_reason: str | None = None
        if SOURCE_OEMBED in allowed:
            state = {"host": OEMBED_HOSTS[0]}
            for s in statuses[:max_checks]:
                remaining = ctx.remaining()
                if remaining is not None and remaining < 5:
                    stop_reason = "deadline"
                    break
                try:
                    checks[s["status_id"]] = fetch_oembed(ctx, s["canonical_url"], state)
                except (RateLimited, QuotaExceeded, Blocked, AuthRequired, HttpError, NetworkError, DeadlineExceeded) as exc:
                    status, code, reason = _failure_outcome(exc)
                    res.source_status(SOURCE_OEMBED, status, reason_code=code, reason=reason)
                    stop_reason = {Status.RATE_LIMITED: "rate_limited", Status.QUOTA: "quota"}.get(status, "deadline" if code == "timeout" else None)
                    break
        else:
            res.source_status(SOURCE_OEMBED, Status.SKIPPED, reason_code="licence", reason="X oEmbed not allowed in this run: "
                              "archived statuses stay unverified")
        recovered, live, unverified = [], 0, 0
        for s in statuses:
            check = checks.get(s["status_id"]) or {}
            if check.get("state") == "unavailable":
                decoded = decode_status_time(s["status_id"], ctx.now())
                recovered.append({"status_id": s["status_id"], "created": decoded.get("created"),
                                  "created_basis": DERIVED_LABEL if decoded["decoded"] else decoded.get("reason"),
                                  "archived_copy_url": s["archived_copy_url"], "first_capture": s["first_capture"],
                                  "last_capture": s["last_capture"], "captures": s["captures"], "label": ARCHIVED_COPY,
                                  "availability": X_UNAVAILABLE_TEXT})
            elif check.get("state") == "available":
                live += 1
            else:
                unverified += 1
        summary.update(checked=len(checks), recovered=recovered, still_available=live, unverified=unverified,
                       partial=bool(unverified or cdx_partial or failures))
        res.attr("x_recovery", summary)
        for r in recovered:
            res.pivot(T.URL, r["archived_copy_url"], "archived_copy", confidence="probable", expand=False,
                      note=f"{ARCHIVED_COPY} of status {r['status_id']} ({X_UNAVAILABLE_TEXT} on X); case subject only")
        if recovered:
            res.finding(
                "Archived copies of X posts no longer available",
                "info",
                f"{len(recovered)} archived post(s) of @{handle} are {X_UNAVAILABLE_TEXT} on X (oEmbed 404); their archived copies "
                f"on web.archive.org are listed. {live} archived post(s) are still available, {unverified} could not be verified.",
                confidence="probable",
                criterion="status URL archived by the Wayback Machine and answered HTTP 404 by X oEmbed (P119 cond 3/4)",
                tags=["archived_copy"],
                source=SOURCE_SOCIAL,
                data={"recovered": len(recovered), "still_available": live, "unverified": unverified},
            )
        if stop_reason in ("rate_limited", "quota", "deadline"):
            res.stop(stop_reason)
        elif unverified and len(checks) < len(statuses):
            res.stop("request_cap")
        if not recovered and not live and unverified:
            res.error = f"{unverified} archived status(es) of @{handle} could not be checked with X oEmbed: {COULD_NOT_VERIFY}"
        return res


def _bounded_int(value: Any, low: int, high: int, default: int) -> int:
    try:
        n = int(value)
    except (TypeError, ValueError):
        return default
    return max(low, min(n, high))
