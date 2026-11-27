"""Telegram public web preview: presence, kind and public channel posts of a handle (P112).

Unauthenticated GETs of ``https://t.me/{name}`` and ``https://t.me/s/{name}[?before=N]`` only: never
an account, session, bot token, Telethon or joining (team rule 1, P112 cond 1). Registry provider
``telegram`` (tier trusted, terms open, source ``telegram.web_preview``); Telegram handles are
PERSONAL_TYPES, so the provider's ``personal_data_review`` comes before default use (A3 BR8).

Shared with ``telegram_channel_watch`` (P357): the one t.me parser (:func:`parse_tme_profile`,
:func:`parse_tme_channel_posts`, stdlib ``html.parser``, 2 MB page cap), the ingestion scrubber
(:func:`scrub_post_text`, :func:`scrub_posts`), the digest (:func:`digest_tme_posts`) and the
fetch helper (:func:`fetch_tme_page`) live here (P112 cond 2).

* FOUND only with the ``tgme_page_title`` marker; the generic 'Telegram: Contact @x' page (HTTP 200
  for any handle) is UNKNOWN 'private or missing: could not read', never ABSENT (P112 cond 2;
  provider marker ``telegram_public_generic_page``). Observed live on 2026-11-26: t.me also serves
  that page to request bursts and to some user agents (curl/*), even for t.me/telegram - one more
  reason it can never mean 'absent'.
* Each result is a channel, group, user or bot; personal user profiles yield presence and display
  name only; posts are read for channels only (cond 3).
* Posts come from ``.tgme_widget_message[data-post]`` with ``?before=`` paging: 2 pages in the
  default preset (~40 posts), 3 in ``--preset deep``; ``min_interval`` 2 s; results cached 1 h
  (cond 4) - **in memory and scrubbed only**: raw t.me HTML never reaches the HTTP cache (cond 5
  wins over cond 4: requests are sent with ``ttl=0``).
* Ingestion scrubbing runs before cache, evidence and reports (cond 5): Luhn-valid 13-19 digit PANs
  become BIN6 + last 4, CPF-like numbers ``***.456.789-**``, e-mails and phones masked; credential
  lines, combo lines and leaked records dropped. Post HTML is never rendered.
* Evidence keeps post id, date, URL and an excerpt of <= 300 chars each side of every matched
  IOC/brand term (<= 1,000 chars per post); reports quote <= 200 chars of matching posts; channel
  dumps are never stored (cond 6).
* Post text goes through the core IOC extractor (``v3lum.core.detect.extract_iocs``, to be replaced
  by the P172 engine ``v3lum.core.ioc.extract`` when it lands); only infrastructure IOCs (URL, domain,
  IP, wallet, onion, Telegram/Discord invite) become pivots: deduplicated, warninglisted (Telegram,
  big platforms), defanged in the one-block summary, ``expand=False`` (cond 7).
* Forwarded-from channels become ``telegram_handle`` pivots with ``expand=False``; media, files,
  og:image and link previews are never fetched and links are never visited (cond 8).
* Bot tokens and webhook URLs are reported as type + SHA-256 prefix only (cond 9).
"""

from __future__ import annotations

import copy
import hashlib
import re
import threading
import unicodedata
import weakref
from collections import Counter, OrderedDict
from html.parser import HTMLParser
from typing import Any
from urllib.parse import urlsplit

from v3lum.core import noise
from v3lum.core.detect import extract_iocs
from v3lum.core.entities import Entity, defang, refang, url_host
from v3lum.core.entities import EntityType as T
from v3lum.core.http import DeadlineExceeded, HttpError, NetworkError, QuotaExceeded, RateLimited
from v3lum.core.models import ModuleResult, Opsec
from v3lum.core.module import HealthCheck, HealthResult, Module, register
from v3lum.core.validators import pan_valid

SOURCE = "telegram.web_preview"
TME_HOST = "t.me"
TME_PAGE_CAP = 2 * 1024 * 1024  # P112 cond 2
TME_GENERIC_REASON = "private or missing: could not read"  # P112 cond 2
NO_PREVIEW_REASON = "no public channel preview (t.me/s redirected to the profile page)"
GENERIC_MARKER_ID = "telegram_public_generic_page"  # provider marker (telegram__p1-G05-1.json)
#: English UI strings drive the channel/group/user/bot classification (P112 cond 3).
TME_HEADERS = {"Accept": "text/html", "Accept-Language": "en"}
PAGE_CACHE_TTL = 3600  # P112 cond 4: 1 h, scrubbed data only
DEFAULT_PAGES = 2  # P112 cond 4: default preset (~40 posts)
DEEP_PAGES = 3  # P112 cond 4: --preset deep
EXCERPT_SIDE = 300  # P112 cond 6
EXCERPT_CAP = 1000  # P112 cond 6
QUOTE_CAP = 200  # P112 cond 6
TOP_N = 5  # P112 cond 7
PIVOTS_PER_GROUP = 20  # 6 groups x 20 + 25 forwards stays under max_pivots
POST_TEXT_CAP = 200_000
MAX_RECORDS = 80

_HANDLE_RE = re.compile(r"^[A-Za-z][A-Za-z0-9_]{4,31}$")
TME_RESERVED = frozenset({
    "s", "c", "joinchat", "addstickers", "addemoji", "addtheme", "addlist", "share", "proxy", "socks", "iv", "login",
    "setlanguage", "confirmphone", "bg", "invoice", "boost", "giftcode", "contact", "m", "nft", "k", "a", "z", "dl", "i",
})
_TME_HOSTS = ("t.me", "telegram.me", "telegram.dog")
_GENERIC_TITLE_RE = re.compile(r"^\s*Telegram:\s*Contact\s+@", re.I)


# ======================================================================================
# handles and URLs
# ======================================================================================


def tme_handle(value: Any) -> str | None:
    """Telegram handle (lower case) of a typed handle ('@x', 'x') or a t.me link, else None.

    Invite links (t.me/+code, t.me/joinchat/code) and reserved paths give None: they are never
    fetched (P112 cond 1: only t.me/{name} and t.me/s/{name}).
    """
    if not isinstance(value, str) or not value.strip():
        return None
    ent = Entity.try_make(T.TELEGRAM_HANDLE, value.strip())
    if ent is None or ent.value in TME_RESERVED:
        return None
    return ent.value


def tme_profile_url(handle: str) -> str | None:
    """https://t.me/{handle} for a valid handle, else None."""
    if not isinstance(handle, str) or not _HANDLE_RE.match(handle) or handle.lower() in TME_RESERVED:
        return None
    return f"https://t.me/{handle}"


def tme_preview_url(handle: str, before: Any = None) -> str | None:
    """https://t.me/s/{handle}[?before=N] for a valid handle, else None (P112 cond 4)."""
    if tme_profile_url(handle) is None:
        return None
    b = _int(before)
    return f"https://t.me/s/{handle}" + (f"?before={b}" if b and b > 0 else "")


def tme_fetch_allowed(url: Any) -> bool:
    """P112 cond 1/8/10 guard: only https://t.me/{name} and https://t.me/s/{name}[?before=N]."""
    if not isinstance(url, str):
        return False
    try:
        sp = urlsplit(url)
        port = sp.port
    except ValueError:
        return False
    if sp.scheme != "https" or (sp.hostname or "").lower() != TME_HOST or port not in (None, 443) or sp.username or sp.fragment:
        return False
    m = re.fullmatch(r"/(?:s/)?([A-Za-z][A-Za-z0-9_]{4,31})", sp.path)
    if not m or m.group(1).lower() in TME_RESERVED:
        return False
    if sp.query:
        return sp.path.startswith("/s/") and re.fullmatch(r"before=\d{1,12}", sp.query) is not None
    return True


def is_media_url(url: Any) -> bool:
    """P112 cond 8/10: True for Telegram media/CDN URLs (avatars, photos, video, emoji images)."""
    if not isinstance(url, str):
        return False
    u = url.strip()
    if u.startswith("//"):
        u = "https:" + u
    try:
        sp = urlsplit(u)
    except ValueError:
        return False
    host = (sp.hostname or "").lower()
    if host.endswith(("telesco.pe", "telegram-cdn.org", "cdn-telegram.org")):
        return True
    if host == "telegram.org" and sp.path.startswith(("/img/", "/file/")):
        return True
    return bool(re.search(r"\.(?:jpe?g|png|gif|webp|mp4|webm|ogg|oga|mp3|tgs|svg)(?:$|\?)", sp.path, re.I) and host in (*_TME_HOSTS, "telegram.org"))


# ======================================================================================
# small helpers
# ======================================================================================


def _int(value: Any) -> int | None:
    if isinstance(value, bool):
        return None
    if isinstance(value, int):
        return value
    if isinstance(value, str) and re.fullmatch(r"\s*\d{1,12}\s*", value):
        return int(value)
    return None


def _to_text(raw: Any, cap: int) -> tuple[str, bool]:
    """(text, truncated) of str/bytes input capped at ``cap`` bytes; other types give ('', False)."""
    if raw is None:
        return "", False
    if isinstance(raw, (bytes, bytearray, memoryview)):
        data = bytes(raw)
        truncated = len(data) > cap
        return data[:cap].decode("utf-8", errors="replace"), truncated
    if isinstance(raw, str):
        if len(raw) > cap // 4:
            enc = raw.encode("utf-8", errors="replace")
            if len(enc) > cap:
                return enc[:cap].decode("utf-8", errors="ignore"), True
        return raw, False
    return "", False


def _iso_utc(value: Any) -> str | None:
    import datetime as _dt

    if not isinstance(value, str) or not value.strip():
        return None
    s = value.strip()
    try:
        d = _dt.datetime.fromisoformat(s[:-1] + "+00:00" if s.endswith(("Z", "z")) else s)
    except ValueError:
        return None
    if d.tzinfo is None:
        d = d.replace(tzinfo=_dt.timezone.utc)
    return d.astimezone(_dt.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def tme_count(text: Any) -> int | None:
    """'9 051 510' / '9.05M' / '12.3K' / '1,5K' / thin-space numbers -> int, else None."""
    if not isinstance(text, str):
        return None
    s = re.sub(r"[    ]", " ", text).strip()
    m = re.fullmatch(r"(\d[\d ,.]*?)\s*([KMB])?", s, re.I)
    if not m:
        return None
    num, suffix = m.group(1).strip(), (m.group(2) or "").upper()
    if suffix:
        try:
            val = float(num.replace(" ", "").replace(",", "."))
        except ValueError:
            return None
        return int(round(val * {"K": 1e3, "M": 1e6, "B": 1e9}[suffix]))
    digits = re.sub(r"[ ,.]", "", num)
    return int(digits) if digits.isdigit() else None


_COUNTER_RE = re.compile(r"(\d[\d    .,]*[KMB]?)\s+(subscribers?|members?|online|monthly users?|photos?|videos?|files?|links?)", re.I)
_COUNTER_NAMES = {"subscriber": "subscribers", "member": "members", "photo": "photos", "video": "videos", "file": "files", "link": "links"}


def _counters(texts: Any) -> dict[str, int]:
    out: dict[str, int] = {}
    for t in texts or ():
        for num, kind in _COUNTER_RE.findall(t or ""):
            low = kind.lower()
            key = "monthly_users" if low.startswith("monthly") else _COUNTER_NAMES.get(low.rstrip("s"), low.rstrip("s"))
            val = tme_count(num)
            if val is not None:
                out[key] = val
    return out


# ======================================================================================
# the one t.me parser (P112 cond 2; shared with P357)
# ======================================================================================

_VOID_TAGS = frozenset({"area", "base", "br", "col", "embed", "hr", "img", "input", "link", "meta", "param", "source", "track", "wbr"})
_TEXT_ROLES = (
    "title", "page_title", "page_extra", "page_desc", "page_action", "chan_title", "chan_user", "counter_value", "counter_type",
    "chan_desc", "post_text", "fwd_name", "preview_site", "preview_title", "views",
)
_MEDIA_CLASSES = {
    "tgme_widget_message_photo_wrap": "photo", "tgme_widget_message_photo": "photo",
    "tgme_widget_message_video_player": "video", "tgme_widget_message_video": "video",
    "tgme_widget_message_roundvideo_player": "round_video", "tgme_widget_message_document_wrap": "document",
    "tgme_widget_message_document": "document", "tgme_widget_message_voice_player": "voice",
    "tgme_widget_message_voice": "voice", "tgme_widget_message_sticker_wrap": "sticker",
    "tgme_widget_message_sticker": "sticker", "tgme_widget_message_poll": "poll",
    "tgme_widget_message_location_wrap": "location", "tgme_widget_message_grouped_wrap": "album",
    "tgme_widget_message_audio": "audio", "tgme_widget_message_audio_player": "audio",
}


def _clean_text(s: str) -> str:
    s = s.replace(" ", " ")
    lines = [re.sub(r"[ \t\r\f\v]+", " ", ln).strip() for ln in s.split("\n")]
    return re.sub(r"\n{3,}", "\n\n", "\n".join(lines)).strip()


def _clean_link(href: Any) -> str | None:
    """Absolute http(s) link of an anchor, or None (media/CDN URLs are never kept, cond 8)."""
    if not isinstance(href, str):
        return None
    h = href.strip()
    if h.startswith("//"):
        h = "https:" + h
    elif h.startswith("/"):
        h = "https://t.me" + h
    try:
        sp = urlsplit(h)
    except ValueError:
        return None
    if sp.scheme not in ("http", "https") or not sp.hostname or is_media_url(h):
        return None
    return h[:2048]


class _TmeParser(HTMLParser):
    """Text-only reader of t.me/{name} and t.me/s/{name} pages: nothing is rendered, no media URL,
    image, document name or script is ever kept."""

    def __init__(self) -> None:
        super().__init__(convert_charrefs=True)
        self.stack: list[tuple[str, list[str]]] = []
        self.active: Counter[str] = Counter()
        self.bufs: dict[str, list[list[str]]] = {}
        self.title_text: str | None = None
        self.meta: dict[str, str] = {}
        self.page: dict[str, Any] = {
            "title": None, "extras": [], "description": None, "action": None, "action_href": None,
            "context_href": None, "username_link": False, "verified": False,
        }
        self.channel: dict[str, Any] = {"title": None, "username": None, "counters": [], "description": None, "verified": False}
        self.more: dict[str, int] = {}
        self.posts: list[dict[str, Any]] = []
        self.post: dict[str, Any] | None = None
        self._counter: dict[str, Any] | None = None
        self.partial = False
        self.seen_history = False

    # ---- posts
    def _start_post(self, data_post: str) -> None:
        if self.post is not None:
            self._finish_post()
        m = re.match(r"^([A-Za-z0-9_]{1,64})/(\d{1,12})$", data_post.strip())
        ch, pid = (m.group(1), int(m.group(2))) if m else (None, None)
        self.post = {
            "channel": ch, "post_id": pid, "url": f"https://t.me/{ch}/{pid}" if m else None, "date": None,
            "views": None, "views_raw": None, "text": "", "links": [], "forwarded_from": None, "link_preview": None,
            "media": set(), "partial": False,
        }

    def _finish_post(self) -> None:
        p = self.post
        if p is None:
            return
        p["media"] = sorted(p["media"])
        p["views"] = tme_count(p.pop("views_raw", None))
        self.posts.append(p)
        self.post = None

    # ---- HTMLParser hooks
    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        a = {k: (v if v is not None else "") for k, v in attrs}
        cls = set(a.get("class", "").split())
        roles: list[str] = []
        if tag == "title":
            roles.append("title")
        elif tag == "meta":
            key = a.get("property") or a.get("name")
            if key in ("og:title", "og:description", "og:site_name", "robots"):  # og:image is never kept
                self.meta[key] = a.get("content", "")
        if tag in ("script", "style", "svg") or "verified-icon" in cls:
            if "verified-icon" in cls:
                if self.active["page_title"]:
                    self.page["verified"] = True
                if self.active["chan_head"]:
                    self.channel["verified"] = True
            roles.append("skip")
        if "tgme_page_title" in cls:
            roles.append("page_title")
        if "tgme_page_extra" in cls:
            roles.append("page_extra")
        if "tgme_page_description" in cls:
            roles.append("page_desc")
        if tag == "a" and "tgme_action_button_new" in cls:
            roles.append("page_action")
            self.page["action_href"] = a.get("href")
        if tag == "a" and "tgme_page_context_link" in cls:
            self.page["context_href"] = a.get("href")
        if tag == "a" and "tgme_username_link" in cls:
            self.page["username_link"] = True
        if "tgme_channel_info_header" in cls:
            roles.append("chan_head")
        if "tgme_channel_info_header_title" in cls:
            roles.append("chan_title")
        if "tgme_channel_info_header_username" in cls:
            roles.append("chan_user")
        if "tgme_channel_info_counter" in cls:
            roles.append("chan_counter")
            self._counter = {"value": None, "type": None}
        if self.active["chan_counter"] and "counter_value" in cls:
            roles.append("counter_value")
        if self.active["chan_counter"] and "counter_type" in cls:
            roles.append("counter_type")
        if "tgme_channel_info_description" in cls:
            roles.append("chan_desc")
        if "tgme_channel_history" in cls:
            self.seen_history = True
        if tag == "a" and "tme_messages_more" in cls:
            for k in ("before", "after"):
                v = _int(a.get("data-" + k))
                if v is not None:
                    self.more.setdefault(k, v)
        if tag == "div" and "tgme_widget_message" in cls and a.get("data-post"):
            self._start_post(a["data-post"])
            roles.append("post")
        elif self.post is not None and self.active["post"]:
            self._post_tag(tag, a, cls, roles)
        if tag == "br" and (self.active["post_text"] or self.active["page_desc"] or self.active["chan_desc"]):
            self.handle_data("\n")
        if tag in _VOID_TAGS:
            return
        self.stack.append((tag, roles))
        for r in roles:
            self.active[r] += 1
            if r in _TEXT_ROLES:
                self.bufs.setdefault(r, []).append([])

    def _post_tag(self, tag: str, a: dict[str, str], cls: set[str], roles: list[str]) -> None:
        p = self.post
        assert p is not None
        if "tgme_widget_message_reply" in cls:
            roles.append("reply")
        if "tgme_widget_message_text" in cls and not self.active["reply"] and not self.active["preview"]:
            roles.append("post_text")
        if "tgme_widget_message_forwarded_from" in cls:
            roles.append("fwd")
            # forwards from users keep no name (P112 cond 3/8): only a linked public channel is kept
            p["forwarded_from"] = {"kind": "hidden_or_user", "name": None, "handle": None}
        if "tgme_widget_message_forwarded_from_name" in cls and p["forwarded_from"] is not None:
            link = _clean_link(a.get("href")) if tag == "a" else None
            handle = tme_handle(link) if link else None
            if handle:
                p["forwarded_from"].update(kind="channel", handle=handle)
                roles.append("fwd_name")
        if tag == "a" and "tgme_widget_message_link_preview" in cls:
            roles.append("preview")
            p["link_preview"] = {"url": _clean_link(a.get("href")), "site_name": None, "title": None}
        if self.active["preview"] and "link_preview_site_name" in cls:
            roles.append("preview_site")
        if self.active["preview"] and "link_preview_title" in cls:
            roles.append("preview_title")
        if "tgme_widget_message_views" in cls:
            roles.append("views")
        if tag == "a" and "tgme_widget_message_date" in cls:
            roles.append("date_link")
            link = _clean_link(a.get("href"))
            if link:
                p["url"] = link
        if tag == "time" and self.active["date_link"] and a.get("datetime") and not p["date"]:
            p["date"] = _iso_utc(a.get("datetime"))
        for c in cls:
            if c in _MEDIA_CLASSES:
                p["media"].add(_MEDIA_CLASSES[c])
        if tag == "a" and self.active["post_text"]:
            link = _clean_link(a.get("href"))
            if link and len(p["links"]) < 200:
                p["links"].append(link)

    def handle_endtag(self, tag: str) -> None:
        if tag in _VOID_TAGS:
            return
        for idx in range(len(self.stack) - 1, -1, -1):
            if self.stack[idx][0] == tag:
                break
        else:
            return
        while len(self.stack) > idx:
            _tag, roles = self.stack.pop()
            for r in reversed(roles):
                self._end_role(r)

    def _end_role(self, r: str) -> None:
        self.active[r] -= 1
        text = None
        if r in _TEXT_ROLES and self.bufs.get(r):
            text = _clean_text("".join(self.bufs[r].pop()))
        p = self.post
        if r == "title":
            self.title_text = self.title_text or text
        elif r == "page_title" and self.page["title"] is None:
            self.page["title"] = text
        elif r == "page_extra" and text:
            self.page["extras"].append(text)
        elif r == "page_desc":
            self.page["description"] = text
        elif r == "page_action":
            self.page["action"] = text
        elif r == "chan_title" and self.channel["title"] is None:
            self.channel["title"] = text
        elif r == "chan_user" and self.channel["username"] is None:
            self.channel["username"] = text
        elif r == "counter_value" and self._counter is not None:
            self._counter["value"] = text
        elif r == "counter_type" and self._counter is not None:
            self._counter["type"] = text
        elif r == "chan_counter" and self._counter is not None:
            if self._counter["value"] and self._counter["type"]:
                self.channel["counters"].append((self._counter["value"], self._counter["type"]))
            self._counter = None
        elif r == "chan_desc" and self.channel["description"] is None:
            self.channel["description"] = text
        elif p is not None:
            if r == "post_text" and text:
                p["text"] = (p["text"] + "\n" + text).strip() if p["text"] else text
            elif r == "fwd_name" and p["forwarded_from"] is not None:
                p["forwarded_from"]["name"] = (text or "")[:200] or None
            elif r == "preview_site" and p["link_preview"] is not None:
                p["link_preview"]["site_name"] = (text or "")[:200] or None
            elif r == "preview_title" and p["link_preview"] is not None:
                p["link_preview"]["title"] = (text or "")[:300] or None
            elif r == "views":
                p["views_raw"] = text
            elif r == "post":
                self._finish_post()

    def handle_data(self, data: str) -> None:
        if self.active["skip"]:
            return
        for r in _TEXT_ROLES:
            if self.active[r] and self.bufs.get(r):
                self.bufs[r][-1].append(data)

    def finish(self) -> _TmeParser:
        try:
            self.close()
        except Exception:  # noqa: BLE001 - html.parser is lenient; a bad tail must never escape
            pass
        if self.post is not None:
            while self.bufs.get("post_text"):
                t = _clean_text("".join(self.bufs["post_text"].pop()))
                if t:
                    self.post["text"] = (self.post["text"] + "\n" + t).strip() if self.post["text"] else t
            self.post["partial"] = True
            self.partial = True
            self._finish_post()
        return self


def _run_parser(text: str) -> _TmeParser:
    p = _TmeParser()
    try:
        p.feed(text)
    except Exception:  # noqa: BLE001 - keep what was parsed from a hostile or broken page
        p.partial = True
    return p.finish()


def _tme_kind(title: str | None, extras: list[str], action: str | None, context_href: str | None, handle: str | None) -> str:
    t = (title or "").lower()
    ex = " ".join(extras or ()).lower()
    act = (action or "").strip().lower()
    if "subscriber" in ex or (context_href and "/s/" in context_href):
        return "channel"
    if "member" in ex:
        return "group"
    if "monthly user" in ex or act == "start bot" or t.startswith("telegram: launch"):
        return "bot"
    if handle and handle.lower().endswith("bot") and (act == "send message" or t.startswith("telegram: contact")):
        return "bot"
    if act == "send message" or t.startswith("telegram: contact"):
        return "user"
    if t.startswith("telegram: view") or act == "view in telegram":
        return "channel"
    return "user"


def _handle_from_page(p: _TmeParser) -> str | None:
    for e in p.page["extras"]:
        m = re.fullmatch(r"@([A-Za-z][A-Za-z0-9_]{4,31})", e.strip())
        if m:
            return m.group(1)
    m = re.search(r"@([A-Za-z][A-Za-z0-9_]{4,31})\s*$", p.title_text or "")
    if m:
        return m.group(1)
    m = re.search(r"[?&]domain=([A-Za-z][A-Za-z0-9_]{4,31})", p.page["action_href"] or "")
    return m.group(1) if m else None


def parse_tme_profile(raw: Any, handle: str | None = None) -> dict[str, Any]:
    """t.me/{name} page -> {state FOUND | UNKNOWN, reason, kind, handle, display_name, url, truncated}.

    HTTP 200 comes back for any handle: without the tgme_page_title marker the generic 'Telegram:
    Contact @x' page gives UNKNOWN 'private or missing: could not read', never ABSENT (P112 cond 2).
    A user profile yields presence and display name only (cond 3); channels, groups and bots add
    verified, description (raw text: scrub it before keeping it), counters and has_preview. No media
    (og:image, avatar) is ever returned.
    """
    text, truncated = _to_text(raw, TME_PAGE_CAP)
    res: dict[str, Any] = {"state": "UNKNOWN", "reason": None, "kind": None, "handle": handle if isinstance(handle, str) else None,
                           "display_name": None, "url": None, "truncated": truncated}
    if not text.strip():
        res["reason"] = "empty page: could not read"
        return res
    if "tgme_" not in text and "<title>Telegram" not in text:
        res["reason"] = "not a t.me page: could not read"
        return res
    p = _run_parser(text)
    h = _handle_from_page(p) or res["handle"]
    res["handle"] = h
    res["url"] = f"https://t.me/{h}" if h and _HANDLE_RE.match(h) else None
    if not p.page["title"]:
        generic = _GENERIC_TITLE_RE.match(p.title_text or "") or p.page["username_link"] or "noindex" in (p.meta.get("robots") or "")
        res["reason"] = TME_GENERIC_REASON if generic else "unrecognised t.me page: could not read"
        return res
    kind = _tme_kind(p.title_text, p.page["extras"], p.page["action"], p.page["context_href"], h)
    res.update(state="FOUND", kind=kind, display_name=p.page["title"][:200])
    if truncated:
        res["reason"] = "page over 2 MB cap: parsed the first 2 MB"
    if kind == "user":
        return res  # P112 cond 3: presence and display name only
    res.update(
        verified=bool(p.page["verified"]),
        description=(p.page["description"] or None),
        counters=_counters(p.page["extras"]),
        has_preview=bool(kind == "channel" and p.page["context_href"] and "/s/" in p.page["context_href"]),
    )
    return res


def parse_tme_channel_posts(raw: Any, handle: str | None = None) -> dict[str, Any]:
    """t.me/s/{name}[?before=N] page -> {state, reason, channel, posts, next_before, truncated, partial}.

    Posts come from .tgme_widget_message[data-post] (P112 cond 4); each has post_id, url, date,
    views, text (raw, in memory only: run :func:`scrub_posts` before keeping anything), in-text links,
    forwarded_from (a linked public channel only), link_preview (href and titles, never the image)
    and media kinds (never fetched, cond 8). ``next_before`` is the ?before= cursor of the older page.
    A profile page served instead (302 from /s/) is UNKNOWN: posts are read for channels only.
    """
    text, truncated = _to_text(raw, TME_PAGE_CAP)
    res: dict[str, Any] = {"state": "UNKNOWN", "reason": None, "channel": None, "posts": [], "next_before": None,
                           "truncated": truncated, "partial": False}
    if not text.strip():
        res["reason"] = "empty page: could not read"
        return res
    p = _run_parser(text)
    if not p.seen_history and not p.posts:
        if p.page["title"] or _GENERIC_TITLE_RE.match(p.title_text or "") or p.page["username_link"]:
            res["reason"] = "no public channel preview (profile page served): posts are read for channels only"
        else:
            res["reason"] = "not a t.me/s channel page: could not read"
        return res
    counters: dict[str, int] = {}
    for val, typ in p.channel["counters"]:
        counters.update(_counters([f"{val} {typ}"]))
    ch_handle = (p.channel["username"] or "").strip().lstrip("@") or None
    if not (ch_handle and _HANDLE_RE.match(ch_handle)):
        ch_handle = handle if isinstance(handle, str) else None
    res["channel"] = {"title": p.channel["title"], "handle": ch_handle, "description": p.channel["description"],
                      "verified": bool(p.channel["verified"]), "counters": counters}
    res["posts"] = p.posts
    ids = [x["post_id"] for x in p.posts if isinstance(x.get("post_id"), int)]
    nb = p.more.get("before") or (min(ids) if ids else None)
    res["next_before"] = nb if nb and nb > 1 else None
    res["partial"] = p.partial or "</html>" not in text[-4096:].lower()
    res["state"] = "FOUND"
    if truncated:
        res["reason"] = "page over 2 MB cap: parsed the first 2 MB"
    elif p.partial:
        res["reason"] = "truncated page: last post parsed partially"
    elif res["partial"]:
        res["reason"] = "truncated page: document ends early"
    elif not p.posts:
        res["reason"] = "no posts in preview"
    return res


# ======================================================================================
# ingestion scrubbing (P112 cond 5 and 9; P145/AR24)
# ======================================================================================

_SECRET_PATTERNS = (
    ("telegram_bot_api_url", re.compile(r"https?://api\.telegram\.org/(?:file/)?bot\d{6,12}:[A-Za-z0-9_-]{30,40}[^\s<>\"']*", re.I)),
    ("discord_webhook_url", re.compile(r"https?://(?:(?:ptb|canary)\.)?discord(?:app)?\.com/api/webhooks/\d{5,25}/[A-Za-z0-9_-]{20,100}", re.I)),
    ("discord_webhook_url", re.compile(r"/api/webhooks/\d{5,25}/[A-Za-z0-9_-]{20,100}", re.I)),
    ("slack_webhook_url", re.compile(r"https://hooks\.slack\.com/services/[A-Za-z0-9]+/[A-Za-z0-9]+/[A-Za-z0-9]{10,64}")),
    ("webhook_url", re.compile(r"https?://(?:www\.)?webhook\.site/[0-9a-f-]{36}[^\s<>\"']*", re.I)),
    ("telegram_bot_token", re.compile(r"(?<![\w:])\d{6,12}:[A-Za-z0-9_-]{35}(?![\w-])")),
)
_PAN_RE = re.compile(r"(?<![\d+])(?:\d[ -]?){12,18}\d(?!\d)")
_CPF_RE = re.compile(r"(?<![\d.])(?:\d{3}\.\d{3}\.\d{3}-\d{2}|\d{11})(?!\d)")
_EMAIL_RE = re.compile(r"(?<![\w.%+-])([A-Za-z0-9._%+-]{1,64})@((?:[A-Za-z0-9-]{1,63}\.)+[A-Za-z]{2,24})(?![\w-])")
_PHONE_RE = re.compile(
    r"(?<![\w+])(?:\+\d{1,3}[ .-]?\(?\d{1,4}\)?(?:[ .-]?\d{2,5}){2,4}|\(\d{2}\)\s?9?\d{4}[ .-]?\d{4}|\d{2}\s9?\d{4}-\d{4})(?!\d)"
)
_DOB_RE = re.compile(r"(?<!\d)\d{2}/\d{2}/(?:19|20)\d{2}(?!\d)")
_CRED_RE = re.compile(r"(?i)\b(?:pass(?:word|wd)?|senha|pwd|passcode)\s*[:=]\s*\S")
_COMBO_RES = (
    re.compile(r"^\s*[^\s:|;@]+@[^\s:|;@]+\.[A-Za-z]{2,24}\s*[:;|]\s*\S+\s*$"),
    re.compile(r"^\s*(?:https?://)?[^\s:|;/]+\.[A-Za-z]{2,24}(?:/\S*)?\s*[:|;]\s*[^\s:|;]+\s*[:|;]\s*\S+\s*$"),
    re.compile(r"(?i)^\s*[^\s:@/]+:[^\s:@/]+@[\w.-]+\.[a-z]{2,24}\b"),
)
_RECORD_KW_RE = re.compile(
    r"(?i)\b(?:nome|cpf|rg|m[ãa]e|pai|nascimento|nasc|endere[çc]o|cep|titular|cvv|cvc|validade|expira|telefone|celular|e-?mail)\s*[:=]"
)
_REMOVED_RE = re.compile(r"\[removed [a-z_]+ #[0-9a-f]{12}\]")
_DROP_LABELS = {"credential": "credential line", "combo": "combo list line", "leaked_record": "leaked record"}


def _pans(line: str) -> list[str]:
    return [re.sub(r"\D", "", m.group(0)) for m in _PAN_RE.finditer(line) if pan_valid(re.sub(r"\D", "", m.group(0)))]


def _pii_kinds(line: str) -> set[str]:
    kinds = set()
    if _pans(line):
        kinds.add("pan")
    if _CPF_RE.search(line):
        kinds.add("cpf")
    if _EMAIL_RE.search(line):
        kinds.add("email")
    if _PHONE_RE.search(line):
        kinds.add("phone")
    if _DOB_RE.search(line):
        kinds.add("dob")
    return kinds


def _drop_reason(line: str) -> str | None:
    if _CRED_RE.search(line):
        return "credential"
    for rx in _COMBO_RES:
        if rx.search(line):
            return "combo"
    pii = _pii_kinds(line)
    if ("pan" in pii or "cpf" in pii) and (len(pii) >= 2 or _RECORD_KW_RE.search(line) or line.count("|") >= 2):
        return "leaked_record"
    if _RECORD_KW_RE.search(line) and pii and line.count(":") >= 2:
        return "leaked_record"
    return None


def scrub_post_text(text: Any) -> dict[str, Any]:
    """P112 cond 5/9 ingestion scrubbing (before cache, evidence and reports).

    Order: bot tokens and webhook URLs -> '[removed <kind> #<sha256 12 hex>]' (cond 9) -> lines with
    credentials, combo lines and leaked records dropped -> Luhn-valid 13-19 digit PANs reduced to
    BIN6 + last 4 -> CPF-like numbers '***.456.789-**' (AR24) -> e-mail local parts and phones masked.
    Returns ``{text, redactions {pan, cpf, email, phone}, dropped, drop_reasons, exposures
    [{kind, sha256_prefix}], bins}`` (``bins``: BIN6 of the Luhn-valid PANs with a card IIN 2-6, dropped lines included).
    """
    out: dict[str, Any] = {"text": "", "redactions": {"pan": 0, "cpf": 0, "email": 0, "phone": 0}, "dropped": 0,
                           "drop_reasons": {}, "exposures": [], "bins": []}
    if not isinstance(text, str) or not text:
        return out
    t = text[:POST_TEXT_CAP]

    def secret(kind: str) -> Any:
        def rep(m: re.Match[str]) -> str:
            h = hashlib.sha256(m.group(0).encode("utf-8")).hexdigest()[:12]
            out["exposures"].append({"kind": kind, "sha256_prefix": h})
            return f"[removed {kind} #{h}]"

        return rep

    for kind, rx in _SECRET_PATTERNS:
        t = rx.sub(secret(kind), t)
    kept, reasons, bins = [], Counter(), []
    for line in t.split("\n"):
        # every Luhn-valid PAN is truncated; only plausible card IINs (first digit 2-6) are reported as BINs
        bins.extend(p[:6] for p in _pans(line) if p[0] in "23456")
        why = _drop_reason(line)
        if why:
            reasons[why] += 1
            continue
        kept.append(line)
    t = "\n".join(kept)
    counts = out["redactions"]

    def pan(m: re.Match[str]) -> str:
        d = re.sub(r"\D", "", m.group(0))
        if not pan_valid(d):
            return m.group(0)
        counts["pan"] += 1
        return d[:6] + "*" * (len(d) - 10) + d[-4:]

    def cpf(m: re.Match[str]) -> str:
        d = re.sub(r"\D", "", m.group(0))
        counts["cpf"] += 1
        return f"***.{d[3:6]}.{d[6:9]}-**"

    def email(m: re.Match[str]) -> str:
        counts["email"] += 1
        return m.group(1)[:1] + "***@" + m.group(2)

    def phone(m: re.Match[str]) -> str:
        d = re.sub(r"\D", "", m.group(0))
        if not 8 <= len(d) <= 15:
            return m.group(0)
        counts["phone"] += 1
        return f"[phone ***{d[-2:]}]"

    t = _PAN_RE.sub(pan, t)
    t = _CPF_RE.sub(cpf, t)
    t = _EMAIL_RE.sub(email, t)
    t = _PHONE_RE.sub(phone, t)
    out.update(text=t, dropped=sum(reasons.values()), drop_reasons=dict(reasons), bins=sorted(set(bins)))
    return out


def scrub_posts(posts: Any) -> list[dict[str, Any]]:
    """Posts from :func:`parse_tme_channel_posts` with text and links scrubbed (cond 5/9): the only
    form kept in memory caches, evidence and reports. Each post gains ``scrub`` (counts of the text
    and its links)."""
    out: list[dict[str, Any]] = []
    for p in posts or ():
        if not isinstance(p, dict):
            continue
        sc = scrub_post_text(p.get("text") or "")
        links = [x for x in (p.get("links") or []) if isinstance(x, str)]
        lp = p.get("link_preview") if isinstance(p.get("link_preview"), dict) else None
        if lp and isinstance(lp.get("url"), str):
            links.append(lp["url"])
        lsc = scrub_post_text("\n".join(links))
        ff = p.get("forwarded_from") if isinstance(p.get("forwarded_from"), dict) else None
        out.append({
            "post_id": p.get("post_id"), "url": p.get("url"), "date": p.get("date"), "views": p.get("views"),
            "text": sc["text"], "links": [x for x in lsc["text"].split("\n") if x.strip()],
            "forwarded_from": {"kind": ff.get("kind"), "handle": ff.get("handle"), "name": ff.get("name") if ff.get("kind") == "channel" else None} if ff else None,
            "media": list(p.get("media") or []), "partial": bool(p.get("partial")),
            "scrub": {
                "redactions": {k: sc["redactions"][k] + lsc["redactions"][k] for k in sc["redactions"]},
                "dropped": sc["dropped"] + lsc["dropped"],
                "drop_reasons": dict(Counter(sc["drop_reasons"]) + Counter(lsc["drop_reasons"])),
                "exposures": sc["exposures"] + lsc["exposures"],
                "bins": sorted(set(sc["bins"]) | set(lsc["bins"])),
            },
        })
    return out


# ======================================================================================
# digest: indicators, excerpts, one-block summary (P112 cond 6-9)
# ======================================================================================

#: Hosts warninglisted on every path (Telegram family) and big platforms (domains and bare-host URLs only, AR06).
TELEGRAM_FAMILY = ("t.me", "telegram.me", "telegram.org", "telegram.dog", "telesco.pe")
BIG_PLATFORMS = (
    "google.com", "youtube.com", "youtu.be", "facebook.com", "instagram.com", "twitter.com", "x.com", "whatsapp.com", "wa.me",
    "github.com", "microsoft.com", "apple.com", "wikipedia.org", "linkedin.com", "tiktok.com", "discord.gg", "discord.com",
    "gmail.com", "outlook.com", "hotmail.com", "yahoo.com",
)
INFRA_TYPES = frozenset({T.URL, T.DOMAIN, T.IPV4, T.IPV6, T.ONION, T.BTC, T.ETH, T.XMR, T.TELEGRAM_INVITE, T.DISCORD_INVITE})
_GROUP_OF = {
    T.URL: "url", T.DOMAIN: "domain", T.IPV4: "ip", T.IPV6: "ip", T.ONION: "onion", T.BTC: "wallet", T.ETH: "wallet",
    T.XMR: "wallet", T.TELEGRAM_INVITE: "invite", T.DISCORD_INVITE: "invite",
}
_SUMMARY_LABELS = (("url", "URL", "URLs"), ("domain", "domain", "domains"), ("ip", "IP", "IPs"), ("wallet", "wallet", "wallets"),
                   ("onion", "onion", "onions"), ("invite", "invite", "invites"))
_TG_INVITE_RE = re.compile(r"(?:https?://)?(?:t\.me|telegram\.me|telegram\.dog)/(?:\+|joinchat/)([A-Za-z0-9_-]{8,64})", re.I)
_DISCORD_INVITE_RE = re.compile(r"(?:https?://)?(?:www\.)?(?:discord\.gg|discord(?:app)?\.com/invite)/([A-Za-z0-9-]{2,32})", re.I)
_TG_LINK_RE = re.compile(r"(?:https?://)?(?:t\.me|telegram\.me)/(?:s/)?([A-Za-z][A-Za-z0-9_]{4,31})(?:/\d+)?", re.I)
_MASKED_EMAIL_RE = re.compile(r"\S*\*\*\*@\S+")
#: live or defanged URLs in post text ('[.]' groups are part of a defanged URL; other brackets end it)
_URL_IN_TEXT_RE = re.compile(r"\b(?:https?|hxxps?)(?:\[:\]|:)//(?:\[\.\]|[^\s<>\"'`\[\]()])+", re.I)


def _host_listed(host: str, suffixes: tuple[str, ...]) -> bool:
    h = (host or "").lower().rstrip(".")
    return any(h == d or h.endswith("." + d) for d in suffixes)


def ioc_warninglisted(entity: Entity) -> bool:
    """P112 cond 7 warninglist: Telegram hosts always; big platforms as domains and bare-host URLs
    only (URLs with a path on them stay, AR06); plus the core named warninglists."""
    if entity.type is T.DOMAIN and _host_listed(entity.value, TELEGRAM_FAMILY + BIG_PLATFORMS):
        return True
    if entity.type is T.URL:
        host = url_host(entity.value)
        if _host_listed(host, TELEGRAM_FAMILY):
            return True
        try:
            sp = urlsplit(entity.value)
        except ValueError:
            return True
        if _host_listed(host, BIG_PLATFORMS) and sp.path in ("", "/") and not sp.query:
            return True
    try:
        return bool(noise.warninglists(entity))
    except Exception:  # noqa: BLE001 - a broken runtime list must never drop the digest
        return False


def post_indicators(text: str, *, own_handle: str = "") -> tuple[list[Entity], list[str]]:
    """Infrastructure indicators of scrubbed post text (core extractor + invites) and the Telegram
    handles it links to. Masked e-mail addresses never yield their domain."""
    clean = _MASKED_EMAIL_RE.sub(" ", text or "")
    found: list[Entity] = []
    seen: set[str] = set()

    def add(ent: Entity | None) -> None:
        if ent is not None and ent.type in INFRA_TYPES and ent.key not in seen:
            seen.add(ent.key)
            found.append(ent)

    for ent in extract_iocs(clean, limit=500):
        add(ent)
    live = refang(clean)
    for m in _TG_INVITE_RE.finditer(live):
        add(Entity.try_make(T.TELEGRAM_INVITE, m.group(1)))
    for m in _DISCORD_INVITE_RE.finditer(live):
        add(Entity.try_make(T.DISCORD_INVITE, m.group(1)))
    mentions = []
    for m in _TG_LINK_RE.finditer(live):
        h = m.group(1).lower()
        if h not in TME_RESERVED and h != (own_handle or "").lower() and h not in mentions:
            mentions.append(h)
    return found, mentions


def _needles(ent: Entity) -> list[str]:
    values = [ent.value]
    if ent.type is T.URL:
        host = url_host(ent.value)
        if host:
            values.append(host)
    return values


def _needle_re(value: str) -> re.Pattern[str]:
    parts = []
    for ch in value:
        parts.append(r"(?:\.|\[\.\]|\(\.\)|\{\.\}|\[dot\]|\(dot\))" if ch == "." else re.escape(ch))
    pat = re.sub(r"^h(?:\\?t){2}p", "h(?:tt|xx)p", "".join(parts), flags=re.I)
    return re.compile(pat, re.I)


def _fold_same_len(s: str) -> str:
    out = []
    for ch in s:
        base = "".join(c for c in unicodedata.normalize("NFKD", ch) if not unicodedata.combining(c)) or ch
        low = base.lower()
        out.append(low[0] if low else ch)
    return "".join(out)


def _brand_spans(text: str, terms: Any) -> list[tuple[int, int]]:
    folded = _fold_same_len(text)
    spans = []
    for term in terms or ():
        if not isinstance(term, str) or not term.strip():
            continue
        ft = _fold_same_len(term.strip())
        start = folded.find(ft)
        while start != -1:
            spans.append((start, start + len(ft)))
            start = folded.find(ft, start + 1)
    return spans


def excerpt_windows(text: str, spans: list[tuple[int, int]], side: int = EXCERPT_SIDE, cap: int = EXCERPT_CAP) -> str | None:
    """P112 cond 6: <= ``side`` chars each side of every matched span, merged, <= ``cap`` in total."""
    if not isinstance(text, str) or not text or not spans:
        return None
    wins = sorted((max(0, s - side), min(len(text), e + side)) for s, e in spans)
    merged: list[tuple[int, int]] = []
    for s, e in wins:
        if merged and s <= merged[-1][1]:
            merged[-1] = (merged[-1][0], max(merged[-1][1], e))
        else:
            merged.append((s, e))
    sep, parts, used = " … ", [], 0
    for s, e in merged:
        room = cap - used - (len(sep) if parts else 0)
        if room <= 0:
            break
        seg = text[s:e][:room]
        used += len(seg) + (len(sep) if parts else 0)
        parts.append(seg)
    return sep.join(parts)


def report_quote(text: str, span: tuple[int, int] | None = None, cap: int = QUOTE_CAP, iocs: Any = ()) -> str | None:
    """P112 cond 6: report quote of <= ``cap`` chars centred on ``span``; URLs and the given IOC
    values (domains, IPs, onions) are defanged for display (AR13)."""
    if not isinstance(text, str) or not text:
        return None
    start = 0
    if span:
        mid = (span[0] + span[1]) // 2
        start = max(0, min(len(text) - cap, mid - cap // 2))
    q = text[start:start + cap]
    q = _URL_IN_TEXT_RE.sub(lambda m: defang(m.group(0)), q)
    for value in sorted({v for v in iocs if isinstance(v, str)}, key=len, reverse=True):
        q = _needle_re(value).sub(lambda m: defang(refang(m.group(0))), q)
    return q[:cap]


def digest_tme_posts(posts: Any, channel_handle: str | None = None, brand_terms: Any = (), *, top_n: int = TOP_N) -> dict[str, Any]:
    """P112 cond 5-9 pipeline over **scrubbed** posts (:func:`scrub_posts`); never returns full post text.

    Returns ``{posts_read, records, indicators [{entity, count, posts}], forwarded_from [{handle,
    name, count}], mentioned_handles, exposures [{kind, sha256_prefix, posts}], brand_mentions,
    summary, counts, top, totals, bins}``. Records exist only for posts with an indicator, a brand
    term, an exposure or a channel forward: post id, date, URL, excerpt (<= 300 chars each side,
    <= 1,000 in total) and a defanged report quote (<= 200 chars).
    """
    own = (channel_handle or "").lower()
    records: list[dict[str, Any]] = []
    agg: dict[str, dict[str, Any]] = {}
    exposures: dict[tuple[str, str], dict[str, Any]] = {}
    forwards: dict[str, dict[str, Any]] = {}
    brands: dict[str, list[Any]] = {}
    mentions: list[str] = []
    totals: Counter[str] = Counter()
    bins: set[str] = set()
    n_posts = 0
    for p in posts or ():
        if not isinstance(p, dict):
            continue
        n_posts += 1
        sc = p.get("scrub") if isinstance(p.get("scrub"), dict) else {}
        text = p.get("text") if isinstance(p.get("text"), str) else ""
        for k, v in (sc.get("redactions") or {}).items():
            totals[k] += int(v or 0)
        for k, v in (sc.get("drop_reasons") or {}).items():
            totals["drop:" + k] += int(v or 0)
        bins.update(b for b in sc.get("bins") or () if isinstance(b, str))
        pid = p.get("post_id")
        found, ment = post_indicators(text + "\n" + "\n".join(p.get("links") or []), own_handle=own)
        for h in ment:
            if h not in mentions:
                mentions.append(h)
        post_iocs = []
        for ent in found:
            if ioc_warninglisted(ent):
                continue
            post_iocs.append(ent)
            a = agg.setdefault(ent.key, {"entity": ent, "count": 0, "posts": []})
            a["count"] += 1
            if pid is not None and pid not in a["posts"] and len(a["posts"]) < 20:
                a["posts"].append(pid)
        post_exposures = [e for e in sc.get("exposures") or () if isinstance(e, dict)]
        for e in post_exposures:
            entry = exposures.setdefault((e.get("kind"), e.get("sha256_prefix")), {"kind": e.get("kind"), "sha256_prefix": e.get("sha256_prefix"), "posts": []})
            if pid is not None and pid not in entry["posts"]:
                entry["posts"].append(pid)
        ff = p.get("forwarded_from") if isinstance(p.get("forwarded_from"), dict) else None
        fwd = ff.get("handle") if ff and ff.get("kind") == "channel" else None
        if fwd and fwd.lower() != own:
            f = forwards.setdefault(fwd.lower(), {"handle": fwd.lower(), "name": ff.get("name"), "count": 0})
            f["count"] += 1
        spans: list[tuple[int, int]] = []
        for ent in post_iocs:
            for needle in _needles(ent):
                spans += [m.span() for m in _needle_re(needle).finditer(text)]
        hits = sorted({t for t in brand_terms or () if isinstance(t, str) and _brand_spans(text, [t])})
        for t in hits:
            brands.setdefault(t, [])
            if pid is not None and pid not in brands[t]:
                brands[t].append(pid)
        spans += _brand_spans(text, hits)
        spans += [m.span() for m in _REMOVED_RE.finditer(text)]
        if post_iocs or hits or post_exposures or fwd:
            first = min(spans) if spans else None
            defang_values = [e.value for e in post_iocs if e.type in (T.DOMAIN, T.IPV4, T.IPV6, T.ONION)]
            records.append({
                "post_id": pid, "date": p.get("date"), "url": p.get("url"),
                "excerpt": excerpt_windows(text, spans) if spans else None,
                "report_quote": report_quote(text, first, iocs=defang_values) if first is not None else None,
                "iocs": [{"type": e.type.value, "value": e.value} for e in post_iocs],
                "brand_terms": hits, "exposures": [{"kind": e.get("kind"), "sha256_prefix": e.get("sha256_prefix")} for e in post_exposures],
                "redactions": dict(sc.get("redactions") or {}), "dropped": int(sc.get("dropped") or 0),
                "media": list(p.get("media") or []), "forwarded_from": fwd,
            })
    indicators = sorted(agg.values(), key=lambda x: (-x["count"], x["entity"].type.value, x["entity"].value))
    counts = Counter(_GROUP_OF[x["entity"].type] for x in indicators)
    parts = [f"{counts[k]} {one if counts[k] == 1 else many}" for k, one, many in _SUMMARY_LABELS if counts.get(k)]
    summary = f"{', '.join(parts)} from {n_posts} posts" if parts else f"no indicators in {n_posts} posts"
    top: dict[str, list[str]] = {}
    for key, _one, _many in _SUMMARY_LABELS:
        vals = [_display(x["entity"]) for x in indicators if _GROUP_OF[x["entity"].type] == key][:top_n]
        if vals:
            top[key] = vals
    return {
        "posts_read": n_posts, "records": records[:MAX_RECORDS], "indicators": indicators,
        "forwarded_from": sorted(forwards.values(), key=lambda f: (-f["count"], f["handle"])),
        "mentioned_handles": mentions[:50], "exposures": list(exposures.values()),
        "brand_mentions": [{"term": t, "posts": ids[:20]} for t, ids in sorted(brands.items())],
        "summary": summary, "counts": dict(counts), "top": top, "totals": dict(totals), "bins": sorted(bins),
    }


def _display(ent: Entity) -> str:
    if ent.type in (T.URL, T.DOMAIN, T.IPV4, T.IPV6, T.ONION):
        return defang(ent.value)
    if ent.type is T.TELEGRAM_INVITE:
        return f"t.me/+{ent.value}"
    if ent.type is T.DISCORD_INVITE:
        return f"discord.gg/{ent.value}"
    return ent.value


# ======================================================================================
# fetching (no raw page is ever cached; scrubbed results are kept 1 h in memory)
# ======================================================================================


class _PageCache:
    """Scrubbed parse results of t.me pages, per HTTP client (one per runtime), PAGE_CACHE_TTL seconds."""

    def __init__(self, size: int = 128) -> None:
        self._lock = threading.Lock()
        self._items: OrderedDict[str, tuple[float, dict[str, Any]]] = OrderedDict()
        self._size = size

    def get(self, key: str, now: float, ttl: float) -> dict[str, Any] | None:
        with self._lock:
            hit = self._items.get(key)
            if hit is None:
                return None
            if now - hit[0] > ttl or now < hit[0]:
                self._items.pop(key, None)
                return None
            self._items.move_to_end(key)
            return copy.deepcopy(hit[1])

    def put(self, key: str, now: float, value: dict[str, Any]) -> None:
        with self._lock:
            self._items[key] = (now, copy.deepcopy(value))
            self._items.move_to_end(key)
            while len(self._items) > self._size:
                self._items.popitem(last=False)


_CACHES: weakref.WeakKeyDictionary[Any, _PageCache] = weakref.WeakKeyDictionary()
_CACHES_LOCK = threading.Lock()


def _page_cache(ctx: Any) -> _PageCache:
    owner = getattr(getattr(ctx, "http", None), "client", None)  # v3lum-lint: allow LINT-01 -- identity key of the per-client page cache only; no request goes through it
    try:
        with _CACHES_LOCK:
            cache = _CACHES.get(owner)
            if cache is None:
                cache = _PageCache()
                _CACHES[owner] = cache
            return cache
    except TypeError:  # no weak-referenceable client: no cross-call cache
        return _PageCache()


def fetch_tme_page(ctx: Any, url: str, *, kind: str, handle: str | None = None, use_cache: bool = True) -> dict[str, Any]:
    """GET one t.me page and return its **scrubbed** parse result (shared with P357).

    ``kind`` 'profile' (t.me/{name}: :func:`parse_tme_profile`, description scrubbed) or 'posts'
    (t.me/s/{name}: :func:`parse_tme_channel_posts`, posts scrubbed with :func:`scrub_posts`). The
    request is sent with ``ttl=0`` (raw HTML never reaches the HTTP cache, P112 cond 5) and a 2 MB
    cap; the scrubbed result is kept in memory for PAGE_CACHE_TTL seconds (cond 4). The generic
    'Contact @x' page (provider marker) is returned as UNKNOWN 'private or missing: could not read';
    every other classified or failed answer raises like ``ctx.http.check`` (rule 5).
    """
    if kind not in ("profile", "posts") or not tme_fetch_allowed(url):
        raise ValueError(f"not a t.me public preview URL: {url!r}")
    cache = _page_cache(ctx)
    now = ctx.now().timestamp()
    key = f"{kind} {url}"
    if use_cache:
        hit = cache.get(key, now, PAGE_CACHE_TTL)
        if hit is not None:
            hit["from_memory"] = True
            return hit
    resp = ctx.http.get(url, ttl=0, max_bytes=TME_PAGE_CAP, headers=dict(TME_HEADERS), source=SOURCE)
    try:
        ctx.http.check(resp)
    except HttpError:
        found = getattr(resp, "classification", None)
        if found is None or getattr(found, "marker_id", "") != GENERIC_MARKER_ID:
            raise
    final = str(getattr(resp, "url", "") or url)
    if kind == "profile":
        parsed = parse_tme_profile(resp.content, handle)
        if parsed.get("description"):
            parsed["description"] = scrub_post_text(parsed["description"])["text"] or None
    else:
        parsed = parse_tme_channel_posts(resp.content, handle)
        redirected = urlsplit(final).path.rstrip("/") != urlsplit(url).path.rstrip("/")
        if redirected and not urlsplit(final).path.startswith("/s/"):
            parsed = {"state": "UNKNOWN", "reason": NO_PREVIEW_REASON, "channel": None, "posts": [], "next_before": None,
                      "truncated": False, "partial": False}
        parsed["posts"] = scrub_posts(parsed.get("posts"))
        ch = parsed.get("channel")
        if isinstance(ch, dict) and ch.get("description"):
            ch["description"] = scrub_post_text(ch["description"])["text"] or None
    parsed["truncated"] = bool(parsed.get("truncated") or getattr(resp, "truncated", False))
    parsed["final_url"] = final
    cache.put(key, now, parsed)
    parsed["from_memory"] = False
    return parsed


def _target(entity: Entity) -> str | None:
    if entity.type in (T.TELEGRAM_HANDLE, T.USERNAME, T.URL):
        return tme_handle(entity.value)
    return None


def _selftest(ctx: Any) -> HealthResult:
    """Doctor self-test: Telegram's own public channel page must parse as a FOUND channel."""
    try:
        page = fetch_tme_page(ctx, "https://t.me/telegram", kind="profile", handle="telegram", use_cache=False)
    except QuotaExceeded as exc:
        return HealthResult("quota", str(exc)[:200])
    except RateLimited as exc:
        return HealthResult("blocked", f"rate limited: {str(exc)[:180]}")
    except HttpError as exc:
        return HealthResult("blocked" if exc.reason_code in ("challenge", "geo_block", "login_wall", "circuit") else "dead", str(exc)[:200])
    except NetworkError as exc:
        return HealthResult("dead", str(exc)[:200])
    if page.get("state") == "FOUND" and page.get("kind") == "channel":
        return HealthResult("ok", "t.me/telegram parsed as a public channel")
    if page.get("reason") == TME_GENERIC_REASON:
        # Telegram's own channel certainly exists: the generic page means throttling (bursts) or a refused UA
        return HealthResult("blocked", "t.me served the generic 'Contact @x' page for t.me/telegram (throttled): could not verify")
    return HealthResult("dead", f"t.me page markup not recognised ({page.get('reason') or page.get('kind')})")


# ======================================================================================
# the module
# ======================================================================================


@register
class TelegramPublic(Module):
    name = "telegram_public"
    title = "Telegram public preview"
    description = (
        "Presence, kind (channel/group/user/bot) and public channel posts of a Telegram handle from the unauthenticated "
        "t.me web preview; post text is scrubbed and only infrastructure indicators are listed."
    )
    category = "username_social"
    accepts = {T.TELEGRAM_HANDLE, T.USERNAME, T.URL}
    produces = {T.URL, T.DOMAIN, T.IPV4, T.IPV6, T.ONION, T.BTC, T.ETH, T.XMR, T.TELEGRAM_INVITE, T.DISCORD_INVITE, T.TELEGRAM_HANDLE}
    terms = "open"
    opsec = Opsec.PASSIVE
    disclosure = "third_party"
    provider = "telegram"
    sources = (SOURCE,)
    hosts = (TME_HOST,)
    access_model = "free_noauth_limited"
    max_requests = 1 + DEEP_PAGES  # profile + up to 3 preview pages (--preset deep)
    expected_latency = 6.0  # profile + 2 pages with 2 s spacing (default preset)
    timeout = 45.0
    min_interval = 2.0  # P112 cond 4
    cache_ttl = PAGE_CACHE_TTL  # P112 cond 4: scrubbed results only, in memory (raw pages never cached)
    max_pivots = 150
    default_enabled = True
    manual_link = "https://t.me/s/{user}"  # inline: also renders for telegram_handle entities
    reference = "https://telegram.org/tos"
    tags = {"free"}
    notice = (
        "Unauthenticated public previews only (no account, session, bot token or joining). Post text is scrubbed "
        "before cache, evidence and reports (cards to BIN6+last4, CPF/e-mail/phone masked, credentials and leaked "
        "records dropped); media, files and links are never fetched. Telegram handles are personal data: the provider's "
        "personal_data_review must be recorded before default use."
    )

    @classmethod
    def health_check(cls) -> HealthCheck:
        return HealthCheck(offline=False, selftest=_selftest)

    def applies(self, entity: Entity, ctx: Any) -> bool:
        handle = _target(entity)
        if handle is None:
            return False
        # P112 cond 4: typed handles and t.me links found in the case; a generic username runs only
        # when the analyst typed it (no username sweep over pivots, A5)
        return entity.type is not T.USERNAME or bool(getattr(ctx, "is_seed", False))

    def run(self, entity: Entity, ctx: Any) -> ModuleResult:
        res = self.result(entity)
        handle = _target(entity)
        profile_url = tme_profile_url(handle or "")
        if not handle or profile_url is None:
            return res.mark("skipped", "not a Telegram handle or t.me link", reason_code="not_applicable")
        page = fetch_tme_page(ctx, profile_url, kind="profile", handle=handle)
        if page.get("state") != "FOUND":
            reason = page.get("reason") or TME_GENERIC_REASON
            res.presence("unknown", marker=reason, url=profile_url, checked_at=ctx.now(), source=SOURCE)
            res.raw = {"handle": handle, "profile_url": profile_url, "state": "UNKNOWN", "reason": reason}
            return res.mark("error", f"t.me/{handle}: {reason}")
        kind = page.get("kind") or "user"
        res.presence("found", marker="tgme_page_title", url=profile_url, checked_at=ctx.now(), source=SOURCE)
        res.attr("account_type", kind)
        res.attr("display_name", page.get("display_name"))
        raw: dict[str, Any] = {"handle": handle, "profile_url": profile_url, "kind": kind}
        res.raw = raw
        if page.get("truncated"):
            res.error = "profile page over the 2 MB cap: parsed the first 2 MB"
        if kind == "user":
            return res  # P112 cond 3: personal profiles yield presence and display name only
        res.attr("verified", bool(page.get("verified")))
        res.attr("bio", page.get("description"))
        counters = page.get("counters") if isinstance(page.get("counters"), dict) else {}
        for key, attr in (("subscribers", "subscribers"), ("members", "members"), ("online", "online_members"), ("monthly_users", "monthly_users")):
            if isinstance(counters.get(key), int):
                res.attr(attr, counters[key])
        if kind != "channel":
            return res  # posts are read for channels only (cond 3)
        self._channel_posts(res, ctx, handle, page, raw)
        return res

    # ------------------------------------------------------------------ channel posts
    def _channel_posts(self, res: ModuleResult, ctx: Any, handle: str, page: dict[str, Any], raw: dict[str, Any]) -> None:
        options = getattr(ctx, "options", None)
        max_pages = DEEP_PAGES if str(getattr(options, "preset", "quick") or "quick") == "deep" else DEFAULT_PAGES
        posts: list[dict[str, Any]] = []
        pages: list[str] = []
        notes: list[str] = []
        has_preview: bool | None = None
        before = None
        for index in range(max_pages):
            url = tme_preview_url(handle, before)
            if url is None:
                break
            try:
                pg = fetch_tme_page(ctx, url, kind="posts", handle=handle)
            except (RateLimited, QuotaExceeded) as exc:
                notes.append(f"preview page {index + 1}: {exc}")
                res.stop("quota" if isinstance(exc, QuotaExceeded) else "rate_limited")
                break
            except DeadlineExceeded:
                raise
            except (HttpError, NetworkError) as exc:  # blocked, challenge, 5xx, connection: could not read (rule 5)
                notes.append(f"preview page {index + 1}: could not read ({exc})")
                break
            pages.append(url)
            if pg.get("state") != "FOUND":
                if index == 0:
                    has_preview = False
                notes.append(f"preview page {index + 1}: {pg.get('reason')}")
                break
            has_preview = True
            known = {p.get("post_id") for p in posts}
            posts.extend(p for p in pg.get("posts") or [] if p.get("post_id") is None or p.get("post_id") not in known)
            if pg.get("reason"):
                notes.append(f"preview page {index + 1}: {pg['reason']}")
            before = pg.get("next_before")
            if not before or not pg.get("posts"):
                break
        if has_preview is None:
            has_preview = bool(page.get("has_preview"))
        res.attr("has_preview", has_preview)
        raw["pages"] = pages
        if notes:
            res.error = "; ".join(n for n in [res.error, *notes] if n)
        if not posts:
            return
        digest = digest_tme_posts(posts, channel_handle=handle, brand_terms=_brand_terms(ctx))
        self._report_digest(res, ctx, handle, digest, raw)

    def _report_digest(self, res: ModuleResult, ctx: Any, handle: str, digest: dict[str, Any], raw: dict[str, Any]) -> None:
        preview = f"https://t.me/s/{handle}"
        res.attr("posts_read", digest["posts_read"])
        res.attr("ioc_summary", {"summary": digest["summary"], "counts": digest["counts"], "top": digest["top"]})
        res.attr("mentioned_handles", digest["mentioned_handles"])
        res.attr("brand_mentions", digest["brand_mentions"])
        totals = digest["totals"]
        drop_reasons = {_DROP_LABELS.get(k[5:], k[5:]): v for k, v in totals.items() if k.startswith("drop:") and v}
        scrub = {
            "pans_truncated": totals.get("pan", 0), "cpfs_redacted": totals.get("cpf", 0), "emails_redacted": totals.get("email", 0),
            "phones_redacted": totals.get("phone", 0), "records_dropped": sum(drop_reasons.values()), "drop_reasons": drop_reasons,
        }
        if any(v for v in scrub.values()):
            res.attr("post_scrubbing", scrub)
        raw.update(posts_read=digest["posts_read"], summary=digest["summary"], records=digest["records"], post_scrubbing=scrub)
        per_group: Counter[str] = Counter()
        for item in digest["indicators"]:
            ent: Entity = item["entity"]
            group = _GROUP_OF[ent.type]
            if per_group[group] >= PIVOTS_PER_GROUP:
                continue
            per_group[group] += 1
            first = item["posts"][0] if item["posts"] else None
            where = f" (e.g. post {first})" if first is not None else ""
            res.pivot(
                ent.type, ent.value, "mentioned_in_post", confidence="possible", expand=False,
                note=f"mentioned in {item['count']} public post(s) of t.me/s/{handle}{where}: hostile-shaped, never visited automatically",
            )
        for fwd in digest["forwarded_from"][:25]:
            res.pivot(T.TELEGRAM_HANDLE, fwd["handle"], "forwarded_from", confidence="possible", expand=False,
                      note=f"{fwd['count']} post(s) forwarded from this public channel")
        quotes = [{"post": r["url"], "quote": r["report_quote"]} for r in digest["records"] if r.get("report_quote")][:TOP_N]
        if digest["indicators"]:
            lines = [f"{key}: {', '.join(vals)}" for key, vals in digest["top"].items()]
            res.finding(
                "Indicators in public Telegram posts",
                "info",
                f"{digest['summary']} (t.me/s/{handle}). Top {TOP_N} per group (defanged): " + "; ".join(lines),
                confidence="possible",
                criterion="infrastructure indicators extracted from scrubbed public post text (never visited)",
                data={"counts": digest["counts"], "top": digest["top"], "quotes": quotes},
                tags=["info"],
                references=[preview],
                source=SOURCE,
            )
        if digest["exposures"]:
            kinds = sorted({e["kind"] for e in digest["exposures"]})
            res.attr("bot_webhook_exposures", digest["exposures"])
            res.finding(
                "Bot tokens or webhook URLs posted in a public channel",
                "medium",
                f"{len(digest['exposures'])} item(s) ({', '.join(kinds)}) posted on t.me/s/{handle}; kept as type + SHA-256 prefix "
                "only, never used or tested.",
                confidence="probable",
                criterion="Telegram bot token / webhook URL pattern in public post text (P112 cond 9)",
                data={"exposures": digest["exposures"]},
                tags=["credential_exposure"],
                references=[preview],
                source=SOURCE,
            )
        bins = digest["bins"]
        if bins:
            own = _own_bins(ctx, bins)
            res.finding(
                "Payment card numbers posted in a public channel",
                "medium",
                f"{len(bins)} card BIN(s) in posts of t.me/s/{handle}: {', '.join(bins[:10])}. Card numbers were reduced to "
                "BIN6 + last 4 at ingestion (leaked-record lines dropped); nothing was stored in full.",
                confidence="probable",
                criterion="Luhn-valid 13-19 digit numbers in public post text (P112 cond 5)",
                data={"bins": bins[:50]},
                tags=["fraud"],
                references=[preview],
                source=SOURCE,
            )
            if own:
                res.finding(
                    "Organisation card BINs in public Telegram posts",
                    "high",
                    f"Card numbers with the organisation's BIN prefixes {', '.join(own)} were posted on t.me/s/{handle}.",
                    confidence="probable",
                    criterion="BIN6 of a Luhn-valid card number in public post text matches an org-profile card BIN",
                    data={"own_bins": own},
                    tags=["fraud"],
                    references=[preview],
                    source=SOURCE,
                )
        dropped = {k: v for k, v in drop_reasons.items() if v}
        if dropped:
            res.finding(
                "Leaked personal or credential records posted in a public channel",
                "medium",
                f"{sum(dropped.values())} line(s) dropped at ingestion and never stored: "
                + ", ".join(f"{k} x{v}" for k, v in sorted(dropped.items())) + f" (t.me/s/{handle}).",
                confidence="possible",
                criterion="lines combining card/CPF data with other identifiers, e-mail:password combos or password assignments (heuristic)",
                data={"drop_reasons": dropped},
                tags=["breach"],
                references=[preview],
                source=SOURCE,
            )
        if digest["brand_mentions"]:
            terms = [b["term"] for b in digest["brand_mentions"]]
            brand_quotes = [{"post": r["url"], "quote": r["report_quote"]} for r in digest["records"] if r.get("brand_terms") and r.get("report_quote")][:TOP_N]
            res.finding(
                "Organisation brand mentioned in public Telegram posts",
                "low",
                f"Brand term(s) {', '.join(terms)} in {sum(len(b['posts']) for b in digest['brand_mentions'])} post(s) of t.me/s/{handle}.",
                confidence="possible",
                criterion="org-profile brand keyword in scrubbed public post text",
                data={"brand_mentions": digest["brand_mentions"], "quotes": brand_quotes},
                tags=["weak_signal"],
                references=[preview],
                source=SOURCE,
            )


def _brand_terms(ctx: Any) -> list[str]:
    org = getattr(ctx, "org", None)
    try:
        terms = org.brand_terms() if org is not None else []
    except Exception:  # noqa: BLE001 - a broken profile never stops the digest
        return []
    return [t for t in terms if isinstance(t, str) and len(t.strip()) >= 3]


def _own_bins(ctx: Any, bins: list[str]) -> list[str]:
    org = getattr(ctx, "org", None)
    if org is None:
        return []
    own = []
    for b in bins:
        ent = Entity.try_make(T.CARD_BIN, b)
        try:
            if ent is not None and org.owns(ent).own:
                own.append(b)
        except Exception:  # noqa: BLE001
            continue
    return own
