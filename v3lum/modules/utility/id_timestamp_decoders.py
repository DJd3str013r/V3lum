"""Snowflake / platform-ID -> creation-time decoders (P314, batch p2-G12-2): X/Twitter, Discord, TikTok, LinkedIn.

Offline (c1): disclosure 'none', terms 'open', no provider (tier n/a), allowed at TLP:RED; nothing is fetched
or resolved. The decoders are public bit layouts, re-implemented here (no third-party code copied):

* X/Twitter post ids: ``(id >> 22) + 1288834974657`` ms (snowflake epoch). Ids below ~2.9e13 (before the
  November 2010 snowflake rollout) are sequential and are not decoded (c3);
* Discord ids (guild, channel, message, webhook): ``(id >> 22) + 1420070400000`` ms;
* TikTok video ids: the top 32 bits are Unix seconds (the method popularised by Bellingcat's MIT-licensed
  tiktok-timestamp; only the published bit layout is used, no code was adapted);
* LinkedIn activity ids: the first 41 bits of the id are Unix milliseconds (LinkdTime method).

Instagram and Mastodon ids are excluded until validated with vectors (c3).

c2: ids are taken ONLY from recognised platform URLs (x.com/twitter.com .../status/ID, discord.com/channels/...
and webhook URLs, tiktok.com/@user/video/ID, linkedin.com/...activity-ID) or after an explicit
``snowflake:`` prefix (``snowflake:discord:ID``, ``snowflake:x:ID``...), plus the typed ``snowflake_id`` and
``tiktok_video_id`` entities (explicit types only). Arbitrary long numbers in text blobs or keywords are never
interpreted. A bare ``snowflake:ID`` / ``snowflake_id`` is ambiguous between the X and Discord epochs: both
readings are shown, labelled, and no single 'created' value is recorded.

c4: a decoded time must fall between the platform's launch and now + 1 day, otherwise it is discarded (status
'out_of_window', never shown as a date). c5: the 'created' attribute is UTC ISO with the epoch used
(``created_epoch``), rendered 'created ~2024-05-02 13:11 UTC (decoded from the ID)'.

Discord webhook URLs carry a token that lets anyone post to the channel: the token is never copied into any
output (only the numeric webhook id is decoded).
"""

from __future__ import annotations

import re
from datetime import datetime, timedelta, timezone
from typing import Any

from v3lum.core.entities import Entity
from v3lum.core.entities import EntityType as T
from v3lum.core.models import ModuleResult, Opsec
from v3lum.core.module import Module, register

UTC = timezone.utc
_EPOCH = datetime(1970, 1, 1, tzinfo=UTC)

X_EPOCH_MS = 1288834974657  # c3
DISCORD_EPOCH_MS = 1420070400000  # c3
#: c3 (binding text): "ids below ~2.9e13, pre-November 2010, are sequential and not decoded".
X_MIN_SNOWFLAKE_ID = 29_000_000_000_000
#: c4 sanity window lower bounds ("platform's launch"); the upper bound is now + 1 day.
PLATFORM_LAUNCH = {
    "x": datetime(2010, 11, 4, tzinfo=UTC),  # snowflake rollout (X/Twitter itself: 2006-03-21)
    "discord": datetime(2015, 5, 13, tzinfo=UTC),  # public launch (the epoch is 2015-01-01)
    "tiktok": datetime(2016, 9, 1, tzinfo=UTC),  # Douyin launch (ByteDance video ids)
    "linkedin": datetime(2003, 5, 5, tzinfo=UTC),  # LinkedIn launch
}
PLATFORM_EPOCH_LABEL = {
    "x": "X snowflake epoch 1288834974657 ms: (id >> 22) + epoch",
    "discord": "Discord snowflake epoch 1420070400000 ms: (id >> 22) + epoch",
    "tiktok": "TikTok video id: id >> 32 = Unix seconds (Bellingcat tiktok-timestamp method, MIT)",
    "linkedin": "LinkedIn activity id: first 41 bits = Unix ms (LinkdTime method)",
}
PLATFORM_TITLE = {"x": "X/Twitter", "discord": "Discord", "tiktok": "TikTok", "linkedin": "LinkedIn"}
STATUS_TEXT = {
    "pre_snowflake": "pre-snowflake sequential X id (below ~2.9e13, before November 2010): no creation time can be derived",
    "out_of_window": "decoded time falls outside the platform's lifetime (launch .. now + 1 day): discarded, not a date",
    "invalid": "not a canonical 64-bit id",
    "unsupported": "platform not supported (Instagram and Mastodon ids are excluded until validated)",
}
_PLATFORM_ALIASES = {"x": "x", "twitter": "x", "discord": "discord", "tiktok": "tiktok", "linkedin": "linkedin"}

_X_URL_RE = re.compile(
    r"\bhttps?://(?:www\.|mobile\.|m\.)?(?:x|twitter)\.com/(?:i/web|[A-Za-z0-9_]{1,15})/status(?:es)?/(\d{1,20})(?!\d)",
    re.I | re.A)
_DISCORD_CHANNEL_RE = re.compile(
    r"\bhttps?://(?:(?:www|ptb|canary)\.)?discord(?:app)?\.com/channels/(@me|\d{1,20})/(\d{1,20})(?:/(\d{1,20}))?(?!\d)",
    re.I | re.A)
_DISCORD_WEBHOOK_RE = re.compile(
    r"\bhttps?://(?:(?:www|ptb|canary)\.)?discord(?:app)?\.com/api(?:/v\d{1,2})?/webhooks/(\d{1,20})(?:/([A-Za-z0-9_-]{1,200}))?",
    re.I | re.A)
_TIKTOK_URL_RE = re.compile(r"\bhttps?://(?:www\.|m\.)?tiktok\.com/@[A-Za-z0-9_.]{1,64}/video/(\d{1,20})(?!\d)", re.I | re.A)
_LINKEDIN_URL_RE = re.compile(
    r"\bhttps?://(?:[a-z]{2,3}\.)?linkedin\.com/(?:posts/[^\s/?#\"'<>]{0,300}?-activity-"
    r"|(?:embed/)?feed/update/urn(?::|%3A)li(?::|%3A)activity(?::|%3A))(\d{15,20})(?!\d)",
    re.I | re.A)
_SNOWFLAKE_PREFIX_RE = re.compile(r"(?<![\w:])snowflake:(?:(x|twitter|discord|tiktok|linkedin):)?(\d{1,20})(?!\w)", re.I | re.A)
#: cheap pre-check for URL/keyword applicability (the full regexes run in run())
_HINT_RE = re.compile(r"(?:x|twitter|discord(?:app)?|tiktok|linkedin)\.com/|snowflake:", re.I)

MAX_TEXT_CHARS = 5 * 1024 * 1024
MAX_ITEMS = 200
MAX_FINDINGS = 25


def _parse_id(value: Any) -> int | None:
    """Canonical positive decimal id < 2**64 without leading zeros (the core WP05 rule)."""
    if isinstance(value, bool):
        return None
    if isinstance(value, int):
        n = value
    elif isinstance(value, str) and value.isascii() and value.isdigit() and 0 < len(value) <= 20:
        if len(value) > 1 and value[0] == "0":
            return None
        n = int(value)
    else:
        return None
    if n <= 0 or n >= 1 << 64:
        return None
    return n


def _iso_from_ms(ms: int, precision: str) -> tuple[str, datetime]:
    dt = _EPOCH + timedelta(milliseconds=ms)
    base = dt.strftime("%Y-%m-%dT%H:%M:%S")
    return (base + (f".{ms % 1000:03d}" if precision == "ms" else "") + "Z"), dt


def decode_platform_id(platform: str, value: Any, *, now: datetime | None = None) -> dict[str, Any]:
    """c3-c5: decode one platform id -> {'status', 'created', 'epoch', 'rendered', 'precision', ...}.

    status: 'ok' | 'out_of_window' (c4) | 'pre_snowflake' (X ids < ~2.9e13, c3) | 'invalid' | 'unsupported'.
    'created' is UTC ISO ('2022-06-14T12:10:42.437Z' for ms schemes, '2019-07-27T13:32:33Z' for TikTok).
    """
    plat = _PLATFORM_ALIASES.get(str(platform or "").lower())
    out: dict[str, Any] = {"platform": plat or str(platform), "id": str(value), "status": "invalid",
                           "created": None, "epoch": None, "rendered": None, "precision": None}
    if plat is None:
        out["status"] = "unsupported"
        return out
    n = _parse_id(value)
    if n is None:
        return out
    out["epoch"] = PLATFORM_EPOCH_LABEL[plat]
    if plat == "x":
        if n < X_MIN_SNOWFLAKE_ID:
            out["status"] = "pre_snowflake"
            return out
        ms, precision = (n >> 22) + X_EPOCH_MS, "ms"
    elif plat == "discord":
        ms, precision = (n >> 22) + DISCORD_EPOCH_MS, "ms"
    elif plat == "tiktok":
        ms, precision = (n >> 32) * 1000, "s"
    else:  # linkedin: first 41 bits of the binary representation (== id >> 22 for today's 63-bit ids)
        bl = n.bit_length()
        if bl < 41:
            return out
        ms, precision = n >> (bl - 41), "ms"
    iso, dt = _iso_from_ms(ms, precision)
    now = now or datetime.now(UTC)
    if now.tzinfo is None:  # a naive 'now' is taken as UTC
        now = now.replace(tzinfo=UTC)
    out["precision"] = precision
    if not (PLATFORM_LAUNCH[plat] <= dt <= now + timedelta(days=1)):
        out["status"] = "out_of_window"
        out["decoded_unchecked"] = iso  # evidence only; never shown as a fact
        return out
    out.update(status="ok", created=iso, rendered=f"created ~{dt:%Y-%m-%d %H:%M} UTC (decoded from the ID)")
    return out


def find_decodable_ids(text: Any) -> list[dict[str, Any]]:
    """c2: ids taken ONLY from recognised platform URLs or an explicit 'snowflake:' prefix.

    Returns [{'platform', 'component', 'id', 'source': 'url'|'prefix', 'primary', 'secret_in_url',
    'ambiguous_platform'}]. Bare numbers are never returned and Discord webhook tokens never leave this
    function (only the numeric webhook id is kept).
    """
    t = text if isinstance(text, str) else ""
    if not t:
        return []
    found: list[dict[str, Any]] = []
    seen: set[tuple[str, str, str]] = set()

    def add(platform: str, component: str, idv: str | None, source: str, primary: bool, *, secret: bool = False,
            ambiguous: bool = False) -> None:
        if idv is None or _parse_id(idv) is None or len(found) >= MAX_ITEMS:
            return
        key = (platform, component, idv)
        if key in seen:
            return
        seen.add(key)
        found.append({"platform": platform, "component": component, "id": idv, "source": source, "primary": primary,
                      "secret_in_url": secret, "ambiguous_platform": ambiguous})

    for m in _X_URL_RE.finditer(t):
        add("x", "post", m.group(1), "url", True)
    for m in _DISCORD_CHANNEL_RE.finditer(t):
        guild, channel, message = m.group(1), m.group(2), m.group(3)
        if guild != "@me":
            add("discord", "guild", guild, "url", False)
        add("discord", "channel", channel, "url", message is None)
        if message:
            add("discord", "message", message, "url", True)
    for m in _DISCORD_WEBHOOK_RE.finditer(t):
        add("discord", "webhook", m.group(1), "url", True, secret=bool(m.group(2)))
    for m in _TIKTOK_URL_RE.finditer(t):
        add("tiktok", "video", m.group(1), "url", True)
    for m in _LINKEDIN_URL_RE.finditer(t):
        add("linkedin", "activity", m.group(1), "url", True)
    for m in _SNOWFLAKE_PREFIX_RE.finditer(t):
        plat = _PLATFORM_ALIASES.get((m.group(1) or "").lower())
        if plat:
            add(plat, "id", m.group(2), "prefix", True)
        else:  # bare 'snowflake:ID' -> both 64-bit snowflake epochs, labelled ambiguous
            add("x", "id", m.group(2), "prefix", True, ambiguous=True)
            add("discord", "id", m.group(2), "prefix", True, ambiguous=True)
    return found


def decode_items(items: list[dict[str, Any]], *, now: datetime | None = None) -> list[dict[str, Any]]:
    """c3-c5 for every found item (status kept per item)."""
    out = []
    for item in items:
        dec = decode_platform_id(item["platform"], item["id"], now=now)
        merged = dict(item)
        merged.update({k: dec.get(k) for k in ("status", "created", "epoch", "rendered", "precision")})
        if dec.get("decoded_unchecked"):
            merged["decoded_unchecked"] = dec["decoded_unchecked"]
        out.append(merged)
    return out


def _public(item: dict[str, Any]) -> dict[str, Any]:
    """The attribute row of one item (no evidence-only fields)."""
    return {k: item.get(k) for k in ("platform", "component", "id", "status", "created", "epoch", "rendered", "primary", "source",
                                     "ambiguous_platform")}


@register
class IdTimestampDecoders(Module):
    name = "id_timestamp_decoders"
    title = "ID timestamp decoders (X, Discord, TikTok, LinkedIn)"
    description = (
        "Offline creation times decoded from post/guild/channel/message/video/activity ids in X, Discord, TikTok and "
        "LinkedIn URLs or after an explicit 'snowflake:' prefix (bare numbers are never interpreted)."
    )
    category = "utility"
    accepts = {T.URL, T.TEXT, T.KEYWORD, T.SNOWFLAKE_ID, T.TIKTOK_VIDEO_ID}
    produces = frozenset()
    tags = {"offline", "free"}
    reference = "https://discord.com/developers/docs/reference#snowflakes"
    notice = (
        "Decoded times are derived from public id bit layouts (X/Discord snowflakes, TikTok video ids, LinkedIn activity "
        "ids); ids outside the platform's lifetime are discarded, never shown as dates."
    )
    # ---- contract v2 declarations ---------------------------------------------------------
    terms = "open"
    opsec = Opsec.PASSIVE
    disclosure = "none"  # c1: offline, ctx.http refuses every request
    hosts = ()
    access_model = "offline"
    expected_latency = 0.01
    max_pivots = 0
    default_enabled = True

    def applies(self, entity: Entity, ctx: Any) -> bool:
        if entity.type in (T.URL, T.KEYWORD):
            return bool(_HINT_RE.search(entity.value or ""))
        return True

    def _items(self, entity: Entity) -> list[dict[str, Any]]:
        if entity.type is T.SNOWFLAKE_ID:
            return [{"platform": p, "component": "id", "id": entity.value, "source": "type", "primary": True,
                     "secret_in_url": False, "ambiguous_platform": True} for p in ("x", "discord")]
        if entity.type is T.TIKTOK_VIDEO_ID:
            return [{"platform": "tiktok", "component": "video", "id": entity.value, "source": "type", "primary": True,
                     "secret_in_url": False, "ambiguous_platform": False}]
        return find_decodable_ids((entity.value or "")[:MAX_TEXT_CHARS])

    def run(self, entity: Entity, ctx: Any) -> ModuleResult:
        res = self.result(entity)
        items = decode_items(self._items(entity), now=ctx.now())
        if not items:
            res.error = "no recognised platform URL or 'snowflake:' prefix: bare numbers are never interpreted (P314 c2)"
            return res.mark("empty")
        res.attr("id_timestamps", [_public(i) for i in items])
        ok = [i for i in items if i["status"] == "ok"]
        # 'created' only where the run entity IS the object (a platform URL or a typed id) and the reading is unambiguous
        primary = [i for i in ok if i["primary"] and not i["ambiguous_platform"]]
        if entity.type is not T.TEXT and entity.type is not T.KEYWORD and len(primary) == 1:
            res.attr("created", primary[0]["created"])
            res.attr("created_epoch", primary[0]["epoch"])
        for item in ok[:MAX_FINDINGS]:
            plat = PLATFORM_TITLE.get(item["platform"], item["platform"])
            ambiguous = bool(item["ambiguous_platform"])
            res.finding(
                "Creation time decoded from the ID" + (" (platform ambiguous)" if ambiguous else ""),
                "info",
                f"{item['rendered']}: {plat} {item['component']} {item['id']}"
                + (" - read with the " + plat + " epoch; the same id under the other snowflake epoch gives another date "
                   "(use snowflake:discord:<id> or snowflake:x:<id>)" if ambiguous else "")
                + f". Method: {item['epoch']}.",
                confidence="possible" if ambiguous else "confirmed",
                data={"platform": item["platform"], "component": item["component"], "id": item["id"], "created": item["created"],
                      "epoch": item["epoch"], "precision": item["precision"], "ambiguous_platform": ambiguous},
                tags=["info"],
                key=f"{item['platform']}:{item['component']}:{item['id']}",
            )
        not_decoded = [i for i in items if i["status"] != "ok"]
        if not_decoded:
            res.finding(
                "ID not decoded",
                "info",
                "; ".join(f"{PLATFORM_TITLE.get(i['platform'], i['platform'])} {i['component']} {i['id']}: "
                          f"{STATUS_TEXT.get(i['status'], i['status'])}" for i in not_decoded[:MAX_FINDINGS]),
                confidence="confirmed",
                data={"items": [{"platform": i["platform"], "component": i["component"], "id": i["id"], "status": i["status"]}
                                for i in not_decoded[:MAX_ITEMS]]},
                tags=["info"],
            )
        res.raw = {"items": [{**_public(i), "decoded_unchecked": i.get("decoded_unchecked"),
                              "secret_in_url": bool(i.get("secret_in_url"))} for i in items]}
        if any(i.get("secret_in_url") for i in items):
            res.raw["note"] = "Discord webhook token present in the input: never copied (only the webhook id is decoded)"
        return res
