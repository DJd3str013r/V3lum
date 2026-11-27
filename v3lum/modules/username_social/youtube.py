"""YouTube channel resolution (P110): Data API v3 forHandle with the team key; keyless channel RSS and oEmbed.

* Handle -> channel id only through the YouTube Data API v3 ``channels.list`` with ``forHandle=@<handle>`` and the
  team's key (1 quota unit; cond 1). ``part=snippet,statistics``: the id is always returned and the statistics
  part carries the counts cond 4 asks for at the same 1-unit cost. The keyless ``youtube.com/@handle`` page
  scrape is NOT built (YouTube's terms bar automated access other than by public search engines, legal floor).
  The API is called on its dedicated service host ``youtube.googleapis.com`` (the discovery rootUrl).
* Keyless published interfaces (cond 2): the channel feed ``www.youtube.com/feeds/videos.xml?channel_id=<id>``
  for known channel ids (parsed with DTD/entity declarations refused and a 2 MB cap) and oEmbed
  (``www.youtube.com/oembed?url=<watch URL>``) for video URLs. Channel ids are validated with
  ``^UC[0-9A-Za-z_-]{22}$``; the feed-level ``yt:channelId`` lacks the 'UC' prefix (observed) so the id is taken
  from the alternate link.
* One key ``youtube`` (cond 3): ``V3LUM_KEY_YOUTUBE``, with ``V3LUM_YOUTUBE_KEY`` and ``V3LUM_YOUTUBE_API_KEY`` as
  aliases only (provider fragment); sent in the query string, masked by the central redactor (AR01, in place).
  Quota units are booked through the provider quota block (10,000 units/day, P334). 403 'Permission denied' /
  forbidden / invalid key = NEEDS_KEY; quotaExceeded = QUOTA; rate-limit reasons = RATE_LIMITED. The Data API
  source is 'key-terms': under the corporate profile it runs only once ``key_plans.youtube = 'business'`` is
  recorded (``ctx.allowed_sources``), else the handle is SKIPPED ``licence``.
* Consent redirects (consent.youtube.com), consent interstitials and Google 'unusual traffic'/CAPTCHA pages are
  BLOCKED ``challenge`` via P321 markers and the redirect check, never empty (cond 4). Channel creation date,
  country and counts become attributes; the feed gives the creation date without a key.
* Storage (cond 5): Data API answers are cached at most 7 days (<= 30 days, refresh or delete) and the evidence is
  redacted (ids, dates and counts only: no descriptions, thumbnails or tags); legal confirms the policy reading.
* personal_data_review comes before default use for handle inputs (cond 6, A3 BR8).
"""

from __future__ import annotations

import re
from typing import Any
from urllib.parse import parse_qs, urlencode, urlsplit

from v3lum.core.entities import Entity
from v3lum.core.entities import EntityType as T
from v3lum.core.http import Blocked
from v3lum.core.models import ModuleResult, Opsec, Status
from v3lum.core.module import HealthCheck, Module, register
from v3lum.modules.username_social.p3g051_common import (
    Problems,
    attempt,
    excerpt,
    host_of,
    iso,
    json_body,
    report_problems,
    safe_url,
    safe_xml_root,
    to_bool,
    to_int,
    to_str,
)

SOURCE_API = "youtube.data_api"
SOURCE_RSS = "youtube.rss"
SOURCE_OEMBED = "youtube.oembed"
KEY = "youtube"
API = "https://youtube.googleapis.com/youtube/v3/channels"
RSS = "https://www.youtube.com/feeds/videos.xml"
OEMBED = "https://www.youtube.com/oembed"
API_TTL = 7 * 86400  # cond 5: <= 30 days
RSS_TTL = 900  # the feed's own Cache-Control max-age
MAX_ENTRIES = 15
_CHANNEL_RE = re.compile(r"^UC[0-9A-Za-z_-]{22}$")
_VIDEO_RE = re.compile(r"^[0-9A-Za-z_-]{11}$")
_HANDLE_RE = re.compile(r"^[A-Za-z0-9._-]{3,30}$")
_YT_HOSTS = ("youtube.com", "www.youtube.com", "m.youtube.com", "music.youtube.com")
_CONSENT_HOSTS = ("consent.youtube.com", "consent.google.com")
_NS_ATOM = "{http://www.w3.org/2005/Atom}"
_NS_YT = "{http://www.youtube.com/xml/schemas/2015}"
_NS_MEDIA = "{http://search.yahoo.com/mrss/}"
_KEY_REASONS = frozenset({"keyInvalid", "API_KEY_INVALID", "keyExpired", "API_KEY_SERVICE_BLOCKED", "forbidden", "accessNotConfigured",
                          "SERVICE_DISABLED", "ACCESS_DENIED", "ipRefererBlocked", "API_KEY_HTTP_REFERRER_BLOCKED"})


def channel_id_ok(value: Any) -> bool:
    """cond 2: ^UC[0-9A-Za-z_-]{22}$."""
    return isinstance(value, str) and bool(_CHANNEL_RE.match(value))


def classify_input(entity: Entity) -> dict[str, Any]:
    """{'kind': handle|channel|video|invalid, 'handle'|'channel_id'|'video_id'}."""
    v = entity.value.strip()
    if entity.type is T.USERNAME:
        h = v.lstrip("@")
        return {"kind": "handle", "handle": h.lower()} if _HANDLE_RE.match(h) else {"kind": "invalid"}
    if entity.type is T.KEYWORD:
        return {"kind": "channel", "channel_id": v} if channel_id_ok(v) else {"kind": "invalid"}
    if entity.type is T.SOCIAL_ACCOUNT:
        platform, _, handle = v.partition(":")
        return {"kind": "handle", "handle": handle} if platform == "youtube" and _HANDLE_RE.match(handle) else {"kind": "invalid"}
    url = safe_url(v)
    if not url:
        return {"kind": "invalid"}
    parts = urlsplit(url)
    host = (parts.hostname or "").lower()
    segs = [s for s in parts.path.split("/") if s]
    if host == "youtu.be" and segs and _VIDEO_RE.match(segs[0]):
        return {"kind": "video", "video_id": segs[0]}
    if host not in _YT_HOSTS:
        return {"kind": "invalid"}
    if segs[:1] == ["watch"]:
        vid = (parse_qs(parts.query).get("v") or [""])[0]
        return {"kind": "video", "video_id": vid} if _VIDEO_RE.match(vid) else {"kind": "invalid"}
    if len(segs) >= 2 and segs[0] in ("shorts", "embed", "live", "v") and _VIDEO_RE.match(segs[1]):
        return {"kind": "video", "video_id": segs[1]}
    if len(segs) >= 2 and segs[0] == "channel" and channel_id_ok(segs[1]):
        return {"kind": "channel", "channel_id": segs[1]}
    if segs and segs[0].startswith("@") and _HANDLE_RE.match(segs[0][1:]):
        return {"kind": "handle", "handle": segs[0][1:].lower()}
    return {"kind": "invalid"}


def api_params(*, handle: str | None = None, channel_id: str | None = None) -> dict[str, str]:
    """cond 1: channels.list forHandle=@<handle> (or id=<UC...>), part=snippet,statistics; the key is added by run()."""
    params = {"part": "snippet,statistics"}
    if handle:
        params["forHandle"] = "@" + handle
    if channel_id:
        params["id"] = channel_id
    return params


def rss_url(channel_id: str) -> str:
    return RSS + "?" + urlencode({"channel_id": channel_id})


def oembed_url(video_id: str) -> str:
    """cond 2: video URLs only, re-sent as the canonical watch URL."""
    return OEMBED + "?" + urlencode({"url": "https://www.youtube.com/watch?v=" + video_id, "format": "json"})


def api_error_reasons(data: Any) -> tuple[list[str], str]:
    if not isinstance(data, dict) or not isinstance(data.get("error"), dict):
        return [], ""
    err = data["error"]
    reasons = [str(x.get("reason")) for x in err.get("errors") or [] if isinstance(x, dict) and x.get("reason")]
    reasons += [str(d.get("reason")) for d in err.get("details") or [] if isinstance(d, dict) and d.get("reason")]
    if err.get("status"):
        reasons.append(str(err["status"]))
    return reasons, str(err.get("message") or "")[:200]


def parse_channels(data: Any) -> list[dict[str, Any]] | None:
    """channels.list -> channel facts (cond 4); None when the answer is not a channel list."""
    if not isinstance(data, dict) or data.get("kind") not in (None, "youtube#channelListResponse"):
        return None
    out = []
    for it in (data.get("items") if isinstance(data.get("items"), list) else [])[:5]:
        if not isinstance(it, dict) or not channel_id_ok(it.get("id")):
            continue
        sn = it.get("snippet") if isinstance(it.get("snippet"), dict) else {}
        st = it.get("statistics") if isinstance(it.get("statistics"), dict) else {}
        hidden = to_bool(st.get("hiddenSubscriberCount"))
        country = to_str(sn.get("country"), 4)
        custom = to_str(sn.get("customUrl"), 40)
        out.append({
            "channel_id": it["id"], "title": to_str(sn.get("title"), 200),
            "handle": custom.lstrip("@").lower() if custom and _HANDLE_RE.match(custom.lstrip("@")) else None,
            "url": "https://www.youtube.com/channel/" + it["id"], "created": iso(sn.get("publishedAt")),
            "country": country.upper() if country and re.fullmatch(r"[A-Za-z]{2}", country) else None,
            "view_count": to_int(st.get("viewCount")), "subscriber_count": None if hidden else to_int(st.get("subscriberCount")),
            "subscriber_count_hidden": hidden, "video_count": to_int(st.get("videoCount")), "source": "Data API v3",
        })
    return out


def parse_rss(raw: Any) -> tuple[dict[str, Any] | None, str]:
    """Channel feed -> {channel_id, title, channel_url, created, entries, uploads_in_feed, last_upload} or (None, why)."""
    root, why = safe_xml_root(raw)
    if root is None:
        return None, why or "unreadable XML"
    if root.tag != _NS_ATOM + "feed":
        return None, "not an Atom feed"
    alt = None
    for ln in root.findall(_NS_ATOM + "link"):
        if ln.get("rel") == "alternate":
            alt = safe_url(ln.get("href"))
    cid = None
    if alt:
        m = re.search(r"/channel/(UC[0-9A-Za-z_-]{22})$", alt)
        cid = m.group(1) if m else None
    raw_cid = (root.findtext(_NS_YT + "channelId") or "").strip()
    if not cid and raw_cid:
        cand = raw_cid if raw_cid.startswith("UC") else "UC" + raw_cid  # the feed-level id lacks 'UC' (observed)
        cid = cand if channel_id_ok(cand) else None
    entries = []
    for ent in root.findall(_NS_ATOM + "entry")[:MAX_ENTRIES]:
        vid = (ent.findtext(_NS_YT + "videoId") or "").strip()
        if not _VIDEO_RE.match(vid):
            continue
        stats = ent.find(f"{_NS_MEDIA}group/{_NS_MEDIA}community/{_NS_MEDIA}statistics")
        entries.append({"video_id": vid, "title": excerpt(ent.findtext(_NS_ATOM + "title") or "", 200),
                        "published": iso(ent.findtext(_NS_ATOM + "published")),
                        "views": to_int(stats.get("views")) if stats is not None else None})
    published = [e["published"] for e in entries if e["published"]]
    return {"channel_id": cid, "title": excerpt(root.findtext(_NS_ATOM + "title") or "", 200),
            "channel_url": f"https://www.youtube.com/channel/{cid}" if cid else alt, "created": iso(root.findtext(_NS_ATOM + "published")),
            "entries": entries, "uploads_in_feed": len(entries), "last_upload": max(published) if published else None}, ""


def parse_oembed(data: Any) -> dict[str, Any] | None:
    if not isinstance(data, dict) or not to_str(data.get("title"), 200) and not safe_url(data.get("author_url")):
        return None
    author_url = safe_url(data.get("author_url"))
    handle = None
    if author_url:
        m = re.match(r"^https://(?:www\.)?youtube\.com/@([A-Za-z0-9._-]{3,30})/?$", author_url)
        handle = m.group(1).lower() if m else None
    return {"title": to_str(data.get("title"), 200), "author_name": to_str(data.get("author_name"), 200), "author_url": author_url,
            "handle": handle}


@register
class YouTube(Module):
    name = "youtube"
    title = "YouTube channel resolution (Data API forHandle, channel RSS, oEmbed)"
    description = (
        "YouTube channel facts: handle -> channel id through the Data API v3 (team key), the channel's public feed (creation date, "
        "latest uploads) for known channel ids, and oEmbed for video URLs (keyless). No youtube.com page scraping."
    )
    category = "username_social"
    accepts = frozenset({T.USERNAME, T.URL, T.KEYWORD, T.SOCIAL_ACCOUNT})
    produces = frozenset({T.URL, T.SOCIAL_ACCOUNT})
    run_on = "any"  # video and channel URLs found by other modules are useful; handles run only on seeds (applies)
    terms = "key-terms"  # Data API key-terms; RSS and oEmbed open (cond 6)
    opsec = Opsec.PASSIVE
    disclosure = "third_party"
    provider = "youtube"
    sources = (SOURCE_API, SOURCE_RSS, SOURCE_OEMBED)
    hosts = ("youtube.googleapis.com", "www.youtube.com")
    access_model = "free_auth_limited"
    optional_keys = (KEY,)
    max_requests = 3  # Data API + feed, or oEmbed
    expected_latency = 0.8
    timeout = 20.0
    min_interval = 1.0
    cache_ttl = API_TTL
    max_pivots = 20
    default_enabled = True
    reference = "https://developers.google.com/youtube/v3/docs/channels/list"
    tags = frozenset({"free"})
    error_markers = (
        {"id": "youtube_consent_or_challenge", "statuses": [200, 403, 429],
         "regex": r"(?i)consent\.(?:youtube|google)\.com/|before you continue to youtube|www\.google\.com/sorry/|unusual traffic from your computer network|g-recaptcha",
         "maps_to": "blocked", "reason_code": "challenge",
         "reason": "YouTube: consent interstitial or Google 'unusual traffic' challenge instead of data (could not verify)"},
        {"id": "youtube_quota_exceeded", "statuses": [403], "regex": r"\"reason\"\s*:\s*\"(?:quotaExceeded|dailyLimitExceeded)\"",
         "maps_to": "quota", "reason_code": "quota", "reason": "YouTube Data API: daily quota exceeded (10,000 units/day)"},
        {"id": "youtube_rate_limited", "statuses": [403, 429], "regex": r"\"reason\"\s*:\s*\"(?:rateLimitExceeded|userRateLimitExceeded)\"",
         "maps_to": "rate_limited", "reason_code": "rate_limited", "reason": "YouTube Data API: rate limit exceeded"},
    )
    notice = (
        "Handle -> channel id only through the Data API v3 with the team key (key-terms: needs key_plans.youtube = 'business' under "
        "the corporate profile); the keyless youtube.com/@handle page scrape is not built (YouTube terms). Data API facts are cached "
        "at most 7 days (YouTube API Services storage policy). personal_data_review comes before default use for handle inputs."
    )

    @classmethod
    def health_check(cls) -> HealthCheck | None:
        return HealthCheck(T.USERNAME, "octocat", expect="ok")

    def applies(self, entity: Entity, ctx: Any) -> bool:
        info = classify_input(entity)
        if info["kind"] == "invalid":
            return False
        # handles (personal data, quota units) only for analyst-typed seeds
        return not (info["kind"] == "handle" and entity.type is not T.URL and not getattr(ctx, "is_seed", True))

    def run(self, entity: Entity, ctx: Any) -> ModuleResult:
        res = self.result(entity)
        info = classify_input(entity)
        if info["kind"] == "video":
            return self._video(res, ctx, info["video_id"])
        if info["kind"] == "channel":
            return self._channel(res, ctx, info["channel_id"])
        if info["kind"] == "handle":
            return self._handle(res, ctx, info["handle"])
        return res.mark("skipped", "not a YouTube handle, channel id, channel URL or video URL", reason_code="not_applicable")

    # ------------------------------------------------------------------------------------------ Data API
    def _api_ready(self, res: ModuleResult, ctx: Any) -> str | None:
        """The key when the Data API may run; otherwise marks the result and returns None."""
        allowed = getattr(ctx, "allowed_sources", None)
        if allowed is not None and SOURCE_API not in allowed:
            res.mark("skipped", "YouTube Data API is 'key-terms': record key_plans.youtube = 'business' (v3lum keys set youtube --plan business) "
                                "to use it under the corporate licence profile", reason_code="licence")
            return None
        key = str(ctx.key(KEY) or "").strip()
        if not key:
            res.mark("needs_key", "resolving a YouTube handle needs the Data API key 'youtube' (V3LUM_KEY_YOUTUBE); the keyless "
                                  "handle-page scrape is not built (YouTube terms)", reason_code="needs_key")
            return None
        return key

    def _call_api(self, ctx: Any, key: str, **kw: str) -> tuple[str, Any]:
        """('ok', channels) | ('needs_key', why); quota/rate markers, 5xx and challenges raise (could not verify)."""
        resp = ctx.http.get(API, params={**api_params(**kw), "key": key}, source=SOURCE_API, ttl=API_TTL, allow_redirects=False)
        if resp.status in (400, 401, 403) and resp.classification is None:
            data, _why = json_body(resp.content)
            reasons, message = api_error_reasons(data)
            if any(r in _KEY_REASONS for r in reasons) or resp.status in (401, 403) or "API key" in message:
                return "needs_key", f"YouTube Data API refused the key ({', '.join(reasons[:3]) or resp.status}): {message[:120]}"
        ctx.http.check(resp)
        data, why = json_body(resp.content)
        reasons, message = api_error_reasons(data)
        if reasons:
            raise ValueError(f"YouTube Data API error {', '.join(reasons[:3])}: {message[:120]}")
        channels = parse_channels(data) if not why else None
        if channels is None:
            raise ValueError(f"unexpected YouTube Data API answer ({why or 'not a channel list'})")
        return "ok", channels

    def _handle(self, res: ModuleResult, ctx: Any, handle: str) -> ModuleResult:
        key = self._api_ready(res, ctx)
        if key is None:
            return res
        try:
            state, payload = self._call_api(ctx, key, handle=handle)
        except ValueError as exc:
            return res.mark("error", f"{exc}: could not verify")
        if state == "needs_key":
            return res.mark("needs_key", payload, reason_code="needs_key")
        if not payload:
            res.presence("absent", marker="channels.list forHandle returned no items", url=f"https://www.youtube.com/@{handle}",
                         checked_at=ctx.now(), source=SOURCE_API)
            res.error = f"no YouTube channel with the handle @{handle}"
            return res.mark("empty")
        channel = payload[0]
        problems: Problems = {}
        feed = self._feed(ctx, channel["channel_id"], problems)
        report_problems(res, problems)
        self._emit_channel(res, ctx, channel, feed, handle=handle)
        return res

    # ------------------------------------------------------------------------------------------ keyless interfaces
    def _get_youtube(self, ctx: Any, url: str, source: str, ttl: int) -> Any:
        """GET on www.youtube.com without following redirects: a consent redirect is BLOCKED (cond 4)."""
        resp = ctx.http.get(url, source=source, ttl=ttl, allow_redirects=False)
        if 300 <= resp.status < 400:
            location = (resp.headers or {}).get("location", "")
            lhost = host_of(location) or ""
            if lhost in _CONSENT_HOSTS or "/sorry/" in location:
                raise Blocked(f"YouTube: redirect to {lhost or 'a challenge page'} (consent interstitial or challenge): could not verify",
                              resp.status, resp.url, reason_code="challenge")
            raise ValueError(f"unexpected redirect to {lhost or '?'}")
        return resp

    def _feed(self, ctx: Any, channel_id: str, problems: Problems) -> dict[str, Any] | None:
        def fetch() -> dict[str, Any] | None:
            resp = self._get_youtube(ctx, rss_url(channel_id), SOURCE_RSS, RSS_TTL)
            if resp.status == 404 and resp.classification is None:
                return {"missing": True}
            ctx.http.check(resp)
            feed, why = parse_rss(resp.content)
            if feed is None:
                raise ValueError(why)
            return feed
        return attempt(problems, SOURCE_RSS, "channel feed", fetch)

    def _channel(self, res: ModuleResult, ctx: Any, channel_id: str) -> ModuleResult:
        problems: Problems = {}
        channel = None
        allowed = getattr(ctx, "allowed_sources", None)
        key = str(ctx.key(KEY) or "").strip()
        if key and (allowed is None or SOURCE_API in allowed):
            got = attempt(problems, SOURCE_API, "Data API", lambda: self._call_api(ctx, key, channel_id=channel_id))
            if got and got[0] == "ok" and got[1]:
                channel = got[1][0]
            elif got and got[0] == "needs_key":
                problems.setdefault(SOURCE_API, []).append((Status.NEEDS_KEY, "needs_key", got[1]))
        resp = self._get_youtube(ctx, rss_url(channel_id), SOURCE_RSS, RSS_TTL)
        feed: dict[str, Any] | None = None
        if resp.status == 404 and resp.classification is None:
            feed = None
        else:
            ctx.http.check(resp)
            feed, why = parse_rss(resp.content)
            if feed is None:
                return res.mark("error", f"unexpected YouTube feed ({why}): could not verify")
        report_problems(res, problems)
        if channel is None and feed is None:
            res.error = f"no public feed for channel {channel_id} (unknown id, or a channel without public uploads)"
            return res.mark("empty")
        if channel is None:
            channel = {"channel_id": feed.get("channel_id") or channel_id, "title": feed["title"], "handle": None,
                       "url": f"https://www.youtube.com/channel/{channel_id}", "created": feed["created"], "country": None,
                       "view_count": None, "subscriber_count": None, "subscriber_count_hidden": None, "video_count": None,
                       "source": "channel feed (keyless)"}
        self._emit_channel(res, ctx, channel, feed)
        return res

    def _video(self, res: ModuleResult, ctx: Any, video_id: str) -> ModuleResult:
        resp = self._get_youtube(ctx, oembed_url(video_id), SOURCE_OEMBED, 86400)
        if resp.status in (400, 404) and resp.classification is None:
            res.error = f"YouTube oEmbed: video {video_id} not found or invalid id (HTTP {resp.status})"
            return res.mark("empty")
        if resp.status == 401 and resp.classification is None:
            res.error = f"YouTube oEmbed: video {video_id} is private (HTTP 401)"
            return res.mark("empty")
        ctx.http.check(resp)
        data, why = json_body(resp.content)
        video = parse_oembed(data) if not why else None
        if video is None:
            return res.mark("error", f"unexpected YouTube oEmbed answer ({why or 'no title or author'}): could not verify")
        res.raw = {"video_id": video_id, "author_url": video["author_url"]}
        res.attr("youtube_video", {"video_id": video_id, **video})
        if video["author_url"]:
            res.pivot(T.URL, video["author_url"], "post_author", confidence="probable", expand=False,
                      note="channel of the video as embedded by YouTube oEmbed")
        if video["handle"]:
            res.pivot(T.SOCIAL_ACCOUNT, f"youtube:{video['handle']}", "post_author", confidence="probable", expand=False,
                      note="YouTube handle of the video's channel (oEmbed)")
        res.finding(
            "YouTube video",
            "info",
            f"Video {video_id} '{video['title'] or '?'}' by {video['author_name'] or '?'}" + (f" ({video['author_url']})" if video["author_url"] else ""),
            confidence="confirmed",
            criterion="YouTube oEmbed answered for the canonical watch URL",
            data={"video_id": video_id},
            tags=["account"],
            references=[f"https://www.youtube.com/watch?v={video_id}"],
            source=SOURCE_OEMBED,
        )
        return res

    # ------------------------------------------------------------------------------------------ results
    def _emit_channel(self, res: ModuleResult, ctx: Any, channel: dict[str, Any], feed: dict[str, Any] | None, *, handle: str | None = None) -> None:
        cid = channel["channel_id"]
        created = channel["created"] or (feed or {}).get("created")
        res.raw = {"channel_id": cid, "source": channel["source"], "created": created, "counts": {k: channel[k] for k in ("view_count", "subscriber_count", "video_count")}}
        res.attr("youtube_channel", {**channel, "created": created})
        res.attr("created", created)
        res.attr("country", channel["country"])
        res.attr("profile_url", channel["url"])
        res.attr("data_notices", ["YouTube API Services: Data API facts are refreshed or deleted within 30 days (cached at most 7 days)"]
                 if channel["source"] == "Data API v3" else None)
        uploads = None
        if feed and not feed.get("missing"):
            uploads = {"channel_id": cid, "uploads_in_feed": feed["uploads_in_feed"], "last_upload": feed["last_upload"], "entries": feed["entries"]}
            res.attr("youtube_uploads", uploads)
            res.attr("last_activity", feed["last_upload"])
        res.presence("found", marker="channels.list returned the channel" if channel["source"] == "Data API v3" else "the channel feed answered",
                     url=channel["url"], checked_at=ctx.now(), source=SOURCE_API if channel["source"] == "Data API v3" else SOURCE_RSS)
        res.pivot(T.URL, channel["url"], "has_account", confidence="confirmed", expand=False, note="YouTube channel page")
        h = channel["handle"] or handle
        if h:
            res.pivot(T.SOCIAL_ACCOUNT, f"youtube:{h}", "has_account", confidence="confirmed", expand=False, note="YouTube handle of the channel")
            res.pivot(T.URL, f"https://www.youtube.com/@{h}", "has_account", confidence="confirmed", expand=False, note="YouTube handle page")
        counts = ", ".join(f"{label} {channel[k]}" for k, label in (("subscriber_count", "subscribers"), ("video_count", "videos"), ("view_count", "views"))
                           if channel.get(k) is not None)
        res.finding(
            "YouTube channel",
            "info",
            f"YouTube channel {cid} '{channel['title'] or '?'}'" + (f" (@{h})" if h else "")
            + (f", created {created[:10]}" if created else "") + (f", country {channel['country']}" if channel["country"] else "")
            + (f"; {counts}" if counts else "")
            + (f"; {uploads['uploads_in_feed']} recent uploads in the feed, last {uploads['last_upload'][:10]}" if uploads and uploads["last_upload"] else "")
            + ".",
            confidence="confirmed",
            criterion=("YouTube Data API channels.list returned the channel" if channel["source"] == "Data API v3"
                       else "the channel's public feed answered for this channel id"),
            data={"channel_id": cid, "created": created},
            tags=["account"],
            references=[channel["url"]],
            source=SOURCE_API if channel["source"] == "Data API v3" else SOURCE_RSS,
            observed_first=created,
        )
