"""Short-link expansion (P070, batch p9-G03-1): ``unshorten_preview`` (PASSIVE, default),
``unshorten_me`` (third-party API, opt-in) and ``unshorten_trace`` (LIGHT, opt-in).

Final conditions (P070) and where they live:

1. Split by opsec. ``unshorten_preview`` (PASSIVE, default): documented no-click preview pages
   (TinyURL ``preview.tinyurl.com/<alias>``, the Bitly ``+`` info page), only for shortener providers
   that offer one and whose registry tier is trusted or community with recorded terms. Today no
   preview provider qualifies: Bitly's Terms of Service (updated November 2026) forbid access "via
   automated or unauthorized means ... including via robots, spiders" and screen-scraping (A9: terms
   that forbid robots are respected), and TinyURL's terms page carries no readable text (A1: terms
   unrecorded never run). The module therefore makes no request (``disclosure='none'``): it gives the
   preview page as a manual link (A9) and records the shortener; the preview parsers
   (:func:`parse_tinyurl_preview`, :func:`parse_bitly_info`; a challenge or login page gives BLOCKED)
   are ready for when legal records the terms (backlog p9-G03-1). Other shorteners on the bundled
   list are left to unshorten_trace.
2. ``unshorten_me`` (default_enabled=False): the unshorten.me JSON API, tier unknown (excluded at
   AMBER and above by the policy gate), 10 new lookups/hour per IP as a P334 provider quota; its
   service fetches the short link (provider flag ``fetches_target``) and stores submitted URLs
   (``reuses_queries``). Per-recipient token URLs are never sent.
3. ``unshorten_trace`` (LIGHT, default_enabled=False): analyst-typed seeds only (``run_on='seeds'``
   and the core LIGHT seed binding), never confidential client URLs (token URLs need --confirm-url).
   A direct HEAD/GET of a short link is a click visible to the link creator's analytics.
4. The tracer goes through ``ctx.http`` only: the core redirect loop checks every hop before it is
   sent (SSRF guard after resolution through the egress profile: private, loopback, link-local,
   CGNAT, metadata addresses refused; https->http downgrades refused; at most 5 hops - the core cap,
   stricter than the 10 the spec allows), and this module's hop check (:func:`plan_hop`) runs first
   on every redirect target: http/https, ports 80/443 unless the seed names one, token URLs, IP
   loggers, non-shortener destinations. 256 KB body cap, no cookies (core), no JS (hints only), HEAD
   then GET. Every hop is recorded (``unshorten_chain``) and written to the core request ledger.
5. By default only hosts on the bundled shortener/redirector list are contacted: the first
   non-shortener destination is recorded uncontacted (``Location`` read only) unless setting
   ``unshorten_trace_follow_final`` (the --follow-final switch) is on; then that hop goes through the
   core hostile-host guard on redirect targets (P376: hostile hosts only via a non-corporate egress,
   fail closed).
6. URLs with a probable per-recipient token (an org-profile e-mail in plain, URL-encoded or base64
   form, any e-mail, opaque tokens of >= 16 characters: the core GUARD-02 rule
   ``policy.recipient_token``) are never contacted automatically and need a per-URL confirmation
   (--confirm-url, A7 BR15) - the seed and every redirect target.
7. The bundled shortener list (``v3lum/data/unshorten/shorteners.json``: MISP warninglists
   url-shortener, CC0, plus V3LUM additions for BR smishing - encurtador.com.br, encurta.net,
   migre.me... - and IP loggers flagged never_contact). Hop URLs are masked (e-mails, tokens) before
   evidence (:func:`mask_hop_url`).
8. The final URL becomes a ``redirects_to`` url pivot for the passive reputation modules (only its
   domain when it carries a token or an e-mail). Tests: redirects to 127.0.0.1 and to an RFC 1918
   address are refused, a token URL is not contacted, the unshorten.me fixture parses.
"""

from __future__ import annotations

import base64
import re
from collections.abc import Mapping
from typing import Any
from urllib.parse import unquote, urljoin, urlsplit, urlunsplit

from v3lum.config import SettingSpec
from v3lum.core.datasets import DataStore
from v3lum.core.entities import Entity
from v3lum.core.entities import EntityType as T
from v3lum.core.http import HttpError, NetworkError, PolicyError, RequestCapReached, host_problem, normalize_host
from v3lum.core.models import ModuleResult, Opsec, Status, status_for
from v3lum.core.module import HealthCheck, HealthResult, Module, register
from v3lum.modules.url_web.light_fetch import (
    attrs,
    confirmed_url,
    detect_block,
    header_first,
    load_json_text,
    looks_like_html,
    same_site,
    to_text,
)

__all__ = [
    "SHORTENERS_FILE",
    "UnshortenMe",
    "UnshortenPreview",
    "UnshortenTrace",
    "load_shorteners",
    "mask_hop_url",
    "parse_bitly_info",
    "parse_meta_refresh",
    "parse_tinyurl_preview",
    "parse_unshorten_me",
    "plan_hop",
    "preview_plan",
    "recipient_token_reason",
    "shortener_info",
    "unshorten_me_url",
]

SHORTENERS_FILE = "unshorten/shorteners.json"
MAX_TRACE_BODY = 256 * 1024  # P070 c4
SRC_UNSHORTEN_ME = "unshorten_me.json_api"

# ======================================================================================
# the bundled shortener list (c7)
# ======================================================================================

_SHORTENERS: dict[str, dict[str, Any]] = {}


def load_shorteners(data: Any = None) -> dict[str, dict[str, Any]]:
    """Index of the bundled shortener/redirector list by host (``data`` overrides the bundled file)."""
    if data is None and _SHORTENERS:
        return _SHORTENERS
    raw = data
    if raw is None:
        try:
            raw = DataStore.bundled_json(SHORTENERS_FILE)
        except (OSError, ValueError):
            raw = {}
    out: dict[str, dict[str, Any]] = {}
    hosts = raw.get("hosts") if isinstance(raw, Mapping) else None
    for entry in hosts if isinstance(hosts, list) else []:
        if isinstance(entry, Mapping) and isinstance(entry.get("host"), str):
            out[normalize_host(entry["host"])] = dict(entry)
    if data is None and out:
        _SHORTENERS.update(out)
    return out


def shortener_info(url_or_host: str, shorteners: Mapping[str, Mapping[str, Any]] | None = None) -> dict[str, Any] | None:
    """The list entry of a URL's host (``www.`` ignored), or None."""
    table = shorteners if shorteners is not None else load_shorteners()
    text = str(url_or_host or "")
    try:
        host = normalize_host(urlsplit(text).hostname if "://" in text else text.split("/", 1)[0])
    except ValueError:
        return None
    entry = table.get(host) or (table.get(host[4:]) if host.startswith("www.") else None)
    return dict(entry) if entry else None


# ======================================================================================
# recipient tokens and masking (c6, c7)
# ======================================================================================

_EMAIL_RE = re.compile(r"[A-Za-z0-9._%+\-]{1,64}@[A-Za-z0-9.\-]{1,253}\.[A-Za-z]{2,24}")


def _token_like(value: str) -> bool:
    v = unquote(value)
    if len(v) < 16 or not re.fullmatch(r"[A-Za-z0-9_\-=.+/]{16,}", v):
        return False
    if re.fullmatch(r"[0-9a-fA-F]{16,}", v) or re.fullmatch(r"[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}", v):
        return True
    words = [w for w in re.split(r"[-_.]", v) if w]
    if words and all(w.isalpha() for w in words):
        return False  # slug-like 'running-shoes-for-women'
    return any(c.isdigit() for c in v) and any(c.isalpha() for c in v)


def _b64_forms(email: str) -> set[str]:
    raw = email.encode()
    forms: set[str] = set()
    for enc in (base64.b64encode, base64.urlsafe_b64encode):
        s = enc(raw).decode()
        forms.update({s, s.rstrip("=")})
    return forms


def _b64_email(value: str) -> bool:
    """Is ``value`` (a path segment or query value) an e-mail address in base64 (std or urlsafe, padded or not)?"""
    v = unquote(value).strip()
    if len(v) < 8 or not re.fullmatch(r"[A-Za-z0-9+/_\-]+={0,2}", v):
        return False
    try:
        text = base64.urlsafe_b64decode((v.replace("+", "-").replace("/", "_").rstrip("=") + "=" * (-len(v.rstrip("=")) % 4)).encode())
        return bool(_EMAIL_RE.search(text.decode("utf-8", "strict")))
    except (ValueError, UnicodeDecodeError):
        return False


def recipient_token_reason(url: str, ctx: Any = None) -> str | None:
    """c6: why a URL probably carries a per-recipient token (core GUARD-02 rule first), else None."""
    try:
        from v3lum.core.policy import recipient_token

        if recipient_token(url, getattr(ctx, "org", None) if ctx is not None else None):
            return "per-recipient token or e-mail address in the URL"
    except Exception:  # noqa: BLE001 - an unreadable URL is treated as a token URL (fail closed)
        return "unreadable URL (treated as a token URL)"
    return None


def mask_hop_url(url: str, org_emails: tuple[str, ...] | list[str] = ()) -> str:
    """c7: a hop URL for evidence and attributes, e-mails (plain, URL-encoded, base64) and opaque
    tokens replaced by placeholders."""
    text = str(url)
    for email in org_emails or ():
        for form in sorted(_b64_forms(email), key=len, reverse=True):
            text = text.replace(form, "[email-b64]")
    text = re.sub(r"[A-Za-z0-9._%+\-]{1,64}(?:@|%40)[A-Za-z0-9.\-]{1,253}\.[A-Za-z]{2,24}", "[email]", text)
    try:
        parts = urlsplit(text)
    except ValueError:
        return "[unparsable URL]"
    path = "/".join("[email-b64]" if _b64_email(seg) else "[token]" if _token_like(seg) else seg for seg in parts.path.split("/"))
    query = "&".join((k + "=[email-b64]") if _b64_email(v) else (k + "=[token]") if _token_like(v) else part
                     for part in parts.query.split("&") if part for k, _, v in [part.partition("=")])
    fragment = "[token]" if parts.fragment and _token_like(parts.fragment) else parts.fragment
    try:
        from v3lum.modules.url_web.archive_mining import mask_harvested_url

        return mask_harvested_url(urlunsplit((parts.scheme, parts.netloc, path, query, fragment)))[0]
    except Exception:  # noqa: BLE001
        return urlunsplit((parts.scheme, parts.netloc, path, query, fragment))


# ======================================================================================
# previews (c1)
# ======================================================================================


def preview_plan(short_url: str, shorteners: Mapping[str, Mapping[str, Any]] | None = None) -> dict[str, Any] | None:
    """The documented no-click preview page of a short link and whether it may be fetched
    automatically: {url, provider, automation ('allowed' | 'manual_only' | 'pending_terms_review')};
    None when the shortener documents no preview (left to unshorten_trace)."""
    text = short_url if "://" in short_url else "https://" + short_url
    try:
        parts = urlsplit(text)
    except ValueError:
        return None
    host = normalize_host(parts.hostname)
    code = parts.path.strip("/")
    if not code or "/" in code or not re.fullmatch(r"[A-Za-z0-9_-]{1,64}", code):
        return None
    info = shortener_info(host, shorteners) or {}
    kind = info.get("preview")
    if kind == "tinyurl" and host == "tinyurl.com":
        url = f"https://preview.tinyurl.com/{code}"
    elif kind == "bitly" and host in ("bit.ly", "bitly.com", "j.mp"):
        url = f"https://bit.ly/{code}+"
    else:
        return None
    return {"url": url, "provider": info.get("provider") or kind, "automation": info.get("preview_automation", "pending_terms_review")}


def _first_external_link(html: str, exclude: tuple[str, ...]) -> str | None:
    for found in re.finditer(r"<a\b[^<>]{0,2048}>", html, re.I):
        href = attrs(found.group(0)).get("href") or ""
        try:
            parts = urlsplit(href)
        except ValueError:
            continue
        if parts.scheme in ("http", "https") and parts.hostname and not any(normalize_host(parts.hostname).endswith(s) for s in exclude):
            return href
    return None


def parse_tinyurl_preview(status: Any, headers: Any, body: Any) -> dict[str, Any]:
    """TinyURL preview page -> {status ok|empty|blocked|error, destination, reason}; a challenge or login
    page is BLOCKED (A9: give the manual link, never retry)."""
    block = detect_block(status, headers, body, login_wall_on_200=True)
    if block:
        return {"status": "blocked", "reason": block, "destination": None}
    st = int(status) if str(status).isdigit() else 0
    if st == 404:
        return {"status": "empty", "reason": "alias not found", "destination": None}
    if st != 200:
        return {"status": "error", "reason": f"HTTP {st}", "destination": None}
    html = to_text(body, MAX_TRACE_BODY)
    found = re.search(r"<a\b[^<>]{0,512}id=[\"']redirecturl[\"'][^<>]{0,2048}>", html, re.I)
    dest = attrs(found.group(0)).get("href") if found else None
    dest = dest or _first_external_link(html, ("tinyurl.com", "tinyurl.dev"))
    if not dest:
        return {"status": "error", "reason": "preview page not understood", "destination": None}
    return {"status": "ok", "reason": None, "destination": dest}


def parse_bitly_info(status: Any, headers: Any, body: Any) -> dict[str, Any]:
    """Bitly '+' info page (only ever a page an analyst saved: Bitly's terms forbid automation) ->
    {status, destination, reason}; login walls and challenges are BLOCKED."""
    block = detect_block(status, headers, body, login_wall_on_200=True)
    if block:
        return {"status": "blocked", "reason": block, "destination": None}
    st = int(status) if str(status).isdigit() else 0
    if st == 404:
        return {"status": "empty", "reason": "link not found", "destination": None}
    if st != 200:
        return {"status": "error", "reason": f"HTTP {st}", "destination": None}
    html = to_text(body, MAX_TRACE_BODY)
    found = re.search(r"\"long_url\"\s*:\s*\"([^\"\s]{1,2048})\"", html)
    dest = found.group(1).replace("\\/", "/") if found else _first_external_link(html, ("bit.ly", "bitly.com", "bitly.is", "j.mp"))
    if not dest:
        return {"status": "error", "reason": "info page not understood", "destination": None}
    return {"status": "ok", "reason": None, "destination": dest}


# ======================================================================================
# unshorten.me (c2)
# ======================================================================================


def unshorten_me_url(short_url: str) -> str:
    """The keyless v1 lookup https://unshorten.me/json/<short URL without scheme> (research C0175)."""
    return "https://unshorten.me/json/" + re.sub(r"^https?://", "", short_url.strip(), flags=re.I)


def parse_unshorten_me(status: Any, body: Any, headers: Any = None) -> dict[str, Any]:
    """unshorten.me JSON (v1 requested_url/resolved_url/usage_count/remaining_calls, or v2
    shortened_url/unshortened_url) -> {status ok|empty|unresolved|quota|rate_limited|blocked|error, ...}; 'empty' only
    when the service resolved the URL to itself (not a short link)."""
    st = int(status) if str(status).isdigit() else 0
    block = detect_block(st, headers, body)
    if block:
        return {"status": "blocked", "reason": block}
    if st == 429:
        return {"status": "rate_limited", "reason": "HTTP 429"}
    if st in (401, 403):
        return {"status": "blocked", "reason": f"HTTP {st} (keyless)"}
    data = load_json_text(body)
    if not isinstance(data, dict):
        return {"status": "error", "reason": "HTML instead of JSON" if looks_like_html(body) else "invalid JSON"}
    remaining = data.get("remaining_calls")
    try:
        remaining = int(remaining) if remaining is not None else None
    except (TypeError, ValueError):
        remaining = None
    requested = data.get("requested_url") or data.get("shortened_url")
    resolved = data.get("resolved_url") or data.get("unshortened_url")
    err = data.get("error") or data.get("message") or data.get("detail")
    if data.get("success") is not True or not resolved:
        text = str(err or "")[:200]
        if re.search(r"limit|quota|exceed|too many", text, re.I) or remaining == 0:
            return {"status": "quota", "reason": text or "remaining_calls 0", "remaining_calls": remaining}
        # the service's own fetch failed ('Unable to resolve the URL'): a dead link and a service-side
        # failure look the same, so this is 'could not verify', never 'the link leads nowhere' (rule 5)
        return {"status": "unresolved", "reason": text or "not resolved", "requested_url": requested, "remaining_calls": remaining}
    if not isinstance(resolved, str) or urlsplit(resolved).scheme not in ("http", "https"):
        return {"status": "error", "reason": "resolved URL is not http(s)"}
    same = bool(requested) and re.sub(r"^https?://", "", str(requested)).rstrip("/") == re.sub(r"^https?://", "", resolved).rstrip("/")
    return {"status": "empty" if same else "ok", "reason": "not a short link" if same else None, "resolved_url": resolved,
            "requested_url": requested, "remaining_calls": remaining, "usage_count": data.get("usage_count")}


# ======================================================================================
# the tracer (c3-c6)
# ======================================================================================

_META_TAG_RE = re.compile(r"<meta\b[^<>]{0,1024}>", re.I)


def parse_meta_refresh(html: Any) -> str | None:
    """``<meta http-equiv=refresh content="0; url=...">`` target (a hint: recorded, never executed)."""
    text = to_text(html, MAX_TRACE_BODY)
    for found in _META_TAG_RE.finditer(text):
        tag = attrs(found.group(0))
        if (tag.get("http-equiv") or "").lower() != "refresh":
            continue
        target = re.search(r"url\s*=\s*['\"]?([^'\";\s]{1,2048})", tag.get("content") or "", re.I)
        if target:
            return target.group(1)
    return None


def js_location_hints(html: Any) -> list[str]:
    """``location = '...'`` / ``location.replace(...)`` literals: hints only, never followed."""
    text = to_text(html, MAX_TRACE_BODY)
    rx = re.compile(r"location(?:\.href)?\s*=\s*[\"']([^\"'\s]{1,2048})[\"']|location\.(?:replace|assign)\(\s*[\"']([^\"'\s]{1,2048})[\"']")
    out: list[str] = []
    for found in rx.finditer(text):
        value = found.group(1) or found.group(2)
        if value not in out:
            out.append(value)
    return out[:10]


def plan_hop(url: str, *, follow_final: bool, ctx: Any = None, seed_ports: tuple[int, ...] = (80, 443),
             shorteners: Mapping[str, Mapping[str, Any]] | None = None) -> dict[str, str]:
    """c3-c6: may the tracer contact ``url`` (a redirect target)? 'contact' (a listed shortener),
    'contact_guarded' (the first non-shortener destination with --follow-final: the core hostile-host
    guard decides), 'record' (the first non-shortener destination: recorded, not contacted),
    'confirm' (a per-recipient token URL), 'refuse' (scheme, port, internal/private names, IP loggers)."""
    try:
        parts = urlsplit(url)
        port = parts.port
    except ValueError:
        return {"action": "refuse", "reason": "unparsable URL"}
    if parts.scheme not in ("http", "https"):
        return {"action": "refuse", "reason": f"scheme {parts.scheme or 'none'} (http/https only)"}
    if parts.username or parts.password:
        return {"action": "refuse", "reason": "credentials in the URL"}
    if port is not None and port not in seed_ports:
        return {"action": "refuse", "reason": f"port {port} (80/443 only)"}
    problem = host_problem(parts.hostname or "")
    if problem:
        return {"action": "refuse", "reason": f"{problem} ({parts.hostname})"}
    info = shortener_info(url, shorteners)
    if info and info.get("never_contact"):
        return {"action": "refuse", "reason": f"{info.get('category', 'ip_logger')}: never contacted automatically"}
    if not info and not follow_final:
        # recorded, never contacted (its recipient token, if any, keeps it to a domain pivot)
        return {"action": "record", "reason": "first non-shortener destination: recorded, not contacted"}
    token = recipient_token_reason(url, ctx)
    if token and not (ctx is not None and confirmed_url(ctx, url)):
        return {"action": "confirm", "reason": f"{token}: needs --confirm-url (A7 BR15)"}
    if info:
        return {"action": "contact", "reason": "listed shortener/redirector"}
    return {"action": "contact_guarded", "reason": "--follow-final: the core hostile-host guard decides (P376)"}


_OPEN_REDIRECT_RE = re.compile(r"[?&](?:url|u|redirect|redirect_uri|next|dest|destination|target|goto|r)=https?(?::|%3A)", re.I)


def chain_flags(urls: list[str]) -> list[str]:
    """Flags over the hop URLs: cross_domain_hop, https_downgrade, known_shortener, open_redirect_param."""
    flags: set[str] = set()
    prev = None
    for url in urls:
        if shortener_info(url):
            flags.add("known_shortener")
        if prev:
            a, b = urlsplit(prev), urlsplit(url)
            if not same_site(a.hostname or "", b.hostname or ""):
                flags.add("cross_domain_hop")
            if a.scheme == "https" and b.scheme == "http":
                flags.add("https_downgrade")
        if _OPEN_REDIRECT_RE.search(url):
            flags.add("open_redirect_param")
        prev = url
    return sorted(flags)


def _emit_destination(res: ModuleResult, final: str, ctx: Any, *, relation: str = "redirects_to", note: str = "") -> None:
    """c8: the final URL as a url pivot for the passive reputation modules; only its domain when it
    carries a recipient token or an e-mail (no recipient identifier reaches third-party providers)."""
    if recipient_token_reason(final, ctx):
        host = (urlsplit(final).hostname or "").lower()
        if host:
            res.pivot(T.DOMAIN, host, relation, confidence="probable", expand=True,
                      note=(note + "; " if note else "") + "the destination URL carries a recipient token: only its domain is pivoted")
        return
    res.pivot(T.URL, final, relation, confidence="probable", expand=True, note=note)


_URL_IN_TEXT_RE = re.compile(r"https?://[^\s'\"<>]{1,2048}")


def _mask_reason(text: Any) -> str:
    """A free-text reason with every URL in it masked like a hop URL (e-mails, tokens)."""
    return _URL_IN_TEXT_RE.sub(lambda m: mask_hop_url(m.group(0)), str(text or ""))


# ======================================================================================
# unshorten_preview (PASSIVE, default, no request today)
# ======================================================================================


@register
class UnshortenPreview(Module):
    name = "unshorten_preview"
    title = "Short-link preview pages (TinyURL preview, Bitly '+') as no-click manual links"
    description = (
        "Recognises short links of the bundled shortener list and gives the documented no-click preview page (TinyURL "
        "preview, Bitly '+' info page) as a manual link; no request is made while the providers' terms do not allow automation."
    )
    category = "url_web"
    accepts = {T.URL}
    produces: frozenset = frozenset()
    tags = {"offline", "free"}
    reference = "https://en.wikipedia.org/wiki/TinyURL"
    terms = "open"  # own code; previews are manual links (no provider receives the value from V3LUM)
    opsec = Opsec.PASSIVE
    disclosure = "none"
    hosts = ()
    access_model = "offline"
    default_enabled = True
    max_pivots = 0
    notice = (
        "No request: Bitly's terms forbid automated access and TinyURL's terms are unrecorded, so the preview pages are manual "
        "links (A1, A9). Opening a preview page does not click through to the destination."
    )

    def applies(self, entity: Entity, ctx: Any) -> bool:
        return shortener_info(entity.value) is not None

    def run(self, entity: Entity, ctx: Any) -> ModuleResult:
        res = self.result(entity)
        info = shortener_info(entity.value) or {}
        plan = preview_plan(entity.value)
        record = {"host": normalize_host(urlsplit(entity.value).hostname), "provider": info.get("provider"),
                  "category": info.get("category") or "url_shortener", "source": info.get("source"),
                  "never_contact": bool(info.get("never_contact"))}
        if plan:
            record.update({"preview_url": plan["url"], "preview_automation": plan["automation"]})
            res.link(f"{plan['provider']} preview page (no click-through to the destination)", plan["url"])
        else:
            record["preview_url"] = None
            record["note"] = "no documented no-click preview: left to unshorten_trace (LIGHT) / unshorten_me"
        res.attr("short_link", record)
        return res


# ======================================================================================
# unshorten_me (third-party API, opt-in)
# ======================================================================================


@register
class UnshortenMe(Module):
    name = "unshorten_me"
    title = "unshorten.me short-link expansion (the service fetches the link)"
    description = (
        "Asks unshorten.me where a short link of the bundled shortener list resolves (its service fetches the link, so V3LUM "
        "never clicks it); 10 new lookups per hour per IP; never sent for per-recipient token URLs."
    )
    category = "url_web"
    accepts = {T.URL}
    produces = {T.URL, T.DOMAIN}
    tags = {"free"}
    reference = "https://unshorten.me/api"
    terms = "open"  # published Terms and Conditions (unshorten.me/terms-of-service): companies may use the Service; provider tier unknown
    opsec = Opsec.PASSIVE
    disclosure = "third_party"
    provider = "unshorten_me"
    sources = (SRC_UNSHORTEN_ME,)
    hosts = ("unshorten.me",)
    access_model = "free_noauth_limited"
    max_requests = 1
    expected_latency = 1.5
    timeout = 30.0
    cache_ttl = 604800  # cached lookups are free on the service too
    max_pivots = 2
    default_enabled = False  # provider tier unknown and fetches_target (A3): opt-in, excluded at TLP:AMBER and above (A2/A8)
    error_markers = (
        {"id": "unshorten_me_quota", "statuses": [200, 429], "regex": "(?i)usage limit|limit exceeded",
         "maps_to": "quota", "reason_code": "quota", "reason": "unshorten.me: hourly lookup quota exhausted"},
    )
    notice = (
        "unshorten.me stores every submitted URL (privacy policy) and fetches the short link itself; tier unknown (excluded at "
        "TLP:AMBER and above). Token URLs are never sent."
    )

    def applies(self, entity: Entity, ctx: Any) -> bool:
        info = shortener_info(entity.value)
        return info is not None and not info.get("never_contact")

    def run(self, entity: Entity, ctx: Any) -> ModuleResult:
        res = self.result(entity)
        if recipient_token_reason(entity.value, ctx):
            return res.mark("skipped", "the short link carries a per-recipient token: never sent to a service that fetches and stores it",
                            reason_code="policy")
        resp = ctx.http.get(unshorten_me_url(entity.value), source=SRC_UNSHORTEN_ME)
        if resp.status != 404:
            ctx.http.check(resp)  # challenges, 429 and the quota marker raise (could not verify)
        parsed = parse_unshorten_me(resp.status, resp.content, resp.headers)
        status = parsed["status"]
        if status == "blocked":
            return res.mark("blocked", f"could not verify: unshorten.me answered a block page ({parsed['reason']})", reason_code="challenge")
        if status == "rate_limited":
            return res.mark("rate_limited", "could not verify: unshorten.me rate limit", reason_code="rate_limited")
        if status == "quota":
            return res.mark("quota", f"could not verify: unshorten.me quota ({parsed['reason']})", reason_code="quota")
        if status == "error":
            return res.mark("error", f"could not verify: unexpected unshorten.me answer ({parsed['reason']})", reason_code="error")
        record = {"service": "unshorten.me", "requested": mask_hop_url(str(parsed.get("requested_url") or entity.value)),
                  "remaining_calls": parsed.get("remaining_calls"), "usage_count": parsed.get("usage_count")}
        if status == "unresolved":
            record["result"] = f"not resolved by the service: {parsed.get('reason')}"
            res.attr("unshorten_lookup", record)
            return res.mark("error", f"could not verify: unshorten.me could not resolve the link ({parsed['reason']})", reason_code="error")
        if status == "empty":
            record["result"] = parsed.get("reason")
            res.attr("unshorten_lookup", record)
            return res.mark("empty")  # the service answered: not resolvable or not a short link
        final = str(parsed["resolved_url"])
        record["resolved"] = mask_hop_url(final)
        res.attr("unshorten_lookup", record)
        _emit_destination(res, final, ctx, note="resolved by unshorten.me (its fetch, not ours)")
        res.raw = {"requested": record["requested"], "resolved": record["resolved"], "remaining_calls": record["remaining_calls"]}
        return res


# ======================================================================================
# unshorten_trace (LIGHT, opt-in)
# ======================================================================================


class _StopHop(Exception):
    """A redirect target the tracer does not contact (recorded instead)."""

    def __init__(self, url: str, action: str, reason: str) -> None:
        super().__init__(reason)
        self.url, self.action, self.reason = url, action, reason


def _selftest(ctx: Any) -> HealthResult:
    """Offline self-test: the shortener list, the hop plan and the masking (no network)."""
    table = load_shorteners()
    named = all(h in table for h in ("bit.ly", "tinyurl.com", "encurtador.com.br", "t.co", "cutt.ly", "rb.gy", "is.gd", "shorturl.at"))
    refuse = all(plan_hop(u, follow_final=True)["action"] == "refuse" for u in (
        "http://169.254.169.254/latest/meta-data/", "http://127.0.0.1:8080/admin", "http://10.0.0.5/", "http://router.local/"))
    masked = mask_hop_url("https://x.example.net/r?u=alice%40example.com&t=9f8e7d6c5b4a39281706")
    if not named or not refuse or "alice" in masked or "9f8e7d6c5b4a39281706" in masked:
        return HealthResult("dead", "tracer self-test failed (shortener list, hop plan or masking)")
    return HealthResult("ok", f"{len(table)} shortener hosts; hop plan and masking ok")


def _light_sends(infos: list[Any], method: str) -> list[Any]:
    """The target sends of one traced request (DoH lookups and cache replays excluded)."""
    return [i for i in infos if getattr(i, "opsec", "") == "light" and getattr(i, "method", "") == method
            and not getattr(i, "cached", False) and "dns-query" not in str(getattr(i, "url", ""))]


@register
class UnshortenTrace(Module):
    name = "unshorten_trace"
    title = "Short-link redirect tracer (LIGHT): reads the Location of listed shorteners"
    description = (
        "LIGHT, analyst-typed seeds only: HEAD (then GET) of a short link of the bundled shortener list, each redirect hop "
        "checked before it is sent; only shortener hosts are contacted and the first other destination is recorded, not "
        "visited (unless unshorten_trace_follow_final)."
    )
    category = "url_web"
    accepts = {T.URL}
    produces = {T.URL, T.DOMAIN}
    run_on = "seeds"
    tags = {"free"}
    reference = "https://github.com/SMAPPNYU/urlExpander"
    terms = "open"  # own code
    opsec = Opsec.LIGHT
    disclosure = "target"
    hosts = ()
    max_requests = 3  # HEAD, then one GET when HEAD is refused or inconclusive (each request follows <= 5 core hops)
    expected_latency = 3.0
    timeout = 45.0
    min_interval = 1.0
    max_rate = 1.0
    cache_ttl = 86400
    max_pivots = 2
    default_enabled = False  # LIGHT is never default (A3)
    notice = (
        "LIGHT: a HEAD/GET of a short link is a click the link creator's analytics can see; never use it on confidential client "
        "URLs. Token URLs need --confirm-url; IP loggers are never contacted."
    )
    settings = {
        "unshorten_trace_follow_final": SettingSpec(
            False, "unshorten_trace: also visit the first non-shortener destination (--follow-final; the hostile-host guard still decides, P376)"
        ),
    }

    @classmethod
    def health_check(cls) -> HealthCheck:
        return HealthCheck(offline=True, selftest=_selftest)

    def run(self, entity: Entity, ctx: Any) -> ModuleResult:
        res = self.result(entity)
        if not getattr(ctx, "is_seed", True):
            return res.mark("skipped", "LIGHT runs only on analyst-typed seeds, never on pivots (A7)", reason_code="scope")
        seed = entity.value
        follow_final = bool(ctx.setting("unshorten_trace_follow_final", False))
        info = shortener_info(seed)
        if info and info.get("never_contact"):
            return res.mark("skipped", f"{info.get('category', 'ip_logger')}: never contacted automatically (manual analysis only)",
                            reason_code="policy")
        if info is None and not follow_final:
            return res.mark("skipped", "not a listed shortener/redirector: the tracer contacts only bundled shortener hosts",
                            reason_code="not_applicable")
        if recipient_token_reason(seed, ctx) and not confirmed_url(ctx, seed):
            return res.mark("skipped", "the short link carries a probable per-recipient token: re-run with --confirm-url <url> (A7 BR15)",
                            reason_code="policy")
        try:
            port = urlsplit(seed).port
        except ValueError:
            return res.mark("error", "unreadable URL", reason_code="error")
        ports = (80, 443) + ((port,) if port else ())
        trace = self._trace(ctx, seed, "HEAD", follow_final, ports)
        if self._needs_get(trace):
            trace = self._trace(ctx, seed, "GET", follow_final, ports)  # HEAD then GET (c4)
        return self._finish(res, ctx, seed, trace)

    @staticmethod
    def _needs_get(trace: Mapping[str, Any]) -> bool:
        """GET after HEAD: HEAD refused (400/403/405/501), or a listed shortener answered 200 (an interstitial
        whose meta refresh / JS hints need the body)."""
        if trace["stop"] is not None or trace["final_status"] is None:
            return False
        if trace["final_status"] in (400, 403, 405, 501):
            return True
        return trace["final_status"] == 200 and shortener_info(str(trace["final_url"] or "")) is not None

    @staticmethod
    def _trace(ctx: Any, seed: str, method: str, follow_final: bool, ports: tuple[int, ...]) -> dict[str, Any]:
        """One request with core redirect following; this module's hop check stops at the first target it
        does not contact (the core checks every hop it does send: SSRF guard, downgrade, hostile hosts)."""
        seen: list[str] = []

        def hop_check(url: str) -> None:
            seen.append(url)
            if len(seen) == 1:
                return  # the analyst-typed seed, judged in run() and by the core LIGHT seed binding
            plan = plan_hop(url, follow_final=follow_final, ctx=ctx, seed_ports=ports)
            if plan["action"] not in ("contact", "contact_guarded"):
                raise _StopHop(url, plan["action"], plan["reason"])

        log = getattr(ctx.http, "request_log", None)
        before = len(log) if isinstance(log, list) else 0

        def sends() -> list[Any]:
            current = getattr(ctx.http, "request_log", None)
            return _light_sends(list(current)[before:], method) if isinstance(current, list) else []

        stop: dict[str, str] | None = None
        resp = None
        try:
            resp = ctx.http.request(method, seed, allow_redirects=True, max_bytes=MAX_TRACE_BODY, hop_check=hop_check)
        except _StopHop as hop:
            stop = {"url": hop.url, "action": hop.action, "reason": hop.reason}
        except PolicyError as exc:
            if not sends():
                raise  # the seed itself was refused (scope, SSRF, hostile host): the run is refused
            text = str(exc)
            if len(seen) > len(sends()):
                stop = {"url": seen[-1], "action": "refuse", "reason": text[:240]}  # refused by the core after this module's check
            elif "downgrade to " in text:
                # the core refuses https->http hops before the hop check: the target (redacted by the core) is
                # recorded uncontacted like any destination, unless the hop plan refuses it outright
                target = text.split("downgrade to ", 1)[1].strip()
                plan = plan_hop(target, follow_final=False, ctx=ctx, seed_ports=ports)
                action = "refuse" if plan["action"] == "refuse" else "record"
                stop = {"url": target, "action": action, "reason": "https->http downgrade (never followed): " + plan["reason"],
                        "truncated": len(target) >= 120}
            else:
                stop = {"url": "", "action": "refuse", "reason": text[:240]}
        except RequestCapReached as exc:
            if not sends():
                raise
            stop = {"url": seen[-1] if len(seen) > len(sends()) else "", "action": "budget", "reason": str(exc)[:240]}
        except (HttpError, NetworkError) as exc:
            if not sends():
                raise
            text = str(exc)
            many = "too many redirects" in text
            stop = {"url": seen[-1] if len(seen) > len(sends()) else "", "action": "refuse" if many else "error",
                    "reason": "more than 5 redirects (core cap): stopped" if many else text[:240]}
        done = sends()
        cached = bool(resp is not None and getattr(resp, "from_cache", False))
        contacted = len(seen) if cached else min(len(done), len(seen))
        if stop is not None and stop.get("url") and seen and stop["url"] == seen[-1]:
            contacted = min(contacted, len(seen) - 1)
        return {
            "method": method, "seen": seen[:contacted] or [seed], "statuses": [int(getattr(i, "status", 0) or 0) for i in done],
            "stop": stop, "cached": cached, "final_url": str(resp.url) if resp is not None else None,
            "final_status": int(resp.status) if resp is not None else None,
            "classification": getattr(resp, "classification", None) if resp is not None else None,
            "headers": resp.headers if resp is not None else {}, "body": bytes(resp.content or b"") if resp is not None and method == "GET" else b"",
        }

    def _finish(self, res: ModuleResult, ctx: Any, seed: str, trace: Mapping[str, Any]) -> ModuleResult:
        stop = trace["stop"]
        chain: list[dict[str, Any]] = []
        for i, url in enumerate(trace["seen"]):
            status = trace["statuses"][i] if i < len(trace["statuses"]) and not trace["cached"] else None
            chain.append({"url": mask_hop_url(url), "status": status, "contacted": True, "method": trace["method"],
                          **({"from_cache": True} if trace["cached"] else {})})
        destination: str | None = None
        hints: list[str] = []
        refused: dict[str, Any] | None = None
        if stop:
            # core refusal texts quote the refused target: masked like every hop URL before evidence (c7)
            stop = dict(stop, reason=_mask_reason(stop["reason"]))
            entry = {"url": mask_hop_url(stop["url"]) if stop.get("url") else None, "status": None, "contacted": False,
                     "action": stop["action"], "reason": stop["reason"]}
            chain.append(entry)
            if stop["action"] == "record":
                destination = stop["url"]
                if stop.get("truncated"):
                    host = urlsplit(destination).hostname or ""
                    destination = f"{urlsplit(destination).scheme}://{host}/" if host else None
            elif stop["action"] in ("refuse", "confirm"):
                refused = {"url": entry["url"], "action": stop["action"], "reason": stop["reason"]}
        elif trace["final_url"] and trace["classification"] is None:
            final_url = str(trace["final_url"])
            status = trace["final_status"]
            location = header_first(trace["headers"], "location") if status in (301, 302, 303, 307, 308) else None
            if location:
                nxt = urljoin(final_url, location.strip())
                chain.append({"url": mask_hop_url(nxt), "status": None, "contacted": False, "action": "record",
                              "reason": "Location of the last hop"})
                destination = nxt
            elif trace["body"]:
                meta = parse_meta_refresh(trace["body"])
                hints = [mask_hop_url(urljoin(final_url, h)) for h in js_location_hints(trace["body"])]
                if meta:
                    nxt = urljoin(final_url, meta)
                    chain.append({"url": mask_hop_url(nxt), "status": None, "contacted": False, "action": "record",
                                  "reason": "meta refresh (recorded, not followed)"})
                    destination = nxt
                elif status == 200 and not shortener_info(final_url):
                    destination = final_url  # --follow-final reached a page
            elif status == 200 and not shortener_info(final_url):
                destination = final_url
        urls = [*trace["seen"], *([stop["url"]] if stop and stop.get("url") else []), *([destination] if destination and not stop else [])]
        flags = chain_flags(urls)
        res.attr("unshorten_chain", chain)
        res.attr("short_link", {
            "host": normalize_host(urlsplit(seed).hostname), "provider": (shortener_info(seed) or {}).get("provider"),
            "category": (shortener_info(seed) or {}).get("category") or ("url_shortener" if shortener_info(seed) else "redirector"),
            "flags": flags, "js_hints": hints[:10], "hops_contacted": 0 if trace["cached"] else len(trace["seen"]),
            "destination": mask_hop_url(destination) if destination else None,
        })
        res.raw = {"chain": chain, "flags": flags, "method": trace["method"]}
        if destination:
            _emit_destination(res, destination, ctx, note="destination of the short link (Location read, not visited)"
                              if stop or not trace["final_url"] or destination != trace["final_url"] else "destination of the short link")
        if refused:
            res.attr("unshorten_refused", refused)
            res.finding(
                "Short link redirects to a target the tracer refuses",
                "info",
                f"The redirect chain continues to {refused['url'] or 'a target that could not be read'}: {refused['reason']}. Nothing was sent there.",
                confidence="confirmed",
                criterion="per-hop safe-fetch check (SSRF guard, https downgrade, recipient-token rule, IP-logger list, ports) refused the next hop (P070 c4-c6)",
                tags=["redirect_refused"],
            )
        if stop and stop["action"] == "budget":
            return res.stop("request_cap")
        if stop and stop["action"] == "error":
            return res.mark("error", f"could not verify: the redirect chain broke after {len(trace['seen'])} hop(s) ({stop['reason']})",
                            reason_code="error")
        if destination or refused:
            return res
        cls = trace["classification"]
        final_status = trace["final_status"] or 0
        if cls is not None:
            try:
                st, code = status_for(cls.reason_code), cls.reason_code
            except ValueError:
                st, code = Status.ERROR, "error"
            if st not in (Status.BLOCKED, Status.RATE_LIMITED, Status.QUOTA, Status.ERROR):
                st, code = Status.ERROR, "error"
            return res.mark(st, f"could not verify: {cls.reason}", reason_code=code)
        if final_status == 429:
            return res.mark("rate_limited", "could not verify: the shortener answered HTTP 429", reason_code="rate_limited")
        if final_status in (401, 403):
            return res.mark("blocked", f"could not verify: the shortener answered HTTP {final_status}", reason_code="challenge")
        if final_status == 404 or final_status == 410:
            return res.mark("empty", f"the shortener answered {final_status} for this link (unknown or removed)")
        if final_status >= 400 or not final_status:
            return res.mark("error", f"could not verify: the shortener answered HTTP {final_status}", reason_code="error")
        return res.mark("empty", "the shortener answered without a redirect, meta refresh or other destination")
