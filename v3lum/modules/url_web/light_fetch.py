"""Shared helpers of batch p9-G03-1 (P062, P063, P065, P068, P070): the LIGHT safe-fetch helper, the
shared homepage fetch and the untrusted-markup helpers the five proposals use.

No module is registered here. Everything the modules of this batch need that the core does not offer
yet (see the batch manifest ``core_requests``) lives here, built only on ``ctx.http``:

* :func:`safe_get` - the module-side half of the "core safe-fetch helper" (P062 c4, P065 c3, P068 c3,
  P070 c4). The core already applies, per request, the SSRF guard on every hop (private, loopback,
  link-local, CGNAT, ULA, metadata and reserved addresses after resolution through the egress
  profile), the LIGHT seed binding (first hop = the analyst-typed seed or a subdomain), the method
  rules (GET/HEAD), the A7 ceilings (1 req/s and 25 requests per target host per scan), the
  hostile-host guard on redirect targets, ``ua_light`` and the request ledger. On top of that this
  helper adds what the final conditions ask and the core does not do: http/https only, ports 80/443
  unless the seed names one, no URL userinfo, same registrable domain (or a listed CDN suffix) and
  inside the seed's hosts, redirects followed by hand (``allow_redirects=False``, at most 5 hops)
  with every hop re-checked, a byte cap per file and the content-type checks of the caller.
* :func:`fetch_homepage` - the shared homepage fetch (P072 c2): one GET of the seed page with the
  same method, URL (fragment dropped), no Accept header, byte cap and TTL in every LIGHT module of
  the batch (favicon_fetch, js_endpoints_live), so the HTTP cache serves the page once per day to all
  of them and to web_fingerprint (P072), which fetches the same URL without an Accept header.
* :func:`cached_homepage` - how ``security_headers`` (P063, disclosure 'none') reads that cached
  response without any request. The core has no cache-only read for offline modules yet, so it
  returns None until the core offers ``ctx.cached_response`` (manifest core request).
* markup helpers (attributes of ``<link>``/``<script>``/``<meta>`` tags, ``<base href>``), block-page
  detection (:func:`detect_block`), multi-valued header handling (:func:`headers_multi`,
  :func:`split_joined_set_cookie`) and the bounded gzip reader (:func:`safe_gunzip`).

Every body is untrusted data: parsed with bounded regular expressions, never executed or rendered.
"""

from __future__ import annotations

import json
import re
import zlib
from collections.abc import Iterable, Mapping
from dataclasses import dataclass, field
from typing import Any
from urllib.parse import urljoin, urlsplit, urlunsplit

from v3lum.core import psl
from v3lum.core.entities import Entity
from v3lum.core.entities import EntityType as T
from v3lum.core.http import host_problem, host_within, normalize_host, parse_ip

__all__ = [
    "Fetched",
    "HOMEPAGE_ACCEPT",
    "HOMEPAGE_MAX_BYTES",
    "HOMEPAGE_TTL",
    "MAX_HOPS",
    "attrs",
    "base_for",
    "cached_homepage",
    "check_target",
    "confirmed_url",
    "content_type",
    "detect_block",
    "fetch_homepage",
    "header_first",
    "header_values",
    "headers_multi",
    "internal_seed_hosts",
    "looks_like_html",
    "mask_text_urls",
    "masked_url",
    "page_title",
    "registrable",
    "safe_get",
    "safe_gunzip",
    "same_site",
    "seed_ports",
    "seed_url",
    "split_joined_set_cookie",
    "to_bytes",
    "to_text",
    "token_url",
    "xml_unescape",
]

#: redirects followed by hand per file (WP11 core cap: 5; P072 c2 'manual redirects <= 5')
MAX_HOPS = 5
#: the shared homepage fetch: no Accept header (the cache key then matches web_fingerprint, P072 c2,
#: which never sets one), the same cap and TTL in every module
HOMEPAGE_ACCEPT: str | None = None
HOMEPAGE_MAX_BYTES = 1_048_576
HOMEPAGE_TTL = 86_400
_REDIRECTS = (301, 302, 303, 307, 308)

# ======================================================================================
# text and header helpers (ported from the batch prep parsers, stdlib only)
# ======================================================================================


def to_bytes(raw: Any) -> bytes:
    if raw is None:
        return b""
    if isinstance(raw, (bytes, bytearray, memoryview)):
        return bytes(raw)
    return str(raw).encode("utf-8", "replace")


def to_text(raw: Any, limit: int | None = None) -> str:
    """Bytes as UTF-8 (errors replaced, BOM stripped); str passes through; optional cap."""
    if raw is None:
        return ""
    if isinstance(raw, (bytes, bytearray, memoryview)):
        data = bytes(raw)
        if limit is not None:
            data = data[:limit]
        text = data.decode("utf-8", "replace")
    else:
        text = str(raw)
        if limit is not None:
            text = text[:limit]
    return text[1:] if text.startswith("﻿") else text


def looks_like_html(raw: Any) -> bool:
    head = to_text(raw, 2048).lstrip().lower()
    return head.startswith(("<!doctype html", "<html")) or "<html" in head[:512] or "<head" in head[:512] or "<body" in head[:1024]


def headers_multi(headers: Any) -> list[tuple[str, str]]:
    """Headers as a list of (lower-case name, value) that keeps duplicates (P063 c2: the Set-Cookie
    list). Accepts pairs, a dict (str or list values), a mapping or a raw header block (status line
    ignored, folded lines joined)."""
    out: list[tuple[str, str]] = []
    if headers is None:
        return out
    if isinstance(headers, str):
        for line in re.split(r"\r?\n", headers):
            if not line.strip() or line.upper().startswith("HTTP/"):
                continue
            if line[0] in " \t" and out:
                out[-1] = (out[-1][0], out[-1][1] + " " + line.strip())
                continue
            if ":" in line:
                name, value = line.split(":", 1)
                out.append((name.strip().lower(), value.strip()))
        return out
    if isinstance(headers, Mapping):
        for name, value in headers.items():
            for item in value if isinstance(value, (list, tuple)) else [value]:
                out.append((str(name).strip().lower(), "" if item is None else str(item).strip()))
        return out
    if isinstance(headers, (list, tuple)):
        for pair in headers:
            if isinstance(pair, (list, tuple)) and len(pair) == 2:
                out.append((str(pair[0]).strip().lower(), "" if pair[1] is None else str(pair[1]).strip()))
    return out


def header_values(headers: Any, name: str) -> list[str]:
    wanted = name.lower()
    return [v for k, v in headers_multi(headers) if k == wanted]


def header_first(headers: Any, name: str) -> str | None:
    values = header_values(headers, name)
    return values[0] if values else None


def content_type(headers: Any) -> str:
    return (header_first(headers, "content-type") or "").split(";", 1)[0].strip().lower()


def split_joined_set_cookie(value: str) -> list[str]:
    """A requests-style comma-joined Set-Cookie value split back into cookies without breaking
    'Expires=Wed, 21 Oct 2026 ...' dates (P063 c2 until the core keeps the urllib3 getlist())."""
    parts = re.split(r",\s*(?=[^;,=\s]{1,256}=)", value or "")
    return [p.strip() for p in parts if p.strip()]


_TITLE_RE = re.compile(r"<title[^<>]{0,200}>([^<]{0,300})</title", re.I)
#: titles and resource names only challenge/block pages carry (any status)
_STRONG_TITLES = (
    ("just a moment...", "challenge: cloudflare"),
    ("attention required! | cloudflare", "challenge: cloudflare block"),
    ("vercel security checkpoint", "challenge: vercel checkpoint"),
    ("ddos-guard", "challenge: ddos-guard"),
    ("sucuri website firewall - access denied", "challenge: sucuri waf"),
    ("access denied", "challenge: access denied page"),
)
_STRONG_BODY = (
    ("cf-browser-verification", "challenge: cloudflare"),
    ("/cdn-cgi/challenge-platform/h/", "challenge: cloudflare"),
    ("_incapsula_resource", "challenge: imperva"),
)
#: widgets normal pages also carry (contact-form reCAPTCHA, Turnstile): only on 403/429/503
_WEAK_BODY = (
    ("g-recaptcha", "challenge: captcha"),
    ("h-captcha", "challenge: captcha"),
    ("cf-turnstile", "challenge: cloudflare turnstile"),
    ("challenges.cloudflare.com", "challenge: cloudflare turnstile"),
    ("perimeterx", "challenge: perimeterx"),
    ("reference #", "challenge: akamai"),
)
#: corporate secure-web-gateway block/warning pages (P072 c7, P063 c5): the page is the proxy's, never the site's
_PROXY_MARKERS = (
    ("zscaler", "proxy: zscaler"),
    ("netskope", "proxy: netskope"),
    ("fortiguard", "proxy: fortiguard"),
    ("web page blocked", "proxy: web filter"),
    ("blocked by your organization", "proxy: web filter"),
    ("palo alto networks", "proxy: palo alto"),
    ("websense", "proxy: websense"),
    ("forcepoint", "proxy: forcepoint"),
)


def page_title(body: Any) -> str | None:
    found = _TITLE_RE.search(to_text(body, 65536))
    return re.sub(r"\s+", " ", found.group(1)).strip() if found else None


def detect_block(status: Any = None, headers: Any = None, body: Any = None, *, login_wall_on_200: bool = False) -> str | None:
    """Challenge, WAF, corporate-proxy and login-wall pages (A9, P321): 'challenge: ...', 'proxy: ...',
    'login_wall: ...' or None. The core classifier runs first on every response; this adds the
    page-level markers the batch needs. Never used to retry (rule 1): the caller reports BLOCKED or
    'inconclusive'."""
    try:
        st = int(status) if status is not None else None
    except (TypeError, ValueError):
        st = None
    if (header_first(headers, "cf-mitigated") or "").lower() == "challenge":
        return "challenge: cloudflare (cf-mitigated)"
    if (header_first(headers, "x-vercel-mitigated") or "").lower() == "challenge":
        return "challenge: vercel checkpoint"
    if st == 407:
        return "proxy: 407 from the egress proxy"
    text = to_text(body, 65536).lower()
    if not text:
        return None
    title = (page_title(text) or "").lower()
    for marker, reason in _STRONG_TITLES:
        if title.startswith(marker) and (marker != "access denied" or st in (401, 403)):
            return reason
    for marker, reason in _STRONG_BODY:
        if marker in text:
            return reason
    if st in (403, 429, 503) or (st is not None and st >= 400 and looks_like_html(text)):
        for marker, reason in _PROXY_MARKERS:
            if marker in text:
                return reason
    if st in (403, 429, 503):
        for marker, reason in _WEAK_BODY:
            if marker in text:
                return reason
    if (st in (401, 403) or (login_wall_on_200 and st == 200)) and re.search(r"<input[^<>]{0,200}type=[\"']?password", text) and re.search(
        r"sign in|log in|login|entrar", text
    ):
        return "login_wall: password form"
    return None


_ATTR_RE = re.compile(r"""([a-zA-Z_:][-a-zA-Z0-9_:.]{0,40})\s*=\s*("[^"]{0,4096}"|'[^']{0,4096}'|[^\s"'=<>`]{1,4096})""")
_BASE_TAG_RE = re.compile(r"<base\b[^<>]{0,2048}>", re.I)


def xml_unescape(text: str) -> str:
    """The five XML entities and numeric references (bounded; no DTD entity is ever expanded)."""

    def rep(m: re.Match[str]) -> str:
        ent = m.group(1)
        named = {"amp": "&", "lt": "<", "gt": ">", "quot": '"', "apos": "'"}
        if ent in named:
            return named[ent]
        try:
            n = int(ent[2:], 16) if ent[:2].lower() == "#x" else int(ent[1:]) if ent[:1] == "#" else None
        except ValueError:
            n = None
        return chr(n) if n is not None and 0 < n < 0x110000 else m.group(0)

    return re.sub(r"&(#?[A-Za-z0-9]{1,8});", rep, text)


def attrs(tag: str) -> dict[str, str]:
    """Attributes of one HTML tag (first occurrence wins, entities decoded, values stripped)."""
    out: dict[str, str] = {}
    for m in _ATTR_RE.finditer(tag):
        value = m.group(2)
        if value[:1] in "\"'":
            value = value[1:-1]
        out.setdefault(m.group(1).lower(), xml_unescape(value).strip())
    return out


def base_for(html: str, page_url: str) -> str:
    """The document base: ``<base href>`` when it is http(s) or relative, else the page URL."""
    found = _BASE_TAG_RE.search(html)
    if found:
        href = attrs(found.group(0)).get("href")
        if href:
            try:
                if urlsplit(href).scheme in ("http", "https", ""):
                    return urljoin(page_url, href)
            except ValueError:
                pass
    return page_url


def safe_gunzip(data: bytes, max_out: int = 10 * 1024 * 1024) -> tuple[bytes | None, str | None]:
    """Bounded gzip decompression (gzip-bomb guard, P065 c4): (bytes, None) or (None, reason)."""
    raw = to_bytes(data)
    if not raw.startswith(b"\x1f\x8b"):
        return None, "not_gzip"
    dec = zlib.decompressobj(16 + zlib.MAX_WBITS)
    out = bytearray()
    buf = raw
    try:
        while buf:
            chunk = dec.decompress(buf, max_out + 1 - len(out))
            out += chunk
            if len(out) > max_out:
                return None, "gzip_bomb"
            buf = dec.unconsumed_tail
            if dec.eof or (not chunk and not buf):
                break
    except zlib.error:
        return None, "gzip_corrupt"
    if not dec.eof:
        return None, "gzip_truncated"
    return bytes(out), None


def load_json_text(raw: Any) -> Any:
    """Parse JSON defensively: the object, or None for HTML/empty/invalid bodies."""
    if isinstance(raw, (dict, list)):
        return raw
    text = to_text(raw).strip()
    if not text or text[0] not in "[{":
        return None
    try:
        return json.loads(text)
    except (ValueError, RecursionError):
        return None


def masked_url(url: Any) -> str:
    """A page-derived URL (an href, a src, a refused redirect target) as it may be stored: e-mail
    addresses, recipient/session parameters, opaque tokens and secrets masked (the P059/P060 archive
    masking). Hostile pages control these values; they never reach attributes, evidence or logs raw."""
    try:
        from v3lum.modules.url_web.archive_mining import mask_harvested_url

        return mask_harvested_url(str(url or ""))[0]
    except Exception:  # noqa: BLE001 - masking unavailable: never keep the URL (fail closed)
        return "[unmaskable URL]"


_URL_IN_TEXT_RE = re.compile(r"https?://[^\s'\"<>]{1,2048}")


def mask_text_urls(text: Any) -> str:
    """Free text (a refusal reason quoting its target) with every http(s) URL in it masked."""
    return _URL_IN_TEXT_RE.sub(lambda m: masked_url(m.group(0)), str(text or ""))


# ======================================================================================
# sites and seeds
# ======================================================================================


def registrable(host: Any) -> str:
    """PSL registrable domain of a host (the host itself for IPs and suffix-only names)."""
    name = normalize_host(host)
    if not name or parse_ip(name) is not None:
        return name
    try:
        return psl.registrable_domain(name) or name
    except Exception:  # noqa: BLE001 - a broken PSL entry never widens a match
        return name


def same_site(host_a: Any, host_b: Any) -> bool:
    a, b = registrable(host_a), registrable(host_b)
    return bool(a) and a == b


def seed_url(entity: Entity) -> str:
    """The page a LIGHT module of this batch reads first: the URL without its fragment (the fragment
    never reaches the server), or https://<domain>/ - the same page web_fingerprint (P072) fetches."""
    if entity.type is T.URL:
        try:
            parts = urlsplit(entity.value)
            return urlunsplit((parts.scheme, parts.netloc, parts.path or "/", parts.query, ""))
        except ValueError:
            return entity.value
    return f"https://{entity.value.strip('.').lower()}/"


def token_url(ctx: Any, url: str) -> bool:
    """A URL with a probable per-recipient token (core GUARD-02 rule ``policy.recipient_token``, the
    org profile's addresses included) that the analyst did not confirm with --confirm-url."""
    try:
        from v3lum.core.policy import recipient_token

        org = getattr(ctx, "org", None)
        hit = bool(recipient_token(url, org))
    except Exception:  # noqa: BLE001 - an unreadable URL is treated as a token URL (fail closed)
        hit = True
    return hit and not confirmed_url(ctx, url)


def confirmed_url(ctx: Any, url: str) -> bool:
    """Is ``url`` one the analyst confirmed with --confirm-url (A7 BR15; ScanOptions.confirmed_urls)?"""
    try:
        confirmed = getattr(getattr(ctx, "options", None), "confirmed_urls", ()) or ()
    except Exception:  # noqa: BLE001
        return False
    if not confirmed:
        return False
    try:
        from v3lum.core.entities import normalize_url

        wanted = {url, normalize_url(url)}
    except ValueError:
        wanted = {url}
    for item in confirmed:
        text = str(item or "").strip()
        if not text:
            continue
        try:
            if text in wanted or normalize_url(text) in wanted:
                return True
        except ValueError:
            continue
    return False


# ======================================================================================
# the safe fetch (module half of the core safe-fetch helper)
# ======================================================================================


@dataclass
class Fetched:
    """One safe fetch: the final answer of a manual redirect loop, or the reason nothing was sent."""

    url: str
    status: int = 0
    headers: dict[str, str] = field(default_factory=dict)
    body: bytes = b""
    history: list[str] = field(default_factory=list)
    truncated: bool = False
    from_cache: bool = False
    #: why the (next) hop was not requested ('' = the answer is the final one)
    refused: str = ""
    #: the redirect target that was refused (never requested)
    refused_url: str = ""
    #: P321 classification or page-level block: 'challenge: ...', 'proxy: ...', ...
    blocked: str = ""
    blocked_status: str = ""  # core classification status when the core classified the answer
    blocked_code: str = ""

    @property
    def ok(self) -> bool:
        return not self.refused and not self.blocked and 200 <= self.status < 300


def _port_of(url: str) -> int | None:
    try:
        return urlsplit(url).port
    except ValueError:
        return -1


def check_target(
    url: str,
    *,
    site_host: str,
    seed_hosts: Iterable[str] = (),
    cdn_suffixes: Iterable[str] = (),
    allowed_ports: Iterable[int] = (80, 443),
    same_site_only: bool = True,
    internal_hosts: Iterable[str] = (),
) -> str:
    """Why ``url`` may not be requested by a LIGHT module of this batch ('' = it may). Checks that need
    no DNS (the core resolves and checks every address afterwards): http/https, no userinfo, a usable
    host name (no internal/ambiguous names or non-public IP literals), ports 80/443 (or a port the
    seed itself names), the same registrable domain as the site or a listed CDN suffix, and - the
    LIGHT seed binding of the core - inside the seed's hosts."""
    try:
        parts = urlsplit(str(url).strip())
    except ValueError:
        return "malformed URL"
    if parts.scheme not in ("http", "https"):
        return f"scheme {parts.scheme or 'none'} (http/https only)"
    if parts.username or parts.password or "@" in parts.netloc:
        return "credentials in the URL"
    host = normalize_host(parts.hostname)
    if not host:
        return "no host"
    problem = host_problem(host)
    if problem and host not in {normalize_host(h) for h in internal_hosts}:
        # an internal/ambiguous name or a non-public address; the analyst's own internal typed seed host
        # (``internal_hosts``) is left to the core, which allows it only for an internal seed (AR02)
        return f"{problem} ({host})"
    port = _port_of(url)
    if port == -1:
        return "invalid port"
    if port is not None and port not in set(allowed_ports):
        return f"port {port} (80/443 only)"
    cdns = [str(s).lower().strip(".") for s in cdn_suffixes if str(s).strip()]
    if same_site_only and site_host and not same_site(host, site_host) and not any(host == s or host.endswith("." + s) for s in cdns):
        return f"{host} is not on the site's registrable domain ({registrable(site_host)})"
    hosts = tuple(seed_hosts)
    if hosts and not host_within(host, hosts):
        return f"{host} is outside the analyst-typed seed ({', '.join(hosts)}): LIGHT contact is bound to the seed (A7)"
    return ""


def internal_seed_hosts(ctx: Any, entity: Entity | None) -> tuple[str, ...]:
    """The seed's hosts when the run is an internal analyst-typed seed (RunInfo.internal_seed), else ().
    Only those exact hosts are exempt from the helper's internal-name refusal; the core SSRF guard still
    decides (an internal target needs an internal typed seed or a scope that lists it)."""
    run = getattr(ctx, "run", None)
    if entity is None or not bool(getattr(run, "internal_seed", False)) or not bool(getattr(run, "is_seed", True)):
        return ()
    try:
        from v3lum.core.http import entity_hosts

        return tuple(normalize_host(h) for h in entity_hosts(entity))
    except Exception:  # noqa: BLE001
        return ()


def _seed_ports(entity: Entity | None) -> tuple[int, ...]:
    ports = [80, 443]
    if entity is not None and entity.type is T.URL:
        port = _port_of(entity.value)
        if port not in (None, -1):
            ports.append(int(port))
    return tuple(ports)


seed_ports = _seed_ports  # public name for the modules of the batch


def safe_get(
    ctx: Any,
    url: str,
    *,
    accept: str | None,
    max_bytes: int,
    entity: Entity | None = None,
    site_host: str = "",
    cdn_suffixes: Iterable[str] = (),
    method: str = "GET",
    max_hops: int = MAX_HOPS,
    ttl: int | None = None,
    same_site_only: bool = True,
) -> Fetched:
    """GET (or HEAD) ``url`` through ``ctx.http`` with redirects followed by hand: every hop is
    checked by :func:`check_target` before it is sent (and by the core SSRF guard after
    resolution); a refused hop is recorded, never requested. Classified answers (challenges,
    blocks, rate limits) come back as ``blocked`` - the caller decides; the core exceptions of a
    refused or failed request (PolicyError, Blocked, NetworkError, RequestCapReached, Cancelled...)
    propagate."""
    ent = entity if entity is not None else getattr(ctx, "entity", None)
    seed_hosts: tuple[str, ...] = ()
    try:
        from v3lum.core.http import entity_hosts

        seed_hosts = entity_hosts(ent) if ent is not None else ()
    except Exception:  # noqa: BLE001
        seed_hosts = ()
    site = site_host or (urlsplit(url).hostname or "")
    ports = _seed_ports(ent)
    internal = internal_seed_hosts(ctx, ent)
    current = url
    history: list[str] = []
    # the redirect answer last received: a refused next hop keeps it, so callers can tell "answered with a
    # redirect we did not follow" (status 3xx) from "nothing was sent" (status 0)
    last_status = 0
    last_headers: dict[str, str] = {}
    last_cached = False
    for _hop in range(max_hops + 1):
        reason = check_target(current, site_host=site, seed_hosts=seed_hosts, cdn_suffixes=cdn_suffixes, allowed_ports=ports,
                              same_site_only=same_site_only, internal_hosts=internal)
        if not reason and token_url(ctx, current):
            # A7 BR15 / GUARD-02: a URL the module built itself (an href, a src, a redirect target) that
            # probably carries a per-recipient token is never fetched without --confirm-url <url>
            reason = "the URL carries a probable per-recipient token (re-run with --confirm-url <url>)"
        if reason:
            if not history:
                return Fetched(url=current, refused=reason, refused_url=current)
            return Fetched(url=history[-1], status=last_status, headers=last_headers, history=history[:-1], from_cache=last_cached,
                           refused=f"redirect not followed: {reason}", refused_url=current)
        kw: dict[str, Any] = {"allow_redirects": False, "max_bytes": max_bytes + 1}
        if accept:
            kw["headers"] = {"Accept": accept}
        if ttl is not None:
            kw["ttl"] = ttl
        resp = ctx.http.request(method, current, **kw)
        body = bytes(resp.content or b"")
        headers = dict(resp.headers or {})
        status = int(resp.status or 0)
        cls = getattr(resp, "classification", None)
        if cls is not None:
            return Fetched(url=current, status=status, headers=headers, body=body[:max_bytes], history=history,
                           truncated=bool(resp.truncated), from_cache=bool(resp.from_cache),
                           blocked=f"{cls.reason_code}: {cls.reason}"[:300], blocked_status=str(cls.status), blocked_code=str(cls.reason_code))
        location = (headers.get("location") or "").strip()
        if status in _REDIRECTS and location:
            try:
                nxt = urljoin(current, location)
            except ValueError:
                return Fetched(url=current, status=status, headers=headers, history=history, refused="unparsable redirect target")
            if urlsplit(current).scheme == "https" and urlsplit(nxt).scheme == "http":
                return Fetched(url=current, status=status, headers=headers, history=history,
                               refused="redirect not followed: https->http downgrade", refused_url=nxt)
            history.append(current)
            current = nxt
            last_status, last_headers, last_cached = status, headers, bool(resp.from_cache)
            continue
        truncated = bool(resp.truncated) or len(body) > max_bytes
        page_block = detect_block(status, headers, body[:65536])
        return Fetched(url=current, status=status, headers=headers, body=body[:max_bytes], history=history, truncated=truncated,
                       from_cache=bool(resp.from_cache), blocked=page_block or "")
    return Fetched(url=history[-1] if history else url, status=last_status, headers=last_headers, history=history[:-1],
                   from_cache=last_cached, refused=f"more than {max_hops} redirects (not followed)", refused_url=current)


def fetch_homepage(ctx: Any, entity: Entity) -> Fetched:
    """The shared homepage fetch (P072 c2): one GET of the seed page (``https://<domain>/`` for a
    domain) without an Accept header, 1 MB and a 24 h TTL, so the HTTP cache serves it to every LIGHT
    module of the batch (and web_fingerprint) that asks for the same page."""
    url = seed_url(entity)
    return safe_get(ctx, url, accept=HOMEPAGE_ACCEPT, max_bytes=HOMEPAGE_MAX_BYTES, entity=entity, ttl=HOMEPAGE_TTL)


def cached_homepage(ctx: Any, entity: Entity) -> dict[str, Any] | None:
    """The cached homepage response of the shared fetch, read WITHOUT any request (P063 c1), as
    ``{url, status, headers (pairs, multi-valued), body}``; None when there is none.

    The frozen core gives disclosure-'none' modules no access to the HTTP cache (``ctx.http`` refuses
    them before the cache is consulted) and the cache drops Set-Cookie headers. Until the core offers
    a cache-only reader (requested: ``ctx.cached_response(url)`` returning a Response
    whose multi-valued headers are kept, P063 c2), this returns None and security_headers is SKIPPED
    'not_applicable'."""
    reader = getattr(type(ctx), "cached_response", None)
    if not callable(reader):
        return None
    try:
        resp = ctx.cached_response(seed_url(entity))
    except Exception:  # noqa: BLE001 - a failing reader means 'no cached response', never a request
        return None
    if resp is None:
        return None
    multi = getattr(resp, "header_list", None)
    headers = list(multi) if isinstance(multi, (list, tuple)) else headers_multi(getattr(resp, "headers", {}) or {})
    return {"url": str(getattr(resp, "url", "") or seed_url(entity)), "status": int(getattr(resp, "status", 0) or 0),
            "headers": headers, "body": bytes(getattr(resp, "content", b"") or b"")[:65536]}
