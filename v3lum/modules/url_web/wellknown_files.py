"""Well-known files (P065, batch p9-G03-1): security.txt (RFC 9116), robots.txt, sitemaps and the MTA-STS
policy (RFC 8461) of an analyst-typed seed - LIGHT, opt-in.

Final conditions (P065) and where they live:

1. LIGHT, ``default_enabled=False``, ``run_on='seeds'``: analyst-typed seeds only (the core LIGHT seed
   binding refuses pivots), after the entity's passive lane and through the hostile-host guard (engine
   two-phase scheduling, P376), inside the LIGHT budget (core: 25 requests per target host per scan).
2. A fixed request set: ``/.well-known/security.txt`` (the legacy ``/security.txt`` only when the first
   is absent), ``/robots.txt``, at most 5 sitemap files and ``https://mta-sts.<domain>/.well-known/
   mta-sts.txt`` (domain seeds; only when the ``_mta-sts`` TXT record is published or could not be
   verified). This module owns the single MTA-STS policy fetch and parser (:func:`parse_mta_sts`);
   email_security_posture (P002) stays DNS-only.
3. Every fetch goes through the safe-fetch helper (``light_fetch.safe_get``): public addresses on every
   hop (core SSRF guard), redirects followed by hand and re-checked, caps security.txt 64 KB,
   robots.txt 512 KB, sitemap 5 MB (a larger body is refused, never parsed truncated).
4. Sitemaps: no XML parser and no DTD/entity processing (any ``<!DOCTYPE``/``<!ENTITY`` is refused; a
   bounded ``<loc>`` extractor reads the values), ``.xml.gz`` through the bounded gzip reader (10 MB
   decompressed cap), sitemap-index recursion one level and 5 files in total, same-site URLs only,
   deduplicated, at most 200 url pivots with expand=False.
5. Soft-404 is decided from content (security.txt must be text/plain with a Contact line; HTML bodies
   are refused) with no random-path probe; 404/410 mean absent only when the server answered normally
   (a 404 carrying a challenge page is blocked).
6. RFC 9116 checks: Expires (required, single, parseable; expired -> an INFO finding), Contact schemes,
   Encryption, Canonical against the fetched URL, the PGP signature presence (cleartext extracted, no
   verification). Contacts are role contacts: e-mail pivots ``contact_email`` with expand=False and no
   mailbox check; they feed the takedown packet (P345). Phone contacts stay an attribute.
7. Disallow paths and sitemap URLs are url entities with expand=False and are never requested (forced
   browsing is the ACTIVE path module's, within scope). The archived robots.txt of the passive mode
   comes from archive_mining (P060).
8. Tests: the recorded security.txt and robots.txt, an XML-bomb sitemap, a gzip bomb and a soft-404 page
   (tests/modules/test_wellknown_files.py).
"""

from __future__ import annotations

import re
from collections.abc import Iterable, Mapping
from datetime import datetime, timezone
from typing import Any
from urllib.parse import unquote, urlsplit

from v3lum.config import SettingSpec
from v3lum.core.entities import Entity
from v3lum.core.entities import EntityType as T
from v3lum.core.http import Blocked, HttpError, NetworkError, PolicyError, QuotaExceeded, RateLimited, RequestCapReached
from v3lum.core.models import ModuleResult, Opsec
from v3lum.core.module import HealthCheck, HealthResult, Module, register
from v3lum.modules.url_web.light_fetch import (
    Fetched,
    content_type,
    detect_block,
    header_first,
    looks_like_html,
    safe_get,
    safe_gunzip,
    same_site,
    to_bytes,
    to_text,
    xml_unescape,
)

__all__ = [
    "MAX_ROBOTS_BYTES",
    "MAX_SECURITY_TXT_BYTES",
    "MAX_SITEMAP_BYTES",
    "WellknownFiles",
    "mta_sts_mx_matches",
    "mta_sts_policy_url",
    "parse_mta_sts",
    "parse_robots",
    "parse_security_txt",
    "parse_sitemap",
    "plan_sitemaps",
    "robots_pivots",
    "wellknown_absence",
]

MAX_SECURITY_TXT_BYTES = 64 * 1024  # P065 c3
MAX_ROBOTS_BYTES = 512 * 1024  # P065 c3
MAX_SITEMAP_BYTES = 5 * 1024 * 1024  # P065 c3
MAX_SITEMAP_DECOMPRESSED = 10 * 1024 * 1024  # P065 c4
MAX_SITEMAP_FILES = 5  # P065 c2/c4
MAX_SITEMAP_PIVOTS = 200  # P065 c4
MAX_ROBOTS_PIVOTS = 50
MAX_MTA_STS_BYTES = 64 * 1024
SECURITY_TXT_FIELDS = ("acknowledgments", "canonical", "contact", "encryption", "expires", "hiring", "policy", "preferred-languages", "csaf")
TEXT_ACCEPT = "text/plain,*/*;q=0.5"
XML_ACCEPT = "application/xml,text/xml;q=0.9,*/*;q=0.5"

# ======================================================================================
# parsers (pure; ported from the batch prep)
# ======================================================================================


def wellknown_absence(status: Any, headers: Any = None, body: Any = None) -> tuple[str, str | None]:
    """c5: ('present' | 'absent' | 'blocked' | 'redirect' | 'inconclusive', reason). 404/410 mean absent
    only when the server answered normally (no challenge/proxy page)."""
    block = detect_block(status, headers, body)
    try:
        st = int(status)
    except (TypeError, ValueError):
        return "inconclusive", "no status"
    if block:
        return "blocked", block
    if st == 200:
        return "present", None
    if st in (404, 410):
        return "absent", None
    if 300 <= st < 400:
        return "redirect", header_first(headers, "location")
    if st in (401, 403, 407, 429, 451):
        return "blocked", f"HTTP {st}"
    return "inconclusive", f"HTTP {st}"


def _strip_pgp(text: str) -> tuple[str, bool]:
    body = text.replace("\r\n", "\n")
    if "-----BEGIN PGP SIGNED MESSAGE-----" not in body[:200]:
        return body, False
    rest = body.split("-----BEGIN PGP SIGNED MESSAGE-----", 1)[1].partition("\n\n")[2]
    message = rest.split("-----BEGIN PGP SIGNATURE-----", 1)[0]
    return "\n".join(ln[2:] if ln.startswith("- ") else ln for ln in message.split("\n")), True


def _parse_iso(value: str) -> datetime | None:
    text = (value or "").strip()
    if not text:
        return None
    text = text[:-1] + "+00:00" if text[-1:] in "zZ" else text
    try:
        when = datetime.fromisoformat(text)
    except ValueError:
        return None
    return when if when.tzinfo else when.replace(tzinfo=timezone.utc)


def parse_security_txt(body: Any, *, status: Any = 200, headers: Any = None, fetched_url: str | None = None,
                       now: datetime | None = None) -> dict[str, Any]:
    """RFC 9116 security.txt -> fields, contacts, validation and pivot candidates (c5, c6). Soft-404
    from content: text/plain and at least one Contact line, else ``present`` False."""
    state, reason = wellknown_absence(status, headers, body)
    if state != "present":
        return {"present": False, "state": state, "reason": reason}
    raw = to_bytes(body)
    if len(raw) > MAX_SECURITY_TXT_BYTES:
        return {"present": False, "state": "inconclusive", "reason": "larger than 64 KB"}
    ctype = content_type(headers) if headers is not None else "text/plain"
    text = to_text(raw)
    if looks_like_html(text):
        return {"present": False, "state": "soft404", "reason": "HTML body (soft 404)"}
    if ctype and ctype != "text/plain":
        return {"present": False, "state": "soft404", "reason": f"content type {ctype} (RFC 9116 requires text/plain)"}
    text, signed = _strip_pgp(text)
    fields: dict[str, list[str]] = {}
    other: dict[str, list[str]] = {}
    bad_lines = 0
    for line in text.split("\n"):
        s = line.strip()
        if not s or s.startswith("#"):
            continue
        found = re.match(r"([A-Za-z0-9-]{1,40})\s*:\s*(.*)$", s)
        if not found:
            bad_lines += 1
            continue
        key, value = found.group(1).lower(), found.group(2).strip()[:500]
        (fields if key in SECURITY_TXT_FIELDS else other).setdefault(key, []).append(value)
    if not fields.get("contact"):
        return {"present": False, "state": "soft404", "reason": "no Contact line (not a security.txt)"}
    now = now or datetime.now(timezone.utc)
    errors: list[str] = []
    warnings: list[str] = []
    expires_raw = fields.get("expires") or []
    expires = _parse_iso(expires_raw[0]) if expires_raw else None
    if not expires_raw:
        errors.append("expires_missing")
    elif len(expires_raw) > 1:
        errors.append("expires_repeated")
    if expires_raw and expires is None:
        errors.append("expires_invalid")
    expired = bool(expires and expires < now)
    if expires and (expires - now).days > 366:
        warnings.append("expires_more_than_a_year_ahead")
    emails: list[str] = []
    urls: list[str] = []
    phones: list[str] = []
    contact_other: list[str] = []
    for contact in fields["contact"]:
        low = contact.lower()
        if low.startswith("mailto:"):
            addr = unquote(contact[7:].split("?", 1)[0]).strip()
            if "@" in addr:
                local, _, dom = addr.rpartition("@")
                emails.append(f"{local}@{dom.lower()}")
        elif low.startswith("https://"):
            urls.append(contact)
        elif low.startswith("http://"):
            urls.append(contact)
            warnings.append("contact_http_not_https")
        elif low.startswith("tel:"):
            phones.append(contact[4:])
        elif re.fullmatch(r"[^@\s]{1,64}@[A-Za-z0-9.-]{1,253}", contact):
            emails.append(contact)
            warnings.append("contact_without_mailto")
        else:
            contact_other.append(contact)
    canonical = fields.get("canonical") or []
    canonical_mismatch = bool(fetched_url and canonical and fetched_url not in canonical)
    if canonical_mismatch:
        warnings.append("canonical_mismatch")
    links = [{"url": u, "kind": "contact"} for u in urls]
    for kind in ("policy", "acknowledgments", "hiring", "csaf", "encryption"):
        links.extend({"url": u, "kind": kind} for u in fields.get(kind, []) if u.lower().startswith(("https://", "http://")))
    return {
        "present": True, "state": "present", "signed": signed, "fields": fields, "unknown_fields": sorted(other),
        "contacts": {"emails": emails, "urls": urls, "phones": phones, "other": contact_other},
        "expires": expires.isoformat() if expires else None, "expired": expired,
        "errors": errors, "warnings": warnings, "bad_lines": bad_lines, "canonical_mismatch": canonical_mismatch, "links": links,
    }


def parse_robots(body: Any, *, max_bytes: int = MAX_ROBOTS_BYTES) -> dict[str, Any]:
    """robots.txt -> groups, Disallow/Allow paths, Sitemap URLs, crawl-delay (line based, capped)."""
    raw = to_bytes(body)
    truncated = len(raw) > max_bytes
    text = to_text(raw[:max_bytes])
    if looks_like_html(text):
        return {"valid": False, "reason": "HTML body (soft 404)", "groups": [], "disallow": [], "allow": [], "sitemaps": [], "truncated": truncated}
    groups: list[dict[str, Any]] = []
    sitemaps: list[str] = []
    disallow: list[str] = []
    allow: list[str] = []
    seen_d: set[str] = set()
    seen_a: set[str] = set()
    current: dict[str, Any] | None = None
    last_was_ua = False
    lines = 0
    for line in text.splitlines():
        lines += 1
        s = line.split("#", 1)[0].strip()
        if not s or ":" not in s:
            continue
        key, value = (x.strip() for x in s.split(":", 1))
        key = key.lower()
        if key == "user-agent":
            if current is None or not last_was_ua:
                current = {"user_agents": [], "disallow": 0, "allow": 0, "crawl_delay": None}
                groups.append(current)
            current["user_agents"].append(value[:100])
            last_was_ua = True
            continue
        last_was_ua = False
        if key == "sitemap":
            if value and value not in sitemaps:
                sitemaps.append(value[:2048])
            continue
        if current is None:
            current = {"user_agents": ["*"], "disallow": 0, "allow": 0, "crawl_delay": None}
            groups.append(current)
        if key == "disallow" and value:
            current["disallow"] += 1
            if value not in seen_d:
                seen_d.add(value)
                disallow.append(value[:2048])
        elif key == "allow" and value:
            current["allow"] += 1
            if value not in seen_a:
                seen_a.add(value)
                allow.append(value[:2048])
        elif key == "crawl-delay":
            try:
                current["crawl_delay"] = float(value)
            except ValueError:
                pass
    return {"valid": True, "reason": None, "groups": groups, "disallow": disallow, "allow": allow, "sitemaps": sitemaps, "lines": lines,
            "truncated": truncated}


def robots_pivots(robots: Mapping[str, Any], base_url: str, cap: int = MAX_ROBOTS_PIVOTS) -> dict[str, Any]:
    """c7: literal Disallow paths -> url candidates (expand=False, never requested); wildcard/'$' rules
    stay patterns; Sitemap URLs split into same-site and foreign."""
    parts = urlsplit(base_url)
    origin = f"{parts.scheme or 'https'}://{parts.netloc}"
    urls: list[str] = []
    patterns: list[str] = []
    for path in robots.get("disallow") or []:
        if not path.startswith("/"):
            continue
        if "*" in path or path.endswith("$"):
            if path not in patterns:
                patterns.append(path)
            continue
        url = origin + path
        if url not in urls and len(urls) < cap:
            urls.append(url)
    same: list[str] = []
    foreign: list[str] = []
    for sm in robots.get("sitemaps") or []:
        try:
            sp = urlsplit(sm)
        except ValueError:
            continue
        (same if sp.scheme in ("http", "https") and same_site(sp.hostname or "", parts.hostname or "") else foreign).append(sm)
    return {"urls": urls, "patterns": patterns, "sitemaps_same_site": same, "sitemaps_foreign": foreign,
            "capped": len([p for p in robots.get("disallow") or [] if p.startswith("/") and "*" not in p and not p.endswith("$")]) > cap}


_LOC_RE = re.compile(r"<(?:([A-Za-z_][\w.-]{0,30}):)?loc\s*>\s*(?:<!\[CDATA\[\s*)?([^<\s]{1,2048})", re.I)
_MEDIA_LOC_PREFIXES = {"image", "video", "news", "xhtml"}


def parse_sitemap(data: Any, site_host: str, *, max_bytes: int = MAX_SITEMAP_BYTES, cap: int = MAX_SITEMAP_PIVOTS) -> dict[str, Any]:
    """c4: XML urlset/sitemapindex, a plain-text list or ``.xml.gz`` -> same-site URLs (deduplicated,
    capped) and child sitemaps (one level). No XML parser: any DOCTYPE/ENTITY is refused and ``<loc>``
    values come from a bounded extractor; gzip goes through the bounded reader (10 MB)."""
    raw = to_bytes(data)
    if raw.startswith(b"\x1f\x8b"):
        unpacked, reason = safe_gunzip(raw, MAX_SITEMAP_DECOMPRESSED)  # 10 MB decompressed cap (gzip bombs)
        if unpacked is None:
            return {"ok": False, "reason": reason, "kind": None, "urls": [], "children": [], "foreign_hosts": []}
        raw = unpacked
    elif len(raw) > max_bytes:
        return {"ok": False, "reason": "larger than 5 MB", "kind": None, "urls": [], "children": [], "foreign_hosts": []}
    text = to_text(raw)
    lowered = text.lower()
    if "<!doctype" in lowered or "<!entity" in lowered:
        return {"ok": False, "reason": "xml_dtd_refused", "kind": None, "urls": [], "children": [], "foreign_hosts": []}
    if looks_like_html(text):
        return {"ok": False, "reason": "HTML body (soft 404)", "kind": None, "urls": [], "children": [], "foreign_hosts": []}
    head = lowered[:4096]
    if "<" in head:
        if "<sitemapindex" in head or re.search(r"<\w+:sitemapindex", head):
            kind = "sitemapindex"
        elif "<urlset" in head or re.search(r"<\w+:urlset", head):
            kind = "urlset"
        else:
            return {"ok": False, "reason": "not a sitemap", "kind": None, "urls": [], "children": [], "foreign_hosts": []}
        locs = []
        for found in _LOC_RE.finditer(text):
            if (found.group(1) or "").lower() in _MEDIA_LOC_PREFIXES:
                continue  # image:loc / video:loc are assets, not pages
            value = found.group(2)
            locs.append(xml_unescape(value[:-3] if value.endswith("]]>") else value))
        closed = re.search(r"</(?:\w+:)?(?:urlset|sitemapindex)\s*>", text[-4096:]) is not None
    else:
        kind = "text"
        locs = [ln.strip() for ln in text.splitlines() if ln.strip().lower().startswith(("http://", "https://"))]
        closed = True
    urls: list[str] = []
    children: list[str] = []
    foreign: set[str] = set()
    seen: set[str] = set()
    total = 0
    for loc in locs:
        total += 1
        try:
            parts = urlsplit(loc)
        except ValueError:
            continue
        if parts.scheme not in ("http", "https") or not parts.hostname:
            continue
        if not same_site(parts.hostname, site_host):
            foreign.add(parts.hostname.lower())
            continue
        if loc in seen:
            continue
        seen.add(loc)
        if kind == "sitemapindex":
            children.append(loc)
        elif len(urls) < cap:
            urls.append(loc)
    return {"ok": True, "reason": None if closed else "truncated XML", "kind": kind, "locs_total": total, "urls": urls,
            "children": children[:50], "foreign_hosts": sorted(foreign)[:50], "capped": len(seen) > cap}


def plan_sitemaps(robots_sitemaps: Iterable[str], site_url: str, already: Iterable[str] = (), max_files: int = MAX_SITEMAP_FILES) -> list[str]:
    """c2/c4: at most 5 same-site sitemap files: the robots Sitemap lines first, else /sitemap.xml."""
    host = urlsplit(site_url).hostname or ""
    listed = list(robots_sitemaps or [])
    cands = [s for s in listed if urlsplit(s).scheme in ("http", "https") and same_site(urlsplit(s).hostname or "", host)]
    if not cands and not listed:
        parts = urlsplit(site_url)
        cands = [f"{parts.scheme or 'https'}://{parts.netloc}/sitemap.xml"]
    done = list(already)
    out: list[str] = []
    for s in cands:
        if s not in out and s not in done:
            out.append(s)
    return out[: max(0, max_files - len(done))]


def mta_sts_policy_url(domain: str) -> str:
    """c2: the single MTA-STS policy fetch this module owns."""
    return f"https://mta-sts.{domain.strip('.').lower()}/.well-known/mta-sts.txt"


def parse_mta_sts(body: Any, *, status: Any = 200, headers: Any = None, max_bytes: int = MAX_MTA_STS_BYTES) -> dict[str, Any]:
    """RFC 8461 policy -> {valid, version, mode, mx[], max_age, errors, warnings} (the one shared parser)."""
    state, reason = wellknown_absence(status, headers, body)
    if state != "present":
        return {"valid": False, "state": state, "reason": reason}
    raw = to_bytes(body)
    if len(raw) > max_bytes:
        return {"valid": False, "state": "inconclusive", "reason": "larger than 64 KB"}
    text = to_text(raw)
    if looks_like_html(text):
        return {"valid": False, "state": "soft404", "reason": "HTML body (soft 404)"}
    ctype = content_type(headers) if headers is not None else "text/plain"
    errors: list[str] = []
    warnings: list[str] = []
    if ctype and ctype != "text/plain":
        warnings.append(f"content type {ctype}")
    values: dict[str, list[str]] = {}
    for i, line in enumerate(text.split("\n"), 1):
        line = line[:-1] if line.endswith("\r") else line
        if not line.strip():
            continue
        if ":" not in line:
            errors.append(f"line {i}: not 'key: value'")
            continue
        key, value = line.split(":", 1)
        if key != key.strip():
            errors.append(f"line {i}: whitespace before the field name")
        values.setdefault(key.strip().lower(), []).append(value.strip()[:255])
    version = (values.get("version") or [None])[0]
    mode = (values.get("mode") or [None])[0]
    mx = values.get("mx") or []
    max_age_raw = (values.get("max_age") or [None])[0]
    if version != "STSv1":
        errors.append(f"version {version}")
    if mode not in ("enforce", "testing", "none"):
        errors.append(f"mode {mode}")
    if mode in ("enforce", "testing") and not mx:
        errors.append("mx missing")
    max_age = None
    if max_age_raw is None:
        errors.append("max_age missing")
    elif not re.fullmatch(r"\d{1,10}", max_age_raw) or int(max_age_raw) > 31_557_600:
        errors.append(f"max_age invalid ({max_age_raw[:20]})")
    else:
        max_age = int(max_age_raw)
        if max_age < 86400:
            warnings.append("max_age below one day")
    for pattern in mx:
        if not re.fullmatch(r"(\*\.)?([A-Za-z0-9-]{1,63}\.)+[A-Za-z0-9-]{1,63}\.?", pattern):
            errors.append(f"mx invalid ({pattern[:60]})")
    if mode == "none":
        warnings.append("mode none (policy withdrawn)")
    return {"valid": not errors, "state": "present", "version": version, "mode": mode, "mx": mx[:20], "max_age": max_age,
            "errors": errors, "warnings": warnings}


def mta_sts_mx_matches(pattern: str, host: str) -> bool:
    """RFC 8461 s4.1: '*.' matches exactly one left-most label."""
    p, h = pattern.lower().rstrip("."), host.lower().rstrip(".")
    if p.startswith("*."):
        rest = p[2:]
        return h.endswith("." + rest) and "." not in h[: -len(rest) - 1]
    return p == h


# ======================================================================================
# the module
# ======================================================================================


def _selftest(ctx: Any) -> HealthResult:
    """Offline self-test: the parsers on in-memory samples (no network)."""
    sec = parse_security_txt("Contact: mailto:security@example.com\nExpires: 2999-01-01T00:00:00Z\n", headers={"content-type": "text/plain"})
    bomb = parse_sitemap('<?xml version="1.0"?><!DOCTYPE x [<!ENTITY a "a">]><urlset><url><loc>https://example.com/&a;</loc></url></urlset>',
                         "example.com")
    sts = parse_mta_sts("version: STSv1\nmode: enforce\nmx: mail.example.com\nmax_age: 86400\n")
    if not sec.get("present") or bomb.get("reason") != "xml_dtd_refused" or not sts.get("valid"):
        return HealthResult("dead", "parser self-test failed")
    return HealthResult("ok", "security.txt, sitemap and MTA-STS parsers ok")


#: per-file states that mean "could not verify" (never an absence)
_COULD_NOT_VERIFY = frozenset({"blocked", "refused", "unreachable", "rate_limited", "quota", "inconclusive", "too_large"})


class _Stop(Exception):
    """The LIGHT budget (25 requests per host per scan) or the module cap stopped the fixed request set."""


@register
class WellknownFiles(Module):
    name = "wellknown_files"
    title = "Well-known files: security.txt, robots.txt, sitemaps, MTA-STS policy (LIGHT)"
    description = (
        "LIGHT, analyst-typed seeds only: reads /.well-known/security.txt (RFC 9116 checks, role contacts), robots.txt, at most "
        "5 sitemap files and the MTA-STS policy; disallowed paths and sitemap URLs are listed, never requested."
    )
    category = "url_web"
    accepts = {T.DOMAIN, T.URL}
    produces = {T.EMAIL, T.URL}
    run_on = "seeds"
    tags = {"free"}
    reference = "https://www.rfc-editor.org/rfc/rfc9116"
    terms = "open"  # own code; RFC 9116, RFC 8461, RFC 9309
    opsec = Opsec.LIGHT
    disclosure = "target"
    hosts = ()
    max_requests = 16  # security.txt (2) + robots.txt + 5 sitemaps + MTA-STS, plus manual redirect hops
    expected_latency = 9.0  # LIGHT pacing: 1 request per second per host
    timeout = 60.0
    min_interval = 1.0
    max_rate = 1.0
    cache_ttl = 86400
    max_pivots = 260
    default_enabled = False  # LIGHT is never default (A3)
    notice = (
        "LIGHT: a fixed set of ordinary GETs of public well-known files on the analyst-typed seed (ua_light). Disallowed paths and "
        "sitemap URLs are never requested (forced browsing is ACTIVE-only, within scope); security.txt contacts are role "
        "addresses, never checked."
    )
    settings = {
        "wellknown_files_max_sitemaps": SettingSpec(MAX_SITEMAP_FILES, "wellknown_files: sitemap files fetched per seed (at most 5, P065 c2)"),
    }

    @classmethod
    def health_check(cls) -> HealthCheck:
        return HealthCheck(offline=True, selftest=_selftest)

    # ---- one file ---------------------------------------------------------------------------
    def _get(self, ctx: Any, entity: Entity, url: str, *, accept: str, max_bytes: int, site: str) -> dict[str, Any]:
        """One safe fetch -> {state, fetched, reason}; refusals and failures are states, never absences."""
        try:
            fetched = safe_get(ctx, url, accept=accept, max_bytes=max_bytes, entity=entity, site_host=site, max_hops=3)
        except RequestCapReached:
            raise _Stop() from None
        except PolicyError as exc:
            if getattr(exc, "reason_code", "") == "scope":
                raise  # not an analyst-typed seed (or outside the scope): the whole run is refused, never a file state
            return {"state": "refused", "reason": str(exc)[:200], "url": url}
        except RateLimited as exc:
            return {"state": "rate_limited", "reason": str(exc)[:200], "url": url}
        except QuotaExceeded as exc:
            return {"state": "quota", "reason": str(exc)[:200], "url": url}
        except Blocked as exc:
            return {"state": "blocked", "reason": str(exc)[:200], "url": url, "code": getattr(exc, "reason_code", "challenge")}
        except (NetworkError, HttpError) as exc:
            return {"state": "unreachable", "reason": str(exc)[:200], "url": url}
        if fetched.refused:
            return {"state": "refused", "reason": fetched.refused, "url": fetched.refused_url or url, "fetched": fetched}
        if fetched.blocked:
            return {"state": "blocked", "reason": fetched.blocked, "url": fetched.url, "fetched": fetched,
                    "code": fetched.blocked_code or "challenge"}
        if fetched.truncated:
            return {"state": "too_large", "reason": f"larger than {max_bytes} bytes (not parsed)", "url": fetched.url, "fetched": fetched}
        state, reason = wellknown_absence(fetched.status, fetched.headers, fetched.body[:65536])
        return {"state": state, "reason": reason, "url": fetched.url, "fetched": fetched}

    def run(self, entity: Entity, ctx: Any) -> ModuleResult:
        res = self.result(entity)
        if not getattr(ctx, "is_seed", True):
            return res.mark("skipped", "LIGHT runs only on analyst-typed seeds, never on pivots (A7)", reason_code="scope")
        if entity.type is T.URL:
            parts = urlsplit(entity.value)
            origin = f"{parts.scheme}://{parts.netloc}"
            site = (parts.hostname or "").lower()
        else:
            site = entity.value.strip(".").lower()
            origin = f"https://{site}"
        summary: dict[str, Any] = {}
        try:
            self._security_txt(res, ctx, entity, origin, site, summary)
            robots = self._robots(res, ctx, entity, origin, site, summary)
            self._sitemaps(res, ctx, entity, origin, site, summary, robots)
            if entity.type is T.DOMAIN:
                self._mta_sts(res, ctx, entity, site, summary)
        except _Stop:
            summary["stopped"] = "LIGHT request budget reached (25 per target host per scan): the remaining files were not fetched"
            res.attr("wellknown_files", summary)
            return res.stop("request_cap")
        res.attr("wellknown_files", summary)
        return self._status(res, summary)

    # ---- security.txt (c5, c6) -----------------------------------------------------------------------
    def _security_txt(self, res: ModuleResult, ctx: Any, entity: Entity, origin: str, site: str, summary: dict[str, Any]) -> None:
        outcome = self._get(ctx, entity, f"{origin}/.well-known/security.txt", accept=TEXT_ACCEPT, max_bytes=MAX_SECURITY_TXT_BYTES, site=site)
        if outcome["state"] == "absent":
            legacy = self._get(ctx, entity, f"{origin}/security.txt", accept=TEXT_ACCEPT, max_bytes=MAX_SECURITY_TXT_BYTES, site=site)
            if legacy["state"] != "absent":
                outcome = legacy
        state = outcome["state"]
        record: dict[str, Any] = {"state": state, "url": outcome.get("url")}
        if state == "present":
            fetched: Fetched = outcome["fetched"]
            parsed = parse_security_txt(fetched.body, status=fetched.status, headers=fetched.headers, fetched_url=fetched.url, now=ctx.now())
            if not parsed["present"]:
                record.update({"state": parsed["state"], "reason": parsed["reason"]})
            else:
                record.update({
                    "signed": parsed["signed"], "expires": parsed["expires"], "expired": parsed["expired"],
                    "contacts": parsed["contacts"], "errors": parsed["errors"], "warnings": parsed["warnings"],
                    "canonical_mismatch": parsed["canonical_mismatch"], "unknown_fields": parsed["unknown_fields"][:20],
                    "fields": {k: v[:10] for k, v in parsed["fields"].items() if k != "contact"},
                })
                self._security_outputs(res, parsed, fetched.url)
        elif outcome.get("reason"):
            record["reason"] = outcome["reason"]
        summary["security_txt"] = record["state"]
        res.attr("security_txt", record)

    @staticmethod
    def _security_outputs(res: ModuleResult, parsed: Mapping[str, Any], url: str) -> None:
        for email in parsed["contacts"]["emails"][:10]:
            res.pivot(T.EMAIL, email, "contact_email", confidence="confirmed", expand=False,
                      note="security.txt role contact (RFC 9116): for responsible disclosure and takedown requests (P345); never checked")
        for link in parsed["links"][:20]:
            res.pivot(T.URL, link["url"], "security_txt_link", confidence="confirmed", expand=False,
                      note=f"security.txt {link['kind']} URL: listed, not requested")
        if parsed["expired"]:
            res.finding(
                "security.txt expired",
                "info",
                f"{url}: Expires {parsed['expires']} is in the past; RFC 9116 says an expired file must not be relied on. Contacts "
                "are still listed for disclosure.",
                confidence="confirmed",
                criterion="RFC 9116 s2.5.5: the Expires field is in the past",
                tags=["misconfiguration"],
                references=("https://www.rfc-editor.org/rfc/rfc9116#section-2.5.5",),
            )

    # ---- robots.txt (c7) -----------------------------------------------------------------------------
    def _robots(self, res: ModuleResult, ctx: Any, entity: Entity, origin: str, site: str, summary: dict[str, Any]) -> dict[str, Any] | None:
        outcome = self._get(ctx, entity, f"{origin}/robots.txt", accept=TEXT_ACCEPT, max_bytes=MAX_ROBOTS_BYTES, site=site)
        record: dict[str, Any] = {"state": outcome["state"], "url": outcome.get("url")}
        parsed = None
        if outcome["state"] == "present":
            parsed = parse_robots(outcome["fetched"].body)
            if not parsed["valid"]:
                record.update({"state": "soft404", "reason": parsed["reason"]})
                parsed = None
            else:
                pivots = robots_pivots(parsed, origin + "/")
                record.update({
                    "groups": len(parsed["groups"]), "disallow": len(parsed["disallow"]), "allow": parsed["allow"][:50],
                    "patterns": pivots["patterns"][:100], "sitemaps": parsed["sitemaps"][:20], "sitemaps_foreign": pivots["sitemaps_foreign"][:20],
                    "crawl_delay": next((g["crawl_delay"] for g in parsed["groups"] if g.get("crawl_delay") is not None), None),
                    "truncated": parsed["truncated"],
                })
                for url in pivots["urls"]:
                    res.pivot(T.URL, url, "robots_path", confidence="confirmed", expand=False,
                              note="robots.txt Disallow path: listed, never requested (forced browsing is ACTIVE-only)")
        elif outcome.get("reason"):
            record["reason"] = outcome["reason"]
        summary["robots_txt"] = record["state"]
        res.attr("robots_txt", record)
        return parsed

    # ---- sitemaps (c4) ---------------------------------------------------------------------------------
    def _sitemaps(self, res: ModuleResult, ctx: Any, entity: Entity, origin: str, site: str, summary: dict[str, Any],
                  robots: Mapping[str, Any] | None) -> None:
        try:
            limit = max(0, min(MAX_SITEMAP_FILES, int(ctx.setting("wellknown_files_max_sitemaps", MAX_SITEMAP_FILES))))
        except (TypeError, ValueError):
            limit = MAX_SITEMAP_FILES
        queue = plan_sitemaps((robots or {}).get("sitemaps") or [], origin + "/", max_files=limit)
        files: list[dict[str, Any]] = []
        urls: list[str] = []
        foreign: set[str] = set()
        done: list[str] = []
        depth = {u: 0 for u in queue}
        capped = False
        while queue and len(done) < limit:
            url = queue.pop(0)
            done.append(url)
            outcome = self._get(ctx, entity, url, accept=XML_ACCEPT, max_bytes=MAX_SITEMAP_BYTES, site=site)
            row: dict[str, Any] = {"url": outcome.get("url") or url, "state": outcome["state"]}
            if outcome["state"] == "present":
                parsed = parse_sitemap(outcome["fetched"].body, site)
                row.update({"kind": parsed.get("kind"), "locs": parsed.get("locs_total"), "reason": parsed.get("reason")})
                if parsed["ok"]:
                    foreign.update(parsed.get("foreign_hosts") or [])
                    capped = capped or bool(parsed.get("capped"))
                    for u in parsed["urls"]:
                        if u not in urls and len(urls) < MAX_SITEMAP_PIVOTS:
                            urls.append(u)
                        elif u not in urls:
                            capped = True
                    if depth.get(url, 0) == 0:  # a sitemap index: one level of children, within the 5-file total
                        for child in parsed["children"]:
                            if child not in done and child not in queue:
                                queue.append(child)
                                depth[child] = 1
                    else:
                        row["children_ignored"] = len(parsed["children"])
                else:
                    row["state"] = "refused" if parsed["reason"] in ("xml_dtd_refused", "gzip_bomb") else "invalid"
            elif outcome.get("reason"):
                row["reason"] = outcome["reason"]
            files.append(row)
        if queue:
            files.extend({"url": u, "state": "not_fetched", "reason": "at most 5 sitemap files per seed (P065 c2)"} for u in queue[:20])
        for url in urls:
            res.pivot(T.URL, url, "sitemap_url", confidence="confirmed", expand=False, note="sitemap URL: listed, never requested")
        if files:
            res.attr("sitemaps", {"files": files, "urls": len(urls), "capped": capped, "foreign_hosts": sorted(foreign)[:50]})
        summary["sitemaps"] = sum(1 for f in files if f["state"] == "present")
        failed = sorted({f["state"] for f in files if f["state"] in _COULD_NOT_VERIFY})
        if failed:
            summary["sitemaps_failed"] = failed

    # ---- MTA-STS (c2) ------------------------------------------------------------------------------------
    def _mta_sts(self, res: ModuleResult, ctx: Any, entity: Entity, domain: str, summary: dict[str, Any]) -> None:
        txt = None
        try:
            answer = ctx.dns.query(f"_mta-sts.{domain}", "TXT")
            if answer.ok:
                records = [str(r).strip('"') for r in answer.records]
                txt = next((r for r in records if r.lower().startswith("v=stsv1")), "")
            elif answer.nxdomain or answer.nodata:
                txt = ""
        except Exception:  # noqa: BLE001 - DNS could not verify: fetch the policy anyway (it is in the fixed set)
            txt = None
        record: dict[str, Any] = {"txt": txt}
        if txt == "":
            record.update({"state": "not_published", "reason": "no v=STSv1 TXT record at _mta-sts (policy not fetched)"})
        else:
            outcome = self._get(ctx, entity, mta_sts_policy_url(domain), accept=TEXT_ACCEPT, max_bytes=MAX_MTA_STS_BYTES, site=domain)
            record.update({"state": outcome["state"], "url": outcome.get("url")})
            if outcome["state"] == "present":
                fetched: Fetched = outcome["fetched"]
                parsed = parse_mta_sts(fetched.body, status=fetched.status, headers=fetched.headers)
                record.update({k: v for k, v in parsed.items() if k != "reason"})
                if parsed.get("reason"):
                    record["reason"] = parsed["reason"]
            elif outcome.get("reason"):
                record["reason"] = outcome["reason"]
        summary["mta_sts"] = record["state"]
        res.attr("mta_sts_policy", record)

    # ---- outcome (rule 5) ----------------------------------------------------------------------------------
    @staticmethod
    def _status(res: ModuleResult, summary: Mapping[str, Any]) -> ModuleResult:
        states = [v for k, v in summary.items() if k in ("security_txt", "robots_txt", "mta_sts") and isinstance(v, str)]
        found = any(s == "present" for s in states) or bool(summary.get("sitemaps"))
        # a sitemap that could not be read counts like any other file of the fixed set (rule 5)
        failed = [s for s in [*states, *(summary.get("sitemaps_failed") or [])] if s in _COULD_NOT_VERIFY]
        if found:
            if failed:
                res.partial = True
                res.error = "partial: some files could not be verified (" + ", ".join(sorted(set(failed))) + ")"
            return res
        if failed:
            if all(s == "blocked" for s in failed):
                return res.mark("blocked", "could not verify: the site answered block pages", reason_code="challenge")
            if all(s == "rate_limited" for s in failed):
                return res.mark("rate_limited", "could not verify: rate limited", reason_code="rate_limited")
            return res.mark("error", "could not verify: " + ", ".join(sorted(set(failed))), reason_code="error")
        return res.mark("empty")  # the server answered normally: none of the files is published
