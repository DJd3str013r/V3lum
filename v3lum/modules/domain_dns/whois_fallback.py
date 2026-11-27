"""WHOIS fallback for TLDs without RDAP (P343 whois_fallback and whois_fallback_public).

Registration data (registrar, dates, nameservers, status, DNSSEC) for names whose TLD publishes no
usable RDAP service in the IANA bootstrap (.ru, .su, .cn, .de, .jp, .io...), and a second path for
.br names on explicit analyst selection.

Final conditions (council #1, P343) and where they live:

1. ``applies()`` is decided only from the shared IANA RDAP bootstrap helper of P003
   (:func:`v3lum.modules.domain_dns.rdap.bootstrap_lookup`, the registered ``iana_rdap_dns.json``
   dataset), never from another module's runtime result (:func:`applicability`): a TLD without an
   RDAP service (``no_rdap``) or with an http-only one (``rdap_http_only``: https downgrades are
   refused, AR01) applies; .br applies only on explicit selection (``-M``/``v3lum run``) of an
   analyst-typed seed (``br_second_path``). An unreadable bootstrap is UNAVAILABLE ``dataset``.
2. Order: the self-hosted who-dat instance (MIT) when setting ``whodat_url`` is configured (https
   only, provider ``whodat_selfhosted``), then port-43 WHOIS to the registry server taken from the
   IANA root-zone page (:func:`parse_iana_root_db`, kept 7 days in the module state: one request
   per TLD per week). The public who-dat.as93.net instance is the separate module
   :class:`WhoisFallbackPublic` (provider ``as93``: unknown tier, default off, excluded at
   TLP:AMBER and above by the policy gate).
3. Port 43 goes only through a core ``whois43`` helper on the socket connector (10 s timeout, 64 KB
   cap, at most one referral hop; UNAVAILABLE when a proxy is configured or 43/tcp is blocked). The
   helper is not in this build (core request of batch p2-G01-4): the module calls
   ``ctx.net.whois43(server, query, timeout=10.0, max_bytes=65536)`` when the core offers it and
   otherwise reports UNAVAILABLE ``offline`` with the IANA facts (registry WHOIS server, registry
   website as a manual link). Registry terms: per-query lookups only, raw text never republished.
   A referral hop goes to a registrar WHOIS server (not a registry: unregistered, unknown tier), so
   it is followed only for thin records (no registrar or creation date) at TLP:CLEAR/GREEN with
   ``--allow-unknown`` (A8); otherwise the referral is recorded, not queried.
4. Registrar, dates, nameservers, status, DNSSEC and meta.source/server are kept through allow-lists
   (:func:`parse_whodat`, :func:`parse_whois_text`); personal contact fields (registro.br exposes
   tech-contact names/e-mails) are dropped at ingestion, before ``res.raw`` and evidence: the
   evidence holds the allow-listed record and :func:`minimise_whois_text` only, and
   ``dropped_fields`` lists key names, never values.
5. WHOIS/who-dat output never creates CNPJ pivots: the only pivots are nameserver domains
   (``expand=False``); the .br -> CNPJ pivot stays RDAP-only (P003 publicIds). Kept strings
   carrying a CPF/CNPJ-shaped number are dropped.
6. Tests replay the recorded ``gaps__whois_fallback`` research sample and a referral case.
"""

from __future__ import annotations

import copy
import html as _html
import json
import re
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from typing import Any
from urllib.parse import quote, urlsplit

from v3lum.config import SettingSpec
from v3lum.core import psl
from v3lum.core.entities import Entity
from v3lum.core.entities import EntityType as T
from v3lum.core.http import (
    AuthRequired,
    Blocked,
    DeadlineExceeded,
    HttpError,
    NetworkError,
    OfflineError,
    PolicyError,
    QuotaExceeded,
    RateLimited,
)
from v3lum.core.models import ModuleResult, Opsec
from v3lum.core.module import HealthCheck, HealthResult, Module, register
from v3lum.modules.domain_dns.rdap import BootstrapUnavailable, bootstrap_lookup

SRC_ROOT_DB = "iana.whois_fallback_root_db"
SRC_BOOTSTRAP = "iana.tlds"  # the P003 bootstrap dataset (iana_rdap_dns.json)
SRC_WHODAT = "whodat_selfhosted.api"
SRC_PORT43 = "registry_whois.port43"
SRC_PUBLIC = "as93.whodat"
SETTING_WHODAT = "whodat_url"

IANA_ROOT_DB_URL = "https://www.iana.org/domains/root/db/{tld}.html"
IANA_ROOT_DB_TTL_S = 7 * 24 * 3600  # FC2: the IANA root-zone answer is reused for 7 days
STATE_PREFIX = "iana_root_db:"
PUBLIC_URL = "https://who-dat.as93.net/{domain}"
WHOIS43_TIMEOUT_S = 10.0  # FC3
WHOIS43_CAP_BYTES = 64 * 1024  # FC3
WHOIS43_MAX_REFERRALS = 1  # FC3: at most one referral hop
NS_PIVOT_CAP = 13
STATUS_CAP = 20
REFERRAL_TLPS = ("clear", "green")  # a registrar WHOIS server is an unknown-tier party (A8)
BLOCKED_CODES = ("challenge", "geo_block", "login_wall", "circuit", "hostile_host")


# ======================================================================================
# shared helpers
# ======================================================================================


def to_text(raw: Any) -> str:
    """bytes/str/None -> str (UTF-8 with replacement; CRLF -> LF). Never raises."""
    if raw is None:
        return ""
    if isinstance(raw, (bytes, bytearray)):
        raw = bytes(raw).decode("utf-8", errors="replace")
    if not isinstance(raw, str):
        raw = str(raw)
    return raw.replace("\r\n", "\n").replace("\r", "\n")


_HTML_RE = re.compile(r"^\s*(<!doctype\s+html|<html\b|<head\b|<body\b|<\?xml|<!--|<title\b)", re.I)
_HOST_RE = re.compile(r"^(?=.{4,253}$)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+(?:[a-z]{2,63}|xn--[a-z0-9-]{1,59})$")
_INTERNAL_SUFFIXES = (".local", ".internal", ".lan", ".corp", ".home", ".localhost", ".intranet", ".private", ".localdomain", ".home.arpa")
# a CPF (11 digits) or CNPJ (14 digits) shaped number, formatted or not (team rule 4, P343 FC5)
_DOC_ID_RE = re.compile(r"(?<![0-9A-Za-z])(?:\d{2}\.?\d{3}\.?\d{3}/?\d{4}-?\d{2}|\d{3}\.?\d{3}\.?\d{3}-?\d{2})(?![0-9A-Za-z])")


def looks_like_html(text: Any) -> bool:
    """True when a body is an HTML/XML page (block page, captive portal, challenge, error page)."""
    return bool(_HTML_RE.match(to_text(text)[:512]))


def valid_hostname(value: Any) -> str | None:
    """A public-looking DNS hostname (no IP literal, single label or internal suffix) or None."""
    if not isinstance(value, str):
        return None
    host = value.strip().rstrip(".").lower()
    if not _HOST_RE.match(host) or host.endswith(_INTERNAL_SUFFIXES):
        return None
    return host


def tld_of(domain: Any) -> str | None:
    """'Example.COM.' -> 'com'; IDN labels -> punycode ('рф' -> 'xn--p1ai'); invalid -> None."""
    if not isinstance(domain, str):
        return None
    d = domain.strip().rstrip(".").lower()
    if not d or "." not in d or any(ch.isspace() for ch in d):
        return None
    label = d.rsplit(".", 1)[1]
    try:
        label = label.encode("idna").decode("ascii")
    except UnicodeError:
        return None
    return label if re.fullmatch(r"[a-z]{2,63}|xn--[a-z0-9-]{1,59}", label) else None


def registrable(domain: str) -> bool:
    """WHOIS is asked for registered names only: a known TLD and the PSL registrable domain itself."""
    tld = tld_of(domain)
    return bool(tld and psl.is_known_tld(tld) and psl.registrable_domain(domain) == domain)


def _ace(name: Any) -> str | None:
    """A domain in its canonical (punycode, lower-case) form, as V3LUM entities store it."""
    if not isinstance(name, str) or not name.strip():
        return None
    ent = Entity.try_make(T.DOMAIN, name.strip().rstrip("."))
    return str(ent.value) if ent is not None else None


def _clean(value: Any, limit: int = 200) -> str | None:
    """A kept free-text value: stripped, bounded, never carrying a CPF/CNPJ-shaped number (FC5)."""
    if not isinstance(value, str):
        return None
    text = " ".join(value.split())[:limit]
    if not text or _DOC_ID_RE.search(text):
        return None
    return text


def _add_unique(items: list[Any], value: Any) -> None:
    if value and value not in items:
        items.append(value)


def _short(exc: BaseException, limit: int = 160) -> str:
    text = str(exc) or type(exc).__name__
    return text if len(text) <= limit else text[: limit - 3] + "..."


# ======================================================================================
# FC1: applicability from the P003 bootstrap helper only
# ======================================================================================


@dataclass(frozen=True)
class Applicability:
    """Whether the WHOIS fallback applies to a name: ``applies`` True / False / None (the
    bootstrap could not be read: could not decide), the path and a readable reason."""

    applies: bool | None
    path: str = ""
    reason: str = ""


def applicability(ctx: Any, domain: str, *, explicit: bool = False) -> Applicability:
    """FC1: decided only from the shared IANA RDAP bootstrap helper (P003), never from another
    module's runtime result. ``explicit``: the analyst selected the module for this typed seed."""
    tld = tld_of(domain)
    if not tld:
        return Applicability(False, "", "not a domain name")
    try:
        match = bootstrap_lookup(ctx, "dns", domain)
    except BootstrapUnavailable as exc:
        return Applicability(None, "", f"{_short(exc)}: cannot decide whether the WHOIS fallback applies (run: v3lum data update iana_rdap_dns.json)")
    if match is None:
        return Applicability(True, "no_rdap", f"no RDAP service for .{tld} in the IANA bootstrap")
    if match.http_only:
        return Applicability(True, "rdap_http_only", f"the IANA bootstrap lists only an http:// RDAP service for .{tld} (https downgrade refused)")
    if tld == "br":
        if explicit:
            return Applicability(True, "br_second_path", "explicit analyst selection: second .br path (no CNPJ pivots: those stay RDAP-only)")
        return Applicability(False, "", f"RDAP serves .br ({match.host}); the second .br path runs only on explicit analyst selection of a typed seed")
    return Applicability(False, "", f"RDAP serves .{tld} ({match.host}): the rdap module answers it")


# ======================================================================================
# FC2: the IANA root zone database page of a TLD
# ======================================================================================


def iana_root_db_url(tld: Any) -> str | None:
    """'ru' -> https://www.iana.org/domains/root/db/ru.html (None for an invalid label)."""
    label = tld_of("x." + tld) if isinstance(tld, str) else None
    return IANA_ROOT_DB_URL.format(tld=label) if label else None


_TITLE_RE = re.compile(r"(?is)<title>\s*\.?(\S+?)\s+Top-Level Domain\s*</title>")


def _html_to_text(text: str) -> str:
    text = re.sub(r"(?is)<(script|style)\b.*?</\1>", " ", text)
    text = re.sub(r"(?s)<[^>]+>", "\n", text)
    return _html.unescape(text)


def parse_iana_root_db(page: Any, tld: str | None = None) -> dict[str, Any]:
    """IANA root-zone page (HTML, or the flattened text of a research snippet) ->
    {'tld', 'title_tld', 'whois_server', 'rdap_base_urls', 'website', 'status', 'reason'}.

    status: ok | no_whois_server ('-' on the page, e.g. .gr) | error. The page must be the one of
    the requested TLD and the WHOIS server a public hostname."""
    text = to_text(page)
    out: dict[str, Any] = {"tld": tld, "title_tld": None, "whois_server": None, "rdap_base_urls": [], "website": None, "status": "error", "reason": None}
    if not text.strip():
        out["reason"] = "empty page"
        return out
    m = _TITLE_RE.search(text)
    if m:
        title = m.group(1).lower()
        try:
            title = title.encode("idna").decode("ascii")
        except UnicodeError:
            pass
        out["title_tld"] = title
        if tld and title != tld.lower():
            out["reason"] = f"page is for .{title}, not .{tld}"
            return out
    flat = re.sub(r"\s+", " ", _html_to_text(text))
    whois = re.search(r"WHOIS Server\s*:?\s*(\S+)", flat, re.I)
    rdap = re.search(r"RDAP (?:Base URLs?|Server)\s*:?\s*(.*?)(?:WHOIS Server|Technical Status|$)", flat, re.I)
    site = re.search(r"Website\s*:?\s*(https?://[^\s<>\"']+)", flat, re.I)
    if rdap:
        out["rdap_base_urls"] = re.findall(r"https?://[^\s<>\"']+", rdap.group(1))[:5]
    if site:
        out["website"] = site.group(1)[:200]
    if not whois:
        out["reason"] = "no WHOIS Server row (not an IANA root-zone page?)"
        return out
    value = whois.group(1).strip()
    if value == "-":
        out["status"], out["reason"] = "no_whois_server", f"no WHOIS server published for .{out['title_tld'] or tld or '?'}"
        return out
    host = valid_hostname(value)
    if not host:
        out["reason"] = f"unusable WHOIS server value {value[:64]!r}"
        return out
    out["whois_server"], out["status"] = host, "ok"
    return out


# ======================================================================================
# FC3: port 43
# ======================================================================================

_WHOIS_QUERY_FORMAT = {
    "whois.denic.de": "-T dn,ace {d}",  # DENIC: domain object, ACE form
    "whois.jprs.jp": "{d}/e",  # JPRS: English output
    "whois.verisign-grs.com": "domain {d}",  # exact domain records only
}
_QUERY_NAME_RE = re.compile(r"(?=.{3,253}$)(?:[a-z0-9_](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+(?:[a-z]{2,63}|xn--[a-z0-9-]{1,59})")


def whois_query(server: Any, domain: Any) -> str | None:
    """The single query line (without CRLF) sent on port 43, or None for an unsafe value: the
    domain is IDNA-encoded and must be a plain hostname (no spaces, CR or LF: no injection)."""
    if not isinstance(domain, str):
        return None
    d = domain.strip().rstrip(".").lower()
    try:
        d = ".".join(label.encode("idna").decode("ascii") for label in d.split("."))
    except UnicodeError:
        return None
    if not _QUERY_NAME_RE.fullmatch(d):
        return None
    fmt = _WHOIS_QUERY_FORMAT.get(str(server or "").lower(), "{d}")
    return fmt.format(d=d)


def decode_whois(data: Any, cap: int = WHOIS43_CAP_BYTES) -> tuple[str, bool]:
    """Raw port-43 bytes -> (text, truncated): 64 KB cap, UTF-8 else Latin-1, never raises."""
    if isinstance(data, str):
        data = data.encode("utf-8", errors="replace")
    if not isinstance(data, (bytes, bytearray)):
        return "", False
    blob = bytes(data)
    truncated = len(blob) > cap
    chunk = blob[:cap]
    try:
        text = chunk.decode("utf-8")
    except UnicodeDecodeError:
        try:
            chunk[:-4].decode("utf-8")
            text = chunk.decode("utf-8", errors="ignore") if truncated else chunk.decode("latin-1")
        except UnicodeDecodeError:
            text = chunk.decode("latin-1")
    return text.replace("\r\n", "\n").replace("\r", "\n"), truncated


def port43_unavailable(ctx: Any) -> str:
    """FC3: why port 43 cannot be used in this run ('' when the core helper may be called)."""
    proxy = ""
    try:
        proxy = str(ctx.setting("proxy", "") or "").strip()
    except Exception:  # noqa: BLE001 - a settings problem must not break the run
        proxy = ""
    if proxy:
        return "port 43 is not used when a proxy is configured (HTTPS-only egress): could not verify"
    if not callable(getattr(getattr(ctx, "net", None), "whois43", None)):
        return "port-43 WHOIS needs the core whois43 helper on the socket connector, which this build does not have: could not verify"
    return ""


# ---- WHOIS text (allow-list, drop at ingestion) -----------------------------------------------

_W_DOMAIN = {"domain", "domain name", "domain_name", "domainname"}
_W_REGISTRAR = {"registrar", "sponsoring registrar", "registrar name", "registrar organization", "registrar organisation"}
_W_REGISTRAR_IANA = {"registrar iana id", "sponsoring registrar iana id"}
_W_REGISTRAR_URL = {"registrar url", "referral url", "registrar website"}
_W_REGISTRAR_ABUSE = {"registrar abuse contact email"}
_W_REFERRAL = {"registrar whois server", "whois server", "refer", "whois", "referralserver"}
_W_CREATED = {"creation date", "created", "created on", "created date", "registration time", "registration date",
              "registered", "registered on", "domain registration date", "domain create date"}
_W_UPDATED = {"updated date", "updated", "last updated", "last-update", "last modified", "last-modified", "changed",
              "modified", "last updated on", "domain last updated date"}
_W_EXPIRES = {"registry expiry date", "registrar registration expiration date", "expiration date", "expiration time",
              "expiry date", "expires", "expires on", "expire", "expire date", "paid-till", "renewal date", "domain expiration date"}
_W_NS = {"name server", "nameserver", "nameservers", "name servers", "nserver"}
_W_STATUS = {"domain status", "status", "state", "registration status"}
_W_DNSSEC = {"dnssec"}
_W_DS = {"dnssec ds data", "ds record", "dsrecord", "ds-rdata"}
_W_DNSKEY = {"dnskey"}
_W_KEEP = (_W_DOMAIN | _W_REGISTRAR | _W_REGISTRAR_IANA | _W_REGISTRAR_URL | _W_REGISTRAR_ABUSE | _W_REFERRAL | _W_CREATED
           | _W_UPDATED | _W_EXPIRES | _W_NS | _W_STATUS | _W_DNSSEC | _W_DS | _W_DNSKEY)

_LINE_RE = re.compile(r"^\s*([A-Za-z][A-Za-z0-9 ._/()-]{0,60}?)\s*:\s*(.*?)\s*$")
_NOT_FOUND_RE = re.compile(r"no match for|no entries found|no matching record|^\s*%?\s*not found|domain not found|"
                           r"no data found|object does not exist|status:\s*(free|available)|is available for registration|"
                           r"no match!!|%error:101", re.I | re.M)
_RATE_RE = re.compile(r"query rate limit exceeded|rate limit exceeded|limit exceeded|too many (queries|requests)|"
                      r"exceeded the (maximum|allowed)|number of allowed queries exceeded|quota exceeded|"
                      r"request rate is too high|whois limit exceeded", re.I)
_BLOCK_RE = re.compile(r"access denied|you have been (banned|blocked)|ip address (is|has been) (blocked|banned|blacklisted)|blacklisted", re.I)
_DNSSEC_YES = {"signeddelegation", "signed", "yes", "active", "true"}
_DNSSEC_NO = {"unsigned", "unsigned delegation", "no", "inactive", "false", "not signed"}


def norm_date(value: Any) -> str | None:
    """Registry date -> ISO 8601 ('YYYY-MM-DD' or 'YYYY-MM-DDTHH:MM:SS[Z]'), else None.

    '19990221 #11026' (registro.br), ISO with Z/offsets (converted to UTC), naive registry-local
    times kept without zone (CNNIC), '21-Feb-1999', '1999.02.21'."""
    if not isinstance(value, str):
        return None
    v = value.split("#", 1)[0].strip()
    if not v:
        return None
    m = re.fullmatch(r"(\d{4})(\d{2})(\d{2})", v) or re.fullmatch(r"(\d{4})[-.](\d{2})[-.](\d{2})", v)
    if m:
        return _valid_date("-".join(m.groups()))
    m = re.fullmatch(r"(\d{4}-\d{2}-\d{2})[T ](\d{2}:\d{2}:\d{2})(?:\.\d+)?\s*(Z|UTC|[+-]\d{2}:?\d{2})?", v, re.I)
    if m:
        day, clock, tz = m.groups()
        try:
            dt = datetime.strptime(day + "T" + clock, "%Y-%m-%dT%H:%M:%S")
        except ValueError:
            return None
        if not tz:
            return dt.strftime("%Y-%m-%dT%H:%M:%S")
        if tz.upper() in ("Z", "UTC"):
            return dt.strftime("%Y-%m-%dT%H:%M:%SZ")
        sign = 1 if tz[0] == "+" else -1
        digits = tz[1:].replace(":", "")
        offset = timedelta(hours=int(digits[:2]), minutes=int(digits[2:4]))
        return (dt - sign * offset).strftime("%Y-%m-%dT%H:%M:%SZ")
    m = re.fullmatch(r"(\d{1,2})-([A-Za-z]{3})-(\d{4})", v)
    if m:
        try:
            return datetime.strptime(v.title(), "%d-%b-%Y").strftime("%Y-%m-%d")
        except ValueError:
            return None
    return None


def _valid_date(text: str) -> str | None:
    try:
        datetime.strptime(text, "%Y-%m-%d")
        return text
    except ValueError:
        return None


def _empty_record(via: str) -> dict[str, Any]:
    return {
        "domain": None, "query": None, "registered": None, "registrar": None,
        "dates": {"created": None, "updated": None, "expires": None},
        "nameservers": [], "status": [], "dnssec": {"signed": None, "ds": []}, "contacts_redacted": {},
        "referral": None, "meta": {"source": None, "server": None, "via": via, "referral": None, "cached": None},
        "domain_mismatch": False, "partial": False, "error": None, "dropped_fields": [],
    }


def _referral_host(value: str) -> str | None:
    v = value.strip()
    if not v or v.lower().startswith("rwhois://"):
        return None
    v = re.sub(r"^whois://", "", v, flags=re.I).split("/", 1)[0]
    v = re.sub(r":43$", "", v)
    return valid_hostname(v)


def is_role_address(email: Any) -> bool:
    """A role mailbox (abuse@, abusecomplaints@, hostmaster@...) kept as the registrar's abuse
    contact; any other address is personal and dropped (FC4)."""
    if not isinstance(email, str) or email.count("@") != 1 or any(c.isspace() for c in email.strip()):
        return False
    local = email.strip().split("@", 1)[0].lower()
    return any(tok in local for tok in ("abuse", "complaint", "hostmaster", "noc", "security", "legal", "compliance", "domain", "registrar", "report"))


def parse_whois_text(text: Any, server: str | None = None, domain: str | None = None) -> dict[str, Any]:
    """FC4: port-43 WHOIS text -> normalised record through an allow-list (drop at ingestion).

    Kept: domain, registrar (name, IANA id, URL, WHOIS server, role abuse mailbox), dates,
    nameservers, status, DNSSEC, meta.source='whois'/meta.server and the referral server. Owner,
    ownerid (CNPJ/CPF), responsible, person, e-mail, phone, address, org, taxpayer-id and contact
    handles/blocks are dropped; only their KEY NAMES are listed. The first occurrence of a scalar
    wins, so registro.br contact-block dates never override the domain dates; comment lines (%, #)
    and ICANN footers (from '>>>') are ignored."""
    t = to_text(text)
    out = _empty_record("whois43")
    out["meta"]["source"], out["meta"]["server"] = "whois", (server or None)
    out["query"] = _ace(domain) if isinstance(domain, str) else None
    if not t.strip():
        out["error"] = "empty WHOIS answer"
        return out
    if looks_like_html(t):
        out["error"] = "HTML instead of WHOIS text"
        return out
    registrar: dict[str, Any] = {"name": None, "iana_id": None, "url": None, "whois_server": None, "abuse_email": None}
    dropped: list[str] = []
    for line in t.split("\n"):
        s = line.strip()
        if not s or s.startswith(("%", "#")):
            continue
        if s.startswith(">>>"):
            break
        m = _LINE_RE.match(line)
        if not m:
            continue
        key = re.sub(r"\s+", " ", m.group(1).strip().lower())
        val = m.group(2).strip()
        if key not in _W_KEEP:
            if not re.search(r"\d{4}", key):
                _add_unique(dropped, key)
            continue
        if not val:
            continue
        if key in _W_DOMAIN and out["domain"] is None:
            out["domain"] = _ace(val) or val.lower().rstrip(".")
        elif key in _W_REGISTRAR and registrar["name"] is None:
            registrar["name"] = _clean(val)
        elif key in _W_REGISTRAR_IANA and registrar["iana_id"] is None and re.fullmatch(r"\d{1,6}", val):
            registrar["iana_id"] = val
        elif key in _W_REGISTRAR_URL and registrar["url"] is None and re.match(r"https?://\S+$", val, re.I):
            registrar["url"] = val[:200]
        elif key in _W_REGISTRAR_ABUSE and registrar["abuse_email"] is None:
            if is_role_address(val):
                registrar["abuse_email"] = val.strip().lower()
            else:
                _add_unique(dropped, key)
        elif key in _W_REFERRAL:
            host = _referral_host(val)
            if host and out["referral"] is None:
                out["referral"] = host
            if host and key in ("registrar whois server", "whois server") and registrar["whois_server"] is None:
                registrar["whois_server"] = host
        elif key in _W_CREATED and out["dates"]["created"] is None:
            out["dates"]["created"] = norm_date(val)
        elif key in _W_UPDATED and out["dates"]["updated"] is None:
            out["dates"]["updated"] = norm_date(val)
        elif key in _W_EXPIRES and out["dates"]["expires"] is None:
            out["dates"]["expires"] = norm_date(val)
        elif key in _W_NS:
            _add_unique(out["nameservers"], valid_hostname(val.split()[0].rstrip(",")))
        elif key in _W_STATUS:
            for part in (val.split(",") if key == "state" else [val.split()[0]]):
                if len(out["status"]) < STATUS_CAP:
                    _add_unique(out["status"], _clean(part, 60))
        elif key in _W_DNSSEC:
            low = val.lower()
            if low in _DNSSEC_YES:
                out["dnssec"]["signed"] = True
            elif low in _DNSSEC_NO and out["dnssec"]["signed"] is None:
                out["dnssec"]["signed"] = False
        elif key in _W_DS:
            if len(out["dnssec"]["ds"]) < 8:
                _add_unique(out["dnssec"]["ds"], re.sub(r"\s+", " ", val)[:200])
            out["dnssec"]["signed"] = True
        elif key in _W_DNSKEY:
            out["dnssec"]["signed"] = True
    if any(registrar.values()):
        out["registrar"] = registrar
    out["dropped_fields"] = dropped
    has_data = has_registration_data(out)
    marker = whois_text_marker(t)
    if marker and marker.startswith("not_found") and not has_data:
        out["registered"] = False
    elif has_data:
        out["registered"] = True
    if marker and marker.startswith("rate_limited"):
        out["partial"] = True
    if out["query"] and out["domain"] and out["domain"] != out["query"]:
        out["domain_mismatch"] = True
    return out


def has_registration_data(record: Any) -> bool:
    """A record holding registration facts (domain, dates or nameservers)."""
    if not isinstance(record, dict):
        return False
    dates = record.get("dates") or {}
    return bool(record.get("domain") or record.get("nameservers") or any(dates.values()))


def whois_text_marker(text: Any) -> str | None:
    """Reason string for a port-43 answer, or None for a usable record. 'rate_limited' also covers
    registro.br's 'Query rate limit exceeded. Reduced information.' (the reduced record still
    parses); 'not_found' only when no record data is present."""
    t = to_text(text)
    if not t.strip():
        return "error: empty WHOIS answer"
    if looks_like_html(t):
        return "error: HTML instead of WHOIS text"
    head = "\n".join(t.split("\n")[:60])
    m = _RATE_RE.search(head)
    if m:
        return "rate_limited: " + m.group(0).lower()
    m = _BLOCK_RE.search(head)
    if m:
        return "blocked: " + m.group(0).lower()
    if _NOT_FOUND_RE.search(t):
        keys = _W_DOMAIN | _W_NS
        for ln in t.split("\n"):
            s = ln.strip()
            if not s or s.startswith(("%", "#")):
                continue
            lm = _LINE_RE.match(ln)
            if lm and lm.group(1).strip().lower() in keys:
                return None
        return "not_found: no registration record"
    return None


def whois_referral(parsed: Any, current_server: str | None = None) -> str | None:
    """The referral WHOIS server an answer names (refer:, whois:, Registrar WHOIS Server:,
    ReferralServer: whois://...), or None when absent, invalid, an IP/internal name or the same
    server."""
    if isinstance(parsed, str):
        parsed = parse_whois_text(parsed, server=current_server)
    ref = (parsed or {}).get("referral") if isinstance(parsed, dict) else None
    if not ref:
        return None
    if current_server and ref == str(current_server).strip().lower().rstrip("."):
        return None
    return ref


def next_referral(parsed: Any, current_server: str | None, hops_done: int) -> str | None:
    """FC3: the server for the next query, or None. At most one referral hop."""
    if hops_done >= WHOIS43_MAX_REFERRALS:
        return None
    return whois_referral(parsed, current_server)


def is_thin(record: Any) -> bool:
    """A registry record without the registrar or the creation date (worth one referral hop)."""
    if not isinstance(record, dict):
        return True
    reg = record.get("registrar") or {}
    return not (reg.get("name") and (record.get("dates") or {}).get("created"))


def merge_referral(primary: dict[str, Any], referral: Any, referral_server: str | None = None) -> dict[str, Any]:
    """Registry answer + one referral answer -> one record. Registry values win; the referral only
    fills missing fields. meta keeps both servers."""
    out = copy.deepcopy(primary)
    if not isinstance(referral, dict):
        return out
    if out.get("registrar") is None and referral.get("registrar"):
        out["registrar"] = copy.deepcopy(referral["registrar"])
    elif out.get("registrar") and referral.get("registrar"):
        for k, v in referral["registrar"].items():
            if out["registrar"].get(k) is None and v is not None:
                out["registrar"][k] = v
    for k in ("created", "updated", "expires"):
        if out["dates"].get(k) is None and (referral.get("dates") or {}).get(k):
            out["dates"][k] = referral["dates"][k]
    for k in ("nameservers", "status"):
        if not out.get(k) and referral.get(k):
            out[k] = list(referral[k])
    if out["dnssec"].get("signed") is None and (referral.get("dnssec") or {}).get("signed") is not None:
        out["dnssec"] = copy.deepcopy(referral["dnssec"])
    out["meta"]["referral"] = referral_server or (referral.get("meta") or {}).get("server")
    for name in referral.get("dropped_fields") or []:
        _add_unique(out["dropped_fields"], name)
    return out


def minimise_whois_text(text: Any) -> str:
    """FC4: evidence copy of a port-43 answer: only allow-listed 'key: value' lines plus the
    not-found/rate-limit line. Comment lines (terms, the client IP registro.br echoes), contact
    blocks and owner/ownerid/responsible/person/e-mail lines never reach the evidence."""
    keep: list[str] = []
    for line in to_text(text).split("\n"):
        s = line.strip()
        if not s:
            continue
        if _NOT_FOUND_RE.search(s) or _RATE_RE.search(s):
            keep.append(s.lstrip("% ").strip())
            continue
        if s.startswith(("%", "#", ">>>")):
            continue
        m = _LINE_RE.match(line)
        if not m:
            continue
        key = re.sub(r"\s+", " ", m.group(1).strip().lower())
        if key not in _W_KEEP:
            continue
        if key in _W_REGISTRAR_ABUSE and not is_role_address(m.group(2)):
            continue
        if _DOC_ID_RE.search(s) and key not in (_W_DS | _W_DNSKEY):
            continue
        keep.append(s)
    return "\n".join(keep[:200]) + ("\n" if keep else "")


# ---- who-dat JSON (self-hosted or public instance) -------------------------------------------


def _str_or_none(value: Any) -> str | None:
    return value.strip() if isinstance(value, str) and value.strip() else None


def parse_whodat(raw: Any, requested_domain: str | None = None) -> dict[str, Any]:
    """FC2/FC4/FC5: who-dat JSON -> normalised record through an allow-list.

    Kept: registrar (name, IANA id, URL, WHOIS server, role abuse mailbox), dates, nameservers,
    status, DNSSEC (signed + DS), meta.source (rdap|whois)/server/referral/cached and the per-role
    'redacted' flags (booleans only). Every contact value is dropped (its path in
    dropped_fields); never a CNPJ. ``domain_mismatch``: a subdomain query answered for the
    registrable domain (live: does-not-exist-0000.example.com -> example.com)."""
    out = _empty_record("whodat")
    req = _ace(requested_domain) if isinstance(requested_domain, str) else None
    out["query"] = req
    obj = raw
    if isinstance(raw, (bytes, bytearray, str)):
        text = to_text(raw)
        if not text.strip():
            out["error"] = "empty body"
            return out
        if looks_like_html(text):
            out["error"] = "HTML instead of JSON"
            return out
        try:
            obj = json.loads(text)
        except ValueError:
            out["error"] = "malformed JSON"
            return out
    if not isinstance(obj, dict):
        out["error"] = "who-dat answer is not an object"
        return out
    if obj.get("error") and not obj.get("domain"):
        out["error"] = "error in an HTTP 200 answer: " + str(obj.get("error"))[:160]
        return out
    out["domain"] = _ace(obj.get("domain")) if _str_or_none(obj.get("domain")) else None
    if not out["query"]:
        out["query"] = _ace(obj.get("query")) if _str_or_none(obj.get("query")) else None
    if isinstance(obj.get("isRegistered"), bool):
        out["registered"] = obj["isRegistered"]
    reg = obj.get("registrar")
    if isinstance(reg, dict):
        url = _str_or_none(reg.get("url"))
        abuse = _str_or_none(reg.get("abuseEmail"))
        iana = str(reg.get("ianaId") or "").strip()
        registrar = {
            "name": _clean(reg.get("name")),
            "iana_id": iana if re.fullmatch(r"\d{1,6}", iana) else None,
            "url": url[:200] if url and re.match(r"https?://\S+$", url, re.I) else None,
            "whois_server": valid_hostname(reg.get("whoisServer")) if reg.get("whoisServer") else None,
            "abuse_email": abuse.lower() if is_role_address(abuse) else None,
        }
        if abuse and not registrar["abuse_email"]:
            out["dropped_fields"].append("registrar.abuseEmail")
        if _str_or_none(reg.get("abusePhone")):
            out["dropped_fields"].append("registrar.abusePhone")
        if any(registrar.values()):
            out["registrar"] = registrar
    for s in obj.get("status") if isinstance(obj.get("status"), list) else []:
        if isinstance(s, str) and s.strip() and len(out["status"]) < STATUS_CAP:
            _add_unique(out["status"], _clean(s.strip().split()[0], 60))
    for ns in obj.get("nameservers") if isinstance(obj.get("nameservers"), list) else []:
        name = ns.get("name") if isinstance(ns, dict) else ns
        _add_unique(out["nameservers"], valid_hostname(name) if isinstance(name, str) else None)
    dn = obj.get("dnssec")
    if isinstance(dn, dict):
        out["dnssec"]["signed"] = dn.get("signed") if isinstance(dn.get("signed"), bool) else None
        for ds in dn.get("dsData") if isinstance(dn.get("dsData"), list) else []:
            if isinstance(ds, dict) and ds.get("digest") and len(out["dnssec"]["ds"]) < 8:
                digest = str(ds.get("digest")).upper()[:128]
                _add_unique(out["dnssec"]["ds"], f"{ds.get('keyTag')} {ds.get('algorithm')} {ds.get('digestType')} {digest}")
    dates = obj.get("dates") if isinstance(obj.get("dates"), dict) else {}
    for k in ("created", "updated", "expires"):
        out["dates"][k] = norm_date(dates.get(k))
    contacts = obj.get("contacts") if isinstance(obj.get("contacts"), dict) else {}
    for role, contact in contacts.items():
        if not isinstance(contact, dict):
            continue
        if isinstance(contact.get("redacted"), bool):
            out["contacts_redacted"][str(role)[:30]] = contact["redacted"]
        for name, value in contact.items():
            if name == "redacted":
                continue
            filled = any(x not in (None, "") for x in value.values()) if isinstance(value, dict) else value not in (None, "")
            if filled:
                out["dropped_fields"].append(f"contacts.{str(role)[:30]}.{str(name)[:30]}")
    meta = obj.get("meta") if isinstance(obj.get("meta"), dict) else {}
    src = _str_or_none(meta.get("source"))
    out["meta"].update({
        "source": src.lower() if src and src.lower() in ("rdap", "whois") else None,
        "server": (_clean(meta.get("server")) or None),
        "referral": (_clean(meta.get("referral")) or None),
        "cached": meta.get("cached") if isinstance(meta.get("cached"), bool) else None,
    })
    out["referral"] = out["meta"]["referral"]
    if out["query"] and out["domain"] and out["query"] != out["domain"]:
        out["domain_mismatch"] = True
    return out


def whodat_from_flat_extract(flat: Any) -> dict[str, Any]:
    """FC6: a research json_extract record (dotted keys such as 'registrar.name', 'meta.source',
    'contacts.registrant.redacted') -> the nested who-dat shape :func:`parse_whodat` reads."""
    if not isinstance(flat, dict):
        return {}
    out: dict[str, Any] = {}
    for key, value in flat.items():
        parts = str(key).split(".")
        node: Any = out
        for part in parts[:-1]:
            node = node.setdefault(part, {})
            if not isinstance(node, dict):
                break
        else:
            node[parts[-1]] = value
    return out


# ---- output ---------------------------------------------------------------------------------


def domain_age_days(created: Any, now: datetime) -> int | None:
    """Days between the created date (date part; registry-local times kept naive) and now."""
    if not isinstance(created, str) or not isinstance(now, datetime):
        return None
    try:
        dt = datetime.strptime(created[:10], "%Y-%m-%d").replace(tzinfo=timezone.utc)
    except ValueError:
        return None
    ref = now if now.tzinfo else now.replace(tzinfo=timezone.utc)
    days = (ref - dt).days
    return days if days >= 0 else None


def registration_pivots(record: Any) -> list[str]:
    """FC4/FC5: the only pivots are nameserver domains (relation nameserver, expand=False, as in
    P003). Never CNPJ, e-mail, person or registrar pivots."""
    if not isinstance(record, dict):
        return []
    return [ns for ns in record.get("nameservers") or [] if valid_hostname(ns)][:NS_PIVOT_CAP]


def evidence_record(record: dict[str, Any]) -> dict[str, Any]:
    """FC4: the evidence copy - the allow-listed record (no contact value ever)."""
    keep = ("domain", "query", "registered", "registrar", "dates", "nameservers", "status", "dnssec", "contacts_redacted", "referral",
            "meta", "domain_mismatch", "partial", "dropped_fields")
    return {k: copy.deepcopy(record.get(k)) for k in keep}


def http_failure(exc: BaseException, label: str) -> tuple[str, str, str]:
    """(status, reason code, reason) of a refused or failed HTTP step: rule 5, could not verify."""
    if isinstance(exc, RateLimited):
        return "rate_limited", "rate_limited", f"{label} rate limited the request: could not verify"
    if isinstance(exc, QuotaExceeded):
        return "quota", "quota", f"{label} quota exhausted: could not verify"
    if isinstance(exc, Blocked):
        code = str(getattr(exc, "reason_code", "") or "challenge")
        return "blocked", code if code in BLOCKED_CODES else "challenge", f"{label} refused the request ({_short(exc)}): could not verify"
    if isinstance(exc, AuthRequired):
        return "blocked", "challenge", f"{label} refused the request (HTTP {getattr(exc, 'status', 0)}; V3LUM sends no credentials): could not verify"
    if isinstance(exc, OfflineError):
        return "unavailable", "offline", f"{label} not in the cache (offline mode): could not verify"
    if isinstance(exc, NetworkError):
        timed_out = "timeout" in str(getattr(exc, "kind", "")).lower() or "timed out" in str(exc).lower()
        return "error", "timeout" if timed_out else "error", f"{label} did not answer ({_short(exc)}): could not verify"
    return "error", "error", f"{label} answered HTTP {getattr(exc, 'status', 0) or '?'} ({_short(exc)}): could not verify"


# ======================================================================================
# the modules
# ======================================================================================


@dataclass
class Lookup:
    """Outcome of one lookup path: a record, a 'not registered' answer or a failure."""

    record: dict[str, Any] | None = None
    not_registered: bool = False
    failure: tuple[str, str, str] | None = None  # (status, reason code, reason)
    reason: str = ""
    evidence: list[str] = field(default_factory=list)
    truncated: bool = False


class _Port43Failure(Exception):
    def __init__(self, failure: tuple[str, str, str]) -> None:
        super().__init__(failure[2])
        self.failure = failure


class _Unverified(Exception):
    """An answer that is not what was asked for: could not verify."""


def whodat_lookup(data: Any, domain: str, label: str) -> Lookup:
    """A parsed who-dat answer -> Lookup (FC2/FC4): errors in a 200, another name, no data ->
    could not verify; isRegistered false -> not registered (the registry's own data)."""
    record = parse_whodat(data, domain)
    if record["error"]:
        return Lookup(failure=("error", "error", f"{label}: {record['error']}: could not verify"))
    if not record["domain"] and record["registered"] is not False:
        return Lookup(failure=("error", "error", f"{label} answered without the domain name: could not verify"))
    if record["domain_mismatch"]:
        return Lookup(failure=("error", "error", f"{label} answered for {record['domain']} instead of {domain}: could not verify"))
    if record["registered"] is False:
        source = record["meta"]["source"] or "?"
        return Lookup(not_registered=True, reason=f"not registered according to {label} (registry {source} data via {record['meta']['server'] or '?'})")
    if not has_registration_data(record):
        return Lookup(failure=("error", "error", f"{label} answered without registration data: could not verify"))
    return Lookup(record=record)


class _RegistrationOutput:
    """Shared behaviour of the two WHOIS-fallback modules (mixin: metadata stays in each class)."""

    name: str

    def _explicit(self, ctx: Any) -> bool:
        include = getattr(getattr(ctx, "options", None), "include", None) or ()
        return self.name in include and bool(getattr(ctx, "is_seed", False))

    def applies(self, entity: Entity, ctx: Any) -> bool:
        domain = str(entity.value)
        if not registrable(domain):
            return False
        # an unreadable bootstrap (None) is decided in run(): UNAVAILABLE 'dataset', never 'not applicable'
        return applicability(ctx, domain, explicit=self._explicit(ctx)).applies is not False

    def _decide(self, res: ModuleResult, ctx: Any, domain: str) -> Applicability | None:
        if not registrable(domain):
            res.mark("skipped", f"{domain} is not a registrable domain: WHOIS answers for registered names only", reason_code="not_applicable")
            return None
        app = applicability(ctx, domain, explicit=self._explicit(ctx))
        if app.applies is None:
            res.mark("unavailable", app.reason, reason_code="dataset")
            return None
        if not app.applies:
            res.mark("skipped", app.reason, reason_code="not_applicable")
            return None
        return app

    def _emit(self, res: ModuleResult, ctx: Any, record: dict[str, Any], *, via: str, raw: dict[str, Any]) -> ModuleResult:
        """Attributes and nameserver pivots of a registration record (FC4/FC5)."""
        res.raw = {**raw, "via": via, "record": evidence_record(record)}
        reg = record.get("registrar") or {}
        dates = record.get("dates") or {}
        meta = record.get("meta") or {}
        res.attr("registered", True)
        res.attr("registrar", reg.get("name"))
        res.attr("registrar_iana_id", reg.get("iana_id"))
        res.attr("registrar_whois_server", reg.get("whois_server"))
        res.attr("abuse_contact", reg.get("abuse_email"))  # role mailboxes only (is_role_address)
        for key in ("created", "updated", "expires"):
            res.attr(key, dates.get(key))
        res.attr("domain_age_days", domain_age_days(dates.get("created"), ctx.now()))
        res.attr("nameservers", list(record.get("nameservers") or []))
        res.attr("status", list(record.get("status") or []))
        signed = (record.get("dnssec") or {}).get("signed")
        if isinstance(signed, bool):
            res.attr("delegation_signed", signed)
        res.attr("registration_source", meta.get("source"))
        res.attr("registration_server", meta.get("server"))
        res.attr("registration_via", via)
        res.attr("registration_referral", meta.get("referral"))
        for ns in registration_pivots(record):
            res.pivot(T.DOMAIN, ns, "nameserver", confidence="confirmed", expand=False)
        if record.get("partial"):
            res.error = "the registry reduced its answer (query rate limit): partial registration data"
            res.stop("rate_limited")
        return res


@register
class WhoisFallback(_RegistrationOutput, Module):
    name = "whois_fallback"
    title = "WHOIS fallback (TLDs without RDAP)"
    description = (
        "Registrar, dates, nameservers, status and DNSSEC for names whose TLD has no usable RDAP service (IANA bootstrap): "
        "a self-hosted who-dat instance when configured, then port-43 WHOIS at the registry server of the IANA root zone database."
    )
    category = "domain_dns"
    accepts = {T.DOMAIN}
    produces = {T.DOMAIN}
    terms = "open"  # IANA and registry data (P343 chair rationale)
    opsec = Opsec.PASSIVE
    disclosure = "third_party"  # IANA receives the TLD; the registries (directly or through who-dat) the domain
    provider = "registry_whois"
    sources = (SRC_PORT43, SRC_ROOT_DB, SRC_BOOTSTRAP, SRC_WHODAT)
    hosts = ("www.iana.org", "data.iana.org")  # root-zone pages, the P003 bootstrap dataset; + the whodat_url host (hosts_from_settings)
    access_model = "free_noauth_limited"
    max_requests = 3  # self-hosted who-dat 1 + IANA root-zone page 1 (cached 7 days) + 1 redirect hop
    expected_latency = 1.0
    timeout = 45.0  # two port-43 hops of at most 10 s each plus the HTTP steps
    min_interval = 1.0
    cache_ttl = 86400  # registration data: 24 h
    daily_quota = 200  # per-query registry use only, never bulk (registry terms)
    max_pivots = NS_PIVOT_CAP
    default_enabled = True
    reference = "https://www.iana.org/domains/root/db"
    tags = {"free"}
    settings = {
        SETTING_WHODAT: SettingSpec(
            "",
            "https URL of a self-hosted who-dat instance (MIT, github.com/Lissy93/who-dat) queried first by whois_fallback; empty = not used",
        ),
    }
    notice = (
        "Per-query registry WHOIS only (registry terms: no bulk or marketing use; the raw text is never republished). Personal "
        "contact fields are dropped at ingestion and WHOIS output never creates CNPJ pivots (RDAP only). Port 43 needs the core "
        "whois43 helper, which this build does not have: until it lands the module reports UNAVAILABLE with the registry's WHOIS "
        "server and website."
    )

    @classmethod
    def health_check(cls) -> HealthCheck | None:
        return HealthCheck(offline=False, selftest=_root_db_selftest)  # reads the IANA page of .ru: never an investigated value

    def run(self, entity: Entity, ctx: Any) -> ModuleResult:
        res = self.result(entity)
        domain = str(entity.value)
        app = self._decide(res, ctx, domain)
        if app is None:
            return res
        tld = str(tld_of(domain))
        raw: dict[str, Any] = {"path": app.path, "applicability": app.reason}
        failures: list[tuple[str, str, str, str]] = []
        # 1. self-hosted who-dat (FC2)
        base = str(ctx.setting(SETTING_WHODAT, "") or "").strip()
        if base:
            look = self._whodat(ctx, base, domain)
            if look.record is not None:
                return self._emit(res, ctx, look.record, via="whodat", raw=raw)
            if look.not_registered:
                res.raw = {**raw, "via": "whodat", "outcome": "not_registered"}
                return res.mark("empty", look.reason)
            if look.failure:
                failures.append((SRC_WHODAT, *look.failure))
        # 2. the IANA root zone database: registry WHOIS server of the TLD (FC2, 7 days)
        try:
            info = self._root_db(ctx, tld)
        except _Unverified as exc:
            failures.append((SRC_ROOT_DB, "error", "error", str(exc)))
            return self._unverified(res, raw, failures)
        except DeadlineExceeded:
            raise
        except (HttpError, NetworkError) as exc:
            failures.append((SRC_ROOT_DB, *http_failure(exc, "www.iana.org")))
            return self._unverified(res, raw, failures)
        raw["iana_root_db"] = {k: info.get(k) for k in ("status", "whois_server", "website", "rdap_base_urls", "fetched_at", "cached")}
        self._root_links(res, tld, info)
        if info.get("status") == "not_found":
            failures.append((SRC_ROOT_DB, "skipped", "not_applicable", f"IANA has no root zone page for .{tld} (not a delegated TLD)"))
            return self._unverified(res, raw, failures)
        server = info.get("whois_server")
        if not server:
            failures.append((SRC_PORT43, "skipped", "not_applicable",
                             f"no WHOIS server is published for .{tld} in the IANA root zone database: nothing to query on port 43 (registry website: manual lookup)"))
            return self._unverified(res, raw, failures)
        res.attr("registry_whois_server", server)
        # 3. port 43 at the registry, at most one referral hop (FC3)
        look = self._port43(ctx, server, domain)
        raw["whois_text"] = look.evidence  # minimised: allow-listed lines only (FC4)
        if look.truncated:
            raw["truncated"] = True
        if look.record is not None:
            return self._emit(res, ctx, look.record, via="whois43", raw=raw)
        if look.not_registered:
            res.raw = {**raw, "via": "whois43", "outcome": "not_registered"}
            return res.mark("empty", look.reason)
        failures.append((SRC_PORT43, *(look.failure or ("error", "error", "port-43 lookup failed: could not verify"))))
        return self._unverified(res, raw, failures)

    # ------------------------------------------------------------------ steps
    def _whodat(self, ctx: Any, base: str, domain: str) -> Lookup:
        if not base.lower().startswith("https://"):
            return Lookup(failure=("skipped", "config", "setting whodat_url must be the https:// URL of a self-hosted who-dat instance: not used"))
        url = base.rstrip("/") + "/" + quote(domain, safe="")
        label = f"the self-hosted who-dat instance ({urlsplit(url).hostname or '?'})"
        try:
            data = ctx.http.get_json(url, source=SRC_WHODAT)
        except PolicyError as exc:
            return Lookup(failure=("skipped", "policy", f"{label} was refused ({_short(exc)}); a host another provider owns is never reached through whodat_url"))
        except DeadlineExceeded:
            raise
        except (HttpError, NetworkError) as exc:
            return Lookup(failure=http_failure(exc, label))
        return whodat_lookup(data, domain, label)

    def _root_db(self, ctx: Any, tld: str) -> dict[str, Any]:
        """The registry WHOIS server of a TLD: module state for 7 days, else the IANA page."""
        key = STATE_PREFIX + tld
        now = ctx.now()
        cached = _state_get(ctx, key)
        if _fresh(cached, now):
            return {**cached, "cached": True}
        url = iana_root_db_url(tld)
        if not url:
            raise _Unverified(f"invalid TLD label {tld!r}")
        resp = ctx.http.get(url, source=SRC_ROOT_DB, ttl=IANA_ROOT_DB_TTL_S, headers={"Accept": "text/html"})
        if resp.status == 404 and resp.classification is None:
            info: dict[str, Any] = {"status": "not_found", "whois_server": None, "website": None, "rdap_base_urls": []}
        else:
            ctx.http.check(resp)  # challenge, 429, 5xx... raise (could not verify)
            parsed = parse_iana_root_db(resp.text, tld)
            if parsed["status"] not in ("ok", "no_whois_server"):
                ctx.http.evict(resp)
                raise _Unverified(f"www.iana.org answered an unexpected page for .{tld} ({parsed['reason']}): could not verify")
            info = {k: parsed[k] for k in ("status", "whois_server", "website", "rdap_base_urls")}
        info["fetched_at"] = now.isoformat()
        if info["status"] != "not_found":  # a 404 may be transient: never kept for a week
            _state_set(ctx, key, info)
        return {**info, "cached": False}

    def _port43(self, ctx: Any, server: str, domain: str) -> Lookup:
        why = port43_unavailable(ctx)
        if why:
            return Lookup(failure=("unavailable", "offline", f"{server}: {why}"))
        query = whois_query(server, domain)
        if not query:
            return Lookup(failure=("error", "error", f"refused to build a WHOIS query for {domain!r} (unsafe value)"))
        try:
            text, truncated = _ask43(ctx, server, query)
        except _Port43Failure as exc:
            return Lookup(failure=exc.failure)
        evidence = [minimise_whois_text(text)]
        parsed = parse_whois_text(text, server=server, domain=domain)
        marker = whois_text_marker(text) or ""
        if marker.startswith("blocked"):
            return Lookup(failure=("blocked", "challenge", f"{server} refused the query ({marker[9:]}): could not verify"), evidence=evidence)
        if marker.startswith("rate_limited") and not has_registration_data(parsed):
            return Lookup(failure=("rate_limited", "rate_limited", f"{server}: {marker[14:]}: could not verify"), evidence=evidence)
        if parsed["registered"] is False:
            return Lookup(not_registered=True, reason=f"no registration record at the registry WHOIS server {server}", evidence=evidence)
        if parsed["error"] or not has_registration_data(parsed):
            return Lookup(failure=("error", "error", f"{server} answered without registration data ({parsed['error'] or 'unrecognised layout'}): could not verify"), evidence=evidence)
        if parsed["domain_mismatch"]:
            return Lookup(failure=("error", "error", f"{server} answered for {parsed['domain']} instead of {domain}: could not verify"), evidence=evidence)
        referral = next_referral(parsed, server, hops_done=0)
        if referral:
            parsed["meta"]["referral"] = referral
            if is_thin(parsed) and self._referral_allowed(ctx):
                ref_query = whois_query(referral, domain)
                try:
                    ref_text, _cut = _ask43(ctx, referral, ref_query) if ref_query else ("", False)
                except _Port43Failure:
                    ref_text = ""  # the registry record stands; the hop could not be verified
                if ref_text:
                    second = parse_whois_text(ref_text, server=referral, domain=domain)
                    if not second["error"] and not second["domain_mismatch"] and has_registration_data(second):
                        parsed = merge_referral(parsed, second, referral)
                        evidence.append(minimise_whois_text(ref_text))
        return Lookup(record=parsed, evidence=evidence, truncated=truncated)

    @staticmethod
    def _referral_allowed(ctx: Any) -> bool:
        """A registrar WHOIS server is not a registry: an unregistered, unknown-tier party (A8)."""
        tlp = str(getattr(ctx, "tlp", "") or "").lower()
        return tlp in REFERRAL_TLPS and bool(getattr(getattr(ctx, "options", None), "allow_unknown", False))

    @staticmethod
    def _root_links(res: ModuleResult, tld: str, info: dict[str, Any]) -> None:
        url = iana_root_db_url(tld)
        if url:
            res.link(f"IANA root zone database: .{tld}", url)
        if info.get("website"):
            res.link(f"Registry website of .{tld} (manual WHOIS lookup)", str(info["website"]))

    @staticmethod
    def _unverified(res: ModuleResult, raw: dict[str, Any], failures: list[tuple[str, str, str, str]]) -> ModuleResult:
        """Rule 5: every path failed or does not exist -> the first failure is the module status;
        each path keeps its own source status (coverage)."""
        for src, status, code, reason in failures:
            res.source_status(src, status, reason_code=code, reason=reason)
        res.raw = {**raw, "failures": [{"source": s, "status": st, "reason_code": c} for s, st, c, _r in failures]}
        _src, status, code, _reason = failures[0]
        return res.mark(status, "; ".join(r for _s, _st, _c, r in failures), reason_code=code)


@register
class WhoisFallbackPublic(_RegistrationOutput, Module):
    name = "whois_fallback_public"
    title = "WHOIS fallback via the public who-dat instance"
    description = (
        "Registration data for names whose TLD has no usable RDAP service, from the public who-dat.as93.net instance "
        "(opt-in: unknown-tier operator, excluded at TLP:AMBER and above)."
    )
    category = "domain_dns"
    accepts = {T.DOMAIN}
    produces = {T.DOMAIN}
    terms = "open"
    opsec = Opsec.PASSIVE
    disclosure = "third_party"  # the public instance (and through it the registry) receives the domain
    provider = "as93"
    sources = (SRC_PUBLIC, SRC_BOOTSTRAP)
    hosts = ("who-dat.as93.net", "data.iana.org")  # the lookup; the P003 bootstrap dataset (applicability, FC1)
    access_model = "free_noauth_limited"
    max_requests = 2  # one lookup (+1 redirect hop)
    expected_latency = 0.3
    timeout = 30.0
    min_interval = 2.0
    cache_ttl = 86400
    daily_quota = 100  # best-effort public instance
    max_pivots = NS_PIVOT_CAP
    default_enabled = False  # unknown tier (P343 FC2, A3/A8)
    reference = "https://github.com/Lissy93/who-dat"
    tags = {"free"}
    notice = (
        "Sends the domain to the public who-dat.as93.net instance (individual operator, unknown tier, shared CDN cache): off by "
        "default, excluded at TLP:AMBER and above, CLEAR/GREEN only with --allow-unknown. Prefer a self-hosted instance (setting "
        "whodat_url of whois_fallback). Contact fields are dropped at ingestion; never CNPJ pivots."
    )

    @classmethod
    def health_check(cls) -> HealthCheck | None:
        return HealthCheck(offline=False, selftest=_public_selftest)  # the central benign value example.com

    def run(self, entity: Entity, ctx: Any) -> ModuleResult:
        res = self.result(entity)
        domain = str(entity.value)
        app = self._decide(res, ctx, domain)
        if app is None:
            return res
        data = ctx.http.get_json(PUBLIC_URL.format(domain=quote(domain, safe="")), source=SRC_PUBLIC)  # refusals raise
        look = whodat_lookup(data, domain, "who-dat.as93.net")
        raw = {"path": app.path, "applicability": app.reason}
        if look.record is not None:
            return self._emit(res, ctx, look.record, via="whodat_public", raw=raw)
        res.raw = {**raw, "via": "whodat_public", "outcome": "not_registered" if look.not_registered else "unverified"}
        if look.not_registered:
            return res.mark("empty", look.reason)
        status, code, reason = look.failure or ("error", "error", "who-dat.as93.net: could not verify")
        return res.mark(status, reason, reason_code=code)


# ======================================================================================
# plumbing
# ======================================================================================


def _ask43(ctx: Any, server: str, query: str) -> tuple[str, bool]:
    """One port-43 query through the core helper (FC3) -> (text, truncated)."""
    helper = getattr(getattr(ctx, "net", None), "whois43", None)
    if not callable(helper):
        raise _Port43Failure(("unavailable", "offline", f"{server}: port-43 WHOIS needs the core whois43 helper: could not verify"))
    try:
        answer = helper(server, query, timeout=WHOIS43_TIMEOUT_S, max_bytes=WHOIS43_CAP_BYTES)
    except OfflineError as exc:
        raise _Port43Failure(("unavailable", "offline", f"43/tcp to {server} is blocked or unreachable ({_short(exc)}): could not verify")) from exc
    except DeadlineExceeded:
        raise
    except (NetworkError, OSError) as exc:
        timed_out = isinstance(exc, TimeoutError) or "timed out" in str(exc).lower() or "timeout" in str(getattr(exc, "kind", "")).lower()
        raise _Port43Failure(("error", "timeout" if timed_out else "error", f"{server} did not answer on port 43 ({_short(exc)}): could not verify")) from exc
    data: Any = answer
    flagged = False
    if not isinstance(answer, (bytes, bytearray, str)):
        flagged = bool(getattr(answer, "truncated", False))
        data = getattr(answer, "content", None)
        if data is None:
            data = getattr(answer, "text", b"")
    text, cut = decode_whois(data, WHOIS43_CAP_BYTES)
    return text, flagged or cut


def _state_get(ctx: Any, key: str) -> dict[str, Any] | None:
    try:
        value = ctx.state.get(key)
    except Exception:  # noqa: BLE001 - module state is a cache: a problem only means a fresh lookup
        return None
    return value if isinstance(value, dict) else None


def _state_set(ctx: Any, key: str, value: dict[str, Any]) -> None:
    try:
        ctx.state.set(key, value)
    except Exception:  # noqa: BLE001 - never fail a lookup because the cache could not be written
        pass


def _fresh(entry: dict[str, Any] | None, now: datetime) -> bool:
    if not entry or entry.get("status") not in ("ok", "no_whois_server"):
        return False
    try:
        fetched = datetime.fromisoformat(str(entry.get("fetched_at")))
    except ValueError:
        return False
    if fetched.tzinfo is None:
        fetched = fetched.replace(tzinfo=timezone.utc)
    age = (now - fetched).total_seconds()
    return 0 <= age < IANA_ROOT_DB_TTL_S


def _root_db_selftest(ctx: Any) -> HealthResult:
    """Doctor self-test of whois_fallback: the IANA root zone page of .ru is readable and parses."""
    try:
        resp = ctx.http.get(IANA_ROOT_DB_URL.format(tld="ru"), source=SRC_ROOT_DB, headers={"Accept": "text/html"})
        ctx.http.check(resp)
    except (Blocked, RateLimited, AuthRequired) as exc:
        return HealthResult("blocked", _short(exc))
    except QuotaExceeded as exc:
        return HealthResult("quota", _short(exc))
    except (HttpError, NetworkError) as exc:
        return HealthResult("dead", _short(exc))
    parsed = parse_iana_root_db(resp.text, "ru")
    if parsed["status"] != "ok":
        return HealthResult("dead", f"IANA root zone page of .ru did not parse ({parsed['reason']})")
    return HealthResult("ok", f"IANA root zone database readable (.ru WHOIS server {parsed['whois_server']}); port 43: {port43_unavailable(ctx) or 'available'}")


def _public_selftest(ctx: Any) -> HealthResult:
    """Doctor self-test of whois_fallback_public on the central benign value example.com."""
    try:
        data = ctx.http.get_json(PUBLIC_URL.format(domain="example.com"), source=SRC_PUBLIC)
    except (Blocked, RateLimited, AuthRequired) as exc:
        return HealthResult("blocked", _short(exc))
    except QuotaExceeded as exc:
        return HealthResult("quota", _short(exc))
    except (HttpError, NetworkError) as exc:
        return HealthResult("dead", _short(exc))
    look = whodat_lookup(data, "example.com", "who-dat.as93.net")
    if look.record is None:
        return HealthResult("dead", look.reason or (look.failure[2] if look.failure else "no registration data"))
    return HealthResult("ok", "who-dat.as93.net answered for example.com")
