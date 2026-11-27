"""Certificate Transparency search (P001 ct_logs, default module): crt.sh, Cert Spotter, ctl.shodan.io.

Final conditions (council #1, P001) and where they live:

1. Two modules: this one (crt.sh, Cert Spotter, ctl.shodan.io - trusted providers) and
   ``ct_logs_extra`` (crt.name, MerkleMap: unknown tier, default_enabled=False).
2. Per-source terms in the registry: crtsh.search open; sslmate.issuances (keyed) key-terms;
   sslmate.issuances_keyless noncommercial; shodan_ctl.hostnames noncommercial. ``terms`` is the most
   restrictive class (noncommercial).
3. The policy gate narrows ``ctx.allowed_sources`` (keyless Cert Spotter and ctl.shodan.io are off under
   the corporate profile until licence-cleared; the keyed source runs once key_plans.certspotter is
   recorded). The key ``certspotter`` is declared in the sslmate provider fragment and sent only as an
   ``Authorization: Bearer`` header.
4. crt.sh ``?q=%25.{apex}&output=json&exclude=expired``; the sources run concurrently inside one budget
   (setting ``ct_logs_budget``, default 30 s, at most 90 s; the core retries 502/503/timeouts only while
   the budget lasts). A source that times out or fails is 'could not verify' and keeps its own status
   (``res.source_statuses``); with no answering source the run is never 'no certificates'.
5. A crt.sh body truncated at the core 15 MB cap is parsed record by record and never as complete
   (partial=True); Cert Spotter pages with ``after=<last id>`` (at most 5 pages). max_requests 10.
6. One hostname sink (:class:`HostnameSink`, shared with P007/P016 until the core adopts it): name_value
   split on newlines, lower-cased, '*.' stripped, Entity + PSL/IANA TLD check, label-boundary apex match,
   deduplicated with provenance; wildcard entries become the ``wildcard_cert`` attribute, never names.
7. Runs once per registrable domain: a subdomain is not applicable (no CT request; the apex run covers
   it). Subdomain pivots are capped; certificate SHA-256 fingerprints pivot with expand=False. CT names
   answering NXDOMAIN (confirmed by a second resolver) are labelled historical (expand=False); a DoH
   failure leaves them unresolved (rule 5).
8. Out-of-apex SAN registrable domains become ``cert_san`` pivots (expand=False); shared certificates
   (> 20 SANs over > 5 registrable domains, or CDN/hosting shared-certificate patterns) give only the
   ``shared_cert`` attribute.
9. ``first_cert_seen`` = earliest not_before (a lower bound of age, never a registration date);
   ``ct_summary`` carries the counts, issuers and the top 20 names; ``subdomains`` is the full list.
10. Brand mode (setting ``ct_brand_search``, default off: the keyword reaches crt.sh): for an analyst-typed
    org_profile domain, one crt.sh identity search ``q=%25{brand}%25`` per brand (>= 4 chars) and scan;
    out-of-profile names become ``lookalike`` pivots (expand=False) for P028.

crt.sh JSON carries no certificate SHA-256 and does not serve fingerprint (``q=<sha256>``) or O= queries
in JSON (HTTP 200 'Unsupported output type', verified 2026-11-26): certificate fingerprints are a manual
link (pivot pack ``ct_rdap_lookups``) and company-name search is in docs/backlog/p1-G01-1.md.
"""

from __future__ import annotations

import concurrent.futures
import ipaddress
import json
import re
import threading
import time
import unicodedata
from collections import Counter
from collections.abc import Callable, Iterable
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from typing import Any
from urllib.parse import urlencode

from v3lum.config import SettingSpec
from v3lum.core import psl
from v3lum.core.entities import Entity
from v3lum.core.entities import EntityType as T
from v3lum.core.http import (
    AuthRequired,
    Blocked,
    Cancelled,
    ConfigError,
    DeadlineExceeded,
    HttpError,
    NetworkError,
    PolicyError,
    QuotaExceeded,
    RateLimited,
    RequestCapReached,
)
from v3lum.core.models import ModuleResult, Opsec, Status, valid_reason
from v3lum.core.module import Module, register

SRC_CRTSH = "crtsh.search"
SRC_CERTSPOTTER = "sslmate.issuances"
SRC_CERTSPOTTER_KEYLESS = "sslmate.issuances_keyless"
SRC_CTL = "shodan_ctl.hostnames"

CRTSH_URL = "https://crt.sh/"
CERTSPOTTER_URL = "https://api.certspotter.com/v1/issuances"
CTL_URL = "https://ctl.shodan.io/api/v1/domain/{apex}/hostnames"

DEFAULT_BUDGET = 30.0
MAX_BUDGET = 90.0
MIN_BUDGET = 5.0
CERTSPOTTER_MAX_PAGES = 5
SUBDOMAIN_PIVOT_CAP = 100
LIVENESS_CAP = 50
LIVENESS_WORKERS = 8
FINGERPRINT_PIVOT_CAP = 25
AFFILIATE_PIVOT_CAP = 25
LOOKALIKE_PIVOT_CAP = 25
BRAND_SEARCH_CAP = 3
BRAND_MIN_LEN = 4
SUBDOMAINS_ATTR_CAP = 5000
EVIDENCE_CERT_CAP = 300
SHARED_SAN_THRESHOLD = 20
SHARED_DOMAIN_THRESHOLD = 5
SHARED_ATTR_CAP = 25
MAX_SANS = 1000
LIVENESS_MIN_BUDGET = 3.0
BRAND_LABEL = "crt.sh brand search"
TOP_NAMES = 20
_MAX_REFS = 50

#: CDN / hosting shared-certificate subject or SAN patterns (P001 cond 8).
SHARED_CERT_PATTERNS: tuple[re.Pattern[str], ...] = tuple(
    re.compile(p)
    for p in (
        r"(^|\.)cloudflaressl\.com$",
        r"^sni\d*\.cloudflaressl\.com$",
        r"(^|\.)ssl\d*\.cf\d\.rackcdn\.com$",
        r"(^|\.)(global\.)?ssl\.fastly\.net$",
        r"(^|\.)incapsula\.com$",
        r"(^|\.)incapdns\.net$",
        r"(^|\.)sucuri\.net$",
        r"(^|\.)tls\.automattic\.com$",
        r"(^|\.)wpengine\.com$",
        r"(^|\.)kinsta\.cloud$",
        r"(^|\.)(akamaiedge|akamaihd|akamai)\.net$",
        r"(^|\.)edgekey\.net$",
        r"(^|\.)edgesuite\.net$",
        r"(^|\.)azureedge\.net$",
        r"(^|\.)b-cdn\.net$",
        r"(^|\.)cdn77\.org$",
    )
)

_DN_ATTR_RE = re.compile(r'(?:^|,\s*)(C|O|OU|CN|ST|L|emailAddress)=("(?:[^"\\]|\\.)*"|[^,]*)')
_HTML_RE = re.compile(r"^\s*(?:<!doctype\s+html|<html|<head|<body|<br|<\?xml|<title|<center|<h1)", re.I)
_ISO_RE = re.compile(r"^(\d{4})-(\d{2})-(\d{2})(?:[T ](\d{2}):(\d{2})(?::(\d{2})(?:\.\d+)?)?)?\s*(Z|[+-]\d{2}:?\d{2})?$", re.I)
_BRAND_RE = re.compile(r"[^a-z0-9-]")
_SHA256_RE = re.compile(r"^[0-9a-fA-F]{64}$")

#: crt.sh error-in-200 markers (P321): an HTML error page where JSON was asked never reads as 'no certificates'.
CRTSH_MARKERS: tuple[dict[str, Any], ...] = (
    {
        "id": "ct_logs_crtsh_unsupported_output",
        "statuses": [200],
        "regex": "(?i)unsupported output type",
        "final_url_regex": r"^https://crt\.sh/",
        "maps_to": "error",
        "reason_code": "error",
        "reason": "crt.sh: unsupported output type for this query (HTML error page in HTTP 200): could not verify",
    },
    {
        "id": "ct_logs_crtsh_statement_timeout",
        "statuses": [200, 500, 502, 503],
        "regex": "(?i)canceling statement due to statement timeout|statement timeout",
        "final_url_regex": r"^https://crt\.sh/",
        "maps_to": "error",
        "reason_code": "timeout",
        "reason": "crt.sh: database statement timeout: could not verify",
    },
    {
        "id": "ct_logs_ctl_error_object",
        "statuses": [200],
        "json_path": "error",
        "regex": r"\S",
        "final_url_regex": r"^https://ctl\.shodan\.io/",
        "maps_to": "error",
        "reason_code": "error",
        "reason": "ctl.shodan.io: error object in HTTP 200: could not verify",
    },
)


# ======================================================================================
# Shared helpers: names, dates, the hostname sink (P001 cond 6; reused by P007/P016)
# ======================================================================================


def _is_ip(value: str) -> bool:
    try:
        ipaddress.ip_address(value.strip("[]"))
        return True
    except ValueError:
        return False


def clean_ct_name(raw: Any) -> tuple[str | None, bool, str]:
    """Normalise one CT identity -> ``(name, is_wildcard, error)``.

    Lower-cases, strips a leading '*.', refuses e-mail SANs, IP literals, inner wildcards and spaces,
    validates through ``Entity.try_make`` (IDN to punycode) and requires an IANA TLD and a name below
    a public suffix (PSL). ``error`` is '' for a usable name, else one of empty, email, not_hostname,
    wildcard_inner, ip_literal, invalid, single_label, bad_tld, public_suffix.
    """
    if not isinstance(raw, str):
        return None, False, "not_hostname"
    s = raw.strip().lower().rstrip(".")
    if not s:
        return None, False, "empty"
    if "@" in s:
        return None, False, "email"
    wildcard = False
    if s.startswith("*."):
        wildcard, s = True, s[2:]
    if "*" in s:
        return None, False, "wildcard_inner"
    if any(ch.isspace() for ch in s) or "/" in s:
        return None, False, "not_hostname"
    if _is_ip(s):
        return None, False, "ip_literal"
    if ":" in s:
        return None, False, "not_hostname"
    ent = Entity.try_make(T.DOMAIN, s)
    if ent is None:
        return None, False, "invalid"
    name = str(ent.value)
    labels = name.split(".")
    if len(labels) < 2:
        return None, False, "single_label"
    if not psl.is_known_tld(labels[-1]):
        return None, False, "bad_tld"
    if psl.registrable_domain(name) is None:
        return None, False, "public_suffix"
    return name, wildcard, ""


def split_name_value(value: Any) -> list[str]:
    """crt.sh ``name_value`` (newline separated) or a list (Cert Spotter ``dns_names``) -> raw names."""
    if isinstance(value, str):
        return [p for p in value.replace("\r", "\n").split("\n") if p.strip()]
    if isinstance(value, (list, tuple)):
        return [p for p in value if isinstance(p, str) and p.strip()]
    return []


def in_apex(name: str, apex: str) -> bool:
    """Label-boundary apex match: ``m.testexample.com`` is not under ``example.com``."""
    return bool(apex) and (name == apex or name.endswith("." + apex))


def registrable(name: str) -> str | None:
    """PSL registrable domain of ``name`` (None for public suffixes and junk)."""
    try:
        return psl.registrable_domain(name)
    except Exception:  # noqa: BLE001 - defensive: an odd value never crashes parsing
        return None


@dataclass
class NameInfo:
    """Provenance of one CT name: the sources that reported it and up to 50 certificate refs."""

    sources: list[str] = field(default_factory=list)
    certs: list[str] = field(default_factory=list)


class HostnameSink:
    """Hostname sink of one registrable domain (P001 cond 6), shared by CT modules (P007/P016).

    ``add(raw, source, cert_ref)`` puts a raw CT identity in one bucket: ``names`` (in-apex host
    names), ``wildcards`` ('*.x' entries under the apex: a wildcard_cert attribute of the parent, never
    names) or ``out_of_apex`` (SAN affiliate candidates); invalid values are counted in ``rejected``.
    Thread-safe; :meth:`merge` combines the sinks of several sources keeping every provenance.
    """

    def __init__(self, apex: str) -> None:
        self.apex = (apex or "").strip().lower().rstrip(".")
        self.names: dict[str, NameInfo] = {}
        self.wildcards: dict[str, NameInfo] = {}
        self.out_of_apex: dict[str, NameInfo] = {}
        self.rejected: Counter[str] = Counter()
        self._lock = threading.Lock()

    def _bucket(self, name: str, wildcard: bool) -> dict[str, NameInfo]:
        if not in_apex(name, self.apex):
            return self.out_of_apex
        return self.wildcards if wildcard else self.names

    @staticmethod
    def _record(info: NameInfo, source: str, cert_ref: str | None) -> None:
        if source and source not in info.sources:
            info.sources.append(source)
        if cert_ref and cert_ref not in info.certs and len(info.certs) < _MAX_REFS:
            info.certs.append(cert_ref)

    def add(self, raw: Any, source: str, cert_ref: str | None = None) -> str | None:
        """Add one raw identity; returns the label kept ('*.x' for wildcards) or None when rejected."""
        name, wildcard, err = clean_ct_name(raw)
        with self._lock:
            if err or name is None:
                self.rejected[err or "invalid"] += 1
                return None
            bucket = self._bucket(name, wildcard)
            self._record(bucket.setdefault(name, NameInfo()), source, cert_ref)
        return ("*." + name) if wildcard else name

    def merge(self, other: HostnameSink) -> None:
        with self._lock:
            for attr in ("names", "wildcards", "out_of_apex"):
                mine, theirs = getattr(self, attr), getattr(other, attr)
                for name, info in theirs.items():
                    target = mine.setdefault(name, NameInfo())
                    for src in info.sources:
                        self._record(target, src, None)
                    for ref in info.certs:
                        self._record(target, "", ref)
            self.rejected.update(other.rejected)

    def subdomains(self) -> list[str]:
        """Sorted in-apex names other than the apex itself."""
        return sorted(n for n in self.names if n != self.apex)

    def wildcard_labels(self) -> list[str]:
        return sorted("*." + n for n in self.wildcards)


def _to_text(raw: Any) -> str | None:
    if raw is None:
        return None
    if isinstance(raw, (bytes, bytearray, memoryview)):
        text = bytes(raw).decode("utf-8", "replace")
    elif isinstance(raw, str):
        text = raw
    else:
        return None
    return text[1:] if text.startswith("﻿") else text


def looks_like_html(body: Any) -> bool:
    """True when a body that should be JSON/text is an HTML (or XML) page."""
    text = _to_text(body)
    if not text:
        return False
    head = text[:1024]
    if _HTML_RE.match(head):
        return True
    low = head.lower()
    return head.lstrip().startswith("<") and ("</" in low or "<br" in low)


def parse_iso8601(value: Any) -> datetime | None:
    """ISO-8601 date/time -> aware UTC datetime (naive input taken as UTC); None otherwise."""
    if not isinstance(value, str):
        return None
    m = _ISO_RE.match(value.strip())
    if not m:
        return None
    y, mo, d, hh, mi, ss, tz = m.groups()
    try:
        dt = datetime(int(y), int(mo), int(d), int(hh or 0), int(mi or 0), int(ss or 0))
    except ValueError:
        return None
    if tz and tz.upper() != "Z":
        sign = 1 if tz[0] == "+" else -1
        digits = tz[1:].replace(":", "")
        dt = dt - timedelta(minutes=sign * (int(digits[:2]) * 60 + int(digits[2:4])))
    return dt.replace(tzinfo=timezone.utc)


def iso(dt: datetime | None) -> str | None:
    return dt.strftime("%Y-%m-%dT%H:%M:%SZ") if dt else None


def salvage_json_array(text: Any) -> tuple[list[Any], bool]:
    """Parse a JSON array record by record -> ``(records, complete)``.

    P001 cond 5: a body cut at the core size cap is never parsed as complete; the records decoded
    before the cut are kept and ``complete`` is False.
    """
    body = _to_text(text) or ""
    dec = json.JSONDecoder()
    i, n = 0, len(body)
    while i < n and body[i].isspace():
        i += 1
    if i >= n or body[i] != "[":
        return [], False
    i += 1
    records: list[Any] = []
    while True:
        while i < n and body[i] in " \t\r\n,":
            i += 1
        if i >= n:
            return records, False
        if body[i] == "]":
            return records, body[i + 1 :].strip() == ""
        try:
            obj, end = dec.raw_decode(body, i)
        except ValueError:
            return records, False
        records.append(obj)
        i = end


def dn_attr(dn: Any, key: str) -> str | None:
    """One attribute (O, CN...) of an X.500 distinguished name string."""
    if not isinstance(dn, str):
        return None
    for k, v in _DN_ATTR_RE.findall(dn):
        if k == key:
            v = v.strip()
            if len(v) >= 2 and v[0] == v[-1] == '"':
                v = v[1:-1].replace('\\"', '"')
            return v or None
    return None


def dns_san(raw: Any) -> str | None:
    """Lenient DNS-name form of a SAN for certificate-sharing counts (every DNS SAN of the certificate
    counts, validated or not): lower-cased, '*.' stripped; e-mails, IPs and non-names give None."""
    if not isinstance(raw, str):
        return None
    s = raw.strip().lower().rstrip(".")
    s = s[2:] if s.startswith("*.") else s
    if not s or "." not in s or "@" in s or "*" in s or "/" in s or ":" in s or any(ch.isspace() for ch in s) or _is_ip(s):
        return None
    return s


def classify_cert_sharing(names: Iterable[str], common_name: Any = None) -> dict[str, Any]:
    """P001 cond 8: a certificate is shared (multi-tenant) when it lists > 20 SANs over > 5 registrable
    domains, or a SAN/subject matches a CDN/hosting shared-certificate pattern."""
    unique = sorted({n for n in (dns_san(raw) for raw in names) if n})
    regs = sorted({r for r in (registrable(n) for n in unique) if r})
    reason = ""
    if len(unique) > SHARED_SAN_THRESHOLD and len(regs) > SHARED_DOMAIN_THRESHOLD:
        reason = f"{len(unique)} SANs over {len(regs)} registrable domains"
    else:
        probe = list(unique)
        if isinstance(common_name, str) and common_name.strip():
            probe.append(common_name.strip().lower().removeprefix("*."))
        for cand in probe:
            if any(p.search(cand) for p in SHARED_CERT_PATTERNS):
                reason = f"CDN/hosting shared-certificate pattern ({cand})"
                break
    return {"shared": bool(reason), "reason": reason, "san_count": len(unique), "registrable_domains": regs}


def fold(text: str) -> str:
    """Accent-fold and lower-case."""
    return "".join(c for c in unicodedata.normalize("NFKD", text) if not unicodedata.combining(c)).lower()


def brand_search_terms(brands: Iterable[Any], min_len: int = BRAND_MIN_LEN) -> list[str]:
    """P001 cond 10: org_profile brand keywords of >= 4 characters, accent-folded and deduplicated."""
    out: list[str] = []
    for brand in brands:
        if not isinstance(brand, str):
            continue
        term = _BRAND_RE.sub("", fold(brand.strip()))
        if len(term) >= min_len and term not in out:
            out.append(term)
    return out


# ======================================================================================
# Per-source outcomes
# ======================================================================================


@dataclass
class SourceOutcome:
    """What one CT source returned inside the shared budget."""

    source: str
    label: str
    status: str = "not_run"  # ok | empty | error | timeout | rate_limited | quota | blocked | needs_key | not_run
    reason: str = ""
    reason_code: str = ""
    partial: bool = False
    truncated: bool = False
    pages: int = 0
    sink: HostnameSink | None = None
    certs: list[dict[str, Any]] = field(default_factory=list)
    stop: BaseException | None = None  # Cancelled / RequestCapReached re-raised by the module after merging

    @property
    def answered(self) -> bool:
        return self.status in ("ok", "empty")

    @property
    def failed(self) -> bool:
        return self.status not in ("ok", "empty", "not_run", "needs_key")


class UnexpectedAnswer(Exception):
    """The source answered something that is not its documented shape: could not verify."""


STATUS_FOR: dict[str, Status] = {
    "error": Status.ERROR,
    "timeout": Status.ERROR,
    "rate_limited": Status.RATE_LIMITED,
    "quota": Status.QUOTA,
    "blocked": Status.BLOCKED,
    "needs_key": Status.NEEDS_KEY,
}
FAILURE_ORDER = ("rate_limited", "quota", "blocked", "timeout", "error", "needs_key")


def run_source(outcome: SourceOutcome, fn: Callable[[SourceOutcome], None], *, keyed: bool = False) -> SourceOutcome:
    """Run ``fn(outcome)`` and translate the core's exceptions into the outcome (rule 5: every failure
    is 'could not verify', never an absence). Cancelled/RequestCapReached are kept in ``outcome.stop``
    so the module can re-raise them after merging (the engine then keeps the partial result)."""
    def keep_partial(status: str, reason: str, code: str) -> None:
        sink = outcome.sink
        has_data = bool(outcome.certs) or (sink is not None and bool(sink.names or sink.wildcards or sink.out_of_apex))
        if has_data:  # a later page or search failed: keep what was collected, flagged partial
            outcome.status, outcome.partial = "ok", True
        else:
            outcome.status = status
        outcome.reason, outcome.reason_code = reason, code

    try:
        fn(outcome)
    except (Cancelled, RequestCapReached) as exc:
        outcome.stop = exc
        keep_partial("error", f"{outcome.label}: stopped ({type(exc).__name__})", "error")
    except RateLimited as exc:
        keep_partial("rate_limited", f"{outcome.label}: rate limited ({exc})", "rate_limited")
    except QuotaExceeded as exc:
        keep_partial("quota", f"{outcome.label}: quota exhausted ({exc})", "quota")
    except Blocked as exc:
        keep_partial("blocked", f"{outcome.label}: blocked ({exc})", str(getattr(exc, "reason_code", "") or "challenge"))
    except AuthRequired as exc:
        if keyed:
            keep_partial("needs_key", f"{outcome.label}: the key was refused ({exc})", "needs_key")
        else:
            keep_partial("blocked", f"{outcome.label}: refused the keyless request ({exc}): could not verify", "challenge")
    except DeadlineExceeded as exc:
        keep_partial("timeout", f"{outcome.label}: no answer within the budget ({exc}): could not verify", "timeout")
    except (PolicyError, ConfigError):
        raise
    except NetworkError as exc:
        kind = str(getattr(exc, "kind", "") or "").lower()
        timed_out = "timeout" in kind or "timed out" in str(exc).lower()
        keep_partial("timeout" if timed_out else "error", f"{outcome.label}: {exc}: could not verify", "timeout" if timed_out else "error")
    except HttpError as exc:
        code = str(getattr(exc, "reason_code", "") or "error")
        keep_partial("timeout" if code == "timeout" else "error", f"{outcome.label}: {exc}: could not verify", code if code in ("timeout", "error") else "error")
    except UnexpectedAnswer as exc:
        keep_partial("error", f"{outcome.label}: {exc}: could not verify", "error")
    except Exception as exc:  # noqa: BLE001 - untrusted data: a parser surprise is 'could not verify', never a crash
        keep_partial("error", f"{outcome.label}: unexpected answer ({type(exc).__name__}): could not verify", "error")
    return outcome


# ======================================================================================
# Source parsers (pure)
# ======================================================================================


def parse_crtsh(records: list[Any], sink: HostnameSink, source: str = SRC_CRTSH) -> list[dict[str, Any]]:
    """crt.sh JSON records -> certificates (deduplicated by issuer + serial: crt.sh lists the
    precertificate and the leaf separately) and names added to ``sink`` with provenance."""
    certs: dict[str, dict[str, Any]] = {}
    for rec in records:
        if not isinstance(rec, dict):
            continue
        serial = rec.get("serial_number") if isinstance(rec.get("serial_number"), str) else None
        issuer = rec.get("issuer_name") if isinstance(rec.get("issuer_name"), str) else None
        issuer_id = rec.get("issuer_ca_id") if isinstance(rec.get("issuer_ca_id"), int) else issuer
        key = f"crtsh:{issuer_id}|{serial}" if serial else f"crtsh:id:{rec.get('id')}"
        cert = certs.get(key)
        if cert is None:
            cn = rec.get("common_name") if isinstance(rec.get("common_name"), str) else None
            cert = {
                "source": source,
                "key": key,
                "crtsh_ids": [],
                "serial": serial,
                "issuer": issuer,
                "issuer_org": dn_attr(issuer, "O"),
                "common_name": cn,
                "not_before": iso(parse_iso8601(rec.get("not_before"))),
                "not_after": iso(parse_iso8601(rec.get("not_after"))),
                "names": [],
                "sans": [],
                "sha256": None,
            }
            certs[key] = cert
        cid = rec.get("id")
        if isinstance(cid, int) and not isinstance(cid, bool) and cid not in cert["crtsh_ids"] and len(cert["crtsh_ids"]) < 10:
            cert["crtsh_ids"].append(cid)
        raw_names = split_name_value(rec.get("name_value"))
        if cert["common_name"]:
            raw_names.append(cert["common_name"])
        for raw in raw_names:
            san = dns_san(raw)
            if san and san not in cert["sans"] and len(cert["sans"]) < MAX_SANS:
                cert["sans"].append(san)
            label = sink.add(raw, source, key)
            if label and label not in cert["names"]:
                cert["names"].append(label)
    return list(certs.values())


def parse_certspotter_page(items: list[Any], sink: HostnameSink, source: str) -> tuple[list[dict[str, Any]], str | None]:
    """One Cert Spotter issuances page -> (certificates, id of the last issuance)."""
    certs: list[dict[str, Any]] = []
    last_id: str | None = None
    for it in items:
        if not isinstance(it, dict):
            continue
        raw_id = it.get("id")
        iid = str(raw_id) if isinstance(raw_id, (str, int)) and not isinstance(raw_id, bool) and str(raw_id).strip() else None
        issuer = it.get("issuer") if isinstance(it.get("issuer"), dict) else {}
        sha = it.get("cert_sha256")
        sha = sha.lower() if isinstance(sha, str) and _SHA256_RE.match(sha) else None
        ref = f"certspotter:{sha or iid}"
        names: list[str] = []
        sans: list[str] = []
        for raw in split_name_value(it.get("dns_names")):
            san = dns_san(raw)
            if san and san not in sans and len(sans) < MAX_SANS:
                sans.append(san)
            label = sink.add(raw, source, ref)
            if label and label not in names:
                names.append(label)
        friendly = issuer.get("friendly_name") if isinstance(issuer.get("friendly_name"), str) else None
        issuer_dn = issuer.get("name") if isinstance(issuer.get("name"), str) else None
        certs.append({
            "source": source,
            "key": ref,
            "id": iid,
            "issuer": issuer_dn,
            "issuer_org": dn_attr(issuer_dn, "O") or friendly,  # the DN O= matches crt.sh's issuer naming
            "common_name": None,
            "not_before": iso(parse_iso8601(it.get("not_before"))),
            "not_after": iso(parse_iso8601(it.get("not_after"))),
            "names": names,
            "sans": sans,
            "sha256": sha,
            "revoked": it.get("revoked") if isinstance(it.get("revoked"), bool) else None,
        })
        if iid:
            last_id = iid
    return certs, last_id


def parse_hostname_list(items: list[Any], sink: HostnameSink, source: str) -> int:
    """A bare JSON list of host names (ctl.shodan.io) -> names in ``sink``; returns the count kept."""
    kept = 0
    for item in items:
        name = item if isinstance(item, str) else (item.get("hostname") if isinstance(item, dict) else None)
        if isinstance(name, str) and sink.add(name, source):
            kept += 1
    return kept


def ct_summary(certs: list[dict[str, Any]], sink: HostnameSink, sources: Iterable[str]) -> dict[str, Any]:
    """P001 cond 9: counts (certificates naming the domain, unique names, earliest not_before,
    issuers) and the top 20 names by certificate count. ``first_cert_seen`` is a lower bound of age."""
    issuers: Counter[str] = Counter()
    freq: Counter[str] = Counter()
    earliest: datetime | None = None
    counted = 0
    seen: set[str] = set()
    for cert in certs:
        bare = [n[2:] if n.startswith("*.") else n for n in cert.get("names") or [] if isinstance(n, str)]
        if not any(in_apex(n, sink.apex) for n in bare):
            continue  # S/MIME-only or test certificates: not a certificate of this domain
        ident = f"{cert.get('not_before')}|{cert.get('not_after')}|{','.join(sorted(set(bare)))}"
        if ident in seen:
            continue  # the same certificate from crt.sh and Cert Spotter (same validity and names) counts once
        seen.add(ident)
        counted += 1
        iss = cert.get("issuer_org") or dn_attr(cert.get("issuer"), "CN") or cert.get("issuer")
        if iss:
            issuers[str(iss)] += 1
        nb = parse_iso8601(cert.get("not_before"))
        if nb and (earliest is None or nb < earliest):
            earliest = nb
        for n in bare:
            if in_apex(n, sink.apex) and n != sink.apex:
                freq[n] += 1
    names = sink.subdomains()
    ranked = sorted(names, key=lambda n: (-freq.get(n, 0), n))
    return {
        "cert_count": counted,
        "unique_names": len(names),
        "first_cert_seen": iso(earliest),
        "issuers": [[name, count] for name, count in issuers.most_common()],
        "top_names": ranked[:TOP_NAMES],
        "wildcards": sink.wildcard_labels(),
        "sources": sorted(set(sources)),
    }


# ======================================================================================
# Per-scan memo (brand searches run once per scan)
# ======================================================================================

_MEMO_LOCK = threading.Lock()
_BRAND_DONE: dict[str, set[str]] = {}
_MEMO_MAX = 64


def claim_once(memo: dict[str, set[str]], case_id: str, key: str) -> bool:
    """True the first time ``key`` is claimed in scan ``case_id`` (no case id: always True)."""
    if not case_id:
        return True
    with _MEMO_LOCK:
        if case_id not in memo and len(memo) >= _MEMO_MAX:
            memo.pop(next(iter(memo)))
        done = memo.setdefault(case_id, set())
        if key in done:
            return False
        done.add(key)
        return True


# ======================================================================================
# The module
# ======================================================================================


def _budget(ctx: Any) -> float:
    try:
        value = float(ctx.setting("ct_logs_budget", DEFAULT_BUDGET))
    except (TypeError, ValueError):
        value = DEFAULT_BUDGET
    return max(MIN_BUDGET, min(MAX_BUDGET, value))


def _monotonic(ctx: Any) -> float:
    clock = getattr(getattr(ctx, "http", None), "clock", None)
    return float(clock.monotonic()) if clock is not None else time.monotonic()


@register
class CtLogs(Module):
    name = "ct_logs"
    title = "Certificate Transparency search"
    description = "Subdomains, certificates, SAN affiliates and first-seen date of a registrable domain from Certificate Transparency (crt.sh, Cert Spotter, ctl.shodan.io)."
    category = "domain_dns"
    accepts = {T.DOMAIN}
    produces = {T.DOMAIN, T.CERT_FP}
    terms = "noncommercial"  # most restrictive source: keyless Cert Spotter and ctl.shodan.io (P001 cond 2)
    opsec = Opsec.PASSIVE
    disclosure = "third_party"
    provider = "crtsh"
    sources = (SRC_CRTSH, SRC_CERTSPOTTER, SRC_CERTSPOTTER_KEYLESS, SRC_CTL)
    hosts = ("crt.sh", "api.certspotter.com", "ctl.shodan.io")
    access_model = "free_noauth_limited"
    optional_keys = ("certspotter",)
    max_requests = 10  # crt.sh 1 + Cert Spotter <= 5 pages + ctl.shodan.io 1 + brand searches <= 3 (P001 cond 5)
    expected_latency = 10.0  # declared p50 cap (P001 cond 5); crt.sh is often slow: measured by doctor (A3 demotion)
    timeout = MAX_BUDGET  # hard run deadline; the shared source budget is the setting ct_logs_budget (30 s)
    min_interval = 1.0
    cache_ttl = 86400
    max_pivots = 200
    error_markers = CRTSH_MARKERS
    manual_link = "ct_rdap_lookups:crtsh_domain"
    default_enabled = True
    reference = "https://crt.sh/"
    tags = {"cert_derived", "free"}
    notice = (
        "Keyless Cert Spotter and ctl.shodan.io are noncommercial: off under the corporate profile until licence-cleared "
        "(crt.sh alone keeps the module useful; Cert Spotter with the team's key once key_plans.certspotter is recorded). "
        "Brand mode (ct_brand_search, off by default) discloses org_profile brand keywords to crt.sh."
    )
    settings = {
        "ct_logs_budget": SettingSpec(int(DEFAULT_BUDGET), "ct_logs: time budget in seconds shared by its CT sources (P001 cond 4: default 30, at most 90)"),
        "ct_brand_search": SettingSpec(False, "ct_logs: opt-in crt.sh identity search q=%brand% for org_profile brands of an own-domain seed (discloses the keyword to crt.sh; P001 cond 10)"),
        "ct_logs_check_liveness": SettingSpec(True, "ct_logs: resolve CT names through DoH and label NXDOMAIN names historical (P001 cond 7)"),
    }

    def applies(self, entity: Entity, ctx: Any) -> bool:
        """Once per registrable domain (P001 cond 7): subdomains are covered by the apex run."""
        name = str(entity.value)
        tld = name.rsplit(".", 1)[-1]
        return psl.is_known_tld(tld) and registrable(name) == name

    # ------------------------------------------------------------------ run
    def run(self, entity: Entity, ctx: Any) -> ModuleResult:
        res = self.result(entity)
        apex = str(entity.value)
        allowed = ctx.allowed_sources
        deadline = _monotonic(ctx) + _budget(ctx)
        tasks: list[tuple[SourceOutcome, Callable[[SourceOutcome], None], bool]] = []
        if SRC_CRTSH in allowed:
            tasks.append((SourceOutcome(SRC_CRTSH, "crt.sh"), lambda o: self._crtsh(o, ctx, apex, deadline), False))
        missing_key = False
        spotter = self._certspotter_plan(ctx, allowed)
        if spotter is not None:
            source, key = spotter
            if source == SRC_CERTSPOTTER and not key:
                missing_key = True
                res.source_status(SRC_CERTSPOTTER, Status.NEEDS_KEY, reason="Cert Spotter: the keyed source is allowed but no certspotter key is configured")
            else:
                tasks.append((SourceOutcome(source, "Cert Spotter"), lambda o, s=source, k=key: self._certspotter(o, ctx, apex, s, k, deadline), bool(key)))
        if SRC_CTL in allowed:
            tasks.append((SourceOutcome(SRC_CTL, "ctl.shodan.io"), lambda o: self._ctl(o, ctx, apex, deadline), False))
        if not tasks:
            if missing_key:
                return res.mark("needs_key", "Cert Spotter needs the certspotter key and no other CT source is allowed")
            return res.mark("skipped", "no Certificate Transparency source is allowed for this run", reason_code="config")
        brand: SourceOutcome | None = None
        brand_terms = self._brand_terms(ctx, entity, allowed)
        if brand_terms:
            brand = SourceOutcome(SRC_CRTSH, BRAND_LABEL)
            tasks.append((brand, lambda o: self._brand_search(o, ctx, brand_terms, deadline), False))
        with concurrent.futures.ThreadPoolExecutor(max_workers=len(tasks), thread_name_prefix="ct_logs") as pool:
            futures = [pool.submit(run_source, outcome, fn, keyed=keyed) for outcome, fn, keyed in tasks]
            for fut in futures:
                fut.result()  # workers never raise, except PolicyError/ConfigError (engine: SKIPPED)
        outcomes = [t[0] for t in tasks if t[0] is not brand]
        stop = next((o.stop for o in [t[0] for t in tasks] if o.stop is not None), None)
        self._build(res, ctx, apex, outcomes, deadline)
        self._brand_output(res, ctx, brand)
        if stop is not None:
            raise stop  # the engine keeps the result built above (partial, stop reason request_cap/cancelled)
        return res

    # ------------------------------------------------------------------ sources
    @staticmethod
    def _certspotter_plan(ctx: Any, allowed: frozenset[str]) -> tuple[str, str] | None:
        """Keyed source when a key is configured and allowed, else the keyless one when allowed."""
        key = ctx.key("certspotter") if SRC_CERTSPOTTER in allowed else ""
        if key:
            return SRC_CERTSPOTTER, key
        if SRC_CERTSPOTTER_KEYLESS in allowed:
            return SRC_CERTSPOTTER_KEYLESS, ""
        if SRC_CERTSPOTTER in allowed:
            return SRC_CERTSPOTTER, ""
        return None

    @staticmethod
    def _crtsh(out: SourceOutcome, ctx: Any, apex: str, deadline: float) -> None:
        out.sink = HostnameSink(apex)
        url = CRTSH_URL + "?" + urlencode({"q": f"%.{apex}", "output": "json", "exclude": "expired"})
        resp = ctx.http.get(url, headers={"Accept": "application/json"}, source=SRC_CRTSH, deadline=deadline)
        ctx.http.check(resp)  # markers, challenge pages, 403/429/5xx -> exceptions (could not verify)
        records, complete = crtsh_records(resp.text, truncated=bool(resp.truncated))
        out.pages = 1
        out.certs = parse_crtsh(records, out.sink)
        if not complete:
            out.truncated = out.partial = True
            out.reason = f"crt.sh answer cut at the size cap: {len(records)} record(s) parsed, never read as complete (P001 cond 5)"
            if not out.certs:
                out.status, out.reason_code = "error", "error"
                out.reason += "; nothing usable before the cut: could not verify"
                return
        out.status = "ok" if (out.sink.names or out.sink.wildcards or out.certs) else "empty"

    @staticmethod
    def _certspotter(out: SourceOutcome, ctx: Any, apex: str, source: str, key: str, deadline: float) -> None:
        out.sink = HostnameSink(apex)
        headers = {"Accept": "application/json"}
        if key:
            headers["Authorization"] = f"Bearer {key}"  # Bearer header only (P001 cond 3)
        after: str | None = None
        for _page in range(CERTSPOTTER_MAX_PAGES):
            params = [("domain", apex), ("include_subdomains", "true"), ("expand", "dns_names"), ("expand", "issuer")]
            if after:
                params.append(("after", after))
            data = ctx.http.get_json(CERTSPOTTER_URL + "?" + urlencode(params), headers=headers, source=source, deadline=deadline)
            if isinstance(data, dict):
                raise UnexpectedAnswer(f"error object {str(data.get('code') or 'without code')[:40]} instead of an issuance list")
            if not isinstance(data, list):
                raise UnexpectedAnswer(f"{type(data).__name__} instead of an issuance list")
            out.pages += 1
            if not data:
                break
            certs, last = parse_certspotter_page(data, out.sink, source)
            out.certs.extend(certs)
            if not last or last == after:
                break
            after = last
        else:
            out.partial = True
            out.reason_code = "request_cap"  # the module's own page cap: stop reason request_cap
            out.reason = f"Cert Spotter page cap reached ({CERTSPOTTER_MAX_PAGES} pages): more issuances may exist"
        out.status = "ok" if (out.sink.names or out.sink.wildcards or out.certs) else "empty"

    @staticmethod
    def _ctl(out: SourceOutcome, ctx: Any, apex: str, deadline: float) -> None:
        out.sink = HostnameSink(apex)
        data = ctx.http.get_json(CTL_URL.format(apex=apex), source=SRC_CTL, deadline=deadline)
        if not isinstance(data, list):
            raise UnexpectedAnswer(f"{type(data).__name__} instead of a host name list")
        out.pages = 1
        parse_hostname_list(data, out.sink, SRC_CTL)
        out.status = "ok" if (out.sink.names or out.sink.wildcards) else "empty"

    # ------------------------------------------------------------------ brand mode (P001 cond 10)
    @staticmethod
    def _brand_terms(ctx: Any, entity: Entity, allowed: frozenset[str]) -> list[str]:
        if not bool(ctx.setting("ct_brand_search", False)) or SRC_CRTSH not in allowed or not ctx.is_seed:
            return []
        org = ctx.org
        try:
            own = org.owns(entity)
        except Exception:  # noqa: BLE001 - a profile problem never breaks a run
            return []
        if not getattr(own, "own", False) or getattr(own, "kind", "") != "domain":
            return []
        terms = brand_search_terms(getattr(b, "keyword", "") for b in getattr(org, "brands", ()) or ())[:BRAND_SEARCH_CAP]
        return [t for t in terms if claim_once(_BRAND_DONE, str(ctx.case_id or ""), t)]

    @staticmethod
    def _brand_search(out: SourceOutcome, ctx: Any, terms: list[str], deadline: float) -> None:
        out.sink = HostnameSink("")  # no apex: every name is a lookalike candidate (out_of_apex)
        for term in terms:
            url = CRTSH_URL + "?" + urlencode({"q": f"%{term}%", "output": "json", "exclude": "expired"})
            resp = ctx.http.get(url, headers={"Accept": "application/json"}, source=SRC_CRTSH, deadline=deadline)
            ctx.http.check(resp)
            records, complete = crtsh_records(resp.text, truncated=bool(resp.truncated))
            out.pages += 1
            if not complete:
                out.partial = True
            parse_crtsh(records, out.sink)
        out.status = "ok" if out.sink.out_of_apex else "empty"

    # ------------------------------------------------------------------ output
    def _build(self, res: ModuleResult, ctx: Any, apex: str, outcomes: list[SourceOutcome], deadline: float) -> None:
        sink = HostnameSink(apex)
        certs: list[dict[str, Any]] = []
        for o in outcomes:
            record_source_status(res, o)
            if o.answered and o.sink is not None:
                sink.merge(o.sink)
                certs.extend(o.certs)
        raw: dict[str, Any] = {
            "apex": apex,
            "sources": {o.source: {"label": o.label, "status": o.status, "reason": o.reason, "partial": o.partial,
                                   "truncated": o.truncated, "pages": o.pages} for o in outcomes},
            "rejected_names": dict(sink.rejected),
        }
        res.raw = raw
        answered = [o for o in outcomes if o.answered]
        if not answered:
            mark_no_answer(res, outcomes)
            return
        incomplete = [o for o in outcomes if o.partial or o.failed]
        if incomplete:
            res.partial = True
            stop = stop_reason_for(incomplete)
            if stop:
                res.stop(stop)
            notes = "; ".join(o.reason for o in incomplete if o.reason)
            res.error = "partial: " + (notes or "a Certificate Transparency source could not be verified")
        if not (sink.names or sink.wildcards or certs):
            res.mark("empty")  # every answering source answered: no certificate for this domain
            return
        summary = ct_summary(certs, sink, [o.label for o in answered])
        subdomains = sink.subdomains()
        res.attr("subdomains", subdomains[:SUBDOMAINS_ATTR_CAP])
        res.attr("wildcard_cert", sink.wildcard_labels())
        res.attr("first_cert_seen", summary["first_cert_seen"])
        res.attr("ct_summary", summary)
        historical, unresolved = emit_subdomain_pivots(res, ctx, sink, deadline)
        res.attr("ct_names_historical", historical)
        res.attr("ct_names_unresolved", unresolved)
        self._fingerprint_pivots(res, certs)
        self._affiliates(res, certs, apex)
        self._summary_finding(res, summary, answered)
        res.link("crt.sh report (all certificates of the domain)", f"https://crt.sh/?q=%25.{apex}")
        raw["certificates"] = [compact_cert(c) for c in certs[:EVIDENCE_CERT_CAP]]
        raw["certificates_total"] = len(certs)
        raw["names"] = {n: list(info.sources) for n, info in list(sink.names.items())[:SUBDOMAINS_ATTR_CAP]}

    @staticmethod
    def _fingerprint_pivots(res: ModuleResult, certs: list[dict[str, Any]]) -> None:
        seen: list[str] = []
        for cert in certs:
            sha = cert.get("sha256")
            if sha and sha not in seen:
                seen.append(sha)
        for sha in seen[:FINGERPRINT_PIVOT_CAP]:
            res.pivot(T.CERT_FP, sha, "has_certificate", confidence="confirmed", expand=False, note="certificate issued for the domain (Certificate Transparency)")

    @staticmethod
    def _affiliates(res: ModuleResult, certs: list[dict[str, Any]], apex: str) -> None:
        """P001 cond 8: SAN affiliates of non-shared certificates; shared certificates link nothing."""
        shared: list[dict[str, Any]] = []
        shared_keys: set[str] = set()
        affiliates: Counter[str] = Counter()
        for cert in certs:
            sharing = classify_cert_sharing(cert.get("sans") or cert.get("names") or [], cert.get("common_name"))
            if sharing["shared"]:
                key = f"{cert.get('issuer_org')}|{cert.get('not_before')}|{sharing['san_count']}"
                if key not in shared_keys and len(shared) < SHARED_ATTR_CAP:
                    shared_keys.add(key)
                    shared.append({
                        "issuer": cert.get("issuer_org") or cert.get("issuer"),
                        "not_before": cert.get("not_before"),
                        "san_count": sharing["san_count"],
                        "registrable_domains": len(sharing["registrable_domains"]),
                        "reason": sharing["reason"],
                    })
                continue
            regs = sorted({r for r in (registrable(n[2:] if n.startswith("*.") else n) for n in cert.get("names") or []) if r})
            if apex not in regs:
                continue  # e.g. an S/MIME certificate matched through an e-mail SAN: no affiliation
            affiliates.update(r for r in regs if r != apex)
        res.attr("shared_cert", shared)
        for reg in sorted(affiliates, key=lambda r: (-affiliates[r], r))[:AFFILIATE_PIVOT_CAP]:
            res.pivot(T.DOMAIN, reg, "cert_san", confidence="probable", expand=False,
                      note=f"SAN affiliate: {affiliates[reg]} non-shared certificate(s) also cover {apex}")

    @staticmethod
    def _summary_finding(res: ModuleResult, summary: dict[str, Any], answered: list[SourceOutcome]) -> None:
        issuers = ", ".join(f"{name} ({count})" for name, count in summary["issuers"][:5]) or "none"
        first = summary["first_cert_seen"] or "unknown"
        top = ", ".join(summary["top_names"][:10])
        res.finding(
            "Certificate Transparency summary",
            "info",
            f"{summary['cert_count']} certificate(s) and {summary['unique_names']} unique name(s) from "
            f"{', '.join(summary['sources'])}; earliest not_before {first} (a lower bound of the domain's age, not a "
            f"registration date); issuers: {issuers}." + (f" Top names: {top}." if top else ""),
            confidence="confirmed",
            criterion="certificates logged in public Certificate Transparency logs",
            data={k: summary[k] for k in ("cert_count", "unique_names", "first_cert_seen", "issuers", "top_names")},
            tags=["info"],
            source=answered[0].source,
            observed_first=summary["first_cert_seen"],
        )

    @staticmethod
    def _brand_output(res: ModuleResult, ctx: Any, brand: SourceOutcome | None) -> None:
        """P001 cond 10: out-of-profile names of the brand search become lookalike pivots (expand=False)."""
        if brand is None:
            return
        if isinstance(res.raw, dict):
            res.raw["brand_search"] = {"status": brand.status, "reason": brand.reason, "pages": brand.pages, "partial": brand.partial}
        if not brand.answered or brand.sink is None:
            return
        org = ctx.org
        lookalikes: list[str] = []
        for reg in sorted({r for r in (registrable(n) for n in brand.sink.out_of_apex) if r}):
            ent = Entity.try_make(T.DOMAIN, reg)
            if ent is None:
                continue
            try:
                own = org.owns(ent)
            except Exception:  # noqa: BLE001 - a profile problem never breaks a run
                continue
            if not getattr(own, "own", False):
                lookalikes.append(reg)
        for reg in lookalikes[:LOOKALIKE_PIVOT_CAP]:
            res.pivot(T.DOMAIN, reg, "lookalike", confidence="possible", expand=False,
                      note="org brand keyword in a certificate name outside the organisation profile (typosquat candidate, P028)")
        if lookalikes:
            res.finding(
                "Certificates naming org brands outside the organisation profile",
                "info",
                f"{len(lookalikes)} registrable domain(s) carry an org_profile brand keyword in Certificate Transparency names; "
                "they are listed as lookalike candidates for typosquat scoring (P028).",
                confidence="possible",
                criterion="crt.sh identity search for org_profile brand keywords (opt-in setting ct_brand_search)",
                data={"count": len(lookalikes), "sample": lookalikes[:20]},
                tags=["info"],
                source=SRC_CRTSH,
            )


def record_source_status(res: ModuleResult, o: SourceOutcome) -> None:
    """Per-source outcome in res.source_statuses (P001 cond 4: per-source status is kept)."""
    if o.status == "not_run":
        return
    if o.answered:
        res.source_status(o.source, Status.OK if o.status == "ok" else Status.EMPTY, reason=o.reason)
        return
    status = STATUS_FOR[o.status]
    code = o.reason_code if valid_reason(status, o.reason_code) else ""
    res.source_status(o.source, status, reason_code=code, reason=o.reason)


def stop_reason_for(outcomes: list[SourceOutcome]) -> str:
    """Canonical stop reason of a partial run ('' when none fits, e.g. a 5xx next to an answer or a body
    cut at the core size cap: partial=True without a stop reason, P001 cond 5)."""
    seen = {o.status for o in outcomes} | {o.reason_code for o in outcomes}
    for stop, keys in (("deadline", {"timeout"}), ("rate_limited", {"rate_limited"}), ("quota", {"quota"}), ("request_cap", {"request_cap"})):
        if seen & keys:
            return stop
    return ""


def mark_no_answer(res: ModuleResult, outcomes: list[SourceOutcome]) -> None:
    """Rule 5: no CT source answered - could not verify, never 'no certificates'."""
    failures = [o for o in outcomes if o.failed or o.status == "needs_key"]
    reasons = "; ".join(o.reason for o in failures if o.reason) or "no Certificate Transparency source answered"
    for wanted in FAILURE_ORDER:
        hit = next((o for o in failures if o.status == wanted), None)
        if hit is not None:
            status = STATUS_FOR[wanted]
            code = hit.reason_code if valid_reason(status, hit.reason_code) else ""
            res.mark(status, f"could not verify: {reasons}", reason_code=code)
            return
    res.mark("error", f"could not verify: {reasons}", reason_code="error")


def emit_subdomain_pivots(res: ModuleResult, ctx: Any, sink: HostnameSink, deadline: float) -> tuple[list[str], list[str]]:
    """Live names first, then unchecked/unresolved, then historical ones (expand=False): P001 cond 7."""
    weight = {n: len(info.certs) + len(info.sources) for n, info in sink.names.items()}
    names = sorted(sink.subdomains(), key=lambda n: (-weight.get(n, 0), n))[:SUBDOMAIN_PIVOT_CAP]
    liveness: dict[str, str] = {}
    if names and bool(ctx.setting("ct_logs_check_liveness", True)) and deadline - _monotonic(ctx) > LIVENESS_MIN_BUDGET:
        liveness = dns_liveness(ctx, names[:LIVENESS_CAP])
    historical = sorted(n for n, state in liveness.items() if state == "historical")
    unresolved = sorted(n for n, state in liveness.items() if state == "unresolved")
    order = {"live": 0, "unchecked": 1, "unresolved": 2, "historical": 3}
    for name in sorted(names, key=lambda n: (order[liveness.get(n, "unchecked")], -weight.get(n, 0), n)):
        state = liveness.get(name, "unchecked")
        seen_in = ", ".join(sink.names[name].sources)
        if state == "historical":
            res.pivot(T.DOMAIN, name, "subdomain", confidence="probable", expand=False,
                      note=f"historical: NXDOMAIN through DoH (confirmed by a second resolver), seen in CT ({seen_in}): passive modules only")
        elif state == "unresolved":
            res.pivot(T.DOMAIN, name, "subdomain", confidence="probable", note=f"seen in CT ({seen_in}); DoH could not verify it (unresolved)")
        else:
            res.pivot(T.DOMAIN, name, "subdomain", confidence="probable", note=f"seen in CT ({seen_in})")
    return historical, unresolved


def crtsh_records(text: str, *, truncated: bool) -> tuple[list[Any], bool]:
    """crt.sh body -> ``(records, complete)``; a truncated or cut body keeps the records before the cut."""
    body = (text or "").strip()
    if not body:
        raise UnexpectedAnswer("empty body instead of a JSON list")
    if looks_like_html(body):
        raise UnexpectedAnswer("HTML instead of JSON")
    if not truncated:
        try:
            data = json.loads(body)
        except ValueError:
            data = None
        if isinstance(data, list):
            return data, True
        if isinstance(data, dict):
            raise UnexpectedAnswer("JSON object instead of a certificate list")
    records, complete = salvage_json_array(body)
    if not records and not body.startswith("["):
        raise UnexpectedAnswer("malformed JSON")
    return records, complete and not truncated


def dns_liveness(ctx: Any, names: list[str]) -> dict[str, str]:
    """DoH liveness of CT names (P001 cond 7): NXDOMAIN confirmed by a second resolver -> 'historical';
    a resolvable name -> 'live'; SERVFAIL/timeouts/refusals -> 'unresolved' (could not verify, rule 5)."""

    def check(name: str) -> tuple[str, str]:
        try:
            confirmed = ctx.dns.confirm_nxdomain(name, "A")
        except Exception:  # noqa: BLE001 - a resolver problem is 'could not verify', never an absence
            return name, "unresolved"
        if confirmed is True:
            return name, "historical"
        if confirmed is False:
            return name, "live"
        return name, "unresolved"

    if not names:
        return {}
    with concurrent.futures.ThreadPoolExecutor(max_workers=min(LIVENESS_WORKERS, len(names)), thread_name_prefix="ct_logs_dns") as pool:
        return dict(pool.map(check, names))


def compact_cert(cert: dict[str, Any]) -> dict[str, Any]:
    """Evidence form of a certificate (names capped at 50)."""
    names = list(cert.get("names") or [])
    return {
        "source": cert.get("source"),
        "issuer": cert.get("issuer_org") or cert.get("issuer"),
        "not_before": cert.get("not_before"),
        "not_after": cert.get("not_after"),
        "serial": cert.get("serial"),
        "sha256": cert.get("sha256"),
        "crtsh_ids": cert.get("crtsh_ids") or [],
        "names": names[:50],
        "name_count": len(names),
    }
