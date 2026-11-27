"""Shared helpers of the internet-scan-engine API modules of batch p3-G02-1.

The modules ``netlas`` (P037), ``onyphe`` (P042), ``censys`` (P044), ``criminalip`` (P048) and ``fofa``
(P049) query keyed internet-scan search engines. This file holds what they share; it registers no module.

* :func:`fetch_json` sends one request through ``ctx.http`` and applies the P321 classification. The
  registry markers can only map to blocked, rate_limited, quota or error, but P037 cond 4, P042 cond 4,
  P048 cond 3 and P049 want 'key missing or refused' answers inside HTTP 200 reported as NEEDS_KEY. A
  marker whose id the module lists in ``needs_key_markers`` therefore raises
  :class:`v3lum.core.http.AuthRequired`, which the engine maps to NEEDS_KEY for keyed modules. Every other
  classification raises as usual. A classified answer is never cached and never read as EMPTY.
* There are coercers for untrusted JSON, and domain, IP and apex helpers built on the core PSL.
* :func:`cert_sharing` applies the P001 shared-certificate rule: more than 20 SANs over more than 5
  registrable domains, or a CDN/hosting shared-certificate pattern. The CDN patterns come from
  ``ct_logs`` when that module is installed.
* :func:`vuln_severity` caps version-inferred vulnerabilities (P291): never CRITICAL from a scan engine
  alone.
* :func:`explicitly_selected` returns True when the module was selected with ``-M`` or runs as a single
  ``v3lum run``.
"""

from __future__ import annotations

import ipaddress
import json
import re
from collections.abc import Iterable, Mapping
from typing import Any

from v3lum.core.entities import Entity
from v3lum.core.entities import EntityType as T
from v3lum.core.http import AuthRequired, HttpError
from v3lum.core.noise import is_public_ip
from v3lum.core.psl import registrable_domain

#: P001 cond 8: a certificate listing more than 20 SANs over more than 5 registrable domains is shared.
SHARED_SAN_THRESHOLD = 20
SHARED_DOMAIN_THRESHOLD = 5
VERSION_INFERRED_CRITERION = "version-inferred from the provider's banner/CPE data, distro backports not considered: confirm on the host"
CVE_RE = re.compile(r"^CVE-\d{4}-\d{4,7}$")
SHA256_RE = re.compile(r"^[0-9a-f]{64}$")
SEVERITY_ORDER = ("info", "low", "medium", "high", "critical")

try:  # the P001 CDN/hosting shared-certificate patterns, when ct_logs is installed
    from v3lum.modules.domain_dns.ct_logs import SHARED_CERT_PATTERNS as _CDN_CERT_PATTERNS
except Exception:  # noqa: BLE001 - an import problem of another module must not break these modules
    _CDN_CERT_PATTERNS = ()


class EndpointRefused(ValueError):
    """An endpoint a module never wires (scan, rescan, upload, search outside the allow-list...)."""


# --------------------------------------------------------------------------------------
# untrusted-data coercers
# --------------------------------------------------------------------------------------


def text(value: Any, limit: int = 200) -> str:
    """A stripped, length-capped string; '' for anything that is not a non-empty string."""
    if not isinstance(value, str):
        return ""
    cleaned = "".join(ch for ch in value if ch.isprintable() or ch == " ").strip()
    return cleaned[:limit]


def integer(value: Any) -> int | None:
    if isinstance(value, bool):
        return None
    if isinstance(value, int):
        return value
    if isinstance(value, float) and value == value and value.is_integer():
        return int(value)
    if isinstance(value, str) and re.fullmatch(r"-?\d{1,15}", value.strip()):
        return int(value.strip())
    return None


def number(value: Any) -> float | None:
    if isinstance(value, bool) or not isinstance(value, (int, float, str)):
        return None
    try:
        out = float(value)
    except ValueError:
        return None
    return out if out == out and out not in (float("inf"), float("-inf")) else None


def flag(value: Any) -> bool | None:
    """True/False from booleans and the strings 'true'/'false' (Netlas writes fp.alarm as a string)."""
    if isinstance(value, bool):
        return value
    if isinstance(value, str) and value.strip().lower() in ("true", "false"):
        return value.strip().lower() == "true"
    return None


def as_list(value: Any) -> list[Any]:
    return value if isinstance(value, list) else []


def as_dict(value: Any) -> dict[str, Any]:
    return value if isinstance(value, dict) else {}


def str_list(value: Any, limit: int = 50, item_limit: int = 300) -> list[str]:
    out: list[str] = []
    for item in as_list(value):
        s = text(item, item_limit)
        if s and s not in out:
            out.append(s)
        if len(out) >= limit:
            break
    return out


def port(value: Any) -> int | None:
    n = integer(value)
    return n if n is not None and 0 < n < 65536 else None


# --------------------------------------------------------------------------------------
# names and addresses
# --------------------------------------------------------------------------------------


def normalize_domain(value: Any) -> str | None:
    """A valid host name (lower-case, no trailing dot, '*.' stripped) or None. Names with an underscore
    label (``_dc-mx...``) are service labels, never hosts, and are dropped."""
    s = text(value, 253).lower().rstrip(".")
    if s.startswith("*."):
        s = s[2:]
    if not s or "." not in s or any(label.startswith("_") for label in s.split(".")):
        return None
    ent = Entity.try_make(T.DOMAIN, s)
    return ent.value if ent is not None else None


def normalize_ip(value: Any) -> str | None:
    s = text(value, 64)
    try:
        return str(ipaddress.ip_address(s))
    except ValueError:
        return None


def public_ip(value: Any) -> str | None:
    ip = normalize_ip(value)
    return ip if ip is not None and is_public_ip(ip) else None


def registrable(name: str | None) -> str | None:
    if not name:
        return None
    try:
        return registrable_domain(name)
    except Exception:  # noqa: BLE001 - a PSL problem only loses the grouping
        return None


def in_apex(name: str | None, apex: str | None) -> bool:
    """Label-wise: ``name`` is ``apex`` or a subdomain of it (never a string suffix)."""
    if not name or not apex:
        return False
    return name == apex or name.endswith("." + apex)


def apex_of(entity: Entity) -> str | None:
    """The registrable domain of a domain entity (the entity value when it is itself registrable)."""
    if entity.type is not T.DOMAIN:
        return None
    return registrable(entity.value) or entity.value


# --------------------------------------------------------------------------------------
# HTTP
# --------------------------------------------------------------------------------------

ABSENT = object()  # fetch_json: the status is a declared absence


def fetch_json(
    ctx: Any,
    method: str,
    url: str,
    *,
    source: str,
    needs_key_markers: Iterable[str] = (),
    absent: Iterable[int] = (),
    headers: Mapping[str, str] | None = None,
    params: Mapping[str, Any] | None = None,
    json_body: Any = None,
    ttl: float | None = None,
    cache_if: Any = None,
    provider_label: str = "provider",
) -> Any:
    """Send one request and return the parsed JSON, or :data:`ABSENT` for a declared absence.

    Raises AuthRequired for a classified answer whose marker id is in ``needs_key_markers`` (the engine
    maps it to NEEDS_KEY), the core exception of any other classification or non-2xx status
    (Blocked, RateLimited, QuotaExceeded, AuthRequired, HttpError) and HttpError for a body that is not
    JSON. Never returns an absence for 401/403/429/5xx.
    """
    kw: dict[str, Any] = {"source": source, "headers": {"Accept": "application/json", **dict(headers or {})}}
    if params:
        kw["params"] = dict(params)
    if json_body is not None:
        kw["json_body"] = json_body
    if ttl is not None:
        kw["ttl"] = ttl
    if cache_if is not None:
        kw["cache_if"] = cache_if
    resp = ctx.http.request(method, url, **kw)
    found = getattr(resp, "classification", None)
    if found is not None and getattr(found, "marker_id", "") in set(needs_key_markers):
        raise AuthRequired(found.reason, resp.status, resp.url, b"")
    if found is None and int(resp.status) in set(absent) and int(resp.status) not in (401, 403, 407, 429, 430, 451) and int(resp.status) < 500:
        return ABSENT
    ctx.http.check(resp)  # raises for a classification or any non-2xx status
    try:
        return json.loads(resp.text)
    except (ValueError, RecursionError):
        raise HttpError(f"{provider_label}: answer is not JSON (truncated or malformed): could not verify", resp.status, resp.url, b"") from None


def json_cache_veto(ok: Any) -> Any:
    """A ``cache_if`` veto: cache only bodies that parse as JSON and satisfy ``ok(data)``."""

    def veto(resp: Any) -> bool:
        try:
            return bool(ok(json.loads(resp.text)))
        except Exception:  # noqa: BLE001 - fail closed: an unreadable body is never cached
            return False

    return veto


def explicitly_selected(module_name: str, ctx: Any) -> bool:
    """True with ``-M <module>`` in a scan, or for a single run outside a scan (``v3lum run``)."""
    options = getattr(ctx, "options", None)
    if module_name in set(getattr(options, "include", ()) or ()):
        return True
    runtime = getattr(ctx, "runtime", None)
    return not bool(getattr(runtime, "in_scan", False))


# --------------------------------------------------------------------------------------
# certificates and vulnerabilities
# --------------------------------------------------------------------------------------


def cert_sharing(names: Iterable[Any], common_name: Any = None) -> dict[str, Any]:
    """P001 cond 8: {shared, reason, san_count, registrable_domains} for a certificate's DNS names."""
    unique = sorted({n for n in (normalize_domain(x) for x in names) if n})
    regs = sorted({r for r in (registrable(n) for n in unique) if r})
    reason = ""
    if len(unique) > SHARED_SAN_THRESHOLD and len(regs) > SHARED_DOMAIN_THRESHOLD:
        reason = f"{len(unique)} SANs over {len(regs)} registrable domains (P001 shared-certificate rule)"
    else:
        probe = list(unique)
        cn = text(common_name, 255).lower().removeprefix("*.")
        if cn:
            probe.append(cn)
        for cand in probe:
            if any(p.search(cand) for p in _CDN_CERT_PATTERNS):
                reason = f"CDN/hosting shared-certificate pattern ({cand})"
                break
    return {"shared": bool(reason), "reason": reason, "san_count": len(unique), "registrable_domains": regs[:25]}


def cn_from_dn(dn: Any) -> str:
    """The CN of an LDAP-style distinguished name ('C=US, O=Example CA, CN=Example Issuing CA')."""
    s = text(dn, 500)
    m = re.search(r"(?:^|[,/]\s*)CN=([^,/]+)", s)
    return m.group(1).strip() if m else ""


def org_from_dn(dn: Any) -> str:
    s = text(dn, 500)
    m = re.search(r"(?:^|[,/]\s*)O=([^,/]+)", s)
    return m.group(1).strip() if m else ""


def vuln_severity(cvss: float | None, label: str | None = None) -> str:
    """P291 cap for version-inferred vulnerabilities: HIGH at most, never CRITICAL from one provider."""
    if cvss is None and label:
        lab = label.strip().lower()
        if lab in ("critical", "high"):
            return "high"
        if lab in ("medium", "moderate"):
            return "medium"
        if lab == "low":
            return "low"
        return "medium"
    if cvss is None:
        return "medium"
    if cvss >= 7.0:
        return "high"
    if cvss >= 4.0:
        return "medium"
    return "low" if cvss > 0 else "info"


def worst(severities: Iterable[str]) -> str:
    ranked = [s for s in severities if s in SEVERITY_ORDER]
    return max(ranked, key=SEVERITY_ORDER.index) if ranked else "info"


def cve_id(value: Any) -> str | None:
    s = text(value, 24).upper()
    return s if CVE_RE.match(s) else None


__all__ = [
    "ABSENT",
    "EndpointRefused",
    "VERSION_INFERRED_CRITERION",
    "apex_of",
    "as_dict",
    "as_list",
    "cert_sharing",
    "cn_from_dn",
    "cve_id",
    "explicitly_selected",
    "fetch_json",
    "flag",
    "in_apex",
    "integer",
    "json_cache_veto",
    "normalize_domain",
    "normalize_ip",
    "number",
    "org_from_dn",
    "port",
    "public_ip",
    "registrable",
    "str_list",
    "text",
    "vuln_severity",
    "worst",
]
