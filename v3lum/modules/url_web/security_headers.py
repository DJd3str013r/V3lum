"""HTTP security headers and cookie-flag audit (P063, batch p9-G03-1): offline analysis of the cached
homepage response, OWASP Secure Headers Project lists.

Final conditions (P063) and where they live:

1. No request of its own: ``disclosure='none'`` and ``opsec=PASSIVE``. The module reads the cached
   homepage response of the shared homepage fetch (``light_fetch.cached_homepage``: the page
   web_fingerprint P072, favicon_fetch and js_endpoints_live fetch) and ends SKIPPED 'not_applicable'
   when there is none. The frozen core gives offline modules no cache-only reader yet, so today the
   module is SKIPPED until the core adds ``ctx.cached_response`` (manifest core request); the audit is
   also a library (:func:`audit_response`, :func:`apply_audit`) for modules that hold the response.
2. Multi-valued headers: :func:`audit_response` takes the header list with duplicates (the Set-Cookie
   list); comma-joined legacy Set-Cookie values are split without breaking ``Expires=`` dates
   (``split_joined_set_cookie``). Keeping urllib3's getlist() in Response and the HTTP cache is a core
   change (manifest core request).
3. Mozilla Observatory-like scoring (start 100, subtract per missing/weak header, bonuses only from a
   base of 90): CSP (unsafe-inline/unsafe-eval/wildcards), HSTS only over HTTPS, X-Frame-Options (or CSP
   frame-ancestors), X-Content-Type-Options, Referrer-Policy, cookies; CSP-Report-Only counts as
   monitoring only; session-like cookie names (sess|sid|auth|token|jwt|remember) without
   Secure/HttpOnly/SameSite.
4. OWASP Secure Headers Project ``ci/headers_add.json`` and ``ci/headers_remove.json`` bundled from the
   GitHub repository (the owasp.org URL 404s) in ``v3lum/data/security_headers/owasp_secure_headers.json``,
   Apache-2.0 (notice fragment ``owasp_secure_headers``).
5. Non-2xx/3xx answers and challenge, proxy or WAF pages are inconclusive (BLOCKED / ERROR 'could not
   verify', never a grade).
6. ONE aggregated finding per site (grade + missing/weak list); never per-header findings.
7. Severity LOW only for org-profile own assets and authorized in-scope targets, INFO for every other
   site, no finding (attributes only) for sites tagged phishing/malicious; never above LOW here (the
   web hygiene rules CR18/CR19 own any MEDIUM). The attributes ``security_headers_missing``, ``hsts``
   and ``cookie_flags`` feed CR18/CR19.
8. Tests: several Set-Cookie headers, a third-party site missing 6 headers -> exactly one INFO
   finding, and the zero-request assertion (tests/modules/test_security_headers.py).

Scoring weights follow the Mozilla HTTP Observatory scoring documentation (MPL-2.0 project; only the
published weights are used, no code).
"""

from __future__ import annotations

import re
from collections.abc import Iterable, Mapping
from typing import Any
from urllib.parse import urlsplit

from v3lum.core.datasets import DataStore
from v3lum.core.entities import Entity
from v3lum.core.entities import EntityType as T
from v3lum.core.models import ModuleResult, Opsec
from v3lum.core.module import Module, register
from v3lum.modules.url_web.light_fetch import (
    cached_homepage,
    detect_block,
    header_first,
    header_values,
    headers_multi,
    split_joined_set_cookie,
)

__all__ = [
    "CORE_HEADERS",
    "OWASP_FILE",
    "SESSION_COOKIE_RE",
    "SecurityHeaders",
    "apply_audit",
    "audit_response",
    "grade_for",
    "load_owasp_reference",
    "parse_set_cookie",
    "security_headers_severity",
]

OWASP_FILE = "security_headers/owasp_secure_headers.json"
#: the headers whose absence is graded (Observatory core set + Permissions-Policy and COOP)
CORE_HEADERS = ("strict-transport-security", "content-security-policy", "x-frame-options", "x-content-type-options",
                "referrer-policy", "permissions-policy", "cross-origin-opener-policy")
GRADE_TABLE = ((100, "A+"), (90, "A"), (85, "A-"), (80, "B+"), (70, "B"), (65, "B-"), (60, "C+"), (50, "C"),
               (45, "C-"), (40, "D+"), (30, "D"), (25, "D-"), (0, "F"))
SESSION_COOKIE_RE = re.compile(r"sess|sid|auth|token|jwt|remember", re.I)  # P063 c3 (verbatim list)
HSTS_HALF_YEAR = 15_768_000
_PRIVATE_REFERRER = {"no-referrer", "same-origin", "strict-origin", "strict-origin-when-cross-origin"}
_UNSAFE_REFERRER = {"unsafe-url", "no-referrer-when-downgrade", "origin", "origin-when-cross-origin"}
_HOSTILE_TAGS = {"phishing", "malicious", "c2", "malware"}
_TECH_HEADERS = ("server", "x-powered-by", "x-aspnet-version", "x-aspnetmvc-version", "x-generator", "x-php-version")


# ======================================================================================
# OWASP reference data (c4)
# ======================================================================================

_REFERENCE: dict[str, Any] = {}


def load_owasp_reference(data: Any = None) -> dict[str, Any]:
    """{recommended: {header: value}, leaky: set of header names, last_update} from the bundled OWASP
    Secure Headers Project lists (``data`` overrides the bundled file)."""
    if data is None and _REFERENCE:
        return _REFERENCE
    raw = data
    if raw is None:
        try:
            raw = DataStore.bundled_json(OWASP_FILE)
        except (OSError, ValueError):
            raw = {}
    add = raw.get("headers_add") if isinstance(raw, Mapping) else None
    rem = raw.get("headers_remove") if isinstance(raw, Mapping) else None
    recommended = {str(h["name"]).lower(): h.get("value") for h in add or [] if isinstance(h, Mapping) and h.get("name")}
    leaky = {str(n).lower() for n in rem or [] if isinstance(n, str) and n}
    out = {"recommended": recommended, "leaky": leaky, "last_update": raw.get("last_update_utc") if isinstance(raw, Mapping) else None}
    if data is None and recommended:
        _REFERENCE.update(out)
    return out


# ======================================================================================
# parsing and scoring (c2, c3)
# ======================================================================================


def parse_set_cookie(value: str) -> dict[str, Any]:
    """One Set-Cookie header -> name and flags; the cookie value itself is never kept."""
    segments = [s.strip() for s in (value or "").split(";")]
    name = (segments[0] if segments else "").partition("=")[0].strip()
    flags: dict[str, Any] = {}
    for seg in segments[1:]:
        if not seg:
            continue
        key, eq, val = seg.partition("=")
        flags[key.strip().lower()] = val.strip() if eq else True
    samesite = flags.get("samesite")
    samesite_l = samesite.lower() if isinstance(samesite, str) else None
    secure = bool(flags.get("secure"))
    prefix = "__Host-" if name.startswith("__Host-") else "__Secure-" if name.startswith("__Secure-") else None
    prefix_ok = not (prefix == "__Secure-" and not secure) and not (
        prefix == "__Host-" and (not secure or "domain" in flags or flags.get("path") != "/"))
    return {
        "name": name[:100],
        "secure": secure,
        "httponly": bool(flags.get("httponly")),
        "samesite": samesite_l,
        "samesite_valid": samesite_l in (None, "strict", "lax", "none") and not (samesite_l == "none" and not secure),
        "persistent": "expires" in flags or "max-age" in flags,
        "prefix": prefix,
        "prefix_valid": prefix_ok,
        "session_like": bool(SESSION_COOKIE_RE.search(name)),
    }


def _set_cookies(headers: list[tuple[str, str]]) -> list[str]:
    out: list[str] = []
    for value in (v for k, v in headers if k == "set-cookie"):
        out.extend(split_joined_set_cookie(value) if "," in value else [value])
    return out


def _csp_directives(value: str) -> dict[str, list[str]]:
    out: dict[str, list[str]] = {}
    for part in (value or "").split(";"):
        tokens = part.strip().split()
        if tokens:
            out.setdefault(tokens[0].lower(), [t.lower() for t in tokens[1:]])
    return out


def _csp_issues(value: str) -> tuple[int, list[str], bool, int]:
    """(score modifier, issues, frame-ancestors present, bonus) of an enforced CSP."""
    d = _csp_directives(value)
    script = d.get("script-src", d.get("default-src"))
    obj = d.get("object-src", d.get("default-src"))
    issues: list[str] = []
    mod = 0
    if script is None:
        issues.append("no script-src/default-src")
        mod = min(mod, -20)
    else:
        nonce = any(t.startswith(("'nonce-", "'sha256-", "'sha384-", "'sha512-")) or t == "'strict-dynamic'" for t in script)
        if "'unsafe-inline'" in script and not nonce:
            issues.append("script-src allows 'unsafe-inline'")
            mod = min(mod, -20)
        if any(t in ("*", "http:", "https:", "data:") or t.startswith("http://") for t in script):
            issues.append("script-src allows wildcard or insecure sources")
            mod = min(mod, -20)
        if "'unsafe-eval'" in script:
            issues.append("script-src allows 'unsafe-eval'")
            mod = min(mod, -10)
    if obj is not None and any(t in ("*", "http:", "https:", "data:") for t in obj):
        issues.append("object-src wildcard")
        mod = min(mod, -20)
    bonus = 10 if not issues and d.get("default-src") == ["'none'"] else 0
    return mod, issues, "frame-ancestors" in d, bonus


def _hsts(value: str) -> dict[str, Any]:
    found = re.search(r"max-age\s*=\s*\"?(\d{1,12})", value or "", re.I)
    low = (value or "").lower()
    return {"present": True, "max_age": int(found.group(1)) if found else None, "include_subdomains": "includesubdomains" in low,
            "preload": "preload" in low}


def _product_tokens(value: str) -> list[dict[str, Any]]:
    out = [{"product": m.group(1), "version": m.group(2)} for m in re.finditer(r"([A-Za-z][A-Za-z0-9._\-]{0,40})/(\d[0-9A-Za-z._\-]{0,24})", value or "")]
    if not out and value and re.fullmatch(r"[A-Za-z][A-Za-z0-9._\- ]{0,40}", value.strip()):
        out.append({"product": value.strip(), "version": None})
    return out


def grade_for(score: int) -> str:
    for floor, grade in GRADE_TABLE:
        if score >= floor:
            return grade
    return "F"


def audit_response(response: Mapping[str, Any], reference: Mapping[str, Any] | None = None) -> dict[str, Any]:
    """Offline audit of one homepage response ``{url, status, headers (pairs, duplicates kept), body}``.

    Returns ``{'inconclusive': reason}`` for non-2xx/3xx, challenge, proxy or WAF answers (c5), else
    the grade, score, tests, missing core headers, weak values, CSP-Report-Only as monitoring only,
    HSTS (HTTPS only), leaky headers of the OWASP list with product/version tokens and per-cookie flags
    (names and flags only)."""
    ref = reference if reference is not None else load_owasp_reference()
    url = str(response.get("url") or "")
    headers = headers_multi(response.get("headers"))
    try:
        status = int(response.get("status"))  # type: ignore[arg-type]
    except (TypeError, ValueError):
        return {"inconclusive": "no HTTP status", "url": url}
    block = detect_block(status, headers, response.get("body"))
    if block:
        return {"inconclusive": block, "url": url, "status": status}
    if not 200 <= status < 400:
        return {"inconclusive": f"HTTP {status} (only 2xx/3xx answers are graded)", "url": url, "status": status}
    scheme = (urlsplit(url).scheme or "https").lower()
    names = {k for k, _ in headers}
    tests: list[dict[str, Any]] = []
    weak: list[dict[str, str]] = []
    missing: list[str] = []
    monitoring: list[str] = []

    def test(test_id: str, modifier: int) -> None:
        tests.append({"id": test_id, "modifier": modifier})

    csp = header_first(headers, "content-security-policy")
    frame_ancestors = False
    csp_bonus = 0
    if csp is None:
        if "content-security-policy-report-only" in names:
            monitoring.append("content-security-policy-report-only")
            test("csp-not-implemented-but-reporting-enabled", -25)
        else:
            test("csp-not-implemented", -25)
        missing.append("content-security-policy")
    else:
        mod, issues, frame_ancestors, csp_bonus = _csp_issues(csp)
        test("csp-implemented-with-issues" if issues else "csp-implemented", mod)
        weak.extend({"header": "content-security-policy", "issue": i} for i in issues)
    hsts: dict[str, Any] | None = None
    hsts_ok = False
    if scheme == "https":
        value = header_first(headers, "strict-transport-security")
        if value is None:
            hsts = {"present": False, "max_age": None, "include_subdomains": False, "preload": False}
            test("hsts-not-implemented", -20)
            missing.append("strict-transport-security")
        else:
            hsts = _hsts(value)
            if hsts["max_age"] is None:
                test("hsts-header-invalid", -20)
                weak.append({"header": "strict-transport-security", "issue": "no max-age"})
            elif hsts["max_age"] < HSTS_HALF_YEAR:
                test("hsts-implemented-max-age-less-than-six-months", -10)
                weak.append({"header": "strict-transport-security", "issue": f"max-age {hsts['max_age']} < 6 months"})
                hsts_ok = True
            else:
                test("hsts-implemented-max-age-at-least-six-months", 0)
                hsts_ok = True
            if hsts["max_age"] is not None and not hsts["include_subdomains"]:
                weak.append({"header": "strict-transport-security", "issue": "no includeSubDomains"})
    else:
        test("hsts-not-applicable-http", 0)
    xfo = header_first(headers, "x-frame-options")
    if xfo is None:
        if frame_ancestors:
            test("x-frame-options-implemented-via-csp", 5)
        else:
            test("x-frame-options-not-implemented", -20)
            missing.append("x-frame-options")
    else:
        v = xfo.strip().lower()
        if v in ("deny", "sameorigin"):
            test("x-frame-options-sameorigin-or-deny", 0)
        elif v.startswith("allow-from"):
            test("x-frame-options-allow-from-origin", 0)
            weak.append({"header": "x-frame-options", "issue": "ALLOW-FROM is obsolete"})
        else:
            test("x-frame-options-header-invalid", -20)
            weak.append({"header": "x-frame-options", "issue": f"invalid value {xfo[:40]!r}"})
    xcto = header_first(headers, "x-content-type-options")
    if xcto is None:
        test("x-content-type-options-not-implemented", -5)
        missing.append("x-content-type-options")
    elif xcto.strip().lower() != "nosniff":
        test("x-content-type-options-header-invalid", -5)
        weak.append({"header": "x-content-type-options", "issue": f"invalid value {xcto[:40]!r}"})
    else:
        test("x-content-type-options-nosniff", 0)
    policies = header_values(headers, "referrer-policy")
    if not policies:
        test("referrer-policy-not-implemented", 0)
        missing.append("referrer-policy")
    else:
        tokens = [t.strip().lower() for v in policies for t in v.split(",") if t.strip()]
        known = [t for t in tokens if t in _PRIVATE_REFERRER | _UNSAFE_REFERRER]
        if not known:
            test("referrer-policy-header-invalid", -5)
            weak.append({"header": "referrer-policy", "issue": "invalid value"})
        elif known[-1] in _UNSAFE_REFERRER:
            test("referrer-policy-unsafe", -5)
            weak.append({"header": "referrer-policy", "issue": f"unsafe value {known[-1]}"})
        else:
            test("referrer-policy-private", 5)
    for name in ("permissions-policy", "cross-origin-opener-policy"):
        if name not in names:
            missing.append(name)
    cookies = [parse_set_cookie(v) for v in _set_cookies(headers)]
    cookie_issues: list[dict[str, str]] = []
    cookie_mod = 0
    if not cookies:
        test("cookies-not-found", 0)
    else:
        insecure = scheme != "https"
        for c in cookies:
            if c["session_like"] and (not c["secure"] or insecure):
                cookie_mod = min(cookie_mod, -10 if (hsts_ok and not insecure) else -40)
                cookie_issues.append({"name": c["name"], "issue": "session cookie without Secure"})
            elif not c["secure"] or insecure:
                cookie_mod = min(cookie_mod, -5 if (hsts_ok and not insecure) else -20)
                cookie_issues.append({"name": c["name"], "issue": "cookie without Secure"})
            if c["session_like"] and not c["httponly"]:
                cookie_mod = min(cookie_mod, -30)
                cookie_issues.append({"name": c["name"], "issue": "session cookie without HttpOnly"})
            if c["session_like"] and c["samesite"] is None:
                cookie_issues.append({"name": c["name"], "issue": "session cookie without SameSite"})
            if not c["samesite_valid"]:
                cookie_mod = min(cookie_mod, -20)
                cookie_issues.append({"name": c["name"], "issue": "invalid SameSite (None without Secure)"})
            if not c["prefix_valid"]:
                cookie_issues.append({"name": c["name"], "issue": f"{c['prefix']} prefix rules broken"})
        if cookie_mod < 0:
            test("cookies-with-issues", cookie_mod)
        elif all(c["samesite"] for c in cookies):
            test("cookies-secure-with-httponly-sessions-and-samesite", 5)
        else:
            test("cookies-secure-with-httponly-sessions", 0)
    base = 100 + sum(t["modifier"] for t in tests if t["modifier"] < 0)
    bonus = sum(t["modifier"] for t in tests if t["modifier"] > 0) + csp_bonus
    score = max(0, base + (bonus if base >= 90 else 0))
    leaky = ref.get("leaky") or set()
    info_leak = {k: v[:200] for k, v in headers if k in leaky}
    tech = [dict(t, header=k) for k in _TECH_HEADERS for v in header_values(headers, k) for t in _product_tokens(v)]
    recommended = ref.get("recommended") or {}
    return {
        "inconclusive": None, "url": url, "status": status, "scheme": scheme,
        "score": score, "grade": grade_for(score), "tests": tests,
        "missing": [n for n in CORE_HEADERS if n in missing], "weak": weak, "monitoring_only": monitoring,
        "present": {n: (header_first(headers, n) or "")[:200] for n in CORE_HEADERS if n in names},
        "hsts": hsts, "info_leak": info_leak, "tech": tech[:20],
        "cookies": cookies, "cookie_issues": cookie_issues,
        "optional_missing": sorted(n for n in recommended if n not in names and n not in CORE_HEADERS),
    }


# ======================================================================================
# severity and output (c6, c7)
# ======================================================================================


def security_headers_severity(*, own_asset: bool = False, authorized_in_scope: bool = False, tags: Iterable[str] = ()) -> str | None:
    """c7: 'low' for org-profile own assets and authorized in-scope targets, 'info' otherwise, None
    (attributes only) for sites tagged phishing/malicious. Never above LOW here."""
    if {str(t).lower() for t in tags} & _HOSTILE_TAGS:
        return None
    return "low" if (own_asset or authorized_in_scope) else "info"


def apply_audit(res: ModuleResult, audit: Mapping[str, Any], severity: str | None, *, source_label: str = "cached homepage") -> ModuleResult:
    """Attributes (``security_headers``, ``security_headers_missing``, ``hsts``, ``cookie_flags``,
    ``info_leak_headers``, ``server``) and at most ONE aggregated finding (c6)."""
    if audit.get("inconclusive"):
        res.attr("security_headers", {"inconclusive": audit["inconclusive"], "status": audit.get("status"), "url": audit.get("url"),
                                      "source": source_label})
        reason = str(audit["inconclusive"])
        if reason.startswith(("challenge", "proxy", "login_wall")):
            return res.mark("blocked", f"inconclusive: the {source_label} is a block page ({reason})",
                            reason_code="login_wall" if reason.startswith("login_wall") else "challenge")
        return res.mark("error", f"inconclusive: {reason}", reason_code="error")
    summary = {k: audit.get(k) for k in ("grade", "score", "missing", "weak", "monitoring_only", "optional_missing", "status", "url")}
    summary["cookie_issues"] = audit.get("cookie_issues") or []
    summary["source"] = source_label
    res.attr("security_headers", summary)
    res.attr("security_headers_missing", list(audit.get("missing") or []))
    if audit.get("hsts"):
        res.attr("hsts", {k: audit["hsts"].get(k) for k in ("present", "max_age", "include_subdomains", "preload")})
    cookies = [{k: c[k] for k in ("name", "secure", "httponly", "samesite", "session_like")} for c in audit.get("cookies") or []]
    res.attr("cookie_flags", cookies)
    res.attr("info_leak_headers", dict(audit.get("info_leak") or {}))
    server = (audit.get("info_leak") or {}).get("server")
    if server:
        res.attr("server", server)
    problems = list(audit.get("missing") or []) + [f"{w['header']}: {w['issue']}" for w in audit.get("weak") or []]
    problems += [f"cookie {c['name']}: {c['issue']}" for c in audit.get("cookie_issues") or []]
    if severity is None or not problems:
        return res
    host = urlsplit(str(audit.get("url") or "")).hostname or ""
    missing = audit.get("missing") or []
    res.finding(
        "Missing or weak HTTP security headers",
        severity,
        f"{host}: grade {audit['grade']} (score {audit['score']}/100); {len(missing)} missing header(s): "
        f"{', '.join(missing) or 'none'}; {len(audit.get('weak') or [])} weak value(s); {len(audit.get('cookie_issues') or [])} cookie issue(s)"
        + ("; CSP present only as Report-Only (monitoring)" if audit.get("monitoring_only") else "") + ".",
        confidence="probable",
        criterion="Observatory-style scoring of the cached homepage response (start 100, minus per missing/weak header; HSTS over "
                  "HTTPS only; CSP-Report-Only is monitoring only); LOW only for own assets and authorized in-scope targets (P063 c3, c7)",
        data={"grade": audit["grade"], "score": audit["score"], "missing": missing, "weak": audit.get("weak") or [],
              "cookie_issues": audit.get("cookie_issues") or [], "monitoring_only": audit.get("monitoring_only") or [], "url": audit.get("url")},
        tags=["misconfiguration"],
        references=("https://owasp.org/www-project-secure-headers/", "https://developer.mozilla.org/en-US/observatory/docs/tests_and_scoring"),
    )
    return res


def _in_scope(ctx: Any, host: str) -> bool:
    try:
        options = ctx.options
        scope = getattr(options, "scope", None)
        authorized = bool(getattr(options, "authorized", False) or str(getattr(options, "authorization_ref", "") or "").strip())
        return bool(authorized and scope is not None and not getattr(scope, "problems", ()) and scope.matches_host(host))
    except Exception:  # noqa: BLE001 - an unreadable scope never raises the severity
        return False


# ======================================================================================
# the module
# ======================================================================================


@register
class SecurityHeaders(Module):
    name = "security_headers"
    title = "HTTP security headers and cookie flags (offline audit of the cached homepage)"
    description = (
        "Grades the security headers and cookie flags of the cached homepage response (Mozilla Observatory-style score, OWASP "
        "Secure Headers lists) without any request; one aggregated finding per site."
    )
    category = "url_web"
    accepts = {T.URL, T.DOMAIN}
    produces: frozenset = frozenset()
    tags = {"offline", "free"}
    reference = "https://owasp.org/www-project-secure-headers/"
    terms = "open"  # own code + OWASP data (Apache-2.0)
    opsec = Opsec.PASSIVE
    disclosure = "none"  # offline analysis of a response another module fetched (P063 c1)
    hosts = ()
    access_model = "offline"
    default_enabled = True
    max_pivots = 0
    notice = "OWASP Secure Headers Project lists (Apache-2.0), bundled. No request: the homepage response comes from the shared fetch cache."

    def run(self, entity: Entity, ctx: Any) -> ModuleResult:
        res = self.result(entity)
        response = cached_homepage(ctx, entity)
        if response is None:
            return res.mark(
                "skipped",
                "no cached homepage response to audit (the shared homepage fetch of web_fingerprint/favicon_fetch/js_endpoints_live "
                "has not run, or the core offers no cache-only read yet): no request is ever made",
                reason_code="not_applicable",
            )
        audit = audit_response(response)
        host = urlsplit(str(response.get("url") or "")).hostname or ""
        try:
            own = bool(getattr(ctx.org.owns(entity), "own", False))
        except Exception:  # noqa: BLE001
            own = False
        severity = security_headers_severity(own_asset=own, authorized_in_scope=_in_scope(ctx, host))
        return apply_audit(res, audit, severity)
