"""Third-party posture graders (P076, batch p9-G03-2): HSTS preload status and SSL Labs cached grades
(``posture_third_party``, PASSIVE) and new SSL Labs assessments (``ssllabs_assess``, ACTIVE).

Final conditions (P076) and where they live:

1. Mozilla Observatory: every API endpoint can trigger a scan (POST /api/v2/scan; GET and POST
   /api/v2/analyze run one when no recent result exists, mdn-http-observatory ``scanOrReturnRecent``), so
   no documented read-only lookup exists: Observatory is not called at all and only the non-triggering
   landing page is given as a manual link (:data:`OBSERVATORY_LANDING`; the per-host analyze page is NOT
   linked because the MDN front end calls GET /api/v2/analyze on load). :func:`check_passive_request`
   refuses every Observatory URL; :func:`parse_observatory_scan` only reads the recorded fixtures.
2. SSL Labs passive lookups use getEndpointData per resolved IP only ('does not initiate new
   assessments, even when a cached report is not found'); analyze (even with fromCache=on) is never
   called passively. 'Hostname blacklisted' / errors[] bodies give ERROR; 429/529 RATE_LIMITED.
3. New assessments live in ``ssllabs_assess`` (ACTIVE: --mode active --authorized REF --scope FILE),
   only for org-profile own assets or scope-file targets, publish=off, no maxAge/fromCache, startNew
   sent once and never repeated (:func:`check_assess_request`).
4. SSL Labs terms are non-commercial: both SSL Labs sources are class ``noncommercial`` in the provider
   registry, so the corporate licence profile skips them (reason_code 'licence') unless a
   licence_allow entry exists; the module queries only ``ctx.allowed_sources`` (HSTS keeps running).
   SSL Labs API v4 (registered role mailbox) is not used yet (backlog).
5. HSTS preload: GET /api/v2/status only, never /preloadable (which makes hstspreload.org fetch the site).
6. ``posture_third_party`` runs only on org-profile own assets and in-scope targets (run_on 'own_assets'
   plus the module check), default_enabled False; grades are second opinions next to security_headers
   (P063) and tls_inspect (P275).
7. tests: recorded SSL Labs info/cached/blacklisted, Observatory and HSTS fixtures, and a test that no
   Observatory POST, analyze-on-miss or /preloadable request can be built in the passive module.
"""

from __future__ import annotations

import datetime as _dt
import ipaddress
import json
import re
import urllib.parse
from collections.abc import Mapping
from typing import Any

from v3lum.config import SettingSpec
from v3lum.core.entities import Entity
from v3lum.core.entities import EntityType as T
from v3lum.core.http import (
    AuthRequired,
    Blocked,
    DeadlineExceeded,
    HttpError,
    NetworkError,
    PolicyError,
    QuotaExceeded,
    RateLimited,
)
from v3lum.core.models import ModuleResult, Opsec, Status
from v3lum.core.module import HealthCheck, HealthResult, Module, register

SSLLABS_HOST = "api.ssllabs.com"
OBSERVATORY_HOST = "observatory-api.mdn.mozilla.net"
HSTS_HOST = "hstspreload.org"
OBSERVATORY_LANDING = "https://developer.mozilla.org/en-US/observatory/"
SRC_HSTS = "hstspreload.status"
SRC_ENDPOINT = "ssllabs.posture_third_party_endpoint"
SRC_ASSESS = "ssllabs.ssllabs_assess_analyze"
MAX_ENDPOINT_IPS = 4
MAX_POLLS = 60


# ============================================================================================ helpers
def _text(raw: Any) -> str:
    if isinstance(raw, (bytes, bytearray)):
        return bytes(raw).decode("utf-8", "replace").lstrip("﻿")
    return raw.lstrip("﻿") if isinstance(raw, str) else ""


def clean(value: Any, limit: int = 200) -> str:
    if not isinstance(value, str):
        return ""
    return re.sub(r"\s+", " ", re.sub(r"[\x00-\x1f\x7f]", " ", value)).strip()[:limit]


def load_json(raw: Any) -> tuple[Any, str | None]:
    if isinstance(raw, (dict, list)):
        return raw, None
    text = _text(raw).strip()
    if not text:
        return None, "empty"
    if text[0] == "<":
        return None, "html_instead_of_json"
    try:
        return json.loads(text), None
    except (ValueError, RecursionError):
        return None, "malformed"


def _result(status: str, reason: str | None = None, reason_code: str | None = None, **data: Any) -> dict[str, Any]:
    out: dict[str, Any] = {"status": status, "reason_code": reason_code, "reason": reason}
    out.update(data)
    return out


# ============================================================================================ requests (FC1/2/3/5/7)
def ssllabs_info_url() -> str:
    return f"https://{SSLLABS_HOST}/api/v3/info"


def ssllabs_endpoint_url(host: str, ip: str) -> str:
    """getEndpointData URL (FC2): never starts an assessment. ValueError for a non-IP or empty host."""
    if not host or not isinstance(host, str):
        raise ValueError("host required")
    ipaddress.ip_address(str(ip))
    q = urllib.parse.urlencode({"host": host.strip().lower().rstrip("."), "s": str(ip)})
    return f"https://{SSLLABS_HOST}/api/v3/getEndpointData?{q}"


def hsts_status_url(domain: str) -> str:
    """hstspreload.org /api/v2/status only (FC5)."""
    return f"https://{HSTS_HOST}/api/v2/status?" + urllib.parse.urlencode({"domain": str(domain).lower().rstrip(".")})


def check_passive_request(method: str, url: str) -> str | None:
    """The FC1/FC2/FC5/FC7 guard of the PASSIVE module: the reason a request must never be built, or
    None. Observatory: every endpoint refused (any of them can scan). SSL Labs: GET info /
    getEndpointData / getStatusCodes only (analyze starts an assessment on a cache miss even with
    fromCache=on; startNew, publish=on and register refused). hstspreload.org: GET /api/v2/status only."""
    if str(method or "").upper() != "GET":
        return f"method {method} refused (the passive module is GET-only)"
    try:
        u = urllib.parse.urlsplit(str(url))
    except ValueError:
        return "unparseable URL"
    host = (u.hostname or "").lower()
    path = u.path.rstrip("/")
    q = urllib.parse.parse_qs(u.query)
    if u.scheme != "https":
        return "https required"
    if host == OBSERVATORY_HOST:
        return "Mozilla Observatory API refused: every endpoint can trigger a scan (P076 cond 1); manual link only"
    if host == SSLLABS_HOST:
        leaf = path.rsplit("/", 1)[-1]
        if not re.fullmatch(r"/api/v[34]/\w+", path):
            return "unknown SSL Labs path"
        if leaf not in ("info", "getEndpointData", "getStatusCodes"):
            return f"SSL Labs {leaf} refused in passive mode (may start an assessment)"
        if "startNew" in q or q.get("publish", ["off"])[0].lower() == "on" or "fromCache" in q:
            return "startNew/publish/fromCache refused in passive mode"
        return None
    if host == HSTS_HOST:
        if path != "/api/v2/status":
            return f"hstspreload.org {path or '/'} refused (only /api/v2/status; /preloadable fetches the site)"
        return None
    return f"undeclared host {host}"


def ssllabs_assess_requests(host: str) -> dict[str, str]:
    """ACTIVE (FC3): the first call starts ONE assessment (startNew=on, publish=off, all=done, no
    maxAge/fromCache); every later poll omits startNew."""
    h = str(host).strip().lower().rstrip(".")
    if not h:
        raise ValueError("host required")
    base = f"https://{SSLLABS_HOST}/api/v3/analyze?"
    return {"start": base + urllib.parse.urlencode({"host": h, "publish": "off", "startNew": "on", "all": "done"}),
            "poll": base + urllib.parse.urlencode({"host": h, "publish": "off", "all": "done"})}


def check_assess_request(url: str, first_call: bool) -> str | None:
    """Guard of the ACTIVE module's URLs (FC3); reason or None."""
    u = urllib.parse.urlsplit(str(url))
    q = urllib.parse.parse_qs(u.query)
    if (u.hostname or "").lower() != SSLLABS_HOST or not u.path.endswith("/analyze") or u.scheme != "https":
        return "not an SSL Labs analyze call"
    if q.get("publish", [""])[0].lower() != "off":
        return "publish must be off"
    if "maxAge" in q or "fromCache" in q:
        return "maxAge/fromCache not allowed in ssllabs_assess"
    if "startNew" in q and not first_call:
        return "startNew repeated (would loop assessments)"
    return None


# ============================================================================================ parsers
def ssllabs_error_marker(http_status: Any, raw: Any = None) -> tuple[str, str, str] | None:
    """(status, reason_code, reason) of an SSL Labs failure, error-in-200 included (FC2), or None."""
    try:
        code = int(http_status)
    except (TypeError, ValueError):
        code = 0
    if code == 429:
        return ("rate_limited", "rate_limited", "SSL Labs 429: too many requests/new assessments")
    if code == 529:
        return ("rate_limited", "rate_limited", "SSL Labs 529: service overloaded (back off 30 min)")
    if code == 503:
        return ("error", "error", "SSL Labs 503: service unavailable (maintenance; back off 15 min)")
    if code == 441:
        return ("needs_key", "needs_key", "SSL Labs v4 441: e-mail not registered")
    if code == 500:
        return ("error", "error", "SSL Labs 500: internal error")
    obj, err = load_json(raw) if raw is not None else (None, None)
    if err == "html_instead_of_json":
        return ("error", "error", "SSL Labs answered HTML instead of JSON")
    if isinstance(obj, dict):
        errs = obj.get("errors")
        if isinstance(errs, list) and errs:
            msgs = "; ".join(
                (f"{e.get('field')}: " if isinstance(e, dict) and e.get("field") else "") + str(e.get("message") if isinstance(e, dict) else e)
                for e in errs[:5])
            return ("error", "error", f"SSL Labs error: {clean(msgs, 300)}")
        if str(obj.get("status", "")).upper() == "ERROR":
            return ("error", "error", f"SSL Labs: {clean(str(obj.get('statusMessage') or 'ERROR'), 200)}")
    if code >= 400:
        return ("error", "error", f"SSL Labs HTTP {code}")
    return None


def parse_ssllabs_info(raw: Any) -> dict[str, Any]:
    """/info -> engine/criteria versions, assessment limits, cool-off and the terms message (FC4)."""
    obj, err = load_json(raw)
    if not isinstance(obj, dict):
        return _result("error", f"info: {err or 'not an object'}", "error")

    def _int(k: str) -> int | None:
        v = obj.get(k)
        return v if isinstance(v, int) and not isinstance(v, bool) else None

    msgs = [clean(m, 300) for m in obj.get("messages", []) if isinstance(m, str)] if isinstance(obj.get("messages"), list) else []
    terms = next((re.search(r"https?://\S+", m).group(0) for m in msgs if re.search(r"https?://\S+", m)), None)
    return _result("ok", engine_version=obj.get("engineVersion"), criteria_version=obj.get("criteriaVersion"),
                   max_assessments=_int("maxAssessments"), current_assessments=_int("currentAssessments"),
                   cool_off_ms=_int("newAssessmentCoolOff"), messages=msgs, terms_url=terms.rstrip(".") if terms else None)


_GRADE_RX = re.compile(r"^(A\+|A-|[A-F]|T|M)$")
_BOOL_VULNS = ("vulnBeast", "heartbleed", "poodle", "freak", "logjam", "drownVulnerable")
#: coded ints of the v3 EndpointDetails (ssllabs-api-docs-v3.md): field -> (vulnerable codes, label)
_INT_VULNS = {"poodleTls": ({2}, "poodleTls"), "openSslCcs": ({3}, "openSslCcs"), "openSSLLuckyMinus20": ({2}, "openSSLLuckyMinus20"),
              "ticketbleed": ({2}, "ticketbleed"), "bleichenbacher": ({2, 3}, "robot"), "zombiePoodle": ({2, 3}, "zombiePoodle"),
              "goldenDoodle": ({4, 5}, "goldenDoodle"), "zeroLengthPaddingOracle": ({6, 7}, "zeroLengthPaddingOracle"),
              "sleepingPoodle": ({10, 11}, "sleepingPoodle")}
#: vulnerabilities SSL Labs itself grades F / exploitable remotely
SEVERE_VULNS = {"heartbleed", "openSslCcs", "robot", "ticketbleed", "drownVulnerable", "openSSLLuckyMinus20", "zombiePoodle", "goldenDoodle",
                "zeroLengthPaddingOracle", "sleepingPoodle", "poodleTls"}


def _endpoint_summary(e: Any) -> dict[str, Any] | None:
    if not isinstance(e, dict):
        return None
    grade = e.get("grade") if isinstance(e.get("grade"), str) and _GRADE_RX.match(e["grade"]) else None
    ip = e.get("ipAddress") if isinstance(e.get("ipAddress"), str) else None
    try:
        ip = str(ipaddress.ip_address(ip)) if ip else None
    except ValueError:
        ip = None
    out: dict[str, Any] = {
        "ip": ip, "server_name": clean(e.get("serverName"), 120) or None, "status_message": clean(e.get("statusMessage"), 120) or None,
        "grade": grade, "grade_trust_ignored": e.get("gradeTrustIgnored") if isinstance(e.get("gradeTrustIgnored"), str) and _GRADE_RX.match(e["gradeTrustIgnored"]) else None,
        "has_warnings": e.get("hasWarnings") if isinstance(e.get("hasWarnings"), bool) else None,
        "is_exceptional": e.get("isExceptional") if isinstance(e.get("isExceptional"), bool) else None,
    }
    d = e.get("details")
    if isinstance(d, dict):
        protos = []
        for p in d.get("protocols") if isinstance(d.get("protocols"), list) else []:
            if isinstance(p, dict) and p.get("name"):
                protos.append(clean(f"{p.get('name')} {p.get('version', '')}", 40))
        vulns = [k for k in _BOOL_VULNS if d.get(k) is True]
        for k, (bad, label) in _INT_VULNS.items():
            v = d.get(k)
            if isinstance(v, int) and not isinstance(v, bool) and v in bad:
                vulns.append(label)
        hsts = d.get("hstsPolicy") if isinstance(d.get("hstsPolicy"), dict) else {}
        chains = d.get("certChains") if isinstance(d.get("certChains"), list) else []
        started = d.get("hostStartTime")
        if isinstance(started, int) and not isinstance(started, bool) and started > 0:
            # when SSL Labs assessed the host: a cached grade can be months old, so findings carry the date
            out["assessed_at"] = _dt.datetime.fromtimestamp(started / 1000.0, tz=_dt.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
        out.update({
            "protocols": protos[:10], "vulnerabilities": sorted(set(vulns)), "hsts_status": clean(hsts.get("status"), 40) or None,
            "hsts_max_age": hsts.get("maxAge") if isinstance(hsts.get("maxAge"), int) else None,
            "forward_secrecy": d.get("forwardSecrecy") if isinstance(d.get("forwardSecrecy"), int) else None,
            "supports_rc4": d.get("supportsRc4") if isinstance(d.get("supportsRc4"), bool) else None,
            "cert_chain_issues": [c.get("issues") for c in chains if isinstance(c, dict) and isinstance(c.get("issues"), int) and c.get("issues")][:5],
        })
    return out


def parse_ssllabs_host(raw: Any, http_status: Any = 200) -> dict[str, Any]:
    """analyze answer (ACTIVE polling, or a recorded cached report) -> host summary. READY -> ok;
    IN_PROGRESS/DNS -> 'in_progress' (keep polling, never startNew again); ERROR/errors[] -> error."""
    marker = ssllabs_error_marker(http_status, raw)
    obj, err = load_json(raw)
    if marker:
        st, rc, reason = marker
        return _result(st, reason, rc, host=obj.get("host") if isinstance(obj, dict) else None,
                       assessment_status=obj.get("status") if isinstance(obj, dict) else None, endpoints=[])
    if not isinstance(obj, dict):
        return _result("error", f"analyze: {err or 'not an object'}", "error", endpoints=[])
    st = str(obj.get("status") or "").upper()
    eps = [x for x in (_endpoint_summary(e) for e in (obj.get("endpoints") if isinstance(obj.get("endpoints"), list) else [])[:16]) if x]
    base = dict(host=clean(obj.get("host"), 253) or None, assessment_status=st or None,
                start_time_ms=obj.get("startTime") if isinstance(obj.get("startTime"), int) else None,
                test_time_ms=obj.get("testTime") if isinstance(obj.get("testTime"), int) else None,
                engine_version=clean(obj.get("engineVersion"), 20) or None, criteria_version=clean(obj.get("criteriaVersion"), 20) or None,
                endpoints=eps)
    if st == "READY":
        return _result("ok" if eps else "empty", None if eps else "no endpoints", None, **base)
    if st in ("IN_PROGRESS", "DNS"):
        return _result("in_progress", f"assessment {st}", None, **base)
    return _result("error", f"unexpected status {clean(st, 40)!r}", "error", **base)


def parse_ssllabs_endpoint(raw: Any, http_status: Any = 200) -> dict[str, Any]:
    """getEndpointData (passive, one call per resolved IP) -> endpoint summary (FC2). The cache-miss
    body is not documented: an errors[] body is ERROR, an endpoint whose statusMessage is not 'Ready'
    (or that has no grade) is 'empty' (no cached grade)."""
    marker = ssllabs_error_marker(http_status, raw)
    if marker:
        st, rc, reason = marker
        return _result(st, reason, rc, endpoint=None)
    obj, err = load_json(raw)
    if not isinstance(obj, dict):
        return _result("error", f"getEndpointData: {err or 'not an object'}", "error", endpoint=None)
    e = _endpoint_summary(obj)
    if not e or not e.get("ip"):
        return _result("error", "endpoint object without ipAddress", "error", endpoint=None)
    if str(obj.get("statusMessage", "")).lower() != "ready" or not e.get("grade"):
        return _result("empty", f"no cached grade for {e['ip']} ({e.get('status_message')})", None, endpoint=e)
    return _result("ok", endpoint=e)


def parse_observatory_scan(raw: Any, http_status: Any = 200) -> dict[str, Any]:
    """Observatory v2 scan JSON -> grade summary. Never wired to a call (FC1): kept for the recorded
    fixtures and a future documented read-only endpoint."""
    obj, err = load_json(raw)
    if isinstance(obj, dict) and isinstance(obj.get("body"), dict) and "status" in obj:
        http_status, obj = obj.get("status"), obj["body"]
    if not isinstance(obj, dict):
        return _result("error", f"observatory: {err or 'not an object'}", "error")
    if obj.get("error"):
        return _result("error", f"{clean(str(obj.get('error')), 60)}: {clean(str(obj.get('message') or ''), 200)}", "error")
    try:
        if int(http_status) >= 400:
            return _result("error", f"observatory HTTP {http_status}", "error")
    except (TypeError, ValueError):
        pass
    grade = obj.get("grade") if isinstance(obj.get("grade"), str) else None
    return _result("ok" if grade else "empty", None if grade else "no grade", None, grade=grade, score=obj.get("score"),
                   tests_passed=obj.get("tests_passed"), tests_failed=obj.get("tests_failed"), details_url=obj.get("details_url"))


HSTS_STATUSES = ("unknown", "pending", "preloaded", "rejected", "removed", "pending-removal", "pending-automated-removal")


def parse_hsts_status(raw: Any, domain: str | None = None, http_status: Any = 200) -> dict[str, Any]:
    """hstspreload.org /api/v2/status -> {preload_status, preloaded, via_parent, preloaded_domain, bulk}
    (FC5; statuses of chromium/hstspreload.org database/domainstate.go)."""
    try:
        if int(http_status) >= 400:
            return _result("error", f"hstspreload HTTP {http_status}", "error")
    except (TypeError, ValueError):
        pass
    obj, err = load_json(raw)
    if not isinstance(obj, dict):
        return _result("error", f"hsts status: {err or 'not an object'}", "error")
    st = obj.get("status")
    if not isinstance(st, str) or st not in HSTS_STATUSES:
        return _result("error", f"unknown preload status {clean(str(st), 40)!r}", "error")
    name = obj.get("name") if isinstance(obj.get("name"), str) else domain
    pd = obj.get("preloadedDomain") if isinstance(obj.get("preloadedDomain"), str) else ""
    preloaded = st in ("preloaded", "pending-removal", "pending-automated-removal")
    via_parent = bool(preloaded and pd and name and pd.lower() != str(name).lower())
    return _result("ok", None, None, name=clean(name, 253) or None, preload_status=st, preloaded=preloaded, preloaded_domain=clean(pd, 253) or None,
                   via_parent=via_parent, bulk=obj.get("bulk") if isinstance(obj.get("bulk"), bool) else None)


# ============================================================================================ shared output
_STATUS = {"rate_limited": Status.RATE_LIMITED, "blocked": Status.BLOCKED, "needs_key": Status.NEEDS_KEY, "quota": Status.QUOTA,
           "error": Status.ERROR, "skipped": Status.SKIPPED}


def failure_of(exc: BaseException) -> tuple[str, str, str]:
    """Core exception -> (status, reason_code, reason): could not verify, never an absence (rule 5)."""
    text = clean(str(exc), 200)
    if isinstance(exc, RateLimited):
        return "rate_limited", "rate_limited", text
    if isinstance(exc, QuotaExceeded):
        return "quota", "quota", text
    if isinstance(exc, (Blocked, AuthRequired)):
        code = str(getattr(exc, "reason_code", "") or "challenge")
        return "blocked", code if code in ("challenge", "geo_block", "login_wall", "circuit", "hostile_host") else "challenge", text
    if isinstance(exc, PolicyError):
        return "skipped", str(getattr(exc, "reason_code", "") or "policy"), text
    if isinstance(exc, DeadlineExceeded):
        return "error", "timeout", text
    if isinstance(exc, NetworkError) and re.search(r"time[d ]?\s?out", text, re.I):
        return "error", "timeout", text
    return "error", "error", text


def endpoint_findings(res: ModuleResult, ep: Mapping[str, Any], *, source: str, cached: bool, observed: Any = None) -> None:
    """Findings for one SSL Labs endpoint: grade below A and remotely exploitable flags (a second
    opinion next to tls_inspect/security_headers)."""
    ip, grade = ep.get("ip"), ep.get("grade")
    how = "cached SSL Labs report" if cached else "SSL Labs assessment"
    if grade in ("F", "T", "M"):
        res.finding(f"SSL Labs grade {grade} on {ip}", "medium", f"{how} graded {ep.get('server_name') or ip} {grade} "
                    f"({'certificate not trusted' if grade == 'T' else 'certificate name mismatch' if grade == 'M' else 'serious TLS problems'}).",
                    confidence="probable", criterion="SSL Labs grade F, T (trust) or M (name mismatch): a third-party second opinion",
                    source=source, key=f"grade:{ip}", observed_last=observed, data=dict(ep))
    elif grade in ("B", "C", "D", "E"):
        res.finding(f"SSL Labs grade {grade} on {ip}", "low", f"{how} graded {ep.get('server_name') or ip} {grade}.",
                    confidence="probable", criterion="SSL Labs grade below A: a third-party second opinion", source=source, key=f"grade:{ip}",
                    observed_last=observed, data=dict(ep))
    severe = sorted(set(ep.get("vulnerabilities") or []) & SEVERE_VULNS)
    if severe:
        res.finding(f"TLS vulnerabilities flagged by SSL Labs on {ip}", "high", f"{how} flags {', '.join(severe)} on {ip}.",
                    confidence="probable", criterion="SSL Labs vulnerability test result (remotely exploitable TLS implementation flaw)",
                    source=source, key=f"vulns:{ip}", observed_last=observed, data={"ip": ip, "vulnerabilities": severe})


def _host_of(entity: Entity) -> str | None:
    if entity.type is T.DOMAIN:
        return entity.value.strip(".").lower()
    try:
        host = (urllib.parse.urlsplit(entity.value).hostname or "").lower().rstrip(".")
    except ValueError:
        return None
    try:
        ipaddress.ip_address(host)
        return None  # SSL Labs and the preload list work on names
    except ValueError:
        return host or None


def _own_or_in_scope(entity: Entity, host: str, ctx: Any) -> bool:
    try:
        if ctx.org.owns(entity).own:
            return True
    except Exception:  # noqa: BLE001 - no profile: not own
        pass
    scope = getattr(getattr(ctx, "options", None), "scope", None)
    try:
        return bool(scope is not None and scope.matches_host(host))
    except Exception:  # noqa: BLE001
        return False


def _selftest_passive(ctx: Any) -> HealthResult:
    """Offline self-test of the request guard and parsers (no network)."""
    try:
        assert check_passive_request("GET", hsts_status_url("example.com")) is None
        assert check_passive_request("GET", ssllabs_endpoint_url("example.com", "93.184.216.34")) is None
        assert check_passive_request("GET", f"https://{HSTS_HOST}/api/v2/preloadable?domain=example.com")
        assert check_passive_request("POST", f"https://{OBSERVATORY_HOST}/api/v2/scan?host=example.com")
        assert check_assess_request(ssllabs_assess_requests("example.com")["poll"], first_call=False) is None
        assert check_assess_request(ssllabs_assess_requests("example.com")["start"], first_call=False)
        return HealthResult("ok", "request guards and parsers ok")
    except AssertionError:
        return HealthResult("dead", "request guard self-test failed")


# ============================================================================================ PASSIVE module
@register
class PostureThirdParty(Module):
    name = "posture_third_party"
    title = "Third-party posture graders (HSTS preload, SSL Labs cached)"
    description = (
        "Second-opinion web posture for own assets and in-scope targets: HSTS preload list status (hstspreload.org /status) and "
        "SSL Labs grades from cached reports (getEndpointData per resolved IP, never a new assessment); Mozilla Observatory as a manual link."
    )
    category = "url_web"
    accepts = {T.DOMAIN, T.URL}
    produces = {T.IPV4, T.IPV6}
    run_on = "own_assets"
    tags = {"cached_only"}
    reference = "https://github.com/ssllabs/ssllabs-scan/blob/master/ssllabs-api-docs-v3.md"
    notice = (
        "Own assets and in-scope targets only. SSL Labs terms are non-commercial: skipped under the corporate licence profile until a "
        "licence_allow entry exists. No call here can start an SSL Labs assessment, make hstspreload.org fetch the site or trigger a "
        "Mozilla Observatory scan (Observatory is a manual link only)."
    )
    terms = "noncommercial"
    opsec = Opsec.PASSIVE
    disclosure = "third_party"
    provider = "ssllabs"
    sources = (SRC_ENDPOINT, SRC_HSTS)
    hosts = (SSLLABS_HOST, HSTS_HOST)
    access_model = "free_noauth_limited"
    max_requests = 1 + MAX_ENDPOINT_IPS
    expected_latency = 4.0
    timeout = 60.0
    min_interval = 2.0
    cache_ttl = 86400
    daily_quota = 200
    max_pivots = 10
    default_enabled = False

    def applies(self, entity: Entity, ctx: Any) -> bool:
        return _host_of(entity) is not None

    def run(self, entity: Entity, ctx: Any) -> ModuleResult:
        res = self.result(entity)
        host = _host_of(entity)
        if host is None:
            return res.mark("skipped", "needs a host name", reason_code="not_applicable")
        if not _own_or_in_scope(entity, host, ctx):
            return res.mark("skipped", "posture graders run only on org-profile own assets and in-scope targets (P076 cond 6)", reason_code="own_asset")
        allowed = ctx.allowed_sources
        outcomes: dict[str, str] = {}
        failures: list[tuple[str, str, str]] = []
        answered = False
        raw: dict[str, Any] = {"host": host}
        # ---- HSTS preload status (FC5)
        if SRC_HSTS in allowed:
            try:
                resp = self._get(ctx, hsts_status_url(host), SRC_HSTS)
                parsed = parse_hsts_status(resp.content, host, resp.status)
                raw["hsts"] = {k: parsed.get(k) for k in ("status", "reason", "preload_status", "preloaded", "preloaded_domain", "via_parent", "bulk")}
                if parsed["status"] == "ok":
                    answered = True
                    outcomes["hstspreload"] = "ok"
                    res.attr("hsts_preload", {"status": parsed["preload_status"], "preloaded": parsed["preloaded"], "via_parent": parsed["via_parent"],
                                              "preloaded_domain": parsed["preloaded_domain"], "bulk": parsed["bulk"], "checked_at": ctx.now().isoformat()})
                else:
                    failures.append(("error", "error", f"hstspreload: {parsed['reason']}"))
                    outcomes["hstspreload"] = "could_not_verify"
                    res.source_status(SRC_HSTS, Status.ERROR, reason_code="error", reason=f"hstspreload: {parsed['reason']}")
            except (RateLimited, QuotaExceeded, Blocked, AuthRequired, HttpError, NetworkError, PolicyError) as exc:
                st, code, reason = failure_of(exc)
                failures.append((st, code, f"hstspreload: {reason}"))
                outcomes["hstspreload"] = "could_not_verify"
                self._source_failure(res, SRC_HSTS, st, code, f"hstspreload: {reason}")
        else:
            outcomes["hstspreload"] = "skipped_licence"
        # ---- SSL Labs cached endpoint data (FC2, FC4)
        if SRC_ENDPOINT in allowed:
            ips, unverified = self._addresses(ctx, host)
            endpoints: list[dict[str, Any]] = []
            ssl_failure = None
            if not ips and unverified:
                outcomes["ssllabs"] = "could_not_verify"
                failures.append(("error", "error", "SSL Labs: the host's addresses could not be resolved (DNS could not verify)"))
            for ip in ips[:MAX_ENDPOINT_IPS]:
                try:
                    resp = self._get(ctx, ssllabs_endpoint_url(host, ip), SRC_ENDPOINT)
                except (RateLimited, QuotaExceeded, Blocked, AuthRequired, HttpError, NetworkError, PolicyError) as exc:
                    ssl_failure = failure_of(exc)
                    break
                parsed = parse_ssllabs_endpoint(resp.content, resp.status)
                if parsed["status"] in ("ok", "empty") and parsed.get("endpoint"):
                    answered = True
                    ep = dict(parsed["endpoint"], cached=parsed["status"] == "ok")
                    endpoints.append(ep)
                elif parsed["status"] != "ok":
                    ssl_failure = (parsed["status"], parsed["reason_code"] or "error", parsed["reason"] or "SSL Labs error")
                    if parsed["status"] in ("rate_limited", "needs_key"):
                        break
            res.attr("ssllabs_endpoints", endpoints)
            graded = [e for e in endpoints if e.get("cached")]
            if graded:
                outcomes["ssllabs"] = "ok"
            elif ssl_failure:
                outcomes["ssllabs"] = "could_not_verify"
            elif endpoints:
                outcomes["ssllabs"] = "no_cached_grade"
            elif ips:
                outcomes["ssllabs"] = "empty"
            elif not unverified:
                outcomes["ssllabs"] = "no_address"
            if ssl_failure:
                st, code, reason = ssl_failure
                failures.append((st, code, f"SSL Labs: {reason}"))
                self._source_failure(res, SRC_ENDPOINT, st, code, f"SSL Labs: {reason}")
            for ep in graded:
                endpoint_findings(res, ep, source=SRC_ENDPOINT, cached=True, observed=ep.get("assessed_at"))
            for ep in endpoints:
                if ep.get("ip"):
                    res.pivot(T.IPV6 if ":" in ep["ip"] else T.IPV4, ep["ip"], "resolves_to", confidence="confirmed", expand=False,
                              note="endpoint graded by SSL Labs")
            raw["ssllabs"] = endpoints
        else:
            outcomes["ssllabs"] = "skipped_licence"
        # ---- Mozilla Observatory: manual link only (FC1)
        res.link("Mozilla HTTP Observatory (manual; opening a per-host page may start a public scan)", OBSERVATORY_LANDING)
        outcomes["mozilla_observatory"] = "manual_link"
        res.attr("posture_sources", outcomes)
        res.raw = raw
        if answered:
            return res
        if failures:
            st, code, reason = failures[0]
            return res.mark(st, reason, reason_code=code)
        return res.mark("empty", "no grader answered with data for this host")

    def _get(self, ctx: Any, url: str, source: str) -> Any:
        """GET through ctx.http after the FC7 guard; classified answers raise the core exception."""
        problem = check_passive_request("GET", url)
        if problem:
            raise PolicyError("policy", problem)
        resp = ctx.http.get(url, source=source)
        if resp.classification is not None:
            ctx.http.check(resp)
        if resp.status >= 500 and resp.status not in (503, 529):
            raise HttpError(f"HTTP {resp.status}", resp.status, url)
        return resp

    @staticmethod
    def _addresses(ctx: Any, host: str) -> tuple[list[str], bool]:
        ips: list[str] = []
        unverified = False
        for rtype in ("A", "AAAA"):
            try:
                ans = ctx.dns.query(host, rtype)
            except Exception:  # noqa: BLE001
                unverified = True
                continue
            if getattr(ans, "could_not_verify", False):
                unverified = True
                continue
            for r in getattr(ans, "records", None) or []:
                try:
                    ips.append(str(ipaddress.ip_address(str(r))))
                except ValueError:
                    continue
        return list(dict.fromkeys(ips)), unverified

    @staticmethod
    def _source_failure(res: ModuleResult, source: str, st: str, code: str, reason: str) -> None:
        status = _STATUS.get(st, Status.ERROR)
        try:
            res.source_status(source, status, reason_code=code, reason=reason)
        except ValueError:
            res.source_status(source, Status.ERROR, reason_code="error", reason=reason)

    @classmethod
    def health_check(cls) -> HealthCheck:
        return HealthCheck(offline=True, selftest=_selftest_passive)


# ============================================================================================ ACTIVE module
@register
class SslLabsAssess(Module):
    name = "ssllabs_assess"
    title = "SSL Labs new assessment (ACTIVE, authorized scope only)"
    description = (
        "Starts ONE new Qualys SSL Labs assessment (publish=off, startNew once, never repeated) of an org-profile own asset or "
        "scope-file target and polls it until READY: Qualys performs dozens of TLS handshakes against the target."
    )
    category = "url_web"
    accepts = {T.DOMAIN, T.URL}
    produces = {T.IPV4, T.IPV6}
    tags = {"fresh_assessment", "slow"}
    reference = "https://github.com/ssllabs/ssllabs-scan/blob/master/ssllabs-api-docs-v3.md"
    notice = (
        "ACTIVE: --mode active --authorized REF --scope FILE; the scope must list the target AND the SSL Labs API host api.ssllabs.com "
        "(the core binds every ACTIVE request to the scope). Results are never published (publish=off). SSL Labs terms are non-commercial."
    )
    terms = "noncommercial"
    opsec = Opsec.ACTIVE
    disclosure = "target"
    provider = "ssllabs"
    sources = (SRC_ASSESS,)
    hosts = (SSLLABS_HOST,)
    max_requests = 1 + MAX_POLLS
    expected_latency = 120.0
    timeout = 660.0
    max_rate = 1.0
    max_pivots = 10
    default_enabled = False
    settings = {
        "ssllabs_assess_poll_interval": SettingSpec(10.0, "ssllabs_assess: seconds between status polls (SSL Labs docs: 5-10 s; never below 5)"),
        "ssllabs_assess_max_polls": SettingSpec(MAX_POLLS, "ssllabs_assess: status polls before giving up (could not verify)"),
    }

    @classmethod
    def health_check(cls) -> HealthCheck:
        return HealthCheck(offline=True, selftest=_selftest_passive)

    def applies(self, entity: Entity, ctx: Any) -> bool:
        return _host_of(entity) is not None

    def run(self, entity: Entity, ctx: Any) -> ModuleResult:
        res = self.result(entity)
        host = _host_of(entity)
        if host is None:
            return res.mark("skipped", "needs a host name", reason_code="not_applicable")
        scope = getattr(getattr(ctx, "options", None), "scope", None)
        if scope is None or not getattr(ctx, "authorized", False):
            return res.mark("skipped", "ssllabs_assess needs --mode active --authorized REF --scope FILE (A7)", reason_code="authorization")
        if not _own_or_in_scope(entity, host, ctx):
            return res.mark("skipped", f"{host} is neither an org-profile own asset nor listed in the scope (P076 cond 3)", reason_code="scope")
        try:
            api_listed = bool(scope.matches_host(SSLLABS_HOST))
        except Exception:  # noqa: BLE001
            api_listed = False
        if not api_listed:
            return res.mark("skipped", f"the scope must also list the SSL Labs API host {SSLLABS_HOST}: ACTIVE requests are bound to the scope "
                            "(core request: a third-party API path for ACTIVE modules)", reason_code="scope")
        urls = ssllabs_assess_requests(host)
        try:
            interval = max(5.0, float(ctx.setting("ssllabs_assess_poll_interval", 10.0)))
        except (TypeError, ValueError):
            interval = 10.0
        try:
            polls_cap = max(1, min(MAX_POLLS, int(ctx.setting("ssllabs_assess_max_polls", MAX_POLLS))))
        except (TypeError, ValueError):
            polls_cap = MAX_POLLS
        parsed = self._call(ctx, urls["start"], first=True)
        polls = 0
        while parsed["status"] == "in_progress" and polls < polls_cap:
            polls += 1
            parsed = self._call(ctx, urls["poll"], first=False, wait=interval)
        res.attr("ssllabs_assessment", {"host": parsed.get("host") or host, "status": parsed.get("assessment_status"), "start_time": parsed.get("start_time_ms"),
                                        "test_time": parsed.get("test_time_ms"), "engine_version": parsed.get("engine_version"),
                                        "criteria_version": parsed.get("criteria_version"), "polls": polls, "publish": "off"})
        res.raw = {"host": host, "polls": polls, "result": {k: v for k, v in parsed.items() if k != "endpoints"}, "endpoints": parsed.get("endpoints")}
        if parsed["status"] == "in_progress":
            return res.mark("error", f"SSL Labs assessment still {parsed.get('assessment_status')} after {polls} polls: could not verify", reason_code="timeout")
        if parsed["status"] not in ("ok", "empty"):
            st = parsed["status"] if parsed["status"] in _STATUS else "error"
            return res.mark(st, parsed.get("reason") or "SSL Labs error", reason_code=parsed.get("reason_code") or "error")
        endpoints = parsed.get("endpoints") or []
        res.attr("ssllabs_endpoints", [dict(e, cached=False) for e in endpoints])
        for ep in endpoints:
            endpoint_findings(res, ep, source=SRC_ASSESS, cached=False, observed=parsed.get("test_time_ms") or ep.get("assessed_at"))
            if ep.get("ip"):
                res.pivot(T.IPV6 if ":" in ep["ip"] else T.IPV4, ep["ip"], "resolves_to", confidence="confirmed", expand=False,
                          note="endpoint assessed by SSL Labs")
        return res

    def _call(self, ctx: Any, url: str, *, first: bool, wait: float | None = None) -> dict[str, Any]:
        problem = check_assess_request(url, first_call=first)
        if problem:
            raise PolicyError("policy", problem)
        kw: dict[str, Any] = {"source": SRC_ASSESS, "ttl": 0}  # polls must never be served from cache
        if first:
            # FC3 'startNew never repeated': the core retries 5xx/connection errors and a short 429, which would
            # re-send startNew=on (a gateway error can hide an assessment that did start): the start call is sent once
            kw["retries"] = 0
        if wait is not None:
            kw["min_interval"] = wait  # the core waits (kill switch and deadline honoured), never a sleep here
        resp = ctx.http.get(url, **kw)
        if resp.classification is not None:
            ctx.http.check(resp)
        return parse_ssllabs_host(resp.content, resp.status)


__all__ = [
    "OBSERVATORY_LANDING", "PostureThirdParty", "SslLabsAssess", "check_assess_request", "check_passive_request", "hsts_status_url",
    "parse_hsts_status", "parse_observatory_scan", "parse_ssllabs_endpoint", "parse_ssllabs_host", "parse_ssllabs_info",
    "ssllabs_assess_requests", "ssllabs_endpoint_url", "ssllabs_error_marker", "ssllabs_info_url",
]
