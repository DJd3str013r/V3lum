"""AbuseIPDB API v2 check: community abuse-report confidence of an IP (and of a small range).

Batch p2-G07-1, proposal P157 (council final conditions):

* c1 - ``GET https://api.abuseipdb.com/api/v2/check?ipAddress={ip}&maxAgeInDays=90`` **without**
  ``verbose``, so report comments (free text that may hold personal data) are never fetched, cached or
  stored; ``check-block`` only for ranges <= /24 (IPv4 /24-/31, IPv6 /120-/127). Header ``Key`` with the
  registered key ``abuseipdb``. ``report``, ``bulk-report`` and ``clear-address`` are never built:
  :func:`request_allowed` is the allow-list every request passes (unit-tested).
* c2 - ``terms='key-terms'`` with ``free_plan_business_use: false``: AbuseIPDB's terms forbid
  commercial use of Free plans and several free accounts per organisation, so under the corporate
  profile the policy gate runs it only with a Basic or higher paid plan recorded as
  ``key_plans.abuseipdb = 'business'``; otherwise SKIPPED ``licence`` with the manual AbuseIPDB link.
* c3 - quota: 1,000 checks per day (the provider's P334 day window, key scope, 80% spent) and 100
  block checks per day (counted by the module from setting ``abuseipdb_plan``: Standard 100, Basic
  1,000, Premium 5,000). A 429 'Daily rate limit ... exceeded' is QUOTA (marker
  ``abuseipdb_daily_limit``), other 429s RATE_LIMITED; 402 (a range or age beyond the plan) is SKIPPED
  ``config``; ``errors[]`` inside a 200 is ERROR (could not verify).
* c4 - abuseConfidenceScore >= 75 with numDistinctUsers >= 3 -> malicious MEDIUM (HIGH only through
  the P171 consensus with an independent family; the finding's ``observed_last`` is lastReportedAt,
  so CR27's 30-day IP window applies); 25-74 (or >= 75 with fewer than 3 reporters) -> LOW suspicious;
  < 25 -> info attribute. isWhitelisted and usageType 'Content Delivery Network' / 'Search Engine
  Spider' dampen (one level lower; attribute ``allowlisted`` so CR27 caps the consensus); usageType
  'Mobile ISP' (CGNAT is common in Brazil) caps at LOW and never votes.
* c5 - findings show distinct reporters, last report date, usageType and ISP. Report categories
  exist only in ``verbose`` answers, which c1 forbids: they are not available (backlog). Provider data
  is not redistributed (attribute ``export_restriction``). Success fixtures are documented shapes
  until the team key exists.

The answer is untrusted data: anything that is not the documented JSON object is 'could not verify'
(ERROR), never an absence.
"""

from __future__ import annotations

import ipaddress
import json
import math
import re
from datetime import datetime, timezone
from typing import Any
from urllib.parse import parse_qs, urlencode, urlsplit

from v3lum.config import SettingSpec
from v3lum.core import noise
from v3lum.core.entities import Entity
from v3lum.core.entities import EntityType as T
from v3lum.core.models import ModuleResult, Opsec, Status
from v3lum.core.module import Module, register

SOURCE = "abuseipdb.check"
HOST = "api.abuseipdb.com"
BASE = "https://api.abuseipdb.com/api/v2"
WEB = "https://www.abuseipdb.com/check/{ip}"
KEY_NAME = "abuseipdb"
KEY_HEADER = "Key"
ATTRIBUTION = "AbuseIPDB"
MAX_AGE_DAYS = 90
PLAN_SETTING = "abuseipdb_plan"
#: daily limits and check-block caps per plan (docs.abuseipdb.com, 2026-11-26)
PLANS: dict[str, dict[str, int]] = {
    "standard": {"check": 1000, "check_block": 100, "block_max_age": 30, "block_min_prefix": 24},
    "webmaster": {"check": 3000, "check_block": 250, "block_max_age": 30, "block_min_prefix": 24},
    "supporter": {"check": 5000, "check_block": 500, "block_max_age": 30, "block_min_prefix": 24},
    "basic": {"check": 10000, "check_block": 1000, "block_max_age": 60, "block_min_prefix": 20},
    "premium": {"check": 50000, "check_block": 5000, "block_max_age": 365, "block_min_prefix": 16},
}
SAFETY_MARGIN = 0.8
DAMPEN_USAGE = ("content delivery network", "search engine spider")
CAP_LOW_USAGE = ("mobile isp",)
_PATHS = {"/api/v2/check": frozenset({"ipAddress", "maxAgeInDays"}), "/api/v2/check-block": frozenset({"network", "maxAgeInDays"})}
_SEVERITY = ("info", "low", "medium", "high", "critical")
_CTRL_RE = re.compile(r"[\x00-\x1f\x7f-\x9f​-‏‪-‮⁦-⁩]")


# --------------------------------------------------------------------------------------
# pure helpers (stdlib only; ported from the batch prep parsers)
# --------------------------------------------------------------------------------------


def clean_text(value: Any, limit: int = 160) -> str | None:
    if value is None or isinstance(value, (dict, list, tuple, set, bool)):
        return None
    text = " ".join(_CTRL_RE.sub(" ", str(value)).split())
    return text[:limit] or None


def as_int(value: Any) -> int | None:
    if value is None or isinstance(value, bool):
        return None
    if isinstance(value, int):
        return value
    if isinstance(value, float) and value.is_integer():
        return int(value)
    if isinstance(value, str) and re.fullmatch(r"\s*-?\d{1,12}\s*", value):
        return int(value)
    return None


def as_bool(value: Any) -> bool | None:
    if isinstance(value, bool):
        return value
    if isinstance(value, str) and value.strip().lower() in ("true", "false"):
        return value.strip().lower() == "true"
    return None


def parse_ts(value: Any) -> datetime | None:
    text = clean_text(value, 64)
    if not text:
        return None
    if text.endswith(("Z", "z")):
        text = text[:-1] + "+00:00"
    try:
        parsed = datetime.fromisoformat(text)
    except ValueError:
        return None
    return parsed if parsed.tzinfo else parsed.replace(tzinfo=timezone.utc)


def iso(value: datetime | None) -> str | None:
    return value.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ") if isinstance(value, datetime) else None


def normalize_domain(value: Any) -> str | None:
    text = clean_text(value, 260)
    if not text:
        return None
    text = text.strip().rstrip(".").lower()
    try:
        text = text.encode("idna").decode("ascii")
    except UnicodeError:
        return None
    if len(text) > 253 or "." not in text:
        return None
    if not all(re.fullmatch(r"(?!-)[a-z0-9-]{1,63}(?<!-)", label) for label in text.split(".")):
        return None
    return text


def load_json(content: bytes | str | None) -> tuple[Any, str]:
    if content is None:
        return None, "empty answer"
    text = content.decode("utf-8", errors="replace") if isinstance(content, (bytes, bytearray)) else str(content)
    text = text.lstrip("﻿").strip()
    if not text:
        return None, "empty answer"
    if text.startswith("<"):
        return None, "HTML page instead of JSON"
    try:
        return json.loads(text), ""
    except (ValueError, RecursionError) as exc:
        return None, f"malformed JSON ({str(exc)[:60]})"


def check_url(ip: str, max_age_days: int = MAX_AGE_DAYS) -> str:
    """GET /api/v2/check?ipAddress=..&maxAgeInDays=90 - never 'verbose' (c1)."""
    return f"{BASE}/check?" + urlencode({"ipAddress": ip, "maxAgeInDays": str(max(1, min(365, int(max_age_days))))})


def check_block_url(network: str, max_age_days: int) -> str:
    """GET /api/v2/check-block?network=..&maxAgeInDays=.. (ranges <= /24 only, c1)."""
    return f"{BASE}/check-block?" + urlencode({"network": network, "maxAgeInDays": str(max(1, min(365, int(max_age_days))))})


def request_allowed(method: str, url: str) -> bool:
    """Allow-list (c1): GET https://api.abuseipdb.com/api/v2/check or /check-block with only their
    documented read parameters; never 'verbose' and never a key in the URL. report, bulk-report,
    clear-address, reports and blacklist are refused."""
    try:
        parts = urlsplit(url)
        query = parse_qs(parts.query, keep_blank_values=True)
    except ValueError:
        return False
    if (method or "").upper() != "GET" or parts.scheme != "https" or parts.hostname != HOST:
        return False
    allowed = _PATHS.get(parts.path)
    if allowed is None:
        return False
    return set(query) <= allowed and all(len(v) == 1 for v in query.values())


def errors_of(obj: Any) -> list[str]:
    out: list[str] = []
    if isinstance(obj, dict) and isinstance(obj.get("errors"), list):
        for item in obj["errors"][:5]:
            detail = clean_text(item.get("detail"), 240) if isinstance(item, dict) else None
            if detail:
                out.append(detail)
    return out


def parse_check(obj: Any) -> dict[str, Any] | None:
    """check JSON -> normalised facts (c4/c5), or None. Report objects (free-text comments, reporter
    ids and countries) are never copied: ``reports_dropped`` flags a body that carried them."""
    data = obj.get("data") if isinstance(obj, dict) else None
    if not isinstance(data, dict) or "abuseConfidenceScore" not in data:
        return None
    hostnames = data.get("hostnames")
    country = clean_text(data.get("countryCode"), 8)
    return {
        "ip": clean_text(data.get("ipAddress"), 64),
        "is_public": as_bool(data.get("isPublic")),
        "is_whitelisted": as_bool(data.get("isWhitelisted")),
        "score": max(0, min(100, as_int(data.get("abuseConfidenceScore")) or 0)),
        "country_code": country.upper() if country and re.fullmatch(r"[A-Za-z]{2}", country) else None,
        "usage_type": clean_text(data.get("usageType"), 80),
        "isp": clean_text(data.get("isp"), 160),
        "domain": normalize_domain(data.get("domain")),
        "hostnames": [h for h in (normalize_domain(x) for x in (hostnames[:10] if isinstance(hostnames, list) else [])) if h],
        "is_tor": as_bool(data.get("isTor")),
        "total_reports": as_int(data.get("totalReports")),
        "distinct_users": as_int(data.get("numDistinctUsers")),
        "last_reported_at": iso(parse_ts(data.get("lastReportedAt"))),
        "reports_dropped": isinstance(data.get("reports"), list) and len(data["reports"]) > 0,
    }


def lower_severity(severity: str) -> str:
    return _SEVERITY[max(0, _SEVERITY.index(severity) - 1)] if severity in _SEVERITY else "info"


def verdict(p: dict[str, Any], now: datetime) -> dict[str, Any]:
    """Normalised check -> verdict (c4). ``high_eligible`` only marks a recent malicious band: the HIGH
    itself comes from the P171 consensus with an independent family, never from this module alone."""
    score = p.get("score") or 0
    users = p.get("distinct_users") or 0
    last = parse_ts(p.get("last_reported_at"))
    age_days = (now - last).total_seconds() / 86400 if last is not None else None
    if score >= 75 and users >= 3:
        band, severity = "malicious", "medium"
        high_eligible = age_days is not None and age_days <= 30
    elif score >= 25:
        band, severity, high_eligible = "suspicious", "low", False
    else:
        band, severity, high_eligible = "info", "info", False
    reasons: list[str] = []
    if p.get("is_whitelisted") is True:
        reasons.append("AbuseIPDB isWhitelisted")
    usage = (p.get("usage_type") or "").strip().lower()
    if usage in DAMPEN_USAGE:
        reasons.append(f"AbuseIPDB usageType {p.get('usage_type')}")
    if reasons:
        severity = lower_severity(severity)
        high_eligible = False
    capped = ""
    if usage in CAP_LOW_USAGE:
        high_eligible = False
        if _SEVERITY.index(severity) > _SEVERITY.index("low"):
            severity = "low"
        capped = "usageType Mobile ISP (CGNAT is common in Brazil): capped at low"
    return {"band": band, "severity": severity, "high_eligible": high_eligible, "dampen_reasons": reasons, "capped": capped}


def facts(p: dict[str, Any]) -> dict[str, Any]:
    """What every finding shows (c5)."""
    return {"abuse_confidence_score": p.get("score"), "distinct_reporters": p.get("distinct_users"),
            "total_reports": p.get("total_reports"), "last_reported_at": p.get("last_reported_at"),
            "usage_type": p.get("usage_type"), "isp": p.get("isp"), "domain": p.get("domain"),
            "country_code": p.get("country_code"), "is_tor": p.get("is_tor"), "is_whitelisted": p.get("is_whitelisted"),
            "max_age_days": MAX_AGE_DAYS}


def parse_check_block(obj: Any, limit: int = 50) -> dict[str, Any] | None:
    data = obj.get("data") if isinstance(obj, dict) else None
    if not isinstance(data, dict) or not ("networkAddress" in data or "reportedAddress" in data):
        return None
    reported: list[dict[str, Any]] = []
    rows = data.get("reportedAddress")
    for row in rows[:limit] if isinstance(rows, list) else []:
        if not isinstance(row, dict):
            continue
        try:
            ip = str(ipaddress.ip_address(str(row.get("ipAddress") or "").strip()))
        except ValueError:
            continue
        reported.append({"ip": ip, "reports": as_int(row.get("numReports")), "last_report": iso(parse_ts(row.get("mostRecentReport"))),
                         "score": as_int(row.get("abuseConfidenceScore"))})
    scores = [r["score"] for r in reported if r["score"] is not None]
    return {"network": clean_text(data.get("networkAddress"), 64), "netmask": clean_text(data.get("netmask"), 64),
            "hosts": as_int(data.get("numPossibleHosts")), "reported": reported, "max_score": max(scores) if scores else None}


def block_network(entity: Entity) -> tuple[str | None, str | None, str]:
    """('ip', value) for a single host, ('block', cidr) for a range <= /24, or (None, None, why)."""
    try:
        net = ipaddress.ip_network(entity.value, strict=False)
    except ValueError:
        return None, None, "not a valid CIDR"
    if net.num_addresses == 1:
        return "ip", str(net.network_address), ""
    low, high = (24, 31) if net.version == 4 else (120, 127)
    if not low <= net.prefixlen <= high:
        return None, None, f"check-block only for ranges <= /24 (got /{net.prefixlen}; P157 c1)"
    return "block", str(net), ""


def public_ip(value: str) -> bool:
    return noise.is_public_ip(value)


# --------------------------------------------------------------------------------------
# the module
# --------------------------------------------------------------------------------------


@register
class AbuseIPDB(Module):
    name = "abuseipdb"
    title = "AbuseIPDB"
    description = (
        "Community abuse-report confidence of an IP (or a range up to /24) from the AbuseIPDB API v2 check "
        "endpoint: score, distinct reporters, last report, usage type and ISP (key required; never reports)."
    )
    category = "threat_intel_ioc"
    accepts = {T.IPV4, T.IPV6, T.CIDR}
    produces = frozenset()
    terms = "key-terms"
    opsec = Opsec.PASSIVE
    disclosure = "third_party"
    provider = "abuseipdb"
    sources = (SOURCE,)
    hosts = (HOST,)
    access_model = "free_auth_limited"
    requires_keys = (KEY_NAME,)
    error_markers = (
        {"id": "abuseipdb_daily_limit", "statuses": [429], "regex": r"(?i)daily rate limit of \d+ requests exceeded",
         "maps_to": "quota", "reason_code": "quota",
         "reason": "AbuseIPDB: daily limit of the key's plan reached (could not verify; deferred)"},
    )
    max_requests = 1
    expected_latency = 1.0
    timeout = 20.0
    min_interval = 1.0
    cache_ttl = 86400
    manual_link = "threat_intel_g07_p2:abuseipdb_check_ip"
    default_enabled = True
    tags = {"reputation"}
    reference = "https://docs.abuseipdb.com/"
    settings = {
        PLAN_SETTING: SettingSpec(
            "standard",
            "AbuseIPDB plan of the configured key: sets the check-block daily budget and maxAgeInDays cap (P157 c3)",
            choices=tuple(PLANS),
        ),
    }
    notice = (
        "AbuseIPDB needs a key and is read-only (check and check-block; never report, bulk-report or clear-address; "
        "never 'verbose', so report comments are never fetched). Its terms forbid commercial use of Free plans: under "
        "the corporate profile it runs only with a Basic or higher paid plan recorded as key_plans.abuseipdb=business "
        "(otherwise skipped: licence, with the manual AbuseIPDB link). AbuseIPDB data stays internal: exports outside "
        "the company carry the verdict, link and source name only."
    )

    def applies(self, entity: Entity, ctx: Any) -> bool:
        if entity.type in (T.IPV4, T.IPV6):
            return public_ip(entity.value)  # private/reserved addresses are never sent
        return True

    def _plan(self, ctx: Any) -> tuple[str, dict[str, int]]:
        name = str(ctx.setting(PLAN_SETTING, "standard") or "standard").strip().lower()
        return (name, PLANS[name]) if name in PLANS else ("standard", PLANS["standard"])

    def _get(self, res: ModuleResult, ctx: Any, url: str, key: str) -> tuple[Any, bool]:
        """One allow-listed GET -> (parsed JSON, True), or (None, False) with ``res`` marked (402 ->
        SKIPPED config, 422 / errors[] / unexpected bodies -> ERROR). Classified answers raise."""
        if not request_allowed("GET", url):  # c1: never anything but check / check-block
            res.mark(Status.ERROR, "refused a non-allow-listed AbuseIPDB request (module bug)", reason_code="error")
            return None, False
        resp = ctx.http.get(url, headers={KEY_HEADER: key, "Accept": "application/json"}, source=SOURCE)
        if resp.status == 402 and resp.classification is None:
            res.mark(Status.SKIPPED, "AbuseIPDB 402: network size or maxAgeInDays beyond the key's plan (setting abuseipdb_plan)", reason_code="config")
            return None, False
        if resp.status == 422 and resp.classification is None:
            obj, _ = load_json(resp.content)
            detail = (errors_of(obj) or ["422"])[0]
            res.mark(Status.ERROR, f"AbuseIPDB rejected a parameter ({detail}): could not verify", reason_code="error")
            return None, False
        ctx.http.check(resp)  # 401/403 -> NEEDS_KEY, 429 -> RATE_LIMITED (daily-limit marker -> QUOTA), challenges, 5xx
        obj, why = load_json(resp.content)
        if why:
            res.mark(Status.ERROR, f"unexpected AbuseIPDB answer ({why}): could not verify", reason_code="error")
            return None, False
        errs = errors_of(obj)
        if errs:
            res.mark(Status.ERROR, f"AbuseIPDB error inside an HTTP 200 answer ({errs[0]}): could not verify", reason_code="error")
            return None, False
        return obj, True

    def run(self, entity: Entity, ctx: Any) -> ModuleResult:
        res = self.result(entity)
        key = str(ctx.key(KEY_NAME) or "").strip()
        if not key:
            return res.mark(Status.NEEDS_KEY, "needs the AbuseIPDB key (v3lum keys set abuseipdb)", reason_code="needs_key")
        target = entity.value
        if entity.type is T.CIDR:
            kind, value, why = block_network(entity)
            if kind is None:
                return res.mark(Status.SKIPPED, why, reason_code="not_applicable")
            if not public_ip(str(value).split("/")[0]):
                return res.mark(Status.SKIPPED, "private or reserved range: never sent to AbuseIPDB", reason_code="not_applicable")
            if kind == "block":
                return self._block(res, ctx, key, str(value))
            target = str(value)
        web = WEB.format(ip=target)
        obj, ok = self._get(res, ctx, check_url(target), key)
        if not ok:
            res.link("AbuseIPDB check page (manual)", web)
            return res
        parsed = parse_check(obj)
        if parsed is None:
            return res.mark(Status.ERROR, "unexpected AbuseIPDB answer (no data.abuseConfidenceScore): could not verify", reason_code="error")
        return self._report(res, ctx, parsed, web)

    # ---- check (c4, c5) ------------------------------------------------------------------
    def _report(self, res: ModuleResult, ctx: Any, p: dict[str, Any], web: str) -> ModuleResult:
        v = verdict(p, ctx.now())
        f = facts(p)
        res.raw = {"status": 200, "check": {k: p[k] for k in p if k != "reports_dropped"}, "reports_dropped": p["reports_dropped"]}
        res.link("AbuseIPDB check page", web)
        res.attr("abuseipdb", {**f, "band": v["band"], "link": web})
        res.attr("reputation", {"abuseipdb": p["score"]})
        res.attr("data_attribution", ATTRIBUTION)
        res.attr("export_restriction", {"source": ATTRIBUTION, "redistributable": False,
                                        "external_exports": "verdict, link and source name only", "verdict": v["band"], "link": web})
        res.attr("isp", p["isp"])
        res.attr("country", p["country_code"])
        res.attr("hostnames", p["hostnames"])
        if p["is_tor"] is True:
            res.attr("is_tor_exit", True)
        if (p.get("usage_type") or "").strip().lower() == "content delivery network":
            res.attr("is_cdn", True)
        if v["dampen_reasons"]:
            res.attr("allowlisted", v["dampen_reasons"])  # dampens the CR27 consensus (SUP-allowlist), never deletes
        reported = (p["total_reports"] or 0) > 0
        if v["band"] == "info":
            if not reported:
                return res.mark(Status.EMPTY, f"no AbuseIPDB reports in the last {MAX_AGE_DAYS} days")
            return res  # < 25: an info attribute, never a finding (c4)
        description = (
            f"AbuseIPDB abuse confidence {p['score']}% from {p['distinct_users'] or 0} distinct reporters "
            f"({p['total_reports'] if p['total_reports'] is not None else '?'} reports in {MAX_AGE_DAYS} days, last "
            f"{(p['last_reported_at'] or 'never')[:10]}); usage type {p['usage_type'] or 'unknown'}; ISP {p['isp'] or 'unknown'}."
        )
        notes = list(v["dampen_reasons"])
        if v["capped"]:
            notes.append(v["capped"])
        if notes:
            description += " " + "; ".join(notes) + "."
        data = {**f, "band": v["band"], "high_eligible": v["high_eligible"], "dampen_reasons": v["dampen_reasons"],
                "upstream_families": ["abuseipdb"]}
        common = {"references": [web], "source": SOURCE, "observed_last": p["last_reported_at"], "data": data}
        if v["band"] == "malicious":
            votes = not v["capped"]  # Mobile ISP (CGNAT) never votes: the cap holds through the consensus
            res.finding(
                "Malicious IP (AbuseIPDB)", v["severity"],
                description + (" HIGH only with an independent corroborating source and a report in the last 30 days (P171)." if votes else ""),
                confidence="probable" if not notes else "possible",
                criterion=f"AbuseIPDB abuseConfidenceScore {p['score']} >= 75 from {p['distinct_users']} >= 3 distinct reporters "
                          f"(maxAgeInDays {MAX_AGE_DAYS})" + (f"; {'; '.join(notes)}" if notes else ""),
                tags=["malicious"] if votes else ["suspicious"], **common,
            )
        else:
            res.finding(
                "Suspicious IP (AbuseIPDB)", v["severity"], description, confidence="possible",
                criterion=f"AbuseIPDB abuseConfidenceScore {p['score']} (25-74, or >= 75 with fewer than 3 distinct reporters)"
                          + (f"; {'; '.join(notes)}" if notes else ""),
                tags=["suspicious"] if v["severity"] != "info" else ["info"], **common,
            )
        return res

    # ---- check-block (c1, c3) --------------------------------------------------------------
    def _block_used(self, ctx: Any) -> int:
        record = ctx.state.get("check_block") or {}
        today = ctx.now().strftime("%Y-%m-%d")
        if not isinstance(record, dict) or record.get("day") != today:
            return 0
        return as_int(record.get("used")) or 0

    def _block(self, res: ModuleResult, ctx: Any, key: str, network: str) -> ModuleResult:
        plan_name, plan = self._plan(ctx)
        prefix = int(network.rsplit("/", 1)[1])
        if ":" not in network and prefix < plan["block_min_prefix"]:
            return res.mark(Status.SKIPPED, f"range larger than the {plan_name} plan allows", reason_code="config")
        budget = math.floor(plan["check_block"] * SAFETY_MARGIN)
        used = self._block_used(ctx)
        if used >= budget:
            return res.mark(Status.QUOTA, f"AbuseIPDB check-block budget used ({used}/{budget} today, {plan_name} plan): could not verify; deferred",
                            reason_code="quota")
        max_age = min(MAX_AGE_DAYS, plan["block_max_age"])
        ctx.state.set("check_block", {"day": ctx.now().strftime("%Y-%m-%d"), "used": used + 1})
        obj, ok = self._get(res, ctx, check_block_url(network, max_age), key)
        if not ok:
            return res
        parsed = parse_check_block(obj)
        if parsed is None:
            return res.mark(Status.ERROR, "unexpected AbuseIPDB check-block answer: could not verify", reason_code="error")
        res.raw = {"status": 200, "check_block": parsed}
        res.attr("abuseipdb_block", {**parsed, "max_age_days": max_age})
        res.attr("data_attribution", ATTRIBUTION)
        res.attr("export_restriction", {"source": ATTRIBUTION, "redistributable": False,
                                        "external_exports": "verdict, link and source name only", "verdict": "range summary", "link": ""})
        if not parsed["reported"]:
            return res.mark(Status.EMPTY, f"no AbuseIPDB reports for addresses of {network} in the last {max_age} days")
        top = parsed["max_score"] or 0
        res.finding(
            "Reported addresses in the range (AbuseIPDB)", "low" if top >= 75 else "info",
            f"{len(parsed['reported'])} address(es) of {network} reported to AbuseIPDB in the last {max_age} days "
            f"(highest abuse confidence {top}%).",
            confidence="possible",
            criterion=f"AbuseIPDB check-block: highest abuseConfidenceScore {top} in the range (>= 75 is low; per-address verdicts need a check)",
            data={"reported": parsed["reported"][:20], "max_score": top, "max_age_days": max_age},
            tags=["suspicious"] if top >= 75 else ["info"], source=SOURCE,
        )
        return res
