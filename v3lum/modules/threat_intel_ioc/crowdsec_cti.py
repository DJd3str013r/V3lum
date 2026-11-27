"""CrowdSec CTI smoke API: crowd-sourced reputation, behaviours, ATT&CK techniques and CVEs of an IP.

Batch p2-G07-1, proposal P152 (council final conditions):

* c1 - ``GET https://cti.api.crowdsec.net/v2/smoke/{ip}`` with the ``x-api-key`` header (key
  ``crowdsec``, env ``V3LUM_KEY_CROWDSEC`` / alias ``V3LUM_CROWDSEC_KEY``, registered in the provider
  fragment ``crowdsec``). No bulk, search or fire endpoint is ever built (:func:`request_allowed`).
* c2 - ``terms='key-terms'`` with ``free_plan_business_use: false``: under the corporate profile the
  policy gate runs it only with a company-account paid key recorded as ``key_plans.crowdsec =
  'business'``; otherwise SKIPPED ``licence`` and the manual CrowdSec CTI console link.
* c3 - the Community plan's 120 lookups per month: a key-scoped P334 month window in the provider
  fragment, plus the module setting ``crowdsec_monthly_quota`` (default 120, the recorded plan's limit
  otherwise; 80% is spent, like every P334 budget) counted in ``ctx.state`` and a per-case cap
  (``crowdsec_case_budget``, default 10). ``run_on='seeds'``: analyst-typed IPs only, never pivots,
  values extracted from pasted text or unconfirmed bulk seeds. Private/reserved addresses and CDN/
  cloud/resolver noise IPs are skipped before any lookup; answers are cached 72 h, so an IP answered
  in the last 72 h is served from the cache and spends nothing.
* c4 - 404 = EMPTY 'not in CrowdSec data' (never benign); 403 ``{"message":"Forbidden"}`` = NEEDS_KEY;
  429 = RATE_LIMITED (a 429 that says the plan limit is exceeded is QUOTA through the
  ``crowdsec_quota_429`` marker); the monthly budget exhausted = QUOTA.
* c5 - ``classifications.false_positives`` and benign/known/safe reputations (SEO crawler, CDN,
  search-engine bots) are info context that dampens other malicious votes (attribute ``allowlisted``,
  tag ``benign_scanner`` for legit scanners: CR27 caps the consensus at LOW), never a ``known_good``
  suppression; behaviours become finding tags (scanner, bruteforce, botnet...); background-noise
  scanners are LOW; ``mitre_techniques`` (the ATT&CK ids CrowdSec derives from its
  ``attack_details`` scenarios) become ``uses_technique`` pivots with ``expand=False``.
* c6 - CVEs (the ``cves`` list and the CVE ids named by ``attack_details`` scenarios) read 'attempted
  exploitation of CVE-X seen by CrowdSec', pivot with ``expand=False`` over the core relation
  ``attempted_exploit`` (IP -> CVE it tried to exploit, never ``has_vuln``), so own-asset
  vulnerability rules (CR15 reads ``has_vuln``) never fire on them.
* c7 - provider data is not redistributed: attribute ``export_restriction`` (verdict, link and source
  name only leave the company) and ``x_redistribution`` in the provider fragment. Only the 403 body is
  a real capture; the 200, 404 and 429 fixtures are documented shapes until the team key exists.

The answer is untrusted data: anything that is not the documented JSON object is 'could not verify'
(ERROR), never an absence.
"""

from __future__ import annotations

import ipaddress
import json
import math
import re
import threading
from collections import OrderedDict
from datetime import datetime, timezone
from typing import Any
from urllib.parse import urlsplit

from v3lum.config import SettingSpec
from v3lum.core import noise
from v3lum.core.entities import Entity
from v3lum.core.entities import EntityType as T
from v3lum.core.models import ModuleResult, Opsec, Status
from v3lum.core.module import Module, register

SOURCE = "crowdsec.smoke"
HOST = "cti.api.crowdsec.net"
API = "https://cti.api.crowdsec.net/v2/smoke/{ip}"
CONSOLE = "https://app.crowdsec.net/cti/{ip}"
KEY_NAME = "crowdsec"
KEY_HEADER = "x-api-key"
ATTRIBUTION = "CrowdSec CTI"
MONTHLY_SETTING = "crowdsec_monthly_quota"
CASE_SETTING = "crowdsec_case_budget"
MONTHLY_DEFAULT = 120
CASE_DEFAULT = 10
#: P334: budgets use at most 80% of the published limit
SAFETY_MARGIN = 0.8
#: background_noise_score (0-10) at or above which the IP is a background-noise scanner
NOISE_SCORE = 8
REPUTATIONS = ("malicious", "suspicious", "unknown", "known", "safe", "benign")
BENIGN_REPUTATIONS = ("known", "safe", "benign")
#: behaviour name (suffix after 'proto:') -> finding tag (vocabulary names)
BEHAVIOR_TAGS = {
    "scan": "scanner", "probing": "scanner", "crawl": "crawler",
    "bruteforce": "bruteforce",  # v3lum-lint: allow LINT-09 -- label of a behaviour CrowdSec reports for the address (detection), never attack code
    "exploit": "exploit_attempt", "spam": "spam", "dos": "dos", "ddos": "dos", "backdoor": "backdoor",
    "malware": "malware", "botnet": "botnet",
}
#: tags that make a finding a CR27 consensus vote: only a 'malicious' verdict may carry them
VOTE_TAGS = frozenset({"malicious", "phishing", "malware", "c2", "botnet"})
NOT_IN_DATA = "not in CrowdSec data (404): not a benign verdict"
_CTRL_RE = re.compile(r"[\x00-\x1f\x7f-\x9f​-‏‪-‮⁦-⁩]")
_TECHNIQUE_RE = re.compile(r"^T\d{4}(?:\.\d{3})?$")
_CVE_RE = re.compile(r"CVE-\d{4}-\d{4,7}", re.I)
_PATH_RE = re.compile(r"^/v2/smoke/([0-9A-Fa-f:.]+)$")


# --------------------------------------------------------------------------------------
# pure helpers (stdlib only; ported from the batch prep parsers)
# --------------------------------------------------------------------------------------


def clean_text(value: Any, limit: int = 160) -> str | None:
    """Display-safe single-line text (control and bidi characters removed), or None."""
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


def iso_ts(value: Any) -> str | None:
    """Provider timestamp (ISO 8601, naive read as UTC) -> 'YYYY-MM-DDTHH:MM:SSZ', or None."""
    text = clean_text(value, 64)
    if not text:
        return None
    if text.endswith(("Z", "z")):
        text = text[:-1] + "+00:00"
    try:
        parsed = datetime.fromisoformat(text)
    except ValueError:
        return None
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)
    return parsed.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def load_json(content: bytes | str | None) -> tuple[Any, str]:
    """(parsed JSON, '') or (None, why) for empty, HTML or malformed bodies."""
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


def request_allowed(method: str, url: str) -> bool:
    """Allow-list (c1): GET https://cti.api.crowdsec.net/v2/smoke/{one IP}, no query string. The
    Partner bulk (?ips=), search and fire endpoints are never built."""
    try:
        parts = urlsplit(url)
    except ValueError:
        return False
    if (method or "").upper() != "GET" or parts.scheme != "https" or parts.hostname != HOST or parts.query:
        return False
    match = _PATH_RE.match(parts.path)
    if not match:
        return False
    try:
        ipaddress.ip_address(match.group(1))
    except ValueError:
        return False
    return True


def _named(value: Any, limit: int = 50) -> list[dict[str, str]]:
    out: list[dict[str, str]] = []
    for item in value[:limit] if isinstance(value, list) else []:
        if isinstance(item, dict):
            name = clean_text(item.get("name"))
            if name:
                out.append({"name": name, "label": clean_text(item.get("label")) or name})
        else:
            name = clean_text(item)
            if name:
                out.append({"name": name, "label": name})
    return out


def _scores(value: Any) -> dict[str, dict[str, int | None]]:
    out: dict[str, dict[str, int | None]] = {}
    if isinstance(value, dict):
        for window in ("overall", "last_day", "last_week", "last_month"):
            block = value.get(window)
            if isinstance(block, dict):
                out[window] = {k: as_int(block.get(k)) for k in ("aggressiveness", "threat", "trust", "anomaly", "total")}
    return out


def behavior_tags(behaviors: list[dict[str, str]]) -> list[str]:
    """Behaviour names ('http:scan', 'ssh:bruteforce') -> sorted vocabulary tags (c5)."""
    tags: set[str] = set()
    for item in behaviors:
        name = item["name"].lower()
        tag = BEHAVIOR_TAGS.get(name.rsplit(":", 1)[-1])
        if tag is None:
            tag = next((t for key, t in BEHAVIOR_TAGS.items() if key in name), None)
        if tag:
            tags.add(tag)
    return sorted(tags)


def extract_cves(*values: Any) -> list[str]:
    found: set[str] = set()
    for value in values:
        for item in value if isinstance(value, (list, tuple)) else [value]:
            if isinstance(item, str):
                found.update(m.upper() for m in _CVE_RE.findall(item))
    return sorted(found)


def parse_smoke(obj: Any) -> dict[str, Any] | None:
    """Smoke JSON -> normalised facts, or None when the body is not a smoke object (c5/c6).

    ``techniques`` come from ``mitre_techniques`` (the ATT&CK ids CrowdSec derives from its scenarios);
    ``attack_details`` are scenario ids kept as context, and the CVE ids they name are merged with the
    top-level ``cves`` list."""
    if not isinstance(obj, dict) or not (clean_text(obj.get("ip"), 64) or isinstance(obj.get("reputation"), str)):
        return None
    loc = obj.get("location") if isinstance(obj.get("location"), dict) else {}
    hist = obj.get("history") if isinstance(obj.get("history"), dict) else {}
    cls = obj.get("classifications") if isinstance(obj.get("classifications"), dict) else {}
    behaviors = _named(obj.get("behaviors"))
    classifications = _named(cls.get("classifications"))
    false_positives = _named(cls.get("false_positives"))
    attack_details = _named(obj.get("attack_details"))
    techniques: list[dict[str, str]] = []
    for item in _named(obj.get("mitre_techniques")):
        tid = item["name"].upper()
        if _TECHNIQUE_RE.match(tid) and all(t["id"] != tid for t in techniques):
            techniques.append({"id": tid, "label": item["label"]})
    cves = extract_cves(obj.get("cves") if isinstance(obj.get("cves"), list) else [],
                        [a["name"] for a in attack_details], [a["label"] for a in attack_details])
    rep = (clean_text(obj.get("reputation"), 20) or "unknown").lower()
    targets = obj.get("target_countries") if isinstance(obj.get("target_countries"), dict) else {}
    country = clean_text(loc.get("country"), 8)
    return {
        "ip": clean_text(obj.get("ip"), 64),
        "reputation": rep if rep in REPUTATIONS else "unknown",
        "confidence": (clean_text(obj.get("confidence"), 10) or "none").lower(),
        "background_noise": (clean_text(obj.get("background_noise"), 10) or "none").lower(),
        "background_noise_score": as_int(obj.get("background_noise_score")),
        "ip_range": clean_text(obj.get("ip_range"), 64),
        "ip_range_24": clean_text(obj.get("ip_range_24"), 64),
        "ip_range_24_reputation": clean_text(obj.get("ip_range_24_reputation"), 20),
        "as_name": clean_text(obj.get("as_name")),
        "as_num": as_int(obj.get("as_num")),
        "country": country.upper() if country and re.fullmatch(r"[A-Za-z]{2}", country) else None,
        "reverse_dns": clean_text(obj.get("reverse_dns"), 253),
        "first_seen": iso_ts(hist.get("first_seen")),
        "last_seen": iso_ts(hist.get("last_seen")),
        "behaviors": behaviors,
        "classifications": classifications,
        "false_positives": false_positives,
        "attack_details": attack_details,
        "techniques": techniques,
        "cves": cves,
        "target_countries": {k.upper()[:8]: as_int(v) for k, v in list(targets.items())[:10] if isinstance(k, str)},
        "scores": _scores(obj.get("scores")),
        "references": _named(obj.get("references")),
    }


def verdict(p: dict[str, Any]) -> dict[str, Any]:
    """Normalised smoke facts -> verdict (c5).

    malicious -> MEDIUM, suspicious -> LOW (P171 consensus may raise either); background-noise
    scanners (``background_noise`` 'high' or a score >= 8) are LOW scanner context; false-positive
    classes, 'scanner:legit' and benign/known/safe reputations are info context that dampens other
    votes (never known_good); 'unknown' -> no verdict."""
    rep = p.get("reputation") or "unknown"
    reasons = [f"CrowdSec false positive: {fp['label']}" for fp in p.get("false_positives") or []]
    if rep in BENIGN_REPUTATIONS:
        reasons.append(f"CrowdSec reputation '{rep}'")
    legit_scanner = any(c["name"].lower().startswith("scanner:legit") for c in p.get("classifications") or [])
    if legit_scanner:
        reasons.append("CrowdSec classification: legit scanner")
    score = p.get("background_noise_score")
    noisy = p.get("background_noise") == "high" or (score is not None and score >= NOISE_SCORE)
    if rep in ("malicious", "suspicious") and reasons:
        band = "benign_context"
    elif rep == "malicious":
        band = "noise_scanner" if noisy else "malicious"
    elif rep == "suspicious":
        band = "noise_scanner" if noisy else "suspicious"
    elif reasons:
        band = "benign_context"
    else:
        band = "unknown"
    severity = {"malicious": "medium", "suspicious": "low", "noise_scanner": "low"}.get(band, "info")
    return {"band": band, "severity": severity, "dampen_reasons": reasons, "legit_scanner": legit_scanner, "noise": noisy}


def target_ip(entity: Entity) -> tuple[str | None, str]:
    """(IP to query, '') or (None, why not) - c1 one IP per GET, c3 skips."""
    value = entity.value
    if entity.type is T.CIDR:
        try:
            net = ipaddress.ip_network(value, strict=False)
        except ValueError:
            return None, "not a valid CIDR"
        if net.num_addresses != 1:
            return None, "CIDR range: the smoke endpoint takes one IP (no range lookups, P152 c1/c3)"
        value = str(net.network_address)
    if not public_ip(value):
        return None, "private, reserved or documentation address: never sent to CrowdSec (P152 c3)"
    etype = T.IPV6 if ":" in value else T.IPV4
    probe = Entity.try_make(etype, value)
    kinds = (noise.noise_kinds(probe) - {"private"}) if probe is not None else frozenset()
    if kinds:
        kind = next((k for k in noise.PRECEDENCE if k in kinds), sorted(kinds)[0])
        return None, f"{kind} infrastructure IP (noise list): no CrowdSec lookup spent (P152 c3)"
    return value, ""


def public_ip(value: str) -> bool:
    return noise.is_public_ip(value)


def monthly_budget(limit: Any) -> int:
    try:
        value = int(limit)
    except (TypeError, ValueError):
        value = MONTHLY_DEFAULT
    return max(0, math.floor(max(0, value) * SAFETY_MARGIN))


class _CaseCounters:
    """Distinct IPs looked up per case (process memory; a case runs in one process)."""

    def __init__(self, max_cases: int = 32) -> None:
        self._cases: OrderedDict[str, set[str]] = OrderedDict()
        self._lock = threading.Lock()
        self._max = max_cases

    def take(self, case_id: str, key: str, limit: int) -> bool:
        with self._lock:
            used = self._cases.get(case_id)
            if used is None:
                used = self._cases[case_id] = set()
                while len(self._cases) > self._max:
                    self._cases.popitem(last=False)
            else:
                self._cases.move_to_end(case_id)
            if key in used:
                return True
            if len(used) >= max(0, int(limit)):
                return False
            used.add(key)
            return True

    def reset(self) -> None:
        with self._lock:
            self._cases.clear()


CASE_COUNTERS = _CaseCounters()


# --------------------------------------------------------------------------------------
# the module
# --------------------------------------------------------------------------------------


@register
class CrowdsecCti(Module):
    name = "crowdsec_cti"
    title = "CrowdSec CTI"
    description = (
        "Crowd-sourced reputation of an IP from the CrowdSec CTI smoke API: verdict, behaviours, false-positive "
        "classes, ATT&CK techniques and CVEs the address tried to exploit (key required)."
    )
    category = "threat_intel_ioc"
    accepts = {T.IPV4, T.IPV6, T.CIDR}
    produces = {T.CVE, T.MITRE}
    run_on = "seeds"
    terms = "key-terms"
    opsec = Opsec.PASSIVE
    disclosure = "third_party"
    provider = "crowdsec"
    sources = (SOURCE,)
    hosts = (HOST,)
    access_model = "free_auth_limited"
    requires_keys = (KEY_NAME,)
    absent_statuses = frozenset({404})
    error_markers = (
        {"id": "crowdsec_quota_429", "statuses": [429], "regex": r"(?i)limit exceeded|quota",
         "maps_to": "quota", "reason_code": "quota",
         "reason": "CrowdSec CTI: the plan's lookup quota is exhausted (could not verify; deferred)"},
    )
    max_requests = 1
    expected_latency = 1.0
    timeout = 20.0
    min_interval = 2.0
    cache_ttl = 259200
    max_pivots = 60
    manual_link = "threat_intel_g07_p2:crowdsec_cti_ip"
    default_enabled = True
    tags = {"reputation"}
    reference = "https://docs.crowdsec.net/u/cti_api/intro"
    settings = {
        MONTHLY_SETTING: SettingSpec(
            MONTHLY_DEFAULT,
            "CrowdSec CTI lookups per month of the recorded plan (Community: 120); 80% is spent (P152 c3, P334)",
        ),
        CASE_SETTING: SettingSpec(
            CASE_DEFAULT,
            "CrowdSec CTI lookups per case (analyst-typed IPs only) so one scan never spends the monthly budget",
        ),
    }
    notice = (
        "CrowdSec CTI needs a key. The free Community key is for testing and personal servers: under the corporate "
        "profile the module runs only with a company-account paid key recorded as key_plans.crowdsec=business "
        "(otherwise skipped: licence, with the manual console link). 120 lookups per month on the Community plan: "
        "analyst-typed IPs only, 72 h cache. CrowdSec data stays internal: exports outside the company carry the "
        "verdict, link and source name only."
    )

    def applies(self, entity: Entity, ctx: Any) -> bool:
        # c3: analyst-typed seeds at depth 0 only (never pivots, text-extracted values or unconfirmed bulk seeds)
        if not getattr(ctx, "is_seed", True) or int(getattr(ctx, "depth", 0) or 0) != 0 or tuple(getattr(ctx, "provenance", ()) or ()):
            return False
        unconfirmed = getattr(getattr(ctx, "options", None), "unconfirmed_seeds", None) or ()
        return entity.key not in unconfirmed

    # ---- monthly budget (c3) -------------------------------------------------------------
    @staticmethod
    def _month_key(ctx: Any) -> str:
        return ctx.now().strftime("%Y-%m")

    def _month_used(self, ctx: Any) -> int:
        record = ctx.state.get("monthly_lookups") or {}
        if not isinstance(record, dict) or record.get("month") != self._month_key(ctx):
            return 0
        return as_int(record.get("used")) or 0

    def _charge_month(self, ctx: Any) -> None:
        ctx.state.set("monthly_lookups", {"month": self._month_key(ctx), "used": self._month_used(ctx) + 1})

    # ---- run ------------------------------------------------------------------------------
    def run(self, entity: Entity, ctx: Any) -> ModuleResult:
        res = self.result(entity)
        key = str(ctx.key(KEY_NAME) or "").strip()
        if not key:
            return res.mark(Status.NEEDS_KEY, "needs the CrowdSec CTI key (v3lum keys set crowdsec)", reason_code="needs_key")
        ip, why = target_ip(entity)
        if ip is None:
            return res.mark(Status.SKIPPED, why, reason_code="not_applicable")
        console = CONSOLE.format(ip=ip)
        url = API.format(ip=ip)
        if not request_allowed("GET", url):  # c1: never anything but one smoke lookup
            return res.mark(Status.ERROR, "refused a non-allow-listed CrowdSec request (module bug)", reason_code="error")
        budget = monthly_budget(ctx.setting(MONTHLY_SETTING, MONTHLY_DEFAULT))
        if self._month_used(ctx) >= budget:
            res.link("CrowdSec CTI console (manual)", console)
            return res.mark(Status.QUOTA, f"CrowdSec CTI monthly budget used ({budget} lookups this month, setting {MONTHLY_SETTING}): "
                            "could not verify; deferred", reason_code="quota")
        case_id = str(getattr(ctx, "case_id", "") or "")
        if case_id:
            limit = as_int(ctx.setting(CASE_SETTING, CASE_DEFAULT))
            limit = CASE_DEFAULT if limit is None else max(0, limit)
            if not CASE_COUNTERS.take(case_id, ip, limit):
                res.link("CrowdSec CTI console (manual)", console)
                return res.mark(Status.QUOTA, f"CrowdSec CTI budget of this case used ({limit} IPs, setting {CASE_SETTING}): "
                                "could not verify; deferred", reason_code="quota")
        resp = ctx.http.get(url, headers={KEY_HEADER: key, "Accept": "application/json"}, source=SOURCE)
        if not resp.from_cache:
            self._charge_month(ctx)
        if resp.status == 404 and resp.classification is None:
            res.raw = {"status": 404}
            res.attr("crowdsec", {"state": "not_in_data", "link": console})
            res.link("CrowdSec CTI console", console)
            return res.mark(Status.EMPTY, NOT_IN_DATA)
        # 403 -> NEEDS_KEY, 429 -> RATE_LIMITED (quota marker -> QUOTA), challenges, 5xx: raised before any
        # data is recorded, so the engine never keeps a 'partial' result for a refused lookup
        ctx.http.check(resp)
        res.link("CrowdSec CTI console", console)
        obj, why = load_json(resp.content)
        if why:
            return res.mark(Status.ERROR, f"unexpected CrowdSec answer ({why}): could not verify", reason_code="error")
        parsed = parse_smoke(obj)
        if parsed is None:
            message = clean_text(obj.get("message")) if isinstance(obj, dict) else None
            if message:
                return res.mark(Status.ERROR, f"CrowdSec error inside an HTTP 200 answer ({message}): could not verify", reason_code="error")
            return res.mark(Status.ERROR, "unexpected CrowdSec answer (not a smoke object): could not verify", reason_code="error")
        return self._report(res, entity, parsed, console)

    # ---- mapping (c5, c6, c7) ---------------------------------------------------------------
    def _report(self, res: ModuleResult, entity: Entity, p: dict[str, Any], console: str) -> ModuleResult:
        v = verdict(p)
        rep = p["reputation"]
        res.raw = {"status": 200, "smoke": p}
        res.attr("crowdsec", {
            "state": "answered", "reputation": rep, "confidence": p["confidence"], "background_noise": p["background_noise"],
            "background_noise_score": p["background_noise_score"], "behaviors": [b["label"] for b in p["behaviors"]][:20],
            "classifications": [c["name"] for c in p["classifications"]][:20], "false_positives": [f["name"] for f in p["false_positives"]][:20],
            "attack_details": [a["name"] for a in p["attack_details"]][:20], "target_countries": p["target_countries"],
            "scores": p["scores"], "ip_range_24": p["ip_range_24"], "ip_range_24_reputation": p["ip_range_24_reputation"],
            "references": [r["label"] for r in p["references"]][:10], "link": console,
        })
        res.attr("reputation", {"crowdsec": rep})
        res.attr("data_attribution", ATTRIBUTION)
        res.attr("export_restriction", {"source": ATTRIBUTION, "redistributable": False,
                                        "external_exports": "verdict, link and source name only", "verdict": rep, "link": console})
        if p["as_num"] is not None:
            res.attr("asn", f"AS{p['as_num']}")
        res.attr("as_org", p["as_name"])
        res.attr("country", p["country"])
        res.attr("rdns", [p["reverse_dns"]] if p["reverse_dns"] else None)
        res.attr("first_seen", p["first_seen"])
        res.attr("last_seen", p["last_seen"])
        res.attr("attack_techniques", [t["id"] for t in p["techniques"]])
        classes = {c["name"].lower() for c in p["classifications"]}
        if "proxy:tor" in classes:
            res.attr("is_tor_exit", True)
        if "proxy:vpn" in classes:
            res.attr("is_vpn", True)
        behaviour = behavior_tags(p["behaviors"])
        if "scanner" in behaviour or v["legit_scanner"] or v["noise"]:
            res.attr("is_scanner", True)
            if v["legit_scanner"]:
                res.attr("scanner_classification", "benign")
        if v["dampen_reasons"]:
            res.attr("allowlisted", v["dampen_reasons"])  # dampens other votes (CR27 SUP-allowlist), never known_good
        self._verdict_finding(res, p, v, behaviour, console)
        self._pivots(res, p)
        return res

    def _verdict_finding(self, res: ModuleResult, p: dict[str, Any], v: dict[str, Any], behaviour: list[str], console: str) -> None:
        behaviours = ", ".join(b["label"] for b in p["behaviors"][:6]) or "none reported"
        cves = p["cves"]
        attempted = "; ".join(f"attempted exploitation of {c} seen by CrowdSec" for c in cves[:5])
        base = (f"CrowdSec reputation '{p['reputation']}' ({p['confidence']} confidence); behaviours: {behaviours}; "
                f"last seen {(p['last_seen'] or 'unknown')[:10]}." + (f" {attempted}." if attempted else ""))
        data = {"band": v["band"], "reputation": p["reputation"], "confidence": p["confidence"], "behaviors": behaviour,
                "cves": cves, "techniques": [t["id"] for t in p["techniques"]], "background_noise": p["background_noise"],
                "upstream_families": ["crowdsec"]}
        common = {"references": [console], "source": SOURCE, "observed_first": p["first_seen"], "observed_last": p["last_seen"]}
        band = v["band"]
        if band == "malicious":
            res.finding(
                "Malicious IP (CrowdSec CTI)", "medium", base + " Raised only by an independent corroborating source (P171).",
                confidence="probable",
                criterion=f"CrowdSec smoke reputation 'malicious' ({p['confidence']} confidence) from crowd-sourced agent signals",
                data=data, tags=["malicious", *behaviour], **common,
            )
        elif band == "suspicious":
            res.finding(
                "Suspicious IP (CrowdSec CTI)", "low", base, confidence="possible",
                criterion=f"CrowdSec smoke reputation 'suspicious' ({p['confidence']} confidence)",
                data=data, tags=["suspicious", *[t for t in behaviour if t not in VOTE_TAGS]], **common,
            )
        elif band == "noise_scanner":
            res.finding(
                "Background-noise scanner (CrowdSec CTI)", "low",
                base + " A background-noise scanner probes the whole internet: not targeting you specifically.",
                confidence="possible",
                criterion=f"CrowdSec reputation '{p['reputation']}' with background noise {p['background_noise']} "
                          f"(score {p['background_noise_score']}): capped at low (P152 c5)",
                data=data, tags=["scanner", *[t for t in behaviour if t not in VOTE_TAGS and t != "scanner"]], **common,
            )
        elif band == "benign_context":
            res.finding(
                "Benign or false-positive activity (CrowdSec CTI)", "info",
                base + " " + "; ".join(v["dampen_reasons"]) + ". Context that dampens other malicious verdicts on this IP; "
                "it is not an allow-list.",
                confidence="probable", criterion="; ".join(v["dampen_reasons"]),
                data={**data, "dampen_reasons": v["dampen_reasons"]},
                tags=["benign_scanner"] if v["legit_scanner"] else ["info"], **common,
            )
        if cves:
            res.finding(
                "Exploitation attempts seen by CrowdSec", "info",
                "; ".join(f"attempted exploitation of {c} seen by CrowdSec" for c in cves[:20])
                + ". The address tried to exploit these CVEs against CrowdSec agents: it is not a statement that the "
                  "address (or your asset) is vulnerable.",
                data={"cves": cves, "attack_details": [a["name"] for a in p["attack_details"]][:20]},
                tags=["exploit_attempt"], **common,
            )

    @staticmethod
    def _pivots(res: ModuleResult, p: dict[str, Any]) -> None:
        for tech in p["techniques"]:
            res.pivot(T.MITRE, tech["id"], "uses_technique", confidence="possible", expand=False,
                      note=f"ATT&CK technique CrowdSec maps from this address's behaviour ({tech['label']})")
        for cve in p["cves"]:
            res.pivot(T.CVE, cve, "attempted_exploit", confidence="possible", expand=False,
                      note=f"attempted exploitation of {cve} seen by CrowdSec (an attempt by this address, not a vulnerability of it)")
