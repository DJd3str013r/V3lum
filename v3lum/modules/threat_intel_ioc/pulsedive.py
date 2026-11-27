"""pulsedive: Pulsedive indicator report of an IPv4, domain or URL (keyed only).

Batch p3-G07-1, proposal P160 (council final conditions):

* c1 - keyed only in this build (key ``pulsedive``, legacy KNOWN_KEYS + the provider fragment alias
  ``V3LUM_PULSEDIVE_KEY``); keyless community lookups are never sent. Registry source
  ``pulsedive.info``: terms key-terms, ``free_plan_business_use`` null: under the corporate profile
  only with ``key_plans.pulsedive = 'business'``.
* c2 - path allow-list enforced by :func:`request_allowed` and its unit test: only
  ``https://pulsedive.com/api/info.php?indicator=`` and ``/api/explore.php``; the analyze endpoint and
  every probe, scan or submit endpoint are never built, because they make Pulsedive actively scan the
  indicator (target contact, team rule 7). The module itself only calls info.php.
* c3 - statuses: risk none/unknown = no finding (never 'clean'); 'retired' indicators are info only;
  ``{"error": ...}`` inside a 200 -> ERROR (module error marker), 'Indicator not found.' (404 or 200)
  -> EMPTY 'not in Pulsedive'; invalid key (401) -> NEEDS_KEY; 429 -> RATE_LIMITED, QUOTA when the
  day/month counter (``X-Requests-Remaining-Day/Month``) is 0; the provider's P334 block paces the
  requests; cache 24 h.
* c4 - findings only for risk >= medium (medium LOW suspicious; high/critical MEDIUM malicious: a
  community aggregator alone never reaches HIGH, the P171 consensus does). ``feeds[]`` are kept as
  upstream provenance (attribute ``pulsedive.feeds`` with their families) and the finding's
  ``data['upstream_families']`` names the feed families the registry source ``embeds``, so CR27
  counts memberships already seen in the local feeds only once (P171/P159); Pulsedive's own family
  stands only for its own analysis and for feeds V3LUM does not consume.

Comments (attacker probe strings appear there), cookies, WHOIS, HTTP headers, banners and screenshots
are never copied. The answer is untrusted data: anything that is not an indicator document is 'could
not verify' (ERROR), never an absence.
"""

from __future__ import annotations

import base64
import ipaddress
import json
import re
from datetime import datetime, timezone
from typing import Any
from urllib.parse import parse_qs, quote, urlencode, urlsplit

from v3lum.core import noise
from v3lum.core.entities import Entity
from v3lum.core.entities import EntityType as T
from v3lum.core.models import ModuleResult, Opsec, Status
from v3lum.core.module import Module, register

SOURCE = "pulsedive.info"
HOST = "pulsedive.com"
INFO_URL = "https://pulsedive.com/api/info.php"
EXPLORE_URL = "https://pulsedive.com/api/explore.php"
KEY_NAME = "pulsedive"
CACHE_TTL = 86400
#: c2 allow-list: path -> (allowed query parameters, required parameter)
ALLOWED = {"/api/info.php": (frozenset({"indicator", "key", "pretty"}), "indicator"),
           "/api/explore.php": (frozenset({"q", "limit", "key", "pretty"}), "q")}
RISK_RANK = {"unknown": -1, "none": 0, "very low": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}
#: feed organisation/name -> registry upstream family (only families the registry source embeds)
FEED_FAMILIES = (
    (r"abuse\.ch|feodo|urlhaus|sslbl|threatfox|malwarebazaar", "abuse.ch"),
    (r"spamhaus", "spamhaus"), (r"blocklist\.de", "blocklist.de"), (r"\bcins\b|ci army|cinsscore", "cins"),
    (r"emerging ?threats|proofpoint", "emergingthreats"), (r"openphish", "openphish"), (r"phishtank", "phishtank"),
    (r"firehol", "firehol"), (r"tor project|torproject|tor exit", "tor-project"), (r"greensnow", "greensnow"),
    (r"binary ?defense", "binarydefense"), (r"dshield|internet storm center|\bsans\b", "dshield"),
    (r"alienvault|\botx\b", "otx"), (r"dataplane", "dataplane"), (r"botvrij", "botvrij"), (r"c2 ?intel|c2-tracker", "c2intelfeeds"),
)
OWN_FAMILY = "pulsedive"
_CTRL_RE = re.compile(r"[\x00-\x1f\x7f-\x9f​-‏‪-‮⁦-⁩]")


# --------------------------------------------------------------------------------------
# pure helpers (stdlib only; ported from the batch prep parsers)
# --------------------------------------------------------------------------------------


def clean_text(value: Any, limit: int = 200) -> str | None:
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
    if isinstance(value, str) and re.fullmatch(r"\s*-?\d{1,18}\s*", value):
        return int(value)
    return None


def str_list(value: Any, limit: int = 20, item_limit: int = 200) -> list[str]:
    """Pulsedive returns one value as a string and several as a list (dns.a, geo.countrycode...)."""
    if isinstance(value, (str, int, float)) and not isinstance(value, bool):
        value = [value]
    out: list[str] = []
    for item in value if isinstance(value, (list, tuple)) else []:
        text = clean_text(item, item_limit)
        if text and text not in out:
            out.append(text)
        if len(out) >= limit:
            break
    return out


def iso(value: Any) -> str | None:
    """'YYYY-MM-DD HH:MM:SS' (UTC) or ISO-8601 -> 'YYYY-MM-DDTHH:MM:SSZ'."""
    text = clean_text(value, 64)
    if not text:
        return None
    try:
        parsed = datetime.fromisoformat(text.replace("Z", "+00:00"))
    except ValueError:
        return None
    parsed = parsed if parsed.tzinfo else parsed.replace(tzinfo=timezone.utc)
    return parsed.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def normalize_domain(value: Any) -> str | None:
    text = clean_text(value, 260)
    if not text:
        return None
    text = text.strip().rstrip(".").lower()
    try:
        ipaddress.ip_address(text)
        return None
    except ValueError:
        pass
    try:
        text = text.encode("idna").decode("ascii")
    except UnicodeError:
        return None
    labels = text.split(".")
    if len(text) > 253 or len(labels) < 2 or labels[-1].isdigit():
        return None
    if not all(re.fullmatch(r"(?!-)[a-z0-9-]{1,63}(?<!-)", label) for label in labels):
        return None
    return text


def is_ip(value: Any) -> bool:
    try:
        ipaddress.ip_address(str(value or "").strip())
    except ValueError:
        return False
    return True


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


def info_url(indicator: str, key: str = "") -> str:
    """c2: GET https://pulsedive.com/api/info.php?indicator=<value>[&key=<key>] (never the analyze or
    probe endpoints). The key travels as the documented query parameter: the redactor masks it and the
    cache key hashes it (P326)."""
    value = clean_text(indicator, 2000)
    if not value or any(c.isspace() for c in indicator.strip()):
        raise ValueError("pulsedive: empty or invalid indicator")
    params = {"indicator": value}
    if key:
        params["key"] = key
    return INFO_URL + "?" + urlencode(params)


def explore_url(query: str, limit: int = 10, key: str = "") -> str:
    """c2: GET https://pulsedive.com/api/explore.php?q=<query>&limit=<n> (read-only search; allow-listed,
    not used by the module run)."""
    value = clean_text(query, 500)
    if not value:
        raise ValueError("pulsedive: empty explore query")
    params: dict[str, Any] = {"q": value, "limit": max(1, min(int(limit), 50))}
    if key:
        params["key"] = key
    return EXPLORE_URL + "?" + urlencode(params)


def request_allowed(method: str, url: str) -> bool:
    """c2 path allow-list (unit-tested): GET https://pulsedive.com/api/info.php?indicator=... or
    /api/explore.php?q=...; every other path (the analyze endpoint, probe/scan/submit endpoints, other
    API scripts), unknown or repeated parameters, POST, http and other hosts are refused."""
    if (method or "").upper() != "GET" or not isinstance(url, str):
        return False
    try:
        parts = urlsplit(url)
        params = parse_qs(parts.query, keep_blank_values=True)
        port = parts.port
    except ValueError:
        return False
    if parts.scheme != "https" or parts.hostname != HOST or port not in (None, 443) or parts.fragment:
        return False
    if parts.username or parts.password:
        return False
    rule = ALLOWED.get(parts.path)
    if rule is None:
        return False
    allowed, required = rule
    if not set(params) <= allowed or required not in params:
        return False
    return all(len(v) == 1 for v in params.values()) and bool(params[required][0].strip())


def risk(value: Any) -> str | None:
    text = (clean_text(value, 20) or "").lower()
    return text if text in RISK_RANK else None


def feed_family(name: Any, organization: Any = None) -> str:
    """c4: feed -> registry upstream family (organisation first, then the feed name); feeds V3LUM does
    not consume are Pulsedive's own family."""
    for text in (clean_text(organization, 120), clean_text(name, 120)):
        low = (text or "").lower()
        for pattern, family in FEED_FAMILIES:
            if low and re.search(pattern, low):
                return family
    return OWN_FAMILY


def parse_info(obj: Any) -> dict[str, Any] | None:
    """info.php body -> normalised facts; None when it is not an indicator document. Comments,
    cookies, WHOIS, HTTP headers, page metadata, banners and screenshots are never copied."""
    if not isinstance(obj, dict) or "indicator" not in obj or "error" in obj:
        return None
    props = obj.get("properties") if isinstance(obj.get("properties"), dict) else {}
    geo = props.get("geo") if isinstance(props.get("geo"), dict) else {}
    dns = props.get("dns") if isinstance(props.get("dns"), dict) else {}
    attrs = obj.get("attributes") if isinstance(obj.get("attributes"), dict) else {}
    redirects = obj.get("redirects") if isinstance(obj.get("redirects"), dict) else {}
    asn_raw = (str_list(geo.get("asn"), 1) or [""])[0]
    asn_match = re.fullmatch(r"AS(\d{1,10})", asn_raw or "")
    threats = []
    for row in obj.get("threats") if isinstance(obj.get("threats"), list) else []:
        if isinstance(row, dict) and clean_text(row.get("name"), 80):
            threats.append({"name": clean_text(row.get("name"), 80), "category": (clean_text(row.get("category"), 30) or "").lower() or None,
                            "risk": risk(row.get("risk")), "linked": iso(row.get("stamp_linked"))})
    feeds = []
    for row in obj.get("feeds") if isinstance(obj.get("feeds"), list) else []:
        if isinstance(row, dict) and clean_text(row.get("name"), 120):
            feeds.append({"name": clean_text(row.get("name"), 120), "category": (clean_text(row.get("category"), 30) or "").lower() or None,
                          "organization": clean_text(row.get("organization"), 120), "linked": iso(row.get("stamp_linked")),
                          "family": feed_family(row.get("name"), row.get("organization"))})
    factors = []
    for row in obj.get("riskfactors") if isinstance(obj.get("riskfactors"), list) else []:
        if isinstance(row, dict) and clean_text(row.get("description"), 160):
            factors.append({"description": clean_text(row.get("description"), 160), "risk": risk(row.get("risk"))})
    country = (str_list(geo.get("countrycode"), 1) or [""])[0].upper()[:2]
    return {
        "indicator": clean_text(obj.get("indicator"), 2000),
        "type": (clean_text(obj.get("type"), 20) or "").lower() or None,
        "risk": risk(obj.get("risk")),
        "risk_recommended": risk(obj.get("risk_recommended")),
        "manual_risk": bool(as_int(obj.get("manualrisk"))),
        "retired": clean_text(obj.get("retired"), 120),
        "stamps": {k: iso(obj.get(f"stamp_{k}")) for k in ("added", "updated", "seen", "probed", "retired")},
        "riskfactors": factors[:20],
        "threats": threats[:20],
        "feeds": feeds[:30],
        "attributes": {k: str_list(attrs.get(k), 15, 60) for k in ("port", "protocol", "technology", "hosttype") if attrs.get(k)},
        "redirects_to": [x for x in (clean_text(r.get("indicator"), 2000) for r in (redirects.get("to") or []) if isinstance(r, dict)) if x][:10],
        "dns": {k: v for k, v in {
            "a": [x for x in str_list(dns.get("a"), 10, 64) if is_ip(x)],
            "aaaa": [x for x in str_list(dns.get("aaaa"), 10, 64) if is_ip(x)],
            "ns": [x for x in (normalize_domain(n) for n in str_list(dns.get("ns"), 10, 253)) if x],
            "ptr": [x for x in (normalize_domain(n) for n in str_list(dns.get("ptr"), 5, 253)) if x],
        }.items() if v},
        "country": country if re.fullmatch(r"[A-Z]{2}", country or "") and country != "ZZ" else None,
        "asn": int(asn_match.group(1)) if asn_match else None,
        "umbrella_rank": as_int(obj.get("umbrella_rank")) or None,
    }


def verdict(p: dict[str, Any]) -> dict[str, Any]:
    """c3/c4: retired -> info only; risk none/unknown/low -> no finding (never clean); medium -> LOW
    suspicious; high/critical -> MEDIUM malicious (HIGH only through the P171 consensus)."""
    rank = RISK_RANK.get(p.get("risk") or "unknown", -1)
    if p.get("retired"):
        return {"band": "retired", "severity": "info", "finding": True}
    if rank < RISK_RANK["medium"]:
        return {"band": "none", "severity": None, "finding": False}
    if rank == RISK_RANK["medium"]:
        return {"band": "suspicious", "severity": "low", "finding": True}
    return {"band": "malicious", "severity": "medium", "finding": True}


def vote_families(p: dict[str, Any]) -> list[str]:
    """c4: the families a verdict stands for, for CR27: the embedded families of its feeds, plus
    Pulsedive's own family for its own analysis (risk factors other than feed membership, threats
    without a feed) and for feeds V3LUM does not consume."""
    fams = {f["family"] for f in p.get("feeds", [])}
    own_factors = [f for f in p.get("riskfactors", []) if RISK_RANK.get(f.get("risk") or "unknown", -1) >= RISK_RANK["medium"]
                   and "feed" not in (f.get("description") or "").lower()]
    if own_factors or not p.get("feeds"):
        fams.add(OWN_FAMILY)
    return sorted(fams)


def pivots(p: dict[str, Any]) -> list[tuple[T, str, str, bool, str]]:
    """(type, value, relation, expand, note) for risk >= medium and not retired: the URL host
    (expand=True), a domain's A records, malware threats (families) and group threats (actors); the
    last three are listed only (expand=False). Below medium nothing is pivoted (example.com links
    Emotet threats at risk none)."""
    if p.get("retired") or RISK_RANK.get(p.get("risk") or "unknown", -1) < RISK_RANK["medium"]:
        return []
    out: list[tuple[T, str, str, bool, str]] = []
    if p.get("type") == "url":
        try:
            host = urlsplit(p.get("indicator") or "").hostname or ""
        except ValueError:
            host = ""
        if is_ip(host):
            out.append((T.IPV6 if ":" in host else T.IPV4, host, "url_host", True, "host of the Pulsedive-listed URL"))
        elif normalize_domain(host):
            out.append((T.DOMAIN, normalize_domain(host) or host, "url_host", True, "host of the Pulsedive-listed URL"))
    if p.get("type") == "domain":
        for addr in p.get("dns", {}).get("a", [])[:10]:
            out.append((T.IPV4, addr, "resolves_to", False, "A record reported by Pulsedive (not resolved by V3LUM)"))
    for threat in p.get("threats", []):
        if threat.get("category") == "malware":
            out.append((T.MALWARE, threat["name"], "family", False, "Pulsedive threat (malware)"))
        elif threat.get("category") == "group":
            out.append((T.THREAT_ACTOR, threat["name"], "attributed_to", False, "Pulsedive threat (group)"))
    return out


def web_link(value: str) -> str:
    """Manual Pulsedive indicator page (base64 of the indicator in ?ioc=)."""
    return "https://pulsedive.com/indicator/?ioc=" + quote(base64.b64encode(value.encode("utf-8")).decode("ascii"), safe="")


def public_ip(value: str) -> bool:
    """Private, reserved and documentation addresses are never sent (patched in tests)."""
    return noise.is_public_ip(value)


# --------------------------------------------------------------------------------------
# the module
# --------------------------------------------------------------------------------------


@register
class Pulsedive(Module):
    name = "pulsedive"
    title = "Pulsedive indicator info"
    description = (
        "Pulsedive risk, risk factors, threats and feed memberships of an IPv4, domain or URL from "
        "pulsedive.com/api/info.php (key required; never the analyze/probe endpoints)."
    )
    category = "threat_intel_ioc"
    accepts = {T.IPV4, T.DOMAIN, T.URL}
    produces = {T.DOMAIN, T.IPV4, T.IPV6, T.MALWARE, T.THREAT_ACTOR}
    terms = "key-terms"
    opsec = Opsec.PASSIVE
    disclosure = "third_party"
    provider = "pulsedive"
    sources = (SOURCE,)
    hosts = (HOST,)
    access_model = "free_auth_limited"
    requires_keys = (KEY_NAME,)
    error_markers = (
        {"id": "pulsedive_quota_day_month", "statuses": [200, 429], "json_path": "error", "regex": "(?i)per (day|month)",
         "maps_to": "quota", "reason_code": "quota",
         "reason": "Pulsedive: daily/monthly limit of the key's plan reached (could not verify; deferred)"},
        {"id": "pulsedive_error_in_200", "statuses": [200], "json_path": "error", "regex": "(?i)^(?!indicator not found)",
         "maps_to": "error", "reason_code": "error", "reason": "Pulsedive: error inside an HTTP 200 answer: could not verify"},
    )
    max_requests = 1
    expected_latency = 0.5
    timeout = 20.0
    min_interval = 1.1
    cache_ttl = CACHE_TTL
    max_pivots = 30
    manual_link = "threat_intel_g07_p3:pulsedive_indicator"
    default_enabled = True
    tags = {"reputation"}
    reference = "https://docs.pulsedive.com/"
    notice = (
        "Pulsedive is keyed only in this build (key 'pulsedive' from a company account; keyless community lookups are "
        "never sent); under the corporate profile it runs only with key_plans.pulsedive=business. Only info.php is "
        "called: the analyze/probe endpoints, which make Pulsedive scan the indicator, are never built."
    )

    def applies(self, entity: Entity, ctx: Any) -> bool:
        if entity.type is T.IPV4:
            return public_ip(entity.value)  # private/reserved addresses are never sent
        return True

    def run(self, entity: Entity, ctx: Any) -> ModuleResult:
        res = self.result(entity)
        key = str(ctx.key(KEY_NAME) or "").strip()
        if not key:
            return res.mark(Status.NEEDS_KEY, "needs the Pulsedive key (v3lum keys set pulsedive)", reason_code="needs_key")
        link = web_link(entity.value)
        try:
            url = info_url(entity.value, key)
        except ValueError as exc:
            return res.mark(Status.SKIPPED, str(exc), reason_code="not_applicable")
        if not request_allowed("GET", url):  # c2: info.php only
            return res.mark(Status.ERROR, "refused a non-allow-listed Pulsedive request (module bug)", reason_code="error")
        resp = ctx.http.get(url, headers={"Accept": "application/json"}, source=SOURCE)
        obj, why = load_json(resp.content)
        message = clean_text(obj.get("error"), 200) if isinstance(obj, dict) else None
        if resp.status in (200, 404) and message and message.lower().startswith("indicator not found"):
            res.raw = {"status": resp.status, "not_found": True}
            return res.mark(Status.EMPTY, "not in Pulsedive ('Indicator not found.')")
        if resp.status == 429:
            day = as_int((resp.headers or {}).get("x-requests-remaining-day"))
            month = as_int((resp.headers or {}).get("x-requests-remaining-month"))
            if day == 0 or month == 0:
                res.link("Pulsedive indicator page (manual)", link)
                period = "daily" if day == 0 else "monthly"
                return res.mark(Status.QUOTA, f"Pulsedive: {period} limit of the key's plan reached (HTTP 429): could not verify; deferred",
                                reason_code="quota")
        if resp.status == 404:
            return res.mark(Status.ERROR, f"Pulsedive HTTP 404 ({message or 'no detail'}): could not verify", reason_code="error")
        ctx.http.check(resp)  # 401 NEEDS_KEY, 429 RATE_LIMITED, error markers, challenges, 5xx
        if why:
            return res.mark(Status.ERROR, f"unexpected Pulsedive answer ({why}): could not verify", reason_code="error")
        if message:
            return res.mark(Status.ERROR, f"Pulsedive error inside an HTTP 200 answer ({message}): could not verify", reason_code="error")
        parsed = parse_info(obj)
        if parsed is None:
            return res.mark(Status.ERROR, "unexpected Pulsedive answer (not an indicator document): could not verify", reason_code="error")
        return self._report(res, parsed, link)

    # ---- report (c3, c4) -------------------------------------------------------------------
    def _report(self, res: ModuleResult, p: dict[str, Any], link: str) -> ModuleResult:
        v = verdict(p)
        families = vote_families(p)
        res.raw = {"status": 200, "indicator": p}
        res.link("Pulsedive indicator page", link)
        facts = {k: p[k] for k in ("risk", "risk_recommended", "manual_risk", "retired", "stamps", "riskfactors", "threats",
                                  "feeds", "attributes", "dns", "umbrella_rank")}
        facts["feed_families"] = sorted({f["family"] for f in p["feeds"]})
        facts["link"] = link
        res.attr("pulsedive", facts)
        res.attr("reputation", {"pulsedive": p["risk"] or "unknown"})
        res.attr("country", p["country"])
        if p["asn"] is not None:
            res.attr("asn", f"AS{p['asn']}")
        if p.get("dns", {}).get("ptr"):
            res.attr("hostnames", p["dns"]["ptr"])
        actors = [t["name"] for t in p["threats"] if t.get("category") == "group"]
        fams = [t["name"] for t in p["threats"] if t.get("category") == "malware"]
        if v["band"] in ("suspicious", "malicious"):
            res.attr("threat_actors", actors or None)
            res.attr("malware_family", fams or None)
        for etype, value, relation, expand, note in pivots(p)[: self.max_pivots]:
            res.pivot(etype, value, relation, confidence="possible" if not expand else "probable", expand=expand, note=note)
        threats = ", ".join(t["name"] for t in p["threats"][:5])
        feeds = ", ".join(f"{f['name']} ({f['organization'] or 'unknown operator'})" for f in p["feeds"][:5])
        if v["band"] == "retired":
            since = (p["stamps"].get("retired") or "")[:10]
            res.finding(
                "Retired Pulsedive indicator", "info",
                f"Pulsedive retired this indicator ({p['retired']}{', since ' + since if since else ''}); last risk "
                f"{p['risk'] or 'unknown'}. History only, never a current verdict.",
                confidence="possible", criterion="Pulsedive retired indicator: info only (P160 cond 3)",
                tags=["info", "retired_indicator"], source=SOURCE, references=[link],
                observed_last=p["stamps"].get("seen"), data={"risk": p["risk"], "retired": p["retired"]},
            )
            return res
        if not v["finding"]:
            return res  # risk none/unknown/low: facts only, never 'clean' (c3, c4)
        description = (
            f"Pulsedive risk {p['risk']}" + (f" (recommended {p['risk_recommended']})" if p["risk_recommended"] and p["risk_recommended"] != p["risk"] else "")
            + (f"; threats: {threats}" if threats else "") + (f"; feeds: {feeds}" if feeds else "")
            + (f"; risk factors: {', '.join(f['description'] for f in p['riskfactors'][:4])}" if p["riskfactors"] else "") + "."
        )
        data = {"risk": p["risk"], "threats": [t["name"] for t in p["threats"][:10]],
                "feeds": [{"name": f["name"], "organization": f["organization"], "family": f["family"]} for f in p["feeds"][:10]],
                "upstream_families": families}
        common = {"references": [link], "source": SOURCE, "observed_first": p["stamps"].get("added"),
                  "observed_last": p["stamps"].get("seen"), "data": data}
        if v["band"] == "malicious":
            tags = ["malicious"] + (["phishing"] if any("phish" in (t["name"] or "").lower() for t in p["threats"]) else [])
            res.finding("Malicious per Pulsedive", v["severity"], description + " HIGH only with an independent corroborating source (P171).",
                        confidence="probable" if p["risk"] == "critical" else "possible",
                        criterion=f"Pulsedive risk {p['risk']} (>= high; community aggregator, one vote per upstream family)",
                        tags=tags, **common)
        else:
            res.finding("Suspicious per Pulsedive", v["severity"], description, confidence="possible",
                        criterion=f"Pulsedive risk {p['risk']} (medium: findings only for risk >= medium)",
                        tags=["suspicious"], **common)
        return res
