"""ipqualityscore: IPQualityScore IP and URL reputation, keyed (P052, veto_lift form).

Batch p3-G02-2, proposal P052. Final conditions implemented here:

* FC1 (veto_lift) - ``accepts = {ipv4, url}`` only. The e-mail and phone validation endpoints are
  never wired: :func:`ipqs_endpoint` refuses every kind other than 'ip' and 'url'
  (:class:`EndpointRefused`), so no request to ``/api/json/email`` or ``/api/json/phone`` can be
  built (unit-tested); a crafted URL value cannot escape ``/api/json/url/`` (fully percent-encoded).
* FC2 (veto_lift) - URL reputation runs only for URLs tagged hostile (malicious/phishing/suspicious:
  an entity tag the core exposes to modules, or a hostile producing relation such as
  ``listed_phishing_url``), never for internal hosts, own (org-profile) URLs or recipient-token URLs
  (the provider fetches the target live), and is skipped at TLP:AMBER and above (SKIPPED 'tlp').
  The registry has no source-level ``reuses_queries``/``fetches_target`` flags yet: they are
  recorded as data in the provider fragment (``x_source_flags``) and enforced here until the core
  supports them (core request).
* FC3 - the key ``ipqs`` (legacy ``config.KNOWN_KEYS`` entry, alias ``V3LUM_IPQS_KEY`` added by the
  provider fragment); key-terms: under the corporate profile it runs only once legal recorded the
  company plan (``key_plans.ipqs = business``).
* FC4 - ``success:false`` in an HTTP 200 body is classified by the provider's P321 markers (credits
  -> QUOTA, rate -> RATE_LIMITED, anything else -> ERROR) and an invalid/unauthorized key is
  reported NEEDS_KEY; never EMPTY. Error bodies are never cached.
* FC5 - the key travels in the URL path: the central redactor (AR01) masks the configured key
  value in every URL, cache row, event, log, error and evidence (tested with ``assert_no_secret``).
* FC6 - monthly budget of 1,000 lookups (provider P334 quota block, key scope);
  ``default_enabled=False``; the fraud score is ONE vote: 'suspicious' (LOW) at score >= 75, never
  'malicious'. Location fields (city, coordinates, zip) are never kept.
* FC7 - the success fixtures are documentation-shaped until a trimmed real capture made with the
  company key replaces them (merge precondition recorded in docs/backlog/p3-G02-2.md); the
  invalid-key fixture is the real research capture.
"""

from __future__ import annotations

import ipaddress
import re
from typing import Any
from urllib.parse import quote, urlsplit

from v3lum.core import http as _http
from v3lum.core import tlp as _tlp
from v3lum.core.entities import Entity
from v3lum.core.entities import EntityType as T
from v3lum.core.models import ModuleResult, Opsec, Status
from v3lum.core.module import Module, register
from v3lum.modules.ip_network.ip_geolocation import (
    EndpointRefused,
    bogon_reason,
    error_message,
    flag,
    integer,
    json_ok,
    normalize_domain,
    normalize_ip,
    parse_asn,
    text,
)

SRC_IP = "ipqualityscore.ip"
SRC_URL = "ipqualityscore.url"
HOST = "ipqualityscore.com"
ALLOWED_KINDS = ("ip", "url")  # FC1
REFUSED_KINDS = ("email", "phone")  # FC1: provider-side mailbox/carrier probing (rule 2 by proxy)
SUSPICIOUS_SCORE = 75  # IPQS guidance: >= 75 suspicious, >= 85 high risk
HOSTILE_TAGS = frozenset({"malicious", "phishing", "suspicious"})  # FC2
#: relations whose producing module already judged the URL hostile (the URL is the listed object)
HOSTILE_RELATIONS = frozenset({"listed_phishing_url", "served_from", "drops", "communicates_with", "group_ioc"})
INTERNAL_SUFFIXES = (".local", ".internal", ".corp", ".lan", ".intranet", ".home.arpa", ".localhost", ".localdomain")
_KEY_RE = re.compile(r"^[A-Za-z0-9]{8,128}$")
_KEY_ERROR = re.compile(r"(?i)\b(invalid|unauthori[sz]ed|missing)\b.*\bkey\b|\bkey\b.*\b(invalid|unauthori[sz]ed|missing)\b")


def ipqs_endpoint(kind: str, key: str, value: str) -> str:
    """IPQS lookup URL with the key in the PATH (/api/json/{kind}/{key}/{value}).

    FC1: only 'ip' and 'url' can be built; 'email', 'phone' or anything else raises
    :class:`EndpointRefused`. IPs must be public; URL values are fully percent-encoded."""
    k = str(kind or "").strip().lower()
    if k not in ALLOWED_KINDS:
        raise EndpointRefused(f"IPQS {kind!r} endpoint is never wired (P052 FC1: e-mail/phone validation probes mailboxes and carriers)")
    if not isinstance(key, str) or not _KEY_RE.match(key):
        raise ValueError("IPQS key missing or not alphanumeric")
    if k == "ip":
        if bogon_reason(value):
            raise ValueError(f"refusing {bogon_reason(value)} address for IPQS")
        return f"https://{HOST}/api/json/ip/{key}/{normalize_ip(value)}"
    parts = urlsplit(str(value or ""))
    if parts.scheme not in ("http", "https") or not parts.hostname:
        raise ValueError("IPQS URL lookup needs an http(s) URL")
    return f"https://{HOST}/api/json/url/{key}/{quote(str(value), safe='')}"


def parse_ip(doc: Any) -> dict[str, Any] | None:
    """IPQS IP reputation record (no location fields); None when the answer is not a success."""
    if not isinstance(doc, dict) or doc.get("success") is not True:
        return None
    rec = {
        "fraud_score": integer(doc.get("fraud_score")), "recent_abuse": flag(doc.get("recent_abuse")),
        "abuse_velocity": text(doc.get("abuse_velocity")), "connection_type": text(doc.get("connection_type")),
        "proxy": flag(doc.get("proxy")), "vpn": flag(doc.get("vpn")) or flag(doc.get("active_vpn")),
        "tor": flag(doc.get("tor")) or flag(doc.get("active_tor")), "bot_status": flag(doc.get("bot_status")),
        "isp": text(doc.get("ISP")), "asn": f"AS{parse_asn(doc.get('ASN'))}" if parse_asn(doc.get("ASN")) else None,
    }
    score = rec["fraud_score"]
    if score is not None and not 0 <= score <= 100:
        rec["fraud_score"] = score = None
    rec["vote"] = "suspicious" if isinstance(score, int) and score >= SUSPICIOUS_SCORE else "no_signal"
    return rec


def parse_url(doc: Any) -> dict[str, Any] | None:
    """IPQS malicious URL scanner record; None when the answer is not a success."""
    if not isinstance(doc, dict) or doc.get("success") is not True:
        return None
    age = doc.get("domain_age") if isinstance(doc.get("domain_age"), dict) else {}
    rec = {
        "risk_score": integer(doc.get("risk_score")), "unsafe": flag(doc.get("unsafe")), "phishing": flag(doc.get("phishing")),
        "malware": flag(doc.get("malware")), "suspicious": flag(doc.get("suspicious")), "category": text(doc.get("category")),
        "domain": normalize_domain(doc.get("domain")), "domain_age": text(age.get("iso")), "redirected": flag(doc.get("redirected")),
        "final_url": text(doc.get("final_url")),
    }
    score = rec["risk_score"]
    if score is not None and not 0 <= score <= 100:
        rec["risk_score"] = score = None
    flags = [f for f in ("phishing", "malware", "unsafe", "suspicious") if rec.get(f)]
    rec["flags"] = flags
    rec["vote"] = "suspicious" if flags or (isinstance(score, int) and score >= SUSPICIOUS_SCORE) else "no_signal"
    return rec


def hostile_evidence(entity: Entity, ctx: Any) -> str:
    """FC2: why this URL counts as tagged hostile ('' when nothing says so)."""
    tags = getattr(ctx, "entity_tags", None)  # exposed by the core once modules can see graph tags (core request)
    if callable(tags):
        try:
            tags = tags()
        except Exception:  # noqa: BLE001 - no tags readable: not hostile-tagged
            tags = None
    found = sorted({str(t).strip().lower() for t in (tags or ()) if isinstance(t, str)} & HOSTILE_TAGS)
    if found:
        return f"tagged {', '.join(found)} in the case"
    prov = getattr(ctx, "provenance", ()) or ()
    if prov:
        last = prov[-1]
        if len(last) >= 3 and str(last[1]) in HOSTILE_RELATIONS:
            return f"reached through the hostile relation {last[1]!r} ({last[2]})"
    return ""


def internal_host(host: str) -> str:
    """Why a URL host is internal/confidential ('' for a public name or address)."""
    h = (host or "").strip().lower().rstrip(".")
    if not h:
        return "no host"
    try:
        ipaddress.ip_address(h.strip("[]"))
        reason = bogon_reason(h.strip("[]"))
        return f"{reason} address" if reason else ""
    except ValueError:
        pass
    if "." not in h:
        return "single-label (intranet) host"
    if h.endswith(INTERNAL_SUFFIXES):
        return "internal domain suffix"
    return ""


@register
class IpQualityScore(Module):
    name = "ipqualityscore"
    title = "IPQualityScore IP/URL reputation"
    description = (
        "IPQualityScore fraud score and proxy/VPN/Tor flags for a public IPv4, and the malicious-URL scanner for URLs "
        "already tagged hostile (keyed; one vote, never 'malicious' alone; e-mail/phone validation never wired)."
    )
    category = "ip_network"
    accepts = {T.IPV4, T.URL}
    produces = frozenset()
    tags = {"reputation"}
    reference = "https://www.ipqualityscore.com/documentation/proxy-detection-api/overview"
    notice = (
        "Keyed (key-terms): runs under the corporate profile only with a company-owned key whose plan legal recorded "
        "(key_plans.ipqs). URL reputation only for hostile-tagged URLs, never internal/own/token URLs, skipped at "
        "TLP:AMBER and above (IPQS reuses submitted URLs and fetches them live). E-mail/phone validation is never used."
    )
    terms = "key-terms"
    opsec = Opsec.PASSIVE
    disclosure = "third_party"
    provider = "ipqualityscore"
    sources = (SRC_IP, SRC_URL)
    hosts = ("ipqualityscore.com", "www.ipqualityscore.com")
    access_model = "free_auth_limited"
    requires_keys = ("ipqs",)
    max_requests = 1
    expected_latency = 2.0
    timeout = 30.0
    min_interval = 1.0
    cache_ttl = 86400
    max_pivots = 0
    default_enabled = False  # FC6

    def applies(self, entity: Entity, ctx: Any) -> bool:
        if entity.type == T.IPV4:
            return bogon_reason(entity.value) is None
        parts = urlsplit(entity.value)
        return parts.scheme in ("http", "https") and bool(parts.hostname)

    def run(self, entity: Entity, ctx: Any) -> ModuleResult:
        res = self.result(entity)
        key = str(ctx.key("ipqs") or "").strip()
        if not key:
            return res.mark(Status.NEEDS_KEY, "IPQualityScore needs the key 'ipqs' (V3LUM_IPQS_KEY)", reason_code="needs_key")
        if entity.type == T.URL:
            why_not = self._url_gate(entity, ctx)
            if why_not is not None:
                status, code, reason = why_not
                return res.mark(status, reason, reason_code=code)
            kind, source = "url", SRC_URL
        else:
            kind, source = "ip", SRC_IP
        if source not in ctx.allowed_sources:
            return res.mark(Status.SKIPPED, f"{source} not allowed in this run", reason_code="licence")
        try:
            url = ipqs_endpoint(kind, key, entity.value)
        except ValueError as exc:
            if "key" in str(exc):
                return res.mark(Status.NEEDS_KEY, "IPQualityScore key is not a valid API key (alphanumeric)", reason_code="needs_key")
            return res.mark(Status.SKIPPED, f"{exc}", reason_code="not_applicable")
        try:
            doc = ctx.http.get_json(url, params={"strictness": "0"}, source=source,
                                    cache_if=json_ok(lambda d: isinstance(d, dict) and d.get("success") is True))
        except (_http.QuotaExceeded, _http.RateLimited, _http.Blocked, _http.AuthRequired):
            raise
        except _http.HttpError as exc:
            msg = error_message(exc)
            if _KEY_ERROR.search(msg):  # FC4: 'Invalid or unauthorized key' in an HTTP 200 body
                return res.mark(Status.NEEDS_KEY, f"IPQualityScore: {msg}", reason_code="needs_key")
            return res.mark(Status.ERROR, f"IPQualityScore: {msg or str(exc)[:160]}: could not verify", reason_code="error")
        return self._ip_result(res, doc) if kind == "ip" else self._url_result(res, doc)

    # ---------------------------------------------------------------------------- gates
    def _url_gate(self, entity: Entity, ctx: Any) -> tuple[Status, str, str] | None:
        """FC2: None when the URL may be sent, else (status, reason_code, reason)."""
        if _tlp.parse(getattr(ctx, "tlp", "amber")) >= _tlp.TLP.AMBER:
            return (Status.SKIPPED, "tlp", "IPQualityScore URL reputation reuses submitted URLs: skipped at TLP:AMBER and above (P052 FC2)")
        host = urlsplit(entity.value).hostname or ""
        why = internal_host(host)
        if why:
            return (Status.SKIPPED, "policy", f"internal/confidential URL ({why}) is never sent to IPQualityScore (P052 FC2)")
        org = getattr(ctx, "org", None)
        try:
            owned = org.owns(entity) if org is not None and not getattr(org, "is_empty", True) else None
        except Exception:  # noqa: BLE001 - an unreadable profile never sends a value out
            return (Status.SKIPPED, "policy", "organisation profile unreadable: URL not sent (P052 FC2)")
        if owned is not None and getattr(owned, "own", False):
            return (Status.SKIPPED, "policy", "org-profile URL is never sent to IPQualityScore (P052 FC2)")
        try:
            from v3lum.core.policy import recipient_token

            token = recipient_token(entity.value, org)
        except Exception:  # noqa: BLE001 - when in doubt the URL is not handed to a live fetcher
            token = True
        confirmed = getattr(getattr(ctx, "options", None), "confirmed_urls", None) or set()
        if token and entity.value not in confirmed:
            return (Status.SKIPPED, "policy", "URL looks like a per-recipient token URL: never handed to a provider that fetches it live (GUARD-02)")
        if not hostile_evidence(entity, ctx):
            return (Status.SKIPPED, "not_applicable", "IPQualityScore URL reputation runs only for URLs tagged malicious/phishing/suspicious (P052 FC2)")
        return None

    # ---------------------------------------------------------------------------- results
    def _ip_result(self, res: ModuleResult, doc: Any) -> ModuleResult:
        rec = parse_ip(doc)
        if rec is None or rec["fraud_score"] is None:
            return res.mark(Status.ERROR, "unexpected IPQualityScore answer (no fraud score): could not verify", reason_code="error")
        res.raw = {"ipqs_ip": rec}
        res.attr("ipqs_ip", rec)
        score = rec["fraud_score"]
        anon = [t for t in ("vpn", "proxy", "tor") if rec.get(t)]
        res.attr("reputation", {"ipqualityscore": f"{'suspicious' if rec['vote'] == 'suspicious' else 'no signal'} (fraud score {score}/100)"})
        if rec["vote"] == "suspicious":
            res.finding(
                "IPQualityScore fraud score high (one vote)",
                "low",
                f"IPQS fraud score {score}/100{', recent abuse' if rec.get('recent_abuse') else ''}"
                f"{' (provider flags: ' + ', '.join(anon) + ')' if anon else ''}. One provider vote: never 'malicious' on its own.",
                confidence="possible",
                criterion=f"IPQS fraud_score >= {SUSPICIOUS_SCORE} (IPQS guidance 'suspicious'); one vote, never 'malicious' alone (P052 FC6)",
                data={"fraud_score": score, "recent_abuse": rec.get("recent_abuse"), "abuse_velocity": rec.get("abuse_velocity")},
                tags=["suspicious", *anon],
                source=SRC_IP,
            )
        else:
            res.finding(
                "IPQualityScore fraud score",
                "info",
                f"IPQS fraud score {score}/100{' (provider flags: ' + ', '.join(anon) + ')' if anon else ''}",
                confidence="possible",
                data={"fraud_score": score},
                tags=["context_only", *anon],
                source=SRC_IP,
            )
        return res

    def _url_result(self, res: ModuleResult, doc: Any) -> ModuleResult:
        rec = parse_url(doc)
        if rec is None or (rec["risk_score"] is None and not rec["flags"]):
            return res.mark(Status.ERROR, "unexpected IPQualityScore URL answer (no risk score): could not verify", reason_code="error")
        res.raw = {"ipqs_url": rec}
        res.attr("ipqs_url", rec)
        score = rec["risk_score"]
        res.attr("reputation", {"ipqualityscore": f"{'suspicious' if rec['vote'] == 'suspicious' else 'no signal'} (risk score {score if score is not None else '?'}/100)"})
        if rec["vote"] == "suspicious":
            flags = rec["flags"]
            res.finding(
                "IPQualityScore flags the URL (one vote)",
                "low",
                f"IPQS URL risk {score if score is not None else '?'}/100{' [' + ', '.join(flags) + ']' if flags else ''}"
                f"{', category ' + rec['category'] if rec.get('category') else ''}. One provider vote: never 'malicious' on its own.",
                confidence="possible",
                criterion="IPQS URL scanner flag (phishing/malware/unsafe/suspicious) or risk_score >= 75; one vote, never 'malicious' alone (P052 FC6)",
                data={"risk_score": score, "flags": flags, "category": rec.get("category")},
                tags=["suspicious"],
                source=SRC_URL,
            )
        else:
            res.finding("IPQualityScore URL risk", "info", f"IPQS URL risk {score}/100", confidence="possible",
                        data={"risk_score": score}, tags=["context_only"], source=SRC_URL)
        return res
