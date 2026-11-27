"""stopforumspam: StopForumSpam forum-spam reports of an IP, an e-mail (as its MD5) or a username.

Batch p3-G07-1, proposal P164 (council final conditions):

* c1 - StopForumSpam only (BotScout is not in this build): ``GET https://api.stopforumspam.org/api``
  with ``json`` and one of ``ip``, ``emailhash`` (MD5 of the normalised, lower-cased address: the
  plaintext address is never sent, :func:`email_hash`) or ``username`` (only in registration-abuse
  cases: setting ``stopforumspam_usernames`` or a recorded purpose naming registration abuse).
  :func:`request_allowed` refuses the plaintext ``email`` parameter, submission fields and every
  other host or path (unit-tested).
* c2 - terms 'noncommercial' (internal use only, no resale): off under the corporate profile until
  legal records a licence_allow entry (registry source ``stopforumspam.api``; tier community); the
  manual link is the StopForumSpam IP check page.
* c3 - ``success: 0`` bodies -> ERROR (module markers; rate words -> RATE_LIMITED; HTTP 503 without
  an error body = query rate exceeded -> RATE_LIMITED); a per-field error inside ``success: 1`` ->
  ERROR, never 'not listed'. Findings only when lastseen <= 90 days and confidence >= 25: severity
  LOW, wording 'reported as forum spammer N times, last <date>', tag spam; frequency < 3 -> info;
  IP hits in cloud/hosting/CDN ranges (core noise lists; mobile/CGNAT tags of P034/P035 are not
  visible to a module run: backlog) -> info. frequency 255 is a blacklist rule or a Tor exit, never
  255 reports -> info with its own wording.
* c4 - never counted in CR27 consensus (tag ``spam`` is not a vote tag; ``data.counts_in_consensus``
  False), capped at LOW; never run on org-profile e-mail addresses (SKIPPED own_asset); e-mail hashes
  and usernames reach the provider by default only after legal records ``personal_data_review`` on
  the provider (null today: the policy gate sends PERSONAL_TYPES only when the module is selected
  explicitly with a recorded purpose, A3 BR8). Daily budget: the provider's P334 block (5,000/day).

The answer is untrusted data: anything that is not the documented JSON object is 'could not verify'
(ERROR), never an absence.
"""

from __future__ import annotations

import hashlib
import ipaddress
import json
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

SOURCE = "stopforumspam.api"
HOST = "api.stopforumspam.org"
API = "https://api.stopforumspam.org/api"
WEB_IP = "https://www.stopforumspam.com/ipcheck/{ip}"
USERNAME_SETTING = "stopforumspam_usernames"
CACHE_TTL = 86400
ALLOWED_PARAMS = frozenset({"ip", "emailhash", "username", "json", "unix", "confidence"})
FINDING_MAX_AGE_DAYS = 90
MIN_CONFIDENCE = 25.0
MIN_FREQUENCY = 3
WILDCARD_FREQUENCY = 255
#: noise kinds that make an IP hit info only (shared infrastructure, c3)
INFO_ONLY_NOISE = frozenset({"cloud", "cdn", "hosting", "datacenter"})
_PURPOSE_RE = re.compile(r"(?i)registration|sign[- ]?up|account creation|cadastro|fake account|bot account|spam registration")
_EMAIL_RE = re.compile(r"^[^@\s]{1,64}@[^@\s]{1,253}$")
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


def as_float(value: Any) -> float | None:
    if value is None or isinstance(value, bool):
        return None
    numeric = isinstance(value, (int, float)) or (isinstance(value, str) and re.fullmatch(r"\s*-?\d{1,12}(\.\d{1,12})?\s*", value))
    if not numeric:
        return None
    out = float(value)
    return out if out == out and out not in (float("inf"), float("-inf")) else None


def parse_ts(value: Any) -> datetime | None:
    """'YYYY-MM-DD HH:MM:SS' (UTC: the &unix form gives the same instant) or epoch seconds."""
    if value is None or isinstance(value, bool):
        return None
    if isinstance(value, (int, float)):
        return datetime.fromtimestamp(float(value), timezone.utc) if 0 < value < 32503680000 else None
    text = clean_text(value, 64)
    if not text:
        return None
    if re.fullmatch(r"\d{9,11}", text):
        return parse_ts(int(text))
    try:
        parsed = datetime.fromisoformat(text.replace("Z", "+00:00"))
    except ValueError:
        return None
    return (parsed if parsed.tzinfo else parsed.replace(tzinfo=timezone.utc)).astimezone(timezone.utc)


def iso(value: Any) -> str | None:
    parsed = parse_ts(value)
    return parsed.strftime("%Y-%m-%dT%H:%M:%SZ") if parsed else None


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


def email_hash(email: Any) -> str | None:
    """c1: MD5 of the trimmed, lower-cased address with the domain in IDNA form; None when it is not an
    address. StopForumSpam skips its own normalisation for emailhash (gmail dot/plus variants are false
    negatives: documented, not 'not listed')."""
    text = email.strip().lower() if isinstance(email, str) else ""
    if not _EMAIL_RE.match(text):
        return None
    local, _, domain = text.rpartition("@")
    try:
        domain = domain.rstrip(".").encode("idna").decode("ascii")
    except UnicodeError:
        return None
    if not local or "." not in domain:
        return None
    return hashlib.md5(f"{local}@{domain}".encode()).hexdigest()  # noqa: S324 - the provider's lookup key, not a security hash


def query_url(field: str, value: str) -> str:
    """c1: GET /api?<field>=<value>&json for ip / emailhash / username (ValueError otherwise)."""
    if field == "ip":
        value = str(ipaddress.ip_address(value.strip()))
    elif field == "emailhash":
        if not re.fullmatch(r"[0-9a-f]{32}", value or ""):
            raise ValueError("stopforumspam: emailhash must be an MD5 hex digest")
    elif field == "username":
        value = clean_text(value, 255) or ""
        if not value:
            raise ValueError("stopforumspam: empty username")
    else:
        raise ValueError(f"stopforumspam: unsupported field {field!r}")
    return API + "?" + urlencode({field: value}) + "&json"


def request_allowed(method: str, url: str) -> bool:
    """c1 guard (unit-tested): GET https://api.stopforumspam.org/api with json and only ip / emailhash
    (an MD5) / username (+ unix, confidence). The plaintext e-mail parameter, submission fields, keys
    and every other host or path are refused."""
    if (method or "").upper() != "GET" or not isinstance(url, str):
        return False
    try:
        parts = urlsplit(url)
        params = parse_qs(parts.query, keep_blank_values=True)
        port = parts.port
    except ValueError:
        return False
    if parts.scheme != "https" or parts.hostname != HOST or port not in (None, 443) or parts.path != "/api" or parts.fragment:
        return False
    if parts.username or parts.password:
        return False
    keys = {k.rstrip("[]") for k in params}
    if not keys <= ALLOWED_PARAMS or "json" not in keys or not keys & {"ip", "emailhash", "username"}:
        return False
    return all(re.fullmatch(r"[0-9a-f]{32}", v) for v in params.get("emailhash", []))


def error_text(value: Any) -> str | None:
    """'error' is a string (documented) or a list of {message} (live 2026-11-26)."""
    if isinstance(value, list):
        msgs = [clean_text(x.get("message"), 120) if isinstance(x, dict) else clean_text(x, 120) for x in value]
        return "; ".join(m for m in msgs if m) or None
    return clean_text(value, 200)


def parse(obj: Any) -> dict[str, Any] | None:
    """SFS JSON -> {success, error, fields: {ip|emailhash|email|username: entry}}; entry = {appears,
    frequency, lastseen, confidence, asn, country, torexit, wildcard, error}. A per-field error inside a
    success 1 body is kept in that field's 'error' (never read as 'not listed'). The echoed value is not
    kept."""
    if not isinstance(obj, dict):
        return None
    out: dict[str, Any] = {"success": as_int(obj.get("success")) == 1, "error": error_text(obj.get("error")), "fields": {}}
    for name in ("ip", "emailhash", "email", "username"):
        entry = obj.get(name)
        if not isinstance(entry, dict):
            continue
        freq = as_int(entry.get("frequency"))
        country = (clean_text(entry.get("country"), 5) or "").upper()
        out["fields"][name] = {
            "appears": bool(as_int(entry.get("appears"))),
            "frequency": freq,
            "lastseen": iso(entry.get("lastseen")),
            "confidence": as_float(entry.get("confidence")),
            "asn": as_int(entry.get("asn")),
            "country": country if re.fullmatch(r"[A-Z]{2}", country) else None,
            "torexit": bool(as_int(entry.get("torexit"))),
            "wildcard": freq == WILDCARD_FREQUENCY,
            "error": clean_text(entry.get("error"), 120),
        }
    return out


def field_verdict(entry: dict[str, Any], field: str, now: datetime, info_reasons: list[str] | None = None) -> dict[str, Any]:
    """c3/c4 for one queried field: finding only when it appears, lastseen <= 90 days and confidence >= 25
    (LOW, tag spam); frequency < 3, older or low-confidence reports and shared-infrastructure IPs -> info;
    wildcard answers (frequency 255) -> info with their own wording."""
    last = (entry.get("lastseen") or "")[:10] or "unknown date"
    if entry.get("wildcard"):
        what = "a Tor exit node" if field == "ip" and entry.get("torexit") else "a StopForumSpam blacklist rule"
        return {"severity": "info", "wording": f"matches {what} (frequency 255 is a list rule, not individual reports), checked {last}",
                "reasons": ["frequency 255: blacklist/wildcard rule"]}
    freq = entry.get("frequency") or 0
    wording = f"reported as forum spammer {freq} times, last {last}"
    reasons = list(info_reasons or [])
    seen = parse_ts(entry.get("lastseen"))
    age = (now - seen).total_seconds() / 86400 if seen else None
    confidence = entry.get("confidence") or 0.0
    if age is None or age > FINDING_MAX_AGE_DAYS:
        reasons.append(f"last report older than {FINDING_MAX_AGE_DAYS} days")
    if confidence < MIN_CONFIDENCE:
        reasons.append(f"confidence {confidence:g} < {MIN_CONFIDENCE:g}")
    if freq < MIN_FREQUENCY:
        reasons.append(f"frequency {freq} < {MIN_FREQUENCY}")
    return {"severity": "info" if reasons else "low", "wording": wording, "reasons": reasons}


def public_ip(value: str) -> bool:
    """Private, reserved and documentation addresses are never sent (patched in tests)."""
    return noise.is_public_ip(value)


# --------------------------------------------------------------------------------------
# the module
# --------------------------------------------------------------------------------------


@register
class StopForumSpam(Module):
    name = "stopforumspam"
    title = "StopForumSpam reputation"
    description = (
        "Forum-spam report history (appearances, frequency, last seen, confidence) of an IP, an e-mail address "
        "(sent only as its MD5) or a username from the StopForumSpam API; a weak signal, never consensus."
    )
    category = "threat_intel_ioc"
    accepts = {T.IPV4, T.IPV6, T.EMAIL, T.USERNAME}
    produces = frozenset()
    terms = "noncommercial"
    opsec = Opsec.PASSIVE
    disclosure = "third_party"
    provider = "stopforumspam"
    sources = (SOURCE,)
    hosts = (HOST,)
    access_model = "free_noauth_limited"
    error_markers = (
        {"id": "stopforumspam_rate", "statuses": [200, 503], "json_path": "error", "regex": "(?i)rate|limit|exceed|too many",
         "maps_to": "rate_limited", "reason_code": "rate_limited",
         "reason": "StopForumSpam: query rate exceeded (could not verify now)"},
        {"id": "stopforumspam_success_0", "statuses": [200, 503], "json_path": "success", "equals": 0,
         "maps_to": "error", "reason_code": "error",
         "reason": "StopForumSpam: success 0 (request not understood or refused): could not verify"},
    )
    max_requests = 1
    expected_latency = 0.5
    timeout = 20.0
    min_interval = 1.0
    cache_ttl = CACHE_TTL
    manual_link = "threat_intel_g07_p3:stopforumspam_ip"
    default_enabled = True
    tags = {"reputation"}
    reference = "https://www.stopforumspam.com/usage"
    settings = {
        USERNAME_SETTING: SettingSpec(
            False,
            "StopForumSpam: also check usernames (registration-abuse cases only, P164 cond 1); a recorded purpose naming "
            "registration abuse enables it for that case",
        ),
    }
    notice = (
        "StopForumSpam terms are non-commercial (internal use only, no resale): off under the corporate profile until legal "
        "records a licence_allow entry. E-mail addresses are sent only as their MD5 hash, never in clear; usernames only in "
        "registration-abuse cases; org-profile addresses are never checked. A weak signal: capped at low, never consensus."
    )

    def applies(self, entity: Entity, ctx: Any) -> bool:
        if entity.type in (T.IPV4, T.IPV6):
            return public_ip(entity.value)  # private/reserved addresses are never sent
        return True

    def _field(self, entity: Entity, ctx: Any, res: ModuleResult) -> tuple[str, str] | None:
        """(field, value) to query, or None with ``res`` marked."""
        if entity.type in (T.IPV4, T.IPV6):
            return "ip", entity.value
        if entity.type is T.EMAIL:
            try:
                own = ctx.org.owns(entity)
            except Exception:  # noqa: BLE001 - an unreadable profile never blocks the skip below
                own = None
            if own is not None and getattr(own, "own", False):
                res.mark(Status.SKIPPED, "org-profile address: never sent to StopForumSpam (P164 cond 4)", reason_code="own_asset")
                return None
            digest = email_hash(entity.value)
            if digest is None:
                res.mark(Status.SKIPPED, "not an e-mail address StopForumSpam can hash", reason_code="not_applicable")
                return None
            return "emailhash", digest
        enabled = bool(ctx.setting(USERNAME_SETTING, False)) or bool(_PURPOSE_RE.search(str(getattr(ctx, "purpose", "") or "")))
        if not enabled:
            res.mark(Status.SKIPPED, "usernames are checked only in registration-abuse cases (setting stopforumspam_usernames or a "
                     "recorded purpose naming registration abuse; P164 cond 1)", reason_code="not_applicable")
            return None
        return "username", entity.value

    def run(self, entity: Entity, ctx: Any) -> ModuleResult:
        res = self.result(entity)
        chosen = self._field(entity, ctx, res)
        if chosen is None:
            return res
        field, value = chosen
        try:
            url = query_url(field, value)
        except ValueError as exc:
            return res.mark(Status.SKIPPED, str(exc), reason_code="not_applicable")
        if not request_allowed("GET", url):  # c1: never the plaintext e-mail, never a submission
            return res.mark(Status.ERROR, "refused a non-allow-listed StopForumSpam request (module bug)", reason_code="error")
        resp = ctx.http.get(url, headers={"Accept": "application/json"}, source=SOURCE)
        if resp.status == 503 and resp.classification is None:  # usage page: 503 = query rate exceeded
            return res.mark(Status.RATE_LIMITED, "StopForumSpam: query rate exceeded (HTTP 503): could not verify now", reason_code="rate_limited")
        ctx.http.check(resp)  # success 0 / rate markers, 403 challenge, 429, 5xx
        obj, why = load_json(resp.content)
        if why:
            return res.mark(Status.ERROR, f"unexpected StopForumSpam answer ({why}): could not verify", reason_code="error")
        parsed = parse(obj)
        if parsed is None:
            return res.mark(Status.ERROR, "unexpected StopForumSpam answer (not a JSON object): could not verify", reason_code="error")
        if not parsed["success"]:
            return res.mark(Status.ERROR, f"StopForumSpam success 0 ({parsed['error'] or 'no detail'}): could not verify", reason_code="error")
        entry = parsed["fields"].get(field) or (parsed["fields"].get("email") if field == "emailhash" else None)
        if entry is None:
            return res.mark(Status.ERROR, f"StopForumSpam answer without the queried {field} field: could not verify", reason_code="error")
        if entry.get("error"):
            return res.mark(Status.ERROR, f"StopForumSpam could not check this {field} ({entry['error']}): could not verify", reason_code="error")
        return self._report(res, ctx, entity, field, entry)

    # ---- report (c3, c4) -------------------------------------------------------------------
    def _report(self, res: ModuleResult, ctx: Any, entity: Entity, field: str, entry: dict[str, Any]) -> ModuleResult:
        res.raw = {"status": 200, "field": field, "answer": entry}
        res.attr("stopforumspam", {field: entry})
        if field == "ip":
            # added only once a usable answer exists: a link before a failed request would turn a
            # rate-limited run into 'partial results' (the engine's manual_link covers failures)
            res.link("StopForumSpam IP check", WEB_IP.format(ip=entity.value))
            res.attr("country", entry.get("country"))
            if entry.get("asn") is not None:
                res.attr("asn", f"AS{entry['asn']}")
            if entry.get("torexit"):
                res.attr("is_tor_exit", True)  # context, never malicious
        if not entry.get("appears"):
            return res.mark(Status.EMPTY, f"no StopForumSpam reports for this {'e-mail hash' if field == 'emailhash' else field}")
        info_reasons: list[str] = []
        if field == "ip":
            try:
                kind = noise.noise_kind(entity)
            except Exception:  # noqa: BLE001 - list problems never block the facts
                kind = None
            if kind in INFO_ONLY_NOISE:
                info_reasons.append(f"shared {kind} address range")
        v = field_verdict(entry, field, ctx.now(), info_reasons)
        what = {"ip": "address", "emailhash": "e-mail address (MD5 hash)", "username": "username"}[field]
        description = f"This {what} is {v['wording']}" + (f" ({'; '.join(v['reasons'])})" if v["reasons"] else "") + \
            f"; confidence {entry.get('confidence') if entry.get('confidence') is not None else '?'}. Forum-spam reports are a weak signal."
        data = {"field": field, "appears": True, "frequency": entry.get("frequency"), "lastseen": entry.get("lastseen"),
                "confidence": entry.get("confidence"), "wildcard": entry.get("wildcard"), "counts_in_consensus": False}
        tags = ["spam"] if v["severity"] == "low" else ["spam", "info"]
        res.finding(
            "Reported forum spammer (StopForumSpam)", v["severity"], description, confidence="possible",
            criterion=(f"StopForumSpam: {v['wording']}; lastseen <= {FINDING_MAX_AGE_DAYS} days and confidence >= {MIN_CONFIDENCE:g} "
                       "(weak signal capped at low, never consensus)") if v["severity"] == "low" else f"StopForumSpam: {v['wording']} - info only",
            tags=tags, source=SOURCE, observed_last=entry.get("lastseen"), data=data,
            references=[WEB_IP.format(ip=entity.value)] if field == "ip" else [],
        )
        return res
