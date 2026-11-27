"""GreyNoise Community API: mass-scanner noise, RIOT (known business services) and classification of an IP.

Batch p2-G02-3, proposal P148 (council final conditions):

* c1-c2 - ``terms='noncommercial'``: the free community tier (GreyNoise EULA s.2.3, 'non-commercial
  purposes') is off under the corporate profile until licence-cleared (the policy gate skips it with
  reason_code 'licence' until a licence_allow entry for ``greynoise.community`` - internal defence, no
  resale or redistribution, after GreyNoise's written confirmation - or a paid plan recorded as
  ``key_plans.greynoise = 'business'``). ``default_enabled`` stays the council's candidate flag.
* c3 - key-first: the registered key ``greynoise`` travels in the ``key`` header whenever it is
  configured (never in the URL). The keyless plan answers ``rate_limit '25-W'`` (25 lookups per week per
  egress IP; ~50/week with a free key): P334 quota blocks have no weekly window yet, so the interim budget
  is ``daily_quota = 3``; analyst-typed seeds at depth 0 only (``run_on='seeds'`` plus :meth:`applies`),
  never values extracted from pasted text, never pivots.
* c4 - HTTP 404 ``'IP not observed scanning the internet'`` is the declared meaningful absence
  (``absent_statuses={404}``), worded 'not observed scanning by GreyNoise' (info), never 'benign'.
  HTTP 429 is RATE_LIMITED ('could not verify'), with the free-key hint once per scan (the quota book
  backs the provider off for the rest of the run after the first 429, so later lookups never reach the
  network or repeat the hint); never 'benign'.
* c5 - ``riot=true``: finding tagged ``known_good`` naming the service (e.g. 'Google Public DNS') and
  attribute ``allowlisted``; it dampens only this IP (the correlation rule ``g02_scanner_intel_dampening``
  caps blocklist-derived findings on the IP at LOW), never URLs or domains hosted on it.
* c6 - ``noise=true`` + benign: 'known benign scanner (<name>)' (tag ``benign_scanner``, attribute
  ``scanner_classification='benign'``: blocklist-derived scores on the IP capped at LOW);
  ``noise=true`` + malicious: 'opportunistic mass scanner' at MEDIUM, explained as 'scans the whole
  internet, not targeting you specifically' (tag ``scanner``).
* c7 - the riot/benign dampening goes through named suppression rules (``greynoise_riot``,
  ``greynoise_benign_scanner`` in ``v3lum/correlations/p2_g02_3.py``) that lower scores and never delete
  other sources' findings. viz.greynoise.io/ips/{ip} is the manual link.
* c8 - tests use the recorded community 404 fixture and the two recorded 429 fixtures.

The answer is untrusted data: anything that is not the documented JSON object is 'could not verify'
(ERROR), never an absence.
"""

from __future__ import annotations

import json
import re
from datetime import datetime, timezone
from typing import Any

from v3lum.core.entities import Entity
from v3lum.core.entities import EntityType as T
from v3lum.core.models import ModuleResult, Opsec
from v3lum.core.module import Module, register
from v3lum.core.noise import is_public_ip

SOURCE = "greynoise.community"
API = "https://api.greynoise.io/v3/community/{ip}"
VIZ = "https://viz.greynoise.io/ips/{ip}"
KEY_NAME = "greynoise"
KEY_HEADER = "key"
ATTRIBUTION = "GreyNoise"
NOT_OBSERVED = "not observed scanning by GreyNoise"
SCANNER_EXPLANATION = "scans the whole internet, not targeting you specifically"
CLASSIFICATIONS = ("benign", "malicious", "suspicious", "unknown")
KEY_HINT = (
    "GreyNoise community quota for this egress is exhausted: could not verify (never read as benign). "
    "A team GreyNoise key raises the weekly quota (v3lum keys set greynoise); under the corporate "
    "profile it also needs a recorded licence decision."
)
KEYED_HINT = "GreyNoise refused further lookups for the configured key (weekly quota): could not verify (never read as benign)."
#: Rule ids of the named suppression rules applied by ``v3lum.correlations.p2_g02_3`` (P148 c7).
RULE_RIOT = "greynoise_riot"
RULE_BENIGN = "greynoise_benign_scanner"
_RATE_PERIODS = {"S": "second", "H": "hour", "D": "day", "W": "week", "M": "month", "Y": "year"}
_CTRL_RE = re.compile(r"[\x00-\x1f\x7f-\x9f​-‏‪-‮⁦-⁩]")
_DATE_RE = re.compile(r"^(\d{4})-(\d{2})-(\d{2})")


# --------------------------------------------------------------------------------------
# pure helpers (stdlib only; ported from the batch prep parsers)
# --------------------------------------------------------------------------------------


def clean_text(value: Any, limit: int = 200) -> str | None:
    """Display-safe single-line text (control and bidi characters removed, whitespace collapsed)."""
    if not isinstance(value, str):
        return None
    text = " ".join(_CTRL_RE.sub(" ", value).split())
    return text[:limit] or None


def _as_bool(value: Any) -> bool | None:
    if isinstance(value, bool):
        return value
    if isinstance(value, str) and value.strip().lower() in ("true", "false"):
        return value.strip().lower() == "true"
    return None


def _iso_date(value: Any) -> str | None:
    if not isinstance(value, str):
        return None
    m = _DATE_RE.match(value.strip())
    if not m:
        return None
    try:
        return datetime(int(m.group(1)), int(m.group(2)), int(m.group(3))).strftime("%Y-%m-%d")
    except ValueError:
        return None


def load_json(content: bytes | str | None) -> Any:
    """Parsed JSON or None for empty, HTML, XML or malformed bodies."""
    if content is None:
        return None
    text = content.decode("utf-8", errors="replace") if isinstance(content, (bytes, bytearray)) else str(content)
    text = text.lstrip("﻿").strip()
    if not text or text.startswith("<"):
        return None
    try:
        return json.loads(text)
    except (ValueError, RecursionError):
        return None


def parse_rate_limit_window(value: Any) -> dict[str, Any] | None:
    """'25-W' -> {'count': 25, 'period': 'week', 'raw': '25-W'} (P148 c3 weekly window); else None."""
    if not isinstance(value, str):
        return None
    m = re.fullmatch(r"\s*(\d{1,7})\s*-\s*([A-Za-z])\s*", value)
    if not m or m.group(2).upper() not in _RATE_PERIODS:
        return None
    return {"count": int(m.group(1)), "period": _RATE_PERIODS[m.group(2).upper()], "raw": f"{m.group(1)}-{m.group(2).upper()}"}


def quota_facts(headers: Any, body: Any) -> dict[str, Any]:
    """Quota facts of an answer: X-Ratelimit-Limit/-Remaining/-Reset (epoch seconds) and the 429 body's
    plan and rate_limit window. Missing values are None."""
    hdrs = {str(k).lower(): v for k, v in (headers or {}).items()} if hasattr(headers, "items") else {}

    def _int(value: Any) -> int | None:
        text = str(value).strip() if value is not None else ""
        return int(text) if re.fullmatch(r"\d{1,12}", text) else None

    reset = _int(hdrs.get("x-ratelimit-reset"))
    reset_at = None
    if reset is not None and 0 < reset < 10**11:
        reset_at = datetime.fromtimestamp(reset, tz=timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    data = body if isinstance(body, dict) else {}
    return {
        "limit": _int(hdrs.get("x-ratelimit-limit")),
        "remaining": _int(hdrs.get("x-ratelimit-remaining")),
        "reset_at": reset_at,
        "plan": clean_text(data.get("plan"), 40),
        "window": parse_rate_limit_window(data.get("rate_limit")),
    }


def rate_limit_reason(facts: dict[str, Any], *, keyed: bool) -> str:
    parts = []
    window = facts.get("window")
    if window:
        parts.append(f"{window['count']} per {window['period']} {'for the key' if keyed else 'per egress IP'}")
    if facts.get("reset_at"):
        parts.append(f"resets {facts['reset_at']}")
    head = "GreyNoise rate limit (HTTP 429)" + (f" ({', '.join(parts)})" if parts else "")
    return f"{head}. {KEYED_HINT if keyed else KEY_HINT}"


def not_observed(data: Any) -> bool:
    """The documented 404 body: 'IP not observed scanning the internet.' (older wording '... or contained
    in RIOT data set.'), noise and riot false."""
    if not isinstance(data, dict):
        return False
    message = data.get("message")
    if isinstance(message, str) and "not observed" in message.lower():
        return _as_bool(data.get("noise")) is not True and _as_bool(data.get("riot")) is not True
    return False


def parse_community(data: Any) -> dict[str, Any] | None:
    """Normalise a 200 answer: {ip, noise, riot, classification, name, last_seen, link, message}; None
    when the body is not the documented object (no noise/riot flags)."""
    if not isinstance(data, dict):
        return None
    noise, riot = _as_bool(data.get("noise")), _as_bool(data.get("riot"))
    if noise is None and riot is None:
        return None
    cls = data.get("classification")
    classification = None
    if isinstance(cls, str) and cls.strip():
        low = cls.strip().lower()
        classification = low if low in CLASSIFICATIONS else "unknown"
    name = clean_text(data.get("name"), 120)
    link = data.get("link")
    return {
        "ip": clean_text(data.get("ip"), 45),
        "noise": bool(noise),
        "riot": bool(riot),
        "classification": classification,
        "name": None if (name or "").lower() in ("", "unknown") else name,
        "last_seen": _iso_date(data.get("last_seen")),
        "link": link if isinstance(link, str) and link.startswith("https://viz.greynoise.io/") and len(link) < 300 else None,
        "message": clean_text(data.get("message"), 120),
    }


def state_of(parsed: dict[str, Any]) -> str:
    """'mass_scanner' | 'riot' | 'benign_scanner' | 'scanner_suspicious' | 'scanner_unclassified' | 'no_flags'."""
    cls = parsed.get("classification")
    if parsed.get("noise") and cls == "malicious":
        return "mass_scanner"  # never suppressed, even when riot is also set (P148 c6)
    if parsed.get("riot"):
        return "riot"
    if parsed.get("noise") and cls == "benign":
        return "benign_scanner"
    if parsed.get("noise") and cls == "suspicious":
        return "scanner_suspicious"
    if parsed.get("noise"):
        return "scanner_unclassified"
    return "no_flags"


# --------------------------------------------------------------------------------------
# module
# --------------------------------------------------------------------------------------


@register
class GreynoiseCommunity(Module):
    name = "greynoise_community"
    title = "GreyNoise Community"
    description = (
        "Whether an IP is internet background noise (mass scanner, benign or malicious) or a known business "
        "service (RIOT) according to the GreyNoise Community API."
    )
    category = "threat_intel_ioc"
    accepts = {T.IPV4}
    produces = frozenset()
    run_on = "seeds"
    terms = "noncommercial"
    opsec = Opsec.PASSIVE
    disclosure = "third_party"
    provider = "greynoise"
    sources = (SOURCE,)
    hosts = ("api.greynoise.io",)
    access_model = "free_noauth_limited"
    optional_keys = (KEY_NAME,)
    absent_statuses = frozenset({404})
    error_markers = (
        {"id": "greynoise_rate_limit_in_200", "statuses": [200], "regex": "You have hit your current rate limit",
         "maps_to": "rate_limited", "reason": "GreyNoise: community rate limit message in an HTTP 200 answer (could not verify)"},
    )
    max_requests = 1
    expected_latency = 0.6
    timeout = 10.0
    min_interval = 2.0
    daily_quota = 3
    cache_ttl = 86400
    manual_link = "scanner_intel_g02_3:greynoise_viz_ip"
    default_enabled = True
    tags = {"reputation"}
    reference = "https://docs.greynoise.io/reference/get_v3-community-ip"
    notice = (
        "GreyNoise community terms are noncommercial (EULA s.2.3): off under the corporate profile until "
        "licence-cleared (a licence_allow entry for greynoise.community - internal defence, no resale or "
        "redistribution - or a paid plan recorded as key_plans.greynoise=business). Keyless quota: 25 lookups "
        "per week per egress IP (a corporate NAT exhausts it quickly); interim budget 3 per day, analyst-typed "
        "seeds only. 'Not observed' never means benign."
    )

    def applies(self, entity: Entity, ctx: Any) -> bool:
        # P148 c3: analyst-typed seeds at depth 0 only (never pivots or values extracted from pasted text)
        if not is_public_ip(entity.value):
            return False
        if not getattr(ctx, "is_seed", True) or int(getattr(ctx, "depth", 0) or 0) != 0 or tuple(getattr(ctx, "provenance", ()) or ()):
            return False
        unconfirmed = getattr(getattr(ctx, "options", None), "unconfirmed_seeds", None) or ()
        return entity.key not in unconfirmed

    def run(self, entity: Entity, ctx: Any) -> ModuleResult:
        res = self.result(entity)
        ip = entity.value
        viz = VIZ.format(ip=ip)
        key = str(ctx.key(KEY_NAME) or "").strip()
        headers = {"Accept": "application/json"}
        if key:
            headers[KEY_HEADER] = key  # c3: key-first, header only (never in the URL)
        resp = ctx.http.get(API.format(ip=ip), headers=headers, source=SOURCE)
        classification = getattr(resp, "classification", None)
        if resp.status == 429 or getattr(classification, "status", "") == "rate_limited":
            # c4: 'could not verify', never benign; the hint is logged once (the quota book backs the provider
            # off for the rest of the run, so later seeds never reach the network)
            facts = quota_facts(resp.headers, load_json(resp.content))
            reason = rate_limit_reason(facts, keyed=bool(key))
            ctx.log(KEYED_HINT if key else KEY_HINT, "warning")
            res.raw = {"status": resp.status, "quota": facts}
            res.link("GreyNoise Visualizer (manual)", viz)
            return res.mark("rate_limited", reason)
        data = load_json(resp.content)
        if resp.status == 404:
            if not_observed(data):
                res.raw = {"status": 404, "message": clean_text(data.get("message"), 120)}
                res.attr("greynoise", {"state": "not_observed", "noise": False, "riot": False})
                res.finding(
                    "Not observed scanning by GreyNoise",
                    "info",
                    "GreyNoise has no record of this IP scanning the internet ('IP not observed scanning the internet'). "
                    "This is not a benign verdict: the IP may still be malicious in other ways.",
                    data={"state": "not_observed"},
                    references=[viz],
                    source=SOURCE,
                )
                res.link("GreyNoise Visualizer", viz)
                return res.mark("empty")  # the documented absence (c4)
            ctx.http.check(resp)  # challenge pages raise first
            return res.mark("error", "unexpected GreyNoise HTTP 404 answer (not the documented 'not observed' body): could not verify")
        ctx.http.check(resp)  # 401/403/5xx, challenges and error-in-200 markers raise (rule 5)
        parsed = parse_community(data)
        if parsed is None:
            return res.mark("error", "unexpected GreyNoise answer (no noise/riot flags): could not verify")
        return self._report(res, parsed, viz)

    def _report(self, res: ModuleResult, parsed: dict[str, Any], viz: str) -> ModuleResult:
        state = state_of(parsed)
        name = parsed.get("name")
        cls = parsed.get("classification")
        last = parsed.get("last_seen")
        res.raw = {"status": 200, "answer": {k: v for k, v in parsed.items() if k != "message"}}
        res.attr("greynoise", {
            "state": "riot" if state == "riot" else ("noise" if parsed.get("noise") else "no_flags"),
            "noise": parsed["noise"], "riot": parsed["riot"], "classification": cls, "name": name,
            "last_seen": last, "link": parsed.get("link"),
        })
        res.attr("data_attribution", ATTRIBUTION)
        if parsed.get("noise"):
            res.attr("is_scanner", True)
            res.attr("scanner_classification", cls or "unknown")
        if last:
            res.attr("last_seen", last)
        refs = [viz]
        if state == "mass_scanner":
            res.finding(
                "Opportunistic mass scanner (GreyNoise)",
                "medium",
                f"GreyNoise classifies this IP as a malicious internet scanner{f' ({name})' if name else ''}: it "
                f"{SCANNER_EXPLANATION}. Last seen {last or 'unknown'}."
                + (" GreyNoise also lists it in RIOT (known business service): conflicting signals, no dampening applied." if parsed.get("riot") else ""),
                confidence="probable",
                criterion="GreyNoise noise=true with classification 'malicious' (mass scanning observed by GreyNoise sensors; opportunistic, not targeted)",
                data={"state": state, "classification": cls, "name": name, "riot": parsed.get("riot")},
                tags=["scanner"],
                references=refs,
                source=SOURCE,
                observed_last=last,
            )
        elif state == "riot":
            label = name or "unnamed service"
            res.attr("allowlisted", [f"GreyNoise RIOT: {label} (common business service)"])
            res.finding(
                f"Known good service ({label})",
                "info",
                f"GreyNoise RIOT lists this IP as a known business service ({label}). This dampens reputation of this IP "
                "only (blocklist-derived findings on it are capped at LOW by rule greynoise_riot); URLs and domains "
                "hosted on it keep their own verdicts.",
                confidence="probable",
                criterion=f"GreyNoise riot=true for this IP ({label})",
                data={"state": state, "service": name, "classification": cls, "suppression_rule": RULE_RIOT, "scope": "ip"},
                tags=["known_good"],
                references=refs,
                source=SOURCE,
                observed_last=last,
            )
        elif state == "benign_scanner":
            label = name or "unnamed"
            res.finding(
                f"Known benign scanner ({label})",
                "info",
                f"GreyNoise classifies this IP as a benign internet scanner ({label}): research or search-engine scanning. "
                "Blocklist-derived scores on this IP are capped at LOW (rule greynoise_benign_scanner); nothing is deleted.",
                confidence="probable",
                criterion=f"GreyNoise noise=true with classification 'benign' ({label})",
                data={"state": state, "name": name, "classification": cls, "suppression_rule": RULE_BENIGN, "scope": "ip"},
                tags=["benign_scanner"],
                references=refs,
                source=SOURCE,
                observed_last=last,
            )
        elif state in ("scanner_suspicious", "scanner_unclassified"):
            suspicious = state == "scanner_suspicious"
            res.finding(
                "Internet-wide scanner (GreyNoise)",
                "low" if suspicious else "info",
                f"GreyNoise sees this IP scanning the internet (classification: {cls or 'unknown'}{f', {name}' if name else ''}): it "
                f"{SCANNER_EXPLANATION}. Last seen {last or 'unknown'}.",
                confidence="possible",
                criterion=f"GreyNoise noise=true with classification '{cls or 'unknown'}' (not benign, not malicious)",
                data={"state": state, "classification": cls, "name": name},
                tags=["scanner"],
                references=refs,
                source=SOURCE,
                observed_last=last,
            )
        else:  # no_flags: answered, neither noise nor RIOT
            res.finding(
                "No GreyNoise noise or RIOT classification",
                "info",
                "GreyNoise answered without noise or RIOT flags for this IP. This is not a benign verdict.",
                data={"state": "no_flags"},
                references=refs,
                source=SOURCE,
            )
            res.link("GreyNoise Visualizer", viz)
            return res.mark("empty")
        res.link("GreyNoise Visualizer", viz)
        return res
