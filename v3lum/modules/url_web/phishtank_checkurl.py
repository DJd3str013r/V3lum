"""phishtank_checkurl: PhishTank single-URL verdict (P075, batch p3-G03-1).

Source ``phishtank.phishtank_checkurl`` (provider ``phishtank``, extended by
``phishtank__p3-G03-1.json``): ``POST https://checkurl.phishtank.com/checkurl/`` with the form fields
``url`` (the full URL, base64-encoded, then form-encoded by the HTTP layer), ``format=json`` and the
optional application key. The URL is looked up, never fetched.

Final conditions implemented (P075):

* c1 - POST checkurl with ``format=json`` and the base64 URL; the User-Agent is PhishTank's documented
  ``phishtank/<app>`` format, bound to checkurl.phishtank.com by the core provider profile
  (``providers.PROFILE_REQUIREMENTS``: ``phishtank/{app}``, the team's own application name, never
  another user's name or key); modules never set a UA themselves. The optional app key is the
  provider's key ``phishtank`` (``V3LUM_PHISHTANK_APP_KEY`` / ``V3LUM_KEY_PHISHTANK``).
* c2 - ``default_enabled = False`` until doctor records < 10 % blocked answers from the team network.
* c3 - 403 or a Cloudflare challenge is BLOCKED (one coverage line), never bypassed or retried with
  other headers; consecutive BLOCKED runs are counted in ``ctx.state``: after
  :data:`DEMOTE_AFTER` the source is link-only for automatic runs (SKIPPED ``demoted`` with the manual
  link; an analyst-typed seed still gets one attempt and a verdict resets the streak). The core health
  state demotes the module from the default set after the same 5 BLOCKED runs and doctor reports it.
* c4 - a finding only when ``verified`` AND ``valid`` are true (booleans live, ``'y'`` strings in the
  documented sample); ``in_database`` alone is not a verdict (example.com is ``in_database`` with
  ``verified=false``). Verifications older than :data:`HISTORICAL_DAYS` days are historical (LOW,
  tag ``historical``); PhishTank is one upstream family, one vote in consensus.
* c5 - only suspected-phishing URLs under triage: analyst-typed seeds or URLs a phishing feed listed
  (provenance relation ``listed_phishing_url``); org_profile URLs (own assets, suppliers) are never
  sent. The per-IP budget announced in ``X-Request-Limit`` / ``-Interval`` / ``-Count`` is kept in
  ``ctx.state``: a used-up window gives RATE_LIMITED without a request; HTTP 509 (documented
  over-limit answer) is RATE_LIMITED through the provider marker.
* c6 - tests use the recorded checkurl JSON answers (the in_database quirk included) and the
  recorded 403 challenge page.
"""

from __future__ import annotations

import base64
import json
import re
from datetime import datetime, timedelta, timezone
from typing import Any

from v3lum.core.entities import Entity
from v3lum.core.entities import EntityType as T
from v3lum.core.http import AuthRequired, Blocked, RateLimited
from v3lum.core.models import ModuleResult, Opsec, Status
from v3lum.core.module import Module, register

SOURCE = "phishtank.phishtank_checkurl"
KEY_NAME = "phishtank"
CHECKURL_URL = "https://checkurl.phishtank.com/checkurl/"
DETAIL_LINK = "https://www.phishtank.com/phish_detail.php?phish_id={phish_id}"
MANUAL_LINK = "https://phishtank.org/"  # 'Is it a phish?' is a POST form with a CSRF token: no deep link exists
CACHE_TTL = 21600  # 6 h: verdicts change when the community votes
HISTORICAL_DAYS = 30  # c4
DEMOTE_AFTER = 5  # c3 (A3/A9)
PHISHING_RELATIONS = frozenset({"listed_phishing_url"})  # c5: URLs a phishing feed listed
STATE_STREAK = "block_streak"
STATE_WINDOW = "request_window"
#: the per-IP window PhishTank announced live (X-Request-Limit 250, X-Request-Limit-Interval 300 Seconds, 2026-11-26)
DEFAULT_WINDOW = {"limit": 250, "interval_s": 300, "count": 0}


# ================================================================================================ helpers
def checkurl_form(url: str, app_key: str = "") -> dict[str, str]:
    """Form fields of one lookup (c1): the full URL base64-encoded, ``format=json``, optional app key."""
    if not isinstance(url, str) or not url.strip():
        raise ValueError("url required")
    form = {"url": base64.b64encode(url.strip().encode("utf-8")).decode("ascii"), "format": "json"}
    if app_key:
        form["app_key"] = app_key
    return form


def _truthy(v: Any) -> bool | None:
    if isinstance(v, bool):
        return v
    if isinstance(v, (int, float)):
        return bool(v)
    if isinstance(v, str):
        s = v.strip().lower()
        if s in ("y", "yes", "true", "1", "t"):
            return True
        if s in ("n", "no", "false", "0", "f", ""):
            return False
    return None


def _int(v: Any) -> int | None:
    if isinstance(v, bool):
        return None
    try:
        return int(v)
    except (TypeError, ValueError):
        return None


def parse_iso(value: Any) -> datetime | None:
    if not isinstance(value, str) or not value.strip():
        return None
    try:
        dt = datetime.fromisoformat(value.strip().replace("Z", "+00:00"))
    except ValueError:
        return None
    return dt if dt.tzinfo else dt.replace(tzinfo=timezone.utc)


def rate_headers(headers: Any) -> dict[str, int | None]:
    """X-Request-Limit / -Interval / -Count -> {limit, interval_s, count, remaining} (c5, P334)."""
    lower = {str(k).lower(): v for k, v in (headers or {}).items()} if isinstance(headers, dict) else {}

    def num(name: str) -> int | None:
        m = re.search(r"\d+", str(lower.get(name) or ""))
        return int(m.group(0)) if m else None

    limit, interval, count = num("x-request-limit"), num("x-request-limit-interval"), num("x-request-count")
    remaining = max(limit - count, 0) if limit is not None and count is not None else None
    return {"limit": limit, "interval_s": interval, "count": count, "remaining": remaining}


def parse_checkurl(raw: Any, now: datetime) -> dict[str, Any]:
    """checkurl JSON -> ``{status, reason, verdict...}`` (c4, c6).

    ``verified`` AND ``valid`` -> verdict ``phish`` (finding); verified and not valid -> ``not_phish``;
    otherwise ``unverified`` (in the database without a community verdict); ``in_database`` false ->
    ``not_in_database`` (EMPTY). ``meta.status`` 'error', XML (``format`` ignored), HTML or garbage ->
    ERROR 'could not verify', never EMPTY.
    """
    text = raw.decode("utf-8", "replace") if isinstance(raw, (bytes, bytearray)) else (raw if isinstance(raw, str) else "")
    text = text.lstrip("﻿")
    head = text.lstrip()[:200].lower()
    if head.startswith("<?xml") or head.startswith("<response"):
        return {"status": Status.ERROR, "reason": "PhishTank answered XML (format=json ignored): could not verify"}
    if head.startswith("<"):
        return {"status": Status.ERROR, "reason": "PhishTank answered HTML instead of JSON (schema changed): could not verify"}
    try:
        obj = json.loads(text) if not isinstance(raw, dict) else raw
    except (ValueError, RecursionError):
        return {"status": Status.ERROR, "reason": "PhishTank answer is not valid JSON: could not verify"}
    if not isinstance(obj, dict):
        return {"status": Status.ERROR, "reason": f"PhishTank answer has an unexpected shape ({type(obj).__name__}): could not verify"}
    meta = obj.get("meta") if isinstance(obj.get("meta"), dict) else {}
    if str(meta.get("status") or "").lower() == "error" or "errortext" in obj:
        return {"status": Status.ERROR, "reason": f"PhishTank error: {str(obj.get('errortext') or 'error')[:200]}: could not verify"}
    res = obj.get("results")
    if isinstance(res, list) and res and isinstance(res[0], dict):
        res = res[0]
    if not isinstance(res, dict) or "in_database" not in res:
        return {"status": Status.ERROR, "reason": "PhishTank answer without results.in_database (schema changed): could not verify"}
    in_db = _truthy(res.get("in_database"))
    if in_db is None:
        return {"status": Status.ERROR, "reason": "PhishTank answer with an unreadable in_database value: could not verify"}
    base = {"in_database": in_db, "consensus_votes": 1, "checked_at": now.strftime("%Y-%m-%dT%H:%M:%SZ")}
    if not in_db:
        return {"status": Status.EMPTY, "reason": "not in the PhishTank database (no verdict; not proof that the URL is safe)",
                "verdict": "not_in_database", **base}
    phish_id = _int(res.get("phish_id"))
    verified, valid = _truthy(res.get("verified")), _truthy(res.get("valid"))
    verified_at = res.get("verified_at") if isinstance(res.get("verified_at"), str) else None
    submitted_at = res.get("submitted_at") if isinstance(res.get("submitted_at"), str) else None
    ref = parse_iso(verified_at) or parse_iso(submitted_at)
    age_days = (now - ref).days if ref else None
    detail = res.get("phish_detail_page") if isinstance(res.get("phish_detail_page"), str) else None
    if not (detail and detail.startswith(("https://www.phishtank.com/", "https://phishtank.org/"))):
        detail = DETAIL_LINK.format(phish_id=phish_id) if phish_id else None
    if verified and valid:
        verdict = "phish"
    elif verified and valid is False:
        verdict = "not_phish"
    else:
        verdict = "unverified"
    historical = age_days is not None and age_days > HISTORICAL_DAYS
    return {"status": Status.OK, "reason": "", "verdict": verdict, "phish_id": phish_id, "detail_page": detail,
            "verified": verified, "valid": valid, "verified_at": verified_at, "submitted_at": submitted_at,
            "age_days": age_days, "historical": historical if verdict == "phish" else None, **base}


# ================================================================================================= module
@register
class PhishtankCheckurl(Module):
    name = "phishtank_checkurl"
    title = "PhishTank URL verdict (checkurl)"
    description = ("Community-verified phishing verdict for a URL under triage from PhishTank's checkurl API: a finding only when "
                   "the URL is verified and still valid; the URL is looked up, never fetched.")
    category = "url_web"
    accepts = {T.URL}
    produces = frozenset()
    tags = {"reputation"}
    reference = "https://phishtank.org/api_info.php"
    notice = ("Only analyst-typed URLs or URLs listed by a phishing feed are sent; org_profile URLs never are. PhishTank sits behind "
              "Cloudflare: a challenge is reported as blocked, never bypassed.")
    terms = "open"
    opsec = Opsec.PASSIVE
    disclosure = "third_party"
    hosts = ("checkurl.phishtank.com",)
    provider = "phishtank"
    sources = (SOURCE,)
    access_model = "free_noauth_limited"
    optional_keys = (KEY_NAME,)
    max_requests = 1
    expected_latency = 1.0
    timeout = 20.0
    min_interval = 1.5  # 250 requests per 300 s per IP (X-Request-Limit) with headroom
    cache_ttl = CACHE_TTL
    daily_quota = 500  # the phishtank provider has no quota block: per-module P334 fallback
    max_pivots = 0
    manual_link = MANUAL_LINK
    default_enabled = False  # c2

    # ------------------------------------------------------------------------------------- scope
    @staticmethod
    def _scope_problem(entity: Entity, ctx: Any) -> tuple[str, str] | None:
        """(reason_code, reason) when the URL must not be sent (c5), else None."""
        if not re.match(r"(?i)^https?://", entity.value):
            return "not_applicable", "PhishTank checks http(s) URLs only"
        org = getattr(ctx, "org", None)
        owned = org.owns(entity) if org is not None else None
        if getattr(owned, "own", False):
            return "own_asset", "org_profile URL: never sent to PhishTank (P075 cond 5)"
        if getattr(owned, "kind", "") == "supplier":
            return "policy", "supplier URL in the org profile: never sent to PhishTank (P075 cond 5)"
        provenance = tuple(getattr(ctx, "provenance", ()) or ())
        listed = bool(provenance) and len(provenance[-1]) > 1 and provenance[-1][1] in PHISHING_RELATIONS
        if not (getattr(ctx, "is_seed", False) or listed):
            return "not_applicable", "PhishTank checks only URLs under phishing triage (analyst-typed seeds or URLs listed by a phishing feed)"
        return None

    # ------------------------------------------------------------------------------------- state
    @staticmethod
    def _streak(ctx: Any) -> int:
        return _int(ctx.state.get(STATE_STREAK)) or 0

    @staticmethod
    def _window_used_up(ctx: Any, now: datetime) -> dict[str, Any] | None:
        win = ctx.state.get(STATE_WINDOW)
        if not isinstance(win, dict):
            return None
        limit, count, interval = _int(win.get("limit")), _int(win.get("count")), _int(win.get("interval_s"))
        since = parse_iso(win.get("at"))
        if None in (limit, count, interval) or since is None or now >= since + timedelta(seconds=interval or 0):
            return None
        return win if count >= limit else None  # type: ignore[operator]

    @staticmethod
    def _save_window(ctx: Any, limits: dict[str, Any], now: datetime, *, exhausted: bool = False) -> None:
        limit, interval, count = limits.get("limit"), limits.get("interval_s"), limits.get("count")
        if limit is None or interval is None:
            return
        if exhausted:
            count = max(int(count or 0), int(limit))
        ctx.state.set(STATE_WINDOW, {"limit": int(limit), "interval_s": int(interval), "count": int(count or 0),
                                     "at": now.strftime("%Y-%m-%dT%H:%M:%SZ")})

    # --------------------------------------------------------------------------------------- run
    def run(self, entity: Entity, ctx: Any) -> ModuleResult:
        res = self.result(entity)
        problem = self._scope_problem(entity, ctx)
        if problem:
            return res.mark(Status.SKIPPED, problem[1], reason_code=problem[0])
        now = ctx.now()
        streak = self._streak(ctx)
        if streak >= DEMOTE_AFTER and not ctx.is_seed:
            res.link("PhishTank (manual check: automation demoted after repeated blocks)", MANUAL_LINK)
            return res.mark(Status.SKIPPED, f"PhishTank demoted to link-only after {streak} consecutive blocked answers (P075 cond 3): "
                                            "check the URL manually or run it as an analyst-typed seed", reason_code="demoted")
        used_up = self._window_used_up(ctx, now)
        if used_up:
            return res.mark(Status.RATE_LIMITED, f"PhishTank per-IP limit used ({used_up['limit']} per {used_up['interval_s']} s, "
                                                 "X-Request-Limit): could not verify now", reason_code="rate_limited")
        try:
            resp = ctx.http.post(CHECKURL_URL, data=checkurl_form(entity.value, ctx.key(KEY_NAME)), headers={"Accept": "application/json"},
                                 source=SOURCE, ttl=CACHE_TTL)
            ctx.http.check(resp)  # challenge pages and keyless 403 -> Blocked; 429 / 509 marker -> RateLimited; 5xx/meta error -> HttpError
        except (Blocked, AuthRequired) as exc:
            code = str(getattr(exc, "reason_code", "") or "")
            if isinstance(exc, AuthRequired) or code not in ("challenge", "geo_block", "login_wall", "circuit", "hostile_host"):
                code = "challenge"  # a 403 even with an app key is a block for this endpoint (c3), never retried
            if code not in ("circuit", "hostile_host"):  # those never reached PhishTank: neutral for the streak
                streak += 1
                ctx.state.set(STATE_STREAK, streak)
            res.link("PhishTank (manual check)", MANUAL_LINK)
            note = f"; {streak} consecutive blocked answers" + (" - demoted to link-only" if streak >= DEMOTE_AFTER else "")
            return res.mark(Status.BLOCKED, f"PhishTank answered with a block or challenge: could not verify, no bypass{note}", reason_code=code)
        except RateLimited:
            # 429 / HTTP 509 (documented over-limit answer): the window is used up until it resets
            prior = ctx.state.get(STATE_WINDOW)
            self._save_window(ctx, prior if isinstance(prior, dict) and prior.get("limit") else DEFAULT_WINDOW, now, exhausted=True)
            raise
        limits = rate_headers(resp.headers)
        if not resp.from_cache:
            self._save_window(ctx, limits, now)
        parsed = parse_checkurl(resp.content, now)
        if parsed["status"] is Status.ERROR:
            return res.mark(Status.ERROR, parsed["reason"])
        if streak:
            ctx.state.set(STATE_STREAK, 0)  # a verdict resets the block streak
        if limits.get("limit") is not None:
            res.attr("phishtank_limits", limits)
        if parsed["status"] is Status.EMPTY:
            return res.mark(Status.EMPTY, parsed["reason"])
        verdict = {k: parsed.get(k) for k in ("verdict", "in_database", "phish_id", "detail_page", "verified", "valid", "verified_at",
                                               "submitted_at", "age_days", "historical", "consensus_votes", "checked_at")}
        res.attr("phishtank_verdict", {k: v for k, v in verdict.items() if v is not None})
        res.raw = {"verdict": verdict}
        if parsed.get("detail_page"):
            res.link(f"PhishTank phish {parsed['phish_id']}", parsed["detail_page"])
        if parsed["verdict"] == "phish":
            historical = bool(parsed["historical"])
            res.finding(
                "Verified phishing URL (PhishTank)",
                "low" if historical else "high",
                (f"PhishTank lists this URL as a verified phish (id {parsed['phish_id']}, verified {parsed['verified_at'] or 'at an unknown date'}"
                 + (f", {parsed['age_days']} days ago: historical, it may be down or cleaned" if historical else "")
                 + "). One community source: one vote in consensus."),
                confidence="probable",
                criterion="PhishTank verified=true and valid=true (in_database alone is not a verdict)"
                          + (f"; verification older than {HISTORICAL_DAYS} days: historical" if historical else ""),
                tags=["phishing", "historical"] if historical else ["phishing", "malicious"],
                references=[parsed["detail_page"]] if parsed.get("detail_page") else [],
                source=SOURCE,
                observed_last=parsed["verified_at"] or parsed["submitted_at"],
                data={"phish_id": parsed["phish_id"], "verified_at": parsed["verified_at"], "age_days": parsed["age_days"],
                      "consensus_votes": 1},
            )
        return res
