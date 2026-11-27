"""TikTok public profile from the server-side hydration JSON (P118 ``tiktok_public``), licence-gated.

Final conditions (FC1-FC6 of P118, batch p3-G05-2):

* FC1 - ``default_enabled = False``, opt-in per run (``-M tiktok_public``), analyst-typed handles only
  (``run_on='seeds'``): never run on pivots.
* FC2 - terms ``'license'``: TikTok's terms forbid "automated scripts to collect information" (legal_dpo,
  2026-11-26). Off under the corporate profile until licence-cleared, and on top of the core licence gate
  this module itself runs only with an active licence_allow entry whose basis is ``provider_grant``
  (TikTok's written permission) or under an active research basis covering the source (a recorded grant):
  a ``licence`` or ``terms_clause`` entry never unlocks it.
* FC3 - one plain GET of ``https://www.tiktok.com/@{u}`` per handle per run, ``min_interval`` 5 s (one at a
  time), no request signing or tokens (X-Bogus, msToken, device ids), no headless browser, no cookie replay,
  no proxy rotation and no retry (provider retries 0; a challenge is never retried by the core).
* FC4 - only the ``__UNIVERSAL_DATA_FOR_REHYDRATION__`` script element is read (2 MB cap) with a schema
  check: missing keys are ERROR 'layout changed', never empty. Verify/captcha pages and empty hydration
  data are BLOCKED (P321 markers of the ``tiktok`` provider, which also short-circuit the host for the run,
  A9; this module adds the same short circuit for answers past the markers' 64 KB window). Five
  consecutive BLOCKED runs demote it (A3 health, core).
* FC5 - output limited to the handle, display name, verified flag, follower count, the bio link (a
  passive-only URL pivot, ``expand=False``) and the account id with its id-derived creation date (the
  shared P314 decoder, ``v3lum.modules.utility.id_timestamp_decoders.decode_platform_id``). oEmbed is not
  used (it returns only embed HTML).
* FC6 - the manual ``https://www.tiktok.com/@{u}`` link is always emitted, with 'automation skipped:
  licence' while the module is not cleared; the doctor self-test probes TikTok's own public account
  (@tiktok) only when the licence is cleared.

The hydration path matches socid_extractor (MIT); it is re-implemented here, no code was copied.
"""

from __future__ import annotations

import re
import threading
import weakref
from typing import Any

from v3lum.core import licence as _licence
from v3lum.core.entities import Entity
from v3lum.core.entities import EntityType as T
from v3lum.core.http import AuthRequired, Blocked, HttpError, NetworkError, QuotaExceeded, RateLimited
from v3lum.core.models import ModuleResult, Opsec
from v3lum.core.module import HealthCheck, HealthResult, Module, register
from v3lum.modules.username_social.community_profiles import (
    ABSENT,
    BLOCKED,
    ERROR,
    FOUND,
    LAYOUT_CHANGED,
    PAGE_CAP,
    SCRIPT_JSON_CAP,
    _int,
    _result,
    _str,
    classify_block,
    clean_url,
    extract_script_json,
    profile_row,
    to_text,
)
from v3lum.modules.utility.id_timestamp_decoders import decode_platform_id

SOURCE = "tiktok.profile_page"
HOST = "www.tiktok.com"
TIKTOK_MIN_INTERVAL_S = 5.0  # FC3
TIKTOK_LICENCE_SKIP = "automation skipped: licence"
#: Absence markers from community tooling, NOT verified live (no request may be sent before the licence is
#: cleared): any other non-zero statusCode is ERROR, never ABSENT. Confirm at the first licensed capture.
TIKTOK_ABSENT_STATUS_CODES = frozenset({10202, 10221})
SELFTEST_HANDLE = "tiktok"  # FC6: TikTok's own public account
_SCRIPT_RE = re.compile(r"<script\b[^>]{0,500}\bid\s*=\s*[\"']__UNIVERSAL_DATA_FOR_REHYDRATION__[\"'][^>]{0,500}>", re.I)
_HANDLE_RE = re.compile(r"^[A-Za-z0-9_.]{2,24}$")
_FC5_KEYS = ("handle", "display_name", "verified", "follower_count", "account_id", "created", "created_epoch", "profile_url")


# ======================================================================================
# handles, URLs and the licence gate (FC1-FC3, FC6)
# ======================================================================================


def normalise_tiktok_handle(value: Any) -> str | None:
    """'@user', 'user' or https://www.tiktok.com/@user[/...] -> 'user' (analyst-typed seeds only, FC1)."""
    s = _str(value, 300)
    if not s:
        return None
    m = re.match(r"^(?:https://)?(?:www\.|m\.)?tiktok\.com/@([^/?#\s]+)", s, re.I)
    if m:
        s = m.group(1)
    elif "://" in s or "/" in s:
        return None
    s = s.lstrip("@")
    return s if _HANDLE_RE.match(s) else None


def handle_of(entity: Entity) -> str | None:
    if entity.type is T.SOCIAL_ACCOUNT:
        platform, _, handle = entity.value.partition(":")
        return normalise_tiktok_handle(handle) if platform == "tiktok" else None
    if entity.type is T.URL:
        return normalise_tiktok_handle(entity.value) if re.match(r"^https://(?:www\.|m\.)?tiktok\.com/@", entity.value, re.I) else None
    if entity.type is T.USERNAME:
        return normalise_tiktok_handle(entity.value)
    return None


def tiktok_profile_url(handle: Any) -> str | None:
    """FC3: the single URL the module may fetch, https://www.tiktok.com/@{u} (no query, no oEmbed)."""
    h = normalise_tiktok_handle(handle)
    return f"https://{HOST}/@{h}" if h else None


def tiktok_fetch_allowed(url: Any) -> bool:
    """FC3/FC5 guard: exactly https://www.tiktok.com/@{handle}; oEmbed, API, video and signed/tokenised URLs
    (any query string such as msToken or X-Bogus, any fragment) are refused."""
    if not isinstance(url, str):
        return False
    m = re.fullmatch(r"https://www\.tiktok\.com/@([A-Za-z0-9_.]{2,24})", url)
    return bool(m)


def licence_cleared(ctx: Any) -> tuple[bool, str]:
    """FC2: (cleared, basis or reason). Only an active licence_allow entry with basis 'provider_grant', or an
    active research basis covering the source under the research profile, clears TikTok."""
    now = ctx.now()
    try:
        state = _licence.LicenceState.load(config=getattr(ctx, "config", None))
    except Exception:  # noqa: BLE001 - an unreadable allow-list fails closed
        return False, "licence allow-list unreadable: fail closed"
    entry = state.entry_for(SOURCE, now)
    if entry is not None and entry.basis == "provider_grant":
        return True, f"provider_grant {entry.legal_ref}"
    try:
        profile = _licence.resolve_profile(getattr(ctx, "config", None), getattr(ctx, "options", None), state=state, now=now)
    except _licence.LicenceError:
        profile = "corporate"
    if profile == "research" and state.research_covers(SOURCE, now) and state.research_basis is not None:
        return True, f"research basis {state.research_basis.legal_ref}"
    if entry is not None:
        return False, f"licence_allow entry basis '{entry.basis}' is not a provider grant (P118 FC2)"
    return False, "no provider_grant licence_allow entry for tiktok.profile_page (P118 FC2)"


# A9 short circuit for walls this module recognises itself (the provider markers trip the core circuit).
_CIRCUITS: weakref.WeakKeyDictionary[Any, dict[str, str]] = weakref.WeakKeyDictionary()
_CIRCUIT_LOCK = threading.Lock()


def _circuit_get(ctx: Any) -> str | None:
    rt = getattr(ctx, "runtime", None)
    try:
        with _CIRCUIT_LOCK:
            return (_CIRCUITS.get(rt) or {}).get(str(getattr(ctx, "case_id", "") or ""))
    except TypeError:
        return None


def _circuit_trip(ctx: Any, reason: str) -> None:
    rt = getattr(ctx, "runtime", None)
    try:
        with _CIRCUIT_LOCK:
            _CIRCUITS.setdefault(rt, {})[str(getattr(ctx, "case_id", "") or "")] = reason
    except TypeError:
        return


# ======================================================================================
# the parser (FC4/FC5)
# ======================================================================================


def parse_tiktok_profile(status: Any, headers: Any = None, body: Any = None, handle: Any = None, now: Any = None) -> dict[str, Any]:
    """www.tiktok.com/@{u}, reading only __UNIVERSAL_DATA_FOR_REHYDRATION__ (FC4).

    Wall/verify/captcha page -> BLOCKED; an empty page or empty hydration data -> BLOCKED; missing keys ->
    ERROR 'layout changed' (never empty); hydration element over 2 MB -> ERROR; TIKTOK_ABSENT_STATUS_CODES
    without userInfo -> ABSENT; a handle mismatch -> ERROR; otherwise FOUND with exactly the FC5 fields.
    """
    st = _int(status)
    blk = classify_block(st, headers, body)
    if blk:
        return _result("tiktok", BLOCKED, blk[1], blk[0])
    if st not in (200, 404):
        return _result("tiktok", ERROR, f"unexpected HTTP {st}")
    text = to_text(body, PAGE_CAP)[0]
    if len(text.strip()) < 512 and "__UNIVERSAL_DATA_FOR_REHYDRATION__" not in text:
        return _result("tiktok", BLOCKED, "empty page (anti-bot answer)", "challenge")
    data, why = extract_script_json(text, _SCRIPT_RE, SCRIPT_JSON_CAP)
    if data is None:
        if why == "empty":
            return _result("tiktok", BLOCKED, "empty hydration data", "challenge")
        if why == "oversize":
            return _result("tiktok", ERROR, "hydration element over the 2 MB cap")
        return _result("tiktok", ERROR, f"{LAYOUT_CHANGED}: hydration element {why}")
    if not isinstance(data, dict):
        return _result("tiktok", ERROR, f"{LAYOUT_CHANGED}: hydration JSON is not an object")
    scope = data.get("__DEFAULT_SCOPE__")
    if not data or scope == {}:
        return _result("tiktok", BLOCKED, "empty hydration data", "challenge")
    if not isinstance(scope, dict):
        return _result("tiktok", ERROR, f"{LAYOUT_CHANGED}: no __DEFAULT_SCOPE__")
    ud = scope.get("webapp.user-detail")
    if ud is None:
        return _result("tiktok", ERROR, f"{LAYOUT_CHANGED}: no webapp.user-detail")
    if not isinstance(ud, dict) or not ud:
        return _result("tiktok", BLOCKED, "empty hydration data (user-detail)", "challenge")
    info = ud.get("userInfo")
    code = _int(ud.get("statusCode"))
    if not isinstance(info, dict) or not info:
        if code in TIKTOK_ABSENT_STATUS_CODES:
            return _result("tiktok", ABSENT, f"user not found or unavailable (statusCode {code})")
        return _result("tiktok", ERROR, f"{LAYOUT_CHANGED}: no userInfo (statusCode {code})")
    user = info.get("user")
    stats = info.get("stats")
    if not isinstance(user, dict) or not isinstance(stats, dict):
        return _result("tiktok", ERROR, f"{LAYOUT_CHANGED}: userInfo.user/stats")
    missing = [k for k in ("id", "uniqueId", "nickname", "verified") if k not in user]
    if "followerCount" not in stats:
        missing.append("stats.followerCount")
    if missing:
        return _result("tiktok", ERROR, f"{LAYOUT_CHANGED}: missing {', '.join(missing)}")
    uid = user.get("id")
    uid = uid if isinstance(uid, str) else (str(uid) if isinstance(uid, int) and not isinstance(uid, bool) else None)
    uniq = _str(user.get("uniqueId"), 60)
    if not uid or not re.fullmatch(r"\d{1,20}", uid) or not uniq:
        return _result("tiktok", ERROR, f"{LAYOUT_CHANGED}: id/uniqueId")
    if isinstance(handle, str) and uniq.lower() != handle.strip().lstrip("@").lower():
        return _result("tiktok", ERROR, f"handle mismatch ({uniq})")
    decoded = decode_platform_id("tiktok", uid, now=now)  # FC5: the shared P314 decoder
    bio = user.get("bioLink") if isinstance(user.get("bioLink"), dict) else {}
    bio_url = clean_url(bio.get("link"))
    facts = {"handle": uniq, "display_name": _str(user.get("nickname"), 200), "verified": user.get("verified") is True,
             "follower_count": _int(stats.get("followerCount")), "account_id": uid,
             "created": decoded.get("created") if decoded.get("status") == "ok" else None,
             "created_epoch": decoded.get("epoch") if decoded.get("status") == "ok" else None,
             "profile_url": f"https://{HOST}/@{uniq}"}
    facts = {k: facts[k] for k in _FC5_KEYS}
    linked = [{"url": bio_url, "source": "bioLink"}] if bio_url else []
    return _result("tiktok", FOUND, facts=facts, linked=linked, id_decode=decoded.get("status"))


# ======================================================================================
# the module
# ======================================================================================


def _selftest(ctx: Any) -> HealthResult:
    """FC6 doctor self-test on TikTok's own public account: only when the licence is cleared."""
    cleared, why = licence_cleared(ctx)
    if not cleared:
        return HealthResult("blocked", f"{TIKTOK_LICENCE_SKIP}: {why}")
    url = tiktok_profile_url(SELFTEST_HANDLE) or ""
    try:
        resp = ctx.http.get(url, source=SOURCE)
        ctx.http.check(resp)
    except (RateLimited, QuotaExceeded) as exc:
        return HealthResult("quota", str(exc)[:200])
    except (Blocked, AuthRequired) as exc:
        return HealthResult("blocked", str(exc)[:200])
    except (HttpError, NetworkError) as exc:
        return HealthResult("dead", str(exc)[:200])
    parsed = parse_tiktok_profile(resp.status, resp.headers, resp.content, SELFTEST_HANDLE, ctx.now())
    if parsed["state"] == FOUND:
        return HealthResult("ok", "hydration layout as expected for @tiktok")
    if parsed["state"] == BLOCKED:
        return HealthResult("blocked", str(parsed.get("reason") or "wall page"))
    return HealthResult("dead", f"drift: {parsed.get('reason')}")


@register
class TiktokPublic(Module):
    name = "tiktok_public"
    title = "TikTok public profile (licence-gated)"
    description = (
        "Handle, display name, verified flag, follower count, bio link and id-derived creation date of an analyst-typed "
        "TikTok handle, from the profile page's hydration JSON (one plain GET); runs only with TikTok's written permission."
    )
    category = "username_social"
    accepts = frozenset({T.USERNAME, T.SOCIAL_ACCOUNT, T.URL})
    produces = frozenset({T.URL})
    run_on = "seeds"  # FC1: analyst-typed handles only, never pivots
    terms = "license"  # FC2: provider_grant only (checked again in run)
    opsec = Opsec.PASSIVE
    disclosure = "third_party"
    provider = "tiktok"
    sources = (SOURCE,)
    hosts = (HOST,)
    access_model = "free_noauth_limited"
    max_requests = 1  # FC3: one GET per handle per run
    expected_latency = 1.5
    timeout = 30.0
    min_interval = TIKTOK_MIN_INTERVAL_S
    cache_ttl = 86400
    max_pivots = 5
    default_enabled = False  # FC1
    manual_link = "https://www.tiktok.com/@{user}"  # FC6
    reference = "https://www.tiktok.com/legal/page/row/terms-of-service/en"
    notice = (
        "TikTok's terms forbid automated collection: terms 'license', off under the corporate profile until legal records "
        "TikTok's written permission as a provider_grant licence_allow entry (a licence or terms_clause entry never unlocks "
        "it). One plain GET per analyst-typed handle, no signing, tokens, headless browser, cookies, proxies or retries; "
        "challenges are BLOCKED and never bypassed. The manual profile link is always emitted."
    )

    @classmethod
    def health_check(cls) -> HealthCheck:
        return HealthCheck(offline=False, selftest=_selftest)

    def applies(self, entity: Entity, ctx: Any) -> bool:
        return handle_of(entity) is not None

    def run(self, entity: Entity, ctx: Any) -> ModuleResult:
        res = self.result(entity)
        handle = handle_of(entity)
        url = tiktok_profile_url(handle) if handle else None
        if not handle or not url or not tiktok_fetch_allowed(url):
            return res.mark("skipped", "not a TikTok handle or profile URL", reason_code="not_applicable")
        if not getattr(ctx, "is_seed", False):
            return res.mark("skipped", "analyst-typed handles only, never pivots (P118 FC1)", reason_code="privacy")
        cleared, why = licence_cleared(ctx)
        res.link("TikTok profile (manual)" if cleared else f"TikTok profile (manual, {TIKTOK_LICENCE_SKIP})", url)  # FC6
        if not cleared:
            return res.mark("skipped", f"{TIKTOK_LICENCE_SKIP}: {why}", reason_code="licence")
        tripped = _circuit_get(ctx)
        if tripped:
            return res.mark("blocked", f"www.tiktok.com short-circuited for this run after {tripped}", reason_code="circuit")
        try:
            resp = ctx.http.get(url, source=SOURCE, retries=0)  # FC3: one plain GET, never retried
            try:
                ctx.http.check(resp)
            except (Blocked, RateLimited, QuotaExceeded):
                raise
            except HttpError:
                if resp.status != 404:
                    raise
        except Blocked as exc:
            _circuit_trip(ctx, exc.reason_code or "challenge")
            return res.mark("blocked", str(exc), reason_code=exc.reason_code)
        except RateLimited as exc:  # FC3: never retried; the manual link alone is not an answer
            return res.mark("rate_limited", f"{exc} (not retried)")
        except QuotaExceeded as exc:
            return res.mark("quota", str(exc))
        parsed = parse_tiktok_profile(resp.status, resp.headers, resp.content, handle, ctx.now())
        res.raw = {"handle": handle, "state": parsed["state"], "reason": parsed.get("reason"), "id_decode": parsed.get("id_decode"),
                   "licence_basis": why}
        state = parsed["state"]
        if state == BLOCKED:
            _circuit_trip(ctx, str(parsed.get("reason") or "challenge"))
            return res.mark("blocked", f"TikTok: {parsed.get('reason')} (could not verify, never retried)",
                            reason_code=parsed.get("reason_code") or "challenge")
        if state == ABSENT:
            res.presence("absent", marker=str(parsed.get("reason")), url=url, checked_at=ctx.now(), source=SOURCE)
            res.error = "no public TikTok account for this handle"
            return res.mark("empty")
        if state != FOUND:
            return res.mark("error", str(parsed.get("reason") or "could not verify"))
        facts = parsed["facts"]
        res.presence("found", marker="hydration userInfo for the handle", url=facts["profile_url"], checked_at=ctx.now(), source=SOURCE)
        res.attr("display_name", facts.get("display_name"))
        res.attr("verified", facts.get("verified"))
        res.attr("followers", facts.get("follower_count"))
        res.attr("account_id", facts.get("account_id"))
        res.attr("created", facts.get("created"))
        res.attr("created_epoch", facts.get("created_epoch"))
        res.attr("profile_url", facts.get("profile_url"))
        res.attr("platform_facts", facts)
        res.attr("profile_row", profile_row(parsed))
        res.raw["facts"] = facts
        for item in parsed["linked"]:
            res.pivot(T.URL, item["url"], "link_on_profile", confidence="possible", expand=False,
                      note="bio link of the TikTok profile: passive-only pivot, self-declared, never fetched by this module")
        created = f", created ~{facts['created'][:10]} (decoded from the id)" if facts.get("created") else ""
        res.finding(
            "Account on TikTok",
            "info",
            f"TikTok account {facts['handle']}{created}. The same handle elsewhere does not prove the same person.",
            confidence="confirmed",
            criterion="TikTok's profile page hydration carries the account for this handle",
            data={"row": profile_row(parsed)},
            tags=["account"],
            references=[facts["profile_url"]],
            source=SOURCE,
        )
        return res
