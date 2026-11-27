"""Wikimedia global account + contributions by user, IP or CIDR (P120).

cond 1: ``meta.wikimedia.org/w/api.php?action=query&meta=globaluserinfo`` (home wiki, edit count,
registration, locked flag) and ``list=usercontribs`` (uclimit <= 50) on pt.wikipedia.org and
en.wikipedia.org; ``uciprange`` for CIDR inputs (MediaWiki refuses ranges broader than IPv4 /16 or IPv6
/32). Registry provider ``wikimedia``: tier trusted, terms open.

cond 2: the User-Agent is built at run time by the core from the provider profile (the binding
PROFILE_REQUIREMENTS template ``V3LUM/{version} (+{contact}) python-requests`` for *.wikipedia.org and
*.wikimedia.org) with setting ``contact_email`` - a team role mailbox, never an analyst's personal
address - and is sent only to the Wikimedia hosts. With ``contact_email`` empty (or a free-mail address)
the module is SKIPPED reason_code 'config' ('needs contact setting') before any request.

cond 3: IP contributions only for analyst-typed IP seeds and org_profile CIDRs, never for pivot IPs
(SKIPPED 'scope'). IP results say that IP edits are historical where logged-out editing is closed or
masked (pt.wikipedia since 2020, temporary accounts) and that IP attribution is low confidence.

cond 4: for usernames only counts, dates and the pages relevant to the case (organisation name and brand
terms of the org_profile, setting ``wikimedia_case_terms``) are kept - never full edit histories or
topic profiles (LGPD art. 11); edit summaries are never fetched (ucprop without 'comment'), continuation
is reported, never followed. Usernames are PERSONAL_TYPES: the provider's personal_data_review is still
to be recorded, so the policy gate sends them only on explicit selection (A3 BR8).

cond 5: maxlag=5 on every request; error objects inside HTTP 200 are detected through the provider's
P321 error markers (maxlag/ratelimited -> RATE_LIMITED, any other error object -> ERROR); 1 request/s
(provider min_interval 1.0, concurrency 1); 429 = could not verify, never absent.
"""

from __future__ import annotations

import ipaddress
import re
import unicodedata
from typing import Any
from urllib.parse import quote

from v3lum.config import SettingSpec
from v3lum.core.entities import Entity
from v3lum.core.entities import EntityType as T
from v3lum.core.http import (
    AuthRequired,
    Blocked,
    DeadlineExceeded,
    HttpError,
    NetworkError,
    QuotaExceeded,
    RateLimited,
)
from v3lum.core.models import ModuleResult, Opsec, Status
from v3lum.core.module import Module, register

SOURCE_GUI = "wikimedia.globaluserinfo"
SOURCE_CONTRIBS = "wikimedia.usercontribs"
META = "https://meta.wikimedia.org/w/api.php"
WIKI_HOSTS = {"ptwiki": "pt.wikipedia.org", "enwiki": "en.wikipedia.org"}  # cond 1
UCLIMIT_MAX = 50  # cond 1
MAXLAG_S = 5  # cond 5
CIDR_LIMITS = {4: 16, 6: 32}  # MediaWiki $wgRangeContributionsCIDRLimit default
UCPROP = "ids|title|timestamp|sizediff|flags"  # cond 4: no 'comment' (edit summaries are never fetched)
RELEVANT_CAP = 20
IP_ROWS_CAP = 50
TTL = 86400
FREE_MAIL_DOMAINS = frozenset({
    "gmail.com", "googlemail.com", "hotmail.com", "hotmail.com.br", "outlook.com", "outlook.com.br", "live.com",
    "msn.com", "yahoo.com", "yahoo.com.br", "ymail.com", "icloud.com", "me.com", "mac.com", "aol.com",
    "proton.me", "protonmail.com", "pm.me", "gmx.com", "gmx.net", "mail.com", "zoho.com", "yandex.com",
    "yandex.ru", "uol.com.br", "bol.com.br", "terra.com.br", "ig.com.br", "globo.com", "r7.com", "tutanota.com",
    "tuta.io", "fastmail.com", "hey.com",
})
_EMAIL_RE = re.compile(r"^[A-Za-z0-9._%+-]{1,64}@(?P<dom>[A-Za-z0-9.-]+\.[A-Za-z]{2,63})$")
_BAD_USER_CHARS = set("#<>[]|{}\n\r\t")
IP_NOTES = {
    "ptwiki": "pt.wikipedia closed logged-out (IP) editing in 2020: IP edits listed here are historical",
    "masked": "where temporary accounts are enabled, logged-out editors' IPs are masked: IP edits listed here may be historical only",
    "confidence": "IP attribution is low confidence (shared NAT, VPN, proxies, dynamic addressing)",
}


# ================================================================================ pure helpers


def contact_email_reason(contact_email: Any) -> str | None:
    """cond 2 + P326: None when the contact setting may go into the Wikimedia UA, else why the module is
    SKIPPED 'config'. Free-mail domains are refused: the UA carries a team role mailbox, never an analyst's
    personal address."""
    if not isinstance(contact_email, str) or not contact_email.strip():
        return "needs contact setting: contact_email is empty (v3lum config set contact_email <team role mailbox>)"
    m = _EMAIL_RE.match(contact_email.strip())
    if not m:
        return "needs contact setting: contact_email is not a valid e-mail address"
    if m.group("dom").lower() in FREE_MAIL_DOMAINS:
        return "needs contact setting: contact_email must be a team role mailbox, not a personal/free-mail address"
    return None


def valid_wiki_user(value: Any) -> str | None:
    """MediaWiki user name (first letter upper-cased as MediaWiki does; the core username normaliser
    lower-cases the rest, so mixed-case names are looked up in that form), or None when invalid."""
    u = value.strip().replace("_", " ") if isinstance(value, str) else ""
    if not u or len(u) > 255 or any(c in _BAD_USER_CHARS for c in u):
        return None
    return u[0].upper() + u[1:]


def globaluserinfo_params(username: str) -> dict[str, str]:
    """cond 1/5: meta=globaluserinfo (home wiki, edit count, registration), formatversion 2, maxlag 5."""
    return {"action": "query", "meta": "globaluserinfo", "guiuser": username, "guiprop": "merged|unattached|editcount",
            "format": "json", "formatversion": "2", "maxlag": str(MAXLAG_S)}


def usercontribs_params(*, user: str | None = None, iprange: str | None = None, limit: int = UCLIMIT_MAX) -> dict[str, str]:
    """cond 1/4/5: list=usercontribs, uclimit <= 50, ucprop without comments, maxlag 5."""
    p = {"action": "query", "list": "usercontribs", "uclimit": str(max(1, min(int(limit), UCLIMIT_MAX))), "ucprop": UCPROP,
         "format": "json", "formatversion": "2", "maxlag": str(MAXLAG_S)}
    if iprange:
        p["uciprange"] = iprange
    else:
        p["ucuser"] = str(user or "")
    return p


def ip_query(value: str) -> dict[str, Any]:
    """cond 1/3: an address -> ucuser, a CIDR -> uciprange (within the MediaWiki range limit); a /32 or /128
    'range' is sent as a plain address. -> {param, value, version} or {error}."""
    v = (value or "").strip()
    try:
        if "/" in v:
            net = ipaddress.ip_network(v, strict=False)
            if net.num_addresses == 1:
                return {"param": "ucuser", "value": str(net.network_address), "version": net.version}
            lim = CIDR_LIMITS[net.version]
            if net.prefixlen < lim:
                return {"error": f"IPv{net.version} ranges broader than /{lim} are not accepted by the MediaWiki API"}
            return {"param": "uciprange", "value": str(net), "version": net.version}
        ip = ipaddress.ip_address(v)
        return {"param": "ucuser", "value": str(ip), "version": ip.version}
    except ValueError:
        return {"error": "not an IP address or CIDR"}


def _is_public(value: str) -> bool:
    try:
        net = ipaddress.ip_network(value.strip(), strict=False)
    except ValueError:
        return False
    return bool(net.network_address.is_global and net.broadcast_address.is_global)


def _flag(v: Any) -> bool:
    """formatversion 1 uses '' for true flags; formatversion 2 uses booleans."""
    return v is True or v == ""


def _str(v: Any, limit: int = 300) -> str | None:
    return v[:limit] if isinstance(v, str) and v else None


def _api_error(obj: Any) -> str | None:
    if not isinstance(obj, dict):
        return None
    err = obj.get("error")
    if isinstance(err, dict) and err.get("code"):
        return str(err.get("code"))[:64]
    errs = obj.get("errors")
    if isinstance(errs, list) and errs and isinstance(errs[0], dict) and errs[0].get("code"):
        return str(errs[0]["code"])[:64]
    return None


def parse_globaluserinfo(obj: Any, keep_wikis: tuple[str, ...] = ("enwiki", "ptwiki")) -> dict[str, Any]:
    """cond 1/4: meta=globaluserinfo -> {state found|missing|error, name, home_wiki, registration, editcount,
    locked, hidden, merged_count, unattached_count, local_wikis, wikis [{wiki, editcount, registration,
    blocked}] (home wiki + pt/en only)}. Groups and per-wiki topic data are never kept."""
    base: dict[str, Any] = {"state": "error", "name": None, "home_wiki": None, "registration": None, "editcount": None,
                            "locked": False, "hidden": False, "merged_count": 0, "unattached_count": 0, "local_wikis": [],
                            "wikis": [], "reason": None}
    code = _api_error(obj)
    if code:
        return dict(base, reason=f"Wikimedia API error {code}")
    g = (obj.get("query") or {}).get("globaluserinfo") if isinstance(obj, dict) and isinstance(obj.get("query"), dict) else None
    if not isinstance(g, dict):
        return dict(base, reason="unexpected Wikimedia answer (no query.globaluserinfo)")
    if "missing" in g:
        return dict(base, state="missing", reason="no global (SUL) account with this name")
    merged = [m for m in g.get("merged") if isinstance(m, dict)] if isinstance(g.get("merged"), list) else []
    unatt = [m for m in g.get("unattached") if isinstance(m, dict)] if isinstance(g.get("unattached"), list) else []
    home = _str(g.get("home"), 64)
    keep = set(keep_wikis) | ({home} if home else set())
    wikis: list[dict[str, Any]] = []
    total = 0
    for m in merged:
        ec = m.get("editcount") if isinstance(m.get("editcount"), int) and not isinstance(m.get("editcount"), bool) else None
        total += ec or 0
        if m.get("wiki") in keep:
            wikis.append({"wiki": str(m.get("wiki")), "editcount": ec, "registration": _str(m.get("registration"), 40),
                          "blocked": isinstance(m.get("blocked"), dict)})
    wikis.sort(key=lambda w: (w["wiki"] != home, w["wiki"]))
    local = sorted({str(m.get("wiki")) for m in merged + unatt if isinstance(m.get("wiki"), str)})
    gec = g.get("editcount")
    ec = gec if isinstance(gec, int) and not isinstance(gec, bool) else (total if merged else None)
    return dict(base, state="found", name=_str(g.get("name"), 255), home_wiki=home, registration=_str(g.get("registration"), 40),
                editcount=ec, locked=_flag(g.get("locked")), hidden=_flag(g.get("hidden")), merged_count=len(merged),
                unattached_count=len(unatt), local_wikis=local, wikis=wikis)


def parse_usercontribs(obj: Any, wiki: str, target_kind: str = "user") -> dict[str, Any]:
    """cond 1/3/4: list=usercontribs -> {state ok|empty|error, wiki, count, first, last, more, contribs
    [{title, ns, timestamp, sizediff, new, minor, ip?}]}. Edit summaries are never read."""
    base: dict[str, Any] = {"state": "error", "wiki": wiki, "count": 0, "first": None, "last": None, "more": False,
                            "contribs": [], "reason": None}
    code = _api_error(obj)
    if code:
        return dict(base, reason=f"Wikimedia API error {code}")
    q = obj.get("query") if isinstance(obj, dict) else None
    items = q.get("usercontribs") if isinstance(q, dict) else None
    if not isinstance(items, list):
        return dict(base, reason="unexpected Wikimedia answer (no query.usercontribs)")
    contribs: list[dict[str, Any]] = []
    for it in items[: UCLIMIT_MAX * 2]:
        if not isinstance(it, dict) or not isinstance(it.get("title"), str):
            continue
        row = {"title": it["title"][:300], "ns": it.get("ns") if isinstance(it.get("ns"), int) else None,
               "timestamp": _str(it.get("timestamp"), 40),
               "sizediff": it.get("sizediff") if isinstance(it.get("sizediff"), int) else None,
               "new": _flag(it.get("new")), "minor": _flag(it.get("minor"))}
        if target_kind in ("ip", "range"):
            row["ip"] = _str(it.get("user"), 64)
        contribs.append(row)
    ts = sorted(r["timestamp"] for r in contribs if r["timestamp"])
    more = isinstance(obj.get("continue"), dict) and bool(obj.get("continue"))
    return dict(base, state="ok" if contribs else "empty", count=len(contribs), first=ts[0] if ts else None,
                last=ts[-1] if ts else None, more=more, contribs=contribs)


def fold(s: Any) -> str:
    text = unicodedata.normalize("NFKD", str(s or ""))
    return "".join(c for c in text if not unicodedata.combining(c)).lower()


def select_relevant(contribs: list[dict[str, Any]], case_terms: list[str], cap: int = RELEVANT_CAP) -> list[dict[str, Any]]:
    """cond 4: only contributions whose page title matches a case term (accent/case-folded substring of at
    least 3 characters); at most ``cap`` rows. Full histories and topic profiles are never emitted."""
    terms = [t for t in (fold(x).strip() for x in case_terms or [] if isinstance(x, str)) if len(t) >= 3]
    if not terms:
        return []
    out = []
    for r in contribs or []:
        title = fold(r.get("title", ""))
        if any(t in title for t in terms):
            out.append(r)
            if len(out) >= cap:
                break
    return out


def wiki_page_url(wiki: str, title: str) -> str | None:
    host = WIKI_HOSTS.get(wiki)
    if not host or not isinstance(title, str) or not title.strip():
        return None
    return f"https://{host}/wiki/" + quote(title.strip().replace(" ", "_"), safe="/:()_,.!'-")


def contributions_url(wiki: str, who: str) -> str | None:
    """Special:Contributions link for the report (manual pivot, never fetched by the module)."""
    host = WIKI_HOSTS.get(wiki) or ("meta.wikimedia.org" if wiki == "metawiki" else None)
    if not host or not isinstance(who, str) or not who.strip():
        return None
    return f"https://{host}/wiki/Special:Contributions/" + quote(who.strip().replace(" ", "_"), safe="/:._-")


def ip_history_notes(wiki: str) -> list[str]:
    """cond 3 notes attached to every IP/CIDR result."""
    notes = [IP_NOTES["ptwiki"]] if wiki == "ptwiki" else []
    return notes + [IP_NOTES["masked"], IP_NOTES["confidence"]]


def _failure(exc: BaseException) -> tuple[Status, str, str]:
    """(status, reason_code, reason) of a failed Wikimedia request (rule 5: could not verify)."""
    text = str(exc)[:200]
    if isinstance(exc, RateLimited):
        return Status.RATE_LIMITED, "rate_limited", f"rate limited ({text})"
    if isinstance(exc, QuotaExceeded):
        return Status.QUOTA, "quota", f"quota ({text})"
    if isinstance(exc, Blocked):
        code = str(getattr(exc, "reason_code", "") or "challenge")
        return Status.BLOCKED, code if code in ("challenge", "geo_block", "login_wall", "circuit", "hostile_host") else "challenge", f"blocked ({text})"
    if isinstance(exc, AuthRequired):
        return Status.BLOCKED, "challenge", f"refused ({text})"
    if isinstance(exc, DeadlineExceeded):
        return Status.ERROR, "timeout", "run deadline reached"
    if isinstance(exc, NetworkError) and re.search(r"time[d ]?\s?out", text, re.I):
        return Status.ERROR, "timeout", f"timeout ({text})"
    return Status.ERROR, "error", f"could not verify ({text})"


_FAILURES = (RateLimited, QuotaExceeded, Blocked, AuthRequired, HttpError, NetworkError, DeadlineExceeded)


# ================================================================================ module


@register
class Wikimedia(Module):
    name = "wikimedia"
    title = "Wikimedia global account and pt/en Wikipedia contributions"
    description = (
        "Wikimedia global (SUL) account of a username (home wiki, registration, edit count, locked) and pt/en Wikipedia "
        "contributions by user, by analyst-typed IP or by org_profile CIDR (counts, dates and case-relevant pages only)."
    )
    category = "username_social"
    accepts = frozenset({T.USERNAME, T.IPV4, T.IPV6, T.CIDR})
    produces = frozenset({T.URL})
    tags = frozenset({"free"})
    reference = "https://www.mediawiki.org/wiki/API:Usercontribs"
    notice = (
        "Wikimedia User-Agent policy: needs setting contact_email (a team role mailbox, never a personal address); without it "
        "the module is skipped (config). IP lookups only for analyst-typed IP seeds and org_profile CIDRs; IP attribution is low "
        "confidence and IP edits are historical where logged-out editing is closed or masked. Usernames: counts, dates and "
        "case-relevant pages only (never full edit histories); personal_data_review before default use."
    )
    terms = "open"
    opsec = Opsec.PASSIVE
    disclosure = "third_party"  # Wikimedia receives the username or IP
    provider = "wikimedia"
    sources = (SOURCE_GUI, SOURCE_CONTRIBS)
    hosts = ("meta.wikimedia.org", "pt.wikipedia.org", "en.wikipedia.org")
    access_model = "free_noauth_limited"
    max_requests = 4  # username: globaluserinfo + pt + en contributions (+1 spare); IP/CIDR: pt + en
    expected_latency = 3.0
    timeout = 45.0
    min_interval = 1.0  # cond 5
    daily_quota = 1000
    cache_ttl = TTL
    max_pivots = RELEVANT_CAP * 2
    default_enabled = True  # council P120 (privacy gate: usernames need explicit selection until reviewed)
    settings = {
        "wikimedia_case_terms": SettingSpec([], "Extra case terms (organisation, brand or product names) whose pages are kept "
                                                "from a user's contributions; the org_profile name and brand terms are always used"),
    }

    def applies(self, entity: Entity, ctx: Any) -> bool:
        if entity.type in (T.IPV4, T.IPV6, T.CIDR):
            return _is_public(entity.value)  # private/reserved ranges are never sent
        return valid_wiki_user(entity.value) is not None

    def run(self, entity: Entity, ctx: Any) -> ModuleResult:
        res = self.result(entity)
        why = contact_email_reason(ctx.setting("contact_email", ""))
        if why:
            return res.mark("skipped", why, reason_code="config")
        if entity.type is T.USERNAME:
            return self._user(res, ctx, entity)
        return self._ip(res, ctx, entity)

    # ------------------------------------------------------------------ requests
    @staticmethod
    def _get(ctx: Any, url: str, params: dict[str, str], source: str) -> Any:
        resp = ctx.http.get(url, params=params, source=source, ttl=TTL)
        ctx.http.check(resp)  # 429, 403 (UA policy), 5xx, challenges and the P321 error markers raise
        try:
            obj = resp.json()
        except (HttpError, ValueError):
            obj = None
        if not isinstance(obj, dict):
            ctx.http.evict(resp)
            raise HttpError("Wikimedia answered HTTP 200 without a JSON object: could not verify", resp.status, resp.url)
        if _api_error(obj):
            ctx.http.evict(resp)
        return obj

    def _contribs(self, ctx: Any, wiki: str, params: dict[str, str], kind: str) -> tuple[dict[str, Any] | None, tuple[Status, str, str] | None]:
        url = f"https://{WIKI_HOSTS[wiki]}/w/api.php"
        try:
            obj = self._get(ctx, url, params, SOURCE_CONTRIBS)
        except _FAILURES as exc:
            st, code, reason = _failure(exc)
            return None, (st, code, f"{wiki}: {reason}")
        parsed = parse_usercontribs(obj, wiki, kind)
        if parsed["state"] == "error":
            return None, (Status.ERROR, "error", f"{wiki}: {parsed['reason']}: could not verify")
        return parsed, None

    def _case_terms(self, ctx: Any) -> list[str]:
        org = getattr(ctx, "org", None)
        terms: list[str] = []
        if org is not None and not getattr(org, "is_empty", True):
            if getattr(org, "name", ""):
                terms.append(str(org.name))
            terms.extend(org.brand_terms())
        extra = ctx.setting("wikimedia_case_terms", [])
        if isinstance(extra, (list, tuple)):
            terms.extend(str(t) for t in extra if isinstance(t, str))
        return terms

    # ------------------------------------------------------------------ username (cond 1/4)
    def _user(self, res: ModuleResult, ctx: Any, entity: Entity) -> ModuleResult:
        user = valid_wiki_user(entity.value)
        if user is None:
            return res.mark("skipped", "not a valid MediaWiki user name", reason_code="not_applicable")
        obj = self._get(ctx, META, globaluserinfo_params(user), SOURCE_GUI)  # failures propagate: could not verify
        acct = parse_globaluserinfo(obj)
        if acct["state"] == "error":
            return res.mark("error", f"{acct['reason']}: could not verify")
        checked_at = ctx.now()
        if acct["state"] == "missing":
            res.presence("absent", marker="CentralAuth globaluserinfo 'missing' flag", url=contributions_url("metawiki", user),
                         checked_at=checked_at, source=SOURCE_GUI)
            return res.mark("empty", f"no global (SUL) Wikimedia account named '{user}' (local-only accounts are not checked)")
        res.presence("found", marker="CentralAuth globaluserinfo account record", url=contributions_url(acct["home_wiki"] or "metawiki", user),
                     checked_at=checked_at, source=SOURCE_GUI)
        summary = {k: acct[k] for k in ("name", "home_wiki", "registration", "editcount", "locked", "hidden", "merged_count",
                                        "unattached_count", "wikis")}
        res.attr("wikimedia_account", summary)
        res.attr("created", acct["registration"])
        res.raw = {"account": summary, "contributions": {}}
        terms = self._case_terms(ctx)
        contributions: dict[str, Any] = {}
        failures: list[tuple[Status, str, str]] = []
        for wiki in ("ptwiki", "enwiki"):
            if wiki not in acct["local_wikis"]:
                continue  # no local account on that wiki: no contributions to ask for
            parsed, failed = self._contribs(ctx, wiki, usercontribs_params(user=acct["name"] or user), "user")
            if failed:
                failures.append(failed)
                continue
            relevant = select_relevant(parsed["contribs"], terms)
            pages = [{"title": r["title"], "timestamp": r["timestamp"], "url": wiki_page_url(wiki, r["title"])} for r in relevant]
            contributions[wiki] = {"count": parsed["count"], "first": parsed["first"], "last": parsed["last"],
                                   "more": parsed["more"], "relevant_pages": pages}
            for p in pages:
                if p["url"]:
                    res.pivot(T.URL, p["url"], "edited_page", confidence="probable", expand=False,
                              note=f"page edited by Wikimedia user '{user}' on {p['timestamp'] or '?'} (matches a case term)")
            link = contributions_url(wiki, user)
            if link:
                res.link(f"Special:Contributions on {WIKI_HOSTS[wiki]} (manual; never fetched)", link)
        if contributions:
            res.attr("wikimedia_contributions", contributions)
            res.raw["contributions"] = {w: {k: v for k, v in c.items() if k != "relevant_pages"} for w, c in contributions.items()}
        for st, code, reason in failures:
            res.source_status(SOURCE_CONTRIBS, st, reason_code=code, reason=reason)
        res.finding(
            "Wikimedia global account",
            "info",
            f"Global account '{acct['name'] or user}'"
            + (f", home wiki {acct['home_wiki']}" if acct["home_wiki"] else "")
            + (f", registered {acct['registration'][:10]}" if acct["registration"] else "")
            + (f", {acct['editcount']} edits" if acct["editcount"] is not None else "")
            + f" across {acct['merged_count']} attached wiki(s). The same username does not prove the same person.",
            confidence="probable",
            source=SOURCE_GUI,
            observed_first=acct["registration"],
        )
        if acct["locked"]:
            res.finding(
                "Wikimedia global account is locked",
                "low",
                "Stewards locked this global account (locks are used for abuse, spam, sockpuppetry or compromised accounts); "
                "the reason is not published by this API.",
                confidence="probable",
                criterion="CentralAuth globaluserinfo 'locked' flag set",
                source=SOURCE_GUI,
            )
        return res

    # ------------------------------------------------------------------ IP / CIDR (cond 1/3)
    def _ip(self, res: ModuleResult, ctx: Any, entity: Entity) -> ModuleResult:
        origin = "seed" if ctx.is_seed else None
        if entity.type is T.CIDR and origin is None:
            own = ctx.org.owns(entity) if getattr(ctx, "org", None) is not None else None
            origin = "org_profile" if own is not None and getattr(own, "own", False) else None
        if origin is None:
            return res.mark("skipped", "IP contributions are looked up only for analyst-typed IP seeds and org_profile CIDRs "
                                       "(never for pivot IPs)", reason_code="scope")
        q = ip_query(entity.value)
        if q.get("error"):
            return res.mark("skipped", str(q["error"]), reason_code="not_applicable")
        kind = "range" if q["param"] == "uciprange" else "ip"
        params = usercontribs_params(iprange=q["value"]) if kind == "range" else usercontribs_params(user=q["value"])
        contributions: dict[str, Any] = {}
        failures: list[tuple[Status, str, str]] = []
        terms = self._case_terms(ctx)
        for wiki in ("ptwiki", "enwiki"):
            parsed, failed = self._contribs(ctx, wiki, params, kind)
            if failed:
                failures.append(failed)
                continue
            rows = [{k: r.get(k) for k in ("title", "timestamp", "sizediff", "ip") if k in r} for r in parsed["contribs"][:IP_ROWS_CAP]]
            contributions[wiki] = {"count": parsed["count"], "first": parsed["first"], "last": parsed["last"],
                                   "more": parsed["more"], "rows": rows, "notes": ip_history_notes(wiki)}
            for r in select_relevant(parsed["contribs"], terms):
                url = wiki_page_url(wiki, r["title"])
                if url:
                    res.pivot(T.URL, url, "edited_page", confidence="possible", expand=False,
                              note=f"page edited from {r.get('ip') or q['value']} on {r['timestamp'] or '?'} (historical; "
                                   "low-confidence attribution)")
            if parsed["count"]:
                link = contributions_url(wiki, q["value"])
                if link:
                    res.link(f"Special:Contributions on {WIKI_HOSTS[wiki]} (manual; never fetched)", link)
        if not contributions:
            st, code, reason = failures[0]
            return res.mark(st, "Wikimedia contributions could not be verified: " + "; ".join(f[2] for f in failures), reason_code=code)
        for st, code, reason in failures:
            res.source_status(SOURCE_CONTRIBS, st, reason_code=code, reason=reason)
        res.attr("wikimedia_contributions", contributions)
        res.raw = {"query": q, "contributions": {w: {k: c[k] for k in ("count", "first", "last", "more")} for w, c in contributions.items()}}
        total = sum(c["count"] for c in contributions.values())
        if not total:
            if failures:
                st, code, reason = failures[0]
                return res.mark(st, "no edits on the wiki that answered; the other could not be verified: "
                                    + "; ".join(f[2] for f in failures), reason_code=code)
            res.error = (f"no pt/en Wikipedia edits from {q['value']} in the API answer (logged-out editing is closed or masked "
                         "on many wikis: absence of edits says little)")
            return res.mark("empty")
        first = min((c["first"] for c in contributions.values() if c["first"]), default=None)
        last = max((c["last"] for c in contributions.values() if c["last"]), default=None)
        res.finding(
            "Wikipedia edits from this IP" if kind == "ip" else "Wikipedia edits from this IP range",
            "info",
            f"{total} edit(s) on " + ", ".join(f"{WIKI_HOSTS[w]} ({c['count']}{'+' if c['more'] else ''})" for w, c in contributions.items())
            + (f" between {first[:10]} and {last[:10]}" if first and last else "")
            + ". " + IP_NOTES["confidence"] + "; IP edits are historical where logged-out editing is closed or masked.",
            confidence="possible",
            tags=["historical", "weak_signal"],
            source=SOURCE_CONTRIBS,
            observed_first=first,
            observed_last=last,
        )
        return res
