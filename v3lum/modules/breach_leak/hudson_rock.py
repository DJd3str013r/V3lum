"""Hudson Rock Cavalier free OSINT endpoints (P134): infostealer exposure METADATA only.

Two modules over ``cavalier.hudsonrock.com/api/json/v2/osint-tools/``:

* ``hudson_rock`` - search-by-email / search-by-username / search-by-ip (run_on 'own_assets', A4):
  addresses on verified org_profile domains (txt_verified/attested); any other address or a
  username only as an analyst-typed seed with ``--breach-scope all`` and a recorded ``--purpose``,
  as context (at most MEDIUM, never an exposure score); IPs only inside org_profile CIDRs (C7).
* ``hudson_rock_domain`` - search-by-domain (counts only) and urls-by-domain (run_on
  'own_assets_only', A11 BR4): verified org_profile domains only (C5, C8).

Binding rules (P134 final conditions):

* C1/C2 the P145 sanitizer schema of every source is a field ALLOWLIST (provider fragment
  ``v3lum/data/providers/hudsonrock.json``) applied by the HTTP client BEFORE the cache, the module,
  evidence, logs and the graph: per stealer only date_compromised, the stealer family and the two
  service counts; at top level only the counts. top_passwords, top_logins, computer_name, ip,
  malware_path, antiviruses, operating_system, the message and any new field never reach this code;
  the module rebuilds every record from the same allowlist again (belt and braces). Cache TTL <= 7 d.
* C4 terms 'unknown': disabled in every profile (default_enabled False) until Hudson Rock confirms
  its terms in writing or legal records a licence_allow entry; coverage reads 'licence: terms unknown'.
* C5 urls-by-domain rows become url entities with expand=False, stripped to scheme + host + path
  (query, fragment, userinfo and user-identifying path segments removed); that endpoint is fetched
  no-store, so unstripped URLs never reach the HTTP cache.
* C6 generic/test/role addresses (A4 list, or >= 5 computers for one address) are flagged, capped
  at POSSIBLE and never scored (info 'generic address').
* C8 own identities: CRITICAL only on a verified org domain with date_compromised <= 12 months;
  older logs with corporate services > 0 HIGH; other older ones MEDIUM 'historical exposure, verify
  rotation', with the date shown.
* C9 every finding carries next steps; leaked data is never used for login attempts, spraying or
  validation in any mode or engagement (A4 BR12).
* C10 30 s per request (the domain search hung > 70 s): a timeout is ERROR 'timeout' (could not
  verify), never 'not found'.
"""

from __future__ import annotations

import datetime as _dt
import ipaddress
import re
from typing import Any
from urllib.parse import unquote, urlsplit

from v3lum.core import http as _http
from v3lum.core.entities import Entity, generic_address_kind
from v3lum.core.entities import EntityType as T
from v3lum.core.models import ModuleResult, Opsec, Status
from v3lum.core.module import Module, register

API = "https://cavalier.hudsonrock.com/api/json/v2/osint-tools/{endpoint}"
SRC_EMAIL = "hudsonrock.search_by_email"
SRC_USERNAME = "hudsonrock.search_by_username"
SRC_IP = "hudsonrock.search_by_ip"
SRC_DOMAIN = "hudsonrock.search_by_domain"
SRC_URLS = "hudsonrock.urls_by_domain"
REQUEST_TIMEOUT = 30.0
GENERIC_COMPUTERS = 5
RECENT_DAYS = 365
MAX_RECORDS = 25
MAX_URLS = 50
LICENCE_NOTE = "licence: terms unknown"
STEALER_ALLOW = ("date_compromised", "stealer_family", "total_corporate_services", "total_user_services")
DOMAIN_COUNTS = (
    ("total", "total"), ("totalStealers", "total_stealers"), ("employees", "employees"), ("users", "users"),
    ("third_parties", "third_parties"), ("totalUrls", "total_urls"),
)
NEXT_STEPS = (
    "reset the password of the affected account(s)",
    "revoke active sessions and tokens",
    "check that MFA is enabled and review the MFA devices",
    "identify the owner of the infected device and route it to incident response",
)
NOT_FOR_LOGIN = "Leaked data is never used for login attempts, spraying or validation (A4 BR12)."
_NOTICE = (
    f"{LICENCE_NOTE}: Hudson Rock's free tools publish no terms, so this source stays disabled in every licence profile "
    "until Hudson Rock confirms its terms in writing or legal records a licence_allow entry (P134 cond 4). Infostealer "
    "metadata only (dates, families, counts): credentials, machine names, victim IPs and malware paths are dropped before "
    f"the cache. {NOT_FOR_LOGIN}"
)
_CTRL = re.compile(r"[\x00-\x1f\x7f-\x9f]")


# --------------------------------------------------------------------------------------
# allowlist rebuild (the HTTP client already applied the same allowlist: belt and braces)
# --------------------------------------------------------------------------------------


def _int(value: Any) -> int | None:
    if isinstance(value, bool):
        return None
    if isinstance(value, int):
        return value
    if isinstance(value, float) and value.is_integer():
        return int(value)
    if isinstance(value, str) and value.strip().isdigit():
        return int(value.strip())
    return None


def _date(value: Any) -> str | None:
    """Compromise date -> 'YYYY-MM-DD' (UTC); None when unreadable."""
    if not isinstance(value, str) or not value.strip():
        return None
    try:
        d = _dt.datetime.fromisoformat(value.strip().replace("Z", "+00:00"))
    except ValueError:
        return None
    if d.tzinfo is None:
        d = d.replace(tzinfo=_dt.timezone.utc)
    return d.astimezone(_dt.timezone.utc).strftime("%Y-%m-%d")


def _family(value: Any) -> str | None:
    if not isinstance(value, str):
        return None
    text = " ".join(_CTRL.sub("", value).split())[:60]
    return text if text and text.lower() not in ("not found", "unknown", "null", "none") else None


def sanitize_identity(data: Any) -> dict[str, Any] | None:
    """search-by-email/username/ip -> {stealers: [allowlisted records], counts}; None when the
    answer is not a stealer answer (no 'stealers' list): could not verify."""
    if not isinstance(data, dict) or not isinstance(data.get("stealers"), list):
        return None
    stealers = []
    for item in data["stealers"]:
        if not isinstance(item, dict):
            continue
        stealers.append(
            {
                "date_compromised": _date(item.get("date_compromised")),
                "stealer_family": _family(item.get("stealer_family")),
                "total_corporate_services": _int(item.get("total_corporate_services")),
                "total_user_services": _int(item.get("total_user_services")),
            }
        )
    return {
        "stealers": stealers,
        "total_corporate_services": _int(data.get("total_corporate_services")),
        "total_user_services": _int(data.get("total_user_services")),
    }


def sanitize_domain(data: Any) -> dict[str, Any] | None:
    """search-by-domain -> counts only (+ stealer-family counts); None when no count is present."""
    if not isinstance(data, dict):
        return None
    out: dict[str, Any] = {k_out: _int(data.get(k_in)) for k_in, k_out in DOMAIN_COUNTS}
    families = data.get("stealerFamilies") if isinstance(data.get("stealerFamilies"), dict) else {}
    out["stealer_families"] = {
        fam: _int(count) for fam, count in ((_family(k), v) for k, v in families.items()) if fam and fam.lower() != "total" and _int(count) is not None
    }
    if all(out[k] is None for _k, k in DOMAIN_COUNTS):
        return None
    return out


_USER_KEYWORDS = {
    "user", "users", "u", "profile", "profiles", "people", "person", "member", "members", "account", "accounts", "home",
    "customer", "customers", "employee", "employees", "perfil", "usuario", "usuarios", "cliente", "clientes", "id",
    "uid", "email", "password_reset", "reset", "confirm", "invite", "invitations", "token", "session",
}
_ACTION_WORDS = {
    "sign_in", "sign_up", "sign_out", "signin", "signup", "signout", "login", "logout", "log_in", "register", "new", "edit",
    "settings", "auth", "oauth", "saml", "sso", "me", "self", "password", "confirmation", "unlock", "current", "index",
    "list", "search", "emails", "security", "dashboard", "admin",
}
_TOKENISH = re.compile(r"^[A-Za-z0-9_\-=.~%]{16,}$")
_UUID = re.compile(r"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$", re.I)
_FILE_EXT = re.compile(r"\.[A-Za-z0-9]{1,6}$")
REDACTED_SEGMENT = "{redacted}"


def _identifying(seg: str, prev: str | None) -> bool:
    s = unquote(seg)
    low = s.lower()
    if not s:
        return False
    if "@" in s or s.startswith("~") or _UUID.match(s) or re.fullmatch(r"\d{5,}", s):
        return True
    if _TOKENISH.match(s) and re.search(r"\d", s) and re.search(r"[A-Za-z]", s):
        return True
    if len(s) >= 32 and re.fullmatch(r"[A-Za-z0-9_\-]+", s):
        return True
    if prev is not None and prev.lower() in _USER_KEYWORDS and low not in _ACTION_WORDS:
        return True
    return bool(re.search(r"[a-z][A-Z]|[A-Z][a-z]+[A-Z]", s) and not _FILE_EXT.search(s) and low not in _ACTION_WORDS)


def strip_url(url: Any) -> str | None:
    """scheme://host[:port]/path with query, fragment, userinfo and user-identifying path segments
    removed (C5; heuristic: e-mails, '~user', UUIDs, long numeric ids, opaque tokens, CamelCase
    handles and the segment after users/, profile/, password_reset/...). None for non-web schemes."""
    if not isinstance(url, str) or not url.strip():
        return None
    try:
        parts = urlsplit(url.strip())
        host = parts.hostname
        port = parts.port
    except ValueError:
        return None
    if parts.scheme.lower() not in ("http", "https", "ftp") or not host:
        return None
    netloc = host.lower().rstrip(".") + (f":{port}" if port else "")
    out, prev = [], None
    for seg in parts.path.split("/"):
        out.append(REDACTED_SEGMENT if seg and _identifying(seg, prev) else seg)
        prev = seg if seg else prev
    return f"{parts.scheme.lower()}://{netloc}{'/'.join(out)}"


def sanitize_urls(data: Any) -> dict[str, list[dict[str, Any]]] | None:
    """urls-by-domain -> {employees_urls, clients_urls} of stripped, merged rows; None when the
    answer carries no URL lists (could not verify)."""
    if not isinstance(data, dict) or not isinstance(data.get("data"), dict):
        return None
    block = data["data"]
    if not any(isinstance(block.get(k), list) for k in ("employees_urls", "clients_urls")):
        return None
    out: dict[str, list[dict[str, Any]]] = {}
    for key in ("employees_urls", "clients_urls"):
        merged: dict[str, dict[str, Any]] = {}
        for row in block.get(key) if isinstance(block.get(key), list) else []:
            if not isinstance(row, dict):
                continue
            url = strip_url(row.get("url"))
            if not url:
                continue
            entry = merged.setdefault(url, {"url": url, "host": urlsplit(url).hostname, "occurrence": 0})
            entry["occurrence"] += _int(row.get("occurrence")) or 0
        out[key] = sorted(merged.values(), key=lambda e: (-e["occurrence"], e["url"]))
    return out


# --------------------------------------------------------------------------------------
# severity (C6-C8)
# --------------------------------------------------------------------------------------


def severity_for(record: dict[str, Any], *, now: _dt.datetime, own_verified: bool) -> tuple[str, str]:
    """(severity, label) of one sanitized record for a non-generic identity."""
    corp = record.get("total_corporate_services") or 0
    if not own_verified:
        return ("medium" if corp > 0 else "low"), "third-party context (no exposure score)"
    when = None
    if record.get("date_compromised"):
        try:
            when = _dt.datetime.fromisoformat(record["date_compromised"]).replace(tzinfo=_dt.timezone.utc)
        except ValueError:
            when = None
    if when is not None and (now - when) <= _dt.timedelta(days=RECENT_DAYS):
        return "critical", "corporate identity in a recent infostealer log"
    if corp > 0:
        return "high", "historical exposure with corporate services, verify rotation"
    return "medium", "historical exposure, verify rotation"


def _failure(exc: BaseException) -> tuple[Status, str] | None:
    """Per-feed 'could not verify' mapping for the two-feed domain module (rule 5)."""
    table = (
        ("QuotaExceeded", Status.QUOTA, "quota"), ("RateLimited", Status.RATE_LIMITED, "rate_limited"),
        ("Blocked", Status.BLOCKED, "challenge"), ("AuthRequired", Status.BLOCKED, "challenge"),
        ("DeadlineExceeded", Status.ERROR, "timeout"), ("OfflineError", Status.UNAVAILABLE, "offline"),
        ("NetworkError", Status.ERROR, "error"), ("HttpError", Status.ERROR, "error"),
    )
    if type(exc).__name__ in ("RequestCapReached", "Cancelled", "PolicyError", "ConfigError"):
        return None
    for name, status, code in table:
        klass = getattr(_http, name, None)
        if klass is not None and isinstance(exc, klass):
            given = str(getattr(exc, "reason_code", "") or "")
            if status is Status.BLOCKED and given in ("challenge", "geo_block", "login_wall", "circuit", "hostile_host"):
                return status, given
            if status is Status.ERROR and given in ("timeout", "error"):
                return status, given
            return status, code
    return None


def _ctx_now(ctx: Any) -> _dt.datetime:
    now = ctx.now() if callable(getattr(ctx, "now", None)) else _dt.datetime.now(_dt.timezone.utc)
    return now if now.tzinfo else now.replace(tzinfo=_dt.timezone.utc)


# --------------------------------------------------------------------------------------
# identity searches
# --------------------------------------------------------------------------------------


@register
class HudsonRock(Module):
    name = "hudson_rock"
    title = "Hudson Rock infostealer exposure (identity)"
    description = (
        "Infostealer-log exposure METADATA for an own-domain e-mail address, an analyst-typed username or an IP of an "
        "org CIDR from Hudson Rock Cavalier's free tools: compromise dates, stealer families, service counts."
    )
    category = "breach_leak"
    accepts = {T.EMAIL, T.USERNAME, T.IPV4}
    run_on = "own_assets"
    tags = {"free"}
    reference = "https://www.hudsonrock.com/free-tools"
    notice = _NOTICE
    terms = "unknown"  # A1 initial class: Hudson Rock free tools (P134 cond 4)
    opsec = Opsec.PASSIVE
    disclosure = "third_party"
    provider = "hudsonrock"
    sources = (SRC_EMAIL, SRC_USERNAME, SRC_IP)
    hosts = ("cavalier.hudsonrock.com",)
    access_model = "free_noauth_limited"
    max_requests = 1
    expected_latency = 1.5
    timeout = 40.0  # one 30 s request (C10) plus margin
    min_interval = 1.0
    cache_ttl = 7 * 86400  # sanitized JSON only (A4: at most 7 days)
    default_enabled = False  # terms unknown (A3 BR2)
    max_pivots = 0

    def run(self, entity: Entity, ctx: Any) -> ModuleResult:
        res = self.result(entity)
        own_verified, why = self._scope(entity, ctx)
        if why:
            code = "own_asset" if entity.type is T.IPV4 else "privacy"
            return res.mark("skipped", why, reason_code=code)
        endpoint, param, source = {
            T.EMAIL: ("search-by-email", "email", SRC_EMAIL),
            T.USERNAME: ("search-by-username", "username", SRC_USERNAME),
            T.IPV4: ("search-by-ip", "ip", SRC_IP),
        }[entity.type]
        data = ctx.http.get_json(API.format(endpoint=endpoint), params={param: entity.value}, source=source, timeout=REQUEST_TIMEOUT)
        clean = sanitize_identity(data)
        if clean is None:
            return res.mark("error", "unexpected Hudson Rock answer (no stealer list): could not verify")
        res.raw = {source: clean}
        records = clean["stealers"]
        if not records:
            return res  # the provider answered with an empty stealer list: EMPTY
        generic = self._generic(entity, len(records))
        res.attr("infostealer", True)
        res.attr("stealer_logs", records[:MAX_RECORDS])
        families = sorted({r["stealer_family"] for r in records if r.get("stealer_family")})
        res.attr("malware_family", families)
        if generic:
            res.attr("generic_address", generic)
            res.finding(
                "Generic address in infostealer logs",
                "info",
                f"{len(records)} infected computer(s) list this {entity.type.value} ({generic}): a shared, role or test identity. "
                "Context only, never scored as exposure.",
                confidence="possible",
                criterion=f"generic/role/test identity (A4 list) or >= {GENERIC_COMPUTERS} computers for one identity (P134 cond 6)",
                data={"computers": len(records), "generic": generic},
                tags=["info", "infostealer", "context_only"],
                source=source,
            )
            return res
        now = _ctx_now(ctx)
        for i, record in enumerate(records[:MAX_RECORDS]):
            severity, label = severity_for(record, now=now, own_verified=own_verified)
            date = record.get("date_compromised") or "unknown date"
            corp = record.get("total_corporate_services")
            user = record.get("total_user_services")
            third_party = not own_verified
            res.finding(
                "Identity found in an infostealer log",
                severity,
                f"{label}: compromised {date}"
                + (f", family {record['stealer_family']}" if record.get("stealer_family") else "")
                + (f", corporate services {corp}" if corp is not None else "")
                + (f", user services {user}" if user is not None else "")
                + ". Next steps: " + "; ".join(NEXT_STEPS) + ". " + NOT_FOR_LOGIN,
                confidence="possible" if third_party else "probable",
                criterion=(
                    f"Hudson Rock {source.split('.', 1)[1].replace('_', '-')}: stealer log dated {date}"
                    + (" (third-party identity: analyst-typed seed with --breach-scope all; context, at most MEDIUM)" if third_party else " (verified org-profile domain)")
                ),
                data={**record, "next_steps": list(NEXT_STEPS), "own_verified": own_verified},
                tags=["infostealer", "context_only"] if third_party else ["infostealer", "credential_exposure"],
                source=source,
                observed_first=record.get("date_compromised"),
                key=f"{date}#{i}",
            )
        return res

    @staticmethod
    def _scope(entity: Entity, ctx: Any) -> tuple[bool, str]:
        """(own verified identity?, skip reason). Defence in depth next to the policy gate (A4/A11)."""
        org = getattr(ctx, "org", None)
        if entity.type is T.IPV4:
            try:
                own = org.owns(entity) if org is not None else None
            except Exception:  # noqa: BLE001 - an unreadable profile owns nothing
                own = None
            if own is not None and getattr(own, "own", False) and getattr(own, "kind", "") == "cidr":
                return True, ""
            return False, "search-by-ip only for IPs inside org_profile CIDRs (P134 cond 7)"
        if entity.type is T.EMAIL and org is not None:
            try:
                if org.is_verified_domain(entity.value.rsplit("@", 1)[-1]):
                    return True, ""
            except Exception:  # noqa: BLE001
                pass
        options = getattr(ctx, "options", None)
        scope_all = str(getattr(options, "breach_scope", "own") or "own").strip().lower() == "all"
        purpose = str(getattr(options, "purpose", "") or "").strip()
        if scope_all and purpose and bool(getattr(ctx, "is_seed", False)):
            return False, ""
        return False, "breach check skipped: not an org domain (third-party identities need an analyst-typed seed, --breach-scope all and --purpose)"

    @staticmethod
    def _generic(entity: Entity, computers: int) -> str | None:
        if entity.type is T.EMAIL:
            kind = generic_address_kind(entity.value)
            if kind:
                return kind
        if entity.type in (T.EMAIL, T.USERNAME) and computers >= GENERIC_COMPUTERS:
            return f"shared ({computers} computers)"
        return None


# --------------------------------------------------------------------------------------
# own-domain searches
# --------------------------------------------------------------------------------------


@register
class HudsonRockDomain(Module):
    name = "hudson_rock_domain"
    title = "Hudson Rock infostealer exposure (own domain)"
    description = (
        "Infostealer counts for a verified own domain (employees, users, third parties, stealer families) and the URLs "
        "of the domain seen in infostealer logs (stripped, attack-surface context) from Hudson Rock Cavalier's free tools."
    )
    category = "breach_leak"
    accepts = {T.DOMAIN}
    produces = {T.URL, T.DOMAIN}
    run_on = "own_assets_only"
    tags = {"free"}
    reference = "https://www.hudsonrock.com/free-tools"
    notice = _NOTICE
    terms = "unknown"
    opsec = Opsec.PASSIVE
    disclosure = "third_party"
    provider = "hudsonrock"
    sources = (SRC_DOMAIN, SRC_URLS)
    hosts = ("cavalier.hudsonrock.com",)
    access_model = "free_noauth_limited"
    max_requests = 2
    expected_latency = 2.0
    timeout = 75.0  # two 30 s requests (C10) plus margin
    min_interval = 1.0
    cache_ttl = 7 * 86400
    default_enabled = False
    max_pivots = MAX_URLS + 20

    def run(self, entity: Entity, ctx: Any) -> ModuleResult:
        res = self.result(entity)
        org = getattr(ctx, "org", None)
        try:
            verified = bool(org is not None and org.is_verified_domain(entity.value))
        except Exception:  # noqa: BLE001
            verified = False
        if not verified:
            return res.mark("skipped", "own-asset-only source: needs a txt_verified or attested org-profile domain (v3lum org verify)", reason_code="own_asset")
        allowed = getattr(ctx, "allowed_sources", None)
        feeds = [s for s in self.sources if allowed is None or s in allowed]
        failures: list[tuple[Status, str, str]] = []
        raw: dict[str, Any] = {}
        answered = 0
        for source in feeds:
            try:
                if source == SRC_DOMAIN:
                    data = ctx.http.get_json(API.format(endpoint="search-by-domain"), params={"domain": entity.value}, source=source, timeout=REQUEST_TIMEOUT)
                    clean = sanitize_domain(data)
                    if clean is None:
                        raise _Unreadable("unexpected Hudson Rock search-by-domain answer (no counts): could not verify")
                    raw[source] = {k_in: clean[k_out] for k_in, k_out in DOMAIN_COUNTS if clean[k_out] is not None}
                    raw[source]["stealerFamilies"] = dict(clean["stealer_families"])
                    self._counts(res, entity, clean)
                else:
                    # no-store: the rows are stripped in memory, unstripped URLs never reach the cache (C5)
                    data = ctx.http.get_json(API.format(endpoint="urls-by-domain"), params={"domain": entity.value}, source=source, timeout=REQUEST_TIMEOUT, ttl=0, cache_if=lambda _resp: False)
                    clean_urls = sanitize_urls(data)
                    if clean_urls is None:
                        raise _Unreadable("unexpected Hudson Rock urls-by-domain answer (no URL lists): could not verify")
                    raw[source] = {"data": {k: [{"url": r["url"], "occurrence": r["occurrence"]} for r in v] for k, v in clean_urls.items()}}
                    self._urls(res, entity, clean_urls)
                answered += 1
            except _Unreadable as exc:
                failures.append((Status.ERROR, "error", str(exc)))
                res.source_status(source, Status.ERROR, reason_code="error", reason=str(exc))
            except Exception as exc:  # noqa: BLE001 - per-feed rule 5, the rest propagates
                mapped = _failure(exc)
                if mapped is None:
                    raise
                failures.append((mapped[0], mapped[1], str(exc)[:200]))
                res.source_status(source, mapped[0], reason_code=mapped[1], reason=str(exc)[:200])
        res.raw = raw
        if not answered:
            if not feeds:
                return res.mark("skipped", f"no feed allowed for this run ({LICENCE_NOTE})", reason_code="licence")
            status, code, _text = failures[0]
            return res.mark(status, "; ".join(t for _s, _c, t in failures), reason_code=code)
        return res

    @staticmethod
    def _counts(res: ModuleResult, entity: Entity, clean: dict[str, Any]) -> None:
        res.attr("stealer_exposure", {k: v for k, v in clean.items() if v not in (None, {})})
        families = sorted(clean["stealer_families"])
        res.attr("malware_family", families)
        employees, users, third = (clean.get(k) or 0 for k in ("employees", "users", "third_parties"))
        if not (employees or users or third):
            return
        res.attr("infostealer", True)
        if employees:
            severity, title = "high", "Employee machines of this own domain in infostealer logs"
        elif users:
            severity, title = "medium", "Users of this own domain in infostealer logs"
        else:
            severity, title = "low", "Third parties of this own domain in infostealer logs"
        res.finding(
            title,
            severity,
            f"Hudson Rock counts for {entity.value}: {employees} employee, {users} user and {third} third-party compromised "
            f"machine(s) (counts only). Next steps: " + "; ".join(NEXT_STEPS) + ". " + NOT_FOR_LOGIN,
            confidence="probable",
            criterion="Hudson Rock search-by-domain counts for a verified org-profile domain (stealer domain search, counts only)",
            data={"employees": employees, "users": users, "third_parties": third, "stealer_families": families, "next_steps": list(NEXT_STEPS)},
            tags=["infostealer", "credential_exposure"] if employees else ["infostealer"],
            source=SRC_DOMAIN,
        )

    @staticmethod
    def _urls(res: ModuleResult, entity: Entity, clean: dict[str, list[dict[str, Any]]]) -> None:
        domain = entity.value.lower()
        rows = [("employee", r) for r in clean.get("employees_urls", [])] + [("client", r) for r in clean.get("clients_urls", [])]
        hosts: set[str] = set()
        for _kind, row in rows[:MAX_URLS]:
            res.pivot(T.URL, row["url"], "stealer_log_url", confidence="possible", expand=False, note="URL seen in infostealer logs (stripped): attack-surface context, never contacted automatically")
            host = (row.get("host") or "").lower()
            try:
                ipaddress.ip_address(host)
                continue  # an IP literal is not a subdomain
            except ValueError:
                pass
            if host and host != domain and host.endswith("." + domain):
                hosts.add(host)
        for host in sorted(hosts)[:20]:
            res.pivot(T.DOMAIN, host, "subdomain", confidence="probable", expand=False, note="host of a URL seen in infostealer logs")
        if rows:
            res.attr("subdomains", sorted(hosts))
            res.finding(
                "URLs of this own domain seen in infostealer logs",
                "info",
                f"{len(clean.get('employees_urls', []))} employee and {len(clean.get('clients_urls', []))} client URL(s) (stripped to scheme, host "
                "and path) appear in infostealer logs: login portals and internal hosts in the attack surface. Never contacted automatically.",
                confidence="probable",
                criterion="Hudson Rock urls-by-domain for a verified org-profile domain",
                data={"employee_urls": len(clean.get("employees_urls", [])), "client_urls": len(clean.get("clients_urls", []))},
                tags=["infostealer", "exposure"],
                source=SRC_URLS,
            )


class _Unreadable(Exception):
    """An answer without the expected structure (could not verify)."""
