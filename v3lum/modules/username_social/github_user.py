"""GitHub user enrichment: profile, public SSH/GPG keys, commit e-mails and activity of a login (P111).

REST API and plain-text endpoints only (P111 cond 1): ``api.github.com/users/{u}``,
``/users/{u}/events/public`` and ``/repos/{r}/commits?author={u}`` when event payloads lack commits;
``github.com/{u}.keys``, ``github.com/{u}.gpg`` and one commit's ``.patch`` as plain-text GETs capped
at 1 MB. github.com/search and every other HTML page are never parsed (GitHub AUP s.7): an HTML page
where data was expected is 'could not verify' (module marker ``github_user_html_instead_of_data``).

This file is also the **one shared GitHub client and budget** (cond 3) of github_user,
github_user_search, git_metadata_identity (P115), osv_ghsa (P185) and org_code_footprint (P359):
:class:`GitHubClient` (REST headers, the key ``github`` as a Bearer header to api.github.com only,
1 MB plain-text cap) and :func:`github_budget` (one X-RateLimit view per runtime: 60 req/h keyless per
egress IP, 5,000/h with the key, search 10/min; ``X-RateLimit-Remaining`` honoured before every API
call). 403/429 with a rate-limit message are RATE_LIMITED (provider marker ``github_user_rate_limit``),
404 is ABSENT. :func:`decode_noreply` is the one noreply helper (cond 6).

* Key ``github`` (V3LUM_KEY_GITHUB; GITHUB_TOKEN/GH_TOKEN aliases) from a team machine account or a
  GitHub App, never an analyst's personal token (cond 4); the doctor self-test refuses classic tokens
  whose X-OAuth-Scopes header is not empty.
* Without a token: analyst-typed seeds only, and the one coverage line 'GitHub anonymous limit 60/h:
  add a token with v3lum keys setup' (NEEDS_KEY for pivots, RATE_LIMITED when the budget is spent)
  instead of per-entity errors (cond 5).
* Commit and event e-mails only for seed accounts (and never for organisations). Noreply addresses
  are decoded into account links and never reported as e-mail exposures; system addresses are
  dropped; third-party and co-author addresses are never collected (cond 6). Seed e-mails pivot with
  relation commit_email (gpg_uid_email for GPG UIDs), PROBABLE, grouped per address with commit count
  and first/last date, ``expand=False`` unless the address is already a case entity; they are case
  data (retention_days) and never sent to breach modules automatically (cond 7).
* .keys/.gpg are stored as SHA-256 fingerprints and GPG UIDs (cond 8); the Ceos activity classifier
  (C0268) yields attributes only (activity level from public REST events, never a sensitive trait).
"""

from __future__ import annotations

import base64
import binascii
import datetime as _dt
import hashlib
import json
import re
import struct
import threading
import weakref
from collections import Counter
from email.header import decode_header, make_header
from email.utils import parseaddr, parsedate_to_datetime
from typing import Any
from urllib.parse import quote, urlsplit

from v3lum.core.entities import Entity, platform_for_url
from v3lum.core.entities import EntityType as T
from v3lum.core.http import (
    AuthRequired,
    Blocked,
    DeadlineExceeded,
    HttpError,
    NetworkError,
    OfflineError,
    QuotaExceeded,
    RateLimited,
)
from v3lum.core.models import ModuleResult, Opsec, Status
from v3lum.core.module import HealthCheck, HealthResult, Module, register

PROVIDER = "github"
SOURCE_API = "github.github_user_api"
SOURCE_WEB = "github.github_user_web"
SOURCE_SEARCH = "github.github_user_search"
API_HOST = "api.github.com"
WEB_HOST = "github.com"
API_ROOT = "https://api.github.com"
API_HEADERS = {"Accept": "application/vnd.github+json", "X-GitHub-Api-Version": "2022-11-28"}
GITHUB_ANON_COVERAGE_LINE = "GitHub anonymous limit 60/h: add a token with v3lum keys setup"  # P111 cond 5
GITHUB_LIMITS = {"core_keyless_per_hour": 60, "core_keyed_per_hour": 5000, "search_keyless_per_min": 10, "search_keyed_per_min": 30}
PLAINTEXT_CAP = 1024 * 1024  # P111 cond 1: .keys/.gpg/.patch capped at 1 MB
PIVOT_RESERVE_SHARE = 0.1  # keyed budget kept for analyst-typed seeds (P334 spirit)
EVENTS_TTL = 6 * 3600
PATCH_TTL = 7 * 86400
SEARCH_TTL = 3600
MAX_COMMIT_REPOS_KEYED = 4
MAX_COMMIT_REPOS_KEYLESS = 2
MAX_PATCHES = 2
MAX_EMAIL_PIVOTS = 20

NOREPLY_RE = re.compile(r"^(\d+)\+([A-Za-z0-9-]+)@users\.noreply\.github\.com$", re.I)  # P111 cond 6 (exact form)
_LEGACY_NOREPLY_RE = re.compile(r"^([A-Za-z0-9-]+)@users\.noreply\.github\.com$", re.I)
_BOT_NOREPLY_RE = re.compile(r"^(\d+)\+([A-Za-z0-9-]+)\[bot\]@users\.noreply\.github\.com$", re.I)
_LOGIN_RE = re.compile(r"^[A-Za-z0-9](?:[A-Za-z0-9-]{0,38})$")
_REPO_RE = re.compile(r"^[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+$")
_RESERVED_PATHS = frozenset({
    "orgs", "settings", "search", "login", "logout", "marketplace", "explore", "topics", "sponsors", "features", "pricing",
    "enterprise", "about", "trending", "collections", "events", "issues", "pulls", "notifications", "new", "codespaces",
    "copilot", "readme", "site", "apps", "team", "customer-stories", "resources", "solutions", "users", "join", "signup",
})
_SYSTEM_EMAILS = frozenset({
    "noreply@github.com", "no-reply@github.com", "notifications@github.com", "support@github.com", "action@github.com",
    "actions@github.com", "github-actions@github.com", "web-flow@github.com", "none@none", "nobody@nowhere",
    "unknown@unknown", "(none)@(none)",
})
_LOCAL_SUFFIXES = (".local", ".localdomain", ".lan", ".internal", ".invalid", ".home.arpa", ".localhost")
_SYSTEM_LOGINS = frozenset({"web-flow", "invalid-email-address", "ghost", "github-actions[bot]", "dependabot[bot]"})


# ======================================================================================
# small helpers
# ======================================================================================

_HTML_START_RE = re.compile(r"^\s*(?:<!doctype\s+html|<html\b|<head\b|<body\b|<!--)", re.I)
_EMAIL_SHAPE_RE = re.compile(r"^[^@\s<>()\[\],;:\"]+@[^@\s<>()\[\],;:\"]+$")


def _to_text(raw: Any, cap: int | None = None) -> tuple[str, bool]:
    if raw is None:
        return "", False
    if isinstance(raw, (bytes, bytearray, memoryview)):
        data = bytes(raw)
        truncated = cap is not None and len(data) > cap
        return (data[:cap] if truncated else data).decode("utf-8", errors="replace"), truncated
    if isinstance(raw, str):
        if cap is not None and len(raw) > cap // 4:
            enc = raw.encode("utf-8", errors="replace")
            if len(enc) > cap:
                return enc[:cap].decode("utf-8", errors="ignore"), True
        return raw, False
    return "", False


def looks_like_html(raw: Any) -> bool:
    """True when a body is an HTML document (an error, login or challenge page instead of data)."""
    if isinstance(raw, (dict, list)):
        return False
    text, _ = _to_text(bytes(raw[:4096]) if isinstance(raw, (bytes, bytearray)) else raw)
    head = text[:4096].lstrip("﻿")
    return bool(_HTML_START_RE.match(head) and re.search(r"<html\b|<!doctype\s+html|<title\b|<body\b", head, re.I))


def load_json(raw: Any) -> Any:
    """Parsed JSON (dict or list) or None for empty, HTML, invalid JSON or other types."""
    if isinstance(raw, (dict, list)):
        return raw
    text, _ = _to_text(raw)
    text = text.lstrip("﻿").strip()
    if not text or text[0] not in "[{":
        return None
    try:
        return json.loads(text)
    except ValueError:
        return None


def _lower_headers(headers: Any) -> dict[str, str]:
    out: dict[str, str] = {}
    if not headers:
        return out
    try:
        items = headers.items() if hasattr(headers, "items") else headers
        for key, val in items:
            if key is None:
                continue
            k = str(key).strip().lower()
            v = "" if val is None else str(val).strip()
            out[k] = v if k not in out else out[k] + ", " + v
    except (TypeError, ValueError):
        return {}
    return out


def _int(value: Any) -> int | None:
    if isinstance(value, bool):
        return None
    if isinstance(value, int):
        return value
    if isinstance(value, float) and value == value and abs(value) < 1e18:
        return int(value)
    if isinstance(value, str) and re.fullmatch(r"\s*[+-]?\d{1,18}\s*", value):
        return int(value)
    return None


def _str(value: Any, cap: int | None = None) -> str | None:
    if not isinstance(value, str):
        return None
    s = value.strip()
    if cap:
        s = s[:cap]
    return s or None


def _parse_dt(value: Any) -> _dt.datetime | None:
    if value is None or isinstance(value, bool):
        return None
    if isinstance(value, _dt.datetime):
        d = value
    elif isinstance(value, (int, float)):
        try:
            return _dt.datetime.fromtimestamp(value, _dt.timezone.utc)
        except (OverflowError, OSError, ValueError):
            return None
    elif isinstance(value, str) and value.strip():
        s = value.strip()
        try:
            d = _dt.datetime.fromisoformat(s[:-1] + "+00:00" if s.endswith(("Z", "z")) else s)
        except ValueError:
            try:
                d = parsedate_to_datetime(s)
            except (TypeError, ValueError, IndexError):
                return None
            if d is None:
                return None
    else:
        return None
    if d.tzinfo is None:
        d = d.replace(tzinfo=_dt.timezone.utc)
    return d.astimezone(_dt.timezone.utc)


def iso_utc(value: Any) -> str | None:
    """ISO 8601 / RFC 2822 / epoch seconds -> 'YYYY-MM-DDTHH:MM:SSZ' (UTC) or None."""
    d = _parse_dt(value)
    return d.strftime("%Y-%m-%dT%H:%M:%SZ") if d else None


def normalise_email(value: Any) -> str | None:
    """Lower-cased e-mail address or None ('<>' and 'mailto:' stripped)."""
    s = _str(value, 320)
    if not s:
        return None
    s = s.strip("<>").strip()
    if s.lower().startswith("mailto:"):
        s = s[7:]
    return s.lower() if _EMAIL_SHAPE_RE.match(s) else None


def _safe_url(value: Any) -> str | None:
    s = _str(value, 2048)
    if not s:
        return None
    try:
        sp = urlsplit(s)
    except ValueError:
        return None
    return s if sp.scheme in ("http", "https") and sp.hostname else None


# ======================================================================================
# logins, URLs and the noreply helper (P111 cond 1 and 6)
# ======================================================================================


def normalise_github_login(value: Any) -> str | None:
    """'login', '@login' or 'https://github.com/login[/...]' -> login, else None."""
    s = _str(value, 300)
    if not s:
        return None
    m = re.match(r"^(?:https?://)?(?:www\.)?github\.com/([^/?#\s]+)", s, re.I)
    if m:
        s = m.group(1)
    elif re.match(r"^[a-z][a-z0-9+.-]*://", s, re.I):
        return None  # a URL on another host is never a GitHub login
    s = s.lstrip("@")
    if s.lower() in _RESERVED_PATHS:
        return None
    return s if _LOGIN_RE.match(s) and "--" not in s and not s.endswith("-") else None


def github_login_of(entity: Entity) -> str | None:
    """The GitHub login an entity names: a username, a github.com profile/repo URL or 'github:<login>'."""
    if entity.type is T.SOCIAL_ACCOUNT:
        platform, _, handle = entity.value.partition(":")
        return normalise_github_login(handle) if platform == "github" else None
    if entity.type in (T.USERNAME, T.URL):
        return normalise_github_login(entity.value)
    return None


def github_repo_commits_path(repo: str) -> str | None:
    """P111 cond 1 fallback when event payloads lack commits: /repos/{r}/commits (author= in params)."""
    return f"/repos/{repo}/commits" if isinstance(repo, str) and _REPO_RE.match(repo) and ".." not in repo else None


def github_patch_url(repo: str, sha: str) -> str | None:
    """P111 cond 1: the plain-text .patch of one public commit (GET capped at 1 MB)."""
    if github_repo_commits_path(repo) is None or not isinstance(sha, str) or not re.fullmatch(r"[0-9a-f]{7,40}", sha):
        return None
    return f"https://github.com/{repo}/commit/{sha}.patch"


def decode_noreply(email: Any) -> dict[str, Any] | None:
    """P111 cond 6 shared helper: a GitHub noreply address -> account link {id, login, bot, url}, else None.

    ``12345678+login@users.noreply.github.com`` -> id 12345678 and the login; the legacy
    ``login@users.noreply.github.com`` form has id None; ``...[bot]@`` addresses are flagged ``bot``
    (system addresses). Noreply addresses are never e-mail exposures.
    """
    s = _str(email, 320)
    if not s:
        return None
    s = s.strip("<>").strip()
    m = NOREPLY_RE.match(s)
    if m:
        return {"id": int(m.group(1)), "login": m.group(2), "bot": False, "url": "https://github.com/" + m.group(2)}
    m = _BOT_NOREPLY_RE.match(s)
    if m:
        return {"id": int(m.group(1)), "login": m.group(2) + "[bot]", "bot": True, "url": None}
    m = _LEGACY_NOREPLY_RE.match(s)
    if m:
        return {"id": None, "login": m.group(1), "bot": False, "url": "https://github.com/" + m.group(1)}
    return None


def system_email_reason(email: Any) -> str | None:
    """P111 cond 6: why a commit/UID address is a system address (dropped), else None.

    Noreply user addresses are not system addresses: :func:`decode_noreply` turns them into links.
    """
    e = normalise_email(email)
    if not e:
        return "not an e-mail address"
    nr = decode_noreply(e)
    if nr is not None:
        return "GitHub bot noreply address" if nr["bot"] else None
    if e.endswith("@users.noreply.github.com"):
        return "undecodable GitHub noreply address"
    if e in _SYSTEM_EMAILS:
        return "GitHub/placeholder system address"
    domain = e.rpartition("@")[2]
    if domain in ("localhost", "localhost.localdomain") or "." not in domain or domain.endswith(_LOCAL_SUFFIXES):
        return "local host address (not a mailbox)"
    return None


# ======================================================================================
# rate limits, tokens (P111 cond 3-5)
# ======================================================================================


def github_rate_budget(headers: Any) -> dict[str, Any]:
    """X-RateLimit-* of one answer: {limit, remaining, used, reset, resource, retry_after_s, keyless}."""
    h = _lower_headers(headers)
    out: dict[str, Any] = {k: _int(h.get("x-ratelimit-" + k)) for k in ("limit", "remaining", "used", "reset")}
    out["resource"] = h.get("x-ratelimit-resource") or None
    out["retry_after_s"] = _int(h.get("retry-after"))
    out["keyless"] = (out["limit"] == GITHUB_LIMITS["core_keyless_per_hour"]) if out["limit"] is not None else None
    return out


_TOKEN_PREFIXES = (("github_pat_", "fine_grained"), ("ghp_", "classic"), ("gho_", "oauth_app"), ("ghu_", "app_user"),
                   ("ghs_", "app_installation"), ("ghr_", "refresh"))


def github_token_kind(token: Any) -> str:
    """P111 cond 4 helper: the kind of a token from its prefix only (the value is never stored or echoed)."""
    if not isinstance(token, str):
        return "unknown"
    t = token.strip()
    for prefix, kind in _TOKEN_PREFIXES:
        if t.startswith(prefix):
            return kind
    return "classic_legacy" if re.fullmatch(r"[0-9a-f]{40}", t) else "unknown"


def github_scope_problem(headers: Any) -> str | None:
    """P111 cond 4 doctor check: why a classic token carrying scopes (X-OAuth-Scopes not empty) is
    refused, else None. Fine-grained tokens send no X-OAuth-Scopes header ('public repositories,
    read-only, no permissions')."""
    scopes = _lower_headers(headers).get("x-oauth-scopes")
    if scopes:
        listed = ", ".join(sorted({s.strip() for s in scopes.split(",") if s.strip()}))
        return (f"classic token with scopes ({listed}): use a no-scope token of the team machine account or a "
                "fine-grained token (public repositories, read-only, no permissions)")
    return None


def parse_github_rate_limit(raw: Any) -> dict[str, dict[str, int | None]]:
    """GET /rate_limit body -> {resource: {limit, remaining, used, reset}} (doctor and budget display)."""
    data = load_json(raw)
    if not isinstance(data, dict) or not isinstance(data.get("resources"), dict):
        return {}
    return {str(name): {k: _int(val.get(k)) for k in ("limit", "remaining", "used", "reset")}
            for name, val in data["resources"].items() if isinstance(val, dict)}


class GitHubBudget:
    """P111 cond 3: the shared X-RateLimit view of every GitHub REST user of one runtime.

    Every API answer updates the window of its resource (core, search...); before a call the client
    refuses (RateLimited, nothing sent) while the window's remaining budget is at or below the
    caller's reserve and its reset time is in the future. Answers served from the HTTP cache carry
    stale headers and are not noted.
    """

    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._state: dict[str, dict[str, int]] = {}

    def note(self, headers: Any, now: float) -> None:
        b = github_rate_budget(headers)
        if b["remaining"] is None or b["reset"] is None:
            return
        resource = b["resource"] or "core"
        with self._lock:
            self._state[resource] = {"limit": b["limit"] or 0, "remaining": b["remaining"], "reset": b["reset"], "seen": int(now)}

    def window(self, resource: str) -> dict[str, int] | None:
        with self._lock:
            st = self._state.get(resource)
            return dict(st) if st else None

    def check(self, resource: str, now: float, *, keyed: bool, reserve: int = 0) -> None:
        st = self.window(resource)
        if not st or st["reset"] <= now or st["remaining"] > reserve:
            return
        until = _dt.datetime.fromtimestamp(st["reset"], _dt.timezone.utc).strftime("%H:%M UTC")
        if not keyed:
            raise RateLimited(f"{GITHUB_ANON_COVERAGE_LINE} (budget spent until {until}; nothing sent)")
        raise RateLimited(f"GitHub {resource} budget at its reserve until {until}: request not sent")

    def snapshot(self) -> dict[str, dict[str, int]]:
        with self._lock:
            return {k: dict(v) for k, v in self._state.items()}


_BUDGETS: weakref.WeakKeyDictionary[Any, GitHubBudget] = weakref.WeakKeyDictionary()
_BUDGETS_LOCK = threading.Lock()


def github_budget(ctx: Any) -> GitHubBudget:
    """The GitHubBudget of the runtime behind ``ctx`` (one per HTTP client, shared by every module)."""
    owner = getattr(getattr(ctx, "http", None), "client", None)  # v3lum-lint: allow LINT-01 -- identity key of the per-client budget table only; no request goes through it
    try:
        with _BUDGETS_LOCK:
            budget = _BUDGETS.get(owner)
            if budget is None:
                budget = GitHubBudget()
                _BUDGETS[owner] = budget
            return budget
    except TypeError:  # an owner that cannot be weak-referenced: a budget for this call only
        return GitHubBudget()


def _usable(ctx: Any, resp: Any, absent: frozenset[int]) -> bool:
    """ctx.http.check semantics, except that an unclassified status in ``absent`` is a documented absence."""
    try:
        ctx.http.check(resp)
    except HttpError:
        if resp.status in absent and getattr(resp, "classification", None) is None:
            return False
        raise
    return True


class GitHubClient:
    """The shared GitHub client (P111 cond 3): REST JSON from api.github.com with the budget and the
    key ``github`` (Bearer header, api.github.com only), plain text from github.com capped at 1 MB.

    Raises like ``ctx.http`` (RateLimited, Blocked, AuthRequired, QuotaExceeded, HttpError...): a
    keyless rate limit carries the one coverage line of cond 5.
    """

    def __init__(self, ctx: Any, *, source: str = SOURCE_API) -> None:
        self.ctx = ctx
        self.source = source
        key = getattr(ctx, "key", None)
        self.token = (key("github") if callable(key) else "") or ""
        self.keyed = bool(self.token)
        self.budget = github_budget(ctx)
        self.scope_problem: str | None = None
        self.api_calls = 0

    def _now(self) -> float:
        return self.ctx.now().timestamp()

    def headers(self) -> dict[str, str]:
        h = dict(API_HEADERS)
        if self.token:
            h["Authorization"] = f"Bearer {self.token}"
        return h

    def pivot_reserve(self, resource: str = "core") -> int:
        """Budget kept for analyst-typed seeds: pivots stop at PIVOT_RESERVE_SHARE of the window."""
        st = self.budget.window(resource)
        limit = (st or {}).get("limit") or (GITHUB_LIMITS["core_keyed_per_hour"] if self.keyed else GITHUB_LIMITS["core_keyless_per_hour"])
        return int(limit * PIVOT_RESERVE_SHARE)

    def api_json(self, path: str, *, params: dict[str, Any] | None = None, absent: frozenset[int] = frozenset({404}),
                 resource: str = "core", ttl: int | None = None, reserve: int = 0) -> Any:
        """GET ``API_ROOT + path`` and return the parsed JSON, or None for a status in ``absent``."""
        self.budget.check(resource, self._now(), keyed=self.keyed, reserve=reserve)
        kw: dict[str, Any] = {"headers": self.headers(), "source": self.source}
        if params:
            kw["params"] = params
        if ttl is not None:
            kw["ttl"] = ttl
        resp = self.ctx.http.get(API_ROOT + path, **kw)
        self.api_calls += 1
        if not getattr(resp, "from_cache", False):
            self.budget.note(resp.headers, self._now())
            self._check_scopes(resp)
        try:
            if not _usable(self.ctx, resp, absent):
                return None
        except RateLimited as exc:
            if not self.keyed:
                raise RateLimited(GITHUB_ANON_COVERAGE_LINE, exc.status, exc.url) from None
            raise
        return resp.json()

    def web_text(self, url: str, *, ttl: int | None = None) -> tuple[str | None, bool]:
        """GET a github.com plain-text endpoint (no key sent): (text, truncated), (None, False) on 404."""
        kw: dict[str, Any] = {"max_bytes": PLAINTEXT_CAP, "source": SOURCE_WEB, "headers": {"Accept": "text/plain"}}
        if ttl is not None:
            kw["ttl"] = ttl
        resp = self.ctx.http.get(url, **kw)
        if not _usable(self.ctx, resp, frozenset({404})):
            return None, False
        return resp.text, bool(getattr(resp, "truncated", False))

    def _check_scopes(self, resp: Any) -> None:
        if not self.keyed or self.scope_problem:
            return
        problem = github_scope_problem(getattr(resp, "headers", {}))
        if problem:
            self.scope_problem = problem
            log = getattr(self.ctx, "log", None)
            if callable(log):
                log(f"GitHub key 'github': {problem}", level="warning")


# ======================================================================================
# parsers (pure, defensive: wrong types and HTML never raise)
# ======================================================================================


def _normalise_blog(value: Any) -> tuple[str | None, str | None]:
    s = _str(value, 500)
    if not s or re.search(r"\s", s) or s.lower().startswith("mailto:"):
        return None, None
    if not re.match(r"^[a-z][a-z0-9+.-]*://", s, re.I):
        s = "https://" + s
    try:
        sp = urlsplit(s)
    except ValueError:
        return None, None
    host = (sp.hostname or "").lower().rstrip(".")
    if sp.scheme.lower() not in ("http", "https") or "." not in host:
        return None, None
    return s, host


def parse_github_user(raw: Any) -> dict[str, Any]:
    """GET /users/{u} -> profile facts (P111 cond 1). The display name stays an attribute: person-name
    lookups belong to github_user_search (cond 2)."""
    data = load_json(raw)
    if not isinstance(data, dict) or not _str(data.get("login")):
        return {"ok": False, "reason": "HTML page instead of a GitHub user" if looks_like_html(raw) else "not a GitHub user object"}
    login = _str(data.get("login"), 39) or ""
    typ = _str(data.get("type"), 30) or "User"
    return {
        "ok": True, "reason": None, "login": login, "id": _int(data.get("id")), "type": typ, "is_org": typ.lower() == "organization",
        "name": _str(data.get("name"), 200), "company": _str(data.get("company"), 200), "blog": _str(data.get("blog"), 500),
        "location": _str(data.get("location"), 200), "email": normalise_email(data.get("email")), "bio": _str(data.get("bio"), 500),
        "twitter_username": _str(data.get("twitter_username"), 50), "public_repos": _int(data.get("public_repos")),
        "public_gists": _int(data.get("public_gists")), "followers": _int(data.get("followers")),
        "following": _int(data.get("following")), "created_at": iso_utc(data.get("created_at")),
        "updated_at": iso_utc(data.get("updated_at")),
        "html_url": _safe_url(data.get("html_url")) or "https://github.com/" + login,
        "avatar_url": _safe_url(data.get("avatar_url")),
    }


_CO_AUTHOR_RE = re.compile(r"^\s*co-authored-by:\s*(.*?)\s*<([^<>\s]+@[^<>\s]+)>\s*$", re.I | re.M)


def co_author_count(message: Any) -> int:
    """Co-authored-by trailers of a commit message (third parties: counted, never kept, cond 6)."""
    if not isinstance(message, str):
        return 0
    return sum(1 for _name, email in _CO_AUTHOR_RE.findall(message[:65536]) if normalise_email(email))


def attribute_commit_author(email: Any, name: Any, seed_login: str | None, seed_names: Any = ()) -> str:
    """P111 cond 6: who an event/patch commit author is relative to the seed.

    'noreply_seed' (the seed's own noreply), 'name_match' (author name equals the seed login or a
    profile name), 'system', 'noreply_other' or 'third_party' (never collected).
    """
    seed = (seed_login or "").lower()
    nr = decode_noreply(email)
    if nr is not None:
        if nr["bot"]:
            return "system"
        return "noreply_seed" if seed and nr["login"].lower() == seed else "noreply_other"
    if system_email_reason(email):
        return "system"
    names = {n.strip().casefold() for n in seed_names or () if isinstance(n, str) and len(n.strip()) >= 4}
    if seed:
        names.add(seed)
    if isinstance(name, str) and name.strip().casefold() in names:
        return "name_match"
    return "third_party"


def parse_github_events(raw: Any, seed_login: str | None = None, seed_names: Any = ()) -> dict[str, Any]:
    """GET /users/{u}/events/public -> commit e-mails, pushes lacking commits, activity counters.

    Trimmed PushEvent payloads (no 'commits' list, GitHub's 2025 change) are returned in
    ``pushes_missing_commits`` so the module falls back to /repos/{r}/commits?author= or the .patch.
    """
    data = load_json(raw)
    empty: dict[str, Any] = {"ok": False, "reason": None, "count": 0, "types": {}, "first": None, "last": None, "repos": [],
                             "commit_emails": [], "pushes_missing_commits": [], "contributions": 0, "page_full": False}
    if not isinstance(data, list):
        empty["reason"] = "HTML page instead of events" if looks_like_html(raw) else "events body is not a JSON list"
        return empty
    types: Counter[str] = Counter()
    dates: list[str] = []
    repos: set[str] = set()
    commit_emails: list[dict[str, Any]] = []
    missing: dict[str, dict[str, Any]] = {}
    contributions = 0
    for ev in data[:300]:
        if not isinstance(ev, dict):
            continue
        et = _str(ev.get("type"), 60) or "UnknownEvent"
        types[et] += 1
        created = iso_utc(ev.get("created_at"))
        if created:
            dates.append(created)
        repo = _str(ev["repo"].get("name"), 200) if isinstance(ev.get("repo"), dict) else None
        if repo:
            repos.add(repo)
        payload = ev.get("payload") if isinstance(ev.get("payload"), dict) else {}
        if et == "PushEvent":
            commits = payload.get("commits")
            if isinstance(commits, list) and commits:
                n = 0
                for c in commits[:100]:
                    if not isinstance(c, dict):
                        continue
                    n += 1
                    author = c.get("author") if isinstance(c.get("author"), dict) else {}
                    email = normalise_email(author.get("email"))
                    if not email:
                        continue
                    name = _str(author.get("name"), 200)
                    commit_emails.append({"email": email, "name": name, "sha": _str(c.get("sha"), 40), "repo": repo, "date": created,
                                          "source": "event", "attribution": attribute_commit_author(email, name, seed_login, seed_names),
                                          "co_author_count": co_author_count(c.get("message"))})
                contributions += max(n, _int(payload.get("distinct_size")) or 0)
            else:
                if repo and repo not in missing:
                    missing[repo] = {"repo": repo, "head": _str(payload.get("head"), 40), "date": created}
                contributions += 1
        elif (et in ("PullRequestEvent", "IssuesEvent") and payload.get("action") == "opened") or (
                et == "CreateEvent" and payload.get("ref_type") == "repository") or et == "PullRequestReviewEvent":
            contributions += 1
    return {"ok": True, "reason": None if data else "no public events", "count": sum(types.values()), "types": dict(types),
            "first": min(dates) if dates else None, "last": max(dates) if dates else None, "repos": sorted(repos),
            "commit_emails": commit_emails, "pushes_missing_commits": list(missing.values()), "contributions": contributions,
            "page_full": len(data) >= 100}


def _repo_from_html_url(url: Any) -> str | None:
    m = re.match(r"^https://github\.com/([A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+)/commit/", url or "") if isinstance(url, str) else None
    return m.group(1) if m else None


def parse_github_commits(raw: Any, seed_login: str | None = None, repo: str | None = None) -> dict[str, Any]:
    """GET /repos/{r}/commits?author={u} -> commit identity records.

    attribution: 'account_match' (GitHub linked the author e-mail to the seed account), 'other_account',
    'no_account' or 'system' (placeholder/bot accounts); only account_match feeds the seed's e-mails.
    Messages are reduced to their co-author count.
    """
    data = load_json(raw)
    if not isinstance(data, list):
        return {"ok": False, "reason": "HTML page instead of commits" if looks_like_html(raw) else "commits body is not a JSON list", "commits": []}
    seed = (seed_login or "").lower()
    out = []
    for it in data[:100]:
        if not isinstance(it, dict):
            continue
        c = it.get("commit") if isinstance(it.get("commit"), dict) else {}
        a = c.get("author") if isinstance(c.get("author"), dict) else {}
        cm = c.get("committer") if isinstance(c.get("committer"), dict) else {}
        acct = it.get("author") if isinstance(it.get("author"), dict) else None
        cacct = it.get("committer") if isinstance(it.get("committer"), dict) else None
        a_login = _str(acct.get("login"), 60) if acct else None
        c_login = _str(cacct.get("login"), 60) if cacct else None
        if acct is None:
            att = "no_account"
        elif a_login and (a_login.lower() in _SYSTEM_LOGINS or a_login.lower().endswith("[bot]")):
            att = "system"
        elif a_login and seed and a_login.lower() == seed:
            att = "account_match"
        else:
            att = "other_account"
        out.append({
            "sha": _str(it.get("sha"), 40), "repo": repo or _repo_from_html_url(it.get("html_url")),
            "author_email": normalise_email(a.get("email")), "author_date": iso_utc(a.get("date")),
            "committer_email": normalise_email(cm.get("email")), "committer_date": iso_utc(cm.get("date")),
            "committer_login": c_login, "attribution": att, "source": "commits_api", "co_author_count": co_author_count(c.get("message")),
        })
    return {"ok": True, "reason": None if out else "no commits", "commits": out}


_PATCH_START_RE = re.compile(r"^From ([0-9a-f]{40}) Mon Sep 17 00:00:00 2001$", re.M)


def _decode_mime(value: Any) -> str | None:
    if not isinstance(value, str):
        return None
    try:
        return str(make_header(decode_header(value))).strip()
    except (ValueError, LookupError, UnicodeError, TypeError):
        return value.strip()


def _rfc822_headers(block: str) -> dict[str, str]:
    headers: dict[str, str] = {}
    last = None
    for line in block.split("\n"):
        if not line.strip():
            break
        if line[:1] in (" ", "\t") and last:
            headers[last] += " " + line.strip()
            continue
        key, sep, val = line.partition(":")
        if not sep:
            continue
        last = key.strip().lower()
        headers.setdefault(last, val.strip())
    return headers


def parse_github_patch(raw: Any, seed_login: str | None = None, seed_names: Any = (), repo: str | None = None) -> dict[str, Any]:
    """github.com/{o}/{r}/commit/{sha}.patch (plain text, 1 MB cap) -> author records (HTML never parsed)."""
    text, truncated = _to_text(raw, PLAINTEXT_CAP)
    res: dict[str, Any] = {"ok": False, "reason": None, "patches": [], "truncated": truncated}
    if not text.strip():
        res["reason"] = "empty patch"
        return res
    if looks_like_html(text):
        res["reason"] = "HTML page instead of a patch (could not verify)"
        return res
    starts = list(_PATCH_START_RE.finditer(text))
    if not starts:
        res["reason"] = "not a git format-patch"
        return res
    for i, m in enumerate(starts):
        end = starts[i + 1].start() if i + 1 < len(starts) else len(text)
        block = text[m.end():end].lstrip("\r\n").replace("\r\n", "\n")
        hdrs = _rfc822_headers(block)
        name, email = parseaddr(_decode_mime(hdrs.get("from")) or "")
        email = normalise_email(email)
        name = name.strip()[:200] or None
        body = block.split("\n\n", 1)[1] if "\n\n" in block else ""
        message = re.split(r"\n---\n", body, maxsplit=1)[0]
        res["patches"].append({
            "sha": m.group(1), "repo": repo, "author_email": email, "author_name": name, "date": iso_utc(hdrs.get("date")),
            "source": "patch", "attribution": attribute_commit_author(email, name, seed_login, seed_names) if email else "unknown",
            "co_author_count": co_author_count(message),
        })
    res["ok"] = True
    if truncated:
        res["reason"] = "over 1 MB cap: parsed the first 1 MB"
    return res


_SEED_ATTRIBUTIONS = frozenset({"account_match", "noreply_seed", "name_match", "uid_seed"})


def group_commit_emails(records: Any, seed_login: str | None = None, case_values: Any = ()) -> dict[str, Any]:
    """P111 cond 6-8: the seed's e-mails grouped per address.

    Input: commit_emails of :func:`parse_github_events`, commits of :func:`parse_github_commits`,
    patches of :func:`parse_github_patch` and :func:`gpg_uid_records`. Output per address: relation
    commit_email (gpg_uid_email when only seen in GPG UIDs), commit count, first/last date, repos,
    sources, ``expand`` only when the address is already a case entity. Noreply addresses become
    account links, system addresses are dropped, third-party and co-author addresses are skipped.
    """
    seed = (seed_login or "").lower()
    case = {v.strip().lower() for v in case_values or () if isinstance(v, str)}
    groups: dict[str, dict[str, Any]] = {}
    accounts: dict[str, dict[str, Any]] = {}
    dropped: Counter[str] = Counter()
    skipped = 0
    for r in records or ():
        if not isinstance(r, dict):
            continue
        cands = []
        att = r.get("attribution")
        if att in _SEED_ATTRIBUTIONS:
            cands.append((r.get("author_email") or r.get("email"), r.get("author_date") or r.get("date")))
        elif att == "system":
            dropped["system address"] += 1
        else:
            skipped += 1
        c_login = r.get("committer_login")
        if isinstance(c_login, str) and seed and c_login.lower() == seed:
            cands.append((r.get("committer_email"), r.get("committer_date")))
        for email, date in cands:
            e = normalise_email(email)
            if not e:
                continue
            nr = decode_noreply(e)
            if nr is not None and not nr["bot"]:
                acc = accounts.setdefault(nr["login"].lower(), {"handle": nr["login"], "id": nr["id"], "url": nr["url"], "seen": 0, "_keys": set()})
                key = r.get("sha") or (r.get("source"), r.get("key_fingerprint"), e)
                if key not in acc["_keys"]:
                    acc["_keys"].add(key)
                    acc["seen"] += 1
                continue
            reason = system_email_reason(e)
            if reason:
                dropped[reason] += 1
                continue
            g = groups.setdefault(e, {"email": e, "relation": "gpg_uid_email", "commits": 0, "first": None, "last": None, "repos": [],
                                      "sources": [], "expand": e in case, "_shas": set()})
            src = r.get("source") or "unknown"
            if src not in g["sources"]:
                g["sources"].append(src)
            if src == "gpg_uid":
                continue
            g["relation"] = "commit_email"
            sha = r.get("sha")
            if sha and sha in g["_shas"]:
                continue
            if sha:
                g["_shas"].add(sha)
            g["commits"] += 1
            d = iso_utc(date)
            if d:
                g["first"] = d if not g["first"] or d < g["first"] else g["first"]
                g["last"] = d if not g["last"] or d > g["last"] else g["last"]
            rp = r.get("repo")
            if isinstance(rp, str) and rp not in g["repos"] and len(g["repos"]) < 5:
                g["repos"].append(rp)
    emails = sorted(groups.values(), key=lambda g: (-g["commits"], g["email"]))
    for g in emails:
        g.pop("_shas", None)
    for a in accounts.values():
        a.pop("_keys", None)
    return {"emails": emails, "accounts": sorted(accounts.values(), key=lambda a: a["handle"].lower()), "dropped": dict(dropped),
            "third_party_skipped": skipped}


# ---- SSH keys (cond 8) ----------------------------------------------------------------

_SSH_TYPE_RE = re.compile(r"^(?:ssh-(?:rsa|dss|ed25519|ed448)|ecdsa-sha2-nistp(?:256|384|521)|sk-(?:ssh-ed25519|ecdsa-sha2-nistp256)@openssh\.com)$")


def _ssh_read(blob: bytes, off: int) -> tuple[bytes | None, int]:
    if off + 4 > len(blob):
        return None, off
    n = struct.unpack(">I", blob[off:off + 4])[0]
    if off + 4 + n > len(blob):
        return None, off
    return blob[off + 4:off + 4 + n], off + 4 + n


def _ssh_bits(ktype: str, blob: bytes) -> int | None:
    if "ed25519" in ktype:
        return 256
    if ktype == "ssh-ed448":
        return 456
    m = re.search(r"nistp(\d+)", ktype)
    if m:
        return int(m.group(1))
    _, off = _ssh_read(blob, 0)
    if ktype == "ssh-rsa":
        _e, off = _ssh_read(blob, off)
        n, _ = _ssh_read(blob, off)
        return int.from_bytes(n, "big").bit_length() if n else None
    if ktype == "ssh-dss":
        p, _ = _ssh_read(blob, off)
        return int.from_bytes(p, "big").bit_length() if p else None
    return None


def parse_ssh_keys(raw: Any, max_keys: int = 100) -> dict[str, Any]:
    """github.com/{u}.keys (also the gitlab.com format) -> OpenSSH SHA-256 fingerprints (cond 8).

    Only {type, fingerprint 'SHA256:...', bits} is returned: key blobs and comments (GitLab puts the
    account's display name there) are never kept.
    """
    text, truncated = _to_text(raw, PLAINTEXT_CAP)
    res: dict[str, Any] = {"ok": True, "reason": None, "keys": [], "invalid_lines": 0, "comments_dropped": 0, "truncated": truncated}
    if looks_like_html(text):
        res.update(ok=False, reason="HTML page instead of SSH keys (could not verify)")
        return res
    seen: set[str] = set()
    for line in text.splitlines():
        s = line.strip()
        if not s or s.startswith("#"):
            continue
        parts = s.split()
        idx = next((i for i, p in enumerate(parts) if _SSH_TYPE_RE.match(p)), None)
        if idx is None or idx + 1 >= len(parts):
            res["invalid_lines"] += 1
            continue
        ktype, b64 = parts[idx], parts[idx + 1]
        try:
            blob = base64.b64decode(b64, validate=True)
        except (binascii.Error, ValueError):
            res["invalid_lines"] += 1
            continue
        inner, _ = _ssh_read(blob, 0)
        if inner is None or inner != ktype.encode("ascii"):
            res["invalid_lines"] += 1
            continue
        if len(parts) > idx + 2:
            res["comments_dropped"] += 1
        fp = "SHA256:" + base64.b64encode(hashlib.sha256(blob).digest()).decode("ascii").rstrip("=")
        if fp in seen:
            continue
        seen.add(fp)
        res["keys"].append({"type": ktype, "fingerprint": fp, "bits": _ssh_bits(ktype, blob)})
        if len(res["keys"]) >= max_keys:
            break
    if not res["keys"]:
        res["reason"] = "no public SSH keys"
    return res


# ---- GPG keys (cond 8; minimal stdlib OpenPGP packet reader) -----------------------------

_ARMOR_RE = re.compile(r"-----BEGIN PGP PUBLIC KEY BLOCK-----(.*?)-----END PGP PUBLIC KEY BLOCK-----", re.S)
_PGP_ALGOS = {1: "rsa", 2: "rsa", 3: "rsa", 16: "elgamal", 17: "dsa", 18: "ecdh", 19: "ecdsa", 22: "eddsa", 25: "x25519",
              26: "x448", 27: "ed25519", 28: "ed448"}
_PGP_CURVES = {
    bytes.fromhex("2b06010401da470f01"): "ed25519", bytes.fromhex("2b060104019755010501"): "cv25519",
    bytes.fromhex("2a8648ce3d030107"): "nistp256", bytes.fromhex("2b81040022"): "nistp384", bytes.fromhex("2b81040023"): "nistp521",
    bytes.fromhex("2b8104000a"): "secp256k1", bytes.fromhex("2b2403030208010107"): "brainpoolP256r1",
    bytes.fromhex("2b240303020801010b"): "brainpoolP384r1", bytes.fromhex("2b240303020801010d"): "brainpoolP512r1",
    bytes.fromhex("2b6570"): "ed25519", bytes.fromhex("2b656e"): "cv25519",
}


def _crc24(data: bytes) -> int:
    crc = 0xB704CE
    for byte in data:
        crc ^= byte << 16
        for _ in range(8):
            crc <<= 1
            if crc & 0x1000000:
                crc ^= 0x1864CFB
    return crc & 0xFFFFFF


def _dearmor(block: str) -> tuple[bytes | None, str | None]:
    lines = [ln.strip() for ln in block.strip("\r\n").splitlines()]
    if "" in lines:
        i = lines.index("")
        if all(":" in ln for ln in lines[:i]):
            lines = lines[i + 1:]
    b64: list[str] = []
    crc = None
    for ln in lines:
        if not ln:
            continue
        if ln.startswith("=") and len(ln) == 5:
            crc = ln[1:]
            break
        b64.append(ln)
    try:
        data = base64.b64decode("".join(b64), validate=True)
    except (binascii.Error, ValueError):
        return None, "malformed armor (bad base64)"
    if crc is not None:
        try:
            want = int.from_bytes(base64.b64decode(crc, validate=True), "big")
        except (binascii.Error, ValueError):
            return None, "malformed armor (bad checksum line)"
        if _crc24(data) != want:
            return None, "armor checksum mismatch (truncated or corrupted block)"
    return data, None


def _iter_packets(data: bytes) -> Any:
    i, n = 0, len(data)
    while i < n:
        b = data[i]
        i += 1
        if not b & 0x80:
            raise ValueError("invalid packet header")
        if b & 0x40:
            tag = b & 0x3F
            if i >= n:
                raise ValueError("truncated packet")
            o1 = data[i]
            i += 1
            if o1 < 192:
                length = o1
            elif o1 < 224:
                if i >= n:
                    raise ValueError("truncated packet")
                length = ((o1 - 192) << 8) + data[i] + 192
                i += 1
            elif o1 == 255:
                if i + 4 > n:
                    raise ValueError("truncated packet")
                length = struct.unpack(">I", data[i:i + 4])[0]
                i += 4
            else:
                raise ValueError("partial body length inside key material")
        else:
            tag = (b >> 2) & 0x0F
            size = {0: 1, 1: 2, 2: 4}.get(b & 3)
            if size is None:
                length = n - i
            else:
                if i + size > n:
                    raise ValueError("truncated packet")
                length = int.from_bytes(data[i:i + size], "big")
                i += size
        if i + length > n:
            raise ValueError("truncated packet")
        yield tag, data[i:i + length]
        i += length


def _pgp_key_info(body: bytes) -> dict[str, Any]:
    if len(body) < 6:
        raise ValueError("short key packet")
    ver = body[0]
    if ver == 4:
        created, algo = struct.unpack(">I", body[1:5])[0], body[5]
        framed = b"\x99" + struct.pack(">H", len(body)) + body
        fp: str | None = hashlib.sha1(framed).hexdigest().upper()  # noqa: S324 - the OpenPGP v4 fingerprint is SHA-1 by definition
        key_id, sha = fp[-16:], hashlib.sha256(framed).hexdigest()
        params = body[6:]
    elif ver in (5, 6):
        if len(body) < 10:
            raise ValueError("short key packet")
        created, algo = struct.unpack(">I", body[1:5])[0], body[5]
        framed = (b"\x9a" if ver == 5 else b"\x9b") + struct.pack(">I", len(body)) + body
        fp = hashlib.sha256(framed).hexdigest().upper()
        key_id, sha = fp[:16], fp.lower()
        params = body[10:]
    elif ver in (2, 3):
        if len(body) < 8:
            raise ValueError("short key packet")
        created, algo = struct.unpack(">I", body[1:5])[0], body[7]
        fp, key_id, sha = None, None, hashlib.sha256(body).hexdigest()
        params = body[8:]
    else:
        raise ValueError(f"unknown key packet version {ver}")
    bits = curve = None
    if algo in (1, 2, 3, 16, 17) and len(params) >= 2:
        bits = struct.unpack(">H", params[:2])[0]
    elif algo in (18, 19, 22) and params:
        oid = params[1:1 + params[0]]
        curve = _PGP_CURVES.get(bytes(oid), "oid:" + oid.hex())
    elif algo in (25, 27):
        curve = "cv25519" if algo == 25 else "ed25519"
    elif algo in (26, 28):
        curve = "x448" if algo == 26 else "ed448"
    return {"version": ver, "fingerprint": fp, "key_id": key_id, "sha256_id": sha, "algorithm": _PGP_ALGOS.get(algo, f"algo-{algo}"),
            "bits": bits, "curve": curve, "created": iso_utc(created)}


def _pgp_uid(body: bytes) -> dict[str, str | None]:
    text = body[:1024].decode("utf-8", errors="replace").strip()
    m = re.search(r"<([^<>\s]+@[^<>\s]+)>", text)
    email = normalise_email(m.group(1)) if m else normalise_email(text if "@" in text else None)
    rest = text[:m.start()] if m else ("" if email else text)
    cm = re.search(r"\(([^()]*)\)\s*$", rest.strip())
    comment = (cm.group(1).strip() or None) if cm else None
    name = (rest[:cm.start()] if cm else rest).strip() or None
    return {"name": name, "comment": comment, "email": email}


def parse_gpg_keys(raw: Any) -> dict[str, Any]:
    """github.com/{u}.gpg -> keys {fingerprint (OpenPGP), key_id, sha256_id, algorithm, bits, curve,
    created, uids, subkeys} (cond 8). Signatures and photo IDs are skipped, never decoded."""
    text, truncated = _to_text(raw, PLAINTEXT_CAP)
    res: dict[str, Any] = {"ok": True, "reason": None, "keys": [], "truncated": truncated}
    if not text.strip():
        res["reason"] = "no GPG keys"
        return res
    if looks_like_html(text):
        res.update(ok=False, reason="HTML page instead of GPG keys (could not verify)")
        return res
    blocks = _ARMOR_RE.findall(text)
    if not blocks:
        if "BEGIN PGP" in text:
            res.update(ok=False, reason="malformed armor (unterminated block)")
        else:
            res["reason"] = "no GPG keys uploaded"
        return res
    errors = []
    for block in blocks:
        data, err = _dearmor(block)
        if data is None:
            errors.append(err)
            continue
        cur: dict[str, Any] | None = None
        try:
            for tag, body in _iter_packets(data):
                if tag == 6:
                    cur = _pgp_key_info(body)
                    cur["uids"], cur["subkeys"] = [], []
                    res["keys"].append(cur)
                elif tag == 14 and cur is not None:
                    cur["subkeys"].append(_pgp_key_info(body))
                elif tag == 13 and cur is not None and len(cur["uids"]) < 50:
                    cur["uids"].append(_pgp_uid(body))
        except ValueError as exc:
            errors.append(f"malformed OpenPGP packets: {exc}")
    if errors:
        res["reason"] = "; ".join(str(e) for e in errors)
        res["ok"] = bool(res["keys"])
    elif not res["keys"]:
        res["reason"] = "no GPG keys"
    return res


def gpg_uid_records(parsed_gpg: Any) -> list[dict[str, Any]]:
    """UID e-mails of keys published on the seed account -> records for :func:`group_commit_emails` (cond 8)."""
    out = []
    keys = parsed_gpg.get("keys", []) if isinstance(parsed_gpg, dict) else []
    for k in keys:
        for u in k.get("uids", []):
            if u.get("email"):
                out.append({"email": u["email"], "date": k.get("created"), "sha": None, "repo": None, "source": "gpg_uid",
                            "attribution": "uid_seed", "key_fingerprint": k.get("fingerprint")})
    return out


# ---- search (cond 2) --------------------------------------------------------------------


def parse_github_search_users(raw: Any, max_candidates: int = 30) -> dict[str, Any]:
    """GET /search/users -> POSSIBLE candidates (never auto-expanded, P111 cond 2)."""
    data = load_json(raw)
    if not isinstance(data, dict) or not isinstance(data.get("items"), list):
        return {"ok": False, "reason": "HTML page instead of search results" if looks_like_html(raw) else "not a search result",
                "total_count": 0, "incomplete": False, "candidates": []}
    cands = []
    for it in data["items"][:max_candidates]:
        if not isinstance(it, dict):
            continue
        login = normalise_github_login(_str(it.get("login"), 39))
        if not login:
            continue
        score = it.get("score")
        cands.append({"handle": login, "id": _int(it.get("id")), "type": _str(it.get("type"), 30) or "User",
                      "url": _safe_url(it.get("html_url")) or "https://github.com/" + login,
                      "score": float(score) if isinstance(score, (int, float)) and not isinstance(score, bool) else None})
    incomplete = data.get("incomplete_results") is True
    reason = "search incomplete (timed out): partial candidates" if incomplete else (None if cands else "no candidates")
    return {"ok": True, "reason": reason, "total_count": _int(data.get("total_count")) or 0, "incomplete": incomplete, "candidates": cands}


# ---- Ceos activity classifier (C0268; cond 8: attributes only) -----------------------------


def classify_activity(events: Any, now: Any = None, idle_days: int = 180) -> dict[str, Any]:
    """Ceos C0268 activity level from REST data only (no contributions-calendar HTML, cond 1).

    Ceos thresholds per year (0 / 1-49 / 50-299 / >= 300) applied to the event contributions
    annualised over the events window (<= 90 days); more than ``idle_days`` without activity lowers
    the level by one and sets ``stalled_for_months``. Attributes only, never a sensitive inference.
    """
    ev = events if isinstance(events, dict) else {}
    now_dt = _parse_dt(now) or _dt.datetime.now(_dt.timezone.utc)
    contributions = _int(ev.get("contributions")) or 0
    first = _parse_dt(ev.get("first"))
    window = 90
    if ev.get("page_full") and first:
        window = max(1, min(90, (now_dt - first).days or 1))
    estimate = int(round(contributions * 365.0 / window))
    last = _parse_dt(ev.get("last"))
    levels = ["inactive", "low", "active", "very_active"]
    lvl = 0 if estimate == 0 else 1 if estimate < 50 else 2 if estimate < 300 else 3
    idle = (now_dt - last).days if last else None
    stalled = idle is not None and idle > idle_days
    if stalled and lvl > 0:
        lvl -= 1
    return {"activity_level": levels[lvl], "stalled_for_months": stalled, "idle_days": idle, "contributions_window": contributions,
            "window_days": window, "estimated_contributions_year": estimate,
            "last_activity": last.strftime("%Y-%m-%dT%H:%M:%SZ") if last else None, "basis": "rest_public_events"}


# ======================================================================================
# per-call failures of secondary endpoints (rule 5: could not verify, never absent)
# ======================================================================================


def _attempt(problems: dict[str, list[tuple[Status, str, str]]], source: str, label: str, fn: Any) -> Any:
    """Run one secondary call; a refusal or failure is recorded per source (the run goes on).

    Rate limits, quotas, deadlines, cancellation and the request cap propagate: the engine keeps the
    data already built and marks the run partial.
    """
    try:
        return fn()
    except (RateLimited, QuotaExceeded, DeadlineExceeded):
        raise
    except Blocked as exc:
        problems.setdefault(source, []).append((Status.BLOCKED, exc.reason_code, f"{label}: {exc}"))
    except AuthRequired as exc:
        problems.setdefault(source, []).append((Status.NEEDS_KEY, "needs_key", f"{label}: {exc}"))
    except OfflineError as exc:
        problems.setdefault(source, []).append((Status.UNAVAILABLE, "offline", f"{label}: {exc}"))
    except (HttpError, NetworkError) as exc:
        code = "timeout" if getattr(exc, "reason_code", "") == "timeout" else "error"
        problems.setdefault(source, []).append((Status.ERROR, code, f"{label}: could not verify ({exc})"))
    except ValueError as exc:  # unexpected body shape (e.g. invalid JSON)
        problems.setdefault(source, []).append((Status.ERROR, "error", f"{label}: unexpected answer ({exc})"))
    return None


def _case_values(ctx: Any, entity: Entity) -> set[str]:
    """E-mail values already in the case as far as the module can see: the seeds of the scan and the
    entities on this run's provenance path (cond 7: expand only for case entities)."""
    keys: set[str] = {entity.key}
    options = getattr(ctx, "options", None)
    for key in (getattr(options, "seed_tlp", None) or {}):
        keys.add(str(key))
    for step in getattr(ctx, "provenance", ()) or ():
        if isinstance(step, (list, tuple)) and step:
            keys.add(str(step[0]))
    return {k.split(":", 1)[1].lower() for k in keys if k.startswith("email:")}


# ======================================================================================
# the module
# ======================================================================================


def _selftest(ctx: Any) -> HealthResult:
    """Doctor self-test (P111 cond 4): GET /rate_limit (never charged by GitHub); a classic token whose
    X-OAuth-Scopes header is not empty is refused."""
    client = GitHubClient(ctx)
    try:
        resp = ctx.http.get(API_ROOT + "/rate_limit", headers=client.headers(), source=SOURCE_API, ttl=0)
        ctx.http.check(resp)
    except AuthRequired as exc:
        return HealthResult("needs_key", f"token refused (invalid, expired or revoked): {str(exc)[:160]}")
    except (RateLimited, QuotaExceeded) as exc:
        return HealthResult("quota", str(exc)[:200])
    except Blocked as exc:
        return HealthResult("blocked", str(exc)[:200])
    except (HttpError, NetworkError) as exc:
        return HealthResult("dead", str(exc)[:200])
    problem = github_scope_problem(resp.headers) if client.keyed else None
    if problem:
        return HealthResult("needs_key", problem)
    core = parse_github_rate_limit(resp.content).get("core") or {}
    if core.get("remaining") == 0:
        return HealthResult("quota", "GitHub core budget spent until its reset")
    kind = "keyed" if client.keyed else "anonymous (60/h)"
    return HealthResult("ok", f"GitHub REST reachable, {kind}, core {core.get('remaining')}/{core.get('limit')}")


@register
class GithubUser(Module):
    name = "github_user"
    title = "GitHub user"
    description = (
        "GitHub REST profile, public SSH/GPG key fingerprints, the seed account's own commit e-mails (noreply decoded) and "
        "public activity of a login, through the shared GitHub client and budget."
    )
    category = "username_social"
    accepts = {T.USERNAME, T.URL, T.SOCIAL_ACCOUNT}
    produces = {T.EMAIL, T.URL, T.DOMAIN, T.USERNAME, T.SOCIAL_ACCOUNT, T.PGP_FINGERPRINT}
    terms = "key-terms"
    opsec = Opsec.PASSIVE
    disclosure = "third_party"
    provider = PROVIDER
    sources = (SOURCE_API, SOURCE_WEB)
    hosts = (API_HOST, WEB_HOST)
    access_model = "free_noauth_limited"
    optional_keys = ("github",)
    max_requests = 10  # user 1 + .keys 1 + .gpg 1 + events 1 + commits <= 4 + .patch <= 2 (A3: <= 10)
    expected_latency = 6.0
    timeout = 60.0
    min_interval = 1.0  # serial, GitHub best practice (secondary limits)
    cache_ttl = 86400
    default_enabled = True
    manual_link = "github_telegram_profiles:github_profile"
    reference = "https://docs.github.com/en/rest/users/users"
    tags = {"free"}
    error_markers = (
        {"id": "github_user_html_instead_of_data", "statuses": [200], "json_path": None, "equals": None,
         "regex": r"(?i)^\s*(?:<!--[\s\S]{0,4000}?-->\s*)?(?:<!doctype\s+html|<html\b)", "final_url_regex": None,
         "maps_to": "error", "reason_code": "error",
         "reason": "GitHub served an HTML page instead of data (REST/plain-text endpoint): could not verify"},
    )
    notice = (
        "GitHub API terms are key-terms: under the corporate profile this runs only once legal records free_plan_business_use "
        "or key_plans.github = 'business'; personal_data_review comes before default use. Use a team machine-account or "
        "GitHub App token, never a personal one. Commit e-mails are case-bound (retention_days) and never sent to breach "
        "modules automatically."
    )

    @classmethod
    def health_check(cls) -> HealthCheck:
        return HealthCheck(offline=False, selftest=_selftest)

    def applies(self, entity: Entity, ctx: Any) -> bool:
        return github_login_of(entity) is not None

    def run(self, entity: Entity, ctx: Any) -> ModuleResult:
        res = self.result(entity)
        login = github_login_of(entity)
        if not login:
            return res.mark("skipped", "not a GitHub login or profile URL", reason_code="not_applicable")
        client = GitHubClient(ctx)
        seed = bool(getattr(ctx, "is_seed", False))
        if not client.keyed and not seed:
            return res.mark("needs_key", GITHUB_ANON_COVERAGE_LINE)  # P111 cond 5: seeds only without a token
        reserve = 0 if seed else client.pivot_reserve()
        data = client.api_json(f"/users/{quote(login, safe='')}", reserve=reserve)
        profile_url = f"https://github.com/{login}"
        if data is None:  # 404: the login does not exist (P111 cond 3)
            res.presence("absent", marker="HTTP 404 Not Found from api.github.com/users", url=profile_url, checked_at=ctx.now(), source=SOURCE_API)
            res.raw = {"handle": login, "state": "absent"}
            return res.mark("empty")
        prof = parse_github_user(data)
        if not prof["ok"]:
            return res.mark("error", f"unexpected GitHub answer ({prof['reason']}): could not verify")
        login = prof["login"] or login
        raw: dict[str, Any] = {"handle": login, "account_id": prof["id"], "account_type": prof["type"]}
        res.raw = raw
        res.presence("found", marker="HTTP 200 user object", url=prof["html_url"], checked_at=ctx.now(), source=SOURCE_API)
        self._profile(res, prof, login)
        problems: dict[str, list[tuple[Status, str, str]]] = {}
        uid_records: list[dict[str, Any]] = []
        if not prof["is_org"]:
            uid_records = self._keys(res, client, login, seed, problems, raw)
        if seed and not prof["is_org"]:
            self._seed_activity(res, ctx, client, entity, login, prof, reserve, uid_records, problems, raw)
        for source, items in problems.items():
            status, code, _ = items[0]
            res.source_status(source, status, reason_code=code, reason="; ".join(text for _s, _c, text in items)[:500])
        if client.scope_problem:
            res.error = "; ".join(x for x in (res.error, f"GitHub key: {client.scope_problem}") if x)
        raw["budget"] = client.budget.snapshot()
        return res

    # ------------------------------------------------------------------ profile
    def _profile(self, res: ModuleResult, prof: dict[str, Any], login: str) -> None:
        res.attr("account_id", prof["id"])
        res.attr("account_type", prof["type"])
        res.attr("display_name", prof["name"])
        res.attr("company", prof["company"])
        res.attr("location", prof["location"])
        res.attr("bio", prof["bio"])
        res.attr("followers", prof["followers"])
        res.attr("following", prof["following"])
        res.attr("public_repos", prof["public_repos"])
        res.attr("public_gists", prof["public_gists"])
        res.attr("created", prof["created_at"])
        res.attr("updated", prof["updated_at"])
        res.attr("avatar_url", prof["avatar_url"])
        url, host = _normalise_blog(prof["blog"])
        if url:
            res.attr("website", url)
            hit = platform_for_url(url)
            if hit is not None:  # a social profile declared as website: an account link, not infrastructure
                res.pivot(T.SOCIAL_ACCOUNT, f"{hit[0]}:{hit[1]}", "has_account", confidence="probable", expand=False,
                          note="profile link declared on the GitHub account")
            elif host and host != WEB_HOST and not host.endswith("." + WEB_HOST):
                res.pivot(T.URL, url, "links_to", confidence="probable", note="website declared on the GitHub profile")
                res.pivot(T.DOMAIN, host[4:] if host.startswith("www.") else host, "links_to", confidence="probable",
                          note="domain of the website declared on the GitHub profile")
        email = prof["email"]
        if email:
            nr = decode_noreply(email)
            if nr is not None and not nr["bot"]:
                if nr["login"].lower() != login.lower():
                    res.pivot(T.SOCIAL_ACCOUNT, f"github:{nr['login']}", "noreply_account", confidence="probable", expand=False,
                              note="decoded from the profile's users.noreply.github.com address")
            elif not system_email_reason(email):
                res.pivot(T.EMAIL, email, "uses_email", confidence="probable", expand=False,
                          note="public e-mail of the GitHub profile: never sent to breach modules automatically (A4)")
        tw = prof["twitter_username"]
        if tw and re.fullmatch(r"[A-Za-z0-9_]{1,15}", tw):
            res.pivot(T.SOCIAL_ACCOUNT, f"x:{tw}", "has_account", confidence="probable", expand=False,
                      note="X/Twitter account declared on the GitHub profile")
        for org in re.findall(r"(?<![\w@])@([A-Za-z0-9][A-Za-z0-9-]{0,38})\b", prof["company"] or "")[:5]:
            if org.lower() != login.lower() and normalise_github_login(org):
                res.pivot(T.SOCIAL_ACCOUNT, f"github:{org}", "declared_org", confidence="possible", expand=False,
                          note="organisation declared in the GitHub profile's company field (self-declared)")

    # ------------------------------------------------------------------ keys (cond 8)
    def _keys(self, res: ModuleResult, client: GitHubClient, login: str, seed: bool, problems: dict[str, Any], raw: dict[str, Any]) -> list[dict[str, Any]]:
        quoted = quote(login, safe="")
        ssh = _attempt(problems, SOURCE_WEB, f"{WEB_HOST}/{login}.keys", lambda: client.web_text(f"https://github.com/{quoted}.keys"))
        if ssh is not None:
            text, truncated = ssh
            parsed = parse_ssh_keys(text or "")
            if not parsed["ok"]:
                problems.setdefault(SOURCE_WEB, []).append((Status.ERROR, "error", f"{login}.keys: {parsed['reason']}"))
            else:
                keys = parsed["keys"]
                res.attr("ssh_keys", keys)
                raw["ssh_keys"] = keys
                if truncated:
                    res.error = "; ".join(x for x in (res.error, f"{login}.keys over the 1 MB cap: first 1 MB read") if x)
        gpg = _attempt(problems, SOURCE_WEB, f"{WEB_HOST}/{login}.gpg", lambda: client.web_text(f"https://github.com/{quoted}.gpg"))
        if gpg is None:
            return []
        parsed_gpg = parse_gpg_keys(gpg[0] or "")
        if not parsed_gpg["ok"]:
            problems.setdefault(SOURCE_WEB, []).append((Status.ERROR, "error", f"{login}.gpg: {parsed_gpg['reason']}"))
            return []
        stored = []
        for k in parsed_gpg["keys"][:20]:
            uids = []
            for u in k.get("uids", [])[:10]:
                # GPG UID e-mails follow the commit e-mail rules (cond 6-8): seed accounts only, noreply
                # addresses become account links, system addresses are dropped
                email = u.get("email")
                nr = decode_noreply(email) if email else None
                uid: dict[str, Any] = {"name": u.get("name"), "email": None}
                if nr is not None:
                    uid["noreply_account"] = None if nr["bot"] else nr["login"]
                elif seed and email and not system_email_reason(email):
                    uid["email"] = email
                uids.append(uid)
            stored.append({"fingerprint": k.get("fingerprint"), "key_id": k.get("key_id"), "sha256_id": k.get("sha256_id"),
                           "algorithm": k.get("algorithm"), "bits": k.get("bits"), "curve": k.get("curve"), "created": k.get("created"),
                           "subkeys": len(k.get("subkeys") or []), "uids": uids})
            if k.get("version") == 4 and k.get("fingerprint"):
                res.pivot(T.PGP_FINGERPRINT, k["fingerprint"], "pgp_key", confidence="confirmed", expand=False,
                          note="OpenPGP key published on the GitHub account")
        if stored:
            res.attr("gpg_keys", stored)
            raw["gpg_keys"] = stored
        return gpg_uid_records(parsed_gpg) if seed else []

    # ------------------------------------------------------------------ seed-only e-mails and activity (cond 6-8)
    def _seed_activity(self, res: ModuleResult, ctx: Any, client: GitHubClient, entity: Entity, login: str, prof: dict[str, Any],
                       reserve: int, uid_records: list[dict[str, Any]], problems: dict[str, Any], raw: dict[str, Any]) -> None:
        names = [prof["name"]] if prof.get("name") else []
        quoted = quote(login, safe="")
        events_raw = _attempt(problems, SOURCE_API, "public events", lambda: client.api_json(
            f"/users/{quoted}/events/public", params={"per_page": 100}, ttl=EVENTS_TTL, reserve=reserve))
        records: list[dict[str, Any]] = list(uid_records)
        events = parse_github_events(events_raw, login, names) if events_raw is not None else None
        if events is not None and not events["ok"]:
            problems.setdefault(SOURCE_API, []).append((Status.ERROR, "error", f"public events: {events['reason']}"))
            events = None
        if events is not None:
            records += events["commit_emails"]
            activity = classify_activity(events, now=ctx.now())
            for key in ("activity_level", "stalled_for_months", "estimated_contributions_year", "last_activity"):
                res.attr(key, activity[key])
            summary = {"events": events["count"], "types": events["types"], "first": events["first"], "last": events["last"],
                       "contributions_window": activity["contributions_window"], "window_days": activity["window_days"]}
            res.attr("public_activity", summary)
            raw["public_activity"] = summary
            records += self._commit_fallback(client, login, names, events["pushes_missing_commits"], reserve, problems)
        grouped = group_commit_emails(records, login, _case_values(ctx, entity))
        self._report_emails(res, ctx, login, grouped, raw)

    def _commit_fallback(self, client: GitHubClient, login: str, names: list[str], pushes: list[dict[str, Any]], reserve: int,
                         problems: dict[str, Any]) -> list[dict[str, Any]]:
        """P111 cond 1: /repos/{r}/commits?author= for pushes whose event payload lacks commits, then
        the .patch of the push head when the commits API linked no commit to the seed."""
        out: list[dict[str, Any]] = []
        max_repos = MAX_COMMIT_REPOS_KEYED if client.keyed else MAX_COMMIT_REPOS_KEYLESS
        patches_left = MAX_PATCHES
        for push in pushes[:max_repos]:
            repo = push.get("repo")
            path = github_repo_commits_path(repo or "")
            if path is None:
                continue
            data = _attempt(problems, SOURCE_API, f"commits of {repo}", lambda p=path: client.api_json(
                p, params={"author": login, "per_page": 30}, absent=frozenset({404, 409}), reserve=reserve))
            parsed = parse_github_commits(data, login, repo) if data is not None else {"ok": True, "commits": []}
            if not parsed["ok"]:
                problems.setdefault(SOURCE_API, []).append((Status.ERROR, "error", f"commits of {repo}: {parsed['reason']}"))
                continue
            out += parsed["commits"]
            if any(c["attribution"] == "account_match" for c in parsed["commits"]) or patches_left <= 0:
                continue
            url = github_patch_url(repo or "", push.get("head") or "")
            if url is None:
                continue
            patches_left -= 1
            got = _attempt(problems, SOURCE_WEB, f"patch of {repo}@{(push.get('head') or '')[:12]}", lambda u=url: client.web_text(u, ttl=PATCH_TTL))
            if got is not None and got[0]:
                patch = parse_github_patch(got[0], login, names, repo)
                if patch["ok"]:
                    out += patch["patches"]
                else:
                    problems.setdefault(SOURCE_WEB, []).append((Status.ERROR, "error", f"patch of {repo}: {patch['reason']}"))
        return out

    def _report_emails(self, res: ModuleResult, ctx: Any, login: str, grouped: dict[str, Any], raw: dict[str, Any]) -> None:
        emails = grouped["emails"]
        accounts = grouped["accounts"]
        if accounts:
            res.attr("noreply_accounts", [{"handle": a["handle"], "id": a["id"]} for a in accounts])
            for a in accounts:
                if a["handle"].lower() != login.lower():
                    res.pivot(T.SOCIAL_ACCOUNT, f"github:{a['handle']}", "noreply_account", confidence="probable", expand=False,
                              note="decoded from a users.noreply.github.com address of the account's own commits")
        raw["commit_email_rules"] = {"dropped": grouped["dropped"], "third_party_skipped": grouped["third_party_skipped"]}
        if not emails:
            return
        listed = [{"email": g["email"], "commits": g["commits"], "first": g["first"], "last": g["last"], "repos": g["repos"],
                   "sources": g["sources"]} for g in emails]
        res.attr("commit_emails", listed)
        raw["commit_emails"] = listed
        for g in emails[:MAX_EMAIL_PIVOTS]:
            if g["relation"] == "commit_email":
                span = f" ({g['first'][:10]} .. {g['last'][:10]})" if g["first"] and g["last"] else ""
                note = f"seen in {g['commits']} public commit(s) of the account{span}"
            else:
                note = "e-mail in a UID of an OpenPGP key published on the account"
            res.pivot(T.EMAIL, g["email"], g["relation"], confidence="probable", expand=bool(g["expand"]),
                      note=note + ": case-bound, never sent to breach modules automatically")
        res.finding(
            "E-mail addresses in the account's public commits",
            "info",
            f"{len(emails)} address(es) used by {login} in its own public commits or GPG UIDs: "
            + ", ".join(g["email"] for g in emails[:10]) + ("" if len(emails) <= 10 else ", ..."),
            confidence="probable",
            criterion="author e-mail of the seed account's own public commits (GitHub account link, noreply or name match) or a UID of its GPG key",
            data={"emails": listed[:20]},
            tags=["identity", "privacy"],
            references=[f"https://github.com/{login}"],
            source=SOURCE_API,
        )
        org = getattr(ctx, "org", None)
        own = []
        for g in emails:
            ent = Entity.try_make(T.EMAIL, g["email"])
            try:
                if ent is not None and org is not None and org.owns(ent).own:
                    own.append(g["email"])
            except Exception:  # noqa: BLE001 - a broken profile never stops the run
                continue
        if own:
            res.finding(
                "Organisation e-mail address in public GitHub commits",
                "low",
                f"{', '.join(own[:10])} appear(s) in public commits or GPG UIDs of {login}: exposed to address harvesting and "
                "social engineering.",
                confidence="probable",
                criterion="commit/GPG e-mail domain matches an org-profile domain",
                data={"emails": own[:20]},
                tags=["exposure", "privacy"],
                references=[f"https://github.com/{login}"],
                source=SOURCE_API,
            )
