"""Shared clients and parsers of the developer-platform enrichers (batch p2-G05-1).

P100 ``dev_profiles_pack`` (modules npm_maintainer, pypi_package, codeberg_user, devto_user,
huggingface_user) and P102 ``dockerhub`` use these helpers; P100 cond 8 shares the npm, PyPI, Codeberg
and Docker Hub clients with org_code_footprint (P359), which imports them from here instead of
re-implementing them. This file registers no module: it only holds pure, defensive parsers (wrong
types, missing fields and HTML where JSON was expected never raise) and small case helpers.

Rules carried by the parsers:

* P100 cond 5/6: only the e-mail of the maintainer/author whose username equals the investigated one is
  kept; it is PROBABLE only when it equals an e-mail already in the case, otherwise POSSIBLE (also when it
  recurs on >= 2 packages); generic/role/test addresses (A4, ``entities.generic_address_kind``) are capped
  at POSSIBLE. Co-maintainer, co-author, publisher and organisation e-mails and usernames are counted,
  never stored, listed or pivoted. E-mail pivots are always ``expand=False``.
* P102 cond 4/5: LABEL e-mails are kept only when equal to a case e-mail or on the account's own verified
  domain; labels inherited from base images are ignored; secrets in layer instructions are masked with
  the core sanitizer (type + first 4/last 4 + SHA-256) or, for passwords, reduced to their type.
* ``seed_username=None`` gives counts only, never e-mails: what P359's organisation footprint needs.
"""

from __future__ import annotations

import datetime as _dt
import json
import re
from collections.abc import Iterable
from email.utils import getaddresses, parsedate_to_datetime
from typing import Any
from urllib.parse import quote, urlsplit

from v3lum.core.entities import Entity, generic_address_kind, platform_for_url
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
from v3lum.core.models import Status
from v3lum.core.sanitize import find_secrets, mask_secret

# ---- hosts and registry sources ------------------------------------------------------------------
NPM_HOST = "registry.npmjs.org"
PYPI_HOST = "pypi.org"
CODEBERG_HOST = "codeberg.org"
DEVTO_HOST = "dev.to"
HF_HOST = "huggingface.co"
DOCKERHUB_HOST = "hub.docker.com"

SOURCE_NPM = "npm.registry"
SOURCE_PYPI = "pypi.json_api"
SOURCE_CODEBERG = "codeberg.api"
SOURCE_DEVTO = "dev_to.users_api"
SOURCE_HF = "huggingface.users_api"
SOURCE_DOCKERHUB = "docker_hub.hub_api"

JSON_CAP = 4 * 1024 * 1024
TOP_PACKAGES = 5  # P100 cond 7: top 5 packages in the summary row
MAX_EMAIL_PIVOTS = 10

# ======================================================================================
# common helpers
# ======================================================================================

_HTML_START_RE = re.compile(r"^\s*(?:<!doctype\s+html|<html\b|<head\b|<body\b|<!--|<title\b)", re.I)
_EMAIL_SHAPE_RE = re.compile(r"^[A-Za-z0-9._%+'\-]{1,64}@(?:[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?\.)+[A-Za-z]{2,63}$")
_DEV_DATE_RE = re.compile(r"^([A-Z][a-z]{2})\s+(\d{1,2}),\s+(\d{4})$")
_MONTHS = {m: i for i, m in enumerate(("Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"), 1)}
_ISO_RE = re.compile(r"^(\d{4}-\d{2}-\d{2})[T ](\d{2}:\d{2}:\d{2})(?:\.(\d+))?(Z|[+-]\d{2}:?\d{2})?$")


def to_text(raw: Any, cap: int | None = None) -> tuple[str, bool]:
    """``(text, truncated)`` for str/bytes input; other types give ``('', False)``."""
    if raw is None:
        return "", False
    if isinstance(raw, (bytes, bytearray, memoryview)):
        data = bytes(raw)
        truncated = cap is not None and len(data) > cap
        return (data[:cap] if truncated else data).decode("utf-8", errors="replace"), truncated
    if isinstance(raw, str):
        if cap is not None:
            enc = raw.encode("utf-8", errors="replace")
            if len(enc) > cap:
                return enc[:cap].decode("utf-8", errors="ignore"), True
        return raw, False
    return "", False


def looks_like_html(raw: Any) -> bool:
    """HTML where JSON or plain text was expected: could not verify (rule 5), never an absence."""
    text = raw if isinstance(raw, str) else to_text(raw)[0]
    return bool(_HTML_START_RE.match(text or ""))


def load_json(raw: Any, cap: int = JSON_CAP) -> tuple[Any, str | None]:
    """``(obj, reason)``: parse str/bytes (dict/list pass through); reason None on success."""
    if isinstance(raw, (dict, list)):
        return raw, None
    text, truncated = to_text(raw, cap)
    if not text.strip():
        return None, "empty body"
    if looks_like_html(text):
        return None, "HTML page instead of JSON"
    try:
        return json.loads(text), None
    except ValueError:
        return None, "truncated body" if truncated else "malformed JSON"


def to_int(value: Any) -> int | None:
    if isinstance(value, bool):
        return None
    if isinstance(value, int):
        return value
    if isinstance(value, float) and value == value and abs(value) < 1e18:
        return int(value)
    if isinstance(value, str) and re.fullmatch(r"\s*-?\d{1,18}\s*", value):
        return int(value)
    return None


def to_str(value: Any, cap: int | None = None) -> str | None:
    if not isinstance(value, str):
        return None
    s = value.strip()
    if not s:
        return None
    return s[:cap] if cap else s


def iso_utc(value: Any) -> str | None:
    """'YYYY-MM-DDTHH:MM:SSZ' from ISO strings, epoch seconds, RFC 2822 dates and DEV's 'Feb  9, 2016'."""
    if value is None or isinstance(value, bool):
        return None
    if isinstance(value, (int, float)):
        try:
            return _dt.datetime.fromtimestamp(float(value), _dt.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
        except (OverflowError, OSError, ValueError):
            return None
    if not isinstance(value, str):
        return None
    s = value.strip()
    if not s or s.startswith("0001-01-01") or len(s) > 64:
        return None
    m = _DEV_DATE_RE.match(s)
    if m and m.group(1) in _MONTHS:
        try:
            return _dt.datetime(int(m.group(3)), _MONTHS[m.group(1)], int(m.group(2)), tzinfo=_dt.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
        except ValueError:
            return None
    m = _ISO_RE.match(s)
    if m:
        tz = m.group(4) or "Z"
        tz = "+00:00" if tz == "Z" else (tz if ":" in tz else tz[:3] + ":" + tz[3:])
        try:
            d = _dt.datetime.fromisoformat(m.group(1) + "T" + m.group(2) + tz)
        except ValueError:
            return None
        return d.astimezone(_dt.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    if re.fullmatch(r"\d{4}-\d{2}-\d{2}", s):
        return s + "T00:00:00Z"
    try:
        d = parsedate_to_datetime(s)
    except (TypeError, ValueError, IndexError):
        return None
    if d is None:
        return None
    if d.tzinfo is None:
        d = d.replace(tzinfo=_dt.timezone.utc)
    return d.astimezone(_dt.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def normalise_email(value: Any) -> str | None:
    """Lower-cased address or None (no display names, no angle brackets)."""
    if not isinstance(value, str):
        return None
    s = value.strip().strip("<>").strip()
    return s.lower() if _EMAIL_SHAPE_RE.match(s) else None


def split_addresses(value: Any) -> list[tuple[str | None, str]]:
    """'A <a@x>, b@y' -> [(display name or None, address)] with valid addresses only."""
    if not isinstance(value, str) or "@" not in value or len(value) > 4000:
        return []
    out = []
    for name, addr in getaddresses([value]):
        e = normalise_email(addr)
        if e:
            out.append(((name or "").strip() or None, e))
    return out


def is_generic_email(addr: str) -> bool:
    """A4: generic, role and test addresses (core list) are capped at POSSIBLE and never scored."""
    try:
        return bool(generic_address_kind(addr))
    except Exception:  # noqa: BLE001 - a broken list never stops a run
        return False


def safe_url(value: Any, cap: int = 500) -> str | None:
    """An http(s) URL with a host, else None (javascript:, data: and junk are dropped)."""
    u = to_str(value, cap)
    if not u or not re.match(r"^https?://", u, re.I) or any(c.isspace() for c in u):
        return None
    try:
        host = urlsplit(u).hostname
    except ValueError:
        return None
    return u if host and "." in host else None


def with_scheme(value: Any) -> str | None:
    """Website field that may lack a scheme ('example.com') -> 'https://example.com'."""
    u = to_str(value, 500)
    if not u:
        return None
    if not re.match(r"^https?://", u, re.I):
        if not re.match(r"^[A-Za-z0-9.-]+\.[A-Za-z]{2,}(?:[/?#]\S*)?$", u):
            return None
        u = "https://" + u
    return safe_url(u)


def platform_summary(platform: str, found: bool, created: str | None = None, count: int | None = None,
                     count_kind: str | None = None, top: Iterable[str] = (), **extra: Any) -> dict[str, Any]:
    """P100 cond 7: one summary row per platform (found, created date, package/model count, top 5)."""
    row: dict[str, Any] = {"platform": platform, "found": bool(found), "created": created, "count": count,
                           "count_kind": count_kind, "top": list(top or [])[:TOP_PACKAGES]}
    row.update({k: v for k, v in extra.items() if v is not None})
    return row


# ---- case helpers --------------------------------------------------------------------------------


def case_keys(ctx: Any, entity: Entity | None = None) -> set[str]:
    """Entity keys of the case as far as a module can see them: the analyst-typed seeds of the scan
    (unconfirmed seeds excluded), the entities on this run's provenance path and the run entity."""
    keys: set[str] = set()
    if entity is not None:
        keys.add(entity.key)
    options = getattr(ctx, "options", None)
    unconfirmed = set(getattr(options, "unconfirmed_seeds", None) or ())
    for key in getattr(options, "seed_tlp", None) or {}:
        if str(key) not in unconfirmed:
            keys.add(str(key))
    for step in getattr(ctx, "provenance", ()) or ():
        if isinstance(step, (list, tuple)) and step:
            keys.add(str(step[0]))
    return keys


def case_emails(ctx: Any, entity: Entity | None = None) -> set[str]:
    """E-mail values already in the case (P100 cond 5, P102 cond 4)."""
    out = set()
    for key in case_keys(ctx, entity):
        if key.startswith("email:"):
            e = normalise_email(key.split(":", 1)[1])
            if e:
                out.add(e)
    return out


def case_logins(ctx: Any, entity: Entity | None = None) -> dict[str, set[str]]:
    """{platform: {lower-case handles}} of platform-qualified accounts already in the case (social_account
    keys and profile URLs): the logins 'already linked to the seed' of P100 cond 7."""
    out: dict[str, set[str]] = {}
    for key in case_keys(ctx, entity):
        etype, _, value = key.partition(":")
        if etype == T.SOCIAL_ACCOUNT.value and ":" in value:
            platform, _, handle = value.partition(":")
            out.setdefault(platform, set()).add(handle.lower())
        elif etype == T.URL.value:
            hit = platform_for_url(value)
            if hit is not None:
                out.setdefault(hit[0], set()).add(hit[1].lower())
    return out


def case_usernames(ctx: Any, entity: Entity | None = None, platform: str = "") -> set[str]:
    """Usernames of the case: username seeds plus ``platform``-qualified accounts."""
    out = set()
    for key in case_keys(ctx, entity):
        etype, _, value = key.partition(":")
        if etype == T.USERNAME.value and value:
            out.add(value.lower())
    if platform:
        out |= case_logins(ctx, entity).get(platform, set())
    return out


_HANDLE_RE = re.compile(r"^[A-Za-z0-9_.-]{1,64}$")


def account_handle(entity: Entity, platform: str, *, url_hosts: Iterable[str] = ()) -> str | None:
    """The account handle a platform adapter investigates: a username, a '<platform>:<handle>' social
    account of that platform, or a profile URL of that platform (parsed offline, never fetched)."""
    if entity.type is T.USERNAME:
        return entity.value if _HANDLE_RE.match(entity.value) else None
    if entity.type is T.SOCIAL_ACCOUNT:
        plat, _, handle = entity.value.partition(":")
        return handle if plat == platform and _HANDLE_RE.match(handle) else None
    if entity.type is T.URL:
        hit = platform_for_url(entity.value)
        if hit is not None and hit[0] == platform:
            return hit[1]
        try:
            host = (urlsplit(entity.value).hostname or "").lower()
        except ValueError:
            return None
        if host in set(url_hosts):
            seg = [p for p in urlsplit(entity.value).path.split("/") if p]
            if seg and _HANDLE_RE.match(seg[0]):
                return seg[0].lower()
    return None


def seed_email_entry(addr: Any, case_mails: Iterable[str] = (), sources: Iterable[str] = (), basis: str | None = None) -> dict[str, Any] | None:
    """P100 cond 5/6: PROBABLE only when the address equals an e-mail already in the case (architect
    floor), otherwise POSSIBLE, also when it recurs on >= 2 packages; generic/role/test addresses are
    capped at POSSIBLE. Always expand=False; never auto-sent to breach/stealer modules (A4)."""
    e = normalise_email(addr)
    if not e:
        return None
    in_case = e in {normalise_email(c) for c in case_mails or () if normalise_email(c)}
    generic = is_generic_email(e)
    src = sorted({str(s) for s in sources or () if s})
    return {"email": e, "confidence": "probable" if in_case and not generic else "possible", "in_case": in_case,
            "generic": generic, "basis": basis, "sources": src, "recurrence": len(src)}


def emit_seed_emails(res: Any, entries: list[dict[str, Any]], *, platform: str, relation: str = "maintainer_email") -> None:
    """Pivot the seed's own e-mails (expand=False, case-bound, never sent to breach modules)."""
    for ent in entries[:MAX_EMAIL_PIVOTS]:
        where = f" on {ent['recurrence']} package(s)" if ent.get("recurrence", 0) > 1 else ""
        why = "equals an e-mail already in the case" if ent["confidence"] == "probable" else (
            "generic/role/test address (A4 cap)" if ent["generic"] else "not yet seen in the case")
        res.pivot(T.EMAIL, ent["email"], relation, confidence=ent["confidence"], expand=False,
                  note=f"{platform}: e-mail of the investigated account's own record{where} ({why}); case-bound, "
                       "never sent to breach/stealer modules automatically")


def attempt(problems: dict[str, list[tuple[Status, str, str]]], source: str, label: str, fn: Any) -> Any:
    """Run one secondary call: a refusal or failure is recorded per source and the run goes on. Rate
    limits, quotas, deadlines, cancellation and the request cap propagate (the engine keeps the data
    already built and marks the run partial)."""
    try:
        return fn()
    except (RateLimited, QuotaExceeded, DeadlineExceeded):
        raise
    except Blocked as exc:
        problems.setdefault(source, []).append((Status.BLOCKED, exc.reason_code, f"{label}: {exc}"))
    except AuthRequired as exc:
        problems.setdefault(source, []).append((Status.BLOCKED, "challenge", f"{label}: {exc}"))
    except OfflineError as exc:
        problems.setdefault(source, []).append((Status.UNAVAILABLE, "offline", f"{label}: {exc}"))
    except (HttpError, NetworkError) as exc:
        code = "timeout" if getattr(exc, "reason_code", "") == "timeout" else "error"
        problems.setdefault(source, []).append((Status.ERROR, code, f"{label}: could not verify ({exc})"))
    except ValueError as exc:
        problems.setdefault(source, []).append((Status.ERROR, "error", f"{label}: unexpected answer ({exc})"))
    return None


def report_problems(res: Any, problems: dict[str, list[tuple[Status, str, str]]]) -> None:
    """One per-source status line for the secondary calls that could not be verified."""
    for source, items in problems.items():
        status, code, _ = items[0]
        res.source_status(source, status, reason_code=code, reason="; ".join(text for _s, _c, text in items)[:500])


# ======================================================================================
# npm registry (C0242): /-/v1/search?text=maintainer:{u}
# ======================================================================================

_NPM_USER_RE = re.compile(r"^[a-z0-9][a-z0-9._-]{0,213}$")
_NPM_SYSTEM_PUBLISHERS = frozenset({"github actions", "gitlab ci", "npm-oidc"})


def npm_search_url(username: Any, size: int = 20) -> str | None:
    """P100 cond 3: registry.npmjs.org/-/v1/search?text=maintainer:{u} (never www.npmjs.com/~{u}, cond 4)."""
    u = username.strip().lower() if isinstance(username, str) else ""
    if not _NPM_USER_RE.match(u):
        return None
    size = max(1, min(int(size), 250))
    return f"https://{NPM_HOST}/-/v1/search?text={quote('maintainer:' + u, safe=':')}&size={size}"


def parse_npm_search(raw: Any, seed_username: str | None = None, case_mails: Iterable[str] = (), top: int = TOP_PACKAGES) -> dict[str, Any]:
    """P100 cond 5-7 (C0242): maintainer search -> summary, the seed's packages and the seed's own e-mails.

    Co-maintainer, publisher and organisation e-mails/usernames are counted, never stored, listed or
    pivoted; packages on which the seed does not appear (search noise) are counted, their people not even
    counted. ``seed_username=None`` (P359) gives package names and counts only."""
    res: dict[str, Any] = {"ok": False, "reason": None, "total": 0, "packages": [], "emails": [],
                           "counted": {"co_maintainers": 0, "other_emails": 0, "system_publishers": 0, "not_seed_packages": 0},
                           "summary": None}
    obj, why = load_json(raw)
    if why or not isinstance(obj, dict) or not isinstance(obj.get("objects"), list):
        res["reason"] = why or ("error object: " + str(obj.get("error"))[:120] if isinstance(obj, dict) and obj.get("error")
                                else "unexpected JSON shape")
        return res
    res["ok"] = True
    seed = seed_username.strip().lower() if isinstance(seed_username, str) and seed_username.strip() else None
    others: set[str] = set()
    other_mails: set[str] = set()
    seed_mails: dict[str, set[str]] = {}
    valid = 0
    for o in obj["objects"][:250]:
        pkg = o.get("package") if isinstance(o, dict) else None
        name = to_str(pkg.get("name"), 214) if isinstance(pkg, dict) else None
        if not name:
            continue
        valid += 1
        people: list[tuple[str, dict[str, Any]]] = []
        pub = pkg.get("publisher")
        if isinstance(pub, dict):
            people.append(("publisher", pub))
        maint = pkg.get("maintainers")
        people += [("maintainer", m) for m in (maint if isinstance(maint, list) else []) if isinstance(m, dict)]
        roles: set[str] = set()
        listed = False
        pkg_others: set[str] = set()
        pkg_other_mails: set[str] = set()
        pkg_seed_mails: set[str] = set()
        system = 0
        for role, p in people:
            u = (to_str(p.get("username"), 214) or "").lower()
            mail = normalise_email(p.get("email"))
            if role == "publisher" and ("trustedPublisher" in p or u in _NPM_SYSTEM_PUBLISHERS):
                system += 1
                continue
            if seed and u == seed:
                listed = True
                roles.add(role)
                if mail:
                    pkg_seed_mails.add(mail)
            else:
                if u:
                    pkg_others.add(u)
                if mail:
                    pkg_other_mails.add(mail)
        if seed and not listed:
            res["counted"]["not_seed_packages"] += 1
            continue
        res["counted"]["system_publishers"] += system
        others |= pkg_others
        other_mails |= pkg_other_mails
        for mail in pkg_seed_mails:
            seed_mails.setdefault(mail, set()).add(name)
        links = pkg.get("links") if isinstance(pkg.get("links"), dict) else {}
        res["packages"].append({"name": name, "version": to_str(pkg.get("version"), 64), "date": iso_utc(pkg.get("date")),
                                "roles": sorted(roles), "repository": to_str(links.get("repository"), 300),
                                "url": safe_url(links.get("npm"), 300)})
    res["total"] = to_int(obj.get("total")) or 0
    if obj["objects"] and not valid:
        res.update(ok=False, reason="no valid package object in a non-empty answer")
        return res
    res["counted"]["co_maintainers"] = len(others)
    res["counted"]["other_emails"] = len(other_mails - set(seed_mails))
    for mail in sorted(seed_mails):
        ent = seed_email_entry(mail, case_mails, sources=seed_mails[mail], basis="npm maintainer/publisher record of the seed")
        if ent:
            res["emails"].append(ent)
    dates = [p["date"] for p in res["packages"] if p["date"]]
    res["summary"] = platform_summary("npm", bool(res["packages"]), created=min(dates) if dates else None,
                                      count=len(res["packages"]) if seed else res["total"], count_kind="packages",
                                      top=[p["name"] for p in res["packages"][:top]],
                                      created_basis="earliest package date in the result page" if dates else None)
    if not res["packages"]:
        res["reason"] = "no packages attributed to the seed"
    return res


# ======================================================================================
# PyPI package JSON (C0253): /pypi/{package}/json
# ======================================================================================

_PYPI_NAME_RE = re.compile(r"^([A-Z0-9]|[A-Z0-9][A-Z0-9._-]{0,200}[A-Z0-9])$", re.I)


def pypi_normalise(name: Any) -> str | None:
    """PEP 503 normalised project name, or None when it is not a valid PEP 508 name."""
    if not isinstance(name, str) or not _PYPI_NAME_RE.match(name.strip()):
        return None
    return re.sub(r"[-_.]+", "-", name.strip()).lower()


def pypi_json_url(name: Any) -> str | None:
    """P100 cond 3: pypi.org/pypi/{package}/json only (never pypi.org/user/*, cond 4)."""
    n = pypi_normalise(name)
    return f"https://{PYPI_HOST}/pypi/{n}/json" if n else None


def pypi_package_of(entity: Entity) -> str | None:
    """Package name of an analyst-typed keyword or of a pypi.org/project/<name> URL."""
    if entity.type is T.KEYWORD:
        return pypi_normalise(entity.value.removeprefix("pypi:").strip())
    if entity.type is T.URL:
        try:
            sp = urlsplit(entity.value)
        except ValueError:
            return None
        if (sp.hostname or "").lower() not in (PYPI_HOST, "www.pypi.org"):
            return None
        m = re.match(r"^/(?:project|simple|pypi)/([^/]+)", sp.path or "")
        return pypi_normalise(m.group(1)) if m else None
    return None


def _name_key(value: Any) -> str:
    return re.sub(r"[^a-z0-9]", "", value.lower()) if isinstance(value, str) else ""


def parse_pypi_package(raw: Any, seed_usernames: Iterable[str] = (), case_mails: Iterable[str] = ()) -> dict[str, Any]:
    """P100 cond 3/5/6/7 (C0253): package JSON -> summary, project URLs and the seed's own e-mail only.

    PyPI author fields carry no usernames, so 'the e-mail of the maintainer whose username equals the
    investigated one' (cond 5) is applied strictly: a case username must hold a role in
    ``ownership.roles``, and the address must carry that username as display name or local part, or be the
    package's only address while that username is its only role holder. Every other address is counted."""
    res: dict[str, Any] = {"ok": False, "reason": None, "name": None, "version": None, "summary_text": None,
                           "first_release": None, "last_release": None, "release_count": 0, "organization": None,
                           "seed_role": None, "seed": None, "role_count": 0, "project_urls": [], "emails": [],
                           "counted": {"other_emails": 0, "other_roles": 0}, "summary": None}
    obj, why = load_json(raw)
    if why or not isinstance(obj, dict) or not isinstance(obj.get("info"), dict):
        res["reason"] = why or "unexpected JSON shape"
        return res
    info = obj["info"]
    res.update(ok=True, name=to_str(info.get("name"), 200), version=to_str(info.get("version"), 64),
               summary_text=to_str(info.get("summary"), 300))
    dates: list[str] = []
    count = 0
    rel = obj.get("releases") if isinstance(obj.get("releases"), dict) else {}
    for files in list(rel.values())[:5000]:
        ds = [iso_utc(f.get("upload_time_iso_8601") or f.get("upload_time")) for f in (files if isinstance(files, list) else [])
              if isinstance(f, dict)]
        ds = [d for d in ds if d]
        if ds:
            count += 1
            dates.append(min(ds))
    res.update(release_count=count, first_release=min(dates) if dates else None, last_release=max(dates) if dates else None)
    own = obj.get("ownership") if isinstance(obj.get("ownership"), dict) else {}
    res["organization"] = to_str(own.get("organization"), 100)
    seeds = {_name_key(s): s for s in seed_usernames or () if _name_key(s)}
    roles = [r for r in (own.get("roles") if isinstance(own.get("roles"), list) else []) if isinstance(r, dict) and to_str(r.get("user"))]
    res["role_count"] = len(roles)
    seed_key = ""
    for r in roles:
        key = _name_key(r.get("user"))
        if key in seeds and not seed_key:
            seed_key = key
            res["seed_role"] = to_str(r.get("role"), 40) or "role"
            res["seed"] = seeds[key]
        else:
            res["counted"]["other_roles"] += 1
    urls = info.get("project_urls") if isinstance(info.get("project_urls"), dict) else {}
    seen: set[str] = set()
    for label, u in list(urls.items())[:30] + [("Home-page", info.get("home_page"))]:
        url = safe_url(u)
        if url and url not in seen:
            seen.add(url)
            res["project_urls"].append({"label": to_str(label, 60), "url": url})
    addrs: list[tuple[str | None, str]] = []
    for field in ("author_email", "maintainer_email"):
        addrs += split_addresses(info.get(field))
    distinct = {m for _, m in addrs}
    sole = bool(seed_key) and res["role_count"] == 1 and len(distinct) == 1
    others: set[str] = set()
    kept: set[str] = set()
    for name, mail in addrs:
        local = mail.split("@", 1)[0]
        if not seed_key:
            others.add(mail)
            continue
        if _name_key(name) == seed_key or _name_key(local) == seed_key:
            basis = "a case username holds a PyPI role and the " + ("display name" if _name_key(name) == seed_key else "local part") + " matches it"
        elif sole:
            basis = "only address of a package whose only role holder is the case username"
        else:
            others.add(mail)
            continue
        if mail in kept:
            continue
        ent = seed_email_entry(mail, case_mails, sources=[res["name"] or "?"], basis=basis)
        if ent:
            kept.add(mail)
            res["emails"].append(ent)
    res["counted"]["other_emails"] = len(others - kept)
    res["summary"] = platform_summary("pypi", True, created=res["first_release"], count=res["release_count"],
                                      count_kind="releases", top=[res["name"]] if res["name"] else [],
                                      created_basis="first release of the package" if res["first_release"] else None)
    return res


# ======================================================================================
# Codeberg / Forgejo users API (C0245): codeberg.org only (self-hosted instances are targets)
# ======================================================================================

_GITEA_USER_RE = re.compile(r"^[A-Za-z0-9](?:[A-Za-z0-9._-]{0,38}[A-Za-z0-9])?$")
_GITEA_RESERVED = frozenset({"search", "heatmap", "api", "explore", "admin", "user", "org", "repo"})


def codeberg_user_url(username: Any) -> str | None:
    """P100 cond 3/4: codeberg.org/api/v1/users/{u} only (corporate/self-hosted Gitea = target)."""
    if not isinstance(username, str) or not _GITEA_USER_RE.match(username.strip()):
        return None
    if username.strip().lower() in _GITEA_RESERVED:
        return None
    return f"https://{CODEBERG_HOST}/api/v1/users/{quote(username.strip(), safe='')}"


def parse_codeberg_user(raw: Any, seed_username: str | None = None, case_mails: Iterable[str] = ()) -> dict[str, Any]:
    """P100 cond 3/5/7 (C0245): user -> summary; a public (non-noreply) e-mail of the seed's own account is
    kept under the cond 5 rule; noreply placeholders are dropped."""
    res: dict[str, Any] = {"ok": False, "reason": None, "login": None, "id": None, "full_name": None, "created": None,
                           "location": None, "website": None, "description": None, "followers": None, "following": None,
                           "email_hidden": True, "emails": [], "summary": None}
    obj, why = load_json(raw)
    if why or not isinstance(obj, dict) or not to_str(obj.get("login")):
        res["reason"] = why or "unexpected JSON shape"
        return res
    login = obj["login"].strip()[:64]
    res.update(ok=True, login=login, id=to_int(obj.get("id")), full_name=to_str(obj.get("full_name"), 200),
               created=iso_utc(obj.get("created")), location=to_str(obj.get("location"), 200),
               website=with_scheme(obj.get("website")), description=to_str(obj.get("description"), 1000),
               followers=to_int(obj.get("followers_count")), following=to_int(obj.get("following_count")))
    mail = normalise_email(obj.get("email"))
    public = bool(mail) and not mail.endswith("@noreply.codeberg.org") and ".noreply." not in mail
    if public and seed_username and login.lower() == str(seed_username).strip().lower():
        res["email_hidden"] = False
        ent = seed_email_entry(mail, case_mails, sources=["codeberg:" + login], basis="public profile e-mail of the account")
        if ent:
            res["emails"].append(ent)
    res["summary"] = platform_summary("codeberg", True, created=res["created"])
    return res


# ======================================================================================
# DEV / Forem users API (C0247)
# ======================================================================================

_DEVTO_USER_RE = re.compile(r"^[A-Za-z0-9_][A-Za-z0-9_.-]{0,59}$")
_GITHUB_LOGIN_RE = re.compile(r"^[A-Za-z0-9](?:[A-Za-z0-9-]{0,38})$")
_X_LOGIN_RE = re.compile(r"^[A-Za-z0-9_]{1,15}$")


def devto_user_url(username: Any) -> str | None:
    """P100 cond 3: dev.to/api/users/by_username?url={u}."""
    if not isinstance(username, str) or not _DEVTO_USER_RE.match(username.strip()):
        return None
    return f"https://{DEVTO_HOST}/api/users/by_username?url={quote(username.strip(), safe='')}"


def parse_devto_user(raw: Any) -> dict[str, Any]:
    """P100 cond 3/7 (C0247): DEV user -> summary + declared GitHub/X logins (see devto_declared_links)."""
    res: dict[str, Any] = {"ok": False, "reason": None, "username": None, "id": None, "name": None, "summary_text": None,
                           "location": None, "website": None, "joined": None, "github_username": None,
                           "twitter_username": None, "summary": None}
    obj, why = load_json(raw)
    if why or not isinstance(obj, dict) or not to_str(obj.get("username")):
        res["reason"] = why or (f"error object: {str(obj.get('error'))[:120]}" if isinstance(obj, dict) and obj.get("error")
                                else "unexpected JSON shape")
        return res
    gh = to_str(obj.get("github_username"), 39)
    tw = (to_str(obj.get("twitter_username"), 16) or "").lstrip("@") or None
    res.update(ok=True, username=obj["username"].strip()[:60], id=to_int(obj.get("id")), name=to_str(obj.get("name"), 200),
               summary_text=to_str(obj.get("summary"), 1000), location=to_str(obj.get("location"), 200),
               website=with_scheme(obj.get("website_url")), joined=iso_utc(obj.get("joined_at")),
               github_username=gh if gh and _GITHUB_LOGIN_RE.match(gh) else None,
               twitter_username=tw if tw and _X_LOGIN_RE.match(tw) else None)
    res["summary"] = platform_summary("devto", True, created=res["joined"])
    return res


def devto_declared_links(profile: dict[str, Any], linked_logins: dict[str, set[str]] | None = None) -> list[dict[str, Any]]:
    """P100 cond 7 (Ceos rule): a DEV github_username/twitter_username equal to a login already linked to the
    seed raises that link to PROBABLE; otherwise it is a POSSIBLE declared account. Always expand=False."""
    out = []
    linked = {k: {str(v).lower() for v in (vals or ())} for k, vals in (linked_logins or {}).items()}
    for field, platform in (("github_username", "github"), ("twitter_username", "x")):
        login = profile.get(field) if isinstance(profile, dict) else None
        if not isinstance(login, str) or not login:
            continue
        upgraded = login.lower() in linked.get(platform, set())
        out.append({"platform": platform, "handle": login, "confidence": "probable" if upgraded else "possible",
                    "raises_existing_link": upgraded})
    return out


# ======================================================================================
# Hugging Face user overview (C0251)
# ======================================================================================

_HF_USER_RE = re.compile(r"^[A-Za-z0-9](?:[A-Za-z0-9_.-]{0,94}[A-Za-z0-9])?$")


def hf_overview_url(username: Any) -> str | None:
    """P100 cond 1: huggingface.co/api/users/{u}/overview."""
    if not isinstance(username, str) or not _HF_USER_RE.match(username.strip()):
        return None
    return f"https://{HF_HOST}/api/users/{quote(username.strip(), safe='')}/overview"


def parse_hf_overview(raw: Any) -> dict[str, Any]:
    """P100 cond 1/7 (C0251): overview -> summary row (created, model count) and organisation names. Avatars
    are not kept. The top-5 models would need /api/models?author= (not a cond 3 endpoint): left empty."""
    res: dict[str, Any] = {"ok": False, "reason": None, "user": None, "fullname": None, "type": None, "created": None,
                           "is_pro": None, "models": None, "datasets": None, "spaces": None, "followers": None,
                           "following": None, "orgs": [], "details": None, "summary": None}
    obj, why = load_json(raw)
    if why or not isinstance(obj, dict) or not to_str(obj.get("user")):
        res["reason"] = why or (f"error object: {str(obj.get('error'))[:120]}" if isinstance(obj, dict) and obj.get("error")
                                else "unexpected JSON shape")
        return res
    res.update(ok=True, user=obj["user"].strip()[:96], fullname=to_str(obj.get("fullname"), 200), type=to_str(obj.get("type"), 20),
               created=iso_utc(obj.get("createdAt")), is_pro=obj.get("isPro") if isinstance(obj.get("isPro"), bool) else None,
               models=to_int(obj.get("numModels")), datasets=to_int(obj.get("numDatasets")), spaces=to_int(obj.get("numSpaces")),
               followers=to_int(obj.get("numFollowers")), following=to_int(obj.get("numFollowing")),
               details=to_str(obj.get("details"), 1000))
    orgs = obj.get("orgs") if isinstance(obj.get("orgs"), list) else []
    res["orgs"] = [o["name"].strip()[:96] for o in orgs[:50] if isinstance(o, dict) and to_str(o.get("name"))]
    res["summary"] = platform_summary("huggingface", True, created=res["created"], count=res["models"], count_kind="models",
                                      datasets=res["datasets"], spaces=res["spaces"])
    return res


# ======================================================================================
# Docker Hub v2 API (C0234): hub.docker.com only; registry-1/auth.docker.io never contacted (P102 cond 2)
# ======================================================================================

DOCKERHUB_REPO_CAP = 5  # P102 cond 3: <= 5 repositories (most recent), latest tag only, one page
_DH_NS_RE = re.compile(r"^[a-z0-9](?:[a-z0-9_.-]{0,253}[a-z0-9])?$")
_DH_TAG_RE = re.compile(r"^[A-Za-z0-9_][A-Za-z0-9_.-]{0,127}$")
LABEL_EMAIL_KEYS = frozenset({"maintainer", "org.opencontainers.image.authors", "org.label-schema.vendor", "author", "authors", "email"})
#: official base-image maintainer addresses: always inherited labels (P102 cond 4)
KNOWN_INHERITED_LABEL_EMAILS = frozenset({"docker-maint@nginx.com"})
#: AWS documentation example keys (secret scanners allow-list them): reported at severity info
DOCUMENTATION_SECRETS = frozenset({"AKIAIOSFODNN7EXAMPLE", "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"})
_HIGH_KINDS = re.compile(r"private_key|aws_secret|url_cred|github|gitlab|npm|docker|slack|stripe|pypi|sendgrid|digitalocean|shopify", re.I)
_URL_USERINFO_RE = re.compile(r"\b[a-z][a-z0-9+.-]{1,20}://([^\s:/@'\"]{1,64}):([^\s/@'\"]{1,128})@[A-Za-z0-9.-]+")
_SEV_ORDER = {"info": 0, "low": 1, "medium": 2, "high": 3}


def dockerhub_urls(namespace: Any, repo: Any = None, tag: Any = None, page_size: int = DOCKERHUB_REPO_CAP) -> dict[str, str] | None:
    """P102 cond 1/3: hub.docker.com v2 endpoints only: users/{u} (308 -> orgs/{o}), repositories (one
    page, newest first, page_size <= 100), the latest tag and its images (layer instructions)."""
    ns = namespace.strip().lower() if isinstance(namespace, str) else ""
    if not _DH_NS_RE.match(ns):
        return None
    base = f"https://{DOCKERHUB_HOST}/v2/"
    urls = {"user": f"{base}users/{ns}/", "org": f"{base}orgs/{ns}",
            "repositories": f"{base}repositories/{ns}/?page_size={max(1, min(int(page_size), 100))}&ordering=last_updated"}
    if isinstance(repo, str) and _DH_NS_RE.match(repo.strip().lower()):
        r = repo.strip().lower()
        urls["tags"] = f"{base}repositories/{ns}/{r}/tags?page_size=1&ordering=last_updated"
        if isinstance(tag, str) and _DH_TAG_RE.match(tag.strip()):
            urls["images"] = f"{base}repositories/{ns}/{r}/tags/{quote(tag.strip(), safe='')}/images"
    return urls


def dockerhub_namespace_of(entity: Entity) -> str | None:
    """A Docker ID/organisation name from a username, 'dockerhub:<ns>' or a hub.docker.com/u|r/<ns> URL."""
    if entity.type is T.URL:
        try:
            sp = urlsplit(entity.value)
        except ValueError:
            return None
        if (sp.hostname or "").lower() != DOCKERHUB_HOST:
            return None
        seg = [p for p in (sp.path or "").split("/") if p]
        if len(seg) >= 2 and seg[0] in ("u", "r", "orgs"):
            ns = seg[1].lower()
            return ns if _DH_NS_RE.match(ns) else None
        return None
    handle = account_handle(entity, "dockerhub")
    if handle and _DH_NS_RE.match(handle.lower()):
        return handle.lower()
    return None


def rate_remaining(headers: Any) -> int | None:
    """X-RateLimit-Remaining / RateLimit-Remaining (P102 cond 3, P103 cond 5) or the IETF 'r=' form."""
    h = {str(k).lower(): str(v) for k, v in (headers or {}).items()} if isinstance(headers, dict) else {}
    for name in ("x-ratelimit-remaining", "ratelimit-remaining"):
        n = to_int(h.get(name))
        if n is not None:
            return n
    m = re.search(r"\br=(\d+)", h.get("ratelimit", ""))
    return int(m.group(1)) if m else None


def gravatar_hash(url: Any) -> str | None:
    """32/64-hex Gravatar hash from an avatar URL (feeds only avatar_correlation's local comparison)."""
    if not isinstance(url, str):
        return None
    m = re.match(r"^https?://(?:www\.|secure\.|[a-z0-9]+\.)?gravatar\.com/avatar/([0-9a-f]{32}|[0-9a-f]{64})\b", url, re.I)
    return m.group(1).lower() if m else None


def parse_dockerhub_account(raw: Any) -> dict[str, Any]:
    """P102 cond 1: users/{u} or orgs/{o} -> account facts (Gravatar hash for P114, profile URL)."""
    res: dict[str, Any] = {"ok": False, "reason": None, "kind": None, "name": None, "full_name": None, "location": None,
                           "company": None, "profile_url": None, "joined": None, "badge": None, "gravatar_hash": None, "summary": None}
    obj, why = load_json(raw)
    if why or not isinstance(obj, dict):
        res["reason"] = why or "unexpected JSON shape"
        return res
    name = to_str(obj.get("username"), 255) or to_str(obj.get("orgname"), 255)
    if not name:
        res["reason"] = f"error object: {str(obj.get('message'))[:120]}" if obj.get("message") else "no account name"
        return res
    kind = "org" if (obj.get("orgname") or str(obj.get("type", "")).lower() == "organization") else "user"
    res.update(ok=True, kind=kind, name=name, full_name=to_str(obj.get("full_name"), 200), location=to_str(obj.get("location"), 200),
               company=to_str(obj.get("company"), 200), profile_url=with_scheme(obj.get("profile_url")),
               joined=iso_utc(obj.get("date_joined")), badge=to_str(obj.get("badge"), 60), gravatar_hash=gravatar_hash(obj.get("gravatar_url")))
    res["summary"] = platform_summary("dockerhub", True, created=res["joined"], account_kind=kind)
    return res


def parse_dockerhub_repositories(raw: Any, cap: int = DOCKERHUB_REPO_CAP) -> dict[str, Any]:
    """P102 cond 3: one page of repositories -> the <= 5 most recently updated public ones."""
    res: dict[str, Any] = {"ok": False, "reason": None, "count": 0, "repos": [], "has_more": False}
    obj, why = load_json(raw)
    if why or not isinstance(obj, dict) or not isinstance(obj.get("results"), list):
        res["reason"] = why or "unexpected JSON shape"
        return res
    repos = []
    for r in obj["results"][:100]:
        if not isinstance(r, dict) or not to_str(r.get("name")) or r.get("is_private") is True:
            continue
        name = r["name"].strip().lower()
        if not _DH_NS_RE.match(name):
            continue
        repos.append({"name": name, "description": to_str(r.get("description"), 300), "stars": to_int(r.get("star_count")),
                      "pulls": to_int(r.get("pull_count")), "last_updated": iso_utc(r.get("last_updated")),
                      "registered": iso_utc(r.get("date_registered"))})
    repos.sort(key=lambda x: x["last_updated"] or "", reverse=True)
    res.update(ok=True, count=to_int(obj.get("count")) or len(repos), repos=repos[:cap], has_more=bool(obj.get("next")) or len(repos) > cap)
    if not repos:
        res["reason"] = "no public repositories"
    return res


def parse_dockerhub_tags(raw: Any) -> dict[str, Any]:
    """P102 cond 3: newest tag only (name, date, digest, platforms). Pusher usernames are dropped."""
    res: dict[str, Any] = {"ok": False, "reason": None, "latest": None}
    obj, why = load_json(raw)
    if why or not isinstance(obj, dict) or not isinstance(obj.get("results"), list):
        res["reason"] = why or "unexpected JSON shape"
        return res
    tags = [t for t in obj["results"][:100] if isinstance(t, dict) and to_str(t.get("name")) and _DH_TAG_RE.match(t["name"].strip())]
    res["ok"] = True
    if not tags:
        res["reason"] = "no tags"
        return res
    tags.sort(key=lambda t: iso_utc(t.get("last_updated")) or "", reverse=True)
    t = tags[0]
    images = t.get("images") if isinstance(t.get("images"), list) else []
    res["latest"] = {"name": t["name"].strip(), "last_updated": iso_utc(t.get("last_updated")), "digest": to_str(t.get("digest"), 80),
                     "platforms": [f"{i.get('os')}/{i.get('architecture')}" for i in images[:32]
                                   if isinstance(i, dict) and isinstance(i.get("os"), str) and isinstance(i.get("architecture"), str)]}
    return res


def _instruction_kind(ins: str) -> str | None:
    m = re.match(r"^\s*([A-Z]+)\b", ins or "")
    return m.group(1) if m else None


def _label_emails(ins: str) -> list[tuple[str, str]]:
    """[(label key, e-mail)] from 'LABEL k=v k2=v2' (Hub renders values unquoted) or 'MAINTAINER x <e>'."""
    kind = _instruction_kind(ins)
    parts = ins.split(None, 1)
    body = parts[1] if len(parts) > 1 else ""
    if kind == "MAINTAINER":
        return [("maintainer", e) for _, e in split_addresses(body)]
    if kind != "LABEL":
        return []
    keys = [(m.start(), m.group(1)) for m in re.finditer(r"(?:^|\s)([A-Za-z0-9][A-Za-z0-9._-]{0,100})=", body)]
    out = []
    for m in re.finditer(r"[A-Za-z0-9._%+'\-]{1,64}@[A-Za-z0-9.-]{1,253}\.[A-Za-z]{2,63}", body):
        key = None
        for pos, k in keys:
            if pos <= m.start():
                key = k
        e = normalise_email(m.group(0))
        if e and key:
            out.append((key.lower(), e))
    return out


def base_boundary(instructions: list[str]) -> int:
    """Index of the last CMD/ENTRYPOINT followed by further instructions: everything up to it was
    inherited from base images (-1 when none)."""
    last = -1
    for i, ins in enumerate(instructions[:-1]):
        if _instruction_kind(ins) in ("CMD", "ENTRYPOINT"):
            last = i
    return last


def _domain_in(email: str, domains: Any) -> bool:
    """Is the address on one of ``domains`` (an iterable of names, or a callable ``domain -> bool`` such
    as the org profile's ``is_verified_domain``)?"""
    d = email.split("@", 1)[1] if "@" in email else ""
    if callable(domains):
        try:
            return bool(d) and bool(domains(d))
        except Exception:  # noqa: BLE001 - a broken check never stops a run
            return False
    for v in domains or ():
        v = str(v).lower().lstrip(".")
        if v and (d == v or d.endswith("." + v)):
            return True
    return False


def layer_secrets(ins: str) -> list[tuple[str, str, str | None, bool]]:
    """Secrets of one instruction through the core detectors (P145/P323): [(kind, value, variable,
    dropped)]. URL credentials ('scheme://user:pass@host') are dropped like passwords. Values live only
    in memory long enough to be masked."""
    out: list[tuple[str, str, str | None, bool]] = []
    seen: set[str] = set()
    for m in _URL_USERINFO_RE.finditer(ins):
        val = m.group(2)
        if val not in seen and not val.startswith("$"):
            seen.add(val)
            out.append(("url_credentials", val, None, True))
    for hit in find_secrets(ins):
        if hit.value in seen:
            continue
        seen.add(hit.value)
        before = ins[max(0, hit.start - 80):hit.start]
        var = re.search(r"([A-Za-z_][A-Za-z0-9_]{0,63})\s*[=:]\s*['\"]?$", before)
        out.append((hit.kind, hit.value, var.group(1) if var else None, hit.action == "drop"))
    return out


def parse_dockerhub_images(raw: Any, repo_tag: str | None = None, case_mails: Iterable[str] = (), verified_domains: Any = (),
                           org_confirmed: bool = False, platform: str = "linux/amd64") -> dict[str, Any]:
    """P102 cond 4/5: tags/{tag}/images -> label e-mails and masked layer secrets (one image, amd64 first).

    cond 4: LABEL/MAINTAINER e-mails are PROBABLE only when equal to a case e-mail or on the account's own
    verified domain; every other address is discarded (counted, never stored); labels inherited from base
    images (up to the base boundary, or known official maintainers) are ignored. cond 5: secrets ->
    type + first 4/last 4 + SHA-256 only (passwords: type only), never validated; one exposure with the
    repo:tag, the instruction indexes and a severity by type (high only for org_profile-confirmed accounts)."""
    res: dict[str, Any] = {"ok": False, "reason": None, "image": None, "label_emails": [],
                           "label_counts": {"kept": 0, "discarded": 0, "inherited": 0}, "exposures": [], "exposure": None}
    obj, why = load_json(raw)
    if why or not isinstance(obj, list):
        res["reason"] = why or "unexpected JSON shape"
        return res
    imgs = [i for i in obj[:64] if isinstance(i, dict) and isinstance(i.get("layers"), list)]
    res["ok"] = True
    if not imgs:
        res["reason"] = "no image with layer instructions"
        return res
    want_os, _, want_arch = platform.partition("/")
    img = next((i for i in imgs if i.get("os") == want_os and i.get("architecture") == want_arch), imgs[0])
    instructions = [(to_str(layer.get("instruction"), 20000) or "") for layer in img["layers"][:500] if isinstance(layer, dict)]
    boundary = base_boundary(instructions)
    res["image"] = {"repo_tag": repo_tag, "os": to_str(img.get("os"), 32), "architecture": to_str(img.get("architecture"), 32),
                    "digest": to_str(img.get("digest"), 80), "last_pushed": iso_utc(img.get("last_pushed")),
                    "layers": len(instructions), "base_boundary": boundary}
    case = {normalise_email(c) for c in case_mails or () if normalise_email(c)}
    kept: dict[str, dict[str, Any]] = {}
    counts = res["label_counts"]
    for idx, ins in enumerate(instructions):
        for key, mail in _label_emails(ins):
            if key not in LABEL_EMAIL_KEYS:
                continue
            if idx <= boundary or mail in KNOWN_INHERITED_LABEL_EMAILS:
                counts["inherited"] += 1
                continue
            if mail in case:
                basis = "equals an e-mail already in the case"
            elif _domain_in(mail, verified_domains):
                basis = "on the account's own verified domain"
            else:
                counts["discarded"] += 1
                continue
            kept.setdefault(mail, {"email": mail, "label": key, "instruction_index": idx, "basis": basis, "repo_tag": repo_tag})
    counts["kept"] = len(kept)
    res["label_emails"] = list(kept.values())
    for idx, ins in enumerate(instructions):
        if idx <= boundary:
            continue
        for kind, val, var, dropped in layer_secrets(ins):
            example = val in DOCUMENTATION_SECRETS
            sev = "high" if _HIGH_KINDS.search(kind) else "medium"
            if example:
                sev = "info"
            elif sev == "high" and not org_confirmed:
                sev = "medium"
            entry: dict[str, Any] = {"type": kind, "repo_tag": repo_tag, "instruction_index": idx,
                                     "instruction_kind": _instruction_kind(ins), "variable": var, "severity": sev}
            if dropped:
                entry["dropped"] = True  # passwords and URL credentials: never hashed (a hash of a password is crackable)
            else:
                masked = mask_secret(val, kind)
                entry.update(preview=masked["preview"], sha256=masked["sha256"])
            if example:
                entry["documentation_example"] = True
            res["exposures"].append(entry)
    if res["exposures"]:
        worst = max((s["severity"] for s in res["exposures"]), key=lambda s: _SEV_ORDER[s])
        res["exposure"] = {"repo_tag": repo_tag, "instruction_indexes": sorted({s["instruction_index"] for s in res["exposures"]}),
                           "kinds": sorted({s["type"] for s in res["exposures"]}), "count": len(res["exposures"]),
                           "severity": worst, "validated": False}
    return res
