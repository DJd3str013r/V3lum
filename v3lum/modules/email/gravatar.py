"""Gravatar public profile (REST v3, by e-mail hash) and avatar existence (P087).

* The address is hashed locally and never sent in clear (cond 1): ``GET
  https://api.gravatar.com/v3/profiles/{sha256(lower(trim(email)))}`` and ``GET
  https://gravatar.com/avatar/{sha256}?d=404`` (avatar existence; Gravatar accepts SHA-256, MD5 is kept
  only to recognise legacy avatar URLs). A username input asks the v3 profile by its slug. The hashes
  are still personal data (dictionary-reversible): the TLP and privacy gates apply (the gravatar
  provider has no personal_data_review yet, so the policy gate sends PERSONAL_TYPES only when the
  module is selected explicitly in a case with a purpose, cond 2).
* Runs on analyst-typed seeds only (``run_on='seeds'``): third-party addresses the analyst typed and
  org-profile addresses entered as seeds; never on pivots or text-extracted values (cond 2).
* 404 ``{'error': 'Profile not found'}`` is the declared absence 'no public Gravatar profile'; the
  avatar check runs anyway (an avatar can exist without a public profile; 200 image = found, 404 =
  absent). 429 = RATE_LIMITED; the provider quota block keeps the keyless 100 requests/hour (cond 3);
  the optional key ``gravatar`` (Bearer) raises the limit.
* Minimised (cond 4): display name, profile URL, verified-account URLs and the avatar hash only -
  location, bio, job, company, pronouns and contact data are never kept. Verified accounts pivot as
  url (+ username where the profile URL shows it) PROBABLE identity links; free-text profile links are
  POSSIBLE url/domain pivots; all ``expand=False``.
* Avatars stay links (cond 5): the image is never embedded in reports; only its SHA-256 file hash is
  recorded for hash-equality avatar correlation - never face recognition or embeddings (no biometrics,
  LGPD art. 11).
"""

from __future__ import annotations

import hashlib
import re
from typing import Any
from urllib.parse import quote, urlsplit

from v3lum.core.entities import Entity
from v3lum.core.entities import EntityType as T
from v3lum.core.http import HttpError
from v3lum.core.models import ModuleResult, Opsec
from v3lum.core.module import Module, register

SOURCE = "gravatar.profiles"
PROFILE_API = "https://api.gravatar.com/v3/profiles/"
AVATAR_URL = "https://gravatar.com/avatar/{hash}"
ABSENT_TEXT = "no public Gravatar profile"
AVATAR_MAX_BYTES = 1_000_000
MAX_ACCOUNTS = 25
MAX_LINKS = 10
_SLUG = re.compile(r"^[a-z0-9][a-z0-9._-]{0,63}$", re.I)
_HEX64 = re.compile(r"^[0-9a-f]{64}$")
_AVATAR_IN_URL = re.compile(r"/avatar/([0-9a-fA-F]{64}|[0-9a-fA-F]{32})(?:[/?#.]|$)")
_ACCOUNT_PATTERNS = {
    "github.com": r"^/([A-Za-z0-9](?:[A-Za-z0-9]|-(?=[A-Za-z0-9])){0,38})/?$",
    "gitlab.com": r"^/([A-Za-z0-9_][A-Za-z0-9_.-]{0,254})/?$",
    "twitter.com": r"^/([A-Za-z0-9_]{1,15})/?$",
    "x.com": r"^/([A-Za-z0-9_]{1,15})/?$",
    "instagram.com": r"^/([A-Za-z0-9_.]{1,30})/?$",
    "facebook.com": r"^/([A-Za-z0-9.]{5,50})/?$",
    "linkedin.com": r"^/in/([A-Za-z0-9_%-]{3,100})/?$",
    "tiktok.com": r"^/@([A-Za-z0-9_.]{2,24})/?$",
    "youtube.com": r"^/@([A-Za-z0-9_.-]{3,30})/?$",
    "twitch.tv": r"^/([A-Za-z0-9_]{4,25})/?$",
    "reddit.com": r"^/(?:user|u)/([A-Za-z0-9_-]{3,20})/?$",
    "medium.com": r"^/@([A-Za-z0-9_.]{1,50})/?$",
}


def normalise_email(value: Any) -> str | None:
    if not isinstance(value, str):
        return None
    v = value.strip().lower()
    if v.count("@") != 1 or any(c.isspace() for c in v):
        return None
    local, domain = v.split("@")
    return v if local and domain and "." in domain.strip(".") else None


def gravatar_hashes(email: Any) -> dict[str, str] | None:
    """{'sha256', 'md5'} of the trimmed lower-case address (cond 1): SHA-256 is the v3 key, MD5 only
    recognises legacy avatar URLs. Computed locally; the address itself is never sent."""
    value = normalise_email(email)
    if value is None:
        return None
    raw = value.encode("utf-8")
    return {"sha256": hashlib.sha256(raw).hexdigest(), "md5": hashlib.md5(raw, usedforsecurity=False).hexdigest()}


def profile_url(identifier: Any) -> str:
    """v3 profile URL: an address is hashed locally (never sent), a 64-hex hash is used as is, any
    other value must be a plain profile slug (username input). ValueError otherwise."""
    if not isinstance(identifier, str) or not identifier.strip():
        raise ValueError("empty identifier")
    value = identifier.strip()
    if "@" in value:
        hashes = gravatar_hashes(value)
        if hashes is None:
            raise ValueError("not an e-mail address")
        return PROFILE_API + hashes["sha256"]
    if _HEX64.match(value.lower()):
        return PROFILE_API + value.lower()
    if _SLUG.match(value):
        return PROFILE_API + quote(value.lower(), safe="")
    raise ValueError("not a Gravatar profile slug")


def avatar_hash_from_url(url: Any) -> str | None:
    m = _AVATAR_IN_URL.search(url) if isinstance(url, str) else None
    return m.group(1).lower() if m else None


def account_username(url: str, service: str | None = None) -> tuple[str, str] | None:
    """(platform, handle) from a verified-account URL; Mastodon-style URLs give 'user@host'."""
    try:
        parts = urlsplit(url)
    except ValueError:
        return None
    host = (parts.hostname or "").lower()
    for prefix in ("www.", "mobile.", "m."):
        if host.startswith(prefix):
            host = host[len(prefix):]
    path = parts.path or "/"
    pattern = _ACCOUNT_PATTERNS.get(host)
    if pattern:
        m = re.match(pattern, path)
        return (host.split(".")[0], m.group(1)) if m else None
    m = re.match(r"^/@([A-Za-z0-9_]{1,30})/?$", path)
    if m and (not service or service.lower() in ("mastodon", "fediverse", "pixelfed", "misskey")):
        return ("fediverse", f"{m.group(1)}@{host}")
    return None


def _http_url(value: Any) -> str | None:
    if not isinstance(value, str):
        return None
    v = value.strip()
    if not v.lower().startswith(("http://", "https://")) or any(c.isspace() for c in v) or len(v) > 500:
        return None
    try:
        host = urlsplit(v).hostname
    except ValueError:
        return None
    return v if host and "." in host else None


def parse_profile(data: Any) -> dict[str, Any] | None:
    """Minimal v3 profile (cond 4): display name, profile URL, avatar hash, verified accounts (hidden ones
    and non-http URLs dropped) and free-text links; every other field is dropped. None if not a profile."""
    if not isinstance(data, dict) or "error" in data:
        return None
    phash = data.get("hash") if isinstance(data.get("hash"), str) else None
    purl = _http_url(data.get("profile_url"))
    if not phash and not purl:
        return None
    accounts = []
    for acc in data.get("verified_accounts") or []:
        if not isinstance(acc, dict) or acc.get("is_hidden") is True:
            continue
        url = _http_url(acc.get("url"))
        if not url:
            continue
        service = acc.get("service_type") if isinstance(acc.get("service_type"), str) else None
        derived = account_username(url, service)
        accounts.append({
            "service": (service or "")[:40] or None,
            "label": acc.get("service_label")[:60] if isinstance(acc.get("service_label"), str) else None,
            "url": url,
            "platform": derived[0] if derived else None,
            "username": derived[1] if derived else None,
        })
        if len(accounts) >= MAX_ACCOUNTS:
            break
    links = []
    for link in data.get("links") or []:
        url = _http_url(link.get("url")) if isinstance(link, dict) else None
        if url:
            label = link.get("label") if isinstance(link.get("label"), str) else None
            links.append({"label": label[:60] if label else None, "url": url})
        if len(links) >= MAX_LINKS:
            break
    avatar = _http_url(data.get("avatar_url"))
    name = data.get("display_name") if isinstance(data.get("display_name"), str) else None
    return {
        "display_name": " ".join(name.split())[:120] if name else None,
        "profile_url": purl,
        "avatar_url": avatar,
        "avatar_hash": avatar_hash_from_url(avatar) or (phash.lower() if phash and _HEX64.match(phash.lower()) else None),
        "verified_accounts": accounts,
        "links": links,
    }


@register
class Gravatar(Module):
    name = "gravatar"
    title = "Gravatar profile and avatar"
    description = (
        "Public Gravatar profile of an e-mail address (hashed locally, never sent in clear) or profile slug: display name, "
        "verified accounts and avatar hash; avatar existence with d=404."
    )
    category = "email"
    accepts = {T.EMAIL, T.USERNAME}
    produces = {T.USERNAME, T.FEDIVERSE_HANDLE, T.URL, T.DOMAIN}
    run_on = "seeds"
    tags = {"free"}
    reference = "https://docs.gravatar.com/rest-api/"
    notice = (
        "The address is hashed locally (SHA-256); the hash is still personal data. Only display name, verified-account "
        "URLs and the avatar hash are kept; avatars stay links and are never analysed for faces (LGPD art. 11)."
    )
    terms = "open"
    opsec = Opsec.PASSIVE
    disclosure = "third_party"  # Gravatar receives the hash (or the slug)
    provider = "gravatar"
    sources = (SOURCE,)
    hosts = ("api.gravatar.com", "gravatar.com")
    access_model = "free_noauth_limited"
    optional_keys = ("gravatar",)
    absent_statuses = frozenset({404})  # 'Profile not found' / avatar d=404: declared absences (cond 3)
    max_requests = 2  # profile + avatar existence
    expected_latency = 1.0
    min_interval = 1.0
    cache_ttl = 86400
    max_pivots = 60
    default_enabled = True

    def run(self, entity: Entity, ctx: Any) -> ModuleResult:
        res = self.result(entity)
        try:
            url = profile_url(entity.value)
        except ValueError:
            return res.mark("skipped", "not an e-mail address or Gravatar profile slug", reason_code="not_applicable")
        key = ctx.key("gravatar")
        headers = {"Authorization": f"Bearer {key}"} if key else None
        data = ctx.http.get_json(url, headers=headers, source=SOURCE)
        profile = None
        if data is not None:
            profile = parse_profile(data)
            if profile is None:
                return res.mark("error", "unexpected Gravatar answer (no profile object): could not verify")
        avatar_hash = (profile or {}).get("avatar_hash")
        if avatar_hash is None and entity.type is T.EMAIL:
            hashes = gravatar_hashes(entity.value)
            avatar_hash = hashes["sha256"] if hashes else None
        avatar_state, avatar_sha = self._avatar(ctx, avatar_hash) if avatar_hash else ("unknown", None)
        res.raw = {"profile_found": profile is not None, "avatar": avatar_state,
                   "profile": {k: v for k, v in (profile or {}).items() if k != "links"} or None}
        if profile is None and avatar_state != "found":
            res.presence("absent", marker=f"HTTP 404 'Profile not found': {ABSENT_TEXT}", url=url, checked_at=ctx.now(), source=SOURCE)
            res.error = ABSENT_TEXT + (" and no avatar" if avatar_state == "absent" else "")
            return res.mark("empty")
        res.attr("gravatar", True)
        avatar_link = AVATAR_URL.format(hash=avatar_hash) + "?d=404" if avatar_hash else None
        if avatar_hash:
            res.attr("avatar_hash", avatar_hash)
        if avatar_state == "found" and avatar_link:
            res.attr("avatar_url", avatar_link)
            res.link("Gravatar avatar (link only, never embedded)", avatar_link)
        if profile is None:
            res.presence("absent", marker=f"HTTP 404 'Profile not found': {ABSENT_TEXT} (avatar present)", url=url,
                         checked_at=ctx.now(), source=SOURCE)
            res.attr("gravatar_profile", {"avatar_hash": avatar_hash, "avatar_sha256": avatar_sha, "profile": None})
            res.finding(
                "Gravatar avatar without a public profile",
                "info",
                "An avatar is registered for this address but no public profile is shown. The avatar stays a link; only its "
                "file hash is kept for hash-equality correlation.",
                confidence="probable",
                criterion="gravatar.com/avatar/{hash}?d=404 answered 200 with an image; the v3 profile answered 404",
                data={"avatar_hash": avatar_hash, "avatar_sha256": avatar_sha},
                tags=["account"],
                source=SOURCE,
            )
            return res
        res.presence("found", marker="HTTP 200 v3 profile object", url=profile.get("profile_url") or url,
                     checked_at=ctx.now(), source=SOURCE)
        card = {
            "display_name": profile["display_name"],
            "profile_url": profile["profile_url"],
            "avatar_hash": avatar_hash,
            "avatar_sha256": avatar_sha,
            "verified_accounts": [{k: a[k] for k in ("service", "label", "url", "username")} for a in profile["verified_accounts"]],
            "links": profile["links"],
        }
        res.attr("gravatar_profile", card)
        if profile["profile_url"]:
            res.link("Gravatar profile", profile["profile_url"])
            res.pivot(T.URL, profile["profile_url"], "has_account", confidence="probable", expand=False,
                      note="Gravatar profile of the investigated identity")
        self._pivots(res, profile)
        accounts = profile["verified_accounts"]
        res.finding(
            "Public Gravatar profile",
            "info",
            f"Public Gravatar profile{' ' + repr(profile['display_name']) if profile['display_name'] else ''} with "
            f"{len(accounts)} verified account(s)"
            + (": " + ", ".join(a["label"] or a["service"] or a["url"] for a in accounts[:8]) if accounts else "")
            + ". Verified accounts are PROBABLE identity links; free-text links are POSSIBLE. Minimised: location, bio, "
            "job and contact data are never kept.",
            confidence="probable",
            criterion="Gravatar v3 profile answered 200 for the locally computed hash (or slug)",
            data={"verified_accounts": len(accounts), "links": len(profile["links"]), "avatar": avatar_state},
            tags=["account", "identity"],
            references=[profile["profile_url"]] if profile["profile_url"] else [],
            source=SOURCE,
        )
        return res

    @staticmethod
    def _avatar(ctx: Any, avatar_hash: str) -> tuple[str, str | None]:
        """Avatar existence with d=404 (cond 3): ('found', sha256 of the bytes) | ('absent', None)."""
        resp = ctx.http.get(AVATAR_URL.format(hash=avatar_hash), params={"d": "404"}, source=SOURCE,
                            max_bytes=AVATAR_MAX_BYTES, headers={"Accept": "image/*"})
        try:
            ctx.http.check(resp)  # 429/challenges/5xx raise ('could not verify')
        except HttpError:
            if resp.status == 404 and getattr(resp, "classification", None) is None:
                return "absent", None  # d=404: no avatar for this hash (declared absence)
            raise
        if resp.status == 404:
            return "absent", None
        ctype = str(resp.headers.get("content-type", "")).lower()
        if resp.status == 200 and (not ctype or ctype.startswith("image/")) and resp.content:
            return "found", hashlib.sha256(bytes(resp.content)).hexdigest()
        return "unknown", None

    @staticmethod
    def _pivots(res: ModuleResult, profile: dict[str, Any]) -> None:
        for acc in profile["verified_accounts"]:
            label = acc["label"] or acc["service"] or "service"
            res.pivot(T.URL, acc["url"], "has_account", confidence="probable", expand=False,
                      note=f"Gravatar verified account ({label}): PROBABLE identity link")
            if acc["username"]:
                etype = T.FEDIVERSE_HANDLE if "@" in acc["username"] else T.USERNAME
                res.pivot(etype, acc["username"], "uses_username", confidence="probable", expand=False,
                          note=f"handle of a Gravatar verified account ({label})")
        for link in profile["links"]:
            res.pivot(T.URL, link["url"], "has_account", confidence="possible", expand=False,
                      note="free-text Gravatar profile link (self-declared): POSSIBLE")
            host = (urlsplit(link["url"]).hostname or "").lower()
            host = host[4:] if host.startswith("www.") else host
            if host:
                res.pivot(T.DOMAIN, host, "links_to", confidence="possible", expand=False,
                          note="domain of a free-text Gravatar profile link (self-declared): POSSIBLE")
