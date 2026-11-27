"""GitLab.com users API and public .keys/.gpg (P103).

* gitlab.com only (cond 1/2): ``/api/v4/users?username={u}`` (200 with ``[]`` = ABSENT), then
  ``/api/v4/users/{id}`` for public_email, linkedin, twitter, discord and website, plus
  ``gitlab.com/{u}.keys`` and ``gitlab.com/{u}.gpg``. Self-hosted GitLab instances on target domains are
  target infrastructure (LIGHT/ACTIVE with scope) and never contacted by this module.
* ``/api/v4/users/{id}`` answered GitLab's own 403 'Not authorized' to an anonymous caller from the
  research egress (2026-11-26): the run keeps the basic profile, records the detail call as could not
  verify (per-source BLOCKED) and never turns it into an absence.
* .keys/.gpg are plain-text GETs capped at 1 MB (cond 3): SSH keys are kept as SHA-256 fingerprints only
  and OpenPGP keys as fingerprints + UIDs, through the same parsers as github_user (P111) so fingerprints
  compare byte for byte; an equal fingerprint is the PROBABLE cross-platform link of correlation rule
  ``p2g051_shared_key_fingerprint`` (and the shared pgp_fingerprint node of both accounts). GPG UID
  e-mails are pivots with expand=False.
* public_email, linked accounts and website are self-published personal data (cond 4): case-bound,
  pivots with expand=False, never sent to breach/stealer modules automatically.
* Rate-limit headers are honoured (cond 5: unauthenticated about 500/min per IP; no new request when 10
  or fewer remain); 429, 5xx and timeouts = could not verify. The avatar is reduced to its Gravatar hash
  for avatar_correlation's local comparison only (P114).
"""

from __future__ import annotations

import re
from typing import Any
from urllib.parse import quote

from v3lum.core.entities import Entity
from v3lum.core.entities import EntityType as T
from v3lum.core.models import ModuleResult, Opsec, Status
from v3lum.core.module import Module, register
from v3lum.modules.username_social.dev_registries import (
    account_handle,
    attempt,
    gravatar_hash,
    iso_utc,
    load_json,
    looks_like_html,
    normalise_email,
    rate_remaining,
    report_problems,
    to_int,
    to_str,
    with_scheme,
)
from v3lum.modules.username_social.github_user import decode_noreply, parse_gpg_keys, parse_ssh_keys

SOURCE = "gitlab.users_api"
HOST = "gitlab.com"
API = "https://gitlab.com/api/v4"
PLAINTEXT_CAP = 1024 * 1024  # cond 3: .keys/.gpg capped at 1 MB
RATE_RESERVE = 10
MAX_GPG_KEYS = 20
_GITLAB_USER_RE = re.compile(r"^[A-Za-z0-9_.][A-Za-z0-9_.-]{0,254}$")
_SOCIAL_HANDLE_RE = re.compile(r"^[A-Za-z0-9_.-]{1,64}$")


def gitlab_handle(entity: Entity) -> str | None:
    """A gitlab.com username from a username, 'gitlab:<u>' or a gitlab.com/<u> profile URL."""
    handle = account_handle(entity, "gitlab")
    if not handle or not _GITLAB_USER_RE.match(handle) or re.search(r"\.(?:git|atom|keys|gpg)$", handle, re.I):
        return None
    return handle


def parse_gitlab_users(raw: Any) -> dict[str, Any]:
    """cond 1: /api/v4/users?username= -> [] = ABSENT, else the account's basic profile."""
    res: dict[str, Any] = {"ok": False, "reason": None, "absent": False, "user": None}
    obj, why = load_json(raw)
    if why or not isinstance(obj, list):
        res["reason"] = why or ("error object: " + str(obj.get("message") or obj.get("error"))[:120] if isinstance(obj, dict)
                                else "unexpected JSON shape")
        return res
    res["ok"] = True
    users = [u for u in obj[:20] if isinstance(u, dict) and to_int(u.get("id")) and to_str(u.get("username"))]
    if not users:
        res["absent"] = not obj  # a non-empty list without a usable user is 'could not verify', not an absence
        if obj:
            res.update(ok=False, reason="no usable user object in the answer")
        return res
    u = users[0]
    res["user"] = {"id": to_int(u.get("id")), "username": u["username"].strip()[:255], "name": to_str(u.get("name"), 200),
                   "state": to_str(u.get("state"), 30), "locked": u.get("locked") is True, "web_url": to_str(u.get("web_url"), 300),
                   "public_email": normalise_email(u.get("public_email")), "avatar_hash": gravatar_hash(u.get("avatar_url"))}
    return res


def parse_gitlab_user_detail(raw: Any) -> dict[str, Any]:
    """cond 1/4: /api/v4/users/{id} -> public_email, linked accounts, website and profile facts."""
    res: dict[str, Any] = {"ok": False, "reason": None, "created_at": None, "bio": None, "location": None, "organization": None,
                           "job_title": None, "public_email": None, "website": None, "accounts": {}, "bot": None, "avatar_hash": None}
    obj, why = load_json(raw)
    if why or not isinstance(obj, dict) or not to_int(obj.get("id")):
        res["reason"] = why or ("error object: " + str(obj.get("message"))[:120] if isinstance(obj, dict) and obj.get("message")
                                else "unexpected JSON shape")
        return res
    res.update(ok=True, created_at=iso_utc(obj.get("created_at")), bio=to_str(obj.get("bio"), 1000), location=to_str(obj.get("location"), 200),
               organization=to_str(obj.get("organization"), 200), job_title=to_str(obj.get("job_title"), 200),
               public_email=normalise_email(obj.get("public_email")), website=with_scheme(obj.get("website_url")),
               bot=obj.get("bot") if isinstance(obj.get("bot"), bool) else None, avatar_hash=gravatar_hash(obj.get("avatar_url")))
    for field, platform in (("linkedin", "linkedin"), ("twitter", "x"), ("discord", "discord"), ("skype", "skype")):
        v = (to_str(obj.get(field), 100) or "").lstrip("@")
        if v and _SOCIAL_HANDLE_RE.match(v):
            res["accounts"][platform] = v
    return res


def stored_gpg_keys(parsed: dict[str, Any]) -> list[dict[str, Any]]:
    """The gpg_keys attribute in github_user's shape (fingerprint, key_id, sha256_id, algorithm, bits, curve,
    created, subkeys count, uids [{name, email}])."""
    out = []
    for k in parsed.get("keys", [])[:MAX_GPG_KEYS]:
        uids = [{"name": u.get("name"), "email": u.get("email")} for u in (k.get("uids") or [])[:10]]
        out.append({"fingerprint": k.get("fingerprint"), "key_id": k.get("key_id"), "sha256_id": k.get("sha256_id"),
                    "algorithm": k.get("algorithm"), "bits": k.get("bits"), "curve": k.get("curve"), "created": k.get("created"),
                    "subkeys": len(k.get("subkeys") or []), "uids": uids})
    return out


@register
class GitlabUser(Module):
    name = "gitlab_user"
    title = "GitLab.com user"
    description = (
        "GitLab.com users API (users?username=, users/{id}) and the public {user}.keys/{user}.gpg: profile, self-published "
        "e-mail and linked accounts, SSH/OpenPGP key fingerprints shared with github_user for cross-platform links."
    )
    category = "username_social"
    accepts = frozenset({T.USERNAME, T.SOCIAL_ACCOUNT, T.URL})
    produces = frozenset({T.URL, T.EMAIL, T.USERNAME, T.SOCIAL_ACCOUNT, T.PGP_FINGERPRINT})
    run_on = "seeds"
    terms = "open"
    opsec = Opsec.PASSIVE
    disclosure = "third_party"
    provider = "gitlab"
    sources = (SOURCE,)
    hosts = (HOST,)
    access_model = "free_noauth_limited"
    max_requests = 4  # users?username + users/{id} + .keys + .gpg
    expected_latency = 2.5
    timeout = 20.0
    min_interval = 0.5
    cache_ttl = 86400  # keys can rotate
    max_pivots = 40
    default_enabled = True
    manual_link = "https://gitlab.com/{user}"
    reference = "https://docs.gitlab.com/api/users/"
    tags = frozenset({"free"})
    notice = (
        "gitlab.com only: self-hosted GitLab instances are target infrastructure and never contacted. public_email, linked "
        "accounts and website are self-published personal data (case-bound, never sent to breach modules automatically); keys "
        "are kept as fingerprints only. personal_data_review comes before default use."
    )

    def applies(self, entity: Entity, ctx: Any) -> bool:
        return gitlab_handle(entity) is not None

    def run(self, entity: Entity, ctx: Any) -> ModuleResult:
        res = self.result(entity)
        handle = gitlab_handle(entity)
        if not handle:
            return res.mark("skipped", "not a GitLab.com username", reason_code="not_applicable")
        quoted = quote(handle, safe="")
        profile = f"https://gitlab.com/{handle}"
        lookup = f"{API}/users?username={quoted}"
        resp = ctx.http.get(lookup, source=SOURCE)
        ctx.http.check(resp)  # 429/5xx/challenges raise: could not verify
        remaining = rate_remaining(resp.headers)
        users = parse_gitlab_users(resp.content)
        if not users["ok"]:
            return res.mark("error", f"unexpected GitLab answer ({users['reason']}): could not verify")
        if users["user"] is None:
            res.presence("absent", marker="HTTP 200 [] from gitlab.com/api/v4/users?username=", url=profile, checked_at=ctx.now(), source=SOURCE)
            res.error = "no GitLab.com account with this username"
            return res.mark("empty")
        user = users["user"]
        handle = user["username"]
        profile = user["web_url"] if (user["web_url"] or "").startswith("https://gitlab.com/") else f"https://gitlab.com/{handle}"
        raw: dict[str, Any] = {"username": handle, "id": user["id"]}
        res.raw = raw
        res.presence("found", marker="HTTP 200 users list with the account", url=profile, checked_at=ctx.now(), source=SOURCE)
        res.attr("account_id", user["id"])
        res.attr("display_name", user["name"])
        res.attr("account_state", {"state": user["state"], "locked": user["locked"]})
        res.attr("profile_url", profile)
        res.attr("avatar_hash", user["avatar_hash"])
        res.pivot(T.URL, profile, "has_account", confidence="confirmed", expand=False, note="GitLab.com profile of the account")
        problems: dict[str, list[tuple[Status, str, str]]] = {}
        detail: dict[str, Any] | None = None
        steps = [("details", f"{API}/users/{user['id']}"), ("keys", f"https://gitlab.com/{quote(handle, safe='')}.keys"),
                 ("gpg", f"https://gitlab.com/{quote(handle, safe='')}.gpg")]
        keys_text: str | None = None
        gpg_text: str | None = None
        for step, url in steps:
            if remaining is not None and remaining <= RATE_RESERVE:
                res.stop("rate_limited")
                res.error = f"GitLab rate budget nearly spent (RateLimit-Remaining {remaining}): {step} not read"
                break
            got = attempt(problems, SOURCE, step, lambda u=url, s=step: self._fetch(ctx, u, s))
            if got is None:
                continue
            body, remaining, note, truncated = got
            if note:
                problems.setdefault(SOURCE, []).append((Status.ERROR, "error", f"{step}: {note}"))
                continue
            if truncated:
                raw.setdefault("truncated", []).append(step)
                res.error = "; ".join(x for x in (res.error, f"{handle}.{step} over the 1 MB cap: first 1 MB read") if x)
            if step == "details":
                detail = parse_gitlab_user_detail(body) if body is not None else None
                if detail is not None and not detail["ok"]:
                    problems.setdefault(SOURCE, []).append((Status.ERROR, "error", f"details: {detail['reason']}"))
                    detail = None
            elif step == "keys":
                keys_text = body
            else:
                gpg_text = body
        self._details(res, user, detail, profile, raw)
        self._keys(res, handle, keys_text, gpg_text, problems, raw)
        report_problems(res, problems)
        res.finding(
            "Account on GitLab.com",
            "info",
            f"GitLab.com account {handle}" + (f", created {detail['created_at'][:10]}" if detail and detail["created_at"] else "")
            + ". Same handle elsewhere does not prove the same person; self-published fields are case-bound.",
            confidence="confirmed",
            criterion="gitlab.com/api/v4/users?username= returned the account",
            data={"id": user["id"], "state": user["state"]},
            tags=["account"],
            references=[profile],
            source=SOURCE,
        )
        return res

    @staticmethod
    def _fetch(ctx: Any, url: str, step: str) -> tuple[Any, int | None, str, bool]:
        """(body, RateLimit-Remaining, problem, truncated): JSON for the detail call, text capped at 1 MB for
        .keys/.gpg. GitLab's own keyless 403 on users/{id} and challenge pages raise (recorded per source,
        never an absence)."""
        plain = step in ("keys", "gpg")
        kw: dict[str, Any] = {"source": SOURCE}
        if plain:
            kw.update(max_bytes=PLAINTEXT_CAP, headers={"Accept": "text/plain"})
        resp = ctx.http.get(url, **kw)
        remaining = rate_remaining(resp.headers)
        if resp.status == 404 and resp.classification is None:
            return None, remaining, "", False
        ctx.http.check(resp)
        if not plain:
            return resp.content, remaining, "", False
        text = resp.text[:PLAINTEXT_CAP] if resp.content else ""
        if looks_like_html(text):
            return None, remaining, f"HTML page instead of {step} (could not verify)", False
        return text, remaining, "", bool(resp.truncated)

    # ------------------------------------------------------------------ profile details (cond 4)
    @staticmethod
    def _details(res: ModuleResult, user: dict[str, Any], detail: dict[str, Any] | None, profile: str, raw: dict[str, Any]) -> None:
        public_email = (detail or {}).get("public_email") or user["public_email"]
        if detail:
            raw["details"] = True
            res.attr("created", detail["created_at"])
            res.attr("bio", detail["bio"])
            res.attr("location", detail["location"])
            res.attr("company", detail["organization"])
            res.attr("job_title", detail["job_title"])
            res.attr("website", detail["website"])
            res.attr("is_bot", detail["bot"])
            if detail["avatar_hash"]:
                res.attr("avatar_hash", detail["avatar_hash"])
            linked = []
            for platform, handle in detail["accounts"].items():
                linked.append({"platform": platform, "handle": handle, "url": None, "source_page": profile})
                if platform in ("linkedin", "x"):
                    res.pivot(T.SOCIAL_ACCOUNT, f"{platform}:{handle}", "linked_account_on_profile", confidence="probable", expand=False,
                              note=f"{platform} account self-published on the GitLab.com profile (case-bound)")
                elif platform == "discord":
                    res.pivot(T.USERNAME, handle, "linked_account_on_profile", confidence="probable", expand=False,
                              note="Discord username self-published on the GitLab.com profile (case-bound)")
            res.attr("linked_accounts", linked)
            if detail["website"]:
                res.pivot(T.URL, detail["website"], "link_on_profile", confidence="probable", expand=False,
                          note="website self-published on the GitLab.com profile (case-bound)")
        if public_email:
            res.attr("public_email", public_email)
            res.pivot(T.EMAIL, public_email, "email_on_profile", confidence="probable", expand=False,
                      note="public_email self-published on the GitLab.com profile: case-bound, never sent to breach/stealer modules automatically")

    # ------------------------------------------------------------------ keys (cond 3)
    @staticmethod
    def _keys(res: ModuleResult, handle: str, keys_text: str | None, gpg_text: str | None, problems: dict[str, Any], raw: dict[str, Any]) -> None:
        if keys_text is not None:
            parsed = parse_ssh_keys(keys_text)
            if not parsed["ok"]:
                problems.setdefault(SOURCE, []).append((Status.ERROR, "error", f"{handle}.keys: {parsed['reason']}"))
            elif parsed["keys"]:
                res.attr("ssh_keys", parsed["keys"])
                raw["ssh_keys"] = len(parsed["keys"])
        if gpg_text is None or not gpg_text.strip():
            return
        parsed_gpg = parse_gpg_keys(gpg_text)
        if not parsed_gpg["ok"]:
            problems.setdefault(SOURCE, []).append((Status.ERROR, "error", f"{handle}.gpg: {parsed_gpg['reason']}"))
            return
        stored = stored_gpg_keys(parsed_gpg)
        if not stored:
            return
        res.attr("gpg_keys", stored)
        raw["gpg_keys"] = len(stored)
        seen: set[str] = set()
        for k in parsed_gpg["keys"][:MAX_GPG_KEYS]:
            if k.get("version") == 4 and k.get("fingerprint"):
                res.pivot(T.PGP_FINGERPRINT, k["fingerprint"], "pgp_key", confidence="confirmed", expand=False,
                          note="OpenPGP key published on the GitLab.com account")
            for uid in (k.get("uids") or [])[:10]:
                email = uid.get("email")
                if not email or email in seen:
                    continue
                seen.add(email)
                nr = decode_noreply(email)
                if nr is not None:
                    if not nr["bot"]:
                        res.pivot(T.SOCIAL_ACCOUNT, f"github:{nr['login']}", "noreply_account", confidence="probable", expand=False,
                                  note="GitHub account decoded from a users.noreply.github.com UID of a GPG key on the GitLab.com account")
                    continue
                res.pivot(T.EMAIL, email, "gpg_uid_email", confidence="probable", expand=False,
                          note="e-mail in a UID of an OpenPGP key published on the GitLab.com account: case-bound, never sent to breach modules automatically")
