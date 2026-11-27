"""E-mail -> GitHub accounts by EXACT commit-author or public-profile e-mail match (P086).

* Endpoints (cond 1): ``search/commits?q=author-email:<email>&sort=author-date&order=desc`` for logins
  and repositories, ``search/users?q=<email> in:email`` for public profile e-mails; a user-search hit
  is confirmed with ``users/{login}`` (exact public e-mail), and one matching commit per account may be
  checked with ``repos/{owner}/{repo}/commits/{sha}`` for a verified signature (search items never
  carry the verification block).
* Team-owned token only (cond 2, rule 1): key ``github`` (Bearer header to api.github.com, through the
  shared P111 GitHub client and budget of ``github_user``); legal records the token's plan as
  business-compatible (key_plans.github = 'business', A1: the source is ``key-terms``). Search budget
  10 requests/min without a token (6 s between search calls) and 30/min with it (``min_interval``
  2 s); 403/429 rate-limit answers (also the secondary limits) are RATE_LIMITED ('could not verify'),
  with the token hint once (the provider marker ``github_user_rate_limit`` and the shared budget).
* Runs on analyst-typed seed addresses only (``run_on='seeds'``, cond 3): third-party addresses the
  analyst typed and org-profile addresses entered as seeds; never pivots or text-extracted values. The
  github provider has no personal_data_review yet: the policy gate sends PERSONAL_TYPES only when the
  module is selected explicitly in a case with a recorded purpose (A3 BR8, AR16).
* A login is reported only after an exact e-mail match in commit metadata or on the public profile
  (cond 4); fuzzy user-search hits are discarded (13 hits for test@example.com, none exact).
* Confidence (cond 5): commit author e-mails are self-asserted - commit-only matches are POSSIBLE
  (0.4); a signature-verified commit or the address public on the profile gives PROBABLE (0.6); never
  CONFIRMED.
* Placeholders (cond 6): GitHub's placeholder addresses (octocat@github.com, noreply@github.com) are
  ignored (nothing is sent); role/test/example addresses are searched but capped at POSSIBLE; accounts
  are deduplicated by author.login and placeholder accounts (invalid-email-address, ghost, web-flow)
  are never reported. ``<id>+<login>@users.noreply.github.com`` addresses are decoded locally to the
  user id (no request).
* Minimisation (cond 7): login, user id, profile URL and the matching repository/commit references
  only - no names, bios, locations, followers or commit messages. Username and URL pivots are
  ``expand=False`` and never auto-expand into further people lookups.
* Purpose limitation (cond 8, GitHub AUP s.7, LGPD): security investigations inside a case only -
  never profiling, HR/performance use, marketing or resale; employees' addresses only under the
  company security policy and privacy notice; the processing is listed in the ROPA (docs/LEGAL.md).
"""

from __future__ import annotations

import re
from typing import Any
from urllib.parse import quote

from v3lum.core.entities import Entity, generic_address_kind
from v3lum.core.entities import EntityType as T
from v3lum.core.http import AuthRequired, Blocked, HttpError, NetworkError, QuotaExceeded, RateLimited
from v3lum.core.models import ModuleResult, Opsec
from v3lum.core.module import Module, register
from v3lum.modules.username_social.github_user import (
    API_HOST,
    API_ROOT,
    GITHUB_ANON_COVERAGE_LINE,
    PROVIDER,
    GitHubClient,
    decode_noreply,
    iso_utc,
)

SOURCE = "github.github_email_pivot_search"
PLACEHOLDER_ADDRESSES = frozenset({"octocat@github.com", "noreply@github.com", "no-reply@github.com"})
PLACEHOLDER_LOGINS = frozenset({"invalid-email-address", "ghost", "web-flow"})
POSSIBLE = 0.4
PROBABLE = 0.6
SEARCH_INTERVAL_KEYLESS = 6.0  # 10 search requests/min without a token
SEARCH_INTERVAL_KEYED = 2.0  # 30/min with the team token
MAX_COMMIT_URLS = 5
MAX_ACCOUNTS = 10
MAX_CONFIRM_KEYED = 3
MAX_CONFIRM_KEYLESS = 2  # the core API is 60 requests/hour per IP without a token
MAX_VERIFY_KEYED = 2
MAX_VERIFY_KEYLESS = 1
_LOGIN_RE = re.compile(r"^[A-Za-z0-9](?:[A-Za-z0-9]|-(?=[A-Za-z0-9])){0,38}$")
_REPO_RE = re.compile(r"^[A-Za-z0-9_.-]{1,100}/[A-Za-z0-9_.-]{1,100}$")
_SHA_RE = re.compile(r"^[0-9a-f]{40}$")
ROPA_NOTE = (
    "Security investigations inside a case only (GitHub AUP s.7, LGPD): never profiling, HR/performance use, marketing "
    "or resale; employees' addresses only under the company security policy and privacy notice (ROPA, docs/LEGAL.md)."
)


def normalise_email(value: Any) -> str | None:
    if not isinstance(value, str):
        return None
    v = value.strip().lower()
    if v.count("@") != 1 or any(c.isspace() for c in v) or len(v) > 254:
        return None
    local, domain = v.split("@")
    return v if local and domain and "." in domain.strip(".") else None


def placeholder_action(email: str) -> tuple[str, str] | None:
    """cond 6: ('ignore', why) for GitHub placeholder addresses (nothing is sent), ('downweight', why) for
    role/test/example addresses (searched, capped at POSSIBLE), None otherwise."""
    value = normalise_email(email)
    if value is None:
        return "ignore", "not a valid e-mail address"
    if value in PLACEHOLDER_ADDRESSES:
        return "ignore", "GitHub placeholder address (matches millions of unrelated commits)"
    try:
        kind = generic_address_kind(value)
    except Exception:  # noqa: BLE001
        kind = None
    if kind:
        return "downweight", f"generic address ({kind}): capped at POSSIBLE"
    return None


def parse_commit_search(data: Any, email: str) -> dict[str, Any]:
    """search/commits answer -> exact author/committer e-mail matches only (cond 1, 4, 6, 7)."""
    want = normalise_email(email)
    out: dict[str, Any] = {"ok": isinstance(data, dict) and isinstance(data.get("items"), list), "total_count": None,
                           "incomplete": False, "accounts": [], "unlinked_commits": 0, "unlinked_repos": [],
                           "placeholder_logins": [], "discarded_non_exact": 0, "exact_matches": 0}
    if not out["ok"]:
        return out
    tc = data.get("total_count")
    out["total_count"] = tc if isinstance(tc, int) and not isinstance(tc, bool) else None
    out["incomplete"] = data.get("incomplete_results") is True
    accounts: dict[str, dict[str, Any]] = {}
    placeholders: set[str] = set()
    unlinked: set[str] = set()
    for item in data["items"][:100]:
        if not isinstance(item, dict):
            continue
        commit = item.get("commit") if isinstance(item.get("commit"), dict) else {}
        c_author = commit.get("author") if isinstance(commit.get("author"), dict) else {}
        c_committer = commit.get("committer") if isinstance(commit.get("committer"), dict) else {}
        if want is None or want not in {normalise_email(c_author.get("email")), normalise_email(c_committer.get("email"))}:
            out["discarded_non_exact"] += 1
            continue
        out["exact_matches"] += 1
        repo = item.get("repository") if isinstance(item.get("repository"), dict) else {}
        full = repo.get("full_name") if isinstance(repo.get("full_name"), str) and _REPO_RE.match(repo["full_name"]) else None
        sha = item.get("sha") if isinstance(item.get("sha"), str) and _SHA_RE.match(item["sha"]) else None
        when = iso_utc(c_author.get("date")) or iso_utc(c_committer.get("date"))
        user = item.get("author") if isinstance(item.get("author"), dict) else None
        login = user.get("login") if user and isinstance(user.get("login"), str) and _LOGIN_RE.match(user["login"]) else None
        if login is None:
            out["unlinked_commits"] += 1
            if full:
                unlinked.add(full)
            continue
        if login.lower() in PLACEHOLDER_LOGINS:
            placeholders.add(login)
            continue
        uid = user.get("id") if isinstance(user.get("id"), int) and not isinstance(user.get("id"), bool) else None
        acc = accounts.setdefault(login.lower(), {
            "login": login, "user_id": uid, "profile_url": f"https://github.com/{login}", "basis": "commit_author",
            "commits": 0, "repos": set(), "commit_urls": [], "first_seen": None, "last_seen": None, "verified_commit": False,
            "_newest": None,
        })
        acc["commits"] += 1
        if full:
            acc["repos"].add(full)
        if full and sha:
            url = f"https://github.com/{full}/commit/{sha}"
            if len(acc["commit_urls"]) < MAX_COMMIT_URLS:
                acc["commit_urls"].append(url)
            if acc["_newest"] is None:
                acc["_newest"] = (full, sha)  # sorted by author date desc: the first one is the newest
        if when:
            acc["first_seen"] = min(filter(None, [acc["first_seen"], when]))
            acc["last_seen"] = max(filter(None, [acc["last_seen"], when]))
    for acc in accounts.values():
        acc["repos"] = sorted(acc["repos"])
    out["accounts"] = sorted(accounts.values(), key=lambda a: (-a["commits"], a["login"].lower()))[:MAX_ACCOUNTS]
    out["placeholder_logins"] = sorted(placeholders)
    out["unlinked_repos"] = sorted(unlinked)[:20]
    return out


def parse_user_search(data: Any) -> dict[str, Any]:
    """search/users candidates: all UNCONFIRMED (tokenised, fuzzy search; items carry no e-mail)."""
    out: dict[str, Any] = {"ok": isinstance(data, dict) and isinstance(data.get("items"), list), "total_count": None, "candidates": []}
    if not out["ok"]:
        return out
    tc = data.get("total_count")
    out["total_count"] = tc if isinstance(tc, int) and not isinstance(tc, bool) else None
    for item in data["items"][:30]:
        if isinstance(item, dict) and isinstance(item.get("login"), str) and _LOGIN_RE.match(item["login"]):
            if item["login"].lower() in PLACEHOLDER_LOGINS:
                continue
            uid = item.get("id") if isinstance(item.get("id"), int) and not isinstance(item.get("id"), bool) else None
            out["candidates"].append({"login": item["login"], "user_id": uid,
                                      "type": item.get("type") if isinstance(item.get("type"), str) else None})
    return out


def profile_email_match(profile: Any, email: str) -> dict[str, Any] | None:
    """users/{login}: {login, user_id, exact} - only the public e-mail is compared; nothing else is kept."""
    if not isinstance(profile, dict) or not isinstance(profile.get("login"), str) or not _LOGIN_RE.match(profile["login"]):
        return None
    uid = profile.get("id") if isinstance(profile.get("id"), int) and not isinstance(profile.get("id"), bool) else None
    public = normalise_email(profile.get("email"))
    want = normalise_email(email)
    return {"login": profile["login"], "user_id": uid, "exact": want is not None and public == want}


def commit_verified(data: Any) -> bool:
    """repos/{o}/{r}/commits/{sha}: commit.verification.verified is True (cond 5 PROBABLE path)."""
    if not isinstance(data, dict):
        return False
    commit = data.get("commit") if isinstance(data.get("commit"), dict) else {}
    ver = commit.get("verification") if isinstance(commit.get("verification"), dict) else {}
    return ver.get("verified") is True


@register
class GithubEmailPivot(Module):
    name = "github_email_pivot"
    title = "GitHub accounts of an e-mail address"
    description = (
        "GitHub accounts linked to an e-mail address by an EXACT commit-author e-mail (commit search) or public profile "
        "e-mail (user search confirmed on the profile); fuzzy hits are discarded, usernames are never auto-expanded."
    )
    category = "email"
    accepts = {T.EMAIL}
    produces = {T.USERNAME, T.URL}
    run_on = "seeds"
    tags = {"identity"}
    reference = "https://docs.github.com/en/rest/search/search"
    notice = "Team-owned GitHub token only (never an analyst's personal token). " + ROPA_NOTE
    terms = "key-terms"
    opsec = Opsec.PASSIVE
    disclosure = "third_party"  # GitHub receives the address in the search query
    provider = PROVIDER
    sources = (SOURCE,)
    hosts = (API_HOST,)
    access_model = "free_noauth_limited"
    optional_keys = ("github",)
    max_requests = 2 + MAX_CONFIRM_KEYED + MAX_VERIFY_KEYED
    expected_latency = 4.0
    min_interval = SEARCH_INTERVAL_KEYED
    cache_ttl = 86400
    max_pivots = 2 * MAX_ACCOUNTS
    default_enabled = True

    def applies(self, entity: Entity, ctx: Any) -> bool:
        action = placeholder_action(entity.value)
        return not (action and action[0] == "ignore")

    def run(self, entity: Entity, ctx: Any) -> ModuleResult:
        res = self.result(entity)
        email = normalise_email(entity.value)
        action = placeholder_action(entity.value)
        if email is None or (action and action[0] == "ignore"):
            return res.mark("skipped", (action or ("", "not an e-mail address"))[1], reason_code="not_applicable")
        downweight = action[1] if action else None
        noreply = decode_noreply(email)
        if noreply is not None:
            return self._noreply(res, noreply)
        client = GitHubClient(ctx, source=SOURCE)
        search_interval = SEARCH_INTERVAL_KEYED if client.keyed else SEARCH_INTERVAL_KEYLESS
        commits = parse_commit_search(
            self._api(ctx, client, "/search/commits", params={"q": f"author-email:{email}", "sort": "author-date",
                                                                 "order": "desc", "per_page": 100},
                      resource="search", min_interval=search_interval),
            email,
        )
        if not commits["ok"]:
            return res.mark("error", "unexpected GitHub commit-search answer: could not verify")
        users = parse_user_search(
            self._api(ctx, client, "/search/users", params={"q": f"{email} in:email", "per_page": 10},
                      resource="search", min_interval=search_interval),
        )
        if not users["ok"]:
            return res.mark("error", "unexpected GitHub user-search answer: could not verify")
        accounts = {a["login"].lower(): a for a in commits["accounts"]}
        partial: list[str] = []
        stop: dict[str, str] = {"reason": "", "failed": "", "failed_code": ""}
        confirmed, discarded = self._confirm(ctx, client, users["candidates"], email, accounts, partial, stop)
        self._verify(ctx, client, accounts, partial, stop)
        res.raw = {
            "commit_search": {"total_count": commits["total_count"], "exact_matches": commits["exact_matches"],
                              "discarded_non_exact": commits["discarded_non_exact"], "incomplete": commits["incomplete"]},
            "user_search": {"total_count": users["total_count"], "candidates": len(users["candidates"]),
                            "confirmed": confirmed, "discarded_non_exact": discarded},
            "accounts": [a["login"] for a in accounts.values()],
        }
        res.attr("github_commit_search", {
            "total_count": commits["total_count"], "exact_matches": commits["exact_matches"],
            "unlinked_commits": commits["unlinked_commits"], "unlinked_repos": commits["unlinked_repos"],
            "discarded_non_exact": commits["discarded_non_exact"] + discarded,
            "placeholder_logins": commits["placeholder_logins"], "incomplete": commits["incomplete"],
        })
        if partial:
            res.error = "; ".join(partial)
        if stop["reason"]:
            res.stop(stop["reason"])
        if commits["incomplete"]:
            res.error = ((res.error + "; ") if res.error else "") + "GitHub search incomplete (timed out on GitHub's side): partial"
        if not accounts and (stop["reason"] or stop["failed"]):
            # the only remaining evidence path (profile checks) could not answer: could not verify, never EMPTY
            if stop["reason"]:
                return res.mark(stop["reason"], res.error)
            return res.mark(stop["failed"], res.error + ": could not verify", reason_code=stop["failed_code"])
        if not accounts:
            if commits["unlinked_commits"]:
                res.finding(
                    "Address used in public commits not linked to a GitHub account",
                    "info",
                    f"{commits['unlinked_commits']} public commit(s) carry this exact author e-mail but no GitHub account is "
                    f"linked to it (repositories: {', '.join(commits['unlinked_repos'][:5]) or 'not shown'}). Context only.",
                    confidence="possible",
                    criterion="exact commit-author e-mail match without an account (self-asserted commit metadata)",
                    data={"unlinked_commits": commits["unlinked_commits"], "repos": commits["unlinked_repos"][:10]},
                    tags=["context_only"],
                    source=SOURCE,
                )
                return res
            return res.mark("empty")
        self._report(res, list(accounts.values()), downweight)
        return res

    # ------------------------------------------------------------------ requests
    @staticmethod
    def _api(ctx: Any, client: GitHubClient, path: str, *, params: dict[str, Any] | None = None, resource: str = "core",
             min_interval: float = 0.0, absent: frozenset[int] = frozenset()) -> Any:
        """One REST call through the shared GitHub client's budget and headers (P111), with a per-call
        politeness interval (the search bucket is per minute). None only for a status in ``absent``."""
        client.budget.check(resource, client._now(), keyed=client.keyed)
        kw: dict[str, Any] = {"headers": client.headers(), "source": SOURCE, "min_interval": min_interval}
        if params:
            kw["params"] = params
        resp = ctx.http.get(API_ROOT + path, **kw)
        client.api_calls += 1
        if not getattr(resp, "from_cache", False):
            client.budget.note(resp.headers, client._now())
        try:
            ctx.http.check(resp)
        except RateLimited as exc:
            if not client.keyed:  # cond 2: the token hint, once
                raise RateLimited(GITHUB_ANON_COVERAGE_LINE, exc.status, exc.url) from None
            raise
        except HttpError:
            if resp.status in absent and getattr(resp, "classification", None) is None:
                return None
            raise
        return resp.json()

    def _confirm(self, ctx: Any, client: GitHubClient, candidates: list[dict[str, Any]], email: str,
                 accounts: dict[str, dict[str, Any]], partial: list[str], stop: dict[str, str]) -> tuple[int, int]:
        """users/{login} for user-search candidates: only an exact public e-mail confirms (cond 4)."""
        limit = MAX_CONFIRM_KEYED if client.keyed else MAX_CONFIRM_KEYLESS
        confirmed = discarded = 0
        ordered = sorted(candidates, key=lambda c: (c["login"].lower() not in accounts, c.get("type") != "User"))
        checked = 0
        for cand in ordered[:limit]:
            try:
                data = self._api(ctx, client, f"/users/{quote(cand['login'], safe='')}", absent=frozenset({404}))
            except (RateLimited, QuotaExceeded) as exc:
                partial.append(f"profile checks stopped ({type(exc).__name__}): remaining candidates unconfirmed")
                stop["reason"] = "rate_limited" if isinstance(exc, RateLimited) else "quota"
                break
            except (Blocked, AuthRequired, HttpError, NetworkError) as exc:
                checked += 1
                discarded += 1  # rule 5: could not verify -> unconfirmed, never 'no public e-mail'
                if not stop["failed"]:
                    blocked = isinstance(exc, (Blocked, AuthRequired))
                    stop["failed"] = "blocked" if blocked else "error"
                    stop["failed_code"] = (getattr(exc, "reason_code", "") or "challenge") if isinstance(exc, Blocked) else ("challenge" if blocked else "error")
                partial.append(f"profile of {cand['login']} could not be checked ({type(exc).__name__}): unconfirmed")
                continue
            checked += 1
            match = profile_email_match(data, email)
            if match is None or not match["exact"]:
                discarded += 1
                continue
            confirmed += 1
            acc = accounts.setdefault(match["login"].lower(), {
                "login": match["login"], "user_id": match["user_id"], "profile_url": f"https://github.com/{match['login']}",
                "basis": "profile_email", "commits": 0, "repos": [], "commit_urls": [], "first_seen": None,
                "last_seen": None, "verified_commit": False, "_newest": None,
            })
            acc["profile_email"] = True
            if acc["basis"] == "commit_author":
                acc["basis"] = "commit_author+profile_email"
        skipped = len(ordered) - checked
        discarded += skipped
        if skipped:
            partial.append(f"{skipped} user-search candidate(s) not checked (request budget): discarded as unconfirmed")
        return confirmed, discarded

    def _verify(self, ctx: Any, client: GitHubClient, accounts: dict[str, dict[str, Any]], partial: list[str],
                stop: dict[str, str]) -> None:
        """One verified-signature check per commit-only account (cond 5 PROBABLE path), capped."""
        limit = MAX_VERIFY_KEYED if client.keyed else MAX_VERIFY_KEYLESS
        todo = [a for a in accounts.values() if not a.get("profile_email") and a.get("_newest")]
        for acc in todo[:limit]:
            if stop["reason"]:
                break
            full, sha = acc["_newest"]
            try:
                data = self._api(ctx, client, f"/repos/{full}/commits/{sha}", absent=frozenset({404, 409, 422}))
            except (RateLimited, QuotaExceeded) as exc:
                partial.append(f"signature checks stopped ({type(exc).__name__}): POSSIBLE")
                stop["reason"] = "rate_limited" if isinstance(exc, RateLimited) else "quota"
                break
            except (Blocked, AuthRequired, HttpError, NetworkError) as exc:
                partial.append(f"signature of {acc['login']}'s commit could not be checked ({type(exc).__name__}): POSSIBLE")
                continue
            acc["verified_commit"] = commit_verified(data)
        if len(todo) > limit:
            partial.append(f"{len(todo) - limit} account(s) without a signature check (request budget): POSSIBLE")

    # ------------------------------------------------------------------ results
    def _noreply(self, res: ModuleResult, noreply: dict[str, Any]) -> ModuleResult:
        """cond 6: a users.noreply.github.com address names its account; decoded locally, no request."""
        login = noreply.get("login")
        if noreply.get("bot") or not isinstance(login, str):
            return res.mark("skipped", "GitHub bot noreply address (system account)", reason_code="not_applicable")
        uid = noreply.get("id")
        res.attr("noreply_accounts", [{"handle": login, "id": uid}])
        res.attr("github_accounts", [{"login": login, "user_id": uid, "profile_url": f"https://github.com/{login}",
                                      "basis": "noreply", "confidence": "probable"}])
        res.pivot(T.USERNAME, login, "noreply_account", confidence="probable", expand=False,
                  note="GitHub login decoded from a users.noreply.github.com address (no request)")
        res.pivot(T.URL, f"https://github.com/{login}", "has_account", confidence="probable", expand=False,
                  note="GitHub profile decoded from a noreply address")
        res.finding(
            "GitHub noreply address decoded",
            "info",
            f"The address is GitHub's private commit address of the account {login}"
            + (f" (user id {uid})" if uid else "") + ": decoded locally, nothing was sent.",
            confidence="probable",
            criterion="<id>+<login>@users.noreply.github.com format (GitHub-generated per account)",
            data={"login": login, "user_id": uid},
            tags=["account", "identity"],
            source=SOURCE,
        )
        return res

    @staticmethod
    def _report(res: ModuleResult, accounts: list[dict[str, Any]], downweight: str | None) -> None:
        rows = []
        for acc in accounts:
            strong = bool(acc.get("profile_email") or acc.get("verified_commit"))
            probable = strong and not downweight
            if acc.get("profile_email"):
                criterion = "the e-mail is public on the GitHub profile (exact match)"
            elif acc.get("verified_commit"):
                criterion = "signature-verified commit with this author e-mail"
            else:
                criterion = "commit author e-mail matches (self-asserted commit metadata)"
            if downweight:
                criterion += f"; {downweight}"
            label = "probable" if probable else "possible"
            row = {k: acc.get(k) for k in ("login", "user_id", "profile_url", "basis", "commits", "repos", "commit_urls",
                                           "first_seen", "last_seen", "verified_commit")}
            row["repos"] = list(row.get("repos") or [])[:20]
            row["confidence"] = label
            rows.append(row)
            score = PROBABLE if probable else POSSIBLE
            res.pivot(T.USERNAME, acc["login"], "uses_username", confidence=score, expand=False,
                      note=f"GitHub login by exact e-mail match ({label}): never auto-expanded")
            res.pivot(T.URL, acc["profile_url"], "has_account", confidence=score, expand=False,
                      note=f"GitHub profile by exact e-mail match ({label})")
            res.finding(
                "GitHub account linked to the address",
                "info",
                f"GitHub account {acc['login']} ({label.upper()}): {criterion}. Commits with the address: {acc.get('commits') or 0}"
                + (f" in {', '.join(row['repos'][:5])}" if row["repos"] else "")
                + (f"; first {acc['first_seen']}, last {acc['last_seen']}" if acc.get("first_seen") else "")
                + ". Minimised: login, id, profile URL and repository/commit references only.",
                confidence=label,
                criterion=criterion,
                data={"login": acc["login"], "user_id": acc.get("user_id"), "basis": acc.get("basis"),
                      "commits": acc.get("commits"), "verified_commit": bool(acc.get("verified_commit"))},
                tags=["account", "identity"],
                references=[acc["profile_url"], *list(acc.get("commit_urls") or [])[:3]],
                source=SOURCE,
                key=acc["login"].lower(),
            )
        res.attr("github_accounts", rows)
