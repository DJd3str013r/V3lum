"""Git commit metadata identities of case-subject GitHub accounts, organisations and repositories (P115).

What it does (final conditions FC1-FC7 of P115, batch p3-G05-2):

* FC1 - API only, through the **shared GitHub REST client and budget of P111**
  (:class:`v3lum.modules.username_social.github_user.GitHubClient`; key ``github``, 60 requests/h keyless,
  5,000/h keyed, X-RateLimit honoured): ``GET /users/{u}/repos?type=owner&sort=pushed&direction=desc&per_page=100``,
  the <= 10 own non-fork repositories with the newest ``pushed_at`` (server order is not trusted), and exactly
  one ``GET /repos/{o}/{r}/commits?per_page=100`` page each: at most 11 requests per account. A repository
  subject costs 2 (``/repos/{o}/{r}`` for the fork flag and owner id, then its commits page). No git binary,
  no clone, no search, no other forge (:func:`git_fetch_allowed` guards every URL).
* FC2 - case subjects only: analyst-typed seeds (``run_on='seeds'``) with a recorded case purpose (AR16);
  never pivots, never arbitrary developers. ``default_enabled = False``.
* FC3 - gitcolombo extraction (MIT, attribution below): author/committer names and e-mails, identity
  trailers (Co-authored-by, Signed-off-by, Reviewed-by, ...) with gitcolombo's malformed-name rule, noreply
  ids decoded by the shared P111 helper (:func:`v3lum.modules.username_social.github_user.decode_noreply`);
  noreply, system (``^(noreply|no-reply|donotreply|do-not-reply)@``) and bot addresses are dropped.
* FC4 - identities tied to the investigated account (GitHub linked the author/committer address to it, or the
  address is its noreply id) are PROBABLE (git author fields are self-declared and forgeable). Every other
  contributor, co-author and sign-off is **counted, never listed**, unless it equals a case entity; commits of
  forks and upstream projects never yield a listed value (forks of an account are skipped; a fork repository
  subject only counts upstream contributors). An organisation never authors commits: its members are counted.
* FC5 - e-mails, names and previous logins pivot with ``expand=False``, are never auto-sent to breach or
  stealer modules (A4) and live no longer than retention_days (core purge; GitHub AUP s.8 purpose limit).
* FC6 - a clone path is not built (it must be one hardened core helper: docs/backlog/p3-G05-2.md).
* FC7 - terms follow P111's GitHub REST source ('key-terms'): registry source
  ``github.git_metadata_identity_commits``.

Adapted code (A6 BR5): the identity trailer pattern and its malformed-name rule, the system-address rule,
fork skipping and the ``GitAnalyst._analyze`` same-e-mail-set clustering are adapted from gitcolombo,
https://github.com/soxoj/gitcolombo, commit 82eb1da79f9239707d08d6d8d8ba53e2d2f9926c, MIT License,
Copyright (c) 2020-2026 Soxoj (notice: v3lum/data/notices/gitcolombo_git_metadata.json).
"""

from __future__ import annotations

import re
from collections import Counter, defaultdict
from typing import Any
from urllib.parse import parse_qs, quote, urlencode, urlsplit

from v3lum.core.entities import Entity
from v3lum.core.entities import EntityType as T
from v3lum.core.http import (
    AuthRequired,
    Blocked,
    Cancelled,
    DeadlineExceeded,
    HttpError,
    NetworkError,
    OfflineError,
    QuotaExceeded,
    RateLimited,
    RequestCapReached,
)
from v3lum.core.models import ModuleResult, Opsec, Status
from v3lum.core.module import Module, register
from v3lum.modules.username_social.dev_registries import case_keys
from v3lum.modules.username_social.github_user import (
    API_ROOT,
    GitHubClient,
    decode_noreply,
    iso_utc,
    load_json,
    looks_like_html,
    normalise_email,
    normalise_github_login,
    system_email_reason,
)

SOURCE = "github.git_metadata_identity_commits"
API_HOST = "api.github.com"
GIT_MAX_REPOS = 10  # FC1
GIT_COMMITS_PER_PAGE = 100  # FC1: one commits page per repository
GIT_MAX_REQUESTS = 1 + GIT_MAX_REPOS  # FC1: 1 repository listing + 10 commit pages per account
REPOS_TTL = 6 * 3600
COMMITS_TTL = 86400
MAX_EMAIL_PIVOTS = 20
MAX_NAME_PIVOTS = 10
MAX_CASE_PIVOTS = 20
REPO_PARAMS = {"type": "owner", "sort": "pushed", "direction": "desc", "per_page": GIT_COMMITS_PER_PAGE}

# gitcolombo (MIT, see the module docstring): identity trailers and the FC3 system-address form.
TRAILER_RE = re.compile(
    r"^(?P<key>Signed-off-by|Co-authored-by|Reviewed-by|Tested-by|Reported-by|Acked-by|Suggested-by|Cc):[ \t]+"
    r"(?P<name>[^<\n]{1,200}?)[ \t]+<(?P<email>[^>\n]{1,320})>[ \t]*$",
    re.MULTILINE | re.IGNORECASE,
)
SYSTEM_EMAIL_RE = re.compile(r"^(?:noreply|no-reply|donotreply|do-not-reply)@", re.I)  # FC3 (exact form)
GITHUB_NOREPLY_SUFFIX = "@users.noreply.github.com"
_BOT_ADDRESSES = frozenset({
    "action@github.com", "actions@github.com", "github-actions@github.com", "bot@renovateapp.com",
    "support@dependabot.com", "dependabot@github.com",
})
_BOT_NAME_RE = re.compile(
    r"\[bot\]$|^(?:dependabot|renovate|github-actions|greenkeeper|snyk-bot|pre-commit-ci|allcontributors|"
    r"semantic-release-bot|imgbot|codecov)(?:\b|\[)", re.I)
_REPO_NAME_RE = re.compile(r"^[A-Za-z0-9_.-]{1,100}$")
_FULL_NAME_RE = re.compile(r"^[A-Za-z0-9-]{1,39}/[A-Za-z0-9_.-]{1,100}$")
_SHA_RE = re.compile(r"^[0-9a-f]{40}$")
#: placeholder author names that never become person_name pivots (they still count for clustering)
_JUNK_NAMES = frozenset({"root", "admin", "administrator", "user", "ubuntu", "unknown", "none", "github", "git", "test",
                         "localhost", "nobody", "your name", "name"})

_GIT_ALLOWED_PATHS = (
    re.compile(r"^/users/[A-Za-z0-9-]{1,39}/repos$"),
    re.compile(r"^/repos/[A-Za-z0-9-]{1,39}/[A-Za-z0-9_.-]{1,100}$"),
    re.compile(r"^/repos/[A-Za-z0-9-]{1,39}/[A-Za-z0-9_.-]{1,100}/commits$"),
)


# ======================================================================================
# small helpers
# ======================================================================================


def _int(value: Any) -> int | None:
    if isinstance(value, bool):
        return None
    if isinstance(value, int):
        return value
    if isinstance(value, str) and re.fullmatch(r"\s*-?\d{1,18}\s*", value):
        return int(value)
    return None


def _str(value: Any, cap: int = 500) -> str | None:
    if not isinstance(value, str):
        return None
    s = value.strip()
    return s[:cap] if s else None


def _email(value: Any) -> str | None:
    """Lower-cased address, or a GitHub noreply address the shared e-mail shape refuses ('...[bot]@...')."""
    e = normalise_email(value)
    if e:
        return e
    s = _str(value, 320)
    if s:
        s = s.strip("<>").strip()
        if decode_noreply(s) is not None:
            return s.lower()
    return None


def _not_json_reason(raw: Any, what: str) -> str:
    if looks_like_html(raw):
        return f"HTML page instead of {what} (could not verify)"
    return f"malformed {what} (could not verify)"


# ======================================================================================
# subjects and URLs (FC1/FC2)
# ======================================================================================


def normalise_git_subject(value: Any) -> dict[str, Any] | None:
    """A GitHub subject -> {'kind': 'account', 'login'} or {'kind': 'repo', 'owner', 'repo', 'full_name'}.

    Accepts 'login', '@login', 'owner/repo', https://github.com/login and https://github.com/owner/repo[.git][/...]
    (deeper paths keep owner and repository). Other forges, plain http and credentialed URLs give None.
    """
    s = _str(value, 400)
    if not s:
        return None
    if re.match(r"^[a-z][a-z0-9+.-]*://", s, re.I):
        try:
            sp = urlsplit(s)
            host = (sp.hostname or "").lower()
            port = sp.port
        except ValueError:
            return None
        if sp.scheme.lower() != "https" or host not in ("github.com", "www.github.com") or sp.username or sp.password:
            return None
        if port not in (None, 443):
            return None
        segs = [p for p in sp.path.split("/") if p]
        if not segs:
            return None
        owner, repo = segs[0], (segs[1] if len(segs) > 1 else None)
    else:
        s = s.lstrip("@")
        owner, _, rest = s.partition("/")
        repo = rest.rstrip("/") or None
        if repo and "/" in repo:
            return None
    login = normalise_github_login(owner)
    if not login:
        return None
    if repo:
        if repo.lower().endswith(".git"):
            repo = repo[:-4]
        if not _REPO_NAME_RE.match(repo) or repo in (".", ".."):
            return None
        return {"kind": "repo", "owner": login, "repo": repo, "full_name": f"{login}/{repo}"}
    return {"kind": "account", "login": login}


def subject_of(entity: Entity) -> dict[str, Any] | None:
    """The GitHub subject an entity names: a username, 'github:<login>' or a github.com account/repository URL."""
    if entity.type is T.SOCIAL_ACCOUNT:
        platform, _, handle = entity.value.partition(":")
        return normalise_git_subject(handle) if platform == "github" and "/" not in handle else None
    if entity.type is T.USERNAME:
        sub = normalise_git_subject(entity.value)
        return sub if sub and sub["kind"] == "account" else None
    if entity.type is T.URL:
        return normalise_git_subject(entity.value) if re.match(r"^https://(?:www\.)?github\.com/", entity.value, re.I) else None
    return None


def git_fetch_allowed(url: Any) -> bool:
    """FC1 guard: https api.github.com, the three endpoint shapes only, page 1 only, per_page <= 100.

    No clone URLs, no github.com HTML, no search, no gpg_keys, no other forge, no credentials, no odd ports.
    """
    if not isinstance(url, str):
        return False
    try:
        sp = urlsplit(url)
        port = sp.port
    except ValueError:
        return False
    if sp.scheme != "https" or (sp.hostname or "").lower() != API_HOST or sp.username or sp.password:
        return False
    if port not in (None, 443) or not any(rx.match(sp.path) for rx in _GIT_ALLOWED_PATHS):
        return False
    q = parse_qs(sp.query)
    if any(_int(v) is None or (_int(v) or 0) > 1 for v in q.get("page", [])):
        return False
    return not any(_int(v) is None or (_int(v) or 0) > GIT_COMMITS_PER_PAGE for v in q.get("per_page", []))


def _api_url(path: str, params: dict[str, Any] | None = None) -> str:
    return API_ROOT + path + (("?" + urlencode(params)) if params else "")


# ======================================================================================
# parsers (pure, defensive: wrong types and HTML never raise)
# ======================================================================================


def _gh_account(obj: Any) -> dict[str, Any] | None:
    if not isinstance(obj, dict):
        return None
    login = _str(obj.get("login"), 60)
    if not login:
        return None
    return {"login": login, "id": _int(obj.get("id")), "type": _str(obj.get("type"), 30)}


def select_repos(raw: Any, max_repos: int = GIT_MAX_REPOS, owner: str | None = None) -> dict[str, Any]:
    """FC1/FC4: repository list -> the <= max_repos own non-fork repositories with the newest pushed_at.

    Forks are skipped (their history is upstream work), as are empty (size 0: the commits API answers 409),
    disabled, private and not-owned entries; entries are re-sorted by pushed_at (server order not trusted).
    """
    data = load_json(raw)
    res: dict[str, Any] = {"ok": False, "reason": None, "selected": [], "forks": 0, "skipped": {}, "total": 0,
                           "owner": None, "page_full": False}
    if not isinstance(data, list):
        res["reason"] = _not_json_reason(raw, "repository list")
        return res
    own = owner.lower() if isinstance(owner, str) else None
    skipped: Counter[str] = Counter()
    cands: list[dict[str, Any]] = []
    for r in data[:GIT_COMMITS_PER_PAGE]:
        if not isinstance(r, dict):
            skipped["malformed"] += 1
            continue
        full = _str(r.get("full_name"), 200)
        if not full or not _FULL_NAME_RE.match(full):
            skipped["malformed"] += 1
            continue
        o_login, name = full.split("/", 1)
        acct = _gh_account(r.get("owner")) or {"login": o_login, "id": None, "type": None}
        if own and acct["login"].lower() != own:
            skipped["not_owned"] += 1
            continue
        if res["owner"] is None:
            res["owner"] = acct
        if r.get("private") is True:
            skipped["private"] += 1
            continue
        if r.get("fork") is True:
            res["forks"] += 1
            skipped["fork"] += 1
            continue
        if r.get("disabled") is True:
            skipped["disabled"] += 1
            continue
        if _int(r.get("size")) == 0:
            skipped["empty"] += 1
            continue
        cands.append({"full_name": full, "owner": o_login, "repo": name, "pushed_at": iso_utc(r.get("pushed_at")),
                      "archived": r.get("archived") is True})
    cands.sort(key=lambda x: x["pushed_at"] or "", reverse=True)
    cap = max(0, int(max_repos))
    if len(cands) > cap:
        skipped["over_cap"] = len(cands) - cap
    res.update(ok=True, selected=cands[:cap], total=len(data), page_full=len(data) >= GIT_COMMITS_PER_PAGE,
               skipped=dict(skipped), reason=None if cands else "no own non-fork repositories")
    return res


def parse_repo_meta(raw: Any) -> dict[str, Any]:
    """GET /repos/{o}/{r} -> fork flag, parent, owner (with id) of a repository subject (FC2/FC4)."""
    data = load_json(raw)
    if not isinstance(data, dict):
        return {"ok": False, "reason": _not_json_reason(raw, "repository JSON")}
    full = _str(data.get("full_name"), 200)
    if not full or not _FULL_NAME_RE.match(full):
        return {"ok": False, "reason": "layout changed: no full_name (could not verify)"}
    parent = data.get("parent") if isinstance(data.get("parent"), dict) else {}
    return {"ok": True, "reason": None, "full_name": full, "fork": data.get("fork") is True,
            "parent": _str(parent.get("full_name"), 200), "owner": _gh_account(data.get("owner")),
            "archived": data.get("archived") is True, "disabled": data.get("disabled") is True,
            "pushed_at": iso_utc(data.get("pushed_at"))}


def git_trailers(message: Any, cap: int = 64) -> list[dict[str, Any]]:
    """FC3: identity trailers (gitcolombo pattern) -> [{'key', 'name', 'email', 'malformed'}].

    gitcolombo's rule: a name containing ':' (another label crammed on the line) or '@' (an @-mention) is
    malformed and never used.
    """
    if not isinstance(message, str):
        return []
    out: list[dict[str, Any]] = []
    for m in TRAILER_RE.finditer(message[:65536]):
        email = (m.group("email") or "").strip()
        if not email:
            continue
        name = (m.group("name") or "").strip()
        out.append({"key": m.group("key").lower(), "name": name[:200], "email": _email(email),
                    "malformed": ":" in name or "@" in name})
        if len(out) >= cap:
            break
    return out


def address_class(email: Any, name: Any = None, login: Any = None, account_type: Any = None) -> tuple[str, dict[str, Any] | None]:
    """FC3: ('personal'|'noreply'|'bot'|'system'|'invalid', decoded noreply or None).

    noreply = GitHub users.noreply addresses (decoded by the shared P111 helper, never an e-mail output);
    bot = [bot] accounts/addresses and CI bots; system = ^(noreply|no-reply|donotreply|do-not-reply)@ and
    GitHub placeholders; invalid = not a mailbox (malformed, localhost, .local...).
    """
    e = _email(email)
    if not e:
        return "invalid", None
    nr = decode_noreply(e)
    if nr is not None:
        return ("bot" if nr["bot"] else "noreply"), nr
    if e.endswith(GITHUB_NOREPLY_SUFFIX):
        return "noreply", None
    local = e.rpartition("@")[0]
    if (isinstance(login, str) and login.lower().endswith("[bot]")) or str(account_type or "").lower() == "bot" \
            or e in _BOT_ADDRESSES or "[bot]" in local or (isinstance(name, str) and _BOT_NAME_RE.search(name.strip())):
        return "bot", None
    if SYSTEM_EMAIL_RE.match(e):
        return "system", None
    why = system_email_reason(e)
    if why:
        return ("invalid" if "local host" in why or "not an e-mail" in why else "system"), None
    return "personal", None


def parse_commits_page(raw: Any, repo: str | None = None) -> dict[str, Any]:
    """FC1/FC3: one ``GET /repos/{o}/{r}/commits?per_page=100`` page -> normalised commit records.

    Each record: sha, repo, author/committer {name, email, date}, author_account / committer_account (GitHub's
    own address -> account link: login, id, type), trailers, verified. Messages are reduced to their trailers.
    """
    data = load_json(raw)
    if not isinstance(data, list):
        return {"ok": False, "reason": _not_json_reason(raw, "commit list"), "commits": [], "page_full": False}
    out: list[dict[str, Any]] = []
    for it in data[:GIT_COMMITS_PER_PAGE]:
        if not isinstance(it, dict):
            continue
        sha = _str(it.get("sha"), 64)
        if not sha or not _SHA_RE.match(sha):
            continue
        c = it.get("commit") if isinstance(it.get("commit"), dict) else {}
        a = c.get("author") if isinstance(c.get("author"), dict) else {}
        cm = c.get("committer") if isinstance(c.get("committer"), dict) else {}
        ver = c.get("verification") if isinstance(c.get("verification"), dict) else {}
        out.append({
            "sha": sha, "repo": repo,
            "author": {"name": _str(a.get("name"), 200), "email": _email(a.get("email")), "date": iso_utc(a.get("date"))},
            "committer": {"name": _str(cm.get("name"), 200), "email": _email(cm.get("email")), "date": iso_utc(cm.get("date"))},
            "author_account": _gh_account(it.get("author")),
            "committer_account": _gh_account(it.get("committer")),
            "trailers": git_trailers(c.get("message")),
            "verified": ver.get("verified") is True,
        })
    return {"ok": True, "reason": None if out else "no commits", "commits": out, "page_full": len(data) >= GIT_COMMITS_PER_PAGE}


def _tied(acct: Any, nr: Any, sub_login: str, sub_id: int | None) -> bool:
    """FC4: is this role tied to the investigated account (GitHub's account link or its noreply id)?"""
    if isinstance(acct, dict):
        lg = acct.get("login")
        if sub_login and isinstance(lg, str) and lg.lower() == sub_login:
            return True
        if sub_id is not None and _int(acct.get("id")) == sub_id:
            return True
    if isinstance(nr, dict):
        if sub_id is not None and nr.get("id") == sub_id:
            return True
        if sub_login and isinstance(nr.get("login"), str) and nr["login"].lower() == sub_login:
            return True
    return False


def extract_identities(commits: Any, subject: Any, case_values: Any = (), fork_repos: Any = ()) -> dict[str, Any]:
    """FC3/FC4/FC5: commit records of a case subject -> identities tied to it, counts for everyone else.

    ``subject`` is :func:`normalise_git_subject` output plus an optional numeric 'id' (the owner object of the
    repository list). Tied = GitHub linked the author/committer address to the subject account, or the address is
    the subject's noreply id: listed as PROBABLE. Everyone else (other contributors, co-authors, sign-offs, other
    trailers, other noreply ids) is counted only, unless the value equals a case entity (``case_values``:
    e-mails, names, logins). Commits of ``fork_repos`` never yield a listed non-subject value. The clustering is
    gitcolombo's GitAnalyst._analyze restricted to the subject's own identities.
    """
    subject = subject if isinstance(subject, dict) else {}
    sub_login = str(subject.get("login") or subject.get("owner") or "").lower()
    sub_id = _int(subject.get("id"))
    case = {v.strip().casefold() for v in (case_values or ()) if isinstance(v, str) and v.strip()}
    forks = {f.lower() for f in (fork_repos or ()) if isinstance(f, str)}

    ident: dict[str, dict[str, Any]] = {}
    noreply: dict[str, dict[str, Any]] = {}
    case_hits: dict[str, dict[str, Any]] = {}
    others: set[str] = set()
    other_commit_shas: set[str] = set()
    upstream: set[str] = set()
    other_noreply: set[str] = set()
    trailer_sets: dict[str, set[str]] = {"co_authors": set(), "sign_offs": set(), "other_trailers": set()}
    counts: Counter[str] = Counter()
    dropped: Counter[str] = Counter()
    name_to_emails: dict[str, set[str]] = defaultdict(set)
    links: set[tuple[tuple[str, str], tuple[str, str]]] = set()
    repos_seen: set[str] = set()
    shas: set[str] = set()

    def is_case(*values: Any) -> bool:
        return any(isinstance(v, str) and v.strip().casefold() in case for v in values if v)

    def note_case(value: str, kind: str, role: str, sha: str) -> None:
        hit = case_hits.setdefault(value, {"value": value, "kind": kind, "roles": Counter(), "commits": set()})
        hit["roles"][role] += 1
        hit["commits"].add(sha)

    def note_noreply(nr: dict[str, Any], role: str, sha: str) -> None:
        rec = noreply.setdefault(str(nr.get("id") or nr["login"].lower()), {
            "login": nr["login"], "id": nr.get("id"), "roles": Counter(), "commits": set(), "previous_login": None})
        rec["roles"][role] += 1
        rec["commits"].add(sha)
        if sub_login and nr["login"].lower() != sub_login:
            rec["previous_login"] = nr["login"]

    def add_identity(email: str, name: Any, role: str, sha: str, repo: str | None, date: Any, via: str) -> None:
        rec = ident.setdefault(email, {"email": email, "names": [], "roles": Counter(), "commits": set(), "first": None,
                                       "last": None, "repos": [], "via": set(), "case_entity": is_case(email)})
        rec["roles"][role] += 1
        rec["commits"].add(sha)
        rec["via"].add(via)
        if isinstance(date, str) and date:
            rec["first"] = date if not rec["first"] or date < rec["first"] else rec["first"]
            rec["last"] = date if not rec["last"] or date > rec["last"] else rec["last"]
        if isinstance(name, str) and name and name not in rec["names"] and len(rec["names"]) < 5:
            rec["names"].append(name)
        if repo and repo not in rec["repos"] and len(rec["repos"]) < 20:
            rec["repos"].append(repo)
        if isinstance(name, str) and name:
            name_to_emails[name].add(email)

    # Pass 1 - roles tied to the subject (order-independent: identities are known before passes 2 and 3).
    pending: list[tuple[Any, ...]] = []
    kept: list[tuple[dict[str, Any], str, bool]] = []
    for c in commits or ():
        if not isinstance(c, dict) or not isinstance(c.get("sha"), str) or c["sha"] in shas:
            continue
        sha = c["sha"]
        shas.add(sha)
        repo = c.get("repo") if isinstance(c.get("repo"), str) else None
        if repo:
            repos_seen.add(repo)
        in_fork = bool(repo) and str(repo).lower() in forks
        kept.append((c, sha, in_fork))
        tied_pairs: dict[str, tuple[str, str]] = {}
        for role in ("author", "committer"):
            p = c.get(role) if isinstance(c.get(role), dict) else {}
            acct = c.get(role + "_account") if isinstance(c.get(role + "_account"), dict) else {}
            email, name = p.get("email"), p.get("name")
            cls, nr = address_class(email, name, acct.get("login"), acct.get("type"))
            if cls in ("system", "bot", "invalid"):
                dropped[cls] += 1
                continue
            tied = _tied(acct, nr, sub_login, sub_id)
            if cls == "noreply":
                if nr and tied:
                    note_noreply(nr, role, sha)
                elif nr:
                    other_noreply.add(nr["login"].lower())
                    if not in_fork and is_case(nr["login"]):
                        note_case(nr["login"], "username", role, sha)
                else:
                    dropped["noreply_undecodable"] += 1
                continue
            if tied:  # the subject's own commits (also inside a fork it owns) identify the subject
                add_identity(email, name, role, sha, repo, p.get("date"), "account_link")
                tied_pairs[role] = (name or "", email)
            else:
                pending.append((email, name, acct.get("login"), role, sha, repo, p.get("date"), in_fork))
        if len(tied_pairs) == 2 and tied_pairs["author"] != tied_pairs["committer"]:
            links.add((tied_pairs["author"], tied_pairs["committer"]))  # gitcolombo 'also known as'

    # Pass 2 - other role observations: an address already tied to the subject keeps counting for it (later
    # unlinked commits made with the same address); everything else is counted, not listed.
    for email, name, login, role, sha, repo, date, in_fork in pending:
        if email in ident:
            add_identity(email, name, role, sha, repo, date, "same_address")
            continue
        if in_fork:
            upstream.add(email)
            continue
        others.add(email)
        other_commit_shas.add(sha)
        if is_case(email, name, login):
            note_case(email, "email", role, sha)

    # Pass 3 - trailers: counted, never listed, unless they repeat a subject identity or match a case entity.
    for c, sha, in_fork in kept:
        for t in c.get("trailers") or ():
            if not isinstance(t, dict):
                continue
            if t.get("malformed"):
                counts["malformed_trailers"] += 1
                continue
            email, name, key = t.get("email"), t.get("name"), t.get("key")
            cls, nr = address_class(email, name)
            if cls in ("system", "bot", "invalid"):
                dropped["trailer_" + cls] += 1
                continue
            if cls == "noreply":
                if nr and _tied({}, nr, sub_login, sub_id):
                    note_noreply(nr, "trailer", sha)
                elif nr:
                    other_noreply.add(nr["login"].lower())
                continue
            if email in ident:
                counts["self_trailers"] += 1
                continue
            if in_fork:
                upstream.add(email)
                continue
            if is_case(email, name):
                note_case(email, "email", "trailer:" + str(key or "?"), sha)
            bucket = {"co-authored-by": "co_authors", "signed-off-by": "sign_offs"}.get(str(key), "other_trailers")
            trailer_sets[bucket].add(email)

    # gitcolombo GitAnalyst._analyze: names sharing the exact same e-mail set are one person.
    emails_to_names: dict[frozenset[str], list[str]] = defaultdict(list)
    for name, emails in name_to_emails.items():
        emails_to_names[frozenset(emails)].append(name)
    same_person = sorted(sorted(names) for names in emails_to_names.values() if len(names) > 1)
    multi_email = sorted(({"name": n, "emails": sorted(es)} for n, es in name_to_emails.items() if len(es) > 1),
                         key=lambda x: x["name"])

    identities = []
    for rec in ident.values():
        rec["roles"] = dict(rec["roles"])
        rec["commits"] = len(rec["commits"])
        rec["via"] = sorted(rec["via"])
        identities.append(rec)
    identities.sort(key=lambda r: (-r["commits"], r["email"]))
    person_names = [{"name": n, "emails": sorted(es)} for n, es in sorted(name_to_emails.items())]
    accounts = []
    for rec in noreply.values():
        rec["roles"] = dict(rec["roles"])
        rec["commits"] = len(rec["commits"])
        accounts.append(rec)
    accounts.sort(key=lambda r: r["login"].lower())
    hits = []
    for hit in case_hits.values():
        hit["roles"] = dict(hit["roles"])
        hit["commits"] = len(hit["commits"])
        hits.append(hit)
    hits.sort(key=lambda h: h["value"])
    counts.update({"other_contributors": len(others), "other_contributor_commits": len(other_commit_shas),
                   "co_authors": len(trailer_sets["co_authors"]), "sign_offs": len(trailer_sets["sign_offs"]),
                   "other_trailers": len(trailer_sets["other_trailers"]), "upstream_contributors": len(upstream),
                   "other_noreply_accounts": len(other_noreply)})
    return {
        "commits_seen": len(shas), "repos_seen": sorted(repos_seen), "identities": identities,
        "person_names": person_names, "noreply_accounts": accounts,
        "clusters": {"same_person": same_person, "multi_email_names": multi_email,
                     "author_committer_links": sorted([list(a), list(b)] for a, b in links)},
        "case_matches": hits, "counts": dict(counts), "dropped": dict(dropped),
    }


# ======================================================================================
# the module
# ======================================================================================


def _case_values(ctx: Any, entity: Entity) -> set[str]:
    """Values of the case as far as the module sees them (seeds and provenance path): e-mails, names, logins."""
    out: set[str] = set()
    for key in case_keys(ctx, entity):
        etype, _, value = key.partition(":")
        if etype == T.SOCIAL_ACCOUNT.value:
            platform, _, handle = value.partition(":")
            if platform == "github" and handle:
                out.add(handle)
        elif etype in (T.EMAIL.value, T.USERNAME.value, T.PERSON.value) and value:
            out.add(value)
    return out


def _person_name_ok(name: str) -> bool:
    n = name.strip()
    return len(n) >= 3 and bool(re.search(r"[^\W\d_]", n)) and n.casefold() not in _JUNK_NAMES


@register
class GitMetadataIdentity(Module):
    name = "git_metadata_identity"
    title = "Git commit metadata identities (GitHub REST)"
    description = (
        "Names and e-mails a case-subject GitHub account, organisation or repository used in its own public commits "
        "(author/committer, identity trailers, noreply ids), read from the GitHub REST API only: <= 10 repositories by "
        "push date, one commits page each; other contributors are counted, never listed."
    )
    category = "username_social"
    accepts = frozenset({T.USERNAME, T.URL, T.SOCIAL_ACCOUNT})
    produces = frozenset({T.EMAIL, T.PERSON, T.USERNAME, T.SOCIAL_ACCOUNT})
    run_on = "seeds"  # FC2: case subjects only, never pivots or arbitrary developers
    terms = "key-terms"  # FC7: follows the GitHub REST source of P111
    opsec = Opsec.PASSIVE
    disclosure = "third_party"  # FC1: api.github.com receives the account or repository name
    provider = "github"
    sources = (SOURCE,)
    hosts = (API_HOST,)
    access_model = "free_noauth_limited"
    optional_keys = ("github",)
    max_requests = GIT_MAX_REQUESTS  # FC1: <= 11 requests per account (A3: > 10 keeps it out of the default set)
    expected_latency = 12.0  # keyless p50 estimate: 11 serial calls with 1 s spacing
    timeout = 90.0
    min_interval = 1.0  # serial, GitHub secondary-limit guidance (shared client)
    cache_ttl = COMMITS_TTL
    max_pivots = 60
    default_enabled = False  # FC2 (legal_dpo floor)
    reference = "https://github.com/soxoj/gitcolombo"
    tags = frozenset({"slow"})
    error_markers = (
        {"id": "git_metadata_identity_html_instead_of_data", "statuses": [200], "json_path": None, "equals": None,
         "regex": r"(?i)^\s*(?:<!--[\s\S]{0,4000}?-->\s*)?(?:<!doctype\s+html|<html\b)", "final_url_regex": None,
         "maps_to": "error", "reason_code": "error",
         "reason": "GitHub served an HTML page instead of REST data: could not verify"},
    )
    notice = (
        "Case subjects only (an analyst-typed GitHub account, organisation or repository with a recorded purpose, "
        "AR16): never run it on arbitrary developers. GitHub API terms are key-terms (P111): under the corporate "
        "profile it runs once legal records free_plan_business_use or key_plans.github = 'business'. Commit e-mails and "
        "names are self-declared and forgeable (PROBABLE at most), case-bound (retention_days) and never sent to breach "
        "or stealer modules automatically. Other contributors are counted, never listed. gitcolombo logic, MIT."
    )

    def applies(self, entity: Entity, ctx: Any) -> bool:
        return subject_of(entity) is not None

    # ------------------------------------------------------------------ run
    def run(self, entity: Entity, ctx: Any) -> ModuleResult:
        res = self.result(entity)
        subject = subject_of(entity)
        if subject is None:
            return res.mark("skipped", "not a GitHub account, organisation or repository", reason_code="not_applicable")
        if not getattr(ctx, "is_seed", False):
            return res.mark("skipped", "case subjects only: analyst-typed accounts, organisations or repositories, never pivots "
                            "(P115 FC2)", reason_code="privacy")
        if not str(getattr(ctx, "purpose", "") or "").strip():
            return res.mark("skipped", "a recorded case purpose is required (--purpose, AR16; P115 FC2)", reason_code="privacy")
        client = GitHubClient(ctx, source=SOURCE)
        if subject["kind"] == "account":
            plan = self._account_plan(res, ctx, client, subject)
        else:
            plan = self._repo_plan(res, ctx, client, subject)
        if plan is None:
            return res
        targets, forks, listing = plan
        commits, read, problems, stop = self._read_commits(ctx, client, targets)
        result = extract_identities(commits, subject, _case_values(ctx, entity), forks)
        self._emit(res, ctx, subject, listing, read, result)
        for source, items in problems.items():
            status, code, _ = items[0]
            res.source_status(source, status, reason_code=code, reason="; ".join(text for _s, _c, text in items)[:500])
        if stop:
            reason, text = stop
            res.error = "; ".join(x for x in (res.error, text) if x)
            res.stop(reason)
        return res

    # ------------------------------------------------------------------ subjects
    def _call(self, client: GitHubClient, path: str, *, params: dict[str, Any] | None = None, absent: frozenset[int] = frozenset({404}),
              ttl: int = COMMITS_TTL) -> Any:
        url = _api_url(path, params)
        if not git_fetch_allowed(url):  # FC1 guard (defence in depth: every URL is built from validated names)
            raise HttpError(f"refused a GitHub request outside the P115 plan: {path}")
        return client.api_json(path, params=params, absent=absent, ttl=ttl)

    def _account_plan(self, res: ModuleResult, ctx: Any, client: GitHubClient, subject: dict[str, Any]) -> Any:
        login = subject["login"]
        data = self._call(client, f"/users/{quote(login, safe='')}/repos", params=REPO_PARAMS, ttl=REPOS_TTL)
        url = f"https://github.com/{login}"
        if data is None:
            res.presence("absent", marker="HTTP 404 from api.github.com/users/{u}/repos", url=url, checked_at=ctx.now(), source=SOURCE)
            res.error = "no GitHub account or organisation with this login"
            res.mark("empty")
            return None
        sel = select_repos(data, owner=login)
        if not sel["ok"]:
            res.mark("error", f"unexpected GitHub answer ({sel['reason']})")
            return None
        owner = sel["owner"] or {}
        if owner.get("id") is not None:
            subject["id"] = owner["id"]
        subject["account_type"] = owner.get("type")
        res.presence("found", marker="HTTP 200 repository list of the account", url=url, checked_at=ctx.now(), source=SOURCE)
        listing = {"total": sel["total"], "skipped": sel["skipped"], "forks": sel["forks"], "page_full": sel["page_full"]}
        return sel["selected"], [], listing

    def _repo_plan(self, res: ModuleResult, ctx: Any, client: GitHubClient, subject: dict[str, Any]) -> Any:
        owner, repo = subject["owner"], subject["repo"]
        data = self._call(client, f"/repos/{quote(owner, safe='')}/{quote(repo, safe='')}")
        url = f"https://github.com/{owner}/{repo}"
        if data is None:
            res.presence("absent", marker="HTTP 404 from api.github.com/repos/{o}/{r}", url=url, checked_at=ctx.now(), source=SOURCE)
            res.error = "no public GitHub repository with this name"
            res.mark("empty")
            return None
        meta = parse_repo_meta(data)
        if not meta["ok"]:
            res.mark("error", f"unexpected GitHub answer ({meta['reason']})")
            return None
        acct = meta["owner"] or {}
        if acct.get("login") and str(acct["login"]).lower() == owner.lower() and acct.get("id") is not None:
            subject["id"] = acct["id"]
        subject["account_type"] = acct.get("type")
        res.presence("found", marker="HTTP 200 repository object", url=url, checked_at=ctx.now(), source=SOURCE)
        full = meta["full_name"]
        target = {"full_name": full, "owner": full.split("/", 1)[0], "repo": full.split("/", 1)[1], "pushed_at": meta["pushed_at"],
                  "archived": meta["archived"]}
        listing = {"fork": meta["fork"], "parent": meta["parent"]}
        return [target], ([full] if meta["fork"] else []), listing

    # ------------------------------------------------------------------ commits (FC1: one page per repository)
    def _read_commits(self, ctx: Any, client: GitHubClient, targets: list[dict[str, Any]]) -> tuple[list[dict[str, Any]], list[dict[str, Any]], dict[str, Any], Any]:
        commits: list[dict[str, Any]] = []
        read: list[dict[str, Any]] = []
        problems: dict[str, list[tuple[Status, str, str]]] = {}
        stop = None
        for t in targets:
            if ctx.cancelled():
                stop = ("cancelled", "run cancelled: remaining repositories not read")
                break
            full = t["full_name"]
            path = f"/repos/{quote(t['owner'], safe='')}/{quote(t['repo'], safe='')}/commits"
            try:
                page = self._call(client, path, params={"per_page": GIT_COMMITS_PER_PAGE}, absent=frozenset({404, 409}))
            except RateLimited as exc:
                stop = ("rate_limited", f"GitHub rate limit after {len(read)} of {len(targets)} repositories ({exc})")
                break
            except QuotaExceeded as exc:
                stop = ("quota", f"GitHub budget spent after {len(read)} of {len(targets)} repositories ({exc})")
                break
            except RequestCapReached:
                stop = ("request_cap", f"request cap reached after {len(read)} of {len(targets)} repositories")
                break
            except DeadlineExceeded:
                stop = ("deadline", f"run deadline reached after {len(read)} of {len(targets)} repositories")
                break
            except Cancelled:
                stop = ("cancelled", "run cancelled: remaining repositories not read")
                break
            except Blocked as exc:
                problems.setdefault(SOURCE, []).append((Status.BLOCKED, exc.reason_code, f"commits of {full}: {exc}"))
                continue
            except AuthRequired as exc:
                problems.setdefault(SOURCE, []).append((Status.NEEDS_KEY, "needs_key", f"commits of {full}: {exc}"))
                continue
            except OfflineError as exc:
                problems.setdefault(SOURCE, []).append((Status.UNAVAILABLE, "offline", f"commits of {full}: {exc}"))
                continue
            except (HttpError, NetworkError, ValueError) as exc:
                code = "timeout" if getattr(exc, "reason_code", "") == "timeout" else "error"
                problems.setdefault(SOURCE, []).append((Status.ERROR, code, f"commits of {full}: could not verify ({exc})"))
                continue
            if page is None:  # 404 (removed meanwhile) or 409 (empty repository)
                read.append({"full_name": full, "pushed_at": t.get("pushed_at"), "commits": 0, "note": "empty or gone"})
                continue
            parsed = parse_commits_page(page, repo=full)
            if not parsed["ok"]:
                problems.setdefault(SOURCE, []).append((Status.ERROR, "error", f"commits of {full}: {parsed['reason']}"))
                continue
            commits += parsed["commits"]
            read.append({"full_name": full, "pushed_at": t.get("pushed_at"), "commits": len(parsed["commits"]),
                         "page_full": parsed["page_full"]})
        return commits, read, problems, stop

    # ------------------------------------------------------------------ output (FC4/FC5)
    def _emit(self, res: ModuleResult, ctx: Any, subject: dict[str, Any], listing: dict[str, Any], read: list[dict[str, Any]],
              result: dict[str, Any]) -> None:
        login = subject.get("login") or subject.get("owner")
        label = subject.get("full_name") or login
        url = f"https://github.com/{label}"
        res.attr("account_id", subject.get("id"))
        res.attr("account_type", subject.get("account_type"))
        res.attr("git_repos_read", {"subject": label, "kind": subject["kind"], "selected": read, **listing,
                                    "commits_seen": result["commits_seen"]})
        identities = [{k: i[k] for k in ("email", "names", "commits", "roles", "first", "last", "repos", "via", "case_entity")}
                      for i in result["identities"]]
        res.attr("git_identities", identities)
        res.attr("noreply_accounts", [{"handle": a["login"], "id": a["id"]} for a in result["noreply_accounts"]])
        res.attr("third_party_counts", {**result["counts"], "dropped": result["dropped"]})
        clusters = result["clusters"]
        if any(clusters.values()):
            res.attr("git_clusters", clusters)
        res.attr("git_case_matches", result["case_matches"])
        res.raw = {"subject": {"kind": subject["kind"], "name": label, "id": subject.get("id"), "type": subject.get("account_type")},
                   "listing": listing, "repos_read": read, "commits_seen": result["commits_seen"],
                   "identities": len(identities), "counts": result["counts"], "dropped": result["dropped"]}
        note = "self-declared git metadata of the subject's own commits (forgeable): case-bound, never sent to breach or stealer modules automatically"
        for i in result["identities"][:MAX_EMAIL_PIVOTS]:
            res.pivot(T.EMAIL, i["email"], "commit_email", confidence="probable", expand=False,
                      note=f"used in {i['commits']} commit(s) GitHub links to {login}: {note}")
        names = [n for n in result["person_names"] if _person_name_ok(n["name"])]
        for n in names[:MAX_NAME_PIVOTS]:
            res.pivot(T.PERSON, n["name"], "git_commit_name", confidence="probable", expand=False,
                      note=f"author name used with {len(n['emails'])} of {login}'s commit address(es): {note}")
        for a in result["noreply_accounts"]:
            if a.get("previous_login"):
                res.pivot(T.SOCIAL_ACCOUNT, f"github:{a['previous_login']}", "previous_handle", confidence="probable", expand=False,
                          note=f"GitHub login at commit time (noreply id {a['id']}) of the account now named {login}")
        for h in result["case_matches"][:MAX_CASE_PIVOTS]:
            etype, value = (T.EMAIL, h["value"]) if h["kind"] == "email" else (T.SOCIAL_ACCOUNT, f"github:{h['value']}")
            res.pivot(etype, value, "case_entity_in_subject_repos", confidence="probable", expand=False,
                      note=f"case entity seen in {h['commits']} commit(s) of {label}'s own repositories")
        if identities:
            res.finding(
                "Identities in the subject's own commits",
                "info",
                f"{len(identities)} address(es) and {len(names)} name(s) used in commits GitHub links to {login} "
                f"({result['commits_seen']} commits read in {len(read)} repositories). Git author fields are self-declared "
                "and forgeable; other contributors are counted, not listed.",
                confidence="probable",
                criterion="author/committer address of commits GitHub links to the subject account (or its noreply id) in its own "
                          "non-fork repositories, one commits page per repository (gitcolombo method)",
                data={"emails": [i["email"] for i in identities[:10]], "counts": result["counts"]},
                tags=["identity", "privacy"],
                references=[url],
                source=SOURCE,
            )
        if result["case_matches"]:
            res.finding(
                "Case entity in the subject's commit metadata",
                "low",
                f"{len(result['case_matches'])} value(s) already in the case appear in the commit metadata of {label}'s own "
                "repositories: " + ", ".join(h["value"] for h in result["case_matches"][:10]),
                confidence="probable",
                criterion="exact match of a case e-mail, name or GitHub login against author/committer/trailer values of the "
                          "subject's own (non-fork) repositories",
                data={"matches": result["case_matches"][:20]},
                tags=["identity"],
                references=[url],
                source=SOURCE,
            )
        org = getattr(ctx, "org", None)
        own = []
        for i in identities:
            ent = Entity.try_make(T.EMAIL, i["email"])
            try:
                if ent is not None and org is not None and org.owns(ent).own:
                    own.append(i["email"])
            except Exception:  # noqa: BLE001 - a broken organisation profile never stops the run
                continue
        if own:
            res.finding(
                "Organisation e-mail address in the subject's public commits",
                "low",
                f"{', '.join(own[:10])} appear(s) in public commits of {label}: exposed to address harvesting and social engineering.",
                confidence="probable",
                criterion="commit e-mail domain matches an org-profile domain",
                data={"emails": own[:20]},
                tags=["exposure", "privacy"],
                references=[url],
                source=SOURCE,
            )
