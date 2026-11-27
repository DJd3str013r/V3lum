"""Organisation source-code footprint (P359, batch p2-G05-2): forge and package-registry organisations
of a company, and (deep preset only) a secret scan of their public repositories.

Two modules share this file:

* ``org_code_footprint`` - the fast inventory (default set; API only, at most 10 requests and about
  15 s per entity, cond 4). Company name, domain, handle or keyword -> candidate organisations on
  GitHub (search type:org, shared P111 client and budget), Codeberg (orgs/{slug}), Docker Hub
  (/v2/orgs/{slug}), npm ('@scope/' search, or 'maintainer:' for a handle), PyPI (/org/{slug}/) and
  GitLab (groups?search=&top_level_only=true). An organisation counts as **confirmed** only when its
  declared website/blog host is an org_profile domain (PSL membership, A11) or the analyst listed it
  in setting ``org_code_footprint_confirmed`` (``['github:acme', 'gitlab:acme-group', ...]``, cond 2);
  unconfirmed organisations are listed as candidates (``expand=False``) and get no repository, member
  or secret look-up. Confirmed organisations: repository count and the 5 most recent repositories
  (at most 30 read, recent first, forks without own commits skipped), public member count (usernames
  only with setting ``org_code_footprint_list_members``, as ``expand=False`` pivots), packages.
* ``org_code_secrets`` - deep preset or ``-M`` only (default_enabled False, its own time budget and
  a progress line, cond 5): the current tree of each confirmed organisation's repositories (<= 30,
  API size <= 50 MB) is downloaded as the provider's tar.gz archive and streamed **in memory** (no git
  binary, no extraction to disk, nothing built or executed; regular files only, 1 MB per member,
  binaries skipped) through the shared gitleaks engine of ``secret_scanner`` (P312). One grouped
  finding per repository lists type, file, commit and line with a keyed fingerprint and at most the
  first 4 characters; full values never leave the scan, are never tested, validated or used (cond 6),
  wording 'exposed in public history; validity not tested'. HIGH only for the own organisation's
  repositories; a third party's secrets get tag ``third_party_disclosure`` (disclosure workflow, not
  shared reports, cond 7). History scanning waits for the hardened git helper of P115.

Who may run (cond 3): in the default set only for the own organisation (an org_profile domain, the
profile's name or a brand keyword); suppliers and other companies only as explicit seeds (``-M`` or
``v3lum run``) with a recorded purpose. Only SaaS forges are contacted (cond 8): self-hosted forges on
org domains are target infrastructure (LIGHT/ACTIVE phase). A PyPI client challenge is BLOCKED
``challenge``, never an absence. GitHub REST is 'key-terms' (as P111); GitLab, Codeberg, npm, PyPI and
Docker Hub 'open' (cond 9).
"""

from __future__ import annotations

import io
import re
import tarfile
import unicodedata
import zlib
from datetime import datetime, timezone
from html.parser import HTMLParser
from typing import Any
from urllib.parse import parse_qs, quote, urlsplit

from v3lum.core.entities import Entity
from v3lum.core.entities import EntityType as T
from v3lum.core.http import AuthRequired, Blocked, DeadlineExceeded, HttpError, NetworkError, QuotaExceeded, RateLimited
from v3lum.core.models import ModuleResult, Opsec
from v3lum.core.module import Module, register

__all__ = [
    "INVENTORY_MAX_REPOS",
    "INVENTORY_RECENT",
    "MAX_MEMBER_BYTES",
    "MAX_REPO_BYTES",
    "SECRET_WORDING",
    "OrgCodeFootprint",
    "OrgCodeSecrets",
    "archive_url",
    "count_from_link_header",
    "extract_host",
    "org_confirmation",
    "org_slug_candidates",
    "parse_codeberg_org",
    "parse_codeberg_repos",
    "parse_dockerhub_org",
    "parse_dockerhub_repos",
    "parse_github_org",
    "parse_github_org_search",
    "parse_github_repos",
    "parse_gitlab_groups",
    "parse_gitlab_projects",
    "parse_npm_search",
    "parse_pypi_org_page",
    "scan_archive_members",
    "select_repos",
]

SRC_GH = "github.org_code_footprint_orgs"
SRC_GH_ARCHIVE = "github.org_code_footprint_archives"
SRC_GL = "gitlab.groups_api"
SRC_GL_ARCHIVE = "gitlab.org_code_footprint_archives"
SRC_CB = "codeberg.api"
SRC_NPM = "npm.registry"
SRC_PYPI = "pypi.org_pages"
SRC_DH = "docker_hub.hub_api"

GH_API = "https://api.github.com"
GL_API = "https://gitlab.com/api/v4"
CB_API = "https://codeberg.org/api/v1"
NPM_SEARCH = "https://registry.npmjs.org/-/v1/search"
PYPI_ORG = "https://pypi.org/org/{slug}/"
DH_API = "https://hub.docker.com/v2"

INVENTORY_MAX_REPOS = 30  # cond 4
INVENTORY_RECENT = 5  # cond 4
MAX_REPO_BYTES = 50 * 1024 * 1024  # cond 5 (API size; also the streamed archive cap)
MAX_MEMBER_BYTES = 1024 * 1024  # cond 5
MAX_TOTAL_BYTES = 256 * 1024 * 1024  # uncompressed safety cap (archive bomb)
MAX_MEMBERS = 20_000
SECRET_WORDING = "exposed in public history; validity not tested"  # cond 6
CONFIRMED_SETTING = "org_code_footprint_confirmed"
MEMBERS_SETTING = "org_code_footprint_list_members"
BINARY_EXTENSIONS = (".png", ".jpg", ".jpeg", ".gif", ".webp", ".ico", ".bmp", ".tif", ".tiff", ".pdf", ".zip", ".gz", ".tgz",
                     ".bz2", ".xz", ".7z", ".rar", ".jar", ".war", ".class", ".so", ".dll", ".exe", ".dylib", ".o", ".a", ".bin",
                     ".woff", ".woff2", ".ttf", ".otf", ".eot", ".mp3", ".mp4", ".mov", ".avi", ".wasm", ".pyc", ".db", ".sqlite",
                     ".psd", ".iso", ".dmg", ".apk", ".ipa")
PYPI_CHALLENGE = {
    "id": "org_code_footprint_pypi_challenge", "statuses": [200, 403], "json_path": None, "equals": None,
    "regex": r"<title>\s*Client Challenge\s*</title>", "final_url_regex": None, "maps_to": "blocked", "reason_code": "challenge",
    "reason": "PyPI: JavaScript client challenge (anti-bot page): could not verify, never bypassed (P359 cond 8)",
}
_SOFT_FAILURES = (RateLimited, Blocked, AuthRequired, QuotaExceeded, HttpError, NetworkError)


# ---------------------------------------------------------------------------------------------
# small helpers
# ---------------------------------------------------------------------------------------------


def _int(value: Any, default: int | None = None) -> int | None:
    if isinstance(value, bool):
        return default
    try:
        return int(str(value).strip().replace(",", ""))
    except (TypeError, ValueError):
        return default


def _iso(value: Any) -> datetime | None:
    if not isinstance(value, str) or not value:
        return None
    try:
        dt = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        return None
    return dt if dt.tzinfo else dt.replace(tzinfo=timezone.utc)


def extract_host(value: Any) -> str | None:
    """Host of a blog/website/profile_url value ('www.example.com', 'https://x/y', 'example.com')."""
    if not isinstance(value, str) or not value.strip():
        return None
    v = value.strip()
    if "://" not in v:
        v = "https://" + v
    try:
        host = (urlsplit(v).hostname or "").rstrip(".").lower()
    except ValueError:
        return None
    if not host or "." not in host or ":" in host or host.replace(".", "").isdigit():
        return None
    return host


def count_from_link_header(link: Any, items_on_page: int = 0) -> int:
    """Total of a per_page=1 listing from the GitHub Link header (rel="last" page number)."""
    if isinstance(link, str):
        for part in link.split(","):
            if 'rel="last"' in part:
                m = re.search(r"<([^>]+)>", part)
                if m:
                    q = parse_qs(urlsplit(m.group(1)).query)
                    page = _int((q.get("page") or [None])[0])
                    if page:
                        return page
    return items_on_page


def org_slug_candidates(company_name: str | None = None, domain: str | None = None, limit: int = 2) -> list[str]:
    """Slugs for providers without org search: the domain's first label and the company name (cond 4 budget)."""
    out: list[str] = []
    cands: list[str] = []
    if isinstance(domain, str) and domain.strip():
        labels = domain.strip().lower().split(".")
        cands.append(labels[1] if labels[0] in ("www", "www2") and len(labels) > 2 else labels[0])
    if isinstance(company_name, str) and company_name.strip():
        base = unicodedata.normalize("NFKD", company_name).encode("ascii", "ignore").decode().lower()
        base = re.sub(r"\b(s\.?a\.?|ltda\.?|inc\.?|llc|ltd\.?|gmbh|corp\.?|me|eireli|co\.?)\b", " ", base)
        words = re.findall(r"[a-z0-9]+", base)
        if words:
            cands.extend(["".join(words), "-".join(words)])
    for cand in cands:
        if cand and re.fullmatch(r"[a-z0-9][a-z0-9_.-]{0,38}", cand) and cand not in out:
            out.append(cand)
    return out[:limit]


# ---------------------------------------------------------------------------------------------
# provider parsers (untrusted JSON/HTML: every field type-checked)
# ---------------------------------------------------------------------------------------------


def parse_github_org_search(obj: Any) -> list[dict[str, Any]]:
    """GitHub /search/users?q=<name>+type:org -> organisation candidates (type Organization only)."""
    items = obj.get("items") if isinstance(obj, dict) else None
    if not isinstance(items, list):
        return []
    return [{"provider": "github", "login": it["login"], "url": it.get("html_url") if isinstance(it.get("html_url"), str) else None}
            for it in items if isinstance(it, dict) and it.get("type") == "Organization" and isinstance(it.get("login"), str)]


def parse_github_org(obj: Any) -> dict[str, Any] | None:
    if not isinstance(obj, dict) or not isinstance(obj.get("login"), str):
        return None
    return {"provider": "github", "login": obj["login"], "name": obj.get("name") if isinstance(obj.get("name"), str) else None,
            "url": obj.get("html_url") if isinstance(obj.get("html_url"), str) else f"https://github.com/{obj['login']}",
            "website_host": extract_host(obj.get("blog")), "verified_domain": bool(obj.get("is_verified")),
            "repo_count": _int(obj.get("public_repos")), "created_at": obj.get("created_at") if isinstance(obj.get("created_at"), str) else None}


def _repo(provider: str, full_name: str, url: Any, fork: Any, archived: Any, created: Any, pushed: Any, size_kb: Any,
          branch: Any, **extra: Any) -> dict[str, Any]:
    return {"provider": provider, "full_name": full_name, "url": url if isinstance(url, str) else None, "fork": bool(fork),
            "archived": bool(archived), "created_at": created if isinstance(created, str) else None,
            "pushed_at": pushed if isinstance(pushed, str) else None, "size_kb": _int(size_kb),
            "default_branch": branch if isinstance(branch, str) and re.fullmatch(r"[A-Za-z0-9._/-]{1,100}", branch) else None, **extra}


def parse_github_repos(obj: Any) -> list[dict[str, Any]]:
    items = obj.get("items") if isinstance(obj, dict) else obj
    return [_repo("github", r["full_name"], r.get("html_url"), r.get("fork"), r.get("archived"), r.get("created_at"), r.get("pushed_at"),
                  r.get("size"), r.get("default_branch"))
            for r in (items if isinstance(items, list) else []) if isinstance(r, dict) and isinstance(r.get("full_name"), str)]


def parse_gitlab_groups(obj: Any, query: str = "") -> list[dict[str, Any]]:
    """GitLab groups?search=&top_level_only=true -> top-level groups whose path or name equals the query."""
    q = (query or "").lower()
    out = []
    for g in obj if isinstance(obj, list) else []:
        if not isinstance(g, dict) or g.get("parent_id") not in (None, 0) or not isinstance(g.get("full_path"), str):
            continue
        names = {str(g.get(k) or "").lower() for k in ("path", "name", "full_path")}
        if q and q not in names:
            continue
        out.append({"provider": "gitlab", "login": g["full_path"], "id": _int(g.get("id")), "name": g.get("name") if isinstance(g.get("name"), str) else None,
                    "url": g.get("web_url") if isinstance(g.get("web_url"), str) else None, "website_host": None})
    return out


def parse_gitlab_projects(obj: Any) -> list[dict[str, Any]]:
    out = []
    for p in obj if isinstance(obj, list) else []:
        if not isinstance(p, dict) or not isinstance(p.get("path_with_namespace"), str):
            continue
        stats = p.get("statistics") if isinstance(p.get("statistics"), dict) else {}
        size_b = _int(stats.get("repository_size"))
        out.append(_repo("gitlab", p["path_with_namespace"], p.get("web_url"), bool(p.get("forked_from_project")), p.get("archived"),
                         p.get("created_at"), p.get("last_activity_at"), size_b // 1024 if size_b is not None else None,
                         p.get("default_branch"), id=_int(p.get("id"))))
    return out


def parse_codeberg_org(obj: Any) -> dict[str, Any] | None:
    if not isinstance(obj, dict):
        return None
    login = obj.get("username") or obj.get("name")
    if not isinstance(login, str) or not login:
        return None
    return {"provider": "codeberg", "login": login, "name": obj.get("full_name") if isinstance(obj.get("full_name"), str) else None,
            "url": f"https://codeberg.org/{login}", "website_host": extract_host(obj.get("website"))}


def parse_codeberg_repos(obj: Any) -> list[dict[str, Any]]:
    return [_repo("codeberg", r["full_name"], r.get("html_url"), r.get("fork"), r.get("archived"), r.get("created_at"), r.get("updated_at"),
                  r.get("size"), r.get("default_branch"), empty=bool(r.get("empty")))
            for r in (obj if isinstance(obj, list) else []) if isinstance(r, dict) and isinstance(r.get("full_name"), str)]


def parse_npm_search(obj: Any, scope: str | None = None) -> dict[str, Any]:
    """npm /-/v1/search -> package names, versions and dates; ``scope`` keeps '@scope/' names only.
    Maintainer e-mails are never read."""
    if not isinstance(obj, dict):
        return {"total": 0, "packages": []}
    pkgs = []
    prefix = f"@{scope.lstrip('@').lower()}/" if scope else ""
    for o in obj.get("objects") if isinstance(obj.get("objects"), list) else []:
        p = o.get("package") if isinstance(o, dict) else None
        if not isinstance(p, dict) or not isinstance(p.get("name"), str):
            continue
        if prefix and not p["name"].lower().startswith(prefix):
            continue
        pkgs.append({"name": p["name"], "version": p.get("version") if isinstance(p.get("version"), str) else None,
                     "date": p.get("date") if isinstance(p.get("date"), str) else None})
    return {"total": _int(obj.get("total"), 0) or 0, "packages": pkgs}


class _PypiOrgParser(HTMLParser):
    """pypi.org/org/{org}/: display name, slug, project count and project snippets (name, last release)."""

    def __init__(self) -> None:
        super().__init__(convert_charrefs=True)
        self.out: dict[str, Any] = {"display_name": None, "org": None, "project_count": None, "projects": []}
        self._grab: str | None = None
        self._buf: list[str] = []
        self._project: dict[str, Any] | None = None

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        a = {k: v or "" for k, v in attrs}
        classes = a.get("class", "").split()
        if tag == "h1" and "author-profile__name" in classes:
            self._start("display_name")
        elif tag == "span" and "break" in classes and self.out["org"] is None:
            self._start("org")
        elif tag == "h2" and self.out["project_count"] is None:
            self._start("h2")
        elif tag == "a" and "package-snippet" in classes:
            self._project = {"name": None, "last_released": None}
        elif tag == "h3" and "package-snippet__title" in classes and self._project is not None:
            self._start("project")
        elif tag == "time" and self._project is not None and a.get("datetime"):
            self._project["last_released"] = a["datetime"]

    def _start(self, what: str) -> None:
        self._grab, self._buf = what, []

    def handle_data(self, data: str) -> None:
        if self._grab:
            self._buf.append(data)

    def handle_endtag(self, tag: str) -> None:
        if self._grab and tag in ("h1", "span", "h2", "h3"):
            text = " ".join("".join(self._buf).split())
            if self._grab == "display_name":
                self.out["display_name"] = text or None
            elif self._grab == "org":
                self.out["org"] = text or None
            elif self._grab == "h2":
                m = re.match(r"^([\d,]+)\s+projects?\b", text)
                if m:
                    self.out["project_count"] = _int(m.group(1))
            elif self._grab == "project" and self._project is not None:
                self._project["name"] = text or None
            self._grab = None
        if tag == "a" and self._project is not None:
            if self._project.get("name") and len(self.out["projects"]) < INVENTORY_MAX_REPOS:
                self.out["projects"].append(self._project)
            self._project = None


def parse_pypi_org_page(text: str) -> dict[str, Any]:
    parser = _PypiOrgParser()
    try:
        parser.feed(text[: 2 * 1024 * 1024])
        parser.close()
    except Exception:  # noqa: BLE001 - html.parser rarely raises; keep what was parsed
        pass
    return parser.out


def parse_dockerhub_org(obj: Any) -> dict[str, Any] | None:
    if not isinstance(obj, dict) or not isinstance(obj.get("orgname"), str):
        return None  # a 404 body is {"orgname": ["<name>"]}
    return {"provider": "dockerhub", "login": obj["orgname"], "name": obj.get("full_name") if isinstance(obj.get("full_name"), str) else None,
            "url": f"https://hub.docker.com/u/{obj['orgname']}", "website_host": extract_host(obj.get("profile_url")),
            "badge": obj.get("badge") if isinstance(obj.get("badge"), str) else None}


def parse_dockerhub_repos(obj: Any) -> dict[str, Any]:
    if not isinstance(obj, dict):
        return {"count": 0, "repos": []}
    repos = [{"name": r["name"], "last_updated": r.get("last_updated") if isinstance(r.get("last_updated"), str) else None,
              "pull_count": _int(r.get("pull_count"))}
             for r in obj.get("results") or [] if isinstance(r, dict) and isinstance(r.get("name"), str)]
    return {"count": _int(obj.get("count"), len(repos)) or 0, "repos": repos}


def org_confirmation(record: dict[str, Any], host_kind: Any, confirmed: set[str]) -> dict[str, str]:
    """cond 2: 'confirmed' only on a website/blog host matching the org_profile (an own domain, or a supplier
    domain for a supplier's organisation) or the analyst's confirmation; anything else stays a candidate.

    ``host_kind(host)`` -> 'own' | 'supplier' | falsy (core A11 membership: PSL registrable domain +
    subdomain, never string suffixes)."""
    key = f"{record.get('provider')}:{str(record.get('login') or '').lower()}"
    if key in confirmed:
        return {"state": "confirmed", "basis": "analyst"}
    host = record.get("website_host")
    if host and callable(host_kind):
        try:
            kind = host_kind(host)
        except Exception:  # noqa: BLE001 - a membership error never confirms
            kind = None
        if kind is True or kind == "own":
            basis = "website_host+github_verified_domain" if record.get("verified_domain") else "website_host"
            return {"state": "confirmed", "basis": basis}
        if kind == "supplier":
            return {"state": "confirmed", "basis": "supplier_website_host"}
    return {"state": "candidate", "basis": "no_owned_website" if host else "no_website"}


def fork_has_own_commits(repo: dict[str, Any], tolerance_s: int = 60) -> bool:
    """A fork counts only when the org pushed to it (pushed_at later than created_at)."""
    created, pushed = _iso(repo.get("created_at")), _iso(repo.get("pushed_at"))
    return bool(created and pushed and (pushed - created).total_seconds() > tolerance_s)


def select_repos(repos: list[dict[str, Any]], cap: int = INVENTORY_MAX_REPOS) -> dict[str, Any]:
    """cond 4/5: recent-first inventory (<= 30, forks without own commits skipped) and deep-scan eligibility."""
    kept, skipped = [], []
    for r in repos:
        if r.get("fork") and not fork_has_own_commits(r):
            skipped.append({"repo": r.get("full_name"), "reason": "fork_without_own_commits"})
            continue
        kept.append(r)
    kept.sort(key=lambda r: _iso(r.get("pushed_at")) or datetime.min.replace(tzinfo=timezone.utc), reverse=True)
    kept = kept[:cap]
    deep = []
    for r in kept:
        size = r.get("size_kb")
        if r.get("empty"):
            deep.append((r, False, "empty"))
        elif size is not None and size * 1024 > MAX_REPO_BYTES:
            deep.append((r, False, "over_50mb"))
        else:
            deep.append((r, True, "ok" if size is not None else "size_unknown_stream_cap"))
    return {"inventory": kept, "recent": kept[:INVENTORY_RECENT], "skipped": skipped, "deep": deep}


def archive_url(repo: dict[str, Any]) -> tuple[str, str] | None:
    """cond 5/8: (archive URL on a declared SaaS host, registry source) of a repository's current tree."""
    ref = repo.get("default_branch") or "HEAD"
    name = repo.get("full_name") or ""
    if not re.fullmatch(r"[A-Za-z0-9_.-]+(?:/[A-Za-z0-9_.-]+)+", name) or any(part in (".", "..") for part in name.split("/")):
        return None
    if repo.get("provider") == "github":
        return f"https://codeload.github.com/{name}/tar.gz/{quote(ref, safe='/')}", SRC_GH_ARCHIVE
    if repo.get("provider") == "gitlab" and repo.get("id"):
        return f"{GL_API}/projects/{int(repo['id'])}/repository/archive.tar.gz?sha={quote(ref, safe='')}", SRC_GL_ARCHIVE
    if repo.get("provider") == "codeberg":
        return f"{CB_API}/repos/{name}/archive/{quote(ref, safe='')}.tar.gz", SRC_CB
    return None


def scan_archive_members(data: bytes, *, max_member: int = MAX_MEMBER_BYTES, max_total: int = MAX_TOTAL_BYTES,
                         max_members: int = MAX_MEMBERS) -> dict[str, Any]:
    """cond 5: stream a tar.gz held in memory; never extract to disk, never execute.

    Returns ``{'commit', 'files': [{'path', 'text'}], 'skipped': [{'path', 'reason'}], 'error'}``: regular
    files only (links, devices skipped), unsafe names skipped, members over 1 MB and binaries skipped,
    total and member-count caps; the top-level '<repo>-<sha>/' folder is stripped; the commit comes
    from the pax global header (codeload)."""
    out: dict[str, Any] = {"commit": None, "files": [], "skipped": [], "error": None}
    total = count = 0
    try:
        with tarfile.open(fileobj=io.BytesIO(bytes(data)), mode="r|gz") as tf:
            for ti in tf:
                if out["commit"] is None:
                    comment = (tf.pax_headers or {}).get("comment")
                    if isinstance(comment, str) and re.fullmatch(r"[0-9a-f]{40}|[0-9a-f]{64}", comment):
                        out["commit"] = comment
                count += 1
                if count > max_members:
                    out["error"] = "member_cap"
                    break
                name = ti.name or ""
                if name.startswith("/") or ".." in name.split("/") or "\\" in name:
                    out["skipped"].append({"path": name[:200], "reason": "unsafe_path"})
                    continue
                if ti.isdir():
                    continue
                rel = name.split("/", 1)[1] if "/" in name else name
                if not ti.isreg():
                    out["skipped"].append({"path": rel[:200], "reason": "not_regular_file"})
                    continue
                if ti.size > max_member:
                    out["skipped"].append({"path": rel[:200], "reason": "over_1mb"})
                    continue
                if rel.lower().endswith(BINARY_EXTENSIONS):
                    continue
                if total + ti.size > max_total:
                    out["error"] = "total_cap"
                    break
                fh = tf.extractfile(ti)
                blob = fh.read(max_member + 1) if fh else b""
                total += len(blob)
                if b"\x00" in blob[:8192]:
                    continue  # binary content
                out["files"].append({"path": rel, "text": blob.decode("utf-8", "replace")})
    except (tarfile.TarError, EOFError, OSError, zlib.error) as exc:
        out["error"] = f"archive_error:{type(exc).__name__}"
    return out


# ---------------------------------------------------------------------------------------------
# shared run logic
# ---------------------------------------------------------------------------------------------


class _Stop(Exception):
    """The request budget of this entity is spent (partial result)."""


class _Footprint:
    """One run's discovery state: budget, soft failures per source, organisations found."""

    def __init__(self, module: Any, ctx: Any, res: ModuleResult, *, budget: int, forges_only: bool = False) -> None:
        self.module, self.ctx, self.res = module, ctx, res
        self.budget = budget
        self.forges_only = forges_only
        self.orgs: list[dict[str, Any]] = []
        self.failures: dict[str, Exception] = {}
        self.answered: set[str] = set()
        allowed = getattr(ctx, "allowed_sources", None)
        self.allowed = set(allowed) if allowed is not None else set(module.sources)
        raw = ctx.setting(CONFIRMED_SETTING, []) or []
        self.confirmed = {str(x).strip().lower() for x in (raw if isinstance(raw, (list, tuple, set)) else [raw]) if str(x).strip()}
        self.gh_client: Any = None

    # -- plumbing
    def _spend(self) -> None:
        if getattr(self.ctx.http, "requests", 0) >= self.budget:
            raise _Stop()

    def _get(self, url: str, source: str, **kw: Any) -> Any:
        """GET with the soft budget; returns the Response (None never)."""
        self._spend()
        return self.ctx.http.get(url, source=source, **kw)

    def _json(self, url: str, source: str, *, absent: tuple[int, ...] = (404,), **kw: Any) -> Any:
        resp = self._get(url, source, **kw)
        if resp.status in absent and getattr(resp, "classification", None) is None:
            self.answered.add(source)
            return None
        self.ctx.http.check(resp)
        self.answered.add(source)
        try:
            return resp.json()
        except ValueError as exc:
            raise HttpError(f"{source}: unexpected non-JSON answer", resp.status, resp.url) from exc

    def _gh(self, path: str, params: dict[str, Any] | None = None, resource: str = "core") -> tuple[Any, Any]:
        """GitHub REST through the shared P111 client budget (key 'github' sent to api.github.com only)."""
        from v3lum.modules.username_social.github_user import GitHubClient

        if self.gh_client is None:
            self.gh_client = GitHubClient(self.ctx, source=SRC_GH)
        client = self.gh_client
        now = self.ctx.now().timestamp()
        client.budget.check(resource, now, keyed=client.keyed)
        self._spend()
        resp = self.ctx.http.get(GH_API + path, params=params, headers=client.headers(), source=SRC_GH)
        if not getattr(resp, "from_cache", False):
            client.budget.note(resp.headers, now)
        if resp.status == 404 and getattr(resp, "classification", None) is None:
            self.answered.add(SRC_GH)
            return None, resp
        self.ctx.http.check(resp)
        self.answered.add(SRC_GH)
        try:
            return resp.json(), resp
        except ValueError as exc:
            raise HttpError("GitHub: unexpected non-JSON answer", resp.status, resp.url) from exc

    def _guard(self, source: str, fn: Any, *args: Any) -> Any:
        """Run one provider step; a soft failure is recorded for the source and the others go on."""
        if source not in self.allowed:
            return None
        try:
            return fn(*args)
        except DeadlineExceeded:
            raise  # the run's time budget is spent: the caller keeps the partial result (stop reason 'deadline')
        except _SOFT_FAILURES as exc:
            self.failures.setdefault(source, exc)
            code = str(getattr(exc, "reason_code", "") or "")
            if isinstance(exc, RateLimited):
                status, code = "rate_limited", "rate_limited"
            elif isinstance(exc, QuotaExceeded):
                status, code = "quota", "quota"
            elif isinstance(exc, AuthRequired):
                status, code = "needs_key", "needs_key"
            elif isinstance(exc, Blocked):
                status = "blocked"
                code = code if code in ("challenge", "geo_block", "login_wall", "circuit", "hostile_host") else "challenge"
            else:
                status, code = "error", code if code in ("timeout", "error") else "error"
            self.res.source_status(source, status, reason_code=code, reason=str(exc)[:200])
            return None

    def _host_kind(self, host: str) -> str | None:
        ent = Entity.try_make(T.DOMAIN, host)
        if ent is None:
            return None
        owned = self.ctx.org.owns(ent)
        if owned.own:
            return "own"
        return "supplier" if getattr(owned, "kind", "") == "supplier" else None

    def _add(self, record: dict[str, Any] | None) -> dict[str, Any] | None:
        if not record:
            return None
        record.update(org_confirmation(record, self._host_kind, self.confirmed))
        self.orgs.append(record)
        return record

    # -- discovery per provider (cond 1)
    def github(self, query: str, handle: str | None) -> None:
        logins: list[str] = []
        if handle:
            logins = [handle]
        elif query:
            data, _resp = self._gh("/search/users", {"q": f"{query} type:org", "per_page": 5}, resource="search")
            cands = parse_github_org_search(data)
            slugs = set(org_slug_candidates(query, None, limit=3)) | {query.lower()}
            exact = [c["login"] for c in cands if c["login"].lower() in slugs]
            for cand in cands[:5]:
                if cand["login"] not in exact:
                    self._add({"provider": "github", "login": cand["login"], "url": cand["url"], "website_host": None,
                               "searched_only": True})
            logins = exact[:1]
        for login in logins:
            data, _resp = self._gh(f"/orgs/{quote(login, safe='')}")
            org = self._add(parse_github_org(data))
            if org and org["state"] == "confirmed":
                repos, _r = self._gh(f"/orgs/{quote(org['login'], safe='')}/repos",
                                     {"per_page": INVENTORY_MAX_REPOS, "sort": "pushed", "type": "public"})
                org["repos"] = parse_github_repos(repos)
                list_members = bool(self.ctx.setting(MEMBERS_SETTING, False))
                members, resp = self._gh(f"/orgs/{quote(org['login'], safe='')}/public_members", {"per_page": 30 if list_members else 1})
                page = members if isinstance(members, list) else []
                org["member_count"] = count_from_link_header(resp.headers.get("link"), len(page)) if resp is not None else None
                if list_members:
                    org["members"] = [m["login"] for m in page if isinstance(m, dict) and isinstance(m.get("login"), str)][:30]

    def codeberg(self, slug: str) -> None:
        data = self._json(f"{CB_API}/orgs/{quote(slug, safe='')}", SRC_CB)
        org = self._add(parse_codeberg_org(data))
        if org and org["state"] == "confirmed":
            resp = self._get(f"{CB_API}/orgs/{quote(org['login'], safe='')}/repos", SRC_CB, params={"limit": 50})
            self.ctx.http.check(resp)
            org["repos"] = parse_codeberg_repos(resp.json())
            org["repo_count"] = _int(resp.headers.get("x-total-count"), len(org["repos"]))
            members = self._get(f"{CB_API}/orgs/{quote(org['login'], safe='')}/public_members", SRC_CB, params={"limit": 1})
            self.ctx.http.check(members)
            org["member_count"] = _int(members.headers.get("x-total-count"))

    def dockerhub(self, slug: str) -> None:
        data = self._json(f"{DH_API}/orgs/{quote(slug, safe='')}", SRC_DH)
        org = self._add(parse_dockerhub_org(data))
        if org and org["state"] == "confirmed":
            repos = self._json(f"{DH_API}/repositories/{quote(org['login'], safe='')}/", SRC_DH,
                               params={"page_size": INVENTORY_RECENT, "ordering": "last_updated"})
            parsed = parse_dockerhub_repos(repos)
            org["packages"] = {"docker": parsed["repos"]}
            org["repo_count"] = parsed["count"]

    def gitlab(self, slug: str) -> None:
        data = self._json(f"{GL_API}/groups", SRC_GL, params={"search": slug, "top_level_only": "true", "per_page": 5})
        for group in parse_gitlab_groups(data, slug)[:1]:
            org = self._add(group)
            if org and org["state"] == "confirmed" and org.get("id"):
                projects = self._json(f"{GL_API}/groups/{int(org['id'])}/projects", SRC_GL,
                                      params={"per_page": INVENTORY_MAX_REPOS, "order_by": "last_activity_at",
                                              "include_subgroups": "false", "archived": "false"})
                org["repos"] = parse_gitlab_projects(projects)

    def npm(self, slug: str, handle: str | None) -> None:
        text = f"maintainer:{handle}" if handle else f"@{slug}/"
        data = self._json(NPM_SEARCH, SRC_NPM, params={"text": text, "size": 20})
        parsed = parse_npm_search(data, None if handle else slug)
        if not parsed["packages"]:
            return
        login = handle or slug
        self._add({"provider": "npm", "login": login, "url": f"https://www.npmjs.com/{'~' + login if handle else 'org/' + login}",
                   "website_host": None, "packages": {"npm": parsed["packages"]}, "package_count": len(parsed["packages"])})

    def pypi(self, slug: str) -> None:
        resp = self._get(PYPI_ORG.format(slug=quote(slug, safe="")), SRC_PYPI, headers={"Accept": "text/html"})
        if resp.status == 404 and getattr(resp, "classification", None) is None:
            self.answered.add(SRC_PYPI)
            return
        self.ctx.http.check(resp)
        self.answered.add(SRC_PYPI)
        page = parse_pypi_org_page(resp.text or "")
        if not page["org"] and not page["projects"]:
            raise HttpError("PyPI: unexpected organisation page layout", resp.status, resp.url)
        login = page["org"] or slug
        self._add({"provider": "pypi", "login": login, "name": page["display_name"], "url": PYPI_ORG.format(slug=quote(login, safe="")),
                   "website_host": None, "packages": {"pypi": page["projects"]}, "package_count": page["project_count"]})

    # -- the whole discovery
    def run(self, entity: Entity) -> str:
        """Query every allowed provider in budget order; returns '' or the stop reason ('request_cap' when the
        entity's request budget is spent, 'deadline' when the run's time budget ran out first)."""
        value = str(entity.value).strip()
        handle = value.lstrip("@") if entity.type is T.USERNAME else None
        if entity.type is T.DOMAIN:
            slugs = org_slug_candidates(None, value)
            query = slugs[0] if slugs else ""
        else:
            slugs = [handle.lower()] if handle else org_slug_candidates(value, None)
            query = handle or value
        slug = slugs[0] if slugs else ""
        steps: list[tuple[str, Any, tuple[Any, ...]]] = [(SRC_GH, self.github, (query, handle))]
        if slug:
            steps += [(SRC_CB, self.codeberg, (slug,)), (SRC_GL, self.gitlab, (slug,))]
            if not self.forges_only:
                steps += [(SRC_DH, self.dockerhub, (slug,)), (SRC_NPM, self.npm, (slug, handle)), (SRC_PYPI, self.pypi, (slug,))]
        for source, fn, args in steps:
            try:
                self._guard(source, fn, *args)
            except _Stop:
                return "request_cap"
            except DeadlineExceeded:
                if not self.orgs and not self.answered:
                    raise  # nothing answered in time: ERROR timeout (could not verify)
                return "deadline"  # keep what the faster providers answered (partial result)
        return ""


def _own_seed(entity: Entity, ctx: Any) -> bool:
    """The seed names the own organisation: an org_profile domain, its name or a brand keyword."""
    org = ctx.org
    own = False
    if not getattr(org, "is_empty", True):
        if entity.type is T.DOMAIN:
            own = bool(org.owns(entity).own)
        elif entity.type in (T.ORG, T.KEYWORD):
            name = str(entity.value).strip().casefold()
            terms = {str(t).casefold() for t in (org.brand_terms() or [])} | ({str(org.name).casefold()} if getattr(org, "name", "") else set())
            own = name in terms
    return own


def _seed_gate(module: Any, entity: Entity, ctx: Any) -> str | None:
    """cond 3: the own organisation runs by default (or a handle the analyst confirmed in
    ``org_code_footprint_confirmed``); anything else needs explicit selection + a recorded purpose."""
    if _own_seed(entity, ctx):
        return None
    raw = ctx.setting(CONFIRMED_SETTING, []) or []
    confirmed = {str(x).strip().lower().split(":", 1)[-1] for x in (raw if isinstance(raw, (list, tuple, set)) else [raw])}
    if entity.type is T.USERNAME and str(entity.value).lstrip("@").lower() in confirmed:
        return None
    options = getattr(ctx, "options", None)
    runtime = getattr(ctx, "runtime", None)
    explicit = module.name in set(getattr(options, "include", ()) or ()) or not bool(getattr(runtime, "in_scan", False))
    if explicit and str(getattr(ctx, "purpose", "") or "").strip():
        return None
    return ("default only for the own organisation (an org_profile domain, name or brand); other companies run only when "
            f"selected explicitly (-M {module.name}) with a recorded --purpose (P359 cond 3)")


def _org_view(org: dict[str, Any]) -> dict[str, Any]:
    keep = ("provider", "login", "url", "state", "basis", "website_host", "repo_count", "member_count", "package_count")
    return {k: org.get(k) for k in keep if org.get(k) is not None}


def _record_inventory(res: ModuleResult, fp: _Footprint) -> None:
    confirmed = [o for o in fp.orgs if o["state"] == "confirmed"]
    candidates = [o for o in fp.orgs if o["state"] != "confirmed"]
    res.attr("code_orgs", [_org_view(o) for o in fp.orgs])
    recent: list[dict[str, Any]] = []
    packages: dict[str, list[Any]] = {}
    counts: dict[str, int] = {}
    for org in confirmed:
        sel = select_repos(org.get("repos") or [])
        if org.get("repos") is not None and org.get("repo_count") is None:
            org["repo_count"] = len(sel["inventory"])
        recent += [{k: r.get(k) for k in ("provider", "full_name", "url", "pushed_at", "fork", "archived")} for r in sel["recent"]]
        for kind, items in (org.get("packages") or {}).items():
            packages.setdefault(kind, []).extend(items[:INVENTORY_MAX_REPOS])
        if org.get("member_count") is not None:
            counts[f"{org['provider']}:{org['login']}"] = int(org["member_count"])
        if org.get("url"):
            res.pivot(T.URL, org["url"], "code_org", confidence="probable", expand=False,
                      note=f"confirmed {org['provider']} organisation ({org['basis']})")
        for member in org.get("members") or []:
            res.pivot(T.USERNAME, member, "org_member", confidence="possible", expand=False,
                      note="public member listed on demand: personal profiles are not enriched without a case reason (P359 cond 4)")
    for org in candidates:
        if org.get("url"):
            res.pivot(T.URL, org["url"], "code_org", confidence="possible", expand=False,
                      note=f"candidate {org['provider']} organisation: not confirmed (name collision possible), not expanded")
        if org.get("website_host"):
            res.pivot(T.DOMAIN, org["website_host"], "links_to", confidence="possible", expand=False,
                      note="website declared by a candidate organisation (unconfirmed)")
    if recent:
        res.attr("code_repos", recent[: INVENTORY_RECENT * 3])
    if packages:
        res.attr("code_packages", packages)
    if counts:
        res.attr("code_member_counts", counts)
    if not fp.orgs:
        return
    res.finding(
        "Source-code and package organisations found",
        "info",
        f"{len(confirmed)} confirmed and {len(candidates)} candidate organisation(s): "
        + ", ".join(f"{o['provider']}:{o['login']} ({o['state']})" for o in fp.orgs[:12])
        + ". Candidates are name matches only (collisions are common) and get no repository, member or secret look-up "
        "until an org_profile website match or the analyst confirms them.",
        confidence="probable" if confirmed else "possible",
        criterion="organisation records on SaaS forges/registries; confirmed only by a declared website host on an org_profile "
        "domain or by the analyst (P359 cond 2)",
        data={"confirmed": [f"{o['provider']}:{o['login']}" for o in confirmed], "candidates": len(candidates)},
        tags=["exposure"] if confirmed else ["weak_signal"],
        key="orgs",
    )


@register
class OrgCodeFootprint(Module):
    name = "org_code_footprint"
    title = "Organisation code footprint (forges and package registries)"
    description = (
        "Company name, domain or handle -> organisations on GitHub, GitLab, Codeberg, npm, PyPI and Docker Hub; confirmed "
        "ones (website on an org_profile domain, or analyst-listed) get repository, member and package counts."
    )
    category = "company_org"
    accepts = {T.ORG, T.DOMAIN, T.USERNAME, T.KEYWORD}
    produces = {T.URL, T.DOMAIN, T.USERNAME}
    run_on = "seeds"
    tags = {"free"}
    reference = "https://docs.github.com/en/rest/orgs/orgs"
    notice = (
        "Default only for the own organisation; suppliers and other companies only with -M and a recorded purpose. Name matches "
        "are candidates until confirmed (collisions are common). Public members are counted, not profiled. API only: no HTML "
        "scraping of github.com, a PyPI challenge is never bypassed."
    )
    terms = "key-terms"
    opsec = Opsec.PASSIVE
    disclosure = "third_party"
    provider = "github"
    sources = (SRC_GH, SRC_GL, SRC_CB, SRC_NPM, SRC_PYPI, SRC_DH)
    hosts = ("api.github.com", "gitlab.com", "codeberg.org", "registry.npmjs.org", "pypi.org", "hub.docker.com")
    access_model = "free_noauth_limited"
    optional_keys = ("github",)
    max_requests = 10  # cond 4
    expected_latency = 6.0
    timeout = 15.0  # cond 4: <= 15 s
    min_interval = 1.0
    cache_ttl = 86400
    error_markers = (PYPI_CHALLENGE,)
    default_enabled = True
    max_pivots = 60
    settings = {CONFIRMED_SETTING: [], MEMBERS_SETTING: False}

    def run(self, entity: Entity, ctx: Any) -> ModuleResult:
        res = self.result(entity)
        refused = _seed_gate(self, entity, ctx)
        if refused:
            return res.mark("skipped", refused, reason_code="own_asset")
        fp = _Footprint(self, ctx, res, budget=self.max_requests)
        stopped = fp.run(entity)
        _record_inventory(res, fp)
        res.raw = {"orgs": [_org_view(o) for o in fp.orgs], "answered": sorted(fp.answered), "failed": sorted(fp.failures)}
        if stopped:
            res.stop(stopped)
        if fp.orgs:
            return res
        if not fp.answered and fp.failures:
            raise next(iter(fp.failures.values()))  # no provider answered: could not verify
        if fp.failures:
            res.error = f"no organisation found on the providers that answered; could not verify: {', '.join(sorted(fp.failures))}"
        return res.mark("empty")


# ---------------------------------------------------------------------------------------------
# deep preset: secret scan of the confirmed organisations' public repositories (cond 5-7)
# ---------------------------------------------------------------------------------------------


def _fingerprint(masked: dict[str, Any]) -> dict[str, Any]:
    """cond 6: a keyed fingerprint and at most the first 4 characters (never the last ones, never the value)."""
    from v3lum.core import hmacid

    display = str(masked.get("display") or "")
    prefix = display.split("…", 1)[0][:4] if "…" in display else ""
    digest = masked.get("sha256")
    fingerprint = hmacid.hmac_hex("secret", str(digest))[:16] if isinstance(digest, str) and digest else None
    return {"prefix": prefix or None, "fingerprint": fingerprint}


@register
class OrgCodeSecrets(Module):
    name = "org_code_secrets"
    title = "Organisation repositories secret scan (deep)"
    description = (
        "Deep preset: the current tree of each confirmed organisation's public repositories (GitHub, GitLab, Codeberg) is "
        "streamed in memory through the gitleaks rules; secrets are reported by type, file and line with a keyed fingerprint."
    )
    category = "company_org"
    accepts = {T.ORG, T.DOMAIN, T.USERNAME, T.KEYWORD}
    produces = frozenset()
    run_on = "seeds"
    tags = {"slow"}
    reference = "https://github.com/gitleaks/gitleaks"
    notice = (
        "Secrets are never tested, validated or used (Codigo Penal art. 154-A): only type, file, commit, line and a keyed "
        "fingerprint with at most 4 characters are kept. Third-party secrets go to the disclosure workflow, not shared reports. "
        "No git binary; archives are streamed in memory and never written to disk or executed."
    )
    terms = "key-terms"
    opsec = Opsec.PASSIVE
    disclosure = "third_party"
    provider = "github"
    sources = (SRC_GH, SRC_GH_ARCHIVE, SRC_GL, SRC_GL_ARCHIVE, SRC_CB)
    hosts = ("api.github.com", "codeload.github.com", "gitlab.com", "codeberg.org")
    access_model = "free_noauth_limited"
    optional_keys = ("github",)
    max_requests = 40  # discovery (cache hits after the inventory) + at most 30 archives
    expected_latency = 90.0
    timeout = 600.0  # cond 5: its own time budget
    min_interval = 2.0  # one archive at a time per host, politely
    cache_ttl = 86400  # API answers only: archive bodies are fetched with ttl 0
    default_enabled = False  # cond 5: deep preset or -M only
    max_pivots = 0

    def run(self, entity: Entity, ctx: Any) -> ModuleResult:
        from v3lum.modules.utility.secret_scanner import scan_text

        res = self.result(entity)
        refused = _seed_gate(self, entity, ctx)
        if refused:
            return res.mark("skipped", refused, reason_code="own_asset")
        own_seed = _own_seed(entity, ctx)
        fp = _Footprint(self, ctx, res, budget=8, forges_only=True)
        fp.run(entity)
        confirmed = [o for o in fp.orgs if o["state"] == "confirmed"]
        if not confirmed:
            if not fp.answered and fp.failures:
                raise next(iter(fp.failures.values()))
            res.error = "no confirmed organisation: secrets are scanned only in org-confirmed repositories (P359 cond 2)"
            return res.mark("empty")
        summary: dict[str, Any] = {"repos_scanned": 0, "repos_skipped": [], "files_scanned": 0, "secrets": 0}
        repos = [(org, item) for org in confirmed for item in select_repos(org.get("repos") or [])["deep"]][:INVENTORY_MAX_REPOS]
        for index, (org, (repo, eligible, why)) in enumerate(repos, 1):
            if not eligible:
                summary["repos_skipped"].append({"repo": repo.get("full_name"), "reason": why})
                continue
            if ctx.cancelled() or (ctx.remaining() is not None and ctx.remaining() < 10):
                summary["repos_skipped"].append({"repo": repo.get("full_name"), "reason": "time_budget"})
                res.stop("deadline")
                continue
            target = archive_url(repo)
            if target is None or target[1] not in fp.allowed:
                summary["repos_skipped"].append({"repo": repo.get("full_name"), "reason": "no_archive_source"})
                continue
            if ctx.http.requests >= self.max_requests:
                summary["repos_skipped"].append({"repo": repo.get("full_name"), "reason": "request_cap"})
                res.stop("request_cap")
                continue
            ctx.log(f"org_code_secrets: scanning {repo['full_name']} ({index}/{len(repos)})")
            scanned = self._scan_repo(ctx, res, org, repo, target, scan_text, summary, own_seed=own_seed)
            if scanned:
                summary["repos_scanned"] += 1
        res.attr("code_secret_scan", summary)
        res.raw = {"orgs": [_org_view(o) for o in confirmed], "scan": summary}
        if summary["repos_scanned"] == 0 and not res.findings:
            res.error = "no repository could be scanned: " + "; ".join(f"{s['repo']}: {s['reason']}" for s in summary["repos_skipped"][:5])
            return res.mark("empty")
        return res

    def _scan_repo(self, ctx: Any, res: ModuleResult, org: dict[str, Any], repo: dict[str, Any], target: tuple[str, str],
                   scan_text: Any, summary: dict[str, Any], *, own_seed: bool) -> bool:
        url, source = target
        try:
            resp = ctx.http.get(url, source=source, ttl=0, max_bytes=MAX_REPO_BYTES, headers={"Accept": "application/gzip"})
            ctx.http.check(resp)
        except _SOFT_FAILURES as exc:
            summary["repos_skipped"].append({"repo": repo["full_name"], "reason": f"could not download ({type(exc).__name__})"})
            return False
        if getattr(resp, "truncated", False):
            summary["repos_skipped"].append({"repo": repo["full_name"], "reason": "over_50mb"})
            return False
        unpacked = scan_archive_members(bytes(resp.content or b""))
        del resp  # the archive is dropped as soon as its members are read (cond 5)
        if unpacked["error"] and not unpacked["files"]:
            summary["repos_skipped"].append({"repo": repo["full_name"], "reason": unpacked["error"]})
            return False
        commit = unpacked["commit"] or repo.get("default_branch") or "HEAD"
        items: list[dict[str, Any]] = []
        for member in unpacked["files"]:
            summary["files_scanned"] += 1
            found = scan_text(member["text"], path=member["path"])
            for hit in found.get("findings") or []:
                if hit.get("generic"):
                    continue  # entropy-only matches are counted by secret_scanner, never reported here
                masked = hit.get("masked") or {}
                fp = _fingerprint(masked) if masked.get("kind") != "password" else {"prefix": None, "fingerprint": None}
                for loc in hit.get("locations") or []:
                    items.append({"type": hit.get("rule_id"), "file": member["path"], "commit": commit, "line": loc.get("line"), **fp})
            member["text"] = ""  # nothing of the file content survives the loop
        if not items:
            return True
        summary["secrets"] += len(items)
        # the own organisation: an own seed, or an organisation whose website is an org_profile domain (cond 6)
        own = own_seed or str(org.get("basis", "")).startswith("website_host")
        title = f"Secrets in public repository {repo['full_name']}"
        res.finding(
            title,
            "high" if own else "medium",
            f"{len(items)} secret candidate(s) in the current tree of {repo['full_name']} ({SECRET_WORDING}). "
            + ("Notify the owning team to revoke and rotate them; never validate or use them."
               if own else "A third party's repository: route this to the disclosure workflow, not to shared reports."),
            confidence="probable",
            criterion=f"gitleaks rule matches (secret_scanner, P312) in the {repo['provider']} archive of the default branch; "
            f"values reduced to a keyed fingerprint and at most 4 characters; {SECRET_WORDING}",
            data={"repo": repo["full_name"], "commit": commit, "items": items[:100], "validated": False, "wording": SECRET_WORDING},
            tags=["credential_exposure"] if own else ["credential_exposure", "third_party_disclosure"],
            references=[repo["url"]] if repo.get("url") else [],
            source=SRC_GH_ARCHIVE if repo["provider"] == "github" else (SRC_GL_ARCHIVE if repo["provider"] == "gitlab" else SRC_CB),
            key=repo["full_name"],
        )
        return True


