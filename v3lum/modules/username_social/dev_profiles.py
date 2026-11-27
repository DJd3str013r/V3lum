"""Developer platform enrichers (P100 ``dev_profiles_pack``): one module per platform (cond 1).

* ``npm_maintainer``: registry.npmjs.org/-/v1/search?text=maintainer:{u} (200 with total 0 = ABSENT).
* ``pypi_package``: pypi.org/pypi/{package}/json, only for package names already in the case (an
  analyst-typed keyword or a pypi.org/project/<name> URL; PyPI has no user API).
* ``codeberg_user``: codeberg.org/api/v1/users/{u} (404 = ABSENT); self-hosted Gitea/Forgejo instances
  are target infrastructure and never contacted (cond 4).
* ``devto_user``: dev.to/api/users/by_username?url={u} (404 = ABSENT).
* ``huggingface_user``: huggingface.co/api/users/{u}/overview (404 = ABSENT; joins the pack now that
  trimmed found + absent fixtures exist, cond 1).

HackerOne is not in this build (cond 2: undocumented internal GraphQL endpoint, terms 'unknown', no
fixture); docs/backlog/p2-G05-1.md keeps it. pypi.org/user/* and www.npmjs.com/~{u} are never fetched
(cond 4): a challenge anywhere (error-in-200 included) is BLOCKED 'challenge' through the core P321
classifier, never ABSENT and never bypassed. Seeds only (``run_on='seeds'``, cond 5). Only the e-mail of
the investigated account's own record is kept (PROBABLE only when already a case e-mail, else POSSIBLE,
expand=False, never auto-sent to breach/stealer modules); co-maintainer, co-author and organisation
e-mails are counted, never stored (cond 6). One summary row per platform (cond 7). The npm, PyPI and
Codeberg parsers live in ``dev_registries`` and are shared with org_code_footprint (P359, cond 8).
"""

from __future__ import annotations

from typing import Any

from v3lum.core.entities import Entity
from v3lum.core.entities import EntityType as T
from v3lum.core.models import ModuleResult, Opsec
from v3lum.core.module import Module, register
from v3lum.modules.username_social.dev_registries import (
    SOURCE_CODEBERG,
    SOURCE_DEVTO,
    SOURCE_HF,
    SOURCE_NPM,
    SOURCE_PYPI,
    account_handle,
    case_emails,
    case_logins,
    case_usernames,
    codeberg_user_url,
    devto_declared_links,
    devto_user_url,
    emit_seed_emails,
    hf_overview_url,
    npm_search_url,
    parse_codeberg_user,
    parse_devto_user,
    parse_hf_overview,
    parse_npm_search,
    parse_pypi_package,
    pypi_json_url,
    pypi_package_of,
)

MAX_PACKAGES_LISTED = 20
MAX_PROJECT_URLS = 10
_PLATFORM_URLS = {"github": "https://github.com/{}", "x": "https://x.com/{}"}


class _DevProfile(Module):
    """Shared declarations of the P100 adapters (abstract: no ``name``, never registered)."""

    category = "username_social"
    produces = frozenset({T.EMAIL, T.URL, T.USERNAME})
    run_on = "seeds"  # P100 cond 5: analyst-typed usernames or platform-qualified accounts in the case
    terms = "open"
    opsec = Opsec.PASSIVE
    disclosure = "third_party"
    access_model = "free_noauth_limited"
    max_requests = 1
    expected_latency = 1.0
    timeout = 10.0
    min_interval = 1.0
    cache_ttl = 86400
    max_pivots = 40
    default_enabled = True
    tags = frozenset({"free"})
    platform = ""

    def handle_of(self, entity: Entity) -> str | None:
        return account_handle(entity, self.platform)

    def applies(self, entity: Entity, ctx: Any) -> bool:
        return self.handle_of(entity) is not None

    @staticmethod
    def found_finding(res: ModuleResult, platform: str, handle: str, summary: dict[str, Any], source: str, url: str, extra: str = "") -> None:
        created = f", created {summary['created'][:10]}" if summary.get("created") else ""
        res.finding(
            f"Account on {platform}",
            "info",
            f"{platform} account {handle}{created}{extra}. Same handle elsewhere does not prove the same person; "
            "self-published fields are case-bound.",
            confidence="confirmed",
            criterion=f"{platform} API answered with the account object",
            data={"summary": summary},
            tags=["account"],
            references=[url],
            source=source,
        )


# ======================================================================================
# npm
# ======================================================================================


@register
class NpmMaintainer(_DevProfile):
    name = "npm_maintainer"
    title = "npm packages maintained by a username"
    description = (
        "Packages the npm registry lists for maintainer:{username} (registry search API, keyless): summary row, top packages "
        "and the account's own maintainer e-mail; co-maintainers are counted, never listed."
    )
    accepts = frozenset({T.USERNAME, T.SOCIAL_ACCOUNT, T.URL})
    provider = "npm"
    sources = (SOURCE_NPM,)
    hosts = ("registry.npmjs.org",)
    expected_latency = 0.5
    reference = "https://github.com/npm/registry/blob/main/docs/REGISTRY-API.md"
    notice = (
        "npm registry metadata contains maintainers' personal e-mails: only the investigated account's own address is kept "
        "(PROBABLE only when already in the case), co-maintainers are counted. www.npmjs.com/~user is behind a Cloudflare "
        "challenge and is never fetched. personal_data_review comes before default use."
    )
    platform = "npm"

    def handle_of(self, entity: Entity) -> str | None:
        handle = account_handle(entity, "npm")
        return handle if handle and npm_search_url(handle) else None

    def run(self, entity: Entity, ctx: Any) -> ModuleResult:
        res = self.result(entity)
        handle = self.handle_of(entity)
        url = npm_search_url(handle) if handle else None
        if not handle or not url:
            return res.mark("skipped", "not an npm username", reason_code="not_applicable")
        handle = handle.lower()
        data = ctx.http.get_json(url, source=SOURCE_NPM)
        parsed = parse_npm_search(data, handle, case_emails(ctx, entity))
        if not parsed["ok"]:
            return res.mark("error", f"unexpected npm registry answer ({parsed['reason']}): could not verify")
        profile = f"https://www.npmjs.com/~{handle}"
        res.raw = {"handle": handle, "total": parsed["total"], "packages": len(parsed["packages"]), "counted": parsed["counted"]}
        if not parsed["packages"]:
            if parsed["total"] == 0:
                res.presence("absent", marker="HTTP 200 {objects: [], total: 0} from the maintainer search", url=url,
                             checked_at=ctx.now(), source=SOURCE_NPM)
                res.error = "no npm packages maintained by this username"
            else:
                res.presence("unknown", url=url, checked_at=ctx.now(), source=SOURCE_NPM)
                res.error = f"the search returned {parsed['total']} package(s) but none lists {handle} as maintainer or publisher"
                res.attr("third_party_counts", parsed["counted"])
            return res.mark("empty")
        res.presence("found", marker="npm maintainer search lists the username on its packages", url=url, checked_at=ctx.now(),
                     source=SOURCE_NPM)
        res.attr("platform_summary", parsed["summary"])
        res.attr("registry_packages", parsed["packages"][:MAX_PACKAGES_LISTED])
        res.attr("third_party_counts", parsed["counted"])
        res.attr("profile_url", profile)
        res.link("npm profile (Cloudflare challenge: manual only)", profile)
        res.pivot(T.URL, profile, "has_account", confidence="confirmed", expand=False, note="npm profile page (never fetched: challenge)")
        emit_seed_emails(res, parsed["emails"], platform="npm")
        top = ", ".join(p["name"] for p in parsed["packages"][:5])
        self.found_finding(res, "npm", handle, parsed["summary"], SOURCE_NPM, url,
                           f": {len(parsed['packages'])} package(s) in the first result page ({top})")
        return res


# ======================================================================================
# PyPI
# ======================================================================================


@register
class PypiPackage(_DevProfile):
    name = "pypi_package"
    title = "PyPI package metadata"
    description = (
        "PyPI JSON metadata of a package already in the case (typed keyword or pypi.org/project URL): releases, organisation, "
        "project URLs and the e-mail of a case username's own author record; other addresses are counted."
    )
    accepts = frozenset({T.KEYWORD, T.URL})
    produces = frozenset({T.EMAIL, T.URL})
    provider = "pypi"
    sources = (SOURCE_PYPI,)
    hosts = ("pypi.org",)
    absent_statuses = frozenset({404})  # package not found
    expected_latency = 0.3
    manual_link = "https://pypi.org/project/{q}/"
    reference = "https://docs.pypi.org/api/json/"
    notice = (
        "PyPI has no user API and pypi.org/user/* is behind a JS challenge: never fetched. Author/maintainer e-mails are "
        "kept only when a case username holds a PyPI role on the package and the address is that user's own; personal_data_review "
        "comes before default use."
    )
    platform = "pypi"

    def handle_of(self, entity: Entity) -> str | None:
        return pypi_package_of(entity)

    def run(self, entity: Entity, ctx: Any) -> ModuleResult:
        res = self.result(entity)
        package = pypi_package_of(entity)
        url = pypi_json_url(package) if package else None
        if not package or not url:
            return res.mark("skipped", "not a PyPI package name or project URL", reason_code="not_applicable")
        data = ctx.http.get_json(url, source=SOURCE_PYPI)
        project_page = f"https://pypi.org/project/{package}/"
        if data is None:  # 404: documented absence of the package
            res.presence("absent", marker="HTTP 404 Not Found from pypi.org/pypi/<package>/json", url=project_page,
                         checked_at=ctx.now(), source=SOURCE_PYPI)
            res.error = "PyPI package not found"
            return res.mark("empty")
        seeds = sorted(case_usernames(ctx, entity, "pypi"))
        parsed = parse_pypi_package(data, seeds, case_emails(ctx, entity))
        if not parsed["ok"]:
            return res.mark("error", f"unexpected PyPI answer ({parsed['reason']}): could not verify")
        res.raw = {"package": parsed["name"], "release_count": parsed["release_count"], "counted": parsed["counted"]}
        res.presence("found", marker="HTTP 200 package JSON", url=project_page, checked_at=ctx.now(), source=SOURCE_PYPI)
        res.attr("pypi_project", {k: parsed[k] for k in ("name", "version", "summary_text", "first_release", "last_release",
                                                         "release_count", "organization", "seed_role", "role_count")}
                 | {"project_urls": parsed["project_urls"][:MAX_PROJECT_URLS]})
        res.attr("platform_summary", parsed["summary"])
        res.attr("third_party_counts", parsed["counted"])
        res.attr("created", parsed["first_release"])
        res.attr("updated", parsed["last_release"])
        res.link("PyPI project page", project_page)
        for item in parsed["project_urls"][:MAX_PROJECT_URLS]:
            res.pivot(T.URL, item["url"], "project_url", confidence="probable", expand=False,
                      note=f"'{item['label'] or 'URL'}' declared in the PyPI metadata of {parsed['name'] or package}")
        emit_seed_emails(res, parsed["emails"], platform="pypi")
        role = f"; case username {parsed['seed']} holds role {parsed['seed_role']}" if parsed["seed_role"] else ""
        res.finding(
            "PyPI package metadata",
            "info",
            f"{parsed['name'] or package} {parsed['version'] or ''}: {parsed['release_count']} release(s) since "
            f"{(parsed['first_release'] or '?')[:10]}{', organisation ' + parsed['organization'] if parsed['organization'] else ''}{role}.",
            confidence="confirmed",
            criterion="pypi.org JSON API answered with the package object",
            data={"summary": parsed["summary"]},
            tags=["account"],
            references=[project_page],
            source=SOURCE_PYPI,
        )
        return res


# ======================================================================================
# Codeberg
# ======================================================================================


@register
class CodebergUser(_DevProfile):
    name = "codeberg_user"
    title = "Codeberg user"
    description = (
        "Codeberg (Forgejo) public user profile from codeberg.org/api/v1/users/{username}: creation date, website, counts and "
        "the account's own public e-mail (noreply placeholders dropped)."
    )
    accepts = frozenset({T.USERNAME, T.SOCIAL_ACCOUNT, T.URL})
    provider = "codeberg"
    sources = (SOURCE_CODEBERG,)
    hosts = ("codeberg.org",)
    absent_statuses = frozenset({404})  # 'user redirect does not exist'
    expected_latency = 0.9
    manual_link = "https://codeberg.org/{user}"
    reference = "https://codeberg.org/api/swagger"
    notice = (
        "codeberg.org only: self-hosted or corporate Gitea/Forgejo instances are target infrastructure and never contacted. "
        "personal_data_review comes before default use."
    )
    platform = "codeberg"

    def handle_of(self, entity: Entity) -> str | None:
        handle = account_handle(entity, "codeberg")
        return handle if handle and codeberg_user_url(handle) else None

    def run(self, entity: Entity, ctx: Any) -> ModuleResult:
        res = self.result(entity)
        handle = self.handle_of(entity)
        url = codeberg_user_url(handle) if handle else None
        if not handle or not url:
            return res.mark("skipped", "not a Codeberg username", reason_code="not_applicable")
        profile = f"https://codeberg.org/{handle}"
        data = ctx.http.get_json(url, source=SOURCE_CODEBERG)
        if data is None:
            res.presence("absent", marker="HTTP 404 'user redirect does not exist' from codeberg.org/api/v1/users", url=profile,
                         checked_at=ctx.now(), source=SOURCE_CODEBERG)
            res.error = "no Codeberg account with this username"
            return res.mark("empty")
        parsed = parse_codeberg_user(data, handle, case_emails(ctx, entity))
        if not parsed["ok"]:
            return res.mark("error", f"unexpected Codeberg answer ({parsed['reason']}): could not verify")
        profile = f"https://codeberg.org/{parsed['login']}"
        res.raw = {"login": parsed["login"], "id": parsed["id"], "email_hidden": parsed["email_hidden"]}
        res.presence("found", marker="HTTP 200 user object", url=profile, checked_at=ctx.now(), source=SOURCE_CODEBERG)
        res.attr("account_id", parsed["id"])
        res.attr("display_name", parsed["full_name"])
        res.attr("bio", parsed["description"])
        res.attr("location", parsed["location"])
        res.attr("website", parsed["website"])
        res.attr("followers", parsed["followers"])
        res.attr("following", parsed["following"])
        res.attr("created", parsed["created"])
        res.attr("profile_url", profile)
        res.attr("platform_summary", parsed["summary"])
        res.pivot(T.URL, profile, "has_account", confidence="confirmed", expand=False, note="Codeberg profile of the account")
        if parsed["website"]:
            res.pivot(T.URL, parsed["website"], "link_on_profile", confidence="probable", expand=False,
                      note="website declared on the Codeberg profile (self-published, case-bound)")
        emit_seed_emails(res, parsed["emails"], platform="codeberg", relation="email_on_profile")
        self.found_finding(res, "Codeberg", parsed["login"], parsed["summary"], SOURCE_CODEBERG, profile)
        return res


# ======================================================================================
# DEV (Forem)
# ======================================================================================


@register
class DevtoUser(_DevProfile):
    name = "devto_user"
    title = "DEV Community user"
    description = (
        "DEV (Forem) public user from dev.to/api/users/by_username: joined date, website and the GitHub/X logins the owner "
        "declared (PROBABLE when equal to a login already linked to the seed)."
    )
    accepts = frozenset({T.USERNAME, T.SOCIAL_ACCOUNT, T.URL})
    produces = frozenset({T.URL, T.SOCIAL_ACCOUNT})
    provider = "dev_to"
    sources = (SOURCE_DEVTO,)
    hosts = ("dev.to",)
    absent_statuses = frozenset({404})
    expected_latency = 0.5
    manual_link = "https://dev.to/{user}"
    reference = "https://developers.forem.com/api/v1"
    notice = (
        "DEV's edge may refuse scripted clients ('Forbidden Bots' 403): that is BLOCKED/challenge, never an absence, and is never "
        "retried with another user agent; use the manual link. personal_data_review comes before default use."
    )
    platform = "devto"

    def handle_of(self, entity: Entity) -> str | None:
        handle = account_handle(entity, "devto")
        return handle if handle and devto_user_url(handle) else None

    def run(self, entity: Entity, ctx: Any) -> ModuleResult:
        res = self.result(entity)
        handle = self.handle_of(entity)
        url = devto_user_url(handle) if handle else None
        if not handle or not url:
            return res.mark("skipped", "not a DEV username", reason_code="not_applicable")
        data = ctx.http.get_json(url, source=SOURCE_DEVTO)
        if data is None:
            res.presence("absent", marker="HTTP 404 from dev.to/api/users/by_username", url=f"https://dev.to/{handle}",
                         checked_at=ctx.now(), source=SOURCE_DEVTO)
            res.error = "no DEV account with this username"
            return res.mark("empty")
        parsed = parse_devto_user(data)
        if not parsed["ok"]:
            return res.mark("error", f"unexpected DEV answer ({parsed['reason']}): could not verify")
        profile = f"https://dev.to/{parsed['username']}"
        res.raw = {"username": parsed["username"], "id": parsed["id"]}
        res.presence("found", marker="HTTP 200 user object", url=profile, checked_at=ctx.now(), source=SOURCE_DEVTO)
        res.attr("account_id", parsed["id"])
        res.attr("display_name", parsed["name"])
        res.attr("bio", parsed["summary_text"])
        res.attr("location", parsed["location"])
        res.attr("website", parsed["website"])
        res.attr("created", parsed["joined"])
        res.attr("profile_url", profile)
        res.attr("platform_summary", parsed["summary"])
        res.pivot(T.URL, profile, "has_account", confidence="confirmed", expand=False, note="DEV profile of the account")
        if parsed["website"]:
            res.pivot(T.URL, parsed["website"], "link_on_profile", confidence="probable", expand=False,
                      note="website declared on the DEV profile (self-published, case-bound)")
        declared = devto_declared_links(parsed, case_logins(ctx, entity))
        if declared:
            res.attr("linked_accounts", [{"platform": d["platform"], "handle": d["handle"],
                                          "url": _PLATFORM_URLS[d["platform"]].format(d["handle"]), "source_page": profile} for d in declared])
        raised = []
        for d in declared:
            why = "equals a login already linked to the seed (Ceos rule)" if d["raises_existing_link"] else "self-declared, not yet linked"
            res.pivot(T.SOCIAL_ACCOUNT, f"{d['platform']}:{d['handle']}", "linked_account_on_profile", confidence=d["confidence"],
                      expand=False, note=f"{d['platform']} login declared on the DEV profile ({why})")
            if d["raises_existing_link"]:
                raised.append(f"{d['platform']}:{d['handle']}")
        if raised:
            res.finding(
                "DEV profile declares an account already linked to the seed",
                "info",
                f"The DEV account {parsed['username']} declares {', '.join(raised)}, which the case already links to the seed: "
                "the link is raised to PROBABLE.",
                confidence="probable",
                criterion="DEV github_username/twitter_username equals a platform-qualified login already in the case (Ceos rule)",
                data={"accounts": raised},
                tags=["identity"],
                references=[profile],
                source=SOURCE_DEVTO,
            )
        self.found_finding(res, "DEV", parsed["username"], parsed["summary"], SOURCE_DEVTO, profile)
        return res


# ======================================================================================
# Hugging Face
# ======================================================================================


@register
class HuggingfaceUser(_DevProfile):
    name = "huggingface_user"
    title = "Hugging Face user"
    description = (
        "Hugging Face Hub public user overview (huggingface.co/api/users/{username}/overview): creation date, model/dataset/space "
        "counts and organisation memberships."
    )
    accepts = frozenset({T.USERNAME, T.SOCIAL_ACCOUNT, T.URL})
    produces = frozenset({T.URL})
    provider = "huggingface"
    sources = (SOURCE_HF,)
    hosts = ("huggingface.co",)
    absent_statuses = frozenset({404})  # {'error': 'This user does not exist'}
    expected_latency = 0.3
    manual_link = "https://huggingface.co/{user}"
    reference = "https://huggingface.co/docs/hub/api"
    notice = "Anonymous Hub limits are shared by the egress IP (about 500 requests per 5 minutes). personal_data_review comes before default use."
    platform = "huggingface"

    def handle_of(self, entity: Entity) -> str | None:
        handle = account_handle(entity, "huggingface")
        return handle if handle and hf_overview_url(handle) else None

    def run(self, entity: Entity, ctx: Any) -> ModuleResult:
        res = self.result(entity)
        handle = self.handle_of(entity)
        url = hf_overview_url(handle) if handle else None
        if not handle or not url:
            return res.mark("skipped", "not a Hugging Face username", reason_code="not_applicable")
        data = ctx.http.get_json(url, source=SOURCE_HF)
        if data is None:
            res.presence("absent", marker="HTTP 404 'This user does not exist' from huggingface.co/api/users", url=f"https://huggingface.co/{handle}",
                         checked_at=ctx.now(), source=SOURCE_HF)
            res.error = "no Hugging Face user with this name"
            return res.mark("empty")
        parsed = parse_hf_overview(data)
        if not parsed["ok"]:
            return res.mark("error", f"unexpected Hugging Face answer ({parsed['reason']}): could not verify")
        profile = f"https://huggingface.co/{parsed['user']}"
        res.raw = {"user": parsed["user"], "type": parsed["type"], "models": parsed["models"]}
        res.presence("found", marker="HTTP 200 user overview", url=profile, checked_at=ctx.now(), source=SOURCE_HF)
        res.attr("display_name", parsed["fullname"])
        res.attr("account_type", parsed["type"])
        res.attr("bio", parsed["details"])
        res.attr("created", parsed["created"])
        res.attr("followers", parsed["followers"])
        res.attr("following", parsed["following"])
        res.attr("organizations", parsed["orgs"])
        res.attr("profile_url", profile)
        res.attr("platform_summary", parsed["summary"])
        res.pivot(T.URL, profile, "has_account", confidence="confirmed", expand=False, note="Hugging Face profile of the account")
        counts = f": {parsed['models'] or 0} model(s), {parsed['datasets'] or 0} dataset(s), {parsed['spaces'] or 0} space(s)"
        self.found_finding(res, "Hugging Face", parsed["user"], parsed["summary"], SOURCE_HF, profile, counts)
        return res
