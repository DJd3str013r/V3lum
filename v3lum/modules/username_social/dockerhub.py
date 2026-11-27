"""Docker Hub users, organisations, repositories and image-label e-mails (P102).

* hub.docker.com v2 API only (cond 1): ``users/{u}/`` (an organisation answers 308 -> ``orgs/{o}``, which
  the core follows on the same declared host), ``repositories/{ns}/?page_size=5&ordering=last_updated``
  (one page), the newest tag of each repository and its ``tags/{tag}/images`` (layer instructions).
  registry-1.docker.io / auth.docker.io are never contacted and layers are never pulled or run (cond 2:
  anonymous pull limits are shared by the corporate NAT and its CI; untrusted content).
* Caps (cond 3): <= 5 repositories (most recent), latest tag only, one page; ``max_requests = 10`` keeps
  the module default-eligible (A3), so 3 or 4 repositories are inspected and the run is marked partial
  (stop reason ``request_cap``) when more were listed; ``x-ratelimit-remaining`` is honoured (no new
  request when 5 or fewer remain: partial, stop reason ``rate_limited``); 404 'User not found' = ABSENT;
  429 = RATE_LIMITED; cache 7 days.
* LABEL/MAINTAINER e-mails (cond 4) are PROBABLE only when equal to a case e-mail or on the account's own
  verified domain (an org-profile txt_verified/attested domain); every other address is discarded
  (counted only); labels inherited from base images (up to the base-image boundary, official
  maintainers) are ignored.
* Secrets in layer instructions (cond 5) pass the core P145/P323 detectors: type + first 4/last 4 +
  SHA-256 only (passwords and URL credentials: type only), never validated or used; one exposure finding
  per repo:tag with the instruction indexes, severity by type, high only for org_profile-confirmed
  accounts. Personal identifiers are pivots with expand=False, never sent to breach/stealer modules.
"""

from __future__ import annotations

from typing import Any
from urllib.parse import urlsplit

from v3lum.core.entities import Entity
from v3lum.core.entities import EntityType as T
from v3lum.core.models import ModuleResult, Opsec, Status
from v3lum.core.module import Module, register
from v3lum.modules.username_social.dev_registries import (
    SOURCE_DOCKERHUB,
    attempt,
    case_emails,
    dockerhub_namespace_of,
    dockerhub_urls,
    is_generic_email,
    parse_dockerhub_account,
    parse_dockerhub_images,
    parse_dockerhub_repositories,
    parse_dockerhub_tags,
    rate_remaining,
    report_problems,
)

RATE_RESERVE = 5  # stop issuing requests when x-ratelimit-remaining <= 5 (cond 3, shared NAT budget)
REQUESTS_PER_REPO = 2  # newest tag + its images


def _get(ctx: Any, url: str) -> tuple[Any, int | None]:
    """GET one Hub API URL -> (parsed JSON or None for a 404, x-ratelimit-remaining). Classified answers,
    429 and other failures raise (could not verify)."""
    resp = ctx.http.get(url, source=SOURCE_DOCKERHUB)
    remaining = rate_remaining(resp.headers)
    if resp.status == 404 and resp.classification is None:
        return None, remaining
    ctx.http.check(resp)
    return resp.json(), remaining


def _verified(ctx: Any) -> Any:
    org = getattr(ctx, "org", None)

    def check(domain: str) -> bool:
        try:
            return bool(org is not None and org.is_verified_domain(domain))
        except Exception:  # noqa: BLE001 - a broken org profile never stops a run
            return False

    return check


@register
class Dockerhub(Module):
    name = "dockerhub"
    title = "Docker Hub account, repositories and image labels"
    description = (
        "Docker Hub v2 API: user or organisation profile, the 5 most recent public repositories, the latest tag's layer "
        "instructions (LABEL e-mails of the case only, masked secrets); registry pulls are never made."
    )
    category = "username_social"
    accepts = frozenset({T.USERNAME, T.SOCIAL_ACCOUNT, T.URL})
    produces = frozenset({T.EMAIL, T.URL, T.USERNAME})
    run_on = "seeds"
    terms = "open"
    opsec = Opsec.PASSIVE
    disclosure = "third_party"
    provider = "docker_hub"
    sources = (SOURCE_DOCKERHUB,)
    hosts = ("hub.docker.com",)
    access_model = "free_noauth_limited"
    absent_statuses = frozenset({404})  # {'message': 'User not found'}
    max_requests = 10  # account (+ org redirect) + repositories + 2 per repository (A3: <= 10)
    expected_latency = 6.0
    timeout = 30.0
    min_interval = 0.5
    cache_ttl = 604800  # cond 3: 7 days
    max_pivots = 40
    default_enabled = True
    manual_link = "https://hub.docker.com/u/{user}"
    reference = "https://docs.docker.com/reference/api/hub/latest/"
    tags = frozenset({"free"})
    notice = (
        "Hub API only: registry-1.docker.io/auth.docker.io are never contacted and layers are never pulled (the anonymous pull "
        "limit is shared by the corporate NAT). Label e-mails are kept only when they are case e-mails or on a verified own "
        "domain; secrets in layer instructions are masked and never validated. personal_data_review comes before default use."
    )

    def applies(self, entity: Entity, ctx: Any) -> bool:
        return dockerhub_namespace_of(entity) is not None

    def run(self, entity: Entity, ctx: Any) -> ModuleResult:
        res = self.result(entity)
        ns = dockerhub_namespace_of(entity)
        urls = dockerhub_urls(ns) if ns else None
        if not ns or not urls:
            return res.mark("skipped", "not a Docker ID or organisation name", reason_code="not_applicable")
        hub_page = f"https://hub.docker.com/u/{ns}"
        data, remaining = _get(ctx, urls["user"])
        if data is None:  # 404: documented absence
            res.presence("absent", marker="HTTP 404 'User not found' from hub.docker.com/v2/users", url=hub_page,
                         checked_at=ctx.now(), source=SOURCE_DOCKERHUB)
            res.error = "no Docker Hub user or organisation with this name"
            return res.mark("empty")
        acct = parse_dockerhub_account(data)
        if not acct["ok"]:
            return res.mark("error", f"unexpected Docker Hub answer ({acct['reason']}): could not verify")
        raw: dict[str, Any] = {"namespace": ns, "kind": acct["kind"]}
        res.raw = raw
        res.presence("found", marker=f"HTTP 200 {acct['kind']} object", url=hub_page, checked_at=ctx.now(), source=SOURCE_DOCKERHUB)
        self._account(res, acct, hub_page)
        verified = _verified(ctx)
        website_host = (urlsplit(acct["profile_url"]).hostname or "").lower() if acct["profile_url"] else ""
        org_confirmed = bool(website_host) and verified(website_host[4:] if website_host.startswith("www.") else website_host)
        problems: dict[str, list[tuple[Status, str, str]]] = {}
        if remaining is not None and remaining <= RATE_RESERVE:
            res.stop("rate_limited")
            res.error = f"Docker Hub rate budget nearly spent (x-ratelimit-remaining {remaining}): repositories not read"
            return res
        got = attempt(problems, SOURCE_DOCKERHUB, "repositories", lambda: _get(ctx, urls["repositories"]))
        repos: list[dict[str, Any]] = []
        if got is not None:
            repo_data, remaining = got
            parsed = parse_dockerhub_repositories(repo_data) if repo_data is not None else {"ok": True, "repos": [], "count": 0, "has_more": False}
            if not parsed["ok"]:
                problems.setdefault(SOURCE_DOCKERHUB, []).append((Status.ERROR, "error", f"repositories: {parsed['reason']}"))
            else:
                repos = parsed["repos"]
                raw["repositories"] = {"count": parsed["count"], "listed": len(repos)}
                res.attr("docker_repositories", repos)
        self._images(res, ctx, ns, repos, remaining, verified, org_confirmed, problems, raw)
        report_problems(res, problems)
        return res

    # ------------------------------------------------------------------ account
    @staticmethod
    def _account(res: ModuleResult, acct: dict[str, Any], hub_page: str) -> None:
        res.attr("account_type", acct["kind"])
        res.attr("display_name", acct["full_name"])
        res.attr("location", acct["location"])
        res.attr("company", acct["company"])
        res.attr("website", acct["profile_url"])
        res.attr("created", acct["joined"])
        res.attr("avatar_hash", acct["gravatar_hash"])  # local Gravatar hash comparison only (P114)
        res.attr("verified", True if acct["badge"] in ("verified_publisher", "official") else None)
        res.attr("profile_url", hub_page)
        res.attr("platform_summary", acct["summary"])
        res.pivot(T.URL, hub_page, "has_account", confidence="confirmed", expand=False, note="Docker Hub page of the account")
        if acct["profile_url"]:
            res.pivot(T.URL, acct["profile_url"], "link_on_profile", confidence="probable", expand=False,
                      note="website declared on the Docker Hub account (self-published, case-bound)")
        res.finding(
            "Account on Docker Hub",
            "info",
            f"Docker Hub {acct['kind']} {acct['name']}" + (f", joined {acct['joined'][:10]}" if acct["joined"] else "")
            + ". Image names and descriptions can leak internal project names.",
            confidence="confirmed",
            criterion="hub.docker.com v2 API answered with the account object",
            data={"summary": acct["summary"]},
            tags=["account"],
            references=[hub_page],
            source=SOURCE_DOCKERHUB,
        )

    # ------------------------------------------------------------------ images (cond 3-5)
    def _images(self, res: ModuleResult, ctx: Any, ns: str, repos: list[dict[str, Any]], remaining: int | None, verified: Any,
                org_confirmed: bool, problems: dict[str, Any], raw: dict[str, Any]) -> None:
        mails = case_emails(ctx, res.entity)
        images: list[dict[str, Any]] = []
        counts = {"kept": 0, "discarded": 0, "inherited": 0}
        kept: dict[str, dict[str, Any]] = {}
        exposures: list[dict[str, Any]] = []
        inspected = 0
        for repo in repos:
            if self.max_requests - int(getattr(ctx.http, "requests", 0) or 0) < REQUESTS_PER_REPO:
                res.stop("request_cap")
                break
            if remaining is not None and remaining <= RATE_RESERVE:
                res.stop("rate_limited")
                break
            urls = dockerhub_urls(ns, repo["name"])
            got = attempt(problems, SOURCE_DOCKERHUB, f"tags of {ns}/{repo['name']}", lambda u=urls["tags"]: _get(ctx, u))
            if got is None:
                continue
            tag_data, remaining = got
            latest = parse_dockerhub_tags(tag_data).get("latest") if tag_data is not None else None
            if not latest:
                continue
            urls = dockerhub_urls(ns, repo["name"], latest["name"])
            if not urls or "images" not in urls:
                continue
            if remaining is not None and remaining <= RATE_RESERVE:
                res.stop("rate_limited")
                break
            got = attempt(problems, SOURCE_DOCKERHUB, f"images of {ns}/{repo['name']}:{latest['name']}",
                          lambda u=urls["images"]: _get(ctx, u))
            if got is None:
                continue
            img_data, remaining = got
            repo_tag = f"{ns}/{repo['name']}:{latest['name']}"
            parsed = parse_dockerhub_images(img_data, repo_tag, mails, verified, org_confirmed)
            if not parsed["ok"]:
                problems.setdefault(SOURCE_DOCKERHUB, []).append((Status.ERROR, "error", f"images of {repo_tag}: {parsed['reason']}"))
                continue
            inspected += 1
            if parsed["image"]:
                images.append(parsed["image"] | {"tag_updated": latest["last_updated"], "platforms": latest["platforms"][:16]})
            for key in counts:
                counts[key] += parsed["label_counts"][key]
            for item in parsed["label_emails"]:
                kept.setdefault(item["email"], item)
            exposures += parsed["exposures"]
            if parsed["exposure"]:
                self._exposure_finding(res, parsed["exposure"], parsed["exposures"], org_confirmed)
        counts["kept"] = len(kept)
        raw["images_inspected"] = inspected
        res.attr("docker_images", images)
        if repos:
            res.attr("label_email_counts", counts)
        res.attr("layer_exposures", exposures)
        for item in kept.values():
            generic = is_generic_email(item["email"])  # A4: generic/role/test addresses are capped at POSSIBLE
            res.pivot(T.EMAIL, item["email"], "image_label_email", confidence="possible" if generic else "probable", expand=False,
                      note=f"{item['label']} label of {item['repo_tag']} (instruction {item['instruction_index']}, {item['basis']}"
                           f"{'; generic/test address' if generic else ''}); case-bound, never sent to breach/stealer modules automatically")
        if res.partial and len(repos) > inspected:
            res.error = "; ".join(x for x in (res.error, f"{inspected} of {len(repos)} listed repositories inspected (request/rate budget)") if x)

    @staticmethod
    def _exposure_finding(res: ModuleResult, exposure: dict[str, Any], entries: list[dict[str, Any]], org_confirmed: bool) -> None:
        severity = exposure["severity"]
        examples_only = all(e.get("documentation_example") for e in entries)
        res.finding(
            "Secrets in public image layer instructions",
            severity,
            f"{exposure['count']} secret(s) of kind(s) {', '.join(exposure['kinds'])} in the layer instructions of "
            f"{exposure['repo_tag']} (instructions {', '.join(str(i) for i in exposure['instruction_indexes'])}). Values are "
            "masked (type + first 4/last 4 + SHA-256; passwords type only) and were never validated or used."
            + (" Only documentation example keys were seen." if examples_only else "")
            + ("" if org_confirmed else " Severity capped at medium: the account is not confirmed by the org profile."),
            confidence="probable",
            criterion="core secret detectors (P145/P323) matched an ENV/ARG/RUN/LABEL instruction after the base-image boundary",
            data={"repo_tag": exposure["repo_tag"], "instruction_indexes": exposure["instruction_indexes"], "kinds": exposure["kinds"],
                  "validated": False, "entries": entries[:20]},
            tags=["exposure", "credential_exposure"],
            source=SOURCE_DOCKERHUB,
            key=exposure["repo_tag"] or "",
        )
