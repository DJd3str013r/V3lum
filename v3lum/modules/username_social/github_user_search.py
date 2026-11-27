"""GitHub user search by person name: POSSIBLE candidate accounts, never auto-expanded (P111 cond 2).

The person_name path of P111, split into this opt-in module because A3 forbids default person_name
source modules (``default_enabled = False``): REST ``api.github.com/search/users`` only, never the
github.com/search HTML page (GitHub AUP s.7). Results are POSSIBLE candidates pivoted with
``expand=False`` (a shared name never proves identity); they wait for the analyst. It runs on
analyst-typed names only (``run_on='seeds'``) through the shared GitHub client and budget of
github_user (search 10 requests/min keyless, 30/min with the key ``github``).
"""

from __future__ import annotations

import re
from typing import Any

from v3lum.core.entities import Entity
from v3lum.core.entities import EntityType as T
from v3lum.core.models import ModuleResult, Opsec
from v3lum.core.module import Module, register
from v3lum.modules.username_social.github_user import (
    API_HOST,
    PROVIDER,
    SEARCH_TTL,
    SOURCE_SEARCH,
    GitHubClient,
    parse_github_search_users,
)

MAX_CANDIDATES = 10
CANDIDATE_NOTE = "GitHub name-search candidate: a shared name does not prove identity (analyst selection required)"


def search_query(name: str) -> str | None:
    """The /search/users ``q`` for a person name: the quoted name in the profile name field, users only."""
    if not isinstance(name, str):
        return None
    clean = re.sub(r"[\"\\]", " ", name)
    clean = re.sub(r"\b(?:in|type|repos|followers|location|language|created|fullname|user|org|is):\S*", " ", clean, flags=re.I)
    clean = " ".join(clean.split())[:100]
    if len(clean) < 3:
        return None
    return f'"{clean}" in:name type:user'


@register
class GithubUserSearch(Module):
    name = "github_user_search"
    title = "GitHub user search (person name)"
    description = (
        "Opt-in: GitHub REST /search/users for an analyst-typed person name; candidate accounts are POSSIBLE and never "
        "auto-expanded (same name does not prove identity)."
    )
    category = "username_social"
    accepts = {T.PERSON}
    produces = {T.SOCIAL_ACCOUNT}
    run_on = "seeds"
    terms = "key-terms"
    opsec = Opsec.PASSIVE
    disclosure = "third_party"
    provider = PROVIDER
    sources = (SOURCE_SEARCH,)
    hosts = (API_HOST,)
    access_model = "free_noauth_limited"
    optional_keys = ("github",)
    max_requests = 1
    expected_latency = 1.5
    min_interval = 1.0  # the search budget (10/min keyless) is enforced through X-RateLimit-Remaining
    cache_ttl = SEARCH_TTL
    default_enabled = False  # P111 cond 2 / A3: person_name inputs are never default
    reference = "https://docs.github.com/en/rest/search/search#search-users"
    tags = {"free"}
    notice = (
        "Opt-in person-name search (A3): candidates are POSSIBLE and never expanded automatically. GitHub API terms are "
        "key-terms; personal_data_review comes before any use beyond explicit selection."
    )

    def applies(self, entity: Entity, ctx: Any) -> bool:
        return search_query(entity.value) is not None

    def run(self, entity: Entity, ctx: Any) -> ModuleResult:
        res = self.result(entity)
        query = search_query(entity.value)
        if query is None:
            return res.mark("skipped", "name too short for a search", reason_code="not_applicable")
        client = GitHubClient(ctx, source=SOURCE_SEARCH)
        data = client.api_json("/search/users", params={"q": query, "per_page": MAX_CANDIDATES}, resource="search",
                               ttl=SEARCH_TTL, absent=frozenset())
        parsed = parse_github_search_users(data, max_candidates=MAX_CANDIDATES)
        if not parsed["ok"]:
            return res.mark("error", f"unexpected GitHub search answer ({parsed['reason']}): could not verify")
        cands = parsed["candidates"]
        res.raw = {"query": query, "total_count": parsed["total_count"], "incomplete": parsed["incomplete"],
                   "candidates": [{"handle": c["handle"], "id": c["id"], "type": c["type"]} for c in cands]}
        if parsed["incomplete"]:
            res.error = "GitHub search incomplete (timed out on GitHub's side): partial candidates"
        if not cands:
            return res.mark("empty")
        res.attr("name_search", {"query": query, "total_count": parsed["total_count"], "incomplete": parsed["incomplete"],
                                 "candidates": cands})
        for c in cands:
            res.pivot(T.SOCIAL_ACCOUNT, f"github:{c['handle']}", "name_search_candidate", confidence="possible", expand=False,
                      note=CANDIDATE_NOTE)
        res.finding(
            "GitHub accounts matching the name (candidates)",
            "info",
            f"{len(cands)} of {parsed['total_count']} account(s) whose profile name matches: "
            + ", ".join(c["handle"] for c in cands) + ". Candidates only: verify identifiers before linking.",
            confidence="possible",
            criterion="profile name field matches the typed person name (GitHub search): weak identity signal",
            data={"candidates": [c["handle"] for c in cands], "total_count": parsed["total_count"]},
            tags=["account", "weak_signal"],
            source=SOURCE_SEARCH,
        )
        return res
