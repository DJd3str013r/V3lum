"""code_search (P305, batch p2-G14-3): Sourcegraph stream API, GitHub code search, GitLab blob search.

Fixtures in tests/fixtures/code_search/ (see _provenance.json): the Sourcegraph bodies are real captures (trimmed,
repositories renamed to example-*); the chunkMatches body and every GitHub/GitLab body are doc-shaped synthetic
fixtures (P305 cond 10: the keyed parts stay behind setting code_search_keyed_sources until real captures exist)."""

from __future__ import annotations

import json
import re

import pytest

from tests.fakes import FakeHttp, assert_no_secret, make_ctx, module_fixture, run_module
from v3lum.core.context import ScanOptions
from v3lum.core.entities import Entity
from v3lum.core.http import NetworkError
from v3lum.core.models import Status
from v3lum.core.orgprofile import OrgProfile
from v3lum.modules.search_dorks import code_search as cs
from v3lum.modules.search_dorks.code_search import CodeSearch

FIX = "tests/fixtures/code_search/"
SG = cs.sourcegraph_url("example.com")
GH = cs.github_url("example.com")
GL = cs.gitlab_url("example.com")
KEYED = {"code_search_keyed_sources": True}
GH_TOKEN = "ghp_unit_test_token_000000000000000000000"
GL_TOKEN = "glpat-unit-test-token-0000"


def body(name: str) -> bytes:
    with open(FIX + name, "rb") as fh:
        return fh.read()


def sg_route(http: FakeHttp, name: str, *, status: int = 200, url: str = SG) -> FakeHttp:
    return http.add("GET", url, status=status, body=body(name), headers={"content-type": "text/event-stream"},
                    match_headers={"accept": "text/event-stream"})


def gh_route(http: FakeHttp, name: str, *, status: int = 200, headers: dict | None = None) -> FakeHttp:
    return http.add("GET", GH, status=status, json=module_fixture("code_search", name), headers=headers,
                    match_headers={"accept": cs.GH_ACCEPT, "authorization": f"Bearer {GH_TOKEN}"})


def run(entity: str = "domain:example.com", http: FakeHttp | None = None, **kw):
    return run_module(CodeSearch, entity, http or FakeHttp(), **kw)


# ------------------------------------------------------------------ Sourcegraph (cond 1, 8, 9)
def test_sourcegraph_lines_ok_locations_only():
    http = sg_route(FakeHttp(), "sourcegraph_lines_ok.txt")
    res = run(http=http)
    assert res.status is Status.OK and res.requests == 1
    hits = res.attributes["code_search_hits"]
    assert [h["repo"] for h in hits] == ["github.com/example-org/example-app", "github.com/example-user/example-proxy"]
    assert hits[0]["hits"][0]["line"] == 144  # lineNumber 143 is 0-based
    assert all(h["severity"] == "info" and h["provenance"] == "third_party_repo" for h in hits)
    urls = {p.entity.value: p for p in res.pivots if p.entity.type.value == "url"}
    assert "https://github.com/example-org/example-app/blob/1111111111111111111111111111111111111111/config.yaml#L144" in urls
    assert all(not p.expand for p in res.pivots)
    owners = {p.entity.value for p in res.pivots if p.relation == "code_repo_owner"}
    assert owners == {"example-org", "example-user"}
    assert [f.title for f in res.findings] == ["Mentioned in public code"]
    assert res.findings[0].severity.name.lower() == "info"
    assert res.attributes["code_search_summary"]["providers"] == {cs.SOURCE_SG: "answered"}
    assert "fragments" not in json.dumps(res.raw)
    http.assert_hosts_within(CodeSearch)


def test_query_is_one_exact_quoted_phrase_with_chunk_matches():
    assert cs.sourcegraph_query("example.com") == '"example.com" type:file count:100 timeout:10s patternType:keyword'
    assert SG.endswith("&v=V3&cm=t")
    assert cs.safe_term('acme" OR repo:evil \\x') == "acme OR repo:evil x"  # quotes stripped: no operator injection
    assert cs.sourcegraph_query(cs.safe_term('x"y')) == '"x y" type:file count:100 timeout:10s patternType:keyword'


def test_raw_bodies_are_never_cached():
    http = sg_route(FakeHttp(), "sourcegraph_lines_ok.txt")
    ctx_kw = {"settings": {}}
    run(http=http, **ctx_kw)
    run(http=http, **ctx_kw)
    assert len([c for c in http.calls if "sourcegraph.com" in c["url"]]) == 2  # ttl 0: no cache hit


def test_chunk_matches_secrets_masked_provenance_and_hostnames():
    http = sg_route(FakeHttp(), "sourcegraph_chunks_ok.txt")
    res = run(http=http)
    assert res.status is Status.OK
    rows = {h["repo"]: h for h in res.attributes["code_search_hits"]}
    assert rows["github.com/example-org/example-infra"]["severity"] == "high"
    assert rows["github.com/example-org/example-infra"]["rules"] == ["password"]  # AKIAIOSFODNN7EXAMPLE is allowlisted
    assert rows["github.com/example-user/dotfiles"]["rules"] == ["private_key"]
    assert rows["github.com/example-intel/ioc-feeds"]["provenance"] == "public_ioc_repo"
    assert rows["gitlab.com/example-group/example-proxy"]["hits"][0]["link"].startswith(
        "https://gitlab.com/example-group/example-proxy/-/blob/6666666666666666666666666666666666666666/example.com.conf")
    high = [f for f in res.findings if f.severity.name.lower() == "high"]
    assert {f.data["repo"] for f in high} == {"github.com/example-org/example-infra", "github.com/example-user/dotfiles"}
    assert all("credential_exposure" in f.tags and f.criterion for f in high)
    ioc = [f for f in res.findings if f.title == "Listed in public IOC repo"]
    assert ioc and "context_only" in ioc[0].tags and ioc[0].severity.name.lower() == "info"
    assert res.attributes["code_search_hostnames"] == ["api.example.com", "build01.corp.example.com"]
    # rule 1 / cond 6: neither the secret nor the fragment is kept anywhere
    assert_no_secret("example-not-a-real-secret-0001", res.raw, res.attributes, [f.to_dict() for f in res.findings])
    assert_no_secret("PRIVATE KEY-----", res.raw, res.attributes, [f.to_dict() for f in res.findings])
    dedup = rows["github.com/example-org/example-infra"]["dedup"]
    assert len(dedup) == 1 and re.fullmatch(r"[0-9a-f]{32}", dedup[0])


def test_backend_missing_with_zero_matches_is_could_not_verify():
    res = run(http=sg_route(FakeHttp(), "sourcegraph_backend_missing_partial.txt"))
    assert res.status is Status.ERROR and "could not verify" in res.error
    assert res.source_statuses[cs.SOURCE_SG]["status"] == "error"


def test_alert_inside_http_200_is_an_error():
    res = run(http=sg_route(FakeHttp(), "sourcegraph_alert_error_in_200.txt"))
    assert res.status is Status.ERROR and "Unable To Process Query" in res.error


def test_clean_done_stream_without_matches_is_empty():
    res = run(http=sg_route(FakeHttp(), "sourcegraph_empty.txt"))
    assert res.status is Status.EMPTY and not res.findings


def test_truncated_or_malformed_stream_is_never_empty():
    res = run(http=sg_route(FakeHttp(), "sourcegraph_truncated_malformed.txt"))
    assert res.status is Status.OK  # the matches read before the cut are kept...
    assert "stream ended before the done event" in res.raw["degraded"][cs.SOURCE_SG]  # ...and the cut is recorded
    cut = b'event: progress\ndata: {"done":false,"matchCount":0,"skipped":[]}\n\nevent: matc'
    res = run(http=FakeHttp().add("GET", SG, body=cut, headers={"content-type": "text/event-stream"}))
    assert res.status is Status.ERROR and "could not verify" in res.error


def test_stream_is_read_with_the_2mb_cap():
    http = sg_route(FakeHttp(), "sourcegraph_lines_ok.txt")
    run(http=http)
    call = next(c for c in http.calls if "sourcegraph.com" in c["url"])
    assert call["max_bytes"] == cs.SSE_MAX_BYTES and call["timeout"] <= cs.SSE_DEADLINE_S


def test_challenge_page_429_5xx_and_network_errors_are_could_not_verify():
    page = (FIX + "../pivots_unverified/cloudflare_challenge_403.html")
    with open(page, encoding="utf-8") as fh:
        html = fh.read()
    res = run(http=FakeHttp().add("GET", SG, status=403, text=html))
    assert res.status is Status.BLOCKED and res.reason_code == "challenge"
    res = run(http=FakeHttp().add("GET", SG, status=429, text="Too Many Requests"))
    assert res.status is Status.RATE_LIMITED
    res = run(http=FakeHttp().add("GET", SG, status=503, text="unavailable"))
    assert res.status is Status.ERROR
    res = run(http=FakeHttp().add("GET", SG, error=NetworkError("connection reset")))
    assert res.status is Status.ERROR and res.status is not Status.EMPTY


def test_html_answer_with_200_is_never_parsed_as_empty():
    res = run(http=FakeHttp().add("GET", SG, text="<html><body>maintenance</body></html>"))
    assert res.status is Status.ERROR


# ------------------------------------------------------------------ scope and privacy (cond 3, 5)
def test_pivots_are_not_searched_unless_org_assets():
    res = run(http=FakeHttp(), is_seed=False, depth=1)
    assert res.status is Status.SKIPPED and res.reason_code == "not_applicable" and res.requests == 0


def test_org_profile_asset_pivot_is_searched_with_the_full_pack():
    org = OrgProfile.from_dict({"org": {"name": "Example Org"},
                                "domains": [{"name": "example.com", "verification": "attested",
                                             "attested_by": "analyst", "attested_date": "2026-11-20"}]})
    http = sg_route(FakeHttp(), "sourcegraph_empty.txt", url=re.compile(r"^https://sourcegraph\.com/\.api/search/stream\?"))
    res = run(http=http, is_seed=False, depth=1, org_profile=org)
    assert res.status is Status.EMPTY
    assert res.raw["full_pack"] is True and res.raw["sensitive_dorks"] is True
    assert len(res.raw["queries"]) <= cs.FULL_PACK_QUERY_CAP
    sent = [c["url"] for c in http.calls]
    assert any("password" in u for u in sent)  # verified own domain: secret-pattern dorks allowed (cond 4)


def test_secret_dorks_never_run_for_third_party_entities():
    plan = cs.plan_queries("example.com", ["sourcegraph", "github"], full_pack=True, sensitive_ok=False)
    assert plan and not any(q["sensitive"] for q in plan)
    assert len(plan) <= cs.FULL_PACK_QUERY_CAP
    default = cs.plan_queries("example.com", ["sourcegraph", "github", "gitlab"], full_pack=False, sensitive_ok=True)
    assert [q["provider"] for q in default] == ["sourcegraph", "github", "gitlab"] and not any(q["dork"] for q in default)
    full = cs.plan_queries("example.com", ["sourcegraph"], full_pack=True, sensitive_ok=True)
    assert any(q["sensitive"] for q in full)


def test_authorized_engagement_allows_secret_dorks_with_the_full_pack():
    http = sg_route(FakeHttp(), "sourcegraph_empty.txt", url=re.compile(r"^https://sourcegraph\.com/"))
    opts = ScanOptions(authorization_ref="ENG-2026-001", authorized=True)
    res = run(http=http, settings={"code_search_full_pack": True}, options=opts)
    assert res.raw["sensitive_dorks"] is True and any("password" in c["url"] for c in http.calls)


def test_usernames_and_emails_need_explicit_selection_and_purpose():
    res = run("username:example_user", FakeHttp())
    assert res.status is Status.SKIPPED and res.reason_code == "privacy" and res.requests == 0
    res = run("email:someone@example.com", FakeHttp(), options=ScanOptions(include={"code_search"}))
    assert res.status is Status.SKIPPED and res.reason_code == "privacy"
    url = cs.sourcegraph_url("example_user")
    http = sg_route(FakeHttp(), "sourcegraph_empty.txt", url=url)
    res = run("username:example_user", http, options=ScanOptions(include={"code_search"}, purpose="incident INC-1"))
    assert res.status is Status.EMPTY and res.requests == 1


def test_no_source_available_is_skipped_config():
    res = run(http=FakeHttp(), allowed_sources=[cs.SOURCE_GH])
    assert res.status is Status.SKIPPED and res.reason_code == "config"


# ------------------------------------------------------------------ GitHub (synthetic doc-shaped, cond 8, 10)
def test_github_is_off_until_enabled_even_with_a_token():
    http = sg_route(FakeHttp(), "sourcegraph_empty.txt")
    res = run(http=http, keys={"github": GH_TOKEN})
    assert res.status is Status.EMPTY and http.hosts() == {"sourcegraph.com"}


def test_github_hits_token_in_header_only_and_secret_masked():
    http = gh_route(sg_route(FakeHttp(), "sourcegraph_empty.txt"), "github_ok.json")
    res = run(http=http, keys={"github": GH_TOKEN}, settings=KEYED)
    assert res.status is Status.OK
    assert all(GH_TOKEN not in c["url"] for c in http.calls)
    rows = {h["repo"]: h for h in res.attributes["code_search_hits"]}
    assert rows["github.com/example-org/example-app"]["severity"] == "high"
    assert rows["github.com/example-org/example-app"]["hits"][0]["link"] == (
        "https://github.com/example-org/example-app/blob/1111111111111111111111111111111111111111/app/settings.py")
    assert res.attributes["code_search_hostnames"] == ["api.example.com", "portal.example.com"]
    assert_no_secret("example-not-a-real-secret-0002", res.raw, res.attributes, [f.to_dict() for f in res.findings])
    high = next(f for f in res.findings if f.severity.name.lower() == "high")
    assert high.source == cs.SOURCE_GH and "third_party_repo" in high.tags


def test_github_own_repo_wording():
    http = gh_route(sg_route(FakeHttp(), "sourcegraph_empty.txt"), "github_ok.json")
    res = run(http=http, keys={"github": GH_TOKEN},
              settings={**KEYED, "code_search_org_accounts": ["example-org"]})
    rows = {h["repo"]: h for h in res.attributes["code_search_hits"]}
    assert rows["github.com/example-org/example-app"]["provenance"] == "own_repo"
    assert rows["github.com/example-user/example-mirror"]["wording"] == "third-party repo mentions our asset"


@pytest.mark.parametrize("name", ["github_secondary_rate_limit_403.json", "github_rate_limited_403.json"])
def test_github_403_rate_limits_are_rate_limited_not_absent(name):
    http = gh_route(sg_route(FakeHttp(), "sourcegraph_empty.txt"), name, status=403)
    res = run(http=http, keys={"github": GH_TOKEN}, settings=KEYED)
    assert res.status is Status.EMPTY  # Sourcegraph answered; GitHub could not verify
    assert res.source_statuses[cs.SOURCE_GH]["status"] == "rate_limited"
    alone = gh_route(FakeHttp(), name, status=403)
    res = run(http=alone, keys={"github": GH_TOKEN}, settings=KEYED, allowed_sources=[cs.SOURCE_GH])
    assert res.status is Status.RATE_LIMITED


def test_github_429_401_422_and_other_403():
    for name, status, expect in (("github_requires_auth_401.json", 401, "needs_key"),
                                 ("github_proxy_blocked_403.json", 403, "needs_key"),
                                 ("github_validation_failed_422.json", 422, "error")):
        http = gh_route(FakeHttp(), name, status=status)
        res = run(http=http, keys={"github": GH_TOKEN}, settings=KEYED, allowed_sources=[cs.SOURCE_GH])
        assert res.status.value == expect, name
        assert res.status is not Status.EMPTY
    http = FakeHttp().add("GET", GH, status=429, text="slow down")
    res = run(http=http, keys={"github": GH_TOKEN}, settings=KEYED, allowed_sources=[cs.SOURCE_GH])
    assert res.status is Status.RATE_LIMITED


def test_github_incomplete_results_is_partial_and_empty_is_empty():
    http = gh_route(FakeHttp(), "github_incomplete_partial.json")
    res = run(http=http, keys={"github": GH_TOKEN}, settings=KEYED, allowed_sources=[cs.SOURCE_GH])
    assert res.status is Status.OK and "incomplete_results" in res.raw["degraded"][cs.SOURCE_GH]
    http = gh_route(FakeHttp(), "github_empty.json")
    res = run(http=http, keys={"github": GH_TOKEN}, settings=KEYED, allowed_sources=[cs.SOURCE_GH])
    assert res.status is Status.EMPTY


def test_github_minute_window_is_never_exceeded():
    ctx = make_ctx(CodeSearch, FakeHttp(), keys={"github": GH_TOKEN})
    now = ctx.now().timestamp()
    ctx.state.set("github_minute", [now - 1] * cs.GITHUB_MINUTE_BUDGET)
    assert CodeSearch._github_slot(ctx) is False
    ctx.state.set("github_minute", [now - 120] * cs.GITHUB_MINUTE_BUDGET)
    assert CodeSearch._github_slot(ctx) is True


def test_unexpected_github_body_is_an_error():
    http = FakeHttp().add("GET", GH, json=["not", "an", "object"])
    res = run(http=http, keys={"github": GH_TOKEN}, settings=KEYED, allowed_sources=[cs.SOURCE_GH])
    assert res.status is Status.ERROR


# ------------------------------------------------------------------ GitLab (synthetic doc-shaped)
def test_gitlab_hits_locations_without_guessed_links():
    http = FakeHttp().add("GET", GL, json=module_fixture("code_search", "gitlab_ok.json"),
                          match_headers={"private-token": GL_TOKEN})
    res = run(http=http, keys={"gitlab": GL_TOKEN}, settings=KEYED, allowed_sources=[cs.SOURCE_GL])
    assert res.status is Status.OK
    rows = {h["repo"]: h for h in res.attributes["code_search_hits"]}
    assert rows["gitlab.com/projects/1000010"]["severity"] == "high"
    assert rows["gitlab.com/projects/1000010"]["hits"][0]["line"] == 10
    assert all(h["link"] is None for r in rows.values() for h in r["hits"])
    assert res.attributes["code_search_hostnames"] == ["build01.corp.example.com"]
    assert all(GL_TOKEN not in c["url"] for c in http.calls)


def test_gitlab_global_blob_search_refusal_is_reported_not_empty():
    http = FakeHttp().add("GET", GL, status=403, json=module_fixture("code_search", "gitlab_scope_unavailable_403.json"))
    res = run(http=http, keys={"gitlab": GL_TOKEN}, settings=KEYED, allowed_sources=[cs.SOURCE_GL])
    assert res.status is Status.SKIPPED and res.reason_code == "config" and "Premium" in res.error
    http = FakeHttp().add("GET", GL, status=401, json=module_fixture("code_search", "gitlab_unauthorized_401.json"))
    res = run(http=http, keys={"gitlab": GL_TOKEN}, settings=KEYED, allowed_sources=[cs.SOURCE_GL])
    assert res.status is Status.NEEDS_KEY
    http = FakeHttp().add("GET", GL, status=429, body=body("gitlab_rate_limited_429.txt"), headers={"retry-after": "60"})
    res = run(http=http, keys={"gitlab": GL_TOKEN}, settings=KEYED, allowed_sources=[cs.SOURCE_GL])
    assert res.status is Status.RATE_LIMITED
    http = FakeHttp().add("GET", GL, json=module_fixture("code_search", "gitlab_empty.json"))
    res = run(http=http, keys={"gitlab": GL_TOKEN}, settings=KEYED, allowed_sources=[cs.SOURCE_GL])
    assert res.status is Status.EMPTY


def test_three_sources_default_plan_is_capped_at_three_queries():
    http = sg_route(FakeHttp(), "sourcegraph_empty.txt")
    gh_route(http, "github_empty.json")
    http.add("GET", GL, json=[])
    res = run(http=http, keys={"github": GH_TOKEN, "gitlab": GL_TOKEN}, settings=KEYED)
    assert res.status is Status.EMPTY and res.requests == 3
    assert set(res.attributes["code_search_summary"]["providers"]) == {cs.SOURCE_SG, cs.SOURCE_GH, cs.SOURCE_GL}


# ------------------------------------------------------------------ pure helpers
def test_provenance_and_hostname_helpers():
    assert cs.classify_repo("github.com/example-intel/ioc-feeds") == "public_ioc_repo"
    assert cs.classify_repo("github.com/x/y", "data/blocklists/hosts.txt") == "public_ioc_repo"
    assert cs.classify_repo("github.com/acme/site", org_accounts=["ACME"]) == "own_repo"
    assert cs.classify_repo("github.com/someone/project") == "third_party_repo"
    assert cs.classify_repo("github.com/someone/project", ioc_repos=["github.com/someone/project"]) == "public_ioc_repo"
    text = "a.example.com login-example.com x.example.com.evil.net b.c.EXAMPLE.com"
    assert cs.extract_hostnames(text, "example.com") == {"a.example.com", "b.c.example.com"}


def test_hit_link_refuses_unsafe_parts():
    hit = {"source": cs.SOURCE_SG, "repo_host": "github.com", "owner": "a", "name": "b", "path": "../x", "commit": "abc"}
    assert cs.hit_link(hit) is None
    hit = {"source": cs.SOURCE_SG, "repo_host": "github.com", "owner": "a b", "name": "b", "path": "x", "commit": "abc"}
    assert cs.hit_link(hit) is None


def test_parsers_never_raise_on_junk():
    assert cs.parse_github({"items": "x"}) is None and cs.parse_gitlab({"message": "x"}) is None
    parsed = cs.parse_sourcegraph_stream(b"event: matches\ndata: {not json\n\n")
    assert parsed["bad_events"] == 1 and cs.sourcegraph_outcome(parsed)[0] == "error"
    assert cs.scan_fragment(None) == ([], "")


def test_entity_validation():
    assert Entity.try_make("domain", "example.com") is not None


# ------------------------------------------------------------------ AR21 golden-path routes
def test_acceptance_routes_replay():
    routes = module_fixture("acceptance", "domain/code_search.json")
    assert routes["schema"] == "v3lum.acceptance_routes/1" and routes["module"] == "code_search"
    http = FakeHttp()
    for r in routes["routes"]:
        http.add(r["method"], r["url"], status=r["status"], body=r["text"].encode(), headers=r.get("headers"))
    res = run(http=http)
    assert res.status is Status.OK and res.requests == len(routes["routes"])
    for etype, module in (("domain", "dork_generator"), ("domain", "pivots_unverified"), ("cnpj", "dork_generator"),
                          ("sha256", "pivots_unverified")):
        offline = module_fixture("acceptance", f"{etype}/{module}.json")
        assert offline["module"] == module and offline["routes"] == []  # offline modules: no request
