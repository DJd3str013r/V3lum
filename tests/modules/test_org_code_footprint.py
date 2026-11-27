"""P359 org_code_footprint: the fast inventory of a company's forge and registry organisations (p2-G05-2).

GitHub /orgs fixtures are DOC-SHAPED (documentation values: the research egress could not reach the
/orgs paths; recapture from the team network before the default set, cond 9); the search, Codeberg,
GitLab, npm, PyPI and Docker Hub fixtures are trimmed LIVE captures of official organisations.
"""

from __future__ import annotations

import json
from pathlib import Path
from urllib.parse import urlencode

from tests.fakes import FakeHttp, module_fixture, run_module
from v3lum.core.context import ScanOptions
from v3lum.core.models import Status
from v3lum.modules.company_org import org_code_footprint as ocf
from v3lum.modules.company_org.org_code_footprint import OrgCodeFootprint

GH = "https://api.github.com"
CB = "https://codeberg.org/api/v1"
GL = "https://gitlab.com/api/v4"
DH = "https://hub.docker.com/v2"
NPM = "https://registry.npmjs.org/-/v1/search"
JSON = {"content-type": "application/json; charset=utf-8"}
ORG_PROFILE = {"org": {"name": "Example Org"},
               "domains": [{"name": "example.com", "verification": "attested", "attested_by": "analyst", "attested_date": "2026-11-01"}]}
PURPOSE = ScanOptions(purpose="supplier code exposure review TICKET-1")


def fx(name):
    return module_fixture("org_code_footprint", name)


def body(name):
    doc = fx(name)
    return doc if not isinstance(doc, dict) or "_meta" not in doc else json.loads(doc["body"]) if isinstance(doc["body"], str) and doc["body"].lstrip()[:1] in "[{" else doc["body"]


def url(base, **params):
    return base + ("?" + urlencode(params) if params else "")


def search_body(*logins):
    return {"total_count": len(logins), "incomplete_results": False,
            "items": [{"login": lg, "id": 23456789 + i, "html_url": f"https://github.com/{lg}", "type": "Organization"} for i, lg in enumerate(logins)]}


def add_quiet_others(http, slug="exampleorg"):
    """The non-GitHub providers answer 'nothing here' for the slug (real 404/empty layouts)."""
    http.add("GET", f"{CB}/orgs/{slug}", status=404, json=json.loads(fx("cb_org_not_found.http.json")["body"]), headers=JSON)
    http.add("GET", url(f"{GL}/groups", search=slug, top_level_only="true", per_page=5), json=[], headers=JSON)
    http.add("GET", f"{DH}/orgs/{slug}", status=404, json={"orgname": [slug]}, headers=JSON)
    http.add("GET", url(NPM, text=f"@{slug}/", size=20), json=fx("npm_search_scope_empty.json"), headers=JSON)
    http.add("GET", f"https://pypi.org/org/{slug}/", status=404, text=fx("pypi_org_not_found.http.json")["body"],
             headers={"content-type": "text/html; charset=UTF-8"})
    return http


def own_org_http(*, list_members=False):
    http = FakeHttp()
    http.add("GET", url(f"{GH}/search/users", q="Example Org type:org", per_page=5), json=search_body("example-org", "example-org-archive"), headers=JSON)
    http.add("GET", f"{GH}/orgs/example-org", json={k: v for k, v in fx("gh_org_ok.json").items() if k != "_fixture"}, headers=JSON)
    http.add("GET", url(f"{GH}/orgs/example-org/repos", per_page=30, sort="pushed", type="public"),
             json=fx("gh_org_repos_ok.json")["items"], headers=JSON)
    members = fx("gh_public_members_count.http.json")
    http.add("GET", url(f"{GH}/orgs/example-org/public_members", per_page=30 if list_members else 1),
             json=json.loads(members["body"]), headers={**JSON, "link": members["headers"]["link"]})
    return add_quiet_others(http)


# ------------------------------------------------------------------------------------- own organisation (cond 1-4)


def test_own_organisation_inventory_is_confirmed_by_the_org_profile_domain():
    http = own_org_http()
    res = run_module(OrgCodeFootprint, "company_name:Example Org", http, org_profile=ORG_PROFILE)
    assert res.status is Status.OK
    orgs = {f"{o['provider']}:{o['login']}": o for o in res.attributes["code_orgs"]}
    gh = orgs["github:example-org"]
    assert gh["state"] == "confirmed" and gh["basis"] == "website_host+github_verified_domain"
    assert gh["website_host"] == "www.example.com" and gh["repo_count"] == 42 and gh["member_count"] == 37
    assert orgs["github:example-org-archive"]["state"] == "candidate"  # a name match only: no expansion
    recent = [r["full_name"] for r in res.attributes["code_repos"]]
    assert recent[:2] == ["example-org/ml-models", "example-org/api-gateway"] and "example-org/upstream-lib" not in recent  # recent first; fork without own commits skipped
    assert "example-org/patched-lib" in recent and len(recent) == 5
    assert res.attributes["code_member_counts"] == {"github:example-org": 37}  # count only, no usernames
    assert not any(p.relation == "org_member" for p in res.pivots)
    assert all(p.expand is False for p in res.pivots)
    confirmed = next(p for p in res.pivots if p.entity.value == "https://github.com/example-org")
    assert confirmed.relation == "code_org" and confirmed.confidence_label.value == "probable"
    assert res.findings[0].severity.label == "info" and "1 confirmed" in res.findings[0].description
    assert res.requests <= OrgCodeFootprint.max_requests
    assert "/orgs/example-org-archive" not in " ".join(http.urls())  # candidates are never expanded (cond 2)
    http.assert_hosts_within(OrgCodeFootprint)


def test_member_usernames_only_on_demand_and_never_expanded():
    res = run_module(OrgCodeFootprint, "company_name:Example Org", own_org_http(list_members=True), org_profile=ORG_PROFILE,
                     settings={"org_code_footprint_list_members": True})
    members = [p for p in res.pivots if p.relation == "org_member"]
    assert [p.entity.value for p in members] == ["example-member"] and members[0].expand is False


def test_the_github_token_goes_to_api_github_com_only():
    http = own_org_http()
    run_module(OrgCodeFootprint, "company_name:Example Org", http, org_profile=ORG_PROFILE, keys={"github": "ghp_FAKEKEYFORTESTS0000000000000000000000"})
    for call in http.calls:
        auth = {k.lower(): v for k, v in (call.get("headers") or {}).items()}.get("authorization")
        assert (auth is not None) == call["url"].startswith(GH)


# ------------------------------------------------------------------------------------- cond 3: who may run


def test_other_companies_need_explicit_selection_and_a_purpose():
    http = FakeHttp()
    res = run_module(OrgCodeFootprint, "company_name:Other Corp", http, org_profile=ORG_PROFILE)
    assert res.status is Status.SKIPPED and res.reason_code == "own_asset" and "--purpose" in res.error
    assert http.calls == []


def test_a_third_party_company_with_purpose_lists_candidates_only():
    http = FakeHttp()
    http.add("GET", url(f"{GH}/search/users", q="Other Org type:org", per_page=5), json=search_body("otherorg"), headers=JSON)
    http.add("GET", f"{GH}/orgs/otherorg", json={"login": "otherorg", "html_url": "https://github.com/otherorg",
                                                  "blog": "https://otherorg.example.net", "public_repos": 3}, headers=JSON)
    add_quiet_others(http, "otherorg")
    res = run_module(OrgCodeFootprint, "company_name:Other Org", http, org_profile=ORG_PROFILE, options=PURPOSE)
    assert res.status is Status.OK
    org = res.attributes["code_orgs"][0]
    assert org["state"] == "candidate" and org["basis"] == "no_owned_website"
    assert "code_repos" not in res.attributes and not any("/repos" in u for u in http.urls())  # no expansion (cond 2)
    assert any(p.entity.value == "otherorg.example.net" and p.expand is False for p in res.pivots)


def test_analyst_confirmation_enables_the_inventory_of_a_codeberg_org():
    http = FakeHttp()
    http.add("GET", f"{GH}/orgs/forgejo", status=404, json=json.loads(fx("gh_org_not_found.http.json")["body"]), headers=JSON)
    http.add("GET", f"{CB}/orgs/forgejo", json=fx("cb_org_ok.json"), headers=JSON)
    repos = fx("cb_org_repos_ok.http.json")
    http.add("GET", url(f"{CB}/orgs/forgejo/repos", limit=50), json=json.loads(repos["body"]), headers={**JSON, "x-total-count": "20"})
    members = fx("cb_org_members_count.http.json")
    http.add("GET", url(f"{CB}/orgs/forgejo/public_members", limit=1), json=json.loads(members["body"]), headers=members["headers"])
    http.add("GET", url(f"{GL}/groups", search="forgejo", top_level_only="true", per_page=5), json=[], headers=JSON)
    http.add("GET", f"{DH}/orgs/forgejo", status=404, json={"orgname": ["forgejo"]}, headers=JSON)
    http.add("GET", url(NPM, text="maintainer:forgejo", size=20), json=fx("npm_search_scope_empty.json"), headers=JSON)
    http.add("GET", "https://pypi.org/org/forgejo/", status=404, text="not found", headers={"content-type": "text/html"})
    res = run_module(OrgCodeFootprint, "username:forgejo", http, settings={"org_code_footprint_confirmed": ["codeberg:forgejo"]})
    assert res.status is Status.OK
    org = res.attributes["code_orgs"][0]
    assert (org["provider"], org["state"], org["basis"], org["repo_count"]) == ("codeberg", "confirmed", "analyst", 20)
    assert res.attributes["code_repos"][0]["provider"] == "codeberg"
    assert res.attributes["code_member_counts"] == {"codeberg:forgejo": 35}  # count only: no member pivot
    assert not any(p.relation == "org_member" for p in res.pivots)


def test_docker_hub_org_confirmed_by_its_profile_url():
    http = FakeHttp()
    http.add("GET", url(f"{GH}/search/users", q="Docker Inc type:org", per_page=5), json=fx("gh_search_org_empty.json"), headers=JSON)
    http.add("GET", f"{CB}/orgs/docker", status=404, json={"message": "GetOrgByName"}, headers=JSON)
    http.add("GET", url(f"{GL}/groups", search="docker", top_level_only="true", per_page=5), json=[], headers=JSON)
    http.add("GET", f"{DH}/orgs/docker", json=fx("dh_org_ok.json"), headers=JSON)
    http.add("GET", url(f"{DH}/repositories/docker/", page_size=5, ordering="last_updated"), json=fx("dh_repos_ok.json"), headers=JSON)
    http.add("GET", url(NPM, text="@docker/", size=20), json=fx("npm_search_scope_empty.json"), headers=JSON)
    http.add("GET", "https://pypi.org/org/docker/", status=404, text="not found", headers={"content-type": "text/html"})
    profile = {"org": {"name": "Docker Inc"}, "domains": [{"name": "docker.com", "verification": "attested", "attested_by": "a", "attested_date": "2026-11-01"}]}
    res = run_module(OrgCodeFootprint, "company_name:Docker Inc", http, org_profile=profile)
    org = next(o for o in res.attributes["code_orgs"] if o["provider"] == "dockerhub")
    assert org["state"] == "confirmed" and org["repo_count"] == 321
    assert res.attributes["code_packages"]["docker"][0]["name"] == "sandbox-templates"


# ------------------------------------------------------------------------------------- could not verify (rule 5)


def test_pypi_challenge_is_blocked_and_the_other_providers_answer():
    ch = fx("pypi_client_challenge.http.json")
    http = FakeHttp()
    http.add("GET", url(f"{GH}/search/users", q="Example Org type:org", per_page=5), json=search_body("example-org"), headers=JSON)
    http.add("GET", f"{GH}/orgs/example-org", status=404, json={"message": "Not Found"}, headers=JSON)
    http.add("GET", f"{CB}/orgs/exampleorg", status=404, json={"message": "GetOrgByName"}, headers=JSON)
    http.add("GET", url(f"{GL}/groups", search="exampleorg", top_level_only="true", per_page=5), json=[], headers=JSON)
    http.add("GET", f"{DH}/orgs/exampleorg", status=404, json={"orgname": ["exampleorg"]}, headers=JSON)
    http.add("GET", url(NPM, text="@exampleorg/", size=20), json=fx("npm_search_scope_empty.json"), headers=JSON)
    http.add("GET", "https://pypi.org/org/exampleorg/", status=200, text=ch["body"], headers=ch["headers"])  # recorded challenge page
    res = run_module(OrgCodeFootprint, "company_name:Example Org", http, org_profile=ORG_PROFILE)
    assert res.status is Status.EMPTY  # the answering providers found nothing ...
    st = res.source_statuses[ocf.SRC_PYPI]
    assert (st["status"], st["reason_code"]) == ("blocked", "challenge")  # ... and PyPI could not verify
    assert "could not verify" in res.error and ocf.SRC_PYPI in res.error


def test_github_rate_limit_is_recorded_per_source():
    rl = fx("gh_search_rate_limited.http.json")
    http = FakeHttp().add("GET", url(f"{GH}/search/users", q="Example Org type:org", per_page=5), status=403, text=rl["body"], headers=rl["headers"])
    add_quiet_others(http)
    res = run_module(OrgCodeFootprint, "company_name:Example Org", http, org_profile=ORG_PROFILE)
    st = res.source_statuses[ocf.SRC_GH]
    assert st["status"] == "rate_limited" and res.status is Status.EMPTY


def test_every_provider_failing_is_never_empty():
    http = FakeHttp()
    http.add("GET", url(f"{GH}/search/users", q="Example Org type:org", per_page=5), status=429, text="slow down")
    http.add("GET", f"{CB}/orgs/exampleorg", status=503, text="down", times=3)
    gl = fx("gl_rate_limited.http.json")
    http.add("GET", url(f"{GL}/groups", search="exampleorg", top_level_only="true", per_page=5), status=429, text=gl["body"], headers=gl["headers"])
    dh = fx("dh_rate_limited.http.json")
    http.add("GET", f"{DH}/orgs/exampleorg", status=429, text=dh["body"], headers=dh["headers"])
    npm = fx("npm_challenge.http.json")
    http.add("GET", url(NPM, text="@exampleorg/", size=20), status=npm["status"], text=npm["body"], headers=npm["headers"])
    http.add("GET", "https://pypi.org/org/exampleorg/", status=502, text="bad gateway", times=3)
    res = run_module(OrgCodeFootprint, "company_name:Example Org", http, org_profile=ORG_PROFILE)
    assert res.status in (Status.RATE_LIMITED, Status.BLOCKED, Status.ERROR) and res.status is not Status.EMPTY


def test_malformed_json_is_could_not_verify_for_that_source():
    http = FakeHttp().add("GET", url(f"{GH}/search/users", q="Example Org type:org", per_page=5), text="{not json", headers=JSON)
    add_quiet_others(http)
    res = run_module(OrgCodeFootprint, "company_name:Example Org", http, org_profile=ORG_PROFILE)
    assert res.source_statuses[ocf.SRC_GH]["status"] == "error"


def test_github_outside_the_allowed_sources_is_never_queried():
    http = add_quiet_others(FakeHttp())
    allowed = [s for s in OrgCodeFootprint.sources if s != ocf.SRC_GH]
    res = run_module(OrgCodeFootprint, "company_name:Example Org", http, org_profile=ORG_PROFILE, allowed_sources=allowed)
    assert res.status is Status.EMPTY and "api.github.com" not in http.hosts()


def test_request_budget_stops_with_a_partial_result(monkeypatch):
    monkeypatch.setattr(OrgCodeFootprint, "max_requests", 3)
    http = own_org_http()
    res = run_module(OrgCodeFootprint, "company_name:Example Org", http, org_profile=ORG_PROFILE)
    assert res.partial and res.stop_reason == "request_cap" and res.requests <= 3


# ------------------------------------------------------------------------------------- parsers


def test_parsers_on_live_layouts():
    gl = json.loads(fx("gl_groups_search_ok.http.json")["body"])
    groups = ocf.parse_gitlab_groups(gl, "gitlab-org")
    assert [g["login"] for g in groups] == ["gitlab-org"]  # exact match only, though it came 2nd
    projects = ocf.parse_gitlab_projects(json.loads(fx("gl_group_projects_ok.http.json")["body"]))
    assert projects[0]["full_name"] == "gitlab-org/gitlab" and projects[0]["id"] == 278964 and projects[0]["size_kb"] is None
    npm = ocf.parse_npm_search(fx("npm_search_scope_ok.json"), "angular")
    assert npm["packages"] and all(p["name"].startswith("@angular/") for p in npm["packages"])
    assert "email" not in json.dumps(npm)
    page = ocf.parse_pypi_org_page((Path(__file__).resolve().parents[1] / "fixtures" / "org_code_footprint" / "pypi_org_ok.html").read_text())
    assert (page["display_name"], page["org"], page["project_count"]) == ("Python Packaging Authority", "pypa", 10)
    assert page["projects"][0] == {"name": "sampleproject", "last_released": "2024-11-06T22:37:09+0000"}
    assert ocf.parse_dockerhub_org({"orgname": ["x"]}) is None
    assert ocf.parse_dockerhub_org(fx("dh_org_ok.json"))["website_host"] == "www.docker.com"
    assert ocf.parse_codeberg_org(fx("cb_org_ok.json"))["website_host"] == "forgejo.org"
    cands = ocf.parse_github_org_search(json.loads(fx("gh_search_org_ok.http.json")["body"]))
    assert [c["login"] for c in cands] == ["microsoft", "MicrosoftDocs", "MicrosoftLearning"]


def test_helpers():
    assert ocf.count_from_link_header(fx("gh_public_members_count.http.json")["headers"]["link"]) == 37
    assert ocf.count_from_link_header(None, 1) == 1
    assert ocf.org_slug_candidates("Exemplo Comércio Ltda.", "www.exemplo.com.br") == ["exemplo", "exemplocomercio"]
    assert ocf.extract_host("www.example.com") == "www.example.com" and ocf.extract_host("http://192.0.2.1/") is None
    sel = ocf.select_repos(ocf.parse_github_repos(fx("gh_org_repos_ok.json")))
    assert {"repo": "example-org/upstream-lib", "reason": "fork_without_own_commits"} in sel["skipped"]
    deep = {r["full_name"]: (ok, why) for r, ok, why in sel["deep"]}
    assert deep["example-org/ml-models"] == (False, "over_50mb") and deep["example-org/api-gateway"] == (True, "ok")
    assert ocf.archive_url({"provider": "github", "full_name": "example-org/api-gateway", "default_branch": "main"})[0] == \
        "https://codeload.github.com/example-org/api-gateway/tar.gz/main"
    assert ocf.archive_url({"provider": "github", "full_name": "../etc", "default_branch": "main"}) is None
    conf = ocf.org_confirmation({"provider": "github", "login": "x", "website_host": "a.example"}, lambda h: "own", set())
    assert conf == {"state": "confirmed", "basis": "website_host"}
    assert ocf.org_confirmation({"provider": "github", "login": "x", "website_host": "a.example"}, lambda h: "supplier", set())["basis"] == "supplier_website_host"
    assert ocf.org_confirmation({"provider": "github", "login": "x"}, lambda h: True, {"github:x"})["basis"] == "analyst"
    assert ocf.org_confirmation({"provider": "github", "login": "x", "website_host": "a.example"}, lambda h: 1 / 0, set())["state"] == "candidate"


def test_metadata():
    cls = OrgCodeFootprint
    assert cls.max_requests <= 10 and cls.timeout <= 15 and cls.default_enabled is True and cls.run_on == "seeds"
    assert cls.terms == "key-terms" and cls.trust_tier == "community"
    assert set(cls.hosts) == {"api.github.com", "gitlab.com", "codeberg.org", "registry.npmjs.org", "pypi.org", "hub.docker.com"}
    assert "keybase.io" not in cls.hosts and "hackerone.com" not in cls.hosts  # cond 8: SaaS forges and registries only
    assert body("gh_org_not_found.http.json")["message"] == "Not Found"


def test_acceptance_route_is_empty_because_example_com_is_not_the_own_organisation():
    from tests.fakes import fixture

    doc = fixture("acceptance/domain/org_code_footprint.json")
    assert (doc["schema"], doc["module"], doc["routes"]) == ("v3lum.acceptance_routes/1", "org_code_footprint", [])
    http = FakeHttp()
    res = run_module(OrgCodeFootprint, "domain:example.com", http)  # no org profile, no purpose
    assert res.status is Status.SKIPPED and res.reason_code == "own_asset" and http.calls == []


def test_gitlab_html_error_and_github_proxy_refusal_are_could_not_verify():
    blocked = fx("gh_orgs_blocked_proxy.http.json")
    gl_err = fx("gl_html_error.http.json")
    http = FakeHttp()
    http.add("GET", f"{GH}/orgs/exampleorg", status=blocked["status"], text=blocked["body"], headers=blocked["headers"])
    http.add("GET", f"{CB}/orgs/exampleorg", status=404, json={"message": "GetOrgByName"}, headers=JSON)
    http.add("GET", url(f"{GL}/groups", search="exampleorg", top_level_only="true", per_page=5), status=gl_err["status"], text=gl_err["body"],
             headers=gl_err["headers"], times=3)
    http.add("GET", f"{DH}/orgs/exampleorg", status=404, json=json.loads(fx("dh_org_not_found.http.json")["body"]), headers=JSON)
    http.add("GET", url(NPM, text="maintainer:exampleorg", size=20), json=fx("npm_search_scope_empty.json"), headers=JSON)
    http.add("GET", "https://pypi.org/org/exampleorg/", status=404, text="not found", headers={"content-type": "text/html"})
    res = run_module(OrgCodeFootprint, "username:exampleorg", http, options=PURPOSE)
    assert res.status is Status.EMPTY and "could not verify" in res.error
    assert res.source_statuses[ocf.SRC_GH]["status"] in ("blocked", "needs_key")
    assert res.source_statuses[ocf.SRC_GL]["status"] == "error"


def test_run_deadline_keeps_the_partial_inventory(monkeypatch):
    from v3lum.core.http import DeadlineExceeded

    http = own_org_http()
    original = ocf._Footprint.codeberg

    def slow(self, slug):
        raise DeadlineExceeded("run deadline reached")

    monkeypatch.setattr(ocf._Footprint, "codeberg", slow)
    res = run_module(OrgCodeFootprint, "company_name:Example Org", http, org_profile=ORG_PROFILE)
    assert res.status is Status.OK and res.partial and res.stop_reason == "deadline"
    assert any(o["login"] == "example-org" for o in res.attributes["code_orgs"])  # GitHub answered before the deadline
    assert original is not slow
