"""Offline tests of git_metadata_identity (P115) on the GitHub REST fixtures in tests/fixtures/git_metadata_identity/.

The GitHub fixtures are DOC-SHAPED (GitHub REST v2022-11-28 layout with documentation values): api.github.com
was refused by the research egress proxy on 2026-11-26 (blocked_proxy.http.json is that real refusal). P115 FC7
asks for a recapture from the team network before merge (docs/backlog/p3-G05-2.md).
"""

from __future__ import annotations

import json

import pytest

from tests.fakes import FakeHttp, module_fixture, run_module
from v3lum.core.context import ScanOptions
from v3lum.core.entities import EntityType as T
from v3lum.core.models import Severity, Status
from v3lum.modules.username_social.git_metadata_identity import (
    GitMetadataIdentity,
    address_class,
    extract_identities,
    git_fetch_allowed,
    git_trailers,
    normalise_git_subject,
    parse_commits_page,
    select_repos,
)

FIX = "git_metadata_identity"
API = "https://api.github.com"
REPOS = API + "/users/{u}/repos?type=owner&sort=pushed&direction=desc&per_page=100"
COMMITS = API + "/repos/{r}/commits?per_page=100"
META = API + "/repos/{r}"
PURPOSE = ScanOptions(purpose="IR-2026-0042: phishing kit repository published by the case subject")
# the ten own non-fork repositories of repos_ok.json, newest pushed_at first (proj-g is over the cap)
SELECTED = ["tooling", "dotfiles", "scanner-cli", "proj-f", "proj-d", "proj-a", "proj-b", "notes", "proj-c", "proj-e"]
THIRD_PARTY = ("other@example.org", "unlinked@example.org", "case.person@example.net", "x@example.org",
               "maint@example.org", "third@example.org", "upstream@example.org", "Other Contributor", "Unlinked Author",
               "Someone Else", "Upstream Maintainer", "other-noreply", "dependabot", "donotreply@example.com", "root@localhost")


def env(name: str) -> dict:
    d = module_fixture(FIX, name)
    return {"status": d["status"], "headers": d["headers"], "text": d["body"]}


def account_http(*, tooling: dict | None = None, extra: dict | None = None) -> FakeHttp:
    http = FakeHttp().add("GET", REPOS.format(u="example-dev"), json=module_fixture(FIX, "repos_ok.json"))
    for repo in SELECTED:
        route = (extra or {}).get(repo)
        if repo == "tooling" and tooling is not None:
            route = tooling
        if route is None:
            route = {"json": []}
        http.add("GET", COMMITS.format(r=f"example-dev/{repo}"), **route)
    return http


def run_account(http: FakeHttp, **kw):
    kw.setdefault("options", PURPOSE)
    return run_module(GitMetadataIdentity, "username:example-dev", http, **kw)


# ---------------------------------------------------------------------------------- pure helpers


@pytest.mark.parametrize("value,expected", [
    ("example-dev", {"kind": "account", "login": "example-dev"}),
    ("@example-dev", {"kind": "account", "login": "example-dev"}),
    ("https://github.com/example-dev", {"kind": "account", "login": "example-dev"}),
    ("https://github.com/example-dev/tooling.git", {"kind": "repo", "owner": "example-dev", "repo": "tooling", "full_name": "example-dev/tooling"}),
    ("https://github.com/example-dev/tooling/blob/main/kit.php", {"kind": "repo", "owner": "example-dev", "repo": "tooling", "full_name": "example-dev/tooling"}),
    ("example-dev/tooling", {"kind": "repo", "owner": "example-dev", "repo": "tooling", "full_name": "example-dev/tooling"}),
    ("http://github.com/example-dev", None),
    ("https://gitlab.com/example-dev", None),
    ("https://user:pw@github.com/example-dev", None),
    ("https://github.com/settings", None),
    ("bad--login", None),
])
def test_normalise_git_subject(value, expected):
    assert normalise_git_subject(value) == expected


def test_fetch_guard_allows_only_the_fc1_plan():
    assert git_fetch_allowed(REPOS.format(u="example-dev"))
    assert git_fetch_allowed(COMMITS.format(r="example-dev/tooling"))
    assert git_fetch_allowed(META.format(r="example-dev/tooling"))
    for url in (API + "/repos/example-dev/tooling/commits?per_page=100&page=2",  # one page only
                API + "/repos/example-dev/tooling/commits?per_page=500",
                API + "/search/commits?q=author:example-dev",
                API + "/users/example-dev/gpg_keys",
                "https://github.com/example-dev/tooling.git",
                "http://api.github.com/users/example-dev/repos",
                "https://gitlab.com/api/v4/users",
                "https://api.github.com:8443/users/example-dev/repos"):
        assert not git_fetch_allowed(url), url


def test_select_repos_sorts_by_pushed_skips_forks_empty_disabled_and_caps_at_ten():
    sel = select_repos(module_fixture(FIX, "repos_ok.json"), owner="example-dev")
    assert [r["repo"] for r in sel["selected"]] == SELECTED
    assert sel["skipped"] == {"fork": 1, "empty": 1, "disabled": 1, "over_cap": 1}
    assert sel["owner"] == {"login": "example-dev", "id": 12345678, "type": "User"}
    assert select_repos("<!DOCTYPE html><html><title>x</title></html>")["ok"] is False


def test_trailers_follow_the_gitcolombo_malformed_name_rule():
    msg = ("Merge\n\nCo-authored-by: Reviewer: Someone <x@example.org>\nCc: @maintainer <maint@example.org>\n"
           "Signed-off-by: Example Developer <dev@example.com>")
    got = git_trailers(msg)
    assert [(t["key"], t["malformed"]) for t in got] == [("co-authored-by", True), ("cc", True), ("signed-off-by", False)]


@pytest.mark.parametrize("email,name,login,expected", [
    ("noreply@example.com", None, None, "system"),
    ("do-not-reply@example.com", None, None, "system"),
    ("noreply@github.com", "GitHub", "web-flow", "system"),
    ("49699333+dependabot[bot]@users.noreply.github.com", "dependabot[bot]", None, "bot"),
    ("support@github.com", "dependabot[bot]", None, "bot"),
    ("12345678+example-dev@users.noreply.github.com", None, None, "noreply"),
    ("root@localhost", "root", None, "invalid"),
    ("dev@example.com", "Example Developer", "example-dev", "personal"),
])
def test_address_classes(email, name, login, expected):
    assert address_class(email, name, login)[0] == expected


def test_identities_are_order_independent():
    commits = parse_commits_page(module_fixture(FIX, "commits_ok.json"), repo="example-dev/tooling")["commits"]
    sub = {"kind": "account", "login": "example-dev", "id": 12345678}
    a = extract_identities(commits, sub)
    b = extract_identities(list(reversed(commits)), sub)
    assert [i["email"] for i in a["identities"]] == [i["email"] for i in b["identities"]]
    assert a["counts"] == b["counts"]


# ---------------------------------------------------------------------------------- the module


def test_account_lists_only_the_subjects_own_identities():
    http = account_http(tooling={"json": module_fixture(FIX, "commits_ok.json")})
    res = run_account(http)
    assert res.status is Status.OK, res.error
    assert len(http.calls) == 11  # FC1: one listing + ten commit pages
    http.assert_hosts_within(GitMetadataIdentity)
    assert res.attributes["presence"]["state"] == "found"
    emails = [i["email"] for i in res.attributes["git_identities"]]
    assert emails == ["dev@example.com", "dev@work.example.net"]
    assert res.attributes["account_id"] == 12345678
    counts = res.attributes["third_party_counts"]
    assert counts["other_contributors"] == 2 and counts["co_authors"] == 1 and counts["sign_offs"] == 1
    assert counts["other_noreply_accounts"] == 1 and counts["malformed_trailers"] == 2
    assert counts["dropped"]["system"] >= 2 and counts["dropped"]["bot"] >= 1 and counts["dropped"]["invalid"] == 2
    pivots = {(p.entity.type, p.entity.value): p for p in res.pivots}
    for p in res.pivots:
        assert p.expand is False and p.confidence_label == "probable"
    assert pivots[(T.EMAIL, "dev@example.com")].relation == "commit_email"
    assert (T.PERSON, "Example Developer") in pivots and (T.PERSON, "E. Developer") in pivots
    # the noreply id of a commit made before the account was renamed reveals the previous login
    assert pivots[(T.SOCIAL_ACCOUNT, "github:old-handle")].relation == "previous_handle"
    assert {"handle": "example-dev", "id": 12345678} in res.attributes["noreply_accounts"]
    assert res.attributes["git_clusters"]["same_person"]  # names sharing the same e-mail set (gitcolombo)
    titles = [f.title for f in res.findings]
    assert titles == ["Identities in the subject's own commits"]
    # FC4: other contributors, co-authors, sign-offs, bots and system addresses are counted, never listed
    blob = json.dumps(res.to_dict(), default=str)
    for value in THIRD_PARTY:
        assert value not in blob, value


def test_case_entity_among_contributors_is_listed_and_flagged():
    opts = ScanOptions(purpose=PURPOSE.purpose, seed_tlp={"username:example-dev": "amber", "email:case.person@example.net": "amber"})
    http = account_http(tooling={"json": module_fixture(FIX, "commits_ok.json")})
    res = run_account(http, options=opts)
    hits = res.attributes["git_case_matches"]
    assert [h["value"] for h in hits] == ["case.person@example.net"]
    piv = [p for p in res.pivots if p.relation == "case_entity_in_subject_repos"]
    assert [p.entity.value for p in piv] == ["case.person@example.net"] and piv[0].expand is False
    assert any(f.title == "Case entity in the subject's commit metadata" and f.severity is Severity.LOW for f in res.findings)
    assert "other@example.org" not in json.dumps(res.to_dict(), default=str)


def test_fork_repository_subject_never_lists_upstream_values_even_case_entities():
    opts = ScanOptions(purpose=PURPOSE.purpose, seed_tlp={"email:case.person@example.net": "amber"})
    http = (FakeHttp()
            .add("GET", META.format(r="example-dev/docs"), json=module_fixture(FIX, "repo_meta_fork.json"))
            .add("GET", COMMITS.format(r="example-dev/docs"), json=module_fixture(FIX, "commits_fork_repo.json")))
    res = run_module(GitMetadataIdentity, "url:https://github.com/example-dev/docs", http, options=opts)
    assert res.status is Status.OK and len(http.calls) == 2  # a repository subject costs 2 requests
    assert [i["email"] for i in res.attributes["git_identities"]] == ["dev@example.com"]
    assert res.attributes["third_party_counts"]["upstream_contributors"] == 2
    assert res.attributes["git_repos_read"]["fork"] is True
    assert not res.attributes.get("git_case_matches")
    blob = json.dumps(res.to_dict(), default=str)
    assert "upstream@example.org" not in blob and "case.person@example.net" not in blob


def test_repository_subject_reads_meta_then_one_commits_page():
    http = (FakeHttp()
            .add("GET", META.format(r="example-dev/tooling"), json=module_fixture(FIX, "repo_meta_ok.json"))
            .add("GET", COMMITS.format(r="example-dev/tooling"), json=module_fixture(FIX, "commits_ok.json")))
    res = run_module(GitMetadataIdentity, "url:https://github.com/example-dev/tooling", http, options=PURPOSE)
    assert res.status is Status.OK
    assert [i["email"] for i in res.attributes["git_identities"]] == ["dev@example.com", "dev@work.example.net"]


def test_404_is_a_documented_absence():
    http = FakeHttp().add("GET", REPOS.format(u="qz7k2v9m4p1w8n3x5c6b"), **env("not_found.http.json"))
    res = run_module(GitMetadataIdentity, "username:qz7k2v9m4p1w8n3x5c6b", http, options=PURPOSE)
    assert res.status is Status.EMPTY and res.attributes["presence"]["state"] == "absent"


def test_empty_repository_409_and_empty_pages_are_not_errors():
    http = account_http(extra={"notes": env("commits_empty_repo.http.json")})
    res = run_account(http)
    assert res.status in (Status.OK, Status.EMPTY)
    assert not res.source_statuses
    assert {"full_name": "example-dev/notes", "pushed_at": "2025-01-01T00:00:00Z", "commits": 0, "note": "empty or gone"} in \
        res.attributes["git_repos_read"]["selected"]


def test_rate_limit_on_the_listing_is_could_not_verify():
    http = FakeHttp().add("GET", REPOS.format(u="example-dev"), **env("rate_limited.http.json"))
    res = run_account(http)
    assert res.status is Status.RATE_LIMITED and res.reason_code == "rate_limited"


def test_secondary_rate_limit_mid_run_keeps_what_was_read_as_partial():
    http = account_http(tooling={"json": module_fixture(FIX, "commits_ok.json")},
                        extra={"dotfiles": env("secondary_rate_limited.http.json")})
    res = run_account(http)
    assert res.partial is True and res.stop_reason == "rate_limited"
    assert [i["email"] for i in res.attributes["git_identities"]] == ["dev@example.com", "dev@work.example.net"]
    assert len(http.calls) == 3  # nothing sent after the rate limit


def test_egress_or_keyless_403_is_blocked_never_absent():
    http = FakeHttp().add("GET", REPOS.format(u="example-dev"), **env("blocked_proxy.http.json"))
    res = run_account(http)
    assert res.status is Status.BLOCKED and res.reason_code == "challenge"


def test_bad_token_is_needs_key_and_token_goes_to_api_github_only():
    http = FakeHttp().add("GET", REPOS.format(u="example-dev"), status=401, json={"message": "Bad credentials"})
    res = run_account(http, keys={"github": "github_pat_" + "A" * 30})
    assert res.status is Status.NEEDS_KEY
    assert http.calls[0]["headers"].get("Authorization", "").startswith("Bearer ")


def test_html_instead_of_json_and_malformed_bodies_are_errors():
    html = module_fixture(FIX, "html_instead_of_json.html")
    http = FakeHttp().add("GET", REPOS.format(u="example-dev"), text=html, headers={"content-type": "text/html"})
    assert run_account(http).status is Status.ERROR
    http = FakeHttp().add("GET", REPOS.format(u="example-dev"), text='{"truncated": ', headers={"content-type": "application/json"})
    assert run_account(http).status is Status.ERROR
    http = FakeHttp().add("GET", REPOS.format(u="example-dev"), json={"message": "not a list"})
    assert run_account(http).status is Status.ERROR


def test_malformed_commit_pages_are_per_source_errors_and_the_rest_is_kept():
    truncated = module_fixture(FIX, "commits_truncated.txt")
    http = account_http(tooling={"json": module_fixture(FIX, "commits_ok.json")},
                        extra={"dotfiles": {"text": truncated, "headers": {"content-type": "application/json"}},
                               "scanner-cli": {"text": "<!DOCTYPE html><html><body>oops</body></html>",
                                               "headers": {"content-type": "text/html"}},
                               "proj-f": {"json": {"message": "not a list"}}})
    res = run_account(http)
    assert res.status is Status.OK
    row = res.source_statuses["github.git_metadata_identity_commits"]
    assert row["status"] == "error" and "dotfiles" in row["reason"] and "scanner-cli" in row["reason"] and "proj-f" in row["reason"]
    assert [i["email"] for i in res.attributes["git_identities"]] == ["dev@example.com", "dev@work.example.net"]


def test_server_error_is_error_never_empty():
    http = FakeHttp().add("GET", REPOS.format(u="example-dev"), status=500, text="boom")
    assert run_account(http).status is Status.ERROR


def test_case_subjects_only_with_a_recorded_purpose():
    http = FakeHttp()
    res = run_module(GitMetadataIdentity, "username:example-dev", http)  # no purpose recorded
    assert res.status is Status.SKIPPED and res.reason_code == "privacy" and not http.calls
    res = run_module(GitMetadataIdentity, "username:example-dev", http, options=PURPOSE, is_seed=False, depth=1)
    assert res.status is Status.SKIPPED and not http.calls
    res = run_module(GitMetadataIdentity, "url:https://gitlab.com/example-dev", http, options=PURPOSE)
    assert res.status is Status.SKIPPED and res.reason_code == "not_applicable"


def test_metadata_matches_the_council_decision():
    m = GitMetadataIdentity
    assert m.default_enabled is False and m.run_on == "seeds" and m.terms == "key-terms"
    assert m.disclosure == "third_party" and m.hosts == ("api.github.com",) and m.max_requests == 11
    assert m.sources == ("github.git_metadata_identity_commits",) and m.optional_keys == ("github",)
    assert m.trust_tier == "trusted"
