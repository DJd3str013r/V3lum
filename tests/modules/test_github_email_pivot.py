"""github_email_pivot (P086): e-mail -> GitHub accounts by EXACT commit-author / public-profile e-mail.

Fixtures in tests/fixtures/github_email_pivot/: the search answers are trimmed live answers of
2026-11-26 (commit search, fuzzy user search) reshaped with documentation accounts (example-dev,
example-org-*); the /users/{login} and single-commit shapes follow the GitHub REST documentation
because the research sandbox's GitHub proxy refused those paths (P086 cond 9: re-capture from the team
network is still due; ``blocked_sandbox_proxy.json`` is that refusal).
"""

from __future__ import annotations

import copy
import json
from urllib.parse import urlencode

from tests.fakes import FakeHttp, module_fixture, run_module
from v3lum.core.models import Status
from v3lum.modules.email.github_email_pivot import (
    GithubEmailPivot,
    commit_verified,
    parse_commit_search,
    placeholder_action,
)

MOD = GithubEmailPivot
API = "https://api.github.com"
OWN = "dev@acme.com.br"  # a non-generic address (documentation-style; never sent anywhere)


def fx(name):
    return module_fixture(MOD, name)


def commits_url(email):
    return f"{API}/search/commits?" + urlencode({"q": f"author-email:{email}", "sort": "author-date", "order": "desc", "per_page": 100})


def users_url(email):
    return f"{API}/search/users?" + urlencode({"q": f"{email} in:email", "per_page": 10})


def env(http, method, url, name, **kw):
    """Route a fixture: envelope fixtures carry status/headers/body, the others are 200 JSON bodies."""
    data = fx(name)
    if isinstance(data, dict) and data.get("_envelope"):
        body = data.get("body")
        if isinstance(body, (dict, list)):
            return http.add(method, url, status=data["status"], json=body, headers=data.get("headers"), **kw)
        return http.add(method, url, status=data["status"], text=body or "", headers=data.get("headers"), **kw)
    return http.add(method, url, json=data, **kw)


def with_email(data, old, new):
    return json.loads(json.dumps(data).replace(old, new))


def test_commit_author_match_is_possible_and_minimised():
    email = "dev@example.com"
    http = FakeHttp()
    env(http, "GET", commits_url(email), "commits_ok.json")
    env(http, "GET", users_url(email), "users_empty.json")
    env(http, "GET", f"{API}/repos/example-org/example-repo/commits/a544af123662c61ae0664b4d41457639d24ed7f1", "commit_verified.json")
    res = run_module(MOD, f"email:{email}", http)
    assert res.status is Status.OK
    accounts = res.attributes["github_accounts"]
    assert [a["login"] for a in accounts] == ["example-dev"]
    acc = accounts[0]
    assert acc["commits"] == 2 and acc["repos"] == ["example-org/another-repo", "example-org/example-repo"]
    # example.com is a generic (IANA example) domain: searched but capped at POSSIBLE even with a verified commit
    assert acc["confidence"] == "possible" and acc["verified_commit"] is True
    summary = res.attributes["github_commit_search"]
    assert summary["unlinked_commits"] == 1 and summary["discarded_non_exact"] == 1
    assert summary["unlinked_repos"] == ["example-org/legacy-repo"]
    pivots = {(p.entity.type.value, p.entity.value): p for p in res.pivots}
    assert set(pivots) == {("username", "example-dev"), ("url", "https://github.com/example-dev")}
    assert all(p.expand is False for p in res.pivots)
    blob = json.dumps([res.attributes, [f.to_dict() for f in res.findings], res.raw], default=str)
    for dropped in ("Example Dev", "Example commit message", "example-other", "other@example.com"):
        assert dropped not in blob  # cond 7: no names, messages or non-exact matches
    finding = res.findings[0]
    assert finding.label.value == "possible" and finding.severity.label == "info"
    http.assert_hosts_within(MOD)


def test_verified_commit_gives_probable_for_a_non_generic_address():
    http = FakeHttp()
    http.add("GET", commits_url(OWN), json=with_email(fx("commits_ok.json"), "dev@example.com", OWN))
    env(http, "GET", users_url(OWN), "users_empty.json")
    env(http, "GET", f"{API}/repos/example-org/example-repo/commits/a544af123662c61ae0664b4d41457639d24ed7f1", "commit_verified.json")
    res = run_module(MOD, f"email:{OWN}", http)
    acc = res.attributes["github_accounts"][0]
    assert acc["confidence"] == "probable" and acc["verified_commit"] is True
    assert res.findings[0].label.value == "probable"
    assert "signature-verified" in res.findings[0].criterion
    assert all(f.label.value != "confirmed" for f in res.findings)  # cond 5: never CONFIRMED


def test_unverified_commit_only_match_stays_possible():
    unsigned = copy.deepcopy(fx("commit_verified.json"))
    unsigned["commit"]["verification"]["verified"] = False
    http = FakeHttp()
    http.add("GET", commits_url(OWN), json=with_email(fx("commits_ok.json"), "dev@example.com", OWN))
    env(http, "GET", users_url(OWN), "users_empty.json")
    http.add("GET", f"{API}/repos/example-org/example-repo/commits/a544af123662c61ae0664b4d41457639d24ed7f1", json=unsigned)
    res = run_module(MOD, f"email:{OWN}", http)
    assert res.attributes["github_accounts"][0]["confidence"] == "possible"
    assert "self-asserted" in res.findings[0].criterion


def test_public_profile_email_confirms_a_user_search_hit():
    http = FakeHttp()
    env(http, "GET", commits_url(OWN), "commits_empty.json")
    env(http, "GET", users_url(OWN), "users_exact.json")
    http.add("GET", f"{API}/users/example-dev", json=with_email(fx("profile_match.json"), "Dev@example.com", "Dev@Acme.com.br"))
    res = run_module(MOD, f"email:{OWN}", http)
    assert res.status is Status.OK
    acc = res.attributes["github_accounts"][0]
    assert acc["login"] == "example-dev" and acc["basis"] == "profile_email" and acc["confidence"] == "probable"
    blob = json.dumps([res.attributes, res.raw, [f.to_dict() for f in res.findings]], default=str)
    for dropped in ("Sao Paulo", "bio text", "Example Org", "exampledev", "blog.example.net"):
        assert dropped not in blob  # profile fields other than the e-mail check are never kept


def test_fuzzy_user_search_hits_are_discarded():
    email = "test@example.com"
    http = FakeHttp()
    env(http, "GET", commits_url(email), "commits_empty.json")
    env(http, "GET", users_url(email), "users_fuzzy.json")
    env(http, "GET", f"{API}/users/example-user-3", "profile_no_email.json")
    env(http, "GET", f"{API}/users/example-org-1", "profile_other_email.json")
    res = run_module(MOD, f"email:{email}", http)
    assert res.status is Status.EMPTY and not res.pivots and not res.findings
    assert res.raw["user_search"]["confirmed"] == 0
    assert res.raw["user_search"]["discarded_non_exact"] == 4  # 2 checked (keyless budget) + 2 never confirmed


def test_placeholder_accounts_are_never_reported():
    email = "old-dev@acme.com.br"
    data = with_email(fx("commits_placeholder.json"), "octocat@github.com", email)
    http = FakeHttp().add("GET", commits_url(email), json=data)
    env(http, "GET", users_url(email), "users_empty.json")
    res = run_module(MOD, f"email:{email}", http)
    assert res.status is Status.EMPTY and not res.pivots
    assert res.attributes["github_commit_search"]["placeholder_logins"] == ["invalid-email-address"]


def test_github_placeholder_address_is_ignored_without_a_request():
    http = FakeHttp()
    res = run_module(MOD, "email:octocat@github.com", http)
    assert res.status is Status.SKIPPED and res.reason_code == "not_applicable"
    assert http.calls == []
    assert placeholder_action("noreply@github.com")[0] == "ignore"
    assert placeholder_action("admin@acme.com.br")[0] == "downweight"
    assert placeholder_action(OWN) is None


def test_noreply_address_is_decoded_locally():
    http = FakeHttp()
    res = run_module(MOD, "email:1000001+example-dev@users.noreply.github.com", http)
    assert http.calls == []
    assert res.status is Status.OK
    assert res.attributes["noreply_accounts"] == [{"handle": "example-dev", "id": 1000001}]
    assert {p.entity.value for p in res.pivots} == {"example-dev", "https://github.com/example-dev"}
    assert all(p.expand is False for p in res.pivots)


def test_team_token_goes_in_the_authorization_header():
    http = FakeHttp()
    http.add("GET", commits_url(OWN), json=fx("commits_empty.json"), match_headers={"Authorization": "Bearer ghp_fixturetoken0000000000000000000000"})
    http.add("GET", users_url(OWN), json=fx("users_empty.json"), match_headers={"Authorization": "Bearer ghp_fixturetoken0000000000000000000000"})
    res = run_module(MOD, f"email:{OWN}", http, keys={"github": "ghp_fixturetoken0000000000000000000000"})
    assert res.status is Status.EMPTY
    assert "ghp_fixturetoken" not in json.dumps(res.to_dict(), default=str)


def test_primary_rate_limit_is_could_not_verify_with_the_token_hint():
    http = FakeHttp()
    env(http, "GET", commits_url(OWN), "rate_limited_primary.json")
    res = run_module(MOD, f"email:{OWN}", http)
    assert res.status is Status.RATE_LIMITED and res.reason_code == "rate_limited"
    assert "token" in res.error.lower()


def test_secondary_rate_limit_and_429_are_rate_limited():
    http = FakeHttp()
    env(http, "GET", commits_url(OWN), "rate_limited_secondary.json")
    assert run_module(MOD, f"email:{OWN}", http).status is Status.RATE_LIMITED
    http2 = FakeHttp().add("GET", commits_url(OWN), status=429, json={"message": "API rate limit exceeded"})
    assert run_module(MOD, f"email:{OWN}", http2).status is Status.RATE_LIMITED


def test_proxy_refusal_on_profile_path_is_blocked_never_absent():
    http = FakeHttp()
    env(http, "GET", commits_url(OWN), "commits_empty.json")
    env(http, "GET", users_url(OWN), "users_exact.json")
    env(http, "GET", f"{API}/users/example-dev", "blocked_sandbox_proxy.json")
    res = run_module(MOD, f"email:{OWN}", http)
    assert res.status is Status.BLOCKED  # keyless 403: could not verify, never 'no public e-mail'


def test_server_errors_and_validation_failures_are_errors():
    http = FakeHttp()
    env(http, "GET", commits_url(OWN), "validation_failed.json")
    assert run_module(MOD, f"email:{OWN}", http).status is Status.ERROR
    http2 = FakeHttp().add("GET", commits_url(OWN), status=502, text="bad gateway", times=3)
    assert run_module(MOD, f"email:{OWN}", http2).status is Status.ERROR


def test_malformed_and_unexpected_answers_are_errors():
    http = FakeHttp().add("GET", commits_url(OWN), text=fx("malformed.txt"), headers={"content-type": "application/json"})
    assert run_module(MOD, f"email:{OWN}", http).status is Status.ERROR
    http2 = FakeHttp().add("GET", commits_url(OWN), json={"message": "unexpected"})
    assert run_module(MOD, f"email:{OWN}", http2).status is Status.ERROR


def test_parsers_are_defensive():
    assert parse_commit_search(None, OWN)["ok"] is False
    assert parse_commit_search({"items": [None, 3, {"commit": "x"}]}, OWN)["discarded_non_exact"] == 1
    assert commit_verified({"commit": {"verification": {"verified": "true"}}}) is False
    assert commit_verified([]) is False


def test_failed_profile_check_leaves_the_candidate_unconfirmed_and_keeps_commit_results():
    http = FakeHttp()
    http.add("GET", commits_url(OWN), json=with_email(fx("commits_ok.json"), "dev@example.com", OWN))
    http.add("GET", users_url(OWN), json={"total_count": 1, "incomplete_results": False,
                                          "items": [{"login": "example-org-1", "id": 2000001, "type": "Organization"}]})
    env(http, "GET", f"{API}/users/example-org-1", "blocked_sandbox_proxy.json")
    env(http, "GET", f"{API}/repos/example-org/example-repo/commits/a544af123662c61ae0664b4d41457639d24ed7f1", "commit_verified.json")
    res = run_module(MOD, f"email:{OWN}", http)
    assert res.status is Status.OK
    assert [a["login"] for a in res.attributes["github_accounts"]] == ["example-dev"]
    assert "could not be checked" in res.error


def test_rate_limit_during_profile_checks_is_a_partial_run():
    http = FakeHttp()
    http.add("GET", commits_url(OWN), json=with_email(fx("commits_ok.json"), "dev@example.com", OWN))
    env(http, "GET", users_url(OWN), "users_exact.json")
    env(http, "GET", f"{API}/users/example-dev", "rate_limited_primary.json")
    res = run_module(MOD, f"email:{OWN}", http)
    assert res.status is Status.OK and res.partial and res.stop_reason == "rate_limited"
    assert res.attributes["github_accounts"][0]["confidence"] == "possible"
