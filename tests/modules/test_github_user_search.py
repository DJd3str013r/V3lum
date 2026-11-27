"""Offline tests of github_user_search (P111 cond 2): opt-in person-name search over REST /search/users,
POSSIBLE candidates never expanded, the shared GitHub budget and every could-not-verify status.

Fixtures: tests/fixtures/github_user_search/ (a real minimised search capture plus DOC-SHAPED error
answers; see the README there).
"""

from __future__ import annotations

import pytest

from tests.fakes import FakeHttp, make_runtime, module_fixture, run_module
from v3lum.core.entities import EntityType as T
from v3lum.core.models import Status
from v3lum.modules.username_social.github_user import GITHUB_ANON_COVERAGE_LINE, GithubUser
from v3lum.modules.username_social.github_user_search import GithubUserSearch, search_query

API = "https://api.github.com/search/users"
NAME = "Example Developer"
FUTURE = 1795698000


def search_url(name: str = NAME) -> str:
    from urllib.parse import urlencode

    return API + "?" + urlencode({"q": search_query(name), "per_page": 10})


def fx(name: str):
    return module_fixture(GithubUserSearch, name)


def add_env(http: FakeHttp, url: str, name: str) -> FakeHttp:
    e = fx(name)
    return http.add("GET", url, status=e["status"], body=e["body"].encode(), headers=e["headers"])


def search_rate(remaining: int = 9) -> dict[str, str]:
    return {"x-ratelimit-limit": "10", "x-ratelimit-remaining": str(remaining), "x-ratelimit-reset": str(FUTURE),
            "x-ratelimit-resource": "search"}


def test_candidates_are_possible_and_never_expanded():
    http = FakeHttp().add("GET", search_url(), json=fx("ok.json"), headers=search_rate())
    res = run_module(GithubUserSearch, f"person_name:{NAME}", http)
    assert res.status is Status.OK, res.error
    assert [(p.entity.type, p.entity.value) for p in res.pivots] == [
        (T.SOCIAL_ACCOUNT, "github:octocat"), (T.SOCIAL_ACCOUNT, "github:example-user-1"), (T.SOCIAL_ACCOUNT, "github:example-user-2")]
    for p in res.pivots:
        assert p.relation == "name_search_candidate" and p.expand is False and p.confidence_label.value == "possible"
        assert "does not prove identity" in p.note
    search = res.attributes["name_search"]
    assert search["total_count"] == 432 and search["incomplete"] is False and len(search["candidates"]) == 3
    finding = res.findings[0]
    assert finding.severity.label == "info" and "weak_signal" in finding.tags
    assert http.urls() == [search_url()]  # REST /search/users only, never the github.com/search HTML page
    http.assert_hosts_within(GithubUserSearch)


def test_empty_search_is_empty():
    http = FakeHttp().add("GET", search_url(), json=fx("empty.json"), headers=search_rate())
    res = run_module(GithubUserSearch, f"person_name:{NAME}", http)
    assert res.status is Status.EMPTY and res.pivots == []


def test_incomplete_search_is_noted():
    http = FakeHttp().add("GET", search_url(), json=fx("incomplete.json"), headers=search_rate())
    res = run_module(GithubUserSearch, f"person_name:{NAME}", http)
    assert res.status is Status.OK and "incomplete" in res.error and res.attributes["name_search"]["incomplete"] is True


def test_search_rate_limit_is_rate_limited_with_the_coverage_line():
    http = FakeHttp()
    add_env(http, search_url(), "rate_limited.http.json")
    res = run_module(GithubUserSearch, f"person_name:{NAME}", http)
    assert res.status is Status.RATE_LIMITED and res.error == GITHUB_ANON_COVERAGE_LINE


def test_spent_search_budget_refuses_before_sending():
    http = FakeHttp().add("GET", search_url(), json=fx("ok.json"), headers=search_rate(0))
    rt = make_runtime(http)
    assert run_module(GithubUserSearch, f"person_name:{NAME}", runtime=rt).status is Status.OK
    again = run_module(GithubUserSearch, "person_name:Another Example", runtime=rt)
    assert again.status is Status.RATE_LIMITED and len(http.calls) == 1


def test_validation_failure_and_html_are_errors():
    http = FakeHttp()
    add_env(http, search_url(), "validation_failed.http.json")
    assert run_module(GithubUserSearch, f"person_name:{NAME}", http).status is Status.ERROR
    http2 = FakeHttp().add("GET", search_url(), text="<!DOCTYPE html><html><title>x</title></html>")
    assert run_module(GithubUserSearch, f"person_name:{NAME}", http2).status is Status.ERROR


@pytest.mark.parametrize("name,query", [
    ("Example Developer", '"Example Developer" in:name type:user'),
    ('Ex"ample  Dev', '"Ex ample Dev" in:name type:user'),
    ("John type:org", '"John" in:name type:user'),
    ("ab", None), ("", None),
])
def test_query_quotes_the_name_and_drops_qualifiers(name, query):
    assert search_query(name) == query


def test_short_names_are_not_applicable():
    http = FakeHttp()
    res = run_module(GithubUserSearch, "person_name:Al", http)
    assert res.status is Status.SKIPPED and http.calls == []


def test_metadata_is_opt_in_and_shares_the_github_client():
    assert GithubUserSearch.default_enabled is False and GithubUserSearch.run_on == "seeds"
    assert GithubUserSearch.terms == "key-terms" and GithubUserSearch.provider == GithubUser.provider
    assert GithubUserSearch.hosts == ("api.github.com",) and GithubUserSearch.max_requests == 1
    assert GithubUserSearch.min_interval <= GithubUser.min_interval  # never slows the shared host for other GitHub modules
