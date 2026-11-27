"""Offline tests of github_user (P111): REST profile, keys, seed-only commit e-mails, noreply decoding,
the shared client and budget, the keyless coverage line and every could-not-verify status.

Fixtures: tests/fixtures/github_user/ (DOC-SHAPED GitHub bodies until the P111 cond 10 recapture from
the team network, a real proxy-403 capture, real public SSH host keys and generated throwaway GPG keys;
see the README there). No real token is used: the test key is not GitHub-shaped.
"""

from __future__ import annotations

import json

import pytest

from tests.fakes import FakeHttp, make_ctx, make_runtime, module_fixture, run_module
from v3lum.core.context import ScanOptions
from v3lum.core.entities import Entity
from v3lum.core.entities import EntityType as T
from v3lum.core.models import Status
from v3lum.core.orgprofile import OrgProfile
from v3lum.modules.username_social import github_user as gh
from v3lum.modules.username_social.github_user import GITHUB_ANON_COVERAGE_LINE, GithubUser

API = "https://api.github.com"
WEB = "https://github.com"
LOGIN = "example-dev"
FUTURE = 1795698000  # after the FakeClock start (2026-11-26T12:00:00Z = 1795694400)
TEST_KEY = "test-token-not-a-real-github-token"


def fx(name: str):
    return module_fixture(GithubUser, name)


def rate(remaining: int = 55, limit: int = 60, resource: str = "core", reset: int = FUTURE) -> dict[str, str]:
    return {"x-ratelimit-limit": str(limit), "x-ratelimit-remaining": str(remaining), "x-ratelimit-reset": str(reset),
            "x-ratelimit-resource": resource}


def add_env(http: FakeHttp, url: str, name: str, **kw) -> FakeHttp:
    e = fx(name)
    return http.add("GET", url, status=e["status"], body=e["body"].encode(), headers=e["headers"], **kw)


def text(http: FakeHttp, url: str, name: str | None = None, *, body: str | None = None, status: int = 200) -> FakeHttp:
    content = fx(name) if name else body
    return http.add("GET", url, status=status, body=(content or "").encode(), headers={"content-type": "text/plain; charset=utf-8"})


def seed_http(*, user=None, events="events_ok.json", commits="commits_ok.json") -> FakeHttp:
    http = FakeHttp()
    http.add("GET", f"{API}/users/{LOGIN}", json=user or fx("user_ok.json"), headers=rate(59))
    text(http, f"{WEB}/{LOGIN}.keys", "keys_ok.txt")
    text(http, f"{WEB}/{LOGIN}.gpg", "gpg_ok.txt")
    if events:
        http.add("GET", f"{API}/users/{LOGIN}/events/public?per_page=100", json=fx(events), headers=rate(58))
    if commits:
        http.add("GET", f"{API}/repos/{LOGIN}/tooling/commits?author={LOGIN}&per_page=30", json=fx(commits), headers=rate(57))
    return http


def dump(res) -> str:
    data = {"attributes": res.attributes, "raw": res.raw, "error": res.error, "findings": [f.to_dict() for f in res.findings],
            "pivots": [p.to_dict() for p in res.pivots], "links": res.links}
    return json.dumps(data, ensure_ascii=False, default=str)


def pivots(res, relation: str | None = None) -> set[tuple[T, str]]:
    return {(p.entity.type, p.entity.value) for p in res.pivots if relation is None or p.relation == relation}


# ======================================================================================
# the seed path (cond 1, 6-8)
# ======================================================================================


def test_seed_profile_keys_events_and_commit_emails():
    http = seed_http()
    res = run_module(GithubUser, f"username:{LOGIN}", http)
    assert res.status is Status.OK, res.error
    a = res.attributes
    assert a["presence"]["state"] == "found" and a["account_id"] == 12345678 and a["account_type"] == "User"
    assert a["display_name"] == "Example Developer" and a["location"] == "São Paulo, Brazil" and a["followers"] == 34
    assert a["website"] == "https://example.com/blog" and a["created"] == "2015-03-02T12:00:00Z"
    # .keys: OpenSSH SHA-256 fingerprints (known answers: GitHub's documented host-key fingerprints)
    assert [(k["type"], k["fingerprint"], k["bits"]) for k in a["ssh_keys"]] == [
        ("ssh-ed25519", "SHA256:+DiY3wvvV6TuJJhbpZisF/zLDA0zPMSvHdkr4UvCOqU", 256),
        ("ecdsa-sha2-nistp256", "SHA256:p2QAMXNIC1TJYWeIOttrVc98/R1BUFWu3/LiyKgUfQM", 256),
        ("ssh-rsa", "SHA256:uNiVztksCsDhcc0u9e8BujQXVUpKZIDTMczCvj3tD2s", 3072)]
    # .gpg: OpenPGP fingerprints cross-checked with GnuPG, UIDs kept for the seed
    assert [k["fingerprint"] for k in a["gpg_keys"]] == ["25FBB5CEE76B105AF5A1923FAC12181FB41C0275", "FCDF969C363CD9A9C08E26C4A03927FE115EA357"]
    assert a["gpg_keys"][0]["uids"][1] == {"name": "Example Developer", "email": "dev@example.com"}
    assert pivots(res, "pgp_key") == {(T.PGP_FINGERPRINT, "25FBB5CEE76B105AF5A1923FAC12181FB41C0275"),
                                      (T.PGP_FINGERPRINT, "FCDF969C363CD9A9C08E26C4A03927FE115EA357")}
    # commit e-mails grouped per address (cond 7) and GPG UID e-mails (cond 8)
    emails = {g["email"]: g for g in a["commit_emails"]}
    assert set(emails) == {"dev@example.com", "dev@work.example.net", "ops@example.org"}
    dev = emails["dev@example.com"]
    assert (dev["commits"], dev["first"], dev["last"]) == (3, "2026-09-10T08:00:00Z", "2026-11-20T13:05:00Z")
    assert dev["sources"] == ["gpg_uid", "event", "commits_api"]
    assert pivots(res, "commit_email") == {(T.EMAIL, "dev@example.com"), (T.EMAIL, "dev@work.example.net")}
    assert pivots(res, "gpg_uid_email") == {(T.EMAIL, "ops@example.org")}
    for p in res.pivots:
        if p.entity.type is T.EMAIL:
            assert p.expand is False and p.confidence_label.value == "probable"  # A4: never auto-sent to breach modules
    # noreply decoded into an account link of the seed itself, never an e-mail (cond 6)
    assert a["noreply_accounts"] == [{"handle": "example-dev", "id": 12345678}]
    # profile pivots
    assert (T.URL, "https://example.com/blog") in pivots(res, "links_to") and (T.DOMAIN, "example.com") in pivots(res, "links_to")
    assert pivots(res, "uses_email") == {(T.EMAIL, "dev@example.com")}
    assert pivots(res, "has_account") == {(T.SOCIAL_ACCOUNT, "x:example_dev")}
    assert pivots(res, "declared_org") == {(T.SOCIAL_ACCOUNT, "github:example-org"), (T.SOCIAL_ACCOUNT, "github:example-labs")}
    assert a["activity_level"] in ("inactive", "low", "active", "very_active") and "last_activity" in a
    assert res.findings and res.findings[0].title == "E-mail addresses in the account's public commits"
    assert res.requests <= GithubUser.max_requests
    http.assert_hosts_within(GithubUser)


def test_third_party_co_author_system_and_noreply_addresses_never_surface():
    res = run_module(GithubUser, f"username:{LOGIN}", seed_http())
    blob = dump(res)
    for never in ("other@example.org", "third@example.net", "unlinked@example.org", "noreply@github.com", "users.noreply.github.com",
                  "Other Contributor", "Third Person"):
        assert never not in blob, never
    assert res.raw["commit_email_rules"]["dropped"] == {"system address": 1}


def test_patch_fallback_when_the_commits_api_links_nothing():
    user = dict(fx("user_ok.json"), name="Exemplo Desenvolvedor São")
    http = seed_http(user=user, commits="commits_empty.json")
    text(http, f"{WEB}/{LOGIN}/tooling/commit/1a2b3c4d5e6f708192a3b4c5d6e7f8091a2b3c4d.patch", "patch_ok.txt")
    res = run_module(GithubUser, f"username:{LOGIN}", http)
    assert res.status is Status.OK, res.error
    emails = {g["email"]: g for g in res.attributes["commit_emails"]}
    assert "patch" in emails["dev@example.com"]["sources"]
    assert "other@example.org" not in dump(res)  # Co-authored-by trailer: counted, never kept
    assert any(u.endswith(".patch") for u in http.urls())


def test_case_entity_addresses_expand():
    options = ScanOptions(seed_tlp={"email:dev@work.example.net": "amber", f"username:{LOGIN}": "amber"})
    res = run_module(GithubUser, f"username:{LOGIN}", seed_http(), options=options)
    by = {p.entity.value: p for p in res.pivots if p.relation == "commit_email"}
    assert by["dev@work.example.net"].expand is True and by["dev@example.com"].expand is False


def test_org_domain_address_in_commits_is_a_low_finding():
    org = OrgProfile.from_dict({"domains": [{"name": "work.example.net", "verification": "confirmed"}]})
    res = run_module(GithubUser, f"username:{LOGIN}", seed_http(), org_profile=org)
    finding = next(f for f in res.findings if f.title == "Organisation e-mail address in public GitHub commits")
    assert finding.severity.label == "low" and finding.data["emails"] == ["dev@work.example.net"] and finding.criterion


def test_organisation_account_reads_the_profile_only():
    http = FakeHttp()
    http.add("GET", f"{API}/users/example-org", json=fx("org_ok.json"), headers=rate(59))
    res = run_module(GithubUser, "username:example-org", http)
    assert res.status is Status.OK
    assert res.attributes["account_type"] == "Organization"
    assert http.urls() == [f"{API}/users/example-org"]  # no keys, events or commit e-mails for organisations
    assert not any(p.entity.type is T.EMAIL for p in res.pivots)  # noreply@github.com is a system address


# ======================================================================================
# pivots and the token (cond 4-6)
# ======================================================================================


def test_pivot_without_token_needs_key_with_the_one_coverage_line():
    http = FakeHttp()
    res = run_module(GithubUser, f"username:{LOGIN}", http, is_seed=False)
    assert res.status is Status.NEEDS_KEY and res.error == GITHUB_ANON_COVERAGE_LINE
    assert http.calls == []


def test_pivot_with_token_reads_profile_and_keys_only_and_sends_the_key_to_the_api_only():
    http = FakeHttp()
    http.add("GET", f"{API}/users/{LOGIN}", json=fx("user_ok.json"), headers=rate(4990, 5000),
             match_headers={"authorization": f"Bearer {TEST_KEY}", "x-github-api-version": "2022-11-28"})
    text(http, f"{WEB}/{LOGIN}.keys", "keys_ok.txt")
    text(http, f"{WEB}/{LOGIN}.gpg", "gpg_ok.txt")
    res = run_module(GithubUser, f"username:{LOGIN}", http, is_seed=False, keys={"github": TEST_KEY})
    assert res.status is Status.OK, res.error
    assert "commit_emails" not in res.attributes and "activity_level" not in res.attributes  # seed accounts only (cond 6)
    assert all(u["email"] is None for k in res.attributes["gpg_keys"] for u in k["uids"])  # UID e-mails: seed rules (cond 8)
    assert not any(p.relation in ("commit_email", "gpg_uid_email") for p in res.pivots)
    web_calls = [c for c in http.calls if c["url"].startswith(WEB + "/")]
    assert web_calls and all("authorization" not in {k.lower() for k in c["headers"]} for c in web_calls)
    assert TEST_KEY not in dump(res)


def test_bad_credentials_with_a_key_are_needs_key():
    http = FakeHttp()
    add_env(http, f"{API}/users/{LOGIN}", "bad_credentials.http.json")
    res = run_module(GithubUser, f"username:{LOGIN}", http, keys={"github": TEST_KEY})
    assert res.status is Status.NEEDS_KEY and res.reason_code == "needs_key"


def test_scoped_classic_token_is_reported():
    http = seed_http(events=None, commits=None)
    http.routes[0].headers["x-oauth-scopes"] = "repo, read:org"
    http.add("GET", f"{API}/users/{LOGIN}/events/public?per_page=100", json=[], headers=rate(57))
    res = run_module(GithubUser, f"username:{LOGIN}", http, keys={"github": TEST_KEY})
    assert res.status is Status.OK and "classic token with scopes (read:org, repo)" in res.error


# ======================================================================================
# statuses (cond 3, rule 5)
# ======================================================================================


def test_404_is_a_documented_absence():
    http = FakeHttp()
    add_env(http, f"{API}/users/{LOGIN}", "not_found.http.json")
    res = run_module(GithubUser, f"username:{LOGIN}", http)
    assert res.status is Status.EMPTY
    assert res.attributes["presence"]["state"] == "absent" and "404" in res.attributes["presence"]["marker"]


def test_403_rate_limit_is_rate_limited_with_the_coverage_line():
    http = FakeHttp()
    add_env(http, f"{API}/users/{LOGIN}", "rate_limited.http.json")
    res = run_module(GithubUser, f"username:{LOGIN}", http)
    assert res.status is Status.RATE_LIMITED and res.reason_code == "rate_limited"
    assert res.error == GITHUB_ANON_COVERAGE_LINE


def test_secondary_rate_limit_429_is_rate_limited_never_retried_for_long_waits():
    http = FakeHttp()
    add_env(http, f"{API}/users/{LOGIN}", "secondary_rate_limited.http.json")
    res = run_module(GithubUser, f"username:{LOGIN}", http, keys={"github": TEST_KEY})
    assert res.status is Status.RATE_LIMITED and len(http.calls) == 1


def test_proxy_or_keyless_403_is_blocked_never_absent():
    http = FakeHttp()
    add_env(http, f"{API}/users/{LOGIN}", "blocked_proxy.http.json")
    res = run_module(GithubUser, f"username:{LOGIN}", http)
    assert res.status is Status.BLOCKED and res.reason_code == "challenge"
    assert "presence" not in res.attributes


def test_server_errors_are_errors():
    http = FakeHttp()
    http.add("GET", f"{API}/users/{LOGIN}", status=502, text="bad gateway")
    res = run_module(GithubUser, f"username:{LOGIN}", http)
    assert res.status is Status.ERROR


def test_html_page_in_a_200_is_an_error():
    http = FakeHttp()
    http.add("GET", f"{API}/users/{LOGIN}", text=fx("html_instead_of_json.html"))
    res = run_module(GithubUser, f"username:{LOGIN}", http)
    assert res.status is Status.ERROR and "HTML page instead of data" in res.error


@pytest.mark.parametrize("body", ["{broken", "[1, 2]", '{"message": "x"}'])
def test_malformed_or_unexpected_json_is_an_error(body):
    http = FakeHttp()
    http.add("GET", f"{API}/users/{LOGIN}", body=body.encode(), headers={"content-type": "application/json"})
    res = run_module(GithubUser, f"username:{LOGIN}", http)
    assert res.status is Status.ERROR


def test_secondary_endpoint_failures_are_recorded_per_source():
    http = FakeHttp()
    http.add("GET", f"{API}/users/{LOGIN}", json=fx("user_ok.json"), headers=rate(59))
    text(http, f"{WEB}/{LOGIN}.keys", body="bad gateway", status=502)
    add_env(http, f"{WEB}/{LOGIN}.gpg", "keys_not_found.http.json")
    http.add("GET", f"{API}/users/{LOGIN}/events/public?per_page=100", json=fx("events_empty.json"), headers=rate(58))
    res = run_module(GithubUser, f"username:{LOGIN}", http)
    assert res.status is Status.OK
    web = res.source_statuses["github.github_user_web"]
    assert web["status"] == "error" and ".keys" in web["reason"]
    assert "ssh_keys" not in res.attributes and "gpg_keys" not in res.attributes


def test_empty_repository_409_and_empty_keys_are_not_errors():
    http = seed_http(commits=None)
    add_env(http, f"{API}/repos/{LOGIN}/tooling/commits?author={LOGIN}&per_page=30", "commits_repo_empty.http.json")
    text(http, f"{WEB}/{LOGIN}/tooling/commit/1a2b3c4d5e6f708192a3b4c5d6e7f8091a2b3c4d.patch", "patch_html.html")
    res = run_module(GithubUser, f"username:{LOGIN}", http)
    assert res.status is Status.OK
    assert "github.github_user_api" not in res.source_statuses
    assert "HTML page" in res.source_statuses["github.github_user_web"]["reason"]  # an HTML patch is never parsed


# ======================================================================================
# the shared budget (cond 3)
# ======================================================================================


def test_spent_budget_stops_the_run_before_sending_and_keeps_partial_data():
    http = FakeHttp()
    http.add("GET", f"{API}/users/{LOGIN}", json=fx("user_ok.json"), headers=rate(0))
    text(http, f"{WEB}/{LOGIN}.keys", "keys_ok.txt")
    text(http, f"{WEB}/{LOGIN}.gpg", "gpg_ok.txt")
    rt = make_runtime(http)
    res = run_module(GithubUser, f"username:{LOGIN}", runtime=rt)
    assert res.status is Status.OK and res.partial is True and res.stop_reason == "rate_limited"
    assert not any("/events/" in u for u in http.urls())  # X-RateLimit-Remaining honoured: nothing sent
    again = run_module(GithubUser, "username:octocat", runtime=rt)  # same runtime: the shared budget refuses at once
    assert again.status is Status.RATE_LIMITED and GITHUB_ANON_COVERAGE_LINE in again.error
    assert len(http.calls) == 3


def test_budget_is_one_per_runtime_and_resets_with_the_window():
    rt = make_runtime(FakeHttp())
    a, b = make_ctx(GithubUser, runtime=rt), make_ctx(GithubUser, runtime=rt)
    assert gh.github_budget(a) is gh.github_budget(b)
    assert gh.github_budget(make_ctx(GithubUser)) is not gh.github_budget(a)
    budget = gh.GitHubBudget()
    budget.note(rate(0, reset=100), now=50)
    with pytest.raises(gh.RateLimited):
        budget.check("core", 60, keyed=False)
    budget.check("core", 150, keyed=False)  # the window reset: allowed again
    budget.note(rate(400, limit=5000), now=50)
    with pytest.raises(gh.RateLimited):
        budget.check("core", 60, keyed=True, reserve=500)  # pivots keep the seed reserve


# ======================================================================================
# inputs, helpers and the doctor check
# ======================================================================================


@pytest.mark.parametrize("entity,login", [
    ("username:example-dev", "example-dev"), ("url:https://github.com/example-dev/tooling", "example-dev"),
    ("social_account:github:example-dev", "example-dev"), ("social_account:x:example_dev", None),
    ("username:bad.login", None), ("url:https://example.com/example-dev", None), ("url:https://github.com/orgs/x", None),
])
def test_login_of_entities(entity, login):
    etype, _, value = entity.partition(":")
    assert gh.github_login_of(Entity.make(T.parse(etype), value)) == login


def test_non_github_inputs_are_not_applicable():
    http = FakeHttp()
    res = run_module(GithubUser, "username:bad.login", http)
    assert res.status is Status.SKIPPED and res.reason_code == "not_applicable" and http.calls == []


@pytest.mark.parametrize("email,expected", [
    ("12345678+example-dev@users.noreply.github.com", {"id": 12345678, "login": "example-dev", "bot": False, "url": "https://github.com/example-dev"}),
    ("example-dev@users.noreply.github.com", {"id": None, "login": "example-dev", "bot": False, "url": "https://github.com/example-dev"}),
    ("41898282+github-actions[bot]@users.noreply.github.com", {"id": 41898282, "login": "github-actions[bot]", "bot": True, "url": None}),
    ("dev@example.com", None), (None, None), ("", None), (12, None),
])
def test_decode_noreply(email, expected):
    assert gh.decode_noreply(email) == expected


def test_noreply_regex_is_the_fc6_form_and_system_addresses_are_dropped():
    assert gh.NOREPLY_RE.pattern == r"^(\d+)\+([A-Za-z0-9-]+)@users\.noreply\.github\.com$"
    for email in ("noreply@github.com", "root@localhost", "dev@build-host.local", "someone@nodot", "not-an-email"):
        assert gh.system_email_reason(email)
    assert gh.system_email_reason("dev@example.com") is None
    assert gh.system_email_reason("12345678+example-dev@users.noreply.github.com") is None


def test_key_parsers_drop_blobs_comments_and_junk():
    k = gh.parse_ssh_keys(fx("keys_with_comments.txt"))
    assert [x["fingerprint"] for x in k["keys"]] == ["SHA256:+DiY3wvvV6TuJJhbpZisF/zLDA0zPMSvHdkr4UvCOqU",
                                                     "SHA256:p2QAMXNIC1TJYWeIOttrVc98/R1BUFWu3/LiyKgUfQM"]
    assert k["comments_dropped"] == 2 and k["invalid_lines"] == 2 and "Example User" not in json.dumps(k)
    assert gh.parse_ssh_keys(fx("keys_empty.txt"))["reason"] == "no public SSH keys"
    assert gh.parse_ssh_keys(fx("patch_html.html"))["ok"] is False
    assert gh.parse_gpg_keys(fx("gpg_empty.txt"))["reason"] == "no GPG keys uploaded"
    bad = gh.parse_gpg_keys(fx("gpg_malformed.txt"))
    assert bad["ok"] is False and "checksum" in bad["reason"]


def test_plain_text_endpoints_are_capped_at_1_mb():
    http = seed_http(events="events_empty.json", commits=None)
    http.routes[1].content = (fx("keys_ok.txt") + "# " + "x" * (gh.PLAINTEXT_CAP + 10)).encode()
    res = run_module(GithubUser, f"username:{LOGIN}", http)
    assert res.status is Status.OK and "1 MB cap" in res.error
    assert all(c.get("max_bytes") == gh.PLAINTEXT_CAP for c in http.calls if c["url"].startswith(WEB + "/"))


def test_activity_classifier_is_attributes_only():
    events = gh.parse_github_events(fx("events_ok.json"), LOGIN)
    a = gh.classify_activity(events, now="2026-11-26T00:00:00Z")
    assert (a["activity_level"], a["stalled_for_months"], a["estimated_contributions_year"]) == ("low", False, 32)
    old = gh.classify_activity({"contributions": 0, "last": "2025-01-01T00:00:00Z"}, now="2026-11-26T00:00:00Z")
    assert old["activity_level"] == "inactive" and old["stalled_for_months"] is True


@pytest.mark.parametrize("fn", [gh.parse_github_user, gh.parse_github_events, gh.parse_github_commits, gh.parse_github_patch,
                                gh.parse_ssh_keys, gh.parse_gpg_keys, gh.parse_github_search_users, gh.parse_github_rate_limit])
@pytest.mark.parametrize("raw", [None, 0, True, [], {}, "", b"", b"\xff" * 10, "<html><body>x</body></html>", "null", "[null]",
                                 '{"items": [null, 1, {"login": 5}]}'])
def test_parsers_never_raise_on_garbage(fn, raw):
    fn(raw)


def test_doctor_selftest_refuses_scoped_classic_tokens():
    hc = GithubUser.health_check()
    assert hc.offline is False and callable(hc.selftest)
    http = FakeHttp()
    add_env(http, f"{API}/rate_limit", "token_classic_scoped.http.json")
    result = hc.selftest(make_ctx(GithubUser, http, keys={"github": TEST_KEY}))
    assert result.status == "needs_key" and "classic token with scopes" in result.detail
    http2 = FakeHttp()
    add_env(http2, f"{API}/rate_limit", "token_classic_noscope.http.json")
    assert hc.selftest(make_ctx(GithubUser, http2, keys={"github": TEST_KEY})).status == "ok"
    http3 = FakeHttp()
    http3.add("GET", f"{API}/rate_limit", json=fx("rate_limit_ok.json"))
    assert hc.selftest(make_ctx(GithubUser, http3)).status == "ok"
    assert gh.github_token_kind("github_pat_" + "x" * 70) == "fine_grained" and gh.github_token_kind(None) == "unknown"


def test_module_metadata_matches_the_council():
    assert GithubUser.default_enabled is True and GithubUser.terms == "key-terms" and GithubUser.trust_tier == "trusted"
    assert GithubUser.optional_keys == ("github",) and GithubUser.max_requests <= 10
    assert set(GithubUser.hosts) == {"api.github.com", "github.com"} and "gitlab.com" not in GithubUser.hosts
    assert GithubUser.shares_input is True
