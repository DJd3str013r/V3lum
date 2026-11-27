"""Offline tests of gitlab_user (P103) on trimmed real GitLab.com answers (tests/fixtures/gitlab_user/)."""

from __future__ import annotations

from tests.fakes import FakeHttp, module_fixture, run_module
from v3lum.core.entities import EntityType as T
from v3lum.core.models import Status
from v3lum.modules.username_social.github_user import parse_gpg_keys, parse_ssh_keys
from v3lum.modules.username_social.gitlab_user import GitlabUser, gitlab_handle

API = "https://gitlab.com/api/v4"
TEXT = {"content-type": "text/plain; charset=utf-8"}


def env(name: str, **headers) -> dict:
    d = module_fixture("gitlab_user", name)
    return {"status": d["status"], "headers": {**d["headers"], **headers}, "text": d["body"]}


def plain(name: str) -> dict:
    return {"body": module_fixture("gitlab_user", name).encode(), "headers": TEXT}


def full_routes(http: FakeHttp, *, detail: dict | None = None, keys: dict | None = None, users_headers: dict | None = None) -> FakeHttp:
    http.add("GET", f"{API}/users?username=gitlab-bot", **env("users_ok.http.json", **(users_headers or {})))
    http.add("GET", f"{API}/users/1786152", **(detail or {"json": module_fixture("gitlab_user", "user_detail_ok.json")}))
    http.add("GET", "https://gitlab.com/gitlab-bot.keys", **(keys or plain("keys_ok.txt")))
    http.add("GET", "https://gitlab.com/gitlab-bot.gpg", **plain("gpg_ok.txt"))
    return http


def by_key(res) -> dict:
    return {(p.entity.type, p.entity.value, p.relation): p for p in res.pivots}


def test_found_user_details_and_key_fingerprints():
    http = full_routes(FakeHttp())
    res = run_module(GitlabUser, "username:gitlab-bot", http)
    assert res.status is Status.OK and not res.partial
    assert res.attributes["account_id"] == 1786152 and res.attributes["public_email"] == "dev@example.com"
    assert res.attributes["company"] == "Example Ltd" and res.attributes["job_title"] == "Engineer"
    assert res.attributes["avatar_hash"] == "be9d18f611892a738e54f2a3a171e2f9"  # Gravatar hash only (P114)
    # cond 3: the same parsers as github_user (P111): fingerprints compare byte for byte
    assert res.attributes["ssh_keys"] == parse_ssh_keys(module_fixture("gitlab_user", "keys_ok.txt"))["keys"]
    gpg = parse_gpg_keys(module_fixture("gitlab_user", "gpg_ok.txt"))
    assert [k["fingerprint"] for k in res.attributes["gpg_keys"]] == [k["fingerprint"] for k in gpg["keys"]]
    assert "Example Dev (gitlab.com)" not in str(res.attributes["ssh_keys"])  # key comments are dropped
    p = by_key(res)
    for k in gpg["keys"]:
        fp = p[(T.PGP_FINGERPRINT, k["fingerprint"], "pgp_key")]
        assert fp.confidence_label == "confirmed" and fp.expand is False
    assert p[(T.EMAIL, "dev@example.com", "gpg_uid_email")].expand is False
    assert p[(T.EMAIL, "ops@example.org", "gpg_uid_email")].expand is False
    assert p[(T.EMAIL, "dev@example.com", "email_on_profile")].confidence_label == "probable"
    assert p[(T.SOCIAL_ACCOUNT, "github:example-dev", "noreply_account")].expand is False
    assert p[(T.SOCIAL_ACCOUNT, "linkedin:example-dev", "linked_account_on_profile")].expand is False
    assert p[(T.SOCIAL_ACCOUNT, "x:exampledev", "linked_account_on_profile")].expand is False
    assert p[(T.URL, "https://example.com/", "link_on_profile")].expand is False
    assert all(pv.expand is False for pv in res.pivots if pv.entity.type in (T.EMAIL, T.SOCIAL_ACCOUNT, T.USERNAME))
    assert not [u for u in http.urls() if "@" in u]
    http.assert_hosts_within(GitlabUser)


def test_empty_list_is_absent():
    http = FakeHttp().add("GET", f"{API}/users?username=qz7k2v9m4p1w8n3x5c6b", **env("users_empty.http.json"))
    res = run_module(GitlabUser, "username:qz7k2v9m4p1w8n3x5c6b", http)
    assert res.status is Status.EMPTY and res.attributes["presence"]["state"] == "absent"
    assert len(http.calls) == 1


def test_keyless_403_on_details_keeps_the_basic_profile():
    http = full_routes(FakeHttp(), detail=env("user_detail_forbidden.http.json"))
    res = run_module(GitlabUser, "username:gitlab-bot", http)
    assert res.status is Status.OK
    assert res.source_statuses["gitlab.users_api"]["status"] in ("blocked", Status.BLOCKED)
    assert "public_email" not in res.attributes and res.attributes["display_name"]
    assert res.attributes["presence"]["state"] == "found"  # never an absence
    assert res.attributes["ssh_keys"]


def test_keys_challenge_and_empty_bodies():
    http = full_routes(FakeHttp(), keys=env("keys_challenge.http.json"))
    res = run_module(GitlabUser, "username:gitlab-bot", http)
    assert res.status is Status.OK and "ssh_keys" not in res.attributes
    assert res.source_statuses["gitlab.users_api"]["status"] in ("blocked", Status.BLOCKED)
    http = FakeHttp()
    http.add("GET", f"{API}/users?username=gitlab-bot", **env("users_ok.http.json"))
    http.add("GET", f"{API}/users/1786152", json=module_fixture("gitlab_user", "user_detail_ok.json"))
    http.add("GET", "https://gitlab.com/gitlab-bot.keys", **plain("keys_empty.txt"))
    http.add("GET", "https://gitlab.com/gitlab-bot.gpg", **plain("gpg_empty.txt"))
    res = run_module(GitlabUser, "username:gitlab-bot", http)
    assert res.status is Status.OK and "ssh_keys" not in res.attributes and "gpg_keys" not in res.attributes
    assert not res.source_statuses


def test_429_5xx_and_malformed_are_could_not_verify():
    http = FakeHttp().add("GET", f"{API}/users?username=gitlab-bot", **env("rate_limited.http.json"))
    assert run_module(GitlabUser, "username:gitlab-bot", http).status is Status.RATE_LIMITED
    http = FakeHttp().add("GET", f"{API}/users?username=gitlab-bot", status=503, text="down", times=5)
    assert run_module(GitlabUser, "username:gitlab-bot", http).status is Status.ERROR
    http = FakeHttp().add("GET", f"{API}/users?username=gitlab-bot", json={"message": "500 Internal Server Error"})
    assert run_module(GitlabUser, "username:gitlab-bot", http).status is Status.ERROR
    http = FakeHttp().add("GET", f"{API}/users?username=gitlab-bot", json=[{"unexpected": True}])
    assert run_module(GitlabUser, "username:gitlab-bot", http).status is Status.ERROR


def test_rate_limit_headers_stop_further_requests():
    http = full_routes(FakeHttp(), users_headers={"ratelimit-remaining": "5"})
    res = run_module(GitlabUser, "username:gitlab-bot", http)
    assert res.status is Status.OK and res.partial and res.stop_reason == "rate_limited"
    assert len(http.calls) == 1


def test_self_hosted_gitlab_is_never_contacted():
    http = FakeHttp()
    res = run_module(GitlabUser, "url:https://gitlab.corp.example/alice", http)
    assert res.status is Status.SKIPPED and http.calls == []
    from tests.fakes import _as_entity  # noqa: PLC0415 - the kit's entity parser

    assert gitlab_handle(_as_entity("url:https://gitlab.com/example-dev")) == "example-dev"
    assert gitlab_handle(_as_entity("social_account:gitlab:example-dev")) == "example-dev"
    assert GitlabUser.hosts == ("gitlab.com",)
