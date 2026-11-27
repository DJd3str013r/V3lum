"""Offline tests of codeberg_user (P100) on trimmed real Codeberg answers (tests/fixtures/codeberg_user/)."""

from __future__ import annotations

from tests.fakes import FakeHttp, module_fixture, run_module
from v3lum.core.context import ScanOptions
from v3lum.core.entities import EntityType as T
from v3lum.core.models import Status
from v3lum.modules.username_social.dev_profiles import CodebergUser

URL = "https://codeberg.org/api/v1/users/{u}"


def env(name: str) -> dict:
    d = module_fixture("codeberg_user", name)
    return {"status": d["status"], "headers": d["headers"], "text": d["body"]}


def test_found_with_noreply_email_dropped():
    http = FakeHttp().add("GET", URL.format(u="forgejo"), json=module_fixture("codeberg_user", "ok.json"))
    res = run_module(CodebergUser, "username:forgejo", http)
    assert res.status is Status.OK
    assert res.attributes["created"] == "2022-11-06T06:18:11Z" and res.attributes["followers"] == 658
    assert res.attributes["platform_summary"]["platform"] == "codeberg"
    assert not [p for p in res.pivots if p.entity.type is T.EMAIL]  # noreply placeholder dropped
    site = [p for p in res.pivots if p.relation == "link_on_profile"]
    assert site and site[0].entity.value.startswith("https://forgejo.org") and site[0].expand is False
    http.assert_hosts_within(CodebergUser)


def test_public_email_of_the_seed_account():
    http = FakeHttp().add("GET", URL.format(u="example-dev"), json=module_fixture("codeberg_user", "ok_public_email.json"))
    res = run_module(CodebergUser, "url:https://codeberg.org/example-dev", http, options=ScanOptions(seed_tlp={"email:dev@example.com": "amber"}))
    assert res.status is Status.OK
    mails = [p for p in res.pivots if p.entity.type is T.EMAIL]
    assert len(mails) == 1 and mails[0].relation == "email_on_profile" and mails[0].expand is False


def test_404_is_absent_429_rate_limited():
    http = FakeHttp().add("GET", URL.format(u="qz7k2v9m4p1w8n3x5c6b"), **env("not_found.http.json"))
    res = run_module(CodebergUser, "username:qz7k2v9m4p1w8n3x5c6b", http)
    assert res.status is Status.EMPTY and res.attributes["presence"]["state"] == "absent"
    http = FakeHttp().add("GET", URL.format(u="example-dev"), **env("rate_limited.http.json"))
    assert run_module(CodebergUser, "username:example-dev", http).status is Status.RATE_LIMITED


def test_html_and_error_in_200_are_errors():
    http = FakeHttp().add("GET", URL.format(u="example-dev"), text="<!DOCTYPE html><html><body>maintenance</body></html>")
    assert run_module(CodebergUser, "username:example-dev", http).status is Status.ERROR
    http = FakeHttp().add("GET", URL.format(u="example-dev"), json={"message": "internal"})
    assert run_module(CodebergUser, "username:example-dev", http).status is Status.ERROR


def test_self_hosted_forgejo_and_reserved_routes_are_never_contacted():
    http = FakeHttp()
    assert run_module(CodebergUser, "url:https://git.corp.example/alice", http).status is Status.SKIPPED
    assert run_module(CodebergUser, "username:search", http).status is Status.SKIPPED
    assert http.calls == []
