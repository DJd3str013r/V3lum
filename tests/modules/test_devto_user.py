"""Offline tests of devto_user (P100) on trimmed real DEV answers (tests/fixtures/devto_user/)."""

from __future__ import annotations

from tests.fakes import FakeHttp, module_fixture, run_module
from v3lum.core.context import ScanOptions
from v3lum.core.entities import EntityType as T
from v3lum.core.models import Status
from v3lum.modules.username_social.dev_profiles import DevtoUser

URL = "https://dev.to/api/users/by_username?url={u}"


def env(name: str) -> dict:
    d = module_fixture("devto_user", name)
    return {"status": d["status"], "headers": d["headers"], "text": d["body"]}


def accounts(res) -> dict:
    return {p.entity.value: p for p in res.pivots if p.entity.type is T.SOCIAL_ACCOUNT}


def test_found_declared_accounts_are_possible():
    http = FakeHttp().add("GET", URL.format(u="thepracticaldev"), json=module_fixture("devto_user", "ok.json"))
    res = run_module(DevtoUser, "username:thepracticaldev", http)
    assert res.status is Status.OK
    assert res.attributes["created"] == "2016-02-09T00:00:00Z"  # DEV's 'Feb  9, 2016'
    acc = accounts(res)
    assert acc["x:thepracticaldev"].confidence_label == "possible" and acc["x:thepracticaldev"].expand is False
    assert not [f for f in res.findings if "already linked" in f.title]
    http.assert_hosts_within(DevtoUser)


def test_ceos_rule_raises_a_login_already_linked_to_the_seed():
    http = FakeHttp().add("GET", URL.format(u="example-dev"), json=module_fixture("devto_user", "ok_linked.json"))
    opts = ScanOptions(seed_tlp={"username:example-dev": "amber", "social_account:github:example-dev": "amber"})
    res = run_module(DevtoUser, "username:example-dev", http, options=opts)
    acc = accounts(res)
    assert acc["github:example-dev"].confidence_label == "probable" and acc["github:example-dev"].expand is False
    assert acc["x:exampledev"].confidence_label == "possible"
    assert any(f.title == "DEV profile declares an account already linked to the seed" for f in res.findings)
    assert {a["platform"] for a in res.attributes["linked_accounts"]} == {"github", "x"}


def test_bot_block_403_is_blocked_never_absent_never_retried():
    http = FakeHttp().add("GET", URL.format(u="thepracticaldev"), **env("blocked_bots.http.json"))
    res = run_module(DevtoUser, "username:thepracticaldev", http)
    assert res.status is Status.BLOCKED and res.reason_code == "challenge"
    assert len(http.calls) == 1


def test_404_is_absent_and_odd_answers_are_errors():
    http = FakeHttp().add("GET", URL.format(u="qz7k2v9m4p1w8n3x5c6b"), **env("not_found.http.json"))
    res = run_module(DevtoUser, "username:qz7k2v9m4p1w8n3x5c6b", http)
    assert res.status is Status.EMPTY and res.attributes["presence"]["state"] == "absent"
    http = FakeHttp().add("GET", URL.format(u="example-dev"), json={"error": "boom", "status": 500})
    assert run_module(DevtoUser, "username:example-dev", http).status is Status.ERROR
    http = FakeHttp().add("GET", URL.format(u="example-dev"), status=429, text="slow")
    assert run_module(DevtoUser, "username:example-dev", http).status is Status.RATE_LIMITED
