"""Offline tests of the memory_lol module (P106) on memory.lol answers (tests/fixtures/memory_lol/: the live empty
answers for benign handles, and the README-documented non-empty shapes with fictional handles and ids)."""

from __future__ import annotations

from tests.fakes import FakeHttp, module_fixture, run_module
from v3lum.core.models import Status
from v3lum.modules.username_social.memory_lol import EMPTY_WORDING, MemoryLol, batch_url, handle_ok, parse_answer

BASE = "https://api.memory.lol/v1/tw/"


def pivots(res) -> dict:
    return {(p.entity.type.value, p.entity.value): p for p in res.pivots}


def test_metadata_follows_the_council():
    assert MemoryLol.default_enabled is False and MemoryLol.terms == "unknown"  # cond 2
    assert MemoryLol.run_on == "seeds" and MemoryLol.hosts == ("api.memory.lol",)
    assert MemoryLol.optional_keys == () and MemoryLol.requires_keys == ()  # keyless only (no login/device flow)


def test_handle_validation_and_batches_of_twenty():
    assert handle_ok("exampleorg") and handle_ok("@Example_1") and not handle_ok("*example") and not handle_ok("not.valid")
    urls = batch_url([f"h{i}" for i in range(25)] + ["H1", "bad.handle"])
    assert len(urls) == 2 and urls[0].count(",") == 19 and urls[1] == BASE + "h20,h21,h22,h23,h24"


def test_history_pivots_previous_names_and_snowflake_id_without_expansion():
    http = FakeHttp().add("GET", BASE + "exampleorg", json=module_fixture("memory_lol", "found.json"))
    res = run_module(MemoryLol, "username:exampleorg", http)
    assert res.status is Status.OK, res.error
    http.assert_hosts_within(MemoryLol)
    hist = res.attributes["x_handle_history"]
    assert "60-day" in hist["window"]
    assert res.attributes["account_id"] == "1111111111111111111"
    p = pivots(res)
    prev = p[("username", "exampleorg_br")]
    assert prev.relation == "uses_username" and prev.expand is False and prev.confidence_label == "probable"
    assert "2026-10-01..2026-11-20" in prev.note
    assert ("username", "exampleorg") not in p  # the seed's own name is not repeated
    sid = p[("snowflake_id", "1111111111111111111")]
    assert sid.relation == "uses_username" and sid.expand is False
    f = res.findings[0]
    assert f.title == "X/Twitter screen-name history" and "60-day" in f.description and f.criterion


def test_legacy_shape_and_old_numeric_ids():
    http = FakeHttp().add("GET", BASE + "exampleorg", json=module_fixture("memory_lol", "found_legacy.json"))
    res = run_module(MemoryLol, "social_account:x:exampleorg", http)
    assert res.status is Status.OK
    p = pivots(res)
    assert ("username", "example_old") in p and ("username", "example_mid") in p
    assert "undated" in p[("username", "example_old")].note
    assert not any(k[0] == "snowflake_id" for k in p)  # a pre-snowflake id stays an attribute only
    assert res.attributes["account_id"] == "2222222222"


def test_batch_shape_is_read_case_insensitively():
    state, accounts, _ = parse_answer(module_fixture("memory_lol", "batch_found.json"), "ExampleOrg")
    assert state == "ok" and accounts[0]["account_id"] == "2222222222" and accounts[0]["previous"] == []
    assert parse_answer(module_fixture("memory_lol", "batch_found.json"), "other")[0] == "empty"


def test_empty_answers_read_no_observation_in_the_window():
    for name in ("empty.json", "batch_empty.json"):
        http = FakeHttp().add("GET", BASE + "github", json=module_fixture("memory_lol", name))
        res = run_module(MemoryLol, "username:github", http)
        assert res.status is Status.EMPTY and EMPTY_WORDING in res.error
        assert "previous handles" not in res.error and "presence" not in res.attributes  # never 'no previous handles' (cond 3)


def test_invalid_handles_are_never_sent():
    http = FakeHttp()
    res = run_module(MemoryLol, "username:not.valid", http)
    assert res.status is Status.SKIPPED and res.reason_code == "not_applicable" and http.calls == []


def test_login_page_is_blocked_and_error_objects_are_could_not_verify():
    page = "<html><body><a href='https://api.memory.lol/v1/login/github'>Log in with GitHub</a></body></html>"
    http = FakeHttp().add("GET", BASE + "exampleorg", text=page)
    res = run_module(MemoryLol, "username:exampleorg", http)
    assert res.status is Status.BLOCKED and res.reason_code == "login_wall"
    http = FakeHttp().add("GET", BASE + "exampleorg", json={"error": "temporarily unavailable"})
    assert run_module(MemoryLol, "username:exampleorg", http).status is Status.ERROR
    http = FakeHttp().add("GET", BASE + "exampleorg", json={"accounts": "nope"})
    assert run_module(MemoryLol, "username:exampleorg", http).status is Status.ERROR
    http = FakeHttp().add("GET", BASE + "exampleorg", body=b"{oops", headers={"content-type": "application/json"})
    assert run_module(MemoryLol, "username:exampleorg", http).status is Status.ERROR


def test_429_and_5xx_are_could_not_verify():
    http = FakeHttp().add("GET", BASE + "exampleorg", status=429, text="Too Many Requests")
    assert run_module(MemoryLol, "username:exampleorg", http).status is Status.RATE_LIMITED
    http = FakeHttp().add("GET", BASE + "exampleorg", status=503, text="unavailable", times=5)
    assert run_module(MemoryLol, "username:exampleorg", http).status is Status.ERROR
