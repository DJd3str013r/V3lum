"""Offline tests of stackexchange_user (P116) on tests/fixtures/stackexchange_user/ (found, empty, bad parameter and the
empty /associated answer are real captures of 2026-11-26 of the 'Community' system user (-1) and random controls; the
name search, ambiguity, throttle and associated-accounts answers are synthetic or documentation-shaped)."""

from __future__ import annotations

from tests.fakes import FakeHttp, module_fixture, run_module
from v3lum.core.models import Status
from v3lum.modules.username_social.community_profiles import STACKEXCHANGE_ATTRIBUTION, StackexchangeUser

FIX = "stackexchange_user"
BY_ID = "https://api.stackexchange.com/2.3/users/{}?site=stackoverflow"
INNAME = "https://api.stackexchange.com/2.3/users?order=desc&sort=name&inname={}&site=stackoverflow"
KEY = "stackexchange-test-key-000000"


def env(name: str) -> dict:
    d = module_fixture(FIX, name)
    return {"status": d["status"], "headers": d["headers"], "text": d["body"]}


def test_user_id_url_found_with_attribution():
    http = FakeHttp().add("GET", BY_ID.format("-1"), **env("found.http.json"))
    res = run_module(StackexchangeUser, "url:https://stackoverflow.com/users/-1/community", http)
    assert res.status is Status.OK
    assert res.attributes["display_name"] == "Community" and res.attributes["account_id"] == -1
    assert res.attributes["data_attribution"] == STACKEXCHANGE_ATTRIBUTION  # FC8: CC BY-SA
    assert len(http.calls) == 1  # no /associated without the key
    http.assert_hosts_within(StackexchangeUser)


def test_name_search_lists_only_one_exact_match_and_honours_backoff():
    http = FakeHttp().add("GET", INNAME.format("Example%20Dev"), **env("inname_synthetic.http.json"))
    res = run_module(StackexchangeUser, "url:https://stackoverflow.com/users/filter?search=Example%20Dev", http)
    assert res.status is Status.OK and res.attributes["platform_facts"]["user_id"] == 100000001
    res = run_module(StackexchangeUser, "url:https://stackoverflow.com/users/filter?search=Example%20Dev", http)
    assert res.status is Status.RATE_LIMITED and "backoff" in res.error and len(http.calls) == 1  # backoff 10 s honoured


def test_ambiguous_and_empty_searches_list_nothing():
    http = FakeHttp().add("GET", INNAME.format("Example"), **env("ambiguous_synthetic.http.json"))
    res = run_module(StackexchangeUser, "url:https://stackoverflow.com/users/filter?search=Example", http)
    assert res.status is Status.EMPTY and not res.pivots and "share this display name" in res.error
    http = FakeHttp().add("GET", INNAME.format("jo6rxa78qvs5pa0n1r8h"), **env("empty.http.json"))
    res = run_module(StackexchangeUser, "url:https://stackoverflow.com/users/filter?search=jo6rxa78qvs5pa0n1r8h", http)
    assert res.status is Status.EMPTY and res.attributes["presence"]["state"] == "absent"


def test_key_adds_the_cross_site_accounts():
    http = (FakeHttp()
            .add("GET", BY_ID.format("100000001") + f"&key={KEY}", json={"items": [{"user_id": 100000001, "account_id": 200000001,
                 "display_name": "Example Dev", "creation_date": 1420070400, "link": "https://stackoverflow.com/users/100000001/example-dev"}],
                 "quota_max": 10000, "quota_remaining": 9000})
            .add("GET", f"https://api.stackexchange.com/2.3/users/200000001/associated?pagesize=100&key={KEY}",
                 json=module_fixture(FIX, "associated_documented.json")))
    res = run_module(StackexchangeUser, "url:https://stackoverflow.com/users/100000001/example-dev", http, keys={"stackexchange": KEY})
    assert res.status is Status.OK and len(http.calls) == 2
    assert "https://security.stackexchange.com/users/3000001" in {p.entity.value for p in res.pivots}
    assert res.attributes["platform_facts"]["associated"]["sites"] == 2
    assert KEY not in str(res.to_dict())


def test_throttle_and_bad_parameter_are_never_absent():
    http = FakeHttp().add("GET", INNAME.format("Example%20Dev"), **env("throttled_documented.http.json"))
    res = run_module(StackexchangeUser, "url:https://stackoverflow.com/users/filter?search=Example%20Dev", http)
    assert res.status is Status.QUOTA  # 'available in 82646 seconds': the daily quota
    http = FakeHttp().add("GET", BY_ID.format("-1"), **env("bad_parameter.http.json"))
    assert run_module(StackexchangeUser, "url:https://stackoverflow.com/users/-1/community", http).status is Status.ERROR
    http = FakeHttp().add("GET", BY_ID.format("-1"), text="<!DOCTYPE html><html><body>down</body></html>", headers={"content-type": "text/html"})
    assert run_module(StackexchangeUser, "url:https://stackoverflow.com/users/-1/community", http).status is Status.ERROR
