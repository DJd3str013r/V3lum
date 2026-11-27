"""Offline tests of pinterest_profile (P116) on tests/fixtures/pinterest_profile/ (found/absent are real captures of
2026-11-26 of the official Pinterest account (pins replaced by documentation values) and a random control)."""

from __future__ import annotations

from tests.fakes import FakeHttp, module_fixture, run_module
from v3lum.core.context import ScanOptions
from v3lum.core.models import Status
from v3lum.modules.username_social.community_profiles import PinterestProfile

FIX = "pinterest_profile"
API = "https://widgets.pinterest.com/v3/pidgets/users/{}/pins/"


def env(name: str) -> dict:
    d = module_fixture(FIX, name)
    return {"status": d["status"], "headers": d["headers"], "text": d["body"]}


def test_found_profile_counts_and_withheld_pin_domains():
    http = FakeHttp().add("GET", API.format("pinterest"), **env("found.http.json"))
    res = run_module(PinterestProfile, "url:https://www.pinterest.com/pinterest/", http)
    assert res.status is Status.OK
    assert res.attributes["account_id"] == "424605208526455283" and res.attributes["followers"] > 0
    assert "pin_link_domains" in res.attributes["content_withheld"]
    http.assert_hosts_within(PinterestProfile)


def test_pin_domains_shown_for_a_brand_abuse_case():
    http = FakeHttp().add("GET", API.format("pinterest"), **env("found.http.json"))
    res = run_module(PinterestProfile, "url:https://www.pinterest.com/pinterest/", http,
                     options=ScanOptions(seed_tlp={"domain:shop.example.com": "amber"}))
    assert "shop.example.com" in res.attributes["profile_content"]["pin_link_domains"]


def test_code_30_is_absent_and_failure_in_200_is_error():
    http = FakeHttp().add("GET", API.format("qz7k2v9m4p1w"), **env("absent.http.json"))
    res = run_module(PinterestProfile, "url:https://www.pinterest.com/qz7k2v9m4p1w/", http)
    assert res.status is Status.EMPTY and res.attributes["presence"]["state"] == "absent"
    http = FakeHttp().add("GET", API.format("pinterest"), **env("error_in_200_synthetic.http.json"))
    res = run_module(PinterestProfile, "url:https://www.pinterest.com/pinterest/", http)
    assert res.status is Status.ERROR and "error in 200" in res.error


def test_truncated_body_rate_limit_and_challenge_are_could_not_verify():
    http = FakeHttp().add("GET", API.format("pinterest"), text=module_fixture(FIX, "truncated.txt"), headers={"content-type": "application/json"})
    assert run_module(PinterestProfile, "url:https://www.pinterest.com/pinterest/", http).status is Status.ERROR
    http = FakeHttp().add("GET", API.format("pinterest"), status=429, text="slow")
    assert run_module(PinterestProfile, "url:https://www.pinterest.com/pinterest/", http).status is Status.RATE_LIMITED
    page = "<html><head><title>Just a moment...</title></head><body><script>window._cf_chl_opt={}</script></body></html>"
    http = FakeHttp().add("GET", API.format("pinterest"), status=403, text=page, headers={"content-type": "text/html"})
    assert run_module(PinterestProfile, "url:https://www.pinterest.com/pinterest/", http).status is Status.BLOCKED


def test_reserved_paths_are_not_profiles():
    res = run_module(PinterestProfile, "url:https://www.pinterest.com/ideas/", FakeHttp())
    assert res.status is Status.SKIPPED and res.reason_code == "not_applicable"
