"""Offline tests of huggingface_user (P100) on trimmed real Hub answers (tests/fixtures/huggingface_user/)."""

from __future__ import annotations

from tests.fakes import FakeHttp, module_fixture, run_module
from v3lum.core.models import Status
from v3lum.modules.username_social.dev_profiles import HuggingfaceUser

URL = "https://huggingface.co/api/users/{u}/overview"


def env(name: str) -> dict:
    d = module_fixture("huggingface_user", name)
    return {"status": d["status"], "headers": d["headers"], "text": d["body"]}


def test_found_summary_and_organisations():
    http = FakeHttp().add("GET", URL.format(u="sfconvertbot"), json=module_fixture("huggingface_user", "ok.json"))
    res = run_module(HuggingfaceUser, "username:SFconvertbot", http)
    assert res.status is Status.OK
    assert res.attributes["organizations"] == ["safetensors"]
    summary = res.attributes["platform_summary"]
    assert summary["count"] == 0 and summary["count_kind"] == "models" and summary["created"] == "2022-10-31T13:59:40Z"
    profile = [p for p in res.pivots if p.relation == "has_account"]
    assert profile and profile[0].entity.value == "https://huggingface.co/SFconvertbot" and profile[0].expand is False
    http.assert_hosts_within(HuggingfaceUser)


def test_404_is_absent():
    http = FakeHttp().add("GET", URL.format(u="qz7k2v9m4p1w8n3x5c6b"), **env("not_found.http.json"))
    res = run_module(HuggingfaceUser, "username:qz7k2v9m4p1w8n3x5c6b", http)
    assert res.status is Status.EMPTY and res.attributes["presence"]["state"] == "absent"


def test_429_challenge_and_malformed_are_could_not_verify():
    http = FakeHttp().add("GET", URL.format(u="example-dev"), **env("rate_limited.http.json"))
    assert run_module(HuggingfaceUser, "username:example-dev", http).status is Status.RATE_LIMITED
    page = "<!DOCTYPE html><html><head><title>Just a moment...</title></head><body>cf-chl-widget</body></html>"
    http = FakeHttp().add("GET", URL.format(u="example-dev"), status=403, text=page)
    assert run_module(HuggingfaceUser, "username:example-dev", http).status is Status.BLOCKED
    http = FakeHttp().add("GET", URL.format(u="example-dev"), json={"error": "Internal Error"})
    assert run_module(HuggingfaceUser, "username:example-dev", http).status is Status.ERROR
    http = FakeHttp().add("GET", URL.format(u="example-dev"), status=502, text="bad gateway", times=5)
    assert run_module(HuggingfaceUser, "username:example-dev", http).status is Status.ERROR
