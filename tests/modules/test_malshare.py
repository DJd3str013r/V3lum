"""Offline tests of the MalShare adapter (P177, module malshare).

The details fixture is synthetic (layout of the community clients listed on doc.php); the no-key
400 body is the research answer.
"""

from __future__ import annotations

from typing import Any
from urllib.parse import urlencode

from tests.fakes import FakeHttp, assert_no_secret, module_fixture, run_module
from v3lum.core.models import Status
from v3lum.modules.malware_hash.hash_lookup_keyed import MalShare, malshare_text_problem

KEY = "malshare-test-key-0123456789abcdef"
MD5 = "53669595e3be509c41604e43a2b445e5"
URL = "https://malshare.com/api.php"


def url(value: str = MD5) -> str:
    return f"{URL}?{urlencode({'api_key': KEY, 'action': 'details', 'hash': value})}"


def exchange(http: FakeHttp, target: str, name: str) -> FakeHttp:
    fx = module_fixture("malshare", name)["response"]
    return http.add("GET", target, status=fx["status"], text=fx["body"], headers={"content-type": "text/plain", **fx.get("headers", {})})


def run(http: FakeHttp, value: str = MD5, **kw: Any) -> Any:
    kw.setdefault("keys", {"malshare": KEY})
    return run_module(MalShare, f"md5:{value}", http, **kw)


def test_details_give_hashes_ssdeep_and_hostile_collection_urls() -> None:
    http = FakeHttp().add("GET", url(), json=module_fixture("malshare", "details_ok_synthetic.json"))
    res = run(http)
    assert res.status is Status.OK, res.error
    assert res.attributes["malshare"]["sources_count"] == 2  # duplicate and junk sources dropped
    assert res.attributes["file_type"] == "PE32"
    assert res.attributes["sha256"] == "1f5c6a15c19cdbd49ac24c2f0a8b595564d076be4cc29d6f2fc8a33965f58bf2"
    f = res.findings[0]
    assert f.severity.label == "low" and "not a family or a verdict" in f.description and f.criterion
    served = [p for p in res.pivots if p.relation == "served_from"]
    assert {p.entity.value for p in served} == {"http://198.51.100.23/bins/sample.exe", "https://downloads.example.com/x/setup.exe"}
    assert all(not p.expand and p.note.startswith("hostile:") for p in served)
    assert [p.entity.type.value for p in res.pivots if p.relation == "similarity_hash"] == ["ssdeep"]
    sha = [p for p in res.pivots if p.relation == "same_file" and p.entity.type.value == "sha256"]
    assert sha and sha[0].expand  # SHA-256 of an MD5 input is investigated
    assert_no_secret(KEY, res.to_dict())  # the api_key URL parameter never reaches the result
    http.assert_hosts_within(MalShare)


def test_not_found_text_is_an_absence_on_404_and_inside_200() -> None:
    assert run(exchange(FakeHttp(), url(), "not_found_404_synthetic.http.json")).status is Status.EMPTY
    res = run(FakeHttp().add("GET", url(), text="Sample not found by hash", headers={"content-type": "text/plain"}))
    assert res.status is Status.EMPTY


def test_key_and_limit_errors_in_text_are_needs_key_and_quota() -> None:
    assert run(exchange(FakeHttp(), url(), "nokey_400.http.json")).status is Status.NEEDS_KEY
    res = run(exchange(FakeHttp(), url(), "quota_429_synthetic.http.json"))
    assert res.status is Status.RATE_LIMITED  # HTTP 429: the core's rate-limit classification wins
    res = run(FakeHttp().add("GET", url(), text="Over Request Limit. Please wait.", headers={"content-type": "text/plain"}))
    assert res.status is Status.QUOTA and res.reason_code == "quota"  # the limit text inside HTTP 200
    res = run(FakeHttp().add("GET", url(), json={"ERROR": {"CODE": 403, "MESSAGE": "Invalid API Key"}}))
    assert res.status is Status.NEEDS_KEY


def test_unexpected_answers_are_errors_never_absences() -> None:
    assert run(FakeHttp().add("GET", url(), json={"ERROR": {"CODE": 500, "MESSAGE": "database unavailable"}})).status is Status.ERROR
    assert run(FakeHttp().add("GET", url(), json={"MD5": None})).status is Status.ERROR
    assert run(FakeHttp().add("GET", url(), text="something odd", headers={"content-type": "text/plain"})).status is Status.ERROR
    assert run(FakeHttp().add("GET", url(), status=502, text="bad gateway", times=3)).status is Status.ERROR
    page = "<html><head><title>Just a moment...</title></head><body>cf-chl-widget</body></html>"
    assert run(FakeHttp().add("GET", url(), status=403, text=page)).status is Status.BLOCKED


def test_text_markers() -> None:
    assert malshare_text_problem(400, "No key specified in `api_key` GET variable")[0] == "needs_key"
    assert malshare_text_problem(429, "Over Request Limit.")[0] == "quota"
    assert malshare_text_problem(404, "Sample not found by hash (x)")[0] == "empty"
    assert malshare_text_problem(200, "hello") is None


def test_no_request_without_a_real_key() -> None:
    http = FakeHttp()
    assert run(http, keys={}).status is Status.NEEDS_KEY and not http.calls
