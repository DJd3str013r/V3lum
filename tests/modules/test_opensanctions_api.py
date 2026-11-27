"""Offline tests for P222 ``opensanctions_api`` (licensed Screening API, batch p3-G10-1).

tests/fixtures/opensanctions_api/: the live keyless 401 and synthetic placeholders of the documented yente
/match shapes (README there; P222 cond 9 asks for a licensed capture before enabling).
"""

from __future__ import annotations

import json
import re

from tests.fakes import FakeHttp, assert_no_secret, module_fixture, run_module
from v3lum.core.context import ScanOptions
from v3lum.core.models import Severity, Status
from v3lum.modules.company_org import opensanctions as osx
from v3lum.modules.company_org.opensanctions import OpenSanctionsApi
from tests.modules.test_opensanctions import install

KEY = "os-test-key-5f2a9c1e"
URL = re.compile(r"^https://api\.opensanctions\.org/match/default\?")
READY = {"keys": {"opensanctions": KEY}, "settings": {osx.SETTING_BUDGET: 10}}


def fx(name: str):
    return module_fixture("opensanctions_api", name)


def exchange(name: str) -> FakeHttp:
    ex = fx(name)
    return FakeHttp().add("POST", URL, status=ex["status"], body=ex["body"].encode(), headers=ex["headers"])


def test_company_query_key_in_header_value_in_body():
    http = FakeHttp().add("POST", URL, json=fx("match_ok.json"))
    res = run_module(OpenSanctionsApi, "company_name:Example Sanctioned Trading", http, **READY)
    assert res.status is Status.OK
    (call,) = http.calls
    assert call["headers"].get("Authorization") == f"ApiKey {KEY}"
    assert KEY not in call["url"] and "Example" not in call["url"]
    assert "algorithm=logic-v1" in call["url"] and "threshold=0.70" in call["url"] and "limit=5" in call["url"]
    body = json.loads(call["body"])
    assert body == {"queries": {"q0": {"schema": "Company", "properties": {"name": ["Example Sanctioned Trading"]}}}}
    hits = res.attributes["opensanctions_matches"]
    assert [h["entity_id"] for h in hits] == ["NK-example-company-1", "NK-example-person-1"]
    company, person = res.findings
    assert company.title == "OpenSanctions possible match - confirm identity" and "sanctions" in company.tags
    assert person.severity is Severity.INFO and "pep" in person.tags and "sanctions" not in person.tags
    raw = json.dumps(res.raw)
    for personal in ("1970-01-01", "person@example.com", "Example address line"):
        assert personal not in raw and personal not in json.dumps(res.attributes)
    assert_no_secret(KEY, res.raw, res.attributes, [f.to_dict() for f in res.findings], res.error)
    http.assert_hosts_within(OpenSanctionsApi)


def test_empty_answer_is_empty():
    http = FakeHttp().add("POST", URL, json=fx("match_empty.json"))
    res = run_module(OpenSanctionsApi, "company_name:Example Nonexistent Holdings", http, **READY)
    assert res.status is Status.EMPTY and res.attributes["opensanctions_screening"]["state"] == "no_match"


def test_missing_key_is_needs_key_and_a_rejected_key_too():
    res = run_module(OpenSanctionsApi, "company_name:Example", FakeHttp(), settings={osx.SETTING_BUDGET: 10})
    assert res.status is Status.NEEDS_KEY
    rejected = run_module(OpenSanctionsApi, "company_name:Example", exchange("api_nokey.http.json"), **READY)
    assert rejected.status is Status.NEEDS_KEY


def test_budget_is_a_hard_stop():
    unset = run_module(OpenSanctionsApi, "company_name:Example", FakeHttp(), keys={"opensanctions": KEY})
    assert unset.status is Status.SKIPPED and unset.reason_code == "config" and osx.SETTING_BUDGET in unset.error
    http = FakeHttp().add("POST", URL, json=fx("match_empty.json"))
    one = {"keys": {"opensanctions": KEY}, "settings": {osx.SETTING_BUDGET: 1}}
    assert run_module(OpenSanctionsApi, "company_name:Example A", http, **one).status is Status.EMPTY
    second = run_module(OpenSanctionsApi, "company_name:Example B", http, **one)
    assert second.status is Status.QUOTA and "hard stop" in second.error
    assert len(http.calls) == 1


def test_quota_wording_is_quota_and_plain_429_is_rate_limited():
    assert run_module(OpenSanctionsApi, "company_name:Example", exchange("quota_429.http.json"), **READY).status is Status.QUOTA
    plain = FakeHttp().add("POST", URL, status=429, json={"detail": "Too many requests"})
    assert run_module(OpenSanctionsApi, "company_name:Example", plain, **READY).status is Status.RATE_LIMITED


def test_errors_are_could_not_verify():
    assert run_module(OpenSanctionsApi, "company_name:Example", exchange("match_invalid_422.http.json"), **READY).status is Status.ERROR
    assert run_module(OpenSanctionsApi, "company_name:Example", FakeHttp().add("POST", URL, status=503, text="down"), **READY).status is Status.ERROR
    failed = {"responses": {"q0": {"status": 500, "results": []}}}
    res = run_module(OpenSanctionsApi, "company_name:Example", FakeHttp().add("POST", URL, json=failed), **READY)
    assert res.status is Status.ERROR and "could not verify" in res.error
    junk = FakeHttp().add("POST", URL, status=200, body=b"<html>oops</html>", headers={"content-type": "text/html"})
    assert run_module(OpenSanctionsApi, "company_name:Example", junk, **READY).status is Status.ERROR


def test_person_needs_purpose_and_never_leaves_without_it():
    http = FakeHttp()
    res = run_module(OpenSanctionsApi, "person_name:Maria Example Silva", http, **READY)
    assert res.status is Status.SKIPPED and res.reason_code == "privacy" and http.calls == []
    http2 = FakeHttp().add("POST", URL, json=fx("match_empty.json"))
    ok = run_module(OpenSanctionsApi, "person_name:Maria Example Silva", http2, options=ScanOptions(purpose="DD-2026-01"), **READY)
    assert ok.status is Status.EMPTY
    assert json.loads(http2.calls[0]["body"])["queries"]["q0"]["schema"] == "Person"


def test_wallet_query_uses_the_normalised_public_key():
    http = FakeHttp().add("POST", URL, json=fx("match_empty.json"))
    run_module(OpenSanctionsApi, "eth_address:0x000000000000000000000000000000000000dEaD", http, **READY)
    q = json.loads(http.calls[0]["body"])["queries"]["q0"]
    assert q == {"schema": "CryptoWallet", "properties": {"publicKey": ["0x000000000000000000000000000000000000dead"]}}


def test_steps_aside_when_the_licensed_bulk_is_imported():
    install()
    http = FakeHttp()
    res = run_module(OpenSanctionsApi, "company_name:Example", http, **READY)
    assert res.status is Status.SKIPPED and res.reason_code == "not_applicable" and http.calls == []


def test_declarations():
    assert OpenSanctionsApi.requires_keys == ("opensanctions",) and OpenSanctionsApi.terms == "license"
    assert OpenSanctionsApi.hosts == ("api.opensanctions.org",) and OpenSanctionsApi.default_enabled is False
