"""Offline tests of hunter_io_count (P090 cond 2: counts only for third parties) with the fixtures in
tests/fixtures/hunter_io_count/ (documentation-shaped success body; real 401 research capture)."""

from __future__ import annotations

import json
import re

from tests.fakes import FakeHttp, assert_no_secret, module_fixture, run_module
from v3lum.core.context import ScanOptions
from v3lum.core.models import Status
from v3lum.modules.email.hunter_io import HunterIoCount

KEY = "hu-test-key-0123456789abcdef"  # fake key
COUNT = re.compile(r"^https://api\.hunter\.io/v2/email-count\?")
PURPOSE = ScanOptions(purpose="supplier risk review, ticket EX-1")


def fx(name: str):
    return module_fixture("hunter_io_count", name)


def run(http: FakeHttp, entity: str = "domain:example.org", **kw):
    kw.setdefault("keys", {"hunter": KEY})
    kw.setdefault("options", PURPOSE)
    return run_module(HunterIoCount, entity, http, **kw)


def test_metadata():
    cls = HunterIoCount
    assert (cls.terms, cls.default_enabled, cls.run_on, cls.sources) == ("key-terms", False, "any", ("hunter.email_count",))
    assert cls.max_requests == 1 and not cls.produces


def test_third_party_domain_gets_counts_only():
    http = FakeHttp().add("GET", COUNT, json=fx("email_count_ok.json"))
    res = run(http)
    assert res.status is Status.OK, res.error
    counts = res.attributes["email_counts"]
    assert counts["total"] == 37 and counts["personal"] == 30 and counts["generic"] == 7
    assert counts["department"]["it"] == 9 and "management" not in counts["department"]  # zero counts dropped
    assert not res.pivots and "@" not in json.dumps(res.attributes)
    assert "domain=example.org" in http.calls[0]["url"]
    http.assert_hosts_within(HunterIoCount)
    assert_no_secret(KEY, res.to_dict())


def test_company_name_uses_the_company_parameter():
    http = FakeHttp().add("GET", COUNT, json=fx("email_count_ok.json"))
    res = run(http, "company_name:Example Org")
    assert res.status is Status.OK and "company=Example+Org" in http.calls[0]["url"]


def test_no_recorded_purpose_is_skipped_privacy():
    http = FakeHttp()
    res = run(http, options=ScanOptions())
    assert res.status is Status.SKIPPED and res.reason_code == "privacy" and http.calls == []


def test_zero_total_is_empty_and_errors_could_not_verify():
    body = {"data": {"total": 0, "personal_emails": 0, "generic_emails": 0, "department": {}, "seniority": {}}, "meta": {}}
    assert run(FakeHttp().add("GET", COUNT, json=body)).status is Status.EMPTY
    env = fx("needs_key_401.json")
    http = FakeHttp().add("GET", COUNT, status=env["status"], json=env["body"], headers=env["headers"])
    assert run(http).status is Status.NEEDS_KEY
    assert run(FakeHttp().add("GET", COUNT, json={"errors": []})).status is Status.ERROR
    assert run(FakeHttp(), keys={}).status is Status.NEEDS_KEY
