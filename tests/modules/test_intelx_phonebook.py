"""intelx_phonebook (P139 cond 5): Intelligence X phonebook selectors of VERIFIED own domains only.

Fixtures in tests/fixtures/intelx_phonebook/: ``needs_key_401.json`` is the real 2026-11-25 keyless answer
(HTTP 401, empty body); the phonebook answers are SYNTHETIC in the IntelligenceX SDK shape with
documentation values (example.com own domain, third-party/lookalike selectors, a wildcard, trailing
punctuation and a phone selector). P139 cond 6: replace with a trimmed real answer before merge.
"""

from __future__ import annotations

import json

from tests.fakes import FakeHttp, module_fixture, run_module
from v3lum.core import sanitize
from v3lum.core.models import Status
from v3lum.core.orgprofile import OrgProfile
from v3lum.modules.breach_leak.intelx_metadata import IntelxPhonebook, parse_phonebook_result

MOD = IntelxPhonebook
KEY = "ixfixture-0000-1111-2222-333344445555"
SID = "2b3d6c9e-0f1a-4c5b-9d7e-8a6b5c4d3e2f"
START = "https://free.intelx.io/phonebook/search"
RESULT = f"https://free.intelx.io/phonebook/search/result?id={SID}&limit=1000&offset=-1"
TERMINATE = f"https://free.intelx.io/intelligent/search/terminate?id={SID}"
OWN = {"domains": [{"name": "example.com", "verification": "attested", "attested_by": "fixture analyst", "attested_date": "2026-11-26"}]}
SEEDED = {"domains": [{"name": "example.com", "verification": "seeded"}]}
KEYS = {"intelx": KEY}


def fx(name):
    return module_fixture(MOD, name)


def run(http, value="domain:example.com", profile=OWN, **kw):
    kw.setdefault("keys", KEYS)
    return run_module(MOD, value, http, org_profile=OrgProfile.from_dict(profile) if profile is not None else None, **kw)


def ok_http():
    http = FakeHttp().add("POST", START, json=fx("search_start_ok.json"), match_headers={"x-key": KEY})
    http.add("GET", RESULT, json=fx("phonebook_result_ok.json"))
    return http


def test_only_own_domain_selectors_are_kept_and_never_expanded():
    http = ok_http()
    res = run(http)
    assert res.status is Status.OK
    sent = json.loads(http.calls[0]["body"])
    assert sent["term"] == "example.com" and sent["target"] == 0 and sent["maxresults"] == 1000
    pivots = {(p.entity.type.value, p.entity.value): p for p in res.pivots}
    assert set(pivots) == {
        ("email", "contato@example.com"), ("email", "user01@example.com"), ("email", "user02@mail.example.com"),
        ("domain", "www.example.com"), ("domain", "mail.example.com"), ("domain", "dev.example.com"), ("domain", "intranet.example.com"),
        ("url", "https://www.example.com/login"), ("url", "http://portal.example.com/path"),
    }
    assert all(p.expand is False for p in res.pivots)
    assert pivots[("email", "user01@example.com")].relation == "leak_index_selector"
    counts = res.attributes["intelx_phonebook"]
    assert counts["third_party_dropped"] == 4 and counts["other_dropped"] == 2 and counts["emails"] == 3
    assert res.attributes["third_party_counts"] == {"selectors": 4}
    text = json.dumps(res.to_dict(), default=str)
    for gone in ("someone@example.net", "attacker.test", "example.org", "5555-0100", "?q=1"):
        assert gone not in text  # people-search over leaks: third-party selectors are counted, never kept (rule 4)
    f = res.findings[0]
    assert {"own_asset", "leak_index", "privacy"} <= set(f.tags) and f.criterion and f.source == "intelx.phonebook"
    assert f.severity.label == "info"  # every address on the IANA example domain is generic (never scored)
    assert [c["url"] for c in http.calls].count(TERMINATE) == 0  # status 1: finished, nothing to terminate
    http.assert_hosts_within(MOD)


def test_not_an_own_verified_domain_never_reaches_the_phonebook():
    for profile, value in ((None, "domain:example.com"), (SEEDED, "domain:example.com"), (OWN, "domain:thirdparty.com.br")):
        http = FakeHttp()
        res = run(http, value, profile=profile)
        assert res.status is Status.SKIPPED and res.reason_code == "own_asset" and http.calls == []


def test_finished_phonebook_without_own_selectors_is_empty():
    http = FakeHttp().add("POST", START, json=fx("search_start_ok.json"))
    http.add("GET", RESULT, json=fx("phonebook_result_empty.json"))
    res = run(http)
    assert res.status is Status.EMPTY and res.attributes["presence"]["state"] == "absent"


def test_phonebook_statuses_are_could_not_verify():
    assert run(FakeHttp(), keys={}).status is Status.NEEDS_KEY
    data = fx("needs_key_401.json")
    http = FakeHttp().add("POST", START, status=data["status"], text="")
    assert run(http).status is Status.NEEDS_KEY  # the free tier has no phonebook lookups
    data = fx("quota_402.json")
    http = FakeHttp().add("POST", START, status=data["status"], text="")
    assert run(http).status is Status.QUOTA
    http = FakeHttp().add("POST", START, json=fx("search_start_ok.json"))
    http.add("GET", RESULT, json={"status": 3, "selectors": []})
    http.add("GET", TERMINATE, status=204, text="")
    res = run(http)
    assert res.status is Status.ERROR and "could not verify" in res.error
    assert [c["url"] for c in http.calls].count(TERMINATE) == 1


def test_parser_and_schema_keep_selectors_only():
    parsed = parse_phonebook_result(fx("phonebook_result_ok.json"))
    assert {"type": "url", "value": "http://portal.example.com/path"} in parsed["selectors"]
    assert parsed["dropped"] == 2 and parsed["state"] == "done"
    body = json.dumps(dict(fx("phonebook_result_ok.json"), password="x", content="leaked")).encode()
    out = json.loads(sanitize.sanitize_body("intelx.phonebook", body, "application/json"))
    assert set(out) == {"status", "selectors"} and "leaked" not in json.dumps(out)
