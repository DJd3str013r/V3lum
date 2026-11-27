"""thehive_sightings (P348, P2 adapter, TheHive 6.0): read-only observable search on the company TheHive.

Fixtures in tests/fixtures/thehive_sightings/ are SYNTHETIC (self-hosted platform), shaped on the
TheHive 6.0 OpenAPI (OutputObservable with numeric TLP/PAP and ms timestamps, OutputCase, OutputUser,
the 401 AuthenticationError body). One observable carries TLP 3 without a label: TheHive 6 reads it as
Amber+Strict but older versions (and the 6.0 docs' own example) as Red, so the adapter keeps the
stricter reading. Creator/assignee logins are documentation addresses and must never be copied.
"""

from __future__ import annotations

import json

import pytest

from tests.fakes import FakeHttp, make_runtime, module_fixture, run_module
from v3lum.core.models import Status
from v3lum.modules.cti_framework import internal_tip_sightings as tip
from v3lum.modules.cti_framework.internal_tip_sightings import TheHiveSightings

BASE = "https://thehive.example.com"
QUERY = f"{BASE}/api/v1/query"
KEY = "thehive-test-key-0123456789abcdef"
KEYS = {"thehive": KEY}
SETTINGS = {"thehive_sightings_url": BASE}
VALUE = "198.51.100.23"


def fx(name):
    return module_fixture(TheHiveSightings, name)


def routes(http, *, user="current_user_readonly.json", observables="observables_hit.json", cases="cases_hit.json"):
    auth = {"Authorization": f"Bearer {KEY}"}
    if user:
        http.add("GET", f"{BASE}/api/v1/user/current", json=fx(user), match_headers=auth, times=1)
    if observables:
        http.add("POST", QUERY, json=fx(observables), match_headers=auth, times=1)
    if cases:
        http.add("POST", QUERY, json=fx(cases), match_headers=auth, times=1)
    return http


def run(http, **kw):
    kw.setdefault("keys", KEYS)
    kw.setdefault("settings", SETTINGS)
    return run_module(TheHiveSightings, f"ipv4:{VALUE}", http, **kw)


def test_contract_metadata():
    cls = TheHiveSightings
    assert (cls.disclosure, cls.provider, cls.sources, cls.hosts) == ("internal", "internal_thehive", ("internal_thehive.query",), ())
    assert cls.category == "cti_framework" and cls.trust_tier == "n/a" and cls.max_tlp.value_str == "red"
    assert cls.requires_keys == ("thehive",) and "thehive_sightings_url" in cls.settings


# ------------------------------------------------------------------ FC5/FC6/FC9: cases, markings, references
def test_cases_holding_the_observable_are_known_internally():
    http = routes(FakeHttp())
    res = run(http)
    assert res.status is Status.OK
    found = {f.key: f for f in res.findings}
    assert set(found) == {"thehive:412", "thehive:431"}
    case = found["thehive:412"]
    assert case.title == "Known internally (TheHive)" and case.severity.label == "medium"  # case severity 2, IOC observable
    assert set(case.tags) == {"internal_sighting", "malicious"} and case.criterion
    assert case.data["ref"] == "TheHive case #412" and case.data["org"] == "EXAMPLE-CSIRT" and case.data["date"] == "2026-10-17"
    assert case.data["tlp"] == "red"  # an observable marked TLP 3 without a label reads as red: never downgraded
    assert found["thehive:431"].severity.label == "low"
    assert res.tlp == "red"
    assert [o["ioc"] for o in case.data["observables"]] == [True, False]
    assert case.data["cortex"][0]["analyzer"] == "AbuseIPDB_2_0"  # existing Cortex reports are reused
    assert {h["ref"] for h in res.attributes["internal_sightings"]} == {"TheHive case #412", "TheHive case #431"}
    http.assert_hosts_within(TheHiveSightings)


def test_personal_logins_are_never_copied():
    res = run(routes(FakeHttp()))
    blob = json.dumps({"findings": [f.to_dict() for f in res.findings], "attributes": res.attributes, "raw": res.raw}, default=str)
    assert "analyst@example.com" not in blob and "v3lum-readonly@example.com" not in blob


def test_values_travel_only_in_json_bodies():
    http = routes(FakeHttp())
    run(http)
    posts = [c for c in http.calls if c["method"] == "POST"]
    first, second = (json.loads(c["body"]) for c in posts)
    assert first["query"][1] == {"_name": "filter", "_eq": {"_field": "data", "_value": VALUE}}
    assert first["query"][-1]["to"] <= 50
    assert second["query"][2] == {"_name": "case"} and second["excludeFields"] == ["description", "summary", "customFields"]
    assert all(VALUE not in c["url"] and "?" not in c["url"] for c in http.calls)
    assert all(0 < (c["timeout"] or 99) <= 5.0 for c in http.calls)


def test_observables_outside_cases_still_count():
    http = routes(FakeHttp(), cases=None).add("POST", QUERY, json=[], times=1)
    res = run(http)
    [finding] = res.findings
    assert finding.key == "thehive:observables" and finding.data["ref"] == "TheHive observable"


def test_no_observable_is_not_known_internally():
    res = run(routes(FakeHttp(), observables="observables_empty.json", cases=None))
    assert res.status is Status.EMPTY and "not known internally (TheHive)" in res.error


def test_case_query_failure_keeps_the_observables():
    http = routes(FakeHttp(), cases=None).add("POST", QUERY, status=500, text="error", times=1)
    res = run(http)
    assert res.status is Status.OK and "case references could not be read" in res.findings[0].description


# ------------------------------------------------------------------ could not verify
def test_authentication_failure_is_needs_key():
    exchange = fx("auth_failed.http.json")
    http = FakeHttp().add("GET", f"{BASE}/api/v1/user/current", status=401, json=exchange["response"]["body"])
    http.add("POST", QUERY, status=401, json=exchange["response"]["body"])
    assert run(http).status is Status.NEEDS_KEY


@pytest.mark.parametrize(
    ("kw", "expected"),
    [
        ({"status": 429, "text": "slow down"}, Status.RATE_LIMITED),
        ({"status": 500, "text": "error"}, Status.ERROR),
        ({"status": 200, "json": {"type": "AuthorizationError", "message": "not allowed"}}, Status.NEEDS_KEY),
        ({"status": 200, "json": {"type": "BadRequest", "message": "invalid query"}}, Status.ERROR),
        ({"status": 200, "json": {"unexpected": True}}, Status.ERROR),
    ],
)
def test_failures_are_could_not_verify(kw, expected):
    http = routes(FakeHttp(), observables=None, cases=None).add("POST", QUERY, **kw)
    res = run(http)
    assert res.status is expected and not res.findings


def test_configuration_and_https_only():
    http = FakeHttp()
    assert run(http, settings={}).status is Status.SKIPPED
    assert run(http, settings={"thehive_sightings_url": "http://thehive.example.com"}).reason_code == "config"
    assert run(http, settings={"thehive_sightings_url": "https://user:pw@thehive.example.com"}).reason_code == "config"
    assert run(http, keys={}).status is Status.NEEDS_KEY
    assert http.calls == []


# ------------------------------------------------------------------ FC3: read-only allow-list, key permissions
@pytest.mark.parametrize(
    ("method", "path", "body"),
    [
        ("POST", "/api/v1/case", {"title": "x"}),
        ("PATCH", "/api/v1/case/~98112", {"status": "Resolved"}),
        ("DELETE", "/api/v1/case/~98112", None),
        ("POST", "/api/v1/observable/~41160", {"ioc": False}),
        ("POST", "/api/v1/query", {"query": [{"_name": "listObservable"}, {"_name": "update", "ioc": False}]}),
        ("POST", "/api/v1/query?name=x", {"query": [{"_name": "listObservable"}]}),
        ("POST", "/api/v1/query", {"query": [{"_name": "listObservable"}], "extra": 1}),
        ("POST", "/api/v1/query", {"query": []}),
    ],
)
def test_write_calls_are_refused(method, path, body):
    assert tip.thehive_request_allowed(method, path, body) is not None


def test_read_calls_are_allowed():
    assert tip.thehive_request_allowed("POST", "/api/v1/query", tip.thehive_observable_query(VALUE)) is None
    assert tip.thehive_request_allowed("POST", "/api/v1/query", tip.thehive_case_query(VALUE)) is None
    assert tip.thehive_request_allowed("GET", "/api/v1/user/current") is None


def test_manage_permissions_warn():
    http = routes(FakeHttp(), user="current_user_write.json")
    rt = make_runtime(http, keys=KEYS, settings=SETTINGS)
    events = []
    rt.events.subscribe(lambda kind, payload: events.append((kind, payload)))
    run_module(TheHiveSightings, f"ipv4:{VALUE}", runtime=rt)
    warnings = [p["message"] for k, p in events if k == "log" and p.get("level") == "warning"]
    assert len(warnings) == 1 and "manageCase/create" in warnings[0]
    assert tip.thehive_write_permissions(fx("current_user_readonly.json")) == []


def test_tlp_reading_never_downgrades():
    assert tip.thehive_tlp(3, None) == "red"  # unknown major version: conservative
    assert tip.thehive_tlp(3, None, major=6) == "amber+strict"
    assert tip.thehive_tlp(2, "Red") == "red"  # label and number disagree: the stricter one
    assert tip.thehive_pap(2, None) == "amber" and tip.thehive_pap(None, "WHITE") == "clear"


def test_parsers_tolerate_junk():
    assert tip.parse_thehive_observables({"x": 1}, VALUE) is None
    [hit] = tip.parse_thehive_observables([None, {"data": VALUE, "reports": "x", "tags": "y", "tlp": "?"}], VALUE)["hits"]
    assert hit["verdict"] == "context" and hit["tlp"] is None
    assert tip.parse_thehive_cases("x") is None and tip.parse_thehive_cases([{"number": "x"}, None]) == [tip.parse_thehive_cases([{"number": "x"}])[0]]
