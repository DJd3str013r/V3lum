"""opencti_sightings (P348, OpenCTI 7.x): read-only GraphQL observable query on the company OpenCTI.

Fixtures in tests/fixtures/opencti_sightings/ are SYNTHETIC (self-hosted platform), shaped on the
OpenCTI 7.x GraphQL schema (StixCyberObservable with x_opencti_score, objectMarking, objectLabel,
createdBy, reports, indicators with valid_until/revoked, stixCoreRelationships) and the documented
'You must be logged in to do this.' error, which GraphQL returns with HTTP 200. Documentation values
only (198.51.100.0/24, EXAMPLE-* organisations).
"""

from __future__ import annotations

import copy
import json

import pytest

from tests.fakes import FakeHttp, make_runtime, module_fixture, run_module
from v3lum.core.context import ScanOptions
from v3lum.core.models import Status
from v3lum.modules.cti_framework import internal_tip_sightings as tip
from v3lum.modules.cti_framework.internal_tip_sightings import OpenCtiSightings

BASE = "https://opencti.example.com"
URL = f"{BASE}/graphql"
TOKEN = "opencti-test-token-0123456789abcdef"
KEYS = {"opencti": TOKEN}
SETTINGS = {"opencti_url": BASE}
VALUE = "198.51.100.23"


def fx(name):
    return module_fixture(OpenCtiSightings, name)


def routes(http, observables, *, me="me_readonly.json"):
    auth = {"Authorization": f"Bearer {TOKEN}"}
    if me:
        http.add("POST", URL, json=fx(me) if isinstance(me, str) else me, match_headers=auth, times=1)
    http.add("POST", URL, json=fx(observables) if isinstance(observables, str) else observables, match_headers=auth)
    return http


def run(http, **kw):
    kw.setdefault("keys", KEYS)
    kw.setdefault("settings", SETTINGS)
    return run_module(OpenCtiSightings, f"ipv4:{VALUE}", http, **kw)


def test_contract_metadata():
    cls = OpenCtiSightings
    assert (cls.disclosure, cls.provider, cls.sources, cls.hosts) == ("internal", "internal_opencti", ("internal_opencti.graphql",), ())
    assert cls.category == "cti_framework" and cls.trust_tier == "n/a" and cls.max_tlp.value_str == "red"
    assert cls.requires_keys == ("opencti",) and cls.timeout == 5.0 and cls.cache_ttl == 0


# ------------------------------------------------------------------ FC5/FC6/FC7
def test_active_indicator_score_markings_reports_and_pivots():
    http = routes(FakeHttp(), "observables_hit.json")
    res = run(http)
    assert res.status is Status.OK
    [finding] = res.findings  # the neighbour .230 is not an exact match
    assert finding.title == "Known internally (OpenCTI)" and finding.severity.label == "high"  # score 80, active indicator
    assert set(finding.tags) == {"internal_sighting", "malicious"} and finding.criterion
    assert finding.data["ref"] == "OpenCTI report 'Fake bank SMS campaign (synthetic)'"
    assert finding.data["org"] == "EXAMPLE-CSIRT" and finding.data["pap"] == "amber" and finding.data["date"] == "2026-11-20"
    states = {i["id"]: i["state"] for i in finding.data["indicators"]}
    assert states == {"in-1": "active", "in-2": "expired", "in-3": "revoked"}
    assert finding.data["tlp"] == "amber+strict" and res.tlp == "amber+strict"  # the report's marking is the highest
    assert res.attributes["tip_score"] == 80
    pivots = {(p.entity.type.value, p.entity.value): p for p in res.pivots}
    assert set(pivots) == {("threat_actor", "Example Intrusion Set"), ("malware_family", "Grandoreiro"), ("mitre_technique", "T1566")}
    assert all(p.expand is False for p in pivots.values())
    http.assert_hosts_within(OpenCtiSightings)


def test_expired_or_revoked_indicators_only_are_historical_low():
    data = copy.deepcopy(fx("observables_hit.json"))
    node = data["data"]["stixCyberObservables"]["edges"][0]["node"]
    node["indicators"]["edges"] = node["indicators"]["edges"][1:]  # drop the active one
    res = run(routes(FakeHttp(), data))
    [finding] = res.findings
    assert finding.severity.label == "low" and "historical" in finding.tags and "malicious" not in finding.tags


def test_observable_without_indicator_is_context():
    data = copy.deepcopy(fx("observables_hit.json"))
    data["data"]["stixCyberObservables"]["edges"][0]["node"]["indicators"]["edges"] = []
    res = run(routes(FakeHttp(), data))
    [finding] = res.findings
    assert finding.severity.label == "info" and "context_only" in finding.tags


def test_value_travels_only_in_graphql_variables():
    http = routes(FakeHttp(), "observables_hit.json")
    run(http)
    query = json.loads(http.calls[1]["body"])
    assert VALUE not in query["query"] and VALUE not in http.calls[1]["url"]
    assert query["variables"]["filters"]["filters"][0]["values"] == [VALUE]
    assert query["variables"]["first"] <= 50
    assert all(c["method"] == "POST" and 0 < (c["timeout"] or 99) <= 5.0 for c in http.calls)


def test_no_observable_is_not_known_internally():
    res = run(routes(FakeHttp(), "observables_empty.json"))
    assert res.status is Status.EMPTY and "not known internally (OpenCTI)" in res.error


# ------------------------------------------------------------------ errors inside HTTP 200 and failures
def test_auth_required_inside_200_is_needs_key():
    res = run(routes(FakeHttp(), "auth_required.json", me="auth_required.json"))
    assert res.status is Status.NEEDS_KEY and "logged in" in res.error


def test_other_graphql_errors_are_could_not_verify():
    body = {"errors": [{"message": "Internal error", "extensions": {"code": "DATABASE_ERROR"}}], "data": None}
    res = run(routes(FakeHttp(), body))
    assert res.status is Status.ERROR and "could not verify" in res.error


@pytest.mark.parametrize(
    ("kw", "expected"),
    [
        ({"status": 401, "json": {"message": "unauthorized"}}, Status.NEEDS_KEY),
        ({"status": 429, "text": "slow down"}, Status.RATE_LIMITED),
        ({"status": 503, "text": "unavailable"}, Status.ERROR),
        ({"status": 200, "json": {"data": {"other": 1}}}, Status.ERROR),
    ],
)
def test_failures_are_could_not_verify(kw, expected):
    http = FakeHttp().add("POST", URL, json=fx("me_readonly.json"), times=1).add("POST", URL, **kw)
    res = run(http)
    assert res.status is expected and not res.findings


def test_covert_and_configuration():
    opts = ScanOptions()
    opts.no_internal = True
    http = FakeHttp()
    assert run(http, options=opts).status is Status.SKIPPED
    assert run(http, settings={}).status is Status.SKIPPED
    assert run(http, keys={}).status is Status.NEEDS_KEY
    assert http.calls == []


# ------------------------------------------------------------------ FC3: queries without mutations, key capabilities
@pytest.mark.parametrize(
    "document",
    [
        "mutation { stixCyberObservableAdd(type: \"IPv4-Addr\") { id } }",
        "mutation DeleteIt { stixCoreObjectEdit(id: \"x\") { delete } }",
        "subscription { stixCyberObservable(id: \"x\") { id } }",
        "  # a comment\n mutation { x }",
    ],
)
def test_mutations_and_subscriptions_are_refused(document):
    assert tip.opencti_query_allowed(document) is not None


def test_queries_are_allowed_and_only_post_graphql():
    assert tip.opencti_query_allowed(tip.OPENCTI_OBSERVABLE_QUERY) is None
    assert tip.opencti_query_allowed('query { about { version } } # "mutation"') is None
    assert tip.opencti_query_allowed('query { x(search: "mutation { y }") }') is None
    adapter = OpenCtiSightings()
    assert adapter.request_allowed("GET", "/graphql", {"query": "query { me { id } }"}) is not None
    assert adapter.request_allowed("POST", "/graphql/upload", {"query": "query { me { id } }"}) is not None
    assert adapter.request_allowed("POST", "/graphql", {"query": "query { me { id } }", "extra": 1}) is not None


def test_write_capable_token_warns():
    http = routes(FakeHttp(), "observables_hit.json", me="me_write.json")
    rt = make_runtime(http, keys=KEYS, settings=SETTINGS)
    events = []
    rt.events.subscribe(lambda kind, payload: events.append((kind, payload)))
    res = run_module(OpenCtiSightings, f"ipv4:{VALUE}", runtime=rt)
    warnings = [p["message"] for k, p in events if k == "log" and p.get("level") == "warning"]
    assert len(warnings) == 1 and "KNOWLEDGE_KNUPDATE" in warnings[0]
    assert res.raw["key_check"]["write_permissions"] == ["KNOWLEDGE_KNUPDATE", "KNOWLEDGE_KNUPDATE_KNDELETE"]
    assert tip.opencti_write_capabilities(fx("me_readonly.json")) == []


def test_parsers_tolerate_junk():
    assert tip.parse_opencti_observables({"data": {"stixCyberObservables": {"edges": "x"}}}, VALUE, tip.datetime.now(tip.timezone.utc)) is None
    junk = {"data": {"stixCyberObservables": {"edges": [None, {"node": {"observable_value": VALUE, "objectMarking": "x", "indicators": {"edges": [None]}}}]}}}
    [hit] = tip.parse_opencti_observables(junk, VALUE, tip.datetime.now(tip.timezone.utc))["hits"]
    assert hit["verdict"] == "observed" and hit["tlp"] is None
    assert tip.opencti_write_capabilities({"data": None}) is None
