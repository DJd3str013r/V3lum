"""misp_sightings (P348, MISP 2.5): read-only restSearch on the company MISP.

Fixtures in tests/fixtures/misp_sightings/ are SYNTHETIC (the instance is self-hosted and cannot be
reached from the research egress), shaped on the MISP 2.5 OpenAPI schemas (AttributeRestSearchListItem,
Tag, Sighting, DecayScore, ExtendedEvent with Orgc) and the UnauthorizedApiErrorResponse; documentation
values only (198.51.100.0/24, EXAMPLE-* organisations, *@example.com service accounts). restsearch_hit
holds five attributes: listed (to_ids, AMBER, galaxy tags, sightings), context (to_ids=false, newest
sighting a false positive), decayed, warninglisted (ip-dst|port composite) and a neighbour address.
"""

from __future__ import annotations

import inspect
import json

import pytest

from tests.fakes import FakeHttp, assert_no_secret, make_runtime, module_fixture, run_module
from v3lum.core.context import ScanOptions
from v3lum.core.http import PolicyError
from v3lum.core.models import Status
from v3lum.modules.cti_framework import internal_tip_sightings as tip
from v3lum.modules.cti_framework.internal_tip_sightings import MispSightings

BASE = "https://misp.example.com"
KEY = "misp-test-key-0123456789abcdefghij"
KEYS = {"misp": KEY}
SETTINGS = {"misp_url": BASE}
VALUE = "198.51.100.23"


def fx(name):
    return module_fixture(MispSightings, name)


def routes(http, *, me="users_view_me_readonly.json", search="restsearch_hit.json", events="events_metadata.json"):
    if me:
        http.add("GET", f"{BASE}/users/view/me", json=fx(me), match_headers={"Authorization": KEY}, times=1)
    if search:
        http.add("POST", f"{BASE}/attributes/restSearch", json=fx(search), match_headers={"Authorization": KEY})
    if events:
        http.add("POST", f"{BASE}/events/restSearch", json=fx(events), match_headers={"Authorization": KEY})
    return http


def run(http, value=VALUE, etype="ipv4", **kw):
    kw.setdefault("keys", KEYS)
    kw.setdefault("settings", SETTINGS)
    return run_module(MispSightings, f"{etype}:{value}", http, **kw)


def by_key(res):
    return {f.key: f for f in res.findings}


# ------------------------------------------------------------------ metadata (FC1, FC2)
def test_contract_metadata():
    cls = MispSightings
    assert (cls.disclosure, cls.provider, cls.sources, cls.hosts) == ("internal", "internal_misp", ("internal_misp.events",), ())
    assert cls.category == "cti_framework" and cls.terms == "open" and cls.trust_tier == "n/a"
    assert cls.max_tlp.value_str == "red"  # internal platforms are allowed at TLP:RED
    assert cls.requires_keys == ("misp",) and cls.default_enabled is True
    assert cls.timeout == 5.0 and cls.min_interval == 0.5 and cls.cache_ttl == 0


# ------------------------------------------------------------------ FC5/FC6/FC7: hits, verdicts, markings, pivots
def test_restsearch_hits_verdicts_markings_and_pivots():
    http = routes(FakeHttp())
    res = run(http)
    assert res.status is Status.OK
    found = by_key(res)
    assert set(found) == {"misp:41021", "misp:41388", "misp:39554", "misp:41402"}  # the neighbour .230 is not an exact match
    listed = found["misp:41021"]
    assert listed.severity.label == "medium" and set(listed.tags) == {"internal_sighting", "malicious"}
    assert listed.data["ref"] == "MISP event #1734" and listed.data["org"] == "EXAMPLE-CSIRT"
    assert listed.data["tlp"] == "amber" and listed.data["date"] == "2026-10-14" and listed.data["verdict"] == "listed"
    assert listed.criterion and listed.source == "internal_misp.events"
    fp = found["misp:41388"]
    assert fp.severity.label == "info" and "false_positive" in fp.tags and "malicious" not in fp.tags
    assert fp.data["sharing_group"] == "12" and "sharing group" in fp.description and fp.data["org"] == "EXAMPLE-SECTOR-ISAC"
    historical = found["misp:39554"]
    assert historical.severity.label == "low" and "historical" in historical.tags and "malicious" not in historical.tags
    warned = found["misp:41402"]
    assert warned.severity.label == "info" and "warninglist" in warned.tags
    assert res.tlp == "amber"  # the highest marking, never downgraded (FC6)
    assert res.attributes["tip_score"] == 71.3
    assert res.attributes["allowlisted"] == ["MISP false-positive sighting", "MISP warninglist: Example benign scanners (synthetic)"]
    assert {h["ref"] for h in res.attributes["internal_sightings"]} == {"MISP event #1734", "MISP event #1802", "MISP event #1650", "MISP event #1811"}
    pivots = {(p.entity.type.value, p.entity.value): p for p in res.pivots}
    assert set(pivots) == {("threat_actor", "Example Actor"), ("malware_family", "Grandoreiro"), ("mitre_technique", "T1566")}
    assert all(p.expand is False for p in pivots.values())
    assert pivots[("threat_actor", "Example Actor")].relation == "attributed_to"
    assert pivots[("mitre_technique", "T1566")].relation == "uses_technique"
    assert res.attributes["threat_actors"] == ["Example Actor"] and res.attributes["attack_techniques"] == ["T1566"]
    assert res.redacted_fields == []
    http.assert_hosts_within(MispSightings)


def test_values_travel_only_in_json_bodies_with_bounded_results_and_timeouts():
    http = routes(FakeHttp())
    run(http)
    posts = [c for c in http.calls if c["method"] == "POST"]
    assert all("?" not in c["url"] and VALUE not in c["url"] for c in http.calls)
    search = json.loads(posts[0]["body"])
    assert search["value"] == VALUE and search["limit"] == 50 and search["includeDecayScore"] == 1
    assert json.loads(posts[1]["body"])["eventid"] == ["1734", "1802", "1650", "1811"]
    assert all(0 < (c["timeout"] or 99) <= 5.0 for c in http.calls)
    assert http.calls[0]["headers"]["Authorization"] == KEY  # MISP: the bare key, never in a URL


def test_no_hit_is_not_known_internally():
    http = routes(FakeHttp(), search="restsearch_empty.json", events=None)
    res = run(http)
    assert res.status is Status.EMPTY and "not known internally (MISP)" in res.error
    assert not res.findings


def test_event_metadata_failure_keeps_the_hits():
    http = routes(FakeHttp(), events=None).add("POST", f"{BASE}/events/restSearch", status=500, text="error")
    res = run(http)
    assert res.status is Status.OK and len(res.findings) == 4
    assert all("org unknown" in f.description for f in res.findings)


# ------------------------------------------------------------------ could not verify (FC4, rule 5)
def test_rejected_key_is_needs_key_and_never_leaks():
    exchange = fx("auth_failed.http.json")
    http = FakeHttp().add("GET", f"{BASE}/users/view/me", status=403, json=exchange["response"]["body"])
    http.add("POST", f"{BASE}/attributes/restSearch", status=403, json=exchange["response"]["body"])
    res = run(http)
    assert res.status is Status.NEEDS_KEY
    assert_no_secret(KEY, res.to_dict(), res.error, [f.to_dict() for f in res.findings], http.urls())


@pytest.mark.parametrize(
    ("kw", "expected"),
    [
        ({"status": 429, "text": "slow down"}, Status.RATE_LIMITED),
        ({"status": 500, "text": "error"}, Status.ERROR),
        ({"status": 404, "text": "not found"}, Status.ERROR),
        ({"status": 200, "text": "<html><body><form action='/users/login'>login</form></body></html>"}, Status.ERROR),
        ({"status": 200, "json": ["not", "a", "restSearch", "answer"]}, Status.ERROR),
    ],
)
def test_failures_are_could_not_verify(kw, expected):
    http = routes(FakeHttp(), search=None, events=None).add("POST", f"{BASE}/attributes/restSearch", **kw)
    res = run(http)
    assert res.status is expected and not res.findings


def test_error_inside_200_is_detected():
    http = routes(FakeHttp(), search=None, events=None).add("POST", f"{BASE}/attributes/restSearch", json={"errors": "Authentication failed: invalid API key"})
    res = run(http)
    assert res.status is Status.NEEDS_KEY


# ------------------------------------------------------------------ FC1/FC2/FC8: configuration, SSRF guard, covert
def test_not_configured_or_without_key_never_sends():
    http = FakeHttp()
    assert run(http, settings={}).status is Status.SKIPPED
    res = run(http, keys={})
    assert res.status is Status.NEEDS_KEY and http.calls == []
    res2 = run(http, settings={"misp_url": "http://misp.example.com"})
    assert res2.status is Status.SKIPPED and res2.reason_code == "config" and http.calls == []


def test_covert_exercise_skips_internal_lookups():
    opts = ScanOptions()
    opts.covert = True
    http = FakeHttp()
    res = run(http, options=opts)
    assert res.status is Status.SKIPPED and res.reason_code == "policy" and "covert" in res.error
    assert http.calls == []


def test_a_url_owned_by_a_third_party_provider_is_never_internal():
    # a 'misp_url' pointing at a host another provider owns never becomes an internal host (FC2)
    http = FakeHttp()
    res = run(http, settings={"misp_url": "https://hashlookup.circl.lu"})
    assert res.status is Status.SKIPPED and res.reason_code == "policy" and http.calls == []


# ------------------------------------------------------------------ FC3: read-only in code, TLS, key permissions
@pytest.mark.parametrize(
    ("method", "path"),
    [
        ("POST", "/attributes/add/1734"),
        ("POST", "/events/edit/1734"),
        ("POST", "/events/publish/1734"),
        ("POST", "/sightings/add"),
        ("POST", "/tags/attachTagToObject"),
        ("DELETE", "/attributes/delete/41021"),
        ("GET", "/attributes/restSearch/value:198.51.100.23"),
        ("POST", "/attributes/restSearch?value=198.51.100.23"),
        ("GET", "/attributes/restSearch"),
    ],
)
def test_write_and_query_string_calls_are_refused(method, path):
    assert tip.misp_request_allowed(method, path) is not None


def test_read_calls_are_allowed():
    for method, path in (("POST", "/attributes/restSearch"), ("POST", "/events/restSearch"), ("GET", "/users/view/me"), ("POST", "/sightings/restSearch/attribute")):
        assert tip.misp_request_allowed(method, path) is None


def test_the_adapter_cannot_send_a_write_call():
    http = FakeHttp()
    rt = make_runtime(http, keys=KEYS, settings=SETTINGS)
    from tests.fakes import make_ctx

    ctx = make_ctx(MispSightings, runtime=rt, entity=f"ipv4:{VALUE}")
    with pytest.raises(PolicyError):
        MispSightings().send(ctx, "POST", BASE, "/attributes/add/1734", KEY, {"value": VALUE})
    assert http.calls == []


def test_tls_verification_is_never_disabled_in_the_adapter():
    source = inspect.getsource(tip)
    assert "verify=False" not in source and "verify = False" not in source


def test_write_capable_key_warns_once_a_day():
    http = routes(FakeHttp(), me="users_view_me_write.json")
    rt = make_runtime(http, keys=KEYS, settings=SETTINGS)
    events = []
    rt.events.subscribe(lambda kind, payload: events.append((kind, payload)))
    res = run_module(MispSightings, f"ipv4:{VALUE}", runtime=rt)
    warnings = [p for k, p in events if k == "log" and p.get("level") == "warning"]
    assert len(warnings) == 1 and "write permissions" in warnings[0]["message"] and "perm_add" in warnings[0]["message"]
    assert res.raw["key_check"]["write_permissions"][:2] == ["perm_add", "perm_modify"]
    assert KEY not in warnings[0]["message"]
    res2 = run_module(MispSightings, f"ipv4:{VALUE}", runtime=rt)  # same day: no second users/view/me call
    assert res2.status is Status.OK
    assert sum(1 for c in http.calls if c["url"].endswith("/users/view/me")) == 1


def test_health_check_self_test_reports_write_permissions():
    from tests.fakes import make_ctx

    hc = MispSightings.health_check()
    assert hc.etype is None and callable(hc.selftest)
    http = FakeHttp().add("GET", f"{BASE}/users/view/me", json=fx("users_view_me_write.json"))
    ctx = make_ctx(MispSightings, http, keys=KEYS, settings=SETTINGS)
    result = hc.selftest(ctx)
    assert result.status == "ok" and result.detail.startswith("WARNING")
    http2 = FakeHttp().add("GET", f"{BASE}/users/view/me", json=fx("users_view_me_readonly.json"))
    assert hc.selftest(make_ctx(MispSightings, http2, keys=KEYS, settings=SETTINGS)).detail == "read-only key"
    assert hc.selftest(make_ctx(MispSightings, FakeHttp(), keys={}, settings=SETTINGS)).status == "needs_key"


# ------------------------------------------------------------------ FC6/FC9 helpers for renderers
def test_marking_helpers_and_the_known_internally_line():
    assert tip.finding_tlp("green", "amber") == "amber" and tip.finding_tlp("tlp:red", "amber") == "red"
    assert tip.visible_in_report("amber+strict", "amber") is False and tip.visible_in_report("green", "amber") is True
    line = tip.internal_sightings_line(
        {
            "thehive": [{"ref": "TheHive case #412", "tlp": "amber"}],
            "misp": [{"ref": "MISP event #1734", "tlp": "amber", "verdict": "listed"}, {"ref": "MISP event #1802", "tlp": "green", "verdict": "false_positive"}],
            "opencti": [{"ref": "OpenCTI report 'x'", "tlp": "red"}],
        },
        report_tlp="amber",
    )
    assert line == "known internally: MISP event #1734, MISP event #1802 (false positive), TheHive case #412"
    assert tip.normalize_tlp("TLP:WHITE") == "clear" and tip.normalize_tlp("tlp:amber+strict") == "amber+strict"


def test_parsers_tolerate_junk():
    assert tip.parse_misp_attributes({"response": "x"}, VALUE) is None
    assert tip.parse_misp_attributes({"response": []}, VALUE) == {"hits": [], "truncated": False}
    junk = {"response": {"Attribute": [None, {"value": VALUE, "Tag": "x", "Sighting": [None, {"type": "9"}], "decay_score": [{"score": "x"}]}]}}
    [hit] = tip.parse_misp_attributes(junk, VALUE)["hits"]
    assert hit["verdict"] == "context" and hit["decay"] is None
    assert tip.misp_key_write_perms({"Role": "x"}) is None
    assert tip.misp_attribute_search_body(VALUE, limit=0)["limit"] == 50  # 0 means 'all' in MISP: never sent
