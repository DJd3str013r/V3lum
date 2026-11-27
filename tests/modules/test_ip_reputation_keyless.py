"""Offline tests of ip_reputation_keyless (P150) with the recorded IPGuardian and NetAPI answers in
tests/fixtures/ip_reputation_keyless/ (the NetAPI feed fixtures live in tests/fixtures/netapi_compromised_feeds/)."""

from __future__ import annotations

import json

import pytest

from tests.fakes import FakeHttp, make_runtime, module_fixture, run_module
from v3lum.core.datasets import DATASETS
from v3lum.core.models import Severity, Status
from v3lum.modules.threat_intel_ioc import netapi_compromised_feeds as feeds
from v3lum.modules.threat_intel_ioc.ip_reputation_keyless import (
    IpReputationKeyless,
    ipguardian_vote,
    list_stem,
    p149_feeds,
    parse_ipguardian,
    parse_netapi,
)

FIX = "ip_reputation_keyless"
IPG = "https://ipguardian.net/api/check"
NETAPI = "https://netapi.com/api-json/?method=compromised-check&value={v}"


def fx(name: str):
    return module_fixture(FIX, name)


def found_with(*lists: tuple[str, str]) -> dict:
    """The recorded found:true answer with its sources replaced (file name, category)."""
    doc = json.loads(json.dumps(fx("ipguardian_found_lists.json")))
    doc["results"]["ip"] = "9.9.9.9"
    doc["results"]["sources"] = [{"filename": f, "category": c, "maintainer": "x", "listed_since": "2026-11-01T00:00:00Z"} for f, c in lists]
    return doc


def routes(ip: str = "9.9.9.9", ipg: dict | None = None, netapi: dict | None = None, value: str | None = None) -> FakeHttp:
    http = FakeHttp()
    if ipg is not None:
        http.add("POST", IPG, **ipg)
    if netapi is not None:
        http.add("GET", NETAPI.format(v=value or ip), **netapi)
    return http


def test_metadata_follows_the_council_decision():
    cls = IpReputationKeyless
    assert (cls.terms, cls.trust_tier, cls.default_enabled) == ("unknown", "unknown", False)  # FC1
    assert {t.value for t in cls.accepts} == {"ipv4", "domain", "url"}
    assert cls.sources == ("ipguardian.check", "netapi.check") and set(cls.hosts) == {"ipguardian.net", "netapi.com"}


def test_not_listed_anywhere_is_empty():
    http = routes(ipg={"json": fx("ipguardian_not_found.json")}, netapi={"json": fx("netapi_check_not_listed_ip.json")})
    res = run_module(IpReputationKeyless, "ipv4:9.9.9.9", http)
    assert res.status is Status.EMPTY
    assert {s: v["status"] for s, v in res.source_statuses.items()} == {"ipguardian.check": "ok", "netapi.check": "ok"}
    body = json.loads(next(c for c in http.calls if c["method"] == "POST")["body"])
    assert body == {"ip": "9.9.9.9"}
    http.assert_hosts_within(IpReputationKeyless)


def test_lists_already_matched_by_p149_add_no_vote_and_bogon_lists_are_ignored():
    http = routes(ipg={"json": fx("ipguardian_found_lists.json")}, netapi={"json": fx("netapi_check_not_listed_ip.json")})
    res = run_module(IpReputationKeyless, "ipv4:9.9.9.9", http)
    lists = res.attributes["ipguardian_lists"]
    assert lists["covered_by_p149"] == ["firehol_level1"]
    assert sorted(lists["ignored_lists"]) == ["cidr_report_bogons", "iblocklist_cidr_report_bogons"]
    assert lists["new_lists"] == [] and "blocklists" not in res.attributes
    (finding,) = res.findings
    assert finding.severity is Severity.INFO and "context_only" in finding.tags


def test_one_vote_never_above_low_and_never_malicious():
    doc = found_with(("bi_any_2_30d.ipset", "attacks"), ("stopforumspam_7d.ipset", "abuse"), ("tor_exits.ipset", "anonymizers"))
    http = routes(ipg={"json": doc}, netapi={"json": fx("netapi_check_listed_synthetic.json")})
    res = run_module(IpReputationKeyless, "ipv4:9.9.9.9", http)
    assert res.status is Status.OK
    (finding,) = res.findings  # ONE vote for the whole module
    assert finding.severity is Severity.LOW and finding.tags == ["suspicious"] and finding.confidence_label.value == "possible"
    assert "malicious" not in str(res.findings[0].to_dict()["tags"])
    assert res.attributes["blocklists"] == ["bi_any_2_30d", "stopforumspam_7d"]
    assert res.attributes["ipguardian_lists"]["context_lists"] == ["tor_exits"]
    assert res.attributes["netapi_compromised"]["listed_now"] is True


def test_local_netapi_feed_answers_first(monkeypatch):
    monkeypatch.setattr(feeds, "MIN_IP_ROWS", 5)
    monkeypatch.setitem(DATASETS[feeds.IP_FEED], "min_bytes", 10)
    with open("tests/fixtures/netapi_compromised_feeds/compromised_ip_slice.txt", "rb") as fh:
        feed = fh.read()
    http = FakeHttp().add("GET", feeds.IP_FEED_URL, body=feed, headers={"content-type": "text/plain"})
    rt = make_runtime(http)
    assert rt.data.update(feeds.IP_FEED).ok
    http.calls.clear()
    http.add("POST", IPG, json=fx("ipguardian_not_found.json"))
    res = run_module(IpReputationKeyless, "ipv4:9.9.9.9", http, runtime=rt)
    assert res.source_statuses["netapi.check"]["status"] == "skipped" and "local first" in res.source_statuses["netapi.check"]["reason"]
    assert [c["url"] for c in http.calls] == [IPG]  # no per-IP NetAPI call


def test_domains_and_url_hosts_go_to_netapi_only_and_never_with_a_path():
    http = routes(netapi={"json": fx("netapi_check_not_listed_domain.json")}, value="example.com")
    res = run_module(IpReputationKeyless, "url:https://example.com/login?user=someone%40example.com", http)
    assert res.status is Status.EMPTY
    (call,) = http.calls
    assert "login" not in call["url"] and "someone" not in call["url"]  # host only
    assert res.source_statuses == {"netapi.check": res.source_statuses["netapi.check"]}


def test_failures_are_could_not_verify_never_empty():
    invalid = fx("ipguardian_invalid_400.json")
    http = routes(ipg={"status": invalid["_status"], "json": invalid["body"]}, netapi={"status": 429, "text": "slow down"})
    res = run_module(IpReputationKeyless, "ipv4:9.9.9.9", http)
    assert res.status is Status.ERROR and "Invalid IP addresses" in res.error
    assert res.source_statuses["netapi.check"]["status"] == "rate_limited"
    netapi_err = fx("netapi_check_invalid_400.json")
    with open("tests/fixtures/ip_reputation_keyless/ipguardian_malformed_truncated.txt", encoding="utf-8") as fh:
        truncated = fh.read()
    http = routes(ipg={"text": truncated, "headers": {"content-type": "application/json"}},
                  netapi={"status": netapi_err["_status"], "json": netapi_err["body"]})
    assert run_module(IpReputationKeyless, "ipv4:9.9.9.9", http).status is Status.ERROR
    http = routes(ipg={"json": {"success": False, "error": "busy"}}, netapi={"json": {"error": {"code": "internal", "message": "oops"}}})
    assert run_module(IpReputationKeyless, "ipv4:9.9.9.9", http).status is Status.ERROR
    page = "<html><head><title>Just a moment...</title></head><body>cf-chl-widget</body></html>"
    http = routes(ipg={"status": 403, "text": page}, netapi={"status": 503, "text": "down"})
    assert run_module(IpReputationKeyless, "ipv4:9.9.9.9", http).status is Status.BLOCKED


def test_one_source_down_still_answers_with_the_other():
    http = routes(ipg={"status": 502, "text": "bad gateway"}, netapi={"json": fx("netapi_check_listed_synthetic.json")})
    res = run_module(IpReputationKeyless, "ipv4:9.9.9.9", http)
    assert res.status is Status.OK and res.findings[0].severity is Severity.LOW
    assert res.source_statuses["ipguardian.check"]["status"] == "error"


def test_bogons_are_never_sent():
    http = FakeHttp()
    for value in ("ipv4:10.0.0.1", "ipv4:192.0.2.1", "url:https://192.168.1.1/x"):
        assert run_module(IpReputationKeyless, value, http).status is Status.SKIPPED
    assert http.calls == []


@pytest.mark.parametrize("name,stem", [("firehol_level1.netset", "firehol_level1"), ("lists/ET_Compromised.ipset", "et_compromised"), (None, "")])
def test_list_stems(name, stem):
    assert list_stem(name) == stem


def test_parsers_and_vote_helpers():
    parsed = parse_ipguardian(fx("ipguardian_not_found_1111.json"))
    assert parsed["found"] is False and parsed["network"]["type"]
    assert parse_ipguardian({"success": True, "results": {"found": "maybe"}}) is None
    assert parse_netapi(fx("netapi_check_not_listed_ip.json"))["licence_hint"] == "CC BY 4.0"
    assert parse_netapi({"listed_now": "x"}) is None
    vote = ipguardian_vote({"lists": [{"list": "firehol_level1", "category": "attacks"}]}, p149_feeds())
    assert vote["vote"] is False and vote["covered_by_p149"] == ["firehol_level1"]
