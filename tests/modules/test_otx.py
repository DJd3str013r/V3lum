"""otx (P153): keyed OTX indicator lookups - parsing, verdict rules, section plan, bounds, status mapping.

Fixtures in tests/fixtures/otx/ (prepared 2026-11-26 from a datacenter egress, see the batch notes):
real answers trimmed and scrubbed (community authors -> community-user-*, pulse names -> 'Community
pulse NN', pulse ids synthetic): ``ipv4_general_whitelisted.json`` (8.8.8.8, live),
``domain_general_pulses.json`` (nic.br, live, 3 community pulses), ``file_general_whitelisted.json``
(EICAR md5, research sample), ``cve_general_labs.json`` (CVE-2021-44228 with labs pulses, research
sample), ``passive_dns_429_anonymous.json`` (live keyless 429 body) and ``bad_key_403.json`` (research
sample). Derived: ``ipv4_general_no_pulses.json`` (validation removed) and
``domain_general_truncated.txt`` (the domain answer cut in half). Synthetic (no keyed capture yet,
documented field names, documentation values): ``passive_dns_synthetic.json`` and
``url_list_synthetic.json``.
"""

from __future__ import annotations

import copy
import datetime as dt

import pytest

from tests.fakes import FakeHttp, assert_no_secret, make_ctx, module_fixture, run_module
from v3lum.core.context import ScanOptions
from v3lum.core.entities import Entity
from v3lum.core.entities import EntityType as T
from v3lum.core.http import NetworkError
from v3lum.core.models import Status
from v3lum.modules.threat_intel_ioc import otx as mod
from v3lum.modules.threat_intel_ioc.otx import Otx, OtxKeyless

KEY = "otx-test-key-0123456789abcdef"
KEYS = {"otx": KEY}
BASE = "https://otx.alienvault.com/api/v1/indicators"
NOW = dt.datetime(2026, 11, 26, 12, 0, tzinfo=dt.timezone.utc)


def fx(name):
    return module_fixture(Otx, name)


def url(cat, value, section="general", page=None):
    out = f"{BASE}/{cat}/{value}/{section}"
    return out + (f"?limit=100&page={page}" if page else "")


def pivots(res, etype=None):
    return {p.entity.value for p in res.pivots if etype is None or p.entity.type is etype}


def recent_copy(general, **changes):
    """A copy of a general answer with pulse fields changed: changes = {index: {field: value}}."""
    data = copy.deepcopy(general)
    for index, fields in changes.items():
        data["pulse_info"]["pulses"][int(index)].update(fields)
    return data


# ------------------------------------------------------------------ metadata (council decisions)
def test_contract_metadata():
    cls = Otx
    assert (cls.terms, cls.disclosure, cls.provider, cls.sources, cls.hosts) == ("key-terms", "third_party", "otx", ("otx.indicators",), ("otx.alienvault.com",))
    assert cls.requires_keys == ("otx",) and cls.default_enabled is True
    assert cls.trust_tier == "trusted" and cls.shares_input is True
    assert (cls.cache_ttl, cls.min_interval) == (86400, 1.0)
    assert cls.max_requests <= 10 and cls.expected_latency <= 10
    assert "abuse.ch" in cls.upstream_families and "otx" in cls.upstream_families  # pulses relaying abuse.ch (P171)
    assert "key-terms" in cls.notice
    assert mod.MAX_BYTES == 5_000_000 and mod.MAX_PULSES == 50 and mod.TIMEOUT_S == {"quick": 20.0, "deep": 60.0}


def test_one_parser_shared_by_both_classes():
    assert issubclass(Otx, mod._OtxBase) and issubclass(OtxKeyless, mod._OtxBase)
    assert Otx.run is OtxKeyless.run and Otx._record_general is OtxKeyless._record_general


# ------------------------------------------------------------------ read-only by construction (cond 2)
def test_request_allow_list_is_read_only():
    good = url("IPv4", "8.8.8.8")
    assert mod.request_allowed("GET", good)
    assert mod.request_allowed("GET", url("domain", "nic.br", "url_list", page=2))
    refused = [
        ("POST", good),
        ("GET", "https://otx.alienvault.com/api/v1/pulses/create"),
        ("GET", "https://otx.alienvault.com/api/v1/pulses/6b0000000000000000000001/indicators"),
        ("GET", "https://otx.alienvault.com/api/v1/indicators/submit_url"),
        ("GET", url("IPv4", "8.8.8.8", "http_scans")),
        ("GET", url("file", "44d88612fea8a8f36de82e1278abb02f", "analysis")),
        ("GET", url("IPv4", "8.8.8.8") + "?limit=1"),
        ("GET", "http://otx.alienvault.com/api/v1/indicators/IPv4/8.8.8.8/general"),
        ("GET", "https://otx.example.com/api/v1/indicators/IPv4/8.8.8.8/general"),
    ]
    for method, target in refused:
        assert not mod.request_allowed(method, target), (method, target)


def test_indicator_urls_and_categories():
    assert mod.indicator_url(Entity.make("domain", "nic.br")) == url("domain", "nic.br")
    assert mod.indicator_url(Entity.make("domain", "www.registro.br")) == url("hostname", "www.registro.br")
    assert mod.indicator_url(Entity.make("domain", "example.com.br")) == url("domain", "example.com.br")  # PSL, not label count
    assert mod.indicator_url(Entity.make("md5", "44D88612FEA8A8F36DE82E1278ABB02F")) == url("file", "44d88612fea8a8f36de82e1278abb02f")
    assert mod.indicator_url(Entity.make("cve", "cve-2021-44228")) == url("cve", "CVE-2021-44228")
    assert mod.indicator_url(Entity.make("url", "https://example.com/a?b=1")) == url("url", "https://example.com/a%3Fb%3D1")
    assert mod.indicator_url(Entity.make("ipv4", "8.8.8.8"), "passive_dns") == url("IPv4", "8.8.8.8", "passive_dns")
    assert mod.indicator_url(Entity.make("sha256", "275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f"), "passive_dns") is None


def test_section_plan():
    ip, dom, h = Entity.make("ipv4", "8.8.8.8"), Entity.make("domain", "nic.br"), Entity.make("md5", "44d88612fea8a8f36de82e1278abb02f")
    assert mod.plan_sections(ip, 0, is_seed=True) == ["general", "passive_dns"]
    assert mod.plan_sections(ip, 0, is_seed=False) == ["general"]  # passive_dns for seeds only
    assert mod.plan_sections(dom, 3, is_seed=False) == ["general", "url_list", "malware"]  # pulse_count > 0
    assert mod.plan_sections(dom, 0, is_seed=False, preset="deep") == ["general", "url_list", "malware"]
    assert mod.plan_sections(dom, 3, is_seed=True, keyless=True) == ["general"]
    assert mod.plan_sections(h, 9, is_seed=True) == ["general"]
    assert mod.plan_sections(dom, 3, is_seed=True, available=["general", "passive_dns"]) == ["general", "passive_dns"]


def test_call_timeout_bounds():
    assert mod.call_timeout("quick", None) == 20.0
    assert mod.call_timeout("deep", None) == 60.0
    assert mod.call_timeout("deep", 7.5) == 7.5  # never past the run deadline


# ------------------------------------------------------------------ happy paths
def test_whitelisted_ip_is_noise_never_malicious():
    http = FakeHttp().add("GET", url("IPv4", "8.8.8.8"), json=fx("ipv4_general_whitelisted.json"),
                          match_headers={"X-OTX-API-KEY": KEY})
    http.add("GET", url("IPv4", "8.8.8.8", "passive_dns"), json={"passive_dns": [], "count": 0})
    res = run_module(Otx, "ipv4:8.8.8.8", http, keys=KEYS)
    assert res.status is Status.OK
    assert [f.severity.label for f in res.findings] == ["info"]
    finding = res.findings[0]
    assert "known_good" in finding.tags and "malicious" not in finding.tags
    assert "Whitelisted IP" in res.attributes["allowlisted"]
    assert res.attributes["asn"] == "AS15169" and res.attributes["country"] == "US"
    assert not res.pivots
    assert ("OTX indicator page", "https://otx.alienvault.com/indicator/ip/8.8.8.8") in res.links
    http.assert_hosts_within(Otx)


def test_domain_with_community_pulses_is_mentioned_low():
    http = FakeHttp().add("GET", url("domain", "nic.br"), json=fx("domain_general_pulses.json"))
    http.add("GET", url("domain", "nic.br", "url_list", page=1), json=fx("url_list_synthetic.json"))
    http.add("GET", url("domain", "nic.br", "malware"), json={"data": [], "count": 0})
    res = run_module(Otx, "domain:nic.br", http, keys=KEYS, is_seed=False)
    assert res.status is Status.OK
    finding = next(f for f in res.findings if f.title == "Mentioned in OTX community pulses")
    assert finding.severity.label == "low" and str(finding.confidence_label.value) == "possible"
    assert "weak_signal" in finding.tags and "malicious" not in finding.tags
    assert finding.criterion and finding.source == "otx.indicators"
    assert finding.data["pulse_count"] == 3 and len(finding.data["top_pulses"]) == 3
    assert finding.observed_first.startswith("2024-10-01") and finding.observed_last.startswith("2026-08-06")
    assert res.attributes["otx_pulse_count"] == 3
    assert [p["name"] for p in res.attributes["otx_pulses"]] == ["Community pulse 01", "Community pulse 02", "Community pulse 03"]
    # cond 7: families/actors/techniques are expand=False pivots, junk labels ('MD5 Hash: ...') dropped
    assert {"Mirai", "Artro", "StealthWorker / GoBrut"} <= pivots(res, T.MALWARE)
    assert not any("hash" in v.lower() for v in pivots(res, T.MALWARE))
    assert "StealthWorker/GoBrut" in pivots(res, T.THREAT_ACTOR)
    assert {"T1001", "T1071", "T1105"} <= pivots(res, T.MITRE)
    label_pivots = [p for p in res.pivots if p.entity.type in (T.MALWARE, T.THREAT_ACTOR, T.MITRE)]
    assert label_pivots and all(p.expand is False for p in label_pivots)
    assert {p.relation for p in label_pivots} == {"family", "attributed_to", "uses_technique"}
    # url_list (pulse_count > 0) -> URL pivots, expand=False
    assert {"http://www.example.com/login.php", "http://www.example.com/a.exe"} <= pivots(res, T.URL)
    assert res.requests == 3
    http.assert_hosts_within(Otx)


def test_two_distinct_recent_authors_make_it_malicious():
    general = recent_copy(fx("domain_general_pulses.json"), **{"2": {"modified": "2026-10-01T00:00:00"}})
    http = FakeHttp().add("GET", url("domain", "nic.br"), json=general)
    http.add("GET", url("domain", "nic.br", "url_list", page=1), json={"url_list": [], "has_next": False})
    http.add("GET", url("domain", "nic.br", "malware"), json={"data": []})
    res = run_module(Otx, "domain:nic.br", http, keys=KEYS, is_seed=False)
    finding = next(f for f in res.findings if f.title == "OTX pulses flag the indicator as malicious")
    assert finding.severity.label == "high" and "malicious" in finding.tags
    assert finding.data["distinct_recent_authors"] == 2
    assert res.attributes["malicious"] is True


def test_clone_of_a_counted_pulse_is_not_a_second_opinion():
    # pulse 02 is a clone of pulse 03 and has another author: still one opinion
    general = recent_copy(fx("domain_general_pulses.json"),
                          **{"0": {"author": {"username": "community-user-b", "id": "0"}, "cloned_from": "6b0000000000000000000002"},
                             "2": {"modified": "2026-10-01T00:00:00"}})
    parsed = mod.parse_general(general)
    result = mod.verdict(parsed, NOW)
    assert result["verdict"] == "mentioned", result


def test_labs_pulse_alone_is_malicious_but_cves_are_only_referenced():
    labs = fx("cve_general_labs.json")
    parsed = mod.parse_general(labs)
    assert mod.verdict(parsed, NOW)["verdict"] == "malicious"
    assert mod.verdict(parsed, NOW, is_cve=True)["verdict"] == "referenced"
    http = FakeHttp().add("GET", url("cve", "CVE-2021-44228"), json=labs)
    res = run_module(Otx, "cve:CVE-2021-44228", http, keys=KEYS)
    assert res.status is Status.OK
    finding = next(f for f in res.findings if f.title == "CVE referenced in OTX threat pulses")
    assert finding.severity.label == "medium" and "malicious" not in finding.tags
    assert not any("malicious" in f.tags for f in res.findings)
    assert res.attributes["cvss"] == 10.0 and res.attributes["exploited_in_wild"] is True
    assert "Cobalt Strike" in pivots(res, T.MALWARE) and "DragonForce" in pivots(res, T.THREAT_ACTOR)
    assert res.requests == 1  # CVEs have the general section only


def test_abusech_relays_count_as_one_author():
    general = fx("domain_general_pulses.json")
    data = copy.deepcopy(general)
    pulses = data["pulse_info"]["pulses"]
    pulses[0].update({"name": "URLhaus malware URLs", "modified": "2026-11-01T00:00:00"})
    pulses[2].update({"name": "ThreatFox IOCs", "modified": "2026-11-02T00:00:00", "author": {"username": "community-user-z", "id": "0"}})
    pulses[1].update({"cloned_from": None, "name": "abuse.ch feed relay", "author": {"username": "community-user-y", "id": "0"}})
    result = mod.verdict(mod.parse_general(data), NOW)
    assert result["verdict"] == "mentioned" and result["authors"] == ["upstream:abuse.ch"]
    assert result["upstream_families"] == ["abuse.ch"]


def test_whitelisted_hash_has_no_pivots():
    data = fx("file_general_whitelisted.json")
    http = FakeHttp().add("GET", url("file", "44d88612fea8a8f36de82e1278abb02f"), json=data)
    res = run_module(Otx, "md5:44d88612fea8a8f36de82e1278abb02f", http, keys=KEYS)
    assert res.status is Status.OK
    assert [f.severity.label for f in res.findings] == ["info"] and "Whitelisted hash" in res.attributes["allowlisted"]
    assert not res.pivots  # no 'Jane Doe' family pivot from a whitelisted indicator's community pulses


def test_benign_infrastructure_with_pulses_is_noise():
    http = FakeHttp().add("GET", url("IPv4", "8.8.8.8"), json=fx("domain_general_pulses.json"))
    res = run_module(Otx, "ipv4:8.8.8.8", http, keys=KEYS, is_seed=False)
    assert [f.severity.label for f in res.findings] == ["info"]
    assert "benign infrastructure" in res.findings[0].description
    assert not res.pivots


def test_no_pulses_is_empty():
    http = FakeHttp().add("GET", url("IPv4", "45.33.32.156"), json=fx("ipv4_general_no_pulses.json"))
    res = run_module(Otx, "ipv4:45.33.32.156", http, keys=KEYS, is_seed=False)
    assert res.status is Status.EMPTY and not res.findings and not res.pivots


def test_pulses_are_capped_by_recency():
    base = fx("domain_general_pulses.json")["pulse_info"]["pulses"][0]
    many = []
    for i in range(60):
        pulse = copy.deepcopy(base)
        pulse.update({"id": f"6b{i:022x}", "name": f"Community pulse {i:02d}", "modified": f"2026-{(i % 12) + 1:02d}-01T00:00:00",
                      "author": {"username": f"community-user-{i}", "id": "0"}, "cloned_from": None})
        many.append(pulse)
    parsed = mod.parse_general({"indicator": "nic.br", "pulse_info": {"count": 60, "pulses": many}})
    assert len(parsed["pulses"]) == 50 and parsed["pulses_capped"] and parsed["pulse_count"] == 60
    modified = [p["modified"] for p in parsed["pulses"]]
    assert modified == sorted(modified, reverse=True)


def test_passive_dns_for_seeds_and_pivot_rules():
    pdns = copy.deepcopy(fx("passive_dns_synthetic.json"))
    pdns["passive_dns"].append({"address": "8.8.4.4", "first": "2026-03-01T00:00:00", "last": "2026-11-01T00:00:00",
                                "hostname": "nic.br", "record_type": "A", "asn": None})
    http = FakeHttp().add("GET", url("domain", "nic.br"), json=fx("domain_general_pulses.json"))
    http.add("GET", url("domain", "nic.br", "passive_dns"), json=pdns)
    http.add("GET", url("domain", "nic.br", "url_list", page=1), json={"url_list": [], "has_next": False})
    http.add("GET", url("domain", "nic.br", "malware"), json={"data": [{"hash": "275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f",
                                                                          "datetime_int": 1763000000}]})
    res = run_module(Otx, "domain:nic.br", http, keys=KEYS, is_seed=True)
    assert res.status is Status.OK and res.requests == 4
    rows = res.attributes["passive_dns"]
    assert {r["address"] for r in rows} >= {"192.0.2.10", "NXDOMAIN", "mail.example.net", "8.8.4.4"}
    assert pivots(res, T.IPV4) == {"8.8.4.4"}  # documentation/NXDOMAIN addresses never become IP pivots
    assert "mail.example.net" in pivots(res, T.DOMAIN)
    assert all(p.expand is False for p in res.pivots)
    assert pivots(res, T.SHA256) == {"275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f"}
    assert res.attributes["malware_samples"][0]["type"] == "sha256"


def test_passive_dns_of_an_ip_gives_hostnames():
    http = FakeHttp().add("GET", url("IPv4", "45.33.32.156"), json=fx("ipv4_general_no_pulses.json"))
    http.add("GET", url("IPv4", "45.33.32.156", "passive_dns"), json=fx("passive_dns_synthetic.json"))
    res = run_module(Otx, "ipv4:45.33.32.156", http, keys=KEYS, is_seed=True)
    assert res.status is Status.OK
    assert {"www.example.com", "old.example.com", "example.com"} <= pivots(res, T.DOMAIN)
    assert {p.relation for p in res.pivots} == {"hosted_domain"}


def test_url_list_pages_until_has_next_is_false():
    page1 = copy.deepcopy(fx("url_list_synthetic.json"))
    page1["has_next"] = True
    page2 = {"url_list": [{"url": "http://www.example.com/next.php", "date": "2026-11-01T00:00:00", "httpcode": 200}], "has_next": False}
    http = FakeHttp().add("GET", url("domain", "nic.br"), json=fx("domain_general_pulses.json"))
    http.add("GET", url("domain", "nic.br", "url_list", page=1), json=page1)
    http.add("GET", url("domain", "nic.br", "url_list", page=2), json=page2)
    http.add("GET", url("domain", "nic.br", "malware"), json={"data": []})
    res = run_module(Otx, "domain:nic.br", http, keys=KEYS, is_seed=False)
    assert "http://www.example.com/next.php" in pivots(res, T.URL)
    assert len(res.attributes["observed_urls"]) == 3


# ------------------------------------------------------------------ keys and status mapping (cond 4)
def test_needs_key_without_the_key():
    res = run_module(Otx, "ipv4:8.8.8.8", FakeHttp())
    assert res.status is Status.NEEDS_KEY and res.reason_code == "needs_key"


def test_bad_key_403_is_needs_key():
    http = FakeHttp().add("GET", url("IPv4", "45.33.32.156"), status=403, json=fx("bad_key_403.json"))
    res = run_module(Otx, "ipv4:45.33.32.156", http, keys=KEYS)
    assert res.status is Status.NEEDS_KEY and res.reason_code == "needs_key"
    assert not res.findings


def test_bad_key_on_a_keyed_section_is_needs_key():
    http = FakeHttp().add("GET", url("IPv4", "45.33.32.156"), json=fx("ipv4_general_no_pulses.json"))  # general ignores bad keys
    http.add("GET", url("IPv4", "45.33.32.156", "passive_dns"), status=403, json=fx("bad_key_403.json"))
    res = run_module(Otx, "ipv4:45.33.32.156", http, keys=KEYS, is_seed=True)
    assert res.status is Status.NEEDS_KEY


def test_429_is_rate_limited_never_absent():
    http = FakeHttp().add("GET", url("IPv4", "45.33.32.156"), status=429, json=fx("passive_dns_429_anonymous.json"))
    res = run_module(Otx, "ipv4:45.33.32.156", http, keys=KEYS)
    assert res.status is Status.RATE_LIMITED and res.reason_code == "rate_limited"
    assert not res.findings


def test_429_on_a_keyed_section_keeps_the_general_verdict_as_partial():
    http = FakeHttp().add("GET", url("domain", "nic.br"), json=fx("domain_general_pulses.json"))
    http.add("GET", url("domain", "nic.br", "passive_dns"), status=429, json=fx("passive_dns_429_anonymous.json"))
    res = run_module(Otx, "domain:nic.br", http, keys=KEYS, is_seed=True)
    assert res.status is Status.OK and res.partial and res.stop_reason == "rate_limited"
    assert any(f.title == "Mentioned in OTX community pulses" for f in res.findings)


def test_5xx_on_a_keyed_section_is_noted_and_the_rest_continues():
    http = FakeHttp().add("GET", url("domain", "nic.br"), json=fx("domain_general_pulses.json"))
    http.add("GET", url("domain", "nic.br", "url_list", page=1), status=502, text="bad gateway")
    http.add("GET", url("domain", "nic.br", "malware"), json={"data": []})
    res = run_module(Otx, "domain:nic.br", http, keys=KEYS, is_seed=False)
    assert res.status is Status.OK and "url_list: could not verify" in res.error


@pytest.mark.parametrize("status", [500, 503])
def test_5xx_on_general_is_error(status):
    http = FakeHttp().add("GET", url("IPv4", "45.33.32.156"), status=status, text="upstream error")
    res = run_module(Otx, "ipv4:45.33.32.156", http, keys=KEYS)
    assert res.status is Status.ERROR and not res.findings
    assert len(http.calls) == 1  # retries=0: OTX calls are bounded


def test_timeout_is_could_not_verify():
    http = FakeHttp().add("GET", url("IPv4", "45.33.32.156"), error=NetworkError("ReadTimeout contacting otx.alienvault.com: timed out", reason_code="timeout", retryable=True))
    res = run_module(Otx, "ipv4:45.33.32.156", http, keys=KEYS)
    assert res.status is Status.ERROR and res.reason_code == "timeout"


def test_undeclared_404_is_error_not_absent():
    http = FakeHttp().add("GET", url("IPv4", "45.33.32.156"), status=404, json={"detail": "Not found."})
    res = run_module(Otx, "ipv4:45.33.32.156", http, keys=KEYS)
    assert res.status is Status.ERROR


def test_400_invalid_indicator_is_not_applicable():
    http = FakeHttp().add("GET", url("domain", "nic.br"), status=400, json={"detail": "Invalid domain"})
    res = run_module(Otx, "domain:nic.br", http, keys=KEYS)
    assert res.status is Status.SKIPPED and res.reason_code == "not_applicable"


def test_error_inside_http_200_is_never_empty():
    http = FakeHttp().add("GET", url("IPv4", "45.33.32.156"), json=fx("bad_key_403.json"))
    res = run_module(Otx, "ipv4:45.33.32.156", http, keys=KEYS)
    assert res.status is Status.ERROR and "could not verify" in res.error


@pytest.mark.parametrize("body", ["truncated", "html", "list"])
def test_malformed_answers_are_could_not_verify(body):
    route = {"truncated": {"text": fx("domain_general_truncated.txt")},
             "html": {"text": "<html><head><title>502 ERROR</title></head><body>The request could not be satisfied.</body></html>"},
             "list": {"json": ["not", "an", "object"]}}[body]
    http = FakeHttp().add("GET", url("domain", "nic.br"), **route)
    res = run_module(Otx, "domain:nic.br", http, keys=KEYS)
    assert res.status is Status.ERROR and "could not verify" in res.error and not res.findings


def test_challenge_page_is_blocked():
    page = "<!DOCTYPE html><html><head><title>Just a moment...</title></head><body><div id='cf-chl-widget'></div></body></html>"
    http = FakeHttp().add("GET", url("IPv4", "45.33.32.156"), status=403, text=page)
    res = run_module(Otx, "ipv4:45.33.32.156", http, keys=KEYS)
    assert res.status is Status.BLOCKED and res.reason_code == "challenge"


def test_truncated_answer_is_never_parsed_as_complete(monkeypatch):
    monkeypatch.setattr(mod, "MAX_BYTES", 1000)
    http = FakeHttp().add("GET", url("domain", "nic.br"), json=fx("domain_general_pulses.json"))
    res = run_module(Otx, "domain:nic.br", http, keys=KEYS)
    assert res.status is Status.ERROR and "truncated" in res.error and not res.findings
    assert http.calls[0]["max_bytes"] == 1000


def test_deep_preset_uses_the_60s_call_timeout():
    http = FakeHttp().add("GET", url("cve", "CVE-2021-44228"), json=fx("cve_general_labs.json"))
    run_module(Otx, "cve:CVE-2021-44228", http, keys=KEYS, options=ScanOptions(preset="deep"))
    assert http.calls[0]["timeout"] == 60.0


def test_private_ips_are_never_sent():
    res = run_module(Otx, "ipv4:10.0.0.1", FakeHttp(), keys=KEYS)
    assert res.status is Status.SKIPPED and res.reason_code == "not_applicable"


def test_key_never_leaks_into_the_result():
    http = FakeHttp().add("GET", url("domain", "nic.br"), json=fx("domain_general_pulses.json"))
    http.add("GET", url("domain", "nic.br", "url_list", page=1), status=500, text=f"echo {KEY}")
    http.add("GET", url("domain", "nic.br", "malware"), json={"data": []})
    res = run_module(Otx, "domain:nic.br", http, keys=KEYS, is_seed=False)
    assert http.calls[0]["headers"].get("X-OTX-API-KEY") == KEY
    assert_no_secret(KEY, res.to_dict(), [f.to_dict() for f in res.findings], res.error)


def test_direct_run_records_evidence_without_indicator_lists():
    http = FakeHttp().add("GET", url("domain", "nic.br"), json=fx("domain_general_pulses.json"))
    http.add("GET", url("domain", "nic.br", "url_list", page=1), json={"url_list": [], "has_next": False})
    http.add("GET", url("domain", "nic.br", "malware"), json={"data": []})
    ctx = make_ctx(Otx, http, keys=KEYS, entity="domain:nic.br", is_seed=False)
    res = Otx().run(Entity.make("domain", "nic.br"), ctx)
    assert res.raw["general"]["pulse_count"] == 3 and len(res.raw["general"]["pulses"]) == 3


def test_pulse_indicator_pivots_keep_personal_identifiers_unexpanded():
    assert mod.pulse_indicator_pivot("email", "someone@example.com") == (T.EMAIL, "someone@example.com", False)
    assert mod.pulse_indicator_pivot("username", "someone") == (T.USERNAME, "someone", False)
    assert mod.pulse_indicator_pivot("IPv4", "203.0.113.7") == (T.IPV4, "203.0.113.7", True)
    assert mod.pulse_indicator_pivot("YARA", "rule x {}") is None


def test_clean_label_drops_junk():
    assert mod.clean_label("Malware Family: StealthWorker / GoBrut") == "StealthWorker / GoBrut"
    assert mod.clean_label("MD5 Hash: f8add7e7161460ea2b1970cf4ca535bf") is None
    assert mod.clean_label("Mitre Attack") is None
    assert mod.canonical_name("malware_family", "Cobalt Strike - S0154") == "Cobalt Strike"
    assert mod.canonical_name("malware_family", "cobaltstrike") == "Cobalt Strike"


@pytest.mark.parametrize("etype,value", [("url", "https://example.com/"), ("sha256", "275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f")])
def test_golden_path_routes_are_complete(etype, value):
    """tests/fixtures/acceptance/<type>/otx.json (real general answers, scrubbed) answer every request."""
    from tests.fakes import fixture

    doc = fixture(f"acceptance/{etype}/otx.json")
    assert doc["schema"] == "v3lum.acceptance_routes/1" and doc["module"] == "otx"
    http = FakeHttp()
    for route in doc["routes"]:
        http.add(route["method"], route["url"], status=route["status"], json=route["json"])
    res = run_module(Otx, f"{etype}:{value}", http, keys=KEYS)
    assert res.status is Status.OK and len(http.calls) == len(doc["routes"])
    assert sum(1 for f in res.findings if f.severity.label != "info") <= 1
