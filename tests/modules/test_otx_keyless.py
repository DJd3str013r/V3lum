"""otx_keyless (P153 cond 1): the 'general' section without a key, opt-in only.

Fixtures in tests/fixtures/otx_keyless/: ``ipv4_general_nokey.json`` (8.8.8.8 answered without a key,
live 2026-11-26), ``domain_general_nokey.json`` (nic.br without a key, live, community authors and
pulse names scrubbed) and ``rate_limited_429.json`` (the live keyless 429 body 'Anonymous access to
this endpoint is limited').
"""

from __future__ import annotations

from tests.fakes import FakeHttp, module_fixture, run_module
from v3lum.core.entities import EntityType as T
from v3lum.core.models import Status
from v3lum.modules.threat_intel_ioc.otx import Otx, OtxKeyless

BASE = "https://otx.alienvault.com/api/v1/indicators"


def fx(name):
    return module_fixture(OtxKeyless, name)


def test_metadata_is_opt_in_and_keyless():
    cls = OtxKeyless
    assert cls.default_enabled is False  # A3 latency rule: ~25 s per keyless call, 429 on shared egress
    assert cls.requires_keys == () and cls.optional_keys == ()
    assert cls.expected_latency > 10 and "slow" in cls.tags
    assert (cls.terms, cls.provider, cls.sources, cls.hosts) == (Otx.terms, Otx.provider, Otx.sources, Otx.hosts)
    assert cls.max_requests == 1 and cls.cache_ttl == 86400


def test_general_only_and_no_key_header_even_when_a_key_is_configured():
    http = FakeHttp().add("GET", f"{BASE}/domain/nic.br/general", json=fx("domain_general_nokey.json"))
    res = run_module(OtxKeyless, "domain:nic.br", http, keys={"otx": "otx-test-key-0123456789abcdef"}, is_seed=True)
    assert res.status is Status.OK
    assert http.urls() == [f"{BASE}/domain/nic.br/general"]  # no passive_dns, url_list or malware
    assert not any(k.lower() == "x-otx-api-key" for k in http.calls[0]["headers"])
    assert any(f.title == "Mentioned in OTX community pulses" for f in res.findings)
    assert {"Mirai", "Artro"} <= {p.entity.value for p in res.pivots if p.entity.type is T.MALWARE}
    http.assert_hosts_within(OtxKeyless)


def test_whitelisted_ip_is_info():
    http = FakeHttp().add("GET", f"{BASE}/IPv4/8.8.8.8/general", json=fx("ipv4_general_nokey.json"))
    res = run_module(OtxKeyless, "ipv4:8.8.8.8", http)
    assert res.status is Status.OK and [f.severity.label for f in res.findings] == ["info"]
    assert not res.pivots


def test_429_is_rate_limited():
    http = FakeHttp().add("GET", f"{BASE}/IPv4/45.33.32.156/general", status=429, json=fx("rate_limited_429.json"))
    res = run_module(OtxKeyless, "ipv4:45.33.32.156", http)
    assert res.status is Status.RATE_LIMITED and res.reason_code == "rate_limited"


def test_keyless_403_is_could_not_verify():
    http = FakeHttp().add("GET", f"{BASE}/IPv4/45.33.32.156/general", status=403, json={"detail": "Authentication required"})
    res = run_module(OtxKeyless, "ipv4:45.33.32.156", http)
    assert res.status is Status.BLOCKED  # a keyless refusal is 'could not verify', never needs_key or absent


def test_empty_answer_is_empty():
    data = dict(fx("ipv4_general_nokey.json"), validation=[], false_positive=[])
    http = FakeHttp().add("GET", f"{BASE}/IPv4/45.33.32.156/general", json=data)
    res = run_module(OtxKeyless, "ipv4:45.33.32.156", http)
    assert res.status is Status.EMPTY
