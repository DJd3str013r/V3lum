"""subdomains_keyed_minor (P007 cond 1): BufferOver and jsmon, unknown tier and opt-in, offline.

Fixtures in tests/fixtures/subdomains_keyed_minor/ (batch p3-G01-1 prep): ``jsmon_ok_documented.json`` is the
response shape published on the jsmon landing page (read 2026-11-26) with example.com names; the BufferOver
answers and every error envelope are synthetic documented shapes (AWS API Gateway bodies for BufferOver's
RapidAPI-backed key service) with documentation values. Real success captures with the team keys are still
owed (P007 cond 7, docs/backlog/p3-G01-1.md).
"""

from __future__ import annotations

import pytest

from tests.fakes import FakeHttp, add_dns, add_nxdomain_everything, assert_no_secret, module_fixture, run_module
from v3lum.core.models import Status
from v3lum.modules.domain_dns import subdomains_keyed as K
from v3lum.modules.domain_dns.subdomains_keyed import SubdomainsKeyedMinor

APEX = "example.com"
BO = K.BUFFEROVER_URL + "?q=.example.com"
JS = K.JSMON_URL.format(apex=APEX)
KEYS = {"bufferover": "bo-test-key-0123456789abcdef", "jsmon": "js-test-key-0123456789abcdef"}
HDR = {"bufferover": {"x-api-key": KEYS["bufferover"]}, "jsmon": {"Api-Key": KEYS["jsmon"]}}


def fx(name):
    return module_fixture("subdomains_keyed_minor", name)


def envelope(name):
    resp = fx(name)["response"]
    body = resp["body"]
    kw = {"status": resp["status"], "headers": resp.get("headers") or {}}
    kw["json" if isinstance(body, (dict, list)) else "text"] = body
    return kw


def test_contract_metadata():
    cls = SubdomainsKeyedMinor
    assert cls.default_enabled is False and cls.trust_tier == "unknown" and cls.terms == "key-terms"
    assert cls.max_tlp.label == "TLP:GREEN"  # unknown tier: excluded at AMBER and above
    assert cls.optional_keys == ("bufferover", "jsmon") and cls.max_requests == 2
    assert set(cls.hosts) == {"tls.bufferover.run", "subdomains.jsmon.sh"}


def test_without_keys_needs_key_and_no_request():
    http = FakeHttp()
    res = run_module(SubdomainsKeyedMinor, "domain:example.com", http)
    assert res.status is Status.NEEDS_KEY and http.calls == []
    assert {v["status"] for v in res.source_statuses.values()} == {"needs_key"}


def test_bufferover_records_split_ip_from_hostname_and_stay_unconfirmed_unless_resolving():
    http = FakeHttp().add("GET", BO, json=fx("bufferover_ok_synthetic.json"), match_headers=HDR["bufferover"])
    add_dns(http, "www.example.com", "A", ["203.0.113.90"])
    add_nxdomain_everything(http)
    res = run_module(SubdomainsKeyedMinor, "domain:example.com", http, keys={"bufferover": KEYS["bufferover"]})
    assert res.status is Status.OK
    prov = res.attributes["subdomain_provenance"]
    assert {"www.example.com", "api.example.com", "dev.example.com", "v6.example.com"} <= set(prov)
    assert not any(n.endswith("example.org") for n in prov)  # out-of-apex record
    assert res.attributes["subdomain_wildcards"] == ["*.example.com"]
    # unknown-tier single source: only the resolving name is confirmed (P016 cond 7 reused)
    assert prov["www.example.com"]["confirmed"] is True and "www.example.com" in res.attributes["subdomains"]
    assert "api.example.com" in res.attributes["subdomains_unconfirmed"]
    assert {p.entity.value for p in res.pivots} == {"www.example.com"}
    facts = res.raw["provider_facts"][K.SRC_BUFFEROVER]["host_ips"]
    assert facts["api.example.com"] == [{"ip": "198.51.100.7"}] and facts["v6.example.com"] == [{"ip": "2001:db8::10"}]
    assert res.raw["sources"][K.SRC_BUFFEROVER]["meta"]["records_skipped"] == 1  # 'garbage-without-ip'
    assert all("x-api-key" not in c["url"] and KEYS["bufferover"] not in c["url"] for c in http.calls)
    assert_no_secret(KEYS["bufferover"], res.to_dict())
    http.assert_hosts_within(SubdomainsKeyedMinor)


def test_bufferover_legacy_fdns_shape():
    http = FakeHttp().add("GET", BO, json=fx("bufferover_fdns_ok_synthetic.json"))
    add_nxdomain_everything(http)
    res = run_module(SubdomainsKeyedMinor, "domain:example.com", http, keys={"bufferover": KEYS["bufferover"]})
    assert res.status is Status.OK
    assert {"old.example.com", "host21.example.com"} <= set(res.attributes["subdomain_provenance"])


def test_jsmon_documented_shape_and_truncation():
    http = FakeHttp().add("GET", JS, json=fx("jsmon_truncated_synthetic.json"), match_headers=HDR["jsmon"])
    add_dns(http, "vpn.example.com", "A", ["203.0.113.91"])
    add_nxdomain_everything(http)
    res = run_module(SubdomainsKeyedMinor, "domain:example.com", http, keys={"jsmon": KEYS["jsmon"]})
    assert res.status is Status.OK and res.partial
    assert "provider_plan" in res.source_statuses[K.SRC_JSMON]["reason"]  # total 4521 > 3 names (Free: 100 results)
    assert {p.entity.value for p in res.pivots} == {"vpn.example.com"}


def test_both_sources_agreeing_confirm_a_name():
    http = FakeHttp()
    http.add("GET", BO, json=fx("bufferover_ok_synthetic.json"))
    http.add("GET", JS, json=fx("jsmon_ok_documented.json"))
    add_nxdomain_everything(http)
    res = run_module(SubdomainsKeyedMinor, "domain:example.com", http, keys=KEYS)
    prov = res.attributes["subdomain_provenance"]
    assert set(prov["api.example.com"]["sources"]) == {K.SRC_BUFFEROVER, K.SRC_JSMON}
    assert prov["api.example.com"]["confirmed"] is True  # a second source agrees
    assert prov["mail.example.com"]["confirmed"] is False  # jsmon only, does not resolve


@pytest.mark.parametrize("url,adapter,name,status", [
    (BO, "bufferover", "bufferover_forbidden_403_synthetic.http.json", "needs_key"),
    (BO, "bufferover", "bufferover_quota_429_synthetic.http.json", "quota"),
    (BO, "bufferover", "bufferover_throttled_429_synthetic.http.json", "rate_limited"),
    (JS, "jsmon", "jsmon_unauthorized_synthetic.http.json", "needs_key"),
    (JS, "jsmon", "jsmon_daily_limit_synthetic.http.json", "quota"),
])
def test_refusals(url, adapter, name, status):
    http = FakeHttp().add("GET", url, **envelope(name))
    res = run_module(SubdomainsKeyedMinor, "domain:example.com", http, keys={adapter: KEYS[adapter]})
    assert res.status.value == status
    assert "subdomains" not in res.attributes


def test_meta_errors_inside_200_is_error():
    http = FakeHttp().add("GET", BO, json=fx("bufferover_meta_error_synthetic.json"))
    res = run_module(SubdomainsKeyedMinor, "domain:example.com", http, keys={"bufferover": KEYS["bufferover"]})
    assert res.status is Status.ERROR and "Meta.Errors" in res.error


def test_split_bufferover_record():
    assert K.split_bufferover_record("192.0.2.10,,www.example.com") == (["192.0.2.10"], ["www.example.com"])
    ips, hosts = K.split_bufferover_record("198.51.100.7,135af848cbec0fbaaad0afbda661041a34057924fce21a89a3270f95c5e707d7,a.example.com,b.example.com")
    assert ips == ["198.51.100.7"] and hosts == ["a.example.com", "b.example.com"]
    assert K.split_bufferover_record("192.0.2.12,Example Org Ltd,EXAMPLE.COM") == (["192.0.2.12"], ["EXAMPLE.COM"])
    assert K.split_bufferover_record(None) == ([], [])
