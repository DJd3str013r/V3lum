"""ip_offline_db (P047 c1-c5, c7-c9): IPtoASN and bgp.tools datasets read locally.

Fixtures in tests/fixtures/ip_offline_db/: slices of the IPtoASN ip2asn-v4/v6 TSV files of
2026-11-01 (ranges of public resolvers, NIC.br and Yahoo, plus 'Not routed' rows) and of
bgp.tools asns.csv (research sample, header 'asn,name,class,cc'). Downloads are simulated through
`v3lum data update` (DataStore.update over FakeHttp): the gzip goes through the core safe_extract.
"""

from __future__ import annotations

import gzip

import pytest

from tests.fakes import FakeHttp, make_runtime, run_module
from v3lum.core.datasets import DATASETS
from v3lum.core.models import Status
from v3lum.modules.ip_network import ip_offline_db
from v3lum.modules.ip_network.ip_offline_db import (
    BGPTOOLS_ASNS,
    IPTOASN_V4,
    IPTOASN_V6,
    IntervalIndex,
    IpOfflineDb,
    age_text,
    parse_bgptools,
    special_purpose,
)

FIX = "tests/fixtures/ip_offline_db"
V4_URL = "https://iptoasn.com/data/ip2asn-v4.tsv.gz"
V6_URL = "https://iptoasn.com/data/ip2asn-v6.tsv.gz"
BGP_URL = "https://bgp.tools/asns.csv"
ROLE = "cti-team@example.com"  # a team role mailbox (documentation domain), never an analyst's address


@pytest.fixture(autouse=True)
def minimised(monkeypatch):
    monkeypatch.setattr(ip_offline_db, "MIN_IPTOASN_ROWS", {4: 5, 6: 3})
    monkeypatch.setattr(ip_offline_db, "MIN_BGPTOOLS_ASNS", 3)
    for name in (IPTOASN_V4, IPTOASN_V6, BGPTOOLS_ASNS):
        monkeypatch.setitem(DATASETS[name], "min_bytes", 10)


def gz(name: str) -> bytes:
    with open(f"{FIX}/{name}", "rb") as fh:
        return gzip.compress(fh.read())


def installed(*, v4: bool = True, v6: bool = True, bgp: bool = True, contact: str = ROLE):
    """A runtime after `v3lum data update` installed the requested datasets."""
    http = FakeHttp()
    http.add("GET", V4_URL, body=gz("ip2asn_v4_slice.tsv"))
    http.add("GET", V6_URL, body=gz("ip2asn_v6_slice.tsv"))
    with open(f"{FIX}/bgptools_asns_ok.csv", "rb") as fh:
        http.add("GET", BGP_URL, body=fh.read(), headers={"content-type": "text/csv"})
    rt = make_runtime(http, settings={"contact_email": contact} if contact else None)
    for flag, name in ((v4, IPTOASN_V4), (v6, IPTOASN_V6), (bgp, BGPTOOLS_ASNS)):
        if flag:
            assert rt.data.update(name).ok, name
    sent = list(http.calls)
    http.calls.clear()
    return http, rt, sent


def test_metadata_and_registry_terms():
    cls = IpOfflineDb
    assert (cls.terms, cls.disclosure, cls.hosts, cls.sources) == ("open", "none", (), ("iptoasn.ip2asn", "bgptools.asns"))
    for name in (IPTOASN_V4, IPTOASN_V6):
        reg = DATASETS[name]
        assert (reg["large"], reg["archive"], reg["licence"], reg["ttl"]) == (True, "gz", "PDDL-1.0", 86400)
    assert DATASETS[BGPTOOLS_ASNS]["url"] == BGP_URL and DATASETS[BGPTOOLS_ASNS]["ttl"] == 86400


def test_ipv4_lookup_with_bgptools_class():
    http, rt, sent = installed()
    res = run_module(IpOfflineDb, "ipv4:66.196.65.10", runtime=rt)
    assert res.status is Status.OK
    attrs = res.attributes
    assert (attrs["asn"], attrs["as_org"], attrs["as_country"], attrs["prefix"]) == ("AS10310", "YAHOO-1 - Yahoo Holdings Inc.", "US", "66.196.64.0/21")
    assert attrs["announced"] is True and attrs["network_type"] == "hosting" and attrs["as_class"] == "Content"
    assert any(p.entity.value == "AS10310" and p.relation == "belongs_to_asn" for p in res.pivots)
    assert any(line.startswith("IPtoASN IPv4, fetched") for line in attrs["dataset_age"])
    assert not http.calls  # the lookup itself is local (disclosure 'none')
    bgp_call = next(c for c in sent if c["url"] == BGP_URL)  # bgp.tools gets the descriptive role-contact UA
    assert ROLE in next(v for k, v in bgp_call["headers"].items() if k.lower() == "user-agent")


def test_ipv4_range_spanning_several_networks_and_not_routed():
    _http, rt, _ = installed()
    res = run_module(IpOfflineDb, "ipv4:8.8.9.9", runtime=rt)
    assert res.attributes["asn"] == "AS3356" and "prefix" not in res.attributes and res.attributes["ip_range"] == "8.8.9.0-8.8.10.255"
    unrouted = run_module(IpOfflineDb, "ipv4:1.0.2.1", runtime=rt)
    assert unrouted.attributes["announced"] is False and "asn" not in unrouted.attributes
    assert unrouted.findings[0].title == "Address not announced in BGP (IPtoASN)"


def test_ipv6_lookup():
    _http, rt, _ = installed()
    res = run_module(IpOfflineDb, "ipv6:2001:4860:4860::8888", runtime=rt)
    assert res.attributes["asn"] == "AS15169" and res.attributes["as_org"] == "GOOGLE - Google LLC"


def test_asn_input_aggregates_ranges_and_class():
    _http, rt, _ = installed()
    res = run_module(IpOfflineDb, "asn:AS10310", runtime=rt)
    assert res.status is Status.OK
    assert (res.attributes["as_range_count"], res.attributes["as_ipv4_addresses"]) == (2, 768 + 2048)
    assert res.attributes["network_type"] == "hosting"
    eyeball = run_module(IpOfflineDb, "asn:AS10000", runtime=rt)  # only in bgp.tools
    assert eyeball.attributes["network_type"] == "eyeball" and eyeball.attributes["as_country"] == "JP"
    assert run_module(IpOfflineDb, "asn:AS64496", runtime=rt).status is Status.EMPTY


def test_missing_dataset_is_unavailable_never_empty_and_never_downloaded():
    http = FakeHttp()
    res = run_module(IpOfflineDb, "ipv4:8.8.8.8", http)
    assert res.status is Status.UNAVAILABLE and res.reason_code == "dataset"
    assert "run v3lum data update" in res.error and not http.calls


def test_bgptools_without_contact_setting_is_skipped_config():
    _http, rt, _ = installed(bgp=False, contact="")
    res = run_module(IpOfflineDb, "ipv4:8.8.8.8", runtime=rt)
    assert res.status is Status.OK and res.attributes["asn"] == "AS15169"
    assert res.source_statuses["bgptools.asns"]["reason_code"] == "config"
    failed = rt.data.update(BGPTOOLS_ASNS)  # data update refuses the generic UA too
    assert failed.status == "failed" and "contact_email" in failed.reason


def test_bgptools_missing_copy_is_unavailable_dataset_source():
    _http, rt, _ = installed(bgp=False)
    res = run_module(IpOfflineDb, "ipv4:8.8.8.8", runtime=rt)
    assert res.status is Status.OK and res.source_statuses["bgptools.asns"]["reason_code"] == "dataset"


def test_private_addresses_are_not_applicable():
    assert run_module(IpOfflineDb, "ipv4:192.168.1.1", FakeHttp()).status is Status.SKIPPED


@pytest.mark.parametrize(
    ("name", "url", "body", "why"),
    [
        (IPTOASN_V4, V4_URL, b"<html><body>Just a moment...</body></html>", ""),
        (IPTOASN_V4, V4_URL, gzip.compress(b"garbage\tline\n" * 50), "too few IPtoASN rows"),
        (BGPTOOLS_ASNS, BGP_URL, b"asn,name\nAS1,x\n", "header"),
    ],
)
def test_bad_downloads_never_replace_a_copy(name, url, body, why):
    http = FakeHttp().add("GET", url, body=body)
    rt = make_runtime(http, settings={"contact_email": ROLE})
    result = rt.data.update(name)
    assert result.status == "failed" and why in result.reason


def test_gzip_size_cap(monkeypatch):
    monkeypatch.setitem(DATASETS[IPTOASN_V6], "max_bytes", 500)  # the gzip body fits, the expanded file does not
    http = FakeHttp().add("GET", V6_URL, body=gz("ip2asn_v6_slice.tsv"))
    result = make_runtime(http).data.update(IPTOASN_V6)
    assert result.status == "failed" and "expands beyond" in result.reason


def test_interval_index_nested_and_disjoint():
    import ipaddress

    idx = IntervalIndex()
    idx.add_network(ipaddress.ip_network("198.51.100.0/24"), "outer")
    idx.add_network(ipaddress.ip_network("198.51.100.128/25"), "inner")
    idx.add_network(ipaddress.ip_network("2001:db8::/32"), "v6")
    idx.add(4, 10, 20, "small")
    idx.freeze()
    assert idx.lookup("198.51.100.200") == ["inner", "outer"]
    assert idx.lookup("198.51.100.5") == ["outer"] and idx.lookup("203.0.113.1") == []
    assert idx.lookup("2001:db8::1") == ["v6"] and len(idx) == 4
    assert idx.within(4, int(ipaddress.ip_address("198.51.100.0")), int(ipaddress.ip_address("198.51.100.255"))) == ["outer", "inner"]


def test_special_purpose_and_helpers():
    assert special_purpose("10.1.2.3") == "rfc1918" and special_purpose("224.0.0.0/3") == "special_supernet"
    assert special_purpose("8.8.8.8") is None and special_purpose("2001:db8::1") == "documentation"
    assert special_purpose("not-an-ip") == "invalid"
    assert age_text(90 * 60) == "1 h 30 min" and age_text(3 * 86400) == "3 days" and age_text(None) == "age unknown"
    with open(f"{FIX}/bgptools_asns_ok.csv", encoding="utf-8") as fh:
        table = parse_bgptools(fh.read())
    assert table[101]["network_type"] == "transit" and table[10000]["network_type"] == "eyeball"
