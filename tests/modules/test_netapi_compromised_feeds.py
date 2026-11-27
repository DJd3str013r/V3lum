"""Offline tests of netapi_compromised_feeds (P150 FC2, local first) with the recorded feed slices in
tests/fixtures/netapi_compromised_feeds/ (victim IPs and domains scrubbed to documentation values)."""

from __future__ import annotations

import pytest

from tests.fakes import FakeHttp, make_runtime, run_module
from v3lum.core.datasets import DATASETS
from v3lum.core.models import Severity, Status
from v3lum.modules.threat_intel_ioc import netapi_compromised_feeds as mod
from v3lum.modules.threat_intel_ioc.netapi_compromised_feeds import (
    DOMAIN_FEED,
    DOMAIN_FEED_URL,
    IP_FEED,
    IP_FEED_URL,
    NetapiCompromisedFeeds,
    parse_domain_rows,
    parse_ip_feed,
)

FIX = "tests/fixtures/netapi_compromised_feeds"


def read(name: str) -> bytes:
    with open(f"{FIX}/{name}", "rb") as fh:
        return fh.read()


@pytest.fixture(autouse=True)
def minimised(monkeypatch):
    """The recorded slices are tiny: lower the validators' row minimums for the tests."""
    monkeypatch.setattr(mod, "MIN_IP_ROWS", 5)
    monkeypatch.setattr(mod, "MIN_DOMAIN_ROWS", 5)
    for name in (IP_FEED, DOMAIN_FEED):
        monkeypatch.setitem(DATASETS[name], "min_bytes", 10)


def installed(*, ip: bool = True, domains: bool = True):
    """A runtime after `v3lum data update` installed the requested feeds; the scan then sends nothing."""
    http = FakeHttp()
    http.add("GET", IP_FEED_URL, body=read("compromised_ip_slice.txt"), headers={"content-type": "text/plain"})
    http.add("GET", DOMAIN_FEED_URL, body=read("compromised_domains_slice.csv"), headers={"content-type": "text/csv"})
    rt = make_runtime(http)
    for flag_, name in ((ip, IP_FEED), (domains, DOMAIN_FEED)):
        if flag_:
            assert rt.data.update(name).ok, name
    http.calls.clear()
    return http, rt


def test_metadata_and_datasets():
    cls = NetapiCompromisedFeeds
    assert (cls.disclosure, cls.terms, cls.default_enabled, cls.hosts) == ("none", "unknown", False, ())
    assert cls.sources == ("netapi.compromised_ip", "netapi.compromised_domains")
    ip_reg, dom_reg = DATASETS[IP_FEED], DATASETS[DOMAIN_FEED]
    assert (ip_reg["terms_class"], ip_reg["source"], bool(ip_reg["large"]), ip_reg["max_bytes"]) == ("unknown", "netapi.compromised_ip", False, 5_000_000)
    assert (dom_reg["terms_class"], dom_reg["source"], dom_reg["large"]) == ("unknown", "netapi.compromised_domains", True)


def test_listed_ip_is_one_low_suspicious_vote_matched_locally():
    http, rt = installed()
    res = run_module(NetapiCompromisedFeeds, "ipv4:203.0.113.10", http, runtime=rt)
    assert res.status is Status.OK
    (finding,) = res.findings
    assert finding.severity is Severity.LOW and finding.tags == ["suspicious"] and "malicious" not in finding.tags
    assert res.attributes["netapi_compromised"]["via"] == "local feed"
    assert http.calls == []  # local only: the value never leaves the machine
    assert res.datasets and res.datasets[0]["name"] == IP_FEED


def test_unlisted_ip_is_empty():
    http, rt = installed()
    assert run_module(NetapiCompromisedFeeds, "ipv4:8.8.8.8", http, runtime=rt).status is Status.EMPTY


def test_domain_rows_exact_match_and_sinkholes_are_context():
    http, rt = installed()
    res = run_module(NetapiCompromisedFeeds, "domain:phish-1.example", http, runtime=rt)
    (finding,) = res.findings
    assert finding.severity is Severity.LOW and res.attributes["netapi_compromised"]["threat_type"] == "cert-polska"
    sink = run_module(NetapiCompromisedFeeds, "domain:sinkholed-1.example", http, runtime=rt)
    (finding,) = sink.findings
    assert finding.severity is Severity.INFO and {"sinkholed", "context_only"} <= set(finding.tags)
    for value in ("sub.phish-1.example", "pages.example"):
        assert run_module(NetapiCompromisedFeeds, f"domain:{value}", http, runtime=rt).status is Status.EMPTY, value
    url = run_module(NetapiCompromisedFeeds, "url:https://brand-login.pages.example/login?id=1", http, runtime=rt)
    assert url.status is Status.OK and url.findings[0].severity is Severity.LOW
    assert http.calls == []


def test_large_domain_feed_is_never_downloaded_mid_scan():
    http, rt = installed(domains=False)
    res = run_module(NetapiCompromisedFeeds, "domain:phish-1.example", http, runtime=rt)
    assert res.status is Status.UNAVAILABLE and res.reason_code == "dataset"
    assert http.calls == []


def test_challenge_or_empty_feed_never_replaces_a_copy():
    http = FakeHttp()
    http.add("GET", IP_FEED_URL, text="<html><head><title>Just a moment...</title></head><body>cf-chl</body></html>")
    rt = make_runtime(http)
    assert not rt.data.update(IP_FEED).ok
    ips, invalid = parse_ip_feed(read("compromised_ip_slice.txt").decode())
    assert len(ips) == 12 and invalid == 0
    rows, invalid = parse_domain_rows(read("compromised_domains_slice.csv").decode())
    assert len(rows) == 8 and invalid == 0 and sum(r["sinkholed"] for r in rows) == 6
    assert parse_domain_rows("domain,threat_type\nbad row\n")[0] == []
