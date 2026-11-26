"""shodan_internetdb (reference keyless HTTP API module): parsing, metadata and status mapping.

Fixtures in tests/fixtures/shodan_internetdb/: real InternetDB answers for 1.1.1.1 and 8.8.8.8
(recorded 2026-11-25), InternetDB's documented 404 body, a 429 body, a trimmed Cloudflare block page
(research sample) and a synthetic risky-ports/CVE answer for the public scan target 45.33.32.156.
"""

from __future__ import annotations

from tests.fakes import FakeHttp, make_ctx, module_fixture, run_module
from v3lum.core.entities import Entity
from v3lum.core.entities import EntityType as T
from v3lum.core.models import Status
from v3lum.modules.ip_network.shodan_internetdb import ShodanInternetDB

URL = "https://internetdb.shodan.io/{ip}"


def pivots(res, etype=None):
    return {p.entity.value for p in res.pivots if etype is None or p.entity.type is etype}


def run(http, ip):
    return ShodanInternetDB().run(Entity.make("ipv4", ip), make_ctx(ShodanInternetDB, http))


# ------------------------------------------------------------------ metadata (A1 phase-0 fix)
def test_contract_v2_metadata():
    cls = ShodanInternetDB
    assert cls.terms == "noncommercial"
    assert (cls.disclosure, cls.provider, cls.sources, cls.hosts) == ("third_party", "shodan", ("shodan.internetdb",), ("internetdb.shodan.io",))
    assert cls.access_model == "free_noauth_limited"
    assert cls.absent_statuses == frozenset({404})
    assert (cls.max_requests, cls.expected_latency) == (1, 1.0)
    assert cls.manual_link == "core_reference:shodan_host"
    assert "licence-cleared" in cls.notice


# ------------------------------------------------------------------ parsing (moved cases)
def test_internetdb_real_sample():
    http = FakeHttp().add("GET", URL.format(ip="1.1.1.1"), json=module_fixture(ShodanInternetDB, "1.1.1.1.json"))
    res = run(http, "1.1.1.1")
    assert res.status is Status.OK
    assert res.attributes["open_ports"][:3] == [53, 80, 443]
    assert "one.one.one.one" in pivots(res, T.DOMAIN)
    assert any("open port" in f.title.lower() for f in res.findings)
    assert all(f.source == "shodan.internetdb" for f in res.findings)
    http.assert_hosts_within(ShodanInternetDB)


def test_internetdb_8888_sample():
    http = FakeHttp().add("GET", URL.format(ip="8.8.8.8"), json=module_fixture(ShodanInternetDB, "8.8.8.8.json"))
    res = run(http, "8.8.8.8")
    assert res.attributes["open_ports"] == [53, 443]
    assert {"dns.google", "test-site.omk.ru"} <= pivots(res, T.DOMAIN)
    assert not any(f.severity.label != "info" for f in res.findings)


def test_internetdb_vulns_and_risky_ports():
    data = module_fixture(ShodanInternetDB, "risky_and_vulns.json")
    http = FakeHttp().add("GET", URL.format(ip="45.33.32.156"), json=data)
    res = run(http, "45.33.32.156")
    assert pivots(res, T.CVE) == {"CVE-2023-0001", "CVE-2023-0002"}
    cve_pivots = [p for p in res.pivots if p.entity.type is T.CVE]
    assert all(p.relation == "has_vuln" for p in cve_pivots)
    assert all(abs(p.confidence - 0.4) < 1e-9 for p in cve_pivots)  # 'possible'
    tags = {t for f in res.findings for t in f.tags}
    assert {"exposure", "misconfiguration", "vulnerable", "version_inferred"} <= tags
    cve = [f for f in res.findings if f.title == "CVE(s) associated with exposed software (version-inferred)"]
    assert len(cve) == 1  # one finding per host, counts in data
    assert cve[0].severity.label == "medium"
    assert str(getattr(cve[0].confidence_label, "value", cve[0].confidence_label)) == "possible"
    assert cve[0].criterion == "version-inferred, distro backports not considered: confirm on the host"
    assert cve[0].data["count"] == 2
    assert all(f.criterion for f in res.findings if f.severity.label != "info")


def test_private_ip_not_applicable():
    assert not ShodanInternetDB().applies(Entity.make("ipv4", "10.0.0.1"), make_ctx(ShodanInternetDB))
    res = run_module(ShodanInternetDB, "ipv4:10.0.0.1", FakeHttp())
    assert res.status is Status.SKIPPED


# ------------------------------------------------------------------ status mapping (P328 cond 5/6, P321)
def test_404_is_a_documented_absence():
    http = FakeHttp().add("GET", URL.format(ip="45.33.32.156"), status=404, json=module_fixture(ShodanInternetDB, "not_found_404.json"))
    res = run_module(ShodanInternetDB, "ipv4:45.33.32.156", http)
    assert res.status is Status.EMPTY
    assert not res.findings and not res.pivots


def test_429_is_rate_limited_never_absent():
    http = FakeHttp().add("GET", URL.format(ip="45.33.32.156"), status=429, json=module_fixture(ShodanInternetDB, "rate_limited_429.json"))
    res = run_module(ShodanInternetDB, "ipv4:45.33.32.156", http)
    assert res.status is Status.RATE_LIMITED
    assert res.reason_code == "rate_limited"
    assert not res.findings


def test_challenge_page_is_blocked():
    page = module_fixture(ShodanInternetDB, "challenge_cloudflare_403.html")
    for status in (403, 200):  # a challenge served with 200 is still a block (P321)
        http = FakeHttp().add("GET", URL.format(ip="45.33.32.156"), status=status, text=page)
        res = run_module(ShodanInternetDB, "ipv4:45.33.32.156", http)
        assert res.status is Status.BLOCKED, status
        assert res.reason_code == "challenge", status
        assert not res.findings


def test_keyless_403_without_markers_is_blocked():
    http = FakeHttp().add("GET", URL.format(ip="45.33.32.156"), status=403, text="Forbidden")
    res = run_module(ShodanInternetDB, "ipv4:45.33.32.156", http)
    assert res.status is Status.BLOCKED and res.reason_code == "challenge"


def test_unexpected_answers_are_could_not_verify_never_empty():
    for body in ([], "ok", 42):  # JSON that is not an object
        http = FakeHttp().add("GET", URL.format(ip="45.33.32.156"), json=body)
        res = run_module(ShodanInternetDB, "ipv4:45.33.32.156", http)
        assert res.status is Status.ERROR and "could not verify" in res.error, body
        assert not res.findings and not res.pivots, body


def test_untrusted_fields_are_type_checked():
    data = {"ip": "45.33.32.156", "ports": None, "hostnames": [None, "ok.example.org", 7], "cpes": None,
            "tags": "c2", "vulns": ["CVE-2023-0001", "cve-2023-0002", "<script>alert(1)</script>", 3]}
    http = FakeHttp().add("GET", URL.format(ip="45.33.32.156"), json=data)
    res = run_module(ShodanInternetDB, "ipv4:45.33.32.156", http)
    assert res.status is Status.OK
    assert res.attributes["vulns"] == ["CVE-2023-0001", "CVE-2023-0002"]  # junk dropped, case normalised
    assert res.attributes["hostnames"] == ["ok.example.org"]
    assert "open_ports" not in res.attributes and "cpes" not in res.attributes
    assert not any(f.title == "Shodan classifies the host as malicious" for f in res.findings)  # 'tags' was not a list


def test_request_cap_is_one():
    http = FakeHttp().add("GET", URL.format(ip="1.1.1.1"), json=module_fixture(ShodanInternetDB, "1.1.1.1.json"))
    res = run_module(ShodanInternetDB, "ipv4:1.1.1.1", http)
    assert res.status is Status.OK and res.requests == 1
    assert http.urls() == [URL.format(ip="1.1.1.1")]
