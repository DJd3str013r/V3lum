"""shodan_internetdb (reference keyless HTTP API module, upgraded by P043): parsing, metadata, status
mapping, the licence skip under the corporate profile, the CVE collapse and the confidence cap.

Fixtures in tests/fixtures/shodan_internetdb/: real InternetDB answers for 1.1.1.1, 8.8.8.8, 9.9.9.9
and 2001:4860:4860::8888 (recorded 2026-11-26; co-tenant hostnames pseudonymised as
cotenantN.example.*), InternetDB's documented 404 body, a 429 body, a trimmed Cloudflare block page
(research sample), a synthetic risky-ports answer and a synthetic version-inferred CVE answer
(Apache 2.4.49 / OpenSSH 7.4 style) for the public scan target 45.33.32.156 - none of the benign
IPs has CVEs.
"""

from __future__ import annotations

import json

from tests.fakes import FakeHttp, make_ctx, make_runtime, module_fixture, run_module
from v3lum import paths
from v3lum.core import policy
from v3lum.core.context import RunInfo, ScanOptions
from v3lum.core.entities import Entity, EntityType
from v3lum.core.entities import EntityType as T
from v3lum.core.models import Severity, Status
from v3lum.modules.ip_network.shodan_internetdb import CVE_LABEL, LAST_SEEN, NOT_SEEN, ShodanInternetDB

URL = "https://internetdb.shodan.io/{ip}"


def pivots(res, etype=None):
    return {p.entity.value for p in res.pivots if etype is None or p.entity.type is etype}


def run(http, ip):
    return ShodanInternetDB().run(Entity.make("ipv4", ip), make_ctx(ShodanInternetDB, http))


# ------------------------------------------------------------------ metadata (A1 phase-0 fix, P043 c1)
def test_contract_v2_metadata():
    cls = ShodanInternetDB
    assert cls.terms == "noncommercial"
    assert (cls.disclosure, cls.provider, cls.sources, cls.hosts) == ("third_party", "shodan", ("shodan.internetdb",), ("internetdb.shodan.io",))
    assert cls.access_model == "free_noauth_limited"
    assert cls.absent_statuses == frozenset({404})
    assert (cls.max_requests, cls.expected_latency, cls.cache_ttl) == (1, 1.0, 86400)
    assert cls.manual_link == "core_reference:shodan_host"
    assert cls.default_enabled is True  # a default candidate: the licence gate skips it under corporate
    assert "licence-cleared" in cls.notice and "shodan_api" in cls.notice and "active port scan" in cls.notice


# ------------------------------------------------------------------ licence (P043 c2-c4)
def test_licence_skip_under_corporate_with_manual_link():
    from v3lum.core import module as module_mod

    module_mod.load_modules()
    rt = make_runtime()
    pctx = policy.make_context(rt, ScanOptions(), path="scan")
    assert pctx.licence_profile == "corporate"
    ip = Entity.make(EntityType.IPV4, "8.8.8.8")
    decision = policy.decide(ShodanInternetDB, ip, pctx, run=RunInfo(entity=ip, is_seed=True))
    assert (decision.allowed, decision.status, decision.reason_code) == (False, Status.SKIPPED, "licence")
    assert decision.emit_manual_link is True and "noncommercial" in decision.reason
    # an active licence_allow entry (Shodan's written permission) clears it; nothing replaces it otherwise
    allow = paths.home() / "licence_allow.json"
    allow.write_text(json.dumps({"entries": [{
        "source_id": "shodan.internetdb", "basis": "provider_grant", "scope": "own-network defence only, no resale",
        "legal_ref": "LEGAL-7", "approver": "legal (DPO office)", "decided_at": "2026-11-01", "review_by": "2027-05-01",
        "evidence_url": "https://www.shodan.io/", "quote": "written permission"}]}), encoding="utf-8")
    allow.chmod(0o600)
    cleared = policy.decide(ShodanInternetDB, ip, policy.make_context(rt, ScanOptions()), run=RunInfo(entity=ip, is_seed=True))
    assert cleared.allowed


# ------------------------------------------------------------------ parsing (P043 c6, c8)
def test_internetdb_real_sample_1111_shared_edge():
    http = FakeHttp().add("GET", URL.format(ip="1.1.1.1"), json=module_fixture(ShodanInternetDB, "1.1.1.1.json"))
    res = run(http, "1.1.1.1")
    assert res.status is Status.OK
    assert res.attributes["open_ports"][:3] == [53, 80, 443]
    assert res.attributes["internetdb_status"] == "seen"
    assert "one.one.one.one" in pivots(res, T.DOMAIN)
    # 1.1.1.1 is a public resolver / CDN edge: the other names are co-tenants, never expanded
    assert all(not p.expand for p in res.pivots if p.entity.type is T.DOMAIN)
    assert res.attributes["shared_ip"] is True
    ports = next(f for f in res.findings if f.title == "Open ports observed by Shodan")
    assert ports.description.count(LAST_SEEN) == len(res.attributes["open_ports"])  # every port line
    assert all(f.source == "shodan.internetdb" for f in res.findings)
    http.assert_hosts_within(ShodanInternetDB)


def test_internetdb_8888_and_9999_and_ipv6_samples():
    http = FakeHttp().add("GET", URL.format(ip="8.8.8.8"), json=module_fixture(ShodanInternetDB, "8.8.8.8.json"))
    res = run(http, "8.8.8.8")
    assert res.attributes["open_ports"] == [53, 443]
    assert {"dns.google", "cotenant1.example.com"} <= pivots(res, T.DOMAIN)
    assert not any(f.severity.label != "info" for f in res.findings)
    quad9 = run(FakeHttp().add("GET", URL.format(ip="9.9.9.9"), json=module_fixture(ShodanInternetDB, "9.9.9.9.json")), "9.9.9.9")
    assert quad9.attributes["open_ports"] == [53, 443, 853]
    v6 = "2001:4860:4860::8888"
    http6 = FakeHttp().add("GET", URL.format(ip=v6), json=module_fixture(ShodanInternetDB, "2001-4860-4860--8888.json"))
    res6 = run_module(ShodanInternetDB, f"ipv6:{v6}", http6)
    assert res6.status is Status.OK and res6.attributes["open_ports"] == [53, 443]


def test_tags_map_to_attributes():
    data = module_fixture(ShodanInternetDB, "vulns_synthetic.json")
    res = run(FakeHttp().add("GET", URL.format(ip="45.33.32.156"), json=data), "45.33.32.156")
    assert res.attributes["is_hosting"] is True and res.attributes["eol_software"] is True and res.attributes["tls_self_signed"] is True
    assert res.attributes["tags"] == ["cloud", "eol-product", "self-signed"]


def test_risky_ports_are_at_most_medium():
    data = module_fixture(ShodanInternetDB, "risky_and_vulns.json")
    res = run(FakeHttp().add("GET", URL.format(ip="45.33.32.156"), json=data), "45.33.32.156")
    risky = next(f for f in res.findings if f.title == "Sensitive services exposed to the internet")
    assert risky.severity is Severity.MEDIUM and LAST_SEEN in risky.criterion
    assert max(f.severity for f in res.findings if f.title != "Shodan classifies the host as malicious") <= Severity.MEDIUM


# ------------------------------------------------------------------ CVEs (P043 c7)
def test_cve_collapse_one_finding_and_confidence_cap():
    data = module_fixture(ShodanInternetDB, "vulns_synthetic.json")
    res = run(FakeHttp().add("GET", URL.format(ip="45.33.32.156"), json=data), "45.33.32.156")
    cves = [f for f in res.findings if "CVE" in f.title]
    assert len(cves) == 1  # one finding per host
    (finding,) = cves
    assert finding.severity is Severity.MEDIUM  # MEDIUM without KEV, never CRITICAL from InternetDB alone
    assert str(getattr(finding.confidence_label, "value", finding.confidence_label)) == "possible"
    assert finding.description.startswith("7 CVEs by version match, KEV: ")
    assert CVE_LABEL in finding.criterion and CVE_LABEL in finding.description and LAST_SEEN in finding.description
    assert {"vulnerable", "version_inferred"} <= set(finding.tags)
    cve_pivots = [p for p in res.pivots if p.entity.type is T.CVE]
    assert len(cve_pivots) == 7 and all(p.relation == "has_vuln" for p in cve_pivots)
    assert all(p.confidence <= 0.5 for p in cve_pivots)  # lowered from 0.6 (P291)


def test_cve_kev_cap_is_high_never_critical(monkeypatch):
    from v3lum.modules.ip_network import shodan_internetdb as mod

    monkeypatch.setattr(mod, "kev_ids", lambda ctx: frozenset({"CVE-2021-41773", "CVE-2021-42013"}))
    data = module_fixture(ShodanInternetDB, "vulns_synthetic.json")
    res = run(FakeHttp().add("GET", URL.format(ip="45.33.32.156"), json=data), "45.33.32.156")
    (finding,) = [f for f in res.findings if "CVE" in f.title]
    assert finding.severity is Severity.HIGH and "KEV: 2" in finding.description and "kev" in finding.tags


def test_private_ip_not_applicable():
    assert not ShodanInternetDB().applies(Entity.make("ipv4", "10.0.0.1"), make_ctx(ShodanInternetDB))
    res = run_module(ShodanInternetDB, "ipv4:10.0.0.1", FakeHttp())
    assert res.status is Status.SKIPPED


# ------------------------------------------------------------------ status mapping (P043 c5, P328, P321)
def test_404_is_not_seen_by_shodan_never_no_open_ports():
    http = FakeHttp().add("GET", URL.format(ip="45.33.32.156"), status=404, json=module_fixture(ShodanInternetDB, "not_found_404.json"))
    res = run_module(ShodanInternetDB, "ipv4:45.33.32.156", http)
    assert res.status is Status.EMPTY  # a documented, meaningful absence
    assert res.attributes["internetdb_status"] == NOT_SEEN
    (finding,) = res.findings
    assert finding.severity is Severity.INFO and finding.title == "Not seen by Shodan scanners"
    assert "open_ports" not in res.attributes and "no open ports" not in finding.description.lower()
    assert not res.pivots


def test_other_404_bodies_are_could_not_verify():
    for body in ({"detail": "Not Found"}, ["x"]):
        http = FakeHttp().add("GET", URL.format(ip="45.33.32.156"), status=404, json=body)
        res = run_module(ShodanInternetDB, "ipv4:45.33.32.156", http)
        assert res.status is Status.ERROR and not res.findings, body


def test_429_is_rate_limited_never_absent():
    http = FakeHttp().add("GET", URL.format(ip="45.33.32.156"), status=429, json=module_fixture(ShodanInternetDB, "rate_limited_429.json"))
    res = run_module(ShodanInternetDB, "ipv4:45.33.32.156", http)
    assert res.status is Status.RATE_LIMITED
    assert res.reason_code == "rate_limited"
    assert not res.findings


def test_challenge_page_is_blocked():
    page = module_fixture(ShodanInternetDB, "challenge_cloudflare_403.html")
    for status in (403, 200, 404):  # a challenge page is a block whatever the status (P321)
        http = FakeHttp().add("GET", URL.format(ip="45.33.32.156"), status=status, text=page)
        res = run_module(ShodanInternetDB, "ipv4:45.33.32.156", http)
        assert res.status is Status.BLOCKED, status
        assert res.reason_code == "challenge", status
        assert not res.findings


def test_keyless_403_without_markers_is_blocked():
    http = FakeHttp().add("GET", URL.format(ip="45.33.32.156"), status=403, text="Forbidden")
    res = run_module(ShodanInternetDB, "ipv4:45.33.32.156", http)
    assert res.status is Status.BLOCKED and res.reason_code == "challenge"


def test_5xx_and_timeouts_are_errors():
    from v3lum.core.http import NetworkError

    http = FakeHttp().add("GET", URL.format(ip="45.33.32.156"), status=503, text="unavailable")
    assert run_module(ShodanInternetDB, "ipv4:45.33.32.156", http).status is Status.ERROR
    http2 = FakeHttp().add("GET", URL.format(ip="45.33.32.157"), error=NetworkError("ReadTimeout contacting internetdb.shodan.io: timed out"))
    assert run_module(ShodanInternetDB, "ipv4:45.33.32.157", http2).status is Status.ERROR


def test_unexpected_answers_are_could_not_verify_never_empty():
    for body in ([], "ok", 42, {"detail": "Internal error"}):  # JSON that is not a usable object
        http = FakeHttp().add("GET", URL.format(ip="45.33.32.156"), json=body)
        res = run_module(ShodanInternetDB, "ipv4:45.33.32.156", http)
        assert res.status is Status.ERROR and "could not verify" in res.error, body
        assert not res.findings and not res.pivots, body
    malformed = FakeHttp().add("GET", URL.format(ip="45.33.32.156"), body=b"{not json", headers={"content-type": "application/json"})
    assert run_module(ShodanInternetDB, "ipv4:45.33.32.156", malformed).status is Status.ERROR


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


def test_acceptance_routes_cover_the_golden_ipv4():
    with open("tests/fixtures/acceptance/ipv4/shodan_internetdb.json", encoding="utf-8") as fh:
        doc = json.load(fh)
    assert doc["schema"] == "v3lum.acceptance_routes/1" and doc["module"] == "shodan_internetdb"
    http = FakeHttp()
    for route in doc["routes"]:
        http.add(route["method"], route["url"], status=route["status"], json=route["json"])
    res = run_module(ShodanInternetDB, "ipv4:8.8.8.8", http)
    assert res.status is Status.OK and len(http.calls) == len(doc["routes"])
    assert sum(1 for f in res.findings if f.severity.label != "info") == 0
