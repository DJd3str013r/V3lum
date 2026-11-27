"""Offline tests of hybrid_analysis (P174) with the fixtures in tests/fixtures/hybrid_analysis/.

Provenance: ``needs_key_403.json`` is the real keyless answer (research 2026-11-25); the other bodies
are documented Hybrid Analysis v2 report-summary shapes with documentation hosts and a synthetic sample
hash (``search_hash_eicar_synthetic.json`` keeps the EICAR test file), until the team key exists
(P174 c5, backlog). ``submit_name``/``submissions`` carry a marker that must never reach a result."""

from __future__ import annotations

import json

import pytest

from tests.fakes import FakeHttp, assert_no_secret, make_runtime, module_fixture, run_module
from v3lum.core.context import RunInfo, ScanOptions
from v3lum.core.entities import Entity
from v3lum.core.entities import EntityType as T
from v3lum.core.models import Severity, Status
from v3lum.core.providers import registry
from v3lum.modules.malware_hash.hybrid_analysis import (
    HOSTILE_NOTE,
    SEARCH_URL,
    HybridAnalysis,
    request_allowed,
    sandbox_benign,
    summary_url,
)

FIX = "hybrid_analysis"
KEY_VALUE = "ha-test-key-0123456789abcdef0123456789abcdef0123456789abcdef"
KEYS = {"hybridanalysis": KEY_VALUE}
SHA256 = "3e9134075b2bf1d15b039867b9a33e0ea1210aab211449c6f0a79cbf7fa8e98e"
EICAR_SHA256 = "275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f"
BASE = "https://hybrid-analysis.com/api/v2"


def body(name: str) -> bytes:
    return json.dumps(module_fixture(FIX, name)).encode()


def search(name: str | None = None, *, status: int = 200, raw: bytes | None = None, http: FakeHttp | None = None) -> FakeHttp:
    http = http or FakeHttp()
    return http.add("POST", SEARCH_URL, status=status, body=raw if raw is not None else body(name or ""),
                    headers={"content-type": "application/json"}, match_headers={"api-key": KEY_VALUE})


def run(value: str, http: FakeHttp, **kw):
    etype = {32: "md5", 40: "sha1", 64: "sha256"}[len(value)]
    return run_module(HybridAnalysis, f"{etype}:{value}", http, keys=KEYS, **kw)


def assert_never_submits(http: FakeHttp) -> None:
    """c2: every request is the search POST or a report-summary GET."""
    for call in http.calls:
        assert request_allowed(call["method"], call["url"]), (call["method"], call["url"])
        assert "/submit" not in call["url"] and "/quick-scan" not in call["url"]


# --------------------------------------------------------------------------------------
# metadata and read-only construction (c1-c3)
# --------------------------------------------------------------------------------------


def test_metadata_matches_the_council_decision():
    cls = HybridAnalysis
    assert (cls.terms, cls.default_enabled, cls.trust_tier, cls.disclosure, cls.category) == ("key-terms", True, "trusted", "third_party", "malware_hash")
    assert cls.requires_keys == ("hybridanalysis",) and cls.hosts == ("hybrid-analysis.com",) and cls.sources == ("hybrid_analysis.search",)
    assert cls.manual_link == "threat_intel_g07_p2:hybrid_analysis_search" and cls.max_requests == 2
    assert registry().source("hybrid_analysis.search").terms.free_plan_business_use is None
    env = registry().keys()["hybridanalysis"].env
    assert "V3LUM_HYBRIDANALYSIS_KEY" in env and "V3LUM_HYBRID_KEY" in env
    assert registry().get("hybrid_analysis").http_profile.user_agent == "neutral"  # a non-empty V3LUM UA


@pytest.mark.parametrize("method,url", [
    ("POST", f"{BASE}/submit/file"),
    ("POST", f"{BASE}/submit/url-for-analysis"),
    ("POST", f"{BASE}/submit/hash-for-url"),
    ("POST", f"{BASE}/quick-scan/file"),
    ("POST", f"{BASE}/quick-scan/url"),
    ("GET", f"{BASE}/report/6553f1e2a1b2c3d4e5f60718/file/pcap"),
    ("GET", f"{BASE}/report/6553f1e2a1b2c3d4e5f60718/dropped-files"),
    ("GET", f"{BASE}/overview/{SHA256}/sample"),
    ("GET", f"{BASE}/overview/{SHA256}/refresh"),
    ("GET", f"{BASE}/feed/latest"),
    ("POST", f"{BASE}/search/terms"),
    ("GET", f"{BASE}/search/hash"),
    ("POST", f"{BASE}/search/hash?hash={SHA256}"),
    ("GET", f"{BASE}/report/not-an-id/summary"),
    ("POST", "http://hybrid-analysis.com/api/v2/search/hash"),
    ("POST", "https://evil.example/api/v2/search/hash"),
])
def test_allow_list_never_builds_a_submission(method, url):
    assert not request_allowed(method, url)


def test_allow_list_accepts_the_search_and_summaries():
    assert request_allowed("POST", SEARCH_URL)
    assert request_allowed("GET", summary_url("6553f1e2a1b2c3d4e5f60718"))
    assert request_allowed("GET", summary_url(f"{SHA256}:160"))
    assert summary_url("../../submit") is None


# --------------------------------------------------------------------------------------
# mapping (c4, c5)
# --------------------------------------------------------------------------------------


def test_malicious_sandbox_verdict_with_family_techniques_and_filtered_hosts():
    http = search("search_hash_ok_synthetic.json")
    res = run(SHA256, http)
    assert res.status is Status.OK
    [f] = res.findings
    assert f.title == "Malicious in a sandbox (Hybrid Analysis)" and f.severity is Severity.MEDIUM
    assert f.tags == ["malicious", "malware"] and f.criterion and f.source == "hybrid_analysis.search"
    assert f.data["threat_score"] == 100 and f.data["families"] == ["Agent.Synthetic"]
    summary = res.attributes["hybrid_analysis"]
    assert summary["verdict"] == "malicious" and summary["threat_score"] == 100 and summary["environments"]
    assert res.attributes["malware_family"] == ["Agent.Synthetic"]
    pivots = {(p.relation, p.entity.value): p for p in res.pivots}
    assert ("family", "Agent.Synthetic") in pivots and not pivots[("family", "Agent.Synthetic")].expand
    assert ("uses_technique", "T1071") in pivots and ("uses_technique", "T1027") in pivots
    c2 = pivots[("communicates_with", "c2.example.net")]
    assert c2.confidence <= 0.5 and not c2.expand and HOSTILE_NOTE in c2.note
    marked = pivots[("communicates_with", "198.51.100.7")]
    assert marked.expand and marked.confidence == pytest.approx(0.7)
    assert ("communicates_with", "ocsp.example.com") not in pivots  # OCSP/CRL infrastructure filtered (c5)
    assert any(x["value"] == "ocsp.example.com" for x in summary["contacted_filtered"])
    assert_no_secret("invoice-scan", res.to_dict())  # submitted file names are never copied
    call = http.calls[0]
    assert call["headers"]["api-key"] == KEY_VALUE and KEY_VALUE not in call["url"]
    assert f"hash={SHA256}" in (call["body"].decode() if isinstance(call["body"], bytes) else str(call["body"]))
    assert_never_submits(http)
    assert_no_secret(KEY_VALUE, res.to_dict())
    http.assert_hosts_within(HybridAnalysis)


def test_a_lean_search_item_reads_one_report_summary():
    http = search("search_hash_lean_synthetic.json")
    http.add("GET", summary_url("6553f1e2a1b2c3d4e5f60718"), body=body("report_summary_synthetic.json"),
             headers={"content-type": "application/json"}, match_headers={"api-key": KEY_VALUE})
    res = run(SHA256, http)
    assert len(http.calls) == 2 and res.status is Status.OK
    assert {p.entity.value for p in res.pivots if p.relation == "communicates_with"} >= {"c2.example.net", "198.51.100.7"}
    assert_never_submits(http)


def test_no_specific_threat_is_facts_without_a_finding():
    sha1 = "74b6df2f7fb71a4e0a64fc374d40df7286ba58cd"
    doc = module_fixture(FIX, "no_specific_threat_synthetic.json")
    doc[0].update(md5="94bc27a41c42bdb00c3de68b6d3365d6", sha1=sha1, sha256=SHA256)
    res = run(sha1, search(raw=json.dumps(doc).encode()))
    assert res.status is Status.OK and not res.findings and not res.pivots
    assert res.attributes["hybrid_analysis"]["verdict"] == "no specific threat"


def test_eicar_is_an_expected_detection():
    res = run(EICAR_SHA256, search("search_hash_eicar_synthetic.json"))
    [f] = res.findings
    assert f.title == "EICAR test file (Hybrid Analysis)" and f.severity is Severity.INFO and f.tags == ["test_file"]
    assert not res.pivots


def test_sandbox_benign_infrastructure_is_filtered():
    assert sandbox_benign(T.DOMAIN, "ctldl.windowsupdate.com")
    assert sandbox_benign(T.DOMAIN, "ocsp.digicert.com")
    assert sandbox_benign(T.IPV4, "10.0.2.15") == "sandbox-internal address"
    assert sandbox_benign(T.IPV4, "8.8.8.8")  # public resolver: noise list
    assert not sandbox_benign(T.DOMAIN, "c2.example.net")


# --------------------------------------------------------------------------------------
# statuses (c4): rule 5 everywhere
# --------------------------------------------------------------------------------------


def test_empty_list_and_404_are_empty():
    assert run(SHA256, search("empty_synthetic.json")).status is Status.EMPTY
    assert run(SHA256, search(raw=b'{"message": "Not Found"}', status=404)).status is Status.EMPTY


def test_403_api_key_messages_are_needs_key():
    res = run(SHA256, search("needs_key_403.json", status=403))
    assert res.status is Status.NEEDS_KEY and "API key is missing" in res.error
    res2 = run(SHA256, search("incompatible_key_403_synthetic.json", status=403))
    assert res2.status is Status.NEEDS_KEY and "incompatible" in res2.error
    res3 = run(SHA256, search(raw=b'{"message": "Forbidden"}', status=403))
    assert res3.status is Status.NEEDS_KEY and "vetting" in res3.error


def test_429_5xx_malformed_error_in_200_and_challenges():
    assert run(SHA256, search("rate_limited_429_synthetic.json", status=429)).status is Status.RATE_LIMITED
    assert run(SHA256, search(raw=b"oops", status=502)).status is Status.ERROR
    assert run(SHA256, search(raw=b'[{"sha256": ')).status is Status.ERROR
    res = run(SHA256, search(raw=b'{"message": "Internal error, try again"}'))
    assert res.status is Status.ERROR and "inside an HTTP 200" in res.error
    page = "<html><head><title>Just a moment...</title></head><body>cf-chl-widget</body></html>"
    http = FakeHttp().add("POST", SEARCH_URL, status=403, text=page)
    assert run(SHA256, http).status is Status.BLOCKED


def test_without_a_key_nothing_is_sent():
    assert run_module(HybridAnalysis, f"sha256:{SHA256}", FakeHttp()).status is Status.NEEDS_KEY


# --------------------------------------------------------------------------------------
# licence (c3)
# --------------------------------------------------------------------------------------


def test_licence_gate_needs_legal_s_business_record_under_corporate():
    from v3lum.core import module as module_mod
    from v3lum.core import policy

    module_mod.load_modules()
    ent = Entity.make(T.SHA256, SHA256)
    free = policy.make_context(make_runtime(keys=KEYS), ScanOptions(), path="scan")
    decision = policy.decide(HybridAnalysis, ent, free, run=RunInfo(entity=ent, is_seed=True))
    assert (decision.allowed, decision.reason_code) == (False, "licence") and decision.emit_manual_link
    business = policy.make_context(make_runtime(keys=KEYS, settings={"key_plans": {"hybridanalysis": "business"}}), ScanOptions(), path="scan")
    assert policy.decide(HybridAnalysis, ent, business, run=RunInfo(entity=ent, is_seed=True)).allowed
