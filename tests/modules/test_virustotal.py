"""Offline tests of virustotal (P158) with the fixtures in tests/fixtures/virustotal/.

Provenance: ``needs_key_401.json`` is the real keyless answer (research 2026-11-25); ``*_docs.json`` are
VirusTotal API documentation examples (docs.virustotal.com, fetched 2026-11-26; addresses and hosts
moved to documentation values, WHOIS replaced); ``*_synthetic.json`` are documented field shapes with
documentation values and a synthetic sample hash (``file_eicar_synthetic.json`` keeps the EICAR test
file), until a licensed key exists (P158 c6, backlog)."""

from __future__ import annotations

import base64
import json

import pytest

from tests.fakes import FakeHttp, assert_no_secret, make_runtime, module_fixture, run_module
from v3lum import paths
from v3lum.core.context import ScanOptions
from v3lum.core.entities import Entity
from v3lum.core.entities import EntityType as T
from v3lum.core.models import Severity, Status
from v3lum.core.providers import registry
from v3lum.modules.threat_intel_ioc import virustotal as mod
from v3lum.modules.threat_intel_ioc.virustotal import (
    NOT_RUN,
    VirusTotal,
    object_url,
    relationship_url,
    request_allowed,
    url_id,
    verdict,
)

FIX = "virustotal"
KEY_VALUE = "vt-test-key-0123456789abcdef0123456789abcdef0123456789abcdef01234567"
KEYS = {"virustotal": KEY_VALUE}
BASE = "https://www.virustotal.com/api/v3"
SAMPLE_SHA256 = "3e9134075b2bf1d15b039867b9a33e0ea1210aab211449c6f0a79cbf7fa8e98e"
SAMPLE_MD5 = "94bc27a41c42bdb00c3de68b6d3365d6"
EICAR_SHA256 = "275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f"


def body(name: str) -> bytes:
    return json.dumps(module_fixture(FIX, name)).encode()


def route(http: FakeHttp, url: str, name: str | None = None, *, status: int = 200, raw: bytes | None = None) -> FakeHttp:
    return http.add("GET", url, status=status, body=raw if raw is not None else body(name or ""),
                    headers={"content-type": "application/json"}, match_headers={"x-apikey": KEY_VALUE})


def obj(etype: T, value: str) -> str:
    return object_url(Entity.make(etype, value))


def rel(etype: T, value: str, name: str) -> str:
    return relationship_url(Entity.make(etype, value), name, 10)


def empty_page() -> bytes:
    return json.dumps({"data": [], "meta": {"count": 0}}).encode()


@pytest.fixture(autouse=True)
def _fresh_budget():
    mod.CASE_BUDGET.reset()
    mod.PACER.reset()
    yield
    mod.PACER.reset()


@pytest.fixture
def premium_pacing(monkeypatch):
    """Relationship tests: no public-key pacing (a premium licence's quota block has no 4/min rate);
    documentation addresses count as public."""
    from v3lum.core import quota

    monkeypatch.setattr(quota.QuotaBook, "_bucket", lambda self, pid, scope, spec, n: 0.0)
    monkeypatch.setattr(mod, "pacing_interval", lambda: 0.0)
    monkeypatch.setattr(mod, "public_ip", lambda value: not value.startswith(("10.", "127.")))


def run_vt(*args, **kw):
    """One lookup in its own minute: the module's public-key pacer starts free (separate scans)."""
    mod.PACER.reset()
    return run_module(VirusTotal, *args, **kw)


def assert_read_only(http: FakeHttp) -> None:
    """c2: every request the module built passes the GET-only allow-list."""
    assert http.calls
    for call in http.calls:
        assert call["method"] == "GET" and request_allowed(call["method"], call["url"]), call["url"]


# --------------------------------------------------------------------------------------
# metadata and read-only construction (c1, c2, c6)
# --------------------------------------------------------------------------------------


def test_metadata_matches_the_council_decision():
    cls = VirusTotal
    assert (cls.terms, cls.default_enabled, cls.trust_tier, cls.disclosure) == ("noncommercial", True, "trusted", "third_party")
    assert "off under the corporate profile until licence-cleared" in cls.notice
    assert cls.requires_keys == ("virustotal",) and cls.hosts == ("www.virustotal.com",) and cls.sources == ("virustotal.api",)
    assert cls.manual_link == "threat_intel_g07_p2:vt_search" and cls.absent_statuses == frozenset({404})
    assert {"virustotal_case_budget", "virustotal_trusted_vendors", "virustotal_page_size"} == set(cls.settings)
    quota = registry().get("virustotal").quota
    assert quota.day == 500 and quota.rate_per_second == pytest.approx(0.0667)


@pytest.mark.parametrize("method,url", [
    ("POST", f"{BASE}/files"),
    ("POST", f"{BASE}/urls"),
    ("GET", f"{BASE}/files/upload_url"),
    ("POST", f"{BASE}/files/{SAMPLE_SHA256}/analyse"),
    ("GET", f"{BASE}/files/{SAMPLE_SHA256}/analyse"),
    ("POST", f"{BASE}/urls/aHR0cHM6Ly9leGFtcGxlLmNvbS8/analyse"),
    ("GET", f"{BASE}/analyses/abc123"),
    ("GET", f"{BASE}/files/{SAMPLE_SHA256}/comments"),
    ("POST", f"{BASE}/files/{SAMPLE_SHA256}/comments"),
    ("POST", f"{BASE}/files/{SAMPLE_SHA256}/votes"),
    ("GET", f"{BASE}/files/{SAMPLE_SHA256}/download"),
    ("GET", f"{BASE}/files/{SAMPLE_SHA256}/download_url"),
    ("GET", f"{BASE}/files/{SAMPLE_SHA256}/relationships/contacted_ips"),
    ("GET", f"{BASE}/files/{SAMPLE_SHA256}/contacted_ips?limit=41"),
    ("GET", f"{BASE}/files/{SAMPLE_SHA256}/contacted_ips?limit=10&x=1"),
    ("GET", f"{BASE}/files/{SAMPLE_SHA256}/downloaded_files?limit=10"),
    ("GET", f"{BASE}/files/{SAMPLE_SHA256}?x=1"),
    ("GET", f"{BASE}/intelligence/search?query=x"),
    ("GET", f"http://www.virustotal.com/api/v3/files/{SAMPLE_SHA256}"),
    ("GET", f"https://evil.example/api/v3/files/{SAMPLE_SHA256}"),
])
def test_allow_list_never_builds_submissions_rescans_comments_or_votes(method, url):
    assert not request_allowed(method, url)


def test_allow_list_accepts_lookups_and_capped_relationship_pages():
    assert request_allowed("GET", obj(T.SHA256, SAMPLE_SHA256))
    assert request_allowed("GET", obj(T.URL, "https://example.com/login"))
    assert request_allowed("GET", rel(T.DOMAIN, "example.com", "subdomains"))
    assert request_allowed("GET", f"{BASE}/domains/example.com/subdomains?limit=40&cursor=abc")
    assert relationship_url(Entity.make(T.URL, "https://example.com/"), "contacted_ips") is None  # c4: no URL relationships


def test_url_ids_are_base64url_without_padding():
    url = "https://example.com/a?b=c"
    expected = base64.urlsafe_b64encode(url.encode()).decode().rstrip("=")
    assert url_id(url) == expected and "=" not in url_id("https://example.com/")
    assert obj(T.URL, url).endswith("/urls/" + url_id(Entity.make(T.URL, url).value))


# --------------------------------------------------------------------------------------
# verdicts (c5)
# --------------------------------------------------------------------------------------


def test_clean_ip_records_facts_and_no_finding():
    http = route(FakeHttp(), obj(T.IPV4, "192.0.2.80"), "ip_ok_docs.json")
    route(http, rel(T.IPV4, "192.0.2.80", "resolutions"), raw=empty_page())
    route(http, rel(T.IPV4, "192.0.2.80", "communicating_files"), raw=empty_page())
    res = run_vt("ipv4:192.0.2.80", http, keys=KEYS)
    assert res.status is Status.OK and not res.findings
    assert res.attributes["reputation"] == {"virustotal": "0/5"} and res.attributes["asn"] == "AS6724"
    assert res.attributes["as_org"] == "Strato AG" and res.attributes["country"] == "DE"
    assert res.attributes["virustotal"]["wording"].startswith("0/5 engines flagged (last analysis 2022-12-22)")
    assert ("VirusTotal report", "https://www.virustotal.com/gui/ip-address/192.0.2.80") in res.links
    assert "whois" not in json.dumps(res.to_dict()).lower()
    assert res.attributes["export_restriction"]["redistributable"] is False
    assert http.calls[0]["headers"]["x-apikey"] == KEY_VALUE
    assert_no_secret(KEY_VALUE, res.to_dict())
    assert_read_only(http)
    http.assert_hosts_within(VirusTotal)


def test_three_engines_are_suspicious_medium_with_the_wording():
    sha = "5a430646b4d3c04f0b43b444ad48443f"
    http = route(FakeHttp(), obj(T.MD5, sha), "file_suspicious_docs.json")
    for name in ("contacted_domains", "contacted_ips", "contacted_urls"):
        route(http, rel(T.MD5, sha, name), raw=empty_page())
    res = run_vt(f"md5:{sha}", http, keys=KEYS)
    [f] = res.findings
    assert f.title == "Suspicious on VirusTotal" and f.severity is Severity.MEDIUM and f.tags == ["suspicious"]
    assert f.description.startswith("3/5 engines flagged (last analysis 2020-06-14); top labels: ")
    assert len(f.data["top_labels"]) == 3 and f.criterion


def test_five_or_more_engines_are_malicious_high_and_submitted_names_are_never_kept(premium_pacing):
    http = route(FakeHttp(), obj(T.SHA256, SAMPLE_SHA256), "file_malicious_synthetic.json")
    for name in ("contacted_domains", "contacted_ips", "contacted_urls"):
        route(http, rel(T.SHA256, SAMPLE_SHA256, name), raw=empty_page())
    res = run_vt(f"sha256:{SAMPLE_SHA256}", http, keys=KEYS)
    [f] = res.findings
    assert f.title == "Malicious on VirusTotal" and f.severity is Severity.HIGH and f.tags == ["malicious", "malware"]
    assert f.description.startswith("8/9 engines flagged") and f.source == "virustotal.api"
    assert res.attributes["malware_family"] == ["agent"] and res.attributes["md5"] == SAMPLE_MD5
    same = {p.entity.value: p for p in res.pivots if p.relation == "same_file"}
    assert SAMPLE_MD5 in same and not same[SAMPLE_MD5].expand
    assert_no_secret("submitted-name-marker", res.to_dict())


def test_eicar_detections_are_expected_info():
    http = route(FakeHttp(), obj(T.SHA256, EICAR_SHA256), "file_eicar_synthetic.json")
    for name in ("contacted_domains", "contacted_ips", "contacted_urls"):
        route(http, rel(T.SHA256, EICAR_SHA256, name), raw=empty_page())
    res = run_vt(f"sha256:{EICAR_SHA256}", http, keys=KEYS)
    [f] = res.findings
    assert f.title == "EICAR test file (VirusTotal)" and f.severity is Severity.INFO and f.tags == ["test_file"]


def test_malicious_url_is_phishing_with_the_final_url_listed():
    url = "https://malicious.example.net/login"
    doc = module_fixture(FIX, "url_malicious_synthetic.json")
    http = route(FakeHttp(), obj(T.URL, url), raw=json.dumps(doc).encode())
    res = run_vt(f"url:{url}", http, keys=KEYS)
    [f] = res.findings
    assert f.severity is Severity.HIGH and set(f.tags) == {"malicious", "phishing"}
    final = [p for p in res.pivots if p.relation == "redirects_to"]
    assert final and final[0].entity.value.startswith("https://malicious.example.net/login/verify.php") and not final[0].expand
    assert len(http.calls) == 1  # URL objects read no relationships (c4)
    assert any("/gui/search/" in link for _label, link in res.links)


def test_trusted_vendor_and_few_engine_bands():
    a = {"malicious": 1, "suspicious": 0, "harmless": 0, "undetected": 60, "total": 61, "date": "2026-11-20T00:00:00Z",
         "top_labels": ["Trojan.X"], "flagged_by": ["Kaspersky"]}
    assert verdict(a)["band"] == "few_engines" and verdict(a)["severity"] == "low"
    assert verdict(a, ["kaspersky"])["band"] == "malicious"
    assert verdict({**a, "malicious": 4})["band"] == "suspicious"
    assert verdict({**a, "malicious": 0, "flagged_by": []})["band"] == "none"
    doc = module_fixture(FIX, "file_suspicious_docs.json")
    doc["data"]["attributes"]["last_analysis_stats"]["malicious"] = 1
    sha = "5a430646b4d3c04f0b43b444ad48443f"
    http = route(FakeHttp(), obj(T.MD5, sha), raw=json.dumps(doc).encode())
    for name in ("contacted_domains", "contacted_ips", "contacted_urls"):
        route(http, rel(T.MD5, sha, name), raw=empty_page())
    res = run_vt(f"md5:{sha}", http, keys=KEYS)
    [f] = res.findings
    assert f.title == "Few engines flag it on VirusTotal" and f.severity is Severity.LOW and "weak_signal" in f.tags


# --------------------------------------------------------------------------------------
# relationships (c4)
# --------------------------------------------------------------------------------------


def test_relationships_one_capped_page_each_filtered_and_not_expanded(premium_pacing):
    domain = "example.com"
    http = route(FakeHttp(), obj(T.DOMAIN, domain), "domain_ok_docs.json")
    resolutions = module_fixture(FIX, "resolutions_ip_synthetic.json")
    resolutions["data"][0]["attributes"]["ip_address"] = "8.8.8.8"  # a public resolver: noise, filtered
    resolutions["meta"] = {"count": 25, "cursor": "next-page-cursor"}
    route(http, rel(T.DOMAIN, domain, "resolutions"), raw=json.dumps(resolutions).encode())
    route(http, rel(T.DOMAIN, domain, "subdomains"), "subdomains_synthetic.json")
    route(http, rel(T.DOMAIN, domain, "communicating_files"), "communicating_files_synthetic.json")
    res = run_vt(f"domain:{domain}", http, keys=KEYS)
    assert res.status is Status.OK and len(http.calls) == 4
    assert all("cursor" not in c["url"] for c in http.calls)  # cursors reported, never followed
    pivots = {(p.relation, p.entity.value): p for p in res.pivots}
    assert ("subdomain", "mail.example.com") in pivots and ("subdomain", "login.example.com") in pivots
    assert ("historical_a_record", "192.0.2.80") in pivots and ("historical_a_record", "8.8.8.8") not in pivots
    assert ("contacted_by", EICAR_SHA256) in pivots
    assert all(not p.expand for p in res.pivots)  # the domain itself is not malicious
    summary = res.attributes["vt_relationships"]
    assert summary["resolutions"]["filtered"] == 1 and summary["resolutions"]["more"] is True
    assert_read_only(http)


def test_relationships_of_a_malicious_sample_are_expanded(premium_pacing):
    http = route(FakeHttp(), obj(T.SHA256, SAMPLE_SHA256), "file_malicious_synthetic.json")
    page = {"data": [{"type": "domain", "id": "c2.example.net", "attributes": {"last_analysis_stats": {"malicious": 9}}},
                     {"type": "domain", "id": "dns.google", "attributes": {}}]}
    route(http, rel(T.SHA256, SAMPLE_SHA256, "contacted_domains"), raw=json.dumps(page).encode())
    route(http, rel(T.SHA256, SAMPLE_SHA256, "contacted_ips"), status=403,
          raw=b'{"error": {"code": "ForbiddenError", "message": "premium only"}}')
    route(http, rel(T.SHA256, SAMPLE_SHA256, "contacted_urls"), raw=empty_page())
    res = run_vt(f"sha256:{SAMPLE_SHA256}", http, keys=KEYS)
    c2 = [p for p in res.pivots if p.entity.value == "c2.example.net"]
    assert c2 and c2[0].relation == "communicates_with" and c2[0].expand
    assert not any(p.entity.value == "dns.google" for p in res.pivots)
    assert res.attributes["vt_relationships"]["contacted_ips"]["read"] is False  # a premium-only page never fails the verdict
    assert res.findings[0].title == "Malicious on VirusTotal"


def test_public_pacing_defers_relationships_and_keeps_the_verdict():
    http = route(FakeHttp(), obj(T.DOMAIN, "example.com"), "domain_ok_docs.json")
    res = run_vt("domain:example.com", http, keys=KEYS)
    assert res.status is Status.OK and len(http.calls) == 1
    summary = res.attributes["vt_relationships"]["resolutions"]
    assert summary["read"] is False and NOT_RUN in summary["reason"]


def test_pivots_read_no_relationships():
    http = route(FakeHttp(), obj(T.DOMAIN, "example.com"), "domain_ok_docs.json")
    res = run_vt("domain:example.com", http, keys=KEYS, is_seed=False, depth=1,
                     provenance=[("ipv4:192.0.2.8", "hosted_domain", "passive_dns")])
    assert res.status is Status.OK and len(http.calls) == 1 and "vt_relationships" not in res.attributes


# --------------------------------------------------------------------------------------
# budget (c3): the scan never waits on VT
# --------------------------------------------------------------------------------------


def test_token_bucket_defers_the_next_lookup_instead_of_waiting():
    http = route(FakeHttp(), obj(T.SHA256, SAMPLE_SHA256), "file_malicious_synthetic.json")
    rt = make_runtime(http, keys=KEYS)
    first = run_module(VirusTotal, f"sha256:{SAMPLE_SHA256}", runtime=rt, is_seed=False, depth=1,
                       provenance=[("domain:example.com", "contacted_by", "virustotal")])
    assert first.status is Status.OK
    second = run_module(VirusTotal, f"md5:{SAMPLE_MD5}", runtime=rt)
    assert second.status is Status.QUOTA and NOT_RUN in second.error and second.reason_code == "quota"
    assert len(http.calls) == 1 and not getattr(rt.clock, "sleeps", [])  # deferred, never waited for in the worker


def test_per_scan_budget_keeps_the_last_share_for_seeds():
    settings = {"virustotal_case_budget": 2}
    http = route(FakeHttp(), obj(T.IPV4, "192.0.2.80"), "ip_ok_docs.json")
    pivot = run_vt("ipv4:192.0.2.80", http, keys=KEYS, settings=settings, case_id="c1", is_seed=False, depth=1,
                       provenance=[("domain:example.com", "resolves_to", "dns_records")])
    assert pivot.status is Status.OK
    later = run_vt("ipv4:192.0.2.81", FakeHttp(), keys=KEYS, settings=settings, case_id="c1", is_seed=False, depth=1,
                       provenance=[("domain:example.com", "resolves_to", "dns_records")])
    assert later.status is Status.QUOTA and "per-scan budget" in later.error  # 2 x 80% = 1 lookup for pivots


# --------------------------------------------------------------------------------------
# statuses: rule 5 everywhere
# --------------------------------------------------------------------------------------


def test_404_is_unknown_to_virustotal():
    res = run_vt(f"sha256:{SAMPLE_SHA256}", route(FakeHttp(), obj(T.SHA256, SAMPLE_SHA256), "not_found_404_docs.json", status=404), keys=KEYS)
    assert res.status is Status.EMPTY and "unknown to VirusTotal" in res.error


def test_401_and_403_are_needs_key():
    for name, status in (("needs_key_401.json", 401), ("wrong_key_401_synthetic.json", 401)):
        res = run_vt(f"sha256:{SAMPLE_SHA256}", route(FakeHttp(), obj(T.SHA256, SAMPLE_SHA256), name, status=status), keys=KEYS)
        assert res.status is Status.NEEDS_KEY
    res = run_vt(f"sha256:{SAMPLE_SHA256}", route(FakeHttp(), obj(T.SHA256, SAMPLE_SHA256), status=403,
                                                                  raw=b'{"error": {"code": "ForbiddenError"}}'), keys=KEYS)
    assert res.status is Status.NEEDS_KEY


def test_quota_exceeded_is_quota_and_too_many_requests_rate_limited():
    res = run_vt(f"sha256:{SAMPLE_SHA256}", route(FakeHttp(), obj(T.SHA256, SAMPLE_SHA256), "quota_429_synthetic.json", status=429), keys=KEYS)
    assert res.status is Status.QUOTA and res.reason_code == "quota"
    res2 = run_vt(f"md5:{SAMPLE_MD5}", route(FakeHttp(), obj(T.MD5, SAMPLE_MD5), "too_many_429_synthetic.json", status=429), keys=KEYS)
    assert res2.status is Status.RATE_LIMITED


def test_errors_malformed_bodies_and_challenges_are_could_not_verify():
    url = obj(T.SHA256, SAMPLE_SHA256)
    assert run_vt(f"sha256:{SAMPLE_SHA256}", route(FakeHttp(), url, raw=b'{"error": {"code": "TransientError"}}', status=503), keys=KEYS).status is Status.ERROR
    assert run_vt(f"sha256:{SAMPLE_SHA256}", route(FakeHttp(), url, raw=b'{"data": {"attributes": '), keys=KEYS).status is Status.ERROR
    res = run_vt(f"sha256:{SAMPLE_SHA256}", route(FakeHttp(), url, raw=b'{"error": {"code": "NotAvailableYet"}}'), keys=KEYS)
    assert res.status is Status.ERROR and "not analysed yet" in res.error
    assert run_vt(f"sha256:{SAMPLE_SHA256}", route(FakeHttp(), url, raw=b'{"data": "nope"}'), keys=KEYS).status is Status.ERROR
    page = "<html><head><title>Just a moment...</title></head><body>cf-chl-widget</body></html>"
    http = FakeHttp().add("GET", url, status=403, text=page)
    assert run_vt(f"sha256:{SAMPLE_SHA256}", http, keys=KEYS).status is Status.BLOCKED


def test_without_a_key_nothing_is_sent():
    assert run_vt(f"sha256:{SAMPLE_SHA256}", FakeHttp()).status is Status.NEEDS_KEY


# --------------------------------------------------------------------------------------
# licence (c1): noncommercial public API, off under corporate until licence-cleared
# --------------------------------------------------------------------------------------


def test_off_under_corporate_until_a_licence_is_recorded():
    from v3lum.core import module as module_mod
    from v3lum.core import policy
    from v3lum.core.context import RunInfo

    module_mod.load_modules()
    ent = Entity.make(T.SHA256, SAMPLE_SHA256)
    business = make_runtime(keys=KEYS, settings={"key_plans": {"virustotal": "business"}})
    decision = policy.decide(VirusTotal, ent, policy.make_context(business, ScanOptions(), path="scan"), run=RunInfo(entity=ent, is_seed=True))
    assert (decision.allowed, decision.reason_code) == (False, "licence") and decision.emit_manual_link  # a key plan never clears noncommercial
    allow = paths.home() / "licence_allow.json"
    allow.write_text(json.dumps({"entries": [{
        "source_id": "virustotal.api", "basis": "licence", "scope": "VirusTotal enterprise licence, internal CTI",
        "legal_ref": "LEGAL-VT-1", "approver": "legal (DPO office)", "decided_at": "2026-11-01", "review_by": "2027-05-01",
        "evidence_url": "https://docs.virustotal.com/reference/public-vs-premium-api", "quote": "premium licence"}]}), encoding="utf-8")
    allow.chmod(0o600)
    cleared = policy.decide(VirusTotal, ent, policy.make_context(make_runtime(keys=KEYS), ScanOptions()), run=RunInfo(entity=ent, is_seed=True))
    assert cleared.allowed
