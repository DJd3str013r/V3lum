"""Offline tests of maltiverse (P154) with the fixtures in tests/fixtures/maltiverse/.

Provenance: ``ip_ok.json`` (8.8.8.8, research 2026-11-25), ``hostname_ok.json`` (example.com),
``url_ok.json`` (``http://example.com``), ``url_not_found.json`` (the neutral stub of
``http://example.com/``) and ``sample_ok.json`` (EICAR) are real keyless answers (live 2026-11-26),
minimised; ``*_docs.json`` are python-maltiverse README examples moved to documentation values;
``*_synthetic.json`` follow the README error shape (``{"status": "fail", "message": ...}``) until the
team key exists (backlog)."""

from __future__ import annotations

import copy
import json
from pathlib import Path

import pytest

from tests.fakes import FakeHttp, assert_no_secret, module_fixture, run_module
from v3lum.core.entities import EntityType as T
from v3lum.core.models import Confidence, Opsec, Severity, Status
from v3lum.core.providers import registry
from v3lum.modules.threat_intel_ioc import maltiverse as mod
from v3lum.modules.threat_intel_ioc.maltiverse import Maltiverse, lookup_url, request_allowed, url_checksum, url_variants

FIX = "maltiverse"
KEY_VALUE = "maltiverse-test-key-0123456789abcdef0123"
KEYS = {"maltiverse": KEY_VALUE}
EICAR_SHA256 = "275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f"


FIXTURES = Path(__file__).resolve().parents[1] / "fixtures" / FIX


def body(name: str) -> bytes:
    """The fixture bytes as served (tests/fixtures/maltiverse/<name>; truncated files stay truncated)."""
    return (FIXTURES / name).read_bytes()


def route(http: FakeHttp, url: str, *, name: str | None = None, raw: bytes | None = None, status: int = 200,
          headers: dict[str, str] | None = None) -> FakeHttp:
    content = raw if raw is not None else body(name or "")
    hdrs = {"content-type": "application/json", **(headers or {})}
    return http.add("GET", url, status=status, body=content, headers=hdrs, match_headers={"authorization": f"Bearer {KEY_VALUE}"})


@pytest.fixture(autouse=True)
def doc_ips(monkeypatch):
    """Documentation addresses stand in for real ones in the documented shapes."""
    monkeypatch.setattr(mod, "public_ip", lambda value: True)


def run(entity: str, http: FakeHttp, **kw):
    return run_module(Maltiverse, entity, http, keys=KEYS, **kw)


def assert_read_only(http: FakeHttp) -> None:
    for call in http.calls:
        assert request_allowed(call["method"], call["url"]), call["url"]


# --------------------------------------------------------------------------------------
# metadata, allow-list, URL normalisation (c1-c3)
# --------------------------------------------------------------------------------------


def test_metadata_matches_the_council_decision():
    cls = Maltiverse
    assert (cls.terms, cls.default_enabled, cls.trust_tier, cls.disclosure) == ("key-terms", True, "trusted", "third_party")
    assert cls.opsec is Opsec.PASSIVE
    assert cls.requires_keys == ("maltiverse",) and cls.hosts == ("api.maltiverse.com",) and cls.sources == ("maltiverse.lookup",)
    assert cls.cache_ttl == 86400 and cls.max_requests == 2 and cls.shares_input is True
    prov = registry().get("maltiverse")
    assert prov.tier == "trusted" and prov.quota.scope == "key" and prov.quota.day == 20
    src = registry().source("maltiverse.lookup")
    assert src.terms.class_ == "key-terms" and src.terms.free_plan_business_use is None
    assert {"abuse.ch", "spamhaus", "triage", "blocklist.de"} <= set(src.embeds)
    assert "V3LUM_MALTIVERSE_KEY" in registry().keys()["maltiverse"].env


def test_allow_list_only_builds_the_four_read_only_lookups():
    for etype, value in [(T.IPV4, "8.8.8.8"), (T.DOMAIN, "example.com"), (T.URL, "http://example.com"), (T.SHA256, EICAR_SHA256)]:
        assert request_allowed("GET", lookup_url(etype, value))
    base = "https://api.maltiverse.com"
    for method, url in [
        ("PUT", f"{base}/ip/8.8.8.8"), ("DELETE", f"{base}/hostname/example.com"), ("POST", f"{base}/ip/8.8.8.8"),
        ("GET", f"{base}/ioc/abc"), ("GET", f"{base}/bulk/ip"), ("GET", f"{base}/search?query=x"), ("GET", f"{base}/auth/login"),
        ("GET", f"{base}/email/someone@example.com"), ("GET", f"{base}/ip/8.8.8.8?key=x"), ("GET", "http://api.maltiverse.com/ip/8.8.8.8"),
        ("GET", "https://maltiverse.com/ip/8.8.8.8"), ("GET", "https://user:pw@api.maltiverse.com/ip/8.8.8.8"),
        ("GET", f"{base}/ip/not-an-ip"), ("GET", f"{base}/sample/{'0' * 32}"), ("GET", f"{base}/url/http://example.com"),
    ]:
        assert not request_allowed(method, url), (method, url)
    with pytest.raises(ValueError):
        lookup_url(T.MD5, "44d88612fea8a8f36de82e1278abb02f")


def test_url_checksum_matches_maltiverse_exactly():
    # python-maltiverse README: url_get("https://alleom.com/weqmo") -> urlchecksum 7b0ef6e5...
    assert url_checksum("https://alleom.com/weqmo") == "7b0ef6e5d95e2ee2c2602135c39f3fe09fe8f1eee7f5769266a0dbe718696ec3"
    doc, stub = module_fixture(FIX, "url_ok.json"), module_fixture(FIX, "url_not_found.json")
    assert url_checksum(doc["url"]) == doc["urlchecksum"]  # 'http://example.com' (live)
    assert url_checksum("http://example.com/") == stub["urlchecksum"] != doc["urlchecksum"]


def test_url_variants_exact_string_first_then_one_variant():
    assert url_variants("https://alleom.com/weqmo") == ["https://alleom.com/weqmo"]
    assert url_variants("http://example.com/") == ["http://example.com/", "http://example.com"]
    assert url_variants("http://example.com") == ["http://example.com", "http://example.com/"]
    assert url_variants("HTTP://Example.COM/Path") == ["HTTP://Example.COM/Path", "http://example.com/Path"]
    assert url_variants("ftp://example.com/") == [] and url_variants("not a url") == [] and url_variants(None) == []


# --------------------------------------------------------------------------------------
# keyed only (c1)
# --------------------------------------------------------------------------------------


def test_without_the_key_nothing_is_sent():
    http = FakeHttp()
    res = run_module(Maltiverse, "ipv4:8.8.8.8", http)
    assert res.status is Status.NEEDS_KEY and not http.calls


def test_private_addresses_are_never_sent(monkeypatch):
    monkeypatch.setattr(mod, "public_ip", lambda value: False)
    http = FakeHttp()
    res = run("ipv4:10.0.0.1", http)
    assert res.status is Status.SKIPPED and res.reason_code == "not_applicable" and not http.calls


# --------------------------------------------------------------------------------------
# documents (c4, c5)
# --------------------------------------------------------------------------------------


def test_whitelisted_ip_dampens_and_keeps_provenance_without_a_finding():
    http = route(FakeHttp(), lookup_url(T.IPV4, "8.8.8.8"), name="ip_ok.json")
    res = run("ipv4:8.8.8.8", http)
    assert res.status is Status.OK and not res.findings
    facts = res.attributes["maltiverse"]
    assert facts["classification"] == "whitelist"
    assert any(row["source"] == "ThreatFox Abuse.ch" and row["family"] == "abuse.ch" and row["last_seen"] == "2023-09-11T07:26:12Z"
               for row in facts["listings"])
    assert {row["source"] for row in facts["benign_listings"]} >= {"Maltiverse", "Public-dns.info"}
    assert any("whitelist" in reason for reason in res.attributes["allowlisted"])
    assert res.attributes["reputation"] == {"maltiverse": "whitelist"} and res.attributes["asn"] == "AS15169"
    # 8.8.8.8 is on the public-DNS warninglist: families are listed, never pivoted (sandbox/relay noise)
    assert {"AsyncRAT", "Ghost RAT", "conficker", "AZORult"} <= set(res.attributes["malware_family"]) and not res.pivots
    http.assert_hosts_within(Maltiverse)
    assert_read_only(http)


def test_family_names_become_listed_malware_family_pivots():
    http = route(FakeHttp(), lookup_url(T.IPV4, "203.0.113.20"), name="ip_ok.json")
    res = run("ipv4:203.0.113.20", http)
    fams = {p.entity.value.lower(): p for p in res.pivots}
    assert {"asyncrat", "ghost rat", "conficker", "azorult"} <= set(fams)  # c5: MITRE/Maltiverse references or family-like names
    assert all(p.expand is False and p.relation == "family" for p in res.pivots)
    assert "trojan.agent" not in fams and "malware download" not in fams and "http spammer" not in fams
    assert fams["asyncrat"].confidence_label is Confidence.PROBABLE  # backed by MITRE S1087


def test_hostname_whitelist_lists_benign_sources_and_resolved_addresses():
    http = route(FakeHttp(), lookup_url(T.DOMAIN, "example.com"), name="hostname_ok.json")
    res = run("domain:example.com", http)
    assert res.status is Status.OK and not res.findings
    facts = res.attributes["maltiverse"]
    assert facts["resolved_ips"][0] == "93.184.216.34"
    assert {"Cisco Umbrella", "Tranco"} <= {row["source"] for row in facts["benign_listings"]}
    assert res.attributes["allowlisted"]


def test_url_lookup_tries_the_exact_string_then_one_variant_and_reports_the_listing_sources():
    http = FakeHttp()
    route(http, lookup_url(T.URL, "http://example.com/"), name="url_not_found.json")  # the entity value: a stub
    route(http, lookup_url(T.URL, "http://example.com"), name="url_ok.json")  # the variant: the document
    res = run("url:http://example.com", http)
    assert res.status is Status.OK and len(http.calls) == 2
    finding = res.findings[0]
    assert finding.title == "Listed as malicious by Maltiverse" and finding.severity is Severity.MEDIUM
    assert "malicious" in finding.tags and finding.source == "maltiverse.lookup"
    assert "Triage (last 2026-11-17)" in finding.criterion and "Triage" in finding.description
    # c4: the recent listings come from Triage, a family V3LUM queries itself: no independent Maltiverse vote
    assert finding.data["upstream_families"] == ["triage"]
    assert finding.observed_last.startswith("2026-11-17")
    assert {p.entity.value for p in res.pivots} >= {"Mintsloader", "Wannacry", "Redline"}
    assert any("maltiverse.com/url/" in str(link) for link in res.links)
    assert_read_only(http)


def test_stub_for_every_variant_is_not_in_maltiverse_never_a_neutral_vote():
    http = FakeHttp()
    route(http, lookup_url(T.URL, "http://example.com/"), name="url_not_found.json")
    route(http, lookup_url(T.URL, "http://example.com"), name="url_not_found.json")
    res = run("url:http://example.com", http)
    assert res.status is Status.EMPTY and "not in Maltiverse" in res.error
    assert "allowlisted" not in res.attributes and not res.findings


def test_404_is_an_unknown_object():
    http = route(FakeHttp(), lookup_url(T.DOMAIN, "unknown.example"), raw=b"{}", status=404)
    assert run("domain:unknown.example", http).status is Status.EMPTY


def test_whitelisted_eicar_sample_keeps_av_signatures():
    http = route(FakeHttp(), lookup_url(T.SHA256, EICAR_SHA256), name="sample_ok.json")
    res = run(f"sha256:{EICAR_SHA256}", http)
    assert res.status is Status.OK and not res.findings
    assert res.attributes["file_size"] == 68 and "EICAR Anti-Virus Test File" in res.attributes["av_signatures"]
    assert res.attributes["maltiverse"]["av_ratio"] == 94
    assert not res.pivots  # tag lists and 'Generic Malware' are not families


def test_malicious_sample_from_the_readme():
    sha = module_fixture(FIX, "sample_malicious_docs.json")["sha256"]
    http = route(FakeHttp(), lookup_url(T.SHA256, sha), name="sample_malicious_docs.json")
    res = run(f"sha256:{sha}", http)
    finding = res.findings[0]
    assert finding.severity is Severity.MEDIUM and finding.data["upstream_families"] == ["hybrid_analysis"]
    assert "Hybrid-Analysis" in finding.criterion


def test_stale_listings_are_maltiverse_history_dated_by_the_last_listing():
    http = route(FakeHttp(), lookup_url(T.IPV4, "203.0.113.98"), name="ip_malicious_docs.json")
    res = run("ipv4:203.0.113.98", http)
    finding = res.findings[0]
    assert finding.severity is Severity.MEDIUM and Confidence.from_value(finding.confidence) is Confidence.POSSIBLE  # no recent listing
    assert finding.data["upstream_families"] == ["maltiverse"]
    assert finding.observed_last.startswith("2020-03-21")  # CR27 reads it as history (30-day IP window)
    assert {"Blocklist.de", "CIArmy", "IBM X-Force Exchange"} <= {row["source"] for row in finding.data["listings"]}


def test_recent_relayed_listing_counts_as_its_upstream_family_and_unqueried_sources_as_maltiverse():
    doc = copy.deepcopy(module_fixture(FIX, "ip_malicious_docs.json"))
    doc["blacklist"] = [
        {"source": "Feodo Tracker Abuse.ch", "description": "Dridex", "first_seen": "2026-11-20 10:00:00", "last_seen": "2026-11-25 10:00:00", "count": 3},
        {"source": "Barracuda", "description": "Malicious Host", "first_seen": "2026-11-21 10:00:00", "last_seen": "2026-11-24 10:00:00", "count": 1},
    ]
    http = route(FakeHttp(), lookup_url(T.IPV4, "203.0.113.98"), raw=json.dumps(doc).encode())
    finding = run("ipv4:203.0.113.98", http).findings[0]
    assert finding.data["upstream_families"] == ["abuse.ch", "maltiverse"]
    assert Confidence.from_value(finding.confidence) is Confidence.PROBABLE


def test_context_booleans_are_attributes_never_malicious():
    doc = copy.deepcopy(module_fixture(FIX, "ip_ok.json"))
    doc.update(classification="neutral", is_tor_node=True, is_known_scanner=True, is_sinkhole=True)
    http = route(FakeHttp(), lookup_url(T.IPV4, "8.8.8.8"), raw=json.dumps(doc).encode())
    res = run("ipv4:8.8.8.8", http)
    assert res.attributes["is_tor_exit"] is True and res.attributes["is_scanner"] is True and res.attributes["is_sinkhole"] is True
    assert not res.findings and res.attributes["allowlisted"][0] == "Maltiverse classification neutral"


# --------------------------------------------------------------------------------------
# could not verify (c3, rule 5)
# --------------------------------------------------------------------------------------


def test_fail_body_inside_200_is_an_error():
    http = route(FakeHttp(), lookup_url(T.IPV4, "203.0.113.9"), name="error_in_200_synthetic.json")
    res = run("ipv4:203.0.113.9", http)
    assert res.status is Status.ERROR and res.reason_code == "error"


def test_quota_message_inside_200_is_quota():
    http = route(FakeHttp(), lookup_url(T.IPV4, "203.0.113.10"), name="quota_in_200_synthetic.json")
    res = run("ipv4:203.0.113.10", http)
    assert res.status is Status.QUOTA and res.reason_code == "quota"


def test_429_is_rate_limited_or_quota_by_the_reset_window():
    http = route(FakeHttp(), lookup_url(T.IPV4, "203.0.113.11"), raw=b'{"status":"fail","message":"slow down"}', status=429,
                 headers={"ratelimit-reset": "30"})
    assert run("ipv4:203.0.113.11", http).status is Status.RATE_LIMITED
    http2 = route(FakeHttp(), lookup_url(T.IPV4, "203.0.113.12"), raw=b"{}", status=429, headers={"ratelimit-reset": "53866"})
    res = run("ipv4:203.0.113.12", http2)
    assert res.status is Status.QUOTA and "53866" in res.error


def test_401_is_needs_key_and_the_key_never_leaks():
    http = route(FakeHttp(), lookup_url(T.IPV4, "203.0.113.13"), raw=b'{"status":"fail","message":"Unauthorized"}', status=401)
    res = run("ipv4:203.0.113.13", http)
    assert res.status is Status.NEEDS_KEY
    assert_no_secret(KEY_VALUE, res.to_dict() if hasattr(res, "to_dict") else res.__dict__)


def test_challenge_page_and_server_errors_are_could_not_verify():
    page = "<!DOCTYPE html><html><head><title>Just a moment...</title></head><body>cf-chl-widget</body></html>"
    http = FakeHttp().add("GET", lookup_url(T.IPV4, "203.0.113.14"), status=403, text=page)
    assert run("ipv4:203.0.113.14", http).status is Status.BLOCKED
    http2 = route(FakeHttp(), lookup_url(T.IPV4, "203.0.113.15"), raw=b"oops", status=502)
    assert run("ipv4:203.0.113.15", http2).status is Status.ERROR


def test_malformed_or_unexpected_bodies_are_errors_never_empty():
    http = route(FakeHttp(), lookup_url(T.IPV4, "8.8.8.8"), name="malformed_truncated.json")
    assert run("ipv4:8.8.8.8", http).status is Status.ERROR
    http2 = route(FakeHttp(), lookup_url(T.IPV4, "8.8.4.4"), raw=b'["not", "an", "object"]')
    assert run("ipv4:8.8.4.4", http2).status is Status.ERROR
    http3 = route(FakeHttp(), lookup_url(T.IPV4, "8.8.8.9"), raw=b'{"type": "email", "classification": "malicious", "blacklist": [{"source": "x"}]}')
    assert run("ipv4:8.8.8.9", http3).status is Status.ERROR
