"""Offline tests of honeypot_intel (P147) with the recorded OffSeq Mirage slices and the HoneyDB
current-API documentation examples in tests/fixtures/honeypot_intel/."""

from __future__ import annotations

from datetime import datetime, timezone

import pytest

from tests.fakes import FakeHttp, assert_no_secret, module_fixture, run_module
from v3lum.core import noise
from v3lum.core.datasets import DATASETS
from v3lum.core.graph import Graph
from v3lum.core.models import Severity, Status
from v3lum.correlations import threat_intel
from v3lum.modules.threat_intel_ioc import honeypot_intel as mod
from v3lum.modules.threat_intel_ioc.honeypot_intel import (
    ANONYMIZERS,
    ATTACKERS,
    KNOWN_SCANNERS,
    OFFSEQ_ATTRIBUTION,
    SRC_ANONYMIZERS,
    SRC_ATTACKERS,
    SRC_HONEYDB,
    SRC_SCANNERS,
    HoneypotIntel,
    honeypot_verdict,
    observation_transport,
    offseq_row,
    parse_honeydb_ip,
    parse_offseq_attackers,
)

FIX = "honeypot_intel"
BASE = "https://feeds.offseq.com/mirage-feed/latest/"
NOW = datetime(2026, 11, 26, 12, 0, tzinfo=timezone.utc)
HONEYDB = "https://honeydb.io/api/ip/{ip}"
KEYS = {"honeydb_api_id": "hdbid0123456789", "honeydb_api_key": "hdbkey0123456789abcdef"}
OFFSEQ_ONLY = (SRC_ATTACKERS, SRC_SCANNERS, SRC_ANONYMIZERS)


def text(name: str) -> str:
    return module_fixture(FIX, name)


def offseq_routes(http: FakeHttp | None = None, *, attackers: str = "offseq_attackers_ok.csv") -> FakeHttp:
    """The three OffSeq files (served as text/csv and text/plain, with Last-Modified like the live feed)."""
    http = http or FakeHttp()
    lm = {"last-modified": "Thu, 26 Nov 2026 03:40:00 GMT"}
    http.add("GET", BASE + "attackers-7d.csv", body=text(attackers).encode(), headers={"content-type": "text/csv", **lm})
    http.add("GET", BASE + "known-scanners-ipv4.txt", body=text("offseq_known_scanners_ok.txt").encode(), headers={"content-type": "text/plain", **lm})
    http.add("GET", BASE + "anonymizers-7d.txt", body=text("offseq_anonymizers_ok.txt").encode(), headers={"content-type": "text/plain", **lm})
    return http


def low_or_more(res):
    return [f for f in res.findings if f.severity >= Severity.LOW]


# --------------------------------------------------------------------------------------
# metadata, parsers and the shared semantics
# --------------------------------------------------------------------------------------


def test_metadata_datasets_and_noise_hook_registration():
    cls = HoneypotIntel
    assert (cls.terms, cls.trust_tier, cls.default_enabled, cls.disclosure) == ("key-terms", "community", True, "third_party")
    assert set(cls.optional_keys) == {"honeydb_api_id", "honeydb_api_key"} and cls.hosts == ("honeydb.io",)
    for name, source in ((ATTACKERS, SRC_ATTACKERS), (KNOWN_SCANNERS, SRC_SCANNERS), (ANONYMIZERS, SRC_ANONYMIZERS)):
        reg = DATASETS[name]
        assert (reg["source"], reg["licence"], reg["terms_class"], reg["attribution"]) == (source, "CC-BY-4.0", "open", OFFSEQ_ATTRIBUTION)
        assert 21600 <= reg["ttl"] <= 86400 and reg["large"] is False  # c1: every 6-24 h, conditional GET


def test_attackers_csv_parses_into_a_compact_index():
    index = parse_offseq_attackers(text("offseq_attackers_ok.csv"))
    assert index.rows == 10 and index.skipped == 0
    rec = index.lookup("23.132.164.50")
    assert rec["cves"] == ["CVE-2017-9841"] and rec["kev"] is True and rec["confidence"] == 93
    assert rec["attack"][:2] == ["T1059", "T1059.004"] and rec["services"] == ["http", "ssh"]
    assert rec["first_seen"] == "2026-11-06T00:00:00Z" and rec["transport"] == "tcp_handshake"
    assert [r["ip"] for r in index.by_cve["CVE-2017-9841"]] == ["23.132.164.50"]
    assert len(index.by_asn[60404]) == 3
    assert index.records["5.2.69.84"]["anonymizer"] == "tor" and index.records["23.234.75.218"]["anonymizer"] == "vpn"
    assert index.records["203.0.113.10"]["shared"] is True  # CGNAT row (address scrubbed to documentation space)
    assert index.records["45.133.18.54"]["recon_only"] is True


def test_truncated_download_keeps_complete_rows_and_html_is_refused():
    index = parse_offseq_attackers(text("offseq_attackers_truncated.csv"))
    assert index.rows == 2 and index.skipped == 1
    with pytest.raises(ValueError):
        parse_offseq_attackers("<!DOCTYPE html><html><head><title>Just a moment...</title></head></html>")
    with pytest.raises(ValueError):
        parse_offseq_attackers("ip,asn\n1.2.3.4,5\n")


def test_field_size_limit_drops_oversized_lines_without_touching_the_global_limit():
    import csv

    before = csv.field_size_limit()
    huge = "9.9.9.9,1,x" + "y" * (mod.FIELD_SIZE_LIMIT + 10) + ",US,2026-11-20T00:00:00Z,2026-11-21T00:00:00Z,,,,false,,3,2,1,10"
    index = parse_offseq_attackers(text("offseq_attackers_ok.csv") + huge + "\n")
    assert index.rows == 10 and index.skipped == 1 and "9.9.9.9" not in index.records
    assert csv.field_size_limit() == before


def test_verdict_semantics_scanner_medium_cap_decay_and_udp():
    assert honeypot_verdict(now=NOW, benign_scanner=True).tags == ["benign_scanner"]
    assert honeypot_verdict(now=NOW, cves=["CVE-2017-9841"], last_seen="2026-11-25").severity == "medium"
    assert honeypot_verdict(now=NOW, confidence=95).severity == "medium"  # never above MEDIUM alone
    old = honeypot_verdict(now=NOW, cves=["CVE-2017-9841"], last_seen="2026-10-01T00:00:00Z")
    assert (old.severity, old.counts) == ("info", False) and "history only" in old.why  # 30-day decay
    udp = honeypot_verdict(now=NOW, transport=observation_transport(["ntp", "snmp"]))
    assert (udp.severity, udp.counts) == ("info", False) and "UDP" in udp.why
    assert observation_transport(["SIP"]) == "possibly_udp" and observation_transport(["sip", "ssh"]) == "tcp"
    assert observation_transport(["ntp"], "tcp_handshake") == "tcp"
    shared = offseq_row(["203.0.113.10", "55836", "Example", "IN", "2026-11-04T05:00:00Z", "2026-11-23T22:00:00Z", "ssh", "cgnat;ssh-bruteforce", "", "false", "T1110", "3", "2", "12", "39"])
    assert honeypot_verdict(now=NOW, shared=shared["shared"]).severity == "low"
    for verdict in (honeypot_verdict(now=NOW), honeypot_verdict(now=NOW, anonymizer="tor")):
        assert "malicious" not in verdict.tags and "scanner" in verdict.tags


def test_honeydb_current_api_example_and_relays_are_display_only():
    doc = module_fixture(FIX, "honeydb_ip_docs_example.json")
    doc["threat_info"] = module_fixture(FIX, "honeydb_threatinfo_docs_example.json")["threat_info"]
    out = parse_honeydb_ip(doc, NOW)
    assert out["listed"] and out["services"] == ["sip"] and out["events"] == 12 and out["asn"] == 36352
    assert out["first_seen"] == "2025-08-07T00:00:00Z" and out["last_seen"] == "2025-11-09T00:00:00Z"
    assert "blocklist_de" in out["relayed_lists"] and "ipsum" in out["relayed_lists"]
    assert out["transport"] == "possibly_udp" and out["counts_for_verdict"] is False  # SIP may be UDP: never a verdict (c7)
    with pytest.raises(ValueError):
        parse_honeydb_ip({"unexpected": True}, NOW)


# --------------------------------------------------------------------------------------
# IPv4 runs
# --------------------------------------------------------------------------------------


def test_offseq_attacker_with_kev_cve_is_a_medium_scanner_sighting_with_pivots():
    http = offseq_routes()
    res = run_module(HoneypotIntel, "ipv4:23.132.164.50", http, allowed_sources=OFFSEQ_ONLY)
    assert res.status is Status.OK
    [finding] = low_or_more(res)
    assert finding.title == "Seen attacking honeypots (OffSeq Mirage)"
    assert finding.severity is Severity.MEDIUM and finding.tags == ["scanner"] and "malicious" not in finding.tags
    assert finding.criterion and finding.source == SRC_ATTACKERS and OFFSEQ_ATTRIBUTION in finding.description
    assert finding.observed_first.startswith("2026-11-06") and finding.observed_last.startswith("2026-11-25")
    pivots = {(p.entity.type.value, p.entity.value, p.relation) for p in res.pivots}
    assert ("asn", "AS401626", "belongs_to_asn") in pivots
    assert ("cve", "CVE-2017-9841", "attempted_exploit") in pivots  # never has_vuln (c6)
    assert ("mitre_technique", "T1190", "observed_technique") in pivots
    assert not any(rel == "has_vuln" for _t, _v, rel in pivots)
    attrs = res.attributes
    assert attrs["is_scanner"] is True and attrs["asn"] == "AS401626" and attrs["source_confidence"] == 93
    assert attrs["honeypot_sightings"][0]["kev"] is True
    assert attrs["honeypot_sightings"][0]["services"] == ["http", "ssh"]
    # the services the address attacked are never written as services the host offers (attack-surface rules)
    assert "services" not in attrs and "scanner_classification" not in attrs
    assert res.source_statuses[SRC_ATTACKERS]["status"] == "ok" and res.source_statuses[SRC_SCANNERS]["status"] == "empty"
    assert {d["name"] for d in res.datasets} >= {ATTACKERS, KNOWN_SCANNERS, ANONYMIZERS}  # citations (attribution in reports)
    http.assert_hosts_within(HoneypotIntel, extra=("feeds.offseq.com",))


def test_known_research_scanner_is_benign_never_malicious_and_feeds_the_noise_hook():
    http = offseq_routes()
    res = run_module(HoneypotIntel, "ipv4:65.49.1.10", http, allowed_sources=OFFSEQ_ONLY)
    assert res.status is Status.OK
    [finding] = res.findings
    assert finding.title == "Known research scanner (benign)" and finding.severity is Severity.INFO
    assert "benign_scanner" in finding.tags and "malicious" not in finding.tags and not res.pivots
    # c2: the noise-provider hook reads the local copy the run just installed (never a download)
    assert mod.noise_kind_for("65.49.1.10") == "benign_scanner"
    assert mod.noise_kind_for("23.132.164.50") is None and mod.noise_kind_for("not an ip") is None
    assert noise.errors() == []  # no runtime list left behind (the registry contract test requires it)


def test_known_scanner_reaches_the_p171_benign_suppression():
    """c2: the benign-scanner finding is context_only (never evidence), so the module also writes
    scanner_classification 'benign', which CR27 reads to downgrade a consensus (SUP-benign_scanner)."""
    res = run_module(HoneypotIntel, "ipv4:65.49.1.10", offseq_routes(), allowed_sources=OFFSEQ_ONLY)
    assert res.attributes["scanner_classification"] == "benign"
    g = Graph(noise_check=False)
    node, _ = g.add_node(res.entity, 0, seed=True)
    g.add_attributes(res.entity, res.attributes, HoneypotIntel.name)
    for f in res.findings:
        g.add_finding(f)
    rule, _why = threat_intel._cr27_downgrade(node)
    assert rule == "SUP-benign_scanner"


def test_noise_hook_is_silent_without_a_local_copy():
    assert mod.noise_kind_for("65.49.1.10") is None


def test_tor_exit_attacker_is_low_anonymizer_context():
    res = run_module(HoneypotIntel, "ipv4:5.2.69.84", offseq_routes(), allowed_sources=OFFSEQ_ONLY)
    [finding] = low_or_more(res)
    assert finding.severity is Severity.LOW and {"scanner", "anonymizer", "tor"} <= set(finding.tags)
    assert res.source_statuses[SRC_ANONYMIZERS]["status"] == "ok"


def test_reconnaissance_only_is_low():
    res = run_module(HoneypotIntel, "ipv4:45.133.18.54", offseq_routes(), allowed_sources=OFFSEQ_ONLY)
    [finding] = low_or_more(res)
    assert finding.severity is Severity.LOW and "reconnaissance only" in finding.description


def test_not_seen_by_honeypots_is_empty():
    res = run_module(HoneypotIntel, "ipv4:8.8.4.4", offseq_routes(), allowed_sources=OFFSEQ_ONLY)
    assert res.status is Status.EMPTY and not res.findings


def test_feed_failures_are_could_not_verify_never_empty():
    page = "<!DOCTYPE html><html><head><title>Just a moment...</title></head><body>cf-chl-widget</body></html>"
    http = FakeHttp()
    for path in ("attackers-7d.csv", "known-scanners-ipv4.txt", "anonymizers-7d.txt"):
        http.add("GET", BASE + path, status=503, text="unavailable")
    res = run_module(HoneypotIntel, "ipv4:23.132.164.50", http, allowed_sources=OFFSEQ_ONLY)
    assert res.status.could_not_verify and "could not verify" in res.error
    http2 = FakeHttp()
    http2.add("GET", BASE + "attackers-7d.csv", status=403, text=page)
    http2.add("GET", BASE + "known-scanners-ipv4.txt", body=text("offseq_known_scanners_ok.txt").encode())
    http2.add("GET", BASE + "anonymizers-7d.txt", body=text("offseq_anonymizers_ok.txt").encode())
    res2 = run_module(HoneypotIntel, "ipv4:23.132.164.50", http2, allowed_sources=OFFSEQ_ONLY)
    # a challenge short-circuits feeds.offseq.com for the run (A9): every file is could-not-verify, never EMPTY
    assert res2.status is Status.BLOCKED and res2.source_statuses[SRC_ATTACKERS]["status"] == "blocked"
    assert {row["status"] for row in res2.source_statuses.values()} == {"blocked"}


def test_private_addresses_are_not_applicable():
    assert run_module(HoneypotIntel, "ipv4:192.168.1.10", FakeHttp()).reason_code == "not_applicable"


# --------------------------------------------------------------------------------------
# HoneyDB adapter (c5, c7)
# --------------------------------------------------------------------------------------


def honeydb_route(http: FakeHttp, ip: str, **kw) -> None:
    http.add("GET", HONEYDB.format(ip=ip), match_headers={"X-HoneyDb-ApiId": KEYS["honeydb_api_id"], "X-HoneyDb-ApiKey": KEYS["honeydb_api_key"]}, **kw)


def test_honeydb_without_keys_is_needs_key_and_offseq_still_answers():
    res = run_module(HoneypotIntel, "ipv4:23.132.164.50", offseq_routes())
    assert res.source_statuses[SRC_HONEYDB]["status"] == "needs_key"
    assert res.status is Status.OK and low_or_more(res)


def test_honeydb_udp_only_sighting_is_context_and_never_a_verdict():
    http = offseq_routes()
    honeydb_route(http, "8.8.4.4", json=module_fixture(FIX, "honeydb_udp_only_synthetic.json"))
    res = run_module(HoneypotIntel, "ipv4:8.8.4.4", http, keys=KEYS)
    [finding] = res.findings
    assert finding.title == "Seen by HoneyDB honeypots" and finding.severity is Severity.INFO
    assert "UDP-derived" in finding.description and "context_only" in finding.tags
    assert not res.pivots
    assert_no_secret(KEYS["honeydb_api_key"], res.to_dict(), res.raw)
    http.assert_hosts_within(HoneypotIntel, extra=("feeds.offseq.com",))


def test_honeydb_tcp_sighting_with_cves_counts_and_pivots():
    doc = module_fixture(FIX, "honeydb_ip_docs_example.json")
    for item in doc["ip_history"]:
        item["service"] = "SSH"
        item["date"] = "2026-11-20"
    doc["cve"] = [{"cve": "CVE-2024-24919"}]
    doc["threat_info"] = module_fixture(FIX, "honeydb_threatinfo_docs_example.json")["threat_info"]
    http = offseq_routes()
    honeydb_route(http, "8.8.4.4", json=doc)
    res = run_module(HoneypotIntel, "ipv4:8.8.4.4", http, keys=KEYS)
    [finding] = low_or_more(res)
    assert finding.source == SRC_HONEYDB and finding.severity is Severity.MEDIUM and finding.tags == ["scanner"]
    assert ("cve", "CVE-2024-24919", "attempted_exploit") in {(p.entity.type.value, p.entity.value, p.relation) for p in res.pivots}
    assert "blocklist_de" in res.attributes["honeypot_relayed_lists"]  # display only, never a HoneyDB vote


def test_honeydb_internet_scanner_is_benign_and_classified_for_p171():
    doc = module_fixture(FIX, "honeydb_ip_docs_example.json")
    doc["internet_scanner"] = True
    http = offseq_routes()
    honeydb_route(http, "8.8.4.4", json=doc)
    res = run_module(HoneypotIntel, "ipv4:8.8.4.4", http, keys=KEYS)
    [finding] = [f for f in res.findings if f.source == SRC_HONEYDB]
    assert finding.title == "Known internet scanner (HoneyDB, benign)" and finding.severity is Severity.INFO
    assert "benign_scanner" in finding.tags and "malicious" not in finding.tags and not res.pivots
    assert res.attributes["scanner_classification"] == "benign"


@pytest.mark.parametrize(("status", "fixture", "expected"), [
    (401, "honeydb_needs_key_401.json", "needs_key"),
    (410, "honeydb_deprecated_410.json", "error"),
    (429, None, "rate_limited"),
])
def test_honeydb_failures_are_per_source_could_not_verify(status, fixture, expected):
    http = offseq_routes()
    kw = {"json": module_fixture(FIX, fixture)} if fixture else {"text": "slow down"}
    honeydb_route(http, "23.132.164.50", status=status, **kw)
    res = run_module(HoneypotIntel, "ipv4:23.132.164.50", http, keys=KEYS)
    row = res.source_statuses[SRC_HONEYDB]
    assert row["status"] == expected
    if status == 410:
        assert "endpoint removed" in row["reason"]
    assert res.status is Status.OK  # OffSeq answered


# --------------------------------------------------------------------------------------
# CVE and AS entities (local index)
# --------------------------------------------------------------------------------------


def test_cve_exploitation_attempts_from_the_local_index():
    res = run_module(HoneypotIntel, "cve:CVE-2017-9841", offseq_routes())
    assert res.status is Status.OK
    activity = res.attributes["honeypot_cve_activity"]
    assert (activity["source_ips"], activity["kev"], activity["window"]) == (1, True, "7d")
    assert res.attributes["exploited_in_wild"] is True
    [finding] = res.findings
    assert finding.severity is Severity.LOW and "kev" in finding.tags and finding.criterion
    assert res.source_statuses[SRC_HONEYDB]["status"] == "skipped"  # IPv4 only
    assert run_module(HoneypotIntel, "cve:CVE-2021-44228", offseq_routes()).status is Status.EMPTY


def test_asn_activity_is_context_only():
    res = run_module(HoneypotIntel, "asn:AS60404", offseq_routes())
    activity = res.attributes["honeypot_asn_activity"]
    assert activity["ips"] == 3 and "web-exploit" in activity["tags"]
    [finding] = res.findings
    assert finding.severity is Severity.INFO and "context_only" in finding.tags
