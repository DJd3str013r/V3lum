"""Unit tests of the batch p2-G02-3 correlation rule g02_scanner_intel_dampening (P148 c5-c7) on its graph
fixtures in tests/fixtures/rules/g02_scanner_intel_dampening/."""

from __future__ import annotations

from tests.fakes import graph_fixture
from v3lum.core.models import Severity
from v3lum.correlations.p2_g02_3 import RULE_ID, scanner_intel_dampening

BASE = f"rules/{RULE_ID}/"


def _run(name: str):
    graph, results, _ = graph_fixture(BASE + name)
    return graph, list(scanner_intel_dampening(graph, results))


def test_riot_caps_blocklist_listings_of_the_ip_and_keeps_specific_evidence():
    graph, corrs = _run("positive_riot_caps_blocklist_listing.json")
    node = graph.get("ipv4:8.8.8.8")
    by_module = {f.module: f for f in node.findings}
    blocklist, dshield, c2 = by_module["ip_blocklists"], by_module["isc_dshield"], by_module["c2_tracker"]
    assert blocklist.severity is Severity.LOW and blocklist.data["severity_before_dampening"] == "medium"
    assert [s["rule"] for s in blocklist.suppressed_by] == ["greynoise_riot"] and blocklist.confidence_label.value == "possible"
    assert dshield.severity is Severity.LOW and dshield.suppressed_by[0]["rule"] == "greynoise_riot"
    assert c2.severity is Severity.HIGH and not c2.suppressed_by  # specific evidence is never dampened
    assert len(node.findings) == 4  # nothing deleted
    [corr] = corrs
    assert corr.severity is Severity.INFO and blocklist.id in corr.evidence and corr.entities[0].key == "ipv4:8.8.8.8"
    # applied once per finding: a second pass changes nothing
    assert list(scanner_intel_dampening(graph, [])) == [] and len(blocklist.suppressed_by) == 1


def test_benign_scanner_rule_name():
    graph, corrs = _run("positive_benign_scanner_caps_scanner_listing.json")
    listing = next(f for f in graph.get("ipv4:198.51.100.23").findings if f.module == "ip_blocklists")
    assert listing.severity is Severity.LOW and listing.suppressed_by[0]["rule"] == "greynoise_benign_scanner"
    assert corrs and "greynoise_benign_scanner" in corrs[0].criterion


def test_domains_hosted_on_a_riot_ip_keep_their_verdicts():
    graph, corrs = _run("negative_domain_on_riot_ip_untouched.json")
    [dom] = graph.get("domain:dns.example.com").findings
    assert dom.severity is Severity.MEDIUM and not dom.suppressed_by and corrs == []


def test_greynoise_malicious_scanning_blocks_the_dampening():
    graph, corrs = _run("negative_greynoise_malicious_conflict.json")
    listing = next(f for f in graph.get("ipv4:203.0.113.66").findings if f.module == "ip_blocklists")
    assert listing.severity is Severity.MEDIUM and not listing.suppressed_by and corrs == []


def test_analyst_override_is_never_crossed():
    graph, results, _ = graph_fixture(BASE + "positive_riot_caps_blocklist_listing.json")
    listing = next(f for f in graph.get("ipv4:8.8.8.8").findings if f.module == "ip_blocklists")
    listing.apply_override(label="confirmed", severity="medium", verdict="true_positive", analyst="soc", note="confirmed abuse", at="2026-11-26T12:00:00Z")
    list(scanner_intel_dampening(graph, results))
    assert listing.severity is Severity.MEDIUM and listing.suppressed_by[-1].get("blocked_by") == "analyst"
