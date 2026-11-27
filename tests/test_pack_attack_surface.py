"""Attack-surface pack (P291: CR07, CR08, CR13-CR16, CR25, CR26, CR31 and the exploitable_exposure
alias): one test per final condition beyond the graph fixtures run by tests/test_rule_fixtures.py."""

from __future__ import annotations

import datetime as dt
import json
from pathlib import Path

import pytest

from v3lum.core import correlate
from v3lum.core.context import ScanOptions
from v3lum.core.correlate import RuleContext, load_graph_fixture, run_rules
from v3lum.core.entities import Entity
from v3lum.core.graph import Graph
from v3lum.core.models import Confidence, Finding, Opsec, Severity
from v3lum.core.orgprofile import OrgProfile
from v3lum.correlations import attack_surface as asp

NOW = dt.datetime(2026, 11, 26, 12, 0, tzinfo=dt.timezone.utc)
ROOT = Path(__file__).resolve().parent.parent
FIXTURES = Path(__file__).parent / "fixtures" / "rules"
ORG = OrgProfile.from_dict({
    "org": {"name": "Acme"},
    "domains": [
        {"name": "acme-corp.example", "verification": "txt_verified"},
        {"name": "acme-saas.example", "verification": "confirmed", "third_party_hosted": True},
    ],
    "cidrs": [{"value": "203.0.113.0/24"}],
})
PACK_RULES = (
    "subdomain_takeover_candidate", "dangling_cloud_ip", "exposed_remote_admin", "exposed_database_or_cache",
    "known_exploited_vuln_on_asset", "outdated_version_disclosed", "stale_host", "shadow_it_outlier",
    "certificate_san_affiliate", "exploitable_exposure",
)
SCOPE = {"authorization_ref": "PT-2026-001", "targets": {"domains": ["partner-lab.example"], "cidrs": ["198.51.100.0/24"]}}


def rctx(org=ORG, **kw) -> RuleContext:
    return RuleContext(now=NOW, org=org, **kw)


def run(g: Graph, rule_id: str, **kw):
    return run_rules(g, [], only={rule_id}, rctx=rctx(**kw))


def add(g: Graph, etype: str, value: str, *, depth: int = 0, seed: bool = True, **attrs):
    node, _ = g.add_node(Entity.make(etype, value), depth, seed=seed)
    for name, value_ in attrs.items():
        source = "fixture"
        if isinstance(value_, tuple):
            value_, source = value_
        node.attributes.setdefault(name, []).append((value_, source))
    return node


def cve_node(g: Graph, cve: str, **attrs):
    return add(g, "cve", cve, depth=1, seed=False, **attrs)


def link(g: Graph, src, dst, relation: str, module: str = "fixture", confidence: float = 0.9):
    g.add_edge(src.entity, dst.entity, relation, module, confidence)


# ------------------------------------------------------------------ registration and data
def test_rules_are_registered_and_the_alias_supersedes_the_legacy_rule():
    correlate.load_rules()
    codes = {rid: correlate.RULES[rid].code for rid in PACK_RULES}
    assert codes["subdomain_takeover_candidate"] == "CR07" and codes["certificate_san_affiliate"] == "CR31"
    info = correlate.RULES["exploitable_exposure"]
    assert info.origin.startswith("v3lum.correlations.attack_surface.") and not info.legacy
    for rid in PACK_RULES:
        rinfo = correlate.RULES[rid]
        assert rinfo.takes_context and rinfo.criterion and rinfo.attack and rinfo.references and rinfo.false_positives
        assert rid not in correlate.RULE_ERRORS


def test_takeover_fingerprint_list_is_pinned_and_attributed():
    doc = json.loads(asp.TAKEOVER_FILE.read_text(encoding="utf-8"))
    assert doc["schema"] == asp.TAKEOVER_SCHEMA and doc["licence"] == "CC-BY-4.0" and len(doc["commit"]) == 40
    assert "can-i-take-over-xyz" in doc["attribution"] and doc["upstream_sha256"]
    notice = json.loads((ROOT / "v3lum" / "data" / "notices" / "can_i_take_over_xyz.json").read_text(encoding="utf-8"))
    assert notice["licence"] == "CC-BY-4.0" and doc["commit"] in notice["version"] and "v3lum/data/takeover_fingerprints.json" in notice["files"]
    assert any(e["vulnerable"] for e in doc["entries"]) and any(not e["vulnerable"] for e in doc["entries"])
    # label-wise suffix matching, never a substring
    assert [e["service"] for e in asp.vulnerable_services("acme.azurewebsites.net")] == ["Microsoft Azure"]
    assert asp.vulnerable_services("acme.notazurewebsites.net") == []
    assert asp.vulnerable_services("acme-lb.elb.amazonaws.com") == []  # listed 'Not vulnerable'


# ------------------------------------------------------------------ CR07 (cond 6)
def _takeover_graph(target: str, **target_attrs):
    g = Graph(noise_check=False)
    sub = add(g, "domain", "app.acme-corp.example")
    sub.ownership = "own_asset"
    tgt = add(g, "domain", target, depth=1, seed=False, **target_attrs)
    link(g, sub, tgt, "cname_to", "dns_records")
    return g, sub, tgt


def test_takeover_needs_a_vulnerable_service_and_confirmed_dangling_evidence():
    g, sub, _ = _takeover_graph("acme-app.azurewebsites.net")
    assert run(g, "subdomain_takeover_candidate") == []  # vulnerable service, no dangling evidence
    sub.attributes["cname_dangling"] = [({"target": "acme-app.azurewebsites.net", "status": "NXDOMAIN", "confirmed": False}, "ct_logs")]
    assert run(g, "subdomain_takeover_candidate") == []  # unconfirmed NXDOMAIN is not evidence
    sub.attributes["cname_dangling"] = [({"target": "acme-app.azurewebsites.net", "status": "NXDOMAIN", "confirmed": True}, "ct_logs")]
    [corr] = run(g, "subdomain_takeover_candidate")
    assert corr.severity is Severity.HIGH and "candidate" in corr.title and "candidate" in corr.criterion
    assert "never claims" in corr.description and "Never claim" in corr.recommendation
    assert corr.attack == ["T1584.001"]


def test_nxdomain_services_ignore_content_fingerprints_and_content_services_accept_them():
    g, sub, _ = _takeover_graph("acme-app.azurewebsites.net")
    sub.attributes["takeover_fingerprint"] = [({"service": "Microsoft Azure", "fingerprint": "x"}, "takeover_check")]
    assert run(g, "subdomain_takeover_candidate") == []  # Azure entries need NXDOMAIN
    g2, sub2, _ = _takeover_graph("acme-files.s3.amazonaws.com")
    sub2.attributes["takeover_fingerprint"] = [({"service": "AWS/S3", "fingerprint": "The specified bucket does not exist"}, "takeover_check")]
    [corr] = run(g2, "subdomain_takeover_candidate")
    assert "AWS/S3" in corr.title and "unclaimed-resource fingerprint" in corr.description


def test_takeover_candidates_outside_the_profile_are_third_party_and_lower():
    g = Graph(noise_check=False)
    pivot = add(g, "domain", "app.vendor.example", depth=1, seed=False, cname_dangling=({"status": "NXDOMAIN", "confirmed": True}, "ct_logs"))
    tgt = add(g, "domain", "vendor-app.azurewebsites.net", depth=2, seed=False)
    link(g, pivot, tgt, "cname_to")
    [corr] = run(g, "subdomain_takeover_candidate")
    assert corr.severity is Severity.LOW and "third_party" in corr.tags


# ------------------------------------------------------------------ CR08 (cond 7)
def test_dangling_cloud_ip_is_possible_unless_the_evidence_is_strong():
    g = Graph(noise_check=False)
    dom = add(g, "domain", "app.acme-corp.example")
    ip = add(g, "ipv4", "198.51.100.90", depth=1, seed=False, cloud_service=("EC2", "cloud_ranges"), cert_sans=(["other-org.example"], "shodan_api"))
    link(g, dom, ip, "resolves_to", "dns_records")
    [weak] = run(g, "dangling_cloud_ip")
    assert weak.label is Confidence.POSSIBLE and weak.severity is Severity.MEDIUM and "re-acquire" in weak.recommendation
    ip.attributes["internetdb_status"] = [("not seen by Shodan scanners", "shodan_internetdb")]
    [strong] = run(g, "dangling_cloud_ip")
    assert strong.label is Confidence.PROBABLE and strong.severity is Severity.HIGH
    ip.attributes["cert_sans"].append((["app.acme-corp.example"], "shodan_api"))
    assert run(g, "dangling_cloud_ip") == []  # the address still serves the name


# ------------------------------------------------------------------ ownership scoping (cond 5, 10)
@pytest.mark.parametrize(("value", "options", "expected"), [
    ("203.0.113.5", None, Severity.HIGH),  # own CIDR
    ("198.51.100.5", ScanOptions(scope=SCOPE), Severity.HIGH),  # ACTIVE-scope target
    ("192.0.2.5", None, Severity.INFO),  # third party
])
def test_exposure_severity_only_for_own_or_in_scope_assets(value, options, expected):
    g = Graph(noise_check=False)
    add(g, "ipv4", value, open_ports=([3389], "shodan_api"), last_seen=("2026-11-25", "shodan_api"))
    [corr] = run(g, "exposed_remote_admin", options=options)
    assert corr.severity is expected
    assert ("third_party" in corr.tags) is (expected is Severity.INFO)


def test_hostile_hosts_get_info_pivots():
    g = Graph(noise_check=False)
    node = add(g, "ipv4", "192.0.2.66", open_ports=([6379, 3389], "shodan_api"))
    g.add_finding(Finding(title="C2", severity=Severity.HIGH, criterion="feed", tags=["c2", "malicious"], entity=node.entity, module="abusech", source="abusech.threatfox"))
    for rid in ("exposed_remote_admin", "exposed_database_or_cache"):
        [corr] = run(g, rid)
        assert corr.severity is Severity.INFO and "infrastructure" in corr.tags and "never probe" in corr.description
        assert "third_party" in corr.tags  # outside the org profile: never verified automatically (cond 10)


def test_an_own_host_listed_as_malicious_is_a_compromised_asset_not_hostile_infrastructure():
    """Cond 5 orders ownership first: an org-profile asset a feed lists as malicious keeps the severity
    of its exposures (possibly compromised) instead of becoming an INFO infrastructure pivot."""
    g = Graph(noise_check=False)
    node = add(g, "ipv4", "203.0.113.6", open_ports=([6379, 3389], "shodan_api"), last_seen=("2026-11-25", "shodan_api"))
    g.add_finding(Finding(title="C2", severity=Severity.HIGH, criterion="feed", tags=["c2", "malicious"], entity=node.entity, module="abusech", source="abusech.threatfox"))
    for rid in ("exposed_remote_admin", "exposed_database_or_cache"):
        [corr] = run(g, rid)
        assert corr.severity is Severity.HIGH and "own_asset" in corr.tags and "infrastructure" not in corr.tags
        assert any("possibly compromised" in line for line in corr.evidence)
    dom = add(g, "domain", "app.acme-corp.example")
    ip = add(g, "ipv4", "192.0.2.67", depth=1, seed=False, open_ports=([3389], "shodan_api"), last_seen=("2026-11-25", "shodan_api"))
    link(g, dom, ip, "resolves_to", "dns_records")
    g.add_finding(Finding(title="listed", severity=Severity.HIGH, criterion="feed", tags=["malicious"], entity=ip.entity, module="abusech", source="abusech.urlhaus"))
    sev = {c.entity_keys()[0]: c.severity for c in run(g, "exposed_remote_admin")}
    assert sev[ip.key] is Severity.HIGH  # the address of an own domain is own, even when a feed lists it


def test_an_address_of_an_own_domain_is_own_unless_shared_cnamed_or_third_party_hosted():
    g = Graph(noise_check=False)
    dom = add(g, "domain", "db.acme-corp.example")
    ip = add(g, "ipv4", "192.0.2.30", depth=1, seed=False, open_ports=([6379], "shodan_api"), last_seen=("2026-11-25", "shodan_api"))
    link(g, dom, ip, "resolves_to", "dns_records")
    [corr] = run(g, "exposed_database_or_cache")
    assert corr.severity is Severity.HIGH and "address of the own domain db.acme-corp.example" in " ".join(corr.evidence)
    ip.attributes["shared_ip"] = [(True, "shodan_internetdb")]
    assert run(g, "exposed_database_or_cache")[0].severity is Severity.INFO
    del ip.attributes["shared_ip"]
    other = add(g, "domain", "db.acme-saas.example")  # entry flagged third_party_hosted
    ip2 = add(g, "ipv4", "192.0.2.31", depth=1, seed=False, open_ports=([6379], "shodan_api"))
    link(g, other, ip2, "resolves_to", "dns_records")
    sev = {c.entity_keys()[0]: c.severity for c in run(g, "exposed_database_or_cache")}
    assert sev == {ip.key: Severity.HIGH, ip2.key: Severity.INFO}
    tgt = add(g, "domain", "acme.cdn-provider.example", depth=1, seed=False)
    link(g, dom, tgt, "cname_to", "dns_records")  # a CNAME'd name resolves to its provider's address
    assert run(g, "exposed_database_or_cache")[0].severity is Severity.INFO


# ------------------------------------------------------------------ observation date (cond 8)
@pytest.mark.parametrize(("last_seen", "label"), [("2026-11-20", Confidence.PROBABLE), ("2026-10-01", Confidence.POSSIBLE), (None, Confidence.POSSIBLE)])
def test_exposure_carries_the_observation_date_and_old_data_lowers_confidence(last_seen, label):
    g = Graph(noise_check=False)
    attrs = {"open_ports": ([27017], "shodan_api")}
    if last_seen:
        attrs["last_seen"] = (last_seen, "shodan_api")
    add(g, "ipv4", "203.0.113.7", **attrs)
    [corr] = run(g, "exposed_database_or_cache")
    assert corr.label is label
    assert (f"observed {last_seen}" if last_seen else "observation date unknown") in corr.description


def test_an_authorized_active_check_is_confirmed(monkeypatch):
    class _Active:
        opsec = Opsec.ACTIVE
        sources = ()

    from v3lum.core import module as module_registry

    monkeypatch.setitem(module_registry.REGISTRY, "t_port_scan", _Active)
    g = Graph(noise_check=False)
    add(g, "ipv4", "203.0.113.8", open_ports=([5900], "t_port_scan"), last_seen=("2026-11-25", "t_port_scan"))
    [corr] = run(g, "exposed_remote_admin")
    assert corr.label is Confidence.CONFIRMED


# ------------------------------------------------------------------ CR15 caps (cond 3)
@pytest.mark.parametrize(("kev", "epss", "cvss", "verified", "owner", "expected"), [
    (True, None, 7.5, True, "own", Severity.CRITICAL),
    (False, 0.6, 7.5, True, "own", Severity.CRITICAL),  # EPSS >= 0.5
    (True, None, 7.5, True, "third_party", Severity.INFO),
    (False, 0.1, 9.8, True, "own", Severity.HIGH),  # CVSS >= 9 alone never CRITICAL
    (True, None, 9.8, False, "own", None),  # version-inferred: CR16, not CR15
    (False, 0.1, 6.0, True, "own", None),  # neither exploited nor critical
])
def test_cr15_critical_needs_exploitation_verification_and_ownership(kev, epss, cvss, verified, owner, expected):
    g = Graph(noise_check=False)
    host = add(g, "ipv4", "203.0.113.9" if owner == "own" else "192.0.2.9")
    attrs = {"cvss": (cvss, "cve_record")}
    if kev:
        attrs["kev"] = (True, "cisa_kev")
    if epss is not None:
        attrs["epss"] = (epss, "epss")
    cve = cve_node(g, "CVE-2099-50001", **attrs)
    link(g, host, cve, "has_vuln", "shodan_api", 0.5)
    if verified:
        host.attributes["vulns_verified"] = [(["CVE-2099-50001"], "shodan_api")]
    out = run(g, "known_exploited_vuln_on_asset")
    assert [c.severity for c in out] == ([expected] if expected is not None else [])


def test_cve_specific_evidence_and_active_checks_verify(monkeypatch):
    g = Graph(noise_check=False)
    host = add(g, "ipv4", "203.0.113.20")
    cve = cve_node(g, "CVE-2099-50002", kev=(True, "cisa_kev"))
    link(g, host, cve, "has_vuln", "nuclei_safe", 0.9)
    g.add_finding(Finding(title="Vulnerable endpoint matched", severity=Severity.HIGH, criterion="CVE-specific response", tags=["vulnerable"],
                          entity=host.entity, module="nuclei_safe", data={"cve": "CVE-2099-50002"}))
    [corr] = run(g, "known_exploited_vuln_on_asset")
    assert corr.severity is Severity.CRITICAL and "CVE-specific evidence" in corr.description and corr.label is Confidence.PROBABLE

    class _Active:
        opsec = Opsec.ACTIVE
        sources = ()

    from v3lum.core import module as module_registry

    monkeypatch.setitem(module_registry.REGISTRY, "nuclei_safe", _Active)
    [confirmed] = run(g, "known_exploited_vuln_on_asset")
    assert "authorized ACTIVE check" in confirmed.description and confirmed.label is Confidence.CONFIRMED


# ------------------------------------------------------------------ CR16 caps and grouping (cond 4, 11)
def test_version_inferred_cves_give_one_finding_per_host_and_product():
    g = Graph(noise_check=False)
    host = add(g, "ipv4", "203.0.113.21", cpes=(["cpe:/a:f5:nginx:1.18.0", "cpe:/a:openbsd:openssh:8.2"], "shodan_internetdb"))
    specs = [
        ("CVE-2099-60001", "f5", "nginx", {"kev": (True, "cisa_kev")}),
        ("CVE-2099-60002", "f5", "nginx", {"cvss": (9.8, "cve_record")}),
        ("CVE-2099-60003", "openbsd", "openssh", {"cvss": (7.5, "cve_record")}),
        ("CVE-2099-60004", "openbsd", "openssh", {"cvss": (5.0, "cve_record")}),
    ]
    for cve_id, vendor, product, attrs in specs:
        cve = cve_node(g, cve_id, affected=([{"vendor": vendor, "product": product}], "cve_record"), **attrs)
        link(g, host, cve, "has_vuln", "shodan_internetdb", 0.5)
    out = {c.key: c for c in run(g, "outdated_version_disclosed")}
    assert set(out) == {"f5:nginx", "openbsd:openssh"}
    assert out["f5:nginx"].severity is Severity.HIGH and out["openbsd:openssh"].severity is Severity.MEDIUM  # caps: KEV -> HIGH, else MEDIUM
    for corr in out.values():
        assert corr.label is Confidence.POSSIBLE and asp.VERSION_LABEL in corr.description and "version_inferred" in corr.tags


def test_nginx_regression_gives_one_high_possible_not_twenty_criticals():
    fx = load_graph_fixture(FIXTURES / "outdated_version_disclosed" / "positive_nginx_20_cves_one_kev.json")
    every = run_rules(fx.graph, fx.results, only=set(PACK_RULES), rctx=fx.rctx)
    assert not [c for c in every if c.severity is Severity.CRITICAL]
    cr16 = [c for c in every if c.rule == "outdated_version_disclosed"]
    assert len(cr16) == 1 and cr16[0].severity is Severity.HIGH and cr16[0].label is Confidence.POSSIBLE
    assert "20 version-inferred CVE(s), KEV: 1" in cr16[0].title


def test_alias_applies_the_cr15_cr16_caps():
    g = Graph(noise_check=False)
    host = add(g, "ipv4", "203.0.113.22", vulns=(["CVE-2099-70001"], "shodan_internetdb"))
    cve_node(g, "CVE-2099-70001", kev=(True, "cisa_kev"))
    [inferred] = run(g, "exploitable_exposure")
    assert inferred.severity is Severity.HIGH and inferred.label is Confidence.POSSIBLE
    host.attributes["vulns_verified"] = [(["CVE-2099-70001"], "shodan_api")]
    [verified] = run(g, "exploitable_exposure")
    assert verified.severity is Severity.CRITICAL
    assert run(g, "exploitable_exposure", org=None)[0].severity is Severity.INFO  # no profile: not an own asset


# ------------------------------------------------------------------ KEV/EPSS through core/datasets (cond 2)
def test_local_kev_and_epss_copies_fill_missing_facts(monkeypatch, tmp_path):
    kev = tmp_path / "cisa_kev"
    kev.write_text(json.dumps({"vulnerabilities": [{"cveID": "CVE-2099-80001"}]}), encoding="utf-8")
    epss = tmp_path / "epss_scores"
    epss.write_text("#model_version:v2099.01.01,score_date:2099-01-01\ncve,epss,percentile\nCVE-2099-80002,0.73,0.99\n", encoding="utf-8")
    monkeypatch.setattr(asp, "_dataset_path", lambda name: {asp.KEV_DATASET: kev, asp.EPSS_DATASET: epss}.get(name))
    g = Graph(noise_check=False)
    host = add(g, "ipv4", "203.0.113.23", vulns=(["CVE-2099-80001", "CVE-2099-80002", "CVE-2099-80003"], "shodan_internetdb"))
    vulns = asp.host_vulns(g, host)
    assert vulns["CVE-2099-80001"].kev and not vulns["CVE-2099-80002"].kev
    assert vulns["CVE-2099-80002"].epss == pytest.approx(0.73) and vulns["CVE-2099-80003"].epss is None
    assert {v.cve for v in vulns.values() if v.hot} == {"CVE-2099-80001", "CVE-2099-80002"}


def test_the_local_epss_copy_is_read_once_per_graph_not_once_per_host(monkeypatch, tmp_path):
    """Performance (P301 cond 5: correlation < 2 s): the CVE rules look every CVE of the graph up
    in one pass over the (large) EPSS file instead of re-reading it for each host."""
    epss = tmp_path / "epss_scores"
    rows = "".join(f"CVE-2099-{90000 + i},0.{i + 1:02d},0.5\n" for i in range(30))
    epss.write_text("#model_version:v2099.01.01,score_date:2099-01-01\ncve,epss,percentile\n" + rows, encoding="utf-8")
    monkeypatch.setattr(asp, "_dataset_path", lambda name: epss if name == asp.EPSS_DATASET else None)
    opened: list[str] = []
    real_open = type(epss).open

    def counting_open(self, *a, **k):
        opened.append(self.name)
        return real_open(self, *a, **k)

    monkeypatch.setattr(type(epss), "open", counting_open)
    g = Graph(noise_check=False)
    for i in range(30):
        add(g, "ipv4", f"203.0.113.{100 + i}", vulns=([f"CVE-2099-{90000 + i}"], "shodan_internetdb"), cpes=(["cpe:/a:nginx:nginx:1.18.0"], "shodan_internetdb"))
    out = run_rules(g, [], only={"known_exploited_vuln_on_asset", "outdated_version_disclosed", "exploitable_exposure", "stale_host"}, rctx=rctx())
    assert opened.count("epss_scores") == 1
    assert sum(1 for c in out if c.rule == "outdated_version_disclosed") == 30


def test_per_cve_verified_flags_of_a_source_verify_inside_a_version_inferred_finding():
    """Cond 3 'the source marks it verified': shodan_api reports data['vulns'] items with
    verified_by_shodan; a verified KEV CVE on an own asset is CR15 CRITICAL, the unverified ones of
    the same finding stay version-inferred (CR16)."""
    g = Graph(noise_check=False)
    host = add(g, "ipv4", "203.0.113.40", cpes=(["cpe:/a:apache:http_server:2.4.49"], "shodan_api"))
    cve_node(g, "CVE-2099-70001", kev=(True, "cisa_kev"))
    cve_node(g, "CVE-2099-70002", kev=(True, "cisa_kev"))
    g.add_finding(Finding(
        title="CVEs by version match (version-inferred)", severity=Severity.HIGH, criterion="version match", entity=host.entity,
        module="shodan_api", source="shodan.host", tags=["vulnerable", "version_inferred"],
        data={"vulns": [{"cve": "CVE-2099-70001", "cvss": 9.8, "verified_by_shodan": True},
                        {"cve": "CVE-2099-70002", "cvss": 7.5, "verified_by_shodan": False}], "count": 2},
    ))
    vulns = asp.host_vulns(g, host)
    assert vulns["CVE-2099-70001"].verified == "source verified" and vulns["CVE-2099-70001"].cvss == pytest.approx(9.8)
    assert vulns["CVE-2099-70002"].verified == ""
    [cr15] = run(g, "known_exploited_vuln_on_asset")
    assert cr15.severity is Severity.CRITICAL and "CVE-2099-70001" in cr15.description and "CVE-2099-70002" not in cr15.description
    [cr16] = run(g, "outdated_version_disclosed")
    assert cr16.severity is Severity.HIGH and cr16.label is Confidence.POSSIBLE and "CVE-2099-70002" in cr16.description


# ------------------------------------------------------------------ CR25 (cond 8)
def test_stale_host_needs_three_signals_and_ignores_security_txt():
    g = Graph(noise_check=False)
    node = add(g, "domain", "old.acme-corp.example", eol_software=(True, "shodan_internetdb"), tls_self_signed=(True, "shodan_internetdb"),
               security_txt=({"present": False}, "wellknown_files"))
    assert run(g, "stale_host") == []
    node.attributes["expires"] = [("2026-12-10", "rdap")]  # registration expires within 30 days
    [corr] = run(g, "stale_host")
    assert corr.severity is Severity.MEDIUM and "security.txt" not in " ".join(corr.evidence[:-1])
    assert any("registration expires" in line for line in corr.evidence)


# ------------------------------------------------------------------ CR26 (cond 9)
def _estate(g: Graph, count: int):
    for i in range(count):
        add(g, "ipv4", f"203.0.113.{150 + i}", as_org=("Odd VPS" if i == 0 else "Acme Hosting", "asn_context"))


def test_shadow_it_outlier_threshold_is_a_setting():
    g = Graph(noise_check=False)
    _estate(g, 12)
    assert run(g, "shadow_it_outlier") == []  # default minimum 20 own assets
    from v3lum.config import Config

    cfg = Config()
    cfg.settings["attack_surface_min_assets"] = 10
    [corr] = run(g, "shadow_it_outlier", settings=cfg)
    assert corr.entity_keys() == ["ipv4:203.0.113.150"] and corr.severity is Severity.LOW
    assert "1 of 12 assets" in corr.description


# ------------------------------------------------------------------ CR31 and the scope (cond 10)
def test_san_affiliates_are_info_and_never_join_the_scope():
    g = Graph(noise_check=False)
    node = add(g, "domain", "acme-corp.example", cert_sans=(["acme-corp.example", "acme-labs.example", "acme-corp.example"], "ct_logs"))
    affiliate = add(g, "domain", "acme-labs.example", depth=1, seed=False)
    link(g, node, affiliate, "cert_san", "ct_logs", 0.5)
    options = ScanOptions(scope=dict(SCOPE))
    before_scope = json.dumps(options.scope, sort_keys=True)
    out = run_rules(g, [], only=set(PACK_RULES), rctx=rctx(options=options))
    [corr] = [c for c in out if c.rule == "certificate_san_affiliate"]
    assert corr.severity is Severity.INFO and "never added to the scope" in corr.description
    assert json.dumps(options.scope, sort_keys=True) == before_scope
    assert all("in_scope" not in n.tags for n in g.nodes.values())


# ------------------------------------------------------------------ acceptance: no network
def test_pack_rules_make_no_network_call(monkeypatch):
    import requests

    def refuse(*a, **k):
        raise AssertionError("a correlation rule tried to use the network")

    monkeypatch.setattr(requests.Session, "request", refuse)
    import socket  # below requests too: no socket, no name resolution

    monkeypatch.setattr(socket.socket, "connect", refuse)
    monkeypatch.setattr(socket, "create_connection", refuse)
    monkeypatch.setattr(socket, "getaddrinfo", refuse)
    for rid in PACK_RULES:
        for path in sorted((FIXTURES / rid).glob("*.json")):
            fx = load_graph_fixture(path)
            run_rules(fx.graph, fx.results, only=set(PACK_RULES), rctx=fx.rctx)
    assert not {rid: correlate.RULE_ERRORS[rid] for rid in PACK_RULES if rid in correlate.RULE_ERRORS}
