"""Threat-intel consensus pack (P171, CR27-CR30): one test per final condition beyond the graph fixtures.

The fixtures under tests/fixtures/rules/{multi_source_malicious,anonymized_infrastructure,
favicon_clone_cluster,jarm_matches_known_c2}/ run through tests/test_rule_fixtures.py; these tests
pin the semantics the fixtures cannot express (exact families, evidence lines, downgrade records,
licence handling, the legacy supersede and the 'no network' acceptance criterion).
"""

from __future__ import annotations

import datetime as dt
from pathlib import Path

import pytest

from tests.fakes import FakeHttp, make_runtime
from v3lum.core import correlate
from v3lum.core.correlate import RuleContext, load_graph_fixture, run_rules
from v3lum.core.entities import Entity
from v3lum.core.graph import Graph
from v3lum.core.models import Confidence, Finding, ModuleResult, Severity
from v3lum.core.orgprofile import OrgProfile
from v3lum.correlations import threat_intel as ti

NOW = dt.datetime(2026, 11, 26, 12, 0, tzinfo=dt.timezone.utc)
FIXTURES = Path(__file__).parent / "fixtures" / "rules"
PACK_RULES = ("multi_source_malicious", "anonymized_infrastructure", "favicon_clone_cluster", "jarm_matches_known_c2")


#: Feed sources these tests name that module batches register (provider fragments of the
#: ip_blocklists / phishing feed batches). Core tests never rely on batch data: when a source is
#: missing, the fixture below registers a synthetic one with the same family, embeds, terms class and
#: tier (what CR27 reads; the hosts are synthetic), and restores the registry afterwards.
_UPSTREAM_SOURCES: dict[str, dict] = {
    "spamhaus.drop_v4": {"tier": "trusted", "family": "spamhaus", "terms": "open"},
    "cinsscore.badguys": {"tier": "community", "family": "cins", "terms": "noncommercial"},
    "phishtank.online_valid": {"tier": "community", "family": "phishtank", "terms": "open"},
    "threatview.feeds": {"tier": "unknown", "family": "threatview", "terms": "unknown"},
    "github.ip_blocklists_ipsum": {
        "family": "ipsum", "terms": "open",
        "embeds": ["abuse.ch", "binarydefense", "blocklist.de", "cins", "dataplane", "dshield", "emergingthreats", "greensnow", "voipbl"],
    },
}


@pytest.fixture(autouse=True)
def upstream_sources():
    from tests.fakes import provider_fragment
    from v3lum.core import providers as providers_mod

    state = providers_mod.snapshot()
    reg = providers_mod.registry()
    try:
        for sid, spec in _UPSTREAM_SOURCES.items():
            if reg.source(sid) is not None:
                continue
            pid, short = sid.split(".", 1)
            source = {"upstream_family": spec["family"], "embeds": list(spec.get("embeds", ()))}
            if pid in reg:  # a core seed provider (github): add the source with an extension fragment
                frag = provider_fragment(pid, sources={short: source}, terms=spec["terms"])
                providers_mod.register(
                    {"schema": providers_mod.SCHEMA_EXTENSION, "extends": pid, "sources": frag["sources"]},
                    origin="tests/test_pack_threat_intel.py",
                )
            else:
                providers_mod.register(
                    provider_fragment(pid, hosts=[f"{pid}.feeds.example.test"], tier=spec["tier"], terms=spec["terms"], sources={short: source}),
                    origin="tests/test_pack_threat_intel.py",
                )
            reg = providers_mod.registry()
        yield
    finally:
        providers_mod.restore(state)


def rctx(**kw) -> RuleContext:
    return RuleContext(now=NOW, **kw)


def listing(entity: Entity, module: str, source: str, *, days_ago: float | None = 1, tags=("malicious",), data=None, **kw) -> Finding:
    last = (NOW - dt.timedelta(days=days_ago)).isoformat() if days_ago is not None else None
    return Finding(
        title=f"listed by {source or module}", severity=Severity.HIGH, criterion="feed listing", tags=list(tags), entity=entity,
        module=module, source=source, observed_last=last, data=dict(data or {}), **kw,
    )


def graph_with(entity: Entity, *findings: Finding, tags=(), noise_kind: str = "", attrs: dict | None = None) -> Graph:
    g = Graph(noise_check=False)
    node, _ = g.add_node(entity, 0, seed=True)
    node.tags.update(tags)
    if noise_kind:
        node.noise, node.noise_kind = True, noise_kind
    for f in findings:
        g.add_finding(f)
    for name, values in (attrs or {}).items():
        for value, src in values:
            node.attributes.setdefault(name, []).append((value, src))
    return g


def cr27(g: Graph, results=(), **kw):
    return run_rules(g, list(results), only={"multi_source_malicious"}, rctx=rctx(**kw))


IP = Entity.make("ipv4", "192.0.2.50")
DOMAIN = Entity.make("domain", "update-portal.example")


# ------------------------------------------------------------------ registration (cond 1)
def test_cr27_supersedes_the_legacy_rule_and_every_pack_rule_is_registered():
    correlate.load_rules()
    info = correlate.RULES["multi_source_malicious"]
    assert info.origin.startswith("v3lum.correlations.threat_intel.") and not info.legacy and info.code == "CR27"
    replaced = correlate.RULE_REPLACED.get("multi_source_malicious")
    assert replaced is None or replaced.origin.startswith("v3lum.correlations.generic.")
    codes = {rid: correlate.RULES[rid].code for rid in PACK_RULES}
    assert codes == {"multi_source_malicious": "CR27", "anonymized_infrastructure": "CR28", "favicon_clone_cluster": "CR29", "jarm_matches_known_c2": "CR30"}
    for rid in PACK_RULES:
        rinfo = correlate.RULES[rid]
        assert rinfo.takes_context and rinfo.criterion and rinfo.attack and rinfo.references and rinfo.false_positives
        assert rid not in correlate.RULE_ERRORS


# ------------------------------------------------------------------ independence: families, not modules (cond 2-3)
def test_feeds_of_one_upstream_count_once_and_dedup_is_recorded():
    g = graph_with(IP, listing(IP, "abusech", "abusech.urlhaus"), listing(IP, "ioc_feeds_offline", "abusech.threatfox"),
                   listing(IP, "ip_blocklists", "abusech.feodotracker"))
    [corr] = cr27(g)
    assert corr.severity is Severity.MEDIUM and "1 independent upstream family" in corr.title
    assert sum(line.startswith("deduplicated:") for line in corr.evidence) == 2
    assert any("family abuse.ch already counted" in line for line in corr.evidence)


def test_two_families_are_high_and_three_are_confirmed():
    g = graph_with(IP, listing(IP, "ip_blocklists", "spamhaus.drop_v4"), listing(IP, "abusech", "abusech.feodotracker"))
    [corr] = cr27(g)
    assert corr.severity is Severity.HIGH and corr.label is Confidence.PROBABLE and "malicious" in corr.tags
    g.add_finding(listing(IP, "ip_blocklists", "cinsscore.badguys"))
    [corr] = cr27(g)
    assert corr.severity is Severity.HIGH and corr.label is Confidence.CONFIRMED and "3 independent upstream families" in corr.title


def test_aggregates_count_as_the_families_they_embed():
    # FireHOL level1 embeds abuse.ch, dshield and Spamhaus: next to a direct abuse.ch vote it adds nothing
    g = graph_with(IP, listing(IP, "ip_blocklists", "abusech.feodotracker"), listing(IP, "ip_blocklists", "firehol.level1"))
    [corr] = cr27(g)
    assert corr.severity is Severity.MEDIUM
    assert any("firehol.level1" in line and "embeds abuse.ch" in line for line in corr.evidence)
    # next to a family it does not embed (CINS) the aggregate is an independent vote
    g2 = graph_with(IP, listing(IP, "ip_blocklists", "cinsscore.badguys"), listing(IP, "ip_blocklists", "firehol.level1"))
    [corr2] = cr27(g2)
    assert corr2.severity is Severity.HIGH and "firehol" in corr2.criterion and "cins" in corr2.criterion
    # two aggregates sharing an embedded family (FireHOL and IPsum both embed abuse.ch) count once
    g3 = graph_with(IP, listing(IP, "ip_blocklists", "firehol.level1"), listing(IP, "ip_blocklists", "github.ip_blocklists_ipsum"))
    [corr3] = cr27(g3)
    assert corr3.severity is Severity.MEDIUM and any("overlaps another counted aggregate" in line for line in corr3.evidence)


def test_otx_pulses_relaying_abusech_count_as_abusech():
    relay = listing(DOMAIN, "otx", "otx.indicators", data={"upstream_families": ["abuse.ch"]})
    g = graph_with(DOMAIN, relay, listing(DOMAIN, "abusech", "abusech.urlhaus"))
    [corr] = cr27(g)
    assert corr.severity is Severity.MEDIUM  # both are abuse.ch
    community = listing(DOMAIN, "otx", "otx.indicators", data={"upstream_families": ["otx"]})
    [corr2] = cr27(graph_with(DOMAIN, community, listing(DOMAIN, "abusech", "abusech.urlhaus")))
    assert corr2.severity is Severity.HIGH  # independent community pulses + abuse.ch
    # a family the source does not declare cannot be claimed (no inflation)
    bogus = listing(DOMAIN, "otx", "otx.indicators", data={"upstream_families": ["spamhaus"]})
    [corr3] = cr27(graph_with(DOMAIN, bogus, listing(DOMAIN, "ip_blocklists", "spamhaus.drop_v4")))
    assert corr3.severity is Severity.HIGH  # OTX counts as its own aggregate (otx + abuse.ch), not as Spamhaus
    assert "spamhaus" in corr3.criterion


def test_per_feed_hits_of_one_finding_are_separate_votes():
    hits = [
        {"source": "spamhaus.drop_v4", "listed_at": (NOW - dt.timedelta(days=2)).date().isoformat()},
        {"source": "abusech.feodotracker", "listed_at": (NOW - dt.timedelta(days=3)).date().isoformat()},
        {"source": "abusech.sslbl", "listed_at": (NOW - dt.timedelta(days=3)).date().isoformat()},
    ]
    f = listing(IP, "ip_blocklists", "spamhaus.drop_v4", data={"hits": hits})
    [corr] = cr27(graph_with(IP, f))
    assert corr.severity is Severity.HIGH and corr.criterion.startswith("2 independent upstream families")


def test_verdicts_without_registry_provenance_need_two_modules_and_form_one_family():
    one = graph_with(DOMAIN, listing(DOMAIN, "t_unknown_a", "", days_ago=None))
    assert cr27(one) == []
    two = graph_with(DOMAIN, listing(DOMAIN, "t_unknown_a", "", days_ago=None), listing(DOMAIN, "t_unknown_b", "", days_ago=None))
    [corr] = cr27(two)
    assert corr.severity is Severity.MEDIUM and ti.UNATTRIBUTED in corr.criterion


# ------------------------------------------------------------------ decay windows and history (cond 4)
def test_decay_window_depends_on_the_type():
    for entity, expected in ((IP, Severity.MEDIUM), (DOMAIN, Severity.HIGH)):
        g = graph_with(entity, listing(entity, "ip_blocklists", "spamhaus.drop_v4", days_ago=2), listing(entity, "abusech", "abusech.urlhaus", days_ago=60))
        [corr] = cr27(g)
        assert corr.severity is expected, entity  # 60 days: history for an IP (30 d), current for a domain (90 d)
    g = graph_with(IP, listing(IP, "ip_blocklists", "spamhaus.drop_v4", days_ago=40), listing(IP, "abusech", "abusech.urlhaus", days_ago=35))
    assert cr27(g) == []  # history only: shown nowhere as consensus


def test_history_is_listed_not_counted_and_iaas_addresses_decay_faster():
    g = graph_with(IP, listing(IP, "ip_blocklists", "spamhaus.drop_v4", days_ago=1), listing(IP, "abusech", "abusech.urlhaus", days_ago=45))
    [corr] = cr27(g)
    assert any(line.startswith("history (not counted): abusech.urlhaus") for line in corr.evidence)
    cloud = graph_with(IP, listing(IP, "ip_blocklists", "spamhaus.drop_v4", days_ago=1), listing(IP, "abusech", "abusech.urlhaus", days_ago=20), noise_kind="cloud")
    [corr2] = cr27(cloud)
    assert corr2.severity is Severity.MEDIUM  # IaaS: 14-day window
    undated = listing(IP, "abusech", "abusech.urlhaus", days_ago=None, tags=("malicious", "historical"))
    [corr3] = cr27(graph_with(IP, listing(IP, "ip_blocklists", "spamhaus.drop_v4"), undated))
    assert corr3.severity is Severity.MEDIUM and any("marks the listing historical" in line for line in corr3.evidence)


# ------------------------------------------------------------------ suppression first, downgrade only (cond 5)
def test_suppressed_findings_are_no_votes_and_stay_in_the_graph():
    a = listing(DOMAIN, "abusech", "abusech.urlhaus")
    b = listing(DOMAIN, "url_domain_blocklists", "phishtank.online_valid", tags=("phishing",))
    for f in (a, b):
        f.downgrade("SUP-warninglist", "on warninglist t_list", to=Confidence.POSSIBLE)
    g = graph_with(DOMAIN, a, b)
    before = [f.to_dict() for f in g.findings()]
    assert cr27(g) == []
    assert [f.to_dict() for f in g.findings()] == before  # the rule never deletes or changes findings
    a.apply_override(label="confirmed", verdict="malicious", analyst="ana")  # an analyst decision always wins
    [corr] = cr27(g)
    assert corr.severity is Severity.MEDIUM
    assert any(line.startswith("suppressed (on warninglist t_list): finding") for line in corr.evidence)  # still listed
    b.apply_override(label="possible", verdict="false_positive", analyst="ana")  # a false-positive verdict is no vote at all
    [corr2] = cr27(g)
    assert corr2.severity is Severity.MEDIUM and any("analyst verdict false_positive" in line for line in corr2.evidence)


def test_a_module_attribute_never_adds_a_vote_its_excluded_finding_did_not_get():
    """The 'malicious' attribute of a module whose listing was excluded (analyst false positive, or
    derived from a shared address) is the same verdict: it never comes back as an attribute vote."""
    f = listing(DOMAIN, "abusech", "abusech.urlhaus")
    f.apply_override(label="possible", verdict="false_positive", analyst="ana")
    g = graph_with(DOMAIN, f, attrs={"malicious": [(True, "abusech")]})
    assert cr27(g) == []


@pytest.mark.parametrize(("tags", "noise_kind", "attrs", "rule_name"), [
    (("benign_scanner",), "benign_scanner", None, "SUP-benign_scanner"),
    ((), "", {"scanner_classification": [("benign", "greynoise")]}, "SUP-benign_scanner"),
    ((), "", {"allowlisted": [(["research scanner"], "otx")]}, "SUP-allowlist"),
    (("cdn",), "cdn", None, "SUP-shared_address"),
    ((), "", {"shared_ip": [(True, "ip_blocklists")]}, "SUP-shared_address"),
])
def test_benign_scanners_allowlists_and_shared_addresses_downgrade_never_delete(tags, noise_kind, attrs, rule_name):
    g = graph_with(IP, listing(IP, "ip_blocklists", "spamhaus.drop_v4"), listing(IP, "abusech", "abusech.feodotracker"),
                   tags=tags, noise_kind=noise_kind, attrs=attrs)
    [corr] = cr27(g)
    assert corr.severity is Severity.LOW and corr.label is Confidence.POSSIBLE
    assert corr.suppressed_by and corr.suppressed_by[-1]["rule"] == rule_name
    assert corr.criterion.startswith("POSSIBLE - ") and "malicious" not in corr.tags


def test_sinkholes_and_warninglisted_values_give_no_consensus(monkeypatch):
    from v3lum.core import noise

    sink = graph_with(IP, listing(IP, "ip_blocklists", "spamhaus.drop_v4"), listing(IP, "abusech", "abusech.feodotracker"),
                      tags=("sinkhole",), attrs={"malicious": [(True, "t_other_feed")]})
    assert cr27(sink) == []  # the 'malicious' attribute of a sinkholed entity is no vote either
    monkeypatch.setattr(noise, "warninglists", lambda entity: ["t_list"] if entity == DOMAIN else [])
    listed = graph_with(DOMAIN, listing(DOMAIN, "abusech", "abusech.urlhaus"), listing(DOMAIN, "url_domain_blocklists", "phishtank.online_valid"))
    assert cr27(listed) == []


@pytest.mark.parametrize(("noise_kind", "attrs", "rule_name"), [
    ("", {"is_tor_exit": [(True, "tor_exit_local")]}, "SUP-anonymizer"),
    ("", {"is_vpn": [(True, "ip_anonymizer_consensus")]}, "SUP-anonymizer"),
    ("resolver", None, "SUP-noise"),
    ("webmail", None, "SUP-noise"),
])
def test_anonymity_infrastructure_and_noise_ranges_never_get_a_malicious_consensus(noise_kind, attrs, rule_name):
    """Cond 5/7: two families listing a Tor exit / VPN endpoint or a resolver/webmail address keep the
    consensus, but at most LOW, POSSIBLE and never tagged malicious (anonymity networks are lawful
    privacy tools; noise ranges carry many unrelated users)."""
    g = graph_with(IP, listing(IP, "ip_blocklists", "spamhaus.drop_v4"), listing(IP, "abusech", "abusech.feodotracker"),
                   noise_kind=noise_kind, attrs=attrs)
    [corr] = cr27(g)
    assert corr.severity is Severity.LOW and corr.label is Confidence.POSSIBLE and "malicious" not in corr.tags
    assert [s["rule"] for s in corr.suppressed_by] == [rule_name]
    assert ("context_only" in corr.tags) is (rule_name == "SUP-anonymizer")
    parked = graph_with(IP, listing(IP, "ip_blocklists", "spamhaus.drop_v4"), listing(IP, "abusech", "abusech.feodotracker"), noise_kind="parked")
    assert cr27(parked)[0].severity is Severity.HIGH  # parked infrastructure is no reason to doubt the listing


# ------------------------------------------------------------------ shared addresses and licence (cond 6)
def test_a_shared_address_never_gives_consensus_to_the_domains_behind_it():
    fx = load_graph_fixture(FIXTURES / "multi_source_malicious" / "positive_cdn_ip_downgraded_cohosted_domains_untainted.json")
    corrs = run_rules(fx.graph, fx.results, only={"multi_source_malicious"}, rctx=fx.rctx)
    assert [c.entity_keys() for c in corrs] == [["ipv4:198.51.100.20"]]
    fx2 = load_graph_fixture(FIXTURES / "multi_source_malicious" / "negative_cdn_ip_listing_does_not_taint_domains.json")
    assert run_rules(fx2.graph, fx2.results, only={"multi_source_malicious"}, rctx=fx2.rctx) == []


def test_licence_disabled_and_unknown_terms_feeds_are_not_counted():
    g = graph_with(IP, listing(IP, "ip_blocklists", "spamhaus.drop_v4"), listing(IP, "ip_blocklists", "cinsscore.badguys"))
    assert cr27(g)[0].severity is Severity.HIGH
    res = ModuleResult(module="ip_blocklists", entity=IP)
    res.source_statuses["cinsscore.badguys"] = {"status": "skipped", "reason_code": "licence", "reason": "skipped: noncommercial terms (licence profile corporate)"}
    [corr] = cr27(g, [res])
    assert corr.severity is Severity.MEDIUM and any("cinsscore.badguys (disabled by the licence profile)" in line for line in corr.evidence)
    [corr2] = cr27(g, meta={"licence_blocked_sources": ["cinsscore.badguys"]})
    assert corr2.severity is Severity.MEDIUM
    unknown = graph_with(DOMAIN, listing(DOMAIN, "ioc_feeds_unreviewed", "threatview.feeds"), listing(DOMAIN, "abusech", "abusech.urlhaus"))
    [corr3] = cr27(unknown)
    assert corr3.severity is Severity.MEDIUM and any("threatview.feeds (unknown terms" in line for line in corr3.evidence)


# ------------------------------------------------------------------ evidence (cond 10)
def test_evidence_lists_sources_families_last_seen_and_terms():
    g = graph_with(DOMAIN, listing(DOMAIN, "abusech", "abusech.urlhaus", days_ago=6), listing(DOMAIN, "url_domain_blocklists", "phishtank.online_valid", days_ago=2))
    [corr] = cr27(g)
    counted = [line for line in corr.evidence if line.startswith("counted: ")]
    assert "counted: abusech.urlhaus (family abuse.ch; last seen 2026-11-20; terms license)" in counted
    assert "counted: phishtank.online_valid (family phishtank; last seen 2026-11-24; terms open)" in counted
    assert all(f"finding:{f.id}" in corr.evidence for f in g.findings())
    assert corr.attack == ["T1583", "T1584"] and corr.version == "2"


# ------------------------------------------------------------------ CR28 (cond 7)
def test_anonymizers_are_context_only_never_above_low_and_never_malicious():
    g = graph_with(IP, listing(IP, "ip_blocklists", "spamhaus.drop_v4"), attrs={
        "is_tor_exit": [(True, "tor_exit_local")], "is_vpn": [(True, "ip_anonymizer_consensus")], "is_proxy": [(True, "proxycheck")],
    })
    [corr] = run_rules(g, [], only={"anonymized_infrastructure"}, rctx=rctx())
    assert corr.severity <= Severity.LOW and "malicious" not in corr.tags and "context_only" in corr.tags
    assert corr.attack == ["T1090.003"] and corr.label is Confidence.CONFIRMED  # three sources
    relay = graph_with(IP, attrs={"is_tor_relay": [(True, "tor_onionoo")]})
    [corr2] = run_rules(relay, [], only={"anonymized_infrastructure"}, rctx=rctx())
    assert corr2.severity is Severity.INFO and corr2.attack == ["T1090.003"]
    assert run_rules(graph_with(DOMAIN, attrs={"is_vpn": [(True, "x")]}), [], only={"anonymized_infrastructure"}, rctx=rctx()) == []


# ------------------------------------------------------------------ CR29 (cond 8)
def _site(g: Graph, value: str, fav: str, **attrs):
    ent = Entity.make("domain", value)
    node, _ = g.add_node(ent, 1)
    node.attributes["favicon_mmh3"] = [(fav, "urlscan_search")]
    for name, val in attrs.items():
        node.attributes[name] = [(val, "rdap")]
    return node


def test_brand_favicon_clone_needs_a_signal_and_a_non_owned_host():
    org = OrgProfile.from_dict({"org": {"name": "Acme"}, "domains": [{"name": "acme-corp.example", "verification": "txt_verified"}], "favicon_hashes": ["-1234567890"]})
    g = Graph(noise_check=False)
    _site(g, "acme-corp-support.example", "-1234567890")
    assert run_rules(g, [], only={"favicon_clone_cluster"}, rctx=rctx(org=org)) == []  # no extra signal
    _site(g, "acme-corp-billing.example", "-1234567890", domain_age_days=4)
    _site(g, "mail.acme-corp.example", "-1234567890", domain_age_days=2)  # own host: never a clone
    [corr] = run_rules(g, [], only={"favicon_clone_cluster"}, rctx=rctx(org=org))
    assert corr.entity_keys()[0] == "domain:acme-corp-billing.example" and corr.severity is Severity.HIGH and "brand favicon clone" in corr.title
    # without an org profile nothing is a brand or owned: the shared favicon is a plain cluster (MEDIUM)
    plain = run_rules(g, [], only={"favicon_clone_cluster"}, rctx=rctx())
    assert {c.entity_keys()[0] for c in plain} == {"domain:acme-corp-billing.example", "domain:mail.acme-corp.example"}
    assert all(c.severity is Severity.MEDIUM for c in plain)


def test_similar_favicons_cluster_through_similar_to_edges():
    g = Graph(noise_check=False)
    a = _site(g, "phish-one.example", "111", domain_age_days=3)
    b = _site(g, "legit-two.example", "222")
    fa, fb = Entity.make("favicon_hash", "111"), Entity.make("favicon_hash", "222")
    g.add_node(fa, 2)
    g.add_node(fb, 2)
    g.add_edge(fa, fb, "similar_to", "favicon_similarity", 0.8)
    corrs = run_rules(g, [], only={"favicon_clone_cluster"}, rctx=rctx())
    assert [c.entity_keys()[0] for c in corrs] == [a.key]
    assert b.key in corrs[0].entity_keys()


# ------------------------------------------------------------------ CR30 (cond 9)
JARM = "07d14d16d21d21d07c42d41d00041d24a458a375eef0c576d23a7bab9a9fb1"


def test_jarm_match_needs_an_extra_signal_for_medium():
    g = Graph(noise_check=False)
    c2, _ = g.add_node(Entity.make("ipv4", "192.0.2.60"), 0, seed=True)
    c2.attributes["jarm"] = [(JARM, "shodan_api")]
    g.add_finding(listing(c2.entity, "abusech", "abusech.threatfox", tags=("c2", "malicious")))
    other, _ = g.add_node(Entity.make("ipv4", "192.0.2.61"), 1)
    other.attributes["jarm"] = [(JARM.upper(), "shodan_api")]
    [weak] = run_rules(g, [], only={"jarm_matches_known_c2"}, rctx=rctx())
    assert weak.entity_keys()[0] == other.key and weak.severity is Severity.LOW and weak.label is Confidence.POSSIBLE
    young, _ = g.add_node(Entity.make("domain", "cdn-update.example"), 1)
    young.attributes["domain_age_days"] = [(6, "rdap")]
    g.add_edge(young.entity, other.entity, "resolves_to", "dns_records")
    [strong] = run_rules(g, [], only={"jarm_matches_known_c2"}, rctx=rctx())
    assert strong.severity is Severity.MEDIUM and any("young domain cdn-update.example" in line for line in strong.evidence)


def test_jarm_matches_reported_by_a_source_count_and_the_c2_does_not_match_itself():
    g = Graph(noise_check=False)
    host, _ = g.add_node(Entity.make("ipv4", "192.0.2.62"), 0, seed=True)
    host.attributes["jarm"] = [(JARM, "shodan_api")]
    host.attributes["jarm_c2_matches"] = [([{"jarm": JARM, "family": "Cobalt Strike", "source": "c2_jarm_list"}], "jarm_lookup")]
    host.attributes["tls_self_signed"] = [(True, "shodan_internetdb")]
    [corr] = run_rules(g, [], only={"jarm_matches_known_c2"}, rctx=rctx())
    assert corr.severity is Severity.MEDIUM and any("Cobalt Strike" in line for line in corr.evidence)
    solo = Graph(noise_check=False)
    c2, _ = solo.add_node(Entity.make("ipv4", "192.0.2.63"), 0, seed=True)
    c2.attributes["jarm"] = [(JARM, "shodan_api")]
    solo.add_finding(listing(c2.entity, "abusech", "abusech.threatfox", tags=("c2", "malicious")))
    assert run_rules(solo, [], only={"jarm_matches_known_c2"}, rctx=rctx()) == []


# ------------------------------------------------------------------ acceptance: no network
def test_pack_rules_make_no_network_call(monkeypatch):
    """Acceptance: every rule of the pack runs over every fixture and a full scan with a FakeHttp
    that has zero routes; any HTTP or DNS attempt would fail the test."""
    import requests

    def refuse(*a, **k):
        raise AssertionError("a correlation rule tried to use the network")

    monkeypatch.setattr(requests.Session, "request", refuse)
    import socket  # below requests too: no socket, no name resolution

    monkeypatch.setattr(socket.socket, "connect", refuse)
    monkeypatch.setattr(socket, "create_connection", refuse)
    monkeypatch.setattr(socket, "getaddrinfo", refuse)
    from v3lum.core import http as core_http

    monkeypatch.setattr(core_http.HttpClient, "request", refuse, raising=False)
    for rid in PACK_RULES:
        for path in sorted((FIXTURES / rid).glob("*.json")):
            fx = load_graph_fixture(path)
            for other in PACK_RULES:
                run_rules(fx.graph, fx.results, only={other}, rctx=fx.rctx)
            assert rid not in correlate.RULE_ERRORS, correlate.RULE_ERRORS.get(rid)
    http = FakeHttp()
    from v3lum.core.context import ScanOptions
    from v3lum.core.engine import Engine

    Engine(make_runtime(http), ScanOptions(include={"t_none"})).investigate([DOMAIN, IP])
    assert http.calls == []


# ------------------------------------------------------------------ contract additions (docs/contract_additions/WP23.md)
def test_wp23_contract_additions_names_resolve():
    """Every name docs/contract_additions/WP23.md documents exists: backticked ``v3lum.*`` names
    (and the short names listed after them with `` / ``), the bundled data files, the vocabulary
    keys declared by the pack fragments and the ATT&CK ids of the pack attack fragments."""
    import importlib
    import json
    import re

    from v3lum.core import attack

    root = Path(__file__).resolve().parent.parent
    doc = (root / "docs" / "contract_additions" / "WP23.md").read_text(encoding="utf-8")
    missing: list[str] = []

    def resolve(dotted: str) -> bool:
        parts = dotted.split(".")
        for cut in range(len(parts), 0, -1):
            try:
                obj = importlib.import_module(".".join(parts[:cut]))
            except ImportError:
                continue
            for attr in parts[cut:]:
                if not hasattr(obj, attr):
                    return False
                obj = getattr(obj, attr)
            return True
        return False

    names = sorted(set(re.findall(r"`(v3lum(?:\.[A-Za-z_][A-Za-z0-9_]*)+)`", doc)))
    missing += [n for n in names if not resolve(n)]
    for module, _first, rest in re.findall(r"`(v3lum\.correlations\.\w+)\.(\w+)`((?: / `\w+`)+)", doc):
        missing += [f"{module}.{short}" for short in re.findall(r"`(\w+)`", rest) if not resolve(f"{module}.{short}")]
    paths = sorted(set(re.findall(r"`((?:v3lum|tests)/[A-Za-z0-9_./-]+)`", doc)))
    missing += [p for p in paths if not (root / p).exists()]
    declared: set[str] = set()
    for pack in ("pack_threat_intel", "pack_attack_surface", "pack_email_spoofing"):
        frag = json.loads((root / "v3lum" / "data" / "vocab" / f"{pack}.json").read_text(encoding="utf-8"))
        declared |= set(frag.get("attributes") or {}) | set(frag.get("tags") or {})
        att = json.loads((root / "v3lum" / "data" / "attack" / f"{pack}.json").read_text(encoding="utf-8"))
        missing += [f"attack:{tid}: {problem}" for tid in att["techniques"] for problem in attack.validate([tid])]
    vocab_keys = [key for row in re.findall(r"^\| ((?:`\w+`, )*`\w+`) \| vocab (?:attributes|tag) \|", doc, flags=re.M)
                  for key in re.findall(r"`(\w+)`", row)]
    missing += [f"vocab:{key}" for key in vocab_keys if key not in declared]
    assert len(names) >= 25 and paths and len(vocab_keys) >= 10 and not missing, missing


WP23_RULES = (
    "multi_source_malicious", "anonymized_infrastructure", "favicon_clone_cluster", "jarm_matches_known_c2",
    "subdomain_takeover_candidate", "dangling_cloud_ip", "exposed_remote_admin", "exposed_database_or_cache",
    "known_exploited_vuln_on_asset", "outdated_version_disclosed", "stale_host", "shadow_it_outlier",
    "certificate_san_affiliate", "exploitable_exposure", "spoofable_email_domain", "spf_lookup_limit",
    "dmarc_reports_external_unauthorized",
)


@pytest.mark.parametrize("rule_id", WP23_RULES)
def test_every_wp23_rule_declares_its_metadata_and_existing_fixtures(rule_id):
    """Plan spec: each rule declares code, criterion, ATT&CK ids, references and false positives,
    and every fixture its metadata names exists (both kinds), so `v3lum rules` never points nowhere."""
    root = Path(__file__).resolve().parent.parent
    correlate.load_rules()
    info = correlate.RULES[rule_id]
    assert info.origin.startswith(("v3lum.correlations.threat_intel.", "v3lum.correlations.attack_surface.", "v3lum.correlations.email_spoofing."))
    assert info.code and info.criterion and info.attack and info.references and info.false_positives and not info.legacy
    assert rule_id not in correlate.RULE_ERRORS, correlate.RULE_ERRORS.get(rule_id)
    names = {Path(p).name for p in info.fixtures}
    assert all((root / p).is_file() for p in info.fixtures), [p for p in info.fixtures if not (root / p).is_file()]
    on_disk = {p.name for p in (FIXTURES / rule_id).glob("*.json")}
    assert names == on_disk, (names ^ on_disk)
    assert any(n.startswith("positive_") for n in names) and any(n.startswith("negative_") for n in names)


def test_the_edge_index_matches_the_graph_queries_and_follows_new_edges():
    g = Graph(noise_check=False)
    a, b, c = (g.add_node(Entity.make("domain", f"{x}.example"), 0, seed=True)[0] for x in ("a", "b", "c"))
    g.add_edge(a.entity, b.entity, "cname_to", "dns_records")
    g.add_edge(a.entity, c.entity, "resolves_to", "dns_records")
    g.add_edge(c.entity, a.entity, "resolves_to", "dns_records")
    for key in (a.key, b.key, c.key):
        for rel in (None, "cname_to", "resolves_to", "nope"):
            assert ti.edges_out(g, key, rel) == g.out_edges(key, rel)
            assert ti.edges_in(g, key, rel) == g.in_edges(key, rel)
            for direction in ("out", "in", "both"):
                assert [n.key for n in ti.adjacent(g, key, rel, direction)] == [n.key for n in g.neighbors(key, rel, direction)]
    g.add_edge(b.entity, c.entity, "cname_to", "dns_records")  # appended after the index was built
    assert ti.edges_out(g, b.key, "cname_to") == g.out_edges(b.key, "cname_to") != []
