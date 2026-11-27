"""Generic correlation rules after WP22: homonym-safe high_signal_tags (AR08), the removed legacy
rules and the remaining generic rules (seeds_linked, shared_infrastructure, username_reuse,
young_domain) unchanged. Graph fixtures of high_signal_tags live in
tests/fixtures/rules/high_signal_tags/ (run by tests/test_rule_fixtures.py)."""

from __future__ import annotations

import datetime as dt
from dataclasses import dataclass, field
from pathlib import Path

import pytest

from v3lum.core import correlate
from v3lum.core.correlate import LEGACY_RULES, RULES, RuleContext, check_fixture, run_rules
from v3lum.core.entities import Entity
from v3lum.core.graph import Graph
from v3lum.core.models import Confidence, Finding, Severity
from v3lum.correlations import generic

NOW = dt.datetime(2026, 11, 26, 12, tzinfo=dt.timezone.utc)
FIXTURES = Path(__file__).parent / "fixtures" / "rules" / "high_signal_tags"
CNPJ = Entity.make("cnpj", "11222333000181")
PERSON = Entity.make("person_name", "Fulano de Tal Exemplo")
COMPANY = Entity.make("company_name", "Acme Comercio Exemplo Ltda")
WALLET = Entity.make("btc_address", "1BoatSLRHtKNngkdXEeobR76b53LETtpyT")
IP = Entity.make("ipv4", "203.0.113.77")


# ------------------------------------------------------------------ a tiny provider registry for family tests
@dataclass(frozen=True)
class FakeSource:
    id: str
    upstream_family: str
    embeds: tuple[str, ...] = ()

    @property
    def families(self) -> frozenset[str]:
        return frozenset({self.upstream_family, *self.embeds}) - {""}


@dataclass
class FakeRegistry:
    sources: dict[str, FakeSource] = field(default_factory=dict)

    def source(self, sid: str) -> FakeSource | None:
        return self.sources.get(sid)


REG = FakeRegistry({
    "feed_one.list": FakeSource("feed_one.list", "family-one"),
    "feed_one.mirror": FakeSource("feed_one.mirror", "family-one"),
    "feed_two.list": FakeSource("feed_two.list", "family-two"),
    "agg.all": FakeSource("agg.all", "aggregator", ("family-one", "family-two")),
})


def rctx(registry=REG) -> RuleContext:
    return RuleContext(now=NOW, providers=registry)


def tagged(entity: Entity, module: str, tag: str, *, source: str = "", conf: float | str = 0.9, data=None, extra_tags=(), sev="high") -> Finding:
    return Finding(f"{tag} finding from {module}", sev, "d", confidence=conf, tags=[tag, *extra_tags], entity=entity, module=module,
                   source=source, data=dict(data or {}))


def graph_with(entity: Entity, *findings: Finding) -> Graph:
    g = Graph(noise_check=False)
    g.add_node(entity, 0, seed=True)
    for f in findings:
        g.add_finding(f)
    return g


def hst(g: Graph, ctx: RuleContext | None = None) -> list:
    return run_rules(g, [], only={"high_signal_tags"}, rctx=ctx or rctx())


# ------------------------------------------------------------------ AR08 acceptance: name-only never CRITICAL
def test_single_module_name_only_sanctions_match_is_medium_possible_with_label():
    f = tagged(PERSON, "sanctions_lists", "sanctions", conf="probable", data={"match_type": "name", "list": "synthetic"},
               extra_tags=["name_only_match"], sev="medium")
    [corr] = hst(graph_with(PERSON, f))
    assert corr.severity is Severity.MEDIUM and corr.label is Confidence.POSSIBLE
    assert corr.title == "Fulano de Tal Exemplo: possible match - verify identifiers (sanctions)"
    assert "Match type: name only" in corr.description and "Underlying confidence: probable" in corr.description
    assert f.id in corr.evidence and "match:name_only" in corr.evidence
    assert corr.rule == "tag_sanctions" and corr.why.startswith("possible match - verify identifiers")


@pytest.mark.parametrize("entity", [PERSON, COMPANY, Entity.make("threat_actor", "Example Group")])
def test_name_entities_without_match_type_are_name_only(entity):
    [corr] = hst(graph_with(entity, tagged(entity, "t_tracker", "sanctions", conf="confirmed")))
    assert corr.severity is Severity.MEDIUM and corr.label is Confidence.POSSIBLE


def test_name_only_from_two_families_is_still_not_critical():
    g = graph_with(COMPANY,
                   tagged(COMPANY, "t_one", "sanctions", source="feed_one.list", data={"match_type": "name"}),
                   tagged(COMPANY, "t_two", "sanctions", source="feed_two.list", data={"match_type": "fuzzy"}))
    [corr] = hst(g)
    assert corr.severity is Severity.MEDIUM and corr.label is Confidence.POSSIBLE  # homonyms do not corroborate


def test_formerly_listed_is_medium_possible():
    f = tagged(CNPJ, "sanctions_lists", "sanctions", conf="confirmed", data={"match_type": "formerly_cnpj"})
    [corr] = hst(graph_with(CNPJ, f))
    assert corr.severity is Severity.MEDIUM and corr.label is Confidence.POSSIBLE and "formerly listed" in corr.description


# ------------------------------------------------------------------ exact identifier matches
@pytest.mark.parametrize(("entity", "data", "kind"), [
    (CNPJ, {"match_type": "exact_cnpj"}, "CNPJ"),
    (CNPJ, {}, "CNPJ"),  # the tag sits on the CNPJ itself
    (WALLET, {"match_type": "exact_wallet"}, "wallet"),
    (Entity.make("domain", "leak-claims.example"), {"match_type": "domain"}, "domain"),
    (COMPANY, {"match_type": "lei"}, "LEI"),  # an LEI matched for a company record
    (Entity.make("url", "https://shop.example/pay"), {}, "URL"),
])
def test_exact_identifier_match_is_critical_with_underlying_confidence(entity, data, kind):
    f = tagged(entity, "t_list", "sanctions", conf="probable", data=data)
    [corr] = hst(graph_with(entity, f))
    assert corr.severity is Severity.CRITICAL and corr.label is Confidence.PROBABLE
    assert f"exact {kind} match" in corr.title and "Match type: exact identifier" in corr.description


def test_exact_match_wins_over_a_name_match_on_the_same_node():
    g = graph_with(CNPJ,
                   tagged(CNPJ, "t_names", "ransomware", conf="possible", data={"match_type": "name"}),
                   tagged(CNPJ, "t_ids", "ransomware", conf="confirmed", data={"match_type": "cnpj"}))
    [corr] = hst(g)
    assert corr.severity is Severity.CRITICAL and corr.label is Confidence.CONFIRMED and corr.rule == "tag_ransomware"


# ------------------------------------------------------------------ independent upstream families
def test_two_independent_families_are_critical():
    g = graph_with(IP,
                   tagged(IP, "t_one", "ransomware", source="feed_one.list", conf="probable"),
                   tagged(IP, "t_two", "ransomware", source="feed_two.list", conf="probable"))
    [corr] = hst(g)
    assert corr.severity is Severity.CRITICAL and corr.label is Confidence.PROBABLE
    assert "2 independent sources" in corr.title and "families:family-one, family-two" in corr.evidence


def test_two_feeds_of_one_family_are_high_not_critical():
    g = graph_with(IP,
                   tagged(IP, "t_one", "ransomware", source="feed_one.list"),
                   tagged(IP, "t_mirror", "ransomware", source="feed_one.mirror"))
    [corr] = hst(g)
    assert corr.severity is Severity.HIGH and "one source - verify" in corr.title


def test_unregistered_sources_share_one_family():
    g = graph_with(IP, tagged(IP, "t_a", "ransomware", source="nobody.a"), tagged(IP, "t_b", "ransomware"))
    [corr] = hst(g)
    assert corr.severity is Severity.HIGH
    assert generic.upstream_families(g.get(IP).findings[0], REG) == frozenset({generic.UNATTRIBUTED_FAMILY})


def test_aggregator_families_narrowed_by_stated_upstreams():
    agg = tagged(IP, "t_agg", "ransomware", source="agg.all", data={"upstream_families": ["family-two", "not-embedded"]})
    assert generic.upstream_families(agg, REG) == frozenset({"family-two"})
    plain = tagged(IP, "t_agg", "ransomware", source="agg.all")
    assert generic.upstream_families(plain, REG) == frozenset({"aggregator"})
    g = graph_with(IP, agg, tagged(IP, "t_one", "ransomware", source="feed_one.list"))
    assert hst(g)[0].severity is Severity.CRITICAL


def test_registry_from_the_provider_registry_when_rctx_has_none():
    [corr] = hst(graph_with(IP, tagged(IP, "t_a", "ransomware")), RuleContext(now=NOW))
    assert corr.severity is Severity.HIGH  # unattributed: never CRITICAL from one module


# ------------------------------------------------------------------ evidence semantics and other tags
def test_context_only_suppressed_and_false_positive_findings_are_ignored():
    ctx_only = tagged(CNPJ, "t_a", "sanctions", data={"match_type": "exact_cnpj"}, extra_tags=["context_only"])
    suppressed = tagged(CNPJ, "t_b", "sanctions", data={"match_type": "exact_cnpj"})
    suppressed.downgrade("SUP-warninglist", "on a warning list")
    fp = tagged(CNPJ, "t_c", "sanctions", data={"match_type": "exact_cnpj"})
    fp.apply_override(label="possible", verdict="false_positive", analyst="ana")
    assert hst(graph_with(CNPJ, ctx_only, suppressed, fp)) == []


def test_takeover_and_credential_exposure_stay_high_with_underlying_confidence():
    dom = Entity.make("domain", "files.corp.example")
    g = graph_with(dom, tagged(dom, "t_takeover", "takeover", conf="possible"), tagged(dom, "t_secrets", "credential_exposure", conf="confirmed"))
    out = {c.rule: c for c in hst(g)}
    assert out["tag_takeover"].severity is Severity.HIGH and out["tag_takeover"].label is Confidence.POSSIBLE
    assert out["tag_credential_exposure"].severity is Severity.HIGH and out["tag_credential_exposure"].label is Confidence.CONFIRMED


def test_match_kind_classification():
    node = graph_with(IP).get(IP)
    cases = {
        ("exact_cnpj", ()): ("exact", "cnpj"), ("domain", ()): ("exact", "domain"), ("name", ()): ("name", "name"),
        ("alias", ()): ("name", "alias"), ("formerly_wallet", ()): ("former", "wallet"), ("", ("name_only_match",)): ("name", "name"),
        ("hash", ()): ("unspecified", "hash"), ("", ()): ("unspecified", ""),
    }
    for (mt, tags), want in cases.items():
        f = tagged(IP, "t", "sanctions", data={"match_type": mt} if mt else None, extra_tags=tags)
        assert generic.match_kind(f, node) == want, (mt, tags)


def test_high_signal_fixtures_include_the_homonym_case():
    names = {p.name for p in FIXTURES.glob("*.json")}
    assert {"positive_homonym_name_only_sanctions.json", "positive_exact_cnpj_sanctions.json"} <= names
    assert check_fixture("high_signal_tags", FIXTURES / "positive_homonym_name_only_sanctions.json") == []
    assert check_fixture("high_signal_tags", FIXTURES / "positive_exact_cnpj_sanctions.json") == []


# ------------------------------------------------------------------ removed legacy rules, remaining generic rules
def test_legacy_rules_shrank_and_the_removed_ids_are_served_by_the_packs():
    correlate.load_rules()
    assert set(LEGACY_RULES) == {"shared_infrastructure", "seeds_linked", "username_reuse", "young_domain", "high_signal_tags"}
    assert set(correlate.RETIRED_LEGACY_RULES) == {"multi_source_malicious", "breach_and_infostealer", "exploitable_exposure"}
    for rid in LEGACY_RULES:
        assert RULES[rid].legacy and RULES[rid].origin.startswith("v3lum.correlations.generic."), rid
    for rid in ("multi_source_malicious", "exploitable_exposure"):
        assert not RULES[rid].legacy and not RULES[rid].origin.startswith("v3lum.correlations.generic."), rid
        replaced = correlate.RULE_REPLACED.get(rid)
        assert replaced is None or not replaced.origin.startswith("v3lum.correlations.generic.")
    assert "breach_and_infostealer" not in RULES
    for name in ("multi_source_malicious", "breach_and_infostealer", "exploitable_exposure"):
        assert not hasattr(generic, name)
    assert not [k for k in correlate.RULE_ERRORS if k in LEGACY_RULES or k in correlate.RETIRED_LEGACY_RULES]


def test_high_signal_tags_metadata():
    info = RULES["high_signal_tags"]
    assert info.takes_context and info.severity == "critical" and "exact identifier" in info.criterion


def test_seeds_linked_and_shared_infrastructure_unchanged():
    g = Graph(noise_check=False)
    a, b = Entity.make("domain", "alpha.example"), Entity.make("domain", "beta.example")
    ip = Entity.make("ipv4", "198.51.100.20")
    g.add_node(a, 0, seed=True)
    g.add_node(b, 0, seed=True)
    g.add_node(ip, 1)
    g.add_edge(a, ip, "resolves_to", "dns_records", 0.9)
    g.add_edge(b, ip, "resolves_to", "dns_records", 0.9)
    out = {c.rule: c for c in run_rules(g, [], only={"seeds_linked", "shared_infrastructure"})}
    linked, shared = out["seeds_linked"], out["shared_infrastructure"]
    assert linked.severity is Severity.MEDIUM and linked.confidence == pytest.approx(0.8)
    assert [e.key for e in linked.entities] == ["domain:alpha.example", "ipv4:198.51.100.20", "domain:beta.example"]
    assert shared.severity is Severity.MEDIUM and shared.confidence == pytest.approx(0.75) and shared.title == "2 domains resolve to 198.51.100.20"
    assert linked.why and shared.why  # run_rules now fills a one-line why from the rule's criterion
    g2 = Graph(noise_check=False)  # weak relations never link (AR06)
    g2.add_node(a, 0, seed=True)
    g2.add_node(b, 0, seed=True)
    mx = Entity.make("domain", "mx.mail.example")
    g2.add_node(mx, 1)
    g2.add_edge(a, mx, "mx_host", "dns_records", 0.9)
    g2.add_edge(b, mx, "mx_host", "dns_records", 0.9)
    assert run_rules(g2, [], only={"seeds_linked", "shared_infrastructure"}) == []


def test_username_reuse_and_young_domain_unchanged():
    g = Graph(noise_check=False)
    handle = Entity.make("username", "handle_example")
    g.add_node(handle, 0, seed=True)
    g.add_attributes(handle, {"profiles": ["a", "b", "c"]}, "t_usernames")
    young = Entity.make("domain", "fresh.example")
    g.add_node(young, 0, seed=True)
    g.add_attributes(young, {"domain_age_days": 5}, "rdap")
    out = {c.rule: c for c in run_rules(g, [], only={"username_reuse", "young_domain"})}
    assert out["username_reuse"].severity is Severity.LOW and out["username_reuse"].confidence == pytest.approx(0.6)
    assert out["young_domain"].severity is Severity.MEDIUM and out["young_domain"].title == "fresh.example was registered 5 day(s) ago"


# ------------------------------------------------------------------ review additions (WP22 review)
@pytest.mark.parametrize("match_type", ["exact", "exact_name", "normalised", "full_name", "strict"])
def test_name_entities_matched_without_an_identifier_stay_name_only(match_type):
    """AR08: an 'exact' name comparison is still a name comparison - two families reporting it for a
    company or person name never make it CRITICAL (homonyms)."""
    for entity in (COMPANY, PERSON):
        g = graph_with(entity,
                       tagged(entity, "t_one", "sanctions", source="feed_one.list", data={"match_type": match_type}),
                       tagged(entity, "t_two", "sanctions", source="feed_two.list", data={"match_type": match_type}))
        [corr] = hst(g)
        assert corr.severity is Severity.MEDIUM and corr.label is Confidence.POSSIBLE, (entity, match_type)
        assert generic.NAME_ONLY_TITLE in corr.title


def test_identifier_kinds_on_name_entities_are_not_name_matches():
    node = graph_with(COMPANY).get(COMPANY)
    f = tagged(COMPANY, "t", "sanctions", data={"match_type": "cnpj_root"})
    assert generic.match_kind(f, node) == ("unspecified", "cnpj_root")
    [corr] = hst(graph_with(COMPANY, f))
    assert corr.severity is Severity.HIGH and "one source - verify" in corr.title


def test_one_registered_family_plus_one_unattributed_module_is_not_critical():
    """An unknown feed never corroborates a registered one (CR27/P171 parity): HIGH, not CRITICAL."""
    g = graph_with(IP, tagged(IP, "t_one", "ransomware", source="feed_one.list"), tagged(IP, "t_unknown", "ransomware"))
    [corr] = hst(g)
    assert corr.severity is Severity.HIGH
    g.add_finding(tagged(IP, "t_unknown_2", "ransomware"))  # two unregistered modules agree: one more family
    [corr] = hst(g)
    assert corr.severity is Severity.CRITICAL and f"families:family-one, {generic.UNATTRIBUTED_FAMILY}" in corr.evidence


def test_one_module_with_attributed_and_unattributed_findings_is_one_family():
    g = graph_with(IP, tagged(IP, "t_one", "ransomware", source="feed_one.list"), tagged(IP, "t_one", "ransomware"),
                   tagged(IP, "t_one", "ransomware", source="nobody.x"))
    [corr] = hst(g)
    assert corr.severity is Severity.HIGH


def test_an_aggregator_never_adds_a_family_it_may_merely_re_serve():
    """An aggregator embedding family-one adds nothing next to a direct family-one listing."""
    agg = tagged(IP, "t_agg", "ransomware", source="agg.all")
    one = tagged(IP, "t_one", "ransomware", source="feed_one.list")
    assert generic.independent_families([agg, one], REG) == ["family-one"]
    assert hst(graph_with(IP, agg, one))[0].severity is Severity.HIGH
    assert generic.independent_families([agg], REG) == ["aggregator"]
    two = tagged(IP, "t_two", "ransomware", source="feed_two.list")
    assert generic.independent_families([one, two, agg], REG) == ["family-one", "family-two"]


def test_ransomware_name_claim_from_trackers_stays_possible_when_corroborated_by_names_only():
    """Two trackers naming the same victim company (name claims) is still a name match (AR08)."""
    g = graph_with(COMPANY,
                   tagged(COMPANY, "ransomlook", "ransomware", source="feed_one.list", data={"match_type": "name"}),
                   tagged(COMPANY, "ransomware_live", "ransomware", source="feed_two.list"))
    [corr] = hst(g)
    assert corr.severity is Severity.MEDIUM and corr.label is Confidence.POSSIBLE
