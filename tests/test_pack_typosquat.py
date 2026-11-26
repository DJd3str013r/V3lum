"""Typosquat and brand-abuse pack (P028: CR04, CR05, CR06, CR35): one test per final condition.

The graph fixtures under tests/fixtures/rules/{typosquat_phishing_capable,
typosquat_with_fresh_certificate,typosquat_on_malicious_infra,new_brand_keyword_domain}/ run through
tests/test_rule_fixtures.py (including the named regressions of cond 12: parked lookalike <= MEDIUM,
fresh MX-enabled lookalike HIGH, own defensive registration and brand subsidiary suppressed). These
tests pin what the fixtures cannot express: no profile -> no finding, the folding and lure list,
own-asset suppression kinds, the CR06 consensus, wording, defanging and the CNPJ/CPF handling.
"""

from __future__ import annotations

import datetime as dt
import json
from pathlib import Path

import pytest

from v3lum.core import correlate
from v3lum.core.correlate import RuleContext, load_graph_fixture, run_rules
from v3lum.core.entities import Entity
from v3lum.core.graph import Graph
from v3lum.core.models import Confidence, Finding, Severity
from v3lum.core.orgprofile import OrgProfile
from v3lum.core.orgprofile import fold as accent_fold
from v3lum.correlations import typosquat as ts

NOW = dt.datetime(2026, 11, 26, 12, 0, tzinfo=dt.timezone.utc)
FIXTURES = Path(__file__).parent / "fixtures" / "rules"
PACK_RULES = (ts.RULE_PHISHING_CAPABLE, ts.RULE_FRESH_CERT, ts.RULE_MALICIOUS_INFRA, ts.RULE_BRAND_KEYWORD)
CODES = {ts.RULE_PHISHING_CAPABLE: "CR04", ts.RULE_FRESH_CERT: "CR05", ts.RULE_MALICIOUS_INFRA: "CR06", ts.RULE_BRAND_KEYWORD: "CR35"}
PROFILE = {
    "org": {"name": "Acme Pagamentos S.A."},
    "domains": [{"name": "acmepay.com.br", "verification": "txt_verified", "criticality": "high"}],
    "brands": [{"keyword": "acmepay", "variants": ["acme pay"], "criticality": "high"}],
    "cnpj_roots": ["11222333"],
    "suppliers": [{"name": "Logiparc Transportes Ltda", "domains": ["logiparc.com.br"], "brands": ["logiparc"]}],
}
OWN = Entity.make("domain", "acmepay.com.br")


def org() -> OrgProfile:
    return OrgProfile.from_dict(PROFILE)


def rctx(**kw) -> RuleContext:
    kw.setdefault("org", org())
    return RuleContext(now=NOW, **kw)


def lookalike(
    domain: str,
    *,
    age: int | None = 12,
    mx: bool = True,
    edge: bool = True,
    attrs: dict | None = None,
    ips: tuple[str, ...] = (),
    graph: Graph | None = None,
) -> tuple[Graph, Entity]:
    """A graph with the own domain and one candidate it imitates (P012 'lookalike' edge)."""
    g = graph or Graph(noise_check=False)
    own, _ = g.add_node(OWN, 0, seed=True)
    own.tags.add("own_asset")
    own.ownership = "own_asset"
    cand = Entity.make("domain", domain)
    g.add_node(cand, 1)
    if edge:
        g.add_edge(OWN, cand, "lookalike", "typosquat", 0.7, expand=False)
    facts: dict = {"registered": True, "registrant_kind": "org", "nameservers": ["ns1.cheap-dns.example"]}
    if age is not None:
        facts["created"] = (NOW - dt.timedelta(days=age)).date().isoformat()
        facts["domain_age_days"] = age
    if mx:
        facts["mx"] = [f"10 mail.{domain}"]
    if ips:
        facts["a_records"] = list(ips)
    facts.update(attrs or {})
    g.add_attributes(cand, facts, "rdap")
    for ip in ips:
        ent = Entity.make("ipv4", ip)
        g.add_node(ent, 2)
        g.add_edge(cand, ent, "resolves_to", "dns_records")
    return g, cand


def run(g: Graph, *rules: str, ctx: RuleContext | None = None):
    return run_rules(g, [], only=set(rules or PACK_RULES), rctx=ctx or rctx())


def listing(entity: Entity, module: str, source: str, *, days_ago: int = 2, tags=("malicious",)) -> Finding:
    seen = (NOW - dt.timedelta(days=days_ago)).isoformat()
    return Finding(title=f"Listed by {source}", severity=Severity.HIGH, criterion="feed listing", tags=list(tags), entity=entity,
                   module=module, source=source, observed_first=seen, observed_last=seen)


def positive_fixtures() -> list[Path]:
    return [p for rid in PACK_RULES for p in sorted((FIXTURES / rid).glob("positive_*.json"))]


# ------------------------------------------------------------------ registration (cond 1-2, 12)
def test_pack_rules_are_registered_with_metadata_and_fixtures():
    correlate.load_rules()
    for rid in PACK_RULES:
        info = correlate.RULES[rid]
        assert info.origin.startswith("v3lum.correlations.typosquat.")
        assert info.code == CODES[rid] and info.takes_context and not info.legacy
        assert info.criterion and info.attack and info.references and info.false_positives
        assert info.fixtures and all(Path(f).is_file() for f in info.fixtures), rid
        names = {Path(f).name for f in info.fixtures}
        assert any(n.startswith("positive_") for n in names) and any(n.startswith("negative_") for n in names)
        assert rid not in correlate.RULE_ERRORS
    assert correlate.RULES[ts.RULE_MALICIOUS_INFRA].severity == "critical"
    assert correlate.RULES[ts.RULE_BRAND_KEYWORD].severity == "medium"


def test_named_constants_match_the_final_conditions():
    assert ts.PHISHING_CAPABLE_MAX_AGE_DAYS == 90
    assert ts.FRESH_CERT_MAX_AGE_DAYS == 30 and ts.NEW_DOMAIN_MAX_AGE_DAYS == 30
    assert ts.CONSENSUS_MIN_FAMILIES == 2 and ts.SHARED_HOSTING_MIN_NAMES == 50
    assert ts.PARKED_CAP is Severity.MEDIUM


# ------------------------------------------------------------------ cond 4: brands only from the org profile
@pytest.mark.parametrize("path", positive_fixtures(), ids=lambda p: f"{p.parent.name}/{p.name}")
def test_without_an_org_profile_no_typosquat_rule_fires(path: Path):
    fx = load_graph_fixture(path)
    assert run_rules(fx.graph, fx.results, only=set(PACK_RULES), rctx=fx.rctx)  # fires with the profile
    fx.rctx.org = None
    assert run_rules(fx.graph, fx.results, only=set(PACK_RULES), rctx=fx.rctx) == []
    fx.rctx.org = OrgProfile.from_dict({})
    assert run_rules(fx.graph, fx.results, only=set(PACK_RULES), rctx=fx.rctx) == []


def test_no_hard_coded_brand_a_famous_lookalike_is_ignored():
    g, _ = lookalike("g00gle-login.com", edge=False)
    assert run(g) == []
    assert ts.protected_brands(None) == [] and ts.lookalike_candidates(g, RuleContext(now=NOW)) == []


def test_supplier_brands_and_domains_are_protected():
    brands = {b.term: b.origin for b in ts.protected_brands(org())}
    # the variant 'acme pay' and the domain label fold to the brand key 'acmepay' (kept once)
    assert brands == {"acmepay": "brand", "logiparc": "supplier brand"}
    g, cand = lookalike("logiparc-boleto.com", edge=False)  # brand carried by the name, no P012 edge
    corrs = run(g, ts.RULE_PHISHING_CAPABLE, ts.RULE_BRAND_KEYWORD)
    assert {c.rule for c in corrs} == {ts.RULE_PHISHING_CAPABLE, ts.RULE_BRAND_KEYWORD}
    assert all(c.entity_keys() == [cand.key] for c in corrs)


# ------------------------------------------------------------------ cond 5: own-asset suppression
def test_suppression_kinds_for_own_supplier_and_verified_assets():
    o = org()
    cases = {
        "cnpj": ({"cnpj_roots": ["11222333"]}, "own_asset"),
        "ns": ({"nameservers": ["ns1.acmepay.com.br"]}, "own_asset"),
        "mx": ({"mx": ["10 mx.acmepay.com.br"]}, "own_asset"),
        "supplier_ns": ({"nameservers": ["dns1.logiparc.com.br"]}, "supplier"),
        "bcb": ({"bcb_verified_domain": True}, "verified_fi"),
    }
    for name, (attrs, kind) in cases.items():
        g, cand = lookalike(f"acmepay-{name}.com", attrs=attrs)
        node = g.get(cand)
        facts = ts._facts(g, ts._Edges(g), node, {}, NOW)
        reason = ts.suppression_reason(g, node, facts, o)
        assert reason is not None and reason[0] == kind, (name, reason)
        assert run(g) == [], name


def test_profile_and_supplier_domains_are_never_candidates():
    g, _ = lookalike("acmepay.com.br", edge=False)
    g2, _ = lookalike("logiparc.com.br", edge=False)
    assert run(g) == [] and run(g2) == []


def test_own_asset_tag_from_the_engine_suppresses():
    g, cand = lookalike("acmepay-conta.com")
    g.get(cand).tags.add("own_asset")
    assert run(g) == []


def test_verified_fi_tag_suppresses_bcb_domains():
    g, cand = lookalike("acmepay-banco.com")
    g.get(cand).tags.add("verified_fi")
    assert run(g) == []


def test_p012_own_registrations_stay_suppressed_when_another_module_finds_them(monkeypatch):
    """P012 lists own/defensive registrations apart (``typosquat_own_registrations``, never in its lookalike table
    and never pivoted): when an NRD feed brings the same fresh, MX-enabled name into the graph, no rule flags it."""
    g, cand = lookalike("acmepay-pix.com", age=5, edge=False, attrs={"nameservers": ["ns1.brandguard.example"]})
    g.get(cand).tags.add("newly_registered")
    g.add_attributes(OWN, {"typosquat_own_registrations": [
        {"domain": "acmepay-pix.com", "ownership": "defensive_probable", "evidence": ["brand-protection registrar (MarkMonitor)"]}]},
        "typosquat")
    assert run(g) == []
    facts = ts._facts(g, ts._Edges(g), g.get(cand), ts._rows_index(g), NOW)
    assert ts.suppression_reason(g, g.get(cand), facts, org()) == ("own_asset", "own or defensive registration (brand-protection "
                                                                    "registrar (MarkMonitor))")
    # a lookalike-table row of another scan never overrides the own verdict, and other verdicts never suppress
    g.add_attributes(OWN, {"typosquat_lookalikes": [{"domain": "acmepay-pix.com", "ownership": "not_brand_owned"}]}, "typosquat_b")
    assert run(g) == []
    monkeypatch.setattr(ts, "OWN_ROW_VERDICTS", frozenset())
    assert {c.rule for c in run(g)} >= {ts.RULE_PHISHING_CAPABLE, ts.RULE_BRAND_KEYWORD}  # the attribute is what suppresses


def test_registrant_cnpj_edge_alone_suppresses_an_own_registration():
    """cond 5: a source that only pivots the registrant CNPJ (no cnpj_roots attribute) still marks the name as own."""
    g, cand = lookalike("acmepay-conta.com")
    cnpj = Entity.make("cnpj", "11222333000181")
    g.add_node(cnpj, 2)
    g.add_edge(cand, cnpj, "registrant", "whois_fallback")
    facts = ts._facts(g, ts._Edges(g), g.get(cand), {}, NOW)
    assert facts.registrant_roots == [] and facts.registrant_cnpjs == ["11222333000181"]
    assert ts.suppression_reason(g, g.get(cand), facts, org())[0] == "own_asset"
    assert run(g) == []


def test_fixture_own_defensive_registration_uses_the_p012_shape():
    doc = json.loads((FIXTURES / ts.RULE_PHISHING_CAPABLE / "negative_own_defensive_registration.json").read_text(encoding="utf-8"))
    own = next(n for n in doc["nodes"] if n["key"] == "domain:acmepay.com.br")
    assert "typosquat_own_registrations" in own["attributes"]
    assert all(r.get("ownership") not in ts.OWN_ROW_VERDICTS for n in doc["nodes"]
               for v in (n.get("attributes") or {}).get("typosquat_lookalikes", []) for r in v["value"])


# ------------------------------------------------------------------ cond 1 + 5: CR04
def test_cr04_fresh_mx_lookalike_is_high_probable():
    g, _ = lookalike("acmepay-fatura.com", age=20)
    [corr] = run(g, ts.RULE_PHISHING_CAPABLE)
    assert corr.severity is Severity.HIGH and corr.label is Confidence.PROBABLE
    assert "phishing_capable" in corr.tags and "typosquat" in corr.tags


@pytest.mark.parametrize("attrs", [{"registrant_kind": "redacted"}, {"privacy_proxy": True}])
def test_cr04_is_possible_while_rdap_is_redacted(attrs):
    g, _ = lookalike("acmepay-fatura.com", attrs=attrs)
    [corr] = run(g, ts.RULE_PHISHING_CAPABLE)
    assert corr.severity is Severity.HIGH and corr.label is Confidence.POSSIBLE
    assert corr.criterion.startswith("POSSIBLE - RDAP redacted")


def test_cr04_is_possible_when_rdap_is_unavailable():
    g = Graph(noise_check=False)
    own, _ = g.add_node(OWN, 0, seed=True)
    own.tags.add("own_asset")
    cand = Entity.make("domain", "acmepay-fatura.com")
    g.add_node(cand, 1)
    g.add_edge(OWN, cand, "lookalike", "typosquat", 0.7, expand=False)
    g.add_attributes(cand, {"mx": ["10 mail.acmepay-fatura.com"], "nameservers": ["ns1.cheap-dns.example"]}, "dns_records")
    [corr] = run(g, ts.RULE_PHISHING_CAPABLE)
    assert corr.label is Confidence.POSSIBLE and "RDAP unavailable" in corr.criterion
    assert "registration date unknown" in corr.criterion


@pytest.mark.parametrize(("age", "mx", "fires"), [(90, True, True), (91, True, False), (12, False, False)])
def test_cr04_age_window_and_mx_are_required(age, mx, fires):
    g, _ = lookalike("acmepay-fatura.com", age=age, mx=mx)
    assert bool(run(g, ts.RULE_PHISHING_CAPABLE)) is fires


def test_cr04_null_mx_does_not_count():
    g, _ = lookalike("acmepay-fatura.com", mx=False, attrs={"mx": ["0 ."]})
    assert run(g, ts.RULE_PHISHING_CAPABLE) == []


def test_cr04_not_registered_per_rdap_is_silent():
    g, _ = lookalike("acmepay-fatura.com", attrs={"registered": False}, mx=False)
    assert run(g, ts.RULE_PHISHING_CAPABLE) == []


# ------------------------------------------------------------------ cond 1: CR05 first certificate only
def test_cr05_uses_the_first_certificate_ever_logged():
    first = (NOW - dt.timedelta(days=12)).date().isoformat()
    g, _ = lookalike("acmepay-login.com", attrs={"first_cert_seen": first})
    [corr] = run(g, ts.RULE_FRESH_CERT)
    assert corr.severity is Severity.HIGH and "12 day(s) ago" in corr.criterion


def test_cr05_never_fires_on_the_latest_renewal():
    old = (NOW - dt.timedelta(days=400)).date().isoformat()
    renewal = (NOW - dt.timedelta(days=3)).date().isoformat()
    g, _ = lookalike("acmepay-login.com", age=500, attrs={
        "first_cert_seen": old, "ct_summary": {"first_cert_seen": old, "last_cert_seen": renewal},
        "cert_not_before": renewal,
    })
    assert run(g, ts.RULE_FRESH_CERT) == []
    # several sources: the earliest first certificate wins
    g2, _ = lookalike("acmepay-login.com", attrs={"first_cert_seen": [renewal, old]})
    assert run(g2, ts.RULE_FRESH_CERT) == []


# ------------------------------------------------------------------ cond 6: CR06 consensus
def test_cr06_two_independent_families_on_a_dedicated_ip_is_critical_and_malicious():
    g, _ = lookalike("acmepay-pix.com", ips=("198.51.100.20",))
    ip = Entity.make("ipv4", "198.51.100.20")
    g.add_attributes(ip, {"is_cdn": False, "is_hosting": False}, "ip_context")
    g.add_finding(listing(ip, "ip_blocklists", "spamhaus.drop_v4"))
    g.add_finding(listing(ip, "abusech", "abusech.threatfox"))
    [corr] = run(g, ts.RULE_MALICIOUS_INFRA)
    assert corr.severity is Severity.CRITICAL and "malicious" in corr.tags
    assert "2 independent upstream families" in corr.criterion
    assert "198.51.100.20" not in corr.criterion + corr.description and "198[.]51[.]100[.]20" in corr.criterion


def test_cr06_one_upstream_twice_is_high_and_never_called_malicious():
    g, _ = lookalike("acmepay-pix.com", ips=("198.51.100.20",))
    ip = Entity.make("ipv4", "198.51.100.20")
    g.add_finding(listing(ip, "abusech", "abusech.threatfox"))
    g.add_finding(listing(ip, "abusech_feeds", "abusech.urlhaus"))
    [corr] = run(g, ts.RULE_MALICIOUS_INFRA)
    assert corr.severity is Severity.HIGH and "malicious" not in corr.tags
    assert "malicious" not in corr.title.lower() and "not called malicious" in corr.description


@pytest.mark.parametrize("ip_attrs", [
    {"is_cdn": True},
    {"cohosted_count": 50},
    {"cloud_role": "shared_hosting"},
    {"shared_ip": True},
])
def test_cr06_shared_hosting_listings_never_count(ip_attrs):
    g, _ = lookalike("acmepay-pix.com", ips=("198.51.100.20",))
    ip = Entity.make("ipv4", "198.51.100.20")
    g.add_attributes(ip, ip_attrs, "ip_context")
    g.add_finding(listing(ip, "ip_blocklists", "spamhaus.drop_v4"))
    g.add_finding(listing(ip, "abusech", "abusech.threatfox"))
    assert run(g, ts.RULE_MALICIOUS_INFRA) == []


def test_cr06_a_hosting_address_is_never_critical():
    g, _ = lookalike("acmepay-pix.com", ips=("198.51.100.20",))
    ip = Entity.make("ipv4", "198.51.100.20")
    g.add_attributes(ip, {"is_hosting": True, "cohosted_count": 3}, "ip_context")
    g.add_finding(listing(ip, "ip_blocklists", "spamhaus.drop_v4"))
    g.add_finding(listing(ip, "abusech", "abusech.threatfox"))
    [corr] = run(g, ts.RULE_MALICIOUS_INFRA)
    assert corr.severity is Severity.HIGH and "malicious" not in corr.tags


def test_cr06_shared_hosting_counts_only_when_the_domain_itself_is_flagged():
    g, cand = lookalike("acmepay-pix.com", ips=("198.51.100.20",))
    ip = Entity.make("ipv4", "198.51.100.20")
    g.add_attributes(ip, {"cohosted_count": 340}, "passive_dns")
    g.add_finding(listing(ip, "ip_blocklists", "spamhaus.drop_v4"))
    g.add_finding(listing(ip, "abusech", "abusech.threatfox"))
    g.add_finding(listing(cand, "abusech", "abusech.urlhaus", tags=("phishing",)))
    [corr] = run(g, ts.RULE_MALICIOUS_INFRA)
    assert corr.severity is Severity.HIGH and "the domain itself" in corr.criterion
    assert any("shared-hosting listings not counted" in e for e in corr.evidence)


def test_cr06_sinkholed_and_stale_listings_are_suppressed_first():
    g, _ = lookalike("acmepay-pix.com", ips=("198.51.100.20",))
    ip = Entity.make("ipv4", "198.51.100.20")
    g.get(ip).tags.add("sinkhole")
    g.add_finding(listing(ip, "ip_blocklists", "spamhaus.drop_v4"))
    g.add_finding(listing(ip, "abusech", "abusech.threatfox"))
    assert run(g, ts.RULE_MALICIOUS_INFRA) == []
    g2, _ = lookalike("acmepay-pix.com", ips=("198.51.100.21",))
    ip2 = Entity.make("ipv4", "198.51.100.21")
    g2.add_finding(listing(ip2, "ip_blocklists", "spamhaus.drop_v4", days_ago=45))  # outside the 30-day IP window
    g2.add_finding(listing(ip2, "abusech", "abusech.threatfox", days_ago=60))
    assert run(g2, ts.RULE_MALICIOUS_INFRA) == []


def test_independent_families_count_shared_upstreams_once():
    a = ts.ListingVote("abusech.threatfox", frozenset({"abuse.ch"}), "abuse.ch")
    b = ts.ListingVote("abusech.urlhaus", frozenset({"abuse.ch"}), "abuse.ch")
    agg = ts.ListingVote("firehol.level1", frozenset({"firehol", "abuse.ch", "spamhaus"}), "firehol")
    assert ts.independent_families([a, b]) == ["abuse.ch"]
    assert ts.independent_families([a, b, agg]) == ["abuse.ch"]
    c = ts.ListingVote("cinsscore.badguys", frozenset({"cins"}), "cins")
    assert sorted(ts.independent_families([a, c])) == ["abuse.ch", "cins"]


# ------------------------------------------------------------------ cond 7: parked capped at MEDIUM
def test_parked_lookalikes_are_capped_at_medium_with_a_label():
    first = (NOW - dt.timedelta(days=5)).date().isoformat()
    g, cand = lookalike("acmepay-boleto.com", attrs={"first_cert_seen": first})
    g.get(cand).tags.add("parked")
    corrs = run(g, ts.RULE_PHISHING_CAPABLE, ts.RULE_FRESH_CERT, ts.RULE_BRAND_KEYWORD)
    assert {c.rule for c in corrs} == {ts.RULE_PHISHING_CAPABLE, ts.RULE_FRESH_CERT, ts.RULE_BRAND_KEYWORD}
    for corr in corrs:
        assert corr.severity <= Severity.MEDIUM and "parked" in corr.tags
    assert all("(parked)" in c.title for c in corrs if c.rule != ts.RULE_BRAND_KEYWORD)


def test_parking_name_servers_mark_a_lookalike_parked():
    g, _ = lookalike("acmepay-boleto.com", attrs={"nameservers": ["ns1.sedoparking.com"]})
    [corr] = run(g, ts.RULE_PHISHING_CAPABLE)
    assert corr.severity is Severity.MEDIUM and "parked" in corr.tags


# ------------------------------------------------------------------ cond 2 + 8: CR35 and the lure list
def test_lure_list_holds_the_p028_words_folded_and_lowercase():
    doc = json.loads(ts.LURES_PATH.read_text(encoding="utf-8"))
    assert doc["schema"] == "v3lum.brand_lures/1"
    cond8 = {"conta", "pix", "boleto", "sac", "segunda-via", "2via", "fatura", "cartao", "credito", "emprestimo", "fgts", "inss",
             "gov", "receita", "regularizar", "desbloqueio", "premio", "cashback", "pontos", "login", "seguranca", "atualizacao",
             "token"}
    assert cond8 <= set(doc["pt"]) | set(doc["en"])
    assert doc["words"] == list(dict.fromkeys(doc["pt"] + doc["en"]))
    for word in doc["words"]:
        assert word == word.lower() and word.isascii() and word == accent_fold(word), word
    assert set(ts.lure_words()) == set(doc["words"])
    meta = set(doc) - {"words", "pt", "en"}
    assert meta <= {"schema", "description", "licence", "source", "reviewer", "date", "notes"}  # the P376 reader ignores these


def test_lure_words_missing_file_gives_empty_tuple(tmp_path):
    assert ts.lure_words(tmp_path / "missing.json") == ()
    bad = tmp_path / "bad.json"
    bad.write_text("{not json", encoding="utf-8")
    assert ts.lure_words(bad) == ()


def test_fold_text_handles_idna_accents_and_homoglyphs():
    assert ts.fold_text("аcmеpay") == ts.fold_text("acmepay")  # Cyrillic a and e
    assert ts.fold_text("acrnepay") == ts.fold_text("acmepay")  # rn -> m
    assert ts.fold_text("acm3pay") == ts.fold_text("acmepay")
    assert ts.fold_text("Cartão") == ts.fold_text("cartao")
    assert ts.fold_text("acmépay-pix.com".encode("idna").decode()) == ts.fold_text("acmepay-pix.com")


@pytest.mark.parametrize(("domain", "lure"), [
    ("acmepay-pix.com", "pix"),
    ("acmepaysegundavia.com", "segunda-via"),
    ("acmepay-2via.com.br", "2via"),
    ("acmepay-cartão.com".encode("idna").decode(), "cartao"),
    ("аcmеpay-boleto.com".encode("idna").decode(), "boleto"),
    ("acmepayseguranca.com", "seguranca"),
])
def test_cr35_brand_keyword_with_lure_after_folding_is_medium(domain, lure):
    g, _ = lookalike(domain, edge=False)
    [corr] = run(g, ts.RULE_BRAND_KEYWORD)
    assert corr.severity is Severity.MEDIUM and corr.label is Confidence.PROBABLE
    assert repr(lure) in corr.criterion


def test_cr35_short_lures_match_only_as_whole_tokens_and_brand_is_never_its_own_lure():
    assert ts.lure_matches("acmepay-sac.com", "acmepay", ts.lure_words()) == ["sac"]
    assert "sac" not in ts.lure_matches("acmepay-massachusetts.com", "acmepay", ts.lure_words())
    assert ts.lure_matches("acmepay.com", "acmepay", ts.lure_words()) == []
    g, _ = lookalike("acmepay-online.com", edge=False)
    assert run(g, ts.RULE_BRAND_KEYWORD) == []


@pytest.mark.parametrize(("age", "fires"), [(30, True), (31, False), (None, False)])
def test_cr35_needs_a_domain_at_most_30_days_old(age, fires):
    g, _ = lookalike("acmepay-pix.com", edge=False, age=age)
    assert bool(run(g, ts.RULE_BRAND_KEYWORD)) is fires


def test_cr35_accepts_the_nrd_tag_when_rdap_has_no_date():
    g, cand = lookalike("acmepay-pix.com", edge=False, age=None)
    g.get(cand).tags.add("newly_registered")
    [corr] = run(g, ts.RULE_BRAND_KEYWORD)
    assert "newly registered (NRD feed)" in corr.criterion


# ------------------------------------------------------------------ cond 9-11: wording, CNPJ/CPF, defanging, evidence chain
def test_wording_is_an_indicator_never_malicious_and_no_takedown():
    first = (NOW - dt.timedelta(days=5)).date().isoformat()
    g, _ = lookalike("acmepay-pix.com", attrs={"first_cert_seen": first})
    corrs = run(g, ts.RULE_PHISHING_CAPABLE, ts.RULE_FRESH_CERT, ts.RULE_BRAND_KEYWORD)
    assert len(corrs) == 3
    for corr in corrs:
        assert ts.WORDING in corr.description and ts.NOT_A_VERDICT in corr.description
        assert "malicious" not in corr.title.lower() and "malicious" not in corr.tags
        assert ts.NO_TAKEDOWN in corr.recommendation


def test_values_are_defanged_with_a_one_line_evidence_chain():
    first = (NOW - dt.timedelta(days=5)).date().isoformat()
    g, _ = lookalike("acmepay-pix.com", attrs={"first_cert_seen": first})
    [corr] = run(g, ts.RULE_PHISHING_CAPABLE)
    assert "acmepay-pix[.]com" in corr.title and "acmepay-pix.com" not in corr.title
    assert "acmepay-pix.com" not in corr.description and "acmepay.com.br" not in corr.description
    chain = corr.why
    assert "\n" not in chain
    assert chain.startswith("registered 12 day(s) ago") and "MX yes" in chain and f"first certificate {first}" in chain
    assert chain.endswith("TI sources: none") and chain in corr.evidence


def test_registrant_cnpj_is_noted_for_analyst_pivot_but_never_pivoted():
    g, cand = lookalike("acmepay-pix.com", attrs={"cnpj_roots": ["99888777"], "registrant_doc": "99.888.777/0001-00"})
    [corr] = run(g, ts.RULE_PHISHING_CAPABLE)
    assert any("registrant CNPJ 99.888.777/0001-00" in e and "company due diligence" in e for e in corr.evidence)
    assert corr.entity_keys() == [cand.key]  # rules never create pivots or extra entities


def test_cpf_registrants_and_legal_representatives_never_appear():
    attrs = {"registrant_kind": "individual", "registrant_doc": "123.456.789-09", "registrant": "Fulano de Tal",
             "legal_representative": "Fulano de Tal"}
    g, cand = lookalike("acmepay-pix.com", attrs=attrs)
    cpf = Entity.try_make("cpf", "12345678909")
    if cpf is not None:
        g.add_node(cpf, 2)
        g.add_edge(cand, cpf, "registrant", "rdap")
    [corr] = run(g, ts.RULE_PHISHING_CAPABLE)
    text = json.dumps(corr.to_dict(), ensure_ascii=False)
    assert "123.456.789" not in text and "12345678909" not in text and "Fulano" not in text
    assert "natural person (identity withheld; never pivoted)" in text
    assert corr.entity_keys() == [cand.key]


def test_rules_only_read_the_graph(monkeypatch):
    """cond 3/11: no network and no LIGHT contact - the rules never touch the HTTP layer."""
    import v3lum.core.http as http

    def boom(*_a, **_kw):  # pragma: no cover - must never run
        raise AssertionError("a correlation rule tried to use the network")

    monkeypatch.setattr(http.HttpClient, "request", boom, raising=False)
    for path in positive_fixtures():
        fx = load_graph_fixture(path)
        before = (len(fx.graph.nodes), len(fx.graph.edges))
        assert run_rules(fx.graph, fx.results, only=set(PACK_RULES), rctx=fx.rctx)
        assert (len(fx.graph.nodes), len(fx.graph.edges)) == before
