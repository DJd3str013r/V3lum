"""Risk model v2 (P302, WP19): golden cases, decay classes, ceilings, inheritance and the engine wiring.

Golden cases of P302 cond 11: 30 pivots with one LOW each stay <= low (model v1 scored the same case
83.1 = critical); one CONFIRMED CRITICAL outranks any number of LOWs; 2 HIGH findings plus their
correlation stay HIGH; frozen-time decay per class. Plus: no decay without a timestamp ('age
unknown'), the shared-infrastructure cap, own assets/known-good never inheriting, inconclusive seeds,
licence-disabled sources, context_only findings, analyst overrides surviving a re-run, and the v1
keys of the risk dict.
"""

from __future__ import annotations

import datetime as dt

import pytest

from tests.fakes import FakeClock, FakeHttp, define_module, make_runtime, test_provider
from v3lum.core import scoring
from v3lum.core.context import ScanOptions
from v3lum.core.engine import Engine
from v3lum.core.entities import Entity
from v3lum.core.graph import Graph
from v3lum.core.models import Confidence, Correlation, ModuleResult, Severity
from v3lum.core.scoring import A_CRIT, DELTA, LEVELS, TAU_DAYS, W_SEV, decay, level, score
from v3lum.core.store import Store

NOW = dt.datetime(2026, 11, 26, 12, 0, tzinfo=dt.timezone.utc)
SEED = Entity.make("domain", "seed-target.com.br")


def mk(entity, title, sev="high", conf="confirmed", tags=("malicious",), module="t_score", source="", observed_last=None, key=""):
    res = ModuleResult(module=module, entity=entity)
    return res.finding(title, sev, "synthetic finding", confidence=conf, criterion="synthetic test criterion", tags=list(tags),
                       source=source, observed_last=observed_last, key=key)


def graph(seed=SEED, *findings):
    g = Graph(noise_check=False)
    g.add_node(seed, seed=True)
    for f in findings:
        g.add_finding(f)
    return g


def pivot(g, parent, child, relation="resolves_to", conf=0.9, *findings):
    g.add_node(child, 1)
    g.add_edge(parent, child, relation, "t_score", conf)
    for f in findings:
        g.add_finding(f)
    return child


def ip(n):
    return Entity.make("ipv4", f"198.51.100.{n}")


def v1_score(g):
    """Model v1 (wave 1), reproduced for the golden comparison."""
    weights = {Severity.INFO: 0.0, Severity.LOW: 0.12, Severity.MEDIUM: 0.3, Severity.HIGH: 0.6, Severity.CRITICAL: 0.88}

    def nor(ws):
        acc = 1.0
        for w in ws:
            acc *= 1.0 - max(0.0, min(0.99, w))
        return round((1.0 - acc) * 100, 1)

    per = {k: nor([weights[f.severity] * f.confidence for f in n.findings]) for k, n in g.nodes.items() if n.findings}
    seeds = [per.get(n.key, 0.0) / 100 for n in g.seeds()]
    pivots = [s / 100 * 0.6 for k, s in per.items() if not g.nodes[k].seed]
    return nor(seeds + pivots)


# ------------------------------------------------------------------ constants and levels


def test_documented_constants():
    assert W_SEV == {Severity.CRITICAL: 10, Severity.HIGH: 7, Severity.MEDIUM: 4, Severity.LOW: 2, Severity.INFO: 0}
    assert scoring.C_CONF == {Confidence.CONFIRMED: 1.0, Confidence.PROBABLE: 0.7, Confidence.POSSIBLE: 0.4}
    assert TAU_DAYS == {"ip": 30, "url": 30, "domain": 90, "typosquat": 180, "breach": 1095, "infostealer": 365, "hash": None}
    assert DELTA == 1.0 and A_CRIT == {"critical": 1.0, "high": 0.95, "medium": 0.85, "low": 0.6}
    assert [t for t, _ in LEVELS] == [80, 55, 30, 8, 0] and LEVELS[-1][1] == "no findings"


def test_levels_keep_the_thresholds_and_rename_the_lowest():
    assert [level(v) for v in (100, 80, 79.9, 55, 54.9, 30, 29.9, 8, 7.9, 0)] == [
        "critical", "critical", "high", "high", "medium", "medium", "low", "low", "no findings", "no findings"]
    assert level("garbage") == "no findings" and level(-3) == "no findings"
    assert "clean" not in {name for _t, name in LEVELS}


def test_v1_keys_still_present_and_v2_keys_added():
    risk = score(graph(SEED, mk(SEED, "listed")), [])
    assert {"score", "level", "entities", "top"} <= set(risk)
    assert risk["score"] == 70.0 and risk["level"] == "high"
    assert risk["entities"][SEED.key]["score"] == 70.0 and risk["entities"][SEED.key]["level"] == "high"
    assert risk["top"] == [{"entity": SEED.key, "score": 70.0, "level": "high"}]
    assert risk["label"] == "triage aid, not a conclusion" and risk["model"] == "v3lum.risk/2"
    assert risk["inconclusive"] == [] and risk["no_export"] == [] and risk["excluded"] == {}
    (c,) = risk["contributors"]
    assert {"finding_id", "entity", "path", "confidence_label", "weight", "words"} <= set(c)
    assert c["entity"] == SEED.key and c["path"] == [] and c["confidence_label"] == "confirmed" and c["weight"] == 0.7
    assert "seed-target[.]com[.]br" in c["words"] and "listed" in c["words"]
    empty = score(graph(SEED), [])
    assert empty["score"] == 0.0 and empty["level"] == "no findings" and empty["entities"] == {} and empty["contributors"] == []


# ------------------------------------------------------------------ golden cases (P302 cond 11)


def test_thirty_pivots_with_one_low_each_stay_low():
    g = graph(SEED)
    for n in range(30):
        pivot(g, SEED, ip(n + 1), "resolves_to", 0.9, mk(ip(n + 1), "low signal", "low", 0.8, tags=("suspicious",)))
    assert v1_score(g) == 83.1  # model v1: critical
    risk = score(g, [])
    assert risk["level"] == "low" and risk["score"] <= 29.9
    assert risk["ceiling"] == "low"
    assert len(risk["contributors"]) == 3 and all(c["path"] for c in risk["contributors"])  # pivots carry their path
    assert risk["contributors"][0]["path"][0]["from"] == SEED.key and risk["contributors"][0]["path"][0]["relation"] == "resolves_to"


def test_one_confirmed_critical_outranks_any_number_of_lows():
    crit = score(graph(SEED, mk(SEED, "ransomware C2", "critical", "confirmed", tags=("c2",))), [])
    assert crit["level"] == "critical"
    tags = ("suspicious", "spam", "scanner", "tor", "proxy", "exposure", "misconfiguration", "newly_registered", "vulnerable", "typosquat")
    lows = [mk(SEED, f"weak signal {i}", "low", "confirmed", tags=(tags[i % len(tags)],), key=str(i)) for i in range(40)]
    g = graph(SEED, *lows)
    for n in range(30):
        pivot(g, SEED, ip(n + 1), "resolves_to", 1.0, mk(ip(n + 1), "low signal", "low", "confirmed", tags=("malicious",)))
    many = score(g, [])
    assert many["level"] == "low" and many["score"] <= 29.9
    assert crit["score"] > many["score"]


def test_two_high_findings_plus_their_correlation_stay_high():
    target = ip(7)
    seed_f = mk(SEED, "listed as malicious", "high", "confirmed", tags=("malicious",), module="t_feed_a")
    g = graph(SEED, seed_f)
    piv_f = mk(target, "C2 server", "high", "confirmed", tags=("c2",), module="t_feed_b")
    pivot(g, SEED, target, "resolves_to", 0.9, piv_f)
    corr = Correlation("t_c2_link", "domain resolves to a C2 server", Severity.HIGH, "synthetic", [SEED, target],
                       confidence="confirmed", evidence=[seed_f.id, piv_f.id], criterion="synthetic rule")
    risk = score(g, [corr])
    assert risk["level"] == "high" and risk["score"] == 79.9  # raw noisy-OR 88.9 would read critical
    assert scoring._noisy_or([0.7, 0.63]) > 0.8
    assert risk["entities"][SEED.key]["level"] == "high"
    # escalation happens only through an explicit correlation rule
    escalated = Correlation("t_c2_link", "domain resolves to a C2 server", Severity.CRITICAL, "synthetic", [SEED, target],
                            confidence="confirmed", evidence=[seed_f.id, piv_f.id], criterion="synthetic rule")
    up = score(g, [escalated])
    assert up["level"] == "critical" and up["entities"][SEED.key]["uplifted_by"] == escalated.id
    assert any(c.get("correlation_id") == escalated.id for c in up["contributors"])


def test_a_correlation_takes_the_max_never_a_second_noisy_or_term():
    f = mk(SEED, "listed", "medium", "confirmed", tags=("malicious",))
    alone = score(graph(SEED, f), [])
    corr = Correlation("t_same", "same fact", Severity.MEDIUM, "synthetic", [SEED], confidence="confirmed", evidence=[f.id], criterion="r")
    both = score(graph(SEED, f), [corr])
    assert alone["score"] == both["score"] == 40.0


# ------------------------------------------------------------------ decay (P302 cond 2)


def test_misp_decay_curve_and_edges():
    assert [round(decay(t, 30, base=80, delta=2), 1) for t in (0, 1, 7, 15, 30, 45)] == [80.0, 65.4, 41.4, 23.4, 0.0, 0.0]
    assert decay(15, 30) == 0.5 and decay(None, 30) == 1.0 and decay(400, None) == 1.0 and decay(-5, 30) == 1.0


@pytest.mark.parametrize(
    ("entity", "tags", "klass", "expected"),
    [
        (Entity.make("ipv4", "198.51.100.20"), ("malicious",), "ip", 35.0),
        (Entity.make("url", "https://phish.example.net/login"), ("phishing",), "url", 35.0),
        (Entity.make("domain", "evil-domain.com.br"), ("malicious",), "domain", round(70 * (1 - 15 / 90), 1)),
        (Entity.make("domain", "seed-targett.com.br"), ("typosquat",), "typosquat", round(70 * (1 - 15 / 180), 1)),
        (Entity.make("email", "maria.silva@acme-industria.com.br"), ("breach",), "breach", round(70 * (1 - 15 / 1095), 1)),
        (Entity.make("email", "maria.silva@acme-industria.com.br"), ("infostealer",), "infostealer", round(70 * (1 - 15 / 365), 1)),
        (Entity.make("sha256", "a" * 64), ("malware",), "hash", 70.0),
    ],
)
def test_frozen_time_decay_per_class(entity, tags, klass, expected):
    f = mk(entity, "observed", "high", "confirmed", tags=tags, observed_last=(NOW - dt.timedelta(days=15)).isoformat())
    assert scoring.decay_class(f) == klass
    risk = score(graph(entity, f), [], now=NOW)
    assert risk["entities"][entity.key]["score"] == expected
    assert "15 days old" in risk["contributors"][0]["age"]


def test_findings_older_than_tau_stop_scoring():
    old = mk(ip(9), "old listing", "high", "confirmed", observed_last=(NOW - dt.timedelta(days=45)).isoformat())
    assert score(graph(ip(9), old), [], now=NOW)["entities"] == {}


def test_no_timestamp_means_no_decay_and_age_unknown():
    f = mk(ip(3), "listed without a date", "high", "confirmed")
    risk = score(graph(ip(3), f), [], now=NOW)
    assert risk["entities"][ip(3).key]["score"] == 70.0
    assert risk["contributors"][0]["age"] == "age unknown" and "age unknown" in risk["contributors"][0]["words"]
    assert scoring.age_days(None, NOW) is None and scoring.age_days("not a date", NOW) is None
    assert scoring.age_days("2026-11-16", NOW) == pytest.approx(10.5)
    assert scoring.decay_class({"entity": "cve:CVE-2021-44228", "tags": []}) is None


# ------------------------------------------------------------------ propagation (P302 cond 5)


def test_shared_infrastructure_caps_the_transferred_contribution_at_low():
    seed_ip = ip(10)
    cohosted = Entity.make("domain", "cohosted-shop.com.br")
    g = graph(seed_ip)
    pivot(g, seed_ip, cohosted, "hosted_domain", 0.9, mk(cohosted, "malware distribution", "critical", "confirmed", tags=("malware",)))
    risk = score(g, [])
    assert risk["entities"][cohosted.key]["level"] == "critical"  # its own risk is unchanged
    assert risk["level"] == "low" and risk["score"] <= 29.9
    assert "shared infrastructure" in risk["contributors"][0]["words"]
    direct = graph(SEED)
    pivot(direct, SEED, cohosted, "redirects_to", 0.9, mk(cohosted, "malware distribution", "critical", "confirmed", tags=("malware",)))
    assert score(direct, [])["level"] == "critical"


def test_only_the_top_five_pivots_count_weighted_by_path_confidence():
    g = graph(SEED)
    for n in range(8):
        pivot(g, SEED, ip(n + 1), "resolves_to", 0.25, mk(ip(n + 1), "medium listing", "medium", "confirmed", tags=("malicious",)))
    risk = score(g, [])
    assert risk["score"] == round((1 - (1 - 0.4 * 0.25) ** 5) * 100, 1) == 41.0  # 5 pivots of 0.4 at path confidence 0.25
    assert round((1 - (1 - 0.4 * 0.25) ** 8) * 100, 1) > 54.9  # all 8 would have reached the medium ceiling


def test_own_assets_and_known_good_entities_never_inherit_risk():
    target = ip(11)

    def case(seed_entity, prepare):
        g = graph(seed_entity)
        prepare(g.get(seed_entity))
        bad = mk(target, "listed as malicious", "high", "confirmed", tags=("malicious",))
        pivot(g, seed_entity, target, "resolves_to", 0.9, bad)
        corr = Correlation("t_link", "seed and listed IP linked", Severity.HIGH, "synthetic", [seed_entity, target],
                           confidence="confirmed", evidence=[bad.id], criterion="synthetic rule")
        return score(g, [corr])

    third = case(SEED, lambda node: None)
    assert third["entities"][SEED.key]["score"] == 70.0 and "uplifted_by" in third["entities"][SEED.key]
    own = case(SEED, lambda node: setattr(node, "ownership", "own_asset"))
    assert SEED.key not in own["entities"] and own["entities"][ip(11).key]["score"] == 70.0
    assert SEED.key not in case(SEED, lambda node: node.add_tag("known_good"))["entities"]
    assert SEED.key not in case(SEED, lambda node: node.add_tag("verified_fi"))["entities"]
    gov = Entity.make("domain", "receita.gov.br")
    assert gov.key not in case(gov, lambda node: None)["entities"]
    # a correlation citing the own asset's own finding still applies to it
    g = graph(SEED, own_f := mk(SEED, "weak e-mail security", "medium", "confirmed", tags=("weak_email_security",)))
    g.get(SEED).ownership = "own_asset"
    corr = Correlation("t_spoof", "spoofable domain", Severity.HIGH, "synthetic", [SEED], confidence="confirmed", evidence=[own_f.id], criterion="r")
    assert score(g, [corr])["entities"][SEED.key]["score"] == 70.0


# ------------------------------------------------------------------ what never scores


def test_context_only_findings_and_correlations_contribute_nothing():
    f = mk(SEED, "third-party breach context", "high", "confirmed", tags=("breach", "context_only"))
    corr = Correlation("t_ctx", "context", Severity.HIGH, "synthetic", [SEED], confidence="confirmed", tags=["context_only"], criterion="r")
    risk = score(graph(SEED, f), [corr])
    assert risk["score"] == 0.0 and risk["entities"] == {} and risk["excluded"] == {"context_only": 2}


def test_known_good_and_rejected_findings_contribute_nothing():
    good = mk(SEED, "allow-listed", "high", "confirmed", tags=("known_good",))
    rejected = mk(SEED, "listed", "high", "confirmed", tags=("malicious",))
    rejected.apply_override(verdict="false_positive", analyst="ana")
    risk = score(graph(SEED, good, rejected), [])
    assert risk["entities"] == {} and risk["excluded"] == {"analyst_rejected": 1, "known_good": 1}


def test_licence_disabled_sources_contribute_nothing():
    with test_provider("t_lic", sources=("a", "b")):
        allowed = mk(SEED, "listed by a", "high", "confirmed", source="t_lic.a", module="t_agg")
        blocked = mk(SEED, "listed by b", "high", "confirmed", tags=("c2",), source="t_lic.b", module="t_agg")
        coverage = {"coverage": {"t_agg": {"sources": {"t_lic.b": {"status": "skipped", "reason_code": "licence"}}}}, "answered": {}}
        risk = score(graph(SEED, allowed, blocked), [], coverage=coverage)
        assert risk["excluded"] == {"licence": 1}
        assert risk["entities"][SEED.key]["score"] == round(70 * 0.85, 1)  # provider grade B
        whole = {"coverage": {"t_agg": {"entities": {SEED.key: {"status": "skipped", "reason_code": "licence"}}}}}
        assert score(graph(SEED, allowed, blocked), [], coverage=whole)["entities"] == {}


def test_warninglisted_findings_count_as_possible_with_a_label():
    f = mk(SEED, "listed", "high", "confirmed")
    f.suppressed_by.append({"rule": "SUP-warninglist", "reason": "on warninglist t_list"})  # label left confirmed on purpose
    risk = score(graph(SEED, f), [])
    assert risk["entities"][SEED.key]["score"] == 28.0  # 0.7 x POSSIBLE 0.4
    assert risk["contributors"][0]["confidence_label"] == "possible" and "on warninglist" in risk["contributors"][0]["words"]
    analyst = mk(SEED, "listed", "high", "confirmed")
    analyst.suppressed_by.append({"rule": "SUP-warninglist", "reason": "on warninglist t_list", "blocked_by": "analyst"})
    analyst.apply_override(label="confirmed", analyst="ana")
    assert score(graph(SEED, analyst), [])["entities"][SEED.key]["score"] == 70.0  # the analyst wins


# ------------------------------------------------------------------ reliability, dedup, corroboration


def test_admiralty_prior_and_feedback_weights():
    with test_provider("t_rel", sources=("feed",)):
        f = mk(SEED, "listed", "high", "confirmed", source="t_rel.feed", module="t_rel_mod")
        assert score(graph(SEED, f), [])["score"] == round(70 * 0.85, 1)  # grade B prior
        assert score(graph(SEED, f), [], source_reliability={"t_rel.feed": 0.5})["score"] == 35.0
        assert score(graph(SEED, f), [], source_reliability={"t_rel.feed": 0.05})["score"] == 21.0  # floor 0.3
        assert score(graph(SEED, f), [], source_reliability={})["score"] == round(70 * 0.85, 1)
    local = mk(SEED, "offline fact", "high", "confirmed", module="t_local")
    assert score(graph(SEED, local), [])["score"] == 70.0  # no registry source: LOCAL_RELIABILITY 1.0
    assert score(graph(SEED, local), [], {"t_local": 0.5})["score"] == 35.0  # v1 module view
    unknown = mk(SEED, "listed", "high", "confirmed", source="t_nowhere.feed", module="t_local")
    assert score(graph(SEED, unknown), [])["score"] == 70.0  # a free-text source falls back to the module's sources


def test_dedup_per_upstream_family_and_corroboration_by_independent_families():
    shared = {"feed": {"upstream_family": "t_upstream"}}
    with test_provider("t_fa", hosts=("a.example.test",), sources=shared), test_provider("t_fb", hosts=("b.example.test",), sources=shared):
        a = mk(SEED, "listed by a", "high", "probable", source="t_fa.feed", module="t_ma")
        b = mk(SEED, "listed by b", "high", "probable", source="t_fb.feed", module="t_mb")
        same = score(graph(SEED, a, b), [])
        assert same["score"] == round(70 * 0.7 * 0.85, 1)  # one upstream family: counted once, no uplift
    with test_provider("t_fa", hosts=("a.example.test",)), test_provider("t_fb", hosts=("b.example.test",)):
        a = mk(SEED, "listed by a", "high", "probable", source="t_fa.default", module="t_ma")
        b = mk(SEED, "listed by b", "high", "probable", source="t_fb.default", module="t_mb")
        indep = score(graph(SEED, a, b), [])
        assert indep["score"] == round(70 * 1.0 * 0.85, 1)  # 2 independent families: +1 level, not a second term
        assert indep["contributors"][0]["confidence_label"] == "confirmed" and "independent sources" in indep["contributors"][0]["words"]
        other = mk(SEED, "exposed admin panel", "medium", "confirmed", tags=("exposure",), module="t_local")
        mixed = score(graph(SEED, a, b, other), [])
        assert mixed["score"] == round(scoring._noisy_or([0.7 * 0.85, 0.4]) * 100, 1)  # different families: noisy-OR


def test_aggregators_embedding_a_family_are_not_independent():
    embed = {"feed": {"upstream_family": "t_aggfam", "embeds": ["t_fa"]}}
    with test_provider("t_fa", hosts=("a.example.test",)), test_provider("t_agg", hosts=("agg.example.test",), sources=embed):
        a = mk(SEED, "listed by a", "high", "probable", source="t_fa.default", module="t_ma")
        b = mk(SEED, "relayed by agg", "high", "probable", source="t_agg.feed", module="t_mb")
        assert score(graph(SEED, a, b), [])["score"] == round(70 * 0.7 * 0.85, 1)


def test_criticality_and_personal_entities():
    g = graph(SEED, mk(SEED, "listed", "high", "confirmed"))
    g.get(SEED).criticality = "low"
    assert score(g, [])["score"] == round(70 * 0.6, 1)
    email = Entity.make("email", "maria.silva@acme-industria.com.br")
    risk = score(graph(email, mk(email, "in a breach", "medium", "confirmed", tags=("breach",))), [])
    assert risk["no_export"] == [email.key] and risk["entities"][email.key]["personal"] is True
    assert risk["entities"][email.key]["contributors"]  # a personal score is shown only with its contributors


def test_possible_identity_links_never_reach_the_contributors():
    handle = Entity.make("username", "maria_silva")
    link = mk(handle, "same person on two platforms", "medium", "possible", tags=("identity",))
    risk = score(graph(handle, link), [])
    assert risk["score"] > 0 and risk["contributors"] == []


def test_inconclusive_seeds_come_from_the_answered_rows():
    g = graph(SEED, mk(SEED, "listed"))
    other = Entity.make("ipv4", "198.51.100.99")
    g.add_node(other, seed=True)
    answered = {SEED.key: {"reputation_answered": 1}, other.key: {"reputation_answered": 2}}
    assert score(g, [], coverage={"coverage": {}, "answered": answered})["inconclusive"] == [SEED.key]
    assert score(g, [], coverage={"answered": {other.key: {"reputation_answered": 3}}})["inconclusive"] == [SEED.key]
    assert score(g, [])["inconclusive"] == []  # no coverage given: nothing is claimed


# ------------------------------------------------------------------ engine wiring (WP19 review additions)


def flagging(self, entity, ctx):
    res = self.result(entity)
    res.finding("Flagged by the synthetic feed", "high", "synthetic verdict", confidence="possible", criterion="synthetic feed verdict", tags=["malicious"])
    res.finding("Context only", "high", "third-party context", confidence="confirmed", criterion="synthetic context", tags=["malicious", "context_only"])
    return res


FLAGGED = Entity.make("domain", "acme-flagged.com.br")


def investigate(**engine_kw):
    rt = make_runtime(FakeHttp(), clock=FakeClock(NOW))
    return Engine(rt, ScanOptions(include={"t_wp19_flag"}, save_evidence=False), **engine_kw).investigate([FLAGGED])


@pytest.fixture()
def flagger(clean_registry):
    return define_module("t_wp19_flag", ["domain"], flagging)


def test_engine_scores_with_model_v2(flagger):
    case = investigate()
    risk = case.risk
    assert risk["model"] == "v3lum.risk/2" and risk["score"] == 28.0  # high x possible; the context_only one is ignored
    assert risk["excluded"]["context_only"] == 1
    assert risk["inconclusive"] == [FLAGGED.key]  # no reputation-capable source answered
    data = case.to_dict()
    assert data["summary"]["risk_level"] == "low" and data["risk"]["contributors"][0]["finding_id"]
    assert not any("'clean'" in n for n in data["notes"])


def test_engine_passes_source_reliability(clean_registry):
    with test_provider("t_wp19_src", sources=("feed",)) as prov:
        def run(self, entity, ctx):
            res = self.result(entity)
            res.finding("listed", "high", "synthetic", confidence="confirmed", criterion="synthetic feed", tags=["malicious"], source="t_wp19_src.feed")
            return res

        define_module("t_wp19_src_mod", ["domain"], run, disclosure="third_party", provider=prov.id, sources=("t_wp19_src.feed",),
                      hosts=prov.hosts, access_model="free_noauth_unlimited")
        rt = make_runtime(FakeHttp(), clock=FakeClock(NOW))
        opts = ScanOptions(include={"t_wp19_src_mod"}, save_evidence=False)
        prior = Engine(rt, opts).investigate([FLAGGED]).risk
        voted = Engine(make_runtime(FakeHttp(), clock=FakeClock(NOW)), ScanOptions(include={"t_wp19_src_mod"}, save_evidence=False),
                       source_reliability={"t_wp19_src.feed": 0.4}).investigate([FLAGGED]).risk
    assert prior["score"] == round(70 * 0.85, 1) and voted["score"] == 28.0


def test_analyst_override_changes_the_contribution_and_survives_a_rerun(flagger, tmp_path):
    store = Store(tmp_path / "v3lum.db", clock=FakeClock(NOW), health=False)
    try:
        first = investigate()
        auto = next(f for f in first.findings if f.title == "Flagged by the synthetic feed")
        assert auto.label is Confidence.POSSIBLE and first.risk["score"] == 28.0
        store.save_case(first.to_dict())
        store.set_override(auto.id, analyst="ana", label="confirmed", note="seen in our proxy logs", case_id=first.case_id)
        for _ in range(2):  # every later run gets the decision back
            again = investigate(overrides=store.overrides_for)
            f = next(x for x in again.findings if x.id == auto.id)
            assert f.label is Confidence.CONFIRMED and f.override["analyst"] == "ana"
            assert again.risk["score"] == 70.0 and again.risk["contributors"][0]["confidence_label"] == "confirmed"
        store.set_override(auto.id, analyst="ana", verdict="false_positive", case_id=first.case_id)
        rejected = investigate(overrides=store.overrides_for)
        assert rejected.risk["score"] == 0.0 and rejected.risk["excluded"]["analyst_rejected"] == 1
        assert investigate().risk["score"] == 28.0  # without the lookup the automatic label comes back
    finally:
        store.close()


def test_a_failing_override_lookup_never_breaks_the_scan(flagger):
    def broken(ids):
        raise RuntimeError("case DB down")

    case = investigate(overrides=broken)
    assert case.risk["score"] == 28.0
    assert any(n.startswith("analyst overrides not applied") for n in case.notes)


def test_app_engine_feedback_and_path_engine(clean_registry):
    from v3lum import app as app_mod
    from v3lum.ui.theme import make_console

    app = app_mod.App(make_console(no_color=True), fx=False)

    class Stub:
        def reliability(self):
            return {"t_mod": 0.5}

        def source_reliability(self):
            return {"p.s": 0.4}

        def overrides_for(self, ids):
            return {}

    app._store = Stub()
    kw = app._engine_feedback()
    assert kw["reliability"] == {"t_mod": 0.5} and kw["source_reliability"] == {"p.s": 0.4} and callable(kw["overrides"])
    engine = app_mod._PathEngine(make_runtime(FakeHttp()), ScanOptions(), path="run", **kw)
    assert engine.policy_path == "run" and engine.source_reliability == {"p.s": 0.4} and engine.overrides == app._store.overrides_for

    class Broken:
        def reliability(self):
            raise RuntimeError("db locked")

        source_reliability = reliability

    app._store = Broken()
    assert app._engine_feedback() == {}  # priors only, never a failed scan
    assert app_mod.level_at_least("no findings", "low") is False and app_mod.level_at_least("inconclusive", "low") is False
    assert app_mod.level_at_least("high", "medium") is True and app_mod.level_at_least("clean", "low") is False


# ------------------------------------------------------------------ review additions (WP19 review)


def test_personal_scores_never_drive_an_automated_action():
    from v3lum import app as app_mod

    email = Entity.make("email", "maria.silva@acme-industria.com.br")
    risk = score(graph(email, mk(email, "in a breach", "high", "confirmed", tags=("breach",))), [])
    assert risk["score"] == 70.0 and risk["level"] == "high"  # shown (with its contributors)...
    assert risk["automation"]["score"] == 0.0 and risk["automation"]["level"] == "no findings"  # ...never automated
    assert "LGPD" in risk["automation"]["basis"]
    assert risk["top"] == [{"entity": email.key, "score": 70.0, "level": "high", "personal": True}]
    # a correlation naming a person is left out too; facts about the domain itself still count
    g = graph(SEED, mk(SEED, "weak e-mail security", "medium", "confirmed", tags=("weak_email_security",)))
    pivot(g, SEED, email, "contact_email", 0.9, mk(email, "in infostealer logs", "high", "confirmed", tags=("infostealer",)))
    corr = Correlation("t_person", "staff address in stealer logs", Severity.CRITICAL, "synthetic", [SEED, email],
                       confidence="confirmed", criterion="synthetic rule")
    mixed = score(g, [corr])
    assert mixed["level"] == "critical" and mixed["automation"]["score"] == 40.0 and mixed["automation"]["level"] == "medium"
    case = {"summary": {"risk_level": "critical"}, "risk": mixed}
    assert app_mod.level_at_least(case, "high") is False and app_mod.level_at_least(case, "medium") is True
    assert app_mod.level_at_least({"summary": {"risk_level": "high"}}, "high") is True  # a v1 case: its level


def test_reading_is_inconclusive_only_at_the_lowest_level():
    answered = {"answered": {SEED.key: {"reputation_answered": 0}}}
    assert score(graph(SEED), [], coverage=answered)["reading"] == "inconclusive"
    assert score(graph(SEED), [], coverage={"answered": {SEED.key: {"reputation_answered": 2}}})["reading"] == "no findings"
    assert score(graph(SEED, mk(SEED, "listed")), [], coverage=answered)["reading"] == "high"  # never hides a scored risk


def test_offline_analyses_never_corroborate_each_other():
    a = mk(SEED, "lookalike of the brand", "high", "probable", tags=("typosquat",), module="t_local_a")
    b = mk(SEED, "brand keyword in the name", "high", "probable", tags=("typosquat",), module="t_local_b")
    risk = score(graph(SEED, a, b), [])
    assert risk["score"] == 49.0  # one PROBABLE HIGH, no '+1 confidence level' from two derived facts
    assert risk["contributors"][0]["confidence_label"] == "probable"
    with test_provider("t_fx", hosts=("x.example.test",)):
        sourced = mk(SEED, "listed as lookalike", "high", "probable", tags=("typosquat",), source="t_fx.default", module="t_mx")
        assert score(graph(SEED, a, sourced), [])["contributors"][0]["confidence_label"] == "probable"  # one real source only


def test_malformed_reliability_values_are_ignored_not_punished():
    local = mk(SEED, "offline fact", "high", "confirmed", module="t_local")
    for bad in (float("nan"), "garbage", None, float("inf")):
        assert score(graph(SEED, local), [], {"t_local": bad})["score"] == 70.0
    with test_provider("t_rel2", sources=("feed",)):
        f = mk(SEED, "listed", "high", "confirmed", source="t_rel2.feed", module="t_rel2_mod")
        assert score(graph(SEED, f), [], source_reliability={"t_rel2.feed": float("nan")})["score"] == round(70 * 0.85, 1)  # prior B
        assert score(graph(SEED, f), [], source_reliability={"t_rel2.feed": 7})["score"] == 70.0  # clamped to 1.0


def test_reject_verdicts_match_the_case_db():
    from v3lum.core import store

    assert scoring.REJECT_VERDICTS == store.REJECT_VERDICTS


def test_prepare_runtime_installs_one_override_hook(clean_registry):
    from v3lum import app as app_mod
    from v3lum.core.store import OverrideHook
    from v3lum.ui.theme import make_console

    app = app_mod.App(make_console(no_color=True), fx=False)

    class Stub:
        def overrides_for(self, ids):
            return {}

    app._store = Stub()
    rt = make_runtime(FakeHttp())
    for _ in range(2):
        app.prepare_runtime(rt, ScanOptions(), path="scan", audit=False)
    assert sum(isinstance(h, OverrideHook) for h in rt.case_hooks) == 1

    class NoOverrides:
        pass

    app._store = NoOverrides()
    bare = make_runtime(FakeHttp())
    app.prepare_runtime(bare, ScanOptions(), path="scan", audit=False)
    assert not any(isinstance(h, OverrideHook) for h in bare.case_hooks)


def test_override_hook_reaches_engines_built_without_overrides(flagger, tmp_path):
    """`cases resume` builds Engine(rt, options) itself: the hook App.prepare_runtime installs still
    applies the analyst decision (P322 cond 3), and applying it twice changes nothing."""
    from v3lum.core.store import OverrideHook

    store = Store(tmp_path / "v3lum.db", clock=FakeClock(NOW), health=False)
    try:
        first = investigate()
        auto = next(f for f in first.findings if f.title == "Flagged by the synthetic feed")
        store.save_case(first.to_dict())
        store.set_override(auto.id, analyst="ana", label="confirmed", case_id=first.case_id)
        rt = make_runtime(FakeHttp(), clock=FakeClock(NOW))
        rt.case_hooks.append(OverrideHook(store))
        again = Engine(rt, ScanOptions(include={"t_wp19_flag"}, save_evidence=False), overrides=store.overrides_for).investigate([FLAGGED])
        f = next(x for x in again.findings if x.id == auto.id)
        assert f.label is Confidence.CONFIRMED and f.override["auto"]["label"] == "possible"
        assert again.risk["score"] == 70.0
    finally:
        store.close()


def test_cases_table_never_prints_clean(clean_registry):
    from v3lum import app as app_mod
    from v3lum.ui.theme import make_console

    console = make_console(no_color=True, width=200)
    app = app_mod.App(console, fx=False)

    class Stub:
        def list_cases(self, limit, search):
            return [{"id": "c-v1", "created": "2025-01-01T00:00:00", "seeds": ["domain:old-case.com.br"], "risk_level": "clean", "risk_score": 0},
                    {"id": "c-v2", "created": "2026-11-26T00:00:00", "seeds": ["domain:new-case.com.br"], "risk_level": "high", "risk_score": 70}]

    app._store = Stub()
    with console.capture() as cap:
        console.print(app.cases_table())
    out = cap.get()
    assert "clean" not in out and "no findings 0" in out and "high 70" in out


def test_contract_additions_names_resolve():
    """Every backticked v3lum name of docs/contract_additions/WP19.md is importable (plan public_api included)."""
    import importlib
    import re
    from pathlib import Path

    text = (Path(__file__).resolve().parent.parent / "docs" / "contract_additions" / "WP19.md").read_text(encoding="utf-8")
    names = sorted(set(re.findall(r"`(v3lum\.[A-Za-z0-9_.]+)`", text)))
    for required in ("score", "level", "W_SEV", "TAU_DAYS", "DELTA", "A_CRIT", "LEVELS", "decay"):
        assert f"v3lum.core.scoring.{required}" in names
    for required in ("normalize_url_key", "group_findings", "group_correlations", "FindingGroup"):
        assert f"v3lum.core.grouping.{required}" in names
    for name in names:
        parts = name.split(".")
        for cut in range(len(parts), 0, -1):
            try:
                obj = importlib.import_module(".".join(parts[:cut]))
            except ImportError:
                continue
            for attr in parts[cut:]:
                obj = getattr(obj, attr)
            break
        else:  # pragma: no cover - nothing importable
            raise AssertionError(name)
