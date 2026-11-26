"""Core suppression stage at the start of ``_finish`` (P322 cond 4/8, P302 cond 7, A4 BR6).

Named rules recorded through ``Finding.downgrade``: SUP-warninglist ('POSSIBLE - on warninglist
<name>'), SUP-sinkhole ('POSSIBLE - sinkhole' + context_only), SUP-generic_address (breach and
infostealer findings on generic/role/test addresses capped at POSSIBLE + context_only). Suppression
only downgrades, never deletes and never crosses an analyst override; ``on_before_finish`` hooks
run before it, before correlations and before scoring.
"""

from __future__ import annotations

from datetime import datetime, timezone

import pytest

from tests.fakes import FakeHttp, define_module, make_runtime
from v3lum.core import noise
from v3lum.core.context import ScanOptions
from v3lum.core.engine import Engine, suppress
from v3lum.core.entities import Entity
from v3lum.core.entities import EntityType as T
from v3lum.core.models import Confidence

LISTED = Entity.make("domain", "listed.example")
SINKHOLE = Entity.make("ipv4", "45.33.32.66")
ROLE = Entity.make("email", "contato@acme-industria.com.br")  # a role mailbox (not an example domain)


@pytest.fixture()
def registry(clean_registry):
    clean_registry.clear()  # only the synthetic modules of the test are candidates
    return clean_registry


def verdicts(self, entity, ctx):
    res = self.result(entity)
    res.finding("listed as malicious", "high", tags=["malicious"], confidence="confirmed", criterion="synthetic feed listing")
    res.finding("hosting facts", "info", tags=["infrastructure"], confidence="confirmed")
    return res


def scan(seeds, *, rt=None, **opts):
    return Engine(rt or make_runtime(FakeHttp()), ScanOptions(**opts)).investigate(list(seeds))


def finding(case, title):
    return next(f for f in case.graph.findings() if f.title == title)


def test_warninglisted_entities_get_their_hostile_findings_downgraded(registry, monkeypatch):
    real = noise.warninglists
    monkeypatch.setattr(noise, "warninglists", lambda entity: ["t_cdn_list"] if entity == LISTED else real(entity))
    define_module("t_sup_wl", [T.DOMAIN], verdicts)
    case = scan([LISTED], include={"t_sup_wl"})
    hostile, info = finding(case, "listed as malicious"), finding(case, "hosting facts")
    assert hostile.label is Confidence.POSSIBLE and hostile.criterion.startswith("POSSIBLE - on warninglist t_cdn_list")
    assert hostile.suppressed_by[0]["rule"] == "SUP-warninglist" and "context_only" not in hostile.tags
    assert info.label is Confidence.CONFIRMED and not info.suppressed_by
    assert len(case.graph.findings()) == 2  # never deleted
    stored = next(f for f in case.to_dict()["findings"] if f["title"] == "listed as malicious")
    assert stored["confidence_label"] == "possible" and stored["suppressed_by"][0]["rule"] == "SUP-warninglist"


def test_sinkholed_entities_keep_their_findings_as_context(registry, monkeypatch):
    real = noise.noise_kinds
    monkeypatch.setattr(noise, "noise_kinds", lambda entity: frozenset({"sinkhole"}) if entity == SINKHOLE else real(entity))
    define_module("t_sup_sink", [T.IPV4], verdicts)
    case = scan([SINKHOLE], include={"t_sup_sink"})
    hostile = finding(case, "listed as malicious")
    assert hostile.label is Confidence.POSSIBLE and hostile.criterion.startswith("POSSIBLE - sinkhole")
    assert "context_only" in hostile.tags and hostile.suppressed_by[0]["rule"] == "SUP-sinkhole"
    assert case.graph.get(SINKHOLE).tagged("sinkhole")


def test_breach_findings_on_generic_addresses_are_capped(registry):
    def breach(self, entity, ctx):
        res = self.result(entity)
        res.finding("address in a data breach", "high", tags=["breach"], confidence="confirmed", criterion="synthetic breach listing")
        res.finding("mailbox exists", "info", confidence="confirmed")
        return res

    define_module("t_sup_breach", [T.EMAIL], breach)
    case = scan([ROLE], include={"t_sup_breach"}, purpose="exposure review SEC-9")
    capped, other = finding(case, "address in a data breach"), finding(case, "mailbox exists")
    assert capped.label is Confidence.POSSIBLE and "context_only" in capped.tags
    assert capped.suppressed_by[0]["rule"] == "SUP-generic_address" and "generic address (role)" in capped.criterion
    assert other.label is Confidence.CONFIRMED and not other.suppressed_by
    personal = scan([Entity.make("email", "maria.silva@acme-industria.com.br")], include={"t_sup_breach"}, purpose="exposure review SEC-9")
    assert finding(personal, "address in a data breach").label is Confidence.CONFIRMED


def test_suppression_never_crosses_an_analyst_override(registry, monkeypatch):
    real = noise.warninglists
    monkeypatch.setattr(noise, "warninglists", lambda entity: ["t_cdn_list"] if entity == LISTED else real(entity))

    class Analyst:
        def on_before_finish(self, case):
            for f in case.graph.findings():
                if f.title == "listed as malicious":
                    f.apply_override(label="confirmed", verdict="malicious", analyst="ana", note="seen in our logs", at="2026-11-26T10:00:00Z")

    define_module("t_sup_override", [T.DOMAIN], verdicts)
    rt = make_runtime(FakeHttp())
    rt.case_hooks.append(Analyst())
    case = scan([LISTED], rt=rt, include={"t_sup_override"})
    hostile = finding(case, "listed as malicious")
    assert hostile.label is Confidence.CONFIRMED and "context_only" not in hostile.tags
    assert hostile.suppressed_by == [{"rule": "SUP-warninglist", "reason": "on warninglist t_cdn_list", "blocked_by": "analyst"}]


def test_on_before_finish_runs_before_suppression_correlations_and_scoring(registry, monkeypatch):
    real = noise.warninglists
    monkeypatch.setattr(noise, "warninglists", lambda entity: ["t_cdn_list"] if entity == LISTED else real(entity))
    seen: dict[str, object] = {}
    other = Entity.make("domain", "unlisted.example")

    class Probe:
        def on_before_finish(self, case):
            seen["label"] = next(f.label for f in case.graph.get(LISTED).findings if f.title == "listed as malicious")
            seen["correlations"] = list(case.correlations)
            seen["risk"] = dict(case.risk)

    define_module("t_sup_a", [T.DOMAIN], verdicts)
    define_module("t_sup_b", [T.DOMAIN], verdicts)
    rt = make_runtime(FakeHttp())
    rt.case_hooks.append(Probe())
    case = scan([LISTED, other], rt=rt, include={"t_sup_a", "t_sup_b"})
    assert seen == {"label": Confidence.CONFIRMED, "correlations": [], "risk": {}}
    assert case.risk  # computed afterwards, on the suppressed findings
    consensus = [c for c in case.correlations if c.rule == "multi_source_malicious"]
    # P171 cond 5: suppression runs before consensus - the warninglisted entity's two verdicts were
    # downgraded and support no correlation; the unlisted entity's two verdicts still do
    assert [c.entity_keys() for c in consensus] == [[other.key]]
    assert all(f.label is Confidence.POSSIBLE for f in case.graph.get(LISTED).findings if "malicious" in f.tags)
    assert all(f.label is Confidence.CONFIRMED for f in case.graph.get(other).findings)


def test_each_rule_applies_once(registry, monkeypatch):
    real = noise.warninglists
    monkeypatch.setattr(noise, "warninglists", lambda entity: ["t_cdn_list"] if entity == LISTED else real(entity))
    define_module("t_sup_once", [T.DOMAIN], verdicts)
    case = scan([LISTED], include={"t_sup_once"})
    assert suppress(case) == 0  # a second pass changes nothing
    assert len(finding(case, "listed as malicious").suppressed_by) == 1


# ------------------------------------------------------------------ legacy rules after suppression
def _rules(graph, only, rctx=None):
    from v3lum.core import correlate

    correlate.load_rules()
    return {(c.rule, tuple(c.entity_keys())): c for c in correlate.run_rules(graph, [], only=set(only), rctx=rctx)}


def _flagged(entity, module, *, tags=("malicious",), suppressed=None, override=None, context_only=False):
    from v3lum.core.models import Finding, Severity

    f = Finding(module=module, entity=entity, title=f"{module} verdict", severity=Severity.HIGH, criterion="synthetic verdict", tags=list(tags))
    if suppressed:
        f.downgrade(suppressed, "synthetic suppression", to=Confidence.POSSIBLE)
    if context_only:
        f.tags.append("context_only")
    if override:
        f.apply_override(**override)
    return f


def test_suppressed_and_context_only_findings_support_no_correlation():
    """P171 cond 5 / A4 BR6: findings downgraded by a SUP-* rule or tagged context_only are no
    evidence for the legacy consensus and high-signal rules; an analyst override restores a finding
    as evidence unless its verdict is a false positive."""
    from v3lum.core.graph import Graph

    g = Graph()
    a, b, c, d = (Entity.make("domain", f"{x}.example") for x in ("plain", "suppressed", "context", "overridden"))
    for ent in (a, b, c, d):
        g.add_node(ent, 0, seed=True)
    for mod in ("m1", "m2"):
        g.add_finding(_flagged(a, mod))
        g.add_finding(_flagged(b, mod, suppressed="SUP-warninglist"))
        g.add_finding(_flagged(c, mod, context_only=True))
    g.add_finding(_flagged(d, "m1", suppressed="SUP-warninglist", override={"label": "confirmed", "verdict": "malicious", "analyst": "ana"}))
    g.add_finding(_flagged(d, "m2", override={"label": "possible", "verdict": "false_positive", "analyst": "ana"}))
    g.add_finding(_flagged(c, "m3", tags=("credential_exposure",), context_only=True))
    out = _rules(g, {"multi_source_malicious", "high_signal_tags"})
    assert set(out) == {("multi_source_malicious", (a.key,))}
    g.add_finding(_flagged(d, "m3"))  # a second real verdict next to the analyst-confirmed one
    assert ("multi_source_malicious", (d.key,)) in _rules(g, {"multi_source_malicious"})


def test_malicious_flags_on_a_sinkholed_entity_are_no_consensus(monkeypatch):
    from v3lum.core.graph import Graph

    real = noise.noise_kinds
    monkeypatch.setattr(noise, "noise_kinds", lambda entity: frozenset({"sinkhole"}) if entity == SINKHOLE else real(entity))
    g = Graph()
    node, _ = g.add_node(SINKHOLE, 0, seed=True)
    assert node.tagged("sinkhole")
    g.add_attributes(SINKHOLE, {"malicious": True}, "m1")
    g.add_attributes(SINKHOLE, {"malicious": True}, "m2")
    assert _rules(g, {"multi_source_malicious"}) == {}
    other = Entity.make("ipv4", "45.33.32.67")
    g.add_node(other, 0, seed=True)
    g.add_attributes(other, {"malicious": True}, "m1")
    g.add_attributes(other, {"malicious": True}, "m2")
    assert set(_rules(g, {"multi_source_malicious"})) == {("multi_source_malicious", (other.key,))}


def test_breach_and_infostealer_respects_generic_and_third_party_addresses():
    """A4 BR6/BR9-BR10 (P146 cond 2, 5-7): never for generic/role/test addresses; MEDIUM context
    for anything that is not a verified own asset; HIGH only for a verified own address."""
    from v3lum.core import correlate
    from v3lum.core.graph import Graph
    from v3lum.core.orgprofile import OrgProfile

    org = OrgProfile.from_dict({"org": {"name": "Acme"}, "domains": [
        {"name": "acme-industria.com.br", "verification": "txt_verified", "criticality": "high"},
        {"name": "acme-seeded.com.br", "verification": "confirmed"},
    ]})
    rctx = correlate.RuleContext(now=datetime(2026, 11, 26, tzinfo=timezone.utc), org=org)
    g = Graph()
    own = Entity.make("email", "maria.silva@acme-industria.com.br")
    unverified = Entity.make("email", "joao.souza@acme-seeded.com.br")
    third = Entity.make("email", "carla.mendes@partner-firm.com.br")
    for ent, ownership in ((ROLE, "own_asset"), (own, "own_asset"), (unverified, "own_asset"), (third, "third_party")):
        node, _ = g.add_node(ent, 0, seed=True)
        node.ownership = ownership
        g.add_finding(_flagged(ent, "t_breach", tags=("breach",)))
        g.add_finding(_flagged(ent, "t_stealer", tags=("infostealer",)))
    out = _rules(g, {"breach_and_infostealer"}, rctx)
    sev = {keys[0]: (c.severity.label, "context_only" in c.tags) for (_rule, keys), c in out.items()}
    assert ROLE.key not in sev  # a role mailbox is never scored as exposure
    assert sev == {own.key: ("high", False), unverified.key: ("medium", True), third.key: ("medium", True)}
