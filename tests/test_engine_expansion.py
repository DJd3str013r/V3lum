"""AR07 pivot-expansion rules and `cases resume` scheduling (synthetic modules, no network).

* ``Node.path_confidence`` = max over seed paths of the product of edge confidences (incremental);
* no auto-expansion below setting ``min_expand_confidence`` (0.5), for POSSIBLE identity pivots,
  for ``similar_to`` (P333 cond 10), for warninglisted values or for SECRET_TYPES;
* from text/file/e-mail-header parents only IOC_TYPES auto-expand; PERSONAL_TYPES become
  ``expand=False`` entries of ``case.pending_personal`` unless ``expand_personal`` + a purpose;
* ``only_pairs`` (resume) runs exactly the recorded pairs with their recorded RunInfo.
"""

from __future__ import annotations

import pytest

from tests.fakes import FakeHttp, allow_vocab, define_module, make_runtime
from v3lum.core import noise
from v3lum.core.context import ScanOptions
from v3lum.core.engine import Engine
from v3lum.core.entities import Entity
from v3lum.core.entities import EntityType as T
from v3lum.core.graph import Graph

SEED = Entity.make("domain", "example.org")
JWT = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dozjgNryP4J3jVmNHl0w5N_XgL0n3I9PlFUP0THsR8U"


@pytest.fixture()
def registry(clean_registry):
    clean_registry.clear()  # only the synthetic modules of the test are candidates
    with allow_vocab(attributes=("ran",)):
        yield clean_registry


def recorder(seen: list[str], pivots=()):
    def run(self, entity, ctx):
        seen.append(entity.key)
        res = self.result(entity)
        if entity == SEED:
            for etype, value, relation, kw in pivots:
                res.pivot(etype, value, relation, **kw)
        return res

    return run


def scan(seeds, *, settings=None, **opts):
    rt = make_runtime(FakeHttp(), settings=settings)
    return Engine(rt, ScanOptions(**opts)).investigate(list(seeds))


# ------------------------------------------------------------------ path confidence
def test_path_confidence_is_the_best_product_over_seed_paths():
    g = Graph()
    a, b, c, d = (Entity.make("domain", f"{x}.example") for x in "abcd")
    g.add_node(a, 0, seed=True)
    g.add_node(b, 1)
    assert g.get(b).path_confidence == 0.0  # not reached from a seed yet
    g.add_edge(a, b, "related", "m", 0.9)
    g.add_node(c, 2)
    g.add_edge(b, c, "related", "m", 0.8)
    assert g.get(c).path_confidence == pytest.approx(0.72)
    g.add_edge(a, c, "related", "m", 0.6)  # a worse direct path keeps the best product
    assert g.get(c).path_confidence == pytest.approx(0.72)
    g.add_node(d, 3)
    g.add_edge(c, d, "related", "m", 0.5)
    assert g.get(d).path_confidence == pytest.approx(0.36)
    g.add_edge(a, b, "subdomain", "m", 1.0)  # a better path to b propagates downstream
    assert (g.get(b).path_confidence, g.get(c).path_confidence, g.get(d).path_confidence) == pytest.approx((1.0, 0.8, 0.4))
    assert g.get(a).path_confidence == 1.0 and g.get(d).to_dict()["path_confidence"] == 0.4
    g.add_node(d, 0, seed=True)  # becoming a seed: 1.0
    assert g.get(d).path_confidence == 1.0
    stored = Graph.from_dict(g.to_dict())  # stored values are kept as they are
    assert stored.get(c).path_confidence == pytest.approx(0.8)


def test_engine_records_path_confidence(registry):
    def dom(self, entity, ctx):
        res = self.result(entity)
        if entity == SEED:
            res.pivot(T.DOMAIN, "a.example.org", "subdomain", confidence=0.9)
        else:
            res.pivot(T.DOMAIN, "b.example.org", "related", confidence=0.8)
        return res

    define_module("t_pc", [T.DOMAIN], dom)
    case = scan([SEED], include={"t_pc"}, depth=2)
    assert case.graph.get(Entity.make("domain", "b.example.org")).path_confidence == pytest.approx(0.72)


# ------------------------------------------------------------------ thresholds and relations
def test_min_expand_confidence(registry):
    seen: list[str] = []
    pivots = [(T.IPV4, "45.33.32.5", "resolves_to", {"confidence": 0.4}), (T.IPV4, "45.33.32.6", "resolves_to", {"confidence": 0.6})]
    define_module("t_mec_dom", [T.DOMAIN], recorder([], pivots))
    define_module("t_mec_ip", [T.IPV4], recorder(seen))
    scan([SEED], include={"t_mec_dom", "t_mec_ip"})
    assert seen == ["ipv4:45.33.32.6"]
    seen.clear()
    scan([SEED], include={"t_mec_dom", "t_mec_ip"}, settings={"min_expand_confidence": 0.3})
    assert sorted(seen) == ["ipv4:45.33.32.5", "ipv4:45.33.32.6"]


def test_possible_identity_pivots_are_not_expanded(registry):
    seen: list[str] = []
    pivots = [
        (T.USERNAME, "jdoe_possible", "uses_username", {"confidence": "possible"}),
        (T.USERNAME, "jdoe_probable", "uses_username", {"confidence": "probable"}),
        (T.USERNAME, "jdoe_related", "related", {"confidence": "possible"}),
    ]
    define_module("t_id_dom", [T.DOMAIN], recorder([], pivots))
    define_module("t_id_user", [T.USERNAME], recorder(seen))
    case = scan([SEED], include={"t_id_dom", "t_id_user"}, purpose="incident 42", settings={"min_expand_confidence": 0.1})
    assert sorted(seen) == ["username:jdoe_probable", "username:jdoe_related"]
    assert case.graph.get(Entity.make("username", "jdoe_possible")) is not None  # listed, not investigated
    assert not case.graph.get(Entity.make("username", "jdoe_possible")).investigated


def test_similar_to_never_expands(registry):
    seen: list[str] = []
    define_module("t_sim_dom", [T.DOMAIN], recorder(seen, [(T.DOMAIN, "examp1e.org", "similar_to", {"confidence": 0.95})]))
    case = scan([SEED], include={"t_sim_dom"})
    assert seen == ["domain:example.org"]
    assert not case.graph.get(Entity.make("domain", "examp1e.org")).investigated


def test_secrets_never_expand(registry):
    seen: list[str] = []
    define_module("t_sec_dom", [T.DOMAIN], recorder([], [(T.JWT, JWT, "related", {"expand": True})]))
    define_module("t_sec_jwt", [T.JWT], recorder(seen))
    case = scan([SEED], include={"t_sec_dom", "t_sec_jwt"})
    assert seen == []
    jwt_nodes = [n for n in case.graph.nodes.values() if n.entity.type is T.JWT]
    assert len(jwt_nodes) == 1 and not jwt_nodes[0].investigated


def test_warninglisted_values_are_listed_not_expanded(registry, monkeypatch):
    seen: list[str] = []
    listed = Entity.make("ipv4", "45.33.32.70")
    real = noise.warninglists
    monkeypatch.setattr(noise, "warninglists", lambda entity: ["t_list"] if entity == listed else real(entity))
    pivots = [(T.IPV4, listed.value, "resolves_to", {}), (T.IPV4, "45.33.32.71", "resolves_to", {})]
    define_module("t_wl_dom", [T.DOMAIN], recorder([], pivots))
    define_module("t_wl_ip", [T.IPV4], recorder(seen))
    case = scan([SEED], include={"t_wl_dom", "t_wl_ip"})
    assert seen == ["ipv4:45.33.32.71"]
    assert case.graph.get(listed) is not None and not case.graph.get(listed).investigated


# ------------------------------------------------------------------ text/file parents
TEXT = Entity.make("text_blob", "phishing report: login at evil.example and write to someone@corp.example (Example Org)")


def text_extractor():
    def run(self, entity, ctx):
        res = self.result(entity)
        res.pivot(T.DOMAIN, "evil.example", "mentions")
        res.pivot(T.EMAIL, "someone@corp.example", "mentions")
        res.pivot(T.ORG, "Example Org", "mentions")
        return res

    return run


def test_text_parents_expand_only_iocs_and_list_personal_values(registry):
    seen: list[str] = []
    define_module("t_txt", [T.TEXT], text_extractor())
    define_module("t_txt_dom", [T.DOMAIN], recorder(seen))
    define_module("t_txt_mail", [T.EMAIL], recorder(seen))
    define_module("t_txt_org", [T.ORG], recorder(seen))
    case = scan([TEXT], include={"t_txt", "t_txt_dom", "t_txt_mail", "t_txt_org"})
    assert seen == ["domain:evil.example"]
    assert case.pending_personal == [{"entity": "email:someone@corp.example", "parent": TEXT.key, "relation": "mentions"}]
    res = next(r for r in case.results if r.module == "t_txt")
    assert {p.entity.key: p.expand for p in res.pivots}["email:someone@corp.example"] is False
    assert case.to_dict()["pending_personal"] == case.pending_personal
    edge = next(e for e in case.graph.edges if e.dst == "email:someone@corp.example")
    assert edge.expand is False


def test_expand_personal_with_a_purpose_expands_them(registry):
    seen: list[str] = []
    define_module("t_txt2", [T.TEXT], text_extractor())
    define_module("t_txt2_mail", [T.EMAIL], recorder(seen))
    case = scan([TEXT], include={"t_txt2", "t_txt2_mail"}, expand_personal=True, purpose="phishing triage INC-7")
    assert seen == ["email:someone@corp.example"] and case.pending_personal == []
    seen.clear()
    case = scan([TEXT], include={"t_txt2", "t_txt2_mail"}, expand_personal=True)  # no purpose: still listed
    assert seen == [] and [p["entity"] for p in case.pending_personal] == ["email:someone@corp.example"]


def test_text_parents_keep_the_input_list_cap(registry):
    seen: list[str] = []

    def many(self, entity, ctx):
        res = self.result(entity)
        for i in range(30):
            res.pivot(T.IPV4, f"45.33.33.{i + 1}", "mentions")
        return res

    define_module("t_txt_many", [T.TEXT], many, max_pivots=100)
    define_module("t_txt_many_ip", [T.IPV4], recorder(seen))
    scan([TEXT], include={"t_txt_many", "t_txt_many_ip"}, max_entities=500)
    assert len(seen) == 30  # INPUT_LIST_CAP, not EXPAND_CAP[IPV4] = 10


# ------------------------------------------------------------------ resume (only_pairs)
def test_resumed_pairs_keep_their_recorded_run_info(registry):
    seen: dict[str, tuple] = {}
    ip = Entity.make("ipv4", "45.33.32.9")

    def ip_run(self, entity, ctx):
        seen[self.name] = (ctx.is_seed, ctx.depth, ctx.provenance, ctx.tlp)
        res = self.result(entity)
        res.pivot(T.DOMAIN, "next.example", "hosted_domain")
        return res

    define_module("t_res_ip", [T.IPV4], ip_run)
    define_module("t_res_other", [T.IPV4], ip_run)
    define_module("t_res_dom", [T.DOMAIN], recorder([]))
    define_module("t_res_optin", [T.IPV4], ip_run, default_enabled=False)
    recorded = {"is_seed": False, "depth": 1, "provenance": [[SEED.key, "resolves_to", "t_res_dom"]], "tlp": "amber+strict"}
    pairs = {("t_res_ip", ip.key): recorded, ("t_res_optin", ip.key): recorded}
    eng = Engine(make_runtime(FakeHttp()), ScanOptions())
    case = eng.investigate([SEED, ip], only_pairs=pairs)  # the ip is passed again: never promoted to a typed seed
    expected = (False, 1, ((SEED.key, "resolves_to", "t_res_dom"),), "amber+strict")
    assert seen == {"t_res_ip": expected, "t_res_optin": expected}  # the analyst asked for these pairs
    assert {r.module for r in case.results} == {"t_res_ip", "t_res_optin"}
    nxt = case.graph.get(Entity.make("domain", "next.example"))
    assert nxt is not None and not nxt.investigated  # recorded, not expanded
    # the same through ScanOptions.only_pairs
    seen.clear()
    case = Engine(make_runtime(FakeHttp()), ScanOptions(only_pairs={("t_res_ip", ip.key): recorded})).investigate([SEED])
    assert seen == {"t_res_ip": expected} and [r.module for r in case.results] == ["t_res_ip"]


def test_facts_and_findings_never_move_a_node(registry):
    """Recording an attribute or a finding keeps the node where the BFS put it (a pivot two hops
    away is reported at depth 2, not 0)."""
    from v3lum.core.models import Finding, Severity

    g = Graph()
    seed, far = Entity.make("domain", "example.org"), Entity.make("ipv4", "45.33.32.90")
    g.add_node(seed, 0, seed=True)
    g.add_node(far, 2)
    g.add_attributes(far, {"country": "BR"}, "t_mod")
    g.add_finding(Finding(module="t_mod", entity=far, title="seen", severity=Severity.INFO))
    assert g.get(far).depth == 2 and g.get(far).path_confidence == 0.0 and not g.get(far).seed

    def dom(self, entity, ctx):
        res = self.result(entity)
        res.pivot(T.IPV4, "45.33.32.91", "resolves_to")
        return res

    def ip(self, entity, ctx):
        res = self.result(entity)
        res.attr("ran", True)
        res.finding("hosting facts", "info", tags=["infrastructure"])
        return res

    define_module("t_depth_dom", [T.DOMAIN], dom)
    define_module("t_depth_ip", [T.IPV4], ip)
    case = scan([SEED], include={"t_depth_dom", "t_depth_ip"})
    stored = {n["key"]: n["depth"] for n in case.to_dict()["entities"]}
    assert stored == {SEED.key: 0, "ipv4:45.33.32.91": 1}
