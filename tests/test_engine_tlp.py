"""A2/AR17 TLP in the engine: per-seed TLP, inheritance by pivots and extracted entities, platform
markings raising entity and case TLP, LIGHT/ACTIVE cases at least AMBER, and secrets never written
raw (item 12: SECRET_TYPES values through ``entities.redacted_value``)."""

from __future__ import annotations

import pytest

from tests.fakes import FakeHttp, assert_no_secret, define_module, make_runtime
from v3lum.core.context import ScanOptions
from v3lum.core.engine import Engine
from v3lum.core.entities import Entity
from v3lum.core.entities import EntityType as T
from v3lum.core.models import Opsec

A = Entity.make("domain", "a.example")
B = Entity.make("domain", "b.example")
JWT = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dozjgNryP4J3jVmNHl0w5N_XgL0n3I9PlFUP0THsR8U"


@pytest.fixture()
def registry(clean_registry):
    clean_registry.clear()  # only the synthetic modules of the test are candidates
    return clean_registry


def scan(seeds, **opts):
    return Engine(make_runtime(FakeHttp()), ScanOptions(**opts)).investigate(list(seeds))


def tlp_of(case, entity) -> str:
    return case.graph.get(entity).tlp


def test_inheritance_seed_to_pivot_to_extracted(registry):
    seen: dict[str, str] = {}

    def dom(self, entity, ctx):
        seen[entity.key] = ctx.tlp
        res = self.result(entity)
        if entity == A:
            res.pivot(T.DOMAIN, "child-a.example", "related")
            res.pivot(T.DOMAIN, "shared.example", "related")
        elif entity == B:
            res.pivot(T.DOMAIN, "child-b.example", "related")
            res.pivot(T.DOMAIN, "shared.example", "related")
        return res

    def text(self, entity, ctx):
        res = self.result(entity)
        res.pivot(T.DOMAIN, "from-text.example", "mentions")
        return res

    blob = Entity.make("text_blob", "indicator from a report: from-text.example")
    define_module("t_tlp_dom", [T.DOMAIN], dom)
    define_module("t_tlp_txt", [T.TEXT], text)
    case = scan([A, B, blob], include={"t_tlp_dom", "t_tlp_txt"}, tlp="green", seed_tlp={A.key: "amber+strict"})
    assert (tlp_of(case, A), tlp_of(case, B), tlp_of(case, blob)) == ("amber+strict", "green", "green")
    assert tlp_of(case, Entity.make("domain", "child-a.example")) == "amber+strict"
    assert tlp_of(case, Entity.make("domain", "child-b.example")) == "green"
    assert tlp_of(case, Entity.make("domain", "shared.example")) == "amber+strict"  # the highest parent wins
    assert tlp_of(case, Entity.make("domain", "from-text.example")) == "green"  # extracted: the input's TLP
    assert seen["domain:child-a.example"] == "amber+strict" and seen["domain:child-b.example"] == "green"  # ctx.tlp
    assert case.tlp == "amber+strict" and case.to_dict()["tlp"] == "amber+strict"
    stored = {n["key"]: n["tlp"] for n in case.to_dict()["entities"]}
    assert stored[A.key] == "amber+strict" and stored["domain:child-b.example"] == "green"


def test_result_markings_raise_entity_and_case_tlp(registry):
    def marked(self, entity, ctx):
        res = self.result(entity)
        if entity == A:
            res.set_marking("TLP:RED")  # e.g. a MISP event tagged tlp:red (A12)
            res.pivot(T.DOMAIN, "from-red-event.example", "related")
        return res

    define_module("t_marked", [T.DOMAIN], marked)
    case = scan([A, B], include={"t_marked"}, tlp="green")
    assert tlp_of(case, A) == "red" and tlp_of(case, B) == "green"
    assert tlp_of(case, Entity.make("domain", "from-red-event.example")) == "red"
    assert case.tlp == "red"


def test_light_and_active_cases_are_at_least_amber(registry):
    define_module("t_tlp_passive", [T.DOMAIN], lambda self, e, c: self.result(e))
    case = scan([A], include={"t_tlp_passive"}, tlp="clear", mode=Opsec.LIGHT)
    assert case.tlp == "amber" and tlp_of(case, A) == "amber"
    assert any("TLP raised to AMBER" in n for n in case.notes)
    passive = scan([A], include={"t_tlp_passive"}, tlp="clear")
    assert passive.tlp == "clear" and not any("TLP raised" in n for n in passive.notes)


def test_unreadable_seed_tlp_fails_closed_to_red(registry):
    define_module("t_tlp_bad", [T.DOMAIN], lambda self, e, c: self.result(e))
    case = scan([A], include={"t_tlp_bad"}, seed_tlp={A.key: "not-a-tlp"})
    assert tlp_of(case, A) == "red" and case.tlp == "red"


def test_secret_values_are_written_redacted(registry):
    def leak(self, entity, ctx):
        res = self.result(entity)
        res.pivot(T.JWT, JWT, "related", expand=False)
        return res

    define_module("t_tlp_jwt", [T.DOMAIN], leak)
    case = scan([A], include={"t_tlp_jwt"})
    jwt_node = next(n for n in case.graph.nodes.values() if n.entity.type is T.JWT)
    data = case.to_dict()
    assert_no_secret(JWT, data)
    stored = next(n for n in data["entities"] if n["type"] == "jwt")
    assert stored["value"] == jwt_node.entity.redacted and stored["key"] == f"jwt:{jwt_node.entity.redacted}"
    assert any(e["dst"] == stored["key"] for e in data["edges"])  # references stay consistent
    assert_no_secret(JWT, case.graph.to_dict())
