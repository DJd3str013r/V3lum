"""Engine behaviour with synthetic modules (no network)."""

from __future__ import annotations

import hashlib
import json
from pathlib import Path

import pytest

from tests.fakes import FakeHttp, make_runtime
from v3lum.core import module as modreg
from v3lum.core.context import ScanOptions
from v3lum.core.engine import Engine
from v3lum.core.entities import Entity
from v3lum.core.entities import EntityType as T
from v3lum.core.http import RateLimited
from v3lum.core.models import Opsec, Status
from v3lum.core.module import Module, register


@pytest.fixture()
def registry():
    modreg.load_modules()
    saved = dict(modreg.REGISTRY)
    yield modreg.REGISTRY
    modreg.REGISTRY.clear()
    modreg.REGISTRY.update(saved)


def define(registry, name, accepts, run, **attrs):
    cls = type(name, (Module,), {"name": name, "accepts": set(accepts), "category": attrs.pop("category", "utility"), "run": run, **attrs})
    return register(cls)


def scan(seeds, include, **opts):
    rt = make_runtime(FakeHttp())
    options = ScanOptions(include=set(include), **opts)
    return Engine(rt, options).investigate([Entity.make(t, v) for t, v in seeds])


def test_findings_attributes_and_pivots(registry):
    def run(self, entity, ctx):
        res = self.result(entity)
        res.attr("country", "BR")
        res.finding("bad thing", "high", tags=["malicious"])
        res.pivot(T.IPV4, "203.0.113.10", "resolves_to")
        return res

    define(registry, "t_dom", [T.DOMAIN], run)
    case = scan([("domain", "example.org")], ["t_dom"], depth=0)
    node = case.graph.get(Entity.make("domain", "example.org"))
    assert node.attr("country") == "BR"
    assert [f.title for f in node.findings] == ["bad thing"]
    assert case.graph.get(Entity.make("ipv4", "203.0.113.10")) is not None
    assert not case.graph.get(Entity.make("ipv4", "203.0.113.10")).investigated  # depth 0
    d = case.to_dict()
    assert d["summary"]["findings"] == 1 and d["edges"][0]["relation"] == "resolves_to"


def test_depth_and_expand_flags(registry):
    calls = []

    def dom(self, entity, ctx):
        calls.append(entity.key)
        res = self.result(entity)
        res.pivot(T.IPV4, "45.33.32.1", "resolves_to")
        res.pivot(T.IPV4, "45.33.32.2", "resolves_to", expand=False)
        res.pivot(T.PERSON, "Jane Roe", "registrant")  # never auto-expanded
        return res

    def ip(self, entity, ctx):
        calls.append(entity.key)
        res = self.result(entity)
        res.pivot(T.DOMAIN, "deeper.example.net", "hosted_domain")
        return res

    define(registry, "t_dom2", [T.DOMAIN], dom)
    define(registry, "t_ip2", [T.IPV4], ip)
    case = scan([("domain", "example.org")], ["t_dom2", "t_ip2"], depth=1)
    assert "ipv4:45.33.32.1" in calls
    assert "ipv4:45.33.32.2" not in calls
    assert "domain:deeper.example.net" not in calls  # depth 2 not allowed
    assert case.graph.get(Entity.make("domain", "deeper.example.net")) is not None
    case2 = scan([("domain", "example.org")], ["t_dom2", "t_ip2"], depth=2)
    assert case2.graph.get(Entity.make("domain", "deeper.example.net")).investigated


def test_noise_not_expanded(registry):
    seen = []

    def dom(self, entity, ctx):
        seen.append(entity.value)
        res = self.result(entity)
        res.pivot(T.DOMAIN, "gmail.com", "related")
        res.pivot(T.IPV4, "8.8.8.8", "resolves_to")
        return res

    define(registry, "t_noise", [T.DOMAIN, T.IPV4], dom)
    case = scan([("domain", "example.org")], ["t_noise"], depth=3)
    assert seen == ["example.org"]
    assert case.graph.get(Entity.make("domain", "gmail.com")).noise


def test_per_parent_cap(registry):
    def dom(self, entity, ctx):
        res = self.result(entity)
        if entity.value == "example.org":
            for i in range(30):
                res.pivot(T.DOMAIN, f"s{i}.example.org", "subdomain")
        return res

    define(registry, "t_cap", [T.DOMAIN], dom)
    case = scan([("domain", "example.org")], ["t_cap"], depth=1)
    investigated = [n for n in case.graph.nodes.values() if n.investigated]
    assert len(investigated) == 1 + 12  # EXPAND_CAP[DOMAIN]


def test_errors_are_isolated(registry):
    def boom(self, entity, ctx):
        raise RuntimeError("module bug")

    def limited(self, entity, ctx):
        raise RateLimited("slow down", 429)

    def fine(self, entity, ctx):
        res = self.result(entity)
        res.attr("ok", True)
        return res

    define(registry, "t_boom", [T.DOMAIN], boom)
    define(registry, "t_limited", [T.DOMAIN], limited)
    define(registry, "t_fine", [T.DOMAIN], fine)
    case = scan([("domain", "example.org")], ["t_boom", "t_limited", "t_fine"])
    by = {r.module: r for r in case.results}
    assert by["t_boom"].status is Status.ERROR and "module bug" in by["t_boom"].error
    assert by["t_limited"].status is Status.RATE_LIMITED
    assert by["t_fine"].status is Status.OK
    assert case.coverage["t_boom"]["status"] == "error"


def test_keys_and_opsec_gating(registry):
    def run(self, entity, ctx):
        res = self.result(entity)
        res.attr("ran", True)
        return res

    define(registry, "t_keyed", [T.DOMAIN], run, requires_keys=("t_service",))
    define(registry, "t_active", [T.DOMAIN], run, opsec=Opsec.ACTIVE)
    case = scan([("domain", "example.org")], ["t_keyed", "t_active"])
    assert case.coverage["t_keyed"]["status"] == "needs_key"
    assert case.coverage["t_active"]["status"] == "skipped"
    assert not case.results

    rt = make_runtime(FakeHttp(), keys={"t_service": "secret"})
    opts = ScanOptions(include={"t_keyed", "t_active"}, mode=Opsec.ACTIVE, authorized=True)
    case2 = Engine(rt, opts).investigate([Entity.make("domain", "example.org")])
    assert {r.module for r in case2.results} == {"t_keyed", "t_active"}


def test_evidence_saved_with_sha256(registry):
    def run(self, entity, ctx):
        res = self.result(entity)
        res.attr("x", 1)
        res.raw = {"answer": 42}
        return res

    define(registry, "t_ev", [T.DOMAIN], run)
    case = scan([("domain", "example.org")], ["t_ev"])
    r = case.results[0]
    blob = Path(r.evidence).read_bytes()
    assert hashlib.sha256(blob).hexdigest() == r.evidence_sha256
    assert json.loads(blob)["data"] == {"answer": 42}


def test_seeds_linked_correlation(registry):
    def run(self, entity, ctx):
        res = self.result(entity)
        res.pivot(T.IPV4, "45.33.40.77", "resolves_to")
        return res

    define(registry, "t_link", [T.DOMAIN], run)
    case = scan([("domain", "a.example"), ("domain", "b.example")], ["t_link"], depth=0)
    rules = {c.rule for c in case.correlations}
    assert "seeds_linked" in rules
    assert "shared_infrastructure" in rules


def test_budget(registry):
    def run(self, entity, ctx):
        res = self.result(entity)
        for i in range(10):
            res.pivot(T.IPV4, f"45.33.32.{i + 1}", "resolves_to")
        return res

    define(registry, "t_budget", [T.DOMAIN, T.IPV4], run)
    case = scan([("domain", "example.org")], ["t_budget"], depth=2, max_entities=4)
    assert sum(1 for n in case.graph.nodes.values() if n.investigated) == 4
    assert any("budget" in n for n in case.notes)


def test_multi_source_malicious_and_risk(registry):
    def bad(self, entity, ctx):
        res = self.result(entity)
        res.finding("flagged", "high", tags=["malicious"], confidence=0.9)
        return res

    define(registry, "t_src1", [T.DOMAIN], bad)
    define(registry, "t_src2", [T.DOMAIN], bad)
    case = scan([("domain", "evil.example")], ["t_src1", "t_src2"])
    assert any(c.rule == "multi_source_malicious" for c in case.correlations)
    assert case.risk["level"] in ("high", "critical")


def test_pivot_cap_per_module(registry):
    def run(self, entity, ctx):
        res = self.result(entity)
        for i in range(20):
            res.pivot(T.IPV4, f"192.0.2.{i + 1}", "resolves_to", expand=False)
        return res

    define(registry, "t_maxpiv", [T.DOMAIN], run, max_pivots=5)
    case = scan([("domain", "example.org")], ["t_maxpiv"])
    assert len(case.results[0].pivots) == 5 and "dropped" in case.results[0].error
