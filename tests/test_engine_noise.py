"""AR06 noise semantics: evaluated when a node is added, never linking entities, URL paths on legit
platforms investigated (synthetic modules, no network).

Regression tests named by AR06: two unrelated Google Workspace domains are not 'linked' via
aspmx.l.google.com, and a Google Forms phishing URL is investigated (tagged
``hosted_on_legit_platform``).
"""

from __future__ import annotations

import pytest

from tests.fakes import FakeHttp, define_module, make_runtime
from v3lum.core import correlate, noise
from v3lum.core.context import ScanOptions
from v3lum.core.engine import Engine
from v3lum.core.entities import Entity
from v3lum.core.entities import EntityType as T
from v3lum.core.graph import LEGIT_PLATFORM_TAG, Graph, tenant_platform

FORMS_URL = "https://docs.google.com/forms/d/e/1FAIpQLSdTestPhishingForm/viewform"


@pytest.fixture()
def registry(clean_registry):
    clean_registry.clear()  # only the synthetic modules of the test are candidates
    return clean_registry


def scan(seeds, *, depth=1, **opts):
    return Engine(make_runtime(FakeHttp()), ScanOptions(depth=depth, **opts)).investigate(list(seeds))


def rules_of(case) -> set[str]:
    return {c.rule for c in case.correlations}


def test_google_workspace_domains_are_not_linked_via_aspmx(registry):
    def mx(self, entity, ctx):
        res = self.result(entity)
        res.pivot(T.DOMAIN, "aspmx.l.google.com", "mx_host")
        return res

    define_module("t_mx", [T.DOMAIN], mx)
    seeds = [Entity.make("domain", "alpha-corp.example"), Entity.make("domain", "beta-shop.example")]
    case = scan(seeds, include={"t_mx"})
    aspmx = case.graph.get(Entity.make("domain", "aspmx.l.google.com"))
    assert aspmx.noise and aspmx.noise_kind == "saas" and not aspmx.investigated
    assert "seeds_linked" not in rules_of(case) and "shared_infrastructure" not in rules_of(case)
    # depth 0 (the v1 bug: noise was only evaluated when expanding) - still noise, still unlinked
    case0 = scan(seeds, include={"t_mx"}, depth=0)
    assert case0.graph.get(Entity.make("domain", "aspmx.l.google.com")).noise
    assert "seeds_linked" not in rules_of(case0)


def test_a_google_forms_phishing_url_is_investigated_and_tagged(registry):
    seen: list[str] = []

    def url_mod(self, entity, ctx):
        seen.append(entity.key)
        res = self.result(entity)
        res.finding("phishing form", "high", tags=["phishing"], criterion="synthetic verdict")
        return res

    def dom(self, entity, ctx):
        res = self.result(entity)
        res.pivot(T.URL, FORMS_URL, "links_to")
        res.pivot(T.URL, "https://docs.google.com/", "links_to")
        return res

    define_module("t_url_mod", [T.URL], url_mod)
    define_module("t_url_dom", [T.DOMAIN], dom)
    case = scan([Entity.make("url", FORMS_URL)], include={"t_url_mod"})
    node = case.graph.get(Entity.make("url", FORMS_URL))
    assert seen == [node.key] and not node.noise and node.tagged(LEGIT_PLATFORM_TAG)
    assert case.risk["score"] > 0  # not noise: its findings count
    seen.clear()
    case2 = scan([Entity.make("domain", "lure.example")], include={"t_url_mod", "t_url_dom"})  # as a pivot
    assert Entity.make("url", FORMS_URL).key in seen
    bare = case2.graph.get(Entity.make("url", "https://docs.google.com/"))
    assert bare.noise and not bare.investigated and not bare.tagged(LEGIT_PLATFORM_TAG)


def test_noise_is_evaluated_when_a_node_is_added(registry, monkeypatch):
    sinkhole, parked = Entity.make("ipv4", "45.33.32.66"), Entity.make("domain", "parked-name.example")
    real = noise.noise_kinds
    fake = {sinkhole.key: frozenset({"sinkhole"}), parked.key: frozenset({"parked"})}
    monkeypatch.setattr(noise, "noise_kinds", lambda entity: fake.get(entity.key) or real(entity))

    def dom(self, entity, ctx):
        res = self.result(entity)
        res.pivot(T.IPV4, "8.8.8.8", "resolves_to")
        res.pivot(T.IPV4, sinkhole.value, "resolves_to")
        res.pivot(T.DOMAIN, parked.value, "related")
        return res

    define_module("t_noise_add", [T.DOMAIN], dom)
    case = scan([Entity.make("domain", "example.org")], include={"t_noise_add"}, depth=0)  # nothing is expanded
    resolver = case.graph.get(Entity.make("ipv4", "8.8.8.8"))
    sink = case.graph.get(sinkhole)
    park = case.graph.get(parked)
    assert (resolver.noise, resolver.noise_kind) == (True, "resolver")
    assert (sink.noise, sink.noise_kind) == (True, "sinkhole") and sink.tagged("sinkhole") and sink.attr("is_sinkhole") is True
    assert (park.noise, park.noise_kind) == (True, "parked") and park.tagged("parked") and park.attr("is_parked") is True
    stored = {n["key"]: n for n in case.to_dict()["entities"]}
    assert stored[sinkhole.key]["noise_kind"] == "sinkhole" and "sinkhole" in stored[sinkhole.key]["tags"]


def test_tenant_sites_of_user_site_platforms_are_not_noise():
    g = Graph()
    tenant, _ = g.add_node(Entity.make("domain", "secure-login-update.wordpress.com"), 0, seed=True)
    assert not tenant.noise and tenant.tagged(LEGIT_PLATFORM_TAG)
    assert tenant_platform(tenant.entity) == "wordpress"
    for infra in ("ns1.wordpress.com", "www.wordpress.com", "lh3.googleusercontent.com", "mail.squarespace.com", "wordpress.com"):
        node, _ = g.add_node(Entity.make("domain", infra), 1)
        assert node.noise, infra
    site, _ = g.add_node(Entity.make("domain", "shop-of-someone.squarespace.com"), 1)
    drive, _ = g.add_node(Entity.make("url", "https://doc-0k-2c-docs.googleusercontent.com/"), 1)
    assert not site.noise and not drive.noise and site.tagged(LEGIT_PLATFORM_TAG)
    gh, _ = g.add_node(Entity.make("domain", "evil.github.io"), 1)  # a PSL tenant: never noise, tagged
    assert not gh.noise and gh.tagged(LEGIT_PLATFORM_TAG)
    stored = Graph.from_dict({"nodes": [{"key": "domain:aspmx.l.google.com", "noise": False}]})  # stored values are kept
    assert not stored.get("domain:aspmx.l.google.com").noise


def _graph(edges, seeds=("domain:a.example", "domain:b.example"), *, extra=()):
    g = Graph()
    for key in seeds:
        g.add_node(Entity.make(*key.split(":", 1)), 0, seed=True)
    for key in extra:
        g.add_node(Entity.make(*key.split(":", 1)), 1)
    for src, dst, rel, kw in edges:
        if g.get(dst) is None:
            g.add_node(Entity.make(*dst.split(":", 1)), 1)
        if g.get(src) is None:
            g.add_node(Entity.make(*src.split(":", 1)), 1)
        g.add_edge(Entity.make(*src.split(":", 1)), Entity.make(*dst.split(":", 1)), rel, "t", **kw)
    return g


@pytest.mark.parametrize(
    ("edges", "linked"),
    [
        ([("domain:a.example", "ipv4:45.33.40.77", "resolves_to", {}), ("domain:b.example", "ipv4:45.33.40.77", "resolves_to", {})], True),
        ([("domain:a.example", "domain:mx.shared.example", "mx_host", {}), ("domain:b.example", "domain:mx.shared.example", "mx_host", {})], False),
        ([("domain:a.example", "domain:ns1.dns.example", "nameserver", {}), ("domain:b.example", "domain:ns1.dns.example", "nameserver", {})], False),
        ([("domain:a.example", "domain:san.example", "cert_san", {}), ("domain:b.example", "domain:san.example", "cert_san", {})], False),
        ([("ipv4:45.33.40.78", "domain:a.example", "hosted_domain", {"expand": False}), ("ipv4:45.33.40.78", "domain:b.example", "hosted_domain", {"expand": False})], False),
        ([("domain:a.example", "ipv4:45.33.40.79", "resolves_to", {"confidence": 0.5}), ("domain:b.example", "ipv4:45.33.40.79", "resolves_to", {"confidence": 0.5})], False),
    ],
)
def test_weak_relations_never_link_seeds(edges, linked):
    correlate.load_rules()
    g = _graph(edges)
    out = {c.rule for c in correlate.run_rules(g, [], only={"seeds_linked", "shared_infrastructure"})}
    assert ("seeds_linked" in out) is linked


def test_platform_tenants_sharing_the_platform_address_are_not_linked():
    correlate.load_rules()
    a, b = "domain:first-blog.wordpress.com", "domain:second-blog.wordpress.com"
    g = _graph([(a, "ipv4:192.0.78.9", "resolves_to", {}), (b, "ipv4:192.0.78.9", "resolves_to", {})], seeds=(a, b))
    out = {c.rule for c in correlate.run_rules(g, [], only={"seeds_linked", "shared_infrastructure"})}
    assert out == set()


def test_noise_domains_never_share_infrastructure():
    correlate.load_rules()
    g = _graph(
        [("domain:gmail.com", "ipv4:45.33.40.80", "resolves_to", {}), ("domain:googlemail.com", "ipv4:45.33.40.80", "resolves_to", {})],
        seeds=("domain:a.example",),
    )
    out = {c.rule for c in correlate.run_rules(g, [], only={"shared_infrastructure"})}
    assert out == set()
