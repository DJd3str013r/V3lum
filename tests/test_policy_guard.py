"""Hostile-host contact guard (GUARD-01, A13/P376) and recipient-token URLs (GUARD-02, A7 BR15).

``policy.contact_guard`` runs for LIGHT/ACTIVE modules after the entity's passive results: hostile
tags, consensus listings and case-DB sightings, and hostile-shaped entities (org-brand lookalike,
young domain, lure word, extracted from text) give BLOCKED 'hostile_host' unless a non-corporate
egress profile or a recorded override exists. Recipient-token URLs are refused unless confirmed.
"""

from __future__ import annotations

import base64
import datetime as _dt
import json
from typing import Any

import pytest

from tests.fakes import define_module
from v3lum.config import Config
from v3lum.core import policy
from v3lum.core.context import RunInfo, ScanOptions
from v3lum.core.entities import Entity, EntityType
from v3lum.core.graph import Graph
from v3lum.core.models import Correlation, Finding, Opsec, Status
from v3lum.core.orgprofile import OrgProfile
from v3lum.core.policy import PolicyContext, contact_guard, recipient_token

NOW = _dt.datetime(2026, 11, 26, 12, 0, tzinfo=_dt.timezone.utc)
ORG = {
    "domains": [
        {"name": "acme-corp.com", "verification": "txt_verified"},
        {"name": "acme-seeded.com", "verification": "seeded"},
    ],
    "brands": [{"keyword": "acme"}, {"keyword": "Contoso", "variants": ["kontoso"]}],
    "suppliers": [{"name": "Partner", "domains": ["acme-partner.com"]}],
}
TOKEN_URL = "https://evil.example/t/9f8e7d6c5b4a39281706f5e4d3c2b1a0"


def _run(self: Any, entity: Entity, ctx: Any) -> Any:
    return self.result(entity)


@pytest.fixture()
def light(clean_registry):
    return define_module("pg_light", ("domain", "url", "ipv4", "email"), _run, opsec=Opsec.LIGHT)


@pytest.fixture()
def active(clean_registry):
    return define_module("pg_active", ("domain", "url", "ipv4"), _run, opsec=Opsec.ACTIVE)


def ent(text: str) -> Entity:
    etype, _, value = text.partition(":")
    return Entity.make(EntityType.parse(etype), value)


def ctx(*, graph: Graph | None = None, settings: dict[str, Any] | None = None, sightings: Any = None, org: dict[str, Any] | None = ORG, **options: Any) -> PolicyContext:
    cfg = Config()
    cfg.settings.update(settings or {})
    opts = ScanOptions(mode=Opsec.ACTIVE)
    for key, value in options.items():
        setattr(opts, key, value)
    return PolicyContext(options=opts, config=cfg, org=OrgProfile.from_dict(org) if org is not None else OrgProfile.empty(), graph=graph, sightings=sightings, now=NOW)


def seed(entity: Entity, **kw: Any) -> RunInfo:
    return RunInfo(entity=entity, is_seed=kw.pop("is_seed", True), case_id="case-1", **kw)


def finding(entity: Entity, *tags: str, title: str = "listed") -> Finding:
    return Finding(title, "high", "", tags=list(tags), entity=entity, module="ti_source", criterion="listed by a TI source")


def graph_with(entity: Entity, *, tags: tuple[str, ...] = (), node_tags: tuple[str, ...] = (), attrs: dict[str, Any] | None = None) -> Graph:
    graph = Graph()
    node, _ = graph.add_node(entity, 0, seed=True)
    for tag in node_tags:
        node.add_tag(tag)
    if tags:
        graph.add_finding(finding(entity, *tags))
    if attrs:
        graph.add_attributes(entity, attrs, "whois")
    return graph


def assert_blocked(decision: Any, *fragments: str) -> None:
    assert (decision.allowed, decision.status, decision.reason_code, decision.rule_id) == (False, Status.BLOCKED, "hostile_host", "GUARD-01"), decision.reason
    assert decision.emit_manual_link is True
    for fragment in fragments:
        assert fragment in decision.reason, (fragment, decision.reason)


def assert_allowed(decision: Any) -> None:
    assert decision.allowed and decision.status is Status.OK and decision.reason_code == "", decision.reason


# --------------------------------------------------------------------------------------
# GUARD-01
# --------------------------------------------------------------------------------------


def test_guard01_hostile_host(light, active):
    """A phishing-tagged entity: blocked from the corporate egress with an explanatory refusal;
    yields to the egress profile of the module's opsec or a recorded override."""
    target = ent("domain:login-portal.example")
    graph = graph_with(target, tags=("phishing",))
    decision = contact_guard(light, target, ctx(graph=graph), run=seed(target))
    assert_blocked(
        decision,
        "needs non-corporate egress",
        "tagged phishing",
        "urlscan search results, archived copies, sandbox reports",
        "v3lum config set proxy_light socks5h://",
        '--egress-override "<reason>"',
        "[GUARD-01]",
    )
    via_proxy = contact_guard(light, target, ctx(graph=graph, settings={"proxy_light": "socks5h://127.0.0.1:9050"}), run=seed(target))
    assert via_proxy.allowed and via_proxy.rule_id == "GUARD-01" and "proxy_light" in via_proxy.reason
    # ACTIVE needs proxy_active: proxy_light does not lift the guard (Tor is never an ACTIVE route)
    assert_blocked(contact_guard(active, target, ctx(graph=graph, settings={"proxy_light": "socks5h://127.0.0.1:9050"}), run=seed(target)), "proxy_active")
    via_active = contact_guard(active, target, ctx(graph=graph, settings={"proxy_active": "http://research-proxy.example:3128"}), run=seed(target))
    assert via_active.allowed and "proxy_active" in via_active.reason
    override = contact_guard(light, target, ctx(graph=graph, egress_override="IR-77: isolated lab"), run=seed(target))
    assert override.allowed and override.rule_id == "GUARD-01" and "--egress-override" in override.reason


@pytest.mark.parametrize("tag", ["malicious", "phishing", "c2", "suspicious"])
def test_hostile_finding_tags(light, tag):
    target = ent("domain:bad-host.example")
    assert_blocked(contact_guard(light, target, ctx(graph=graph_with(target, tags=(tag,))), run=seed(target)), f"tagged {tag}")


def test_hostile_entity_tag_on_the_node(light):
    target = ent("ipv4:203.0.113.66")
    assert_blocked(contact_guard(light, target, ctx(graph=graph_with(target, node_tags=("c2",))), run=seed(target)), "tagged c2")


def test_clean_entity_is_allowed_and_passive_modules_always_pass(light, clean_registry):
    target = ent("domain:example.com")
    graph = graph_with(target, tags=("info",))
    assert_allowed(contact_guard(light, target, ctx(graph=graph), run=seed(target)))
    passive = define_module("pg_passive", ("domain",), _run)
    hostile = graph_with(target, tags=("phishing",))
    decision = contact_guard(passive, target, ctx(graph=hostile), run=seed(target))
    assert decision.allowed and decision.reason == "no target contact"


@pytest.mark.parametrize("tag", ["malware", "botnet", "spam", "scanner"])
def test_consensus_listing_by_finding_tags(light, tag):
    target = ent("ipv4:198.51.100.7")
    assert_blocked(contact_guard(light, target, ctx(graph=graph_with(target, tags=(tag,))), run=seed(target)), f"listed as {tag}")


def test_consensus_listing_by_blocklists_attribute(light):
    target = ent("ipv4:198.51.100.8")
    graph = graph_with(target, attrs={"blocklists": ["spamhaus_drop"]})
    assert_blocked(contact_guard(light, target, ctx(graph=graph), run=seed(target)), "listed by spamhaus_drop")


def test_consensus_listing_by_cr27_correlation(light):
    target = ent("domain:consensus-bad.example")
    graph = graph_with(target)
    graph.correlations = [Correlation("multi_source_malicious", "listed by 2 families", "high", "", entities=[target], criterion="2 families")]  # type: ignore[attr-defined]
    assert_blocked(contact_guard(light, target, ctx(graph=graph), run=seed(target)), "CR27")


def test_case_db_sightings_with_hostile_verdict(light):
    target = ent("domain:seen-before.example")
    calls: list[dict[str, Any]] = []

    def lookup(entity: Entity, *, case_id: str, case_tlp: str) -> dict[str, Any]:
        calls.append({"entity": entity.key, "case_id": case_id, "case_tlp": case_tlp})
        if entity == target:
            return {"visible": [{"case_id": "c-old", "created": "2026-10-01", "verdict": "malicious"}], "restricted_count": 0}
        return {"visible": [], "restricted_count": 0}

    assert_blocked(contact_guard(light, target, ctx(sightings=lookup), run=seed(target)), "case-DB sighting with verdict malicious")
    assert calls[0] == {"entity": target.key, "case_id": "case-1", "case_tlp": "amber"}


def test_case_db_sightings_benign_or_restricted_do_not_block(light):
    target = ent("domain:seen-benign.example")

    class Summary:
        visible = [{"case_id": "c1", "created": "2026-10-01", "verdict": "benign"}]
        restricted_count = 3  # higher-TLP cases: no verdicts leak (A2)

    assert_allowed(contact_guard(light, target, ctx(sightings=lambda e: Summary()), run=seed(target)))
    broken = contact_guard(light, target, ctx(sightings=lambda e: 1 / 0), run=seed(target))
    assert broken.allowed  # an unavailable case DB is not a hostile signal by itself


@pytest.mark.parametrize(
    ("value", "graph_entity", "attrs", "blocked"),
    [
        ("domain:fresh-domain.com", "domain:fresh-domain.com", {"domain_age_days": 12}, True),
        ("domain:fresh-domain.com", "domain:fresh-domain.com", {"domain_age_days": 30}, True),
        ("domain:fresh-domain.com", "domain:fresh-domain.com", {"domain_age_days": 400}, False),
        ("domain:login.fresh-domain.com", "domain:fresh-domain.com", {"domain_age_days": 3}, True),
        ("url:https://login.fresh-domain.com/verify", "domain:fresh-domain.com", {"domain_age_days": 3}, True),
    ],
)
def test_young_domains_are_hostile_shaped(light, value, graph_entity, attrs, blocked):
    target = ent(value)
    graph = graph_with(ent(graph_entity), attrs=attrs)
    decision = contact_guard(light, target, ctx(graph=graph), run=seed(target))
    if blocked:
        assert_blocked(decision, "days ago")
    else:
        assert_allowed(decision)


def test_newly_registered_tag_is_a_young_domain(light):
    target = ent("domain:brand-new.example")
    assert_blocked(contact_guard(light, target, ctx(graph=graph_with(target, tags=("newly_registered",))), run=seed(target)), "newly registered domain")


@pytest.mark.parametrize(
    ("value", "blocked"),
    [
        ("domain:acme-login.com", True),
        ("domain:secure.acme-verify.net", True),
        ("domain:acrne-secure.com", True),  # rn -> m
        ("domain:acmé.com", True),  # accent-folded IDN
        ("domain:аcme.com", True),  # Cyrillic а
        ("domain:4cme-portal.com", True),  # 4 -> a
        ("url:https://acme-billing.example/login", True),
        ("domain:contosso.com", True),  # one insertion away from a >= 5-letter brand
        ("domain:cnotoso.com", True),  # transposition
        ("domain:kontoso-pay.com", True),  # a declared variant
        ("domain:acme-corp.com", False),  # verified own domain
        ("domain:mail.acme-corp.com", False),
        ("domain:acme-partner.com", False),  # supplier
        ("domain:acme-seeded.com", True),  # seeded entries are proposals, never trusted
        ("domain:example.com", False),
        ("domain:academy.com", False),
    ],
)
def test_brand_lookalikes_are_hostile_shaped(light, value, blocked):
    target = ent(value)
    decision = contact_guard(light, target, ctx(), run=seed(target))
    if blocked:
        assert_blocked(decision, "lookalike of the org brand")
    else:
        assert_allowed(decision)


def test_no_org_profile_means_no_lookalike_check(light, tmp_path, monkeypatch):
    monkeypatch.setattr(policy, "DATA_DIR", tmp_path)  # no lure-word list: 'login' is a bundled lure word (WP24)
    target = ent("domain:acme-login.com")
    assert_allowed(contact_guard(light, target, ctx(org=None), run=seed(target)))


def test_lure_word_domains(light, tmp_path, monkeypatch):
    target = ent("domain:atualizacao-cadastro.com")
    empty = tmp_path / "empty"
    empty.mkdir()
    monkeypatch.setattr(policy, "DATA_DIR", empty)
    assert_allowed(contact_guard(light, target, ctx(), run=seed(target)))  # no lure list installed: no lure check
    (tmp_path / "brand_lures_pt.json").write_text(json.dumps({"schema": "v3lum.lures/1", "words": ["atualização", "cadastro", "pix"]}), encoding="utf-8")
    monkeypatch.setattr(policy, "DATA_DIR", tmp_path)
    assert "atualizacao" in policy.lure_words()
    assert_blocked(contact_guard(light, target, ctx(), run=seed(target)), "lure-word domain")
    assert_blocked(contact_guard(light, ent("domain:pix-premio.com"), ctx(), run=seed(ent("domain:pix-premio.com"))), "'pix'")
    assert_allowed(contact_guard(light, ent("domain:meupixel.com"), ctx(), run=seed(ent("domain:meupixel.com"))))  # short words match whole tokens only
    own = ent("domain:cadastro.acme-corp.com")
    assert_allowed(contact_guard(light, own, ctx(), run=seed(own)))  # own assets are not hostile-shaped


def test_text_provenance_is_hostile_shaped(light, active):
    target = ent("url:https://docs-share.example/view")
    from_mail = seed(target, is_seed=False, provenance=(("email_headers:abc123", "extracted_from", "ioc_extract"),))
    assert_blocked(contact_guard(active, target, ctx(), run=from_mail), "extracted from text/file/e-mail input")
    from_text = seed(target, is_seed=False, provenance=(("text_blob:" + "x" * 20, "mentions", "ioc_extract"),))
    assert_blocked(contact_guard(light, target, ctx(), run=from_text), "extracted")
    assert_allowed(contact_guard(light, target, ctx(), run=seed(target)))  # an analyst-typed seed
    # a pivot whose parent in the case graph is a pasted text (no provenance in the run)
    graph = Graph()
    parent = Entity.make(EntityType.TEXT, "pasted body with https://docs-share.example/view")
    graph.add_node(parent, 0, seed=True)
    graph.add_node(target, 1)
    graph.add_edge(parent, target, "extracted_from", "ioc_extract")
    assert_blocked(contact_guard(active, target, ctx(graph=graph), run=seed(target, is_seed=False)), "extracted")
    own = ent("url:https://acme-corp.com/news")
    own_run = seed(own, is_seed=False, provenance=(("text_blob:" + "y" * 20, "mentions", "ioc_extract"),))
    assert_allowed(contact_guard(active, own, ctx(), run=own_run))  # own (confirmed+) assets are exempt


def test_redirect_targets_and_resolved_addresses(light):
    start = ent("url:https://short.example/abc")
    landing = ent("url:https://landing.example/pay")
    graph = Graph()
    graph.add_node(start, 0, seed=True)
    graph.add_node(landing, 1)
    graph.add_edge(start, landing, "redirects_to", "urlscan_search")
    graph.add_finding(finding(landing, "phishing"))
    assert_blocked(contact_guard(light, start, ctx(graph=graph), run=seed(start)), "tagged phishing (url")
    # a domain resolving to a C2-tagged address: contacting the name reaches that address
    name = ent("domain:innocent-looking.example")
    ip = ent("ipv4:45.155.205.7")
    graph2 = Graph()
    graph2.add_node(name, 0, seed=True)
    node, _ = graph2.add_node(ip, 1)
    graph2.add_edge(name, ip, "resolves_to", "dns_records")
    graph2.add_finding(finding(ip, "c2"))
    assert_blocked(contact_guard(light, name, ctx(graph=graph2), run=seed(name)), "tagged c2 (ipv4 45.155.205.7)")
    node.noise = True  # a shared CDN address does not taint the names on it
    assert_allowed(contact_guard(light, name, ctx(graph=graph2), run=seed(name)))


@pytest.mark.parametrize("tag", ["phishing_kit_exfil", "crypto_scam", "fraud", "hijacked_netblock"])
def test_vocabulary_hostile_tags_beyond_the_four(light, tag):
    """Hostile tags of the shared vocabulary (blocklist and phishing-kit modules) block contact too."""
    target = ent("domain:bad-shop.example")
    assert_blocked(contact_guard(light, target, ctx(graph=graph_with(target, tags=(tag,))), run=seed(target)), f"tagged {tag}")


@pytest.mark.parametrize(("attrs", "fragment"), [({"malicious": True}, "tagged malicious"), ({"suspicious": True}, "tagged suspicious")])
def test_hostile_boolean_attributes(light, attrs, fragment):
    """Modules record verdicts as the boolean attributes malicious/suspicious as well as tags."""
    target = ent("ipv4:198.51.100.20")
    assert_blocked(contact_guard(light, target, ctx(graph=graph_with(target, attrs=attrs)), run=seed(target)), fragment)
    clean = graph_with(target, attrs={"malicious": False, "suspicious": False})
    assert_allowed(contact_guard(light, target, ctx(graph=clean), run=seed(target)))


def test_blocklist_listings_count_but_ad_tracking_lists_do_not(light):
    target = ent("domain:listed.example")
    tagged = graph_with(target, tags=("blocklisted",))
    assert_blocked(contact_guard(light, target, ctx(graph=tagged), run=seed(target)), "listed as blocklisted")
    hits = graph_with(target, attrs={"blocklist_hits": [{"list": "CERT.PL", "feed": "certpl", "category": "phishing"}], "blocklists": ["CERT.PL"]})
    assert_blocked(contact_guard(light, target, ctx(graph=hits), run=seed(target)), "listed by CERT.PL")
    families = graph_with(target, attrs={"blocklist_families": ["firehol"]})
    assert_blocked(contact_guard(light, target, ctx(graph=families), run=seed(target)), "listed by firehol")
    # an ad/tracking-only listing (StevenBlack hosts) is no threat signal
    ads = Graph()
    ads.add_node(target, 0, seed=True)
    ads.add_finding(finding(target, "ads_tracking", "weak_signal", title="Listed on ad/tracking blocklists (tag only)"))
    ads.add_attributes(target, {"blocklist_hits": [{"list": "StevenBlack hosts", "category": "ads_tracking"}], "blocklists": ["StevenBlack hosts"]}, "url_domain_blocklists")
    assert_allowed(contact_guard(light, target, ctx(graph=ads), run=seed(target)))
    # ...unless a threat list lists it too
    ads.add_attributes(target, {"blocklist_hits": [{"list": "URLhaus", "category": "malicious"}]}, "url_domain_blocklists")
    assert_blocked(contact_guard(light, target, ctx(graph=ads), run=seed(target)), "listed by URLhaus")


def test_typosquat_and_brand_abuse_tags_are_hostile_shaped(light):
    target = ent("domain:paypa1-login.example")
    assert_blocked(contact_guard(light, target, ctx(graph=graph_with(target, tags=("typosquat",))), run=seed(target)), "tagged typosquat")
    assert_blocked(contact_guard(light, target, ctx(graph=graph_with(target, tags=("brand_abuse",))), run=seed(target)), "tagged brand_abuse")
    own = ent("domain:acme-corp.com")  # the organisation's own defensive registration: not hostile-shaped
    assert_allowed(contact_guard(light, own, ctx(graph=graph_with(own, tags=("typosquat",))), run=seed(own)))


@pytest.mark.parametrize(
    ("value", "created", "blocked"),
    [
        ("domain:fresh-by-date.com", "2026-11-20", True),
        ("domain:fresh-by-date.com", "2026-10-27T08:00:00Z", True),  # 30 days
        ("domain:fresh-by-date.com", "2026-10-26", False),  # 31 days
        ("domain:fresh-by-date.com", "2019-03-01", False),
        ("ipv4:203.0.113.77", "2026-11-25", False),  # 'created' of an address is no domain age
    ],
)
def test_registration_date_makes_a_young_domain(light, value, created, blocked):
    target = ent(value)
    decision = contact_guard(light, target, ctx(graph=graph_with(target, attrs={"created": created})), run=seed(target))
    if blocked:
        assert_blocked(decision, "days ago")
    else:
        assert_allowed(decision)


def test_host_serving_a_hostile_url(light):
    """Contacting a host that serves a URL tagged hostile reaches the same attacker server."""
    host = ent("domain:serves-phish.example")
    url = ent("url:https://serves-phish.example/secure/verify")

    def build(*, relation: str = "hosts_url", url_tags: tuple[str, ...] = ("phishing",), noise: bool = False, url_entity: Entity = url) -> Graph:
        graph = Graph()
        node, _ = graph.add_node(host, 0, seed=True)
        node.noise = noise
        graph.add_node(url_entity, 1)
        if relation == "hosts_url":
            graph.add_edge(host, url_entity, "hosts_url", "urlscan_search")
        else:
            graph.add_edge(url_entity, host, "url_host", "core")
        graph.add_finding(finding(url_entity, *url_tags))
        return graph

    assert_blocked(contact_guard(light, host, ctx(graph=build()), run=seed(host)), "hosts a URL tagged phishing")
    assert_blocked(contact_guard(light, host, ctx(graph=build(relation="url_host")), run=seed(host)), "hosts a URL tagged phishing")
    # shared platforms are not tainted by one abused URL
    assert_allowed(contact_guard(light, host, ctx(graph=build(noise=True)), run=seed(host)))
    assert_allowed(contact_guard(light, host, ctx(graph=build(url_tags=("phishing", "hosted_on_legit_platform"))), run=seed(host)))
    # a URL on another host (a subdomain) says nothing about this exact host
    other = ent("url:https://login.serves-phish.example/x")
    assert_allowed(contact_guard(light, host, ctx(graph=build(url_entity=other)), run=seed(host)))


def test_unusable_egress_profile_does_not_lift_the_guard(light, active):
    target = ent("domain:login-portal.example")
    graph = graph_with(target, tags=("phishing",))
    tor = {"proxy_active": "socks5h://127.0.0.1:9050"}
    assert_blocked(contact_guard(active, target, ctx(graph=graph, settings=tor), run=seed(target)), "cannot be used", "Tor")
    no_port = {"proxy_light": "socks5h://127.0.0.1"}
    assert_blocked(contact_guard(light, target, ctx(graph=graph, settings=no_port), run=seed(target)), "needs a port")
    bad_scheme = {"proxy_light": "ftp://proxy.example:21"}
    assert_blocked(contact_guard(light, target, ctx(graph=graph, settings=bad_scheme), run=seed(target)), "unsupported proxy scheme")
    tor_light = contact_guard(light, target, ctx(graph=graph, settings={"proxy_light": "socks5h://127.0.0.1:9050"}), run=seed(target))
    assert tor_light.allowed and "proxy_light" in tor_light.reason  # Tor is fine for LIGHT reads


def test_hostile_reasons_is_public_and_lists_every_signal(light):
    target = ent("domain:acme-fresh.com")
    graph = graph_with(target, tags=("suspicious",), attrs={"domain_age_days": 2})
    reasons = policy.hostile_reasons(target, ctx(graph=graph), run=seed(target))
    assert reasons[0] == "tagged suspicious"
    assert "lookalike of the org brand 'acme'" in reasons and "domain registered 2 days ago" in reasons
    assert policy.hostile_reasons(ent("domain:example.com"), ctx(), run=seed(ent("domain:example.com"))) == []


# --------------------------------------------------------------------------------------
# GUARD-02 recipient tokens
# --------------------------------------------------------------------------------------

ORG_PROFILE = OrgProfile.from_dict(ORG)
B64 = base64.b64encode(b"ana@acme-corp.com").decode()
B64URL = base64.urlsafe_b64encode(b"ana.silva@acme-corp.com>>").decode()


@pytest.mark.parametrize(
    ("url", "expected"),
    [
        ("https://evil.example/landing?u=ana@acme-corp.com", True),
        ("https://evil.example/landing?u=ana%40acme-corp.com", True),
        ("https://evil.example/landing?u=ana%2540acme-corp.com", True),  # double encoded
        (f"https://evil.example/landing?id={B64}", True),
        (f"https://evil.example/r/{B64URL}", True),
        ("https://evil.example/landing#ana@acme-corp.com", True),
        ("https://evil.example/landing?e=someone.else@gmail.com", True),  # any address identifies a recipient
        ("https://evil.example/t/a1b2c3d4e5f6g7h8", True),  # 16-char opaque token
        ("https://evil.example/t/a1b2c3d4e5f6g7h", False),  # 15 chars
        ("https://evil.example/track/550e8400-e29b-41d4-a716-446655440000", True),
        ("https://evil.example/x?sid=8f14e45fceea167a5a36dedd4bea2543", True),
        ("https://evil.example/u/1234567890123456", True),
        ("https://evil.example/q?k=XyzAbcDefGhiJklMnoP", True),  # mixed-case random letters
        ("https://example.com/2026/11/26/my-long-article-title-here", False),
        ("https://example.com/search?q=threat+intel&utm_source=newsletter", False),
        ("https://example.com/products/shoes/running", False),
        ("https://example.com/", False),
        ("https://example.com/documentation/getting-started-guide", False),
    ],
)
def test_recipient_token_detection(url, expected):
    assert recipient_token(url, ORG_PROFILE) is expected, url
    assert recipient_token(Entity.make(EntityType.URL, url), ORG_PROFILE) is expected


@pytest.mark.parametrize(
    ("url", "expected"),
    [
        ("https://victim%40corp.example@evil.example/", True),  # e-mail in the userinfo
        ("https://ana@acme-corp.com@evil.example/landing", True),
        ("https://reader@evil.example/", False),  # a user name is no e-mail address
        ("https://evil.example/?e=user@example.xn--p1ai", True),  # punycode TLD
        ("https://blog.example.com/windows11-vs-windows10", False),  # versioned words are slug words
        ("https://blog.example.com/top10-tips-for-ios17-users", False),
        ("https://evil.example/r/ab12-cd34-ef56-gh78", True),  # a segmented random code stays a token
        ("https://evil.example/r/abc123def456ghi789", True),
    ],
)
def test_recipient_token_userinfo_and_slug_words(url, expected):
    assert recipient_token(url, ORG_PROFILE) is expected, url


def test_url_tagged_recipient_token_in_the_case_is_guarded(light, clean_registry):
    """A URL that the case tagged recipient_token (e.g. by the extraction engine) is refused like a
    detected one - by the guard and by decide() for a provider that fetches the target."""
    from tests.fakes import provider_fragment
    from v3lum.core import providers

    target = ent("url:https://evil.example/landing/view")
    assert not recipient_token(target.value, ORG_PROFILE)
    graph = graph_with(target, node_tags=("recipient_token",))
    decision = contact_guard(light, target, ctx(graph=graph), run=seed(target))
    assert (decision.allowed, decision.reason_code, decision.rule_id) == (False, "policy", "GUARD-02")
    assert contact_guard(light, target, ctx(graph=graph, confirmed_urls={target.value}), run=seed(target)).allowed
    providers.register(provider_fragment("pg_fetcher", hosts=("api.pg-fetcher.example.test",), fetches_target=True), origin="tests")
    fetcher = define_module(
        "pg_fetcher_mod", ("url",), _run, disclosure="third_party", provider="pg_fetcher", sources=("pg_fetcher.default",),
        hosts=("api.pg-fetcher.example.test",), access_model="free_noauth_unlimited", default_enabled=False,
    )
    refused = policy.decide(fetcher, target, ctx(graph=graph, preset="deep", mode=Opsec.PASSIVE), run=seed(target))
    assert (refused.allowed, refused.reason_code, refused.rule_id) == (False, "policy", "GUARD-02")


def test_recipient_token_org_domain_in_base64_with_profile():
    payload = base64.b64encode(b"acme-corp.com").decode().rstrip("=")
    url = f"https://evil.example/o?d={payload}"
    assert recipient_token(url, ORG_PROFILE)


def test_guard02_recipient_token(light, active):
    """Token URLs are refused even with proxy_light or --egress-override; only the exact confirmed
    URL passes, and a confirmed URL still passes the hostile-host checks."""
    target = ent(f"url:{TOKEN_URL}")
    for extra in ({}, {"settings": {"proxy_light": "socks5h://127.0.0.1:9050"}}, {"egress_override": "IR-77"}):
        decision = contact_guard(light, target, ctx(**extra), run=seed(target))
        assert (decision.allowed, decision.status, decision.reason_code, decision.rule_id) == (False, Status.SKIPPED, "policy", "GUARD-02")
        assert decision.reason == "URL carries a per-recipient token: re-run with --confirm-url <url> [GUARD-02]"
        assert decision.emit_manual_link is False  # never offer a click on the recipient's link
    assert_allowed(contact_guard(light, target, ctx(confirmed_urls={TOKEN_URL}), run=seed(target)))
    assert_allowed(contact_guard(light, target, ctx(confirmed_urls={"HTTPS://EVIL.EXAMPLE/t/9f8e7d6c5b4a39281706f5e4d3c2b1a0"}), run=seed(target)))
    other = contact_guard(light, target, ctx(confirmed_urls={"https://evil.example/t/another-token-0000000000"}), run=seed(target))
    assert other.rule_id == "GUARD-02"
    hostile = graph_with(target, tags=("phishing",))
    assert_blocked(contact_guard(active, target, ctx(graph=hostile, confirmed_urls={TOKEN_URL}), run=seed(target)), "tagged phishing")


def test_guard02_applies_to_org_mail_tokens(light):
    target = ent("url:https://evil.example/landing?u=ana%40acme-corp.com")
    decision = contact_guard(light, target, ctx(), run=seed(target))
    assert decision.rule_id == "GUARD-02" and decision.reason_code == "policy"


class _GrowingSet(set):
    """A tag set another thread grows while the guard reads it: the first iteration raises like a
    live ``set`` changed during iteration."""

    def __init__(self, *args: Any) -> None:
        super().__init__(*args)
        self.raised = False

    def __iter__(self):
        if not self.raised:
            self.raised = True
            raise RuntimeError("Set changed size during iteration")
        return super().__iter__()


def test_guard_reads_live_graph_collections_through_snapshots(light):
    """Audit (wave 2): redirect hops run the guard in module worker threads while the engine thread
    grows the case graph; the consensus check copies the node's tags (retrying a copy that raced)
    instead of iterating the live set, so a racing update never turns into a spurious refusal and a
    listing tag is still seen."""
    graph = Graph()
    node, _ = graph.add_node(ent("domain:listed.example"), 0)
    node.tags = _GrowingSet({"blocklisted"})
    assert policy._consensus(node, ctx(graph=graph)) == "listed as blocklisted"
    node.tags = _GrowingSet({"blocklisted"})
    reasons = policy.hostile_reasons(ent("domain:listed.example"), ctx(graph=graph))
    assert any("listed as blocklisted" in r for r in reasons), reasons
