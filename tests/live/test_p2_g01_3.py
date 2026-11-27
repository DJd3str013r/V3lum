"""Live checks of batch p2-G01-3 (subdomains_passive P016, protective_dns P020, archive_mining P060 and the
opt-in subdomains_passive_extra / protective_dns_extra); run with V3LUM_LIVE=1.

Benign public values only: example.com (the IANA reserved domain) and registro.br (the .br registry,
whose archived robots.txt history is public). Keyless sources: the THC subdomain database (one page),
the core DoH resolvers, Cloudflare 1.1.1.2/1.1.1.3 and Quad9 (RFC 8484 through dnspython), the Wayback
CDX index and Arquivo.pt. The opt-in modules whose feeds have 'unknown' or 'noncommercial' terms are
licence-blocked under the shipped corporate profile: the check asserts the policy decision and never
calls them.

A 403/429/challenge/reset/timeout from this datacenter egress is an acceptable outcome when the module
reports it as could-not-verify (BLOCKED / RATE_LIMITED / QUOTA / ERROR / UNAVAILABLE), never as an
absence (web.archive.org resets connections from this egress in every recorded sweep).
"""

from __future__ import annotations

import json

import pytest

from tests.fakes import run_module
from v3lum.config import Config
from v3lum.core import module as module_mod
from v3lum.core import policy
from v3lum.core.context import RunInfo, Runtime, ScanOptions
from v3lum.core.entities import Entity, EntityType
from v3lum.core.models import Status
from v3lum.modules.domain_dns.protective_dns import ProtectiveDns
from v3lum.modules.domain_dns.protective_dns_extra import ProtectiveDnsExtra
from v3lum.modules.domain_dns.subdomains_passive import SubdomainsPassive
from v3lum.modules.domain_dns.subdomains_passive_extra import SubdomainsPassiveExtra
from v3lum.modules.url_web.archive_mining import ArchiveMining

pytestmark = pytest.mark.live
COULD_NOT_VERIFY = {Status.BLOCKED, Status.RATE_LIMITED, Status.QUOTA, Status.ERROR, Status.UNAVAILABLE}


def live_runtime(**settings) -> Runtime:
    cfg = Config()
    cfg.settings.update(settings)
    return Runtime(cfg, no_cache=True)


def corporate_decision(cls, value: str):
    module_mod.load_modules()
    etype, _, raw = value.partition(":")
    ent = Entity.make(EntityType.parse(etype), raw)
    return policy.decide(cls, ent, policy.make_context(live_runtime(), ScanOptions(), path="run"), run=RunInfo(entity=ent, is_seed=True))


def outcome(res) -> str:
    return f"{res.status.value} {res.reason_code or ''} {res.error[:300]} {json.dumps(res.source_statuses, default=str)[:600]}"


# ------------------------------------------------------------------ P016
def test_subdomains_passive_thc_example_com():
    decision = corporate_decision(SubdomainsPassive, "domain:example.com")
    assert decision.allowed and "thc.subdomains" in (decision.allowed_sources or ()), decision
    res = run_module(SubdomainsPassive, "domain:example.com", runtime=live_runtime(subdomains_passive_resolve=40),
                     allowed_sources=tuple(decision.allowed_sources or ()))
    print("subdomains_passive:", outcome(res))
    assert res.status in {Status.OK, Status.EMPTY} | COULD_NOT_VERIFY, outcome(res)
    if res.status is Status.OK:
        coverage = res.attributes["subdomain_coverage"]
        assert coverage["sources"]["thc.subdomains"]["status"] in ("ok", "partial"), coverage
        assert "example.com" not in res.attributes.get("subdomains", [])  # the apex itself is never a subdomain
        assert all(p.entity.value.endswith(".example.com") for p in res.pivots)
        assert len(res.pivots) <= 12
    assert set(res.hosts) <= {"ip.thc.org", "dns.google", "cloudflare-dns.com"}, res.hosts


def test_subdomains_passive_extra_is_licence_blocked_under_corporate():
    decision = corporate_decision(SubdomainsPassiveExtra, "domain:example.com")
    assert not decision.allowed and decision.status is Status.SKIPPED, decision


# ------------------------------------------------------------------ P020
def test_protective_dns_example_com():
    decision = corporate_decision(ProtectiveDns, "domain:example.com")
    assert decision.allowed, decision
    res = run_module(ProtectiveDns, "domain:example.com", runtime=live_runtime(), allowed_sources=tuple(decision.allowed_sources or ()))
    print("protective_dns:", outcome(res), res.attributes.get("protective_dns", {}).get("summary"))
    assert res.status in {Status.OK} | COULD_NOT_VERIFY, outcome(res)
    if res.status is Status.OK:
        attr = res.attributes["protective_dns"]
        assert not attr["security_blocked"] and not [f for f in res.findings if "suspicious" in f.tags], attr  # a benign name
        assert attr["lines"][0].startswith("not blocked by "), attr["lines"]
        assert "clean" not in json.dumps(attr).lower()
    assert set(res.hosts) <= {"security.cloudflare-dns.com", "family.cloudflare-dns.com", "dns.quad9.net", "dns.google",
                              "cloudflare-dns.com"}, res.hosts


def test_protective_dns_extra_is_licence_blocked_under_corporate():
    decision = corporate_decision(ProtectiveDnsExtra, "domain:example.com")
    assert not decision.allowed and decision.status is Status.SKIPPED, decision


# ------------------------------------------------------------------ P060
def test_archive_mining_registro_br():
    res = run_module(ArchiveMining, "domain:registro.br", runtime=live_runtime(archive_mining_max_bodies=2, archive_mining_budget=60))
    print("archive_mining:", outcome(res), json.dumps(res.attributes.get("archive_sources", {}))[:600])
    assert res.status in {Status.OK, Status.EMPTY} | COULD_NOT_VERIFY, outcome(res)
    assert set(res.hosts) <= {"web.archive.org", "arquivo.pt"}, res.hosts  # never the live site
    assert all(p.expand is False for p in res.pivots)
    bodies = [b for b in (res.raw or {}).get("bodies", [])]
    assert len(bodies) <= 2
    if res.status is Status.OK and res.attributes.get("archived_robots"):
        assert res.attributes["archived_robots"]["versions"]
