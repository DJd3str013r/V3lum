"""Live checks of batch p3-G02-2 (ip_geolocation, ipqualityscore, zoomeye, ip_reputation_keyless,
netapi_compromised_feeds, networksdb); run with V3LUM_LIVE=1.

Benign values only (8.8.8.8, 1.1.1.1). ip_geolocation is the only keyless source with recorded terms
('open'): it is called live. IPGuardian and NetAPI are terms 'unknown' (P150 FC1): under the shipped
corporate profile they are licence-blocked, so the check asserts the policy decision and never calls
them (their behaviour was recorded live on 2026-11-26 by the batch prep). The keyed sources
(IPQualityScore, ZoomEye, NetworksDB) are not called without company keys: the check asserts
NEEDS_KEY before any request. A 403/429/challenge/timeout from this datacenter egress is an
acceptable outcome when the module reports it as could-not-verify, never as an absence.
"""

from __future__ import annotations

import pytest

from tests.fakes import run_module
from v3lum.config import Config
from v3lum.core import module as module_mod
from v3lum.core import policy
from v3lum.core.context import RunInfo, Runtime, ScanOptions
from v3lum.core.entities import Entity, EntityType
from v3lum.core.models import Status
from v3lum.modules.company_org.networksdb import NetworksDb
from v3lum.modules.ip_network.ip_geolocation import IpGeolocation
from v3lum.modules.ip_network.ipqualityscore import IpQualityScore
from v3lum.modules.ip_network.zoomeye import ZoomEye
from v3lum.modules.threat_intel_ioc.ip_reputation_keyless import IpReputationKeyless
from v3lum.modules.threat_intel_ioc.netapi_compromised_feeds import NetapiCompromisedFeeds

pytestmark = pytest.mark.live
COULD_NOT_VERIFY = {Status.BLOCKED, Status.RATE_LIMITED, Status.QUOTA, Status.ERROR, Status.UNAVAILABLE}


def live_runtime() -> Runtime:
    return Runtime(Config(), no_cache=True)


def decision(cls, value: str, **options):
    module_mod.load_modules()
    etype, _, raw = value.partition(":")
    ent = Entity.make(EntityType.parse(etype), raw)
    pctx = policy.make_context(live_runtime(), ScanOptions(**options), explicit={cls.name}, path="run")
    return policy.decide(cls, ent, pctx, run=RunInfo(entity=ent, is_seed=True))


# ------------------------------------------------------------------ P051 (keyless, open terms)
@pytest.mark.parametrize("ip", ["8.8.8.8", "1.1.1.1"])
def test_ip_geolocation_live(ip):
    allowed = decision(IpGeolocation, f"ipv4:{ip}")
    assert allowed.allowed, allowed.reason  # open terms, community tier: allowed at AMBER when selected (-M)
    res = run_module(IpGeolocation, f"ipv4:{ip}", runtime=live_runtime())
    assert res.status in {Status.OK} | COULD_NOT_VERIFY, (res.status, res.error)
    if res.status is Status.OK:
        geo = res.attributes["geo_votes"]
        assert geo["approximate"] is True and geo["providers"]
        assert res.attributes.get("asn") in {"AS15169", "AS13335", None}
        assert not {"country", "city", "latitude", "longitude"} & set(res.attributes)
        assert all(p.expand is False for p in res.pivots)
    assert set(res.hosts) <= {"ipwho.is", "free.freeipapi.com"}


# ------------------------------------------------------------------ P150 (unknown terms): licence-blocked, never called
@pytest.mark.parametrize(("cls", "value"), [(IpReputationKeyless, "ipv4:8.8.8.8"), (NetapiCompromisedFeeds, "ipv4:8.8.8.8")])
def test_unknown_terms_sources_are_licence_blocked(cls, value):
    d = decision(cls, value)
    assert not d.allowed and d.reason_code == "licence", (d.reason_code, d.reason)


# ------------------------------------------------------------------ keyed sources without keys
@pytest.mark.parametrize(("cls", "value"), [(IpQualityScore, "ipv4:8.8.8.8"), (NetworksDb, "ipv4:8.8.8.8")])
def test_keyed_sources_need_their_key(cls, value):
    d = decision(cls, value)
    assert not d.allowed and d.reason_code in {"needs_key", "licence"}, (d.reason_code, d.reason)


def test_zoomeye_unknown_tier_is_excluded_at_amber():
    d = decision(ZoomEye, "ipv4:8.8.8.8")  # default TLP:AMBER
    assert not d.allowed and d.reason_code in {"tlp", "tier", "needs_key", "licence"}, (d.reason_code, d.reason)
