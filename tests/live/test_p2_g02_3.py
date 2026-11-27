"""Live checks of batch p2-G02-3 (greynoise_community, isc_dshield, leakix); run with V3LUM_LIVE=1.

The licence profile is respected here too: under the shipped corporate profile GreyNoise Community and
SANS ISC are 'noncommercial' (P148 c2, P151 c1) and LeakIX is 'key-terms' without a recorded business plan
(P274 c1), so none of them is called - each check asserts the policy decision instead (no request, the
manual link is emitted). When a licence_allow entry (or a recorded research basis) clears a source in the
analyst's V3LUM home, the module is run once against the benign value 8.8.8.8; a 429 (GreyNoise's weekly
per-egress quota), an ISC /blockme.html redirect or any challenge from this datacenter egress is an
acceptable outcome when it is reported as could-not-verify, never as an absence.

Recorded behaviour from this egress (2026-11-25/26, batch prep and implementation): GreyNoise answered
429 {plan: Community, rate_limit: 25-W} with X-Ratelimit-Remaining 0 (the recorded 8.8.8.8 404 'not
observed' fixture dates from 2026-11-25); ISC answered /api/ip/8.8.8.8?json with 200 JSON, then redirected
/api/threatfeeds and /api/asnum and finally /api/ to /blockme.html (temporary lock-out of the egress);
viz.greynoise.io answers 403 to scripts and every leakix.net web page redirects to /auth/login.
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
from v3lum.modules.pentest_recon.leakix import Leakix
from v3lum.modules.threat_intel_ioc.greynoise_community import GreynoiseCommunity
from v3lum.modules.threat_intel_ioc.isc_dshield import IscDshield

pytestmark = pytest.mark.live
COULD_NOT_VERIFY = {Status.BLOCKED, Status.RATE_LIMITED, Status.QUOTA, Status.ERROR}


def live_runtime() -> Runtime:
    return Runtime(Config(), no_cache=True)


def decision_for(cls, value: str, rt: Runtime | None = None):
    module_mod.load_modules()
    etype, _, raw = value.partition(":")
    ent = Entity.make(EntityType.parse(etype), raw)
    rt = rt or live_runtime()
    return policy.decide(cls, ent, policy.make_context(rt, ScanOptions(), path="run"), run=RunInfo(entity=ent, is_seed=True))


# ------------------------------------------------------------------ P148
def test_greynoise_community_live_or_licence_blocked():
    rt = live_runtime()
    decision = decision_for(GreynoiseCommunity, "ipv4:8.8.8.8", rt)
    if not decision.allowed:
        assert decision.reason_code in ("licence", "quota"), decision  # c2: off under corporate until licence-cleared
        assert decision.emit_manual_link
        return
    res = run_module(GreynoiseCommunity, "ipv4:8.8.8.8", runtime=rt)
    assert res.status in {Status.EMPTY, Status.OK} | COULD_NOT_VERIFY, (res.status, res.error)
    if res.status is Status.RATE_LIMITED:
        assert "never read as benign" in res.error  # c4: the free-key hint, never 'benign'
    if res.status in (Status.EMPTY, Status.OK):
        assert res.attributes["greynoise"]["state"] in ("not_observed", "riot", "noise", "no_flags")


# ------------------------------------------------------------------ P151
def test_isc_dshield_live_or_licence_blocked():
    rt = live_runtime()
    decision = decision_for(IscDshield, "ipv4:8.8.8.8", rt)
    if not decision.allowed:
        assert decision.reason_code in ("licence", "config"), decision  # c1 licence; c4 contact_email
        return
    res = run_module(IscDshield, "ipv4:8.8.8.8", runtime=rt)
    assert res.status in {Status.OK, Status.EMPTY} | COULD_NOT_VERIFY, (res.status, res.error)
    if res.status is Status.OK:
        assert res.attributes["asn"] == "AS15169" and res.attributes["data_attribution"] == "SANS ISC / DShield"


# ------------------------------------------------------------------ P274
def test_leakix_needs_a_business_key_and_sends_nothing_without_it():
    decision = decision_for(Leakix, "domain:example.com")
    if not decision.allowed:
        assert decision.reason_code in ("licence", "needs_key"), decision
        return
    rt = live_runtime()
    res = run_module(Leakix, "domain:example.com", runtime=rt)
    assert res.status in {Status.OK, Status.EMPTY, Status.NEEDS_KEY} | COULD_NOT_VERIFY, (res.status, res.error)
