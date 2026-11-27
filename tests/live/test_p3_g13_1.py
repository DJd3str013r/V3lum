"""Live checks of batch p3-G13-1 (saas_tenant_discovery, cdn_origin_hypothesis); run with V3LUM_LIVE=1.

Benign values only: the vendors' own tenants (okta.okta.com, ecosystem.atlassian.net, support.zendesk.com) and
the random name the research used (thisorgdoesnotexist0000x), reached through synthetic org profiles. No login,
sign-up, reset or user endpoint is requested (the module cannot build one). A 403/429/challenge/timeout from this
datacenter egress is an acceptable outcome when it is reported as 'unknown' / could-not-verify, never 'absent'.
cdn_origin_hypothesis makes no request at all: its live check asserts that even with the network open.
"""

from __future__ import annotations

import pytest

from tests.fakes import run_module
from v3lum.config import Config
from v3lum.core.context import Runtime
from v3lum.core.models import Status
from v3lum.core.orgprofile import OrgProfile
from v3lum.modules.pentest_recon import saas_tenant_discovery as std
from v3lum.modules.pentest_recon.cdn_origin_hypothesis import CdnOriginHypothesis
from v3lum.modules.pentest_recon.saas_tenant_discovery import SaasTenantDiscovery

pytestmark = pytest.mark.live
COULD_NOT_VERIFY = {Status.BLOCKED, Status.RATE_LIMITED, Status.QUOTA, Status.ERROR}


def live_runtime(profile: dict) -> Runtime:
    return Runtime(Config(), no_cache=True, org=OrgProfile.from_dict(profile))


def _rows(res) -> dict[tuple[str, str], dict]:
    return {(r["vendor"], r["candidate"]): r for r in res.attributes.get("saas_tenant_checks", [])}


def test_vendor_own_tenants_exist_or_could_not_verify() -> None:
    profile = {"org": {"name": "Okta"}, "domains": [{"name": "okta.example"}, {"name": "ecosystem.example"}, {"name": "support.example"}]}
    res = run_module(SaasTenantDiscovery, "domain:okta.example", runtime=live_runtime(profile), case_id="live-p3g131-own")
    assert res.status in {Status.OK, Status.EMPTY} | COULD_NOT_VERIFY, (res.status, res.error)
    rows = _rows(res)
    assert set(res.hosts) and all(h.endswith((".okta.com", ".atlassian.net", ".zendesk.com")) for h in res.hosts)
    for key, expected in ((("okta", "okta"), "exists"), (("atlassian", "ecosystem"), "exists"), (("zendesk", "support"), "exists")):
        row = rows[key]
        assert row["state"] in (expected, "unknown"), row  # never 'absent' for a tenant that exists
        print(key, row["state"], row["marker"], row["reason"], row["http_status"])
    assert rows[("okta", "support")]["reason"].startswith("refused")  # 'support' is an Okta service label: never sent


def test_random_name_is_absent_or_could_not_verify() -> None:
    profile = {"org": {"name": "Nonexistent"}, "domains": [{"name": "thisorgdoesnotexist0000x.example"}]}
    res = run_module(SaasTenantDiscovery, "domain:thisorgdoesnotexist0000x.example", runtime=live_runtime(profile), case_id="live-p3g131-random")
    assert res.status in {Status.OK, Status.EMPTY} | COULD_NOT_VERIFY, (res.status, res.error)
    for row in res.attributes.get("saas_tenant_checks", []):
        assert row["state"] in ("absent", "unknown"), row
        print(row["vendor"], row["state"], row["marker"], row["reason"], row["http_status"])
    for url in res.attributes.get("saas_tenant_checks", []):
        assert url["url"] is None or std.rule2_violation(url["url"]) is None


def test_cdn_origin_hypothesis_module_never_touches_the_network() -> None:
    res = run_module(CdnOriginHypothesis, "domain:example.com", runtime=Runtime(Config(), no_cache=True))
    assert res.status is Status.OK and res.hosts == {} and len(res.links) == 2
