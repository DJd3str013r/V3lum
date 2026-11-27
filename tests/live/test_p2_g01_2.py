"""Live checks of batch p2-G01-2 (tranco_rank P010, m365_tenant + m365_tenant_azmap P011, hackertarget P014,
passive_dns P015); run with V3LUM_LIVE=1.

Keyless sources only, benign public values: the real Tranco daily list (downloaded through the dataset
manager exactly as `v3lum data update` does, matched locally: google.com, a phishing-style path on
sites.google.com and a name under the PSL private suffix github.io), Microsoft's domain-level tenant
endpoints for microsoft.com and cloudflare.com (GetUserRealm only with the fixed probe local part),
azmap.dev for microsoft.com (unknown operator: one call, DoH confirmations through the core resolvers),
HackerTarget for 8.8.8.8 (the shared datacenter egress usually has the free quota used up: QUOTA is the
expected 'could not verify') and mnemonic + Robtex passive DNS for example.com (CIRCL needs the team's own
account: NEEDS_KEY for that feed without any request). A 403/429/geo-block/timeout from this datacenter
egress is an acceptable outcome when the module reports it as could-not-verify, never as an absence.
"""

from __future__ import annotations

import json

import pytest

from tests.fakes import run_module
from v3lum.config import Config
from v3lum.core.context import Runtime
from v3lum.core.entities import EntityType
from v3lum.core.models import Status
from v3lum.modules.domain_dns import tranco_rank as TR
from v3lum.modules.domain_dns.hackertarget import QUOTA_LINE, HackerTarget
from v3lum.modules.domain_dns.m365_tenant import M365Tenant
from v3lum.modules.domain_dns.m365_tenant_azmap import M365TenantAzmap
from v3lum.modules.domain_dns.passive_dns import CIRCL, PassiveDns
from v3lum.modules.domain_dns.tranco_rank import TrancoRank

pytestmark = pytest.mark.live
COULD_NOT_VERIFY = {Status.BLOCKED, Status.RATE_LIMITED, Status.QUOTA, Status.ERROR, Status.UNAVAILABLE}
MICROSOFT_TENANT = "72f988bf-86f1-41af-91ab-2d7cd011db47"


def live_runtime(**settings) -> Runtime:
    cfg = Config()
    cfg.settings.update(settings)
    return Runtime(cfg, no_cache=True)


def outcome(res) -> str:
    return f"{res.status.value} {res.reason_code or ''} {res.error[:300]} {json.dumps(res.source_statuses, default=str)[:500]}"


# ------------------------------------------------------------------ P010 tranco_rank
def test_tranco_rank_real_daily_list():
    rt = live_runtime()
    update = rt.data.update(TR.LIST_DATASET)
    print("tranco list update:", update)
    if not update.ok:
        res = run_module(TrancoRank, "domain:google.com", runtime=rt)
        print("tranco_rank without the list:", outcome(res))
        assert (res.status, res.reason_code) == (Status.UNAVAILABLE, "dataset"), outcome(res)
        return
    id_update = rt.data.update(TR.ID_DATASET)
    print("tranco id update:", id_update)
    res = run_module(TrancoRank, "domain:google.com", runtime=rt)
    print("tranco_rank google.com:", outcome(res), res.attributes.get("tranco_context"))
    assert res.status is Status.OK, outcome(res)
    attrs = res.attributes
    assert 1 <= attrs["tranco_rank"] <= 10 and attrs["tranco_popularity"] == "popular"
    assert attrs["tranco_dampener"]["dampen"] is True and res.findings == []
    assert attrs["tranco_list"]["sha256"] == rt.data.info(TR.LIST_DATASET).sha256
    if id_update.ok:
        assert TR._LIST_ID.match(attrs["tranco_list"]["list_id"])
    # P010 c4: a phishing-style URL on a top shared platform keeps its full score
    shared = run_module(TrancoRank, "url:https://sites.google.com/view/account-verify-0000/home", runtime=rt)
    print("tranco_rank sites.google.com URL:", outcome(shared), shared.attributes.get("tranco_context"))
    assert shared.status is Status.OK and shared.attributes["tranco_dampener"]["dampen"] is False
    assert shared.attributes["shared_platform"]["platform"] == "sites.google.com"
    # P010 c5: a name under a PSL private suffix is ranked per registrable domain, never by github.io's rank
    private = run_module(TrancoRank, "domain:v3lum-live-check-0000.github.io", runtime=rt)
    print("tranco_rank under github.io:", outcome(private), private.attributes.get("tranco_context"))
    assert private.status is Status.OK
    assert private.attributes["tranco_lookup_domain"] == "v3lum-live-check-0000.github.io"
    assert private.attributes["tranco_popularity"] == "not in top 1M" and "tranco_rank" not in private.attributes


# ------------------------------------------------------------------ P011 m365_tenant
def test_m365_tenant_microsoft_and_cloudflare():
    rt = live_runtime()
    res = run_module(M365Tenant, "domain:microsoft.com", runtime=rt)
    print("m365_tenant microsoft.com:", outcome(res), {k: v for k, v in res.attributes.items() if k.startswith("m365_")})
    realm = (res.raw or {}).get("realm") or {}
    if realm.get("login_is_probe") is not None:  # P011 c2: Microsoft echoes the only local part ever sent
        assert realm["login_is_probe"] is True, realm
    assert res.status in {Status.OK} | COULD_NOT_VERIFY, outcome(res)
    if res.status is Status.OK:
        assert res.attributes["m365_tenant_id"] == MICROSOFT_TENANT
        assert res.attributes.get("m365_namespace_type") in {"Managed", None}  # None: realm could not be verified
    fed = run_module(M365Tenant, "domain:cloudflare.com", runtime=rt)
    print("m365_tenant cloudflare.com:", outcome(fed), fed.attributes.get("m365_identity_provider"))
    assert fed.status in {Status.OK} | COULD_NOT_VERIFY, outcome(fed)
    if fed.status is Status.OK and fed.attributes.get("m365_namespace_type") == "Federated":
        idp = fed.attributes["m365_identity_provider"]
        assert "?" not in idp["url"]  # the AuthURL query echoes the probe login: dropped
        if idp["kind"] != "microsoft_sts":
            assert any(p.relation == "identity_provider" and p.entity.value == idp["host"] for p in fed.pivots)


# ------------------------------------------------------------------ P011 m365_tenant_azmap (unknown operator)
def test_m365_tenant_azmap_microsoft_com():
    rt = live_runtime()
    res = run_module(M365TenantAzmap, "domain:microsoft.com", runtime=rt)
    confirmation = res.attributes.get("m365_dns_confirmation", {})
    print("m365_tenant_azmap microsoft.com:", outcome(res), res.attributes.get("m365_related_domains", {}).get("count"),
          {k: confirmation.get(k) for k in ("checked", "confirmed", "doh_queries", "stop_reason")})
    assert res.status in {Status.OK} | COULD_NOT_VERIFY, outcome(res)
    if res.status is Status.OK:
        assert res.attributes["m365_tenant_id"] == MICROSOFT_TENANT
        assert res.attributes["m365_related_domains"]["count"] >= 10
        assert confirmation["doh_queries"] <= 100 and confirmation["checked"] <= 50
        pivots = [p for p in res.pivots if p.relation == "same_m365_tenant"]
        assert len(pivots) <= 10 and all(p.entity.value in confirmation["confirmed"] for p in pivots)


# ------------------------------------------------------------------ P014 hackertarget
def test_hackertarget_ipv4_8_8_8_8():
    rt = live_runtime()
    res = run_module(HackerTarget, "ipv4:8.8.8.8", runtime=rt)
    print("hackertarget 8.8.8.8:", outcome(res), res.attributes.get("asn"), res.attributes.get("cohosting"), res.raw)
    assert res.status in {Status.OK, Status.EMPTY} | COULD_NOT_VERIFY, outcome(res)
    if res.status is Status.QUOTA:
        assert res.error == QUOTA_LINE and res.reason_code == "quota"  # P014 c2/c7: never EMPTY
    if res.attributes.get("asn"):
        assert res.attributes["asn"] == "AS15169"
    if res.attributes.get("cohosting"):  # 8.8.8.8 is a public resolver: counts only (P014 c6)
        assert res.attributes["cohosting"]["mode"] == "count_only"
        assert not [p for p in res.pivots if p.relation == "hosted_domain"]


# ------------------------------------------------------------------ P015 passive_dns
def test_passive_dns_example_com():
    rt = live_runtime(passive_dns_mnemonic_pages=1)
    res = run_module(PassiveDns, "domain:example.com", runtime=rt)
    print("passive_dns example.com:", outcome(res), res.attributes.get("pdns_summary"), res.attributes.get("pdns_record_count"))
    assert res.status in {Status.OK, Status.EMPTY} | COULD_NOT_VERIFY | {Status.NEEDS_KEY}, outcome(res)
    statuses = dict(res.source_statuses or {})
    print("per-feed:", json.dumps(statuses, default=str)[:600])
    assert statuses[CIRCL]["status"] == "needs_key"  # no account: NEEDS_KEY for CIRCL only, no request
    assert "www.circl.lu" not in (res.hosts or {})
    if res.status is Status.OK:
        rows = res.attributes["passive_dns"]
        assert 0 < len(rows) <= 20 and res.attributes["pdns_summary"].startswith("resolved to")
        assert all(r["sources"] and ("first_seen" in r and "last_seen" in r) for r in rows)
        for p in res.pivots:  # P015 c6: only records seen inside the last 12 months pivot
            assert p.entity.type in {EntityType.IPV4, EntityType.IPV6, EntityType.DOMAIN}
