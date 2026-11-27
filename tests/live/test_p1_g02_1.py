"""Live checks of batch p1-G02-1 (ripestat, team_cymru_asn, cloud_ranges, nicbr_asn); run with V3LUM_LIVE=1.

Keyless sources, benign public values only: 8.8.8.8 / AS15169 / 2001:4860:4860::8888 (Google public
DNS), 1.1.1.1 (Cloudflare), 104.16.1.1 (a Cloudflare edge), 3.5.140.10 (an AWS EC2 block),
200.160.2.3 (registro.br) and CNPJ 00.000.000/0001-91 (the golden CNPJ input). The dataset modules
download the real provider files and the NIC.br list through the dataset manager, then match
offline.

A 403/429/challenge/timeout from this datacenter egress is an acceptable outcome when the module
reports it as could-not-verify (BLOCKED / RATE_LIMITED / QUOTA / ERROR / UNAVAILABLE), never as an
absence. Known from the research egress: api.github.com/meta is refused by the session's own egress
policy, so cloud_ranges reports that feed per source and answers 'not cloud' only with every
dataset loaded.
"""

from __future__ import annotations

import pytest

from tests.fakes import run_module
from v3lum.config import Config
from v3lum.core.context import Runtime
from v3lum.core.entities import EntityType as T
from v3lum.core.models import Status
from v3lum.modules.ip_network.cloud_ranges import CloudRanges
from v3lum.modules.ip_network.nicbr_asn import NicbrAsn
from v3lum.modules.ip_network.ripestat import RipeStat
from v3lum.modules.ip_network.team_cymru_asn import TeamCymruAsn

pytestmark = pytest.mark.live
COULD_NOT_VERIFY = {Status.BLOCKED, Status.RATE_LIMITED, Status.QUOTA, Status.ERROR, Status.UNAVAILABLE}


def live_runtime():
    return Runtime(Config(), no_cache=True)


def test_ripestat_ip_8888():
    res = run_module(RipeStat, "ipv4:8.8.8.8", runtime=live_runtime())
    assert res.status in {Status.OK} | COULD_NOT_VERIFY, (res.status, res.error)
    if res.status is Status.OK:
        assert res.attributes["asn"] == "AS15169" and res.attributes["prefix"] == "8.8.8.0/24"
        assert res.attributes.get("abuse_contact", "").endswith("@google.com")
        assert all(c["source"] == "ripestat.data_api" for c in res.attributes.get("abuse_contacts", []))
        assert res.requests <= RipeStat.max_requests


def test_ripestat_asn_15169():
    res = run_module(RipeStat, "asn:AS15169", runtime=live_runtime())
    assert res.status in {Status.OK} | COULD_NOT_VERIFY, (res.status, res.error)
    if res.status is Status.OK:
        counts = res.attributes["announced_prefix_counts"]
        assert counts["total"] >= counts["pivoted"] and counts["pivoted"] <= 100
        assert len([p for p in res.pivots if p.relation == "announces"]) == counts["pivoted"]


def test_ripestat_company_name():
    res = run_module(RipeStat, "company_name:cloudflare", runtime=live_runtime())
    assert res.status in {Status.OK, Status.EMPTY} | COULD_NOT_VERIFY, (res.status, res.error)
    if res.status is Status.OK:
        assert all(not p.expand and p.relation == "owns_network" for p in res.pivots)


@pytest.mark.parametrize(("value", "asn", "prefix"), [("ipv4:8.8.8.8", "AS15169", "8.8.8.0/24"), ("ipv6:2001:4860:4860::8888", "AS15169", None)])
def test_team_cymru_origin(value, asn, prefix):
    res = run_module(TeamCymruAsn, value, runtime=live_runtime())
    assert res.status in {Status.OK} | COULD_NOT_VERIFY, (res.status, res.error)
    if res.status is Status.OK:
        assert res.attributes["asn"] == asn and res.attributes["as_org"] == "Google LLC"
        if prefix:
            assert res.attributes["prefix"] == prefix


def test_team_cymru_asn_name():
    res = run_module(TeamCymruAsn, "asn:AS15169", runtime=live_runtime())
    assert res.status in {Status.OK} | COULD_NOT_VERIFY, (res.status, res.error)
    if res.status is Status.OK:
        assert res.attributes["as_org"] == "Google LLC" and res.attributes["country"] == "US"


def test_cloud_ranges_edge_and_compute():
    rt = live_runtime()
    edge = run_module(CloudRanges, "ipv4:104.16.1.1", runtime=rt)
    assert edge.status in {Status.OK} | COULD_NOT_VERIFY, (edge.status, edge.error)
    if edge.status is Status.OK:
        assert edge.attributes["cloud_role"] == "cdn_edge" and edge.attributes["third_party_hosted"] is True
    compute = run_module(CloudRanges, "ipv4:3.5.140.10", runtime=rt)
    assert compute.status in {Status.OK} | COULD_NOT_VERIFY, (compute.status, compute.error)
    if compute.status is Status.OK:
        assert compute.attributes["cloud_provider"] == "AWS" and compute.attributes["cloud_role"] in ("iaas", "shared_hosting", "provider_network")
        assert "third_party_hosted" not in compute.attributes or compute.attributes["cloud_role"] != "iaas"
    for feed in edge.source_statuses.values():  # every feed that failed is reported, never silently dropped
        assert feed["status"] == "unavailable" and feed["reason_code"] == "dataset"


def test_nicbr_asn_registro_br_and_golden_cnpj():
    rt = live_runtime()
    res = run_module(NicbrAsn, "ipv4:200.160.2.3", runtime=rt)
    assert res.status in {Status.OK} | COULD_NOT_VERIFY, (res.status, res.error)
    if res.status is Status.OK:
        assert res.attributes["asn"] == "AS22548" and res.attributes["owner_cnpj"] == "05.506.560/0001-36"
        assert (T.CNPJ, "05506560000136") in {(p.entity.type, p.entity.value) for p in res.pivots}
    cnpj = run_module(NicbrAsn, "cnpj:00000000000191", runtime=rt)
    assert cnpj.status in {Status.OK} | COULD_NOT_VERIFY, (cnpj.status, cnpj.error)
    if cnpj.status is Status.OK:
        assert "AS11993" in cnpj.attributes["owned_networks"]["asns"]
