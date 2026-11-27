"""Live checks of batch p2-G02-1 (asn_context, abusix_contacts, ip_context_lists, ipinfo, shodan_api);
run with V3LUM_LIVE=1.

Benign values only: 8.8.8.8 / 2001:4860:4860::8888 (Google public DNS), AS15169 and AS22548 (NIC.br).
Keyless sources are called once each; the keyed modules (ipinfo, shodan_api) are checked to end
NEEDS_KEY without sending anything (keyless answers are never relied on). A 403/429/challenge/timeout
from this datacenter egress is an acceptable outcome when the module reports it as could-not-verify,
never as an absence.
"""

from __future__ import annotations

import pytest

from tests.fakes import FakeHttp, run_module
from v3lum.config import Config
from v3lum.core.context import Runtime
from v3lum.core.models import Status
from v3lum.modules.ip_network.abusix_contacts import AbusixContacts
from v3lum.modules.ip_network.asn_context import SRC_CIRCL, SRC_PDB, SRC_SS, AsnContext
from v3lum.modules.ip_network.ip_context_lists import LIST_BY_KEY, SRC_X4B, IpContextLists
from v3lum.modules.ip_network.ipinfo import IpInfo
from v3lum.modules.ip_network.shodan_api import ShodanApi

pytestmark = pytest.mark.live
COULD_NOT_VERIFY = {Status.BLOCKED, Status.RATE_LIMITED, Status.QUOTA, Status.ERROR, Status.UNAVAILABLE}


def live_runtime() -> Runtime:
    return Runtime(Config(), no_cache=True)


# ------------------------------------------------------------------ P033
def test_asn_context_ip_live():
    res = run_module(AsnContext, "ipv4:8.8.8.8", runtime=live_runtime())
    assert res.status in {Status.OK, Status.EMPTY} | COULD_NOT_VERIFY, (res.status, res.error)
    rows = {sid: row["status"] for sid, row in res.source_statuses.items()}
    assert set(rows) == {SRC_PDB, SRC_CIRCL, SRC_SS}, rows
    if rows[SRC_SS] == "ok":
        assert res.attributes["asn"] == "AS15169" and res.attributes["prefix"] == "8.8.8.0/24"
    if rows[SRC_CIRCL] == "ok" and "bgp_ranking" in res.attributes:
        assert 0 < res.attributes["bgp_ranking"]["percentile"] <= 100
        assert all(f.severity.label == "info" for f in res.findings)


def test_asn_context_asn_live():
    res = run_module(AsnContext, "asn:AS22548", runtime=live_runtime())
    assert res.status in {Status.OK, Status.EMPTY} | COULD_NOT_VERIFY, (res.status, res.error)
    rows = {sid: row["status"] for sid, row in res.source_statuses.items()}
    if rows.get(SRC_PDB) == "ok":
        net = res.attributes["peeringdb_network"]
        assert net["asn"] == 22548 and net["ix_count"] and "poc_set" not in net and "notes" not in net
    if rows.get(SRC_SS) == "ok":
        assert any(p.startswith("200.160.") for p in res.attributes["announced_prefixes"])


# ------------------------------------------------------------------ P041
@pytest.mark.parametrize("value", ["ipv4:8.8.8.8", "ipv6:2001:4860:4860::8888"])
def test_abusix_contacts_live(value):
    res = run_module(AbusixContacts, value, runtime=live_runtime())
    assert res.status in {Status.OK, Status.EMPTY} | COULD_NOT_VERIFY, (res.status, res.error)
    if res.status is Status.OK:
        assert res.attributes["abuse_contact"].endswith("@google.com")
        assert all(p.expand is False for p in res.pivots)


# ------------------------------------------------------------------ P035
def test_ip_context_lists_live():
    rt = live_runtime()
    res = run_module(IpContextLists, "ipv4:8.8.8.8", runtime=rt)
    # the Apple list (> 5 MB) is never downloaded during a run: without `v3lum data update` it is 'not checked'
    assert res.status in {Status.EMPTY, Status.UNAVAILABLE, Status.OK}, (res.status, res.error)
    if not res.source_statuses.get(SRC_X4B):
        info = rt.data.info(LIST_BY_KEY["x4bnet_datacenter_ipv4"].dataset)
        assert info.present and info.bytes > 150_000  # the daily list passed the validator
        assert res.raw["lists"]["ip_context_lists.x4bnet_datacenter_ipv4.txt"]["entries"] >= 5_000
    dom = run_module(IpContextLists, "domain:host.mooo.com", runtime=rt)
    assert dom.status in {Status.OK, Status.UNAVAILABLE}, (dom.status, dom.error)
    if dom.status is Status.OK:
        assert dom.attributes["context_tags"] == ["dynamic_dns"]


# ------------------------------------------------------------------ P036 / P039: keyed, never keyless
@pytest.mark.parametrize(("cls", "value"), [(IpInfo, "ipv4:8.8.8.8"), (ShodanApi, "ipv4:8.8.8.8"), (ShodanApi, "domain:example.com")])
def test_keyed_modules_need_their_key_and_send_nothing(cls, value):
    http = FakeHttp()  # no route: a keyless request would fail the test
    res = run_module(cls, value, http)
    assert res.status is Status.NEEDS_KEY and http.calls == []
