"""Live checks of batch p3-G02-1 (netlas, onyphe, censys, criminalip, fofa); run with V3LUM_LIVE=1.

Benign values only (8.8.8.8, example.com). Netlas is the only source of the batch that answers without
a key. Its keyless and Community use is noncommercial (P037 cond 1), so under the shipped corporate
profile the policy gate refuses it with 'licence'. The check asserts that decision. It then calls the
module directly, outside the gate, on the benign values, only to verify the parser against the live
answer: one request per value, the same requests the batch prep made on 2026-11-26.

The keyed sources are not called without company keys: ONYPHE, Censys, Criminal IP and FOFA. The check
asserts NEEDS_KEY before any request is sent. A 403/429/challenge/timeout from this datacenter egress is
an acceptable outcome when the module reports it as could-not-verify, never as an absence.
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
from v3lum.modules.ip_network.censys import Censys
from v3lum.modules.ip_network.criminalip import CriminalIp
from v3lum.modules.ip_network.fofa import Fofa
from v3lum.modules.ip_network.netlas import Netlas
from v3lum.modules.ip_network.onyphe import Onyphe

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


def test_netlas_is_licence_gated_under_corporate():
    dec = decision(Netlas, "ipv4:8.8.8.8")
    assert not dec.allowed and dec.reason_code == "licence", dec.reason


def test_netlas_keyless_ip_parser_live():
    res = run_module(Netlas, "ipv4:8.8.8.8", runtime=live_runtime())  # single run: keyless allowed (P037 cond 2)
    assert res.status in {Status.OK, Status.EMPTY} | COULD_NOT_VERIFY, (res.status, res.error)
    if res.status is Status.OK:
        a = res.attributes
        assert a.get("asn") == "AS15169" and 443 in a.get("open_ports", [])
        assert a["cohosting"]["mode"] == "count_only"  # tens of thousands of names: shared, count only (cond 5)
        assert not [p for p in res.pivots if p.relation == "hosted_domain"]
    assert set(res.hosts) <= {"app.netlas.io"}


def test_netlas_keyless_domain_parser_live():
    res = run_module(Netlas, "domain:example.com", runtime=live_runtime(), is_seed=False, depth=1)  # host answer only
    assert res.status in {Status.OK, Status.EMPTY} | COULD_NOT_VERIFY, (res.status, res.error)
    if res.status is Status.OK:
        a = res.attributes
        assert a.get("a_records") or a.get("aaaa_records") or a.get("nameservers")
        assert all(p.expand is False for p in res.pivots if p.relation in ("resolves_to", "nameserver", "mx_host"))
    assert set(res.hosts) <= {"app.netlas.io"}


@pytest.mark.parametrize(("cls", "value"), [(Onyphe, "ipv4:8.8.8.8"), (Censys, "ipv4:8.8.8.8"), (CriminalIp, "ipv4:8.8.8.8"),
                                            (Fofa, "domain:example.com")])
def test_keyed_sources_need_a_key_before_any_request(cls, value):
    res = run_module(cls, value, runtime=live_runtime())
    assert res.status is Status.NEEDS_KEY, (res.status, res.error)
    assert not res.hosts
