"""Live checks of batch p3-G01-1 (registrobr_domain_status; the keyed subdomains_keyed, subdomains_keyed_minor and
cl0q without keys); run with V3LUM_LIVE=1.

Keyless sources and benign values only: nic.br and registro.br (the registry's own names) as analyst-typed seeds.
No key is used and no keyed provider is contacted: without their keys the keyed modules must answer NEEDS_KEY
before any request. A 403/429/challenge/reset/timeout from this datacenter egress is an acceptable outcome when the
module reports it as could-not-verify (BLOCKED / RATE_LIMITED / QUOTA / ERROR), never as 'available' or an absence.
Validin (P017) is not delivered (app.validin.com resets connections from this egress: docs/backlog/p3-G01-1.md).
"""

from __future__ import annotations

import pytest

from tests.fakes import run_module
from v3lum.config import Config
from v3lum.core.context import Runtime
from v3lum.core.models import Status
from v3lum.modules.domain_dns.cl0q import Cl0q
from v3lum.modules.domain_dns.registrobr_domain_status import RegistrobrDomainStatus
from v3lum.modules.domain_dns.subdomains_keyed import SubdomainsKeyed, SubdomainsKeyedMinor

pytestmark = pytest.mark.live
COULD_NOT_VERIFY = {Status.BLOCKED, Status.RATE_LIMITED, Status.QUOTA, Status.ERROR}


def live_runtime(**settings):
    cfg = Config()
    cfg.settings.update(settings)
    return Runtime(cfg, no_cache=True)


@pytest.mark.parametrize("name", ["nic.br", "registro.br"])
def test_registrobr_domain_status_registry_names(name):
    res = run_module(RegistrobrDomainStatus, f"domain:{name}", runtime=live_runtime(), case_id=f"live-{name}")
    assert res.status in {Status.OK} | COULD_NOT_VERIFY, (res.status, res.error)
    if res.status is Status.OK:
        assert res.attributes["registrobr_status"] == "registered"
        rec = res.attributes["registrobr_availability"]
        assert rec["checked_name"] == name and rec["status_code"] == 2 and rec["exempt"] is True
        assert not res.findings and not res.pivots
    assert set(res.hosts) <= set(RegistrobrDomainStatus.hosts)


def test_registrobr_domain_status_never_sends_a_subdomain():
    res = run_module(RegistrobrDomainStatus, "domain:www.registro.br", runtime=live_runtime(), case_id="live-sub")
    assert res.status is Status.SKIPPED and not res.hosts


@pytest.mark.parametrize("cls,entity", [
    (SubdomainsKeyed, "domain:example.com"),
    (SubdomainsKeyedMinor, "domain:example.com"),
    (Cl0q, "domain:example.com"),
])
def test_keyed_modules_without_keys_need_a_key_and_send_nothing(cls, entity):
    res = run_module(cls, entity, runtime=live_runtime())
    assert res.status is Status.NEEDS_KEY and not res.hosts
