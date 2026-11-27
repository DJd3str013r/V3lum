"""Live checks of batch p3-G07-1 (maltiverse, ibm_xforce, pulsedive, kaspersky_opentip,
stopforumspam, cymru_mhr); run with V3LUM_LIVE=1.

Benign values only: 8.8.8.8 and the documentation address test@example.com for StopForumSpam (the
address leaves the machine only as its MD5), the EICAR test-file MD5 and an all-zero MD5 for Team
Cymru MHR. Both keyless sources are 'noncommercial': the shipped corporate profile refuses them (the
checks assert that decision) and the modules are called directly, as ``v3lum run`` would with a
recorded licence decision. The keyed modules are not called without company keys: the checks assert
that nothing is sent. A 403/429/challenge/timeout from this datacenter egress is an acceptable
outcome when the module reports it as could-not-verify, never as an absence.
"""

from __future__ import annotations

import pytest

from tests.fakes import FakeHttp, run_module
from v3lum.config import Config
from v3lum.core import module as module_mod
from v3lum.core import policy
from v3lum.core.context import RunInfo, Runtime, ScanOptions
from v3lum.core.entities import Entity, EntityType
from v3lum.core.models import Severity, Status
from v3lum.modules.malware_hash.cymru_mhr import CymruMHR
from v3lum.modules.threat_intel_ioc.ibm_xforce import IBMXForce
from v3lum.modules.threat_intel_ioc.kaspersky_opentip import KasperskyOpenTIP
from v3lum.modules.threat_intel_ioc.maltiverse import Maltiverse
from v3lum.modules.threat_intel_ioc.pulsedive import Pulsedive
from v3lum.modules.threat_intel_ioc.stopforumspam import StopForumSpam

pytestmark = pytest.mark.live
COULD_NOT_VERIFY = {Status.BLOCKED, Status.RATE_LIMITED, Status.QUOTA, Status.ERROR, Status.UNAVAILABLE}
EICAR_MD5 = "44d88612fea8a8f36de82e1278abb02f"


def live_runtime() -> Runtime:
    return Runtime(Config(), no_cache=True)


def decision(cls, value: str, **options):
    module_mod.load_modules()
    etype, _, raw = value.partition(":")
    ent = Entity.make(EntityType.parse(etype), raw)
    pctx = policy.make_context(live_runtime(), ScanOptions(**options), explicit={cls.name}, path="run")
    return policy.decide(cls, ent, pctx, run=RunInfo(entity=ent, is_seed=True))


@pytest.mark.parametrize(("cls", "value"), [(StopForumSpam, "ipv4:8.8.8.8"), (CymruMHR, f"md5:{EICAR_MD5}")])
def test_noncommercial_sources_are_refused_under_the_corporate_profile(cls, value):
    d = decision(cls, value)
    assert not d.allowed and d.reason_code == "licence", d


def test_stopforumspam_ip_answer_or_could_not_verify():
    res = run_module(StopForumSpam, "ipv4:8.8.8.8", runtime=live_runtime())
    assert res.status in {Status.OK, Status.EMPTY} | COULD_NOT_VERIFY, (res.status, res.error)
    if res.status in (Status.OK, Status.EMPTY):
        assert "ip" in res.attributes["stopforumspam"]
        assert all(f.severity <= Severity.LOW and f.data["counts_in_consensus"] is False for f in res.findings)
    assert set(res.hosts) <= {"api.stopforumspam.org"}


def test_stopforumspam_email_is_sent_only_as_its_md5():
    res = run_module(StopForumSpam, "email:test@example.com", runtime=live_runtime())
    assert res.status in {Status.OK, Status.EMPTY} | COULD_NOT_VERIFY, (res.status, res.error)
    if res.status is Status.OK:
        assert res.findings[0].tags[0] == "spam" and res.findings[0].severity <= Severity.LOW
    assert "test@example.com" not in str(res.raw)


def test_cymru_mhr_eicar_is_known_malware_or_could_not_verify():
    res = run_module(CymruMHR, f"md5:{EICAR_MD5}", runtime=live_runtime())
    assert res.status in {Status.OK} | COULD_NOT_VERIFY, (res.status, res.error)
    if res.status is Status.OK:
        mhr = res.attributes["cymru_mhr"]
        assert mhr["detection_pct"] >= 30 and res.findings[0].title == "Known malware hash (Team Cymru MHR)"


def test_cymru_mhr_unknown_hash_is_an_absence_or_could_not_verify():
    res = run_module(CymruMHR, f"md5:{'0' * 32}", runtime=live_runtime())
    assert res.status in {Status.EMPTY} | COULD_NOT_VERIFY, (res.status, res.error)
    assert not res.findings


@pytest.mark.parametrize(("cls", "value"), [(Maltiverse, "ipv4:8.8.8.8"), (Pulsedive, "domain:example.com"),
                                            (IBMXForce, "ipv4:8.8.8.8"), (KasperskyOpenTIP, f"md5:{EICAR_MD5}")])
def test_keyed_sources_send_nothing_without_the_company_key(cls, value):
    http = FakeHttp()
    res = run_module(cls, value, http)
    assert res.status in {Status.NEEDS_KEY, Status.SKIPPED} and not http.calls, (res.status, res.error)
