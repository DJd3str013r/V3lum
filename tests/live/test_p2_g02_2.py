"""Live checks of batch p2-G02-2 (dnsbl, honeypot_intel, ip_anonymizer_consensus, honeypot_intel_extra);
run with V3LUM_LIVE=1.

Benign values only: 8.8.8.8 (Google public DNS), the RFC 5782 test points and CVE-2021-44228. The
licence profile is respected: under the shipped corporate profile only the 'open' DNSBLs (SpamCop,
DroneBL) are queried, and the 'unknown'-terms modules (every anonymizer provider, HoneyLabs and
jamesbrine.com.au) are licence-blocked, so the check asserts the policy decision and never calls
them. Keyed sources (Spamhaus DQS, http:BL, HoneyDB) are not called without keys. A 403/429/
challenge/timeout from this datacenter egress is an acceptable outcome when the module reports it
as could-not-verify, never as an absence.
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
from v3lum.modules.ip_network.dnsbl import Dnsbl
from v3lum.modules.ip_network.ip_anonymizer_consensus import IpAnonymizerConsensus
from v3lum.modules.threat_intel_ioc.honeypot_intel import ATTACKERS, KNOWN_SCANNERS, HoneypotIntel, noise_kind_for
from v3lum.modules.threat_intel_ioc.honeypot_intel_extra import HoneypotIntelExtra

pytestmark = pytest.mark.live
COULD_NOT_VERIFY = {Status.BLOCKED, Status.RATE_LIMITED, Status.QUOTA, Status.ERROR, Status.UNAVAILABLE}


def live_runtime() -> Runtime:
    return Runtime(Config(), no_cache=True)


def corporate_decision(cls, value: str):
    module_mod.load_modules()
    etype, _, raw = value.partition(":")
    ent = Entity.make(EntityType.parse(etype), raw)
    rt = live_runtime()
    return policy.decide(cls, ent, policy.make_context(rt, ScanOptions(), path="run"), run=RunInfo(entity=ent, is_seed=True))


# ------------------------------------------------------------------ P045
def test_dnsbl_open_lists_live():
    decision = corporate_decision(Dnsbl, "ipv4:8.8.8.8")
    assert decision.allowed and set(decision.allowed_sources or ()) >= {"spamcop.bl", "dronebl.dnsbl"}
    assert "uceprotect.level1" not in (decision.allowed_sources or ())  # noncommercial: off under corporate (P045 c2)
    res = run_module(Dnsbl, "ipv4:8.8.8.8", runtime=live_runtime(), allowed_sources=tuple(decision.allowed_sources or ()))
    assert res.status in {Status.EMPTY, Status.OK} | COULD_NOT_VERIFY, (res.status, res.error)
    if res.status is Status.EMPTY:
        # both test points answered as documented and 8.8.8.8 is not listed (P045 c6)
        assert res.attributes["dnsbl_summary"].startswith("not listed on 2 queried lists"), res.attributes
    rows = {sid: row["status"] for sid, row in res.source_statuses.items()}
    assert set(rows) >= {"spamcop.bl", "dronebl.dnsbl"}


# ------------------------------------------------------------------ P147
def test_honeypot_intel_offseq_live():
    rt = live_runtime()
    res = run_module(HoneypotIntel, "ipv4:8.8.8.8", runtime=rt, allowed_sources=("offseq.mirage_attackers", "offseq.mirage_known_scanners", "offseq.mirage_anonymizers"))
    assert res.status in {Status.EMPTY, Status.OK} | COULD_NOT_VERIFY, (res.status, res.error)
    if res.status in (Status.EMPTY, Status.OK):
        assert rt.data.info(ATTACKERS).present and rt.data.info(KNOWN_SCANNERS).present
        assert "malicious" not in {t for f in res.findings for t in f.tags}
        assert noise_kind_for("8.8.8.8") is None  # a public resolver is not a research scanner
        cve = run_module(HoneypotIntel, "cve:CVE-2021-44228", runtime=rt)
        assert cve.status in {Status.EMPTY, Status.OK}, (cve.status, cve.error)


def test_honeydb_needs_keys_and_is_not_called_without_them():
    decision = corporate_decision(HoneypotIntel, "ipv4:8.8.8.8")
    assert decision.allowed  # the OffSeq feed is open
    assert "honeydb.api" not in (decision.allowed_sources or ())  # key-terms without a business plan: licence (P147 c1)


# ------------------------------------------------------------------ unknown terms: licence-blocked, never called
@pytest.mark.parametrize(("cls", "value"), [
    (IpAnonymizerConsensus, "ipv4:8.8.8.8"),
    (HoneypotIntelExtra, "cve:CVE-2021-44228"),
    (HoneypotIntelExtra, "ipv4:8.8.8.8"),
])
def test_unknown_terms_modules_are_licence_blocked_under_corporate(cls, value):
    decision = corporate_decision(cls, value)
    assert not decision.allowed and decision.status is Status.SKIPPED, decision
    assert decision.reason_code in ("licence", "not_default", "tlp", "tier"), decision
