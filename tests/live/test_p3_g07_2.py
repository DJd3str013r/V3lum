"""Live checks of batch p3-G07-2 (triage, metadefender, malshare, polyswarm, virusshare,
filescan_reputation, structural_hash_pivots); run with V3LUM_LIVE=1.

Benign values only (the EICAR test file and an all-zero SHA-256). filescan_reputation is the only
keyless source: its terms are 'unknown' (P178 FC2), so the shipped corporate profile refuses it (the
check asserts that decision) and the module itself is called directly, as `v3lum run` would with a
recorded legal basis. The EICAR answer is about 3.5 MB decoded on 2026-11-26, above the 2 MB cap of
P178 FC3: ERROR 'response too large' is the expected outcome, never a parse of a cut body. The keyed
adapters (P177) and structural_hash_pivots (abuse.ch Auth-Key) are not called without company keys:
the check asserts NEEDS_KEY before any request. A 403/429/challenge/timeout from this datacenter
egress is an acceptable outcome when the module reports it as could-not-verify, never as an absence.
"""

from __future__ import annotations

import pytest

from tests.fakes import FakeHttp, run_module
from v3lum.config import Config
from v3lum.core import module as module_mod
from v3lum.core import policy
from v3lum.core.context import RunInfo, Runtime, ScanOptions
from v3lum.core.entities import Entity, EntityType
from v3lum.core.models import Status
from v3lum.modules.malware_hash.filescan_reputation import FilescanReputation
from v3lum.modules.malware_hash.hash_lookup_keyed import MalShare, MetaDefender, PolySwarm, Triage, VirusShare
from v3lum.modules.malware_hash.structural_hash_pivots import StructuralHashPivots

pytestmark = pytest.mark.live
COULD_NOT_VERIFY = {Status.BLOCKED, Status.RATE_LIMITED, Status.QUOTA, Status.ERROR, Status.UNAVAILABLE}
EICAR = "275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f"
ZERO = "0" * 64


def live_runtime() -> Runtime:
    return Runtime(Config(), no_cache=True)


def decision(cls, value: str, **options):
    module_mod.load_modules()
    etype, _, raw = value.partition(":")
    ent = Entity.make(EntityType.parse(etype), raw)
    pctx = policy.make_context(live_runtime(), ScanOptions(**options), explicit={cls.name}, path="run")
    return policy.decide(cls, ent, pctx, run=RunInfo(entity=ent, is_seed=True))


def test_filescan_terms_unknown_are_refused_under_the_corporate_profile():
    d = decision(FilescanReputation, f"sha256:{EICAR}")
    assert not d.allowed and d.reason_code == "licence", d


def test_filescan_eicar_answer_is_too_large_or_could_not_verify():
    res = run_module(FilescanReputation, f"sha256:{EICAR}", runtime=live_runtime())
    assert res.status in {Status.OK} | COULD_NOT_VERIFY, (res.status, res.error)
    if res.status is Status.ERROR:
        assert "too large" in res.error or "could not verify" in res.error
    if res.status is Status.OK:  # Filescan trimmed its answer below 2 MB: the parser must hold
        assert res.attributes["filescan"]["verdict"] in ("malicious", "suspicious")
        assert set(res.raw) == {"verdict", "tags", "report_ids"}
    assert set(res.hosts) <= {"www.filescan.io"}


def test_filescan_unknown_hash_is_an_absence_or_could_not_verify():
    res = run_module(FilescanReputation, f"sha256:{ZERO}", runtime=live_runtime())
    assert res.status in {Status.EMPTY} | COULD_NOT_VERIFY, (res.status, res.error)


@pytest.mark.parametrize("cls", [Triage, MetaDefender, MalShare, PolySwarm, VirusShare, StructuralHashPivots])
def test_keyed_sources_need_their_key_and_send_nothing(cls):
    http = FakeHttp()
    res = run_module(cls, f"sha256:{EICAR}", http)
    assert res.status is Status.NEEDS_KEY and not http.calls, (res.status, res.error)
