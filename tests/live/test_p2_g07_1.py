"""Live checks of batch p2-G07-1 (crowdsec_cti P152, abuseipdb P157, virustotal P158, hybrid_analysis P174,
lol_datasets P268); run with V3LUM_LIVE=1.

Only the keyless source is called: lol_datasets refreshes its four datasets through the real dataset
manager (validators included; LOLDrivers is 36 MB and is downloaded here because `v3lum data update`
runs outside a scan) and then answers benign public values offline: the LOLBAS binary certutil.exe,
the HijackLibs DLL sqlite.dll, the LOLRMM tool AnyDesk and the hash of the well-known vulnerable Intel
driver iqvw64e.sys (CVE-2015-2291). The four keyed APIs are never called without a team key: the checks
only assert that they refuse to send anything (NEEDS_KEY before any request).

A 403/429/challenge/timeout from this datacenter egress is an acceptable outcome when it is reported as
could-not-verify (a failed update installs nothing; the module then answers UNAVAILABLE 'dataset', never
an absence).
"""

from __future__ import annotations

import pytest

from tests.fakes import FakeHttp, run_module
from v3lum.config import Config
from v3lum.core.context import Runtime
from v3lum.core.models import Severity, Status
from v3lum.modules.malware_hash import lol_datasets as lol
from v3lum.modules.malware_hash.hybrid_analysis import HybridAnalysis
from v3lum.modules.malware_hash.lol_datasets import LolDatasets
from v3lum.modules.threat_intel_ioc.abuseipdb import AbuseIPDB
from v3lum.modules.threat_intel_ioc.crowdsec_cti import CrowdsecCti
from v3lum.modules.threat_intel_ioc.virustotal import VirusTotal

pytestmark = pytest.mark.live
IQVW64E_SHA256 = "4429f32db1cc70567919d7d47b844a91cf1329a6cd116f582305f3b7b60cd60b"


def live_runtime() -> Runtime:
    return Runtime(Config(), no_cache=True)


def _update(rt: Runtime, name: str) -> bool:
    result = rt.data.update(name)
    print(f"{name}: {result.status} {result.reason[:160]} {result.new_sha256[:12]}")
    assert result.status in ("updated", "unchanged", "failed")
    if result.status == "failed":
        assert result.reason  # could not verify from this egress: reported, nothing installed
    return result.ok


def test_lol_datasets_refresh_and_offline_answers_live():
    rt = live_runtime()
    lol.reset_memo()
    ok = {name: _update(rt, name) for name in (lol.DS_LOLBAS, lol.DS_HIJACKLIBS, lol.DS_LOLRMM, lol.DS_LOLDRIVERS)}
    if ok[lol.DS_LOLBAS]:
        res = run_module(LolDatasets, "keyword:certutil.exe -urlcache -split -f", runtime=rt)
        titles = {f.title for f in res.findings}
        assert "LOLBAS binary (living off the land)" in titles
        assert all(f.severity is Severity.INFO and "context_only" in f.tags for f in res.findings)
    if ok[lol.DS_HIJACKLIBS]:
        res = run_module(LolDatasets, "keyword:sqlite.dll", runtime=rt)
        assert any(f.title == "HijackLibs DLL-hijack candidate" for f in res.findings)
    if ok[lol.DS_LOLRMM]:
        res = run_module(LolDatasets, "keyword:AnyDesk", runtime=rt)
        assert any("rmm_tool" in f.tags for f in res.findings)
    if ok[lol.DS_LOLDRIVERS]:
        res = run_module(LolDatasets, f"sha256:{IQVW64E_SHA256}", runtime=rt)
        driver = [f for f in res.findings if f.source == "loldrivers.dataset"]
        assert driver and driver[0].title == "Known vulnerable driver - BYOVD (LOLDrivers)"
        index = lol.load_index(lol.DS_LOLDRIVERS, rt.data.path(lol.DS_LOLDRIVERS))
        print(f"loldrivers slim index: {index['stats']}")
        assert index["stats"]["drivers"] >= lol.MIN_ITEMS[lol.DS_LOLDRIVERS]
    if not any(ok.values()):
        pytest.skip("no LOL dataset could be refreshed from this egress (reported as could not verify)")


@pytest.mark.parametrize("cls,entity", [
    (CrowdsecCti, "ipv4:8.8.8.8"),
    (AbuseIPDB, "ipv4:8.8.8.8"),
    (VirusTotal, "domain:example.com"),
    (HybridAnalysis, "sha256:275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f"),
])
def test_keyed_modules_never_send_without_a_key_live(cls, entity):
    http = FakeHttp()  # nothing may reach the network: the key check comes first
    res = run_module(cls, entity, http)
    assert res.status is Status.NEEDS_KEY and not http.calls
