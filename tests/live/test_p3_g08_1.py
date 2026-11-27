"""Live checks of batch p3-G08-1 (shodan_cvedb, euvd, csaf_advisories, csaf_redhat_vex,
debian_security_tracker): keyless sources and the benign public value CVE-2021-44228 (Log4Shell) only.

Run once with ``V3LUM_LIVE=1 pytest -q -m live tests/live/test_p3_g08_1.py``. Each test has its own empty
V3LUM home. A 403/429/challenge from a datacenter egress is an acceptable outcome when the module reports
it as could-not-verify (rule 5): the test is then skipped with the reason. The CSAF sync fetches at most
one document per vendor; the Debian check downloads the real tracker export (~15 MB gzip) once and builds
the index with the real validator.
"""

from __future__ import annotations

import pytest

from v3lum.config import Config
from v3lum.core.context import Runtime, ScanOptions
from v3lum.core.engine import Engine
from v3lum.core.entities import Entity
from v3lum.core.entities import EntityType as T
from v3lum.core.models import Status
from v3lum.modules.vulnerability_cve.csaf_advisories import CsafAdvisories, sync_csaf
from v3lum.modules.vulnerability_cve.csaf_redhat_vex import CsafRedhatVex
from v3lum.modules.vulnerability_cve.debian_security_tracker import DATASET, DebianSecurityTracker
from v3lum.modules.vulnerability_cve.euvd import Euvd
from v3lum.modules.vulnerability_cve.shodan_cvedb import ShodanCvedb

pytestmark = pytest.mark.live
CVE = "CVE-2021-44228"
COULD_NOT_VERIFY = (Status.BLOCKED, Status.RATE_LIMITED, Status.QUOTA)


def _runtime() -> Runtime:
    return Runtime(Config(), no_cache=True)


def _run(cls, value: str = CVE, etype: T = T.CVE, runtime: Runtime | None = None):
    return Engine(runtime or _runtime(), ScanOptions()).run_module(cls, Entity.make(etype, value))


def _skip_if_refused(res) -> None:
    if res.status in COULD_NOT_VERIFY:
        pytest.skip(f"{res.module} could not be verified from this egress: {res.status.value} {res.reason_code} {res.error}")


def test_live_shodan_cvedb_record():
    res = _run(ShodanCvedb)
    _skip_if_refused(res)
    assert res.status is Status.OK, res.error
    a = res.attributes
    assert "kev" not in a and a["exploited"] == {"cisa_kev_via_shodan_cvedb": None}
    assert any(c["score"] == 10.0 for c in a["cvss_scores"]) and a["epss"] > 0.9


def test_live_shodan_cvedb_product_search():
    res = _run(ShodanCvedb, "log4j", T.KEYWORD)
    _skip_if_refused(res)
    if res.status is Status.ERROR and res.reason_code == "timeout":
        pytest.skip("CVEDB product search timed out (observed 6 s TTFB on 2026-11-26): could not verify")
    assert res.status is Status.OK, res.error
    assert res.attributes["cvedb_search_hits"] and all(p.entity.type is T.CVE for p in res.pivots)


def test_live_euvd_record_within_the_cap():
    res = _run(Euvd)
    _skip_if_refused(res)
    assert res.status is Status.OK, res.error
    a = res.attributes
    assert a["advisory_aliases"][0].startswith("EUVD-") and a["exploited"]["euvd"].startswith("2021-")
    assert not res.pivots


def test_live_csaf_redhat_vex():
    res = _run(CsafRedhatVex)
    _skip_if_refused(res)
    assert res.status is Status.OK, res.error
    counts = res.attributes["vex_statuses"]["counts"]
    assert counts["fixed"] > 0 and counts["not_affected"] > 0


def test_live_csaf_sync_one_document_per_vendor_then_offline_lookup():
    runtime = _runtime()
    summary = sync_csaf(runtime, max_docs=1, doc_interval=1.0)
    statuses = {v: s["status"] for v, s in summary["vendors"].items()}
    if all(s == "error" for s in statuses.values()):
        pytest.skip(f"no CSAF vendor reachable from this egress: {summary}")
    for vendor, info in summary["vendors"].items():
        if info["status"] == "error":
            continue
        assert info["canonical_ok"] is True, vendor
        assert info["planned"] <= 1 and info.get("refused_paths", 0) == 0, info
    res = _run(CsafAdvisories, "openssl", T.KEYWORD, runtime=runtime)
    assert res.status in (Status.OK, Status.EMPTY) and res.requests == 0


def test_live_debian_tracker_dataset_index_and_lookup():
    runtime = _runtime()
    update = runtime.data.update(DATASET)  # `v3lum data update debian_security_tracker`: the streaming validator builds the index
    if update.status == "failed":
        pytest.skip(f"Debian tracker could not be downloaded from this egress: {update.reason}")
    res = _run(DebianSecurityTracker, "CVE-2024-6387", runtime=runtime)
    assert res.status is Status.OK, res.error
    fixes = {f["codename"]: f for f in res.attributes["distro_fixes"] if f["package"] == "openssh"}
    assert fixes["bookworm"]["status"] == "fixed" and fixes["bookworm"]["fixed"].startswith("1:9.2p1-2+deb12u")
    assert res.requests == 0
