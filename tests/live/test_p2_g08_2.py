"""Live checks of batch p2-G08-2 (exploit_index, poc_index, cve_offline_mirror, msrc_patch_tuesday): keyless
sources and the benign public value CVE-2021-44228 (Log4Shell) only.

Run once with ``V3LUM_LIVE=1 pytest -q -m live tests/live/test_p2_g08_2.py``. Each test has its own empty
V3LUM home, so the datasets are downloaded with their real validators (Exploit-DB CSV 10.5 MB, Metasploit
metadata 11.4 MB, nuclei cves.json 2.4 MB, deltaLog.json ~29 MB, one MSRC month document ~20 MB). A
403/429/challenge from a datacenter egress is an acceptable outcome when it is reported as could-not-verify
(rule 5): the test is then skipped with the reason. The cvelistV5 baseline release archive is not downloaded
(the dataset manager has no streamed download yet: docs/backlog/p2-G08-2.md); the mirror test indexes the
live record of CVE-2021-44228 instead.
"""

from __future__ import annotations

import pytest

from v3lum.config import Config
from v3lum.core.context import Runtime, ScanOptions
from v3lum.core.engine import Engine
from v3lum.core.entities import Entity
from v3lum.core.entities import EntityType as T
from v3lum.core.models import Status
from v3lum.modules.vulnerability_cve.cve_offline_mirror import (
    DELTALOG_DATASET,
    CveOfflineMirror,
    MirrorDB,
    cvelist_record_url,
    mirror_row,
    parse_delta_log,
)
from v3lum.modules.vulnerability_cve.exploit_index import EXPLOITDB_DATASET, METASPLOIT_DATASET, NUCLEI_DATASET, ExploitIndex
from v3lum.modules.vulnerability_cve.g08_offline import job_http
from v3lum.modules.vulnerability_cve.msrc_patch_tuesday import MsrcDB, MsrcPatchTuesday, refresh_msrc
from v3lum.modules.vulnerability_cve.poc_index import POC_LABEL, PocIndex

pytestmark = pytest.mark.live
CVE = "CVE-2021-44228"
COULD_NOT_VERIFY = (Status.BLOCKED, Status.RATE_LIMITED, Status.QUOTA)


def _runtime() -> Runtime:
    return Runtime(Config(), no_cache=True)


def _run(cls, value: str = CVE, runtime: Runtime | None = None, etype: T = T.CVE):
    return Engine(runtime or _runtime(), ScanOptions()).run_module(cls, Entity.make(etype, value))


def _skip_if_refused(res) -> None:
    if res.status in COULD_NOT_VERIFY:
        pytest.skip(f"{res.module} could not be verified from this egress: {res.status.value} {res.reason_code} {res.error}")


def test_live_poc_index_lists_capped_labelled_claims():
    res = _run(PocIndex)
    _skip_if_refused(res)
    assert res.status is Status.OK, res.error
    a = res.attributes
    assert a["exploit_maturity"].startswith("poc_claimed (") and a["poc_repos_total"] > 100
    assert a["poc_confidence"] <= 0.4 and "exploit_available" not in a
    assert len(res.pivots) == 5 and all(p.expand is False and p.note == POC_LABEL for p in res.pivots)
    assert all(t["repo"].startswith("hxxps://github[.]com/") for t in a["poc_repos"])
    assert set(res.hosts) == {"raw.githubusercontent.com"}


def test_live_exploit_index_datasets_and_lookup():
    runtime = _runtime()
    results = {name: runtime.data.update(name) for name in (EXPLOITDB_DATASET, METASPLOIT_DATASET, NUCLEI_DATASET)}
    failed = {n: r for n, r in results.items() if r.status == "failed"}
    if len(failed) == len(results):
        pytest.skip(f"no exploit dataset could be downloaded from this egress: {failed}")
    res = _run(ExploitIndex, runtime=runtime)
    _skip_if_refused(res)
    assert res.status is Status.OK, res.error
    a = res.attributes
    assert a["exploit_available"] is True and a["exploit_maturity"] == "weaponised"
    assert a["exploit_sources"]["metasploit"] >= 1 and res.requests == 0
    assert all(p.expand is False for p in res.pivots) and not res.findings


def test_live_cve_mirror_deltalog_and_record_parse():
    runtime = _runtime()
    update = runtime.data.update(DELTALOG_DATASET)
    if update.status == "failed":
        pytest.skip(f"deltaLog.json could not be downloaded from this egress: {update.reason}")
    parsed = parse_delta_log(runtime.data.path(DELTALOG_DATASET).read_bytes())
    assert parsed["reason"] is None and parsed["entries"] > 0 and parsed["items"]
    assert all(i["url"].startswith("https://raw.githubusercontent.com/CVEProject/cvelistV5/main/cves/") for i in parsed["items"][:50])
    http = job_http(runtime, module="cve_offline_mirror", provider="github", sources=("github.cve_offline_mirror_cvelist",),
                    hosts=("raw.githubusercontent.com",), max_requests=1)
    resp = http.get(cvelist_record_url(CVE), ttl=0)
    if resp.status in (403, 429):
        pytest.skip(f"cvelistV5 record refused from this egress: HTTP {resp.status}")
    row, reason = mirror_row(resp.content, CVE)
    assert reason is None and row["kev"] == 1 and row["ssvc_exploitation"] == "active"
    with MirrorDB(readonly=False) as db:
        db.upsert([row])
        db.set_meta(baseline_completed_at="2026-11-26T00:00:00.000000Z", last_sync_at="2026-11-26T00:00:00.000000Z", records=db.count())
    res = _run(CveOfflineMirror, runtime=runtime)
    assert res.status is Status.OK and res.attributes["kev"] is True and res.attributes["ssvc"]["exploitation"] == "active"


def test_live_msrc_refresh_of_one_month_and_lookup():
    runtime = _runtime()
    summary = refresh_msrc(runtime, max_documents=1)
    if summary["status"] == "error" or (summary["status"] == "partial" and not summary["indexed"]):
        pytest.skip(f"MSRC could not be verified from this egress: {summary.get('reason') or summary}")
    assert summary["indexed"] and summary["indexed"][0]["vulnerabilities"] > 100
    with MsrcDB() as db:
        doc_id = summary["indexed"][0]["id"]
        cve = db.con.execute("SELECT cve FROM msrc_fix WHERE doc_id = ? AND kb IS NOT NULL LIMIT 1", (doc_id,)).fetchone()[0]
    res = _run(MsrcPatchTuesday, cve, runtime=runtime)
    assert res.status is Status.OK, res.error
    assert res.attributes["msrc_kbs"] and res.attributes["msrc_documents"] == [doc_id] and "kev" not in res.attributes
