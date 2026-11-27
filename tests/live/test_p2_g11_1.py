"""Live checks of batch p2-G11-1 (orkl P293, cti_news_rss P298, ransomware_matrices P372,
technique_detections_tests P373, cisa_advisories P374); run with V3LUM_LIVE=1.

Benign public values only: CVE-2021-44228 (ORKL search, the only module that sends a value: an IOC type),
the curated feeds read through the dataset manager (nothing sent), the BushidoUK matrices and the CISA KEV
catalogue for CVE-2024-1709, ATT&CK T1567.002 for Sigma/Atomic, and the CISA advisories feed (answered 200 to
the dataset manager on 2026-11-26; an Akamai 403 must surface as 'could not verify'). A 403/429/challenge from
this egress is an acceptable outcome when it is reported as could-not-verify (never an absence).
"""

from __future__ import annotations

import pytest

from tests.fakes import run_module
from v3lum.config import Config
from v3lum.core.context import Runtime
from v3lum.core.models import Status
from v3lum.modules.cti_framework.cisa_advisories import CisaAdvisories
from v3lum.modules.cti_framework.cti_news_rss import CtiNewsRss
from v3lum.modules.cti_framework.orkl import Orkl
from v3lum.modules.cti_framework.ransomware_matrices import RansomwareMatrices
from v3lum.modules.cti_framework.technique_detections_tests import TechniqueDetectionsTests, yaml_safe_load

pytestmark = pytest.mark.live
COULD_NOT_VERIFY = {Status.BLOCKED, Status.RATE_LIMITED, Status.QUOTA, Status.ERROR, Status.UNAVAILABLE}


def live_runtime(**settings) -> Runtime:
    cfg = Config()
    for name, value in settings.items():
        cfg.set(name, value)
    return Runtime(cfg, no_cache=True)


def test_orkl_cve_search_live():
    res = run_module(Orkl, "cve:CVE-2021-44228", runtime=live_runtime())
    print(res.status, res.error, res.attributes.get("cti_report_count"), res.attributes.get("cti_reports_fuzzy_dropped"))
    if res.status in COULD_NOT_VERIFY:
        pytest.skip(f"orkl.eu could not be verified from this egress: {res.status.value} {res.error}")
    assert res.status in (Status.OK, Status.EMPTY)
    if res.status is Status.OK:
        assert res.attributes["cti_report_count"] >= 1
        assert all("CVE-2021-44228" in r["title"].upper() or r.get("url") for r in res.attributes["cti_reports"])
        assert all("archive.orkl.eu" not in url for _label, url in res.links)


def test_cti_news_rss_feeds_live():
    rt = live_runtime(cti_news_rss_feeds=["therecord", "databreaches", "certbr", "ichi", "darkreading"])
    res = run_module(CtiNewsRss, "keyword:ransomware", runtime=rt)
    health = res.attributes.get("cti_feed_health", {})
    print(res.status, res.error, {k: (v.get("state"), v.get("items"), v.get("reason")) for k, v in health.items()})
    assert res.status in (Status.OK, Status.EMPTY) or res.status in COULD_NOT_VERIFY
    assert health["darkreading"]["state"] == "blocked"  # curated: challenge, never fetched
    read = [k for k, v in health.items() if v.get("state") in ("ok", "stale")]
    if not read:
        pytest.skip("no feed could be read from this egress")
    assert res.status in (Status.OK, Status.EMPTY)


def test_ransomware_matrices_cve_card_live():
    res = run_module(RansomwareMatrices, "cve:CVE-2024-1709", runtime=live_runtime())
    print(res.status, res.error, res.attributes.get("patch_priority"), res.source_statuses)
    if res.status in COULD_NOT_VERIFY:
        pytest.skip(f"matrices not downloadable from this egress: {res.error}")
    assert res.status is Status.OK and res.attributes["patch_priority"] in ("highest", "raised")
    assert "reported exploited by ransomware" in res.attributes["ransomware_cve_card"]["label"]
    actor = run_module(RansomwareMatrices, "threat_actor:LockBit", runtime=live_runtime())
    assert actor.status is Status.OK and actor.attributes["ransomware_tool_leads"]


def test_technique_detections_live():
    res = run_module(TechniqueDetectionsTests, "mitre_technique:T1567.002", runtime=live_runtime())
    print(res.status, res.error, res.attributes.get("detection_coverage"), res.attributes.get("sigma_release"), res.source_statuses)
    if res.status in COULD_NOT_VERIFY:
        pytest.skip(f"Sigma/Atomic not downloadable from this egress: {res.error}")
    assert res.status is Status.OK and res.attributes.get("atomic_tests")
    if yaml_safe_load() is None:
        assert res.source_statuses["github.technique_detections_sigma"]["reason_code"] == "package"
    else:
        assert res.attributes.get("sigma_release")


def test_cisa_advisories_feed_live():
    res = run_module(CisaAdvisories, "malware_family:Akira", runtime=live_runtime())
    print(res.status, res.reason_code, res.error)
    # an Akamai 'Access Denied' (seen on advisory pages from the datacenter egress) -> BLOCKED 'could not verify'
    assert res.status in (Status.OK, Status.EMPTY, Status.BLOCKED, Status.ERROR, Status.RATE_LIMITED)
    if res.status is Status.BLOCKED:
        assert "never 'no advisory'" in res.error
