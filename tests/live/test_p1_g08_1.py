"""Live checks of batch p1-G08-1 (cisa_kev, cve_record, epss, epss_api): keyless sources, the benign
public value CVE-2021-44228 (Log4Shell) only.

Run once with ``V3LUM_LIVE=1 pytest -q -m live tests/live/test_p1_g08_1.py``. Each test has its own
empty V3LUM home, so the datasets (KEV 1.9 MB, EPSS 2.9 MB gzip, CWE 2.1 MB zip) are downloaded with
their real validators. A 403/429/challenge from a datacenter egress is an acceptable outcome when the
module reports it as could-not-verify (rule 5): the test is then skipped with the reason.
"""

from __future__ import annotations

import pytest

from v3lum.config import Config
from v3lum.core.context import Runtime, ScanOptions
from v3lum.core.engine import Engine
from v3lum.core.entities import Entity
from v3lum.core.entities import EntityType as T
from v3lum.core.models import Status
from v3lum.modules.vulnerability_cve.cisa_kev import CisaKev
from v3lum.modules.vulnerability_cve.cve_record import CWE_DATASET, NVD_NOTICE, CveRecord
from v3lum.modules.vulnerability_cve.epss import Epss
from v3lum.modules.vulnerability_cve.epss_api import EpssApi

pytestmark = pytest.mark.live
CVE = "CVE-2021-44228"
COULD_NOT_VERIFY = (Status.BLOCKED, Status.RATE_LIMITED, Status.QUOTA)


def _runtime() -> Runtime:
    return Runtime(Config(), no_cache=True)


def _run(cls, runtime: Runtime | None = None):
    return Engine(runtime or _runtime(), ScanOptions()).run_module(cls, Entity.make(T.CVE, CVE))


def _skip_if_refused(res) -> None:
    if res.status in COULD_NOT_VERIFY:
        pytest.skip(f"{res.module} could not be verified from this egress: {res.status.value} {res.reason_code} {res.error}")


def test_live_cisa_kev_catalogue_and_lookup():
    res = _run(CisaKev)
    _skip_if_refused(res)
    assert res.status is Status.OK, res.error
    a = res.attributes
    assert a["kev"] is True and a["kev_date_added"] == "2021-12-10" and a["kev_ransomware_use"] == "Known"
    assert a["kev_ransomware_known"] is True and a["kev_catalog_version"]
    assert res.requests == 0 and res.datasets and res.datasets[0]["name"] == "cisa_kev"


def test_live_cve_record_cveawg_nvd_and_cwe_names():
    runtime = _runtime()
    cwe = runtime.data.update(CWE_DATASET)  # `v3lum data update cwe_catalog`: the real validator runs
    res = _run(CveRecord, runtime)
    _skip_if_refused(res)
    assert res.status is Status.OK, res.error
    a = res.attributes
    assert a["cve_state"] == "PUBLISHED" and a["cvss"] == 10.0 and "CWE-502" in a["cwe"]
    assert a["kev"] is True and a["ssvc"]["exploitation"] == "active"
    nvd = res.source_statuses.get("nist_nvd.cve_api")
    if nvd is None:  # NVD answered: CPE configurations and the notice travel with its data
        assert a["cpe_total"] > 10 and a["data_notices"] == [NVD_NOTICE]
    else:
        assert nvd["status"] in ("blocked", "rate_limited", "quota", "error"), nvd
    if cwe.ok:
        assert "CWE-502 Deserialization of Untrusted Data" in a["cwe_names"]
    assert set(res.hosts) <= {"cveawg.mitre.org", "services.nvd.nist.gov"}
    assert res.requests <= CveRecord.max_requests


def test_live_epss_daily_file():
    res = _run(Epss)  # outside a scan the large file may be downloaded (a scan never does)
    _skip_if_refused(res)
    assert res.status is Status.OK, res.error
    a = res.attributes
    assert a["epss"] > 0.9 and a["epss_percentile"] > 0.99 and a["epss_model_version"].startswith("v")
    assert "likely to be exploited soon" in a["epss_text"] and res.requests == 0


def test_live_epss_api_without_a_local_file():
    res = _run(EpssApi)
    _skip_if_refused(res)
    assert res.status is Status.OK, res.error
    assert res.attributes["epss"] > 0.9 and res.attributes["epss_date"]
    assert set(res.hosts) <= {"api.first.org"} and res.requests == 1
