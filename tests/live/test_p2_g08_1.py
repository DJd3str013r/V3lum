"""Live checks of batch p2-G08-1 (circl_vulnlookup, osv_ghsa, securitycontext_cve, the endoflife datasets):
keyless sources only, with the benign public value CVE-2021-44228 (Log4Shell) and the nginx product.

Run once with ``V3LUM_LIVE=1 pytest -q -m live tests/live/test_p2_g08_1.py``. Each test has its own empty
V3LUM home (no cache, no local EPSS file). A 403/429/challenge from a datacenter egress is an acceptable
outcome when the module reports it as could-not-verify (rule 5): the test is then skipped with the reason.
``vulncheck`` needs the company key and is not checked here (P186 cond 4: success fixture with the team key).
"""

from __future__ import annotations

import pytest

from v3lum.config import Config
from v3lum.core.context import Runtime, ScanOptions
from v3lum.core.engine import Engine
from v3lum.core.entities import Entity
from v3lum.core.entities import EntityType as T
from v3lum.core.models import Status
from v3lum.modules.vulnerability_cve import endoflife as eol
from v3lum.modules.vulnerability_cve.circl_vulnlookup import CirclVulnLookup
from v3lum.modules.vulnerability_cve.osv_ghsa import OsvGhsa
from v3lum.modules.vulnerability_cve.securitycontext_cve import SecurityContextCve

pytestmark = pytest.mark.live
CVE = "CVE-2021-44228"
COULD_NOT_VERIFY = (Status.BLOCKED, Status.RATE_LIMITED, Status.QUOTA)


def _runtime() -> Runtime:
    return Runtime(Config(), no_cache=True)


def _run(cls, value: str = CVE, etype: T = T.CVE):
    return Engine(_runtime(), ScanOptions()).run_module(cls, Entity.make(etype, value))


def _skip_if_refused(res) -> None:
    if res.status in COULD_NOT_VERIFY:
        pytest.skip(f"{res.module} could not be verified from this egress: {res.status.value} {res.reason_code} {res.error}")


def test_live_circl_record_sightings_and_epss():
    res = _run(CirclVulnLookup)
    _skip_if_refused(res)
    assert res.status is Status.OK, res.error
    a = res.attributes
    assert a["cve_state"] == "PUBLISHED" and a["cvss"] == 10.0 and "kev" not in a
    assert a["circl_sightings"]["total"] > 100 and a["exploited"]["circl"] <= "2021-12-31"
    if "circl_vulnlookup.circl_vulnlookup_epss" not in res.source_statuses:
        assert 0.9 <= a["epss"] <= 1.0
    assert set(res.hosts) == {"vulnerability.circl.lu"}


def test_live_circl_ghsa_keyword():
    res = _run(CirclVulnLookup, "GHSA-jfh8-c2jp-5v3q", T.KEYWORD)
    _skip_if_refused(res)
    assert res.status is Status.OK, res.error
    assert CVE in res.attributes["advisory_aliases"]


def test_live_osv_records_and_distro_fixes():
    res = _run(OsvGhsa)
    _skip_if_refused(res)
    assert res.status is Status.OK, res.error
    a = res.attributes
    assert any(d["distro"] == "debian" and d.get("fixed") for d in a["distro_fixes"])
    assert "GHSA-jfh8-c2jp-5v3q" in a["advisory_aliases"]
    assert any(r["package"] == "org.apache.logging.log4j:log4j-core" for r in a["package_ranges"])
    # GitHub REST from this egress: answered, or a could-not-verify source status (never an absence)
    gh = res.source_statuses.get("github.osv_ghsa_advisories")
    assert gh is None or gh["status"] in ("blocked", "rate_limited", "needs_key", "error", "empty")


def test_live_securitycontext_schema_still_matches():
    res = _run(SecurityContextCve)
    _skip_if_refused(res)
    assert res.status is Status.OK, res.error
    sec = res.attributes["cve_secondary"]
    assert sec["cvss"]["score"] >= 9.0 and "cisa" in sec.get("kev_lists", [])


def test_live_endoflife_dataset_and_evaluation():
    rt = _runtime()
    result = rt.data.update("endoflife.nginx")
    if result.status not in ("updated", "unchanged", "not_modified"):
        pytest.skip(f"endoflife.date could not be fetched from this egress: {result.status} {result.reason}")
    product = eol.local_product("nginx")
    assert product and product["slug"] == "nginx" and len(product["releases"]) >= 5
    ev = eol.eol_evaluate(product, "nginx/1.18.0", "header", "2026-11-26", asset_scope="own")
    assert ev["finding"] is True and ev["status"] == "eol" and ev["cycle"] == "1.18"
