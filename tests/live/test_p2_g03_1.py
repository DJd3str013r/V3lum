"""Live checks of batch p2-G03-1 (gtm_expand, phishstats, retirejs_osv, datasets of retirejs_check and
takedown_packet); run with V3LUM_LIVE=1.

Keyless sources and benign values only: the public gov.br Tag Manager container recorded by the research
(GTM-NHZSKTD), an unknown container id, PhishStats lookups of 1.1.1.1 and example.com, an OSV npm query
for jquery 1.12.4 (library name and version only), and the RetireJS / IANA registrar dataset downloads.
google_safe_browsing needs a key (Web Risk / Safe Browsing): without one it makes no request, which is
checked offline. analytics_ids is offline.

A 403/429/challenge/reset/timeout from this datacenter egress is an acceptable outcome when the module
reports it as could-not-verify (BLOCKED / RATE_LIMITED / QUOTA / ERROR / UNAVAILABLE), never as an
absence.
"""

from __future__ import annotations

import pytest

from tests.fakes import run_module
from v3lum.config import Config
from v3lum.core.context import Runtime
from v3lum.core.datasets import DataStore
from v3lum.core.entities import Entity
from v3lum.core.entities import EntityType as T
from v3lum.core.models import Status
from v3lum.modules.url_web import gtm_expand as gtm_mod
from v3lum.modules.url_web import retirejs_check as retire_mod
from v3lum.modules.url_web import takedown_packet as tp
from v3lum.modules.url_web.google_safe_browsing import GoogleSafeBrowsing
from v3lum.modules.url_web.gtm_expand import GtmExpand
from v3lum.modules.url_web.phishstats import PhishStats
from v3lum.modules.url_web.retirejs_check import RetireJsOsv

pytestmark = pytest.mark.live
COULD_NOT_VERIFY = {Status.BLOCKED, Status.RATE_LIMITED, Status.QUOTA, Status.ERROR, Status.UNAVAILABLE}
JQUERY_BANNER = "/*! jQuery v1.12.4 | (c) jQuery Foundation | jquery.org/license */\n!function(a,b){}(window,function(a,b){});"


def live_runtime(**settings):
    cfg = Config()
    cfg.settings.update(settings)
    return Runtime(cfg, no_cache=True)


def test_gtm_expand_public_govbr_container():
    gtm_mod.BUDGET.reset()
    res = run_module(GtmExpand, "analytics_id:GTM-NHZSKTD", runtime=live_runtime())
    assert res.status in {Status.OK} | COULD_NOT_VERIFY, (res.status, res.error)
    if res.status is Status.OK:
        assert res.attributes["gtm_container"]["found"] is True
        assert any(p.entity.value.startswith(("G-", "UA-", "AW-")) for p in res.pivots)
        assert set(res.hosts) <= {"www.googletagmanager.com"}


def test_gtm_expand_unknown_container_is_empty_from_content():
    gtm_mod.BUDGET.reset()
    res = run_module(GtmExpand, "analytics_id:GTM-ZZZZ999", runtime=live_runtime())
    assert res.status in {Status.EMPTY} | COULD_NOT_VERIFY, (res.status, res.error)


def test_phishstats_ip_lookup():
    res = run_module(PhishStats, "ipv4:1.1.1.1", runtime=live_runtime())
    assert res.status in {Status.OK, Status.EMPTY} | COULD_NOT_VERIFY, (res.status, res.error)
    if res.status is Status.OK:
        assert all("@" not in str(r.get("url")) for r in res.attributes["phishstats_records"])
        assert all("context_only" in f.tags for f in res.findings)  # an IP never inherits the verdict


def test_phishstats_example_com_exact_host():
    res = run_module(PhishStats, "domain:example.com", runtime=live_runtime())
    assert res.status in {Status.OK, Status.EMPTY} | COULD_NOT_VERIFY, (res.status, res.error)


def test_retirejs_osv_jquery_1124():
    retire_mod.OSV_BUDGET.reset()
    res = run_module(RetireJsOsv, Entity.make(T.TEXT, JQUERY_BANNER), runtime=live_runtime())
    assert res.status in {Status.OK} | COULD_NOT_VERIFY, (res.status, res.error)
    if res.status is Status.OK:
        row = res.attributes["js_libraries"][0]
        assert row["npm"] == "jquery" and "CVE-2019-11358" in row["osv_cves"]


def test_google_safe_browsing_without_key_sends_nothing():
    res = run_module(GoogleSafeBrowsing, "domain:example.com", runtime=live_runtime())
    assert res.status is Status.NEEDS_KEY and not res.hosts


@pytest.mark.parametrize("name,parser", [(retire_mod.DATASET, retire_mod.retire_load_repo), (tp.REGISTRAR_DATASET, tp.parse_iana_registrar_csv)])
def test_dataset_downloads(name, parser):
    rt = live_runtime()
    store = DataStore(rt)
    try:
        path = store.fetch(name)
    except Exception as exc:  # noqa: BLE001 - a refused download is could-not-verify, recorded by the run
        pytest.skip(f"dataset {name} not downloadable from this egress: {type(exc).__name__}: {str(exc)[:120]}")
    out = parser(path.read_bytes())
    assert not out.get("error"), out.get("error")
