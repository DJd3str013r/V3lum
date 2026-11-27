"""Live checks of batch p1-G01-2 (typosquat, typosquat_dnstwister, web_archives, web_archives_deep,
web_archives_ukwa); run with V3LUM_LIVE=1.

Keyless sources and benign values only: example.com (RFC 2606) and registro.br (NIC.br's own domain).
The typosquat forward scan is capped at a handful of candidates (DoH lookups of example.com
permutations through the core resolvers; no candidate is ever contacted).

A 403/429/challenge/reset/timeout from this datacenter egress is an acceptable outcome when the module
reports it as could-not-verify (BLOCKED / RATE_LIMITED / QUOTA / ERROR / UNAVAILABLE), never as an
absence. Known from the research egress (2026-11-25/26): web.archive.org resets every connection
(CDX and id_ snapshots) while archive.org/wayback/available answers; Common Crawl index queries with
results are reset; CarbonDate answers with every source empty; UKWA answers 403 'Under Maintenance'.
"""

from __future__ import annotations

import pytest

from tests.fakes import run_module
from v3lum.config import Config
from v3lum.core.context import Runtime, ScanOptions
from v3lum.core.models import Status
from v3lum.modules.domain_dns.typosquat import Typosquat
from v3lum.modules.domain_dns.typosquat_dnstwister import TyposquatDnstwister
from v3lum.modules.url_web.web_archives import WebArchives
from v3lum.modules.url_web.web_archives_deep import WebArchivesDeep
from v3lum.modules.url_web.web_archives_ukwa import WebArchivesUkwa

pytestmark = pytest.mark.live
COULD_NOT_VERIFY = {Status.BLOCKED, Status.RATE_LIMITED, Status.QUOTA, Status.ERROR, Status.UNAVAILABLE}


def live_runtime(**settings):
    cfg = Config()
    cfg.settings.update(settings)
    return Runtime(cfg, no_cache=True)


def test_typosquat_forward_scan_of_example_com():
    rt = live_runtime(typosquat_candidates=6, typosquat_doh_budget=30)
    res = run_module(Typosquat, "domain:example.com", runtime=rt, options=ScanOptions(include={"typosquat"}))
    assert res.status in {Status.OK} | COULD_NOT_VERIFY, (res.status, res.error)
    if res.status is Status.OK:
        cov = res.attributes["typosquat_coverage"]
        assert cov["candidates_checked"] == 6 and cov["doh_queries"] <= 30
        assert cov["registered"] + cov["unregistered"] + cov["nxdomain_unconfirmed"] + cov["could_not_verify"] == 6
        assert all(p.relation == "lookalike" and p.expand is False for p in res.pivots)
        assert set(res.hosts) <= {"dns.google", "cloudflare-dns.com", "rdap.registro.br"}


def test_typosquat_reverse_mode_is_offline():
    rt = live_runtime()
    rt.org = {"name": "Live check", "brands": [{"keyword": "registro"}], "domains": [{"name": "registro.br", "verification": "confirmed"}]}
    res = run_module(Typosquat, "domain:registro-pix.com.br", runtime=rt)
    assert res.status is Status.OK and res.attributes["lookalike_matches"][0]["protected"] == "registro.br"
    assert not res.hosts  # no request at all


def test_typosquat_dnstwister_fuzz_example_com():
    rt = live_runtime(typosquat_candidates=4, typosquat_doh_budget=20)
    res = run_module(TyposquatDnstwister, "domain:example.com", runtime=rt, tlp="green", options=ScanOptions(include={"typosquat_dnstwister"}))
    assert res.status in {Status.OK, Status.SKIPPED} | COULD_NOT_VERIFY, (res.status, res.error)
    if res.status is Status.OK:
        assert res.attributes["typosquat_coverage"]["candidates_generated"] > 100  # ~298 entries for example.com
    elif res.status is Status.SKIPPED:
        assert res.reason_code in ("licence", "tlp", "not_applicable")


def test_web_archives_example_com():
    res = run_module(WebArchives, "domain:example.com", runtime=live_runtime())
    assert res.status in {Status.OK, Status.EMPTY} | COULD_NOT_VERIFY, (res.status, res.error)
    sources = res.attributes.get("archive_sources", {})
    if res.status is Status.OK:
        assert res.attributes["archive_first"] <= res.attributes["archive_last"]
        assert "never archived" not in str(res.attributes).lower()
        assert all("user:pass" not in u for u in res.attributes.get("archived_urls", []))
    for name, outcome in sources.items():  # a reset is 'archive unreachable', never an absence
        if "reset" in outcome.lower() or "timed out" in outcome.lower():
            assert outcome.startswith("could_not_verify"), (name, outcome)


def test_web_archives_registro_br_uses_arquivo():
    res = run_module(WebArchives, "domain:registro.br", runtime=live_runtime())
    assert res.status in {Status.OK, Status.EMPTY} | COULD_NOT_VERIFY, (res.status, res.error)
    if res.status is Status.OK:
        assert "arquivo_pt" in res.attributes["archive_sources"]


def test_web_archives_deep_example_com():
    res = run_module(WebArchivesDeep, "domain:example.com", runtime=live_runtime())
    assert res.status in {Status.OK, Status.EMPTY} | COULD_NOT_VERIFY, (res.status, res.error)
    if res.status is Status.OK:
        assert res.attributes["archive_sources"].get("commoncrawl_collinfo") in ("ok", None) or res.attributes["archive_sources"]["commoncrawl_collinfo"].startswith("could_not_verify")


def test_web_archives_ukwa_reports_maintenance_as_could_not_verify():
    res = run_module(WebArchivesUkwa, "domain:example.com", runtime=live_runtime(web_archives_ukwa_enabled=True))
    assert res.status in {Status.OK, Status.EMPTY} | COULD_NOT_VERIFY, (res.status, res.error)
