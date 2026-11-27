"""Live checks of batch p3-G03-1 (public_api_exposure, phishtank_checkurl); run with V3LUM_LIVE=1.

Keyless sources and benign values only: the APIs.guru directory (list.json and metrics.json through the
real dataset manager, then a local match of github.com - nothing about the target reaches APIs.guru) and
the PhishTank checkurl lookup of http://example.com/ (the in_database quirk: no verdict expected).
Postman's public search is not exercised: its terms are 'unknown' and it stays disabled until legal
records them (P069 cond 2). builtwith needs a key (no request without one, checked offline).

A 403/429/509/challenge/timeout from this datacenter egress is an acceptable outcome when the module
reports it as could-not-verify (BLOCKED / RATE_LIMITED / QUOTA / ERROR / UNAVAILABLE), never as an
absence.
"""

from __future__ import annotations

import pytest

from tests.fakes import run_module
from v3lum.config import Config
from v3lum.core.context import Runtime
from v3lum.core.models import Status
from v3lum.modules.url_web import public_api_exposure as M
from v3lum.modules.url_web.phishtank_checkurl import PhishtankCheckurl
from v3lum.modules.url_web.public_api_exposure import PublicApiExposure

pytestmark = pytest.mark.live
COULD_NOT_VERIFY = {Status.BLOCKED, Status.RATE_LIMITED, Status.QUOTA, Status.ERROR, Status.UNAVAILABLE}


def live_runtime(**settings):
    cfg = Config()
    cfg.settings.update(settings)
    return Runtime(cfg, no_cache=True)


def test_apisguru_directory_download_and_local_match():
    rt = live_runtime()
    listed = rt.data.update(M.APISGURU_LIST)
    metrics = rt.data.update(M.APISGURU_METRICS)
    if not listed.ok:
        pytest.skip(f"APIs.guru list.json not downloadable from this egress: {listed.reason}")
    assert metrics.ok, metrics.reason
    res = run_module(PublicApiExposure, "domain:github.com", runtime=rt, allowed_sources=frozenset({M.SOURCE_APISGURU}))
    assert res.status is Status.OK, (res.status, res.error)
    keys = {m["key"] for m in res.attributes["public_api_directory"]}
    assert "github.com:api.github.com" in keys
    info = res.attributes["public_api_directory_info"]
    assert info["entries"] >= M.APISGURU_MIN_ENTRIES and info["metrics_num_apis"] and info["complete"] is True
    assert set(res.hosts) == set()  # matched locally: no request about the target
    benign = run_module(PublicApiExposure, "domain:example.com", runtime=rt, allowed_sources=frozenset({M.SOURCE_APISGURU}))
    assert benign.status is Status.EMPTY, (benign.status, benign.error)  # the health-check expectation


def test_phishtank_checkurl_example_com_quirk():
    res = run_module(PhishtankCheckurl, "url:http://example.com/", runtime=live_runtime())
    assert res.status in {Status.OK, Status.EMPTY} | COULD_NOT_VERIFY, (res.status, res.error)
    if res.status is Status.OK:
        verdict = res.attributes["phishtank_verdict"]
        assert verdict["in_database"] is True and verdict["verdict"] in ("unverified", "not_phish")
        assert res.findings == []  # in_database alone is never a verdict (P075 cond 4)
        assert set(res.hosts) <= {"checkurl.phishtank.com"}
    if res.status is Status.BLOCKED:
        assert res.reason_code in ("challenge", "circuit")
