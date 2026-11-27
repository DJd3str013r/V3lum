"""Live checks of batch p2-G14-3 (pivots_unverified P304, code_search P305, dork_generator P306); run with V3LUM_LIVE=1.

* code_search: the keyless Sourcegraph public stream API with the benign term example.com (one request). The public
  instance degraded from this egress during prep (backend-missing): 'could not verify' (error / blocked /
  rate_limited) is an acceptable outcome, never 'empty'. GitHub and GitLab need team tokens and stay off (merge gate,
  P305 cond 10): not called.
* pivots_unverified and dork_generator are offline by design (cond 1 of P304 and P306: V3LUM never requests these
  pages or search engines); the live check runs them through the real engine and registry and proves no request is
  sent (FakeHttp without routes).
"""

from __future__ import annotations

import pytest

from tests.fakes import FakeHttp, run_module
from v3lum.config import Config
from v3lum.core import links, providers
from v3lum.core.context import Runtime
from v3lum.core.models import Status
from v3lum.modules.search_dorks import code_search as cs
from v3lum.modules.search_dorks import pivots_unverified as pu
from v3lum.modules.search_dorks.code_search import CodeSearch
from v3lum.modules.search_dorks.dork_generator import DorkGenerator
from v3lum.modules.search_dorks.pivots_unverified import PivotsUnverified

pytestmark = pytest.mark.live
COULD_NOT_VERIFY = {Status.BLOCKED, Status.RATE_LIMITED, Status.QUOTA, Status.ERROR, Status.UNAVAILABLE}


def test_registry_and_packs_live():
    assert not [e for e in providers.registry().errors if "p2-G14-3" in e or "sourcegraph" in e]
    assert pu.module_link_errors() == []
    assert not [e for e in links.errors() if e.startswith("unverified_")]


def test_code_search_sourcegraph_live():
    rt = Runtime(Config(), no_cache=True)
    res = run_module(CodeSearch, "domain:example.com", runtime=rt)
    print(f"code_search: {res.status.value} {res.reason_code} {res.error[:200]} "
          f"summary={res.attributes.get('code_search_summary')} requests={res.requests}")
    assert res.requests <= cs.DEFAULT_QUERY_CAP
    if res.status in COULD_NOT_VERIFY:
        assert res.status is not Status.EMPTY and res.error
        return
    assert res.status in (Status.OK, Status.EMPTY)
    if res.status is Status.OK:
        hits = res.attributes["code_search_hits"]
        assert hits and all(h["repo"] and h["hits"] for h in hits)
        assert all(not p.expand for p in res.pivots)


def test_offline_modules_send_nothing_live():
    http = FakeHttp()
    res = run_module(PivotsUnverified, "url:https://example.com/", http, tlp="clear")
    assert res.status is Status.OK and res.requests == 0
    res = run_module(DorkGenerator, "domain:example.com", http, tlp="clear")
    assert res.status is Status.OK and res.requests == 0 and http.calls == []
