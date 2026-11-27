"""Live checks of batch p9-G13-3 (path_discovery, port_scan, public_docs_discovery); run with V3LUM_LIVE=1.

PASSIVE keyless sources with benign values only: public_docs_discovery on example.com (RFC 2606)
through the Wayback CDX and the Common Crawl index, and one pinned SecLists list from GitHub's raw
host (the dataset path that `v3lum data update` takes). A 403/429/reset/timeout from this datacenter
egress is acceptable when reported as could-not-verify, never as an absence (known: web.archive.org
resets every connection from the research egress).

Target-contact code (path_discovery, port_scan) never contacts a third-party host here: their live
behaviour is checked only against servers the tests start on 127.0.0.1 (loopback HTTP site with
soft-404, login redirect and a panel; loopback TCP listeners open/closed/silent), in
tests/modules/test_path_discovery.py and tests/modules/test_port_scan.py.
"""

from __future__ import annotations

import pytest

from tests.fakes import run_module
from v3lum.config import Config
from v3lum.core.context import Runtime, ScanOptions
from v3lum.core.models import Status
from v3lum.modules.pentest_recon import forced_browsing as fb
from v3lum.modules.pentest_recon.path_discovery import WORDLISTS, dataset_name
from v3lum.modules.pentest_recon.public_docs_discovery import PublicDocsDiscovery

pytestmark = pytest.mark.live
COULD_NOT_VERIFY = {Status.BLOCKED, Status.RATE_LIMITED, Status.QUOTA, Status.ERROR, Status.UNAVAILABLE}


def live_runtime(**settings):
    cfg = Config()
    cfg.settings.update(settings)
    return Runtime(cfg, no_cache=True)


def test_public_docs_discovery_example_com_archives_only():
    rt = live_runtime(public_docs_discovery_max_documents=2)
    res = run_module(PublicDocsDiscovery, "domain:example.com", runtime=rt, options=ScanOptions(include={"public_docs_discovery"}))
    assert res.status in {Status.OK, Status.EMPTY} | COULD_NOT_VERIFY, (res.status, res.error)
    assert set(res.hosts) <= {"web.archive.org", "index.commoncrawl.org", "data.commoncrawl.org"}  # never the live site, no Brave (no key)
    cov = res.attributes.get("public_docs_coverage", {})
    assert cov.get("brave") in (None, "needs_key") or str(cov.get("brave")).startswith("not_queried")
    if res.status is Status.OK:
        assert all(p.expand is False for p in res.pivots)


def test_seclists_pinned_list_installs_and_passes_the_path_policy():
    rt = live_runtime()
    name = dataset_name("graphql")
    result = rt.data.update(name)
    assert result.status in ("updated", "unchanged", "installed", "ok", "fresh"), (result.status, result.reason)
    path = rt.data.path(name) if callable(getattr(rt.data, "path", None)) else None
    data = path.read_bytes() if path is not None else rt.data.fetch(name).read_bytes()
    parsed = fb.parse_wordlist(data)
    assert parsed["sha256"] == WORDLISTS["graphql"][1]
    assert 0 < parsed["total"] <= fb.WORDLIST_CAP and not parsed["over_cap"]
