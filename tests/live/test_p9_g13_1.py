"""Live checks of batch p9-G13-1 (P025, P276, P277, P279); run with V3LUM_LIVE=1.

* takeover_candidates (PASSIVE) - the pinned can-i-take-over-xyz fingerprints download (commit + SHA-256
  of the active lock) and a DoH-only check of a benign name (www.github.com, a CNAME to github.com):
  no takeover evidence, nothing contacted but the public resolvers and the pinned raw.githubusercontent
  file.
* typosquat_live_checks (LIGHT) - one homepage GET of example.com (the org-profile 'brand' of the test)
  and one of example.org (its 'lookalike'): both IANA pages are the same, so the comparison must say
  'likely live clone'. The favicon GET is switched off here so each host gets a single page GET. ppdeep
  is used when installed, else the deterministic stand-in of the unit tests.
* takeover_verify, sensitive_files, tls_protocol_scan (ACTIVE) - never against third-party hosts: their
  real-transport checks run against 127.0.0.1 servers in the unit tests (tests/modules/).
"""

from __future__ import annotations

from types import SimpleNamespace

import pytest

from tests.fakes import run_module
from tests.modules.test_typosquat_live_checks import FakePpdeep
from v3lum.config import Config
from v3lum.core.context import Runtime, ScanOptions
from v3lum.core.entities import Entity
from v3lum.core.entities import EntityType as T
from v3lum.core.graph import Graph
from v3lum.core.models import Opsec, Status
from v3lum.core.orgprofile import OrgProfile

pytestmark = pytest.mark.live
COULD_NOT_VERIFY = {Status.RATE_LIMITED, Status.BLOCKED, Status.ERROR, Status.QUOTA}
DOH_HOSTS = {"dns.google", "cloudflare-dns.com", "dns.quad9.net", "doh.opendns.com"}


def live_runtime(**settings) -> Runtime:
    cfg = Config()
    cfg.settings.update(settings)
    return Runtime(cfg, no_cache=True)


def test_takeover_fingerprints_download_matches_the_pinned_commit_and_hash():
    from v3lum.modules.pentest_recon import subdomain_takeover  # noqa: F401 - registers the dataset

    rt = live_runtime()
    result = rt.data.update("can_i_take_over_xyz_fingerprints")
    if not result.ok:
        pytest.skip(f"fingerprints not downloaded from this egress: {result.reason}")
    parsed = subdomain_takeover.parse_fingerprints(rt.data.path("can_i_take_over_xyz_fingerprints").read_text(encoding="utf-8"))
    print("can-i-take-over-xyz:", result.status, parsed["counts"])
    assert parsed["ok"] and len(parsed["rows"]) > 50 and any("S3" in r["service"] for r in parsed["rows"])


def test_takeover_candidates_benign_cname_has_no_takeover_evidence():
    from v3lum.modules.pentest_recon.subdomain_takeover import TakeoverCandidates

    res = run_module(TakeoverCandidates, "domain:www.github.com", runtime=live_runtime())
    assert res.status in {Status.OK, Status.EMPTY} | COULD_NOT_VERIFY, (res.status, res.error)
    print("takeover_candidates www.github.com:", res.status.value, res.attributes.get("takeover_check"))
    assert all(f.severity.label in ("info", "low") for f in res.findings), [f.title for f in res.findings]
    if res.status is Status.OK:
        assert res.attributes["takeover_check"]["state"] in ("not_reported", "no_evidence", "cloud_address")
    assert set(res.hosts) <= DOH_HOSTS | {"raw.githubusercontent.com"}, res.hosts


def test_typosquat_live_checks_single_page_gets_of_example_com_and_example_org(monkeypatch):
    from v3lum.modules.domain_dns import typosquat_live_checks as mod
    from v3lum.modules.domain_dns.typosquat_live_checks import TyposquatLiveChecks

    real = mod.load_ppdeep()
    engine = real if real is not None else FakePpdeep()
    monkeypatch.setattr(mod, "load_ppdeep", lambda: engine)
    monkeypatch.setattr(TyposquatLiveChecks, "_favicon", lambda self, res, ctx, entity, page: {})  # one page GET per host
    org = OrgProfile.from_dict({"org": {"name": "Live test"}, "domains": [{"name": "example.com", "verification": "attested",
                                                                            "attested_by": "test", "attested_date": "2026-11-26"}]})
    rt = Runtime(Config(), no_cache=True, org=org)
    graph = Graph()
    brand, cand = Entity.make(T.DOMAIN, "example.com"), Entity.make(T.DOMAIN, "example.org")
    graph.add_node(brand, seed=True)
    graph.add_node(cand, seed=True)
    graph.add_edge(brand, cand, "lookalike", "typosquat", 0.7, expand=False)
    rt.policy_context = SimpleNamespace(graph=graph)
    light = ScanOptions(mode=Opsec.LIGHT)
    ref = run_module(TyposquatLiveChecks, "domain:example.com", runtime=rt, options=light)
    if ref.status in COULD_NOT_VERIFY:
        pytest.skip(f"example.com not reachable from this egress: {ref.status.value} {ref.error}")
    assert ref.status is Status.OK, (ref.status, ref.error)
    fp = ref.attributes["page_fingerprint"]
    assert fp["role"] == "brand_reference" and fp["title"] == "Example Domain"
    graph.add_attributes(brand, ref.attributes, "typosquat_live_checks")
    res = run_module(TyposquatLiveChecks, "domain:example.org", runtime=rt, options=light)
    if res.status in COULD_NOT_VERIFY:
        pytest.skip(f"example.org not reachable from this egress: {res.status.value} {res.error}")
    live = res.attributes["live_check"]
    print("typosquat_live_checks example.org:", live["state"], live.get("comparison", {}).get("wording"), res.attributes["mail_capability"])
    assert live["state"] == "live_clone" and live["comparison"]["score"] >= mod.LIVE_CLONE_THRESHOLD
    assert res.attributes["mail_capability"]["source"] == "dns facts (no SMTP contact)"
    assert set(res.hosts) <= DOH_HOSTS | {"example.org"}, res.hosts
