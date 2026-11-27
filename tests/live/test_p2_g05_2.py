"""Live checks of batch p2-G05-2 (avatar_correlation P114, threat_actor_handles P195, org_code_footprint P359);
run with V3LUM_LIVE=1.

Benign public values only: GitHub's own organisation avatar, the Forgejo project on Codeberg (an
open-source organisation), and the handle 'octocat' (GitHub's mascot, the benign collision example of
the council text). A 403/429/challenge or a research-proxy refusal from this datacenter egress is an
accepted outcome when the module reports it as could-not-verify (blocked / rate_limited / error),
never as an absence. profile_id_extractor (P107) makes no request: its saved-page tests are offline.
"""

from __future__ import annotations

import pytest

from tests.fakes import run_module
from v3lum.config import Config
from v3lum.core.context import Runtime, ScanOptions
from v3lum.core.models import Status
from v3lum.modules.company_org.org_code_footprint import OrgCodeFootprint
from v3lum.modules.cti_framework.threat_actor_handles import ThreatActorHandles
from v3lum.modules.username_social import avatar_correlation as ac

pytestmark = pytest.mark.live
COULD_NOT_VERIFY = {Status.BLOCKED, Status.RATE_LIMITED, Status.ERROR, Status.QUOTA}


@pytest.fixture
def live_runtime():
    return Runtime(Config(), no_cache=True)


def test_avatar_correlation_live(live_runtime):
    pytest.importorskip("PIL")
    ac.CASE_BUDGET.reset()
    res = run_module(ac.AvatarCorrelation, "url:https://avatars.githubusercontent.com/u/9919?s=96&v=4", runtime=live_runtime)
    if res.status in COULD_NOT_VERIFY:
        pytest.skip(f"avatar CDN could not be verified from this egress: {res.status.value} {res.error[:120]}")
    assert res.status is Status.OK, res.error
    assert len(res.attributes["avatar_dhash"]) == 16 and len(res.attributes["avatar_sha256"]) == 64
    assert res.attributes["avatar_facts"]["format"] in ("PNG", "JPEG", "GIF", "WEBP")


def test_org_code_footprint_live(live_runtime):
    live_runtime.config.settings["org_code_footprint_confirmed"] = ["codeberg:forgejo"]
    res = run_module(OrgCodeFootprint, "username:forgejo", runtime=live_runtime,
                     options=ScanOptions(purpose="live parser check of a public open-source organisation"))
    assert res.status is not Status.EMPTY or res.source_statuses, res.error
    if res.status in COULD_NOT_VERIFY:
        pytest.skip(f"no provider answered from this egress: {res.status.value} {res.error[:120]}")
    orgs = {f"{o['provider']}:{o['login']}": o for o in res.attributes.get("code_orgs", [])}
    assert orgs.get("codeberg:forgejo", {}).get("state") == "confirmed", (orgs, res.source_statuses)
    if "codeberg.api" not in res.source_statuses:  # the repository listing answered too
        assert orgs["codeberg:forgejo"]["repo_count"] >= 1
    for source, st in res.source_statuses.items():  # e.g. the research proxy refusing api.github.com /orgs paths
        assert st["status"] in ("blocked", "rate_limited", "error", "needs_key", "quota"), (source, st)


def test_threat_actor_handles_live(live_runtime):
    live_runtime.data.update("threat_actor_handles.readme")
    res = run_module(ThreatActorHandles, "username:octocat", runtime=live_runtime)
    if res.status in COULD_NOT_VERIFY | {Status.UNAVAILABLE}:
        pytest.skip(f"forum lists could not be downloaded from this egress: {res.status.value} {res.error[:120]}")
    assert res.status in (Status.OK, Status.EMPTY), res.error
    assert res.raw["lists_checked"] >= 15 and res.raw["lists_missing_upstream"] == 9
    if res.status is Status.OK:
        finding = res.findings[0]
        assert finding.confidence <= 0.3 and "context_only" in finding.tags and res.pivots == []
