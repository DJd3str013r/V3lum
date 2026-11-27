"""Live checks of batch p2-G03-2 (mobile_app_impersonation, P346); run with V3LUM_LIVE=1.

Keyless sources only, benign public values: the public brand 'Google' (a synthetic org profile of Google
LLC built from public facts) against the Apple iTunes Search API (country=br, metadata only) and Google's
Digital Asset Links of google.com / youtube.com through the P008 client. Koodous needs the company token
(none in this environment): the check asserts NEEDS_KEY without any Koodous request. A 403 (Apple refuses
this shared datacenter egress intermittently), 429, geo-block or timeout is an acceptable outcome when the
module reports it as could-not-verify, never as an absence.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from tests.fakes import run_module
from v3lum.config import Config
from v3lum.core.context import Runtime
from v3lum.core.models import Status
from v3lum.core.orgprofile import OrgProfile
from v3lum.modules.url_web import mobile_app_impersonation as mod
from v3lum.modules.url_web.mobile_app_impersonation import MobileAppImpersonation

pytestmark = pytest.mark.live
COULD_NOT_VERIFY = {Status.BLOCKED, Status.RATE_LIMITED, Status.QUOTA, Status.ERROR, Status.UNAVAILABLE}
FIX = Path(__file__).resolve().parents[1] / "fixtures" / "mobile_app_impersonation"


def google_org() -> OrgProfile:
    return OrgProfile.from_dict(json.loads((FIX / "org_profile_google.json").read_text(encoding="utf-8")))


def live_runtime(org: OrgProfile | None = None) -> Runtime:
    return Runtime(Config(), no_cache=True, org=org)


def outcome(res) -> str:
    return f"{res.status.value} {res.reason_code or ''} {res.error[:300]} {json.dumps(res.source_statuses, default=str)[:400]}"


def test_mobile_app_impersonation_google_brand_live():
    org = google_org()
    res = run_module(MobileAppImpersonation, "domain:google.com", runtime=live_runtime(org))
    cov = res.attributes.get("app_store_coverage", {})
    print("mobile_app_impersonation google.com:", outcome(res), json.dumps(cov, default=str)[:600])
    assert res.status in {Status.OK, Status.EMPTY} | COULD_NOT_VERIFY, outcome(res)
    assert res.source_statuses.get("koodous.apks", {}).get("status") == "needs_key"  # no token: never called
    if res.status is Status.OK:
        official = res.attributes.get("official_apps") or []
        assert official, "official apps expected for the Google profile"
        android = [a for a in official if a["store"] == "android"]
        apple = [a for a in official if a["store"] == "apple"]
        print(f"  official: {len(apple)} App Store, {len(android)} Android (DAL); review list: "
              f"{len(res.attributes.get('lookalike_apps') or [])}")
        assert all(a.get("bundle_id") for a in official)
        blob = json.dumps([res.attributes, res.raw], default=str)
        assert "mzstatic" not in blob and "artworkUrl" not in blob  # c3: metadata only
        for f in res.findings:
            if f.title.startswith("Possible "):
                assert f.severity.label == "low" and "malicious" not in f.tags
    itunes = res.source_statuses.get("apple.itunes_search")
    if itunes is not None:
        print("  apple itunes could not verify:", itunes)
        assert itunes["status"] in {"blocked", "rate_limited", "quota", "error"}


def test_parser_on_a_live_itunes_answer():
    """One raw Apple search through the module helper (same request path, same UA)."""
    from tests.fakes import make_ctx

    ctx = make_ctx(MobileAppImpersonation, runtime=live_runtime(), entity="keyword:wikipedia")
    resp = ctx.http.get(mod.itunes_search_url("wikipedia"), source=mod.SOURCE_ITUNES)
    print("itunes search wikipedia:", resp.status, resp.headers.get("content-type"), len(resp.content))
    if resp.status == 403 or resp.classification is not None:
        assert mod.bare_403(resp) or resp.classification is not None
        return
    parsed = mod.parse_itunes_results(resp.text)
    print("  parsed:", parsed["state"], parsed["result_count"], [a["name"] for a in parsed["apps"][:5]])
    assert parsed["state"] in ("ok", "empty")
    assert all("artworkUrl100" not in a for a in parsed["apps"])
