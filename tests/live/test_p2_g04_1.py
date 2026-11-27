"""Live checks for batch p2-G04-1 (run with V3LUM_LIVE=1; benign values only).

* github_email_pivot: the IANA example address someone@example.com (commit + user search; generic, so
  any account is capped at POSSIBLE);
* gravatar: sha256(someone@example.com) (no profile expected) and Gravatar's own profile slug 'gravatar';
* leakcheck_public: the IANA test address test@example.com (the research value; found >= 100 = generic);
* lunar_domain_exposure: example.com (implausible volume: caveat expected);
* xposedornot: test@example.com (generic; 200+ breaches) and the catalogue dataset;
* xposedornot_domain: 8tracks.com answered from the catalogue dataset.

hibp_account and xposedornot_domain_breaches need a company key: not checked live. A 403/429/challenge/
timeout from this datacenter egress is an acceptable outcome when the module reports it as
could-not-verify (BLOCKED / RATE_LIMITED / QUOTA / ERROR), never as an absence.
"""

from __future__ import annotations

import pytest

from tests.fakes import run_module
from v3lum.config import Config
from v3lum.core.context import Runtime, ScanOptions
from v3lum.core.models import Status
from v3lum.modules.breach_leak.leakcheck_public import LeakcheckPublic
from v3lum.modules.breach_leak.lunar_domain_exposure import LunarDomainExposure
from v3lum.modules.breach_leak.xposedornot import XposedOrNot, XposedOrNotDomain
from v3lum.modules.email.github_email_pivot import GithubEmailPivot
from v3lum.modules.email.gravatar import Gravatar

pytestmark = pytest.mark.live
COULD_NOT_VERIFY = {Status.BLOCKED, Status.RATE_LIMITED, Status.QUOTA, Status.ERROR}
SCOPE_ALL = ScanOptions(breach_scope="all", purpose="live parser check with IANA test values")


def live_runtime():
    return Runtime(Config(), no_cache=True)


def ok_or_could_not_verify(res, *allowed):
    assert res.status in {Status.OK, *allowed} or res.status in COULD_NOT_VERIFY, (res.status, res.reason_code, res.error)


def test_github_email_pivot_example_address():
    res = run_module(GithubEmailPivot, "email:someone@example.com", runtime=live_runtime())
    ok_or_could_not_verify(res, Status.EMPTY)
    if res.status in (Status.OK, Status.EMPTY):
        assert "github_commit_search" in res.attributes or res.status is Status.EMPTY
        assert all(a["confidence"] == "possible" for a in res.attributes.get("github_accounts") or [])


def test_gravatar_absent_hash_and_org_profile():
    absent = run_module(Gravatar, "email:someone@example.com", runtime=live_runtime())
    ok_or_could_not_verify(absent, Status.EMPTY)
    org = run_module(Gravatar, "username:gravatar", runtime=live_runtime())
    ok_or_could_not_verify(org)
    if org.status is Status.OK:
        assert org.attributes["gravatar_profile"]["profile_url"].startswith("https://")


def test_leakcheck_public_test_address_is_generic():
    res = run_module(LeakcheckPublic, "email:test@example.com", runtime=live_runtime(), options=SCOPE_ALL)
    ok_or_could_not_verify(res, Status.EMPTY)
    if res.status is Status.OK:
        assert res.attributes["breach_hit_count"] >= 100
        assert all("context_only" in f.tags for f in res.findings)


def test_lunar_example_com_card_with_caveat():
    res = run_module(LunarDomainExposure, "domain:example.com", runtime=live_runtime())
    ok_or_could_not_verify(res, Status.EMPTY)
    if res.status is Status.OK:
        assert res.tlp == "amber"
        assert res.attributes["domain_exposure"]["caveats"]


def test_xposedornot_test_address_and_catalogue():
    res = run_module(XposedOrNot, "email:test@example.com", runtime=live_runtime(), options=SCOPE_ALL)
    ok_or_could_not_verify(res, Status.EMPTY)
    if res.status is Status.OK:
        assert res.attributes["generic_address"]
        assert res.attributes["breach_count"] > 0
    dom = run_module(XposedOrNotDomain, "domain:8tracks.com", runtime=live_runtime())
    ok_or_could_not_verify(dom)
    if dom.status is Status.OK:
        assert "not accounts at this domain" in dom.attributes["service_breach_records"][0]["wording"]
