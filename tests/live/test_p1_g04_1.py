"""Live checks for batch p1-G04-1 (run with V3LUM_LIVE=1; benign values only).

* email_hygiene datasets: the CC0/MIT lists from raw.githubusercontent.com through the dataset
  manager (validated, installed), then the offline classifier reads the local copies;
* email_hygiene_online: google.com (domain only) on Kickbox Open and MailCheck.ai;
* hibp_catalog: the keyless catalogue dataset, adobe.com, the breach name Adobe, an unknown name
  (404) and /dataclasses;
* hudson_rock / hudson_rock_domain: the IANA test address test@example.com (the research value) and
  urls-by-domain for example.com (the domain search hung > 70 s in research, so it is not asked).

A 403/429/challenge/timeout from this datacenter egress is an acceptable outcome when the module
reports it as could-not-verify (BLOCKED / RATE_LIMITED / QUOTA / ERROR), never as an absence.
email_header_analyzer is offline (nothing to check live).
"""

from __future__ import annotations

import pytest

from tests.fakes import make_ctx, run_module
from v3lum.config import Config
from v3lum.core.context import Runtime, ScanOptions
from v3lum.core.models import Status
from v3lum.core.orgprofile import OrgProfile
from v3lum.modules.breach_leak.hibp_catalog import HibpCatalog, data_classes
from v3lum.modules.breach_leak.hudson_rock import HudsonRock, HudsonRockDomain
from v3lum.modules.email.email_hygiene import DISPOSABLE_DATASET, FREE_DATASET, ROLE_DATASET, EmailHygiene, hygiene_lists
from v3lum.modules.email.email_hygiene_online import EmailHygieneOnline

pytestmark = pytest.mark.live
COULD_NOT_VERIFY = {Status.BLOCKED, Status.RATE_LIMITED, Status.QUOTA, Status.ERROR}
VICTIM_KEYS = ("top_passwords", "top_logins", "computer_name", "malware_path", "antiviruses", "operating_system")


def live_runtime(org=None):
    return Runtime(Config(), no_cache=True, org=org)


def test_email_hygiene_lists_refresh_and_classify():
    rt = live_runtime()
    outcomes = {name: rt.data.update(name) for name in (DISPOSABLE_DATASET, FREE_DATASET, ROLE_DATASET)}
    for name, result in outcomes.items():
        assert result.ok or result.reason, name
    ctx = make_ctx(EmailHygiene, runtime=rt, entity="email:throwaway@yopmail.com")
    lists = hygiene_lists(ctx)
    if all(r.ok for r in outcomes.values()):
        assert lists.origin == {"disposable": "dataset", "free": "dataset", "roles": "dataset"}
    res = run_module(EmailHygiene, "email:throwaway@yopmail.com", runtime=rt)
    assert res.status is Status.OK and res.attributes["disposable"] is True


def test_email_hygiene_online_google_com():
    res = run_module(EmailHygieneOnline, "domain:google.com", runtime=live_runtime())
    assert res.status is Status.OK or res.status in COULD_NOT_VERIFY, (res.status, res.error)
    if res.status is Status.OK:
        for opinion in res.attributes["hygiene_opinions"].values():
            assert opinion["disposable"] is False


def test_hibp_catalog_keyless_endpoints():
    rt = live_runtime()
    res = run_module(HibpCatalog, "domain:adobe.com", runtime=rt)
    assert res.status is Status.OK or res.status in COULD_NOT_VERIFY, (res.status, res.error)
    if res.status is not Status.OK:
        pytest.skip(f"HIBP could not be verified from this egress: {res.status.value} {res.error[:120]}")
    assert any(b["name"] == "Adobe" for b in res.attributes["service_breaches"])
    keyword = run_module(HibpCatalog, "keyword:Adobe", runtime=rt)
    assert keyword.status is Status.OK and keyword.attributes["breach_metadata"]["breach_date"] == "2013-10-04"
    unknown = run_module(HibpCatalog, "keyword:NoSuchBreachV3lumCheck", runtime=rt)
    assert unknown.status is Status.EMPTY or unknown.status in COULD_NOT_VERIFY
    names = data_classes(make_ctx(HibpCatalog, runtime=rt, entity="domain:adobe.com"))
    assert not names or "Passwords" in names


def test_hudson_rock_iana_test_address():
    options = ScanOptions(breach_scope="all", purpose="live parser check with the IANA test address")
    res = run_module(HudsonRock, "email:test@example.com", runtime=live_runtime(), options=options)
    assert res.status in (Status.OK, Status.EMPTY) or res.status in COULD_NOT_VERIFY, (res.status, res.error)
    text = repr((res.raw, res.attributes, [f.to_dict() for f in res.findings]))
    assert not any(key in text for key in VICTIM_KEYS)
    if res.status is Status.OK:
        assert res.attributes["generic_address"] == "example_domain"
        assert [f.title for f in res.findings] == ["Generic address in infostealer logs"]


def test_hudson_rock_urls_by_domain_example_com():
    org = OrgProfile.from_dict({"domains": [{"name": "example.com", "verification": "attested", "attested_by": "live test", "attested_date": "2026-11-26"}]})
    res = run_module(HudsonRockDomain, "domain:example.com", runtime=live_runtime(org), allowed_sources=["hudsonrock.urls_by_domain"])
    assert res.status in (Status.OK, Status.EMPTY) or res.status in COULD_NOT_VERIFY, (res.status, res.error)
    for pivot in res.pivots:
        assert "?" not in pivot.entity.value and "@" not in pivot.entity.value.split("//", 1)[-1]
        assert pivot.expand is False
