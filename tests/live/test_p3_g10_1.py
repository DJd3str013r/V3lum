"""Live checks of batch p3-G10-1 (icij_offshore_api, sec_edgar, wikidata, eu_vies; the keyed and licensed
modules only prove they send nothing); run with V3LUM_LIVE=1.

Keyless sources only, benign public values: the company name 'Example Holdings Limited' for the ICIJ
reconciliation fallback (explicitly selected, as P221 cond 4 asks), the listed company 'Apple Inc.' at the SEC
(with a documentation contact soc@example.com in the User-Agent, as the SEC fair access policy asks),
'Banco do Brasil' at Wikidata (same contact) and the public VAT number LU26375245 (a company) at VIES.
A 403/429/challenge/geo-block/timeout from this datacenter egress is an acceptable outcome when it is
reported as could-not-verify (BLOCKED / RATE_LIMITED / QUOTA / ERROR / UNAVAILABLE), never as an absence.
"""

from __future__ import annotations

import pytest

from tests.fakes import FakeHttp, run_module
from v3lum.config import Config
from v3lum.core.context import Runtime, ScanOptions
from v3lum.core.models import Status
from v3lum.modules.company_org.eu_vies import EuVies
from v3lum.modules.company_org.icij_offshore import IcijOffshoreApi
from v3lum.modules.company_org.opensanctions import OpenSanctionsApi
from v3lum.modules.company_org.sec_edgar import SecEdgar
from v3lum.modules.company_org.uk_companies_house import UkCompaniesHouse
from v3lum.modules.company_org.wikidata import Wikidata

pytestmark = pytest.mark.live
COULD_NOT_VERIFY = {Status.BLOCKED, Status.RATE_LIMITED, Status.QUOTA, Status.ERROR, Status.UNAVAILABLE}
CONTACT = "soc@example.com"


def live_runtime(**settings: object) -> Runtime:
    cfg = Config()
    cfg.settings.update(settings)
    return Runtime(cfg, no_cache=True)


def report(res) -> None:
    print(res.module, res.status.value, res.reason_code, res.error[:200], sorted(res.attributes), res.hosts)


def test_icij_reconciliation_fallback():
    res = run_module(IcijOffshoreApi, "company_name:Example Holdings Limited", runtime=live_runtime(),
                     options=ScanOptions(include=["icij_offshore_api"]))
    report(res)
    if res.status in COULD_NOT_VERIFY:
        assert res.findings == []
        pytest.skip(f"ICIJ could not be verified from this egress: {res.status.value} {res.error[:160]}")
    assert res.status in (Status.OK, Status.EMPTY), (res.status, res.error)
    assert set(res.hosts) <= {"offshoreleaks.icij.org"}
    for f in res.findings:
        assert "not evidence of wrongdoing" in f.title and f.confidence_label.value == "possible"


def test_sec_edgar_listed_company():
    res = run_module(SecEdgar, "company_name:Apple Inc.", runtime=live_runtime(contact_email=CONTACT))
    report(res)
    if res.status in COULD_NOT_VERIFY:
        pytest.skip(f"SEC could not be verified from this egress: {res.status.value} {res.error[:160]}")
    assert res.status is Status.OK, (res.status, res.error)
    company = res.attributes["sec_company"]
    assert company["cik"] in ("0000320193", "320193", 320193), company
    assert set(res.hosts) <= set(SecEdgar.hosts)


def test_sec_edgar_refuses_without_contact():
    http = FakeHttp()
    res = run_module(SecEdgar, "company_name:Apple Inc.", http)
    assert res.status is Status.SKIPPED and http.calls == []


def test_wikidata_organisation():
    res = run_module(Wikidata, "company_name:Banco do Brasil", runtime=live_runtime(contact_email=CONTACT))
    report(res)
    if res.status in COULD_NOT_VERIFY:
        pytest.skip(f"Wikidata could not be verified from this egress: {res.status.value} {res.error[:160]}")
    assert res.status is Status.OK, (res.status, res.error)
    assert res.attributes["wikidata_item"]["qid"].startswith("Q")
    assert all(p.expand is False for p in res.pivots)


def test_eu_vies_public_company_number():
    res = run_module(EuVies, "eu_vat:LU26375245", runtime=live_runtime())
    report(res)
    if res.status in COULD_NOT_VERIFY:
        assert res.findings == [] and res.attributes.get("vat_validation", {}).get("state", "not_verified") == "not_verified"
        pytest.skip(f"VIES could not be verified from this egress: {res.status.value} {res.error[:160]}")
    assert res.status is Status.OK, (res.status, res.error)
    assert res.attributes["vat_validation"]["state"] == "valid"


@pytest.mark.parametrize("cls, value", [(OpenSanctionsApi, "company_name:Example Holdings Limited"),
                                        (UkCompaniesHouse, "company_name:Example Holdings Limited")])
def test_keyed_modules_send_nothing_without_company_keys(cls, value):
    http = FakeHttp()
    res = run_module(cls, value, http)
    assert res.status in (Status.NEEDS_KEY, Status.SKIPPED) and http.calls == []
