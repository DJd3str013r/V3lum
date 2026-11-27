"""xposedornot_domain (P137 cond 2): 'was this SERVICE breached' answered locally from the XposedOrNot
catalogue dataset (the domain is never sent). Fixture: ``catalogue_subset.json`` = 14 of the 801 entries
of the live /v1/breaches catalogue (2026-11-26), logos/descriptions kept on two entries to prove they
are dropped.
"""

from __future__ import annotations

import json

import pytest

from tests.fakes import FakeHttp, module_fixture, run_module
from v3lum.core.models import Status
from v3lum.modules.breach_leak.xposedornot import CATALOGUE_DATASET, XposedOrNotDomain

MOD = XposedOrNotDomain
CATALOGUE = "https://api.xposedornot.com/v1/breaches"


@pytest.fixture(autouse=True)
def small_catalogue(monkeypatch):
    from v3lum.core import datasets
    from v3lum.modules.breach_leak import xposedornot as xon

    monkeypatch.setattr(xon, "MIN_CATALOGUE", 5)
    monkeypatch.setitem(datasets.DATASETS[CATALOGUE_DATASET], "min_bytes", 1)


def catalogue_http():
    return FakeHttp().add("GET", CATALOGUE, json=module_fixture(MOD, "catalogue_subset.json"))


def test_service_breach_answered_locally_with_fixed_wording():
    http = catalogue_http()
    res = run_module(MOD, "domain:www.8tracks.com", http)
    assert res.status is Status.OK
    assert http.urls() == [CATALOGUE]  # the dataset download only: the domain is never sent
    rec = res.attributes["service_breach_records"][0]
    assert rec["name"] == "8tracks" and rec["breach_date"] == "2017-06"
    assert "not accounts at this domain" in rec["wording"]
    f = res.findings[0]
    assert f.title == "XposedOrNot: this service was breached" and f.severity.label == "low"
    blob = json.dumps([res.attributes, res.raw, [x.to_dict() for x in res.findings]], default=str)
    assert "logo" not in blob.lower()


def test_sensitive_service_is_masked():
    res = run_module(MOD, "domain:hjedd.com", catalogue_http())
    assert res.status is Status.OK
    assert res.attributes["service_breach_records"][0]["name"] == "sensitive breach (name withheld)"
    assert "Hjedd" not in json.dumps([res.attributes, [x.to_dict() for x in res.findings]])


def test_unknown_service_is_empty_after_a_full_catalogue_search():
    res = run_module(MOD, "domain:acme.com.br", catalogue_http())
    assert res.status is Status.EMPTY and not res.findings


def test_catalogue_download_failure_is_never_empty():
    http = FakeHttp().add("GET", CATALOGUE, status=503, text="down", times=3)
    res = run_module(MOD, "domain:8tracks.com", http)
    assert res.status not in (Status.OK, Status.EMPTY)
    page = "<html><head><title>Just a moment...</title></head><body>cf-chl-widget</body></html>"
    http2 = FakeHttp().add("GET", CATALOGUE, status=403, text=page)
    assert run_module(MOD, "domain:8tracks.com", http2).status not in (Status.OK, Status.EMPTY)
