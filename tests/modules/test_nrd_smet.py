"""nrd_smet (P005 cond 2): the smet.cz list as a separate dataset source with unknown terms.

Fixtures in tests/fixtures/nrd_smet/: ``today_ok.txt`` holds the first 7 names of the real smet.cz
``today.txt`` (research sample, 2026-11-25; the real list holds about 140,000 names) and ``empty.txt`` an
empty body (derived).
"""

from __future__ import annotations

import subprocess
import sys
from pathlib import Path

import pytest

from tests.fakes import FakeClock, FakeHttp, make_runtime, run_module
from v3lum.core import policy
from v3lum.core.context import RunInfo, ScanOptions
from v3lum.core.datasets import DATASETS, unregister_dataset
from v3lum.core.entities import Entity, EntityType
from v3lum.core.models import Status
from v3lum.modules.domain_dns import nrd_feeds as mod
from v3lum.modules.domain_dns.nrd_feeds import SMET_DATASET, SMET_URL, NrdSmet

FIXTURES = Path(__file__).resolve().parents[1] / "fixtures" / "nrd_smet"


@pytest.fixture(autouse=True)
def small_list(monkeypatch):
    monkeypatch.setattr(mod, "MIN_NAMES", 5)
    mod._TEXTS.clear()
    yield
    if mod._smet_terms_class() == "unknown":
        unregister_dataset(SMET_DATASET)


def installed():
    mod.register_smet_dataset()
    DATASETS[SMET_DATASET]["min_bytes"] = 10
    http = FakeHttp().add("GET", SMET_URL, body=(FIXTURES / "today_ok.txt").read_bytes(), headers={"content-type": "text/plain"}, times=1)
    rt = make_runtime(http, clock=FakeClock())
    assert rt.data.update(SMET_DATASET).ok
    http.calls.clear()
    return http, rt


def test_contract_metadata_unknown_terms_and_off():
    cls = NrdSmet
    assert (cls.terms, cls.disclosure, cls.sources, cls.default_enabled) == ("unknown", "none", ("smet.nrd_today",), False)
    assert mod._smet_terms_class() == "unknown"


def test_dataset_is_not_registered_for_data_update_while_terms_are_unknown():
    """Importing the module registers no smet.cz dataset: `v3lum data update` never fetches an unreviewed list."""
    assert mod.smet_registration_allowed() is False
    code = ("import v3lum.modules.domain_dns.nrd_feeds as m; from v3lum.core.datasets import DATASETS; "
            "print(m.SMET_DATASET in DATASETS, m.RELEASE_DATASET in DATASETS)")
    out = subprocess.run([sys.executable, "-c", code], cwd=Path(__file__).resolve().parents[2], capture_output=True, text=True, timeout=120)
    assert out.returncode == 0, out.stderr[-500:]
    assert out.stdout.split() == ["False", "True"]


def test_disabled_in_every_licence_profile():
    from v3lum.core import module as module_mod

    module_mod.load_modules()
    rt = make_runtime()
    ent = Entity.make(EntityType.DOMAIN, "example.com")
    default = policy.decide(NrdSmet, ent, policy.make_context(rt, ScanOptions(), path="scan"), run=RunInfo(entity=ent, is_seed=True))
    assert (default.allowed, default.reason_code) == (False, "not_default")
    pctx = policy.make_context(rt, ScanOptions(), explicit={"nrd_smet"}, path="scan")  # even with -M nrd_smet
    decision = policy.decide(NrdSmet, ent, pctx, run=RunInfo(entity=ent, is_seed=True))
    assert (decision.allowed, decision.status, decision.reason_code) == (False, Status.SKIPPED, "licence")


def test_local_membership_once_cleared():
    http, rt = installed()
    res = run_module(NrdSmet, "domain:00-design.com", runtime=rt)
    assert res.status is Status.OK and res.attributes["nrd_first_seen"] == "2026-11-26"
    (f,) = res.findings
    assert f.source == "smet.nrd_today" and not f.tags  # untagged without a DoH confirmation
    miss = run_module(NrdSmet, "domain:example.com", runtime=rt)
    assert miss.status is Status.EMPTY and "smet.cz list of 2026-11-26" in miss.error
    assert not http.calls


def test_empty_and_html_downloads_are_rejected():
    http, rt = installed()
    http.add("GET", SMET_URL, body=(FIXTURES / "empty.txt").read_bytes())
    assert rt.data.update(SMET_DATASET).status == "failed"
    http.add("GET", SMET_URL, text="<html><head><title>Just a moment...</title></head><body>cf-chl-widget</body></html>")
    assert rt.data.update(SMET_DATASET).status == "failed"
    assert run_module(NrdSmet, "domain:00-design.com", runtime=rt).status is Status.OK  # the last good copy stays


def test_missing_list_is_unavailable():
    mod.register_smet_dataset()
    res = run_module(NrdSmet, "domain:example.com", FakeHttp())
    assert res.status is Status.UNAVAILABLE and res.reason_code == "dataset"
