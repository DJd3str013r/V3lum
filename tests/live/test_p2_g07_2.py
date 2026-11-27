"""Live checks of batch p2-G07-2 (siem_search, offline_hash_sets).

Run once with ``V3LUM_LIVE=1 pytest -q -m live tests/live/test_p2_g07_2.py``. No investigated value is
sent anywhere: offline_hash_sets is offline (disclosure none) and its export needs the abuse.ch
Auth-Key (none in this build environment), and siem_search talks only to the team's internal SIEM,
which a datacenter egress cannot reach (A12: synthetic fixtures). What can be checked live is the
state of the keyless abuse.ch export endpoints the module must never rely on: the legacy keyless
MalwareBazaar export answers 410 Gone, and that body is refused as an export copy (never read as
'no samples'). A 403/429/challenge from this egress is reported as could-not-verify and skipped.
"""

from __future__ import annotations

import pytest

from v3lum.config import Config
from v3lum.core.context import Runtime, ScanOptions
from v3lum.core.engine import Engine
from v3lum.core.entities import Entity
from v3lum.core.entities import EntityType as T
from v3lum.core.models import Status
from v3lum.modules.cti_framework.siem_search import SiemSearch
from v3lum.modules.malware_hash.offline_hash_sets import OfflineHashSets, export_problem

pytestmark = pytest.mark.live
LEGACY_EXPORT = "https://bazaar.abuse.ch/export/csv/recent/"
EXPORT_PAGE = "https://bazaar.abuse.ch/export/"
EICAR_SHA256 = "275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f"


def _runtime() -> Runtime:
    return Runtime(Config(), no_cache=True)


def _get(url: str):
    resp = _runtime().http.request("GET", url, timeout=20)
    if resp.status in (403, 429) or resp.classification is not None and resp.classification.status in ("blocked", "rate_limited"):
        pytest.skip(f"{url} could not be verified from this egress: HTTP {resp.status}")
    return resp


def test_live_legacy_keyless_export_is_gone_and_never_read_as_data():
    resp = _get(LEGACY_EXPORT)
    assert resp.status == 410, resp.status
    problem = export_problem(resp.text)
    assert problem and "410" in problem  # a saved 410 body is an error, never an empty export


def test_live_export_page_still_documents_keyed_exports():
    resp = _get(EXPORT_PAGE)
    assert resp.status == 200
    assert "export" in resp.text.lower()
    assert export_problem(resp.text) is not None  # an HTML page is never an export copy


def test_live_offline_module_stays_offline_without_a_copy():
    res = Engine(_runtime(), ScanOptions()).run_module(OfflineHashSets, Entity.make(T.SHA256, EICAR_SHA256))
    assert res.status is Status.UNAVAILABLE and res.reason_code == "dataset" and res.requests == 0 and not res.hosts


def test_live_siem_search_without_configuration_contacts_nothing():
    res = Engine(_runtime(), ScanOptions()).run_module(SiemSearch, Entity.make(T.IPV4, "8.8.8.8"))
    assert res.status in (Status.NEEDS_KEY, Status.SKIPPED) and res.requests == 0 and not res.hosts
