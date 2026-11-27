"""Live checks of batch p3-G12-1 (geocoding, card_bin, user_agent_analysis; imei_check without a key); run with
V3LUM_LIVE=1.

Benign public values only: the Marco Zero of Sao Paulo (a public monument) and the postal code of NIC.br's building
for geocoding, binlist.net's own documentation BIN for card_bin (one request: 5/hour per IP), a well-known scanner
user agent against the teler list. No contact mailbox is configured here, so Nominatim must be SKIPPED 'config'
(nothing is sent to OSM without the identifying User-Agent) and Photon answers. A 403/429/challenge/timeout from this
datacenter egress is an acceptable outcome when the module reports it as could-not-verify, never as an absence.
"""

from __future__ import annotations

import pytest

from tests.fakes import run_module
from v3lum.config import Config
from v3lum.core.context import Runtime
from v3lum.core.models import Status
from v3lum.modules.geo_image_meta.geocoding import Geocoding
from v3lum.modules.utility.card_bin import CardBin
from v3lum.modules.utility.imei_check import ImeiCheck
from v3lum.modules.utility.user_agent_analysis import UserAgentAnalysis

pytestmark = pytest.mark.live
COULD_NOT_VERIFY = {Status.BLOCKED, Status.RATE_LIMITED, Status.QUOTA, Status.ERROR, Status.UNAVAILABLE}


def live_runtime(**settings):
    cfg = Config()
    cfg.settings.update(settings)
    return Runtime(cfg, no_cache=True)


def test_geocoding_reverse_marco_zero_via_photon_without_contact():
    res = run_module(Geocoding, "coordinates:-23.550278,-46.633889", runtime=live_runtime(), case_id="live-geo-rev")
    assert res.status in {Status.OK, Status.EMPTY} | COULD_NOT_VERIFY, (res.status, res.error)
    assert res.source_statuses["osmf_nominatim.geocoding"]["reason_code"] == "config"
    assert "nominatim.openstreetmap.org" not in res.hosts
    if res.status is Status.OK:
        assert res.attributes["geo_provider"] == "photon"
        assert res.attributes["geo_address"].get("country_code") == "BR"
        assert res.attributes["geo_attribution"].startswith("(c) OpenStreetMap contributors")


def test_geocoding_forward_cep_via_photon_without_contact():
    res = run_module(Geocoding, "cep:04578-000", runtime=live_runtime(), case_id="live-geo-cep")
    assert res.status in {Status.OK, Status.EMPTY} | COULD_NOT_VERIFY, (res.status, res.error)
    if res.status is Status.OK:
        assert res.attributes["geo_precision"] in ("postcode", "street", "city")
        assert res.attributes["geo_address"].get("country_code") == "BR"


def test_card_bin_docs_bin():
    res = run_module(CardBin, "card_bin:45717360", runtime=live_runtime(), case_id="live-bin")
    assert res.status in {Status.OK, Status.EMPTY} | COULD_NOT_VERIFY, (res.status, res.error)
    if res.status is Status.OK:
        assert res.attributes["card_scheme"] == "visa"
    assert set(res.hosts) <= {"lookup.binlist.net"}


def test_user_agent_analysis_with_the_real_teler_list():
    res = run_module(UserAgentAnalysis, "user_agent:sqlmap/1.8.11#stable (https://sqlmap.org)", runtime=live_runtime(),
                     case_id="live-ua")
    assert res.status is Status.OK
    assert res.attributes["ua_category"] == "scanner"
    st = res.source_statuses.get("github.user_agent_analysis_teler_bad_crawlers")
    assert st is None or st["status"] in ("unavailable", "error")  # could-not-verify is reported, never silent
    if st is None:
        assert res.attributes["ua_parsed"]["bad_crawler_match"] is True and res.datasets


def test_imei_check_without_a_key_sends_nothing():
    res = run_module(ImeiCheck, "imei:353893101234566", runtime=live_runtime(), case_id="live-imei")
    assert res.status is Status.NEEDS_KEY and not res.hosts
