"""mac_oui (P315, batch p2-G12-2): IEEE MA-L/MA-M/MA-S/IAB listings matched offline by longest prefix.

Fixtures in tests/fixtures/mac_oui/: trimmed heads of the real IEEE CSVs downloaded on 2026-11-26 (corporate
registrants; small registrants' street addresses cut to city/state/country), a truncated download and the
HTML block page shape the validator must reject.
"""

from __future__ import annotations

import os
from datetime import datetime, timezone

import pytest

from tests.fakes import FakeClock, FakeHttp, make_ctx, module_fixture, run_module
from v3lum import paths
from v3lum.core.datasets import DATASETS
from v3lum.core.http import PolicyError
from v3lum.core.models import Status
from v3lum.modules.utility import mac_oui as M
from v3lum.modules.utility.mac_oui import MacOui

CLOCK = "2026-11-26T12:00:00Z"
FETCHED = datetime(2026, 11, 26, 7, 1, 0, tzinfo=timezone.utc)
FILES = {"ieee_oui_ma_l": "ieee_ma_l.csv", "ieee_oui_ma_m": "ieee_ma_m.csv", "ieee_oui_ma_s": "ieee_ma_s.csv",
         "ieee_oui_iab": "ieee_iab.csv"}


def install(names=tuple(FILES), *, content=None):
    """Place local copies where the dataset manager keeps them (isolated V3LUM_HOME), dated today."""
    for name in names:
        path = paths.datasets_dir() / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(content if content is not None else module_fixture("mac_oui", FILES[name]), encoding="utf-8")
        stamp = FETCHED.timestamp()
        os.utime(path, (stamp, stamp))


def run(mac, http=None, **kw):
    http = http or FakeHttp()
    res = run_module(MacOui, f"mac_address:{mac}", http, clock=FakeClock(CLOCK), **kw)
    assert http.calls == []  # disclosure none: no MAC or prefix ever leaves the machine
    return res


@pytest.fixture(autouse=True)
def _fresh_index():
    M._CACHE.update(key=None, index=None)
    yield
    M._CACHE.update(key=None, index=None)


# ------------------------------------------------------------------ c1: parsing and the dataset manager
def test_ieee_csv_quirks_quoted_commas_nfkc_private_and_padding():
    rows = {r["assignment"]: r for r in M.parse_ieee_csv(module_fixture("mac_oui", "ieee_ma_l.csv"))["rows"]}
    assert rows["FCFBFB"]["org"] == "Cisco Systems, Inc" and rows["FCFBFB"]["country_hint"] == "US"
    assert rows["58108C"]["country_hint"] == "BR"
    assert rows["E4F14C"]["private"] is True
    assert rows["B812DA"]["org"] == "LVSWITCHES INC."  # leading space removed
    assert rows["203233"]["org"] == "SHENZHEN BILIAN ELECTRONIC CO.,LTD"  # full-width comma -> NFKC


def test_dataset_validator_rejects_html_truncated_and_wrong_registry(tmp_path):
    check = M._validator("MA-L", 30000)
    bad = tmp_path / "x.csv"
    for name, why in (("ieee_html_instead_of_csv.html", "html_instead_of_csv"), ("ieee_ma_l_truncated.csv", "too_few_rows")):
        bad.write_text(module_fixture("mac_oui", name), encoding="utf-8")
        with pytest.raises(ValueError, match=why):
            check(bad)
    assert M.validate_ieee_csv(module_fixture("mac_oui", "ieee_ma_m.csv"), "MA-L").startswith("wrong_registry")
    assert M.validate_ieee_csv(module_fixture("mac_oui", "ieee_ma_l.csv"), "MA-L") is None


def test_datasets_registered_with_registry_source_and_licence():
    for name in ("ieee_oui_ma_l", "ieee_oui_ma_m", "ieee_oui_ma_s", "ieee_oui_iab", "ieee_oui_cid"):
        reg = DATASETS[name]
        assert reg["source"] == "ieee.oui_registries" and reg["terms_class"] == "open" and reg["licence"]
        assert reg["url"].startswith("https://standards-oui.ieee.org/")
    assert DATASETS["ieee_oui_ma_l"]["essential"] and not DATASETS["ieee_oui_cid"]["essential"]


# ------------------------------------------------------------------ c1/c5: longest-prefix match
@pytest.mark.parametrize("mac,registry,bits,org", [
    ("FC:FB:FB:01:FA:21", "MA-L", 24, "Cisco Systems, Inc"),
    ("70:B3:D5:0A:C1:23", "MA-S", 36, "RoboCore Tecnologia"),  # MA-S beats the RA parent 70B3D5
    ("C8:5C:E2:70:00:01", "MA-M", 28, "SYNERGY SYSTEMS AND SOLUTIONS"),  # MA-M beats the RA parent C85CE2
    ("00:50:C2:F7:10:00", "IAB", 36, "RF Code"),  # IAB blocks live only in iab.csv
])
def test_longest_prefix_match(mac, registry, bits, org):
    install()
    res = run(mac)
    assert res.status is Status.OK
    assert res.attributes["mac_vendor"] == org
    assert res.attributes["mac_oui"]["registry"] == registry and res.attributes["mac_oui"]["bits"] == bits
    assert res.findings[0].title == "MAC vendor (IEEE registry)"
    assert {d["name"] for d in res.datasets} >= {"ieee_oui_ma_l", "ieee_oui_ma_m", "ieee_oui_ma_s", "ieee_oui_iab"}


def test_duplicate_assignment_lists_alternatives_and_private_registrant():
    install()
    res = run("08:00:30:12:34:56")
    assert res.attributes["mac_vendor"] == "NETWORK RESEARCH CORPORATION"
    assert res.attributes["mac_oui"]["alternatives"] == ["ROYAL MELBOURNE INST OF TECH", "CERN"]
    res = run("E4:F1:4C:00:00:01")
    assert res.attributes["mac_oui"]["private_registrant"] is True and "Private" in res.findings[0].description


def test_ra_parent_without_local_sub_block_is_reported_with_its_fallback_prefix():
    install()
    res = run("C8:5C:E2:B0:00:01")  # MA-M parent present, this sub-block missing from the trimmed mam.csv
    assert res.status is Status.OK
    assert res.attributes["mac_oui"]["status"] == "sub_block_unknown"
    assert res.attributes["mac_oui"]["fallback_prefix"] == "C85CE2B"  # 7 hex digits: MA-M block size
    assert "mac_vendor" not in res.attributes


def test_unknown_prefix_is_empty_with_the_prefix_only_fallback():
    install()
    res = run("00:4A:00:12:34:56")
    assert res.status is Status.EMPTY and "not in the IEEE registries" in res.error
    assert res.attributes["mac_oui"]["fallback_prefix"] == "004A00"


# ------------------------------------------------------------------ c2: local / multicast / random MACs
@pytest.mark.parametrize("mac,quadrant", [("02:00:5E:10:00:01", "AAI"), ("DA:A1:19:5C:3E:01", "ELI"),
                                          ("AA:00:04:00:0A:04", "ELI"), ("06:11:22:33:44:55", "reserved")])
def test_locally_administered_macs_are_flagged_never_looked_up(mac, quadrant):
    res = run(mac)  # no dataset installed: the lookup is never attempted
    assert res.status is Status.OK
    assert res.attributes["mac_flags"]["locally_administered"] is True
    assert res.attributes["mac_flags"]["slap_quadrant"] == quadrant
    assert res.findings[0].title == "Random/private MAC: vendor lookup not meaningful"
    assert "random/private MAC: vendor lookup not meaningful" in res.findings[0].description
    assert "random_mac" in res.findings[0].tags and "mac_oui" not in res.attributes and not res.datasets


def test_multicast_and_null_macs_are_flagged():
    assert run("01:00:5E:00:00:FB").attributes["mac_flags"]["multicast"] is True
    null = run("00:00:00:00:00:00")
    assert null.attributes["mac_flags"]["null"] is True and null.attributes["mac_flags"]["lookup_allowed"] is False


def test_lookup_vendor_never_offers_a_fallback_for_flagged_macs():
    idx = M.build_oui_index(M.parse_ieee_csv(module_fixture("mac_oui", "ieee_ma_l.csv"))["rows"])
    assert M.lookup_vendor(idx, "AA:00:04:00:0A:04") == {"status": "flagged", "reason": M.MAC_RANDOM_REASON,
                                                         "flags": M.mac_flags("AA:00:04:00:0A:04"), "fallback_prefix": None}
    assert M.registry_prefix("FC:FB:FB:01:FA:21", "MA-S") == "FCFBFB01F" and M.registry_prefix("FC:FB:FB", "MA-L") is None


# ------------------------------------------------------------------ datasets missing / partial
def test_no_local_copy_offline_is_unavailable_dataset():
    from tests.fakes import make_runtime

    rt = make_runtime(offline=True)
    res = run_module(MacOui, "mac_address:FC:FB:FB:01:FA:21", runtime=rt)
    assert res.status is Status.UNAVAILABLE and res.reason_code == "dataset"


def test_missing_sub_registry_makes_unknown_prefixes_could_not_verify():
    install(("ieee_oui_ma_l",))
    from tests.fakes import make_runtime

    rt = make_runtime(offline=True, clock=FakeClock(CLOCK))
    assert run_module(MacOui, "mac_address:FC:FB:FB:01:FA:21", runtime=rt).attributes["mac_vendor"] == "Cisco Systems, Inc"
    res = run_module(MacOui, "mac_address:00:4A:00:12:34:56", runtime=rt)
    assert res.status is Status.UNAVAILABLE and res.reason_code == "dataset"  # never 'unknown vendor' on a partial index


def test_offline_module_never_touches_the_network():
    ctx = make_ctx(MacOui, FakeHttp())
    with pytest.raises(PolicyError):
        ctx.http.get("https://api.macvendors.com/FCFBFB")
    assert MacOui.disclosure == "none" and MacOui.default_enabled is True and MacOui.terms == "open"
    assert MacOui.max_tlp.value_str == "red"
