"""mac_oui_online (P315 c3-c4, batch p2-G12-2): the opt-in prefix-only relay for prefixes missing from the
IEEE index.

Fixtures in tests/fixtures/mac_oui_online/: real maclookup.app and macvendors.com captures of 2026-11-26
(FCFBFB, C85CE27, 70B3D50AC, unknown 004A00; maclookup street addresses replaced by 'Example Street 1').
The IEEE listings come from tests/fixtures/mac_oui/ (trimmed real heads).
"""

from __future__ import annotations

import os
import re
from datetime import datetime, timezone

import pytest

from tests.fakes import FakeClock, FakeHttp, make_runtime, module_fixture, run_module
from v3lum import paths
from v3lum.core.models import Status
from v3lum.modules.utility import mac_oui as M
from v3lum.modules.utility.mac_oui_online import MacOuiOnline, parse_macvendors, prefix_urls

CLOCK = "2026-11-26T12:00:00Z"
FETCHED = datetime(2026, 11, 26, 7, 1, 0, tzinfo=timezone.utc)
KEY = "mlk_testvalue_0123456789"
ML = "https://api.maclookup.app/v2/macs/{p}"
MV = "https://api.macvendors.com/{p}"
CHALLENGE = "<html><head><title>Just a moment...</title></head><body>cf-chl-widget</body></html>"


def fx(name):
    return module_fixture("mac_oui_online", name)


def ieee(name):
    return module_fixture("mac_oui", name)


def install(*, drop: tuple[str, ...] = ()):
    """Local IEEE copies (isolated V3LUM_HOME); rows whose assignment is in ``drop`` are left out."""
    files = {"ieee_oui_ma_l": "ieee_ma_l.csv", "ieee_oui_ma_m": "ieee_ma_m.csv", "ieee_oui_ma_s": "ieee_ma_s.csv",
             "ieee_oui_iab": "ieee_iab.csv"}
    for name, fname in files.items():
        lines = [ln for ln in ieee(fname).splitlines(keepends=True) if not any(f",{d}," in ln for d in drop)]
        path = paths.datasets_dir() / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text("".join(lines), encoding="utf-8")
        os.utime(path, (FETCHED.timestamp(), FETCHED.timestamp()))


def run(mac, http, **kw):
    return run_module(MacOuiOnline, f"mac_address:{mac}", http, clock=FakeClock(CLOCK), **kw)


def assert_prefix_only(http, mac):
    full = re.sub(r"[^0-9A-F]", "", mac.upper())
    for url in http.urls():
        assert full not in url.upper(), url  # c4: never the full MAC
        assert re.search(r"/([0-9A-F]{6}|[0-9A-F]{7}|[0-9A-F]{9})(\?|$)", url), url


@pytest.fixture(autouse=True)
def _fresh_index():
    M._CACHE.update(key=None, index=None)
    yield
    M._CACHE.update(key=None, index=None)


# ------------------------------------------------------------------ metadata (c3, A3, A8)
def test_opt_in_unknown_tier_and_terms():
    cls = MacOuiOnline
    assert cls.default_enabled is False and cls.disclosure == "third_party" and cls.terms == "unknown"
    assert cls.trust_tier == "unknown" and cls.max_tlp.value_str == "green"  # never at AMBER until a tier is recorded
    assert set(cls.hosts) == {"api.maclookup.app", "api.macvendors.com"} and cls.max_requests == 2
    assert cls.optional_keys == ("maclookup",) and cls.min_interval >= 1.0


def test_prefix_urls_refuse_a_full_mac():
    assert prefix_urls("FCFBFB01FA21") is None and prefix_urls("FC:FB:FB") is None
    assert prefix_urls("c85ce27") == {"maclookup.macs_v2": ML.format(p="C85CE27"), "macvendors.lookup": MV.format(p="C85CE27")}


# ------------------------------------------------------------------ c3: only prefixes missing from the IEEE index
def test_prefix_known_locally_is_never_sent():
    install()
    http = FakeHttp()
    res = run("FC:FB:FB:01:FA:21", http)
    assert res.status is Status.SKIPPED and res.reason_code == "not_applicable" and http.calls == []


def test_random_mac_is_never_sent():
    http = FakeHttp()
    res = run("DA:A1:19:5C:3E:01", http)
    assert res.status is Status.SKIPPED and res.reason_code == "not_applicable" and http.calls == []


def test_without_the_ieee_index_nothing_is_sent():
    http = FakeHttp()
    res = run_module(MacOuiOnline, "mac_address:00:4A:00:12:34:56", http, runtime=make_runtime(http, offline=True))
    assert res.status is Status.UNAVAILABLE and res.reason_code == "dataset" and http.calls == []


# ------------------------------------------------------------------ c4: prefix-only answers
def test_unknown_ma_l_prefix_macvendors_404_is_an_absence():
    install()
    http = FakeHttp().add("GET", MV.format(p="004A00"), status=404, json=fx("macvendors_not_found_404.json"),
                          headers={"content-type": "application/json"})
    res = run("00:4A:00:12:34:56", http)
    assert res.status is Status.EMPTY and "unknown to macvendors" in res.error
    assert_prefix_only(http, "00:4A:00:12:34:56")
    http.assert_hosts_within(MacOuiOnline)


def test_ma_m_sub_block_sends_seven_hex_digits():
    install(drop=("C85CE27",))
    http = FakeHttp().add("GET", MV.format(p="C85CE27"), text=fx("macvendors_ok_ma_m.txt"), headers={"content-type": "text/plain"})
    res = run("C8:5C:E2:70:12:34", http)
    assert res.status is Status.OK and res.attributes["mac_vendor"] == "SYNERGY SYSTEMS AND SOLUTIONS"
    assert res.attributes["mac_online_lookup"] == {"source": "macvendors.lookup", "prefix_sent": "C85CE27"}
    assert http.urls() == [MV.format(p="C85CE27")]
    assert_prefix_only(http, "C8:5C:E2:70:12:34")


def test_keyed_maclookup_first_ma_s_nine_hex_digits_and_key_never_echoed():
    install(drop=("70B3D50AC",))
    http = FakeHttp().add("GET", ML.format(p="70B3D50AC") + f"?apiKey={KEY}", json=module_fixture("mac_oui_online", "maclookup_ok_ma_s.json"))
    res = run("70:B3:D5:0A:C1:23", http, keys={"maclookup": KEY})
    assert res.status is Status.OK and res.attributes["mac_vendor"] == "RoboCore Tecnologia"
    look = res.attributes["mac_online_lookup"]
    assert look["block_type"] == "MA-S" and look["block_size"] == 4095 and look["country"] == "BR"
    assert KEY not in repr(res.raw) and KEY not in repr(res.attributes)
    assert_prefix_only(http, "70:B3:D5:0A:C1:23")


def test_maclookup_found_false_is_an_absence():
    install()
    http = FakeHttp().add("GET", ML.format(p="004A00") + f"?apiKey={KEY}", json=module_fixture("mac_oui_online", "maclookup_not_found.json"))
    res = run("00:4A:00:12:34:56", http, keys={"maclookup": KEY})
    assert res.status is Status.EMPTY


# ------------------------------------------------------------------ could not verify (rule 5)
def test_429_on_one_provider_asks_the_other_and_reports_it():
    install()
    http = (FakeHttp().add("GET", MV.format(p="004A00"), status=429, text="slow down", headers={"retry-after": "60"})
            .add("GET", ML.format(p="004A00"), json=module_fixture("mac_oui_online", "maclookup_ok.json")))
    res = run("00:4A:00:12:34:56", http)
    assert res.status is Status.OK and res.attributes["mac_vendor"] == "Cisco Systems, Inc"
    assert res.source_statuses["macvendors.lookup"]["status"] == "rate_limited"


def test_429_on_both_is_rate_limited_never_empty():
    install()
    http = (FakeHttp().add("GET", MV.format(p="004A00"), status=429, text="slow down", headers={"retry-after": "60"})
            .add("GET", ML.format(p="004A00"), status=429, text="slow down", headers={"retry-after": "60"}))
    res = run("00:4A:00:12:34:56", http)
    assert res.status is Status.RATE_LIMITED


def test_challenge_then_5xx_is_blocked():
    install()
    http = (FakeHttp().add("GET", MV.format(p="004A00"), status=403, text=CHALLENGE, headers={"content-type": "text/html"})
            .add("GET", ML.format(p="004A00"), status=503, text="unavailable", times=5))
    res = run("00:4A:00:12:34:56", http)
    assert res.status is Status.BLOCKED and res.reason_code == "challenge"


def test_error_inside_http_200_is_never_an_answer():
    install()
    http = (FakeHttp().add("GET", ML.format(p="004A00") + f"?apiKey={KEY}",
                           json={"success": False, "error": "internal", "errorCode": 500})
            .add("GET", MV.format(p="004A00"), status=200, text='{"errors":{"detail":"Server Error"}}',
                 headers={"content-type": "application/json"}))
    res = run("00:4A:00:12:34:56", http, keys={"maclookup": KEY})
    assert res.status is Status.ERROR
    assert res.source_statuses["maclookup.macs_v2"]["status"] == "error"


def test_malformed_answers_are_errors():
    install()
    http = (FakeHttp().add("GET", MV.format(p="004A00"), status=200, text="<html><body>maintenance</body></html>",
                           headers={"content-type": "text/html"})
            .add("GET", ML.format(p="004A00"), status=200, text="{not json", headers={"content-type": "application/json"}))
    res = run("00:4A:00:12:34:56", http)
    assert res.status is Status.ERROR
    assert parse_macvendors(200, fx("macvendors_ok.txt")) == {"status": "found", "org": "Cisco Systems, Inc"}
