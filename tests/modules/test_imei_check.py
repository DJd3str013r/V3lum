"""imei_check (P319, batch p3-G12-1): TAC -> device model at imeidb.xyz; only the TAC probe leaves the machine."""

from __future__ import annotations

import json

from tests.fakes import FakeHttp, assert_no_secret, make_runtime, module_fixture, run_module
from v3lum import paths
from v3lum.core.context import ScanOptions
from v3lum.core.engine import Engine
from v3lum.core.entities import Entity
from v3lum.core.entities import EntityType as T
from v3lum.core.models import Status
from v3lum.modules.utility import imei_check as IC
from v3lum.modules.utility.imei_check import ImeiCheck

IMEI = "353893101234566"  # synthetic: TAC 35389310 (docs example TAC), serial 123456, valid Luhn digit
SERIAL = "123456"
PROBE_URL = "https://imeidb.xyz/api/imei/353893100000000?format=json"
TOKEN = "imeidb-test-token-0123456789abcdef"
KEYS = {"imeidb": TOKEN}


def env(name: str) -> dict:
    data = module_fixture("imei_check", name)
    kw = {"status": data["status"], "headers": data.get("headers") or {}}
    body = data["body"]
    if isinstance(body, str):
        kw["text"] = body
    else:
        kw["json"] = body
    return kw


def test_success_sends_only_the_tac_probe_with_the_token_in_a_header():
    http = FakeHttp().add("GET", PROBE_URL, match_headers={"X-Api-Key": TOKEN}, **env("imeidb_ok_docs_synthetic.json"))
    rt = make_runtime(http, keys=KEYS, cache=True)
    res = run_module(ImeiCheck, f"imei:{IMEI}", http, runtime=rt)
    assert res.status is Status.OK
    dev = res.attributes["device_info"]
    assert dev["brand"] == "Apple" and dev["model"] == "iPhone 11 Pro Max" and dev["tac"] == "35389310"
    assert dev["os_family"] == "iOS" and dev["nettech"][:2] == ["GSM", "CDMA"]
    assert "serial" not in json.dumps(dev) and "blacklist" not in json.dumps(dev)  # probe fields dropped
    assert res.attributes["imei_tac"] == "35389310" and res.attributes["imei_masked"] == "35389310*******"
    f = res.findings[0]
    assert "privacy" in f.tags and f.source == "imeidb.tac" and f.severity.name == "INFO"
    # FC3: the real serial never leaves the machine; AR01: the token is never in a URL
    for call in http.calls:
        assert SERIAL not in call["url"] and IMEI not in call["url"] and TOKEN not in call["url"]
    produced = {"attributes": res.attributes, "raw": res.raw,
                "findings": [[f.title, f.description, f.criterion, f.data] for f in res.findings]}
    assert IMEI not in json.dumps(produced, default=str)  # the module never echoes the full IMEI
    assert_no_secret(TOKEN, res.to_dict(), res.raw, res.error, paths.home())
    http.assert_hosts_within(ImeiCheck)


def test_401_is_needs_key():
    http = FakeHttp().add("GET", PROBE_URL, **env("imeidb_needs_key_401.json"))
    res = run_module(ImeiCheck, f"imei:{IMEI}", http, keys=KEYS)
    assert res.status is Status.NEEDS_KEY and res.reason_code == "needs_key"


def test_missing_token_is_needs_key_before_any_request():
    http = FakeHttp()
    res = run_module(ImeiCheck, f"imei:{IMEI}", http)
    assert res.status is Status.NEEDS_KEY
    assert http.calls == []


def test_402_out_of_money_is_quota():
    http = FakeHttp().add("GET", PROBE_URL, **env("imeidb_quota_402.json"))
    res = run_module(ImeiCheck, f"imei:{IMEI}", http, keys=KEYS)
    assert res.status is Status.QUOTA and res.reason_code == "quota"


def test_429_is_rate_limited():
    http = FakeHttp().add("GET", PROBE_URL, **env("imeidb_rate_limited_429.json"), times=2)
    res = run_module(ImeiCheck, f"imei:{IMEI}", http, keys=KEYS)
    assert res.status is Status.RATE_LIMITED


def test_460_invalid_imei_and_5xx_are_errors():
    http = FakeHttp().add("GET", PROBE_URL, **env("imeidb_error_460.json"))
    assert run_module(ImeiCheck, f"imei:{IMEI}", http, keys=KEYS).status is Status.ERROR
    http2 = FakeHttp().add("GET", PROBE_URL, status=503, text="maintenance", times=3)
    assert run_module(ImeiCheck, f"imei:{IMEI}", http2, keys=KEYS).status is Status.ERROR


def test_html_in_200_and_error_in_200_are_never_empty():
    http = FakeHttp().add("GET", PROBE_URL, **env("imeidb_html_in_200.json"))
    assert run_module(ImeiCheck, f"imei:{IMEI}", http, keys=KEYS).status is Status.ERROR
    http2 = FakeHttp().add("GET", PROBE_URL, json={"success": False, "message": "Your request was made with invalid credentials.", "code": 401})
    assert run_module(ImeiCheck, f"imei:{IMEI}", http2, keys=KEYS).status is Status.ERROR
    http3 = FakeHttp().add("GET", PROBE_URL, json={"success": True, "data": {"tac": 35389310}})
    assert run_module(ImeiCheck, f"imei:{IMEI}", http3, keys=KEYS).status is Status.ERROR


def test_not_found_is_a_documented_absence():
    http = FakeHttp().add("GET", PROBE_URL, json={"success": False, "message": "IMEI not found", "code": 404})
    res = run_module(ImeiCheck, f"imei:{IMEI}", http, keys=KEYS)
    assert res.status is Status.EMPTY and "not proof" in res.error


def test_tac_probe_helpers_never_carry_the_serial():
    assert IC.tac_probe(IMEI) == "353893100000000"
    assert IC.mask_imei(IMEI) == "35389310*******"
    for bad in (IMEI, "353893101234567", "35389310"):
        try:
            IC.imeidb_url(bad)
        except ValueError:
            continue
        raise AssertionError(f"{bad} must never become a request")  # pragma: no cover
    assert IC.imeidb_url(IC.tac_probe(IMEI)) == "https://imeidb.xyz/api/imei/353893100000000"


def test_unknown_tier_provider_receives_nothing_through_the_policy_gate():
    """FC4: imeidb.xyz is unknown tier until reviewed; the gate never sends it a PERSONAL_TYPES value."""
    rt = make_runtime(FakeHttp(), keys=KEYS, settings={"key_plans": {"imeidb": "business"}})
    opts = ScanOptions(include={"imei_check"}, include_disabled=True, purpose="device triage", tlp="clear",
                       allow_unknown=True)
    decision = Engine(rt, opts).decide_single(ImeiCheck, Entity.make(T.IMEI, IMEI))
    assert decision.allowed is False and decision.reason_code == "tier"


def test_metadata_matches_the_council_decision():
    assert ImeiCheck.default_enabled is False and ImeiCheck.terms == "key-terms"
    assert ImeiCheck.trust_tier == "unknown" and ImeiCheck.requires_keys == ("imeidb",)
    assert ImeiCheck.accepts == frozenset({T.IMEI}) and ImeiCheck.max_requests == 1
