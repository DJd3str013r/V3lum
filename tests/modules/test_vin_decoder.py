"""vin_decoder (P320): offline WMI/check digit first, NHTSA vPIC second (US-centric), never owner lookups.

Fixtures (tests/fixtures/vin_decoder/): trimmed real vPIC captures (the research sample for the published example
VIN 1HGCM82633A004352, the NHTSA documentation pattern 5UXWX7C5*BA, a batch, an HTTP-200 error answer, the
9BWZZZ37*VT pattern vPIC knows only by WMI, DecodeWMI/9BW, GetWMIsForManufacturer/volkswagen), a cut-off body,
synthetic offline vectors (serials carry EXAMP: they identify no vehicle) and a labelled text sample whose
person, e-mail and phone are documentation values.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from tests.fakes import FakeHttp, module_fixture, run_module
from v3lum.core.entities import Entity, display_value
from v3lum.core.entities import EntityType as T
from v3lum.core.http import NetworkError
from v3lum.core.models import Status
from v3lum.core.module import get_module
from v3lum.modules.utility import vin_decoder as vd
from v3lum.modules.utility.vin_decoder import VinDecoder

FIX = Path(__file__).resolve().parents[1] / "fixtures" / "vin_decoder"
URL = "https://vpic.nhtsa.dot.gov/api/vehicles/DecodeVinValues/{vin}?format=json"
NA_VIN = "1HGCM82633A004352"  # published example VIN of the research sample (2003 Honda Accord)
NA_BAD = "1HGCM82643A004352"  # same with position 9 changed
BR_VW = "9BWZZZ377VTEXAMPL"  # synthetic Brazilian VW VIN with a failing check digit
BR_HONDA = "93HGE6850AZEXAMPL"  # synthetic 93H VIN (WMI not listed by vPIC)


def vectors():
    return {v["id"]: v["vin"] for v in module_fixture("vin_decoder", "offline_vectors.json")["vectors"]}


def table():
    return json.loads((Path(vd.__file__).resolve().parents[2] / "data" / "vin_decoder" / "wmi_table.json").read_text())


def run(vin, http=None, **kw):
    http = http if http is not None else FakeHttp()
    res = run_module(VinDecoder, Entity.make(T.VIN, vin), http, **kw)
    return res, http


def blob(res):
    return json.dumps({"a": res.attributes, "raw": res.raw, "f": [(f.title, f.description, f.data) for f in res.findings],
                       "e": res.error}, default=str)


# ---- c1: detection ------------------------------------------------------------------------------

def test_labelled_vins_only_never_bare_tokens():
    text = (FIX / "labelled_text.txt").read_text(encoding="utf-8")
    got = [d["vin"] for d in vd.detect_labelled_vins(text)]
    assert got == [BR_VW, "9BD178169XBEXAMP0", NA_VIN, BR_HONDA]
    assert "9BWZZZ377VTEXAMPO" not in got  # contains O: never a VIN
    assert "AB12CD34EF56GH78J" not in got  # no label (a tracking code)
    assert vd.detect_labelled_vins("Token solto 1HGCM82633A004352 sem rotulo") == []
    assert vd.detect_labelled_vins("protocolo 1HGCM82633A004352X") == []
    assert vd.detect_labelled_vins(None) == []


def test_normalize_and_syntax():
    v = vectors()
    assert vd.normalize_vin(" vin: 1hgcm826-33a004352 ") == NA_VIN
    for bad in ("partial_pattern", "has_letter_o", "too_short"):
        assert vd.normalize_vin(v[bad]) is None and not vd.is_vin_syntax(v[bad])
    assert vd.normalize_vin(17) is None


def test_core_detects_the_type_prefix_but_not_a_bare_token():
    from v3lum.core import detect

    assert detect.detect(f"vin:{BR_VW}")[0].type is T.VIN
    assert all(d.type is not T.VIN for d in detect.detect(NA_VIN))


# ---- c2: offline decode -------------------------------------------------------------------------

def test_check_digit_enforced_only_for_north_american_wmis():
    v = vectors()
    t = table()
    ok = vd.vin_offline_decode(v["na_valid"], t, 2026)
    assert ok["validity"] == "valid" and ok["check_digit"]["matches"] and ok["check_digit"]["enforced"]
    bad = vd.vin_offline_decode(v["na_bad_check_digit"], t, 2026)
    assert bad["validity"] == "invalid" and bad["check_digit"]["expected"] == "3"
    assert vd.vin_check_digit(v["na_check_digit_x"]) == "X" and vd.vin_offline_decode(v["na_check_digit_x"], t, 2026)["validity"] == "valid"
    br = vd.vin_offline_decode(v["br_vw_failing_check_digit"], t, 2026)  # c2: a note, never 'invalid'
    assert br["validity"] == "valid" and not br["check_digit"]["matches"] and not br["check_digit"]["enforced"]
    assert "not required for this WMI region" in br["check_digit"]["note"]
    assert vd.vin_offline_decode(v["br_fiat_passing_check_digit"], t, 2026)["check_digit"]["matches"]
    assert vd.vin_offline_decode("ABC", t, 2026)["validity"] == "not_a_vin"


def test_country_from_iso3780_never_from_vpic():
    assert vd.iso3780_country("9BW") == {"country": "Brazil", "region": "South America"}
    assert vd.iso3780_country("93H")["country"] == "Brazil" and vd.iso3780_country("9C2")["country"] == "Brazil"
    assert vd.iso3780_country("1HG")["country"] == "United States" and vd.iso3780_country("3VW")["country"] == "Mexico"
    assert vd.iso3780_country("WVW")["country"] == "Germany" and vd.iso3780_country("JHM")["country"] == "Japan"
    assert vd.iso3780_country("KMH")["country"] == "South Korea" and vd.iso3780_country("ZFA")["country"] == "Italy"
    assert vd.iso3780_country("8AP")["country"] == "Argentina" and vd.iso3780_country("9FB")["country"] == "Colombia"
    assert vd.iso3780_country("B1X") == {"country": None, "region": "Africa"}  # outside the sure ranges: region only
    rows = vd.parse_vpic_wmis_for_manufacturer(module_fixture("vin_decoder", "vpic_wmis_for_manufacturer_vw.json"))
    nine_bw = next(r for r in rows if r["wmi"] == "9BW")
    assert nine_bw["vpic_country"] == "MEXICO" and nine_bw["country"] == "Brazil"


def test_bundled_wmi_table_has_the_brazilian_wmis():
    t = table()
    rows = t["table"]
    assert t["schema"] == "v3lum.vin_wmi_table/1" and t["count"] == len(rows) > 500
    assert rows["9BW"]["source"] == "nhtsa_vpic" and rows["9BW"]["make"] == "VOLKSWAGEN"
    assert rows["9BD"]["source"] == "curated" and rows["9BD"]["make"].startswith("FIAT")
    assert rows["93H"]["source"] == "curated" and rows["93H"]["make"].startswith("HONDA")
    assert rows["9C2"]["manufacturer"] == "MOTO HONDA DA AMAZONIA LTDA."
    assert all(vd.is_vin_syntax(k + "0" * 14) for k in rows)
    assert not any("country" in r for r in rows.values())  # c2: country is derived from ISO 3780, never stored
    wmi = vd.parse_vpic_decode_wmi(module_fixture("vin_decoder", "vpic_decode_wmi_9bw.json"))
    assert wmi["manufacturer"] == rows["9BW"]["manufacturer"]


def test_model_year_candidates():
    assert vd.model_year_candidates(NA_VIN, 2026) == [2003]
    assert vd.model_year_candidates(BR_VW, 2026) == [2027, 1997]  # non-NA: position 10 is only a hint
    assert vd.model_year_candidates("ABC", 2026) == []


# ---- c3: online step ----------------------------------------------------------------------------

def test_happy_path_decodes_with_the_us_label_and_masks_the_vin():
    http = FakeHttp().add("GET", URL.format(vin=NA_VIN), json=module_fixture("vin_decoder", "vpic_ok_full.json"))
    res, _ = run(NA_VIN, http)
    assert res.status is Status.OK and res.requests == 1
    a = res.attributes
    assert (a["vehicle_make"], a["vehicle_model"], a["vehicle_model_year"]) == ("HONDA", "Accord", "2003")
    assert a["vehicle_details"]["plant"]["country"] == "UNITED STATES (USA)" and a["vehicle_details"]["engine"]["cylinders"] == "6"
    assert a["vin_country"] == "United States" and a["vin_validity"] == "valid"
    assert a["vin_wmi"]["manufacturer"] == "AMERICAN HONDA MOTOR CO., INC." and a["vin_wmi"]["wmi"] == "1HG"
    assert a["vpic_result"]["error_codes"] == [0] and "US-market" in a["vpic_result"]["scope"]
    assert "vPIC: 2003 HONDA Accord" in a["vin_summary"] and "[US-market data]" in a["vin_summary"]
    finding = res.findings[0]
    assert finding.title == "VIN decoded" and "US-market data" in finding.description
    assert NA_VIN not in blob(res)  # c4: never the full VIN in attributes, findings or evidence
    assert res.raw["vin_masked"] == "1HGCM82633A******"
    assert not res.source_statuses
    http.assert_hosts_within(VinDecoder)


def test_brazilian_vin_with_failing_check_digit_is_valid_and_us_centric():
    http = FakeHttp().add("GET", URL.format(vin=BR_VW), json=module_fixture("vin_decoder", "vpic_not_found.json"))
    res, _ = run(BR_VW, http)
    a = res.attributes
    assert res.status is Status.OK and a["vin_validity"] == "valid" and a["vin_country"] == "Brazil"
    assert a["vin_check_digit"]["enforced"] is False and a["vin_check_digit"]["matches"] is False
    assert not [f for f in res.findings if "mismatch" in f.title]  # c2: a note, never a finding
    assert a["vin_wmi"]["make"] == "VOLKSWAGEN" and a["vehicle_make"] == "VOLKSWAGEN"
    assert "no detailed data" in a["vin_summary"] and "not required for this region" in a["vin_summary"]
    assert BR_VW not in blob(res)


def test_north_american_check_digit_mismatch_is_a_low_finding():
    body = module_fixture("vin_decoder", "vpic_ok_full.json")
    rec = dict(body["Results"][0], VIN=NA_BAD, ErrorCode="1",
               ErrorText="1 - Check Digit (9th position) does not calculate properly")
    http = FakeHttp().add("GET", URL.format(vin=NA_BAD), json=dict(body, Results=[rec]))
    res, _ = run(NA_BAD, http)
    assert res.attributes["vin_validity"] == "invalid"
    f = next(f for f in res.findings if f.title == "VIN check digit mismatch (North American VIN)")
    assert f.severity.name == "LOW" and f.criterion and "vin_check_digit_mismatch" in f.tags
    assert res.attributes["vpic_result"]["errors"][0]["flag"] == "check_digit"
    assert "vPIC flags the check digit" in res.attributes["vin_summary"]


def test_error_in_200_without_vehicle_data_is_a_vpic_absence_not_a_failure():
    http = FakeHttp().add("GET", URL.format(vin=BR_HONDA), json=module_fixture("vin_decoder", "vpic_error_in_200.json"))
    res, _ = run(BR_HONDA, http)
    assert res.status is Status.OK  # the offline facts stand
    assert res.source_statuses[vd.SRC_VPIC]["status"] == "empty"
    assert "vehicle_make" not in res.attributes and "vPIC: no vehicle data" in res.attributes["vin_summary"]
    assert [e["flag"] for e in res.attributes["vpic_result"]["errors"]] == ["incomplete", "not_registered_us", "model_year_mismatch"]
    assert res.attributes["vin_wmi"]["source"] == "curated" and res.attributes["vin_wmi"]["make"].startswith("HONDA")


@pytest.mark.parametrize("status,expected,code", [(429, "rate_limited", "rate_limited"), (403, "blocked", "challenge"),
                                                  (401, "blocked", "challenge"), (500, "error", "error")])
def test_refusals_are_could_not_verify_for_vpic(status, expected, code):
    http = FakeHttp().add("GET", URL.format(vin=NA_VIN), status=status, text="<html>nope</html>")
    res, _ = run(NA_VIN, http)
    st = res.source_statuses[vd.SRC_VPIC]
    assert (st["status"], st["reason_code"]) == (expected, code)
    assert res.status is Status.OK and "could not verify" in res.error  # never 'no vehicle data'
    assert "vehicle_make" not in res.attributes and "vPIC: could not verify" in res.attributes["vin_summary"]
    assert res.attributes["vin_country"] == "United States"


def test_timeout_and_dead_network_are_could_not_verify():
    http = FakeHttp().add("GET", URL.format(vin=NA_VIN), error=NetworkError("read timed out", kind="ReadTimeout", retryable=False))
    res, _ = run(NA_VIN, http)
    assert res.source_statuses[vd.SRC_VPIC]["status"] == "error" and "could not verify" in res.error


@pytest.mark.parametrize("kind", ["malformed", "html", "list", "no_results", "other_vin"])
def test_unusable_answers_are_errors_never_absences(kind):
    if kind == "malformed":
        route = {"text": (FIX / "vpic_malformed.json").read_text(), "headers": {"content-type": "application/json"}}
    elif kind == "html":
        route = {"text": "<!doctype html><html><body>Service unavailable</body></html>"}
    elif kind == "list":
        route = {"json": ["not", "an", "object"]}
    elif kind == "no_results":
        route = {"json": {"Count": 0, "Message": "Results returned successfully", "Results": []}}
    else:
        route = {"json": module_fixture("vin_decoder", "vpic_batch_ok.json")}  # two records, none for this VIN
    http = FakeHttp().add("GET", URL.format(vin=NA_VIN), **route)
    res, _ = run(NA_VIN, http)
    assert res.source_statuses[vd.SRC_VPIC]["status"] == "error" and "could not verify" in res.error
    assert res.status is Status.OK and "vehicle_make" not in res.attributes


def test_batch_parser_and_forms():
    parsed = vd.parse_vpic_decode(module_fixture("vin_decoder", "vpic_batch_ok.json"))
    assert parsed["ok"] and parsed["count"] == 2
    assert [r["make"] for r in parsed["results"]] == ["BMW", "VOLKSWAGEN"]
    assert vd.vpic_result_reason(parsed["results"][0]) == "incomplete"
    assert vd.vpic_result_reason(parsed["results"][1]) == "no_detailed_data"
    partial = vd.parse_vpic_decode(module_fixture("vin_decoder", "vpic_ok_partial.json"))
    assert partial["results"][0]["plant_country"] == "GERMANY"
    vins = [f"1HGCM8263{i % 10}A{i:06d}" for i in range(120)]
    forms = vd.vpic_batch_forms(vins + ["ABC", vins[0]], {vins[0]: 2003})
    assert len(forms) == 3 and forms[0]["DATA"].count(";") == 49 and forms[0]["DATA"].startswith(f"{vins[0]},2003;")
    assert all("ABC" not in f["DATA"] for f in forms)
    with pytest.raises(ValueError):
        vd.vpic_decode_url("9BWZZZ37*VT")  # only validated VINs leave the machine


# ---- keyword input with a label (c1) ------------------------------------------------------------

def test_keyword_with_a_chassi_label_is_decoded_offline_and_pivoted():
    res = run_module(VinDecoder, Entity.make(T.KEYWORD, f"Chassi: {BR_VW}"), FakeHttp())
    assert res.status is Status.OK and res.requests == 0
    piv = res.pivots[0]
    assert piv.entity.type is T.VIN and piv.entity.value == BR_VW and piv.relation == "mentions" and piv.expand
    row = res.attributes["vin_labelled"][0]
    assert row["vin_masked"] == "9BWZZZ377VT******" and row["country"] == "Brazil" and row["validity"] == "valid"
    assert BR_VW not in json.dumps(res.attributes)
    side = run_module(VinDecoder, Entity.make(T.KEYWORD, f"nº do chassi {BR_VW}"), FakeHttp(), is_seed=False, depth=1)
    assert side.pivots[0].expand is False and "analyst selection" in side.pivots[0].note


def test_bare_keyword_is_never_a_vin():
    res = run_module(VinDecoder, Entity.make(T.KEYWORD, NA_VIN), FakeHttp())
    assert res.status is Status.SKIPPED and res.reason_code == "not_applicable" and not res.pivots


# ---- c3/c4: metadata, privacy and forbidden lookups ---------------------------------------------

def test_metadata_matches_the_council():
    cls = get_module("vin_decoder")
    assert cls is VinDecoder and cls.default_enabled is False and cls.terms == "open"
    assert cls.disclosure == "third_party" and cls.trust_tier == "trusted" and cls.shares_input
    assert cls.hosts == ("vpic.nhtsa.dot.gov",) and cls.max_requests == 1 and cls.daily_quota == 500
    assert T.PLATE_BR not in cls.produces and T.PERSON not in cls.produces  # c4: no owner/plate lookups


def test_vin_is_personal_and_masked_in_exports():
    from v3lum.core.entities import PERSONAL_TYPES

    assert T.VIN in PERSONAL_TYPES
    assert display_value(T.VIN, NA_VIN) == "1HGCM82633A******"


def test_privacy_gate_runs_it_only_when_selected_with_a_purpose():
    """c3 (A3/A8): VIN is a PERSONAL_TYPE and the nhtsa provider has no personal-data review yet."""
    from tests.fakes import make_runtime
    from v3lum.core import policy
    from v3lum.core.context import RunInfo, ScanOptions

    rt = make_runtime()
    ent = Entity.make(T.VIN, NA_VIN)
    run_info = RunInfo(entity=ent, is_seed=True)
    no_purpose = policy.decide(VinDecoder, ent, policy.make_context(rt, ScanOptions(), explicit=["vin_decoder"]), run=run_info)
    assert not no_purpose.allowed and no_purpose.reason_code == "privacy"
    not_selected = policy.decide(VinDecoder, ent, policy.make_context(rt, ScanOptions(purpose="FRAUD-2026-01")), run=run_info)
    assert not not_selected.allowed
    selected = policy.decide(VinDecoder, ent, policy.make_context(rt, ScanOptions(purpose="FRAUD-2026-01"), explicit=["vin_decoder"]),
                             run=run_info)
    assert selected.allowed, selected.reason
    red = policy.decide(VinDecoder, ent, policy.make_context(rt, ScanOptions(purpose="FRAUD-2026-01", tlp="red"), explicit=["vin_decoder"]),
                        run=run_info)
    assert not red.allowed and red.reason_code == "tlp"
