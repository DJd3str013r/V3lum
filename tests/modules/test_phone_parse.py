"""phone_parse (P126): offline libphonenumber facts, the bundled Anatel DDD table and text extraction.

Fixtures in tests/fixtures/phone_parse/ (documentation numbers only: +55 DD [9]5555-01xx, NANP 555-01xx,
the Ofcom drama range, Banco do Brasil's public 0800 729 0001 / 4004 0001):
* ``ok_*``/``invalid_*``/``not_a_number``/``too_long``: the plain values phonenumbers 9.0.44 returned
  (``collect_phone_facts`` schema);
* ``extract_*``: PT-BR texts and the matcher output of the whole-text PhoneNumberMatcher;
* ``brasilapi_ddd_*``: BrasilAPI DDD answers (P127 dataset records; city names are public data);
* ``cnl_lopub_trimmed.txt``: 73 real lines of Anatel's CNL public download (one area-centre seat per
  DDD plus the border towns and the two anomalies), ISO-8859-1 as served;
* ``br_ddd_table_malformed.json``: a broken table for the validator.
"""

from __future__ import annotations

import hashlib
import json
import sys
import time
import zipfile

import pytest

from tests.fakes import FIXTURES, FakeHttp, make_ctx, module_fixture, run_module
from v3lum.core import datasets
from v3lum.core.entities import Entity
from v3lum.core.entities import EntityType as T
from v3lum.core.http import PolicyError
from v3lum.core.models import Status
from v3lum.core.validators import cpf_check_digits, cpf_valid
from v3lum.data import __file__ as _data_init
from v3lum.modules.phone import phone_parse as pp
from v3lum.modules.phone.phone_parse import PhoneParse

FX = FIXTURES / "phone_parse"
BUNDLED = json.loads((pp.Path(_data_init).parent / "phone_parse" / "br_ddd.json").read_text(encoding="utf-8"))
phonenumbers = pytest.importorskip("phonenumbers")


def facts(name, table=BUNDLED, dataset=None):
    return pp.normalise_phone_facts(module_fixture("phone_parse", f"{name}.json")["result"], table, dataset)


def text(name):
    return (FX / name).read_text(encoding="utf-8")


# ------------------------------------------------------------------ FC1/FC2: facts from libphonenumber
def test_br_mobile_facts():
    f = facts("ok_br_mobile")
    assert f["ok"] and f["valid"] and f["e164"] == "+5511955550100"
    assert f["line_type"] == "mobile"
    assert f["formats"] == {"e164": "+5511955550100", "international": "+55 11 95555-0100", "national": "(11) 95555-0100"}
    assert f["geodescription"]["level"] == "state" and f["geodescription"]["uf"] == "SP"  # a bare 'São Paulo' is the state
    assert f["br"]["line_hint"] == "mobile" and f["br"]["ddd"] == "11"
    assert f["ddd"]["uf"] == "SP" and f["ddd"]["main_city"] == "São Paulo" and f["ddd"]["cities"] is None
    assert f["ddd"]["coverage"] == pp.CITY_LIST_UNAVAILABLE
    assert f["time_zones"] == ["America/Sao_Paulo"] and f["time_zone_caveat"] is None
    assert f["carrier"] is None  # no prefix data for 11 95555: never guessed


def test_carrier_is_always_labelled_original():
    f = facts("ok_br_mobile_carrier")
    assert f["carrier"] == {"name": "Vivo", "label": "original carrier (portability not reflected)"}


def test_landline_gives_a_city_and_multi_state_ddd():
    land = facts("ok_br_landline")
    assert land["line_type"] == "fixed" and land["br"]["line_hint"] == "landline"
    assert land["geodescription"] == {"text": "São Paulo - SP", "level": "city", "country": "BR", "city": "São Paulo", "uf": "SP", "state": "São Paulo"}
    df = facts("ok_br_landline_df")
    assert df["ddd"]["uf"] == "DF" and df["ddd"]["ufs"] == ["DF", "GO"] and df["ddd"]["main_city"] == "Brasília"


def test_time_zone_caveat_for_ddd_81():
    f = facts("ok_br_landline_tz_quirk_81")
    assert f["time_zones"] == ["America/Noronha"] and f["uf_time_zones"][0] == "America/Recife"
    assert "UTC-2" in f["time_zone_caveat"] and "UTC-3" in f["time_zone_caveat"]


@pytest.mark.parametrize(("name", "cls", "prefix", "line_type"), [
    ("ok_br_tollfree_0800", "toll_free", "0800", "toll_free"),
    ("ok_br_shared_cost_4004", "national_single_number", "4004", "shared_cost"),
    ("ok_br_telemarketing_0303", "telemarketing", "0303", "shared_cost"),
    ("ok_br_premium_0900", "premium_rate", "0900", "premium_rate"),
])
def test_non_geographic_numbers(name, cls, prefix, line_type):
    f = facts(name)
    assert f["valid"] and f["line_type"] == line_type
    assert f["br"]["line_hint"] == "non_geographic" and f["ddd"] is None
    assert f["br"]["non_geographic"]["class"] == cls and f["br"]["non_geographic"]["prefix"] == prefix
    assert f["geodescription"]["level"] == "country"


def test_foreign_numbers_have_no_br_facts():
    us = facts("ok_us_fictional")
    assert us["region"] == "US" and us["br"] is None and us["ddd"] is None
    assert us["geodescription"]["level"] == "locality" and us["time_zones"] == ["America/Los_Angeles"]
    gb = facts("ok_gb_drama")
    assert gb["region"] == "GB" and gb["line_type"] == "fixed"


@pytest.mark.parametrize(("name", "reason"), [
    ("invalid_unallocated_ddd", "unallocated DDD 20"),
    ("invalid_too_short", "too_short"),
    ("invalid_8digit_mobile", "8-digit mobile without the ninth digit (pre-2016 format)"),
])
def test_invalid_numbers(name, reason):
    f = facts(name)
    assert f["ok"] and not f["valid"] and f["invalid_reason"] == reason
    assert "Etc/Unknown" not in f["time_zones"]


@pytest.mark.parametrize(("name", "reason"), [("not_a_number", "not_a_number"), ("too_long", "too_long")])
def test_parse_errors_are_reported_not_guessed(name, reason):
    f = facts(name)
    assert not f["ok"] and reason in f["reason"] and f["e164"] is None


@pytest.mark.parametrize("raw", [None, [], "x", {}, {"e164": "123"}, {"e164": "+5511955550100", "valid": "yes", "timezones": "x", "type": 7}])
def test_malformed_facts_never_crash(raw):
    f = pp.normalise_phone_facts(raw)
    assert isinstance(f, dict)
    if isinstance(raw, dict) and raw.get("e164") == "+5511955550100":
        assert f["ok"] and f["valid"] is False and f["time_zones"] == [] and f["line_type"] == "unknown"
    else:
        assert not f["ok"]


def test_installed_library_matches_the_recorded_facts():
    """Regression guard: the fixtures are phonenumbers 9.0.44 output; a library upgrade that changes them shows up here."""
    if phonenumbers.__version__ != "9.0.44":
        pytest.skip(f"fixtures recorded with phonenumbers 9.0.44, installed {phonenumbers.__version__}")
    keys = ("valid", "possible", "possible_reason", "region", "type", "e164", "international", "national", "geo_pt", "carrier_pt", "timezones")
    for path in sorted(FX.glob("ok_*.json")) + sorted(FX.glob("invalid_*.json")):
        rec = json.loads(path.read_text(encoding="utf-8"))["result"]
        live = pp.collect_phone_facts(rec["input"], "BR")
        assert {k: live.get(k) for k in keys} == {k: rec.get(k) for k in keys}, path.name
    assert "parse_error" in pp.collect_phone_facts("abc", "BR")


def test_br_number_facts_reads_only_core_e164():
    assert pp.br_number_facts("+55 11 95555-0100")["ok"] is False  # never re-normalised (FC1)
    assert pp.br_number_facts("+14155550100")["reason"] == "not a Brazilian number"
    assert pp.br_number_facts("+551175550100")["line_hint"] == "mobile_sme_8digit"
    assert pp.br_number_facts("+55119555")["line_hint"] == "invalid_length"


# ------------------------------------------------------------------ FC3: bundled table, generator, P127 dataset
def test_bundled_table_is_valid_and_from_anatel():
    assert pp.validate_br_ddd_table(BUNDLED) == []
    assert set(BUNDLED["ddd"]) == pp.BR_DDD_CODES and len(BUNDLED["ddd"]) == 67
    assert "Anatel" in BUNDLED["source"] and BUNDLED["source_url"].startswith("https://sistemas.anatel.gov.br/")
    assert BUNDLED["ddd"]["61"]["ufs"] == ["DF", "GO"] and BUNDLED["ddd"]["47"]["ufs"] == ["SC", "PR"]
    capitals = {e["main_city"] for e in BUNDLED["ddd"].values() if e["main_city_basis"] == "state capital"}
    assert capitals == set(pp.UF_CAPITALS.values())


def test_validator_lists_every_problem_of_a_broken_table():
    problems = "\n".join(pp.validate_br_ddd_table(module_fixture("phone_parse", "br_ddd_table_malformed.json")))
    for expected in ("missing source", "generated_at is not an ISO date", "source is not Anatel", "source_url is not an Anatel",
                     "DDD 11: bad uf", "DDD 12: empty main_city", "bad DDD key '1'", "bad DDD key '20'", "DDD 23 is not allocated",
                     "DDD 61: ufs must list valid UFs including uf", "DDD 62: entry is not an object", "missing DDDs"):
        assert expected in problems
    assert pp.validate_br_ddd_table(["not", "a", "table"]) == ["table is not a JSON object"]
    draft = dict(BUNDLED, source="DRAFT table (not from Anatel)")
    assert any("draft" in p for p in pp.validate_br_ddd_table(draft))


def test_generator_rebuilds_the_bundled_table_from_real_cnl_lines():
    records, digests = pp.read_cnl_inputs([FX / "cnl_lopub_trimmed.txt"])
    assert len(records) == 73 and digests[0]["localities"] == 73
    table = pp.build_br_ddd_table(records, generated_at="2026-11-26", inputs=digests)
    assert pp.validate_br_ddd_table(table) == []
    assert table["ddd"] == BUNDLED["ddd"]
    assert {(a["ddd"], a["uf"], a["municipio"]) for a in table["anomalies"]} == {("48", "SP", "Bariri"), ("51", "MT", "Boa Esperança do Norte")}
    carajas = next(r for r in records if r["municipio"] == "Parauapebas")
    assert carajas["cn"] == "94" and carajas["centro_area"] == "SIM"  # the area centre of a municipality need not be its seat


def test_generator_cli_reads_the_zip_of_the_public_form(tmp_path):
    archive = tmp_path / "LOPUB000001.ZIP"
    with zipfile.ZipFile(archive, "w") as zf:
        zf.write(FX / "cnl_lopub_trimmed.txt", "LOPUB000001.TXT")
        zf.writestr("LAYOUT_LOPUB.doc", "layout")
    out = tmp_path / "br_ddd.json"
    assert pp.main([str(out), str(archive), "--date", "2026-11-26"]) == 0
    table = json.loads(out.read_text(encoding="utf-8"))
    assert table["ddd"] == BUNDLED["ddd"] and table["generated_at"] == "2026-11-26" and table["inputs"]["files"] == 1
    assert pp.main([str(out)]) == 2  # usage


def test_generator_refuses_missing_ddds_and_unreviewed_main_cities(monkeypatch):
    records, _ = pp.read_cnl_inputs([FX / "cnl_lopub_trimmed.txt"])
    with pytest.raises(ValueError, match="DDD 94: no locality"):
        pp.build_br_ddd_table([r for r in records if r["cn"] != "94"], generated_at="2026-11-26")
    monkeypatch.setitem(pp.MAIN_CITY_OVERRIDES, "12", ("SP", "Jacareí"))  # a municipality that is not an area centre
    with pytest.raises(ValueError, match="DDD 12: override"):
        pp.build_br_ddd_table(records, generated_at="2026-11-26")
    monkeypatch.delitem(pp.MAIN_CITY_OVERRIDES, "12")
    with pytest.raises(ValueError, match="DDD 12: no state capital and no reviewed override"):
        pp.build_br_ddd_table(records, generated_at="2026-11-26")


def test_notice_records_the_bundled_table():
    notice = json.loads((pp.Path(_data_init).parent / "notices" / "phone_parse_br_ddd.json").read_text(encoding="utf-8"))
    raw = (pp.Path(_data_init).parent / "phone_parse" / "br_ddd.json").read_bytes()
    assert notice["sha256"] == hashlib.sha256(raw).hexdigest() and notice["bundled"] is True
    assert notice["source_url"] == BUNDLED["source_url"] and "Anatel" in notice["attribution"]


def test_uf_tables_are_consistent():
    assert set(pp.UF_NAMES) == set(pp.UF_CAPITALS) == set(pp.UF_NEIGHBOURS) == set(pp.UF_TIME_ZONES)
    for uf, neighbours in pp.UF_NEIGHBOURS.items():
        assert all(uf in pp.UF_NEIGHBOURS[n] for n in neighbours), uf  # borders are symmetric
    assert set(pp.MAIN_CITY_OVERRIDES).isdisjoint({cn for cn, e in BUNDLED["ddd"].items() if e["main_city_basis"] == "state capital"})


def test_brasilapi_ddd_records():
    df = pp.parse_brasilapi_ddd(module_fixture("phone_parse", "brasilapi_ddd_ok_df.json"))
    assert df["ok"] and df["state"] == "DF" and "BRASÍLIA" in df["cities"] and len(df["cities"]) == 13
    assert pp.parse_brasilapi_ddd(module_fixture("phone_parse", "brasilapi_ddd_ok_sp.json"))["state"] == "SP"
    assert pp.parse_brasilapi_ddd(module_fixture("phone_parse", "brasilapi_ddd_not_found.json"))["reason"] == "not_found"
    assert pp.parse_brasilapi_ddd((FX / "brasilapi_ddd_malformed.json").read_bytes())["reason"] == "malformed JSON"
    assert pp.parse_brasilapi_ddd("<!doctype html><html><body>blocked</body></html>")["reason"] == "HTML page instead of JSON"
    assert pp.parse_brasilapi_ddd(["x"])["reason"] == "unexpected JSON shape"
    assert pp.parse_brasilapi_ddd({"state": "XX", "cities": []})["reason"] == "missing state/cities"


def test_ddd_dataset_shapes():
    df = module_fixture("phone_parse", "brasilapi_ddd_ok_df.json")
    assert set(pp.parse_ddd_dataset({"61": df, "20": df, "xx": df})) == {"61"}
    assert set(pp.parse_ddd_dataset([dict(df, ddd="61"), {"ddd": "11", "name": "DDD_NOT_FOUND"}])) == {"61"}
    assert pp.parse_ddd_dataset("junk") == {}
    info = pp.ddd_info("61", BUNDLED, pp.parse_brasilapi_ddd(df))
    assert info["cities_source"] == "brasilapi_ddd" and info["coverage"] is None and len(info["cities"]) == 13


# ------------------------------------------------------------------ module runs (phone entities)
def test_module_br_mobile_through_the_engine():
    http = FakeHttp()
    res = run_module(PhoneParse, "phone:+55 11 95555-0100", http)
    assert res.status is Status.OK and http.calls == [] and res.requests == 0
    a = res.attributes
    assert a["valid"] is True and a["line_type"] == "mobile" and a["country"] == "BR" and a["region"] == "SP"
    assert a["phone_formats"]["national"] == "(11) 95555-0100"
    assert a["phone_ddd"]["main_city"] == "São Paulo" and a["phone_ddd"]["coverage"] == pp.CITY_LIST_UNAVAILABLE
    assert a["phone_br"]["line_hint"] == "mobile" and a["timezone"] == ["America/Sao_Paulo"]
    assert "city" not in a  # a mobile's geodescription is the state, never a city
    assert any(d["name"] == pp.DDD_TABLE and d["fetched_at"] == "bundled" for d in res.datasets)
    assert res.raw["facts"]["e164"] == "+5511955550100"


def test_module_labels_the_original_carrier_and_flags_time_zones():
    res = run_module(PhoneParse, "phone:+55 21 99555-0100")
    assert res.attributes["original_carrier"] == {"name": "Vivo", "label": pp.ORIGINAL_CARRIER_LABEL}
    recife = run_module(PhoneParse, "phone:(81) 5555-0100")
    tz = [f for f in recife.findings if f.title == "libphonenumber time zone differs from the DDD state"]
    assert len(tz) == 1 and tz[0].severity.label == "info"


def test_module_invalid_number_is_a_fact_not_an_error():
    res = run_module(PhoneParse, "phone:+55 20 95555-0100")
    assert res.status is Status.OK
    assert res.attributes["valid"] is False and res.attributes["phone_invalid_reason"] == "unallocated DDD 20"
    finding = next(f for f in res.findings if f.title == "Phone number is not valid")
    assert finding.severity.label == "info" and "unallocated DDD 20" in finding.description


def test_module_non_geographic_and_foreign_numbers():
    toll = run_module(PhoneParse, "phone:0800 729 0001")
    assert toll.attributes["line_type"] == "toll_free" and "phone_ddd" not in toll.attributes
    assert any(f.title == "Non-geographic Brazilian number" and f.data["class"] == "toll_free" for f in toll.findings)
    us = run_module(PhoneParse, "phone:+1 415-555-0100")
    assert us.attributes["country"] == "US" and "phone_br" not in us.attributes
    assert not any(d["name"] == pp.DDD_TABLE for d in us.datasets)  # the BR table is cited only when used


def test_offline_module_has_no_network():
    ctx = make_ctx(PhoneParse, FakeHttp())
    with pytest.raises(PolicyError):  # disclosure 'none': ctx.http refuses every request
        ctx.http.get("https://brasilapi.com.br/api/ddd/v1/11")


def test_missing_package_is_unavailable(monkeypatch):
    monkeypatch.setitem(sys.modules, "phonenumbers", None)  # import phonenumbers -> ImportError
    res = PhoneParse().run(Entity.make("phone", "+5511955550100"), make_ctx(PhoneParse))
    assert res.status is Status.UNAVAILABLE and res.reason_code == "package"


def test_missing_or_invalid_table_degrades_to_libphonenumber_facts(monkeypatch):
    ctx = make_ctx(PhoneParse)
    monkeypatch.setattr(ctx.data, "bundled_json", lambda name: dict(BUNDLED, source="DRAFT"))
    assert pp._ddd_table(ctx) is None

    def missing(name):
        raise FileNotFoundError(name)

    monkeypatch.setattr(ctx.data, "bundled_json", missing)
    res = PhoneParse().run(Entity.make("phone", "+5511955550100"), ctx)
    assert res.status is Status.OK and res.attributes["valid"] is True
    assert res.attributes["phone_ddd"]["uf"] is None and "region" not in res.attributes


def test_brasilapi_dataset_is_read_only_when_registered_and_present(clean_registry):
    ctx = make_ctx(PhoneParse)
    assert pp._ddd_dataset(ctx) == {}  # not registered (P127 not landed): never fetched
    datasets.register_dataset(
        pp.BRASILAPI_DDD_DATASET, "https://brasilapi.com.br/api/ddd/v1/all", ttl=30 * 86400, licence="MIT code; Anatel data",
        terms_class="open", provider="brasilapi", source="brasilapi.ddd", expect="json",
    )
    assert pp._ddd_dataset(ctx) == {}  # registered but never downloaded: no download mid-scan
    path = ctx.data.store.path(pp.BRASILAPI_DDD_DATASET)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps({"61": module_fixture("phone_parse", "brasilapi_ddd_ok_df.json")}), encoding="utf-8")
    res = PhoneParse().run(Entity.make("phone", "+556155550100"), ctx)
    ddd = res.attributes["phone_ddd"]
    assert ddd["cities_source"] == "brasilapi_ddd" and "VALPARAÍSO DE GOIÁS" in ddd["cities"] and ddd["coverage"] is None
    assert any(d["name"] == pp.BRASILAPI_DDD_DATASET for d in ctx.data.used)


# ------------------------------------------------------------------ FC4: extraction from text and files
def _by_e164(matches):
    out = {}
    for m in matches:
        out.setdefault(m["e164"], [m["start"], m["end"]])
    return out


@pytest.mark.parametrize("name", ["extract_ok", "extract_formats"])
def test_windowed_extraction_equals_the_whole_text_matcher(name):
    expected = _by_e164(module_fixture("phone_parse", f"{name}_matches.json")["matches"])
    out = pp.extract_phones(text(f"{name}.txt"), region="BR")
    assert {p["e164"]: p["spans"][0] for p in out["phones"]} == expected
    assert not out["cap_hit"] and not out["windows_capped"]


def test_protocol_numbers_and_cnpj_are_not_phones():
    found = {p["e164"] for p in pp.extract_phones(text("extract_ok.txt"))["phones"]}
    assert not any("2026112612345" in e for e in found) and not any("000000000191" in e for e in found)


def test_match_cap():
    assert len({m["e164"] for m in module_fixture("phone_parse", "extract_cap_matches.json")["matches"]}) == 150
    out = pp.extract_phones(text("extract_cap.txt"))
    assert out["distinct"] == pp.MATCH_CAP == 100 and out["cap_hit"] is True
    res = run_module(PhoneParse, Entity.make("text_blob", text("extract_cap.txt")))
    assert len(res.pivots) == 100 and all(p.expand is False for p in res.pivots)
    finding = next(f for f in res.findings if f.title == "Phone numbers extracted from text")
    assert finding.data["cap_hit"] is True and "capped at 100 distinct numbers" in finding.description


def test_text_run_lists_personal_pivots_for_analyst_selection():
    res = run_module(PhoneParse, Entity.make("text_blob", text("extract_ok.txt")), FakeHttp())
    assert res.status is Status.OK and res.requests == 0
    values = {p.entity.value for p in res.pivots}
    assert values == set(_by_e164(module_fixture("phone_parse", "extract_ok_matches.json")["matches"]))
    for p in res.pivots:  # PERSONAL_TYPES from text never auto-expand (AR07)
        assert p.entity.type is T.PHONE and p.expand is False and p.note == pp.PERSONAL_NOTE and p.relation == "mentions"
    assert res.raw["spans"]["+5511955550100"] == [[48, 63]]


def test_cpf_shaped_digit_strings_never_become_phones():
    cpf = "119555501" + cpf_check_digits("119555501")
    assert cpf_valid(cpf) and pp.cpf_shaped(cpf)
    assert pp.collect_phone_facts("+55" + cpf)["valid"] is True  # also a valid SP mobile: ambiguous
    res = run_module(PhoneParse, Entity.make("text_blob", f"contato {cpf} e (11) 95555-0100"))
    assert {p.entity.value for p in res.pivots} == {"+5511955550100"}
    assert res.raw["withheld_cpf_shaped"] == 1
    assert any(f.title == "Phone extraction incomplete" for f in res.findings)
    assert cpf not in json.dumps({"raw": res.raw, "pivots": [p.entity.value for p in res.pivots]})


def test_default_region_setting_is_used_for_national_formats():
    sample = "call (415) 555-0100 today"
    br = run_module(PhoneParse, Entity.make("text_blob", sample))  # default BR: DDD 41 + landline 5555-0100
    assert {p.entity.value for p in br.pivots} == {"+554155550100"} and br.raw["region"] == "BR"
    us = run_module(PhoneParse, Entity.make("text_blob", sample), settings={"default_region": "US"})
    assert {p.entity.value for p in us.pivots} == {"+14155550100"} and us.raw["region"] == "US"
    bad = run_module(PhoneParse, Entity.make("text_blob", sample), settings={"default_region": "brazil"})
    assert bad.raw["region"] == "BR"  # an unusable setting falls back to BR


def test_phones_after_long_digit_rich_prose_are_found():
    """The whole-text matcher gives up after 65,535 failed candidates; the windows never do."""
    filler = "Pedido 2026-11-26 ref 4512 valor 1.234,56 lote 98765 cod 314159 " * 18000  # ~1.1 MB
    blob = filler + " fale com (11) 95555-0101 ou 0800 729 0001."
    start = time.perf_counter()
    out = pp.extract_phones(blob)
    assert {p["e164"] for p in out["phones"]} == {"+5511955550101", "+558007290001"}
    assert time.perf_counter() - start < 10


def test_pathological_input_is_bounded():
    start = time.perf_counter()
    assert pp.phone_candidate_windows(".-" * 500_000)["windows"] == []
    capped = pp.phone_candidate_windows("1 " * 20_000, max_windows=50)
    assert capped["capped"] is True and len(capped["windows"]) == 50
    assert time.perf_counter() - start < 5


def test_cancelled_extraction_stops():
    out = pp.extract_phones(text("extract_ok.txt"), cancelled=lambda: True)
    assert out["cancelled"] is True and out["phones"] == []


def test_file_inputs(tmp_path):
    note = tmp_path / "note.txt"
    note.write_text(text("extract_ok.txt"), encoding="utf-8")
    res = run_module(PhoneParse, Entity.make("file", str(note)))
    assert res.status is Status.OK and "+558007290001" in {p.entity.value for p in res.pivots}
    image = tmp_path / "photo.png"
    image.write_bytes(b"\x89PNG....")
    skipped = run_module(PhoneParse, Entity.make("file", str(image)))
    assert skipped.status is Status.SKIPPED and skipped.reason_code == "not_applicable"


def test_unreadable_file_is_an_error_not_an_empty_result(tmp_path, monkeypatch):
    note = tmp_path / "note.txt"
    note.write_text("(11) 95555-0100")
    ent = Entity.make("file", str(note))

    def denied(*args, **kwargs):
        raise PermissionError(13, "Permission denied")

    ctx = make_ctx(PhoneParse)
    monkeypatch.setattr("v3lum.modules.phone.phone_parse.open", denied, raising=False)  # shadows the builtin there only
    res = PhoneParse().run(ent, ctx)
    assert res.status is Status.ERROR and "Permission denied" in res.error and not res.pivots


def test_text_without_phones_is_empty():
    res = run_module(PhoneParse, Entity.make("text_blob", "nenhum telefone aqui, só o CEP 01310-100 e a data 26/11/2026"))
    assert res.status is Status.EMPTY and not res.pivots
