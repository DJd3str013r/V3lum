"""br_validators (P232): offline Brazilian identifier validators and the BR entity rule set.

Fixtures in tests/fixtures/br_validators/ (prep batch p1-G10-1, 2026-11-26): ``research_vectors.json``
(the 18 research vectors of the prototype, 18/18 passing, plus the RFB alphanumeric example; the phone
vector moved to the documentation range +55 11 9555-01xx), ``selftest_ok.json`` (the live_osint
selftest sample), ``phone_cpf_collision.txt`` (valid-DV phone numbers that must never become CPFs),
``scam_messages.txt`` (synthetic BR scam texts: example.com, documentation phones, BCB/doc CPF and CNPJ
vectors) and ``masking_cases.json``. CPFs used are documentation examples (529.982.247-25,
123.456.789-09), never linked to a person.
"""

from __future__ import annotations

import json
import socket

import pytest

from tests.fakes import FakeHttp, make_ctx, make_runtime, module_fixture, run_module
from v3lum.core.context import ScanOptions
from v3lum.core.entities import Entity, mask_cpf
from v3lum.core.entities import EntityType as T
from v3lum.core.http import PolicyError
from v3lum.core.models import Status
from v3lum.modules.brazil_public_data import br_parsers as P
from v3lum.modules.brazil_public_data.br_validators import BrValidators

VECTORS = module_fixture(BrValidators, "research_vectors.json")
RAW_CPF = "52998224725"
FMT_CPF = "529.982.247-25"


def _texts(res) -> str:
    """Everything the module produced (never the subject entity itself)."""
    findings = [{k: v for k, v in f.to_dict().items() if k != "entity"} for f in res.findings]
    return json.dumps(
        [res.attributes, findings, res.raw, res.error, [(p.entity.key, p.note) for p in res.pivots], res.links],
        default=str,
        ensure_ascii=False,
    )


# ------------------------------------------------------------------ metadata (cond 1)
def test_metadata_offline_open_default_and_red_safe():
    cls = BrValidators
    assert (cls.disclosure, cls.hosts, cls.provider, cls.sources) == ("none", (), "", ())
    assert cls.terms == "open" and cls.default_enabled is True and cls.opsec.label == "passive"
    assert cls.trust_tier == "n/a" and cls.shares_input is False and cls.max_tlp.value_str == "red"
    assert set(cls.accepts) == {T.CNPJ, T.CPF, T.PLATE_BR, T.TEXT, T.CEP, T.PIX}
    assert cls.category == "brazil_public_data"


def test_ctx_http_refuses_every_request():
    ctx = make_ctx(BrValidators, FakeHttp(), entity="cnpj:00000000000191")
    with pytest.raises(PolicyError):
        ctx.http.get("https://example.com/")


# ------------------------------------------------------------------ research vectors (cond 2, 9, 10)
def test_research_vectors_18_and_rfb_alphanumeric_example():
    v = VECTORS
    for value, expected in v["cpf_valid"]:
        assert P.cpf_valid(value) is expected, value
    for value, ufs in v["cpf_region"]:
        assert P.cpf_region(value)["ufs"] == ufs
    for value, expected in v["cnpj_valid"]:
        assert P.cnpj_valid(value) is expected, value
    for base, dv in v["cnpj_dv"]:
        assert P.cnpj_dv(base) == dv
    for plate, fmt, equiv in v["plates"]:
        info = P.plate_info(plate)
        assert info["format"] == fmt and info["mercosul" if fmt == "old" else "old"] == equiv, plate
    assert [P.pix_key_type(k) for k, _ in v["pix_key_type"]] == [t for _, t in v["pix_key_type"]]
    br = P.parse_brcode(v["brcode_manual"]["payload"])
    assert br["crc_ok"] and br["crc_found"] == "1D3D" and br["key"] == v["brcode_manual"]["key"]
    b = v["boleto_bancario"]
    p = P.parse_boleto(b["line"], today=b["today"])
    assert p["check_digits_ok"] and p["bank_code"] == "001" and p["amount_cents"] == 12345 and p["due"]["chosen"] == "2026-12-10"
    assert not P.parse_boleto(v["boleto_bancario_tampered"]["line"], today=b["today"])["general_dv_ok"]
    for factor, today, expected in v["due_factor"]:
        assert P.due_dates_from_factor(factor, today)["chosen"] == expected
    assert P.parse_boleto(v["arrecadacao_mod10"]["line"])["check_digits_ok"]
    assert P.parse_boleto(v["arrecadacao_mod11"]["line"])["general_dv_ok"]
    assert [P.cep_info(c)["uf_hint"] for c, _ in v["cep_uf"]] == [u for _, u in v["cep_uf"]]
    assert len(P.DDD_UF) == v["ddd_uf"]["count"] and P.DDD_UF[11] == "SP" and P.DDD_UF[99] == "MA"
    c = P.cnj_parse(v["cnj"]["number"])
    assert c["check_ok"] and c["datajud_alias"] == v["cnj"]["alias"]
    assert P.cnj_parse(v["cnj"]["trf1"])["datajud_alias"] == "api_publica_trf1"
    rfb = v["rfb_alnum_example"]
    info = P.cnpj_info(rfb["formatted"])
    assert info["valid"] and info["normalized"] == rfb["normalized"] and info["normalized"][12:] == rfb["dv"] and info["alphanumeric"]


def test_selftest_sample_agrees():
    s = module_fixture(BrValidators, "selftest_ok.json")
    assert P.cnpj_valid("00000000000191") is s["cnpj_numeric_bb_00000000000191"]
    assert P.cnpj_dv("12ABC34501DE") == s["cnpj_alnum_rfb_example_12ABC34501DE"]


def test_cnpj_alphanumeric_root_and_headquarters():
    info = P.cnpj_info("12.abc.345/01de-35")
    assert info["formatted"] == "12.ABC.345/01DE-35" and info["root"] == "12ABC345" and info["order"] == "01DE"
    assert not info["is_headquarters"] and info["wording"] == "check digits valid (format only)"
    hq = info["hq_cnpj"]
    assert hq.startswith("12ABC3450001") and P.cnpj_valid(hq) and P.cnpj_info(hq)["is_headquarters"]
    branch = "000000000002" + P.cnpj_dv("000000000002")
    assert P.cnpj_valid(branch) and P.cnpj_headquarters(branch) == "00000000000191"
    assert P.cnpj_headquarters("00000000") == "00000000000191" and P.cnpj_headquarters("123") is None
    for bad in ("12ABC34501DEAB", "11111111111111", None, "12ABC34501DE36"):
        assert not P.cnpj_valid(bad)
    for published in ("11791301000105", "31746200000111", "35116112000197", "42987643000110", "50147517000186", "52870614000128"):
        assert P.cnpj_valid(published)  # Brazilian Tax IDs published in the OFAC SDN list (2026-11-20)
    with pytest.raises(ValueError):
        P.cnpj_dv("12ABC")


def test_cpf_region_wording_is_issuance_never_residence():
    r = P.cpf_region(FMT_CPF)
    assert r["text"] == "CPF issued in fiscal region 7 (ES, RJ)" and r["info_only"] is True
    assert "resid" not in r["text"].lower()
    assert P.cpf_region("111.111.111-11") is None and P.cpf_region("123") is None


def test_one_masking_function_and_masking_cases():
    assert P.mask_cpf is mask_cpf  # the core AR24 function, never a second one
    for case in module_fixture(BrValidators, "masking_cases.json")["cases"]:
        assert getattr(P, case["fn"])(case["in"]) == case["out"], case


def test_other_personal_ids_are_masked_only_never_types_or_validators():
    # cond 6: never auto-detected entity types, never pivots; validators wait for official vectors
    for name in ("pis_valid", "titulo_valid", "renavam_valid", "cns_valid", "cnh_valid"):
        assert not hasattr(P, name)
    assert {t.value for t in BrValidators.accepts}.isdisjoint({"pis", "nis", "titulo", "renavam", "cns", "cnh"})
    assert P.mask_national_id("123.45678.90-0") == "***.45678.9*-*"
    assert all(e["type"] != "pis" for e in P.extract_br_entities("PIS 123.45678.90-0 CNS 898001234567891"))


def test_plates_cep_and_pix_key_types():
    assert P.plate_info("abc-1234")["search_forms"] == ["ABC1234", "ABC1C34"]
    assert P.plate_info("ABC1Z34")["search_forms"] == ["ABC1Z34"] and P.plate_info("AB12345") is None
    assert P.cep_info("01001-000") == {"valid": True, "normalized": "01001000", "formatted": "01001-000", "uf_hint": "SP",
                                       "wording": "format valid (existence not checked)"}
    assert not P.cep_info("00000-000")["valid"] and not P.cep_info("1234")["valid"]
    assert P.pix_key_type("+5520955550101") is None  # DDD 20 does not exist
    assert P.pix_key_type("+14155550101") is None and P.pix_key_type("not-an-email@") is None
    assert P.pix_key_type("12.ABC.345/01DE-35") == "cnpj" and P.pix_key_type(None) is None


# ------------------------------------------------------------------ typing gate (cond 7)
def _collision_lines():
    for line in module_fixture(BrValidators, "phone_cpf_collision.txt").splitlines():
        if line and not line.startswith("#"):
            label, text = line.split(" | ", 1)
            yield label, text


def test_phone_cpf_collision_fixture_never_types_phones_as_cpf():
    seen = set()
    for label, text in _collision_lines():
        seen.add(label)
        ents = P.extract_br_entities(text)
        types = [e["type"] for e in ents]
        if label == "PHONE":
            assert "cpf" not in types and "phone" in types, (text, ents)
        elif label == "CPF":
            cpfs = [e for e in ents if e["type"] == "cpf"]
            assert len(cpfs) == 1 and cpfs[0]["display"] == "***.982.247-**" and cpfs[0]["value"] == "***.982.247-**", (text, ents)
            assert cpfs[0]["expand"] is False
        else:
            assert "cpf" not in types and "phone" not in types, (text, ents)
        assert RAW_CPF not in json.dumps(ents)
    assert seen == {"PHONE", "CPF", "NONE"}
    masked = P.extract_br_entities("CPF ***.982.247-** (masked, never completed)")
    assert [e["type"] for e in masked] == ["masked_cpf"] and masked[0]["value"] == "***.982.247-**"


def test_typing_gate_direct():
    assert P.type_11_digit_candidate("zap 11955550166", 4, 15)["type"] == "phone"
    assert P.type_11_digit_candidate("CPF 11955550166", 4, 15)["type"] == "cpf"  # same digits, CPF context
    weak = P.type_11_digit_candidate("ref 11955550166", 4, 15)
    assert weak["type"] == "phone" and weak["confidence"] == 0.4
    assert P.type_11_digit_candidate("ref 52998224725", 4, 15)["type"] is None
    assert P.type_11_digit_candidate("12345", 0, 5)["reason"] == "not 11 digits"


def test_module_types_collision_lines_like_the_rule_set():
    http = FakeHttp()
    for label, text in _collision_lines():
        res = run_module(BrValidators, Entity.make(T.TEXT, text), http)
        listed = res.attributes.get("br_entities", [])
        types = {e["type"] for e in listed}
        if label == "PHONE":
            assert "cpf" not in types and any(p.entity.type is T.PHONE for p in res.pivots)
        if label == "CPF":
            assert "cpf" in types and not any(p.entity.type is T.CPF for p in res.pivots)
        assert RAW_CPF not in _texts(res)
    assert http.calls == []


# ------------------------------------------------------------------ zero network for CPF text (cond 3)
def test_cpf_text_makes_zero_network_requests(monkeypatch):
    calls = []

    def boom(*args, **kwargs):
        calls.append(args)
        raise AssertionError("network access attempted")

    monkeypatch.setattr(socket.socket, "connect", boom)
    monkeypatch.setattr(socket, "create_connection", boom)
    monkeypatch.setattr(socket, "getaddrinfo", boom)
    http = FakeHttp()
    res = run_module(BrValidators, Entity.make(T.TEXT, f"Cliente CPF {FMT_CPF}, chave pix {RAW_CPF}"), http)
    assert res.status is Status.OK
    assert {e["type"] for e in res.attributes["br_entities"]} == {"cpf", "pix_key"}
    assert http.calls == [] and calls == []
    assert res.pivots == [] and RAW_CPF not in _texts(res) and FMT_CPF not in _texts(res)
    cpf_seed = run_module(BrValidators, f"cpf:{FMT_CPF}", http)
    assert cpf_seed.status is Status.OK and http.calls == [] and calls == []


# ------------------------------------------------------------------ BR rule set (cond 8)
def _scam_blocks() -> dict[str, list[dict]]:
    text = module_fixture(BrValidators, "scam_messages.txt")
    blocks = {}
    for block in text.split("=== ")[1:]:
        title, body = block.split("\n", 1)
        blocks[title.split(" ")[1]] = body
    return blocks


def test_br_rule_set_on_scam_messages():
    blocks = {k: P.extract_br_entities(v) for k, v in _scam_blocks().items()}
    m1 = blocks["1"]
    assert [e["type"] for e in m1] == ["boleto", "phone", "phone"]
    assert m1[0]["checksum_ok"] and m1[0]["value"].startswith("341") and m1[0]["confidence"] == 0.95
    assert [e["value"] for e in m1[1:]] == ["+5511955550101", "+551155550102"]
    m2 = blocks["2"]
    assert [e["type"] for e in m2] == ["brcode", "pix_key"]
    assert m2[0]["checksum_ok"] and m2[1]["key_type"] == "email" and not m2[1]["expand"]
    m3 = blocks["3"]
    assert [e["type"] for e in m3] == ["cnj", "cnpj", "cpf", "boleto"]
    assert m3[0]["value"].endswith(".2025.8.26.0000") and m3[1]["value"] == "00000000000191"
    assert m3[2]["display"] == "***.982.247-**" and m3[2]["expand"] is False
    assert m3[3]["rule"] == "boleto_arrecadacao" and m3[3]["checksum_ok"]
    assert blocks["4"] == []
    assert [r[0] for r in P.BR_RULES][0] == "brcode_emv" and P.BR_PRIORITY[:3] == ("brcode", "boleto", "cnj")


def test_extractor_priority_brcode_masks_inner_numbers_and_cpf_keys():
    payload = module_fixture("boleto_pix", "brcode_dynamic.txt").strip()
    assert [e["type"] for e in P.extract_br_entities("pague: " + payload + " obrigado")] == ["brcode"]
    inner = P.build_brcode([("00", "01"), ("26", None), ("52", "0000"), ("53", "986"), ("58", "BR"), ("59", "LOJA 6304ABCD"), ("60", "SAO PAULO")],
                           [("00", "br.gov.bcb.pix"), ("01", "pix@example.com")])
    ents = P.extract_br_entities("codigo " + inner)
    assert len(ents) == 1 and ents[0]["checksum_ok"] and ents[0]["value"] == inner
    cpf_code = {c["id"]: c["payload"] for c in module_fixture("boleto_pix", "brcode_cases.json")["cases"]}["cpf_key"]
    cpf_ents = P.extract_br_entities("pix " + cpf_code)
    assert cpf_ents[0]["type"] == "brcode" and cpf_ents[0]["display"] == "PIX BR Code (CPF key masked)"
    assert RAW_CPF not in json.dumps(cpf_ents)


def test_module_on_scam_messages_pivots_without_expansion():
    http = FakeHttp()
    blocks = _scam_blocks()
    res = run_module(BrValidators, Entity.make(T.TEXT, blocks["3"]), http)
    assert res.status is Status.OK
    keys = {p.entity.key: p for p in res.pivots}
    assert "cnpj:00000000000191" in keys and keys["cnpj:00000000000191"].expand is False
    assert any(k.startswith("boleto:") for k in keys) and not any(k.startswith("cpf:") for k in keys)
    titles = [f.title for f in res.findings]
    assert titles == ["Brazilian identifiers found in text", "CPF in the text (masked, not pivoted)"]
    assert all(f.severity.label == "info" for f in res.findings)
    assert RAW_CPF not in _texts(res)
    res2 = run_module(BrValidators, Entity.make(T.TEXT, blocks["2"]), http)
    kinds = {p.entity.type for p in res2.pivots}
    assert kinds == {T.PIX_BRCODE, T.EMAIL} and all(p.expand is False for p in res2.pivots)
    empty = run_module(BrValidators, Entity.make(T.TEXT, blocks["4"]), http)
    assert empty.status is Status.EMPTY
    assert http.calls == []


# ------------------------------------------------------------------ module per input type (cond 2-4, 9)
def test_cnpj_branch_gets_structure_and_head_office_pivot():
    http = FakeHttp()
    res = run_module(BrValidators, "cnpj:12.ABC.345/01DE-35", http)
    assert res.status is Status.OK
    a = res.attributes
    assert a["valid"] is True and a["validity_note"] == "check digits valid (format only)"
    assert a["formatted_value"] == "12.ABC.345/01DE-35"
    assert a["cnpj_structure"]["root"] == "12ABC345" and a["cnpj_structure"]["alphanumeric"] is True
    (piv,) = res.pivots
    assert piv.relation == "headquarters" and piv.expand is False and piv.entity.value == a["cnpj_structure"]["hq_cnpj"]
    hq = run_module(BrValidators, "cnpj:00.000.000/0001-91", http)
    assert hq.attributes["cnpj_structure"]["is_headquarters"] is True and hq.pivots == []
    assert http.calls == []


def test_cpf_seed_is_masked_never_pivoted_and_region_is_info_only():
    res = run_module(BrValidators, f"cpf:{FMT_CPF}", FakeHttp())
    a = res.attributes
    assert a["masked_value"] == "***.982.247-**" and a["validity_note"] == "check digits valid (format only)"
    assert a["cpf_fiscal_region"] == "CPF issued in fiscal region 7 (ES, RJ)"
    assert res.pivots == [] and res.findings == []
    assert RAW_CPF not in _texts(res) and FMT_CPF not in _texts(res)


def test_plate_cep_and_evp_inputs():
    http = FakeHttp()
    plate = run_module(BrValidators, "plate_br:ABC1234", http)
    assert plate.attributes["plate_forms"]["search_forms"] == ["ABC1234", "ABC1C34"] and plate.pivots == []
    assert "never an owner lookup" in plate.attributes["validity_note"]
    cep = run_module(BrValidators, "cep:70040-912", http)
    assert cep.attributes["cep_uf_hint"] == "DF" and cep.attributes["validity_note"] == "format valid (existence not checked)"
    evp = run_module(BrValidators, "pix_key:123e4567-e12b-12d1-a456-426655440000", http)
    assert evp.attributes["pix_key_type"] == "evp" and "no DICT lookup" in evp.attributes["validity_note"]
    assert http.calls == []


# ------------------------------------------------------------------ masking in every renderer (cond 5, 10)
def _cpf_case():
    from v3lum.core.engine import Engine

    rt = make_runtime(FakeHttp())
    options = ScanOptions(include={"br_validators"}, purpose="masking test DD-0")
    case = Engine(rt, options).investigate([Entity.make(T.CPF, FMT_CPF)])
    return case.to_dict()


def _renders(case: dict) -> dict[str, str]:
    from v3lum.report import html, markdown, stix
    from v3lum.ui.render import render_case
    from v3lum.ui.theme import make_console

    console = make_console(width=200)
    console.record = True
    render_case(console, case, full=True)
    return {"terminal": console.export_text(), "html": html.render(case), "md": markdown.render(case),
            "json": json.dumps(case, ensure_ascii=False, default=str), "stix": json.dumps(stix.bundle(case), ensure_ascii=False)}


def test_module_facts_are_masked_in_every_renderer():
    case = _cpf_case()
    module_parts = json.dumps([[e.get("attributes") for e in case["entities"]], case["findings"]], default=str)
    assert "***.982.247-**" in module_parts and RAW_CPF not in module_parts and FMT_CPF not in module_parts
    assert all(e.get("display") == "***.982.247-**" for e in case["entities"] if e.get("type") == "cpf")
    outputs = _renders(case)
    for name in ("terminal", "html", "json"):
        assert "***.982.247-**" in outputs[name], name
    for name, text in outputs.items():
        assert FMT_CPF not in text, name  # the formatted CPF never appears anywhere


@pytest.mark.xfail(reason="core renderers still print the raw seed key (cpf:<11 digits>): terminal input line, Markdown seeds, STIX "
                          "report description and the JSON report (= the case dict: entity key/value, coverage, execution, answered); core "
                          "request of batch p1-G10-1 (AR24 / P232 cond 5)", strict=False)
def test_raw_cpf_never_appears_in_any_renderer():
    outputs = _renders(_cpf_case())
    leaks = [name for name, text in outputs.items() if RAW_CPF in text]
    assert leaks == []
