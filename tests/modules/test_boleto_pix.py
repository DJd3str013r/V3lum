"""boleto_pix (P233): offline boleto and PIX BR Code parsing with offline bank tables.

Fixtures in tests/fixtures/boleto_pix/ (prep batch p1-G10-1, recorded 2026-11-26):
``bcb_str_ok.csv`` (ParticipantesSTR.csv as served by www.bcb.gov.br, untruncated, 473 rows, UTF-8 BOM;
the same file is the bundled snapshot), ``brasilapi_banks_ok.json`` (all 473 banks, fields reduced to
ispb/name/code/fullName), ``brasilapi_pix_participants_ok.json`` (880 participants as served),
``brasilapi_banks_truncated.json`` (cut at 2,000 bytes), ``brasilapi_not_found.http.json`` (the live 404
of /api/banks/v1/9999, error shape only: the module never calls per value), ``bcb_str_html.html``
(synthetic maintenance page), ``brcode_bcb_manual.txt`` (the BCB manual vector, CRC 1D3D),
``brcode_tampered.txt`` (one merchant letter changed), ``brcode_dynamic.txt`` / ``brcode_cases.json`` and
``boleto_cases.json`` (synthetic codes built with the parsers and cross-checked against the research
prototype: pix.example.com, pix@example.com, +5511955550101, documentation CPF/CNPJ vectors).
"""

from __future__ import annotations

import datetime as dt
import json
import os

import pytest

from tests.fakes import FakeClock, FakeHttp, make_ctx, make_runtime, module_fixture, run_module
from v3lum import paths
from v3lum.core.datasets import DATASETS, DatasetError
from v3lum.core.entities import Entity
from v3lum.core.entities import EntityType as T
from v3lum.core.http import PolicyError
from v3lum.core.models import Status
from v3lum.core.orgprofile import OrgProfile
from v3lum.modules.brazil_public_data import boleto_pix as mod
from v3lum.modules.brazil_public_data import br_parsers as P
from v3lum.modules.brazil_public_data.boleto_pix import BoletoPix

TODAY = dt.date(2026, 11, 26)
CASES = module_fixture(BoletoPix, "boleto_cases.json")
LINES = {c["id"]: c["line"] for c in CASES["cases"]}
BRCODES = {c["id"]: c["payload"] for c in module_fixture(BoletoPix, "brcode_cases.json")["cases"]}


def fx_bytes(name: str) -> bytes:
    from tests.fakes import FIXTURES

    return (FIXTURES / "boleto_pix" / name).read_bytes()


@pytest.fixture(scope="module")
def bank_index():
    str_rows = P.parse_bcb_str_csv(fx_bytes("bcb_str_ok.csv"))["entries"]
    banks = P.parse_brasilapi_banks(fx_bytes("brasilapi_banks_ok.json"))["entries"]
    pix = P.parse_brasilapi_pix_participants(fx_bytes("brasilapi_pix_participants_ok.json"))["entries"]
    return P.build_bank_index(str_rows, banks, pix)


@pytest.fixture(autouse=True)
def fresh_memo():
    mod._MEMO.clear()
    yield
    mod._MEMO.clear()


#: installed copies carry a fixed fetch time (file mtime, no MANIFEST entry) so ages never follow the wall clock
FETCHED_AT = dt.datetime(2026, 11, 26, 6, 0, tzinfo=dt.timezone.utc).timestamp()


def install(name: str, content: bytes) -> None:
    path = paths.datasets_dir() / name
    path.write_bytes(content)
    os.utime(path, (FETCHED_AT, FETCHED_AT))


def _texts(res) -> str:
    findings = [{k: v for k, v in f.to_dict().items() if k != "entity"} for f in res.findings]
    return json.dumps([res.attributes, findings, res.raw, res.error, [(p.entity.key, p.note) for p in res.pivots]], default=str, ensure_ascii=False)


# ------------------------------------------------------------------ metadata (cond 9)
def test_metadata_offline_datasets_only():
    cls = BoletoPix
    assert (cls.disclosure, cls.hosts, cls.provider) == ("none", (), "")
    assert cls.sources == ("bcb.str_participants", "brasilapi.banks") and cls.terms == "open"
    assert cls.default_enabled is True and cls.trust_tier == "n/a" and cls.max_tlp.value_str == "red"
    assert T.URL not in cls.produces  # cond 5: the dynamic location URL is never a url entity
    for name, url, src in ((mod.DS_STR, mod.STR_URL, "bcb.str_participants"), (mod.DS_BANKS, mod.BANKS_URL, "brasilapi.banks"),
                           (mod.DS_PIX, mod.PIX_URL, "brasilapi.banks")):
        reg = DATASETS[name]
        assert reg["url"] == url and reg["source"] == src and reg["ttl"] == 7 * 86400 and reg["terms_class"] == "open"
        assert callable(reg["validate"]) and reg["licence"]
    ctx = make_ctx(BoletoPix, FakeHttp(), entity="boleto:" + LINES["bancario_ok_new_cycle"])
    with pytest.raises(PolicyError):
        ctx.http.get(mod.BANKS_URL + "/341")  # never per-value API calls


# ------------------------------------------------------------------ boleto parsing (cond 1, 2, 7, 8)
def test_boleto_cases(bank_index):
    for case in CASES["cases"]:
        p = P.parse_boleto(case["line"], today=CASES["today"])
        if case.get("ok") is False:
            assert not p["ok"] and p["error"].startswith("not a boleto"), case["id"]
            continue
        assert p["ok"], case["id"]
        for key in ("bank_code", "amount_cents", "segment", "cnpj_root", "check_digits_ok", "due_factor"):
            if key in case:
                assert p[key] == case[key], (case["id"], key, p.get(key))
        if "due_chosen" in case:
            assert p["due"]["chosen"] == case["due_chosen"] and p["due"]["cycle"] == case["cycle"], case["id"]
        if "ambiguous" in case:
            assert p["due"]["ambiguous"] is case["ambiguous"], case["id"]
    ok = P.parse_boleto(LINES["bancario_ok_new_cycle"], today=CASES["today"])
    assert ok["input_kind"] == "linha_digitavel" and ok["fields_dv_ok"] and ok["currency_ok"]
    assert P.boleto_verdict_line(ok, bank_index=bank_index) == "Boleto: check digits OK - bank 341 (ITAÚ UNIBANCO S.A.), due 2026-12-01, R$ 1.234,56"
    bar = P.parse_boleto(LINES["barcode_44"], today=CASES["today"])
    assert bar["input_kind"] == "barcode" and bar["fields_dv_ok"] is None and bar["check_digits_ok"]
    amb = P.parse_boleto(LINES["bancario_ambiguous_factor"], today=CASES["today"])
    line = P.boleto_verdict_line(amb, bank_index=bank_index)
    assert "due date ambiguous" in line and amb["due"]["old_cycle"] in line and amb["due"]["new_cycle"] in line
    nodue = P.parse_boleto(LINES["bancario_no_due_no_amount"], today=CASES["today"])
    assert P.boleto_verdict_line(nodue, bank_index=bank_index) == "Boleto: check digits OK - bank 104 (CAIXA ECONOMICA FEDERAL), no due date, amount not set"
    tampered = P.parse_boleto(LINES["bancario_tampered_value"], today=CASES["today"])
    assert not tampered["general_dv_ok"] and tampered["fields_dv_ok"]
    assert P.boleto_verdict_line(tampered) == "Boleto: CHECK DIGIT MISMATCH - invalid or altered code (typed or altered line)"
    assert P.boleto_verdict_line(tampered, origin="ocr") == P.boleto_verdict_line(tampered, origin="qr") == "Boleto: could not verify (OCR)"
    assert P.parse_boleto(LINES["bancario_typo_field1"], today=CASES["today"])["field_dvs"][0] is False
    arr = P.parse_boleto(LINES["arrecadacao_mod11_cnpj"])
    assert arr["dv_method"] == "mod11" and arr["company_id"] == "00000000"
    assert P.boleto_verdict_line(P.parse_boleto(LINES["arrecadacao_mod10_energy"])).startswith(
        "Boleto (arrecadacao): check digits OK - segment 3 (energia eletrica e gas), R$ 98,76")
    assert not P.parse_boleto(LINES["arrecadacao_tampered"])["check_digits_ok"]
    assert P.boleto_verdict_line(P.parse_boleto("123")).startswith("Boleto: not a boleto line")


def test_due_date_cycles_both_shown_when_ambiguous():
    d = P.due_dates_from_factor(1647, TODAY)
    assert (d["chosen"], d["cycle"], d["ambiguous"]) == ("2026-12-01", "new", False) and d["old_cycle"] == "2002-04-11"
    old = P.due_dates_from_factor(9743, dt.date(2024, 6, 1))
    assert old["cycle"] == "old" and old["chosen"] == "2024-06-10" and old["new_cycle"] == "2049-01-30"
    assert P.due_dates_from_factor(9999, TODAY)["chosen"] == "2025-02-21"
    assert P.due_dates_from_factor(1000, TODAY)["chosen"] == "2025-02-22"
    amb = P.due_dates_from_factor(5000, TODAY)
    assert amb["ambiguous"] and (amb["old_cycle"], amb["new_cycle"]) == ("2011-06-16", "2036-02-05")
    assert P.due_dates_from_factor(0, TODAY)["chosen"] is None
    assert P.due_dates_from_factor(999, TODAY)["new_cycle"] is None  # never a negative new-cycle offset
    assert P.due_dates_from_factor("x", TODAY)["factor"] is None


def test_boleto_bank_mismatch_helper(bank_index):
    for item in CASES["claimed_bank_texts"]:
        parsed = P.parse_boleto(LINES[item["line_id"]], today=CASES["today"])
        res = P.boleto_bank_mismatch(parsed, item["text"], bank_index=bank_index)
        if item["mismatch"]:
            assert res["severity"] == "high" and res["confidence"] == "probable" and res["malicious"] is False
            assert res["title"] == "boleto bank mismatch: possible tampering" and res["barcode_bank"] == "341" and res["claimed_banks"] == ["001"]
        else:
            assert res is None


def test_format_brl():
    assert P.format_brl(123456) == "R$ 1.234,56" and P.format_brl(5) == "R$ 0,05"
    assert P.format_brl(123456789012) == "R$ 1.234.567.890,12" and P.format_brl("x") == "R$ ?"


# ------------------------------------------------------------------ BR Code (cond 3, 4, 5, 7, 8)
def test_crc_and_bcb_manual_vector():
    assert P.crc16_ccitt_false(b"123456789") == 0x29B1
    manual = P.parse_brcode(module_fixture(BoletoPix, "brcode_bcb_manual.txt"))
    assert manual["ok"] and manual["crc_ok"] and manual["crc_found"] == "1D3D" and manual["key_type"] == "evp" and manual["txid"] == "***"
    assert P.brcode_verdict_line(manual) == ("PIX: merchant Fulano de Tal, city BRASILIA, key evp (123e4567-e12b-12d1-a456-426655440000), "
                                             "txid ***, amount not set, CRC OK")
    t = P.parse_brcode(module_fixture(BoletoPix, "brcode_tampered.txt"))
    assert t["ok"] and t["crc_ok"] is False and t["status_text"] == "altered or corrupted payload"
    assert P.brcode_verdict_line(t).endswith("CRC MISMATCH: altered or corrupted payload")
    tq = P.parse_brcode(module_fixture(BoletoPix, "brcode_tampered.txt"), origin="qr")
    assert tq["status_text"] == "could not verify (OCR)" and P.brcode_verdict_line(tq).endswith("could not verify (OCR)")


def test_dynamic_location_is_a_host_pivot_never_a_url():
    d = P.parse_brcode(module_fixture(BoletoPix, "brcode_dynamic.txt").strip())
    assert d["ok"] and d["crc_ok"] and d["dynamic"] and d["point_of_initiation"] == "12" and d["key"] is None
    assert (d["location_host"], d["location_host_defanged"], d["location_masked"]) == ("pix.example.com", "pix[.]example[.]com", "pix.example.com/***")
    ents = P.brcode_entities(d)
    assert [(p["type"], p["value"], p["relation"], p["expand"]) for p in ents["pivots"] if p["type"] == "domain"] == [
        ("domain", "pix.example.com", "pix_location_host", False)]
    assert not any(p["type"] == "url" for p in ents["pivots"]) and "9d36b84f" not in json.dumps(ents)
    assert ents["attributes"]["pix_location_url"] == "pix.example.com/***"


def test_brcode_keys_bounds_and_cpf_masking():
    email = P.parse_brcode(BRCODES["email_key"])
    assert email["crc_ok"] and email["key_type"] == "email" and email["txid"] == "PEDIDO123"
    pivots = P.brcode_entities(email)["pivots"]
    assert {(p["type"], p["value"], p["relation"], p["expand"]) for p in pivots} == {
        ("email", "pix@example.com", "pix_key_of", False), ("company_name", "LOJA EXEMPLO LTDA", "pix_merchant", False)}
    phone = P.brcode_entities(P.parse_brcode(BRCODES["phone_key"]))
    assert [(p["type"], p["value"], p["expand"]) for p in phone["pivots"]] == [("phone", "+5511955550101", False)]  # natural person: no name pivot
    cnpj = P.brcode_entities(P.parse_brcode(BRCODES["cnpj_key"]))
    assert any(p["type"] == "cnpj" and p["value"] == "00000000000191" and p["expand"] for p in cnpj["pivots"])
    cpf = P.parse_brcode(BRCODES["cpf_key"])
    assert cpf["key_type"] == "cpf" and cpf["key_display"] == "***.982.247-**"
    cpf_ents = P.brcode_entities(cpf)
    assert cpf_ents["pivots"] == [] and cpf_ents["attributes"]["pix_key"] == "***.982.247-**"
    assert "52998224725" not in P.brcode_verdict_line(cpf) and "52998224725" not in json.dumps(cpf_ents)
    assert P.parse_brcode(BRCODES["other_gui"])["error"].startswith("not a PIX BR Code")
    nested = P.parse_brcode(BRCODES["nested_unreserved"])
    assert nested["ok"] and nested["crc_ok"] and nested["key"] == "pix@example.com"
    assert P.parse_brcode(BRCODES["malformed_length"])["error"].startswith("malformed BR Code")
    assert P.parse_brcode(BRCODES["oversize"])["error"] == "not a BR Code: payload larger than 512 bytes"
    assert P.parse_brcode(None)["error"].startswith("not a BR Code") and P.parse_brcode("hello")["error"].startswith("not a BR Code")
    with pytest.raises(ValueError):
        P.parse_emv_tlv("2604" + "0004ab", depth=3)


def test_payee_brand_mismatch_helper():
    cnpj = P.parse_brcode(BRCODES["cnpj_key"])
    assert P.payee_brand_mismatch(cnpj, claimed_brand="Banco do Brasil", brand_cnpj_roots=["00000000"]) is None
    assert P.payee_brand_mismatch(cnpj, claimed_brand="Banco do Brasil") is None  # merchant name matches
    res = P.payee_brand_mismatch(cnpj, claimed_brand="Nubank", brand_keywords=["nubank", "nu pagamentos"], brand_cnpj_roots=["18236120"])
    assert res["severity"] == "medium" and res["title"] == "payee differs from claimed brand" and res["malicious"] is False
    assert P.payee_brand_mismatch(P.parse_brcode(BRCODES["phone_key"]), claimed_brand="Loja Exemplo")["severity"] == "medium"


# ------------------------------------------------------------------ bank tables (cond 9)
def test_bcb_str_table():
    t = P.parse_bcb_str_csv(fx_bytes("bcb_str_ok.csv"))
    assert t["ok"] and t["bom"] and t["rows"] == 473 and t["bad_rows"] == 0
    by = {e["ispb"]: e for e in t["entries"]}
    assert by["00000000"] == {"ispb": "00000000", "short_name": "BCO DO BRASIL S.A.", "code": "001", "compe": True, "access": "RSFN",
                              "full_name": "Banco do Brasil S.A.", "start_date": "2002-04-22"}
    assert by["00038166"]["code"] is None and by["28719664"]["code"] is None  # 'n/a' and '0'
    assert P.validate_table(t, min_rows=P.STR_MIN_ROWS, what="STR participants") is None
    assert P.parse_bcb_str_csv(fx_bytes("bcb_str_html.html"))["error"] == "error: HTML page instead of ParticipantesSTR.csv"
    assert P.parse_bcb_str_csv(b"")["error"].startswith("empty:")
    assert P.parse_bcb_str_csv(b"a,b\n1,2\n")["error"].startswith("malformed: STR CSV header lacks")


def test_brasilapi_tables_and_error_bodies():
    banks = P.parse_brasilapi_banks(fx_bytes("brasilapi_banks_ok.json"))
    assert banks["ok"] and len(banks["entries"]) == 473
    code_map = {e["code"]: e["name"] for e in banks["entries"] if e["code"]}
    assert code_map["001"] == "BCO DO BRASIL S.A." and code_map["260"] == "NU PAGAMENTOS - IP"
    pix = P.parse_brasilapi_pix_participants(fx_bytes("brasilapi_pix_participants_ok.json"))
    assert pix["ok"] and len(pix["entries"]) == 880
    assert P.validate_table(pix, min_rows=P.PIX_PARTICIPANTS_MIN_ROWS, what="PIX participants") is None
    trunc = P.parse_brasilapi_banks(fx_bytes("brasilapi_banks_truncated.json"))
    assert trunc["error"] == "malformed: truncated or invalid BrasilAPI banks JSON"
    nf = module_fixture(BoletoPix, "brasilapi_not_found.http.json")
    assert P.parse_brasilapi_banks(nf["body"])["error"] == "error: BrasilAPI BANK_CODE_NOT_FOUND instead of the BrasilAPI banks list"
    assert P.parse_brasilapi_banks(b"<!DOCTYPE html><html></html>")["error"].startswith("error: HTML page")


def test_bank_index_and_aliases(bank_index):
    assert P.bank_name("341", bank_index) == "ITAÚ UNIBANCO S.A." and P.bank_name(1, bank_index) == "BCO DO BRASIL S.A."
    assert P.bank_name("999", bank_index) is None and P.bank_name("0", bank_index) is None
    assert bank_index["by_ispb"]["00000000"]["source"] == "bcb_str"
    assert bank_index["by_ispb"]["35534511"]["source"] == "brasilapi_pix" and bank_index["by_ispb"]["35534511"]["pix_participant"] is True
    for alias, code in P.BANK_ALIASES.items():
        assert code in bank_index["by_code"], alias
    assert P.detect_bank_mentions("Pague no Itaú ou no BANCO DO BRASIL") == ["001", "341"]
    assert P.detect_bank_mentions("caixa de papelao") == []
    assert mod.claimed_bank_codes("Banco 237-2 | Ficha de compensação", bank_index) == ["237"]
    assert mod.claimed_bank_codes("Pedido 237-5 de 12 itens", bank_index) == []  # wrong bank-code check digit


# ------------------------------------------------------------------ dataset downloads (cond 9, rule 5)
def test_str_download_is_validated_before_it_replaces_the_copy():
    http = FakeHttp().add("GET", mod.STR_URL, body=fx_bytes("bcb_str_ok.csv"), headers={"content-type": "application/octet-stream"})
    rt = make_runtime(http)
    assert rt.data.update(mod.DS_STR).status == "updated"
    good = (paths.datasets_dir() / mod.DS_STR).read_bytes()
    http2 = FakeHttp().add("GET", mod.STR_URL, body=fx_bytes("bcb_str_html.html"), headers={"content-type": "text/html"})
    result = make_runtime(http2).data.update(mod.DS_STR)
    assert result.status == "failed" and (paths.datasets_dir() / mod.DS_STR).read_bytes() == good  # previous copy kept
    short = b"\xef\xbb\xbfISPB,Nome_Reduzido,N\xc3\xbamero_C\xc3\xb3digo,Participa_da_Compe,Acesso_Principal,Nome_Extenso,In\xc3\xadcio_da_Opera\xc3\xa7\xc3\xa3o\n" + b"x" * 20000
    http3 = FakeHttp().add("GET", mod.STR_URL, body=short)
    assert make_runtime(http3).data.update(mod.DS_STR).status == "failed"


@pytest.mark.parametrize(
    ("status", "body", "code"),
    [
        (429, "slow down", "rate_limited"),
        (403, "<html><head><title>Vercel Security Checkpoint</title></head><body>vercel</body></html>", "challenge"),
        (503, "Service Unavailable", "error"),
    ],
)
def test_brasilapi_refusals_never_replace_or_create_a_table(status, body, code):
    http = FakeHttp().add("GET", mod.BANKS_URL, status=status, text=body)
    rt = make_runtime(http)
    with pytest.raises(DatasetError) as exc:
        rt.data.fetch(mod.DS_BANKS, ttl=0)
    assert exc.value.reason_code == code
    assert not (paths.datasets_dir() / mod.DS_BANKS).exists()


def test_brasilapi_truncated_json_is_rejected():
    http = FakeHttp().add("GET", mod.BANKS_URL, body=fx_bytes("brasilapi_banks_truncated.json"), headers={"content-type": "application/json"})
    assert make_runtime(http).data.update(mod.DS_BANKS).status == "failed"
    http2 = FakeHttp().add("GET", mod.PIX_URL, body=fx_bytes("brasilapi_pix_participants_ok.json"), headers={"content-type": "application/json"})
    assert make_runtime(http2).data.update(mod.DS_PIX).status == "updated"


# ------------------------------------------------------------------ the module (cond 1-9)
def test_boleto_input_uses_the_bundled_snapshot_offline():
    http = FakeHttp()
    res = run_module(BoletoPix, "boleto:" + LINES["bancario_ok_new_cycle"], http)
    assert res.status is Status.OK and res.findings == []
    assert res.attributes["boleto_verdict"] == "Boleto: check digits OK - bank 341 (ITAÚ UNIBANCO S.A.), due 2026-12-01, R$ 1.234,56"
    facts = res.attributes["boleto_facts"]
    assert facts["bank_ispb"] == "60701190" and facts["bank_source"] == "bcb_str" and facts["due"]["cycle"] == "new"
    tables = {t["table"]: t for t in res.attributes["bank_tables"]}
    assert tables["BCB STR participants"]["source"] == "bundled snapshot" and tables["BCB STR participants"]["refreshed"] == mod.BUNDLED_STR_DATE
    assert tables["BrasilAPI banks"]["source"] == "not downloaded"
    assert any(d["name"] == mod.BUNDLED_STR for d in res.datasets)
    assert http.calls == []


def test_tampered_boleto_reads_check_digit_mismatch_or_ocr():
    res = run_module(BoletoPix, "boleto:" + LINES["bancario_tampered_value"], FakeHttp())
    assert res.attributes["boleto_verdict"] == "Boleto: CHECK DIGIT MISMATCH - invalid or altered code (typed or altered line)"
    (f,) = res.findings
    assert f.title == "Boleto check digit mismatch: invalid or altered code" and f.severity.label == "low"
    assert "tampering_suspected" in f.tags and "malicious" not in f.tags and f.criterion
    ocr = run_module(BoletoPix, "boleto:" + LINES["bancario_tampered_value"], FakeHttp(), is_seed=False, depth=1,
                     provenance=[("file:/tmp/boleto.png", "ocr_text", "image_ocr")])
    assert ocr.attributes["boleto_verdict"] == "Boleto: could not verify (OCR)"
    assert [g.severity.label for g in ocr.findings] == ["info"] and ocr.findings[0].title.endswith("(OCR)")


def test_brcode_input_pivots_follow_the_key_rules():
    http = FakeHttp()
    res = run_module(BoletoPix, "pix_brcode:" + BRCODES["email_key"], http)
    assert res.attributes["pix_verdict"].startswith("PIX: merchant LOJA EXEMPLO LTDA, city SAO PAULO, key email (pix@example.com)")
    assert res.attributes["pix_crc_status"] == "CRC OK" and res.attributes["pix_amount"] == "R$ 10,00"
    piv = {(p.entity.key, p.relation, p.expand) for p in res.pivots}
    assert piv == {("email:pix@example.com", "pix_key_of", False), ("company_name:LOJA EXEMPLO LTDA", "pix_merchant", False)}
    cnpj = run_module(BoletoPix, "pix_brcode:" + BRCODES["cnpj_key"], http)
    assert ("cnpj:00000000000191", "pix_key_of", True) in {(p.entity.key, p.relation, p.expand) for p in cnpj.pivots}
    dyn = run_module(BoletoPix, "pix_brcode:" + module_fixture(BoletoPix, "brcode_dynamic.txt").strip(), http)
    assert {(p.entity.key, p.relation, p.expand) for p in dyn.pivots} >= {("domain:pix.example.com", "pix_location_host", False)}
    assert not any(p.entity.type is T.URL for p in dyn.pivots) and dyn.attributes["pix_location_url"] == "pix.example.com/***"
    cpf = run_module(BoletoPix, "pix_brcode:" + BRCODES["cpf_key"], http)
    assert cpf.pivots == [] and cpf.attributes["pix_key"] == "***.982.247-**" and "52998224725" not in _texts(cpf)
    assert http.calls == []  # the dynamic location URL is never fetched


def test_text_with_tampered_brcode_and_claimed_bank_mismatch():
    http = FakeHttp()
    tampered = run_module(BoletoPix, Entity.make(T.TEXT, "Pix copia e cola: " + module_fixture(BoletoPix, "brcode_tampered.txt").strip()), http)
    (f,) = tampered.findings
    assert f.title == "PIX BR Code CRC mismatch: altered or corrupted payload" and f.severity.label == "medium"
    assert tampered.attributes["pix_crc_status"] == ["altered or corrupted payload"]
    text = "BANCO DO BRASIL S.A. - Pagavel em qualquer banco ate o vencimento. Linha digitavel: " + LINES["bancario_ok_new_cycle"]
    res = run_module(BoletoPix, Entity.make(T.TEXT, text), http)
    (mismatch,) = res.findings
    assert mismatch.title == "Boleto bank mismatch: possible tampering" and mismatch.severity.label == "high"
    assert mismatch.confidence_label.value == "probable" and mismatch.data["claimed_banks"] == ["001"]
    assert "malicious" not in mismatch.tags and "tampering_suspected" in mismatch.tags
    same = run_module(BoletoPix, Entity.make(T.TEXT, "Itaú Unibanco - Ficha de compensação " + LINES["bancario_ok_new_cycle"]), http)
    assert same.findings == []
    assert http.calls == []


def test_payee_mismatch_against_org_brand_and_bank_names():
    org = OrgProfile.from_dict({"org": {"name": "Exemplo"}, "brands": [{"keyword": "Lojaexemplar"}], "cnpj_roots": ["12345678"]})
    text = "Lojaexemplar: pague sua fatura com o Pix " + BRCODES["phone_key"]
    res = run_module(BoletoPix, Entity.make(T.TEXT, text), FakeHttp(), org_profile=org)
    (f,) = res.findings
    assert f.title == "PIX payee differs from claimed brand" and f.severity.label == "medium" and f.data["claimed_brands"] == ["Lojaexemplar"]
    bank = run_module(BoletoPix, Entity.make(T.TEXT, "Fatura Nubank: pague via Pix " + BRCODES["cnpj_key"]), FakeHttp())
    assert [g.title for g in bank.findings] == ["PIX payee differs from claimed brand"]
    ok = run_module(BoletoPix, Entity.make(T.TEXT, "Banco do Brasil: pague via Pix " + BRCODES["cnpj_key"]), FakeHttp())
    assert ok.findings == []


def _p360_install() -> None:
    """P360's DominiosVerificados copy (batch p1-G10-3 fixture: BB own domain + the member BB-BI, root 24933830)."""
    from tests.fakes import FIXTURES

    install(mod._p360.DOMINIOS.dataset, (FIXTURES / "bcb_authorized_institutions" / "dominios_ok.json").read_bytes())


def _brcode_cnpj_key(merchant: str, cnpj14: str) -> str:
    return P.build_brcode([("00", "01"), ("26", None), ("52", "0000"), ("53", "986"), ("58", "BR"), ("59", merchant), ("60", "BRASILIA"),
                           ("62", [("05", "***")])], [("00", "br.gov.bcb.pix"), ("01", cnpj14)])


def test_p360_conglomerate_roots_belong_to_the_claimed_bank():
    member = "249338300001" + P.cnpj_dv("249338300001")  # BB-BANCO DE INVESTIMENTO S/A, a BB conglomerate member
    text = "Banco do Brasil: pague via Pix " + _brcode_cnpj_key("BB BANCO DE INVESTIMENTO", member)
    without = run_module(BoletoPix, Entity.make(T.TEXT, text), FakeHttp())
    assert [f.title for f in without.findings] == ["PIX payee differs from claimed brand"]  # only the STR root 00000000 is known
    _p360_install()
    mod._MEMO.clear()
    res = run_module(BoletoPix, Entity.make(T.TEXT, text), FakeHttp())
    assert res.findings == [] and mod._p360.DOMINIOS.dataset in {d["name"] for d in res.datasets}  # the P360 copy is cited
    brands = mod.claimed_brands("Banco do Brasil", make_ctx(BoletoPix, FakeHttp(), entity="text_blob:x"), mod.load_bank_index(
        make_ctx(BoletoPix, FakeHttp(), entity="text_blob:x"))[0])
    assert brands[0]["source"] == "bank" and {"00000000", "24933830"} <= set(brands[0]["roots"]) and brands[0]["bcb_verified_domains"] == ["bb.com.br"]


def test_p360_verified_domain_in_the_text_is_a_claim():
    text = "Atendimento oficial www.bb.com.br - quite o debito via Pix " + BRCODES["email_key"]
    assert run_module(BoletoPix, Entity.make(T.TEXT, text), FakeHttp()).findings == []  # P360 not installed: no claim
    _p360_install()
    res = run_module(BoletoPix, Entity.make(T.TEXT, text), FakeHttp())
    (f,) = res.findings
    assert f.title == "PIX payee differs from claimed brand" and f.data["claimed_brands"] == ["BANCO DO BRASIL S.A."]
    assert f.severity.label == "medium" and "malicious" not in f.tags
    for other in ("bb.com.br.evil.example", "fakebb.com.br", "contato@example.com"):
        lookalike = run_module(BoletoPix, Entity.make(T.TEXT, f"Acesse {other} e pague via Pix " + BRCODES["email_key"]), FakeHttp())
        assert lookalike.findings == [], other
    paid_to_bb = run_module(BoletoPix, Entity.make(T.TEXT, "Acesse bb.com.br e pague via Pix " + BRCODES["cnpj_key"]), FakeHttp())
    assert paid_to_bb.findings == []  # the key CNPJ root 00000000 belongs to the institution of bb.com.br


def test_labelled_keys_without_code_and_empty_text():
    res = run_module(BoletoPix, Entity.make(T.TEXT, "chave pix: pix@example.com"), FakeHttp())
    assert [(p.entity.key, p.relation, p.expand) for p in res.pivots] == [("email:pix@example.com", "pix_key_of", False)]
    cpf_key = run_module(BoletoPix, Entity.make(T.TEXT, "chave pix 52998224725"), FakeHttp())
    assert cpf_key.status is Status.EMPTY and cpf_key.pivots == []
    assert run_module(BoletoPix, Entity.make(T.TEXT, "nothing to see"), FakeHttp()).status is Status.EMPTY


def test_local_tables_are_used_with_their_refresh_dates():
    install(mod.DS_STR, fx_bytes("bcb_str_ok.csv"))
    install(mod.DS_BANKS, fx_bytes("brasilapi_banks_ok.json"))
    install(mod.DS_PIX, fx_bytes("brasilapi_pix_participants_ok.json"))
    res = run_module(BoletoPix, "boleto:" + LINES["bancario_ok_new_cycle"], FakeHttp())
    tables = {t["table"]: t for t in res.attributes["bank_tables"]}
    assert {t["source"] for t in tables.values()} == {"dataset"} and not any(t["stale"] for t in tables.values())
    old = run_module(BoletoPix, "boleto:" + LINES["bancario_ok_new_cycle"], FakeHttp(), clock=FakeClock("2027-01-10T12:00:00Z"))
    assert all(t["stale"] for t in old.attributes["bank_tables"])
    install(mod.DS_STR, fx_bytes("bcb_str_html.html"))  # a broken local copy: the bundled snapshot still answers
    res2 = run_module(BoletoPix, "boleto:" + LINES["bancario_ok_new_cycle"], FakeHttp())
    sources = [t["source"] for t in res2.attributes["bank_tables"] if t["table"] == "BCB STR participants"]
    assert sources == ["dataset", "bundled snapshot"] and "ITAÚ" in res2.attributes["boleto_verdict"]


def test_file_input_reads_text_files_only(tmp_path):
    good = tmp_path / "boleto.txt"
    good.write_text("Linha digitavel " + LINES["bancario_ok_new_cycle"], encoding="utf-8")
    res = run_module(BoletoPix, Entity.make(T.FILE, str(good)), FakeHttp())
    assert res.status is Status.OK and res.attributes["boleto_verdict"][0].startswith("Boleto: check digits OK - bank 341")
    image = tmp_path / "boleto.png"
    image.write_bytes(b"\x89PNG\r\n\x1a\n")
    skipped = run_module(BoletoPix, Entity.make(T.FILE, str(image)), FakeHttp())
    assert skipped.status is Status.SKIPPED and skipped.reason_code == "not_applicable"


def test_evp_key_input():
    res = run_module(BoletoPix, "pix_key:123e4567-e12b-12d1-a456-426655440000", FakeHttp())
    assert res.attributes["pix_key_type"] == "evp" and res.pivots == []
