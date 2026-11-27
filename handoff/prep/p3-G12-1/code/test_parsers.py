"""Tests for parsers.py (batch p3-G12-1). Fixtures are loaded by path from ../fixtures.

Run: cd code && python3 -m pytest -q -p no:cacheprovider .
No network: every test works on stored fixtures; Pillow is only needed by the two optional
image_ela end-to-end tests (skipped when it is missing).
"""
import json
import re
from pathlib import Path

import pytest

import parsers as p

FIX = Path(__file__).parent.parent / "fixtures"
RAW = Path(__file__).parent.parent / "raw" / "live"
MODULES = ("geocoding", "image_ela", "document_identity_signals", "user_agent_analysis", "card_bin", "imei_check")
FULL_CPF_RE = re.compile(r"(?<![\d*])\d{3}\.?\d{3}\.?\d{3}-?\d{2}(?!\d)")


def raw(name):
    return (FIX / name).read_bytes()


def text(name):
    return (FIX / name).read_text(encoding="utf-8")


def load(name):
    """(status, headers, body) for an envelope fixture, a JSON body or a raw text body."""
    data = raw(name)
    if name.endswith(".json"):
        obj = json.loads(data)
        if isinstance(obj, dict) and obj.get("_envelope") == 1:
            return obj["status"], obj.get("headers", {}), obj["body"]
        return 200, {}, obj
    return 200, {}, data


def body_bytes(body):
    """Envelope bodies as the module would receive them from HTTP (bytes)."""
    if isinstance(body, (dict, list)):
        return json.dumps(body).encode()
    return body.encode() if isinstance(body, str) else body


# =============================================================== fixtures hygiene

def test_manifest_lists_every_fixture_and_names_follow_convention():
    man = json.loads(text("MANIFEST.json"))
    listed = {e["file"] for e in man["fixtures"]}
    on_disk = {f.name for f in FIX.iterdir() if f.name != "MANIFEST.json"}
    assert listed == on_disk
    for e in man["fixtures"]:
        module, case = e["file"].split("__", 1)
        assert module in MODULES and module == e["module"]
        assert e["provenance"] in ("live", "research", "synthetic")
        assert case


def test_fixtures_carry_no_secrets_or_personal_contacts():
    secret_re = re.compile(r"(?i)set-cookie|authorization|x-api-key|[?&](?:token|key|apikey)=")
    email_re = re.compile(r"[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}")
    for f in FIX.iterdir():
        if f.suffix in (".jpg", ".png"):
            continue
        t = f.read_text(encoding="utf-8", errors="replace")
        assert not secret_re.search(t), f.name
        assert all(m.endswith(("example.com", "example.org")) for m in email_re.findall(t)), f.name


# =============================================================== generic helpers

def test_marker_status_mapping():
    assert p.marker_status("absent: x") == ("EMPTY", None)
    assert p.marker_status("needs_key: x") == ("NEEDS_KEY", "needs_key")
    assert p.marker_status("rate_limited: x") == ("RATE_LIMITED", "rate_limited")
    assert p.marker_status("quota: x") == ("QUOTA", "quota")
    assert p.marker_status("blocked: challenge: cf") == ("BLOCKED", "challenge")
    assert p.marker_status("blocked: Nominatim usage-policy block") == ("BLOCKED", None)
    assert p.marker_status("skipped: config: x") == ("SKIPPED", "config")
    assert p.marker_status("skipped: privacy: x") == ("SKIPPED", "privacy")
    assert p.marker_status("skipped: whatever") == ("SKIPPED", "not_applicable")
    assert p.marker_status("error: x") == ("ERROR", "error")
    assert p.marker_status(None) == (None, None)
    assert p.marker_status("weird: x") == (None, None)


def test_load_json_is_defensive():
    assert p.load_json(b"") == (None, "empty")
    assert p.load_json("<html><body>x</body></html>") == (None, "html")
    assert p.load_json(b"{oops") == (None, "malformed")
    assert p.load_json(b'{"a": 1}') == ({"a": 1}, None)
    assert p.load_json([1]) == ([1], None)


def test_luhn_helpers():
    assert p.luhn_valid("4111111111111111")
    assert not p.luhn_valid("4111111111111112")
    assert p.luhn_check_digit("35389310000000") == "0"
    assert p.luhn_valid("356938035643809")  # research selftest IMEI


# =============================================================== P262 geocoding

def test_nominatim_search_ok_forward_record():
    status, headers, body = load("geocoding__nominatim_search_ok.json")
    assert p.nominatim_marker(status, body_bytes(body), headers) is None
    places = p.parse_nominatim_search(body_bytes(body))
    assert len(places) == 1
    pl = places[0]
    assert (pl["lat"], pl["lon"]) == (-23.55039, -46.633081)
    assert pl["osm_url"] == "https://www.openstreetmap.org/way/75488634"
    assert pl["precision"] == "city"  # place_rank 24 (a square: not a street address)
    rec = p.geocode_record(pl, "forward", attempt_precision="street")
    assert rec["label"] == "approximate place (OSM)"
    assert rec["disclaimer"] == "an address is not proof of residence"
    assert "OpenStreetMap contributors" in rec["attribution"]
    assert rec["precision"] == "street"
    assert rec["pivots"][0] == {"type": "coordinates", "value": "-23.550390,-46.633081", "expand": False}


def test_nominatim_reverse_ok_record_and_cep_pivot():
    status, headers, body = load("geocoding__nominatim_reverse_ok.json")
    assert p.nominatim_marker(status, body_bytes(body), headers) is None
    pl = p.parse_nominatim_reverse(body_bytes(body))
    assert pl["precision"] == "street" and pl["place_rank"] == 30
    assert pl["address"]["postcode"] == "01001-001"
    assert pl["address"]["state_code"] == "SP" and pl["address"]["country_code"] == "BR"
    rec = p.geocode_record(pl, "reverse")
    assert rec["direction"] == "reverse"
    assert rec["pivots"] == [{"type": "cep", "value": "01001-001", "expand": False}]  # no coordinate pivot back


@pytest.mark.parametrize("name,kind", [
    ("geocoding__nominatim_search_empty.json", "absent"),
    ("geocoding__nominatim_reverse_not_found.json", "absent"),
    ("geocoding__nominatim_blocked_403.json", "blocked"),
    ("geocoding__nominatim_rate_limited_509.json", "rate_limited"),
    ("geocoding__nominatim_rate_limited_629.json", "rate_limited"),
])
def test_nominatim_markers(name, kind):
    status, headers, body = load(name)
    m = p.nominatim_marker(status, body_bytes(body), headers)
    assert p.marker_kind(m) == kind, m
    assert p.parse_nominatim_search(body_bytes(body)) == []
    assert p.parse_nominatim_reverse(body_bytes(body)) is None


def test_nominatim_block_page_is_never_empty_even_with_200():
    _, _, body = load("geocoding__nominatim_blocked_403.json")
    assert p.marker_status(p.nominatim_marker(200, body_bytes(body))) == ("BLOCKED", None)
    assert p.marker_kind(p.nominatim_marker(403, b"<html><body>Access denied</body></html>")) == "blocked"
    assert p.marker_kind(p.nominatim_marker(200, b"<html><body>maintenance</body></html>")) == "error"
    assert p.marker_kind(p.nominatim_marker(200, b'{"error": {"code": 400, "message": "bad"}}')) == "error"
    assert "Retry-After 0" in p.nominatim_marker(429, b"", {"Retry-After": "0"})


def test_photon_search_dedup_and_lon_lat_swap():
    status, headers, body = load("geocoding__photon_search_ok.json")
    assert p.photon_marker(status, body_bytes(body), headers) is None
    places = p.parse_photon(body_bytes(body))
    assert len(places) == 2  # office + shop tags of the same OSM node collapse
    first = places[0]
    assert (first["lat"], first["lon"]) == (-23.601516, -46.694729)
    assert first["address"]["house_number"] == "11541" and first["address"]["postcode"] == "04578-000"
    assert first["precision"] == "street" and first["provider"] == "photon"
    assert first["osm_url"] == "https://www.openstreetmap.org/node/2720165956"
    assert len(p.keep_country(places, "BR")) == 2
    assert p.keep_country(places, "PT") == []


def test_photon_cep_and_reverse():
    _, _, body = load("geocoding__photon_search_cep_ok.json")
    pl = p.parse_photon(body_bytes(body))[0]
    assert pl["precision"] == "postcode" and pl["address"]["postcode"] == "04578-000"
    rec = p.geocode_record(pl, "forward")
    assert rec["precision"] == "postcode"
    assert {"type": "cep", "value": "04578-000", "expand": False} in rec["pivots"]
    _, _, body = load("geocoding__photon_reverse_ok.json")
    pl = p.parse_photon(body_bytes(body))[0]
    assert (pl["lat"], pl["lon"]) == (-23.550395, -46.633947)
    assert pl["name"] == "Marco Zero" and pl["address"]["postcode"] == "01001-001"


def test_photon_empty_and_error():
    status, _, body = load("geocoding__photon_search_empty.json")
    assert p.marker_kind(p.photon_marker(status, body_bytes(body))) == "absent"
    status, _, body = load("geocoding__photon_error_400.json")
    m = p.photon_marker(status, body_bytes(body))
    assert p.marker_kind(m) == "error" and "Invalid value for 'lat'" in m
    assert p.parse_photon(body_bytes(body)) == []
    assert p.marker_kind(p.photon_marker(200, b"<html>x</html>")) == "error"
    assert p.marker_kind(p.photon_marker(429, b"")) == "rate_limited"


def test_address_parsing_and_fallback_chain():
    addr = p.parse_br_address("Av. das Nações Unidas, 11541 - Itaim Bibi, São Paulo - SP, 04578-000")
    assert (addr["street"], addr["number"], addr["city"], addr["uf"], addr["cep"]) == (
        "Av. das Nações Unidas", "11541", "São Paulo", "SP", "04578-000")
    attempts = p.build_nominatim_search_attempts(addr)
    assert [a["precision"] for a in attempts] == ["street", "postcode", "city"]
    assert all(a["params"]["countrycodes"] == "br" and a["params"]["limit"] == "1" for a in attempts)
    assert attempts[0]["params"]["street"] == "11541 Av. das Nações Unidas"
    assert p.photon_query_from_address(addr) == "Av. das Nações Unidas 11541, São Paulo SP"
    cep_only = p.parse_br_address("CEP 01001-000")
    assert [a["precision"] for a in p.build_nominatim_search_attempts(cep_only)] == ["postcode"]
    assert p.photon_query_from_address(cep_only) == "01001-000"
    assert p.build_nominatim_search_attempts(None) == []


def test_inputs_keyword_coordinates_cep():
    assert p.address_from_keyword("address: Praça da Sé, São Paulo") == "Praça da Sé, São Paulo"
    assert p.address_from_keyword("endereço:Rua Exemplo 1") == "Rua Exemplo 1"
    assert p.address_from_keyword("Praça da Sé, São Paulo") is None  # bare keyword / pasted text
    c = p.normalize_coordinates("23°33'01\"S 46°38'02\"W")
    assert (c["lat"], c["lon"]) == (-23.550278, -46.633889)
    assert p.normalize_coordinates("-23.550278, -46.633889")["key"] == "-23.550278,-46.633889"
    assert p.normalize_coordinates("91,10") is None
    assert p.normalize_coordinates("0,0")["null_island"]
    with pytest.raises(ValueError):
        p.build_nominatim_reverse_params("0,0")
    with pytest.raises(ValueError):
        p.build_photon_reverse_params("x")
    assert p.build_nominatim_reverse_params("-23.55,-46.63")["zoom"] == "18"
    assert p.normalize_cep("01001000") == "01001-000"
    assert p.normalize_cep("00000-000") is None


def test_identifying_user_agent_and_config_skip():
    assert p.nominatim_user_agent("V3LUM/2.0", "soc@example.com") == "V3LUM/2.0 (contact: soc@example.com)"
    assert p.nominatim_user_agent("V3LUM/2.0", "") is None
    assert p.nominatim_config_marker("soc@example.com") is None
    assert p.marker_status(p.nominatim_config_marker(None)) == ("SKIPPED", "config")


def test_legal_floor_gates():
    assert p.reverse_geocode_gate("seed") is None
    m = p.reverse_geocode_gate("exif")
    assert p.marker_status(m) == ("SKIPPED", "privacy")
    assert p.reverse_geocode_gate("exif", analyst_confirmed=True) is None
    assert p.forward_geocode_gate("seed_address") is None
    assert p.marker_status(p.forward_geocode_gate("company_record")) == ("SKIPPED", "not_default")
    assert p.forward_geocode_gate("company_record", explicit_request=True) is None
    assert p.marker_status(p.forward_geocode_gate("text_blob")) == ("SKIPPED", "privacy")
    assert not p.place_export_allowed("reverse", "exif")
    assert p.place_export_allowed("reverse", "exif", analyst_opt_in=True)
    assert p.place_export_allowed("forward", "company_record")


# =============================================================== P264 image_ela

EDIT_BOX_FRAC = (160 / 256, 32 / 192, 224 / 256, 96 / 192)


def test_sniff_and_jpeg_only():
    assert p.sniff_image_format(raw("image_ela__original_q90.jpg")) == "jpeg"
    assert p.sniff_image_format(raw("image_ela__lossless.png")) == "png"
    assert p.ela_applicability("jpeg") is None
    m = p.ela_applicability("png")
    assert p.marker_status(m) == ("SKIPPED", "not_applicable") and "ELA not meaningful for lossless images" in m
    assert p.marker_status(p.ela_applicability(None)) == ("SKIPPED", "not_applicable")


def test_jpeg_info_and_quality_estimate():
    info = p.jpeg_info(raw("image_ela__original_q90.jpg"))
    assert (info["width"], info["height"], info["components"]) == (256, 192, 3)
    assert info["jfif"] and not info["errors"]
    q = p.jpeg_estimate_quality(info["dqt"])
    assert q["quality"] == 90 and q["exact"]
    bad = p.jpeg_info(raw("image_ela__truncated.jpg"))
    assert bad is not None and bad["errors"]
    assert p.jpeg_info(raw("image_ela__lossless.png")) is None


def test_child_outputs_original_vs_edited():
    orig = p.normalize_ela_child_output(json.loads(raw("image_ela__child_original.json")))
    edit = p.normalize_ela_child_output(json.loads(raw("image_ela__child_edited.json")))
    for res in (orig, edit):
        assert res["ok"] and not res["errors"]
        assert res["severity"] == "info" and res["score_delta"] == 0
        assert res["terminal_line"] == "ELA map in the HTML report (heuristic, not proof)"
        assert "not proof of tampering" in res["wording"]
        assert res["png_data_uri"].startswith("data:image/png;base64,")
        assert not any("tamper" in k for k in res["attributes"])
        assert res["attributes"]["ela_resave_quality"] == 90 and res["attributes"]["jpeg_quality_estimate"] == 90
    a, b = orig["attributes"], edit["attributes"]
    assert b["ela_region_ratio"] > 2 * a["ela_region_ratio"]
    assert b["ela_max"] > a["ela_max"]
    x0, y0, x1, y1 = b["ela_hot_regions"][0]["box"]
    bx0, by0, bx1, by1 = EDIT_BOX_FRAC
    assert bx0 <= x0 and x1 <= bx1 and by0 <= y0 and y1 <= by1  # hottest tile lies in the pasted box


def test_child_outputs_skip_and_bad():
    res = p.normalize_ela_child_output(json.loads(raw("image_ela__child_png_skipped.json")))
    assert not res["ok"] and p.marker_status(res["skip"]) == ("SKIPPED", "not_applicable")
    assert p.ELA_LOSSLESS_REASON in res["skip"]
    for name in ("image_ela__child_malformed.json", "image_ela__child_error.json"):
        res = p.normalize_ela_child_output(json.loads(raw(name)))
        assert not res["ok"] and res["errors"] and res["attributes"] == {}
    assert not p.normalize_ela_child_output(b"<html>not json</html>")["ok"]


def test_ela_caps_and_pure_aggregates():
    assert p.marker_status(p.ela_input_check(101 * 1024 * 1024)) == ("SKIPPED", "policy")
    assert p.ela_input_check(1000, 10000, 5000) is not None  # 50 MP
    assert p.ela_input_check(1000, 256, 192) is None
    flat = p.ela_summary(p.ela_aggregate_bytes(16, 16, bytes(256)))
    assert flat["max"] == 0 and flat["mean"] == 0  # research smoke test: flat image -> max_diff 0
    err = bytearray(64 * 64)
    for y in range(8, 16):
        for x in range(48, 56):
            err[y * 64 + x] = 40
    s = p.ela_summary(p.ela_aggregate_bytes(64, 64, bytes(err)))
    assert s["max"] == 40 and s["hot_regions"][0]["row"] == 1 and s["hot_regions"][0]["col"] == 6
    assert p.ela_aggregate_bytes(4, 4, b"x") is None
    assert p.png_data_uri(b"not a png") is None
    assert p.png_data_uri(raw("image_ela__lossless.png"), max_bytes=100) is None


def test_reference_child_end_to_end_with_pillow():
    pytest.importorskip("PIL")
    import ela_child_reference as child
    o = p.normalize_ela_child_output(child.ela(raw("image_ela__original_q90.jpg"), png_max_width=64))
    e = p.normalize_ela_child_output(child.ela(raw("image_ela__edited_q90.jpg"), png_max_width=64))
    assert o["ok"] and e["ok"]
    assert e["attributes"]["ela_region_ratio"] > o["attributes"]["ela_region_ratio"]
    assert child.ela(raw("image_ela__lossless.png"))["skipped"] == "not_jpeg"


def test_reference_child_synthetic_images_generated_in_test():
    pil = pytest.importorskip("PIL.Image")
    import io

    import ela_child_reference as child
    flat = pil.new("RGB", (64, 48), (128, 128, 128))
    buf = io.BytesIO()
    flat.save(buf, "JPEG", quality=90)
    res = p.normalize_ela_child_output(child.ela(buf.getvalue(), png_max_width=32))
    assert res["ok"] and res["attributes"]["ela_max"] <= 2
    png = io.BytesIO()
    flat.save(png, "PNG")
    out = p.normalize_ela_child_output(child.ela(png.getvalue()))
    assert p.marker_status(out["skip"]) == ("SKIPPED", "not_applicable")


# =============================================================== P273 document_identity_signals

def _no_full_cpf(result):
    dumped = json.dumps(result, ensure_ascii=False)
    assert not FULL_CPF_RE.search(dumped), dumped
    assert "_digits" not in dumped and "_choice" not in dumped


def test_gazette_paragraph_nearest_cpf_is_the_subjects():
    t = text("document_identity_signals__gazette_paragraph.txt")
    r = p.identity_signals(t, "Beltrana da Silva", cpf="000.000.002-72", city="Santos", uf="SP")
    assert r["layout"] == "prose"
    assert r["nearest_cpf_masked"] == "***.000.002-**"  # not Fulano's (before) nor Cicrano's (after)
    assert "typed_cpf_next_to_name" in r["signals"] and "city_near_name" in r["signals"]
    assert r["confidence"] == "strong" and r["alert"] is None
    assert all(w["end"] - w["start"] <= p.MAX_WINDOW for w in r["windows"])
    assert r["privacy"] and not r["cross_case_index"] and not r["export"]
    _no_full_cpf(r)


def test_gazette_paragraph_subject_without_cpf_gets_none():
    t = text("document_identity_signals__gazette_paragraph.txt")
    r = p.identity_signals(t, "Deltrano Costa", uf="SP")
    assert r["name_found"] and r["nearest_cpf_masked"] is None
    assert r["criterion"] == "name found without a CPF nearby (homonyms possible)"
    assert r["signals"] == ["uf_near_name"] and r["confidence"] == "weak"  # UF only: weak
    _no_full_cpf(r)


def test_neighbours_cpf_raises_homonym_alert():
    t = text("document_identity_signals__gazette_paragraph.txt")
    r = p.identity_signals(t, "Fulano de Tal Souza", cpf="000.000.002-72")
    assert r["nearest_cpf_masked"] == "***.000.001-**"
    assert r["alert"] and r["confidence"] == "weak"
    assert r["typed_cpf"] == {"masked": "***.000.002-**", "found_in_document": True, "next_to_name": False}
    _no_full_cpf(r)


def test_table_layout_never_borrows_a_neighbours_line():
    t = text("document_identity_signals__gazette_table.txt")
    assert p.document_layout(t) == "lines"
    r = p.identity_signals(t, "Deltrano Costa")
    assert r["layout"] == "lines" and r["nearest_cpf_masked"] is None
    for name, masked in (("Fulano de Tal Souza", "***.000.001-**"), ("Cícrano Pereira Lima", "***.000.003-**")):
        res = p.identity_signals(t, name)
        assert res["nearest_cpf_masked"] == masked, name
        _no_full_cpf(res)


def test_name_without_cpf_nearby_document():
    t = text("document_identity_signals__no_cpf.txt")
    r = p.identity_signals(t, "Deltrano Costa", cpf="000.000.002-72")
    assert r["name_found"] and r["nearest_cpf_masked"] is None
    assert r["typed_cpf"]["found_in_document"] and not r["typed_cpf"]["next_to_name"]
    _no_full_cpf(r)
    absent = p.identity_signals(t, "Pessoa Inexistente Exemplo")
    assert not absent["name_found"] and absent["criterion"] == "name not found in this document"


def test_masked_cpfs_are_never_fragment_joined():
    t = text("document_identity_signals__masked_list.txt")
    r = p.identity_signals(t, "Beltrana da Silva", cpf="000.000.002-72")
    assert r["nearest_cpf_masked"] == "***.000.002-**"
    assert r["signals"] == ["masked_cpf_next_to_name"]
    assert r["typed_cpf"]["next_to_name"] is False and r["typed_cpf"]["found_in_document"] is False
    assert "analyst compares" in r["criterion"]
    _no_full_cpf(r)


def test_form_layout_cpf_on_next_line():
    t = text("document_identity_signals__contract_form.txt")
    r = p.identity_signals(t, "FULANO DE TAL SOUZA", city="Campinas", uf="SP")
    assert r["layout"] == "prose" and r["nearest_cpf_masked"] == "***.000.001-**"
    assert r["confidence"] == "medium" and "city_near_name" in r["signals"]
    _no_full_cpf(r)


def test_identity_helpers():
    assert p.mask_cpf("000.000.001-91") == "***.000.001-**"
    assert p.mask_cpfs_in_text("CPF 000.000.001-91 e 00000000272") == "CPF ***.000.001-** e ***.000.002-**"
    assert p.cpf_valid("111.444.777-35") and not p.cpf_valid("111.111.111-11")
    assert p.name_regex("Fulano") is None
    r = p.identity_signals("x", "Fulano")
    assert r["errors"] and not r["name_found"]
    assert p.identity_signals(None, "Fulano de Tal")["criterion"] == "empty document"


# =============================================================== P317 user_agent_analysis

def _matcher():
    parsed = p.parse_bad_crawlers(raw("user_agent_analysis__teler_bad_crawlers_ok.txt"))
    return parsed, p.compile_crawler_matcher(parsed["patterns"])


def test_parse_teler_list_keeps_spaces_and_normalises_generic():
    parsed, _ = _matcher()
    assert len(parsed["patterns"]) == 19 and parsed["rejected"] == []
    assert " YLT" in parsed["patterns"] and "^FDM " in parsed["patterns"]
    assert parsed["normalised"][0][1].startswith("(bot|crawl|headless")
    assert p.validate_bad_crawlers(parsed, min_patterns=10) is None
    assert p.marker_kind(p.validate_bad_crawlers(parsed)) == "error"  # a real list has ~1,741 lines


def test_teler_404_and_html_are_errors():
    status, _, body = load("user_agent_analysis__teler_not_found_404.json")
    assert p.marker_kind(p.teler_dataset_marker(status, body)) == "error"
    assert p.parse_bad_crawlers(body)["errors"]
    assert p.parse_bad_crawlers("<html><body>x</body></html>")["errors"]
    assert p.marker_kind(p.teler_dataset_marker(429, "")) == "rate_limited"


def test_phpids_filters_are_never_ua_patterns():
    assert p.is_phpids_filter_set(raw("user_agent_analysis__teler_common_web_attacks.json"))
    assert p.is_phpids_filter_set(raw("user_agent_analysis__teler_bad_crawlers_ok.txt")) is None


def test_synthetic_uas_classification():
    _, matcher = _matcher()
    cases = json.loads(raw("user_agent_analysis__synthetic_uas.json"))["uas"]
    for case in cases:
        r = p.classify_user_agent(case["ua"], matcher)
        for key, want in case.items():
            if key in ("ua", "note"):
                continue
            assert r[key] == want, (case["ua"][:60], key, r[key])
        assert r["risk_ceiling"] == "LOW" and r["never_malicious"]
        assert "malicious" not in r["tags"] and r["severity"] in ("info", "low")
        assert len(r["ua"].encode()) <= 1024


def test_bad_crawler_match_flags():
    _, matcher = _matcher()
    assert p.classify_user_agent("curl/8.5.0", matcher)["bad_crawler_match"]
    assert p.classify_user_agent("sqlmap/1.8", matcher)["bad_crawler_match"]
    chrome = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36"
    assert not p.classify_user_agent(chrome, matcher)["bad_crawler_match"]
    assert p.classify_user_agent(chrome, None)["category"] == "browser"


def test_redos_static_screen_rejects_catastrophic_patterns():
    assert "nested_quantifier" in p.redos_static_flags(r"(a+)+$")
    assert "quantified_alternation" in p.redos_static_flags(r"(a|aa)*$")
    assert "backreference" in p.redos_static_flags(r"(a)\1")
    parsed = p.parse_bad_crawlers("good\n(x+)+y\n(a|ab)*c\n")
    assert parsed["patterns"] == ["good"] and len(parsed["rejected"]) == 2


def test_redos_fuzz_own_table_and_teler_within_budget():
    inputs = p.adversarial_uas()
    assert all(len(s.encode()) <= 1024 for s in inputs)
    for pattern in p.ua_table_patterns():
        assert not [f for f in p.redos_static_flags(pattern) if f in p.REDOS_REJECT], pattern
        assert p.regex_time_ms(pattern, inputs) < 25.0, pattern  # per-UA budget, generous for CI
    _, matcher = _matcher()
    assert p.regex_time_ms(matcher, inputs) < 50.0
    # the classifier truncates before matching: a 1 MB UA costs the same as 1 KB
    big = "Mozilla/5.0 (" + "a" * 1_000_000
    r = p.classify_user_agent(big, matcher)
    assert r["truncated"] and len(r["ua"]) == 1024


def test_full_teler_list_if_present():
    path = RAW / "teler_bad_crawlers.body"
    if not path.exists():
        pytest.skip("raw teler list not present")
    parsed = p.parse_bad_crawlers(path.read_bytes())
    assert p.validate_bad_crawlers(parsed) is None
    assert len(parsed["patterns"]) >= 1700 and not parsed["rejected"]
    matcher = p.compile_crawler_matcher(parsed["patterns"])
    assert p.regex_time_ms(matcher, p.adversarial_uas()) < 200.0


def test_truncate_ua_utf8_boundary():
    s = "é" * 600  # 1200 bytes
    t, cut = p.truncate_ua(s)
    assert cut and len(t.encode()) <= 1024 and t == "é" * 512
    assert p.truncate_ua(None) == ("", False)


# =============================================================== P318 card_bin

def test_binlist_ok():
    status, headers, body = load("card_bin__binlist_ok.json")
    assert p.binlist_marker(status, body_bytes(body), headers) is None
    out = p.parse_binlist(body_bytes(body))
    assert (out["scheme"], out["type"], out["brand"]) == ("visa", "debit", "Visa Classic/Dankort")
    assert (out["country_alpha2"], out["currency"], out["bank_name"]) == ("DK", "DKK", "Jyske Bank A/S")
    assert "latitude" not in json.dumps(out)


@pytest.mark.parametrize("name,kind", [
    ("card_bin__binlist_empty_in_200.json", "absent"),
    ("card_bin__binlist_not_found_404.json", "absent"),
    ("card_bin__binlist_invalid_400.json", "error"),
    ("card_bin__binlist_rate_limited_429.json", "rate_limited"),
    ("card_bin__binlist_challenge_403.json", "blocked"),
])
def test_binlist_markers(name, kind):
    status, headers, body = load(name)
    m = p.binlist_marker(status, body_bytes(body), headers)
    assert p.marker_kind(m) == kind, m
    if kind == "rate_limited":
        assert "unknown" not in m.lower()  # 429 is never 'unknown BIN'
    if kind == "blocked":
        assert p.marker_status(m) == ("BLOCKED", "challenge")


def test_binlist_html_in_200_is_error():
    assert p.marker_kind(p.binlist_marker(200, b"<html><body>oops</body></html>")) == "error"
    assert p.marker_kind(p.binlist_marker(200, b"[]")) == "error"


def test_binlist_request_sends_only_the_bin():
    url, headers = p.binlist_request("45717360")
    assert url == "https://lookup.binlist.net/457173" and headers == {"Accept-Version": "3"}
    assert p.binlist_request("45717360", digits=8)[0].endswith("/45717360")
    for bad in ("4111111111111111", "12345", "411111111"):
        with pytest.raises(ValueError):
            p.binlist_request(bad)


def test_pan_minimisation_in_text():
    t = text("card_bin__pan_text_synthetic.txt")
    pans = p.find_pans(t)
    assert [x["display"] for x in pans] == ["411111******1111", "555555******4444", "378282*****0005",
                                            "636297******7013"]
    assert [x["scheme_guess"] for x in pans] == ["visa", "mastercard", "amex", "elo"]
    dumped = json.dumps(pans)
    assert not re.search(r"\d{9,}", dumped)  # at most the 8-digit BIN survives
    masked = p.mask_pans_in_text(t)
    full = ["4111111111111111", "5555555555554444", "378282246310005", "6362970000457013"]
    assert p.pan_leak_offenders(masked, full) == []
    assert p.pan_leak_offenders(t, full) == ["****1111", "****4444", "****0005", "****7013"]
    assert "00.000.000/0001-91" in masked and "+55 11 5555-0123" in masked


def test_card_bin_input_normalisation_and_own_bins():
    assert p.normalize_card_bin("4111 1111 1111 1111") == {"bin": "41111111", "bin6": "411111",
                                                          "truncated_from": "pan", "display": "411111******1111"}
    assert p.normalize_card_bin("457173") == {"bin": "457173", "bin6": "457173", "truncated_from": None}
    assert p.normalize_card_bin("41111111111")["bin"] == "41111111"
    assert p.normalize_card_bin("12") is None
    assert p.own_bin_match("45717360", ["457173"]) == "own"
    assert p.own_bin_match("457173", ["45717360"]) == "possible_own"
    assert p.own_bin_match("411111", ["457173"]) is None


# =============================================================== P319 imei_check

def test_imeidb_live_401_is_needs_key():
    status, headers, body = load("imei_check__imeidb_needs_key_401.json")
    m = p.imeidb_marker(status, body_bytes(body))
    assert p.marker_status(m) == ("NEEDS_KEY", "needs_key")
    assert p.parse_imeidb(body_bytes(body)) is None


def test_imeidb_docs_success_shape():
    status, _, body = load("imei_check__imeidb_ok_docs_synthetic.json")
    assert p.imeidb_marker(status, body_bytes(body)) is None
    out = p.parse_imeidb(body_bytes(body))
    assert out["tac"] == "35389310" and out["brand"] == "Apple" and out["model"] == "iPhone 11 Pro Max"
    assert out["device_type"] == "Smartphone" and out["os_family"] == "iOS"
    assert not {"serial", "query", "controlNumber", "device_image", "blacklist"} & set(out)


@pytest.mark.parametrize("name,kind", [
    ("imei_check__imeidb_quota_402.json", "quota"),
    ("imei_check__imeidb_rate_limited_429.json", "rate_limited"),
    ("imei_check__imeidb_error_460.json", "error"),
    ("imei_check__imeidb_html_in_200.json", "error"),
])
def test_imeidb_markers(name, kind):
    status, _, body = load(name)
    assert p.marker_kind(p.imeidb_marker(status, body_bytes(body))) == kind


def test_only_the_tac_leaves():
    probe = p.imei_tac_probe("353893101224013")
    assert probe == "353893100000000" and p.luhn_valid(probe)
    url, headers = p.imeidb_request(probe, "dummy-token")
    assert "dummy-token" not in url and headers["X-Api-Key"] == "dummy-token"
    assert "/api/imei/353893100000000" in url
    with pytest.raises(ValueError):
        p.imeidb_request("353893101224013", "dummy-token")  # real serial never sent
    with pytest.raises(ValueError):
        p.imeidb_request(probe, "")
    info = p.imei_parse("35-389310-122401-3")
    assert info["luhn_valid"] and info["tac"] == "35389310" and info["masked"] == "35389310*******"
    assert "122401" not in json.dumps(info)
    assert p.IMEIDB_KEY_ENV == "V3LUM_IMEIDB_TOKEN"
