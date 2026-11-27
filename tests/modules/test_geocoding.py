"""geocoding (P262, batch p3-G12-1): Nominatim (OSMF) with Photon as the only fallback, offline over FakeHttp."""

from __future__ import annotations

import json
from urllib.parse import urlencode

from tests.fakes import FakeHttp, module_fixture, run_module
from v3lum.core.models import Status
from v3lum.modules.geo_image_meta import geocoding as G
from v3lum.modules.geo_image_meta.geocoding import Geocoding

CONTACT = {"contact_email": "soc@example.com"}
REV_PARAMS = {"lat": "-23.550278", "lon": "-46.633889", "format": "jsonv2", "zoom": "18", "addressdetails": "1"}
NOM_REVERSE = "https://nominatim.openstreetmap.org/reverse?" + urlencode(REV_PARAMS)
PH_REVERSE = "https://photon.komoot.io/reverse?" + urlencode(
    {"lat": "-23.550278", "lon": "-46.633889", "limit": "1", "lang": "en"})
SEED = "coordinates:-23.550278,-46.633889"
ADDRESS = "keyword:address: Avenida das Nações Unidas, 11541, São Paulo - SP, 04578-000"


def env(name: str) -> dict:
    """FakeHttp.add keywords of an envelope fixture (status, headers, json or text body)."""
    data = module_fixture("geocoding", name)
    kw = {"status": data["status"], "headers": data.get("headers") or {}}
    body = data["body"]
    if isinstance(body, str):
        kw["text"] = body
    else:
        kw["json"] = body
    return kw


def nom_search(**params: str) -> str:
    base = {"countrycodes": "br", "format": "jsonv2", "addressdetails": "1", "limit": "1"}
    return "https://nominatim.openstreetmap.org/search?" + urlencode({**base, **params})


def photon_search(q: str) -> str:
    return "https://photon.komoot.io/api/?" + urlencode({"q": q, "limit": "5", "lang": "en"})


STREET = nom_search(street="11541 Avenida das Nações Unidas", city="São Paulo", state="SP", postalcode="04578-000")
POSTCODE = nom_search(postalcode="04578-000")
CITY = nom_search(city="São Paulo", state="SP")


# ------------------------------------------------------------------ reverse geocoding
def test_reverse_nominatim_happy_path_is_labelled_and_attributed():
    http = FakeHttp().add("GET", NOM_REVERSE, **env("nominatim_reverse_ok.json"))
    res = run_module(Geocoding, SEED, http, settings=CONTACT)
    assert res.status is Status.OK
    a = res.attributes
    assert a["geo_label"] == "approximate place (OSM)"
    assert a["geo_precision"] == "street"
    assert a["geo_disclaimer"] == "an address is not proof of residence"
    assert a["geo_attribution"] == "(c) OpenStreetMap contributors (ODbL 1.0)"
    assert a["geo_provider"] == "nominatim" and a["geo_direction"] == "reverse"
    assert a["geo_address"]["state_code"] == "SP" and a["geo_address"]["postcode"] == "01001-001"
    assert a["geo_export_allowed"] is False
    assert a["country"] == "BR"
    f = res.findings[0]
    assert f.severity.name == "INFO" and "privacy" in f.tags and f.source == "osmf_nominatim.geocoding"
    # reverse: only the CEP pivots, never auto-expanded (FC5)
    assert [(p.entity.type.value, p.entity.value, p.expand) for p in res.pivots] == [("cep", "01001001", False)]
    # the identifying UA carries the contact mailbox on the OSM host only (P326)
    assert "soc@example.com" in http.calls[0]["headers"].get("User-Agent", "")
    http.assert_hosts_within(Geocoding)


def test_reverse_without_contact_email_skips_nominatim_and_uses_photon():
    http = FakeHttp().add("GET", PH_REVERSE, **env("photon_reverse_ok.json"))
    res = run_module(Geocoding, SEED, http)
    assert res.status is Status.OK
    assert res.attributes["geo_provider"] == "photon"
    st = res.source_statuses["osmf_nominatim.geocoding"]
    assert st["status"] == "skipped" and st["reason_code"] == "config"
    assert http.hosts() == {"photon.komoot.io"}  # nothing was sent to Nominatim
    # Photon geometry is [lon, lat]: swapped
    assert -24 < res.attributes["geo_place"]["lat"] < -23 and -47 < res.attributes["geo_place"]["lon"] < -46


def test_reverse_nominatim_403_access_blocked_is_blocked_and_photon_answers():
    http = (FakeHttp().add("GET", NOM_REVERSE, **env("nominatim_blocked_403.json"))
            .add("GET", PH_REVERSE, **env("photon_reverse_ok.json")))
    res = run_module(Geocoding, SEED, http, settings=CONTACT)
    assert res.status is Status.OK and res.attributes["geo_provider"] == "photon"
    st = res.source_statuses["osmf_nominatim.geocoding"]
    assert st["status"] == "blocked"


def test_reverse_both_sources_down_is_could_not_verify_never_empty():
    http = (FakeHttp().add("GET", NOM_REVERSE, **env("nominatim_blocked_403.json"))
            .add("GET", PH_REVERSE, status=429, text="Too Many Requests"))
    res = run_module(Geocoding, SEED, http, settings=CONTACT)
    assert res.status is Status.BLOCKED
    assert "could not verify" in res.error


def test_reverse_629_cdn_refusal_is_rate_limited():
    http = (FakeHttp().add("GET", NOM_REVERSE, **env("nominatim_rate_limited_629.json"))
            .add("GET", PH_REVERSE, status=503, text="upstream down", times=2))
    res = run_module(Geocoding, SEED, http, settings=CONTACT)
    assert res.status is Status.RATE_LIMITED and res.reason_code == "rate_limited"


def test_reverse_509_bandwidth_limit_is_rate_limited():
    http = (FakeHttp().add("GET", NOM_REVERSE, **env("nominatim_rate_limited_509.json"))
            .add("GET", PH_REVERSE, **env("photon_error_400.json")))
    res = run_module(Geocoding, SEED, http, settings=CONTACT)
    assert res.status is Status.RATE_LIMITED
    assert res.source_statuses["komoot.geocoding"]["status"] == "error"


def test_reverse_unable_to_geocode_is_a_documented_absence():
    http = (FakeHttp().add("GET", NOM_REVERSE, **env("nominatim_reverse_not_found.json"))
            .add("GET", PH_REVERSE, json={"type": "FeatureCollection", "features": []}))
    res = run_module(Geocoding, SEED, http, settings=CONTACT)
    assert res.status is Status.EMPTY
    assert "not proof" in res.error


def test_reverse_null_island_and_pivot_coordinates_are_never_sent():
    http = FakeHttp()
    res = run_module(Geocoding, "coordinates:0,0", http, settings=CONTACT)
    assert res.status is Status.SKIPPED and res.reason_code == "not_applicable"
    # FC4: coordinates from EXIF/devices/pivots need a per-entity analyst confirmation (typed seed)
    res2 = run_module(Geocoding, SEED, http, settings=CONTACT, is_seed=False, depth=1)
    assert res2.status is Status.SKIPPED and res2.reason_code == "privacy"
    assert http.calls == []


# ------------------------------------------------------------------ forward geocoding
def test_forward_address_street_attempt_wins():
    http = FakeHttp().add("GET", STREET, **env("nominatim_search_ok.json"))
    res = run_module(Geocoding, ADDRESS, http, settings=CONTACT)
    assert res.status is Status.OK
    assert res.attributes["geo_precision"] == "street" and res.attributes["geo_direction"] == "forward"
    pivots = {(p.entity.type.value, p.expand) for p in res.pivots}
    assert ("coordinates", False) in pivots
    coords = next(p for p in res.pivots if p.entity.type.value == "coordinates")
    assert coords.relation == "located_at" and "not proof of residence" in coords.note


def test_forward_falls_back_street_postcode_city_then_photon():
    empty = env("nominatim_search_empty.json")
    http = (FakeHttp().add("GET", STREET, **empty).add("GET", POSTCODE, **empty).add("GET", CITY, **empty)
            .add("GET", photon_search("Avenida das Nações Unidas 11541, São Paulo SP"), **env("photon_search_ok.json")))
    res = run_module(Geocoding, ADDRESS, http, settings=CONTACT)
    assert res.status is Status.OK
    assert res.attributes["geo_provider"] == "photon" and res.attributes["geo_precision"] == "street"
    assert [c["url"].split("?")[0] for c in http.calls] == [
        "https://nominatim.openstreetmap.org/search"] * 3 + ["https://photon.komoot.io/api/"]
    attempts = res.raw["attempts"]
    assert [a["precision"] for a in attempts[:3]] == ["street", "postcode", "city"]
    # the CEP pivot is the place's postcode, never auto-expanded
    assert {(p.entity.value, p.expand) for p in res.pivots if p.entity.type.value == "cep"} == {("04578000", False)}
    # duplicate OSM object (office + shop tags) collapsed by the parser
    places = G.parse_photon(module_fixture("geocoding", "photon_search_ok.json")["body"])
    assert len({(p["osm_type"], p["osm_id"]) for p in places}) == len(places)


def test_forward_postcode_precision_when_street_has_no_match():
    http = (FakeHttp().add("GET", STREET, **env("nominatim_search_empty.json"))
            .add("GET", POSTCODE, **env("nominatim_search_ok.json")))
    res = run_module(Geocoding, ADDRESS, http, settings=CONTACT)
    assert res.status is Status.OK and res.attributes["geo_precision"] == "postcode"


def test_forward_cep_seed_uses_postcode_then_photon_filtered_to_brazil():
    url = nom_search(postalcode="04578-000")
    http = (FakeHttp().add("GET", url, **env("nominatim_search_empty.json"))
            .add("GET", photon_search("04578-000"), **env("photon_search_cep_ok.json")))
    res = run_module(Geocoding, "cep:04578-000", http, settings=CONTACT)
    assert res.status is Status.OK
    assert res.attributes["geo_precision"] == "postcode"
    assert res.attributes["geo_address"]["country_code"] == "BR"


def test_forward_all_absent_is_empty_with_honest_wording():
    empty = env("nominatim_search_empty.json")
    http = (FakeHttp().add("GET", nom_search(postalcode="04578-000"), **empty)
            .add("GET", photon_search("04578-000"), **env("photon_search_empty.json")))
    res = run_module(Geocoding, "cep:04578-000", http, settings=CONTACT)
    assert res.status is Status.EMPTY
    assert "not proof" in res.error


def test_forward_nominatim_error_in_200_and_malformed_json_are_errors_never_absent():
    http = (FakeHttp().add("GET", nom_search(postalcode="04578-000"),
                           json={"error": {"code": 400, "message": "Parameter 'postalcode' invalid"}})
            .add("GET", photon_search("04578-000"), text="{not json", headers={"content-type": "application/json"}))
    res = run_module(Geocoding, "cep:04578-000", http, settings=CONTACT)
    assert res.status is Status.ERROR
    assert res.source_statuses["osmf_nominatim.geocoding"]["status"] == "error"
    assert res.source_statuses["komoot.geocoding"]["status"] == "error"


def test_forward_photon_html_and_5xx_are_errors():
    http = (FakeHttp().add("GET", nom_search(postalcode="04578-000"), status=500, text="boom", times=2)
            .add("GET", photon_search("04578-000"), status=200, text="<html><body>maintenance</body></html>",
                 headers={"content-type": "text/html"}))
    res = run_module(Geocoding, "cep:04578-000", http, settings=CONTACT)
    assert res.status is Status.ERROR


def test_keyword_needs_an_explicit_address_prefix():
    http = FakeHttp()
    res = run_module(Geocoding, "keyword:Avenida Paulista 1000", http, settings=CONTACT)
    assert res.status is Status.SKIPPED and res.reason_code == "not_applicable"
    assert http.calls == []


def test_parse_br_address_and_attempt_builder():
    addr = G.parse_br_address("Avenida das Nações Unidas, 11541, São Paulo - SP, 04578-000")
    assert addr["street"] == "Avenida das Nações Unidas" and addr["number"] == "11541"
    assert addr["city"] == "São Paulo" and addr["uf"] == "SP" and addr["cep"] == "04578-000"
    attempts = G.build_nominatim_search_attempts(addr)
    assert [a["precision"] for a in attempts] == ["street", "postcode", "city"]
    assert all(a["params"]["countrycodes"] == "br" and a["params"]["limit"] == "1" for a in attempts)


def test_export_view_strips_places_that_may_locate_a_person():
    attrs = {"geo_place": {"lat": 1}, "geo_display_name": "x", "geo_precision": "street",
             "geo_attribution": G.OSM_ATTRIBUTION, "geo_export_allowed": False}
    view = G.export_view(attrs)
    assert "geo_place" not in view and view["geo_precision"] == "street"
    assert G.export_view(attrs, case_opt_in=True) == attrs


def test_metadata_matches_the_council_decision():
    assert Geocoding.default_enabled is True and Geocoding.terms == "open"
    assert Geocoding.disclosure == "third_party" and Geocoding.run_on == "seeds"
    assert Geocoding.trust_tier == "community"
    assert Geocoding.cache_ttl == 30 * 86400
    assert "text_blob" not in {t.value for t in Geocoding.accepts}
    assert json.dumps(sorted(Geocoding.hosts)) == json.dumps(["nominatim.openstreetmap.org", "photon.komoot.io"])
