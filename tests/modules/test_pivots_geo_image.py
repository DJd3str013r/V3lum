"""pivots_geo_image (P260): the geo_image pack and its renderer. Offline: no request is ever made.

tests/fixtures/pivots_geo_image/hostile_values.json holds the prep's sample and hostile values (c3) and
live_checks.json the re-check facts behind checked_at (c7).
"""

from __future__ import annotations

import copy
import datetime as dt
import json
from types import SimpleNamespace
from urllib.parse import parse_qs, unquote, urlsplit

import pytest

from tests.fakes import FakeHttp, module_fixture, run_module
from v3lum.core import links as core_links
from v3lum.core.context import ScanOptions
from v3lum.core.entities import Entity
from v3lum.core.entities import EntityType as T
from v3lum.core.models import Status
from v3lum.modules.geo_image_meta import pivots_geo_image as g
from v3lum.modules.geo_image_meta.pivots_geo_image import PivotsGeoImage

IMG = "https://upload.wikimedia.org/wikipedia/commons/a/a9/Example.jpg"
HOSTILE = module_fixture("pivots_geo_image", "hostile_values.json")


def run(etype, value, **kw):
    http = FakeHttp()
    res = run_module(PivotsGeoImage, Entity.make(etype, value) if isinstance(value, str) else value, http, **kw)
    assert http.calls == [] and res.requests == 0  # c1: V3LUM never requests these URLs
    return res


def pack():
    return json.loads((core_links.PACKS_DIR / "geo_image.json").read_text(encoding="utf-8"))


def test_pack_is_clean_and_in_the_frozen_schema():
    found, errors, data = g.load_pack()
    assert errors == [] and data["schema"] == "v3lum.pivot_pack/1" and core_links.lint_pack(data, source="geo_image.json") == []
    assert [lk.id for lk in found] == ["tineye_url", "google_lens_url", "imgops_url", "yandex_images_url", "osm_marker", "google_maps_point"]
    for item in data["x_module_links"]:  # c1: every frozen field
        assert {"label", "template", "entity_types", "category", "host", "verified", "checked_at", "privacy", "publishes",
                "touches_target", "login_required", "antibot"} <= set(item) and item["publishes"] is False
    yandex = next(lk for lk in found if lk.id == "yandex_images_url")
    assert yandex.max_tlp.label == "TLP:GREEN" and "foreign provider (RU)" in yandex.warning  # c10


def test_every_host_has_a_provider_with_a_tier():  # c4/c5
    from v3lum.core import providers

    reg = providers.registry()
    tiers = {lk.host: reg.provider_for_host(lk.host).tier for lk in g.load_pack()[0]}
    assert tiers == {"tineye.com": "trusted", "lens.google.com": "trusted", "imgops.com": "unknown", "yandex.com": "trusted",
                     "www.openstreetmap.org": "trusted", "www.google.com": "trusted"}


def test_clear_tlp_renders_reverse_image_links_in_curated_order():
    res = run(T.URL, IMG, options=ScanOptions(tlp="clear"))
    assert res.status is Status.OK
    hosts = [urlsplit(url).hostname for _label, url in res.links]
    assert hosts == ["tineye.com", "lens.google.com", "imgops.com", "yandex.com"]  # c6
    for _label, url in res.links:
        assert g.check_rendered_url(url, urlsplit(url).hostname) == []
    tineye = res.links[0][1]
    assert parse_qs(urlsplit(tineye).query)["url"] == [IMG]  # exact round trip, no injection
    assert res.links[2][1] == "https://imgops.com/upload.wikimedia.org/wikipedia/commons/a/a9/Example.jpg"
    assert "unknown operator" in res.links[2][0]
    assert res.findings[0].title == "Reverse-image links: not for identifying people"  # c9 standing label
    assert res.raw["standing_label"] == g.REVERSE_IMAGE_LABEL


def test_amber_and_red_rendering():
    res = run(T.URL, IMG)  # default TLP:AMBER
    hosts = [urlsplit(url).hostname for _label, url in res.links]
    assert hosts == ["tineye.com", "lens.google.com"]  # c10 Yandex and the unknown-tier ImgOps hidden at AMBER+
    assert all("opening sends" in label for label, _url in res.links)  # c2
    assert {h["ref"] for h in res.raw["hidden"]} == {"geo_image:imgops_url", "geo_image:yandex_images_url"}
    red = run(T.URL, IMG, options=ScanOptions(tlp="red"))
    assert red.status is Status.SKIPPED and red.reason_code == "tlp" and not red.links


@pytest.mark.parametrize("url", sorted(HOSTILE["image_urls_rejected"]))
def test_page_private_internal_and_token_urls_get_no_links(url):  # c8
    ok, why = g.image_url_eligible(url)
    assert not ok and why


def test_hostile_values_render_only_on_the_declared_host():  # c3
    links = {lk.id: lk for lk in g.load_pack()[0]}
    for raw in HOSTILE["image_urls_rendered"]:
        ent = SimpleNamespace(type=T.URL, value=raw)
        for ident in ("tineye_url", "google_lens_url", "yandex_images_url", "imgops_url"):
            url = g.render(links[ident], ent)
            assert url is not None, (ident, raw)
            parts = urlsplit(url)
            assert parts.scheme == "https" and parts.hostname == links[ident].host and not parts.fragment
            if ident != "imgops_url":
                assert parse_qs(parts.query)["url"] == [raw]
            else:
                assert unquote(parts.path[1:]) == raw.split("://", 1)[1]


def test_coordinates_placeholders_and_privacy_gate():  # c11
    for raw in HOSTILE["coordinates_rejected"]:
        assert g.coordinate_values(raw) is None, raw
    for raw, (lat, lon) in HOSTILE["coordinates_ok"].items():
        assert g.coordinate_values(raw) == {"lat": lat, "lon": lon}
    res = run(T.COORDINATES, "-23.550278,-46.633889")
    assert res.status is Status.SKIPPED and res.reason_code == "privacy" and not res.links
    opted = run(T.COORDINATES, "-23.550278,-46.633889", options=ScanOptions(tlp="green", show_personal=True, purpose="case 42"))
    assert [u for _l, u in opted.links] == ["https://www.openstreetmap.org/?mlat=-23.550278&mlon=-46.633889&zoom=18",
                                            "https://www.google.com/maps/search/?api=1&query=-23.550278,-46.633889"]
    pivot = run(T.COORDINATES, "-23.550278,-46.633889", options=ScanOptions(show_personal=True, purpose="x"), is_seed=False)
    assert pivot.reason_code == "privacy"  # only coordinates the analyst typed or confirmed


def test_urls_found_in_files_get_no_links():  # c9
    prov = (("file:/cases/x/photo.jpg", "qr_payload", "qr_decode"),)
    res = run(T.URL, IMG, provenance=prov, options=ScanOptions(tlp="clear"))
    assert res.status is Status.SKIPPED and "document or file" in res.error


def test_lint_refuses_unsafe_entries():
    base = copy.deepcopy(pack()["x_module_links"][0])
    bad = {
        "raw": {**base, "template": "https://tineye.com/search?url={raw}"},
        "host": {**base, "template": "https://evil.example/search?url={url_q}"},
        "fragment": {**base, "template": "https://tineye.com/search#{url_q}"},
        "format": {**base, "template": "https://tineye.com/search?url={0.__class__}"},
        "publishes": {**base, "publishes": True},
        "keyword_unknown_tier": {**base, "host": "imgops.com", "template": "https://imgops.com/{url_path}", "entity_types": ["keyword"]},
        "coords_not_private": {**pack()["x_module_links"][4], "privacy": False},
        "bad_max_tlp": {**base, "x_max_tlp": "purple"},
    }
    for name, entry in bad.items():
        assert g.lint_geo_entry(entry), name


def test_recheck_report_lists_stale_links():  # c7
    assert g.recheck_report(dt.date(2026, 12, 1)) == []
    stale = g.recheck_report(dt.date(2027, 6, 1))
    assert {s["ref"] for s in stale} == {f"geo_image:{i}" for i in ("tineye_url", "google_lens_url", "imgops_url",
                                                                     "yandex_images_url", "osm_marker", "google_maps_point")}
    checks = module_fixture("pivots_geo_image", "live_checks.json")
    assert checks  # the re-check facts behind checked_at


def test_contract_metadata():
    assert PivotsGeoImage.disclosure == "none" and PivotsGeoImage.default_enabled is True and PivotsGeoImage.hosts == ()
