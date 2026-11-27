"""analytics_ids (P061 offline extractor, batch p2-G03-1).

Fixtures in tests/fixtures/analytics_ids/ (prep p2-G03-1, recorded 2026-11-26):
``ok_live_page_cloudflare.html`` (www.cloudflare.com head, the two GTM script blocks kept),
``empty_live_page_nicbr.html`` (nic.br head: Matomo + google-site-verification, no Google analytics id),
``ids_mixed_synthetic.html`` (synthetic: every id family, template ids and decoys).
"""

from __future__ import annotations

import time

from tests.fakes import FIXTURES, FakeHttp, run_module
from v3lum.core.entities import Entity
from v3lum.core.entities import EntityType as T
from v3lum.core.models import Status
from v3lum.modules.url_web import analytics_ids as mod
from v3lum.modules.url_web.analytics_ids import AnalyticsIds


def fx(name: str) -> str:
    return (FIXTURES / "analytics_ids" / name).read_text(encoding="utf-8")


def ids_of(res) -> set[str]:
    return {p.entity.value for p in res.pivots}


# ------------------------------------------------------------------ metadata (cond 1)
def test_metadata_offline_extractor():
    cls = AnalyticsIds
    assert (cls.disclosure, cls.hosts, cls.provider, cls.sources) == ("none", (), "", ())
    assert cls.terms == "open" and cls.default_enabled is True and cls.access_model == "offline"
    assert cls.max_tlp.name == "RED"


def test_no_request_is_ever_made(tmp_path):
    http = FakeHttp()
    res = run_module(AnalyticsIds, Entity.make(T.TEXT, fx("ids_mixed_synthetic.html")), http)
    assert res.status is Status.OK
    assert http.calls == []


# ------------------------------------------------------------------ regexes (cond 2)
def test_mixed_ids_regexes_templates_and_decoys():
    res = run_module(AnalyticsIds, Entity.make(T.TEXT, fx("ids_mixed_synthetic.html")))
    assert res.status is Status.OK
    # ca-pub- normalised to pub-; AW-/DC- never extracted from pages (only from GTM containers)
    assert ids_of(res) == {"G-TEST0001AB", "UA-99999901-1", "GTM-TEST01X", "pub-9999999900000001", "pub-9999999900000002"}
    assert all(p.relation == "mentions" and p.expand for p in res.pivots)
    sightings = {s["id"]: s for s in res.attributes["analytics_sightings"]}
    assert sightings["UA-99999901-1"]["key"] == "UA-99999901"
    assert sightings["pub-9999999900000001"]["count"] == 4  # comment, script src, data-ad-client (ca-pub- folded)
    templates = {i for i, s in sightings.items() if s["template"]}
    assert templates == {"G-XXXXXXXXXX", "GTM-XXXX", "UA-000000-1", "pub-0000000000000000"}
    shared = [f for f in res.findings if "shared_tracking_id" in f.tags]
    assert len(shared) == 1 and shared[0].severity.label == "info" and shared[0].confidence <= 0.3
    assert not any(v.startswith("AW-") or v.startswith("DC-") for v in res.attributes["analytics_ids"])


def test_regexes_are_case_sensitive_and_bounded():
    text = "g-abcdef1 G-abcdef12 G-ABC12 GTM-ABCDEFGHIJK UA-123-1 UA-12345678901-1 pub-12345 xG-ABCDEF12 G-ABCDEF12"
    out = mod.extract_analytics_ids(text, where="text")
    assert [i["id"] for i in out["ids"]] == ["G-ABCDEF12"]
    assert mod.analytics_kind("G-WGZPDK4DH1") == "ga4"  # the bellingcat digits-only regex would miss it
    assert mod.analytics_kind("g-wgzpdk4dh1") is None


def test_analytics_regexes_1mb_adversarial_time_budget():
    body = mod.adversarial_analytics_body(1_000_000)
    assert len(body) == 1_000_000
    start = time.perf_counter()
    out = mod.extract_analytics_ids(body, where="text")
    elapsed = time.perf_counter() - start
    assert elapsed < 2.0, elapsed
    assert len(out["ids"]) <= mod.MAX_IDS


def test_live_page_cloudflare_gtm_container():
    res = run_module(AnalyticsIds, Entity.make(T.TEXT, fx("ok_live_page_cloudflare.html")))
    assert ids_of(res) == {"GTM-NDGPDFZ"}
    assert res.attributes["analytics_sightings"][0]["count"] == 2


def test_page_without_google_ids_is_empty():
    res = run_module(AnalyticsIds, Entity.make(T.TEXT, fx("empty_live_page_nicbr.html")))
    assert res.status is Status.EMPTY
    assert res.pivots == []


def test_url_input_carries_its_own_id():
    res = run_module(AnalyticsIds, "url:https://www.googletagmanager.com/gtm.js?id=GTM-TEST01X")
    assert ids_of(res) == {"GTM-TEST01X"}
    assert res.attributes["analytics_sightings"][0]["where"] == "url"


def test_file_input(tmp_path):
    page = tmp_path / "saved_page.html"
    page.write_text(fx("ok_live_page_cloudflare.html"), encoding="utf-8")
    res = run_module(AnalyticsIds, Entity.make(T.FILE, str(page)))
    assert res.status is Status.OK and ids_of(res) == {"GTM-NDGPDFZ"}
    assert res.attributes["analytics_sightings"][0]["where"] == "file"


def test_binary_like_file_is_not_applicable(tmp_path):
    blob = tmp_path / "image.png"
    blob.write_bytes(b"\x89PNG GTM-TEST01X")
    res = run_module(AnalyticsIds, Entity.make(T.FILE, str(blob)))
    assert res.status is Status.SKIPPED and res.reason_code == "not_applicable"


def test_truncation_is_reported():
    text = " ".join(f"UA-{10000000 + i}-1" for i in range(mod.MAX_IDS + 5))
    res = run_module(AnalyticsIds, Entity.make(T.TEXT, text))
    assert len(res.pivots) == mod.MAX_IDS
    assert any(f.title == "Tracking-id extraction truncated" for f in res.findings)


# ------------------------------------------------------------------ id facts (cond 4-5)
def test_analytics_id_input_describes_and_flags_template():
    res = run_module(AnalyticsIds, "analytics_id:UA-000000-1")
    info = res.attributes["analytics_id_info"]
    assert info["shared"] is True and info["template"] is True
    assert res.pivots == []
    assert res.findings[0].confidence <= 0.3 and "shared_tracking_id" in res.findings[0].tags


def test_analytics_id_input_regular_gtm():
    res = run_module(AnalyticsIds, "analytics_id:GTM-NHZSKTD")
    info = res.attributes["analytics_id_info"]
    assert info["kind"] == "gtm" and info["shared"] is False
    assert info["expandable_by"][0] == "gtm_expand"
    assert res.findings == []


def test_shared_id_decision_fanout_and_known_list():
    assert mod.shared_id_decision("UA-99999902-1", 51)["shared"] is True
    assert mod.shared_id_decision("UA-99999902-1", 50)["shared"] is False
    assert mod.shared_id_decision("UA-99999909-4", None, known_shared_ids=("UA-99999909",))["shared"] is True
    assert mod.shared_id_decision("G-TEST0001AB")["confidence_cap"] == 0.7


def test_windows_overlap_tolerance():
    d = mod.parse_iso
    a = (d("2019-03-01T00:00:00Z"), d("2019-03-01T00:00:00Z"))
    b = (d("20190510000000"), d("20190510000000"))
    c = (d("2026-11-26T00:00:00Z"), d("2026-11-26T00:00:00Z"))
    assert mod.windows_overlap(a, b) is True
    assert mod.windows_overlap(a, c) is False
    assert mod.windows_overlap(a, (None, None)) is False


def test_sighting_labels_name_where_and_when():
    assert mod.sighting_label("archive", snapshot="20190301000000") == "archive snapshot 20190301000000"
    assert mod.sighting_label("gtm", container="GTM-NHZSKTD", seen_at="2026-11-26T06:42:59Z") == "GTM container GTM-NHZSKTD (2026-11-26)"
    assert mod.sighting_label("live", seen_at="2026-11-26T06:42:59Z") == "live page 2026-11-26"
