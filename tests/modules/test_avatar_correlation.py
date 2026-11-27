"""P114 avatar_correlation: whole-image dHash of allow-listed avatars (batch p2-G05-2).

Images are synthetic (cond 9); response headers are the real ones captured from the avatar CDNs on
2026-11-26 (``fetch_*.http.json``: bodies omitted, only their hashes were recorded).
"""

from __future__ import annotations

import ast
import sqlite3
from pathlib import Path

import pytest

from tests.fakes import FakeHttp, make_runtime, module_fixture, run_module
from v3lum.core import lint
from v3lum.core.models import Status
from v3lum.modules.username_social import avatar_correlation as ac
from v3lum.modules.username_social.avatar_correlation import AvatarCorrelation

FIX = Path(__file__).resolve().parents[1] / "fixtures" / "avatar_correlation"
EXPECTED = module_fixture("avatar_correlation", "synthetic_expected.json")["images"]
GH_URL = "https://avatars.githubusercontent.com/u/1000001?v=4"
GRAVATAR_URL = "https://secure.gravatar.com/avatar/be9d18f611892a738e54f2a3a171e2f9?s=80&d=identicon"
BSKY_URL = "https://cdn.bsky.app/img/avatar/plain/did:plc:example/bafkexample@jpeg"


def image(name: str) -> bytes:
    return (FIX / name).read_bytes()


def headers(case: str) -> dict[str, str]:
    return dict(module_fixture("avatar_correlation", f"{case}.http.json")["headers"])


def serve(url: str, name: str, case: str = "fetch_ok", **kw) -> FakeHttp:
    hdrs = headers(case)
    hdrs.pop("content-length", None)
    if name.endswith((".jpg", ".jpeg")):
        hdrs["content-type"] = "image/jpeg"
    elif name.endswith(".webp"):
        hdrs["content-type"] = "image/webp"
    elif name.endswith(".gif"):
        hdrs["content-type"] = "image/gif"
    return FakeHttp().add("GET", url, body=image(name), headers=hdrs, **kw)


@pytest.fixture(autouse=True)
def _fresh_budget():
    ac.CASE_BUDGET.reset()
    yield
    ac.CASE_BUDGET.reset()


# ------------------------------------------------------------------------------------- happy paths


def test_hashes_a_github_avatar_and_keeps_only_url_sha256_and_dhash():
    http = serve(GH_URL, "synthetic_a.png")
    res = run_module(AvatarCorrelation, f"url:{GH_URL}", http)
    assert res.status is Status.OK
    exp = EXPECTED["synthetic_a.png"]
    assert res.attributes["avatar_dhash"] == exp["dhash"]
    assert res.attributes["avatar_sha256"] == exp["sha256"]
    facts = res.attributes["avatar_facts"]
    assert (facts["format"], facts["width"], facts["height"], facts["frames_used"]) == ("PNG", 128, 128, 1)
    assert facts["upload_date_hint"] == "2026-05-06T23:10:28Z"  # real GitHub Last-Modified header
    assert "avatar_ignored" not in res.attributes
    assert res.pivots == [] and res.findings == []
    assert set(res.raw) == {"url", "sha256", "dhash", "format", "size", "stddev32", "ignored", "upload_date_hint", "source"}
    assert res.raw["source"] == "github.avatar_correlation_avatars"
    http.assert_hosts_within(AvatarCorrelation)
    req = http.calls[0]
    assert req["method"] == "GET" and "authorization" not in {k.lower() for k in (req.get("headers") or {})}


@pytest.mark.parametrize("name", ["synthetic_a_resized.jpg", "synthetic_a.webp", "synthetic_anim.gif"])
def test_resized_recompressed_and_animated_copies_stay_within_distance(name):
    url = BSKY_URL if name.endswith(".jpg") else GH_URL
    res = run_module(AvatarCorrelation, f"url:{url}", serve(url, name, "fetch_bsky_no_last_modified" if url == BSKY_URL else "fetch_ok"))
    assert res.status is Status.OK
    assert ac.hamming(res.attributes["avatar_dhash"], EXPECTED["synthetic_a.png"]["dhash"]) <= ac.DHASH_MATCH_MAX
    if name.endswith(".gif"):
        assert res.attributes["avatar_facts"]["frames_used"] == 1  # first frame only


def test_bluesky_cdn_without_last_modified_has_no_upload_hint():
    res = run_module(AvatarCorrelation, f"url:{BSKY_URL}", serve(BSKY_URL, "synthetic_a_resized.jpg", "fetch_bsky_no_last_modified"))
    assert res.status is Status.OK and res.attributes["avatar_facts"]["upload_date_hint"] is None
    assert res.raw["source"] == "bsky_app.avatars"


def test_gravatar_sentinel_date_is_dropped_and_flat_avatars_are_ignored():
    res = run_module(AvatarCorrelation, f"url:{GRAVATAR_URL}", serve(GRAVATAR_URL, "synthetic_flat.png", "fetch_gravatar_default"))
    assert res.status is Status.OK
    assert res.attributes["avatar_ignored"] == "flat"  # cond 5: stddev < 6
    assert res.attributes["avatar_facts"]["upload_date_hint"] is None  # 1984 sentinel


def test_bundled_placeholders_are_loaded_and_matched(monkeypatch):
    from v3lum.core.datasets import DataStore

    placeholders = ac.load_placeholders(DataStore())
    assert {p["platform"] for p in placeholders} >= {"gravatar", "x"}
    gravatar = next(p for p in placeholders if p["platform"] == "gravatar")
    assert ac.placeholder_match(gravatar["dhash"], "", placeholders)["platform"] == "gravatar"
    assert ac.placeholder_match("ffffffffffffffff", gravatar["sha256"], placeholders)["platform"] == "gravatar"
    assert ac.placeholder_match(EXPECTED["synthetic_a.png"]["dhash"], "", placeholders) is None
    monkeypatch.setattr(ac, "load_placeholders", lambda _data: [{"platform": "exampleplat", "dhash": EXPECTED["synthetic_a.png"]["dhash"], "sha256": ""}])
    res = run_module(AvatarCorrelation, f"url:{GH_URL}", serve(GH_URL, "synthetic_a.png"))
    assert res.attributes["avatar_ignored"] == "placeholder:exampleplat"


def test_redirect_inside_the_allow_list_is_followed():
    first = "https://www.gravatar.com/avatar/be9d18f611892a738e54f2a3a171e2f9"
    http = serve(GRAVATAR_URL, "synthetic_b.png", "fetch_gravatar_default")
    http.add("GET", first, status=302, redirect_to=GRAVATAR_URL)
    res = run_module(AvatarCorrelation, f"url:{first}", http)
    assert res.status is Status.OK and res.attributes["avatar_dhash"] == EXPECTED["synthetic_b.png"]["dhash"]


# ------------------------------------------------------------------------------------- refusals


def test_redirect_outside_the_allow_list_is_refused():
    http = FakeHttp().add("GET", GH_URL, status=302, redirect_to="https://evil.example.net/avatar.png")
    res = run_module(AvatarCorrelation, f"url:{GH_URL}", http)
    assert res.status is Status.SKIPPED and res.reason_code == "policy"
    assert "evil.example.net" not in http.hosts()


@pytest.mark.parametrize("url", ["https://www.example.com/me.jpg", "https://gitlab.com/example-dev",
                                 "https://secure.gravatar.com/avatar/x.svg", "https://pbs.twimg.com/profile_images/1/a.jpg"])
def test_urls_outside_the_allow_list_are_never_fetched(url):
    http = FakeHttp()
    res = run_module(AvatarCorrelation, f"url:{url}", http)
    assert res.status is Status.SKIPPED and res.reason_code == "not_applicable"
    assert http.calls == []


def test_url_decision_cases():
    for case in module_fixture("avatar_correlation", "url_cases.json")["cases"]:
        ok, reason = ac.avatar_url_decision(case["url"])
        assert ok is case["allowed"], case
        if not ok:
            assert reason == case["reason"], case


def test_svg_is_never_parsed():
    http = FakeHttp().add("GET", GH_URL, body=image("synthetic_icon.svg"), headers={"content-type": "image/svg+xml"})
    res = run_module(AvatarCorrelation, f"url:{GH_URL}", http)
    assert res.status is Status.SKIPPED and "SVG" in res.error


def test_decompression_bomb_is_refused_before_decoding():
    res = run_module(AvatarCorrelation, f"url:{GH_URL}", serve(GH_URL, "synthetic_bomb.png"))
    assert res.status is Status.SKIPPED and "pixel limit" in res.error
    assert "avatar_dhash" not in res.attributes


def test_truncated_image_is_could_not_verify():
    res = run_module(AvatarCorrelation, f"url:{GH_URL}", serve(GH_URL, "synthetic_truncated.png"))
    assert res.status is Status.ERROR and "could not verify" in res.error


def test_html_instead_of_an_image_is_could_not_verify():
    http = FakeHttp().add("GET", GH_URL, text="<html><body>hello</body></html>", headers={"content-type": "text/html"})
    res = run_module(AvatarCorrelation, f"url:{GH_URL}", http)
    assert res.status is Status.ERROR and "could not verify" in res.error


def test_oversized_avatar_is_not_downloaded_further():
    big = image("synthetic_a.png") + b"\x00" * (ac.MAX_AVATAR_BYTES + 10)
    http = FakeHttp().add("GET", GH_URL, body=big, headers={"content-type": "image/png"})
    res = run_module(AvatarCorrelation, f"url:{GH_URL}", http)
    assert res.status is Status.SKIPPED and "512 KB" in res.error


def test_404_means_the_image_is_gone():
    res = run_module(AvatarCorrelation, f"url:{GH_URL}", FakeHttp().add("GET", GH_URL, status=404, text="Not Found"))
    assert res.status is Status.EMPTY and "404" in res.error


def test_429_403_5xx_and_challenges_are_could_not_verify():
    assert run_module(AvatarCorrelation, f"url:{GH_URL}", FakeHttp().add("GET", GH_URL, status=429, text="slow down")).status is Status.RATE_LIMITED
    assert run_module(AvatarCorrelation, f"url:{GH_URL}", FakeHttp().add("GET", GH_URL, status=403, text="denied")).status is Status.BLOCKED
    assert run_module(AvatarCorrelation, f"url:{GH_URL}", FakeHttp().add("GET", GH_URL, status=503, text="down", times=3)).status is Status.ERROR
    page = "<html><head><title>Just a moment...</title></head><body>cf-chl-widget</body></html>"
    res = run_module(AvatarCorrelation, f"url:{GH_URL}", FakeHttp().add("GET", GH_URL, status=200, text=page, headers={"content-type": "text/html"}))
    assert res.status is Status.BLOCKED


def test_case_budget_of_thirty_downloads():
    ac.CASE_BUDGET.limit = 1
    try:
        first = run_module(AvatarCorrelation, f"url:{GH_URL}", serve(GH_URL, "synthetic_a.png"), case_id="case-1")
        assert first.status is Status.OK
        http = FakeHttp()
        second = run_module(AvatarCorrelation, f"url:{BSKY_URL}", http, case_id="case-1")
        assert second.status is Status.QUOTA and "per case" in second.error and http.calls == []
        other = run_module(AvatarCorrelation, f"url:{GH_URL}", serve(GH_URL, "synthetic_a.png"), case_id="case-2")
        assert other.status is Status.OK
    finally:
        ac.CASE_BUDGET.limit = ac.MAX_DOWNLOADS_PER_CASE


def test_old_or_missing_pillow_is_unavailable(monkeypatch):
    assert ac.MIN_PILLOW == (13, 0, 0)
    assert not ac.pillow_version_ok("10.0.0") and ac.pillow_version_ok("13.0.0") and ac.pillow_version_ok("13.1.0rc1")
    monkeypatch.setattr(ac, "pillow_version_ok", lambda version=None: False)
    http = FakeHttp()
    res = run_module(AvatarCorrelation, f"url:{GH_URL}", http)
    assert res.status is Status.UNAVAILABLE and res.reason_code == "package" and http.calls == []


# ------------------------------------------------------------------------------------- cond 4/9


def test_image_is_never_cached_or_stored(tmp_path):
    http = serve(GH_URL, "synthetic_a.png")
    rt = make_runtime(http, cache=True)
    res = run_module(AvatarCorrelation, f"url:{GH_URL}", runtime=rt)
    assert res.status is Status.OK
    db = getattr(rt.http.cache, "path", None) or getattr(rt.http.cache, "db_path", None)
    if db and Path(str(db)).exists():
        with sqlite3.connect(str(db)) as conn:
            tables = [r[0] for r in conn.execute("SELECT name FROM sqlite_master WHERE type='table'")]
            for table in tables:
                for row in conn.execute(f'SELECT * FROM "{table}"'):
                    assert not any(isinstance(v, (bytes, bytearray)) and b"\x89PNG" in v for v in row)
    assert b"\x89PNG" not in repr(res.raw).encode() and b"\x89PNG" not in repr(res.attributes).encode()


def test_no_face_or_biometric_library_is_imported():
    source = Path(ac.__file__).read_text(encoding="utf-8")
    imported: set[str] = set()
    for node in ast.walk(ast.parse(source)):
        if isinstance(node, ast.Import):
            imported.update(alias.name.split(".")[0] for alias in node.names)
        elif isinstance(node, ast.ImportFrom) and node.module:
            imported.add(node.module.split(".")[0])
    assert not imported & set(ac.FORBIDDEN_IMAGING_MODULES)
    assert imported & {"PIL"} == {"PIL"}  # Pillow alone (cond 3)
    assert ".crop(" not in source  # whole-image hashing only: no region is ever cut out
    assert lint.blocking(lint.lint_module_source(Path(ac.__file__))) == []


def test_unavatar_is_not_in_this_build():
    assert not any("unavatar" in h for h in AvatarCorrelation.hosts)
    assert AvatarCorrelation.requires_keys == () and AvatarCorrelation.optional_keys == ()
    doc = module_fixture("avatar_correlation", "unavatar_rate_limited.http.json")
    assert doc["status"] == 429  # recorded once with a domain value: anonymous quota exhausted (cond 8 context)


def test_math_helpers():
    assert ac.hamming("0000000000000000", "000000000000000f") == 4
    assert ac.hamming(None, "00") == 64
    assert ac.dhash_from_gray9x8([0] * 72) == "0000000000000000"
    with pytest.raises(ValueError):
        ac.dhash_from_gray9x8([1, 2, 3])
    assert ac.is_flat(5.9) and not ac.is_flat(6.0) and ac.is_flat("x")
    assert ac.check_avatar_payload(b"", "image/png") == (False, "empty")
    assert ac.check_avatar_payload(image("synthetic_a.png"), "text/html") == (False, "content_type")
    assert ac.sniff_image_format(image("synthetic_a.webp")) == "webp"
    assert ac.upload_date_hint({"last-modified": "not a date"}) is None


# ------------------------------------------------------------------------------------- rules (cond 1/5/6/7)


def _graph(accounts: int, *, dhash: str = "002070c860630300", settings: dict | None = None, meta: dict | None = None):
    from v3lum.core.correlate import RuleContext
    from v3lum.core.graph import Graph
    from v3lum.config import Config

    nodes, edges = [], []
    for i in range(accounts):
        prof, av = f"url:https://github.com/example-{i}", f"url:https://avatars.githubusercontent.com/u/{1000 + i}"
        nodes += [{"key": prof, "depth": 0, "seed": True},
                  {"key": av, "depth": 1, "attributes": {"avatar_dhash": [{"value": dhash, "source": "avatar_correlation"}]}}]
        edges.append({"src": prof, "dst": av, "relation": "has_avatar", "module": "github_user", "confidence": 0.9})
    cfg = Config()
    cfg.settings.update(settings or {})
    import datetime as dt

    rctx = RuleContext(now=dt.datetime(2026, 11, 26, tzinfo=dt.timezone.utc), settings=cfg, meta=meta or {})
    return Graph.from_dict({"nodes": nodes, "edges": edges}), rctx


def test_rule_common_image_on_more_than_three_accounts_is_not_an_identity_signal():
    from v3lum.correlations import p2_g05_2 as rules

    graph, rctx = _graph(4)
    out = list(rules.avatar_reuse(graph, [], rctx))
    assert len(out) == 1 and "common image" in out[0].title and "context_only" in out[0].tags
    graph, rctx = _graph(3)
    out = list(rules.avatar_reuse(graph, [], rctx))
    assert len(out) == 3 and all(c.title.startswith("same avatar image (dHash distance 0)") for c in out)
    assert all(c.confidence_label.value == "possible" and "same person" not in c.description.replace("never proof of the same person", "") for c in out)


def test_rule_sightings_turn_a_pair_into_a_common_image():
    from v3lum.correlations import p2_g05_2 as rules

    class Summary:
        total = 2

    graph, rctx = _graph(2, meta={"sightings_lookup": lambda entity, **kw: Summary()})
    out = list(rules.avatar_reuse(graph, [], rctx))
    assert len(out) == 1 and "common_image" in out[0].tags  # 2 accounts + 2 other cases >= 4


def test_rule_brand_logo_avatars_are_impersonation_signals_not_pairs():
    from v3lum.correlations import p2_g05_2 as rules

    graph, rctx = _graph(2, settings={"avatar_correlation_brand_logos": {"examplebrand": ["002070c860630300"]}})
    assert list(rules.avatar_reuse(graph, [], rctx)) == []
    logos = list(rules.avatar_brand_logo(graph, [], rctx))
    assert len(logos) == 2 and all(c.title == "uses examplebrand logo" and "brand_abuse" in c.tags for c in logos)


def test_acceptance_route_is_empty_because_the_golden_url_is_not_an_avatar():
    from tests.fakes import fixture

    doc = fixture("acceptance/url/avatar_correlation.json")
    assert (doc["schema"], doc["module"], doc["routes"]) == ("v3lum.acceptance_routes/1", "avatar_correlation", [])
    http = FakeHttp()
    res = run_module(AvatarCorrelation, "url:https://example.com/", http)
    assert res.status is Status.SKIPPED and res.reason_code == "not_applicable" and http.calls == []


def test_rule_gravatar_hashes_are_computed_locally_from_normalised_addresses():
    from v3lum.correlations import p2_g05_2 as rules

    cases = module_fixture("avatar_correlation", "gravatar_cases.json")
    hashes = rules._gravatar_hashes(cases["emails"][1])  # ' Dev@Example.COM ' normalises to dev@example.com
    assert hashes == {cases["md5_dev"]: "md5", cases["sha256_dev"]: "sha256"}
    assert any(cases["md5_dev"] in u for u in cases["avatar_urls"])
