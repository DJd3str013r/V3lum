"""id_timestamp_decoders (P314, batch p2-G12-2): offline platform-id -> creation-time decoders.

Fixtures in tests/fixtures/id_timestamp_decoders/: vectors.json (the three P314 c6 vectors plus constructed
round-trips), text_blob_ptbr.txt (a synthetic pasted note: documentation handles, a FAKE webhook token) and
negatives.txt (bare ids, CPF/phone-like digits, unrecognised hosts, out-of-window and non-canonical ids).
"""

from __future__ import annotations

import json
from datetime import datetime, timezone

import pytest

from tests.fakes import FakeClock, FakeHttp, make_ctx, module_fixture, run_module
from v3lum.core.entities import Entity
from v3lum.core.http import PolicyError
from v3lum.core.models import Severity, Status
from v3lum.modules.utility.id_timestamp_decoders import (
    X_MIN_SNOWFLAKE_ID,
    IdTimestampDecoders,
    decode_platform_id,
    find_decodable_ids,
)

NOW = datetime(2026, 11, 26, tzinfo=timezone.utc)
CLOCK = "2026-11-26T12:00:00Z"
VECTORS = module_fixture("id_timestamp_decoders", "vectors.json")
BLOB = module_fixture("id_timestamp_decoders", "text_blob_ptbr.txt")
NEGATIVES = module_fixture("id_timestamp_decoders", "negatives.txt")


def run(value: str):
    return run_module(IdTimestampDecoders, value, clock=FakeClock(CLOCK))


@pytest.mark.parametrize("vec", VECTORS["vectors"], ids=lambda v: f"{v['platform']}-{v['id']}")
def test_spec_vectors_and_round_trips(vec):
    out = decode_platform_id(vec["platform"], vec["id"], now=NOW)
    assert out["status"] == "ok"
    assert out["created"] == vec["created"]
    if "rendered" in vec:
        assert out["rendered"] == vec["rendered"]  # c5 rendering example


def test_p314_c6_vectors_exact():
    assert decode_platform_id("x", "1536682540265873408", now=NOW)["created"] == "2022-06-14T12:10:42.437Z"
    assert decode_platform_id("discord", "613425648685547541", now=NOW)["created"] == "2019-08-20T17:34:31.544Z"
    assert decode_platform_id("tiktok", "6718335390845095173", now=NOW)["created"] == "2019-07-27T13:32:33Z"


def test_x_post_url_sets_created_with_epoch():
    res = run("url:https://x.com/example/status/1536682540265873408")
    assert res.status is Status.OK
    assert res.attributes["created"] == "2022-06-14T12:10:42.437Z"
    assert "1288834974657" in res.attributes["created_epoch"]
    f = res.findings[0]
    assert f.title == "Creation time decoded from the ID" and f.severity is Severity.INFO
    assert f.description.startswith("created ~2022-06-14 12:10 UTC (decoded from the ID)")
    assert not res.pivots


def test_discord_message_url_primary_is_the_message():
    res = run("url:https://discord.com/channels/613425648685547541/613425648685547544/1235579295498416149")
    rows = {r["component"]: r for r in res.attributes["id_timestamps"]}
    assert set(rows) == {"guild", "channel", "message"}
    assert rows["message"]["primary"] and not rows["guild"]["primary"]
    assert res.attributes["created"] == "2024-05-02T13:11:00.000Z"
    assert "1420070400000" in res.attributes["created_epoch"]


def test_tiktok_and_linkedin_urls():
    res = run("url:https://www.tiktok.com/@example/video/6718335390845095173")
    assert res.attributes["created"] == "2019-07-27T13:32:33Z"
    res = run("url:https://www.linkedin.com/feed/update/urn:li:activity:7034310859677622848/")
    assert res.attributes["created"] == "2023-02-23T00:00:00.123Z"


def test_text_blob_only_platform_urls_and_prefix():
    res = run_module(IdTimestampDecoders, Entity.make("text_blob", BLOB), clock=FakeClock(CLOCK))
    assert res.status is Status.OK
    rows = res.attributes["id_timestamps"]
    plats = {(r["platform"], r["component"]) for r in rows}
    assert {("x", "post"), ("discord", "guild"), ("discord", "message"), ("discord", "webhook"), ("tiktok", "video"),
            ("linkedin", "activity"), ("discord", "id"), ("x", "id")} <= plats
    assert "created" not in res.attributes  # a text blob is not the object: no single creation time
    ambiguous = [r for r in rows if r["ambiguous_platform"]]
    # bare snowflake:ID -> the X reading is labelled ambiguous; the explicit snowflake:discord: reading of the same id wins
    assert {r["platform"] for r in ambiguous} == {"x"}
    assert [r for r in rows if r["platform"] == "discord" and r["component"] == "id"][0]["ambiguous_platform"] is False
    # the FAKE webhook token never leaves the module
    produced = json.dumps({"a": res.attributes, "raw": res.raw, "f": [f.description for f in res.findings]})
    assert "AbCdEfGhIjKlMnOpQrStUvWxYz0123456789" not in produced
    assert res.raw["note"].startswith("Discord webhook token present")


def test_bare_numbers_are_never_interpreted():
    text = NEGATIVES.splitlines()[0] + "\n" + NEGATIVES.splitlines()[1]
    assert find_decodable_ids(text) == []
    res = run_module(IdTimestampDecoders, Entity.make("text_blob", "pedido 1536682540265873408 protocolo 613425648685547541"),
                     clock=FakeClock(CLOCK))
    assert res.status is Status.EMPTY and "bare numbers are never interpreted" in res.error
    res = run("keyword:1536682540265873408")
    assert res.status is Status.SKIPPED and res.reason_code == "not_applicable"


def test_negatives_pre_snowflake_out_of_window_and_non_canonical():
    items = {(i["platform"], i["id"]) for i in find_decodable_ids(NEGATIVES)}
    assert ("x", "20") in items and ("tiktok", "1000") in items
    assert not any(i[1].startswith("0") for i in items)  # leading zero: not canonical
    assert not any("xsnowflake" in i[1] for i in items)
    assert decode_platform_id("x", "20", now=NOW)["status"] == "pre_snowflake"
    assert decode_platform_id("x", str(X_MIN_SNOWFLAKE_ID - 1), now=NOW)["status"] == "pre_snowflake"
    late = decode_platform_id("x", "9223372036854775807", now=NOW)
    assert late["status"] == "out_of_window" and late["created"] is None and late["rendered"] is None
    assert decode_platform_id("tiktok", "1000", now=NOW)["status"] == "out_of_window"
    assert decode_platform_id("instagram", "3141592653589793238", now=NOW)["status"] == "unsupported"
    res = run("url:https://x.com/example/status/9223372036854775807")
    assert "created" not in res.attributes
    assert res.findings[0].title == "ID not decoded" and "outside the platform's lifetime" in res.findings[0].description


def test_typed_snowflake_and_tiktok_entities():
    res = run("snowflake_id:613425648685547541")
    assert "created" not in res.attributes  # ambiguous X/Discord: both readings, no single value
    titles = {f.title for f in res.findings}
    assert titles == {"Creation time decoded from the ID (platform ambiguous)"}
    assert all(f.confidence_label == "possible" for f in res.findings)
    assert {f.data["platform"] for f in res.findings} == {"x", "discord"}
    res = run("tiktok_video_id:6718335390845095173")
    assert res.attributes["created"] == "2019-07-27T13:32:33Z"


def test_explicit_platform_prefix_in_keyword():
    res = run("keyword:snowflake:discord:613425648685547541")
    assert res.status is Status.OK
    assert [r["created"] for r in res.attributes["id_timestamps"]] == ["2019-08-20T17:34:31.544Z"]


def test_offline_module_never_touches_the_network():
    ctx = make_ctx(IdTimestampDecoders, FakeHttp())
    with pytest.raises(PolicyError):
        ctx.http.get("https://x.com/")
    assert IdTimestampDecoders.disclosure == "none" and IdTimestampDecoders.hosts == ()
    assert IdTimestampDecoders.default_enabled is True and IdTimestampDecoders.terms == "open"


def test_golden_url_is_not_applicable():
    res = run("url:https://example.com/")
    assert res.status is Status.SKIPPED and res.reason_code == "not_applicable"
