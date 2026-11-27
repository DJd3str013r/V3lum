"""x_archive_import (P121): offline X archive import with provenance, safe in-memory reading, Ceos indicators.

Fixtures in tests/fixtures/x_archive_import/ are SYNTHETIC archives built by the batch p3-G05-3 prep
(documentation domains and addresses only; account e-mail owner@example.com and login IP 192.0.2.10 are
planted to prove they are never copied): ``ok.zip`` (manifest, account, profile, tweets.js +
tweets-part1.js, deleted-tweets.js, plus direct messages, IP audit, a media file and the bundled viewer that
must never be read), ``bot.zip`` (a bulk-created automated account), the attack cases ``zip_slip.zip``,
``absolute_path.zip``, ``zip_bomb.zip`` (30 MB of zeros declared at > 1000x), ``declared_oversize.zip``
(300 MB declared), ``malformed_js.zip`` (a JS expression instead of JSON), ``not_archive.zip``,
``legacy_tweet_js.zip`` (the older data/tweet.js name) and a bare ``tweets_only.js``.
"""

from __future__ import annotations

import io
import json
import shutil
import socket
import zipfile
from pathlib import Path

import pytest

from tests.fakes import FIXTURES, FakeHttp, run_module
from v3lum.core.models import Severity, Status
from v3lum.modules.username_social import x_archive_import as A
from v3lum.modules.username_social.x_archive_import import XArchiveImport

FX = FIXTURES / "x_archive_import"
PROVENANCE = {"source": "export handed over by the account holder (ticket SOC-1234)", "date": "2026-11-20",
              "legal_basis": "account_holder", "reference": "SOC-1234"}


def stage(tmp_path: Path, name: str, provenance: dict | None = PROVENANCE, data: bytes | None = None) -> Path:
    target = tmp_path / name
    if data is None:
        shutil.copyfile(FX / name, target)
    else:
        target.write_bytes(data)
    if provenance is not None:
        (tmp_path / (name + A.PROVENANCE_SUFFIX)).write_text(json.dumps(provenance), encoding="utf-8")
    return target


def run(path: Path, http: FakeHttp | None = None):
    return run_module(XArchiveImport, f"file:{path}", http or FakeHttp())


def zip_bytes(members: dict[str, bytes], *, flag_bits: int = 0, symlink: str | None = None) -> bytes:
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
        for name, content in members.items():
            info = zipfile.ZipInfo(name)
            info.compress_type = zipfile.ZIP_DEFLATED
            if symlink == name:
                info.external_attr = (0o120777 << 16)
            zf.writestr(info, content)
    data = bytearray(buf.getvalue())
    if flag_bits:  # mark every member encrypted in both local and central headers
        for sig, off in ((b"PK\x03\x04", 6), (b"PK\x01\x02", 8)):
            pos = data.find(sig)
            while pos != -1:
                data[pos + off] |= flag_bits
                pos = data.find(sig, pos + 4)
    return bytes(data)


TWEETS = (b'window.YTD.tweets.part0 = [{"tweet": {"id_str": "2062134197744566272", "created_at": '
          b'"Wed Jun 03 11:28:00 +0000 2026", "full_text": "ok", "entities": {}}}]')


def test_metadata_is_offline_and_opt_in():
    assert XArchiveImport.disclosure == "none" and XArchiveImport.hosts == () and XArchiveImport.default_enabled is False
    assert XArchiveImport.terms == "open" and XArchiveImport.trust_tier == "n/a"


def test_import_reads_only_the_documented_data_files(tmp_path, monkeypatch):
    def no_network(*_a, **_k):  # cond 1: a unit test asserts no HTTP call (and no socket at all)
        raise AssertionError("x_archive_import must never touch the network")

    monkeypatch.setattr(socket, "create_connection", no_network)
    monkeypatch.setattr(socket, "getaddrinfo", no_network)
    http = FakeHttp()
    res = run(stage(tmp_path, "ok.zip"), http)
    assert res.status is Status.OK, res.error
    assert http.calls == [] and res.hosts == {}
    arc = res.attributes["x_archive"]
    assert arc["account"]["handle"] == "exampleorg" and arc["posts"] == 30 and arc["deleted_posts"] == 1
    assert arc["generated_at"] == "2026-10-01T12:00:00.000Z" and arc["ignored_outside_data"] == 2  # viewer never opened
    assert "data/direct-messages.js" in arc["skipped_data"] and "data/ip-audit.js" in arc["skipped_data"]
    everything = json.dumps([res.attributes, res.raw, [f.description for f in res.findings], [p.note for p in res.pivots]], default=str)
    for leaked in ("owner@example.com", "192.0.2.10", "private message", "never opened or executed", "createdVia"):
        assert leaked not in everything, leaked  # account e-mail, IP audit, DMs and the viewer are never read or copied
    prov = res.attributes["archive_provenance"]
    assert prov["legal_basis"] == "account_holder" and len(prov["sha256"]) == 64  # cond 2: recorded in the case
    pivots = {(p.relation, p.entity.value) for p in res.pivots}
    assert ("archive_account", "exampleorg") in pivots and ("link_on_profile", "https://example.com/") in pivots
    assert {("interacted_with", "example_agency"), ("interacted_with", "example_news")} <= pivots
    assert all(not p.expand for p in res.pivots)
    assert res.attributes["automation_likelihood"] == "low"
    assert [f.title for f in res.findings] == ["X archive imported"]


def test_provenance_is_required_before_anything_is_read(tmp_path):
    res = run(stage(tmp_path, "ok.zip", provenance=None))
    assert res.status is Status.SKIPPED and res.reason_code == "config" and "provenance" in res.error
    assert "x_archive" not in res.attributes
    bad = dict(PROVENANCE, legal_basis="found_on_a_forum")
    res = run(stage(tmp_path, "bot.zip", provenance=bad))
    assert res.status is Status.SKIPPED and res.reason_code == "config" and "legal process" in res.error
    res = run(stage(tmp_path, "legacy_tweet_js.zip", provenance=dict(PROVENANCE, date="last week")))
    assert res.status is Status.SKIPPED and "ISO date" in res.error


def test_automation_indicators_are_low_confidence_and_show_metrics(tmp_path):
    res = run(stage(tmp_path, "bot.zip"))
    assert res.status is Status.OK
    assert res.attributes["automation_likelihood"] == "high"
    ind = res.attributes["automation_indicators"]
    ids = {s["id"] for s in ind["signals"]}
    assert {"numeric_handle", "default_avatar", "mostly_reposts", "regular_intervals", "all_hours"} <= ids
    assert ind["metrics"]["repost_pct"] > 80 and ind["metrics"]["distinct_hours"] >= 23
    (finding,) = [f for f in res.findings if f.title == "Automation indicators (Ceos thresholds)"]
    assert finding.severity is Severity.LOW and finding.confidence <= 0.4  # cond 6
    assert "never the sole basis of a decision about a person (LGPD art. 20)" in finding.description
    assert "automation_indicator" in finding.tags and finding.data["metrics"]["handle_trailing_digits"] == 6


def test_thresholds_follow_ceos():
    assert A.AUTOMATION_THRESHOLDS == {"interval_cv_max": 0.5, "interval_min_gaps": 20, "repost_pct_min": 80, "repost_min_posts": 20,
                                       "distinct_hours_min": 23, "distinct_hours_min_posts": 50, "handle_digits_min": 6,
                                       "posts_per_day_max": 72, "young_account_days": 90, "young_account_posts": 1000}
    two = A.automation_indicators([], {"handle": "bot1234567", "created_at": "2026-01-01T00:00:00Z"},
                                  {"avatar_url": "https://abs.twimg.com/sticky/default_profile_images/default_profile.png"})
    assert two["likelihood"] == "medium" and two["severity"] == "low" and two["confidence"] == 0.3
    assert A.automation_indicators([])["likelihood"] == "low"


@pytest.mark.parametrize(("name", "needle"), [
    ("zip_slip.zip", "zip-slip"),
    ("absolute_path.zip", "absolute member path"),
    ("zip_bomb.zip", "zip bomb"),
    ("declared_oversize.zip", "above 200 MB"),
])
def test_unsafe_archives_are_refused(tmp_path, name, needle):
    res = run(stage(tmp_path, name))
    assert res.status is Status.ERROR and needle in res.error
    assert "x_archive" not in res.attributes and not list(tmp_path.glob("**/evil.js")) and not Path("/tmp/evil.js").exists()


def test_other_archive_refusals(tmp_path):
    cases = {
        "encrypted.zip": (zip_bytes({"data/tweets.js": TWEETS}, flag_bits=0x1), "encrypted member"),
        "symlink.zip": (zip_bytes({"data/tweets.js": TWEETS, "data/link.js": b"/etc/passwd"}, symlink="data/link.js"), "symlink member"),
        "backslash.zip": (zip_bytes({"data\\..\\tweets.js": TWEETS}), "backslash"),
        "members.zip": (zip_bytes({f"m/{i}.txt": b"x" for i in range(2001)}), "too many members"),
    }
    for name, (data, needle) in cases.items():
        res = run(stage(tmp_path, name, data=data))
        assert res.status is Status.ERROR and needle in res.error, (name, res.status, res.error)


def test_inflation_budget_is_enforced_while_reading(monkeypatch):
    monkeypatch.setitem(A.ARCHIVE_LIMITS, "total_bytes", 100)
    out = A.scan_x_archive(zip_bytes({"data/tweets.js": TWEETS}))
    assert out["state"] == "rejected" and out["reason_code"] == "size_cap"


def test_js_is_parsed_as_json_never_evaluated(tmp_path):
    res = run(stage(tmp_path, "malformed_js.zip"))
    assert res.status is Status.ERROR and "not JSON after the window.YTD prefix" in res.error
    assert A.parse_ytd_js("window.YTD.tweets.part0 = (function(){return []})()")["error"]
    assert A.parse_ytd_js('window.YTD.tweets.part0 = [{"a": 1}];')["data"] == [{"a": 1}]


def test_legacy_names_and_bare_tweets_js(tmp_path):
    res = run(stage(tmp_path, "legacy_tweet_js.zip"))
    assert res.status is Status.OK and res.attributes["x_archive"]["posts"] == 3
    res = run(stage(tmp_path, "tweets_only.js"))
    assert res.status is Status.OK and res.attributes["x_archive"]["single_file"] is True
    assert "data/account.js missing" in res.attributes["x_archive"]["warnings"][0]


def test_not_an_archive_is_not_applicable(tmp_path):
    res = run(stage(tmp_path, "not_archive.zip"))
    assert res.status is Status.SKIPPED and res.reason_code == "not_applicable"
    plain = tmp_path / "notes.txt"
    plain.write_text("hello", encoding="utf-8")
    res = run(plain)
    assert res.status is Status.SKIPPED and res.reason_code == "not_applicable"


def test_handle_mismatch_with_the_recorded_subject(tmp_path):
    res = run(stage(tmp_path, "ok.zip", provenance=dict(PROVENANCE, account_handle="@another_handle")))
    assert res.status is Status.OK
    assert any(f.title == "Archive account differs from the recorded subject" for f in res.findings)
