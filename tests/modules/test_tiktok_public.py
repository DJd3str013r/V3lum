"""Offline tests of tiktok_public (P118) on tests/fixtures/tiktok_public/.

No live TikTok answer could be captured: the terms class is 'license' and P118 FC2 allows automation only with
TikTok's written permission, so profile_ok.html wraps the research subset of the official @tiktok hydration
(2026-11-25) and every other page is synthetic (markers from community tooling). Recapture at the first licensed run.
"""

from __future__ import annotations

import json
import os

import pytest

from tests.fakes import FakeHttp, make_runtime, module_fixture, run_module
from v3lum.core.context import ScanOptions
from v3lum.core.models import Status
from v3lum.modules.username_social.tiktok_public import (
    TiktokPublic,
    _selftest,
    normalise_tiktok_handle,
    parse_tiktok_profile,
    tiktok_fetch_allowed,
)

FIX = "tiktok_public"
PAGE = "https://www.tiktok.com/@{}"
HTML = {"content-type": "text/html; charset=utf-8"}


def allow_file(tmp_path, basis: str = "provider_grant") -> dict:
    entry = {"source_id": "tiktok.profile_page", "basis": basis, "scope": "brand-abuse investigations of the company",
             "legal_ref": "LEGAL-2026-099", "approver": "legal", "decided_at": "2026-11-01", "review_by": "2027-10-31",
             "evidence_url": "https://www.tiktok.com/legal/page/row/terms-of-service/en", "quote": "written permission on file"}
    path = tmp_path / "licence_allow.json"
    path.write_text(json.dumps({"schema": "v3lum.licence_allow/1", "entries": [entry]}), encoding="utf-8")
    os.chmod(path, 0o600)
    return {"licence_allow_path": str(path)}


def page(name: str) -> dict:
    return {"text": module_fixture(FIX, name), "headers": HTML}


def run(entity: str, http: FakeHttp, settings: dict | None = None, **kw):
    return run_module(TiktokPublic, entity, http, settings=settings or {}, **kw)


def test_not_cleared_emits_only_the_manual_link(tmp_path):
    http = FakeHttp()
    res = run("username:tiktok", http)
    assert res.status is Status.SKIPPED and res.reason_code == "licence" and not http.calls
    assert ("TikTok profile (manual, automation skipped: licence)", "https://www.tiktok.com/@tiktok") in [tuple(x) for x in res.links]
    res = run("username:tiktok", http, settings=allow_file(tmp_path, basis="terms_clause"))
    assert res.status is Status.SKIPPED and "not a provider grant" in res.error and not http.calls  # FC2: no terms_clause basis


def test_provider_grant_reads_only_the_fc5_fields(tmp_path):
    http = FakeHttp().add("GET", PAGE.format("tiktok"), **page("profile_ok.html"))
    res = run("username:tiktok", http, settings=allow_file(tmp_path))
    assert res.status is Status.OK and len(http.calls) == 1
    facts = res.attributes["platform_facts"]
    assert set(facts) <= {"handle", "display_name", "verified", "follower_count", "account_id", "created", "created_epoch", "profile_url"}
    assert facts["account_id"] == "107955" and res.attributes["verified"] is True and res.attributes["followers"] == 97100000
    assert "created" not in facts  # the legacy small id is not time-based (P314 out_of_window)
    blob = json.dumps(res.to_dict(), default=str)
    for hidden in ("secUid", "MS4wLjABAAAAv7iSuuXDJGDvJkmH", "Your next discovery", "470100000", "privateAccount"):
        assert hidden not in blob, hidden
    assert ("TikTok profile (manual)", "https://www.tiktok.com/@tiktok") in [tuple(x) for x in res.links]
    http.assert_hosts_within(TiktokPublic)


def test_bio_link_is_a_passive_only_pivot_and_the_id_gives_the_creation_date(tmp_path):
    http = FakeHttp().add("GET", PAGE.format("example.shop"), **page("profile_biolink_synthetic.html"))
    res = run("url:https://www.tiktok.com/@example.shop", http, settings=allow_file(tmp_path))
    assert res.status is Status.OK
    assert res.attributes["created"] == "2021-03-04T05:06:07Z"
    assert "Bellingcat" in res.attributes["created_epoch"]
    [pv] = res.pivots
    assert pv.entity.value == "https://shop.example.com/tiktok" and pv.expand is False and pv.relation == "link_on_profile"


def test_challenge_is_blocked_and_short_circuits_the_host(tmp_path):
    settings = allow_file(tmp_path)
    http = (FakeHttp().add("GET", PAGE.format("tiktok"), **page("challenge_synthetic.html"))
            .add("GET", PAGE.format("example.shop"), **page("profile_biolink_synthetic.html")))
    rt = make_runtime(http, settings=settings)
    res = run_module(TiktokPublic, "username:tiktok", http, runtime=rt, case_id="case-1")
    assert res.status is Status.BLOCKED and res.reason_code == "challenge"
    res = run_module(TiktokPublic, "username:example.shop", http, runtime=rt, case_id="case-1")
    assert res.status is Status.BLOCKED and res.reason_code == "circuit"
    assert len(http.calls) == 1  # never retried, the rest of the run sends nothing


@pytest.mark.parametrize("name", ["empty_hydration_synthetic.html", "empty_page_synthetic.html", "empty_user_detail_synthetic.html"])
def test_empty_hydration_is_blocked_never_empty(tmp_path, name):
    http = FakeHttp().add("GET", PAGE.format("tiktok"), **page(name))
    res = run("username:tiktok", http, settings=allow_file(tmp_path))
    assert res.status is Status.BLOCKED and res.reason_code == "challenge"


@pytest.mark.parametrize("name", ["layout_changed_synthetic.html", "missing_keys_synthetic.html", "no_hydration_synthetic.html",
                                  "unknown_status_synthetic.html"])
def test_layout_change_is_error_never_empty(tmp_path, name):
    http = FakeHttp().add("GET", PAGE.format("tiktok"), **page(name))
    res = run("username:tiktok", http, settings=allow_file(tmp_path))
    assert res.status is Status.ERROR and "layout changed" in res.error


def test_documented_not_found_code_is_absent(tmp_path):
    http = FakeHttp().add("GET", PAGE.format("tiktok"), **page("not_found_synthetic.html"))
    res = run("username:tiktok", http, settings=allow_file(tmp_path))
    assert res.status is Status.EMPTY and res.attributes["presence"]["state"] == "absent"


def test_rate_limit_is_never_retried(tmp_path):
    http = FakeHttp().add("GET", PAGE.format("tiktok"), status=429, text="slow down", headers={"retry-after": "5"})
    res = run("username:tiktok", http, settings=allow_file(tmp_path))
    assert res.status is Status.RATE_LIMITED and len(http.calls) == 1


def test_mismatch_and_oversized_hydration_are_errors(tmp_path):
    http = FakeHttp().add("GET", PAGE.format("someone"), **page("profile_ok.html"))
    res = run("username:someone", http, settings=allow_file(tmp_path))
    assert res.status is Status.ERROR and "handle mismatch" in res.error
    big = ('<html><body><script id="__UNIVERSAL_DATA_FOR_REHYDRATION__" type="application/json">{"x":"'
           + "a" * (2 * 1024 * 1024 + 10) + '"}</script></body></html>')
    assert parse_tiktok_profile(200, HTML, big, "tiktok")["reason"] == "hydration element over the 2 MB cap"


def test_seeds_only_and_typed_handles():
    http = FakeHttp()
    res = run_module(TiktokPublic, "username:tiktok", http, is_seed=False, depth=1)
    assert res.status is Status.SKIPPED and res.reason_code == "privacy" and not http.calls
    assert normalise_tiktok_handle("@Example.Shop") == "Example.Shop"
    assert normalise_tiktok_handle("https://www.tiktok.com/@example.shop/video/6935660794721884762") == "example.shop"
    assert normalise_tiktok_handle("https://example.com/@x") is None


def test_fetch_guard_refuses_oembed_api_video_and_signed_urls():
    assert tiktok_fetch_allowed("https://www.tiktok.com/@tiktok")
    for url in ("https://www.tiktok.com/oembed?url=https://www.tiktok.com/@tiktok/video/1",
                "https://www.tiktok.com/api/user/detail/?uniqueId=tiktok",
                "https://www.tiktok.com/@tiktok/video/6935660794721884762",
                "https://www.tiktok.com/@tiktok?msToken=x&X-Bogus=y",
                "http://www.tiktok.com/@tiktok", "https://m.tiktok.com/@tiktok"):
        assert not tiktok_fetch_allowed(url), url


def test_doctor_self_test_never_runs_without_the_licence(tmp_path):
    from tests.fakes import make_ctx

    ctx = make_ctx(TiktokPublic, FakeHttp(), options=ScanOptions())
    assert _selftest(ctx).status == "blocked"
    http = FakeHttp().add("GET", PAGE.format("tiktok"), **page("profile_ok.html"))
    ctx = make_ctx(TiktokPublic, http, settings=allow_file(tmp_path))
    assert _selftest(ctx).status == "ok"


def test_metadata_matches_the_council_decision():
    m = TiktokPublic
    assert m.terms == "license" and m.default_enabled is False and m.run_on == "seeds"
    assert m.min_interval >= 5.0 and m.max_requests == 1 and m.hosts == ("www.tiktok.com",)
    assert m.trust_tier == "trusted"
