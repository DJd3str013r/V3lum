"""username_check_extended (P113 opt-in username pack): same engine, extended selection.

Fixtures: tests/fixtures/username_check_extended/ holds a trimmed Maigret database (MIT, claimed
handles replaced, credentials redacted) and its db_meta manifest; the per-site answers recorded
2026-11-26 (Dribbble, About.me, Kaggle official accounts and random controls) are shared with the
default pack in tests/fixtures/username_check/.
"""

from __future__ import annotations

import dataclasses
import json
import re
from types import SimpleNamespace
from typing import Any

import pytest

from tests.fakes import FakeHttp, make_ctx, module_fixture, run_module, test_provider
from v3lum import paths
from v3lum.core import datasets as datasets_mod
from v3lum.core import providers
from v3lum.core.entities import EntityType as T
from v3lum.core.models import Opsec, Status
from v3lum.core.module import register
from v3lum.modules.username_social import username_check as uc
from v3lum.modules.username_social.username_check_extended import UsernameCheckExtended

FIX = "username_check_extended"
SITE_FIX = "username_check"
SITES = {"v3lum:dribbble": "https://dribbble.com/{}", "v3lum:aboutme": "https://about.me/{}", "v3lum:kaggle": "https://www.kaggle.com/{}"}


def env(name: str) -> dict[str, Any]:
    return module_fixture(SITE_FIX, name)


def add_env(http: FakeHttp, url: Any, name: str) -> FakeHttp:
    e = env(name)
    return http.add("GET", url, status=e["status"], text=e["body"], headers=e["headers"])


def add_sherlock(http: FakeHttp) -> FakeHttp:
    http.add("GET", uc.SHERLOCK_URL, text=json.dumps(module_fixture(SITE_FIX, "sherlock_manifest_ok.json")))
    http.add("GET", uc.SHERLOCK_EXCLUSIONS_URL, text=module_fixture(SITE_FIX, "sherlock_exclusions_ok.txt"))
    return http


def maigret_db() -> dict[str, Any]:
    return module_fixture(FIX, "maigret_db_ok.json")


class _ReviewedRegistry:
    """The provider registry with some source terms recorded 'open' (what legal_dpo's review would do)."""

    def __init__(self, reg: Any, reviewed: set[str]) -> None:
        self._reg = reg
        self._reviewed = reviewed

    def source(self, sid: str) -> Any:
        src = self._reg.source(sid)
        if src is not None and sid in self._reviewed:
            return dataclasses.replace(src, terms=dataclasses.replace(src.terms, class_="open"))
        return src

    def __getattr__(self, name: str) -> Any:
        return getattr(self._reg, name)


# ------------------------------------------------------------------------------------- metadata
def test_metadata_matches_the_council_decision():
    cls = UsernameCheckExtended
    assert (cls.name, cls.run_on, cls.default_enabled, cls.category) == ("username_check_extended", "seeds", False, "username_social")
    assert (cls.opsec, cls.disclosure, cls.access_model) == (Opsec.PASSIVE, "third_party", "free_noauth_limited")
    assert cls.max_requests == 600 and cls.timeout >= uc.EXTENDED_DEADLINE and cls.min_interval >= 1.0  # FC1/FC10
    assert {"pack", "curated_pack", "slow", "people_sweep"} <= cls.tags
    assert cls.hosts == uc.pack_hosts("username_check_extended") == ("about.me", "dribbble.com", "www.kaggle.com")
    assert {uc.SRC_MAIGRET, uc.SRC_MAIGRET_META, "about_me.profile_page", "dribbble.profile_page", "kaggle.profile_page"} <= set(cls.sources)
    # terms = the most restrictive site source: the three sites await legal_dpo (A1 'unknown')
    assert cls.terms == "unknown" == providers.most_restrictive(providers.registry().source(s).terms.class_ for s in cls.sources)
    assert cls.trust_tier == "community" and cls.load_pack().default is False


def test_maigret_dataset_is_pinned_update_only_and_verified():
    reg = datasets_mod.DATASETS[uc.MAIGRET_DATA]
    assert reg["large"] is True and reg["source"] == uc.SRC_MAIGRET and reg["licence"] == "MIT" and callable(reg["validate"])
    assert uc.MAIGRET_META < uc.MAIGRET_DATA  # `v3lum data update` refreshes the manifest first (sorted names)
    assert datasets_mod.DATASETS[uc.WMN]["pinned_sha256"] == uc.WMN_SHA256
    assert datasets_mod.dataset_errors() == []


# ------------------------------------------------------------------------------ the bundled pack
def test_sites_without_reviewed_terms_never_receive_the_handle():
    """FC16/A1: About.me, Dribbble and Kaggle terms are 'unknown': skipped (licence), listed in coverage."""
    http = add_sherlock(FakeHttp())
    res = run_module(UsernameCheckExtended, "username:exampleorg", http)
    assert res.status is Status.SKIPPED and res.reason_code == "licence"
    assert not any(h in u for u in http.urls() for h in ("dribbble.com", "about.me", "kaggle.com"))
    assert res.attributes["site_checks_coverage"] == "skipped: 3 licence"
    for sid in ("about_me.profile_page", "dribbble.profile_page", "kaggle.profile_page"):
        assert res.source_statuses[sid]["status"] == "skipped" and res.source_statuses[sid]["reason_code"] == "licence"
    http.assert_hosts_within(UsernameCheckExtended, extra=("raw.githubusercontent.com",))


def test_selftest_skips_sites_without_reviewed_terms():
    http = FakeHttp()
    result = uc.run_selftest(UsernameCheckExtended, make_ctx(UsernameCheckExtended, http))
    assert result.status == "ok" and "no site to self-test" in result.detail and http.urls() == []


def test_once_terms_are_reviewed_the_calibrated_sites_answer_tri_state(monkeypatch):
    reviewed = _ReviewedRegistry(providers.registry(), {"about_me.profile_page", "dribbble.profile_page", "kaggle.profile_page"})
    monkeypatch.setattr(uc, "_providers", SimpleNamespace(registry=lambda: reviewed))
    http = add_sherlock(FakeHttp())
    add_env(http, SITES["v3lum:dribbble"].format("dribbble"), "dribbble_ok.json")
    add_env(http, re.compile(r"^https://dribbble\.com/[a-z][a-z0-9]{19}$"), "dribbble_not_found.json")
    add_env(http, SITES["v3lum:aboutme"].format("dribbble"), "aboutme_redirect.json")
    add_env(http, SITES["v3lum:kaggle"].format("dribbble"), "kaggle_not_found.json")
    res = run_module(UsernameCheckExtended, "username:dribbble", http)
    assert res.status is Status.OK
    assert res.attributes["site_checks"] == "username_check_extended: 1 found · 1 could not verify · 1 absent · 0 not checked: budget"
    assert res.attributes["site_checks_coverage"] == "1 unexpected redirect"
    (finding,) = res.findings
    assert finding.title == "Same handle found on Dribbble" and finding.source == "dribbble.profile_page"
    assert res.attributes["profiles"][0]["url"] == "https://dribbble.com/dribbble"
    assert res.source_statuses["about_me.profile_page"]["status"] == "error"  # could not verify (redirect)
    states = {e["url"]: e["state"] for e in res.raw["sites"]}
    assert states[SITES["v3lum:kaggle"].format("dribbble")] == "absent"  # reCAPTCHA words on a 404 are not a block
    http.assert_hosts_within(UsernameCheckExtended, extra=("raw.githubusercontent.com",))


# ------------------------------------------------------------------------------ Maigret entries
MAIGRET_SOURCE = "t_username_mg.profile"


def _maigret_dataset() -> dict[str, Any]:
    """Maigret-format entries (the three check types and the curated-profile exclusions) on example.test."""
    host = "https://mg{}.example.test"
    return {
        "sites": {
            "MsgSite": {"url": host.format(1) + "/user/{username}", "urlMain": host.format(1), "checkType": "message",
                        "presenseStrs": ["Perfil de"], "absenceStrs": ["\"error\":\"Not Found\""], "tags": ["br", "tech"], "usernameClaimed": "example-claimed"},
            "StatusSite": {"url": host.format(2) + "/usuario/{username}", "urlMain": host.format(2), "checkType": "status_code", "tags": ["br"]},
            "RespSite": {"url": host.format(3) + "/u/{username}", "urlProbe": host.format(3) + "/api/profiles/{username}", "urlMain": host.format(3), "checkType": "response_url"},
            "EngineSite": {"engine": "XenForo", "urlMain": host.format(4), "tags": ["forum"]},
            "ProtectedSite": {"url": host.format(5) + "/perfil/{username}", "urlMain": host.format(5), "checkType": "message", "presenseStrs": ["x"],
                              "absenceStrs": ["y"], "protection": ["tls_fingerprint"]},
        },
        "engines": {"XenForo": {"site": {"url": "{urlMain}/members/?username={username}", "checkType": "message", "absenceStrs": ["no member"]}}},
        "tags": ["br"],
    }


@pytest.fixture
def maigret_pack(clean_registry):
    ids = tuple(f"maigret:{n}" for n in ("MsgSite", "StatusSite", "RespSite", "EngineSite", "ProtectedSite"))
    hosts = tuple(f"mg{i}.example.test" for i in range(1, 6))
    sites = {sid: {"name": sid.split(":")[1], "provider": "t_username_mg", "source": MAIGRET_SOURCE, "hosts": [hosts[i]],
                   "tier": "community", "tier_rationale": "test site", "calibration": {"verdict": "correct"}} for i, sid in enumerate(ids)}
    overlay = uc.parse_overlay({"sites": sites})
    with test_provider("t_username_mg", hosts=hosts, tier="community", sources=("profile",)):

        class SyntheticExtended(uc.UsernamePackBase):
            name = "t_username_extended"
            title = "synthetic extended pack"
            description = "synthetic Maigret entries over example.test hosts"
            category = "username_social"
            accepts = {T.USERNAME}
            terms = "open"
            opsec = Opsec.PASSIVE
            disclosure = "third_party"
            hosts = tuple(sorted(f"mg{i}.example.test" for i in range(1, 6)))
            max_requests = 600
            expected_latency = 60.0
            provider = "t_username_mg"
            sources = (MAIGRET_SOURCE, uc.SRC_MAIGRET, uc.SRC_SHERLOCK, uc.SRC_SHERLOCK_EXCLUSIONS)
            access_model = "free_noauth_limited"
            timeout = uc.EXTENDED_DEADLINE + uc.GRACE
            min_interval = 1.0
            tags = {"pack", "curated_pack", "slow"}
            default_enabled = False
            run_on = "seeds"
            pack_id = "t_username_extended"
            default_pack = False

            @classmethod
            def load_pack(cls) -> uc.Pack:
                return uc.Pack("t_username_extended", ids, overlay, {}, False, uc._bundled()["collision"])

        yield register(SyntheticExtended)


def test_missing_maigret_database_is_unavailable_never_downloaded_mid_run(maigret_pack):
    http = add_sherlock(FakeHttp())
    res = run_module(maigret_pack, "username:exampleorg", http)
    assert res.status is Status.UNAVAILABLE and res.reason_code == "dataset"
    assert res.source_statuses[uc.SRC_MAIGRET]["reason_code"] == "dataset"
    assert uc.MAIGRET_DATA_URL not in http.urls()


def test_maigret_check_types_run_and_the_curated_profile_filters_hold(maigret_pack):
    (paths.datasets_dir() / uc.MAIGRET_DATA).write_text(json.dumps(_maigret_dataset()), encoding="utf-8")
    http = add_sherlock(FakeHttp())
    http.add("GET", "https://mg1.example.test/user/exampleorg", text="<h1>Perfil de Example Org</h1>")
    http.add("GET", re.compile(r"^https://mg1\.example\.test/user/[a-z][a-z0-9]{19}$"), status=404, text='{"error":"Not Found"}')
    http.add("GET", "https://mg2.example.test/usuario/exampleorg", status=404, text="not here")
    http.add("GET", "https://mg3.example.test/api/profiles/exampleorg", status=302, text="", headers={"location": "/en-us/"})
    res = run_module(maigret_pack, "username:exampleorg", http)
    assert res.attributes["site_checks"] == "t_username_extended: 1 found · 0 could not verify · 2 absent · 0 not checked: budget"
    assert res.attributes["profiles"][0]["url"] == "https://mg1.example.test/user/exampleorg"
    skipped = {s["site"]: s["reason"] for s in res.raw["skipped"]}
    assert skipped["maigret:EngineSite"].startswith("engine entry")
    assert skipped["maigret:ProtectedSite"].startswith("anti-bot protection")
    assert not any(h in u for u in http.urls() for h in ("mg4.example.test", "mg5.example.test"))
    assert uc.MAIGRET_DATA in {d["name"] for d in res.datasets}


def test_maigret_update_needs_the_db_meta_sha256(tmp_path):
    data = json.dumps(maigret_db()).encode()
    good_meta = dict(module_fixture(FIX, "maigret_db_meta_ok.json"), data_sha256=uc.sha256_hex(data))
    target = tmp_path / ".tmp-candidate"
    target.write_bytes(data)
    (tmp_path / uc.MAIGRET_META).write_text(json.dumps(good_meta), encoding="utf-8")
    assert uc._validate_maigret(target) is True
    (tmp_path / uc.MAIGRET_META).write_text(json.dumps(module_fixture(FIX, "maigret_db_meta_ok.json")), encoding="utf-8")
    with pytest.raises(ValueError, match="sha256 mismatch"):
        uc._validate_maigret(target)
    (tmp_path / uc.MAIGRET_META).unlink()
    with pytest.raises(ValueError, match="not downloaded"):
        uc._validate_maigret(target)


def test_db_meta_parse_and_update_plan():
    meta = uc.parse_maigret_db_meta(json.dumps(module_fixture(FIX, "maigret_db_meta_ok.json")))
    assert meta["ok"] and meta["sites_count"] == 11640 and len(meta["data_sha256"]) == 64
    assert uc.parse_maigret_db_meta(module_fixture(FIX, "maigret_db_meta_not_found.txt"))["error"] == "download answered '404: Not Found'"
    assert uc.maigret_update_plan(meta, meta["data_sha256"])["action"] == "keep"
    assert uc.maigret_update_plan(meta, "0" * 64)["action"] == "download"
    assert uc.maigret_update_plan(meta, None, b"other bytes")["action"] == "reject"
    assert uc.maigret_update_plan({"ok": False, "error": "x"}, None)["action"] == "keep"


def test_maigret_normalisation_and_curated_profile_rules():
    parsed = uc.parse_maigret_db(json.dumps(maigret_db()))
    assert parsed["ok"] and "XenForo" in parsed["engines"]
    sites = {s["name"]: s for s in parsed["sites"]}
    engine = sites["valinor.com.br"]
    assert engine["engine"] == "XenForo" and engine["check_url"].endswith("/members/?username={username}")  # engine template merged
    reasons = uc.pack_filter_reasons(engine, pack="username_check_extended")
    assert any(r.startswith("engine entry") for r in reasons)
    assert "disabled in dataset" in uc.pack_filter_reasons(sites["Raidforums"], pack="username_check_extended")
    assert uc.pack_filter_reasons(sites["Filmow"], pack="username_check_extended") == []
    default = uc.pack_filter_reasons(sites["Filmow"], pack="username_check")
    assert any("two-sided" in r or "presence AND absence" in r for r in default)
    assert any("Maigret back-fill" in r for r in uc.pack_filter_reasons(sites["Alura"], pack="username_check"))
