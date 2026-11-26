"""Licence profile and allow-list (A1, P377): expiry and the 12-month cap (fail closed), the research
basis requirement, key-terms with a business plan and the A1 initial classes of the seed fragments."""

from __future__ import annotations

import datetime as _dt
import json
import os

import pytest

from tests.fakes import provider_fragment
from v3lum import paths
from v3lum.config import Config
from v3lum.core import licence as L
from v3lum.core import providers as providers_mod
from v3lum.core.context import ScanOptions

NOW = _dt.datetime(2026, 11, 26, 12, 0, tzinfo=_dt.timezone.utc)


def entry(sid: str = "shodan.internetdb", decided: str = "2026-11-01", review: str = "2027-05-01", **over: str) -> dict[str, str]:
    data = {
        "source_id": sid, "basis": "provider_grant", "scope": "own-network defence only, no resale", "legal_ref": "LEGAL-1",
        "approver": "legal (DPO office)", "decided_at": decided, "review_by": review, "evidence_url": "https://example.com/terms", "quote": "permission granted",
    }
    data.update(over)
    return data


def write_allow(data: object, name: str = "licence_allow.json", mode: int = 0o600) -> os.PathLike[str]:
    path = paths.home() / name
    path.write_text(json.dumps(data), encoding="utf-8")
    path.chmod(mode)
    return path


# --------------------------------------------------------------------------------------
# dates, expiry, cap
# --------------------------------------------------------------------------------------


def test_add_months_clamps_to_month_end():
    assert L.add_months(_dt.date(2026, 11, 26), 12) == _dt.date(2027, 11, 26)
    assert L.add_months(_dt.date(2028, 2, 29), 12) == _dt.date(2029, 2, 28)
    assert L.add_months(_dt.date(2026, 1, 31), 1) == _dt.date(2026, 2, 28)
    assert L.add_months(_dt.date(2026, 12, 15), 1) == _dt.date(2027, 1, 15)


@pytest.mark.parametrize(
    ("decided", "review", "today", "active"),
    [
        ("2026-11-01", "2027-05-01", "2026-11-26", True),
        ("2026-11-01", "2027-05-01", "2027-05-01", True),  # the review day itself
        ("2026-11-01", "2027-05-01", "2027-05-02", False),  # expired: fail closed
        ("2026-11-01", "2027-11-01", "2027-06-01", True),  # exactly 12 months
        ("2026-11-01", "2027-11-02", "2026-11-26", False),  # beyond the 12-month cap: never active
        ("2026-12-01", "2027-06-01", "2026-11-26", False),  # not decided yet
        ("2026-11-01", "2026-10-01", "2026-10-15", False),  # review before decision
    ],
)
def test_entry_active_window_and_twelve_month_cap(decided, review, today, active):
    state = L.LicenceState.from_dict({"entries": [entry(decided=decided, review=review)]})
    assert state.active("shodan.internetdb", _dt.date.fromisoformat(today)) is active


def test_entry_beyond_cap_is_kept_but_reported():
    state = L.LicenceState.from_dict({"entries": [entry(review="2028-01-01")]})
    assert len(state.entries) == 1 and not state.active("shodan.internetdb", NOW)
    assert any("at most 12 months" in e for e in state.errors)


def test_malformed_entries_are_dropped_with_errors():
    data = {
        "schema": L.LICENCE_ALLOW_SCHEMA,
        "entries": [
            entry(sid="not a source id"),
            entry(basis="handshake"),
            entry(legal_ref=""),
            entry(review="soon"),
            "just text",
            entry(sid="shodan.cvedb"),
        ],
    }
    state = L.LicenceState.from_dict(data)
    assert [e.source_id for e in state.entries] == ["shodan.cvedb"]
    assert len([e for e in state.errors if "dropped" in e]) == 4
    assert any("must be an object" in e for e in state.errors)


def test_expiring_and_expired():
    state = L.LicenceState.from_dict({
        "entries": [
            entry(sid="a_prov.one", decided="2026-06-01", review="2026-12-10"),  # 14 days left
            entry(sid="a_prov.two", decided="2026-11-01", review="2027-05-01"),
            entry(sid="a_prov.three", decided="2025-10-01", review="2026-10-01"),  # expired
        ]
    })
    assert [e.source_id for e in state.expiring(NOW)] == ["a_prov.one"]
    assert [e.source_id for e in state.expiring(NOW, days=200)] == ["a_prov.one", "a_prov.two"]
    assert [e.source_id for e in state.expired(NOW)] == ["a_prov.three"]
    assert [e.source_id for e in state.active_entries(NOW)] == ["a_prov.one", "a_prov.two"]


def test_entry_for_prefers_the_latest_active_review():
    state = L.LicenceState.from_dict({"entries": [entry(review="2027-01-01", legal_ref="OLD"), entry(review="2027-05-01", legal_ref="NEW")]})
    assert state.entry_for("shodan.internetdb", NOW).legal_ref == "NEW"


# --------------------------------------------------------------------------------------
# loading
# --------------------------------------------------------------------------------------


def test_load_missing_default_file_is_empty_without_warning():
    state = L.LicenceState.load()
    assert state.entries == () and state.research_basis is None and state.warnings == [] and state.errors == []
    assert state.path.endswith("licence_allow.json")


def test_load_configured_missing_path_warns(tmp_path):
    cfg = Config()
    cfg.settings["licence_allow_path"] = str(tmp_path / "team" / "allow.json")
    state = L.LicenceState.load(config=cfg)
    assert state.entries == () and any("not a readable file" in w for w in state.warnings)


def test_load_from_setting_and_default_path():
    write_allow({"entries": [entry()]})
    assert L.LicenceState.load().active("shodan.internetdb", NOW)
    team = write_allow({"entries": [entry(sid="shodan.cvedb")]}, name="team_allow.json")
    cfg = Config()
    cfg.settings["licence_allow_path"] = str(team)
    loaded = L.LicenceState.load(config=cfg)
    assert loaded.active("shodan.cvedb", NOW) and not loaded.active("shodan.internetdb", NOW)
    assert len(loaded.sha256) == 64


def test_load_invalid_json_is_an_error():
    path = paths.home() / "licence_allow.json"
    path.write_text("{not json", encoding="utf-8")
    path.chmod(0o600)
    state = L.LicenceState.load()
    assert state.entries == () and any("invalid JSON" in e for e in state.errors)


@pytest.mark.skipif(os.name != "posix", reason="POSIX file modes")
def test_load_looser_than_0600_warns_and_writable_by_others_is_ignored():
    write_allow({"entries": [entry()]}, mode=0o644)
    state = L.LicenceState.load()
    assert state.active("shodan.internetdb", NOW) and any("looser than 0600" in w for w in state.warnings)
    write_allow({"entries": [entry()]}, mode=0o666)
    state = L.LicenceState.load()
    assert state.entries == () and any("ignored" in w for w in state.warnings)  # fail closed
    write_allow({"entries": [entry()]}, mode=0o660)
    assert L.LicenceState.load().entries == ()  # group-writable in the home: ignored too


def test_bare_entry_list_is_accepted():
    state = L.LicenceState.from_dict([entry()])
    assert state.active("shodan.internetdb", NOW)


# --------------------------------------------------------------------------------------
# research basis and profile resolution
# --------------------------------------------------------------------------------------


def basis(**over: object) -> dict[str, object]:
    data = {"legal_ref": "LEGAL-R", "approver": "legal", "date": "2026-11-01", "scope": ["shodan.internetdb", "abusech"]}
    data.update(over)
    return data


def test_research_basis_requirement_and_scope():
    state = L.LicenceState.from_dict({"research_basis": basis()})
    assert state.research_allowed(NOW)
    assert state.research_covers("shodan.internetdb", NOW) and state.research_covers("abusech.urlhaus", NOW)
    assert not state.research_covers("shodan.cvedb", NOW)
    star = L.LicenceState.from_dict({"research_basis": basis(scope="*")})
    assert star.research_covers("anything.source", NOW)
    wildcard = L.LicenceState.from_dict({"research_basis": basis(scope="shodan.*, other.thing")})
    assert wildcard.research_covers("shodan.cvedb", NOW) and wildcard.research_covers("other.thing", NOW)


def test_research_basis_free_text_scope_covers_nothing():
    state = L.LicenceState.from_dict({"research_basis": basis(scope="Academic research on phishing kits!")})
    assert state.research_allowed(NOW)
    assert not state.research_covers("shodan.internetdb", NOW)


@pytest.mark.parametrize(
    "prose",
    [
        "research on all phishing kits",  # 'all' is a word, never a wildcard
        "all",
        "everything except shodan",  # an exclusion must never read as an inclusion
        "no shodan use",
        "shodan.internetdb, academic use only",  # one prose word voids the whole scope
    ],
)
def test_research_basis_prose_scope_never_widens_the_profile(prose):
    state = L.LicenceState.from_dict({"research_basis": basis(scope=prose)})
    assert state.research_allowed(NOW)  # the profile itself stays selectable...
    for sid in ("shodan.internetdb", "abusech.urlhaus", "shodan.cvedb"):
        assert not state.research_covers(sid, NOW), (prose, sid)  # ...but it unlocks nothing
    assert any("prose covers nothing" in e for e in state.errors)
    src = providers_mod.registry().source("shodan.internetdb")
    verdict = L.evaluate_source(src, providers_mod.registry().get("shodan"), profile="research", now=NOW, state=state)
    assert not verdict.allowed


def test_research_basis_ids_and_registered_provider_words():
    for scope in ("shodan abusech", "shodan.internetdb, abusech.*", ["shodan", "abusech.urlhaus"], "*"):
        state = L.LicenceState.from_dict({"research_basis": basis(scope=scope)})
        assert state.research_covers("shodan.internetdb", NOW) and state.research_covers("abusech.urlhaus", NOW), scope
        assert state.errors == [], (scope, state.errors)
    unknown_word = L.LicenceState.from_dict({"research_basis": basis(scope="shodan notaprovider")})
    assert not unknown_word.research_covers("shodan.internetdb", NOW)  # a word that is no registered provider


def test_research_basis_unreadable_review_by_is_never_active():
    state = L.LicenceState.from_dict({"research_basis": basis(review_by="2027-13-45")})
    assert not state.research_allowed(NOW)  # never silently the 12-month default
    assert any("review_by must be a date" in e for e in state.errors)


@pytest.mark.parametrize("bad", ["2026-11-01garbage", "2026-11-1", "01/11/2026", "2026-11-01 later", "20261101"])
def test_entry_dates_must_be_iso_dates(bad):
    state = L.LicenceState.from_dict({"entries": [entry(decided=bad)]})
    assert state.entries == () and any("decided_at must be a date" in e for e in state.errors)


def test_entry_dates_accept_full_iso_datetimes():
    state = L.LicenceState.from_dict({"entries": [entry(decided="2026-11-01T09:30:00Z", review="2027-05-01T00:00:00+00:00")]})
    assert [(e.decided_at, e.review_by) for e in state.entries] == [("2026-11-01", "2027-05-01")]
    assert state.active("shodan.internetdb", NOW)


@pytest.mark.parametrize(
    "bad",
    [basis(legal_ref=""), basis(approver=""), basis(date="later"), basis(date="2025-06-01"), basis(review_by="2028-01-01"), basis(date="2027-01-01")],
)
def test_incomplete_expired_or_future_research_basis_is_not_allowed(bad):
    assert not L.LicenceState.from_dict({"research_basis": bad}).research_allowed(NOW)


def test_resolve_profile():
    cfg = Config()
    empty = L.LicenceState.empty()
    assert L.resolve_profile(cfg, ScanOptions(), state=empty) == "corporate"
    with pytest.raises(L.LicenceError) as err:
        L.resolve_profile(cfg, ScanOptions(licence_profile="research"), state=empty, now=NOW)
    assert str(err.value) == "licence_profile=research needs a recorded legal basis (docs/LEGAL.md)"
    allowed = L.LicenceState.from_dict({"research_basis": basis()})
    assert L.resolve_profile(cfg, ScanOptions(licence_profile="research"), state=allowed, now=NOW) == "research"
    cfg.settings["licence_profile"] = "research"
    assert L.resolve_profile(cfg, ScanOptions(), state=allowed, now=NOW) == "research"
    assert L.resolve_profile(cfg, ScanOptions(licence_profile="corporate"), state=empty) == "corporate"  # the flag wins
    with pytest.raises(L.LicenceError):
        L.resolve_profile(cfg, ScanOptions(licence_profile="anything-goes"), state=allowed)
    assert issubclass(L.LicenceError, ValueError)


def test_resolve_profile_loads_the_allow_list_when_not_given():
    write_allow({"research_basis": basis(date="2026-11-01")})
    cfg = Config()
    assert L.resolve_profile(cfg, ScanOptions(licence_profile="research"), now=NOW) == "research"


# --------------------------------------------------------------------------------------
# per-source evaluation
# --------------------------------------------------------------------------------------


def test_a1_initial_classes_of_the_seed_fragments():
    """abuse.ch MalwareBazaar/URLhaus/ThreatFox blocked, YARAify/Feodo/SSLBL allowed, InternetDB
    blocked under corporate (A1 BR11)."""
    reg = providers_mod.registry()
    expected = {
        "abusech.malwarebazaar": (False, "license"),
        "abusech.urlhaus": (False, "license"),
        "abusech.threatfox": (False, "license"),
        "abusech.yaraify": (True, "open"),
        "abusech.feodotracker": (True, "open"),
        "abusech.sslbl": (True, "open"),
        "shodan.internetdb": (False, "noncommercial"),
        "shodan.cvedb": (False, "noncommercial"),
        "shodan.api": (False, "key-terms"),
        "core_doh.resolvers": (True, "open"),
    }
    for sid, (allowed, cls) in expected.items():
        src = reg.source(sid)
        verdict = L.evaluate_source(src, reg.get(src.provider), profile="corporate", now=NOW)
        assert (verdict.allowed, verdict.terms_class) == (allowed, cls), sid
        ok, reason = L.source_allowed(src, reg.get(src.provider), profile="corporate", now=NOW, key_plan=None)
        assert ok is allowed
        if not allowed:
            assert reason == f"skipped: {cls} terms (licence profile corporate)"
    internetdb = L.evaluate_source(reg.source("shodan.internetdb"), reg.get("shodan"), now=NOW)
    assert "commercial Shodan subscription" in internetdb.remedy  # the registry's licensed alternative


def test_key_terms_needs_a_business_plan():
    reg = providers_mod.registry()
    src, prov = reg.source("shodan.api"), reg.get("shodan")
    assert not L.evaluate_source(src, prov, now=NOW).allowed
    assert not L.evaluate_source(src, prov, now=NOW, key_plan={"shodan": "free"}, keys=("shodan",)).allowed
    business = L.evaluate_source(src, prov, now=NOW, key_plan={"shodan": "business"}, keys=("shodan",))
    assert business.allowed and business.basis == "business_plan:shodan"
    assert L.evaluate_source(src, prov, now=NOW, key_plan="business").allowed  # a plan string for the source's key
    cfg = Config()
    cfg.settings["key_plans"] = {"shodan": "business"}
    via_config = L.evaluate_source(src, prov, now=NOW, key_plan=L.key_plan_lookup(cfg), keys=("shodan",))
    assert via_config.allowed and via_config.basis == "business_plan:shodan"
    assert L.key_plan_lookup({"key_plans": {"shodan": "free"}})("shodan") in ("", "free")
    blocked = L.evaluate_source(src, prov, now=NOW)
    assert blocked.remedy == "record a business plan: v3lum keys set shodan --plan business"


def test_key_terms_module_keys_only(clean_registry):
    """In the policy gate (module_keys_only) only the module's own keys of the source's provider can
    carry a business plan: another provider's business key, or a provider key the module does not
    send, never licenses the module's (keyless) requests."""
    reg = providers_mod.registry()
    src, prov = reg.source("shodan.api"), reg.get("shodan")
    plans = {"shodan": "business", "otx": "business"}
    # the module sends the shodan key: its business plan counts
    assert L.evaluate_source(src, prov, now=NOW, key_plan=plans, keys=("shodan",), module_keys_only=True).basis == "business_plan:shodan"
    # the module only has another provider's key: its requests to shodan are keyless
    other = L.evaluate_source(src, prov, now=NOW, key_plan=plans, keys=("otx",), module_keys_only=True)
    assert not other.allowed and other.remedy == "record a business plan: v3lum keys set shodan --plan business"
    assert not L.evaluate_source(src, prov, now=NOW, key_plan=plans, keys=(), module_keys_only=True).allowed
    # outside the gate (doctor --licences, no module context) the provider's declared key decides
    assert L.evaluate_source(src, prov, now=NOW, key_plan=plans, keys=()).allowed
    assert L.source_allowed(src, prov, now=NOW, key_plan=plans, keys=("otx",), module_keys_only=True)[0] is False
    # a provider that declares no key: only legacy keys without a recorded provider can decide
    providers_mod.register(provider_fragment("lic_nokey", hosts=("api.lic-nokey.example.test",), sources={
        "main": {"terms": {"class": "key-terms", "evidence_url": "https://e.example.test/", "quote": "q", "checked_at": "2026-11-26", "reviewer": "tests", "free_plan_business_use": None}},
    }), origin="tests")
    reg = providers_mod.registry()
    nokey_src, nokey = reg.source("lic_nokey.main"), reg.get("lic_nokey")
    assert not L.evaluate_source(nokey_src, nokey, now=NOW, key_plan=plans, keys=("otx",), module_keys_only=True).allowed  # otx belongs to otx
    legacy = L.evaluate_source(nokey_src, nokey, now=NOW, key_plan={"virustotal": "business"}, keys=("virustotal",), module_keys_only=True)
    assert legacy.allowed and legacy.basis == "business_plan:virustotal"


def test_key_terms_free_plan_business_use_runs_without_a_plan(clean_registry):
    fragment = provider_fragment("lic_free_biz", hosts=("api.lic-free-biz.example.test",), sources={
        "main": {"terms": {"class": "key-terms", "evidence_url": "https://e.example.test/", "quote": "free plan allows business use", "checked_at": "2026-11-26", "reviewer": "tests", "free_plan_business_use": True}},
    })
    providers_mod.register(fragment, origin="tests")
    reg = providers_mod.registry()
    verdict = L.evaluate_source(reg.source("lic_free_biz.main"), reg.get("lic_free_biz"), now=NOW)
    assert verdict.allowed and verdict.basis == "open"


def test_allow_entries_and_research_under_each_profile():
    reg = providers_mod.registry()
    src, prov = reg.source("abusech.urlhaus"), reg.get("abusech")
    allow = L.LicenceState.from_dict({"entries": [entry(sid="abusech.urlhaus", legal_ref="SUB-1")]})
    for profile in ("corporate", "research"):
        verdict = L.evaluate_source(src, prov, profile=profile, now=NOW, state=allow)
        assert verdict.allowed and verdict.basis == "allow:SUB-1"
    research = L.LicenceState.from_dict({"research_basis": basis()})
    assert not L.evaluate_source(src, prov, profile="corporate", now=NOW, state=research).allowed  # research needs the profile
    covered = L.evaluate_source(src, prov, profile="research", now=NOW, state=research)
    assert covered.allowed and covered.basis == "research:LEGAL-R"
    outside = L.evaluate_source(reg.source("shodan.cvedb"), reg.get("shodan"), profile="research", now=NOW, state=research)
    assert not outside.allowed and outside.reason.endswith("outside the research basis scope")
    # unknown terms stay disabled in every profile
    unknown = L.evaluate_source(None, None, profile="research", now=NOW, state=L.LicenceState.from_dict({"research_basis": basis(scope="*")}), source_id="ghost.source")
    assert not unknown.allowed and unknown.terms_class == "unknown" and unknown.source_id == "ghost.source"
    assert L.LicenceState.empty().source_allowed(src, prov, now=NOW) == (False, "skipped: license terms (licence profile corporate)")


def test_load_without_config_reads_the_setting_from_config_json(tmp_path):
    team = write_allow({"entries": [entry(sid="shodan.cvedb")]}, name="team_allow_2.json")
    cfg = Config()
    cfg.settings["licence_allow_path"] = str(team)
    cfg.save()
    state = L.LicenceState.load()  # no path, no config: Config.load() supplies the setting
    assert state.path == str(team) and state.active("shodan.cvedb", NOW)
