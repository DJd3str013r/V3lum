"""Config v2: core defaults, the settings registry, the key registry, key plans, 0600 writes, redaction."""

from __future__ import annotations

import json
import os
import stat
import threading

import pytest

from v3lum import __version__, config, paths
from v3lum.config import (
    DEFAULT_SETTINGS,
    KNOWN_KEYS,
    SETTINGS_META,
    Config,
    SettingSpec,
    key_env_names,
    key_registry,
    mask,
    register_settings,
)
from v3lum.core import providers

NEW_DEFAULTS = {
    "tlp": "amber",
    "licence_profile": "corporate",
    "licence_allow_path": "",
    "key_plans": {},
    "scan_deadline": 90.0,
    "preset": "quick",
    "min_expand_confidence": 0.5,
    "retention_days": 180,
    "cache_max_age_days": 30,
    "audit_retention_days": 0,
    "org_profile_path": "",
    "egress_country": "",
    "proxy_light": "",
    "proxy_active": "",
    "contact_email": "",
    "contact_url": "",
    "ca_bundle": "",
    "doh_providers": ["google", "cloudflare"],
    "doh_internal": "",
    "light_for_own_assets": False,
    "sightings_personal": False,
    "sensitive_sites": False,
    "skip_keyed_when_answered": False,
    "quota_db_path": "",
    "plugins_enabled": False,
    "plugin_allow": [],
    "defang": True,
    "analyst": "",
    "default_purpose": "",
    "default_ticket": "",
    "default_legal_basis": "",
    "misp_url": "",
    "opencti_url": "",
    "certstream_url": "",
    "watch_interval": 3600,
    "watch_max_runtime": 28800,
    "watch_max_alerts": 0,
    "watch_enrich_per_hour": 30,
    "evidence_max_file_bytes": 5000000,
    "evidence_max_case_bytes": 200000000,
    "attack_surface_min_assets": 20,
}
LEGACY_SETTINGS = (
    "mode", "depth", "threads", "timeout", "max_entities", "cache_ttl", "dns_mode", "doh_provider", "proxy",
    "user_agent", "default_region", "report_dir", "report_formats", "feedback", "fx", "nsfw_sites",
)


@pytest.fixture()
def settings_state():
    saved = dict(SETTINGS_META)
    yield
    SETTINGS_META.clear()
    SETTINGS_META.update(saved)


@pytest.fixture()
def registry_state():
    state = providers.snapshot()
    yield
    providers.restore(state)


def _config_path():
    return paths.config_file()


# ---------------------------------------------------------------------------------- defaults


def test_new_defaults():
    for name, default in NEW_DEFAULTS.items():
        assert DEFAULT_SETTINGS[name] == default, name
    cfg = Config()
    assert cfg.get("tlp") == "amber"
    assert cfg.get("licence_profile") == "corporate"
    ua = cfg.get("user_agent")
    assert ua == f"V3LUM/{__version__}" and ua.startswith("V3LUM/")
    assert "Mozilla" not in ua and "@" not in ua  # neutral: no browser spoofing, no mailbox (P326)
    assert "Mozilla/5.0" in cfg.get("ua_light")  # LIGHT/ACTIVE contact uses a common browser UA


def test_legacy_settings_kept_and_described():
    for name in LEGACY_SETTINGS:
        assert name in DEFAULT_SETTINGS
    assert list(DEFAULT_SETTINGS)[: len(LEGACY_SETTINGS)] == list(LEGACY_SETTINGS)
    for name, default in DEFAULT_SETTINGS.items():
        spec = SETTINGS_META[name]
        assert isinstance(spec, SettingSpec) and spec.owner == "core" and spec.description, name
        assert spec.default == default
        json.dumps(default)
    assert SETTINGS_META["tlp"].choices == ("clear", "green", "amber", "amber+strict", "red")
    assert SETTINGS_META["licence_profile"].choices == ("corporate", "research")


def test_default_settings_are_not_shared_between_configs():
    a, b = Config(), Config()
    a.settings["key_plans"]["shodan"] = "business"
    a.settings["doh_providers"].append("quad9")
    assert b.get("key_plans") == {} and DEFAULT_SETTINGS["key_plans"] == {}
    assert DEFAULT_SETTINGS["doh_providers"] == ["google", "cloudflare"]


# ---------------------------------------------------------------------------------- settings registry


def test_module_setting_registration_get_set(settings_state):
    register_settings("synth_mod", {"synth_mod_limit": 5, "synth_mod_tags": ["a"], "synth_mod_map": {}})
    cfg = Config()
    assert cfg.get("synth_mod_limit") == 5
    assert SETTINGS_META["synth_mod_limit"].owner == "synth_mod"
    cfg.set("synth_mod_limit", "7")
    assert cfg.get("synth_mod_limit") == 7
    cfg.set("synth_mod_tags", "x, y ,z")
    assert cfg.get("synth_mod_tags") == ["x", "y", "z"]
    cfg.set("synth_mod_map", '{"a": 1}')
    assert cfg.get("synth_mod_map") == {"a": 1}
    with pytest.raises(ValueError):
        cfg.set("synth_mod_map", "[1, 2]")
    reloaded = Config.load()
    assert reloaded.get("synth_mod_limit") == 7 and reloaded.get("synth_mod_tags") == ["x", "y", "z"]
    register_settings("synth_mod", {"synth_mod_limit": 5, "synth_mod_tags": ["a"], "synth_mod_map": {}})  # idempotent
    with pytest.raises(KeyError):
        cfg.set("synth_unknown_setting", "1")


def test_module_setting_collisions(settings_state):
    with pytest.raises(ValueError, match="core setting"):
        register_settings("synth_mod", {"tlp": "red"})
    register_settings("synth_mod", {"synth_shared": 1})
    with pytest.raises(ValueError, match="already registered by synth_mod"):
        register_settings("other_mod", {"synth_shared": 2})
    with pytest.raises(ValueError, match="must match"):
        register_settings("synth_mod", {"Bad-Name": 1})
    with pytest.raises(ValueError, match="JSON-serialisable"):
        register_settings("synth_mod", {"synth_obj": object()})
    assert config.unregister_settings("synth_mod") == ["synth_shared"]
    register_settings("other_mod", {"synth_shared": 2})
    assert config.settings_for("other_mod")["synth_shared"].default == 2
    assert config.unregister_settings("core") == [] and "tlp" in SETTINGS_META


def test_reregistration_replaces_the_owner_settings(settings_state):
    register_settings("synth_mod", {"synth_a": 1, "synth_b": 2})
    register_settings("synth_mod", {"synth_a": 1})
    assert "synth_b" not in SETTINGS_META and "synth_a" in SETTINGS_META


def test_module_settings_saved_before_registration_survive(settings_state):
    _config_path().write_text(json.dumps({"settings": {"later_mod_limit": 9, "depth": 3}, "keys": {}}), encoding="utf-8")
    cfg = Config.load()
    assert cfg.get("depth") == 3 and cfg.get("later_mod_limit") == 9
    cfg.set("threads", "4")  # saving keeps the not-yet-registered module setting
    assert json.loads(_config_path().read_text(encoding="utf-8"))["settings"]["later_mod_limit"] == 9
    register_settings("later_mod", {"later_mod_limit": 1})
    assert Config.load().get("later_mod_limit") == 9


def test_set_validates_types_and_choices():
    cfg = Config()
    cfg.set("tlp", "amber+strict")
    assert cfg.get("tlp") == "amber+strict"
    with pytest.raises(ValueError, match="expected one of clear, green, amber, amber\\+strict, red"):
        cfg.set("tlp", "purple")
    with pytest.raises(ValueError, match="choices"):
        cfg.set("licence_profile", "anything")
    with pytest.raises(ValueError, match="choices"):
        cfg.set("doh_providers", "google,opendns")
    cfg.set("doh_providers", "cloudflare,google")
    assert cfg.get("doh_providers") == ["cloudflare", "google"]
    cfg.set("defang", "false")
    assert cfg.get("defang") is False
    with pytest.raises(ValueError):
        cfg.set("defang", "maybe")
    with pytest.raises(ValueError):
        cfg.set("retention_days", "a lot")
    cfg.set("key_plans", '{"github": "free"}')
    assert cfg.get("key_plans") == {"github": "free"}


def test_env_overrides(monkeypatch, settings_state):
    monkeypatch.setenv("V3LUM_TLP", "red")
    monkeypatch.setenv("V3LUM_RETENTION_DAYS", "30")
    monkeypatch.setenv("V3LUM_DEFANG", "not-a-bool")  # malformed override: ignored, default kept
    register_settings("synth_mod", {"synth_mod_limit": 5})
    monkeypatch.setenv("V3LUM_SYNTH_MOD_LIMIT", "11")
    cfg = Config.load()
    assert cfg.get("tlp") == "red" and cfg.get("retention_days") == 30 and cfg.get("defang") is True
    assert cfg.get("synth_mod_limit") == 11
    register_settings("late_mod", {"late_mod_depth": 2})  # registered after the config was loaded
    monkeypatch.setenv("V3LUM_LATE_MOD_DEPTH", "4")
    assert cfg.get("late_mod_depth") == 4
    monkeypatch.setenv("V3LUM_LATE_MOD_DEPTH", "four")
    assert cfg.get("late_mod_depth") == 2
    monkeypatch.setenv("V3LUM_KEY_PLANS", '{"x": "business"}')  # V3LUM_KEY_* is reserved for API keys
    assert Config.load().get("key_plans") == {}


# ---------------------------------------------------------------------------------- key registry


def test_known_keys_structure_unchanged():
    assert len(KNOWN_KEYS) == 28
    for name, spec in KNOWN_KEYS.items():
        desc, url, aliases = spec
        assert isinstance(desc, str) and isinstance(url, str) and isinstance(aliases, tuple), name


def test_key_registry_union_of_legacy_and_fragment_keys():
    reg = key_registry()
    assert set(KNOWN_KEYS) <= set(reg)
    fragment_keys = providers.registry().keys()
    assert {"shodan", "github", "abusech", "misp", "opencti"} <= set(fragment_keys)
    assert set(fragment_keys) <= set(reg)
    assert len(reg) == len(set(KNOWN_KEYS) | set(fragment_keys))
    assert reg["github"].env == ("GITHUB_TOKEN", "GH_TOKEN") and reg["github"].provider == "github"
    assert reg["misp"].env == ("MISP_API_KEY",) and reg["misp"].provider == "internal_misp"
    assert reg["opencti"].env == ("OPENCTI_TOKEN",)
    assert reg["virustotal"].provider == "" and reg["virustotal"].env == ("VT_API_KEY", "VIRUSTOTAL_API_KEY")
    assert all(not spec.multi_key for spec in reg.values())


def test_key_registry_unions_aliases_and_prefers_fragment_text(registry_state):
    providers.register({
        "schema": "v3lum.provider/1", "id": "synth_vt", "name": "Synthetic", "operator": "tests", "hosts": ["vt.synth.example"],
        "hosts_from_settings": [], "internal": False, "tier": "trusted", "tier_rationale": "tests", "tier_reviewer": "tests",
        "tier_date": "2026-11-26",
        "flags": {"publishes_queries": False, "reuses_queries": False, "fetches_target": False, "sensitive": False},
        "personal_data_review": None, "reliability": {"grade": "B", "justification": "tests"}, "http_profile": {},
        "quota": None, "error_markers": [],
        "keys": {"virustotal": {"description": "VirusTotal (fragment text)", "signup_url": "https://vt.synth.example/key", "env": ["VT_KEY_ALT", "VT_API_KEY"], "multi_key": False, "plan_hint": "business"}},
        "sources": {},
    })
    spec = key_registry()["virustotal"]
    assert spec.env == ("VT_API_KEY", "VIRUSTOTAL_API_KEY", "VT_KEY_ALT")
    assert spec.description == "VirusTotal (fragment text)" and spec.signup_url == "https://vt.synth.example/key"
    assert spec.provider == "synth_vt" and spec.plan_hint == "business"
    assert "VT_KEY_ALT" in key_env_names()


def test_key_env_names_covers_every_alias():
    names = key_env_names()
    for name, (_d, _u, aliases) in KNOWN_KEYS.items():
        assert f"V3LUM_KEY_{name.upper()}" in names
        assert set(aliases) <= names
    for spec in providers.registry().keys().values():
        assert f"V3LUM_KEY_{spec.name.upper()}" in names and set(spec.env) <= names
    assert {"GITHUB_TOKEN", "GH_TOKEN", "ABUSECH_AUTH_KEY", "SHODAN_API_KEY", "MISP_API_KEY", "OPENCTI_TOKEN", "V3LUM_KEY_MISP"} <= names


def test_key_resolution_env_aliases_and_file(monkeypatch):
    cfg = Config()
    assert cfg.key("misp") == "" and cfg.key_source("misp") == ""
    monkeypatch.setenv("MISP_API_KEY", "misp-alias-value-123")
    assert cfg.key("misp") == "misp-alias-value-123" and cfg.key_source("misp") == "env"
    monkeypatch.setenv("V3LUM_KEY_MISP", "misp-primary-value-456")
    assert cfg.key("misp") == "misp-primary-value-456"
    monkeypatch.setenv("GH_TOKEN", "gh-alias-value-789")
    assert cfg.keys()["github"] == "gh-alias-value-789"
    cfg.file_keys["custom"] = "custom-value-000"
    assert cfg.keys()["custom"] == "custom-value-000" and cfg.key_source("custom") == "config"


# ---------------------------------------------------------------------------------- key plans and storage


def test_key_plan_recording():
    cfg = Config()
    assert cfg.key_plan("shodan") == ""
    cfg.set_key("Shodan", " abcdef123456 ", plan="business")
    assert cfg.key("shodan") == "abcdef123456" and cfg.key_plan("shodan") == "business"
    cfg.set_key("github", "ghp_value_1234567890")
    assert cfg.key_plan("github") == ""
    loaded = Config.load()
    assert loaded.key_plan("shodan") == "business" and loaded.key("shodan") == "abcdef123456"
    loaded.set_key("shodan", "abcdef123456", plan="free")
    assert Config.load().key_plan("shodan") == "free"
    with pytest.raises(ValueError, match="plan"):
        loaded.set_key("shodan", "abcdef123456", plan="enterprise")
    assert loaded.unset_key("shodan") is True
    again = Config.load()
    assert again.key("shodan") == "" and again.key_plan("shodan") == "" and "shodan" not in again.get("key_plans")
    assert again.unset_key("shodan") is False
    weird = Config()
    weird.settings["key_plans"] = {"x": "platinum"}
    assert weird.key_plan("x") == ""


def test_config_json_is_written_0600(monkeypatch):
    old = os.umask(0)  # even a permissive umask cannot widen the mode: os.open(..., 0o600)
    try:
        cfg = Config()
        cfg.set_key("shodan", "abcdef123456")
    finally:
        os.umask(old)
    path = _config_path()
    assert stat.S_IMODE(path.stat().st_mode) == 0o600
    assert [p.name for p in path.parent.iterdir() if p.name.endswith(".tmp")] == []
    chmods: list[object] = []
    monkeypatch.setattr(os, "chmod", lambda *a, **k: chmods.append(a))
    cfg.set("depth", "2")
    assert chmods == []  # no chmod-after-write window (AR03)
    assert stat.S_IMODE(path.stat().st_mode) == 0o600
    data = json.loads(path.read_text(encoding="utf-8"))
    assert data["settings"] == {"depth": 2} and data["keys"] == {"shodan": "abcdef123456"}


def test_save_replaces_a_loose_existing_file():
    path = _config_path()
    path.write_text("{}", encoding="utf-8")
    os.chmod(path, 0o644)
    Config().save()
    assert stat.S_IMODE(path.stat().st_mode) == 0o600


def test_set_key_and_load_register_values_with_the_redactor(monkeypatch):
    from v3lum.core import redact

    redact.clear()
    secret = "s3cr3t-key-value-0001"
    Config().set_key("shodan", secret)
    assert secret not in redact.redact_text(f"https://api.shodan.io/x?key={secret}&q={secret}")
    assert secret not in redact.redact_text(f"error contacting /export/{secret}/full.csv")
    redact.clear()
    assert secret in redact.redact_text(f"/export/{secret}/full.csv")  # cleared: nothing registered
    Config.load()
    assert secret not in redact.redact_text(f"/export/{secret}/full.csv")  # loaded file keys are registered
    redact.clear()
    env_secret = "env-key-value-0002"
    monkeypatch.setenv("ABUSECH_AUTH_KEY", env_secret)
    Config.load()
    assert env_secret not in redact.redact_text(f"/v2/files/exports/{env_secret}/recent.csv")
    redact.clear()
    Config().key("abusech")
    assert env_secret not in redact.redact_text(f"/v2/files/exports/{env_secret}/recent.csv")


def test_mask():
    assert mask("") == "" and mask("short") == "*****"
    assert mask("abcdef123456") == "abc******456"


# ---------------------------------------------------------------------------------- review hardening


def test_core_owner_is_reserved(settings_state):
    """'core' owns the built-in settings: registering under it would replace and drop them."""
    before = dict(SETTINGS_META)
    for mapping in ({}, {"tlp": "clear"}, {"core_extra": 1}):
        with pytest.raises(ValueError, match="reserved"):
            register_settings("core", mapping)
    assert before == SETTINGS_META and SETTINGS_META["tlp"].default == "amber"


def test_register_settings_default_must_match_its_choices(settings_state):
    with pytest.raises(ValueError, match="not one of its choices"):
        register_settings("synth_mod", {"synth_mode": SettingSpec(default="loud", choices=("quiet", "normal"))})
    register_settings("synth_mod", {"synth_mode": SettingSpec(default="quiet", choices=["quiet", "normal"])})
    assert SETTINGS_META["synth_mode"].choices == ("quiet", "normal") and SETTINGS_META["synth_mode"].owner == "synth_mod"


def test_repr_never_shows_key_values():
    secret = "repr-secret-value-9876"
    cfg = Config()
    cfg.file_keys["shodan"] = secret
    assert secret not in repr(cfg) and secret not in str(cfg)


@pytest.mark.parametrize(
    ("name", "value", "stored"),
    [
        ("tlp", "TLP:RED", "red"),
        ("tlp", "Amber+Strict", "amber+strict"),
        ("tlp", "white", "clear"),
        ("mode", "PASSIVE", "passive"),
        ("licence_profile", "Corporate", "corporate"),
        ("doh_providers", "Google, https://doh.corp.example/dns-query", ["google", "https://doh.corp.example/dns-query"]),
        ("misp_url", "https://misp.corp.example/", "https://misp.corp.example/"),
        ("misp_url", "", ""),
        ("contact_email", " cti@company.example ", "cti@company.example"),
        ("contact_url", "https://cti.company.example/", "https://cti.company.example/"),
        ("egress_country", "br", "BR"),
        ("scan_deadline", "0", 0.0),
        ("key_plans", '{"shodan": "business"}', {"shodan": "business"}),
    ],
)
def test_set_stores_the_canonical_value(name, value, stored):
    cfg = Config()
    cfg.set(name, value)
    assert cfg.get(name) == stored
    assert Config.load().get(name) == stored


@pytest.mark.parametrize(
    ("name", "value", "needle"),
    [
        ("tlp", "purple", "invalid TLP value"),
        ("doh_providers", "google,http://doh.corp.example/dns-query", "https://"),
        ("doh_providers", "google,opendns", "choices"),
        ("misp_url", "http://misp.corp.example/", "https://"),
        ("opencti_url", "misp.corp.example", "https://"),
        ("doh_internal", "https://", "with a host"),
        ("contact_email", "not an address", "role mailbox"),
        ("contact_url", "ftp://cti.company.example/", "http"),
        ("user_agent", "V3LUM/1\r\nX-Injected: 1", "control characters"),
        ("egress_country", "BRA", "alpha-2"),
        ("threads", "-1", ">= 0"),
        ("scan_deadline", "nan", "finite"),
        ("retention_days", "1.5", "invalid literal for int"),
        ("key_plans", '{"shodan": "platinum"}', "key_plans"),
        ("defang", "maybe", "boolean"),
    ],
)
def test_set_refuses_invalid_values(name, value, needle):
    cfg = Config()
    before = cfg.get(name)
    with pytest.raises(ValueError, match=needle):
        cfg.set(name, value)
    assert cfg.get(name) == before


def test_url_settings_refuse_embedded_credentials_without_echoing_them():
    cfg = Config()
    with pytest.raises(ValueError, match="must not embed credentials") as info:
        cfg.set("misp_url", "https://svc:Sup3rS3cret@misp.corp.example/")
    assert "Sup3rS3cret" not in str(info.value)


def test_load_ignores_invalid_stored_and_env_values(monkeypatch, settings_state):
    _config_path().write_text(json.dumps({"settings": {
        "tlp": "purple", "licence_profile": "anything", "threads": "abc", "misp_url": "http://misp.corp.example/",
        "depth": 3, "doh_providers": ["cloudflare", "https://doh.corp.example/dns-query"],
    }, "keys": {}}), encoding="utf-8")
    monkeypatch.setenv("V3LUM_LICENCE_PROFILE", "researchy")
    monkeypatch.setenv("V3LUM_MODE", "LIGHT")
    cfg = Config.load()
    assert cfg.get("tlp") == "amber" and cfg.get("licence_profile") == "corporate"  # fail safe: invalid -> default
    assert cfg.get("threads") == DEFAULT_SETTINGS["threads"] and cfg.get("misp_url") == ""
    assert cfg.get("depth") == 3 and cfg.get("doh_providers") == ["cloudflare", "https://doh.corp.example/dns-query"]
    assert cfg.get("mode") == "light"  # case-insensitive choice
    joined = "\n".join(cfg.problems)
    for needle in ("setting tlp ignored", "setting licence_profile ignored", "setting threads ignored", "setting misp_url ignored", "V3LUM_LICENCE_PROFILE ignored"):
        assert needle in joined, joined
    monkeypatch.setenv("V3LUM_TLP", "TLP:RED")
    assert Config.load().get("tlp") == "red"  # an alias spelling is never silently dropped to amber


def test_unreadable_config_file_is_reported():
    _config_path().write_text("{broken", encoding="utf-8")
    cfg = Config.load()
    assert cfg.get("tlp") == "amber" and any("invalid JSON" in p for p in cfg.problems)


def test_env_beats_file_for_module_settings_registered_after_load(monkeypatch, settings_state):
    _config_path().write_text(json.dumps({"settings": {"late_mod_level": 1}, "keys": {}}), encoding="utf-8")
    monkeypatch.setenv("V3LUM_LATE_MOD_LEVEL", "5")
    cfg = Config.load()
    register_settings("late_mod", {"late_mod_level": 0})
    assert cfg.get("late_mod_level") == 5  # precedence: environment > config file
    cfg.set("late_mod_level", "7")  # an explicit change in this process wins
    assert cfg.get("late_mod_level") == 7
    monkeypatch.delenv("V3LUM_LATE_MOD_LEVEL")
    _config_path().write_text(json.dumps({"settings": {"late_mod_choice": "loud"}, "keys": {}}), encoding="utf-8")
    cfg = Config.load()
    register_settings("late_mod", {"late_mod_level": 0, "late_mod_choice": SettingSpec(default="quiet", choices=("quiet", "normal"))})
    assert cfg.get("late_mod_choice") == "quiet"  # an invalid stored value falls back to the default


def test_set_key_refuses_control_characters_without_echoing_the_value():
    cfg = Config()
    secret = "abcdef\n123456-secret"
    with pytest.raises(ValueError, match="control characters") as info:
        cfg.set_key("shodan", secret)
    assert "123456-secret" not in str(info.value) and cfg.key("shodan") == ""


def test_concurrent_changes_and_saves_stay_consistent(settings_state):
    cfg = Config()
    register_settings("synth_conc", {f"synth_conc_{i}": 0 for i in range(6)})
    errors: list[BaseException] = []
    start = threading.Barrier(6)

    def worker(i: int) -> None:
        try:
            start.wait()
            for n in range(5):
                cfg.set(f"synth_conc_{i}", str(n + 1))
                cfg.set_key(f"synth_conc_key_{i}", f"value-{i}-{n}-0123456789")
        except BaseException as exc:  # pragma: no cover - reported below
            errors.append(exc)

    threads = [threading.Thread(target=worker, args=(i,)) for i in range(6)]
    for t in threads:
        t.start()
    for t in threads:
        t.join(timeout=20)
    assert errors == []
    data = json.loads(_config_path().read_text(encoding="utf-8"))  # the last write is complete JSON
    assert stat.S_IMODE(_config_path().stat().st_mode) == 0o600
    loaded = Config.load()
    assert all(loaded.get(f"synth_conc_{i}") == 5 for i in range(6)) and len(data["keys"]) == 6
    assert [p.name for p in _config_path().parent.iterdir() if p.name.endswith(".tmp")] == []


def test_key_lookups_ignore_case():
    cfg = Config()
    cfg.set_key("Shodan", "abcdef123456", plan="business")
    assert cfg.key("SHODAN") == "abcdef123456" and cfg.key_source("Shodan") == "config" and cfg.key_plan("SHODAN") == "business"
    assert cfg.key("") == "" and cfg.key_source("") == ""
