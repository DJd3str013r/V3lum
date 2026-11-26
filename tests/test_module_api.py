"""Module contract v2 (sections 1-2): registration lint, derived attributes, readiness, describe, health."""

from __future__ import annotations

import json
import sys
import textwrap
from typing import Any

import pytest

from v3lum import config
from v3lum.core import module, providers, tlp
from v3lum.core.entities import Entity
from v3lum.core.entities import EntityType as T
from v3lum.core.models import Opsec, Status
from v3lum.core.module import (
    ACCESS_LABELS,
    ACCESS_MODELS,
    BENIGN_VALUES,
    CATEGORIES,
    CEILINGS,
    DERIVED,
    DISCLOSURES,
    MUST_DECLARE,
    OPTIONAL_PACKAGES,
    REGISTRY,
    RESERVED_TAGS,
    RUN_ON,
    TERMS,
    HealthCheck,
    HealthResult,
    Module,
    Readiness,
    RegistrationError,
    load_errors,
    load_modules,
    readiness,
    readiness_check,
    register,
)
from v3lum.core.providers import ErrorMarker

V1_KEYS = {
    "name", "title", "description", "category", "accepts", "produces", "opsec", "requires_keys", "optional_keys",
    "requires_packages", "hosts", "reference", "tags", "default_enabled", "notice", "shares_input", "terms", "daily_quota",
}
V2_KEYS = {
    "disclosure", "provider", "sources", "access_model", "access_label", "run_on", "max_requests", "expected_latency",
    "timeout", "requires_egress", "max_rate", "absent_statuses", "error_markers", "manual_link", "settings", "trust_tier",
    "upstream_families", "reliability", "sensitive", "publishes_queries", "reuses_queries", "fetches_target", "max_tlp",
    "contract",
}


# ---------------------------------------------------------------------------------- isolation and builders


@pytest.fixture()
def reg():
    """Isolate the module registry, provider registry, settings and load errors around a test."""
    load_modules()
    saved_modules = dict(REGISTRY)
    saved_errors = dict(module._LOAD_ERRORS)
    saved_owners = set(module._SETTINGS_OWNERS)
    saved_settings = dict(config.SETTINGS_META)
    pstate = providers.snapshot()
    yield REGISTRY
    REGISTRY.clear()
    REGISTRY.update(saved_modules)
    module._LOAD_ERRORS.clear()
    module._LOAD_ERRORS.update(saved_errors)
    module._SETTINGS_OWNERS.clear()
    module._SETTINGS_OWNERS.update(saved_owners)
    config.SETTINGS_META.clear()
    config.SETTINGS_META.update(saved_settings)
    providers.restore(pstate)


def add_provider(
    pid: str,
    *,
    hosts: tuple[str, ...] | None = None,
    tier: str = "trusted",
    sources: dict[str, Any] | None = None,
    internal: bool = False,
    keys: dict[str, Any] | None = None,
    grade: str = "B",
    hosts_from_settings: tuple[str, ...] = (),
    **flags: bool,
) -> providers.Provider:
    """Register a synthetic provider; ``sources`` maps sid -> terms class (or a full source dict)."""
    src_block: dict[str, Any] = {}
    for sid, spec in (sources or {"feed": "open"}).items():
        if isinstance(spec, str):
            spec = {"class": spec}
        terms = {
            "class": spec.get("class", "open"),
            "evidence_url": "https://terms.synth.example/",
            "quote": "synthetic terms",
            "checked_at": "2026-11-26",
            "reviewer": "tests",
            "free_plan_business_use": None,
        }
        entry = {"title": f"{pid} {sid}", "terms": terms, "upstream_family": spec.get("family", pid), "sanitizer": spec.get("sanitizer"), "dataset": None, "notes": ""}
        if "embeds" in spec:
            entry["embeds"] = spec["embeds"]
        src_block[sid] = entry
    fragment = {
        "schema": "v3lum.provider/1",
        "id": pid,
        "name": f"Synthetic {pid}",
        "operator": "tests",
        "hosts": list(hosts if hosts is not None else (f"api.{pid}.example",)),
        "hosts_from_settings": list(hosts_from_settings),
        "internal": internal,
        "tier": tier,
        "tier_rationale": "synthetic",
        "tier_reviewer": "tests",
        "tier_date": "2026-11-26",
        "flags": {
            "publishes_queries": flags.get("publishes_queries", False),
            "reuses_queries": flags.get("reuses_queries", False),
            "fetches_target": flags.get("fetches_target", False),
            "sensitive": flags.get("sensitive", False),
        },
        "personal_data_review": None,
        "reliability": {"grade": grade, "justification": "synthetic"},
        "http_profile": {},
        "quota": None,
        "error_markers": [],
        "keys": {k: {"description": f"key {k}", "signup_url": "", "env": [v] if v else [], "multi_key": False, "plan_hint": ""} for k, v in (keys or {}).items()},
        "sources": src_block,
    }
    return providers.register(fragment, origin="test_module_api")


def _run(self: Module, entity: Entity, ctx: Any) -> Any:
    return self.result(entity)


def make(name: str = "t_mod", *, bases: tuple[type, ...] = (Module,), cls_name: str | None = None, **attrs: Any) -> type[Module]:
    body: dict[str, Any] = {"name": name, "title": name, "description": "synthetic module", "category": "utility", "accepts": {T.DOMAIN}, "run": _run}
    body.update(attrs)
    return type(cls_name or name, bases, body)


def offline(name: str = "t_offline", **attrs: Any) -> type[Module]:
    base = {"terms": "open", "opsec": Opsec.PASSIVE, "disclosure": "none", "hosts": ()}
    base.update(attrs)
    return make(name, **base)


def networked(pid: str, name: str = "t_net", *, sid: str = "feed", **attrs: Any) -> type[Module]:
    base: dict[str, Any] = {
        "terms": "open",
        "opsec": Opsec.PASSIVE,
        "disclosure": "third_party",
        "provider": pid,
        "sources": (f"{pid}.{sid}",),
        "hosts": (f"api.{pid}.example",),
        "access_model": "free_noauth_unlimited",
        "max_requests": 5,
        "expected_latency": 1.0,
    }
    base.update(attrs)
    return make(name, **base)


def target(name: str = "t_light", **attrs: Any) -> type[Module]:
    base: dict[str, Any] = {
        "terms": "open", "opsec": Opsec.LIGHT, "disclosure": "target", "hosts": (), "max_requests": 5,
        "expected_latency": 1.0, "default_enabled": False,
    }
    base.update(attrs)
    return make(name, **base)


def refused(cls: type[Module], needle: str) -> RegistrationError:
    with pytest.raises(RegistrationError) as info:
        register(cls)
    message = str(info.value)
    assert message.startswith(f"{cls.name}: ") and " - " in message, message  # '<module>: <problem> - <fix>'
    assert needle in message, message
    assert REGISTRY.get(cls.name) is not cls
    return info.value


# ---------------------------------------------------------------------------------- constants


def test_contract_constants():
    assert len(CATEGORIES) == 21
    assert TERMS == ("open", "key-terms", "license", "noncommercial", "unknown") == providers.TERMS_ORDER
    assert DISCLOSURES == ("none", "internal", "third_party", "target")
    assert RUN_ON == ("any", "seeds", "own_assets", "own_assets_only")
    assert len(ACCESS_MODELS) == 7 and set(ACCESS_LABELS) == set(ACCESS_MODELS)
    assert ACCESS_LABELS["free_noauth_limited"] == "free, no key, limited"
    assert ACCESS_LABELS["free_auth_limited"] == "free key, limited"
    assert ACCESS_LABELS["commercial_only"] == "paid only" and ACCESS_LABELS["offline"] == "offline"
    assert MUST_DECLARE == ("terms", "opsec", "disclosure", "hosts")
    assert module.MUST_DECLARE_NETWORKED == ("max_requests", "expected_latency")
    assert module.REMOVED == ("user_agent", "shares_input") and set(module.REMOVED_REASONS) == set(module.REMOVED)
    assert {"trust_tier", "providers", "upstream_families", "reliability", "sensitive", "publishes_queries", "reuses_queries", "fetches_target", "shares_input", "max_tlp", "access_label", "terms_sources"} == set(DERIVED)
    assert CEILINGS == {"light_max_rps": 1.0, "active_max_rps": 10.0}
    for pkg, extra in {"phonenumbers": "full", "dns": "full", "PIL": "full", "pypdf": "full", "socks": "full", "websocket": "watch", "yaml": "yaml"}.items():
        assert OPTIONAL_PACKAGES[pkg] == extra


def test_base_class_defaults():
    assert Module.terms == "unknown"  # fail closed (A1)
    assert Module.disclosure == ""  # no default: must be declared
    assert Module.opsec is Opsec.PASSIVE and Module.hosts == () and Module.run_on == "any"
    assert Module.max_requests == 10 and Module.expected_latency == 5.0 and Module.timeout == 60.0
    assert Module.max_rate is None and Module.manual_link == "" and Module.settings == {}
    assert Module.requires_egress == frozenset() and Module.absent_statuses == frozenset() and Module.error_markers == ()
    assert not hasattr(Module, "user_agent")


def test_reserved_tags_have_meanings():
    contract = {
        "core", "offline", "slow", "noisy", "brazil", "free", "curated_pack", "cached_only", "high_fp", "bulk_download",
        "people_sweep", "sensitive_sites", "fresh_assessment", "cert_derived", "pack", "reputation", "watch_source", "watch_only",
    }
    assert isinstance(RESERVED_TAGS, dict) and contract <= set(RESERVED_TAGS)
    assert all(isinstance(v, str) and len(v) > 10 for v in RESERVED_TAGS.values())
    assert "inconclusive" in RESERVED_TAGS["reputation"] and "minimum answer set" in RESERVED_TAGS["reputation"]
    assert "v3lum watch" in RESERVED_TAGS["watch_source"] and "watch_hits" in RESERVED_TAGS["watch_source"]
    assert "never selected outside" in RESERVED_TAGS["watch_only"]


# ---------------------------------------------------------------------------------- MUST-declare and removed names


@pytest.mark.parametrize("missing", MUST_DECLARE)
def test_must_declare(reg, missing):
    attrs = {"terms": "open", "opsec": Opsec.PASSIVE, "disclosure": "none", "hosts": ()}
    del attrs[missing]
    refused(make("t_missing", **attrs), f"{missing} not declared")


def test_explicit_declarations_register(reg):
    cls = register(offline("t_explicit"))
    assert REGISTRY["t_explicit"] is cls


def test_declarations_in_a_mixin_count(reg):
    class Offline:
        terms = "open"
        opsec = Opsec.PASSIVE
        disclosure = "none"
        hosts = ()

    cls = register(make("t_mixin", bases=(Offline, Module)))
    assert cls.disclosure == "none" and cls.trust_tier == "n/a"


def test_networked_modules_declare_max_requests_and_latency(reg):
    add_provider("synth_nd")
    attrs = dict(terms="open", opsec=Opsec.PASSIVE, disclosure="third_party", provider="synth_nd", sources=("synth_nd.feed",), hosts=("api.synth_nd.example",), access_model="free_noauth_unlimited")
    refused(make("t_nolimits", **attrs), "max_requests, expected_latency not declared")
    refused(make("t_nolatency", max_requests=3, **attrs), "expected_latency not declared")
    assert register(make("t_limits", max_requests=3, expected_latency=0.5, **attrs)).max_requests == 3
    assert register(offline("t_offline_nolimits")).max_requests == 10  # 'none' modules may keep the defaults


@pytest.mark.parametrize("attr", ["user_agent", "shares_input"])
def test_removed_names_refused(reg, attr):
    refused(offline("t_removed", **{attr: False if attr == "shares_input" else "Mozilla/5.0"}), "removed in contract v2")


@pytest.mark.parametrize("attr", [a for a in DERIVED if a != "shares_input"])
def test_derived_names_refused(reg, attr):
    refused(offline("t_derived", **{attr: "x"}), f"derived attribute {attr!r}")


# ---------------------------------------------------------------------------------- identity and enums


@pytest.mark.parametrize(
    ("attrs", "needle"),
    [
        ({"name": "X"}, "invalid module name"),
        ({"name": "ab"}, "invalid module name"),
        ({"category": "misc"}, "unknown category"),
        ({"accepts": set()}, "accepts is empty"),
        ({"accepts": "domain"}, "accepts must be a set"),
        ({"accepts": {"not_a_type"}}, "unknown entity type"),
        ({"tags": "free"}, "tags must be a set"),
        ({"reference": "ftp://docs.example/"}, "not an http(s) URL"),
        ({"terms": "free"}, "unknown terms class"),
        ({"disclosure": "public"}, "unknown disclosure"),
        ({"opsec": "loud"}, "invalid opsec"),
        ({"run_on": "everyone"}, "unknown run_on"),
        ({"access_model": "cheap"}, "unknown access_model"),
        ({"hosts": "api.example.com"}, "hosts must be a tuple"),
        ({"default_enabled": "yes"}, "default_enabled must be a boolean"),
        ({"max_requests": 100001}, "max_requests"),
        ({"max_requests": -1}, "max_requests"),
        ({"expected_latency": -1}, "expected_latency"),
        ({"timeout": -1}, "timeout"),
        ({"min_interval": float("nan")}, "min_interval"),
        ({"daily_quota": 0}, "daily_quota"),
        ({"settings": ["x"]}, "settings must be a dict"),
    ],
)
def test_identity_and_enum_rules(reg, attrs, needle):
    base = {"terms": "open", "opsec": Opsec.PASSIVE, "disclosure": "none", "hosts": ()}
    base.update(attrs)
    name = base.pop("name", "t_enum")
    refused(make(name, **base), needle)


def test_accepts_strings_are_normalised(reg):
    cls = register(offline("t_strings", accepts={"domain", T.URL}, produces=["ipv4"], tags=["free"]))
    assert cls.accepts == frozenset({T.DOMAIN, T.URL}) and cls.produces == frozenset({T.IPV4}) and cls.tags == frozenset({"free"})


def test_timeout_zero_means_no_run_deadline(reg):
    assert register(offline("t_no_deadline", timeout=0)).timeout == 0


def test_duplicate_module_names(reg):
    register(offline("t_dup", cls_name="FirstDup"))
    refused(offline("t_dup", cls_name="SecondDup"), "duplicate module name")


def test_invalid_host_syntax(reg):
    add_provider("synth_host")
    refused(networked("synth_host", hosts=("https://api.synth_host.example/x",)), "invalid host")


def test_access_model_defaults_and_requirement(reg):
    assert register(offline("t_am_none")).access_model == "offline"
    assert register(target("t_am_target")).access_model == "free_noauth_unlimited"
    add_provider("synth_int", hosts=(), internal=True, hosts_from_settings=("misp_url",))
    cls = register(make("t_am_internal", terms="open", opsec=Opsec.PASSIVE, disclosure="internal", provider="synth_int", sources=("synth_int.feed",), hosts=(), max_requests=2, expected_latency=1.0))
    assert cls.access_model == "internal" and cls.access_label == "internal platform"
    add_provider("synth_am")
    refused(networked("synth_am", access_model=""), "access_model not declared")
    assert register(networked("synth_am", "t_am_net", access_model="free_auth_limited")).access_label == "free key, limited"


# ---------------------------------------------------------------------------------- disclosure rules


def test_light_and_active_iff_target(reg):
    add_provider("synth_lt")
    refused(networked("synth_lt", "t_light_tp", opsec=Opsec.LIGHT, default_enabled=False), "declare disclosure = 'target'")
    refused(target("t_passive_target", opsec=Opsec.PASSIVE), "disclosure 'target' on a PASSIVE module")
    light = register(target("t_light_ok"))
    active = register(target("t_active_ok", opsec=Opsec.ACTIVE))
    assert light.shares_input and active.shares_input and light.trust_tier == "n/a"
    assert light.max_tlp is tlp.TLP.AMBER and light.access_model == "free_noauth_unlimited"


def test_none_means_no_hosts_and_no_provider(reg):
    add_provider("synth_none")
    refused(offline("t_none_hosts", hosts=("api.synth_none.example",)), "offline module")
    refused(offline("t_none_provider", provider="synth_none"), "offline module")
    cls = register(offline("t_none_dataset", sources=("synth_none.feed",)))  # dataset users list their sources
    assert cls.shares_input is False and cls.max_tlp is tlp.TLP.RED and cls.trust_tier == "n/a"
    assert cls.providers == frozenset({"synth_none"}) and cls.publishes_queries is False


def test_internal_requires_an_internal_provider(reg):
    add_provider("synth_ext")
    add_provider("synth_in", hosts=(), internal=True, hosts_from_settings=("opencti_url",))
    attrs = dict(terms="open", opsec=Opsec.PASSIVE, disclosure="internal", hosts=(), max_requests=2, expected_latency=1.0)
    refused(make("t_internal_ext", provider="synth_ext", sources=("synth_ext.feed",), **attrs), "are not internal")
    refused(make("t_internal_noprov", **attrs), "internal module without provider or sources")
    refused(make("t_internal_mixed", provider="synth_in", sources=("synth_in.feed", "synth_ext.feed"), **attrs), "are not internal")
    cls = register(make("t_internal_ok", provider="synth_in", sources=("synth_in.feed",), **attrs))
    assert cls.trust_tier == "n/a" and cls.max_tlp is tlp.TLP.RED and cls.shares_input is False


def test_third_party_needs_registered_provider_sources_and_hosts(reg):
    add_provider("synth_a", hosts=("api.synth_a.example", "*.cdn.synth_a.example"))
    add_provider("synth_b")
    refused(networked("synth_missing"), "provider 'synth_missing' is not registered")  # the provider first, then its sources
    refused(networked("synth_missing", sources=("synth_a.feed",), hosts=()), "provider 'synth_missing' is not registered")
    refused(networked("synth_a", sources=()), "without a registered provider and sources")
    refused(networked("synth_a", sources=("synth_a.nope",)), "source 'synth_a.nope' is not in the provider registry")
    refused(networked("synth_a", hosts=("api.unregistered.example",)), "is not in the provider registry")
    refused(networked("synth_a", hosts=("api.synth_b.example",)), "belongs to provider 'synth_b'")
    refused(networked("synth_a", sources=("synth_b.feed",), hosts=("api.synth_b.example",)), "has none of the module's sources")
    ok = register(networked("synth_a", "t_tp_ok", hosts=("api.synth_a.example", "x.cdn.synth_a.example", "*.cdn.synth_a.example")))
    assert ok.providers == frozenset({"synth_a"}) and ok.hosts == ("api.synth_a.example", "x.cdn.synth_a.example", "*.cdn.synth_a.example")
    multi = register(networked("synth_a", "t_tp_multi", sources=("synth_a.feed", "synth_b.feed"), hosts=("api.synth_a.example", "api.synth_b.example")))
    assert multi.providers == frozenset({"synth_a", "synth_b"})


def test_doh_only_module_shape(reg):
    cls = register(make("t_doh", terms="open", opsec=Opsec.PASSIVE, disclosure="third_party", provider="core_doh", sources=("core_doh.resolvers",), hosts=(), access_model="free_noauth_unlimited", max_requests=0, expected_latency=1.5))
    assert cls.trust_tier == "trusted" and cls.upstream_families == frozenset({"dns"}) and cls.max_tlp is tlp.TLP.AMBER_STRICT


# ---------------------------------------------------------------------------------- terms


def test_terms_must_equal_the_most_restrictive_source_class(reg):
    add_provider("synth_mix", sources={"open_feed": "open", "paid_feed": "license"})
    both = ("synth_mix.open_feed", "synth_mix.paid_feed")
    err = refused(networked("synth_mix", sources=both, terms="open"), "most restrictive source class is 'license'")
    assert "synth_mix.paid_feed=license" in str(err)
    cls = register(networked("synth_mix", "t_terms_ok", sources=both, terms="license"))
    assert cls.terms_sources == {"synth_mix.open_feed": "open", "synth_mix.paid_feed": "license"}
    add_provider("synth_nc", sources={"feed": "noncommercial"})
    refused(networked("synth_nc", "t_nc", terms="license"), "declare terms = 'noncommercial'")
    assert register(networked("synth_nc", "t_nc_ok", terms="noncommercial")).terms == "noncommercial"


def test_modules_without_sources_declare_open(reg):
    refused(offline("t_nosrc", terms="noncommercial"), "without registry sources")
    refused(target("t_nosrc_target", terms="unknown"), "without registry sources")
    assert register(offline("t_nosrc_ok")).terms == "open"


# ---------------------------------------------------------------------------------- A3 default rules


@pytest.mark.parametrize(
    "case",
    ["light", "terms_unknown", "tier_unknown", "max_requests", "latency", "person_name", "high_fp", "bulk_download", "people_sweep", "sensitive_sites", "fresh_assessment", "fetches_target"],
)
def test_a3_default_rules(reg, case):
    add_provider("synth_ok")
    add_provider("synth_unknown_terms", sources={"feed": "unknown"})
    add_provider("synth_unknown_tier", tier="unknown")
    add_provider("synth_fetch", fetches_target=True)
    builders: dict[str, Any] = {
        "light": lambda **kw: target("t_a3", **kw),
        "terms_unknown": lambda **kw: networked("synth_unknown_terms", "t_a3", terms="unknown", **kw),
        "tier_unknown": lambda **kw: networked("synth_unknown_tier", "t_a3", **kw),
        "max_requests": lambda **kw: networked("synth_ok", "t_a3", max_requests=11, **kw),
        "latency": lambda **kw: networked("synth_ok", "t_a3", expected_latency=10.5, **kw),
        "person_name": lambda **kw: networked("synth_ok", "t_a3", category="person_name", **kw),
        "fetches_target": lambda **kw: networked("synth_fetch", "t_a3", **kw),
    }
    for tag in module.NEVER_DEFAULT_TAGS:
        builders[tag] = lambda tag=tag, **kw: networked("synth_ok", "t_a3", tags={tag}, **kw)
    refused(builders[case](default_enabled=True), "default_enabled True")
    assert register(builders[case](default_enabled=False)).default_enabled is False


def test_a3_exceptions(reg):
    add_provider("synth_ok")
    add_provider("synth_fetch", fetches_target=True)
    pack = register(networked("synth_ok", "t_pack", max_requests=150, tags={"curated_pack"}))
    cached = register(networked("synth_fetch", "t_cached", tags={"cached_only"}))
    assert pack.default_enabled and cached.default_enabled and cached.fetches_target
    add_provider("synth_lic", sources={"feed": "license"})
    assert register(networked("synth_lic", "t_lic", terms="license")).default_enabled  # licence gate decides at run time


# ---------------------------------------------------------------------------------- other field rules


def test_max_rate_ceilings(reg):
    assert register(target("t_rate_l", max_rate=1.0)).max_rate == 1.0
    refused(target("t_rate_l2", max_rate=1.5), "above the light ceiling")
    assert register(target("t_rate_a", opsec=Opsec.ACTIVE, max_rate=10.0)).max_rate == 10.0
    refused(target("t_rate_a2", opsec=Opsec.ACTIVE, max_rate=10.5), "above the active ceiling")
    refused(offline("t_rate_p", max_rate=0.5), "max_rate on a PASSIVE module")
    refused(target("t_rate_z", max_rate=0), "max_rate 0 is invalid")


def test_requires_egress_codes(reg):
    assert register(offline("t_egress", requires_egress={"BR"})).requires_egress == frozenset({"BR"})
    refused(offline("t_egress_lower", requires_egress={"br"}), "requires_egress")
    refused(offline("t_egress_long", requires_egress={"BRA"}), "requires_egress")
    refused(offline("t_egress_str", requires_egress="BR"), "requires_egress")


def test_absent_statuses_range(reg):
    assert register(offline("t_absent", absent_statuses={404, 410})).absent_statuses == frozenset({404, 410})
    refused(offline("t_absent_bad", absent_statuses={700}), "absent_statuses")
    refused(offline("t_absent_int", absent_statuses=404), "absent_statuses")


@pytest.mark.parametrize("status", [401, 403, 407, 429, 430, 451, 500, 503, 599])
def test_absent_statuses_never_declare_a_refusal_or_failure(reg, status):
    """Rule 5: refusals, throttling and server failures mean 'could not verify' - declaring them as
    absences fails registration (ScopedHttp.get_json raises for them anyway)."""
    err = refused(offline(f"t_absent_{status}", absent_statuses={404, status}), "could not verify")
    assert str(status) in str(err) and "never an absence (rule 5)" in str(err)


def test_error_markers_schema(reg):
    marker = {"id": "count", "regex": "API count exceeded", "maps_to": "quota", "reason": "Synth: daily quota exhausted"}
    cls = register(offline("t_markers", error_markers=(marker,)))
    assert cls.error_markers == (ErrorMarker(id="count", regex="API count exceeded", maps_to="quota", reason="Synth: daily quota exhausted"),)
    assert cls.describe()["error_markers"][0]["maps_to"] == "quota"
    refused(offline("t_markers_bad", error_markers=({**marker, "maps_to": "empty"},)), "invalid error marker")
    refused(offline("t_markers_dup", error_markers=(marker, marker)), "duplicate error marker id")
    refused(offline("t_markers_type", error_markers=marker), "error_markers must be a tuple")


def test_manual_link_must_resolve(reg, monkeypatch):
    from v3lum.core import links

    seen: list[str] = []

    def validate(value: str) -> list[str]:
        seen.append(value)
        return [] if value == "core_reference:shodan_host" else [f"unknown link {value}"]

    monkeypatch.setattr(links, "validate_manual_link", validate, raising=False)
    assert register(offline("t_link", manual_link="core_reference:shodan_host")).manual_link == "core_reference:shodan_host"
    refused(offline("t_link_bad", manual_link="nope:missing"), "does not resolve (unknown link nope:missing)")
    assert seen == ["core_reference:shodan_host", "nope:missing"]
    assert register(offline("t_link_none")).manual_link == ""  # empty: no lookup
    assert len(seen) == 2


def test_settings_registration_and_collisions(reg):
    cls = register(offline("t_settings", settings={"t_settings_limit": 25}))
    assert config.SETTINGS_META["t_settings_limit"].owner == "t_settings"
    assert config.Config().get("t_settings_limit") == 25
    refused(offline("t_settings_core", settings={"tlp": "red"}), "collides with a core setting")
    refused(offline("t_settings_other", settings={"t_settings_limit": 3}), "collides with a setting of t_settings")
    assert register(cls) is cls  # re-registration of the owner is idempotent
    assert module.unregister("t_settings") and "t_settings_limit" not in config.SETTINGS_META
    assert register(offline("t_settings_other", settings={"t_settings_limit": 3})).settings == {"t_settings_limit": 3}


def test_stale_settings_of_dropped_modules_are_released(reg):
    register(offline("t_stale", settings={"t_stale_value": 1}))
    REGISTRY.pop("t_stale")  # e.g. a test fixture restoring the registry dict
    assert register(offline("t_stale_new", settings={"t_stale_value": 2})).settings == {"t_stale_value": 2}


def test_sensitive_modules_need_a_schema_per_source(reg):
    from v3lum.core import sanitize

    add_provider("synth_breach", sources={"lookup": "open"}, sensitive=True)
    refused(networked("synth_breach", "t_breach", sid="lookup"), "without a sanitizer schema for source 'synth_breach.lookup'")
    sanitize.register_schema("synth_breach.lookup", keep=["breaches[].Name"])
    try:
        cls = register(networked("synth_breach", "t_breach_ok", sid="lookup"))
    finally:
        cleanup = getattr(sanitize, "unregister_schema", None)
        if callable(cleanup):
            cleanup("synth_breach.lookup")
    assert cls.sensitive is True
    add_provider("synth_breach2", sources={"lookup": {"class": "open", "sanitizer": {"keep": ["sources[].name"]}}})
    refused(offline("t_breach_cat", category="breach_leak", sources=("synth_breach2.lookup", "synth_ok_missing.x")), "is not in the provider registry")
    by_category = register(networked("synth_breach2", "t_breach_cat2", sid="lookup", category="breach_leak"))
    assert by_category.sensitive is True  # category breach_leak, schema from the fragment's sanitizer block


def test_keys_must_be_registered(reg):
    add_provider("synth_keyed", keys={"synthkey": "SYNTH_API_KEY"})
    refused(offline("t_key_missing", requires_keys=("no_such_key",)), "key 'no_such_key' is not registered")
    refused(offline("t_key_opt_missing", optional_keys=("no_such_key",)), "key 'no_such_key' is not registered")
    cls = register(networked("synth_keyed", "t_keyed", requires_keys=("synthkey",), optional_keys=("github",), access_model="free_auth_limited"))
    assert cls.requires_keys == ("synthkey",)
    refused(offline("t_key_str", requires_keys="synthkey"), "requires_keys must be a tuple")


def test_requires_packages_known_and_extras_fragments(reg, tmp_path):
    assert register(offline("t_pkg_core", requires_packages=("phonenumbers",))).requires_packages == ("phonenumbers",)
    refused(offline("t_pkg_unknown", requires_packages=("fancylib",)), "not a known optional dependency")
    good = {"schema": "v3lum.extra/1", "package": "fancylib", "pip": "fancylib>=2", "extra": "fancy", "licence": "MIT", "justification": "test extra"}
    (tmp_path / "fancylib.json").write_text(json.dumps(good), encoding="utf-8")
    (tmp_path / "gpltool.json").write_text(json.dumps({**good, "package": "gpltool", "licence": "GPL-3.0-only"}), encoding="utf-8")
    (tmp_path / "wrongname.json").write_text(json.dumps({**good, "package": "other"}), encoding="utf-8")
    (tmp_path / "dns.json").write_text(json.dumps({**good, "package": "dns", "extra": "dnsonly"}), encoding="utf-8")
    (tmp_path / "lgpllib.json").write_text(json.dumps({**good, "package": "lgpllib", "licence": "LGPL-3.0-or-later"}), encoding="utf-8")
    try:
        merged = module.reload_extras(tmp_path)
        assert merged["fancylib"] == "fancy" and merged["lgpllib"] == "fancy" and merged["dns"] == "full"
        assert module.EXTRAS["fancylib"].pip == "fancylib>=2"
        errors = "\n".join(module.extras_errors())
        assert "gpltool.json" in errors and "GPL" in errors
        assert "wrongname.json" in errors and "dns.json" in errors
        assert "gpltool" not in OPTIONAL_PACKAGES
        assert register(offline("t_pkg_extra", requires_packages=("fancylib",))).requires_packages == ("fancylib",)
        load_modules(force=True)
        assert any(k == "extras:gpltool.json" for k in load_errors())
    finally:
        module.reload_extras()
    assert "fancylib" not in OPTIONAL_PACKAGES and module.extras_errors() == []


# ---------------------------------------------------------------------------------- derived attributes


def test_derived_attributes(reg):
    add_provider("synth_trusted", sources={"feed": {"class": "open", "family": "abuse.ch"}}, grade="A")
    add_provider("synth_comm", tier="community", sources={"agg": {"class": "open", "family": "firehol", "embeds": ["spamhaus"]}}, grade="C")
    cls = register(networked(
        "synth_trusted", "t_derived_vals",
        sources=("synth_trusted.feed", "synth_comm.agg"), hosts=("api.synth_trusted.example", "api.synth_comm.example"),
    ))
    assert cls.trust_tier == "community"  # lowest tier among the providers
    assert cls.providers == frozenset({"synth_trusted", "synth_comm"})
    assert cls.upstream_families == frozenset({"abuse.ch", "firehol", "spamhaus"})
    assert cls.reliability == "A"  # primary provider grade
    assert cls.sensitive is False and cls.publishes_queries is False and cls.reuses_queries is False
    assert cls.fetches_target is False and cls.shares_input is True
    assert cls.max_tlp is tlp.TLP.AMBER  # community -> amber
    assert cls.access_label == "free, no key, unlimited"
    assert cls.terms_sources == {"synth_trusted.feed": "open", "synth_comm.agg": "open"}
    trusted = register(networked("synth_trusted", "t_derived_trusted"))
    assert trusted.trust_tier == "trusted" and trusted.max_tlp is tlp.TLP.AMBER_STRICT


def test_derived_flags_and_tlp_ceilings(reg):
    add_provider("synth_reuse", reuses_queries=True)
    add_provider("synth_pub", publishes_queries=True)
    add_provider("synth_sens", sensitive=True, sources={"feed": {"class": "open", "sanitizer": {"keep": ["count"]}}})
    reuse = register(networked("synth_reuse", "t_reuse"))
    assert reuse.reuses_queries and reuse.max_tlp is tlp.TLP.GREEN
    pub = register(networked("synth_pub", "t_pub"))
    assert pub.publishes_queries and pub.max_tlp is None and pub.describe()["max_tlp"] is None
    sens = register(networked("synth_sens", "t_sens"))
    assert sens.sensitive
    unknown = add_provider("synth_unk", tier="unknown")
    assert unknown.tier == "unknown"
    unk = register(networked("synth_unk", "t_unk", default_enabled=False))
    assert unk.trust_tier == "unknown" and unk.max_tlp is tlp.TLP.GREEN


def test_reregistration_and_subclassing(reg):
    add_provider("synth_sub")
    base = register(networked("synth_sub", "t_base"))
    assert register(base) is base  # idempotent: derived values are not mistaken for declarations
    sub = register(make("t_sub", bases=(base,), max_requests=2))
    assert sub.max_requests == 2 and sub.trust_tier == "trusted" and REGISTRY["t_base"] is base
    refused(make("t_sub_derived", bases=(base,), trust_tier="trusted"), "derived attribute 'trust_tier'")
    off = register(offline("t_off_base"))
    assert off.access_model == "offline"
    # a filled-in default of the base class does not count as a declaration in a subclass
    refused(make("t_off_sub", bases=(off,), disclosure="third_party", provider="synth_sub", sources=("synth_sub.feed",), hosts=("api.synth_sub.example",), max_requests=1, expected_latency=1.0), "access_model not declared")


def test_register_rejects_non_modules(reg):
    with pytest.raises(RegistrationError):
        register(object)  # type: ignore[arg-type]


# ---------------------------------------------------------------------------------- describe, readiness, health


def test_describe_keeps_v1_keys_and_adds_v2(reg):
    add_provider("synth_desc")
    cls = register(networked("synth_desc", "t_desc", requires_egress={"BR"}, absent_statuses={404}, settings={"t_desc_x": 1}))
    d = cls.describe()
    assert set(d) >= V1_KEYS and set(d) >= V2_KEYS
    json.dumps(d)
    assert d["contract"] == "v2" and d["shares_input"] is True and d["terms"] == "open"
    assert d["disclosure"] == "third_party" and d["provider"] == "synth_desc" and d["sources"] == ["synth_desc.feed"]
    assert d["max_tlp"] == "amber+strict" and d["access_label"] == "free, no key, unlimited"
    assert d["requires_egress"] == ["BR"] and d["absent_statuses"] == [404] and d["settings"] == {"t_desc_x": 1}
    for cls_ in list(REGISTRY.values()):
        desc = cls_.describe()
        assert set(desc) >= V1_KEYS
        json.dumps(desc)


def test_readiness_check_statuses_and_reason_codes(reg):
    add_provider("synth_ready", keys={"synth_ready_key": ""})
    pkg = register(offline("t_ready_pkg", requires_packages=("websocket",)))
    keyed = register(networked("synth_ready", "t_ready_key", requires_keys=("synth_ready_key",), access_model="free_auth_limited"))
    light = register(target("t_ready_light"))
    active = register(target("t_ready_active", opsec=Opsec.ACTIVE))
    plain = register(offline("t_ready_plain"))
    import importlib.util

    if importlib.util.find_spec("websocket") is None:
        r = readiness_check(pkg, {}, Opsec.PASSIVE)
        assert (r.ready, r.status, r.reason_code) == (False, Status.UNAVAILABLE, "package") and "v3lum[watch]" in r.reason
    r = readiness_check(keyed, {}, Opsec.PASSIVE)
    assert (r.ready, r.status, r.reason_code) == (False, Status.NEEDS_KEY, "needs_key")
    assert readiness_check(keyed, {"synth_ready_key": "value"}, Opsec.PASSIVE).ready
    assert readiness_check(keyed, {"synth_ready_key"}, Opsec.PASSIVE).ready  # a set of configured names works too
    r = readiness_check(light, {}, Opsec.PASSIVE)
    assert (r.status, r.reason_code, r.reason) == (Status.SKIPPED, "opsec", "light module (current mode: passive)")
    assert readiness_check(light, {}, Opsec.LIGHT).ready
    r = readiness_check(active, {}, Opsec.ACTIVE, authorized=False)
    assert (r.status, r.reason_code) == (Status.SKIPPED, "authorization")
    assert readiness_check(active, {}, Opsec.ACTIVE, authorized=True) == Readiness(True, Status.OK, "", "ready")
    assert readiness(plain, {}, Opsec.PASSIVE) == (True, "ready")
    ready, reason = readiness(keyed, {}, Opsec.PASSIVE)
    assert ready is False and reason == "needs API key: synth_ready_key"
    assert readiness(light, {}, Opsec.PASSIVE) == (False, "light module (current mode: passive)")
    assert readiness(active, {}, Opsec.ACTIVE) == (False, "active module: requires --authorized")


def test_readiness_missing_package(reg, monkeypatch):
    cls = register(offline("t_pkg_missing", requires_packages=("phonenumbers",)))
    monkeypatch.setattr(module, "package_available", lambda name: False)
    r = readiness_check(cls, {}, Opsec.PASSIVE)
    assert (r.ready, r.status, r.reason_code) == (False, Status.UNAVAILABLE, "package")
    assert r.reason.startswith("needs python package: phonenumbers") and "v3lum[full]" in r.reason


def test_health_check_defaults(reg):
    add_provider("synth_hc")
    dom = register(networked("synth_hc", "t_hc_domain"))
    assert dom.health_check() == HealthCheck(etype=T.DOMAIN, value="example.com")
    ip = register(networked("synth_hc", "t_hc_ip", accepts={T.IPV4, T.IPV6}))
    assert ip.health_check().value == "8.8.8.8"
    md5 = register(networked("synth_hc", "t_hc_md5", accepts={T.MD5}))
    assert md5.health_check().value == "44d88612fea8a8f36de82e1278abb02f"  # EICAR
    user = register(networked("synth_hc", "t_hc_user", accepts={T.USERNAME}))
    assert user.health_check().value == "octocat"
    phone = register(networked("synth_hc", "t_hc_phone", accepts={T.PHONE}))
    assert phone.health_check() is None  # no benign value for the type
    assert register(offline("t_hc_offline")).health_check() is None
    assert register(target("t_hc_target")).health_check() is None  # LIGHT/ACTIVE must override with a self-test
    hc = dom.health_check()
    assert hc.expect == "ok" and hc.offline is False and hc.selftest is None and hc.entity == Entity.make("domain", "example.com")


def test_benign_values_are_valid_entities():
    assert list(BENIGN_VALUES)[:3] == [T.DOMAIN, T.URL, T.EMAIL]
    for etype, value in BENIGN_VALUES.items():
        assert Entity.make(etype, value).value == value


def test_health_check_selftest_contract(reg):
    calls: list[Any] = []

    def selftest(ctx: Any) -> HealthResult:
        calls.append(ctx)
        return HealthResult("ok", "loopback fixture answered")

    class Probe(Module):
        name = "t_selftest"
        title = "self-test"
        description = "LIGHT module with an offline self-test"
        category = "pentest_recon"
        accepts = {T.DOMAIN}
        terms = "open"
        opsec = Opsec.LIGHT
        disclosure = "target"
        hosts = ()
        max_requests = 3
        expected_latency = 1.0
        default_enabled = False

        @classmethod
        def health_check(cls) -> HealthCheck:
            return HealthCheck(offline=True, selftest=selftest)

    register(Probe)
    hc = Probe.health_check()
    assert hc.offline and callable(hc.selftest) and hc.entity is None
    result = hc.selftest(object())
    assert result == HealthResult("ok", "loopback fixture answered") and result.ok and len(calls) == 1
    for status in module.HEALTH_STATUSES:
        assert HealthResult(status).status == status
    assert module.HEALTH_STATUSES == ("ok", "blocked", "quota", "needs_key", "dead")
    with pytest.raises(ValueError):
        HealthResult("absent")


# ---------------------------------------------------------------------------------- loading


def test_load_modules_records_registration_errors(reg, tmp_path):
    plugin = tmp_path / "v1_style.py"
    plugin.write_text(textwrap.dedent('''
        from v3lum.core.entities import EntityType as T
        from v3lum.core.module import Module, register

        @register
        class V1Style(Module):
            name = "t_v1_style_plugin"
            category = "utility"
            accepts = {T.DOMAIN}
            hosts = ("api.example.com",)
            shares_input = True
    '''), encoding="utf-8")
    try:
        load_modules(extra_dirs=[str(tmp_path)], force=True)  # never raises
        errors = load_errors()
        assert str(plugin) in errors
        assert errors[str(plugin)].startswith("RegistrationError: t_v1_style_plugin: terms, opsec, disclosure not declared")
        assert "t_v1_style_plugin" not in REGISTRY
    finally:
        sys.modules.pop("v3lum_plugin_v1_style", None)


def test_load_modules_clears_errors_of_plugins_that_load_now(reg, tmp_path):
    plugin = tmp_path / "flaky_plugin.py"
    plugin.write_text("raise RuntimeError('broken at import')\n", encoding="utf-8")
    try:
        load_modules(extra_dirs=[str(tmp_path)], force=True)
        assert load_errors()[str(plugin)] == "RuntimeError: broken at import"
        assert "v3lum_plugin_flaky_plugin" not in sys.modules  # no half-initialised module left behind
        plugin.write_text("VALUE = 1\n", encoding="utf-8")
        load_modules(extra_dirs=[str(tmp_path)], force=True)
        assert str(plugin) not in load_errors()
    finally:
        sys.modules.pop("v3lum_plugin_flaky_plugin", None)


# ---------------------------------------------------------------------------------- review hardening


def test_reserved_module_name_core(reg):
    """'core' owns the built-in settings: a module named so could replace or drop them."""
    before = dict(config.SETTINGS_META)
    refused(offline("core", settings={"tlp": "clear"}), "module name 'core' is reserved")
    refused(offline("core"), "is reserved")
    assert before == config.SETTINGS_META and config.SETTINGS_META["tlp"].default == "amber"
    assert "core" in module.RESERVED_NAMES


def test_checks_run_in_contract_order(reg):
    """Rules 3-4 (opsec <=> target, none => no hosts/provider) come before registry lookups (rules 5-7)."""
    refused(make("t_order_light", terms="open", opsec=Opsec.LIGHT, disclosure="third_party", provider="nope", sources=("nope.x",), hosts=(), max_requests=1, expected_latency=1.0, access_model="offline", default_enabled=False), "declare disclosure = 'target'")
    refused(offline("t_order_none", provider="nope"), "offline module (disclosure 'none') declares hosts or a provider")
    refused(make("t_order_tp", terms="open", opsec=Opsec.PASSIVE, disclosure="third_party", sources=("nope.x",), hosts=(), max_requests=1, expected_latency=1.0, access_model="free_noauth_unlimited"), "third_party module without a registered provider and sources")
    refused(offline("t_order_src", sources=("nope.x",)), "source 'nope.x' is not in the provider registry")


@pytest.mark.parametrize(
    ("attrs", "needle"),
    [
        ({"category": ["utility"]}, "unknown category"),
        ({"category": {"utility": 1}}, "unknown category"),
        ({"opsec": True}, "invalid opsec True"),
        ({"opsec": False}, "invalid opsec False"),
        ({"settings": {"Bad-Name": 1}}, "setting name 'Bad-Name' is invalid"),
        ({"settings": {"t_json_set": {1, 2}}}, "not JSON-serialisable"),
    ],
)
def test_malformed_values_raise_registration_errors(reg, attrs, needle):
    refused(offline("t_malformed", **attrs), needle)  # RegistrationError, never a TypeError


def test_sensitive_module_needs_sources_with_schemas(reg):
    """P327 cond 10 / A4: a sensitive module cannot register without a sanitizer schema - none without sources."""
    refused(offline("t_sens_nosrc", category="breach_leak"), "sensitive module (category breach_leak or a sensitive provider) without registry sources")


def test_target_module_hosts_need_registry_entries(reg):
    """AR11: every host a module declares has a registry entry, target-contact modules included."""
    add_provider("synth_tgt", sources={"wordlist": "open"})
    refused(target("t_tgt_unreg", hosts=("api.unregistered.example",)), "is not in the provider registry")
    refused(target("t_tgt_nosrc", hosts=("api.synth_tgt.example",)), "which has none of the module's sources")
    cls = register(target("t_tgt_ok", hosts=("api.synth_tgt.example",), sources=("synth_tgt.wordlist",)))
    assert cls.providers == frozenset({"synth_tgt"}) and cls.trust_tier == "n/a" and cls.terms_sources == {"synth_tgt.wordlist": "open"}
    assert register(target("t_tgt_plain")).hosts == ()  # target-derived hosts need no declaration


def test_subclass_inherits_the_settings_of_its_registered_base(reg):
    base = register(offline("t_set_base", settings={"t_set_base_limit": 5}))
    sub = register(make("t_set_sub", bases=(base,)))  # inherits the base's settings: no false collision
    assert sub.settings == {"t_set_base_limit": 5} and sub.describe()["settings"] == {"t_set_base_limit": 5}
    assert config.SETTINGS_META["t_set_base_limit"].owner == "t_set_base"
    refused(make("t_set_sub2", bases=(base,), settings={"t_set_base_limit": 9}), "collides with a setting of t_set_base")
    own = register(make("t_set_sub3", bases=(base,), settings={"t_set_sub3_extra": 1}))
    assert config.SETTINGS_META["t_set_sub3_extra"].owner == "t_set_sub3" and own.settings == {"t_set_sub3_extra": 1}


def test_shipped_modules_register_cleanly():
    """Acceptance: no load errors on the shipped tree and the reference modules carry v2 metadata."""
    load_modules()
    assert load_errors() == {}
    assert providers.registry().errors == []
    shodan = REGISTRY["shodan_internetdb"]
    assert shodan.terms == "noncommercial" and shodan.disclosure == "third_party" and shodan.trust_tier == "trusted"
    assert shodan.providers == frozenset({"shodan"}) and shodan.max_tlp is tlp.TLP.AMBER_STRICT
    dns = REGISTRY["dns_records"]
    assert dns.provider == "core_doh" and dns.sources == ("core_doh.resolvers",) and dns.hosts == ()
    ioc = REGISTRY["ioc_extract"]
    assert ioc.disclosure == "none" and ioc.shares_input is False and ioc.max_tlp is tlp.TLP.RED
    for cls in REGISTRY.values():
        assert cls.describe()["contract"] == "v2"
