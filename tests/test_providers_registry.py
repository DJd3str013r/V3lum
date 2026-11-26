"""Provider registry (AR11): fragments, validation, host ownership, profiles and the core seeds."""

from __future__ import annotations

import copy
import json
import threading
from pathlib import Path
from typing import Any

import pytest

from v3lum.config import Config
from v3lum.core import providers
from v3lum.core.providers import (
    ADMIRALTY,
    PROFILE_REQUIREMENTS,
    TERMS_ORDER,
    TIERS,
    TTL_CLASSES,
    ErrorMarker,
    HttpProfile,
    KeySpec,
    Provider,
    ProviderRegistry,
    QuotaSpec,
    Source,
    lowest_tier,
    most_restrictive,
    parse_marker,
)

SEEDS = {
    "core_doh", "google_public_dns", "cloudflare_dns", "quad9", "internal_doh", "shodan", "iana",
    "publicsuffix", "github", "abusech", "internal_misp", "internal_opencti",
}


def frag(pid: str = "synth", *, hosts: tuple[str, ...] = ("api.synth.example",), sources: dict[str, Any] | None = None, **over: Any) -> dict[str, Any]:
    """A valid 'v3lum.provider/1' fragment; keyword arguments override top-level fields."""
    src = sources if sources is not None else {"default": source()}
    data: dict[str, Any] = {
        "schema": "v3lum.provider/1",
        "id": pid,
        "name": f"Synthetic {pid}",
        "operator": "V3LUM tests",
        "hosts": list(hosts),
        "hosts_from_settings": [],
        "internal": False,
        "tier": "trusted",
        "tier_rationale": "synthetic provider for tests",
        "tier_reviewer": "tests",
        "tier_date": "2026-11-26",
        "flags": {"publishes_queries": False, "reuses_queries": False, "fetches_target": False, "sensitive": False},
        "personal_data_review": None,
        "reliability": {"grade": "B", "justification": "synthetic"},
        "http_profile": {},
        "quota": None,
        "error_markers": [],
        "keys": {},
        "sources": src,
    }
    data.update(over)
    return data


def source(cls: str = "open", **over: Any) -> dict[str, Any]:
    data: dict[str, Any] = {
        "title": "synthetic source",
        "terms": {
            "class": cls,
            "evidence_url": "https://terms.synth.example/",
            "quote": "synthetic terms quote",
            "checked_at": "2026-11-26",
            "reviewer": "tests",
            "free_plan_business_use": None,
        },
        "upstream_family": "synth",
        "sanitizer": None,
        "dataset": None,
        "notes": "",
    }
    data.update(over)
    return data


def write(directory: Path, name: str, data: Any) -> Path:
    path = directory / name
    path.write_text(json.dumps(data), encoding="utf-8")
    return path


@pytest.fixture()
def registry_state():
    """Restore the process-wide provider registry after the test."""
    state = providers.snapshot()
    yield
    providers.restore(state)


# ---------------------------------------------------------------------------------- shipped seeds


def test_every_seed_fragment_is_valid():
    reg = providers.load_dir()
    assert reg.errors == []
    assert {p.id for p in reg.providers()} >= SEEDS
    assert providers.registry().errors == []


def test_seed_files_are_named_after_their_ids():
    for pid in sorted(SEEDS):
        data = json.loads((providers.DATA_DIR / f"{pid}.json").read_text(encoding="utf-8"))
        assert data["schema"] == providers.SCHEMA_PROVIDER and data["id"] == pid
    for path in sorted(providers.DATA_DIR.glob("*.json")):
        data = json.loads(path.read_text(encoding="utf-8"))
        if path.stem.startswith("_set_"):
            assert data["schema"] == providers.SCHEMA_SET
        elif "__" in path.stem:
            assert data["schema"] == providers.SCHEMA_EXTENSION and data["extends"] == path.stem.split("__", 1)[0]
        else:
            assert data["schema"] == providers.SCHEMA_PROVIDER and data["id"] == path.stem


def _seed(pid: str) -> dict[str, Any]:
    """The seed fragment as shipped (packages may extend the provider; these assertions hold for the seed)."""
    return json.loads((providers.DATA_DIR / f"{pid}.json").read_text(encoding="utf-8"))


def test_abusech_classes_match_the_a1_initial_classes():
    reg = providers.load_dir()
    a1 = {
        "malwarebazaar": "license", "urlhaus": "license", "threatfox": "license",
        "yaraify": "open", "feodotracker": "open", "sslbl": "open",
    }
    assert {sid: s["terms"]["class"] for sid, s in _seed("abusech")["sources"].items()} == a1
    for sid, cls in a1.items():
        src = reg.source(f"abusech.{sid}")
        assert src.terms.class_ == cls and src.upstream_family == "abuse.ch"
    for sid in ("malwarebazaar", "urlhaus", "threatfox"):
        src = reg.source(f"abusech.{sid}")
        assert src.terms.free_plan_business_use is False
        assert src.licensed_alternative
    assert reg.source("abusech.feodotracker").terms.free_plan_business_use is True


def test_shodan_sources():
    reg = providers.load_dir()
    assert reg.source("shodan.internetdb").terms.class_ == "noncommercial"
    assert reg.source("shodan.cvedb").terms.class_ == "noncommercial"
    api = reg.source("shodan.api")
    assert api.terms.class_ == "key-terms" and api.terms.free_plan_business_use is None
    assert reg.provider_for_host("internetdb.shodan.io").id == "shodan"
    assert set(_seed("shodan")["hosts"]) == {"internetdb.shodan.io", "cvedb.shodan.io", "api.shodan.io", "www.shodan.io"}
    assert set(_seed("shodan")["hosts"]) <= set(reg.get("shodan").hosts)
    assert reg.get("shodan").keys["shodan"].env == ("SHODAN_API_KEY",)


def test_dns_and_reference_seeds():
    reg = providers.load_dir()
    core = reg.get("core_doh")
    assert _seed("core_doh")["hosts"] == [] and core.tier == "trusted" and core.flags == providers.ProviderFlags()
    assert reg.source("core_doh.resolvers").upstream_family == "dns"
    for pid, host in (("google_public_dns", "dns.google"), ("cloudflare_dns", "cloudflare-dns.com"), ("quad9", "dns.quad9.net")):
        prov = reg.get(pid)
        assert _seed(pid)["hosts"] == [host] and reg.provider_for_host(host) is prov and prov.tier == "trusted"
        assert prov.http_profile.ttl is not None and prov.http_profile.ttl <= 3600
        assert reg.source(f"{pid}.doh").terms.class_ == "open"
    assert reg.source("iana.tlds").terms.class_ == "open"
    assert reg.source("publicsuffix.psl").terms.class_ == "open"
    github = reg.get("github")
    assert _seed("github")["sources"] == {}  # dataset sources come from extension fragments
    assert github.keys["github"].env == ("GITHUB_TOKEN", "GH_TOKEN")
    assert {"github.com", "api.github.com", "raw.githubusercontent.com", "codeload.github.com", "objects.githubusercontent.com"} <= set(github.hosts)


def test_internal_seeds():
    reg = providers.load_dir()
    doh = reg.get("internal_doh")
    assert doh.internal and doh.hosts == () and doh.hosts_from_settings == ("doh_internal",)
    assert doh.flags == providers.ProviderFlags()
    src = reg.source("internal_doh.resolver")
    assert src.terms.class_ == "open" and src.upstream_family == "dns"
    misp, octi = reg.get("internal_misp"), reg.get("internal_opencti")
    assert misp.internal and misp.hosts_from_settings == ("misp_url",) and "misp" in misp.keys
    assert octi.internal and octi.hosts_from_settings == ("opencti_url",) and "opencti" in octi.keys
    assert reg.source("internal_misp.events").terms.class_ == "open"
    assert reg.source("internal_opencti.graphql").terms.class_ == "open"


def test_hosts_from_settings_resolution():
    reg = providers.load_dir()
    assert reg.hosts_for("internal_misp", {"misp_url": "https://misp.corp.example/events"}) == ("misp.corp.example",)
    assert reg.hosts_for("internal_misp", {"misp_url": "http://misp.corp.example/"}) == ()  # TLS only (A12)
    assert reg.hosts_for("internal_misp", {}) == ()
    assert reg.hosts_for("internal_misp", None) == ()
    cfg = Config()
    cfg.settings["doh_internal"] = "https://doh.corp.example/dns-query"
    assert reg.hosts_for("internal_doh", cfg) == ("doh.corp.example",)
    assert reg.hosts_for("shodan", cfg) == reg.get("shodan").hosts
    assert reg.hosts_for("no_such_provider", cfg) == ()


# ---------------------------------------------------------------------------------- ordering helpers


def test_most_restrictive_ordering():
    assert TERMS_ORDER == ("open", "key-terms", "license", "noncommercial", "unknown")
    for i, low in enumerate(TERMS_ORDER):
        for high in TERMS_ORDER[i:]:
            assert most_restrictive([low, high]) == high
            assert most_restrictive([high, low]) == high
    assert most_restrictive([]) == "open"
    assert most_restrictive(["open", "bogus"]) == "unknown"


def test_lowest_tier():
    assert TIERS == ("trusted", "community", "unknown")
    assert lowest_tier(["trusted"]) == "trusted"
    assert lowest_tier(["trusted", "community"]) == "community"
    assert lowest_tier(["community", "unknown", "trusted"]) == "unknown"
    assert lowest_tier([]) == "unknown"
    assert lowest_tier(["bogus"]) == "unknown"


def test_admiralty_and_ttl_classes():
    assert ADMIRALTY == {"A": 1.0, "B": 0.85, "C": 0.7, "D": 0.5, "E": 0.3, "F": 0.5}
    assert TTL_CLASSES == {"dns": 3600, "rdap": 86400, "cnpj": 259200, "sanitized_breach": 604800, "crypto": 3600, "sanctions": 86400}


# ---------------------------------------------------------------------------------- loading rules


def test_provider_file_parses_into_dataclasses(tmp_path):
    data = frag(
        "synth",
        sources={"feed": source("license", embeds=["abuse.ch", "spamhaus"], licensed_alternative="buy the Synth licence")},
        keys={"synth": {"description": "Synth key", "signup_url": "https://synth.example/keys", "env": ["SYNTH_API_KEY"], "multi_key": False, "plan_hint": "business plan"}},
        http_profile={"user_agent": "contact", "accept": "application/json", "timeout": 10, "retries": 0, "max_bytes": 1000, "ttl": 60, "min_interval": 1.5, "concurrency": 2},
        quota={"scope": "egress_ip", "hour": 25, "day": 100, "published": True, "evidence_url": "https://synth.example/limits"},
        error_markers=[{"id": "count", "regex": "API count exceeded", "maps_to": "quota", "reason": "Synth: daily quota exhausted"}],
        personal_data_review={"basis": "LIA 2026-11", "reviewer": "dpo", "date": "2026-11-20"},
        x_owner="tests",
    )
    write(tmp_path, "synth.json", data)
    reg = providers.load_dir(tmp_path)
    assert reg.errors == []
    prov = reg.get("synth")
    assert isinstance(prov, Provider) and prov.origin == "synth.json" and prov.extra == {"x_owner": "tests"}
    assert prov.http_profile == HttpProfile("contact", "application/json", None, 10.0, 0, 1000, 60, 1.5, 2)
    assert prov.http_profile.ua_kind == "contact" and prov.http_profile.ua_placeholders == frozenset({"contact"})
    assert prov.quota == QuotaSpec(scope="egress_ip", hour=25, day=100, published=True, evidence_url="https://synth.example/limits")
    assert prov.quota.budget("day") == 80 and prov.quota.budget("hour") == 20 and prov.quota.budget("month") is None
    assert prov.error_markers == (ErrorMarker(id="count", regex="API count exceeded", maps_to="quota", reason="Synth: daily quota exhausted"),)
    assert prov.keys["synth"] == KeySpec("synth", "synth", "Synth key", "https://synth.example/keys", ("SYNTH_API_KEY",), False, "business plan")
    assert prov.personal_data_review.reviewer == "dpo"
    src = reg.source("synth.feed")
    assert isinstance(src, Source) and src.sid == "feed" and src.provider == "synth"
    assert src.embeds == ("abuse.ch", "spamhaus") and src.licensed_alternative == "buy the Synth licence"
    assert src.families == frozenset({"synth", "abuse.ch", "spamhaus"})
    assert prov.source("feed") is src and prov.source("synth.feed") is src and prov.source("other.feed") is None
    assert reg.keys()["synth"].provider == "synth"


@pytest.mark.parametrize(
    ("mutate", "needle"),
    [
        (lambda d: d.update(tier="famous"), "tier must be one of"),
        (lambda d: d.update(tier_date="26/11/2026"), "tier_date"),
        (lambda d: d.update(reliability={"grade": "Z", "justification": "x"}), "reliability"),
        (lambda d: d["flags"].pop("sensitive"), "flags.sensitive"),
        (lambda d: d.update(name=""), "name is required"),
        (lambda d: d.update(hosts=["HTTPS://Api.Synth.Example/path"]), "invalid host"),
        (lambda d: d.update(hosts=["*.com"]), "invalid host"),
        (lambda d: d.update(colour="blue"), "unknown field"),
        (lambda d: d["sources"]["default"]["terms"].update({"class": "free"}), "terms.class"),
        (lambda d: d["sources"]["default"]["terms"].update({"checked_at": "yesterday"}), "checked_at"),
        (lambda d: d["sources"]["default"]["terms"].update({"evidence_url": ""}), "evidence_url"),
        (lambda d: d["sources"]["default"]["terms"].update({"quote": ""}), "quote is required"),
        (lambda d: d["sources"]["default"].update(upstream_family=""), "upstream_family"),
        (lambda d: d.update(keys={"synth": {"description": "x", "env": ["SYNTH_KEY"], "multi_key": True}}), "multi_key"),
        (lambda d: d.update(http_profile={"user_agent": "Synth/{version} {email}"}), "unknown placeholder"),
        (lambda d: d.update(http_profile={"user_agent": "Mozilla/5.0 (X11) Gecko/{version}"}), "browser UA"),
        (lambda d: d.update(quota={"scope": "egress_ip", "day": 100, "published": True, "evidence_url": "https://x.example/", "safety_margin": 0.95}), "safety_margin"),
        (lambda d: d.update(quota={"scope": "egress_ip", "published": True, "evidence_url": "https://x.example/"}), "at least one of"),
        (lambda d: d.update(error_markers=[{"id": "x", "regex": "boom", "maps_to": "empty", "reason": "Synth"}]), "maps_to"),
    ],
)
def test_invalid_fragments_are_errors_and_dropped(tmp_path, mutate, needle, registry_state):
    data = frag("synth")
    mutate(data)
    write(tmp_path, "synth.json", data)
    reg = providers.load_dir(tmp_path)
    assert isinstance(reg, ProviderRegistry)
    assert reg.get("synth") is None  # fail closed: the provider and its hosts stay unregistered
    assert reg.provider_for_host("api.synth.example") is None
    assert any(needle in e for e in reg.errors), reg.errors
    with pytest.raises(ValueError, match="synth"):
        providers.register(data)
    assert providers.registry().get("synth") is None


def test_unknown_terms_need_no_quote(tmp_path):
    data = frag("synth", sources={"default": source("unknown")})
    data["sources"]["default"]["terms"].update(evidence_url="", quote="")
    write(tmp_path, "synth.json", data)
    reg = providers.load_dir(tmp_path)
    assert reg.errors == [] and reg.source("synth.default").terms.class_ == "unknown"


def test_id_must_match_file_stem_and_bad_json_is_reported(tmp_path):
    write(tmp_path, "other.json", frag("synth"))
    (tmp_path / "broken.json").write_text("{not json", encoding="utf-8")
    reg = providers.load_dir(tmp_path)
    assert any("file name stem" in e for e in reg.errors)
    assert any(e.startswith("broken.json: invalid JSON") for e in reg.errors)
    assert len(reg) == 0


def test_host_owned_twice_is_an_error(tmp_path, registry_state):
    write(tmp_path, "alpha.json", frag("alpha", hosts=("shared.synth.example", "a.synth.example")))
    write(tmp_path, "beta.json", frag("beta", hosts=("shared.synth.example",)))
    reg = providers.load_dir(tmp_path)
    assert reg.get("alpha") is not None and reg.get("beta") is None
    assert any("already owned by provider 'alpha'" in e for e in reg.errors)
    assert reg.provider_for_host("shared.synth.example").id == "alpha"
    # programmatic registration of a host owned by a seed fragment
    with pytest.raises(ValueError, match="already owned"):
        providers.register(frag("thief", hosts=("internetdb.shodan.io",)))
    with pytest.raises(ValueError, match="duplicate provider id"):
        providers.register(frag("shodan", hosts=("other.synth.example",)))


def test_key_declared_by_two_providers_is_an_error(tmp_path):
    key = {"shared": {"description": "x", "signup_url": "", "env": [], "multi_key": False, "plan_hint": ""}}
    write(tmp_path, "alpha.json", frag("alpha", hosts=("a.synth.example",), keys=key))
    write(tmp_path, "beta.json", frag("beta", hosts=("b.synth.example",), keys=key))
    reg = providers.load_dir(tmp_path)
    assert reg.get("beta") is None and any("key 'shared' is already declared" in e for e in reg.errors)


def test_extension_is_add_only(tmp_path):
    write(tmp_path, "alpha.json", frag("alpha", hosts=("a.synth.example",)))
    ext = {
        "schema": "v3lum.provider-ext/1",
        "extends": "alpha",
        "hosts": ["data.synth.example"],
        "sources": {"dataset": source("noncommercial", dataset="synth_list.txt")},
        "error_markers": [{"id": "busy", "statuses": [200, 503], "json_path": "status", "equals": "busy", "maps_to": "rate_limited", "reason": "Alpha: busy"}],
    }
    write(tmp_path, "alpha__datasets.json", ext)
    write(tmp_path, "alpha__dup.json", {**ext, "hosts": [], "error_markers": [], "sources": {"default": source()}})
    write(tmp_path, "alpha__tier.json", {"schema": "v3lum.provider-ext/1", "extends": "alpha", "tier": "unknown"})
    write(tmp_path, "ghost__x.json", {"schema": "v3lum.provider-ext/1", "extends": "ghost", "hosts": ["g.synth.example"]})
    write(tmp_path, "alpha__steal.json", {"schema": "v3lum.provider-ext/1", "extends": "alpha", "hosts": ["a.synth.example"]})
    reg = providers.load_dir(tmp_path)
    alpha = reg.get("alpha")
    assert alpha.hosts == ("a.synth.example", "data.synth.example")
    assert set(alpha.sources) == {"default", "dataset"} and reg.source("alpha.dataset").dataset == "synth_list.txt"
    assert [m.id for m in alpha.error_markers] == ["busy"] and alpha.error_markers[0].statuses == (200, 503)
    assert reg.provider_for_host("data.synth.example").id == "alpha"
    joined = "\n".join(reg.errors)
    assert "alpha__dup.json" in joined and "already exists" in joined
    assert "alpha__tier.json" in joined and "add only" in joined
    assert "ghost__x.json" in joined and "not registered" in joined
    assert "alpha__steal.json" in joined and "already listed" in joined
    assert reg.get("alpha").tier == "trusted"


def test_extension_cannot_take_a_host_of_another_provider(tmp_path):
    write(tmp_path, "alpha.json", frag("alpha", hosts=("a.synth.example",)))
    write(tmp_path, "beta.json", frag("beta", hosts=("b.synth.example",)))
    write(tmp_path, "beta__x.json", {"schema": "v3lum.provider-ext/1", "extends": "beta", "hosts": ["a.synth.example"]})
    reg = providers.load_dir(tmp_path)
    assert reg.get("beta").hosts == ("b.synth.example",)
    assert any("already owned by provider 'alpha'" in e for e in reg.errors)


def test_provider_set(tmp_path):
    write(tmp_path, "_set_sites.json", {
        "schema": "v3lum.provider-set/1",
        "providers": [
            {k: v for k, v in frag("site_one", hosts=("one.synth.example",)).items() if k != "schema"},
            frag("site_two", hosts=("two.synth.example",)),
            frag("site_bad", hosts=("bad.synth.example",), tier="?"),
        ],
    })
    reg = providers.load_dir(tmp_path)
    assert {p.id for p in reg.providers()} == {"site_one", "site_two"}
    assert reg.get("site_one").origin == "_set_sites.json[0]"
    assert any(e.startswith("_set_sites.json[2]") for e in reg.errors)
    write(tmp_path, "_set_broken.json", {"schema": "v3lum.provider/1", "providers": []})
    assert any("_set_broken.json" in e for e in providers.load_dir(tmp_path).errors)


def test_wildcard_lookup_and_strict_subdomain_rule(registry_state):
    providers.register(frag("wild", hosts=("*.cdn.synth.example", "exact.synth.example")))
    providers.register(frag("narrow", hosts=("*.eu.cdn.synth.example", "pinned.cdn.synth.example")))
    reg = providers.registry()
    assert reg.provider_for_host("a.cdn.synth.example").id == "wild"
    assert reg.provider_for_host("A.CDN.Synth.Example.").id == "wild"
    assert reg.provider_for_host("deep.a.cdn.synth.example").id == "wild"
    assert reg.provider_for_host("cdn.synth.example") is None  # strict subdomains only
    assert reg.provider_for_host("x.eu.cdn.synth.example").id == "narrow"  # longest wildcard wins
    assert reg.provider_for_host("pinned.cdn.synth.example").id == "narrow"  # exact before wildcard
    assert reg.provider_for_host("exact.synth.example").id == "wild"
    assert reg.provider_for_host("other.synth.example") is None
    assert reg.provider_for_host("*.cdn.synth.example").id == "wild"  # identical wildcard pattern
    assert reg.provider_for_host("") is None
    assert providers.host_matches("a.b.example", "*.b.example") and not providers.host_matches("b.example", "*.b.example")
    assert providers.host_matches("*.x.b.example", "*.b.example") and not providers.host_matches("evilb.example", "*.b.example")


def test_register_unregister_reload_and_snapshot(registry_state):
    before = providers.snapshot()
    prov = providers.register(frag("synth_live"))
    assert providers.registry().get("synth_live") is prov
    ext = providers.register({"schema": "v3lum.provider-ext/1", "extends": "synth_live", "hosts": ["more.synth.example"], "sources": {"extra": source()}})
    assert ext.hosts == ("api.synth.example", "more.synth.example")
    assert providers.reload().get("synth_live").hosts == ("api.synth.example", "more.synth.example")  # survives reload
    assert providers.unregister("synth_live") is True
    assert providers.registry().get("synth_live") is None and providers.reload().get("synth_live") is None
    assert providers.unregister("synth_live") is False
    providers.register(frag("synth_live"))
    providers.restore(before)
    assert providers.registry().get("synth_live") is None
    with pytest.raises(ValueError, match="register"):
        providers.register({"schema": "v3lum.provider-set/1", "providers": []})


def test_registry_lists_are_sorted():
    reg = providers.load_dir()
    assert [p.id for p in reg.providers()] == sorted(p.id for p in reg.providers())
    assert [s.id for s in reg.sources()] == sorted(s.id for s in reg.sources())
    assert "abusech" in reg and len(reg) >= len(SEEDS)


# ---------------------------------------------------------------------------------- error markers


def test_parse_marker():
    m = parse_marker({"id": "hackertarget_count", "regex": "API count exceeded", "maps_to": "quota", "reason_code": "quota", "reason": "HackerTarget: daily quota exhausted"})
    assert m.statuses == (200,) and m.reason_code == "quota"
    assert parse_marker(m.to_dict()) == m and parse_marker(m) == m
    j = parse_marker({"id": "criminalip_403", "json_path": "status", "equals": 403, "maps_to": "blocked", "reason": "Criminal IP: key rejected"})
    assert j.to_dict()["equals"] == 403 and hash(j)
    u = parse_marker({"id": "isc_blockme", "final_url_regex": "/blockme\\.html", "maps_to": "blocked", "reason_code": "challenge", "reason": "SANS ISC block page"})
    assert u.final_url_regex
    bad = [
        {"id": "x", "regex": "a", "maps_to": "empty", "reason": "r"},
        {"id": "x", "regex": "a", "maps_to": "quota", "reason_code": "challenge", "reason": "r"},
        {"id": "x", "regex": "(", "maps_to": "error", "reason": "r"},
        {"id": "x", "json_path": "status", "maps_to": "error", "reason": "r"},
        {"id": "x", "maps_to": "error", "reason": "r"},
        {"id": "x", "regex": "a", "maps_to": "error", "reason": ""},
        {"id": "X Y", "regex": "a", "maps_to": "error", "reason": "r"},
        {"id": "x", "regex": "a", "statuses": [99], "maps_to": "error", "reason": "r"},
        {"id": "x", "regex": "a", "maps_to": "error", "reason": "r", "bypass": True},
        "not a dict",
    ]
    for item in bad:
        with pytest.raises(ValueError):
            parse_marker(item)


def test_duplicate_marker_ids_in_a_provider(tmp_path):
    marker = {"id": "busy", "regex": "busy", "maps_to": "rate_limited", "reason": "Synth: busy"}
    write(tmp_path, "synth.json", frag("synth", error_markers=[marker, marker]))
    reg = providers.load_dir(tmp_path)
    assert reg.get("synth") is None and any("duplicate error marker id" in e for e in reg.errors)


# ---------------------------------------------------------------------------------- PROFILE_REQUIREMENTS


def _compliant(pattern: str, req: dict[str, Any]) -> dict[str, Any]:
    host = pattern.replace("*.", "www.")
    profile = {k: v for k, v in req.items() if k != "flags.sensitive"}
    data = frag("compliant", hosts=(host,), http_profile=profile)
    if "flags.sensitive" in req:
        data["flags"]["sensitive"] = req["flags.sensitive"]
    return data


def _free_host(pattern: str) -> None:
    """Unregister the seed provider owning the host a test fragment is about to claim."""
    owner = providers.registry().provider_for_host(pattern.replace("*.", "www."))
    if owner is not None:
        providers.unregister(owner.id)


@pytest.mark.parametrize("pattern", sorted(PROFILE_REQUIREMENTS))
def test_profile_requirements_accept_a_compliant_fragment(pattern, registry_state):
    _free_host(pattern)
    prov = providers.register(_compliant(pattern, PROFILE_REQUIREMENTS[pattern]))
    assert providers.profile_violations(prov) == []


@pytest.mark.parametrize("pattern", sorted(PROFILE_REQUIREMENTS))
def test_profile_requirements_reject_a_contradicting_fragment(pattern, registry_state):
    req = PROFILE_REQUIREMENTS[pattern]
    data = _compliant(pattern, req)
    if "user_agent" in req:
        data["http_profile"]["user_agent"] = "browser"
    elif "accept" in req:
        data["http_profile"]["accept"] = "text/html"
    else:
        data["http_profile"]["ttl"] = req["ttl"] * 2
    _free_host(pattern)
    with pytest.raises(ValueError, match="PROFILE_REQUIREMENTS"):
        providers.register(data)


def test_profile_requirement_examples(tmp_path):
    write(tmp_path, "registrobr.json", frag("registrobr", hosts=("rdap.registro.br",), http_profile={"user_agent": "browser", "accept": "application/rdap+json", "accept_language": "pt-BR", "ttl": 3600}))
    write(tmp_path, "hibp.json", frag("hibp", hosts=("haveibeenpwned.com",), http_profile={"user_agent": "neutral", "ttl": 3600}))
    write(tmp_path, "wiki.json", frag("wiki", hosts=("*.wikipedia.org",), http_profile={"user_agent": "contact"}))
    write(tmp_path, "slowdns.json", frag("slowdns", hosts=("dns.google",), http_profile={}))
    reg = providers.load_dir(tmp_path)
    joined = "\n".join(reg.errors)
    assert reg.get("registrobr") is None and "user_agent = 'neutral'" in joined
    assert reg.get("hibp") is None and "flags.sensitive=true" in joined
    assert reg.get("wiki") is None and "python-requests" in joined
    assert reg.get("slowdns") is None and "ttl <= 3600" in joined


def test_profile_requirement_applies_to_extensions(tmp_path):
    write(tmp_path, "alpha.json", frag("alpha", hosts=("a.synth.example",), http_profile={"user_agent": "browser"}))
    write(tmp_path, "alpha__br.json", {"schema": "v3lum.provider-ext/1", "extends": "alpha", "hosts": ["registro.br"]})
    reg = providers.load_dir(tmp_path)
    assert reg.get("alpha").hosts == ("a.synth.example",)
    assert reg.provider_for_host("registro.br") is None
    assert any("alpha__br.json" in e and "PROFILE_REQUIREMENTS" in e for e in reg.errors)


def test_registry_objects_are_frozen():
    prov = providers.load_dir().get("shodan")
    with pytest.raises(AttributeError):
        prov.tier = "unknown"  # type: ignore[misc]
    assert hash(prov) == hash("shodan")
    copy.deepcopy(prov)


# ---------------------------------------------------------------------------------- review hardening


@pytest.mark.parametrize(
    "mutate",
    [
        lambda d: d.update(reliability={"grade": ["A"], "justification": "x"}),
        lambda d: d.update(reliability={"grade": {"A": 1}, "justification": "x"}),
        lambda d: d.update(reliability=["A"]),
        lambda d: d.update(tier=["trusted"]),
        lambda d: d.update(flags=[1, 2]),
        lambda d: d.update(http_profile={"user_agent": ["neutral"]}),
        lambda d: d.update(quota={"scope": ["key"], "day": 1, "published": False}),
        lambda d: d.update(error_markers=[{"id": "x", "regex": "a", "maps_to": ["quota"], "reason": "r"}]),
        lambda d: d["sources"]["default"]["terms"].update({"class": ["open"]}),
    ],
)
def test_unhashable_values_are_errors_never_crashes(tmp_path, mutate, registry_state):
    """'Never raised': a malformed fragment is an error entry, not a TypeError that kills registry()."""
    data = frag("synth")
    mutate(data)
    write(tmp_path, "synth.json", data)
    reg = providers.load_dir(tmp_path)  # must not raise
    assert reg.get("synth") is None and reg.errors and all(e.startswith("synth.json") for e in reg.errors)
    with pytest.raises(ValueError):
        providers.register(data)


def test_provider_files_must_name_their_schema(tmp_path, registry_state):
    data = frag("synth")
    del data["schema"]
    write(tmp_path, "synth.json", data)
    reg = providers.load_dir(tmp_path)
    assert reg.get("synth") is None and any("schema is required" in e for e in reg.errors)
    assert providers.register(data).id == "synth"  # programmatic fragments may omit it


@pytest.mark.parametrize("pattern", ["*.co.uk", "*.com.br", "*.gov.br", "*.github.io", "*.amazonaws.com", "*.blogspot.com", "*.cloudfront.net"])
def test_wildcards_over_public_suffix_namespaces_are_refused(tmp_path, pattern, registry_state):
    """A PASSIVE module may reach only declared hosts: '*.com.br' would let it reach any registrant (a target)."""
    write(tmp_path, "synth.json", frag("synth", hosts=("api.synth.example", pattern)))
    reg = providers.load_dir(tmp_path)
    assert reg.get("synth") is None and any("public-suffix namespace" in e and pattern in e for e in reg.errors)
    write(tmp_path, "synth.json", frag("synth", hosts=("api.synth.example",)))
    write(tmp_path, "synth__wide.json", {"schema": "v3lum.provider-ext/1", "extends": "synth", "hosts": [pattern]})
    reg = providers.load_dir(tmp_path)
    assert reg.get("synth").hosts == ("api.synth.example",) and any("synth__wide.json" in e for e in reg.errors)


def test_registrable_wildcards_stay_allowed(tmp_path):
    write(tmp_path, "synth.json", frag("synth", hosts=("*.synth.example", "*.wikidata.example", "*.github.com")))
    reg = providers.load_dir(tmp_path)
    assert reg.errors == [] and reg.provider_for_host("api.github.com").id == "synth"


@pytest.mark.parametrize("ip", ["127.0.0.1", "10.1.2.3", "192.168.0.10", "169.254.169.254", "100.64.0.1", "::1", "fd00::1", "0.0.0.0"])
def test_non_global_ip_literals_are_refused_as_static_hosts(tmp_path, ip, registry_state):
    write(tmp_path, "synth.json", frag("synth", hosts=(ip,)))
    reg = providers.load_dir(tmp_path)
    assert reg.get("synth") is None and any("private, loopback, link-local or reserved" in e for e in reg.errors)


def test_global_ip_literals_are_accepted(tmp_path):
    write(tmp_path, "synth.json", frag("synth", hosts=("8.8.8.8", "2001:4860:4860::8888")))
    reg = providers.load_dir(tmp_path)
    assert reg.errors == [] and reg.provider_for_host("8.8.8.8").id == "synth"


def test_hosts_from_settings_never_claim_another_providers_host():
    """A misp_url pointing at a third-party host must not become an 'internal' host (allowed at TLP:RED)."""
    reg = providers.load_dir()
    assert reg.hosts_for("internal_misp", {"misp_url": "https://internetdb.shodan.io/"}) == ()
    assert reg.hosts_for("internal_doh", {"doh_internal": "https://dns.google/resolve"}) == ()
    assert reg.hosts_for("internal_misp", {"misp_url": "https://user:pw@misp.corp.example/"}) == ("misp.corp.example",)


@pytest.mark.parametrize(
    ("cls", "flag", "ok"),
    [
        ("open", True, True), ("open", None, True), ("open", False, False),
        ("key-terms", True, True), ("key-terms", False, True), ("key-terms", None, True),
        ("license", False, True), ("license", True, False),
        ("noncommercial", None, True), ("noncommercial", True, False),
        ("unknown", None, True),
    ],
)
def test_free_plan_business_use_must_not_contradict_the_class(tmp_path, cls, flag, ok):
    src = source(cls)
    src["terms"]["free_plan_business_use"] = flag
    write(tmp_path, "synth.json", frag("synth", sources={"default": src}))
    reg = providers.load_dir(tmp_path)
    assert (reg.get("synth") is not None) is ok, reg.errors
    if not ok:
        assert any("contradicts class" in e for e in reg.errors)


@pytest.mark.parametrize(
    ("sanitizer", "needle"),
    [
        ({"keep": ["breaches[].Name", "a..b"]}, "keep path 'a..b' is invalid"),
        ({"keep": ["items[0].name"]}, "keep path 'items[0].name' is invalid"),
        ({"keep": ["breaches[].Name"], "drop": ["password"]}, "unknown sanitizer field"),
        ({"keep": []}, "sanitizer must be null"),
    ],
)
def test_sanitizer_blocks_are_validated(tmp_path, sanitizer, needle):
    write(tmp_path, "synth.json", frag("synth", sources={"default": source(sanitizer=sanitizer)}))
    reg = providers.load_dir(tmp_path)
    assert reg.get("synth") is None and any(needle in e for e in reg.errors), reg.errors


def test_valid_sanitizer_block_is_kept(tmp_path):
    keep = {"keep": ["breaches[].Name", "*.count", "[].date", "stealers[].date_compromised"], "notes": "metadata only"}
    write(tmp_path, "synth.json", frag("synth", sources={"default": source(sanitizer=keep)}))
    reg = providers.load_dir(tmp_path)
    assert reg.errors == [] and reg.source("synth.default").sanitizer == keep


def test_register_keeps_a_private_copy_of_the_fragment(registry_state):
    data = frag("synth_copy")
    providers.register(data)
    data["hosts"].append("evil.synth.example")
    data["sources"]["default"]["terms"]["class"] = "open"
    data["tier"] = "unknown"
    reloaded = providers.reload().get("synth_copy")
    assert reloaded.hosts == ("api.synth.example",) and reloaded.tier == "trusted"


@pytest.mark.parametrize("ua", ["contact", "Tool/{version} (+{contact})", "keycdn-tools:{contact_url}"])
def test_contact_ua_is_refused_for_unknown_tier_providers(tmp_path, ua):
    """P326 cond 5: the identifying UA never goes to unknown-tier providers."""
    write(tmp_path, "synth.json", frag("synth", tier="unknown", http_profile={"user_agent": ua}))
    reg = providers.load_dir(tmp_path)
    assert reg.get("synth") is None and any("unknown-tier" in e for e in reg.errors)
    write(tmp_path, "synth.json", frag("synth", tier="community", http_profile={"user_agent": ua}))
    assert providers.load_dir(tmp_path).errors == []
    write(tmp_path, "synth.json", frag("synth", tier="unknown", http_profile={"user_agent": "neutral"}))
    assert providers.load_dir(tmp_path).errors == []


def test_concurrent_registrations_and_lookups(registry_state):
    """The engine reads the registry from worker threads while plugins/tests register providers."""
    errors: list[BaseException] = []
    start = threading.Barrier(9)

    def registrar(i: int) -> None:
        try:
            start.wait()
            providers.register(frag(f"synth_t{i}", hosts=(f"api.t{i}.synth.example",)))
        except BaseException as exc:  # pragma: no cover - reported below
            errors.append(exc)

    def reader() -> None:
        try:
            start.wait()
            for _ in range(200):
                reg = providers.registry()
                assert reg.provider_for_host("internetdb.shodan.io").id == "shodan"
                assert reg.source("abusech.urlhaus").terms.class_ == "license"
        except BaseException as exc:  # pragma: no cover - reported below
            errors.append(exc)

    threads = [threading.Thread(target=registrar, args=(i,)) for i in range(8)] + [threading.Thread(target=reader)]
    for t in threads:
        t.start()
    for t in threads:
        t.join(timeout=10)
    assert errors == []
    reg = providers.registry()
    assert all(reg.provider_for_host(f"api.t{i}.synth.example").id == f"synth_t{i}" for i in range(8))
    assert reg.errors == []


def test_abusech_licence_sources_quote_the_commercial_use_clause():
    reg = providers.load_dir()
    for sid in ("malwarebazaar", "urlhaus", "threatfox"):
        terms = reg.source(f"abusech.{sid}").terms
        assert "may require a paid subscription" in terms.quote and terms.evidence_url == "https://abuse.ch/terms-of-use/"
    assert "commercial and non-commercial purposes" in reg.source("abusech.sslbl").terms.quote
