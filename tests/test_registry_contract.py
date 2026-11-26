"""Registry contract test (module-author contract v2, section 22) - gates every module merge (A16).

Every check re-derives the rules from the class body and the registries, independently of
``@register``: a module inserted into the REGISTRY without registration (or a class defined in a
module file but never registered) is still caught. Failures name the module and the fix.

Covered: no load/registry/vocab/link/rule/noise/attack errors; v2 enums and explicit declarations;
every host and source registered; terms == most restrictive source class; the A3 default rules;
LIGHT/ACTIVE offline self-test and the safety-suite merge gate; keys and packages registered;
unique settings; a test file + fixtures per module (compiled P331 specs use
tests/fixtures/specs/<name>/); sensitive modules have sanitizer schemas; rule fixtures for
non-legacy rules; dataset sources and licences registered; notice fragments parse.
"""

from __future__ import annotations

import importlib
import inspect
import json
import pkgutil
import re
import warnings
from pathlib import Path
from typing import Any

import pytest

from v3lum import config
from v3lum.core import correlate, datasets, links, providers, sanitize, vocab
from v3lum.core import module as modreg
from v3lum.core.entities import PERSONAL_TYPES, EntityType
from v3lum.core.http import NEVER_ABSENT_STATUS
from v3lum.core.models import Opsec
from v3lum.core.tlp import TLP

ROOT = Path(__file__).resolve().parent.parent
TESTS = ROOT / "tests"
FIXTURES = TESTS / "fixtures"
SAFETY_GATE = TESTS / "safety" / "test_scope.py"
NOTICES = ROOT / "v3lum" / "data" / "notices"
REFERENCE_MODULES = ("dns_records", "email_basics", "shodan_internetdb", "ioc_extract")

NAME_RE = re.compile(r"^[a-z][a-z0-9_]{2,63}$")
COUNTRY_RE = re.compile(r"^[A-Z]{2}$")
NOT_DEFAULT_TAGS = frozenset({"high_fp", "bulk_download", "people_sweep", "sensitive_sites", "fresh_assessment"})
NETWORKED = ("third_party", "internal", "target")
TIER_ORDER = ("trusted", "community", "unknown")  # most to least trusted (A8)
NOTICE_NAME_RE = re.compile(r"^[a-z0-9][a-z0-9_.-]{0,63}$")
SHA256_RE = re.compile(r"^[0-9a-f]{64}$")

modreg.load_modules()
#: shipped modules: classes from the v3lum package and compiled P331 specs (synthetic test modules
#: registered by other test files are not part of the shipped tree)
MODULE_NAMES = sorted(
    name for name, cls in modreg.REGISTRY.items() if cls.__module__.startswith("v3lum.") or getattr(cls, "spec_origin", "")
)


# --------------------------------------------------------------------------------------
# helpers
# --------------------------------------------------------------------------------------


#: attribute names @register wrote on a class (derived values, filled defaults): not declarations
SET_BY_REGISTER = getattr(modreg, "_MARK", "__v3lum_set_by_register__")


def declared(cls: type, attr: str) -> bool:
    """Declared in the class body or a base other than Module (compiled specs and mixins count);
    values @register wrote on the class do not count."""
    for klass in cls.__mro__:
        if klass is modreg.Module or klass is object:
            continue
        own = vars(klass)
        if attr in own and attr not in own.get(SET_BY_REGISTER, ()):
            return True
    return False


def registered_ancestors(cls: type) -> set[str]:
    """Names of the registered base modules whose settings ``cls`` inherits without re-declaring
    them (a class body that declares ``settings`` owns all of its settings)."""
    if "settings" in vars(cls) and "settings" not in vars(cls).get(SET_BY_REGISTER, ()):
        return set()
    names = set()
    for klass in cls.__mro__[1:]:
        if isinstance(klass, type) and issubclass(klass, modreg.Module) and klass is not modreg.Module:
            base_name = str(vars(klass).get("name", "") or "")
            if base_name and modreg.REGISTRY.get(base_name) is klass:
                names.add(base_name)
    return names


def source_providers(cls: type) -> set[str]:
    return {str(sid).split(".", 1)[0] for sid in getattr(cls, "sources", ()) or ()}


def module_providers(cls: type) -> set[str]:
    pids = source_providers(cls)
    if getattr(cls, "provider", ""):
        pids.add(cls.provider)
    return pids


def host_ok(host: str, allowed_providers: set[str], reg: Any) -> bool:
    """The host (or '*.suffix' pattern) is owned by one of the module's providers."""
    owner = reg.provider_for_host(host)
    return owner is not None and owner.id in allowed_providers


def _lowest_tier(tiers: Any) -> str:
    seen = [t if t in TIER_ORDER else "unknown" for t in tiers]
    return max(seen, key=TIER_ORDER.index) if seen else "unknown"


def expected_derived(cls: type, reg: Any) -> dict[str, Any]:
    """Section 2 derived attributes re-computed from the provider registry (never from @register)."""
    disclosure = getattr(cls, "disclosure", None)
    known = [reg.get(p) for p in sorted(module_providers(cls)) if reg.get(p) is not None]
    receivers = known if disclosure != "none" else []
    tier = _lowest_tier(p.tier for p in known) if disclosure == "third_party" else "n/a"
    publishes = any(p.flags.publishes_queries for p in receivers)
    reuses = any(p.flags.reuses_queries for p in receivers)
    if publishes:
        ceiling: Any = None  # rule 7: never receives a value
    elif disclosure in ("none", "internal"):
        ceiling = TLP.RED
    elif disclosure == "target":
        ceiling = TLP.AMBER
    elif reuses or tier not in ("trusted", "community"):
        ceiling = TLP.GREEN
    else:
        ceiling = TLP.AMBER_STRICT if tier == "trusted" else TLP.AMBER
    return {
        "providers": frozenset(p.id for p in known),
        "trust_tier": tier,
        "sensitive": getattr(cls, "category", "") == "breach_leak" or any(p.flags.sensitive for p in known),
        "publishes_queries": publishes,
        "reuses_queries": reuses,
        "fetches_target": any(p.flags.fetches_target for p in receivers),
        "shares_input": disclosure in ("third_party", "target"),
        "max_tlp": ceiling,
    }


def module_problems(cls: type) -> list[str]:
    """Every contract-v2 violation of ``cls`` as 'problem - fix' strings (empty = compliant)."""
    reg = providers.registry()
    out: list[str] = []
    name = str(getattr(cls, "name", "") or "")

    def bad(problem: str, fix: str) -> None:
        out.append(f"{name or cls.__name__}: {problem} - {fix}")

    # ---- identity ------------------------------------------------------------------
    if not NAME_RE.match(name):
        bad("name must match ^[a-z][a-z0-9_]{2,63}$", "rename the module")
    for attr in ("title", "description"):
        if not str(getattr(cls, attr, "") or "").strip():
            bad(f"{attr} is empty", f"declare a {attr}")
    if getattr(cls, "category", None) not in modreg.CATEGORIES:
        bad(f"unknown category {getattr(cls, 'category', None)!r}", f"use one of {', '.join(modreg.CATEGORIES)}")
    accepts = getattr(cls, "accepts", ())
    if not accepts or not all(isinstance(t, EntityType) for t in accepts):
        bad("accepts must be a non-empty set of EntityType", "declare accepts = {EntityType...}")
    if not all(isinstance(t, EntityType) for t in getattr(cls, "produces", ()) or ()):
        bad("produces must contain EntityType members", "fix produces")
    if getattr(cls, "run_on", "any") not in modreg.RUN_ON:
        bad(f"run_on {getattr(cls, 'run_on', None)!r} is not one of {modreg.RUN_ON}", "fix run_on")
    reference = getattr(cls, "reference", "")
    if not isinstance(reference, str) or (reference and not re.match(r"^https?://\S+$", reference)):
        bad(f"reference {reference!r} is not an http(s) URL", "point reference to the source's documentation or terms page")

    # ---- explicit declarations and removed names -------------------------------------
    for attr in modreg.MUST_DECLARE:
        if not declared(cls, attr):
            bad(f"{attr} is not declared in the class body", f"declare {attr} explicitly (contract v2: no implicit defaults)")
    disclosure = getattr(cls, "disclosure", None)
    if disclosure in NETWORKED:
        for attr in modreg.MUST_DECLARE_NETWORKED:
            if not declared(cls, attr):
                bad(f"{attr} is not declared (disclosure {disclosure!r})", f"declare {attr}")
    for attr in modreg.REMOVED:
        if declared(cls, attr):
            bad(f"{attr} is a removed v1 name", "delete it (UA comes from the provider http_profile; shares_input is derived)")
    for attr in modreg.DERIVED:
        if attr not in modreg.REMOVED and declared(cls, attr):
            bad(f"{attr} is derived from the provider registry", "delete it: @register sets derived names")

    # ---- enums -----------------------------------------------------------------------
    terms = getattr(cls, "terms", None)
    opsec = getattr(cls, "opsec", None)
    if terms not in modreg.TERMS:
        bad(f"terms {terms!r} is not one of {modreg.TERMS}", "declare the terms class of its sources")
    if not isinstance(opsec, Opsec):
        bad(f"opsec {opsec!r} is not an Opsec member", "use Opsec.PASSIVE | LIGHT | ACTIVE")
    if disclosure not in modreg.DISCLOSURES:
        bad(f"disclosure {disclosure!r} is not one of {modreg.DISCLOSURES}", "declare disclosure")
    access_model = getattr(cls, "access_model", "") or modreg.DEFAULT_ACCESS_MODEL.get(disclosure or "", "")
    if access_model not in modreg.ACCESS_MODELS:
        bad(f"access_model {access_model!r} is not one of {modreg.ACCESS_MODELS}", "declare access_model (required for third_party)")
    if disclosure == "third_party" and not declared(cls, "access_model"):
        bad("access_model is not declared (disclosure 'third_party')", f"declare one of {modreg.ACCESS_MODELS}")

    # ---- disclosure rules --------------------------------------------------------------
    hosts = tuple(getattr(cls, "hosts", ()) or ())
    sources = tuple(getattr(cls, "sources", ()) or ())
    provider = str(getattr(cls, "provider", "") or "")
    contact = isinstance(opsec, Opsec) and opsec >= Opsec.LIGHT
    if contact != (disclosure == "target"):
        bad("opsec LIGHT/ACTIVE <=> disclosure 'target' is violated", "LIGHT/ACTIVE modules declare disclosure 'target' and vice versa")
    if disclosure == "none" and (hosts or provider):
        bad("disclosure 'none' with hosts/provider", "offline modules declare hosts = () and provider = ''")
    if disclosure in ("third_party", "internal"):
        if not provider or reg.get(provider) is None:
            bad(f"provider {provider!r} is not registered", "add a provider fragment under v3lum/data/providers/")
        if not sources:
            bad("no sources declared", "declare sources = ('provider.source', ...)")
        if disclosure == "internal":
            external = sorted(p for p in module_providers(cls) if reg.get(p) is not None and not reg.get(p).internal)
            if external:
                bad(f"provider(s) {external} of an internal module are not internal", "internal modules use internal provider fragments only (A12)")
        if provider and sources and provider not in source_providers(cls):
            bad(f"primary provider {provider!r} has none of the module's sources", f"list the {provider} sources the module queries")
        for host in hosts:
            if not host_ok(host, source_providers(cls), reg):
                bad(f"host {host!r} is not owned by a provider of its sources", "register the host in that provider's fragment (or an extension)")
    for sid in sources:
        if reg.source(sid) is None:
            bad(f"source {sid!r} is not registered", "add it to the provider fragment (or a provider-ext fragment)")

    # ---- terms == most restrictive source class (A1) -----------------------------------------
    classes = [reg.source(s).terms.class_ for s in sources if reg.source(s) is not None]
    if sources and classes:
        expected = providers.most_restrictive(classes)
        if terms != expected:
            bad(f"terms {terms!r} differs from the most restrictive source class {expected!r}", f"declare terms = {expected!r}")
    if not sources:
        if disclosure not in ("none", "target"):
            bad("a module without sources must be offline (none) or target-contact", "declare its registry sources")
        if terms != "open":
            bad(f"terms {terms!r} for a module without registry sources", "declare terms = 'open'")

    # ---- runtime limits ----------------------------------------------------------------
    max_rate = getattr(cls, "max_rate", None)
    if max_rate is not None and isinstance(opsec, Opsec):
        ceiling = modreg.CEILINGS["light_max_rps"] if opsec is Opsec.LIGHT else modreg.CEILINGS["active_max_rps"]
        if opsec is Opsec.PASSIVE or float(max_rate) > ceiling or float(max_rate) <= 0:
            bad(f"max_rate {max_rate!r} above the A7 ceiling", f"LIGHT <= {modreg.CEILINGS['light_max_rps']}, ACTIVE <= {modreg.CEILINGS['active_max_rps']} req/s")
    for code in getattr(cls, "requires_egress", ()) or ():
        if not COUNTRY_RE.match(str(code)):
            bad(f"requires_egress code {code!r}", "use ISO 3166 alpha-2 codes (e.g. 'BR')")
    for status in getattr(cls, "absent_statuses", ()) or ():
        if not isinstance(status, int) or not 100 <= status <= 599:
            bad(f"absent_statuses entry {status!r}", "use HTTP statuses 100-599")
        elif status in NEVER_ABSENT_STATUS or status >= 500:
            bad(f"absent_statuses entry {status} means 'could not verify', never an absence (rule 5)", "declare only documented meaningful absences such as 404/410")
    marker_ids: set[str] = set()
    for marker in getattr(cls, "error_markers", ()) or ():
        try:
            parsed = providers.parse_marker(marker)
        except ValueError as exc:
            bad(f"invalid error marker ({exc})", "follow the error-marker schema (contract section 7)")
            continue
        if parsed.id in marker_ids:
            bad(f"duplicate error marker id {parsed.id!r}", "give every marker a unique id")
        marker_ids.add(parsed.id)
    max_requests = getattr(cls, "max_requests", 10)
    if not isinstance(max_requests, int) or isinstance(max_requests, bool) or not 0 <= max_requests <= 100000:
        bad(f"max_requests {max_requests!r}", "use an int in 0..100000")
    for attr in ("expected_latency", "timeout", "min_interval"):
        value = getattr(cls, attr, 0)
        if isinstance(value, bool) or not isinstance(value, (int, float)) or value != value or value < 0:
            bad(f"{attr} {value!r} is not a non-negative number of seconds", f"declare {attr} in seconds")
    for attr, low in (("daily_quota", 1), ("cache_ttl", 0)):
        value = getattr(cls, attr, None)
        if value is not None and (isinstance(value, bool) or not isinstance(value, int) or value < low):
            bad(f"{attr} {value!r} is invalid", f"use None or an integer >= {low}")
    max_pivots = getattr(cls, "max_pivots", 100)
    if isinstance(max_pivots, bool) or not isinstance(max_pivots, int) or max_pivots < 0:
        bad(f"max_pivots {max_pivots!r} is invalid", "use a non-negative integer")
    manual = str(getattr(cls, "manual_link", "") or "")
    if manual:
        errs = links.validate_manual_link(manual)
        if errs:
            bad(f"manual_link {manual!r} does not resolve ({'; '.join(errs)})", "use '<pack>:<link_id>' of a shipped pack or a valid https template")

    # ---- A3 default rules ----------------------------------------------------------------
    tags = set(getattr(cls, "tags", ()) or ())
    provs = [reg.get(p) for p in module_providers(cls) if reg.get(p) is not None]
    reasons = []
    if contact:
        reasons.append("opsec LIGHT/ACTIVE")
    if terms == "unknown":
        reasons.append("terms unknown")
    if disclosure in ("third_party", "internal") and any(p.tier == "unknown" for p in provs):
        reasons.append("provider tier unknown")
    if isinstance(max_requests, int) and max_requests > 10 and "curated_pack" not in tags:
        reasons.append("max_requests > 10 without tag curated_pack")
    if float(getattr(cls, "expected_latency", 0) or 0) > 10:
        reasons.append("expected_latency > 10 s")
    if getattr(cls, "category", "") == "person_name" and disclosure == "third_party":
        reasons.append("person_name module sending values to a third party")
    reasons += [f"tag {t}" for t in sorted(tags & NOT_DEFAULT_TAGS)]
    if any(p.flags.fetches_target for p in provs) and "cached_only" not in tags:
        reasons.append("fetches_target provider without tag cached_only")
    if reasons and getattr(cls, "default_enabled", True):
        bad(f"default_enabled must be False ({', '.join(reasons)})", "declare default_enabled = False (A3)")

    # ---- sensitive => sanitizer schema per source (A4) ---------------------------------------
    sensitive = getattr(cls, "category", "") == "breach_leak" or any(p.flags.sensitive for p in provs)
    if sensitive:
        for sid in sources or ("<none>",):
            if sanitize.schema_for(sid) is None:
                bad(f"sensitive module without a sanitizer schema for {sid!r}", "sanitize.register_schema(source, keep=[...]) or a fragment sanitizer block")

    # ---- keys, packages, settings ----------------------------------------------------------
    keys = config.key_registry()
    for key in tuple(getattr(cls, "requires_keys", ()) or ()) + tuple(getattr(cls, "optional_keys", ()) or ()):
        if key not in keys:
            bad(f"key {key!r} is not registered", "declare it in the provider fragment 'keys' block")
    for pkg in getattr(cls, "requires_packages", ()) or ():
        if pkg not in modreg.OPTIONAL_PACKAGES:
            bad(f"package {pkg!r} is not a known optional package", "add a v3lum/data/extras/<package>.json fragment")
    inherited_from = registered_ancestors(cls)
    for setting in (getattr(cls, "settings", None) or {}):
        spec = config.SETTINGS_META.get(setting)
        if spec is not None and spec.owner != name and spec.owner in inherited_from:
            continue  # inherited, not re-declared, from a registered base module: it stays the base's (as @register does)
        if spec is None or spec.owner != name:
            owner = spec.owner if spec is not None else "nobody"
            bad(f"setting {setting!r} is registered by {owner}", "module settings need unique names (prefix them with the module name)")

    # ---- registration and derived attributes (set by @register, never declared) -------------------
    # A class that bypassed @register keeps the Module defaults of every derived name (e.g. trust tier
    # 'unknown', sensitive False): the policy gate and the sanitizer would then judge it wrongly.
    if SET_BY_REGISTER not in vars(cls):
        bad("the class was not registered through @register (no registration mark)", "decorate the class with @register")
    for attr, expected in expected_derived(cls, reg).items():
        actual = getattr(cls, attr, None)
        if actual != expected:
            bad(f"derived {attr} is {actual!r}, the provider registry gives {expected!r}", "register the class with @register (never set derived names)")

    # ---- health check ----------------------------------------------------------------------
    try:
        hc = cls.health_check()
    except Exception as exc:  # pragma: no cover - reported below
        bad(f"health_check() raised {type(exc).__name__}: {exc}", "fix health_check")
        hc = None
    if contact:
        if hc is None or not getattr(hc, "offline", False) or not callable(getattr(hc, "selftest", None)):
            bad("LIGHT/ACTIVE module without an offline self-test", "override health_check() -> HealthCheck(offline=True, selftest=callable)")
        if not SAFETY_GATE.exists():
            bad("LIGHT/ACTIVE module merged before the safety suite exists", "wait for tests/safety/test_scope.py (AR20, A7 merge gate)")
    elif disclosure != "none" and hc is not None and getattr(hc, "etype", None) is not None:
        out.extend(f"{name}: {p}" for p in health_check_problems(hc, accepts))

    # ---- per-module test file + fixtures (A16 merge gate) -------------------------------------
    out.extend(f"{name}: {p}" for p in per_module_test_problems(cls))
    return out


def health_check_problems(hc: Any, accepts: Any) -> list[str]:
    """A probe health check sends one benign value from the central list (P332 cond 9): doctor and
    the keys wizard run it against the real provider, so it must never carry a real person's data."""
    etype, value = hc.etype, getattr(hc, "value", "")
    if etype not in accepts:
        return [f"health_check entity type {etype!r} is not accepted - use a benign value of an accepted type"]
    if getattr(hc, "entity", None) is None:
        return [f"health_check value {value!r} is not a valid {getattr(etype, 'value', etype)} - use the benign value of module.BENIGN_VALUES"]
    benign = modreg.BENIGN_VALUES.get(etype)
    if benign is not None and value != benign:
        return [f"health_check value {value!r} is not the central benign value {benign!r} - probe with module.BENIGN_VALUES[{etype}]"]
    if benign is None and etype in PERSONAL_TYPES:
        return [f"health_check probes a personal type ({etype.value}) without a central benign value - add one to module.BENIGN_VALUES (WP02) first"]
    return []


def per_module_test_problems(cls: type) -> list[str]:
    name = str(getattr(cls, "name", "") or "")
    if getattr(cls, "spec_origin", ""):
        spec_dir = FIXTURES / "specs" / name
        missing = [p for p in ("ok.*", "error_in_200.*", "expected.json") if not list(spec_dir.glob(p))]
        return [f"compiled spec without tests/fixtures/specs/{name}/{p}" for p in missing]
    test_file = TESTS / "modules" / f"test_{name}.py"
    if not test_file.exists():
        return [f"missing tests/modules/test_{name}.py - add offline tests with tests/fakes.py"]
    source = test_file.read_text(encoding="utf-8")
    problems = []
    if "tests.fakes" not in source:
        problems.append(f"tests/modules/test_{name}.py does not use the offline kit tests/fakes.py (FakeHttp, make_ctx, run_module)")
    if getattr(cls, "disclosure", None) == "none":
        return problems  # offline modules may use inline data
    fixture_dir = FIXTURES / name
    if not fixture_dir.is_dir() or not any(p.is_file() for p in fixture_dir.rglob("*")):
        problems.append(f"missing trimmed real fixtures in tests/fixtures/{name}/")
    refs = (f"fixtures/{name}", f'"{name}/', f"'{name}/", f"module_fixture({cls.__name__}", f'module_fixture("{name}"', f"module_fixture('{name}'")
    if not any(ref in source for ref in refs):
        problems.append(f"tests/modules/test_{name}.py does not use tests/fixtures/{name}/ (module_fixture)")
    return problems


# --------------------------------------------------------------------------------------
# registry-wide checks
# --------------------------------------------------------------------------------------


def test_reference_modules_are_registered():
    assert set(REFERENCE_MODULES) <= set(MODULE_NAMES)


def test_no_module_load_errors():
    assert modreg.load_errors() == {}


def test_provider_registry_has_no_errors():
    assert providers.registry().errors == []


def test_vocabulary_has_no_errors():
    assert vocab.errors() == []
    for kind, name, fname in vocab.redeclarations():
        merged = {"attribute": vocab.attributes, "tag": vocab.tags, "relation": vocab.relations}[kind]()
        try:
            doc = json.loads((Path(vocab.FRAGMENT_DIR) / fname).read_text(encoding="utf-8"))
        except (OSError, ValueError):
            continue
        desc = (doc.get(kind + "s") or {}).get(name, "")
        if desc.strip() and desc.strip() != merged.get(name, "").strip():
            warnings.warn(f"vocab {kind} {name!r} re-declared in {fname} with a different description (first wins)", stacklevel=1)


def test_pivot_links_have_no_errors():
    assert links.errors() == []


def test_platform_fragments_and_extras_have_no_errors():
    """v3lum/data/platforms (SOCIAL_PLATFORMS) and v3lum/data/extras (OPTIONAL_PACKAGES) fragments."""
    from v3lum.core import entities

    assert entities.platform_errors() == []
    assert modreg.extras_errors() == []


def test_correlation_rules_have_no_errors():
    correlate.load_rules()
    assert correlate.RULE_ERRORS == {}


def test_noise_and_attack_have_no_errors():
    from v3lum.core import attack, noise

    assert noise.errors() == []
    assert attack.errors() == []


def test_every_module_class_is_registered():
    """A class defined in a module file but never registered (missing @register) is caught."""
    import v3lum.modules as pkg

    registered = set(modreg.REGISTRY.values())
    stray = []
    for info in pkgutil.walk_packages(pkg.__path__, prefix=pkg.__name__ + "."):
        mod = importlib.import_module(info.name)
        for _, obj in inspect.getmembers(mod, inspect.isclass):
            if obj.__module__ != mod.__name__ or not issubclass(obj, modreg.Module) or obj is modreg.Module:
                continue
            if "name" in vars(obj) and obj not in registered:
                stray.append(f"{obj.__module__}.{obj.__qualname__}")
    assert not stray, f"module classes defined without @register: {stray}"


def test_registry_entries_are_the_registered_classes():
    for name, cls in modreg.REGISTRY.items():
        assert cls.name == name, f"REGISTRY[{name!r}] holds {cls.__name__} named {cls.name!r}"


@pytest.mark.parametrize("name", MODULE_NAMES)
def test_module_contract(name):
    problems = module_problems(modreg.REGISTRY[name])
    assert not problems, "\n".join(problems)


def test_module_settings_are_unique():
    owners: dict[str, str] = {}
    for name in MODULE_NAMES:
        cls = modreg.REGISTRY[name]
        inherited_from = registered_ancestors(cls)
        for setting in getattr(cls, "settings", None) or {}:
            assert setting not in config.DEFAULT_SETTINGS, f"{name}: setting {setting!r} collides with a core setting"
            spec = config.SETTINGS_META.get(setting)
            if spec is not None and spec.owner in inherited_from:
                continue  # inherited from a registered base module: counted for its owner
            assert setting not in owners, f"setting {setting!r} declared by {owners[setting]} and {name}"
            owners[setting] = name


def test_non_legacy_rules_ship_fixtures():
    correlate.load_rules()
    missing = []
    for rule_id, info in correlate.RULES.items():
        if getattr(info, "legacy", False):
            continue
        folder = FIXTURES / "rules" / rule_id
        if not list(folder.glob("positive_*.json")) or not list(folder.glob("negative_*.json")):
            missing.append(rule_id)
    assert not missing, f"rules without tests/fixtures/rules/<rule_id>/positive_*.json and negative_*.json: {missing}"


def test_dataset_sources_and_licences_are_registered():
    """Every registered dataset names a registry source, a licence and the source's terms class."""
    assert datasets.dataset_errors() == []


NOTICE_FIELDS = {"schema": str, "name": str, "source_url": str, "version": str, "sha256": str, "licence": str, "attribution": str, "bundled": bool, "files": list}


def notice_problems(path: Path) -> list[str]:
    try:
        doc = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError) as exc:
        return [f"{path.name}: unreadable ({exc})"]
    if not isinstance(doc, dict):
        return [f"{path.name}: top level must be an object"]
    out = [f"{path.name}: field {k!r} must be {t.__name__}" for k, t in NOTICE_FIELDS.items() if not isinstance(doc.get(k), t)]
    if doc.get("schema") != "v3lum.notice/1":
        out.append(f"{path.name}: schema must be 'v3lum.notice/1'")
    if doc.get("name") != path.stem or not NOTICE_NAME_RE.match(path.stem):
        out.append(f"{path.name}: name must equal the file stem and match {NOTICE_NAME_RE.pattern}")
    if not str(doc.get("source_url", "")).startswith("https://"):
        out.append(f"{path.name}: source_url must be https")
    if not str(doc.get("licence", "")).strip():
        out.append(f"{path.name}: licence is required")
    if not str(doc.get("attribution", "")).strip():
        out.append(f"{path.name}: attribution is required (the text the licence asks for)")
    sha = doc.get("sha256")
    if isinstance(sha, str) and sha and not SHA256_RE.match(sha):
        out.append(f"{path.name}: sha256 must be '' or 64 lower-case hex digits")
    if re.search(r"\b(A|L)?GPL|BY-SA|\bNC\b|NonCommercial", str(doc.get("licence", ""))) and doc.get("bundled"):
        out.append(f"{path.name}: GPL-family, share-alike and non-commercial material is never bundled (A6)")
    files = doc.get("files") if isinstance(doc.get("files"), list) else []
    for item in files:
        if not isinstance(item, str) or item.startswith("/") or ".." in Path(item).parts:
            out.append(f"{path.name}: files entry {item!r} must be a repository-relative path")
        elif not (ROOT / item).exists():
            out.append(f"{path.name}: files entry {item!r} does not exist (stale notice)")
    return out


def test_notice_fragments_parse():
    problems = [p for path in sorted(NOTICES.glob("*.json")) for p in notice_problems(path)]
    assert not problems, "\n".join(problems)


# --------------------------------------------------------------------------------------
# the checker itself (a bypassed registration is still caught)
# --------------------------------------------------------------------------------------


def _bare(**body: Any) -> type:
    base = {"name": "t_contract_probe", "title": "probe", "description": "probe", "category": "utility", "accepts": frozenset({EntityType.DOMAIN})}
    base.update(body)
    return type("Probe", (modreg.Module,), base)


def test_checker_catches_missing_declarations_and_bad_hosts():
    cls = _bare()
    problems = "\n".join(module_problems(cls))
    for attr in ("terms", "opsec", "disclosure", "hosts"):
        assert f"{attr} is not declared" in problems
    cls2 = _bare(terms="open", opsec=Opsec.PASSIVE, disclosure="third_party", hosts=("evil.example",), provider="shodan", sources=("shodan.internetdb",), max_requests=1, expected_latency=1.0)
    problems2 = "\n".join(module_problems(cls2))
    assert "host 'evil.example' is not owned" in problems2
    assert "most restrictive source class 'noncommercial'" in problems2


def test_checker_catches_a3_default_and_light_gate():
    cls = _bare(terms="open", opsec=Opsec.LIGHT, disclosure="target", hosts=(), max_requests=5, expected_latency=1.0, default_enabled=True)
    problems = "\n".join(module_problems(cls))
    assert "default_enabled must be False (opsec LIGHT/ACTIVE" in problems
    assert "offline self-test" in problems
    if not SAFETY_GATE.exists():
        assert "safety suite" in problems


def test_checker_requires_test_file_and_fixtures():
    cls = _bare(name="t_no_tests_module", terms="open", opsec=Opsec.PASSIVE, disclosure="none", hosts=())
    assert any("missing tests/modules/test_t_no_tests_module.py" in p for p in module_problems(cls))


def test_checker_catches_a_bypassed_registration_of_a_well_formed_module():
    """A third-party module put into the REGISTRY without @register keeps the Module defaults of the
    derived names (tier 'unknown', no TLP ceiling...): the checker flags it although every
    declaration is right."""
    from v3lum.modules.ip_network.shodan_internetdb import ShodanInternetDB

    body = {k: v for k, v in vars(ShodanInternetDB).items() if k not in modreg.DERIVED and k != SET_BY_REGISTER and not k.startswith("__")}
    body["error_markers"] = ()
    clone = type("BypassedClone", (modreg.Module,), body)
    problems = "\n".join(module_problems(clone))
    assert "not registered through @register" in problems
    assert "derived trust_tier is 'unknown', the provider registry gives 'trusted'" in problems
    assert "derived max_tlp" in problems
    assert not [p for p in module_problems(ShodanInternetDB) if "derived" in p or "registration mark" in p]


def test_checker_catches_provider_and_health_check_mistakes():
    cls = _bare(
        terms="noncommercial", opsec=Opsec.PASSIVE, disclosure="third_party", hosts=("internetdb.shodan.io",), provider="core_doh",
        sources=("shodan.internetdb",), access_model="free_noauth_limited", max_requests=1, expected_latency=1.0,
        accepts=frozenset({EntityType.IPV4}),
    )
    problems = "\n".join(module_problems(cls))
    assert "primary provider 'core_doh' has none of the module's sources" in problems
    hc = modreg.HealthCheck(etype=EntityType.IPV4, value="203.0.113.7")
    assert "not the central benign value '8.8.8.8'" in "\n".join(health_check_problems(hc, {EntityType.IPV4}))
    assert health_check_problems(modreg.HealthCheck(etype=EntityType.IPV4, value="8.8.8.8"), {EntityType.IPV4}) == []
    phone = modreg.HealthCheck(etype=EntityType.PHONE, value="+5511912345678")
    assert "personal type" in "\n".join(health_check_problems(phone, {EntityType.PHONE}))
    bogus = modreg.HealthCheck(etype=EntityType.IPV4, value="not-an-ip")
    assert "not a valid ipv4" in "\n".join(health_check_problems(bogus, {EntityType.IPV4}))


def test_checker_accepts_settings_inherited_from_a_registered_base(clean_registry):
    """A subclass of a registered module inherits its settings without owning them (same rule as
    @register); re-declaring them in the subclass body is still a collision."""

    def run(self, entity, ctx):
        return self.result(entity)

    body = {"title": "t", "description": "t", "category": "utility", "accepts": {EntityType.DOMAIN}, "terms": "open",
            "opsec": Opsec.PASSIVE, "disclosure": "none", "hosts": (), "run": run}
    base = modreg.register(type("Base", (modreg.Module,), dict(body, name="t_contract_base", settings={"t_contract_base_limit": 3})))
    sub = modreg.register(type("Sub", (base,), {"name": "t_contract_sub", "title": "sub", "description": "sub"}))
    modreg.register(sub)  # registering again keeps the base's ownership
    assert registered_ancestors(sub) == {"t_contract_base"}
    assert not [p for p in module_problems(sub) if "setting" in p]
    clash = type("Clash", (base,), {"name": "t_contract_clash", "title": "c", "description": "c", "settings": {"t_contract_base_limit": 5}})
    assert any("setting 't_contract_base_limit' is registered by t_contract_base" in p for p in module_problems(clash))


def test_notice_checker(tmp_path):
    good = {"schema": "v3lum.notice/1", "name": "t_notice", "source_url": "https://example.org/", "version": "1", "sha256": "",
            "licence": "MIT", "attribution": "MIT, (c) example", "bundled": True, "files": ["v3lum/core/http.py"]}
    path = tmp_path / "t_notice.json"
    path.write_text(json.dumps(good))
    assert notice_problems(path) == []
    path.write_text(json.dumps(dict(good, licence="CC-BY-SA-4.0", sha256="xyz", files=["../etc/passwd", "v3lum/core/nope.py"])))
    problems = "\n".join(notice_problems(path))
    assert "never bundled" in problems and "sha256" in problems and "repository-relative" in problems and "stale notice" in problems
