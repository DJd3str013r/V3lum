"""Engine outcome mapping (WP01, module_author_contract section 3) and the thin v2 integration.

One test per exception -> (status, reason_code, partial, stop_reason); partial-result recovery
through collect_results; fail-closed sanitizer; selection through the policy gate (Engine.select
returns (cls, policy.Decision) pairs since wave 2: not_default, POL-02, TLP:RED, rule 7, daily
quota); the disclosure ledger; RunInfo/RuleContext plumbing; timeline fragments.
Synthetic module classes are local stubs (not registered unless a test inserts them).
"""

from __future__ import annotations

import json
from pathlib import Path
from types import SimpleNamespace

import pytest

from tests.fakes import DOH_HOSTS, FakeHttp
from v3lum.config import Config
from v3lum.core import correlate, datasets, engine as engine_mod, http, sanitize, vocab
from v3lum.core import module as modreg
from v3lum.core.context import Runtime, ScanOptions
from v3lum.core.engine import Engine, build_timeline
from v3lum.core.entities import Entity
from v3lum.core.entities import EntityType as T
from v3lum.core.graph import Graph
from v3lum.core.models import ContractViolation, Finding, ModuleResult, Opsec, Status, finding_id
from v3lum.core.module import Module

DOMAIN = Entity.make("domain", "example.org")


def make_engine(options: ScanOptions | None = None) -> Engine:
    rt = Runtime(Config(), http_client=FakeHttp())
    return Engine(rt, options or ScanOptions())


def stub(run, name: str = "t_status_mod", **attrs):
    body = {
        "name": name, "title": name, "description": "synthetic", "category": "utility", "accepts": frozenset({T.DOMAIN}),
        "produces": frozenset(), "terms": "open", "disclosure": "none", "hosts": (), "opsec": Opsec.PASSIVE, "run": run,
    }
    body.update(attrs)
    return type(name, (Module,), body)


def raising(exc: BaseException, *, with_data: bool = False):
    def run(self, entity, ctx):
        res = self.result(entity)
        if with_data:
            res.attr("country", "BR")
        raise exc

    return run


class _StubDatasetUnavailable(Exception):
    reason_code = "dataset"


@pytest.fixture()
def dataset_unavailable(monkeypatch):
    cls = getattr(datasets, "DatasetUnavailable", None)
    if cls is None:  # WP04 not landed yet: a local stand-in with the contract name
        monkeypatch.setattr(datasets, "DatasetUnavailable", _StubDatasetUnavailable, raising=False)
        cls = _StubDatasetUnavailable
    return cls


def _dataset_exc(cls):
    try:
        return cls("big_list", reason_code="dataset", message="run v3lum data update big_list")
    except TypeError:
        return cls("run v3lum data update big_list")


# ------------------------------------------------------------------ one test per exception
CASES = [
    ("quota_no_data", lambda: http.QuotaExceeded("daily quota used"), False, {}, (Status.QUOTA, "quota", False, "")),
    ("quota_with_data", lambda: http.QuotaExceeded("daily quota used"), True, {}, (Status.OK, "", True, "quota")),
    ("rate_limited_no_data", lambda: http.RateLimited("slow down", 429), False, {}, (Status.RATE_LIMITED, "rate_limited", False, "")),
    ("rate_limited_with_data", lambda: http.RateLimited("slow down", 429), True, {}, (Status.OK, "", True, "rate_limited")),
    ("request_cap_with_data", lambda: http.RequestCapReached(), True, {}, (Status.OK, "", True, "request_cap")),
    ("request_cap_no_data", lambda: http.RequestCapReached(), False, {}, (Status.EMPTY, "", True, "request_cap")),
    ("cancelled", lambda: http.Cancelled(), True, {}, (Status.OK, "", True, "cancelled")),
    ("blocked_default", lambda: http.Blocked("anti-bot page", 403), False, {}, (Status.BLOCKED, "challenge", False, "")),
    ("blocked_geo", lambda: http.Blocked("geo", 451, reason_code="geo_block"), False, {}, (Status.BLOCKED, "geo_block", False, "")),
    ("blocked_login_wall", lambda: http.Blocked("login", 200, reason_code="login_wall"), False, {}, (Status.BLOCKED, "login_wall", False, "")),
    ("auth_keyed", lambda: http.AuthRequired("HTTP 401", 401), False, {"requires_keys": ("t_key",)}, (Status.NEEDS_KEY, "needs_key", False, "")),
    ("auth_optional_key", lambda: http.AuthRequired("HTTP 403", 403), False, {"optional_keys": ("t_key",)}, (Status.NEEDS_KEY, "needs_key", False, "")),
    ("auth_keyless", lambda: http.AuthRequired("HTTP 403", 403), False, {}, (Status.BLOCKED, "challenge", False, "")),
    ("policy_scope", lambda: http.PolicyError("outside scope", reason_code="scope"), False, {}, (Status.SKIPPED, "scope", False, "")),
    ("policy_default", lambda: http.PolicyError("host not declared"), False, {}, (Status.SKIPPED, "policy", False, "")),
    ("config", lambda: http.ConfigError("contact_email is empty"), False, {}, (Status.SKIPPED, "config", False, "")),
    ("deadline", lambda: http.DeadlineExceeded(), True, {}, (Status.ERROR, "timeout", False, "")),
    ("offline", lambda: http.OfflineError("offline mode: not cached"), False, {}, (Status.UNAVAILABLE, "offline", False, "")),
    ("network", lambda: http.NetworkError("ConnectionError contacting x"), False, {}, (Status.ERROR, "error", False, "")),
    ("http_error", lambda: http.HttpError("HTTP 500 from x", 500), False, {}, (Status.ERROR, "error", False, "")),
    ("module_bug", lambda: RuntimeError("module bug"), True, {}, (Status.ERROR, "error", False, "")),
]


@pytest.mark.parametrize(("case", "make_exc", "with_data", "attrs", "expected"), CASES, ids=[c[0] for c in CASES])
def test_exception_mapping(case, make_exc, with_data, attrs, expected):
    cls = stub(raising(make_exc(), with_data=with_data), **attrs)
    res = make_engine().run_module(cls, DOMAIN)
    assert (res.status, res.reason_code, res.partial, res.stop_reason) == expected
    assert res.module == cls.name and res.entity == DOMAIN
    if expected[2]:  # partial runs keep what the module collected
        assert (res.attributes == {"country": "BR"}) is with_data
    elif expected[0] is not Status.OK:
        assert res.error  # the human text stays in the error field
    if case == "module_bug":
        assert "module bug" in res.error and "traceback" in res.raw and res.attributes == {}


def test_context_refusal_maps_to_a_status_and_never_raises(monkeypatch):
    eng = make_engine()

    def refuse(*args, **kw):
        raise http.PolicyError("no public resolver at TLP:RED", reason_code="tlp")

    monkeypatch.setattr(eng.runtime, "context", refuse)
    res = eng.run_module(stub(lambda self, e, c: self.result(e)), DOMAIN)
    assert (res.status, res.reason_code, res.module, res.entity) == (Status.SKIPPED, "tlp", "t_status_mod", DOMAIN)


def test_partial_recovery_never_uses_another_entitys_result():
    def run(self, entity, ctx):
        helper = ModuleResult(module=self.name, entity=Entity.make("domain", "other.example"))
        helper.attr("country", "US")  # a fact about another entity
        raise http.RequestCapReached()

    res = make_engine().run_module(stub(run), DOMAIN)
    assert (res.status, res.partial, res.stop_reason) == (Status.EMPTY, True, "request_cap")
    assert res.entity == DOMAIN and res.attributes == {}


@pytest.mark.parametrize("exc", [http.Cancelled(), http.RequestCapReached(), http.QuotaExceeded("daily quota used")], ids=["cancelled", "cap", "quota"])
def test_a_stop_after_a_block_keeps_could_not_verify(exc):
    def run(self, entity, ctx):
        res = self.result(entity)
        res.attr("country", "BR")
        res.mark("blocked", "challenge page on the first request")
        raise exc

    res = make_engine().run_module(stub(run), DOMAIN)
    assert (res.status, res.reason_code, res.partial) == (Status.BLOCKED, "challenge", True)  # never ok/empty (rule 5)
    assert res.stop_reason in ("cancelled", "request_cap", "quota") and "challenge page" in res.error


def test_directly_appended_duplicate_findings_get_unique_ids():
    def run(self, entity, ctx):
        res = self.result(entity)
        res.findings.append(Finding("Same", entity=entity))
        res.findings.append(Finding("Same", entity=entity))
        res.findings.append(Finding("Stored", id="0123456789ab"))
        return res

    res = make_engine().run_module(stub(run), DOMAIN)
    assert [f.id for f in res.findings] == [
        finding_id("t_status_mod", DOMAIN.key, "Same"),
        finding_id("t_status_mod", DOMAIN.key, "Same", "#2"),
        "0123456789ab",  # explicit (stored) ids are kept
    ]
    assert res.findings[2].entity == DOMAIN


def test_res_hosts_lists_the_doh_resolvers_of_a_real_run():
    from tests.fakes import add_dns
    from tests.fakes import run_module as engine_run

    fake = FakeHttp()
    add_dns(fake, "example.org", "A", ["192.0.2.10"])

    def run(self, entity, ctx):
        res = self.result(entity)
        res.attr("a_records", list(ctx.dns.query(entity.value, "A").records))
        return res

    cls = stub(run, name="t_doh_mod", disclosure="third_party", provider="core_doh", sources=("core_doh.resolvers",), max_requests=1, expected_latency=1.0)
    res = engine_run(cls, DOMAIN, fake)
    assert res.status is Status.OK and res.attributes["a_records"] == ["192.0.2.10"]
    assert res.hosts.get("dns.google", 0) >= 1 and set(res.hosts) <= DOH_HOSTS  # the ledger names the resolver
    assert res.requests == 0  # DoH is not counted against max_requests


def test_dataset_unavailable(dataset_unavailable):
    cls = stub(raising(_dataset_exc(dataset_unavailable)))
    res = make_engine().run_module(cls, DOMAIN)
    assert (res.status, res.reason_code, res.partial) == (Status.UNAVAILABLE, "dataset", False)


def test_cancel_reason_becomes_stop_reason():
    eng = make_engine()
    eng.runtime.cancel_reason = "deadline"
    res = eng.run_module(stub(raising(http.Cancelled(), with_data=True)), DOMAIN)
    assert (res.status, res.partial, res.stop_reason) == (Status.OK, True, "deadline")
    eng.runtime.cancel_reason = "operator pressed ctrl+c"  # not a stop reason: generic 'cancelled'
    res = eng.run_module(stub(raising(http.Cancelled())), DOMAIN)
    assert (res.status, res.partial, res.stop_reason) == (Status.EMPTY, True, "cancelled")


def test_applies_false_and_empty_and_direct_status():
    res = make_engine().run_module(stub(lambda self, e, c: self.result(e), applies=lambda self, e, c: False), DOMAIN)
    assert (res.status, res.reason_code) == (Status.SKIPPED, "not_applicable")
    res = make_engine().run_module(stub(lambda self, e, c: self.result(e)), DOMAIN)
    assert (res.status, res.reason_code) == (Status.EMPTY, "")

    def direct(self, entity, ctx):
        res = self.result(entity)
        res.status = Status.RATE_LIMITED  # v1 style: no reason code
        return res

    res = make_engine().run_module(stub(direct), DOMAIN)
    assert (res.status, res.reason_code) == (Status.RATE_LIMITED, "rate_limited")
    res = make_engine().run_module(stub(lambda self, e, c: self.result(e).mark("blocked", "challenge page")), DOMAIN)
    assert (res.status, res.reason_code, res.error) == (Status.BLOCKED, "challenge", "challenge page")


def test_errors_are_redacted():
    redact = pytest.importorskip("v3lum.core.redact")
    secret = "SuperSecretKey0123456789"
    redact.register_secret(secret)
    res = make_engine().run_module(stub(raising(RuntimeError(f"failed calling https://api.example.test/?key={secret}"))), DOMAIN)
    assert secret not in res.error and secret not in json.dumps(res.raw)


# ------------------------------------------------------------------ sanitizer stage
def test_sanitizer_failure_fails_closed(monkeypatch):
    def run(self, entity, ctx):
        res = self.result(entity)
        res.raw = {"anything": 1}
        res.attr("country", "BR")
        res.finding("F", "info")
        return res

    def boom(res, cls):
        raise sanitize.SanitizerError("bug")

    monkeypatch.setattr(sanitize, "sanitize_result", boom)
    res = make_engine().run_module(stub(run), DOMAIN)
    assert (res.status, res.reason_code) == (Status.ERROR, "sanitizer")
    assert res.raw is None and res.findings == [] and res.attributes == {} and res.pivots == []


def test_sanitizer_runs_on_every_result():
    def run(self, entity, ctx):
        res = self.result(entity)
        res.raw = {"line": "alice@corp.example:hunter2", "password": "hunter2"}
        return res.mark("ok")

    res = make_engine().run_module(stub(run, category="breach_leak", sources=("nobody.nothing",)), DOMAIN)
    assert res.raw is None and "raw" in res.redacted_fields  # sensitive without a schema: raw dropped
    res = make_engine().run_module(stub(run), DOMAIN)
    # WP09: password-labelled values are dropped in every module (P145 cond 5/8), combos keep the e-mail
    assert res.raw == {"line": "alice@corp.example"} and {"raw:combo", "raw.password"} <= set(res.redacted_fields)


# ------------------------------------------------------------------ ids, ledger, datasets, strict mode
def test_finding_ids_follow_the_engine_module_name():
    def run(self, entity, ctx):
        res = ModuleResult(module="some_other_name", entity=entity)
        res.finding("Title", "info")
        return res

    res = make_engine().run_module(stub(run, name="t_real_name"), DOMAIN)
    assert res.module == "t_real_name"
    assert res.findings[0].module == "t_real_name"
    assert res.findings[0].id == finding_id("t_real_name", DOMAIN.key, "Title")


def test_hosts_include_doh_scope_and_dataset_citations(monkeypatch):
    eng = make_engine()
    citation = {"name": "t_ds", "sha256": "0" * 64, "fetched_at": "2026-11-26T00:00:00Z", "licence": "CC0"}
    fake_ctx = SimpleNamespace(
        http=SimpleNamespace(requests=2, cache_hits=1, hosts={"api.example.test": 2}),
        doh=SimpleNamespace(hosts={"dns.google": 3, "api.example.test": 1}),
        data=SimpleNamespace(used=[citation]),
    )
    monkeypatch.setattr(eng.runtime, "context", lambda *a, **k: fake_ctx)

    def run(self, entity, ctx):
        res = self.result(entity)
        res.attr("country", "BR")
        return res

    res = eng.run_module(stub(run), DOMAIN)
    assert res.hosts == {"api.example.test": 3, "dns.google": 3}
    assert res.datasets == [citation] and (res.requests, res.cache_hits) == (2, 1)


def test_strict_contract_violation_surfaces(monkeypatch):
    monkeypatch.setenv("V3LUM_STRICT", "1")
    cls = stub(lambda self, e, c: self.result(e).finding("Bad", "high") and None)
    with pytest.raises(ContractViolation):
        make_engine().run_module(cls, DOMAIN)
    monkeypatch.setenv("V3LUM_STRICT", "0")

    def run(self, entity, ctx):
        res = self.result(entity)
        res.finding("Bad", "high")
        return res

    res = make_engine().run_module(stub(run), DOMAIN)
    assert res.status is Status.OK and res.findings[0].criterion == "unspecified"


def test_run_info_is_passed_to_the_context(monkeypatch):
    run_info_cls = pytest.importorskip("v3lum.core.context").RunInfo
    eng = make_engine()
    seen = []
    real = eng.runtime.context

    def spy(*args, **kw):
        seen.append(kw.get("run"))
        return real(*args, **kw)

    monkeypatch.setattr(eng.runtime, "context", spy)
    run = run_info_cls(entity=DOMAIN, is_seed=False, depth=1)
    eng.run_module(stub(lambda self, e, c: self.result(e)), DOMAIN, run=run)
    assert seen == [run]


def test_single_runs_without_run_info_still_know_their_entity():
    """`v3lum run` (App.run_single) calls run_module without RunInfo: the run is an analyst-typed
    seed and ctx.entity / ctx.state's guard on the investigated value still see the entity."""
    seen = []

    def run(self, entity, ctx):
        seen.append((ctx.entity, ctx.is_seed, ctx.depth, ctx.provenance))
        return self.result(entity)

    res = make_engine().run_module(stub(run), DOMAIN)
    assert res.status is Status.EMPTY and seen == [(DOMAIN, True, 0, ())]


def test_each_investigation_starts_with_a_fresh_http_circuit(registry):
    """A host short-circuited after a challenge in one scan gets a new chance in the next scan of the
    same Runtime (shell sessions): Engine.investigate calls HttpClient.reset_circuit()."""
    mod = registry(stub(lambda self, e, c: self.result(e), name="t_circuit_mod"))
    rt = Runtime(Config(), transport=FakeHttp(), no_cache=True)
    rt.http._trip(["blocked.example.test"], "challenge")
    assert rt.http.circuit_hosts() == frozenset({"blocked.example.test"})
    Engine(rt, ScanOptions(include={mod.name}, save_evidence=False)).investigate([DOMAIN])
    assert rt.http.circuit_hosts() == frozenset()


# ------------------------------------------------------------------ selection
@pytest.fixture()
def registry(monkeypatch):
    modreg.load_modules()

    def add(cls):
        monkeypatch.setitem(modreg.REGISTRY, cls.name, cls)
        return cls

    return add


def blocked_for(eng: Engine, name: str):
    runnable, blocked = eng.select(DOMAIN)
    assert all(len(b) == 2 for b in blocked)  # (module class, policy.Decision)
    return [c.name for c, _d in runnable], {c.name: (d.status, d.reason, d.reason_code) for c, d in blocked}.get(name)


def test_selection_goes_through_the_policy_gate(registry):
    """WP08 replaced the interim A16 source opt-in by policy.decide: opt-in modules (default_enabled
    False) are SKIPPED 'not_default' unless -M or --preset deep / --all-modules selects them, and a
    network module placed in the registry without @register never runs (POL-02)."""
    optin = registry(stub(lambda self, e, c: self.result(e), name="t_optin_mod", default_enabled=False))
    offline = registry(stub(lambda self, e, c: self.result(e), name="t_offline_mod"))
    runnable, block = blocked_for(make_engine(), optin.name)
    assert optin.name not in runnable and offline.name in runnable
    assert (block[0], block[2]) == (Status.SKIPPED, "not_default")
    runnable, block = blocked_for(make_engine(ScanOptions(include={optin.name})), optin.name)
    assert optin.name in runnable and block is None
    runnable, block = blocked_for(make_engine(ScanOptions(include_disabled=True)), optin.name)
    assert optin.name in runnable
    for disclosure in ("third_party", "internal", "target"):
        cls = registry(stub(lambda self, e, c: self.result(e), name=f"t_{disclosure}_mod", disclosure=disclosure))
        assert blocked_for(make_engine(ScanOptions(include={cls.name})), cls.name)[1][2] == "policy"


def _third_party(name: str, prov, **attrs):
    from tests.fakes import define_module, source_ids

    return define_module(
        name, [T.DOMAIN], lambda self, e, c: self.result(e), disclosure="third_party", provider=prov.id, sources=source_ids(prov),
        hosts=prov.hosts, access_model="free_noauth_unlimited", **attrs,
    )


def test_tlp_red_skips_modules_that_share_the_input(clean_registry, registry):
    from tests.fakes import test_provider

    with test_provider("t_red_prov") as prov:
        src = _third_party("t_red_src", prov)
        offline = registry(stub(lambda self, e, c: self.result(e), name="t_red_offline"))
        opts = ScanOptions(include={src.name, offline.name}, tlp="red")
        runnable, block = blocked_for(make_engine(opts), src.name)
        assert block[0] is Status.SKIPPED and block[2] == "tlp"
        assert offline.name in runnable


def test_providers_that_publish_lookups_never_run(clean_registry, registry):
    from tests.fakes import test_provider

    with test_provider("t_pub_prov", publishes_queries=True) as prov:
        pub = _third_party("t_pub_mod", prov, default_enabled=False)
        for opts in (ScanOptions(include={pub.name}, tlp="clear"), ScanOptions(include_disabled=True, tlp="clear")):
            runnable, block = blocked_for(make_engine(opts), pub.name)
            assert pub.name not in runnable and (block[0], block[2]) == (Status.SKIPPED, "policy") and "publishes" in block[1]
    calls = []
    direct = stub(lambda self, e, c: calls.append(e) or self.result(e), name="t_pub_direct", disclosure="third_party", publishes_queries=True)
    res = make_engine().run_module(direct, DOMAIN)  # the `v3lum run` path does not go through select()
    assert (res.status, res.reason_code, calls) == (Status.SKIPPED, "policy", [])


def test_a_red_seed_keeps_third_party_modules_away(clean_registry):
    from tests.fakes import test_provider

    with test_provider("t_red_seed_prov") as prov:
        src = _third_party("t_red_seed_src", prov)
        opts = ScanOptions(include={src.name}, tlp="amber", seed_tlp={DOMAIN.key: "TLP:RED"})
        runnable, block = blocked_for(make_engine(opts), src.name)
        assert src.name not in runnable and block[0] is Status.SKIPPED and block[2] == "tlp"
        opts = ScanOptions(include={src.name}, tlp="amber", seed_tlp={DOMAIN.key: "not-a-tlp"})
        assert blocked_for(make_engine(opts), src.name)[1][2] == "tlp"  # unreadable marking: fail closed


def test_runtime_is_in_scan_while_investigating(registry):
    """AR10: datasets.DataStore refuses large downloads while Runtime.in_scan is set."""
    seen = []

    def run(self, entity, ctx):
        seen.append(ctx.runtime.in_scan)
        return self.result(entity)

    mod = registry(stub(run, name="t_in_scan_mod"))
    eng = make_engine(ScanOptions(include={mod.name}, save_evidence=False))
    eng.runtime.cancel_reason = "deadline"  # left over from an earlier scan
    eng.investigate([DOMAIN])
    assert seen == [True] and eng.runtime.in_scan is False and eng.runtime.cancel_reason == ""


def test_global_timeout_trips_the_kill_switch(registry):
    mod = registry(stub(lambda self, e, c: self.result(e), name="t_deadline_mod"))
    eng = make_engine(ScanOptions(include={mod.name}, save_evidence=False, timeout_total=1e-9))
    case = eng.investigate([DOMAIN])
    assert case.interrupted and eng.runtime.cancel_event.is_set() and eng.runtime.cancel_reason == "deadline"
    assert any("global timeout" in n for n in case.notes)


def test_exhausted_daily_quota_is_quota(registry):
    cls = registry(stub(lambda self, e, c: self.result(e), name="t_quota_mod", daily_quota=1))
    eng = make_engine(ScanOptions(include={cls.name}))
    assert cls.name in blocked_for(eng, cls.name)[0]
    eng.runtime.quota.add(cls.name, 1)
    runnable, block = blocked_for(eng, cls.name)
    assert cls.name not in runnable and block[0] is Status.QUOTA and block[2] == "quota"


def test_quota_coverage_stays_visible_on_the_first_screen(registry):
    """An exhausted daily quota was 'rate_limited' in v1 and is 'quota' now: the terminal coverage
    table keeps listing it as a could-not-verify source (it must never silently disappear)."""
    from v3lum.ui.render import _coverage
    from v3lum.ui.theme import make_console

    cls = registry(stub(lambda self, e, c: self.result(e), name="t_quota_cov_mod", daily_quota=1))
    eng = make_engine(ScanOptions(include={cls.name}, save_evidence=False))
    eng.runtime.quota.add(cls.name, 1)
    case = eng.investigate([DOMAIN]).to_dict()
    assert case["coverage"][cls.name]["status"] == "quota" and case["coverage"][cls.name]["reason_code"] == "quota"
    console = make_console(no_color=True, width=120)
    with console.capture() as cap:
        console.print(_coverage(case, full=False))
    assert "quota (1)" in cap.get() and cls.name in cap.get()


def test_readiness_blocked_tuples(clean_registry, registry):
    keyed = registry(stub(lambda self, e, c: self.result(e), name="t_keyed_mod", requires_keys=("t_missing_key",)))
    from tests.fakes import define_module

    active = define_module("t_active_mod", [T.DOMAIN], lambda self, e, c: self.result(e), opsec=Opsec.ACTIVE)
    eng = make_engine(ScanOptions(include={keyed.name, active.name}))
    assert blocked_for(eng, keyed.name)[1][::2] == (Status.NEEDS_KEY, "needs_key")
    assert blocked_for(eng, active.name)[1][::2] == (Status.SKIPPED, "opsec")
    eng = make_engine(ScanOptions(include={active.name}, mode=Opsec.ACTIVE))
    assert blocked_for(eng, active.name)[1][::2] == (Status.SKIPPED, "authorization")
    rows = {r["module"]: r for r in eng.plan(DOMAIN)}
    assert rows[active.name]["reason_code"] == "authorization" and rows[active.name]["ready"] is False


# ------------------------------------------------------------------ investigate: coverage, RunInfo, RuleContext
def test_investigate_coverage_reason_codes_and_run_info(registry, monkeypatch):
    def dom(self, entity, ctx):
        res = self.result(entity)
        res.pivot(T.IPV4, "45.33.32.20", "resolves_to")
        return res

    def ip(self, entity, ctx):
        raise http.Blocked("geo", 451, reason_code="geo_block")

    d = registry(stub(dom, name="t_cov_dom"))
    i = registry(stub(ip, name="t_cov_ip", accepts=frozenset({T.IPV4})))
    src = registry(stub(lambda self, e, c: self.result(e), name="t_cov_src", disclosure="third_party"))
    eng = make_engine(ScanOptions(include={d.name, i.name}, depth=1, save_evidence=False))
    runs = []
    real = eng.run_module

    def spy(cls, entity, case_dir=None, *, run=None):
        runs.append((cls.name, entity.key, run))
        return real(cls, entity, case_dir, run=run)

    monkeypatch.setattr(eng, "run_module", spy)
    case = eng.investigate([DOMAIN])
    assert case.coverage[i.name]["status"] == "blocked" and case.coverage[i.name]["reason_code"] == "geo_block"
    by = {name: run for name, _key, run in runs}
    if by[d.name] is not None:  # RunInfo available (context v2)
        assert by[d.name].is_seed is True and by[d.name].depth == 0
        assert by[i.name].is_seed is False and by[i.name].depth == 1
        assert by[i.name].provenance == ((DOMAIN.key, "resolves_to", d.name),)
    assert src.name not in case.coverage  # not selected at all (-M list)
    data = case.to_dict()
    assert data["tlp"] == ScanOptions().tlp
    assert data["modules"][0]["reason_code"] in ("", "geo_block")


def test_coverage_reason_code_always_matches_the_merged_status(registry):
    """A module that answers for one entity and is blocked for another shows status ok (the merged
    best outcome) with no reason code - never the pair ('ok', 'geo_block') - while the per-status
    counters keep the failure."""

    def run(self, entity, ctx):
        if entity.value == "example.org":
            res = self.result(entity)
            res.attr("country", "BR")
            res.pivot(T.DOMAIN, "child.example.org", "subdomain")
            return res
        raise http.Blocked("geo", 451, reason_code="geo_block")

    mod = registry(stub(run, name="t_cov_mixed"))
    case = make_engine(ScanOptions(include={mod.name}, depth=1, save_evidence=False)).investigate([DOMAIN])
    cov = case.coverage[mod.name]
    assert cov["runs"] == 2 and cov["status"] == "ok" and cov["ok"] == 1 and cov["blocked"] == 1
    assert cov.get("reason_code", "") == ""


def test_a_case_where_no_source_answered_says_inconclusive(registry):
    """Rule 5 (audit of wave 1): with every source module opt-in (interim A16 guard) or every run
    could-not-verify, the case says 'inconclusive: no source answered' instead of letting a
    zero-finding 'clean' read as a verdict; a case where a module answered gets no such note."""
    src = registry(stub(lambda self, e, c: self.result(e), name="t_note_src", default_enabled=False))
    case = make_engine(ScanOptions(categories={"utility"}, save_evidence=False)).investigate([DOMAIN])
    assert case.coverage[src.name]["reason_code"] == "not_default"
    notes = [n for n in case.notes if n.startswith("inconclusive")]
    assert len(notes) == 1 and "opt-in" in notes[0]

    def blocked(self, entity, ctx):
        raise http.Blocked("challenge page", 403)

    dead = registry(stub(blocked, name="t_note_blocked"))
    case = make_engine(ScanOptions(include={dead.name}, save_evidence=False)).investigate([DOMAIN])
    assert any(n.startswith("inconclusive") and "could not verify" in n for n in case.notes)

    def answers(self, entity, ctx):
        res = self.result(entity)
        res.attr("country", "BR")
        return res

    ok = registry(stub(answers, name="t_note_ok"))
    case = make_engine(ScanOptions(include={ok.name}, save_evidence=False)).investigate([DOMAIN])
    assert not [n for n in case.notes if n.startswith("inconclusive")]


def test_investigate_reports_not_default_in_coverage(registry):
    src = registry(stub(lambda self, e, c: self.result(e), name="t_cov_src2", default_enabled=False))
    case = make_engine(ScanOptions(categories={"utility"}, save_evidence=False)).investigate([DOMAIN])
    assert case.coverage[src.name]["status"] == "skipped" and case.coverage[src.name]["reason_code"] == "not_default"


def test_rules_receive_a_rule_context(registry):
    correlate.load_rules()
    saved_rules, saved_errors = dict(correlate.RULES), dict(correlate.RULE_ERRORS)
    seen = []

    @correlate.rule("t_ctx_probe", "Context probe")
    def probe(graph, results, rctx):
        seen.append(rctx)
        return []

    try:
        mod = registry(stub(lambda self, e, c: self.result(e), name="t_ctx_mod"))
        eng = make_engine(ScanOptions(include={mod.name}, save_evidence=False))
        eng.runtime.meta["purpose"] = "unit test"
        eng.investigate([DOMAIN])
    finally:
        correlate.RULES.clear()
        correlate.RULES.update(saved_rules)
        correlate.RULE_ERRORS.clear()
        correlate.RULE_ERRORS.update(saved_errors)
    rctx = seen[0]
    assert rctx.options is eng.options and rctx.settings is eng.runtime.config
    assert rctx.meta == {"purpose": "unit test"} and rctx.now.tzinfo is not None


def test_evidence_records_redacted_fields(registry, tmp_path):
    def run(self, entity, ctx):
        res = self.result(entity)
        res.raw = {"note": "alice@corp.example:hunter2"}
        res.attr("country", "BR")
        return res

    mod = registry(stub(run, name="t_ev_mod"))
    case = make_engine(ScanOptions(include={mod.name})).investigate([DOMAIN])
    res = next(r for r in case.results if r.module == mod.name)
    blob = json.loads(Path(res.evidence).read_text(encoding="utf-8"))
    assert blob["redacted_fields"] == ["raw:combo"] and "hunter2" not in json.dumps(blob)


@pytest.mark.parametrize("bad", ["../../outside", "a/b", "..", ".hidden", "x" * 200])
def test_case_ids_never_name_a_path(bad):
    with pytest.raises(ValueError, match="invalid case id"):
        make_engine(ScanOptions(save_evidence=False)).investigate([DOMAIN], case_id=bad)


def test_evidence_path_never_holds_the_value(registry):
    email = Entity.make("email", "alice.person@corp.example")

    def run(self, entity, ctx):
        res = self.result(entity)
        res.raw = {"seen": True}
        res.attr("country", "BR")
        return res

    mod = registry(stub(run, name="t_ev_path_mod", accepts=frozenset({T.EMAIL})))
    case = make_engine(ScanOptions(include={mod.name}, purpose="unit test")).investigate([email])
    path = Path(next(r for r in case.results if r.module == mod.name).evidence)
    assert "alice" not in str(path) and "corp" not in path.name
    assert path.parent.name == "evidence" and path.name.startswith("t_ev_path_mod__email__")


def test_evidence_never_holds_a_configured_key(registry):
    redact = pytest.importorskip("v3lum.core.redact")
    secret = "EvidenceKey0123456789abcd"
    redact.register_secret(secret)

    def run(self, entity, ctx):
        res = self.result(entity)
        res.raw = {"request": f"https://api.example.test/v1/lookup?apikey={secret}", "echo": secret}
        res.attr("country", "BR")
        return res

    mod = registry(stub(run, name="t_ev_key_mod"))
    case = make_engine(ScanOptions(include={mod.name})).investigate([DOMAIN])
    res = next(r for r in case.results if r.module == mod.name)
    text = Path(res.evidence).read_text(encoding="utf-8")
    assert secret not in text and json.loads(text)["data"]["echo"] == redact.MASK


def test_evidence_files_are_owner_only(registry):
    """A10/AR03 (audit of wave 1): evidence may hold provider data about people - written 0600 from
    creation whatever the process umask."""
    import os
    import stat

    def run(self, entity, ctx):
        res = self.result(entity)
        res.raw = {"answer": "x"}
        res.attr("country", "BR")
        return res

    mod = registry(stub(run, name="t_ev_mode_mod"))
    old = os.umask(0o022)
    try:
        case = make_engine(ScanOptions(include={mod.name})).investigate([DOMAIN])
    finally:
        os.umask(old)
    res = next(r for r in case.results if r.module == mod.name)
    assert res.evidence and stat.S_IMODE(os.stat(res.evidence).st_mode) == 0o600


def test_no_key_value_leaves_a_run_in_any_result_field(registry):
    """AR01 (audit of wave 1): a module that echoes a request URL or an upstream message carrying a
    configured key (or an unregistered key-like parameter) into findings, attributes, links, pivots,
    per-feed reasons or its own error string never puts the key into the result - hence never into
    the graph, the live events, the case JSON or the reports. Pivot values are indicators: only a
    configured key is masked there, a key-like parameter of an investigated URL stays in the IOC."""
    redact = pytest.importorskip("v3lum.core.redact")
    secret = "ResultKey0123456789abcdXYZ"
    redact.register_secret(secret)
    url = f"https://api.example.test/v1/lookup/{secret}?q=example.org"

    def run(self, entity, ctx):
        res = self.result(entity)
        res.attr("tags", [f"seen at {url}"])
        res.finding(f"Listed ({secret})", "low", f"answer of {url}", criterion=f"verdict from {url}", data={"url": url, secret: 1}, references=[url])
        res.link("raw answer", url + "&apikey=UNREGISTEREDkey987")
        res.pivot(T.URL, f"https://other.example.test/{secret}/page", "links_to", note=f"from {url}")
        res.pivot(T.URL, "https://phish.example.test/login?token=RecipientToken12345", "links_to")  # an IOC, kept
        res.source_status("t_src.feed", Status.BLOCKED, reason=f"refused at {url}")
        res.raw = {"request": url}
        res.error = f"partial answer from {url}"
        return res

    from tests.fakes import test_provider

    mod = registry(stub(run, name="t_key_echo_mod", sources=("t_src.feed",)))
    events: list[tuple[str, dict]] = []
    eng = make_engine(ScanOptions(include={mod.name}, save_evidence=False))
    eng.runtime.events.subscribe(lambda kind, payload: events.append((kind, payload)))
    with test_provider("t_src", sources=("feed",)):  # POL-04: every declared source is a registered source
        case = eng.investigate([DOMAIN])
    res = next(r for r in case.results if r.module == mod.name)
    blob = json.dumps(case.to_dict(), default=str) + json.dumps(res.to_dict(), default=str) + json.dumps(res.raw, default=str)
    blob += repr([(kind, payload) for kind, payload in events if kind in ("finding", "module_done", "entity")])
    assert secret not in blob and "UNREGISTEREDkey987" not in blob
    assert res.findings and res.links and len(res.pivots) == 2 and res.source_statuses  # masked, not dropped
    assert redact.MASK in res.findings[0].description and res.links[0][1].endswith("apikey=" + redact.MASK)
    values = [p.entity.value for p in res.pivots]
    assert any(f"/{redact.MASK}/page" in v for v in values)
    assert "https://phish.example.test/login?token=RecipientToken12345" in values


def test_a_run_that_returns_no_result_is_an_error_never_empty(registry):
    """Rule 5: a module bug (run() returning None or anything but a ModuleResult) never reads as
    'nothing found' - whatever the source answered."""

    def run(self, entity, ctx):
        res = self.result(entity)
        res.attr("country", "BR")
        return None  # forgot to return the result

    mod = registry(stub(run, name="t_no_return_mod"))
    res = make_engine(ScanOptions(include={mod.name})).run_module(mod, DOMAIN)
    assert res.status is Status.ERROR and res.reason_code == "error" and "not a ModuleResult" in res.error


# ------------------------------------------------------------------ timeline and aliases
def test_fragment_timeline_attribute_in_build_timeline(tmp_path, monkeypatch):
    directory = tmp_path / "vocab"
    directory.mkdir()
    (directory / "t_pack.json").write_text(json.dumps({
        "schema": "v3lum.vocab/1",
        "attributes": {"first_seen_breach": "oldest breach date"},
        "timeline": {"first_seen_breach": "first seen in a breach"},
    }))
    monkeypatch.setattr(vocab, "FRAGMENT_DIR", directory)
    vocab.reload()
    try:
        g = Graph()
        g.add_node(Entity.make("email", "alice@corp.example"), 0, seed=True)
        g.add_attributes(Entity.make("email", "alice@corp.example"), {"first_seen_breach": "2019-05-01", "created": "2020-01-02T00:00:00Z"}, "t_mod")
        events = {(e["date"], e["event"]) for e in build_timeline(g)}
        assert ("2019-05-01", "first seen in a breach") in events and ("2020-01-02", "registered/created") in events
    finally:
        monkeypatch.undo()
        vocab.reload()
    assert engine_mod._DATE_ATTRS == vocab.CORE_TIMELINE


def test_no_auto_expand_alias():
    from v3lum.core import entities

    if hasattr(entities, "NO_AUTO_EXPAND"):
        assert engine_mod.NO_AUTO_EXPAND is entities.NO_AUTO_EXPAND
    assert T.CPF in engine_mod.NO_AUTO_EXPAND and T.TEXT in engine_mod.NO_AUTO_EXPAND
    assert engine_mod._STATUS_RANK["quota"] > engine_mod._STATUS_RANK["rate_limited"] > engine_mod._STATUS_RANK["empty"]
