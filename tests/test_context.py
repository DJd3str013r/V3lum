"""Context v2 (module-author contract section 6), the module test kit (section 21) and conftest.

Covers: ScanOptions defaults/to_dict; RunInfo propagation to ctx properties; ctx.http carrying the
module metadata (host enforcement, max_requests, deadline, markers, cancel); ctx.dns public-resolver
flags by disclosure/TLP over the per-run core DoH scope; ctx.setting; key values registered with
the redactor; ctx.quota_remaining; ctx.state (persistence, 0600, size cap, isolation, refusals);
the tests.fakes kit; the conftest network guard (meta-test) and environment scrub.
"""

from __future__ import annotations

import json
import os
import socket
import sqlite3
import stat
import threading

import pytest

from tests import conftest
from tests.fakes import (
    DOH_HOSTS,
    DeadHttp,
    FakeClock,
    FakeHttp,
    UnexpectedRequest,
    add_dns,
    add_dns_failure,
    add_nxdomain_everything,
    allow_vocab,
    assert_no_secret,
    define_module,
    doh_url,
    fixture,
    graph_fixture,
    make_ctx,
    make_runtime,
    module_fixture,
    provider_fragment,
    run_module,
    source_ids,
    test_provider,
)
from v3lum import config
from v3lum.core import providers, redact, vocab
from v3lum.core.context import STATE_MAX_BYTES, Context, ModuleState, RunInfo, Runtime, ScanOptions, StateError
from v3lum.core.entities import Entity
from v3lum.core.entities import EntityType as T
from v3lum.core.http import Cancelled, DeadlineExceeded, NetworkError, PolicyError, QuotaExceeded, RequestCapReached, RequestInfo
from v3lum.core.models import Opsec, Status


def _noop(self, entity, ctx):
    return self.result(entity)


@pytest.fixture()
def net_module(clean_registry):
    """A third_party module on the synthetic provider (hosts api.example.test + extra.example.test)."""
    with test_provider(hosts=("api.example.test", "extra.example.test"), keys=("t_ctx_key",)) as prov:
        cls = define_module(
            "t_ctx_net", [T.DOMAIN], _noop,
            disclosure="third_party", provider=prov.id, sources=source_ids(prov), hosts=("api.example.test",),
            access_model="free_noauth_limited", max_requests=2, expected_latency=1.0, timeout=5.0,
            optional_keys=("t_ctx_key",),
        )
        yield cls


# --------------------------------------------------------------------------------------
# ScanOptions / RunInfo
# --------------------------------------------------------------------------------------


def test_scan_options_defaults():
    o = ScanOptions()
    assert o.tlp == "amber"  # A2
    assert o.mode is Opsec.PASSIVE and o.authorized is False and o.depth == 1
    assert (o.preset, o.breach_scope, o.licence_profile) == ("quick", "own", "")
    assert (o.authorization_ref, o.scope_path, o.scope, o.purpose, o.ticket, o.legal_basis, o.egress_override) == ("", "", None, "", "", "", "")
    assert not (o.expand_personal or o.allow_unknown or o.show_personal or o.no_defang)
    assert o.seed_tlp == {} and o.unconfirmed_seeds == set() and o.only_pairs is None


def test_scan_options_to_dict():
    v1 = {"tlp", "mode", "authorized", "depth", "max_entities", "threads", "include", "exclude", "categories", "include_disabled", "offline", "no_cache", "authorization_note"}
    v2 = {"authorization_ref", "scope_path", "scope", "preset", "purpose", "ticket", "legal_basis", "breach_scope", "expand_personal", "allow_unknown", "egress_override", "licence_profile", "show_personal", "no_defang", "seed_tlp", "unconfirmed_seeds", "only_pairs"}
    d = ScanOptions().to_dict()
    assert v1 | v2 <= set(d)
    assert d["scope"] is None and d["only_pairs"] is None
    scope = type("Scope", (), {"sha256": "ab" * 32})()
    opts = ScanOptions(
        scope=scope, unconfirmed_seeds={"domain:b.example", "domain:a.example"}, seed_tlp={"domain:a.example": "red"},
        only_pairs={("dns_records", "domain:a.example"): {"is_seed": False, "depth": 1, "provenance": [], "tlp": "amber"}},
    )
    d = opts.to_dict()
    assert d["scope"] == "ab" * 32
    assert d["unconfirmed_seeds"] == ["domain:a.example", "domain:b.example"]
    assert d["only_pairs"] == [{"module": "dns_records", "entity": "domain:a.example", "is_seed": False, "depth": 1, "provenance": [], "tlp": "amber"}]
    json.dumps(d)
    assert len(ScanOptions(scope={"targets": ["example.com"]}).to_dict()["scope"]) == 64  # digest of the loaded scope


def test_run_info_defaults_and_frozen():
    run = RunInfo()
    assert (run.entity, run.is_seed, run.depth, run.provenance, run.allowed_sources, run.tlp, run.deadline, run.case_id, run.priority, run.internal_seed) == (None, True, 0, (), None, "", None, "", "seed", False)
    with pytest.raises(AttributeError):
        run.depth = 3  # type: ignore[misc]


def test_run_info_propagates_to_ctx(net_module):
    provenance = (("domain:seed.example", "subdomain", "t_ctx_net"),)
    ctx = make_ctx(
        net_module, FakeHttp(), entity="domain:a.seed.example", is_seed=False, depth=2, provenance=provenance,
        allowed_sources=(), tlp="TLP:AMBER+STRICT", case_id="20261126-120000-abcd", priority="pivot",
    )
    assert isinstance(ctx, Context)
    assert ctx.entity == Entity.make("domain", "a.seed.example")
    assert (ctx.is_seed, ctx.depth, ctx.provenance) == (False, 2, provenance)
    assert ctx.allowed_sources == frozenset()
    assert ctx.tlp == "amber+strict" and ctx.case_id == "20261126-120000-abcd"
    assert ctx.run.priority == "pivot"
    default = make_ctx(net_module, FakeHttp())
    assert default.allowed_sources == frozenset(net_module.sources)  # None = every declared source
    assert default.tlp == "amber" and default.is_seed and default.depth == 0
    assert make_ctx(net_module, FakeHttp(), options=ScanOptions(tlp="red")).tlp == "red"


def test_ctx_mode_authorized_opsec_and_purpose(clean_registry):
    light = define_module("t_ctx_light", [T.DOMAIN], _noop, opsec=Opsec.LIGHT)
    ctx = make_ctx(light, FakeHttp(), options=ScanOptions(mode=Opsec.PASSIVE, purpose="incident 42"))
    assert ctx.mode is Opsec.PASSIVE and ctx.allowed_opsec is Opsec.PASSIVE and ctx.purpose == "incident 42"
    ctx2 = make_ctx(light, FakeHttp(), options=ScanOptions(mode=Opsec.ACTIVE, authorized=True))
    assert ctx2.allowed_opsec is Opsec.LIGHT and ctx2.authorized is True


# --------------------------------------------------------------------------------------
# ctx.http carries the module metadata
# --------------------------------------------------------------------------------------


def test_ctx_http_host_enforcement(net_module):
    http = FakeHttp().add("GET", "https://api.example.test/v1/x", json={"ok": True}).add("GET", "https://extra.example.test/", json={})
    ctx = make_ctx(net_module, http)
    assert ctx.http.get_json("https://api.example.test/v1/x") == {"ok": True}
    with pytest.raises(PolicyError):
        ctx.http.get("https://elsewhere.example/")  # undeclared host
    with pytest.raises(PolicyError):
        ctx.http.get("https://extra.example.test/")  # provider host the module does not declare (P327 cond 4)
    assert http.urls() == ["https://api.example.test/v1/x"]
    assert ctx.http.hosts == {"api.example.test": 1}


def test_ctx_http_internal_hosts_from_settings(clean_registry):
    fragment = provider_fragment("t_ctx_internal", hosts=(), internal=True, hosts_from_settings=["t_ctx_platform_url"], sources=("events",))
    with test_provider(**{k: v for k, v in fragment.items() if k not in ("schema", "id")}, provider_id="t_ctx_internal") as prov:
        cls = define_module("t_ctx_tip", [T.DOMAIN], _noop, disclosure="internal", provider=prov.id, sources=source_ids(prov), hosts=())
        http = FakeHttp().add("GET", "https://tip.corp.example/api/events", json=[])
        ctx = make_ctx(cls, http, settings={"t_ctx_platform_url": "https://tip.corp.example/"})
        assert ctx.http.get_json("https://tip.corp.example/api/events") == []
        with pytest.raises(PolicyError):
            ctx.http.get("https://api.example.test/")


def test_ctx_http_max_requests(net_module):
    http = FakeHttp().add("GET", "https://api.example.test/*", json={})
    ctx = make_ctx(net_module, http)
    ctx.http.get("https://api.example.test/1")
    ctx.http.get("https://api.example.test/2")
    with pytest.raises(RequestCapReached):
        ctx.http.get("https://api.example.test/3")
    assert ctx.http.requests == 2 and len(http.calls) == 2


def test_ctx_http_deadline_and_remaining(net_module):
    clock = FakeClock()
    http = FakeHttp().add("GET", "https://api.example.test/*", json={})
    ctx = make_ctx(net_module, http, clock=clock)
    assert ctx.deadline == pytest.approx(clock.monotonic() + net_module.timeout)
    assert ctx.remaining() == pytest.approx(5.0)
    clock.advance(6)
    assert ctx.remaining() == 0.0
    with pytest.raises(DeadlineExceeded):
        ctx.http.get("https://api.example.test/late")
    assert not http.calls
    run_deadline = clock.monotonic() + 1.5
    ctx2 = make_ctx(net_module, http, clock=clock, deadline=run_deadline)
    assert ctx2.deadline == run_deadline and ctx2.remaining() == pytest.approx(1.5)


def test_ctx_http_slow_response_hits_the_deadline(net_module):
    clock = FakeClock()
    http = FakeHttp(clock=clock).add("GET", "https://api.example.test/slow", json={}, latency=10)
    ctx = make_ctx(net_module, http, clock=clock)
    with pytest.raises(DeadlineExceeded):
        ctx.http.get("https://api.example.test/slow")


def test_ctx_http_error_markers_and_keyless(clean_registry):
    marker = {"id": "t_quota_body", "statuses": [200], "json_path": "error", "equals": "quota exceeded", "maps_to": "quota", "reason": "Test provider: daily quota exhausted"}
    with test_provider() as prov:
        cls = define_module(
            "t_ctx_markers", [T.DOMAIN], _noop, disclosure="third_party", provider=prov.id, sources=source_ids(prov),
            hosts=prov.hosts, access_model="free_noauth_limited", error_markers=(marker,),
        )
        http = FakeHttp().add("GET", "https://api.example.test/q", json={"error": "quota exceeded"}).add("GET", "https://api.example.test/f", status=403, text="Forbidden")
        ctx = make_ctx(cls, http)
        with pytest.raises(QuotaExceeded):
            ctx.http.get_json("https://api.example.test/q")  # error inside HTTP 200 (P321)
        res = run_module(cls, "domain:example.com", http)
        assert res.status is Status.EMPTY  # the synthetic run() makes no request
        from v3lum.core.http import Blocked

        with pytest.raises(Blocked) as err:
            ctx.http.get_json("https://api.example.test/f")  # keyless 403 = could not verify
        assert err.value.reason_code == "challenge"


def test_cancel_kill_switch(net_module):
    http = FakeHttp().add("GET", "https://api.example.test/*", json={})
    rt = make_runtime(http)
    ctx = rt.context(net_module, ScanOptions(), run=RunInfo(entity=Entity.make("domain", "example.com")))
    assert not ctx.cancelled()
    rt.cancel("scope window ended")
    assert rt.cancel_reason == "scope window ended" and rt.cancel_event.is_set() and ctx.cancelled()
    with pytest.raises(Cancelled):
        ctx.http.get("https://api.example.test/after-cancel")
    rt2 = make_runtime(FakeHttp())
    rt2.cancel()
    assert rt2.cancel_reason == "cancelled"


def test_offline_module_gets_no_network(clean_registry):
    cls = define_module("t_ctx_offline", [T.DOMAIN], _noop)
    http = FakeHttp().add("GET", "https://api.example.test/", json={})
    ctx = make_ctx(cls, http)
    with pytest.raises(PolicyError):
        ctx.http.get("https://api.example.test/")
    assert not http.calls


def test_target_module_has_no_static_host_list(clean_registry):
    cls = define_module("t_ctx_target", [T.DOMAIN], _noop, opsec=Opsec.LIGHT)
    http = FakeHttp().add("GET", "https://www.target.example/robots.txt", text="User-agent: *")
    ctx = make_ctx(cls, http, options=ScanOptions(mode=Opsec.LIGHT))
    assert ctx.http.get("https://www.target.example/robots.txt").status == 200  # scope checks: wave 2
    assert ctx.net is not None


# --------------------------------------------------------------------------------------
# ctx.dns over the per-run core DoH scope
# --------------------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("disclosure", "tlp", "public", "fallback"),
    [
        ("third_party", "clear", True, True),
        ("third_party", "green", True, True),
        ("third_party", "amber", True, False),
        ("third_party", "amber+strict", True, False),
        ("third_party", "red", False, False),
        ("none", "clear", False, False),
        ("internal", "green", False, False),
    ],
)
def test_dns_public_flags_by_disclosure_and_tlp(clean_registry, disclosure, tlp, public, fallback):
    attrs = {"disclosure": disclosure}
    if disclosure != "none":
        prov_id = "core_doh" if disclosure == "third_party" else "internal_doh"
        sid = "core_doh.resolvers" if disclosure == "third_party" else "internal_doh.resolver"
        attrs.update(provider=prov_id, sources=(sid,), hosts=(), max_requests=0, expected_latency=1.0)
        if disclosure == "third_party":
            attrs["access_model"] = "free_noauth_unlimited"
    cls = define_module(f"t_ctx_dns_{disclosure}", [T.DOMAIN], _noop, **attrs)
    ctx = make_ctx(cls, FakeHttp(), tlp=tlp)
    assert (ctx.dns.allow_public, ctx.dns.allow_public_fallback) == (public, fallback)


def test_dns_red_without_internal_resolver_is_could_not_verify(clean_registry):
    from v3lum.modules.domain_dns.dns_records import DnsRecords

    http = FakeHttp()
    ctx = make_ctx(DnsRecords, http, tlp="red")
    answer = ctx.dns.query("example.com", "A")
    assert answer.could_not_verify and not answer.nxdomain
    assert not http.calls  # no public resolver at RED (A2)


def test_dns_is_not_counted_and_reaches_the_ledger():
    from v3lum.modules.domain_dns.dns_records import DnsRecords

    http = FakeHttp()
    add_dns(http, "example.com", "A", ["93.184.215.14"])
    ctx = make_ctx(DnsRecords, http)
    assert ctx.dns.query("example.com", "A").records == ["93.184.215.14"]
    assert ctx.http.requests == 0  # DoH is not charged to the module (max_requests = 0)
    assert ctx.doh.hosts == {"dns.google": 1}
    assert all("edns_client_subnet=0.0.0.0" in u for u in http.urls())
    with pytest.raises(PolicyError):
        ctx.doh.get("https://api.example.test/")  # the core scope only reaches DoH resolvers


def test_doh_scope_of_offline_or_red_runs_reaches_only_the_internal_resolver(clean_registry):
    from v3lum.modules.domain_dns.dns_records import DnsRecords

    offline = define_module("t_ctx_doh_offline", [T.DOMAIN], _noop)
    for ctx in (make_ctx(offline, FakeHttp()), make_ctx(DnsRecords, FakeHttp(), tlp="red")):
        with pytest.raises(PolicyError):
            ctx.doh.get(doh_url("example.com", "A"))  # no public DoH, even through ctx.doh (A2)
    http = FakeHttp()
    add_dns(http, "intranet.corp.example", "A", ["10.1.2.3"], provider="https://doh.corp.example/dns-query")
    ctx = make_ctx(offline, http, settings={"doh_internal": "https://doh.corp.example/dns-query"})
    assert ctx.dns.query("intranet.corp.example", "A").records == ["10.1.2.3"]
    assert http.hosts() == {"doh.corp.example"}


def test_internal_doh_resolver_first():
    from v3lum.modules.domain_dns.dns_records import DnsRecords

    http = FakeHttp()
    add_dns(http, "intranet.corp.example", "A", ["10.1.2.3"], provider="https://doh.corp.example/dns-query")
    ctx = make_ctx(DnsRecords, http, settings={"doh_internal": "https://doh.corp.example/dns-query"})
    assert ctx.dns.providers[0] == "internal"
    assert ctx.dns.query("intranet.corp.example", "A").records == ["10.1.2.3"]
    http.assert_hosts_within(DnsRecords)


# --------------------------------------------------------------------------------------
# settings, keys, quota
# --------------------------------------------------------------------------------------


def test_setting_resolves_module_and_core_settings(clean_registry):
    cls = define_module("t_ctx_settings", [T.DOMAIN], _noop, settings={"t_ctx_limit": 5})
    assert make_ctx(cls, FakeHttp()).setting("t_ctx_limit") == 5
    assert make_ctx(cls, FakeHttp(), settings={"t_ctx_limit": 9}).setting("t_ctx_limit") == 9
    ctx = make_ctx(cls, FakeHttp())
    assert ctx.setting("tlp") == "amber"
    assert ctx.setting("t_ctx_not_a_setting", "fallback") == "fallback"
    unregistered = type("Unregistered", (), {"name": "t_ctx_unreg", "settings": {"t_ctx_unreg_mode": "fast"}})
    assert make_ctx(unregistered, FakeHttp()).setting("t_ctx_unreg_mode") == "fast"


def test_setting_declared_as_setting_spec(clean_registry):
    """Module settings may declare SettingSpec(default, description, choices=...): ctx.setting gives
    the default (registered or not), and the choices are enforced by Config.set."""
    spec = config.SettingSpec("fast", "scan depth of the synthetic module", choices=("fast", "full"))
    cls = define_module("t_ctx_spec", [T.DOMAIN], _noop, settings={"t_ctx_spec_mode": spec})
    ctx = make_ctx(cls, FakeHttp())
    assert ctx.setting("t_ctx_spec_mode") == "fast"
    assert config.SETTINGS_META["t_ctx_spec_mode"].description == "scan depth of the synthetic module"
    with pytest.raises(ValueError):
        ctx.config.set("t_ctx_spec_mode", "deep")
    unregistered = type("UnregisteredSpec", (), {"name": "t_ctx_unreg2", "settings": {"t_ctx_unreg2_mode": spec}})
    assert make_ctx(unregistered, FakeHttp()).setting("t_ctx_unreg2_mode") == "fast"


def test_key_values_registered_with_the_redactor_at_runtime_start(net_module):
    secret = "tk-0123456789abcdef"
    redact.clear()
    make_runtime(FakeHttp(), keys={"t_ctx_key": secret})
    assert redact.registered_count() >= 1
    assert secret not in redact.redact_text(f"GET https://api.example.test/?q=1 token {secret}")
    ctx = make_ctx(net_module, FakeHttp(), keys={"t_ctx_key": secret}, settings={"key_plans": {"t_ctx_key": "business"}})
    assert ctx.has_key("t_ctx_key") and ctx.key("t_ctx_key") == secret
    assert ctx.key_plan("t_ctx_key") == "business" and ctx.key_plan("shodan") == ""


def test_keyless_flag_follows_configured_keys(net_module):
    assert make_ctx(net_module, FakeHttp()).http.keyless is True
    assert make_ctx(net_module, FakeHttp(), keys={"t_ctx_key": "tk-0123456789abcdef"}).http.keyless is False


def test_quota_remaining_thin(clean_registry):
    cls = define_module("t_ctx_daily", [T.DOMAIN], _noop, daily_quota=5)
    rt = make_runtime(FakeHttp())
    ctx = rt.context(cls, ScanOptions())
    assert ctx.quota_remaining() == 5
    rt.quota.add("t_ctx_daily", 2)
    assert ctx.quota_remaining() == 3
    assert rt.context(define_module("t_ctx_unbudgeted", [T.DOMAIN], _noop), ScanOptions()).quota_remaining() is None
    quota = {"scope": "egress_ip", "day": 100, "published": True, "evidence_url": "https://terms.example.test/limits"}
    with test_provider("t_ctx_quota_provider", quota=quota) as prov:
        budgeted = define_module(
            "t_ctx_budgeted", [T.DOMAIN], _noop, disclosure="third_party", provider=prov.id, sources=source_ids(prov),
            hosts=prov.hosts, access_model="free_noauth_limited", daily_quota=1000,
        )
        ctx2 = rt.context(budgeted, ScanOptions())
        assert ctx2.quota_remaining() == 80  # registry budget: 80% of the published day limit (P334)
        rt.quota.add(prov.id, 30)
        assert ctx2.quota_remaining() == 50


# --------------------------------------------------------------------------------------
# ctx.state
# --------------------------------------------------------------------------------------


def test_state_persists_across_runtimes_with_0600(clean_registry):
    cls = define_module("t_ctx_state", [T.DOMAIN], _noop)
    make_ctx(cls, FakeHttp()).state.set("disabled_sites", {"site_a": "2026-11-26"})
    ctx = make_ctx(cls, FakeHttp())  # a new Runtime
    assert ctx.state.get("disabled_sites") == {"site_a": "2026-11-26"}
    assert ctx.state.get("missing", 7) == 7
    path = ctx.state.path
    assert path.name == "t_ctx_state.json" and path.parent.name == "state"
    assert stat.S_IMODE(os.stat(path).st_mode) == 0o600
    assert ctx.state.all() == {"disabled_sites": {"site_a": "2026-11-26"}}
    assert ctx.state.delete("disabled_sites") is True and ctx.state.delete("disabled_sites") is False
    assert ctx.state.all() == {}


def test_state_isolated_per_module(clean_registry):
    a = define_module("t_ctx_state_a", [T.DOMAIN], _noop)
    b = define_module("t_ctx_state_b", [T.DOMAIN], _noop)
    make_ctx(a, FakeHttp()).state.set("position", 3)
    assert make_ctx(b, FakeHttp()).state.get("position") is None
    assert make_ctx(a, FakeHttp()).state.get("position") == 3


def test_state_size_cap_and_json_only(clean_registry):
    cls = define_module("t_ctx_state_cap", [T.DOMAIN], _noop)
    state = make_ctx(cls, FakeHttp()).state
    state.set("small", "x")
    with pytest.raises(StateError):
        state.set("big", "y" * (STATE_MAX_BYTES + 1))
    assert state.all() == {"small": "x"}  # unchanged
    with pytest.raises(StateError):
        state.set("obj", object())
    with pytest.raises(StateError):
        state.set("nan", float("nan"))
    with pytest.raises(StateError):
        state.set("", 1)
    state.path.write_text(json.dumps({"big": "z" * STATE_MAX_BYTES}))  # grown outside ctx.state
    assert state.get("big") is None and state.all() == {}  # never loaded past the cap


def test_state_refuses_personal_values_and_secrets(clean_registry):
    cls = define_module("t_ctx_state_priv", [T.EMAIL, T.DOMAIN], _noop)
    ctx = make_ctx(cls, FakeHttp(), entity="email:john.doe@acme.example")
    with pytest.raises(StateError):
        ctx.state.set("last", "john.doe@acme.example")
    with pytest.raises(StateError):
        ctx.state.set("seen", ["other.person@acme.example"])  # any e-mail address
    with pytest.raises(StateError):
        ctx.state.set("cpf", "111.444.777-35")
    secret = "tk-statesecret-0123456789"
    redact.register_secret(secret)
    with pytest.raises(StateError):
        ctx.state.set("key", {"value": secret})
    ctx.state.set("checked_domains", 12)  # aggregate counters are fine
    assert ctx.state.get("checked_domains") == 12
    with pytest.raises(StateError):
        ModuleState("../escape")


def test_state_refuses_unformatted_cpf_and_entity_digits(clean_registry):
    cls = define_module("t_ctx_state_digits", [T.PHONE, T.DOMAIN], _noop)
    ctx = make_ctx(cls, FakeHttp(), entity="phone:+5511912345678")
    with pytest.raises(StateError):
        ctx.state.set("cpf", "11144477735")  # a valid CPF without punctuation
    with pytest.raises(StateError):
        ctx.state.set("cpf_number", 11144477735)
    with pytest.raises(StateError):
        ctx.state.set("last", "5511912345678")  # the run's phone in digits-only form
    ctx.state.set("serial", "12345678901")  # 11 digits that are not a valid CPF are fine
    ctx.state.set("enabled", True)
    assert ctx.state.all() == {"serial": "12345678901", "enabled": True}
    assert stat.S_IMODE(os.stat(ctx.state.path.parent).st_mode) == 0o700


def test_state_is_thread_safe(clean_registry):
    cls = define_module("t_ctx_state_threads", [T.DOMAIN], _noop)
    ctx = make_ctx(cls, FakeHttp())

    def work(i: int) -> None:
        ctx.state.set(f"k{i}", i)

    threads = [threading.Thread(target=work, args=(i,)) for i in range(12)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    assert ctx.state.all() == {f"k{i}": i for i in range(12)}


def test_state_available_to_health_self_tests(clean_registry):
    from v3lum.core.module import HealthCheck, HealthResult

    def selftest(ctx):
        n = ctx.state.get("runs", 0) + 1
        ctx.state.set("runs", n)
        return HealthResult("ok", f"run {n}")

    hc = HealthCheck(offline=True, selftest=selftest)
    cls = define_module("t_ctx_selftest", [T.DOMAIN], _noop, opsec=Opsec.LIGHT)
    assert hc.selftest(make_ctx(cls, FakeHttp())).detail == "run 1"
    assert hc.selftest(make_ctx(cls, FakeHttp())).detail == "run 2"


# --------------------------------------------------------------------------------------
# Runtime
# --------------------------------------------------------------------------------------


def test_runtime_v2_attributes():
    clock = FakeClock("2026-11-26T08:00:00Z")
    rt = make_runtime(FakeHttp(), clock=clock)
    assert isinstance(rt, Runtime)
    assert rt.clock is clock and rt.now() == clock.now() and rt.now().tzinfo is not None
    assert (rt.meta, rt.in_scan, rt.cancel_reason, rt.case_hooks) == ({}, False, "", [])
    assert rt.providers is providers.registry()
    assert rt.org.is_empty  # lazy load_default(config): no profile in the isolated home
    rt2 = make_runtime(FakeHttp(), org_profile={"domains": [{"name": "acme.example", "verification": "txt_verified"}]})
    assert rt2.org.is_verified_domain("acme.example")
    assert make_ctx(type("Probe", (), {"name": "probe"}), FakeHttp(), runtime=rt2).org is rt2.org
    legacy = Runtime(config.Config(), transport=FakeHttp(), now=lambda: clock.now(), no_cache=True)
    assert legacy.now() == clock.now()


def test_http_request_event_carries_request_info(net_module):
    events = []
    http = FakeHttp().add("GET", "https://api.example.test/ev", json={})
    rt = make_runtime(http)
    rt.events.subscribe(lambda kind, payload: events.append((kind, payload)))
    rt.context(net_module, ScanOptions()).http.get("https://api.example.test/ev")
    infos = [p["info"] for k, p in events if k == "http_request"]
    assert infos and isinstance(infos[0], RequestInfo)
    assert infos[0].module == "t_ctx_net" and infos[0].host == "api.example.test"
    assert any(k == "http" for k, _ in events)  # the legacy event stays


def test_core_helper_classes_without_metadata_still_work():
    """Core helpers (e.g. doctor probes) pass a bare class: no module host list applies."""
    probe = type("Doctor", (), {"name": "doctor", "cache_ttl": 0, "min_interval": 0})
    http = FakeHttp().add("GET", "https://api.github.com/zen", text="ok")
    ctx = make_runtime(http).context(probe)
    assert ctx.http.get("https://api.github.com/zen", ttl=0).status == 200


@pytest.mark.parametrize("disclosure", [None, "", "bogus"])
def test_module_subclass_without_valid_disclosure_fails_closed(disclosure):
    """A Module subclass that bypassed @register without a valid disclosure gets no network and no
    public resolver (P327 cond 3-5): it is never treated like an unrestricted core helper."""
    from v3lum.core.module import Module

    body = {"name": "t_ctx_undeclared", "accepts": frozenset({T.DOMAIN}), "hosts": ("api.example.test",)}
    if disclosure is not None:
        body["disclosure"] = disclosure
    cls = type("Undeclared", (Module,), body)
    http = FakeHttp().add("GET", "https://api.example.test/*", json={})
    add_dns(http, "example.com", "A", ["93.184.215.14"])
    ctx = make_ctx(cls, http)
    assert ctx.http.disclosure == "none"
    with pytest.raises(PolicyError):
        ctx.http.get("https://api.example.test/exfil")
    assert ctx.dns.allow_public is False and ctx.dns.query("example.com", "A").could_not_verify
    assert not http.calls
    with pytest.raises(PolicyError):
        ctx.net.connect("example.com", 443)


def test_duck_typed_class_with_metadata_is_enforced_like_a_module():
    meta = type("Meta", (), {"name": "t_ctx_duck", "disclosure": "third_party", "hosts": ("api.example.test",), "max_requests": 1})
    http = FakeHttp().add("GET", "https://api.example.test/*", json={})
    ctx = make_ctx(meta, http)
    ctx.http.get("https://api.example.test/one")
    with pytest.raises(PolicyError):
        ctx.http.get("https://elsewhere.example/")
    with pytest.raises(RequestCapReached):
        ctx.http.get("https://api.example.test/two")


def test_internal_doh_entries_must_be_internal():
    """A public resolver or a credentialed URL configured as 'internal' never widens a scope that
    must stay internal (offline/internal modules, TLP:RED)."""
    from v3lum.core.context import doh_hosts

    def hosts(**settings):
        cfg = config.Config()
        cfg.settings.update(settings)
        return doh_hosts(cfg, public=False)

    assert hosts(doh_internal="https://doh.corp.example/dns-query") == ("doh.corp.example",)
    assert hosts(doh_internal="https://dns.google/resolve") == ()
    assert hosts(doh_internal="https://user:pw@doh.corp.example/dns-query") == ()
    assert hosts(doh_internal="http://doh.corp.example/dns-query") == ()
    assert hosts(doh_providers=["https://cloudflare-dns.com/dns-query", "https://doh2.corp.example/q"]) == ("doh2.corp.example",)
    public = doh_hosts(config.Config(), public=True)
    assert {"dns.google", "cloudflare-dns.com"} <= set(public)


@pytest.mark.parametrize(
    "url",
    [
        "https://mozilla.cloudflare-dns.com/dns-query",  # subdomain of a public DoH operator
        "https://dns.google./resolve",  # trailing dot
        "https://[2001:4860:4860::8888]/resolve",  # IP literal of a public anycast network
        "https://8.8.8.8/resolve",
    ],
)
def test_internal_doh_scope_uses_the_resolver_rule_for_public_hosts(url):
    """The internal-only DoH scope and the Resolver agree on what is public (dns.is_public_doh_host):
    a public resolver never passes as the organisation's internal DoH at TLP:RED (A2, P029 cond 7)."""
    from v3lum.core.context import doh_hosts
    from v3lum.core.dns import Resolver

    cfg = config.Config()
    cfg.settings["doh_internal"] = url
    assert doh_hosts(cfg, public=False) == ()
    assert Resolver(None, internal_url=url).internal_url == ""


def test_ctx_http_settings_hosts_follow_the_provider_registry_rule(clean_registry):
    """hosts_from_settings go through ProviderRegistry.hosts_for: an http:// URL or a host another
    provider owns never becomes an 'internal' host of ctx.http (A12, fail closed)."""
    fragment = provider_fragment("t_ctx_internal2", hosts=(), internal=True, hosts_from_settings=["t_ctx_platform2_url"], sources=("events",))
    with test_provider(**{k: v for k, v in fragment.items() if k not in ("schema", "id")}, provider_id="t_ctx_internal2") as prov:
        cls = define_module("t_ctx_tip2", [T.DOMAIN], _noop, disclosure="internal", provider=prov.id, sources=source_ids(prov), hosts=())
        for url, host in (("http://tip.corp.example/", "tip.corp.example"), ("https://internetdb.shodan.io/", "internetdb.shodan.io")):
            http = FakeHttp().add("GET", f"https://{host}/api", json=[])
            ctx = make_ctx(cls, http, settings={"t_ctx_platform2_url": url})
            assert host not in (ctx.http.allowed_hosts or ())
            with pytest.raises(PolicyError):
                ctx.http.get_json(f"https://{host}/api")
            assert http.calls == []
        ok = make_ctx(cls, FakeHttp(), settings={"t_ctx_platform2_url": "https://tip.corp.example/"})
        assert ok.http.allowed_hosts == ("tip.corp.example",)


def test_ctx_log_is_redacted():
    from v3lum.modules.domain_dns.dns_records import DnsRecords

    secret = "tk-logsecret-0123456789"
    events = []
    ctx = make_ctx(DnsRecords, FakeHttp(), keys={"shodan": secret})
    ctx.runtime.events.subscribe(lambda kind, payload: events.append((kind, payload)))
    ctx.log(f"GET https://api.example.test/v1?apikey=abc123def456 with {secret}")
    message = next(p["message"] for k, p in events if k == "log")
    assert secret not in message and "abc123def456" not in message
    assert message.startswith("GET https://api.example.test/v1?apikey=")


def test_quota_book_is_created_once_under_concurrency():
    rt = make_runtime(FakeHttp())
    books = []

    def grab() -> None:
        books.append(rt.quota)

    threads = [threading.Thread(target=grab) for _ in range(8)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    assert len({id(b) for b in books}) == 1


# --------------------------------------------------------------------------------------
# tests.fakes kit
# --------------------------------------------------------------------------------------


def test_fakehttp_normalised_matching_and_headers():
    http = FakeHttp()
    http.add("GET", "https://API.Example.test/search?b=2&a=1", json={"hit": 1})
    http.add("GET", "https://api.example.test/h", json={"auth": True}, match_headers={"Accept": "application/json"})
    assert http.request("GET", "https://api.example.test/search?a=1&b=2").json() == {"hit": 1}
    assert http.request("GET", "https://api.example.test/search", params={"a": 1, "b": 2}).json() == {"hit": 1}
    with pytest.raises(AssertionError, match="unexpected HTTP request"):
        http.request("GET", "https://api.example.test/h")
    assert http.request("GET", "https://api.example.test/h", headers={"accept": "application/json"}).json() == {"auth": True}
    assert http.hosts() == {"api.example.test"}


def test_fakehttp_times_gives_a_sequence():
    http = FakeHttp().add("GET", "https://api.example.test/seq", status=503, times=1).add("GET", "https://api.example.test/seq", json={"n": 2})
    assert http.request("GET", "https://api.example.test/seq").status == 503
    assert http.request("GET", "https://api.example.test/seq").json() == {"n": 2}
    assert http.request("GET", "https://api.example.test/seq").json() == {"n": 2}


def test_fakehttp_transport_redirects_through_the_real_client(net_module):
    http = FakeHttp()
    http.add("GET", "https://api.example.test/old", redirect_to="https://api.example.test/new")
    http.add("GET", "https://api.example.test/new", json={"moved": True})
    resp = make_ctx(net_module, http).http.get("https://api.example.test/old")
    assert resp.status == 200 and resp.json() == {"moved": True}
    assert resp.history == ["https://api.example.test/old"]
    assert [c["method"] for c in http.calls] == ["GET", "GET"]
    off_host = FakeHttp().add("GET", "https://api.example.test/out", redirect_to="https://elsewhere.example/")
    with pytest.raises(PolicyError):
        make_ctx(net_module, off_host).http.get("https://api.example.test/out")  # every hop host-checked


def test_fakehttp_latency_and_deadline():
    clock = FakeClock()
    http = FakeHttp(clock=clock).add("GET", "https://api.example.test/slow", json={}, latency=2.5)
    start = clock.monotonic()
    resp = http.send("GET", "https://api.example.test/slow")
    assert clock.monotonic() - start == pytest.approx(2.5) and resp.elapsed == 2.5
    with pytest.raises(DeadlineExceeded):
        http.send("GET", "https://api.example.test/slow", deadline=clock.monotonic() + 1)
    assert http.send("GET", "https://api.example.test/slow", max_bytes=1).truncated is True


def test_assert_hosts_within(net_module):
    http = FakeHttp().add("GET", "https://api.example.test/a", json={})
    add_dns(http, "example.com", "A", [])
    http.request("GET", "https://api.example.test/a")
    http.request("GET", doh_url("example.com", "A"))
    http.assert_hosts_within(net_module)
    http.add("GET", "https://cdn.example.test/x", json={})
    http.request("GET", "https://cdn.example.test/x")
    with pytest.raises(AssertionError, match="undeclared hosts"):
        http.assert_hosts_within(net_module)
    http.assert_hosts_within(net_module, extra=("*.example.test",))
    assert {"dns.google", "cloudflare-dns.com", "dns.quad9.net"} <= DOH_HOSTS


def test_doh_helpers_build_the_core_urls():
    url = doh_url("example.com", "mx")
    assert url.startswith("https://dns.google/resolve?") and "edns_client_subnet=0.0.0.0%2F0" in url and "type=MX" in url
    assert doh_url("example.com", "A", provider="cloudflare") == "https://cloudflare-dns.com/dns-query?name=example.com&type=A"
    http = FakeHttp()
    add_dns(http, "a.example", "A", ["192.0.2.1"], provider="all")
    add_dns_failure(http, "b.example", "A", kind="servfail")
    add_dns_failure(http, "c.example", "A", kind="refused", provider="cloudflare")
    add_dns_failure(http, "d.example", "A", kind="http500")
    add_dns_failure(http, "e.example", "A", kind="timeout")
    add_nxdomain_everything(http)
    assert http.request("GET", doh_url("a.example", "A", provider="cloudflare")).json()["Answer"][0]["data"] == "192.0.2.1"
    assert http.request("GET", doh_url("b.example", "A")).json()["Status"] == 2
    assert http.request("GET", doh_url("c.example", "A", provider="cloudflare")).json()["Status"] == 5
    assert http.request("GET", doh_url("d.example", "A")).status == 500
    with pytest.raises(NetworkError):
        http.request("GET", doh_url("e.example", "A"))
    assert http.request("GET", doh_url("zzz.example", "TXT", provider="cloudflare")).json()["Status"] == 3
    with pytest.raises(ValueError):
        add_dns_failure(http, "x.example", "A", kind="nope")


def test_dead_http_records_and_fails():
    http = DeadHttp()
    with pytest.raises(NetworkError):
        http.send("GET", "https://api.example.test/x")
    with pytest.raises(NetworkError):
        http.request("GET", "https://api.example.test/y")
    assert http.hosts() == {"api.example.test"}


def test_run_module_fails_on_a_request_without_route(clean_registry):
    """The engine maps a module's exceptions to statuses; a missing FakeHttp route must still fail
    the test instead of looking like a dead source (status ERROR)."""

    def calls_api(self, entity, ctx):
        ctx.http.get("https://routes.example.test/not-routed")
        return self.result(entity)

    with test_provider("t_ctx_route_provider", hosts=("routes.example.test",)) as prov:
        cls = define_module(
            "t_ctx_unrouted", [T.DOMAIN], calls_api, disclosure="third_party", provider=prov.id, sources=source_ids(prov),
            hosts=prov.hosts, access_model="free_noauth_limited",
        )
        http = FakeHttp()
        with pytest.raises(UnexpectedRequest, match="routes.example.test/not-routed"):
            run_module(cls, "domain:example.com", http)
        assert http.unexpected == ["GET https://routes.example.test/not-routed"]
        http.add("GET", "https://routes.example.test/not-routed", json={})
        assert run_module(cls, "domain:example.com", http).status is Status.EMPTY  # routed now: no failure


def test_run_module_passes_run_info_fields(clean_registry):
    seen = {}

    def run(self, entity, ctx):
        seen.update(seed=ctx.is_seed, depth=ctx.depth, internal=ctx.run.internal_seed, case=ctx.case_id, tlp=ctx.tlp)
        return self.result(entity)

    cls = define_module("t_ctx_runinfo", [T.DOMAIN], run)
    run_module(cls, "domain:example.com", is_seed=False, depth=2, internal_seed=True, case_id="c-1", tlp="green")
    assert seen == {"seed": False, "depth": 2, "internal": True, "case": "c-1", "tlp": "green"}


def test_run_module_and_define_module_defaults(clean_registry):
    def run(self, entity, ctx):
        res = self.result(entity)
        res.attr("country", "BR")
        return res

    cls = define_module("t_ctx_defaults", [T.DOMAIN], run)
    assert (cls.terms, cls.disclosure, cls.hosts, cls.opsec, cls.category) == ("open", "none", (), Opsec.PASSIVE, "utility")
    assert run_module(cls, "domain:example.com").attributes == {"country": "BR"}
    assert run_module(cls, Entity.make("domain", "example.com")).status is Status.OK
    with pytest.raises(ValueError):
        run_module(cls, "example.com")
    light = define_module("t_ctx_light_defaults", [T.DOMAIN], run, opsec=Opsec.LIGHT)
    assert light.disclosure == "target" and light.default_enabled is False
    with test_provider() as prov:
        net = define_module("t_ctx_net_defaults", [T.DOMAIN], run, disclosure="third_party", provider=prov.id, sources=source_ids(prov), hosts=prov.hosts, access_model="free_noauth_limited")
        assert (net.max_requests, net.expected_latency) == (10, 1.0)


def test_test_provider_registers_and_unregisters():
    assert providers.registry().get("t_ctx_tmp") is None
    with test_provider("t_ctx_tmp", hosts=("tmp.example.test",), keys={"t_ctx_tmp_key": "temporary key"}, terms="license") as prov:
        reg = providers.registry()
        assert reg.get("t_ctx_tmp") is prov and reg.provider_for_host("tmp.example.test").id == "t_ctx_tmp"
        assert reg.source("t_ctx_tmp.default").terms.class_ == "license"
        assert "t_ctx_tmp_key" in config.key_registry()
    assert providers.registry().get("t_ctx_tmp") is None
    assert "t_ctx_tmp_key" not in config.key_registry()


def test_allow_vocab_extends_strict_mode_temporarily():
    from v3lum.core.models import ModuleResult

    assert vocab.strict_enabled()
    res = ModuleResult(module="t", entity=Entity.make("domain", "example.com"))
    with pytest.raises(vocab.UnknownVocab):
        res.attr("t_ctx_custom_attr", 1)
    with allow_vocab(attributes=("t_ctx_custom_attr",), tags=("t_ctx_tag",), relations={"t_ctx_rel": "test relation"}):
        res.attr("t_ctx_custom_attr", 1)
        assert vocab.is_known_tag("t_ctx_tag") and vocab.is_known_relation("t_ctx_rel")
    with pytest.raises(vocab.UnknownVocab):
        res.attr("t_ctx_custom_attr", 2)


def test_assert_no_secret_scans_everything(tmp_path):
    secret = "Zx9-secret/token+value"
    clean = {"a": ["nothing here"], "b": b"bytes"}
    assert_no_secret(secret, "plain text", b"raw", clean, tmp_path)
    (tmp_path / "sub").mkdir()
    (tmp_path / "sub" / "evidence.json").write_text(json.dumps({"url": "https://x.example/?k=" + secret}))
    with pytest.raises(AssertionError) as err:
        assert_no_secret(secret, tmp_path)
    assert secret not in str(err.value) and "evidence.json" in str(err.value)
    db = tmp_path / "cache.sqlite"
    conn = sqlite3.connect(db)
    conn.execute("CREATE TABLE t (v TEXT)")
    conn.execute("INSERT INTO t VALUES (?)", (f"https://x.example/{secret}",))
    conn.commit()
    conn.close()
    with pytest.raises(AssertionError):
        assert_no_secret(secret, db)
    from urllib.parse import quote

    with pytest.raises(AssertionError):
        assert_no_secret(secret, {"logged": quote(secret, safe="")})  # URL-encoded forms count
    wal_db = tmp_path / "other" / "cache.db"
    wal_db.parent.mkdir()
    wal_db.write_bytes(b"SQLite format 3\x00")
    (tmp_path / "other" / "cache.db-wal").write_bytes(b"page " + secret.encode())
    with pytest.raises(AssertionError, match="cache.db-wal"):
        assert_no_secret(secret, wal_db)  # a database path also covers its WAL/journal side files


def test_fixture_helpers():
    assert module_fixture("shodan_internetdb", "1.1.1.1.json")["ip"] == "1.1.1.1"
    assert fixture("shodan_internetdb/8.8.8.8.json")["ip"] == "8.8.8.8"
    assert "Attention Required" in module_fixture("shodan_internetdb", "challenge_cloudflare_403.html")


def test_graph_fixture_wrapper(tmp_path):
    doc = {
        "schema": "v3lum.graph_fixture/1",
        "now": "2026-11-26T12:00:00Z",
        "options": {},
        "org_profile": {"domains": [{"name": "acme.example", "verification": "txt_verified"}]},
        "meta": {},
        "nodes": [{"key": "domain:acme.example", "depth": 0, "seed": True, "attributes": {"country": [{"value": "BR", "source": "t"}]}, "findings": []}],
        "edges": [],
        "results": [],
        "expect": {},
    }
    path = tmp_path / "positive_sample.json"
    path.write_text(json.dumps(doc))
    graph, results, rctx = graph_fixture(path)
    assert graph.get(Entity.make("domain", "acme.example")).attr("country") == "BR"
    assert results == [] and rctx.now.year == 2026
    assert rctx.org.is_verified_domain("acme.example")


# --------------------------------------------------------------------------------------
# conftest: network guard (meta-test), environment scrub, strict mode, markers
# --------------------------------------------------------------------------------------


def test_network_guard_refuses_non_loopback():
    with pytest.raises(RuntimeError, match="network disabled in tests"):
        socket.create_connection(("192.0.2.1", 80), timeout=0.1)
    with pytest.raises(RuntimeError, match="network disabled in tests"):
        socket.getaddrinfo("example.com", 443)
    with socket.socket() as s, pytest.raises(RuntimeError, match="network disabled in tests"):
        s.connect(("203.0.113.1", 80))
    with socket.socket() as s, pytest.raises(RuntimeError, match="network disabled in tests"):
        s.connect_ex(("198.51.100.1", 443))
    import requests

    with pytest.raises(RuntimeError, match="network disabled in tests"):
        requests.get("https://example.com/", timeout=0.2)


def test_network_guard_refuses_udp_sends_and_legacy_lookups():
    """Connectionless sends (UDP DNS as dnspython does it) and the legacy resolver calls are
    refused before anything leaves the machine."""
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
        with pytest.raises(RuntimeError, match="network disabled in tests"):
            s.sendto(b"\x00", ("192.0.2.53", 53))
        with pytest.raises(RuntimeError, match="network disabled in tests"):
            s.sendto(b"\x00", 0, ("192.0.2.53", 53))
        if hasattr(s, "sendmsg"):
            with pytest.raises(RuntimeError, match="network disabled in tests"):
                s.sendmsg([b"\x00"], [], 0, ("192.0.2.53", 53))
    for lookup, arg in ((socket.gethostbyname, "example.com"), (socket.gethostbyname_ex, "example.com"), (socket.gethostbyaddr, "192.0.2.1")):
        with pytest.raises(RuntimeError, match="network disabled in tests"):
            lookup(arg)
    with pytest.raises(RuntimeError, match="network disabled in tests"):
        socket.getnameinfo(("192.0.2.1", 80), 0)
    assert socket.gethostbyname("localhost").startswith("127.")


def test_network_guard_allows_udp_to_loopback():
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as server, socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as client:
        server.bind(("127.0.0.1", 0))
        server.settimeout(0.2)
        client.sendto(b"ping", server.getsockname())
        assert server.recvfrom(16)[0] == b"ping"


def test_network_guard_allows_loopback():
    server = socket.socket()
    server.bind(("127.0.0.1", 0))
    server.listen(1)
    try:
        port = server.getsockname()[1]
        with socket.create_connection(("127.0.0.1", port), timeout=0.2):
            pass
        assert socket.getaddrinfo("localhost", port)
    finally:
        server.close()
    assert conftest.is_loopback("::1") and conftest.is_loopback("::ffff:127.0.0.1") and conftest.is_loopback("LOCALHOST")
    assert not conftest.is_loopback("10.0.0.1") and not conftest.is_loopback("0.0.0.0")


def test_proxies_removed_so_a_local_proxy_cannot_tunnel_out():
    assert not any(os.environ.get(name) for name in conftest.PROXY_VARS)


def test_live_marker_needs_v3lum_live():
    item = type("Item", (), {"get_closest_marker": lambda self, name: object() if name == "live" else None})()
    assert conftest.live_allowed(item) is (os.environ.get("V3LUM_LIVE") == "1")
    plain = type("Item", (), {"get_closest_marker": lambda self, name: None})()
    assert conftest.live_allowed(plain) is False


def test_no_developer_key_leaks_into_tests():
    names = config.key_env_names()
    assert names <= conftest.key_env_names()
    leaked = sorted(n for n in os.environ if n in names or n.endswith(conftest.KEY_SUFFIXES) or (n.startswith("V3LUM_") and n not in ("V3LUM_HOME", "V3LUM_LIVE", "V3LUM_STRICT")))
    assert not leaked, f"key-like variables visible inside a test: {leaked}"


def test_scrub_covers_every_legacy_alias(monkeypatch):
    aliases = {alias for (_d, _u, envs) in config.KNOWN_KEYS.values() for alias in envs}
    assert {"GOOGLE_SAFEBROWSING_KEY", "PULSEDIVE_API_KEY", "GH_TOKEN"} <= aliases  # once leaking names
    extra = {"V3LUM_KEY_SHODAN", "SOMETHING_API_KEY", "X_TOKEN", "Y_AUTH_KEY", "V3LUM_DEPTH", "AWS_SECRET_ACCESS_KEY", "SOME_SECRET", "DB_PASSWORD"}
    for alias in aliases | extra:
        monkeypatch.setenv(alias, "dummy-value")
    monkeypatch.setenv("V3LUM_LIVE", "0")
    removed = set(conftest.scrub_env(monkeypatch))
    assert aliases <= removed and extra <= removed
    assert "V3LUM_HOME" not in removed and os.environ.get("V3LUM_HOME")
    assert "V3LUM_LIVE" not in removed


def test_registry_snapshot_restores_every_registry():
    """clean_registry (registry_snapshot) undoes modules, settings, providers, sanitizer schemas,
    datasets, runtime noise lists and load errors registered inside the block."""
    from v3lum.core import datasets, noise, sanitize
    from v3lum.core import module as modreg

    with conftest.registry_snapshot(), test_provider("t_snap_provider", hosts=("snap.example.test",)) as prov:
        sid = source_ids(prov)[0]
        define_module("t_snap_module", [T.DOMAIN], _noop, settings={"t_snap_setting": 1})
        sanitize.register_schema(sid, keep=["name"])
        datasets.register_dataset("t_snap_dataset", "https://snap.example.test/list.txt", licence="CC0-1.0", terms_class="open", provider=prov.id, source=sid)
        noise.register_list("t-snap-list", dataset="t_snap_dataset", fmt="lines")
        modreg._LOAD_ERRORS["t_snap_broken"] = "SyntaxError: synthetic"
        providers.register(provider_fragment("t_snap_leaked", hosts=("leak.example.test",)), origin="tests")
    assert "t_snap_module" not in modreg.REGISTRY and "t_snap_setting" not in config.SETTINGS_META
    assert sanitize.schema_for("t_snap_provider.default") is None
    assert "t_snap_dataset" not in datasets.DATASETS and "t-snap-list" not in noise._RUNTIME
    assert "t_snap_broken" not in modreg.load_errors()
    assert providers.registry().get("t_snap_leaked") is None


def test_registry_snapshot_restores_the_correlation_tables():
    """A pack rule superseding a legacy rule (RULE_REPLACED) and a data-rule compiler registered
    inside the block are undone too."""
    from v3lum.core import correlate

    correlate.load_rules()
    before = (set(correlate.RULES), dict(correlate.RULE_REPLACED), dict(correlate._COMPILERS), dict(correlate.RULE_ERRORS))
    with conftest.registry_snapshot():

        @correlate.rule("young_domain", "pack version of a legacy rule", criterion="test")
        def _pack_rule(graph, results):
            return []

        correlate.register_compiler("t_snap_kind", lambda doc: [])
        assert "young_domain" in correlate.RULE_REPLACED and "t_snap_kind" in correlate._COMPILERS
    after = (set(correlate.RULES), dict(correlate.RULE_REPLACED), dict(correlate._COMPILERS), dict(correlate.RULE_ERRORS))
    assert after == before
    assert correlate.RULES["young_domain"].legacy is True


def test_strict_mode_and_isolated_home(isolated_home):
    assert os.environ["V3LUM_STRICT"] == "1"
    assert os.environ["V3LUM_HOME"] == str(isolated_home)


def test_markers_registered(request):
    lines = request.config.getini("markers")
    for marker in ("live", "safety", "acceptance", "slow"):
        assert any(line.startswith(marker + ":") for line in lines)
