"""P376 cond 5-9 / A13: two-phase scheduling per entity and the contact guard.

PASSIVE runs of an entity are submitted first (case-DB sightings, then internal platforms, A12);
LIGHT/ACTIVE runs wait until every passive run of that entity is absorbed, then
``policy.contact_guard`` decides: a phishing-tagged entity gives BLOCKED 'hostile_host' (coverage
+ manual link) unless a non-corporate egress profile is configured.
"""

from __future__ import annotations

import threading
import time

import pytest

from tests.fakes import FakeHttp, define_module, make_runtime, test_provider
from v3lum.core import policy
from v3lum.core.context import ScanOptions
from v3lum.core.engine import Engine
from v3lum.core.entities import Entity
from v3lum.core.entities import EntityType as T
from v3lum.core.models import Opsec

SEED = Entity.make("domain", "example.org")
MANUAL = "https://archive.example.test/lookup?q={q}"


@pytest.fixture()
def registry(clean_registry):
    clean_registry.clear()  # only the synthetic modules of the test are candidates
    return clean_registry


def test_light_modules_run_after_every_passive_run_of_the_entity(registry):
    order: list[str] = []
    lock = threading.Lock()

    def mark(text: str) -> None:
        with lock:
            order.append(text)

    def passive(name: str, delay: float):
        def run(self, entity, ctx):
            mark(f"{name}:start")
            time.sleep(delay)  # still running while the LIGHT module would otherwise start
            mark(f"{name}:end")
            return self.result(entity)

        return run

    def light(self, entity, ctx):
        mark("light:start")
        return self.result(entity)

    define_module("t_p_fast", [T.DOMAIN], passive("fast", 0.0))
    define_module("t_p_slow", [T.DOMAIN], passive("slow", 0.1))
    define_module("t_light", [T.DOMAIN], light, opsec=Opsec.LIGHT)
    rt = make_runtime(FakeHttp())
    rt.events.subscribe(lambda kind, payload: mark(f"done:{payload['result'].module}") if kind == "module_done" else None)
    case = Engine(rt, ScanOptions(include={"t_p_fast", "t_p_slow", "t_light"}, mode=Opsec.LIGHT, threads=8)).investigate([SEED])
    assert {r.module for r in case.results} == {"t_p_fast", "t_p_slow", "t_light"}
    start = order.index("light:start")
    assert order.index("done:t_p_fast") < start and order.index("done:t_p_slow") < start  # absorbed before contact


def test_contact_guard_blocks_a_phishing_tagged_entity(registry, monkeypatch):
    ran: list[str] = []
    guarded: list[tuple[str, bool]] = []
    real = policy.contact_guard

    def spy(cls, entity, pctx, *, run):
        decision = real(cls, entity, pctx, run=run)
        guarded.append((cls.name, any(f.module == "t_ti" for f in pctx.graph.get(entity).findings)))
        return decision

    monkeypatch.setattr(policy, "contact_guard", spy)

    def ti(self, entity, ctx):
        res = self.result(entity)
        res.finding("listed as phishing", "high", tags=["phishing"], criterion="synthetic feed listing")
        return res

    def light(self, entity, ctx):
        ran.append(entity.key)
        return self.result(entity)

    define_module("t_ti", [T.DOMAIN], ti)
    define_module("t_fetch", [T.DOMAIN], light, opsec=Opsec.LIGHT, manual_link=MANUAL)
    case = Engine(make_runtime(FakeHttp()), ScanOptions(include={"t_ti", "t_fetch"}, mode=Opsec.LIGHT)).investigate([SEED])
    assert ran == [] and guarded == [("t_fetch", True)]  # decided after the passive finding was merged
    cov = case.coverage["t_fetch"]
    assert (cov["status"], cov["reason_code"]) == ("blocked", "hostile_host") and "non-corporate egress" in cov["reason"]
    assert case.skips["hostile_host"] == ["t_fetch"]
    manual = [link for link in case.links[SEED.key] if link.get("manual")]
    assert [(m["module"], m["note"]) for m in manual] == [("t_fetch", "automation skipped: hostile_host")]
    assert manual[0]["url"] == "https://archive.example.test/lookup?q=example.org"


def test_the_guard_yields_to_a_configured_light_egress_profile(registry):
    ran: list[str] = []

    def ti(self, entity, ctx):
        res = self.result(entity)
        res.finding("listed as phishing", "high", tags=["phishing"], criterion="synthetic feed listing")
        return res

    def light(self, entity, ctx):
        ran.append(entity.key)
        return self.result(entity)

    define_module("t_ti2", [T.DOMAIN], ti)
    define_module("t_fetch2", [T.DOMAIN], light, opsec=Opsec.LIGHT)
    rt = make_runtime(FakeHttp(), settings={"proxy_light": "socks5h://127.0.0.1:9050"})
    case = Engine(rt, ScanOptions(include={"t_ti2", "t_fetch2"}, mode=Opsec.LIGHT)).investigate([SEED])
    assert ran == [SEED.key]
    assert any("proxy_light" in n and "GUARD-01" in n for n in case.notes)  # the yield stays visible


def test_a_contact_module_without_passive_runs_is_released_at_once(registry):
    ran: list[str] = []
    define_module("t_only_light", [T.DOMAIN], lambda self, e, c: ran.append(e.key) or self.result(e), opsec=Opsec.LIGHT)
    case = Engine(make_runtime(FakeHttp()), ScanOptions(include={"t_only_light"}, mode=Opsec.LIGHT)).investigate([SEED])
    assert ran == [SEED.key] and case.results[0].module == "t_only_light"


def test_case_sightings_and_internal_platforms_run_first(registry):
    order: list[str] = []

    def rec(self, entity, ctx):
        order.append(self.name)
        return self.result(entity)

    with test_provider("t_misp_prov", hosts=("misp.corp.example",), internal=True) as prov:
        define_module("t_aaa_plain", [T.DOMAIN], rec)
        define_module(
            "t_internal_misp", [T.DOMAIN], rec, disclosure="internal", provider=prov.id, sources=tuple(sorted(s.id for s in prov.sources.values())),
            hosts=prov.hosts,
        )
        define_module("case_sightings", [T.DOMAIN], rec)
        Engine(make_runtime(FakeHttp()), ScanOptions(threads=1)).investigate([SEED])
    assert order == ["case_sightings", "t_internal_misp", "t_aaa_plain"]


# ------------------------------------------------------------------ redirect hops of target contact
def test_context_binds_the_run_scope_and_redirect_guard_to_target_contact(registry):
    """LIGHT/ACTIVE contexts hand the run facts, the scope and the redirect contact guard to ctx.http
    and share ctx.http (and the org profile) with ctx.net; passive contexts get no guard."""
    from v3lum.core.context import RunInfo

    light = define_module("t_bind_light", [T.DOMAIN], lambda self, e, c: self.result(e), opsec=Opsec.LIGHT)
    passive = define_module("t_bind_passive", [T.DOMAIN], lambda self, e, c: self.result(e))
    rt = make_runtime(FakeHttp())
    run = RunInfo(entity=SEED, is_seed=True)
    scope = object()  # the binding is passed through as given (the HTTP scope and connector check it)
    ctx = rt.context(light, ScanOptions(mode=Opsec.LIGHT, scope=scope), run=run)
    assert ctx.http.run is run and ctx.http.scope is scope and callable(ctx.http.contact_guard)
    assert ctx.net.http is ctx.http and ctx.net.run is run and ctx.net.scope is scope
    assert ctx.http.cancel_event is ctx.net.cancel_event is ctx.cancel_event is rt.cancel_event
    plain = rt.context(passive, ScanOptions(scope=scope), run=run)
    assert plain.http.contact_guard is None and plain.http.run is run and plain.http.scope is scope


def test_redirect_guard_fails_closed_and_checks_recipient_tokens(registry, monkeypatch):
    from v3lum.core.context import RunInfo, redirect_guard

    light = define_module("t_hop_light", [T.URL], lambda self, e, c: self.result(e), opsec=Opsec.LIGHT)
    rt = make_runtime(FakeHttp())
    run = RunInfo(entity=Entity.make("url", "https://start.example.net/"), is_seed=True)
    opts = ScanOptions(mode=Opsec.LIGHT)
    assert redirect_guard(rt, light, opts, run, "https://next.example.net/page").allowed  # no hostile signal
    token = redirect_guard(rt, light, opts, run, "https://next.example.net/r?t=Zx81kQpLr04MnTyV9wBc")
    assert (token.allowed, token.reason_code) == (False, "policy")  # GUARD-02: per-recipient token
    bad = redirect_guard(rt, light, opts, run, "javascript:alert(1)")
    assert (bad.allowed, bad.reason_code) == (False, "hostile_host")

    def broken(*args, **kwargs):
        raise RuntimeError("guard bug")

    monkeypatch.setattr(policy, "contact_guard", broken)
    failed = redirect_guard(rt, light, opts, run, "https://next.example.net/page")
    assert (failed.allowed, failed.status, failed.reason_code) == (False, "blocked", "hostile_host")
