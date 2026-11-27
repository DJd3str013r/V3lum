"""Engine behaviour with synthetic modules (no network).

Synthetic modules are declared with ``tests.fakes.define_module`` (contract v2 metadata; offline
unless they use the synthetic provider of ``test_provider``) inside the ``clean_registry`` fixture.
Findings of severity >= low carry a criterion and attribute names are vocabulary names (test-only
names go through ``allow_vocab``), because tests run in strict contract mode.

Engine v2 (WP08): every selection goes through ``policy.decide``; ``tests/test_engine_*.py`` cover
deadlines, expansion, noise, coverage, two-phase scheduling, TLP and suppression.
"""

from __future__ import annotations

import hashlib
import json
import os
import stat
from pathlib import Path

import pytest

from tests.fakes import FakeHttp, allow_vocab, define_module, make_runtime, source_ids, test_provider
from v3lum.core import policy
from v3lum.core.context import ScanOptions
from v3lum.core.engine import CaseResult, Engine
from v3lum.core.entities import Entity
from v3lum.core.entities import EntityType as T
from v3lum.core.evidence import EvidenceStore, evidence_name
from v3lum.core.http import RateLimited
from v3lum.core.models import ModuleResult, Opsec, Status

TEST_ATTRIBUTES = ("ok", "ran", "x")  # test-only attribute names (strict mode)


@pytest.fixture()
def registry(clean_registry):
    with allow_vocab(attributes=TEST_ATTRIBUTES):
        yield clean_registry


@pytest.fixture()
def isolated(registry):
    """Only the synthetic modules of the test are candidates (the registry is restored afterwards)."""
    registry.clear()
    return registry


def define(registry, name, accepts, run, **attrs):
    return define_module(name, accepts, run, **attrs)


def scan(seeds, include, *, http=None, rt=None, **opts):
    rt = rt or make_runtime(http or FakeHttp())
    options = ScanOptions(include=set(include), **opts)
    return Engine(rt, options).investigate([Entity.make(t, v) for t, v in seeds])


def test_findings_attributes_and_pivots(registry):
    def run(self, entity, ctx):
        res = self.result(entity)
        res.attr("country", "BR")
        res.finding("bad thing", "high", tags=["malicious"], criterion="synthetic test criterion")
        res.pivot(T.IPV4, "203.0.113.10", "resolves_to")
        return res

    define(registry, "t_dom", [T.DOMAIN], run)
    case = scan([("domain", "example.org")], ["t_dom"], depth=0)
    node = case.graph.get(Entity.make("domain", "example.org"))
    assert node.attr("country") == "BR"
    assert [f.title for f in node.findings] == ["bad thing"]
    assert case.graph.get(Entity.make("ipv4", "203.0.113.10")) is not None
    assert not case.graph.get(Entity.make("ipv4", "203.0.113.10")).investigated  # depth 0
    d = case.to_dict()
    assert d["summary"]["findings"] == 1 and d["edges"][0]["relation"] == "resolves_to"


def test_depth_and_expand_flags(registry):
    calls = []

    def dom(self, entity, ctx):
        calls.append(entity.key)
        res = self.result(entity)
        res.pivot(T.IPV4, "45.33.32.1", "resolves_to")
        res.pivot(T.IPV4, "45.33.32.2", "resolves_to", expand=False)
        res.pivot(T.PERSON, "Jane Roe", "registrant")  # never auto-expanded
        return res

    def ip(self, entity, ctx):
        calls.append(entity.key)
        res = self.result(entity)
        res.pivot(T.DOMAIN, "deeper.example.net", "hosted_domain")
        return res

    define(registry, "t_dom2", [T.DOMAIN], dom)
    define(registry, "t_ip2", [T.IPV4], ip)
    case = scan([("domain", "example.org")], ["t_dom2", "t_ip2"], depth=1)
    assert "ipv4:45.33.32.1" in calls
    assert "ipv4:45.33.32.2" not in calls
    assert "domain:deeper.example.net" not in calls  # depth 2 not allowed
    assert case.graph.get(Entity.make("domain", "deeper.example.net")) is not None
    case2 = scan([("domain", "example.org")], ["t_dom2", "t_ip2"], depth=2)
    assert case2.graph.get(Entity.make("domain", "deeper.example.net")).investigated


def test_noise_not_expanded(registry):
    seen = []

    def dom(self, entity, ctx):
        seen.append(entity.value)
        res = self.result(entity)
        res.pivot(T.DOMAIN, "gmail.com", "related")
        res.pivot(T.IPV4, "8.8.8.8", "resolves_to")
        return res

    define(registry, "t_noise", [T.DOMAIN, T.IPV4], dom)
    case = scan([("domain", "example.org")], ["t_noise"], depth=3)
    assert seen == ["example.org"]
    assert case.graph.get(Entity.make("domain", "gmail.com")).noise


def test_per_parent_cap(registry):
    def dom(self, entity, ctx):
        res = self.result(entity)
        if entity.value == "example.org":
            for i in range(30):
                res.pivot(T.DOMAIN, f"s{i}.example.org", "subdomain")
        return res

    define(registry, "t_cap", [T.DOMAIN], dom)
    case = scan([("domain", "example.org")], ["t_cap"], depth=1)
    investigated = [n for n in case.graph.nodes.values() if n.investigated]
    assert len(investigated) == 1 + 12  # EXPAND_CAP[DOMAIN]


def test_errors_are_isolated(registry):
    def boom(self, entity, ctx):
        raise RuntimeError("module bug")

    def limited(self, entity, ctx):
        raise RateLimited("slow down", 429)

    def fine(self, entity, ctx):
        res = self.result(entity)
        res.attr("ok", True)
        return res

    define(registry, "t_boom", [T.DOMAIN], boom)
    define(registry, "t_limited", [T.DOMAIN], limited)
    define(registry, "t_fine", [T.DOMAIN], fine)
    case = scan([("domain", "example.org")], ["t_boom", "t_limited", "t_fine"])
    by = {r.module: r for r in case.results}
    assert by["t_boom"].status is Status.ERROR and "module bug" in by["t_boom"].error
    assert by["t_limited"].status is Status.RATE_LIMITED
    assert by["t_fine"].status is Status.OK
    assert case.coverage["t_boom"]["status"] == "error"


def _scope_file(tmp_path: Path, ref: str, domains: list[str]) -> Path:
    path = tmp_path / "scope.json"
    path.write_text(json.dumps({
        "authorization_ref": ref,
        "owner": "Example Org security team",
        "contacts": ["soc@example.org"],
        "ticket": "SEC-1",
        "window_start": "2026-11-01T00:00:00Z",
        "window_end": "2026-12-31T23:59:59Z",
        "targets": {"domains": domains, "cidrs": [], "url_prefixes": []},
        "exclusions": {"domains": [], "cidrs": [], "url_prefixes": []},
    }))
    return path


def test_keys_and_opsec_gating(registry, tmp_path):
    """Keys (POL-12) and opsec (POL-09) gates; an ACTIVE run needs a real authorization reference and
    a scope file covering the seed (A7, POL-10) - `authorized=True` alone no longer unlocks it."""
    scope_mod = pytest.importorskip("v3lum.core.scope")

    def run(self, entity, ctx):
        res = self.result(entity)
        res.attr("ran", True)
        return res

    with test_provider("t_service_provider", keys=("t_service",)) as prov:
        define(
            registry, "t_keyed", [T.DOMAIN], run,
            requires_keys=("t_service",), disclosure="third_party", provider=prov.id, sources=source_ids(prov),
            hosts=prov.hosts, access_model="free_auth_limited",
        )
        define(registry, "t_active", [T.DOMAIN], run, opsec=Opsec.ACTIVE)
        case = scan([("domain", "example.org")], ["t_keyed", "t_active"])
        assert case.coverage["t_keyed"]["status"] == "needs_key"
        assert case.coverage["t_active"]["status"] == "skipped" and case.coverage["t_active"]["reason_code"] == "opsec"
        assert not case.results

        rt = make_runtime(FakeHttp(), keys={"t_service": "secret-value-1"})
        no_ref = Engine(rt, ScanOptions(include={"t_keyed", "t_active"}, mode=Opsec.ACTIVE, authorized=True)).investigate([Entity.make("domain", "example.org")])
        assert {r.module for r in no_ref.results} == {"t_keyed"}
        assert no_ref.coverage["t_active"]["reason_code"] == "authorization"

        scope = scope_mod.Scope.load(_scope_file(tmp_path, "PENTEST-2026-11", ["example.org"]))
        opts = ScanOptions(include={"t_keyed", "t_active"}, mode=Opsec.ACTIVE, authorized=True, authorization_ref="PENTEST-2026-11", scope=scope)
        case2 = Engine(make_runtime(FakeHttp(), keys={"t_service": "secret-value-1"}), opts).investigate([Entity.make("domain", "example.org")])
        assert {r.module for r in case2.results} == {"t_keyed", "t_active"}
        assert case2.to_dict()["tlp"] == "amber"  # ACTIVE cases are at least AMBER


def test_evidence_saved_with_sha256(registry):
    def run(self, entity, ctx):
        res = self.result(entity)
        res.attr("x", 1)
        res.raw = {"answer": 42}
        return res

    define(registry, "t_ev", [T.DOMAIN], run)
    case = scan([("domain", "example.org")], ["t_ev"])
    r = case.results[0]
    blob = Path(r.evidence).read_bytes()
    assert hashlib.sha256(blob).hexdigest() == r.evidence_sha256
    assert json.loads(blob)["data"] == {"answer": 42}


def test_seeds_linked_correlation(registry):
    def run(self, entity, ctx):
        res = self.result(entity)
        res.pivot(T.IPV4, "45.33.40.77", "resolves_to")
        return res

    define(registry, "t_link", [T.DOMAIN], run)
    case = scan([("domain", "a.example"), ("domain", "b.example")], ["t_link"], depth=0)
    rules = {c.rule for c in case.correlations}
    assert "seeds_linked" in rules
    assert "shared_infrastructure" in rules


def test_budget(registry):
    def run(self, entity, ctx):
        res = self.result(entity)
        for i in range(10):
            res.pivot(T.IPV4, f"45.33.32.{i + 1}", "resolves_to")
        return res

    define(registry, "t_budget", [T.DOMAIN, T.IPV4], run)
    case = scan([("domain", "example.org")], ["t_budget"], depth=2, max_entities=4)
    assert sum(1 for n in case.graph.nodes.values() if n.investigated) == 4
    assert any("budget" in n for n in case.notes)


@pytest.mark.parametrize(("families", "severity"), [(("t_family_a", "t_family_b"), "high"), (("t_shared_upstream", "t_shared_upstream"), "medium")])
def test_multi_source_malicious_and_risk(registry, families, severity):
    """CR27 semantics (P171, WP23): the legacy rule gave CRITICAL as soon as two *module names*
    flagged an entity. The pack rule counts *upstream families* from the provider registry
    (Finding.source -> upstream_family): two synthetic modules whose sources belong to different
    families give HIGH; two modules relaying the same upstream count once and give MEDIUM."""

    def flag(self, entity, ctx):
        res = self.result(entity)
        res.finding("flagged", "high", tags=["malicious"], confidence=0.9, criterion="synthetic source verdict", source=self.sources[0])
        return res

    fam_a, fam_b = families
    with test_provider("t_feed_one", hosts=("one.example.test",), sources={"feed": {"upstream_family": fam_a}}) as one, \
         test_provider("t_feed_two", hosts=("two.example.test",), sources={"feed": {"upstream_family": fam_b}}) as two:
        for name, prov in (("t_src1", one), ("t_src2", two)):
            define(registry, name, [T.DOMAIN], flag, disclosure="third_party", provider=prov.id, sources=source_ids(prov),
                   hosts=prov.hosts, access_model="free_noauth_unlimited")
        case = scan([("domain", "evil.example")], ["t_src1", "t_src2"])
    [consensus] = [c for c in case.correlations if c.rule == "multi_source_malicious"]
    assert consensus.severity.label == severity
    assert consensus.criterion.startswith(f"{1 if fam_a == fam_b else 2} independent upstream famil")
    assert consensus.entity_keys() == ["domain:evil.example"]
    assert case.risk["level"] in ("high", "critical")  # two HIGH findings on the seed, whatever the consensus


def test_pivot_cap_per_module(registry):
    def run(self, entity, ctx):
        res = self.result(entity)
        for i in range(20):
            res.pivot(T.IPV4, f"192.0.2.{i + 1}", "resolves_to", expand=False)
        return res

    define(registry, "t_maxpiv", [T.DOMAIN], run, max_pivots=5)
    case = scan([("domain", "example.org")], ["t_maxpiv"])
    assert len(case.results[0].pivots) == 5 and "dropped" in case.results[0].error


def test_blocked_status_and_daily_quota(registry):
    from v3lum.core.http import Blocked

    def walled(self, entity, ctx):
        raise Blocked("site: anti-bot/WAF page", 403)

    def counted(self, entity, ctx):
        ctx.http.get("https://api.example.test/ping")  # one real (fake-transport) network request
        res = self.result(entity)
        res.attr("ok", True)
        return res

    with test_provider() as prov:
        define(registry, "t_walled", [T.DOMAIN], walled)
        define(
            registry, "t_quota", [T.DOMAIN], counted,
            daily_quota=1, disclosure="third_party", provider=prov.id, sources=source_ids(prov), hosts=prov.hosts,
            access_model="free_noauth_limited",
        )
        http = FakeHttp().add("GET", "https://api.example.test/ping", json={"pong": True})
        case = scan([("domain", "example.org")], ["t_walled", "t_quota"], http=http)
        by = {r.module: r for r in case.results}
        assert by["t_walled"].status is Status.BLOCKED
        assert by["t_quota"].status is Status.OK
        # second scan: quota (1/day) already used -> not scheduled, reported as quota (P328 cond 1)
        case2 = scan([("domain", "example.net")], ["t_quota"], http=http)
        assert not case2.results
        assert case2.coverage["t_quota"]["status"] == "quota"


# ------------------------------------------------------------------ engine v2 (WP08)
def test_every_selection_goes_through_policy_decide(isolated, monkeypatch):
    """Acceptance (WP08): every module selection - seeds, pivots, opt-in modules, `v3lum run` -
    is a policy.decide call; what the gate refuses never runs."""
    calls: list[tuple[str, str, bool, bool, int]] = []
    real = policy.decide

    def spy(cls, entity, pctx, *, run):
        decision = real(cls, entity, pctx, run=run)
        calls.append((cls.name, entity.key, decision.allowed, run.is_seed, run.depth))
        return decision

    monkeypatch.setattr(policy, "decide", spy)
    ran: list[tuple[str, str]] = []

    def dom(self, entity, ctx):
        ran.append((self.name, entity.key))
        res = self.result(entity)
        res.pivot(T.IPV4, "45.33.32.1", "resolves_to")
        return res

    def ip(self, entity, ctx):
        ran.append((self.name, entity.key))
        return self.result(entity)

    define(isolated, "t_spy_dom", [T.DOMAIN], dom)
    define(isolated, "t_spy_ip", [T.IPV4], ip)
    define(isolated, "t_spy_optin", [T.DOMAIN], dom, default_enabled=False)
    case = scan([("domain", "example.org")], [], depth=1)
    decided = {(name, key) for name, key, *_ in calls}
    assert decided == {("t_spy_dom", "domain:example.org"), ("t_spy_optin", "domain:example.org"), ("t_spy_ip", "ipv4:45.33.32.1")}
    assert set(ran) == {(name, key) for name, key, allowed, *_ in calls if allowed}
    assert ("t_spy_optin", "domain:example.org") not in ran and case.skips["not_default"] == ["t_spy_optin"]
    seed_row = next(c for c in calls if c[0] == "t_spy_dom")
    pivot_row = next(c for c in calls if c[0] == "t_spy_ip")
    assert seed_row[3:] == (True, 0) and pivot_row[3:] == (False, 1)
    # the `v3lum run` path decides through the same gate
    calls.clear()
    eng = Engine(make_runtime(FakeHttp()), ScanOptions())
    decision = eng.decide_single(isolated["t_spy_optin"], Entity.make("domain", "example.org"))
    assert decision.allowed and calls == [("t_spy_optin", "domain:example.org", True, True, 0)]


def test_select_returns_decisions(isolated):
    define(isolated, "t_sel_ok", [T.DOMAIN], lambda self, e, c: self.result(e))
    define(isolated, "t_sel_optin", [T.DOMAIN], lambda self, e, c: self.result(e), default_enabled=False)
    eng = Engine(make_runtime(FakeHttp()), ScanOptions())
    runnable, blocked = eng.select(Entity.make("domain", "example.org"))
    assert [(c.name, d.allowed) for c, d in runnable] == [("t_sel_ok", True)]
    assert [(c.name, d.status, d.reason_code, d.rule_id) for c, d in blocked] == [("t_sel_optin", Status.SKIPPED, "not_default", "POL-01")]
    rows = {r["module"]: r for r in eng.plan(Entity.make("domain", "example.org"))}
    assert rows["t_sel_ok"]["ready"] and rows["t_sel_optin"]["reason_code"] == "not_default" and not rows["t_sel_optin"]["ready"]
    deep = Engine(make_runtime(FakeHttp()), ScanOptions(include_disabled=True))  # --all-modules = --preset deep
    assert deep.options.preset == "deep"
    assert {c.name for c, _d in deep.select(Entity.make("domain", "example.org"))[0]} == {"t_sel_ok", "t_sel_optin"}


def test_case_dict_v2_shape(registry):
    def run(self, entity, ctx):
        res = self.result(entity)
        res.attr("country", "BR")
        return res

    define(registry, "t_shape", [T.DOMAIN], run)
    case = scan([("domain", "example.org")], ["t_shape"])
    d = case.to_dict()
    assert d["schema"] == "v3lum.case/2"
    for key in ("tlp", "partial", "coverage", "execution", "answered", "skips", "pending_personal", "meta",
                "org_profile_sha256", "licence_profile", "deferred", "licence_used", "options"):
        assert key in d, key
    assert d["tlp"] == "amber" and d["partial"] == {} and d["licence_profile"] in ("corporate", "research")
    row = d["modules"][0]
    for key in ("hosts", "datasets", "reason_code", "partial"):
        assert key in row
    assert d["options"]["confirmed_urls"] == [] and d["options"]["subject_roles"] == {}
    assert "cache_keys" not in d
    json.dumps(d)


def test_options_record_confirmed_urls_by_hash_only():
    url = "https://phish.example.test/login?u=someone@example.org"
    opts = ScanOptions(confirmed_urls={url}, subject_roles={"email:someone@example.org": "incident_victim"})
    d = opts.to_dict()
    assert d["confirmed_urls"] == [hashlib.sha256(url.encode()).hexdigest()] and url not in json.dumps(d["confirmed_urls"])
    assert d["subject_roles"] == {"email:someone@example.org": "incident_victim"}


def test_evidence_store_names_modes_and_requests(registry, tmp_path):
    """EvidenceStore(case_dir).save(res, requests=...) -> (path, sha256): value-free name with the
    keyed HMAC, 0600 file in 0700 directories, redacted request records."""
    entity = Entity.make("email", "alice.person@corp.example")
    res = ModuleResult("t_store_mod", entity)
    res.raw = {"seen": True}
    store = EvidenceStore(tmp_path / "case-1")
    old = os.umask(0o022)
    try:
        path, digest = store.save(res, requests=[{"method": "GET", "url": "https://api.example.test/v1?q=x", "status": 200, "host": "api.example.test"}])
    finally:
        os.umask(old)
    blob = Path(path).read_bytes()
    assert hashlib.sha256(blob).hexdigest() == digest
    assert "alice" not in Path(path).name and Path(path).name == evidence_name("t_store_mod", entity, digest)
    assert Path(path).name.startswith("t_store_mod__email__") and Path(path).name.endswith(f"__{digest[:10]}.json")
    assert stat.S_IMODE(os.stat(path).st_mode) == 0o600
    assert stat.S_IMODE(os.stat(tmp_path / "case-1").st_mode) == 0o700 and stat.S_IMODE(os.stat(Path(path).parent).st_mode) == 0o700
    data = json.loads(blob)
    assert data["requests"][0]["url"] == "https://api.example.test/v1?q=x" and data["data"] == {"seen": True}


def test_evidence_of_a_scan_records_the_request_log(registry):
    def run(self, entity, ctx):
        ctx.http.get("https://api.example.test/ping")
        res = self.result(entity)
        res.attr("ok", True)
        res.raw = {"pong": True}
        return res

    with test_provider() as prov:
        define(registry, "t_ev_req", [T.DOMAIN], run, disclosure="third_party", provider=prov.id, sources=source_ids(prov), hosts=prov.hosts, access_model="free_noauth_unlimited")
        http = FakeHttp().add("GET", "https://api.example.test/ping", json={"pong": True})
        case = scan([("domain", "example.org")], ["t_ev_req"], http=http)
    data = json.loads(Path(case.results[0].evidence).read_text(encoding="utf-8"))
    assert [r["host"] for r in data["requests"]] == ["api.example.test"]


def test_ownership_tags_and_findings(registry):
    """A11/P378 cond 10: with an org profile every asset node is own_asset/third_party with its
    criticality and tag; findings copy their node's ownership; the case records the profile hash."""
    org = {"org": {"name": "Example Org"}, "domains": [{"name": "example.org", "verification": "txt_verified", "criticality": "high"}]}

    def run(self, entity, ctx):
        res = self.result(entity)
        res.finding("exposed thing", "low", criterion="synthetic criterion")
        if entity.value == "example.org":
            res.pivot(T.DOMAIN, "evil.example", "related", expand=False)
            res.pivot(T.SHA256, "275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f", "related", expand=False)
        return res

    define(registry, "t_own", [T.DOMAIN], run)
    rt = make_runtime(FakeHttp(), org_profile=org)
    case = scan([("domain", "example.org")], ["t_own"], rt=rt)
    own = case.graph.get(Entity.make("domain", "example.org"))
    other = case.graph.get(Entity.make("domain", "evil.example"))
    hashed = case.graph.get(Entity.make("sha256", "275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f"))
    assert (own.ownership, own.criticality) == ("own_asset", "high") and own.tagged("own_asset")
    assert other.ownership == "third_party" and other.tagged("third_party") and other.criticality == ""
    assert hashed.ownership == ""  # not an asset type
    assert [f.ownership for f in own.findings] == ["own_asset"]
    assert case.to_dict()["org_profile_sha256"] == getattr(rt.org, "sha256", "")
    no_org = scan([("domain", "example.org")], ["t_own"])
    assert no_org.graph.get(Entity.make("domain", "example.org")).ownership == "" and no_org.org_profile_sha256 == ""


def test_case_hooks_order(registry):
    seen: list[tuple[str, bool, int]] = []

    class Hook:
        def on_case_start(self, case):
            seen.append(("start", bool(case.results), len(case.correlations)))

        def on_before_finish(self, case):
            seen.append(("before_finish", bool(case.results), len(case.correlations)))

        def on_case_end(self, case):
            seen.append(("end", bool(case.results), len(case.correlations)))

    def bad(self, entity, ctx):
        res = self.result(entity)
        res.finding("flagged", "high", tags=["malicious"], confidence=0.9, criterion="synthetic source verdict")
        return res

    define(registry, "t_hook1", [T.DOMAIN], bad)
    define(registry, "t_hook2", [T.DOMAIN], bad)
    rt = make_runtime(FakeHttp())
    rt.case_hooks.append(Hook())
    scan([("domain", "evil.example")], ["t_hook1", "t_hook2"], rt=rt)
    assert [s[0] for s in seen] == ["start", "before_finish", "end"]
    assert seen[0][1:] == (False, 0) and seen[1] == ("before_finish", True, 0) and seen[2][2] >= 1


def test_cache_keys_are_collected_for_the_case(registry):
    def run(self, entity, ctx):
        ctx.http.get("https://api.example.test/ping")
        res = self.result(entity)
        res.attr("ok", True)
        return res

    with test_provider() as prov:
        define(registry, "t_cache_keys", [T.DOMAIN], run, disclosure="third_party", provider=prov.id, sources=source_ids(prov), hosts=prov.hosts, access_model="free_noauth_unlimited")
        http = FakeHttp().add("GET", "https://api.example.test/ping", json={"pong": True})
        rt = make_runtime(http, cache=True)
        case = scan([("domain", "example.org")], ["t_cache_keys"], rt=rt)
    assert case.cache_keys and rt.cache_key_collector is None
    assert isinstance(case, CaseResult) and "cache_keys" not in case.to_dict()


def test_runs_are_recorded_in_the_module_health_state(registry):
    """Every executed run reaches health.record_run (A3 demotion data); single runs too."""
    from v3lum.core.health import HealthState

    define(registry, "t_health_mod", [T.DOMAIN], lambda self, e, c: self.result(e))
    scan([("domain", "example.org")], ["t_health_mod"])
    Engine(make_runtime(FakeHttp()), ScanOptions()).run_module(registry["t_health_mod"], Entity.make("domain", "example.net"))
    assert HealthState.load().stats("t_health_mod")["runs"] == 2


def test_dataset_errors_keep_their_canonical_outcome(registry):
    """A dataset fetch refused by a challenge page or a quota is could-not-verify with its own code,
    never a module bug (no traceback); DatasetUnavailable stays UNAVAILABLE 'dataset'."""
    from v3lum.core.datasets import DatasetError, DatasetUnavailable

    def raising(exc):
        def run(self, entity, ctx):
            raise exc

        return run

    define(registry, "t_ds_challenge", [T.DOMAIN], raising(DatasetError("feed answered a challenge page", reason_code="challenge")))
    define(registry, "t_ds_quota", [T.DOMAIN], raising(DatasetError("download quota used", reason_code="quota")))
    define(registry, "t_ds_odd", [T.DOMAIN], raising(DatasetError("odd", reason_code="not-a-code")))
    define(registry, "t_ds_missing", [T.DOMAIN], raising(DatasetUnavailable("big_list")))
    case = scan([("domain", "example.org")], ["t_ds_challenge", "t_ds_quota", "t_ds_odd", "t_ds_missing"])
    by = {r.module: (r.status, r.reason_code, r.raw) for r in case.results}
    assert by["t_ds_challenge"] == (Status.BLOCKED, "challenge", None)
    assert by["t_ds_quota"] == (Status.QUOTA, "quota", None)
    assert by["t_ds_odd"] == (Status.ERROR, "error", None)
    assert by["t_ds_missing"] == (Status.UNAVAILABLE, "dataset", None)


def test_decide_single_runs_the_contact_guard_for_target_contact(isolated):
    """`v3lum run` goes through decide_single: policy.decide, then the contact guard for LIGHT/ACTIVE
    (here GUARD-02: a URL carrying a per-recipient token needs a per-URL confirmation, A7 BR15)."""
    url = "https://track.example.net/click?t=Zx81kQpLr04MnTyV9wBc"
    define(isolated, "t_single_light", [T.URL], lambda self, e, c: self.result(e), opsec=Opsec.LIGHT)
    cls, entity = isolated["t_single_light"], Entity.make("url", url)
    refused = Engine(make_runtime(FakeHttp()), ScanOptions(mode=Opsec.LIGHT)).decide_single(cls, entity)
    assert (refused.allowed, refused.status, refused.reason_code, refused.rule_id) == (False, Status.SKIPPED, "policy", "GUARD-02")
    confirmed = Engine(make_runtime(FakeHttp()), ScanOptions(mode=Opsec.LIGHT, confirmed_urls={url})).decide_single(cls, entity)
    assert confirmed.allowed
    passive = Engine(make_runtime(FakeHttp()), ScanOptions()).decide_single(cls, entity)
    assert not passive.allowed and passive.reason_code == "opsec"  # never escalated by `v3lum run`


def test_run_info_priority_and_internal_seeds(isolated):
    """RunInfo per (module, entity): priority seed/pivot/pivot2 by depth; internal_seed only for
    analyst-typed seeds naming private space (never inherited by pivots); unconfirmed seeds are not
    analyst-typed."""
    seen: dict[str, tuple] = {}

    def run(self, entity, ctx):
        seen[entity.key] = (ctx.run.priority, ctx.run.internal_seed, ctx.is_seed, ctx.depth)
        res = self.result(entity)
        if entity.key == "ipv4:10.0.0.5":
            res.pivot(T.IPV4, "45.33.32.1", "related")
        elif entity.key == "ipv4:45.33.32.1":
            res.pivot(T.IPV4, "45.33.32.2", "related")
        return res

    define(isolated, "t_runinfo", [T.IPV4, T.DOMAIN], run)
    rt = make_runtime(FakeHttp())
    seeds = [Entity.make("ipv4", "10.0.0.5"), Entity.make("domain", "fileserver.corp.internal"), Entity.make("domain", "example.org")]
    opts = ScanOptions(include={"t_runinfo"}, depth=3, unconfirmed_seeds={"domain:example.org"})
    Engine(rt, opts).investigate(seeds)
    assert seen["ipv4:10.0.0.5"] == ("seed", True, True, 0)
    assert seen["domain:fileserver.corp.internal"] == ("seed", True, True, 0)
    assert seen["domain:example.org"] == ("seed", False, False, 0)  # unconfirmed: not analyst-typed
    assert seen["ipv4:45.33.32.1"] == ("pivot", False, False, 1)  # pivots never inherit internal_seed
    assert seen["ipv4:45.33.32.2"] == ("pivot2", False, False, 2)


def test_contract_additions_names_resolve():
    """Every backticked v3lum.* name of docs/contract_additions/WP08.md exists (module attribute,
    class attribute, dataclass field or Runtime instance attribute)."""
    import dataclasses
    import importlib
    import re

    doc = (Path(__file__).resolve().parent.parent / "docs" / "contract_additions" / "WP08.md").read_text(encoding="utf-8")
    names = sorted(set(re.findall(r"`(v3lum(?:\.[A-Za-z_][A-Za-z0-9_]*)+)`", doc)))
    runtime = make_runtime(FakeHttp())
    missing = []
    for dotted in names:
        parts = dotted.split(".")
        obj = None
        for cut in range(len(parts), 0, -1):
            try:
                obj = importlib.import_module(".".join(parts[:cut]))
            except ImportError:
                continue
            rest = parts[cut:]
            break
        for i, attr in enumerate(rest):
            if hasattr(obj, attr):
                obj = getattr(obj, attr)
            elif dataclasses.is_dataclass(obj) and attr in {f.name for f in dataclasses.fields(obj)} and i == len(rest) - 1:
                obj = True
            elif isinstance(obj, type) and isinstance(runtime, obj) and hasattr(runtime, attr):
                obj = getattr(runtime, attr)
            else:
                missing.append(dotted)
                break
    assert len(names) > 30 and not missing, missing


def test_a_missing_external_tool_is_unavailable_package(registry):
    tools = pytest.importorskip("v3lum.core.tools")

    def run(self, entity, ctx):
        raise tools.ToolUnavailable("nuclei is not on PATH: install it from the official release")

    define(registry, "t_tool_missing", [T.DOMAIN], run)
    res = Engine(make_runtime(FakeHttp()), ScanOptions()).run_module(registry["t_tool_missing"], Entity.make("domain", "example.org"))
    assert (res.status, res.reason_code, res.raw) == (Status.UNAVAILABLE, "package", None)


# ------------------------------------------------------------------ review fixes (WP08 review)
def test_each_investigation_starts_a_new_quota_run(registry):
    """P334: the quota book's in-memory state (backoffs 'for the rest of this run', token buckets,
    per-run deferral counts, run signals) never leaks from one scan of a runtime into the next, nor
    into the next case's quota lines."""
    define(registry, "t_qrun", [T.DOMAIN], lambda self, e, c: self.result(e))
    rt = make_runtime(FakeHttp())
    rt.quota.defer("an-earlier-case", "t_qrun", "domain:example.org", "quota used")  # one deferral of a previous run
    assert any("t_qrun" in line for line in rt.quota.quota_lines())
    case = scan([("domain", "example.org")], ["t_qrun"], rt=rt)
    assert not any("t_qrun" in line for line in case.meta["quota_lines"])

    calls: list[str] = []

    class Book:
        def reset_run(self) -> None:
            calls.append("reset_run")

        def quota_lines(self) -> list[str]:
            return []

    rt.quota = Book()
    scan([("domain", "example.org")], ["t_qrun"], rt=rt)
    scan([("domain", "example.net")], ["t_qrun"], rt=rt)
    assert calls == ["reset_run", "reset_run"]


def test_case_meta_keeps_only_json_data(registry):
    """runtime.meta carries live objects (the policy gate's sightings_lookup callable): they never
    reach the stored case, which must serialise as plain JSON."""
    define(registry, "t_meta", [T.DOMAIN], lambda self, e, c: self.result(e))
    rt = make_runtime(FakeHttp())
    rt.meta["sightings_lookup"] = lambda entity, **kw: None
    rt.meta["egress"] = {"profile": "default", "ip": ""}
    rt.meta["probe"] = object()
    case = scan([("domain", "example.org")], ["t_meta"], rt=rt)
    assert "sightings_lookup" not in case.meta and "probe" not in case.meta
    assert case.meta["egress"] == {"profile": "default", "ip": ""} and "quota_lines" in case.meta
    json.dumps(case.to_dict())  # no default=: the case is JSON data
    assert callable(rt.meta["sightings_lookup"])  # the runtime keeps its plumbing


def test_case_tlp_is_known_when_the_case_starts(registry):
    seen: list[str] = []

    class Hook:
        def on_case_start(self, case):
            seen.append(case.tlp)

    define(registry, "t_tlp_start", [T.DOMAIN], lambda self, e, c: self.result(e))
    rt = make_runtime(FakeHttp())
    rt.case_hooks.append(Hook())
    scan([("domain", "a.example"), ("domain", "b.example")], ["t_tlp_start"], rt=rt, tlp="green", seed_tlp={"domain:b.example": "amber+strict"})
    scan([("domain", "c.example")], ["t_tlp_start"], rt=rt, tlp="clear", mode=Opsec.LIGHT)
    assert seen == ["amber+strict", "amber"]  # the highest seed; LIGHT/ACTIVE cases at least AMBER


def test_a_finding_about_another_entity_gets_a_proper_node(registry):
    """A finding on an entity the module did not pivot to: the node sits one level below the run's
    entity, inherits its TLP, gets its ownership tag, and the finding copies the ownership."""
    from v3lum.core.models import Finding, Severity

    other = Entity.make("domain", "partner-cdn.example")

    def run(self, entity, ctx):
        res = self.result(entity)
        res.findings.append(Finding(module=self.name, entity=other, title="serves the seed's assets", severity=Severity.LOW, criterion="synthetic criterion"))
        return res

    define(registry, "t_other_entity", [T.DOMAIN], run)
    org = {"org": {"name": "Example Org"}, "domains": [{"name": "example.org", "verification": "txt_verified", "criticality": "high"}]}
    rt = make_runtime(FakeHttp(), org_profile=org)
    case = scan([("domain", "example.org")], ["t_other_entity"], rt=rt, tlp="green", seed_tlp={"domain:example.org": "amber+strict"})
    node = case.graph.get(other)
    assert (node.depth, node.tlp, node.ownership, node.investigated) == (1, "amber+strict", "third_party", False)
    assert node.tagged("third_party") and [f.ownership for f in node.findings] == ["third_party"]


def test_run_module_applies_a_decision(isolated):
    """`v3lum run`: run_module(cls, entity, decision=engine.decide_single(...)) never re-decides - a
    refusal returns its outcome without running, and an allowing decision narrows ctx.allowed_sources
    (an aggregator never queries a licence-blocked feed on the single-run path)."""
    seen: list[frozenset] = []
    terms = {"class": "noncommercial", "evidence_url": "https://terms.example.test/", "quote": "synthetic terms", "checked_at": "2026-11-26", "reviewer": "tests", "free_plan_business_use": None}
    with test_provider("t_single_agg_prov", sources={"open_feed": {}, "nc_feed": {"terms": terms}}) as prov:
        ids = source_ids(prov)

        def run(self, entity, ctx):
            seen.append(ctx.allowed_sources)
            return self.result(entity)

        cls = define(
            isolated, "t_single_agg", [T.DOMAIN], run, disclosure="third_party", provider=prov.id, sources=ids, hosts=prov.hosts,
            terms="noncommercial", access_model="free_noauth_unlimited",
        )
        eng = Engine(make_runtime(FakeHttp()), ScanOptions())
        entity = Entity.make("domain", "example.org")
        decision = eng.decide_single(cls, entity)
        assert decision.allowed and decision.allowed_sources == frozenset({f"{prov.id}.open_feed"})
        res = eng.run_module(cls, entity, decision=decision)
    assert res.status is Status.EMPTY and seen == [frozenset({f"{prov.id}.open_feed"})]
    ran: list[str] = []
    optin = define(isolated, "t_single_optin", [T.DOMAIN], lambda self, e, c: ran.append(e.key) or self.result(e), opsec=Opsec.LIGHT)
    refused = eng.decide_single(optin, entity)
    res = eng.run_module(optin, entity, decision=refused)
    assert ran == [] and (res.status, res.reason_code) == (Status.SKIPPED, "opsec") and res.error == refused.reason


def test_select_outside_a_scan_decides_with_the_current_configuration(isolated):
    """No policy context is cached for the engine's lifetime: a key configured after a first
    listing unlocks the module at the next one."""
    with test_provider("t_late_key_prov", keys=("t_late_key",)) as prov:
        cls = define(
            isolated, "t_late_keyed", [T.DOMAIN], lambda self, e, c: self.result(e), requires_keys=("t_late_key",),
            disclosure="third_party", provider=prov.id, sources=source_ids(prov), hosts=prov.hosts, access_model="free_auth_limited",
        )
        rt = make_runtime(FakeHttp())
        eng = Engine(rt, ScanOptions())
        entity = Entity.make("domain", "example.org")
        _runnable, blocked = eng.select(entity)
        assert [(c.name, d.reason_code) for c, d in blocked] == [(cls.name, "needs_key")]
        rt.config.file_keys["t_late_key"] = "configured-later-123"
        runnable, _blocked = eng.select(entity)
        assert [c.name for c, _d in runnable] == [cls.name]


def test_evidence_never_holds_a_raw_secret_of_the_run(tmp_path):
    """Defence in depth behind the sanitizer: a raw SECRET_TYPES value of the run (its entity or a
    pivot) is written in its persisted form wherever it appears in the evidence payload."""
    jwt = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dozjgNryP4J3jVmNHl0w5N_XgL0n3I9PlFUP0THsR8U"
    entity = Entity.make("jwt", jwt)
    res = ModuleResult("t_secret_ev", entity)
    res.raw = {"token": jwt, "note": f"decoded {jwt}", jwt: 1}
    path, _digest = EvidenceStore(tmp_path / "case-s").save(res, requests=[{"method": "GET", "url": f"https://api.example.test/decode?t={jwt}", "status": 200}])
    text = Path(path).read_text(encoding="utf-8")
    assert jwt not in text and entity.redacted in text and jwt not in Path(path).name


def test_evidence_files_are_never_written_through_a_planted_link(tmp_path):
    entity = Entity.make("domain", "example.org")
    res = ModuleResult("t_link_ev", entity)
    res.raw = {"answer": 1}
    store = EvidenceStore(tmp_path / "case-l")
    path, _digest = store.save(res)
    os.unlink(path)
    outside = tmp_path / "outside.txt"
    outside.write_text("untouched", encoding="utf-8")
    os.symlink(outside, path)
    with pytest.raises(OSError):
        store.save(res)
    assert outside.read_text(encoding="utf-8") == "untouched"


def test_the_case_records_the_licence_profile_the_gate_enforced(registry):
    """A1: research without a recorded legal basis runs under the corporate profile (the policy
    context falls back, fail closed): the case must say corporate, never carry a research banner."""
    define(registry, "t_lic_profile", [T.DOMAIN], lambda self, e, c: self.result(e))
    case = scan([("domain", "example.org")], ["t_lic_profile"], licence_profile="research")
    assert case.licence_profile == "corporate" and case.to_dict()["licence_profile"] == "corporate"
    assert any("corporate licence profile" in n for n in case.notes)


def test_evidence_names_never_fall_back_to_a_plain_hash_of_the_value(tmp_path, monkeypatch):
    """A4 BR7: without the installation secret the name part is random - a plain SHA-256 of an
    e-mail address could be tested against guessed addresses."""
    from v3lum.core import hmacid

    def unavailable(*args, **kwargs):
        raise OSError("secret.key not readable")

    monkeypatch.setattr(hmacid, "hmac12", unavailable)
    entity = Entity.make("email", "alice.person@corp.example")
    res = ModuleResult("t_ev_fallback", entity)
    res.raw = {"seen": True}
    path, _digest = EvidenceStore(tmp_path / "case-f").save(res)
    part = Path(path).name.split("__")[2]
    assert len(part) == 12 and part != hashlib.sha256(entity.key.encode("utf-8")).hexdigest()[:12]
    assert part != hashlib.sha256(entity.value.encode("utf-8")).hexdigest()[:12] and "alice" not in Path(path).name
