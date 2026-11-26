"""AR20 (f) - methods and ceilings (A7, P327 cond 9): ACTIVE issues only GET/HEAD/OPTIONS and LIGHT
only GET/HEAD unless an approved fragment in ``v3lum/data/policy/method_allowlist/`` lists the
module (writes, deletes, tracing and tunnelling never); the hard ceilings hold whatever a module or
a scope asks for: rate (ACTIVE <= 10/s, LIGHT <= 1/s per target host), concurrency (<= 2 per host),
the LIGHT budget (<= 25 requests per target host per scan), the ACTIVE case budget, ports (<= 1000
per host) and wordlists (<= 5000 entries).

Black box: synthetic modules run through the engine over the real HTTP client and socket connector;
``FakeHttp`` and a ``FakeClock`` record what left and when.
"""

from __future__ import annotations

import itertools
import json
import threading
import time

import pytest

from tests.fakes import make_runtime
from tests.safety.conftest import (
    IN_SCOPE_HOST,
    IN_SCOPE_IP,
    Ledger,
    TrackingHttp,
    active_module,
    active_options,
    calls_to,
    coverage_of,
    dns,
    host_of,
    light_module,
    light_options,
    scan,
)
from v3lum.core.http import (
    ACTIVE_METHODS,
    LIGHT_METHODS,
    NEVER_ALLOWED_METHODS,
    PORT_SCAN_MAX,
    WORDLIST_MAX,
    PolicyError,
    method_allowlist,
    method_allowlist_errors,
    reload_method_allowlist,
)
from v3lum.core.module import RegistrationError

pytestmark = pytest.mark.safety

SEED = f"domain:{IN_SCOPE_HOST}"
URL = f"https://{IN_SCOPE_HOST}/api"
METHODS = ("GET", "HEAD", "OPTIONS", "POST", "PUT", "PATCH", "DELETE", "TRACE", "CONNECT", "PROPFIND", "MKCOL")


@pytest.fixture()
def target(http):
    dns(http, IN_SCOPE_HOST, a=[IN_SCOPE_IP])
    http.add("*", URL, text="ok")
    http.add("*", f"https://{IN_SCOPE_HOST}/item/*", text="item")
    return http


@pytest.fixture()
def allowlist(tmp_path):
    """Write method allow-list fragments into a test directory (added to the shipped one)."""
    folder = tmp_path / "method_allowlist"
    folder.mkdir()

    def write(module: str, methods: dict[str, str], *, approved_by: str = "architect (safety suite)", decision_ref: str = "ADR-SAFETY-1") -> None:
        data = {"schema": "v3lum.method_allow/1", "module": module, "methods": methods, "approved_by": approved_by, "decision_ref": decision_ref}
        (folder / f"{module}.json").write_text(json.dumps(data), encoding="utf-8")
        reload_method_allowlist(extra_dirs=[folder])

    yield write
    reload_method_allowlist(extra_dirs=())


def sending(method: str, outcome: dict[str, str], url: str = URL):
    """run(): one request with ``method`` (records 'sent' or the refusal), then returns."""

    def run(self, ent, ctx):
        try:
            ctx.http.request(method, url, data={"q": "x"} if method in ("POST", "PUT", "PATCH") else None)
        except PolicyError as exc:
            outcome[method] = f"refused: {exc}"
        else:
            outcome[method] = "sent"
        return self.result(ent)

    return run


def run_method(opsec: str, method: str, http, scope_file, name: str = "t_safety_method") -> str:
    outcome: dict[str, str] = {}
    make = active_module if opsec == "active" else light_module
    make(name, sending(method, outcome))
    opts = active_options(scope_file(), {name}) if opsec == "active" else light_options({name})
    scan(make_runtime(http), opts, SEED)
    return outcome[method]


# --------------------------------------------------------------------------------------
# methods
# --------------------------------------------------------------------------------------


@pytest.mark.parametrize("opsec", ["light", "active"])
@pytest.mark.parametrize("method", METHODS)
def test_target_contact_uses_only_read_methods(registry, target, scope_file, opsec, method):
    allowed = (ACTIVE_METHODS if opsec == "active" else LIGHT_METHODS)
    outcome = run_method(opsec, method, target, scope_file)
    sent = [c["method"] for c in calls_to(target, IN_SCOPE_HOST)]
    if method in allowed:
        assert outcome == "sent" and sent == [method]
    else:
        assert outcome.startswith("refused") and sent == [], (method, outcome, sent)
        assert "method_allowlist" in outcome or "Tor" in outcome or "GET/HEAD" in outcome


def test_the_read_method_sets_are_the_a7_sets():
    assert set(LIGHT_METHODS) == {"GET", "HEAD"} and set(ACTIVE_METHODS) == {"GET", "HEAD", "OPTIONS"}
    assert {"PUT", "PATCH", "DELETE", "TRACE", "CONNECT"} <= NEVER_ALLOWED_METHODS


def test_an_approved_fragment_allows_its_module_one_documented_read_method(registry, target, scope_file, allowlist):
    allowlist("t_safety_graphql", {"POST": "GraphQL introspection query: a read (ADR-SAFETY-1)"})
    assert run_method("active", "POST", target, scope_file, name="t_safety_graphql") == "sent"
    assert [c["method"] for c in calls_to(target, IN_SCOPE_HOST)] == ["POST"]
    # another module, the same method: refused
    assert run_method("active", "POST", target, scope_file, name="t_safety_not_listed").startswith("refused")
    # the fragment never extends to other methods of the listed module
    assert run_method("active", "DELETE", target, scope_file, name="t_safety_graphql").startswith("refused")
    assert [c["method"] for c in calls_to(target, IN_SCOPE_HOST)] == ["POST"]


def test_a_light_module_needs_its_own_fragment_too(registry, target, scope_file, allowlist):
    assert run_method("light", "POST", target, scope_file, name="t_safety_light_post").startswith("refused")
    allowlist("t_safety_light_post", {"POST": "read-only search form (ADR-SAFETY-1)"})
    assert run_method("light", "POST", target, scope_file, name="t_safety_light_post") == "sent"


@pytest.mark.parametrize(
    ("methods", "kw", "needle"),
    [
        ({"DELETE": "cleanup"}, {}, "can never be allow-listed"),
        ({"PUT": "upload a probe"}, {}, "can never be allow-listed"),
        ({"TRACE": "debug"}, {}, "can never be allow-listed"),
        ({"POST": "search"}, {"approved_by": ""}, "approved_by and decision_ref"),
        ({"POST": "search"}, {"decision_ref": ""}, "approved_by and decision_ref"),
        ({"POST": ""}, {}, "justification"),
    ],
)
def test_unapproved_or_writing_fragments_grant_nothing(registry, target, scope_file, allowlist, methods, kw, needle):
    allowlist("t_safety_bad_fragment", methods, **kw)
    assert "t_safety_bad_fragment" not in method_allowlist()
    assert any("t_safety_bad_fragment" in e and needle in e for e in method_allowlist_errors())
    (method,) = methods
    assert run_method("active", method, target, scope_file, name="t_safety_bad_fragment").startswith("refused")
    assert calls_to(target, IN_SCOPE_HOST) == []


def test_the_shipped_method_allowlist_is_clean():
    """Every fragment shipped in v3lum/data/policy/method_allowlist/ is approved, read-only and valid
    (a broken or writing fragment fails this gate)."""
    reload_method_allowlist(extra_dirs=())
    assert method_allowlist_errors() == []
    for module, entry in method_allowlist().items():
        assert entry.approved_by and entry.decision_ref, module
        assert not set(entry.methods) & NEVER_ALLOWED_METHODS, module
        assert all(why.strip() for why in entry.methods.values()), module


# --------------------------------------------------------------------------------------
# forbidden actions: no login attempt, borrowed session or V3LUM key toward a target
# --------------------------------------------------------------------------------------

CREDENTIAL_HEADERS = {
    "Authorization": "Basic YWRtaW46YWRtaW4=",  # admin:admin - a default-login check
    "Cookie": "session=borrowed",
    "X-Api-Key": "k-123",
    "Proxy-Authorization": "Basic eDp5",
}


@pytest.mark.parametrize("opsec", ["light", "active"])
@pytest.mark.parametrize("header", sorted(CREDENTIAL_HEADERS))
def test_credentials_never_go_to_a_target(registry, target, scope_file, opsec, header):
    outcome: dict[str, str] = {}

    def run(self, ent, ctx):
        try:
            ctx.http.get(URL, headers={header: CREDENTIAL_HEADERS[header]})
        except PolicyError as exc:
            outcome["result"] = f"refused: {exc}"
        else:
            outcome["result"] = "sent"
        return self.result(ent)

    make = active_module if opsec == "active" else light_module
    make("t_safety_creds", run)
    opts = active_options(scope_file(), {"t_safety_creds"}) if opsec == "active" else light_options({"t_safety_creds"})
    scan(make_runtime(target), opts, SEED)
    assert outcome["result"].startswith("refused") and "never goes to a target" in outcome["result"], outcome
    assert calls_to(target, IN_SCOPE_HOST) == []


def test_url_userinfo_never_reaches_a_target(registry, loopback):
    """https://admin:admin@target/ must not become a login attempt: the real transport sends neither an
    Authorization header nor the credentials (no ~/.netrc either)."""
    from v3lum.core.clock import SYSTEM_CLOCK
    from v3lum.core.http import RequestsTransport

    srv = loopback()
    outcome: dict[str, str] = {}

    def run(self, ent, ctx):
        try:
            ctx.http.get(f"http://admin:s3cr3t-pw@wiki.internal:{srv.port}/login")
        except PolicyError:
            outcome["result"] = "refused"  # a refusal is fine too: nothing may carry the credentials
        else:
            outcome["result"] = "sent"
        return self.result(ent)

    light_module("t_safety_userinfo", run)
    rt = make_runtime(RequestsTransport(trust_env=False), clock=SYSTEM_CLOCK)
    rt.http.egress.resolver = lambda host, profile: ["127.0.0.1"]
    scan(rt, light_options({"t_safety_userinfo"}), f"url:http://wiki.internal:{srv.port}/status")
    assert outcome["result"] == "refused" or len(srv.requests) == 1, (outcome, srv.requests)
    for request in srv.requests:
        sent = json.dumps(request).lower()
        assert "authorization" not in sent and "s3cr3t-pw" not in sent and "admin" not in sent, request


# --------------------------------------------------------------------------------------
# ceilings: rate, concurrency, budgets, ports, wordlists
# --------------------------------------------------------------------------------------


def stamped(http, clock) -> list[float]:
    """The clock time of every send to the target host (hook)."""
    stamps: list[float] = []

    def hook(method: str, url: str) -> None:
        if host_of(url) == IN_SCOPE_HOST:
            stamps.append(clock.monotonic())

    http.hooks.append(hook)
    return stamps


def looping(n: int, url=lambda i: f"https://{IN_SCOPE_HOST}/item/{i}"):
    def run(self, ent, ctx):
        for i in range(n):
            ctx.http.get(url(i))
        return self.result(ent)

    return run


def gaps(stamps: list[float]) -> list[float]:
    return [round(b - a, 6) for a, b in itertools.pairwise(stamps)]


@pytest.mark.parametrize(("limits", "interval"), [(None, 0.1), ({"max_rps": 4}, 0.25)])
def test_active_rate_per_target_host(registry, target, scope_file, clock, limits, interval):
    stamps = stamped(target, clock)
    active_module("t_safety_rate", looping(6), max_rate=10.0, min_interval=0.0)
    scope = scope_file(limits=limits) if limits else scope_file()
    scan(make_runtime(target), active_options(scope, {"t_safety_rate"}), SEED)
    assert len(stamps) == 6
    assert min(gaps(stamps)) >= interval - 1e-6, gaps(stamps)


def test_light_rate_is_one_request_per_second_per_host(registry, target, clock):
    stamps = stamped(target, clock)
    light_module("t_safety_light_rate", looping(5), max_rate=1.0)
    scan(make_runtime(target), light_options({"t_safety_light_rate"}), SEED)
    assert len(stamps) == 5 and min(gaps(stamps)) >= 1.0 - 1e-6, gaps(stamps)


def test_modules_cannot_declare_a_rate_above_the_ceiling(registry):
    with pytest.raises(RegistrationError, match="ceiling"):
        active_module("t_safety_fast_active", looping(1), max_rate=50.0)
    with pytest.raises(RegistrationError, match="ceiling"):
        light_module("t_safety_fast_light", looping(1), max_rate=5.0)


@pytest.mark.parametrize("limits", [{"max_rps": 50}, {"max_concurrency": 5}, {"max_pps": 5000}, {"max_requests": 100000}])
def test_a_scope_above_the_ceilings_allows_nothing(registry, target, scope_file, limits):
    active_module("t_safety_scope_ceiling", looping(3))
    case = scan(make_runtime(target), active_options(scope_file(limits=limits), {"t_safety_scope_ceiling"}), SEED)
    assert coverage_of(case, "t_safety_scope_ceiling", SEED)["reason_code"] == "scope"
    assert calls_to(target, IN_SCOPE_HOST) == []


def test_light_budget_is_25_requests_per_target_host_per_scan(registry, target):
    """Two LIGHT modules on the same seed host share the 25-request budget of the scan; the module
    that hits it ends partial ('request_cap'), never with an invented answer."""
    light_module("t_safety_budget_a", looping(20))
    light_module("t_safety_budget_b", looping(20, url=lambda i: f"https://{IN_SCOPE_HOST}/item/b{i}"))
    case = scan(make_runtime(target), light_options({"t_safety_budget_a", "t_safety_budget_b"}, threads=1), SEED)
    assert len(calls_to(target, IN_SCOPE_HOST)) == 25
    rows = [coverage_of(case, m, SEED) for m in ("t_safety_budget_a", "t_safety_budget_b")]
    assert [r["stop_reason"] for r in rows if r.get("partial")] == ["request_cap"]
    # a new scan starts a new budget
    case2 = scan(make_runtime(target), light_options({"t_safety_budget_a"}), SEED)
    assert coverage_of(case2, "t_safety_budget_a", SEED)["status"] in ("ok", "empty")


def test_the_light_budget_holds_under_concurrency(registry, target):
    """Four LIGHT modules on eight worker threads race for the same host: the scan still sends exactly
    25 requests to it (the ceiling is charged atomically)."""
    names = [f"t_safety_budget_conc_{i}" for i in range(4)]
    for i, name in enumerate(names):
        light_module(name, looping(20, url=lambda j, i=i: f"https://{IN_SCOPE_HOST}/item/c{i}-{j}"))
    case = scan(make_runtime(target), light_options(set(names), threads=8), SEED)
    assert len(calls_to(target, IN_SCOPE_HOST)) == 25
    rows = [coverage_of(case, name, SEED) for name in names]
    assert all(r["status"] in ("ok", "empty") for r in rows)
    assert sum(1 for r in rows if r.get("partial") and r.get("stop_reason") == "request_cap") >= 1


def test_the_active_case_budget_holds_under_concurrency(registry, target, scope_file):
    names = [f"t_safety_case_conc_{i}" for i in range(4)]
    for i, name in enumerate(names):
        active_module(name, looping(10, url=lambda j, i=i: f"https://{IN_SCOPE_HOST}/item/a{i}-{j}"))
    scan(make_runtime(target), active_options(scope_file(limits={"max_requests": 7}), set(names), threads=8), SEED)
    assert len(calls_to(target, IN_SCOPE_HOST)) == 7


@pytest.mark.xfail(
    strict=True,
    reason="WP08 engine.py: a RequestCapReached raised by an A7 ceiling (LIGHT 25/host, the ACTIVE case budget, the port ceiling) "
    "is reported as 'request cap reached (<max_requests> per entity)', hiding which ceiling stopped the run - see the WP28 report open_issues",
)
def test_a_ceiling_stop_names_the_ceiling(registry, target, scope_file):
    """The analyst must see which hard ceiling stopped a run (A3 readable reasons), not the module's
    own max_requests (200 here, never reached)."""
    light_module("t_safety_cap_reason", looping(30))
    case = scan(make_runtime(target), light_options({"t_safety_cap_reason"}), SEED)
    row = coverage_of(case, "t_safety_cap_reason", SEED)
    assert row["partial"] and row["stop_reason"] == "request_cap"
    assert "LIGHT ceiling" in row["reason"] and "200 per entity" not in row["reason"], row["reason"]


def test_probe_rate_and_total_attempt_rate_hold_for_raw_sockets(registry, scope_file, clock):
    """Port probes obey the per-host probe rate (ACTIVE <= 10/s) and the global connection-attempt
    rate (scope max_pps; here 4/s, lower than the per-host rate)."""

    def probing(stamps: list[float]):
        def run(self, ent, ctx):
            for port in range(50000, 50006):
                try:
                    ctx.net.connect("127.0.0.1", port, timeout=0.2).close()
                except OSError:
                    pass
                stamps.append(clock.monotonic())
            return self.result(ent)

        return run

    scope_targets = {"domains": ["acme.example"], "cidrs": ["127.0.0.1/32"]}
    for limits, interval in ((None, 0.1), ({"max_pps": 4}, 0.25)):
        stamps: list[float] = []
        name = f"t_safety_probe_rate_{int(interval * 100)}"
        active_module(name, probing(stamps), accepts=("ipv4",))
        scope = scope_file(targets=scope_targets, limits=limits) if limits else scope_file(targets=scope_targets)
        scan(make_runtime(clock=clock), active_options(scope, {name}), "ipv4:127.0.0.1")
        assert len(stamps) == 6
        assert min(round(b - a, 6) for a, b in itertools.pairwise(stamps)) >= interval - 1e-6, (limits, stamps)


def test_active_case_budget_follows_the_scope(registry, target, scope_file):
    active_module("t_safety_case_budget", looping(10))
    case = scan(make_runtime(target), active_options(scope_file(limits={"max_requests": 5}), {"t_safety_case_budget"}), SEED)
    assert len(calls_to(target, IN_SCOPE_HOST)) == 5
    row = coverage_of(case, "t_safety_case_budget", SEED)
    assert row["partial"] and row["stop_reason"] == "request_cap"


@pytest.mark.parametrize(("limits", "peak"), [(None, 2), ({"max_concurrency": 1}, 1)])
def test_at_most_two_concurrent_connections_per_target_host(registry, scope_file, clock, limits, peak):
    """Four ACTIVE modules probe the same host at once: never more than 2 (or the scope's lower
    max_concurrency) connections to it are open at the same time."""

    class Slow(TrackingHttp):
        def __init__(self) -> None:
            super().__init__(clock=clock)
            self.active = 0
            self.peak = 0
            self.lock = threading.Lock()

        def send(self, method, url, **kw):
            if host_of(url) != IN_SCOPE_HOST:
                return super().send(method, url, **kw)
            with self.lock:
                self.active += 1
                self.peak = max(self.peak, self.active)
            try:
                time.sleep(0.03)  # the target is slow to answer
                return super().send(method, url, **kw)
            finally:
                with self.lock:
                    self.active -= 1

    http = Slow()
    dns(http, IN_SCOPE_HOST, a=[IN_SCOPE_IP])
    http.add("GET", f"https://{IN_SCOPE_HOST}/item/*", text="item")
    names = [f"t_safety_conc_{i}" for i in range(4)]
    for i, name in enumerate(names):
        active_module(name, looping(3, url=lambda j, i=i: f"https://{IN_SCOPE_HOST}/item/{i}-{j}"))
    scope = scope_file(limits=limits) if limits else scope_file()
    scan(make_runtime(http), active_options(scope, set(names), threads=8), SEED)
    assert len(calls_to(http, IN_SCOPE_HOST)) == 12
    assert 1 <= http.peak <= peak  # normally exactly ``peak``: four modules compete for the host


def test_port_probes_stop_at_1000_ports_per_host(registry, scope_file, clock):
    ports = list(range(50000, 50000 + PORT_SCAN_MAX + 1))
    seen: dict[str, object] = {}

    def scanner(self, ent, ctx):
        tried = 0
        try:
            for port in ports:
                tried += 1
                try:
                    ctx.net.connect("127.0.0.1", port, timeout=0.5).close()
                except OSError:
                    continue
        finally:
            seen["tried"] = tried
        return self.result(ent)

    # 1000 probes at <= 10/s take 100 s: the module declares a longer run deadline, the scan a longer deadline
    active_module("t_safety_ports", scanner, accepts=("ipv4",), timeout=300.0)
    rt = make_runtime(clock=clock)
    ledger = Ledger(rt)
    scope = scope_file(targets={"domains": ["acme.example"], "cidrs": ["127.0.0.1/32"]})
    case = scan(rt, active_options(scope, {"t_safety_ports"}, timeout_total=600.0), "ipv4:127.0.0.1")
    assert PORT_SCAN_MAX == 1000
    assert len(ledger.to("127.0.0.1", method="CONNECT")) == PORT_SCAN_MAX
    assert seen["tried"] == PORT_SCAN_MAX + 1  # the 1001st port was refused before any socket
    row = coverage_of(case, "t_safety_ports", "ipv4:127.0.0.1")
    assert row["partial"] and row["stop_reason"] == "request_cap"


def test_wordlists_are_capped_at_5000_entries(registry, target, scope_file):
    sizes: dict[str, int] = {}

    def run(self, ent, ctx):
        sizes["endless"] = len(ctx.net.cap_wordlist(f"word{i}" for i in itertools.count()))
        sizes["large"] = len(ctx.net.cap_wordlist([f"w{i}" for i in range(12000)]))
        sizes["small"] = len(ctx.net.cap_wordlist(["admin", "login", "api"]))
        return self.result(ent)

    active_module("t_safety_words", run)
    scan(make_runtime(target), active_options(scope_file(), {"t_safety_words"}), SEED)
    assert WORDLIST_MAX == 5000
    assert sizes == {"endless": 5000, "large": 5000, "small": 3}
