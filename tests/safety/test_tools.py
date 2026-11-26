"""AR20 (j) - the external-tool runner (core/tools.py, WP11; A6 BR3, A7 BR11-12): a tool never
launches against an out-of-scope, CDN, private or pivot target; the ToolSpec forced flags and the
rate clamp are always applied; every launch is in the request ledger; the kill switch (Ctrl+C, the
scan deadline) kills it within 2 s.

Black box: synthetic LIGHT/ACTIVE modules call ``ctx.net.run_tool`` during engine scans; the tool is
a fake binary on a temporary PATH that appends one JSON line per launch (argv, pid, process group)
to a log file, so a launch that should not have happened is always visible.
"""

from __future__ import annotations

import json
import os
import stat
import sys
import threading
import time
import uuid
from pathlib import Path

import pytest

from tests.fakes import make_runtime
from tests.safety.conftest import (
    CDN_IP,
    IN_SCOPE_HOST,
    IN_SCOPE_IP,
    METADATA_IP,
    OUT_OF_SCOPE_IP,
    KillSwitchProbe,
    Ledger,
    active_module,
    active_options,
    coverage_of,
    dns,
    entity,
    interrupt_engine_when,
    light_module,
    light_options,
    passive_module,
    pivot_source,
    scan,
)
from v3lum.core.clock import SYSTEM_CLOCK
from v3lum.core.context import RunInfo
from v3lum.core.engine import Engine
from v3lum.core.http import PolicyError
from v3lum.core.models import Status
from v3lum.core.tools import ToolResult, ToolSpec, register_tool, unregister_tool

pytestmark = [pytest.mark.safety, pytest.mark.skipif(os.name != "posix", reason="the fake tool is a POSIX script")]

SEED = f"domain:{IN_SCOPE_HOST}"
TOOL = "safetytool"
KILL_WITHIN = 2.0

FAKE_TOOL = """#!{python}
import json, os, sys, time
args = sys.argv[1:]
if args == ["-version"]:
    print("safetytool v2.0.0")
    sys.exit(0)
with open({log!r}, "a", encoding="utf-8") as fh:
    env = {{k: v for k, v in os.environ.items() if "proxy" in k.lower() or k == "NETRC"}}
    fh.write(json.dumps({{"argv": args, "pid": os.getpid(), "pgid": os.getpgrp(), "env": env}}) + "\\n")
if "--sleep" in args:
    time.sleep(float(args[args.index("--sleep") + 1]))
print(json.dumps({{"argv": args}}))
"""


class FakeTool:
    """The fake binary's launch log (argv, pid, process group and the proxy/netrc variables it saw)."""

    def __init__(self, log: Path, binary: str) -> None:
        self.log = log
        self.binary = binary

    def launches(self) -> list[dict]:
        if not self.log.exists():
            return []
        return [json.loads(line) for line in self.log.read_text(encoding="utf-8").splitlines() if line.strip()]


@pytest.fixture()
def tool(tmp_path, monkeypatch):
    """Register ``safetytool`` (forced -duc -ni -silent, forbidden -up/-interactsh-url, rate flag
    -rl with max_rate 50, proxy flag -proxy) backed by a fake binary on a temporary PATH."""
    bindir = tmp_path / "bin"
    bindir.mkdir()
    log = tmp_path / "launches.jsonl"
    binary = f"v3lum-safety-{uuid.uuid4().hex[:8]}"
    path = bindir / binary
    path.write_text(FAKE_TOOL.format(python=sys.executable, log=str(log)), encoding="utf-8")
    path.chmod(path.stat().st_mode | stat.S_IXUSR | stat.S_IXGRP | stat.S_IXOTH)
    monkeypatch.setenv("PATH", f"{bindir}{os.pathsep}{os.environ.get('PATH', '')}")
    spec = ToolSpec(
        name=TOOL, binary=binary, version_args=("-version",), min_version="2.0.0", licence="MIT",
        forced_args=("-duc", "-ni", "-silent"), forbidden_args=("-up", "-interactsh-url"), rate_flag="-rl", max_rate=50.0, proxy_flag="-proxy",
    )
    register_tool(spec)
    try:
        yield FakeTool(log, binary)
    finally:
        unregister_tool(TOOL)


def launching(targets_of, outcomes: dict[str, str], args_of=None):
    """run(): one run_tool call per target (records the ToolResult argv or the refusal)."""

    def run(self, ent, ctx):
        for target in targets_of(ent):
            args = args_of(target) if args_of else ["-u", target]
            try:
                result = ctx.net.run_tool(TOOL, args, targets=[target], timeout=10)
            except PolicyError as exc:
                outcomes[target] = f"refused ({exc.reason_code}): {exc}"
            except Exception as exc:  # noqa: BLE001 - recorded: the assertions say what was expected
                outcomes[target] = f"error {type(exc).__name__}: {exc}"
            else:
                outcomes[target] = json.loads(result.stdout)["argv"]
        return self.result(ent)

    return run


# --------------------------------------------------------------------------------------
# targets: never out of scope, CDN, private or a pivot
# --------------------------------------------------------------------------------------

FORBIDDEN_TARGETS = [
    "https://partner.example.org/",  # out of scope
    OUT_OF_SCOPE_IP,  # out of scope
    "evil.example.net:443",  # out of scope
    "https://mail.acme.example/",  # excluded by the scope
    CDN_IP,  # CDN address, not listed
    "cdn.acme.example",  # in scope by name, on CDN addresses (network probe)
    "https://cdn.acme.example/",  # in scope by name, on CDN addresses (HTTP probe without shared_infra_hosts)
    "10.0.0.7",  # private
    METADATA_IP,  # cloud metadata
    "db.acme.example",  # in scope by name, resolves to a private address
    "127.0.0.1",  # loopback
    "intranet",  # single-label internal name
]


def test_the_tool_never_launches_against_out_of_scope_cdn_or_private_targets(registry, http, scope_file, cdn_noise, tool):
    dns(http, IN_SCOPE_HOST, a=[IN_SCOPE_IP])
    # a network-probe target named by host is resolved first (a name may be in scope through its
    # addresses, A7), then refused: the resolver answers, the tool never starts
    dns(http, "evil.example.net", a=[OUT_OF_SCOPE_IP])
    dns(http, "cdn.acme.example", a=[CDN_IP])
    dns(http, "db.acme.example", a=["10.0.0.7"])
    allowed = f"https://{IN_SCOPE_HOST}/"
    outcomes: dict[str, str] = {}
    active_module("t_safety_tool_targets", launching(lambda ent: [*FORBIDDEN_TARGETS, allowed], outcomes))
    rt = make_runtime(http)
    ledger = Ledger(rt)
    scan(rt, active_options(scope_file(), {"t_safety_tool_targets"}), SEED)
    for target in FORBIDDEN_TARGETS:
        assert str(outcomes[target]).startswith("refused"), (target, outcomes[target])
    assert isinstance(outcomes[allowed], list)  # the in-scope target ran: the refusals are not a broken tool
    launches = tool.launches()
    assert len(launches) == 1 and launches[0]["argv"][-2:] == ["-u", allowed]
    assert [r.host for r in ledger.records if r.method == "EXEC"] == [IN_SCOPE_HOST]


def test_arguments_cannot_point_the_tool_at_an_unchecked_target(registry, http, scope_file, tool):
    """A module cannot list an in-scope target and aim the tool elsewhere through its arguments."""
    outcomes: dict[str, str] = {}
    sneaky = {
        f"https://{IN_SCOPE_HOST}/": ["-u", "https://evil.example.net/"],
        IN_SCOPE_IP: ["-target", f"{OUT_OF_SCOPE_IP}:443"],
    }
    dns(http, IN_SCOPE_HOST, a=[IN_SCOPE_IP])
    active_module("t_safety_tool_args", launching(lambda ent: list(sneaky), outcomes, args_of=lambda t: sneaky[t]))
    scan(make_runtime(http), active_options(scope_file(), {"t_safety_tool_args"}), SEED)
    for target in sneaky:
        assert str(outcomes[target]).startswith("refused (scope)"), outcomes[target]
    assert tool.launches() == []


def test_the_tool_never_runs_for_a_pivot(registry, http, scope_file, tool):
    """ACTIVE: an out-of-scope pivot never gets the module (pivots never inherit scope). LIGHT: the
    module runs on the analyst-typed seed only, and a pivot run is refused by the connector."""
    outcomes: dict[str, str] = {}
    pivot_source("t_safety_tool_pivots", [("domain", "pivot.example.net", "related"), ("domain", "sub.www.acme.example", "subdomain")])
    active_module("t_safety_tool_active", launching(lambda ent: [ent.value], outcomes))
    dns(http, IN_SCOPE_HOST, a=[IN_SCOPE_IP])
    dns(http, "sub.www.acme.example", a=["93.184.216.60"])
    case = scan(make_runtime(http), active_options(scope_file(), {"t_safety_tool_pivots", "t_safety_tool_active"}), SEED)
    assert coverage_of(case, "t_safety_tool_active", "domain:pivot.example.net")["reason_code"] == "scope"
    assert "pivot.example.net" not in outcomes
    assert all("pivot.example.net" not in " ".join(launch["argv"]) for launch in tool.launches())

    light_outcomes: dict[str, str] = {}
    light = light_module("t_safety_tool_light", launching(lambda ent: [ent.value, "pivot.example.net"], light_outcomes))
    rt = make_runtime(http)
    before = len(tool.launches())
    scan(rt, light_options({"t_safety_tool_light"}), SEED)
    assert str(light_outcomes["pivot.example.net"]).startswith("refused (scope)")  # outside the seed
    pivot = entity("domain:sub.www.acme.example")
    res = Engine(rt, light_options({"t_safety_tool_light"})).run_module(light, pivot, run=RunInfo(entity=pivot, is_seed=False, depth=1, case_id="c-pivot"))
    assert res.status in (Status.OK, Status.EMPTY)
    assert "never on pivots" in str(light_outcomes["sub.www.acme.example"])
    assert len(tool.launches()) == before + 1  # only the seed itself
    assert tool.launches()[-1]["argv"][-2:] == ["-u", IN_SCOPE_HOST]


def test_passive_modules_never_launch_tools(ti_provider, http, tool):
    outcomes: dict[str, str] = {}
    passive_module("t_safety_tool_passive", launching(lambda ent: [IN_SCOPE_IP], outcomes), ti_provider)
    scan(make_runtime(http), light_options({"t_safety_tool_passive"}), "domain:example.org")
    assert str(outcomes[IN_SCOPE_IP]).startswith("refused (policy)")
    assert tool.launches() == []


# --------------------------------------------------------------------------------------
# forced flags, rate clamp, ledger
# --------------------------------------------------------------------------------------


@pytest.mark.parametrize(("opsec", "limits", "rate"), [("active", None, "10"), ("active", {"max_rps": 4}, "4"), ("light", None, "1")])
def test_forced_flags_and_the_rate_clamp_are_always_applied(registry, http, scope_file, tool, opsec, limits, rate):
    outcomes: dict[str, str] = {}
    target = IN_SCOPE_HOST if opsec == "light" else IN_SCOPE_IP
    make = active_module if opsec == "active" else light_module
    make("t_safety_tool_flags", launching(lambda ent: [target], outcomes, args_of=lambda t: ["-u", t, "positional"]))
    dns(http, IN_SCOPE_HOST, a=[IN_SCOPE_IP])
    scope = scope_file(limits=limits) if limits else scope_file()
    opts = active_options(scope, {"t_safety_tool_flags"}) if opsec == "active" else light_options({"t_safety_tool_flags"})
    scan(make_runtime(http), opts, SEED)
    assert outcomes[target] == ["-duc", "-ni", "-silent", "-rl", rate, "-u", target, "positional"]  # core arguments first


@pytest.mark.parametrize(
    "args",
    [["-rl", "100"], ["-rl=100"], ["--rl", "100"], ["-duc=false"], ["-ni=false"], ["-up"], ["--up=true"], ["-interactsh-url", "x.oast.example"],
     ["-proxy", "http://127.0.0.1:1"], ["--"], ["-"]],
)
def test_modules_cannot_override_core_flags(registry, http, scope_file, tool, args):
    outcomes: dict[str, str] = {}
    active_module("t_safety_tool_override", launching(lambda ent: [IN_SCOPE_IP], outcomes, args_of=lambda t: list(args)))
    scan(make_runtime(http), active_options(scope_file(), {"t_safety_tool_override"}), SEED)
    assert str(outcomes[IN_SCOPE_IP]).startswith("refused (policy)"), outcomes[IN_SCOPE_IP]
    assert tool.launches() == []


def test_every_launch_is_in_the_request_ledger(registry, http, scope_file, tool):
    outcomes: dict[str, str] = {}
    targets = [IN_SCOPE_IP, f"https://{IN_SCOPE_HOST}/"]
    dns(http, IN_SCOPE_HOST, a=[IN_SCOPE_IP])
    active_module("t_safety_tool_ledger", launching(lambda ent: targets, outcomes))
    rt = make_runtime(http)
    ledger = Ledger(rt)
    case = scan(rt, active_options(scope_file(), {"t_safety_tool_ledger"}), SEED)
    execs = [r for r in ledger.records if r.method == "EXEC"]
    assert [r.host for r in execs] == [IN_SCOPE_IP, IN_SCOPE_HOST]
    for record in execs:
        assert (record.module, record.opsec, record.egress_profile, record.status) == ("t_safety_tool_ledger", "active", "default", 0)
        assert record.url == f"exec://{TOOL}/{record.host}"
    (res,) = [r for r in case.results if r.module == "t_safety_tool_ledger"]
    assert [i.host for i in res._request_log if i.method == "EXEC"] == [IN_SCOPE_IP, IN_SCOPE_HOST]  # the run's own ledger
    assert len(tool.launches()) == 2


# --------------------------------------------------------------------------------------
# egress: the tool takes the module's egress profile, never the environment's
# --------------------------------------------------------------------------------------


def test_the_tool_runs_through_the_contact_profile_and_a_scrubbed_environment(registry, http, scope_file, tool, socks_proxy, monkeypatch):
    """With proxy_active configured the core passes it through the ToolSpec proxy flag (after the
    forced flags); the environment's proxies and netrc never reach the tool process."""
    for name in ("HTTP_PROXY", "HTTPS_PROXY", "ALL_PROXY", "http_proxy", "https_proxy", "NO_PROXY"):
        monkeypatch.setenv(name, "http://corporate-proxy.example:3128")
    monkeypatch.setenv("NETRC", "/tmp/netrc-of-the-analyst")
    outcomes: dict[str, str] = {}
    active_module("t_safety_tool_egress", launching(lambda ent: [IN_SCOPE_IP], outcomes))
    rt = make_runtime(http, settings={"proxy_active": socks_proxy.url})
    rt.http.egress.resolver = lambda host, profile: [IN_SCOPE_IP]
    ledger = Ledger(rt)
    scan(rt, active_options(scope_file(), {"t_safety_tool_egress"}), SEED)
    (launch,) = tool.launches()
    assert launch["argv"][:7] == ["-duc", "-ni", "-silent", "-rl", "10", "-proxy", socks_proxy.url], launch["argv"]
    assert launch["env"] == {}, launch["env"]  # no proxy variables, no NETRC
    assert [(r.method, r.egress_profile) for r in ledger.records if r.method == "EXEC"] == [("EXEC", "active")]
    assert http.calls == []


def test_a_tool_without_a_proxy_flag_never_bypasses_a_contact_profile(registry, http, scope_file, tool, socks_proxy):
    """A configured proxy_active and a tool that cannot be told to use it: refused (fail closed),
    never launched on the default route."""
    plain = ToolSpec(name="safetytool_noproxy", binary=tool.binary, version_args=("-version",), min_version="2.0.0", licence="MIT",
                     forced_args=("-duc",), rate_flag="-rl", max_rate=50.0)
    register_tool(plain)
    try:
        outcomes: dict[str, str] = {}

        def run(self, ent, ctx):
            try:
                ctx.net.run_tool("safetytool_noproxy", ["-u", IN_SCOPE_IP], targets=[IN_SCOPE_IP], timeout=10)
            except PolicyError as exc:
                outcomes["result"] = f"refused ({exc.reason_code}): {exc}"
            else:
                outcomes["result"] = "launched"
            return self.result(ent)

        active_module("t_safety_tool_noproxy", run)
        rt = make_runtime(http, settings={"proxy_active": socks_proxy.url})
        scan(rt, active_options(scope_file(), {"t_safety_tool_noproxy"}), SEED)
    finally:
        unregister_tool("safetytool_noproxy")
    assert outcomes["result"].startswith("refused (policy)") and "no proxy flag" in outcomes["result"], outcomes
    assert tool.launches() == []


# --------------------------------------------------------------------------------------
# kill switch
# --------------------------------------------------------------------------------------


def sleeping_tool(results: list, finished: threading.Event, stats: dict):
    def run(self, ent, ctx):
        try:
            results.append(ctx.net.run_tool(TOOL, ["--sleep", "30"], targets=[IN_SCOPE_IP], timeout=60))
            return self.result(ent)
        finally:
            stats["finished_at"] = time.monotonic()
            finished.set()

    return run


def assert_dead(launch: dict) -> None:
    for kill, ident in ((os.kill, launch["pid"]), (os.killpg, launch["pgid"])):
        with pytest.raises(ProcessLookupError):
            kill(ident, 0)


@pytest.mark.parametrize("stop", ["ctrl_c", "deadline"])
def test_the_kill_switch_kills_the_tool_within_two_seconds(registry, scope_file, tool, monkeypatch, stop):
    results: list[ToolResult] = []
    finished = threading.Event()
    stats: dict = {}
    active_module("t_safety_tool_sleep", sleeping_tool(results, finished, stats))
    rt = make_runtime(clock=SYSTEM_CLOCK)
    probe = KillSwitchProbe(rt, lambda: len(tool.launches()))
    kw = {}
    if stop == "ctrl_c":
        interrupt_engine_when(monkeypatch, lambda: bool(tool.launches()))
    else:
        kw["timeout_total"] = 1.0  # well after the launch (the fake tool starts in a few tens of ms)
    case = scan(rt, active_options(scope_file(window_start="2026-01-01T00:00:00Z", window_end="2099-12-31T23:59:59Z"), {"t_safety_tool_sleep"}, **kw), SEED)
    assert probe.fired.wait(KILL_WITHIN) and finished.wait(KILL_WITHIN), "the tool outlived the kill switch"
    assert stats["finished_at"] - probe.at < KILL_WITHIN
    (result,) = results
    assert result.killed == "cancelled" and result.returncode != 0
    (launch,) = tool.launches()
    assert_dead(launch)
    assert case.partial == {("cancelled" if stop == "ctrl_c" else "deadline"): True}


def test_the_run_deadline_kills_the_tool(registry, scope_file, tool):
    results: list[ToolResult] = []
    finished = threading.Event()
    stats: dict = {}
    active_module("t_safety_tool_overrun", sleeping_tool(results, finished, stats), timeout=1.0)
    rt = make_runtime(clock=SYSTEM_CLOCK)
    start = time.monotonic()
    scan(rt, active_options(scope_file(window_start="2026-01-01T00:00:00Z", window_end="2099-12-31T23:59:59Z"), {"t_safety_tool_overrun"}), SEED)
    assert finished.wait(KILL_WITHIN)
    assert stats["finished_at"] - start < 1.0 + KILL_WITHIN
    (result,) = results
    assert result.killed == "deadline"
    assert_dead(tool.launches()[0])
