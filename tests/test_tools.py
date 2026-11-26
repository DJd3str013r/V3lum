"""External-tool runner (WP11, A6 BR3, A7 BR11-12): a fake binary on a temporary PATH checks forced
and forbidden arguments, the rate clamp, the egress proxy flag, scope and seed checks before
launch, the kill switch within 2 s, the scrubbed environment, output caps, EXEC ledger records and
UNAVAILABLE 'package' for a missing binary."""

from __future__ import annotations

import copy
import json
import os
import socket
import stat
import sys
import threading
import time
import uuid

import pytest

from v3lum.config import Config
from v3lum.core import tools
from v3lum.core.context import RunInfo
from v3lum.core.entities import Entity
from v3lum.core.http import PolicyError
from v3lum.core.models import Opsec
from v3lum.core.net import Connector, EgressProfiles
from v3lum.core.scope import Scope
from v3lum.core.tools import ToolResult, ToolSpec, ToolUnavailable, register_tool, unregister_tool

pytestmark = pytest.mark.skipif(os.name != "posix", reason="the fake binary is a POSIX script")

FAKE_TOOL = """#!{python}
import json, os, sys, time
args = sys.argv[1:]
if args == ["-version"]:
    print("faketool v1.2.3")
    sys.exit(0)
if "--sleep" in args:
    time.sleep(float(args[args.index("--sleep") + 1]))
if "--big" in args:
    sys.stdout.write("x" * int(args[args.index("--big") + 1]))
    sys.exit(0)
if "--env" in args:
    print(json.dumps(sorted(os.environ)))
    sys.exit(0)
if "--home" in args:
    print(json.dumps({{"home": os.environ.get("HOME"), "cwd": os.getcwd()}}))
    sys.exit(0)
print(json.dumps({{"argv": args, "cwd": os.getcwd()}}))
sys.exit(int(args[args.index("--exit") + 1]) if "--exit" in args else 0)
"""

SCOPE = {
    "authorization_ref": "PENTEST-2026-042",
    "owner": "ACME S.A.",
    "contacts": ["soc@acme.example"],
    "ticket": "SEC-1",
    "window_start": "2026-01-01T00:00:00Z",
    "window_end": "2099-12-31T23:59:59Z",  # wide: tests on the real clock never age out
    "targets": {"domains": ["acme.example", "*.acme.example"], "cidrs": ["93.184.216.0/24"]},
}


def make_scope(**changes) -> Scope:
    data = copy.deepcopy(SCOPE)
    data.update(changes)
    return Scope.from_dict(data)


def cfg(**settings) -> Config:
    config = Config()
    config.settings.update(settings)
    return config


@pytest.fixture()
def fake_binary(tmp_path, monkeypatch):
    """A fake tool on a temporary PATH; returns its file name."""
    bindir = tmp_path / "bin"
    bindir.mkdir()
    name = f"v3lumfake-{uuid.uuid4().hex[:8]}"
    path = bindir / name
    path.write_text(FAKE_TOOL.format(python=sys.executable), encoding="utf-8")
    path.chmod(path.stat().st_mode | stat.S_IXUSR | stat.S_IXGRP | stat.S_IXOTH)
    monkeypatch.setenv("PATH", f"{bindir}{os.pathsep}{os.environ.get('PATH', '')}")
    return name


@pytest.fixture()
def spec(fake_binary):
    tool = ToolSpec(
        name="faketool", binary=fake_binary, version_args=("-version",), min_version="1.2.0", licence="MIT",
        forced_args=("-duc", "-ni"), forbidden_args=("-up", "-interactsh-url"), rate_flag="-rl", max_rate=50.0, proxy_flag="-proxy",
    )
    register_tool(tool)
    yield tool
    unregister_tool("faketool")


def active(**kw) -> Connector:
    kw.setdefault("scope", make_scope())
    kw.setdefault("run", RunInfo(case_id="case-1"))
    kw.setdefault("config", cfg())
    kw.setdefault("egress", EgressProfiles(kw["config"], resolver=lambda host, profile: ["93.184.216.34"]))
    return Connector(module="t_tool", opsec=Opsec.ACTIVE, **kw)


def argv_of(result: ToolResult) -> list[str]:
    return json.loads(result.stdout)["argv"]


# --------------------------------------------------------------------------------------
# arguments
# --------------------------------------------------------------------------------------


def test_forced_args_come_first_and_the_rate_is_clamped(spec):
    """The core's arguments precede the module's: a parser that stops at the first positional
    argument (Go's flag package) can never skip them."""
    conn = active()
    result = conn.run_tool("faketool", ["-u", "https://www.acme.example/"], targets=["https://www.acme.example/"])
    assert result.returncode == 0 and not result.killed and not result.truncated
    assert argv_of(result) == ["-duc", "-ni", "-rl", "10", "-u", "https://www.acme.example/"]  # min(50, A7 10/s)
    assert json.loads(result.stdout)["cwd"] != os.getcwd()  # a temporary working directory
    slower = active(scope=make_scope(limits={"max_rps": 4}))
    assert argv_of(slower.run_tool("faketool", [], targets=["93.184.216.34"]))[-2:] == ["-rl", "4"]
    positional = argv_of(conn.run_tool("faketool", ["extra-positional", "-u", "https://www.acme.example/"], targets=["https://www.acme.example/"]))
    assert positional.index("-duc") < positional.index("extra-positional")


@pytest.mark.parametrize(
    "args",
    [["--up"], ["--up=true"], ["--interactsh-url", "x.oast.example"], ["--rl", "1000"], ["--proxy", "http://x:1"], ["-duc=false"], ["--ni=false"], ["--"], ["-"]],
)
def test_every_spelling_of_a_forbidden_forced_or_core_flag_is_refused(spec, args):
    conn = active()
    with pytest.raises(PolicyError) as err:
        conn.run_tool("faketool", args, targets=["93.184.216.34"])
    assert err.value.reason_code == "policy" and conn.request_log == []


@pytest.mark.parametrize("arg", ["https://outside.example.net/", "-target=http://10.0.0.5/", "8.8.8.8", "8.8.8.8:443", "[2001:4860::1]:443"])
def test_arguments_naming_unchecked_targets_are_refused(spec, arg):
    """A module cannot list an in-scope target and point the tool elsewhere through its arguments."""
    conn = active()
    with pytest.raises(PolicyError) as err:
        conn.run_tool("faketool", ["-u", arg], targets=["https://www.acme.example/"])
    assert err.value.reason_code == "scope" and conn.request_log == []
    # the checked target itself (by name or by its checked address) is fine
    assert conn.run_tool("faketool", ["-u", "https://www.acme.example/x", "-ip", "93.184.216.34"], targets=["https://www.acme.example/"]).returncode == 0


def test_light_rate_is_one_per_second(spec):
    seed = RunInfo(entity=Entity.make("domain", "seed.example.com"), case_id="c")
    conn = Connector(
        module="t_tool", opsec=Opsec.LIGHT, run=seed, config=cfg(), egress=EgressProfiles(cfg(), resolver=lambda h, p: ["93.184.216.34"])
    )
    assert argv_of(conn.run_tool("faketool", [], targets=["seed.example.com"]))[-2:] == ["-rl", "1"]


@pytest.mark.parametrize("args", [["-up"], ["-up=true"], ["-interactsh-url", "x.oast.example"], ["-rl", "100"], ["-rl=100"], ["-proxy", "http://x:1"]])
def test_forbidden_and_core_owned_args_are_refused_before_launch(spec, args):
    conn = active()
    with pytest.raises(PolicyError) as err:
        conn.run_tool("faketool", args, targets=["93.184.216.34"])
    assert err.value.reason_code == "policy"
    assert conn.request_log == []  # nothing was launched


def test_args_are_a_list_and_targets_are_required(spec):
    conn = active()
    with pytest.raises(TypeError):
        conn.run_tool("faketool", "-u https://www.acme.example/", targets=["https://www.acme.example/"])
    with pytest.raises(PolicyError):
        conn.run_tool("faketool", [], targets=[])


# --------------------------------------------------------------------------------------
# targets: scope (ACTIVE) and seeds only (LIGHT), checked before launch
# --------------------------------------------------------------------------------------


@pytest.mark.parametrize("target", ["8.8.8.8", "https://outside.example.net/", "10.0.0.5", "intranet"])
def test_out_of_scope_targets_are_refused_before_launch(spec, target):
    conn = active()
    with pytest.raises(PolicyError):
        conn.run_tool("faketool", [], targets=["93.184.216.34", target])
    assert conn.request_log == []


def test_pivot_and_off_seed_targets_are_refused_for_light(spec):
    egress = EgressProfiles(cfg(), resolver=lambda h, p: ["93.184.216.34"])
    pivot = RunInfo(entity=Entity.make("domain", "seed.example.com"), is_seed=False, case_id="c")
    conn = Connector(module="t_tool", opsec=Opsec.LIGHT, run=pivot, config=cfg(), egress=egress)
    with pytest.raises(PolicyError) as err:
        conn.run_tool("faketool", [], targets=["seed.example.com"])
    assert err.value.reason_code == "scope" and "pivots" in str(err.value)
    seed = RunInfo(entity=Entity.make("domain", "seed.example.com"), case_id="c")
    conn = Connector(module="t_tool", opsec=Opsec.LIGHT, run=seed, config=cfg(), egress=egress)
    with pytest.raises(PolicyError) as err:
        conn.run_tool("faketool", [], targets=["other.example.net"])
    assert err.value.reason_code == "scope"
    assert conn.request_log == []


def test_passive_modules_cannot_run_tools(spec):
    with pytest.raises(PolicyError):
        Connector(module="t_tool", opsec=Opsec.PASSIVE).run_tool("faketool", [], targets=["93.184.216.34"])
    with pytest.raises(PolicyError):
        Connector(module="t_tool", disclosure="third_party", opsec=Opsec.LIGHT).run_tool("faketool", [], targets=["93.184.216.34"])


# --------------------------------------------------------------------------------------
# egress: the profile proxy goes through proxy_flag, or the run is refused
# --------------------------------------------------------------------------------------


@pytest.fixture()
def proxy_port():
    srv = socket.socket()
    srv.bind(("127.0.0.1", 0))
    srv.listen(4)
    yield srv.getsockname()[1]
    srv.close()


def test_the_egress_proxy_is_passed_through_the_proxy_flag(spec, proxy_port):
    settings = cfg(proxy_active=f"http://127.0.0.1:{proxy_port}")
    conn = active(config=settings, egress=EgressProfiles(settings, resolver=lambda h, p: ["93.184.216.34"]))
    argv = argv_of(conn.run_tool("faketool", [], targets=["93.184.216.34"]))
    assert argv[-2:] == ["-proxy", f"http://127.0.0.1:{proxy_port}"]
    assert conn.request_log[-1].egress_profile == "active"


def test_a_tool_without_proxy_flag_never_runs_off_the_profile(fake_binary, proxy_port):
    register_tool(ToolSpec(name="noproxy", binary=fake_binary, rate_flag="-rl"))
    try:
        settings = cfg(proxy_active=f"http://127.0.0.1:{proxy_port}")
        conn = active(config=settings, egress=EgressProfiles(settings, resolver=lambda h, p: ["93.184.216.34"]))
        with pytest.raises(PolicyError) as err:
            conn.run_tool("noproxy", [], targets=["93.184.216.34"])
        assert "no proxy flag" in str(err.value) and conn.request_log == []
        assert argv_of(active().run_tool("noproxy", [], targets=["93.184.216.34"]))[-2:] == ["-rl", "10"]  # default route: fine
    finally:
        unregister_tool("noproxy")


def test_a_tool_gets_a_private_home_and_never_the_proxy_credentials(spec, proxy_port, monkeypatch):
    """HOME is the run's temporary directory (the analyst's ~/.curlrc, ~/.config/nuclei, ~/.pdcp or
    ~/.netrc are never read); ToolResult.argv (evidence) shows the proxy without its credentials."""
    monkeypatch.setenv("HOME", "/home/analyst-real-home")
    out = json.loads(active().run_tool("faketool", ["--home"], targets=["93.184.216.34"]).stdout)
    assert out["home"] == out["cwd"] and out["home"] != "/home/analyst-real-home"
    settings = cfg(proxy_active=f"http://scanner:pr0xy-s3cret@127.0.0.1:{proxy_port}")
    conn = active(config=settings, egress=EgressProfiles(settings, resolver=lambda h, p: ["93.184.216.34"]))
    result = conn.run_tool("faketool", [], targets=["93.184.216.34"])
    assert f"http://scanner:pr0xy-s3cret@127.0.0.1:{proxy_port}" in argv_of(result)  # the tool itself gets it
    assert "pr0xy-s3cret" not in " ".join(result.argv) and f"http://127.0.0.1:{proxy_port}" in result.argv


def test_the_environment_is_scrubbed(spec, monkeypatch):
    monkeypatch.setenv("HTTPS_PROXY", "http://env-proxy.invalid:3128")
    monkeypatch.setenv("http_proxy", "http://env-proxy.invalid:3128")
    monkeypatch.setenv("SHODAN_API_KEY", "not-for-tools")
    monkeypatch.setenv("V3LUM_PROXY", "x")
    names = json.loads(active().run_tool("faketool", ["--env"], targets=["93.184.216.34"]).stdout)
    assert "PATH" in names
    assert not {"HTTPS_PROXY", "http_proxy", "SHODAN_API_KEY", "V3LUM_PROXY"} & set(names)


# --------------------------------------------------------------------------------------
# kill switch, deadline, output caps and the ledger
# --------------------------------------------------------------------------------------


def test_cancel_kills_the_tool_within_two_seconds(spec):
    cancel = threading.Event()
    conn = active(cancel_event=cancel)
    out: dict[str, object] = {}

    def run() -> None:
        start = time.monotonic()
        out["result"] = conn.run_tool("faketool", ["--sleep", "30"], targets=["93.184.216.34"])
        out["elapsed"] = time.monotonic() - start

    thread = threading.Thread(target=run, daemon=True)
    thread.start()
    time.sleep(0.15)
    stopped = time.monotonic()
    cancel.set()
    thread.join(timeout=3)
    assert not thread.is_alive() and time.monotonic() - stopped < 2.0
    result = out["result"]
    assert isinstance(result, ToolResult) and result.killed == "cancelled" and result.returncode != 0
    assert conn.request_log[-1].error == "killed: cancelled"


def test_the_run_deadline_and_timeout_kill_the_tool(spec):
    import v3lum.core.clock as clock_mod

    conn = active(deadline=clock_mod.SYSTEM_CLOCK.monotonic() + 0.15)
    result = conn.run_tool("faketool", ["--sleep", "30"], targets=["93.184.216.34"])
    assert result.killed == "deadline" and result.duration < 2.0
    timed = active().run_tool("faketool", ["--sleep", "30"], targets=["93.184.216.34"], timeout=0.15)
    assert timed.killed == "timeout" and timed.duration < 2.0


def test_output_is_capped(spec, monkeypatch):
    monkeypatch.setattr(tools, "STDOUT_MAX_BYTES", 100)
    result = active().run_tool("faketool", ["--big", "5000"], targets=["93.184.216.34"])
    assert len(result.stdout) == 100 and result.truncated


def test_every_launch_is_an_exec_record_per_target(spec):
    infos = []
    conn = active(on_request_info=infos.append)
    result = conn.run_tool("faketool", ["--exit", "3"], targets=["93.184.216.34", "www.acme.example:8443"])
    assert result.returncode == 3
    records = [r for r in conn.request_log if r.method == "EXEC"]
    assert [(r.host, r.port) for r in records] == [("93.184.216.34", 0), ("www.acme.example", 8443)]
    for record in records:
        assert (record.module, record.opsec, record.egress_profile, record.status) == ("t_tool", "active", "default", 3)
        assert record.url == f"exec://faketool/{record.host}" and record.error == "exit 3"
    assert infos == records


# --------------------------------------------------------------------------------------
# registry, versions and missing binaries
# --------------------------------------------------------------------------------------


def test_a_missing_binary_is_unavailable_package():
    register_tool(ToolSpec(name="absent", binary=f"v3lum-absent-{uuid.uuid4().hex[:6]}"))
    try:
        with pytest.raises(ToolUnavailable) as err:
            active().run_tool("absent", [], targets=["93.184.216.34"])
        assert (err.value.status, err.value.reason_code) == ("unavailable", "package")
        assert "PATH" in str(err.value) and "never downloads" in str(err.value)
        assert tools.version("absent") is None and tools.version_ok("absent") is None
    finally:
        unregister_tool("absent")
    with pytest.raises(ToolUnavailable):
        active().run_tool("never-registered", [], targets=["93.184.216.34"])


def test_versions_for_doctor(spec):
    assert tools.version("faketool") == "1.2.3"
    assert tools.version_ok("faketool") is True
    assert spec in tools.tools()
    older = ToolSpec(name="faketool2", binary=spec.binary, min_version="2.0")
    register_tool(older)
    try:
        assert tools.version_ok("faketool2") is False
    finally:
        unregister_tool("faketool2")


@pytest.mark.parametrize(
    ("kwargs", "needle"),
    [
        ({"name": "Bad Name", "binary": "x"}, "tool name"),
        ({"name": "t1", "binary": "/usr/bin/nmap"}, "bare file name"),
        ({"name": "t1", "binary": "x", "rate_flag": "rl"}, "command-line flag"),
        ({"name": "t1", "binary": "x", "max_rate": 0}, "max_rate"),
        ({"name": "t1", "binary": "x", "version_regex": "("}, "does not compile"),
    ],
)
def test_invalid_specs_are_refused(kwargs, needle):
    with pytest.raises(ValueError, match=needle):
        register_tool(ToolSpec(**kwargs))


def test_a_name_is_registered_once(fake_binary):
    first = ToolSpec(name="once", binary=fake_binary)
    register_tool(first)
    try:
        assert register_tool(ToolSpec(name="once", binary=fake_binary)) == first  # identical: no-op
        with pytest.raises(ValueError, match="already registered"):
            register_tool(ToolSpec(name="once", binary=fake_binary, forced_args=("-x",)))
    finally:
        unregister_tool("once")
