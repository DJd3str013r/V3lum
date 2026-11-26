"""External tools for LIGHT/ACTIVE modules (A6 BR3, A7 BR11-12): the only sanctioned subprocess path.

GPL/AGPL scanners (nuclei, nmap, ...) run only as separately installed processes found on ``PATH``:
V3LUM never imports, bundles, downloads or updates them. A module file declares the tool once at
import time and runs it through ``ctx.net.run_tool``::

    from v3lum.core.tools import ToolSpec, register_tool

    NUCLEI = register_tool(ToolSpec(
        name="nuclei", binary="nuclei", version_args=("-version",), version_regex=r"v?(\\d+\\.\\d+\\.\\d+)",
        min_version="3.3.0", licence="MIT", forced_args=("-duc", "-ni", "-silent", "-jsonl"),
        forbidden_args=("-up", "-update", "-ut", "-interactsh-url", "-iserver"), rate_flag="-rl", max_rate=10.0,
        proxy_flag="-proxy",
    ))

    result = ctx.net.run_tool("nuclei", ["-u", url, "-tags", "tech"], targets=[url])

``ctx.net.run_tool(name, args, *, targets, timeout=None) -> ToolResult`` (disclosure 'target' only):

* the binary is ``shutil.which(spec.binary)`` on PATH only; missing -> :class:`ToolUnavailable`
  (UNAVAILABLE 'package') with an install hint;
* ``shell=False``, an environment scrubbed to PATH/locale/temp variables (no proxy variables, no
  keys) with a private HOME (the run's temporary working directory: the analyst's own tool
  configuration and credentials are never read), stdin closed;
* ``forced_args`` and the core's rate and proxy flags come **first** (a positional argument in the
  module's ``args`` can never stop a parser before them); ``args`` naming a forbidden, forced or
  core-owned flag in any spelling (``-up``, ``--up``, ``--up=x``), or holding ``--`` / ``-``, are
  refused (PolicyError 'policy'); every URL or IP literal in ``args`` must be one of ``targets``
  (PolicyError 'scope');
* the ``rate_flag`` value is clamped to min(max_rate, the A7 ceiling: 10/s ACTIVE, 1/s LIGHT, lower
  with the scope's max_rps);
* the module's egress-profile proxy goes through ``proxy_flag``; a LIGHT/ACTIVE profile with a
  proxy and a tool without ``proxy_flag`` fails closed (PolicyError);
* every target is checked before launch like a socket connection (SSRF guard after resolution
  through the profile, ACTIVE scope with ``probe='network'``, LIGHT only on the analyst-typed seed:
  pivots are refused) and charged to the A7 ceilings;
* the run deadline, the kill switch and ``timeout`` kill the whole process group within 2 s;
* stdout is capped at 10 MB and stderr at 1 MB (``truncated``);
* one ``RequestInfo`` (method 'EXEC', host = target, module, egress profile, opsec) per target goes
  to the request ledger; ``ToolResult.argv`` shows the proxy without its credentials.

A tool resolves target names itself: on the default route the checked address cannot be pinned
(a name may resolve differently for the tool), and on a proxied profile the tool's own proxy support
decides whether names are resolved remotely.

``tools()`` and ``version(name)`` serve ``v3lum doctor`` (WP25).
"""

from __future__ import annotations

import os
import re
import shutil
import signal
import subprocess
import tempfile
import threading
import time
from collections.abc import Iterable
from dataclasses import dataclass
from typing import Any
from urllib.parse import urlsplit

from v3lum.core.http import ACTIVE_MAX_RPS, LIGHT_MAX_RPS, PolicyError, _opsec_label, normalize_host, parse_ip

__all__ = [
    "STDERR_MAX_BYTES",
    "STDOUT_MAX_BYTES",
    "ToolResult",
    "ToolSpec",
    "ToolUnavailable",
    "get_tool",
    "register_tool",
    "run",
    "tools",
    "unregister_tool",
    "version",
    "version_ok",
]

STDOUT_MAX_BYTES = 10 * 1024 * 1024
STDERR_MAX_BYTES = 1024 * 1024
#: seconds between kill-switch checks while a tool runs, and the SIGTERM grace before SIGKILL
_POLL = 0.05
_TERM_GRACE = 1.0
#: environment variables a tool inherits (nothing else: no proxies, no keys, no V3LUM settings)
_ENV_KEEP = (
    "PATH", "HOME", "USER", "LOGNAME", "LANG", "LANGUAGE", "LC_ALL", "LC_CTYPE", "TZ", "TMPDIR", "TEMP", "TMP",
    "SYSTEMROOT", "SYSTEMDRIVE", "COMSPEC", "PATHEXT", "WINDIR", "USERPROFILE", "APPDATA", "LOCALAPPDATA",
)
#: variables pointing at the user's profile; a launched tool gets its temporary directory instead
_HOME_VARS = ("HOME", "USERPROFILE", "APPDATA", "LOCALAPPDATA")
_NAME_RE = re.compile(r"^[a-z][a-z0-9_-]{1,63}$")
_FLAG_RE = re.compile(r"^-{1,2}[A-Za-z0-9][A-Za-z0-9_.-]*$")
_VERSION_TIMEOUT = 10.0
#: URLs inside an argument (any scheme: a tool may take tcp://, udp://, ssl:// targets too)
_ARG_URL_RE = re.compile(r"[A-Za-z][A-Za-z0-9+.-]{1,15}://[^\s\"'<>,;|]+")


class ToolUnavailable(Exception):
    """The tool's binary is not on PATH (or not registered): UNAVAILABLE 'package' with an install
    hint. ``status`` = 'unavailable', ``reason_code`` = 'package'."""

    status = "unavailable"
    reason_code = "package"

    def __init__(self, message: str) -> None:
        super().__init__(message)
        self.message = message


@dataclass(frozen=True)
class ToolSpec:
    """How V3LUM may run one external tool (see the module docstring).

    ``name`` (registry key, ``^[a-z][a-z0-9_-]{1,63}$``), ``binary`` (file name looked up on PATH,
    never a path), ``version_args``/``version_regex``/``min_version`` (doctor), ``licence``,
    ``forced_args`` (always appended), ``forbidden_args`` (refused in module args, also as
    ``flag=value``), ``rate_flag`` + ``max_rate`` (the core sets the rate, clamped to A7),
    ``proxy_flag`` (how the egress-profile proxy is passed), ``notes``."""

    name: str
    binary: str
    version_args: tuple[str, ...] = ("-version",)
    version_regex: str = r"(\d+(?:\.\d+)+)"
    min_version: str = ""
    licence: str = ""
    forced_args: tuple[str, ...] = ()
    forbidden_args: tuple[str, ...] = ()
    rate_flag: str | None = None
    max_rate: float = 10.0
    proxy_flag: str | None = None
    notes: str = ""

    def problems(self) -> list[str]:
        """Why this spec cannot be registered ([] when it is valid)."""
        out: list[str] = []
        if not _NAME_RE.match(str(self.name or "")):
            out.append(f"tool name {self.name!r} must match {_NAME_RE.pattern}")
        binary = str(self.binary or "")
        if not binary or "/" in binary or "\\" in binary or binary in (".", "..") or "\x00" in binary:
            out.append(f"binary {binary!r} must be a bare file name found on PATH (never a path)")
        for field_name in ("version_args", "forced_args", "forbidden_args"):
            value = getattr(self, field_name)
            if isinstance(value, str) or not all(isinstance(a, str) and "\x00" not in a for a in value):
                out.append(f"{field_name} must be a tuple of strings")
        for field_name in ("rate_flag", "proxy_flag"):
            value = getattr(self, field_name)
            if value is not None and (not isinstance(value, str) or not _FLAG_RE.match(value)):
                out.append(f"{field_name} {value!r} must be a command-line flag such as -rl")
        try:
            re.compile(self.version_regex)
        except (re.error, TypeError):
            out.append(f"version_regex {self.version_regex!r} does not compile")
        try:
            if not float(self.max_rate) > 0:
                out.append("max_rate must be > 0")
        except (TypeError, ValueError):
            out.append("max_rate must be a number")
        return out


@dataclass(frozen=True)
class ToolResult:
    """Outcome of one tool run: ``returncode`` (negative = killed by that signal), ``stdout``
    (capped at 10 MB) and ``stderr`` (capped at 1 MB) as text, ``duration`` (s), ``truncated``
    (an output cap was hit), ``killed`` ('' or 'cancelled' | 'deadline' | 'timeout') and ``argv``
    (the command line run, for the evidence)."""

    returncode: int
    stdout: str
    stderr: str
    duration: float
    truncated: bool
    killed: str = ""
    argv: tuple[str, ...] = ()


_REGISTRY: dict[str, ToolSpec] = {}
_LOCK = threading.Lock()


def register_tool(spec: ToolSpec) -> ToolSpec:
    """Register ``spec`` (at import time in the module file). Re-registering an identical spec is a
    no-op; a different spec under the same name, or an invalid spec, raises ValueError."""
    if not isinstance(spec, ToolSpec):
        raise TypeError("register_tool() takes a ToolSpec")
    problems = spec.problems()
    if problems:
        raise ValueError(f"tool {spec.name!r}: " + "; ".join(problems))
    with _LOCK:
        existing = _REGISTRY.get(spec.name)
        if existing is not None and existing != spec:
            raise ValueError(f"tool {spec.name!r} is already registered with a different spec")
        _REGISTRY[spec.name] = spec
    return spec


def unregister_tool(name: str) -> bool:
    """Forget a registered tool (tests and plugins). True when it was registered."""
    with _LOCK:
        return _REGISTRY.pop(name, None) is not None


def get_tool(name: str) -> ToolSpec | None:
    with _LOCK:
        return _REGISTRY.get(name)


def tools() -> list[ToolSpec]:
    """Every registered tool, by name (doctor lists them with their versions)."""
    with _LOCK:
        return [_REGISTRY[name] for name in sorted(_REGISTRY)]


def _env(home: str | None = None) -> dict[str, str]:
    """The scrubbed environment of a tool. With ``home`` (a run's temporary directory) the tool also
    gets a private HOME: it never reads the analyst's own tool configuration or credentials
    (~/.curlrc proxies, ~/.config/nuclei, ~/.pdcp, ~/.netrc...), which could move its traffic off
    the egress profile or log it in somewhere."""
    env = {name: os.environ[name] for name in _ENV_KEEP if name in os.environ}
    if home:
        for name in _HOME_VARS:
            if name == "HOME" or name in env:
                env[name] = home
    return env


def _which(spec: ToolSpec) -> str | None:
    return shutil.which(spec.binary)


def version(name: str) -> str | None:
    """The installed version of tool ``name`` (``version_args`` + ``version_regex`` over stdout and
    stderr), or None when it is not registered, not on PATH or does not answer within 10 s."""
    spec = get_tool(name)
    if spec is None:
        return None
    path = _which(spec)
    if path is None:
        return None
    try:
        proc = subprocess.run(  # noqa: S603 - fixed argv, shell=False, scrubbed environment
            [path, *spec.version_args], capture_output=True, timeout=_VERSION_TIMEOUT, env=_env(), stdin=subprocess.DEVNULL, check=False,
        )
    except (OSError, subprocess.SubprocessError):
        return None
    text = (proc.stdout or b"")[:65536].decode("utf-8", errors="replace") + "\n" + (proc.stderr or b"")[:65536].decode("utf-8", errors="replace")
    match = re.search(spec.version_regex, text)
    if match is None:
        return None
    return match.group(1) if match.groups() else match.group(0)


def _version_tuple(text: str) -> tuple[int, ...]:
    return tuple(int(p) for p in re.findall(r"\d+", text)[:4])


def version_ok(name: str) -> bool | None:
    """True when the installed version is >= ``min_version`` (or none is required), False when
    older, None when the version is unknown (missing tool, no answer)."""
    spec = get_tool(name)
    found = version(name)
    if spec is None or found is None:
        return None
    return not spec.min_version or _version_tuple(found) >= _version_tuple(spec.min_version)


# ======================================================================================
# Running a tool (Connector.run_tool)
# ======================================================================================


def _flag_of(arg: str) -> str:
    return arg.split("=", 1)[0] if arg.startswith("-") else arg


def _flag_name(arg: str) -> str:
    """The name of a flag argument whatever its spelling: '-up', '--up', '-up=x' and '--up=x' are
    all 'up' (Go and most CLI parsers accept one or two dashes). '' for a non-flag argument."""
    if not arg.startswith("-") or arg in ("-", "--"):
        return ""
    return arg.lstrip("-").split("=", 1)[0]


def _check_args(spec: ToolSpec, args: list[str]) -> None:
    """Refuse forbidden flags, the core-owned rate/proxy flags and any flag the spec forces (in every
    spelling), NUL bytes and the '--' / '-' terminators (the core's own arguments come first)."""
    owned = {_flag_name(f) for f in (spec.rate_flag, spec.proxy_flag) if f}
    forced = {_flag_name(a) for a in spec.forced_args} - {""}
    forbidden = {_flag_name(a) for a in spec.forbidden_args} - {""}
    forbidden_tokens = {a for a in spec.forbidden_args if not _flag_name(a)}
    for arg in args:
        if "\x00" in arg:
            raise PolicyError("policy", f"{spec.name}: an argument contains a NUL byte")
        if arg in ("--", "-"):
            raise PolicyError("policy", f"{spec.name}: {arg!r} is not accepted in module arguments (options end only where the core says)")
        name = _flag_name(arg)
        if (name and name in forbidden) or arg in forbidden_tokens:
            raise PolicyError("policy", f"{spec.name}: argument {_flag_of(arg)!r} is forbidden for this tool (ToolSpec.forbidden_args)")
        if name and name in owned:
            raise PolicyError("policy", f"{spec.name}: {_flag_of(arg)!r} is set by the core (rate limit and egress proxy are never chosen by modules)")
        if name and name in forced:
            raise PolicyError("policy", f"{spec.name}: {_flag_of(arg)!r} is forced by the tool spec and cannot be set or overridden by the module")


def _arg_hosts(arg: str) -> list[str]:
    """Hosts an argument designates: every URL inside it, and the argument (or the value of
    ``-flag=value``) when it is an IP literal or an ``ip:port`` / ``[v6]:port`` pair. Bare host
    names cannot be told apart from other values and are not detected."""
    found = []
    for match in _ARG_URL_RE.finditer(arg):
        try:
            host = urlsplit(match.group(0)).hostname or ""
        except ValueError:
            host = "?"  # an unparsable URL designates something: refused below
        found.append(normalize_host(host) or "?")
    value = arg.split("=", 1)[1] if arg.startswith("-") and "=" in arg else arg
    if "://" not in value:
        text = value.strip()
        if text.startswith("[") and "]" in text:
            text = text[1:].split("]", 1)[0]
        elif text.count(":") == 1:
            text = text.split(":", 1)[0]
        if parse_ip(text) is not None:
            found.append(normalize_host(text))
    return found


def _check_arg_targets(spec: ToolSpec, args: list[str], checked: list[tuple[str, int, str, str]]) -> None:
    """Every URL or IP literal in the module's arguments must be one of the checked targets (a module
    cannot list in-scope ``targets`` and scan something else through ``args``)."""
    allowed = {host for host, _port, _ip, _profile in checked} | {ip for _host, _port, ip, _profile in checked if ip}
    for arg in args:
        for host in _arg_hosts(arg):
            if host not in allowed:
                raise PolicyError(
                    "scope", f"{spec.name}: argument names {host}, which is not among the checked targets of this run (list it in targets=; A7)"
                )


def _rate(spec: ToolSpec, opsec: str, scope: Any) -> str:
    ceiling = LIGHT_MAX_RPS if opsec == "light" else ACTIVE_MAX_RPS
    limits = getattr(scope, "limits", None)
    asked = getattr(limits, "max_rps", None) if limits is not None else None
    rate = min(float(spec.max_rate), ceiling, float(asked) if asked else ceiling)
    return str(int(rate)) if float(rate).is_integer() else f"{rate:g}"


def _target_host(target: str) -> tuple[str, int]:
    """(host, port) of a target given as a URL, host, host:port, [v6]:port or IP."""
    text = str(target or "").strip()
    if not text:
        raise ValueError("an empty target")
    if "://" in text:
        parts = urlsplit(text)
        try:
            port = parts.port or 0
        except ValueError:
            port = 0
        return normalize_host(parts.hostname or ""), port
    if text.startswith("["):
        host, _, rest = text[1:].partition("]")
        port = rest[1:] if rest.startswith(":") else ""
        return normalize_host(host), int(port) if port.isdigit() else 0
    if parse_ip(text) is not None:
        return normalize_host(text), 0
    host, sep, port = text.rpartition(":")
    if sep and port.isdigit() and "/" not in text:
        return normalize_host(host), int(port)
    return normalize_host(text.split("/", 1)[0]), 0


class _Reader(threading.Thread):
    """Drains one pipe into a capped buffer (the process never blocks on a full pipe)."""

    def __init__(self, stream: Any, cap: int) -> None:
        super().__init__(daemon=True)
        self.stream = stream
        self.cap = cap
        self.data = bytearray()
        self.truncated = False

    def run(self) -> None:
        try:
            while True:
                chunk = self.stream.read(65536)
                if not chunk:
                    return
                room = self.cap - len(self.data)
                if room > 0:
                    self.data += chunk[:room]
                if len(chunk) > room:
                    self.truncated = True
        except (OSError, ValueError):
            return


def _kill(proc: subprocess.Popen[bytes]) -> None:
    """SIGTERM the process group, SIGKILL it after a short grace (within 2 s in total)."""
    if proc.poll() is not None:
        return
    if os.name == "posix":
        try:
            os.killpg(proc.pid, signal.SIGTERM)
        except (ProcessLookupError, PermissionError):
            pass
        try:
            proc.wait(timeout=_TERM_GRACE)
            return
        except subprocess.TimeoutExpired:
            pass
        try:
            os.killpg(proc.pid, signal.SIGKILL)
        except (ProcessLookupError, PermissionError):
            pass
    else:  # pragma: no cover - Windows
        proc.kill()
    try:
        proc.wait(timeout=_TERM_GRACE)
    except subprocess.TimeoutExpired:  # pragma: no cover
        pass


def run(connector: Any, name: str, args: Iterable[str], *, targets: Iterable[str], timeout: float | None = None) -> ToolResult:
    """Run tool ``name`` for ``connector`` (a ``ctx.net``) against ``targets``: the implementation of
    ``Connector.run_tool`` (see the module docstring for every rule)."""
    connector._check()
    spec = get_tool(name)
    if spec is None:
        raise ToolUnavailable(f"external tool {name!r} is not registered (a module registers its ToolSpec with tools.register_tool)")
    path = _which(spec)
    if path is None:
        raise ToolUnavailable(
            f"{spec.binary} is not on PATH: install {spec.name} from its official release yourself and put it on PATH "
            "(V3LUM never downloads, bundles or updates external tools); `v3lum doctor` shows the version found"
        )
    if isinstance(args, str):
        raise TypeError("args must be a list of arguments, not one string (no shell is ever used)")
    argv = [str(a) for a in args]
    _check_args(spec, argv)
    wanted = [str(t) for t in (targets or ())]
    if isinstance(targets, str) or not wanted:
        raise PolicyError("policy", f"{spec.name}: run_tool needs the list of targets it will contact (checked before launch)")
    opsec = _opsec_label(connector.opsec)
    checked: list[tuple[str, int, str, str]] = []
    for target in wanted:
        host, port = _target_host(target)
        if not host:
            raise PolicyError("policy", f"{spec.name}: {target!r} names no host")
        is_url = "://" in target
        name_, ips, profile = connector._authorize(host, what=f"{spec.name} run", probe="http" if is_url else "network", url=target if is_url else None)
        checked.append((name_, port, ips[0] if ips else "", profile))
    profile = checked[0][3]
    prof = connector.egress.profile(profile)
    if prof.proxy and profile != "default" and not spec.proxy_flag:
        raise PolicyError(
            "policy", f"{spec.name} has no proxy flag: it cannot run through the {profile} egress profile ({prof.setting}); refused (fail closed, A13)"
        )
    _check_arg_targets(spec, argv, checked)
    for host, _port, _ip, _profile in checked:
        connector.ceilings.charge(opsec, host, case_id=connector.case_id, scope=connector.scope)
    # The core's arguments come FIRST: many parsers (Go's flag package: nuclei, httpx...) stop at the
    # first positional argument, so forced flags appended after the module's arguments could be
    # silently ignored; the module's arguments cannot repeat them (_check_args).
    core = list(spec.forced_args)
    if spec.rate_flag:
        core += [spec.rate_flag, _rate(spec, opsec, connector.scope)]
    shown = list(core)
    if spec.proxy_flag and prof.proxy:
        core += [spec.proxy_flag, prof.proxy]
        shown += [spec.proxy_flag, prof.label]  # never the proxy credentials (ToolResult.argv goes to evidence)
    return _launch(connector, spec, [path, *core, *argv], checked, timeout, shown=(path, *shown, *argv))


def _launch(
    connector: Any, spec: ToolSpec, argv: list[str], checked: list[tuple[str, int, str, str]], timeout: float | None, *, shown: tuple[str, ...] = ()
) -> ToolResult:
    clock = connector.clock
    start = time.monotonic()
    killed = ""
    returncode = -1
    out = err = None
    error = ""
    with tempfile.TemporaryDirectory(prefix="v3lum-tool-") as workdir:
        try:
            proc = subprocess.Popen(  # noqa: S603 - argv list, shell=False, scrubbed environment
                argv, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.PIPE, env=_env(home=workdir), cwd=workdir, shell=False,
                start_new_session=os.name == "posix",
            )
        except OSError as exc:
            error = type(exc).__name__
            for host, port, ip, profile in checked:
                connector.record("EXEC", host, port, url=f"exec://{spec.name}/{host}", path=spec.name, ip=ip, profile=profile, error=error)
            raise ToolUnavailable(f"{spec.binary} could not be started: {exc.strerror or exc}") from None
        out = _Reader(proc.stdout, STDOUT_MAX_BYTES)
        err = _Reader(proc.stderr, STDERR_MAX_BYTES)
        out.start()
        err.start()
        try:
            while True:
                try:
                    returncode = proc.wait(timeout=_POLL)
                    break
                except subprocess.TimeoutExpired:
                    pass
                if connector.cancel_event is not None and connector.cancel_event.is_set():
                    killed = "cancelled"
                elif connector.deadline is not None and clock.monotonic() >= connector.deadline:
                    killed = "deadline"
                elif timeout is not None and time.monotonic() - start >= float(timeout):
                    killed = "timeout"
                if killed:
                    _kill(proc)
                    returncode = proc.returncode if proc.returncode is not None else -9
                    break
        except BaseException:
            _kill(proc)
            raise
        finally:
            out.join(timeout=_TERM_GRACE)
            err.join(timeout=_TERM_GRACE)
            duration = time.monotonic() - start
            for host, port, ip, profile in checked:
                connector.record(
                    "EXEC", host, port, url=f"exec://{spec.name}/{host}", path=spec.name, ip=ip, profile=profile,
                    status=returncode if returncode >= 0 else 0, nbytes=len(out.data), elapsed=duration,
                    error=f"killed: {killed}" if killed else (f"exit {returncode}" if returncode else ""),
                )
    return ToolResult(
        returncode=returncode,
        stdout=bytes(out.data).decode("utf-8", errors="replace"),
        stderr=bytes(err.data).decode("utf-8", errors="replace"),
        duration=round(duration, 3),
        truncated=out.truncated or err.truncated,
        killed=killed,
        argv=tuple(shown or argv),
    )
