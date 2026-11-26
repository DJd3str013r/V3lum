"""Egress profiles (P376 cond 1-4, A13, WP11): profile selection per opsec, sessions that never trust
the environment, fail closed when proxy_light is down (nothing on the default route), Tor refused
as proxy_active, no local getaddrinfo for target hosts on socks5h, public IP on request."""

from __future__ import annotations

import socket
import threading

import pytest
import requests

from tests.fakes import FakeClock, FakeHttp
from v3lum.config import Config
from v3lum.core import http as http_mod
from v3lum.core.context import RunInfo
from v3lum.core.entities import Entity
from v3lum.core.http import HttpClient, PolicyError, RequestsTransport, reload_method_allowlist
from v3lum.core.models import Opsec
from v3lum.core.net import IPIFY_URL, Connector, EgressProfiles, public_ip
from v3lum.core.redact import redact_text


def free_port() -> int:
    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    port = s.getsockname()[1]
    s.close()
    return port


def cfg(**settings) -> Config:
    config = Config()
    config.settings.update(settings)
    return config


class FakeSocks5:
    """A minimal SOCKS5 server on loopback (no auth): records each CONNECT request (address type,
    address, port) and answers the tunnelled request with a fixed HTTP 200 (or echoes a banner)."""

    def __init__(self, *, refuse: bool = False, banner: bytes = b"") -> None:
        self.refuse = refuse
        self.banner = banner
        self.requests: list[tuple[str, str, int]] = []
        self.srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.srv.bind(("127.0.0.1", 0))
        self.srv.listen(8)
        self.srv.settimeout(0.05)
        self.port = self.srv.getsockname()[1]
        self.stop = threading.Event()
        self.thread = threading.Thread(target=self._serve, daemon=True)
        self.thread.start()

    @property
    def url(self) -> str:
        return f"socks5h://127.0.0.1:{self.port}"

    def _recv(self, conn: socket.socket, n: int) -> bytes:
        data = b""
        while len(data) < n:
            chunk = conn.recv(n - len(data))
            if not chunk:
                raise OSError("closed")
            data += chunk
        return data

    def _serve(self) -> None:
        while not self.stop.is_set():
            try:
                conn, _ = self.srv.accept()
            except (TimeoutError, OSError):
                continue
            threading.Thread(target=self._handle, args=(conn,), daemon=True).start()

    def _handle(self, conn: socket.socket) -> None:
        with conn:
            try:
                conn.settimeout(2)
                _ver, nmethods = self._recv(conn, 2)
                self._recv(conn, nmethods)
                conn.sendall(b"\x05\x00")
                _ver, _cmd, _rsv, atyp = self._recv(conn, 4)
                if atyp == 1:
                    addr, kind = socket.inet_ntoa(self._recv(conn, 4)), "ipv4"
                elif atyp == 4:
                    addr, kind = socket.inet_ntop(socket.AF_INET6, self._recv(conn, 16)), "ipv6"
                else:
                    addr, kind = self._recv(conn, self._recv(conn, 1)[0]).decode(), "name"
                port = int.from_bytes(self._recv(conn, 2), "big")
                self.requests.append((kind, addr, port))
                if self.refuse:
                    conn.sendall(b"\x05\x05\x00\x01" + b"\x00" * 6)
                    return
                conn.sendall(b"\x05\x00\x00\x01" + b"\x00" * 6)
                if self.banner:
                    conn.sendall(self.banner)
                    conn.recv(64)
                    return
                conn.recv(4096)
                conn.sendall(b"HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nContent-Length: 7\r\nConnection: close\r\n\r\nvia-tor")
            except OSError:
                return

    def close(self) -> None:
        self.stop.set()
        self.srv.close()
        self.thread.join(timeout=2)


@pytest.fixture()
def socks_server():
    server = FakeSocks5()
    yield server
    server.close()


# --------------------------------------------------------------------------------------
# selection and sessions
# --------------------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("settings", "opsec", "expected"),
    [
        ({}, Opsec.PASSIVE, "default"),
        ({}, Opsec.LIGHT, "default"),
        ({}, Opsec.ACTIVE, "default"),
        ({"proxy_light": "http://127.0.0.1:3128"}, Opsec.PASSIVE, "default"),  # third-party APIs never move
        ({"proxy_light": "http://127.0.0.1:3128"}, Opsec.LIGHT, "light"),
        ({"proxy_light": "http://127.0.0.1:3128"}, Opsec.ACTIVE, "default"),
        ({"proxy_active": "http://127.0.0.1:3129"}, Opsec.ACTIVE, "active"),
        ({"proxy_active": "http://127.0.0.1:3129"}, "light", "default"),
        ({"proxy": "http://corp-proxy:3128", "proxy_light": "socks5h://127.0.0.1:9050"}, "passive", "default"),
    ],
)
def test_profile_selection_per_opsec(settings, opsec, expected):
    egress = EgressProfiles(cfg(**settings))
    assert egress.profile_for(opsec) == expected
    assert egress.profile_for(opsec, tags=("malicious", "phishing")) == expected  # case tags never move traffic


def test_light_and_active_sessions_never_trust_the_environment(monkeypatch):
    monkeypatch.setenv("HTTPS_PROXY", "http://env-proxy.invalid:8080")
    egress = EgressProfiles(cfg(proxy_light="http://127.0.0.1:3128", proxy_active="socks5h://127.0.0.1:1080"))
    name, light = egress.session_for(Opsec.LIGHT)
    assert name == "light" and light.trust_env is False
    assert light.proxies == {"http": "http://127.0.0.1:3128", "https": "http://127.0.0.1:3128"}
    assert isinstance(light.auth, http_mod._NoAuth)  # never ~/.netrc credentials
    name, active = egress.session_for(Opsec.ACTIVE)
    assert name == "active" and active.trust_env is False and active.proxies["https"] == "socks5h://127.0.0.1:1080"
    # the environment proxy never reaches a profile session's requests
    merged = light.merge_environment_settings("https://target.example.test/", {}, None, None, None)
    assert dict(merged["proxies"]) == {"http": "http://127.0.0.1:3128", "https": "http://127.0.0.1:3128"}  # no env proxy
    name, default = egress.session_for(Opsec.PASSIVE)
    assert name == "default" and default.trust_env is True  # the default route keeps the corporate environment


def test_socks5_is_upgraded_to_remote_dns_and_credentials_never_show():
    egress = EgressProfiles(cfg(proxy_light="socks5://analyst:pa55w0rd-x9@127.0.0.1:1080"))
    prof = egress.profile("light")
    assert prof.proxy.startswith("socks5h://") and prof.remote_dns
    assert prof.label == "socks5h://127.0.0.1:1080"
    assert "pa55w0rd-x9" not in redact_text("proxy said pa55w0rd-x9")  # registered with the redactor
    assert egress.describe()[1] == {"name": "light", "setting": "proxy_light", "configured": True, "proxy": "socks5h://127.0.0.1:1080", "tor": False, "error": ""}


@pytest.mark.parametrize(
    ("value", "needle"),
    [("ftp://127.0.0.1:21", "unsupported proxy scheme"), ("socks5h://127.0.0.1", "needs a port"), ("http://", "no host")],
)
def test_unusable_profiles_refuse_their_requests(value, needle):
    egress = EgressProfiles(cfg(proxy_light=value))
    assert any(needle in e for e in egress.errors)
    with pytest.raises(PolicyError):
        egress.session_for(Opsec.LIGHT)
    http = FakeHttp(clock=FakeClock())
    with pytest.raises(PolicyError):
        HttpClient(transport=http, egress=egress).request("GET", "https://93.184.216.34/", opsec="light")
    assert not http.calls  # never resent on the default route


# --------------------------------------------------------------------------------------
# fail closed
# --------------------------------------------------------------------------------------


def test_an_unreachable_proxy_light_never_falls_back_to_the_default_route():
    dead = f"http://127.0.0.1:{free_port()}"
    http = FakeHttp(clock=FakeClock()).add("GET", "https://93.184.216.34/", text="would answer")
    c = HttpClient(transport=http, settings=cfg(proxy_light=dead), retries=2)
    with pytest.raises(PolicyError) as err:
        c.request("GET", "https://93.184.216.34/", opsec="light")
    assert err.value.reason_code == "policy" and "proxy_light unreachable: request refused" in str(err.value)
    run = RunInfo(entity=Entity.make("domain", "seed.example.com"), case_id="c")
    with pytest.raises(PolicyError) as err:  # a bound request (DoH through the profile first)
        c.request("GET", "https://seed.example.com/", opsec="light", run=run)
    assert "proxy_light unreachable" in str(err.value)
    assert http.calls == []  # asserted on the default-route transport: nothing was sent
    conn = Connector(module="t_net", opsec=Opsec.LIGHT, config=cfg(proxy_light=dead), run=RunInfo(internal_seed=True))
    with pytest.raises(PolicyError) as err:
        conn.connect("93.184.216.34", 443, timeout=1)
    assert "proxy_light unreachable" in str(err.value) and conn.connections == 0


def test_a_proxy_dying_mid_request_is_refused_not_retried(monkeypatch):
    """The transport reports the proxy itself unreachable: PolicyError, no retry, no fallback."""
    http = FakeHttp(clock=FakeClock())
    egress = EgressProfiles(cfg(proxy_light=f"http://127.0.0.1:{free_port()}"))
    light = RequestsTransport(proxy=egress.profile("light").proxy, trust_env=False)
    egress._transports["light"] = light
    egress._reachable["light"] = 1e18  # the proxy answered the reachability probe a moment ago
    c = HttpClient(transport=http, egress=egress, retries=3)
    with pytest.raises(PolicyError) as err:
        c.request("GET", "http://93.184.216.34/", opsec="light")
    assert "proxy_light unreachable" in str(err.value)
    assert http.calls == []


def test_a_reachable_proxy_passes_the_probe():
    listener = socket.socket()
    listener.bind(("127.0.0.1", 0))
    listener.listen(1)
    try:
        egress = EgressProfiles(cfg(proxy_light=f"http://127.0.0.1:{listener.getsockname()[1]}"))
        egress.ensure_reachable("light")  # no exception
        egress.ensure_reachable("default")  # the default route is never probed
    finally:
        listener.close()


# --------------------------------------------------------------------------------------
# Tor
# --------------------------------------------------------------------------------------


def test_tor_is_refused_as_proxy_active_and_allowed_as_proxy_light(tmp_path):
    egress = EgressProfiles(cfg(proxy_active="socks5h://127.0.0.1:9050", proxy_light="socks5h://127.0.0.1:9150"))
    active, light = egress.profile("active"), egress.profile("light")
    assert active.tor and "Tor is allowed for LIGHT reads only" in active.error
    assert light.tor and light.error == ""
    assert any("proxy_active" in e for e in egress.errors)
    with pytest.raises(PolicyError):
        egress.session_for(Opsec.ACTIVE)
    http = FakeHttp(clock=FakeClock()).add("*", "https://93.184.216.34/", text="ok")
    with pytest.raises(PolicyError):
        HttpClient(transport=http, egress=egress).request("GET", "https://93.184.216.34/", opsec="active")
    assert http.calls == []
    # Tor carries LIGHT reads only, even for a method an approved fragment would allow
    folder = tmp_path / "allow"
    folder.mkdir()
    (folder / "t_tor.json").write_text(
        '{"schema": "v3lum.method_allow/1", "module": "t_tor", "methods": {"POST": "read-only search form"}, "approved_by": "a", "decision_ref": "b"}',
        encoding="utf-8",
    )
    reload_method_allowlist(extra_dirs=[folder])
    try:
        tor_egress = EgressProfiles(cfg(proxy_light="socks5h://127.0.0.1:9050"), transports={"light": FakeHttp(clock=FakeClock())})
        with pytest.raises(PolicyError) as err:
            HttpClient(transport=http, egress=tor_egress).request("POST", "https://93.184.216.34/", opsec="light", module="t_tor")
        assert "LIGHT reads only" in str(err.value)
    finally:
        reload_method_allowlist(extra_dirs=())


# --------------------------------------------------------------------------------------
# no local DNS for target hosts through a socks5h profile
# --------------------------------------------------------------------------------------


def test_no_local_getaddrinfo_for_targets_on_socks5h(socks_server, monkeypatch):
    looked_up: list[str] = []
    guarded = socket.getaddrinfo

    def spy(host, *args, **kwargs):
        looked_up.append(str(host))
        return guarded(host, *args, **kwargs)

    monkeypatch.setattr(socket, "getaddrinfo", spy)
    default = FakeHttp(clock=FakeClock())
    egress = EgressProfiles(cfg(proxy_light=socks_server.url), resolver=lambda host, profile: ["93.184.216.34"])
    c = HttpClient(transport=default, egress=egress, settings=cfg(proxy_light=socks_server.url), retries=0, timeout=5)
    run = RunInfo(entity=Entity.make("url", "http://target.example.test/x"), case_id="c")
    resp = c.request("GET", "http://target.example.test/x", opsec="light", run=run)
    assert resp.status == 200 and resp.content == b"via-tor"
    assert socks_server.requests == [("name", "target.example.test", 80)]  # the proxy resolves the name
    assert "target.example.test" not in looked_up  # never resolved locally
    assert set(looked_up) <= {"127.0.0.1"}  # only the proxy itself
    assert default.calls == []  # and nothing on the default route


def test_profile_resolution_goes_through_the_profile():
    """Without an injected resolver, a bound LIGHT request resolves the target with DoH sent
    through the light transport (never the default route, never getaddrinfo)."""
    from tests.fakes import add_dns

    light = FakeHttp(clock=FakeClock())
    add_dns(light, "target.example.test", "A", ["93.184.216.34"])
    add_dns(light, "target.example.test", "AAAA", [])
    light.add("GET", "https://target.example.test/", text="ok")
    default = FakeHttp(clock=FakeClock())
    egress = EgressProfiles(cfg(proxy_light="http://127.0.0.1:3128"), transports={"light": light})
    infos = []
    c = HttpClient(transport=default, egress=egress, retries=0, on_request_info=infos.append)
    run = RunInfo(entity=Entity.make("url", "https://target.example.test/"), case_id="c")
    assert c.request("GET", "https://target.example.test/", opsec="light", run=run).status == 200
    assert default.calls == []
    assert {i.egress_profile for i in infos} == {"light"}
    assert "pin_ip" not in light.calls[-1]  # a proxied route sends the name: no pinning
    assert any("dns.google" in call["url"] for call in light.calls)


# --------------------------------------------------------------------------------------
# public IP of a profile (doctor --egress, on request only)
# --------------------------------------------------------------------------------------


def test_public_ip_per_profile_on_request_only():
    default = FakeHttp(clock=FakeClock()).add("GET", IPIFY_URL, json={"ip": "198.51.100.7"})
    light = FakeHttp(clock=FakeClock()).add("GET", IPIFY_URL, json={"ip": "2001:db8::7"})
    egress = EgressProfiles(cfg(proxy_light="socks5h://127.0.0.1:9050"), transports={"light": light})
    c = HttpClient(transport=default, egress=egress)
    assert public_ip("default", client=c) == "198.51.100.7"
    assert egress.public_ip("light", client=c) == "2001:db8::7"
    assert public_ip("active", client=c) == "198.51.100.7"  # unconfigured: the default route
    assert public_ip("default", client=c) == "198.51.100.7"
    assert len(default.calls) == 3  # never cached
    broken = FakeHttp(clock=FakeClock()).add("GET", IPIFY_URL, json={"error": "nope"})
    egress2 = EgressProfiles(cfg())
    assert public_ip("default", client=HttpClient(transport=broken, egress=egress2), egress=egress2) is None
    assert "without an IP" in egress2.last_error


def test_unknown_profile_names_are_refused():
    with pytest.raises(PolicyError):
        HttpClient(transport=FakeHttp(clock=FakeClock())).request("GET", "https://api.ipify.org/", egress_profile="tor")
    with pytest.raises(KeyError):
        EgressProfiles(cfg()).effective("tor")


def test_requests_session_for_the_default_route_is_the_clients_own():
    transport = RequestsTransport(proxy="", trust_env=True)
    egress = EgressProfiles(cfg(), default_transport=transport)
    name, sess = egress.session_for("passive")
    assert name == "default" and sess is transport.session()
    assert isinstance(sess, requests.Session)


def test_onion_reads_go_through_a_socks_light_route_by_name(socks_server):
    """An .onion read travels by name through the SOCKS LIGHT route (Tor, whatever its port) and is
    never resolved; it never takes the default route and never carries anything but GET/HEAD."""
    onion = "http://" + "b" * 56 + ".onion/index"
    default = FakeHttp(clock=FakeClock())
    c = HttpClient(transport=default, settings=cfg(proxy_light=socks_server.url), retries=0, timeout=5)
    run = RunInfo(entity=Entity.make("url", onion), case_id="c")
    resp = c.request("GET", onion, opsec="light", run=run)
    assert resp.status == 200
    assert socks_server.requests[-1] == ("name", "b" * 56 + ".onion", 80)
    with pytest.raises(PolicyError):
        c.request("POST", onion, opsec="light", run=run, module="t_onion")
    with pytest.raises(PolicyError):
        HttpClient(transport=default, settings=cfg(proxy_light="http://127.0.0.1:3128")).request("GET", onion, opsec="light")
    assert default.calls == []
