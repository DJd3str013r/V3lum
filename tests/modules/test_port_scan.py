"""port_scan (P286): ACTIVE TCP connect scan - offline tests with tests/fakes.py and loopback listeners.

Safety expectations proven here: connections only to scope-listed IP addresses (never a domain, a
pivot, an out-of-scope or a too-large range), connect only (nothing sent on a banner port), the
proxied-egress case is 'could not test' (never closed), the kill switch stops the scan, port lists
above 1000 are refused and no CVE is ever produced.
"""

from __future__ import annotations

import socket
import threading
from pathlib import Path

import pytest

from tests.fakes import FakeHttp, make_ctx, make_runtime, module_fixture, run_module
from v3lum.core.clock import SYSTEM_CLOCK
from v3lum.core.context import ScanOptions
from v3lum.core.entities import EntityType as T
from v3lum.core.models import Opsec, Status
from v3lum.core.scope import Scope
from v3lum.modules.pentest_recon import port_scan as ps
from v3lum.modules.pentest_recon.port_scan import (
    PortScan,
    connect_state,
    egress_suspect,
    parse_banner,
    parse_ports,
    software_hint,
)

REF = "PENTEST-2026-042"
FIXTURES = Path(__file__).resolve().parents[1] / "fixtures" / "port_scan"


def scope(cidrs=("127.0.0.1/32",)):
    return Scope.from_dict({
        "authorization_ref": REF, "owner": "Engagement owner (tests)", "contacts": ["soc@acme.example"], "ticket": "T-2",
        "window_start": "2026-11-26T00:00:00Z", "window_end": "2026-11-27T00:00:00Z",
        "targets": {"domains": ["acme.example"], "cidrs": list(cidrs)},
    })


def active(sc=None):
    return ScanOptions(mode=Opsec.ACTIVE, authorized=True, authorization_ref=REF, scope=sc or scope())


def banner(name):
    return (FIXTURES / name).read_bytes()


# --------------------------------------------------------------------------------------------- parsers


@pytest.mark.parametrize(("name", "port", "protocol", "product", "version"), [
    ("banner_ssh_ok.bin", 22, "ssh", "OpenSSH", "9.6p1"),
    ("banner_ftp_vsftpd.bin", 21, "ftp", "vsftpd", "3.0.5"),
    ("banner_smtp_postfix.bin", 25, "smtp", "Postfix", None),
    ("banner_smtp_exim.bin", 25, "smtp", "Exim", "4.96"),
    ("banner_imap_dovecot.bin", 143, "imap", "Dovecot", None),
    ("banner_pop3_dovecot.bin", 110, "pop3", "Dovecot", None),
    ("banner_mysql_ok.bin", 3306, "mysql", "MySQL", None),
    ("banner_mariadb_ok.bin", 3306, "mysql", "MariaDB", None),
    ("banner_redis_protected.bin", 6379, "redis", "Redis", None),
    ("banner_vnc.bin", 5900, "vnc", "RFB", None),
    ("banner_rsync.bin", 873, "rsync", None, None),
    ("banner_telnet_iac.bin", 23, "telnet", None, None),
])
def test_banner_fixtures_parse(name, port, protocol, product, version):
    got = parse_banner(banner(name), port)
    assert got["state"] == "banner" and got["protocol"] == protocol
    assert got["product"] == product
    if version:
        assert got["version"] == version
    assert got["sha256"] and "\x1b" not in got["display"]


def test_banner_edge_cases():
    assert parse_banner(banner("banner_empty.bin"))["state"] == "silent"
    big = parse_banner(banner("banner_oversize.bin"))
    assert big["truncated"] and big["bytes"] == 1024
    odd = parse_banner(banner("banner_malformed.bin"))
    assert odd["protocol"] is None and odd["flags"]
    assert "ssh_v1_compatible" in parse_banner(banner("banner_ssh_v1compat.bin"), 22)["flags"]
    assert "host_not_allowed" in parse_banner(banner("banner_mysql_host_blocked.bin"), 3306)["flags"]
    assert parse_banner(banner("banner_smtp_rejected.bin"), 25)["flags"]
    assert parse_banner(b"\x1b[31mevil\x1b[0m\r\n")["display"].startswith("\\x1b")


def test_software_hint_never_maps_cves():
    hint = software_hint(parse_banner(banner("banner_ssh_ok.bin"), 22))
    assert hint["confidence"] == "version-inferred" and hint["backport_possible"] is True
    assert hint["cpe23"].startswith("cpe:2.3:a:openbsd:openssh:9.6:p1:")
    assert "cve" not in str(hint).lower()


def test_connect_states_are_tri_state_and_egress_is_never_closed():
    ok = module_fixture("port_scan", "connect_ok.json")
    assert {connect_state(o)["state"] for o in ok["outcomes"]} <= {"open", "closed", "filtered"}
    proxied = module_fixture("port_scan", "connect_egress_proxied.json")
    assert {connect_state(o)["state"] for o in proxied["outcomes"]} == {"could_not_test"}
    assert connect_state({"result": "timeout"})["state"] == "filtered"
    assert connect_state({"result": "refused"})["state"] == "closed"
    assert ps.outcome_of(OSError("proxy_active could not open a tunnel to 1.2.3.4:22: HTTP/1.1 403"))["errno"] == "PROXY_REFUSED"
    assert ps.outcome_of(ConnectionRefusedError(111, "refused"))["result"] == "refused"
    assert ps.outcome_of(TimeoutError("timed out"))["result"] == "timeout"


def test_uniform_local_rsts_are_egress_not_closed():
    rst = module_fixture("port_scan", "connect_local_rst.json")
    assert egress_suspect(rst["outcomes"]).startswith("egress:")
    assert egress_suspect(rst["outcomes"], special=True) is None
    closed = module_fixture("port_scan", "connect_all_closed.json")
    assert egress_suspect(closed["outcomes"]) is None


def test_port_lists_are_capped_at_1000():
    assert parse_ports("22, 80,8000-8002") == [22, 80, 8000, 8001, 8002]
    with pytest.raises(ValueError):
        parse_ports("1-1001")
    with pytest.raises(ValueError):
        parse_ports("1-600,1000-1500")
    with pytest.raises(ValueError):
        parse_ports("ssh")


def test_default_order_is_top_100_without_ics():
    ctx = make_ctx(PortScan)
    rows = ps.load_port_order(ctx.data.bundled_json(ps.PORT_ORDER))
    ports = [r["port"] for r in rows]
    assert len(ports) == 100 and len(set(ports)) == 100
    assert not {502, 102, 20000, 44818, 1911, 2404, 4840} & set(ports)
    assert {r["port"] for r in rows if r["role"] == "server_first"} == {21, 22, 23, 25, 110, 119, 143, 587, 873, 2222, 3306, 3690, 5900, 6379, 61616}


# --------------------------------------------------------------------------------------------- loopback


class Listener:
    """A loopback TCP listener: 'banner' sends bytes on accept, 'silent' accepts and says nothing."""

    def __init__(self, kind, payload=b""):
        self.kind, self.payload = kind, payload
        self.sock = socket.socket()
        self.sock.bind(("127.0.0.1", 0))
        self.sock.listen(8)
        self.port = self.sock.getsockname()[1]
        self.received = []
        self.conns = []
        self.thread = threading.Thread(target=self._serve, daemon=True)
        self.thread.start()

    def _serve(self):
        while True:
            try:
                conn, _ = self.sock.accept()
            except OSError:
                return
            self.conns.append(conn)
            if self.kind == "banner":
                conn.sendall(self.payload)
            conn.settimeout(0.5)
            try:
                data = conn.recv(64)
                if data:
                    self.received.append(data)
            except OSError:
                pass

    def close(self):
        for c in self.conns:
            c.close()
        self.sock.close()


def free_port():
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


@pytest.fixture()
def listeners(monkeypatch):
    open_ = Listener("banner", banner("banner_ssh_ok.bin"))
    silent = Listener("silent")
    closed = free_port()
    rows = [{"rank": 1, "port": open_.port, "service": "ssh", "role": "server_first", "category": "remote_admin"},
            {"rank": 2, "port": silent.port, "service": "smtp", "role": "server_first", "category": "mail"},
            {"rank": 3, "port": closed, "service": "http-alt", "role": "http", "category": "web"}]
    monkeypatch.setattr(ps, "load_port_order", lambda data: rows)
    yield open_, silent, closed
    open_.close()
    silent.close()


def settings_for(ports):
    return {"port_scan_ports": ",".join(str(p) for p in ports), "port_scan_banner_timeout": 0.3, "port_scan_connect_timeout": 1.0}


def test_loopback_open_closed_and_silent_ports(listeners):
    open_, silent, closed = listeners
    res = run_module(PortScan, "ipv4:127.0.0.1", options=active(), settings=settings_for([open_.port, silent.port, closed]))
    assert res.status is Status.OK, res.error
    summary = res.attributes["port_scan"]
    assert summary["counts"] == {"open": 2, "closed": 1, "filtered": 0, "could_not_test": 0}
    by_port = {r["port"]: r for r in summary["open"]}
    assert by_port[open_.port]["product"] == "OpenSSH" and by_port[open_.port]["banner_sha256"]
    assert "banner" not in by_port[silent.port]
    assert res.attributes["open_ports"] == sorted([open_.port, silent.port])
    assert res.attributes["software_hints"][0]["confidence"] == "version-inferred"
    assert summary["egress"].startswith("default route")
    assert {p.entity.type for p in res.pivots} == {T.PORT_SERVICE} and all(p.expand is False for p in res.pivots)
    assert not any(p.entity.type is T.CVE for p in res.pivots)
    assert open_.received == [] and silent.received == []  # nothing is ever sent to a banner port
    assert any(f.title == "Remote administration service reachable" for f in res.findings)


def test_proxied_egress_is_could_not_test_never_closed(listeners):
    open_, silent, closed = listeners
    proxy = socket.socket()
    proxy.bind(("127.0.0.1", 0))
    proxy.listen(8)

    def refuse():
        while True:
            try:
                conn, _ = proxy.accept()
            except OSError:
                return
            try:
                conn.recv(1024)
                conn.sendall(b"HTTP/1.1 403 Forbidden\r\nContent-Length: 0\r\n\r\n")
            finally:
                conn.close()

    threading.Thread(target=refuse, daemon=True).start()
    try:
        settings = settings_for([open_.port, closed]) | {"proxy_active": f"http://127.0.0.1:{proxy.getsockname()[1]}"}
        res = run_module(PortScan, "ipv4:127.0.0.1", options=active(), settings=settings)
    finally:
        proxy.close()
    assert res.status is Status.ERROR and "could not test" in res.error
    counts = res.attributes["port_scan"]["counts"]
    assert counts["closed"] == 0 and counts["open"] == 0 and counts["could_not_test"] == 2


def test_domain_seed_is_refused_without_any_connection():
    http = FakeHttp()
    res = run_module(PortScan, "domain:www.acme.example", http, options=active())
    assert res.status is Status.SKIPPED and res.reason_code == "scope"
    assert not http.calls


def test_out_of_scope_ip_gets_no_socket(listeners):
    res = run_module(PortScan, "ipv4:93.184.217.66", options=active(scope(cidrs=("93.184.216.0/24",))),
                     settings=settings_for([22]))
    assert res.status is Status.SKIPPED


def test_range_above_a_slash_29_is_refused():
    res = run_module(PortScan, "cidr:93.184.216.0/28", options=active(scope(cidrs=("93.184.216.0/24",))))
    assert res.status is Status.SKIPPED and "/29" in res.error


def test_pivots_and_unscoped_runs_never_scan(listeners):
    open_, _, _ = listeners
    pivot = run_module(PortScan, "ipv4:127.0.0.1", options=active(), settings=settings_for([open_.port]), is_seed=False, depth=1)
    assert pivot.status is Status.SKIPPED
    unscoped = run_module(PortScan, "ipv4:127.0.0.1", options=ScanOptions(mode=Opsec.ACTIVE, authorized=True, authorization_ref=REF),
                          settings=settings_for([open_.port]))
    assert unscoped.status is Status.SKIPPED
    assert open_.conns == []


def test_kill_switch_stops_the_scan(listeners, monkeypatch):
    open_, silent, closed = listeners
    rt = make_runtime(settings=settings_for([open_.port, silent.port, closed]))
    calls = {"n": 0}
    real_probe = PortScan._probe

    def probe(self, ctx, address, port, role, ct, bw):
        calls["n"] += 1
        if calls["n"] == 1:
            rt.cancel("cancelled")
        return real_probe(self, ctx, address, port, role, ct, bw)

    monkeypatch.setattr(PortScan, "_probe", probe)
    res = run_module(PortScan, "ipv4:127.0.0.1", options=active(), runtime=rt)
    assert res.partial and res.stop_reason == "cancelled"
    assert open_.conns == [] and silent.conns == []
    assert "banners" not in res.attributes.get("port_scan", {})  # banner details stay out of the attribute


def free_ports(n):
    socks = [socket.socket() for _ in range(n)]
    for s in socks:
        s.bind(("127.0.0.1", 0))
    ports = [s.getsockname()[1] for s in socks]
    for s in socks:
        s.close()
    return ports


def test_uniform_instant_rsts_are_egress_could_not_test_with_real_pacing(monkeypatch):
    """The connect timing must exclude the connector's pacing wait (<= 10 probes/s): with the real clock
    a local firewall's instant RSTs must still be recognised (could not test, never 'closed')."""
    ports = free_ports(21)
    rows = [{"rank": i, "port": p, "service": "x", "role": "client_first", "category": "web"} for i, p in enumerate(ports)]
    monkeypatch.setattr(ps, "load_port_order", lambda data: rows)
    monkeypatch.setattr(ps, "ip_problem", lambda address: "")  # treat the loopback listener host as a remote target
    real = ps.egress_suspect
    # 20 ms keeps the test stable on a loaded machine and stays far below the ~100-200 ms pacing wait
    monkeypatch.setattr(ps, "egress_suspect", lambda outcomes, **kw: real(outcomes, **{**kw, "max_local_rtt_ms": 20.0}))
    rt = make_runtime(clock=SYSTEM_CLOCK, settings={"port_scan_ports": ",".join(map(str, ports)), "port_scan_connect_timeout": 1.0})
    res = run_module(PortScan, "ipv4:127.0.0.1", options=active(), runtime=rt)
    assert res.status is Status.ERROR and "could not test" in res.error, (res.status, res.error)
    summary = res.attributes["port_scan"]
    assert summary["counts"]["closed"] == 0 and summary["counts"]["could_not_test"] == 21
    assert summary["egress_note"].startswith("egress:")


def test_connect_rtt_comes_from_the_connector_ledger_not_the_pacing_wait():
    class Info:
        def __init__(self, host, port, elapsed, method="CONNECT"):
            self.host, self.port, self.elapsed, self.method = host, port, elapsed, method

    class Ctx:
        class net:  # noqa: N801 - a stand-in for ctx.net
            request_log = [Info("198.51.100.7", 22, 0.0004), Info("198.51.100.7", 23, 0.0310), Info("2001:db8::1", 22, 0.0021)]

    assert ps.connect_rtt_ms(Ctx, "198.51.100.7", 22, fallback=180.0) == 0.4
    assert ps.connect_rtt_ms(Ctx, "2001:db8::1", 22, fallback=180.0) == 2.1
    assert ps.connect_rtt_ms(Ctx, "198.51.100.8", 22, fallback=180.0) == 180.0  # no record: the slower fallback


def test_no_port_answering_is_could_not_verify_never_a_clean_result(monkeypatch):
    from v3lum.core.net import Connector

    def silent(self, host, port, *, timeout=None):
        raise TimeoutError(f"timed out connecting to {host}:{port}")

    monkeypatch.setattr(Connector, "connect", silent)
    res = run_module(PortScan, "ipv4:127.0.0.1", options=active(), settings=settings_for([22, 80, 443]))
    assert res.status is Status.ERROR and res.reason_code == "timeout", (res.status, res.error)
    counts = res.attributes["port_scan"]["counts"]
    assert counts == {"open": 0, "closed": 0, "filtered": 3, "could_not_test": 0}
    assert not res.pivots


def test_a_slash_29_probes_hosts_only():
    import ipaddress

    assert ps.target_addresses(ipaddress.ip_network("192.0.2.8/29")) == [f"192.0.2.{i}" for i in range(9, 15)]
    assert ps.target_addresses(ipaddress.ip_network("192.0.2.8/32")) == ["192.0.2.8"]
    assert ps.target_addresses(ipaddress.ip_network("192.0.2.8/31")) == ["192.0.2.8", "192.0.2.9"]
    assert len(ps.target_addresses(ipaddress.ip_network("2001:db8::/125"))) == 8


def test_offline_selftest():
    hc = PortScan.health_check()
    assert hc.offline and hc.selftest(make_ctx(PortScan)).status == "ok"
