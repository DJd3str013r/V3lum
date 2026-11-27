"""Offline tests for the ACTIVE axfr module (P281).

The AXFR path is exercised against a loopback TCP DNS server the test itself starts on 127.0.0.1
(FC8): target-contact code never reaches a third-party host. The scope lists ``zone.test`` and
127.0.0.0/8, and the nameserver resolves (through FakeHttp DoH) to 127.0.0.1, so the ACTIVE scope
binding and SSRF guard allow the loopback probe while refusing everything else.
"""

from __future__ import annotations

import socket
import struct
import threading
from collections.abc import Callable, Iterator
from typing import Any

import pytest

from tests.fakes import FakeClock, FakeHttp, add_dns, make_runtime, module_fixture, run_module
from v3lum.core.context import ScanOptions
from v3lum.core.models import Opsec, Status
from v3lum.core.scope import Scope
from v3lum.modules.pentest_recon.axfr import (
    Axfr,
    classify_ns_managed,
    parse_zone_text,
    scan_txt_for_secret_markers,
)

pytest.importorskip("dns", reason="dnspython (extra 'full') is required for the AXFR tests")

import dns.message  # noqa: E402
import dns.rcode  # noqa: E402
import dns.rrset  # noqa: E402

REF = "PENTEST-2026-281"
DOMAIN = "zone.test"
NS = "ns1.zone.test"
WINDOW = ("2026-11-26T00:00:00Z", "2026-11-27T00:00:00Z")

MANAGED = [
    {"name": "Cloudflare", "ns_markers": [".ns.cloudflare.com", ".cloudflare.com"], "asns": [13335]},
    {"name": "Route 53", "ns_markers": ["awsdns-", "awsdns"], "asns": [16509]},
    {"name": "registro.br", "ns_markers": [".dns.br", ".registro.br"], "asns": [22548]},
]


# --------------------------------------------------------------------------------------
# a loopback TCP DNS server that speaks just enough AXFR
# --------------------------------------------------------------------------------------


class LoopbackDns:
    """Answers one AXFR request on 127.0.0.1 with a canned message, then closes. ``mode`` is
    'zone' (a full transfer), 'refused' (REFUSED rcode) or 'empty' (NOERROR, no records)."""

    def __init__(self, mode: str = "zone") -> None:
        self.mode = mode
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.sock.bind(("127.0.0.1", 0))
        self.sock.listen(1)
        self.port = int(self.sock.getsockname()[1])
        self.requests: list[bytes] = []
        self._release = threading.Event()
        self._thread = threading.Thread(target=self._serve, daemon=True)
        self._thread.start()

    def _serve(self) -> None:
        try:
            conn, _addr = self.sock.accept()
        except OSError:
            return
        with conn:
            header = _recv(conn, 2)
            if len(header) < 2:
                return
            (qlen,) = struct.unpack(">H", header)
            query_wire = _recv(conn, qlen)
            self.requests.append(query_wire)
            try:
                query = dns.message.from_wire(query_wire)
            except Exception:  # noqa: BLE001
                return
            if self.mode == "stall":
                # announce a long message, send one byte, then go silent (a slow-drip server)
                conn.sendall(struct.pack(">H", 4000) + b"\x00")
                self._release.wait(10)
                return
            reply = self._reply(query)
            conn.sendall(struct.pack(">H", len(reply)) + reply)

    def _reply(self, query: Any) -> bytes:
        resp = dns.message.make_response(query)
        if self.mode == "refused":
            resp.set_rcode(dns.rcode.REFUSED)
            return resp.to_wire()
        if self.mode == "servfail":
            resp.set_rcode(dns.rcode.SERVFAIL)
            return resp.to_wire()
        if self.mode == "empty":
            return resp.to_wire()
        soa = dns.rrset.from_text(
            "zone.test.", 3600, "IN", "SOA", "ns1.zone.test. host.zone.test. 1 7200 3600 1209600 3600"
        )
        www = dns.rrset.from_text("www.zone.test.", 3600, "IN", "A", "192.0.2.10")
        mail = dns.rrset.from_text("mail.zone.test.", 3600, "IN", "A", "192.0.2.11")
        txt = dns.rrset.from_text("zone.test.", 3600, "IN", "TXT", '"api_key=AKIAIOSFODNN7EXAMPLE"')
        resp.answer.extend([soa, www, mail, txt, soa])
        return resp.to_wire()

    def close(self) -> None:
        self._release.set()
        try:
            self.sock.close()
        except OSError:
            pass


def _recv(conn: socket.socket, n: int) -> bytes:
    chunks: list[bytes] = []
    while n > 0:
        chunk = conn.recv(n)
        if not chunk:
            break
        chunks.append(chunk)
        n -= len(chunk)
    return b"".join(chunks)


@pytest.fixture()
def server_factory() -> Iterator[Callable[[str], LoopbackDns]]:
    created: list[LoopbackDns] = []

    def make(mode: str = "zone") -> LoopbackDns:
        srv = LoopbackDns(mode)
        created.append(srv)
        return srv

    yield make
    for srv in created:
        srv.close()


# --------------------------------------------------------------------------------------
# helpers
# --------------------------------------------------------------------------------------


def _scope(**changes: Any) -> Scope:
    data = {
        "authorization_ref": REF,
        "owner": "AXFR engagement",
        "contacts": ["soc@zone.test"],
        "ticket": "PT-281",
        "window_start": WINDOW[0],
        "window_end": WINDOW[1],
        "targets": {"domains": [DOMAIN, f"*.{DOMAIN}"], "cidrs": ["127.0.0.0/8"]},
    }
    data.update(changes)
    return Scope.from_dict(data)


def _active_options(scope: Scope, port: int) -> ScanOptions:
    return ScanOptions(
        mode=Opsec.ACTIVE, authorized=True, authorization_ref=REF, scope=scope,
        include={"axfr"}, threads=1, save_evidence=False,
    )


def _run(server: LoopbackDns | None, *, ns_records: list[str] | None = None, ns_ip: str = "127.0.0.1",
         scope: Scope | None = None, port: int | None = None, **kw: Any) -> Any:
    clock = FakeClock()
    http = FakeHttp(clock=clock)
    add_dns(http, DOMAIN, "NS", ns_records if ns_records is not None else [NS])
    add_dns(http, NS, "A", [ns_ip])
    add_dns(http, NS, "AAAA", [])
    scope = scope or _scope()
    the_port = port if port is not None else (server.port if server else 53)
    rt = make_runtime(http, clock=clock, settings={"axfr_port": the_port})
    return run_module(
        Axfr, f"domain:{DOMAIN}", runtime=rt,
        options=_active_options(scope, the_port), **kw,
    )


# --------------------------------------------------------------------------------------
# pure parser tests
# --------------------------------------------------------------------------------------


def test_classify_ns_managed_matches_and_skips():
    assert classify_ns_managed("ns-cloud-a1.googledomains.com", MANAGED) is None  # not in this subset
    assert classify_ns_managed("kate.ns.cloudflare.com", MANAGED) == "Cloudflare"
    assert classify_ns_managed("ns-123.awsdns-45.org", MANAGED) == "Route 53"
    assert classify_ns_managed("a.dns.br", MANAGED) == "registro.br"
    assert classify_ns_managed("ns1.self-hosted.test", MANAGED) is None
    assert classify_ns_managed(None, MANAGED) is None


def test_classify_ns_managed_by_asn():
    assert classify_ns_managed("ns1.example.test", MANAGED, asn=13335) == "Cloudflare"
    assert classify_ns_managed("ns1.example.test", MANAGED, asn=64500) is None


def test_parse_zone_text_defensive():
    assert parse_zone_text(None) == []
    assert parse_zone_text("; just a comment\n$ORIGIN zone.test.\n") == []
    recs = parse_zone_text("www.zone.test. 3600 IN A 192.0.2.10\nzone.test. 3600 IN TXT \"v=spf1 -all\"")
    assert recs[0] == {"name": "www.zone.test", "ttl": 3600, "rtype": "A", "value": "192.0.2.10"}
    assert recs[1]["rtype"] == "TXT" and recs[1]["value"] == "v=spf1 -all"


def test_scan_txt_secret_markers():
    assert scan_txt_for_secret_markers(["v=spf1 include:_spf.google.com -all"]) is None
    assert scan_txt_for_secret_markers(["api_key=AKIAIOSFODNN7EXAMPLE"]) is not None
    assert scan_txt_for_secret_markers(12345) is None


def test_parse_zone_text_on_trimmed_fixture():
    data = module_fixture("axfr", "ok.json")
    recs = parse_zone_text(data["zone_text"])
    assert len(recs) >= 7
    names = {r["name"] for r in recs if r["rtype"] in ("A", "AAAA", "CNAME")}
    assert {"www.example.com", "dev.example.com", "vpn.example.com", "internal.example.com"} <= names
    txt = [r["value"] for r in recs if r["rtype"] == "TXT"]
    assert scan_txt_for_secret_markers(txt) is not None  # the _deploy TXT carries an AWS example key


def test_classify_ns_managed_over_fixture_ns_list():
    data = module_fixture("axfr", "ns_list.json")
    for ns in data["nameservers"]:
        skipped = classify_ns_managed(ns["name"], MANAGED + [
            {"name": "NS1", "ns_markers": [".nsone.net"]},
            {"name": "Google Cloud DNS", "ns_markers": [".googledomains.com"]},
        ])
        assert (skipped is not None) == (ns["expect"] == "skip"), ns["name"]


# --------------------------------------------------------------------------------------
# the ACTIVE path against the loopback server
# --------------------------------------------------------------------------------------


def test_successful_transfer_is_high_with_pivots(server_factory):
    server = server_factory("zone")
    res = _run(server)
    assert res.status is Status.OK
    high = [f for f in res.findings if f.severity.name == "HIGH"]
    assert high and "zone transfer" in high[0].title.lower()
    assert list(high[0].attack) == ["T1590.002"]
    # transferred names become subdomain pivots, never auto-expanded
    pivots = {p.entity.value for p in res.pivots}
    assert "www.zone.test" in pivots and "mail.zone.test" in pivots
    assert all(p.expand is False for p in res.pivots)
    # the zone_transfer attribute records a confirmed per-NS state
    zt = res.attributes["zone_transfer"]
    assert any(a["state"] == "confirmed" and a["record_count"] >= 3 for a in zt)


def test_transferred_txt_secret_is_scrubbed_and_flagged(server_factory):
    server = server_factory("zone")
    res = _run(server)
    # the raw AWS example key never survives anywhere in the result
    from tests.fakes import assert_no_secret

    assert_no_secret("AKIAIOSFODNN7EXAMPLE", res.attributes, res.findings, res.raw)
    assert any("secret" in f.title.lower() for f in res.findings)


def test_refused_transfer_is_info_good(server_factory):
    server = server_factory("refused")
    res = _run(server)
    assert res.status is Status.OK
    assert not [f for f in res.findings if f.severity.name in ("HIGH", "MEDIUM")]
    info = [f for f in res.findings if f.severity.name == "INFO"]
    assert info and "refused" in info[0].title.lower()
    zt = res.attributes["zone_transfer"]
    assert any(a["state"] == "not_observed" for a in zt)


def test_managed_provider_nameserver_is_skipped_not_tested():
    # the NS is Cloudflare: never contacted, recorded as a managed-provider skip (no server needed)
    res = _run(None, ns_records=["kate.ns.cloudflare.com"], scope=_scope(
        targets={"domains": [DOMAIN, f"*.{DOMAIN}", "ns.cloudflare.com", "*.ns.cloudflare.com"], "cidrs": ["127.0.0.0/8"]},
    ))
    zt = res.attributes["zone_transfer"]
    assert zt and zt[0]["state"] == "skipped" and "managed provider" in zt[0]["reason"].lower()
    assert not res.findings
    assert res.status is Status.SKIPPED  # nothing was tested: never OK/empty (rule 5)


def test_nameserver_out_of_scope_is_skipped():
    # the NS name and its address are both outside the scope: skipped, never contacted
    clock = FakeClock()
    http = FakeHttp(clock=clock)
    add_dns(http, DOMAIN, "NS", ["ns1.external-dns.test"])
    add_dns(http, "ns1.external-dns.test", "A", ["203.0.113.9"])
    add_dns(http, "ns1.external-dns.test", "AAAA", [])
    rt = make_runtime(http, clock=clock, settings={"axfr_port": 53})
    res = run_module(Axfr, f"domain:{DOMAIN}", runtime=rt, options=_active_options(_scope(), 53))
    zt = res.attributes["zone_transfer"]
    assert zt and zt[0]["state"] == "skipped" and "scope" in zt[0]["reason"].lower()


def test_tcp53_refused_is_could_not_test(server_factory):
    # point the module at a loopback port nothing listens on: connection refused = could not test
    free = socket.socket()
    free.bind(("127.0.0.1", 0))
    dead_port = int(free.getsockname()[1])
    free.close()
    res = _run(None, port=dead_port, scope=_scope())
    assert res.status is Status.ERROR  # could not test, never 'empty'/'closed'
    assert "could not test" in res.error.lower()
    zt = res.attributes["zone_transfer"]
    assert zt and zt[0]["state"] == "could_not_test"


def test_servfail_is_could_not_test_not_refused(server_factory):
    # only REFUSED/NOTAUTH/NOTIMP read as 'refused: good'; SERVFAIL did not answer the question
    server = server_factory("servfail")
    res = _run(server)
    assert res.status is Status.ERROR
    assert not [f for f in res.findings if "refused" in f.title.lower()]
    zt = res.attributes["zone_transfer"]
    assert zt[0]["state"] == "could_not_test" and "SERVFAIL" in zt[0]["reason"]


def test_slow_drip_server_is_cut_at_the_per_ns_cap(server_factory, monkeypatch):
    from v3lum.modules.pentest_recon import axfr as axfr_mod

    monkeypatch.setattr(axfr_mod, "MAX_SECONDS", 1.0)  # FC4 total cap per NS (30 s in production)
    server = server_factory("stall")
    import time as _time

    start = _time.monotonic()
    res = _run(server)
    assert _time.monotonic() - start < 8.0  # a total cap, not a per-read timeout
    zt = res.attributes["zone_transfer"]
    assert zt[0]["state"] == "could_not_test"
    assert res.status is Status.ERROR


def test_pivots_and_text_extracted_entities_never_transfer(server_factory):
    # FC1: never on pivots or on entities extracted from text/files - the NS is never contacted
    for kw in ({"is_seed": False, "depth": 1}, {"provenance": [("file:dump.txt", "mentions", "ioc_extract")]}):
        server = server_factory("zone")
        res = _run(server, **kw)
        assert res.status is Status.SKIPPED
        assert server.requests == []
    assert Axfr.run_on == "seeds"


def test_unresolvable_nameservers_is_could_not_verify():
    clock = FakeClock()
    http = FakeHttp(clock=clock)
    from tests.fakes import add_dns_failure

    add_dns_failure(http, DOMAIN, "NS", kind="servfail")
    add_dns_failure(http, DOMAIN, "NS", kind="servfail", provider="cloudflare")
    rt = make_runtime(http, clock=clock, settings={"axfr_port": 53})
    res = run_module(Axfr, f"domain:{DOMAIN}", runtime=rt, options=_active_options(_scope(), 53))
    assert res.status is Status.ERROR
    assert "could not verify" in res.error.lower()


def test_health_selftest_offline():
    hc = Axfr.health_check()
    assert hc.offline is True and hc.selftest is not None
    rt = make_runtime()
    ctx = rt.context(Axfr, ScanOptions(mode=Opsec.ACTIVE), run=None)
    result = hc.selftest(ctx)
    assert result.status == "ok"
