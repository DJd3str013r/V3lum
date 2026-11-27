"""tls_protocol_scan (P277, ACTIVE): tri-state handshake classification (outcomes recorded on loopback
with this Python/OpenSSL build: tests/fixtures/tls_protocol_scan/), the P275 interception gate, the
4-handshake plan, client-side 'could not test', UNAVAILABLE without the core helper, and real
loopback TLS servers configured per protocol (FC8) reached through ctx.net under a scope that lists
127.0.0.1."""

from __future__ import annotations

import json
import shutil
import socket
import ssl
import subprocess
import threading
import warnings
from pathlib import Path
from types import SimpleNamespace

import pytest

from tests.fakes import FIXTURES, FakeHttp, make_ctx, make_runtime, run_module
from v3lum.core.context import ScanOptions
from v3lum.core.engine import Engine
from v3lum.core.entities import Entity
from v3lum.core.entities import EntityType as T
from v3lum.core.graph import Graph
from v3lum.core.models import Opsec, Status
from v3lum.core.scope import Scope
from v3lum.modules.pentest_recon import tls_protocol_scan as tps
from v3lum.modules.pentest_recon.tls_protocol_scan import TlsProtocolScan

FIX = Path(FIXTURES) / "tls_protocol_scan"
REF = "PENTEST-2026-042"


def fx(name: str) -> dict:
    return json.loads((FIX / name).read_text(encoding="utf-8"))


def scope(**targets) -> Scope:
    return Scope.from_dict({
        "authorization_ref": REF, "owner": "Engagement owner (tests)", "contacts": ["soc@example.com"], "ticket": "T-1",
        "window_start": "2026-11-26T00:00:00Z", "window_end": "2026-11-27T00:00:00Z",
        "targets": targets or {"domains": ["example.com", "*.example.com"], "cidrs": ["93.184.216.0/24"]},
    })


def active(sc: Scope | None = None) -> ScanOptions:
    return ScanOptions(mode=Opsec.ACTIVE, authorized=True, authorization_ref=REF, scope=sc if sc is not None else scope())


def clear_on(port: int) -> dict:
    """The recorded P275 'no interception' node, for the port the test server listens on."""
    attrs = fx("p275_node_clear.json")
    attrs["tls_handshake"] = {**attrs["tls_handshake"], "port": port}
    return attrs


def graph_with(entity_text: str, attrs: dict) -> Graph:
    etype, _, value = entity_text.partition(":")
    graph = Graph(noise_check=False)
    node, _ = graph.add_node(Entity.make(T(etype), value), seed=True)
    for name, value in attrs.items():
        if name != "note":
            node.attributes[name] = [(value, "tls_inspect")]
    return graph


class FakeTls:
    """A recorded core helper: answers each probe id with a recorded outcome (no socket)."""

    def __init__(self, outcomes: dict[str, dict]) -> None:
        self.outcomes = outcomes
        self.calls: list[dict] = []

    def probe(self, host, port, *, server_name, min_version, max_version, ciphers, timeout):
        self.calls.append({"host": host, "port": port, "min": min_version, "max": max_version, "ciphers": ciphers, "timeout": timeout})
        probe_id = next(p["id"] for p in tps.PROBES if p["min"] == min_version and p["max"] == max_version and p["ciphers"] == ciphers)
        return dict(self.outcomes.get(probe_id) or fx("timeout.json"))


def run_with(helper, entity_text: str = "domain:www.example.com", node_attrs: dict | None = None, settings: dict | None = None):
    rt = make_runtime(FakeHttp(), settings=settings or {})
    if node_attrs is not None:
        rt.policy_context = SimpleNamespace(graph=graph_with(entity_text, node_attrs))
    ent = Entity.make(T(entity_text.split(":", 1)[0]), entity_text.split(":", 1)[1])
    ctx = make_ctx(TlsProtocolScan, runtime=rt, options=active(), entity=ent)
    if helper is not None:
        ctx.tls = helper
    return TlsProtocolScan().run(ent, ctx), ctx


# ---------------------------------------------------------------------------------- classifier (recorded loopback outcomes)
@pytest.mark.parametrize(("name", "probe_id", "state", "side"), [
    ("tls10_accepted.json", "tls1_0", "accepted", "server"),
    ("tls11_accepted.json", "tls1_1", "accepted", "server"),
    ("tls10_accepted_cert_untrusted.json", "tls1_0", "accepted", "server"),
    ("tls10_refused_alert.json", "tls1_0", "refused", "server"),
    ("tls11_refused_unsupported.json", "tls1_1", "refused", "server"),
    ("tls10_client_no_protocols.json", "tls1_0", "could_not_test", "client"),
    ("weak_client_no_cipher.json", "weak_broken", "could_not_test", "client"),
    ("weak_broken_accepted_anon.json", "weak_broken", "accepted", "server"),
    ("weak_no_pfs_accepted.json", "weak_no_pfs", "accepted", "server"),
    ("weak_refused_handshake_failure.json", "weak_broken", "refused", "server"),
    ("not_tls_wrong_version.json", "tls1_0", "could_not_test", "path"),
    ("timeout.json", "tls1_0", "could_not_test", "path"),
    ("eof_no_alert.json", "tls1_0", "could_not_test", "path"),
    ("connection_refused.json", "tls1_0", "could_not_test", "path"),
    ("proxy_connect_refused.json", "tls1_0", "could_not_test", "proxy"),
])
def test_classify_recorded_outcomes(name, probe_id, state, side):
    probe = next(p for p in tps.PROBES if p["id"] == probe_id)
    verdict = tps.classify_handshake(fx(name), probe)
    assert (verdict["state"], verdict["side"]) == (state, side)
    if name == "tls10_accepted_cert_untrusted.json":
        assert verdict["version"] == "TLSv1" and "tls_inspect" in verdict["reason"]


def test_client_side_refusals_are_never_disabled_on_server():
    for name in ("tls10_client_no_protocols.json", "weak_client_no_cipher.json"):
        assert "disabled" not in json.dumps(tps.classify_handshake(fx(name), tps.PROBES[0]))


def test_plan_has_at_most_four_probes_and_reports_client_gaps_without_contact():
    caps = fx("client_caps.json")
    probes, cannot = tps.plan_probes(caps)
    assert len(probes) <= tps.MAX_EXTRA_HANDSHAKES == 4
    assert any("3des" in c["reason"] and c["side"] == "client" for c in cannot)
    probes2, cannot2 = tps.plan_probes({"has_tlsv1": False, "has_tlsv1_1": False, "cipher_names_broken": [], "cipher_names_no_pfs": []})
    assert probes2 == [] and {c["probe"] for c in cannot2} == {"tls1_0", "tls1_1", "weak_broken", "weak_no_pfs"}


# ---------------------------------------------------------------------------------- module gating
def test_without_the_core_tls_helper_it_is_unavailable_and_contacts_nothing():
    http = FakeHttp()
    res = run_module(TlsProtocolScan, "domain:www.example.com", http, options=active())
    assert (res.status, res.reason_code) == (Status.UNAVAILABLE, "package")
    assert "ctx.tls" in res.error and http.calls == []


def test_interception_found_by_p275_means_not_tested():
    helper = FakeTls({})
    res, _ctx = run_with(helper, node_attrs=fx("p275_node_intercepted.json"))
    assert (res.status, res.reason_code) == (Status.SKIPPED, "not_applicable")
    assert "intercepted, not tested" in res.error and helper.calls == []
    assert res.attributes["tls_protocol_scan"]["interception"]["issuer"].startswith("O=Example Corp")


def test_no_p275_verdict_or_another_egress_means_not_tested():
    helper = FakeTls({})
    res, _ = run_with(helper, node_attrs=None)
    assert "interception unknown, not tested" in res.error and helper.calls == []
    res2, _ = run_with(helper, node_attrs=fx("p275_node_light_proxy.json"))
    assert "interception unknown, not tested" in res2.error and helper.calls == []
    # P275 checked the default route, but this run's ACTIVE route is proxy_active: a different egress
    res3, _ = run_with(helper, node_attrs=fx("p275_node_clear.json"), settings={"proxy_active": "http://127.0.0.1:9/"})
    assert "not tested" in res3.error and helper.calls == []


def test_clear_egress_runs_four_probes_and_feeds_cr17():
    helper = FakeTls({
        "tls1_0": fx("tls10_accepted.json"), "tls1_1": fx("tls11_refused_unsupported.json"),
        "weak_broken": fx("weak_refused_handshake_failure.json"), "weak_no_pfs": fx("weak_no_pfs_accepted.json"),
    })
    res, _ = run_with(helper, node_attrs=fx("p275_node_clear.json"))
    assert res.status is Status.OK, res.error
    assert len(helper.calls) == 4 and all(c["timeout"] == 10.0 and "@SECLEVEL=0" in c["ciphers"] for c in helper.calls)
    assert res.attributes["tls_protocols"] == {"TLSv1": "accepted", "TLSv1.1": "refused"}
    assert res.attributes["tls_weak_ciphers"] == ["AES256-GCM-SHA384"]
    by_key = {f.key: f for f in res.findings}
    assert by_key["443|tls1_0"].severity.label == "medium" and by_key["443|weak_no_pfs"].severity.label == "low"
    evidence = by_key["443|tls1_0"].data
    assert evidence["protocol"] == "TLSv1" and evidence["egress_profile"] == "default" and by_key["443|tls1_0"].attack == ["T1557"]
    summary = res.attributes["tls_protocol_scan"]
    assert summary["egress_profile"] == "default" and any(c["side"] == "client" for c in summary["client_cannot"])


def test_only_client_side_failures_is_could_not_verify():
    no = fx("tls10_client_no_protocols.json")
    helper = FakeTls({"tls1_0": no, "tls1_1": no, "weak_broken": fx("weak_client_no_cipher.json"), "weak_no_pfs": fx("timeout.json")})
    res, _ = run_with(helper, node_attrs=fx("p275_node_clear.json"))
    assert res.status is Status.ERROR and "no probe could be tested" in res.error
    assert res.attributes["tls_protocols"] == {"TLSv1": "could_not_test", "TLSv1.1": "could_not_test"}
    assert res.findings == []


def test_a_verdict_on_another_port_never_clears_this_port():
    """FC5 is per host:port: P275 checked 443 only, so 8443 is 'interception unknown, not tested'."""
    helper = FakeTls({"tls1_0": fx("tls10_accepted.json")})
    res, _ = run_with(helper, node_attrs=fx("p275_node_clear.json"), settings={"tls_protocol_scan_ports": [443, 8443]})
    assert {c["port"] for c in helper.calls} == {443}
    by_port = {s["port"]: s for s in res.attributes["tls_protocol_scan"]["ports"]}
    assert by_port[8443]["probes"] == [] and "interception unknown, not tested" in by_port[8443]["reason"]
    assert by_port[443]["interception"]["state"] == "clear"
    only_other, _ = run_with(FakeTls({}), node_attrs=fx("p275_node_clear.json"), settings={"tls_protocol_scan_ports": [8443]})
    assert (only_other.status, only_other.reason_code) == (Status.SKIPPED, "not_applicable")


def test_never_on_pivots_or_values_found_in_text():
    """FC2: analyst-typed seeds only (run_on='seeds' plus applies())."""
    assert TlsProtocolScan.run_on == "seeds"
    ent = Entity.make(T.DOMAIN, "www.example.com")
    seed = make_ctx(TlsProtocolScan, FakeHttp(), options=active(), entity=ent)
    pivot = make_ctx(TlsProtocolScan, FakeHttp(), options=active(), entity=ent, is_seed=False)
    from_text = make_ctx(TlsProtocolScan, FakeHttp(), options=active(), entity=ent,
                         provenance=[("text_blob:abc", "mentions", "ioc_extract")])
    assert TlsProtocolScan().applies(ent, seed)
    assert not TlsProtocolScan().applies(ent, pivot) and not TlsProtocolScan().applies(ent, from_text)
    res = run_module(TlsProtocolScan, "domain:www.example.com", FakeHttp(), options=active(), is_seed=False)
    assert res.status is Status.SKIPPED


def test_kill_switch_mid_run_is_a_partial_result():
    class StopAfterOne(FakeTls):
        def __init__(self, outcomes, runtime):
            super().__init__(outcomes)
            self.runtime = runtime

        def probe(self, *a, **k):
            out = super().probe(*a, **k)
            self.runtime.cancel("cancelled")
            return out

    rt = make_runtime(FakeHttp())
    rt.policy_context = SimpleNamespace(graph=graph_with("domain:www.example.com", fx("p275_node_clear.json")))
    ent = Entity.make(T.DOMAIN, "www.example.com")
    ctx = make_ctx(TlsProtocolScan, runtime=rt, options=active(), entity=ent)
    ctx.tls = StopAfterOne({"tls1_0": fx("tls10_refused_alert.json")}, rt)
    res = TlsProtocolScan().run(ent, ctx)
    assert len(ctx.tls.calls) == 1 and res.partial and res.stop_reason == "cancelled"


def test_policy_gate_needs_active_mode_and_authorization():
    rt = make_runtime(FakeHttp())
    ent = Entity.make(T.DOMAIN, "www.example.com")
    assert Engine(rt, ScanOptions()).decide_single(TlsProtocolScan, ent).reason_code == "opsec"
    assert Engine(rt, ScanOptions(mode=Opsec.ACTIVE, scope=scope())).decide_single(TlsProtocolScan, ent).reason_code == "authorization"


def test_offline_selftest_is_ok():
    hc = TlsProtocolScan.health_check()
    assert hc.offline is True
    assert hc.selftest(make_ctx(TlsProtocolScan, FakeHttp())).status == "ok"


# ---------------------------------------------------------------------------------- real loopback TLS servers (FC8)
@pytest.fixture(scope="module")
def cert(tmp_path_factory):
    if shutil.which("openssl") is None:
        pytest.skip("openssl CLI not available to make a throwaway loopback certificate")
    folder = tmp_path_factory.mktemp("tlscert")
    key, crt = folder / "k.pem", folder / "c.pem"
    subprocess.run(["openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes", "-keyout", str(key), "-out", str(crt), "-days", "2",
                    "-subj", "/CN=localhost", "-addext", "subjectAltName=DNS:localhost"], check=True, capture_output=True)
    return str(crt), str(key)


class LoopbackTlsServer:
    """A TLS server on 127.0.0.1 configured for one protocol family (throwaway certificate)."""

    def __init__(self, kind: str, crt: str, key: str) -> None:
        with warnings.catch_warnings():
            warnings.simplefilter("ignore", DeprecationWarning)
            self.ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
            self.ctx.load_cert_chain(crt, key)
            if kind == "legacy_tls10":
                self.ctx.set_ciphers("DEFAULT:@SECLEVEL=0")
                self.ctx.minimum_version = ssl.TLSVersion.TLSv1
                self.ctx.maximum_version = ssl.TLSVersion.TLSv1
        self.srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.srv.bind(("127.0.0.1", 0))
        self.srv.listen(8)
        self.srv.settimeout(0.1)
        self.port = self.srv.getsockname()[1]
        self.stop = threading.Event()
        self.thread = threading.Thread(target=self._serve, daemon=True)
        self.thread.start()

    def _serve(self) -> None:
        while not self.stop.is_set():
            try:
                conn, _ = self.srv.accept()
            except (TimeoutError, OSError):
                continue
            try:
                conn.settimeout(3)
                tls = self.ctx.wrap_socket(conn, server_side=True)
                tls.close()
            except (ssl.SSLError, OSError):
                pass
            finally:
                conn.close()

    def close(self) -> None:
        self.stop.set()
        self.srv.close()
        self.thread.join(timeout=2)


class LoopbackTls:
    """The requested core helper shape (``ctx.tls.probe``) over the core connector: the socket comes
    from ``ctx.net.connect`` (scope, SSRF guard, ceilings, ledger); the pinned context keeps
    verification on, trusting only the throwaway loopback certificate."""

    def __init__(self, ctx, cafile: str) -> None:
        self.ctx, self.cafile, self.connects = ctx, cafile, 0

    def probe(self, host, port, *, server_name, min_version, max_version, ciphers, timeout):
        with warnings.catch_warnings():
            warnings.simplefilter("ignore", DeprecationWarning)
            context = ssl.create_default_context(cafile=self.cafile)
            context.minimum_version = getattr(ssl.TLSVersion, min_version)
            context.maximum_version = getattr(ssl.TLSVersion, max_version)
        try:
            context.set_ciphers(ciphers)
        except ssl.SSLError as exc:
            return {"ok": False, "stage": "context", "error_type": type(exc).__name__, "reason": "", "str": str(exc)}
        sock = self.ctx.net.connect(host, port, timeout=timeout)
        self.connects += 1
        try:
            try:
                tls = context.wrap_socket(sock, server_hostname=server_name or "localhost")
            except (ssl.SSLError, OSError) as exc:
                return {"ok": False, "stage": "handshake", "error_type": type(exc).__name__, "reason": str(getattr(exc, "reason", "") or ""),
                        "str": str(exc)}
            version, cipher = tls.version(), tls.cipher()
            tls.close()
            return {"ok": True, "stage": "handshake", "version": version, "cipher": cipher[0] if cipher else None}
        finally:
            sock.close()


@pytest.mark.parametrize(("kind", "expected"), [
    ("legacy_tls10", {"TLSv1": "accepted", "TLSv1.1": "refused"}),
    ("modern", {"TLSv1": "refused", "TLSv1.1": "refused"}),
])
def test_loopback_servers_per_protocol(cert, kind, expected):
    crt, key = cert
    server = LoopbackTlsServer(kind, crt, key)
    try:
        rt = make_runtime(FakeHttp(), settings={"tls_protocol_scan_ports": [server.port]})
        rt.policy_context = SimpleNamespace(graph=graph_with("ipv4:127.0.0.1", clear_on(server.port)))
        ent = Entity.make(T.IPV4, "127.0.0.1")
        options = active(scope(cidrs=["127.0.0.1/32"]))
        ctx = make_ctx(TlsProtocolScan, runtime=rt, options=options, entity=ent)
        helper = LoopbackTls(ctx, crt)
        ctx.tls = helper
        res = TlsProtocolScan().run(ent, ctx)
        assert res.attributes["tls_protocols"] == expected, res.attributes["tls_protocol_scan"]
        assert helper.connects == 4  # never more than four extra handshakes per host:port
        # every connection went through the core connector and its ledger
        assert [r.method for r in ctx.net.request_log].count("CONNECT") == 4
        if kind == "modern":
            assert res.findings == []
        else:
            assert {f.key for f in res.findings} >= {f"{server.port}|tls1_0"}
    finally:
        server.close()


def test_loopback_target_outside_the_scope_is_never_connected(cert):
    crt, key = cert
    server = LoopbackTlsServer("modern", crt, key)
    try:
        rt = make_runtime(FakeHttp(), settings={"tls_protocol_scan_ports": [server.port]})
        rt.policy_context = SimpleNamespace(graph=graph_with("ipv4:127.0.0.1", clear_on(server.port)))
        ent = Entity.make(T.IPV4, "127.0.0.1")
        ctx = make_ctx(TlsProtocolScan, runtime=rt, options=active(), entity=ent)  # the scope does not list 127.0.0.1
        helper = LoopbackTls(ctx, crt)
        ctx.tls = helper
        from v3lum.core.http import PolicyError

        with pytest.raises(PolicyError):
            TlsProtocolScan().run(ent, ctx)
        assert helper.connects == 0
    finally:
        server.close()
