"""Offline tests of tls_inspect (P275): a FakeTls with real PEM fixtures (c10), plus the safety
expectations of a LIGHT module through the real core connector (seeds only, SSRF guard, kill switch,
loopback handshake)."""

from __future__ import annotations

import json
import shutil
import socket
import ssl
import subprocess
import threading
from pathlib import Path
from types import SimpleNamespace

import pytest

from tests.fakes import FakeClock, FakeHttp, make_ctx, make_runtime, module_fixture, run_module
from v3lum.core.context import ScanOptions
from v3lum.core.entities import Entity
from v3lum.core.entities import EntityType as T
from v3lum.core.graph import Graph
from v3lum.core.http import Cancelled, PolicyError
from v3lum.core.models import Opsec, Status
from v3lum.core.orgprofile import OrgProfile
from v3lum.modules.pentest_recon import tls_inspect as mod
from v3lum.modules.pentest_recon.tls_inspect import Handshake, TlsInspect

FIX = Path(__file__).resolve().parents[1] / "fixtures" / "tls_inspect"
LIGHT = ScanOptions(mode=Opsec.LIGHT)
ORG = OrgProfile.from_dict({"domains": [{"name": "example.com", "verification": "attested", "attested_by": "analyst",
                                         "attested_date": "2026-11-01"}]})


def pem(name: str) -> list[bytes]:
    return mod.pem_to_der_list((FIX / name).read_text(encoding="ascii"))


ROOT = pem("test_root_ca.pem")


class FakeTls:
    """c10: the handshake helper double - real DER chains from the PEM fixtures, no network."""

    def __init__(self, chain: str | None = None, *, verified: bool = True, anchor: bool = True, verify_code: int | None = None,
                 verify_error: str = "", profile: str = "light", ip: str = "93.184.216.34") -> None:
        self.chain = (pem(chain) + (ROOT if anchor else [])) if chain else []
        self.verified, self.verify_code, self.verify_error = verified, verify_code, verify_error
        self.profile, self.ip = profile, ip
        self.calls: list[tuple[str, int, str]] = []

    def handshake(self, host: str, port: int, server_name: str) -> Handshake:
        self.calls.append((host, port, server_name))
        return Handshake(host, port, server_name, self.verified, chain_der=list(self.chain) if self.verified else [],
                         chain_verified=self.verified and bool(self.chain), verify_code=self.verify_code,
                         verify_error=self.verify_error, version="TLSv1.3" if self.verified else None,
                         cipher="TLS_AES_128_GCM_SHA256" if self.verified else None, egress_profile=self.profile, resolved_ip=self.ip)


@pytest.fixture()
def mozilla(monkeypatch):
    """Mozilla's bundle = the test PKI root (so fixture chains verify like public ones); not the inspection CA."""
    spki = frozenset({mod.parse_der_certificate(ROOT[0])["spki_sha256"]})
    monkeypatch.setattr(mod, "mozilla_spki", lambda: spki)
    mod._MEMO.clear()
    return spki


def run(entity: str, fake: FakeTls, monkeypatch, **kw):
    monkeypatch.setattr(mod, "tls_helper", lambda ctx: fake)
    kw.setdefault("options", LIGHT)
    return run_module(TlsInspect, entity, FakeHttp(), clock=FakeClock(), **kw)


def titles(res) -> dict:
    return {f.title: f for f in res.findings}


# ---- metadata and self-test ------------------------------------------------------------------


def test_light_metadata_and_offline_selftest():
    cls = TlsInspect
    assert cls.opsec is Opsec.LIGHT and cls.disclosure == "target" and cls.default_enabled is False
    assert cls.terms == "open" and cls.trust_tier == "n/a" and cls.hosts == () and cls.run_on == "seeds"
    assert cls.max_rate is not None and cls.max_rate <= 1.0
    hc = cls.health_check()
    assert hc.offline is True and callable(hc.selftest)
    result = hc.selftest(make_ctx(cls, FakeHttp()))
    assert result.status == "ok", result.detail


def test_stdlib_der_reader_matches_the_recorded_facts():
    cases = json.loads((FIX / "expected_facts.json").read_text())["cases"]
    for name, expected in cases.items():
        for der, exp in zip(pem(f"{name}.pem"), expected):
            got = mod.parse_der_certificate(der)
            assert {k: got.get(k) for k in exp} == exp, name


def test_cryptography_path_agrees_when_the_extra_is_installed():
    pytest.importorskip("cryptography")
    for name in ("ok_chain", "weak_rsa1024_sha1_chain", "shared_san_chain"):
        der = pem(f"{name}.pem")[0]
        a, b = mod.parse_with_cryptography(der), mod.parse_der_certificate(der)
        for key in ("sha256", "serial", "san_dns", "key_type", "key_size", "not_after", "sig_hash"):
            assert a[key] == b[key], (name, key)


# ---- c10: the three council examples ------------------------------------------------------------


def test_intercepted_chain_gives_the_banner_and_no_certificate_findings(monkeypatch, mozilla):
    fake = FakeTls("intercepted_chain.pem", anchor=False)  # leaf + the inspection root (not a Mozilla root)
    res = run("domain:www.example.org", fake, monkeypatch, org_profile=ORG)
    assert res.status is Status.OK
    banner = "TLS interception by Example TLS Inspection CA detected on this network: certificate findings suppressed"
    f = titles(res)["TLS interception detected on this network: certificate findings suppressed"]
    assert banner in f.description and {"tls_interception", "inconclusive"} <= set(f.tags)
    assert res.attributes["intercepted_by"] == "Example TLS Inspection CA"
    assert len(res.findings) == 1 and not res.pivots
    assert not {"tls_certificate", "cert_sans", "shared_cert"} & set(res.attributes)
    assert res.attributes["tls_handshake"]["interception_check"] == "done"


def test_expired_own_asset_certificate_is_high(monkeypatch, mozilla):
    res = run("domain:portal.example.com", FakeTls("expired_chain.pem"), monkeypatch, org_profile=ORG)
    f = titles(res)["TLS certificate expired"]
    assert f.severity.label == "high" and f.criterion and "own_asset" in f.tags
    cert = res.attributes["tls_certificate"]
    assert cert["not_after"].startswith("2026-10-01") and cert["chain_verified"] is True and cert["hostname_match"] is True


def test_the_same_certificate_on_a_third_party_host_is_info(monkeypatch, mozilla):
    res = run("domain:portal.example.com", FakeTls("expired_chain.pem"), monkeypatch)
    f = titles(res)["TLS certificate expired"]
    assert f.severity.label == "info" and {"third_party", "context_only"} <= set(f.tags)
    assert all(x.severity.label == "info" for x in res.findings)


# ---- c7 hygiene ---------------------------------------------------------------------------------


@pytest.mark.parametrize(("chain", "host", "title", "severity"), [
    ("expires_10d_chain.pem", "vpn.example.com", "TLS certificate expires within 14 days", "medium"),
    ("expires_20d_chain.pem", "mail.example.com", "TLS certificate expires within 30 days", "low"),
    ("mismatch_chain.pem", "shop.example.com", "TLS certificate does not match the host name", "high"),
    ("weak_rsa1024_sha1_chain.pem", "legacy.example.com", "Weak TLS certificate key", "medium"),
    ("weak_rsa1024_sha1_chain.pem", "legacy.example.com", "Weak TLS certificate signature hash", "medium"),
    ("weak_ec224_chain.pem", "iot.example.com", "Weak TLS certificate key", "medium"),
])
def test_hygiene_severities_for_own_assets(monkeypatch, mozilla, chain, host, title, severity):
    res = run(f"domain:{host}", FakeTls(chain), monkeypatch, org_profile=ORG)
    assert titles(res)[title].severity.label == severity


def test_self_signed_internal_seed_is_medium_and_not_interception(monkeypatch, mozilla):
    fake = FakeTls("self_signed.pem", anchor=False, ip="10.20.30.40")
    res = run("domain:intranet.example.com", fake, monkeypatch, org_profile=ORG)
    assert titles(res)["Self-signed TLS certificate"].severity.label == "medium"
    assert res.attributes["tls_handshake"]["interception_check"] == "not_applicable_private_target"
    assert "intercepted_by" not in res.attributes


def test_in_scope_target_keeps_the_severity(monkeypatch, mozilla):
    scope = SimpleNamespace(matches_host=lambda h: h == "portal.example.com", problems=())
    res = run("domain:portal.example.com", FakeTls("expired_chain.pem"), monkeypatch, options=ScanOptions(mode=Opsec.LIGHT, scope=scope))
    f = titles(res)["TLS certificate expired"]
    assert f.severity.label == "high" and "in_scope" in f.tags and "third_party" not in f.tags


# ---- c8 hostile hosts ---------------------------------------------------------------------------


def _hostile_runtime(host: str, *tags: str):
    rt = make_runtime(FakeHttp(), clock=FakeClock())
    graph = Graph()
    node, _ = graph.add_node(Entity.make(T.DOMAIN, host), seed=True)
    for tag in tags:
        node.add_tag(tag)
    rt.policy_context = SimpleNamespace(graph=graph)
    return rt


def test_hostile_host_gets_facts_and_phishing_signals_never_findings(monkeypatch, mozilla):
    rt = _hostile_runtime("www.example.org", "phishing", "typosquat")
    res = run("domain:www.example.org", FakeTls("phish_new_dv_chain.pem"), monkeypatch, runtime=rt)
    assert res.status is Status.OK
    assert not [f for f in res.findings if f.title in mod.HYGIENE_TITLES.values()]
    signals = {s["signal"] for s in res.attributes["tls_phishing_signals"]}
    assert signals == {"cert_issued_lt_7d", "free_dv_cert_on_lookalike"}
    assert res.attributes["tls_certificate"]["issuer"].startswith("CN=R11")
    fp = [p for p in res.pivots if p.entity.type is T.CERT_FP]
    assert fp and fp[0].relation == "handshake_certificate"
    sans = {p.entity.value: p.expand for p in res.pivots if p.relation == "cert_san"}
    # c9 applies on hostile hosts too: SANs inside the apex expand (passive modules only), others are listed
    assert all(expand == (mod.registrable(v) == "example.org") for v, expand in sans.items())
    host = "www.examplebank-seguranca.example"
    res2 = run(f"domain:{host}", FakeTls("phish_new_dv_chain.pem"), monkeypatch, runtime=_hostile_runtime(host, "phishing"))
    assert {p.entity.value: p.expand for p in res2.pivots if p.relation == "cert_san"} == {"examplebank-seguranca.example": True}
    assert not [f for f in res2.findings if f.title in mod.HYGIENE_TITLES.values()]


# ---- c9 pivots ----------------------------------------------------------------------------------


def test_san_and_fingerprint_pivots(monkeypatch, mozilla):
    res = run("domain:example.com", FakeTls("ok_chain.pem"), monkeypatch)
    sans = [p for p in res.pivots if p.relation == "cert_san"]
    assert {p.entity.value for p in sans} <= {"example.com"} or sans == []  # the subject itself is not a pivot
    fp = [p for p in res.pivots if p.entity.type is T.CERT_FP]
    expected = mod.parse_der_certificate(pem("ok_chain.pem")[0])["sha256"]
    assert fp and fp[0].entity.value == expected and fp[0].expand is True
    assert res.attributes["cert_sans"] == ["example.com", "*.example.com"]
    assert titles(res)["Wildcard TLS certificate"].severity.label == "info"


def test_san_outside_the_apex_is_not_expanded(monkeypatch, mozilla):
    res = run("domain:other.example.net", FakeTls("mismatch_chain.pem"), monkeypatch)
    assert not [p for p in res.pivots if p.relation == "cert_san"]  # its only SAN is the subject
    piv = mod.san_pivots({"san_dns": ["a.example.com", "b.example.net", "*.example.com"]}, "www.example.com")
    assert piv == [{"value": "a.example.com", "expand": True}, {"value": "b.example.net", "expand": False},
                   {"value": "example.com", "expand": True}]


def test_shared_certificate_is_an_attribute_only(monkeypatch, mozilla):
    res = run("domain:shop-a.example.com", FakeTls("shared_san_chain.pem"), monkeypatch)
    shared = res.attributes["shared_cert"][0]
    assert shared["san_count"] == 25 and "registrable domains" in shared["reason"]
    assert not [p for p in res.pivots if p.relation == "cert_san"]
    fp = [p for p in res.pivots if p.entity.type is T.CERT_FP]
    assert fp and fp[0].expand is False


# ---- verification failures and rule 5 -----------------------------------------------------------


def test_verify_failure_without_a_chain_still_reports_the_reason(monkeypatch, mozilla):
    fake = FakeTls(verified=False, verify_code=10, verify_error="certificate has expired")
    res = run("domain:portal.example.com", fake, monkeypatch, org_profile=ORG)
    assert titles(res)["TLS certificate expired"].severity.label == "high"
    assert res.attributes["tls_handshake"]["verified"] is False


def test_unexplained_verify_failure_is_could_not_verify(monkeypatch, mozilla):
    fake = FakeTls(verified=False, verify_code=85, verify_error="Missing Authority Key Identifier")
    res = run("domain:portal.example.com", fake, monkeypatch)
    assert res.status is Status.ERROR and "could not verify" in res.error


@pytest.mark.parametrize(("exc", "code"), [(TimeoutError("timed out"), "timeout"), (ConnectionRefusedError(), "error"),
                                           (ssl.SSLError("handshake failure"), "error")])
def test_network_failures_are_errors_never_empty(monkeypatch, mozilla, exc, code):
    class Broken:
        def handshake(self, *_a):
            raise exc

    monkeypatch.setattr(mod, "tls_helper", lambda ctx: Broken())
    res = run_module(TlsInspect, "domain:example.com", FakeHttp(), options=LIGHT)
    assert res.status is Status.ERROR and res.reason_code == code


def test_one_handshake_per_host_per_case(monkeypatch, mozilla):
    fake = FakeTls("ok_chain.pem")
    run("domain:example.com", fake, monkeypatch, case_id="case-1")
    run("url:https://example.com/login", fake, monkeypatch, case_id="case-1")
    run("domain:example.com", fake, monkeypatch, case_id="case-2")
    assert len(fake.calls) == 2


def test_pivots_are_never_contacted(monkeypatch, mozilla):
    fake = FakeTls("ok_chain.pem")
    res = run("domain:example.com", fake, monkeypatch, is_seed=False, depth=1)
    assert res.status is Status.SKIPPED and res.reason_code == "scope" and fake.calls == []


def test_url_target_uses_its_https_port():
    assert mod.target_of(Entity.make(T.URL, "https://example.com:8443/x")) == ("example.com", 8443)
    assert mod.target_of(Entity.make(T.URL, "http://example.com:8080/x")) == ("example.com", 443)
    assert mod.target_of(Entity.make(T.IPV4, "93.184.216.34")) == ("93.184.216.34", 443)


def test_interception_state_is_recorded_per_egress_profile(monkeypatch, mozilla):
    rt = make_runtime(FakeHttp(), clock=FakeClock())
    run("domain:www.example.org", FakeTls("intercepted_chain.pem", anchor=False, profile="light"), monkeypatch, runtime=rt)
    ctx = make_ctx(TlsInspect, runtime=rt, entity="domain:www.example.org")
    assert ctx.state.get("interception")["light"]["intercepted_by"] == "Example TLS Inspection CA"


def test_pure_helpers_never_crash_on_junk():
    with pytest.raises(mod.DerError):
        mod.parse_der_certificate(b"\x30\x03\x02\x01")
    assert mod.parse_certificate(b"junk") == {}
    assert mod.parse_peercert(json.loads((FIX / "peercert_ok.json").read_text()))["san_dns"]
    assert mod.pem_to_der_list(None) == [] and mod.pem_to_der_list("-----BEGIN CERTIFICATE-----!!-----END CERTIFICATE-----") == []
    assert mod.anchor_intercepted_by([], frozenset({"x"})) is None
    out = mod.analyze_tls([], hostname="x.example.com", now=FakeClock().now(), ownership="third_party", verified=False)
    assert out["findings"] == [] and out["fingerprint"] is None


def test_probe_samples_drive_the_interception_rule():
    probe = module_fixture("tls_inspect", "probe_intercepted.json")
    assert "self-signed certificate in certificate chain" in probe["mozilla_store_only"]["error"]
    assert probe["system_store"]["verified"] is True


# ---- safety through the real core connector (no FakeTls) -----------------------------------------


def test_real_connector_refuses_a_pivot_before_any_contact():
    ctx = make_ctx(TlsInspect, FakeHttp(), entity="domain:example.com", is_seed=False, depth=1, options=LIGHT)
    with pytest.raises(PolicyError) as err:
        mod.NetTls(ctx).handshake("example.com", 443, "example.com")
    assert err.value.reason_code == "scope"
    assert not [r for r in ctx.net.request_log if r.method == "CONNECT"]


def test_real_connector_refuses_private_addresses_without_an_internal_seed():
    res = run_module(TlsInspect, "ipv4:10.0.0.5", FakeHttp(), options=LIGHT)
    assert res.status is Status.SKIPPED and res.reason_code == "policy"


def test_kill_switch_stops_the_handshake_before_contact():
    ctx = make_ctx(TlsInspect, FakeHttp(), entity="domain:example.com", options=LIGHT)
    ctx.runtime.cancel("cancelled")
    with pytest.raises(Cancelled):
        TlsInspect().run(Entity.make(T.DOMAIN, "example.com"), ctx)
    assert not [r for r in ctx.net.request_log if r.method == "CONNECT"]


def _loopback_cert(folder: Path) -> tuple[Path, Path]:
    if shutil.which("openssl") is None:
        pytest.skip("openssl is not installed")
    cert, key = folder / "cert.pem", folder / "key.pem"
    subprocess.run(["openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes", "-keyout", str(key), "-out", str(cert), "-days", "2",
                    "-subj", "/CN=127.0.0.1", "-addext", "subjectAltName=IP:127.0.0.1"], check=True, capture_output=True, timeout=60)
    return cert, key


def test_loopback_handshake_through_the_real_connector(tmp_path, monkeypatch):
    cert, key = _loopback_cert(tmp_path)
    server_ctx = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)
    server_ctx.load_cert_chain(str(cert), str(key))
    srv = socket.socket()
    srv.bind(("127.0.0.1", 0))
    srv.listen(2)
    srv.settimeout(5)
    received: list[bytes] = []

    def serve() -> None:
        try:
            raw, _ = srv.accept()
            with server_ctx.wrap_socket(raw, server_side=True) as tls:
                tls.settimeout(2)
                try:
                    received.append(tls.recv(64))
                except (OSError, ssl.SSLError):
                    pass
        except OSError:
            pass

    thread = threading.Thread(target=serve, daemon=True)
    thread.start()
    real = ssl.create_default_context

    def trusting(*args, **kwargs):  # the default verifying context, also trusting the test certificate
        ctx = real(*args, **kwargs)
        ctx.load_verify_locations(str(cert))
        return ctx

    monkeypatch.setattr(ssl, "create_default_context", trusting)
    mod._MEMO.clear()
    port = srv.getsockname()[1]
    try:
        res = run_module(TlsInspect, f"url:https://127.0.0.1:{port}/", FakeHttp(), options=LIGHT, internal_seed=True)
    finally:
        srv.close()
        thread.join(timeout=5)
    assert res.status is Status.OK, res.error
    hs = res.attributes["tls_handshake"]
    assert hs["verified"] is True and hs["port"] == port and hs["interception_check"] == "not_applicable_private_target"
    assert res.attributes["tls_certificate"]["hostname_match"] is True
    assert received in ([], [b""])  # no application data was ever sent
