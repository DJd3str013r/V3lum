"""Offline tests of page_capture (P347) against a fake driver (c7): the renderer never fetches anything
itself - every request goes through the module's route handler and ``ctx.http`` (FakeHttp here)."""

from __future__ import annotations

import json
import socket
from pathlib import Path
from types import SimpleNamespace
from urllib.parse import urljoin

import pytest

from tests.fakes import FakeClock, FakeHttp, add_dns, make_ctx, make_runtime, module_fixture, run_module
from v3lum.core.context import ScanOptions
from v3lum.core.entities import Entity
from v3lum.core.entities import EntityType as T
from v3lum.core.graph import Graph
from v3lum.core.http import Cancelled
from v3lum.core.models import Opsec, Status
from v3lum.modules.url_web import page_capture as mod
from v3lum.modules.url_web.page_capture import CaptureOutput, PageCapture, RouteRequest

FIX = Path(__file__).resolve().parents[1] / "fixtures" / "page_capture"
SEED = "https://login.example.com/secure/"
LIGHT = ScanOptions(mode=Opsec.LIGHT, include={"page_capture"})  # c6: selected by name (-M page_capture)
JPEG = b"\xff\xd8\xff\xe0" + b"\x00" * 64 + b"\xff\xd9"
PROXY = "http://analyst:proxypass@proxy-light.example.net:3128"


def html(name: str) -> str:
    return (FIX / name).read_text(encoding="utf-8")


class FakeDriver:
    """c7: the renderer double - asks the route handler for the navigation (following 3xx answers the
    handler gives) and then for each sub-request the page would make."""

    def __init__(self, subrequests: list[RouteRequest] | None = None, jpeg: bytes | None = JPEG) -> None:
        self.subrequests = subrequests or []
        self.jpeg = jpeg
        self.launches: list[dict] = []
        self.decisions: list[tuple[str, str]] = []

    def capture(self, request):
        self.launches.append(request.launch)
        url, dom = request.seed_url, ""
        for _hop in range(11):
            d = request.route(RouteRequest(url, "GET", "document", True))
            self.decisions.append((url, d.action))
            if d.action != "fulfill":
                break
            if d.status in (301, 302, 303, 307, 308) and d.headers.get("location"):
                url = urljoin(url, d.headers["location"])
                continue
            dom = d.body.decode("utf-8", "replace")
            break
        for sub in self.subrequests:
            self.decisions.append((sub.url, request.route(sub).action))
        return CaptureOutput(final_url=url, dom_html=dom, screenshot_jpeg=self.jpeg, elapsed_s=2.0)


@pytest.fixture()
def env(monkeypatch):
    """A hardened, non-root host with proxy_light configured and a seed the case tagged phishing.
    (ctx.http itself stays on the FakeHttp transport; the real proxy_light fail-closed path is
    tested separately below and in tests/safety/test_egress.py.)"""
    monkeypatch.setattr(mod, "running_as_root", lambda: False)
    monkeypatch.setattr(mod, "proxy_light", lambda ctx: PROXY)
    monkeypatch.setattr(mod, "case_tags", lambda ctx, entity, url: {"phishing"})
    yield monkeypatch
    mod.DRIVER_FACTORY = None


def install(monkeypatch, driver: FakeDriver) -> FakeDriver:
    monkeypatch.setattr(mod, "DRIVER_FACTORY", lambda: driver)
    return driver


def dns(http: FakeHttp, *hosts: str) -> FakeHttp:
    for host in hosts:
        add_dns(http, host, "A", ["93.184.216.34"], provider="all")
        add_dns(http, host, "AAAA", [], provider="all")
    return http


def run(url: str, http: FakeHttp, **kw):
    kw.setdefault("options", LIGHT)
    return run_module(PageCapture, f"url:{url}", http, clock=FakeClock(), **kw)


def target_calls(http: FakeHttp) -> list[dict]:
    return [c for c in http.calls if "dns" not in c["url"] and "resolve" not in c["url"]]


# ---- metadata, hardening (c1, c2, c4) ------------------------------------------------------------


def test_light_metadata_optional_extra_and_offline_selftest():
    cls = PageCapture
    assert cls.opsec is Opsec.LIGHT and cls.disclosure == "target" and cls.default_enabled is False
    assert cls.requires_packages == ("playwright",) and cls.run_on == "seeds" and cls.terms == "open"
    hc = cls.health_check()
    assert hc.offline is True
    assert hc.selftest(make_ctx(cls, FakeHttp())).status in ("ok", "dead")  # no browser is ever started


def test_launch_arguments_are_hardened():
    cfg = mod.launch_config()
    problems = [p for p in mod.check_launch_config(cfg) if not p.startswith("running as root")]
    assert problems == []
    args = cfg["launch"]["args"]
    assert "--force-webrtc-ip-handling-policy=disable_non_proxied_udp" in args  # WebRTC: proxied traffic only
    assert "--disable-quic" in args and "--auth-server-allowlist=_" in args  # QUIC off, no NTLM/Kerberos
    assert any(a.startswith("--host-resolver-rules=MAP * ~NOTFOUND") for a in args)  # no local DNS
    assert "--no-sandbox" not in args and cfg["launch"]["chromium_sandbox"] is True
    assert cfg["context"]["accept_downloads"] is False and cfg["context"]["service_workers"] == "block"
    assert cfg["context"]["permissions"] == [] and cfg["launch"]["proxy"]["server"] == mod.BLACKHOLE_PROXY


def test_recorded_launch_configs():
    assert mod.check_launch_config(module_fixture("page_capture", "launch_config_hardened_synthetic.json")) == []
    problems = mod.check_launch_config(module_fixture("page_capture", "launch_config_unsafe_synthetic.json"))
    for needle in ("chromium_sandbox", "running as root", "--no-sandbox", "--disable-web-security", "--load-extension",
                   "accept_downloads", "service_workers", "permissions", "ignore_https_errors", "bypass_csp", "credentials",
                   "--disable-quic", "no proxy"):
        assert any(needle in p for p in problems), needle


def test_root_refuses_to_start(env):
    env.setattr(mod, "running_as_root", lambda: True)
    drv = install(env, FakeDriver())
    res = run(SEED, dns(FakeHttp(), "login.example.com"))
    assert res.status is Status.SKIPPED and res.reason_code == "config" and drv.launches == []


def test_without_proxy_light_it_fails_closed(env):
    env.setattr(mod, "proxy_light", lambda ctx: "")
    drv = install(env, FakeDriver())
    http = FakeHttp()
    res = run(SEED, http)
    assert res.status is Status.SKIPPED and res.reason_code == "policy" and "proxy_light" in res.error
    assert drv.launches == [] and http.calls == []


def test_a_dead_proxy_light_is_never_bypassed(env):
    env.undo()
    env.setattr(mod, "running_as_root", lambda: False)
    env.setattr(mod, "case_tags", lambda ctx, entity, url: {"phishing"})
    srv = socket.socket()
    srv.bind(("127.0.0.1", 0))
    dead = srv.getsockname()[1]
    srv.close()
    install(env, FakeDriver())
    http = dns(FakeHttp(), "login.example.com")
    http.add("GET", SEED, text=html("dom_phishing_form_synthetic.html"))
    res = run(SEED, http, settings={"proxy_light": f"http://127.0.0.1:{dead}"})
    assert res.status is Status.SKIPPED and res.reason_code == "policy"
    assert not [c for c in target_calls(http) if "login.example.com" in c["url"]]  # nothing on the corporate route


def test_missing_playwright_is_unavailable_package(env):
    env.setattr(mod, "DRIVER_FACTORY", None)
    env.setattr(mod, "package_available", lambda name: False)
    res = run(SEED, FakeHttp())
    assert res.status is Status.UNAVAILABLE and res.reason_code == "package"


# ---- c6 gates -------------------------------------------------------------------------------------


def test_untagged_seed_is_refused_before_any_contact(env):
    env.setattr(mod, "case_tags", lambda ctx, entity, url: set())
    drv = install(env, FakeDriver())
    http = FakeHttp()
    res = run(SEED, http)
    assert res.status is Status.SKIPPED and res.reason_code == "policy" and drv.launches == [] and http.calls == []


def test_preset_deep_without_explicit_selection_is_refused(env):
    drv = install(env, FakeDriver())
    http = FakeHttp()
    res = run(SEED, http, options=ScanOptions(mode=Opsec.LIGHT, include_disabled=True, preset="deep"))
    assert res.status is Status.SKIPPED and res.reason_code == "not_default" and "-M page_capture" in res.error
    assert drv.launches == [] and http.calls == []


def test_pivots_are_never_captured(env):
    drv = install(env, FakeDriver())
    res = run(SEED, FakeHttp(), is_seed=False, depth=1)
    assert res.status is Status.SKIPPED and res.reason_code == "scope" and drv.launches == []


def test_recipient_identifier_needs_a_per_url_confirmation(env):
    url = "https://login.example.com/secure/?u=user%40example.com"
    drv = install(env, FakeDriver())
    res = run(url, FakeHttp())
    assert res.status is Status.SKIPPED and "--confirm-url" in res.error and drv.launches == []


def test_case_tags_read_the_case_graph():
    rt = make_runtime(FakeHttp(), clock=FakeClock())
    graph = Graph()
    node, _ = graph.add_node(Entity.make(T.URL, SEED), seed=True)
    node.add_tag("phishing")
    rt.policy_context = SimpleNamespace(graph=graph)
    ctx = make_ctx(PageCapture, runtime=rt, entity=f"url:{SEED}")
    assert mod.case_tags(ctx, Entity.make(T.URL, SEED), SEED) == {"phishing"}
    assert mod.case_tags(make_ctx(PageCapture, FakeHttp(), entity=f"url:{SEED}"), Entity.make(T.URL, SEED), SEED) == set()


# ---- capture (c3, c5, c8, c9) ---------------------------------------------------------------------


def phishing_http() -> FakeHttp:
    http = dns(FakeHttp(), "login.example.com")
    http.add("GET", SEED, text=html("dom_phishing_form_synthetic.html"), headers={"content-type": "text/html", "set-cookie": "sid=abc"})
    http.add("GET", "https://login.example.com/secure/app.css", text="body{}", headers={"content-type": "text/css"})
    return http


SUBREQUESTS = [
    RouteRequest("https://login.example.com/secure/app.css", "GET", "stylesheet"),
    RouteRequest("https://cdn.example.net/logo-examplebank.png", "GET", "image"),  # other host: LIGHT seed binding
    RouteRequest("http://10.0.0.1/admin", "GET", "xhr"),  # private address
    RouteRequest("http://169.254.169.254/latest/meta-data/", "GET", "fetch"),  # cloud metadata
    RouteRequest("http://2130706433/", "GET", "fetch"),  # decimal loopback
    RouteRequest("http://intranet/", "GET", "fetch"),  # single-label intranet name
    RouteRequest("file:///etc/passwd", "GET", "document"),
    RouteRequest("wss://evil.example.org/socket", "GET", "websocket"),
    RouteRequest("https://login.example.com/secure/post.php", "POST", "xhr"),  # auto-submitted form
]


def test_phishing_capture_is_hashed_evidence_fetched_only_through_ctx_http(env):
    drv = install(env, FakeDriver(SUBREQUESTS))
    http = phishing_http()
    res = run(SEED, http)
    assert res.status is Status.OK, res.error
    f = {x.title: x for x in res.findings}["Phishing indicators observed in a headless capture"]
    assert f.severity.label == "medium" and f.criterion and "phishing" in f.tags
    assert "user@example.com" not in f.description
    ev = res.attributes["page_capture"]
    assert ev["seed_url"] == SEED and ev["final_url"] == SEED and ev["verdict"] == "phishing indicators observed"
    assert set(ev["sha256"]) == {"screenshot", "dom", "har"} and all(len(v) == 64 for v in ev["sha256"].values())
    assert ev["captured_at_utc"].startswith("2026-11-26T12:00") and ev["captured_at_sao_paulo"].endswith("-03:00")
    assert ev["egress_profile"] and ev["tlp"] == "amber" and ev["blocked_requests"] >= 7
    shot = res.attributes["page_screenshot"]
    assert shot["data_uri"].startswith("data:image/jpeg;base64,") and "egress" in shot["caption"] and "America/Sao_Paulo" in shot["caption"]
    assert res.attributes["login_form"] is True and "user@example.com" not in json.dumps(res.attributes.get("title", ""))
    hosts = {c["url"].split("/")[2] for c in target_calls(http)}
    assert hosts == {"login.example.com"}  # never the CDN, a private/metadata address, a WebSocket or a POST
    assert all(c["method"] in ("GET", "HEAD") for c in target_calls(http))
    blocked = dict((u, a) for u, a in drv.decisions)
    assert blocked["https://cdn.example.net/logo-examplebank.png"] == "abort"
    assert blocked["https://login.example.com/secure/post.php"] == "abort"
    raw = json.dumps(res.raw)
    assert "proxypass" not in raw and "sid=abc" not in raw  # no proxy credential or cookie value in the evidence
    assert drv.launches[0]["launch"]["chromium_sandbox"] is True
    pivots = {(p.entity.type.value, p.entity.value, p.relation) for p in res.pivots}
    assert any(rel == "capture_form_action_host" for _t, _v, rel in pivots)


def test_benign_looking_page_is_inconclusive_never_benign(env):
    install(env, FakeDriver())
    http = dns(FakeHttp(), "login.example.com")
    http.add("GET", SEED, text=html("dom_benign_example.html"), headers={"content-type": "text/html"})
    res = run(SEED, http)
    assert res.status is Status.OK
    assert res.attributes["capture_verdict"] == "inconclusive (possible cloaking/geofencing)"
    assert "benign" not in json.dumps(res.attributes).lower().replace("never benign", "")
    f = res.findings[0]
    assert f.severity.label == "info" and "cloaking_possible" in f.tags


@pytest.mark.parametrize(("fixture", "status"), [("dom_challenge_cloudflare.html", 403), ("dom_turnstile_gate_synthetic.html", 200),
                                                  ("dom_hcaptcha_synthetic.html", 200)])
def test_challenge_pages_end_blocked_without_retry(env, fixture, status):
    install(env, FakeDriver())
    http = dns(FakeHttp(), "login.example.com")
    http.add("GET", SEED, status=status, text=html(fixture), headers={"content-type": "text/html"})
    res = run(SEED, http)
    assert res.status is Status.BLOCKED and res.reason_code == "challenge"
    assert len([c for c in target_calls(http) if c["url"] == SEED]) == 1  # no retry


def test_redirects_are_followed_by_ctx_http_and_recorded(env):
    install(env, FakeDriver())
    http = dns(FakeHttp(), "login.example.com", "www.example.org")
    http.add("GET", SEED, redirect_to="https://www.example.org/landing")
    http.add("GET", "https://www.example.org/landing", text=html("dom_phishing_form_synthetic.html"), headers={"content-type": "text/html"})
    res = run(SEED, http)
    assert res.status is Status.OK, res.error
    ev = res.attributes["page_capture"]
    assert ev["final_url"] == "https://www.example.org/landing" and ev["redirect_chain"][0] == SEED
    assert ("url", "https://www.example.org/landing", "capture_final_url") in {(p.entity.type.value, p.entity.value, p.relation) for p in res.pivots}
    assert len([c for c in target_calls(http) if c["url"] == "https://www.example.org/landing"]) == 1  # served once to the renderer


def test_a_confirmed_url_carrying_a_victim_address_is_masked_in_report_text(env):
    """The core refuses unconfirmed recipient-token hops (GUARD-02); a confirmed capture keeps the exact
    URL in the evidence only - attributes, findings and pivots never carry the victim's address (c8)."""
    install(env, FakeDriver())
    url = "https://login.example.com/secure/?u=user%40example.com"
    final = "https://www.example.org/landing?email=user%40example.com"
    http = dns(FakeHttp(), "login.example.com", "www.example.org")
    http.add("GET", url, redirect_to=final)
    http.add("GET", final, text=html("dom_phishing_form_synthetic.html"), headers={"content-type": "text/html"})
    opts = ScanOptions(mode=Opsec.LIGHT, include={"page_capture"}, confirmed_urls={url, final})
    res = run(url, http, options=opts)
    assert res.status is Status.OK, res.error
    shown = json.dumps({"a": res.attributes, "f": [f.description for f in res.findings]})
    assert "user%40example.com" not in shown and "user@example.com" not in shown
    assert not [p for p in res.pivots if p.relation == "capture_final_url"]
    assert res.raw["evidence"]["final_url"] == final  # the court-usable record keeps the exact URL (case evidence)


def test_nothing_is_fetched_after_the_time_budget(env, monkeypatch):
    router = mod._Router(make_ctx(PageCapture, FakeHttp(), entity=f"url:{SEED}", options=LIGHT), SEED, 30.0)
    monkeypatch.setattr(mod.time, "monotonic", lambda: router._t0 + 31.0)
    decision = router(RouteRequest(SEED, "GET", "document", True))
    assert decision.action == "abort" and router.partial == "deadline" and router.count == 0


def test_document_navigations_are_capped_at_the_redirect_budget(env):
    router = mod._Router(make_ctx(PageCapture, FakeHttp(), entity=f"url:{SEED}", options=LIGHT), SEED, 30.0)
    router.navigations = mod.BUDGET["max_redirects"] + 1
    decision = router(RouteRequest("https://login.example.com/next", "GET", "document", True))
    assert decision.action == "abort" and "redirect budget" in decision.reason and router.count == 0


def test_request_ceiling_stops_the_capture_partial(env):
    subs = [RouteRequest(f"https://login.example.com/secure/a{i}.js", "GET", "script") for i in range(40)]
    install(env, FakeDriver(subs))
    http = phishing_http()
    for i in range(40):
        http.add("GET", f"https://login.example.com/secure/a{i}.js", text="//", headers={"content-type": "text/javascript"})
    res = run(SEED, http)
    assert res.status is Status.OK and res.partial and res.stop_reason == "request_cap"
    assert len(target_calls(http)) <= 25  # LIGHT: <= 25 requests per target host per scan


def test_kill_switch_stops_the_capture(env):
    class CancellingDriver(FakeDriver):
        def capture(self, request):
            ctx.runtime.cancel("cancelled")
            return super().capture(request)

    install(env, CancellingDriver([RouteRequest("https://login.example.com/secure/app.css")]))
    http = phishing_http()
    ctx = make_ctx(PageCapture, http, entity=f"url:{SEED}", options=LIGHT)
    with pytest.raises(Cancelled):
        PageCapture().run(Entity.make(T.URL, SEED), ctx)
    assert target_calls(http) == []


def test_seed_on_a_private_address_is_refused(env):
    drv = install(env, FakeDriver())
    res = run("http://10.1.2.3/login", FakeHttp())
    assert res.status is Status.SKIPPED and res.reason_code == "policy" and drv.launches == []


# ---- pure helpers -------------------------------------------------------------------------------------


@pytest.mark.parametrize(("url", "why"), [
    ("ftp://example.com/x", "scheme"), ("https://user:pw@example.com/", "userinfo"), ("http://127.0.0.1/", "loopback"),
    ("http://0x7f.1/", "loopback"), ("http://[::ffff:127.0.0.1]/", "loopback"), ("http://169.254.169.254/", "metadata"),
    ("http://100.64.1.1/", "cgnat"), ("http://[fd00::1]/", "ula"), ("http://10.0.0.1/", "private"),
    ("http://metadata.google.internal/", "metadata"), ("http://printer.local/", "intranet_name"), ("http://intranet/", "intranet_name"),
    ("https://example.com/", None),
])
def test_destination_guard(url, why):
    assert mod.destination_block_reason(url) == why


def test_dns_rebinding_is_refused():
    assert mod.destination_block_reason("https://rebind.example.com/", ["10.0.0.7"]) == "dns_rebinding"


def test_har_scrubbing_and_email_redaction():
    har = json.loads((FIX / "har_ok_synthetic.har").read_text(encoding="utf-8"))
    assert "proxypass" in json.dumps(har)  # the fixture carries the values on purpose
    clean = json.dumps(mod.scrub_har(har, ["proxypass"]))
    assert "proxypass" not in clean and "Bearer " not in clean
    assert mod.redact_emails("contact user@example.com now") == "contact u***@example.com now"


def test_evidence_helpers():
    now = FakeClock().now()
    rec = mod.evidence_record(seed_url=SEED, final_url=SEED, redirect_chain=[SEED], captured_at=now, screenshot=JPEG, dom=b"<html>",
                              har=b"{}", egress_profile="light", tlp="amber")
    assert rec["captured_at_sao_paulo"].startswith("2026-11-26T09:00") and rec["sha256"]["har"]
    assert mod.jpeg_data_uri(b"\x89PNG....")[0] is None
    assert mod.jpeg_data_uri(b"\xff\xd8\xff" + b"0" * (2 * 1024 * 1024) + b"\xff\xd9")[1].startswith("data URI")
    assert mod.budget_violations(request_count=151, redirect_hops=11, har_bytes=26 * 1024 * 1024, elapsed_s=31, screenshots=2)
    assert mod.capture_verdict({"forms": [], "challenge": None})["label"] == "inconclusive (possible cloaking/geofencing)"
    summary = mod.dom_summary(html("dom_phishing_form_synthetic.html"), SEED)
    assert summary["forms"] and summary["email_count"] >= 1 and "user@example.com" not in summary["text_excerpt"]
