"""SSRF and redirect guard (AR02), scope and seed binding (A7) and the LIGHT/ACTIVE request rules
(WP11) of the HTTP client: FakeHttp redirect chains with fake DNS answers (DoH through the egress
profile), pinning of the checked address, method allow-list, UA rules and ceilings."""

from __future__ import annotations

import copy
import json
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs, urlsplit

import pytest

from tests.fakes import DOH_HOSTS, FakeClock, FakeHttp, add_dns
from v3lum import __version__
from v3lum.config import Config
from v3lum.core import http as http_mod
from v3lum.core import noise
from v3lum.core.context import RunInfo
from v3lum.core.entities import Entity
from v3lum.core.http import (
    Blocked,
    Cancelled,
    HttpClient,
    PolicyError,
    RequestCapReached,
    RequestsTransport,
    Response,
    ScopedHttp,
    allowed_methods,
    host_problem,
    ip_problem,
    method_allowlist,
    method_allowlist_errors,
    reload_method_allowlist,
)
from v3lum.core.net import EgressProfiles
from v3lum.core.scope import Scope

UA_LIGHT = "Mozilla/5.0 (X11; Linux x86_64) TestBrowser/9.9"
SCOPE = {
    "authorization_ref": "PENTEST-2026-042",
    "owner": "ACME S.A.",
    "contacts": ["soc@acme.example"],
    "ticket": "SEC-1",
    "window_start": "2026-01-01T00:00:00Z",
    "window_end": "2099-12-31T23:59:59Z",  # wide: tests on the real clock never age out
    "targets": {"domains": ["acme.example", "*.acme.example"], "cidrs": ["93.184.216.0/24"]},
    "roe": {"user_agent": "pentest-PENTEST-2026-042", "header": {"name": "X-Engagement-Token", "value": "c0ffee42"}},
}


def make_scope(**changes) -> Scope:
    data = copy.deepcopy(SCOPE)
    data.update(changes)
    return Scope.from_dict(data)


def client(http: FakeHttp, *, egress=None, **settings) -> HttpClient:
    cfg = Config()
    cfg.settings.update({"ua_light": UA_LIGHT, **settings})
    return HttpClient(transport=http, clock=http.clock, settings=cfg, retries=0, egress=egress)


def fake() -> FakeHttp:
    return FakeHttp(clock=FakeClock())


def dns(http: FakeHttp, name: str, a=(), aaaa=()) -> None:
    add_dns(http, name, "A", list(a))
    add_dns(http, name, "AAAA", list(aaaa))


def seed(url: str, **kw) -> RunInfo:
    kw.setdefault("case_id", "case-1")
    return RunInfo(entity=Entity.make("url", url), **kw)


def target_calls(http: FakeHttp) -> list[dict]:
    """Calls that reached a target (DoH lookups, public or the internal resolver, excluded)."""
    return [c for c in http.calls if (urlsplit(c["url"]).hostname or "") not in (*DOH_HOSTS, "doh.corp.example")]


def looked_up(http: FakeHttp) -> set[str]:
    names = set()
    for c in http.calls:
        if (urlsplit(c["url"]).hostname or "") in DOH_HOSTS:
            names |= set(parse_qs(urlsplit(c["url"]).query).get("name", []))
    return names


@pytest.fixture()
def cdn_list(tmp_path):
    frag = tmp_path / "noise"
    frag.mkdir()
    (frag / "cdn_test.json").write_text(
        json.dumps({"schema": "v3lum.noise/1", "kind": "cdn", "source": "test", "licence": "CC0-1.0", "cidrs": ["104.16.0.0/13"]}), encoding="utf-8"
    )
    noise.reload(extra_dirs=[frag])
    yield
    noise.reload(extra_dirs=())


@pytest.fixture()
def allowlist_dir(tmp_path):
    folder = tmp_path / "method_allowlist"
    folder.mkdir()
    yield folder
    reload_method_allowlist(extra_dirs=())


# --------------------------------------------------------------------------------------
# address and name classes
# --------------------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("value", "expected"),
    [
        ("10.0.0.5", "private"),
        ("172.16.3.4", "private"),
        ("192.168.1.1", "private"),
        ("127.0.0.1", "loopback"),
        ("::1", "loopback"),
        ("169.254.169.254", "cloud metadata"),
        ("fd00:ec2::254", "cloud metadata"),
        ("169.254.10.10", "link-local"),
        ("fe80::1", "link-local"),
        ("100.64.1.1", "CGNAT"),
        ("fc00::1", "unique local (ULA)"),
        ("224.0.0.1", "multicast"),
        ("0.0.0.0", "reserved"),
        ("240.0.0.1", "reserved"),
        ("203.0.113.9", "documentation range"),
        ("::ffff:10.0.0.5", "private (IPv4 embedded in IPv6)"),
        ("2002:a00:5::1", "private (IPv4 embedded in IPv6)"),
        ("64:ff9b::a00:5", "private (IPv4 embedded in IPv6)"),
        ("93.184.216.34", ""),
        ("2606:4700:4700::1111", ""),
        ("not-an-ip", "not an IP address"),
    ],
)
def test_ip_problem_classes(value, expected):
    assert ip_problem(value) == expected


@pytest.mark.parametrize(
    ("host", "needle"),
    [
        ("intranet", "single-label"),
        ("metadata.google.internal", "internal name (.internal)"),
        ("printer.local", ".local"),
        ("nas.lan", ".lan"),
        ("wiki.corp", ".corp"),
        ("router.home", ".home"),
        ("x.localdomain", ".localdomain"),
        ("a.localhost", ".localhost"),
        ("2130706433", "ambiguous numeric"),
        ("0x7f.1", "ambiguous numeric"),
        ("0177.0.0.1", "ambiguous numeric"),
        ("10.0.0.5", "private"),
        ("www.example.com", ""),
    ],
)
def test_host_problem(host, needle):
    found = host_problem(host)
    assert (needle in found) if needle else found == ""


# --------------------------------------------------------------------------------------
# redirect chains with fake DNS answers
# --------------------------------------------------------------------------------------


@pytest.mark.parametrize(("ip", "rtype"), [("10.0.0.5", "A"), ("169.254.169.254", "A"), ("::1", "AAAA"), ("100.64.1.1", "A"), ("fc00::1", "AAAA")])
def test_a_redirect_to_a_name_resolving_inside_is_never_sent(ip, rtype):
    http = fake()
    dns(http, "seed.example.com", a=["93.184.216.34"])
    http.add("GET", "https://seed.example.com/", redirect_to="https://inner.example.net/admin")
    dns(http, "inner.example.net", a=[ip] if rtype == "A" else [], aaaa=[ip] if rtype == "AAAA" else [])
    with pytest.raises(PolicyError) as err:
        client(http).request("GET", "https://seed.example.com/", opsec="light", run=seed("https://seed.example.com/"))
    assert err.value.reason_code == "policy" and ip in str(err.value) and "SSRF" in str(err.value)
    assert [c["url"] for c in target_calls(http)] == ["https://seed.example.com/"]  # inner.example.net never contacted
    assert "inner.example.net" in looked_up(http)  # checked after resolution through the profile


@pytest.mark.parametrize(
    "target",
    [
        "https://intranet/",
        "https://metadata.google.internal/computeMetadata/v1/",
        "https://printer.local/",
        "https://2130706433/",
        "https://0x7f.1/",
        "https://169.254.169.254/latest/meta-data/",
        "https://[::1]/",
    ],
)
def test_internal_names_and_literals_are_refused_before_any_lookup(target):
    http = fake()
    dns(http, "seed.example.com", a=["93.184.216.34"])
    http.add("GET", "https://seed.example.com/", redirect_to=target)
    with pytest.raises(PolicyError) as err:
        client(http).request("GET", "https://seed.example.com/", opsec="light", run=seed("https://seed.example.com/"))
    assert err.value.reason_code == "policy"
    host = urlsplit(target).hostname
    assert host not in looked_up(http)  # refused by name: never even resolved
    assert len(target_calls(http)) == 1


def test_unbound_requests_still_get_the_name_and_literal_checks():
    http = fake().add("GET", "http://127.0.0.1:8080/", text="ok")
    c = client(http)
    with pytest.raises(PolicyError):
        c.request("GET", "http://127.0.0.1:8080/", opsec="light")
    with pytest.raises(PolicyError):
        c.request("GET", "https://intranet/", opsec="active")
    assert not http.calls


INTERNAL_DOH = "https://doh.corp.example/dns-query"


def internal_dns(http: FakeHttp, name: str, a=(), aaaa=()) -> None:
    add_dns(http, name, "A", list(a), provider=INTERNAL_DOH)
    add_dns(http, name, "AAAA", list(aaaa), provider=INTERNAL_DOH)


def test_an_internal_typed_seed_is_allowed_and_pinned():
    http = fake()
    internal_dns(http, "wiki.corp", a=["10.20.30.40"])
    http.add("GET", "https://wiki.corp/status", text="ok")
    run = seed("https://wiki.corp/status", internal_seed=True)
    resp = client(http, doh_internal=INTERNAL_DOH).request("GET", "https://wiki.corp/status", opsec="light", run=run)
    assert resp.status == 200
    assert target_calls(http)[-1]["pin_ip"] == "10.20.30.40"
    # the same request without the internal flag is refused (internal name and private address)
    with pytest.raises(PolicyError):
        client(fake()).request("GET", "https://wiki.corp/status", opsec="light", run=seed("https://wiki.corp/status"))


def test_internal_names_never_go_to_a_public_resolver():
    """An internal name is resolved only by the organisation's own DoH (setting doh_internal): never
    by Google/Cloudflare (it would leak the internal namespace), never through a proxied profile."""
    from v3lum.core.http import NetworkError

    http = fake()
    dns(http, "wiki.corp", a=["10.20.30.40"])  # a public resolver would answer: it must never be asked
    run = seed("https://wiki.corp/status", internal_seed=True)
    with pytest.raises(NetworkError) as err:
        client(http).request("GET", "https://wiki.corp/status", opsec="light", run=run)  # no doh_internal configured
    assert "could not verify" in str(err.value)
    assert http.calls == [] and "wiki.corp" not in looked_up(http)
    light = fake()
    settings = Config()
    settings.settings.update({"proxy_light": "http://127.0.0.1:3128", "doh_internal": INTERNAL_DOH})
    egress = EgressProfiles(settings, transports={"light": light})  # an injected transport stands for the proxy
    with pytest.raises(NetworkError) as err:
        HttpClient(transport=http, egress=egress, retries=0).request("GET", "https://wiki.corp/", opsec="light", run=run)
    assert "internal name" in str(err.value) and light.calls == [] and http.calls == []


def test_an_internal_seed_never_unlocks_cloud_metadata():
    http = fake()
    internal_dns(http, "wiki.corp", a=["10.20.30.40"])
    http.add("GET", "http://wiki.corp/", redirect_to="http://169.254.169.254/latest/meta-data/")
    with pytest.raises(PolicyError) as err:
        client(http, doh_internal=INTERNAL_DOH).request("GET", "http://wiki.corp/", opsec="light", run=seed("http://wiki.corp/", internal_seed=True))
    assert "cloud metadata" in str(err.value)
    assert [c["url"] for c in target_calls(http)] == ["http://wiki.corp/"]


def test_the_checked_address_is_pinned_and_recorded():
    http = fake()
    dns(http, "seed.example.com", a=["93.184.216.34"], aaaa=["2606:2800:220:1:248:1893:25c8:1946"])
    http.add("GET", "https://seed.example.com/", text="ok")
    infos = []
    c = client(http)
    c.on_request_info = infos.append
    resp = c.request("GET", "https://seed.example.com/", opsec="light", run=seed("https://seed.example.com/"))
    assert resp.status == 200
    call = target_calls(http)[-1]
    assert call["pin_ip"] == "93.184.216.34"  # IPv4 preferred; the transport connects to it
    sent = [i for i in infos if i.host == "seed.example.com"][-1]
    assert (sent.resolved_ip, sent.egress_profile, sent.opsec) == ("93.184.216.34", "default", "light")


class _HostEcho(BaseHTTPRequestHandler):
    seen: list[str] = []

    def log_message(self, *args):  # silence
        pass

    def do_GET(self):  # noqa: N802
        _HostEcho.seen.append(self.headers.get("Host", ""))
        body = b"pinned"
        self.send_response(200)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)


@pytest.fixture()
def echo_server():
    _HostEcho.seen = []
    srv = ThreadingHTTPServer(("127.0.0.1", 0), _HostEcho)
    thread = threading.Thread(target=srv.serve_forever, kwargs={"poll_interval": 0.05}, daemon=True)
    thread.start()
    yield srv.server_address[1]
    srv.shutdown()


def test_the_real_transport_connects_to_the_checked_address(echo_server):
    """Direct route: the connection goes to the checked IP while Host keeps the name (a local
    resolution of the name would hit the test network guard)."""
    port = echo_server
    egress = EgressProfiles(Config(), resolver=lambda host, profile: ["127.0.0.1"])
    c = HttpClient(transport=RequestsTransport(trust_env=False), egress=egress, retries=0, timeout=5)
    url = f"http://pinned.example.test:{port}/hello"
    resp = c.request("GET", url, opsec="light", run=seed(url, internal_seed=True))
    assert resp.status == 200 and resp.content == b"pinned"
    assert resp.pinned_ip == "127.0.0.1"
    assert _HostEcho.seen == [f"pinned.example.test:{port}"]


def test_a_name_that_does_not_resolve_is_not_sent():
    http = fake()
    add_dns(http, "gone.example.com", "A", [], status=3)
    add_dns(http, "gone.example.com", "AAAA", [], status=3)
    from v3lum.core.http import NetworkError

    with pytest.raises(NetworkError) as err:
        client(http).request("GET", "https://gone.example.com/", opsec="light", run=seed("https://gone.example.com/"))
    assert "does not resolve" in str(err.value)
    assert not target_calls(http)


# --------------------------------------------------------------------------------------
# seed binding (LIGHT) and scope binding (ACTIVE)
# --------------------------------------------------------------------------------------


def test_light_runs_only_on_the_typed_seed():
    http = fake()
    dns(http, "www.seed.example.com", a=["93.184.216.34"])
    http.add("GET", "https://www.seed.example.com/", text="ok")
    c = client(http)
    run = RunInfo(entity=Entity.make("domain", "seed.example.com"), case_id="c")
    assert c.request("GET", "https://www.seed.example.com/", opsec="light", run=run).status == 200  # a subdomain of the seed
    with pytest.raises(PolicyError) as err:
        c.request("GET", "https://other.example.net/", opsec="light", run=run)
    assert err.value.reason_code == "scope"
    pivot = RunInfo(entity=Entity.make("domain", "seed.example.com"), is_seed=False, case_id="c")
    with pytest.raises(PolicyError) as err:
        c.request("GET", "https://www.seed.example.com/", opsec="light", run=pivot)
    assert err.value.reason_code == "scope" and "pivots" in str(err.value)


def test_active_needs_a_scope_and_stays_inside_it():
    http = fake()
    dns(http, "www.acme.example", a=["93.184.216.34"])
    http.add("GET", "https://www.acme.example/", redirect_to="https://partner.example.org/")
    dns(http, "partner.example.org", a=["93.184.217.1"])
    c = client(http)
    run = RunInfo(entity=Entity.make("domain", "www.acme.example"), case_id="c")
    with pytest.raises(PolicyError) as err:
        c.request("GET", "https://www.acme.example/", opsec="active", run=run)  # no scope
    assert err.value.reason_code == "scope" and "--scope" in str(err.value)
    sc = make_scope()
    with pytest.raises(PolicyError) as err:
        c.request("GET", "https://outside.example.net/", opsec="active", run=run, scope=sc)
    assert err.value.reason_code == "scope"
    with pytest.raises(PolicyError) as err:  # in scope, but the redirect target is not
        c.request("GET", "https://www.acme.example/", opsec="active", run=run, scope=sc)
    assert err.value.reason_code == "scope" and "redirect" in str(err.value)
    assert [c_["url"] for c_ in target_calls(http)] == ["https://www.acme.example/"]


def test_active_in_scope_name_resolving_privately_is_refused_unless_listed():
    http = fake()
    dns(http, "db.acme.example", a=["10.0.0.7"])
    http.add("GET", "https://db.acme.example/", text="ok")
    run = RunInfo(entity=Entity.make("domain", "db.acme.example"), case_id="c")
    with pytest.raises(PolicyError):
        client(http).request("GET", "https://db.acme.example/", opsec="active", run=run, scope=make_scope())
    assert not target_calls(http)
    listed = make_scope(targets={"domains": ["acme.example", "*.acme.example"], "cidrs": ["10.0.0.0/24"]})
    assert client(http).request("GET", "https://db.acme.example/", opsec="active", run=run, scope=listed).status == 200


def test_active_cdn_targets_need_shared_infra_hosts(cdn_list):
    http = fake()
    dns(http, "www.acme.example", a=["104.16.5.5"])
    http.add("GET", "https://www.acme.example/", text="ok")
    run = RunInfo(entity=Entity.make("domain", "www.acme.example"), case_id="c")
    with pytest.raises(PolicyError) as err:
        client(http).request("GET", "https://www.acme.example/", opsec="active", run=run, scope=make_scope())
    assert err.value.reason_code == "scope" and "shared_infra_hosts" in str(err.value)
    assert not target_calls(http)
    shared = make_scope(shared_infra_hosts=["www.acme.example"])
    assert client(http).request("GET", "https://www.acme.example/", opsec="active", run=run, scope=shared).status == 200


# --------------------------------------------------------------------------------------
# hostile-host guard on redirect targets
# --------------------------------------------------------------------------------------


class Decision:
    def __init__(self, allowed: bool, status: str = "blocked", reason_code: str = "hostile_host", reason: str = "") -> None:
        self.allowed, self.status, self.reason_code, self.reason = allowed, status, reason_code, reason


def test_redirect_targets_rerun_the_contact_guard():
    http = fake()
    dns(http, "seed.example.com", a=["93.184.216.34"])
    http.add("GET", "https://seed.example.com/", redirect_to="https://evil.example.net/kit")
    dns(http, "evil.example.net", a=["93.184.217.66"])
    seen: list[str] = []

    def guard(url: str) -> Decision:
        seen.append(url)
        return Decision(False, reason="evil.example.net is tagged phishing: needs non-corporate egress")

    with pytest.raises(Blocked) as err:
        client(http).request("GET", "https://seed.example.com/", opsec="light", run=seed("https://seed.example.com/"), contact_guard=guard)
    assert err.value.reason_code == "hostile_host" and "non-corporate egress" in str(err.value)
    assert seen == ["https://evil.example.net/kit"]  # the first hop was decided by the engine already
    assert [c["url"] for c in target_calls(http)] == ["https://seed.example.com/"]


def test_a_failing_guard_refuses_the_hop():
    http = fake()
    dns(http, "seed.example.com", a=["93.184.216.34"])
    http.add("GET", "https://seed.example.com/", redirect_to="https://next.example.net/")

    def guard(url: str) -> Decision:
        raise RuntimeError("graph unavailable")

    with pytest.raises(PolicyError):
        client(http).request("GET", "https://seed.example.com/", opsec="light", run=seed("https://seed.example.com/"), contact_guard=guard)


def test_a_skipped_guard_decision_is_a_policy_refusal():
    http = fake()
    dns(http, "seed.example.com", a=["93.184.216.34"])
    http.add("GET", "https://seed.example.com/", redirect_to="https://next.example.net/?u=0123456789abcdef0123")
    dns(http, "next.example.net", a=["93.184.217.2"])
    with pytest.raises(PolicyError) as err:
        client(http).request(
            "GET", "https://seed.example.com/", opsec="light", run=seed("https://seed.example.com/"),
            contact_guard=lambda url: Decision(False, status="skipped", reason_code="policy", reason="URL carries a per-recipient token"),
        )
    assert "per-recipient token" in str(err.value)


# --------------------------------------------------------------------------------------
# method rules (A7) and the allow-list fragments
# --------------------------------------------------------------------------------------


def test_light_and_active_methods():
    http = fake().add("*", "https://93.184.216.34/", text="ok")
    c = client(http)
    with pytest.raises(PolicyError) as err:
        c.request("POST", "https://93.184.216.34/", opsec="light", data={"a": "1"}, module="t_mod")
    assert "method_allowlist/t_mod.json" in str(err.value)
    with pytest.raises(PolicyError):
        c.request("OPTIONS", "https://93.184.216.34/", opsec="light", module="t_mod")
    assert c.request("OPTIONS", "https://93.184.216.34/", opsec="active", module="t_mod").status == 200
    for method in ("DELETE", "PUT", "PATCH"):
        with pytest.raises(PolicyError):
            c.request(method, "https://93.184.216.34/", opsec="active", module="t_mod")
    assert allowed_methods("t_mod", "light") == {"GET", "HEAD"} and allowed_methods("t_mod", "active") == {"GET", "HEAD", "OPTIONS"}
    assert len(target_calls(http)) == 1


def test_an_approved_fragment_allows_a_read_only_method(allowlist_dir):
    (allowlist_dir / "t_graphql.json").write_text(
        json.dumps({"schema": "v3lum.method_allow/1", "module": "t_graphql", "methods": {"POST": "GraphQL introspection is a read"}, "approved_by": "architect", "decision_ref": "ADR-7"}),
        encoding="utf-8",
    )
    (allowlist_dir / "t_unapproved.json").write_text(
        json.dumps({"schema": "v3lum.method_allow/1", "module": "t_unapproved", "methods": {"POST": "x"}, "approved_by": "", "decision_ref": ""}), encoding="utf-8"
    )
    (allowlist_dir / "t_writer.json").write_text(
        json.dumps({"schema": "v3lum.method_allow/1", "module": "t_writer", "methods": {"DELETE": "cleanup"}, "approved_by": "a", "decision_ref": "b"}), encoding="utf-8"
    )
    reload_method_allowlist(extra_dirs=[allowlist_dir])
    assert set(method_allowlist()) == {"t_graphql"}
    errors = method_allowlist_errors()
    assert any("t_unapproved" in e and "approved_by and decision_ref" in e for e in errors)
    assert any("t_writer" in e and "can never be allow-listed" in e for e in errors)
    http = fake().add("POST", "https://93.184.216.34/graphql", json={"data": {}})
    c = client(http)
    assert c.request("POST", "https://93.184.216.34/graphql", opsec="active", json_body={"query": "{__schema{types{name}}}"}, module="t_graphql").status == 200
    with pytest.raises(PolicyError):
        c.request("POST", "https://93.184.216.34/graphql", opsec="active", module="t_unapproved")


def test_shipped_tree_has_no_allowlist_problems():
    reload_method_allowlist(extra_dirs=())
    assert method_allowlist() == {} and method_allowlist_errors() == []
    readme = http_mod._ALLOWLIST_DIR / "README.md"
    assert readme.is_file()


# --------------------------------------------------------------------------------------
# identity: no V3LUM/contact UA or organisation identity toward targets (P326 cond 5)
# --------------------------------------------------------------------------------------


def test_bound_light_requests_use_ua_light_and_drop_identity_headers():
    http = fake()
    dns(http, "seed.example.com", a=["93.184.216.34"])
    http.add("GET", "https://seed.example.com/", text="ok")
    c = client(http, contact_email="cti@acme.example")
    c.request(
        "GET", "https://seed.example.com/", opsec="light", run=seed("https://seed.example.com/"),
        headers={"User-Agent": f"V3LUM/{__version__} (+cti@acme.example)", "From": "cti@acme.example", "X-Note": "ask cti@acme.example", "Accept": "text/html"},
    )
    headers = {k.lower(): v for k, v in target_calls(http)[-1]["headers"].items()}
    assert headers["user-agent"] == UA_LIGHT
    assert "from" not in headers and "x-note" not in headers and headers["accept"] == "text/html"
    assert not any("v3lum" in v.lower() or "acme" in v.lower() for v in headers.values())


def test_active_requests_carry_the_roe_identity_only():
    http = fake()
    dns(http, "www.acme.example", a=["93.184.216.34"])
    http.add("GET", "https://www.acme.example/", text="ok")
    run = RunInfo(entity=Entity.make("domain", "www.acme.example"), case_id="c")
    client(http).request("GET", "https://www.acme.example/", opsec="active", run=run, scope=make_scope(), user_agent="custom/1.0")
    headers = {k.lower(): v for k, v in target_calls(http)[-1]["headers"].items()}
    assert headers["user-agent"] == "pentest-PENTEST-2026-042" and headers["x-engagement-token"] == "c0ffee42"
    bare = make_scope(roe={})
    client(http).request("GET", "https://www.acme.example/", opsec="active", run=run, scope=bare)
    headers = {k.lower(): v for k, v in target_calls(http)[-1]["headers"].items()}
    assert headers["user-agent"] == UA_LIGHT and "x-engagement-token" not in headers


# --------------------------------------------------------------------------------------
# ceilings (A7) and the kill switch
# --------------------------------------------------------------------------------------


def test_light_is_one_request_per_second_and_25_per_host_per_scan():
    http = fake().add("GET", "https://93.184.216.34/", text="ok")
    c = client(http)
    for _ in range(25):
        c.request("GET", "https://93.184.216.34/", opsec="light", module="t_light")
    assert http.clock.sleeps.count(pytest.approx(1.0)) == 24  # 1 req/s per target host
    with pytest.raises(RequestCapReached) as err:
        c.request("GET", "https://93.184.216.34/", opsec="light", module="t_light")
    assert "25 requests" in str(err.value)
    c.reset_circuit()  # a new scan
    assert c.request("GET", "https://93.184.216.34/", opsec="light", module="t_light").status == 200


def test_active_rate_and_case_budget_follow_the_scope():
    http = fake()
    dns(http, "www.acme.example", a=["93.184.216.34"])
    http.add("GET", "https://www.acme.example/", text="ok")
    c = client(http)
    sc = make_scope(limits={"max_rps": 5, "max_requests": 3})
    run = RunInfo(entity=Entity.make("domain", "www.acme.example"), case_id="case-9")
    for _ in range(3):
        c.request("GET", "https://www.acme.example/", opsec="active", run=run, scope=sc)
    assert http.clock.sleeps == [pytest.approx(0.2), pytest.approx(0.2)]  # 5 req/s from the scope
    with pytest.raises(RequestCapReached) as err:
        c.request("GET", "https://www.acme.example/", opsec="active", run=run, scope=sc)
    assert "ACTIVE budget" in str(err.value)
    other_case = RunInfo(entity=Entity.make("domain", "www.acme.example"), case_id="case-10")
    assert c.request("GET", "https://www.acme.example/", opsec="active", run=other_case, scope=sc).status == 200


class _SlowTransport:
    """Counts concurrent sends; each send waits a little (real threads)."""

    def __init__(self) -> None:
        self.active = 0
        self.peak = 0
        self.lock = threading.Lock()

    def send(self, method, url, *, headers, body=None, timeout=None, max_bytes=None, deadline=None):
        with self.lock:
            self.active += 1
            self.peak = max(self.peak, self.active)
        time.sleep(0.05)
        with self.lock:
            self.active -= 1
        return Response(200, url, {}, b"ok")


def test_active_holds_at_most_two_connections_per_host():
    transport = _SlowTransport()
    c = HttpClient(transport=transport, retries=0, max_per_host=8)
    c.limiter.reserve = lambda host, interval=0.0: 0.0  # isolate concurrency from pacing
    threads = [threading.Thread(target=c.request, args=("GET", "https://93.184.216.34/"), kwargs={"opsec": "active"}) for _ in range(6)]
    for t in threads:
        t.start()
    for t in threads:
        t.join(timeout=5)
    assert transport.peak == 2


def test_the_kill_switch_stops_target_requests():
    http = fake().add("GET", "https://93.184.216.34/", text="ok")
    cancel = threading.Event()
    scoped = ScopedHttp(client(http), module="t_light", opsec="light", disclosure="target", cancel_event=cancel)
    assert scoped.get("https://93.184.216.34/").status == 200
    cancel.set()
    with pytest.raises(Cancelled):
        scoped.get("https://93.184.216.34/")
    assert len(target_calls(http)) == 1


def test_onion_services_need_a_tor_light_profile():
    http = fake()
    c = client(http)
    onion = "http://" + "a" * 56 + ".onion/"
    for opsec in ("light", "active", "passive"):
        with pytest.raises(PolicyError):
            c.request("GET", onion, opsec=opsec)
    assert not http.calls


def test_scoped_http_passes_its_binding_and_modules_cannot_override_it():
    http = fake()
    dns(http, "seed.example.com", a=["93.184.216.34"])
    http.add("GET", "https://seed.example.com/", text="ok")
    run = seed("https://seed.example.com/")
    scoped = ScopedHttp(client(http), module="t_light", opsec="light", disclosure="target", run=run)
    assert scoped.get("https://seed.example.com/").status == 200
    with pytest.raises(PolicyError):  # a module cannot widen its binding with its own run/scope
        scoped.get("https://other.example.net/", run=RunInfo(entity=Entity.make("domain", "other.example.net")))
    sent = [i for i in scoped.request_log if i.host == "seed.example.com"]
    assert sent[-1].egress_profile == "default" and sent[-1].resolved_ip == "93.184.216.34"
    assert scoped.hosts.get("dns.google", 0) >= 2  # the resolver saw the target name: disclosure ledger
    assert scoped.requests == 1  # DoH lookups never count against max_requests


def make_tls_cert(folder, name: str = "tls.example.test"):
    """A throwaway self-signed certificate for ``name`` (openssl CLI; the test is skipped without it)."""
    import shutil
    import subprocess

    if shutil.which("openssl") is None:
        pytest.skip("openssl is not installed")
    cert, key = folder / "cert.pem", folder / "key.pem"
    subprocess.run(
        ["openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes", "-keyout", str(key), "-out", str(cert), "-days", "2",
         "-subj", f"/CN={name}", "-addext", f"subjectAltName=DNS:{name}"],
        check=True, capture_output=True, timeout=60,
    )
    return cert, key


def test_a_pinned_https_request_keeps_sni_and_certificate_checks(tmp_path):
    import ssl

    cert, key = make_tls_cert(tmp_path)
    srv = ThreadingHTTPServer(("127.0.0.1", 0), _HostEcho)
    context = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)
    context.load_cert_chain(str(cert), str(key))
    srv.socket = context.wrap_socket(srv.socket, server_side=True)
    thread = threading.Thread(target=srv.serve_forever, kwargs={"poll_interval": 0.05}, daemon=True)
    thread.start()
    _HostEcho.seen = []
    try:
        port = srv.server_address[1]
        transport = RequestsTransport(trust_env=False, ca_bundle=str(cert))
        resp = transport.send("GET", f"https://tls.example.test:{port}/", headers={}, pin_ip="127.0.0.1", timeout=5, max_bytes=1000)
        assert resp.status == 200 and resp.pinned_ip == "127.0.0.1" and _HostEcho.seen == [f"tls.example.test:{port}"]
        from v3lum.core.http import NetworkError

        with pytest.raises(NetworkError) as err:  # the certificate is checked against the name, not the IP
            transport.send("GET", f"https://other.example.test:{port}/", headers={}, pin_ip="127.0.0.1", timeout=5, max_bytes=1000)
        assert "SSL" in str(err.value)
    finally:
        srv.shutdown()


# --------------------------------------------------------------------------------------
# review additions: credentials, identity, self-test contexts, the scope window, kill switch
# --------------------------------------------------------------------------------------


@pytest.mark.parametrize(
    "kw",
    [
        {"headers": {"Authorization": "Basic YWRtaW46YWRtaW4="}},  # a default-login attempt
        {"headers": {"Cookie": "session=borrowed"}},
        {"headers": {"X-Api-Key": "anything"}},
        {"params": {"apikey": "sk-test-0123456789abcdef"}},  # a configured V3LUM key in the URL
        {"data": {"q": "sk-test-0123456789abcdef"}},  # ... or in the body
    ],
)
def test_credentials_never_go_to_targets(kw, allowlist_dir):
    from v3lum.core.redact import register_secret

    register_secret("sk-test-0123456789abcdef", label="t_key")
    (allowlist_dir / "t_mod.json").write_text(  # POST approved: the body rule itself is under test
        json.dumps({"schema": "v3lum.method_allow/1", "module": "t_mod", "methods": {"POST": "read-only search form"}, "approved_by": "a", "decision_ref": "b"}),
        encoding="utf-8",
    )
    reload_method_allowlist(extra_dirs=[allowlist_dir])
    http = fake().add("*", "https://93.184.216.34/", text="ok")
    method = "POST" if "data" in kw else "GET"
    with pytest.raises(PolicyError) as err:
        client(http).request(method, "https://93.184.216.34/", opsec="active", module="t_mod", **kw)
    assert err.value.reason_code == "policy" and "no login attempts" in str(err.value)
    assert "sk-test-0123456789abcdef" not in str(err.value)
    assert not http.calls


def test_the_roe_header_is_the_only_token_a_target_receives():
    http = fake()
    dns(http, "www.acme.example", a=["93.184.216.34"])
    http.add("GET", "https://www.acme.example/", text="ok")
    run = RunInfo(entity=Entity.make("domain", "www.acme.example"), case_id="c")
    sc = make_scope(roe={"header": {"name": "X-Auth-Token", "value": "engagement-7"}})  # a credential-like name, agreed with the owner
    assert client(http).request("GET", "https://www.acme.example/", opsec="active", run=run, scope=sc).status == 200
    assert {k.lower(): v for k, v in target_calls(http)[-1]["headers"].items()}["x-auth-token"] == "engagement-7"


def test_a_ua_naming_v3lum_anywhere_never_reaches_a_target():
    http = fake().add("GET", "https://93.184.216.34/", text="ok")
    client(http).request("GET", "https://93.184.216.34/", opsec="light", user_agent=f"Mozilla/5.0 (compatible; V3LUM/{__version__})")
    assert target_calls(http)[-1]["headers"]["User-Agent"] == UA_LIGHT


def test_an_active_module_context_without_an_entity_needs_a_scope():
    """An ACTIVE ctx without an entity (a self-test, never a scan run) and without a scope never
    reaches a public target: only internal hosts, and only with internal_seed."""
    http = fake().add("GET", "https://93.184.216.34/", text="ok").add("GET", "http://127.0.0.1:8080/health", text="ok")
    c = client(http)
    scoped = ScopedHttp(c, module="t_self", opsec="active", disclosure="target", run=RunInfo(case_id="c", internal_seed=True))
    with pytest.raises(PolicyError) as err:
        scoped.get("https://93.184.216.34/")
    assert err.value.reason_code == "scope"
    assert scoped.get("http://127.0.0.1:8080/health").status == 200  # the loopback self-test works
    no_flag = ScopedHttp(c, module="t_self", opsec="active", disclosure="target", run=RunInfo(case_id="c"))
    for url in ("http://127.0.0.1:8080/health", "https://93.184.216.34/"):
        with pytest.raises(PolicyError) as err:
            no_flag.get(url)
        assert err.value.reason_code == "scope"
    assert [call["url"] for call in target_calls(http)] == ["http://127.0.0.1:8080/health"]


def test_the_scope_window_bounds_target_contact():
    http = fake()
    dns(http, "www.acme.example", a=["93.184.216.34"])
    http.add("GET", "https://www.acme.example/", text="ok")
    run = RunInfo(entity=Entity.make("domain", "www.acme.example"), case_id="c")
    closed = make_scope(window_start="2026-11-01T00:00:00Z", window_end="2026-11-26T11:00:00Z")  # the fake clock is 12:00
    with pytest.raises(Cancelled) as err:
        client(http).request("GET", "https://www.acme.example/", opsec="active", run=run, scope=closed)
    assert "window closed" in str(err.value)
    later = make_scope(window_start="2026-11-26T13:00:00Z", window_end="2026-11-27T00:00:00Z")
    with pytest.raises(PolicyError) as err:
        client(http).request("GET", "https://www.acme.example/", opsec="active", run=run, scope=later)
    assert err.value.reason_code == "scope" and "opens at" in str(err.value)
    assert not target_calls(http)
    c = client(http)
    assert c.request("GET", "https://www.acme.example/", opsec="active", run=run, scope=make_scope()).status == 200


class _StallingBody(BaseHTTPRequestHandler):
    """Sends its headers and a first chunk, then stalls (a slow-drip server) until released."""

    release = threading.Event()

    def log_message(self, *args):
        pass

    def do_GET(self):  # noqa: N802
        self.send_response(200)
        self.send_header("Content-Length", "100000")
        self.end_headers()
        self.wfile.write(b"x" * 10)
        self.wfile.flush()
        _StallingBody.release.wait(5)


def test_the_kill_switch_interrupts_a_body_read_on_a_silent_server():
    srv = ThreadingHTTPServer(("127.0.0.1", 0), _StallingBody)
    srv.daemon_threads = True
    thread = threading.Thread(target=srv.serve_forever, kwargs={"poll_interval": 0.05}, daemon=True)
    thread.start()
    cancel = threading.Event()
    _StallingBody.release.clear()
    try:
        transport = RequestsTransport(trust_env=False)
        threading.Timer(0.2, cancel.set).start()
        start = time.monotonic()
        with pytest.raises(Cancelled):
            transport.send("GET", f"http://127.0.0.1:{srv.server_address[1]}/", headers={}, timeout=10, max_bytes=10**6, cancel_event=cancel)
        assert time.monotonic() - start < 1.5  # not the 10 s socket timeout
    finally:
        _StallingBody.release.set()
        srv.shutdown()
        srv.server_close()
