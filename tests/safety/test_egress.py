"""AR20 (c) - egress fails closed (P376 cond 1-4, A13): with proxy_light/proxy_active configured but
down, no request leaves on the default (corporate) route; the profile sessions never trust the
environment (no environment proxies, NO_PROXY bypass or ~/.netrc credentials); target names are
resolved through the profile, never by a local getaddrinfo; third-party API traffic keeps the
default route.

Black box: engine scans with synthetic modules over the real HTTP client, egress profiles and socket
connector. The default route is a ``FakeHttp`` transport (it records anything that would have left
through the corporate egress); the proxies are a dead loopback port or a loopback SOCKS5 server.
"""

from __future__ import annotations

import json

import pytest

from tests.fakes import FakeHttp, make_runtime
from tests.safety.conftest import (
    IN_SCOPE_HOST,
    IN_SCOPE_IP,
    Ledger,
    active_module,
    active_options,
    coverage_of,
    dns,
    free_port,
    light_module,
    light_options,
    looked_up,
    passive_module,
    scan,
    target_calls,
)
from v3lum.core.http import RequestsTransport
from v3lum.core.models import Opsec

pytestmark = pytest.mark.safety

TARGET = "target.safety.example"
API = "https://api.safety-ti.example/v1/lookup?q=example"


def attempts(outcomes: dict[str, str], *, port: int = 443):
    """run(): contact the entity's host every way a target module can (HTTP GET/HEAD and a raw
    socket), recording each outcome, then GET once more without catching (the run's status)."""

    def run(self, ent, ctx):
        host = ent.value if ent.type.value != "url" else ent.value.split("/")[2]
        url = ent.value if ent.type.value == "url" else f"https://{host}/"
        for label, call in (
            ("http.get", lambda: ctx.http.get(url)),
            ("http.head", lambda: ctx.http.head(url)),
            ("net.connect", lambda: ctx.net.connect(host, port, timeout=1)),
        ):
            try:
                call()
            except Exception as exc:  # noqa: BLE001 - every refusal is recorded
                outcomes[label] = f"{type(exc).__name__}: {exc}"
            else:
                outcomes[label] = "sent"
        ctx.http.get(url)
        return self.result(ent)

    return run


def calling(url: str):
    def run(self, ent, ctx):
        ctx.http.get(url)
        return self.result(ent)

    return run


# --------------------------------------------------------------------------------------
# fail closed: a configured profile whose proxy is down
# --------------------------------------------------------------------------------------


def test_proxy_light_down_refuses_contact_and_nothing_leaves_on_the_default_route(ti_provider, http, socket_spy):
    dead = free_port()
    dns(http, TARGET, a=[IN_SCOPE_IP])  # a default-route answer exists: it must never be asked
    http.add("*", f"https://{TARGET}/", text="would answer")
    http.add("GET", API, json={"verdict": "unknown"})
    outcomes: dict[str, str] = {}
    light_module("t_safety_light_egress", attempts(outcomes))
    passive_module("t_safety_ti_egress", calling(API), ti_provider)
    rt = make_runtime(http, settings={"proxy_light": f"http://127.0.0.1:{dead}"})
    ledger = Ledger(rt)
    case = scan(rt, light_options({"t_safety_light_egress", "t_safety_ti_egress"}), f"domain:{TARGET}")

    for label in ("http.get", "http.head", "net.connect"):
        assert outcomes[label].startswith("PolicyError") and "proxy_light unreachable" in outcomes[label], (label, outcomes[label])
    row = coverage_of(case, "t_safety_light_egress", f"domain:{TARGET}")
    assert (row["status"], row["reason_code"]) == ("skipped", "policy") and "proxy_light unreachable" in row["reason"]
    # nothing reached the target on the corporate route, and the target name was never resolved there
    assert [c["url"] for c in target_calls(http)] == [API]
    assert TARGET not in looked_up(http)
    # the only socket the run opened was the reachability probe of the (dead) proxy itself
    assert set(socket_spy.connects) <= {("127.0.0.1", dead)} and socket_spy.connects
    assert TARGET not in socket_spy.lookups
    # third-party API traffic kept the default route (A13)
    assert coverage_of(case, "t_safety_ti_egress", f"domain:{TARGET}")["status"] in ("ok", "empty")
    assert {r.egress_profile for r in ledger.to("api.safety-ti.example")} == {"default"}
    assert ledger.to(TARGET) == []


def test_proxy_active_down_refuses_contact_and_nothing_leaves_on_the_default_route(registry, http, scope_file, socket_spy):
    dead = free_port()
    dns(http, IN_SCOPE_HOST, a=[IN_SCOPE_IP])
    http.add("*", f"https://{IN_SCOPE_HOST}/", text="would answer")
    outcomes: dict[str, str] = {}
    active_module("t_safety_active_egress", attempts(outcomes))
    rt = make_runtime(http, settings={"proxy_active": f"http://127.0.0.1:{dead}"})
    case = scan(rt, active_options(scope_file(), {"t_safety_active_egress"}), f"domain:{IN_SCOPE_HOST}")
    for label in ("http.get", "http.head", "net.connect"):
        assert outcomes[label].startswith("PolicyError") and "proxy_active unreachable" in outcomes[label], (label, outcomes[label])
    assert coverage_of(case, "t_safety_active_egress", f"domain:{IN_SCOPE_HOST}")["reason_code"] == "policy"
    assert http.calls == []  # not even a DoH lookup of the target on the corporate route
    assert set(socket_spy.connects) <= {("127.0.0.1", dead)} and IN_SCOPE_HOST not in socket_spy.lookups


def test_a_hostile_target_is_never_contacted_from_the_corporate_route_when_the_proxy_is_down(registry, http, socket_spy):
    """The hostile-host guard yields to a configured proxy_light; when that proxy is down the
    request is refused - it never falls back to the corporate egress (A13, P376 cond 3 and 6)."""
    dns(http, TARGET, a=[IN_SCOPE_IP])
    http.add("GET", f"https://{TARGET}/", text="phishing kit")
    from tests.safety.conftest import offline_module

    def tagging(self, ent, ctx):
        res = self.result(ent)
        res.finding("listed as phishing", "high", tags=["phishing"], criterion="synthetic feed listing (safety suite)")
        return res

    offline_module("t_safety_feed", tagging)
    light_module("t_safety_fetch", calling(f"https://{TARGET}/"))
    rt = make_runtime(http, settings={"proxy_light": f"http://127.0.0.1:{free_port()}"})
    case = scan(rt, light_options({"t_safety_feed", "t_safety_fetch"}), f"domain:{TARGET}")
    row = coverage_of(case, "t_safety_fetch", f"domain:{TARGET}")
    assert (row["status"], row["reason_code"]) == ("skipped", "policy") and "proxy_light unreachable" in row["reason"], row
    assert http.calls == []
    assert TARGET not in socket_spy.lookups


def test_the_hostile_host_guard_keeps_flagged_targets_off_the_corporate_route(registry, http):
    """No egress profile: a target its own passive results flag phishing is never contacted (BLOCKED
    'hostile_host', P376 cond 6); a benign target that redirects to an org-brand lookalike is cut at
    the redirect hop (the guard re-runs on every hop, AR02/A13)."""
    from tests.safety.conftest import offline_module

    phish, seed = "phish.example.net", "www.safety-seed.example"
    dns(http, phish, a=["93.184.217.70"])
    dns(http, seed, a=["93.184.217.71"])
    http.add("GET", f"https://{phish}/", text="phishing kit")
    http.add("GET", f"https://{seed}/out", redirect_to="https://contoso-portal.example.net/landing")

    def tagging(self, ent, ctx):
        res = self.result(ent)
        if ent.value == phish:
            res.finding("listed as phishing", "high", tags=["phishing"], criterion="synthetic feed listing (safety suite)")
        return res

    def fetch(self, ent, ctx):
        ctx.http.get(f"https://{ent.value}/" if ent.value == phish else f"https://{seed}/out")
        return self.result(ent)

    offline_module("t_safety_feed2", tagging)
    light_module("t_safety_guarded", fetch)
    rt = make_runtime(http, org_profile={"brands": [{"keyword": "contoso"}]})
    case = scan(rt, light_options({"t_safety_feed2", "t_safety_guarded"}), f"domain:{phish}", f"domain:{seed}")
    first = coverage_of(case, "t_safety_guarded", f"domain:{phish}")
    assert (first["status"], first["reason_code"]) == ("blocked", "hostile_host") and "non-corporate egress" in first["reason"]
    hop = coverage_of(case, "t_safety_guarded", f"domain:{seed}")
    assert (hop["status"], hop["reason_code"]) == ("blocked", "hostile_host"), hop
    assert "lookalike of the org brand" in hop["reason"]
    assert [c["url"] for c in target_calls(http)] == [f"https://{seed}/out"]  # the lookalike was never contacted
    assert "contoso-portal.example.net" not in looked_up(http)


def test_tor_is_never_an_active_route(registry, http, scope_file):
    """proxy_active on a Tor SOCKS port is refused (fail closed), never replaced by the default route."""
    dns(http, IN_SCOPE_HOST, a=[IN_SCOPE_IP])
    http.add("*", f"https://{IN_SCOPE_HOST}/", text="would answer")
    active_module("t_safety_tor_active", calling(f"https://{IN_SCOPE_HOST}/"))
    rt = make_runtime(http, settings={"proxy_active": "socks5h://127.0.0.1:9050"})
    case = scan(rt, active_options(scope_file(), {"t_safety_tor_active"}), f"domain:{IN_SCOPE_HOST}")
    row = coverage_of(case, "t_safety_tor_active", f"domain:{IN_SCOPE_HOST}")
    assert (row["status"], row["reason_code"]) == ("skipped", "policy") and "Tor" in row["reason"], row
    assert http.calls == []


@pytest.mark.parametrize("value", ["ftp://127.0.0.1:21", "socks5h://127.0.0.1", "http://", "not a url"])
def test_an_unusable_light_profile_refuses_instead_of_falling_back(registry, http, value):
    dns(http, TARGET, a=[IN_SCOPE_IP])
    http.add("*", f"https://{TARGET}/", text="would answer")
    light_module("t_safety_bad_profile", calling(f"https://{TARGET}/"))
    case = scan(make_runtime(http, settings={"proxy_light": value}), light_options({"t_safety_bad_profile"}), f"domain:{TARGET}")
    row = coverage_of(case, "t_safety_bad_profile", f"domain:{TARGET}")
    assert (row["status"], row["reason_code"]) == ("skipped", "policy"), row
    assert http.calls == []


# --------------------------------------------------------------------------------------
# profile sessions: trust_env False, names resolved through the profile
# --------------------------------------------------------------------------------------


def test_the_light_route_ignores_environment_proxies_no_proxy_and_netrc(registry, http, socks_proxy, socket_spy, tmp_path, monkeypatch):
    """A LIGHT scan through a SOCKS5h proxy_light while the environment carries a proxy for every
    scheme, NO_PROXY='*' and a netrc entry for the target: the request still goes through the
    profile's proxy, by name, without credentials; the target name is never resolved locally."""
    env_proxy = f"http://127.0.0.1:{free_port()}"  # dead: if the session read it, the request would fail
    for name in ("HTTP_PROXY", "HTTPS_PROXY", "ALL_PROXY", "http_proxy", "https_proxy", "all_proxy"):
        monkeypatch.setenv(name, env_proxy)
    monkeypatch.setenv("NO_PROXY", "*")
    monkeypatch.setenv("no_proxy", "*")
    netrc = tmp_path / "netrc"
    netrc.write_text(f"machine {TARGET} login analyst password n3trc-s3cret\n", encoding="utf-8")
    netrc.chmod(0o600)
    monkeypatch.setenv("NETRC", str(netrc))
    resolved: list[tuple[str, str]] = []
    seen: dict[str, object] = {}

    def fetch(self, ent, ctx):
        resp = ctx.http.get(f"http://{TARGET}/page")
        seen["status"], seen["body"] = resp.status, resp.content
        return self.result(ent)

    light_module("t_safety_socks", fetch)
    rt = make_runtime(http, settings={"proxy_light": socks_proxy.url})

    def through_profile(host: str, profile: str) -> list[str]:
        resolved.append((host, profile))
        return [IN_SCOPE_IP]

    rt.http.egress.resolver = through_profile  # the profile resolver (DoH through the proxy) stand-in
    ledger = Ledger(rt)
    case = scan(rt, light_options({"t_safety_socks"}), f"url:http://{TARGET}/page")

    assert coverage_of(case, "t_safety_socks", f"url:http://{TARGET}/page")["status"] in ("ok", "empty")
    assert seen == {"status": 200, "body": b"via-proxy"}
    assert socks_proxy.connects == [("name", TARGET, 80)]  # the proxy resolves the name (socks5h)
    assert resolved == [(TARGET, "light")]  # checked through the profile, never on the default route
    request = socks_proxy.payloads[0].decode("latin-1").lower()
    assert f"host: {TARGET}" in request
    assert "authorization" not in request and "n3trc-s3cret" not in request  # no ~/.netrc credentials
    assert TARGET not in socket_spy.lookups and set(socket_spy.lookups) <= {"127.0.0.1"}
    assert ("127.0.0.1", socks_proxy.port) in socket_spy.connects
    assert {port for host, port in socket_spy.connects} <= {socks_proxy.port}  # the environment proxy was never used
    assert http.calls == []  # nothing on the default route, not even a DoH lookup
    assert {r.egress_profile for r in ledger.to(TARGET)} == {"light"}
    name, session = rt.http.egress.session_for(Opsec.LIGHT)
    assert name == "light" and session.trust_env is False
    assert dict(session.merge_environment_settings(f"http://{TARGET}/", {}, None, None, None)["proxies"]) == {
        "http": socks_proxy.url, "https": socks_proxy.url,
    }


def test_light_raw_sockets_go_through_the_profile_proxy(registry, http, socks_proxy, socket_spy):
    """P376 cond 4: raw-socket work (banner grabs, TLS handshakes) gets its socket from the core
    connector applying the LIGHT profile: the connection is tunnelled through proxy_light, the
    target name is resolved through the profile and never by a local getaddrinfo, and nothing
    leaves on the default route."""
    seen: dict[str, object] = {}

    def grab(self, ent, ctx):
        sock = ctx.net.connect(TARGET, 80, timeout=1)
        try:
            sock.sendall(f"HEAD / HTTP/1.1\r\nHost: {TARGET}\r\n\r\n".encode())
            seen["reply"] = sock.recv(64)
        finally:
            sock.close()
        return self.result(ent)

    light_module("t_safety_socks_raw", grab)
    rt = make_runtime(http, settings={"proxy_light": socks_proxy.url})
    resolved: list[tuple[str, str]] = []

    def through_profile(host: str, profile: str) -> list[str]:
        resolved.append((host, profile))
        return [IN_SCOPE_IP]

    rt.http.egress.resolver = through_profile
    ledger = Ledger(rt)
    case = scan(rt, light_options({"t_safety_socks_raw"}), f"domain:{TARGET}")
    assert coverage_of(case, "t_safety_socks_raw", f"domain:{TARGET}")["status"] in ("ok", "empty")
    assert bytes(seen["reply"]).startswith(b"HTTP/1.1 200")  # the proxy's answer: the tunnel was used
    assert resolved == [(TARGET, "light")]
    assert [(addr, port) for _kind, addr, port in socks_proxy.connects] == [(IN_SCOPE_IP, 80)]  # the checked address, via the proxy
    assert TARGET not in socket_spy.lookups and {host for host, _port in socket_spy.connects} <= {"127.0.0.1"}
    assert {port for _host, port in socket_spy.connects} == {socks_proxy.port}
    assert http.calls == []
    assert [(r.method, r.egress_profile) for r in ledger.to(TARGET)] == [("CONNECT", "light")]


def test_active_contact_goes_through_proxy_active(registry, http, scope_file, socks_proxy, socket_spy):
    """ACTIVE HTTP probes take proxy_active (socks5h: the proxy gets the name), the scope is checked on
    the address resolved through the profile, and the default route carries nothing."""
    resolved: list[tuple[str, str]] = []
    seen: dict[str, object] = {}

    def fetch(self, ent, ctx):
        resp = ctx.http.get(f"http://{IN_SCOPE_HOST}/status")
        seen["status"], seen["body"] = resp.status, resp.content
        return self.result(ent)

    active_module("t_safety_active_socks", fetch)
    rt = make_runtime(http, settings={"proxy_active": socks_proxy.url})

    def through_profile(host: str, profile: str) -> list[str]:
        resolved.append((host, profile))
        return [IN_SCOPE_IP]

    rt.http.egress.resolver = through_profile
    ledger = Ledger(rt)
    case = scan(rt, active_options(scope_file(), {"t_safety_active_socks"}), f"domain:{IN_SCOPE_HOST}")
    assert coverage_of(case, "t_safety_active_socks", f"domain:{IN_SCOPE_HOST}")["status"] in ("ok", "empty")
    assert seen == {"status": 200, "body": b"via-proxy"}
    assert socks_proxy.connects == [("name", IN_SCOPE_HOST, 80)]
    assert resolved == [(IN_SCOPE_HOST, "active")]
    assert IN_SCOPE_HOST not in socket_spy.lookups and http.calls == []
    assert {r.egress_profile for r in ledger.to(IN_SCOPE_HOST)} == {"active"}


# --------------------------------------------------------------------------------------
# per-recipient tokens (P376 cond 10, A7 BR15): never fetched automatically
# --------------------------------------------------------------------------------------

TOKEN_URLS = [
    "https://www.acme.example/track?t=Zx8Kq2LmN4pR7sT9vW1y",  # opaque token (>= 16 chars) in the query
    "https://www.acme.example/u/Zx8Kq2LmN4pR7sT9vW1yAb/",  # opaque token in the path
    "https://www.acme.example/?e=ana.souza%40contoso.example",  # an org_profile e-mail, URL-encoded
    "https://www.acme.example/?e=YW5hLnNvdXphQGNvbnRvc28uZXhhbXBsZQ==",  # the same e-mail, base64
]
ORG = {"domains": ["contoso.example"], "emails": ["ana.souza@contoso.example"]}


@pytest.mark.parametrize("url", TOKEN_URLS)
def test_a_seed_url_with_a_recipient_token_is_never_fetched_automatically(registry, http, url):
    dns(http, IN_SCOPE_HOST, a=[IN_SCOPE_IP])
    http.add("GET", url, text="landing")
    light_module("t_safety_token_seed", calling(url), accepts=("url",))
    case = scan(make_runtime(http, org_profile=ORG), light_options({"t_safety_token_seed"}), f"url:{url}")
    row = coverage_of(case, "t_safety_token_seed", f"url:{url}")
    assert (row["status"], row["reason_code"]) == ("skipped", "policy") and "--confirm-url" in row["reason"], row
    assert target_calls(http) == []


def test_a_confirmed_token_url_is_fetched_and_a_token_redirect_hop_is_not(registry, http):
    url, hop = TOKEN_URLS[0], TOKEN_URLS[1]
    dns(http, IN_SCOPE_HOST, a=[IN_SCOPE_IP])
    http.add("GET", url, redirect_to=hop)
    http.add("GET", hop, text="landing")
    light_module("t_safety_token_ok", calling(url), accepts=("url",))
    opts = light_options({"t_safety_token_ok"}, confirmed_urls={url})
    case = scan(make_runtime(http, org_profile=ORG), opts, f"url:{url}")
    row = coverage_of(case, "t_safety_token_ok", f"url:{url}")
    assert (row["status"], row["reason_code"]) == ("skipped", "policy") and "--confirm-url" in row["reason"], row  # the hop
    assert [c["url"] for c in target_calls(http)] == [url]  # the confirmed URL only: the token hop never left


@pytest.mark.xfail(
    strict=True,
    reason="WP11 http.py: the per-recipient-token guard (GUARD-02, P376 cond 10 / A7) runs for the seed (decide) and for redirect "
    "hops only; a token URL a LIGHT/ACTIVE module builds itself (a crawled link) is sent on its first hop - see the WP28 report open_issues",
)
@pytest.mark.parametrize("opsec", ["light", "active"])
def test_a_module_never_fetches_a_recipient_token_url_it_found_itself(registry, http, scope_file, opsec):
    """A crawler on the seed finds a link with a per-recipient token (a phishing lure addressed to a
    member of the organisation): following it automatically would tell the sender that the lure was
    opened. The request must be refused like the seed and the redirect hop are."""
    dns(http, IN_SCOPE_HOST, a=[IN_SCOPE_IP])
    for url in TOKEN_URLS:
        http.add("GET", url, text="landing")
    outcomes: dict[str, str] = {}

    def crawl(self, ent, ctx):
        for url in TOKEN_URLS:
            try:
                ctx.http.get(url)
            except Exception as exc:  # noqa: BLE001 - any refusal counts: the request is what matters
                outcomes[url] = f"refused: {type(exc).__name__}"
            else:
                outcomes[url] = "sent"
        return self.result(ent)

    make = active_module if opsec == "active" else light_module
    make("t_safety_token_crawl", crawl)
    opts = active_options(scope_file(), {"t_safety_token_crawl"}) if opsec == "active" else light_options({"t_safety_token_crawl"})
    scan(make_runtime(http, org_profile=ORG), opts, f"domain:{IN_SCOPE_HOST}")
    assert target_calls(http) == [], f"token URLs were fetched: {[c['url'] for c in target_calls(http)]}"
    assert all(o.startswith("refused") for o in outcomes.values()), outcomes


# --------------------------------------------------------------------------------------
# identity: target contact never names V3LUM or the organisation (A7, P326 cond 5)
# --------------------------------------------------------------------------------------

CONTACT = "soc@contoso.example"
IDENTITY_SETTINGS = {"contact_email": CONTACT, "user_agent": f"V3LUM/1.0 (+mailto:{CONTACT})"}
ROE = {"user_agent": "pentest-PENTEST-2026-042", "header": {"name": "X-Engagement-Token", "value": "c0ffee42"}}


def sending_headers(headers: dict[str, str]):
    def run(self, ent, ctx):
        ctx.http.get(f"https://{IN_SCOPE_HOST}/page", headers=headers)
        return self.result(ent)

    return run


@pytest.mark.parametrize("opsec", ["light", "active", "active+roe"])
def test_target_contact_never_carries_the_v3lum_or_contact_identity(registry, http, scope_file, opsec):
    dns(http, IN_SCOPE_HOST, a=[IN_SCOPE_IP])
    http.add("GET", f"https://{IN_SCOPE_HOST}/page", text="page")
    asked = {"User-Agent": f"V3LUM/1.0 (+mailto:{CONTACT})", "From": CONTACT, "X-Contact": f"mailto:{CONTACT}", "Accept": "text/html"}
    make = light_module if opsec == "light" else active_module
    make("t_safety_identity", sending_headers(asked))
    if opsec == "light":
        opts = light_options({"t_safety_identity"})
    else:
        opts = active_options(scope_file(roe=ROE) if opsec == "active+roe" else scope_file(), {"t_safety_identity"})
    scan(make_runtime(http, settings=IDENTITY_SETTINGS), opts, f"domain:{IN_SCOPE_HOST}")
    (sent,) = [c["headers"] for c in target_calls(http)]
    text = json.dumps(sent).lower()
    assert "v3lum" not in text and CONTACT not in text and "from" not in {k.lower() for k in sent}, sent
    assert sent.get("Accept") == "text/html"  # ordinary headers pass untouched
    if opsec == "active+roe":
        assert sent["User-Agent"] == ROE["user_agent"] and sent["X-Engagement-Token"] == "c0ffee42"
    else:
        assert sent["User-Agent"].startswith("Mozilla/5.0")  # the egress-profile browser UA (ua_light)


@pytest.mark.xfail(
    strict=True,
    reason="WP11 http.py: HttpClient._headers strips only the From header and values naming the contact mailbox/URL; other "
    "headers a LIGHT/ACTIVE module sets may still name V3LUM or the organisation's own domains (A7, P326 cond 5) - see the WP28 "
    "report open_issues",
)
@pytest.mark.parametrize("header", [("X-Scanner", "V3LUM"), ("Referer", "https://intranet.contoso.example/soc/case-42")])
def test_target_contact_never_names_the_tool_or_the_organisation_in_any_header(registry, http, header):
    dns(http, IN_SCOPE_HOST, a=[IN_SCOPE_IP])
    http.add("GET", f"https://{IN_SCOPE_HOST}/page", text="page")
    light_module("t_safety_identity2", sending_headers(dict([header])))
    rt = make_runtime(http, settings=IDENTITY_SETTINGS, org_profile={"domains": ["contoso.example"]})
    scan(rt, light_options({"t_safety_identity2"}), f"domain:{IN_SCOPE_HOST}")
    for call in target_calls(http):
        text = json.dumps(call["headers"]).lower()
        assert "v3lum" not in text and "contoso.example" not in text, call["headers"]


def test_the_direct_route_connects_to_the_checked_address_without_local_dns(registry, loopback, socket_spy):
    """No proxy configured: the target name is resolved through the profile resolver and the
    connection is pinned to the checked address - the OS resolver never sees the target name."""
    srv = loopback()
    resolved: list[tuple[str, str]] = []

    def fetch(self, ent, ctx):
        ctx.http.get(ent.value)
        return self.result(ent)

    light_module("t_safety_pinned", fetch)
    from v3lum.core.clock import SYSTEM_CLOCK

    rt = make_runtime(RequestsTransport(trust_env=False), clock=SYSTEM_CLOCK)

    def through_profile(host: str, profile: str) -> list[str]:
        resolved.append((host, profile))
        return ["127.0.0.1"]

    rt.http.egress.resolver = through_profile
    url = f"http://wiki.internal:{srv.port}/status"  # an internal analyst-typed seed may resolve to loopback
    case = scan(rt, light_options({"t_safety_pinned"}), f"url:{url}")
    assert coverage_of(case, "t_safety_pinned", f"url:{url}")["status"] in ("ok", "empty")
    assert resolved == [("wiki.internal", "default")]
    assert [r["headers"].get("Host") for r in srv.requests] == [f"wiki.internal:{srv.port}"]
    assert "wiki.internal" not in socket_spy.lookups
    assert ("127.0.0.1", srv.port) in socket_spy.connects


def test_passive_third_party_calls_never_move_to_a_contact_profile(ti_provider, socks_proxy):
    """Egress profiles carry target contact only: third-party APIs keep the default route (A13; P334
    budgets stay global), even with proxy_light and proxy_active configured."""
    default = FakeHttp()
    default.add("GET", API, json={"verdict": "unknown"})
    passive_module("t_safety_ti_only", calling(API), ti_provider)
    rt = make_runtime(default, settings={"proxy_light": socks_proxy.url, "proxy_active": socks_proxy.url})
    ledger = Ledger(rt)
    case = scan(rt, light_options({"t_safety_ti_only"}), "domain:example.org")
    assert coverage_of(case, "t_safety_ti_only", "domain:example.org")["status"] in ("ok", "empty")
    assert [c["url"] for c in default.calls] == [API]
    assert socks_proxy.connects == []
    assert {r.egress_profile for r in ledger.to("api.safety-ti.example")} == {"default"}
