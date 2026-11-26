"""AR20 (a) - scope fuzz (A7, AR02, P327 cond 4): an ACTIVE scan with a scope file sends zero requests
to out-of-scope pivots, CDN ranges, private/metadata addresses and redirect targets - including
names that resolve inside and redirect hops - and LIGHT never runs on pivots.

This file is the merge gate of LIGHT/ACTIVE modules: ``tests/test_registry_contract.py`` refuses
them until it exists, and it must pass (A7, A16).

Black box: synthetic modules run through ``Engine.investigate`` / ``Engine.run_module`` over the
real policy gate, HTTP client (resolution through the egress profile, scope and SSRF checks on every
hop, pinning) and a ``FakeHttp`` transport with fake DoH answers; FakeHttp records every request
that would have left.
"""

from __future__ import annotations

import ipaddress
import random
import string

import pytest

from tests.safety.conftest import (
    CDN_IP,
    IN_SCOPE_CIDR,
    IN_SCOPE_HOST,
    IN_SCOPE_IP,
    METADATA_IP,
    OUT_OF_SCOPE_IP,
    REF,
    active_module,
    active_options,
    calls_to,
    coverage_of,
    dns,
    entity,
    host_of,
    light_module,
    light_options,
    looked_up,
    pivot_source,
    scan,
    target_calls,
)
from tests.fakes import make_runtime
from v3lum.core.engine import Engine
from v3lum.core.entities import EntityType as T
from v3lum.core.http import Blocked, NetworkError, PolicyError
from v3lum.core.models import Status

pytestmark = pytest.mark.safety

SEED = f"domain:{IN_SCOPE_HOST}"


def url_of(ent) -> str:
    return ent.value if ent.type is T.URL else f"https://{ent.value}/"


def probing(seen: list[str]):
    """run(): GET the entity (its URL, or https://<host>/) - an ACTIVE/LIGHT probe."""

    def run(self, ent, ctx):
        seen.append(ent.key)
        ctx.http.get(url_of(ent))
        return self.result(ent)

    return run


def trying(urls: list[str], outcomes: dict[str, str]):
    """run(): a misbehaving module on an in-scope entity that tries every URL of ``urls`` (redirects
    followed), recording 'sent' or the refusal for each."""

    def run(self, ent, ctx):
        for url in urls:
            try:
                ctx.http.get(url)
            except (PolicyError, Blocked, NetworkError) as exc:
                outcomes[url] = f"refused: {type(exc).__name__}: {exc}"
            else:
                outcomes[url] = "sent"
        return self.result(ent)

    return run


def assert_never_contacted(http, hosts) -> None:
    contacted = {host_of(c["url"]) for c in http.calls}
    leaked = sorted(h for h in hosts if h.lower().strip("[]") in contacted)
    assert not leaked, f"requests reached {leaked}"


def assert_pinned_in_scope(http) -> None:
    """Every request that left went to a checked, in-scope address (the address it was pinned to)."""
    net = ipaddress.ip_network(IN_SCOPE_CIDR)
    for call in target_calls(http):
        assert host_of(call["url"]).endswith("acme.example"), call["url"]
        assert ipaddress.ip_address(call["pin_ip"]) in net, call


# --------------------------------------------------------------------------------------
# engine: pivots never inherit scope
# --------------------------------------------------------------------------------------


def test_active_scan_sends_zero_requests_to_out_of_scope_cdn_and_private_pivots(registry, http, scope_file, cdn_noise):
    pivots = [
        ("domain", "partner.example.org", "related"),  # out of scope
        ("domain", "acme.example.net", "lookalike"),  # out of scope (lookalike of the target)
        ("domain", "mail.acme.example", "subdomain"),  # excluded by the scope
        ("domain", "cdn.acme.example", "subdomain"),  # in scope by name, resolves into a CDN range
        ("domain", "db.acme.example", "subdomain"),  # in scope by name, resolves to a private address
        ("domain", "meta.acme.example", "subdomain"),  # in scope by name, resolves to cloud metadata
        ("domain", "mixed.acme.example", "subdomain"),  # one public and one private address
        ("domain", "v6.acme.example", "subdomain"),  # IPv6 unique-local only
        ("ipv4", OUT_OF_SCOPE_IP, "resolves_to"),  # out of scope
        ("ipv4", CDN_IP, "resolves_to"),  # CDN (noise: never expanded)
        ("ipv4", "10.0.0.7", "resolves_to"),  # private
        ("ipv4", METADATA_IP, "resolves_to"),  # cloud metadata
        ("url", "https://evil.example.net/kit", "links_to"),  # out of scope
        ("url", f"https://{IN_SCOPE_HOST}/go-out", "links_to"),  # in scope, redirects out of scope
        ("url", "https://portal.acme.example/go-in", "links_to"),  # in scope, redirects to a private name
        ("url", f"https://{IN_SCOPE_HOST}/go-meta", "links_to"),  # in scope, redirects to the metadata endpoint
    ]
    dns(http, IN_SCOPE_HOST, a=[IN_SCOPE_IP])
    dns(http, "portal.acme.example", a=["93.184.216.40"])
    dns(http, "cdn.acme.example", a=[CDN_IP])
    dns(http, "db.acme.example", a=["10.0.0.7"])
    dns(http, "meta.acme.example", a=[METADATA_IP])
    dns(http, "mixed.acme.example", a=["93.184.216.41", "10.0.0.8"])
    dns(http, "v6.acme.example", aaaa=["fc00::1"])
    dns(http, "intranet.acme.example", a=["10.1.2.3"])
    http.add("GET", f"https://{IN_SCOPE_HOST}/", text="home")
    http.add("GET", f"https://{IN_SCOPE_HOST}/go-out", redirect_to="https://evil.example.net/landing")
    http.add("GET", "https://portal.acme.example/go-in", redirect_to="https://intranet.acme.example/admin")
    http.add("GET", f"https://{IN_SCOPE_HOST}/go-meta", redirect_to=f"https://{METADATA_IP}/latest/meta-data/")
    seen: list[str] = []
    pivot_source("t_safety_pivots", pivots)
    active_module("t_safety_probe", probing(seen))
    rt = make_runtime(http)
    case = scan(rt, active_options(scope_file(), {"t_safety_pivots", "t_safety_probe"}), SEED)

    forbidden = [
        "partner.example.org", "acme.example.net", "mail.acme.example", "cdn.acme.example", "db.acme.example",
        "meta.acme.example", "mixed.acme.example", "v6.acme.example", "evil.example.net", "intranet.acme.example",
        OUT_OF_SCOPE_IP, CDN_IP, "10.0.0.7", "10.0.0.8", "10.1.2.3", METADATA_IP, "fc00::1",
    ]
    assert_never_contacted(http, forbidden)
    assert {host_of(c["url"]) for c in target_calls(http)} == {IN_SCOPE_HOST, "portal.acme.example"}
    assert_pinned_in_scope(http)
    assert http.unexpected == []
    # out-of-scope names were refused by the scope itself: never even sent to a resolver
    assert not looked_up(http) & {"partner.example.org", "acme.example.net", "evil.example.net", "mail.acme.example"}

    # the gate refused the out-of-scope pivots: the module never ran on them (pivots never inherit scope)
    for ent in ("domain:partner.example.org", "domain:acme.example.net", "domain:mail.acme.example", f"ipv4:{OUT_OF_SCOPE_IP}", "url:https://evil.example.net/kit"):
        row = coverage_of(case, "t_safety_probe", ent)
        assert (row.get("status"), row.get("reason_code")) == ("skipped", "scope"), (ent, row)
        assert entity(ent).key not in seen
    # in scope by name, refused after resolution / on the redirect hop: SKIPPED 'scope', nothing sent
    for ent, needle in (
        ("domain:cdn.acme.example", "shared_infra_hosts"),
        ("domain:db.acme.example", "10.0.0.7"),
        ("domain:meta.acme.example", METADATA_IP),
        ("domain:mixed.acme.example", "10.0.0.8"),
        ("domain:v6.acme.example", "fc00::1"),
        (f"url:https://{IN_SCOPE_HOST}/go-out", "outside the scope"),
        ("url:https://portal.acme.example/go-in", "10.1.2.3"),
        (f"url:https://{IN_SCOPE_HOST}/go-meta", "outside the scope"),
    ):
        row = coverage_of(case, "t_safety_probe", ent)
        assert (row.get("status"), row.get("reason_code")) == ("skipped", "scope"), (ent, row)
        assert needle in row.get("reason", ""), (ent, row)
    # CDN, private and metadata addresses as pivots are noise: never scheduled at all
    for ent in (f"ipv4:{CDN_IP}", "ipv4:10.0.0.7", f"ipv4:{METADATA_IP}"):
        assert entity(ent).key not in seen
    assert coverage_of(case, "t_safety_probe", SEED)["status"] in ("ok", "empty")


def test_a_misbehaving_active_module_cannot_leave_the_scope(registry, http, scope_file, cdn_noise):
    """Request-level fuzz: an ACTIVE module running on an in-scope seed points ctx.http at lookalike
    names, encoded and numeric address forms, private/metadata/CDN addresses, in-scope names that
    resolve inside, and in-scope URLs that redirect out. Every one is refused; none is contacted."""
    rng = random.Random(20261126)  # deterministic fuzz
    alphabet = string.ascii_lowercase + string.digits
    out_hosts = [
        "acme.example.evil.net", "evilacme.example", "acme-example.net", "acme.example.co", "notacme.example",
        "www.acme.example.attacker.org", "acme.example.attacker.org", "mail.acme.example", "xn--acme-9qa.example",
        OUT_OF_SCOPE_IP, CDN_IP, "10.0.0.7", "172.16.3.4", "192.168.1.1", "127.0.0.1", "100.64.1.1", METADATA_IP,
        "[::1]", "[fc00::1]", "[fe80::1]", "[::ffff:10.0.0.7]", "[::ffff:a9fe:a9fe]", "[64:ff9b::a00:7]",
        "2130706433", "0x7f.1", "0177.0.0.1", "017700000001", "localhost", "intranet", "metadata.google.internal",
        "printer.local", "wiki.corp",
    ]
    for _ in range(25):  # random labels under parents that are not the target
        label = "".join(rng.choice(alphabet) for _ in range(rng.randint(1, 12)))
        out_hosts.append(f"{label}.{rng.choice(['example.net', 'example.org', 'acme.example.net', 'acmeexample.org', 'example.com'])}")
    urls = [f"https://{h}/" for h in out_hosts]
    urls += [
        f"https://{IN_SCOPE_HOST}@evil.example.net/",  # userinfo trick: the real host is evil.example.net
        f"https://evil.example.net/{IN_SCOPE_HOST}/",
        f"https://evil.example.net/?u=https://{IN_SCOPE_HOST}/",
        f"https://evil.example.net#@{IN_SCOPE_HOST}/",
        f"https://{IN_SCOPE_HOST}.evil.example.net/",
        f"http://[::ffff:{OUT_OF_SCOPE_IP}]/",
        f"https://{IN_SCOPE_HOST}:8443@{METADATA_IP}/",
    ]
    inside = {}  # in-scope names whose answers point inside or at shared infrastructure
    targets = [*["10.0.0.7", "172.16.3.4", "192.168.1.1", "127.0.0.1", "100.64.1.1", METADATA_IP], CDN_IP, "104.17.0.9"]
    for i in range(12):
        name = f"h{i}-{''.join(rng.choice(alphabet) for _ in range(6))}.acme.example"
        inside[name] = targets[i % len(targets)]
        dns(http, name, a=[inside[name]])
        urls.append(f"https://{name}/")
    redirects = {
        "/r-out": "https://evil.example.net/",
        "/r-meta": f"https://{METADATA_IP}/latest/meta-data/",
        "/r-private-name": "https://intranet.acme.example/",
        "/r-cdn-name": "https://cdn.acme.example/",
        "/r-excluded": "https://mail.acme.example/",
        "/r-downgrade": f"http://{IN_SCOPE_HOST}/",
        "/r-suffix": f"https://{IN_SCOPE_HOST}.evil.example.net/",
        "/r-scheme-relative": "//evil.example.net/x",
        "/r-ip": f"https://{OUT_OF_SCOPE_IP}/",
        "/r-mapped": "https://[::ffff:a9fe:a9fe]/",
        "/r-file": "file:///etc/passwd",
    }
    for path, location in redirects.items():
        http.add("GET", f"https://{IN_SCOPE_HOST}{path}", redirect_to=location)
        urls.append(f"https://{IN_SCOPE_HOST}{path}")
    dns(http, IN_SCOPE_HOST, a=[IN_SCOPE_IP])
    dns(http, "intranet.acme.example", a=["10.1.2.3"])
    dns(http, "cdn.acme.example", a=[CDN_IP])
    outcomes: dict[str, str] = {}
    active_module("t_safety_fuzz", trying(urls, outcomes), max_requests=500)
    rt = make_runtime(http)
    case = scan(rt, active_options(scope_file(), {"t_safety_fuzz"}), SEED)

    assert coverage_of(case, "t_safety_fuzz", SEED)["status"] in ("ok", "empty")
    sent = sorted(u for u, outcome in outcomes.items() if outcome == "sent")
    assert sent == [], f"out-of-scope requests were sent: {sent}"
    assert set(outcomes) == set(urls)
    never = [host_of(u) or u for u in urls if not u.startswith(f"https://{IN_SCOPE_HOST}/")]
    never += [host_of(v) for v in redirects.values() if host_of(v)] + list(inside.values()) + ["10.1.2.3"]
    assert_never_contacted(http, [h for h in never if h and h != IN_SCOPE_HOST])
    # only the first hops of the redirecting in-scope URLs left, each pinned to the checked address
    assert sorted(c["url"] for c in target_calls(http)) == sorted(f"https://{IN_SCOPE_HOST}{p}" for p in redirects)
    assert_pinned_in_scope(http)
    assert http.unexpected == []


def test_a_misbehaving_active_module_cannot_open_sockets_outside_the_scope(registry, http, scope_file, cdn_noise, socket_spy):
    """Raw sockets (ctx.net.connect: port probes, banner grabs, TLS handshakes) obey the same scope
    as HTTP: out-of-scope and excluded names, CDN/private/loopback/metadata addresses (literal or
    behind an in-scope name) and ambiguous numeric hosts are refused before any socket exists, and
    the target names are never resolved by the local resolver."""
    dns(http, IN_SCOPE_HOST, a=[IN_SCOPE_IP])
    dns(http, "db.acme.example", a=["10.0.0.7"])
    dns(http, "cdn.acme.example", a=[CDN_IP])
    dns(http, "meta.acme.example", a=[METADATA_IP])
    dns(http, "mail.acme.example", a=["93.184.216.25"])  # in the target CIDR, but excluded by name
    dns(http, "evil.example.net", a=["93.184.217.9"])
    targets = [
        OUT_OF_SCOPE_IP, CDN_IP, "10.0.0.7", METADATA_IP, "127.0.0.1", "::1", "fc00::1", "::ffff:10.0.0.7", "100.64.1.1",
        "db.acme.example", "cdn.acme.example", "meta.acme.example", "mail.acme.example", "evil.example.net",
        "localhost", "intranet", "0x7f.1", "2130706433", "017700000001",
    ]
    outcomes: dict[str, str] = {}

    def run(self, ent, ctx):
        for target in targets:
            try:
                ctx.net.connect(target, 443, timeout=0.2).close()
            except PolicyError as exc:
                outcomes[target] = f"refused ({exc.reason_code})"
            except Exception as exc:  # noqa: BLE001 - recorded: anything but a refusal fails below
                outcomes[target] = f"{type(exc).__name__}: {exc}"
            else:
                outcomes[target] = "connected"
        return self.result(ent)

    active_module("t_safety_socket_fuzz", run)
    case = scan(make_runtime(http), active_options(scope_file(), {"t_safety_socket_fuzz"}), SEED)
    assert coverage_of(case, "t_safety_socket_fuzz", SEED)["status"] in ("ok", "empty")
    assert set(outcomes) == set(targets)
    assert {t: o for t, o in outcomes.items() if not o.startswith("refused")} == {}
    assert socket_spy.connects == [] and socket_spy.lookups == []  # no socket, no local getaddrinfo
    assert http.unexpected == []


def test_url_prefix_targets_bind_every_hop_to_the_prefix(registry, http, scope_file):
    """A scope that lists only a URL prefix on a shared host: requests (and redirect hops) outside the
    prefix, on another port or through an encoded/dot-segment path never leave."""
    portal = "portal.partner.example"
    prefix = f"https://{portal}/acme/"
    dns(http, portal, a=["93.184.218.5"])
    http.add("GET", f"{prefix}status", text="in scope")
    http.add("GET", f"{prefix}go", redirect_to=f"https://{portal}/other/")
    tries = [
        f"{prefix}status", f"https://{portal}/other/", f"{prefix}../other/", f"https://{portal}/acme%2f..%2fother/", f"https://{portal}/acmex",
        f"https://{portal}:8443/acme/status", f"http://{portal}/acme/status", f"{prefix}go",
    ]
    outcomes: dict[str, str] = {}
    active_module("t_safety_prefix", trying(tries, outcomes), accepts=(T.URL,))
    scope = scope_file(targets={"url_prefixes": [prefix]})
    case = scan(make_runtime(http), active_options(scope, {"t_safety_prefix"}), f"url:{prefix}status")
    assert coverage_of(case, "t_safety_prefix", f"url:{prefix}status")["status"] in ("ok", "empty")
    assert sorted(u for u, o in outcomes.items() if o == "sent") == [f"{prefix}status"]
    assert sorted(c["url"] for c in target_calls(http)) == [f"{prefix}go", f"{prefix}status"]  # the hop to /other/ never left
    assert http.unexpected == []


@pytest.mark.parametrize(
    ("changes", "options", "code"),
    [
        ({}, {"scope": None}, "scope"),  # no --scope FILE
        ({}, {"authorization_ref": ""}, "authorization"),  # no --authorized REF
        ({}, {"authorization_ref": "confirmed"}, "authorization"),  # a placeholder, not a reference
        ({"authorization_ref": "PENTEST-2026-999"}, {}, "scope"),  # the scope is bound to another REF
        ({"window_start": "2026-11-01T00:00:00Z", "window_end": "2026-11-26T11:00:00Z"}, {}, "scope"),  # window closed
        ({"window_start": "2026-11-26T13:00:00Z", "window_end": "2026-11-27T00:00:00Z"}, {}, "scope"),  # not open yet
        ({"limits": {"max_rps": 50}}, {}, "scope"),  # above the A7 ceilings: the file is refused
        ({"owner": None}, {}, "scope"),  # malformed: a scope with problems allows nothing
        ({"targets": {"domains": ["other.example.org"]}}, {}, "scope"),  # the seed is not a target
    ],
)
def test_active_never_runs_without_a_valid_scope_bound_to_the_authorization(registry, http, scope_file, changes, options, code):
    dns(http, IN_SCOPE_HOST, a=[IN_SCOPE_IP])
    http.add("GET", f"https://{IN_SCOPE_HOST}/", text="home")
    seen: list[str] = []
    active_module("t_safety_unscoped", probing(seen))
    opts = active_options(scope_file(**changes), {"t_safety_unscoped"})
    for name, value in options.items():
        setattr(opts, name, value)
    case = scan(make_runtime(http), opts, SEED)
    row = coverage_of(case, "t_safety_unscoped", SEED)
    assert (row["status"], row["reason_code"]) == ("skipped", code), row
    assert seen == [] and target_calls(http) == []


def test_every_execution_path_keeps_the_scope(registry, http, scope_file):
    """`v3lum run` (decide_single + run_module) refuses an out-of-scope target before running, and a
    direct run_module call without a decision is still bound to the scope at the HTTP layer."""
    dns(http, "partner.example.org", a=[OUT_OF_SCOPE_IP])
    seen: list[str] = []
    cls = active_module("t_safety_single", probing(seen))
    eng = Engine(make_runtime(http), active_options(scope_file(), {"t_safety_single"}))
    target = entity("domain:partner.example.org")
    decision = eng.decide_single(cls, target)
    assert (decision.allowed, decision.reason_code) == (False, "scope")
    refused = eng.run_module(cls, target, decision=decision)
    assert (refused.status, refused.reason_code) == (Status.SKIPPED, "scope") and seen == []
    direct = eng.run_module(cls, target)  # no decision: the request-level binding still refuses
    assert (direct.status, direct.reason_code) == (Status.SKIPPED, "scope")
    assert "outside the scope" in direct.error and seen == [target.key]
    assert target_calls(http) == [] and calls_to(http, "partner.example.org") == []


@pytest.mark.xfail(
    strict=True,
    reason="WP04 datasets.py (+ WP08 context.py): an unregistered ad-hoc ctx.data.fetch(name, url) is sent on the default route "
    "outside the module's scope binding (A7) - see the WP28 report open_issues",
)
def test_an_active_module_cannot_reach_out_of_scope_through_ad_hoc_data(registry, http, scope_file):
    """ctx.data is a network path too: an ACTIVE module must not reach an out-of-scope host by
    'downloading a dataset' from it."""
    dns(http, IN_SCOPE_HOST, a=[IN_SCOPE_IP])
    http.add("GET", "https://evil.example.net/wordlist.txt", text="admin\n")
    tried: list[str] = []

    def run(self, ent, ctx):
        try:
            ctx.data.fetch_text("t_safety_adhoc_words", "https://evil.example.net/wordlist.txt")
        except Exception as exc:  # noqa: BLE001 - any refusal counts; the request is what matters
            tried.append(type(exc).__name__)
        return self.result(ent)

    active_module("t_safety_data_escape", run)
    scan(make_runtime(http), active_options(scope_file(), {"t_safety_data_escape"}), SEED)
    assert calls_to(http, "evil.example.net") == [], "an out-of-scope host was contacted through ctx.data"


def test_cdn_fronted_in_scope_names_need_shared_infra_hosts(registry, http, scope_file, cdn_noise):
    """A7: an in-scope name on CDN addresses is contacted only when the scope lists it under
    shared_infra_hosts (HTTP probes); the listing never extends to other names."""
    dns(http, "cdn.acme.example", a=[CDN_IP])
    dns(http, "img.acme.example", a=["104.16.9.9"])
    http.add("GET", "https://cdn.acme.example/", text="fronted")
    seen: list[str] = []
    active_module("t_safety_cdn", probing(seen))
    refused = scan(make_runtime(http), active_options(scope_file(), {"t_safety_cdn"}), "domain:cdn.acme.example")
    assert coverage_of(refused, "t_safety_cdn", "domain:cdn.acme.example")["reason_code"] == "scope"
    assert target_calls(http) == []
    listed = scope_file(shared_infra_hosts=["cdn.acme.example"])
    case = scan(make_runtime(http), active_options(listed, {"t_safety_cdn"}), "domain:cdn.acme.example", "domain:img.acme.example")
    assert coverage_of(case, "t_safety_cdn", "domain:cdn.acme.example")["status"] in ("ok", "empty")
    assert coverage_of(case, "t_safety_cdn", "domain:img.acme.example")["reason_code"] == "scope"
    assert [host_of(c["url"]) for c in target_calls(http)] == ["cdn.acme.example"]


# --------------------------------------------------------------------------------------
# LIGHT: analyst-typed seeds only, never pivots
# --------------------------------------------------------------------------------------


def test_light_never_runs_on_pivots(registry, http):
    pivots = [
        ("domain", "partner.example.org", "related"),
        ("domain", "shop.www.acme.example", "subdomain"),  # even a subdomain of the seed is a pivot
        ("url", f"https://{IN_SCOPE_HOST}/login", "links_to"),  # even the seed's own host
        ("ipv4", IN_SCOPE_IP, "resolves_to"),
    ]
    dns(http, IN_SCOPE_HOST, a=[IN_SCOPE_IP])
    http.add("GET", f"https://{IN_SCOPE_HOST}/", text="home")
    seen: list[str] = []
    pivot_source("t_safety_pivots_l", pivots)
    light_module("t_safety_light", probing(seen))
    case = scan(make_runtime(http), light_options({"t_safety_pivots_l", "t_safety_light"}), SEED)
    assert seen == [entity(SEED).key]  # the analyst-typed seed only
    for etype, value, _relation in pivots:
        row = coverage_of(case, "t_safety_light", f"{etype}:{value}")
        assert (row.get("status"), row.get("reason_code")) == ("skipped", "scope"), (value, row)
        assert "analyst-typed seeds" in row.get("reason", "")
    assert [c["url"] for c in target_calls(http)] == [f"https://{IN_SCOPE_HOST}/"]
    assert calls_to(http, "partner.example.org") == [] and calls_to(http, "shop.www.acme.example") == []


def test_light_never_runs_on_unconfirmed_or_text_extracted_seeds(registry, http):
    dns(http, IN_SCOPE_HOST, a=[IN_SCOPE_IP])
    seen: list[str] = []
    light_module("t_safety_light_u", probing(seen))
    seed = entity(SEED)
    case = scan(make_runtime(http), light_options({"t_safety_light_u"}, unconfirmed_seeds={seed.key}), seed)
    assert coverage_of(case, "t_safety_light_u", seed)["reason_code"] == "scope"
    assert seen == [] and target_calls(http) == []


def test_a_light_module_cannot_contact_other_hosts_from_the_seed_run(registry, http):
    """Request-level seed binding: on the seed run, a LIGHT module's requests start only at the seed
    (or a subdomain of it); pivot hosts, other names and internal addresses are refused before any
    request, and a redirect hop that resolves inside is refused after resolution (WP11: LIGHT redirect
    hops are re-checked by the SSRF guard and the hostile-host guard on every hop)."""
    dns(http, IN_SCOPE_HOST, a=[IN_SCOPE_IP])
    dns(http, "img.www.acme.example", a=["93.184.216.50"])
    dns(http, "inner.www.acme.example", a=["192.168.1.1"])
    dns(http, "hop.example.net", a=["10.0.0.9"])
    http.add("GET", f"https://{IN_SCOPE_HOST}/", text="home")
    http.add("GET", "https://img.www.acme.example/", text="img")
    http.add("GET", f"https://{IN_SCOPE_HOST}/away", redirect_to="https://hop.example.net/")
    urls = [
        f"https://{IN_SCOPE_HOST}/", "https://img.www.acme.example/", "https://partner.example.org/", "https://acme.example/",
        f"https://{OUT_OF_SCOPE_IP}/", "https://10.0.0.7/", f"https://{METADATA_IP}/", "https://inner.www.acme.example/",
        f"https://{IN_SCOPE_HOST}/away",
    ]
    outcomes: dict[str, str] = {}
    light_module("t_safety_light_fuzz", trying(urls, outcomes))
    scan(make_runtime(http), light_options({"t_safety_light_fuzz"}), SEED)
    assert sorted(u for u, o in outcomes.items() if o == "sent") == ["https://img.www.acme.example/", f"https://{IN_SCOPE_HOST}/"]
    assert "10.0.0.9" in outcomes[f"https://{IN_SCOPE_HOST}/away"]
    assert_never_contacted(
        http, ["partner.example.org", "acme.example", OUT_OF_SCOPE_IP, "10.0.0.7", METADATA_IP, "inner.www.acme.example", "192.168.1.1", "hop.example.net"]
    )
    # names that are not the seed are refused by the binding itself: never sent to a resolver
    assert not looked_up(http) & {"partner.example.org", "acme.example"}
    assert http.unexpected == []


def test_the_light_active_merge_gate_is_open(registry):
    """This file is the gate of tests/test_registry_contract.py (A7, A16): with it in place a
    LIGHT/ACTIVE module is no longer refused for a missing safety suite."""
    from pathlib import Path

    from tests import test_registry_contract as contract

    assert Path(contract.SAFETY_GATE).resolve() == Path(__file__).resolve()
    for make in (light_module, active_module):
        cls = make(f"t_safety_gate_{make.__name__}", probing([]))
        assert not [p for p in contract.module_problems(cls) if "safety suite" in p]


def test_contract_additions_names_resolve():
    """Every tests.safety.conftest helper named in docs/contract_additions/WP28.md exists."""
    import re
    from pathlib import Path

    from tests.safety import conftest

    doc = (Path(__file__).resolve().parents[2] / "docs" / "contract_additions" / "WP28.md").read_text(encoding="utf-8")
    row = next(line for line in doc.splitlines() if line.startswith("| `tests.safety.conftest` helpers"))
    names = re.findall(r"`([A-Za-z_][A-Za-z0-9_]*)`", row.split("|")[4])
    assert len(names) >= 8
    for name in names:
        assert hasattr(conftest, name), name


def test_scope_fixture_is_valid():
    """Sanity check of the suite's own engagement data (a broken scope would make every refusal above
    trivially true)."""
    from tests.fakes import FakeClock
    from tests.safety.conftest import BASE_SCOPE
    from v3lum.core.scope import Scope

    scope = Scope.from_dict(BASE_SCOPE)
    assert scope.validate(REF, FakeClock().now()) == []
    assert scope.matches_host(IN_SCOPE_HOST) and scope.matches_ip(IN_SCOPE_IP) and not scope.matches_host("mail.acme.example")
