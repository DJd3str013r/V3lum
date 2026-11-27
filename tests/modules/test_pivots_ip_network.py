"""pivots_ip_network (P057): IP & ASN tools, manual links only. V3LUM never fetches these URLs.

Verification records: tests/fixtures/pivots_ip_network/verified_templates.json; golden URLs: render_golden.json."""

from __future__ import annotations

import base64
from urllib.parse import parse_qs, unquote, urlsplit

import pytest

from tests.fakes import FakeHttp, module_fixture, run_module
from v3lum.core import links, noise
from v3lum.core.entities import Entity, EntityType
from v3lum.core.models import Status
from v3lum.modules.ip_network.pivots_ip_network import PivotsIpNetwork
from v3lum.modules.utility import pivot_gated_links as pg

GOLDEN = module_fixture("pivots_ip_network", "render_golden.json")
FOREIGN = "foreign provider: queries are logged abroad - never paste internal host names"


def urls(res):
    return [u for _l, u in res.links]


def fofa_query(url):
    return base64.b64decode(unquote(parse_qs(urlsplit(url).query)["qbase64"][0])).decode()


# ------------------------------------------------------------------ cond 9: no link for non-public values
V4_REFUSED = [
    ("0.1.2.3", "this network"), ("10.0.0.1", "private"), ("100.64.0.1", "CGNAT"), ("100.127.255.254", "CGNAT"),
    ("127.0.0.1", "loopback"), ("169.254.169.254", "link-local"), ("172.16.5.4", "private"), ("192.0.0.8", "IETF"),
    ("192.0.2.10", "documentation"), ("192.168.1.1", "private"), ("198.18.0.1", "benchmarking"),
    ("198.51.100.7", "documentation"), ("203.0.113.9", "documentation"), ("224.0.0.251", "multicast"),
    ("240.0.0.1", "reserved"), ("255.255.255.255", "reserved"),
]
V6_REFUSED = [
    ("::1", "loopback"), ("::", "unspecified"), ("::ffff:10.0.0.1", "IPv4-mapped"), ("64:ff9b::a00:1", "NAT64"),
    ("100::1", "discard"), ("2001::1", "IETF"), ("2001:db8::1", "documentation"), ("2002:a00:1::1", "6to4"),
    ("3fff::1", "documentation"), ("fd12:3456::1", "ULA"), ("fe80::1", "link-local"), ("fec0::1", "site-local"),
    ("ff02::1", "multicast"),
]


@pytest.mark.parametrize(("value", "needle"), V4_REFUSED)
def test_every_non_public_ipv4_range_is_refused(value, needle):
    assert needle in pg.public_value_problem(Entity.make("ipv4", value))
    res = run_module(PivotsIpNetwork, f"ipv4:{value}", FakeHttp(), tlp="clear")
    assert res.status is Status.SKIPPED and res.reason_code == "not_applicable" and res.links == []


@pytest.mark.parametrize(("value", "needle"), V6_REFUSED)
def test_every_non_public_ipv6_range_is_refused(value, needle):
    assert needle in pg.public_value_problem(Entity(EntityType.IPV6, value))


@pytest.mark.parametrize("value", ["10.0.0.0/8", "100.64.0.0/16", "192.168.0.0/24", "0.0.0.0/0", "8.0.0.0/4",
                                   "fd00::/8", "2001:db8::/48", "::/0"])
def test_cidrs_overlapping_a_refused_range_get_no_prefix_link(value):
    assert pg.public_value_problem(Entity.make("cidr", value)).startswith(("network overlapping", "IPv6 network outside"))
    res = run_module(PivotsIpNetwork, f"cidr:{value}", tlp="clear")
    assert res.links == [] and res.reason_code == "not_applicable"


@pytest.mark.parametrize(("value", "needle"), [("AS0", "reserved"), ("AS23456", "AS_TRANS"), ("AS64500", "documentation"),
                                               ("AS64512", "private"), ("AS65535", "reserved"), ("AS65540", "documentation"),
                                               ("AS100000", "reserved"), ("AS4200000001", "private"), ("AS4294967295", "reserved")])
def test_private_reserved_and_documentation_asns_are_refused(value, needle):
    assert needle in pg.public_value_problem(Entity(EntityType.ASN, value))


@pytest.mark.parametrize("value", ["intranet", "fileserver.local", "build.internal", "pc.corp", "nas.lan", "x.home.arpa",
                                   "a.test", "b.example", "c.invalid", "1.0.0.10.in-addr.arpa", "router.home"])
def test_single_label_and_internal_names_are_refused(value):
    assert pg.public_value_problem(Entity(EntityType.DOMAIN, value))


@pytest.mark.parametrize(("etype", "value"), [("ipv4", "8.8.4.4"), ("ipv6", "2606:4700:4700::1111"), ("cidr", "1.1.1.0/24"),
                                               ("asn", "AS13335"), ("domain", "example.com"), ("url", "https://example.org/x")])
def test_public_values_pass(etype, value):
    assert pg.public_value_problem(Entity.make(etype, value)) == ""


def test_the_engine_never_attaches_pack_links_to_private_noise_entities():
    """Core pack links (bgp.he.net, IPinfo...) are attached by the engine only to non-noise entities: private,
    loopback, link-local, ULA, reserved and documentation addresses are noise. CGNAT and `v3lum links` are the
    documented gap (docs/backlog/p2-G14-1.md)."""
    for value in ("10.0.0.1", "127.0.0.1", "169.254.1.1", "192.0.2.1", "240.0.0.1", "224.0.0.1"):
        assert noise.is_noise(Entity.make("ipv4", value))
    for value in ("fd00::1", "fe80::1", "::1", "2001:db8::1"):
        assert noise.is_noise(Entity.make("ipv6", value))
    data = pg.pack_data("ip_network")
    assert data["x_public_only"] is True and all(i.get("x_public_only") is True for i in data["links"])


# ------------------------------------------------------------------ cond 10-11: FOFA {b64q} and Criminal IP
def test_fofa_and_criminal_ip_at_green_with_the_foreign_badge():
    res = run_module(PivotsIpNetwork, "ipv4:9.9.9.9", FakeHttp(), tlp="green")
    assert res.status is Status.OK and res.requests == 0
    assert urls(res) == ["https://search.criminalip.io/asset/report/9.9.9.9", "https://en.fofa.info/result?qbase64=aXA9IjkuOS45Ljki"]
    assert all(FOREIGN in label for label, _u in res.links)
    assert fofa_query(urls(res)[1]) == 'ip="9.9.9.9"'


@pytest.mark.parametrize("tlp", ["amber", "amber+strict"])
def test_foreign_providers_are_hidden_at_amber_and_above(tlp):
    res = run_module(PivotsIpNetwork, "ipv4:9.9.9.9", tlp=tlp)
    assert res.status is Status.SKIPPED and res.reason_code == "tlp" and res.links == []
    assert {h["id"] for h in res.raw["hidden"]} == {"criminalip", "fofa_ip"}


def test_red_emits_nothing():
    res = run_module(PivotsIpNetwork, "cidr:8.8.8.0/24", tlp="red")
    assert res.status is Status.SKIPPED and res.reason_code == "tlp" and res.links == []


def test_b64q_matches_the_live_fofa_urls_and_refuses_breakouts():
    assert pg.b64q('ip="{q}"', "8.8.8.8") == "aXA9IjguOC44Ljgi"
    assert pg.b64q('icon_hash="{q}"', "708578229") == "aWNvbl9oYXNoPSI3MDg1NzgyMjki"
    assert pg.b64q('ip="{q}"', "2001:4860:4860::8888").endswith("%3D%3D")  # padding percent-encoded (live URL)
    for bad in ('8.8.8.8" || ip="1.1.1.1', "8.8.8.8\\", "8.8.8.8\n", ""):
        with pytest.raises(ValueError):
            pg.b64q('ip="{q}"', bad)
    with pytest.raises(ValueError):
        pg.b64q('title="{q}"', "x")  # only the vetted expressions


def test_favicon_hash_renders_only_the_icon_hash_search():
    res = run_module(PivotsIpNetwork, "favicon_hash:-1361878421", tlp="clear")
    assert len(res.links) == 1 and fofa_query(urls(res)[0]) == 'icon_hash="-1361878421"'
    gl = pg.module_links("ip_network")["fofa_icon_hash"]
    assert pg.render(gl, Entity.make("ipv4", "9.9.9.9")) is None
    assert "fofa_cert" not in pg.module_links("ip_network")  # cert= needs a login (excluded)


def test_hostile_values_never_break_out_of_the_fofa_term():
    gl = pg.module_links("ip_network")["fofa_ip"]
    assert pg.render(gl, Entity(EntityType.IPV4, '1.2.3.4" || port="22')) is None


# ------------------------------------------------------------------ bgp.he.net prefix ({cidrp})
def test_prefix_page_keeps_the_literal_slash_and_normalises_the_network():
    res = run_module(PivotsIpNetwork, "cidr:8.8.8.7/24", tlp="amber")  # no TLP ceiling: renderers show it as text
    assert res.status is Status.OK and urls(res) == ["https://bgp.he.net/net/8.8.8.0/24"]
    assert pg.cidrp("2001:4860::/32") == "2001%3A4860%3A%3A/32"


# ------------------------------------------------------------------ core pack links (cond 6, 8)
def test_core_links_for_an_ip_and_an_asn_in_curated_order():
    ip = [r for r in links.pivot_links_for(Entity.make("ipv4", "9.9.9.9")) if r.ref.startswith("ip_network:")]
    assert [r.ref for r in ip] == ["ip_network:bgphe_ip", "ip_network:ipinfo_ip", "ip_network:scamalytics", "ip_network:myipms"]
    myip = ip[-1]
    assert myip.antibot and links.BADGE_UNKNOWN_OPERATOR in myip.badge
    asn = {r.ref: r.url for r in links.pivot_links_for(Entity.make("asn", "15169")) if r.ref.startswith("ip_network:")}
    assert asn == {"ip_network:bgphe_as": "https://bgp.he.net/AS15169", "ip_network:ipinfo_asn": "https://ipinfo.io/AS15169",
                   "ip_network:cidr_report_as": "https://www.cidr-report.org/cgi-bin/as-report?as=AS15169&view=2.0"}
    exonerator = links.render("tor_relays:exonerator", Entity.make("ipv4", "9.9.9.9"))
    assert exonerator.url == "https://metrics.torproject.org/exonerator.html?ip=9.9.9.9&lang=en"


def test_golden_urls():
    for g in GOLDEN:
        entity = Entity.make(g["type"], g["value"])
        pack, ident = g["ref"].split(":")
        rendered = links.render(g["ref"], entity) if g["renderer"] == "core" else pg.render(pg.module_links(pack)[ident], entity)
        assert rendered is not None and rendered.url == g["url"], g
