"""Core DoH resolver: the v1 cases, with the P029 URL change (Google always carries ECS 0.0.0.0/0)."""

from urllib.parse import parse_qsl, urlsplit

import pytest

from tests.fakes import FakeHttp, add_dns
from v3lum.core.dns import Resolver, reverse_name
from v3lum.core.http import NetworkError, ScopedHttp

GOOGLE = "https://dns.google/resolve"
CLOUDFLARE = "https://cloudflare-dns.com/dns-query"


def resolver(http):
    return Resolver(ScopedHttp(http))


def test_txt_join_and_quotes():
    http = FakeHttp()
    add_dns(http, "example.com", "TXT", ['"v=spf1 include:_spf.google.com " "~all"', '"google-site-verification=abc"'])
    ans = resolver(http).query("example.com", "TXT")
    assert ans.ok
    assert ans.records == ["v=spf1 include:_spf.google.com ~all", "google-site-verification=abc"]


def test_mx_and_null_mx():
    http = FakeHttp()
    add_dns(http, "a.com", "MX", ["10 MX1.A.COM.", "20 mx2.a.com."])
    add_dns(http, "b.com", "MX", ["0 ."])
    assert resolver(http).query("a.com", "MX").records == ["10 mx1.a.com", "20 mx2.a.com"]
    assert resolver(http).query("b.com", "MX").records == ["0 ."]


def test_nxdomain_and_ad_flag():
    http = FakeHttp()
    add_dns(http, "nope.example", "A", [], status=3)
    add_dns(http, "signed.example", "A", ["1.2.3.4"], ad=True)
    r = resolver(http)
    assert r.query("nope.example", "A").nxdomain
    ans = r.query("signed.example", "A")
    assert ans.authenticated and ans.records == ["1.2.3.4"]


def test_filters_other_rr_types():
    http = FakeHttp()
    http.add(
        "GET",
        f"{GOOGLE}?name=www.example.com&type=A&edns_client_subnet=0.0.0.0/0",
        json={"Status": 0, "Answer": [{"type": 5, "data": "example.com."}, {"type": 1, "data": "93.184.215.14"}]},
    )
    ans = resolver(http).query("www.example.com", "A")
    assert ans.records == ["93.184.215.14"]
    assert ans.cnames == ["example.com"]  # the CNAME hop is kept apart from the A records


def test_google_url_carries_ecs_in_order():
    http = FakeHttp()
    add_dns(http, "x.com", "A", ["5.6.7.8"])
    resolver(http).query("x.com", "A")
    url = http.urls()[0]
    assert url == f"{GOOGLE}?name=x.com&type=A&edns_client_subnet=0.0.0.0%2F0"
    assert [k for k, _ in parse_qsl(urlsplit(url).query)] == ["name", "type", "edns_client_subnet"]


@pytest.mark.parametrize(
    "failure",
    [
        {"status": 503},
        {"status": 500},
        {"status": 429},
        {"error": NetworkError("ConnectionError contacting dns.google: reset")},
    ],
    ids=["503", "500", "429", "transport"],
)
def test_fallback_to_cloudflare(failure):
    http = FakeHttp()
    http.add("GET", f"{GOOGLE}?name=x.com&type=A&edns_client_subnet=0.0.0.0/0", **failure)
    http.add("GET", f"{CLOUDFLARE}?name=x.com&type=A", json={"Status": 0, "Answer": [{"type": 1, "data": "5.6.7.8"}]})
    ans = resolver(http).query("x.com", "A")
    assert ans.records == ["5.6.7.8"]
    assert ans.resolver == "cloudflare"


def test_no_fallback_on_dns_answers():
    """An NXDOMAIN (or SERVFAIL) answer is final: the next resolver is never asked."""
    http = FakeHttp()
    add_dns(http, "gone.example", "A", [], status=3)
    add_dns(http, "broken.example", "A", [], status=2)
    r = resolver(http)
    assert r.query("gone.example", "A").nxdomain
    assert r.query("broken.example", "A").could_not_verify
    assert all(u.startswith(GOOGLE) for u in http.urls())


def test_reverse_name():
    assert reverse_name("8.8.4.4") == "4.4.8.8.in-addr.arpa"
