from tests.fakes import FakeHttp, add_dns
from v3lum.core.dns import Resolver, reverse_name
from v3lum.core.http import ScopedHttp


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
        "https://dns.google/resolve?name=www.example.com&type=A",
        json={"Status": 0, "Answer": [{"type": 5, "data": "example.com."}, {"type": 1, "data": "93.184.215.14"}]},
    )
    assert resolver(http).query("www.example.com", "A").records == ["93.184.215.14"]


def test_fallback_to_cloudflare():
    http = FakeHttp()
    http.add("GET", "https://dns.google/resolve?name=x.com&type=A", status=503)
    http.add("GET", "https://cloudflare-dns.com/dns-query?name=x.com&type=A", json={"Status": 0, "Answer": [{"type": 1, "data": "5.6.7.8"}]})
    assert resolver(http).query("x.com", "A").records == ["5.6.7.8"]


def test_reverse_name():
    assert reverse_name("8.8.4.4") == "4.4.8.8.in-addr.arpa"
