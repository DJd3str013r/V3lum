"""typosquat_dnstwister (P012 cond 11): opt-in dnstwister.report adapter.

Fixtures in tests/fixtures/typosquat_dnstwister/: the real /api/ index and /api/fuzz/ answer for
example.com recorded 2026-11-26 (15 of 298 entries kept, per-entry *_url fields dropped), a research
sample cut mid-entry (truncated body) and the real 'error code: 1101' answer to an invalid hex path.
"""

from __future__ import annotations

from tests.fakes import FakeHttp, add_dns, add_nxdomain_everything, module_fixture, run_module
from v3lum.core.context import ScanOptions
from v3lum.core.models import Status
from v3lum.modules.domain_dns.typosquat_dnstwister import TyposquatDnstwister, dnstwister_hex, parse_fuzz

FUZZ = "https://dnstwister.report/api/fuzz/{}"
HEX = "6578616d706c652e636f6d"  # example.com, as /api/to_hex returns it
EXPLICIT = ScanOptions(include={"typosquat_dnstwister"})


def fx(name):
    return module_fixture(TyposquatDnstwister, name)


def raw(name):
    from tests.fakes import FIXTURES

    return (FIXTURES / "typosquat_dnstwister" / name).read_text(encoding="utf-8")


def test_contract_metadata():
    cls = TyposquatDnstwister
    assert cls.default_enabled is False and cls.trust_tier == "community" and cls.terms == "unknown"
    assert cls.hosts == ("dnstwister.report", "rdap.registro.br") and cls.provider == "dnstwister"
    assert cls.run_on == "seeds" and cls.cache_ttl == 604800 and cls.min_interval == 2.0


def test_hex_encoding_matches_to_hex():
    assert dnstwister_hex("example.com") == HEX
    assert dnstwister_hex("itaú.com.br") == b"xn--ita-boa.com.br".hex()
    assert dnstwister_hex("") is None and dnstwister_hex("a" * 70 + ".com") is None


def test_excluded_at_amber_and_above_before_any_request():
    for level in ("amber", "amber+strict", "red"):
        http = FakeHttp()
        res = run_module(TyposquatDnstwister, "domain:example.com", http, tlp=level, options=EXPLICIT)
        assert res.status is Status.SKIPPED and res.reason_code == "tlp" and http.calls == []


def test_runs_once_per_explicit_brand_at_green_and_checks_candidates_through_doh():
    http = FakeHttp().add("GET", FUZZ.format(HEX), json=fx("fuzz_ok.json"))
    for prov in ("cloudflare", "google"):
        add_dns(http, "login-example.com", "NS", ["ns1.example.net."], provider=prov)
        add_dns(http, "login-example.com", "A", ["203.0.113.30"], provider=prov)
        add_dns(http, "login-example.com", "MX", ["10 mx.example.net."], provider=prov)
        add_dns(http, "login-example.com", "AAAA", [], provider=prov)
    add_nxdomain_everything(http)
    res = run_module(TyposquatDnstwister, "domain:example.com", http, tlp="green", options=EXPLICIT)
    assert res.status is Status.OK, res.error
    cov = res.attributes["typosquat_coverage"]
    assert cov["mode"].startswith("forward via dnstwister") and cov["candidates_generated"] == 14
    finding = [f for f in res.findings if f.title == "Registered lookalike domain"][0]
    assert finding.data["domain"] == "login-example.com" and finding.severity.label == "medium"
    assert {p.entity.value for p in res.pivots} == {"login-example.com"} and all(not p.expand for p in res.pivots)
    dnstwister = [c["url"] for c in http.calls if "dnstwister.report" in c["url"]]
    assert dnstwister == [FUZZ.format(HEX)]  # one fuzz call; never /api/parked, /whois, /ip or /mx
    http.assert_hosts_within(TyposquatDnstwister)


def test_not_applicable_without_an_org_domain_or_explicit_selection():
    http = FakeHttp()
    res = run_module(TyposquatDnstwister, "domain:example.com", http, tlp="green")
    assert res.status is Status.SKIPPED and res.reason_code == "not_applicable" and http.calls == []
    sub = run_module(TyposquatDnstwister, "domain:www.example.com", FakeHttp(), tlp="green", options=EXPLICIT)
    assert sub.status is Status.SKIPPED


def test_parse_fuzz_maps_fuzzers_and_drops_bad_entries():
    parsed = parse_fuzz(fx("fuzz_ok.json"))
    names = {c["domain"]: c for c in parsed["candidates"]}
    assert "example.com" not in names  # the 'Original' entry
    assert names["example.online"]["fuzzer"] == "tld-swap" and names["login-example.com"]["fuzzer"] == "dictionary"
    assert names["xn--xample-9ua.com"]["domain_unicode"].endswith("xample.com")
    bad = {"fuzzy_domains": [{"domain": "evil.com", "domain_as_hexadecimal": HEX}, {"domain": "-bad-.com"}, "junk", {"domain": 5}]}
    assert parse_fuzz(bad)["candidates"] == []
    assert parse_fuzz("not json")["error"] and parse_fuzz({"x": 1})["error"]


def test_truncated_body_keeps_complete_entries_and_is_partial():
    parsed = parse_fuzz(raw("fuzz_truncated.json"))
    assert parsed["partial"] is True and parsed["domain"] == "example.com" and parsed["candidates"]
    http = FakeHttp().add("GET", FUZZ.format(HEX), text=raw("fuzz_truncated.json"), headers={"content-type": "application/json"})
    add_nxdomain_everything(http)
    res = run_module(TyposquatDnstwister, "domain:example.com", http, tlp="green", options=EXPLICIT)
    assert res.partial is True and res.attributes["typosquat_coverage"]["dnstwister_partial"] is True


def test_worker_error_page_429_and_challenge_are_could_not_verify():
    err = FakeHttp().add("GET", FUZZ.format(HEX), status=500, text=raw("error_bad_hex.txt"), headers={"content-type": "text/plain"})
    res = run_module(TyposquatDnstwister, "domain:example.com", err, tlp="green", options=EXPLICIT)
    assert res.status is Status.ERROR and "Cloudflare Workers error page" in res.error  # marker dnstwister_worker_error
    limited = FakeHttp().add("GET", FUZZ.format(HEX), status=429, text="slow down")
    assert run_module(TyposquatDnstwister, "domain:example.com", limited, tlp="green", options=EXPLICIT).status is Status.RATE_LIMITED
    page = "<html><head><title>Just a moment...</title></head><body>cf-chl-widget</body></html>"
    challenge = FakeHttp().add("GET", FUZZ.format(HEX), status=403, text=page)
    assert run_module(TyposquatDnstwister, "domain:example.com", challenge, tlp="green", options=EXPLICIT).status is Status.BLOCKED


def test_unexpected_200_answers_are_errors_never_empty():
    html = FakeHttp().add("GET", FUZZ.format(HEX), text="<html><body>maintenance</body></html>")
    assert run_module(TyposquatDnstwister, "domain:example.com", html, tlp="green", options=EXPLICIT).status is Status.ERROR
    shape = FakeHttp().add("GET", FUZZ.format(HEX), json=fx("api_root.json"))  # a JSON object without fuzzy_domains
    res = run_module(TyposquatDnstwister, "domain:example.com", shape, tlp="green", options=EXPLICIT)
    assert res.status is Status.ERROR and "could not verify" in res.error
