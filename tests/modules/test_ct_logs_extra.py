"""ct_logs_extra (P001 cond 1): crt.name and MerkleMap, unknown-tier operators, opt-in.

Fixtures in tests/fixtures/ct_logs_extra/ (batch p1-G01-1 prep, 2026-11-26): the live crt.name answer for
example.com trimmed to its first 30 lines plus an IDN line (text/plain, one name per line), a synthetic
NDJSON variant, crt.name's live 400 'invalid apex' answer for a subdomain, MerkleMap's research 401 and a
synthetic MerkleMap page (UNVERIFIED shape: no keyed sample exists).
"""

from __future__ import annotations

from tests.fakes import FakeHttp, add_nxdomain_everything, assert_no_secret, module_fixture, run_module
from v3lum.core.models import Status
from v3lum.modules.domain_dns.ct_logs import HostnameSink, UnexpectedAnswer
from v3lum.modules.domain_dns.ct_logs_extra import CtLogsExtra, parse_crtname, parse_merklemap

CRTNAME = "https://crt.name/v1/search?apex=example.com"
MM = "https://api.merklemap.com/v1/search?query=*.example.com&page={page}"
NO_DNS = {"ct_logs_check_liveness": False}
KEY = "merklemap-test-key-0123456789"


def fx(name):
    return module_fixture(CtLogsExtra, name)


def only(*sources):
    return {"allowed_sources": frozenset(sources)}


def subdomain_pivots(res):
    return {p.entity.value: p for p in res.pivots if p.relation == "subdomain"}


# ------------------------------------------------------------------ metadata (P001 cond 1-3)
def test_contract_metadata_keeps_unknown_operators_out_of_the_default_set():
    cls = CtLogsExtra
    assert cls.default_enabled is False
    assert cls.terms == "unknown" and cls.trust_tier == "unknown"
    assert cls.terms_sources == {"crtname.search": "unknown", "merklemap.search": "key-terms"}
    assert str(cls.max_tlp.value_str) == "green"  # excluded at TLP:AMBER and above (A8)
    assert cls.optional_keys == ("crtname", "merklemap")
    assert cls.hosts == ("crt.name", "api.merklemap.com") and cls.max_requests <= 10


# ------------------------------------------------------------------ parsing
def test_crtname_plain_text_and_idn():
    sink = HostnameSink("example.com")
    text = fx("crtname_ok.txt")
    assert parse_crtname(text, sink) == len([ln for ln in text.splitlines() if ln.strip()])
    assert "dummy-host.example.com" in sink.names and "xn--caf-dma.example.com" in sink.names
    assert "xn--80ajirwbh.xn--h1aanv1d.life.example.com" in sink.names


def test_crtname_ndjson_framing_is_tolerated():
    sink = HostnameSink("example.com")
    parse_crtname(fx("crtname_ndjson.txt"), sink)
    assert set(sink.names) == {"example.com", "www.example.com", "api.example.com"}
    assert sink.wildcard_labels() == ["*.dev.example.com"]
    assert sink.rejected["not_hostname"] >= 2


def test_crtname_error_text_and_html_are_unexpected():
    for body in ("invalid apex: not an apex (eTLD+1 is example.com)\n", "<html><body>oops</body></html>"):
        try:
            parse_crtname(body, HostnameSink("example.com"))
        except UnexpectedAnswer:
            continue
        raise AssertionError(body)


def test_merklemap_unverified_shape():
    sink = HostnameSink("example.com")
    records, count = parse_merklemap(fx("merklemap_ok.json"), sink)
    assert (records, count) == (3, 3)
    assert set(sink.names) >= {"www.example.com", "api.example.com"} and sink.wildcard_labels() == ["*.example.com"]
    try:
        parse_merklemap({"error": "invalid api key"}, HostnameSink("example.com"))
    except UnexpectedAnswer:
        pass
    else:
        raise AssertionError("an error object must not read as 'no names'")


# ------------------------------------------------------------------ module runs
def test_both_sources_with_a_merklemap_key():
    http = FakeHttp()
    http.add("GET", CRTNAME, text=fx("crtname_ok.txt"), headers={"content-type": "text/plain; charset=utf-8"})
    http.add("GET", MM.format(page=0), json=fx("merklemap_ok.json"), match_headers={"authorization": f"Bearer {KEY}"})
    res = run_module(CtLogsExtra, "domain:example.com", http, keys={"merklemap": KEY}, settings=NO_DNS)
    assert res.status is Status.OK and not res.partial
    subs = subdomain_pivots(res)
    assert "api.example.com" in subs and "dummy-host.example.com" in subs
    assert subs["www.example.com"].note == "seen in CT (merklemap.search)"
    assert res.attributes["wildcard_cert"] == ["*.example.com"]
    assert {s: v["status"] for s, v in res.source_statuses.items()} == {"crtname.search": "ok", "merklemap.search": "ok"}
    assert_no_secret(KEY, res.to_dict(), res.raw)
    http.assert_hosts_within(CtLogsExtra)


def test_merklemap_without_key_needs_key_while_crtname_answers():
    http = FakeHttp().add("GET", CRTNAME, text=fx("crtname_ok.txt"), headers={"content-type": "text/plain"})
    res = run_module(CtLogsExtra, "domain:example.com", http, settings=NO_DNS)
    assert res.status is Status.OK
    assert res.source_statuses["merklemap.search"]["status"] == "needs_key"
    assert not any("merklemap" in c["url"] for c in http.calls)


def test_merklemap_alone_without_key_is_needs_key():
    res = run_module(CtLogsExtra, "domain:example.com", FakeHttp(), settings=NO_DNS, **only("merklemap.search"))
    assert res.status is Status.NEEDS_KEY


def test_merklemap_401_with_a_key_is_needs_key():
    resp = fx("merklemap_needs_key.http.json")["response"]
    http = FakeHttp().add("GET", MM.format(page=0), status=resp["status"], text=resp["body"])
    res = run_module(CtLogsExtra, "domain:example.com", http, keys={"merklemap": KEY}, settings=NO_DNS, **only("merklemap.search"))
    assert res.status is Status.NEEDS_KEY


def test_crtname_400_invalid_apex_is_could_not_verify():
    resp = fx("crtname_not_apex.http.json")["response"]
    http = FakeHttp().add("GET", CRTNAME, status=resp["status"], text=resp["body"], headers=resp["headers"])
    res = run_module(CtLogsExtra, "domain:example.com", http, settings=NO_DNS, **only("crtname.search"))
    assert res.status is Status.ERROR and "could not verify" in res.error and not res.pivots


def test_429_and_challenge_are_never_empty():
    http = FakeHttp().add("GET", CRTNAME, status=429, text="Too Many Requests", headers={"retry-after": "60"})
    assert run_module(CtLogsExtra, "domain:example.com", http, settings=NO_DNS, **only("crtname.search")).status is Status.RATE_LIMITED
    page = "<!DOCTYPE html><html><head><title>Just a moment...</title></head><body>cf-chl-widget</body></html>"
    http2 = FakeHttp().add("GET", CRTNAME, status=403, text=page)
    res = run_module(CtLogsExtra, "domain:example.com", http2, settings=NO_DNS, **only("crtname.search"))
    assert res.status is Status.BLOCKED and res.reason_code == "challenge"


def test_empty_answer_is_empty():
    http = FakeHttp().add("GET", CRTNAME, text="", headers={"content-type": "text/plain"})
    res = run_module(CtLogsExtra, "domain:example.com", http, settings=NO_DNS, **only("crtname.search"))
    assert res.status is Status.EMPTY


def test_merklemap_pages_stop_at_the_count_or_the_cap():
    page = fx("merklemap_ok.json")
    http = FakeHttp()
    for n in range(3):
        http.add("GET", MM.format(page=n), json=dict(page, count=100))
    res = run_module(CtLogsExtra, "domain:example.com", http, keys={"merklemap": KEY}, settings=NO_DNS, **only("merklemap.search"))
    assert res.status is Status.OK and res.partial and res.stop_reason == "request_cap" and "page cap" in res.error
    assert len(http.calls) == 3


def test_subdomain_is_not_applicable():
    http = FakeHttp()
    assert run_module(CtLogsExtra, "domain:www.example.com", http).status is Status.SKIPPED
    assert http.calls == []


def test_liveness_labels_historical_names():
    http = FakeHttp().add("GET", CRTNAME, text="example.com\ngone.example.com\n", headers={"content-type": "text/plain"})
    add_nxdomain_everything(http)
    res = run_module(CtLogsExtra, "domain:example.com", http, **only("crtname.search"))
    assert res.attributes["ct_names_historical"] == ["gone.example.com"]
    assert subdomain_pivots(res)["gone.example.com"].expand is False
