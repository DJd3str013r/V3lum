"""chainabuse (P204): Chainabuse community scam reports (keyed, noncommercial terms).

Fixtures in tests/fixtures/chainabuse/: ``needs_key_401.json`` is the real keyless answer of
GET api.chainabuse.com/v0/reports (research sample, 2026-11-25). ``reports_ok_synthetic.json`` and
``reports_empty_synthetic.json`` are SYNTHETIC (no team key in this build; shape from the research record
and docs.chainabuse.com 'Screening addresses', documentation values only) - P204 cond 5 asks for keyed
captures, recorded in docs/backlog/p2-G09-1.md.
"""

from __future__ import annotations

import base64

import pytest

from tests.fakes import FakeHttp, assert_no_secret, module_fixture, run_module
from v3lum.core.models import Status
from v3lum.modules.crypto.chainabuse import REPORTS_URL, Chainabuse, assess, category_tags, mask_pii, parse_reports

KEY = "cab-test-0123456789abcdef"
ADDR = "0x1111111111111111111111111111111111111111"
URL = f"{REPORTS_URL}?address={ADDR}&page=1&perPage=50"
AUTH = "Basic " + base64.b64encode(f"{KEY}:{KEY}".encode()).decode()


def route(http: FakeHttp, url: str = URL, **kw) -> FakeHttp:
    return http.add("GET", url, match_headers={"Authorization": AUTH}, **kw)


def test_metadata_noncommercial_keyed_default_candidate():
    cls = Chainabuse
    assert cls.terms == "noncommercial" and cls.requires_keys == ("chainabuse",) and cls.default_enabled is True
    assert (cls.provider, cls.sources, cls.hosts, cls.disclosure) == ("trm_chainabuse", ("trm_chainabuse.reports_api",), ("api.chainabuse.com",), "third_party")
    assert cls.trust_tier == "community" and cls.max_requests == 1 and cls.manual_link == "https://www.chainabuse.com/address/{q}"


def test_without_key_needs_key_and_sends_nothing():
    http = FakeHttp()
    res = run_module(Chainabuse, f"eth_address:{ADDR}", http)
    assert res.status is Status.NEEDS_KEY and http.calls == []


def test_reports_summary_masked_and_capped_at_medium():
    http = route(FakeHttp(), json=module_fixture("chainabuse", "reports_ok_synthetic.json"))
    res = run_module(Chainabuse, f"eth_address:{ADDR}", http, keys={"chainabuse": KEY})
    assert res.status is Status.OK and res.requests == 1
    reports = res.attributes["chainabuse_reports"]
    assert reports["count"] == 3 and reports["checked"] == 1 and reports["trusted"] == 1
    assert reports["first_report"] == "2026-09-14" and reports["last_report"] == "2026-11-20"
    assert reports["wording"].startswith("3 community reports (unverified): ")
    assert "last report 2026-11-20" in reports["wording"]
    assert set(reports["related"]) == {"wallet-support.example", "TWoXbK3nKuugcEocWVwB4k1Sp1HkcrZPz1"}  # never the queried address
    excerpts = " ".join(reports["excerpts"])
    for leaked in ("suporte@example.com", "5555-0101", "123.456.789-09", "@example_handle", "ref=victim42"):
        assert leaked not in excerpts
    assert "[email]" in excerpts and "[phone]" in excerpts and "[cpf]" in excerpts and all(len(e) <= 120 for e in reports["excerpts"])
    [finding] = res.findings
    assert finding.severity.label == "medium" and finding.confidence_label.value == "probable"
    assert set(finding.tags) == {"fraud", "phishing", "ransomware"} and "unverified" in finding.title
    assert finding.observed_first and finding.observed_last and finding.source == "trm_chainabuse.reports_api"
    assert any(url.startswith("https://www.chainabuse.com/address/") for _l, url in res.links)
    assert_no_secret(KEY, res.to_dict())
    assert_no_secret(AUTH.split()[1], res.to_dict())
    http.assert_hosts_within(Chainabuse)


def test_single_unverified_report_is_low_suspicious():
    one = [module_fixture("chainabuse", "reports_ok_synthetic.json")[1]]  # unchecked, untrusted
    http = route(FakeHttp(), json=one)
    res = run_module(Chainabuse, f"eth_address:{ADDR}", http, keys={"chainabuse": KEY})
    [finding] = res.findings
    assert finding.severity.label == "low" and "suspicious" in finding.tags and "fraud" not in finding.tags
    assert finding.confidence_label.value == "possible" and "ransomware" in finding.tags


def test_no_reports_is_empty():
    http = route(FakeHttp(), json=module_fixture("chainabuse", "reports_empty_synthetic.json"))
    res = run_module(Chainabuse, f"eth_address:{ADDR}", http, keys={"chainabuse": KEY})
    assert res.status is Status.EMPTY and res.attributes["chainabuse_reports"]["count"] == 0


def test_rejected_key_is_needs_key():
    http = route(FakeHttp(), status=401, json=module_fixture("chainabuse", "needs_key_401.json"))
    assert run_module(Chainabuse, f"eth_address:{ADDR}", http, keys={"chainabuse": KEY}).status is Status.NEEDS_KEY


@pytest.mark.parametrize(
    "status,body,expected",
    [
        (429, "Too Many Requests", Status.RATE_LIMITED),
        (502, "bad gateway", Status.ERROR),
        (403, "<html><head><title>Attention Required! | Cloudflare</title></head><body>cf-chl-widget</body></html>", Status.BLOCKED),
    ],
)
def test_http_failures_are_could_not_verify(status, body, expected):
    http = route(FakeHttp(), status=status, text=body, times=2)
    assert run_module(Chainabuse, f"eth_address:{ADDR}", http, keys={"chainabuse": KEY}).status is expected


def test_error_inside_http_200_is_never_empty():
    http = route(FakeHttp(), json={"message": "Internal server error"})
    res = run_module(Chainabuse, f"eth_address:{ADDR}", http, keys={"chainabuse": KEY})
    assert res.status is Status.ERROR and "could not verify" in res.error
    http2 = route(FakeHttp(), text="<html>not json</html>")
    assert run_module(Chainabuse, f"eth_address:{ADDR}", http2, keys={"chainabuse": KEY}).status is Status.ERROR


def test_domains_and_btc_addresses_use_the_same_parameter():
    url = f"{REPORTS_URL}?address=wallet-support.example&page=1&perPage=50"
    http = route(FakeHttp(), url=url, json=[])
    assert run_module(Chainabuse, "domain:wallet-support.example", http, keys={"chainabuse": KEY}).status is Status.EMPTY
    btc = "1KwdXzmjqp39iuZCecTGytQfxVtHiLmg1Z"
    http2 = route(FakeHttp(), url=f"{REPORTS_URL}?address={btc}&page=1&perPage=50", json=[])
    assert run_module(Chainabuse, f"btc_address:{btc}", http2, keys={"chainabuse": KEY}).status is Status.EMPTY


def test_invalid_address_is_never_sent():
    http = FakeHttp()
    res = run_module(Chainabuse, "other_crypto_address:TNotAValidTronAddressXXXXXXXXXXXXX", http, keys={"chainabuse": KEY})
    assert res.status is Status.SKIPPED and res.reason_code == "not_applicable" and http.calls == []


def test_page_cap_is_reported():
    report = module_fixture("chainabuse", "reports_ok_synthetic.json")[0]
    http = route(FakeHttp(), json={"reports": [report] * 50})
    res = run_module(Chainabuse, f"eth_address:{ADDR}", http, keys={"chainabuse": KEY})
    assert res.attributes["chainabuse_reports"]["page_cap_reached"] is True and "page cap" in res.findings[0].description


def test_helpers():
    assert assess(0, False) == (None, None) and assess(2, False) == ("low", "suspicious") and assess(1, True) == ("medium", "fraud")
    assert category_tags(["Blackmail - Sextortion", "PHISHING", "Ransomware"]) == ["extortion", "phishing", "ransomware"]
    assert mask_pii("call (11) 5555-0102 or +55 11 5555-0103, card 4111 1111 1111 1111") == "call [phone] or [phone], card [card]"
    assert parse_reports({"unexpected": True})["status"] == "error" and parse_reports("x")["status"] == "error"
