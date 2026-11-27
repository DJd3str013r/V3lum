"""Offline tests for P223 ``sec_edgar`` (batch p3-G10-1).

Fixtures in tests/fixtures/sec_edgar/ are trimmed live/research SEC answers (README there).
"""

from __future__ import annotations

import re
from pathlib import Path
from urllib.parse import parse_qs, urlsplit

import pytest

from tests.fakes import FakeHttp, make_runtime, module_fixture, run_module
from v3lum.core.context import ScanOptions
from v3lum.core.models import Severity, Status
from v3lum.modules.company_org import sec_edgar as sec
from v3lum.modules.company_org.sec_edgar import SecEdgar

FIX = Path(__file__).resolve().parents[1] / "fixtures/sec_edgar"
CONTACT = {"contact_email": "cti-team@example.com"}
EFTS = re.compile(r"^https://efts\.sec\.gov/LATEST/search-index\?")
MSFT = sec.SUBMISSIONS_URL.format(cik10="0000789019")
APPLE = sec.SUBMISSIONS_URL.format(cik10="0000320193")


def fx(name: str):
    return module_fixture("sec_edgar", name)


def routes(*, efts: str = "efts_empty.json", subs: dict[str, str] | None = None) -> FakeHttp:
    http = FakeHttp().add("GET", sec.TICKERS_URL, json=fx("company_tickers_sample.json"))
    for url, name in (subs or {}).items():
        http.add("GET", url, json=fx(name))
    return http.add("GET", EFTS, json=fx(efts))


def test_without_contact_email_it_is_skipped_config_and_sends_nothing():
    http = FakeHttp()
    res = run_module(SecEdgar, "company_name:Microsoft Corp", http)
    assert res.status is Status.SKIPPED and res.reason_code == "config" and "contact" in res.error
    assert http.calls == []


def test_registrant_own_item_105_disclosures_from_submissions():
    http = routes(efts="efts_ok.json", subs={MSFT: "submissions_ok.json"})
    res = run_module(SecEdgar, "company_name:Microsoft Corp", http, settings=CONTACT)
    assert res.status is Status.OK, res.error
    company = res.attributes["sec_company"]
    assert company["cik"] == "0000789019" and company["tickers"] == ["MSFT"] and company["match"] == "name_exact"
    assert company["confidence"] == "possible"  # a name match stays POSSIBLE (cond 5)
    discl = res.attributes["sec_cyber_disclosures"]
    own = [d for d in discl if d["relation"] == "own_cik"]
    assert {d["adsh"] for d in own} == {"0001193125-24-011295", "0001193125-24-062997"}
    assert {d["form"] for d in own} == {"8-K", "8-K/A"}
    finding = next(f for f in res.findings if f.data["adsh"] == "0001193125-24-011295")
    assert finding.title == "Material cybersecurity incident disclosed to the SEC (8-K Item 1.05)"
    assert finding.severity is Severity.LOW and finding.confidence_label.value == "possible"
    assert "cyber_incident_disclosure" in finding.tags and finding.source == "sec.submissions"
    assert finding.data["url"] == "https://www.sec.gov/Archives/edgar/data/789019/000119312524011295/d708866d8k.htm"
    assert all(f.severity in (Severity.INFO, Severity.LOW) for f in res.findings)
    assert res.attributes["sec_search_coverage"]["first_page_only"] is True
    assert res.pivots == []
    http.assert_hosts_within(SecEdgar)


def test_identifying_user_agent_only_with_the_role_mailbox():
    http = routes(subs={MSFT: "submissions_ok.json"})
    run_module(SecEdgar, "company_name:Microsoft Corp", http, settings=CONTACT)
    for call in http.calls:
        assert "cti-team@example.com" in call["headers"].get("User-Agent", ""), call["url"]


def test_efts_query_never_carries_parentheses_and_is_first_page_only():
    http = routes(subs={MSFT: "submissions_ok.json"})
    run_module(SecEdgar, "company_name:Microsoft (USA) Corp", http, settings=CONTACT)
    efts = [c for c in http.calls if c["url"].startswith(sec.EFTS_URL)]
    (call,) = efts
    q = parse_qs(urlsplit(call["url"]).query)
    assert "(" not in q["q"][0] and ")" not in q["q"][0]
    assert q["q"][0] == '"Microsoft USA Corp" "Item 1.05" OR "cybersecurity incident"'
    assert q["forms"] == ["8-K,6-K"] and q["startdt"] == ["2023-12-18"] and "from" not in q
    with pytest.raises(ValueError):
        sec.efts_query("()")
    literal = fx("efts_parentheses_literal.json")
    assert sec.parse_efts(literal)["total"] == 0  # live proof: parentheses matched nothing


def test_mentions_by_other_registrants_are_info_possible():
    http = routes(efts="efts_mentions.json")
    http.add("GET", sec.SUBMISSIONS_URL.format(cik10="0002152623"), status=404, json={"error": "not found"})
    res = run_module(SecEdgar, "company_name:Navient", http, settings=CONTACT)
    assert res.status is Status.OK
    navient = [f for f in res.findings if f.data["company"] == "NAVIENT CORP"]
    assert navient and navient[0].data["relation"] in ("own_ticker", "own_name") and navient[0].confidence_label.value == "possible"
    for f in res.findings:
        if f.data["relation"] == "mention":
            assert f.severity is Severity.INFO and "context_only" in f.tags and f.confidence_label.value == "possible"
    assert len(res.findings) <= sec.EFTS_CAP


def test_ticker_keyword_is_a_confirmed_identity_when_selected():
    http = routes(subs={MSFT: "submissions_ok.json"})
    rt = make_runtime(http, settings=CONTACT)
    rt.in_scan = True
    res = run_module(SecEdgar, "keyword:MSFT", http, runtime=rt, options=ScanOptions(include=["sec_edgar"]))
    assert res.attributes["sec_company"]["match"] == "ticker" and res.attributes["sec_company"]["confidence"] == "confirmed"
    own = next(f for f in res.findings if f.data["relation"] == "own_cik")
    assert own.confidence_label.value == "confirmed"


def test_keyword_without_explicit_selection_is_not_default():
    http = FakeHttp()
    rt = make_runtime(http, settings=CONTACT)
    rt.in_scan = True
    res = run_module(SecEdgar, "keyword:MSFT", http, runtime=rt)
    assert res.status is Status.SKIPPED and res.reason_code == "not_default" and http.calls == []


def test_no_registrant_and_no_hit_is_empty_and_no_cyber_is_ok_without_findings():
    res = run_module(SecEdgar, "company_name:Totally Unknown Widgets", routes(), settings=CONTACT)
    assert res.status is Status.EMPTY
    apple = run_module(SecEdgar, "company_name:Apple Inc.", routes(subs={APPLE: "submissions_no_cyber.json"}), settings=CONTACT)
    assert apple.status is Status.OK and apple.findings == [] and apple.attributes["sec_company"]["cik"] == "0000320193"


def test_fair_access_403_is_blocked_with_the_ua_hint_never_no_filings():
    ex = fx("blocked_403.http.json")
    http = FakeHttp().add("GET", sec.TICKERS_URL, json=fx("company_tickers_sample.json"))
    http.add("GET", MSFT, status=ex["status"], body=ex["body"].encode(), headers=ex["headers"])
    res = run_module(SecEdgar, "company_name:Microsoft Corp", http, settings=CONTACT)
    assert res.status is Status.BLOCKED and "contact_email" in res.error


def test_efts_failure_after_company_facts_is_a_per_source_could_not_verify():
    http = FakeHttp().add("GET", sec.TICKERS_URL, json=fx("company_tickers_sample.json")).add("GET", MSFT, json=fx("submissions_ok.json"))
    http.add("GET", EFTS, status=429, text="slow down")
    res = run_module(SecEdgar, "company_name:Microsoft Corp", http, settings=CONTACT)
    assert res.status is Status.OK
    assert "rate_limited" in str(res.source_statuses.get(sec.SOURCE_EFTS))
    only_efts = FakeHttp().add("GET", sec.TICKERS_URL, json=fx("company_tickers_sample.json")).add("GET", EFTS, status=503, text="down")
    assert run_module(SecEdgar, "company_name:Totally Unknown Widgets", only_efts, settings=CONTACT).status is Status.ERROR


def test_truncated_submissions_is_error_never_empty():
    http = FakeHttp().add("GET", sec.TICKERS_URL, json=fx("company_tickers_sample.json"))
    http.add("GET", MSFT, body=(FIX / "submissions_truncated.txt").read_bytes(), headers={"content-type": "application/json"})
    assert run_module(SecEdgar, "company_name:Microsoft Corp", http, settings=CONTACT).status is Status.ERROR


def test_unknown_cik_404_is_an_absence_of_that_registrant():
    http = FakeHttp().add("GET", sec.TICKERS_URL, json=fx("company_tickers_sample.json"))
    http.add("GET", MSFT, status=404, json={"error": "not found"}).add("GET", EFTS, json=fx("efts_empty.json"))
    res = run_module(SecEdgar, "company_name:Microsoft Corp", http, settings=CONTACT)
    assert res.status in (Status.OK, Status.EMPTY) and "sec_company" not in res.attributes


def test_local_matching_rules():
    rows = sec.parse_tickers(fx("company_tickers_sample.json"))
    assert {r["cik10"] for r in sec.match_company("GOOG", rows, ticker=True)} == {"0001652044"}
    navient = sec.match_company("Navient Corp", rows)
    assert navient and navient[0]["cik10"] == "0002152623" and navient[0]["confidence"] == "possible"
    assert sec.cik10("789019") == "0000789019" and sec.cik10("0") is None and sec.cik10("abc") is None
    assert SecEdgar.default_enabled is False and SecEdgar.min_interval == 0.5
