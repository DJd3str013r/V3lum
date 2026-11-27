"""Offline tests for ooni (P023): recorded OONI measurements and aggregation answers.

Fixtures in tests/fixtures/ooni/ (provenance in MANIFEST.json): live api.ooni.io answers of 2026-11-26
(aggregation per country, CN anomalies, BR empty, invalid probe_cc), research samples and a few synthetic
error envelopes; the licence text is the verbatim OONI data licence (P023 cond 3).
"""

from __future__ import annotations

import copy
import json
from urllib.parse import urlencode

import pytest

from tests.fakes import FakeHttp, module_fixture, run_module
from v3lum.core import providers
from v3lum.core.models import Severity, Status
from v3lum.modules.domain_dns.ooni import (
    AGGREGATION_URL,
    ISO_3166_ALPHA2,
    MEASUREMENTS_URL,
    OONI_ATTRIBUTION,
    Ooni,
    counts_from_measurements,
    country_summary,
    next_page,
    parse_aggregation,
    parse_aggregation_by_country,
    parse_measurements,
    probe_countries,
    valid_cc,
)

MOD = Ooni
SINCE, UNTIL = "2026-10-27", "2026-11-27"  # FakeClock 2026-11-26: last 30 days, until = tomorrow
CN_ON = {"ooni_case_country": "CN"}


def fx(name: str):
    return module_fixture(MOD, name)


def http_fx(name: str):
    resp = fx(name)["response"]
    return resp["status"], dict(resp.get("headers") or {}), resp["body"]


def agg_url(domain: str, cc: str) -> str:
    return AGGREGATION_URL + "?" + urlencode({"domain": domain, "probe_cc": cc, "since": SINCE, "until": UNTIL})


def meas_url(domain: str, cc: str) -> str:
    return MEASUREMENTS_URL + "?" + urlencode({"domain": domain, "probe_cc": cc, "limit": 50, "since": SINCE, "until": UNTIL})


def country_row(cc: str) -> dict:
    """One live per-country row of tests/fixtures/ooni/aggregation_by_country.json as a no-axis answer."""
    row = next(r for r in fx("aggregation_by_country.json")["result"] if r["probe_cc"] == cc)
    return {"v": 0, "dimension_count": 0, "result": {k: v for k, v in row.items() if k != "probe_cc"}}


def test_br_sporadic_noise_and_case_country_possible_blocking_with_page_cap():
    page1 = fx("measurements_anomaly_cn.json")
    http = (FakeHttp()
            .add("GET", agg_url("www.google.com", "BR"), json=country_row("BR"))
            .add("GET", agg_url("www.google.com", "CN"), json=country_row("CN"))
            .add("GET", meas_url("www.google.com", "CN"), json=page1)
            .add("GET", page1["metadata"]["next_url"], json=fx("measurements_page2_synthetic.json")))
    res = run_module(MOD, "domain:www.google.com", http, settings=CN_ON)
    assert res.status is Status.OK, res.error
    by_cc = {s["probe_cc"]: s for s in res.attributes["ooni_censorship"]}
    assert by_cc["BR"]["state"] == "anomalies_sporadic" and by_cc["BR"]["measurement_count"] == 1318
    assert "usual network noise" in by_cc["BR"]["text"]
    cn = by_cc["CN"]
    assert cn["state"] == "anomalies_consistent" and cn["tested_count"] == 44 and cn["anomaly_rate"] == pytest.approx(40 / 44, abs=1e-4)
    assert cn["blocking_types"] == {"tcp_ip": 2} and "TCP/IP blocking" in cn["text"]
    assert len(cn["evidence"]) == 2 and all(u.startswith("https://api.ooni.io/api/v1/raw_measurement") for u in cn["evidence"])
    assert all(u.startswith("https://explorer.ooni.org/m/") for u in cn["manual_links"])
    assert len(http.calls) == 4  # 2 aggregations + 2 measurement pages: the page-2 next_url is never followed (cond 1)
    titles = {f.key: f.title for f in res.findings}
    assert titles == {"BR": "OONI measurements: sporadic anomalies only", "CN": "Possible blocking seen by OONI probes (not confirmed)"}
    for f in res.findings:  # context only, never scored (cond 2)
        assert f.severity is Severity.INFO and {"context_only", "censorship"} <= set(f.tags) and f.source == "ooni.api"
        assert OONI_ATTRIBUTION in f.description and f.criterion
    assert res.attributes["data_attribution"] == OONI_ATTRIBUTION  # cond 3: report footer attribution
    assert not res.pivots
    labels = [label for label, _url in res.links]
    assert any("explorer.ooni.org" in url for _l, url in res.links) and all("manual" in label for label in labels)
    http.assert_hosts_within(MOD)


def test_confirmed_blocking_is_the_only_blocked_wording():
    agg = {"v": 0, "dimension_count": 0, "result": {"anomaly_count": 4, "confirmed_count": 3, "failure_count": 0, "ok_count": 6, "measurement_count": 10}}
    page = copy.deepcopy(fx("measurements_anomaly_cn.json"))
    page["metadata"]["next_url"] = None
    for r in page["results"]:
        r["probe_cc"] = "BR"
    page["results"][0]["confirmed"] = True  # derived from the live CN page: one fingerprinted block page
    http = (FakeHttp()
            .add("GET", agg_url("www.google.com", "BR"), json=agg)
            .add("GET", meas_url("www.google.com", "BR"), json=page))
    res = run_module(MOD, "domain:www.google.com", http)
    summary = res.attributes["ooni_censorship"][0]
    assert summary["state"] == "confirmed_blocking" and "confirmed in BR" in summary["text"]
    finding = res.findings[0]
    assert finding.title == "Blocking confirmed by OONI probes" and finding.severity is Severity.INFO
    assert "context_only" in finding.tags


def test_www_variant_only_when_the_exact_host_has_no_measurements():
    http = (FakeHttp()
            .add("GET", agg_url("google.com", "BR"), json=fx("aggregation_empty_synthetic.json"))
            .add("GET", agg_url("www.google.com", "BR"), json=fx("aggregation_ok.json")))
    res = run_module(MOD, "domain:google.com", http)
    assert res.status is Status.OK
    summary = res.attributes["ooni_censorship"][0]
    assert summary["domain"] == "www.google.com" and summary["state"] == "anomalies_sporadic"
    assert "queried www.google.com" in summary["text"]
    assert len(http.calls) == 2  # sporadic anomalies (152 of 23692 tests): no evidence pages for network noise


def test_no_measurements_is_empty_never_not_blocked():
    http = FakeHttp().add("GET", agg_url("www.example.com", "BR"), json=fx("aggregation_empty_synthetic.json"))
    res = run_module(MOD, "domain:www.example.com", http)
    assert res.status is Status.EMPTY and "no evidence either way" in res.error
    assert not res.findings and "not blocked" not in res.error


def test_invalid_case_country_is_never_sent():
    http = FakeHttp().add("GET", agg_url("www.example.com", "BR"), json=fx("aggregation_empty_synthetic.json"))
    res = run_module(MOD, "domain:www.example.com", http, settings={"ooni_case_country": "BRA"})
    assert [c["url"] for c in http.calls] == [agg_url("www.example.com", "BR")] or len(http.calls) == 1
    assert "probe_cc=BRA" not in json.dumps(http.urls())
    assert any("ooni_case_country" in n for n in res.raw["notes"])


def test_429_is_rate_limited_and_stops_querying():
    st, headers, body = http_fx("rate_limited_429_synthetic.http.json")
    http = FakeHttp().add("GET", agg_url("www.google.com", "BR"), status=st, headers=headers, body=body.encode())
    res = run_module(MOD, "domain:www.google.com", http, settings=CN_ON)
    assert res.status is Status.RATE_LIMITED and "could not verify" in res.error
    assert all("probe_cc=CN" not in u for u in http.urls())  # the case country is not hammered after a refusal


def test_5xx_html_is_error():
    st, headers, body = http_fx("error_502_html_synthetic.http.json")
    http = FakeHttp().add("GET", agg_url("www.example.com", "BR"), status=st, headers=headers, body=body.encode())
    res = run_module(MOD, "domain:www.example.com", http)
    assert res.status is Status.ERROR and "could not verify" in res.error


def test_challenge_page_is_blocked():
    st, headers, body = http_fx("explorer_challenge_429.http.json")  # live Vercel checkpoint (explorer.ooni.org)
    http = FakeHttp().add("GET", agg_url("www.example.com", "BR"), status=403, headers=headers, body=body.encode())
    res = run_module(MOD, "domain:www.example.com", http)
    assert res.status is Status.BLOCKED and res.reason_code == "challenge"


def test_error_in_200_and_malformed_answers_are_errors():
    http = FakeHttp().add("GET", agg_url("www.example.com", "BR"), json={"error": "Invalid probe_cc"})
    assert run_module(MOD, "domain:www.example.com", http).status is Status.ERROR
    http2 = FakeHttp().add("GET", agg_url("www.example.com", "BR"), text="<html><body>maintenance</body></html>")
    res2 = run_module(MOD, "domain:www.example.com", http2)
    assert res2.status is Status.ERROR and "could not verify" in res2.error
    http3 = FakeHttp().add("GET", agg_url("www.example.com", "BR"), json={"unexpected": True})
    assert run_module(MOD, "domain:www.example.com", http3).status is Status.ERROR
    page = {"metadata": {"next_url": None}, "results": "not a list"}
    agg = {"v": 0, "result": {"anomaly_count": 3, "confirmed_count": 0, "failure_count": 0, "ok_count": 1, "measurement_count": 4}}
    http4 = (FakeHttp().add("GET", agg_url("www.example.com", "BR"), json=agg)
             .add("GET", meas_url("www.example.com", "BR"), json=page))
    assert run_module(MOD, "domain:www.example.com", http4).status is Status.ERROR


def test_one_country_failing_keeps_the_other_as_partial():
    st, headers, body = http_fx("rate_limited_429_synthetic.http.json")
    http = (FakeHttp()
            .add("GET", agg_url("www.google.com", "BR"), json=country_row("BR"))
            .add("GET", agg_url("www.google.com", "CN"), status=st, headers=headers, body=body.encode()))
    res = run_module(MOD, "domain:www.google.com", http, settings=CN_ON)
    assert res.status is Status.OK and res.partial and res.stop_reason == "rate_limited"
    states = {s["probe_cc"]: s["state"] for s in res.attributes["ooni_censorship"]}
    assert states == {"BR": "anomalies_sporadic", "CN": "could_not_verify"}
    assert "CN" in res.error and "could not verify" in res.error
    assert [f.key for f in res.findings] == ["BR"]


def test_low_rate_budget_stops_before_the_api_refuses():
    http = FakeHttp().add("GET", agg_url("www.google.com", "BR"), json=country_row("CN") | {}, headers={"x-ratelimit-remaining": "10"})
    res = run_module(MOD, "domain:www.google.com", http, settings=CN_ON)
    assert len(http.calls) == 1  # no measurement pages, no case country
    assert res.status is Status.OK and res.partial and res.stop_reason == "rate_limited"
    br = res.attributes["ooni_censorship"][0]
    assert "evidence not collected" in br["text"]


def test_url_input_uses_its_host_and_ip_urls_are_not_applicable():
    http = FakeHttp().add("GET", agg_url("www.example.com", "BR"), json=fx("aggregation_empty_synthetic.json"))
    res = run_module(MOD, "url:https://www.example.com/login?next=1", http)
    assert res.status is Status.EMPTY and len(http.calls) == 1
    assert run_module(MOD, "url:http://203.0.113.5/x", FakeHttp()).status is Status.SKIPPED


def test_licence_is_noncommercial_with_evidence():
    text = fx("licence_data.md")
    assert "Attribution-NonCommercial-ShareAlike 4.0" in text
    assert MOD.terms == "noncommercial" and MOD.default_enabled is False
    src = providers.registry().source("ooni.api")
    assert src.terms.class_ == "noncommercial" and src.terms.free_plan_business_use is False
    assert "ooni/license" in src.terms.evidence_url


# ======================================================================================
# pure helpers
# ======================================================================================


def test_parsers_on_live_answers():
    by_cc = parse_aggregation_by_country(fx("aggregation_by_country.json"))
    assert set(by_cc) == {"AE", "BR", "CN", "DE", "ES", "RU", "US"} and set(by_cc) <= ISO_3166_ALPHA2
    assert parse_aggregation(fx("aggregation_by_country.json"))["measurement_count"] == sum(c["measurement_count"] for c in by_cc.values())
    _st, _h, body = http_fx("measurements_empty_br.http.json")
    empty = parse_measurements(json.loads(body))
    assert empty == {"results": [], "next_url": None}
    invalid_cc = parse_measurements(fx("measurements_invalid_cc_empty.json"))
    assert invalid_cc["results"] == []  # what an invalid probe_cc looks like: hence valid_cc() before sending
    page = parse_measurements(fx("measurements_anomaly_cn.json"))
    first = page["results"][0]
    assert first["probe_asn"] == "AS56040" and first["blocking_type"] == "tcp_ip" and first["date"] == "2026-11-25"
    assert counts_from_measurements(page["results"], "CN") == {"measurement_count": 3, "anomaly_count": 2, "confirmed_count": 0,
                                                               "failure_count": 1, "ok_count": 0}
    assert parse_aggregation(["junk"]) is None and parse_measurements("<html>") is None


def test_next_page_cap_and_host_checks():
    url = fx("measurements_anomaly_cn.json")["metadata"]["next_url"]
    assert next_page(url, 1, "www.google.com") == (url, "")
    assert next_page(url, 2, "www.google.com") == (None, "page_cap")
    assert next_page(url, 1, "example.com")[1] == "foreign_url"
    assert next_page("https://evil.example/api/v1/measurements?domain=www.google.com", 1, "www.google.com")[1] == "foreign_url"
    assert next_page(None, 1, "www.google.com") == (None, "last_page")


def test_country_states_and_country_codes():
    base = {"measurement_count": 0, "anomaly_count": 0, "confirmed_count": 0, "failure_count": 0, "ok_count": 0}
    kw = {"host": "example.com", "since": SINCE, "until": UNTIL}
    assert country_summary("BR", base, **kw)["state"] == "no_measurements"
    assert country_summary("BR", base | {"measurement_count": 5, "failure_count": 5}, **kw)["state"] == "failures_only"
    assert country_summary("BR", base | {"measurement_count": 5, "ok_count": 5}, **kw)["state"] == "no_anomaly"
    assert country_summary("BR", base | {"measurement_count": 10, "anomaly_count": 2}, **kw)["state"] == "anomalies_sporadic"
    assert country_summary("BR", base | {"measurement_count": 4, "anomaly_count": 3}, **kw)["state"] == "anomalies_consistent"
    assert valid_cc("br") and not valid_cc("BRA") and not valid_cc("UK") and valid_cc("XK")
    assert probe_countries("cn") == ["BR", "CN"] and probe_countries("BR") == ["BR"] and probe_countries("UK") == ["BR"]
