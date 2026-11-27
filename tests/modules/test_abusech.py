"""abusech (P156): URLhaus/ThreatFox/MalwareBazaar APIs, Feodo Tracker + SSLBL local matching, exports.

Fixtures in tests/fixtures/abusech/ (see the batch notes; no success answer could be captured without
the team key, cond 10 - backlog):
* ``*_docs.json``: the providers' public API documentation examples (fetched 2026-11-26), valid JSON,
  hosts/IPs/handles replaced by documentation values (example.com/.net/.org, 192.0.2/198.51.100/
  203.0.113, reporter_a);
* ``api_no_key_401.json``: the real 401 body of the three APIs without a key (research sample);
* ``mb_get_info_synthetic.json`` and ``*_export_recent_synthetic.csv``: built from the documented field
  lists with documentation values (synthetic; to be replaced by team-key captures, cond 10);
* ``feodo_ipblocklist.json`` (live 2026-11-26: 5 entries, last update 2026-03-04), ``sslbl_sha1.csv`` /
  ``sslbl_sha1_truncated.csv`` (live, trimmed: with and without the END trailer),
  ``sslbl_ip_deprecated_0_rows.csv`` (the live deprecated IP list, 0 rows) and
  ``legacy_export_410.txt`` (the live 410 body of the legacy keyless exports).
"""

from __future__ import annotations

import json

import pytest

from tests.fakes import FakeHttp, assert_no_secret, make_runtime, module_fixture, run_module
from v3lum import paths
from v3lum.core import redact
from v3lum.core.entities import Entity
from v3lum.core.entities import EntityType as T
from v3lum.core.http import NetworkError
from v3lum.core.models import Status
from v3lum.modules.threat_intel_ioc import abusech as mod
from v3lum.modules.threat_intel_ioc.abusech import Abusech

KEY = "abusech-test-key-0123456789"
KEYS = {"abusech": KEY}
URLHAUS = "https://urlhaus-api.abuse.ch/v1/"
THREATFOX = "https://threatfox-api.abuse.ch/api/v1/"
BAZAAR = "https://mb-api.abuse.ch/api/v1/"
EICAR_SHA256 = "275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f"


@pytest.fixture(autouse=True)
def _fresh_parse_cache(monkeypatch):
    """Parsed feed copies are memoized per process by dataset version: start every test empty."""
    from collections import OrderedDict

    from v3lum.modules.threat_intel_ioc import abusech as _abusech

    monkeypatch.setattr(_abusech, "_MEMO", OrderedDict())


def fx(name):
    return module_fixture(Abusech, name)


def install(name, content):
    """Place a local dataset copy as `v3lum data update` would (the module never downloads)."""
    target = paths.datasets_dir() / name
    target.write_text(content if isinstance(content, str) else json.dumps(content), encoding="utf-8")
    return target


def pivots(res, etype=None):
    return {p.entity.value for p in res.pivots if etype is None or p.entity.type is etype}


def sent_queries(http):
    """(url, body) of every request the module sent, to prove each one is allow-listed (cond 4)."""
    out = []
    for call in http.calls:
        body = call.get("body") or b""
        out.append((call["url"], body.decode("utf-8", "replace") if isinstance(body, bytes) else str(body)))
    return out


# ------------------------------------------------------------------ metadata and registration
def test_contract_metadata():
    cls = Abusech
    assert cls.terms == "license"
    assert cls.terms_sources == {"abusech.urlhaus": "license", "abusech.threatfox": "license", "abusech.malwarebazaar": "license",
                                 "abusech.feodotracker": "open", "abusech.sslbl": "open"}
    assert cls.optional_keys == ("abusech",) and cls.requires_keys == ()  # no per-entity NEEDS_KEY before the run (cond 9)
    assert cls.default_enabled is True and cls.trust_tier == "trusted"
    assert cls.upstream_families == frozenset({"abuse.ch"})
    assert set(cls.hosts) == {"urlhaus-api.abuse.ch", "threatfox-api.abuse.ch", "mb-api.abuse.ch"}
    assert "licence-cleared" in cls.notice


def test_shared_datasets_are_registered_once_with_their_open_sources():
    from v3lum.core.datasets import DATASETS, dataset_errors

    assert DATASETS[mod.FEODO_DATASET]["source"] == "abusech.feodotracker"
    assert DATASETS[mod.SSLBL_DATASET]["source"] == "abusech.sslbl"
    assert DATASETS[mod.SSLBL_DATASET]["url"] == "https://sslbl.abuse.ch/blacklist/sslblacklist.csv"
    assert {DATASETS[n]["terms_class"] for n in (mod.FEODO_DATASET, mod.SSLBL_DATASET)} == {"open"}
    # one registration per list: no other dataset downloads the same URL (cond 8: never downloaded twice)
    for name in (mod.FEODO_DATASET, mod.SSLBL_DATASET):
        assert [n for n, reg in DATASETS.items() if reg["url"] == DATASETS[name]["url"]] == [name]
    assert not any("{AUTH_KEY}" in reg["url"] or "abuse.ch/v2/files/exports" in reg["url"] for reg in DATASETS.values())
    assert dataset_errors() == []


# ------------------------------------------------------------------ cond 4: read-only by construction
@pytest.mark.parametrize("platform,query", [
    ("malwarebazaar", "get_file"), ("malwarebazaar", "upload"), ("urlhaus", "download"), ("threatfox", "submit_ioc"),
    ("urlhaus", "submit"), ("urlhaus", "submission"), ("threatfox", "get_iocs"), ("malwarebazaar", "add_comment"),
    ("malwarebazaar", "update"), ("threatfox", "taginfo"), ("bogus", "get_info"),
])
def test_forbidden_queries_are_never_built(platform, query):
    with pytest.raises(mod.QueryRefused):
        mod.build_request(platform, query, hash=EICAR_SHA256)


def test_allowed_queries_and_unknown_parameters():
    req = mod.build_request("urlhaus", "host", host="example.com")
    assert (req.url, req.form, req.json) == ("https://urlhaus-api.abuse.ch/v1/host/", {"host": "example.com"}, None)
    req = mod.build_request("threatfox", "search_hash", hash=EICAR_SHA256)
    assert req.json == {"query": "search_hash", "hash": EICAR_SHA256} and req.url == THREATFOX
    req = mod.build_request("malwarebazaar", "get_info", hash=EICAR_SHA256)
    assert req.form == {"query": "get_info", "hash": EICAR_SHA256}
    with pytest.raises(mod.QueryRefused):
        mod.build_request("malwarebazaar", "get_info", hash=EICAR_SHA256, file="x")
    with pytest.raises(mod.QueryRefused):
        mod.build_request("urlhaus", "url")


def test_every_request_of_a_full_run_is_allow_listed():
    http = (FakeHttp().add("POST", URLHAUS + "payload/", json=fx("urlhaus_payload_ok_docs.json"))
            .add("POST", THREATFOX, json=fx("threatfox_search_hash_ok_docs.json"))
            .add("POST", BAZAAR, json=fx("mb_get_info_synthetic.json")))
    res = run_module(Abusech, f"sha256:{EICAR_SHA256}", http, keys=KEYS)
    assert res.status is Status.OK and res.requests == 3
    for url, body in sent_queries(http):
        assert url in (URLHAUS + "payload/", THREATFOX, BAZAAR)
        assert not any(word in body for word in ("get_file", "download", "upload", "submit")), body
    assert all(call["headers"].get("Auth-Key") == KEY for call in http.calls)  # terms s.2.1: every call
    http.assert_hosts_within(Abusech)


# ------------------------------------------------------------------ cond 5: central query_status mapping
@pytest.mark.parametrize("body,status,code", [
    ({"query_status": "ok", "data": []}, Status.OK, ""),
    ({"query_status": "no_results"}, Status.EMPTY, ""),
    ({"query_status": "no_result", "data": "Your search did not yield any results"}, Status.EMPTY, ""),
    ({"query_status": "hash_not_found"}, Status.EMPTY, ""),
    ({"query_status": "illegal_search_term"}, Status.SKIPPED, "not_applicable"),
    ({"query_status": "illegal_hash"}, Status.SKIPPED, "not_applicable"),
    ({"query_status": "invalid_host"}, Status.SKIPPED, "not_applicable"),
    ({"query_status": "no_hash_provided"}, Status.SKIPPED, "not_applicable"),
    ({"query_status": "unknown_auth_key"}, Status.NEEDS_KEY, "needs_key"),
    ({"error": "Unauthorized"}, Status.NEEDS_KEY, "needs_key"),
    ({"query_status": "user_blacklisted"}, Status.ERROR, "error"),
    ({"query_status": "file_not_found"}, Status.ERROR, "error"),
    ({"data": []}, Status.ERROR, "error"),
    (["not", "an", "object"], Status.ERROR, "error"),
])
def test_query_status_mapping(body, status, code):
    got, got_code, _text = mod.map_query_status(body)
    assert (got, got_code) == (status, code)


# ------------------------------------------------------------------ cond 9: without the key
def test_without_key_one_coverage_reason_and_manual_links_no_request():
    http = FakeHttp()
    res = run_module(Abusech, "url:http://malware-host.example.com/x", http)
    assert res.status is Status.NEEDS_KEY and res.error == mod.NO_KEY_LINE
    assert http.calls == []
    assert {s["reason"] for s in res.source_statuses.values()} == {mod.NO_KEY_LINE}
    hosts = {link[1].split("/")[2] for link in res.links}
    assert hosts == {"urlhaus.abuse.ch", "threatfox.abuse.ch"}


def test_without_key_the_open_feeds_still_run():
    install("ip_blocklists.feodo.json", fx("feodo_ipblocklist.json"))
    res = run_module(Abusech, "ipv4:50.16.16.211", FakeHttp())
    assert res.status is Status.OK
    finding = next(f for f in res.findings if f.title == "Listed on Feodo Tracker (botnet C2)")
    assert finding.source == "abusech.feodotracker" and {"c2", "malicious"} <= set(finding.tags)
    assert res.attributes["blocklists"] == ["Feodo Tracker"]
    assert res.source_statuses["abusech.urlhaus"]["status"] == "needs_key"
    assert "QakBot" in pivots(res, T.MALWARE)
    assert any(d["name"] == mod.FEODO_DATASET for d in res.datasets)


# ------------------------------------------------------------------ licence gate (cond 2)
def test_licence_blocked_sources_are_never_queried():
    open_only = ("abusech.feodotracker", "abusech.sslbl")
    http = FakeHttp()
    res = run_module(Abusech, "url:http://malware-host.example.com/x", http, keys=KEYS, allowed_sources=open_only)
    assert res.status is Status.SKIPPED and res.reason_code == "licence"
    assert http.calls == [] and res.links
    install("ip_blocklists.feodo.json", fx("feodo_ipblocklist.json"))
    res = run_module(Abusech, "ipv4:8.8.8.8", http, keys=KEYS, allowed_sources=open_only)
    assert res.status is Status.EMPTY and http.calls == []  # Feodo answered: not listed


# ------------------------------------------------------------------ URLhaus (cond 7)
def test_urlhaus_url_online_is_high_with_host_and_payload_pivots():
    http = (FakeHttp().add("POST", URLHAUS + "url/", json=fx("urlhaus_url_ok_docs.json"))
            .add("POST", THREATFOX, json=fx("threatfox_no_result_docs.json")))
    target = "http://malware-host.example.com/VMYB-ht_JAQo-gi/INV/Outstanding-Invoices/"
    res = run_module(Abusech, f"url:{target}", http, keys=KEYS)
    assert res.status is Status.OK
    finding = next(f for f in res.findings if f.title == "Listed on URLhaus (malware URL)")
    assert finding.severity.label == "high" and {"malware", "malicious"} <= set(finding.tags)
    assert finding.data["status"] == ["online"] and finding.source == "abusech.urlhaus"
    assert pivots(res, T.DOMAIN) == {"malware-host.example.com"}
    assert {"dc9f3b226bccb2f1fd4810cde541e5a10d59a1fe683f4a9462293b6ade8d8403", "01fa56184fcaa42b6ee1882787a34098c79898c182814774fd81dc18a6af0b00"} <= pivots(res, T.SHA256)
    assert "Heodo" in pivots(res, T.MALWARE)
    assert res.source_statuses["abusech.threatfox"]["status"] == "empty"
    raw = json.dumps(res.to_dict())
    assert "urlhaus-api.abuse.ch/v1/download" not in raw and "reporter_a" not in raw


def test_urlhaus_host_with_offline_history_is_low_historical():
    data = fx("urlhaus_host_ok_docs.json")
    for rec in data["urls"]:
        rec["url_status"] = "offline"
    http = FakeHttp().add("POST", URLHAUS + "host/", json=data).add("POST", THREATFOX, json=fx("threatfox_no_result_docs.json"))
    res = run_module(Abusech, "domain:vektorex.example.net", http, keys=KEYS)
    finding = next(f for f in res.findings if f.title == "Listed on URLhaus (malware host)")
    assert finding.severity.label == "low" and "historical" in finding.tags  # listed 2019, offline > 90 days
    assert {"http://vektorex.example.net/source/Z/5016223.exe"} <= pivots(res, T.URL)
    assert all(p.expand is False for p in res.pivots if p.entity.type is T.URL)


def test_urlhaus_host_online_is_high():
    http = FakeHttp().add("POST", URLHAUS + "host/", json=fx("urlhaus_host_ok_docs.json")).add("POST", THREATFOX, json=fx("threatfox_no_result_docs.json"))
    res = run_module(Abusech, "domain:vektorex.example.net", http, keys=KEYS)
    assert next(f for f in res.findings if f.title == "Listed on URLhaus (malware host)").severity.label == "high"


def test_abused_legitimate_service_is_info_never_malicious():
    data = fx("urlhaus_host_ok_docs.json")
    data["host"] = "drive.google.com"
    for rec in data["urls"]:
        rec["url"] = rec["url"].replace("vektorex.example.net", "drive.google.com")
    http = FakeHttp().add("POST", URLHAUS + "host/", json=data).add("POST", THREATFOX, json=fx("threatfox_no_result_docs.json"))
    res = run_module(Abusech, "domain:drive.google.com", http, keys=KEYS)
    assert [f.severity.label for f in res.findings] == ["info"]
    assert "abused_legit_service" in res.findings[0].tags
    assert not any("malicious" in f.tags for f in res.findings) and "malicious" not in res.attributes


def test_urlhaus_payload_lookup():
    http = (FakeHttp().add("POST", URLHAUS + "payload/", json=fx("urlhaus_payload_ok_docs.json"))
            .add("POST", THREATFOX, json=fx("threatfox_no_result_docs.json"))
            .add("POST", BAZAAR, json=fx("mb_hash_not_found_docs.json")))
    res = run_module(Abusech, "md5:1585ad28f7d1e0ca696e6c6c2f1d008a", http, keys=KEYS)
    finding = next(f for f in res.findings if f.title == "Payload listed on URLhaus")
    assert finding.severity.label == "high" and finding.data["family"] == "Heodo"
    assert "35e304d10d53834e3e41035d12122773c9a4d183a24e03f980ad3e6b2ecde7fa" in pivots(res, T.SHA256)
    assert {"http://www.compromised-site.example.org/bn/wp-content/PaymentStatus/"} <= pivots(res, T.URL)
    assert res.source_statuses["abusech.malwarebazaar"]["status"] == "empty"


def test_severity_rules():
    import datetime as dt

    now = dt.datetime(2026, 11, 26, tzinfo=dt.timezone.utc)
    assert mod.urlhaus_severity("online", None, None, now)["severity"] == "high"
    assert mod.urlhaus_severity("offline", "2026-11-10", None, now)["severity"] == "high"
    assert mod.urlhaus_severity("offline", "2026-09-26", None, now)["severity"] == "medium"
    old = mod.urlhaus_severity("offline", "2026-06-01", None, now)
    assert old["severity"] == "low" and old["label"] == "historical"
    assert mod.urlhaus_severity("online", None, None, now, legit="saas service")["severity"] == "info"
    assert mod.threatfox_label(25)["label"] == "suspicious" and mod.threatfox_label(50)["label"] == "malicious"
    assert mod.threatfox_label(None)["label"] == "suspicious"


# ------------------------------------------------------------------ ThreatFox (cond 7/8)
def test_threatfox_ip_port_listing():
    install("ip_blocklists.feodo.json", fx("feodo_ipblocklist.json"))
    data = fx("threatfox_search_ioc_ok_docs.json")
    data["data"][0]["first_seen"] = "2026-11-20 09:10:23 UTC"
    http = FakeHttp().add("POST", URLHAUS + "host/", json=fx("urlhaus_no_results_docs.json")).add("POST", THREATFOX, json=data)
    res = run_module(Abusech, "ipv4:203.0.113.104", http, keys=KEYS)
    assert res.status is Status.OK
    finding = next(f for f in res.findings if f.title == "Listed on ThreatFox")
    assert finding.severity.label == "high" and {"c2", "malicious"} <= set(finding.tags)
    assert finding.data["family_ids"] == ["win.cobalt_strike"] and res.attributes["source_confidence"] == 75
    assert "Cobalt Strike" in pivots(res, T.MALWARE)
    assert "b325c92fa540edeb89b95dbfd4400c1cb33599c66859a87aead820e568a2ebe7" in pivots(res, T.SHA256)
    assert res.source_statuses["abusech.feodotracker"]["status"] == "empty"


def test_threatfox_low_confidence_is_suspicious():
    data = fx("threatfox_search_hash_ok_docs.json")
    data["data"] = [data["data"][1]]  # confidence 25
    data["data"][0]["ioc"] = "c2-domain.example.org"
    http = FakeHttp().add("POST", URLHAUS + "host/", json=fx("urlhaus_no_results_docs.json")).add("POST", THREATFOX, json=data)
    res = run_module(Abusech, "domain:c2-domain.example.org", http, keys=KEYS)
    finding = next(f for f in res.findings if f.title == "Listed on ThreatFox")
    assert "suspicious" in finding.tags and "malicious" not in finding.tags
    assert str(finding.confidence_label.value) == "possible"
    assert res.attributes["suspicious"] is True


def test_threatfox_sample_iocs_are_communicates_with_pivots():
    http = (FakeHttp().add("POST", URLHAUS + "payload/", json=fx("urlhaus_no_results_docs.json"))
            .add("POST", THREATFOX, json=fx("threatfox_search_hash_ok_docs.json"))
            .add("POST", BAZAAR, json=fx("mb_hash_not_found_docs.json")))
    res = run_module(Abusech, f"sha256:{EICAR_SHA256}", http, keys=KEYS)
    finding = next(f for f in res.findings if f.title == "Sample with ThreatFox IOCs")
    assert finding.data["records"] == 2
    comms = {p.entity.value for p in res.pivots if p.relation == "communicates_with"}
    assert comms == {"http://c2.example.org:3606/is-ready", "c2-domain.example.org"}
    assert {"Houdini", "Dridex"} <= pivots(res, T.MALWARE)


# ------------------------------------------------------------------ MalwareBazaar
def test_malwarebazaar_get_info_keeps_metadata_only():
    http = (FakeHttp().add("POST", BAZAAR, json=fx("mb_get_info_synthetic.json")))
    res = run_module(Abusech, "sha1:eb0e81598d8526d88cac4695a3e9360cc8fbb331", http, keys=KEYS)
    assert res.status is Status.OK and res.requests == 1  # SHA-1: MalwareBazaar only
    finding = next(f for f in res.findings if f.title == "Known malware sample on MalwareBazaar")
    assert finding.severity.label == "high" and finding.data["family"] == "Adwind"
    assert res.attributes["yara_rules"] == ["Adwind_JAR"] and res.attributes["av_signatures"] == ["Win.Trojan.Adwind-1"]
    assert pivots(res, T.SHA256) == {"094fd325049b8a9cf6d3e5ef2a6d4cc6a567d7d49c35f8bb8dd9e3c6acf3d78d"}
    assert pivots(res, T.TLSH) and pivots(res, T.SSDEEP)
    assert pivots(res, T.IPV4) == {"203.0.113.50"}  # vendor C2, hostile
    raw = json.dumps(res.to_dict()) + json.dumps([f.to_dict() for f in res.findings])
    for dropped in ("example_handle", "Example Analyst", "reporter_a", "x.com/example", "file_information"):
        assert dropped not in raw


# ------------------------------------------------------------------ status mapping per platform
def test_401_with_a_key_is_needs_key():
    http = (FakeHttp().add("POST", URLHAUS + "url/", status=401, json=fx("api_no_key_401.json"))
            .add("POST", THREATFOX, status=401, json=fx("api_no_key_401.json")))
    res = run_module(Abusech, "url:http://malware-host.example.com/x", http, keys=KEYS)
    assert res.status is Status.NEEDS_KEY and res.reason_code == "needs_key"
    assert "rejected" in res.error


def test_one_platform_failing_while_the_others_answer():
    http = (FakeHttp().add("POST", URLHAUS + "url/", status=503, text="maintenance", times=2)
            .add("POST", THREATFOX, json=fx("threatfox_no_result_docs.json")))
    res = run_module(Abusech, "url:http://malware-host.example.com/x", http, keys=KEYS)
    assert res.status is Status.EMPTY  # ThreatFox answered; URLhaus is listed as could-not-verify
    assert res.source_statuses["abusech.urlhaus"]["status"] == "error"
    assert res.source_statuses["abusech.threatfox"]["status"] == "empty"


def test_a_429_backs_off_the_whole_provider():
    http = (FakeHttp().add("POST", URLHAUS + "url/", status=429, text="slow down")
            .add("POST", THREATFOX, json=fx("threatfox_no_result_docs.json")))
    res = run_module(Abusech, "url:http://malware-host.example.com/x", http, keys=KEYS)
    assert res.status is Status.RATE_LIMITED  # the core backs off every abuse.ch host after a 429
    assert {s["status"] for s in res.source_statuses.values()} == {"rate_limited"}


def test_all_platforms_rate_limited_is_rate_limited():
    http = (FakeHttp().add("POST", URLHAUS + "url/", status=429, text="slow down").add("POST", THREATFOX, status=429, text="slow down"))
    res = run_module(Abusech, "url:http://malware-host.example.com/x", http, keys=KEYS)
    assert res.status is Status.RATE_LIMITED and res.reason_code == "rate_limited"


def test_5xx_and_timeouts_are_errors():
    http = (FakeHttp().add("POST", URLHAUS + "url/", status=500, text="error", times=2)
            .add("POST", THREATFOX, error=NetworkError("ReadTimeout contacting threatfox-api.abuse.ch", reason_code="timeout", retryable=False)))
    res = run_module(Abusech, "url:http://malware-host.example.com/x", http, keys=KEYS)
    assert res.status is Status.ERROR
    assert res.source_statuses["abusech.threatfox"]["reason_code"] == "timeout"


def test_error_and_input_problems_inside_http_200():
    http = (FakeHttp().add("POST", URLHAUS + "host/", json=fx("urlhaus_invalid_host_docs.json"))
            .add("POST", THREATFOX, json=fx("threatfox_illegal_search_term_docs.json")))
    res = run_module(Abusech, "domain:example.com", http, keys=KEYS)
    assert res.status is Status.SKIPPED and res.reason_code == "not_applicable"
    http = (FakeHttp().add("POST", URLHAUS + "host/", json={"query_status": "user_blacklisted"})
            .add("POST", THREATFOX, json={"query_status": "server_error"}))
    res = run_module(Abusech, "domain:example.com", http, keys=KEYS)
    assert res.status is Status.ERROR and "could not verify" in res.error


def test_malformed_json_is_never_empty():
    http = (FakeHttp().add("POST", URLHAUS + "host/", text="<html><body>maintenance</body></html>")
            .add("POST", THREATFOX, body=b'{"query_status": "ok", "data": ['))
    res = run_module(Abusech, "domain:example.com", http, keys=KEYS)
    assert res.status is Status.ERROR and not res.findings


def test_legacy_410_is_recognised_and_never_used():
    assert mod.legacy_export_gone(fx("legacy_export_410.txt"))
    assert not mod.legacy_export_gone("ok")


# ------------------------------------------------------------------ SSLBL and Feodo (local, open)
def test_sslbl_certificate_listing():
    install("ip_blocklists.sslbl.csv", fx("sslbl_sha1.csv"))
    res = run_module(Abusech, "cert_fingerprint:3ec4de7981b35b599489e6131411bfab779a3993", FakeHttp())
    finding = next(f for f in res.findings if f.title == "Certificate listed on SSLBL")
    assert finding.severity.label == "high" and finding.data["family"] == "Vidar"
    assert "Vidar" in pivots(res, T.MALWARE)
    res = run_module(Abusech, "cert_fingerprint:0000000000000000000000000000000000000000", FakeHttp())
    assert res.status is Status.EMPTY


def test_sslbl_parser_completeness_and_zero_rows():
    complete = mod.parse_sslbl(fx("sslbl_sha1.csv"))
    assert complete["complete"] and len(complete["rows"]) == 6 and complete["meta"]["last_updated"] == "2026-11-25T18:28:00Z"
    truncated = mod.parse_sslbl(fx("sslbl_sha1_truncated.csv"))
    assert not truncated["complete"] and len(truncated["rows"]) == 3
    deprecated = mod.parse_sslbl(fx("sslbl_ip_deprecated_0_rows.csv"))
    assert deprecated["rows"] == {} and deprecated["meta"]["deprecated"] == "2025-01-03"


def test_sslbl_zero_row_copy_is_unhealthy_never_empty():
    install("ip_blocklists.sslbl.csv", fx("sslbl_ip_deprecated_0_rows.csv"))
    res = run_module(Abusech, "cert_fingerprint:3ec4de7981b35b599489e6131411bfab779a3993", FakeHttp())
    assert res.status is Status.ERROR and "unhealthy" in res.error


def test_missing_local_feed_is_unavailable_dataset():
    res = run_module(Abusech, "cert_fingerprint:3ec4de7981b35b599489e6131411bfab779a3993", FakeHttp())
    assert res.status is Status.UNAVAILABLE and res.reason_code == "dataset" and f"v3lum data update {mod.SSLBL_DATASET}" in res.error


def test_feodo_historical_listing_is_low():
    install("ip_blocklists.feodo.json", fx("feodo_ipblocklist.json"))
    res = run_module(Abusech, "ipv4:162.243.103.246", FakeHttp())  # offline, last online 2026-03-07
    finding = next(f for f in res.findings if f.title == "Listed on Feodo Tracker (botnet C2)")
    assert finding.severity.label == "low" and "historical" in finding.tags


def test_dataset_download_validates_and_keeps_the_previous_copy():
    good, empty = fx("sslbl_sha1.csv"), fx("sslbl_ip_deprecated_0_rows.csv")
    assert mod._sslbl_valid(_write_tmp("good.csv", good)) and not mod._sslbl_valid(_write_tmp("empty.csv", empty))
    install(mod.SSLBL_DATASET, good)  # the copy `v3lum data update` installed earlier
    http = FakeHttp().add("GET", "https://sslbl.abuse.ch/blacklist/sslblacklist.csv", text=empty, headers={"content-type": "text/csv"})
    result = make_runtime(http).data.update(mod.SSLBL_DATASET)  # whichever batch registered the shared entry last
    assert result.status == "failed"
    assert "Vidar" in (paths.datasets_dir() / mod.SSLBL_DATASET).read_text()  # the previous copy is kept


def _write_tmp(name, content):
    path = paths.datasets_dir() / f".test-{name}"
    path.write_text(content, encoding="utf-8")
    return path


# ------------------------------------------------------------------ cond 6: bulk lists use the exports
def test_pasted_list_beyond_the_threshold_uses_exports_not_api_calls():
    http = FakeHttp().add("POST", URLHAUS + "host/", json=fx("urlhaus_no_results_docs.json"), times=2)
    http.add("POST", THREATFOX, json=fx("threatfox_no_result_docs.json"), times=2)
    parent = [("text_blob:paste-1", "mentions", "ioc_extract")]
    settings = {"abusech_bulk_threshold": 2}
    for i in range(1, 3):  # the first two IOCs of the paste use the API
        res = run_module(Abusech, f"domain:host{i}.example.com", http, keys=KEYS, settings=settings, case_id="case-bulk", is_seed=False, provenance=parent)
        assert res.status is Status.EMPTY
    calls = len(http.calls)
    res = run_module(Abusech, "domain:host3.example.com", http, keys=KEYS, settings=settings, case_id="case-bulk", is_seed=False, provenance=parent)
    assert len(http.calls) == calls  # no API call for the third IOC
    assert res.status is Status.UNAVAILABLE and res.reason_code == "dataset"
    assert "terms s.7.3" in res.source_statuses["abusech.urlhaus"]["reason"]
    install("abusech_threatfox_recent.csv", fx("threatfox_export_recent_synthetic.csv"))
    res = run_module(Abusech, "domain:c2-panel.example.net", http, keys=KEYS, settings=settings, case_id="case-bulk", is_seed=False, provenance=parent)
    assert len(http.calls) == calls
    finding = next(f for f in res.findings if f.title == "Listed in the ThreatFox export")
    assert finding.data["family"] == "Vidar" and "suspicious" in finding.tags  # confidence 25


def test_export_parsers():
    urlhaus = mod.parse_export(fx("urlhaus_export_recent_synthetic.csv"), "urlhaus")
    assert urlhaus["url:http://198.51.100.23:40135/i"][0]["status"] == "online"
    threatfox = mod.parse_export(fx("threatfox_export_recent_synthetic.csv"), "threatfox")
    assert threatfox["ipv4:203.0.113.9"][0]["family"] == "Cobalt Strike"
    bazaar = mod.parse_export(fx("mb_export_recent_synthetic.csv"), "malwarebazaar")
    assert bazaar[f"sha256:{EICAR_SHA256}"][0]["family"] == "ExampleFamily"
    assert bazaar["md5:44d88612fea8a8f36de82e1278abb02f"] and bazaar["sha1:3395856ce81f2b7382dee72602f798b642f14140"]


# ------------------------------------------------------------------ cond 3: the key never leaks
def test_export_template_and_key_redaction():
    assert mod.EXPORT_TEMPLATES["urlhaus"] == "https://urlhaus-api.abuse.ch/v2/files/exports/{AUTH_KEY}/recent.csv"
    make_runtime(FakeHttp(), keys=KEYS)  # the runtime registers configured keys with the redactor (AR01)
    url = mod.export_url("urlhaus", KEY)
    assert KEY in url and KEY not in redact.redact_url(url)
    with pytest.raises(mod.QueryRefused):
        mod.export_url("urlhaus", "bad key with spaces")


def test_key_never_reaches_the_result():
    http = (FakeHttp().add("POST", URLHAUS + "url/", status=500, text=f"debug: Auth-Key {KEY}")
            .add("POST", THREATFOX, json=fx("threatfox_no_result_docs.json")))
    res = run_module(Abusech, "url:http://malware-host.example.com/x", http, keys=KEYS)
    assert_no_secret(KEY, res.to_dict(), res.error, res.source_statuses)


def test_family_queries_are_bounded():
    data = fx("threatfox_search_ioc_ok_docs.json")
    http = FakeHttp().add("POST", THREATFOX, json=data).add("POST", BAZAAR, json=fx("mb_get_info_synthetic.json"))
    res = run_module(Abusech, "malware_family:Cobalt Strike", http, keys=KEYS)
    assert res.status is Status.OK
    bodies = [body for _url, body in sent_queries(http)]
    assert any('"limit": 25' in b for b in bodies) and any("limit=25" in b for b in bodies)
    assert all(p.expand is False for p in res.pivots)


def test_entity_types_and_plans():
    allowed = set(mod.SOURCES.values())
    assert [r.query for r in mod.plan(Entity.make("ipv4", "8.8.8.8"), allowed)] == ["host", "search_ioc"]
    assert [r.query for r in mod.plan(Entity.make("sha1", "3395856ce81f2b7382dee72602f798b642f14140"), allowed)] == ["get_info"]
    assert mod.plan(Entity.make("cert_fingerprint", "3395856ce81f2b7382dee72602f798b642f14140"), allowed) == []
