"""cisa_kev (P182): offline lookups in the local CISA KEV catalogue.

Fixtures in tests/fixtures/cisa_kev/ (prep batch p1-G08-1, recorded 2026-11-26 from www.cisa.gov):
``catalog_ok.json`` (4 real entries of catalogue 2026.11.25, ``count`` rewritten to 4: Log4Shell with
knownRansomwareCampaignUse 'Known', Heartbleed, two 2026-11-25 additions with forensicTriage 'Yes'),
``access_denied_403.http.json`` (the real Akamai 'Access Denied' page CISA serves for a missing feed
path, reference id zeroed), ``not_modified_304.http.json`` (the real conditional-GET answer) and
``truncated_206.txt`` (the first 900 bytes of a research range download).
"""

from __future__ import annotations

import json

import pytest

from tests.fakes import FIXTURES, FakeClock, FakeHttp, make_ctx, make_runtime, module_fixture, run_module
from v3lum import paths
from v3lum.core.datasets import DATASETS
from v3lum.core.entities import EntityType as T
from v3lum.core.models import Status
from v3lum.modules.vulnerability_cve import cisa_kev as kev_mod
from v3lum.modules.vulnerability_cve.cisa_kev import (
    KEV_DATASET,
    KEV_FEED_URL,
    CisaKev,
    check_kev_document,
    kev_search,
    parse_kev_catalog,
    validate_kev_catalog,
)

CATALOG = module_fixture(CisaKev, "catalog_ok.json")
ETAG = '"1cf6ca-6611f1b6e2660"'
LAST_MODIFIED = "Wed, 25 Nov 2026 19:48:12 GMT"


@pytest.fixture(autouse=True)
def small_catalog(monkeypatch):
    """The trimmed fixture holds 4 entries: lower the completeness floors for the download tests (the
    real floors are tested below on a full-size synthetic catalogue)."""
    monkeypatch.setitem(DATASETS[KEV_DATASET], "min_bytes", 100)
    monkeypatch.setattr(kev_mod, "KEV_MIN_ENTRIES", 1)


def kev_http(times: int | None = None) -> FakeHttp:
    return FakeHttp().add("GET", KEV_FEED_URL, json=CATALOG, headers={"ETag": ETAG, "Last-Modified": LAST_MODIFIED}, times=times)


def runtime(http: FakeHttp, **kw):
    clock = FakeClock()
    return make_runtime(http, clock=clock, **kw), clock


def exchange(name: str) -> dict:
    return module_fixture(CisaKev, name)["response"]


# ------------------------------------------------------------------ metadata (P182 council values)
def test_metadata_is_offline_tlp_red_safe_and_default():
    cls = CisaKev
    assert (cls.disclosure, cls.hosts, cls.provider, cls.sources) == ("none", (), "", ("cisa.kev",))
    assert cls.terms == "open" and cls.default_enabled is True and cls.opsec.label == "passive"
    assert cls.trust_tier == "n/a" and cls.shares_input is False and cls.max_requests == 0
    assert cls.max_tlp.value_str == "red"  # disclosure none: TLP:RED-safe
    assert {T.CVE, T.KEYWORD} == set(cls.accepts) and not cls.produces
    reg = DATASETS[KEV_DATASET]
    assert reg["url"] == KEV_FEED_URL and reg["ttl"] == 6 * 3600 and reg["source"] == "cisa.kev"
    assert reg["terms_class"] == "open" and "public domain" in reg["licence"] and reg["essential"] and reg["large"] is False


# ------------------------------------------------------------------ listed CVEs (cond 1, 2)
def test_listed_cve_gets_kev_facts_without_any_request():
    http = kev_http()
    res = run_module(CisaKev, "cve:CVE-2021-44228", http)
    assert res.status is Status.OK
    a = res.attributes
    assert a["kev"] is True
    assert (a["kev_date_added"], a["kev_due_date"]) == ("2021-12-10", "2021-12-24")
    assert (a["kev_vendor"], a["kev_product"]) == ("Apache", "Log4j2")
    assert a["kev_ransomware_use"] == "Known" and a["kev_ransomware_known"] is True  # its own flag (cond 2)
    assert a["cwe"] == ["CWE-20", "CWE-400", "CWE-502"]
    assert a["kev_catalog_version"] == "2026.11.25"
    assert a["kev_status"].startswith("in CISA KEV since 2021-12-10") and "known ransomware use" in a["kev_status"]
    assert not res.findings and not res.pivots  # facts for the CVE card, never a severity (CR15 decides, cond 3)
    assert res.requests == 0 and http.urls() == [KEV_FEED_URL]  # one bulk download, zero per-CVE requests
    assert [d["name"] for d in res.datasets] == [KEV_DATASET]  # cited: name, sha256, fetched_at (coverage)
    assert res.datasets[0]["sha256"] and res.datasets[0]["fetched_at"]
    assert ("CISA KEV catalogue entry", "https://www.cisa.gov/known-exploited-vulnerabilities-catalog?field_cve=CVE-2021-44228") in res.links


def test_unknown_ransomware_use_sets_no_flag_and_triage_flag():
    http = kev_http(times=1)
    rt, _clock = runtime(http)
    heartbleed = run_module(CisaKev, "cve:CVE-2014-0160", runtime=rt)
    assert heartbleed.attributes["kev_ransomware_use"] == "Unknown"
    assert "kev_ransomware_known" not in heartbleed.attributes
    juniper = run_module(CisaKev, "cve:CVE-2026-103406", runtime=rt)  # served from the local copy
    assert juniper.attributes["kev_forensic_triage"] is True
    assert any("supportportal.juniper.net" in u for u in juniper.attributes["kev_references"])
    assert len(http.calls) == 1


def test_not_in_kev_never_reads_not_exploited():
    res = run_module(CisaKev, "cve:CVE-2023-0001", kev_http())
    assert res.status is Status.EMPTY  # the dataset answered: CISA has not listed it
    status = res.attributes["kev_status"]
    assert status.startswith("not in CISA KEV (catalog 2026.11.25")
    assert "absence is no evidence either way" in status
    for forbidden in ("not exploited", "unexploited", "no exploitation", "safe", "clean"):
        assert forbidden not in status.lower()
    assert "kev" not in res.attributes  # never kev=False: absence is not a fact about exploitation


# ------------------------------------------------------------------ dataset manager behaviour (AR10)
def test_conditional_get_304_keeps_the_copy_and_refreshes_its_age():
    not_modified = exchange("not_modified_304.http.json")
    http = kev_http(times=1).add(
        "GET", KEV_FEED_URL, status=not_modified["status"], headers=not_modified["headers"], match_headers={"If-None-Match": ETAG}
    )
    rt, clock = runtime(http)
    assert run_module(CisaKev, "cve:CVE-2021-44228", runtime=rt).status is Status.OK
    clock.advance(7 * 3600)  # past the 6 h TTL: a conditional GET, answered 304
    res = run_module(CisaKev, "cve:CVE-2021-44228", runtime=rt)
    assert res.status is Status.OK and res.attributes["kev"] is True
    assert len(http.calls) == 2 and http.calls[1]["headers"].get("If-None-Match") == ETAG
    assert rt.data.info(KEV_DATASET).age_hours == 0.0  # fetched_at refreshed by the 304


def test_akamai_403_without_a_copy_is_could_not_verify():
    page = exchange("access_denied_403.http.json")
    http = FakeHttp().add("GET", KEV_FEED_URL, status=page["status"], text=page["body"], headers=page["headers"])
    res = run_module(CisaKev, "cve:CVE-2021-44228", http)
    assert res.status is Status.BLOCKED and res.reason_code in ("challenge", "geo_block")  # the core picks the code (P321)
    assert "could not verify" in res.error and "v3lum data update cisa_kev" in res.error
    assert "kev" not in res.attributes and "kev_status" not in res.attributes


def test_failed_refresh_serves_the_previous_copy():
    page = exchange("access_denied_403.http.json")
    http = kev_http(times=1).add("GET", KEV_FEED_URL, status=403, text=page["body"])
    rt, clock = runtime(http)
    run_module(CisaKev, "cve:CVE-2021-44228", runtime=rt)
    clock.advance(7 * 3600)
    res = run_module(CisaKev, "cve:CVE-2021-44228", runtime=rt)
    assert res.status is Status.OK and res.attributes["kev"] is True  # stale copy kept, never replaced by the page
    assert rt.data.info(KEV_DATASET).stale is True


def test_truncated_download_is_rejected_never_empty():
    truncated = (FIXTURES / "cisa_kev" / "truncated_206.txt").read_text(encoding="utf-8")
    http = FakeHttp().add("GET", KEV_FEED_URL, text=truncated, headers={"content-type": "application/json"})
    res = run_module(CisaKev, "cve:CVE-2021-44228", http)
    assert res.status is Status.ERROR and "could not verify" in res.error
    assert not (paths.datasets_dir() / KEV_DATASET).exists()  # the truncated body never became the copy
    assert "kev_status" not in res.attributes


def test_offline_without_a_copy_is_unavailable_dataset():
    rt = make_runtime(FakeHttp(), offline=True)
    res = run_module(CisaKev, "cve:CVE-2021-44228", runtime=rt)
    assert res.status is Status.UNAVAILABLE and res.reason_code == "dataset"


def test_tlp_red_still_answers_offline():
    res = run_module(CisaKev, "cve:CVE-2021-44228", kev_http(), tlp="red")
    assert res.status is Status.OK and res.attributes["kev"] is True


# ------------------------------------------------------------------ validation with the real floors
def test_validator_with_real_floors(tmp_path, monkeypatch):
    monkeypatch.setattr(kev_mod, "KEV_MIN_ENTRIES", 1000)
    small = tmp_path / "small.json"
    small.write_text(json.dumps(CATALOG), encoding="utf-8")
    with pytest.raises(ValueError, match="only 4 valid KEV entries"):
        validate_kev_catalog(small)
    template = CATALOG["vulnerabilities"][0]
    full = dict(CATALOG, count=1200, vulnerabilities=[dict(template, cveID=f"CVE-2099-{10000 + n}") for n in range(1, 1201)])
    good = tmp_path / "full.json"
    good.write_text(json.dumps(full), encoding="utf-8")
    assert validate_kev_catalog(good) is True
    assert "partial download" in check_kev_document(dict(full, count=1805))
    assert "without catalogVersion" in check_kev_document(dict(full, catalogVersion=""))
    assert "no vulnerabilities list" in check_kev_document({"title": "x"})
    broken = tmp_path / "broken.json"
    broken.write_text((FIXTURES / "cisa_kev" / "truncated_206.txt").read_text(encoding="utf-8"), encoding="utf-8")
    with pytest.raises(ValueError, match="not valid JSON"):
        validate_kev_catalog(broken)


def test_parser_is_defensive():
    doc = {"catalogVersion": "x", "vulnerabilities": [None, 3, {"cveID": "CVE-INVALID"}, {"cveID": "cve-2021-44228", "cwes": "CWE-1", "notes": 5},
                                                      {"cveID": "CVE-2021-44228", "notes": "see https://vendor.example/a@b.example/x ; https://vendor.example/advisory"}]}
    parsed = parse_kev_catalog(doc)
    assert parsed["skipped"] == 3 and list(parsed["entries"]) == ["CVE-2021-44228"]
    entry = parsed["entries"]["CVE-2021-44228"]
    assert entry["references"] == ["https://vendor.example/advisory"]  # no address embedded in a kept URL
    assert parse_kev_catalog("not a dict") == {"meta": {}, "entries": {}, "skipped": 0}


# ------------------------------------------------------------------ keyword input: local search only
def test_keyword_search_is_local():
    http = kev_http(times=1)
    rt, _clock = runtime(http)
    res = run_module(CisaKev, "keyword:log4j2", runtime=rt)
    assert res.status is Status.OK and res.requests == 0
    hits = res.attributes["kev_search_hits"]
    assert [h["cve"] for h in hits] == ["CVE-2021-44228"] and hits[0]["ransomware_use"] == "Known"
    newest = run_module(CisaKev, "keyword:Session Smart", runtime=rt).attributes["kev_search_hits"]
    assert newest[0]["cve"] == "CVE-2026-103406"
    assert run_module(CisaKev, "keyword:no such vendor anywhere", runtime=rt).status is Status.EMPTY
    assert run_module(CisaKev, "keyword:ab", runtime=rt).status is Status.SKIPPED
    assert len(http.calls) == 1  # only the bulk download
    entries = parse_kev_catalog(CATALOG)["entries"]
    assert [e["cve"] for e in kev_search(entries, "openssl information")] == ["CVE-2014-0160"]


# ------------------------------------------------------------------ doctor: copy older than 48 h (cond 4)
def test_health_selftest_flags_a_copy_older_than_48_hours():
    http = kev_http(times=1)
    rt, clock = runtime(http)
    check = CisaKev.health_check()
    assert check.offline is True and callable(check.selftest)
    missing = check.selftest(make_ctx(CisaKev, runtime=rt))
    assert missing.status == "dead" and "not downloaded" in missing.detail
    run_module(CisaKev, "cve:CVE-2021-44228", runtime=rt)
    assert check.selftest(make_ctx(CisaKev, runtime=rt)).status == "ok"
    clock.advance(49 * 3600)
    stale = check.selftest(make_ctx(CisaKev, runtime=rt))
    assert stale.status == "dead" and "> 48 h" in stale.detail and "v3lum data update cisa_kev" in stale.detail
