"""cisa_advisories (P374): CISA advisories feed + curated STIX IOC files, matched locally.

Fixtures in tests/fixtures/cisa_advisories/: ``feed_real_trimmed.xml`` is the REAL advisories feed
captured 2026-11-26 through the dataset manager (4 of 30 items, descriptions cut); ``blocked_akamai_403.http.json``
is the REAL Akamai 'Access Denied' answer the same host gives curl's default client and every advisory
page. An advisory page and a STIX IOC file need the team network (P374 cond 1, batch backlog), so
``feed_synthetic.xml`` (a #StopRansomware item, absent from the current real feed) and
``stix_synthetic.json`` / ``stix_invalid_synthetic.json`` reproduce the documented shapes with fictional
AA99-* advisories and documentation values only.
"""

from __future__ import annotations

import subprocess

import pytest

from tests.fakes import FIXTURES, FakeClock, FakeHttp, make_runtime, module_fixture, run_module
from v3lum.core.datasets import DATASETS
from v3lum.core.entities import EntityType as T
from v3lum.core.links import validate_manual_link
from v3lum.core.models import Severity, Status
from v3lum.modules.cti_framework import cisa_advisories as mod
from v3lum.modules.cti_framework.cisa_advisories import (
    FEED_DATASET,
    FEED_URL,
    IOC_SOURCE,
    CisaAdvisories,
    advisory_id,
    family_from_title,
    ioc_tags,
    parse_advisories,
    stix_check,
    stix_summary,
)

FX = FIXTURES / "cisa_advisories"
FEED = (FX / "feed_synthetic.xml").read_text(encoding="utf-8")
STIX = module_fixture(CisaAdvisories, "stix_synthetic.json")
IOC_URL = "https://www.cisa.gov/sites/default/files/2026-09/aa99-001a-stix.json"


def feed_http(body: str = FEED) -> FakeHttp:
    return FakeHttp().add("GET", FEED_URL, text=body, headers={"Content-Type": "application/rss+xml", "ETag": '"feed-1"'})


@pytest.fixture
def ioc_file(monkeypatch, clean_registry):
    entry = {"advisory_id": "AA99-001A", "url": IOC_URL, "published": "2026-09-01"}
    mod.register_ioc_file(entry)
    monkeypatch.setattr(mod, "IOC_FILE_ENTRIES", [entry])
    mod._MEMO.clear()
    return entry


# ------------------------------------------------------------------ metadata (council values)
def test_metadata_matches_the_council_decision():
    cls = CisaAdvisories
    assert cls.default_enabled is True and cls.terms == "open" and cls.disclosure == "none" and cls.hosts == ()
    assert cls.sources == ("cisa.advisories", "cisa.advisories_ioc") and cls.max_requests == 0
    assert validate_manual_link(cls.manual_link) == []  # A9: the manual advisory search
    reg = DATASETS[FEED_DATASET]
    assert reg["ttl"] == 86400 and reg["terms_class"] == "open" and "public domain" in reg["licence"]
    assert mod.IOC_FILE_ENTRIES == []  # nothing guessed: the curated list is empty until captured (FC1)


# ------------------------------------------------------------------ FC1/FC2: the real Akamai block
def test_akamai_block_is_could_not_verify_never_no_advisory():
    cap = module_fixture(CisaAdvisories, "blocked_akamai_403.http.json")
    http = FakeHttp().add("GET", FEED_URL, status=cap["status"], text=cap["body"], headers=cap["headers"])
    res = run_module(CisaAdvisories, "malware_family:Akira", http)
    assert res.status is Status.BLOCKED and res.reason_code in ("geo_block", "challenge")
    assert "could not verify" in res.error and "never 'no advisory'" in res.error
    assert len(http.calls) == 1  # never retried with other headers or user agents
    sent = {k.lower(): v for k, v in http.calls[0]["headers"].items()}
    assert "mozilla" not in sent.get("user-agent", "").lower()


def test_rate_limit_and_5xx_are_never_empty():
    http = FakeHttp().add("GET", FEED_URL, status=503, text="down", times=3)
    assert run_module(CisaAdvisories, "cve:CVE-2023-4966", http).status is Status.ERROR
    http2 = FakeHttp().add("GET", FEED_URL, status=429, text="slow", headers={"Retry-After": "60"}, times=3)
    assert run_module(CisaAdvisories, "cve:CVE-2023-4966", http2).status in (Status.RATE_LIMITED, Status.ERROR)


def test_unsafe_or_broken_feed_is_error():
    doctype = (FIXTURES / "cti_news_rss" / "doctype_entity_rejected.xml").read_text(encoding="utf-8")
    assert run_module(CisaAdvisories, "keyword:Examplelocker", feed_http(doctype)).status is Status.ERROR
    assert run_module(CisaAdvisories, "keyword:Examplelocker", feed_http("<rss><channel><item>")).status is Status.ERROR


# ------------------------------------------------------------------ FC3/FC6: feed parsing and cards
def test_real_feed_capture_parses_and_answers():
    real = (FX / "feed_real_trimmed.xml").read_text(encoding="utf-8")
    items = parse_advisories(real)["items"]
    assert len(items) == 4 and items[0]["published"] == "2026-11-25T12:00:00Z"  # RFC 822 two-digit year
    assert items[1]["advisory_id"] == "ICSA-26-328-01" and "CVE-2026-103406" in items[0]["cves"]
    res = run_module(CisaAdvisories, "cve:CVE-2026-103406", feed_http(real))
    assert res.status is Status.OK
    card = res.attributes["cisa_advisories"][0]
    assert card["title"] == "CISA Adds 10 Known Exploited Vulnerabilities to Catalog" and card["published"].startswith("2026-11-25")
    kw = run_module(CisaAdvisories, "keyword:Schneider Electric", feed_http(real))
    assert kw.attributes["cisa_advisories"][0]["advisory_id"] == "ICSA-26-328-02"


def test_feed_items_carry_ids_families_cves_and_techniques():
    body = FEED.replace("IOC files: STIX JSON.", "IOC files: STIX JSON. Techniques T1486 and T1219.")
    items = {i["advisory_id"]: i for i in parse_advisories(body)["items"]}
    first = items["AA99-001A"]
    assert first["stop_ransomware"] is True and first["family"] == "Examplelocker"
    assert first["cves"] == ["CVE-2023-4966"] and first["techniques"] == ["T1219", "T1486"]
    assert advisory_id("https://www.cisa.gov/news-events/cybersecurity-advisories/aa24-131a") == "AA24-131A"
    assert family_from_title("#StopRansomware: Akira Ransomware") == "Akira" and family_from_title("CISA Releases X") is None


def test_family_card_lists_advisories_newest_first():
    body = FEED.replace("IOC files: STIX JSON.", "IOC files: STIX JSON. Techniques T1486.")
    res = run_module(CisaAdvisories, "malware_family:Examplelocker", feed_http(body))
    assert res.status is Status.OK
    cards = res.attributes["cisa_advisories"]
    assert [c["advisory_id"] for c in cards] == ["AA99-001A", "AA99-002A"]
    assert cards[0]["stop_ransomware"] is True and "ioc_file" not in cards[0]  # no curated IOC file
    assert res.attributes["cisa_families_unresolved"] == ["Examplelocker"]  # listed, never guessed
    pivots = {(p.entity.type, p.entity.value) for p in res.pivots}
    assert (T.CVE, "CVE-2023-4966") in pivots and (T.CVE, "CVE-2024-1709") in pivots and (T.MITRE, "T1486") in pivots
    assert all(not p.expand for p in res.pivots)
    finding = res.findings[0]
    assert finding.severity is Severity.INFO and "cisa_advisory" in finding.tags and "public domain" in finding.description
    assert res.attributes["dataset_age"][0].startswith("cisa_advisories.feed, fetched")
    assert res.links[0][1].endswith("/aa99-001a")


def test_cve_card_and_keyword_search():
    res = run_module(CisaAdvisories, "cve:CVE-2023-4966", feed_http())
    assert [c["advisory_id"] for c in res.attributes["cisa_advisories"]] == ["AA99-001A"] and not res.pivots
    kw = run_module(CisaAdvisories, "keyword:Industrial Control Systems", feed_http())
    assert kw.attributes["cisa_advisories"][0]["link"].endswith("icsa-99-001-01")


def test_unknown_value_is_empty_with_the_feed_answering():
    res = run_module(CisaAdvisories, "threat_actor:Exemplo Inexistente", feed_http())
    assert res.status is Status.EMPTY and "3 items" in res.error


def test_daily_poll_one_download_for_many_entities():
    http = feed_http()
    rt = make_runtime(http, clock=FakeClock())
    for value in ("cve:CVE-2023-4966", "malware_family:Examplelocker", "keyword:Examplelocker"):
        assert run_module(CisaAdvisories, value, runtime=rt).status is Status.OK
    assert len(http.calls) == 1


# ------------------------------------------------------------------ FC3: STIX schema check
def test_stix_schema_check():
    assert stix_check(STIX) is None
    assert "2.1 required" in stix_check(module_fixture(CisaAdvisories, "stix_invalid_synthetic.json"))
    assert stix_check({"type": "bundle", "id": "bundle--x"}) == "bad bundle id"
    broken = {"type": "bundle", "id": "bundle--00000000-0000-4000-8000-000000000000", "objects": [{"type": "indicator", "id": "indicator--1"}]}
    assert "without a STIX pattern" in stix_check(broken)


def test_stix_summary_uses_structured_fields_and_the_shared_ioc_engine():
    summary = stix_summary(STIX)
    assert summary["advisory_id"] == "AA99-001A" and summary["cves"] == ["CVE-2023-4966"]
    assert summary["attack_ids"] == ["T1219", "T1486"] and summary["tools"] == ["PsExec"]
    values = {(i["type"], i["value"]) for i in summary["indicators"]}
    assert ("ipv4", "203.0.113.10") in values and ("domain", "exfil.example.net") in values
    assert not any(i["value"].lower() == "psexec.exe" for i in summary["indicators"])  # a file name is not an IOC type here


# ------------------------------------------------------------------ FC4/FC5: local IOC matching
def test_ioc_types_are_not_applicable_without_curated_files():
    res = run_module(CisaAdvisories, "ipv4:203.0.113.10", FakeHttp())
    assert res.status is Status.SKIPPED and res.reason_code == "not_applicable"


def test_benign_values_are_never_malicious(ioc_file):
    http = FakeHttp().add("GET", IOC_URL, json=STIX)
    res = run_module(CisaAdvisories, "ipv4:8.8.8.8", http)  # public resolver (P169)
    match = res.attributes["cisa_ioc_matches"][0]
    assert match["advisory_id"] == "AA99-001A" and "warninglist" in match["tags"] and match["matchable_as_malicious"] is False
    assert res.findings[0].severity is Severity.INFO and "context_only" in res.findings[0].tags
    eicar = run_module(CisaAdvisories, "sha256:275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f", http)
    assert eicar.findings[0].severity is Severity.INFO  # test-file hash on a warninglist


def test_current_network_ioc_is_medium_and_ages_into_history(ioc_file, monkeypatch):
    monkeypatch.setattr("v3lum.modules.threat_intel_ioc.warninglists.local_classification",
                        lambda entity: {"outcome": "none", "categories": [], "suppress_matches": [], "tag_matches": []})
    clock = FakeClock()
    http = FakeHttp().add("GET", IOC_URL, json=STIX)
    rt = make_runtime(http, clock=clock)
    res = run_module(CisaAdvisories, "domain:exfil.example.net", runtime=rt)
    finding = res.findings[0]
    assert finding.severity is Severity.MEDIUM and finding.criterion and "cisa_advisory" in finding.tags
    assert res.attributes["cisa_ioc_matches"][0]["historical"] is False  # 86 days after 2026-09-01
    clock.advance(10 * 86400)
    old = run_module(CisaAdvisories, "domain:exfil.example.net", runtime=rt)
    assert old.findings[0].severity is Severity.INFO and "historical" in old.findings[0].tags  # FC4


def test_hashes_keep_their_weight(ioc_file, monkeypatch):
    monkeypatch.setattr("v3lum.modules.threat_intel_ioc.warninglists.local_classification",
                        lambda entity: {"outcome": "none", "categories": [], "suppress_matches": [], "tag_matches": []})
    clock = FakeClock()
    clock.advance(400 * 86400)
    http = FakeHttp().add("GET", IOC_URL, json=STIX)
    res = run_module(CisaAdvisories, "sha256:275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f", http, clock=clock)
    assert res.findings[0].severity is Severity.HIGH and "historical" not in res.findings[0].tags


def test_dual_use_and_fail_closed_tags(monkeypatch):
    now = FakeClock().now()
    monkeypatch.setattr("v3lum.modules.threat_intel_ioc.warninglists.local_classification", lambda entity: None)
    tags = ioc_tags(T.DOMAIN, "tools.example.org", {"name": "Rclone exfiltration endpoint", "description": ""}, "2026-11-01", now)
    assert "dual_use" in tags["tags"] and tags["dual_use_tools"] == ["rclone"]
    assert tags["warninglists"] == ["warninglist unavailable"] and tags["matchable_as_malicious"] is False


def test_invalid_stix_file_is_reported_never_empty(ioc_file):
    http = FakeHttp().add("GET", IOC_URL, json=module_fixture(CisaAdvisories, "stix_invalid_synthetic.json"))
    res = run_module(CisaAdvisories, "ipv4:198.51.100.7", http)
    assert res.status is Status.ERROR and IOC_SOURCE in res.source_statuses


def test_module_never_spawns_a_process(monkeypatch):
    def boom(*a, **k):
        raise AssertionError("no process may be spawned")
    monkeypatch.setattr(subprocess, "Popen", boom)
    assert run_module(CisaAdvisories, "cve:CVE-2023-4966", feed_http()).status is Status.OK
