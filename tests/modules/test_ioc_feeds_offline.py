"""ioc_feeds_offline (P159): open feeds matched locally - load pipeline, health rules, grouping, CIRCL.

Fixtures in tests/fixtures/ioc_feeds_offline/ (live 2026-11-26 unless noted, trimmed):
``tweetfeed_week.csv`` (TweetFeed rows, reporting handles and tweet ids scrubbed), ``circl_manifest.json``
(5 real manifest entries), ``circl_hashes_derived.csv`` (12 real hashes.csv lines of the 2015 Black Vine
event + md5(value) lines derived from the real Kali365 event 814c12e6, the way the MISP feed generator
writes hashes.csv - verified against a live event), ``meta_index.json`` + ``meta_2023_05_malware_iocs.csv``
(Meta threat-research), ``sigbase_hash_iocs.txt`` / ``sigbase_c2_iocs.txt`` (signature-base),
``sslbl_sha1.csv`` (SSLBL certificates) and ``sslbl_deprecated_0_rows.csv`` (the deprecated SSLBL IP
list: a 0-row copy). The module never makes a request: every test runs with an empty FakeHttp.
"""

from __future__ import annotations

import pytest

from tests.fakes import FakeHttp, module_fixture, run_module
from v3lum import paths
from v3lum.core.entities import Entity
from v3lum.core.entities import EntityType as T
from v3lum.core.models import Status
from v3lum.modules.threat_intel_ioc import abusech
from v3lum.modules.threat_intel_ioc import ioc_feeds_offline as mod
from v3lum.modules.threat_intel_ioc.ioc_feeds_offline import IocFeedsOffline

KALI365_UUID = "814c12e6-0e88-42fb-a463-601d42b70881"


@pytest.fixture(autouse=True)
def _fresh_parse_cache(monkeypatch):
    """Parsed feed copies are memoized per process by dataset version: start every test empty."""
    from collections import OrderedDict

    from v3lum.modules.threat_intel_ioc import abusech as _abusech

    monkeypatch.setattr(_abusech, "_MEMO", OrderedDict())


def fx(name):
    return module_fixture(IocFeedsOffline, name)


def install(name, content):
    (paths.datasets_dir() / name).write_text(content, encoding="utf-8")


def install_all():
    import json

    install(mod.DS_TWEETFEED, fx("tweetfeed_week.csv"))
    install(mod.DS_CIRCL_MANIFEST, json.dumps(fx("circl_manifest.json")))
    install(mod.DS_CIRCL_HASHES, fx("circl_hashes_derived.csv"))
    install(mod.DS_META_INDEX, json.dumps(fx("meta_index.json")))
    install("meta_tr_2023_05_malware_iocs.csv", fx("meta_2023_05_malware_iocs.csv"))
    install(mod.DS_SIGBASE_HASH, fx("sigbase_hash_iocs.txt"))
    install(mod.DS_SIGBASE_C2, fx("sigbase_c2_iocs.txt"))
    install(abusech.SSLBL_DATASET, fx("sslbl_sha1.csv"))


def run(value, http=None, **kw):
    http = http if http is not None else FakeHttp()
    res = run_module(IocFeedsOffline, value, http, **kw)
    assert http.calls == []  # disclosure 'none': no request, ever
    return res


# ------------------------------------------------------------------ metadata (cond 1-3)
def test_contract_metadata():
    cls = IocFeedsOffline
    assert (cls.terms, cls.disclosure, cls.hosts, cls.provider, cls.default_enabled) == ("open", "none", (), "", True)
    assert set(cls.terms_sources.values()) == {"open"}
    assert set(cls.sources) == {"github.ioc_feeds_offline_tweetfeed", "circl.misp_osint_feed", "github.ioc_feeds_offline_meta",
                                "github.ioc_feeds_offline_sigbase", "abusech.sslbl"}
    assert cls.trust_tier == "n/a" and cls.max_requests == 0


def test_every_feed_dataset_is_registered_with_its_source_terms():
    from v3lum.core.datasets import DATASETS, dataset_errors

    for feed in mod.FEEDS:
        for name in feed.datasets:
            assert DATASETS[name]["source"] == feed.source, name
    assert DATASETS[mod.DS_CIRCL_HASHES]["large"] is True and DATASETS[mod.DS_TV_DOMAIN]["large"] is True  # > 5 MB: data update only
    assert all("filename-iocs" not in reg["url"] for reg in DATASETS.values())  # untrusted regexes are never fetched (cond 5)
    assert all(reg["url"].startswith(mod.CIRCL_BASE) for name, reg in DATASETS.items() if name.startswith("circl_osint"))  # same host only
    assert dataset_errors() == []


# ------------------------------------------------------------------ hits and grouping (cond 6/7)
def test_tweetfeed_phishing_domain():
    install_all()
    res = run("domain:sksports.pk")
    assert res.status is Status.OK
    finding = res.findings[0]
    assert finding.title == "Listed in offline threat feeds" and finding.description.startswith("seen in 1 feed: TweetFeed")
    assert finding.severity.label == "low" and str(finding.confidence_label.value) == "possible"  # TweetFeed labels are low
    assert {"suspicious", "phishing"} <= set(finding.tags)
    assert finding.criterion and finding.source == "github.ioc_feeds_offline_tweetfeed"
    assert res.attributes["feed_hits"][0]["feed"] == "TweetFeed"
    assert res.attributes["blocklists"] == ["TweetFeed"]
    assert all("reporter" not in hit for hit in res.attributes["feed_hits"])  # the reporting handle column is not indexed
    assert res.attributes["feed_hits"][0]["reference"].startswith("https://x.com/")  # the post stays as provenance
    assert any(d["name"] == mod.DS_TWEETFEED for d in res.datasets)


def test_url_matches_by_value_and_by_host():
    install_all()
    res = run("url:https://sksports.pk/join_zoom_interview.bat")
    feeds = res.findings[0].data["feeds"]
    assert feeds[0]["match"] == "value"
    res = run("url:https://sksports.pk/other.html")
    assert res.findings[0].data["feeds"][0]["match"] == "url_host"


def test_signature_base_c2_with_otx_upstream():
    install_all()
    res = run("domain:anvprn.com")
    finding = res.findings[0]
    assert finding.severity.label == "medium" and {"malicious", "c2"} <= set(finding.tags)
    assert finding.data["upstream_families"] == ["otx"]  # 'Source: AlienVault OTX' blocks are not an independent vote
    assert res.attributes["feed_hits"][0]["label"].startswith("APT10 C2 IOCs")


def test_signature_base_hash_listing():
    install_all()
    res = run("sha1:01edb82de7b9666eaa5d2791a14092f2e73d2795")
    assert res.status is Status.OK and "malware" in res.findings[0].tags
    res = run("md5:042cc382acb5b2b70c78baa77bb7c5f9")
    assert "SlingShot APT" in res.findings[0].description and res.findings[0].references == ["https://securelist.com/apt-slingshot/84312/"]


def test_meta_report_hit_gives_family_and_reference():
    install_all()
    res = run("sha256:4b740be3b607687b0db472504dd734a87ed7be63b26211454cd58cf67b0874fb")
    finding = res.findings[0]
    assert "NodeStealer" in {p.entity.value for p in res.pivots if p.entity.type is T.MALWARE}
    assert finding.references == ["https://about.fb.com/news/2023/05/how-meta-protects-businesses-from-malware/"]
    assert finding.severity.label == "medium"


def test_meta_url_listings_older_than_90_days_are_low():
    install_all()
    res = run("url:http://bit.ly/3KJwgoH")
    assert res.findings[0].severity.label == "low"  # Meta is medium, but a 2023 URL listing is low (cond 6)


def test_circl_hit_through_hashes_and_manifest():
    install_all()
    res = run("domain:data-doc-sfym.p-50ds7vs5.workers.dev")
    assert res.status is Status.OK
    finding = res.findings[0]
    assert "CIRCL OSINT" in finding.description and finding.severity.label == "medium"
    assert finding.references == [f"{mod.CIRCL_BASE}{KALI365_UUID}.json"]
    assert "Kali365" in {p.entity.value for p in res.pivots if p.entity.type is T.MALWARE}
    assert res.attributes["feed_hits"][0]["label"] == "NEW KALI365 PHAAS KIT BEING ABUSED IN THE WILD"
    assert run("ipv4:157.230.53.233").status is Status.OK


def test_circl_events_outside_the_window_do_not_count():
    install_all()
    res = run("domain:ameteksen.com")  # in hashes.csv, but its event is from 2015
    assert res.status is Status.EMPTY
    res = run("domain:ameteksen.com", settings={"ioc_feeds_offline_circl_window_days": 5000})
    assert res.status is Status.OK


def test_two_independent_families_raise_the_confidence():
    install_all()
    install(mod.DS_SIGBASE_C2, fx("sigbase_c2_iocs.txt") + "\n# Kali365 PhaaS https://example.org/report\ndata-doc-sfym.p-50ds7vs5.workers.dev\n")
    res = run("domain:data-doc-sfym.p-50ds7vs5.workers.dev")
    finding = res.findings[0]
    assert finding.data["upstream_families"] == ["circl", "signature-base"]
    assert finding.severity.label == "high" and finding.description.startswith("seen in 2 feeds")


def test_sslbl_from_the_shared_dataset():
    install_all()
    res = run("cert_fingerprint:3ec4de7981b35b599489e6131411bfab779a3993")
    assert res.status is Status.OK and {"c2", "malicious"} <= set(res.findings[0].tags)
    assert "Vidar" in {p.entity.value for p in res.pivots}


def test_not_listed_is_empty_with_dataset_ages_in_coverage():
    install_all()
    res = run("domain:example.com")
    assert res.status is Status.EMPTY and not res.findings
    reasons = " ".join(s["reason"] for s in res.source_statuses.values())
    assert "fetched" in reasons


def test_family_query_counts_listings():
    install_all()
    res = run("malware_family:NodeStealer")
    assert res.status is Status.OK and res.attributes["ioc_count"]["Meta threat-research"] == 2
    assert res.findings[0].severity.label == "info"


# ------------------------------------------------------------------ health rules (cond 4/8)
def test_missing_datasets_are_unavailable_never_empty():
    res = run("domain:sksports.pk")
    assert res.status is Status.UNAVAILABLE and res.reason_code == "dataset" and "v3lum data update" in res.error


def test_zero_row_feed_is_unhealthy_never_no_hits():
    install(abusech.SSLBL_DATASET, fx("sslbl_deprecated_0_rows.csv"))
    res = run("cert_fingerprint:3ec4de7981b35b599489e6131411bfab779a3993")
    assert res.status is Status.ERROR and "parsed to 0 rows" in res.error
    assert res.source_statuses["abusech.sslbl"]["status"] == "error"


def test_stale_feed_is_skipped_and_reported():
    old = "\n".join(line.replace("2026-11-26", "2026-10-01") for line in fx("tweetfeed_week.csv").splitlines())
    install(mod.DS_TWEETFEED, old)
    res = run("domain:sksports.pk")  # the only feed copy present is stale
    assert res.status is Status.UNAVAILABLE and "stale" in res.error
    install_all()
    install(mod.DS_TWEETFEED, old)
    res = run("domain:sksports.pk")  # other feeds answered: not listed there; TweetFeed skipped as stale
    assert res.status is Status.EMPTY
    status = res.source_statuses["github.ioc_feeds_offline_tweetfeed"]
    assert status["status"] == "unavailable" and "stale" in status["reason"]


def test_licence_filtered_sources_are_not_read():
    install_all()
    res = run("domain:sksports.pk", allowed_sources=("circl.misp_osint_feed",))
    assert res.status is Status.EMPTY and "github.ioc_feeds_offline_tweetfeed" not in res.source_statuses


# ------------------------------------------------------------------ load pipeline (cond 4)
@pytest.mark.parametrize("etype,value,ok", [
    (T.IPV4, "0.0.0.2", False), (T.IPV4, "1.0.0.0", False), (T.IPV4, "249.223.175.5", False), (T.IPV4, "10.1.2.3", False),
    (T.IPV4, "120.229.26.013", True), (T.DOMAIN, "0000153.0000255.0000011.0000125", False),
    (T.DOMAIN, "0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.c.f.0.0.0.0.0.e.ip6.arpa", False), (T.DOMAIN, "evil[.]example[.]com", True),
    (T.URL, "hxxp://evil[.]example[.]com/x", True), (T.URL, "ftp://evil.example.com/x", False), (T.URL, "http://10.0.0.5/x", False),
    (T.MD5, "0000a3de2cfb52c8362d1aa16cc6cde7", True), (T.MD5, "xyz", False),
])
def test_validate(etype, value, ok):
    ent, why = mod.validate(etype, value)
    assert (ent is not None) is ok, why
    if etype is T.IPV4 and ok:
        assert ent.value == "120.229.26.13"


def test_warninglisted_and_cdn_rows_are_not_indexed():
    feed = next(f for f in mod.FEEDS if f.id == "sigbase_c2")
    index = mod._index(feed, [(T.IPV4, "8.8.8.8", {}), (T.DOMAIN, "drive.google.com", {}), (T.DOMAIN, "anvprn.com", {})])
    assert list(index.rows) == ["domain:anvprn.com"] and index.dropped["warninglist_or_cdn"] == 2


def test_hash_index_lookups():
    from pathlib import Path

    path = Path(paths.datasets_dir()) / "hashes_test.csv"
    path.write_text(fx("circl_hashes_derived.csv"), encoding="utf-8")
    index = mod.HashIndex(path)
    assert len(index) == 22
    assert index.events("157.230.53.233") == [KALI365_UUID]
    assert index.events("not-listed.example.com") == []


def test_parsers_on_trimmed_feeds():
    rows = mod.parse_tweetfeed(fx("tweetfeed_week.csv"))
    assert len(rows) == 8 and rows[0][2]["family"] == "Formbook"
    assert all(r[2]["reference"].startswith("https://x.com/researcher_") for r in rows)
    c2 = mod.parse_sigbase_c2(fx("sigbase_c2_iocs.txt"))
    assert ("suroot.com" in {r[1] for r in c2}) and all("LOKI C2 IOCs" not in r[2]["label"] for r in c2)
    assert {r[1] for r in c2 if r[0] is T.IPV4} >= {"176.123.5.126", "58.64.143.244"}
    events = mod.parse_circl_manifest(fx("circl_manifest.json"))
    assert events[KALI365_UUID]["families"] == ["Kali365"] and events[KALI365_UUID]["date"].startswith("2026-04-24")
    turla = next(e for e in events.values() if e["info"] == "Turla Outlook White Paper")
    assert turla["actors"] == ["Turla Group"]


def test_entity_lookup_keys():
    keys = mod._lookup_keys(Entity.make("url", "http://1.2.3.4:8080/panel"))
    assert ("ipv4:1.2.3.4", "url_host") in keys
