"""ip_blocklists (P149 c1-c8): downloadable blocklists matched locally.

Fixtures in tests/fixtures/ip_blocklists/ were recorded on 2026-11-26 and minimised: Spamhaus DROP
v4/v6 and ASN-DROP NDJSON (real netblocks/ASNs; the metadata line recomputed for the kept records),
a truncated DROP download, the retired EDROP stub, Feodo Tracker JSON (C2 hosts and names replaced
by documentation values) and an empty list, the SSLBL certificate CSV (real SHA1 IOCs) and the
retired SSLBL IP list, IPsum, the FireHOL level1 netset (bogons kept to prove they are dropped),
blocklist.de, CINS, ET compromised, GreenSnow, Binary Defense, DataPlane and VoIPBL lists, a Varnish
501 page (IPsum) and an nginx 301 page (www.binarydefense.com). Attacker addresses were replaced
by 198.51.100.x / 2001:db8:bad::x keeping the real cross-feed overlaps (198.51.100.1 is on
blocklist.de, CINS, GreenSnow, Binary Defense, DataPlane and IPsum).
"""

from __future__ import annotations

import json

import pytest

from tests.fakes import FakeClock, FakeHttp, make_runtime, module_fixture, run_module
from v3lum.core import policy
from v3lum.core.context import RunInfo, ScanOptions
from v3lum.core.datasets import DATASETS
from v3lum.core.entities import Entity, EntityType
from v3lum.core.models import Severity, Status
from v3lum.modules.ip_network import ip_offline_db
from v3lum.modules.threat_intel_ioc import ip_blocklists
from v3lum.modules.threat_intel_ioc.ip_blocklists import FEEDS, IpBlocklists, dataset_name, parse_feed, score_hits

FILES = {
    "spamhaus_drop_v4": "spamhaus_drop_v4_ok.json",
    "spamhaus_drop_v6": "spamhaus_drop_v6_ok.json",
    "spamhaus_asndrop": "spamhaus_asndrop_ok.json",
    "feodo": "feodo_ok.json",
    "sslbl": "sslbl_certs_ok.csv",
    "ipsum": "ipsum_ok.txt",
    "firehol_level1": "firehol_level1_ok.netset",
    "blocklist_de": "blocklist_de_ok.txt",
    "cins": "cins_ok.txt",
    "et_compromised": "et_compromised_ok.txt",
    "greensnow": "greensnow_ok.txt",
    "binarydefense": "binarydefense_ok.txt",
    "dataplane_sshclient": "dataplane_sshclient_ok.txt",
    "voipbl": "voipbl_ok.txt",
}
OPEN = {"spamhaus.drop_v4", "spamhaus.drop_v6", "spamhaus.asndrop", "abusech.feodotracker", "abusech.sslbl", "github.ip_blocklists_ipsum", "binarydefense.banlist"}
SHA1 = "9ca8233118bf720ea5c2e141f0dde31c4cc9c818"


@pytest.fixture(autouse=True)
def minimised(monkeypatch):
    monkeypatch.setattr(ip_offline_db, "TEST_PUBLIC_LABELS", frozenset({"documentation"}))
    for spec in FEEDS.values():
        monkeypatch.setitem(spec, "min_entries", min(spec["min_entries"], 1))


def raw(feed_id: str) -> bytes:
    with open(f"tests/fixtures/ip_blocklists/{FILES[feed_id]}", "rb") as fh:
        return fh.read()


def feeds_http(*, skip: tuple[str, ...] = (), override: dict | None = None, times: int | None = None) -> FakeHttp:
    http = FakeHttp()
    for feed_id, spec in FEEDS.items():
        if feed_id in skip:
            continue
        route = (override or {}).get(feed_id) or {"body": raw(feed_id), "headers": {"last-modified": "Thu, 26 Nov 2026 04:00:00 GMT"}}
        http.add("GET", spec["url"], times=times, **route)
    return http


def hit_feeds(res) -> set[str]:
    return {h["feed"] for h in res.attributes.get("blocklist_hits", [])}


# ------------------------------------------------------------------ registry (c1, c2, c3)
def test_metadata_terms_and_per_feed_registry():
    cls = IpBlocklists
    assert (cls.terms, cls.disclosure, cls.hosts, cls.category) == ("noncommercial", "none", (), "threat_intel_ioc")
    assert set(cls.sources) == {spec["source"] for spec in FEEDS.values()}
    for feed_id, spec in FEEDS.items():
        reg = DATASETS[dataset_name(feed_id)]
        assert reg["source"] == spec["source"] and reg["ttl"] == spec["ttl"] and reg["attribution"]
        assert reg["terms_class"] == ("open" if spec["source"] in OPEN else "noncommercial"), feed_id
    assert FEEDS["feodo"]["ttl"] == 900 and FEEDS["spamhaus_drop_v4"]["ttl"] >= 3600
    assert all(21600 <= FEEDS[f]["ttl"] <= 86400 for f in ("blocklist_de", "cins", "ipsum", "voipbl"))
    assert "ip_blocklists_disabled_feeds" in cls.settings


def test_corporate_profile_queries_only_open_feeds():
    from v3lum.core import module as module_mod

    module_mod.load_modules()
    rt = make_runtime()
    ip = Entity.make(EntityType.IPV4, "198.51.100.1")
    decision = policy.decide(IpBlocklists, ip, policy.make_context(rt, ScanOptions(), path="scan"), run=RunInfo(entity=ip, is_seed=True))
    assert decision.allowed and set(decision.allowed_sources) == OPEN
    assert "blocklist_de.all" in decision.blocked_sources and "firehol.level1" in decision.blocked_sources
    http = feeds_http()
    res = run_module(IpBlocklists, "ipv4:198.51.100.1", http, allowed_sources=decision.allowed_sources)
    requested = set(http.urls())
    assert FEEDS["blocklist_de"]["url"] not in requested and FEEDS["cins"]["url"] not in requested  # never fetched
    assert hit_feeds(res) == {"binarydefense", "ipsum"}  # the open feeds that list it


# ------------------------------------------------------------------ consensus and fidelity (c5, c6)
def test_independent_families_raise_one_level_and_aggregates_are_one_vote():
    res = run_module(IpBlocklists, "ipv4:198.51.100.1", feeds_http())
    assert res.status is Status.OK
    assert hit_feeds(res) == {"blocklist_de", "cins", "greensnow", "binarydefense", "dataplane_sshclient", "ipsum"}
    (finding,) = res.findings
    data = finding.data
    assert data["votes"] == 5 and "ipsum" not in data["families"]  # IPsum embeds those families: one vote
    assert any(d["feed"] == "ipsum" for d in data["deduplicated"])
    assert finding.severity is Severity.HIGH  # best MEDIUM (CINS, IPsum 9) + >= 2 families, capped at HIGH
    assert "malicious" not in finding.tags and {"blocklisted", "suspicious"} <= set(finding.tags)
    assert res.attributes["ipsum_count"] == 9 and res.attributes["suspicious"] is True
    assert "5 independent families" in finding.criterion


def test_c2_hit_is_high_and_firehol_counts_as_its_families():
    res = run_module(IpBlocklists, "ipv4:198.51.100.5", feeds_http())
    assert hit_feeds(res) == {"feodo", "firehol_level1"}
    (finding,) = res.findings
    assert finding.severity is Severity.HIGH and finding.data["votes"] == 1  # FireHOL embeds abuse.ch
    assert {"malicious", "c2", "botnet"} <= set(finding.tags) and finding.source == "abusech.feodotracker"
    assert res.attributes["malware_family"] == ["QakBot"] and res.attributes["malicious"] is True
    feodo = next(h for h in res.attributes["blocklist_hits"] if h["feed"] == "feodo")
    assert feodo["details"]["port"] == 443 and feodo["currency"] == "current"
    assert any(p.entity.value == "c2-198-51-100-5.example.net" and not p.expand for p in res.pivots)


def test_offline_c2_is_historical():
    res = run_module(IpBlocklists, "ipv4:198.51.100.10", feeds_http())
    feodo = next(h for h in res.attributes["blocklist_hits"] if h["feed"] == "feodo")
    assert feodo["currency"] == "historical" and "historical (offline C2)" in res.findings[0].description


def test_single_low_feed_is_low_weak_signal():
    res = run_module(IpBlocklists, "ipv4:198.51.100.28", feeds_http())  # VoIPBL only
    (finding,) = res.findings
    assert finding.severity is Severity.LOW and "weak_signal" in finding.tags
    assert str(getattr(finding.confidence_label, "value", finding.confidence_label)) == "possible"


def test_spamhaus_drop_netblock_hit_with_sbl_link_and_cidr_pivot():
    res = run_module(IpBlocklists, "ipv4:1.10.16.5", feeds_http())
    assert hit_feeds(res) == {"spamhaus_drop_v4", "firehol_level1"}
    (finding,) = res.findings
    assert finding.severity is Severity.HIGH and "hijacked_netblock" in finding.tags and finding.data["votes"] == 1
    assert any(url == "https://check.spamhaus.org/sbl/query/SBL256894" for _l, url in res.links)
    assert any(p.entity.value == "1.10.16.0/20" and p.relation == "in_network" and not p.expand for p in res.pivots)
    assert finding.observed_last  # the listing date (Spamhaus metadata timestamp)


def test_ipv6_feeds():
    drop = run_module(IpBlocklists, "ipv6:2001:678:254::1", feeds_http())
    assert hit_feeds(drop) == {"spamhaus_drop_v6"} and drop.findings[0].severity is Severity.HIGH
    bde = run_module(IpBlocklists, "ipv6:2001:db8:bad::1", feeds_http())
    assert hit_feeds(bde) == {"blocklist_de"} and bde.findings[0].severity is Severity.LOW


def test_asn_drop_and_sslbl_certificates():
    asn = run_module(IpBlocklists, "asn:AS245", feeds_http())
    assert asn.findings[0].title == "AS listed on Spamhaus ASN-DROP" and asn.findings[0].severity is Severity.HIGH
    cert = run_module(IpBlocklists, f"cert_fingerprint:{SHA1}", feeds_http())
    assert cert.findings[0].title == "Certificate on the abuse.ch SSL Blacklist"
    assert cert.attributes["malware_family"] == ["PureLogsStealer"] and cert.findings[0].severity is Severity.HIGH
    sha256 = "a" * 64
    assert run_module(IpBlocklists, f"cert_fingerprint:{sha256}", FakeHttp()).status is Status.SKIPPED  # SHA1 list only


def test_cidr_inputs():
    inside = run_module(IpBlocklists, "cidr:1.10.16.0/24", feeds_http())
    assert hit_feeds(inside) == {"spamhaus_drop_v4", "firehol_level1"}
    block = run_module(IpBlocklists, "cidr:198.51.100.0/24", feeds_http())
    counts = next(f for f in block.findings if f.title == "Listed addresses inside the range").data["inside"]
    assert counts["VoIPBL"] == 5 and counts["blocklist.de (all)"] == 4


def test_no_hit_is_empty_and_nothing_is_sent():
    http = feeds_http()
    res = run_module(IpBlocklists, "ipv4:198.51.100.99", http)
    assert res.status is Status.EMPTY and not res.findings
    assert all("198.51.100.99" not in url for url in http.urls())  # downloads only: matching is local
    assert all(not any(r in url for r in ("edrop", "sslipblacklist", "ja3")) for url in http.urls())  # retired lists


# ------------------------------------------------------------------ P034 edges and warninglists (c6, c7)
def test_cdn_edge_is_capped_low_and_iaas_keeps_severity(monkeypatch):
    monkeypatch.setattr(ip_blocklists.noise, "noise_kinds", lambda entity: frozenset({"cdn"}))
    res = run_module(IpBlocklists, "ipv4:198.51.100.5", feeds_http())
    assert res.findings[0].severity is Severity.LOW and res.attributes["shared_ip"] is True
    assert "shared/reassignable IP" in res.findings[0].description and "malicious" not in res.attributes
    monkeypatch.setattr(ip_blocklists.noise, "noise_kinds", lambda entity: frozenset({"cloud"}))
    iaas = run_module(IpBlocklists, "ipv4:198.51.100.5", feeds_http())
    assert iaas.findings[0].severity is Severity.HIGH and iaas.attributes["verdict_lifetime_days"] == 14


def test_warninglist_applies_before_scoring(monkeypatch):
    monkeypatch.setattr(ip_blocklists.noise, "warninglists", lambda entity: ["test-benign-list"])
    res = run_module(IpBlocklists, "ipv4:198.51.100.5", feeds_http())
    finding = res.findings[0]
    assert str(getattr(finding.confidence_label, "value", finding.confidence_label)) == "possible"
    assert finding.criterion.startswith("POSSIBLE - on warninglist test-benign-list")


# ------------------------------------------------------------------ provenance, staleness, failures (c3, c8)
def test_every_hit_carries_feed_date_age_provenance_and_attribution():
    res = run_module(IpBlocklists, "ipv4:198.51.100.1", feeds_http())
    for hit in res.attributes["blocklist_hits"]:
        assert hit["name"] and hit["feed_age"] and hit["attribution"]
        assert set(hit["provenance"]) == {"feed", "fetched_at", "sha256"} and len(hit["provenance"]["sha256"]) == 64
        assert hit["restricted"] is (hit["terms"] != "open")
    ipsum = next(h for h in res.attributes["blocklist_hits"] if h["feed"] == "ipsum")
    assert ipsum["listed_at"] == "2026-11-26T02:00:45Z"  # the feed's own 'Last update' header
    assert sorted(res.findings[0].data["restricted_sources"]) == ["blocklist_de.all", "cinsscore.badguys", "dataplane.sshclient", "greensnow.list"]


def test_feed_older_than_3x_ttl_is_reported_stale():
    clock = FakeClock()
    http = feeds_http(times=1)
    http.add("GET", FEEDS["feodo"]["url"], status=503, text="down")
    for feed_id, spec in FEEDS.items():
        if feed_id != "feodo":
            http.add("GET", spec["url"], status=304, body=b"")
    rt = make_runtime(http, clock=clock)
    run_module(IpBlocklists, "ipv4:198.51.100.5", runtime=rt)
    clock.advance(4 * 900)  # Feodo's TTL is 15 min: its refresh fails, the copy is now > 3x TTL
    res = run_module(IpBlocklists, "ipv4:198.51.100.5", runtime=rt)
    feodo = next(h for h in res.attributes["blocklist_hits"] if h["feed"] == "feodo")
    assert feodo["stale"] is True and "STALE" in res.findings[0].description
    assert "stale copy" in res.source_statuses["abusech.feodotracker"]["reason"]


def test_one_feed_down_is_a_source_status():
    http = feeds_http(skip=("ipsum",))
    http.add("GET", FEEDS["ipsum"]["url"], status=501, text=module_fixture(IpBlocklists, "ipsum_error_501.html"))
    res = run_module(IpBlocklists, "ipv4:198.51.100.1", http)
    assert res.status is Status.OK and res.source_statuses["github.ip_blocklists_ipsum"]["status"] == "error"


def test_all_feeds_down_is_could_not_verify():
    dead = FakeHttp()
    for spec in FEEDS.values():
        dead.add("GET", spec["url"], status=503, text="down")
    down = run_module(IpBlocklists, "ipv4:198.51.100.1", dead)
    assert down.status is Status.ERROR and "could not verify" in down.error and not down.findings


def test_disabled_feeds_setting():
    res = run_module(IpBlocklists, "ipv4:198.51.100.28", feeds_http(), settings={"ip_blocklists_disabled_feeds": ["voipbl"]})
    assert res.status is Status.EMPTY and res.source_statuses["voipbl.update"]["reason_code"] == "config"


def test_private_and_special_addresses_are_never_checked():
    assert run_module(IpBlocklists, "ipv4:10.1.2.3", FakeHttp()).status is Status.SKIPPED
    feed = parse_feed("firehol_level1", raw("firehol_level1"))
    assert feed.dropped_special == 10 and feed.entries == 5  # bogons/RFC 1918/224.0.0.0/3 dropped at load
    assert any("224.0.0.0/3" in e for e in feed.dropped_examples)


# ------------------------------------------------------------------ validation (c3, c4)
@pytest.mark.parametrize(
    ("feed_id", "route", "why"),
    [
        ("spamhaus_drop_v4", {"body": None}, "Spamhaus metadata"),  # truncated NDJSON (no metadata line)
        ("spamhaus_drop_v4", {"body": b'{"cidr":"1.10.16.0/20","sblid":"SBL1","rir":"apnic"}\n{"type":"metadata","timestamp":1795613204,"records":3}\n'}, "record count mismatch"),
        ("feodo", {"json": {"error": "quota exceeded"}}, ""),  # registration shared with abusech (p1-G07-1): either validator rejects it
        ("cins", {"status": 200, "text": "<!DOCTYPE html><html><head><title>Just a moment...</title></head><body>cf-chl</body></html>"}, ""),
        ("greensnow", {"body": b""}, ""),
        ("binarydefense", {"status": 301, "text": None}, ""),
    ],
)
def test_bad_downloads_never_replace_the_good_copy(feed_id, route, why):
    name = dataset_name(feed_id)
    if route.get("body", "x") is None:  # NDJSON: read as bytes (module_fixture would parse one JSON document)
        with open("tests/fixtures/ip_blocklists/spamhaus_drop_v4_truncated.json", "rb") as fh:
            route = {"body": fh.read()}
    if route.get("text", "x") is None:
        route = {"status": 301, "text": module_fixture(IpBlocklists, "binarydefense_moved_301.html")}
    http = FakeHttp().add("GET", FEEDS[feed_id]["url"], body=raw(feed_id), times=1).add("GET", FEEDS[feed_id]["url"], **route)
    rt = make_runtime(http)
    first = rt.data.update(name)
    assert first.ok
    second = rt.data.update(name)
    assert second.status == "failed" and why in second.reason
    assert rt.data.info(name).sha256 == first.new_sha256  # the previous copy is kept


def test_collapsed_download_is_rejected(monkeypatch):
    name = dataset_name("cins")
    http = FakeHttp().add("GET", FEEDS["cins"]["url"], body=b"\n".join(f"203.0.113.{i}".encode() for i in range(1, 60)), times=1)
    http.add("GET", FEEDS["cins"]["url"], body=b"203.0.113.1\n203.0.113.2\n203.0.113.3\n")
    rt = make_runtime(http)
    assert rt.data.update(name).ok
    second = rt.data.update(name)
    assert second.status == "failed" and "fell from 59 to 3" in second.reason


def test_parsers_on_trimmed_fixtures():
    drop = parse_feed("spamhaus_drop_v4", raw("spamhaus_drop_v4"))
    assert drop.entries == 5 and not drop.problem and drop.listed_at.startswith("2026-")
    asn = parse_feed("spamhaus_asndrop", raw("spamhaus_asndrop"))
    assert set(asn.asns) == {245, 2601, 2702, 3507}
    sslbl = parse_feed("sslbl", raw("sslbl"))
    assert sslbl.sha1[SHA1]["malware"] == "PureLogsStealer" and sslbl.listed_at == "2026-11-25T18:28:00Z"
    dataplane = parse_feed("dataplane_sshclient", raw("dataplane_sshclient"))
    assert dataplane.entries == 3 and dataplane.listed_at == "2026-11-26T04:00:00Z"
    voip = parse_feed("voipbl", raw("voipbl"))
    assert voip.entries == 5 and voip.dropped_special == 3 and not voip.problem
    assert parse_feed("feodo", b"[]").entries == 0 and not parse_feed("feodo", b"[]").problem  # may be empty
    retired = module_fixture(IpBlocklists, "spamhaus_edrop_retired.txt")
    assert "merged into" in retired and "deprecated" in module_fixture(IpBlocklists, "sslbl_ips_retired.txt")
    empty = module_fixture(IpBlocklists, "feodo_empty.json")
    assert empty == []


def test_score_caps_and_dedupe_rules():
    def hit(feed, family, fidelity_count=None, embeds=()):
        return {"feed": feed, "family": family, "embeds": list(embeds), "details": {"count": fidelity_count} if fidelity_count else {}}

    one = score_hits([hit("feodo", "abuse.ch")])
    assert one["severity"] == "high" and one["votes"] == 1
    two_high = score_hits([hit("feodo", "abuse.ch"), hit("spamhaus_drop_v4", "spamhaus")])
    assert two_high["severity"] == "high"  # never CRITICAL (CR27 caps consensus at HIGH)
    agg = score_hits([hit("firehol_level1", "firehol", embeds=("spamhaus",)), hit("ipsum", "ipsum", 2, embeds=("spamhaus", "cins"))])
    assert agg["votes"] == 1 and agg["deduplicated"][0]["why"] == "overlaps another counted aggregate"
    shared = score_hits([hit("feodo", "abuse.ch"), hit("cins", "cins")], shared=True)
    assert shared["severity"] == "low" and shared["verdict_lifetime_days"] is None
    assert json.dumps(shared)  # JSON-serialisable for evidence


def test_acceptance_routes_cover_the_golden_ipv4_under_corporate():
    """AR21 golden path (8.8.8.8, corporate profile): the open IPv4 feeds are downloaded, nothing matches."""
    with open("tests/fixtures/acceptance/ipv4/ip_blocklists.json", encoding="utf-8") as fh:
        doc = json.load(fh)
    assert doc["module"] == "ip_blocklists"
    http = FakeHttp()
    for route in doc["routes"]:
        body = {"json": route["json"]} if "json" in route else {"body": route["text"].encode()}
        http.add(route["method"], route["url"], status=route["status"], **body)
    res = run_module(IpBlocklists, "ipv4:8.8.8.8", http, allowed_sources=OPEN)
    assert res.status is Status.EMPTY and len(http.calls) == len(doc["routes"]) and not res.source_statuses
