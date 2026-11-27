"""warninglists (P169): MISP warninglists compact bundle - SUPPRESS / TAG / TOP-SITE outcomes, offline.

FC10 values run on the shipped build (v3lum/data/warninglists/, MISP warninglists commit 922dbb3e, 194
lists): 8.8.8.8, 1.1.1.1, google.com, a CDN IP, a sinkhole IP and the EICAR hash, plus the two
regressions (a phishing-feed URL on docs.google.com stays flagged; a sites.google.com phishing URL from
a pasted e-mail is investigated and scored). Fixtures in tests/fixtures/warninglists/ are trimmed real
list.json files (2026-11-26) used for the parser, the refresh path through the dataset manager and the
index invariants; the two FC10 regression inputs and the pasted e-mail are labelled synthetic
(documentation values only).
"""

from __future__ import annotations

import gzip
import hashlib
import json
import random
from pathlib import Path

import pytest

from tests.fakes import FIXTURES, FakeHttp, define_module, make_runtime, run_module
from v3lum import paths
from v3lum.core import noise
from v3lum.core.context import ScanOptions
from v3lum.core.engine import Engine, suppress
from v3lum.core.entities import Entity
from v3lum.core.entities import EntityType as T
from v3lum.core.http import NetworkError
from v3lum.core.models import Confidence, Status
from v3lum.modules.threat_intel_ioc import warninglists as wl
from v3lum.modules.threat_intel_ioc.warninglists import Warninglists

FIX = FIXTURES / "warninglists"
EICAR_SHA256 = "275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f"
EMPTY_MD5 = "d41d8cd98f00b204e9800998ecf8427e"
SINKHOLE_IP = "104.236.150.45"  # MISP warninglists 'sinkholes' (version 20261014)
CDN_IP = "104.16.132.229"  # Cloudflare edge
CHALLENGE = "<!DOCTYPE html><html><head><title>Just a moment...</title></head><body>cf-chl-widget</body></html>"


@pytest.fixture(autouse=True, scope="module")
def fresh_index():
    """One index for the file (the cache key follows the bundle and the local copies of each test's home)."""
    wl.reset_cache()
    yield
    wl.reset_cache()


def fixture_bytes(name: str) -> bytes:
    return (FIX / name).read_bytes()


def run(value: str, http: FakeHttp | None = None):
    http = http if http is not None else FakeHttp()  # offline module: any request would fail the test
    res = run_module(Warninglists, value, http)
    assert http.calls == [] and http.unexpected == []
    return res


def titles(res) -> set[str]:
    return {f.title for f in res.findings}


def lists_of(res) -> set[str]:
    return {m["list"] for m in res.attributes.get("warninglist_matches", [])}


# ------------------------------------------------------------------------------- FC10 values
def test_public_resolver_8888_is_suppressed_with_list_and_version_date():
    res = run("ipv4:8.8.8.8")
    assert res.status is Status.OK
    assert res.attributes["warninglist_outcome"] == "suppress"
    assert {"public-dns-v4", "datacenter-ipv4"} <= lists_of(res)
    sup = next(f for f in res.findings if f.title == wl.SUPPRESS_TITLE)
    assert "likely benign because List of known IPv4 public DNS resolvers (2026-08-29)" in sup.description
    assert sup.severity.label == "info" and {"warninglist", "known_good", "context_only"} <= set(sup.tags)
    assert res.attributes["allowlisted"] == ["MISP warninglist: List of known IPv4 public DNS resolvers (2026-08-29)"]
    datacenter = next(m for m in res.attributes["warninglist_matches"] if m["list"] == "datacenter-ipv4")
    assert datacenter["licence"] == "MIT" and datacenter["outcome"] == "tag"  # X4BNet list keeps its MIT notice (FC9)
    assert not res.pivots  # recorded, not pivoted (FC3)


def test_public_resolver_1111_is_suppressed():
    res = run("ipv4:1.1.1.1")
    assert res.attributes["warninglist_outcome"] == "suppress"
    assert "public-dns-v4" in lists_of(res)


def test_google_com_is_a_popular_site_never_suppressed():
    res = run("domain:google.com")
    assert res.attributes["warninglist_outcome"] == "tag"
    assert res.attributes["popular_site"] is True and res.attributes["reputation_downweight"] == "registrable_domain"
    assert {"tranco10k", "cisco_top10k", "cloudflare-top10k", "google"} <= lists_of(res)
    assert "Popular site (top-site list)" in titles(res) and wl.SUPPRESS_TITLE not in titles(res)
    assert "allowlisted" not in res.attributes


def test_subdomain_of_a_top_site_is_never_down_weighted():
    res = run("domain:mail.google.com")
    assert "reputation_downweight" not in res.attributes  # FC4: the registrable domain itself only
    assert any("context only, no down-weight for mail.google.com" in n for n in res.attributes["warninglist_notes"])


def test_cdn_ip_is_tagged_third_party_hosted():
    res = run(f"ipv4:{CDN_IP}")
    assert res.attributes["warninglist_outcome"] == "tag" and "cloudflare" in lists_of(res)
    assert res.attributes["is_cdn"] is True and res.attributes["third_party_hosted"] is True
    assert "CDN address range (MISP warninglist)" in titles(res)
    assert wl.active_probe_excluded(Entity.make("ipv4", CDN_IP))  # A7 ACTIVE exclusion hook (FC8)


def test_sinkhole_ip_sets_is_sinkhole_with_the_infected_clients_note():
    res = run(f"ipv4:{SINKHOLE_IP}")
    assert res.attributes["is_sinkhole"] is True and "sinkholes" in lists_of(res)
    sink = next(f for f in res.findings if f.title == "Known sinkhole (MISP warninglist)")
    assert "hits = infected clients, not attacker infrastructure" in sink.description and "sinkhole" in sink.tags


def test_eicar_hash_is_tagged_test_file_and_shown_not_suppressed():
    res = run(f"sha256:{EICAR_SHA256}")
    assert res.attributes["warninglist_outcome"] == "tag" and "eicar.com" in lists_of(res)
    test_file = next(f for f in res.findings if f.title == "Antivirus test file (EICAR)")
    assert "test_file" in test_file.tags and "never suppressed" in test_file.description


def test_empty_file_hash_is_suppressed():
    res = run(f"md5:{EMPTY_MD5}")
    assert res.attributes["warninglist_outcome"] == "suppress" and "empty-hashes" in lists_of(res)


def test_unlisted_values_are_empty():
    for value in ("domain:v3lum-unlisted-test-name.example", "sha256:" + "ab" * 32, "ipv4:198.51.100.7"):
        res = run(value)
        if value.startswith("ipv4"):
            continue  # documentation ranges are on the RFC lists
        assert res.status is Status.EMPTY and not res.findings and not res.attributes


# ------------------------------------------------------------------------------- FC2 matching
def test_label_aligned_matching_never_string_suffix():
    assert run("domain:notgoogle.com").status is Status.EMPTY
    res = run("domain:mail.google.com")
    assert any(m["match"] == "subdomain" and m["entry"] == "google.com" for m in res.attributes["warninglist_matches"])


def test_dynamic_dns_subdomain_is_tagged_never_suppressed():
    res = run("domain:victim-panel.duckdns.org")
    assert "dynamic-dns" in lists_of(res)
    assert res.attributes["warninglist_outcome"] == "tag" and res.attributes["user_content_parent"] == "duckdns.org"
    assert "Dynamic DNS service (MISP warninglist)" in titles(res)


def test_cidr_inside_a_list_applies_and_partial_overlaps_never_do():
    inside = run("cidr:104.16.0.0/16")
    assert inside.attributes["warninglist_outcome"] == "tag" and "cloudflare" in lists_of(inside)
    wide = run("cidr:104.0.0.0/8")
    assert wide.attributes["warninglist_outcome"] == "none"
    assert all(m["match"] == "cidr_partial_overlap" for m in wide.attributes["warninglist_matches"])
    assert titles(wide) == {"Network partially overlaps MISP warninglists"}
    assert "never applied" in wide.attributes["warninglist_notes"][0]


def test_interval_index_matches_brute_force():
    rng = random.Random(1169)
    nets = []
    for _ in range(300):
        prefix = rng.choice([8, 12, 16, 20, 24, 28, 32])
        base = rng.randrange(0, 2**32) >> (32 - prefix) << (32 - prefix)
        nets.append((base, base + 2 ** (32 - prefix) - 1, f"l{len(nets)}"))
    index = wl.IntervalIndex((4, s, e, label) for s, e, label in nets)
    import ipaddress

    for _ in range(2000):
        probe = rng.randrange(0, 2**32)
        expected = sorted({label for s, e, label in nets if s <= probe <= e})
        assert index.lookup(str(ipaddress.IPv4Address(probe))) == expected


def test_public_suffix_parent_never_suppresses():
    bundle = {"lists": {
        "suppress-hosts": {"name": "synthetic suppress list", "type": "hostname", "kind": "host", "version": 20261126, "version_date": "2026-11-26",
                           "outcome": "suppress", "category": "public_resolver", "licence": "CC0-1.0", "entries": ["github.io", "dns.example.net"], "subdomain_only": []},
    }}
    index = wl.build_index(bundle["lists"], {"commit": "test"})
    exact = wl.classify(T.DOMAIN, "dns.example.net", index.lookup(T.DOMAIN, "dns.example.net"))
    assert exact["suppressed"]
    under_suffix = index.lookup(T.DOMAIN, "evil.github.io")
    assert under_suffix and under_suffix[0]["above_registrable"] is True
    cls = wl.classify(T.DOMAIN, "evil.github.io", under_suffix)
    assert not cls["suppressed"] and any("public suffix" in n or "user-content" in n for n in cls["notes"])


# ------------------------------------------------------------------------------- FC5/FC6 regressions
def feed_hits(self, entity, ctx):
    """Synthetic phishing feed: every URL and address it is asked about is 'listed' (FC10 regressions)."""
    res = self.result(entity)
    res.finding("Listed by a phishing feed", "high", "synthetic feed hit", confidence="probable", criterion="synthetic phishing feed listing",
                tags=["phishing", "malicious"])
    return res


def feed_finding(case, entity):
    node = case.graph.get(entity)
    assert node is not None
    return next(f for f in node.findings if f.title == "Listed by a phishing feed")


def test_phishing_feed_url_on_docs_google_stays_flagged(clean_registry):
    record = json.loads(fixture_bytes("phishing_feed_docs_google_synthetic.json"))
    url = Entity.make("url", record["url"])
    res = run(f"url:{record['url']}")
    assert res.attributes["warninglist_outcome"] == "tag"  # never suppress a URL (FC3)
    assert "URL on a listed legitimate platform" in titles(res)  # hosted_on_legit_platform (FC5)
    assert noise.warninglists(url) == [] and not noise.is_noise(url)  # the core never downgrades it
    resolver = Entity.make("ipv4", "8.8.8.8")
    assert "misp.public-dns-v4" in noise.warninglists(resolver)  # while a SUPPRESS value is (AR06 merge)

    define_module("t_g11_feed", [T.URL, T.IPV4], feed_hits)
    case = Engine(make_runtime(FakeHttp()), ScanOptions(include={"warninglists", "t_g11_feed"})).investigate([url, resolver])
    on_url, on_resolver = feed_finding(case, url), feed_finding(case, resolver)
    assert on_url.label is Confidence.PROBABLE and not on_url.suppressed_by  # stays flagged
    assert case.graph.get(url).tagged("hosted_on_legit_platform")
    assert on_resolver.label is Confidence.POSSIBLE and on_resolver.suppressed_by[0]["rule"] == "SUP-warninglist"
    assert "misp.public-dns-v4" in on_resolver.criterion
    assert len([f for f in case.graph.findings() if f.title == "Listed by a phishing feed"]) == 2  # never deleted (FC6)
    assert suppress(case) == 0  # each rule applies once


def test_sites_google_phishing_url_from_a_pasted_email_is_investigated_and_scored(clean_registry):
    text = fixture_bytes("pasted_email_sites_google_synthetic.eml").decode("utf-8")
    target = "https://sites.google.com/view/example-mailbox-validation/login?ref=quota"

    define_module("t_g11_phish_feed", [T.URL], feed_hits)
    case = Engine(make_runtime(FakeHttp()), ScanOptions(include={"ioc_extract", "warninglists", "t_g11_phish_feed"})).investigate([Entity.make("text_blob", text)])
    node = case.graph.get(Entity.make("url", target))
    assert node is not None and not node.noise and node.investigated
    assert node.tagged("hosted_on_legit_platform")
    hit = feed_finding(case, Entity.make("url", target))
    assert hit.label is Confidence.PROBABLE and not hit.suppressed_by  # investigated and scored, never silenced
    resolver = case.graph.get(Entity.make("ipv4", "8.8.8.8"))
    assert resolver is not None and not resolver.investigated  # the resolver in the text is noise: recorded, not pivoted


# ------------------------------------------------------------------------------- FC1 bundle, FC9 licences
def test_bundle_is_within_the_size_budget_and_matches_its_manifest():
    blob = wl.bundle_path().read_bytes()
    assert len(blob) <= wl.BUNDLE_GZIP_BUDGET
    bundle = json.loads(gzip.decompress(blob))
    manifest = wl.load_manifest()
    assert manifest["bundle_sha256"] == hashlib.sha256(blob).hexdigest() and manifest["commit"] == wl.PIN_COMMIT
    assert set(manifest["lists"]) == set(bundle["lists"]) and bundle["_meta"]["commit"] == wl.PIN_COMMIT
    types = {lst["type"] for lst in bundle["lists"].values()}
    assert types <= {"string", "hostname", "cidr", "substring"}  # never a regex list (FC1)
    assert not set(bundle["lists"]) & wl.HEAVY_OPTIONAL  # heavy lists never bundled (FC9)
    assert {"vpn-ipv4", "datacenter-ipv4"} <= set(bundle["_meta"]["x4bnet_mit_lists"])
    assert all(lst["licence"] == ("MIT" if slug in wl.X4BNET_LISTS else "CC0-1.0") for slug, lst in bundle["lists"].items())


def test_regex_lists_are_excluded_and_substring_lists_only_when_bounded():
    regex = wl.parse_warninglist(fixture_bytes("common_contact_emails_regex.json"), "common-contact-emails")
    assert regex["excluded_reason"].startswith("regex list")
    sub = wl.parse_warninglist(fixture_bytes("automated_malware_analysis_substring.json"), "automated-malware-analysis")
    assert sub["type"] == "substring" and sub["bounded"] and sub["kind"] == "host" and not sub["excluded_reason"]


def test_builder_is_reproducible_and_applies_the_policy():
    parsed = {
        "public-dns-v4": wl.parse_warninglist(fixture_bytes("public_dns_v4_ok.json"), "public-dns-v4"),
        "sinkholes": wl.parse_warninglist(fixture_bytes("sinkholes_ok.json"), "sinkholes"),
        "tranco10k": wl.parse_warninglist(fixture_bytes("tranco10k_ok.json"), "tranco10k"),
        "common-contact-emails": wl.parse_warninglist(fixture_bytes("common_contact_emails_regex.json"), "common-contact-emails"),
        "tranco": wl.parse_warninglist(fixture_bytes("tranco10k_ok.json"), "tranco"),
    }
    a = wl.bundle_bytes(wl.build_compact_bundle(parsed, commit=wl.PIN_COMMIT, built="2026-11-26"))
    b = wl.bundle_bytes(wl.build_compact_bundle(parsed, commit=wl.PIN_COMMIT, built="2026-11-26"))
    assert a == b  # reproducible (sorted keys, gzip mtime 0)
    bundle = json.loads(gzip.decompress(a))
    assert bundle["lists"]["public-dns-v4"]["outcome"] == "suppress" and bundle["lists"]["sinkholes"]["category"] == "sinkhole"
    assert bundle["lists"]["tranco10k"]["outcome"] == "top_site"
    assert "regex" in bundle["excluded"]["common-contact-emails"] and "FC9" in bundle["excluded"]["tranco"]


def test_policy_table_never_suppresses_vendor_or_unknown_lists():
    assert wl.list_policy("google")["outcome"] == "top_site"  # holds docs/drive/forms.google.com (FC5)
    assert wl.list_policy("security-provider-blogpost")["outcome"] == "top_site"  # holds sites.google.com
    assert wl.list_policy("some-new-list")["outcome"] == "tag"  # unknown lists can never suppress
    assert wl.list_policy("shodan-scanning")["category"] == "benign_scanner"
    assert wl.list_policy("eicar.com")["category"] == "test_file"


def test_committed_noise_fragments_are_generated_from_the_bundle():
    bundle = json.loads(gzip.decompress(wl.bundle_path().read_bytes()))
    generated = wl.noise_fragments(bundle, checked_at="2026-11-26")
    shipped = {p.stem: json.loads(p.read_text(encoding="utf-8")) for p in (Path(wl.__file__).parents[2] / "data" / "noise").glob("misp_wl_*.json")}
    assert generated == shipped  # never hand-edited
    assert noise.errors() == [] or not any("misp" in e for e in noise.errors())


def test_core_noise_export_kinds_and_documentation_values():
    assert noise.is_sinkhole(Entity.make("ipv4", SINKHOLE_IP))
    assert noise.noise_kind(Entity.make("ipv4", CDN_IP)) == "cdn"
    assert noise.warninglists(Entity.make("ipv4", "192.0.2.1")) == []  # documentation values stay real hosts for the core
    assert noise.warninglists(Entity.make("domain", "example.com")) == []
    assert "misp.public-dns-hostname" in noise.warninglists(Entity.make("domain", "dns.google"))


def test_summary_line():
    classes = [wl.local_classification(Entity.make("ipv4", v)) for v in ("8.8.8.8", "1.1.1.1", CDN_IP)]
    assert wl.suppressed_summary_line(classes) == "2 indicators suppressed as known-benign (public-dns-v4)"
    assert wl.suppressed_summary_line([]) is None


# ------------------------------------------------------------------------------- refresh (FC1)
def test_weekly_refresh_replaces_a_bundled_list_with_the_downloaded_copy():
    url = wl.RAW_URL.format(slug="sinkholes")
    rt = make_runtime(FakeHttp().add("GET", url, body=fixture_bytes("sinkholes_ok.json")))
    result = rt.data.update("warninglists.sinkholes")
    assert result.status == "updated"
    wl.reset_cache()
    res = run(f"ipv4:{SINKHOLE_IP}")
    match = next(m for m in res.attributes["warninglist_matches"] if m["list"] == "sinkholes")
    assert match["origin"] == "downloaded" and res.attributes["warninglists_build"]["downloaded_lists"] == 1
    assert any(d["name"] == "warninglists.sinkholes" for d in res.datasets)


@pytest.mark.parametrize(
    ("kind", "response"),
    [
        ("404 body", {"status": 404, "text": "404: Not Found", "headers": {"content-type": "text/plain"}}),
        ("challenge", {"status": 200, "text": CHALLENGE, "headers": {"content-type": "text/html"}}),
        ("forbidden", {"status": 403, "text": "Forbidden"}),
        ("rate limited", {"status": 429, "text": "slow down"}),
        ("server error", {"status": 503, "text": "unavailable"}),
        ("timeout", {"error": NetworkError("ReadTimeout contacting raw.githubusercontent.com: timed out")}),
        ("truncated", {"status": 200, "body": None}),
        ("kind changed", {"status": 200, "body": "tranco"}),
    ],
)
def test_refresh_failures_keep_the_bundled_list(kind, response):
    url = wl.RAW_URL.format(slug="sinkholes")
    body = response.get("body", "unset")
    if body is None:
        response = {"status": 200, "body": fixture_bytes("truncated.json")}
    elif body == "tranco":
        response = {"status": 200, "body": fixture_bytes("tranco10k_ok.json")}  # a hostname list served for a cidr list
    http = FakeHttp().add("GET", url, **response)
    result = make_runtime(http).data.update("warninglists.sinkholes")
    assert result.status == "failed", kind
    assert not (paths.datasets_dir() / "warninglists.sinkholes").exists()
    wl.reset_cache()
    res = run(f"ipv4:{SINKHOLE_IP}")
    assert next(m for m in res.attributes["warninglist_matches"] if m["list"] == "sinkholes")["origin"] == "bundled"


def test_an_unusable_downloaded_copy_never_replaces_the_bundled_list():
    (paths.datasets_dir() / "warninglists.sinkholes").write_bytes(fixture_bytes("truncated.json"))
    res = run(f"ipv4:{SINKHOLE_IP}")
    assert next(m for m in res.attributes["warninglist_matches"] if m["list"] == "sinkholes")["origin"] == "bundled"


def test_every_bundled_list_is_a_registered_weekly_dataset():
    manifest = wl.load_manifest()
    from v3lum.core.datasets import DATASETS

    for slug in manifest["lists"]:
        reg = DATASETS[f"warninglists.{slug}"]
        assert reg["url"] == wl.RAW_URL.format(slug=slug) and reg["ttl"] == 7 * 86400 and reg["large"] is True
        assert reg["source"] == wl.SOURCE and reg["terms_class"] == "open"


# ------------------------------------------------------------------------------- failures
def test_unusable_bundle_is_could_not_verify(monkeypatch, tmp_path):
    broken = tmp_path / "broken.json.gz"
    broken.write_bytes(b"not gzip")
    monkeypatch.setattr(wl, "bundle_path", lambda: broken)
    res = run("ipv4:8.8.8.8")
    assert res.status is Status.UNAVAILABLE and res.reason_code == "dataset"


def test_parser_never_raises_on_odd_input():
    for raw in (b"", b"<html><body>proxy</body></html>", b"404: Not Found", b"[1,2]", b'{"list": "x"}', b"\xff\xfe", fixture_bytes("truncated.json")):
        parsed = wl.parse_warninglist(raw, "x")
        assert parsed["marker"] and not parsed["entries"]


def test_sinkholed_domain_rule_fixtures():
    """FC7: a domain resolving to a sinkhole is stated sinkholed (info, context only), never live C2."""
    from v3lum.core import correlate
    from v3lum.correlations import p1_g11_1

    rule_dir = FIXTURES / "rules" / p1_g11_1.RULE_ID
    for path in sorted(rule_dir.glob("*.json")):
        assert correlate.check_fixture(p1_g11_1.RULE_ID, path) == [], path.name
    fx = correlate.load_graph_fixture(rule_dir / "positive_resolves_to_sinkhole.json")
    (corr,) = [c for c in correlate.run_rules(fx.graph, fx.results, {p1_g11_1.RULE_ID}, rctx=fx.rctx)]
    assert {"sinkholed", "context_only"} <= set(corr.tags) and "hits = infected clients, not attacker infrastructure" in corr.description


GOLDEN = {"domain": "example.com", "ipv4": "8.8.8.8", "url": "https://example.com/", "sha256": EICAR_SHA256}


@pytest.mark.parametrize("etype", sorted(GOLDEN))
def test_acceptance_golden_inputs_need_no_route(etype):
    """AR21 golden path: the module is offline, so every golden input runs with an empty route list."""
    doc = json.loads((FIXTURES / "acceptance" / etype / "warninglists.json").read_text(encoding="utf-8"))
    assert doc == {"schema": "v3lum.acceptance_routes/1", "module": "warninglists", "routes": []}
    res = run(f"{etype}:{GOLDEN[etype]}")
    assert res.status in (Status.OK, Status.EMPTY)
    findings = [f for f in res.findings if f.severity.label != "info"]
    assert findings == []  # context only: never a non-info finding on a benign input


def test_module_metadata():
    assert Warninglists.disclosure == "none" and Warninglists.hosts == () and Warninglists.terms == "open"
    assert Warninglists.default_enabled is True and Warninglists.sources == ("github.warninglists_misp",)
    assert Warninglists.produces == frozenset()
