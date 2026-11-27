"""cloud_ranges (P034): shared range index, provider file parsers, labels, dataset fallbacks.

Fixtures in tests/fixtures/cloud_ranges/ are trimmed real provider files (AWS ip-ranges.json,
Google cloud.json/goog.json, Cloudflare ips-v4/v6, Fastly public-ip-list, Oracle OCI) recorded on
2026-11-26, the truncated research downloads (``*_truncated.json``) and two files labelled synthetic:
the GitHub meta schema (api.github.com/meta was refused by the research egress) and the cloudcheck
schema with documentation values (cloudcheck data is AGPL repository data: never committed).
"""

from __future__ import annotations

import hashlib
import ipaddress
import json
import random
from pathlib import Path

import pytest

from tests.fakes import FIXTURES, FakeHttp, make_runtime, run_module
from v3lum import paths
from v3lum.core import datasets
from v3lum.core.models import Status
from v3lum.modules.ip_network import cloud_ranges as cr
from v3lum.modules.ip_network.cloud_ranges import CloudRanges, RangeIndex

FIX = FIXTURES / "cloud_ranges"
OFFICIAL = {
    "cloud_ranges_aws.json": "aws_ok.json",
    "cloud_ranges_gcp_cloud.json": "gcp_cloud_ok.json",
    "cloud_ranges_google_goog.json": "google_goog_ok.json",
    "cloud_ranges_cloudflare_v4.txt": "cloudflare_v4.txt",
    "cloud_ranges_cloudflare_v6.txt": "cloudflare_v6.txt",
    "cloud_ranges_fastly.json": "fastly_ok.json",
    "cloud_ranges_oracle_oci.json": "oracle_oci_ok.json",
    "cloud_ranges_github_meta.json": "github_meta_synthetic.json",
}
ALL = {**OFFICIAL, "cloud_ranges_cloudcheck.json": "cloudcheck_synthetic.json"}
OFFICIAL_SOURCES = sorted({cr.DATASET_BY_NAME[n].source for n in OFFICIAL})
CHALLENGE = "<!DOCTYPE html><html><head><title>Just a moment...</title></head><body>cf-chl-widget</body></html>"


def install(files: dict[str, str] | None = None, *, extra: dict[str, bytes] | None = None) -> None:
    """Put local dataset copies in the isolated datasets directory (as `v3lum data update` would)."""
    target = paths.datasets_dir()
    for name, fixture_name in (ALL if files is None else files).items():
        (target / name).write_bytes((FIX / fixture_name).read_bytes())
    for name, body in (extra or {}).items():
        (target / name).write_bytes(body)


def offline_runtime():
    return make_runtime(FakeHttp(), offline=True)


def run(value: str, **kw):
    kw.setdefault("runtime", offline_runtime())  # local copies only: a missing file is never downloaded here
    return run_module(CloudRanges, value, **kw)


def titles(res):
    return {f.title for f in res.findings}


# ------------------------------------------------------------------ labels (cond 5-7, 9)
def test_cdn_edge_ip_is_noise_with_label_and_pivot_note():
    install()
    res = run("ipv4:104.16.1.1")
    assert res.status is Status.OK
    a = res.attributes
    assert a["cloud_label"] == "Cloudflare CDN edge" and a["cloud_role"] == "cdn_edge"
    assert a["is_cloud"] is True and a["is_cdn"] is True and a["is_hosting"] is False
    assert a["third_party_hosted"] is True and a["pivot_note"] == "not pivoted: shared CDN/cloud IP"
    assert a["cloud_range"] == "104.16.0.0/13" and "verdict_lifetime_days" not in a
    assert not res.pivots  # shared edges are never pivoted (and the module creates none)
    finding = res.findings[0]
    assert finding.title == "Shared CDN edge address" and "noise" in finding.tags
    assert "not pivoted: shared CDN/cloud IP" in finding.description
    assert set(a["dataset_age_days"]) == set(ALL)


def test_iaas_ip_is_not_noise_and_ec2_wins_over_s3_on_one_block():
    install()
    res = run("ipv4:3.5.140.10")
    a = res.attributes
    assert a["cloud_label"] == "AWS ap-northeast-2 EC2" and a["cloud_role"] == "iaas"
    assert a["cloud_also"] == ["AWS ap-northeast-2 S3"]
    assert a["verdict_lifetime_days"] == 14 and "third_party_hosted" not in a and "pivot_note" not in a
    assert a["is_hosting"] is True and a["is_cdn"] is False
    assert titles(res) == {"Cloud compute (IaaS) address"}
    assert "noise" not in res.findings[0].tags


@pytest.mark.parametrize(
    ("value", "label", "role"),
    [
        ("ipv4:18.228.1.1", "AWS sa-east-1 EC2", "iaas"),  # AMAZON (generic) + EC2: the specific record wins
        ("ipv4:13.32.1.1", "AWS CloudFront CDN edge", "cdn_edge"),
        ("ipv4:99.83.109.5", "AWS Global Accelerator anycast edge", "cdn_edge"),
        ("ipv4:16.12.2.9", "AWS sa-east-1 S3", "shared_hosting"),
        ("ipv4:70.232.81.1", "AWS ap-southeast-4 (Amazon network)", "provider_network"),
        ("ipv4:70.232.86.125", "AWS ap-southeast-4 EC2", "iaas"),  # a /32 nested in an AMAZON /21
        ("ipv6:2600:1f2e::1", "AWS sa-east-1 EC2", "iaas"),
        ("ipv6:2600:9000:3000::1", "AWS CloudFront CDN edge", "cdn_edge"),
        ("ipv4:34.95.130.1", "Google Cloud southamerica-east1", "iaas"),
        ("ipv4:8.8.8.8", "Google front end (Google services)", "cdn_edge"),  # goog.json only
        ("ipv4:151.101.1.1", "Fastly CDN edge", "cdn_edge"),
        ("ipv6:2606:4700::1111", "Cloudflare CDN edge", "cdn_edge"),
        ("ipv4:129.148.16.5", "Oracle OCI sa-saopaulo-1", "iaas"),
        ("ipv4:129.148.12.5", "Oracle OSN (shared service) sa-saopaulo-1", "shared_service"),
        ("ipv4:134.70.84.5", "Oracle Object Storage sa-saopaulo-1", "shared_hosting"),
    ],
)
def test_official_file_labels(value, label, role):
    install()
    res = run(value)
    assert res.status is Status.OK
    assert (res.attributes["cloud_label"], res.attributes["cloud_role"]) == (label, role)
    assert res.attributes["cloud_sources"] and all(s.startswith("cloud_ranges_") for s in res.attributes["cloud_sources"])


def test_google_cloud_range_inside_goog_json_is_compute_not_front_end():
    install()
    res = run("ipv4:34.39.200.1")  # cloud.json 34.39.128.0/17 inside goog.json 34.32.0.0/11
    assert res.attributes["cloud_role"] == "iaas" and res.attributes["cloud_label"] == "Google Cloud southamerica-east1"


def test_edge_and_iaas_labels_without_cloudcheck():
    """cond 3: the official provider files alone pass the same tests (cloudcheck not allowed here)."""
    install(OFFICIAL)
    edge = run("ipv4:104.16.1.1", allowed_sources=OFFICIAL_SOURCES)
    iaas = run("ipv4:3.5.140.10", allowed_sources=OFFICIAL_SOURCES)
    other = run("ipv4:200.160.2.3", allowed_sources=OFFICIAL_SOURCES)
    assert edge.attributes["cloud_label"] == "Cloudflare CDN edge" and edge.attributes["third_party_hosted"] is True
    assert iaas.attributes["cloud_label"] == "AWS ap-northeast-2 EC2" and iaas.attributes["verdict_lifetime_days"] == 14
    assert other.status is Status.EMPTY  # every allowed dataset loaded: 'not in the loaded ranges'
    assert "github.cloud_ranges_cloudcheck" not in edge.source_statuses
    assert all(d["name"] != "cloud_ranges_cloudcheck.json" for d in edge.datasets)


def test_official_files_win_over_cloudcheck():
    install()
    res = run("ipv4:18.228.1.9")  # cloudcheck synthetic 'Amazon' 18.228.1.0/24 is more specific, but runtime data
    assert res.attributes["cloud_label"] == "AWS sa-east-1 EC2"
    assert res.attributes["cloud_sources"] == ["cloud_ranges_aws.json"]


def test_cloudcheck_runtime_labels_through_the_module():
    """cloudcheck covers providers without an official file; roles come from the V3LUM table."""
    install(OFFICIAL)
    synthetic = {
        "_synthetic": "cloudcheck v3 schema, public example ranges for module-level tests",
        "DigitalOcean": {"name": "DigitalOcean", "tags": ["cloud"], "cidrs": ["64.225.0.0/17"]},
        "Akamai": {"name": "Akamai", "tags": ["cloud"], "cidrs": ["45.79.0.0/16"]},
        "Zscaler": {"name": "Zscaler", "tags": ["cloud"], "cidrs": ["165.225.0.0/17"]},
        "Imperva": {"name": "Imperva", "tags": ["waf"], "cidrs": ["45.60.0.0/16"]},
        "DoD": {"name": "DoD", "tags": ["gov"], "cidrs": ["214.0.0.0/8"]},
    }
    install({}, extra={"cloud_ranges_cloudcheck.json": json.dumps(synthetic).encode()})
    do = run("ipv4:64.225.1.1")
    assert do.attributes["cloud_label"] == "DigitalOcean IaaS compute (cloudcheck)" and do.attributes["cloud_role"] == "iaas"
    assert "rented or provider compute" in do.findings[0].description.lower()
    akamai = run("ipv4:45.79.10.10")  # Akamai space includes Linode compute: never hidden as noise
    assert akamai.attributes["cloud_role"] == "provider_network" and "third_party_hosted" not in akamai.attributes
    zscaler = run("ipv4:165.225.1.1")
    assert zscaler.attributes["cloud_role"] == "shared_proxy" and zscaler.attributes["third_party_hosted"] is True
    imperva = run("ipv4:45.60.1.1")
    assert imperva.attributes["cloud_role"] == "cdn_edge" and imperva.attributes["is_cdn"] is True
    gov = run("ipv4:214.1.1.1")  # government networks are not cloud
    assert gov.status is Status.EMPTY


# ------------------------------------------------------------------ rule 5 (cond 4)
def test_missing_dataset_is_unavailable_never_not_cloud():
    install(OFFICIAL)  # cloudcheck missing; the offline runtime cannot download it
    res = run("ipv4:200.160.2.3")
    assert res.status is Status.UNAVAILABLE and res.reason_code == "dataset"
    assert "cloud_ranges_cloudcheck.json" in res.error and "could not verify" in res.error
    feed = res.source_statuses["github.cloud_ranges_cloudcheck"]
    assert feed["status"] == "unavailable" and feed["reason_code"] == "dataset"


def test_no_dataset_at_all_is_unavailable():
    res = run("ipv4:104.16.1.1")
    assert res.status is Status.UNAVAILABLE and res.reason_code == "dataset"
    assert not res.findings and "is_cloud" not in res.attributes


def test_a_match_stands_when_another_dataset_is_missing():
    install(OFFICIAL)
    res = run("ipv4:104.16.1.1")
    assert res.status is Status.OK and res.attributes["cloud_label"] == "Cloudflare CDN edge"
    assert res.source_statuses["github.cloud_ranges_cloudcheck"]["status"] == "unavailable"


def test_not_in_any_range_is_empty_with_dataset_ages():
    install()
    res = run("ipv4:200.160.2.3")
    assert res.status is Status.EMPTY and set(res.attributes["dataset_age_days"]) == set(ALL)
    assert not res.findings and not res.pivots


def test_private_and_documentation_addresses_are_not_applicable():
    install()
    for value in ("ipv4:10.1.2.3", "ipv4:192.0.2.10", "ipv6:2001:db8::1", "cidr:192.168.0.0/16"):
        res = run(value)
        assert res.status is Status.SKIPPED and res.reason_code == "not_applicable"


def test_cidr_inputs_contained_and_partial_overlap():
    install()
    inside = run("cidr:104.16.8.0/24")
    assert inside.attributes["cloud_label"] == "Cloudflare CDN edge" and inside.attributes["cloud_range"] == "104.16.0.0/13"
    overlap = run("cidr:104.0.0.0/11")  # wider than 104.16.0.0/13 and 104.24.0.0/14
    assert overlap.status is Status.OK and titles(overlap) == {"Network partially overlaps cloud/CDN ranges"}
    assert "is_cloud" not in overlap.attributes
    outside = run("cidr:200.160.0.0/20")
    assert outside.status is Status.EMPTY


# ------------------------------------------------------------------ downloads (cond 2-4)
def _routes(http: FakeHttp, overrides: dict[str, dict]) -> None:
    for spec in cr.DATASETS:
        http.add("GET", spec.url, **overrides.get(spec.name, {"status": 500, "text": "upstream down"}))


def test_downloads_are_validated_before_they_replace_anything():
    http = FakeHttp()
    v4 = (FIX / "cloudflare_v4.txt").read_bytes()
    _routes(http, {
        "cloud_ranges_cloudflare_v4.txt": {"body": v4, "headers": {"content-type": "text/plain;charset=UTF-8"}},
        "cloud_ranges_cloudflare_v6.txt": {"body": (FIX / "cloudflare_v6.txt").read_bytes(), "headers": {"content-type": "text/plain"}},
        "cloud_ranges_fastly.json": {"json": json.loads((FIX / "fastly_ok.json").read_text())},
        "cloud_ranges_aws.json": {"json": json.loads((FIX / "aws_ok.json").read_text())},  # far below 500 KB: rejected
        "cloud_ranges_gcp_cloud.json": {"status": 403, "text": CHALLENGE},  # challenge page: rejected
        "cloud_ranges_google_goog.json": {"body": (FIX / "gcp_cloud_truncated.json").read_bytes(), "headers": {"content-type": "application/json"}},
        "cloud_ranges_github_meta.json": {"status": 429, "text": "slow down"},
    })
    res = run_module(CloudRanges, "ipv4:104.16.1.1", http)
    assert res.status is Status.OK and res.attributes["cloud_label"] == "Cloudflare CDN edge"
    store = paths.datasets_dir()
    assert (store / "cloud_ranges_cloudflare_v4.txt").read_bytes() == v4
    assert (store / "cloud_ranges_fastly.json").is_file()
    for rejected in ("cloud_ranges_aws.json", "cloud_ranges_gcp_cloud.json", "cloud_ranges_google_goog.json",
                     "cloud_ranges_oracle_oci.json", "cloud_ranges_github_meta.json", "cloud_ranges_cloudcheck.json"):
        assert not (store / rejected).exists(), rejected
    for source in ("aws.ip_ranges", "gstatic.cloud_ip_ranges", "gstatic.google_ip_ranges", "oracle.oci_public_ip_ranges",
                   "github.cloud_ranges_meta", "github.cloud_ranges_cloudcheck"):
        assert res.source_statuses[source]["status"] == "unavailable", source
    http.assert_hosts_within(CloudRanges, extra={(s.url.split('/')[2]) for s in cr.DATASETS})


def test_failed_refresh_keeps_the_last_good_copy_with_its_date():
    install()
    name = "cloud_ranges_cloudflare_v4.txt"
    body = (FIX / "cloudflare_v4.txt").read_bytes()
    manifest = {"schema": "v3lum.datasets_manifest/1", "datasets": {name: {
        "url": cr.DATASET_BY_NAME[name].url, "fetched_at": "2026-11-10T12:00:00Z", "sha256": hashlib.sha256(body).hexdigest(),
        "bytes": len(body), "etag": "", "last_modified": "", "licence": "public", "terms_class": "open", "attribution": "",
        "provider": "cloudflare", "source": "cloudflare.ips", "stale": False}}}
    (paths.datasets_dir() / "MANIFEST.json").write_text(json.dumps(manifest))
    http = FakeHttp().add("GET", cr.DATASET_BY_NAME[name].url, status=403, text=CHALLENGE)
    res = run_module(CloudRanges, "ipv4:104.16.1.1", http)
    assert res.status is Status.OK and res.attributes["cloud_label"] == "Cloudflare CDN edge"
    assert (paths.datasets_dir() / name).read_bytes() == body  # the stale copy survived the challenge page
    assert res.attributes["dataset_age_days"][name] == pytest.approx(16.0, abs=0.01)
    assert "Cloud range data older than 7 days" in titles(res)


# ------------------------------------------------------------------ parsers and validation
@pytest.mark.parametrize(
    ("parser", "fixture_name", "minimum"),
    [
        (cr.parse_aws_ip_ranges, "aws_ok.json", 18),
        (cr.parse_gcp_cloud, "gcp_cloud_ok.json", 5),
        (cr.parse_google_goog, "google_goog_ok.json", 7),
        (cr.parse_cloudflare_v4, "cloudflare_v4.txt", 15),
        (cr.parse_cloudflare_v6, "cloudflare_v6.txt", 7),
        (cr.parse_fastly, "fastly_ok.json", 24),
        (cr.parse_oracle_oci, "oracle_oci_ok.json", 5),
        (cr.parse_github_meta, "github_meta_synthetic.json", 12),
        (cr.parse_cloudcheck, "cloudcheck_synthetic.json", 6),
    ],
)
def test_provider_file_parsers(parser, fixture_name, minimum):
    parsed = parser((FIX / fixture_name).read_bytes())
    assert not parsed.error
    assert len(parsed.records) >= minimum
    assert all(ipaddress.ip_network(r.cidr) for r in parsed.records)


def test_parser_metadata_and_cloudcheck_skips():
    aws = cr.parse_aws_ip_ranges((FIX / "aws_ok.json").read_bytes())
    assert aws.meta == {"sync_token": "1795657625", "created": "2026-11-26-01-47-05"}
    check = cr.parse_cloudcheck((FIX / "cloudcheck_synthetic.json").read_bytes())
    assert check.meta["skipped_providers"] == ["DoD"] and check.skipped == 1  # 'not-a-cidr'
    assert all(not r.official for r in check.records)
    roles = {r.provider: r.role for r in check.records}
    assert roles["Akamai"] == "provider_network" and roles["DigitalOcean"] == "iaas" and roles["Zscaler"] == "shared_proxy"
    assert roles["Newcdn"] == "provider_network"  # an unreviewed provider is never noise


@pytest.mark.parametrize(
    ("parser", "fixture_name"),
    [(cr.parse_aws_ip_ranges, "aws_truncated.json"), (cr.parse_gcp_cloud, "gcp_cloud_truncated.json"), (cr.parse_oracle_oci, "oracle_oci_truncated.json")],
)
def test_truncated_downloads_are_rejected(parser, fixture_name):
    assert "malformed JSON" in parser((FIX / fixture_name).read_bytes()).error


def test_error_and_html_bodies_are_never_an_empty_list():
    assert "HTML" in cr.parse_cloudflare_v4(CHALLENGE).error
    assert "no range lists" in cr.parse_github_meta({"message": "API rate limit exceeded for 203.0.113.1."}).error
    assert cr.parse_fastly({"unexpected": True}).error
    assert cr.parse_cloudcheck({}).error


def test_validators_check_entry_counts(tmp_path):
    spec = cr.DATASET_BY_NAME["cloud_ranges_cloudflare_v4.txt"]
    good = tmp_path / "v4.txt"
    good.write_bytes((FIX / "cloudflare_v4.txt").read_bytes())
    assert cr._validator(spec)(good) is True
    short = tmp_path / "short.txt"
    short.write_text("104.16.0.0/13\n")
    with pytest.raises(ValueError, match="too few valid entries"):
        cr._validator(spec)(short)
    html = tmp_path / "page.html"
    html.write_text(CHALLENGE)
    with pytest.raises(ValueError, match="HTML"):
        cr._validator(spec)(html)


def test_too_broad_and_invalid_entries_are_dropped():
    parsed = cr.parse_cloudflare_v4("0.0.0.0/0\n1.0.0.0/7\n104.16.0.0/13\nnot-a-cidr\n# comment\n")
    assert [r.cidr for r in parsed.records] == ["104.16.0.0/13"]
    assert parsed.too_broad == 2 and parsed.skipped == 1
    v6 = cr.parse_cloudflare_v6("2000::/3\n2606:4700::/32\n")
    assert [r.cidr for r in v6.records] == ["2606:4700::/32"] and v6.too_broad == 1


def test_datasets_are_registered_with_sources_licences_and_terms():
    for spec in cr.DATASETS:
        reg = datasets.DATASETS[spec.name]
        assert reg["source"] == spec.source and reg["terms_class"] == "open" and reg["licence"]
        assert reg["ttl"] == 86400 and reg["validate"] is not None
    assert "AGPL" in datasets.DATASETS["cloud_ranges_cloudcheck.json"]["licence"]
    assert datasets.dataset_errors() == [] or all("cloud_ranges" not in e for e in datasets.dataset_errors())


# ------------------------------------------------------------------ the shared index (cond 1)
def test_range_index_matches_brute_force():
    rng = random.Random(34)
    cidrs: list[str] = []
    for _ in range(300):
        base = rng.randrange(0, 2**32)
        plen = rng.choice([8, 12, 16, 20, 24, 28, 32])
        cidrs.append(str(ipaddress.ip_network((base, plen), strict=False)))
    for _ in range(60):
        base = rng.randrange(0, 2**128)
        cidrs.append(str(ipaddress.ip_network((base, rng.choice([19, 32, 48, 64, 128])), strict=False)))
    index = RangeIndex((c, c) for c in cidrs)
    nets = [ipaddress.ip_network(c) for c in cidrs]
    probes = [ipaddress.ip_address(rng.randrange(0, 2**32)) for _ in range(400)]
    probes += [n.network_address for n in nets[:200]] + [n.broadcast_address for n in nets[:200]]
    probes += [ipaddress.ip_address(rng.randrange(0, 2**128)) for _ in range(50)] + [n.network_address for n in nets[300:]]
    for ip in probes:
        expected = sorted((n for n in nets if n.version == ip.version and ip in n), key=lambda n: -n.prefixlen)
        got = [ipaddress.ip_network(c) for c in index.lookup(ip)]
        assert sorted(got, key=lambda n: (-n.prefixlen, int(n.network_address))) == sorted(expected, key=lambda n: (-n.prefixlen, int(n.network_address)))
        if got:  # innermost first
            assert got[0].prefixlen == max(n.prefixlen for n in expected)


def test_range_index_cidr_lookup_and_mapped_addresses():
    index = RangeIndex([("10.0.0.0/8", "a"), ("10.1.0.0/16", "b"), ("10.1.2.0/24", "c"), ("2001:db8::/32", "v6")])
    assert index.lookup("10.1.2.3") == ("c", "b", "a")
    assert index.lookup("::ffff:10.1.9.9") == ("b", "a")  # IPv4-mapped IPv6 uses the IPv4 table
    assert index.lookup_cidr("10.1.0.0/20") == ("b", "a") and index.lookup_cidr("10.0.0.0/7") == ()
    assert index.lookup("2001:db8::1") == ("v6",) and index.lookup("not-an-ip") == () and len(index) == 4
    assert "10.200.0.1" in index and "11.0.0.1" not in index
    assert index.overlapping("10.0.0.0/7") == ("a", "b", "c")  # wider than every block: all intersect
    assert index.overlapping("10.1.2.128/25") == ("c", "b", "a") and index.overlapping("12.0.0.0/8") == ()


# ------------------------------------------------------------------ core helpers (cond 1, 8)
def test_local_classification_noise_hook_and_active_guard():
    install()
    assert cr.noise_kind_for("104.16.1.1") == "cdn"
    assert cr.noise_kind_for("16.12.2.9") == "hosting"
    assert cr.noise_kind_for("3.5.140.10") is None  # rented compute is never noise
    assert cr.local_classification("200.160.2.3") is None
    fresh = {spec.name: {"present": True, "age_days": 1.0, "stale": False} for spec in cr.DATASETS}
    assert "shared CDN/cloud infrastructure" in cr.active_guard("104.16.1.1", status=fresh)
    assert cr.active_guard("104.16.1.1", status=fresh, scope_lists_target=True) is None
    assert cr.active_guard("3.5.140.10", status=fresh) is None
    old = dict(fresh, **{"cloud_ranges_aws.json": {"present": True, "age_days": 8.5, "stale": True}})
    assert "fail closed" in cr.active_guard("3.5.140.10", status=old)
    missing = dict(fresh, **{"cloud_ranges_fastly.json": {"present": False, "age_days": None, "stale": True}})
    assert "missing (fail closed)" in cr.active_guard("3.5.140.10", status=missing)


def test_classify_precedence_and_noise_flags():
    rec = cr.CloudRecord
    chain = [rec("3.5.140.0/22", "AWS", "S3", "x", "shared_hosting", "cloud_ranges_aws.json"),
             rec("3.5.140.0/22", "AWS", "EC2", "x", "iaas", "cloud_ranges_aws.json"),
             rec("3.5.140.0/22", "AWS", "AMAZON", "x", "provider_network", "cloud_ranges_aws.json", generic=True)]
    cls = cr.classify(chain)
    assert cls["role"] == "iaas" and cls["noise"] is False and cls["also"] == ["AWS x S3"]
    assert cr.classify([]) is None
    edge = cr.classify([rec("104.16.0.0/13", "Cloudflare", "CDN edge", "", "cdn_edge", "cloud_ranges_cloudflare_v4.txt")])
    assert edge["noise"] and edge["third_party_hosted"] and edge["pivot_note"] == cr.NOISE_PIVOT_NOTE


def test_module_declarations():
    assert CloudRanges.disclosure == "none" and CloudRanges.hosts == () and CloudRanges.terms == "open"
    assert CloudRanges.default_enabled is True and CloudRanges.trust_tier == "n/a"
    assert set(CloudRanges.sources) == {spec.source for spec in cr.DATASETS}
    assert Path(cr.__file__).read_text().count("register_dataset(") == 1  # one loop registers every file
