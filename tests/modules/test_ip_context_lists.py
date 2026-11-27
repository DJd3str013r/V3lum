"""ip_context_lists (P035): offline context labels, Private Relay suppression, rule 5 for missing lists.

Fixtures in tests/fixtures/ip_context_lists/ are trimmed real list heads recorded on 2026-11-26 from a
datacenter egress (X4BNet vpn/datacenter IPv4 and IPv6 heads, the mthcht ProtonVPN/Mullvad/Surfshark,
DynDNS and suspicious-user-agent CSV heads, an Apple Private Relay slice with IPv4 and IPv6 ranges and a
truncated tail, the FireHOL firehol_proxies and socks_proxy_30d ipset headers with their proxy entries
replaced by documentation addresses, a raw.githubusercontent.com '404: Not Found' body and the FireHOL
nginx 404 page) plus two labelled synthetic files: the RMM CSV layout (the real RMM path is unverified)
and an X4BNet head with one Private Relay range added (suppression test).
"""

from __future__ import annotations

import hashlib
import json

import pytest

from tests.fakes import FIXTURES, FakeHttp, make_runtime, run_module
from v3lum import paths
from v3lum.core import policy
from v3lum.core.context import RunInfo, ScanOptions
from v3lum.core.datasets import DATASETS
from v3lum.core.entities import Entity, EntityType
from v3lum.core.models import Status
from v3lum.modules.ip_network import ip_context_lists as icl
from v3lum.modules.ip_network.ip_context_lists import (
    FIREHOL_NOT_WIRED,
    LIST_BY_KEY,
    LISTS,
    SRC_FIREHOL,
    SRC_RELAY,
    SRC_UA,
    SRC_X4B,
    IpContextLists,
    domain_match,
    firehol_upstream_plan,
    parse_cidr_lines,
    parse_domain_csv,
    parse_firehol_header,
    parse_ip_csv,
    parse_relay_csv,
    parse_ua_csv,
)

FIX = FIXTURES / "ip_context_lists"
FILES = {
    "x4bnet_vpn_ipv4": "x4bnet_vpn_ipv4_head.txt",
    "x4bnet_vpn_ipv6": "x4bnet_vpn_ipv6_head.txt",
    "x4bnet_datacenter_ipv4": "x4bnet_datacenter_ipv4_head.txt",
    "x4bnet_datacenter_ipv6": "x4bnet_datacenter_ipv6_head.txt",
    "mthcht_vpn_protonvpn": "mthcht_vpn_protonvpn_head.csv",
    "mthcht_vpn_mullvad": "mthcht_vpn_mullvad_head.csv",
    "mthcht_vpn_surfshark": "mthcht_vpn_surfshark_head.csv",
    "mthcht_dyndns": "mthcht_dyndns_head.csv",
    "mthcht_suspicious_ua": "mthcht_suspicious_ua_head.csv",
    "apple_private_relay": "private_relay_slice.csv",
}
OPEN_SOURCES = {spec.source for spec in LISTS}
CHALLENGE = "<!DOCTYPE html><html><head><title>Just a moment...</title></head><body>cf-chl-widget</body></html>"


def install(files: dict[str, str] | None = None) -> None:
    """Local dataset copies, as `v3lum data update` would leave them."""
    for key, fixture_name in (FILES if files is None else files).items():
        (paths.datasets_dir() / LIST_BY_KEY[key].dataset).write_bytes((FIX / fixture_name).read_bytes())


def old_manifest(*keys: str, fetched_at: str = "2026-11-10T12:00:00Z") -> None:
    """Record the copies of ``keys`` as fetched on ``fetched_at`` (16 days before the frozen clock)."""
    entries = {}
    for key in keys:
        spec = LIST_BY_KEY[key]
        body = (paths.datasets_dir() / spec.dataset).read_bytes()
        entries[spec.dataset] = {"url": spec.url, "fetched_at": fetched_at, "sha256": hashlib.sha256(body).hexdigest(), "bytes": len(body),
                                 "etag": "", "last_modified": "", "licence": spec.licence, "terms_class": "open", "attribution": spec.attribution,
                                 "provider": spec.source.split(".")[0], "source": spec.source, "stale": False}
    (paths.datasets_dir() / "MANIFEST.json").write_text(json.dumps({"schema": "v3lum.datasets_manifest/1", "datasets": entries}))


def run(value: str, http: FakeHttp | None = None, **kw):
    if http is None:
        kw.setdefault("runtime", make_runtime(FakeHttp(), offline=True))  # local copies only
    return run_module(IpContextLists, value, http, **kw)


def statuses(res):
    return {sid: row["status"] for sid, row in res.source_statuses.items()}


# ------------------------------------------------------------------ c5: context tags, never verdicts
def test_x4bnet_vpn_and_datacenter_labels_are_context_only():
    install()
    res = run("ipv4:2.26.8.5")
    assert res.status is Status.OK
    assert res.attributes["context_tags"] == ["vpn"] and res.attributes["is_vpn"] is True
    row = res.attributes["context_matches"][0]
    assert row["list"] == "ip_context_lists.x4bnet_vpn_ipv4.txt" and row["matched"] == "2.26.8.0/22" and row["stale"] is False
    assert len(row["dataset_sha256"]) == 16 and "X4BNet" in res.attributes["data_attribution"]
    (finding,) = res.findings
    assert finding.severity.label == "info" and {"context_only", "vpn"} <= set(finding.tags)
    assert not ({"malicious", "suspicious", "blocklisted"} & set(finding.tags))
    assert not res.pivots
    dc = run("ipv4:1.12.3.4")
    assert dc.attributes["context_tags"] == ["datacenter"] and dc.attributes["is_hosting"] is True and "is_vpn" not in dc.attributes


@pytest.mark.parametrize(
    ("value", "label"),
    [
        ("ipv4:45.14.71.15", "ProtonVPN server"),  # exit IP column
        ("ipv4:185.159.156.56", "ProtonVPN server"),  # entry IP column
        ("ipv6:2a04:27c0:0:e::f001", "Mullvad VPN relay"),
        ("ipv4:89.187.161.24", "Surfshark VPN server"),
        ("ipv6:2001:ac8::1", "X4BNet VPN ranges"),
    ],
)
def test_vpn_server_lists_match_ipv4_and_ipv6(value, label):
    install()
    res = run(value)
    assert res.status is Status.OK and res.attributes["context_tags"] == ["vpn"]
    assert {m["label"] for m in res.attributes["context_matches"]} == {label}


# ------------------------------------------------------------------ c6: privacy_relay suppression
def test_privacy_relay_suppresses_vpn_labels_and_is_never_an_anonymiser():
    install(dict(FILES, x4bnet_vpn_ipv4="x4bnet_vpn_ipv4_relay_overlap_synthetic.txt"))
    res = run("ipv4:172.224.226.5")
    assert res.status is Status.OK
    assert res.attributes["context_tags"] == ["privacy_relay"]
    assert "is_vpn" not in res.attributes and "is_proxy" not in res.attributes
    relay = res.attributes["privacy_relay"]
    assert relay == {"range": "172.224.226.0/27", "country": "GB", "region": "GB-EN", "city": "London",
                     "dataset": "ip_context_lists.apple_private_relay.csv"}
    vpn_row = next(r for r in res.attributes["context_matches"] if r["tag"] == "vpn")
    assert vpn_row["suppressed_by"] == "privacy_relay"
    for finding in res.findings:  # CR28 reads vpn/proxy/anonymizer tags: none on a relay range
        assert not ({"vpn", "proxy", "anonymizer", "malicious"} & set(finding.tags))
        assert finding.severity.label == "info"
    (finding,) = res.findings
    assert finding.title == "Apple iCloud Private Relay egress address" and "privacy_relay" in finding.tags
    assert "suppressed" in finding.description and finding.data["suppressed"] == ["vpn"]


def test_privacy_relay_ipv6_range_with_geo_hint():
    install()
    res = run("ipv6:2a02:26f7:d980:ed2f::1")
    assert res.attributes["context_tags"] == ["privacy_relay"]
    assert res.attributes["privacy_relay"]["city"] == "Tandil" and res.attributes["privacy_relay"]["country"] == "AR"


# ------------------------------------------------------------------ CIDR input
def test_cidr_inside_a_listed_block_and_partial_overlap():
    install()
    inside = run("cidr:2.26.9.0/24")
    assert inside.status is Status.OK and inside.attributes["context_tags"] == ["vpn"]
    overlap = run("cidr:2.26.0.0/16")
    assert overlap.status is Status.OK and "context_tags" not in overlap.attributes and "is_vpn" not in overlap.attributes
    assert overlap.findings[0].title == "CIDR overlaps context-list ranges"
    assert all(r.get("partial") for r in overlap.attributes["context_matches"])


# ------------------------------------------------------------------ c2: rule 5 for missing/stale lists
def test_not_on_any_list_is_empty_and_names_what_was_not_checked():
    install()
    res = run("ipv4:8.8.8.8")
    assert res.status is Status.EMPTY
    assert "absence is not a verdict" in res.error and "proxy: not checked" in res.error
    assert set(res.attributes["dataset_age_days"]) == {LIST_BY_KEY[k].dataset for k in FILES if LIST_BY_KEY[k].group == "ip"}


def test_missing_list_gives_unavailable_never_not_a_vpn():
    install({k: v for k, v in FILES.items() if k != "apple_private_relay"})
    res = run("ipv4:8.8.8.8")
    assert res.status is Status.UNAVAILABLE and res.reason_code == "dataset"
    assert "not checked" in res.error and "apple_private_relay" in res.error
    assert statuses(res)[SRC_RELAY] == "unavailable"
    assert "v3lum data update" in res.source_statuses[SRC_RELAY]["reason"]


def test_a_match_still_reports_the_lists_that_were_not_checked():
    install({"x4bnet_vpn_ipv4": FILES["x4bnet_vpn_ipv4"]})
    res = run("ipv4:2.26.8.5")
    assert res.status is Status.OK and res.attributes["context_tags"] == ["vpn"]
    assert statuses(res)[SRC_RELAY] == "unavailable" and statuses(res)["github.ip_context_lists_mthcht_vpn"] == "unavailable"
    finding = res.findings[0]  # the VPN label could not be checked against the Private Relay ranges: said so
    assert finding.data["privacy_relay_checked"] is False and "Private Relay list was not checked" in finding.description


def test_large_relay_list_is_never_downloaded_during_a_run():
    install({k: v for k, v in FILES.items() if k != "apple_private_relay"})
    http = FakeHttp()  # no route: any download attempt would fail the test (UnexpectedRequest)
    res = run_module(IpContextLists, "ipv4:8.8.8.8", http)
    assert res.status is Status.UNAVAILABLE and http.calls == []
    assert "large list" in res.source_statuses[SRC_RELAY]["reason"]
    assert DATASETS[LIST_BY_KEY["apple_private_relay"].dataset]["large"] is True


def test_stale_copy_miss_is_not_checked_and_refresh_failure_keeps_the_copy():
    install()
    old_manifest("x4bnet_vpn_ipv4")
    spec = LIST_BY_KEY["x4bnet_vpn_ipv4"]
    body = (paths.datasets_dir() / spec.dataset).read_bytes()
    http = FakeHttp().add("GET", spec.url, status=404, text=(FIX / "github_raw_not_found.txt").read_text())
    res = run_module(IpContextLists, "ipv4:8.8.8.8", http)
    assert res.status is Status.UNAVAILABLE and res.reason_code == "dataset"
    assert "stale copy" in res.source_statuses[SRC_X4B]["reason"]
    assert (paths.datasets_dir() / spec.dataset).read_bytes() == body  # the failed refresh replaced nothing
    http.assert_hosts_within(IpContextLists, extra={"raw.githubusercontent.com"})


def test_stale_copy_positive_match_is_reported_and_flagged():
    install()
    old_manifest("x4bnet_vpn_ipv4")
    spec = LIST_BY_KEY["x4bnet_vpn_ipv4"]
    http = FakeHttp().add("GET", spec.url, status=403, text=CHALLENGE)
    res = run_module(IpContextLists, "ipv4:2.26.8.5", http)
    assert res.status is Status.OK and res.attributes["context_tags"] == ["vpn"]
    row = res.attributes["context_matches"][0]
    assert row["stale"] is True and row["age_days"] == pytest.approx(16.0, abs=0.01)
    assert "stale list copy" in res.findings[0].description


@pytest.mark.parametrize(
    "route",
    [
        {"status": 200, "text": (FIX / "github_raw_not_found.txt").read_text(), "headers": {"content-type": "text/plain"}},
        {"status": 200, "text": CHALLENGE, "headers": {"content-type": "text/html"}},
        {"status": 200, "body": (FIX / "x4bnet_vpn_ipv4_head.txt").read_bytes(), "headers": {"content-type": "text/plain"}},  # too few entries
    ],
)
def test_invalid_downloads_never_install_a_copy(route):
    install({k: v for k, v in FILES.items() if k != "x4bnet_vpn_ipv4"})
    spec = LIST_BY_KEY["x4bnet_vpn_ipv4"]
    http = FakeHttp().add("GET", spec.url, **route)
    res = run_module(IpContextLists, "ipv4:2.26.8.5", http)
    assert not (paths.datasets_dir() / spec.dataset).exists()
    assert res.status is Status.UNAVAILABLE and statuses(res)[SRC_X4B] == "unavailable"


def test_validator_refuses_html_short_and_truncated_bodies(tmp_path):
    validate = DATASETS[LIST_BY_KEY["apple_private_relay"].dataset]["validate"]
    bad = tmp_path / "relay.csv"
    bad.write_bytes((FIX / "private_relay_truncated.csv").read_bytes())
    with pytest.raises(ValueError, match="minimum"):
        validate(bad)
    html = tmp_path / "page.html"
    html.write_bytes((FIX / "firehol_upstream_not_found.html").read_bytes())
    with pytest.raises(ValueError, match="HTML"):
        DATASETS[LIST_BY_KEY["x4bnet_vpn_ipv4"].dataset]["validate"](html)
    good = tmp_path / "v4.txt"
    good.write_text("\n".join(f"203.{i // 256}.{i % 256}.0/24" for i in range(600)))  # documentation-like filler, 600 blocks
    assert DATASETS[LIST_BY_KEY["x4bnet_vpn_ipv4"].dataset]["validate"](good) is True


# ------------------------------------------------------------------ c7: domain and user-agent matching
@pytest.mark.parametrize(
    ("value", "matched", "exact"),
    [("host.mooo.com", "mooo.com", False), ("mooo.com", "mooo.com", True), ("a.b.us.to", "us.to", False)],
)
def test_dyndns_matches_on_label_boundaries(value, matched, exact):
    install()
    res = run(f"domain:{value}")
    assert res.status is Status.OK and res.attributes["context_tags"] == ["dynamic_dns"]
    row = res.attributes["context_matches"][0]
    assert row["matched"] == matched and row["entry"]["provider"] == "afraid.org"
    finding = res.findings[0]
    assert finding.title == "Dynamic DNS provider domain" and {"dynamic_dns", "context_only"} <= set(finding.tags)
    assert (row["matched"] == value) is exact


@pytest.mark.parametrize("value", ["notmooo.com", "mooo.com.example.net", "example.com"])
def test_dyndns_never_matches_substrings(value):
    install()
    res = run(f"domain:{value}")
    assert res.status is Status.EMPTY and "rmm_tool: not checked" in res.error


def test_rmm_layout_and_wildcard_rows():
    parsed = parse_domain_csv((FIX / "mthcht_rmm_synthetic.csv").read_bytes())
    assert parsed.entries == 5 and parsed.stats["wildcard"] == 1
    assert domain_match("relay.splashtop.com", parsed.data)["matched"] == "splashtop.com"
    assert domain_match("splashtop.com", parsed.data) is None  # '*.x' rows match sub-domains only
    assert domain_match("web.anydesk.com", parsed.data)["meta"]["tool"] == "AnyDesk"


def test_user_agent_lists_match_exactly():
    install()
    hit = run("user_agent:Mozilla/5.0 (ARTEX)")
    assert hit.status is Status.OK and hit.attributes["context_tags"] == ["suspicious_user_agent"]
    assert hit.attributes["context_matches"][0]["entry"]["tool"] == "ARTEX"
    assert hit.findings[0].severity.label == "info" and "context_only" in hit.findings[0].tags
    for miss in ("mozilla/5.0 (artex)", "Mozilla/5.0 (ARTEX) extra", "artex-scan/1.0", "x CyberStrikeAI-WebShell/1.0"):
        assert run(f"user_agent:{miss}").status is Status.EMPTY, miss
    parsed = parse_ua_csv((FIX / "mthcht_suspicious_ua_head.csv").read_bytes())
    assert parsed.stats["exact"] == 2 and parsed.stats["wildcard"] == 2  # glob rows set aside, never matched


# ------------------------------------------------------------------ c4: FireHOL per upstream, licence in coverage
def test_firehol_header_names_its_upstreams_and_nothing_is_wired():
    header = parse_firehol_header((FIX / "firehol_proxies_header.netset").read_bytes())
    assert header["name"] == "firehol_proxies" and header["category"] == "anonymizers"
    assert header["includes"] == ["iblocklist_proxies", "ip2proxy_px1lite", "socks_proxy_30d", "sslproxies_30d"]
    assert header["entries_subnets"] == 2599783 and header["source_url"] == ""
    plan = firehol_upstream_plan(header)
    assert plan["consume_aggregate"] is False and plan["wired"] == []
    assert plan["unrecorded"] == header["includes"]  # no upstream terms recorded: none is wired
    socks = parse_firehol_header((FIX / "firehol_socks_proxy_30d_header.ipset").read_bytes())
    assert socks["name"] == "socks_proxy_30d" and socks["maintainer"] == "Free Proxy List" and socks["aggregation"] == "30 days"


def test_firehol_noncommercial_upstream_is_licence_blocked_in_coverage():
    header = parse_firehol_header((FIX / "firehol_proxies_header.netset").read_bytes())
    terms = {"socks_proxy_30d": "noncommercial", "sslproxies_30d": "open", "iblocklist_proxies": "noncommercial"}
    plan = firehol_upstream_plan(header, terms)
    assert plan["wired"] == ["sslproxies_30d"] and plan["licence_blocked"] == ["socks_proxy_30d"]
    assert plan["unavailable"] == ["iblocklist_proxies"] and plan["unrecorded"] == ["ip2proxy_px1lite"]
    assert plan["coverage"] == [{"source": "firehol.proxies:socks_proxy_30d", "status": "skipped", "reason_code": "licence",
                                 "reason": "skipped: noncommercial terms (licence profile corporate)"}]
    allowed = firehol_upstream_plan(header, terms, licence_allow={"socks_proxy_30d"})
    assert allowed["wired"] == ["socks_proxy_30d", "sslproxies_30d"] and allowed["coverage"] == []


def test_corporate_profile_blocks_the_firehol_source_and_keeps_the_open_lists():
    from v3lum.core import module as module_mod

    module_mod.load_modules()
    install()
    rt = make_runtime(FakeHttp(), offline=True)
    ip = Entity.make(EntityType.IPV4, "2.26.8.5")
    decision = policy.decide(IpContextLists, ip, policy.make_context(rt, ScanOptions(), path="scan"), run=RunInfo(entity=ip, is_seed=True))
    assert decision.allowed and set(decision.allowed_sources) == OPEN_SOURCES
    assert "noncommercial" in decision.blocked_sources[SRC_FIREHOL]
    res = run_module(IpContextLists, "ipv4:2.26.8.5", runtime=rt, allowed_sources=decision.allowed_sources)
    assert res.status is Status.OK and SRC_FIREHOL not in res.source_statuses
    licensed = run("ipv4:2.26.8.5")  # firehol.proxies licence-allowed: reported as not checked, never 'not a proxy'
    assert licensed.source_statuses[SRC_FIREHOL] == {"status": "unavailable", "reason_code": "dataset", "reason": FIREHOL_NOT_WIRED}


def test_input_type_without_an_allowed_list_is_licence_skipped():
    res = run("user_agent:Mozilla/5.0 (ARTEX)", allowed_sources=frozenset({SRC_X4B}))
    assert res.status is Status.SKIPPED and res.reason_code == "licence"
    assert SRC_UA not in res.source_statuses


# ------------------------------------------------------------------ parsers, registrations, applicability
def test_parsers_refuse_error_bodies_and_count_invalid_lines():
    assert "error body" in parse_cidr_lines((FIX / "github_raw_not_found.txt").read_bytes()).error
    assert "HTML" in parse_cidr_lines((FIX / "firehol_upstream_not_found.html").read_bytes()).error
    relay = parse_relay_csv((FIX / "private_relay_truncated.csv").read_bytes())
    assert relay.stats["invalid"] == 1 and relay.entries == 5
    assert "IP columns" in parse_ip_csv(b"name,port\nexample,1\n", ("dest_ip",)).error
    v6 = parse_cidr_lines(b"# comment\n2001:ac8::/32\n10.0.0.0/8\n0.0.0.0/0\nnot-a-cidr\n")
    assert v6.entries == 1 and v6.stats == {"lines": 5, "valid": 1, "invalid": 1, "comments": 1, "refused": 2, "v4": 0, "v6": 1}
    proton = parse_ip_csv((FIX / "mthcht_vpn_protonvpn_head.csv").read_bytes(), ("src_ip_entry", "src_ip_exit"))
    assert proton.entries == 16 and proton.data.contains("45.14.71.15")


def test_each_list_is_parsed_once_per_downloaded_version():
    install()
    first = run("ipv4:2.26.8.5")
    key = (LIST_BY_KEY["x4bnet_vpn_ipv4"].dataset, first.raw["lists"]["ip_context_lists.x4bnet_vpn_ipv4.txt"]["sha256"])
    cached = icl._PARSED[key]
    run("ipv4:2.26.8.6")
    assert icl._PARSED[key] is cached


def test_registrations_record_terms_and_provenance():
    assert IpContextLists.disclosure == "none" and IpContextLists.hosts == () and IpContextLists.terms == "noncommercial"
    assert IpContextLists.default_enabled is True and set(IpContextLists.sources) == OPEN_SOURCES | {SRC_FIREHOL}
    for spec in LISTS:
        reg = DATASETS[spec.dataset]
        assert reg["source"] == spec.source and reg["terms_class"] == "open" and reg["licence"] and reg["attribution"]
        assert reg["ttl"] == (7 * 86400 if spec.key == "apple_private_relay" else 86400)
        assert callable(reg["validate"])
    assert "IPLocate" in DATASETS[LIST_BY_KEY["x4bnet_vpn_ipv4"].dataset]["attribution"]
    notices = FIXTURES.parent.parent / "v3lum" / "data" / "notices"
    for name in ("ip_context_lists_x4bnet", "ip_context_lists_mthcht", "ip_context_lists_apple_private_relay"):
        notice = json.loads((notices / f"{name}.json").read_text())
        assert notice["bundled"] is False and "v3lum/modules/ip_network/ip_context_lists.py" in notice["files"]


@pytest.mark.parametrize("value", ["ipv4:10.1.2.3", "ipv4:192.0.2.7", "ipv6:fe80::1", "cidr:10.0.0.0/8"])
def test_private_and_documentation_space_is_not_applicable(value):
    install()
    res = run(value)
    assert res.status is Status.SKIPPED and res.reason_code == "not_applicable"


def _replay(etype, module):
    """FakeHttp with the AR21 golden-path routes of tests/fixtures/acceptance/<etype>/<module>.json."""
    import base64

    doc = json.loads((FIXTURES / "acceptance" / etype / f"{module}.json").read_text(encoding="utf-8"))
    assert doc["schema"] == "v3lum.acceptance_routes/1" and doc["module"] == module
    http = FakeHttp()
    for route in doc["routes"]:
        if "json" in route:
            body = {"json": route["json"]}
        elif "body_b64" in route:
            body = {"body": base64.b64decode(route["body_b64"])}
        else:
            body = {"text": route["text"]}
        http.add(route["method"], route["url"], status=route["status"], headers=route.get("headers") or {}, **body)
    return http, doc


@pytest.mark.parametrize(("etype", "value", "requests"), [("ipv4", "ipv4:8.8.8.8", 7), ("domain", "domain:example.com", 1)])
def test_acceptance_routes_of_the_golden_inputs(etype, value, requests):
    """AR21 golden path without local copies: the daily lists are requested once each; the trimmed real
    heads fail the entry minimum, so nothing is installed and the run is 'not checked' (never 'not a VPN')."""
    http, doc = _replay(etype, "ip_context_lists")
    res = run_module(IpContextLists, value, http)
    assert len(doc["routes"]) == requests and len(http.calls) == requests
    assert res.status is Status.UNAVAILABLE and res.reason_code == "dataset"
