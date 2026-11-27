"""Batch p2-G14-1 pivot packs (P026 domain_dns, P057 ip_network, P083 url_web, P170 threat_intel_ioc, P180
malware_hash, P194 vulnerability): schema, CI rendering with sample and hostile values (cond 3), provider tiers
(cond 4-5), curated order (cond 6), re-check data (cond 7) and the batch lint rules.

The packs are offline data: V3LUM never requests these URLs (cond 1). The golden URLs in
tests/fixtures/pivots_*/render_golden.json are the ones the maintainer requested live (verification records in
verified_templates.json: status, date and size only)."""

from __future__ import annotations

import copy
import datetime as dt
import json
import re
from urllib.parse import parse_qsl, urlsplit

import pytest

from tests.fakes import FakeHttp, module_fixture, run_module
from v3lum.core import links, providers
from v3lum.core.entities import IOC_TYPES, PERSONAL_TYPES, Entity, EntityType
from v3lum.core.models import Status
from v3lum.modules.utility import pivot_gated_links as pg

PACKS = pg.PACKS
MODULE_OF = {
    "domain_dns": "pivots_domain_dns", "ip_network": "pivots_ip_network", "url_web": "pivots_url_web",
    "threat_intel_ioc": "pivots_threat_intel", "malware_hash": "pivots_malware_hash", "vulnerability": "pivots_vulnerability",
}
FROZEN = ("id", "label", "template", "entity_types", "category", "host", "verified", "checked_at", "privacy", "publishes",
          "touches_target", "login_required", "antibot")
SAMPLES = {
    "domain": "example.com", "url": "https://example.com/login?next=/a#frag", "ipv4": "93.184.215.14",
    "ipv6": "2606:2800:21f:cb07:6820:80da:af6b:8b2c", "cidr": "93.184.215.0/24", "asn": "AS15133",
    "md5": "44d88612fea8a8f36de82e1278abb02f", "sha1": "3395856ce81f2b7382dee72602f798b642f14140",
    "sha256": "275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f", "cve": "CVE-2021-44228",
    "keyword": "banco do brasil", "analytics_id": "GTM-5F22G6", "favicon_hash": "708578229",
    "malware_family": "emotet", "cert_fingerprint": "96bcec06264976f37460779acf28c5a7cfe8a3c0aae11a8ffcee05c0bddf08c6",
}
HOSTILE = [
    'exa"mple.com', "exa'mple.com", "exa mple.com", "exämple.com", "example.com\nX-Injected: 1", "example.com\r\n",
    "example.com#frag", "example.com?x=1&y=2", "example.com&run=1", "../../etc/passwd", "{0.__class__}", "{raw}",
    "%00%0d%0a", "<script>alert(1)</script>", "a/b\\c", "javascript:alert(1)", "https://user:pw@evil.example/",
    "日本語.example", "‮example.com", "x" * 300,
]
URL_CHARS = re.compile(r"^[A-Za-z0-9\-._~:/?#\[\]@!$&'()*+,;=%]+$")


def pack_file(name):
    return json.loads((links.PACKS_DIR / f"{name}.json").read_text(encoding="utf-8"))


def all_entries():
    for name in PACKS:
        data = pack_file(name)
        for item in data.get("links") or []:
            yield name, "core", item
        for item in data.get(pg.EXT_KEY) or []:
            yield name, "module", item


ENTRIES = list(all_entries())


def render_any(pack, kind, item, entity):
    if kind == "core":
        link = links.get_link(f"{pack}:{item['id']}")
        assert link is not None, f"{pack}:{item['id']} did not load: {links.errors()}"
        return links.render(link, entity)
    gl = pg.module_links(pack)[item["id"]]
    return pg.render(gl, entity)


def query_keys(url):
    return sorted(k for k, _v in parse_qsl(urlsplit(url).query, keep_blank_values=True))


# ------------------------------------------------------------------ cond 1: schema, loading, lint
MY_PROVIDER_FILES = (
    "completedns", "dnsviz", "whoxy", "dmarcian", "domaintools", "intodns", "mxtoolbox", "verisignlabs", "who_is",
    "whois_com", "hurricane_electric", "scamalytics", "cidr_report", "myipms", "aa419", "crawlgraph", "securityheaders",
    "scamadviser", "w3techs", "website_informer", "webtechsurvey", "cesnet_nerd", "fortiguard", "multirbl", "urlvoid",
    "threatbook", "sploitus", "rapid7", "netcraft__p2-G14-1",
)


def test_packs_load_clean_and_every_link_survives_the_lint():
    mine_reg = [e for e in providers.registry().errors if e.split(".json", 1)[0] in MY_PROVIDER_FILES]
    assert mine_reg == []  # other batches' fragments may be mid-edit; ours must be clean
    for pid in MY_PROVIDER_FILES:
        if "__" not in pid:
            assert providers.registry().get(pid) is not None, pid
    mine = [e for e in links.errors() if e.split(":", 1)[0].removesuffix(".json") in PACKS]
    assert mine == []
    assert pg.module_link_errors() == []
    for name in PACKS:
        data = pack_file(name)
        assert data["schema"] == links.SCHEMA and data["pack"] == name and data["x_batch"] == "p2-G14-1"
        assert pg.lint_pack_data(data, pack=name) == []
        loaded = {link.id for link in links.packs()[name].links}
        assert loaded == {i["id"] for i in data["links"]}, "a link was dropped (lint or duplicate template)"
        assert set(pg.module_links(name)) == {i["id"] for i in data.get(pg.EXT_KEY) or []}


@pytest.mark.parametrize(("pack", "kind", "item"), ENTRIES, ids=[f"{p}:{i['id']}" for p, _k, i in ENTRIES])
def test_every_entry_has_the_frozen_fields_and_safe_flags(pack, kind, item):
    for field in FROZEN:
        assert field in item, f"{field} missing"
    assert item["publishes"] is False and item["login_required"] is False and item["privacy"] is False
    assert item["template"].startswith(f"https://{item['host']}/")
    assert "{raw}" not in item["template"] and "{0" not in item["template"]
    if item["verified"]:
        assert dt.date.fromisoformat(item["checked_at"]) <= dt.date(2026, 11, 26)
    else:
        assert item["checked_at"] == ""
    assert not set(item["entity_types"]) & {t.value for t in PERSONAL_TYPES}, "no personal values in these packs"


def test_offline_data_disclosure_none_and_no_value_ever_fetched():
    from v3lum.core.module import get_module, load_modules

    load_modules()
    for name in ("pivots_domain_dns", "pivots_ip_network", "pivots_url_web", "pivots_threat_intel"):
        cls = get_module(name)
        assert cls.disclosure == "none" and cls.hosts == () and cls.max_requests == 0
        assert cls.terms == "open" and cls.default_enabled is True and cls.access_model == "offline"


# ------------------------------------------------------------------ cond 3: CI render, sample and hostile values
@pytest.mark.parametrize(("pack", "kind", "item"), ENTRIES, ids=[f"{p}:{i['id']}" for p, _k, i in ENTRIES])
def test_ci_renders_every_template_with_a_sample_per_declared_type(pack, kind, item):
    template_keys = query_keys(re.sub(r"\{[a-z0-9_]+\}", "x", item["template"]))
    for etype in item["entity_types"]:
        entity = Entity.make(etype, SAMPLES[etype])
        rendered = render_any(pack, kind, item, entity)
        assert rendered is not None, f"{etype} sample did not render"
        parts = urlsplit(rendered.url)
        assert parts.scheme == "https" and parts.hostname == item["host"] and parts.port is None
        assert parts.username is None and parts.fragment == ""
        assert URL_CHARS.match(rendered.url), rendered.url
        assert query_keys(rendered.url) == template_keys


@pytest.mark.parametrize("value", HOSTILE)
@pytest.mark.parametrize(("pack", "kind", "item"), ENTRIES, ids=[f"{p}:{i['id']}" for p, _k, i in ENTRIES])
def test_hostile_values_never_escape_the_declared_encoder(pack, kind, item, value):
    template_keys = query_keys(re.sub(r"\{[a-z0-9_]+\}", "x", item["template"]))
    for etype in item["entity_types"]:
        rendered = render_any(pack, kind, item, Entity(EntityType(etype), value))  # bypasses normalisation
        if rendered is None:
            continue  # the encoder or a value rule refused it: never a guessed URL
        parts = urlsplit(rendered.url)
        assert parts.scheme == "https" and parts.hostname == item["host"] and parts.port is None
        assert parts.username is None and parts.password is None and parts.fragment == ""
        assert URL_CHARS.match(rendered.url), rendered.url
        assert query_keys(rendered.url) == template_keys, "a value injected a query parameter"
        assert not re.search(r"[\s<>\"'{}\\]", rendered.url)


@pytest.mark.parametrize("module", sorted(MODULE_OF.values()))
def test_golden_urls_match_the_urls_requested_live(module):
    for g in module_fixture(module, "render_golden.json"):
        entity = Entity.make(g["type"], g["value"])
        pack, ident = g["ref"].split(":")
        if g["renderer"] == "core":
            rendered = links.render(g["ref"], entity)
        else:
            rendered = pg.render(pg.module_links(pack)[ident], entity)
        assert rendered is not None and rendered.url == g["url"], g


# ------------------------------------------------------------------ cond 4-5: provider registry and tiers
EXPECTED_TIERS = {
    # P026
    "crt.sh": "trusted", "dnsviz.net": "trusted", "dnssec-debugger.verisignlabs.com": "trusted", "mxtoolbox.com": "trusted",
    "dmarcian.com": "trusted", "reverseip.domaintools.com": "trusted", "whois.domaintools.com": "trusted",
    "www.whois.com": "trusted", "completedns.com": "community", "host.io": "community", "www.whoxy.com": "community",
    "intodns.com": "community", "who.is": "community",
    # P057
    "bgp.he.net": "trusted", "ipinfo.io": "trusted", "metrics.torproject.org": "trusted", "www.cidr-report.org": "trusted",
    "search.criminalip.io": "community", "scamalytics.com": "community", "myip.ms": "unknown",
    # P083
    "builtwith.com": "trusted", "urlscan.io": "trusted", "sitereport.netcraft.com": "trusted",
    "securityheaders.com": "trusted", "play.google.com": "trusted", "db.aa419.org": "community",
    "www.scamadviser.com": "community", "w3techs.com": "community", "website.informer.com": "community",
    "crawlgraph.com": "unknown", "ghostarchive.org": "unknown", "webtechsurvey.com": "unknown",
    # P170
    "nerd.cesnet.cz": "trusted", "www.fortiguard.com": "trusted", "viz.greynoise.io": "trusted",
    "www.urlvoid.com": "community", "threatbook.io": "community", "i.threatbook.io": "community",
    "honeylabs.net": "unknown", "multirbl.valli.org": "unknown", "cybercrime-tracker.net": "unknown",
    # P180 / P194
    "tria.ge": "trusted", "vulnerability.circl.lu": "trusted", "www.rapid7.com": "trusted", "sploitus.com": "unknown",
}


def test_every_link_host_has_a_registry_provider_with_the_cond5_tier():
    reg = providers.registry()
    hosts = {item["host"] for _p, _k, item in ENTRIES}
    for name in PACKS:
        hosts |= {ref["template"].split("/")[2] for ref in pack_file(name).get("x_served_by") or []}
        hosts |= {p["host"] for p in pack_file(name).get("x_pending") or []}
    for host in sorted(hosts):
        provider = reg.provider_for_host(host)
        assert provider is not None, f"{host}: no provider (A8)"
        assert provider.tier_rationale and provider.tier_reviewer and provider.tier_date
        assert provider.flags.publishes_queries is False, f"{host} publishes queries (rule 7)"
        if host != "en.fofa.info":
            assert provider.tier == EXPECTED_TIERS[host], f"{host}: {provider.tier}"
    # FOFA's fragment belongs to another batch and records 'unknown'; cond 5 proposes community (registry reviewer).
    assert reg.provider_for_host("en.fofa.info").tier in ("community", "unknown")


@pytest.mark.parametrize(("pack", "kind", "item"), ENTRIES, ids=[f"{p}:{i['id']}" for p, _k, i in ENTRIES])
def test_unknown_tier_hosts_take_ioc_values_only_and_carry_the_badge(pack, kind, item):
    if links.host_tier(item["host"]) != "unknown":
        return
    assert {EntityType(t) for t in item["entity_types"]} <= IOC_TYPES
    etype = item["entity_types"][0]
    rendered = render_any(pack, kind, item, Entity.make(etype, SAMPLES[etype]))
    assert links.BADGE_UNKNOWN_OPERATOR in rendered.badge


def test_the_lint_refuses_free_text_on_unknown_tier_hosts():
    data = copy.deepcopy(pack_file("vulnerability"))
    sploitus = next(i for i in data["links"] if i["id"] == "sploitus")
    sploitus["entity_types"] = ["cve", "keyword"]
    assert any("IOC_TYPES values only" in e for e in links.lint_pack(data, source="vulnerability.json"))
    data = copy.deepcopy(pack_file("threat_intel_ioc"))
    cct = next(i for i in data["links"] if i["id"] == "cybercrime_tracker")
    cct["entity_types"] = ["domain", "malware_family"]  # P170 cond 11: no family search before a tier promotion
    assert any("IOC_TYPES values only" in e for e in links.lint_pack(data, source="threat_intel_ioc.json"))


def test_served_by_references_resolve_and_render():
    seen = 0
    for name in PACKS:
        for ref in pack_file(name).get("x_served_by") or []:
            link = links.get_link(ref["ref"])
            assert link is not None and link.template == ref["template"]
            etype = link.entity_types[0].value
            assert links.render(link, Entity.make(etype, SAMPLES[etype])) is not None
            seen += 1
    assert seen == 5


# ------------------------------------------------------------------ cond 6: curated order
CURATED = {
    "domain_dns": ["dnsviz", "whoxy", "hostio", "mxtoolbox_spf", "mxtoolbox_dmarc", "mxtoolbox_mx", "dmarcian", "completedns",
                   "domaintools_reverse_ip", "intodns", "verisign_dnssec_debugger", "whois_is", "whois_com", "domaintools_whois"],
    "ip_network": ["bgphe_ip", "bgphe_as", "ipinfo_ip", "ipinfo_asn", "scamalytics", "cidr_report_as", "myipms"],
    "url_web": ["builtwith_profile", "builtwith_relationships", "builtwith_tag", "netcraft_site_report", "aa419", "w3techs",
                "webtechsurvey", "website_informer", "crawlgraph", "ghostarchive", "google_play_search"],
    "threat_intel_ioc": ["nerd_ip", "fortiguard_search", "multirbl", "honeylabs", "cybercrime_tracker"],
    "malware_hash": ["triage_hash", "triage_family"],
    "vulnerability": ["circl_vuln", "rapid7_db", "sploitus"],
}


@pytest.mark.parametrize("pack", PACKS)
def test_file_order_is_the_curated_analyst_value_order(pack):
    assert [i["id"] for i in pack_file(pack)["links"]] == CURATED[pack]


def test_rendered_order_groups_by_question_verified_first_then_file_order():
    entity = Entity.make("domain", "example.com")
    mine = [r for r in links.pivot_links_for(entity) if r.ref.startswith("domain_dns:")]
    ordered = pg.terminal_order(mine)
    cats = [r.category for r in ordered]
    assert cats == sorted(cats, key=links.LINK_CATEGORIES.index)
    other = [r.ref.split(":")[1] for r in ordered if r.category == "other"]
    assert other[-1] == "domaintools_whois"  # antibot, unverified: last in its group (P026 cond 11)
    assert other[:3] == ["dnsviz", "hostio", "mxtoolbox_spf"]
    assert pg.TERMINAL_MAX_LINKS == 8


# ------------------------------------------------------------------ cond 7: re-check data (doctor --links)
def test_recheck_report_lists_unverified_and_stale_links():
    report = pg.recheck_report(dt.date(2026, 11, 26))
    refs = {r["ref"]: r["reason"] for r in report}
    assert refs["domain_dns:domaintools_whois"] == "unverified"
    assert refs["malware_hash:triage_family"] == "unverified"
    assert "url_web:google_play_details (pending)" in refs and "threat_intel_ioc:threatbook_ip (pending)" in refs
    assert "ip_network:bgphe_ip" not in refs
    stale = {r["ref"] for r in pg.recheck_report(dt.date(2027, 6, 1))}
    assert "ip_network:bgphe_ip" in stale and "domain_dns:crtsh_cert_sha256 (module link)" in stale
    early = {r["ref"]: r["reason"] for r in pg.recheck_report(dt.date(2026, 11, 20))}
    assert early["ip_network:bgphe_ip"] == "checked_at in the future"


# ------------------------------------------------------------------ batch lint rules (final conditions)
BAD = [
    ("url_web", {"id": "mdn", "template": "https://developer.mozilla.org/en-US/observatory/analyze?host={q}", "host": "developer.mozilla.org"}, "MDN Observatory"),
    ("domain_dns", {"id": "cdns_ajax", "template": "https://completedns.com/dns-history/ajax/?domain={q}", "host": "completedns.com"}, "ajax"),
    ("domain_dns", {"id": "dnsviz_analyze", "template": "https://dnsviz.net/d/{q}/analyze/", "host": "dnsviz.net"}, "/analyze/"),
    ("malware_hash", {"id": "triage_submit", "template": "https://tria.ge/upload?url={q}", "host": "tria.ge"}, "search pages only"),
    ("url_web", {"id": "sh", "template": "https://securityheaders.com/?q={q}&followRedirects=on", "host": "securityheaders.com"}, "hide=on"),
    ("vulnerability", {"id": "sploitus2", "template": "https://sploitus.com/?query={q}", "host": "sploitus.com", "label": "Sploitus"}, "view only"),
    ("ip_network", {"id": "fofa_plain", "template": "https://en.fofa.info/result?qbase64={b64}", "host": "en.fofa.info"}, "{b64q}"),
    ("ip_network", {"id": "foreign", "template": "https://search.criminalip.io/asset/report/{q}", "host": "search.criminalip.io",
                    "x_badge": "foreign provider: queries are logged abroad"}, "x_max_tlp green"),
    ("domain_dns", {"id": "crt_any", "template": "https://crt.sh/?q={q}", "host": "crt.sh", "entity_types": ["cert_fingerprint"]}, "SHA-256"),
    ("url_web", {"id": "scam_core", "template": "https://www.scamadviser.com/check-website/{q}", "host": "www.scamadviser.com",
                 "x_max_tlp": "green"}, "module renderer"),
    ("url_web", {"id": "raw", "template": "https://builtwith.com/{raw}", "host": "builtwith.com"}, "{raw}"),
]


@pytest.mark.parametrize(("pack", "entry", "needle"), BAD, ids=[b[1]["id"] for b in BAD])
def test_batch_rules_refuse_what_the_final_conditions_exclude(pack, entry, needle):
    item = {"label": "x", "entity_types": ["domain"], **entry}
    assert any(needle in e for e in pg.batch_rule_problems(pack, item)), pg.batch_rule_problems(pack, item)


def test_scan_trigger_module_links_need_seed_only_and_a_green_ceiling():
    entry = {"id": "uv", "label": "URLVoid", "template": "https://www.urlvoid.com/scan/{q}/", "host": "www.urlvoid.com",
             "entity_types": ["domain"], "touches_target": True, "x_max_tlp": "green"}
    assert any("x_seed_only" in e for e in pg.batch_rule_problems("threat_intel_ioc", entry, module_link=True))


def test_excluded_and_pending_entries_are_never_rendered():
    hosts = {link.host for link in links.templates()}
    assert "developer.mozilla.org" not in hosts and "searchdns.netcraft.com" not in hosts
    assert "threatbook.io" not in hosts and "i.threatbook.io" not in hosts  # P170 cond 10: pending browser check
    templates = [link.template for link in links.templates()]
    assert not [t for t in templates if "completedns.com/dns-history/ajax" in t or "/analyze" in t and "dnsviz" in t]
    for name in PACKS:
        for item in pack_file(name).get("x_excluded") or []:
            assert item["reason"] and item["host"]


def test_a_broken_pack_file_fails_closed(tmp_path, monkeypatch):
    good = pack_file("threat_intel_ioc")
    monkeypatch.setattr(links, "PACKS_DIR", tmp_path)
    (tmp_path / "url_web.json").write_text("{not json", encoding="utf-8")
    good[pg.EXT_KEY][0]["template"] = "http://www.urlvoid.com/scan/{q}/"  # http: refused
    (tmp_path / "threat_intel_ioc.json").write_text(json.dumps(good), encoding="utf-8")
    pg.reset_cache()
    try:
        assert pg.module_links("url_web") == {} and "unreadable pack" in pg.module_link_errors("url_web")[0]
        assert "urlvoid" not in pg.module_links("threat_intel_ioc")
        assert any("https" in e for e in pg.module_link_errors("threat_intel_ioc"))
        from v3lum.modules.url_web.pivots_url_web import PivotsUrlWeb

        res = run_module(PivotsUrlWeb, "domain:example.com", FakeHttp(), tlp="clear")
        assert res.status is Status.SKIPPED and res.reason_code == "not_applicable" and res.links == []
    finally:
        pg.reset_cache()


# ------------------------------------------------------------------ P180 / P194 (pack-only proposals)
def test_triage_search_only_for_hashes_and_unverified_family_search():
    eicar = Entity.make("sha256", SAMPLES["sha256"].upper())
    assert links.render("malware_hash:triage_hash", eicar).url == f"https://tria.ge/s?q={SAMPLES['sha256']}"
    fam = links.render("malware_hash:triage_family", Entity.make("malware_family", "Agent Tesla"))
    assert fam.url == "https://tria.ge/s?q=family%3AAgent%20Tesla" and links.BADGE_UNVERIFIED in fam.badge
    assert all(urlsplit(link.template).path in ("/s", "/reports") for link in links.templates() if link.host == "tria.ge")


def test_cve_pages_and_the_sploitus_caution():
    cve = Entity.make("cve", "cve-2021-44228")
    out = {r.ref: r for r in links.pivot_links_for(cve) if r.ref.startswith("vulnerability:")}
    assert [r.split(":")[1] for r in out] == ["circl_vuln", "rapid7_db", "sploitus"]
    assert out["vulnerability:sploitus"].label.endswith("exploit listings - view only, never download or run code")
    assert links.BADGE_UNKNOWN_OPERATOR in out["vulnerability:sploitus"].badge
    keyword = {r.ref for r in links.pivot_links_for(Entity.make("keyword", "log4shell"))}
    assert "vulnerability:rapid7_db" in keyword and "vulnerability:sploitus" not in keyword


# ------------------------------------------------------------------ fixtures hygiene
@pytest.mark.parametrize("module", sorted(MODULE_OF.values()))
def test_fixtures_are_small_and_hold_no_personal_data(module):
    from tests.fakes import FIXTURES

    for path in (FIXTURES / module).iterdir():
        text = path.read_text(encoding="utf-8")
        assert len(text) < 20_000
        assert not re.search(r"[A-Za-z0-9._%+-]+@(?!example\.)[A-Za-z0-9.-]+\.[a-z]{2,}", text)
        assert "56986996" not in text  # research fingerprint of an intercepting proxy: never kept
