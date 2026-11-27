"""pivots_unverified (P304, batch p2-G14-3): challenge-walled / SPA pivot pages, manual links only.

The packs are offline data (cond 1): these tests never route a request to a link host. Hostile values and sample
values: tests/fixtures/pivots_unverified/render_values.json (documentation values only)."""

from __future__ import annotations

import copy
import datetime as dt
import json
from urllib.parse import urlsplit

import pytest

from tests.fakes import FakeHttp, module_fixture, run_module
from v3lum.core import links
from v3lum.core import tlp as _tlp
from v3lum.core.context import ScanOptions
from v3lum.core.entities import Entity
from v3lum.core.entities import EntityType as T
from v3lum.core.models import Status
from v3lum.core.providers import registry
from v3lum.modules.search_dorks import pivots_unverified as pu
from v3lum.modules.search_dorks.pivots_unverified import PivotsUnverified

VALUES = module_fixture("pivots_unverified", "render_values.json")
PACK_DIR = links.PACKS_DIR


def pack_json(name: str) -> dict:
    return json.loads((PACK_DIR / f"{name}.json").read_text(encoding="utf-8"))


def all_entries():
    return pu.pack_entries()


# ------------------------------------------------------------------ cond 1, 3, 7-10: lint
@pytest.mark.parametrize("pack", pu.PACKS)
def test_every_pack_is_lint_clean(pack):
    assert pu.lint_pack_data(pack_json(pack), pack=pack) == []
    assert not [e for e in links.errors() if pack in e]
    assert pu.module_link_errors(pack) == []


def test_packs_load_and_no_link_is_lost_to_a_duplicate():
    for pack, entry, is_module in all_entries():
        if is_module:
            assert any(ml.id == entry["id"] for ml in pu.module_links(pack))
            continue
        link = links.get_link(f"{pack}:{entry['id']}")
        if link is None:  # an identical (template, types) pair served by an earlier pack is dropped by the loader
            assert any(t.template == entry["template"] for t in links.templates()), entry["id"]


def test_packs_are_offline_data_and_never_curl_verified():
    for _pack, entry, _is_module in all_entries():
        assert entry["publishes"] is False and entry["touches_target"] is False and entry["login_required"] is False
        assert entry.get("x_verification") in (None, "browser")
        if entry["verified"] is False:
            assert entry["label"].endswith(pu.MARKER_CHALLENGE)
        assert "{raw}" not in entry["template"]


def test_module_makes_zero_requests():
    http = FakeHttp()  # no route: any request would fail the test
    for value in ("url:https://example.com/", "ipv4:8.8.8.8", "domain:example.com", "cve:CVE-2021-44228"):
        res = run_module(PivotsUnverified, value, http, tlp="clear")
        assert res.requests == 0
    assert http.calls == []


# ------------------------------------------------------------------ cond 3: render every template
def _rendered(pack, entry, is_module, entity):
    if is_module:
        ml = next(m for m in pu.module_links(pack) if m.id == entry["id"])
        return pu.render_module_link(ml, entity)
    link = links.get_link(f"{pack}:{entry['id']}")
    return links.render(link, entity) if link else None


def _static_counts(template):
    import re

    static = re.sub(r"\{[a-z0-9_]+\}", "", template)
    return {ch: static.count(ch) for ch in "?#&"}


def test_every_template_renders_a_sample_value_on_its_declared_host():
    for pack, entry, is_module in all_entries():
        for etype in entry["entity_types"]:
            entity = Entity.make(etype, VALUES["samples"][etype])
            rendered = _rendered(pack, entry, is_module, entity)
            if rendered is None and not is_module and links.get_link(f"{pack}:{entry['id']}") is None:
                continue  # served by an earlier pack (see the duplicate test)
            if entry.get("template", "").endswith("{br_national}") and etype == "phone":
                assert rendered is not None
            assert rendered is not None, (pack, entry["id"], etype)
            parts = urlsplit(rendered.url)
            assert parts.scheme == "https" and parts.hostname == entry["host"] and parts.port is None
            assert pu.check_rendered(rendered.url, host=entry["host"], template=entry["template"]) == []


@pytest.mark.parametrize("hostile", VALUES["hostile"])
def test_hostile_values_never_escape_the_declared_host(hostile):
    for pack, entry, is_module in all_entries():
        for etype in entry["entity_types"]:
            entity = Entity.try_make(etype, hostile)
            if entity is None:
                continue  # the normaliser refuses it: nothing renders
            rendered = _rendered(pack, entry, is_module, entity)
            if rendered is None:
                continue
            parts = urlsplit(rendered.url)
            assert parts.scheme == "https" and parts.hostname == entry["host"], (entry["id"], hostile)
            assert parts.username is None and parts.port is None
            assert all(ord(c) > 0x20 and ord(c) < 0x7F for c in rendered.url)
            counts = {ch: rendered.url.count(ch) for ch in "?#&"}
            assert counts == _static_counts(entry["template"]), (entry["id"], hostile, rendered.url)


def test_encoders():
    assert pu.canonical_url("HTTPS://Example.COM") == "https://example.com/"
    assert pu.canonical_url("https://example.com:443/a#frag") == "https://example.com/a"
    assert pu.canonical_url("https://user:pw@example.com/") is None
    assert pu.url_path("https://example.com/a?b=1#c") == "https://example.com/a%3Fb%3D1"
    assert pu.url_path("https://example.com/../../submit") is None
    assert pu.url_path("https://example.com/%2e%2e/save") is None
    import hashlib

    assert pu.url_sha256("https://Example.com") == hashlib.sha256(b"https://example.com/").hexdigest()
    assert pu.cve_num("CVE-2021-44228") == "2021-44228" and pu.cve_num("2021-1") is None
    import base64
    from urllib.parse import unquote

    q = pu.hunter_q(T.IPV4, "8.8.8.8")
    assert base64.b64decode(unquote(q)).decode() == 'ip="8.8.8.8"'
    assert pu.hunter_q(T.DOMAIN, 'x" OR "1') is None


# ------------------------------------------------------------------ cond 7-10: lint rejections
def _core_entry(**over):
    base = copy.deepcopy(pack_json("unverified_reputation")["links"][0])
    base.update(over)
    return base


@pytest.mark.parametrize(("over", "needle"), [
    ({"template": "https://www.virustotal.com/gui/file/{q}/rescan", "host": "www.virustotal.com",
      "entity_types": ["sha256"]}, "rescan"),
    ({"template": "https://www.virustotal.com/gui/search/{q}", "host": "www.virustotal.com",
      "entity_types": ["sha256"]}, "VirusTotal"),
    ({"template": "https://web.archive.org/save/{q}", "host": "web.archive.org", "entity_types": ["url"]}, "save"),
    ({"template": "https://archive.ph/submit/?url={qp}", "host": "archive.ph", "entity_types": ["url"]}, "submit"),
    ({"template": "https://centralops.net/co/DomainDossier.aspx?addr={qp}&svc_scan=true", "host": "centralops.net",
      "entity_types": ["domain"]}, "svc_scan"),
    ({"template": "https://www.shodan.io/search?query={qp}", "host": "www.shodan.io", "entity_types": ["ipv4"]}, "login"),
    ({"login_required": True}, "login"),
    ({"x_verification": "curl"}, "curl"),
    ({"verified": True, "checked_at": "2026-11-01", "x_verification": "browser", "x_checked_by": None}, "browser check"),
    ({"template": "https://metadefender.com/upload/{q}", "host": "metadefender.com", "entity_types": ["sha256"]}, "upload"),
])
def test_lint_rejects(over, needle):
    problems = pu.p304_rule_problems(_core_entry(**over))
    assert any(needle.lower() in p.lower() for p in problems), problems


def test_browser_verified_entry_is_accepted_only_when_dated_and_marked():
    entry = _core_entry(verified=True, checked_at="2026-11-20", x_verification="browser", x_checked_by="analyst-1",
                        label="AbuseIPDB check (domain) (browser)")
    assert pu.p304_rule_problems(entry, today=dt.date(2026, 11, 26)) == []
    future = dict(entry, checked_at="2027-01-01")
    assert pu.p304_rule_problems(future, today=dt.date(2026, 11, 26))
    wrong_marker = dict(entry, label="AbuseIPDB check (domain) (may show a challenge)")
    assert pu.p304_rule_problems(wrong_marker, today=dt.date(2026, 11, 26))


def test_centralops_template_never_carries_svc_scan():
    entry = next(e for p, e, _m in all_entries() if e["id"] == "centralops_dossier")
    assert "svc_scan" not in entry["template"]
    assert "dom_whois=true" in entry["template"]


def test_kaspersky_needs_clear_max_tlp_and_badge():
    data = pack_json("unverified_reputation")
    entry = next(e for e in data["x_module_links"] if e["id"] == "kaspersky_opentip")
    assert entry["x_max_tlp"] == "clear" and entry["x_badge"] == pu.BADGE_RU
    assert pu.p304_rule_problems(dict(entry, x_max_tlp="amber"))
    assert pu.p304_rule_problems(dict(entry, x_badge=None))


# ------------------------------------------------------------------ cond 4, 5, 11: tiers and privacy
TIERS = {
    "trusted": ["www.virustotal.com", "www.shodan.io", "platform.censys.io", "securitytrails.com", "radar.cloudflare.com",
                "lookup.icann.org", "web.archive.org", "bazaar.abuse.ch", "urlhaus.abuse.ch", "www.abuseipdb.com",
                "talosintelligence.com", "otx.alienvault.com", "exchange.xforce.ibmcloud.com", "opentip.kaspersky.com",
                "check.spamhaus.org", "www.hybrid-analysis.com", "www.joesandbox.com", "metadefender.com", "nvd.nist.gov",
                "www.exploit-db.com", "www.facebook.com"],
    "community": ["app.netlas.io", "spur.us", "centralops.net", "search.dnslytics.com", "dotdb.com", "tgstat.com",
                  "www.tellows.com.br", "www.cvedetails.com", "vulners.com", "ahmia.fi", "intel.arkm.com",
                  "www.chainabuse.com"],
    "unknown": ["archive.ph", "hunter.how"],
}


@pytest.mark.parametrize(("tier", "host"), [(t, h) for t, hosts in TIERS.items() for h in hosts])
def test_initial_tiers_and_rationale(tier, host):
    provider = registry().provider_for_host(host)
    assert provider is not None, host
    assert provider.tier == tier and provider.tier_rationale


def test_every_link_host_has_a_provider_entry():
    for _pack, entry, _m in all_entries():
        provider = registry().provider_for_host(entry["host"])
        assert provider is not None and provider.tier_rationale, entry["host"]


def test_unknown_tier_hosts_take_ioc_values_only_and_carry_the_badge():
    for _pack, entry, _m in all_entries():
        if links.host_tier(entry["host"]) == "unknown":
            assert all(T(t) in links.IOC_TYPES for t in entry["entity_types"]), entry["id"]
    bad = _core_entry(template="https://archive.ph/{domain}", host="archive.ph", entity_types=["keyword"])
    assert links.lint_pack({"schema": links.SCHEMA, "pack": "x_test", "title": "t", "links": [bad]}, source="x_test.json")
    res = run_module(PivotsUnverified, "url:https://example.com/", tlp="clear")
    archive = [label for label, url in res.links if "archive.ph" in url]
    assert archive and all(links.BADGE_UNKNOWN_OPERATOR in label for label in archive)


def test_privacy_links_only_for_typed_seeds_of_an_opted_in_case():
    handle = Entity.make("username", "example_user")
    assert not [r for r in links.pivot_links_for(handle) if r.host == "tgstat.com"]
    assert [r for r in links.pivot_links_for(handle, include_privacy=True) if r.host == "tgstat.com"]
    phone = Entity.make("phone", "+5511955550123")
    tellows = [r for r in links.pivot_links_for(phone, include_privacy=True) if r.host == "www.tellows.com.br"]
    assert tellows and tellows[0].url == "https://www.tellows.com.br/num/11955550123"
    foreign = Entity.make("phone", "+12025550123")
    assert not [r for r in links.pivot_links_for(foreign, include_privacy=True) if r.host == "www.tellows.com.br"]
    ranked = pu.rank_links(handle, _tlp.TLP.CLEAR, include_privacy=False)
    assert not ranked["terminal"]


# ------------------------------------------------------------------ cond 2, 6, 10: module output
def test_url_seed_at_clear():
    res = run_module(PivotsUnverified, "url:https://example.com/a?b=1", tlp="clear")
    assert res.status is Status.OK
    urls = [u for _l, u in res.links]
    vt = pu.url_sha256("https://example.com/a?b=1")
    assert f"https://www.virustotal.com/gui/url/{vt}" in urls
    assert "https://archive.ph/https://example.com/a%3Fb%3D1" in urls
    assert any(u.startswith("https://opentip.kaspersky.com/") for u in urls)
    assert all("opening sends" not in label for label, _u in res.links)
    assert res.raw["ranked"][0]["ref"] == "unverified_reputation:virustotal_url"  # top tool first (cond 6)


def test_amber_labels_carry_the_disclosure_warning_and_hide_kaspersky_and_unknown_tier():
    res = run_module(PivotsUnverified, "url:https://example.com/")
    assert res.status is Status.OK  # default TLP:AMBER
    assert all("opening sends" in label for label, _u in res.links)
    assert not any("kaspersky" in u or "archive.ph" in u for _l, u in res.links)
    reasons = {h["ref"]: h["reason"] for h in res.raw["hidden"]}
    assert "max_tlp" in reasons["unverified_reputation:kaspersky_opentip"]
    assert "unknown-tier" in reasons["unverified_history:archive_today_url"]
    vt_label = next(label for label, u in res.links if "virustotal" in u)
    assert "the SHA-256 of https://example.com/ to www.virustotal.com" in vt_label


def test_kaspersky_hidden_from_green():
    res = run_module(PivotsUnverified, "sha256:" + "a" * 64, tlp="green")
    assert not any("kaspersky" in u for _l, u in res.links)
    res = run_module(PivotsUnverified, "sha256:" + "a" * 64, tlp="clear")
    label = next(label for label, u in res.links if "kaspersky" in u)
    assert pu.BADGE_RU in label


def test_red_hides_every_third_party_link():
    res = run_module(PivotsUnverified, "url:https://example.com/", tlp="red")
    assert res.status is Status.SKIPPED and res.reason_code == "tlp" and not res.links


def test_amber_strict_keeps_trusted_hosts_only():
    res = run_module(PivotsUnverified, "favicon_hash:-1234567", tlp="amber+strict")
    assert res.status is Status.EMPTY and not res.links


def test_cve_seed_gets_exploitdb_and_ranked_reference_pages():
    res = run_module(PivotsUnverified, "cve:CVE-2021-44228", tlp="clear")
    assert [u for _l, u in res.links] == ["https://www.exploit-db.com/search?cve=2021-44228"]
    refs = [r["ref"] for r in res.raw["ranked"]]
    assert {"unverified_cve:nvd_cve", "unverified_cve:cvedetails_cve", "unverified_cve:vulners_cve"} <= set(refs)
    assert all(r["marker"] == pu.MARKER_CHALLENGE for r in res.raw["ranked"])


def test_terminal_ranking_caps_at_eight_and_ranks_top_tools_first():
    ranked = pu.rank_links(Entity.make("domain", "example.com"), _tlp.TLP.CLEAR)
    assert len(ranked["terminal"]) == pu.TERMINAL_LINK_CAP and ranked["rest"] > 0
    hosts = [r["host"] for r in ranked["terminal"]]
    assert hosts[0] == "www.abuseipdb.com" and hosts[1] == "otx.alienvault.com"
    prio = [pu.TOP_TOOL_HOSTS.index(h) if h in pu.TOP_TOOL_HOSTS else len(pu.TOP_TOOL_HOSTS) for h in hosts]
    assert prio == sorted(prio)  # top tools first, then pack order


def test_routed_entries_are_present():
    hosts = {e["host"] for _p, e, _m in all_entries()}
    assert {"www.chainabuse.com", "www.facebook.com", "www.cvedetails.com", "vulners.com", "nvd.nist.gov",
            "www.exploit-db.com", "ahmia.fi"} <= hosts
    explorer_hosts = {t.host for t in links.templates()}
    assert {"etherscan.io", "bscscan.com", "intel.arkm.com"} <= explorer_hosts  # P216 explorers: crypto pack links


def test_meta_ad_library_gets_brand_values_only():
    brand = Entity.make("company_name", "Example Org")
    rendered = links.render("unverified_brand:meta_ad_library", brand)
    assert rendered is not None and "country=BR" in rendered.url and "q=Example+Org" in rendered.url
    assert links.render("unverified_brand:meta_ad_library", Entity.make("person_name", "Maria Exemplo")) is None


# ------------------------------------------------------------------ cond 12: doctor --links data
def test_recheck_report_lists_never_checked_and_stale_browser_checks(monkeypatch):
    report = pu.recheck_report(dt.date(2026, 11, 26))
    assert not report["due"]
    assert len(report["never_checked"]) == len(all_entries())
    stale = [("unverified_cve", dict(_core_entry(), id="stale", verified=True, checked_at="2026-06-01",
                                     x_verification="browser", x_checked_by="analyst-1"), False),
             ("unverified_cve", dict(_core_entry(), id="fresh", verified=True, checked_at="2026-11-01",
                                     x_verification="browser", x_checked_by="analyst-1"), False)]
    monkeypatch.setattr(pu, "pack_entries", lambda pack=None: stale)
    report = pu.recheck_report(dt.date(2026, 11, 26))
    assert [d["ref"] for d in report["due"]] == ["unverified_cve:stale"] and report["due"][0]["age_days"] == 178


def test_challenge_page_fixture_is_what_curl_gets():
    with open("tests/fixtures/pivots_unverified/cloudflare_challenge_403.html", encoding="utf-8") as fh:
        page = fh.read()
    assert "Just a moment" in page  # why these links are browser-only (A9): never fetched by V3LUM


def test_unrelated_entity_types_are_not_applicable():
    assert T.PHONE not in PivotsUnverified.accepts and T.CPF not in PivotsUnverified.accepts


def test_options_do_not_unlock_personal_module_links():
    res = run_module(PivotsUnverified, "domain:example.com", tlp="clear",
                     options=ScanOptions(show_personal=True, purpose="incident"))
    assert res.status is Status.OK and all(r["ref"] for r in res.raw["ranked"])
