"""pivots_threat_intel (P170): reputation pages, manual links only. V3LUM never fetches these URLs.

Verification records: tests/fixtures/pivots_threat_intel/verified_templates.json; golden URLs: render_golden.json."""

from __future__ import annotations

import pytest

from tests.fakes import FakeHttp, module_fixture, run_module
from v3lum.core import links
from v3lum.core.entities import Entity, EntityType
from v3lum.core.models import Status
from v3lum.modules.threat_intel_ioc.pivots_threat_intel import PivotsThreatIntel
from v3lum.modules.utility import pivot_gated_links as pg

GOLDEN = module_fixture("pivots_threat_intel", "render_golden.json")
CHECKS = {c["check"]: c for c in module_fixture("pivots_threat_intel", "verified_templates.json")["checks"]}


def urls(res):
    return [u for _l, u in res.links]


@pytest.fixture(autouse=True)
def not_hostile(monkeypatch):
    monkeypatch.setattr(pg, "hostile_reasons", lambda ctx, entity: [])


# ------------------------------------------------------------------ cond 9: URLVoid
def test_urlvoid_for_a_typed_domain_at_green():
    http = FakeHttp()
    res = run_module(PivotsThreatIntel, "domain:example.com", http, tlp="green")
    assert res.status is Status.OK and http.calls == []
    assert urls(res) == ["https://www.urlvoid.com/scan/example.com/"]
    assert "contact the target live" in res.links[0][0] and res.raw["links"][0]["touches_target"]


@pytest.mark.parametrize("tlp", ["amber", "amber+strict"])
def test_urlvoid_hidden_at_amber_and_above(tlp):
    res = run_module(PivotsThreatIntel, "domain:example.com", tlp=tlp)
    assert res.status is Status.SKIPPED and res.reason_code == "tlp" and res.links == []


def test_urlvoid_never_for_discovered_or_hostile_domains(monkeypatch):
    res = run_module(PivotsThreatIntel, "domain:example.com", tlp="clear", is_seed=False, depth=1)
    assert res.links == [] and res.reason_code == "not_applicable"
    monkeypatch.setattr(pg, "hostile_reasons", lambda ctx, entity: ["hostile-shaped name"])
    res = run_module(PivotsThreatIntel, "domain:example.com", tlp="clear")
    assert res.links == [] and res.reason_code == "policy"


# ------------------------------------------------------------------ cond 8: CyberCrime-Tracker URL search ({urlhp})
def test_url_search_sends_host_and_path_only():
    res = run_module(PivotsThreatIntel, "url:https://user:pw@Example.com:8443/panel/gate.php?id=1#x", tlp="amber")
    assert res.status is Status.OK  # no TLP ceiling: the renderers show it as non-clickable text at AMBER
    assert urls(res) == ["https://cybercrime-tracker.net/index.php?search=example.com%3A8443%2Fpanel%2Fgate.php"]
    assert links.BADGE_UNKNOWN_OPERATOR in res.links[0][0]
    assert res.raw["links"][0]["disclosure"].startswith("opening sends ")


@pytest.mark.parametrize("value", ["url:http://192.168.1.10/panel/", "url:http://nas.local/gate.php", "url:http://[fd00::1]/x"])
def test_url_search_never_for_internal_hosts(value):
    res = run_module(PivotsThreatIntel, value, tlp="clear")
    assert res.links == [] and res.reason_code == "not_applicable"


def test_urlhp_encoder_refuses_non_http_values():
    with pytest.raises(ValueError):
        pg.urlhp("ftp://example.com/x")
    gl = pg.module_links("threat_intel_ioc")["cybercrime_tracker_url"]
    assert pg.render(gl, Entity(EntityType.URL, "javascript:alert(1)")) is None
    assert CHECKS["cybercrime_tracker_url_form"]["status"] == 200


def test_red_emits_nothing():
    res = run_module(PivotsThreatIntel, "url:https://example.com/x", tlp="red")
    assert res.status is Status.SKIPPED and res.reason_code == "tlp" and res.links == []


# ------------------------------------------------------------------ core links, cond 10-11
def test_ipv4_core_links_in_curated_order():
    out = [r for r in links.pivot_links_for(Entity.make("ipv4", "9.9.9.9")) if r.ref.startswith("threat_intel_ioc:")]
    assert [r.ref.split(":")[1] for r in out] == ["nerd_ip", "fortiguard_search", "multirbl", "honeylabs", "cybercrime_tracker"]
    by_id = {r.ref.split(":")[1]: r for r in out}
    assert by_id["fortiguard_search"].antibot and by_id["honeylabs"].antibot
    for ident in ("multirbl", "honeylabs", "cybercrime_tracker"):
        assert links.BADGE_UNKNOWN_OPERATOR in by_id[ident].badge
    assert "automated DNSBL checks use the DNS modules" in by_id["multirbl"].label
    grey = links.render("scanner_intel_g02_3:greynoise_viz_ip", Entity.make("ipv4", "9.9.9.9"))
    assert grey.url == "https://viz.greynoise.io/ips/9.9.9.9"


def test_threatbook_is_pending_and_never_rendered():
    assert not [link for link in links.templates() if "threatbook" in link.host]
    pending = pg.pack_data("threat_intel_ioc")["x_pending"][0]
    assert pending["id"] == "threatbook_ip" and pending["login_required"] is True and pending["max_tlp"] == "green"
    assert pending["badge"] == "foreign provider (CN): queries are logged abroad"


def test_malware_family_values_never_reach_the_unknown_tier_tracker():
    out = [r for r in links.pivot_links_for(Entity.make("malware_family", "zeus")) if r.host == "cybercrime-tracker.net"]
    assert out == []


def test_golden_urls():
    for g in GOLDEN:
        entity = Entity.make(g["type"], g["value"])
        pack, ident = g["ref"].split(":")
        rendered = links.render(g["ref"], entity) if g["renderer"] == "core" else pg.render(pg.module_links(pack)[ident], entity)
        assert rendered is not None and rendered.url == g["url"], g
