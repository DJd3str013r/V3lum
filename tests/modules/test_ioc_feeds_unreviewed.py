"""ioc_feeds_unreviewed (P159 cond 3): feeds without recorded terms, matched locally, default off.

Fixtures in tests/fixtures/ioc_feeds_unreviewed/ (live 2026-11-26, trimmed; public C2 infrastructure kept
on purpose): C2IntelFeeds ``c2intel_ipc2s_30day.csv``, ``c2intel_domain_url_ip_30day.csv``,
``c2intel_domainc2s_fronting.csv`` (a 'Fronting Domain' row) and ``c2intel_header_only_0_rows.csv``
(derived: header only); ThreatView ``threatview_ip_high.txt`` (with the published junk lines 0.0.0.2,
1.0.0.0, 249.223.175.5 and the zero-padded 120.229.26.013), ``threatview_domain_high.txt`` (with
reverse-DNS and numeric junk), ``threatview_md5_all.txt`` and ``threatview_cobaltstrike_c2_defanged_stale.txt``
(defanged header, last generated 2026-02-08); ViriBack ``viriback_c2_dump.csv`` (with a Cloudflare IP).
"""

from __future__ import annotations

import pytest

from tests.fakes import FakeHttp, module_fixture, run_module
from v3lum import paths
from v3lum.core.entities import EntityType as T
from v3lum.core.models import Status
from v3lum.modules.threat_intel_ioc import ioc_feeds_offline as mod
from v3lum.modules.threat_intel_ioc.ioc_feeds_offline import IocFeedsUnreviewed


@pytest.fixture(autouse=True)
def _fresh_parse_cache(monkeypatch):
    """Parsed feed copies are memoized per process by dataset version: start every test empty."""
    from collections import OrderedDict

    from v3lum.modules.threat_intel_ioc import abusech as _abusech

    monkeypatch.setattr(_abusech, "_MEMO", OrderedDict())


def fx(name):
    return module_fixture(IocFeedsUnreviewed, name)


def install(name, fixture_name):
    (paths.datasets_dir() / name).write_text(fx(fixture_name), encoding="utf-8")


def install_all():
    install(mod.DS_C2INTEL_IP, "c2intel_ipc2s_30day.csv")
    install(mod.DS_C2INTEL_DOMAIN, "c2intel_domain_url_ip_30day.csv")
    install(mod.DS_TV_IP, "threatview_ip_high.txt")
    install(mod.DS_TV_DOMAIN, "threatview_domain_high.txt")
    install(mod.DS_TV_MD5, "threatview_md5_all.txt")
    install(mod.DS_TV_COBALT, "threatview_cobaltstrike_c2_defanged_stale.txt")
    install(mod.DS_VIRIBACK, "viriback_c2_dump.csv")


def run(value, **kw):
    http = FakeHttp()
    res = run_module(IocFeedsUnreviewed, value, http, **kw)
    assert http.calls == []  # offline: panel and C2 URLs are never visited
    return res


def test_metadata_unknown_terms_default_off():
    cls = IocFeedsUnreviewed
    assert (cls.terms, cls.default_enabled, cls.disclosure, cls.hosts) == ("unknown", False, "none", ())
    assert set(cls.terms_sources.values()) == {"unknown"}
    assert set(cls.sources) == {"github.ioc_feeds_unreviewed_c2intel", "threatview.feeds", "viriback.c2_tracker"}


def test_c2intel_possible_label_is_low():
    install_all()
    res = run("ipv4:1.117.74.144")
    finding = res.findings[0]
    assert finding.title == "Listed in unreviewed offline feeds"
    assert finding.severity.label == "low" and {"suspicious", "c2"} <= set(finding.tags)
    assert "Cobalt Strike" in {p.entity.value for p in res.pivots if p.entity.type is T.MALWARE}


def test_fronting_domains_are_never_hostile():
    install(mod.DS_C2INTEL_DOMAIN, "c2intel_domainc2s_fronting.csv")
    res = run("domain:360.net")
    assert res.status is Status.OK
    assert [f.severity.label for f in res.findings] == ["info"]
    assert "blocklists" not in res.attributes and "malicious" not in res.attributes


def test_header_only_feed_is_unhealthy():
    install(mod.DS_C2INTEL_DOMAIN, "c2intel_header_only_0_rows.csv")
    res = run("domain:1.win-faw.win")
    assert res.status is Status.ERROR and "parsed to 0 rows" in res.error


def test_threatview_junk_is_dropped_and_padded_octets_normalised():
    install_all()
    assert run("ipv4:120.229.26.13").status is Status.OK
    assert run("ipv4:119.42.148.186").status is Status.OK
    assert run("ipv4:182.16.98.84").findings[0].data["feeds"][0]["feed"] == "ThreatView"
    rows = mod._index(next(f for f in mod.FEEDS if f.id == "threatview"), mod.parse_threatview_list(fx("threatview_ip_high.txt"), T.IPV4))
    assert {"bogon", "network_address"} <= set(rows.dropped)
    assert "ipv4:0.0.0.2" not in rows.rows and "ipv4:1.0.0.0" not in rows.rows


def test_threatview_large_domain_list_is_validated_on_hit():
    install_all()
    assert run("domain:00000001gogoli.info").status is Status.OK
    assert run("domain:example.com").status is Status.EMPTY


def test_threatview_md5():
    install_all()
    res = run("md5:0010c09e584eeee0cf2231fc30a8c65e")
    assert res.status is Status.OK and "malware" in res.findings[0].tags


def test_threatview_c2_defanged_header_and_stale():
    rows, generated = mod.parse_threatview_c2(fx("threatview_cobaltstrike_c2_defanged_stale.txt"))
    assert generated == "2026-02-08T00:00:00Z"  # 'threatview[.]io' header refanged before use
    assert ("ipv4", "107.150.105.91") in {(r[0].value, r[1]) for r in rows}
    assert any(r[2].get("role") == "beacon_host" and r[1] == "myteamserver.online" for r in rows)
    install(mod.DS_TV_COBALT, "threatview_cobaltstrike_c2_defanged_stale.txt")
    res = run("ipv4:107.150.105.91")  # newest detection 2026-02-08: more than 3x its 1-day interval
    assert res.status is Status.UNAVAILABLE and "stale" in res.error


def test_viriback_panel_url_and_old_listing():
    install_all()
    res = run("url:http://111.68.15.221:8888/supershell/login/")
    finding = res.findings[0]
    assert finding.severity.label == "medium" and {"malicious", "c2"} <= set(finding.tags)
    assert "Supershell" in {p.entity.value for p in res.pivots}
    res = run("url:http://officeman.tk/images/admin.php")  # first seen 2019: an old URL listing is low
    assert res.findings[0].severity.label == "low"


def test_cdn_ips_in_the_dump_are_suppressed(monkeypatch):
    monkeypatch.setattr(mod, "is_noise", lambda ent: ent.value.startswith("172.64."))
    install_all()
    assert run("ipv4:172.64.80.1").status is Status.EMPTY
    assert run("url:https://cel2esia.top/login").status is Status.OK


def test_missing_lists_are_unavailable():
    res = run("ipv4:1.117.74.144")
    assert res.status is Status.UNAVAILABLE and res.reason_code == "dataset"
