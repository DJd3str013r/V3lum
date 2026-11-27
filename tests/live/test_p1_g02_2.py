"""Live checks of batch p1-G02-2 (tor_exit_local, tor_onionoo, tor_exit_history, shodan_internetdb,
ip_offline_db, ip_offline_geo, ip_blocklists); run with V3LUM_LIVE=1.

Keyless sources, benign public values only: 8.8.8.8 / AS15169 / 2001:4860:4860::8888 (Google public
DNS) and, for the Tor modules, one current Tor exit taken from the live bulk exit list (public relay
infrastructure; Onionoo exists to answer about relays). Dataset modules download the real files
through the dataset manager (as `v3lum data update` does), then match offline.

The licence profile is respected here too: under the shipped corporate profile the noncommercial
sources (Shodan InternetDB, the noncommercial blocklist feeds) are licence-blocked, so they are not
called - the check asserts the SKIPPED 'licence' decision instead (P043 c3: nothing calls
internetdb.shodan.io under corporate). bgp.tools needs the team role contact (setting contact_email)
and is SKIPPED 'config' without it. A 403/429/challenge/timeout from this datacenter egress is an
acceptable outcome when the module reports it as could-not-verify, never as an absence.
"""

from __future__ import annotations

import pytest

from tests.fakes import run_module
from v3lum.config import Config
from v3lum.core import module as module_mod
from v3lum.core import policy
from v3lum.core.context import RunInfo, Runtime, ScanOptions
from v3lum.core.datasets import DATASETS
from v3lum.core.entities import Entity, EntityType
from v3lum.core.models import Status
from v3lum.modules.ip_network import tor_exit_history as history_mod
from v3lum.modules.ip_network.ip_offline_db import IPTOASN_V4, IPTOASN_V6, IpOfflineDb
from v3lum.modules.ip_network.ip_offline_geo import ASN as DBIP_ASN
from v3lum.modules.ip_network.ip_offline_geo import COUNTRY as DBIP_COUNTRY
from v3lum.modules.ip_network.ip_offline_geo import IpOfflineGeo
from v3lum.modules.ip_network.shodan_internetdb import ShodanInternetDB
from v3lum.modules.ip_network.tor_exit_history import TorExitHistory
from v3lum.modules.ip_network.tor_exit_local import BULK_EXIT_LIST, RUNNING_RELAYS, TorExitLocal, parse_bulk_exit_list
from v3lum.modules.ip_network.tor_onionoo import TorOnionoo
from v3lum.modules.threat_intel_ioc.ip_blocklists import FEEDS, IpBlocklists, dataset_name, parse_feed

pytestmark = pytest.mark.live
COULD_NOT_VERIFY = {Status.BLOCKED, Status.RATE_LIMITED, Status.QUOTA, Status.ERROR, Status.UNAVAILABLE}


def live_runtime() -> Runtime:
    return Runtime(Config(), no_cache=True)


def corporate_decision(cls, value: str):
    module_mod.load_modules()
    etype, _, raw = value.partition(":")
    ent = Entity.make(EntityType.parse(etype), raw)
    rt = live_runtime()
    return policy.decide(cls, ent, policy.make_context(rt, ScanOptions(), path="run"), run=RunInfo(entity=ent, is_seed=True))


def a_current_exit(rt: Runtime) -> str | None:
    """One current Tor exit from the live bulk list (None when the list could not be fetched)."""
    if not rt.data.update(BULK_EXIT_LIST).ok:
        return None
    with open(rt.data.fetch(BULK_EXIT_LIST, ttl=10**12), encoding="utf-8") as fh:
        exits, _invalid = parse_bulk_exit_list(fh.read())
    return sorted(e for e in exits if ":" not in e)[0] if exits else None


# ------------------------------------------------------------------ P040
def test_tor_exit_local_live():
    rt = live_runtime()
    res = run_module(TorExitLocal, "ipv4:8.8.8.8", runtime=rt)
    assert res.status in {Status.EMPTY} | COULD_NOT_VERIFY, (res.status, res.error)
    if res.status is Status.EMPTY:
        assert rt.data.info(BULK_EXIT_LIST).present and rt.data.info(RUNNING_RELAYS).present
        exit_ip = a_current_exit(rt)
        assert exit_ip
        hit = run_module(TorExitLocal, f"ipv4:{exit_ip}", runtime=rt)
        assert hit.status is Status.OK and hit.attributes["is_tor_exit"] is True
        assert hit.findings[0].severity.label == "low" and "anonymizer" in hit.findings[0].tags


def test_tor_onionoo_live():
    rt = live_runtime()
    not_tor = run_module(TorOnionoo, "ipv4:8.8.8.8", runtime=rt)
    assert not_tor.status in {Status.SKIPPED} | COULD_NOT_VERIFY, (not_tor.status, not_tor.error)
    if not_tor.status is Status.SKIPPED:
        assert not_tor.requests == 0  # 8.8.8.8 never left the machine
    exit_ip = a_current_exit(rt)
    if exit_ip is None:
        pytest.skip("bulk exit list not reachable from this egress")
    res = run_module(TorOnionoo, f"ipv4:{exit_ip}", runtime=rt)
    assert res.status in {Status.OK, Status.EMPTY} | COULD_NOT_VERIFY, (res.status, res.error)
    if res.status is Status.OK:
        assert res.attributes["is_tor_relay"] is True and "contact" not in str(res.raw)
        assert all(r["fingerprint"] for r in res.attributes["tor_relay"])


def test_tor_exit_history_live_current_month():
    rt = live_runtime()
    exit_ip = a_current_exit(rt)
    if exit_ip is None:
        pytest.skip("bulk exit list not reachable from this egress")
    today = rt.now().date()
    name = history_mod.register_collector_month(today.year, today.month, current=True)
    result = rt.data.update(name)  # what `v3lum data update` does (8-15 MB tar.xz)
    if not result.ok:
        pytest.skip(f"CollecTor archive not downloadable from this egress: {result.reason}")
    import datetime as dt

    day = (today - dt.timedelta(days=2)).isoformat() if today.day > 2 else today.isoformat()
    rt.config.settings["tor_exit_history_dates"] = [day]
    res = run_module(TorExitHistory, f"ipv4:{exit_ip}", runtime=rt)
    assert res.status in {Status.OK} | COULD_NOT_VERIFY, (res.status, res.error)
    if res.status is Status.OK:
        answer = next(a for a in res.attributes["tor_exit_history"] if a["source"] == "CollecTor")
        assert answer["state"] in ("was_exit", "not_exit_on_date") and answer["date"] == day


# ------------------------------------------------------------------ P043
def test_shodan_internetdb_is_not_called_under_corporate():
    decision = corporate_decision(ShodanInternetDB, "ipv4:8.8.8.8")
    assert (decision.allowed, decision.reason_code) == (False, "licence")
    assert decision.emit_manual_link is True


# ------------------------------------------------------------------ P047
def test_ip_offline_db_live_iptoasn():
    rt = live_runtime()
    results = {name: rt.data.update(name) for name in (IPTOASN_V4, IPTOASN_V6)}
    if not all(r.ok for r in results.values()):
        pytest.skip(f"IPtoASN not downloadable from this egress: {[r.reason for r in results.values()]}")
    res = run_module(IpOfflineDb, "ipv4:8.8.8.8", runtime=rt)
    assert res.status is Status.OK and res.attributes["asn"] == "AS15169"
    assert res.source_statuses["bgptools.asns"]["reason_code"] == "config"  # no team role contact configured
    v6 = run_module(IpOfflineDb, "ipv6:2001:4860:4860::8888", runtime=rt)
    assert v6.status is Status.OK and v6.attributes["asn"] == "AS15169"
    asn = run_module(IpOfflineDb, "asn:AS15169", runtime=rt)
    assert asn.status is Status.OK and asn.attributes["as_range_count"] > 0


def test_ip_offline_geo_live_dbip_download():
    rt = live_runtime()
    for name in (DBIP_COUNTRY, DBIP_ASN):
        result = rt.data.update(name)
        if not result.ok and "404" in result.reason:
            pytest.skip(f"DB-IP release {DATASETS[name]['url']} not published yet")
        assert result.ok, result.reason  # gzip extracted through safe_extract, mmdb marker validated
    try:
        import maxminddb  # noqa: F401
    except ImportError:
        res = run_module(IpOfflineGeo, "ipv4:8.8.8.8", runtime=rt)
        assert res.status is Status.UNAVAILABLE and res.reason_code == "package"
        return
    res = run_module(IpOfflineGeo, "ipv4:8.8.8.8", runtime=rt)
    assert res.status is Status.OK and res.attributes["asn"] == "AS15169"


# ------------------------------------------------------------------ P149
def test_ip_blocklists_live_open_feeds():
    decision = corporate_decision(IpBlocklists, "ipv4:8.8.8.8")
    allowed = set(decision.allowed_sources or ())
    assert allowed and "blocklist_de.all" not in allowed  # noncommercial feeds stay off under corporate
    rt = live_runtime()
    res = run_module(IpBlocklists, "ipv4:8.8.8.8", runtime=rt, allowed_sources=allowed)
    assert res.status in {Status.OK, Status.EMPTY} | COULD_NOT_VERIFY, (res.status, res.error)
    parsed = {}
    for feed_id, spec in FEEDS.items():
        if spec["source"] not in allowed or spec["kind"] != "net" or 4 not in spec["versions"]:
            continue
        info = rt.data.info(dataset_name(feed_id))
        if info.present:
            with open(rt.data.fetch(dataset_name(feed_id), ttl=10**12), "rb") as fh:
                parsed[feed_id] = parse_feed(feed_id, fh.read()).entries
    assert parsed and all(count >= 1 or FEEDS[f].get("may_be_empty") for f, count in parsed.items()), parsed
