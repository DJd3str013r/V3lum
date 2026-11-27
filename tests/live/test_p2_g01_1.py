"""Live checks of batch p2-G01-1 (digital_asset_links P008, govbr_domains P009, nrd_feeds P005); run with
V3LUM_LIVE=1.

Keyless sources only, benign public values: google.com and example.com for Digital Asset Links, the SISP
gov.br list (receita.gov.br), the WhoisDS free daily list of a recent date and the registro.br release
list (downloaded through the dataset manager exactly as `v3lum data update` does, matched locally).
The keyed modules (hostio, securitytrails, domainsdb_search) have no team key in this environment: the
check asserts NEEDS_KEY without any request. nrd_smet has 'unknown' terms and is never run: the check
asserts the licence refusal. A 403/429/geo-block/timeout from this datacenter egress is an acceptable
outcome when the module reports it as could-not-verify, never as an absence.
"""

from __future__ import annotations

import json
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest

from tests.fakes import FakeHttp, run_module
from v3lum.config import Config
from v3lum.core import module as module_mod
from v3lum.core import policy
from v3lum.core.context import RunInfo, Runtime, ScanOptions
from v3lum.core.entities import Entity, EntityType
from v3lum.core.models import Status
from v3lum.modules.domain_dns import nrd_feeds
from v3lum.modules.domain_dns.digital_asset_links import DigitalAssetLinks
from v3lum.modules.domain_dns.domainsdb_search import DomainsdbSearch
from v3lum.modules.domain_dns.govbr_domains import DATASET as GOVBR_DATASET
from v3lum.modules.domain_dns.govbr_domains import GovbrDomains
from v3lum.modules.domain_dns.hostio import HostIo
from v3lum.modules.domain_dns.nrd_feeds import NrdFeeds, NrdSmet
from v3lum.modules.domain_dns.securitytrails import SecurityTrails

pytestmark = pytest.mark.live
COULD_NOT_VERIFY = {Status.BLOCKED, Status.RATE_LIMITED, Status.QUOTA, Status.ERROR, Status.UNAVAILABLE}


def live_runtime(**settings) -> Runtime:
    cfg = Config()
    cfg.settings.update(settings)
    return Runtime(cfg, no_cache=True)


def outcome(res) -> str:
    return f"{res.status.value} {res.reason_code or ''} {res.error[:300]} {json.dumps(res.source_statuses, default=str)[:400]}"


# ------------------------------------------------------------------ P008
def test_digital_asset_links_google_and_example():
    rt = live_runtime()
    res = run_module(DigitalAssetLinks, "domain:google.com", runtime=rt)
    print("digital_asset_links google.com:", outcome(res), len(res.attributes.get("official_android_apps", [])))
    assert res.status in {Status.OK} | COULD_NOT_VERIFY, outcome(res)
    if res.status is Status.OK:
        apps = res.attributes["official_android_apps"]
        assert apps and all("." in a["package"] for a in apps)
        assert any(len(fp) == 95 for a in apps for fp in a["sha256"])
    empty = run_module(DigitalAssetLinks, "domain:example.com", runtime=rt)
    print("digital_asset_links example.com:", outcome(empty))
    assert empty.status in {Status.EMPTY} | COULD_NOT_VERIFY, outcome(empty)
    if empty.status is Status.EMPTY:
        assert empty.error == "no Digital Asset Links statements published"


# ------------------------------------------------------------------ P009
def test_govbr_domains_real_list():
    rt = live_runtime()
    result = rt.data.update(GOVBR_DATASET)
    print("govbr update:", result)
    if not result.ok:
        res = run_module(GovbrDomains, "domain:receita.gov.br", runtime=rt)
        assert res.status in COULD_NOT_VERIFY, outcome(res)
        return
    res = run_module(GovbrDomains, "domain:receita.gov.br", runtime=rt)
    print("govbr receita.gov.br:", outcome(res), res.attributes.get("official_gov_br"))
    assert res.status is Status.OK and res.attributes["official_gov_br"]["domain"] == "receita.gov.br"
    assert any(p.entity.type is EntityType.CNPJ and p.relation == "registrant" for p in res.pivots)
    miss = run_module(GovbrDomains, "domain:dominio-inexistente-v3lum.gov.br", runtime=rt)
    assert miss.status is Status.EMPTY and "not in the SISP gov.br list" in miss.error


# ------------------------------------------------------------------ P005
def test_nrd_feeds_real_lists():
    rt = live_runtime()
    today = datetime.now(timezone.utc).date()
    installed = None
    for day in (today - timedelta(days=1), today - timedelta(days=2)):
        nrd_feeds.register_whoisds_day(day)
        result = rt.data.update(nrd_feeds.whoisds_name(day))
        print("whoisds update:", result.name, result.status, result.reason[:160])
        if result.ok:
            installed = day
            break
    release = rt.data.update(nrd_feeds.RELEASE_DATASET)
    print("registro.br update:", release.status, release.reason[:160])
    if installed is None and not release.ok:
        res = run_module(NrdFeeds, "domain:example.com", runtime=rt)
        assert res.status is Status.UNAVAILABLE and res.reason_code == "dataset", outcome(res)
        return
    if installed is not None:
        path = Path(rt.data.fetch(nrd_feeds.whoisds_name(installed)))
        names = [n for n in nrd_feeds.read_zip_member(path.read_bytes()).splitlines() if n.strip().isascii() and n.count(".") == 1]
        assert len(names) >= nrd_feeds.MIN_NAMES
        sample = names[len(names) // 2].strip().lower()
        res = run_module(NrdFeeds, f"domain:{sample}", runtime=rt)
        print("nrd_feeds hit:", sample, outcome(res), res.attributes.get("nrd_first_seen"))
        assert res.status is Status.OK and res.attributes["nrd_first_seen"] == installed.isoformat()
        assert not any("newly_registered" in f.tags for f in res.findings)  # no public DoH for an offline module
    miss = run_module(NrdFeeds, "domain:example.com", runtime=rt)
    print("nrd_feeds miss:", outcome(miss))
    assert miss.status in (Status.EMPTY, Status.UNAVAILABLE)
    if release.ok:
        br = run_module(NrdFeeds, "domain:registro.br", runtime=rt)
        print("nrd_feeds .br:", outcome(br))
        assert br.status is Status.EMPTY and "no NRD feed for .br" in br.error


def test_nrd_smet_is_never_run_under_any_profile():
    module_mod.load_modules()
    ent = Entity.make(EntityType.DOMAIN, "example.com")
    pctx = policy.make_context(live_runtime(), ScanOptions(), explicit={"nrd_smet"}, path="run")
    decision = policy.decide(NrdSmet, ent, pctx, run=RunInfo(entity=ent, is_seed=True))
    assert not decision.allowed and decision.reason_code == "licence", decision


# ------------------------------------------------------------------ keyed modules (no team key here)
@pytest.mark.parametrize("cls,value", [(HostIo, "domain:example.com"), (SecurityTrails, "domain:example.com"),
                                       (DomainsdbSearch, "keyword:example")])
def test_keyed_modules_need_their_key_and_send_nothing(cls, value):
    http = FakeHttp()
    res = run_module(cls, value, http)
    assert res.status in (Status.NEEDS_KEY, Status.SKIPPED) and not http.calls, outcome(res)
