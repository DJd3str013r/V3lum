"""Live checks of batch p1-G09-1 (ransomlook P196, ransomware_live P197, ransomfeed P356, crypto_sanctions
P205 split offline/onchain, tron_explorer P207); run with V3LUM_LIVE=1.

Benign or public values only: the golden domain example.com (the trackers' placeholder website, which
must never read as a victim), well-known ransomware group names for the actor views, public OFAC SDN
addresses (the 0xB10C lists and the address the Chainalysis oracle answer was recorded for), the
Ethereum Foundation address (not sanctioned, not frozen) and the USDT-TRC20 contract (a public
contract account). No victim name, natural person or customer wallet is ever searched.

ransomware.live keyless v2 is 'noncommercial' (research profile with a recorded legal basis only):
it is never called here. The check is the corporate policy decision (licence-blocked, manual link,
no request) and the PRO API answering 'Missing X-API-KEY header' without a key (the needs-key path).

A 403/429/challenge/timeout from this datacenter egress is an acceptable outcome when it is reported
as could-not-verify (statuses blocked / rate_limited / quota / error / unavailable, never 'empty').
"""

from __future__ import annotations

import pytest

from tests.fakes import make_ctx, run_module
from v3lum.config import Config
from v3lum.core import policy
from v3lum.core.context import RunInfo, Runtime, ScanOptions
from v3lum.core.entities import Entity
from v3lum.core.entities import EntityType as T
from v3lum.core.http import AuthRequired
from v3lum.core.models import Status
from v3lum.modules.crypto import crypto_sanctions_offline as off
from v3lum.modules.crypto.crypto_sanctions_offline import ASSETS, CryptoSanctionsOffline
from v3lum.modules.crypto.crypto_sanctions_onchain import CryptoSanctionsOnchain
from v3lum.modules.crypto.tron_explorer import USDT_CONTRACT, TronExplorer
from v3lum.modules.darkweb_ransomware import ransomfeed as rf
from v3lum.modules.darkweb_ransomware import ransomlook as rl
from v3lum.modules.darkweb_ransomware import ransomware_live as rwl
from v3lum.modules.darkweb_ransomware.ransomfeed import Ransomfeed
from v3lum.modules.darkweb_ransomware.ransomlook import RansomLook
from v3lum.modules.darkweb_ransomware.ransomware_live import RansomwareLive

pytestmark = pytest.mark.live
COULD_NOT_VERIFY = {Status.BLOCKED, Status.RATE_LIMITED, Status.QUOTA, Status.ERROR, Status.UNAVAILABLE}
OFAC_ETH = "0x0330070FD38Ec3bB94F58FA55D40368271E9e54A"  # OFAC SDN; oracle answer recorded 2026-11-26
EF = "0xde0b295669a9fd93d5f28d9ec85e40f4cb697bae"  # Ethereum Foundation: not sanctioned, not frozen
TRON_OFAC = "TYK29mbyvVxLaLUKdFSTRADMwoxaVbVZQg"  # TRON line of the OFAC USDT list (USDT-TRC20 frozen on 2026-11-26)


def live_runtime() -> Runtime:
    return Runtime(Config(), no_cache=True)


def _update(rt: Runtime, names: list[str]) -> dict[str, object]:
    out = {}
    for name in names:
        result = rt.data.update(name)
        out[name] = result
        print(f"{name}: {result.status} {result.reason[:160]} {result.new_sha256[:12]}")
        assert result.status in ("updated", "unchanged", "failed")
        if result.status == "failed":  # could not verify from this egress: reported, nothing installed
            assert result.reason
    return out


def _could_not_verify(res) -> bool:
    if res.status in COULD_NOT_VERIFY:
        print(f"could not verify: {res.status.value} {res.reason_code} {res.error[:160]}")
        return True
    return False


# ------------------------------------------------------------------ RansomLook (P196)
def test_ransomlook_domain_search_and_actor_index():
    rt = live_runtime()
    res = run_module(RansomLook, "domain:example.com", runtime=rt, is_seed=True)
    if not _could_not_verify(res):
        assert res.status is Status.EMPTY, (res.status, res.error, [f.title for f in res.findings])
        assert res.attributes["ransomware_listing"].startswith("not listed by RansomLook (data as of 20")
    results = _update(rt, [rl.GROUPS_DATASET, rl.RECENT_DATASET])
    actor = run_module(RansomLook, "threat_actor:akira", runtime=rt, is_seed=True)
    if all(r.ok for r in results.values()):  # answered from the daily index: no value sent
        assert actor.status is Status.OK, (actor.status, actor.error)
        assert actor.attributes["ransomware_group"] == "akira" and actor.attributes["ransomware_group_profile"]["known"] is True
        assert actor.findings[0].title == "Ransomware group tracked by RansomLook" and actor.findings[0].severity.label == "info"
        assert all(p.expand is False for p in actor.pivots if p.entity.type is T.ONION)
    else:
        assert actor.status in COULD_NOT_VERIFY | {Status.OK}, (actor.status, actor.error)


# ------------------------------------------------------------------ Ransomfeed (P356)
def test_ransomfeed_rss_index_placeholder_rows_and_gang_card():
    rt = live_runtime()
    results = _update(rt, [rf.RSS_DATASET])
    res = run_module(Ransomfeed, "domain:example.com", runtime=rt, is_seed=True)
    if not _could_not_verify(res):  # the API answers the killsec rows whose website is the placeholder
        assert res.status is Status.EMPTY, (res.status, res.error, [f.title for f in res.findings])
        assert res.attributes["ransomware_listing"].startswith("not listed by Ransomfeed (data as of 20")
        assert res.raw["api"]["counts"]["api_rows"] >= 0 and res.raw["api"]["counts"]["matched"] == 0
        if results[rf.RSS_DATASET].ok:
            assert res.raw["api"]["counts"]["rss_items"] > 100
    gang = run_module(Ransomfeed, "threat_actor:killsec", runtime=rt, is_seed=True)
    if not _could_not_verify(gang):
        assert gang.status is Status.OK, (gang.status, gang.error)
        profile = gang.attributes["ransomware_group_profile"]
        assert profile["tracker"] == "ransomfeed" and profile["name"].lower() == "killsec"
        assert not any(p.entity.type is T.ONION for p in gang.pivots)  # ransomfeed cards never pivot onions


# ------------------------------------------------------------------ ransomware.live (P197)
def test_ransomware_live_corporate_gate_and_pro_needs_key():
    rt = live_runtime()
    org = Entity.make(T.DOMAIN, "example.com")
    decision = policy.decide(RansomwareLive, org, policy.make_context(rt, ScanOptions(), path="scan"), run=RunInfo(entity=org, is_seed=True))
    assert (decision.allowed, decision.status, decision.reason_code) == (False, Status.SKIPPED, "licence")
    assert decision.emit_manual_link is True  # cond 3: corporate profile = one line + the manual search link
    ctx = make_ctx(RansomwareLive, runtime=rt, allowed_sources=(rwl.SOURCE_PRO,))
    resp = ctx.http.get(rwl.PRO_SEARCH_URL, params={"q": "example.com"}, source=rwl.SOURCE_PRO, headers={"Accept": "application/json"})
    print(f"PRO without key: HTTP {resp.status} {resp.content[:120]!r}")
    if resp.status in (403, 429) or resp.status >= 500:
        pytest.skip(f"api-pro.ransomware.live answered {resp.status} from this egress (could not verify)")
    assert resp.status == 401 and b"X-API-KEY" in resp.content
    with pytest.raises(AuthRequired):
        ctx.http.check(resp)


# ------------------------------------------------------------------ OFAC lists offline (P205)
def test_ofac_lists_download_and_match_offline():
    rt = live_runtime()
    results = _update(rt, [off.dataset_name(a) for a in ASSETS])
    res = run_module(CryptoSanctionsOffline, f"eth_address:{EF}", runtime=rt)
    if not all(r.ok for r in results.values()):
        assert res.status in COULD_NOT_VERIFY, (res.status, res.error)  # a missing list: never 'not on OFAC lists'
        pytest.skip(f"some OFAC lists were not installed: {[n for n, r in results.items() if not r.ok]}")
    assert res.status is Status.EMPTY and res.attributes["sanctions_status"].startswith("not on OFAC lists as of 20")
    eth_path = rt.data.fetch(off.dataset_name("ETH"))
    first = off.parse_list(eth_path.read_text(encoding="utf-8"))[0]  # any address of today's ETH list
    hit = run_module(CryptoSanctionsOffline, f"eth_address:{first}", runtime=rt)
    assert hit.status is Status.OK and hit.findings[0].title == "Address on the OFAC SDN list (US)"
    assert hit.findings[0].severity.label == "critical" and "ETH" in hit.findings[0].data["lists"]
    tron = run_module(CryptoSanctionsOffline, f"other_crypto_address:{TRON_OFAC}", runtime=rt)
    assert tron.status in (Status.OK, Status.EMPTY)  # format matching inside the mixed USDT list
    print(f"TRON OFAC line still listed: {tron.status.value} {tron.findings[0].data['lists'] if tron.findings else []}")


# ------------------------------------------------------------------ on-chain checks (P205)
def test_onchain_oracle_and_issuer_freezes():
    rt = live_runtime()
    listed = run_module(CryptoSanctionsOnchain, f"eth_address:{OFAC_ETH}", runtime=rt)
    if not _could_not_verify(listed):
        assert listed.status is Status.OK and listed.attributes["sanctioned"] is True, (listed.status, listed.error)
        assert listed.attributes["onchain_checks"]["chainalysis_oracle"]
        assert any(f.severity.label == "critical" and "sanctions" in f.tags for f in listed.findings)
    clean = run_module(CryptoSanctionsOnchain, f"eth_address:{EF}", runtime=rt)
    if not _could_not_verify(clean):
        assert clean.status is Status.EMPTY and "sanctioned" not in clean.attributes, (clean.status, clean.error)
        assert clean.attributes["sanctions_status"].startswith("not listed by the Chainalysis sanctions checks as of 20")
    tron = run_module(CryptoSanctionsOnchain, f"other_crypto_address:{TRON_OFAC}", runtime=rt)
    if not _could_not_verify(tron):
        frozen = [f for f in tron.findings if "issuer_freeze" in f.tags]
        print(f"USDT-TRC20 freeze of the OFAC TRON line: {tron.status.value} {tron.attributes.get('issuer_frozen')}")
        assert tron.status in (Status.OK, Status.EMPTY) and (tron.status is Status.EMPTY or frozen)
        assert all(f.severity.label == "high" and "sanctions" not in f.tags for f in frozen)  # frozen, never 'sanctioned'


# ------------------------------------------------------------------ TronGrid (P207)
def test_tron_explorer_public_contract_account():
    rt = live_runtime()
    res = run_module(TronExplorer, f"other_crypto_address:{USDT_CONTRACT}", runtime=rt)
    if _could_not_verify(res):
        return
    assert res.status is Status.OK, (res.status, res.error)
    a = res.attributes
    assert a["chain"] == "tron" and a["balance"].endswith(" TRX") and a["transfers_seen"] >= 0
    assert all(p.expand is False for p in res.pivots if p.relation == "transacted_with")
    assert "tronscan.api" not in res.source_statuses  # no Tronscan row without its key
