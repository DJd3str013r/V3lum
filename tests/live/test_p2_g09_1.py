"""Live checks of batch p2-G09-1 (deepdarkcti_index P198, onion_lookup P199, chainabuse P204,
goplus_security P206, walletexplorer P208); run with V3LUM_LIVE=1.

Benign or public values only: the Tor Project's own onion service, a synthetic valid-checksum onion
(never crawled), a ransomware leak-site onion taken from today's deepdarkCTI list (matched offline: the
onion itself is never contacted), well-known group names, the Ethereum Foundation wallet, the OFAC
SDN-listed Ronin-bridge exploiter address (a public IOC) and WalletExplorer's own API-page example
address with a generic caller id. Chainabuse needs a key and its terms are noncommercial: only the
corporate policy decision and the no-key path are checked (no request).

A 403/429/challenge/timeout from this datacenter egress is an acceptable outcome when it is reported as
could-not-verify (statuses blocked / rate_limited / quota / error / unavailable, never 'empty').
"""

from __future__ import annotations

import pytest

from tests.fakes import run_module
from v3lum.config import Config
from v3lum.core import policy
from v3lum.core.context import RunInfo, Runtime, ScanOptions
from v3lum.core.entities import Entity
from v3lum.core.entities import EntityType as T
from v3lum.core.models import Status
from v3lum.modules.crypto.chainabuse import Chainabuse
from v3lum.modules.crypto.goplus_security import EF_WALLET, GoplusSecurity
from v3lum.modules.crypto.walletexplorer import INDEX_DATASET, Walletexplorer
from v3lum.modules.darkweb_ransomware import deepdarkcti_index as ddc
from v3lum.modules.darkweb_ransomware.deepdarkcti_index import LISTS, DeepdarkctiIndex
from v3lum.modules.darkweb_ransomware.onion_lookup import TOR_PROJECT_ONION, OnionLookup
from v3lum.modules.darkweb_ransomware.onion_safety import AHMIA_DATASET

pytestmark = pytest.mark.live
COULD_NOT_VERIFY = {Status.BLOCKED, Status.RATE_LIMITED, Status.QUOTA, Status.ERROR, Status.UNAVAILABLE}
SYNTHETIC_ONION = "7lv6yjwjmm4xc5kxdf4lozqu5vjeq4s4il4ut5gg4wg2vcpumg7rvxyd.onion"
RONIN = "0x098b716b8aaf21512996dc57eb0615e2383e2f96"
WE_EXAMPLE = "16SbwNa22nBwhLtg6HzWVYFQiUxtNzAUpt"


def live_runtime() -> Runtime:
    return Runtime(Config(), no_cache=True)


def _update(rt: Runtime, names: list[str]) -> dict[str, object]:
    out = {}
    for name in names:
        result = rt.data.update(name)
        out[name] = result
        print(f"{name}: {result.status} {result.reason[:160]} {result.new_sha256[:12]}")
        assert result.status in ("updated", "unchanged", "failed")
        if result.status == "failed":
            assert result.reason
    return out


def _could_not_verify(res) -> bool:
    if res.status in COULD_NOT_VERIFY:
        print(f"could not verify: {res.status.value} {res.reason_code} {res.error[:160]}")
        return True
    return False


# ------------------------------------------------------------------ deepdarkCTI (P198)
def test_deepdarkcti_lists_parse_healthy_and_match_offline():
    rt = live_runtime()
    lists = _update(rt, [ddc.list_dataset(n) for n in LISTS])
    commits = _update(rt, [ddc.commit_dataset(n) for n in LISTS])
    _update(rt, [AHMIA_DATASET])
    installed = [n for n in LISTS if lists[ddc.list_dataset(n)].ok]
    if not installed:
        pytest.skip("no deepdarkCTI list could be installed from this egress (could not verify)")
    print(f"commit dates: {[(n, r.status) for n, r in commits.items()]}")
    text = rt.data.fetch_text(ddc.list_dataset("ransomware_gang"))
    parsed = ddc.parse_ddc_list(text, "ransomware_gang")
    assert ddc.list_health(parsed) is None, ddc.list_health(parsed)
    leak = next(e for e in parsed["entries"] if e["kind"] == "onion" and e["group"] and not e["index_row"])
    res = run_module(DeepdarkctiIndex, f"onion:{leak['key']}", runtime=rt)
    if _could_not_verify(res):
        return
    assert res.status is Status.OK and res.requests == 0, (res.status, res.error)
    assert any(f.data["group"] == leak["group"] for f in res.findings)
    assert all("suspicious" in f.tags and f.severity.label in ("info", "medium") for f in res.findings)
    assert all(p.expand is False for p in res.pivots)
    group = run_module(DeepdarkctiIndex, "threat_actor:lockbit", runtime=rt)
    assert group.status in {Status.OK, Status.EMPTY} | COULD_NOT_VERIFY
    miss = run_module(DeepdarkctiIndex, f"onion:{SYNTHETIC_ONION}", runtime=rt)
    assert miss.status in (Status.EMPTY, Status.ERROR), (miss.status, miss.error)  # ERROR only if a list is unusable


# ------------------------------------------------------------------ AIL onion-lookup + Ahmia filter (P199)
def test_onion_lookup_tor_project_and_unknown_onion():
    rt = live_runtime()
    banned = _update(rt, [AHMIA_DATASET])
    res = run_module(OnionLookup, f"onion:{TOR_PROJECT_ONION}", runtime=rt)
    if not banned[AHMIA_DATASET].ok:
        assert res.status is Status.UNAVAILABLE  # fail closed: nothing sent without the filter
        pytest.skip("Ahmia banned list could not be installed from this egress")
    if not _could_not_verify(res):
        assert res.status is Status.OK, (res.status, res.error)
        assert res.attributes["first_seen"] and res.attributes["onion_titles"]
    unknown = run_module(OnionLookup, f"onion:{SYNTHETIC_ONION}", runtime=rt)
    if not _could_not_verify(unknown):
        assert unknown.status is Status.EMPTY, (unknown.status, unknown.error)


# ------------------------------------------------------------------ Chainabuse (P204): policy and key only
def test_chainabuse_is_licence_gated_and_keyed():
    rt = live_runtime()
    entity = Entity.make(T.ETH, EF_WALLET)
    decision = policy.decide(Chainabuse, entity, policy.make_context(rt, ScanOptions(), path="scan"), run=RunInfo(entity=entity, is_seed=True))
    print(f"chainabuse under corporate: {decision.status} {decision.reason_code} {decision.reason[:120]}")
    assert decision.allowed is False and decision.reason_code in ("licence", "needs_key")
    res = run_module(Chainabuse, f"eth_address:{EF_WALLET}", runtime=rt)
    assert res.status is Status.NEEDS_KEY and res.requests == 0


# ------------------------------------------------------------------ GoPlus (P206)
def test_goplus_clean_wallet_and_flagged_exploiter():
    rt = live_runtime()
    clean = run_module(GoplusSecurity, f"eth_address:{EF_WALLET}", runtime=rt)
    if not _could_not_verify(clean):
        assert clean.status is Status.EMPTY, (clean.status, clean.error, [f.title for f in clean.findings])
        assert clean.attributes["goplus_flags"]["1"]["phishing_activities"] is False
    flagged = run_module(GoplusSecurity, f"eth_address:{RONIN}", runtime=rt)
    if not _could_not_verify(flagged):
        assert flagged.status is Status.OK, (flagged.status, flagged.error)
        assert any(f.data.get("flag") == "stealing_attack" for f in flagged.findings)
        assert all("sanctions" not in f.tags for f in flagged.findings)


# ------------------------------------------------------------------ WalletExplorer (P208)
def test_walletexplorer_labelled_example():
    rt = live_runtime()
    rt.config.settings["walletexplorer_caller_id"] = "osint-team"  # generic team identifier
    _update(rt, [INDEX_DATASET])
    res = run_module(Walletexplorer, f"btc_address:{WE_EXAMPLE}", runtime=rt)
    if _could_not_verify(res):
        return
    assert res.status is Status.OK, (res.status, res.error)
    cluster = res.attributes["wallet_cluster"]
    assert cluster["label"] == "BTC-e.com" and cluster["updated_to_block"] > 900000
    print(f"WalletExplorer category {cluster['category']}, data as of block {cluster['updated_to_block']}")
    assert "stop_node" in res.findings[0].tags
