"""Live checks of batch p2-G09-2 (btc_explorers P211, evm_explorers P212, telegram_channel_watch P357); run
with V3LUM_LIVE=1.

Benign public values only: the Bitcoin genesis address (1A1zP1...), a freshly minted random Litecoin address
(nobody's), the Ethereum Foundation multisig, the ens.eth name, Telegram's own public channel @telegram and
the deepdarkCTI Telegram lists (GPL-3.0, downloaded at runtime by the dataset manager, never vendored).
Keyed adapters (Etherscan, Ethplorer, Blockchair, BlockCypher token) are not called: the team keys are not
configured here. A 403/429/challenge/timeout from this datacenter egress is an acceptable outcome when it is
reported as could-not-verify (blocked / rate_limited / quota / error / unavailable, never 'empty').
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from tests.fakes import run_module
from v3lum.config import Config
from v3lum.core.context import Runtime
from v3lum.core.models import Status
from v3lum.core.orgprofile import OrgProfile
from v3lum.modules.crypto.btc_explorers import BtcExplorers
from v3lum.modules.crypto.evm_explorers import EvmExplorers
from v3lum.modules.darkweb_ransomware import telegram_channel_watch as tw
from v3lum.modules.darkweb_ransomware.telegram_channel_watch import TelegramChannelWatch

pytestmark = pytest.mark.live
COULD_NOT_VERIFY = {Status.BLOCKED, Status.RATE_LIMITED, Status.QUOTA, Status.ERROR, Status.UNAVAILABLE}
GENESIS = "1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa"
EMPTY_LTC = "ltc1qzn9caqwrf3qgkc3hrvy3sph0qzvurrk0f3mznm"  # random, freshly minted for the prep live check (nobody's)
EF = "0xde0b295669a9fd93d5f28d9ec85e40f4cb697bae"


def live_runtime(**settings) -> Runtime:
    cfg = Config()
    cfg.settings.update(settings)
    return Runtime(cfg, no_cache=True)


def _could_not_verify(res) -> bool:
    if res.status in COULD_NOT_VERIFY:
        print(f"could not verify: {res.status.value} {res.reason_code} {res.error[:200]}")
        return True
    return False


def test_btc_explorers_genesis_address_from_the_first_public_explorer():
    res = run_module(BtcExplorers, f"btc_address:{GENESIS}", runtime=live_runtime())
    fo = res.attributes.get("explorer_failover", {})
    print(res.status.value, res.attributes.get("balance"), res.attributes.get("tx_count"), json.dumps(fo)[:600])
    if _could_not_verify(res):
        assert res.status is not Status.EMPTY
        return
    assert res.status is Status.OK and fo["answered_by"] in ("blockstream", "mempool", "blockchain_com")
    assert res.attributes["chain"] == "bitcoin" and res.attributes["tx_count"] > 60000
    assert res.attributes["disclosed_to"][-1] == fo["answered_by"]  # sequential: the answering explorer is the last one asked
    assert all(p.expand is False for p in res.pivots) and len(res.pivots) <= 10


def test_btc_explorers_random_litecoin_address_is_empty_from_litecoinspace():
    res = run_module(BtcExplorers, f"other_crypto_address:{EMPTY_LTC}", runtime=live_runtime())
    print(res.status.value, res.attributes.get("wallet_status"), json.dumps(res.attributes.get("explorer_failover"))[:400])
    if _could_not_verify(res):
        return
    assert res.status is Status.EMPTY and res.attributes["explorer_failover"]["answered_by"] == "litecoinspace"


def test_evm_explorers_ethereum_foundation_and_ens():
    res = run_module(EvmExplorers, f"eth_address:{EF}", runtime=live_runtime())
    print(res.status.value, res.attributes.get("balance"), res.attributes.get("is_contract"), json.dumps(res.attributes.get("explorer_failover"))[:700])
    if not _could_not_verify(res):
        assert res.status is Status.OK and res.attributes["chain"] == "ethereum"
        assert res.attributes.get("is_contract") is True  # the EF multisig is a contract (RPC eth_getCode)
        assert all(p.expand is False for p in res.pivots)
    ens = run_module(EvmExplorers, "domain:ens.eth", runtime=live_runtime())
    print(ens.status.value, [(p.relation, p.entity.value) for p in ens.pivots])
    if not _could_not_verify(ens):
        assert ens.status is Status.OK and ens.pivots[0].relation == "ens_resolves_to"


def test_telegram_channel_watch_one_cycle_on_the_official_channel(tmp_path: Path):
    team = {"version": 1, "channels": [{"handle": "telegram", "justification": "live check of the parser on Telegram's own public channel",
                                        "owner": "cti-team", "review_date": "2027-05-01",
                                        "reviewed_by": {"cti_lead": "2026-11-26", "legal": "2026-11-26"}}]}
    path = tmp_path / "telegram_watch.json"
    path.write_text(json.dumps(team), encoding="utf-8")
    org = OrgProfile.from_dict({"brands": [{"keyword": "telegram"}]})
    rt = live_runtime(telegram_channel_watch_list_path=str(path), telegram_channel_watch_use_deepdarkcti=False)
    rt.org = org
    res = run_module(TelegramChannelWatch, "keyword:telegram", runtime=rt)
    book = res.attributes.get("telegram_watch_cycle", {})
    print(res.status.value, res.error[:200], json.dumps(book)[:500], (res.attributes.get("telegram_watch_digest") or [""])[0][:200])
    if _could_not_verify(res):
        assert res.status is not Status.EMPTY
        return
    assert res.status in (Status.OK, Status.EMPTY) and book["channels_read"] == 1 and book["pages_read"] == 1  # first run: newest page only


def test_deepdarkcti_telegram_lists_download_and_parse():
    rt = live_runtime()
    for name in tw.DDC_DATASETS:
        result = rt.data.update(name)
        print(name, result.status, result.reason[:160], result.new_sha256[:12])
        assert result.status in ("updated", "unchanged", "failed")
        if result.status == "failed":
            assert result.reason
            continue
        text = Path(rt.data.fetch(name)).read_text(encoding="utf-8", errors="replace")
        parsed = tw.parse_deepdarkcti_telegram(text)
        picked = tw.select_deepdarkcti_channels(parsed)
        print(f"{name}: {parsed['rows_total']} rows, {len(picked)} public ONLINE/VALID channels")
        assert parsed["header"] is not None and all(c["handle"] for c in picked)
